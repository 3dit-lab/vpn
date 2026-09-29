"""Резервная копия состояния портала для переезда на другой сервер.

В копию входят все клиентские конфиги с ТЕКУЩИМИ ключами (после ротаций тоже) и состояние портала:
организации (коды доступа, лимиты, статусы, хеши паролей администраторов), люди, выдачи, журнал.
Копия всегда шифруется парольной фразой (AES-256-GCM, ключ из фразы через scrypt): в ней приватные ключи.

Формат файла: b"VPNBAK1\\n" + salt(16) + nonce(12) + AES-GCM(tar.gz), заголовок входит в аутентифицируемые данные.
"""
import io
import json
import os
import re
import tarfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"VPNBAK1\n"
HEADER_LEN = len(MAGIC) + 16 + 12
SCRYPT_N = 2 ** 15
CONF_NAME_RE = re.compile(r"^client\d{3,}\.conf$")
MAX_CONF_BYTES = 64 * 1024
MAX_STATE_BYTES = 32 * 1024 * 1024
MAX_FILES = 5000
TABLES = ("orgs", "people", "assignments", "audit")


def _derive(passphrase, salt):
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(passphrase.encode("utf-8"))


def encrypt(plain, passphrase):
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + salt + nonce
    return header + AESGCM(_derive(passphrase, salt)).encrypt(nonce, plain, header)


def decrypt(blob, passphrase):
    if not blob.startswith(MAGIC) or len(blob) < HEADER_LEN + 16:
        raise ValueError("Это не файл резервной копии портала")
    header = blob[:HEADER_LEN]
    salt = header[len(MAGIC):len(MAGIC) + 16]
    nonce = header[len(MAGIC) + 16:]
    try:
        return AESGCM(_derive(passphrase, salt)).decrypt(nonce, blob[HEADER_LEN:], header)
    except Exception:
        raise ValueError("Неверная парольная фраза или файл повреждён")


def _rows(conn, table):
    return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]


def dump_state(conn, conf_dir, traffic_file=None):
    """Собирает tar.gz (в памяти) с состоянием портала и всеми конфигами."""
    state = {t: _rows(conn, t) for t in TABLES}
    try:  # накопленные счётчики трафика по ключам (их ведёт служба vpn-traffic)
        state["traffic"] = json.loads(Path(traffic_file).read_text()) if traffic_file else None
    except (OSError, ValueError):
        state["traffic"] = None
    confs = {}
    for f in sorted(Path(conf_dir).iterdir()):
        if CONF_NAME_RE.match(f.name):
            confs[f.name] = f.read_bytes()
    manifest = {
        "format": 1,
        "created_at": int(time.time()),
        "counts": {**{t: len(state[t]) for t in TABLES}, "configs": len(confs)},
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = int(time.time())
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
        add("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1).encode())
        add("state.json", json.dumps(state, ensure_ascii=False).encode())
        for name, data in confs.items():
            add(f"configs/{name}", data)
    return buf.getvalue(), manifest


def read_backup(plain):
    """Разбирает и проверяет tar.gz. Возвращает (manifest, state, configs). Небезопасные имена и размеры отклоняются."""
    manifest = state = None
    configs = {}
    try:
        tar = tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz")
    except tarfile.TarError:
        raise ValueError("Содержимое копии повреждено")
    with tar:
        members = tar.getmembers()
        if len(members) > MAX_FILES:
            raise ValueError("Слишком много файлов в копии")
        for m in members:
            if not m.isfile():
                raise ValueError(f"Недопустимый элемент в копии: {m.name!r}")
            if m.name == "manifest.json" and m.size <= 1_000_000:
                manifest = json.loads(tar.extractfile(m).read())
            elif m.name == "state.json" and m.size <= MAX_STATE_BYTES:
                state = json.loads(tar.extractfile(m).read())
            elif m.name.startswith("configs/") and m.size <= MAX_CONF_BYTES:
                name = m.name[len("configs/"):]
                if not CONF_NAME_RE.match(name):
                    raise ValueError(f"Недопустимое имя конфига: {name!r}")
                data = tar.extractfile(m).read()
                if b"[Interface]" not in data or b"PrivateKey" not in data:
                    raise ValueError(f"Конфиг {name} выглядит неверно")
                configs[name] = data
            else:
                raise ValueError(f"Недопустимый элемент в копии: {m.name!r}")
    if not manifest or manifest.get("format") != 1:
        raise ValueError("Неизвестный формат резервной копии")
    if not isinstance(state, dict) or any(t not in state for t in TABLES):
        raise ValueError("В копии нет состояния портала")
    return manifest, state, configs


def restore_state(conn, conf_dir, state, configs, traffic_file=None):
    """Полностью заменяет организации, людей, выдачи и журнал состоянием из копии и записывает конфиги."""
    ids_org = {o["id"] for o in state["orgs"]}
    ids_person = {p["id"] for p in state["people"]}
    if any(p["org_id"] not in ids_org for p in state["people"]):
        raise ValueError("Копия несогласована: у человека нет организации")
    if any(a["person_id"] not in ids_person for a in state["assignments"]):
        raise ValueError("Копия несогласована: у выдачи нет владельца")
    for a in state["assignments"]:
        if f"client{a['slot']:03d}.conf" not in configs:
            raise ValueError(f"В копии нет файла конфига для выданного №{a['slot']:03d}")

    conn.execute("BEGIN IMMEDIATE")
    try:
        for t in ("assignments", "people", "orgs", "audit"):
            conn.execute(f"DELETE FROM {t}")
        for t in TABLES:
            rows = state[t]
            if not rows:
                continue
            cols = list(rows[0].keys())
            q = f"INSERT INTO {t}({','.join(cols)}) VALUES({','.join('?' * len(cols))})"
            conn.executemany(q, [[r[c] for c in cols] for r in rows])
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    conf_dir = Path(conf_dir)
    conf_dir.mkdir(parents=True, exist_ok=True)
    for name, data in configs.items():
        tmp = conf_dir / f".{name}.tmp"
        tmp.write_bytes(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, conf_dir / name)

    if traffic_file and isinstance(state.get("traffic"), dict):
        tf = Path(traffic_file)
        tmp = tf.with_name("." + tf.name + ".tmp")
        tmp.write_text(json.dumps(state["traffic"]))
        os.chmod(tmp, 0o640)
        os.replace(tmp, tf)
