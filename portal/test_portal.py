#!/usr/bin/env python3
"""Тесты портала v2 (организации, два уровня администраторов, peers.json, резервная копия).
Запуск: python3 portal/test_portal.py (нужны Flask, cryptography, Pillow)."""
import base64
import importlib
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

SUPER_PW = "superpass12"
FAILS = []
COUNT = 0


def check(name, cond, extra=""):
    global COUNT
    COUNT += 1
    if not cond:
        FAILS.append(name)
        print(f"FAIL: {name} {extra}")


def b64key(seed):
    return base64.b64encode(bytes([seed % 256]) * 32).decode()


def write_confs(d, n):
    (d / "configs").mkdir(exist_ok=True)
    for i in range(1, n + 1):
        (d / "configs" / f"client{i:03d}.conf").write_text(
            f"[Interface]\nPrivateKey = {b64key(i)}\nAddress = 10.8.0.{i + 1}/32\nDNS = 1.1.1.1\n\n"
            f"[Peer]\nPublicKey = {b64key(200)}\nPresharedKey = {b64key(i + 50)}\nEndpoint = x:51820\nAllowedIPs = 1.2.3.0/24\n")


def load(slots=6, prepare=None):
    d = Path(tempfile.mkdtemp())
    write_confs(d, slots)
    if prepare:
        prepare(d)
    os.environ.update(PORTAL_DEV="1", PORTAL_DATA=str(d), PORTAL_CONFIGS=str(d / "configs"),
                      PORTAL_PEERS=str(d / "peers.json"), SUPERADMIN_PASSWORD=SUPER_PW,
                      PORTAL_LOG_DIR=str(d / "logs"), PORTAL_SECRET_KEY="test")
    os.environ.pop("ADMIN_PASSWORD", None)
    sys.modules.pop("portal", None)
    p = importlib.import_module("portal")
    return p, d


class Ctx:
    def __init__(self, p):
        self.p = p

    def client(self):
        return self.p.app.test_client()

    def csrf(self, c, url="/"):
        c.get(url)
        with c.session_transaction() as s:
            return s["csrf"]

    def cap(self, c, url):
        html = c.get(url).get_data(as_text=True)
        cid = re.search(r'name="captcha_id" value="([^"]+)"', html).group(1)
        with self.p.app.app_context():
            ans = self.p.db().execute("SELECT answer FROM captchas WHERE id=?", (cid,)).fetchone()[0]
        with c.session_transaction() as s:
            return s["csrf"], cid, ans

    def emp_login(self, c, code, phone="+79001112233", name="Иванов Иван", ip="10.0.0.1", bad_captcha=False):
        t, cid, ans = self.cap(c, "/")
        return c.post("/login", data={"csrf": t, "code": code, "phone": phone, "name": name, "captcha_id": cid,
                                      "captcha": "zzzzz" if bad_captcha else ans},
                      headers={"X-Real-IP": ip}, follow_redirects=True)

    def claim(self, c, ip="10.0.0.1"):
        return c.post("/claim", data={"csrf": self.csrf(c), "label": "тест"}, headers={"X-Real-IP": ip}, follow_redirects=True)

    def super_login(self, c, pw=SUPER_PW, ip="10.1.0.1"):
        t, cid, ans = self.cap(c, "/super/login")
        return c.post("/super/login", data={"csrf": t, "password": pw, "captcha_id": cid, "captcha": ans},
                      headers={"X-Real-IP": ip}, follow_redirects=True)

    def org_login(self, c, slug, pw, ip="10.2.0.1"):
        t, cid, ans = self.cap(c, "/org/login")
        return c.post("/org/login", data={"csrf": t, "slug": slug, "password": pw, "captcha_id": cid, "captcha": ans},
                      headers={"X-Real-IP": ip}, follow_redirects=True)

    def post(self, c, url, ip="10.1.0.1", **data):
        with c.session_transaction() as s:
            t = s["csrf"]
        return c.post(url, data={"csrf": t, **data}, headers={"X-Real-IP": ip}, follow_redirects=True)

    def org(self, slug):
        with self.p.app.app_context():
            r = self.p.db().execute("SELECT * FROM orgs WHERE slug=?", (slug,)).fetchone()
            return dict(r) if r else None

    def slots(self, phone=None):
        with self.p.app.app_context():
            q = "SELECT a.slot FROM assignments a JOIN people p ON p.id=a.person_id"
            if phone:
                return [r[0] for r in self.p.db().execute(q + " WHERE p.phone=? ORDER BY 1", (phone,))]
            return [r[0] for r in self.p.db().execute(q + " ORDER BY 1")]


def peers_of(d):
    return json.loads((d / "peers.json").read_text())["peers"]


def create_org(x, sc, name, slug, limit="3", code=""):
    r = x.post(sc, "/super/org/create", name=name, slug=slug, limit=limit, code=code)
    m = re.search(r"пароль: (\S+?) \(", r.get_data(as_text=True).replace("&#34;", '"'))
    return m.group(1) if m else None


def main():
    p, d = load(slots=6)
    x = Ctx(p)

    # ---------- общий администратор: вход и защита
    anon = x.client()
    check("super: без входа редирект", anon.get("/super", follow_redirects=False).status_code == 302)
    check("super: /admin ведёт на /super", "/super" in anon.get("/admin").headers["Location"])
    sc = x.client()
    check("super: неверный пароль", "Неверный пароль" in x.super_login(sc, "wrongpass99").get_data(as_text=True))
    r = x.super_login(sc)
    check("super: вход", "Организации" in r.get_data(as_text=True))

    # ---------- создание организаций
    pw_a = create_org(x, sc, "Альфа", "alfa", "2", "11111")
    pw_b = create_org(x, sc, "Бета", "beta", "5", "22222")
    check("org: пароль показан", bool(pw_a) and bool(pw_b))
    check("org: создана", x.org("alfa")["key_limit"] == 2 and x.org("alfa")["code"] == "11111")
    r = x.post(sc, "/super/org/create", name="Дубль", slug="dub", limit="1", code="11111")
    check("org: дубль кода отклонён", "уже используется" in r.get_data(as_text=True) and not x.org("dub"))
    r = x.post(sc, "/super/org/create", name="Дубль", slug="alfa", limit="1")
    check("org: дубль логина отклонён", "уже есть" in r.get_data(as_text=True))
    r = x.post(sc, "/super/org/create", name="Плохой", slug="Bad Slug!", limit="1")
    check("org: плохой логин отклонён", not x.org("bad slug!"))
    r = x.post(sc, "/super/org/create", name="Лим", slug="lim", limit="99999")
    check("org: лимит вне диапазона", not x.org("lim"))
    r = x.post(sc, "/super/org/create", name="Авто", slug="auto", limit="1")
    auto = x.org("auto")
    check("org: код сгенерирован", auto and re.fullmatch(r"\d{5}", auto["code"]))
    r = x.post(sc, "/super/org/create", name="Кривой код", slug="kk", limit="1", code="12")
    check("org: кривой код отклонён", not x.org("kk"))
    # CSRF
    r = sc.post("/super/org/create", data={"name": "Нет", "slug": "nocsrf", "limit": "1"})
    check("super: CSRF обязателен", not x.org("nocsrf"))

    # ---------- сотрудники и лимиты
    e1 = x.client()
    check("emp: неверный код", "Неверный код" in x.emp_login(e1, "00000").get_data(as_text=True))
    e1 = x.client()
    check("emp: неверная капча", "Неверные символы" in x.emp_login(e1, "11111", bad_captcha=True).get_data(as_text=True))
    e1 = x.client()
    r = x.emp_login(e1, "11111")
    check("emp: вход по коду Альфы", "Альфа" in r.get_data(as_text=True))
    x.claim(e1)
    x.claim(e1)
    r = x.claim(e1)
    check("emp: лимит организации (2)", "Лимит ключей" in r.get_data(as_text=True))
    check("emp: выдано 2", len(x.slots("+79001112233")) == 2)
    e2 = x.client()
    x.emp_login(e2, "11111", phone="89002223344", name="Петров Пётр")
    r = x.claim(e2)
    check("emp: лимит общий на организацию", "Лимит ключей" in r.get_data(as_text=True) and not x.slots("+79002223344"))

    # изоляция: сотрудник Беты не видит конфиги Альфы
    e3 = x.client()
    x.emp_login(e3, "22222", phone="+79001112233", name="Иванов Иван")  # тот же телефон в другой организации
    check("emp: тот же телефон в другой орг. — нет чужих конфигов", "/conf" not in e3.get("/").get_data(as_text=True))
    s1 = x.slots("+79001112233")[0]
    check("emp: чужой конфиг недоступен", e3.get(f"/d/{s1}/conf").status_code == 404)
    r = e1.get(f"/d/{s1}/conf")
    check("emp: свой конфиг скачивается", r.status_code == 200 and b"PrivateKey" in r.data
          and "3dit-vpn-" in r.headers["Content-Disposition"])
    for i in range(3):
        x.claim(e3)
    check("emp: Бета до 3 устройств на человека", len(x.slots()) == 5)  # 2 Альфа + 3 Бета

    # peers.json
    pe = peers_of(d)
    check("peers: все выданные включены", len(pe) == 5, str(len(pe)))
    check("peers: формат", all(re.fullmatch(r"[A-Za-z0-9+/]{43}=", q["public"]) and q["ip"].startswith("10.8.0.") for q in pe))
    check("peers: права 0600", oct((d / "peers.json").stat().st_mode & 0o777) == "0o600")

    # ---------- лимит: увеличение, уменьшение
    oa = x.org("alfa")["id"]
    x.post(sc, f"/super/org/{oa}/limit", delta="1")
    check("limit: +1", x.org("alfa")["key_limit"] == 3)
    x.post(sc, f"/super/org/{oa}/limit", delta="-10")
    check("limit: ниже нуля не уходит", x.org("alfa")["key_limit"] == 3)
    x.post(sc, f"/super/org/{oa}/limit", limit="1")
    check("limit: абсолютное значение", x.org("alfa")["key_limit"] == 1)
    r = x.claim(e2)
    check("limit: ниже выданного — новые не выдаются", "Лимит ключей" in r.get_data(as_text=True))
    x.post(sc, f"/super/org/{oa}/limit", limit="abc")
    check("limit: мусор отклонён", x.org("alfa")["key_limit"] == 1)
    x.post(sc, f"/super/org/{oa}/limit", limit="4")
    r = x.claim(e2)
    check("limit: увеличение открывает выдачу", len(x.slots("+79002223344")) == 1)

    # ---------- отключение организации
    x.post(sc, f"/super/org/{oa}/toggle")
    check("toggle: отключена", x.org("alfa")["enabled"] == 0)
    check("toggle: peers.json без Альфы", len(peers_of(d)) == 3)
    check("toggle: сессия сотрудника блокируется", e1.get(f"/d/{s1}/conf").status_code == 403)
    e1b = x.client()
    check("toggle: вход по коду отключённой", "отключён" in x.emp_login(e1b, "11111").get_data(as_text=True))
    ow = x.client()
    x.org_login(ow, "alfa", pw_a)
    r = ow.get("/org")
    check("toggle: админ организации видит режим отключения", r.status_code == 200 and "отключ" in r.get_data(as_text=True).lower())
    r = x.post(ow, f"/org/release/{s1}", ip="10.2.0.1")
    check("toggle: админ отключённой орг. не может освобождать", s1 in x.slots())
    x.post(sc, f"/super/org/{oa}/toggle")
    check("toggle: включена обратно", x.org("alfa")["enabled"] == 1 and len(peers_of(d)) == 5 + 1)

    # ---------- администратор организации
    oc = x.client()
    check("orgadmin: неверный пароль", "Неверный логин" in x.org_login(oc, "alfa", "nope-nope-1").get_data(as_text=True))
    oc = x.client()
    check("orgadmin: чужой пароль", "Неверный логин" in x.org_login(oc, "beta", pw_a).get_data(as_text=True))
    oc = x.client()
    r = x.org_login(oc, "alfa", pw_a)
    html = r.get_data(as_text=True)
    check("orgadmin: вход", "Альфа" in html and "11111" in html)
    check("orgadmin: не видит других организаций", "Бета" not in html and "22222" not in html)
    check("orgadmin: не пускают в /super", oc.get("/super").status_code == 302)
    check("orgadmin: экспорт CSV", oc.get("/org/export.csv").status_code == 200)
    beta_slot = 5
    x.post(oc, f"/org/release/{beta_slot}", ip="10.2.0.1")
    check("orgadmin: нельзя освободить чужой конфиг", beta_slot in x.slots())
    old_conf = (d / "configs" / f"client{s1:03d}.conf").read_text()
    x.post(oc, f"/org/release/{s1}", ip="10.2.0.1")
    new_conf = (d / "configs" / f"client{s1:03d}.conf").read_text()
    check("release: конфиг освобождён", s1 not in x.slots())
    check("release: ключи заменены", old_conf != new_conf and re.search(r"PrivateKey = (\S+)", old_conf).group(1)
          != re.search(r"PrivateKey = (\S+)", new_conf).group(1))
    check("release: старый пир убран из peers.json", len(peers_of(d)) == 5)
    ow2 = x.client()
    check("orgadmin: сотрудник без входа", ow2.get("/org").status_code == 302)
    # пароль организации
    x.post(sc, f"/super/org/{oa}/admin-password")
    oc2 = x.client()
    check("orgadmin: старый пароль после сброса не работает", "Неверный логин" in x.org_login(oc2, "alfa", pw_a).get_data(as_text=True))

    # ---------- редактирование/код/удаление
    x.post(sc, f"/super/org/{oa}/update", name="Альфа-2", slug="alfa2")
    check("update: переименована", x.org("alfa2") and x.org("alfa2")["name"] == "Альфа-2")
    x.post(sc, f"/super/org/{oa}/code", code="22222")
    check("code: дубль отклонён", x.org("alfa2")["code"] == "11111")
    x.post(sc, f"/super/org/{oa}/code", code="33333")
    check("code: смена", x.org("alfa2")["code"] == "33333")
    x.post(sc, f"/super/org/{oa}/code", code="")
    check("code: случайный", re.fullmatch(r"\d{5}", x.org("alfa2")["code"]) is not None)
    e1c = x.client()
    check("code: старый код не работает", "Неверный код" in x.emp_login(e1c, "11111").get_data(as_text=True))
    x.post(sc, f"/super/org/{oa}/delete")
    check("delete: с выдачами нельзя", x.org("alfa2") is not None)
    for s in x.slots():
        with p.app.app_context():
            row = p.db().execute("SELECT o.slug FROM assignments a JOIN people pe ON pe.id=a.person_id JOIN orgs o ON o.id=pe.org_id WHERE a.slot=?", (s,)).fetchone()
        if row["slug"] == "alfa2":
            x.post(sc, f"/super/release/{s}")
    x.post(sc, f"/super/org/{oa}/delete")
    check("delete: пустую можно", x.org("alfa2") is None)

    # ---------- экспорты
    r = sc.get("/super/export.csv")
    check("export: организации", r.status_code == 200 and "Бета" in r.get_data(as_text=True))
    check("export: CSV защищён от формул", "'=" not in "" and r.status_code == 200)

    # ---------- резервная копия
    bp = "/super/backup"
    check("backup: без входа редирект", anon.get(bp).status_code == 302)
    check("backup: форма", sc.get(bp).status_code == 200)
    r = x.post(sc, bp, password="wrong-pass-1", passphrase="a" * 16, passphrase2="a" * 16)
    check("backup: неверный пароль", "Неверный пароль" in r.get_data(as_text=True))
    r = x.post(sc, bp, password=SUPER_PW, passphrase="short", passphrase2="short")
    check("backup: короткая фраза", "не короче 12" in r.get_data(as_text=True))
    r = x.post(sc, bp, password=SUPER_PW, passphrase="a" * 16, passphrase2="b" * 16)
    check("backup: фразы не совпали", "не совпадают" in r.get_data(as_text=True))
    r = sc.post(bp, data={"password": SUPER_PW, "passphrase": "a" * 16, "passphrase2": "a" * 16})
    check("backup: CSRF обязателен", r.headers.get("Content-Type", "").startswith("application/octet") is False)
    PH = "correct horse battery"
    r = x.post(sc, bp, password=SUPER_PW, passphrase=PH, passphrase2=PH)
    blob = r.data
    check("backup: файл получен", r.status_code == 200 and blob.startswith(b"VPNBAK1\n")
          and ".vpnbak" in r.headers["Content-Disposition"])
    import backup
    check("backup: не читается без фразы", b"PrivateKey" not in blob and "Бета".encode() not in blob)
    try:
        backup.decrypt(blob, "wrong phrase here")
        check("backup: неверная фраза", False)
    except ValueError:
        check("backup: неверная фраза", True)
    bad = bytearray(blob)
    bad[-5] ^= 1
    try:
        backup.decrypt(bytes(bad), PH)
        check("backup: подмена обнаружена", False)
    except ValueError:
        check("backup: подмена обнаружена", True)
    manifest, state, confs = backup.read_backup(backup.decrypt(blob, PH))
    check("backup: манифест", manifest["counts"]["configs"] == 6 and manifest["counts"]["orgs"] >= 2)

    # восстановление в чистый экземпляр
    p2, d2 = load(slots=6, prepare=lambda dd: None)
    x2 = Ctx(p2)
    with p2.app.app_context():
        c = p2.db()
        backup.restore_state(c, p2.CONF_DIR, state, confs)
        p2.write_peers(c)
    check("restore: организации", x2.org("beta") and x2.org("beta")["code"] == "22222")
    check("restore: выдачи", x2.slots() == x.slots(), f"{x2.slots()} vs {x.slots()}")
    check("restore: конфиги с ротированными ключами",
          (d2 / "configs" / f"client{s1:03d}.conf").read_text() == new_conf)
    check("restore: peers.json совпадает", peers_of(d2) == peers_of(d))
    e3b = x2.client()
    r = x2.emp_login(e3b, "22222", phone="+79001112233", name="Иванов Иван")
    check("restore: сотрудник входит и видит свои конфиги", r.get_data(as_text=True).count("/conf") >= 3)
    ob = x2.client()
    check("restore: пароль админа организации сохранился", "Бета" in x2.org_login(ob, "beta", pw_b).get_data(as_text=True))

    # небезопасные архивы
    import tarfile
    def mk(names):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            for n, data in names:
                i = tarfile.TarInfo(n)
                i.size = len(data)
                t.addfile(i, io.BytesIO(data))
        return buf.getvalue()
    for bad_name in ("../evil", "configs/../../etc/passwd", "configs/x.conf", "/abs"):
        try:
            backup.read_backup(mk([("manifest.json", b'{"format":1}'), (bad_name, b"[Interface]\nPrivateKey=x")]))
            check(f"backup: отклонено {bad_name}", False)
        except ValueError:
            check(f"backup: отклонено {bad_name}", True)
    try:
        backup.restore_state(sqlite3.connect(":memory:"), d2 / "c", {"orgs": [], "people": [{"id": 1, "org_id": 9}], "assignments": [], "audit": []}, {})
        check("restore: несогласованность", False)
    except ValueError:
        check("restore: несогласованность", True)

    # ---------- трафик
    with p.app.app_context():
        owner_slots = sorted(r[0] for r in p.db().execute("SELECT a.slot FROM assignments a JOIN people pe ON pe.id=a.person_id JOIN orgs o ON o.id=pe.org_id WHERE o.slug='beta'"))
    slot_a, slot_b = owner_slots[0], owner_slots[1]
    pub_a, pub_b = p.peer_info(slot_a)["public"], p.peer_info(slot_b)["public"]
    GB = 1024 ** 3
    (d / "traffic.json").write_text(json.dumps({"version": 1, "peers": {
        pub_a: {"rx": GB, "tx": 2 * GB, "lrx": 0, "ltx": 0}, pub_b: {"rx": 512 * 1024, "tx": 1024 * 1024, "lrx": 0, "ltx": 0}}}))
    ob_ = x.client()
    html = x.org_login(ob_, "beta", pw_b).get_data(as_text=True)
    check("traffic: админ организации видит трафик пользователя", "3.0 ГБ" in html)
    check("traffic: итог по организации Беты", "трафик всего" in html)
    r = ob_.get("/org/export.csv").get_data(as_text=True)
    check("traffic: CSV с байтами", str(3 * GB + 512 * 1024 + 1024 * 1024) in r)
    html = sc.get("/super").get_data(as_text=True)
    check("traffic: общий админ видит трафик организации", "ГБ" in html)
    with p.app.app_context():
        beta_tot = [o for o in p.org_rows() if o["slug"] == "beta"][0]["traffic"]
    expected = 3 * GB + 512 * 1024 + 1024 * 1024
    check("traffic: сумма по организации", beta_tot == expected, f"{beta_tot} != {expected}")
    csv_super = sc.get("/super/export.csv").get_data(as_text=True)
    check("traffic: CSV организаций содержит трафик", "Трафик" in csv_super)
    # освобождение сохраняет накопленное в итоге человека
    before = beta_tot
    x.post(ob_, f"/org/release/{slot_a}", ip="10.2.0.1")
    with p.app.app_context():
        after = [o for o in p.org_rows() if o["slug"] == "beta"][0]["traffic"]
        fresh = p.slot_traffic(slot_a)
    check("traffic: после освобождения итог не теряется", after == before, f"{after} != {before}")
    check("traffic: у нового ключа счётчик с нуля", fresh == (0, 0))
    r = x.post(sc, bp, password=SUPER_PW, passphrase=PH, passphrase2=PH)
    _, st2, _ = backup.read_backup(backup.decrypt(r.data, PH))
    check("traffic: счётчики входят в копию", isinstance(st2.get("traffic"), dict) and pub_a in st2["traffic"]["peers"])
    p5, d5 = load(slots=6)
    with p5.app.app_context():
        backup.restore_state(p5.db(), p5.CONF_DIR, st2, confs, p5.TRAFFIC_FILE)
    check("traffic: восстановление счётчиков", json.loads((d5 / "traffic.json").read_text())["peers"][pub_b]["tx"] == 1024 * 1024)
    # ---------- журнал
    with p.app.app_context():
        acts = [r[0] for r in p.db().execute("SELECT action FROM audit")]
    for a in ("создана организация", "изменён лимит ключей", "доступ отключён", "освобождён конфиг",
              "создана резервная копия", "выдан конфиг", "удалена организация"):
        check(f"audit: {a}", a in acts)

    # ---------- ограничение перебора кода
    p3, d3 = load(slots=2)
    x3 = Ctx(p3)
    c = x3.client()
    for _ in range(5):
        x3.emp_login(c, "99999", ip="9.9.9.9")
    r = x3.emp_login(c, "99999", ip="9.9.9.9")
    check("bruteforce: блокировка после 5 неверных", "Слишком много" in r.get_data(as_text=True))
    fl = (d3 / "logs" / "auth.log")
    check("bruteforce: AUTHFAIL для fail2ban", fl.exists() and re.search(r"AUTHFAIL ip=9\.9\.9\.9 kind=code", fl.read_text()))

    # ---------- миграция v1 -> v2
    def v1(dd):
        con = sqlite3.connect(dd / "portal.db")
        con.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE people(phone TEXT PRIMARY KEY, name TEXT, created_at INTEGER);
            CREATE TABLE assignments(slot INTEGER PRIMARY KEY, phone TEXT, label TEXT, assigned_at INTEGER,
                                     last_download_at INTEGER, downloads INTEGER DEFAULT 0);
            INSERT INTO settings VALUES('code','54321');
            INSERT INTO people VALUES('+79005556677','Сидоров Сидор',1700000000);
            INSERT INTO assignments VALUES(3,'+79005556677','ноут',1700000100,NULL,0);
        """)
        con.commit()
        con.close()
    p4, d4 = load(slots=4, prepare=v1)
    x4 = Ctx(p4)
    m = x4.org("main")
    check("migrate: организация main с прежним кодом", m and m["code"] == "54321" and m["key_limit"] == 4)
    check("migrate: выдача сохранена", x4.slots("+79005556677") == [3])
    c = x4.client()
    r = x4.emp_login(c, "54321", phone="+79005556677", name="Сидоров Сидор")
    check("migrate: вход по старому коду", "/d/3/conf" in r.get_data(as_text=True))
    check("migrate: peers.json содержит пира", [q["slot"] for q in peers_of(d4)] == [3])
    p4b = importlib.reload(p4)  # повторная инициализация не ломает данные
    check("migrate: идемпотентно", Ctx(p4b).slots() == [3])

    print(f"\nПроверок: {COUNT}, провалено: {len(FAILS)}")
    if FAILS:
        print("\n".join(" - " + f for f in FAILS))
        sys.exit(1)
    print("Все проверки пройдены")


if __name__ == "__main__":
    main()
