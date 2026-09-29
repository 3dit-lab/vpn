#!/usr/bin/env python3
"""Портал выдачи VPN-конфигов (ООО «Тридит»).

Один общий QR ведёт сюда. Сотрудник вводит общий код доступа (5 цифр), телефон и фамилию с именем
(без SMS-подтверждения; имя нужно только для таблицы у администратора) и получает первый свободный
конфиг. На человека до 3 конфигов (по одному на устройство); скачать свой конфиг можно повторно
(например, для переустановки приложения). У администратора отдельная страница с таблицей выдачи.

Запуск (см. deploy/vpn-portal.service):  gunicorn --bind 127.0.0.1:8081 portal:app

Переменные окружения:
    PORTAL_SECRET_KEY  секрет подписи сессий (обязателен)
    PORTAL_CODE        начальный код доступа, 5 цифр (дальше меняется на странице администратора)
    ADMIN_PASSWORD     пароль администратора (не короче 8 символов; без него админ-страница отключена)
    PORTAL_DATA        каталог данных (по умолчанию /var/lib/vpn-portal)
    PORTAL_CONFIGS     каталог с файлами clientNNN.conf (по умолчанию $PORTAL_DATA/configs)
    PORTAL_TZ          часовой пояс для отображения (по умолчанию Europe/Samara)
    PORTAL_DEV=1       режим разработки (кука без Secure, секрет генерируется сам)
"""
import csv
import hmac
import io
import logging
import os
import random
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, Response, flash, g, get_flashed_messages, redirect, render_template, request, session
from jinja2 import DictLoader
from PIL import Image, ImageDraw, ImageFilter, ImageFont

DEV = os.environ.get("PORTAL_DEV") == "1"
DATA_DIR = Path(os.environ.get("PORTAL_DATA", "/var/lib/vpn-portal"))
CONF_DIR = Path(os.environ.get("PORTAL_CONFIGS", str(DATA_DIR / "configs")))
DB_PATH = DATA_DIR / "portal.db"
MAX_DEVICES = 3
ADMIN_SESSION_SECONDS = 8 * 3600

# лимиты попыток: (максимум, окно в секундах)
LIMIT_LOGIN_IP = (5, 15 * 60)       # неверных кодов с одного IP
LIMIT_LOGIN_ALL = (40, 60 * 60)     # неверных кодов всего (защита от перебора с многих адресов)
LIMIT_ADMIN_IP = (5, 15 * 60)
LIMIT_ADMIN_ALL = (20, 60 * 60)
LIMIT_CLAIM_IP = (10, 60 * 60)      # выдач конфигов с одного IP в час
LIMIT_CAPTCHA_IP = (10, 15 * 60)    # неверных ответов на капчу с одного IP
LIMIT_CAPTCHA_NEW_IP = (30, 10 * 60)  # показов капчи с одного IP (защита от заливки базы)
CAPTCHA_TTL = 300
CAPTCHA_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # без похожих 0/O, 1/I

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo(os.environ.get("PORTAL_TZ", "Europe/Samara"))
except Exception:  # старый Python или нет tzdata
    TZ = timezone(timedelta(hours=4))

app = Flask(__name__)
secret = os.environ.get("PORTAL_SECRET_KEY")
if not secret:
    if DEV:
        secret = secrets.token_hex(32)
    else:
        raise RuntimeError("Не задан PORTAL_SECRET_KEY")
app.config.update(
    SECRET_KEY=secret,
    SESSION_COOKIE_NAME="vpn_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=not DEV,
    PERMANENT_SESSION_LIFETIME=timedelta(days=365),
    MAX_CONTENT_LENGTH=16 * 1024,
)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("portal")

# Отдельный файл только с неудачными входами: его читает fail2ban (deploy/fail2ban/).
# Формат строки: "<время> AUTHFAIL ip=<адрес> kind=<причина>"
auth_log = logging.getLogger("portal.auth")
auth_log.handlers.clear()
_log_dir = os.environ.get("PORTAL_LOG_DIR", "/var/log/vpn-portal")
try:
    Path(_log_dir).mkdir(parents=True, exist_ok=True)
    _h = RotatingFileHandler(Path(_log_dir) / "auth.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    _h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    auth_log.addHandler(_h)
except OSError:
    log.warning("Не удалось открыть %s/auth.log: fail2ban не увидит неудачные входы", _log_dir)

# --------------------------------------------------------------------------- шаблоны

CSS = """
:root { --bg:#f6f7f9; --card:#fff; --fg:#1b1f24; --muted:#5b6570; --accent:#1f6feb; --line:#dde2e8; --warn:#fff4e5; --warnfg:#7a4b00; --ok:#e7f6ec; --okfg:#155724; --err:#fdecea; --errfg:#8a1c14; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#12151a; --card:#1a1e24; --fg:#e8ebef; --muted:#9aa4af; --accent:#5b9dff; --line:#2b323b; --warn:#3a2d12; --warnfg:#f0c674; --ok:#14301d; --okfg:#8fd6a3; --err:#3b1a17; --errfg:#f2a39b; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:680px; margin:0 auto; padding:16px; }
main.wide { max-width:1100px; }
h1 { font-size:22px; margin:8px 0 4px; }
h2 { font-size:17px; margin:0 0 8px; }
.sub { color:var(--muted); margin:0 0 16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; margin:0 0 12px; }
.btn { display:block; width:100%; text-align:center; padding:13px 16px; border-radius:10px; border:0; font:inherit; font-weight:600; text-decoration:none; cursor:pointer; margin:8px 0 0; }
.primary { background:var(--accent); color:#fff; }
.secondary { background:transparent; color:var(--accent); border:1px solid var(--accent); }
.danger { background:transparent; color:var(--errfg); border:1px solid var(--errfg); padding:4px 10px; width:auto; display:inline-block; margin:2px 0; font-size:13px; }
label { display:block; margin:12px 0 4px; font-weight:600; }
input[type=text], input[type=tel], input[type=password], input[type=number] { width:100%; padding:12px; border-radius:10px; border:1px solid var(--line); background:var(--bg); color:var(--fg); font:inherit; }
.msg { border-radius:10px; padding:12px 14px; margin:0 0 12px; font-size:15px; }
.msg.ok { background:var(--ok); color:var(--okfg); }
.msg.err { background:var(--err); color:var(--errfg); }
.warn { background:var(--warn); color:var(--warnfg); border-radius:10px; padding:12px 14px; margin:0 0 12px; font-size:15px; }
.dev { border-top:1px solid var(--line); padding:12px 0; }
.dev:first-of-type { border-top:0; }
small, .muted { color:var(--muted); }
.app { display:flex; justify-content:space-between; gap:8px; align-items:center; padding:8px 0; border-top:1px solid var(--line); flex-wrap:wrap; }
.app:first-of-type { border-top:0; }
.app.me { font-weight:600; }
.app a { color:var(--accent); }
table { border-collapse:collapse; width:100%; font-size:14px; }
th, td { border-bottom:1px solid var(--line); padding:8px 6px; text-align:left; vertical-align:top; }
th { color:var(--muted); font-weight:600; white-space:nowrap; }
.scroll { overflow-x:auto; }
.stats { display:flex; gap:12px; flex-wrap:wrap; margin:0 0 12px; }
.stat { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:10px 16px; }
.stat b { display:block; font-size:22px; }
.row { display:flex; gap:8px; flex-wrap:wrap; align-items:end; }
.row > * { flex:1 1 160px; }
.link { background:none; border:0; color:var(--accent); cursor:pointer; font:inherit; padding:0; }
"""

TEMPLATES = {
    "captcha.html": """{% if captcha_id %}
<label for="captcha">Символы с картинки</label>
<img src="/captcha/{{ captcha_id }}.png" width="200" height="70" alt="Проверочные символы" style="display:block;background:#fff;border-radius:8px;border:1px solid var(--line)">
<input type="hidden" name="captcha_id" value="{{ captcha_id }}">
<input id="captcha" name="captcha" type="text" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="8" required>
<small><a href="{{ refresh_url }}" style="color:var(--accent)">Показать другую картинку</a></small>
{% else %}
<div class="msg err">Слишком много запросов. Подождите несколько минут и обновите страницу.</div>
{% endif %}""",

    "base.html": """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer">
<title>{% block title %}Доступ к VPN{% endblock %}</title>
<style>""" + CSS + """</style></head>
<body><main class="{% block cls %}{% endblock %}">
{% for cat, text in messages %}<div class="msg {{ cat }}">{{ text }}</div>{% endfor %}
{% block content %}{% endblock %}
</main></body></html>""",

    "login.html": """{% extends "base.html" %}
{% block content %}
<h1>Доступ к VPN</h1>
<p class="sub">ООО «Тридит»</p>
<div class="card">
  <form method="post" action="/login" autocomplete="on">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label for="code">Код доступа (5 цифр)</label>
    <input id="code" name="code" type="text" inputmode="numeric" pattern="[0-9]{5}" maxlength="5" autocomplete="off" required>
    <label for="phone">Номер телефона</label>
    <input id="phone" name="phone" type="tel" inputmode="tel" placeholder="+7 900 000-00-00 или 8 900 000-00-00" autocomplete="tel" required>
    <label for="name">Фамилия и имя <small>(при первом входе)</small></label>
    <input id="name" name="name" type="text" maxlength="80" autocomplete="name" value="{{ name or '' }}">
    {% with refresh_url='/' %}{% include "captcha.html" %}{% endwith %}
    <button class="btn primary" type="submit"{% if not captcha_id %} disabled{% endif %}>Войти</button>
  </form>
  <p><small>Код доступа вам сообщил администратор. Вход по номеру телефона без SMS: телефон нужен только для того, чтобы найти ваши конфиги при повторном входе.</small></p>
</div>
{% endblock %}""",

    "dashboard.html": """{% extends "base.html" %}
{% block content %}
<h1>Доступ к VPN</h1>
<p class="sub">{{ name }} · {{ phone }}</p>

<div class="warn">Конфиг личный: не пересылайте его другим людям. Один конфиг работает только на одном устройстве. Для второго и третьего устройства получите отдельные конфиги ниже.</div>

<div class="card">
  <h2>Мои конфиги</h2>
  {% for d in devices %}
  <div class="dev">
    <b>Устройство {{ loop.index }}</b>{% if d.label %} · {{ d.label }}{% endif %}<br>
    <small>Конфиг №{{ '%03d' % d.slot }} · выдан {{ d.at }}</small>
    <a class="btn primary" href="/d/{{ d.slot }}/conf">Скачать конфиг</a>
    <button class="btn secondary copy" type="button" data-url="/d/{{ d.slot }}/conf">Скопировать конфиг</button>
    <small class="copystate"></small>
  </div>
  {% else %}
  <p class="muted">Конфигов пока нет. Нажмите кнопку ниже, чтобы получить первый.</p>
  {% endfor %}

  {% if devices|length < max_devices %}
  <form method="post" action="/claim" onsubmit="return confirm('Получить {{ 'конфиг' if not devices else 'дополнительный конфиг' }}? Он закрепляется за вами.');">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label for="label">Название устройства <small>(необязательно)</small></label>
    <input id="label" name="label" type="text" maxlength="30" placeholder="например, iPhone">
    <button class="btn primary" type="submit">{% if not devices %}Получить конфиг{% else %}Получить конфиг для устройства {{ devices|length + 1 }}{% endif %}</button>
  </form>
  {% else %}
  <p><small>Выдано максимальное число конфигов ({{ max_devices }}).</small></p>
  {% endif %}
  <p><small>Переустановили приложение или сменили телефон? Новый конфиг не нужен: скачайте свой прежний конфиг заново.</small></p>
</div>

<div class="card">
  <h2>Приложения</h2>
  <div class="app" data-os="ios"><span>iPhone / iPad</span><span><a href="https://apps.apple.com/app/id6744725017" rel="noopener">DefaultVPN (App Store)</a></span></div>
  <div class="app" data-os="android"><span>Android</span><span><a href="https://play.google.com/store/apps/details?id=org.amnezia.vpn" rel="noopener">Google Play</a> · <a href="/apps/">файл .apk</a></span></div>
  <div class="app" data-os="windows"><span>Windows</span><span><a href="/apps/">Скачать</a> · <a href="https://amnezia.org/en/downloads" rel="noopener">сайт разработчика</a></span></div>
  <div class="app" data-os="mac"><span>macOS</span><span><a href="/apps/">Скачать</a> · <a href="https://amnezia.org/en/downloads" rel="noopener">сайт разработчика</a></span></div>
  <div class="app" data-os="linux"><span>Linux</span><span><a href="/apps/">Скачать</a> · <a href="https://amnezia.org/en/downloads" rel="noopener">сайт разработчика</a></span></div>
  <p><small>На iPhone Amnezia VPN в российском App Store недоступен, поэтому используется DefaultVPN. На остальных системах ставится Amnezia VPN.</small></p>
</div>

<div class="card">
  <h2>Как подключить</h2>
  <ol>
    <li>Установите приложение для своей системы (список выше).</li>
    <li>Нажмите «Скачать конфиг» и откройте файл в приложении: на телефоне через «Поделиться» / «Открыть в…», на компьютере через добавление подключения из файла.</li>
    <li>Включите подключение. Заблокированные сервисы (мессенджеры, нейросети) заработают, банки и госуслуги останутся без VPN.</li>
  </ol>
  <p><small>Не получается? Напишите в поддержку: it@3dit.ru</small></p>
</div>

<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link" type="submit">Выйти</button></form>

<script>
(function () {
  var ua = navigator.userAgent || "", p = navigator.platform || "", id = "";
  if (/iPhone|iPad|iPod/.test(ua) || (p === "MacIntel" && navigator.maxTouchPoints > 1)) id = "ios";
  else if (/Android/.test(ua)) id = "android";
  else if (/Windows/.test(ua)) id = "windows";
  else if (/Mac/.test(ua)) id = "mac";
  else if (/Linux|X11/.test(ua)) id = "linux";
  var me = document.querySelector('[data-os="' + id + '"]');
  if (me) me.className += " me";
  var btns = document.querySelectorAll(".copy");
  for (var i = 0; i < btns.length; i++) {
    btns[i].addEventListener("click", function () {
      var b = this, st = b.parentNode.querySelector(".copystate");
      function done(ok) { st.textContent = ok ? "Конфиг скопирован в буфер обмена." : "Не удалось скопировать, используйте «Скачать конфиг»."; }
      fetch(b.getAttribute("data-url"), {credentials: "same-origin"}).then(function (r) { return r.text(); }).then(function (text) {
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
        } else {
          var ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
          var ok = false; try { ok = document.execCommand("copy"); } catch (e) {}
          document.body.removeChild(ta); done(ok);
        }
      }, function () { done(false); });
    });
  }
})();
</script>
{% endblock %}""",

    "admin_login.html": """{% extends "base.html" %}
{% block title %}Администратор{% endblock %}
{% block content %}
<h1>Администратор</h1>
<div class="card">
  <form method="post" action="/admin/login">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label for="pw">Пароль</label>
    <input id="pw" name="password" type="password" autocomplete="current-password" required>
    {% with refresh_url='/admin/login' %}{% include "captcha.html" %}{% endwith %}
    <button class="btn primary" type="submit"{% if not captcha_id %} disabled{% endif %}>Войти</button>
  </form>
</div>
{% endblock %}""",

    "admin.html": """{% extends "base.html" %}
{% block title %}Администратор: выдача конфигов{% endblock %}
{% block cls %}wide{% endblock %}
{% block content %}
<h1>Выдача VPN-конфигов</h1>
<div class="stats">
  <div class="stat"><b>{{ total }}</b>всего конфигов</div>
  <div class="stat"><b>{{ used }}</b>выдано</div>
  <div class="stat"><b>{{ free }}</b>свободно</div>
  <div class="stat"><b>{{ people|length }}</b>человек</div>
  <div class="stat"><b>{{ by_count[1] }} / {{ by_count[2] }} / {{ by_count[3] }}</b>с 1 / 2 / 3 конфигами</div>
</div>
{% if free == 0 %}<div class="msg err">Свободных конфигов не осталось. Нужно сгенерировать дополнительные (см. README).</div>{% elif free <= 10 %}<div class="msg err">Свободных конфигов осталось мало: {{ free }}.</div>{% endif %}

<div class="card scroll">
  <table>
    <tr><th>Фамилия Имя</th><th>Телефон</th><th>Конфигов</th><th>Конфиги (устройства)</th><th>Первая выдача</th><th>Последнее скачивание</th></tr>
    {% for p in people %}
    <tr>
      <td>{{ p.name or '—' }}</td>
      <td>{{ p.phone }}</td>
      <td>{{ p.confs|length }}</td>
      <td>
        {% for a in p.confs %}
        <form method="post" action="/admin/release/{{ a.slot }}" style="display:block" onsubmit="return confirm('Освободить конфиг №{{ '%03d' % a.slot }}? Ключ в конфиге не меняется: устройство, где он установлен, продолжит подключаться, а сам конфиг может быть выдан другому человеку.');">
          <input type="hidden" name="csrf" value="{{ csrf }}">
          №{{ '%03d' % a.slot }}{% if a.label %} · {{ a.label }}{% endif %}
          <button class="danger" type="submit">Освободить</button>
        </form>
        {% else %}<span class="muted">нет</span>{% endfor %}
      </td>
      <td>{{ p.first }}</td>
      <td>{{ p.last }}</td>
    </tr>
    {% else %}
    <tr><td colspan="6" class="muted">Пока никто не получал конфиги.</td></tr>
    {% endfor %}
  </table>
  <p><a href="/admin/export.csv">Скачать таблицу (CSV)</a></p>
</div>

<div class="card">
  <h2>Код доступа</h2>
  <p>Текущий код: <b>{{ code }}</b>. Смена кода не разлогинивает тех, кто уже вошёл.</p>
  <form method="post" action="/admin/code" class="row">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <div><label for="newcode">Новый код (5 цифр, пусто = случайный)</label>
    <input id="newcode" name="code" type="text" inputmode="numeric" pattern="[0-9]{5}" maxlength="5"></div>
    <div><button class="btn primary" type="submit">Сменить код</button></div>
  </form>
</div>

<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link" type="submit">Выйти</button></form>
{% endblock %}""",
}
app.jinja_loader = DictLoader(TEMPLATES)

# --------------------------------------------------------------------------- база данных

SCHEMA = """
CREATE TABLE IF NOT EXISTS people (
    phone TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS assignments (
    slot INTEGER PRIMARY KEY,
    phone TEXT NOT NULL REFERENCES people(phone),
    label TEXT NOT NULL DEFAULT '',
    assigned_at INTEGER NOT NULL,
    last_download_at INTEGER,
    downloads INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_assignments_phone ON assignments(phone);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attempts (ts INTEGER NOT NULL, ip TEXT NOT NULL, kind TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_attempts ON attempts(kind, ts);
CREATE TABLE IF NOT EXISTS captchas (id TEXT PRIMARY KEY, answer TEXT NOT NULL, ts INTEGER NOT NULL);
"""


def connect():
    c = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=10000")
    return c


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = connect()
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM settings WHERE key='code'").fetchone():
        code = os.environ.get("PORTAL_CODE", "")
        if not re.fullmatch(r"\d{5}", code):
            code = f"{secrets.randbelow(100000):05d}"
        c.execute("INSERT INTO settings(key, value) VALUES('code', ?)", (code,))
    c.close()


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    c = g.pop("db", None)
    if c is not None:
        c.close()


init_db()

# --------------------------------------------------------------------------- вспомогательное

SLOT_RE = re.compile(r"^client(\d{3,})\.conf$")


def all_slots():
    if not CONF_DIR.is_dir():
        return []
    slots = []
    for f in CONF_DIR.iterdir():
        m = SLOT_RE.match(f.name)
        if m:
            slots.append(int(m.group(1)))
    return sorted(slots)


def now():
    return int(time.time())


def fmt(ts):
    return datetime.fromtimestamp(ts, TZ).strftime("%d.%m.%Y %H:%M") if ts else "—"


def client_ip():
    if request.remote_addr in ("127.0.0.1", "::1"):
        return request.headers.get("X-Real-IP") or request.remote_addr
    return request.remote_addr


def normalize_phone(raw):
    """+7XXXXXXXXXX из ввода вида +7…, 8…, 7… или просто 10 цифр; иначе None."""
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 11 and digits[0] in "78":
        digits = digits[1:]
    # российский номер: 10 цифр после +7/8, код региона начинается с 3, 4, 8 или 9
    if len(digits) != 10 or digits[0] not in "3489":
        return None
    return "+7" + digits


def phone_display(p):
    return f"{p[:2]} {p[2:5]} {p[5:8]}-{p[8:10]}-{p[10:12]}"


def clean_text(s, max_len):
    s = re.sub(r"[\x00-\x1f\x7f]", " ", s or "")
    return re.sub(r"\s+", " ", s).strip()[:max_len]


def mask_phone(p):
    return p[:5] + "***" + p[-2:]


def csv_safe(s):
    return "'" + s if s and s[0] in "=+-@\t\r" else s


def record_attempt(kind):
    c = db()
    c.execute("INSERT INTO attempts(ts, ip, kind) VALUES(?,?,?)", (now(), client_ip(), kind))
    c.execute("DELETE FROM attempts WHERE ts < ?", (now() - 86400,))


def count_attempts(kind, window, per_ip):
    q = "SELECT COUNT(*) FROM attempts WHERE kind=? AND ts>?"
    args = [kind, now() - window]
    if per_ip:
        q += " AND ip=?"
        args.append(client_ip())
    return db().execute(q, args).fetchone()[0]


def blocked(kind, ip_limit, all_limit=None):
    if count_attempts(kind, ip_limit[1], True) >= ip_limit[0]:
        return True
    return bool(all_limit) and count_attempts(kind, all_limit[1], False) >= all_limit[0]


def auth_fail(kind):
    """Запись для fail2ban о неудачной попытке входа."""
    auth_log.info("AUTHFAIL ip=%s kind=%s", client_ip(), kind)


FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    "DejaVuSans-Bold.ttf",
]


def _font(size):
    for p in FONT_PATHS:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def captcha_png(answer):
    """Картинка с искажёнными символами, шумом и линиями (собственная капча без внешних сервисов)."""
    rng = random.SystemRandom()
    w, h = 200, 70
    img = Image.new("RGB", (w, h), (255, 255, 255))
    d = ImageDraw.Draw(img)
    for _ in range(7):  # фоновые линии
        d.line([(rng.randint(0, w), rng.randint(0, h)), (rng.randint(0, w), rng.randint(0, h))],
               fill=(rng.randint(150, 220),) * 3, width=rng.randint(1, 2))
    font = _font(44)
    x = 10
    for ch in answer:
        tile = Image.new("RGBA", (50, 62), (255, 255, 255, 0))
        ImageDraw.Draw(tile).text((8, 4), ch, font=font, fill=(rng.randint(0, 80), rng.randint(0, 80), rng.randint(0, 120), 255))
        tile = tile.rotate(rng.randint(-28, 28), resample=Image.BICUBIC)
        img.paste(tile, (x, rng.randint(0, 8)), tile)
        x += 33 + rng.randint(-3, 3)
    for _ in range(3):  # линии поверх текста
        d.line([(0, rng.randint(15, 55)), (w, rng.randint(15, 55))], fill=(rng.randint(60, 140),) * 3, width=2)
    for _ in range(160):  # точки
        px, py = rng.randint(0, w - 1), rng.randint(0, h - 1)
        d.point((px, py), fill=(rng.randint(0, 160),) * 3)
    img = img.filter(ImageFilter.SMOOTH)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def new_captcha():
    """Создаёт одноразовую капчу и возвращает её id (None, если с этого IP слишком много запросов)."""
    if blocked("captcha_new", LIMIT_CAPTCHA_NEW_IP):
        return None
    record_attempt("captcha_new")
    cid = secrets.token_urlsafe(12)
    answer = "".join(secrets.choice(CAPTCHA_CHARS) for _ in range(5))
    c = db()
    c.execute("DELETE FROM captchas WHERE ts < ?", (now() - 2 * CAPTCHA_TTL,))
    c.execute("INSERT INTO captchas(id, answer, ts) VALUES(?,?,?)", (cid, answer, now()))
    return cid


def verify_captcha(cid, answer):
    """Проверка ответа. Капча одноразовая: после любой проверки удаляется."""
    c = db()
    c.execute("BEGIN IMMEDIATE")
    try:
        row = c.execute("SELECT answer, ts FROM captchas WHERE id=?", (cid or "",)).fetchone()
        c.execute("DELETE FROM captchas WHERE id=?", (cid or "",))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    if not row or now() - row["ts"] > CAPTCHA_TTL:
        return False
    given = re.sub(r"\s", "", answer or "").upper()
    return hmac.compare_digest(given.encode(), row["answer"].encode())


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
        return False
    return True


def current_person():
    phone = session.get("phone")
    if not phone:
        return None
    return db().execute("SELECT * FROM people WHERE phone=?", (phone,)).fetchone()


def is_admin():
    return bool(session.get("admin")) and time.time() - session.get("admin_at", 0) < ADMIN_SESSION_SECONDS


def page(template, **ctx):
    ctx["messages"] = get_flashed_messages(with_categories=True)
    ctx["csrf"] = csrf_token()
    return render_template(template, **ctx)


@app.after_request
def headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    )
    return resp


# --------------------------------------------------------------------------- страницы сотрудника

@app.route("/")
def index():
    person = current_person()
    if not person:
        return page("login.html", captcha_id=new_captcha())
    rows = db().execute(
        "SELECT slot, label, assigned_at FROM assignments WHERE phone=? ORDER BY assigned_at, slot", (person["phone"],)
    ).fetchall()
    devices = [{"slot": r["slot"], "label": r["label"], "at": fmt(r["assigned_at"])} for r in rows]
    return page("dashboard.html", name=person["name"] or "Без имени", phone=phone_display(person["phone"]),
                devices=devices, max_devices=MAX_DEVICES)


@app.route("/login", methods=["POST"])
def login():
    if not check_csrf():
        flash("Сессия устарела, попробуйте ещё раз.", "err")
        return redirect("/")
    if blocked("login", LIMIT_LOGIN_IP, LIMIT_LOGIN_ALL) or blocked("captcha", LIMIT_CAPTCHA_IP):
        flash("Слишком много неверных попыток. Подождите около 15 минут и попробуйте снова.", "err")
        return redirect("/")
    phone = normalize_phone(request.form.get("phone"))
    if not phone:
        flash("Введите номер телефона в формате +7… или 8… (10 цифр после кода страны).", "err")
        return redirect("/")
    if not verify_captcha(request.form.get("captcha_id", ""), request.form.get("captcha", "")):
        record_attempt("captcha")
        auth_fail("captcha")
        flash("Неверные символы с картинки. Попробуйте ещё раз.", "err")
        return redirect("/")
    code = re.sub(r"\D", "", request.form.get("code", ""))
    real = db().execute("SELECT value FROM settings WHERE key='code'").fetchone()["value"]
    if not hmac.compare_digest(code, real):
        record_attempt("login")
        auth_fail("code")
        log.info("login: неверный код ip=%s", client_ip())
        flash("Неверный код доступа.", "err")
        return redirect("/")
    name = clean_text(request.form.get("name"), 80)
    c = db()
    person = c.execute("SELECT * FROM people WHERE phone=?", (phone,)).fetchone()
    if not person:
        if len(name) < 2:
            flash("При первом входе укажите фамилию и имя.", "err")
            return redirect("/")
        c.execute("INSERT INTO people(phone, name, created_at) VALUES(?,?,?)", (phone, name, now()))
        log.info("login: новый человек %s", mask_phone(phone))
    else:
        if not person["name"] and name:
            c.execute("UPDATE people SET name=? WHERE phone=?", (name, phone))
        log.info("login: вход %s", mask_phone(phone))
    session.clear()
    session.permanent = True
    session["phone"] = phone
    csrf_token()
    return redirect("/")


@app.route("/logout", methods=["POST"])
def logout():
    if check_csrf():
        session.clear()
    return redirect("/")


@app.route("/claim", methods=["POST"])
def claim():
    person = current_person()
    if not person:
        return redirect("/")
    if not check_csrf():
        flash("Сессия устарела, обновите страницу.", "err")
        return redirect("/")
    if blocked("claim", LIMIT_CLAIM_IP):
        flash("Слишком много запросов. Попробуйте позже.", "err")
        return redirect("/")
    label = clean_text(request.form.get("label"), 30)
    c = db()
    c.execute("BEGIN IMMEDIATE")
    try:
        have = c.execute("SELECT COUNT(*) FROM assignments WHERE phone=?", (person["phone"],)).fetchone()[0]
        if have >= MAX_DEVICES:
            c.execute("ROLLBACK")
            flash(f"Вам уже выдано максимальное число конфигов ({MAX_DEVICES}).", "err")
            return redirect("/")
        taken = {r[0] for r in c.execute("SELECT slot FROM assignments")}
        free = [s for s in all_slots() if s not in taken]
        if not free:
            c.execute("ROLLBACK")
            log.warning("claim: свободные конфиги закончились")
            flash("Свободные конфиги закончились. Обратитесь к администратору.", "err")
            return redirect("/")
        slot = free[0]
        c.execute("INSERT INTO assignments(slot, phone, label, assigned_at) VALUES(?,?,?,?)",
                  (slot, person["phone"], label, now()))
        c.execute("COMMIT")
    except Exception:
        try:
            c.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    record_attempt("claim")
    log.info("claim: %s получил конфиг №%03d", mask_phone(person["phone"]), slot)
    flash(f"Конфиг №{slot:03d} выдан. Скачайте его ниже.", "ok")
    return redirect("/")


@app.route("/d/<int:slot>/conf")
def download(slot):
    person = current_person()
    if not person:
        return Response("Требуется вход", status=403, mimetype="text/plain")
    c = db()
    row = c.execute("SELECT phone FROM assignments WHERE slot=?", (slot,)).fetchone()
    if not row or row["phone"] != person["phone"]:
        return Response("Не найдено", status=404, mimetype="text/plain")
    path = CONF_DIR / f"client{slot:03d}.conf"
    if not path.is_file():
        return Response("Файл конфига не найден, сообщите администратору", status=500, mimetype="text/plain")
    c.execute("UPDATE assignments SET downloads=downloads+1, last_download_at=? WHERE slot=?", (now(), slot))
    return Response(path.read_bytes(), mimetype="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="3dit-vpn-{slot:03d}.conf"',
    })


@app.route("/captcha/<cid>.png")
def captcha_image(cid):
    row = db().execute("SELECT answer, ts FROM captchas WHERE id=?", (cid,)).fetchone()
    if not row or now() - row["ts"] > CAPTCHA_TTL:
        return Response("Не найдено", status=404, mimetype="text/plain")
    return Response(captcha_png(row["answer"]), mimetype="image/png")


# --------------------------------------------------------------------------- администратор

def admin_required():
    if not is_admin():
        return redirect("/admin/login")
    return None


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return page("admin_login.html", captcha_id=new_captcha())
    if not check_csrf():
        flash("Сессия устарела, попробуйте ещё раз.", "err")
        return redirect("/admin/login")
    admin_pw = os.environ.get("ADMIN_PASSWORD", "")
    if len(admin_pw) < 8:
        flash("Пароль администратора не настроен на сервере.", "err")
        return redirect("/admin/login")
    if blocked("admin", LIMIT_ADMIN_IP, LIMIT_ADMIN_ALL) or blocked("captcha", LIMIT_CAPTCHA_IP):
        flash("Слишком много неверных попыток. Подождите около 15 минут.", "err")
        return redirect("/admin/login")
    if not verify_captcha(request.form.get("captcha_id", ""), request.form.get("captcha", "")):
        record_attempt("captcha")
        auth_fail("admin-captcha")
        flash("Неверные символы с картинки. Попробуйте ещё раз.", "err")
        return redirect("/admin/login")
    if not hmac.compare_digest(request.form.get("password", "").encode(), admin_pw.encode()):
        record_attempt("admin")
        auth_fail("admin-password")
        log.warning("admin: неверный пароль ip=%s", client_ip())
        flash("Неверный пароль.", "err")
        return redirect("/admin/login")
    phone = session.get("phone")
    session.clear()
    if phone:
        session["phone"] = phone
        session.permanent = True
    session["admin"] = True
    session["admin_at"] = time.time()
    csrf_token()
    log.info("admin: вход ip=%s", client_ip())
    return redirect("/admin")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    if check_csrf():
        session.pop("admin", None)
        session.pop("admin_at", None)
    return redirect("/admin/login")


def load_people():
    c = db()
    people = {}
    for p in c.execute("SELECT phone, name, created_at FROM people ORDER BY created_at, phone"):
        people[p["phone"]] = {"phone": phone_display(p["phone"]), "raw": p["phone"], "name": p["name"],
                              "created": p["created_at"], "confs": [], "first_ts": None, "last_ts": None}
    for a in c.execute("SELECT slot, phone, label, assigned_at, last_download_at FROM assignments ORDER BY assigned_at, slot"):
        p = people.get(a["phone"])
        if p is None:
            continue
        p["confs"].append({"slot": a["slot"], "label": a["label"]})
        p["first_ts"] = min(p["first_ts"] or a["assigned_at"], a["assigned_at"])
        if a["last_download_at"]:
            p["last_ts"] = max(p["last_ts"] or 0, a["last_download_at"])
    out = list(people.values())
    for p in out:
        p["first"] = fmt(p["first_ts"])
        p["last"] = fmt(p["last_ts"])
    return out


@app.route("/admin")
def admin():
    r = admin_required()
    if r:
        return r
    people = load_people()
    slots = all_slots()
    used = db().execute("SELECT COUNT(*) FROM assignments").fetchone()[0]
    by_count = {1: 0, 2: 0, 3: 0}
    for p in people:
        n = len(p["confs"])
        if n in by_count:
            by_count[n] += 1
    code = db().execute("SELECT value FROM settings WHERE key='code'").fetchone()["value"]
    return page("admin.html", people=people, total=len(slots), used=used, free=max(len(slots) - used, 0),
                by_count=by_count, code=code)


@app.route("/admin/release/<int:slot>", methods=["POST"])
def admin_release(slot):
    r = admin_required()
    if r:
        return r
    if not check_csrf():
        flash("Сессия устарела, обновите страницу.", "err")
        return redirect("/admin")
    cur = db().execute("DELETE FROM assignments WHERE slot=?", (slot,))
    if cur.rowcount:
        log.info("admin: освобождён конфиг №%03d", slot)
        flash(f"Конфиг №{slot:03d} освобождён.", "ok")
    return redirect("/admin")


@app.route("/admin/code", methods=["POST"])
def admin_code():
    r = admin_required()
    if r:
        return r
    if not check_csrf():
        flash("Сессия устарела, обновите страницу.", "err")
        return redirect("/admin")
    code = re.sub(r"\D", "", request.form.get("code", ""))
    if not code:
        code = f"{secrets.randbelow(100000):05d}"
    if not re.fullmatch(r"\d{5}", code):
        flash("Код должен состоять ровно из 5 цифр.", "err")
        return redirect("/admin")
    db().execute("UPDATE settings SET value=? WHERE key='code'", (code,))
    log.info("admin: код доступа изменён")
    flash(f"Код доступа изменён: {code}", "ok")
    return redirect("/admin")


@app.route("/admin/export.csv")
def admin_export():
    r = admin_required()
    if r:
        return r
    buf = io.StringIO()
    buf.write("﻿")  # BOM, чтобы Excel правильно открыл кириллицу
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Фамилия Имя", "Телефон", "Конфигов", "Конфиги", "Первая выдача", "Последнее скачивание"])
    for p in load_people():
        confs = ", ".join(f"№{i['slot']:03d}" + (f" ({csv_safe(i['label'])})" if i["label"] else "") for i in p["confs"])
        w.writerow([csv_safe(p["name"]), p["raw"], len(p["confs"]), confs, p["first"], p["last"]])
    return Response(buf.getvalue(), mimetype="text/csv; charset=utf-8", headers={
        "Content-Disposition": 'attachment; filename="vpn-access.csv"',
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8081)
