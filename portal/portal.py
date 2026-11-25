#!/usr/bin/env python3
"""Портал выдачи VPN-конфигов (ООО «Тридит»), несколько организаций.

Один общий QR ведёт на портал. Сотрудник вводит код доступа СВОЕЙ организации (5 цифр), телефон и фамилию с
именем (без SMS; имя нужно только для таблицы) и решает капчу. Он получает первый свободный конфиг из общего пула;
на человека число конфигов не ограничено (по одному на устройство), пока хватает лимита ключей организации;
администратор может вручную задать лимит устройств для конкретного человека. Скачать свой конфиг можно повторно.

Уровни доступа:
  * сотрудник      : /                      (код организации + телефон)
  * админ организации: /org/login → /org     (логин и пароль выдаёт общий админ; видит только свою организацию)
  * общий админ    : /super/login → /super   (организации, коды, лимиты ключей, включение и отключение доступа,
                                              зашифрованная резервная копия всех ключей для переезда)

Отключение организации и освобождение конфига действуют и на VPN-сервере: портал пишет peers.json со списком
разрешённых пиров, а служба vpn-peer-sync (root, scripts/sync-peers.py) применяет его к интерфейсу awg0.

Запуск (см. deploy/vpn-portal.service):  gunicorn --bind 127.0.0.1:8081 portal:app

Переменные окружения:
    PORTAL_SECRET_KEY     секрет подписи сессий (обязателен)
    SUPERADMIN_PASSWORD   пароль общего администратора, не короче 8 символов (запасное имя: ADMIN_PASSWORD)
    PORTAL_DATA           каталог данных (по умолчанию /var/lib/vpn-portal)
    PORTAL_CONFIGS        каталог с файлами clientNNN.conf (по умолчанию $PORTAL_DATA/configs)
    PORTAL_PEERS          путь к peers.json (по умолчанию $PORTAL_DATA/peers.json)
    PORTAL_LOG_DIR        каталог логов (по умолчанию /var/log/vpn-portal)
    PORTAL_TZ             часовой пояс отображения (по умолчанию Europe/Samara)
    PORTAL_DEV=1          режим разработки (кука без Secure, секрет генерируется сам)
"""
import base64
import csv
import fcntl
import hashlib
import hmac
import io
import json
import logging
import os
import random
import re
import secrets
import sqlite3
from contextlib import nullcontext
import time
import uuid
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from flask import Flask, Response, flash, g, get_flashed_messages, redirect, render_template, request, session
from jinja2 import DictLoader
from PIL import Image, ImageDraw, ImageFilter, ImageFont

import backup

DEV = os.environ.get("PORTAL_DEV") == "1"
DATA_DIR = Path(os.environ.get("PORTAL_DATA", "/var/lib/vpn-portal"))
CONF_DIR = Path(os.environ.get("PORTAL_CONFIGS", str(DATA_DIR / "configs")))
TRAFFIC_FILE = Path(os.environ.get("PORTAL_TRAFFIC", str(DATA_DIR / "traffic.json")))
PEERS_FILE = Path(os.environ.get("PORTAL_PEERS", str(DATA_DIR / "peers.json")))


def parse_servers(raw):
    """PORTAL_SERVERS="auto|vpn.3dit.ru|Авто;fi|fi-1-vpn.3dit.ru|Финляндия-1;all|vpn.3dit.ru|Авто, весь трафик|full":
    варианты Endpoint при выдаче конфига; четвёртое поле full: весь трафик через VPN (AllowedIPs = 0.0.0.0/0, ::/0)."""
    out = []
    for part in (raw or "").split(";"):
        bits = [b.strip() for b in part.split("|")]
        if len(bits) in (3, 4) and re.fullmatch(r"[a-z0-9]{1,12}", bits[0]) and re.fullmatch(r"[A-Za-z0-9.-]{1,100}", bits[1]) and bits[2]:
            out.append({"key": bits[0], "host": bits[1], "title": bits[2][:40], "full": len(bits) == 4 and bits[3] == "full"})
    return out


SERVERS = parse_servers(os.environ.get("PORTAL_SERVERS"))
WG_SERVERS = parse_servers(os.environ.get("PORTAL_WG_SERVERS"))
WG_GATEWAYS = {}
if WG_SERVERS or os.environ.get("PORTAL_WG_ENDPOINT"):
    from wireguard_profile import Gateway, client_address

    key, dns = os.environ["PORTAL_WG_PUBLIC_KEY"], os.environ.get("PORTAL_WG_DNS", "")
    if WG_SERVERS:
        port = int(os.environ.get("PORTAL_WG_PORT", "51822"))
        WG_GATEWAYS = {s["key"]: Gateway(f"{s['host']}:{port}", key, dns, full=s["full"]) for s in WG_SERVERS}
    else:
        WG_GATEWAYS["default"] = Gateway(os.environ["PORTAL_WG_ENDPOINT"], key, dns)
XRAY_STATE = Path(os.environ.get("XRAY_STATE", "/etc/vpn-xray.json"))
XRAY_UI = os.environ.get("PORTAL_XRAY_UI") == "1"  # кнопка «Ссылка для Happ»: пока выключена, включается PORTAL_XRAY_UI=1
DB_PATH = DATA_DIR / "portal.db"
SHARED_DSN = os.environ.get("PORTAL_DB_DSN")
if SHARED_DSN:
    import postgres_backend
    import router_gateway_inventory
ADMIN_SESSION_SECONDS = 8 * 3600
MAX_ORG_LIMIT = 10000
DEFAULT_ORG_LIMIT = 10

# лимиты попыток: (максимум, окно в секундах)
LIMIT_LOGIN_IP = (5, 15 * 60)        # неверных кодов с одного IP
LIMIT_LOGIN_ALL = (40, 60 * 60)      # неверных кодов всего (защита от перебора с многих адресов)
LIMIT_ADMIN_IP = (5, 15 * 60)
LIMIT_ADMIN_ALL = (20, 60 * 60)
LIMIT_CLAIM_IP = (10, 60 * 60)       # выдач конфигов с одного IP в час
LIMIT_CAPTCHA_IP = (10, 15 * 60)     # неверных ответов на капчу с одного IP
LIMIT_CAPTCHA_NEW_IP = (30, 10 * 60)  # показов капчи с одного IP (защита от заливки базы)
CAPTCHA_TTL = 300
CAPTCHA_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # без похожих 0/O, 1/I
PASSWORD_CHARS = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,29}$")

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo(os.environ.get("PORTAL_TZ", "Europe/Samara"))
except Exception:  # старый Python или нет tzdata
    TZ = timezone(timedelta(hours=4))

app = Flask(__name__)
if SHARED_DSN:
    @app.errorhandler(postgres_backend.Unavailable)
    def database_unavailable(_error):
        return Response("База временно недоступна. Повторите запрос.", status=503,
                        headers={"Retry-After": "5"}, mimetype="text/plain")
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
main.wide { max-width:1150px; }
h1 { font-size:22px; margin:8px 0 4px; }
.portal-head { padding:clamp(16px,4vw,24px); margin:0 0 16px; border-radius:16px; color:#fff; background:radial-gradient(ellipse at 98% 20%, #245dac 0%, transparent 64%), #132547; }
.portal-head h1 { font-size:clamp(24px,5vw,32px); line-height:1.15; margin:4px 0; }
.portal-head p { margin:0; color:#dceaff; }
.portal-head a { display:inline-block; margin-top:10px; color:#fff; font-weight:600; text-underline-offset:.2em; }
.portal-head a:focus-visible { outline:2px solid #fff; outline-offset:3px; }
h2 { font-size:17px; margin:0 0 8px; }
a { color:var(--accent); }
.sub { color:var(--muted); margin:0 0 16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; margin:0 0 12px; }
.btn { display:block; width:100%; text-align:center; padding:13px 16px; border-radius:10px; border:0; font:inherit; font-weight:600; text-decoration:none; cursor:pointer; margin:8px 0 0; }
.primary { background:var(--accent); color:#fff; }
.secondary { background:transparent; color:var(--accent); border:1px solid var(--accent); }
.danger { background:transparent; color:var(--errfg); border:1px solid var(--errfg); }
.sm { padding:4px 10px; width:auto; display:inline-block; margin:2px 0; font-size:13px; }
label { display:block; margin:12px 0 4px; font-weight:600; }
input[type=text], input[type=tel], input[type=password], input[type=number] { width:100%; padding:12px; border-radius:10px; border:1px solid var(--line); background:var(--bg); color:var(--fg); font:inherit; }
.msg { border-radius:10px; padding:12px 14px; margin:0 0 12px; font-size:15px; word-break:break-word; }
.msg.ok { background:var(--ok); color:var(--okfg); }
.msg.err { background:var(--err); color:var(--errfg); }
.warn { background:var(--warn); color:var(--warnfg); border-radius:10px; padding:12px 14px; margin:0 0 12px; font-size:15px; }
.dev { border-top:1px solid var(--line); padding:12px 0; }
.dev:first-of-type { border-top:0; }
small, .muted { color:var(--muted); }
.app { display:flex; justify-content:space-between; gap:8px; align-items:center; padding:8px 0; border-top:1px solid var(--line); flex-wrap:wrap; }
.app:first-of-type { border-top:0; }
.app.me { font-weight:600; }
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
.badge { display:inline-block; padding:2px 10px; border-radius:99px; font-size:13px; font-weight:600; }
.badge.on { background:var(--ok); color:var(--okfg); }
.badge.off { background:var(--err); color:var(--errfg); }
.bar { height:8px; border-radius:99px; background:var(--line); overflow:hidden; min-width:80px; }
.bar > i { display:block; height:100%; background:var(--accent); }
.bar.full > i { background:var(--errfg); }
.inline { display:inline; }
code { background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:1px 6px; font-size:14px; }
/* Overview for the VPN super administrator */
.admin-overview { padding-block:24px 40px; }
.admin-overview .portal-head {
  padding:clamp(20px,4vw,36px);
  background:radial-gradient(ellipse at 90% 15%, #245dac, transparent 70%), linear-gradient(110deg,#101d39,#172f53);
}
.admin-overview .portal-head h1 { margin:8px 0; font-size:clamp(24px,5vw,36px); }
.admin-overview .admin-brand { font-size:13px; font-weight:750; letter-spacing:.08em; }
.admin-header-row, .admin-section-head {
  display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px 16px;
}
.admin-overview .portal-head form { margin:0; }
.admin-overview .portal-head .btn {
  margin:0; color:#fff; border:1px solid #a9c5e8; background:#142c4e;
}
.admin-pool { margin-top:20px; max-width:32rem; }
.admin-pool meter {
  display:block; appearance:none; width:100%; height:12px; margin-top:6px; background:none;
}
.admin-pool meter::-webkit-meter-bar { background:#47628a; border:0; border-radius:99px; }
.admin-pool meter::-webkit-meter-optimum-value { background:#94c4ff; border-radius:99px; }
.admin-pool meter::-moz-meter-bar { background:#94c4ff; border-radius:99px; }
.admin-nav { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 16px; }
.admin-nav a {
  display:inline-flex; align-items:center; min-height:40px; padding:6px 12px;
  border:1px solid var(--line); border-radius:99px; background:var(--card); font-weight:650; text-decoration:none;
}
.admin-nav a:hover { border-color:var(--accent); text-decoration:underline; }
.admin-overview .stats { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); margin-bottom:16px; }
.admin-overview .stat { display:flex; flex-direction:column; gap:4px; padding:12px 14px; color:var(--muted); font-size:13px; }
.admin-overview .stat b { color:var(--fg); font-size:clamp(21px,3vw,30px); line-height:1.15; font-variant-numeric:tabular-nums; }
.admin-overview .stat.available { border-color:var(--okfg); background:var(--ok); color:var(--okfg); }
.admin-overview .stat.available b { color:inherit; }
.admin-overview .card { padding:clamp(12px,2vw,20px); margin-bottom:16px; }
.admin-overview .primary { background:#245dac; color:#fff; }
.admin-overview :where(a, button, input, .scroll):focus-visible { outline:2px solid var(--accent); outline-offset:3px; }
.admin-overview .portal-head .btn:focus-visible { outline-color:white; }
.admin-overview :where(section) { scroll-margin-top:16px; }
.admin-section-head h2 { margin:0; }
.admin-section-head { margin-bottom:12px; }
.admin-table { min-width:850px; font-variant-numeric:tabular-nums; }
.admin-table th { background:var(--bg); }
.admin-table :is(th,td) { vertical-align:middle; }
.admin-table tbody tr:hover { background:var(--bg); }
.admin-table tbody :is(th,td) { padding-block:10px; }
.admin-table tbody th { background:transparent; color:var(--fg); white-space:normal; overflow-wrap:anywhere; }
.admin-table .capacity { min-width:95px; }
.admin-limit-controls, .admin-limit-controls .inline {
  display:flex; align-items:center; flex-wrap:wrap; gap:4px;
}
.admin-limit-controls input[type=number] { width:5.25rem; padding:4px 6px; }
.admin-create { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; align-items:end; }
.admin-create-footer { display:flex; flex-wrap:wrap; align-items:center; gap:8px 16px; margin-top:14px; }
.admin-create-footer .btn { width:auto; margin:0; }
.admin-create-footer small { overflow-wrap:anywhere; }
.admin-overview .admin-backup { display:flex; justify-content:space-between; flex-wrap:wrap; align-items:center; gap:12px; }
.admin-backup p { margin:0; color:var(--muted); }
.admin-backup .btn { margin:0; width:auto; }
.router-gateways { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:8px; list-style:none; padding:0; }
.router-gateways li { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:4px 8px; background:var(--bg); border:1px solid var(--line); border-radius:9px; padding:8px 10px; }
.router-profile-table { min-width:420px; }
.router-filter { display:flex; flex-wrap:wrap; gap:8px 12px; align-items:end; margin:0 0 12px; }
.router-filter[hidden] { display:none; }
.router-filter > label { flex:1 1 11rem; margin:0; }
.router-filter > label:first-child { flex-basis:16rem; }
.router-filter :is(input, select) { display:block; min-height:42px; margin-top:4px; }
.router-filter select { width:100%; border:1px solid var(--line); border-radius:10px; padding:8px 10px; background:var(--bg); color:var(--fg); font:inherit; }
.router-filter .btn { flex:0 0 auto; width:auto; min-height:42px; margin:0; }
.router-profile-table tbody th { color:var(--fg); white-space:normal; overflow-wrap:anywhere; }
.admin-scroll-hint { display:none; margin:0 0 8px; color:var(--muted); }
@media (max-width:920px) { .admin-scroll-hint { display:block; } }
@media (max-width:700px) {
  .admin-overview .stats { grid-template-columns:repeat(3,minmax(0,1fr)); gap:8px; }
  .admin-create { grid-template-columns:repeat(2,minmax(0,1fr)); }
}
@media (max-width:390px) {
  .admin-overview .stats { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .admin-create { grid-template-columns:1fr; }
}
"""

PEOPLE_TABLE = """<div class="scroll"><table>
  <tr><th>Фамилия Имя</th><th>Телефон</th><th>Конфигов</th><th>Лимит устройств</th><th>Конфиги (устройства)</th><th>Трафик</th><th>Первая выдача</th><th>Последнее скачивание</th></tr>
  {% for p in people %}
  <tr>
    <td>{{ p.name or '—' }}</td>
    <td>{{ p.phone }}</td>
    <td>{{ p.confs|length }}</td>
    <td>
      {% if can_release %}
      <form method="post" action="{{ limit_url }}{{ p.id }}/limit" class="inline">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <input name="limit" type="text" inputmode="numeric" maxlength="4" value="{{ p.dev_limit if p.dev_limit is not none else '' }}" placeholder="без лимита" style="width:6.5em;padding:4px 8px;margin:0">
        <button class="btn secondary sm" type="submit">OK</button>
      </form>
      {% else %}{{ p.dev_limit if p.dev_limit is not none else 'без лимита' }}{% endif %}
    </td>
    <td>
      {% for a in p.confs %}
      <form method="post" action="{{ release_url }}{{ a.slot }}" class="inline" onsubmit="return confirm('Освободить конфиг №{{ '%03d' % a.slot }}? Ключ будет заменён: устройство, где он установлен, перестанет подключаться, а конфиг вернётся в пул.');">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        №{{ '%03d' % a.slot }}{% if a.label %} · {{ a.label }}{% endif %}
        {% if can_release %}<button class="btn danger sm" type="submit">Освободить</button>{% endif %}
      </form><br>
      {% else %}<span class="muted">нет</span>{% endfor %}
    </td>
    <td title="скачано клиентом / отправлено клиентом">{{ fmt_bytes(p.total) }}<br><small class="muted">↓ {{ fmt_bytes(p.tx) }} · ↑ {{ fmt_bytes(p.rx) }}</small></td>
    <td>{{ p.first }}</td>
    <td>{{ p.last }}</td>
  </tr>
  {% else %}
  <tr><td colspan="8" class="muted">Пока никто не получал конфиги.</td></tr>
  {% endfor %}
</table></div>"""

AUDIT_TABLE = """{% if audit %}<div class="card scroll"><h2>Последние действия</h2><table>
  <tr><th>Время</th><th>Кто</th><th>Действие</th><th>Подробности</th></tr>
  {% for e in audit %}<tr><td>{{ e.at }}</td><td>{{ e.actor }}</td><td>{{ e.action }}</td><td>{{ e.details }}</td></tr>{% endfor %}
</table></div>{% endif %}"""

TEMPLATES = {
    "captcha.html": """{% if captcha_id %}
<label for="captcha">Символы с картинки</label>
<img src="/captcha/{{ captcha_id }}.png" width="200" height="70" alt="Проверочные символы" style="display:block;background:#fff;border-radius:8px;border:1px solid var(--line)">
<input type="hidden" name="captcha_id" value="{{ captcha_id }}">
<input id="captcha" name="captcha" type="text" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="8" required>
<small><a href="{{ refresh_url }}">Показать другую картинку</a></small>
{% else %}
<div class="msg err">Слишком много запросов. Подождите несколько минут и обновите страницу.</div>
{% endif %}""",

    "people_table.html": PEOPLE_TABLE,
    "audit_table.html": AUDIT_TABLE,

    "base.html": """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/x-icon" href="/apps/favicon.ico">
<meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer">
<title>{% block title %}Доступ к VPN{% endblock %}</title>
<style>""" + CSS + """</style></head>
<body><main class="{% block cls %}{% endblock %}">
{% for cat, text in messages %}<div class="msg {{ cat }}">{{ text }}</div>{% endfor %}
{% block content %}{% endblock %}
</main></body></html>""",

    "login.html": """{% extends "base.html" %}
{% block content %}
<header class="portal-head">
  <p>ООО «Тридит»</p>
  <h1>{{ "VPN для устройства из Guard" if from_guard else "Доступ к VPN" }}</h1>
  <a href="/apps/">Приложения для VPN</a>
</header>
<div class="card">
  {% if from_guard %}<p>Введите номер телефона и код организации. После входа конфиг сохранится в вашем профиле, когда вы нажмёте «Получить конфиг».</p>{% endif %}
  <form method="post" action="/login" autocomplete="on">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    {% if from_guard %}<input type="hidden" name="from_guard" value="1">{% endif %}
    <label for="code">Код доступа организации (5 цифр)</label>
    <input id="code" name="code" type="text" inputmode="numeric" pattern="[0-9]{5}" maxlength="5" autocomplete="off" required>
    <label for="phone">Номер телефона</label>
    <input id="phone" name="phone" type="tel" inputmode="tel" placeholder="+7 900 000-00-00 или 8 900 000-00-00" autocomplete="tel"{% if from_guard %} autofocus{% endif %} required>
    <label for="name">Фамилия и имя <small>(при первом входе)</small></label>
    <input id="name" name="name" type="text" maxlength="80" autocomplete="name" value="{{ name or '' }}">
    {% with refresh_url='/?from=guard' if from_guard else '/' %}{% include "captcha.html" %}{% endwith %}
    <button class="btn primary" type="submit"{% if not captcha_id %} disabled{% endif %}>Войти</button>
  </form>
  <p><small>Код доступа вам сообщил администратор вашей организации. Вход по номеру телефона без SMS: телефон нужен только для того, чтобы найти ваши конфиги при повторном входе.</small></p>
</div>
{% endblock %}""",

    "dashboard.html": """{% extends "base.html" %}
{% block content %}
<header class="portal-head">
  <h1>Доступ к VPN</h1>
  <p>{{ org_name }} · {{ name }} · {{ phone }}</p>
  <a href="/apps/">Приложения для VPN</a>
</header>

<div class="warn">Конфиг личный: не пересылайте его другим людям. Один конфиг работает только на одном устройстве. Для каждого следующего устройства получите отдельный конфиг ниже.</div>

<div class="card">
  <h2>Мои конфиги</h2>
  {% for d in devices %}
  <div class="dev" id="config-{{ d.slot }}">
    <b>Устройство {{ loop.index }}</b>{% if d.label %} · {{ d.label }}{% endif %}<br>
    <small>Конфиг №{{ '%03d' % d.slot }} · выдан {{ d.at }}</small>
    {% if servers %}<br><label>Сервер
      <select class="srv" data-slot="{{ d.slot }}">{% for sv in servers %}<option value="{{ sv.key }}">{{ sv.title }}</option>{% endfor %}</select></label>
    <small>«Авто»: подключение к доступному серверу. Региональный вариант выбирайте, если нужен конкретный сервер. Вариант «весь трафик» пускает через VPN весь интернет устройства, без разделения.</small><br>{% endif %}
    <a class="btn primary dl" href="/d/{{ d.slot }}/conf{% if servers %}?srv={{ servers[0].key }}{% endif %}">Скачать конфиг</a>
    <button class="btn secondary copy" type="button" data-url="/d/{{ d.slot }}/conf{% if servers %}?srv={{ servers[0].key }}{% endif %}">Скопировать конфиг</button>
    {% if d.wireguard and not wireguard_servers %}<a class="btn secondary" href="/d/{{ d.slot }}/conf?format=wireguard">Скачать WireGuard</a>{% endif %}
    {% if d.wireguard and wireguard_servers %}
    <form method="get" action="/d/{{ d.slot }}/conf">
      <input type="hidden" name="format" value="wireguard">
      <label>Сервер WireGuard
        <select name="srv">{% for sv in wireguard_servers %}<option value="{{ sv.key }}">{{ sv.title }}</option>{% endfor %}</select>
      </label>
      <button class="btn secondary" type="submit">Скачать WireGuard</button>
    </form>
    {% endif %}
    {% if xray %}<button class="btn secondary copy" type="button" data-what="Ссылка скопирована. В Happ: «+» → «Вставить из буфера обмена»." data-url="/d/{{ d.slot }}/vless{% if servers %}?srv={{ servers[0].key }}{% endif %}">Ссылка для Happ</button>{% endif %}
    <small class="copystate"></small>
  </div>
  {% else %}
  <p class="muted">Конфигов пока нет. Нажмите кнопку ниже, чтобы получить первый.</p>
  {% endfor %}

  <div id="claim-device">
  {% if from_guard %}
  <h2>Конфиг для устройства из Guard</h2>
  <p>Профиль {{ phone }} · {{ org_name }}. Здесь появится новый конфиг. Выданные ранее конфиги доступны в списке выше.</p>
  {% endif %}
  {% if dev_limit is none or devices|length < dev_limit %}
  <form method="post" action="/claim" onsubmit="return confirm('Получить {{ 'конфиг' if not devices else 'дополнительный конфиг' }}? Он закрепляется за вами.');">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    {% if from_guard %}
    <input type="hidden" name="from_guard" value="1">
    {% if not guard_phone_verified %}
    <label for="claim-phone">Подтвердите номер телефона профиля</label>
    <input id="claim-phone" type="tel" name="phone" inputmode="tel" autocomplete="tel" required>
    {% endif %}
    {% endif %}
    <label for="label">Название устройства <small>(необязательно)</small></label>
    <input id="label" name="label" type="text" maxlength="30" placeholder="например, iPhone">
    <button class="btn primary" type="submit">{% if not devices %}Получить конфиг{% else %}Получить конфиг для устройства {{ devices|length + 1 }}{% endif %}</button>
  </form>
  {% else %}
  <p><small>Выдано максимальное число конфигов ({{ dev_limit }}): такой лимит задал администратор организации.</small></p>
  {% endif %}
  </div>
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
  <p>Для файла WireGuard (.conf) <a href="/apps/#wireguard">скачайте WireGuard</a>.</p>
  {% if xray %}<p><small>Если VPN не подключается (например, в мобильной сети), используйте приложение <b>Happ</b>: нажмите «Ссылка для Happ», в Happ добавьте её из буфера обмена. Файлы Happ для Windows, macOS и Linux — на странице <a href="/apps/">приложений</a>, для телефонов — в App Store / Google Play.</small></p>{% endif %}
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
{% if servers %}
  document.querySelectorAll("select.srv").forEach(function (sel) {
    sel.addEventListener("change", function () {
      var dev = sel.closest(".dev"), u = "/d/" + sel.getAttribute("data-slot") + "/conf?srv=" + encodeURIComponent(sel.value);
      dev.querySelector("a.dl").setAttribute("href", u);
      dev.querySelector(".copy").setAttribute("data-url", u);
      var xb = dev.querySelector(".copy[data-what]");
      if (xb) xb.setAttribute("data-url", "/d/" + sel.getAttribute("data-slot") + "/vless?srv=" + encodeURIComponent(sel.value));
    });
  });
{% endif %}
  var btns = document.querySelectorAll(".copy");
  for (var i = 0; i < btns.length; i++) {
    btns[i].addEventListener("click", function () {
      var b = this, st = b.parentNode.querySelector(".copystate");
      function done(ok) { st.textContent = ok ? (b.getAttribute("data-what") || "Конфиг скопирован в буфер обмена.") : "Не удалось скопировать, используйте «Скачать конфиг»."; }
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
{% block title %}{{ title }}{% endblock %}
{% block content %}
<h1>{{ title }}</h1>
<div class="card">
  <form method="post" action="{{ action }}">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    {% if with_login %}
    <label for="slug">Логин организации</label>
    <input id="slug" name="slug" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required>
    {% endif %}
    <label for="pw">Пароль</label>
    <input id="pw" name="password" type="password" autocomplete="current-password" required>
    {% with refresh_url=action %}{% include "captcha.html" %}{% endwith %}
    <button class="btn primary" type="submit"{% if not captcha_id %} disabled{% endif %}>Войти</button>
  </form>
</div>
{% endblock %}""",

    "org.html": """{% extends "base.html" %}
{% block title %}{{ org.name }}: выдача конфигов{% endblock %}
{% block cls %}wide{% endblock %}
{% block content %}
<h1>{{ org.name }}</h1>
<p class="sub">Администратор организации · код доступа для сотрудников: <b>{{ org.code }}</b></p>
{% if not org.enabled %}<div class="msg err">Доступ вашей организации отключён общим администратором. Сотрудники не могут входить и подключаться. Изменения недоступны, обратитесь в поддержку: it@3dit.ru</div>{% endif %}
<div class="stats">
  <div class="stat"><b>{{ stats.issued }} из {{ org.key_limit }}</b>конфигов выдано</div>
  <div class="stat"><b>{{ stats.free_limit }}</b>можно выдать ещё</div>
  <div class="stat"><b>{{ stats.people }}</b>человек</div>
  <div class="stat"><b>{{ fmt_bytes(stats.total) }}</b>трафик всего</div>
</div>
{% if org.enabled and stats.free_limit == 0 %}<div class="msg err">Лимит ключей организации исчерпан. Чтобы увеличить его, обратитесь к общему администратору.</div>{% endif %}
<div class="card">
  {% with release_url='/org/release/', limit_url='/org/person/', can_release=org.enabled %}{% include "people_table.html" %}{% endwith %}
  <p><a href="/org/export.csv">Скачать таблицу (CSV)</a></p>
</div>
{% include "audit_table.html" %}
<form method="post" action="/org/logout"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link" type="submit">Выйти</button></form>
{% endblock %}""",

    "super.html": """{% extends "base.html" %}
{% block title %}Общий администратор{% endblock %}
{% block cls %}wide admin-overview{% endblock %}
{% block content %}
<header class="portal-head">
  <div class="admin-header-row">
    <p class="admin-brand">3DIT VPN</p>
    <form method="post" action="/super/logout">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <button class="btn sm" type="submit">Выйти</button>
    </form>
  </div>
  <h1>Общий администратор</h1>
  <p>Управление организациями и ключами VPN</p>
  {% if pool.total %}
  <div class="admin-pool">
    <p id="pool-usage">Сотрудникам выдано {{ pool.assigned }} из {{ pool.total }} ключей</p>
    <meter min="0" max="{{ pool.total }}" value="{{ pool.assigned }}" aria-labelledby="pool-usage"></meter>
  </div>
  {% endif %}
</header>
<nav class="admin-nav" aria-label="Разделы управления">
  <a href="#organizations">Организации</a>
  <a href="#create-organization">Добавить организацию</a>
  {% if router_inventory %}<a href="#router-vpn">VPN роутеров</a>{% endif %}
  <a href="#backup">Резервная копия</a>
  {% if audit %}<a href="#audit">Журнал действий</a>{% endif %}
</nav>
<div class="stats">
  <div class="stat"><b>{{ pool.total }}</b>Ключей в пуле</div>
  <div class="stat"><b>{{ pool.assigned }}</b>Выдано</div>
  <div class="stat{% if pool.free > 10 %} available{% endif %}"><b>{{ pool.free }}</b>Свободно</div>
  <div class="stat"><b>{{ pool.limits }}</b>Сумма лимитов</div>
  <div class="stat"><b>{{ orgs|length }}</b>Организаций</div>
</div>
{% if pool.limits > pool.total %}<div class="warn">Сумма лимитов ({{ pool.limits }}) больше пула ({{ pool.total }}): последним организациям ключей может не хватить. Нужно сгенерировать дополнительные конфиги (см. README).</div>{% endif %}
{% if pool.free == 0 %}<div class="msg err">Свободных ключей в пуле не осталось.</div>{% elif pool.free <= 10 %}<div class="msg err">В пуле осталось мало свободных ключей: {{ pool.free }}.</div>{% endif %}

<section id="organizations" class="card" aria-labelledby="org-heading">
  <div class="admin-section-head">
    <h2 id="org-heading">Организации</h2>
    <a class="btn secondary sm" href="/super/export.csv">Скачать сводку (CSV)</a>
  </div>
  <p class="admin-scroll-hint"><small>Прокрутите таблицу вправо, чтобы увидеть настройки доступа.</small></p>
  <div class="scroll" tabindex="0" role="region" aria-labelledby="org-heading">
  <table class="admin-table">
    <thead><tr><th scope="col">Организация</th><th scope="col">Логин</th><th scope="col">Код</th><th scope="col">Статус</th><th scope="col">Выдано / лимит</th><th scope="col">Трафик</th><th scope="col">Людей</th><th scope="col">Лимит ключей</th><th scope="col">Доступ</th></tr></thead>
    <tbody>
    {% for o in orgs %}
    <tr>
      <th scope="row"><a href="/super/org/{{ o.id }}">{{ o.name }}</a></th>
      <td>{{ o.slug }}{% if not o.has_admin %}<br><small class="muted">пароль не задан</small>{% endif %}</td>
      <td><code>{{ o.code }}</code></td>
      <td><span class="badge {{ 'on' if o.enabled else 'off' }}">{{ 'включена' if o.enabled else 'отключена' }}</span></td>
      <td class="capacity">{{ o.issued }} / {{ o.key_limit }}<div aria-hidden="true" class="bar{% if o.issued >= o.key_limit %} full{% endif %}"><i style="width:{{ o.percent }}%"></i></div></td>
      <td title="скачано клиентами / отправлено клиентами">{{ fmt_bytes(o.traffic) }}<br><small class="muted">↓ {{ fmt_bytes(o.tx) }} · ↑ {{ fmt_bytes(o.rx) }}</small></td>
      <td>{{ o.people }}</td>
      <td><div class="admin-limit-controls">
        <form method="post" action="/super/org/{{ o.id }}/limit" class="inline">
          <input type="hidden" name="csrf" value="{{ csrf }}">
          <input type="number" name="limit" value="{{ o.key_limit }}" min="0" max="{{ max_limit }}" aria-label="Лимит ключей для {{ o.name }}">
          <button class="btn secondary sm" type="submit">Сохранить</button>
        </form>
        <form method="post" action="/super/org/{{ o.id }}/limit" class="inline"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="delta" value="-10"><button class="btn secondary sm" type="submit">−10</button></form>
        <form method="post" action="/super/org/{{ o.id }}/limit" class="inline"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="delta" value="10"><button class="btn secondary sm" type="submit">+10</button></form>
      </div></td>
      <td>
        <form method="post" action="/super/org/{{ o.id }}/toggle" class="inline"{% if o.enabled %} onsubmit="return confirm('Отключить доступ организации «{{ o.name }}»? Её сотрудники потеряют доступ к порталу и к VPN.');"{% endif %}>
          <input type="hidden" name="csrf" value="{{ csrf }}">
          <button class="btn {{ 'danger' if o.enabled else 'primary' }} sm" type="submit">{{ 'Отключить' if o.enabled else 'Включить' }}</button>
        </form>
      </td>
    </tr>
    {% else %}
    <tr><td colspan="9" class="muted">Организаций пока нет. Добавьте первую ниже.</td></tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
</section>

<section id="create-organization" class="card" aria-labelledby="create-heading">
  <h2 id="create-heading">Добавить организацию</h2>
  <form method="post" action="/super/org/create">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="admin-create">
      <div><label for="n">Название</label><input id="n" name="name" type="text" maxlength="80" required></div>
      <div><label for="s">Логин администратора <small>(латиница, цифры, дефис)</small></label><input id="s" name="slug" type="text" maxlength="30" autocapitalize="none" required></div>
      <div><label for="l">Лимит ключей</label><input id="l" name="limit" type="number" min="0" max="{{ max_limit }}" value="{{ default_limit }}"></div>
      <div><label for="c">Код доступа <small>(5 цифр, пусто = случайный)</small></label><input id="c" name="code" type="text" inputmode="numeric" pattern="[0-9]{5}" maxlength="5"></div>
    </div>
    <div class="admin-create-footer">
      <button class="btn primary" type="submit">Создать организацию</button>
      <small>Пароль администратора создаётся автоматически и показывается один раз.</small>
    </div>
  </form>
</section>

{% if router_inventory %}
<section id="router-vpn" class="card" aria-labelledby="router-vpn-heading">
  <h2 id="router-vpn-heading">VPN роутеров через Guard</h2>
  <p class="sub">Отдельный пул. Один роутер может занимать по одному слоту на нескольких шлюзах.</p>
  {% if router_inventory.fresh %}
  <p><b>{{ router_inventory.routers|length }}</b> роутеров · <b>{{ router_inventory.profiles }}</b> профилей на ответивших шлюзах</p>
  {% endif %}
  <ul class="router-gateways">
    {% for g in router_inventory.gateways %}
    <li><b>{{ g.title }}</b>
      {% if g.fresh %}<span>{{ g.count }} профилей</span>
      {% elif g.collected %}<span class="badge off">Данные устарели</span>
      {% else %}<span class="badge off">Нет данных</span>{% endif %}
    </li>
    {% endfor %}
  </ul>
  {% if router_inventory.routers %}
  <div class="router-filter" hidden>
    <label>Имя роутера или VPN-адрес
      <input id="router-search" type="text" placeholder="Например, P63 или 10.9.3.6" autocomplete="off">
    </label>
    <label>Шлюз
      <select id="router-gateway">
        <option value="">Все шлюзы</option>
        {% for gateway in router_inventory.gateways %}
        {% if gateway.fresh %}<option value="{{ gateway.title }}">{{ gateway.title }}</option>{% endif %}
        {% endfor %}
      </select>
    </label>
    <button id="router-filter-reset" class="btn secondary sm" type="button">Сбросить</button>
  </div>
  <div class="scroll" tabindex="0" role="region" aria-label="Роутеры и адреса VPN">
    <table class="router-profile-table">
      <thead><tr><th scope="col">Роутер</th>{% for g in router_inventory.gateways %}<th scope="col">{{ g.title }}</th>{% endfor %}</tr></thead>
      <tbody>{% for router in router_inventory.routers %}
      <tr data-router="{{ router.name }}"><th scope="row">{{ router.name }}</th>{% for g in router_inventory.gateways %}<td data-gateway="{{ g.title }}" data-address="{{ router.addresses.get(g.title, '') }}">
        {% if router.addresses.get(g.title) %}<code>{{ router.addresses[g.title] }}</code>
        {% elif not g.fresh %}<small>Нет данных</small>{% else %}—{% endif %}
      </td>{% endfor %}</tr>
      {% endfor %}</tbody>
    </table>
  </div>
  <p id="router-filter-status" class="sub" role="status" hidden></p>
  <script>
  (function () {
    const section = document.getElementById("router-vpn");
    const filters = section.querySelector(".router-filter");
    const search = document.getElementById("router-search");
    const gateway = document.getElementById("router-gateway");
    const status = document.getElementById("router-filter-status");
    const rows = [...section.querySelectorAll("[data-router]")];
    function apply() {
      const query = search.value.trim().toLowerCase();
      let count = 0;
      for (const row of rows) {
        const addresses = [...row.querySelectorAll("[data-address]")]
          .filter(cell => cell.dataset.address && (!gateway.value || cell.dataset.gateway === gateway.value));
        const name = row.dataset.router.toLowerCase();
        row.hidden = !addresses.length || !(
          name.includes(query) || addresses.some(cell => cell.dataset.address.includes(query))
        );
        if (!row.hidden) count++;
      }
      status.hidden = !query && !gateway.value;
      status.textContent = count ? "Найдено " + count + " из " + rows.length : "Поиск ничего не нашёл.";
    }
    search.addEventListener("input", apply);
    gateway.addEventListener("change", apply);
    document.getElementById("router-filter-reset").addEventListener("click", function () {
      search.value = "";
      gateway.value = "";
      apply();
      search.focus();
    });
    filters.hidden = false;
  })();
  </script>
  {% endif %}
</section>
{% endif %}

<section id="backup" class="card admin-backup" aria-labelledby="backup-heading">
  <div>
    <h2 id="backup-heading">Резервная копия</h2>
    <p>Зашифрованный файл с ключами и настройками организаций для переезда на другой сервер.</p>
  </div>
  <a class="btn secondary sm" href="/super/backup">Создать копию</a>
</section>

{% if audit %}<section id="audit" aria-label="Журнал действий">{% include "audit_table.html" %}</section>{% endif %}
{% endblock %}""",

    "super_org.html": """{% extends "base.html" %}
{% block title %}{{ org.name }}{% endblock %}
{% block cls %}wide{% endblock %}
{% block content %}
<p><a href="/super">← Все организации</a></p>
<h1>{{ org.name }} <span class="badge {{ 'on' if org.enabled else 'off' }}">{{ 'включена' if org.enabled else 'отключена' }}</span></h1>
<p class="sub">Логин администратора: <b>{{ org.slug }}</b> · код доступа: <code>{{ org.code }}</code></p>
<div class="stats">
  <div class="stat"><b>{{ stats.issued }} из {{ org.key_limit }}</b>конфигов выдано</div>
  <div class="stat"><b>{{ stats.free_limit }}</b>осталось в лимите</div>
  <div class="stat"><b>{{ stats.people }}</b>человек</div>
  <div class="stat"><b>{{ fmt_bytes(stats.total) }}</b>трафик всего</div>
</div>
{% if org.key_limit < stats.issued %}<div class="warn">Лимит ({{ org.key_limit }}) ниже числа выданных ключей ({{ stats.issued }}): новые ключи не выдаются, уже выданные продолжают работать.</div>{% endif %}

<div class="card">
  <h2>Настройки</h2>
  <div class="row">
    <form method="post" action="/super/org/{{ org.id }}/update">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <label for="n">Название</label><input id="n" name="name" type="text" maxlength="80" value="{{ org.name }}" required>
      <label for="s">Логин администратора</label><input id="s" name="slug" type="text" maxlength="30" value="{{ org.slug }}" autocapitalize="none" required>
      <button class="btn secondary" type="submit">Сохранить</button>
    </form>
    <form method="post" action="/super/org/{{ org.id }}/limit">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <label for="l">Лимит ключей</label><input id="l" name="limit" type="number" min="0" max="{{ max_limit }}" value="{{ org.key_limit }}">
      <button class="btn secondary" type="submit">Сохранить лимит</button>
    </form>
    <form method="post" action="/super/org/{{ org.id }}/code">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <label for="c">Код доступа <small>(5 цифр, пусто = случайный)</small></label><input id="c" name="code" type="text" inputmode="numeric" pattern="[0-9]{5}" maxlength="5">
      <button class="btn secondary" type="submit">Сменить код</button>
    </form>
  </div>
  <div class="row">
    <form method="post" action="/super/org/{{ org.id }}/toggle"{% if org.enabled %} onsubmit="return confirm('Отключить доступ организации? Её сотрудники потеряют доступ к порталу и к VPN.');"{% endif %}>
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <button class="btn {{ 'danger' if org.enabled else 'primary' }}" type="submit">{{ 'Отключить доступ' if org.enabled else 'Включить доступ' }}</button>
    </form>
    <form method="post" action="/super/org/{{ org.id }}/admin-password" onsubmit="return confirm('Создать новый пароль администратора организации? Старый перестанет работать.');">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <button class="btn secondary" type="submit">Новый пароль администратора</button>
    </form>
    <form method="post" action="/super/org/{{ org.id }}/delete" onsubmit="return confirm('Удалить организацию «{{ org.name }}»? Действие необратимо.');">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <button class="btn danger" type="submit">Удалить организацию</button>
    </form>
  </div>
  <p><small>Удалить можно только организацию без выданных конфигов (сначала освободите их).</small></p>
</div>

<div class="card">
  <h2>Сотрудники</h2>
  {% with release_url='/super/release/', limit_url='/super/person/', can_release=True %}{% include "people_table.html" %}{% endwith %}
</div>
{% include "audit_table.html" %}
{% endblock %}""",

    "backup.html": """{% extends "base.html" %}
{% block title %}Резервная копия{% endblock %}
{% block content %}
<p><a href="/super">← Назад</a></p>
<h1>Резервная копия ключей</h1>
<p class="sub">Для переезда на другой сервер без перенастройки устройств</p>
<div class="warn">В копии все приватные ключи и настройки организаций. Файл шифруется парольной фразой: без неё его не открыть, а при потере фразы восстановить копию нельзя. Храните файл и фразу отдельно.</div>
<div class="card">
  <form method="post" action="/super/backup">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label for="pw">Пароль общего администратора</label>
    <input id="pw" name="password" type="password" autocomplete="current-password" required>
    <label for="p1">Парольная фраза для копии <small>(не короче 12 символов)</small></label>
    <input id="p1" name="passphrase" type="password" autocomplete="new-password" minlength="12" required>
    <label for="p2">Повторите фразу</label>
    <input id="p2" name="passphrase2" type="password" autocomplete="new-password" minlength="12" required>
    <button class="btn primary" type="submit">Скачать зашифрованную копию</button>
  </form>
  <p><small>Восстановление на новом сервере: <code>sudo ./scripts/restore-backup.py файл.vpnbak</code> (см. README).</small></p>
</div>
{% endblock %}""",
}
app.jinja_loader = DictLoader(TEMPLATES)

# --------------------------------------------------------------------------- база данных

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    code TEXT NOT NULL UNIQUE,
    key_limit INTEGER NOT NULL DEFAULT 10,
    enabled INTEGER NOT NULL DEFAULT 1,
    admin_hash TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES orgs(id),
    phone TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    rx_archived INTEGER NOT NULL DEFAULT 0,
    tx_archived INTEGER NOT NULL DEFAULT 0,
    dev_limit INTEGER,
    UNIQUE(org_id, phone)
);
CREATE TABLE IF NOT EXISTS assignments (
    slot INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES people(id),
    label TEXT NOT NULL DEFAULT '',
    assigned_at INTEGER NOT NULL,
    last_download_at INTEGER,
    downloads INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_assign_person ON assignments(person_id);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    org_id INTEGER,
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS attempts (ts INTEGER NOT NULL, ip TEXT NOT NULL, kind TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_attempts ON attempts(kind, ts);
CREATE TABLE IF NOT EXISTS captchas (id TEXT PRIMARY KEY, answer TEXT NOT NULL, ts INTEGER NOT NULL);
"""


def connect():
    if SHARED_DSN:
        return postgres_backend.Connection(SHARED_DSN)
    c = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=10000")
    return c


def _columns(c, table):
    return [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]


def _table_exists(c, name):
    return bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())


def migrate_v1(c):
    """Первая версия портала (одна организация, код в settings) -> несколько организаций.
    Все существующие люди и выдачи переходят в организацию «Основная организация» (логин main)."""
    if _table_exists(c, "people") and "org_id" not in _columns(c, "people") and not _table_exists(c, "people_v1"):
        c.execute("ALTER TABLE people RENAME TO people_v1")
        c.execute("ALTER TABLE assignments RENAME TO assignments_v1")
    c.executescript(SCHEMA)
    if not _table_exists(c, "people_v1"):
        return
    code = None
    if _table_exists(c, "settings"):
        row = c.execute("SELECT value FROM settings WHERE key='code'").fetchone()
        code = row["value"] if row else None
    if not code or not re.fullmatch(r"\d{5}", code):
        code = f"{secrets.randbelow(100000):05d}"
    c.execute("BEGIN IMMEDIATE")
    try:
        if not c.execute("SELECT 1 FROM orgs").fetchone():
            c.execute("INSERT INTO orgs(name, slug, code, key_limit, enabled, admin_hash, created_at) VALUES(?,?,?,?,1,NULL,?)",
                      ("Основная организация", "main", code, max(len(all_slots()), 1), int(time.time())))
        oid = c.execute("SELECT id FROM orgs ORDER BY id LIMIT 1").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO people(org_id, phone, name, created_at) SELECT ?, phone, name, created_at FROM people_v1", (oid,))
        c.execute("""INSERT OR IGNORE INTO assignments(slot, person_id, label, assigned_at, last_download_at, downloads)
                     SELECT a.slot, p.id, a.label, a.assigned_at, a.last_download_at, a.downloads
                     FROM assignments_v1 a JOIN people p ON p.phone = a.phone AND p.org_id = ?""", (oid,))
        c.execute("DROP TABLE assignments_v1")
        c.execute("DROP TABLE people_v1")
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    log.info("Миграция v1 -> v2 выполнена: люди и выдачи перенесены в организацию «Основная организация»")


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SHARED_DSN:
        c = connect()
        try:
            write_peers(c)
        finally:
            c.close()
        return
    with open(DATA_DIR / ".init.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # несколько процессов gunicorn стартуют одновременно
        c = connect()
        c.execute("PRAGMA journal_mode=WAL")
        migrate_v1(c)
        c.executescript(SCHEMA)
        for col, ddl in (("rx_archived", "INTEGER NOT NULL DEFAULT 0"), ("tx_archived", "INTEGER NOT NULL DEFAULT 0"),
                         ("dev_limit", "INTEGER")):  # базы, созданные до появления этих полей
            if col not in _columns(c, "people"):
                c.execute(f"ALTER TABLE people ADD COLUMN {col} {ddl}")
        c.execute("PRAGMA user_version=2")
        write_peers(c)
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


# --------------------------------------------------------------------------- пул конфигов и пиры VPN

SLOT_RE = re.compile(r"^client(\d{3,})\.conf$")


def slot_parity():
    """Чётность слотов, которые выдаёт ЭТОТ сервер: 0 (чётные), 1 (нечётные) или None (любые).
    Читается из локального файла PORTAL_SLOT_PARITY (/etc/vpn-slot-parity: odd|even), он не реплицируется:
    у каждого сервера свой. Так основной и резервный не выдадут один и тот же слот даже при рассинхроне."""
    if SHARED_DSN:
        return None
    try:
        v = Path(os.environ.get("PORTAL_SLOT_PARITY", "/etc/vpn-slot-parity")).read_text().strip().lower()
    except OSError:
        return None
    return {"odd": 1, "even": 0}.get(v)


def all_slots(c=None):
    if SHARED_DSN:
        c = c or db()
        return [r[0] for r in c.execute("SELECT slot FROM portal_configs ORDER BY slot")]
    if not CONF_DIR.is_dir():
        return []
    slots = []
    for f in CONF_DIR.iterdir():
        m = SLOT_RE.match(f.name)
        if m:
            slots.append(int(m.group(1)))
    return sorted(slots)


def _b64(raw):
    return base64.b64encode(raw).decode()


def _public_from_private(priv_b64):
    k = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64, validate=True))
    return _b64(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


_peer_cache = {}


def peer_info(slot, c=None, text=None):
    """Данные пира для сервера, полученные из клиентского конфига: публичный ключ, PSK, IP в туннеле."""
    if SHARED_DSN:
        if text is None:
            c = c or db()
            row = c.execute("SELECT body FROM portal_configs WHERE slot=?", (slot,)).fetchone()
            if not row:
                return None
            text = row[0]
        stamp = hashlib.sha256(text.encode()).digest()
    else:
        path = CONF_DIR / f"client{slot:03d}.conf"
        try:
            st = path.stat()
        except OSError:
            return None
        stamp = (st.st_mtime_ns, st.st_size)
    hit = _peer_cache.get(slot)
    if hit and hit[0] == stamp:
        return hit[1]
    if not SHARED_DSN:
        text = path.read_text()
    priv = re.search(r"(?m)^PrivateKey\s*=\s*(\S+)", text)
    psk = re.search(r"(?m)^PresharedKey\s*=\s*(\S+)", text)
    addr = re.search(r"(?m)^Address\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})/32", text)
    info = None
    if priv and psk and addr:
        try:
            info = {"slot": slot, "public": _public_from_private(priv.group(1)), "psk": psk.group(1), "ip": addr.group(1)}
            wg_address = shared_wg_address(slot)
            if wg_address:
                info["wireguard_ip"] = wg_address
        except ValueError:
            info = None
    _peer_cache[slot] = (stamp, info)
    return info


def enabled_slots(c):
    """Пиры, которым разрешено подключаться к VPN: выданные конфиги включённых организаций."""
    return [r[0] for r in c.execute(
        "SELECT a.slot FROM assignments a JOIN people p ON p.id=a.person_id JOIN orgs o ON o.id=p.org_id "
        "WHERE o.enabled=1 ORDER BY a.slot")]


def write_peers(c):
    """Пишет peers.json для службы vpn-peer-sync. Файл меняется только при изменении содержимого."""
    with open(PEERS_FILE.with_name("." + PEERS_FILE.name + ".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        project_peers(c)


def project_peers(c):
    peers = []
    if SHARED_DSN:
        rows = ((r[0], r[1]) for r in c.execute(
            "SELECT a.slot, cfg.body FROM assignments a JOIN portal_configs cfg ON cfg.slot=a.slot "
            "JOIN people p ON p.id=a.person_id JOIN orgs o ON o.id=p.org_id WHERE o.enabled=1 ORDER BY a.slot"
        ))
    else:
        rows = ((slot, None) for slot in enabled_slots(c))
    for slot, text in rows:
        info = peer_info(slot, c, text)
        if info:
            peers.append(info)
        else:
            log.warning("peers: для конфига №%03d нет валидного файла, пир не будет разрешён", slot)
    payload = json.dumps({"version": 1, "peers": peers}, sort_keys=True, indent=1)
    try:
        if PEERS_FILE.read_text() == payload:
            return
    except OSError:
        pass
    tmp = PEERS_FILE.with_name("." + PEERS_FILE.name + ".tmp")
    tmp.write_text(payload)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PEERS_FILE)


_traffic_cache = {"stamp": None, "data": {}}


def traffic_files():
    """Свой traffic.json и файлы traffic-<сервер>.json, которые присылают другие серверы."""
    files = [TRAFFIC_FILE]
    try:
        files += sorted(TRAFFIC_FILE.parent.glob(TRAFFIC_FILE.stem + "-*.json"))
    except OSError:
        pass
    return files


def traffic_totals():
    """Накопленный трафик по публичным ключам: сумма по всем серверам (traffic.json ведёт служба vpn-traffic от root)."""
    stamp = []
    for f in traffic_files():
        try:
            st = f.stat()
            stamp.append((f.name, st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    stamp = tuple(stamp)
    if _traffic_cache["stamp"] != stamp:
        data = {}
        for f in traffic_files():
            try:
                raw = json.loads(f.read_text()).get("peers", {})
                for k, v in raw.items():
                    if isinstance(v, dict):
                        rx, tx = data.get(k, (0, 0))
                        data[k] = (rx + int(v.get("rx", 0)), tx + int(v.get("tx", 0)))
            except (OSError, ValueError, AttributeError, TypeError):
                continue
        _traffic_cache.update(stamp=stamp, data=data)
    return _traffic_cache["data"]


def slot_traffic(slot, totals=None):
    """(получено сервером от клиента, отправлено клиенту) по текущему ключу конфига."""
    info = peer_info(slot)
    if not info:
        return 0, 0
    totals = totals if totals is not None else traffic_totals()
    rx, tx = totals.get(info["public"], (0, 0))
    xrx, xtx = totals.get(f"xray:{slot:03d}", (0, 0))
    return rx + xrx, tx + xtx


def fmt_bytes(n):
    n = int(n or 0)
    if n < 1024:
        return f"{n} Б"
    for unit in ("КБ", "МБ", "ГБ", "ТБ"):
        n /= 1024
        if n < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if n >= 100 else f"{n:.1f} {unit}"


def shared_wg_address(slot):
    if WG_GATEWAYS:
        try:
            return client_address(slot)
        except ValueError:
            pass
    return None


app.jinja_env.globals["fmt_bytes"] = fmt_bytes


def rotate_slot(slot, c=None):
    """Меняет ключи конфига (клиентский ключ и PSK): прежнее устройство перестаёт подключаться, конфиг можно выдать заново."""
    path = CONF_DIR / f"client{slot:03d}.conf"
    if SHARED_DSN:
        text = c.execute("SELECT body FROM portal_configs WHERE slot=?", (slot,)).fetchone()[0]
    else:
        text = path.read_text()
    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    new_priv, new_psk = _b64(raw), _b64(secrets.token_bytes(32))
    text, n1 = re.subn(r"(?m)^PrivateKey\s*=.*$", lambda m: f"PrivateKey = {new_priv}", text, count=1)
    text, n2 = re.subn(r"(?m)^PresharedKey\s*=.*$", lambda m: f"PresharedKey = {new_psk}", text, count=1)
    if not (n1 and n2):
        raise RuntimeError(f"В конфиге №{slot:03d} не найдены PrivateKey/PresharedKey")
    if SHARED_DSN:
        c.execute("UPDATE portal_configs SET body=? WHERE slot=?", (text, slot))
    else:
        tmp = path.with_name("." + path.name + ".tmp")
        tmp.write_text(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    _peer_cache.pop(slot, None)


# --------------------------------------------------------------------------- вспомогательное

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


def hash_password(pw):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def check_password(pw, stored):
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc, bytes.fromhex(h))
    except (ValueError, AttributeError):
        return False


DUMMY_HASH = hash_password("нет-такого-пароля")  # чтобы время проверки не выдавало, существует ли организация


def gen_password(n=12):
    return "".join(secrets.choice(PASSWORD_CHARS) for _ in range(n))


def super_password():
    return os.environ.get("SUPERADMIN_PASSWORD") or os.environ.get("ADMIN_PASSWORD", "")


def unique_code(c):
    for _ in range(200):
        code = f"{secrets.randbelow(100000):05d}"
        if not c.execute("SELECT 1 FROM orgs WHERE code=?", (code,)).fetchone():
            return code
    raise RuntimeError("Не удалось подобрать свободный код")


def audit(actor, action, details="", org_id=None):
    c = db()
    c.execute("INSERT INTO audit(ts, actor, org_id, action, details) VALUES(?,?,?,?,?)", (now(), actor, org_id, action, details))
    c.execute("DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - 5000")


def audit_rows(org_id=None, limit=30):
    q, args = "SELECT ts, actor, action, details FROM audit", []
    if org_id is not None:
        q += " WHERE org_id=?"
        args.append(org_id)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [{"at": fmt(r["ts"]), "actor": r["actor"], "action": r["action"], "details": r["details"]} for r in db().execute(q, args)]


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
    g.vpn_auth_failed = True


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
    for _ in range(7):
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
    for _ in range(3):
        d.line([(0, rng.randint(15, 55)), (w, rng.randint(15, 55))], fill=(rng.randint(60, 140),) * 3, width=2)
    for _ in range(160):
        d.point((rng.randint(0, w - 1), rng.randint(0, h - 1)), fill=(rng.randint(0, 160),) * 3)
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
    if SHARED_DSN:
        row = c.execute("DELETE FROM captchas WHERE id=? RETURNING answer, ts", (cid or "",)).fetchone()
    else:
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
    return bool(sent) and hmac.compare_digest(sent, session.get("csrf", ""))


def page(template, **ctx):
    ctx["messages"] = get_flashed_messages(with_categories=True)
    ctx["csrf"] = csrf_token()
    return render_template(template, **ctx)


@app.after_request
def headers(resp):
    if g.get("vpn_auth_failed", False):
        resp.headers["X-VPN-Auth-Failure"] = "1"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    )
    return resp


def employee_keys():
    return {k: session[k] for k in ("org", "phone") if k in session}


# --------------------------------------------------------------------------- сотрудник

def current_person():
    org_id, phone = session.get("org"), session.get("phone")
    if not org_id or not phone:
        return None
    return db().execute(
        "SELECT p.id, p.org_id, p.phone, p.name, p.dev_limit, o.name AS org_name, o.enabled AS org_enabled, o.key_limit AS org_limit "
        "FROM people p JOIN orgs o ON o.id=p.org_id WHERE p.org_id=? AND p.phone=?", (org_id, phone)).fetchone()


@app.route("/healthz")
def health():
    try:
        db().execute("SELECT slot FROM portal_configs LIMIT 1" if SHARED_DSN else "SELECT 1").fetchone()
    except (sqlite3.Error, postgres_backend.Error if SHARED_DSN else sqlite3.Error):
        return "Unavailable\n", 503
    return "OK\n", 200


@app.route("/")
def index():
    from_guard = request.args.get("from") == "guard"
    person = current_person()
    if person and not person["org_enabled"]:
        session.pop("org", None)
        session.pop("phone", None)
        flash("Доступ для вашей организации отключён. Обратитесь к администратору организации.", "err")
        person = None
    if not person:
        return page("login.html", captcha_id=new_captcha(), from_guard=from_guard)
    rows = db().execute("SELECT slot, label, assigned_at FROM assignments WHERE person_id=? ORDER BY assigned_at, slot",
                        (person["id"],)).fetchall()
    devices = [{"slot": r["slot"], "label": r["label"], "at": fmt(r["assigned_at"]),
                "wireguard": bool(shared_wg_address(r["slot"]))} for r in rows]
    return page("dashboard.html", name=person["name"] or "Без имени", phone=phone_display(person["phone"]),
                from_guard=from_guard, guard_phone_verified=session.get("guard_verified_phone") == person["phone"],
                org_name=person["org_name"], devices=devices, dev_limit=person["dev_limit"], servers=SERVERS,
                wireguard_servers=WG_SERVERS, xray=XRAY_UI and bool(xray_state()))


@app.route("/login", methods=["POST"])
def login():
    from_guard = request.form.get("from_guard") == "1"
    landing = "/?from=guard#claim-device" if from_guard else "/"
    if not check_csrf():
        flash("Сессия устарела, попробуйте ещё раз.", "err")
        return redirect(landing)
    if blocked("login", LIMIT_LOGIN_IP, LIMIT_LOGIN_ALL) or blocked("captcha", LIMIT_CAPTCHA_IP):
        flash("Слишком много неверных попыток. Подождите около 15 минут и попробуйте снова.", "err")
        return redirect(landing)
    phone = normalize_phone(request.form.get("phone"))
    if not phone:
        flash("Введите номер телефона в формате +7… или 8… (10 цифр после кода страны).", "err")
        return redirect(landing)
    if not verify_captcha(request.form.get("captcha_id", ""), request.form.get("captcha", "")):
        record_attempt("captcha")
        auth_fail("captcha")
        flash("Неверные символы с картинки. Попробуйте ещё раз.", "err")
        return redirect(landing)
    code = re.sub(r"\D", "", request.form.get("code", ""))
    c = db()
    org = c.execute("SELECT * FROM orgs WHERE code=?", (code,)).fetchone() if len(code) == 5 else None
    if not org:
        record_attempt("login")
        auth_fail("code")
        log.info("login: неверный код ip=%s", client_ip())
        flash("Неверный код доступа.", "err")
        return redirect(landing)
    if not org["enabled"]:
        flash("Доступ для вашей организации отключён. Обратитесь к администратору организации.", "err")
        return redirect(landing)
    name = clean_text(request.form.get("name"), 80)
    person = c.execute("SELECT * FROM people WHERE org_id=? AND phone=?", (org["id"], phone)).fetchone()
    if not person:
        if len(name) < 2:
            flash("При первом входе укажите фамилию и имя.", "err")
            return redirect(landing)
        insert = "INSERT INTO people(org_id, phone, name, created_at) VALUES(?,?,?,?)"
        if SHARED_DSN:
            insert += " ON CONFLICT (org_id, phone) DO NOTHING"
        c.execute(insert, (org["id"], phone, name, now()))
        log.info("login: новый человек %s (%s)", mask_phone(phone), org["slug"])
    else:
        if not person["name"] and name:
            c.execute("UPDATE people SET name=? WHERE id=?", (name, person["id"]))
        log.info("login: вход %s (%s)", mask_phone(phone), org["slug"])
    details = f"{org['slug']} · IP {client_ip()}"
    if not person:
        details += " · первый вход"
    if from_guard:
        details += " · из Guard"
    audit(f"user {mask_phone(phone)}", "вход", details, org["id"])
    session.clear()
    session.permanent = True
    session["org"] = org["id"]
    session["phone"] = phone
    if from_guard:
        session["guard_verified_phone"] = phone
    csrf_token()
    return redirect(landing)


@app.route("/logout", methods=["POST"])
def logout():
    if check_csrf():
        session.clear()
    return redirect("/")


@app.route("/claim", methods=["POST"])
def claim():
    from_guard = request.form.get("from_guard") == "1"
    landing = "/?from=guard#claim-device" if from_guard else "/"
    person = current_person()
    if not person:
        return redirect(landing)
    if not check_csrf():
        flash("Сессия устарела, обновите страницу.", "err")
        return redirect(landing)
    if not person["org_enabled"]:
        return redirect(landing)
    if blocked("claim", LIMIT_CLAIM_IP):
        flash("Слишком много запросов. Попробуйте позже.", "err")
        return redirect(landing)
    if (from_guard and session.get("guard_verified_phone") != person["phone"]
            and normalize_phone(request.form.get("phone")) != person["phone"]):
        flash("Номер не совпадает с текущим профилем. Введите его заново или выйдите и войдите в нужный профиль.", "err")
        return redirect(landing)
    label = clean_text(request.form.get("label"), 30)
    c = db()
    if SHARED_DSN:
        c.begin_write()
    else:
        c.execute("BEGIN IMMEDIATE")
    try:
        query = "SELECT key_limit, enabled FROM orgs WHERE id=?"
        if SHARED_DSN:
            query += " FOR UPDATE"
        org = c.execute(query, (person["org_id"],)).fetchone()
        limit = person["dev_limit"]
        if SHARED_DSN:
            current = c.execute("SELECT dev_limit FROM people WHERE id=? FOR UPDATE", (person["id"],)).fetchone()
            limit = current[0] if current else 0
        have = c.execute("SELECT COUNT(*) FROM assignments WHERE person_id=?", (person["id"],)).fetchone()[0]
        used = c.execute("SELECT COUNT(*) FROM assignments a JOIN people p ON p.id=a.person_id WHERE p.org_id=?",
                         (person["org_id"],)).fetchone()[0]
        taken = {r[0] for r in c.execute("SELECT slot FROM assignments")}
        par = slot_parity()
        free = [s for s in all_slots(c) if s not in taken and (par is None or s % 2 == par)]
        if from_guard:
            free = [s for s in free if shared_wg_address(s)]
        problem = None
        if not org or not org["enabled"]:
            problem = "Доступ для вашей организации отключён."
        elif limit is not None and have >= limit:
            problem = f"Администратор ограничил число ваших устройств: {limit}."
        elif used >= org["key_limit"]:
            problem = "Лимит ключей вашей организации исчерпан. Обратитесь к администратору организации."
        elif not free:
            log.warning("claim: свободные конфиги в пуле закончились")
            problem = ("Свободных конфигов WireGuard сейчас нет. Обратитесь к администратору."
                       if from_guard else "Свободные конфиги закончились. Обратитесь к администратору.")
        if problem:
            c.execute("ROLLBACK")
            flash(problem, "err")
            return redirect(landing)
        slot = free[0]
        c.execute("INSERT INTO assignments(slot, person_id, label, assigned_at) VALUES(?,?,?,?)",
                  (slot, person["id"], label, now()))
        c.execute("COMMIT")
    except Exception:
        try:
            c.execute("ROLLBACK")
        except (sqlite3.Error, postgres_backend.Error if SHARED_DSN else sqlite3.Error):
            pass
        raise
    record_attempt("claim")
    audit(f"user {mask_phone(person['phone'])}", "выдан конфиг", f"№{slot:03d}", person["org_id"])
    write_peers(c)
    log.info("claim: %s получил конфиг №%03d", mask_phone(person["phone"]), slot)
    flash(f"Конфиг №{slot:03d} выдан. Скачайте его ниже.", "ok")
    if from_guard:
        session.pop("guard_verified_phone", None)
        return redirect(f"/#config-{slot}")
    return redirect("/")


@app.route("/d/<int:slot>/conf")
def download(slot):
    person = current_person()
    if not person or not person["org_enabled"]:
        return Response("Требуется вход", status=403, mimetype="text/plain")
    plain = request.args.get("format") == "wireguard"
    if plain and not shared_wg_address(slot):
        return Response("WireGuard недоступен для этого конфига", status=404, mimetype="text/plain")
    c = db()
    if SHARED_DSN:
        with c.write_transaction():
            row = c.execute(
                "UPDATE assignments a SET downloads=a.downloads+1, last_download_at=? "
                "FROM portal_configs cfg, people p, orgs o "
                "WHERE a.slot=? AND a.person_id=? AND cfg.slot=a.slot AND p.id=a.person_id "
                "AND o.id=p.org_id AND o.enabled=1 RETURNING cfg.body",
                (now(), slot, person["id"]),
            ).fetchone()
            if not row:
                return Response("Не найдено", status=404, mimetype="text/plain")
            body = row[0].encode("utf-8")
    else:
        row = c.execute("SELECT person_id FROM assignments WHERE slot=?", (slot,)).fetchone()
        if not row or row["person_id"] != person["id"]:
            return Response("Не найдено", status=404, mimetype="text/plain")
        path = CONF_DIR / f"client{slot:03d}.conf"
        if not path.is_file():
            return Response("Файл конфига не найден, сообщите администратору", status=500, mimetype="text/plain")
        c.execute("UPDATE assignments SET downloads=downloads+1, last_download_at=? WHERE slot=?", (now(), slot))
        body = path.read_bytes()
    chosen = next((x for x in SERVERS if x["key"] == request.args.get("srv")), None)
    suffix = ""
    if plain:
        try:
            gateway = WG_GATEWAYS.get(request.args.get("srv")) or next(iter(WG_GATEWAYS.values()))
            body = gateway.render(slot, body)
        except (ValueError, KeyError) as error:
            log.error("download: WireGuard slot %d could not be rendered (%s)", slot, type(error).__name__)
            return Response("Не удалось собрать WireGuard-конфиг", status=503, mimetype="text/plain")
        suffix = "-wg"
    elif chosen:
        body = re.sub(rb"(?m)^(Endpoint\s*=\s*)[^:\s]+(:\d+)\s*$",
                      lambda m: m.group(1) + chosen["host"].encode() + m.group(2), body)
        if chosen.get("full"):
            body = re.sub(rb"(?m)^AllowedIPs\s*=.*$", b"AllowedIPs = 0.0.0.0/0, ::/0", body)
            suffix = f"-{chosen['key']}"
    return Response(body, mimetype="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="3dit-vpn-{slot:03d}{suffix}.conf"',
    })


def xray_state():
    """Параметры VLESS+Reality из /etc/vpn-xray.json (нет файла или он некорректен: Xray не используется)."""
    try:
        st = json.loads(XRAY_STATE.read_text())
        uuid.UUID(st["salt"])
        for k in ("public", "short_id", "sni", "port"):
            if not st.get(k):
                return None
        return st
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


@app.route("/d/<int:slot>/vless")
def download_vless(slot):
    person = current_person()
    if not person or not person["org_enabled"]:
        return Response("Требуется вход", status=403, mimetype="text/plain")
    st = xray_state() if XRAY_UI else None
    if not st:
        return Response("Не настроено", status=404, mimetype="text/plain")
    row = db().execute("SELECT person_id FROM assignments WHERE slot=?", (slot,)).fetchone()
    if not row or row["person_id"] != person["id"]:
        return Response("Не найдено", status=404, mimetype="text/plain")
    chosen = next((x for x in SERVERS if x["key"] == request.args.get("srv")), None) or (SERVERS[0] if SERVERS else None)
    host = chosen["host"] if chosen else request.host.split(":")[0]
    title = f"3dit-vpn-{slot:03d}" + (f" {chosen['title']}" if chosen else "")
    link = (f"vless://{uuid.uuid5(uuid.UUID(st['salt']), f'slot{slot:03d}')}@{host}:{int(st['port'])}"
            f"?encryption=none&flow=xtls-rprx-vision&security=reality&sni={st['sni']}&fp={st.get('fp') or 'ios'}"
            f"&pbk={st['public']}&sid={st['short_id']}&type=tcp#{quote(title)}")
    return Response(link + "\n", mimetype="text/plain")


@app.route("/captcha/<cid>.png")
def captcha_image(cid):
    row = db().execute("SELECT answer, ts FROM captchas WHERE id=?", (cid,)).fetchone()
    if not row or now() - row["ts"] > CAPTCHA_TTL:
        return Response("Не найдено", status=404, mimetype="text/plain")
    return Response(captcha_png(row["answer"]), mimetype="image/png")


# --------------------------------------------------------------------------- общее для администраторов

def is_admin(role):
    return session.get("role") == role and time.time() - session.get("admin_at", 0) < ADMIN_SESSION_SECONDS


def admin_login_guard(login_url):
    """Общие проверки перед входом администратора. Возвращает redirect при отказе, иначе None."""
    if not check_csrf():
        flash("Сессия устарела, попробуйте ещё раз.", "err")
        return redirect(login_url)
    if blocked("admin", LIMIT_ADMIN_IP, LIMIT_ADMIN_ALL) or blocked("captcha", LIMIT_CAPTCHA_IP):
        flash("Слишком много неверных попыток. Подождите около 15 минут.", "err")
        return redirect(login_url)
    return None


def start_admin_session(role, **extra):
    keep = employee_keys()
    session.clear()
    if keep:
        session.permanent = True
        session.update(keep)
    session["role"] = role
    session["admin_at"] = time.time()
    session.update(extra)
    csrf_token()


def load_people(org_id):
    c = db()
    people = {}
    totals = traffic_totals()
    ordering = "lower(name)" if SHARED_DSN else "name COLLATE NOCASE"
    for p in c.execute("SELECT id, phone, name, created_at, rx_archived, tx_archived, dev_limit FROM people "
                       f"WHERE org_id=? ORDER BY {ordering}, phone", (org_id,)):
        people[p["id"]] = {"id": p["id"], "dev_limit": p["dev_limit"], "phone": phone_display(p["phone"]), "raw": p["phone"], "name": p["name"],
                           "confs": [], "first_ts": None, "last_ts": None,
                           "rx": p["rx_archived"], "tx": p["tx_archived"]}
    for a in c.execute("SELECT a.slot, a.person_id, a.label, a.assigned_at, a.last_download_at FROM assignments a "
                       "JOIN people p ON p.id=a.person_id WHERE p.org_id=? ORDER BY a.assigned_at, a.slot", (org_id,)):
        p = people.get(a["person_id"])
        if p is None:
            continue
        rx, tx = slot_traffic(a["slot"], totals)
        p["rx"] += rx
        p["tx"] += tx
        p["confs"].append({"slot": a["slot"], "label": a["label"], "rx": rx, "tx": tx})
        p["first_ts"] = min(p["first_ts"] or a["assigned_at"], a["assigned_at"])
        if a["last_download_at"]:
            p["last_ts"] = max(p["last_ts"] or 0, a["last_download_at"])
    out = list(people.values())
    for p in out:
        p["first"], p["last"] = fmt(p["first_ts"]), fmt(p["last_ts"])
        p["total"] = p["rx"] + p["tx"]
    return out


def org_stats(org, people):
    issued = sum(len(p["confs"]) for p in people)
    rx, tx = sum(p["rx"] for p in people), sum(p["tx"] for p in people)
    return {"issued": issued, "people": len(people), "rx": rx, "tx": tx, "total": rx + tx,
            "free_limit": max(org["key_limit"] - issued, 0)}


def people_csv(people, org_name=None):
    buf = io.StringIO()
    buf.write("﻿")  # BOM, чтобы Excel правильно открыл кириллицу
    w = csv.writer(buf, delimiter=";")
    header = ["Фамилия Имя", "Телефон", "Конфигов", "Лимит устройств", "Конфиги", "Первая выдача", "Последнее скачивание",
              "Трафик всего, байт", "Скачано клиентом, байт", "Отправлено клиентом, байт"]
    w.writerow(header)
    for p in people:
        confs = ", ".join(f"№{i['slot']:03d}" + (f" ({csv_safe(i['label'])})" if i["label"] else "") for i in p["confs"])
        w.writerow([csv_safe(p["name"]), p["raw"], len(p["confs"]), "" if p["dev_limit"] is None else p["dev_limit"], confs, p["first"], p["last"], p["total"], p["tx"], p["rx"]])
    return buf.getvalue()


def release_slot(slot, actor, org_id=None):
    """Освобождает конфиг: ключи заменяются, устройство прежнего владельца отключается, конфиг возвращается в пул."""
    c = db()
    with c.write_transaction() if SHARED_DSN else nullcontext():
        row = c.execute("SELECT a.slot, p.org_id, p.phone FROM assignments a JOIN people p ON p.id=a.person_id WHERE a.slot=?", (slot,)).fetchone()
        if not row or (org_id is not None and row["org_id"] != org_id):
            flash("Конфиг не найден.", "err")
            return False
        rx, tx = slot_traffic(slot)
        try:
            rotate_slot(slot, c)
        except (OSError, RuntimeError) as e:
            log.error("release: не удалось заменить ключи конфига №%03d: %s", slot, e)
            flash(f"Не удалось заменить ключи конфига №{slot:03d}, конфиг не освобождён.", "err")
            return False
        c.execute("UPDATE people SET rx_archived=rx_archived+?, tx_archived=tx_archived+? WHERE id=(SELECT person_id FROM assignments WHERE slot=?)", (rx, tx, slot))
        c.execute("DELETE FROM assignments WHERE slot=?", (slot,))
        audit(actor, "освобождён конфиг", f"№{slot:03d} ({mask_phone(row['phone'])}), ключи заменены", row["org_id"])
    write_peers(c)
    log.info("release: %s освободил конфиг №%03d", actor, slot)
    flash(f"Конфиг №{slot:03d} освобождён, ключи заменены.", "ok")
    return True


# --------------------------------------------------------------------------- администратор организации

def current_org_admin():
    if not is_admin("org"):
        return None
    return db().execute("SELECT * FROM orgs WHERE id=?", (session.get("admin_org"),)).fetchone()


@app.route("/org/login", methods=["GET", "POST"])
def org_login():
    if request.method == "GET":
        return page("admin_login.html", title="Администратор организации", action="/org/login",
                    with_login=True, captcha_id=new_captcha())
    r = admin_login_guard("/org/login")
    if r:
        return r
    if not verify_captcha(request.form.get("captcha_id", ""), request.form.get("captcha", "")):
        record_attempt("captcha")
        auth_fail("org-captcha")
        flash("Неверные символы с картинки. Попробуйте ещё раз.", "err")
        return redirect("/org/login")
    slug = clean_text(request.form.get("slug"), 30).lower()
    org = db().execute("SELECT * FROM orgs WHERE slug=?", (slug,)).fetchone()
    stored = org["admin_hash"] if org and org["admin_hash"] else DUMMY_HASH
    good = check_password(request.form.get("password", ""), stored) and bool(org and org["admin_hash"])
    if not good:
        record_attempt("admin")
        auth_fail("org-password")
        log.warning("org-admin: неверный логин или пароль ip=%s", client_ip())
        flash("Неверный логин или пароль.", "err")
        return redirect("/org/login")
    start_admin_session("org", admin_org=org["id"])
    audit(f"admin {org['slug']}", "вход", f"IP {client_ip()}", org["id"])
    return redirect("/org")


@app.route("/org/logout", methods=["POST"])
def org_logout():
    if check_csrf():
        for k in ("role", "admin_at", "admin_org"):
            session.pop(k, None)
    return redirect("/org/login")


@app.route("/org")
def org_home():
    org = current_org_admin()
    if not org:
        return redirect("/org/login")
    people = load_people(org["id"])
    return page("org.html", org=dict(org), people=people, stats=org_stats(org, people), audit=audit_rows(org["id"]))


@app.route("/org/release/<int:slot>", methods=["POST"])
def org_release(slot):
    org = current_org_admin()
    if not org:
        return redirect("/org/login")
    if not check_csrf():
        flash("Сессия устарела, обновите страницу.", "err")
    elif not org["enabled"]:
        flash("Доступ организации отключён, изменения недоступны.", "err")
    else:
        release_slot(slot, f"admin {org['slug']}", org_id=org["id"])
    return redirect("/org")


def _set_person_limit(pid, org_id, actor):
    c = db()
    row = c.execute("SELECT id, org_id, phone, dev_limit FROM people WHERE id=?", (pid,)).fetchone()
    if not row or (org_id is not None and row["org_id"] != org_id):
        flash("Человек не найден.", "err")
        return None
    raw = re.sub(r"\s", "", request.form.get("limit", ""))
    if raw == "":
        new = None
    elif raw.isdigit() and int(raw) <= 1000:
        new = int(raw)
    else:
        flash("Лимит устройств: число от 0 до 1000 или пусто (без ограничения).", "err")
        return row["org_id"]
    c.execute("UPDATE people SET dev_limit=? WHERE id=?", (new, pid))
    audit(actor, "лимит устройств", f"{mask_phone(row['phone'])}: {'без лимита' if row['dev_limit'] is None else row['dev_limit']} -> {'без лимита' if new is None else new}", row["org_id"])
    flash("Лимит устройств сохранён." if new is not None else "Лимит устройств снят.", "ok")
    return row["org_id"]


@app.route("/org/person/<int:pid>/limit", methods=["POST"])
def org_person_limit(pid):
    org = current_org_admin()
    if not org:
        return redirect("/org/login")
    if not check_csrf():
        flash("Сессия устарела, обновите страницу.", "err")
    elif not org["enabled"]:
        flash("Доступ организации отключён, изменения недоступны.", "err")
    else:
        _set_person_limit(pid, org["id"], f"admin {org['slug']}")
    return redirect("/org")


@app.route("/org/export.csv")
def org_export():
    org = current_org_admin()
    if not org:
        return redirect("/org/login")
    return Response(people_csv(load_people(org["id"])), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="vpn-access.csv"'})


# --------------------------------------------------------------------------- общий администратор

def super_required():
    return is_admin("super")


@app.route("/super/login", methods=["GET", "POST"])
def super_login():
    if request.method == "GET":
        return page("admin_login.html", title="Общий администратор", action="/super/login",
                    with_login=False, captcha_id=new_captcha())
    r = admin_login_guard("/super/login")
    if r:
        return r
    pw = super_password()
    if len(pw) < 8:
        flash("Пароль общего администратора не настроен на сервере.", "err")
        return redirect("/super/login")
    if not verify_captcha(request.form.get("captcha_id", ""), request.form.get("captcha", "")):
        record_attempt("captcha")
        auth_fail("super-captcha")
        flash("Неверные символы с картинки. Попробуйте ещё раз.", "err")
        return redirect("/super/login")
    if not hmac.compare_digest(request.form.get("password", "").encode(), pw.encode()):
        record_attempt("admin")
        auth_fail("super-password")
        log.warning("super: неверный пароль ip=%s", client_ip())
        flash("Неверный пароль.", "err")
        return redirect("/super/login")
    start_admin_session("super")
    audit("super", "вход", f"ip {client_ip()}")
    return redirect("/super")


@app.route("/super/logout", methods=["POST"])
def super_logout():
    if check_csrf():
        for k in ("role", "admin_at", "admin_org"):
            session.pop(k, None)
    return redirect("/super/login")


@app.route("/admin")
def admin_compat():
    return redirect("/super")


@app.route("/admin/login")
def admin_login_compat():
    return redirect("/super/login")


def org_rows():
    ordering = "lower(o.name)" if SHARED_DSN else "o.name COLLATE NOCASE"
    rows = db().execute(
        "SELECT o.*, (SELECT COUNT(*) FROM people p WHERE p.org_id=o.id) AS people, "
        "(SELECT COUNT(*) FROM assignments a JOIN people p ON p.id=a.person_id WHERE p.org_id=o.id) AS issued "
        f"FROM orgs o ORDER BY {ordering}").fetchall()
    totals = traffic_totals()
    used = {}
    c = db()
    for r in c.execute("SELECT org_id, SUM(rx_archived) rx, SUM(tx_archived) tx FROM people GROUP BY org_id"):
        used[r["org_id"]] = [r["rx"] or 0, r["tx"] or 0]
    for r in c.execute("SELECT a.slot, p.org_id FROM assignments a JOIN people p ON p.id=a.person_id"):
        rx, tx = slot_traffic(r["slot"], totals)
        u = used.setdefault(r["org_id"], [0, 0])
        u[0] += rx
        u[1] += tx
    out = []
    for r in rows:
        d = dict(r)
        d["rx"], d["tx"] = used.get(r["id"], [0, 0])
        d["traffic"] = d["rx"] + d["tx"]
        d["has_admin"] = bool(r["admin_hash"])
        d["percent"] = 100 if r["key_limit"] <= 0 else min(100, r["issued"] * 100 // r["key_limit"])
        out.append(d)
    return out


@app.route("/super")
def super_home():
    if not super_required():
        return redirect("/super/login")
    orgs = org_rows()
    total = len(all_slots())
    assigned = db().execute("SELECT COUNT(*) FROM assignments").fetchone()[0]
    pool = {"total": total, "assigned": assigned, "free": max(total - assigned, 0),
            "limits": sum(o["key_limit"] for o in orgs)}
    inventory = router_gateway_inventory.overview(db(), int(time.time())) if SHARED_DSN else None
    return page("super.html", orgs=orgs, pool=pool, audit=audit_rows(), router_inventory=inventory,
                max_limit=MAX_ORG_LIMIT, default_limit=DEFAULT_ORG_LIMIT)


def _parse_limit(raw):
    try:
        v = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return v if 0 <= v <= MAX_ORG_LIMIT else None


def _org_or_none(oid):
    return db().execute("SELECT * FROM orgs WHERE id=?", (oid,)).fetchone()


def super_post(fn):
    """Обёртка для изменяющих запросов общего администратора: вход, CSRF."""
    def wrapper(*args, **kwargs):
        if not super_required():
            return redirect("/super/login")
        if not check_csrf():
            flash("Сессия устарела, обновите страницу.", "err")
            return redirect(request.referrer and "/super" or "/super")
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@app.route("/super/org/create", methods=["POST"])
@super_post
def super_org_create():
    c = db()
    name = clean_text(request.form.get("name"), 80)
    slug = clean_text(request.form.get("slug"), 30).lower()
    limit = _parse_limit(request.form.get("limit") or DEFAULT_ORG_LIMIT)
    code = re.sub(r"\D", "", request.form.get("code", ""))
    if len(name) < 2:
        flash("Укажите название организации.", "err")
    elif not SLUG_RE.match(slug):
        flash("Логин: 2–30 символов, латинские буквы, цифры и дефис, начинается с буквы или цифры.", "err")
    elif limit is None:
        flash(f"Лимит ключей: число от 0 до {MAX_ORG_LIMIT}.", "err")
    elif code and not re.fullmatch(r"\d{5}", code):
        flash("Код доступа должен состоять ровно из 5 цифр.", "err")
    elif c.execute("SELECT 1 FROM orgs WHERE slug=?", (slug,)).fetchone():
        flash("Организация с таким логином уже есть.", "err")
    elif code and c.execute("SELECT 1 FROM orgs WHERE code=?", (code,)).fetchone():
        flash("Такой код доступа уже используется другой организацией.", "err")
    else:
        code = code or unique_code(c)
        pw = gen_password()
        insert = "INSERT INTO orgs(name, slug, code, key_limit, enabled, admin_hash, created_at) VALUES(?,?,?,?,1,?,?)"
        if SHARED_DSN:
            insert += " RETURNING id"
        cur = c.execute(insert, (name, slug, code, limit, hash_password(pw), now()))
        oid = cur.fetchone()[0] if SHARED_DSN else cur.lastrowid
        audit("super", "создана организация", f"{name} ({slug}), лимит {limit}", oid)
        flash(f"Организация «{name}» создана. Код доступа: {code}. Логин администратора: {slug}, пароль: {pw} "
              f"(пароль показан один раз, сохраните его).", "ok")
    return redirect("/super")


@app.route("/super/org/<int:oid>")
def super_org_view(oid):
    if not super_required():
        return redirect("/super/login")
    org = _org_or_none(oid)
    if not org:
        return redirect("/super")
    people = load_people(oid)
    return page("super_org.html", org=dict(org), people=people, stats=org_stats(org, people),
                audit=audit_rows(oid), max_limit=MAX_ORG_LIMIT)


@app.route("/super/org/<int:oid>/update", methods=["POST"])
@super_post
def super_org_update(oid):
    c = db()
    org = _org_or_none(oid)
    if not org:
        return redirect("/super")
    name = clean_text(request.form.get("name"), 80)
    slug = clean_text(request.form.get("slug"), 30).lower()
    if len(name) < 2:
        flash("Укажите название организации.", "err")
    elif not SLUG_RE.match(slug):
        flash("Логин: 2–30 символов, латинские буквы, цифры и дефис.", "err")
    elif c.execute("SELECT 1 FROM orgs WHERE slug=? AND id<>?", (slug, oid)).fetchone():
        flash("Организация с таким логином уже есть.", "err")
    else:
        c.execute("UPDATE orgs SET name=?, slug=? WHERE id=?", (name, slug, oid))
        audit("super", "изменена организация", f"{org['name']} ({org['slug']}) -> {name} ({slug})", oid)
        flash("Сохранено.", "ok")
    return redirect(f"/super/org/{oid}")


@app.route("/super/org/<int:oid>/limit", methods=["POST"])
@super_post
def super_org_limit(oid):
    c = db()
    org = _org_or_none(oid)
    if not org:
        return redirect("/super")
    back = "/super/org/%d" % oid if "/super/org/" in (request.referrer or "") else "/super"
    if request.form.get("delta"):
        try:
            new = org["key_limit"] + int(request.form["delta"])
        except ValueError:
            new = None
        new = new if new is not None and 0 <= new <= MAX_ORG_LIMIT else None
    else:
        new = _parse_limit(request.form.get("limit"))
    if new is None:
        flash(f"Лимит ключей: число от 0 до {MAX_ORG_LIMIT}.", "err")
    else:
        c.execute("UPDATE orgs SET key_limit=? WHERE id=?", (new, oid))
        audit("super", "изменён лимит ключей", f"{org['key_limit']} -> {new}", oid)
        flash(f"Лимит ключей организации «{org['name']}»: {new}.", "ok")
    return redirect(back)


@app.route("/super/org/<int:oid>/code", methods=["POST"])
@super_post
def super_org_code(oid):
    c = db()
    org = _org_or_none(oid)
    if not org:
        return redirect("/super")
    code = re.sub(r"\D", "", request.form.get("code", ""))
    if code and not re.fullmatch(r"\d{5}", code):
        flash("Код доступа должен состоять ровно из 5 цифр.", "err")
    elif code and c.execute("SELECT 1 FROM orgs WHERE code=? AND id<>?", (code, oid)).fetchone():
        flash("Такой код доступа уже используется другой организацией.", "err")
    else:
        code = code or unique_code(c)
        c.execute("UPDATE orgs SET code=? WHERE id=?", (code, oid))
        audit("super", "изменён код доступа", "", oid)
        flash(f"Новый код доступа организации «{org['name']}»: {code}", "ok")
    return redirect(f"/super/org/{oid}")


@app.route("/super/org/<int:oid>/toggle", methods=["POST"])
@super_post
def super_org_toggle(oid):
    c = db()
    org = _org_or_none(oid)
    if not org:
        return redirect("/super")
    new = 0 if org["enabled"] else 1
    c.execute("UPDATE orgs SET enabled=? WHERE id=?", (new, oid))
    audit("super", "доступ включён" if new else "доступ отключён", org["name"], oid)
    write_peers(c)
    flash(f"Доступ организации «{org['name']}» {'включён' if new else 'отключён'}.", "ok")
    return redirect("/super/org/%d" % oid if "/super/org/" in (request.referrer or "") else "/super")


@app.route("/super/org/<int:oid>/admin-password", methods=["POST"])
@super_post
def super_org_password(oid):
    org = _org_or_none(oid)
    if not org:
        return redirect("/super")
    pw = gen_password()
    db().execute("UPDATE orgs SET admin_hash=? WHERE id=?", (hash_password(pw), oid))
    audit("super", "новый пароль администратора организации", "", oid)
    flash(f"Новый пароль администратора «{org['name']}»: логин {org['slug']}, пароль {pw} (показан один раз, сохраните его).", "ok")
    return redirect(f"/super/org/{oid}")


@app.route("/super/org/<int:oid>/delete", methods=["POST"])
@super_post
def super_org_delete(oid):
    c = db()
    org = _org_or_none(oid)
    if not org:
        return redirect("/super")
    issued = c.execute("SELECT COUNT(*) FROM assignments a JOIN people p ON p.id=a.person_id WHERE p.org_id=?", (oid,)).fetchone()[0]
    if issued:
        flash(f"Нельзя удалить организацию: выдано конфигов {issued}. Сначала освободите их.", "err")
        return redirect(f"/super/org/{oid}")
    c.execute("DELETE FROM people WHERE org_id=?", (oid,))
    c.execute("DELETE FROM orgs WHERE id=?", (oid,))
    audit("super", "удалена организация", f"{org['name']} ({org['slug']})")
    flash(f"Организация «{org['name']}» удалена.", "ok")
    return redirect("/super")


@app.route("/super/release/<int:slot>", methods=["POST"])
@super_post
def super_release(slot):
    row = db().execute("SELECT p.org_id FROM assignments a JOIN people p ON p.id=a.person_id WHERE a.slot=?", (slot,)).fetchone()
    release_slot(slot, "super")
    return redirect(f"/super/org/{row['org_id']}" if row else "/super")


@app.route("/super/person/<int:pid>/limit", methods=["POST"])
@super_post
def super_person_limit(pid):
    oid = _set_person_limit(pid, None, "super")
    return redirect(f"/super/org/{oid}" if oid else "/super")


@app.route("/super/export.csv")
def super_export():
    if not super_required():
        return redirect("/super/login")
    buf = io.StringIO()
    buf.write("﻿")
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Организация", "Логин", "Код доступа", "Статус", "Выдано ключей", "Лимит ключей", "Людей", "Трафик всего, байт"])
    for o in org_rows():
        w.writerow([csv_safe(o["name"]), o["slug"], o["code"], "включена" if o["enabled"] else "отключена",
                    o["issued"], o["key_limit"], o["people"], o["traffic"]])
    return Response(buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="vpn-organizations.csv"'})


@app.route("/super/backup", methods=["GET", "POST"])
def super_backup():
    if not super_required():
        return redirect("/super/login")
    if request.method == "GET":
        return page("backup.html")
    if not check_csrf():
        flash("Сессия устарела, обновите страницу.", "err")
        return redirect("/super/backup")
    if blocked("admin", LIMIT_ADMIN_IP, LIMIT_ADMIN_ALL):
        flash("Слишком много неверных попыток. Подождите около 15 минут.", "err")
        return redirect("/super/backup")
    pw = super_password()
    if len(pw) < 8 or not hmac.compare_digest(request.form.get("password", "").encode(), pw.encode()):
        record_attempt("admin")
        auth_fail("super-backup-password")
        flash("Неверный пароль общего администратора.", "err")
        return redirect("/super/backup")
    phrase, phrase2 = request.form.get("passphrase", ""), request.form.get("passphrase2", "")
    if len(phrase) < 12:
        flash("Парольная фраза должна быть не короче 12 символов.", "err")
        return redirect("/super/backup")
    if phrase != phrase2:
        flash("Парольные фразы не совпадают.", "err")
        return redirect("/super/backup")
    if SHARED_DSN:
        c = db()
        with c.read_snapshot():
            configs = {f"client{r[0]:03d}.conf": r[1].encode("utf-8")
                       for r in c.execute("SELECT slot, body FROM portal_configs ORDER BY slot")}
            plain, manifest = backup.dump_state(c, CONF_DIR, TRAFFIC_FILE, configs=configs)
    else:
        plain, manifest = backup.dump_state(db(), CONF_DIR, TRAFFIC_FILE)
    blob = backup.encrypt(plain, phrase)
    counts = manifest["counts"]
    audit("super", "создана резервная копия", f"организаций {counts['orgs']}, людей {counts['people']}, выдано {counts['assignments']}, конфигов {counts['configs']}")
    log.info("backup: создана резервная копия (%d байт)", len(blob))
    stamp = datetime.now(TZ).strftime("%Y%m%d-%H%M")
    return Response(blob, mimetype="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="vpn-backup-{stamp}.vpnbak"'})


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8081)
