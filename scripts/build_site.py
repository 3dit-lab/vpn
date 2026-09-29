#!/usr/bin/env python3
"""Сборка личных страниц и QR-кодов для клиентов.

Читает secrets/state.json и out/clients/*.conf (их создаёт generate.py), добавляет каждому
клиенту постоянный случайный токен (в state.json, поэтому ссылки не меняются при пересборке) и
создаёт статический сайт, который раздаёт nginx:

    out/site/c/<token>/index.html          личная страница сотрудника
    out/site/c/<token>/3dit-vpn-NNN.conf   его конфиг
    out/qr/clientNNN.png                   QR со ссылкой на личную страницу
    out/qr-links.csv                       имя, ссылка (СЕКРЕТНО: ссылка даёт доступ к приватному ключу)

Пример:
    python3 scripts/build_site.py --domain pm-vpn.3dit.ru
"""
import argparse
import csv
import html
import json
import os
import secrets
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title>VPN: подключение __NUM__</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --fg:#1b1f24; --muted:#5b6570; --accent:#1f6feb; --line:#dde2e8; --warn:#fff4e5; --warnfg:#7a4b00; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#12151a; --card:#1a1e24; --fg:#e8ebef; --muted:#9aa4af; --accent:#5b9dff; --line:#2b323b; --warn:#3a2d12; --warnfg:#f0c674; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  main { max-width:640px; margin:0 auto; padding:16px; }
  h1 { font-size:22px; margin:8px 0 4px; }
  h2 { font-size:17px; margin:0 0 8px; }
  .sub { color:var(--muted); margin:0 0 16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; margin:0 0 12px; }
  .btn { display:block; width:100%; text-align:center; padding:14px 16px; border-radius:10px; border:0; font:inherit; font-weight:600; text-decoration:none; cursor:pointer; margin:8px 0 0; }
  .primary { background:var(--accent); color:#fff; }
  .secondary { background:transparent; color:var(--accent); border:1px solid var(--accent); }
  ol { margin:8px 0 0; padding-left:22px; }
  li { margin:6px 0; }
  .warn { background:var(--warn); color:var(--warnfg); border-radius:10px; padding:12px 14px; margin:0 0 12px; font-size:15px; }
  details { margin:0 0 12px; }
  summary { cursor:pointer; color:var(--accent); padding:8px 0; }
  code { background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:1px 6px; font-size:14px; }
  .os { display:none; }
  .os.show { display:block; }
  small { color:var(--muted); }
</style>
</head>
<body>
<main>
  <h1>Доступ к VPN</h1>
  <p class="sub">Личное подключение № __NUM__ · ООО «Тридит»</p>

  <div class="warn">Эта страница и файл конфигурации личные. Не пересылайте ссылку и не публикуйте её: по ней можно подключиться от вашего имени.</div>

  <div class="card">
    <h2>1. Скачайте свой конфиг</h2>
    <a class="btn primary" href="__CONF__" download="__CONF__">Скачать конфиг (__CONF__)</a>
    <button class="btn secondary" id="copy" type="button">Скопировать конфиг</button>
    <small id="copystate"></small>
  </div>

  <div class="card">
    <h2>2. Установите приложение</h2>
    <a class="btn secondary" href="/apps/">Приложения для Windows, macOS, Linux и Android</a>
  </div>

  <div class="card">
    <h2>3. Добавьте конфиг в приложение</h2>

    <div class="os" id="os-ios">
      <b>iPhone / iPad</b>
      <ol>
        <li>Установите из App Store приложение <b>DefaultVPN</b> (iOS 16 и новее). Оно доступно в российском App Store.</li>
        <li>Нажмите «Скачать конфиг» выше. Файл сохранится в Safari.</li>
        <li>Откройте скачанный файл, нажмите «Поделиться» (или «Открыть в…») и выберите DefaultVPN.</li>
        <li>Разрешите добавление VPN-конфигурации, когда iOS попросит, и включите подключение.</li>
      </ol>
      <p><small>Приложение Amnezia VPN в российском App Store недоступно; для него нужен аккаунт App Store другой страны.</small></p>
    </div>

    <div class="os" id="os-android">
      <b>Android</b>
      <ol>
        <li>Установите приложение Amnezia VPN (Google Play или файл .apk со страницы приложений; для файла разрешите установку из неизвестных источников).</li>
        <li>Нажмите «Скачать конфиг» выше.</li>
        <li>В приложении выберите добавление подключения из файла и укажите скачанный файл (или откройте файл из уведомления о загрузке через приложение).</li>
        <li>Включите подключение.</li>
      </ol>
    </div>

    <div class="os" id="os-windows">
      <b>Windows</b>
      <ol>
        <li>Установите Amnezia VPN со страницы приложений.</li>
        <li>Нажмите «Скачать конфиг» выше.</li>
        <li>В приложении выберите добавление подключения из файла и укажите скачанный файл.</li>
        <li>Включите подключение.</li>
      </ol>
    </div>

    <div class="os" id="os-mac">
      <b>macOS</b>
      <ol>
        <li>Установите Amnezia VPN со страницы приложений.</li>
        <li>Нажмите «Скачать конфиг» выше.</li>
        <li>В приложении выберите добавление подключения из файла и укажите скачанный файл.</li>
        <li>Включите подключение.</li>
      </ol>
    </div>

    <div class="os" id="os-linux">
      <b>Linux</b>
      <ol>
        <li>Установите Amnezia VPN со страницы приложений и импортируйте скачанный файл так же, как на других системах.</li>
        <li>Либо из консоли, если установлены <code>amneziawg-tools</code>: <code>sudo awg-quick up ./__CONF__</code></li>
      </ol>
    </div>

    <div class="os" id="os-other">
      Выберите свою систему в списке ниже.
    </div>
  </div>

  <details>
    <summary>Инструкции для других систем</summary>
    <div class="card"><b>Windows и macOS:</b> установите Amnezia VPN, скачайте конфиг, в приложении выберите добавление подключения из файла.</div>
    <div class="card"><b>Android:</b> установите Amnezia VPN, скачайте конфиг, добавьте его в приложении из файла.</div>
    <div class="card"><b>iPhone / iPad:</b> установите DefaultVPN из App Store, скачайте конфиг, откройте файл через «Поделиться» и выберите DefaultVPN.</div>
    <div class="card"><b>Linux:</b> Amnezia VPN или <code>sudo awg-quick up ./__CONF__</code>.</div>
  </details>

  <div class="card">
    <h2>Как проверить, что всё работает</h2>
    <p>После включения должны открываться заблокированные сервисы (мессенджеры, нейросети). Банки, госуслуги и локальные сайты продолжают работать напрямую, без VPN. Если подключение не поднимается, напишите в поддержку: it@3dit.ru.</p>
  </div>
</main>

<pre id="conf" hidden>__CONFTEXT__</pre>
<script>
(function () {
  var ua = navigator.userAgent || "";
  var p = navigator.platform || "";
  var id = "other";
  if (/iPhone|iPad|iPod/.test(ua) || (p === "MacIntel" && navigator.maxTouchPoints > 1)) id = "ios";
  else if (/Android/.test(ua)) id = "android";
  else if (/Windows/.test(ua)) id = "windows";
  else if (/Mac/.test(ua)) id = "mac";
  else if (/Linux|X11/.test(ua)) id = "linux";
  var el = document.getElementById("os-" + id);
  if (el) el.className += " show";

  var btn = document.getElementById("copy"), st = document.getElementById("copystate");
  btn.addEventListener("click", function () {
    var text = document.getElementById("conf").textContent;
    function done(ok) { st.textContent = ok ? "Конфиг скопирован в буфер обмена." : "Не удалось скопировать. Используйте кнопку «Скачать конфиг»."; }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    } else {
      var ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      var ok = false; try { ok = document.execCommand("copy"); } catch (e) {}
      document.body.removeChild(ta); done(ok);
    }
  });
})();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--state", default=str(ROOT / "secrets" / "state.json"))
    ap.add_argument("--out", default=str(ROOT / "out"))
    args = ap.parse_args()

    import qrcode
    from PIL import Image, ImageDraw

    state_path = Path(args.state)
    state = json.loads(state_path.read_text())
    out = Path(args.out)

    # постоянные токены: создаём только недостающие
    changed = False
    for c in state["clients"].values():
        if "token" not in c:
            c["token"] = secrets.token_urlsafe(24)  # 192 бита
            changed = True
    if changed:
        state_path.write_text(json.dumps(state, indent=2))
        os.chmod(state_path, 0o600)

    site = out / "site"
    if site.exists():
        shutil.rmtree(site)
    (site / "c").mkdir(parents=True)
    qr_dir = out / "qr"
    if qr_dir.exists():
        shutil.rmtree(qr_dir)
    qr_dir.mkdir()

    links = []
    for name, c in sorted(state["clients"].items()):
        num = name.replace("client", "")
        conf_src = out / "clients" / f"{name}.conf"
        conf_text = conf_src.read_text()
        conf_name = f"3dit-vpn-{num}.conf"  # имя файла = имя туннеля (до 15 символов)
        d = site / "c" / c["token"]
        d.mkdir()
        (d / conf_name).write_text(conf_text)
        page = (PAGE.replace("__NUM__", num)
                    .replace("__CONF__", conf_name)
                    .replace("__CONFTEXT__", html.escape(conf_text)))
        (d / "index.html").write_text(page)
        for f in d.iterdir():
            os.chmod(f, 0o644)

        url = f"https://{args.domain}/c/{c['token']}/"
        q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
        q.add_data(url)
        q.make(fit=True)
        img = q.make_image(fill_color="black", back_color="white").convert("RGB")
        w, h = img.size
        canvas = Image.new("RGB", (w, h + 34), "white")
        canvas.paste(img, (0, 0))
        ImageDraw.Draw(canvas).text((10, h + 8), f"VPN  №{num}", fill="black")
        canvas.save(qr_dir / f"{name}.png")
        links.append([name, url])

    with open(out / "qr-links.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "url"])
        w.writerows(links)
    os.chmod(out / "qr-links.csv", 0o600)

    print(f"Страниц: {len(links)}; пример ссылки: {links[0][1]}")
    print(f"Сайт: {site}; QR: {qr_dir}")


if __name__ == "__main__":
    main()
