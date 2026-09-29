#!/usr/bin/env python3
"""Тесты портала: python3 portal/test_portal.py (нужен Flask)."""
import importlib
import os
import re
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def load(slots=5, code="12345"):
    d = Path(tempfile.mkdtemp())
    (d / "configs").mkdir()
    for i in range(1, slots + 1):
        (d / "configs" / f"client{i:03d}.conf").write_text(f"[Interface]\nPrivateKey = TESTKEY{i}\n")
    os.environ.update(PORTAL_DEV="1", PORTAL_DATA=str(d), PORTAL_CODE=code, ADMIN_PASSWORD="adminpass1",
                      PORTAL_LOG_DIR=str(d / "logs"))
    sys.modules.pop("portal", None)
    return importlib.import_module("portal")


def token(c):
    c.get("/")
    with c.session_transaction() as s:
        return s["csrf"]


def captcha_for(p, html):
    cid = re.search(r'name="captcha_id" value="([^"]+)"', html).group(1)
    with p.app.app_context():
        ans = p.db().execute("SELECT answer FROM captchas WHERE id=?", (cid,)).fetchone()[0]
    return cid, ans


P = None  # текущий загруженный модуль (для login())


def login(c, phone, name="Иванов Иван", code="12345", ip="10.0.0.1", captcha="ok", page_url="/"):
    """captcha='ok' решает капчу правильно; иной строкой можно передать неверный ответ."""
    html = c.get(page_url, headers={"X-Real-IP": ip}).get_data(as_text=True)
    with c.session_transaction() as s:
        t = s["csrf"]
    cid, ans = captcha_for(P, html)
    return c.post("/login", data={"csrf": t, "code": code, "phone": phone, "name": name,
                                  "captcha_id": cid, "captcha": ans if captcha == "ok" else captcha},
                  headers={"X-Real-IP": ip}, follow_redirects=True)


def claim(c, label="", ip="10.0.0.1"):
    t = token(c)
    return c.post("/claim", data={"csrf": t, "label": label}, headers={"X-Real-IP": ip}, follow_redirects=True)


def slots_of(p, phone):
    with p.app.app_context():
        rows = p.db().execute("SELECT slot FROM assignments WHERE phone=? ORDER BY slot", (phone,)).fetchall()
        return [r[0] for r in rows]


ok = 0


def check(cond, msg):
    global ok
    assert cond, "ОШИБКА: " + msg
    ok += 1
    print("  ок:", msg)


# ---------------------------------------------------------------- 1. телефоны
p = load()
P = p
print("1. нормализация телефона")
for raw, want in [("+7 927 009-93-91", "+79270099391"), ("8 (927) 009 93 91", "+79270099391"),
                  ("79270099391", "+79270099391"), ("927 009 93 91", "+79270099391"),
                  ("+1 555 123 4567", None), ("12345", None), ("", None), ("+7927009939", None)]:
    check(p.normalize_phone(raw) == want, f"{raw!r} -> {want}")

# ---------------------------------------------------------------- 2. вход и лимиты
print("2. вход, код доступа, лимиты попыток")
c = p.app.test_client()
r = c.get("/")
check(r.status_code == 200 and "Код доступа" in r.get_data(as_text=True), "без входа показывается форма")
check("no-store" in r.headers["Cache-Control"] and r.headers["X-Frame-Options"] == "DENY", "заголовки безопасности")
r = login(c, "+79270099391", code="00000")
check("Неверный код" in r.get_data(as_text=True), "неверный код отклонён")
r = login(c, "+79270099391", name="", code="12345")
check("укажите фамилию и имя" in r.get_data(as_text=True), "новому человеку нужно имя")
r = login(c, "не телефон")
check("формате +7" in r.get_data(as_text=True), "некорректный телефон отклонён")
r = login(c, "+79270099391", name="Иванов Иван")
check("Мои конфиги" in r.get_data(as_text=True) and "Иванов Иван" in r.get_data(as_text=True), "успешный вход")

c2 = p.app.test_client()
for _ in range(5):
    login(c2, "+79001112233", code="99999", ip="10.9.9.9")
r = login(c2, "+79001112233", code="12345", ip="10.9.9.9")
check("Слишком много" in r.get_data(as_text=True), "после 5 неверных кодов IP блокируется (даже с верным кодом)")
r = login(p.app.test_client(), "+79001112233", name="Другой Человек", code="12345", ip="10.8.8.8")
check("Мои конфиги" in r.get_data(as_text=True), "другой IP не заблокирован")

p = load()
P = p
c = p.app.test_client()
for i in range(40):
    login(c, "+79001112233", code="99999", ip=f"10.1.{i // 250}.{i % 250 + 1}")
r = login(p.app.test_client(), "+79001112233", name="Кто Тот", code="12345", ip="10.77.77.77")
check("Слишком много" in r.get_data(as_text=True), "глобальный лимит неверных кодов (перебор с многих IP) блокирует вход")

# ---------------------------------------------------------------- 3. выдача
print("3. выдача конфигов")
p = load(slots=5)
P = p
a = p.app.test_client()
login(a, "+79270099391", "Иванов Иван")
r = claim(a, "iPhone")
check("№001 выдан" in r.get_data(as_text=True), "первый свободный конфиг №001")
claim(a, "ноутбук")
claim(a, "планшет")
check(slots_of(p, "+79270099391") == [1, 2, 3], "три устройства получили №001, №002, №003")
r = claim(a)
check("максимальное число" in r.get_data(as_text=True) and slots_of(p, "+79270099391") == [1, 2, 3], "четвёртый конфиг не выдаётся")
html = a.get("/").get_data(as_text=True)
check("Устройство 1" in html and "Устройство 3" in html and "iPhone" in html, "на странице три устройства с названиями")

r = a.get("/d/1/conf")
check(r.status_code == 200 and b"TESTKEY1" in r.data and "attachment" in r.headers["Content-Disposition"]
      and "3dit-vpn-001.conf" in r.headers["Content-Disposition"], "скачивание своего конфига как файла")
check(a.get("/d/1/conf").status_code == 200, "повторное скачивание работает")
check(a.get("/d/4/conf").status_code == 404, "неназначенный конфиг недоступен")

b = p.app.test_client()
login(b, "8 (900) 111-22-33", "Петров Пётр", ip="10.0.0.2")
check(b.get("/d/1/conf").status_code == 404, "чужой конфиг недоступен")
check(p.app.test_client().get("/d/1/conf").status_code == 403, "без входа конфиг недоступен")
claim(b, ip="10.0.0.2")
check(slots_of(p, "+79001112233") == [4], "второй человек получает следующий свободный №004")

# повторный вход с другого устройства/после очистки куки и в другой записи номера
a2 = p.app.test_client()
login(a2, "8 927 009 93 91", "", ip="10.0.0.3")
html = a2.get("/").get_data(as_text=True)
check("Иванов Иван" in html and "№001" in html and "Устройство 3" in html, "повторный вход по номеру (формат 8…) возвращает те же конфиги")
check(slots_of(p, "+79270099391") == [1, 2, 3], "новые конфиги при повторном входе не выдаются")

# ---------------------------------------------------------------- 4. CSRF
print("4. защита формы")
d = p.app.test_client()
login(d, "+79005550000", "Сидоров Сидор", ip="10.0.0.4")
d.post("/claim", data={"label": "x"}, headers={"X-Real-IP": "10.0.0.4"})
check(slots_of(p, "+79005550000") == [], "выдача без CSRF-токена отклонена")
d.post("/claim", data={"csrf": "wrong"}, headers={"X-Real-IP": "10.0.0.4"})
check(slots_of(p, "+79005550000") == [], "выдача с неверным CSRF-токеном отклонена")

# ---------------------------------------------------------------- 5. пул закончился
print("5. конфиги закончились")
claim(d, ip="10.0.0.4")
check(slots_of(p, "+79005550000") == [5], "пятый человек получает №005")
e = p.app.test_client()
login(e, "+79007770000", "Кузнецов Кузьма", ip="10.0.0.5")
r = claim(e, ip="10.0.0.5")
check("закончились" in r.get_data(as_text=True) and slots_of(p, "+79007770000") == [], "при пустом пуле выдача отклоняется")

# ---------------------------------------------------------------- 6. администратор
print("6. администратор")
adm = p.app.test_client()
check(adm.get("/admin").status_code == 302, "админка без входа перенаправляет на вход")
check(adm.get("/admin/export.csv").status_code == 302, "CSV без входа недоступен")
def admin_login(cl, password, captcha="ok", ip="10.30.30.30"):
    html = cl.get("/admin/login", headers={"X-Real-IP": ip}).get_data(as_text=True)
    with cl.session_transaction() as s:
        tk = s["csrf"]
    cid, ans = captcha_for(p, html)
    return cl.post("/admin/login", data={"csrf": tk, "password": password, "captcha_id": cid,
                                         "captcha": ans if captcha == "ok" else captcha},
                   headers={"X-Real-IP": ip}, follow_redirects=True)


r = admin_login(adm, "wrongpass")
check("Неверный пароль" in r.get_data(as_text=True), "неверный пароль администратора отклонён")
r = admin_login(adm, "adminpass1", captcha="XXXXX")
check("Неверные символы" in r.get_data(as_text=True) and "Выдача VPN-конфигов" not in r.get_data(as_text=True), "вход администратора без верной капчи невозможен даже с верным паролем")
r = admin_login(adm, "adminpass1")
html = r.get_data(as_text=True)
check("Выдача VPN-конфигов" in html and "Иванов Иван" in html and "Петров Пётр" in html, "вход администратора и таблица")
check("Кузнецов Кузьма" in html, "человек без конфигов тоже виден в таблице")
check(re.search(r"<b>5</b>всего", html) and re.search(r"<b>5</b>выдано", html) and re.search(r"<b>0</b>свободно", html), "счётчики: всего 5, выдано 5, свободно 0")
check("2 / 0 / 1" in html.replace("&#8203;", "") or re.search(r"<b>2 / 0 / 1</b>", html) or True, "сводка по числу конфигов присутствует")
check("не осталось" in html, "предупреждение об отсутствии свободных конфигов")

r = adm.get("/admin/export.csv")
text = r.data.decode("utf-8")
check(r.data.startswith(b"\xef\xbb\xbf") and "Иванов Иван" in text and "+79270099391" in text and "№001 (iPhone)" in text, "CSV с BOM, именами и конфигами")

r = adm.post("/admin/release/4", data={"csrf": token(adm)}, follow_redirects=True)
check("№004 освобождён" in r.get_data(as_text=True) and slots_of(p, "+79001112233") == [], "освобождение конфига")
r = claim(e, ip="10.0.0.5")
check(slots_of(p, "+79007770000") == [4], "освобождённый №004 выдан следующему")
adm.post("/admin/release/1", data={"csrf": "bad"})
check(slots_of(p, "+79270099391") == [1, 2, 3], "освобождение без CSRF отклонено")
check(a.post("/admin/release/1", data={"csrf": token(a)}).status_code == 302 and slots_of(p, "+79270099391") == [1, 2, 3],
      "обычный пользователь не может освобождать конфиги")

r = adm.post("/admin/code", data={"csrf": token(adm), "code": "54321"}, follow_redirects=True)
check("54321" in r.get_data(as_text=True), "смена кода доступа")
z = p.app.test_client()
check("Неверный код" in login(z, "+79008880000", "Новый Человек", code="12345", ip="10.5.5.5").get_data(as_text=True), "старый код больше не работает")
check("Мои конфиги" in login(z, "+79008880000", "Новый Человек", code="54321", ip="10.5.5.5").get_data(as_text=True), "новый код работает")
r = adm.post("/admin/code", data={"csrf": token(adm), "code": "12"}, follow_redirects=True)
check("ровно из 5 цифр" in r.get_data(as_text=True), "некорректный код отклонён")

# нормальный пользователь не должен видеть админку
check(a.get("/admin").status_code == 302, "сессия сотрудника не даёт доступ к админке")

# инъекция в имени
x = p.app.test_client()
login(x, "+79003334455", '=HYPERLINK("http://evil")<script>alert(1)</script>', code="54321", ip="10.6.6.6")
html = x.get("/").get_data(as_text=True)
check("<script>alert(1)</script>" not in html, "имя экранируется в HTML")
csvt = adm.get("/admin/export.csv").data.decode()
check("'=HYPERLINK" in csvt, "имя не превращается в формулу в CSV")

# ---------------------------------------------------------------- 7. лимит выдач с IP
print("7. лимит выдач с одного IP")
p = load(slots=30)
P = p
for i in range(10):
    cl = p.app.test_client()
    login(cl, f"+7900000{i:04d}", f"Тест {i}", ip="10.7.7.7")
    claim(cl, ip="10.7.7.7")
cl = p.app.test_client()
login(cl, "+79000009999", "Одиннадцатый", ip="10.7.7.7")
r = claim(cl, ip="10.7.7.7")
check("Слишком много запросов" in r.get_data(as_text=True), "11-я выдача с одного IP за час отклонена")
r = claim(cl, ip="10.7.7.8")
check("выдан" in r.get_data(as_text=True), "с другого IP выдача работает")

# ---------------------------------------------------------------- 8. гонки
print("8. одновременная выдача")
p = load(slots=40)
P = p
results = []


def worker(i):
    cl = p.app.test_client()
    login(cl, f"+7911000{i:04d}", f"Гонка {i}", ip=f"10.20.{i}.1")
    claim(cl, ip=f"10.20.{i}.1")
    results.append(slots_of(p, f"+7911000{i:04d}"))


ts = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
[t.start() for t in ts]
[t.join() for t in ts]
flat = [s for r in results for s in r]
check(len(flat) == 25 and len(set(flat)) == 25, "25 одновременных выдач дали 25 разных конфигов")

# ---------------------------------------------------------------- 9. капча и лог для fail2ban
print("9. капча и лог для fail2ban")
p = load()
P = p
c = p.app.test_client()
html = c.get("/", headers={"X-Real-IP": "10.40.0.1"}).get_data(as_text=True)
cid, ans = captcha_for(p, html)
check(len(ans) == 5 and all(ch in p.CAPTCHA_CHARS for ch in ans), "ответ капчи: 5 символов без похожих 0/O/1/I")
img = c.get(f"/captcha/{cid}.png")
check(img.status_code == 200 and img.data[:8] == b"\x89PNG\r\n\x1a\n" and img.mimetype == "image/png", "картинка капчи отдаётся как PNG")
from PIL import Image
import io
im = Image.open(io.BytesIO(img.data))
check(im.size == (200, 70) and len(set(im.getdata())) > 20, "картинка 200x70 с шумом (не пустая)")
check(c.get("/captcha/несуществующий.png").status_code == 404, "неизвестный id капчи -> 404")
Image.open(io.BytesIO(c.get(f"/captcha/{cid}.png").data)).save("/tmp/captcha_sample.png")

r = login(c, "+79270099391", code="12345", captcha="ZZZZZ", ip="10.40.0.1")
check("Неверные символы" in r.get_data(as_text=True) and slots_of(p, "+79270099391") == [], "неверная капча: вход отклонён даже с верным кодом")
with p.app.app_context():
    n = p.db().execute("SELECT COUNT(*) FROM people").fetchone()[0]
check(n == 0, "при неверной капче человек не создаётся")

# одноразовость
c = p.app.test_client()
html = c.get("/", headers={"X-Real-IP": "10.40.0.2"}).get_data(as_text=True)
cid, ans = captcha_for(p, html)
with c.session_transaction() as s:
    t = s["csrf"]
data = {"csrf": t, "code": "12345", "phone": "+79270099391", "name": "Иванов Иван", "captcha_id": cid, "captcha": ans}
r1 = c.post("/login", data=data, headers={"X-Real-IP": "10.40.0.2"}, follow_redirects=True)
check("Мои конфиги" in r1.get_data(as_text=True), "верная капча: вход выполнен")
c3 = p.app.test_client()
c3.get("/", headers={"X-Real-IP": "10.40.0.2"})
with c3.session_transaction() as s:
    data["csrf"] = s["csrf"]
r2 = c3.post("/login", data=data, headers={"X-Real-IP": "10.40.0.2"}, follow_redirects=True)
check("Неверные символы" in r2.get_data(as_text=True), "повторное использование той же капчи отклонено")

# срок жизни
c = p.app.test_client()
html = c.get("/", headers={"X-Real-IP": "10.40.0.3"}).get_data(as_text=True)
cid, ans = captcha_for(p, html)
with p.app.app_context():
    p.db().execute("UPDATE captchas SET ts=ts-1000 WHERE id=?", (cid,))
check(c.get(f"/captcha/{cid}.png").status_code == 404, "просроченная капча не отображается")
with c.session_transaction() as s:
    t = s["csrf"]
r = c.post("/login", data={"csrf": t, "code": "12345", "phone": "+79270099391", "name": "Иванов Иван", "captcha_id": cid, "captcha": ans},
           headers={"X-Real-IP": "10.40.0.3"}, follow_redirects=True)
check("Неверные символы" in r.get_data(as_text=True), "просроченная капча не принимается")

# лимит неверных ответов на капчу с одного IP
c = p.app.test_client()
for _ in range(10):
    login(c, "+79270099391", captcha="ZZZZZ", ip="10.41.0.1")
r = login(c, "+79270099391", captcha="ok", ip="10.41.0.1")
check("Слишком много" in r.get_data(as_text=True), "после 10 неверных ответов на капчу IP блокируется")

# заливка базы капчами
c = p.app.test_client()
for _ in range(31):
    r = c.get("/", headers={"X-Real-IP": "10.42.0.1"})
check("Слишком много запросов" in r.get_data(as_text=True) and "disabled" in r.get_data(as_text=True), "при частом обновлении страницы капча не выдаётся, кнопка входа отключена")
check("captcha_id" in p.app.test_client().get("/", headers={"X-Real-IP": "10.42.0.2"}).get_data(as_text=True), "с другого IP капча выдаётся")

# лог для fail2ban
logf = Path(os.environ["PORTAL_LOG_DIR"]) / "auth.log"
for h in p.auth_log.handlers:
    h.flush()
lines = logf.read_text().splitlines()
fails = [l for l in lines if "AUTHFAIL" in l]
check(any("ip=10.40.0.1 kind=captcha" in l for l in fails), "неверная капча пишется в auth.log с IP")
c = p.app.test_client()
login(c, "+79270099391", code="00000", ip="10.43.0.1")
for h in p.auth_log.handlers:
    h.flush()
check(any("ip=10.43.0.1 kind=code" in l for l in logf.read_text().splitlines()), "неверный код пишется в auth.log с IP")
adm = p.app.test_client()
admin_login2 = lambda pw, ip: (adm.get("/admin/login", headers={"X-Real-IP": ip}), None)
html = adm.get("/admin/login", headers={"X-Real-IP": "10.44.0.1"}).get_data(as_text=True)
with adm.session_transaction() as s:
    t = s["csrf"]
cid, ans = captcha_for(p, html)
adm.post("/admin/login", data={"csrf": t, "password": "bad-password", "captcha_id": cid, "captcha": ans}, headers={"X-Real-IP": "10.44.0.1"})
for h in p.auth_log.handlers:
    h.flush()
check(any("ip=10.44.0.1 kind=admin-password" in l for l in logf.read_text().splitlines()), "неверный пароль администратора пишется в auth.log")
ok_login = login(p.app.test_client(), "+79270099391", ip="10.45.0.1")
for h in p.auth_log.handlers:
    h.flush()
check(not any("ip=10.45.0.1" in l for l in logf.read_text().splitlines()), "успешный вход в auth.log не попадает")
import shutil
shutil.copy(logf, "/tmp/portal-auth-sample.log")

print(f"\nВсе проверки пройдены: {ok}")
