#!/usr/bin/env bash
# Разворачивает портал выдачи VPN-конфигов: приложение (gunicorn + systemd), nginx с сертификатом
# Let's Encrypt, fail2ban и зеркало приложений. Запуск от root на сервере (Ubuntu/Debian) из каталога
# склонированного репозитория:
#
#   sudo DOMAIN=pm-vpn.3dit.ru EMAIL=you@example.com ./scripts/setup-web.sh /путь/к/clients
#
# /путь/к/clients: каталог с файлами client001.conf, client002.conf … (из архива, каталог clients/).
# Необязательные переменные:
#   PORTAL_CODE     начальный код доступа из 5 цифр (по умолчанию случайный; потом меняется в админке)
#   ADMIN_PASSWORD  пароль администратора, не короче 8 символов (по умолчанию случайный)
#   IGNOREIP        адреса через пробел, которые fail2ban никогда не банит (например, офисный IP)
# Требования: домен указывает на этот сервер, порты 80 и 443 (TCP) открыты снаружи.
# Повторный запуск безопасен: база выдачи, пароль и код сохраняются, новые конфиги добавляются в пул.
set -euo pipefail

DOMAIN="${DOMAIN:-pm-vpn.3dit.ru}"
EMAIL="${EMAIL:-}"
IGNOREIP="${IGNOREIP:-}"
CONFIGS_SRC="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$HERE/../deploy"
PORTAL_SRC="$HERE/../portal/portal.py"
ENV_FILE=/etc/vpn-portal.env
DATA=/var/lib/vpn-portal

[ "$(id -u)" -eq 0 ] || { echo "Запустите от root"; exit 1; }
[ -d "$CONFIGS_SRC" ] && ls "$CONFIGS_SRC"/client*.conf >/dev/null 2>&1 \
  || { echo "Использование: $0 /путь/к/clients   (в каталоге должны быть файлы client001.conf …)"; exit 1; }
[ -f "$PORTAL_SRC" ] || { echo "Не найден $PORTAL_SRC"; exit 1; }
for f in nginx-http.conf nginx-https.conf nginx-proxy.inc vpn-portal.service \
         fail2ban/filter.d/vpn-portal-auth.conf fail2ban/jail.d/vpn-portal.local; do
  [ -f "$DEPLOY/$f" ] || { echo "Не найден шаблон $DEPLOY/$f"; exit 1; }
done
if [ -n "${PORTAL_CODE:-}" ] && ! [[ "$PORTAL_CODE" =~ ^[0-9]{5}$ ]]; then echo "PORTAL_CODE: ровно 5 цифр"; exit 1; fi
if [ -n "${ADMIN_PASSWORD:-}" ] && [ "${#ADMIN_PASSWORD}" -lt 8 ]; then echo "ADMIN_PASSWORD: не короче 8 символов"; exit 1; fi
if [ -n "${ADMIN_PASSWORD:-}" ] && ! [[ "$ADMIN_PASSWORD" =~ ^[A-Za-z0-9._@%+-]+$ ]]; then
  echo "ADMIN_PASSWORD: допустимы латинские буквы, цифры и . _ @ % + -"; exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx certbot curl jq python3-flask python3-pil fonts-dejavu-core gunicorn fail2ban

# ---- пользователь, код и данные портала
id vpnportal >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vpnportal
install -d -m 755 /opt/vpn-portal
install -m 644 "$PORTAL_SRC" /opt/vpn-portal/portal.py
install -d -o vpnportal -g vpnportal -m 700 "$DATA" "$DATA/configs"
for f in "$CONFIGS_SRC"/client*.conf; do
  install -o vpnportal -g vpnportal -m 600 "$f" "$DATA/configs/$(basename "$f")"
done
install -d -o vpnportal -g vpnportal -m 755 /var/log/vpn-portal
touch /var/log/vpn-portal/auth.log
chown vpnportal:vpnportal /var/log/vpn-portal/auth.log

# ---- секреты (создаются один раз)
NEW_ENV=0
if [ ! -f "$ENV_FILE" ]; then
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  CODE="${PORTAL_CODE:-$(python3 -c 'import secrets; print(f"{secrets.randbelow(100000):05d}")')}"
  ADMINPW="${ADMIN_PASSWORD:-$(python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(16)))')}"
  (umask 077; printf 'PORTAL_SECRET_KEY=%s\nPORTAL_CODE=%s\nADMIN_PASSWORD=%s\n' "$SECRET" "$CODE" "$ADMINPW" > "$ENV_FILE")
  NEW_ENV=1
fi
chmod 600 "$ENV_FILE"

# ---- сервис портала
install -m 644 "$DEPLOY/vpn-portal.service" /etc/systemd/system/vpn-portal.service
systemctl daemon-reload
systemctl enable vpn-portal
systemctl restart vpn-portal
for _ in $(seq 1 20); do
  curl -fsS -o /dev/null http://127.0.0.1:8081/ 2>/dev/null && break
  sleep 0.5
done
curl -fsS -o /dev/null http://127.0.0.1:8081/ || { echo "Портал не запустился: journalctl -u vpn-portal -n 50"; exit 1; }

# ---- статика и фаервол
install -d -m 755 /var/www/vpn /var/www/certbot
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi

# ---- nginx: сначала HTTP для выпуска сертификата
install -m 644 "$DEPLOY/nginx-proxy.inc" /etc/nginx/vpn-portal-proxy.inc
CONF=/etc/nginx/conf.d/vpn.conf
sed "s/__DOMAIN__/$DOMAIN/g" "$DEPLOY/nginx-http.conf" > "$CONF"
nginx -t
systemctl enable --now nginx
systemctl reload nginx

if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
  if [ -n "$EMAIL" ]; then MAILARG=(-m "$EMAIL"); else MAILARG=(--register-unsafely-without-email); fi
  certbot certonly --webroot -w /var/www/certbot -d "$DOMAIN" --non-interactive --agree-tos "${MAILARG[@]}"
fi
install -d /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

sed "s/__DOMAIN__/$DOMAIN/g" "$DEPLOY/nginx-https.conf" > "$CONF"
nginx -t
systemctl reload nginx

# ---- fail2ban
install -m 644 "$DEPLOY/fail2ban/filter.d/vpn-portal-auth.conf" /etc/fail2ban/filter.d/vpn-portal-auth.conf
sed "s#__IGNOREIP__#127.0.0.1/8 ::1 $IGNOREIP#" "$DEPLOY/fail2ban/jail.d/vpn-portal.local" > /etc/fail2ban/jail.d/vpn-portal.local
fail2ban-client -t >/dev/null || { echo "Ошибка конфигурации fail2ban: fail2ban-client -t"; exit 1; }
systemctl enable fail2ban
systemctl restart fail2ban

# ---- приложения (один раз; дальше запускать fetch-apps.sh вручную)
if [ -x "$HERE/fetch-apps.sh" ]; then
  "$HERE/fetch-apps.sh" || echo "ПРЕДУПРЕЖДЕНИЕ: приложения не скачались, повторите позже: sudo $HERE/fetch-apps.sh"
fi

echo
echo "Готово: https://$DOMAIN/"
if [ "$NEW_ENV" = 1 ]; then
  echo "Код доступа для сотрудников: $CODE   (потом меняется в админке)"
  echo "Администратор: https://$DOMAIN/admin   пароль: $ADMINPW"
  echo "Запишите их: пароль хранится только в $ENV_FILE (доступ только у root)."
else
  echo "Используются существующие секреты из $ENV_FILE (код доступа виден в админке)."
fi
echo "Защита: fail2ban (вход: 6 неудач за 10 минут = бан на час). Статус: fail2ban-client status"
