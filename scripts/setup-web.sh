#!/usr/bin/env bash
# Разворачивает сайт с личными страницами VPN и зеркалом приложений (nginx + Let's Encrypt).
# Запуск от root на сервере (Ubuntu/Debian), из каталога склонированного репозитория:
#
#   sudo DOMAIN=pm-vpn.3dit.ru EMAIL=you@example.com ./scripts/setup-web.sh /путь/к/out/site
#
# /путь/к/out/site: каталог site из архива (внутри него каталог c/ с личными страницами).
# Требования: домен указывает на этот сервер, порты 80 и 443 (TCP) открыты снаружи.
set -euo pipefail

DOMAIN="${DOMAIN:-pm-vpn.3dit.ru}"
EMAIL="${EMAIL:-}"
SITE_SRC="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$HERE/../deploy"

[ "$(id -u)" -eq 0 ] || { echo "Запустите от root"; exit 1; }
[ -d "$SITE_SRC/c" ] || { echo "Использование: $0 /путь/к/out/site   (внутри должен быть каталог c/)"; exit 1; }
[ -f "$DEPLOY/nginx-http.conf" ] && [ -f "$DEPLOY/nginx-https.conf" ] || { echo "Не найдены шаблоны nginx в $DEPLOY"; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx certbot curl jq

# файлы сайта: личные страницы обновляются целиком, каталог apps/ не трогаем
install -d -m 755 /var/www/vpn /var/www/certbot
rm -rf /var/www/vpn/c
cp -a "$SITE_SRC/c" /var/www/vpn/c
chown -R root:root /var/www/vpn/c
find /var/www/vpn/c -type d -exec chmod 755 {} +
find /var/www/vpn/c -type f -exec chmod 644 {} +

# фаервол
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi

CONF=/etc/nginx/conf.d/vpn.conf

# 1) HTTP-конфиг для проверки домена
sed "s/__DOMAIN__/$DOMAIN/g" "$DEPLOY/nginx-http.conf" > "$CONF"
nginx -t
systemctl enable --now nginx
systemctl reload nginx

# 2) сертификат
if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
  if [ -n "$EMAIL" ]; then MAILARG=(-m "$EMAIL"); else MAILARG=(--register-unsafely-without-email); fi
  certbot certonly --webroot -w /var/www/certbot -d "$DOMAIN" --non-interactive --agree-tos "${MAILARG[@]}"
fi
install -d /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

# 3) боевой HTTPS-конфиг
sed "s/__DOMAIN__/$DOMAIN/g" "$DEPLOY/nginx-https.conf" > "$CONF"
nginx -t
systemctl reload nginx

# 4) приложения (один раз; дальнейшие обновления: запускать fetch-apps.sh вручную)
if [ -x "$HERE/fetch-apps.sh" ]; then
  "$HERE/fetch-apps.sh" || echo "ПРЕДУПРЕЖДЕНИЕ: приложения не скачались, повторите позже: sudo $HERE/fetch-apps.sh"
fi

echo "Готово: https://$DOMAIN/ (личные страницы по адресам /c/<токен>/)"
