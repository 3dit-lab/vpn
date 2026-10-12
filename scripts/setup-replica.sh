#!/usr/bin/env bash
# Резервный сервер портала (второй сервер). Портал открыт на обоих серверах: запросы идут на основной сервер,
# а если он недоступен, отвечает локальная копия (данные забираются с основного раз в минуту).
# VPN на этом сервере уже работает отдельно (install-server.sh); здесь только портал, обмен и nginx.
#
#   sudo PRIMARY=fi-1-vpn.3dit.ru DOMAIN=pm-vpn.3dit.ru ALIASES="vpn.3dit.ru fi-1-vpn.3dit.ru kz-1-vpn.3dit.ru" \
#        PEER_NAME=kz-1 ./scripts/setup-replica.sh
#
# Запускается дважды:
#   1) первый запуск ставит пакеты, создаёт SSH-ключ и nginx для проверок сертификата, печатает строку для основного сервера;
#   2) после добавления строки на основной сервер (scripts/add-replica-key.sh) запустить ещё раз: данные, сертификат, nginx, службы.
set -euo pipefail

PRIMARY="${PRIMARY:?Укажите PRIMARY (имя основного сервера, например fi-1-vpn.3dit.ru)}"
DOMAIN="${DOMAIN:-pm-vpn.3dit.ru}"
ALIASES="${ALIASES:-vpn.3dit.ru}"
PEER_NAME="${PEER_NAME:?Укажите PEER_NAME этого сервера (например kz-1)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$HERE/../deploy"
PORTAL_DIR="$HERE/../portal"
KEY=/root/.ssh/vpn-replica
DATA=/var/lib/vpn-portal

[ "$(id -u)" -eq 0 ] || { echo "Запустите от root"; exit 1; }
for f in vpn-portal.service vpn-peer-sync.service vpn-peer-sync.path vpn-peer-sync.timer vpn-traffic.service vpn-traffic.timer \
         vpn-replica.service vpn-replica.timer nginx-secondary.conf nginx-primary.inc nginx-proxy.inc; do
  [ -f "$DEPLOY/$f" ] || { echo "Не найден $DEPLOY/$f"; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx curl jq rsync openssh-client python3-flask python3-cryptography python3-pil fonts-dejavu-core gunicorn

id vpnportal >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vpnportal
install -d -m 755 /opt/vpn-portal
install -m 644 "$PORTAL_DIR/portal.py" /opt/vpn-portal/portal.py
install -m 644 "$PORTAL_DIR/backup.py" /opt/vpn-portal/backup.py
for s in sync-peers.py collect-traffic.py replica-pull.py; do install -m 755 "$HERE/$s" /opt/vpn-portal/$s; done
install -d -o vpnportal -g vpnportal -m 700 "$DATA" "$DATA/configs"
install -d -o vpnportal -g vpnportal -m 755 /var/log/vpn-portal
touch /var/log/vpn-portal/auth.log; chown vpnportal:vpnportal /var/log/vpn-portal/auth.log
install -d -m 755 /var/www/vpn

for u in vpn-portal.service vpn-peer-sync.service vpn-peer-sync.path vpn-peer-sync.timer vpn-traffic.service vpn-traffic.timer \
         vpn-replica.service vpn-replica.timer; do
  install -m 644 "$DEPLOY/$u" /etc/systemd/system/$u
done
systemctl daemon-reload

printf '{"primary": "%s", "key": "%s", "peer": "%s"}\n' "$PRIMARY" "$KEY" "$PEER_NAME" > /etc/vpn-replica.json
chmod 600 /etc/vpn-replica.json
install -d -m 700 /root/.ssh
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "vpn-replica-$PEER_NAME" -f "$KEY"

# nginx: только HTTP с проксированием проверок Let's Encrypt на основной сервер
install -m 644 "$DEPLOY/nginx-proxy.inc" /etc/nginx/vpn-portal-proxy.inc
sed "s/__PRIMARY__/$PRIMARY/g" "$DEPLOY/nginx-primary.inc" > /etc/nginx/vpn-portal-primary.inc
CONF=/etc/nginx/conf.d/vpn.conf
if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
  cat > "$CONF" <<NG
server {
    listen 80;
    server_name $DOMAIN $ALIASES;
    location /.well-known/acme-challenge/ { proxy_pass http://$PRIMARY:80; proxy_set_header Host \$host; proxy_connect_timeout 5s; }
    location / { return 301 https://\$host\$request_uri; }
}
NG
fi
rm -f /etc/nginx/sites-enabled/default
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 80/tcp; ufw allow 443/tcp; fi
nginx -t && systemctl enable --now nginx && systemctl reload nginx

# проверка доступа к основному серверу
TESTF="$(mktemp)"
if ! ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "root@$PRIMARY" export > "$TESTF" 2>/dev/null \
   || ! tar -tzf "$TESTF" >/dev/null 2>&1; then
  rm -f "$TESTF"
  echo
  echo "Основной сервер пока не принимает ключ. На ОСНОВНОМ сервере выполните:"
  echo "  sudo /путь/к/репозиторию/scripts/add-replica-key.sh '$(cat $KEY.pub)' <IP этого сервера> $PEER_NAME $DOMAIN"
  echo "и разрешите SSH (22/tcp) с адреса этого сервера в файрволе основного сервера. Затем запустите этот скрипт ещё раз."
  exit 0
fi
rm -f "$TESTF"

# первая синхронизация данных
python3 /opt/vpn-portal/replica-pull.py
[ -s /etc/vpn-portal.env ] || { echo "Нет /etc/vpn-portal.env после синхронизации"; exit 1; }
[ -d "/etc/letsencrypt/live/$DOMAIN" ] || { echo "Нет сертификата $DOMAIN: на основном сервере запустите setup-web.sh с ALIASES, включающим имена обоих серверов"; exit 1; }

sed "s/__DOMAIN__/$DOMAIN/g; s/__ALIASES__/$ALIASES/g; s/__PRIMARY__/$PRIMARY/g" "$DEPLOY/nginx-secondary.conf" > "$CONF"
nginx -t
systemctl enable --now vpn-portal
systemctl reload nginx
systemctl enable --now vpn-peer-sync.path vpn-peer-sync.timer vpn-traffic.timer vpn-replica.timer
systemctl start vpn-peer-sync.service || true
echo
echo "Готово: резервный сервер портала работает (https://$DOMAIN/ проксируется на $PRIMARY, при его отказе отвечает локальная копия)."
echo "Если появится файл $DATA/DIVERGED, при отказе основного сервера здесь были выдачи: разберите расхождение вручную."
