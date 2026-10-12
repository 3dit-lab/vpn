#!/usr/bin/env bash
# Установка Xray (VLESS+Reality) рядом с AmneziaWG. Запуск от root из клона репозитория.
#   основной сервер:  sudo bash scripts/setup-xray.sh
#   резервный:        sudo XRAY_SECONDARY=1 bash scripts/setup-xray.sh   (параметры придут репликацией с основного)
# Переменные: XRAY_PORT (8443), XRAY_SNI (www.microsoft.com), XRAY_VERSION (latest)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$HERE/../deploy"
PORT="${XRAY_PORT:-8443}"
SNI="${XRAY_SNI:-www.microsoft.com}"
VER="${XRAY_VERSION:-latest}"
STATE=/etc/vpn-xray.json
[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 1; }
apt-get install -y unzip openssl curl >/dev/null

if [ ! -x /usr/local/bin/xray ]; then
  if [ "$VER" = latest ]; then BASE=https://github.com/XTLS/Xray-core/releases/latest/download
  else BASE=https://github.com/XTLS/Xray-core/releases/download/$VER; fi
  T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
  curl -fsSL -o "$T/x.zip" "$BASE/Xray-linux-64.zip"
  curl -fsSL -o "$T/x.dgst" "$BASE/Xray-linux-64.zip.dgst"
  want="$(grep -i '^SHA2-256' "$T/x.dgst" | head -1 | sed 's/.*= *//')"
  have="$(sha256sum "$T/x.zip" | cut -d' ' -f1)"
  [ -n "$want" ] && [ "$want" = "$have" ] || { echo "контрольная сумма Xray не совпала"; exit 1; }
  unzip -q -o "$T/x.zip" -d "$T/x"
  install -m 755 "$T/x/xray" /usr/local/bin/xray
  mkdir -p /usr/local/share/xray
  for f in geoip.dat geosite.dat; do [ ! -f "$T/x/$f" ] || install -m 644 "$T/x/$f" /usr/local/share/xray/$f; done
fi
/usr/local/bin/xray version | head -1

getent group xray >/dev/null || groupadd --system xray
id xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin -g xray xray
getent group vpnportal >/dev/null && usermod -aG xray vpnportal || true

if [ ! -f "$STATE" ] && [ -z "${XRAY_SECONDARY:-}" ]; then
  echo "проверка TLS 1.3 у $SNI ..."
  echo | openssl s_client -connect "$SNI:443" -servername "$SNI" -tls1_3 2>/dev/null | grep -q 'TLSv1.3' \
    || { echo "$SNI не отвечает по TLS 1.3, выберите другой XRAY_SNI"; exit 1; }
  kp="$(/usr/local/bin/xray x25519)"
  priv="$(echo "$kp" | grep -i 'private' | head -1 | sed 's/.*: *//')"
  pub="$(echo "$kp" | grep -iE 'public|password' | head -1 | sed 's/.*: *//')"
  [ -n "$priv" ] && [ -n "$pub" ] || { echo "не удалось разобрать ключи Reality"; exit 1; }
  umask 077
  python3 - "$priv" "$pub" "$SNI" "$PORT" > "$STATE.new" <<'PY'
import json, secrets, sys, uuid
priv, pub, sni, port = sys.argv[1:5]
print(json.dumps({"private": priv, "public": pub, "short_id": secrets.token_hex(8), "sni": sni,
                  "port": int(port), "salt": str(uuid.uuid4())}, indent=1))
PY
  chown root:xray "$STATE.new"; chmod 640 "$STATE.new"; mv "$STATE.new" "$STATE"
  echo "созданы параметры Reality: $STATE"
fi
[ -f "$STATE" ] && chgrp xray "$STATE" && chmod 640 "$STATE" || true

install -m 755 "$HERE/sync-xray.py" /opt/vpn-portal/sync-xray.py
install -m 755 "$HERE/collect-xray-traffic.py" /opt/vpn-portal/collect-xray-traffic.py
for u in xray.service vpn-xray-sync.service vpn-xray-sync.timer vpn-xray-traffic.service vpn-xray-traffic.timer; do
  install -m 644 "$DEPLOY/$u" /etc/systemd/system/$u
done
mkdir -p /usr/local/etc/xray && chgrp xray /usr/local/etc/xray && chmod 750 /usr/local/etc/xray
systemctl daemon-reload
if [ -f "$STATE" ]; then
  python3 /opt/vpn-portal/sync-xray.py
  chgrp xray /usr/local/etc/xray/config.json 2>/dev/null || true
  systemctl enable --now xray.service
fi
systemctl enable --now vpn-xray-sync.timer vpn-xray-traffic.timer
systemctl restart vpn-portal 2>/dev/null || true
command -v ufw >/dev/null && ufw status | grep -q "$PORT/tcp" || echo "Откройте порт: ufw allow $PORT/tcp"
echo "Готово."
