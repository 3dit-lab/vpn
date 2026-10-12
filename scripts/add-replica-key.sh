#!/usr/bin/env bash
# ОСНОВНОЙ сервер: разрешает резервному серверу забирать данные портала (ограниченный ключ: только export и import-traffic).
#   sudo ./scripts/add-replica-key.sh '<публичный ключ>' <IP резервного сервера> <имя, например kz-1> <домен сертификата>
set -euo pipefail
PUB="${1:?публичный ключ}"; IP="${2:?IP резервного сервера}"; NAME="${3:?имя, например kz-1}"; DOMAIN="${4:-pm-vpn.3dit.ru}"
[ "$(id -u)" -eq 0 ] || { echo "Запустите от root"; exit 1; }
[[ "$PUB" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ [A-Za-z0-9._@-]+)?$ ]] || { echo "Ожидается публичный ключ ssh-ed25519"; exit 1; }
[[ "$IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "Некорректный IP"; exit 1; }
[[ "$NAME" =~ ^[a-z0-9-]{1,20}$ ]] || { echo "Имя: строчные латинские буквы, цифры, дефис"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
install -m 755 "$HERE/replica-serve.py" /opt/vpn-portal/replica-serve.py
install -d -m 700 /root/.ssh
AK=/root/.ssh/authorized_keys
touch "$AK"; chmod 600 "$AK"
KEYBODY="$(echo "$PUB" | awk '{print $2}')"
grep -v -F "$KEYBODY" "$AK" > "$AK.new" || true
echo "command=\"/opt/vpn-portal/replica-serve.py $NAME $DOMAIN\",restrict,from=\"$IP\" $PUB" >> "$AK.new"
chmod 600 "$AK.new"; mv "$AK.new" "$AK"
echo "Ключ добавлен: $NAME ($IP) может только export и import-traffic."
echo "Файрвол: ufw allow from $IP to any port 22 proto tcp"
