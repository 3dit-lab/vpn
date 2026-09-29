#!/usr/bin/env bash
# Установка AmneziaWG на сервер (Ubuntu 20.04/22.04/24.04) и применение готового awg0.conf.
# Запуск от root:  ./install-server.sh /путь/к/awg0.conf
set -euo pipefail

CONF_SRC="${1:-}"
[ "$(id -u)" -eq 0 ] || { echo "Запустите от root"; exit 1; }
[ -f "$CONF_SRC" ] || { echo "Использование: $0 /путь/к/awg0.conf"; exit 1; }
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || { echo "Скрипт рассчитан на Ubuntu (PPA amnezia/ppa). Ваша ОС: ${PRETTY_NAME:-?}"; exit 1; }

PORT="$(awk -F' *= *' '/^ListenPort/{print $2}' "$CONF_SRC")"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y software-properties-common iptables "linux-headers-$(uname -r)"
add-apt-repository -y ppa:amnezia/ppa
apt-get update -y
apt-get install -y amneziawg amneziawg-tools

# маршрутизация клиентов наружу
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-awg.conf
sysctl --system >/dev/null

install -d -m 700 /etc/amnezia/amneziawg
install -m 600 "$CONF_SRC" /etc/amnezia/amneziawg/awg0.conf

# открыть порт, если включён ufw
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "${PORT}/udp"
fi

systemctl enable --now awg-quick@awg0
sleep 1
awg show awg0 | head -8
echo "Готово. UDP-порт ${PORT} должен быть доступен снаружи (проверьте фаервол провайдера/облака)."
