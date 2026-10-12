#!/usr/bin/env bash
# DNS-роль сервера:
#  1) unbound для клиентов VPN (слушает только 10.8.0.1, снаружи недоступен);
#  2) vpn-dnsd: авторитетный DNS зоны (например vpn.3dit.ru), отдаёт только живые серверы.
# Запуск от root:  PUBLIC_IP=194.77.71.148 ./scripts/install-dns.sh [--no-zone]
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Запустите от root"; exit 1; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y unbound python3-dnslib dnsutils

# ---- unbound для клиентов VPN ----
install -m 644 "$HERE/deploy/unbound-vpn.conf" /etc/unbound/unbound.conf.d/vpn.conf
# убрать включённый по умолчанию IPv6/локальный интерфейс не нужно: interface задаёт наш адрес
systemctl enable unbound
systemctl restart unbound

# ---- авторитетная зона ----
if [ "${1:-}" != "--no-zone" ]; then
  id vpndns >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin vpndns
  install -d -m 755 /opt/vpn-dns
  install -m 755 "$HERE/scripts/vpn-dnsd.py" /opt/vpn-dns/vpn-dnsd.py
  if [ ! -f /etc/vpn-dnsd.json ]; then
    install -m 644 "$HERE/deploy/vpn-dnsd.json.example" /etc/vpn-dnsd.json
    [ -n "${PUBLIC_IP:-}" ] && sed -i "s/\"listen\": \"[0-9.]*\"/\"listen\": \"$PUBLIC_IP\"/" /etc/vpn-dnsd.json
    echo "Создан /etc/vpn-dnsd.json — проверьте listen и список серверов."
  fi
  install -m 644 "$HERE/deploy/vpn-dnsd.service" /etc/systemd/system/vpn-dnsd.service
  systemctl daemon-reload
  systemctl enable --now vpn-dnsd
  sleep 1
  systemctl --no-pager status vpn-dnsd | head -5 || true
fi

echo
echo "Проверка (после поднятия awg0):  dig @10.8.0.1 ya.ru +short"
echo "Фаервол (ufw) вручную: разрешить DNS из туннеля и публичный DNS зоны:"
echo "  ufw allow in on awg0 to any port 53"
echo "  ufw allow 53/udp && ufw allow 53/tcp"
