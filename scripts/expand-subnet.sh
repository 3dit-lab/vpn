#!/usr/bin/env bash
# Расширение подсети VPN на работающем сервере БЕЗ перезапуска туннеля (клиенты не отключаются).
# Клиентские конфиги не меняются: у них адреса /32, а список hosts() подсети сохраняет порядок.
#   sudo ./scripts/expand-subnet.sh 10.8.0.0/23 10.8.0.0/20
# Запускать на КАЖДОМ сервере с VPN. Меняет: awg0.conf и awg0.base.conf (Address, правила NAT в PostUp/PostDown),
# unbound (access-control), а на живом интерфейсе — адрес awg0 и правило MASQUERADE.
set -euo pipefail
OLD="${1:?старая подсеть, например 10.8.0.0/23}"; NEW="${2:?новая подсеть, например 10.8.0.0/20}"
[ "$(id -u)" -eq 0 ] || { echo "Запустите от root"; exit 1; }
python3 - "$OLD" "$NEW" <<'PY'
import ipaddress, sys
o, n = ipaddress.ip_network(sys.argv[1]), ipaddress.ip_network(sys.argv[2])
assert n.supernet_of(o) and o.network_address == n.network_address, "новая подсеть должна включать старую с тем же началом"
PY
SRV_IP="${OLD%/*}"; SRV_IP="${SRV_IP%.*}.1"; OLDLEN="${OLD#*/}"; NEWLEN="${NEW#*/}"
CONF_DIR=/etc/amnezia/amneziawg
for f in "$CONF_DIR/awg0.conf" "$CONF_DIR/awg0.base.conf"; do
  [ -f "$f" ] || continue
  cp -p "$f" "$f.bak-subnet"
  sed -i "s#^Address = ${SRV_IP}/${OLDLEN}#Address = ${SRV_IP}/${NEWLEN}#; s#-s ${OLD} #-s ${NEW} #g" "$f"
  grep -q "Address = ${SRV_IP}/${NEWLEN}" "$f" || { echo "Не удалось изменить $f"; exit 1; }
done
# unbound: разрешить клиентам новой подсети
U=/etc/unbound/unbound.conf.d/vpn.conf
if [ -f "$U" ]; then sed -i "s#access-control: ${OLD} allow#access-control: ${NEW} allow#" "$U"; systemctl reload unbound || systemctl restart unbound; fi
# живое применение
if ip link show awg0 >/dev/null 2>&1; then
  IF="$(ip -4 route show default | awk '{print $5; exit}')"
  iptables -t nat -C POSTROUTING -s "$NEW" -o "$IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$NEW" -o "$IF" -j MASQUERADE
  ip addr add "${SRV_IP}/${NEWLEN}" dev awg0 2>/dev/null || true
  ip addr del "${SRV_IP}/${OLDLEN}" dev awg0 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s "$OLD" -o "$IF" -j MASQUERADE 2>/dev/null || true
fi
echo "Готово: $OLD -> $NEW"; ip -4 addr show awg0 | grep inet; iptables -t nat -S POSTROUTING | grep MASQ
