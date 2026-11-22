#!/usr/bin/env bash
# Freeze local portal writers, switch to PostgreSQL, then publish after all nodes are ready.
set -euo pipefail

mode=${1:?Pass preflight, freeze, activate, publish or rollback}
site=${2:?Pass fi-1, fi-2 or ee-1}
case "$site" in
    fi-1|fi-2) nginx_conf=/etc/nginx/conf.d/vpn.conf ;;
    ee-1) nginx_conf=/etc/nginx/conf.d/vpn-ee-1-https.conf ;;
    *) exit 2 ;;
esac
repo=$(cd "$(dirname "$0")/.." && pwd)
state=/var/lib/pm-vpn-portal-cutover
hold=/etc/nginx/pm-vpn-maintenance
dropin=/etc/systemd/system/vpn-portal.service.d/shared.conf
staged=/etc/vpn-portal-shared.staged
env=/etc/vpn-portal-shared.env
umask 077

preflight() {
    test -s "$nginx_conf"
    test -s "$staged"
    test ! -e "$state"
    test ! -e "$hold"
    test ! -e "$env"
    test ! -e "$dropin"
    test -x /opt/vpn-portal-shared/python
    /opt/vpn-portal-shared/python -c 'import psycopg, flask; from gunicorn.app.wsgiapp import run'
    systemctl is-active --quiet vpn-portal
    systemctl is-active --quiet wg-quick@wg-portal
    systemctl is-active --quiet awg-quick@awg0
    nginx -t
}

case "$mode" in
    preflight) preflight ;;
    freeze)
        preflight
        install -d -m 0700 "$state"
        cp -p "$nginx_conf" "$state/nginx"
        if test -f /var/lib/vpn-portal/peers.json; then
            cp -p /var/lib/vpn-portal/peers.json "$state/peers.json"
        fi
        if systemctl is-active --quiet vpn-replica.timer; then
            touch "$state/replica.timer"
            systemctl stop vpn-replica.timer vpn-replica.service
        fi
        awk '{print} /^[[:space:]]*server[[:space:]]*\{[[:space:]]*$/ {
            print "    if (-f /etc/nginx/pm-vpn-maintenance) { return 503; }"
        }' "$state/nginx" >"$nginx_conf"
        grep -q 'pm-vpn-maintenance' "$nginx_conf"
        touch "$hold"
        nginx -t
        systemctl reload nginx
        systemctl stop vpn-portal
        printf '%s\n' "Frozen: $site"
        ;;
    activate)
        test -f "$hold"
        test -s "$state/nginx"
        install -m 0600 "$staged" "$env"
        install -d -m 0755 "$(dirname "$dropin")"
        cat >"$dropin" <<'UNIT'
[Service]
EnvironmentFile=/etc/vpn-portal-shared.env
WorkingDirectory=/opt/vpn-portal-shared
ExecStart=
ExecStart=/opt/vpn-portal-shared/python -c "from gunicorn.app.wsgiapp import run; run()" --workers 2 --bind 127.0.0.1:8081 portal:app
UNIT
        chmod 0644 "$dropin"
        if [ "$site" = ee-1 ]; then
            sed -i -e 's@proxy_pass https://10.77.240.1;@proxy_pass http://127.0.0.1:8081;@' \
                -e 's@proxy_set_header Host vpn.3dit.ru;@proxy_set_header Host $host;@' "$nginx_conf"
            install -m 0755 "$repo/scripts/sync-peers.py" /opt/vpn-portal/sync-peers.py
            for unit in vpn-peer-sync.service vpn-peer-sync.path vpn-peer-sync.timer; do
                install -m 0644 "$repo/deploy/$unit" /etc/systemd/system/
            done
        fi
        systemctl daemon-reload
        nginx -t
        systemctl reload nginx
        systemctl start vpn-portal
        for i in {1..20}; do
            if curl -fsS --noproxy '*' --max-time 2 http://127.0.0.1:8081/ >/dev/null; then break; fi
            test "$i" -lt 20
            sleep 1
        done
        systemctl start vpn-portal-peers.service
        systemctl start vpn-peer-sync.service wg-portal-sync.service
        wg show wg-portal peers | wc -l
        awg show awg0 peers | wc -l
        printf '%s\n' "Active behind maintenance: $site"
        ;;
    publish)
        test -f "$hold"
        test -s "$env"
        systemctl is-active --quiet vpn-portal
        systemctl enable --now vpn-portal-peers.timer vpn-peer-sync.path vpn-peer-sync.timer wg-portal-sync.timer
        if test -e "$state/replica.timer"; then systemctl disable vpn-replica.timer; fi
        rm -f "$hold"
        printf '%s\n' "Published: $site"
        ;;
    rollback)
        test -f "$hold" || { echo "Public requests may have reached PostgreSQL; SQLite rollback refused" >&2; exit 1; }
        test -s "$state/nginx"
        systemctl stop vpn-portal vpn-portal-peers.timer wg-portal-sync.timer
        rm -f "$dropin" "$env"
        cp -p "$state/nginx" "$nginx_conf"
        if test -f "$state/peers.json"; then
            cp -p "$state/peers.json" /var/lib/vpn-portal/peers.json
        fi
        systemctl daemon-reload
        nginx -t
        systemctl start vpn-portal
        if test -e "$state/replica.timer"; then systemctl start vpn-replica.timer; fi
        systemctl reload nginx
        rm -f "$hold"
        mv "$state" "$state.rollback.$(date +%s)"
        ;;
    *) exit 2 ;;
esac
