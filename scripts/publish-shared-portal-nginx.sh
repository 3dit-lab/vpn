#!/usr/bin/env bash
set -euo pipefail

site=${1:?Pass fi-2 or ee-1}
tls=/etc/nginx/pm-vpn-tls/current
test -s "$tls/fullchain.pem"
test -s "$tls/privkey.pem"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

case "$site" in
    fi-2)
        conf=/etc/nginx/conf.d/vpn.conf
        cp -p "$conf" "$work/original"
        sed -E 's@/etc/letsencrypt/live/pm-vpn.3dit.ru/@/etc/nginx/pm-vpn-tls/current/@g' "$conf" |
            awk '/location \/apps\// {apps=1}
                 /include \/etc\/nginx\/vpn-portal-primary.inc;/ && !apps {sub(/vpn-portal-primary/, "vpn-portal-proxy")}
                 {print}
                 /^[[:space:]]*}/ {apps=0}' >"$work/config"
        ;;
    ee-1)
        conf=/etc/nginx/conf.d/vpn-ee-1-shared.conf
        if test -f "$conf"; then cp -p "$conf" "$work/original"; fi
        awk '/^server \{/ {inside=1} inside' /etc/nginx/conf.d/vpn-ee-1-https.conf |
            sed -e 's@server_name ee-1-vpn.3dit.ru;@server_name vpn.3dit.ru pm-vpn.3dit.ru;@' \
                -e 's@/etc/letsencrypt/live/ee-1-vpn.3dit.ru/@/etc/nginx/pm-vpn-tls/current/@g' >"$work/config"
        cat >>"$work/config" <<'NGINX'

server {
    listen 80;
    server_name vpn.3dit.ru pm-vpn.3dit.ru;
    location ^~ /.well-known/acme-challenge/ {
        proxy_pass http://10.77.240.1;
        proxy_set_header Host $host;
        proxy_connect_timeout 3s;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}
NGINX
        ;;
    *) exit 2 ;;
esac
install -m 0644 "$work/config" "$conf"
ready() {
    for attempt in {1..10}; do
        if curl -fsS --noproxy '*' --resolve vpn.3dit.ru:443:127.0.0.1 --max-time 3 https://vpn.3dit.ru/ >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}
if nginx -t && systemctl reload nginx && ready; then
    systemctl enable --now "pm-vpn-portal-tls@$site.timer"
else
    if test -f "$work/original"; then cp -p "$work/original" "$conf"; else rm "$conf"; fi
    nginx -t && systemctl reload nginx
    exit 1
fi
