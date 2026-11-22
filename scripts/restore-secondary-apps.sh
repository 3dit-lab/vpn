#!/usr/bin/env bash
# Keep the existing app installer mirror reachable from the independent portals.
set -euo pipefail

site=${1:?Pass fi-2 or ee-1}
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

case "$site" in
    fi-2)
        paths=(/etc/nginx/vpn-portal-primary.inc)
        cat >"$work/0" <<'NGINX'
proxy_pass https://10.77.240.1;
proxy_set_header Host vpn.3dit.ru;
proxy_ssl_server_name on;
proxy_ssl_name vpn.3dit.ru;
proxy_ssl_verify on;
proxy_ssl_verify_depth 3;
proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
proxy_connect_timeout 3s;
NGINX
        ;;
    ee-1)
        paths=(/etc/nginx/conf.d/vpn-ee-1-https.conf /etc/nginx/conf.d/vpn-ee-1-shared.conf)
        for i in "${!paths[@]}"; do
            if grep -Fq 'location /apps/ {' "${paths[$i]}"; then
                cp "${paths[$i]}" "$work/$i"
                continue
            fi
            awk 'NR==FNR {snippet=snippet $0 ORS; next}
                /^    location \/ \{/ && !added {printf "%s",snippet; added=1}
                {print}' /dev/stdin "${paths[$i]}" >"$work/$i" <<'NGINX'
    location /apps/ {
        proxy_pass https://10.77.240.1;
        proxy_set_header Host vpn.3dit.ru;
        proxy_ssl_server_name on;
        proxy_ssl_name vpn.3dit.ru;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 3;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    }

NGINX
        done
        ;;
    *) exit 2 ;;
esac
for i in "${!paths[@]}"; do
    cp -p "${paths[$i]}" "$work/original.$i"
    install -m 0644 "$work/$i" "${paths[$i]}"
done
ready() {
    for attempt in {1..5}; do
        if curl -fsS --noproxy '*' --resolve vpn.3dit.ru:443:127.0.0.1 \
            --max-time 8 https://vpn.3dit.ru/apps/ >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}
if nginx -t && systemctl reload nginx && ready; then
    echo "Installer mirror reachable on $site"
else
    for i in "${!paths[@]}"; do cp -p "$work/original.$i" "${paths[$i]}"; done
    nginx -t
    systemctl reload nginx
    exit 1
fi
