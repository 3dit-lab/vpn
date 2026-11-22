#!/usr/bin/env bash
set -euo pipefail

site=${1:?Pass fi-2 or ee-1}
case "$site" in
    fi-2) source=fi-1-vpn.3dit.ru; extra=() ;;
    ee-1)
        source=10.77.240.1
        extra=(-o BindInterface=vpn-cluster -o UserKnownHostsFile=/root/.ssh/vpn-replica-known-hosts)
        ;;
    *) exit 2 ;;
esac
umask 077
dst=/etc/nginx/pm-vpn-tls
install -d -m 0700 "$dst"
work=$(mktemp -d "$dst/.new.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
timeout 20 ssh -T -i /root/.ssh/vpn-replica -o IdentitiesOnly=yes -o BatchMode=yes \
    -o ConnectTimeout=5 -o StrictHostKeyChecking=yes "${extra[@]}" \
    "root@$source" export-tls >"$work/tls.tgz"
tar -xOzf "$work/tls.tgz" fullchain.pem >"$work/fullchain.pem"
tar -xOzf "$work/tls.tgz" privkey.pem >"$work/privkey.pem"
openssl x509 -in "$work/fullchain.pem" -checkend 86400 -noout
for domain in vpn.3dit.ru pm-vpn.3dit.ru; do
    openssl x509 -in "$work/fullchain.pem" -checkhost "$domain" -noout | grep -q 'does match'
done
cmp <(openssl x509 -in "$work/fullchain.pem" -pubkey -noout) \
    <(openssl pkey -in "$work/privkey.pem" -pubout)
if cmp -s "$work/fullchain.pem" "$dst/current/fullchain.pem" && cmp -s "$work/privkey.pem" "$dst/current/privkey.pem"; then
    exit 0
fi
old=$(readlink "$dst/current" || true)
rm "$work/tls.tgz"
revision=${work##*/}
ln -s "$revision" "$dst/.current.$revision"
mv -Tf "$dst/.current.$revision" "$dst/current"
if nginx -t && systemctl reload nginx; then
    trap - EXIT
    if [[ "$old" == .new.* && "$old" != "$revision" ]]; then rm -rf -- "$dst/$old"; fi
else
    rm "$dst/current"
    if [[ -n "$old" ]]; then ln -s "$old" "$dst/current"; fi
    exit 1
fi
