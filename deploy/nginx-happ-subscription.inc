# The URL grants access to the subscription, so do not log it.
location ^~ /happ-sub/ {
    access_log off;
    error_log /dev/null;
    proxy_intercept_errors off;
    include /etc/nginx/vpn-portal-proxy.inc;
}
