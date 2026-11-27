# The URL grants access to the subscription, so do not log it.
location ^~ /happ-sub/ {
    access_log off;
    error_log /dev/null;
    proxy_intercept_errors off;
    error_page 502 503 504 = @happ_subscription_unavailable;
    include /etc/nginx/vpn-portal-proxy.inc;
}

location @happ_subscription_unavailable {
    access_log off;
    error_log /dev/null;
    return 503;
}
