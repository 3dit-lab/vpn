# Резервный сервер: проксирование на основной (подключается из nginx-secondary.conf). __PRIMARY__ подставляет setup-replica.sh
proxy_pass https://__PRIMARY__;
proxy_ssl_server_name on;
proxy_ssl_name __PRIMARY__;
proxy_ssl_verify on;
proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_connect_timeout 3s;
proxy_read_timeout 30s;
client_max_body_size 16k;
