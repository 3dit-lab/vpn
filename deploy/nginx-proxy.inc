# Общие настройки проксирования на портал (подключается из nginx-https.conf)
proxy_pass http://127.0.0.1:8081;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_read_timeout 30s;
client_max_body_size 16k;
