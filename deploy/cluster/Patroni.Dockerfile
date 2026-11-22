FROM postgres:18.7@sha256:eb63372c1e05c755f55fa30cbd07aecc443676fc6c0fa90b9002d01537841e1a
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/patroni \
 && /opt/patroni/bin/pip install --no-cache-dir 'patroni[etcd3,psycopg3]==4.1.5'
USER postgres
ENTRYPOINT ["/opt/patroni/bin/patroni"]
CMD ["/etc/patroni/config.yml"]
