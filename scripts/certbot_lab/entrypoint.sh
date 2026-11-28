#!/bin/sh
set -eu
chown 0:0 /fixture
chown -R 0:0 /fixture
# Configuration is container-local. No deployment credentials or host files.
mkdir -p /root/.cloudflare /run/nginx
cat > /root/.cloudflare/cloudflare.cfg << 'EOF'
[CloudFlare]
base_url = http://provider:8056/client/v4
max_request_retries = 0
EOF
chmod 600 /root/.cloudflare/cloudflare.cfg
cat > /etc/nginx/nginx.conf << 'EOF'
worker_processes 1;
pid /run/nginx.pid;
events { worker_connections 64; }
http {
  access_log off;
  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
}
EOF
mkdir -p /etc/letsencrypt
printf 'dns-cloudflare-propagation-seconds = 0\n' > /etc/letsencrypt/cli.ini
nginx
exec sleep infinity
