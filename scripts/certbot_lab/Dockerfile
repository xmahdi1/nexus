FROM ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5
RUN apt-get update && apt-get install -y --no-install-recommends certbot python3-certbot-nginx python3-certbot-dns-cloudflare python3-dnslib nginx ca-certificates && rm -rf /var/lib/apt/lists/*
COPY provider.py /lab/provider.py
COPY entrypoint.sh /lab/entrypoint.sh
ENTRYPOINT ["/bin/sh", "/lab/entrypoint.sh"]
