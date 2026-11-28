ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server nginx cron iproute2 ca-certificates caddy ufw curl python3 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd /root/.ssh && chmod 700 /root/.ssh && sed -i 's/worker_processes auto;/worker_processes 1;/' /etc/nginx/nginx.conf
COPY entrypoint.sh /fixture-entrypoint.sh
ENTRYPOINT ["/bin/sh", "/fixture-entrypoint.sh"]
