ARG GUEST_IMAGE=debian:bookworm-slim
FROM ${GUEST_IMAGE} AS guest
ARG KERNEL_PACKAGE=linux-image-cloud-amd64
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd-sysv dbus python3 openssh-server iproute2 ${KERNEL_PACKAGE} initramfs-tools && rm -rf /var/lib/apt/lists/*
RUN rm -f /etc/ssh/ssh_host_* && mkdir -p /root/.ssh && chmod 700 /root/.ssh && truncate -s 0 /etc/machine-id
COPY guest.network /etc/systemd/network/10-fixture.network
RUN ln -sf /lib/systemd/system/systemd-networkd.service /etc/systemd/system/multi-user.target.wants/systemd-networkd.service && ln -sf /lib/systemd/system/ssh.service /etc/systemd/system/multi-user.target.wants/ssh.service
RUN printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n' > /etc/ssh/sshd_config.d/fixture.conf
RUN rm -rf /var/cache/apt/archives /var/lib/apt/lists
# The capability-dropped runtime copies this rootfs into an owned ext4 image.
# Ubuntu's unused default home otherwise requires DAC override to traverse.
RUN if [ -d /home/ubuntu ]; then chown root:root /home/ubuntu; fi

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 seabios e2fsprogs openssh-client && rm -rf /var/lib/apt/lists/*
COPY --from=guest / /guest
RUN cp /guest/boot/vmlinuz-* /kernel && cp /guest/boot/initrd.img-* /initrd && rm -rf /guest/boot/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
