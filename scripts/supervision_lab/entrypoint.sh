#!/bin/sh
set -eu
umask 077
cp /fixture/client.pub /guest/root/.ssh/authorized_keys
cp /fixture/nonce /guest/nexus-fixture-nonce
ssh-keygen -q -t ed25519 -N '' -f /guest/etc/ssh/ssh_host_ed25519_key
truncate -s 768M /disk.img
mkfs.ext4 -q -F -d /guest /disk.img
exec qemu-system-x86_64 -accel tcg,thread=single -m 384 -smp 1 -no-reboot -nographic \
  -kernel /kernel -initrd /initrd -drive file=/disk.img,format=raw,if=virtio \
  -append 'root=/dev/vda rw console=ttyS0 systemd.unified_cgroup_hierarchy=1 systemd.log_level=warning' \
  -netdev user,id=net0,restrict=on,hostfwd=tcp:0.0.0.0:2222-:22 \
  -device virtio-net-pci,netdev=net0 -device virtio-rng-pci
