#!/bin/bash
set -e

# Regenerate host keys if they weren't baked into the image layer (first boot).
ssh-keygen -A >/dev/null 2>&1 || true

service apache2 start
echo "[entrypoint] apache2 started"
echo "[entrypoint] starting sshd in foreground"
exec /usr/sbin/sshd -D -e
