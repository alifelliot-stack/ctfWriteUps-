# Git-clone tools — OctoPain (web / wiki) + SSH/privesc

Every tool as a `git clone` you can run on a bare pwnbox. Grouped by whether it
runs straight after cloning (Python / Ruby / Bash — no build) or needs a compiler
(Go / Rust — grab the prebuilt binary instead). Lab / CTF use only.

```bash
mkdir -p ~/tools && cd ~/tools
```

---

## A. Clone-and-run (no build needed) — do these first

```bash
# Wordlists — the big one, everything else references it
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
#   subdomains:  ~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
#   dirs:        ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

# dirsearch — directory brute (pure Python, no install)
git clone --depth 1 https://github.com/maurosoria/dirsearch.git
#   run:  python3 ~/tools/dirsearch/dirsearch.py -u http://octopus.garden/ -x 403

# WhatWeb — fingerprint the wiki (the apt copy on this box is broken; use this)
git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git
#   run:  ruby ~/tools/WhatWeb/whatweb http://TARGET.octopus.garden/

# git-dumper — pull an exposed /.git folder (needs: pip install requests dulwich)
git clone --depth 1 https://github.com/arthaud/git-dumper.git
pip install -r ~/tools/git-dumper/requirements.txt --break-system-packages 2>/dev/null
#   run:  python3 ~/tools/git-dumper/git_dumper.py http://TARGET.octopus.garden/.git out/

# linux-smart-enumeration + LinEnum — privesc enum after you get a shell
git clone --depth 1 https://github.com/diego-treitos/linux-smart-enumeration.git
git clone --depth 1 https://github.com/rebootuser/LinEnum.git

# PEASS-ng — linpeas.sh is just a script, no build
git clone --depth 1 https://github.com/peass-ng/PEASS-ng.git
#   linpeas:  ~/tools/PEASS-ng/linPEAS/linpeas.sh

# username-anarchy — turn names from the wiki into SSH usernames (Ruby)
git clone --depth 1 https://github.com/urbanadventurer/username-anarchy.git
#   run:  ruby ~/tools/username-anarchy/username-anarchy -i names.txt > users.txt
```

---

## B. Needs a compiler (Go / Rust) — clone+build OR just grab the binary

If `go` / `cargo` aren't on the box, don't fight it — use the prebuilt binary line.

```bash
# ffuf (Go) — vhost + dir fuzzer
git clone --depth 1 https://github.com/ffuf/ffuf.git && (cd ffuf && go build .)
#   no Go?  curl -sL https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz | tar xz -C ~/tools/

# gobuster (Go) — dir/dns/vhost brute
git clone --depth 1 https://github.com/OJ/gobuster.git && (cd gobuster && go build .)
#   no Go?  grab the Linux_x86_64.tar.gz from https://github.com/OJ/gobuster/releases/latest

# feroxbuster (Rust) — fast recursive dir brute
git clone --depth 1 https://github.com/epi052/feroxbuster.git && (cd feroxbuster && cargo build --release)
#   no Rust?  curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz | tar xz -C ~/tools/

# nuclei (Go) — templated CVE/misconfig scanner
git clone --depth 1 https://github.com/projectdiscovery/nuclei.git && (cd nuclei/cmd/nuclei && go build .)
#   no Go?  grab linux_amd64.zip from https://github.com/projectdiscovery/nuclei/releases/latest

# pspy (Go) — watch cron/processes for privesc, no deps when static
#   just grab the binary:  curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o ~/tools/pspy64 && chmod +x ~/tools/pspy64
```

---

## C. If you also touch the AD box (My Corp / DC)

```bash
# impacket — GetNPUsers, GetUserSPNs, secretsdump, psexec...
git clone --depth 1 https://github.com/fortra/impacket.git
pip install ~/tools/impacket --break-system-packages 2>/dev/null

# netexec (nxc) — SMB/LDAP/WinRM swiss-army
git clone --depth 1 https://github.com/Pennyw0rth/NetExec.git
pip install ~/tools/NetExec --break-system-packages 2>/dev/null

# enum4linux-ng — SMB/RPC/LDAP enum (Python, clone-and-run)
git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git
#   run:  python3 ~/tools/enum4linux-ng/enum4linux-ng.py -A 10.0.0.5

# kerbrute (Go) — Kerberos user enum, no creds
#   binary:  curl -sL https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -o ~/tools/kerbrute && chmod +x ~/tools/kerbrute

# BloodHound.py collector
git clone --depth 1 https://github.com/dirkjanm/BloodHound.py.git
pip install ~/tools/BloodHound.py --break-system-packages 2>/dev/null
```

---

## Put the binaries on PATH

```bash
echo 'export PATH=$PATH:~/tools:~/tools/ffuf:~/tools/gobuster:~/tools/feroxbuster/target/release' >> ~/.bashrc
source ~/.bashrc
```

> Prefer the one-shot installer (`tools-setup.sh`) when you just want everything;
> use these `git clone` lines when apt/pipx is locked or you want the source.

---

## Troubleshooting

### `bash: ~/tools/ffuf: Is a directory`
`~/tools/ffuf` ended up as a folder (a git clone, or a tarball that extracted into
a dir), so there's no binary to run at that path. Install the real binary to
`/usr/local/bin` so you can just call `ffuf`:

```bash
cd /tmp
url=$(curl -sL https://api.github.com/repos/ffuf/ffuf/releases/latest | grep -o 'https://[^"]*linux_amd64.tar.gz')
curl -sL "$url" -o ffuf.tgz && tar xzf ffuf.tgz ffuf && sudo mv ffuf /usr/local/bin/
ffuf -V        # should print a version
```

Same idea for gobuster / feroxbuster / nuclei: grab the release binary and move it
into `/usr/local/bin` instead of running it out of a cloned source folder.

### `whatweb: cannot load such file`
The apt `whatweb` on this pwnbox is broken. Don't fix it. Clone and run it instead:
```bash
git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git ~/tools/WhatWeb
ruby ~/tools/WhatWeb/whatweb http://octopus.garden/
```
