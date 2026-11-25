#!/usr/bin/env bash
# =============================================================================
# pwnbox tools-setup.sh  -  grab the essential CTF / Boot2Root tools
# Target: x86_64 Linux (Kali / Ubuntu / Debian pwnbox). Lab / CTF use only.
#
# Usage on the pwnbox:
#   curl -sL https://raw.githubusercontent.com/alifelliot-stack/ctfWriteUps-/main/pwnbox-setup/tools-setup.sh -o tools-setup.sh
#   chmod +x tools-setup.sh
#   ./tools-setup.sh          # installs everything into ~/tools + pipx
#   ./tools-setup.sh web      # only web/wiki tooling
#   ./tools-setup.sh ad       # only Active Directory tooling
#
# Binaries land in ~/tools/bin  ->  add to PATH (the script reminds you).
# =============================================================================
set -uo pipefail

TOOLS="$HOME/tools"
BIN="$TOOLS/bin"
mkdir -p "$BIN"
MODE="${1:-all}"

say(){ printf '\n\033[1;36m[*] %s\033[0m\n' "$*"; }
ok(){ printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m[!] %s\033[0m\n' "$*"; }

# pull a GitHub release asset whose name matches a grep pattern
# usage: gh_dl <owner/repo> <grep-pattern> <output-filename>
gh_dl(){
  local repo="$1" pat="$2" out="$3"
  local url
  url=$(curl -sL "https://api.github.com/repos/$repo/releases/latest" \
        | grep -oE '"browser_download_url": *"[^"]+"' | cut -d'"' -f4 \
        | grep -iE "$pat" | head -n1)
  if [ -z "$url" ]; then warn "no asset for $repo ($pat)"; return 1; fi
  echo "    -> $url"
  curl -sL "$url" -o "$BIN/$out" || { warn "download failed: $repo"; return 1; }
  ok "got $out"
}

ensure_pipx(){
  if ! command -v pipx >/dev/null 2>&1; then
    say "installing pipx"
    python3 -m pip install --user pipx --break-system-packages 2>/dev/null \
      || python3 -m pip install --user pipx
    python3 -m pipx ensurepath
  fi
}

# ---------------------------------------------------------------- APT basics
say "apt basics (needs sudo; skips silently if offline/locked)"
sudo apt-get update -y 2>/dev/null
sudo apt-get install -y curl wget git python3-pip pipx unzip jq \
  nmap whatweb nikto hydra john hashcat smbclient ldap-utils dnsutils \
  seclists 2>/dev/null && ok "apt packages requested" || warn "apt partial/failed - GitHub installs below still work"

# ---------------------------------------------------------------- SecLists
if [ ! -d /usr/share/seclists ] && [ ! -d "$TOOLS/SecLists" ]; then
  say "cloning SecLists (shallow)"
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$TOOLS/SecLists" \
    && ok "SecLists -> $TOOLS/SecLists" || warn "SecLists clone failed"
fi

# ---------------------------------------------------------------- WEB tools
if [ "$MODE" = "all" ] || [ "$MODE" = "web" ]; then
  say "web / wiki binaries from GitHub"
  # ffuf
  gh_dl ffuf/ffuf 'linux_amd64.tar.gz' ffuf.tgz && \
    tar xzf "$BIN/ffuf.tgz" -C "$BIN" ffuf 2>/dev/null; rm -f "$BIN/ffuf.tgz"
  # gobuster
  gh_dl OJ/gobuster 'Linux_x86_64.tar.gz' gob.tgz && \
    tar xzf "$BIN/gob.tgz" -C "$BIN" gobuster 2>/dev/null; rm -f "$BIN/gob.tgz"
  # feroxbuster (fast dir brute, static)
  gh_dl epi052/feroxbuster 'feroxbuster_amd64.deb|x86_64-linux-feroxbuster.tar.gz' fx.tgz && \
    tar xzf "$BIN/fx.tgz" -C "$BIN" feroxbuster 2>/dev/null; rm -f "$BIN/fx.tgz"
  # nuclei
  gh_dl projectdiscovery/nuclei 'linux_amd64.zip' nuclei.zip && \
    unzip -o "$BIN/nuclei.zip" nuclei -d "$BIN" >/dev/null 2>&1; rm -f "$BIN/nuclei.zip"
  # httpx
  gh_dl projectdiscovery/httpx 'linux_amd64.zip' httpx.zip && \
    unzip -o "$BIN/httpx.zip" httpx -d "$BIN" >/dev/null 2>&1; rm -f "$BIN/httpx.zip"
  chmod +x "$BIN"/* 2>/dev/null
  # git-dumper (for exposed /.git)
  ensure_pipx; pipx install git-dumper 2>/dev/null && ok "git-dumper" || warn "git-dumper skipped"
fi

# ---------------------------------------------------------------- AD tools
if [ "$MODE" = "all" ] || [ "$MODE" = "ad" ]; then
  say "Active Directory binaries from GitHub"
  # kerbrute
  gh_dl ropnop/kerbrute 'linux_amd64$' kerbrute && chmod +x "$BIN/kerbrute" 2>/dev/null
  say "Active Directory python tools via pipx"
  ensure_pipx
  for p in impacket netexec certipy-ad bloodhound-ce ldapdomaindump; do
    pipx install "$p" 2>/dev/null && ok "$p" || warn "$p skipped (try: pipx install $p)"
  done
  # enum4linux-ng
  if [ ! -d "$TOOLS/enum4linux-ng" ]; then
    git clone --depth 1 https://github.com/cddmp/enum4linux-ng "$TOOLS/enum4linux-ng" 2>/dev/null \
      && ln -sf "$TOOLS/enum4linux-ng/enum4linux-ng.py" "$BIN/enum4linux-ng" \
      && ok "enum4linux-ng" || warn "enum4linux-ng skipped"
  fi
  # evil-winrm (ruby gem)
  if ! command -v evil-winrm >/dev/null 2>&1; then
    gem install evil-winrm 2>/dev/null && ok "evil-winrm" || warn "evil-winrm: run 'sudo gem install evil-winrm'"
  fi
  # bloodhound.py collector
  pipx install bloodhound 2>/dev/null && ok "bloodhound-python" || warn "bloodhound-python skipped"
fi

# ---------------------------------------------------------------- privesc helpers
if [ "$MODE" = "all" ]; then
  say "privesc / pivot helpers"
  # pspy
  gh_dl DominicBreuker/pspy 'pspy64$' pspy64 && chmod +x "$BIN/pspy64" 2>/dev/null
  # chisel
  gh_dl jpillora/chisel 'linux_amd64.gz' chisel.gz && \
    gunzip -f "$BIN/chisel.gz" 2>/dev/null && chmod +x "$BIN/chisel" 2>/dev/null
  # linpeas / winpeas
  gh_dl peass-ng/PEASS-ng 'linpeas.sh$' linpeas.sh && chmod +x "$BIN/linpeas.sh" 2>/dev/null
  gh_dl peass-ng/PEASS-ng 'winPEASany.exe$' winPEASany.exe 2>/dev/null
fi

# ---------------------------------------------------------------- PATH
say "done"
echo "Binaries: $BIN"
echo "Wordlists: ${TOOLS}/SecLists  (or /usr/share/seclists)"
echo
echo "Add tools to PATH for this + future shells:"
echo "    echo 'export PATH=\$PATH:$BIN' >> ~/.bashrc && source ~/.bashrc"
echo
echo "Quick check:"
echo "    ffuf -V ; kerbrute ; nxc --version ; evil-winrm -h | head -1"
