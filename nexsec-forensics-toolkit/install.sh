#!/usr/bin/env bash
# =====================================================================
# NexSec Final - Digital Forensics Toolkit installer
# Tools collected from 10 HTB / LetsDefend DF writeups
# Target: Debian / Kali / Ubuntu (apt based)
# Usage:  chmod +x install.sh && ./install.sh
# =====================================================================
set -u
G='\033[0;32m'; Y='\033[1;33m'; N='\033[0m'
say(){ echo -e "${G}[*] $1${N}"; }
warn(){ echo -e "${Y}[!] $1${N}"; }

say "Updating apt package lists"
sudo apt update

# ---- Network / PCAP forensics ----------------------------------------
say "Network / PCAP forensics (Wireshark, tshark, tcpdump)"
sudo apt install -y wireshark tshark tcpdump

# ---- Disk / filesystem / browser forensics ---------------------------
say "Disk, filesystem and browser forensics"
sudo apt install -y sleuthkit autopsy sqlitebrowser tree mtools

# ---- Hashing & static malware triage ---------------------------------
say "Hashing and static malware triage"
sudo apt install -y hashdeep detect-it-easy

# ---- Email forensics -------------------------------------------------
say "Email forensics (Thunderbird to open .eml/.msg)"
sudo apt install -y thunderbird

# ---- Archives --------------------------------------------------------
say "Archive handling"
sudo apt install -y p7zip-full unzip

# ---- Python tooling via pipx -----------------------------------------
say "Python tooling (pipx)"
sudo apt install -y pipx python3-pip
pipx ensurepath >/dev/null 2>&1 || true

say "autoit-ripper (extract compiled AutoIt scripts)"
pipx install autoit-ripper 2>/dev/null || pip install --user --break-system-packages autoit-ripper

say "eml-analyzer (CLI email header / URL analysis)"
pipx install eml-analyzer 2>/dev/null || pip install --user --break-system-packages eml-analyzer

say "sigma-cli (inspect / convert Sigma rules)"
pipx install sigma-cli 2>/dev/null || pip install --user --break-system-packages sigma-cli

# ---- Make everything runnable from anywhere --------------------------
# Put the pipx bin dir on PATH, and install a global 'nexsec-tools'
# command plus the toolkit folder so you can call it from any directory.
say "Wiring tools into PATH so they run from anywhere"

BIN_DIR="/usr/local/bin"
SHARE_DIR="/usr/local/share/nexsec-forensics-toolkit"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"   # folder this script lives in

# 1) pipx tools live in ~/.local/bin - make sure it is on PATH for good
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  grep -q '.local/bin' "$rc" 2>/dev/null || \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
done
export PATH="$HOME/.local/bin:$PATH"

# 2) copy the whole toolkit folder to a shared location
sudo mkdir -p "$SHARE_DIR"
sudo cp -f "$SRC_DIR"/install.sh "$SRC_DIR"/TOOLS.md "$SRC_DIR"/README.md "$SHARE_DIR"/ 2>/dev/null || true

# 3) global command: type 'nexsec-tools' anywhere to read the reference,
#    'nexsec-tools check' to see what is installed, 'nexsec-tools install' to re-run setup
sudo tee "$BIN_DIR/nexsec-tools" >/dev/null <<'WRAP'
#!/usr/bin/env bash
SHARE_DIR="/usr/local/share/nexsec-forensics-toolkit"
case "${1:-ref}" in
  check)
    for t in tshark sqlitebrowser tree mtype diec hashdeep autoit-ripper eml-analyzer sigma; do
      command -v "$t" >/dev/null && echo "have: $t" || echo "need: $t"
    done ;;
  install) bash "$SHARE_DIR/install.sh" ;;
  *) ${PAGER:-less} "$SHARE_DIR/TOOLS.md" ;;
esac
WRAP
sudo chmod +x "$BIN_DIR/nexsec-tools"
say "Installed 'nexsec-tools' to $BIN_DIR (run it from any folder)"

# ---- Manual / not-in-apt --------------------------------------------
warn "Manual installs (not in apt, see TOOLS.md for details):"
warn "  CyberChef  - usually pre-installed on the NexSec pwnbox at /opt/CyberChef"
warn "               else download the standalone .zip from gchq.github.io/CyberChef"
warn "  Splunk     - free tier, heavy. Download from splunk.com. grep/awk works for small logs"
warn "  VirusTotal - web service (virustotal.com). Optional CLI: 'vt' from VirusTotal/vt-cli"

say "Done."
say "Open a new terminal (or run: source ~/.bashrc) so PATH updates take effect."
say "Then from ANY folder you can run:"
echo "  nexsec-tools          # open the classified tools reference"
echo "  nexsec-tools check    # see which tools are installed vs missing"
echo "  nexsec-tools install  # re-run this setup"
