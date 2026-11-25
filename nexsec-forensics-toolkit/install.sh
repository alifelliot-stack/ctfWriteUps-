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

# ---- Manual / not-in-apt --------------------------------------------
warn "Manual installs (not in apt, see TOOLS.md for details):"
warn "  CyberChef  - usually pre-installed on the NexSec pwnbox at /opt/CyberChef"
warn "               else download the standalone .zip from gchq.github.io/CyberChef"
warn "  Splunk     - free tier, heavy. Download from splunk.com. grep/awk works for small logs"
warn "  VirusTotal - web service (virustotal.com). Optional CLI: 'vt' from VirusTotal/vt-cli"

say "Done. Run the checker below to confirm what landed:"
echo '  for t in tshark sqlitebrowser tree mtype diecl hashdeep autoit-ripper eml-analyzer sigma; do command -v $t >/dev/null && echo "  OK  $t" || echo "  --  $t missing"; done'
