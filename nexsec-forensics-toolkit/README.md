# NexSec Forensics Toolkit

Digital forensics tools collected from 10 HTB / LetsDefend writeups, ready to set up on the
NexSec pwnbox for the forensics stage. See [TOOLS.md](TOOLS.md) for the full classified list
of what each tool does and which writeup used it.

## How to get it on the pwnbox

### Option 1: clone the whole repo
```bash
git clone https://github.com/alifelliot-stack/ctfWriteUps-.git
cd ctfWriteUps-/nexsec-forensics-toolkit
chmod +x install.sh
./install.sh
```

### Option 2: grab just these two files
```bash
mkdir df-tools && cd df-tools
wget https://raw.githubusercontent.com/alifelliot-stack/ctfWriteUps-/main/nexsec-forensics-toolkit/install.sh
wget https://raw.githubusercontent.com/alifelliot-stack/ctfWriteUps-/main/nexsec-forensics-toolkit/TOOLS.md
chmod +x install.sh
./install.sh
```

## Before you install: check what is already there
The pwnbox usually ships with a lot already (Wireshark, CyberChef under `/opt`, sqlitebrowser).
Check first so you only install what is missing:
```bash
for t in tshark sqlitebrowser tree diec hashdeep autoit-ripper eml-analyzer sigma; do
  command -v "$t" >/dev/null && echo "have: $t" || echo "need: $t"
done
```

## Things to remember on the day
- `install.sh` uses `sudo`. If the pwnbox account has no sudo, the apt installs will fail.
  The pipx tools can still go in with `--user`, and CyberChef works in the browser with no install.
- The pwnbox network may be restricted. If GitHub or apt is blocked, download this folder to a
  laptop the night before and move it in by USB or upload.
- Downloading from your own repo is prep, not an AI tool, so it does not break the event rules.
- For most log questions, `grep`, `awk`, `sort`, `strings` and `xxd` are faster than a heavy GUI.
