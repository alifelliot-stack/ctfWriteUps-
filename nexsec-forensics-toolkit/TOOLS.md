# NexSec Final - Digital Forensics Toolkit

Tools pulled from 10 HTB / LetsDefend forensics writeups, grouped by what they do.
Run `install.sh` to set up the apt and Python tools on Kali/Debian. A few are manual
installs or Windows-only, and those have a Linux alternative listed.

Quick install:
```bash
chmod +x install.sh
./install.sh
```

---

## 1. Network / PCAP forensics

| Tool | Use for | Install | Writeup |
|------|---------|---------|---------|
| Wireshark | Open pcap/pcapng, follow TCP/HTTP streams, read banners, Conversations for timing | `apt install wireshark` | PCAP Analysis, Shellshock |
| tshark | Wireshark on the command line, good for scripting/grep | `apt install tshark` | (companion) |
| tcpdump | Quick capture / read on the CLI | `apt install tcpdump` | (companion) |

## 2. Log analysis

| Tool | Use for | Install | Writeup |
|------|---------|---------|---------|
| Splunk | Upload logs, search by keyword, sort by time, filter requests | Manual download (splunk.com, free tier). Heavy. | WordPress Web Forensics |
| grep / awk | Filter auth.log, syslog, messages for users and events | built-in | SSHole, Brutus |
| sigma-cli | Read/convert Sigma detection rules (selection, condition, logsource) | `pipx install sigma-cli` | Learn Sigma |

> For small log files you do not need Splunk. `grep`, `awk`, `sort` and `less` answer most
> questions faster. Keep Splunk for when you actually need the search UI.

## 3. Static malware triage

| Tool | Use for | Install | Writeup |
|------|---------|---------|---------|
| CyberChef | Decode Base64, From Hex, remove null bytes, XOR, general recipe work | Pre-installed on pwnbox at `/opt/CyberChef`, else standalone zip from gchq.github.io/CyberChef | PowerShell Script, Malicious AutoIT |
| Detect It Easy (DIE) | PE structure, entropy, section virtual addresses, timestamp, entry point | `apt install detect-it-easy` (CLI is `diec`, GUI `die`) | Malicious AutoIT |
| autoit-ripper | Extract compiled AutoIt source (.au3) from a PE | `pipx install autoit-ripper` | Malicious AutoIT |
| HashCalc | MD5/SHA hashing (Windows GUI) | Linux: `md5sum`, `sha256sum`, or `hashdeep` (`apt install hashdeep`) | Malicious AutoIT |
| Notepad++ | Read extracted scripts (Windows) | Linux: any editor (mousepad, vim, VS Code) | Malicious AutoIT |

## 4. Email forensics

| Tool | Use for | Install | Writeup |
|------|---------|---------|---------|
| Outlook / Thunderbird | Open the message, read internet headers (Return-Path, Received-SPF), hover URLs | Linux: `apt install thunderbird` | Phishing Email |
| eml-analyzer | CLI pull of headers, URLs, attachments from .eml | `pipx install eml-analyzer` | (Linux alt for Phishing) |
| VirusTotal | URL / domain / file reputation | Web (virustotal.com). CLI optional: `vt` | Phishing Email, Malicious AutoIT |

## 5. Disk, filesystem and browser forensics

| Tool | Use for | Install | Writeup |
|------|---------|---------|---------|
| Autopsy / Sleuth Kit | Mount and browse disk images, carve cache files | `apt install autopsy sleuthkit` | RemoteAccessRegret |
| sqlitebrowser | Open Chrome History (SQLite), query `urls` table | `apt install sqlitebrowser` | RemoteAccessRegret |
| tree | List mounted artifact contents | `apt install tree` | RemoteAccessRegret |
| mount / mtools | Mount FAT images (`mount -o loop`, or `mtype`/`mcopy`) | `apt install mtools` | RemoteAccessRegret |

## 6. Unix / log artifact forensics

| Tool | Use for | Install | Writeup |
|------|---------|---------|---------|
| last / utmpdump | Read wtmp binary login history | built-in (util-linux) | Brutus |
| utmp.py | Decode wtmp when investigator CPU arch differs from the target | Provided with the challenge (gist 4n6ist/99241df...). Keep a copy in your notes. | Brutus |
| grep + os-release | OS/version from `/etc/os-release`, SSH events from `messages` | built-in | SSHole, Brutus |

---

## What each writeup needed (at a glance)

1. PowerShell Script -> CyberChef
2. PCAP Analysis -> Wireshark
3. Shellshock -> Wireshark
4. Phishing Email -> email viewer + VirusTotal
5. Learn Sigma -> Sigma rule reading (sigma-cli)
6. SSHole -> grep + Unix log analysis
7. WordPress Web Forensics -> Splunk
8. Malicious AutoIT -> HashCalc, Detect It Easy, autoit-ripper, CyberChef, Notepad++, VirusTotal
9. Brutus -> utmp.py, python3, last/utmpdump
10. RemoteAccessRegret -> sqlitebrowser, tree, Autopsy, FAT mount

## Notes for the NexSec pwnbox

- CyberChef, Ghidra, enum4linux-ng and others were already under `/opt` on the pwnbox, so check there before installing.
- No AI tools are allowed inside the pwnbox during the event. This toolkit is prep, set it up and learn the commands beforehand.
- For most log questions, plain `grep`, `awk`, `sort`, `strings` and `xxd` are faster than a heavy GUI. Lead with those.
