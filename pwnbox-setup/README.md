# pwnbox-setup

One-shot installer for a bare pwnbox / Kali that's missing the usual CTF tooling.
Pulls binaries straight from GitHub releases and Python tools via `pipx`, so it
works even when the box has a half-stripped apt. Lab / CTF use only.

## Run it on the pwnbox

```bash
curl -sL https://raw.githubusercontent.com/alifelliot-stack/ctfWriteUps-/main/pwnbox-setup/tools-setup.sh -o tools-setup.sh
chmod +x tools-setup.sh
./tools-setup.sh            # everything
# or scope it:
./tools-setup.sh web        # ffuf, gobuster, feroxbuster, nuclei, httpx, git-dumper, SecLists
./tools-setup.sh ad         # kerbrute, netexec, impacket, certipy, bloodhound.py, enum4linux-ng, evil-winrm
```

Then add the binaries to your PATH (the script prints this at the end):

```bash
echo 'export PATH=$PATH:~/tools/bin' >> ~/.bashrc && source ~/.bashrc
```

## What you get

| Tool | Use | Source |
|------|-----|--------|
| ffuf / gobuster / feroxbuster | dir + vhost fuzzing | GitHub release |
| nuclei / httpx | web fingerprint + CVE templates | GitHub release |
| git-dumper | pull an exposed `/.git` | pipx |
| kerbrute | Kerberos user enum (no creds) | GitHub release |
| netexec (nxc) | SMB/LDAP/WinRM swiss-army | pipx |
| impacket | GetNPUsers, GetUserSPNs, secretsdump, psexec... | pipx |
| certipy-ad | AD CS (ESC1-8) | pipx |
| bloodhound.py | domain graph collection | pipx |
| enum4linux-ng | SMB/RPC/LDAP enum | git |
| evil-winrm | WinRM shell | gem |
| pspy / chisel / linpeas / winPEAS | privesc + pivot | GitHub release |
| SecLists | wordlists | git |

## Notes

- x86_64 Linux only. For arm64, edit the `gh_dl` grep patterns in the script.
- Some steps need `sudo` (apt) and internet to GitHub; each step fails soft and
  keeps going, so a locked apt won't stop the GitHub binaries from installing.
- `john` / `hashcat` are installed via apt where available — they're too big to
  ship as release binaries here.

> Quick sanity check after install:
> `ffuf -V ; kerbrute ; nxc --version ; evil-winrm -h | head -1`
