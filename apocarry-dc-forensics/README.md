# Apocarry Incident — DC Forensics (Jump Seat Q1)

**Event:** NexSec Final · Apocarry Incident
**Box:** Windows AD Domain Controller · `carry-dc.apocarry.nexsec`
**Review account:** `rowan` / `Carry-Review-21!`

> Evidence work only. Read logs, do not clear or overwrite them. Lab / CTF use only.

---

## Jump Seat Q1

> Compare the Terminal Services records with the later Q9-matching Security 4624
> logons. Which account and source IPv4 pair appears in both sets of records? The
> matching RDP session precedes the `winupdate.exe` Prefetch run and Security Event 1102.

**Answer format:** `nexsec26{account;IPv4}`  (semicolon between the two fields)

### What it is really asking

Find the single `account + source IPv4` pair that appears in **both**:

1. the Terminal Services (RDP) connection records, and
2. the Security log 4624 logons of **Type 10** (RemoteInteractive = RDP)

Then confirm it is the attacker session by the timeline: that RDP logon happens
**before** the `winupdate.exe` Prefetch run **and before** Security Event 1102
(audit log cleared). Picture: attacker RDPs in, runs a fake updater, then wipes logs.

---

## The 4 artifacts

| Artifact | Log / path | Pull these fields |
|---|---|---|
| RDP auth success | `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`, Event **1149** | username, source IP |
| RDP session logon | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`, Events **21, 22, 25** | user, source network address |
| Security RDP logon | `Security.evtx`, Event **4624**, **LogonType 10** | TargetUserName, IpAddress |
| Timeline anchors | `Security.evtx` Event **1102** (log cleared) + `C:\Windows\Prefetch\WINUPDATE.EXE-*.pf` | the two cutoff times |

Raw `.evtx` files live in `C:\Windows\System32\winevt\Logs\`.

---

## Step by step

### Step 1 — Pull the Terminal Services RDP records

Non-destructive PowerShell (run as `rowan`):

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' |
  Where-Object Id -eq 1149 |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [pscustomobject]@{
      Time = $_.TimeCreated
      User = $x.Event.UserData.EventXML.Param1
      IP   = $x.Event.UserData.EventXML.Param3
    }
  } | Sort-Object Time
```

Also useful (session logon/reconnect with source address):

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' |
  Where-Object { $_.Id -in 21,22,25 } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [pscustomobject]@{
      Time    = $_.TimeCreated
      Id      = $_.Id
      User    = $x.Event.UserData.EventXML.User
      Address = $x.Event.UserData.EventXML.Address
    }
  } | Sort-Object Time
```

Write down every `(User, IP)` you see. This is **set A**.

### Step 2 — Pull the Security 4624 Type-10 logons

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624 } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = $x.Event.EventData.Data
    if ( ($d | Where-Object Name -eq 'LogonType').'#text' -eq 10 ) {
      [pscustomobject]@{
        Time = $_.TimeCreated
        Acct = ($d | Where-Object Name -eq 'TargetUserName').'#text'
        IP   = ($d | Where-Object Name -eq 'IpAddress').'#text'
      }
    }
  } | Sort-Object Time
```

Logon Type 10 means RDP. Write down every `(Acct, IP)`. This is **set B**.

### Step 3 — Intersect set A and set B

Find the `account + IPv4` pair that is present in **both** lists. Ignore pairs that
only appear in one. Normally only one survives. If more than one does, Step 4 decides.

### Step 4 — Anchor the timeline

```powershell
# when the audit log was cleared (Event 1102)
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102 } |
  Select-Object TimeCreated

# when winupdate.exe last ran (Prefetch)
Get-ChildItem C:\Windows\Prefetch\WINUPDATE.EXE-*.pf |
  Select-Object Name, LastWriteTime
```

The correct session's timestamp must come **before** the `winupdate.exe` prefetch
LastRun **and before** the 1102 clear time. That ordering confirms the attacker pair
and rules out any legitimate admin RDP that happened later.

### Step 5 — Build the flag

```
nexsec26{account;IPv4}
```

Use the exact account name and source IPv4 from the surviving pair. No spaces, no
extra words.

---

## Offline alternative (cleaner IR)

Instead of querying the live DC, export the three logs and the Prefetch and parse
them on the pwnbox. This never risks the evidence on the host.

```bash
# on the pwnbox, after copying the .evtx out
chainsaw search -i Security.evtx -t 'Event.System.EventID: =4624' | grep -i 'LogonType.*10'
# or Eric Zimmerman tools:
EvtxECmd.exe -f Security.evtx --csv out
PECmd.exe -f WINUPDATE.EXE-XXXX.pf        # winupdate.exe run times
```

Same logic: intersect Terminal Services records with 4624 Type-10, confirm against
the winupdate.exe run and the 1102 clear.

---

## Quick reference — event IDs

| ID | Log | Meaning |
|----|-----|---------|
| 1149 | TerminalServices-RemoteConnectionManager | RDP user authenticated (user + source IP) |
| 21 / 22 / 25 | TerminalServices-LocalSessionManager | session logon / shell start / reconnect |
| 4624 (Type 10) | Security | successful RemoteInteractive (RDP) logon |
| 1102 | Security | audit log was cleared |
