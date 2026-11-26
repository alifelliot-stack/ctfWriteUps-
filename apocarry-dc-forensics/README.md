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

## Fast path: pivot from the 1102 log-clear event

This is the shortest route once you have found Event 1102. The log-clear event names
the account that did it and, more importantly, the **Logon ID** of the session. That
Logon ID links the wipe straight back to the logon that carries the source IP.

### Step A — Read the 1102 event details

Open the 1102 event (Security log), Details tab. In this incident it showed:

```
LogFileCleared
  SubjectUserSid    : S-1-5-21-357959444-3534398086-3571024275-1001
  SubjectUserName   : svc-admin
  SubjectDomainName : SKY-JMP01
  SubjectLogonId    : 0x1dcb2
```

So `svc-admin` cleared the log. Note **SubjectLogonId `0x1dcb2`** and the event's
timestamp (General tab) as your "logs cleared" anchor. (SKY-JMP01 is the Jump Seat
jump host.)

### Step B — Follow the Logon ID into the 4624

Find the 4624 whose **New Logon > Logon ID** equals the SubjectLogonId above. That is
the logon that opened this session, and it carries the source IP and logon type:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | ForEach-Object {
  $x=[xml]$_.ToXml(); $d=$x.Event.EventData.Data
  if( ($d|?{$_.Name -eq 'TargetLogonId'}).'#text' -eq '0x1dcb2' ){
    [pscustomobject]@{
      Time =$_.TimeCreated
      Acct =($d|?{$_.Name -eq 'TargetUserName'}).'#text'
      Type =($d|?{$_.Name -eq 'LogonType'}).'#text'    # expect 10 = RDP
      IP   =($d|?{$_.Name -eq 'IpAddress'}).'#text'    # the source IPv4
    } } }
```

In the GUI instead: filter Security for 4624, open each, match **New Logon > Logon ID**
to `0x1DCB2`. Read **Account Name**, **Logon Type** (should be 10), and
**Source Network Address**.

### Step C — Confirm the pair appears in Terminal Services too

The question wants the pair present in **both** record sets. Check that the same
`svc-admin + IP` also shows in the Terminal Services 1149 records:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' |
  Where-Object Id -eq 1149 | ForEach-Object {
    $x=[xml]$_.ToXml()
    [pscustomobject]@{ Time=$_.TimeCreated; User=$x.Event.UserData.EventXML.Param1; IP=$x.Event.UserData.EventXML.Param3 }
  } | Where-Object User -like '*svc-admin*'
```

### Step D — Watch for decoy RDP sessions

There is more than one RDP connection in the logs, and not all of them are the attacker.
A 1149 record in this incident showed `it-helpdesk` / `192.168.77.5` at 04:54. **That is
a decoy** — do not submit it. It does not line up with the session that wiped the logs.

Anchor on the 1102 Logon ID instead (Step B). The 4624 for Logon ID `0x1dcb2` resolves to:

```
svc-admin / 192.168.77.3   (LogonType 10 = RDP)
```

That same `svc-admin` + `192.168.77.3` also appears in a Terminal Services 1149 record
and precedes the `winupdate.exe` prefetch run and the 1102 clear. So it is the pair in
both sets and it fits the timeline.

Verify the pair in the 4624 Type 10 set:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | % {
  $x=[xml]$_.ToXml(); $d=$x.Event.EventData.Data
  $acct=($d|?{$_.Name -eq 'TargetUserName'}).'#text'
  $ip  =($d|?{$_.Name -eq 'IpAddress'}).'#text'
  $type=($d|?{$_.Name -eq 'LogonType'}).'#text'
  if($acct -eq 'svc-admin' -and $ip -eq '192.168.77.3'){
    [pscustomobject]@{Time=$_.TimeCreated; Acct=$acct; Type=$type; IP=$ip} } }
```

### Step E — Flag (confirmed correct)

```
nexsec2026{svc-admin;192.168.77.3}
```

> Note the accepted prefix is `nexsec2026{...}` (not `nexsec26{...}`).

**Lesson:** do not assume the first 1149 record you open is the attacker. The box
plants a decoy helpdesk RDP from a near-identical IP (`.5` vs `.3`). Always anchor on
the 1102 Logon ID pivot, then confirm the pair in both the TS records and 4624 Type 10,
and that it precedes winupdate.exe and the log clear.

> The generic cross-reference method below reaches the same answer from scratch if you
> have not found the 1102 event yet.

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
| 4624 (Type 3) | Security | successful Network logon (SMB / NTLM) |
| 1102 | Security | audit log was cleared |

---

## More forensic questions

### Q — Event 1102 Record ID + ATT&CK technique

Read the `<EventRecordID>` from the 1102 event (Details tab -> **XML View**, under
`<System>`), and map the log-clear behavior to MITRE ATT&CK.

- Record ID (this incident): `11811`
- Technique: `T1070.001` (Indicator Removal: **Clear Windows Event Logs**)

How to map any behavior to a technique: describe it in plain words (clearing the event
log = hiding tracks = Defense Evasion), search `attack.mitre.org` for the behavior or
the Event ID. The T1070.001 page lists Windows Event ID 1102 as a detection source.

**Flag:** `nexsec2026{11811;T1070.001}`

### Q — exact Security-log clearing command

Source: `ConsoleHost_history.txt` (PowerShell history). It contains three clear commands:

```
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```

`wevtutil cl <log>` clears a log. The Security-specific one:

**Flag:** `nexsec2026{wevtutil cl Security}`  (if spaces are rejected: `nexsec2026{wevtutil_cl_Security}`)

### Console history — full attacker sequence (context)

```
whoami
tasklist | findstr lsass
C:\Windows\Temp\winupdate.exe -sn 192.168.77.0/24        # network sweep of the /24
wevtutil cl Security                                      # clear logs (T1070.001)
wevtutil cl System
wevtutil cl Application
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 860 C:\Windows\Temp\lsass.dmp full
```

- `winupdate.exe -sn 192.168.77.0/24` -> host-discovery scan (network scanner family)
- `rundll32 ... comsvcs.dll, MiniDump <pid> lsass.dmp full` -> LSASS credential dump,
  ATT&CK **T1003.001** (OS Credential Dumping: LSASS Memory)

### Q — winupdate.exe SHA-1 + tool family

Static analysis only (never run the sample).

SHA-1 (this incident): `0ae6c11cb3eb730a866cf5b1fbc79079879c3549`

```bash
sha1sum winupdate.exe                                     # SHA-1
exiftool winupdate.exe                                    # PE version info: OriginalFilename, ProductName
strings -n 6 winupdate.exe | grep -iE 'scan|usage|version|http'   # tool banner / usage
```

Windows:
```powershell
Get-FileHash -Algorithm SHA1 winupdate.exe
(Get-Item winupdate.exe).VersionInfo | Format-List *     # OriginalFilename / ProductName name the tool
```
Also Properties -> Details tab shows the version resource. The `-sn <cidr>` usage points
to a network/host-discovery scanner (look for nmap / masscan / SoftPerfect / Advanced IP
Scanner / fscan in the metadata or strings).

**Flag:** `nexsec2026{0ae6c11cb3eb730a866cf5b1fbc79079879c3549;<toolname>}`

### Q — earliest 4624 (svc-admin, Type 3, NTLM, 192.168.77.3) after the 1102 clear

```powershell
$clear = (Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} | Sort TimeCreated | Select -First 1).TimeCreated

Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | % {
  $x=[xml]$_.ToXml(); $d=$x.Event.EventData.Data
  [pscustomobject]@{
    Time    = $_.TimeCreated
    Record  = $_.RecordId
    User    = ($d|?{$_.Name -eq 'TargetUserName'}).'#text'
    Type    = ($d|?{$_.Name -eq 'LogonType'}).'#text'
    Auth    = ($d|?{$_.Name -eq 'AuthenticationPackageName'}).'#text'
    IP      = ($d|?{$_.Name -eq 'IpAddress'}).'#text'
    LogonId = ($d|?{$_.Name -eq 'TargetLogonId'}).'#text'
  }
} | ? { $_.User -eq 'svc-admin' -and $_.Type -eq '3' -and $_.Auth -eq 'NTLM' -and $_.IP -eq '192.168.77.3' -and $_.Time -gt $clear } |
  Sort Time | Select -First 1 | % {
    "RecordID = $($_.Record)"
    "LogonID  = $($_.LogonId)"
    "UTC      = $($_.Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  }
```

GUI alternative (Event Viewer -> Security -> Filter Current Log -> XML tab):

```xml
<QueryList><Query Id="0" Path="Security"><Select Path="Security">
*[System[(EventID=4624)]]
and *[EventData[Data[@Name='TargetUserName']='svc-admin']]
and *[EventData[Data[@Name='LogonType']='3']]
and *[EventData[Data[@Name='AuthenticationPackageName']='NTLM']]
and *[EventData[Data[@Name='IpAddress']='192.168.77.3']]
</Select></Query></QueryList>
```

Sort oldest first, take the first entry after the 1102 time. `<TimeCreated SystemTime>`
is already UTC.

**Flag:** `nexsec2026{<RecordID>;<TargetLogonId>;<UTC_timestamp>}`  (if the ISO `...T..Z`
form is rejected, try `YYYY-MM-DD HH:MM:SS`)

#### Manual method (Event Viewer only, no PowerShell)

Use this when the custom XML filter throws the "channel path invalid" error on a saved log.

1. **Open the saved log:** Event Viewer -> Action -> **Open Saved Log** -> browse to
   `...\jumpseat-evidence\C\Windows\System32\winevt\Logs\Security.evtx`.
2. **Filter to logons:** right pane -> **Filter Current Log** -> set **Event ID** to `4624`
   -> OK. (Use the simple filter, not Create Custom View.)
3. **Sort oldest first:** click the **Date and Time** column header until the arrow points
   up (oldest at the top). You want the *earliest* match, so start from the top, but only
   consider events **after** the 1102 clear time.
4. **Open each 4624 and check the General tab** for all four conditions:
   - **New Logon -> Account Name** = `svc-admin` (not the Subject account)
   - **Logon Type** = `3`
   - **Network Information -> Source Network Address** = `192.168.77.3`
   - **Detailed Authentication Information -> Authentication Package** = `NTLM`
5. **The first event (top-down) that matches all four is your answer.**
6. **Read the three values** from that event:
   - General tab -> note the **Logged** time, then convert to UTC if your box is not UTC.
   - **Details** tab -> **XML View**:
     - `<EventRecordID>…</EventRecordID>` = Record ID
     - `<Data Name="TargetLogonId">0x…</Data>` = Logon ID (New Logon > Logon ID)
     - `<TimeCreated SystemTime="…Z">` = the event time already in **UTC**

Tip: the `SystemTime` in XML view is UTC, so use that string directly for the timestamp
rather than converting the local "Logged" time by hand.

**Flag:** `nexsec2026{<EventRecordID>;<TargetLogonId>;<SystemTime UTC>}`

---

## Troubleshooting

### "The specified channel path is invalid (15000)"

Happens when you paste a custom **XML filter** (with `Path="Security"`) while viewing a
**saved `.evtx` file** from the triage. The XML query points at the live Security
channel, which does not exist in that context, so Event Viewer errors out.

Fix 1 (best) — query the file directly in PowerShell with `-Path`:

```powershell
$log = 'C:\path\to\triage\C\Windows\System32\winevt\Logs\Security.evtx'
Get-WinEvent -Path $log | ? Id -eq 4624 | % {
  $x=[xml]$_.ToXml(); $d=$x.Event.EventData.Data
  [pscustomobject]@{
    Time=$_.TimeCreated; Record=$_.RecordId
    User=($d|?{$_.Name -eq 'TargetUserName'}).'#text'
    Type=($d|?{$_.Name -eq 'LogonType'}).'#text'
    Auth=($d|?{$_.Name -eq 'AuthenticationPackageName'}).'#text'
    IP  =($d|?{$_.Name -eq 'IpAddress'}).'#text'
    LogonId=($d|?{$_.Name -eq 'TargetLogonId'}).'#text'
  }
} | ? { $_.User -eq 'svc-admin' -and $_.Type -eq '3' -and $_.Auth -eq 'NTLM' -and $_.IP -eq '192.168.77.3' } |
  Sort Time | Select Record,LogonId,@{n='UTC';e={$_.Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')}} -First 1
```

Find the log path if unknown: `Get-ChildItem -Recurse -Filter Security.evtx C:\ 2>$null | Select FullName`

Fix 2 (GUI) — use **Filter Current Log** (not "Create Custom View") on the open saved
log. The simple filter (Event ID `4624`) works on saved logs; it cannot match EventData
fields, so scroll the results for svc-admin / Type 3 / NTLM / 192.168.77.3.
