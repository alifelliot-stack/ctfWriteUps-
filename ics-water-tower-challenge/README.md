# ICS/SCADA — Pump Station 4 (Modbus TCP, no authentication)

A simulated Industrial Control System challenge: a PLC controlling an
elevated water tower's level, speaking real Modbus TCP. Under normal
operation the tank cycles safely between 20% and 80% full. Your goal is
to force it to overflow — using nothing but the same unauthenticated
protocol the real operators use — and read the resulting incident flag
back out of the PLC's own memory.

## The setup

- `plc_server.py` runs two services:
  - **Modbus TCP on port 5020** — the actual control interface. Function
    codes `0x03` (Read Holding Registers) and `0x06` (Write Single
    Register), framed exactly like a real PLC. There is no login, no
    handshake, no credential of any kind — because that's genuinely how
    Modbus TCP works. Anyone who can route a TCP connection to the port
    can read and write process values.
  - **A read-only HTTP dashboard on port 8080** (`http://localhost:8080/`)
    — the "HMI" (human-machine interface) an operator would watch. It
    polls the PLC once a second and shows the tank level, pump state, and
    interlock status. It cannot be used to change anything; it's purely
    observational, same as the exploit vector isn't there.

Point-list (register map) for the PLC:

| Reg | Name                 | Access | Notes                                   |
|-----|----------------------|--------|------------------------------------------|
| 0   | `water_level`         | RO     | 0-1200, i.e. 0.0%-120.0% tank fill       |
| 1   | `pump_on`              | RW     | 0/1                                       |
| 2   | `high_level_setpoint`  | RW     | default 800 (80.0%)                       |
| 3   | `interlock_enabled`    | RW     | 0/1, default 1 — the safety trip switch  |
| 4   | `overflow_flag`        | RO     | latches to 1 once level >= 1000 (100%)   |
| 5   | `low_level_setpoint`   | RW     | default 200 (20.0%)                       |
| 99  | `flag_length`          | RO     | set once overflow triggers                |
| 100+| flag bytes (1 char/register) | RO | set once overflow triggers          |

Any write to a register not marked RW returns a real Modbus exception
(`0x86`/`0x83`, illegal data address) — the level, the overflow latch,
and the flag storage block genuinely cannot be written to directly.

## Run it

```bash
cd ics-water-tower-challenge
python3 plc_server.py
```

Watch it operate normally at `http://localhost:8080/` — the tank fills to
80%, the pump shuts off, drains to 20%, the pump restarts. That's the
`interlock_enabled` safety logic doing exactly what it's meant to do:
capping the tank below overflow no matter how long the pump runs.

Then attack it:

```bash
python3 solve.py
```

or by hand with any Modbus client (`pymodbus`, `mbpoll`, Wireshark to
inspect the traffic, etc.) pointed at `127.0.0.1:5020`.

## The exploit

1. **Reconnaissance is free.** Read holding registers 0-5 — no
   credential prompt, nothing. You can immediately see the tank level,
   the pump state, and both setpoints.
2. **Disable the safety interlock**: write register `3` = `0`. This is
   the actual vulnerability — a bit that's supposed to represent a safety
   trip is implemented as an ordinary, remotely-writable process
   register, with nothing distinguishing it from any other setpoint.
3. **Force the pump on**: write register `1` = `1` (in case the interlock
   had already stopped it). With the interlock disabled, nothing will
   stop the pump again once it's running.
4. **Wait.** The tank fills past 100% within a few seconds of simulated
   time, and `overflow_flag` (register 4) latches to `1`.
5. **Read the flag out of the PLC**: register `99` holds the flag length,
   registers `100` onward hold its ASCII bytes — retrieved the exact same
   way you'd read any other process value, because to the protocol
   there's no difference.

(Raising `high_level_setpoint`, register `2`, above 1000 while leaving the
interlock enabled works too — same underlying issue, different register.)

`solve.py` automates all of this with a ~100-line hand-rolled Modbus
client (just `socket` + `struct`, no dependencies) so the mechanics of
the protocol are visible rather than hidden behind a library.

## Why this works

- **Modbus TCP has no authentication, by design.** It's a 1979-era
  protocol built for isolated serial control networks, later carried
  over TCP/IP largely unchanged. It was never meant to be reachable from
  anywhere an attacker could be — the entire security model assumes the
  network itself is the trust boundary.
- **The safety function isn't actually separate from the control
  function.** A real Safety Instrumented System (SIS) is supposed to be
  an independent device, on its own wiring, that a compromised PLC can't
  touch — SIL-rated hardware whose whole job is to fail safe even if the
  basic process controller is fully compromised. Here, "safety" is just
  another bit in the same register bank as everything else, writable by
  anyone who can write anything. This is not a hypothetical: the 2017
  TRITON/TRISIS malware targeted exactly this pattern — a Schneider
  Electric Triconex safety controller — to disable safety logic and let
  an unsafe process state occur undetected.
- **No segmentation, no monitoring.** In this demo the Modbus port is
  reachable directly; nothing inspects the traffic for a suspicious
  sequence like "disable interlock, then force output on."

## The fix

- **Network segmentation.** ICS/OT networks should be isolated from IT
  networks and the internet by firewalls and, for the most sensitive
  links, unidirectional gateways ("data diodes") that physically permit
  monitoring data out but nothing in.
- **Protocol-level authentication and encryption.** Plain Modbus TCP has
  none; use a secure variant (Modbus/TCP Security, IEC 62351) or tunnel
  it over an authenticated, encrypted channel (e.g. stunnel/VPN) so only
  authorized engineering workstations can issue writes at all.
- **A genuinely independent Safety Instrumented System.** Safety-critical
  trips should live on separate, hardened hardware that a PLC or its
  operator network cannot reach or reconfigure — so a compromised control
  path can never disable the safety path.
- **Least-privilege write access and change control.** Not every
  register a device exposes needs to be remotely writable at all; where
  writes are necessary, role-based access control and logging/alerting on
  writes to safety-relevant points (exactly the `interlock_enabled` write
  in this challenge) turns a silent takeover into a detected one.
- **Anomaly/behavioral monitoring.** ICS-aware intrusion detection
  (Suricata/Zeek ICS protocol parsers, or a purpose-built OT monitoring
  product) can flag an unusual write sequence like this one even when the
  write itself is technically "valid" Modbus traffic.

## Files

| File             | Purpose                                                          |
|------------------|-------------------------------------------------------------------|
| `plc_server.py`  | The simulated PLC (Modbus TCP) + read-only HMI dashboard (HTTP).  |
| `solve.py`       | Reference exploit — a minimal hand-rolled Modbus client.          |
