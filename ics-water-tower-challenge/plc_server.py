#!/usr/bin/env python3
"""
plc_server.py — simulated PLC for "Pump Station 4", a water-tower level
control system.

Speaks real Modbus TCP (MBAP header, function codes 0x03 Read Holding
Registers and 0x06 Write Single Register) on port 5020 — the same wire
protocol a real PLC would speak, including the industry-standard weakness
that Modbus TCP has *no authentication at all*. Anyone who can reach the
port can read and write registers; the protocol has no concept of a
login. That's not a bug introduced for this challenge — it's how the real
protocol (from 1979) actually works, which is exactly why ICS networks
are supposed to be firewalled off from anything that can reach them.

Run:
    python3 plc_server.py

Then either:
  - point any real Modbus client at 127.0.0.1:5020 (pymodbus, mbpoll, ...), or
  - use the minimal client bundled in solve.py, or
  - just watch the live HMI dashboard at http://127.0.0.1:8080/
"""
import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODBUS_PORT = 5020
HTTP_PORT = 8080
FLAG = "flag{m0dbus_h4s_n0_4uth_s0_1_0wn3d_th3_pump}"

# --- Register map (a "point list", in ICS terms) ----------------------
# 0    water_level          0-1200  (0.0%-120.0% tank fill)   read-only
# 1    pump_on              0 / 1                             writable
# 2    high_level_setpoint  default 800 (=80.0%)               writable
# 3    interlock_enabled    0 / 1, default 1 — safety trip     writable (should NOT be, but is)
# 4    overflow_flag        0 / 1, latches once level >= 1000  read-only
# 5    low_level_setpoint   default 200 (=20.0%)                writable
# 99   flag_length          set once overflow triggers         read-only
# 100+ flag bytes (1 ASCII char per register), set once overflow triggers, read-only

NUM_REGS = 200
regs = [0] * NUM_REGS
regs[0] = 300   # starting level: 30.0%
regs[1] = 1     # pump running (normal operation)
regs[2] = 800   # high setpoint: 80.0%
regs[3] = 1     # safety interlock ENABLED
regs[5] = 200   # low setpoint: 20.0%

lock = threading.Lock()

# Only these addresses accept writes. Everything else (level, overflow
# flag, the flag storage block) is application-enforced read-only, same
# as a real device would restrict writes on process-value registers.
WRITABLE = {1, 2, 3, 5}

PUMP_FLOW = 40  # level units added per tick while the pump runs
LEAK = 6        # constant drain per tick (usage + evaporation)


def simulate():
    """Background physics + control loop, ticking twice a second."""
    while True:
        time.sleep(0.5)
        with lock:
            level = regs[0]
            pump_on = regs[1]
            high = regs[2]
            interlock = regs[3]
            low = regs[5]

            # Combined bang-bang level controller + high-level safety trip.
            # Both behaviors are gated on the SAME interlock_enabled bit —
            # a real Safety Instrumented System would be a separate,
            # independently-wired device that a PLC register write can't
            # touch. Here it's just another Modbus register.
            if interlock:
                if pump_on and level >= high:
                    pump_on = 0
                elif not pump_on and level <= low:
                    pump_on = 1
                regs[1] = pump_on

            delta = (PUMP_FLOW if pump_on else 0) - LEAK
            level = max(0, min(1200, level + delta))
            regs[0] = level

            if level >= 1000 and regs[4] == 0:
                regs[4] = 1
                flag_bytes = FLAG.encode()
                regs[99] = len(flag_bytes)
                for i, b in enumerate(flag_bytes):
                    regs[100 + i] = b


# --- Minimal, real Modbus TCP server ----------------------------------

def recvall(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_modbus(conn):
    with conn:
        while True:
            header = recvall(conn, 7)
            if not header:
                return
            tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", header)
            pdu = recvall(conn, length - 1)
            if pdu is None:
                return
            func = pdu[0]

            if func == 0x03:  # Read Holding Registers
                start, qty = struct.unpack(">HH", pdu[1:5])
                with lock:
                    if start < 0 or qty < 1 or start + qty > NUM_REGS:
                        resp_pdu = bytes([0x83, 0x02])  # illegal data address
                    else:
                        values = regs[start:start + qty]
                        resp_pdu = bytes([0x03, qty * 2]) + b"".join(
                            struct.pack(">H", v) for v in values
                        )

            elif func == 0x06:  # Write Single Register
                addr, value = struct.unpack(">HH", pdu[1:5])
                with lock:
                    if addr not in WRITABLE:
                        resp_pdu = bytes([0x86, 0x02])  # illegal data address
                    else:
                        regs[addr] = value & 0xFFFF
                        resp_pdu = pdu  # spec: echo the request back

            else:
                resp_pdu = bytes([func | 0x80, 0x01])  # illegal function

            mbap = struct.pack(">HHHB", tx_id, 0, len(resp_pdu) + 1, unit_id)
            conn.sendall(mbap + resp_pdu)


def modbus_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", MODBUS_PORT))
    srv.listen(5)
    print(f"[plc] Modbus TCP listening on 0.0.0.0:{MODBUS_PORT} (no authentication)")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_modbus, args=(conn,), daemon=True).start()


# --- Read-only HMI dashboard (HTTP, separate from the Modbus port) ----

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Pump Station 4 — HMI</title>
<style>
  body { font-family: Arial, sans-serif; background: #0f1622; color: #d7e3f4; margin: 0; }
  header { background: #142236; padding: 14px 24px; border-bottom: 2px solid #24405f; }
  header h1 { margin: 0; font-size: 18px; }
  header p { margin: 4px 0 0; font-size: 12px; color: #7d93b3; }
  main { max-width: 640px; margin: 24px auto; padding: 0 20px; }
  .tank { position: relative; width: 160px; height: 320px; margin: 20px auto;
          border: 3px solid #3a5a82; border-radius: 6px; background: #0a121e; overflow: hidden; }
  .tank .fill { position: absolute; bottom: 0; left: 0; right: 0; background: linear-gradient(#2b8fd6, #1b5f96);
                transition: height .4s linear; }
  .tank .fill.over { background: linear-gradient(#e53e3e, #a52020); }
  .tank .mark { position: absolute; left: 0; right: 0; border-top: 1px dashed #5a7ba3; font-size: 10px; color: #7d93b3; padding-left: 4px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 20px; }
  .card { background: #142236; border: 1px solid #24405f; border-radius: 6px; padding: 10px 14px; font-size: 13px; }
  .card .label { color: #7d93b3; font-size: 11px; text-transform: uppercase; }
  .card .value { font-size: 18px; font-weight: bold; margin-top: 2px; }
  .ok { color: #48bb78; } .bad { color: #f56565; } .warn { color: #ecc94b; }
  .flagbox { margin-top: 20px; padding: 14px; background: #3a1414; border: 1px solid #e53e3e;
             border-radius: 6px; font-family: monospace; font-size: 14px; display: none; word-break: break-all; }
</style>
</head>
<body>
<header>
  <h1>Riverside Water Utility — Pump Station 4</h1>
  <p>Elevated tank level control — read-only operator view</p>
</header>
<main>
  <div class="tank">
    <div class="fill" id="fill" style="height:0%"></div>
    <div class="mark" style="bottom:80%">HIGH SETPOINT</div>
    <div class="mark" style="bottom:20%">LOW SETPOINT</div>
  </div>
  <div class="grid">
    <div class="card"><div class="label">Level</div><div class="value" id="level">--</div></div>
    <div class="card"><div class="label">Pump</div><div class="value" id="pump">--</div></div>
    <div class="card"><div class="label">Safety interlock</div><div class="value" id="interlock">--</div></div>
    <div class="card"><div class="label">Overflow alarm</div><div class="value" id="overflow">--</div></div>
  </div>
  <div class="flagbox" id="flagbox"></div>
</main>
<script>
async function poll() {
  try {
    const r = await fetch('/status.json');
    const d = await r.json();
    const fill = document.getElementById('fill');
    fill.style.height = Math.min(100, d.level_pct) + '%';
    fill.classList.toggle('over', d.overflow);
    document.getElementById('level').textContent = d.level_pct.toFixed(1) + '%';
    document.getElementById('pump').innerHTML = d.pump_on ? '<span class="ok">RUNNING</span>' : '<span class="warn">STOPPED</span>';
    document.getElementById('interlock').innerHTML = d.interlock_enabled ? '<span class="ok">ENABLED</span>' : '<span class="bad">DISABLED</span>';
    document.getElementById('overflow').innerHTML = d.overflow ? '<span class="bad">TRIPPED</span>' : '<span class="ok">clear</span>';
    if (d.overflow && d.flag) {
      const box = document.getElementById('flagbox');
      box.style.display = 'block';
      box.textContent = 'TANK OVERFLOW — incident log: ' + d.flag;
    }
  } catch (e) {}
}
setInterval(poll, 1000);
poll();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/status.json":
            with lock:
                data = {
                    "level_pct": regs[0] / 10,
                    "pump_on": bool(regs[1]),
                    "high_setpoint_pct": regs[2] / 10,
                    "low_setpoint_pct": regs[5] / 10,
                    "interlock_enabled": bool(regs[3]),
                    "overflow": bool(regs[4]),
                    "flag": FLAG if regs[4] else None,
                }
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def http_server():
    srv = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    print(f"[hmi] Dashboard on http://0.0.0.0:{HTTP_PORT}/")
    srv.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=simulate, daemon=True).start()
    threading.Thread(target=http_server, daemon=True).start()
    modbus_server()
