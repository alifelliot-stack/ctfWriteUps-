#!/usr/bin/env python3
"""
Reference solver for the self-decoding VM crackme -- works directly
against the compiled ./vmcrack binary, not against the source.

What a real analysis session looks like, and what this script automates:

  1. `readelf -sW vmcrack` lists ENCODE_KEY, ENCODED_BYTECODE and
     ENCODED_TARGET as local symbols with addresses and sizes -- the
     obfuscated bytecode and target never left the binary, they're just
     not disassembled as code.
  2. `readelf -SW vmcrack` gives .rodata's virtual address and file
     offset, so each symbol's address converts to a file offset and its
     raw bytes can be read straight out of the ELF file.
  3. Two scalar constants aren't in any symbol -- they're small
     immediates in the disassembly:
       - `objdump -d --disassemble=run_vm vmcrack` shows
         `mov BYTE PTR [rbp-0x72], 0xc9` initializing `prev` -- that's IV.
       - `objdump -d --disassemble=main vmcrack` shows `xor eax, 0x5a`
         where the target bytes get unmasked -- that's TARGET_MASK.
     (Both are hardcoded below with that provenance; a full disassembler
     is out of scope for this script.)
  4. XOR-decode the bytecode and the target with the recovered keys.
  5. The decoded bytecode is executed with vm_common.run_vm() -- the
     *exact same* interpreter used to build the challenge, reused
     unmodified here as the "I understood the ISA" proof.
  6. Because each output byte only depends on input bytes at or before
     its own index (the `prev` chain only runs forward), the 20-byte
     flag can be recovered one byte at a time: try all 256 values for
     byte i with the already-solved prefix fixed, keep whichever
     reproduces target[i]. No brute force explosion, no need to derive
     the closed-form algebraic inverse (though README.md shows that too).
"""
import subprocess
import sys

import vm_common as vm

BINARY = "./vmcrack"

# See docstring point 3 -- read directly off the disassembly, not derived.
IV = 0xC9
TARGET_MASK = 0x5A


def read_symbols(binary):
    out = subprocess.run(["readelf", "-sW", binary], capture_output=True, text=True).stdout
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[-1] in ("ENCODE_KEY", "ENCODED_BYTECODE", "ENCODED_TARGET"):
            addr = int(parts[1], 16)
            size = int(parts[2])
            syms[parts[-1]] = (addr, size)
    return syms


def read_section_map(binary, section=".rodata"):
    out = subprocess.run(["readelf", "-SW", binary], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if section in line:
            parts = line.split()
            # "[ N] .rodata PROGBITS <addr> <off> <size> ..."
            idx = parts.index(section)
            addr = int(parts[idx + 2], 16)
            off = int(parts[idx + 3], 16)
            return addr, off
    raise RuntimeError(f"{section} not found")


def extract_bytes(binary, addr, size, section_addr, section_off):
    file_off = section_off + (addr - section_addr)
    with open(binary, "rb") as f:
        f.seek(file_off)
        return list(f.read(size))


def main():
    syms = read_symbols(BINARY)
    sec_addr, sec_off = read_section_map(BINARY)

    ek_addr, ek_size = syms["ENCODE_KEY"]
    bc_addr, bc_size = syms["ENCODED_BYTECODE"]
    tg_addr, tg_size = syms["ENCODED_TARGET"]

    encode_key = extract_bytes(BINARY, ek_addr, ek_size, sec_addr, sec_off)
    encoded_bytecode = extract_bytes(BINARY, bc_addr, bc_size, sec_addr, sec_off)
    encoded_target = extract_bytes(BINARY, tg_addr, tg_size, sec_addr, sec_off)

    print(f"[*] ENCODE_KEY       ({ek_size}B): {bytes(encode_key).hex()}")
    print(f"[*] ENCODED_BYTECODE ({bc_size}B) @ {hex(bc_addr)}")
    print(f"[*] ENCODED_TARGET   ({tg_size}B): {bytes(encoded_target).hex()}")

    code = [b ^ encode_key[i % len(encode_key)] for i, b in enumerate(encoded_bytecode)]
    target = [b ^ TARGET_MASK for b in encoded_target]
    content_len = len(target)
    print(f"[*] decoded target: {bytes(target).hex()}  (content length {content_len})")

    recovered = [0] * content_len
    for i in range(content_len):
        for guess in range(256):
            recovered[i] = guess
            out = vm.run_vm(code, recovered, IV, content_len)
            if out[i] == target[i]:
                break
        else:
            print(f"[!] no byte reproduces target[{i}] -- extraction or IV/MASK is wrong", file=sys.stderr)
            sys.exit(1)

    flag = "flag{" + bytes(recovered).decode() + "}"
    print(f"[+] recovered flag: {flag}")

    check = subprocess.run([BINARY, flag], capture_output=True, text=True)
    print(f"[*] verifying against the real binary: {check.stdout.strip()!r}")
    assert check.stdout.strip() == "Correct!", "sanity check failed"


if __name__ == "__main__":
    main()
