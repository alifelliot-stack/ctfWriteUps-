# Reverse Engineering — Self-Decoding VM Crackme

The hardest of this repo's challenges: a small C binary whose actual
flag-checking logic isn't x86 code at all. It's a custom 9-opcode
bytecode program, interpreted by a hand-rolled VM, stored XOR-encoded at
rest, and only decoded into memory right before it runs — with a silent
anti-debugging trap that corrupts the decode key the moment a debugger
attaches. Getting the flag means defeating three stacked layers, in the
right order: notice the anti-debug trap, statically pull the encoded
data straight out of the ELF, and reconstruct exactly what the VM does
to invert it.

## Objective

```
./vmcrack
Enter the flag: flag{????????????????????}
```

20 characters between the braces. Recover them.

## Build & run

```bash
cd reverse-engineering-vmcrack
./build.sh
./vmcrack                                    # interactive
./vmcrack "flag{s3lf_d3c0d1ng_vm9000}"       # or pass it as argv[1]
```

Recommended tools if you're following along by hand: `file`, `strings`,
`nm`, `readelf`, `objdump -d -M intel`, `gdb`, `strace`, `python3`. None
of this needs a decompiler, though one certainly wouldn't hurt.

## Step 1 — first look

```bash
file vmcrack
nm vmcrack | grep -v ' U '
```

`main` reads a line, checks it's `flag{` + 20 chars + `}`, then calls
`run_vm()`. `run_vm` is short and full of a `switch` on a single byte
read from a `code[]` array one position at a time — that's the tell for
a custom bytecode interpreter, not the real algorithm. The real
algorithm is data, not code, and it's sitting in `.rodata` somewhere.

## Step 2 — the trap: don't just `gdb` it

The obvious next move is to break on `run_vm` and step through it. Try
it:

```bash
gdb -q -batch -ex 'run flag{s3lf_d3c0d1ng_vm9000}' -ex quit ./vmcrack
# ... Wrong.
```

Even with the *correct* flag, it fails under gdb. Same under `strace`.
Nothing crashes, nothing prints "debugger detected" — it just silently
gives the wrong answer, which is far more likely to send you chasing the
wrong lead than an obvious abort() would.

The cause is in `main()`:

```c
int under_debugger = (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1);
...
ek[i] = ENCODE_KEY[i] ^ (under_debugger ? 0x01 : 0x00);
```

`PTRACE_TRACEME` asks the kernel to let your own parent trace you — but
a process can only have *one* tracer. If gdb or strace already attached
first, the call fails with `EPERM`, and `under_debugger` becomes true.
That flips one bit of every byte of the bytecode-decode key, so the
"decoded" bytecode is total garbage and the VM computes nonsense no
matter what flag you typed — with no observable difference from a wrong
flag.

**The lesson, and the intended path through this challenge**: don't run
it under a tracer at all. Everything from here on is static.

## Step 3 — pull the obfuscated data straight out of the binary

```bash
readelf -sW vmcrack | grep -E 'ENCODE_KEY|ENCODED_BYTECODE|ENCODED_TARGET'
```

```
12: 0000000000002020     4 OBJECT  LOCAL  DEFAULT  18 ENCODE_KEY
13: 0000000000002040   301 OBJECT  LOCAL  DEFAULT  18 ENCODED_BYTECODE
14: 0000000000002170    20 OBJECT  LOCAL  DEFAULT  18 ENCODED_TARGET
```

Local symbols weren't stripped, so their addresses and exact sizes are
right there. Cross-reference with the section headers
(`readelf -SW vmcrack`) to turn each virtual address into a file offset,
then just read the raw bytes out of the file — no execution needed.
`solve.py`'s `extract_bytes()` does exactly this.

XOR-decode the bytecode against the (unencoded — it's only 4 bytes and
isn't itself obfuscated) `ENCODE_KEY`, repeating every 4 bytes. That
gives you 301 bytes of decoded opcodes.

## Step 4 — disassemble the bytecode

The opcodes (found by reading `run_vm`'s `switch` in `objdump -d
--disassemble=run_vm -M intel vmcrack`):

| Opcode | Mnemonic     | Operand | Effect                          |
|--------|--------------|---------|----------------------------------|
| 0x00   | `HALT`       | —       | stop                             |
| 0x01   | `PUSH_INPUT` | index   | push `input[index]`              |
| 0x02   | `PUSH_CONST` | byte    | push a literal byte              |
| 0x03   | `XOR`        | —       | pop b, pop a, push a^b           |
| 0x04   | `ADD`        | —       | pop b, pop a, push (a+b) mod 256 |
| 0x05   | `ROL`        | n       | pop a, push a rotated left n bits|
| 0x06   | `SET_PREV`   | —       | pop a, `prev = a`, push a back   |
| 0x07   | `GET_PREV`   | —       | push `prev`                      |
| 0x08   | `STORE_OUT`  | index   | pop a, `out[index] = a`          |

Decoding the first 20 bytes (round 0 and the start of round 1):

```
0000: PUSH_INPUT 0x00
0002: PUSH_CONST 0x5a
0004: XOR
0005: PUSH_CONST 0x11
0007: ADD
0008: ROL 0x01
000a: GET_PREV
000b: XOR
000c: SET_PREV
000d: STORE_OUT 0x00
000f: PUSH_INPUT 0x01
0011: PUSH_CONST 0x17
0013: XOR
0014: PUSH_CONST 0x7f
0016: ADD
0017: ROL 0x02
...
```

The whole 301-byte program is just this same 10-instruction block
repeated 20 times (one per input byte), with the `PUSH_INPUT` index,
the two `PUSH_CONST` values, the `ROL` amount, and the `STORE_OUT` index
all advancing each round. No jumps — it's a flat, unrolled loop, which
is what makes it tractable to fully read by hand instead of needing an
actual disassembler-with-control-flow.

Per round `i`, in C terms:

```c
t = input[i] ^ key[i % 8];
t = (t + consts[i % 4]) & 0xFF;
t = rol8(t, (i % 5) + 1);
t = t ^ prev;
prev = t;
out[i] = t;
```

Reading off the constants from the 20 rounds gives the 8-byte `key[]`
and 4-byte `consts[]`. `prev` starts at `IV` (`0xc9` — visible as an
immediate in `run_vm`'s disassembly: `mov BYTE PTR [rbp-0x72], 0xc9`).

## Step 5 — get the target and invert

`ENCODED_TARGET` (20 bytes) is XOR-masked with a single byte — found the
same way, by reading where `main()` unmasks it:
`xor eax, 0x5a` in the disassembly. Decode it the same way.

Two valid ways to finish from here:

**A. Byte-by-byte oracle brute force** (what `solve.py` does). Notice
`out[i]` only ever depends on `input[0..i]` — `prev` only ever carries
*forward*. So: try all 256 values for `input[0]`, keep the one whose
`out[0]` matches `target[0]`; with that fixed, try all 256 values for
`input[1]`; and so on. 20 x 256 = 5,120 trials total against a
reimplemented VM (`vm_common.py`, the exact interpreter used to build
the challenge) — instant, and it requires only that your VM
*reimplementation* is correct, not that you've derived any closed-form
math.

**B. Direct algebraic inversion**, if you'd rather not brute force at
all — every step in the round is invertible:

```python
prev = IV
input_bytes = []
for i in range(20):
    t = target[i] ^ prev          # undo the final XOR with prev
    t = ror8(t, (i % 5) + 1)      # undo ROL
    t = (t - consts[i % 4]) & 0xFF  # undo ADD
    t = t ^ key[i % 8]            # undo the first XOR
    input_bytes.append(t)
    prev = target[i]              # prev was set to *this round's cipher output*
```

Both land on the same 20 bytes.

## Step 6 — solve it

```bash
python3 solve.py
```

```
[*] ENCODE_KEY       (4B): deadbeef
[*] ENCODED_BYTECODE (301B) @ 0x2040
[*] ENCODED_TARGET   (20B): e7697e9269f843d6613f756e56496f3eefdab83c
[*] decoded target: bd3324c833a2198c3b652f340c133564b580e266  (content length 20)
[+] recovered flag: flag{s3lf_d3c0d1ng_vm9000}
[*] verifying against the real binary: 'Correct!'
```

`solve.py` reads only the compiled binary (via `readelf`) plus the two
small disassembly-derived constants (`IV`, `TARGET_MASK`) — it never
looks at `bytecode.h` or `gen_bytecode.py`. Those two files are the
*author-side* build tooling, included for transparency about exactly how
the challenge was constructed (see "Files" below), not part of the
intended solve path.

## Why this is the hard one

Every other challenge in this repo has one vulnerability to find and
exploit. This one stacks three different defensive techniques that each
individually defeat a *different* lazy approach:

- **The custom VM** defeats jumping straight to a decompiler and reading
  the algorithm off of native code — there is no native "check the
  flag" function to decompile. You have to write (or reason through) an
  interpreter for an instruction set that only exists in this binary.
- **At-rest XOR encoding** of both the bytecode and the target defeats a
  plain `strings`/hexdump skim — the interesting bytes don't look like
  anything until you find and reverse the two small decode routines.
- **The self-`ptrace` anti-debug trap** defeats the instinct to just
  single-step through it in a debugger, and does so *silently* — a
  loud "debugger detected, exiting" would be a much smaller obstacle
  than getting a plausible-looking wrong answer with no error at all.

None of the three is individually exotic — each is a real technique used
in actual copy-protection and malware. What makes this "very
complicated" is that they compose: you cannot brute-force past the VM
without decoding it, can't decode it while casually debugging, and even
once you're past all of that, the transform is stateful (chained through
`prev`) rather than 20 independent single-byte comparisons, so you can't
even shortcut it with a per-byte oracle against the *running program* —
you have to actually reimplement the VM yourself.

## If this were real software, what would make it stronger

This crackme is inherently beatable no matter how well it's obfuscated,
because the *entire secret* — key, constants, and target — ships inside
the binary the attacker controls. Obfuscation raises the cost of
extraction; it can't make the secret unextractable. Real hardening
options fall into two categories:

- **Raise the cost further** (what commercial protectors like
  VMProtect/Themida do at scale): virtualize much more of the binary,
  not just one check function; add code-integrity self-checks that
  detect *patched* bytes as well as ptrace, so nopping the anti-debug
  call breaks the checksum instead; interleave real and decoy VM
  handlers; mutate the bytecode/VM per build.
- **Remove the secret from the client entirely** (the only approach
  that's actually unbeatable by reversing): validate the flag/license
  against a server that holds the real secret, so there's nothing local
  to extract no matter how much time an attacker spends. Any
  client-side check, however obfuscated, is fundamentally a "will
  eventually be reversed" proposition.

## Files

| File              | Purpose                                                            |
|-------------------|----------------------------------------------------------------------|
| `vm.c`            | The crackme: bytecode interpreter, anti-debug check, main().        |
| `bytecode.h`      | Generated: the encoded bytecode/key/target `vm.c` `#include`s.       |
| `vm_common.py`    | The one true VM semantics — used both to build and to solve.        |
| `gen_bytecode.py` | Author-side "compiler": assembles the program, computes the target, writes `bytecode.h`. Not part of the intended solve path. |
| `build.sh`        | Compiles `vm.c` -> `./vmcrack`.                                     |
| `solve.py`        | Reference solver — extracts everything from the compiled binary and recovers the flag. |
