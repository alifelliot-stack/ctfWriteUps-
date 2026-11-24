"""
Shared VM semantics, used both to *generate* the challenge (compute the
target bytes the compiled C binary will check against) and, unmodified,
as the reference interpreter inside solve.py. Keeping exactly one
implementation of the opcode semantics means the generator and the
solver can never silently disagree about what the VM does.

Instruction set (1-byte opcode, optional 1-byte immediate operand):
  0x00 HALT
  0x01 PUSH_INPUT  <i>   push input_bytes[i]
  0x02 PUSH_CONST  <b>   push literal byte b
  0x03 XOR                pop b, pop a, push a^b
  0x04 ADD                pop b, pop a, push (a+b) mod 256
  0x05 ROL         <n>   pop a, push rol8(a, n)
  0x06 SET_PREV           pop a, prev = a, push a back
  0x07 GET_PREV           push prev
  0x08 STORE_OUT   <i>   pop a, out[i] = a
"""

HALT, PUSH_INPUT, PUSH_CONST, XOR, ADD, ROL, SET_PREV, GET_PREV, STORE_OUT = range(9)

OPNAMES = {
    HALT: "HALT", PUSH_INPUT: "PUSH_INPUT", PUSH_CONST: "PUSH_CONST",
    XOR: "XOR", ADD: "ADD", ROL: "ROL", SET_PREV: "SET_PREV",
    GET_PREV: "GET_PREV", STORE_OUT: "STORE_OUT",
}
# opcodes that carry a 1-byte immediate operand
HAS_OPERAND = {PUSH_INPUT, PUSH_CONST, ROL, STORE_OUT}


def rol8(x: int, n: int) -> int:
    n &= 7
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF


def disassemble(bytecode):
    """Yields (pc, mnemonic, operand_or_None) -- for humans/write-ups."""
    pc = 0
    n = len(bytecode)
    while pc < n:
        op = bytecode[pc]
        start = pc
        pc += 1
        operand = None
        if op in HAS_OPERAND:
            operand = bytecode[pc]
            pc += 1
        yield start, OPNAMES.get(op, f"??{op:#x}"), operand
        if op == HALT:
            break


def run_vm(bytecode, input_bytes, iv, out_len):
    """Executes the flat (no-jump) bytecode program. Returns the `out` array."""
    stack = []
    prev = iv & 0xFF
    out = [0] * out_len
    pc = 0
    n = len(bytecode)
    while pc < n:
        op = bytecode[pc]
        pc += 1
        if op == HALT:
            break
        elif op == PUSH_INPUT:
            i = bytecode[pc]; pc += 1
            stack.append(input_bytes[i] & 0xFF)
        elif op == PUSH_CONST:
            b = bytecode[pc]; pc += 1
            stack.append(b & 0xFF)
        elif op == XOR:
            b = stack.pop(); a = stack.pop(); stack.append((a ^ b) & 0xFF)
        elif op == ADD:
            b = stack.pop(); a = stack.pop(); stack.append((a + b) & 0xFF)
        elif op == ROL:
            nshift = bytecode[pc]; pc += 1
            a = stack.pop(); stack.append(rol8(a, nshift))
        elif op == SET_PREV:
            a = stack.pop(); prev = a; stack.append(a)
        elif op == GET_PREV:
            stack.append(prev)
        elif op == STORE_OUT:
            i = bytecode[pc]; pc += 1
            a = stack.pop(); out[i] = a
        else:
            raise ValueError(f"unknown opcode {op:#x} at pc={pc - 1}")
    return out


def build_program(key, consts, count):
    """Assembles the flat (unrolled, no-jump) bytecode for `count` rounds."""
    prog = []

    def emit(op, *operand):
        prog.append(op)
        prog.extend(operand)

    for i in range(count):
        emit(PUSH_INPUT, i)
        emit(PUSH_CONST, key[i % len(key)])
        emit(XOR)
        emit(PUSH_CONST, consts[i % len(consts)])
        emit(ADD)
        emit(ROL, (i % 5) + 1)
        emit(GET_PREV)
        emit(XOR)
        emit(SET_PREV)
        emit(STORE_OUT, i)
    emit(HALT)
    return prog
