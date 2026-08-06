// vm.c -- "self-decoding VM" crackme.
//
// The actual flag-checking algorithm is not native x86 code: it's a
// small custom bytecode program (see bytecode.h) interpreted by run_vm()
// below. The bytecode is stored XOR-encoded and only decoded into a
// stack buffer right before it's executed. On top of that, a ptrace
// self-check subtly corrupts the decode key if the process is already
// being traced (i.e. run under a debugger), so the program silently
// always reports "Wrong." under a debugger instead of crashing or
// printing anything suspicious.
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include "bytecode.h"

enum {
    OP_HALT = 0x00,
    OP_PUSH_INPUT = 0x01,
    OP_PUSH_CONST = 0x02,
    OP_XOR = 0x03,
    OP_ADD = 0x04,
    OP_ROL = 0x05,
    OP_SET_PREV = 0x06,
    OP_GET_PREV = 0x07,
    OP_STORE_OUT = 0x08,
};

static unsigned char rol8(unsigned char x, unsigned char n) {
    n &= 7;
    return (unsigned char)((x << n) | (x >> (8 - n)));
}

// Executes a flat (no-jump) bytecode program against `input`, filling
// `out[CONTENT_LEN]`.
static void run_vm(const unsigned char *code, int code_len,
                    const unsigned char *input, unsigned char *out) {
    unsigned char stack[64];
    int sp = 0;
    unsigned char prev = IV;
    int pc = 0;

    while (pc < code_len) {
        unsigned char op = code[pc++];
        switch (op) {
            case OP_HALT:
                return;
            case OP_PUSH_INPUT:
                stack[sp++] = input[code[pc++]];
                break;
            case OP_PUSH_CONST:
                stack[sp++] = code[pc++];
                break;
            case OP_XOR: {
                unsigned char b = stack[--sp], a = stack[--sp];
                stack[sp++] = a ^ b;
                break;
            }
            case OP_ADD: {
                unsigned char b = stack[--sp], a = stack[--sp];
                stack[sp++] = (unsigned char)(a + b);
                break;
            }
            case OP_ROL: {
                unsigned char n = code[pc++];
                unsigned char a = stack[--sp];
                stack[sp++] = rol8(a, n);
                break;
            }
            case OP_SET_PREV: {
                unsigned char a = stack[sp - 1];
                prev = a;
                break;
            }
            case OP_GET_PREV:
                stack[sp++] = prev;
                break;
            case OP_STORE_OUT: {
                unsigned char idx = code[pc++];
                out[idx] = stack[--sp];
                break;
            }
            default:
                return; // malformed program -- bail out
        }
    }
}

int main(int argc, char **argv) {
    char line[128];

    if (argc == 2) {
        strncpy(line, argv[1], sizeof(line) - 1);
        line[sizeof(line) - 1] = '\0';
    } else {
        printf("Enter the flag: ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) return 1;
        line[strcspn(line, "\r\n")] = '\0';
    }

    size_t len = strlen(line);
    if (len != CONTENT_LEN + 6 || strncmp(line, "flag{", 5) != 0 || line[len - 1] != '}') {
        puts("Wrong.");
        return 1;
    }
    unsigned char content[CONTENT_LEN];
    memcpy(content, line + 5, CONTENT_LEN);

    // Self-ptrace anti-debug trick: a process can only be traced by one
    // tracer at a time. If we're already being traced (gdb/strace
    // attached), this fails with EPERM.
    int under_debugger = (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1);

    // Decode the bytecode. If under a debugger, flip one bit of the
    // decode key -- every decoded byte comes out wrong, silently, with
    // no crash and no visible check to patch around at this point.
    unsigned char ek[4];
    for (int i = 0; i < 4; i++) {
        ek[i] = ENCODE_KEY[i] ^ (under_debugger ? 0x01 : 0x00);
    }
    unsigned char code[BYTECODE_LEN];
    for (int i = 0; i < BYTECODE_LEN; i++) {
        code[i] = ENCODED_BYTECODE[i] ^ ek[i % 4];
    }

    unsigned char out[CONTENT_LEN];
    memset(out, 0, sizeof(out));
    run_vm(code, BYTECODE_LEN, content, out);

    unsigned char target[CONTENT_LEN];
    for (int i = 0; i < CONTENT_LEN; i++) {
        target[i] = ENCODED_TARGET[i] ^ TARGET_MASK;
    }

    if (memcmp(out, target, CONTENT_LEN) == 0) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong.");
    return 1;
}
