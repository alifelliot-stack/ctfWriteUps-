#!/usr/bin/env python3
"""
Reference solver for the 3-stage hash-chain challenge.

Solves stage 1 (dictionary attack), then stage 2 (numeric brute force,
chained on stage 1's answer), then stage 3 (short alnum brute force
through a nested SHA1->MD5 hash, chained on stages 1+2), then derives the
final key from all three secrets and decrypts the flag.

Nothing here is guessed — every stage is solved by exhaustively checking
candidates against the salted target hash from challenge.json. That's the
point: there is no shortcut that skips the compute.
"""
import hashlib
import hmac
import itertools
import json
import string
import time


def sha256_stretch(data: bytes, rounds: int) -> bytes:
    for _ in range(rounds):
        data = hashlib.sha256(data).digest()
    return data


def keystream(key: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hmac.new(key, counter.to_bytes(4, "big"), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def main():
    with open("challenge.json") as f:
        chal = json.load(f)
    with open("wordlist.txt") as f:
        words = [w.strip() for w in f if w.strip()]

    t0 = time.time()

    # --- Stage 1: dictionary attack ---------------------------------
    s1 = chal["stage1"]
    word1 = None
    for w in words:
        if hashlib.sha256((s1["salt"] + w).encode()).hexdigest() == s1["hash"]:
            word1 = w
            break
    assert word1, "stage 1 failed"
    print(f"[stage1] word1  = {word1!r}   (+{time.time() - t0:.2f}s)")

    # --- Stage 2: brute force 6-digit pin, chained on word1 ---------
    s2 = chal["stage2"]
    pin2 = None
    for n in range(10 ** 6):
        pin = f"{n:06d}"
        if hashlib.sha256((s2["salt"] + word1 + pin).encode()).hexdigest() == s2["hash"]:
            pin2 = pin
            break
    assert pin2, "stage 2 failed"
    print(f"[stage2] pin2   = {pin2!r}   (+{time.time() - t0:.2f}s)")

    # --- Stage 3: brute force 4-char [a-z0-9] token through a nested
    #     SHA1 -> MD5 hash, chained on word1 + pin2 ---------------------
    s3 = chal["stage3"]
    alphabet = string.ascii_lowercase + string.digits
    token3 = None
    for tup in itertools.product(alphabet, repeat=4):
        tok = "".join(tup)
        inner = hashlib.sha1((s3["salt"] + word1 + pin2 + tok).encode()).hexdigest()
        if hashlib.md5(inner.encode()).hexdigest() == s3["hash"]:
            token3 = tok
            break
    assert token3, "stage 3 failed"
    print(f"[stage3] token3 = {token3!r}   (+{time.time() - t0:.2f}s)")

    # --- Final: derive stretched key from all 3 secrets, decrypt ----
    fin = chal["final"]
    key = sha256_stretch((fin["salt"] + word1 + pin2 + token3).encode(), 200_000)
    ct = bytes.fromhex(fin["ciphertext_hex"])
    flag = bytes(a ^ b for a, b in zip(ct, keystream(key, len(ct)))).decode()
    print(f"[flag]   {flag}   (total {time.time() - t0:.2f}s)")


if __name__ == "__main__":
    main()
