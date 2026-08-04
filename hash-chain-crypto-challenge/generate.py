#!/usr/bin/env python3
"""
Author-side build script for the 3-stage hash-chain challenge.
Picks fresh random secrets, derives the public challenge.json, and prints
the secrets once for the author's own records. Re-run to mint a new
instance (e.g. for a different flag or a live event).

Chain design:

  stage 1  word1  <-- dictionary attack over wordlist.txt
           H1 = sha256(salt1 + word1)

  stage 2  pin2   <-- brute force over 000000-999999
           H2 = sha256(salt2 + word1 + pin2)          (needs word1)

  stage 3  token3 <-- brute force over [a-z0-9]{4}
           inner  = sha1(salt3 + word1 + pin2 + token3)
           H3     = md5(inner)                        (needs word1, pin2)

  final    key = stretch(salt_final + word1 + pin2 + token3, 200_000 rounds)
           ciphertext = flag XOR keystream(key)        (needs all three)

Each stage's hash is *salted*, so it can't be looked up in a public
rainbow table or answered from a model's memorized hash/plaintext pairs —
it has to be brute-forced against the actual keyspace, and each stage's
keyspace only makes sense once the previous stage's plaintext is known.
"""
import hashlib
import hmac
import json
import os
import secrets
import string


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
    with open("wordlist.txt") as f:
        words = [w.strip() for w in f if w.strip()]

    rng = secrets.SystemRandom()

    salt1 = secrets.token_hex(8)
    word1 = rng.choice(words)
    h1 = hashlib.sha256((salt1 + word1).encode()).hexdigest()

    salt2 = secrets.token_hex(8)
    pin2 = f"{rng.randrange(10 ** 6):06d}"
    h2 = hashlib.sha256((salt2 + word1 + pin2).encode()).hexdigest()

    salt3 = secrets.token_hex(8)
    alphabet = string.ascii_lowercase + string.digits
    token3 = "".join(rng.choice(alphabet) for _ in range(4))
    inner = hashlib.sha1((salt3 + word1 + pin2 + token3).encode()).hexdigest()
    h3 = hashlib.md5(inner.encode()).hexdigest()

    flag = os.environ.get(
        "CHALLENGE_FLAG", "flag{thr33_s4lty_st4g3s_n0_sh0rtcuts_4_ai}"
    )
    salt_final = secrets.token_hex(8)
    key = sha256_stretch((salt_final + word1 + pin2 + token3).encode(), 200_000)
    ct = bytes(a ^ b for a, b in zip(flag.encode(), keystream(key, len(flag))))

    challenge = {
        "stage1": {
            "salt": salt1,
            "hash": h1,
            "algo": "sha256(salt + word)",
            "keyspace": "wordlist.txt (dictionary attack)",
        },
        "stage2": {
            "salt": salt2,
            "hash": h2,
            "algo": "sha256(salt + word1 + pin)",
            "keyspace": "000000-999999",
        },
        "stage3": {
            "salt": salt3,
            "hash": h3,
            "algo": "md5(sha1(salt + word1 + pin2 + token3))",
            "keyspace": "[a-z0-9]{4}",
        },
        "final": {
            "salt": salt_final,
            "ciphertext_hex": ct.hex(),
            "algo": "key = sha256^200000(salt + word1 + pin2 + token3); "
                    "flag = ciphertext XOR HMAC-SHA256-CTR-keystream(key)",
        },
    }

    with open("challenge.json", "w") as f:
        json.dump(challenge, f, indent=2)

    print("challenge.json written.")
    print("author-only secrets (do NOT publish):")
    print("  word1  =", word1)
    print("  pin2   =", pin2)
    print("  token3 =", token3)
    print("  flag   =", flag)


if __name__ == "__main__":
    main()
