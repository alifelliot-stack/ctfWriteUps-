# 3-Stage Hash Chain — Crypto Puzzle (AI-Resistant)

A self-contained, three-layer "hash → plaintext" crypto challenge. Each
stage's secret is salted and hashed, and each stage's hash *depends on the
previous stage's plaintext* — so the three stages must be broken in order,
each by brute force, before a final key-derivation step decrypts the flag.

No network, no dependencies beyond the Python standard library
(`hashlib`, `hmac`, `secrets`, `itertools`).

## The chain

```
stage 1   word1    <- dictionary attack over wordlist.txt (4096 entries)
          H1 = sha256(salt1 + word1)

stage 2   pin2     <- brute force over 000000-999999
          H2 = sha256(salt2 + word1 + pin2)                 (needs word1)

stage 3   token3   <- brute force over [a-z0-9]{4}
          inner    = sha1(salt3 + word1 + pin2 + token3)
          H3       = md5(inner)                             (needs word1, pin2)

final     key = sha256, iterated 200,000 times, seeded with
                salt_final + word1 + pin2 + token3           (needs all three)
          flag = ciphertext XOR HMAC-SHA256-CTR-keystream(key)
```

`challenge.json` publishes every salt, every target hash, and the final
ciphertext. `wordlist.txt` is the public stage-1 keyspace. Nothing else is
given — no oracle to check partial guesses, no plaintext hints.

## Run it

```bash
cd hash-chain-crypto-challenge
python3 solve.py
```

The reference solver brute-forces all three stages in order and prints the
flag (~1-2 seconds on a modern laptop — small keyspaces on purpose, see
below, so this stays a scripting exercise rather than a compute-cluster
exercise).

To mint a fresh instance with a new flag and new random secrets:

```bash
CHALLENGE_FLAG='flag{your_flag_here}' python3 generate.py
```

This overwrites `challenge.json`. `wordlist.txt` is static and doesn't need
regenerating (`make_wordlist.py` produced it once, deterministically, from
a fixed seed — rerunning it is only needed if you want a different
keyspace).

## Why it's built this way

- **Every hash is salted.** A raw, unsalted `md5("password")`-style hash
  can be reversed instantly by pasting it into a public rainbow-table
  lookup site — no cryptography required, just a database lookup. Salting
  every stage (`sha256(salt + secret)`) makes every target hash unique to
  this instance, so no precomputed table (and no model that memorized
  common hash → plaintext pairs during training) can shortcut it. The only
  way in is to hash actual candidates against the actual salt.
- **The stages are chained, not independent.** Stage 2's hash is
  `sha256(salt2 + word1 + pin2)` — it structurally cannot be attacked
  without already knowing `word1`. Same for stage 3 needing both `word1`
  and `pin2`. This forces a strict solve order; there's no "guess the
  easiest stage first" or "brute force stage 3 for free hints about stage
  1" shortcut.
- **A custom, non-dictionary wordlist.** Stage 1's keyspace
  (`wordlist.txt`) is synthetic, pronounceable nonsense generated from a
  fixed random seed (`make_wordlist.py`) — not `/usr/share/dict/words`,
  not a leaked password list, not anything a model would recognize or have
  indexed. It still has to be brute-forced with code; there's no
  "recognize the word" trick available.
- **Nested/mixed hash functions in stage 3.** `md5(sha1(...))` isn't
  cryptographically meaningful by itself, but it defeats naive "detect the
  hash type and look it up" tooling (hash-identifier utilities, online
  crackers) that expect a single, unwrapped, well-known hash format.
- **No partial-credit oracle.** The challenge only publishes final target
  hashes and a final ciphertext — never a "here's whether your guess for
  stage 2 alone is right" check independent of also having stage 1 right.
  Combined with the salting, there is no way to verify a guess for any
  stage without actually computing the hash chain in code.
- **KDF stretching on the final key.** The final decryption key is
  `sha256` applied 200,000 times to the concatenated secrets before it's
  used as a keystream seed. This doesn't change the brute-force cost of
  the three stages (each is checked against its own fast single-round
  hash) but it does mean the *decryption* step itself can't be waved away
  as "just hash the secrets once and XOR" — matching how a real KDF
  (PBKDF2/scrypt/Argon2-style stretching) would be used to derive a key
  from low-entropy inputs.

Put together: an AI assistant (or a human) staring at `challenge.json` and
reasoning about it in its head has no path to the flag — the salted hashes
give it nothing to pattern-match against, and the chaining means even a
correct guess for one stage is unverifiable in isolation. The only route
through is exactly what `solve.py` does: write code, brute-force each
stage against its real keyspace, and decrypt at the end.

## Files

| File               | Purpose                                                        |
|--------------------|-----------------------------------------------------------------|
| `challenge.json`   | Public: salts, target hashes, final ciphertext.                 |
| `wordlist.txt`     | Public: stage-1 dictionary-attack keyspace (4096 words).        |
| `solve.py`         | Reference solver — brute-forces all 3 stages, decrypts the flag.|
| `generate.py`      | Author-side script that builds `challenge.json` from a flag.    |
| `make_wordlist.py` | One-time, seeded generator for `wordlist.txt`.                  |

## Adjusting the difficulty

Every keyspace is a few lines in `generate.py` / `solve.py`:

- Stage 1: swap `wordlist.txt` for a larger list, or generate it with a
  different seed/length in `make_wordlist.py`.
- Stage 2: widen the PIN (e.g. 8 digits) for a slower brute force.
- Stage 3: lengthen `token3` or widen its alphabet
  (`string.ascii_lowercase + string.digits` → add uppercase/punctuation) —
  each extra character multiplies the keyspace by the alphabet size.
- Final: raise the 200,000-round stretch count to make the last step
  itself take longer to compute (does not affect stages 1-3's brute-force
  cost, only the one-time key derivation after they're solved).

Keep stage 2/3 keyspaces small enough that a pure-Python brute force
finishes in seconds to minutes — the challenge is about *forcing* code
execution over reasoning, not about turning it into a distributed
cracking job.
