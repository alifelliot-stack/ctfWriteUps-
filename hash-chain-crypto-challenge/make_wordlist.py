#!/usr/bin/env python3
"""
Generates wordlist.txt: a static, deterministic list of ~4000 pronounceable
pseudo-words used as the stage-1 dictionary-attack keyspace.

Not a real dictionary on purpose: it keeps the challenge fully
self-contained (no dependency on /usr/share/dict/words or a downloaded
wordlist) and guarantees stage 1 isn't solvable by looking up the salted
hash against public rainbow tables or "common English word" hash lists.

Run once; the output is committed as wordlist.txt.
"""
import random

ONSETS = ["b", "br", "c", "cr", "d", "dr", "f", "fr", "g", "gr", "h", "j",
          "k", "kl", "l", "m", "n", "p", "pl", "pr", "qu", "r", "s", "sk",
          "sl", "sn", "sp", "st", "sw", "t", "tr", "v", "w", "z"]
VOWELS = ["a", "e", "i", "o", "u", "ai", "ea", "oo", "ou", "ie"]
CODAS = ["n", "r", "t", "s", "l", "m", "nd", "rk", "st", "th", "sh", "ng", "ck"]

def make_word(rng: random.Random) -> str:
    syllables = rng.randint(2, 3)
    word = ""
    for i in range(syllables):
        word += rng.choice(ONSETS) + rng.choice(VOWELS)
    if rng.random() < 0.6:
        word += rng.choice(CODAS)
    return word

def main():
    rng = random.Random(1337)  # fixed seed -> reproducible list
    words = set()
    while len(words) < 4096:
        words.add(make_word(rng))
    with open("wordlist.txt", "w") as f:
        f.write("\n".join(sorted(words)) + "\n")
    print(f"wrote {len(words)} words to wordlist.txt")

if __name__ == "__main__":
    main()
