---
tags: [cryptography, symmetric-crypto, cryptohack, aes]
---

# Symmetric Crypto - ECB Byte-at-a-Time Attack

Recovers a secret appended after attacker-controlled input, using only an ECB encryption oracle — no decrypt function needed. Built entirely on two facts: ECB encrypts every 16-byte block independently, and AES is deterministic.

---

## Setup

Oracle: `Encrypt(your_input || SECRET, KEY)`, ECB mode. You control `your_input` (a prefix); `SECRET` is unknown and appended after it.

---

## Core Idea

For each unknown byte, build two 16-byte blocks that should encrypt identically *iff* your guess is correct:

- **Reference block** — a block whose last byte is the real (unknown) secret byte, with the other 15 bytes known to you. Get its ciphertext from `targets` (precomputed once, see below).
- **Candidate block** — `(A*16 + known + guess)[-16:]`, i.e. the 16 bytes ending in your guess, where `known` is everything recovered so far.

Since both blocks are exactly 16 bytes and ECB encrypts each block independently of its neighbors, encrypting a candidate gives you `AES_k(candidate)` regardless of what surrounds it in the request. So:

```
AES_k(candidate) == reference  ⇔  guess == secret_byte
```

Batch every guess in `CHARSET` into one request — ECB still encrypts each 16-byte chunk independently, so the response is just N independent ciphertexts to scan.

---

## Precomputing the Reference Blocks (16 requests, one-time)

The reference block for byte `secret[L]` depends only on `(L+1) % 16` — call this `offset`. For a given `offset`, the needed reference is always a block of `encrypt(A*(16-offset) || SECRET)`; only *which block* (`b_idx = (L+1) // 16`) changes as `L` grows.

So instead of re-querying the oracle for a fresh reference block on every iteration (the old approach), precompute the ciphertext for all 16 possible filler lengths **once**, up front:

```python
# targets[offset] = AES_k( A*(16-offset) || SECRET ), offset = 0..15
targets = [encrypt(b"A" * (BLOCK_SIZE - i)) for i in range(BLOCK_SIZE)]
```

Each `targets[offset]` ciphertext covers the *entire* secret. As `known` grows, you just slice a different block (`b_idx`) out of the *same* stored ciphertext — no new "reference" requests are ever needed again.

> `offset == 0` corresponds to filler length 16 (not 0) — same fix as the old note's `pad_len == 0` special case, just baked into the precomputed table instead of handled per-iteration.

---

## Per-Byte Recovery (≈1 batched request)

```python
b_idx, offset = divmod(len(known) + 1, BLOCK_SIZE)
target = targets[offset][b_idx * BLOCK_SIZE : (b_idx + 1) * BLOCK_SIZE]
```

`target` is the 16-byte ciphertext block whose plaintext ends in `secret[len(known)]`.

```python
candidates = [(b"A" * BLOCK_SIZE + bytes(known) + bytes([c]))[-BLOCK_SIZE:] for c in CHARSET]
```

Each candidate is the same "16 bytes ending in position `len(known)`" window, but built from `known + guess` instead of the real secret. Batch-encrypt all candidates, compare each to `target`. The matching `c` is `secret[len(known)]`.

**Sanity check (L = len(known)):**

| L | offset | b_idx | reference window | last byte |
|---|---|---|---|---|
| 0 | 1 | 0 | `A*15 \|\| secret[0]` | `secret[0]` |
| 14 | 15 | 0 | `A*1 \|\| secret[0:15]` | `secret[14]` |
| 15 | 0 | 1 | `secret[0:16]` (block 1 of `A*16\|\|secret`) | `secret[15]` |
| 16 | 1 | 1 | `secret[1:17]` (block 1 of `A*15\|\|secret`) | `secret[16]` |

The `offset` cycles 0–15 with period 16; `b_idx` increments each time it wraps. That's why a fixed set of 16 precomputed ciphertexts is enough for a secret of *any* length.

---

## Implementation

```python
import requests
import time

BASE = "https://aes.cryptohack.org/ecb_oracle/encrypt"
BLOCK_SIZE = 16
session = requests.Session()

# 56 blocks * 16 bytes * 2 hex chars = 1792 chars per URL — safe for most servers
MAX_BLOCKS_PER_REQUEST = 56

def encrypt(data: bytes) -> bytes:
    for attempt in range(5):
        try:
            r = session.get(f"{BASE}/{data.hex()}/", timeout=10)
            r.raise_for_status()
            return bytes.fromhex(r.json()["ciphertext"])
        except Exception:
            if attempt == 4:
                raise
            time.sleep(1.5 * (attempt + 1))


def encrypt_blocks(blocks):
    """Batch-encrypt many 16-byte blocks, yielding one ciphertext block at a time.

    ECB encrypts each block independently, so concatenating N candidate blocks
    into one request gives back N independent ciphertexts — no interaction between them.
    Generator so the caller can early-exit as soon as a match is found,
    skipping later request chunks entirely.
    """
    data = b"".join(blocks)
    for chunk_start in range(0, len(data), MAX_BLOCKS_PER_REQUEST * BLOCK_SIZE):
        chunk = data[chunk_start:chunk_start + MAX_BLOCKS_PER_REQUEST * BLOCK_SIZE]
        ct = encrypt(chunk)[:len(chunk)]  # strip the trailing encrypted-SECRET bytes
        for block_start in range(0, len(ct), BLOCK_SIZE):
            yield ct[block_start:block_start + BLOCK_SIZE]


# Common flag characters first → early-exit fires sooner on average
CHARSET = list(b"etoanihsrdlucgwyfmpbkvjxqz{}_0123456789ETOANIHSRDLUCGWYFMPBKVJXQZ")
for i in range(256):
    if i not in CHARSET:
        CHARSET.append(i)

known = bytearray(b"crypto{")

# Pre-compute reference ciphertext at all 16 possible filler offsets — 16 requests, done once.
# targets[i] = AES-ECB( A*(BLOCK_SIZE-i) || secret )
targets = [encrypt(b"A" * (BLOCK_SIZE - i)) for i in range(BLOCK_SIZE)]

while True:
    # Which precomputed ciphertext (offset) and which block within it (b_idx)
    # holds the reference for the next unknown byte. The "+1" places the
    # target byte at the *last* position of its block.
    b_idx, offset = divmod(len(known) + 1, BLOCK_SIZE)
    target = targets[offset][b_idx * BLOCK_SIZE:(b_idx + 1) * BLOCK_SIZE]

    # Each candidate: slide a 16-byte window over (A*16 + known + guess).
    # Encrypts to `target` iff guess == secret[len(known)].
    candidates = [
        (b"A" * BLOCK_SIZE + bytes(known) + bytes([c]))[-BLOCK_SIZE:]
        for c in CHARSET
    ]

    found = None
    for c, ct_block in zip(CHARSET, encrypt_blocks(candidates)):
        if ct_block == target:
            found = c
            break

    if found is None:
        break

    known.append(found)
    print(f"\r{bytes(known)}", end="", flush=True)

    if known.endswith(b"}"):
        break

print()
print("FLAG:", bytes(known).decode())
```

> `CHARSET` here covers the full 0–255 range (common chars first, then the rest), unlike the old printable-only charset. That means a PKCS#7 padding byte *will* match something — so the loop relies on `known.endswith(b"}")` to stop, not on "no match found".

> `encrypt_blocks` chunks at `MAX_BLOCKS_PER_REQUEST` to stay under URL length limits. With 256 candidates (16 bytes each) that's ≥2 chunks worst case, but frequency-ordering + early-exit usually resolves within the first chunk.

---

## Quick Reference

| Approach | Setup requests | Requests per byte (typical) |
|---|---|---|
| Naive, 1 guess/request, all 256 bytes | 0 | ~256 |
| Old note: per-byte reference + batched printable guesses | 0 | ~2 |
| This version: precomputed reference table + batched full-byte guesses | 16 (one-time) | ~1 |

---

**See also:** [Symmetric Crypto - AES Modes & Weak Key Generation](./Symmetric%20Crypto%20-%20AES%20Modes%20%26%20Weak%20Key%20Generation.md) · [Python - Toolkit](./Python%20-%20Toolkit.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
