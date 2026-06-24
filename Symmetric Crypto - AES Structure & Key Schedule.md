---
tags: [cryptography, symmetric-crypto, cryptohack, aes]
---

# Symmetric Crypto - AES Structure & Key Schedule

AES-128: a keyed permutation operating on a 4x4-byte state, built from key expansion + 11 AddRoundKey applications interleaved with 10 rounds of SubBytes/ShiftRows/MixColumns.

---

## Symmetric Ciphers

Same key for encryption and decryption.

- **Block ciphers** (AES): fixed-size blocks, encryption function + key.
- **Stream ciphers**: XOR plaintext with a pseudo-random keystream, byte by byte.

Real-world failures are usually in the **mode of operation**, not the cipher itself.

---

## AES as a Keyed Permutation

A permutation = bijection: every input block maps to exactly one output block, reversibly. The key determines *which* permutation out of all possible ones is used.

> Theoretically "broken" ≠ practically broken. Academics call a cipher broken if an attack exists that's faster than brute force — even if still computationally infeasible (e.g. biclique attack on AES).

**Single-key attack**: attacker has plaintext/ciphertext pairs under one unknown key — the standard threat model.

---

## Confusion, Diffusion, Avalanche

- **Confusion**: relationship between key and ciphertext should look as complex/random as possible. SubBytes provides this (non-linear S-box).
- **Diffusion**: every output bit should depend on many input bits. ShiftRows + MixColumns provide this.
- **Avalanche effect**: ideal diffusion — flipping one plaintext bit flips ~half the ciphertext bits.

Without diffusion, the same byte position would get the same substitution every round — attackable independently per position. Diffusion makes each S-box input a function of multiple bytes, exploding algebraic complexity each round.

---

## Round Structure (AES-128)

1. **KeyExpansion** — derive 11 round keys from the 128-bit key (see below).
2. **Initial AddRoundKey** — XOR state with round key 0.
3. **10 rounds**, each:
   - SubBytes
   - ShiftRows
   - MixColumns *(skipped in round 10)*
   - AddRoundKey

### Why MixColumns is skipped in the final round

MixColumns is **linear**: `MixColumns(state ⊕ key) = MixColumns(state) ⊕ MixColumns(key)`. If round 10 had MixColumns before AddRoundKey, it could be cancelled by redefining the last round key as `MixColumns⁻¹(k10)` — adds zero security, pure wasted computation. Dropping it also makes encryption/decryption more structurally symmetric (decryption runs the same operations in reverse).

---

## Key Schedule (KeyExpansion)

**Why 11 keys for 10 rounds**: AddRoundKey is applied once *before* round 1 (key 0) and once at the *end* of each of the 10 rounds (keys 1–10). 1 + 10 = 11.

44 total 32-bit words (11 × 4). First 4 words = the master key. Each subsequent word:

- **Normal word** (not the start of a new round-group): `w[i] = w[i-1] ^ w[i-4]`
- **Round-starting word** (every 4th word): transform `w[i-1]` first, then XOR with `w[i-4]`:
  1. **RotWord** — rotate the word left by 1 byte
  2. **SubWord** — S-box every byte
  3. XOR the **first byte only** with `Rcon[round]`

```python
word.append(word.pop(0))           # RotWord
word = [s_box[b] for b in word]    # SubWord
word[0] ^= r_con[i]                 # Rcon — only byte 0
word = bytes(a ^ b for a, b in zip(word, key_columns[-iteration_size]))
```

> AES-256 has an extra SubWord-only step at the midpoint of each 8-word group — irrelevant for AES-128.

**Why Rcon exists**: without it, every round's key-derivation formula would be identical — `w[4k] = SubWord(RotWord(w[4k-1])) ^ w[4k-4]` for all rounds k. That periodic symmetry is exploitable (related-key attacks). Rcon injects a different constant per round, breaking the symmetry while keeping the formula structurally the same.

---

## AddRoundKey

```python
def add_round_key(s, k):
    return [[a ^ b for a, b in zip(row_s, row_k)] for row_s, row_k in zip(s, k)]
```

`k` = one full round key matrix (`round_keys[i]`, 4x4). XOR is self-inverse — same function works for encryption and decryption.

> `expand_key` returns `round_keys[0]` as a list of lists, but every other round key as `bytes` objects. Doesn't matter for `add_round_key` — `zip()` and indexing treat `bytes` and `list[int]` identically for reading. Only matters if you try to mutate a round key (bytes are immutable) — never needed here.

---

**See also:** [Symmetric Crypto - AES SubBytes & S-Box](./Symmetric%20Crypto%20-%20AES%20SubBytes%20%26%20S-Box.md) · [Symmetric Crypto - AES ShiftRows & MixColumns](./Symmetric%20Crypto%20-%20AES%20ShiftRows%20%26%20MixColumns.md) · [Symmetric Crypto - AES Decryption (Inverse Cipher)](./Symmetric%20Crypto%20-%20AES%20Decryption%20%28Inverse%20Cipher%29.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
