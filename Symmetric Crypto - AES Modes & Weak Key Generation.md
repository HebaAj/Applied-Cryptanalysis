---
tags: [cryptography, symmetric-crypto, cryptohack, aes]
---

# Symmetric Crypto - AES Modes & Weak Key Generation

Modes of operation define how a block cipher handles messages longer than one block — real-world AES failures live here, not in AES itself. ECB's determinism and weak key derivation are the two most common root causes.

---

## Modes of Operation

A block cipher (AES) only defines how to transform *one* fixed-size block. A **mode of operation** defines how to chain/arrange many blocks to encrypt an arbitrary-length message. Security failures in "AES-based" systems are almost always a mode/protocol problem, not a break of AES's internals.

---

## ECB (Electronic Codebook)

Splits plaintext into 16-byte blocks, encrypts **each block independently** with the same key. No IV, no chaining between blocks.

**The defining property**: AES is deterministic — `Encrypt(block, KEY)` always produces the same output for the same `block` and `KEY`. In ECB, this means:

- Identical plaintext blocks → identical ciphertext blocks (leaks structure even without any oracle).
- `Decrypt(Encrypt(x, KEY), KEY) == x` always, for any `x`, under the same `KEY`.

---

## Decrypt-Oracle Vulnerability

If a service exposes an unrestricted `decrypt(ciphertext)` endpoint using the **same KEY** that encrypted a secret (e.g. a flag), the decrypt endpoint completely undoes the encryption:

```
ciphertext = Encrypt(FLAG, KEY)       # from an /encrypt_flag/ endpoint
plaintext  = Decrypt(ciphertext, KEY) # via the decrypt endpoint
plaintext == FLAG
```

> The cipher isn't broken — the *protocol* is. Giving decrypt access under the same key as the thing being protected is equivalent to handing over the plaintext directly, regardless of how secure AES itself is.

When no decrypt endpoint exists but the attacker controls a prefix prepended to the secret before encryption, ECB's block-independence enables a different attack — see [Symmetric Crypto - ECB Byte-at-a-Time Attack](./Symmetric%20Crypto%20-%20ECB%20Byte-at-a-Time%20Attack.md).

---

## Key Generation — CSPRNG vs Derived Keys

Symmetric keys must be random bytes from a **cryptographically-secure PRNG (CSPRNG)** — not passwords, words, or other predictable/low-entropy data, even after hashing.

```python
KEY = hashlib.md5(keyword.encode()).digest()   # keyword from a dictionary wordlist
```

`md5(keyword)` *looks* like 16 random bytes — but the actual entropy is bounded by the wordlist size (a few hundred thousand words), not 2^128. An attacker who knows the derivation scheme just hashes every candidate word and checks which key decrypts correctly — a dictionary attack, not a cryptanalytic break of MD5 or AES.

```python
for word in words:
    key = hashlib.md5(word.encode()).digest()
    if AES.new(key, AES.MODE_ECB).decrypt(ciphertext).startswith(b"crypto{"):
        # found it
```

> "Looks like random bytes" ≠ "is random" — always check *how* a key was generated, not just its format.

---

**See also:** [Symmetric Crypto - ECB Byte-at-a-Time Attack](./Symmetric%20Crypto%20-%20ECB%20Byte-at-a-Time%20Attack.md) · [Symmetric Crypto - AES Structure & Key Schedule](./Symmetric%20Crypto%20-%20AES%20Structure%20%26%20Key%20Schedule.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
