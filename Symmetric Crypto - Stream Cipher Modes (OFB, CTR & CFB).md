---
tags: [cryptography, symmetric-crypto, cryptohack, aes]
---

# Symmetric Crypto - Stream Cipher Modes (OFB, CTR & CFB)

OFB, CTR, and CFB all turn AES into a stream cipher by generating a keystream `O_i` via `E_k` and XOR-ing it with the plaintext — decryption recomputes the same `O_i` and never calls `D_k`. Both attacks below break a *keystream-reuse/predictability* failure, not AES itself.

---

## Shared Idea — Block Cipher as Keystream Generator


```
C_i = P_i ⊕ O_i      P_i = C_i ⊕ O_i
```


`O_i` is produced by feeding *something* through `E_k`. What that "something" is — and whether it depends on the data — is the only difference between the three modes below.

```
plaintext  →  XOR  →  ciphertext
              ↑
            O_i = E_k(something_i)
```

Because it's pure XOR:
- No padding — works on arbitrary-length messages, last block just truncates.
- Encrypt and decrypt are the *same operation* (XOR is self-inverse) — both only ever call `E_k`.

> Security depends entirely on `O_i` never repeating under the same key. If `O_a == O_b` for two different messages, `C_a ⊕ C_b = P_a ⊕ P_b` — the keystream cancels and you're left with a many-time-pad, crackable via known-plaintext/crib-dragging.

---

## OFB (Output Feedback)

Keystream chains into itself:


```
O_1 = E_k(IV),    O_i = E_k(O_{i-1})
```


```
IV → E_k → O1 → E_k → O2 → E_k → O3 → ...
      |          |          |
   ⊕ P1=C1    ⊕ P2=C2    ⊕ P3=C3
```

Sequential by construction — `O_i` depends on `O_{i-1}`, so you can't parallelize or jump to block `i` without computing every block before it.

### Attack — Symmetry (IV reuse → encrypt oracle = decrypt oracle)

`/encrypt_flag/` produces `iv || OFB(FLAG, key, iv)` with a **fresh random IV each time**, but `/encrypt/<pt>/<iv>/` lets the attacker pick *any* IV — including the one the flag was encrypted under.

Re-encrypting under the same `(key, IV)` regenerates the identical `O_1, O_2, ...` chain. Feeding the flag's ciphertext back through `/encrypt/` with that same IV computes:


```
Enc(C, IV) = C ⊕ O = (P ⊕ O) ⊕ O = P
```


```python
import requests

BASE_URL = "https://aes.cryptohack.org/symmetry"
BLOCK_SIZE = 16

def encrypt(plaintext: bytes, iv: bytes) -> bytes:
    r = requests.get(f"{BASE_URL}/encrypt/{plaintext.hex()}/{iv.hex()}/")
    return bytes.fromhex(r.json()["ciphertext"])

def solve() -> str:
    data = bytes.fromhex(requests.get(f"{BASE_URL}/encrypt_flag/").json()["ciphertext"])
    iv, flag_ct = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    # same (key, IV) -> same keystream -> XOR-ing it back in cancels the first XOR
    return encrypt(flag_ct, iv).decode()
```

> The vulnerability is purely in the *protocol* (an encrypt endpoint that accepts attacker-chosen IVs reused from a real ciphertext) — OFB itself is fine if IVs are never reused.

---

## CTR (Counter Mode)

Each keystream block is independent — `O_i` comes from encrypting a per-block counter value, not from chaining:


```
O_i = E_k(counter_i),      counter_i \text{ all distinct}
```


```
counter_1 → E_k → O1 ⊕ P1 = C1
counter_2 → E_k → O2 ⊕ P2 = C2
counter_3 → E_k → O3 ⊕ P3 = C3
```

No chaining → fully parallelizable and supports random access (decrypt block 500 without touching 1–499). Only requirement: every `(key, counter_i)` pair must be unique.

### ECB-as-primitive → CTR

`AES.new(KEY, AES.MODE_ECB)` is just a raw single-block oracle: feed 16 bytes, get back `E_k(those 16 bytes)`, no state. That **is** the `E_k(·)` in the CTR formula — CTR mode is "ECB, plus a counter-generation routine, plus XOR with plaintext":

```python
keystream = cipher.encrypt(ctr.increment())   # E_k(counter_i) via the ECB primitive
xored = [a ^ b for a, b in zip(block, keystream)]
```

### Attack — Bean Counter (broken counter → repeating keystream)

`StepUpCounter` is constructed with `step_up=False`, so `self.stup = False`. In `increment()`'s else-branch:

```python
self.newIV = hex(int(self.value, 16) - self.stup)
```

`False == 0` in Python — so this is `value - 0 = value`. **The counter never changes.** Every `O_i = E_k(same constant)` — CTR degenerates into the entire file XORed with one repeating 16-byte keystream block. This is now exactly the OFB-IV-reuse failure mode (many-time-pad), except the "many times" is every block of a single file.

Fix: recover that one keystream block via a known-plaintext crib — every PNG starts with a fixed 16-byte header — then **repeating-key XOR** it against the whole file.

```python
from urllib.request import urlopen
from itertools import cycle
import json

BASE_URL = "https://aes.cryptohack.org/bean_counter"
PNG_HEADER = bytes.fromhex("89504e470d0a1a0a0000000d49484452")  # known first 16 bytes of any PNG

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def solve():
    ciphertext = bytes.fromhex(json.loads(urlopen(f"{BASE_URL}/encrypt/").read())["encrypted"])
    # crib: explicit slice — first ciphertext block ⊕ known plaintext block = the (constant) keystream block
    keystream = xor(ciphertext[:16], PNG_HEADER)
    # whole file is one repeating-key XOR — cycle() makes that relationship explicit
    plaintext = xor(ciphertext, cycle(keystream))
    with open("bean_flag.png", "wb") as f:
        f.write(plaintext)
```

> `xor(ciphertext[:16], PNG_HEADER)` slices explicitly rather than relying on `zip`'s silent truncation to "happen" to produce 16 bytes — same result, but the length is visible at a glance.

> Security of CTR lives entirely in the counter-generation routine — not in AES. Always trace through a custom counter implementation by hand for a few iterations before trusting it.

---

## CFB (Cipher Feedback) — for completeness

Feeds back the *ciphertext* (not the keystream's own output, unlike OFB):


```
O_i = E_k(C_{i-1}),      C_0 = IV
```


```
C0=IV → E_k → O1 ⊕ P1 = C1
C1    → E_k → O2 ⊕ P2 = C2
C2    → E_k → O3 ⊕ P3 = C3
```

Decryption: `P_i = C_i ⊕ E_k(C_{i-1})` — the decryptor already has `C_{i-1}` from the received ciphertext stream, so this still only calls `E_k`, never `D_k`. Like OFB, it's sequential (can't parallelize encryption — each `C_i` depends on `C_{i-1}`), but decryption *can* be parallelized since all `C_{i-1}` values are already known upfront.

---

## Quick Reference

| Mode | Keystream `O_i` | Sequential? | Parallel decrypt? | Calls `D_k`? |
|------|-----------------|-------------|--------------------|--------------|
| OFB | `E_k(O_{i-1})`, `O_0 := IV` | Yes (both directions) | No | No |
| CTR | `E_k(counter_i)` | No | Yes | No |
| CFB | `E_k(C_{i-1})`, `C_0 := IV` | Encrypt only | Yes | No |

| Attack | Root cause | Exploit |
|---|---|---|
| Symmetry (OFB) | Encrypt endpoint accepts attacker-chosen IV, reused from a real ciphertext | `Enc(C, IV) == Dec(C, IV) == P` when `(key, IV)` repeats |
| Bean Counter (CTR) | `counter - False` bug → counter never increments | Constant keystream block → recover via PNG-header crib, XOR every block |

---

**See also:** [Symmetric Crypto - AES Modes & Weak Key Generation](./Symmetric%20Crypto%20-%20AES%20Modes%20%26%20Weak%20Key%20Generation.md) · [Symmetric Crypto - CBC Mode & Oracle Attacks](./Symmetric%20Crypto%20-%20CBC%20Mode%20%26%20Oracle%20Attacks.md) · [Python - Toolkit](./Python%20-%20Toolkit.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
