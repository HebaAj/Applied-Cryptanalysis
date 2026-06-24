---
tags: [cryptography, symmetric-crypto, cryptohack, aes]
---

# Symmetric Crypto - CBC Mode & Oracle Attacks

CBC chains blocks via XOR with the previous ciphertext block (IV for block 1), fixing ECB's identical-block leak. Both attacks below exploit the *same* relationship — `P_i = D_k(C_i) ⊕ C_{i-1}` — from opposite directions: one recovers plaintext without the key, the other forges plaintext without the key.

---

## CBC Mode

**Encryption** — `C_0 := IV`, then for each block:


```
C_i = E_k(P_i ⊕ C_{i-1})
```


```
P1 ⊕ IV → E_k → C1
P2 ⊕ C1 → E_k → C2
```

**Decryption** — algebraic inverse, same chain run backwards:


```
P_i = D_k(C_i) ⊕ C_{i-1}
```


```
C1 → D_k → ⊕ IV → P1
C2 → D_k → ⊕ C1 → P2
```

`E_k`/`D_k` are deterministic single-block AES operations — no notion of "mode" baked in. CBC is just `D_k` plus an XOR bookkeeping step around it. That's what makes both attacks below possible: anything that gives you raw `D_k(X)` for chosen `X` gives you a CBC decrypter, *if* you also supply the right `C_{i-1}`.

> IV is sent in the clear alongside the ciphertext — not secret, only needs to be unpredictable *before* encryption (`os.urandom(16)`).

---

## Attack 1 — CBC Decryption via an ECB-Decrypt Oracle (Mode Mixing)

**Setup:** server encrypts with `AES-CBC` but exposes a decrypt route running `AES-ECB` under the *same key*. ECB-decrypt on a blob just applies `D_k` to each 16-byte chunk independently — no XOR, no IV, no chaining. That's exactly the bare `D_k(·)` term in the CBC formula.

Feed the oracle `C1 || C2 || ... || Cn` → get back `D_k(C1) || ... || D_k(Cn)`. Pair each with the *previous* ciphertext block (`C_0 = IV`, given to you in the response) and XOR:

```python
import requests

BASE = "https://aes.cryptohack.org/ecbcbcwtf"
BLOCK_SIZE = 16

def get_flag_blob() -> bytes:
    r = requests.get(f"{BASE}/encrypt_flag/")
    return bytes.fromhex(r.json()["ciphertext"])  # iv || C1 || C2 || ... || Cn

def ecb_decrypt(data: bytes) -> bytes:
    r = requests.get(f"{BASE}/decrypt/{data.hex()}/")
    return bytes.fromhex(r.json()["plaintext"])   # D_k applied block-by-block, no chaining

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

blob = get_flag_blob()
iv, ct = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]   # C1..Cn

dk = ecb_decrypt(ct)                                                  # D_k(C1) || ... || D_k(Cn), one request
dk_blocks = [dk[i:i+BLOCK_SIZE] for i in range(0, len(dk), BLOCK_SIZE)]

prev = [iv] + blocks[:-1]   # C0=IV, C1, ..., C_{n-1} — the XOR partner for each block
plaintext = b"".join(xor(d, p) for d, p in zip(dk_blocks, prev))
```

> The IV from the response *is* `C_0` — no need to recover or guess it. One ECB-decrypt request recovers the entire CBC plaintext.

---

## Attack 2 — CBC Bit-Flipping (Cookie Forgery)

**Setup:** you can't choose plaintext (`get_cookie` takes no input) and don't have the key — but you *can* send back a modified `IV` alongside the unmodified ciphertext to a CBC-decrypt check.

From `P_i = D_k(C_i) ⊕ C_{i-1}`: `D_k(C_i)` is fixed once `C_i` is fixed. Flipping `C_{i-1}` by some `δ` flips `P_i` by the same `δ`:


```
P_i^{new} = D_k(C_i) ⊕ (C_{i-1}⊕\delta) = P_i^{old}⊕\delta
```


So `δ = original ⊕ desired`, applied to `C_{i-1}`, turns `P_i` into whatever you want — byte for byte, no key needed.

**This challenge:** the field to forge (`admin=False` → `admin=True`) sits entirely in block 1, whose "`C_{i-1}`" is the **IV**. Flip the IV, leave the ciphertext untouched:

```python
import requests

BASE = "https://aes.cryptohack.org/flipping_cookie"
BLOCK_SIZE = 16
session = requests.Session()

def get_cookie() -> bytes:
    r = session.get(f"{BASE}/get_cookie/", timeout=10)
    return bytes.fromhex(r.json()["cookie"])  # iv || C1 || C2 || ...

def check_admin(cookie: bytes, iv: bytes) -> dict:
    r = session.get(f"{BASE}/check_admin/{cookie.hex()}/{iv.hex()}/", timeout=10)
    return r.json()

blob = get_cookie()
iv, ct = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]

# Block 1 plaintext is always "admin=False;expi" (fixed format string, first 16 bytes)
original = b"admin=False;expi"
desired  = b"admin=True;;expi"   # split(b";") -> [..., b"admin=True", b"", ...]

new_iv = bytes(iv[i] ^ original[i] ^ desired[i] for i in range(BLOCK_SIZE))
print(check_admin(ct, new_iv))
```

> **Collateral damage rule:** flipping `C_{i-1}` for `i>1` also wrecks `P_{i-1} = D_k(C_{i-1}) ⊕ C_{i-2}` — `D_k` has no "smooth" behavior, one flipped bit scrambles the whole 16-byte output unpredictably. Only safe "for free" when `i=1`: `C_0 = IV` isn't anyone's ciphertext, so there's no `P_0` to corrupt. If the target field spanned block ≥2, the previous block's plaintext would need fixing too (or to not matter).

---

## Quick Reference

| Attack | You control | Oracle gives you | Formula |
|---|---|---|---|
| Mode-mixing decrypt | nothing (no inputs to encrypt route) | `D_k` per block (mislabeled ECB-decrypt) | `P_i = D_k(C_i) ⊕ C_{i-1}`, `C_0=IV` |
| Bit-flipping forgery | `IV` (or `C_{i-1}` for `i>1`) sent to decrypt check | nothing — pure XOR algebra | `P_i^{new} = P_i^{old} ⊕ δ`, `δ = C_{i-1}^{old} ⊕ C_{i-1}^{new}` |

---

**See also:** [Symmetric Crypto - AES Modes & Weak Key Generation](./Symmetric%20Crypto%20-%20AES%20Modes%20%26%20Weak%20Key%20Generation.md) · [Symmetric Crypto - ECB Byte-at-a-Time Attack](./Symmetric%20Crypto%20-%20ECB%20Byte-at-a-Time%20Attack.md) · [Python - Toolkit](./Python%20-%20Toolkit.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
