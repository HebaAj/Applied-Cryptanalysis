---
tags: [cryptography, rsa, cryptohack]
---

# RSA - Fundamentals

RSA is an asymmetric encryption scheme whose security rests on the hardness of factoring a large composite modulus N = p·q.

---

## The Trapdoor

RSA encryption is modular exponentiation:


```
c = m^e \mod N
```


Easy to compute forward. Hard to invert without knowing the private key d — because inverting requires knowing φ(N), which requires factoring N.

---

## Key Generation

```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long

p = getPrime(1024)
q = getPrime(1024)
N = p * q

phi = (p - 1) * (q - 1)   # Euler's totient — only computable if you know p, q

e = 65537                  # public exponent — standard choice (see below)
d = pow(e, -1, phi)        # private key: modular inverse of e mod phi(N)
```

> `d` exists only if `gcd(e, φ(N)) = 1`. Key generation loops until this holds — that's why `e = 65537` is preferred (prime, rarely divides φ(N)).

---

## Why e = 65537

65537 = 2¹⁶ + 1 in binary: `1 0000 0000 0000 0001` — only **two 1-bits**.

Repeated squaring costs one operation per bit. Two 1-bits = 16 squarings + 1 multiply. Encryption is cheap.

Why not smaller (e.g. e = 3)?
- If `m` is small and `e = 3`: `m³ < N`, so `c = m³` with no modular reduction — integer cube root recovers m directly.
- Broadcast attacks (Håstad): same m encrypted to 3 parties under e=3 → CRT recovers m.

65537 is large enough to avoid these, small enough to keep encryption fast.

---

## Euler's Theorem & Why RSA Works

φ(N) counts integers in [1, N) coprime to N. For N = p·q:


```
φ(N) = (p-1)(q-1)
```


Euler's theorem: if gcd(a, N) = 1,


```
a^{φ(N)} ≡ 1 mod N
```


d is chosen so that `e·d ≡ 1 mod φ(N)`, meaning `e·d = 1 + k·φ(N)` for some k. Then:


```
m^{ed} = m^{1 + kφ(N)} = m · (m^{φ(N)})^k ≡ m · 1^k ≡ m mod N
```


Decryption undoes encryption exactly because ed collapses to 1 mod φ(N).

---

## Encrypt / Decrypt

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes

pt = bytes_to_long(b"message")
ct = pow(pt, e, N)          # encrypt with public key
pt = pow(ct, d, N)          # decrypt with private key
print(long_to_bytes(pt))
```

> pt must be < N, otherwise modular reduction loses information and decryption fails.

---

## RSA Signatures

Sign with **private** key, verify with **public** key — the reverse of encryption.

```python
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Sign
h = bytes_to_long(hashlib.sha256(message).digest())   # hash as integer
S = pow(h, d, N)                                       # sign with private key

# Verify
h_check = pow(S, e, N)                                 # recover hash with public key
assert h_check == bytes_to_long(hashlib.sha256(message).digest())
```

> In real systems, use separate key pairs for encryption and signing.

---

## Quick Reference

| Symbol | Role | Formula |
|--------|------|---------|
| N | modulus | p·q |
| e | public exponent | 65537 (standard) |
| d | private key | e⁻¹ mod φ(N) |
| φ(N) | Euler's totient | (p−1)(q−1) |
| c | ciphertext | mᵉ mod N |
| m | plaintext | cᵈ mod N |

---

**See also:** [RSA - Primes & Factoring Attacks](./RSA%20-%20Primes%20%26%20Factoring%20Attacks.md) · [RSA - Public Exponent Attacks](./RSA%20-%20Public%20Exponent%20Attacks.md) · [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
