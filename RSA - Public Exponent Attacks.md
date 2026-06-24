---
tags: [cryptography, rsa, cryptohack]
---

# RSA - Public Exponent Attacks

When e is too small and the plaintext is also small, modular reduction may never kick in — leaving the ciphertext trivially invertible without factoring N or knowing d.

---

## The Core Mechanism

RSA encrypts as `c = mᵉ mod N`. The mod N only does something if `mᵉ ≥ N`. If `mᵉ < N`, then:


```
c = m^e
```


No modular structure — just integer exponentiation. Invert by taking the e-th root over the integers.

---

## e = 1 (Trivial)

`c = m¹ mod N = m mod N`. Since m < N for any valid plaintext, `c = m` exactly.

```python
from Crypto.Util.number import long_to_bytes

ct = 44981230718212183604274785925793145442655465025264554046028251311164494127485
print(long_to_bytes(ct))   # ct is pt directly
```

No computation needed — the "encryption" did nothing.

---

## e = 3, Small Plaintext (Cube Root Attack)

If m is small enough that `m³ < N`, then `c = m³` with no modular reduction.

**Check:** compare digit counts — if ct is much smaller than N, the reduction didn't fire.

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

ct = 243251053617903760309941844835411292373350655973075480264001352919865180151222189820473358411037759381328642957324889519192337152355302808400638052620580409813222660643570085177957

pt, exact = gmpy2.iroot(ct, 3)   # exact integer cube root — no floating point
assert exact                       # True confirms ct is a perfect cube
print(long_to_bytes(pt))
```

> Never use `math.cbrt` or `round(ct**(1/3))` on crypto-scale integers. Floating point has 53 bits of precision — your ct is ~190 bits. Use `gmpy2.iroot(n, k)` for exact integer nth roots of any size.

**If `exact` is False:** `m³ ≥ N` — modular reduction did kick in. Cube root attack fails. Need Håstad's broadcast attack (same m encrypted under 3 different public keys with e=3 → recover m via CRT).

---

## Why Small e Is Dangerous

| e | Attack condition | Attack |
|---|-----------------|--------|
| 1 | always | ct = pt directly |
| 3 | m³ < N | integer cube root |
| 3 | same m, 3 different keys | Håstad broadcast (CRT) |
| any small e | m small relative to N | e-th root over integers |

The fix is always the same: pad the message before encryption (OAEP padding). Padding ensures m is large and randomised — `mᵉ` always wraps around mod N regardless of e.

---

**See also:** [RSA - Fundamentals](./RSA%20-%20Fundamentals.md) · [RSA - Primes & Factoring Attacks](./RSA%20-%20Primes%20%26%20Factoring%20Attacks.md) · [Number Theory - Chinese Remainder Theorem](./Number%20Theory%20-%20Chinese%20Remainder%20Theorem.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
