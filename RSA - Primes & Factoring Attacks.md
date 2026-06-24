---
tags: [cryptography, rsa, cryptohack]
---

# RSA - Primes & Factoring Attacks

Factoring N = p·q gives φ(N) = (p−1)(q−1), which gives d — so factoring breaks RSA entirely. Different factoring algorithms exploit different mistakes in prime generation.

---

## Why Exactly Two Large Primes

**One prime:** N = p → φ(N) = p−1 is public. No trapdoor.

**Many primes:** N = p·q·r·... → smaller individual factors, easier to find one via ECM or trial division. Also φ(N) computation leaks more structure.

**Special case N = p²:** `isqrt(N) = p` directly. Instant break.

The requirements for N:
- Exactly **two** prime factors
- Both **~1024 bits** (so N is ~2048 bits)
- Chosen **independently** with a CSPRNG
- p−1 and q−1 must each have a **large prime factor** (defeats Pollard's p−1)
- p and q must be **far apart** (defeats Fermat)

---

## Fermat Factorisation

**When it works:** p and q are close together (|p − q| is small).

**Why:** If p ≈ q, then N ≈ p², so √N ≈ p. Search around √N for a, b where N = a² − b² = (a+b)(a−b).

```python
from math import isqrt

def fermat_factor(N):
    a = isqrt(N) + 1
    while True:
        b2 = a*a - N
        b = isqrt(b2)
        if b*b == b2:           # b² is a perfect square → found split
            return a - b, a + b
        a += 1
```

**Example:** N = 8051, √8051 ≈ 89.7, start a = 90.
- b² = 8100 − 8051 = 49, b = 7 ✓
- p = 83, q = 97

> If no split found quickly, primes are far apart — Fermat won't work.

---

## Pollard's p−1

**When it works:** p−1 is **smooth** (has only small prime factors).

**Why:** By Fermat, `a^(p−1) ≡ 1 mod p`. If p−1 is smooth, construct M = product of small prime powers such that (p−1) | M. Then `a^M ≡ 1 mod p`, so `gcd(a^M − 1, N)` leaks p.

```python
from math import gcd

def pollard_p1(N, B=1000):
    a = 2
    for p in primes_up_to(B):
        pk = p
        while pk < B:
            a = pow(a, p, N)
            pk *= p
    return gcd(a - 1, N)
```

**Defence:** choose p such that p−1 = 2·q where q is also prime (safe prime). Then p−1 has one huge factor — Pollard needs B ≥ q to work, which is infeasible.

---

## ECM (Elliptic Curve Method)

**When it works:** N has at least one **small factor** (≤ ~80 bits / 25 decimal digits).

**Why Pollard's p−1 fails for large factors:** you only get one group (integers mod p). If p−1 isn't smooth, you're stuck. ECM fixes this by working on a randomly chosen elliptic curve mod N — each curve gives a different group with a different order. Some of those orders will be smooth even when p−1 isn't.

**Core idea:**
1. Pick random elliptic curve E and point P on it (build curve around the point: pick x, y, a randomly, set b = y² − x³ − ax mod N)
2. Compute Q = k·P using scalar multiplication mod N
3. Point addition requires computing `λ = (y₂−y₁)·(x₂−x₁)⁻¹ mod N` — the denominator `(x₂−x₁)` needs a modular inverse via gcd
4. If gcd(denominator, N) ≠ 1 and ≠ N → factor found

**Why the gcd leaks a factor:** arithmetic mod N secretly behaves like arithmetic mod p and mod q simultaneously (CRT). If the curve order mod p divides k, the point hits infinity mod p → denominator ≡ 0 mod p → gcd catches it.

**For many small factors:** ECM peels them off one at a time. Use SageMath's built-in ECM — significantly faster than pure-Python alternatives.

```python
# In SageMath (sagecell.sagemath.org)
from sage.interfaces.ecm import ECM

ecm = ECM()
factors = ecm.factor(N)
print(factors)
```

> For large N with 30+ small factors, use SageMath online — `primefac` on Windows has multiprocessing issues and is slower.

---

## Computing φ(N) from Many Factors

For N = p₁·p₂·...·pₖ (all distinct):


```
φ(N) = (p_1-1)(p_2-1)·s(p_k-1)
```


```python
from math import prod

factors = list(primefac(N))           # or ecm.factor(N) in SageMath
phi = prod(p - 1 for p in factors)
d = pow(e, -1, phi)
m = pow(ct, d, N)
```

> If factors has repeats (N = p²·q), φ(N) = p(p−1)(q−1) — not (p−1)²(q−1).

---

## Quick Reference

| Attack | Exploits | Works when |
|--------|----------|------------|
| Fermat | p, q close | \|p−q\| is small |
| Pollard's p−1 | p−1 smooth | p−1 has only small prime factors |
| ECM | small individual factors | any factor ≤ ~80 bits |
| Trial division | tiny factors | factor < ~10⁶ |
| GNFS | general | best known for large N; 512-bit RSA broken, 2048-bit standing |

---

**See also:** [RSA - Fundamentals](./RSA%20-%20Fundamentals.md) · [RSA - Public Exponent Attacks](./RSA%20-%20Public%20Exponent%20Attacks.md) · [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
