---
tags: [cryptography, number-theory, cryptohack]
---

# Number Theory - Modular Binomial

One-line summary: exploit structure of `(a·p + b·q)^e mod N` when `e` equals one of N's prime factors, using Frobenius to split and cancel terms.

---

## The Problem Form

Given:
```
c1 = (a1·p + b1·q)^e1  mod N
c2 = (a2·p + b2·q)^e2  mod N
N = p·q
```
All of `a1, a2, b1, b2, e1, e2, c1, c2, N` are known. Goal: recover `p` and `q`.

**The exploit condition: `e1 = p` and `e2 = q`.**
This is not derived — it's given by how the problem is constructed. The attack only works under this condition.

---

## Why (a + b)^e Splits — Frobenius Endomorphism

Normally `(a + b)^e ≠ a^e + b^e`. The binomial theorem gives middle terms that don't vanish.

But when the exponent is a prime `p`, working **mod p**:

```
(a + b)^p = Σ C(p,k) · a^k · b^(p-k)   for k = 0..p
```

Every middle term (0 < k < p) contains `C(p,k)` as a factor. Why does `C(p,k) ≡ 0 mod p`?

```
C(p,k) = p! / (k! · (p-k)!)
```

- Numerator: `p!` contains `p` explicitly as a factor
- Denominator: `k! · (p-k)!)` — since `k < p` and `(p-k) < p`, neither factorial contains `p` (p is prime)
- So the denominator fully cancels into `(p-1)!` part of numerator, leaving `p` with nothing to cancel into
- Therefore `p | C(p,k)` for all `0 < k < p`

Every middle term ≡ 0 mod p. Only first and last survive:

```
(a + b)^p ≡ a^p + b^p  (mod p)
```

> **This only holds mod p (the prime used as exponent), not mod N directly.**

---

## The Attack — Step by Step

**Step 1: Raise to cross-exponents**

Raise `c1` to `e2` and `c2` to `e1` — now both are at exponent `e1·e2`:

```
c1^e2 = (a1·p + b1·q)^(e1·e2)  mod N
c2^e1 = (a2·p + b2·q)^(e1·e2)  mod N
```

**Step 2: Apply Frobenius to split**

Since `e1 = p`, Frobenius applies mod p on `c1`. Since `e2 = q`, it applies mod q on `c2`. After splitting:

```
c1^e2 ≡ (a1·p)^(e1·e2) + (b1·q)^(e1·e2)  mod N
c2^e1 ≡ (a2·p)^(e1·e2) + (b2·q)^(e1·e2)  mod N
```

**Step 3: Normalize — eliminate the a coefficients**

Multiply each equation by the modular inverse of its `a` coefficient raised to `e1·e2`:

```
a1^(-e1·e2) · c1^e2 = p^(e1·e2) + a1^(-e1·e2) · (b1·q)^(e1·e2)  mod N
a2^(-e1·e2) · c2^e1 = p^(e1·e2) + a2^(-e1·e2) · (b2·q)^(e1·e2)  mod N
```

Both equations now have `p^(e1·e2)` as an isolated term.

**Step 4: Subtract — p terms cancel**

```
a2^(-e1·e2) · c2^e1 - a1^(-e1·e2) · c1^e2
= a2^(-e1·e2) · (b2·q)^(e1·e2) - a1^(-e1·e2) · (b1·q)^(e1·e2)  mod N
```

The `p^(e1·e2)` terms are identical → they cancel. What remains is purely a function of `q`.

**Step 5: Extract q via gcd**

The result is a multiple of `q` but not `p`, so:

```
q = gcd(result, N)
p = N // q
```

---

## Implementation

```python
from math import gcd

# pow(a, -k, N) = modular inverse of a^k mod N (Python 3.8+)
# requires gcd(a, N) = 1 — guaranteed by problem construction

result = (
    pow(a2, -e2 * e1, N) * pow(c2, e1, N)
  - pow(a1, -e1 * e2, N) * pow(c1, e2, N)
)

q = gcd(result, N)
p = N // q
```

> `pow(a, -k, N)` uses the extended Euclidean algorithm internally. The negative exponent is not regular arithmetic — Python interprets it as: compute `(a^k mod N)^(-1) mod N`.

> Inverse only exists if `gcd(a, N) = 1`. If it doesn't exist, Python raises `ValueError`.

---

## Quick Reference

| Step                     | Operation                   | Purpose                               |
| ------------------------ | --------------------------- | ------------------------------------- |
| Raise to cross-exponents | `c1^e2`, `c2^e1`            | Equalize exponents to `e1·e2`         |
| Frobenius split          | `(a+b)^p ≡ a^p + b^p mod p` | Separate p and q terms                |
| Multiply by `a^(-e1·e2)` | modular inverse             | Isolate `p^(e1·e2)` in both equations |
| Subtract                 | `eq2 - eq1`                 | Cancel p terms                        |
| gcd with N               | `gcd(result, N)`            | Extract q                             |

---

**See also:** [Number Theory - GCD & Modular Arithmetic](./Number%20Theory%20-%20GCD%20%26%20Modular%20Arithmetic.md) · [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) · [Number Theory - Chinese Remainder Theorem](./Number%20Theory%20-%20Chinese%20Remainder%20Theorem.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
