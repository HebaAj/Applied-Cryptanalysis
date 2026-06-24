---
tags: [cryptography, number-theory, cryptohack]
---

# Number Theory - GCD & Modular Arithmetic

> Foundational number theory concepts — GCD, coprimality, modular congruence, and finite fields.

---

## Greatest Common Divisor (GCD)

The **GCD** of two positive integers is the largest integer that divides both of them.

**Coprime integers:** if `gcd(a, b) = 1` then `a` and `b` are coprime — they share no common factor.

Shortcuts to know they're coprime:
- `a` is prime and `b < a` → coprime
- both `a` and `b` are prime → coprime

---

## Euclidean Algorithm

Finding GCD without factoring — just repeated division.

```
a = q · b + r
```
- if `r = 0` → `b` is the GCD
- if `r ≠ 0` → replace `a` with `b`, `b` with `r`, repeat
- last non-zero `r` is the GCD

```python
def gcd(a, b):
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a
```

---

## Extended Euclidean Algorithm

Finds integers `u, v` such that:
```
a·u + b·v = gcd(a, b)
```

Useful for finding modular inverses (if `gcd(a,m) = 1`, then `u` is the inverse of `a` mod `m`).

```python
# tracks: remainder, x-coefficient, y-coefficient
# r1 = a, x1 = 1, y1 = 0
# r2 = b, x2 = 0, y2 = 1
# q  = r1 // r2
# r3 = r1 - q·r2,  x3 = x1 - q·x2,  y3 = y1 - q·y2
# when r = 0 → previous row has gcd, x, y

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x
```

---

## Modular Congruence

Two integers are **congruent modulo m** if they have the same remainder when divided by `m`:
```
a ≡ b mod m
```

Equivalently: `m` divides `(a - b)`.

Special case: if `m | a` then `a ≡ 0 mod m`.

---

## Finite Fields (Fp)

`Fp` is the set `{0, 1, ..., p-1}` where `p` is prime.

Under both addition and multiplication, **every element has an inverse**:
- Additive inverse: `a + b⁺ ≡ 0 mod p`
- Multiplicative inverse: `a · b* ≡ 1 mod p`

This is what makes `Fp` a *field* — you can add, subtract, multiply, and divide freely without leaving the set.

> For multiplication, the inverse only exists when `gcd(a, p) = 1` — which is always true for any `a` in `{1, ..., p-1}` since `p` is prime.

---

**See also:** [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) · [Number Theory - Quadratic Residues](./Number%20Theory%20-%20Quadratic%20Residues.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
