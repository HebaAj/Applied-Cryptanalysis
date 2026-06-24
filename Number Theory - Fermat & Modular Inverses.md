---
tags: [cryptography, number-theory, cryptohack]
---

# Number Theory - Fermat & Modular Inverses

> Fermat's little theorem and how it gives us multiplicative inverses in modular arithmetic.

---

## Fermat's Little Theorem

If `p` is prime and `a` is not divisible by `p`:
```
a^(p-1) ≡ 1 mod p
```

More general form (works for any integer `a`):
```
a^p ≡ a mod p
```

This is the backbone of almost everything in modular arithmetic — it tells us that exponentiation is periodic with period `p-1`.

---

## Multiplicative Inverse

For every element `g` in `Fp`, there exists a unique `d` such that:
```
g · d ≡ 1 mod p
```

`d` is the **multiplicative inverse** of `g`, written `g⁻¹`.

**How to find it using Fermat:**

From `g^(p-1) ≡ 1`, we can rewrite as:
```
g · g^(p-2) ≡ 1 mod p
```

So:
```
g⁻¹ = g^(p-2) mod p
```

```python
def mod_inverse(g, p):
    return pow(g, p - 2, p)
```

> This only works when `p` is prime. For non-prime moduli, use the Extended Euclidean Algorithm instead — see [Number Theory - GCD & Modular Arithmetic](./Number%20Theory%20-%20GCD%20%26%20Modular%20Arithmetic.md).

---

**See also:** [Number Theory - GCD & Modular Arithmetic](./Number%20Theory%20-%20GCD%20%26%20Modular%20Arithmetic.md) · [Number Theory - Quadratic Residues](./Number%20Theory%20-%20Quadratic%20Residues.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
