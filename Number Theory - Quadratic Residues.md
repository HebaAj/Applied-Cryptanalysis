---
tags: [cryptography, number-theory, cryptohack]
---

# Number Theory - Quadratic Residues

> What makes a number a perfect square mod p, and how to check it.

---

## Definition

An integer `x` is a **Quadratic Residue** mod `p` if there exists some `a` such that:
```
a² ≡ x mod p
```

If no such `a` exists → `x` is a **Quadratic Non-Residue**.

Think of it as: does `x` have a square root in `Fp`?

---

## Legendre's Symbol

A formal notation for checking if `a` is a QR mod `p`:
```
(a/p) = a^((p-1)/2) mod p
```

That's it — it's just Euler's criterion with a name and a symbol.

| Result | Meaning |
|--------|---------|
| `(a/p) = 1` | `a` is a quadratic residue (and `a ≢ 0 mod p`) |
| `(a/p) = -1` | `a` is a quadratic non-residue |
| `(a/p) = 0` | `a ≡ 0 mod p` |

```python
def legendre(a, p):
    result = pow(a, (p - 1) // 2, p)
    if result == p - 1:
        return -1       # non-residue
    return result       # 0 or 1
```

> About 50% of elements in Fp are quadratic residues.

---

## Multiplication Property

The Legendre symbol multiplies like signs:

```
QR  × QR  = QR      (+1 × +1 = +1)
QR  × QNR = QNR     (+1 × -1 = -1)
QNR × QNR = QR      (-1 × -1 = +1)
```

Memory trick: replace QR with `+1` and QNR with `-1` — the multiplication rules are identical to sign arithmetic.

This means you can determine the QR status of a product without computing the product itself — just multiply the Legendre symbols.

---

## Why This Matters

Knowing `x` is a QR tells you a square root *exists* — but not what it is. To actually find the square root, you need [Number Theory - Tonelli-Shanks](./Number%20Theory%20-%20Tonelli-Shanks.md).

---

**See also:** [Number Theory - Tonelli-Shanks](./Number%20Theory%20-%20Tonelli-Shanks.md) · [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
