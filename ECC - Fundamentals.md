---
tags: [cryptography, number-theory, cryptohack]
---

# ECC - Fundamentals

Asymmetric crypto built on point arithmetic over elliptic curves — same trapdoor principle as DH/RSA but far smaller key sizes for equivalent security (256-bit ECC ≈ 3072-bit DH ≈ 128-bit AES).

---

## The Curve

Standard Weierstrass form:

**E: Y² = X³ + aX + b**

Together with a point at infinity O. Valid curves must satisfy **4a³ + 27b² ≠ 0** — this is the discriminant of the cubic. If it equals zero, the cubic has a repeated root → the curve has a self-intersection or cusp (singularity) → tangent line isn't unique → point addition breaks.

Over a finite field 𝔽ₚ:

**E(𝔽ₚ) = { (x,y) : x,y ∈ 𝔽ₚ, y² ≡ x³ + ax + b mod p } ∪ {O}**

No longer a continuous curve — a finite set of points. Group structure still holds.

---

## Point Addition

Given P, Q ∈ E(𝔽ₚ):

**P ≠ Q:** draw line through P and Q, third intersection reflected → λ = (y₂ − y₁) · (x₂ − x₁)⁻¹ mod p

**P = Q:** tangent line at P → λ = (3x₁² + a) · (2y₁)⁻¹ mod p

Then:
- **x₃ = λ² − x₁ − x₂ mod p**
- **y₃ = λ(x₁ − x₃) − y₁ mod p**

Group properties:
- P + O = P (identity)
- P + (−P) = O where **−P = (x, p−y)** — reflection flips y only
- Associative + commutative (abelian group)

```python
p = ...
a = ...
O = None

def point_add(P, Q):
    if P is O: return Q
    if Q is O: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return O   # P + (-P) = O
    lam = ((3*x1**2 + a) * pow(2*y1, -1, p) if P == Q
           else (y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam**2 - x1 - x2) % p
    return x3, (lam*(x1 - x3) - y1) % p
```

> Division is always modular inverse — `pow(x, -1, p)` — never floating point.

---

## Scalar Multiplication

**[n]P** = P added to itself n times. Double-and-add runs in O(log n):

```python
def scalar_mult(n, P):
    Q, R = P, O
    while n > 0:
        if n & 1: R = point_add(R, Q)   # add if bit is set
        Q = point_add(Q, Q)              # double
        n >>= 1
    return R
```

**ECDLP (Elliptic Curve Discrete Logarithm Problem):** given Q and P, find n such that Q = [n]P. Hard for well-chosen curves — this is the trapdoor.

---

## ECDH Key Exchange

Structurally identical to DH — exponentiation becomes scalar mult, 𝔽ₚ* becomes E(𝔽ₚ):

| Step | DH | ECDH |
|---|---|---|
| Public params | prime p, generator g | curve E, prime p, generator G |
| Alice private | a | nA |
| Alice public | gᵃ mod p | [nA]G |
| Shared secret | Bᵃ mod p | x-coord of [nA·nB]G |
| Hardness | DLP | ECDLP |

The shared secret is always just the **x-coordinate** — both ±y give the same x.

---

## Point Compression

y² = f(x) has exactly two solutions: y and p−y. So a public key can be compressed to **x + 1 parity bit** (even/odd of y).

Receiver reconstructs y: compute rhs = x³ + ax + b mod p, take modular square root, pick the root matching the parity bit.

**Square root shortcuts by prime form:**

| p mod | Formula | Notes |
|---|---|---|
| p ≡ 3 mod 4 | `pow(rhs, (p+1)//4, p)` | one-liner |
| p ≡ 5 mod 8 | `pow(rhs, (p+3)//8, p)`, fix with √(−1) if v²≠rhs | Curve25519's case |
| p ≡ 1 mod 8 | Tonelli-Shanks | no shortcut |

```python
# Curve25519 (p ≡ 5 mod 8)
def sqrt25519(u):
    v = pow(u % p, (p + 3) // 8, p)
    if pow(v, 2, p) != u % p:
        v = v * pow(2, (p - 1) // 4, p) % p   # multiply by sqrt(-1)
    return v
```

---

**See also:** [ECC - Montgomery Curves & Side Channels](./ECC%20-%20Montgomery%20Curves%20%26%20Side%20Channels.md) · [ECC - Weak Curve Attacks](./ECC%20-%20Weak%20Curve%20Attacks.md) · [Diffie-Hellman](./Diffie-Hellman.md) · [Number Theory - Quadratic Residues](./Number%20Theory%20-%20Quadratic%20Residues.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
