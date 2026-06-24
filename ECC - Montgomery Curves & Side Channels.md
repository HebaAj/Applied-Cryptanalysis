---
tags: [cryptography, number-theory, cryptohack]
---

# ECC - Montgomery Curves & Side Channels

Montgomery curve form and the Montgomery Ladder — designed for constant-time scalar multiplication to resist side-channel attacks. X25519 (used in TLS/AdaptiveQKE) is the standard deployment.

---

## Montgomery Curve Form

**By² = x³ + Ax² + x**

Different from Weierstrass (Y² = X³ + aX + b) — the Ax² term enables x-only arithmetic, which is what makes the Montgomery Ladder efficient.

Curve25519: y² = x³ + 486662x² + x mod 2²⁵⁵−19 (A=486662, B=1).

---

## Affine Addition & Doubling

```python
A25 = 486662
B25 = 1
p25 = 2**255 - 19
O = None

def m_double(P):
    x1, y1 = P
    # numerator: 3x² + 2Ax + 1 — the 2*A*x term is specific to Montgomery form
    a = (3*x1**2 + 2*A25*x1 + 1) * pow(2*B25*y1, -1, p25) % p25
    x3 = (B25*a**2 - A25 - 2*x1) % p25
    return x3, (a*(x1 - x3) - y1) % p25

def m_add(P, Q):
    if P is O: return Q
    if Q is O: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p25 == 0: return O
    if P == Q: return m_double(P)
    a = (y2 - y1) * pow(x2 - x1, -1, p25) % p25
    x3 = (B25*a**2 - A25 - x1 - x2) % p25
    return x3, (a*(x1 - x3) - y1) % p25
```

> The doubling formula has `2*A*x₁` in the numerator — not `2*x₁`. Dropping the A is a silent bug that may work for specific test points but fails generally.

---

## Montgomery Ladder

Standard scalar multiplication for Montgomery curves. Key property: **both branches do exactly one doubling and one addition** — operation count doesn't leak the secret scalar.

```
Maintains: R0, R1 where R1 = R0 + P always
For each bit of k (MSB-1 down to 0):
    if bit = 0: R0 = [2]R0,   R1 = R0 + R1
    if bit = 1: R0 = R0 + R1, R1 = [2]R1
Return R0
```

Compare to double-and-add: bit=0 does only a double, bit=1 does double + add. An attacker measuring power/timing can read off the secret bit by bit.

---

## Making It Truly Constant-Time

The basic ladder still has two leaks:

**Leak 1 — iteration count reveals bit length of k:** if k is 200 bits vs 256 bits, the loop runs differently. Fix: always iterate a **fixed number of bits** (e.g. 255 for Curve25519), padding with leading zeros.

**Leak 2 — if/else branches can leak via CPU side channels:** branch prediction, cache behavior. Fix: replace the `if` with **cswap** (conditional swap) — a branchless operation:

```
for each bit ki (fixed iteration count):
    cswap(ki, R0, R1)      # swap if bit=1, no-op if 0 — branchless
    R1 = R0 + R1
    R0 = [2]R0
    cswap(ki, R0, R1)      # swap back
```

cswap is implemented via bitwise ops: `R0 XOR (mask AND (R0 XOR R1))` where mask is all-ones or all-zeros depending on the bit. CPU executes identical instructions either way.

X25519 (RFC 7748) mandates cswap + fixed 255-bit iteration count.

---

## Side-Channel Attacks

**Timing attacks on ECDSA:** scalar multiplication timing leaks bits of the nonce k. Enough signatures + lattice reduction → full private key recovery.

**LadderLeak:** timing attack against the Montgomery Ladder itself. Some implementations start the loop from the first *set* bit rather than a fixed position — leaks a fraction of a bit about the scalar per signature. Individually negligible, but:
- Collect many ECDSA signatures
- Each leaks a tiny bit about its nonce
- Lattice reduction combines the partial leaks → private key

Fixed by always iterating from a fixed bit position. Ironic because the Montgomery Ladder was designed to be constant-time — the attack exploits an implementation shortcut that undermines the design.

---

## Quick Reference

| Concept | Detail |
|---|---|
| Montgomery form | By² = x³ + Ax² + x |
| Curve25519 | A=486662, B=1, p=2²⁵⁵−19 |
| Montgomery Ladder | constant-op scalar mult: 1 double + 1 add per bit regardless |
| cswap | branchless swap via bitwise ops — eliminates if/else leak |
| X25519 | ECDH over Curve25519, x-only, cswap + 255 fixed iterations |
| LadderLeak | variable start bit leaks scalar info → lattice → key recovery |

---

**See also:** [ECC - Fundamentals](./ECC%20-%20Fundamentals.md) · [ECC - Weak Curve Attacks](./ECC%20-%20Weak%20Curve%20Attacks.md) · [Diffie-Hellman](./Diffie-Hellman.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
