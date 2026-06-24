---
tags: [cryptography, cryptohack, ecc]
---

# ECC - MOV Attack (Moving Problems)

One-line summary: when a curve's order splits into a smooth part and one large prime factor, Pohlig-Hellman kills the smooth part for free, and the leftover large-prime DLP can be moved off the curve into a finite field's multiplicative group via a pairing — where it's often easier to solve.

---

## Setup

Order of `G` factors as `n = q1 * q2`:
- `q1` — product of small primes → trivial with [Pohlig-Hellman](./ECC%20-%20Weak%20Curve%20Attacks.md)
- `q2` — one large prime → the part that actually needs work

Splitting the discrete log this way is just Pohlig-Hellman again: project `G` and `A` onto each subgroup, solve independently, recombine with CRT.

```python
G1, A1 = (n // q1) * G, (n // q1) * A   # lands in the q1-order subgroup
G2, A2 = (n // q2) * G, (n // q2) * A   # lands in the q2-order subgroup

a1 = G1.discrete_log(A1)   # mod q1 — instant, q1 is smooth
```

The only open question is `a mod q2`.

---

## Two ways to close out q2

**Option A — brute it on the curve.** If `sqrt(q2)` is small enough to be feasible (think `< 10^8`-ish steps), Pollard's rho directly on `E` solves `a2 = log_{G2}(A2)` with `O(sqrt(q2))` time and ~no memory. No pairing required — this is the boring, low-effort path, and it's worth trying first.

**Option B — MOV attack.** If `sqrt(q2)` is too large for rho/BSGS but `q2` divides `p^k - 1` for some small `k`, the ECDLP can be transported into `F_{p^k}*` via the **Weil pairing**, where sub-exponential index calculus (e.g. CADO-NFS) beats the `O(sqrt(q2))` curve-side bound.

> Always check `sqrt(q2)` against your actual compute budget before reaching for MOV — it's a heavier technique (pairing computation + finite-field DLP setup) than a plain Pollard's rho call. The challenge being *named* for MOV doesn't mean it's the only/fastest path; smaller `q2` than the designer assumed is common as compute gets cheaper over time.

---

## Why the pairing move works

The Weil pairing `e(P, Q)` is bilinear: `e([x]P, Q) = e(P, Q)^x`. So if `Q` is a point of order `q2` linearly independent from `G2`:

```
g = e(G2, Q)        # lives in F_{p^k}*
h = e(A2, Q) = e([a2]G2, Q) = e(G2, Q)^a2 = g^a2
```

Solving `h = g^a2` is now a discrete log in `F_{p^k}*` — a finite-field DLP, not an ECDLP. Then `a = CRT([a1, a2], [q1, q2])`.

```python
# k = smallest k such that q2 | (p^k - 1)
for k in range(1, 20):
    if (p**k - 1) % q2 == 0:
        break

Fpk.<z> = GF(p^k)
Ek = E.change_ring(Fpk)
G2k, A2k = Ek(G2), Ek(A2)

# auxiliary point Q: order q2, not a multiple of G2k (else pairing is trivial)
while True:
    Q = Ek.random_element()
    Q = (Q.order() // q2) * Q
    if Q.order() == q2 and G2k.weil_pairing(Q, q2) != 1:
        break

g = G2k.weil_pairing(Q, q2)
h = A2k.weil_pairing(Q, q2)
a2 = g.log(h)          # finite-field DLP — index calculus territory for large q2
```

---

## Implementation (what actually ran)

No Sage available — used PARI/GP instead. `elllog` runs the full Pohlig-Hellman decomposition internally (factors `n`, solves each piece, CRTs them back) and picked Pollard's rho for the `q2 ≈ 1.15×10^15` factor on its own — `sqrt(q2) ≈ 3.4×10^7` was small enough that **Option A won**, no pairing needed in practice.

```gp
p = 1331169830894825846283645180581;
E = ellinit([-35, 98], p);
G = [479691812266187139164535778017, 568535594075310466177352868412];
A = [1110072782478160369250829345256, 800079550745409318906383650948];
B = [1290982289093010194550717223760, 762857612860564354370535420319];

n = 103686954799254136375814;   \\ order of G = 2*7*271*23687*1153763334005213
alice_secret = elllog(E, A, G, n);
assert(ellmul(E, G, alice_secret) == A);

shared_secret = ellmul(E, B, alice_secret)[1];   \\ x-coord, fed into KDF
```

> `discrete_log`/`elllog` choosing rho vs BSGS vs MOV is implementation-dependent — Sage's generic `discrete_log` may need explicit `algorithm='pari'` or a manual split to avoid defaulting to memory-heavy BSGS on the large factor.

---

## Quick Reference

| Concept | One-liner |
| --- | --- |
| Smooth/large split | `n = q1 * q2`, solve each via Pohlig-Hellman, recombine with CRT |
| Pollard's rho (curve) | `O(sqrt(q2))` time, ~`O(1)` memory — try before reaching for MOV |
| MOV attack | moves ECDLP → `F_{p^k}*` DLP via Weil pairing when `q2 \| p^k - 1` |
| Embedding degree k | smallest k with `q2 \| (p^k - 1)` — small k is what makes MOV worth it |
| Auxiliary point Q | order q2, linearly independent from G2 — needed so the pairing isn't trivial |

---

**See also:** [ECC - Weak Curve Attacks](./ECC%20-%20Weak%20Curve%20Attacks.md) · [ECC - Fundamentals](./ECC%20-%20Fundamentals.md) · [Diffie-Hellman](./Diffie-Hellman.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
