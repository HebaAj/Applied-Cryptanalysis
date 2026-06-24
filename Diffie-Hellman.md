---
tags: [cryptography, number-theory, cryptohack, diffie-hellman]
---

# Diffie-Hellman

Protocol for establishing a shared secret over an insecure channel; security rests on the hardness of the discrete logarithm in a carefully chosen finite field.

---

## Finite Fields & Subgroups

𝔽ₚ = {0, 1, ..., p−1} with addition and multiplication mod p. When p is prime, every nonzero element has a multiplicative inverse (because gcd(x, p) = 1 for all x in 1..p−1), promoting the ring ℤ/pℤ to a **field**.

𝔽ₚ* = 𝔽ₚ \ {0} — the multiplicative group, size p−1.

Repeated multiplication of any element g generates a **subgroup** H = ⟨g⟩ = {g, g², g³, ...}. Because the group is finite, powers eventually cycle back to 1. The number of steps before that happens is the **order** of g.

**Lagrange's theorem:** the order of any element must divide |𝔽ₚ*| = p−1.

*Why:* the cosets of ⟨g⟩ partition 𝔽ₚ* into equal-sized, non-overlapping chunks. Each coset aH = {a·h : h ∈ H} has the same size as H (multiplication by a nonzero element is a bijection — no mod collisions, because inverses exist). Since the cosets tile the group perfectly: |𝔽ₚ*| = m × |H|, so |H| divides p−1.

---

## Primitive Elements (Generators)

A **primitive element** g has order exactly p−1 — its powers visit every element of 𝔽ₚ* before cycling. Also called a **generator**.

Non-generators have order k < p−1 where k | p−1; their subgroup is a strict subset of 𝔽ₚ*.

### Finding a generator efficiently

Brute-force (compute all powers until cycle) is infeasible for large p. Instead, use the prime factorisation of p−1:

g is a generator ⟺ for every prime factor q of p−1:

```
g^((p-1)/q) ≢ 1 (mod p)
```

*Why it works:* if g's order k < p−1, then k divides p−1, so some prime factor q of p−1 satisfies k | (p−1)/q, meaning g^((p−1)/q) ≡ 1. The check catches every non-generator.

```python
from primefac import primefac

def is_generator(g, p):
    factors = set(primefac(p - 1))
    return all(pow(g, (p-1) // q, p) != 1 for q in factors)

# find smallest generator
p = 28151
g = next(g for g in range(2, p) if is_generator(g, p))
```

> `primefac` works for small/medium p. For large standardised DH primes, p−1's factorisation is published — no computation needed.

---

## The Protocol

**Setup (public):** prime p, generator g.

**Key exchange:**
1. Alice picks secret a, sends A = gᵃ mod p
2. Bob picks secret b, sends B = gᵇ mod p
3. Alice computes Bᵃ mod p = gᵃᵇ mod p
4. Bob computes Aᵇ mod p = gᵃᵇ mod p

Both arrive at the same shared secret gᵃᵇ mod p. An eavesdropper sees g, p, A, B but recovering a or b requires solving the discrete logarithm — assumed hard for large p.

```python
# if you hold secret a and intercept B:
shared_secret = pow(B, a, p)
```

---

## Discrete Logarithm Hardness

Given g, A, p — find a such that gᵃ ≡ A (mod p). Hard in general; several algorithms exploit weaknesses in how p is chosen:

| Attack | Exploits | Defence |
|---|---|---|
| Pohlig-Hellman | small prime factors of p−1 | safe prime: p = 2q+1, so p−1 = 2q |
| Baby-step Giant-step | brute force with √p steps | large p |
| Index calculus | smooth numbers mod p | large p |

**Safe primes** (p = 2q+1, q prime) ensure p−1 = 2q, so Pohlig-Hellman reduces to one subproblem of size q — still hard.

**Pohlig-Hellman sketch:** factorise p−1 into prime powers, solve the discrete log in each small subgroup separately (work ∝ size of each factor), combine with CRT. Only effective when all factors are small.

---

## Solving the Discrete Log (small p)

For CryptoHack challenges with small p (64-bit and below), SageMath handles it in one line:

```python
from sage.all import GF, discrete_log

p = 0xde26ab651b92a129
g = 0x2
B = 0xa4c3c1a4cb2be693

F = GF(p)
b = discrete_log(F(B), F(g))       # recover Bob's secret
shared_secret = pow(A, b, p)
```

> For 64-bit p, `discrete_log` in SageMath is fast (seconds). Above ~80 bits, it stalls — use a specialised solver or check if p−1 is smooth (Pohlig-Hellman via SageMath's `discrete_log` still handles smooth cases automatically).

---

## Attacks

### MITM — send g to both sides

Intercept A and B. Send g to Alice (instead of B) and g to Bob (instead of A):
- Alice computes gᵃ mod p = **A** → shared secret is A
- Bob computes gᵇ mod p = **B** → shared secret is B

You know both A and B. Alice and Bob have different secrets (session broken), but you can decrypt whichever side sends the flag.

### MITM — send 1 to a side

Send 1 to Alice instead of B:
- Alice computes 1ᵃ mod p = **1** → shared secret is always 1

No need to intercept anything — the secret is known before connecting. Simpler for flag recovery, but doesn't give you both sides.

> Sending g is more powerful in a real relay attack (two valid sessions). Sending 1 is simpler when you only need to decrypt one side.

### Parameter downgrade attack

When Alice and Bob negotiate which DH group to use, intercept the negotiation and replace Alice's supported list with only the weakest option (e.g. DH64). Bob picks it, both use a 64-bit prime, and the discrete log is now feasible.

```python
# netcat flow:
# 1. intercept Alice's {"supported": ["DH1536","DH1024",...,"DH64"]}
# 2. forward only {"supported": ["DH64"]} to Bob
# 3. Bob responds {"chosen": "DH64"} — forward to Alice
# 4. now intercept p, g, A, B and solve discrete_log(F(B), F(g))
```

---

**See also:** [Number Theory - GCD & Modular Arithmetic](./Number%20Theory%20-%20GCD%20%26%20Modular%20Arithmetic.md) · [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) · [Number Theory - Chinese Remainder Theorem](./Number%20Theory%20-%20Chinese%20Remainder%20Theorem.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
