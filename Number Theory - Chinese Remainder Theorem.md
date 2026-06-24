---
tags: [cryptography, number-theory, cryptohack]
---

# Number Theory - Chinese Remainder Theorem

> Given a system of congruences with pairwise coprime moduli, CRT guarantees a unique solution.

---

## The Problem

You have multiple congruences and you want one `x` that satisfies all of them:
```
x ≡ a1 mod n1
x ≡ a2 mod n2
...
x ≡ an mod nn
```

**CRT says:** if all moduli are pairwise coprime (`gcd(ni, nj) = 1` for every pair), then there exists a **unique** solution:
```
x ≡ a mod N     where N = n1 · n2 · ... · nn
```

---

## Solving the System

**Start with the largest modulus.** For `x ≡ a mod p`, rewrite as:
```
x = a + k·p     (k is some integer)
```

Then substitute into the next congruence and solve for `k`. This gives you a new expression for `x` with fewer unknowns. Repeat until `x` is fully determined.

Each substitution narrows the solution — you go from infinitely many candidates down to one unique `x` in `[0, N)`.

---

## Example

```
x ≡ 2 mod 3
x ≡ 3 mod 5
x ≡ 2 mod 7
```

**Step 1 — largest modulus: `x ≡ 2 mod 7`**
```
x = 2 + 7k
```

**Step 2 — substitute into `x ≡ 3 mod 5`:**
```
2 + 7k ≡ 3 mod 5
2k ≡ 1 mod 5          (7 ≡ 2 mod 5)
k ≡ 3 mod 5           (inverse of 2 mod 5 is 3)
k = 3 + 5m
→ x = 2 + 7(3 + 5m) = 23 + 35m
```

**Step 3 — substitute into `x ≡ 2 mod 3`:**
```
23 + 35m ≡ 2 mod 3
2 + 2m ≡ 2 mod 3      (23 ≡ 2, 35 ≡ 2 mod 3)
m ≡ 0 mod 3
m = 3j
→ x = 23 + 35(3j) = 23 + 105j
```

**Solution:** `x ≡ 23 mod 105`

Verify:
```
23 mod 3 = 2  ✓
23 mod 5 = 3  ✓
23 mod 7 = 2  ✓
```

---

## Implementation

The naive approach (stepping through candidates until a match) breaks completely on large moduli. The proper way uses the **Extended Euclidean Algorithm** to compute the answer directly.

The idea: for each congruence `x ≡ a mod n`, construct a term that equals `a` mod `n` and equals `0` mod every other modulus. Sum all terms → you get `x`.

How? For each `n`:
- `Ni = N // n` — product of all moduli *except* `n`. This is automatically `≡ 0` mod every other modulus (they're all factors of it)
- `inv = Ni⁻¹ mod n` — the modular inverse of `Ni` mod `n`
- term = `a · Ni · inv` — this equals `a · 1 = a` mod `n`, and `0` mod everything else

Sum all terms and reduce mod `N`.

```python
def crt(remainders, moduli):
    N = 1
    for n in moduli:
        N *= n                      # N = product of all moduli

    x = 0
    for a, n in zip(remainders, moduli):
        Ni = N // n                 # all moduli except current one
        inv = pow(Ni, -1, n)        # inverse of Ni mod n (Extended Euclidean)
        x += a * Ni * inv           # this term = a mod n, and 0 mod everything else
    return x % N                    # unique solution in [0, N)

# example
remainders = [2, 3, 2]
moduli     = [3, 5, 7]
print(crt(remainders, moduli))      # 23
```

> `pow(Ni, -1, n)` computes the modular inverse directly — available natively in Python 3.8+. No sorting needed, no searching, works on arbitrarily large moduli.

---

## Why Pairwise Coprime?

If moduli share factors, the system can contradict itself and no solution exists. Coprime moduli guarantee the congruences never clash — each one adds clean, independent information about `x`.

---

**See also:** [Number Theory - GCD & Modular Arithmetic](./Number%20Theory%20-%20GCD%20%26%20Modular%20Arithmetic.md) · [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
