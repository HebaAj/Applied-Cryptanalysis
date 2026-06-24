---
tags: [cryptography, number-theory, cryptohack]
---

# Number Theory - Tonelli-Shanks

> Algorithm for finding the actual square root of a quadratic residue mod p — for when Euler's criterion isn't enough.

---

## The Problem

We have `x` (confirmed QR via Euler's criterion). We want `R` such that:
```
R² ≡ x mod p
```

**Easy case:** if `p ≡ 3 mod 4`, the shortcut is:
```
R ≡ x^((p+1)/4) mod p
```

**Hard case:** when `p ≡ 1 mod 4` (meaning `4 | p-1`), that shortcut breaks — this is where Tonelli-Shanks comes in.

---

## How the Algorithm Was Discovered (the why)

### First attempt: find k where (x^k)² = x

From Fermat we can only work with exponentiation. So the natural question is: is there a `k` such that `x^k` is the square root?

```
(x^k)² = x  →  2k ≡ 1 mod (p-1)  →  k = 2⁻¹ mod (p-1)
```

Problem: the inverse of 2 mod `(p-1)` doesn't exist — `p-1` is always even, so `gcd(2, p-1) = 2 ≠ 1`. Dead end.

### Step 1: Factor out the 2s from p-1

Since `p-1` is even, split it:
```
p - 1 = 2^s · q    (q is odd)
```

Now `q` is odd so `gcd(2, q) = 1` — the inverse of 2 exists mod `q`. So:
```
k = (q+1)/2    (since 2k ≡ 1 mod q means k = (q+1)/2)
```

Our best guess for `R` becomes:
```
R = x^((q+1)/2)
```

Check it by squaring:
```
R² = x^(q+1) = x^q · x = t · x
```

We wanted just `x`, but we got `t · x` where `t = x^q`.

**`t` wasn't planned — it appeared naturally as the leftover. It's the error.**

### What do we know about t?

From Fermat: `x^(2^s · q) ≡ 1`, so:
```
t^(2^s) = (x^q)^(2^s) ≡ 1 mod p
```

And from Euler (x is a QR): `x^(2^(s-1)·q) ≡ 1`, meaning:
```
t^(2^(s-1)) ≡ 1 mod p
```

So if you keep squaring `t`, it eventually hits 1. The position where it hits 1 is its order — a power of 2. **When t = 1, we're done** because then `R² = 1 · x = x`.

### Step 2: Fix the error — find b where b² = t⁻¹

If we multiply `R` by some `b`:
```
(R · b)² = R² · b² = t · x · b²
```

For this to equal `x`:
```
b² = t⁻¹
```

Finding `b` directly is the same hard problem again. So instead we need a **controllable element** `c` that can generate any power-of-2-order element we need.

### Step 3: Find c — the correction tool

`t` has 2-power order, so `b²` must also live in the 2-power subgroup. We need `c` to be a **generator** of that entire subgroup, meaning its order must be exactly `2^s`.

For order exactly `2^s`, we need:
```
c^(2^s) ≡ 1        (satisfied by Fermat for any element)
c^(2^(s-1)) ≢ 1    (this is the extra condition)
```

Since `c^(2^(s-1))` is a square root of 1, and the only options are `1` and `-1`, we need:
```
c^(2^(s-1)) ≡ -1 mod p
```

Where does `-1` naturally appear? **Euler's criterion for non-residues:**
```
z^((p-1)/2) ≡ -1 mod p    (when z is a non-residue)
z^(2^(s-1) · q) ≡ -1 mod p
```

So set `c = z^q`:
```
c^(2^(s-1)) = (z^q)^(2^(s-1)) = z^(2^(s-1)·q) ≡ -1 mod p  ✓
```

A **residue** would give `+1` here instead → order would be smaller → can't generate the full subgroup → can't always find the correction we need.

> ~50% of elements are non-residues, so finding `z` is fast — just try `z = 2, 3, 4, ...` until Euler's criterion returns `-1`.

### Step 4: Reduce t to 1 iteratively

Instead of cancelling `t` all at once, we peel it off one layer at a time.

Each iteration:
1. Find the current order of `t` — smallest `i` where `t^(2^i) ≡ 1`
2. Compute `b = c^(2^(M-i-1))` where `M` starts at `s`
3. Update: `R ← R · b`, `t ← t · b²`, `c ← b²`, `M ← i`

Why does `t · b²` have smaller order? Because `b` is chosen so that `b^(2^i) ≡ -1`, and `t^(2^(i-1)) ≡ -1` as well — their product at step `(i-1)` gives `(-1)·(-1) = 1`, so the new `t` hits 1 one step earlier.

Order of `t` strictly decreases each iteration → guaranteed to converge.

---

## The Algorithm

```
Input: x (QR), p (prime)
Output: R where R² ≡ x mod p

1. Factor: p-1 = 2^s · q  (q odd)
2. Find z: a non-residue mod p  (try z=2,3,... until z^((p-1)/2) ≡ -1)
3. Initialize:
     M = s
     c = z^q mod p
     t = x^q mod p
     R = x^((q+1)/2) mod p
4. Loop:
     if t = 1 → return R
     find smallest i > 0 where t^(2^i) ≡ 1
     b = c^(2^(M-i-1)) mod p
     M = i
     c = b² mod p
     t = t·b² mod p
     R = R·b mod p
```

```python
def tonelli_shanks(x, p):
    # factor p-1
    s, q = 0, p - 1
    while q % 2 == 0:
        q //= 2
        s += 1

    # find non-residue
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    # initialize
    M = s
    c = pow(z, q, p)
    t = pow(x, q, p)
    R = pow(x, (q + 1) // 2, p)

    while True:
        if t == 1:
            return R
        # find order of t
        i, temp = 1, (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        # correction
        b = pow(c, pow(2, M - i - 1), p)
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p
```

---

## Worked Example

**Find the square root of `x = 2` mod `p = 17`.**

**Verify:** `2^8 mod 17 = 256 mod 17 = 1` → QR ✓

**Step 1 — Factor p-1:**
```
p - 1 = 16 = 2^4 · 1   →   s = 4, q = 1
```

**Step 2 — Find non-residue z:**
```
z = 3: 3^8 mod 17 = 6561 mod 17 = 16 = -1  ✓
```

**Step 3 — Initialize:**
```
M = 4
c = 3^1 mod 17 = 3
t = 2^1 mod 17 = 2
R = 2^1 mod 17 = 2       (since (q+1)/2 = 1)
```

Check: `R² = 4 = 2·2 = t·x` ✓ — error is `t = 2`

**Step 4 — Loop:**

*Iteration 1:* `t = 2 ≠ 1`

Find order of `t = 2`:
```
2^1 = 2,  2^2 = 4,  2^4 = 16 ≡ -1,  2^8 ≡ 1  →  i = 3 (since 2^(2^3) = 2^8 ≡ 1)
```

Wait, let me be precise — smallest `i` where `t^(2^i) ≡ 1`:
```
t^(2^1) = 2^2 = 4 ≠ 1
t^(2^2) = 2^4 = 16 ≠ 1
t^(2^3) = 2^8 = 256 ≡ 1 mod 17  →  i = 3
```

Compute correction:
```
b = c^(2^(M-i-1)) = 3^(2^(4-3-1)) = 3^(2^0) = 3^1 = 3
```

Update:
```
c = b² = 9
t = t · b² = 2 · 9 = 18 ≡ 1 mod 17
R = R · b = 2 · 3 = 6
```

*Iteration 2:* `t = 1` → **return R = 6**

**Verify:** `6² = 36 = 2·17 + 2 ≡ 2 mod 17` ✓

---

## Summary of the Discovery Chain

```
want R² = x
→ try R = x^k, need 2k ≡ 1 mod (p-1), impossible since p-1 is even
→ split p-1 = 2^s·q, use k = (q+1)/2
→ R² = x^q · x = t · x  (t appeared as the leftover)
→ need b where b² = t⁻¹ to fix R
→ need c with order 2^s to generate any correction needed
→ c^(2^(s-1)) must be -1 → non-residue gives this via Euler
→ reduce order of t by 1 each iteration until t = 1
→ done
```

---

**See also:** [Number Theory - Quadratic Residues](./Number%20Theory%20-%20Quadratic%20Residues.md) · [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
