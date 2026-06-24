---
tags: [cryptography, elliptic-curves, cryptohack]
---

# ECC - ECDSA Weak/Reused Nonce Attack (ProSign3)

One-line summary: if the per-signature nonce `k` is predictable or reused, the private key can be recovered algebraically from a single signature (or two, in the reuse variant) — same root cause as the PS3 ECDSA key leak.

---

## How ECDSA Signing Works

To sign a hash `z` with private key `d`:

1. Pick random nonce `k` (must be uniform over `[1, n-1]`, secret, and never reused)
2. Compute point `R = k·G`
3. `r = R.x mod n`
4. `s = k⁻¹(z + r·d) mod n`
5. Signature is `(r, s)`

Security depends entirely on `k` being unpredictable and unique per signature. The equation in step 4 has two unknowns (`k` and `d`) — break either constraint on `k` and the system collapses to one unknown.

---

## Attack 1: Brute-Forceable Nonce Range

If `k` is drawn from a tiny range (e.g. due to a variable-shadowing bug limiting it to `randrange(1, seconds_value)` instead of `randrange(1, n)`), brute-force every candidate:

```python
recovered_k = None
for k_candidate in range(1, 59):       # range observed/known to be tiny
    R = k_candidate * g
    if (R.x() % n) == r:               # matches the r from a real signature
        recovered_k = k_candidate
        break
```

> callout: watch for local variables shadowing module-level names (e.g. a local `n` reassigned to seconds-of-minute, silently breaking `randrange(1, n)` elsewhere in scope).

---

## Attack 2: Nonce Reuse Across Two Signatures

If the *same* `k` is used for two different messages (detectable: identical `r` values, since `r` only depends on `R = k·G`), `k` can be solved directly without brute force:

```
s1 = k⁻¹(z1 + r·d) mod n
s2 = k⁻¹(z2 + r·d) mod n
```

Subtracting eliminates `d`, solving for `k` directly. (This is the classic attack that broke the PS3's ECDSA signing — Sony reused `k` for every signature instead of randomizing it.)

---

## Recovering the Private Key

Once `k` is known (either method), rearrange the signing equation:

```
s = k⁻¹(z + r·d) mod n
s·k = z + r·d           mod n
r·d = s·k - z           mod n
d   = (s·k - z) · r⁻¹   mod n
```

```python
d = ((s * k - z) * pow(r, -1, n)) % n
```

With `d` recovered, you can sign anything yourself — not forging a signature, but legitimately holding the private key.

```python
from ecdsa.ecdsa import Public_key, Private_key

pubkey = Public_key(g, g * d)
privkey = Private_key(pubkey, d)
forged_sig = privkey.sign(target_hash, k=some_fresh_random_nonce)
```

> callout: `z` is the integer-converted hash of the message (`bytes_to_long(sha1(msg).digest())`), truncated to the curve's bit length if the hash output is longer than `n`.

---

## Quick Reference

| Failure mode               | Detection                       | Recovery method                                    |
| -------------------------- | ------------------------------- | -------------------------------------------------- |
| Tiny/predictable `k` range | Known/guessable bound on nonce  | Brute-force `k`, then solve for `d`                |
| Reused `k` across 2 sigs   | Identical `r` in two signatures | Subtract equations to solve `k` directly, then `d` |

---

**See also:** [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md) [ECC - Invalid Generator Attack (Curveball)](./ECC%20-%20Invalid%20Generator%20Attack%20%28Curveball%29.md) [ECC - Weak Curve Attacks](./ECC%20-%20Weak%20Curve%20Attacks.md)
[ECC - Montgomery Curves & Side Channels](./ECC%20-%20Montgomery%20Curves%20%26%20Side%20Channels.md) [ECC - Fundamentals](./ECC%20-%20Fundamentals.md)