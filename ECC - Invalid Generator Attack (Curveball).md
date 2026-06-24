---
tags: [cryptography, elliptic-curves, cryptohack]
---

# ECC - Invalid Generator Attack (Curveball)

One-line summary: forging a "trusted" public key by supplying your own generator point instead of the curve's standard one — the same flaw as CVE-2020-0601.

---

## Core Mechanism

ECDH/ECDSA security assumes the generator `G` is a fixed, public, trusted curve parameter. If a system lets the *caller* supply `G` as part of the request, and only checks the resulting public key `Q` against a trusted list — not the generator used to produce it — the trust check can be bypassed entirely.

Given any target point `Q` (someone else's trusted public key) and the curve's group order `n`:

```
Q · (n + 1) = Q · n + Q = O + Q = Q
```

since `n · P = O` (point at infinity / identity) for any point `P` on the curve. So setting your "private key" `d = n + 1` and your "generator" `g = Q` produces:

```
g · d = Q · (n + 1) = Q
```

— mathematically identical to using `d = 1`, but `d = n+1` is a huge integer, so it sails past any naive check like `abs(d) == 1`.

> callout: this only works because the server lets you choose the generator per-request. A correct implementation hardcodes `G` and never accepts it as input.

---

## Implementation

```python
# curve order for P256 (secp256r1) — public, standard parameter
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

d = n + 1  # behaves like d=1 under the group's modular arithmetic, but isn't literally 1

packet = {
    "host": "anything",          # not checked against the forged point
    "curve": "secp256r1",
    "generator": [Qx, Qy],       # the trusted party's public key, used AS the generator
    "private_key": d
}
# server computes Q' = generator * d = Q, matching the trusted cert's stored public key
```

---

## Real-World Mapping: CVE-2020-0601 ("CurveBall")

Windows CryptoAPI (`crypt32.dll`) validated ECC certificates by checking only whether the public key point matched a trusted root CA's public key — not whether the certificate's explicit curve parameters (including `G`) matched the standard ones. An attacker could forge a certificate using a legitimate CA's public key as their chosen generator, with a crafted private key, producing a "publicly trusted" signature Windows would accept — enabling forged code-signing certs and MITM on HTTPS. Patched January 2020 (disclosed by the NSA).

| CryptoHack challenge | Real-world parallel |
|---|---|
| Custom `generator` in JSON packet | Explicit curve params in X.509 cert |
| `search_trusted(Q)` checks point only | CryptoAPI checked public key point only |
| `d = n+1` masquerading as `d=1` | Forged private key paired with hijacked generator |

---

**See also:** [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md) [ECC - ECDSA Weak Nonce Attack (ProSign3)](./ECC%20-%20ECDSA%20Weak%20Nonce%20Attack%20%28ProSign3%29.md) [ECC - Weak Curve Attacks](./ECC%20-%20Weak%20Curve%20Attacks.md)
[ECC - Montgomery Curves & Side Channels](./ECC%20-%20Montgomery%20Curves%20%26%20Side%20Channels.md) [ECC - Fundamentals](./ECC%20-%20Fundamentals.md)
