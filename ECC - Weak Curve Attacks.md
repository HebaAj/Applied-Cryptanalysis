---
tags: [cryptography, number-theory, cryptohack]
---

# ECC - Weak Curve Attacks

How to spot and exploit poorly chosen elliptic curves — the ECC equivalent of attacking weak DH parameters.

---

## Spotting a Weak Curve

| Signal | What it means |
|---|---|
| Custom curve (not P-256, P-384, Curve25519, etc.) | standardized curves are safe by construction — custom is always suspicious in CTF |
| `n = randint(1, p)` instead of `randint(1, order)` | secret chosen mod p, not mod curve order — author isn't thinking about group structure |
| No order validation in the code | no `assert` on subgroup order, no cofactor check |
| Small or "random-looking" prime p | safe primes for ECC are chosen for efficiency (Mersenne-like); arbitrary decimals are suspicious |

**The definitive check — factor the curve order:**

```python
# SageMath
E = EllipticCurve(GF(p), [a, b])
print(factor(E.order()))
```

All small factors → smooth order → **Pohlig-Hellman applies**.

---

## Pohlig-Hellman on Elliptic Curves

Same principle as Pohlig-Hellman on DH — reduce one hard ECDLP into many easy ones:

1. Factor the group order N = p₁^e₁ · p₂^e₂ · ... · pₖ^eₖ
2. For each prime power pᵢ^eᵢ: project G and Q into the subgroup of order pᵢ^eᵢ by multiplying by N/pᵢ^eᵢ
3. Solve the small ECDLP in each subgroup (via BSGS — feasible because subgroups are small)
4. Combine with CRT → recover n mod N

**SageMath (version-safe):**

```python
E = EllipticCurve(GF(p), [a, b])
G = E(gx, gy)
B = E(bx, by)
A = E(ax, ay)

b_priv = B.log(G)                    # .log(G) works on older SageMath versions
shared_secret = int((A * b_priv)[0]) # x-coordinate; int() converts SageMath integer
```

> `.log(G)` is version-safe — works on sagecell.sagemath.org. The newer standalone `discrete_log(target, base, ord=order, operation='+')` has different argument order than the DH version and may not exist on older builds.

---

## Other ECC Attack Patterns

| Attack         | Trigger                     | Mechanism                                               |
| -------------- | --------------------------- | ------------------------------------------------------- |
| Pohlig-Hellman | smooth curve order          | subgroup ECDLP + CRT                                    |
| BSGS           | prime order but small       | meet-in-the-middle, O(√order)                           |
| Invalid curve  | no point validation         | send point on different curve with weak order           |
| MOV attack     | embedding degree is small   | reduce ECDLP to DLP in 𝔽ₚᵏ (easier)                    |
| Smart's attack | trace-one / anomalous curve | curve order = p → lift to p-adics, solve in linear time |

> For CryptoHack, Pohlig-Hellman is the most common. Invalid curve attacks appear in later challenges. MOV and Smart's are rare but worth recognizing by name.

---

## ECDH Decryption After Key Recovery

Standard pattern once you have the private key:

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# shared_secret is the x-coordinate of [n]B
sha1 = hashlib.sha1()
sha1.update(str(shared_secret).encode('ascii'))
key = sha1.digest()[:16]

iv = bytes.fromhex(data['iv'])
ct = bytes.fromhex(data['encrypted_flag'])

cipher = AES.new(key, AES.MODE_CBC, iv)
print(unpad(cipher.decrypt(ct), 16))
```

> The shared secret is hashed to derive the AES key — hash function and key derivation method vary per challenge. Check the source code.

---

**See also:** [ECC - Fundamentals](./ECC%20-%20Fundamentals.md) · [ECC - Montgomery Curves & Side Channels](./ECC%20-%20Montgomery%20Curves%20%26%20Side%20Channels.md) · [Diffie-Hellman](./Diffie-Hellman.md) · [Number Theory - Chinese Remainder Theorem](./Number%20Theory%20-%20Chinese%20Remainder%20Theorem.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
