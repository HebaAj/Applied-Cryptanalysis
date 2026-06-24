---
tags: [python, cryptohack]
---

# Python - Toolkit

Reference for core Python patterns that come up repeatedly in crypto implementations: zip, comprehensions, pure-vs-mutating functions, bytes/list interop, XOR helpers, and standard library reference. HTTP-oracle/concurrency patterns live in [Python - HTTP Oracle & Concurrency Patterns](./Python%20-%20HTTP%20Oracle%20%26%20Concurrency%20Patterns.md).

---

## zip()

`zip(a, b)` pairs up elements from two (or more) iterables positionally, lazily, stopping at the shortest input. Used constantly for "combine corresponding elements" — e.g. AddRoundKey (XOR state byte with key byte at the same position):

```python
[a ^ b for a, b in zip(row_s, row_k)]
```

**vs. indexing:**

```python
[row_s[i] ^ row_k[i] for i in range(len(row_s))]
```

`zip` avoids the index variable entirely — less error-prone (no off-by-one, no `len()` mismatch between the two sequences if they happen to differ). Performance-wise `zip` is implemented in C and is at least as fast as indexed access for this kind of loop; the index version has the extra overhead of repeated `__getitem__` calls plus `range()`. For 16-byte AES blocks the difference is negligible either way — `zip` wins on readability/safety, not speed, at this scale.

> `zip` silently truncates to the shorter input if lengths differ — a real footgun if state/key rows ever mismatch in length. `itertools.zip_longest` exists if that needs to be an error instead of silent truncation.

---

## List Comprehensions vs map+lambda

`[f(x) for x in xs]` and `list(map(f, xs))` are equivalent in result and performance. Comprehensions are preferred — no `list()` wrapper needed, and `lambda x: table[x]` is just `table.__getitem__`, which a comprehension expresses more directly.

> Avoid `sum(list_of_lists, [])` to flatten — it's O(n²) (each `+` copies everything accumulated so far). Use `[x for row in matrix for x in row]` or `itertools.chain.from_iterable`.

---

## Pure Functions vs In-Place Mutation

Pure (return new object, don't touch input) is the default for this vault's AES code:

```python
def sub_bytes(s, sbox=s_box):
    return [[sbox[b] for b in row] for row in s]   # new nested list
```

Avoids aliasing bugs (`backup = state` then mutating `state` would silently corrupt `backup` too) and keeps every intermediate round state inspectable for debugging against test vectors. In-place mutation is a real optimization in production/embedded crypto (avoids repeated allocation) — not worth it at 16-byte-block scale.

> A list comprehension over `for row in s` for a list-of-lists produces genuinely new inner lists too (not shared references) — equivalent to a deep copy at this nesting depth. `list(s)` alone would only shallow-copy the outer list.

---

## bytes vs list[int]

Both are sequences of ints 0–255 when iterated or indexed — interchangeable for reading:

```python
b'\x8c\x97\x16C'[0]        # 140
list(b'\x8c\x97\x16C')      # [140, 151, 22, 67]
```

`bytes` is immutable — `b[0] = x` raises `TypeError`. Fine for AES round keys (read-only, never mutated); would matter if a function tried to mutate one in place.

---

## XOR Two Byte Strings

Same `zip` pairing as AddRoundKey above, but feeding the generator straight into `bytes()` instead of collecting a `list` — `bytes()` accepts any iterable of ints 0–255:

```python
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
```

This is the workhorse for every CBC formula (`P_i = D_k(C_i) ⊕ C_{i-1}`, `δ = original ⊕ desired`, etc.) — both the mode-mixing decrypt and the bit-flipping forgery reduce to one call of this.

> Same truncation footgun as `zip` above — if `a` and `b` differ in length (e.g. IV vs. a longer ciphertext slice), the result silently comes out the length of the shorter one. Worth a sanity-check `len(a) == len(b)` when the inputs aren't both guaranteed-16-byte blocks.

> When extracting a fixed-size piece *on purpose* — e.g. a known-plaintext crib block — slice explicitly (`ciphertext[:16]`) rather than relying on this truncation to "happen" to produce the right length. Same result, but the size is visible at the call site instead of being an implicit consequence of the second argument's length.

### Repeating-Key XOR via itertools.cycle

`cycle(keystream)` repeats a short sequence indefinitely; combined with `zip` (which still stops at the *shorter* input — here, `ciphertext`), the same `xor()` helper above XORs the entire ciphertext against `keystream` repeated as many times as needed:

```python
from itertools import cycle

plaintext = xor(ciphertext, cycle(keystream))
```

This is the natural expression of a many-time-pad / repeating-key-XOR scenario — e.g. CTR mode with a broken counter that never advances, where every block's keystream is the same 16 bytes.

> `pwntools`' `xor()` (`from pwn import xor`) already cycles the shorter argument internally — `xor(ciphertext, keystream)` alone gives the same result without importing `itertools`. The hand-rolled version is preferred here for being stdlib-only and for keeping one consistent `xor` helper across every note/script.

---

## Integer Roots (gmpy2)

For crypto-scale integers, never use `math.cbrt` or `x**(1/k)` — floating point has 53 bits of precision. Use `gmpy2.iroot` for exact arbitrary-precision integer roots.

```python
import gmpy2

# k-th root of n
root, exact = gmpy2.iroot(n, k)
# root = largest integer r where r^k ≤ n
# exact = True if n is a perfect k-th power

# example: cube root attack on RSA with e=3, small plaintext
pt, exact = gmpy2.iroot(ct, 3)
assert exact    # False means ct wrapped mod N — cube root attack doesn't apply
```

> `math.isqrt` is fine for square roots (exact, stdlib, Python 3.8+). For any other root, use `gmpy2.iroot`.

---

## Hash to Integer (for RSA Signing)

RSA signing requires H(m) as an integer to compute `S = H(m)^d mod N`.

```python
import hashlib
from Crypto.Util.number import bytes_to_long

h = bytes_to_long(hashlib.sha256(message).digest())   # bytes → big-endian int
```

> `.hexdigest()` → `int(hexdigest, 16)` is equivalent but adds a redundant step. Use `.digest()` + `bytes_to_long` directly.

---

## SageMath — Discrete Logarithm (DH / 𝔽ₚ*)

For DH challenges with small p (≤ 64-bit), SageMath's `discrete_log` solves in seconds. Don't implement BSGS manually when SageMath is available.

```python
from sage.all import GF, discrete_log

F = GF(p)
b = discrete_log(F(B), F(g))   # find b s.t. g^b ≡ B mod p
shared_secret = pow(A, b, p)
```

> Works fast up to ~64-bit p. For smooth p−1 (Pohlig-Hellman applies), SageMath handles larger p automatically. Above ~80 bits with non-smooth p−1, it stalls.

---

## SageMath — ECC & ECDLP

For ECC challenges. `EllipticCurve(GF(p), [a, b])` builds the curve; point arithmetic uses `+` and `*` natively.

```python
p = ...
a = ...
b = ...

E = EllipticCurve(GF(p), [a, b])
G = E(gx, gy)
B = E(bx, by)
A = E(ax, ay)

# Recover private key via Pohlig-Hellman (triggered automatically for smooth order)
b_priv = B.log(G)                    # older SageMath: .log(G) on the point
# b_priv = discrete_log(B, G, ord=E.order(), operation='+')  # newer syntax

shared_secret = int((A * b_priv)[0]) # x-coordinate; int() converts SageMath integer
```

> `.log(G)` is the version-safe syntax — works on older SageMath (sagecell.sagemath.org). The standalone `discrete_log(target, base)` has reversed argument order vs. the DH version — easy to mix up.

**Check if a curve is Pohlig-Hellman vulnerable:**
```python
print(factor(E.order()))   # all small factors → smooth → Pohlig-Hellman applies
```

---

## Useful Library Functions

| Function                                                      | Use                                                                                            |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `pow(a, -1, N)`                                               | modular inverse (Python 3.8+, EGCD under the hood) — `gcd(a,N)=1` required                     |
| `int.from_bytes(b, 'big')` / `int.to_bytes(n, length, 'big')` | bytes ↔ integer conversion                                                                     |
| `bytes.fromhex(s)` / `bytes.hex()`                            | hex string ↔ bytes                                                                             |
| `itertools.chain.from_iterable`                               | flatten nested iterables, O(n)                                                                 |
| `itertools.cycle(iterable)`                                   | repeat a short sequence indefinitely — pairs with `zip`/`xor` truncation for repeating-key XOR |
| `functools.reduce`                                            | fold a binary op across a sequence (e.g. chained XOR)                                          |
| `hashlib`                                                     | MD5/SHA-family hashing                                                                         |
| `from Crypto.Util.number import bytes_to_long, long_to_bytes` | bytes ↔ big-endian integer (for RSA plaintext / hash-to-int)                                   |
| `gmpy2.iroot(n, k)`                                           | exact integer k-th root — required for cube root attack and any nth root on large integers     |
| `from sage.interfaces.ecm import ECM`                         | elliptic curve factorisation (SageMath only) — fastest for N with many small factors           |
| `from sage.all import GF, discrete_log`                       | solve discrete log mod p — fast for small/smooth p, use instead of manual BSGS                 |
| `EllipticCurve(GF(p), [a,b])` / `B.log(G)`                   | ECC in SageMath — build curve, recover private key via Pohlig-Hellman (`.log` = version-safe)  |


---

**See also:** [Python - HTTP Oracle & Concurrency Patterns](./Python%20-%20HTTP%20Oracle%20%26%20Concurrency%20Patterns.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
