---
tags: [cryptography, symmetric-crypto, cryptohack, aes]
---

# Symmetric Crypto - AES SubBytes & S-Box

SubBytes: per-byte table-lookup substitution. Provides AES's non-linearity (confusion). The only step with no diffusion — operates on each byte independently.

---

## Why Non-Linearity Matters

A linear function `f(x) = ax + b` is solvable from a handful of input/output pairs, and linear approximations compose across rounds — that's what linear cryptanalysis exploits. The S-box is designed for **high non-linearity** so no useful linear approximation exists.

---

## How the S-Box is Built

Two steps, applied to every byte 0x00–0xff once, precomputed into a 256-entry table:

1. **Modular inverse in GF(2^8)** — multiplicative inverse under the field's reduction polynomial `m(x) = x^8+x^4+x^3+x+1` (`0x11B`). Same algorithm as integer modular inverse (Extended Euclidean), just on GF(2) polynomials. `0x00 → 0x00` (no inverse, fixed exception). This is the genuinely non-linear core — no shortcut formula.
2. **Affine transformation** — fixed linear formula over GF(2) plus constant `0x63`:

   ```
   b'_i = b_i ⊕ b_{i+4} ⊕ b_{i+5} ⊕ b_{i+6} ⊕ b_{i+7} ⊕ c_i   (indices mod 8)
   ```

   Linear on its own — its job is avoiding algebraic fixed points (e.g. `S(x) = x`) and giving the S-box good avalanche properties on top of the inversion.

> The closed-form single-polynomial expression for "inversion + affine" exists (high-degree, exponents near 0xfe in GF(2^8)) but is never evaluated at runtime — it exists for cryptanalysts to study the S-box's algebraic properties. AES uses the precomputed 256-entry table.

### Worked Example: 0x53

- `0x53 = x^6+x^4+x+1`. EGCD against `m(x)` → inverse = `x^7+x^6+x^3+x = 0xCA`.
- Affine transform on `0xCA` (`11001010`) → `0xED`.
- `0x53 → 0xCA → 0xED` — matches the real AES S-box entry.

---

## Implementation

```python
def sub_bytes(s, sbox=s_box):
    return [[sbox[byte] for byte in row] for row in s]

def inv_sub_bytes(s, sbox=inv_s_box):
    return [[sbox[byte] for byte in row] for row in s]
```

`inv_s_box[s_box[b]] == b` for all b — exact inverses, built once by inverting the table mapping.

> Returns a **new** 4x4 matrix (pure function) rather than mutating in place — avoids aliasing bugs (a second reference to the same state object silently changing too) and keeps every intermediate round state inspectable for debugging against test vectors. Mutation-in-place is a real optimization in production C/embedded AES, but irrelevant at this scale.

---

**See also:** [Symmetric Crypto - AES Structure & Key Schedule](./Symmetric%20Crypto%20-%20AES%20Structure%20%26%20Key%20Schedule.md) · [Symmetric Crypto - AES ShiftRows & MixColumns](./Symmetric%20Crypto%20-%20AES%20ShiftRows%20%26%20MixColumns.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
