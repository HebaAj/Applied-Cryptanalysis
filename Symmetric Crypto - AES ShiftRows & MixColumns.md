---
tags: [cryptography, symmetric-crypto, cryptohack, aes]
---

# Symmetric Crypto - AES ShiftRows & MixColumns

Diffusion steps. ShiftRows permutes bytes between columns; MixColumns mixes bytes within a column via GF(2^8) matrix multiplication built entirely from `xtime`.

---

## ShiftRows

Row 0 unchanged, row 1 shifts left by 1, row 2 by 2, row 3 by 3 (wrapping). Prevents columns being encrypted independently — without it AES degenerates into 4 parallel independent ciphers.

```python
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
```

> The AES spec fills the state **column-major**; this code (and most Python AES code) fills **row-major** — the transpose. Operations swap which axis they apply to under that convention, but the final ciphertext is identical as long as the convention is consistent everywhere (key schedule, ShiftRows, MixColumns). Verify against a known test vector to confirm consistency.

Right-hand side evaluated fully before assignment — no read-after-write bug despite in-place mutation. Pure permutation, no key involved.

---

## xtime — Multiply by 2 in GF(2^8)

```python
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
```

Each byte = a polynomial (bit i = coefficient of x^i). "Multiply by x" = shift left by 1. If the top bit (x^7) was set, the shift produces an x^8 term that doesn't fit in 8 bits — reduce it using the field modulus `x^8+x^4+x^3+x+1 = 0` → `x^8 = x^4+x^3+x+1 = 0x1B`. XOR with `0x1B` applies that reduction.

Direct analogy to integer modular arithmetic: "multiply by 2 mod p" sometimes needs `-p` to stay in range — `xtime`'s `^0x1B` is the same idea with XOR as subtraction and `0x1B` as the modulus reduction term. **Not a special case for overflow — it's the whole definition of ×2 in this field.**

`·1` = no-op, `·3 = xtime(x) ^ x`. MixColumns' matrix only has entries 1/2/3, so `xtime` + XOR is the **only primitive needed** for all of MixColumns.

---

## MixColumns

Matrix-multiplies each column by:

```
[2 3 1 1]
[1 2 3 1]
[1 1 2 3]
[3 1 1 2]
```

```python
def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])
```

`t = a0⊕a1⊕a2⊕a3` precomputed once and reused — each output then needs only **one** `xtime` call instead of two (naive matrix form needs `xtime(a0)` *and* `xtime(a1)` for `b0`). `u = a[0]` saved before `a[0]` is overwritten, since `a[3]`'s line needs the original `a0`.

---

## InvMixColumns — Forward + Correction Trick

The inverse matrix (`0E 0B 0D 09`) decomposes as the forward matrix's coefficients (`02 03 01 01`) XOR some multiples of 4. Rather than implementing a second matrix multiplication, pre-apply the "×4 difference" to the data, then run the *same* forward `mix_columns`:

```python
def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))   # "×4" correction
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v
    mix_columns(s)   # forward matrix on corrected data = inverse matrix on original
```

`mix_columns` has no idea it's being used for decryption — same code, different (pre-corrected) input. Code-reuse pattern: if `mix_columns` is correct, `inv_mix_columns` inherits correctness for free.

> Trace check: `[19,5C,F8,1D] --InvMixColumns--> [ED,C7,57,DD]`. `u = xtime(xtime(19^F8)) = A9`. `s0' = 19^A9 = B0`. Running forward `mix_columns` on the corrected column reproduces `b0 = ED`. ✓

---

**See also:** [Symmetric Crypto - AES Structure & Key Schedule](./Symmetric%20Crypto%20-%20AES%20Structure%20%26%20Key%20Schedule.md) · [Symmetric Crypto - AES SubBytes & S-Box](./Symmetric%20Crypto%20-%20AES%20SubBytes%20%26%20S-Box.md) · [Symmetric Crypto - AES Decryption (Inverse Cipher)](./Symmetric%20Crypto%20-%20AES%20Decryption%20%28Inverse%20Cipher%29.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
