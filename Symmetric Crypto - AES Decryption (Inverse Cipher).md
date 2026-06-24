---
tags: [cryptography, symmetric-crypto, cryptohack, aes]
---

# Symmetric Crypto - AES Decryption (Inverse Cipher)

Decryption = full reversal of encryption's operation sequence (not pairwise swaps), with round keys applied in reverse order (k10 → k0).

---

## General Principle: Full Reverse

If `f = D ∘ C ∘ B ∘ A` (apply A, then B, then C, then D), then `f⁻¹ = A⁻¹ ∘ B⁻¹ ∘ C⁻¹ ∘ D⁻¹` — reverse the *order* of the operations, then invert each one. This is a single global flip of the sequence, not adjacent-pair swaps.

`AddRoundKey` is self-inverse (XOR) — `InvAddRoundKey = AddRoundKey`.

---

## Mapping Encryption → Decryption

Encryption per round: `SubBytes → ShiftRows → MixColumns → AddRoundKey`
Full-reverse + invert each → `AddRoundKey → InvMixColumns → InvShiftRows → InvSubBytes`

| Encryption | Decryption (full reverse) |
|---|---|
| Initial: `AddRoundKey(k0)` alone | **Last** step: `AddRoundKey(k0)` alone |
| Rounds 1–9: `SubBytes→ShiftRows→MixColumns→AddRoundKey(ki)` | Loop ki=9→1: `AddRoundKey(ki)→InvMixColumns→InvShiftRows→InvSubBytes` |
| Round 10 (no MixColumns): `SubBytes→ShiftRows→AddRoundKey(k10)` | **First** step: `AddRoundKey(k10)→InvShiftRows→InvSubBytes` |

---

## The Naming Trap

The decrypt skeleton's `# Initial add round key step` is **not** "just AddRoundKey" — it undoes encryption's entire round 10 (a 3-op block: `AddRoundKey(k10)→InvShiftRows→InvSubBytes`), since round 10 had no MixColumns to undo either. Decrypt's `# final round (skips InvMixColumns)` undoes encryption's standalone initial `AddRoundKey(k0)` — genuinely just 1 operation, nothing else was ever there to skip.

> "Initial"/"final" describe the **shape** of decrypt's own computation (mirroring encrypt's outlier-step / N-1-uniform-rounds / outlier-step shape) — not which encryption step each corresponds to. Decrypt's "initial" undoes encrypt's *final*, and vice versa.

---

## Structure

```python
def decrypt(key, ciphertext):
    round_keys = expand_key(key)   # used k10 → k0

    # state = ciphertext as 4x4 matrix

    # First block — undo encryption round 10
    # AddRoundKey(k10) → InvShiftRows → InvSubBytes

    for i in range(N_ROUNDS - 1, 0, -1):
        # AddRoundKey(k_i) → InvMixColumns → InvShiftRows → InvSubBytes
        pass

    # Last block — undo encryption's initial AddRoundKey
    # AddRoundKey(k0)

    # state → plaintext bytes
```

---

**See also:** [Symmetric Crypto - AES Structure & Key Schedule](./Symmetric%20Crypto%20-%20AES%20Structure%20%26%20Key%20Schedule.md) · [Symmetric Crypto - AES ShiftRows & MixColumns](./Symmetric%20Crypto%20-%20AES%20ShiftRows%20%26%20MixColumns.md) · [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md)
