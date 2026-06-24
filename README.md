# Applied Cryptanalysis

A structured knowledge base covering the mathematics, mechanisms, and attack patterns behind modern cryptography — built through hands-on work with [CryptoHack](https://cryptohack.org) challenges.

These notes prioritise **understanding over memorisation**: every concept explains the *why* behind it, every attack traces back to the assumption it breaks, and every code sample is commented for purpose rather than just syntax.

---

## Topics Covered

### Number Theory
Foundations used throughout all of cryptography.

| Note | Topics |
|------|--------|
| [Number Theory - GCD & Modular Arithmetic](./Number%20Theory%20-%20GCD%20%26%20Modular%20Arithmetic.md) | Euclidean algorithm, extended GCD, finite fields |
| [Number Theory - Fermat & Modular Inverses](./Number%20Theory%20-%20Fermat%20%26%20Modular%20Inverses.md) | Fermat's little theorem, computing inverses |
| [Number Theory - Quadratic Residues](./Number%20Theory%20-%20Quadratic%20Residues.md) | Legendre symbol, Euler's criterion |
| [Number Theory - Tonelli-Shanks](./Number%20Theory%20-%20Tonelli-Shanks.md) | Square roots mod p — full derivation from first principles |
| [Number Theory - Chinese Remainder Theorem](./Number%20Theory%20-%20Chinese%20Remainder%20Theorem.md) | CRT construction, worked example, implementation |
| [Number Theory - Modular Binomial](./Number%20Theory%20-%20Modular%20Binomial.md) | Frobenius endomorphism attack on structured RSA moduli |

### Symmetric Cryptography (AES)
AES internals from scratch, then the real-world modes and attacks.

| Note | Topics |
|------|--------|
| [AES Structure & Key Schedule](./Symmetric%20Crypto%20-%20AES%20Structure%20%26%20Key%20Schedule.md) | Round structure, confusion/diffusion, Rcon, why MixColumns is skipped in round 10 |
| [AES SubBytes & S-Box](./Symmetric%20Crypto%20-%20AES%20SubBytes%20%26%20S-Box.md) | GF(2⁸) inversion, affine transform, why non-linearity matters |
| [AES ShiftRows & MixColumns](./Symmetric%20Crypto%20-%20AES%20ShiftRows%20%26%20MixColumns.md) | xtime, GF(2⁸) matrix multiplication, InvMixColumns reuse trick |
| [AES Decryption (Inverse Cipher)](./Symmetric%20Crypto%20-%20AES%20Decryption%20%28Inverse%20Cipher%29.md) | Full-reverse principle, naming traps, decryption structure |
| [AES Modes & Weak Key Generation](./Symmetric%20Crypto%20-%20AES%20Modes%20%26%20Weak%20Key%20Generation.md) | ECB determinism, decrypt-oracle vulnerability, CSPRNG vs derived keys |
| [ECB Byte-at-a-Time Attack](./Symmetric%20Crypto%20-%20ECB%20Byte-at-a-Time%20Attack.md) | Full attack with precomputed reference table and batched guessing |
| [CBC Mode & Oracle Attacks](./Symmetric%20Crypto%20-%20CBC%20Mode%20%26%20Oracle%20Attacks.md) | Mode-mixing decrypt attack, IV bit-flipping forgery |
| [Stream Cipher Modes (OFB, CTR & CFB)](./Symmetric%20Crypto%20-%20Stream%20Cipher%20Modes%20%28OFB%2C%20CTR%20%26%20CFB%29.md) | Keystream reuse attacks, broken counter attack |

### RSA
Key generation, why the math works, and attacks on bad parameters.

| Note | Topics |
|------|--------|
| [RSA Fundamentals](./RSA%20-%20Fundamentals.md) | Trapdoor, key generation, φ(N), why e=65537, signatures |
| [RSA Primes & Factoring Attacks](./RSA%20-%20Primes%20%26%20Factoring%20Attacks.md) | Fermat factorisation, Pollard's p−1, ECM |
| [RSA Public Exponent Attacks](./RSA%20-%20Public%20Exponent%20Attacks.md) | e=1 trivial, cube root attack (e=3), why padding matters |

### Diffie-Hellman
| Note | Topics |
|------|--------|
| [Diffie-Hellman](./Diffie-Hellman.md) | Finite fields, generators, discrete log hardness, MITM attacks, parameter downgrade |

### Elliptic Curve Cryptography
| Note | Topics |
|------|--------|
| [ECC Fundamentals](./ECC%20-%20Fundamentals.md) | Curve equation, point addition, scalar mult, ECDLP, ECDH, point compression |
| [ECC Montgomery Curves & Side Channels](./ECC%20-%20Montgomery%20Curves%20%26%20Side%20Channels.md) | Montgomery form, ladder algorithm, cswap, LadderLeak, X25519 |
| [ECC Weak Curve Attacks](./ECC%20-%20Weak%20Curve%20Attacks.md) | Pohlig-Hellman on curves, how to spot weak parameters |
| [ECC MOV Attack (Moving Problems)](./ECC%20-%20MOV%20Attack%20%28Moving%20Problems%29.md) | Smooth/large-prime order split, Weil pairing transfer to finite field DLP |
| [ECC Invalid Generator Attack (Curveball)](./ECC%20-%20Invalid%20Generator%20Attack%20%28Curveball%29.md) | CVE-2020-0601 — forging trusted public keys via custom generator |
| [ECC ECDSA Weak Nonce Attack (ProSign3)](./ECC%20-%20ECDSA%20Weak%20Nonce%20Attack%20%28ProSign3%29.md) | Private key recovery from predictable or reused signing nonce |

### Python Reference
| Note | Topics |
|------|--------|
| [Python - Toolkit](./Python%20-%20Toolkit.md) | zip, comprehensions, XOR helpers, gmpy2, SageMath, bytes/int conversion, concurrency |
| [Python - HTTP Oracle & Concurrency Patterns](./Python%20-%20HTTP%20Oracle%20%26%20Concurrency%20Patterns.md) | Session reuse, ThreadPoolExecutor, retry with backoff |

---

## Navigation

The [Applied Cryptanalysis MOC](./Applied%20Cryptanalysis%20MOC.md) (Map of Content) lists every note and provides a quick-reference table of concepts with one-line summaries — useful as a lookup when you remember the concept but not which note covers it.

---

## Using These Notes

**On GitHub:** all cross-references are clickable links. Browse any note and follow the "See also" links at the bottom to navigate related topics.

**In Obsidian:** clone the repository and open the folder as a vault. Obsidian supports standard markdown links natively, so everything works as-is. If you prefer wiki-link syntax, run a find-and-replace:
- Find: `\]\(\./(.*?)\.md\)` → Replace: `]]` (adjusting the opening bracket)
