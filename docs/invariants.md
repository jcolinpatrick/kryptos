# Ground-Truth Invariants Registry

**Status**: Verified — these invariants MUST NEVER be violated by any code in this repository.

---

## 1. Ciphertext Invariants

| Property | Value | Verification |
|----------|-------|-------------|
| Full CT | `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR` | Import-time assert in k4lab.py, domain.py, k4_constants.py |
| Length | 97 (prime) | `assert len(CT) == 97` |
| First char | `O` | `assert CT[0] == 'O'` |
| Last char | `R` | `assert CT[-1] == 'R'` |
| Character set | A-Z only (uppercase) | `assert CT.isalpha() and CT.isupper()` |
| IC | 0.0361 (below random 0.0385) | Computed, verified in doctor() |

## 2. Crib Invariants (0-indexed positions)

| Crib | Start | End (inclusive) | Length |
|------|-------|-----------------|--------|
| EASTNORTHEAST | 21 | 33 | 13 |
| BERLINCLOCK | 63 | 73 | 11 |
| **Total** | | | **24 positions** |

### Position-by-position map:
```
Pos 21: E    Pos 22: A    Pos 23: S    Pos 24: T    Pos 25: N
Pos 26: O    Pos 27: R    Pos 28: T    Pos 29: H    Pos 30: E
Pos 31: A    Pos 32: S    Pos 33: T
Pos 63: B    Pos 64: E    Pos 65: R    Pos 66: L    Pos 67: I
Pos 68: N    Pos 69: C    Pos 70: L    Pos 71: O    Pos 72: C
Pos 73: K
```

### Self-encrypting positions (CT == PT):
- **Position 32**: CT[32] = PT[32] = `S`
- **Position 73**: CT[73] = PT[73] = `K`

### NOT self-encrypting (verified):
- Position 27: CT = `P`, PT = `R`
- Position 28: CT = `R`, PT = `T`

### Position 74 is NOT a crib:
- BERLINCLOCK ends at position 73 (inclusive). Position 74 is unknown plaintext.

## 3. Bean Constraints

### Equality (1):
| Position A | Position B |
|-----------|-----------|
| 27 | 65 |

`k[27] == k[65]` — The keystream value at position 27 must equal the keystream value at position 65.

Under Vigenere: k[27] = k[65] = 24 (= Y)
Under Beaufort: k[27] = k[65] = 6 (= G)

### Inequalities (21):
```
k[24] != k[28]    k[28] != k[33]    k[24] != k[33]    k[21] != k[30]
k[21] != k[64]    k[30] != k[64]    k[68] != k[25]    k[22] != k[31]
k[66] != k[70]    k[26] != k[71]    k[69] != k[72]    k[23] != k[32]
k[71] != k[21]    k[25] != k[26]    k[24] != k[66]    k[31] != k[73]
k[29] != k[63]    k[32] != k[33]    k[67] != k[68]    k[27] != k[72]
k[23] != k[28]
```

### Verification:
- `k4suite/k4suite/core/cribs.py:verify_bean()` — authoritative implementation
- `k4lab.py` has equivalent logic in `implied_key_values()` + periodicity check

## 4. Alphabet Invariants

| Name | Sequence | Source |
|------|----------|--------|
| AZ (standard) | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` | Standard English |
| KA (Kryptos-keyed) | `KRYPTOSABCDEFGHIJLMNQUVWXZ` | Keyword: KRYPTOS |

Both must:
- Be exactly 26 characters
- Contain each letter A-Z exactly once (bijection)
- KA = keyword_mixed_alphabet("KRYPTOS", AZ)

## 5. Known Vigenere Keystream (at crib positions)

| Crib | Positions | Keystream Letters | Keystream Numeric |
|------|-----------|------------------|------------------|
| ENE | 21-33 | BLZCDCYYGCKAZ | (1,11,25,2,3,2,24,24,6,2,10,0,25) |
| BC | 63-73 | MUYKLGKORNA | (12,20,24,10,11,6,10,14,17,13,0) |

Bean equality verified: k[27] = 24 = Y, k[65] = 24 = Y

### Known Beaufort Keystream (at crib positions):
| Crib | Positions | Keystream Numeric |
|------|-----------|------------------|
| ENE | 21-33 | (9,11,9,14,3,4,6,10,20,10,10,10,11) |
| BC | 63-73 | (14,2,6,6,1,6,14,10,19,17,20) |

Bean equality verified: k[27] = 6 = G, k[65] = 6 = G

## 6. Permutation Convention

**Convention**: `output[i] = input[perm[i]]`

A permutation maps output position to input position. Inverse via `invert_perm()`.

### k4suite block transposition:
- Operates on 24-char blocks (4 full blocks in 97-char CT)
- Remainder (position 96) passes through unchanged
- `unmask_transposition()` applies the **inverse** permutation

## 7. Statistical Observations (verified but not invariants)

| Measurement | Value | Note |
|-------------|-------|------|
| Pre-ENE IC (pos 0-20) | 0.0667 | English-like — possibly different cipher |
| Full CT IC | 0.0361 | Below random |
| Underdetermination | SA trivially achieves 24/24 with 73 free keys | Cipher MUST have structured key gen |

## 8. Structural Constraints

- **K5 exists**: 97 chars, shares coded words at same positions as K4
- This means the cipher is **position-dependent**, NOT state-dependent
- **Eliminates**: Chaocipher, Enigma, and any cipher where key depends on preceding ciphertext/plaintext
- **Implication**: cipher is polyalphabetic substitution with non-periodic, position-dependent key

## 9. Eliminated Hypotheses (verified — do not re-test)

| Hypothesis | Status | Evidence |
|-----------|--------|---------|
| Linear recurrence keystream orders 1-8 | ELIMINATED | Algebraic proof, no solution in Z_26 |
| Affine recurrence orders 1-8 | ELIMINATED | Same proof |
| Polynomial position key k[i]=f(i), degrees 1-20 | ELIMINATED | No solution over Z_26 |
| Columnar transposition + periodic Vigenere (widths 5-10, periods 1-22) | ELIMINATED | ~8M orderings tested both directions |
| Running key from K1-K3 PT/CT, Carter book, Morse | ELIMINATED | At noise floor (5/24) |
| Gromark/Vimark (linear recurrence ≤ order 8) | ELIMINATED | Subsumed by recurrence elimination |
| State-dependent ciphers (Chaocipher, Enigma) | ELIMINATED | K5 position-dependent constraint |
