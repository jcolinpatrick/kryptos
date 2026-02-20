# E-EXPLORER-07: K5-Derived Positional Constraints on K4

**Date:** 2026-02-20
**Agent:** Explorer
**Status:** Analysis complete. No new eliminations. Theoretical framework established.

---

## Summary

K5 is a second 97-character message encrypted by Sanborn using the same method as K4. It "shares coded words at the same positions" as K4's known cribs (EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73). This analysis examines what this constraint implies mathematically and what it eliminates.

## Key Findings

### 1. K5 CT is NOT publicly available
We have no K5 ciphertext to work with. All analysis is theoretical.

### 2. "Coded words at same positions" — most likely interpretation
The plaintext words EASTNORTHEAST and BERLINCLOCK (or equivalent English words) appear at the same positions (21-33, 63-73) in both K4 and K5. The ciphertext differs because different surrounding plaintext produces different output, but the shared words at fixed positions are a design feature.

### 3. Position-dependence (confirmed, not new)
The K5 constraint requires that the cipher at position i depends only on i and a fixed key, NOT on preceding plaintext or ciphertext. This was already proven algebraically. It eliminates:
- Autokey-CT, Chaocipher, Enigma (all state-dependent)

### 4. Transposition is NOT ruled out
K5 uses the same method as K4, so the same transposition (if any) applies to both. This is automatic and places no new constraint.

### 5. Key design converges on "lookup table"
ALL surviving evidence (non-periodic, non-polynomial, position-dependent, reusable, hand-executable, non-readable keystream) converges on:
- **Lookup table** (arbitrary key values per position) — i.e., Sanborn's "coding charts"
- **Running key from unknown text** (equivalent to a text-derived lookup table)

### 6. Vigenere tableau as running key: NOISE
Tested 5 reading orders of the KRYPTOS-keyed Vigenere tableau (rows, columns, diagonal, snake, first-4-rows) as running key sources. Best: 5/24 (NOISE).

### 7. K5 CT would be decisive
When K5 CT becomes available:
- **Depth-of-two attack**: CT4[i] - CT5[i] = PT4[i] - PT5[i] (mod 26), eliminating the key entirely
- **Key recovery at cribs**: decrypt K5 at positions 21-33 and 63-73 using K4's known key values
- **Shared CT test**: if CT4[crib] = CT5[crib], confirms same key schedule for both messages

### 8. Testable prediction
Under Vigenere with shared key, K4 key at crib positions is `BLZCDCYYGCKAZ` (pos 21-33) and `MUYKLGKORNA` (pos 63-73). Decrypting K5 CT at these positions with these key values should yield recognizable English words.

## What's New vs. What Was Already Known

| Finding | New? | Prior evidence |
|---------|------|---------------|
| Position-dependence | No | Algebraic proof from cribs |
| State-dependent ciphers eliminated | No | Already eliminated |
| Transposition not ruled out | No | Already known |
| Key is lookup table / running key | Strengthened | Was primary hypothesis |
| Vigenere tableau as running key | New test | 5/24 = NOISE |
| K5 CT enables depth-of-two | New theoretical result | Untestable without K5 CT |

## Conclusion

The K5 constraint confirms what we already knew and strengthens the convergence toward the "coding charts as lookup table" hypothesis. **No new cipher families are eliminated.** The analysis is primarily valuable as a theoretical framework for when K5 CT becomes available, at which point it would be the single most powerful tool for breaking K4.

## Artifacts
- Script: `/home/cpatrick/kryptos/scripts/e_explorer_07_k5_constraints.py`
- Results: `/home/cpatrick/kryptos/artifacts/explorer_07_k5_constraints.json`

## Repro
```bash
PYTHONPATH=src python3 -u scripts/e_explorer_07_k5_constraints.py
```
