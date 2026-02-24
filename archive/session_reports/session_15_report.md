# Session 15 Report — Fractionation Complete Elimination + Thematic Extension

**Date**: 2026-02-18
**Focus**: Cross-group algebraic elimination of Bifid/Trifid at all remaining periods; thematic plaintext extension under identity + Vigenère.

## Major Results

### E-S-42: Bifid 6×6 — COMPLETE ELIMINATION (ALL periods 2-97)

**Method**: Cross-group algebraic constraint propagation using union-find.

Previous work (Session 10, E-S-05) eliminated Bifid 6×6 at periods 2-8 and 11 using single-group same-cell contradictions. Periods 9, 10, 12+ survived because single groups lacked sufficient crib coverage.

**Key Insight**: Cross-group constraints provide additional equations. At period 9, group 7 (pos 63-71) is fully known (9/9 PT chars). Combined with group 3 (pos 27-35, 7/9 known), the algebraic chain is:

1. Group 7 pairs 5+6: B, R, T forced into same column (call it `f`) → `rB ≠ rT`
2. Group 7 pair 3: P's column = rN = rB
3. Group 3 pair 1: `sq⁻¹(rR, rT) = P` → `rT = cP = rB`
4. **Contradiction**: `rT = rB` but `rT ≠ rB` (from step 1)

Both standard (rows-then-cols) and reverse (cols-then-rows) conventions produce contradictions.

**Tested periods**: 2-97 (full range). **ALL eliminated** under both conventions.

- Artifact: `results/e_s_42_bifid6x6_extended.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_42_bifid6x6_extended.py`

### E-S-42b: Trifid 3×3×3 — NEAR-COMPLETE ELIMINATION (periods 2-97 except 16)

**Method**: Same cross-group union-find approach, extended to 3D cube coordinates.

**Period 9 proof (pigeonhole)**:
1. Group 7 + Group 3 cross-constraints force `lR = lL` (via chains through 6 equations)
2. With `lR = lL`: letters T, L, C, P are all at cube position `(lL, lL, *)`
3. Pigeonhole: 4 distinct letters need 4 distinct values from {0,1,2} → **IMPOSSIBLE**

**Period 16**: SOLE SURVIVOR — insufficient cross-group constraints for contradiction.

**Tested periods**: 2-97. All eliminated except period 16.

- Artifact: `results/e_s_42b_trifid_extended.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_42b_trifid_extended.py`

### E-S-43: Thematic Plaintext Extension — NOISE

Tested 193 thematic words/phrases from K4's known themes (1986 Egypt, 1989 Berlin Wall, "delivering a message", "what's the point?", Kryptos vocabulary, Carter's tomb, compass directions) at all valid positions in the ciphertext.

**Under identity transposition + Vigenère**:
- 10,196 valid placements evaluated
- Period-7 consistency: **0/7 for ALL placements**
- No placement reduces key entropy below baseline (3.657 vs 4.700 random)
- English fragments in derived key are consistent with random expectation

**Verdict**: NOISE. Confirms identity transposition is NOT the model (consistent with all prior evidence of a transposition layer).

- Artifact: `results/e_s_43_thematic_extension.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_43_thematic_extension.py`

## Updated Elimination Landscape

### Cipher families now COMPLETELY eliminated (direct + transposed + all periods)

| Family | Periods Tested | Result |
|--------|---------------|--------|
| Bifid 5×5 | N/A | IMPOSSIBLE (26 letters, 25 cells) |
| Bifid 6×6 | **2-97** | **ELIMINATED** (cross-group algebraic) |
| Trifid 3×3×3 | 2-15, 17-97 | ELIMINATED (period 16 sole survivor) |
| Hill n=2,3,4 | All offsets | ELIMINATED |
| Monoalphabetic | + columnar 5-8 | ELIMINATED |
| ADFGVX | N/A | STRUCTURALLY IMPOSSIBLE (doubles length) |
| Straddling checkerboard | N/A | STRUCTURALLY IMPOSSIBLE (digit output) |
| Nihilist | N/A | STRUCTURALLY IMPOSSIBLE (digit output) |

### What remains viable

1. **Running key from unknown text** + specific transposition (UNDERDETERMINED from 24 cribs)
2. **Polyalphabetic with non-periodic key** + transposition (tested families exhausted)
3. **Trifid 3×3×3 period 16** (sole algebraic survivor; may still fail under direct search)
4. **Physical/procedural method** ("not dependent on heavy mathematics")
5. **Position-dependent alphabets** (Scheidt's "change the language base")
6. **Turning grille** (only 2M MC samples of 4^25 space)
7. **Mixed alphabet period 5**: 2 orderings survive out of 5040

### Structural constraints on the cipher

The cipher must:
- Preserve message length (97 in, 97 out)
- Use the standard 26-letter alphabet (all 26 appear in CT)
- Be position-dependent, not state-dependent (K5 constraint)
- Have non-periodic key generation (algebraic proof)
- Be executable by hand (Sanborn/Scheidt requirement)
- NOT be any single-layer classical cipher (all tested)
- NOT be Bifid or Trifid at any testable period

This severely limits the remaining cipher families to:
- **Running key ciphers** (the key IS plaintext from another source)
- **Custom/bespoke methods** designed specifically for Kryptos
- **Physical reading-order transpositions** based on the sculpture layout

## Recommended Next Directions

1. **Trifid period 16 direct search**: Use the partially-known groups to constrain a 3×3×3 cube search. The search space is smaller than the algebraic check suggests.
2. **Sculpture physical layout analysis**: Determine the exact row/column structure of K4 on the copperplate. The reading order may BE the transposition.
3. **Running key + specific transposition**: If we assume the running key is from Carter's "Tomb of Tutankhamun" AND the transposition is keyword-based (KRYPTOS, etc.), the compound search is feasible.
4. **Community monitoring**: The Kobek/Byrne solution exists but is sealed. New auction items or Sanborn statements could provide breakthrough information.

---
*Session 15 — 2026-02-18 — 3 experiments (E-S-42, E-S-42b, E-S-43) + period extensions*
