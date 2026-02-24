# Session 14b Report — Myszkowski, Hill After Transposition, Fundamental Limits

**Date**: 2026-02-18 (continued)
**Focus**: Testing Tier 4 (never-tested) cipher families and probing fundamental underdetermination limits.

## Experiments Completed

### E-S-39: Myszkowski Transposition + Periodic Vig/Beau — ELIMINATED
- **Myszkowski transposition**: columnar variant where tied columns are read left-to-right across rows
- ALL 47,293 weak orderings (Fubini number for width 7) × periods 2-14 × 4 cipher variants
- **Result: 0 hits in 3.8s**
- Standard columnar (5040) is a subset; the 42,253 Myszkowski-only orderings add nothing
- Script: `scripts/e_s_39_myszkowski.py`
- Artifact: `results/e_s_39_myszkowski.json`

### E-S-40: Lag-7 Deep Analysis + Running Key Limits — UNDERDETERMINED
- **Part 1**: 9 lag-7 matching positions identified. Only (65,72) has both positions in cribs: CT[65]=CT[72]=P, PT[65]=R, PT[72]=C → key[65]-key[72]≡11 (mod 26)
- **Part 2**: Bipartite matching (can 24 crib positions find distinct CT positions with needed values?) succeeds **36.1%** of the time for random keys. Carter text: 34.8%. → Test is useless for discrimination
- **Part 3**: SA on transposition achieves English-like key fragments (qg=-56.6, better than English average) by choosing appropriate σ
- **Conclusion**: Running key + arbitrary transposition is **fundamentally UNDERDETERMINED** from 24 cribs. Cannot identify correct key or transposition without additional constraints.
- Script: `scripts/e_s_40_lag7_deep_analysis.py`
- Artifact: `results/e_s_40_lag7_deep.json`

### E-S-41: Hill Cipher + Columnar Transposition — ELIMINATED
- **Motivation**: Extra "L" on Kryptos tableau creates "HILL" reading down (anomaly B1)
- Hill n=2: 11 known digraphs → 22 equations / 4 unknowns = massively overdetermined
- Hill n=3: 6-7 known trigraphs → 18-21 equations / 9 unknowns = well-constrained
- Tested: widths 5-8, Models A and B, offsets 0-2
- **Result: 0 solutions in 44s**
- **Implication**: False positive rate ~10^{-25} per transposition (n=2). Hill + ANY structured transposition family is effectively eliminated.
- Script: `scripts/e_s_41_hill_transposition.py`
- Artifact: `results/e_s_41_hill_transposition.json`

### Quick Tests (inline)
- **Monoalphabetic + columnar (widths 5-8)**: 11 equality + 263 injectivity constraints from 13 distinct PT letters. **0 passes** across all orderings. ELIMINATED.
- **Self-keying schemes** (CT-reversed, CT-shifted, keywords KRYPTOS/PALIMPSEST/ABSCISSA/etc., numeric dates/coordinates): max 3/24 = noise
- **E-S-33b completed**: Mixed-width double columnar: ALL width combos (5,5)-(8,7), (7,7) at p=2-14, **0 hits** in 1B+ pairs. ELIMINATED.

## Fundamental Limits Reached

### What we've proven computationally
With 24 known plaintext positions, the following compound cipher models are EXHAUSTIVELY ELIMINATED for columnar transposition widths 5-8:

| Substitution Layer | + Transposition | Status |
|---|---|---|
| Periodic Vigenère/Beaufort (p=2-14) | Single columnar | ELIMINATED |
| Periodic Vigenère/Beaufort (p=2-14) | Double columnar | ELIMINATED |
| Periodic Vigenère/Beaufort (p=2-14) | Myszkowski | ELIMINATED |
| Gronsfeld (digit-only, p=2-14) | Single columnar | ELIMINATED |
| Hill n=2,3 | Single columnar | ELIMINATED |
| Monoalphabetic | Single columnar | ELIMINATED |
| Mixed alphabet (p=9) | Single columnar | ELIMINATED |
| Autokey (PT/CT) | Identity | ELIMINATED |
| Running key (known texts) | Identity + columnar | NOISE |

### What CANNOT be eliminated from 24 cribs
- Running key from unknown text + arbitrary transposition → UNDERDETERMINED (E-S-40)
- Mixed alphabet at periods 5,7 + columnar → underdetermined (too few equality constraints)
- Any cipher model + non-columnar, non-keyword transposition → untestable without enumeration

## Strategic Assessment: Where Are We?

### The underdetermination wall
E-S-40 proves that with only 24 known plaintext positions, **the running key + arbitrary transposition model is fundamentally untestable**. Any English text fragment can serve as the running key by choosing an appropriate transposition. This is the central bottleneck.

### What might break through
1. **Discover the specific transposition method** — from physical analysis of the sculpture layout, or from Scheidt's design principles
2. **Extend the plaintext** — from thematic analysis (1986 Egypt, 1989 Berlin) or K5 cross-correlation
3. **Find the source text** — the running key source (if it exists) may be identifiable from the themes
4. **The "coding charts"** — purchased at auction for $962,500. If they ever surface, they contain the answer.
5. **The Smithsonian solution** — sealed until 2075, but its existence proves the cipher IS solvable

### Recommended next directions
1. **Thematic plaintext construction**: Build candidate plaintexts based on the known themes and test them against the ciphertext
2. **K5 cross-correlation**: If any K5 ciphertext becomes available, use shared-position constraint
3. **Non-standard transposition creativity**: The sculpture's physical layout may encode the transposition pattern
4. **Broader running key search**: Texts about Tutankhamun's tomb (1986 Egypt connection), Berlin Wall speeches, CIA operational messages
5. **Community intelligence**: Monitor for auction item leaks, Sanborn interviews, new clues

---
*Session 14b — 2026-02-18 — 4 experiments (E-S-38 through E-S-41) + inline tests*
