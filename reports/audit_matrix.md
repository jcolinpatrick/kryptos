# Formal Audit Matrix: Assumption Dependencies Across All Eliminations

**Date**: 2026-02-26
**Context**: First-principles audit of hidden assumptions in 260+ K4 experiments

## Assumptions Under Test

| Code | Assumption | Risk Level |
|------|-----------|------------|
| **A1** | Fixed crib positions (0-indexed: 21-33, 63-73) | **HIGH** — universally required |
| **A2** | Exact crib content (EASTNORTHEAST, BERLINCLOCK) | **HIGH** — universally required |
| **A3** | Additive key model (single mod-26 shift per position) | MEDIUM — required for periodic sub |
| **A4** | Bean constraint validity (k[27]=k[65] + 21 inequalities) | MEDIUM — requires A1+A2+A3 |
| **A5** | Rectangular/standard geometry | LOW — only specific transposition types |
| **A6** | Public-source running key | LOW — only running-key eliminations |
| **A7** | Single-layer cipher | MEDIUM — all Tier 2 direct eliminations |
| **A8** | Position-preserving (CT[i] → PT[i] before any transposition) | **HIGH** — all Tier 2 eliminations |

## Dependency Matrix

✓ = assumption REQUIRED for the elimination to hold
✗ = assumption NOT required (elimination valid even if assumption fails)

### Tier 1: Mathematical Proofs

| Elimination | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Pure transposition only | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ |
| Periodic polyalph (direct, all variants) | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Hill 2×2 / 3×3 / >4 (direct) | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Bean period impossibility (p∈{2-7,9-12,14,15,17,18,21,22,25}) | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| **Full pairwise period impossibility (ALL p=2-26)** | **✓** | **✓** | **✓** | **✗*** | **✗** | **✗** | **✗** | **✗** |
| Progressive key + ANY transposition | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Quadratic/Fibonacci key + ANY trans | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Autokey (PT/CT) + arbitrary trans | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| ADFGVX (length parity proof) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Bifid 5×5 (26 letters in CT) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |

*Full pairwise uses ALL 276 pairwise constraints from 24 crib positions, not just the 22 Bean constraints. Does not require Bean as a separate assumption — derives constraints directly from A1+A2+A3.

### Tier 2: Exhaustive Search (Direct Correspondence)

| Elimination | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Columnar w5-w9 (exhaustive) | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| Columnar w10-w15 (sampled) | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ |
| Double columnar (Bean-compatible widths) | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| Myszkowski widths 5-13 | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ |
| AMSCO/Nihilist/Swapped w8-13 | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| Simple trans families (14K perms) | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ |
| Three-layer Sub+Trans+Sub | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| Mono+Trans+Periodic | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| Vigenère/Beaufort (all periods, direct) | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Gromark/Vimark p=4-7 | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Quagmire I-IV | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Bifid/Playfair/Four-Square/Two-Square | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| VIC/Chain Addition | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Running key (K1-K3 + 15 public texts) | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ | ✓ | ✓ |
| Hill + transposition (E-ANTIPODES-01) | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Gromark/Vimark + trans (E-ANTIPODES-05) | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |

### Tier 3: Bespoke/Physical Experiments

| Elimination | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Misspelling-derived keys | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Sculpture coordinate offsets | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Tableau path/permutation keys | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Antipodes width/geometry ciphers | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ |
| Physical reversal/mirror operations | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ |

### Tier 4: OPEN (Not Eliminated)

| Hypothesis | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Running key from unknown text + trans | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Bespoke physical/procedural cipher | ? | ? | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Non-standard structures | ? | ? | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

## Cascade Analysis: What Breaks If Each Assumption Falls

### If A1 fails (crib positions are wrong):
- **ALL eliminations weaken** — every single entry requires A1
- Bean constraints become invalid (derived from position-specific keystream)
- Non-periodicity proof becomes conditional
- The 669B+ configurations scored by anchored crib become unreliable
- **Mitigation**: E-AUDIT-01 robustness test shows proof is robust to ±3 positional drift for periods ≤23

### If A2 fails (crib content has errors):
- Same cascade as A1 — equally universal
- **Mitigation**: E-AUDIT-01 shows 99.7% of single-letter substitutions preserve the proof
- Adjacent transpositions: 100% robust

### If A3 fails (non-additive key model):
- All periodic polyalphabetic eliminations survive only as "within additive family"
- Bean constraints become non-inferable
- Non-periodicity proof becomes family-specific
- **Impact**: ~60% of Tier 1-2 eliminations become conditional
- **Remaining valid**: Bifid/Playfair (structural), ADFGVX (parity), pure transposition, VIC/Chain

### If A4 fails (Bean invalid — follows from A3 failure):
- Universal period impossibility proof loses 17 of 25 eliminated periods
- Progressive/Quadratic/Fibonacci key proofs all fail
- Autokey structural proof fails
- Multi-layer eliminations weaken
- **Impact**: ~40% of Tier 1 proofs become conditional

### If A7 fails (multi-layer cipher):
- ALL Tier 2 single-layer exhaustive searches become "eliminated as single layer only"
- These methods remain OPEN as one layer of a multi-layer system
- **Impact**: Most Tier 2 eliminations become conditional
- **Already known**: This is the "OPEN as one layer of multi-layer" caveat in elimination_tiers.md

### If A8 fails (non-positional correspondence):
- ALL Tier 2 direct-correspondence searches become conditional
- Methods that tested CT[i]→PT[i] mapping don't cover transposed indexing
- **Impact**: Entire Tier 2 exhaustive search space becomes conditional
- **Mitigation**: Tier 1 proofs that include "ANY transposition" (Bean period proof) are NOT affected

## Summary Statistics

| Assumption | Required by | % of all eliminations |
|---|---|---|
| A1 (fixed positions) | 54/54 Tier 1-3 | 100% |
| A2 (exact content) | 54/54 Tier 1-3 | 100% |
| A3 (additive key) | ~35/54 | ~65% |
| A4 (Bean valid) | ~22/54 | ~41% |
| A5 (rectangular) | ~18/54 | ~33% |
| A6 (public text) | 1/54 | ~2% |
| A7 (single layer) | ~30/54 | ~56% |
| A8 (positional) | ~25/54 | ~46% |

## New Result from E-AUDIT-01

The full pairwise constraint analysis (using ALL 276 pairwise constraints from 24 crib positions, not just Bean's 22) eliminates ALL periods 2-26 under the additive key model. This is strictly stronger than the Bean-only proof (which left 8 periods surviving). The full pairwise proof:
- Eliminates {8, 13, 16, 19, 20, 23, 24, 26} in addition to Bean's eliminations
- Is robust to 97.1% of all single-perturbation tests
- Only periods 24-26 resurrect, and only under positional drift or deletion
- No period ≤23 ever resurrects under any single perturbation
