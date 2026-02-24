# Session 16 Report — Trifid Complete Elimination + Lag-7 Structural Exploitation

**Date**: 2026-02-18
**Focus**: Trifid period 16 elimination, lag-7 autocorrelation structural analysis, period-7 key models with transposition.

## Major Results

### E-S-44: Trifid Period 16 — ELIMINATED (partial-triple fix)

**Bug found**: The E-S-42b script only extracted equalities from FULLY-KNOWN Trifid triples. Partially-known triples (2 of 3 elements known) also yield valid coordinate equalities (e.g., if triple (l(E), l(?20), l(A)) → CT_letter, then l(CT_letter) = l(E) is valid regardless of the unknown).

**With fix**: 69 equalities (was 51) → 79 same-cell contradictions (was 0).

**TRIFID 3×3×3 IS NOW COMPLETELY ELIMINATED AT ALL PERIODS 2-97.**

- Artifact: `results/e_s_44_trifid_p16.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_44_trifid_p16.py`

### E-S-45: Lag-7 Structural Exploitation

Identified all 9 lag-7 matching positions. Only ONE (65,72) has both positions in cribs.

**Key finding**: Period-7 Vigenère key preserves English lag-7 structure:
- English plaintext: mean=5.67 lag-7 matches, P(≥9)=12.5%
- Vig + random key: mean=3.48, P(≥9)=0.7% (baseline)
- **Vig + period-7 key: mean=5.69, P(≥9)=12.5%** (English structure preserved)
- Vig + English running key: mean=3.56, P(≥9)=0.9% (no help)
- Vig + period-7 key + width-7 columnar: mean=4.60, P(≥9)=4.3%

**No transposition alone produces elevated lag-7** from random input.

**Implication**: The lag-7 signal is best explained by a period-7 substitution key applied to English plaintext. This doesn't prove period-7, but it's the most natural explanation.

- Artifact: `results/e_s_45_lag7_exploitation.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_45_lag7_exploitation.py`

### E-S-46: Position-Dependent Alphabets — NOISE

Tested Quagmire I-IV, progressive shift, Beaufort variants, and mixed-alphabet autokey with 14+ keywords. 11,114 configs, best 5/24.

**Verdict**: NOISE. Position-dependent alphabets under direct correspondence fail.

- Artifact: `results/e_s_46_position_alphabets.json`

### E-S-47 + E-S-47b: Period-7 Key + Arbitrary Transposition — UNDERDETERMINED

**Model A** (period in PT space): 7.4B valid key combinations, 100% pass rate. Massively underdetermined.

**Model B** (period in CT space): ~8B valid key combinations, 100% pass rate. Also underdetermined.

**Structured transposition** (keyword columnar): best 6/24 = noise.

Both models are underdetermined because arbitrary transposition gives 97! DOF, dwarfing the 24 crib constraints.

- Artifacts: `results/e_s_47_period7_transposition.json`, `results/e_s_47b_model_b.json`

### E-S-48: Joint SA — Transposition + Period-7 Key

**Model A** (20 restarts × 200K steps): Global best 24/24 cribs, qg/c=-3.99 (better than English -4.29), key=RBHCCGS.

**Model B**: Global best 21/24 cribs, qg/c=-4.20, key=ATCCHBM.

**Verdict**: Underdetermination artifact — same as E-S-21. SA with 97-DOF transposition can arrange CT letters into quadgram-pleasing sequences while satisfying period-7 constraints. Output is gibberish, not English sentences.

**Interesting observation**: Model B (period in CT space) is slightly MORE constrained — only 21/24 vs 24/24 for Model A. This might mean Model B is the correct interpretation IF there's a real period-7 component.

- Artifact: `results/e_s_48_joint_sa.json`

## Updated Elimination Status

### Newly eliminated this session
| Family | Result | Method |
|--------|--------|--------|
| Trifid 3×3×3 period 16 | **ELIMINATED** | Partial-triple algebraic constraints |
| Position-dependent alphabets (direct) | **NOISE** (5/24) | 11K configs, 14+ keywords |

### Underdetermination confirmed
| Model | Result | DOF |
|-------|--------|-----|
| Period-7 key + arbitrary σ (Model A) | 100% keys valid | 7 key + 97! trans |
| Period-7 key + arbitrary σ (Model B) | 100% keys valid | 7 key + 97! trans |
| SA with period-7 (Model A) | 24/24, qg=-3.99 | artifact |
| SA with period-7 (Model B) | 21/24, qg=-4.20 | slightly constrained |

## Key Insight: The Underdetermination Wall

This session confirms the fundamental challenge: **any model with free transposition + substitution is underdetermined from 24 cribs + quadgram fitness.** The SA can always find solutions.

To break through, we need:
1. **External constraints** on the transposition (e.g., sculpture physical layout, keyword structure)
2. **Stronger language model** (word segmentation, sentence structure, thematic coherence)
3. **More cribs** (unlikely unless new Sanborn clues emerge)
4. **The lag-7 signal as discriminator**: period-7 key is the most motivated model, but quadgrams alone can't find the RIGHT period-7 key among billions

## Recommended Next Directions

1. **Word-boundary-aware scoring**: Instead of raw quadgrams, use a dictionary-based scorer that requires the plaintext to segment into real English words. This dramatically constrains the search.
2. **Thematic scoring**: Score for presence of thematic words (EGYPT, BERLIN, WALL, TOMB, etc.) as a tie-breaker.
3. **Keyword transposition search**: Instead of arbitrary σ, restrict to keyword-based columnar/double columnar transpositions derived from thematic words. This reduces σ from 97! to ~10^5.
4. **Grid-based transposition from sculpture layout**: Determine the exact grid dimensions of K4 on the copperplate and test grid-derived reading orders.

---
*Session 16 — 2026-02-18 — 6 experiments (E-S-44 through E-S-48)*
