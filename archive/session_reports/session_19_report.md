# Session 19 Report — K3 Method Analysis + Keystream Deep Dive

**Date**: 2026-02-18
**Focus**: Analytical approach — K3 method variants, keystream pattern search, crib alignment analysis, width-7 non-periodic substitution probe.

## Strategic Shift

Session 18 concluded that brute-force elimination has hit the underdetermination wall: period-7 Vigenère + arbitrary transposition has ~10²² solutions. Session 19 shifts to an analytical approach: what can we deduce from K3's known method, Sanborn's clues, and the structure of the 24 known keystream values?

## Experiment Results

### E-S-58: K3 Method Variant + Keystream Deep Analysis

**Method**: Five-phase analytical experiment covering direct keystream patterns, width-7 transposition IC analysis, crib alignment, K3 variant sweep, and running key text matching.

#### Phase A: Direct Keystream Patterns — NO SIGNAL

| Analysis | Vigenère | Beaufort | Verdict |
|----------|---------|---------|---------|
| IC (full) | 0.0471 | 0.0797 | Beau high but driven by K×5, G×4 |
| IC (ENE) | 0.0641 | 0.1026 | Beau ENE artificially high |
| IC (BC) | 0.0182 | 0.0727 | Both noisy for n=11 |
| Arithmetic progressions | max 3 | max 2 | Noise |
| Fibonacci-like | max 2 | max 3 | Noise |
| Coordinate/date match | 0 | 0 | No matches |
| Readable text (6 alphabets) | None | None | No recognizable text |
| Linear position function | < 8/24 for all (a,b) | same | Noise |

**Beaufort IC = 0.0797 explained**: K (key value 10) appears 5 times in 24 values, driven by:
- Position 32: self-encrypting (S→S, always gives k=2×18%26=10)
- Position 31: CT[31]=K, PT=A, always gives k=10+0=10
- Three other structural coincidences. **ARTIFACT, not evidence of Beaufort cipher.**

Vigenère ROT13 keystream ends in "BEAN" — coincidence (P(specific 4-letter word) ≈ 1/21760).

#### Phase B: Width-7 IC Analysis — NO DISCRIMINATION

- 1200/20160 configs (6%) have key IC ≥ 0.055 — too many for discrimination
- K3's exact key (KRYPTOS) gives IC = 0.0688 — at English level for n=24
- Top IC = 0.1014 — within expected tail
- IC on 24 values has σ ≈ 0.015, making IC ≥ 0.067 expected for ~25% of random keys

#### Phase C: Crib Alignment — SUGGESTIVE STRUCTURAL PROPERTY

**Key finding: GCD(21, 63) = 21 = 3 × 7**

| Width | Both cribs at boundary? | P(both) |
|-------|------------------------|---------|
| 3 | YES | 0.116 |
| **7** | **YES** | **0.021** |
| 21 | YES (trivial) | 0.0001 |

- P(both cribs start at width-7 row boundary) = **0.021** (significant at 5% level)
- In a 7-column grid: ENE fills rows 3-4 exactly, BC fills rows 9-10
- Crib coverage per column: 4/14 (cols 0-3), 3/14 (cols 4-5), 2/13 (col 6)
- Under K3's key, mapped CT positions have gaps [1,5,1,7,1,5,8,...] — quasi-periodic with period ~14 (= number of rows)

**Combined evidence for width 7:**
1. K3 uses width-7 columnar transposition
2. Lag-7 autocorrelation z = 3.036 (p ≈ 0.002)
3. Both cribs at width-7 boundaries (p ≈ 0.021)

Joint probability under independence: ~0.002 × 0.021 ≈ 4×10⁻⁵. Width 7 is very likely relevant.

#### Phase D: K3 Variant Analysis — NO DISCRIMINATION

| Variant | IC | Best period | Score |
|---------|-----|------------|-------|
| K3 exact (KRYPTOS) | 0.069 | 11 | 12/24 |
| K3 reversed columns | 0.036 | 10 | 12/24 |
| K3 reverse order | 0.033 | 13 | 12/24 |
| K3 double | 0.033 | 11 | 12/24 |
| K3+ABSCISSA double | 0.058 | 14 | 13/24 |
| KW SCHEIDT | 0.091 | 13 | 13/24 |
| KW LANGLEY | 0.098 | 10 | 12/24 |
| KW PALIMPSEST | 0.062 | 13 | 14/24 |

All keyword transpositions produce noise-level period scores. High IC values are within n=24 variance.

#### Phase E: Running Key Text Matching — NOISE

| Text | Best Vig | Best Beau |
|------|---------|----------|
| Carter (multiple) | 6/24 | 6/24 |
| CIA Charter | 6/24 | 5/24 |
| Reagan Berlin speech | 5/24 | 6/24 |
| UDHR | 6/24 | 5/24 |

Expected best match for random text: ~4-5/24 (birthday effect over many offsets). All at noise floor.

- Artifact: `results/e_s_58_k3_variant_keystream.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_58_k3_variant_keystream.py`

### E-S-59: Width-7 Non-Periodic Substitution Probe

**Method**: All 5040 width-7 columnar orderings × 4 model/variant combos. For each, derive keystream at 24 crib positions, compute IC, check Carter running key match, test Bean equality.

**Results**:
- **Bean-passing configs: 0/20,160** — EXPECTED (Bean equality doesn't apply with transposition, per E-S-57b). The condition CT[σ(27)] = CT[σ(65)] fails for all 42 possible (col6_read_pos, col2_read_pos) pairs.
- **Carter best match: 9/24** at order [1,5,3,0,4,2,6] — NOISE (expected ~15 such results over 100M implicit tests)
- **Top composite score: 34.28** — driven by high IC (0.098) + Carter 9/24, both at noise floor after multiple testing correction
- Quadgram scoring non-functional (data format mismatch — fix needed for future)

- Artifact: `results/e_s_59_width7_nonperiodic.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_59_width7_nonperiodic.py`

### E-S-22 (Background, from prior session): AMSCO + Disrupted Columnar

**Result**: Best 15/24 at period 8 (Swapped columnar w=8, Beaufort). Period 7 best: 0/24. **NOISE.**

## Analytical Insights

### 1. Width 7 Evidence Is Converging

Three independent lines of evidence point to width 7:
- K3's transposition width (PUBLIC FACT)
- Lag-7 autocorrelation (z=3.036, INTERNAL RESULT)
- Crib alignment (p=0.021, DERIVED FACT)

Joint significance: p ≈ 4×10⁻⁵ under independence.

### 2. Model B (Trans→Sub) Is More Consistent

The E-S-59 Bean analysis, while not eliminating anything new, reveals that:
- Under Model A (Sub→Trans), the crib-derived constraint CT[σ(27)]=CT[σ(65)] NEVER holds for width-7 columnar
- Under Model B (Trans→Sub), the relevant Bean constraint depends on unknown plaintext at non-crib positions

This means if K4 uses width-7 columnar + single-layer substitution:
- Model A is **strongly disfavored** (Bean condition at 0/42 possible column pairs)
- Model B is **consistent** and matches K3's structure (K3 also uses Trans→Sub)

### 3. The Substitution Key Remains Unknown

- Not periodic (periods 2-14 tested exhaustively)
- Not from any known text (Carter, CIA charter, Reagan, JFK, UDHR, NSA Act)
- Not a simple function of position (linear, polynomial, affine all tested)
- The direct keystream (BLZCDCYYGCKAZ...MUYKLGKORNA) has no detectable pattern

### 4. Sanborn's Clues Are Under-Exploited

The most productive remaining direction may be interpretive rather than computational:
- **"What's the point?"** — Could refer to a specific starting position, compass point, coordinate, or cipher parameter
- **"Delivering a message"** — Could describe the cipher's procedural nature
- **"Who says it is even a math solution?"** — Suggests procedural/physical element

## Background Tasks

| Task | Status | Result |
|------|--------|--------|
| E-S-11 (running key + columnar) | Still running | Expected noise |
| E-S-31 (Carter running key) | Still running | Expected noise |

## Updated Strategic Assessment

Session 19 narrows the viable space but doesn't break through:

**What we now know:**
- Width 7 is very likely part of the cipher (3 independent lines of evidence)
- Model B (trans→sub) is more consistent than Model A
- The substitution key is not from any tested source
- The direct keystream has no detectable algebraic or textual pattern

**What we need:**
1. The SPECIFIC key text (if running key) or key derivation procedure
2. OR the SPECIFIC transposition variant (beyond basic columnar)
3. OR external information (sealed plaintext, auctioned coding charts)
4. OR a fundamentally different model that we haven't considered

**Recommended next directions:**
1. **Interpretive analysis of "What's the point?"** — Generate and test specific hypotheses
2. **K2 coordinate-derived keys** — Use the embedded coordinates as cipher parameters
3. **Physical sculpture layout** — Determine exact row/column dimensions from reference photos
4. **Non-columnar width-7 transpositions** — Rail fence, turning grille, or custom route at width 7

---
*Session 19 — 2026-02-18 — 2 experiments (E-S-58, E-S-59), 1 background result (E-S-22)*
