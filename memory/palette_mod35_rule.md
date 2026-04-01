# Palette Null Position Selection Rule — (pos%7, pos%5) Table

## Date: 2026-03-15, UPDATED 2026-03-16

## Scripts
- `scripts/campaigns/e_palette_position_rule_hunt.py` -> `results/palette_position_rule_hunt.json`
- `scripts/campaigns/e_palette_mod35_tiebreaker.py` -> `results/palette_mod35_tiebreaker.json`
- `scripts/campaigns/e_palette_ka_row_extremeness.py` -> `results/palette_ka_row_extremeness.json`
- `scripts/analysis/e_mod35_table_derivation.py` -> `results/mod35_table_derivation.json`
- `scripts/analysis/e_mod35_table_verification.py` (verification + significance)
- `scripts/analysis/e_mod35_debug_discrepancy.py` (debug trace)

## IN-SAMPLE POST-HOC FIT: (pos%7, pos%5) Cell Table Classifies All 17 Consensus Null Palette Positions

> **Audit note (2026-04-01):** This is a Level C descriptive anomaly — a post-hoc
> in-sample fit discovered by searching the data. Leave-one-out cross-validation on the
> public site shows 47% accuracy (below 49% baseline), meaning this table has zero
> predictive power. The "35/35" classification is descriptive, not generative. The
> (7,5) moduli are thematically motivated (KRYPTOS/SEVEN) but the null calibration
> for how often random labels produce perfect separation under some mod pair is pending.

### The Rule (35/35 in-sample fit — no holdout validation)
A palette position p (where CT[p] in {B,G,I,K,O,W,Z}) is a consensus null if and only if:

1. The (p%7, p%5) cell is classified as "null" in the 7x5 table below, OR
2. The (p%7, p%5) cell is "mixed" AND this is the FIRST palette position in that cell (lowest p)

### The 7x5 Classification Table (KRYPTOS x SEVEN)
```
       S(0)  E(1)  V(2)  E(3)  N(4)    <- SEVEN[pos%5]
K(0):   ?     R     R     -     N       <- KRYPTOS[pos%7]
R(1):   N     N     -     N     -
Y(2):   R     R     N     ?     -
P(3):   R     R     N     R     N
T(4):   -     R     -     R     N
O(5):   N     -     ?     -     R
S(6):   N     -     R     R     R
```
N=always null, R=always real, ?=mixed (first=null, later=real), -=no palette position

### Classification counts
- 10 pure-null cells (10 cells, 14 positions, all null)
- 13 pure-real cells (13 cells, 15 positions, all real)
- 3 mixed cells (3 cells, 6 positions: 3 null + 3 real)
- 9 empty cells (no palette position at that (p%7,p%5) value)

### The 3 Mixed Cells — Tiebreaker Details
| Cell (p%7,p%5) | NULL pos | NULL CT | REAL pos | REAL CT |
|---------------|----------|---------|----------|---------|
| (0,0)         | 0        | O       | 70       | Z       |
| (2,3)         | 58       | W       | 93       | K       |
| (5,2)         | 12       | B       | 47       | Z       |

Three tiebreaker rules all work:
1. **Earlier position = null** (all 3 null positions are lower than their paired real)
2. **Lower grid row = null** (all 3 null positions are in earlier grid rows)
3. **KA_row not extreme = null**: Null letters have KA_row in {1,4} (inner rows of Polybius grid); Real letters have KA_row in {0,5} (first/last row). This is content-based rather than position-based.

### Structural Interpretation
- The 7x5 grid corresponds to KRYPTOS (period 7) x SEVEN (period 5)
- lcm(7,5) = 35, so the pattern repeats with period 35
- K4 has 97 positions: 97 = 2*35 + 27 (2 full cycles + partial third)
- Mixed cells arise where the same (p%7,p%5) value appears multiple times in different cycles
- "First occurrence = null" tiebreaker: the null-insertion algorithm processes positions forward

### What Does NOT Work (Negative Results from Exhaustive Search)
- No perfect (a*pos + b) mod M rule for any M <= 31
- No perfect (a*KA(CT) + b*pos) mod M rule for any M <= 14
- No perfect pair-of-features mod M rule (tested ALL 13 features x 4 operations x 6 moduli)
- No perfect triple-feature mod M rule (tested all key feature triples)
- No Beaufort(KRYPTOS,SEVEN) output mod M perfectly separates N/R cells
- No modular arithmetic on (KW_AZ+SV_AZ) or (KW_KA+SV_KA) separates the cells

### Comprehensive Table Generation Search (2026-03-16) — NEGATIVE

**Target:** The 7x5 table as a 35-bit number = 19132483216 (binary: 10001110100011000101000011010010000).

**Number properties:** target mod 7 = 0, target mod 97 = 1, target mod 73 = 13, target mod 26 = 2. Factors: 2^4 * 7 * 11^2 * 1,411,783.

**14 approach families tested, 8 exact matches found (all cipher-based), ZERO from arithmetic/binary/geometric rules:**

| Approach | Configs Tested | Best Distance | Exact Matches |
|----------|---------------|---------------|---------------|
| Linear (a*r+b*c+d) mod M + threshold | ~500K | 3 | 0 |
| Keyword tableau (cipher output set) | ~2K words x 3 variants | 0 | **8** |
| Binary number encoding | 1,482 | 6 | 0 |
| Polybius-based | N/A (structurally impossible) | N/A | 0 |
| Diagonal/stripe (a*r+b*c+d) | ~283K | 5 | 0 |
| Letter identity rules | ~1K | 6 | 0 |
| Installation constant arithmetic | 16,456 | 5 | 0 |
| Threshold column-by-column (all M) | all M 2-35 | no valid M | 0 |
| Multiplicative | ~2K | 7 | 0 |
| Quadratic | ~150K | 4 | 0 |
| Checkerboard/XOR | ~5K | 6 | 0 |

**The 8 exact matches:**
All are of the form: compute Cipher(KRYPTOS[pos%7], WORD[pos%5]) on some alphabet, get an output letter. If the output letter falls in a specific null set, the cell is null. If in the complement, real. This produces perfect 26/26 separation on occupied cells.

| Word | Alphabet | Variant | Null Letters (count) |
|------|----------|---------|----------------------|
| TOWER | AZ | Vigenere | C,D,N,R,S,T,U,V,Y,Z (10) |
| TOWER | AZ | VarBeau | B,C,F,G,H,I,N,X,Y (9) |
| CHART | AZ | Beaufort | D,I,M,N,O,P,Q,T,U,Y (10) |
| LAYER | KA | Vigenere | D,H,I,J,K,P,Q,R,Y,Z (10) |
| LAYER | KA | VarBeau | D,E,F,J,K,R,S,W,X,Z (10) |

**Near misses (dist=1):** SOUTH (AZ_beau), HEAST (AZ_beau) -- 25/26.

### NULL CALIBRATION (2026-04-01): NOT SIGNIFICANT

**500K random 17/35 labelings tested: 100% achieve perfect separation under SOME
mod pair with product ≤ 97.** The specific pair (7,5) achieves 0/500K, but since
the search was over all 268 mod pairs, the relevant null is "any pair works" —
and this is trivially true. The 35/35 in-sample fit is expected, not unusual.

Combined with LOO-CV accuracy of 47% (below 49% baseline), the KRYPTOS×SEVEN
table has zero evidential value. It is retained as a Level D exploratory pattern
for transparency only.

Script: `scripts/analysis/e_mod35_null_calibration.py`

### STATISTICAL SIGNIFICANCE: NONE (confirmed by null calibration)
- **Exhaustive enumeration**: ~58,682 / 11,881,376 AZ words (0.49%) produce perfect separation
- For KA: ~41,444 / 11,881,376 (0.35%)
- Many English words match each variant (hundreds)
- Individual word matches are NOT significant (p ~ 1/200)
- Thematic resonance (TOWER = installation shape, CHART = coding chart, LAYER = two layers) is suggestive but not dispositive

### Null letter sets have NO simple structure
- Not threshold-based (not "output < T")
- Not Polybius-row or column based
- Not contiguous in any alphabet ordering
- Effectively arbitrary partitions of the 18 distinct output values

### Updated Open Questions
1. ~~What generates the 7x5 classification table?~~ **RESOLVED (partial):** Cipher operations KRYPTOS x WORD can generate it, but ~0.5% of words work. The table may be a hand-written lookup table rather than algorithmically derived.
2. Does the table extend to predict the 7 VARYING null positions? (No -- varying positions are NOT palette positions.)
3. Can the "first occurrence" tiebreaker be tested with a cipher model to produce better than 15/24?
4. **RESOLVED**: Combined significance via Fisher's method (palette p ≈ 3.0 × 10⁻⁵ + BCL keystream p = 6.3 × 10⁻⁴) = p ≈ 3.5 × 10⁻⁷. Joint MC (10M trials): 0 co-occurrences → p < 10⁻⁷. Strongly significant.

### Connection to Prior Findings
- The col7_column=1 all-null finding (5/5, p=0.019) is EXPLAINED by this table: all 5 palette positions at pos%7=1 fall in pure-null cells (1,0), (1,1), (1,3).
- The col%8 in {0,1} all-null finding (8/8, p=0.001) is partially explained: 5 of those 8 positions are in col7_column=1 pure-null cells. The remaining 3 are in cells (0,4)=null, (5,0)=null, (6,0)=null -- all pure-null.
