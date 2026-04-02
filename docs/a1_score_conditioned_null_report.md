# A1 Score-Conditioned Null Experiment — Final Report

**Date:** 2026-04-01  
**Script:** `scripts/analysis/e_a1_score_conditioned_null.py`  
**Results:** `results/a1_score_conditioned_null.json`

---

## Question

Does the observed low palette diversity in the A1 finding (17 positions, 7 distinct letters) survive under a discovery-process-matched null?

## Answer

**A1 fails under the matched null.**

The SA discovery process, when run on real K4, produces a consensus mask with **11 distinct letters** — well within the null distribution (p=0.30). The original claim of 7 distinct letters at 17 positions cannot be reproduced by the SA and was an artifact of post-hoc position selection.

---

## Pre-Registered Decision Rule

- **SURVIVES:** K4 consensus_distinct < 2.5th percentile of null distribution
- **FAILS:** K4 consensus_distinct ≥ 5th percentile of null distribution  
- **INCONCLUSIVE:** Between 2.5th and 5th, or <30 qualifying nulls

## Observed Values

| Metric | K4 | Null mean | Null 2.5th | Null 5th | p-value |
|---|---|---|---|---|---|
| Consensus distinct (letter-shuffled) | 11 | 12.3 | 10 | 10 | 0.297 |
| Consensus distinct (block-shuffled) | 11 | 12.3 | 10 | 10 | 0.257 |
| Consensus distinct (crib-planted) | 11 | 12.6 | 10 | 10 | 0.178 |
| Min distinct any mask | 12 | 12.4–12.8 | — | — | 0.37–0.51 |
| Position stability (Jaccard) | 0.217 | 0.222–0.227 | — | — | indistinguishable |
| Best SA score | 13 | mode 12–13 | — | — | typical |

**K4's consensus diversity (11) is at the 29th percentile of the letter-shuffled null, the 26th percentile of the block-shuffled null, and the 18th percentile of the crib-planted null. It is not in the tail of any distribution.**

## Critical Finding: The Hardcoded 7-Letter Result Is Not Reproducible

The hardcoded `CONSENSUS_NULL_POSITIONS` in `constants.py` (17 positions with 7 distinct letters) **does not emerge from the SA discovery process.** When the exact SA procedure from `f_consensus_null_v1.py` is replicated:

| Quantity | Hardcoded | SA-discovered |
|---|---|---|
| Consensus distinct | 7 | 11 |
| Letters | {B,G,I,K,O,W,Z} | {B,C,D,E,G,H,K,O,S,T,W} |
| Overlap with hardcoded | 17/17 | 7/17 |
| Jaccard with hardcoded | 1.000 | 0.259 |

The hardcoded positions were a post-hoc selection: all 17 were chosen from the 31 non-crib positions where CT already contains palette letters. The "7 distinct" observation is therefore tautological — it measures a property that was used to select the positions.

## Experimental Design

**SA parameters (exact match to f_consensus_null_v1.py):**
- 30 restarts per CT, 300,000 steps per restart
- T0=0.5, Tf=0.01, exponential cooling
- 24 null positions removed
- KA autokey Vigenère with keyword KRYPTOS
- Consensus = top-17 positions by frequency among masks scoring ≥8/24

**Null families (100 CTs each):**
1. **Letter-shuffled:** Randomize non-crib positions, preserve exact unigram counts
2. **Block-shuffled:** Shuffle 7-character blocks of non-crib positions
3. **Crib-planted:** Random CT letters with real CT preserved at crib positions

**Total compute:** 9,030 SA restarts × 300K steps across 26 workers in 47 minutes.

**Null distribution of consensus_distinct (letter-shuffled):**

```
 10:   9 ( 9.0%)
 11:  20 (20.0%) ◄ K4
 12:  28 (28.0%)  ← mode
 13:  25 (25.0%)
 14:  10 (10.0%)
 15:   7 ( 7.0%)
 16:   1 ( 1.0%)
```

## Score-Conditioned Analysis

Among letter-shuffled nulls with best score ≥12 (matching K4's score of 13):
- 82 out of 100 null CTs achieved this score level
- Score-matched consensus distinct: mean=12.5, K4=11, p=0.265
- **K4 is not unusual even when conditioned on score.**

## Stability Analysis

K4's position stability (mean pairwise Jaccard = 0.217) is indistinguishable from null CTs (mean 0.226). The SA does not converge more strongly on K4 than on random ciphertexts.

## What Went Wrong with A1

1. **Lost provenance:** The 17 hardcoded positions in `constants.py` were introduced 2026-03-23 without a reproducible artifact chain. The specific SA run that produced them is not recoverable.

2. **Circular selection:** All 17 positions happen to be at CT positions containing palette letters {B,G,I,K,O,W,Z}. Since 31 of 73 non-crib positions have palette letters, and we only need 17, the positions were selected FROM the palette — not discovered independently of it.

3. **Naive null model:** The original p-value (2.4 × 10⁻⁵) used a positional null: "draw 17 from 97 positions." This null is dramatically mismatched to the SA discovery process, which searches over non-crib positions guided by a cipher-model objective.

4. **Downstream contamination:** All observations downstream of A1 — BCL enrichment (A2), KA mod-5 (A3), mod-35 table (A5), AP enrichment (A8) — depend on the palette definition and collapse with it.

## Verdict

**A1 fails under the matched null.** The SA-discovered consensus on real K4 has 11 distinct letters, placing it at the 18th–30th percentile across three null families. The claimed 7-letter observation was a post-hoc selection artifact, not a reproducible SA output. The positional p-value of 2.4 × 10⁻⁵ is invalid because the null model was mismatched to the discovery process.

## Recommendations

1. **Remove `CONSENSUS_NULL_POSITIONS` and `NULL_PALETTE` from `constants.py`** or clearly mark them as deprecated/historical with a pointer to this report.

2. **Retire all analyses downstream of A1** (A2 BCL enrichment, A3 KA mod-5, A5 mod-35, A8 AP enrichment) as they depend on the invalidated palette.

3. **Update MEMORY.md** to reflect A1's failure.

4. **A new computational sweep is NOT justified** based on palette diversity. The stego hypothesis as formulated (palette letters at specific positions) is not supported by the SA discovery process.

5. **Running-key from untested source texts** remains the only structurally open computational avenue, independent of A1.

---

## Reproduction

```bash
PYTHONPATH=src python3 -u scripts/analysis/e_a1_score_conditioned_null.py
```

Runtime: ~47 min on 28-vCPU VM. Results: `results/a1_score_conditioned_null.json`.

Master seed: 42. All SA seeds derived deterministically.
