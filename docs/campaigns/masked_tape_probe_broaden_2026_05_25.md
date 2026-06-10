# Pre-Registration: Masked Non-Periodic Tape Probe — BROADENED (M4 / arbitrary_null_mask)

**Date:** 2026-05-25
**Author agent:** keystream/tape-model specialist
**Tier:** secondary_exploratory (no GAP-advancing provenance artifact; quarantined — never promoted to a global K4 fact)
**Status:** PRE-REGISTERED before execution. Thresholds, universe, hash rule, and expected-max-null fixed here.
**Extends:** `docs/campaigns/masked_tape_probe_2026_05_25.md` (quadratic / residue-mask slice, CLEAN NULL, universe hash 58d695c7…). This campaign covers the axes that prior run explicitly deferred.

---

## 1. Strategic rationale (why this slice is still OPEN)

The prior slice closed: AZ/A=0, residue masks (`p mod m == r`, m 3..12), quadratic tape
`k[i]=(a+bi+ci^2) mod 26`, |mask|!=24 — 3.85M configs, CLEAN NULL (real best 7/24).
It deferred three orthogonal axes. This campaign closes them as ONE bounded universe:

1. **Convention flip:** add the KA keyword-mixed alphabet (KRYPTOSABCDEFGHIJLMNQUVWXZ);
   demonstrate A=1 indexing is a degenerate relabel absorbed by the polynomial constant
   term (Sec. 5.3) rather than a new axis.
2. **New mask families** (distinct from residue masks): contiguous-block nulls and
   symmetric edge-padding. All `|mask| != 24`, none intersect crib positions 21-33 / 63-73.
3. **New non-periodic tape generators** (distinct from quadratic): cubic polynomial and a
   Fibonacci-style additive recurrence mod 26 (single-use, aperiodic over CT').

Prior eliminations remain non-transferring for the same reasons documented in the prior
pre-reg: E-FRAC-38 (quadratic Bean elimination) is scoped to `direct_ct_pt`; the CT73
algebraic proof and Gromark/Vimark closures are scoped to `ct73_null_extracted` with
|mask|=24 / periodic substitution. This campaign keeps `|mask| != 24` AND keeps every tape
NON-periodic over the message, staying out of both closed regions.

## 2. Alignment model

`arbitrary_null_mask` — some carved CT chars are nulls; true PT shorter than 97; cribs are
CT-position-anchored (carved positions 21-33, 63-73) and remapped into CT' coordinates by
`remap_crib_dict`. Masks do NOT intersect crib positions (`allow_crib_nulls=False`).

## 3. Five-component hypothesis (F, G, N, T, A)

- **F (cipher):** additive — Vigenere `C=(P+K)`, Beaufort `C=(K-P)`, VarBeaufort `C=(P-K)`.
  All three variants. Two alphabets: AZ (A=0) and KA (keyword-mixed, index space).
- **G (keystream gen):** two NON-PERIODIC finite tapes, used once over CT' (length len(CT')):
  - **Cubic:** `k[i] = (a + b*i + c*i^2 + d*i^3) mod 26`, `a in 0..25` (full constant term),
    `b,c,d in 0..9`. 26 x 10 x 10 x 10 = 26,000 keys.
  - **Fibonacci-style:** `k[0]=s0, k[1]=s1, k[i]=(k[i-1]+k[i-2]) mod 26`, `s0,s1 in 0..25`.
    26 x 26 = 676 keys. Aperiodic single-use over the message.
  - Per (mask, variant, alphabet): 26,000 + 676 = 26,676 keys.
- **N (null insertion):** two generative, enumerable families over non-crib positions:
  - **Contiguous block:** a single run of `k` consecutive nulls, `k in {4,6,8,10,12}`, at
    every legal start where the run avoids cribs and stays in [0,97). 260 masks.
  - **Symmetric edge-padding:** `h` head nulls (0..h-1) + `t` tail nulls (97-t..96),
    `h,t in {2,4,6,8,10}`. 25 masks.
  - Union (deduped, |mask|!=24, no crib intersection): **285 unique masks**, sizes
    {4,6,8,10,12,14,16,18,20}.
- **T (tape consumption):** SKIP — tape index `i` runs over extracted CT' positions.
- **A (alignment):** CT' = carved CT minus nulls; PT[i] = decrypt(CT'[i]); cribs checked at
  remapped CT' positions.

## 4. Bounded, enumerable universe + hash

- Masks: 285. Keys: 26,676 (26,000 cubic + 676 fib). Variants: 3. Alphabets: 2 (AZ, KA).
- **Total universe size N = 285 x 3 x 2 x 26,676 = 45,615,960 configs.**
- **Universe SHA-256:** computed and recorded by the sweep at runtime over the sorted
  enumeration of `(sorted(mask) | alphabet.label | variant.value | generator-tag |
  coeff-ranges)`. Printed and saved to the results JSON `universe_sha256` field. This
  pre-reg fixes the GENERATIVE RULE; the script materializes and hashes it deterministically.

## 5. Scoring thresholds (PRE-REGISTERED)

### 5.1 crib_score
0..24 at remapped crib positions (mask-universe-aware — crib_score alone is NEVER promotable).

### 5.2 Analytic max-of-N null (binomial(24, 1/26) over N = 45,615,960), computed BEFORE running:

| crib_score >= k | per-config tail | E[count] over N |
|---|---|---|
| 8  | 2.02e-06 | 92.3 |
| 9  | 1.42e-07 | 6.49 |
| 10 | 8.45e-09 | 0.385 |
| 11 | 4.27e-10 | 0.0195 |
| 12 | 1.84e-11 | 8.4e-04 |
| 13 | 6.75e-13 | 3.1e-05 |
| 14 | 2.11e-14 | 9.6e-07 |

Idealized-null realistic max ~ 10. Masks correlate cribs within a mask, so the empirical
shuffle null (Sec. 7) is the honest calibrator.

### 5.3 A=1 convention robustness (no extra axis)
A=1 indexing relabels every letter index by +1 mod 26 on a 26-letter additive cipher. For
crib match `(C-K) mod 26 == P` (and the Beaufort/VarBeau analogues), a uniform +offset on
the alphabet output is absorbed by the polynomial constant term `a` (and, for Fibonacci, by
a constant shift of both seeds — covered by the full 26x26 seed grid only up to the
recurrence; documented as a known partial). Because `a` sweeps the full 0..25, the SET of
A=1 decryptions for the cubic family is IDENTICAL to A=0. The runner asserts this empirically
(parity test: best crib_score under an explicit +1 output relabel == A=0 best). If it
DIFFERS, the run HALTS and reports a convention-dependent result (escalation rule).

### 5.4 Promotion gate (all required)
`crib_score >= 13` AND `bean_passed == True` AND ngram support AND beats the empirical
shuffle-null max-of-N at p < 0.001. Anything `crib_score >= 13` is a CANDIDATE FOR DISPROOF,
flagged and STOPPED — not promoted.

## 6. Stop rule

EXHAUSTIVE over the declared 45,615,960-config universe. No early stop, no budget cut.
Checkpoint to disk if wall time exceeds 10 min. Records full per-mask maxima and global best.

## 7. Null calibration (mask-universe-aware)

Empirical null: shuffle the carved CT (fixed seeds 2000+b), run the IDENTICAL universe
(285 masks x 26,676 keys x 3 variants x 2 alphabets), record max crib_score and max
bean-passing crib_score per shuffle. B = 20 shuffles. p-value of real best =
`(extreme+1)/(B+1)` where extreme = # shuffles whose max-of-N >= real best.

## 8. Predictions (falsifiable)

- **P1 (null):** real-CT best crib_score <= ~10, indistinguishable from shuffle-null max-of-N.
- **P2 (signal):** if a masked non-periodic tape generated K4, >=1 config has crib_score >= 13,
  bean_passed True, ngram support, exceeding shuffle-null max-of-N at p < 0.001.

Overwhelming prior: P1 holds (clean null). A clean, hash-documented null on these
previously-deferred axes is the intended deliverable.

## 9. Reproduction

```
PYTHONPATH=src python3 -u scripts/_uncategorized/e_masked_nonperiodic_tape_broaden.py
```

Artifacts: `results/masked_nonperiodic_tape_broaden_<timestamp>.json`.
