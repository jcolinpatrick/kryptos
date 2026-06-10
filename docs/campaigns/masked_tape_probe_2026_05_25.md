# Pre-Registration: Masked Finite Non-Periodic Tape Probe (M4 / arbitrary_null_mask)

**Date:** 2026-05-25
**Author agent:** keystream/tape-model specialist
**Tier:** secondary_exploratory (no GAP-advancing provenance artifact; quarantined — never promoted to a global K4 fact)
**Status:** PRE-REGISTERED before execution. Thresholds and expected-max-null fixed here.

---

## 1. Strategic rationale (why this slice is OPEN)

Every relevant prior elimination is scoped to a NARROWER alignment model than the
one tested here (session briefing 2026-05-25 ASSUMPTION BOUNDARIES):

- E-FRAC-38 BEAN-eliminates the quadratic key `k[i]=ai^2+bi+c` — but the proof
  derives Bean from the **direct CT97 / transposition** assumption
  (`align: direct_ct_pt`). It does NOT transfer when Bean is re-derived per-mask
  on an extracted CT' of length != 73.
- The CT73 algebraic proof closes **24-null masks -> length-73 + periodic
  substitution** (`align: ct73_null_extracted`). Avoided here: every mask has
  `|mask| != 24` (PT length != 73), and the keystream is **non-periodic** over
  the message (a single-use finite tape, M4), not a repeating block.
- Gromark/Vimark orders 1-8 closed on 73-char CT (`align: ct73_null_extracted`).
  Avoided: PT length != 73 and the generator is a polynomial keystream, not a
  lagged-recurrence Gromark/Vimark primer.

Novelty axes (both required by task): NON-periodic finite tape AND null counts != 24.

## 2. Alignment model

`arbitrary_null_mask` — some carved CT chars are nulls; true PT shorter than 97;
cribs are CT-position-anchored (carved positions 21-33, 63-73) and remapped into
CT' coordinates by `remap_crib_dict`. Masks do NOT intersect crib positions
(`allow_crib_nulls=False`, kernel default invariant #2).

## 3. Five-component hypothesis (F, G, N, T, A)

- **F (cipher):** additive — Vigenere `C=(P+K)`, Beaufort `C=(K-P)`,
  VarBeaufort `C=(P-K)`. All three variants. Alphabet A=0 (AZ). [Convention robustness
  note: AZ only this run; A=1/KA deferred — see limitations.]
- **G (keystream gen):** finite NON-PERIODIC tape `k[i] = (a + b*i + c*i^2) mod 26`,
  `i` = position in CT' (0-indexed), `a,b,c in {0..25}`. Tape length = len(CT') so it
  is used once and never repeats (genuinely aperiodic over the message). Hand-executable.
- **N (null insertion):** nulls at carved positions `p in noncrib` with
  `p mod m == r`, for `m in {3..12}`, `r in {0..m-1}`. Generative, enumerable,
  hand-checkable regular-skip rule.
- **T (tape consumption):** SKIP — the tape advances only at non-null (extracted)
  positions; index `i` runs over CT' positions. (Equivalent here to indexing the
  polynomial on extracted coordinates.)
- **A (alignment):** CT' = carved CT with null positions removed; PT[i] = decrypt(CT'[i]);
  cribs checked at remapped CT' positions.

## 4. Bounded, enumerable universe + hash

- **Masks:** 73 unique masks (dedup of m in {3..12} x r in {0..m-1} over the 73
  non-crib positions, dropping empty masks and the single |mask|==24 mask). All
  `|mask| != 24`; sizes 5..25 (PT lengths 72..92), none touch cribs.
- **Keys:** 26^3 = 17,576 quadratic keys (a,b,c).
- **Variants:** 3.
- **Total universe size N = 73 x 17,576 x 3 = 3,849,144 configs.**
- **Universe SHA-256:** computed and recorded by the sweep at runtime (over the
  sorted list of `(sorted(mask) | variant | a,b,c)` tuples); printed and saved to
  the results JSON `universe_sha256` field. This pre-reg fixes the GENERATIVE RULE;
  the script materializes and hashes it deterministically.

## 5. Scoring thresholds (PRE-REGISTERED)

- `crib_score`: 0..24 at remapped crib positions (mask-universe-aware — crib_score
  alone is NEVER promotable, invariant #5).
- **Expected max-of-N crib_score under binomial(24, 1/26) null over N=3,849,144:**
  expected count of configs with crib>=9 is 0.55; crib>=10 is 0.033; crib>=13 is
  2.6e-6. So under the idealized null the realistic max is ~9-10. An empirical
  shuffle null (Sec. 7) calibrates the true max.
- **Promotion gate (all required):** `crib_score >= 13` AND `bean_passed == True`
  AND `ngram_score` above the 73-char floor (-4.0/char proxy; we report ngram but
  use it as support, not a hard pre-set floor on variable-length PT) AND the candidate
  beats the empirical shuffle-null max-of-N at p < 0.001 after the implicit
  N-multiplicity already baked into the max-of-N statistic.
- **Anything `crib_score >= 13`** is treated as a CANDIDATE FOR DISPROOF, checked
  against the empirical null and Bean — not a solution.

## 6. Stop rule

EXHAUSTIVE over the declared universe (all 3,849,144 configs evaluated). No early
stop, no budget cut. The sweep records the full top-K and per-(bean_passed) maxima.

## 7. Null calibration (mask-universe-aware)

Empirical null: shuffle the carved CT (fixed seed), run the IDENTICAL universe
(same 73 masks x 17,576 keys x 3 variants), record the max crib_score and the
distribution. Repeat for a small number of shuffles to estimate the null max-of-N
distribution. p-value of the real best = fraction of shuffle runs whose max-of-N
crib_score (with the same Bean/ngram gate) >= the real best. `(extreme+1)/(B+1)`.

## 8. Predictions (falsifiable)

- **P1 (null prediction):** Under H0 (no masked-tape signal), the real-CT best
  crib_score is <= ~10 and indistinguishable from the shuffle-null max-of-N.
- **P2 (signal prediction):** If a masked quadratic tape generated K4, at least one
  config has crib_score >= 13 with bean_passed True AND ngram support, exceeding the
  shuffle-null max-of-N at p < 0.001.

Overwhelming prior: P1 holds (clean null). A clean, hash-documented null on this
previously-open slice is the intended deliverable.

## 9. Reproduction

```
PYTHONPATH=src python3 -u scripts/_uncategorized/e_masked_quadratic_tape_probe.py
```

Artifacts: `results/masked_quadratic_tape_probe_<timestamp>.json`.
