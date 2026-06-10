# Pre-registration — Quagmire III tableau-axis completion (C1/C5 coverage debt)

**ID:** `f_quagmire_tableau_axis_completion_2026_06_09`
**Date frozen:** 2026-06-09 (before any dispatch; thresholds in this file are frozen)
**Runner:** `scripts/campaigns/f_quagmire_tableau_axis_completion_2026_06_09.py`
**Status at freeze:** not yet run.

---

## 1. What debt this pays (provenance)

The 2026-05-28 `k4-dynamic-solve-v1` run recorded a [DERIVED FACT]
(`results/workflows/k4_dynamic_solve/20260528T222343Z/final_report.md:151`):

> The KRYPTOS-tableau pinning in C1 and C5 is a DSL limitation (no diagonal
> ct==pt multi-value sweep), NOT a tested negative.

Five Quagmire III tableau keywords — **PALIMPSEST, ABSCISSA, LATITUDE,
MAGNETIC, COMPASS** — were proposed (h12 expected_cardinality 28,080) but
never tested, because ParamRange axes are independent Cartesian and the
dispatcher (correctly) aborts a whole spec on the first off-diagonal
`ct_kw != pt_kw` binding. The report's follow-up #3 (single-value dispatches
for the 5 tableaus) was never executed (verified 2026-06-09: no matching
entry in `exhaustion_log.json`, `results/workflows/`, `results/dsl_jobs/`,
or `docs/campaigns/`).

**Toolchain fix enabling this cell (landed 2026-06-09, this session):** the
quagmire translator now accepts a `tableau_keyword` param expanding to the
identical ct==pt pair for `quagmire_iii` (mutually exclusive with explicit
ct/pt keyword params; invalid for `quagmire_iv`; off-diagonal abort semantics
for explicit lists intentionally unchanged). TDD regression tests:
`kryptosbot/tests/test_quagmire_tableau_sweep.py` (9 tests; full kryptosbot
suite 2650 passed / 1 skipped).

**Overlap check (disproof-protocol step 1, done pre-freeze):**
`f_quagmire_cross_alphabet_v1` (cross-alphabet Q2/Q1 modes — different
mechanism), `f_q2_indicator_sweep_v1` (Quagmire II *autokey* on null-extracted
CT73 — different mechanism and alignment model), `masked_quagmire_iii_probe_2026_05_25`
(masked cell — different alignment model), `f_w10_quagmire_iii_v1` (w10
Bean-survivor columnar context). None sweeps the Quagmire III tableau axis on
the h12/h3 shapes. The dispatcher's substring overlap heuristic will still
flag family overlap; both specs carry `override_exhaustion=True` with this
paragraph as justification.

## 2. Universe (frozen; exhaustive — stop rule = full enumeration)

**New-cell Arm A1 (C5 / h12 shape — decoupled-period Quagmire III, direct):**
one `quagmire` layer, alphabet AZ:
- `tableau_keyword` ∈ {PALIMPSEST, ABSCISSA, LATITUDE, MAGNETIC, COMPASS} (5)
- `period_keyword` ∈ {CIA, WEST, EAST, NORTH, SOUTH, TIME, CLOCK, LIGHT, NSA,
  RED, ZONE, GRID, CODE, KEY, ROW, ARC, SUN, DIAL, TICK, HOUR, WIND, POLE} (22 — verbatim from spec_h12)
- `indicator` ∈ {K, A, R} (3)
- `variant` = quagmire_iii
- `crib_alignment = direct_positional`. **Documented decision:** the original
  h12 declared `free`, but at run time (2026-05-28) free was unimplemented and
  the verdict was effectively computed anchored (Lever B1 landed 2026-05-31).
  This cell completes the *effective* statistic of the original verdict. A
  free-scored tier is NOT part of this cell (listed under scope-not-eliminated).
- Cardinality: 5 × 22 × 3 = **330**.

**New-cell Arm B1 (C1 / h3 shape — route outer × Quagmire III inner,
post-transposition):** two layers:
- `route_boustrophedon`: `width` ∈ {7, 14} × `vertical` ∈ {false, true} (4)
- `quagmire`: `tableau_keyword` ∈ same 5; `period_keyword` ∈ {PALIMPSEST,
  ABSCISSA, KRYPTOS, CLOCK, BERLIN, NORTHEAST} (6 — verbatim from spec_h3);
  `indicator` = K; `variant` = quagmire_iii
- `crib_alignment = post_transposition` (crib-scoring anchored after route
  undo; Bean frame per AUDIT-5 — with a non-additive inner, Bean is expected
  N/A / context-only: `_keystream_frame_ct` requires a trailing additive).
- Cardinality: 4 × 5 × 6 × 1 = **120**.

**Total new-cell universe: 450 configs.** Spec/universe hashes recorded by the
dispatcher at run time and copied into the summary artifact.

**Replication controls (NOT part of the closure claim):**
- A0: re-dispatch spec_h12's exact explicit-pin shape (ct/pt = KRYPTOS, 66
  configs) with `crib_alignment=direct_positional` (see Arm A1 note). Gate:
  best kernel-verified crib_score == **5** (original: period=CIA, indicator=A).
- B0: re-dispatch spec_h3 verbatim (KRYPTOS tableau, 24 configs,
  post_transposition). Gate: best crib_score == **4** (original: width=14,
  vertical=false, period=KRYPTOS). Bean may differ from the 2026-05-28 record
  (pre-AUDIT-5 carved-frame Bean is untrusted); the gate is crib-only.
- **Halt rule:** if either gate fails, STOP — do not interpret the new cell;
  investigate dispatcher semantic drift first.
- A0 doubles as a regression check that the `tableau_keyword` fix left
  explicit-pin semantics byte-identical.

## 3. Null model (conditional-null contract)

- `null_used`: campaign-local **matched keyword-population null**, dispatched
  through the **identical** `execute()` path (same pipeline shape, same
  alignment, same indicators/routes/variant; only the *keyword content* —
  the theorist-chosen axis — is resampled). Order-statistic matched:
  per-replicate **max over the full replicate universe** vs real max
  (max-of-N vs max-of-N; per the 2026-05-28 alignment-null order-stat trap
  memo).
- M = **200** replicates per new-cell arm. Replicate r seed:
  `20260609_000 + 100000*arm_index + r` (arm_index: A1=0, B1=1).
- Keyword pool: `wordlists/english.txt`, uppercased, `^[A-Z]+$` only,
  length-matched multiset per axis (tableaus: {10,8,8,8,7}; A1 periods:
  7×len3 + 11×len4 + 4×len5; B1 periods: {10,8,7,5,6,9}), sampled distinct
  within an axis, excluding the union of all real keywords above.
- Caveat (stated per skill contract): the pool is general English of matched
  length, not "K4-thematic" English; the null controls mechanical/structural
  chance, not thematic specialness. `null_matches_admission_process`: true
  for the mechanical axes; thematic-prior residue acknowledged.
- Multiplicity: 2 arms; Bonferroni — report per-arm empirical tail
  `(1 + #(null_max >= real_max)) / (M + 1)`; the empirical floor at M=200 is
  ~5e-3, which is adequate ONLY for a null verdict; any positive finding
  requires recalibration at n_samples >= 10/1e-6 before an alert-grade
  p-claim (AUDIT-4 invariant).
- Spec-level `NullBaselineSpec(shuffled_ct, 1000)` is declared on the real
  arms as a secondary surface control; the campaign-level matched null above
  is the primary preregistered null.

## 4. Frozen kill criterion / verdicts

- **CLEAN_NULL (cell closed):** zero configs in A1 ∪ B1 with kernel-verified
  `crib_score >= 18`. (Bean is NOT in the kill rule: the inner is
  non-additive, so the additive Bean derivation is inapplicable by
  construction — recorded as context only, per spec_h3 precedent.)
- **ESCALATE (no verdict from this run):** any config with `crib_score >= 18`.
  Escalation path (pre-committed): kernel re-verification in a fresh
  interpreter; per-char quadgram floor `>= -4.5`; matched null recalibrated to
  n_samples >= 10/1e-6; red-team-disprover review. No SIGNAL/solve language
  before all four pass.
- **REPLICATION_FAILURE:** either control gate misses — toolchain
  investigation, no cell verdict.
- Forced-crib control (AUDIT-3 concretization): cribs pasted into an
  otherwise-random PT must show crib 24/24 with per-char ngram at the
  gibberish floor — printed alongside results to anchor "crib alone is not a
  solve."

## 5. Scope

- **Closes (on CLEAN_NULL):** Quagmire III with tableau_keyword ∈ {PALIMPSEST,
  ABSCISSA, LATITUDE, MAGNETIC, COMPASS} on exactly the two 2026-05-28 cluster
  shapes: (A1) direct-positional decoupled-period sweep {22 periods × 3
  indicators}; (B1) boustrophedon-outer {w∈{7,14} × vertical∈{f,t}} ×
  {6 periods × indicator K} under post_transposition. Scoped to the recorded
  universe hashes.
- **Does NOT close:** free-alignment scoring of these shapes; other tableau
  keywords; other period-keyword sets; other indicators; other routes/widths;
  quagmire_iv; KA-layer variants; any masked/null-bearing model; the broader
  route-outer × Quagmire-inner matrix (RANK-4 UNKNOWN cell from the 2026-06-09
  survey — needs its own coverage audit + prereg).

## 6. Assumption bundles

- A1: `["ct97_direct_positional", "az_a0", "no_null_mask",
  "quagmire_iii_k1k2_convention", "H1_effective_statistic_of_h12"]`
- B1: `["transposed", "az_a0", "no_null_mask", "non_direct_alignment",
  "outer_route_then_quagmire_iii", "bean_inapplicable_nonadditive_inner"]`

## 7. Replay

```bash
PYTHONPATH=src python3 -u scripts/campaigns/f_quagmire_tableau_axis_completion_2026_06_09.py \
  --out results/k4_next_goal
```

Deterministic given the frozen seeds; dispatcher artifacts under
`results/k4_next_goal/{jobs,null_jobs}/`; summary at
`results/k4_next_goal/qtab_summary.json`.
