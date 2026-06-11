# Pre-registration: solver multi-layer free-alignment sweep (2026-06-11)

**Campaign ID:** `f_solver_free_alignment_2026_06_11`
**Runner:** `scripts/campaigns/f_solver_free_alignment_2026_06_11.py`
**Author:** autonomous session 2026-06-11 (Claude), per Colin's go-ahead on the
solver alignment extension and the standing real-K4 directive.
**Status at registration:** thresholds frozen BEFORE any campaign config was
executed. Written after the solver `crib_alignment` extension landed TDD-green
(10 new tests in `kryptosbot/tests/test_solver_alignment.py`; kryptosbot suite
2740 passed, core suite 2238 passed) and the known-answer gate passed 3/3
(`self_test.py --panel all --mode dry-run --cycles 20000`).

---

## 1. Hypothesis and why this is genuinely untested

**[HYPOTHESIS]** A bounded TWO- or THREE-LAYER classical composition decrypt of
the carved 97-char K4 CT yields a plaintext containing the disclosed cribs
(EASTNORTHEAST, BERLINCLOCK) at NON-canonical offsets.

**Alignment model:** `non_direct_alignment` (R1), probed at the detection level
via `crib_alignment="free"` (cribs matched anywhere). ALIGN-CAUSE:
transposition-induced or mask-induced — the free matcher is agnostic.

**Convention bundle (Step 0 freeze):**
- ALPHABET: AZ (A=0); KA (`KRYPTOSABCDEFGHIJLMNQUVWXZ`, A=0) on keyword
  substitution layers where declared; transposition layers AZ.
- VARIANT: vigenere K=(CT−PT), beaufort K=(CT+PT), var_beaufort K=(PT−CT), A=0.
- POSITIONS: 0-indexed; canonical crib positions NOT assumed.
- ALIGNMENT: `non_direct_alignment`; DSL `crib_alignment="free"`.
- NULL RULE: no_null_mask (length-97 stream preserved by every pipeline).
- SCOPE: GLOBAL over the 97-char candidate PT.
- BEAN APPLIES?: **No.** N/A by construction under free (dispatcher reports
  `bean_passed=False`, `scoring_mode="free"`). No Bean elimination cited.

**Why untested:** `f_free_alignment_classical_2026_06_10` §6 explicitly lists
"multi-layer pipelines" beyond its A5 arm (two-layer columnar × additive,
thematic keywords) as NOT closed. This campaign's universe is the deterministic
clue-bounded solver enumeration (`kryptosbot/solver.py::build_sweep_specs`,
rounds 0 and 1) under the new `crib_alignment="free"` parameter:

- Round 0 (96 specs, est. 13,132 configs): two-layer {columnar, rail_fence,
  reverse_blocks, route_boustrophedon, route_diagonal, skip_route} ×
  {vigenere, beaufort, variant_beaufort, atbash, caesar}, BOTH decrypt orders.
- Round 1 (388 specs, est. 237,216 configs): three-layer — two transpositions
  + one substitution, sub-outermost and sub-middle decrypt orders, all ordered
  pairs of distinct transposition families.
- Keywords (12, attested-content): KRYPTOS, PALIMPSEST, ABSCISSA, BERLIN,
  CLOCK, LANGLEY, NORTHEAST, SHADOW, FORCES, LUCID, MEMORY, IQLUSION.

**Distinctness vs prior free closures (declared BEFORE run):**
- vs A1/A3 (single-layer additive): disjoint — every spec here is ≥2 layers.
- vs A5 (two-layer columnar × additive × thematic): 5/12 keywords (KRYPTOS,
  PALIMPSEST, ABSCISSA, LANGLEY, IQLUSION) are in the thematic list, so those
  columnar×additive sub-cells are REDUNDANT with A5 and serve as
  redundant-coverage controls (expected 0 hits, consistent with A5's clean
  null). 7/12 keywords (BERLIN, CLOCK, NORTHEAST, SHADOW, FORCES, LUCID,
  MEMORY) are NOT in the thematic list (verified by grep before run) — those
  sub-cells are NEW.
- vs A4 (52 hash-locked routes × additive single-inner): the solver's
  route_boustrophedon / route_diagonal × additive two-layer cells may
  PARTIALLY overlap A4's route universe at coincident widths; declared as
  possible-partial overlap, redundant where it occurs.
- Entirely NEW: all of round 1 (three-layer); two-layer with rail_fence /
  reverse_blocks / skip_route outers; columnar/route × atbash/caesar.

## 2. Frozen universe

The runner materializes all 484 specs BEFORE dispatch and records a SHA-256
universe hash over the sorted spec serializations, plus the keyword list. No
universe expansion after seeing results. Per-spec cardinality cap 2,000
(solver `_MAX_SPEC_CARDINALITY`); expected total ≈ 250,348 configs.

## 3. Scoring and dispatch path

- Real dispatcher only: `kryptosbot.job_dispatcher.execute()` per spec on the
  REAL-K4 path (no challenge args — the challenge branch has no free matcher).
  Kernel-verified `score_candidate_free` (`scoring_mode="free"`), Lever B1.
- Free crib score support is {0, 11, 13, 24}. Free scores are NEVER compared
  to anchored scores or anchored nulls (G-1).
- Admissibility: NO `override_exhaustion`. B-3 alignment-scoped overlap means
  only free-marked exhaustion entries bind; pre-run inspection found no
  free-marked entry whose family string contains a pipeline kind, so zero
  rejections are predicted. Any rejection that does occur is recorded in the
  summary and adjudicated openly — never silently skipped.

## 4. Controls (run BEFORE the arms; campaign aborts if any fails)

- **C0 (known-answer gate):** `self_test.py --panel all --mode dry-run
  --cycles 20000` exits 0 with "solved: 3/3" (run at campaign start;
  fail-closed).
- **C1 (kernel):** `score_candidate_free` on a constructed 97-char PT with
  EASTNORTHEAST at offset 5 and BERLINCLOCK at offset 60 returns crib_score 24
  with `canonical_positions=False`.
- **C2 (worker path):** `job_dispatcher._evaluate_one` on a synthetic
  CT = vigenere_encrypt(displaced-crib PT, PALIMPSEST, AZ) with
  `crib_alignment="free"`, `challenge_crib_dict=None` returns kernel-verified
  crib_score 24, `scoring_mode="free"` (verbatim from the
  f_free_alignment_classical template).
- **C3 (standing):** zoo fixture F9 pins the end-to-end `execute()` free
  solve; both suites green at run HEAD. Pipeline-depth execution of these
  EXACT 484 spec shapes is additionally pinned by the 2026-06-11 direct-
  alignment solver run (250,348 configs executed and scored).
  Alignment affects only the scoring branch, so no separate three-layer
  free control is constructed.

## 5. Null model and decision rules (FROZEN — adopted verbatim from f_free_alignment_classical §5)

- Analytic per-config tails under the G-1 free-matched nulls (uniform-output
  model): P(≥11) ≈ 2.4e-14, P(≥13) ≈ 3.4e-17, P(24) ≈ 8.1e-31.
- Campaign-wide expectation under H0 across ≈ 250,348 configs:
  ≈ 6.0e-9 expected hits ≥ 11. The expected outcome under H0 is ZERO free
  hits anywhere.
- **Declared caveat (inherited + extended):** the analytic null assumes
  ~uniform output letters; specific (key, geometry) combinations — including
  multi-layer compositions — can in principle exceed the iid value. Decision
  rules therefore treat ANY hit as investigate-first, never auto-signal; the
  verification step recomputes the hit's probability under a key-matched
  empirical null (50k random keys, same composition shape, free-scored).
- **DETECT-24:** any kernel-verified free crib_score == 24 → solve-candidate
  protocol: canonical_positions recorded; per-char quadgram floor ≥ −4.5;
  fresh-interpreter reproduction; family-wise p vs free-matched null
  (Bonferroni over 250,348); red-team review. BREAKTHROUGH is an INPUT to
  validation (AUDIT-3).
- **SIGNAL (rule S):** any config with free crib_score ∈ {11, 13} →
  investigate-first per the caveat above; report family-wise corrected p.
- **CLEAN_NULL:** zero configs ≥ 11 → the campaign closes as a bounded clean
  null over the hashed universe.

## 6. Scope statement

CLOSES (exactly, if CLEAN_NULL): "two- and three-layer compositions from the
solver's 484-spec universe (6 transposition × 5 substitution families, 12
listed keywords, AZ/KA, both/all decrypt orders, default width/depth/block/
skip ranges) applied to the carved 97-char K4 CT produce no plaintext
containing either disclosed crib as a contiguous substring anywhere."

DOES NOT CLOSE: PT length ≠ 97; keywords outside the 12; parameter values
outside the solver's default ranges; ≥4-layer pipelines; sub-innermost
three-layer order (solver emits sub-outer and sub-middle only); key_tape /
running-key / quagmire inners; non-contiguous crib dispersal; fragment-level
presence (<11); every cell already declared NOT closed by
f_free_alignment_classical §6 that this universe does not reach.

## 7. Compute plan

28-vCPU VM; specs dispatched serially, each through execute()'s internal pool
(cpu_count − 2 workers). Expected wall: tens of minutes (484 pool spin-ups
dominate; kernel throughput ≈ 10⁵ configs/s). Artifacts: per-spec JSON under
`results/solver_free_alignment_2026_06_11/jobs/`, summary + verdict at
`results/solver_free_alignment_2026_06_11/summary.json`.
