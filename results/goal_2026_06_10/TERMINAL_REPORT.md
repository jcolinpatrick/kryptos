# TERMINAL REPORT — autonomous /goal session 2026-06-10

**Goal:** autonomously solve Kryptos K4 with this repo, or produce a
reproducible terminal report proving what remains open.

## 0. VERDICT: **EXHAUSTED_CURRENT_REPO** (K4 NOT solved)

K4 remains unsolved. This session (a) removed the last known way a
genuine non-direct solve could die silently inside the toolchain,
(b) calibrated the free-alignment scoring mode that fix exposed, and
(c) exhausted the newly-opened free-alignment detection lens over every
bounded classical universe the repo can currently express — ~5.97M
configurations, all clean null. What remains open is exactly what was
open after the 2026-06-06/07 frontier verdicts, minus the
displaced-crib escape hatch this session closed: acquisition-gated
evidence (GAP-09 photo, bespoke chart), Bin-D engineering (detector
mathematics proven underpowered at K4 parameters), and unbounded model
space that no bounded sweep can certify.

## 1. What this session did (chronological, all reproducible)

1. **Committed the suite-assurance patchset** (`f213b4d`): B-1
   (contract boundary zeroed genuine free-alignment finds — fixed,
   frame-aware), B-2 (post_transposition Bean recomputed in the carved
   frame at the boundary — fixed per AUDIT-5), B-3 (direct-scope
   exhaustion entries blocked non-direct dispatch — fixed). 48 new
   tests. Both suites green (kryptosbot 2693+1, core 2238).
2. **G-1: free-matched null baselines** (`ceb8e02`):
   `scoring_mode` dimension in `kryptosbot/null_baselines.py` with the
   analytic `free_crib_substring` tail. Key derived fact: CT has 2 E's,
   the two cribs jointly need 3, so free 24/24 is EXACTLY impossible
   under any permutation-of-CT null. Free results now gate and annotate
   against free-built nulls only (`ok_free_matched` / `free_null_miss`;
   controller halt extended). 29 new tests; suites green (2722+1 / 2238).
3. **Dispatcher performance fix:** `HypothesisSpec.spec_hash` property
   re-serialized the whole spec per access inside the per-config loop —
   an accidental quadratic costing 120s of a 124s 10k-keyword shard.
   Hoisted; 83× speedup; dispatcher regression tests green.
4. **First free-alignment campaign**
   (`f_free_alignment_classical_2026_06_10`, pre-registered with frozen
   thresholds BEFORE any config ran; addenda A4/A5/A6 registered before
   those arms ran): see
   `results/free_alignment_classical/FINAL.md`. Six arms, 5,968,842
   configs, **CLEAN_NULL** everywhere (best free crib 0/24 across the
   entire campaign — neither crib appears as a contiguous substring in
   ANY decrypt output). Controls (kernel, worker-fn on synthetic CT,
   committed zoo F9) all passed pre-run. Registered in
   `exhaustion_log.json`.

## 2. Why the campaign mattered (and its honest limits)

Every historical single-layer/route/columnar/QIII sweep scored cribs
ANCHORED at positions 21–33/63–73. A correct inner system whose cribs
were displaced (by nulls, offsets, or reading order) would have scored
≈0 and been discarded — and until B-1 (this session) even a free-scored
24/24 would have been zeroed at the contract boundary. That entire
escape hatch is now closed for: additive single layers (AZ/KA ×
thematic + 742k-word English breadth), Quagmire III diagonal tableaus,
52-route × additive, columnar × additive in both peel orders, and the
route × QIII matrix.

Limits: closure is detection-level (contiguous full-crib presence in
length-97 decrypt output) over hashed keyword/route universes. It says
nothing about PT length ≠ 97, non-keyword keys, key_tape inners,
≥3-layer pipelines, or mechanisms that disperse crib letters
non-contiguously.

## 3. What remains open (the frontier, restated precisely)

- **Acquisition-gated (Bin E / GAP register):** GAP-09 needs new
  physical/archival data (independent square-on photo); bespoke
  chart-based cipher needs the public chart or a CipherProcedureLicense;
  GAP-04 square-on imagery. No amount of repo compute moves these.
- **Bin-D engineering:** Mono+Trans+Running-key detection is
  mathematically underdetermined at K4 parameters (E-FRAC-54 + 2026-06-06
  detector results: 73 free PT + 26 σ DOF saturate detection). A new
  detector idea, not more sweeps.
- **Unbounded model space:** arbitrary_null_mask (no pre-registered
  statistic since the palette retirement), joint_mask_mechanism (solver
  substrate exists for periodic family only), non-named reorderings,
  bespoke procedures. Open by nature; any future run needs the same
  bounded/pre-registered discipline used here.
- **Free-alignment extensions not yet run:** key_tape inners re-lensed
  free (hours-scale, low EV), fragment-level (<full-crib) detection
  (needs its own calibrated null to avoid noise-mining), ≥3-layer free.

## 4. Reproducibility index

| Item | Command / artifact |
|---|---|
| Suites | `PYTHONPATH=src venv/bin/pytest tests/ -n 26` ; `… kryptosbot/tests/ -n 26` |
| Readiness gate | `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000` (3/3) |
| Doctor | `PYTHONPATH=src python3 -m kryptos doctor` (21/21) |
| G-1 nulls | `PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines_r2_4.py` (free entries incl.) |
| Campaign | replay commands in `results/free_alignment_classical/FINAL.md` |
| Pre-reg | `docs/campaigns/free_alignment_classical_2026_06_10.md` |
| Exhaustion entry | `exhaustion_log.json` → `f_free_alignment_classical_2026_06_10` |

## 5. Truth-taxonomy statement

[INTERNAL RESULT] All campaign verdicts above (artifact pointers and
repro commands given). [DERIVED FACT] The CT-multiset impossibility of
free 24 under permutation nulls (compute from `kernel.constants.CT`).
[HYPOTHESIS] Anything in §3 about where a solve might still live.
Nothing in this report claims K4 progress beyond bounded eliminations.
