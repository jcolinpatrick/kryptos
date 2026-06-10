# Pre-registration — route-outer × Quagmire-III-inner under post_transposition

**ID:** `f_route_outer_quagmire_iii_posttrans_2026_06_09`
**Date frozen:** 2026-06-10 (before any dispatch; all thresholds in this file are
frozen). Filename carries the 2026-06-09 date of the goal directive and of
`results/k4_next_goal/FINAL.md` §6.1, which named this cell.
**Runner:** `scripts/campaigns/f_route_outer_quagmire_iii_posttrans_2026_06_09.py`
**Coverage audit (prerequisite):** `results/k4_route_qiii_next/COVERAGE_AUDIT.md`
**Status at freeze:** not yet run.

## 1. Provenance

`results/k4_next_goal/FINAL.md` §6.1 names the "route-outer ×
Quagmire-III-inner matrix under post_transposition" as the next best finite
experiment (the 2026-06-09 survey's RANK-4 UNKNOWN). The coverage audit
confirms: the dispatcher ledger contains **zero** multi-layer quagmire specs;
the only adjacent closures are TABP (KRYPTOS tableau, different outer set),
the 52-route closures with additive/key_tape inners (different inner
mechanism), and the 2026-06-09 qtab B0/B1 boustrophedon corner (84-config
involution overlap, exploited as gate G1 below).

Enabled by: `tableau_keyword` (cf9dee1) + verified grille hole_mask gather
convention (faab9a0, unit test
`test_grille_perm_encoding_byte_identical_to_route_boustrophedon`).

## 2. Universe (frozen; exhaustive — stop rule = full enumeration)

One `HypothesisSpec`, pipeline in decrypt order (outer first):

- Layer 0 `grille`, alphabet AZ: `hole_mask` ∈ the canonical 52-route
  reordering universe of the 2026-05-29 closures, perms **verbatim**
  (decrypt step = `gather(perm)` ≡ `apply_perm(CT, perm)`), hash-locked:
  the runner asserts `len == 52` and
  `reordering_hash == 7a9ac67336cd37e2f7be75c59d549b75618395c47a4bcd515d652232996ae6aa`
  (fail-closed; computed pre-freeze).
- Layer 1 `quagmire`, alphabet AZ, `variant = quagmire_iii`:
  - `tableau_keyword` ∈ {KRYPTOS, PALIMPSEST, ABSCISSA, LATITUDE, MAGNETIC,
    COMPASS} (6 — the 2026-06-09 five + KRYPTOS; every value precedented in a
    prior frozen pre-reg, zero new keyword choices)
  - `period_keyword` ∈ h12 ∪ h3 union, CLOCK deduped (27): CIA, WEST, EAST,
    NORTH, SOUTH, TIME, CLOCK, LIGHT, NSA, RED, ZONE, GRID, CODE, KEY, ROW,
    ARC, SUN, DIAL, TICK, HOUR, WIND, POLE, PALIMPSEST, ABSCISSA, KRYPTOS,
    BERLIN, NORTHEAST
  - `indicator` ∈ {K, A, R} (3 — verbatim from spec_h12/qtab A1)
- `crib_alignment = post_transposition` (anchored after the pipeline's
  route undo). Bean: inner is non-additive ⇒ `_keystream_frame_ct` finds no
  trailing additive ⇒ expected `scoring_mode =
  post_transposition_bean_unavailable`; Bean recorded N/A, context only
  (qtab B1 precedent; AUDIT-5 contract).
- Cardinality: 52 × 6 × 27 × 3 = **25,272**. The runner halts if
  `total_tested != 25272`.
- `compute_budget_cpu_minutes = 10` (cap 2,000,000 ≥ 25,272);
  `override_exhaustion = True` with the coverage audit as justification
  (the dispatcher's substring heuristic flags the quagmire family; the
  audited mechanisms differ).

Known double-coverage (documented, not part of the closure claim): identity
route × {6 tableaus × 22 h12 periods × 3 indicators} ≈ qtab A0/A1 direct
cells; {grid7,grid14}_serpRow × B1 inner = the involutive qtab B0/B1 corner.

## 3. Replication / encoding gates (run BEFORE the new cell; halt on failure)

- **G0 (drift gate):** re-dispatch archived `spec_h3.json` verbatim (KRYPTOS
  tableau, 24 cfg, post_transposition). Gate: best kernel-verified
  crib_score == **4** and total_tested == 24 (the 2026-05-28 and 2026-06-09
  values).
- **G1 (dual-encoding gate, real CT):** (a) `route_boustrophedon`
  w∈{7,14}×vertical=False × {5 new tableaus × 6 h3 periods × indicator K}
  (60 cfg); (b) `grille` hole_mask ∈ {grid7_serpRow, grid14_serpRow} × the
  same inner (60 cfg). Gate: **identical** best_score, best crib_score, and
  best_candidate_pt between (a) and (b) (horizontal serpentine perms are
  involutive, so the two encodings define the same 60 hypotheses).
- Failure of G0 → `REPLICATION_FAILURE`; failure of G1 →
  `ENCODING_MISMATCH`. Either: exit 3, **no cell verdict**, investigate
  toolchain drift first.

## 4. Null model (conditional-null contract)

- Campaign-local **matched keyword-population null** through the identical
  `execute()` path; order-statistic matched (per-replicate max over the full
  25,272-config replicate universe vs the real max).
- Resampled axes (theorist-chosen keyword content only): tableau multiset
  lens {7,10,8,8,8,7}; period multiset lens of the 27-keyword union
  (7×len3, 11×len4, 4×len5, len6, len7, len8, len9, len10). Pool:
  `wordlists/english.txt`, uppercased, `^[A-Z]+$`, distinct within an axis,
  excluding the union of all real keywords above.
- Fixed (mechanical/structural) axes: the 52 routes, indicators {K,A,R},
  variant, alphabet, alignment.
- M = **200** replicates. Replicate r seed: `20260610000 + r`.
- Caveat (skill contract): the pool controls mechanical/structural chance,
  not thematic specialness. Empirical tail floor at M=200 is ~5e-3 —
  adequate ONLY for a null verdict; any positive finding pre-commits to
  recalibration at n_samples ≥ 10/1e-6 before alert-grade claims (AUDIT-4).
- Spec-level `NullBaselineSpec(shuffled_ct, 1000)` on the real arm as a
  secondary surface control.

## 5. Frozen kill criterion / verdicts

- **CLEAN_NULL (cell closed):** zero configs with kernel-verified
  `crib_score >= 18`. (Bean not in the kill rule: non-additive inner.)
- **ESCALATE (no verdict from this run):** any config `crib_score >= 18`.
  Pre-committed path: kernel re-verification in a fresh interpreter;
  per-char quadgram floor ≥ −4.5; matched null recalibrated to ≥ 10/1e-6;
  red-team-disprover review. No SIGNAL/solve language before all four pass.
- **REPLICATION_FAILURE / ENCODING_MISMATCH:** see §3.
- Forced-crib control (AUDIT-3): cribs pasted into seeded random PT printed
  alongside (crib 24/24 at gibberish ngram) — crib alone is not a solve.

## 6. Scope

- **Closes (on CLEAN_NULL):** Quagmire III inner (tableau ∈ the 6, period ∈
  the 27, indicator ∈ {K,A,R}) behind each of the canonical 52 byte-identical
  reorderings under post_transposition, AZ, scoped to the recorded
  spec/universe hashes.
- **Does NOT close:** routes outside the 52; other tableau/period/indicator
  values; quagmire_iv; KA-layer variants; free alignment; masked models;
  Q-III inners behind reorderings not byte-identical to this universe.

## 7. Assumption bundle

`["transposed", "az_a0", "no_null_mask", "non_direct_alignment",
"outer_byte_reordering_then_quagmire_iii",
"bean_inapplicable_nonadditive_inner",
"reordering_universe_7a9ac67336cd37e2"]`

## 8. Replay

```bash
PYTHONPATH=src python3 -u scripts/campaigns/f_route_outer_quagmire_iii_posttrans_2026_06_09.py \
  --out results/k4_route_qiii_next
```

Deterministic given the frozen seeds; artifacts under
`results/k4_route_qiii_next/{jobs,null_jobs}/`; summary at
`results/k4_route_qiii_next/route_qiii_summary.json`.
