# Admitted-Theory Conditional Null Design

**Status:** DRAFT v1 (2026-05-04). Implementation: `scripts/_infra/calibrate_admitted_theory_null.py`. This document is the design contract; the script is the operational artifact.

---

## Objective

Estimate the distribution of `best_score` (and component scores: `crib_score`, `bean_passed`, `ngram_score`) for theories that satisfy the framework's admissibility shape but carry no cryptographic signal.

The current calibrated nulls (`crib_score__random_text`, `crib_score__shuffled_ct`, `crib_score__matched_variant_family`) are theory-agnostic: they compute the score distribution under random plaintext / random key / random permutation. The admitted-theory ledger is **not** drawn from these distributions — it is conditioned on "mechanism survived the critic + red-team + admissibility gates."

The current operational finding *"no audited active K4 lead is supported by the existing campaign outputs"* depends on interpreting per-family score elevations (e.g., geodetic +1.54 vs random null) as either:
- (a) cryptographic content (real signal in family X), or
- (b) admissibility-gating bias (mechanisms designed to target cribs achieve this elevation in expectation).

Without a conditional null, (a) and (b) are confounded. This design specifies the missing measurement.

---

## Null Definition

A **random admitted theory** is a synthetically generated test object that:

1. Uses a valid `_SUPPORTED_KINDS` cipher kind OR a project methodological-family shape.
2. Has parameters drawn from a bounded distribution that mirrors the admissible parameter space (e.g., keywords from a generic English-words pool of size N=719 to match the project's curated list, periods drawn from {1..26}, alphabets from {AZ, KA}, etc.).
3. Has parameters drawn **without conditioning on K4 cribs.** A random keyword may happen to match crib characters, but the generation process must not enrich for crib alignment beyond the coarse structural affordances available to all admitted theories (e.g., "uses one of 719 keywords" is allowed; "selects keywords ranked by their effect on crib_score" is forbidden).
4. Passes syntactic DSL validation OR is explicitly excluded from the DSL path with the same exclusion semantics the dispatcher applies.
5. Passes or intentionally mocks the critic's shape gates (kind in valid set, family in valid set, kill criteria present) without invoking the LLM critic itself.

The key contract: **the admitted-theory generator must produce specs that, when scored against the canonical 97-char K4 CT through the canonical kernel scoring path, give a score distribution interpretable as "what does a typical admitted theory score?"**

---

## Stratification

The score distribution must be stratified by axes that we expect to systematically shift it:

| Axis | Levels | Reason |
|---|---|---|
| Cipher kind | vigenere, beaufort, var_beaufort, columnar, myszkowski, route, rail_fence, polybius (bifid), grille, key_tape, quagmire, reverse_blocks | Different kinds have different inherent crib-hit probabilities |
| Alphabet | AZ, KA, keyword_mixed | KA reorders; different effective key space |
| Scoring mode | anchored (`score_candidate`), free (`score_candidate_free`) | Free scoring searches cribs anywhere |
| Crib alignment | direct positional, post-transposition | Tier-1/2 eliminations apply to direct positional only |
| Composition depth | single-layer, two-layer | Compositional families produce different score distributions |
| Parameter cardinality bin | small (≤10 configs), medium (10–100), large (>100) | Larger search spaces have larger maxima under same null |
| Family methodological vs DSL | DSL-cipher, methodological (k2_coords, archive_evidence, antipodes, etc.) | Methodological families don't dispatch through DSL |

**Phase 1 of this calibration covers DSL-cipher families only.** Methodological-family conditional null is a Phase 2 follow-up — it requires mocking worker logic and is substantially more complex.

---

## Outputs

For each stratum:

- `n_samples` (int): number of synthetic theories drawn
- `mean` (float): mean of `best_score`
- `stdev` (float): sample standard deviation
- `percentiles`: p01, p05, p10, p25, p50, p75, p90, p95, p99, p999
- `tail_floor`: `1 / n_samples` (smallest empirically-resolvable p-value)
- `empirical_p_for_observed_max` (float | None): p-value of the observed ledger max under this stratum's null, if a comparable ledger entry exists
- `bonferroni_p` (float | None): empirical p × stratum count for cross-stratum correction
- `bean_pass_rate` (float): fraction passing Bean (must be near 624/26²⁴ ≈ vanishing under truly random keystream)
- `ngram_score_mean` (float): for separate analysis of language fit

Comparison against ledger:

For each (family, stratum) where the ledger has ≥10 entries, report:
- `ledger_mean`
- `null_mean`
- `delta = ledger_mean - null_mean`
- `delta_z` = (ledger_mean - null_mean) / (null_stdev / sqrt(ledger_n))
- `interpretation`: one of {`indistinguishable_from_null`, `elevated_consistent_with_admissibility_bias`, `elevated_beyond_admissibility_bias_warrants_followup`, `inconclusive_due_to_insufficient_samples`}

Output format: JSON manifest (committed) + JSONL distributions (gitignored).

```text
null_baselines/admitted_theory_manifest.json     # committed
results/null_baselines/admitted_theory/           # gitignored
  vigenere_AZ_anchored_direct_singlelayer__v1.jsonl
  vigenere_KA_anchored_direct_singlelayer__v1.jsonl
  beaufort_AZ_anchored_direct_singlelayer__v1.jsonl
  ... (one per stratum)
  ledger_comparison.json
```

---

## Failure Modes (explicitly tested)

The synthetic null sampler must be guarded against:

1. **Synthetic null too weak** (under-attacks cribs). Symptom: synthetic score distribution looks like pure random_text null. Detection: synthetic mean should be ≥ random_text mean for cipher families that the dispatcher routinely sees succeeding partially.
2. **Synthetic null too strong** (accidentally search-optimal). Symptom: synthetic mean approaches ledger max. Detection: max synthetic score across N=10K samples should remain < 18 (signal threshold) for honest no-signal nulls.
3. **Period underdetermination contamination.** Symptom: high-period samples score artificially high. Detection: stratify by period; per-period max should match CLAUDE.md's documented per-period random expectations.
4. **Bean-invariance degeneracy.** Symptom: theories that propose non-crib edits trivially pass Bean (Bean is crib-position-only). Detection: bean_pass_rate by edit-type; if non-crib-edit theories pass at much higher rate than crib-edit theories, the synthetic null reproduces the documented `4ae72d4d` failure mode.
5. **Family-specific cherry-picking.** Symptom: per-family means differ from null even before introducing cipher signal. Detection: cross-family null means should be approximately equal (random keyword × random params → same expectation regardless of family label).
6. **Admissibility-overlap false positives.** Symptom: synthetic specs collide with already-tested ledger entries (overlap), giving them artificial admissibility weight. Detection: track collisions, exclude or downweight.
7. **DSL-validation drift.** Symptom: synthetic specs that pass DSL validation in this script differ from what the dispatcher accepts. Detection: pipe synthetic specs through the actual `_translate_layer` and assert agreement.

---

## Implementation Contract

### Script: `scripts/_infra/calibrate_admitted_theory_null.py`

CLI:

```
PYTHONPATH=src python3 -u scripts/_infra/calibrate_admitted_theory_null.py \
    [--quick]                          # small sample size for smoke test
    [--samples-per-stratum N]          # default 10000, --quick reduces to 200
    [--seed N]                         # default 42
    [--only-stratum STRATUM]           # filter to one stratum
    [--keywords PATH]                  # default wordlists/thematic_keywords.txt
    [--output-root PATH]               # default results/null_baselines/admitted_theory/
    [--manifest-path PATH]             # default null_baselines/admitted_theory_manifest.json
    [--ledger-comparison]              # produce ledger_comparison.json
    [--workers N]                      # default cpu_count() - 2
```

### Generation strategy

For each stratum (cipher_kind × alphabet × scoring_mode × crib_alignment × composition_depth):

1. Draw N synthetic specs from the parameter distribution.
2. For each spec, build the kernel pipeline via `compose.build_pipeline`.
3. Apply pipeline to canonical K4 CT.
4. Score plaintext via `kryptos.kernel.scoring.aggregate.score_candidate` (or `score_candidate_free` for free-crib mode).
5. Record full breakdown: crib_score, bean_passed, ngram_score, classification.
6. Accumulate distribution.

Worker pool `multiprocessing.Pool(workers)` for parallel scoring. Per-worker chunk size: 100 specs.

### Failure-mode guards

Each guard is a separate test in `tests/test_admitted_theory_null.py`:

- `test_synthetic_max_below_signal_threshold`: across 10K samples per stratum, max(crib_score) < 18.
- `test_period_stratified_max_matches_doctrine`: at period 24, mean ≥ 19.0 (matches CLAUDE.md's documented "random configs at period 24 score ~19.2/24").
- `test_bean_pass_rate_low`: bean_pass_rate < 1% per stratum (Bean is restrictive).
- `test_cross_family_means_approximately_equal`: no family pair differs by more than 1 score point in mean.
- `test_dsl_validation_agreement`: a sample of synthetic specs piped through `_translate_layer` produces no errors.

### Resumable checkpointing

Each stratum writes its JSONL incrementally with a header line containing:
- generation seed
- generation start timestamp
- generation script SHA
- spec generation parameters (so a partial run can be resumed)

A trailer line is written on completion. Resume is detected by trailer-absent.

### Manifest

`null_baselines/admitted_theory_manifest.json` is small, committed, and contains:

```json
{
  "schema_version": "admitted_theory_null.v1",
  "generated_at": "2026-05-04T...",
  "kernel_commit": "...",
  "script_sha": "...",
  "default_seed": 42,
  "strata": [
    {
      "name": "vigenere_AZ_anchored_direct_singlelayer",
      "cipher_kind": "vigenere",
      "alphabet": "AZ",
      "scoring_mode": "anchored",
      "crib_alignment": "direct",
      "composition_depth": 1,
      "n_samples": 10000,
      "summary": {"mean": ..., "stdev": ..., "max": ..., "tail_floor": 0.0001},
      "distribution_path": "results/null_baselines/admitted_theory/vigenere_AZ_anchored_direct_singlelayer__v1.jsonl"
    },
    ...
  ],
  "ledger_comparison_path": "results/null_baselines/admitted_theory/ledger_comparison.json"
}
```

The full distribution JSONLs are gitignored (large); the manifest is committed.

---

## Acceptance Criteria

This calibration is complete when:

```bash
PYTHONPATH=src python3 -u scripts/_infra/calibrate_admitted_theory_null.py --quick
PYTHONPATH=src pytest tests/test_admitted_theory_null.py kryptosbot/tests/ -q
```

both pass, AND `results/null_baselines/admitted_theory/ledger_comparison.json` can answer the question:

> *"Do the observed family-level score elevations survive a conditional admitted-theory null?"*

with one of these answers:

- `yes` — at least one family's ledger mean exceeds the conditional null mean by >2 stdev with multiplicity correction (across families) preserving significance. **Reopens the corresponding family's mechanism for bounded retest.**
- `no` — all family ledger means fall within the conditional null's expected range. **Confirms the operational finding "no audited active K4 lead."**
- `inconclusive due to insufficient sampling` — quick mode insufficient; full mode required.

---

## Phase 2 Implementation Status (2026-05-04)

| Component | Status |
|---|---|
| Design doc (this file) | ✅ committed |
| Script `calibrate_admitted_theory_null.py` | 🟡 starter implementation in same commit (DSL-cipher families only) |
| Test file `tests/test_admitted_theory_null.py` | 🟡 stub with 5 failure-mode guards (not all implemented) |
| Methodological-family conditional null | ⛔ deferred — requires worker-mock infrastructure (Phase 2.1) |
| Ledger comparison report | 🟡 produced by `--ledger-comparison` flag |
| Quick-mode pass | 🟡 verifies pipeline; full N=10K calibration deferred to operator |

**Honest limitation**: this Phase 2 deliverable is a design contract + working DSL-cipher null sampler. The methodological-family conditional null (the higher-mean families: geodetic, k3_continuity, k2_coords, archive_evidence, antipodes) requires a separate Phase 2.1 effort because those families dispatch through worker scripts, not the DSL path. Their conditional null sampler must mock the worker mechanism, which is family-specific and substantially more work.

The Phase 1 finding *"no audited active K4 lead"* therefore remains operationally correct under the existing measurement, but cannot be sharpened until Phase 2.1 lands. This is documented in `current_signal_inventory.md` §"What would change this conclusion."

---

## Reproducibility checklist

- [ ] `PYTHONPATH=src python3 -m kryptos doctor` returns all-PASS.
- [ ] `null_baselines/manifest.json` `kernel_commit` matches current kernel.
- [ ] Calibration script executed with documented seed, sample count, kernel commit.
- [ ] Manifest committed; full distributions gitignored under `results/`.
- [ ] All five failure-mode guards in `tests/test_admitted_theory_null.py` pass.
- [ ] Ledger comparison report written and inspected.
- [ ] Phase 7 decision memo cites this calibration's outcome verbatim.

---

*Authored 2026-05-04 by Claude Opus 4.7 acting as principal research engineer / epistemic auditor. The phrasing intentionally distinguishes (a) what this calibration delivers, (b) what is deferred to Phase 2.1 (methodological-family null), and (c) what can be claimed from the current state. Do not promote claims beyond the data.*
