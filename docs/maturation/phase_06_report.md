# Phase 6 — Calibrated null baselines — Report

**Date:** 2026-04-21
**Entry baseline:** `e1afbff [auto] Update 1 doc(s),4 other file(s)` (Phase 5 content)
**Goal (brief §8):** replace raw-score reasoning with p-value reasoning.
A `crib_score` of 18 means nothing in isolation; what matters is
P(crib_score ≥ 18 | matched null on same n, same alphabet, same scoring path).

---

## 1. What shipped

| Component | Lines / count |
|---|---|
| `kryptosbot/null_baselines.py` | 408 lines; NullDistribution + build/cache/p-value + staleness |
| `scripts/_infra/calibrate_null_baselines.py` | 110 lines; offline batch calibrator |
| `null_baselines/manifest.json` | 5 distributions calibrated (committed) |
| `results/null_baselines/*.json` | 3.4 MB full distributions (gitignored) |
| `src/kryptos/kernel/scoring/aggregate.py` | +`p_value_breakdown` field on `ScoreBreakdown`, +`_compute_p_value_breakdown` helper, +`include_p_values` param on `score_candidate` |
| `kryptosbot/alerts.py` | +`_p_value_gate_passes()`, `classify_outcome()` gates SIGNAL + BREAKTHROUGH on p-value |
| `kryptosbot/dsl_tools.py` | `compute_null_baseline` now wired to the real module (Phase 5 stub retired) |
| `kryptosbot/tests/test_null_baselines.py` | 17 new tests |
| `kryptosbot/tests/test_dsl_tools.py` | 4 tests updated to reflect expanded tool capability |

**Test delta this phase:** `kryptosbot/tests/` 512 → 530 (+18, net). `tests/` unchanged.

---

## 2. Distribution summaries

From `null_baselines/manifest.json`, produced by the offline calibrator
on kernel commit `e1afbff1`:

| Scorer | Method | n_samples | Mean | Stdev | Max | Parametric tail | Wall-clock |
|---|---|---|---|---|---|---|---|
| `crib_score` | `random_text` | 100 000 | **0.9237** | **0.9423** | 7 | Binomial(24, 1/26) (exact) | 3.71s |
| `crib_score` | `shuffled_ct` | 100 000 | 1.0163 | 0.9837 | 8 | (empirical) | 2.66s |
| `crib_score` | `matched_variant_family` | 100 000 | 0.9210 | 0.9409 | 7 | (empirical) | 6.05s |
| `ngram_score` | `random_text` | 50 000 | −6.4262 | 0.0824 | −5.9127 | Normal (CLT fit) | 2.99s |
| `ngram_score` | `shuffled_ct` | 50 000 | −6.4073 | 0.0648 | −6.0766 | Normal (CLT fit) | 2.38s |

**Theoretical check (crib_score × random_text):**
24 Bernoulli(1/26) sum ⇒
- Expected mean: 24/26 = 0.9231
- Expected stdev: √(24 × 1/26 × 25/26) = 0.9421

Empirical 0.9237 / 0.9423 matches to 3-4 decimals. Directly verified in
`TestTheoretical::test_crib_score_random_text_mean_matches_theory`.

**Right-tailed p-values for crib_score × random_text** (exact Binomial):

| crib_score | p-value |
|---|---|
| ≥ 5 | 1.94 × 10⁻³ |
| ≥ 10 | 8.45 × 10⁻⁹ |
| ≥ 18 | 3.65 × 10⁻²¹ |
| ≥ 24 | 1.10 × 10⁻³⁴ |

The alert-gate threshold (1 × 10⁻⁶) corresponds to crib_score ≈ 6-7
under random_text. Any contract that clears the project's pre-existing
SIGNAL threshold (crib_score ≥ 18) clears the p-value gate by 15 orders
of magnitude.

---

## 3. `NullDistribution` design decisions

### 3.1 Why mix empirical and parametric tails

Brief §8.6 requires p-values reliable below 1 × 10⁻⁶. A 100 000-sample
empirical MC can only resolve to ~10⁻⁵; the 1/N floor truncates any
observation more extreme than the most-extreme sample. Two options:

- **(A)** Scale MC to 10⁷+ samples. Days of compute per distribution.
- **(B)** Fit a parametric family when one is derivable and use the
  analytic tail for extreme observations.

Phase 6 took (B):

- `crib_score` is analytically **exactly** Binomial(24, 1/26) under
  random_text (24 independent Bernoulli trials at positions 21-33 and
  63-73, each matching with probability 1/26). No parametric
  approximation error. Implemented in `_binomial_right_tail`.
- `ngram_score` is a sum of ~94 quadgram log-probabilities per
  plaintext. CLT applies; the empirical distribution is strikingly
  Gaussian (see the tight stdev above). `_normal_right_tail` uses
  `math.erfc`.
- `composite` has no clean parametric form; the empirical tail with
  1/N upper bound is the honest fallback.

### 3.2 Cache schema

`results/null_baselines/<scorer>__<method>__<alphabet>__n<chars>__v1.json`
stores the full sorted scores (multi-MB). **Gitignored.**

`null_baselines/manifest.json` stores a per-distribution summary:
mean, stdev, percentiles (p01..p999), parametric_model, `kernel_commit`,
`seed`, `n_samples`. **Committed** so anyone cloning can see which
calibration state the repo expects.

`calibration_stale(dist)` compares the stored `kernel_commit` against
the current git HEAD. When they differ, the cache is considered stale
and `get_or_build` rebuilds. `'unknown'` commits (git unavailable at
build or load time) are treated as never-stale so CI environments
without git don't cause false invalidations.

---

## 4. Alert-path integration (brief §8.4)

### 4.1 Gate behaviour

`kryptosbot/alerts.py::classify_outcome` now runs
`_p_value_gate_passes(best_plaintext, crib_score, hypothesis_id)`
before returning either SIGNAL or BREAKTHROUGH. The gate:

1. Calls `null_baselines.p_value_for_alert` which looks up the
   `(crib_score, random_text, AZ, 97)` distribution from the cache.
2. If cache present and p-value ≤ 1 × 10⁻⁶: gate passes, alert fires.
3. If cache present and p-value > 1 × 10⁻⁶: gate fails, alert suppressed
   (INFO log).
4. If cache missing: gate passes open (legacy crib-score-only behaviour)
   with a WARNING log ("Alert is UNCALIBRATED: null baseline cache
   missing"). Once the operator runs the calibrator, subsequent alerts
   become properly gated.

### 4.2 Design rationale for fail-open on cache miss

The brief (§8.4) says: "if not, fall back to the old threshold and
emit a warning in the artifact that the alert is uncalibrated." Phase 6
implements this exactly: **an uncalibrated framework never becomes
silent on a high score**. It just degrades to the pre-Phase-6 behaviour
with a visible WARNING. This prevents a dropped cache from masking a
real signal.

### 4.3 Why it doesn't change existing test outcomes

All existing alert tests use synthetic contracts where
`best_plaintext` is typically empty or a short placeholder. The cache
lookup returns the real 100K-sample distribution, p_value for crib=18
comes back as ~3.7 × 10⁻²¹ (well below gate), and the alert fires
identically. The only test that had to change was one of the Phase 5
`compute_null_baseline` tests that had explicitly asserted
`not_yet_available` for combos now supported.

---

## 5. `ScoreBreakdown.p_value_breakdown` field (brief §8.3)

New optional field on the canonical ScoreBreakdown dataclass:

```python
p_value_breakdown: Optional[Dict[str, float]] = None
```

Populated by `score_candidate(..., include_p_values=True)` via
`_compute_p_value_breakdown`, which looks up the null cache and fills:

```python
{"crib_score": 3.7e-21,  "ngram_score": 0.05}
```

`None` means either the caller didn't request p-values OR the null
cache is unavailable. Every existing caller that constructs a
ScoreBreakdown without `include_p_values` sees `None`, so backward
compatibility is absolute. Serialized by `to_dict()` only when populated.

---

## 6. `dsl_tools.compute_null_baseline` rewire

The Phase-5 stub supported exactly one combo and returned
`not_yet_available` for the rest. Phase 6 replaced the implementation
body with a direct call through `null_baselines.get_cached` +
`null_baselines.get_or_build`. Now **every** combo in
`_VALID_SCORERS × _VALID_METHODS × _VALID_ALPHABETS` is handled.

Failure modes now return `status="error"` (hard validation failure) or
`status="not_yet_available"` (only if an unsupported scorer raises
`NotImplementedError`, e.g. future `matched_variant_family` for a
non-Vigenère family). The envelope provenance reports `cache: "hit" |
"rebuilt_stale" | "miss_built"`.

Four Phase-5 tests in `test_dsl_tools.py` were updated to match the
richer tool capability. The Phase-5 stub's `results/null_baselines_phase5_stub.json`
cache file is now unused; the `_PHASE5_NULL_CACHE_PATH` constant is
retained as a legacy-path reference but no code writes to it.

---

## 7. Calibration script (brief §8.5)

`scripts/_infra/calibrate_null_baselines.py`:

```bash
# Full calibration (default):
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py

# Smoke calibration (reduced sample counts):
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py --quick

# Target one scorer:
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py --only crib_score
```

Full calibration runs in **17.8 seconds** on the 28-core VM (single-threaded;
no parallelism needed because the per-distribution wall-clock is already
small). Builds the 5 standard distributions listed in §2.

The script path was one fix iteration: `kryptosbot/` lives at repo root,
not under `src/`, so the script needed a separate `sys.path.insert(0, _ROOT)`
in addition to the usual `src/`. Caught by the first run of the calibrator.

---

## 8. Test battery (brief §8.6)

`kryptosbot/tests/test_null_baselines.py` (17 tests in 6 classes):

| Class | Tests | Purpose |
|---|---|---|
| `TestTheoretical` | 4 | Empirical ⇋ closed-form check; Binomial and normal tail spot-checks |
| `TestPValueSemantics` | 4 | p-value at p99 ≈ 0.01, tail behaviour, parametric dominance, free-function ⇋ method equivalence |
| `TestStaleness` | 3 | Same / different / 'unknown' kernel commit handling |
| `TestCache` | 2 | Cache miss returns None; save/load roundtrip preserves fields |
| `TestK1Sanity` | 1 | A known correct-crib PT has p < 10⁻¹⁰ against the matched null |
| `TestAlertIntegration` | 3 | `p_value_for_alert` happy path, gate suppression (via monkeypatch), cache-miss fallback |

All 17 pass in 0.74s.

---

## 9. Acceptance criteria (brief §8.7)

| Criterion | Status |
|---|---|
| `kryptosbot/null_baselines.py` exists with three null models and caching | ✅ (random_text, shuffled_ct, matched_variant_family; all three cached) |
| Alerts now gate on p-value | ✅ (with fail-open fallback to legacy on cache miss, brief-mandated) |
| Null cache manifest committed | ✅ (`null_baselines/manifest.json`) |
| `docs/maturation/phase_06_report.md` includes the null-distribution summaries | ✅ (§2 of this file) |
| Full suite green | ✅ (`tests/` 1525; `kryptosbot/tests/` 512 → 530, +18 net) |

---

## 10. Deferred to later phases

| Item | Phase |
|---|---|
| `composite` scorer null distribution (fast enough but skipped for Phase 6 scope) | any |
| `matched_variant_family` for non-Vigenère families (beaufort, variant_beaufort, columnar, ...) | any (per-family add) |
| KA-alphabet distributions for the scorers (Phase 6 is AZ only) | when KA cipher support lands — linked to Phase 5 dispatcher work |
| `include_p_values=True` propagated through the dispatcher's `_evaluate_one` worker | next Phase 4 / 5 revision (trivial wiring) |
| Exact Binomial tail extended to crib_score × shuffled_ct (K4 CT letter distribution differs from uniform; strictly, this needs a multivariate hypergeometric for exactness) | future precision work if ever needed |
| Adaptive MC that targets n_samples = f(smallest required p-value) | future if 10⁻⁸ resolution becomes actionable |

---

## 11. Changed files summary

```
A  kryptosbot/null_baselines.py                        (408 lines)
A  scripts/_infra/calibrate_null_baselines.py           (110 lines)
A  null_baselines/manifest.json                         (manifest, committed)
M  src/kryptos/kernel/scoring/aggregate.py               (+p_value_breakdown field, helper)
M  kryptosbot/alerts.py                                  (+_p_value_gate_passes, gate in classify_outcome)
M  kryptosbot/dsl_tools.py                               (compute_null_baseline rewired)
M  kryptosbot/tests/test_dsl_tools.py                    (4 tests updated for richer tool)
A  kryptosbot/tests/test_null_baselines.py               (17 new tests)
A  docs/maturation/phase_06_report.md                    (this file)
```

No change to the dispatcher, the DSL, the controller's cycle, the kernel
scoring algorithms, the campaign runner, or any production path outside
the alert path (which fails open to legacy on cache miss).
