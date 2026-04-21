# Phase R2-4 — Matched nulls for columnar and extended variant families

**Date:** 2026-04-21
**Round:** Maturation Round 2
**Author:** Claude Code Opus 4.7
**Status:** complete — 6 new distributions calibrated, committed to manifest, K3 extreme-null validated

## Summary

| Metric | Before R2-4 | After R2-4 |
|---|---|---|
| matched_variant_family distributions | 1 (Vigenère-AZ from Phase 6) | **7** (added 6 × R2-4) |
| Families with matched nulls | Vigenère only | **Vigenère, Beaufort, Variant-Beaufort, columnar_single, columnar_double** |
| ngram_score × transposition null | not built | **2 new distributions** |
| Calibration wall-clock (50K × 6) | N/A | **14.1s on the 28-vCPU VM** |
| Test count (kryptosbot) | 617 | **635** (+18 R2-4 tests) |
| Test count (core) | 1525 | 1525 (unchanged) |

**K3 discovery status: YES** (§0.5 policy — R2-4 is calibration-layer work only; self-test behavior unchanged. Verified: cycle 9345.)

## 1. What was calibrated (brief §5.1)

Six new distributions, all at `n_chars=97`, `alphabet=AZ`, `n_samples=50000`, `seed=42`:

| # | Scorer | Family | Mean | Stdev | Max observed |
|---|---|---|---|---|---|
| 1 | `crib_score` | `beaufort` | 0.9180 | 0.957 | 7 |
| 2 | `crib_score` | `variant_beaufort` | 0.9147 | 0.942 | 6 |
| 3 | `crib_score` | `columnar_single` | 1.0244 | 0.977 | 7 |
| 4 | `crib_score` | `columnar_double` | 1.0201 | 0.989 | 7 |
| 5 | `ngram_score` | `columnar_single` | -6.4015 | 0.064 | -6.063 |
| 6 | `ngram_score` | `columnar_double` | -6.4062 | 0.065 | -6.057 |

**Scale sanity:** the expected mean of `crib_score` under a truly random 24-position 26-alphabet match is 24/26 ≈ 0.923. The additive families (beaufort, variant_beaufort) land within 0.01 of that — good. Columnar families land slightly higher (~1.02), reflecting the fact that columnar output is a permutation of the real K4 CT (which has a distribution biased toward English-frequency letters), so coincidental crib matches are slightly more likely than pure random. The separation tracks theory; R2-4 does not try to correct it because the brief explicitly calls for *family-matched* nulls, not identical distributions.

**ngram_score on columnar outputs:** mean per-char ≈ -6.40 is consistent with uniform-letter baseline (uniform English-ish quadgrams: about -6.4). The scorer's frequency is quadgram, not unigram, so permuting letters does NOT preserve quadgram frequencies — columnar output looks ngram-random, not English-like. K3's plaintext (-3.78-ish, English) is ~40 stdevs above the mean under this null, confirming the brief's §5.5 extreme-null expectation.

## 2. Sampling semantics (brief §5.2) — deviation clarified

The brief's §5.2 pseudocode described a 4-step process that appears to include a superfluous step 2 (encrypting a random PT with the drawn key). R2-4's implementation adopts the simpler equivalent: **"draw a random family member (key/widths/permutations), apply it as decryption to the real K4 CT, score the candidate."** The PT-sampling step is eliminated because the random PT is never used downstream.

**Legacy Phase 6 `matched_variant_family__AZ` (family="")** — preserved unchanged. The Phase 6 semantic was "random-PT-encrypted-with-random-key produces some CT, score it against K4 cribs." That null is actually closer to `random_text` than to "what a family member does to K4 CT." R2-4 does NOT rewrite that entry (to avoid breaking Phase 6 alert-gate semantics) but the 6 new entries use the corrected brief §5.2 semantics. This is documented in the phase report rather than silently changed.

## 3. Schema change

`NullDistribution` gained an optional `family: str = ""` field:

- `cache_key` now includes the family for matched_variant_family entries: `crib_score__matched_variant_family__AZ__n97__columnar_double`.
- Empty family preserves the Phase 6 cache key (`crib_score__matched_variant_family__AZ__n97`) for backward compatibility.
- Full cache filename + manifest entry both include the family suffix.
- `from_dict` / `to_full_dict` round-trip the new field.

`get_cached()` and `get_or_build()` accept an optional `family=""` keyword. Callers that don't pass it see Phase-6 behavior.

`_sample_one_matched_family` dispatches on family name:

- `""` → legacy Phase 6 path (unchanged).
- `"vigenere"` | `"beaufort"` | `"variant_beaufort"` → random keyword, decrypt K4 CT.
- `"columnar_single"` | `"columnar_double"` → random `(width, col_order)` per layer, decrypt K4 CT.

## 4. Calibration script

New: `scripts/_infra/calibrate_null_baselines_r2_4.py`. Single command:

```bash
PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines_r2_4.py
```

- Builds all 6 distributions in deterministic order with fixed seed=42.
- 50,000 samples each (per brief §5.4 — tighter than Phase 6's 100K; total runtime 14.1s including all 6).
- `--quick` flag for 2K-sample smoke tests.
- `--only-family` flag for incremental rebuilds.

No multiprocessing needed — the 14-second total runtime is well under the brief's 5-minute budget. Committing single-threaded keeps the calibration artifact deterministic across runs.

## 5. Tail resolution note (brief §5.4)

Empirical tail floor: **1/50000 = 2 × 10⁻⁵**. The brief explicitly called this out: "for columnar p-values below ~2 × 10⁻⁵ the reported value is a floor, not a point estimate." R2-4 implements this by returning `1/N` as the p-value when an observation exceeds the empirical max. For the ngram_score × columnar distributions there is no parametric extrapolation: `parametric_model=None`, `p_value_tail_method="empirical"`. Real signal far beyond the tail (e.g., English text) still registers as "below the floor" rather than as a miscalibrated pseudo-Gaussian tail.

For `crib_score × matched_variant_family` on additive families, the brief's original Phase-6 Gaussian approximation is preserved by `normal_approx` fallback. Transposition families do NOT get the Gaussian approximation — the skewed discrete distribution defeats the Gaussian tail estimate at the interesting tail. Documented in code (`null_baselines.py:489`):

> R2-4: ngram_score on transposition nulls is empirical only — the output is a permutation of the K4 CT and carries the empirical letter-frequency structure of the carved text, not a Gaussian-behaving noise process. The brief §5.4 documents this 1/N floor explicitly; do not pretend normality.

## 6. K3 integration check (brief §5.5)

The test `TestK3UnderColumnarDoubleNull::test_k3_pt_is_extreme_vs_columnar_double_null` exercises the acceptance criterion:

> "Verify the known-answer K3 configuration is extreme under this null (p < 10⁻⁵ expected, given the matched-family baseline should concentrate around random-noise scores)."

Under the `ngram_score × columnar_double` null (mean -6.40, stdev 0.065), K3's first-97-char plaintext prefix scores approximately **-3.8** per char (English). That's roughly **40 standard deviations** above the null mean. The normal-tail p-value pins to essentially zero; the empirical floor is 2e-5. Test asserts `p ≤ 1e-3` (a generous margin that passes with room to spare).

**Interpretation:** a real cipher break like K3 should be dramatically extreme under matched nulls. The test doubles as a sanity check that the null-distribution pipeline is wired correctly — if a future change accidentally made the null look English-like, this test would catch it.

## 7. Manifest changes (committed)

Manifest at `null_baselines/manifest.json` now includes 6 new entries under `distributions.*`. Each carries:

- `family` — the cipher family tag.
- Full percentile snapshot (p01 through p999).
- `parametric_model: null` for columnar (empirical only, per §5).
- `parametric_model: "normal"` for beaufort/variant_beaufort crib_score (consistent with Phase 6 Vigenère treatment).

The full distribution JSON files live under `results/null_baselines/` (gitignored); only the manifest summary is committed.

## 8. Test delta

New file: `kryptosbot/tests/test_r2_4_matched_nulls.py` — 18 tests in 4 classes.

| Class | Tests | Guards |
|---|---|---|
| `TestFamilyFieldPlumbing` | 4 | valid_families contents; cache_key disambiguation; legacy empty-family cache_key stable; dict round-trip |
| `TestBuildSanity` | 5 (4 parametrized + 1) | each of 4 families builds cleanly; unknown family raises |
| `TestManifestContainsR2_4Entries` | 6 (parametrized) | manifest has all 6 R2-4 entries with correct family/method/alphabet/n_chars |
| `TestGetCachedHonorsFamily` | 2 | columnar_double cache hit; legacy empty family still hits Phase 6 cache |
| `TestK3UnderColumnarDoubleNull` | 1 | **Integration: K3 plaintext is p ≤ 10⁻³ under the columnar_double ngram null** |

**Full test counts:**
```
tests/ (core):     1525 passed (unchanged)
kryptosbot/tests/: 635 passed (was 617 after R2-3, +18 new R2-4 tests)
Total:             2160 passed, 6 deprecation warnings (pre-existing), 0 failures
```

## 9. Brief acceptance criteria (§5.5) — self-audit

| Criterion | Status |
|---|---|
| 6 new distributions calibrated and committed | ✅ manifest contains all 6 |
| `null_baselines.get_cached` returns new entries correctly | ✅ `test_columnar_double_cache_hit` |
| Phase 6 alert gate behavior unchanged for Vigenère | ✅ family="" cache_key unchanged |
| R2-1's K3 configuration extreme under columnar_double null | ✅ `test_k3_pt_is_extreme_vs_columnar_double_null` |
| ≥ 6 new tests | ✅ 18 tests across 4 classes |

## 10. Self-test at phase exit

K1 cycle 15; K2 cycle 17; K3 cycle 9345. No drift. Artifact: `results/self_test/r2_4_final.json`.
