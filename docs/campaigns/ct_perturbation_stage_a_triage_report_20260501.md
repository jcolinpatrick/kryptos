# CT-Perturbation Stage A Triage Report

Date: 2026-05-01

## 1. Executive Summary

Stage A was not fully correct as first run. The old full run did iterate the advertised 10,465,764 configurations, but the KA half used AZ-derived Bean constraints while KA candidate keystreams were recovered in KA index space. That is a semantic bug, not a harmless artifact issue.

The suite has been hardened. Bean derivation is now CT- and alphabet-parametric, H0/H1 accounting is explicit, JSONL artifacts are always created, artifact audit CLI exists, missing KA ngram null cannot produce solution-grade alerts, `--resume` fails closed, trace mode records actual loop visits, and selective synthetic recovery now exercises a crib-position correction.

The hardened full rerun `triaged_20260501T173033Z_full` completed and passed audit:

- expected/evaluated configs: 10,465,764 / 10,465,764
- H1 variants: 2,425
- H0 variants: 1
- total CT variants: 2,426
- crib-position H1 variants: 600
- non-crib-position H1 variants: 1,825
- bean_pass_total: 0
- alerts/watchlist: 0 / 0

## 2. What Was Audited

Audited files and related dependencies:

- `kryptosbot/ct_perturbation.py`
- `scripts/campaigns/ct_perturbation_stage_a.py`
- `tests/test_ct_perturbation_stage_a.py`
- `docs/campaigns/ct_perturbation_stage_a_prereg.md`
- `kryptosbot/null_baselines.py`
- `scripts/_infra/calibrate_null_baselines.py`
- `kryptosbot/config.py`
- `kryptosbot/constants.py`
- `src/kryptos/kernel/constants.py`
- `src/kryptos/kernel/transforms/vigenere.py`
- `src/kryptos/kernel/scoring/`
- `wordlists/thematic_keywords_v2.txt`

No deprecated `campaign_v2.py` or deprecated `worker.py` imports were found in Stage A. No use of `kryptosbot.config.K4_CIPHERTEXT`, `KRYPTOS_CT_OVERRIDE`, or `KRYPTOS_CRIB_DICT_OVERRIDE` was found in the suite. Running-key, non-English source text, CorpusLicense, Stage B, Stage C, and source-text bijection branches remain unimplemented and unexposed.

## 3. Exact Observed Old Run

Run id: `20260501T160636Z_full`

Command:

```bash
PYTHONPATH=src python3 -u scripts/campaigns/ct_perturbation_stage_a.py \
  --keywords wordlists/thematic_keywords_v2.txt \
  --workers 26 \
  --execute-full \
  --include-h0-baseline \
  --synthetic-recovery-test \
  --run-id 20260501T160636Z_full
```

Observed terminal output:

```text
Synthetic recovery: passed=True alerts=1 candidates=58224
Stage A run 20260501T160636Z_full: ct_variants=2425 keywords=719 total_universe=10465764 workers=26
null cache: ngram_AZ=present ngram_KA=missing
Done. evaluated=10465764 alerts=0 watchlist=0 bean_pass=0
```

Old artifact audit failed because schema-v1 artifacts were not self-auditing:

- missing `coverage_report.json`
- missing `alerts.jsonl`
- missing `watchlist.jsonl`
- summary lacked schema/version, H0/H1 counts, expected cardinality, null status, worker/benchmark fields, and position-class counts
- log printed H1-only `ct_variants=2425` while total cardinality used 2,426 including H0

Old progress still recorded `variants_processed=2426` and `candidates_evaluated=10465764`, so no formula-only evaluated bug was inferred from the old counters.

## 4. Artifact Audit

Old run `20260501T160636Z_full`: audit failed for missing/self-insufficient artifacts. `audit_report.json` was written under that run directory documenting the failures.

Hardened run `triaged_20260501T173033Z_full`: audit passed.

Required schema-v2 artifacts now exist:

- `preregistration.json`
- `universe_manifest.json`
- `progress.json`
- `summary.json`
- `coverage_report.json`
- `top_candidates.jsonl`
- `watchlist.jsonl`
- `alerts.jsonl`
- `recovery_test_report.json`
- `audit_report.json`

JSONL files are present even when empty.

## 5. Runtime Audit

The old fast runtime is plausible. The old single-worker 100-H1 benchmark evaluated 435,714 configs in 36.1 seconds. With 26 workers, the old full 10.46M run in about 42 seconds was plausible.

The hardened full run took 47.9 seconds for the main sweep after synthetic recovery, reporting about 218,642 configs/sec. The runtime remains plausible after the KA Bean fix because variant-level work is parallelized across 26 workers.

## 6. Loop Accounting Audit

Counters now increment only inside visited config loops. The formula-derived expected cardinality is recorded separately as `expected_total_config_cardinality`.

Regression coverage includes:

- worker/config fault injection raises a controlled exception
- failed run writes `status=failed`
- failed run does not report `candidates_evaluated == expected_total_config_cardinality`
- progress records variants completed, expected total, candidates evaluated, workers, last completed variant, status, and errors
- `--trace-first-configs N` records actual visited configs with variant, family, alphabet, keyword, effective period, crib/Bean/ngram checks, and rejection reason
- workers=1 and workers=2 produce equivalent counts on a tiny universe

## 7. Cryptographic Semantics Audit

Kernel formulas confirmed:

- Vigenere: `K = CT - PT mod 26`, decrypt `PT = CT - K`
- Beaufort: `K = CT + PT mod 26`, decrypt `PT = K - CT`
- Variant Beaufort: `K = PT - CT mod 26`, decrypt `PT = CT + K`

Known-answer tests now cover all three families under both AZ and KA alphabets. Keyword letters are encoded through the selected alphabet, then cycled by keyword length.

Critical fixed bug: Bean constraints are now derived in the same alphabet index space used for the candidate. Canonical AZ constraints remain `(1 eq, 242 ineq, 101 linear)`. Canonical KA constraints are different `(1 eq, 254 ineq, 92 linear)`, so using AZ constraints for KA candidates was wrong.

## 8. CT-Perturbation Coverage Matrix

| Hypothesis | Covered? | Evidence | Caveat |
|---|---:|---|---|
| H0 canonical additive keyword | yes | H0 executed in hardened full run | Direct cribs and 719-keyword list only |
| H1 substitution at crib position | yes | 600 variants executed | Direct positional crib alignment only |
| H1 non-crib substitution affecting Bean | no | Bean uses crib positions only | Mathematically impossible under current setup |
| H1 non-crib substitution affecting ngram after survivor | partial | 1,825 variants executed | No survivor existed in full run |
| H1 insertion/deletion | no | substitution generator only | Not Stage A |
| H2 archive-anchored substitution | no | no H2 generator | Stage B only |
| independent period 1-26 | no | `period_policy=keyword_length` | period-expanded search not implemented |
| keyword outside curated list | no | keyword_count=719 | list-scoped only |
| non-keyword-periodic key | no | finite repeated keywords only | running-key out of scope |
| outer transposition before direct cribs | no | fixed CT/PT coordinates | separate model required |

## 9. Null Policy

Current null status:

- AZ ngram null: present
- KA ngram null: missing

Missing KA ngram null does not invalidate a `bean_pass_total=0` Bean-layer negative. It would invalidate future solution-grade KA alert semantics. The hardened policy keeps `require_null_for_alert=True`; with `--allow-null-unavailable`, missing-null candidates can be emitted only as `watchlist_null_unavailable`, not `alert`.

Deterministic KA ngram calibration path is documented in `ct_perturbation_stage_a_coverage_audit.md`; no KA null was faked.

## 10. Synthetic Recovery

Recovery report for hardened full run:

- structural recovery: passed, non-crib perturbation, 58,224 candidates, 1,826 alerts, 1 matching planted correction
- selective recovery: passed, crib-position perturbation at position 21, 12,696 candidates, 1 alert, 1 matching planted correction

The structural test is intentionally broad and degenerate because the synthetic plaintext filler is low-information. The selective test is the load-bearing recovery check for crib-position CT-parametric scoring.

## 11. Final Narrow Interpretation

Supported after the hardened full rerun:

> No Bean-consistent candidate was found under H0 plus all Hamming-1 single-character substitutions of the 97-character carved K4 CT, across {Vigenere, Beaufort, Variant Beaufort} x {AZ, KA} x the 719-keyword curated project list, using direct positional crib alignment and the implemented CT-parametric, alphabet-parametric Bean derivation. Under this direct-positional additive setup, only Hamming-1 substitutions at the 24 crib positions can change crib/Bean feasibility; non-crib substitutions are covered only insofar as they affect downstream scoring after a crib/Bean survivor exists.

Do not claim:

- K4 cannot be solved by CT correction.
- Sanborn did or did not make a mistake.
- Hamming<=2 is eliminated.
- All classical families are eliminated.
- The original independent period 1-26 proposal has been eliminated.
- Running-key, non-English source text, CorpusLicense, Stage B, or Stage C were implemented or tested.
