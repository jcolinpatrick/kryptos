# Campaign 001 — Closure Note

| field | value |
|---|---|
| campaign_id | `campaign_001_team_of_rivals` |
| run_id | `2026-04-30T10-53-32Z` |
| status | **CLOSED — null_level** |
| closed_on | 2026-04-30 |
| audit_artifact | `results/real_k4_hcc_bridge_audit/campaign_001_team_of_rivals.json` (gitignored — regenerable, not committed) |
| audit_repro | `PYTHONPATH=src python3 -u kryptosbot/run_controller.py --real-k4-hcc-bridge-audit --bridge-packs-dir data/real_k4_pseudo_clue_packs/campaign_001_team_of_rivals --real-k4-hcc-bridge-audit-out results/real_k4_hcc_bridge_audit/campaign_001_team_of_rivals.json --real-k4-hcc-bridge-audit-max-specs 5000` |
| campaign_commit | `8426844` |

## Result summary

- packs loaded: 31
- specs compiled / dispatched / scored: 1,730 / 1,730 / 1,730
- admissibility rejected / dispatch errors / no-candidate: 0 / 0 / 0
- max_crib: **5 / 24**
- expected null max (Binomial(24, 1/26), max over 1,730 draws): **5.35**
- p(max ≥ 5): **0.965**
- null classification: `null_level`
- top-20 bean_passed: 0; top-20 ngram_score > 0: 0
- run-level classification: `interpretive_pipeline_test` (no promotion)

## What this means

The bridge worked end-to-end. The hypotheses did not. The observed
maximum is **below** the expected null max for a search of 1,730
candidates, and **no** top candidate carries any corroborating
plaintext-shape support (Bean and ngram both null). The null model is
intentionally LOOSE (independent Binomial across n_candidates is an
upper bound on the null tail because real candidates are correlated
decrypts of one ciphertext); even under that loose null, the campaign
produced less apparent signal than chance.

## What this does NOT mean

- **It does not prove any tested family is impossible.** It rejects
  these specific encodings at this specific search breadth. A pack
  with a stronger mechanism mapping or a tighter parameter constraint
  could still produce signal where these did not.
- **It does not invalidate the bridge.** Schema, compiler, dispatch,
  scoring, null calibration, and the non-claim banner all worked as
  designed.
- **It does not justify a real-K4 progress claim of any kind.**

## Hard rule for follow-up campaigns

More breadth raises the maximum-of-N null threshold. Adding more
packs of the same shape is **not** a productive next step. Future
real-K4 pseudo-clue packs MUST meet the stricter admission standard
in [`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](../../../docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md)
before authoring or compute. The standard requires, among other
things, a predicted side-effect beyond crib score (Bean effect, ngram
floor, anomaly alignment, or null-mask/route prediction) so that any
future "promising" hit carries independent corroboration on day one.

## Per-family rollup (for negative-evidence ledger reference)

| family | name | packs | specs | max_crib | bean_pass any | ngram>0 any | disposition |
|---|---|---:|---:|---:|---:|---:|---|
| F1 | public crib geometry | 5 | 204 | 4 | no | no | no signal under campaign_001 encoding |
| F2 | Sanborn/Scheidt two-systems (Tier-3 hearsay) | 5 | 630 | 4 | no | no | no signal under campaign_001 encoding |
| F3 | Stehle anomaly (+5 / spacing-4) | 4 | 103 | 3 | no | no | no signal under campaign_001 encoding |
| F4 | BCL Beaufort (post-retired-palette policy) | 4 | 60 | 3 | no | no | no signal under campaign_001 encoding |
| F5 | width-21 vertical bigrams (and post-null w10/w17) | 5 | 252 | 4 | no | no | no signal under campaign_001 encoding |
| F6 | NDYAHR / YAR shifted-letter | 4 | 391 | 3 | no | no | no signal under campaign_001 encoding |
| F7 | K2/K3 provenance analogy | 4 | 90 | 5 | no | no | no signal under campaign_001 encoding |
| total | | 31 | 1730 | 5 | no | no | null_level (p=0.965) |

The F7 search-wide ceiling (5/24) was tied by a single
PALIMPSEST/ABSCISSA vig+col candidate with `bean_passed=False` and
`ngram_score=0.0` — the classic null-level pattern of a coincidental
crib match without plaintext-shape corroboration.

---

*Authored 2026-04-30 by Claude Opus 4.7 + Colin Patrick. This file is
authoritative for campaign 001 disposition; if MEMORY.md or anywhere
else references campaign 001 as live, treat that reference as stale
and update it to point here.*
