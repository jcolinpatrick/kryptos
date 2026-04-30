# Campaign 002 — Admission-Gated Micro-Campaign — Closure Note

| field | value |
|---|---|
| campaign_id | `campaign_002_admission_gated_micro` |
| run_id | `2026-04-30T11-20-18Z` |
| status | **CLOSED — null_level (side-effect predictions unfired)** |
| closed_on | 2026-04-30 |
| audit_artifact | `results/real_k4_hcc_bridge_audit/campaign_002_admission_gated_micro.json` |
| admission_validator | `scripts/_infra/validate_pseudo_clue_pack_admission.py` |
| admission_standard | `docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md` |
| audit_repro | `PYTHONPATH=src python3 -u <internal> --real-k4-hcc-bridge-audit --bridge-packs-dir data/k4_clue_packs/campaign_002_admission_gated_micro --real-k4-hcc-bridge-audit-out results/real_k4_hcc_bridge_audit/campaign_002_admission_gated_micro.json --real-k4-hcc-bridge-audit-max-specs 5000` |

## Result summary

- packs loaded: 3 (all admission-gated, all `tightened` from campaign 001)
- specs compiled / dispatched / scored: 30 / 30 / 30
- admissibility rejected / dispatch errors / no-candidate: 0 / 0 / 0
- max_crib: **1 / 24**
- expected null max (Binomial(24, 1/26), max over 30 draws): **3.24**
- p(max ≥ 1): **≈ 1.0**
- score histogram: {0: 15, 1: 15} — degenerate, no candidate reached crib_score = 2
- top-20 bean_passed: 0; top-20 ngram_score > 0: 0
- null classification: `null_level`
- run-level classification: `interpretive_pipeline_test` (no promotion)
- wall time: 0.2 s

## Validator result

All 3 packs passed mechanical admission checks (HUMAN_REVIEW markers
on R7 / R10 acknowledge the side-effect and predeclared-success
phrases are present and require an author's judgment that they are
falsifiable — judgment is recorded below).

## Side-effect prediction outcomes

Each pack predeclared a side-effect that activates only at
`crib_score >= 12`. No candidate reached that threshold, so no
prediction was either corroborated or falsified. The predictions are
preserved for any future campaign that produces a candidate above the
activation gate.

| pack | predicted side-effect | activation threshold | observed | outcome |
|---|---|---:|---:|---|
| 002-01 Stehle (LESSON-019, BERLIN-only) | `bean_passed=True` | crib_score ≥ 12 | max crib_score = 1 | **UNFIRED** |
| 002-02 width-21 (route_boustrophedon+vig, BERLIN-only) | `ngram_score >= -8` | crib_score ≥ 12 | max crib_score = 1 | **UNFIRED** |
| 002-03 BCL VB (col+variant_beaufort, KRYPTOS-only) | `bean_passed=True` | crib_score ≥ 12 | max crib_score = 1 | **UNFIRED** |

## Disposition

This is a **null-level closure**. The encodings are rejected at this
search breadth; the families remain not-impossible (per the rule that
campaign-001 negative evidence rejects the encoding, not the family).
The side-effect predictions are preserved and will activate on any
future tighter pack that produces a candidate above the threshold.

Notable structural observations:

1. **Below-random crib scores.** With 30 candidates, the null
   expected_max is 3.24; observed max is 1. A 50/50 histogram split
   between scores 0 and 1 means each candidate is performing close to
   independent of the disclosed cribs. Tightening to evidence-driven
   keyword pools (single keyword each pack) preserves admission
   discipline but eliminates the broader keyword sampling that
   produced the campaign-001 ceiling at 5/24.
2. **The trade-off is interpretable.** Campaign 001 was 1,730 specs
   with max_crib=5 and null_expected_max=5.35 (p=0.965). Campaign 002
   is 30 specs with max_crib=1 and null_expected_max=3.24 (p≈1.0).
   Both are null. Campaign 002's smaller search has a lower null
   threshold — so any signal it DID produce would be more
   interpretable. It produced none.

## Hard rule for future campaigns

Same as the campaign 001 rule: **do not expand by adding more packs of
campaign-001 or campaign-002 shape**. The next admission-gated micro
campaign should EITHER

- (a) add a new provenance source not yet cited
  (`campaign_001_coverage: new_provenance` per the admission standard),
  AND/OR
- (b) test a structurally new mechanism not in the existing routing
  table (which requires extending the bridge compiler, NOT this task),

**before** adding more packs. Repeating the tightening axis without a
new evidence anchor will only further constrain a search that has
already returned null.

## Per-family rollup (for negative-evidence ledger reference)

| pack | provenance | mechanism | n_specs | max_crib | bean any | ngram>0 any | side-effect outcome |
|---|---|---|---:|---:|---:|---:|---|
| 002-01 | E0a Stehle + BERLIN crib | LESSON-019 (caesar+columnar+route_boustrophedon), shift=5 width=4 | 12 | 1 | no | no | unfired |
| 002-02 | E0e width-21 + BERLIN crib | route_boustrophedon + vigenere, width=21 | 12 | 1 | no | no | unfired |
| 002-03 | E0b KRYPTOS-distance + KRYPTOS keyword | columnar + variant_beaufort | 6 | 1 | no | no | unfired |

---

*Authored 2026-04-30 by Claude Opus 4.7 + Colin Patrick. The
admission-gated micro-campaign approach is validated end-to-end:
30 specs, 0.2 seconds, clean null with zero false-promotion risk.*
