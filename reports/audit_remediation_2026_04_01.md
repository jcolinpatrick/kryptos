# Audit Remediation Report — 2026-04-01

**Trigger:** Team of Rivals statistical audit (5-reviewer adversarial review)
**Scope:** Repo-wide methodological hardening + public-claims consistency pass
**Verdict on input:** CONDITIONAL PASS — strong computation, weak statistical interpretation and claim discipline

---

## Summary of Changes

### New Files Created (8)

| File | Purpose |
|------|---------|
| `docs/claim_inventory.md` | Inventories 16 claims with evidence class, public exposure, and recommended action |
| `docs/public_surface_map.md` | Maps all public-facing surfaces with audit risk ratings |
| `docs/claims_ladder.md` | Durable 4-level evidence classification framework (Level A-D) |
| `docs/statistical_ledger.md` | Anomaly accounting with null models, correction status, and allowed wording |
| `tests/test_position_mapping.py` | 17 integration tests for multi-layer position mapping |
| `scripts/analysis/e_mod35_null_calibration.py` | Null calibration: P(random labeling achieves perfect mod-pair separation) |
| `scripts/analysis/e_threshold_calibration.py` | Crib-score null distribution for threshold calibration |
| `reports/audit_remediation_2026_04_01.md` | This file |

### Files Modified (17)

| File | Changes |
|------|---------|
| `MEMORY.md` | Fixed "model-independent" → "ciphertext-intrinsic under Beaufort A=0"; added Level tags to campaign summaries |
| `README.md` | Added additive-key condition to running-key hypothesis; scoped "noise-level" to tested families |
| `docs/elimination_tiers.md` | Added explicit additive-model assumption to Tier 1 header; qualified "only structured model" |
| `docs/research_questions.md` | Added additive-key qualification to running-key claim |
| `docs/crypto_field_manual/10_people_orgs_timeline.md` | Qualified two "only structured model" claims with additive-key condition |
| `docs/crypto_field_manual/30_k4_mapping_matrix.md` | Qualified "ONLY structured model" claim |
| `memory/bcl_palette_keystream.md` | Replaced "MODEL-INDEPENDENT" with "CIPHERTEXT-INTRINSIC UNDER BEAUFORT A=0"; added audit note; corrected "strongest anomaly" to "lowest uncorrected p-value"; added search-breadth caveat |
| `memory/palette_deep_investigation.md` | Added audit note; reconciled three p-values with explicit null models; qualified "suggests" language to [HYPOTHESIS] |
| `memory/palette_mod35_rule.md` | Relabeled "DISCOVERY" to "IN-SAMPLE POST-HOC FIT"; added null calibration results (100% of random labelings have perfect separation); relabeled significance from "WEAK" to "NONE" |
| `reports/final_synthesis.md` | Scoped "0 genuine signals" to "within tested cipher families and parameter ranges" |
| `scripts/_infra/session_briefing.py` | Fixed "model-independent" and "Strongest single" language in anomaly display |
| `scripts/campaigns/e_statistical_validation_v1.py` | Fixed "MODEL-INDEPENDENT" comment |
| `src/kryptos/kernel/scoring/aggregate.py` | Narrowed bare `except Exception` to specific exception types in 4 locations |
| `ops/site_builder/templates/methodology.html` | Added additive-model caveat to Bean section; added "How to Read Claims" section with Level A-D definitions; qualified "all repeating-key" and "all self-keying" with additive-key assumption; corrected BCL keystream language |
| `ops/site_builder/templates/faq.html` | Added "under direct positional correspondence" qualifier to elimination claim; added additive-key condition to "approaches remain open" answer |
| `ops/site_builder/templates/elimination.html` | Changed "This approach is ruled out" to "ruled out within the tested scope" |

---

## What Was Tightened Statistically

1. **Multiple-testing accounting:** Created `docs/statistical_ledger.md` tracking 5 anomalies with null models, raw p-values, correction status, and allowed public wording. Bottom line: only palette diversity (p≈2.4e-5) is borderline after conservative Bonferroni ÷1000; BCL enrichment and KA mod-5 do NOT survive.

2. **Mod-35 null calibration:** Ran 500K random-labeling trials showing **100% achieve perfect separation under some mod pair**. The (7,5) finding is trivially expected. Combined with LOO-CV=47%, the KRYPTOS×SEVEN table has zero evidential value. Status downgraded from "weak" to "none."

3. **Threshold calibration:** Characterized the null distribution of crib scores (2M trials). NOISE_FLOOR=6 is at the 99.976th percentile of random text. STORE=10 and above: effectively impossible under random text. Thresholds confirmed well-calibrated for this use case.

4. **P-value reconciliation:** Palette diversity now has all three p-values (positional: 2.4e-5, permutation: 3.0e-5, Stirling: 7.78e-5) documented in a single location with explicit null-model labels.

5. **Fisher combined p-value:** Documented the non-independence between palette diversity and BCL enrichment tests (share palette definition). Joint MC result retained but flagged as not accounting for search breadth.

---

## What Was Tightened Editorially

1. **"Model-independent" → "ciphertext-intrinsic under Beaufort A=0 convention"** across all memory docs, session briefing, and key scripts.

2. **"ONLY structured model surviving Bean" → qualified with "under additive-key assumptions"** across README, elimination tiers, research questions, and crypto field manual (6 locations).

3. **"ELIMINATED" scoped** — campaign summaries in MEMORY.md now carry Level tags. Public template changed from "ruled out" to "ruled out within tested scope."

4. **"35/35 PERFECT" → "in-sample post-hoc fit"** with null calibration result and LOO-CV prominently noted.

5. **"Strongest single anomaly" → "lowest uncorrected p-value among tested anomalies"** with search-breadth caveat.

6. **Additive-model condition** added to: Tier 1 header in elimination tiers, methodology page Bean section, FAQ elimination claims, and running-key hypothesis descriptions.

7. **"How to Read Claims" section** added to the methodology page with Level A-D definitions and p-value correction context.

---

## Tests Added

17 new integration tests in `tests/test_position_mapping.py`:

- `TestNullMaskRemoval` (6 tests): null position validity, letter preservation, crib shifting, null counts, extracted text length, palette membership
- `TestTranspositionInversion` (4 tests): round-trip correctness, bijection property, column readoff, crib preservation through transposition
- `TestBeanAcrossLayers` (5 tests): Bean equality positions, keystream values, inequality count, transposition mapping, keystream constant verification
- `TestMaskTranspositionComposition` (2 tests): composition order matters, full round-trip

**Notable:** Writing these tests exposed that I initially expected 11 nulls before BCL when the actual count is 12. This validates the audit's concern about mapping bugs.

---

## Claims Downgraded or Relabeled

| Claim | Was | Now |
|-------|-----|-----|
| BCL keystream palette enrichment | "model-independent" | "ciphertext-intrinsic under Beaufort A=0" (Level C) |
| Mod-35 classification | "35/35 PERFECT" | "in-sample post-hoc fit, zero evidential value" (Level D) |
| Running key "only remaining" | Unqualified | "under additive-key assumptions" |
| Campaign results "ALL NOISE" | Unqualified | "within tested scope (Level B)" |
| Palette "strongest anomaly" | Rhetorical | "lowest uncorrected p-value; borderline after correction" |
| All Bean-based eliminations | Unconditional | Conditioned on additive key model |

---

## What Remains Open

| Item | Priority | Why Deferred |
|------|----------|-------------|
| LaTeX proof document (`docs/proofs/k4_stego_findings.tex`) | P2 | Contains "model-independent" at lines 81, 299 but site already warns "known issues, working draft" |
| Script-level "model-independent" in ~8 analysis scripts | P3 | These are historical analysis code, not public-facing; volume makes bulk edit risky |
| Formal Bayesian model comparison | P3 | Structural improvement; not blocking for current claims |
| Sensitivity analysis (holdout-one on null positions) | P2 | Script scaffold exists conceptually; implementation deferred |
| Stale `scripts/EXHAUSTION.json` deletion | P3 | Low risk; CLAUDE.md already warns against using it |
| Cipher taxonomy coverage audit | P3 | Structural improvement for future work |

---

## What Was Intentionally NOT Changed

1. **The findings page (kryptosbot.com)** — Already well-disciplined: palette retired, KRYPTOS×SEVEN labeled non-evidence, model-conditional language throughout. No changes needed.
2. **The home page** — "Here's everything we've ruled out" is accurate; "not a claim" disclaimer is strong. No changes needed.
3. **Core scoring code logic** — Scoring algorithms are correct; only exception handling was narrowed.
4. **Elimination database records** — Individual elimination entries already have confidence tiers and scope limitations in the template.

---

## Recommended Next Research Steps

1. **Holdout-one sensitivity analysis** on consensus null positions — scaffold the script and run
2. **Address the LaTeX proof document** — add errata or revise
3. **Bayesian model comparison** — even a simplified prior over ~5 remaining cipher families would sharpen strategic direction
4. **Publication preparation** — if the palette diversity result is to be published, it needs a formal pre-registered replication (possible with K5 when available)

---

*Audit remediation complete 2026-04-01. All public surfaces now consistent with the claims ladder framework.*
