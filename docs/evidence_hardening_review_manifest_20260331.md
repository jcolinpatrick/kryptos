# Evidence-Hardening Review Manifest

**Date:** 2026-03-31
**Scope:** Project-wide claim discipline pass
**Standard:** Every public-facing claim must be auditable, every strong claim must have provenance,
every weak claim must be labeled weak, every invalid claim must be removed or retracted.

---

## Files Edited

### Site Templates (ops/site_builder/templates/)

| File | Changes |
|------|---------|
| **base.html** | Nav: "Findings" → "Observations" |
| **home.html** | "Finding 1/2/3" → "Observation 1/2/Exploratory"; "Confirmed findings" link → "Statistical observations"; "See what we found" → "See what we observed"; disclaimer rewritten to remove "three statistical findings constrain how K4 was constructed" |
| **findings.html** | Title: "Confirmed Findings" → "Statistical Observations"; intro rewritten (post-hoc, model-dependent caveats lead); proof PDF labeled as draft with known errors; "4 of 5 W's" cherry-pick downgraded to consequence note; Finding 3 radically demoted ("Exploratory — No Predictive Power", confidence bar lowered, stat pills lead with LOO-CV failure, caveat retitled "Why this is not evidence"); conclusion section rewritten with conditional language; "confirms" → "indicates" |
| **methodology.html** | "Quadruple-24 Coincidence" reframed as "not evidence, documented because community discusses it"; Bean proof scoped to "direct positional correspondence"; "leading model" → "working model (not proven)"; palette+keystream coupling labeled as not-independent tests |
| **faq.html** | "All standard cipher families exhaustively eliminated" scoped to "single-layer under direct correspondence" with multi-layer caveat |

### README.md

| Change | Detail |
|--------|--------|
| "Current hypotheses" → "Working hypotheses" | Added "None of these are proven" header |
| Null palette claim | Changed from "strongest confirmed statistical signal" to model-conditional language with Jaccard overlap stat |
| Scoring table | "Statistically significant" → "Unusual at short periods; likely false positive at periods >7" |
| Eliminations list | Added multi-layer caveat: "Single-layer eliminations do not rule out the same cipher family as one layer of a multi-layer construction" |

### CLAUDE.md

| Change | Detail |
|--------|--------|
| "confirmed findings" (2 occurrences) | → "statistical observations" |
| "leading hypotheses" | → "working hypotheses" |

### docs/

| File | Changes |
|------|---------|
| **kryptos_ground_truth.md** | "[USER GROUND TRUTH]" tag for scrambled-CT Cardan grille hypothesis → "[HYPOTHESIS]" with "This is unproven and should not be treated as fact" |
| **research_questions.md** | RQ-1 "It is likely position-dependent" → labeled as hypothesis with "this inference is unproven" |
| **anomaly_registry.md** | "Through our lens: if K4 uses a Hill cipher component, that would explain..." → "Hill cipher is algebraically eliminated... The 'HILL' reading is a physical observation; it has not led to a productive attack vector"; YAR "Through our lens" speculation → "Speculation (not evidence)" with "None have produced testable predictions that survived evaluation" |

### reports/

| File | Changes |
|------|---------|
| **k4_stego_findings_public.md** | Title: "What We Found Hidden Inside Kryptos K4" → "Statistical Observations on Kryptos K4 Null Positions"; added evidentiary status warning block; "strong evidence that K4 uses a hidden layer" → conditional language; all "Finding #N" → "Observation #N"; "Independent Confirmation from Dr. Richard Bean" → caveats added (not independent, same data/model); "Espionage Signature" section (KGB numerology) → "Thematic Associations (Not Evidence)" with explicit "no evidentiary value" statement; "What This Means for Solving K4" → all conditional ("if the null model is correct"); "The cipher is standard — probably Beaufort" → "The cipher type is unknown"; "we believe the stego layer is now largely understood" → "we observe a statistically unusual palette restriction"; "Finding #3: The 14-Column Grid" → "Observation #3 (Exploratory)"; "Finding #4" → labeled no predictive power; p-value standardized to 1/16,000 |

### ops/site_builder/overrides.toml

| Change | Detail |
|--------|--------|
| **e_varying_null_resolution** | Override added: best_score=0, verdict=NOISE, title/description explain this is not a decryption test (fixes H2 from site audit) |
| **E-AUTOKEY-VIG-AZ** | Added scope_limitations explaining structural impossibility and why 21/24 is expected (fixes H4 from site audit) |

---

## Files Created

| File | Purpose |
|------|---------|
| **docs/EVIDENCE_POLICY.md** | Defines claim classification, what counts as evidence, language discipline rules, model-conditional result requirements, post-hoc finding rules, retraction protocol |
| **docs/SCRIPT_RIGOR_STANDARD.md** | Defines script quality tiers (A-E), standard header format, comment discipline rules, deprecation warning format |
| **REVIEW_MANIFEST.md** | This file |

---

## Claims Downgraded

| Claim | From | To | Reason |
|-------|------|----|--------|
| "Confirmed Findings" (site-wide label) | Confirmed | Statistical Observations | All findings are post-hoc and model-conditional |
| KRYPTOS × SEVEN "Finding 3" | Finding with 35/35 accuracy | Exploratory with zero predictive power | LOO-CV shows 47% accuracy (below 49% baseline) |
| Null palette "strong evidence" | Strong evidence | Model-conditional observation | Positions shift across cipher models (Jaccard 0.161) |
| "Independent confirmation" from Bean | Independent confirmation | Related observation using same data | Both use KA-family models on same 97-char ciphertext |
| Joint p-value "1 in 7 million" | Combined significance | Post-hoc combined test, not pre-registered | Computed after both observations known |
| "The cipher is standard — probably Beaufort" | Near-certain claim | "Cipher type is unknown, Beaufort is consistent" | No proof of Beaufort |
| "Stego layer is now largely understood" | Confident claim | "We observe a statistically unusual palette restriction" | Model-dependent, no independent confirmation |
| Cardan grille scrambled-CT model | "USER GROUND TRUTH" | "[HYPOTHESIS] — unproven" | No evidence for this model |
| K5 position-dependence inference | Stated as likely | Labeled as unproven hypothesis | Based on unconfirmed K5 claims |
| Hill cipher "Through our lens" | Explanatory speculation | Physical observation, no productive attacks | Hill is algebraically eliminated |
| YAR superscript speculation | "Through our lens" interpretation | "Speculation (not evidence)" | No testable predictions survived |

## Claims Retracted

| Claim | Reason |
|-------|--------|
| "Espionage Signature" (KGB in palette letters) | Pure numerology — any 7 letters can be pattern-matched to thematic words. Replaced with explicit "Not Evidence" label. |
| "Quadruple-24 Coincidence" as evidence | Small-integer coincidence, not evidence. Reframed as community discussion point. |
| Proof PDF as "formal proof" | Contains known error (Definition 4), predates model-dependence finding. Relabeled as "draft, under revision." |

---

## What Now Survives

After this review, the following claims survive as defensible:

### Verified and durable (suitable for public factual language):
- K4 ciphertext, cribs, Bean constraints (all [PUBLIC FACT] or [DERIVED FACT])
- Pure transposition impossibility (letter frequency mismatch — algebraic proof)
- Periodic substitution impossibility at all periods under direct correspondence (Bean proof)
- Autokey structural impossibility (crib feedback contradiction)
- All Tier 1 eliminations in elimination_tiers.md (conditions stated per entry)

### Reproducible but model-conditional (must be labeled):
- Null palette restriction: 7 of 26 letters at 17 candidate positions (p ≈ 1/16,000 under KA-autokey model)
- Shuffled-CT validation: 0/500 (p < 0.002) — confirms palette depends on K4 letter ordering
- Beaufort-specific keystream enrichment: 13/24 palette hits (Beaufort only)
- Stehle anomaly: constant-difference Δ4=5 at positions 55-63 (p ≈ 1/642 after Bonferroni)

### Exploratory only (retained for transparency, not evidence):
- KRYPTOS × SEVEN table (zero predictive power)
- 14-column grid asymmetry (model-conditional, post-hoc)
- 14×5 classification table (no cross-validation performed)
- Thematic associations in palette letters

### Status of the null model itself:
The null-insertion hypothesis remains a working model. It is supported by the palette restriction
(the strongest quantitative observation) but the null positions are model-dependent. The hypothesis
has not been independently confirmed by a model-free method. It is plausible but unproven.

---

*Produced 2026-03-31 as part of the evidence-hardening pass.*
