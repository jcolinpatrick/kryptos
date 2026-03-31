# MEMORY.md — K4 Decision-Support Index

Dashboard for agents working on K4. For repo setup and commands, see `CLAUDE.md`.
For full history and experiment detail, see topic files listed in the reference index below.

---

## Project State (2026-03-30)

- 993 scripts pushed to GitHub, 386 eliminations on internal.com, 671B+ configs scored
- No credible decrypt path established
- All positive findings are descriptive anomalies, not actionable decrypt levers
- Computational attack surface is exhausted; remaining paths require external evidence or untested source texts
- **Null mask positions proven model-dependent** (Jaccard 0.161 across 5 cipher models)
- **Shuffled-CT test confirms palette is K4-specific** (0/500 shuffled CTs hit ≤7 distinct, p<0.002) — but model-conditional, not proven intrinsic
- internal.com: submission feedback loop live (token-based status page)
- GitHub: 2,945 clones (113 unique) in 14 days ending 2026-03-30; daily polling set up

---

## Hard Blockers

1. **Null-mask provenance** *(model-dependent, K4-specific)* — Shuffled-CT test (0/500, p<0.002) confirms palette restriction is real for K4's letter order, not an SA artifact. But positions shift with cipher model (Jaccard 0.161). Palette is "anomalous under KA-autokey" not "intrinsic to K4."
2. **Short-text underdetermination** — 97 chars; surface statistics are weak and frequently deceptive
3. **Multi-layer ambiguity** — Tier 2 single-layer eliminations do NOT eliminate those families as one layer of a multi-layer construction
4. **External-information ceiling** — Some avenues require physical/chart/archive evidence

---

## What Is Eliminated (High Confidence)

All periodic polyalphabetic (all periods 1-26, all tested mixed tableaux) | Autokey (all variants, structural proof) | Gronsfeld | Porta | Hill | Fractionation (bifid, trifid, ADFGVX, four-square) | Gromark/Vimark (8.74B configs) | All tested running-key sources via bijection (47B checks, 10 alphabet modes, 11 texts) | English running-key + columnar on 3,432 palette-consistent extracts (61M configs) | VIC family (52M+ configs) | RS44 stencil-mask (905.6M configs) | Wheatstone clock (327M) | ITA-2 XOR | Interrupted-key Vigenere (14.7M) | Baudot mod-31 | Wilson prime mask | Sawtooth mask | Ubchi null insertion | Soviet three-step | Sanborn matrix | CKM credential (173M+) | NDYAHR (all 5 variants) | Cold War keywords | MCMC quadgram on CT73 | K0 Morse running key | Progressive running key | Palette-derived key material | 72+1 delimiter | Nomenclator (algebraically = running key)

Full evidence: `elimination_ledger.md` in session memory.

---

## DO NOT TEST (without a materially new assumption)

Autokey variants | DEFECTOR/PALIMPSEST inherited-ceiling | K2 number-word keys | YES WONDERFUL THINGS as PT[0:18] | Positional lookup-table keying | CIA cryptonym digraphs | Leetspeak/palette-as-number | K2 coordinate keys | 72+1 delimiter | NDYAHR reinterpretations | INCLINARE stacking | Cold War keyword families | K1-K3 PT as literal keys | Mailing-list hypotheses already tested | CKM mod-26 constructions | OBKOGBOWWKWIWGZIG as key | CT80 single-layer keywords | RS44 grid-mask | Full VIC pipeline | Wheatstone | ITA-2/Baudot/Wilson/sawtooth | Interrupted-key Vigenere | Ubchi/Soviet three-step/Sanborn matrix

---

## What Remains Open

1. **Running-key from UNTESTED sources** — model survives structurally (13 mono DOF). Priority: Kahn's "Codebreakers", Schliemann Troy, pre-1990 Egyptological texts.
2. **Bespoke chart-based system** — archive's "Code Breaker" overlay and "actual coding charts" suggest non-standard mechanisms. Primary live branch after tableau arithmetic eliminated.
3. **Multi-layer hand-executable systems** — untested peel orders, non-obvious layer combinations.
4. **External evidence**: K5 ciphertext, recovered coding charts, circled letters on IMG_1223-1235, Sanborn's coding system (in private hands).
5. **ABSCISSA as procedural/physical chart clue** (not standard arithmetic — that's eliminated).

---

## Immediate Next Actions

1. Expand source-text corpus — re-run bijection on new sources (~25 min/mode)
2. Word-boundary discriminator on mono+trans+running-key model
3. Investigate bespoke chart mechanisms from archive photos
4. Treat early statistics as advisory only; test both peel orders for two-layer hypotheses

---

## Confirmed Anomalies (Real but Unexploitable)

- **Null palette {B,G,I,K,O,W,Z}** — 7 letters at 17 positions (p~3e-5 nominal). **Model-conditional**: positions shift with cipher model (Jaccard 0.161). Shuffled-CT: 0/500 hit ≤7 distinct (p<0.002), confirming K4-specificity but NOT model-independence. Grade C.
- **KA mod 5 structure** — all 7 palette letters have KA index in {0,3} mod 5 (p=0.0005)
- **BCL Beaufort keystream 7/8 palette** (p=0.0006) — unique to Beaufort A=0
- **14-column grid asymmetry** — filler density 55% left vs 17% right (p~7e-5)
- **Null insertion non-random** — IC=0.1103, 2.87x random (p=0.0008)

All grade C or below (descriptive, post-hoc, mask-dependent). See `statistical_audit_20260326.md`.

---

## Critical Pitfalls

- Positions are 0-indexed (cribs at 21-33, 63-73)
- Import constants; never hardcode CT, cribs, or null positions
- KA ordering is non-standard (KRYPTOSABCDEFGHIJLMNQUVWXZ)
- Vigenere: K=(CT-PT)%26 | Beaufort: K=(CT+PT)%26 | Variant Beaufort: K=(PT-CT)%26
- High scores at large periods are always false positives
- A promising score is not evidence until independently reproduced

---

## Archives of American Art — Key Findings (2026-03-27)

ABSCISSA confirmed as Sanborn research term | Beaufort cipher in handwritten list | "3 words most" | "He lied" (K2 coordinate change) | "I wrote the Plain Text to be enigmatic" | Physical overlay "Code Breaker" sketch | ATBASH on same page as ABSCISSA | "4, 8, 10, 26 = Col" | Antipodes completely absent from archive

Detail: `archive_aaa_findings.md` in session memory.

---

## Campaign & Audit Summaries

- **TICOM/Novel (2026-03-28):** 14 scripts, 1.3B configs, ~75 min. RS44, VIC, Wheatstone, ITA-2, interrupted-key, Wilson, sawtooth, Baudot, Ubchi, Soviet three-step, Sanborn matrix: ALL NOISE.
- **Site audit (2026-03-28):** p-value inconsistency fixed; categorizer 350→25 uncategorized (93% reduction); title humanizer added.
- **Extra L (2026-03-29):** "Extra L at end of line" = tableau anomaly or transposition padding. 97+1=98=2×7×7. All tested hypotheses NOISE. UNTESTED: CT98 at width 7/14 with keyword column orders.

---

## Reference Index

### Session Memory (`.claude/projects/.../memory/`)

**Elimination & Audit**
- [Elimination Ledger](elimination_ledger.md) — Master record, 50+ experiments
- [Statistical Audit](statistical_audit_20260326.md) — Evidence grading (A-E)
- [Null Mask Validation](null_mask_validation_20260326.md) — IC non-discriminative, palette = provenance
- [Null Mask Model Dependence](null_mask_model_dependence.md) — SA positions shift with cipher model, shuffled-CT confirms K4-specificity

**Campaign Reports**
- [Session 2026-03-28](session_20260328_archive_campaigns.md) — TICOM/novel + archive forensics
- [Session 2026-03-16](session_20260316_heavyweight.md) — Cold War keywords, DEFECTOR+PALIMPSEST
- [Campaign v3 Design](campaign_v3_design.md) — Multi-agent architecture

**Cipher Family Deep Dives**
- [VIC Family](vic_family_exhaustive.md) | [NDYAHR](ndyahr_exhaustive.md) | [Grille/Cardan](grille_cardan_results.md) | [Mbox Mining](mbox_mining_results.md)

**Stego / Null Layer**
- [Stego Null Mask Tests](stego_null_mask_tests.md) | [Telegraph PT Model](telegraph_plaintext_model.md)

**Primary Sources**
- [Archive AAA](archive_aaa_findings.md) | [Antipodes Absence](antipodes_archive_absence.md) | [Dan Brown](dan_brown_lost_symbol_analysis.md) | [Sanborn Manuscript](sanborn_manuscript_revelations.md) | [Coding Chart Sealed](coding_chart_sealed.md)

**User & Feedback**
- [User Background](user_background.md) | [Multi-layer Blindspot](feedback_multilayer_cipher_blindspot.md) | [Statistical Posture](feedback_statistical_audit_posture.md) | [Site Language](feedback_site_language.md) | [Campaign v3](feedback_campaign_v3_no_utility.md) | [Merge to Main](feedback_merge_to_main.md) | [Tablet Responsive](feedback_tablet_responsive.md)

**External References**
- [KUBARK PDF](kubark_pdf_reference.md) | [Smithsonian Visit](smithsonian_visit.md) | [AAA Archive Visit](project_aaa_archive_visit.md) | [Polybius Paper](project_polybius_paper.md) | [Classify Endpoint](project_classify_endpoint.md)

**Session 2026-03-30**
- [Null Mask Model Dependence](null_mask_model_dependence.md) | [NYT vs Null Mask](nyt_article_null_mask_impact.md) | [Reddit Audit](reddit_statistical_audit.md) | [Proof Doc Audit](proof_document_audit.md) | [Submission Feedback](submission_feedback_loop.md) | [GitHub Traffic](github_traffic_polling.md)

### Repo Memory (`memory/`)
- `keystream_forensics_v2.md` | `palette_deep_investigation.md` | `bcl_palette_keystream.md` | `palette_mod35_rule.md` | `palette_null_separator.md` | `polybius_row_selection.md` | `width10_17_deep_investigation.md` | `width21_bigram_73char.md` | `ticom_archive_research.md` | `bruteforce_7remaining.md`

Last updated: 2026-03-30
