# MEMORY.md — K4 Strategic Context

For elimination landscape, anomalies, DO NOT TEST, and results verdicts:
**`PYTHONPATH=src python3 scripts/_infra/session_briefing.py`** (CLAUDE.md step 2)

This file covers volatile strategic state that the briefing script doesn't generate from data.

---

## Project State (2026-04-06)

- 993+ scripts, 386 eliminations on internal.com, 671B+ configs scored
- No credible decrypt path. All positive findings are descriptive anomalies.
- Single-layer AND two-layer classical cipher space now systematically tested
- Composition framework operational: 105K+ branches tested (v1+v2+v3), max 6/24 = noise
- v3 adds 6 stateful/architecture-specific families: band offset, polarity switch, progressive key, state alphabet, band polarity, compass offset — all noise
- internal.com: submission feedback loop live, community cipher challenge deployed
- Archive page updated: 7 new images (Copper "Veil" plaintext, SECRET PAST gallery list, concept sketches, Sanborn CIA letter, press clippings)

---

## Hard Blockers

1. ~~**Null-mask provenance**~~ **RETIRED (April 2026)** — Score-conditioned null experiment showed SA produces 11 distinct letters on K4, indistinguishable from shuffled controls (p=0.30). The "7 letters at 17 positions" was a post-hoc selection artifact. See `docs/a1_score_conditioned_null_report.md`. All palette-dependent claims (BCL enrichment, KA mod-5, AP enrichment, mod-35 table) are also retired.
2. **Short-text underdetermination** — 97 chars; surface statistics are weak and frequently deceptive
3. **Multi-layer ambiguity** — Single-layer eliminations do NOT eliminate those families as one layer of a multi-layer construction
4. **External-information ceiling** — Some avenues require physical/chart/archive evidence

---

## Research Phase — FINAL CHECKLIST

Per `docs/exhaustion_audit_2026_04_08.md` (internal review board, 2026-04-08), the project is in its final honest search window. Running-key has been **demoted from #1 open family to residual admissible family** — finite checklist, not a leading hypothesis. Thresholds pre-registered in `docs/preregistered_thresholds_2026_04_08.md`.

### Bin C — Testable now (execute, then stop)

1. **C7 — Admissibility backlog cleanup** — Review 16 `ASSUMPTION_UNMET` running-key scripts; declare source, add license, or archive. ~1 engineering day.
2. **C1 — Carter Vol 1 + columnar w6/8/9 × 3 variants, admissibility-gated.** ~150K configs. Pre-registered escalation criterion.
3. **C2 — Kahn Codebreakers + columnar w6/8/9 × 3 variants, admissibility-gated.** ~150K configs.
4. **C6 — Non-columnar 3-layer enumeration** (route / Myszkowski / rail-fence / block as middle layer) via extended composition framework. Only bin-C item with a real architectural argument.
5. **C3/C4 — Bifid/four-square as composition outer** — DEFERRED; only run if C1/C2/C6 produce an ESCALATED candidate that justifies continued registry expansion.
6. **C5/C8 — Homophonic composition outer / stateful seed expansion** — Deferred; run only if earlier bin-C campaigns escalate.

**Stop condition:** all of C7/C1/C2/C6 complete AND no ESCALATED candidate → publish `exhaustion_certificate_2026_04_08.md` and transition to waiting-list phase.

### Bin D — Weakly testable (engineering, not compute)

- Mono+Trans+Running-key — detection-underdetermined (E-FRAC-54). Needs a new detection apparatus, not more sweeps.
- Running-key from unknown non-English text — E-FRAC-51 bound is English-specific. Needs pre-declared language + new CorpusLicense.
- Berlin Clock / Weltzeituhr time-dependent permutations — needs archive-derived clock-state argument.
- Pre-ENE (0-20) as separate sub-cipher — no crib/constraint available.
- Archive-term operationalization (ABSCISSA, ATBASH, "4, 8, 10, 26 = Col") — needs a parametric mapping from term to cipher family.

### Bin E — Untestable under current clues (waiting list)

- Bespoke chart-based cipher procedures — needs public chart reproduction OR a `CipherProcedureLicense` schema.
- Model-free null mask search — no defined statistic; palette version retired (post-hoc artifact).
- K5 ciphertext — not published.
- Circled letters IMG_1223-1235 — needs forensic extraction of archive photos.
- Photogrammetric sculpture data — needs primary-source field measurement.
- Sanborn's private coding system — not public.

**These are prerequisites for being able to test anything new, not testable hypotheses.**

---

## Archives of American Art — Key Findings (2026-03-27)

ABSCISSA confirmed as Sanborn research term | Beaufort cipher in handwritten list | "3 words most" | "He lied" (K2 coordinate change) | "I wrote the Plain Text to be enigmatic" | Physical overlay "Code Breaker" sketch | ATBASH on same page as ABSCISSA | "4, 8, 10, 26 = Col" | Antipodes completely absent from archive

Detail: `archive_aaa_findings.md` in session memory.

---

## Campaign & Audit Summaries

- **Composition v1+v2+v3 (2026-04-06):** 105K+ compositions across 37 campaigns. v1: additive+transposition. v2: Vigenere/Beaufort inner, 80-char CT. v3: 6 stateful/architecture families (band offset, polarity switch, progressive key, state alphabet, band polarity, compass offset). Max 6/24 = noise. Bean inequality pruning confirms periodic single-layer elimination. Reports: `reports/composition_campaign_v{1,2,3}.md`.
- **TICOM/Novel (2026-03-28):** 14 scripts, 1.3B configs, ~75 min. RS44, VIC, Wheatstone, ITA-2, interrupted-key, Wilson, sawtooth, Baudot, Ubchi, Soviet three-step, Sanborn matrix: all noise (Level B).
- **Null mask diversity (→ RETIRED 2026-04-01):** Original positional null p=2.4e-5 invalidated by score-conditioned null. Post-hoc selection artifact.
- **Extra L (2026-03-29):** 97+1=98=2x7x7. All noise (Level B).

---

## Critical Pitfalls

- Positions are 0-indexed (cribs at 21-33, 63-73)
- Import constants; never hardcode CT, cribs, or null positions
- KA ordering is non-standard (KRYPTOSABCDEFGHIJLMNQUVWXZ)
- Beaufort A=0 is the confirmed default
- High scores at large periods are always false positives
- Null positions are MODEL-DEPENDENT — always state which model
- **Palette {B,G,I,K,O,W,Z} is RETIRED** — post-hoc selection artifact (April 2026 audit)

---

## Reference Index

### Session Memory (`.claude/projects/.../memory/`)

- [Composition Campaigns](composition_campaigns_v1v2.md) — 105K+ compositions (v1+v2+v3), max 6/24 = noise
- [Null Mask Model Dependence](null_mask_model_dependence.md) — SA positions shift with cipher model
- [NYT vs Null Mask](nyt_article_null_mask_impact.md) — Article does not invalidate null hypothesis
- [Reddit Audit](reddit_statistical_audit.md) — Multiple testing survives, wrong null model 2x weaker
- [Proof Doc Audit](proof_document_audit.md) — Definition 4 wrong, K-sum error, core arithmetic OK
- [Submission Feedback](submission_feedback_loop.md) — Token-based status tracking implemented
- [GitHub Traffic](github_traffic_polling.md) — Daily cron in logs/github_traffic/
- [Mbox Mining](mbox_mining_results.md) — 18,766 K4-relevant posts from kryptos.groups.io
- [Community Challenge](challenge_page.md) — Cipher challenge: Quagmire III + null insertion, ntfy on solve

### Repo Memory (`memory/`)

- `keystream_forensics_v2.md` — Corrected keystream, DEFECTOR autokey structurally impossible
- `palette_deep_investigation.md` — 18-test investigation, mod-5, Beaufort key=N
- `bcl_palette_keystream.md` — BCL 7/8 palette enrichment (ciphertext-intrinsic under Beaufort A=0; Level C anomaly)
- `palette_mod35_rule.md` — (pos%7,pos%5) table classifies all 17 consensus nulls
- `polybius_row_selection.md` — KRYPTOS×SEVEN dual-keyword model
- `width10_17_deep_investigation.md` — Cipher-layer bigrams, col7 artifacts
- `width21_bigram_73char.md` — Stego-layer artifact, disappears after null extraction
- `ticom_archive_research.md` — RS44, VIC, Ubchi parallels to K4

Last updated: 2026-04-08 (exhaustion audit; running-key demoted to residual checklist)
