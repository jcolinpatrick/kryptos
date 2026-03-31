# MEMORY.md — K4 Strategic Context

For elimination landscape, anomalies, DO NOT TEST, and results verdicts:
**`PYTHONPATH=src python3 scripts/_infra/session_briefing.py`** (CLAUDE.md step 2)

This file covers volatile strategic state that the briefing script doesn't generate from data.

---

## Project State (2026-03-30)

- 993 scripts, 386 eliminations on kryptosbot.com, 671B+ configs scored
- No credible decrypt path. All positive findings are descriptive anomalies.
- Computational attack surface is exhausted for classical single-layer ciphers
- kryptosbot.com: submission feedback loop live (token-based status page)
- GitHub: 2,945 clones (113 unique) in 14 days ending 2026-03-30

---

## Hard Blockers

1. **Null-mask provenance** — Palette {B,G,I,K,O,W,Z} is K4-specific (0/40K SA masks have ≤7 distinct), NOT an optimizer artifact. But positions shift with cipher model (Jaccard 0.161). Palette is model-conditional, not proven intrinsic.
2. **Short-text underdetermination** — 97 chars; surface statistics are weak and frequently deceptive
3. **Multi-layer ambiguity** — Single-layer eliminations do NOT eliminate those families as one layer of a multi-layer construction
4. **External-information ceiling** — Some avenues require physical/chart/archive evidence

---

## What Remains Open

1. **Running-key from UNTESTED sources** — model survives structurally (13 mono DOF). Priority: Kahn's "Codebreakers", Schliemann Troy, pre-1990 Egyptological texts.
2. **Bespoke chart-based system** — archive's "Code Breaker" overlay and "actual coding charts" suggest non-standard mechanisms.
3. **Multi-layer hand-executable systems** — Mono+Trans+Running key is UNDERDETERMINED (E-FRAC-54).
4. **Model-free null mask search** — score CT73 by intermediate statistics, not cipher-model cribs.
5. **External evidence**: K5 ciphertext, recovered coding charts, circled letters on IMG_1223-1235.

---

## Archives of American Art — Key Findings (2026-03-27)

ABSCISSA confirmed as Sanborn research term | Beaufort cipher in handwritten list | "3 words most" | "He lied" (K2 coordinate change) | "I wrote the Plain Text to be enigmatic" | Physical overlay "Code Breaker" sketch | ATBASH on same page as ABSCISSA | "4, 8, 10, 26 = Col" | Antipodes completely absent from archive

Detail: `archive_aaa_findings.md` in session memory.

---

## Campaign & Audit Summaries

- **TICOM/Novel (2026-03-28):** 14 scripts, 1.3B configs, ~75 min. RS44, VIC, Wheatstone, ITA-2, interrupted-key, Wilson, sawtooth, Baudot, Ubchi, Soviet three-step, Sanborn matrix: ALL NOISE.
- **Null mask diversity (2026-03-30):** SA does NOT drive toward low diversity (r=+0.05). 0/40K masks at any score tier have ≤7 distinct. Palette is genuinely anomalous.
- **Extra L (2026-03-29):** 97+1=98=2x7x7. All tested hypotheses NOISE.

---

## Critical Pitfalls

- Positions are 0-indexed (cribs at 21-33, 63-73)
- Import constants; never hardcode CT, cribs, or null positions
- KA ordering is non-standard (KRYPTOSABCDEFGHIJLMNQUVWXZ)
- Beaufort A=0 is the confirmed default
- High scores at large periods are always false positives
- Null positions are MODEL-DEPENDENT — always state which model

---

## Reference Index

### Session Memory (`.claude/projects/.../memory/`)

- [Null Mask Model Dependence](null_mask_model_dependence.md) — SA positions shift with cipher model
- [NYT vs Null Mask](nyt_article_null_mask_impact.md) — Article does not invalidate null hypothesis
- [Reddit Audit](reddit_statistical_audit.md) — Multiple testing survives, wrong null model 2x weaker
- [Proof Doc Audit](proof_document_audit.md) — Definition 4 wrong, K-sum error, core arithmetic OK
- [Submission Feedback](submission_feedback_loop.md) — Token-based status tracking implemented
- [GitHub Traffic](github_traffic_polling.md) — Daily cron in logs/github_traffic/
- [Mbox Mining](mbox_mining_results.md) — 18,766 K4-relevant posts from kryptos.groups.io

### Repo Memory (`memory/`)

- `keystream_forensics_v2.md` — Corrected keystream, DEFECTOR autokey structurally impossible
- `palette_deep_investigation.md` — 18-test investigation, mod-5, Beaufort key=N
- `bcl_palette_keystream.md` — BCL 7/8 palette enrichment (model-independent)
- `palette_mod35_rule.md` — (pos%7,pos%5) table classifies all 17 consensus nulls
- `polybius_row_selection.md` — KRYPTOS×SEVEN dual-keyword model
- `width10_17_deep_investigation.md` — Cipher-layer bigrams, col7 artifacts
- `width21_bigram_73char.md` — Stego-layer artifact, disappears after null extraction
- `ticom_archive_research.md` — RS44, VIC, Ubchi parallels to K4

Last updated: 2026-03-30
