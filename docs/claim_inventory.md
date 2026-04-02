# Claim Inventory — Audit Remediation (2026-04-01)

This file inventories every significant claim found across public and internal surfaces,
assessed against the Team of Rivals statistical audit. Each entry records whether the
claim is too strong, acceptable, or requires correction.

**Legend:**
- **OK** — Claim is defensible as written
- **SOFTEN** — Claim overstates; needs qualifying language
- **RELABEL** — Claim uses wrong category (e.g., "proof" for an observation)
- **QUALIFY** — Claim is correct but missing scope conditions
- **REMOVE** — Claim should be deleted
- **REWRITE** — Claim needs substantial rewording

---

## P0 — Critical (public-facing overclaims)

| # | Claim (paraphrase) | File | Current Class | Assessment | Action | Public? |
|---|---|---|---|---|---|---|
| 1 | BCL palette keystream is "model-independent" | `memory/bcl_palette_keystream.md` title, §3, §9; `MEMORY.md:82`; `scripts/_infra/session_briefing.py:274`; `docs/proofs/k4_stego_findings.tex:81,299` | DERIVED FACT | **TOO STRONG** — Beaufort-specific; only the arithmetic identity CT+PT is model-free, not the interpretation as "keystream" | REWRITE → "ciphertext-intrinsic under Beaufort A=0 convention" | Yes (via reports/site) |
| 2 | "Running key is the ONLY structured model surviving Bean constraints" (unqualified) | `README.md:122`; `docs/elimination_tiers.md:27`; `docs/research_questions.md:53`; `docs/crypto_field_manual/10_people_orgs_timeline.md:193,247`; `docs/crypto_field_manual/30_k4_mapping_matrix.md:69` | DERIVED FACT | **MISSING CONDITION** — True only under additive-key assumption; does not apply if cipher is non-additive | QUALIFY → add "under additive-key assumptions" | Yes |
| 3 | "ELIMINATED" used without tier/scope throughout MEMORY.md and reports | `MEMORY.md:49`; `reports/final_synthesis.md` passim; `docs/elimination_tiers.md` passim | Mixed | **TOO LOOSE** — Readers cannot distinguish Tier 1 proof from Tier 2 search from Tier 3 statistical | QUALIFY → add tier reference or scope phrase | Mixed |
| 4 | Mod-35 rule: "35/35 PERFECT" / "Classifies All 17" | `memory/palette_mod35_rule.md:13,16`; `scripts/campaigns/e_statistical_validation_v1.py:500` | INTERNAL RESULT | **MISLEADING** — Post-hoc in-sample fit with no holdout validation; LOO-CV shows 47% accuracy | RELABEL → "in-sample post-hoc fit" | Partially |
| 5 | Palette p-values inconsistent: 3.0e-5 vs 7.78e-5 vs ~2.4e-5 | `memory/palette_deep_investigation.md:5` | INTERNAL RESULT | **CONFUSING** — Three different values from different null models, not reconciled | REWRITE → single canonical section with all three labeled | Internal |

## P1 — Important (internal rigor)

| # | Claim | File | Assessment | Action | Public? |
|---|---|---|---|---|---|
| 6 | "Strongest single anomaly" for BCL 7/8 | `memory/palette_deep_investigation.md:110`; `memory/bcl_palette_keystream.md:110` | **TOO STRONG** — No search-breadth correction applied | SOFTEN → "lowest uncorrected p-value among tested anomalies" | Internal |
| 7 | Fisher combined p ≈ 3.5e-7 presented without independence caveat | `memory/palette_mod35_rule.md:119` | **MISSING CAVEAT** — Component tests share palette definition | QUALIFY → note non-independence | Internal |
| 8 | Tier 1 "~99.9%" without additive-model condition in header | `docs/elimination_tiers.md:61` | **MISSING CONDITION** — Bean proofs require additive key model | QUALIFY → add condition to tier header | Mixed |
| 9 | "ZERO positive findings survive across all 55 experiments" | `reports/frac_statistical_meta_analysis.md:6` | **SCOPE MISSING** — True within tested families/parameters, not absolute | QUALIFY → "within tested cipher families and parameter ranges" | Internal |
| 10 | Score thresholds (NOISE=6, STORE=10, etc.) lack calibration | `src/kryptos/kernel/constants.py:92-95` | **UNDOCUMENTED** — Thresholds are practical heuristics, not statistically calibrated | Document as heuristic; add calibration roadmap | Internal |

## P2 — Moderate (accuracy/consistency)

| # | Claim | File | Assessment | Action |
|---|---|---|---|---|
| 11 | "All single-layer classical ciphers have been eliminated" (FAQ) | `ops/site_builder/templates/faq.html:25` | Approximately correct but imprecise — should say "under direct correspondence" | QUALIFY |
| 12 | Bean constraints methodology page lacks additive-model caveat | `ops/site_builder/templates/methodology.html:98-111` | Missing condition statement | QUALIFY |
| 13 | "no repeating key of any length" proven impossible (methodology) | `ops/site_builder/templates/methodology.html:108` | Correct but should specify "under direct positional correspondence" | QUALIFY |
| 14 | Home page credibility bar: "Everything documented" | `ops/site_builder/templates/home.html:38` | Acceptable but slightly strong — anomaly documentation has gaps | OK (borderline) |
| 15 | Site findings page labels palette as "RETIRED" | `ops/site_builder/templates/findings.html:112` | Well-handled — already shows controls failed | OK |
| 16 | KRYPTOS×SEVEN labeled "No Predictive Power" on site | `ops/site_builder/templates/findings.html:392-416` | Well-handled — already labeled exploratory | OK |

---

## Summary

- **P0 items requiring immediate fix:** 5 (BCL language, Bean conditionality, ELIMINATED scoping, mod-35 relabeling, p-value reconciliation)
- **P1 items requiring fix:** 5 (strongest anomaly, Fisher independence, Tier 1 header, FRAC headline, threshold documentation)
- **P2 items requiring qualification:** 4
- **Items already acceptable:** 3 (site findings page is well-disciplined)

The public site (kryptosbot.com) is generally MORE careful than internal docs — the findings page
already retired the palette, labeled KRYPTOS×SEVEN as non-evidence, and uses model-conditional
language. The README is reasonably disciplined. The main risk vectors are:
1. Internal research docs (memory/, reports/) that use stronger language than the site
2. "model-independent" appearing in multiple places
3. "ELIMINATED" without scope/tier throughout
4. Bean conditionality missing from public methodology and elimination tier headers
