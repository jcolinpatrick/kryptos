# Public Surface Map — Audit Remediation (2026-04-01)

Every public-facing surface where a skeptical reader could find claims.
Ordered by visibility (most-seen first).

---

## Tier 1: High-visibility (landing pages, README)

| Surface | File/URL | Audit Risk | Status |
|---------|----------|------------|--------|
| GitHub README | `README.md` | Bean conditionality missing from hypothesis #4; "ELIMINATED" in §"What's been eliminated" is tier-unqualified but has good caveat at bottom | Needs minor qualification |
| Home page (kryptosbot.com) | `ops/site_builder/templates/home.html` | Generally safe; "ruled out" in hero is acceptable; findings preview cards are cautious; "not a claim" disclaimer is strong | OK |
| Findings page | `ops/site_builder/templates/findings.html` | **Best-disciplined surface in the project.** Palette retired, KRYPTOS×SEVEN labeled non-evidence, model-conditional language throughout, known-issues caveat on PDF | OK |
| FAQ | `ops/site_builder/templates/faq.html` | "All single-layer classical ciphers have been eliminated" needs "under direct correspondence" qualifier; otherwise good | Minor fix |

## Tier 2: Medium-visibility (methodology, browse, about)

| Surface | File/URL | Audit Risk | Status |
|---------|----------|------------|--------|
| Methodology page | `ops/site_builder/templates/methodology.html` | Bean section lacks additive-model caveat; "no repeating key" needs direct-correspondence qualifier; palette retirement well-documented | Needs fixes |
| Elimination detail pages | `ops/site_builder/templates/elimination.html` | Template shows confidence tier, scope limitations, assumptions — well-structured. "This approach is ruled out" at line 32 is slightly strong for Tier 3 results | Minor fix |
| About Kryptos page | `ops/site_builder/templates/about_kryptos.html` | Factual, respectful, no overclaims | OK |
| Submit page | `ops/site_builder/templates/submit.html` | Neutral and functional | OK |
| About Me page | `ops/site_builder/templates/about_me.html` | Not reviewed in detail | Check |

## Tier 3: Internal docs reachable from GitHub

| Surface | File/URL | Audit Risk | Status |
|---------|----------|------------|--------|
| MEMORY.md | `MEMORY.md` | "model-independent" at line 82; "ELIMINATED" without tier in campaign summaries | Needs fixes |
| CLAUDE.md | `CLAUDE.md` | Internal-facing; generally technical; Bean caveat present in gotchas section | OK |
| Elimination tiers doc | `docs/elimination_tiers.md` | Tier 1 header lacks additive-model condition; "~99.9%" should be qualified | Needs fix |
| Ground truth doc | `docs/kryptos_ground_truth.md` | Well-structured with truth taxonomy | OK |
| Research questions | `docs/research_questions.md` | "ONLY structured model" needs Bean condition | Needs fix |
| Final synthesis report | `reports/final_synthesis.md` | "0 genuine signals" is scope-correct but should say "within tested families" | Minor fix |
| FRAC meta-analysis | `reports/frac_statistical_meta_analysis.md` | "ZERO positive findings survive" needs scope qualifier | Minor fix |
| Anomaly registry | `docs/anomaly_registry.md` | Not reviewed | Check |

## Tier 4: Research notes (memory/)

| Surface | File/URL | Audit Risk | Status |
|---------|----------|------------|--------|
| BCL palette keystream | `memory/retired/bcl_palette_keystream.md` (moved 2026-04-09; stub at `memory/bcl_palette_keystream.md`) | RETIRED 2026-04-01 (score-conditioned null). Formerly "MODEL-INDEPENDENT" in title and §3. | **RETIRED** — no longer a live surface |
| Palette deep investigation | `memory/retired/palette_deep_investigation.md` (moved 2026-04-09; stub at `memory/palette_deep_investigation.md`) | RETIRED 2026-04-01 (post-hoc selection artifact). | **RETIRED** |
| Palette mod35 rule | `memory/retired/palette_mod35_rule.md` (moved 2026-04-09; stub at `memory/palette_mod35_rule.md`) | RETIRED 2026-04-01 (in-sample post-hoc fit; LOO-CV ~47%). | **RETIRED** |
| Palette null separator | `memory/retired/palette_null_separator.md` (moved 2026-04-09) | RETIRED 2026-04-01 (inherits retired palette). | **RETIRED** |
| Polybius row-selection | `memory/retired/polybius_row_selection.md` (moved 2026-04-09) | RETIRED 2026-04-01 (depends on retired palette). | **RETIRED** |
| Keystream forensics v2 | `memory/keystream_forensics_v2.md` | Documents v1 bug correction — actually good epistemic practice | OK |

**Note (2026-04-09):** this surface-map document is itself a 2026-04-01 audit
artifact. The tier-4 rows above have been updated in place to reflect the
2026-04-09 quarantine of the palette family under `memory/retired/`. The rest
of the document is preserved for traceability. See `memory/retired/README.md`
and `docs/a1_score_conditioned_null_report.md` for the retirement record.

## Tier 5: LaTeX/PDF documents

| Surface | File/URL | Audit Risk | Status |
|---------|----------|------------|--------|
| Statistical write-up (PDF) | `docs/proofs/k4_stego_findings.tex` | "model-independent" at lines 81, 299; site already warns "known issues, working draft" | Needs fix but lower priority (draft status noted) |

---

## Cross-Surface Consistency Risks

| Risk | Surfaces Involved | Severity |
|------|------------------|----------|
| "model-independent" appears in memory/, scripts/, docs/proofs/ but site findings page does NOT use this language | Internal vs public | Medium — hostile reader comparing GitHub repo to site would find inconsistency |
| README says "only structured...model" without additive-key condition; site methodology page says same | README vs methodology | Medium |
| Internal "ELIMINATED" is tier-unqualified; site elimination pages show tiers properly | Internal vs site | Low — site is better |
| Palette p-values differ between memory/ docs | Internal only | Low for public risk |
