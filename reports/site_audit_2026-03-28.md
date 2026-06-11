# kryptosbot.com — Site Accuracy Audit

**Date:** 2026-03-28
**Scope:** All pages on kryptosbot.com checked against codebase ground truth (`kryptos.kernel.constants`, `exhaustion_log.json`, `MEMORY.md`, elimination ledger, primary sources).
**Pages audited:** Home, Methodology, Findings, FAQ, About Kryptos, About Me, Research Questions, Browse (all 7 categories), Recent, Archive, Submit, Report Error, Terms, plus spot-checks on elimination detail pages.

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **HIGH** (factual error visible to public) | 4 | Wrong numbers, contradictory stats, misleading score |
| **MEDIUM** (inconsistency or stale data) | 7 | Cross-page contradictions, outdated claims, missing context |
| **LOW** (cosmetic or minor) | 6 | Naming, categorization, duplicate entries |
| **CORRECT** (verified accurate) | 20+ | Core claims verified against ground truth |

---

## HIGH Severity Issues

### H1. Null Palette Odds — Contradictory Numbers Across Pages

| Page | Claimed Odds |
|------|-------------|
| **Homepage** | "about 1 in 33,000" |
| **Methodology** | "roughly 1 in 16,000" |
| **Findings** | "1 in 16,000" |
| **MEMORY.md** | "p~3e-5" = 1 in ~33,333 |

**Problem:** The same statistic is quoted as two different numbers on the same website. `p=3e-5` (1 in 33,000) and `p=6.25e-5` (1 in 16,000) are substantially different. These likely come from different tests (permutation test vs. combinatorial calculation) but the distinction is not explained.

**Fix:** Pick one authoritative number with its derivation method and use it consistently. If both tests were run, report the more conservative (larger p-value = 1 in 16,000) everywhere and note the other in a technical footnote.

---

### H2. `e_varying_null_resolution` Shows 24/24 Score with "NOISE" Verdict

On the browse/uncategorized page, the entry `e_varying_null_resolution` displays:
- **Best score: 24/24**
- **Verdict: NOISE**

This is deeply misleading. A visitor seeing "24/24 NOISE" will be confused — 24/24 is defined as "FULL MATCH" in the methodology. The experiment actually measures something different (null-mask crib preservation, not decryption), and every mask trivially scores 24/24 because crib positions are always preserved. The `best_score` field should not be ingested from this result file, or the entry should be excluded from the elimination database.

**Fix:** Either (a) exclude this experiment from the site data loader, (b) override best_score to N/A in `overrides.toml`, or (c) add a scope note explaining this is not a decryption score.

---

### H3. LOO Cross-Validation Accuracy — Contradictory Numbers

| Source | LOO Accuracy | Baseline |
|--------|-------------|----------|
| **Findings page** | 47% | 49% |
| **Elimination ledger** | 51.4% | below baseline |
| **MEMORY.md (prior)** | 51.4% | 48.6% |

**Problem:** The website's published figure (47%) differs from the session memory's figure (51.4%). These may refer to different versions of the test (different null-mask assumptions), but the discrepancy is not explained.

**Fix:** Determine which number is from the most recent, correct test and use it consistently. Update the other source.

---

### H4. Autokey Entry Shows 21/24 Score — Needs Context

The substitution browse page shows:
- **"Autokey cipher with all variant combinations"** — 456,976 configs, **21/24**, verdict: **ELIMINATED**, Tier 1

A score of 21/24 with an ELIMINATED verdict at Tier 1 (mathematical proof) needs prominent context. A casual visitor may wonder why 21/24 wasn't investigated further. The detail page should explain that autokey is structurally impossible (crib feedback contradiction) and the 21/24 is the maximum achievable before the contradiction manifests.

**Fix:** Add scope note to the overrides.toml entry explaining the structural impossibility proof and why 21/24 is expected.

---

## MEDIUM Severity Issues

### M1. "K1-K3 Solved in 1999" — Incomplete on Homepage

- **Homepage:** "K1–K3 were solved in 1999"
- **About Kryptos page:** "David Stein (1998, classified) and independently by Jim Gillogly (1999)"

The homepage claim is misleading. K1-K3 were first solved by David Stein at CIA in February 1998 (classified). Jim Gillogly independently solved them publicly in 1999. The NSA team (including Ken Miller) also solved them around the same period. The about-kryptos page is more accurate but still omits the NSA team.

**Fix:** Homepage should say "K1–K3 were solved in 1998–1999" or link to the about-kryptos page for details.

---

### M2. "Unsolved for 35 Years" — Borderline Stale

The sculpture was dedicated November 3, 1990. As of March 28, 2026, that's 35 years and ~5 months. "Over 35 years" is currently accurate, but will become "36 years" in November 2026. Multiple pages say "35 years" — this should be checked periodically or made dynamic.

**Fix:** Use "over 35 years" (currently correct) or dynamically compute from 1990.

---

### M3. Auction Date — "2025" vs Actual

The FAQ states the K4 chart was "sold at auction in 2025 for $962,500." The ground truth document says "per 2025 reporting" — meaning the reporting was in 2025, but the actual auction date may differ. This should be verified against the Christie's lot record.

**Fix:** Verify the actual auction date from Christie's records and update.

---

### M4. "869 Letters" on About-Me Page — Unverified

The about-me page states Kryptos consists of "869 letters hand-cut into copper." The standard K-section counts (K1: 69, K2: 372, K3: 336, K4: 97) total 874 cipher characters, plus 4 question mark delimiters = 878. The front face also contains the Vigenere tableau. The "869" figure needs a primary source citation — it may refer to just certain sections or exclude delimiters.

**Fix:** Verify against a primary source (Sanborn interview, Elonka Dunin's documentation, or direct count from sculpture photos). If uncertain, use "nearly 900 characters" or cite the specific source.

---

### M5. RQ-3 Shows "0/29 Eliminated" Despite Extensive Transposition Testing

The research-questions page shows RQ-3 (transposition layer) with 0 of 29 hypotheses eliminated. But the elimination ledger documents extensive transposition testing: columnar (widths 5-15), double columnar, Myszkowski, RS44, route, spiral, serpentine — all eliminated. The RQ coverage table in the database appears not to have been updated.

**Fix:** Update the `rq_coverage` data in the novelty ledger database to reflect actual transposition eliminations.

---

### M6. 145 Uncategorized Eliminations (37.6% of Total)

Over a third of all eliminations are in the "Uncategorized" bucket. Many clearly belong to specific categories:
- `f_vic_nonstandard_keyschedule_v1` → bespoke or substitution
- `E-CKM-02`, `E-CKM-03b` → key-models
- `MITM-MONO-TRANSPOSITION` → multi-layer
- `BLITZ-STRIP-CIPHER-V2` → transposition
- `WHEATSTONE-CLOCK-*` → bespoke

**Fix:** Expand the categorizer keyword rules or add `overrides.toml` entries for the most obvious miscategorizations. Aim to get uncategorized below 50 entries.

---

### M7. Non-Normalized Verdicts Displayed on Site

Six eliminations display raw verdict strings instead of canonical categories:
- `"NOISE: max 6/24 across 46,170 configs"`
- `"NOISE: max 5/24. Key ≠ f(row,col)"`
- `"NOISE: best 18/24 at w9/p11 ≈ expected by chance (Monte Carlo: ~3.6 hits expected)"`
- `"NOISE: all high scores at high periods (underdetermined)..."`
- `"NOISE: 18/24 at period 13 (expected random ~13.5 at p=13; false positive...)"`
- `"NOISE: 15/24 at period 8 only; period 7 = 0/24; Bean FAIL"`

These should all normalize to just "NOISE" in the display, with the detail in description or scope notes.

**Fix:** The `_normalize_verdict()` function in data_loader.py should strip explanatory suffixes from "NOISE:" prefixed verdicts.

---

## LOW Severity Issues

### L1. Duplicate Elimination Pages for Re-run Experiments

Two pairs of results from the same experiment run on different dates appear as separate elimination pages:
- `baudot_mod31_20260324_123652` and `baudot_mod31_20260328_102015` — identical parameters, identical results
- `wheatstone_clock_20260324` and `wheatstone_clock_20260328` — same

**Fix:** Deduplicate by keeping only the most recent result, or merge into a single elimination with both dates noted.

---

### L2. `e_berlin_clock_route` — "INTERESTING" at 0/24

This entry shows verdict "INTERESTING" but score 0/24. The INTERESTING threshold is 10+ per the methodology. Either the verdict is wrong (should be NOISE) or the score field doesn't reflect the actual finding (the experiment found interesting structural patterns at score 0).

**Fix:** Override verdict to NOISE, or clarify in the description that "interesting" refers to structural findings, not crib score.

---

### L3. Many Entries Show "N/A" for Configs Tested

Approximately 200+ of the 386 eliminations show "N/A" for configs tested. This undermines the "671.0B+" headline stat by making it seem like many experiments didn't track their work.

**Fix:** Backfill config counts from result JSON files where possible. For proof-based eliminations (Tier 1), display "N/A — mathematical proof" rather than just "N/A".

---

### L4. `href="#{{key}}"` Template Artifact

The `base.html` template contains `href="#{{key}}"` which appears in raw source. While the generated HTML doesn't contain this (Jinja2 resolves it), it suggests a potential for unresolved template variables if the context is missing.

**Fix:** This was verified as not present in generated output — no action needed, but add a Jinja2 `default('')` filter as defensive measure.

---

### L5. Search Index Titles Are Raw Experiment IDs

Many entries in the search index have titles like `e_csp_p23_w15_beau_01` or `E-CKM-02` rather than human-readable titles. This makes search results cryptic for visitors.

**Fix:** Add human-readable titles in `overrides.toml` for the most-viewed or highest-profile eliminations.

---

### L6. No Meta Description on Several Pages

The submit, report-error, and terms pages lack specific meta descriptions, defaulting to the site-wide description. This is a minor SEO issue.

**Fix:** Add page-specific `<meta name="description">` tags.

---

## Verified Correct (Spot Checks)

| Claim | Source | Verified |
|-------|--------|----------|
| K4 ciphertext (97 chars) | `kryptos.kernel.constants.CT` | Exact match |
| Crib positions 21-33 (ENE), 63-73 (BCL) | `CRIB_POSITIONS` | Correct (0-indexed) |
| 24 known plaintext characters (13+11) | Constants | Correct |
| Bean EQ: positions 27 and 65 | `BEAN_EQ` | Correct |
| Bean INEQ: 242 pairs | `BEAN_INEQ` | Correct (len=242) |
| Null palette: {B,G,I,K,O,W,Z} | `CONSENSUS_NULL_POSITIONS` + CT | Correct |
| 17 consensus null positions | `CONSENSUS_NULL_POSITIONS` | Correct |
| W absorption: 4 of 5 | CT analysis | Correct (W at 20,36,58,74 = null; 48 = non-null) |
| E count: 2 in CT, 3 in cribs | CT + crib analysis | Correct |
| Stehle anomaly: positions 55-63, delta4=5 | CT numeric analysis | All values verified exactly |
| Total eliminations: 386 | `data_loader.load_all()` | Correct |
| Total configs: 671.0B | Sum of configs_tested | Correct (670,968,488,512) |
| KA mod-5 pattern | KA sequence analysis | Correct (all palette letters at mod5 ∈ {0,3}) |
| Combined odds 1 in 7 million | p=1.4e-7 | Mathematically consistent |
| Sculpture dedication: November 3, 1990 | Public record | Correct |
| Ed Scheidt: retired Chairman, CIA Cryptographic Center | Public record | Correct |
| Two encryption systems (Sanborn quote, Nov 5 1990) | IMG_1249 transcript | Correct |
| "I wrote the Plain Text to be enigmatic" | IMG_1410 | Correct |
| "He lied" coordinate change | IMG_1384 | Correct |
| ABSCISSA as Sanborn research term | IMG_1340 | Correct |
| Beaufort cipher in handwritten list | IMG_1569 | Correct |
| Cyrillic Projector solved 2003 | Public record | Correct |

---

## Archive Page — Specific Findings

The archive page is the most content-rich and was checked against the photo inventory at `reference/archive_photo_evidence_inventory.md`.

**Verified correct:**
- All IMG_ numbers match the inventory
- Quotes from Sanborn match transcriptions
- Coordinate values (38°57'6.5"N / 77°8'44"W and the 37° variant) are correct
- "Code Breaker" overlay concept (IMG_1555) accurately described
- CIA cryptonym explanation (IMG_1570) accurately quoted
- FUMEE/OBMAN production details correct

**One concern:**
- The page presents interpretive claims alongside factual descriptions without always distinguishing them. For example, "Question marks may encode letter J" (from IMG_1531 stencil anomaly) is presented as a plausible interpretation but could be misread as a finding. Consider adding [HYPOTHESIS] tags to interpretive claims, consistent with the truth taxonomy.

---

## Recommendations (Priority Order)

1. **Fix H1** — Standardize null palette p-value across all pages (pick one number)
2. **Fix H2** — Remove or relabel the 24/24 NOISE entry (`e_varying_null_resolution`)
3. **Fix H3** — Standardize LOO accuracy figure
4. **Fix M7** — Normalize verdict strings in data loader
5. **Fix M6** — Categorize the 50+ obvious misassignments in uncategorized
6. **Fix M5** — Update RQ-3 coverage data
7. **Fix M1** — Update homepage K1-K3 solve date to "1998-1999"
8. **Fix H4** — Add structural impossibility context to autokey 21/24 entry
9. **Fix L1** — Deduplicate re-run entries (Baudot, Wheatstone)
10. **Fix L2** — Correct berlin_clock_route verdict
11. **Fix M4** — Verify "869 letters" claim
12. **Fix M3** — Verify auction date

---

*Generated 2026-03-28 by Claude based on full cross-referencing of live site content against codebase ground truth.*
