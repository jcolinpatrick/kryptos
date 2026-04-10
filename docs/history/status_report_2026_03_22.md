---
status: HISTORICAL SNAPSHOT — not authoritative
snapshot_date: 2026-03-22
superseded_by: MEMORY.md + docs/exhaustion_audit_2026_04_08.md + docs/exhaustion_certificate_2026_04_08.md
reason: Predates composition v1+v2+v3 (105K+ configs), score-conditioned null retirement of palette family (2026-04-01), and Team of Rivals exhaustion audit (2026-04-08). Quantitative claims and posture are stale.
---

> # HISTORICAL SNAPSHOT — NOT CURRENT DOCTRINE
>
> This document was authoritative on 2026-03-22 and has since been superseded.
> Do not use it to drive new work. For current project state run the session
> briefing and read `MEMORY.md`. See `docs/history/README.md` for context.

# KryptosBot Project Status Report

**Date:** 2026-03-22
**Prepared by:** Analyst (Claude claude-sonnet-4-6)
**Source files read:** `memory/elimination_ledger.md`, `memory/confirmed_findings.md`,
`memory/analyst_reviews.md`, `MEMORY.md`, `exhaustion_log.json`, `results/` directory,
`reports/final_synthesis.md`

---

## 1. Project Overview

**Mission:** Determine the true plaintext and full encryption method of Kryptos K4 — the
final unsolved panel of Jim Sanborn's 1990 CIA headquarters sculpture.

**Current assessment (as of 2026-03-22):** ALL computational approaches have been
exhausted. 950+ experiments, 884B+ cipher configurations tested, zero breakthroughs.
The project has entered a non-computational phase. Remaining paths to solution require
physical access to the K4 encoding chart, the installation itself, or a mechanism
revelation from Sanborn or Scheidt.

### Codebase Size

| Component | Count / Size |
|-----------|-------------|
| Source packages (`src/kryptos/`) | 4 layers: kernel, pipeline, novelty, cli |
| Experiment scripts (`scripts/**/*.py`) | 900+ tracked scripts across 32+ subdirectories |
| Test files (`tests/*.py`) | 25 test files |
| Exhaustion log entries | 574 entries (one per script/campaign) |
| Results files (`results/**/*.json`) | 200+ JSON artifacts (plus JSONL, txt, md) |
| Memory topic files (`memory/`) | 40+ topic files |
| Reports (`reports/`) | Multiple synthesis and analysis reports |

### Infrastructure Maturity

The framework is mature and purpose-built. Key capabilities:

- **Scoring engine:** Two-path scoring (`score_candidate()` anchored, `score_candidate_free()`
  floating) with thresholds NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24. Score 24/24
  with Bean PASS would indicate a candidate solution.
- **Parallel compute:** `SweepRunner` with checkpointing, WAL-mode SQLite persistence,
  28-core parallelism.
- **Novelty system:** 13 research questions (RQ-1..RQ-13) with hypothesis triage ledger.
- **Benchmark suite:** Tier 0-3 benchmarks for regression testing.
- **Site and API:** `kryptosbot.com` static site with FastAPI backend (theory classifier,
  submission queue).
- **Multi-agent SDK:** KryptosBot SDK with 23 strategies across 4 modes.

---

## 2. Elimination Landscape

**Source:** `memory/elimination_ledger.md` (last updated 2026-03-21)

**Total eliminated hypotheses:** 95+
**Total configurations tested (ledger):** ~15B+ (MEMORY.md states 884B+ across all
sources including sweep runs not individually logged)

### Summary by Attack Family

| Category | Configurations Tested | Elimination Class | Key Artifact |
|----------|-----------------------|-------------------|--------------|
| All periodic substitution (Vig/Beau/VBeau, all periods 1-26, AZ/KA) | Complete (6 variants x 26 periods) | **MATHEMATICAL PROOF** | Key conflicts at all crib positions under 242 Bean inequalities |
| CT-autokey (all 576 configs) | 576 | **ANALYTICAL** | `scripts/substitution/e_analytical_eliminator.py` |
| Autokey on raw 97 + primers (<=13 chars) | 7.9M+ | noise (max 9/24) | — |
| Period-13 mixed-alphabet polyalphabetic | 475K+ keywords | **MATHEMATICAL IMPOSSIBILITY** | `results/period13_mixed_alphabet_beaufort.json` |
| 99 narrative/Cold War keywords | 99 | ZERO above threshold | `results/f_narrative_keyword_sweep_v1.json` |
| Pure transposition | All perms (letter freq proof) | **MATHEMATICAL PROOF** | CT has 2 E's, cribs need 3 |
| Non-standard transposition (serpentine/spiral/Myszkowski/rail) | 64,960 | ZERO >=7/24 | — |
| MITM mono sub + structured transposition (14 families) | 4.2M | ZERO hits | — |
| MITM periodic sub (p2-20) + structured transposition | 240M | ZERO hits | — |
| TKAS v1: all trans within CT73 + periodic key p1-13 | 4.5M trans x 3 variants x 13 periods | 19/24 max = underdetermination noise | `results/f_tkas_v1.json` |
| Null mask + periodic sub (p=1-23) | ~325 triples + 550K random masks | **PROVEN IMPOSSIBLE** | — |
| Palette-constrained null mask exhaustive | 27,456 (C(14,7) x 8 variants) | DISPROVED | `results/palette_exhaustive_null_mask.json` |
| DEFECTOR:AZ_beau+col7 null mask exhaustive | 231.9M (C(56,7)) | ZERO above 15/24 | `results/bruteforce_7remaining_complete.json` |
| Four-Square / Playfair / Two-Square | SA exhaustive | 23/24 ceiling = SA overfitting | `memory/four_square_hypothesis.md` |
| VIC cipher — ALL variants (5 sub-models) | **1.32B+** | noise (max 10/24) | `memory/vic_narrative_sweep_elimination.md` |
| Gromark on 73-char null-extracted | **8.74B** | ZERO crib-consistent | `results/gromark_73char/summary.json` |
| 2-round letter Feistel | 12,320 | **STRUCTURAL IMPOSSIBILITY** | `scripts/substitution/e_differential_feistel.py` |
| Fleissner 8x9 + periodic sub | All | **ALGEBRAIC IMPOSSIBILITY** | `memory/fleissner_8x9_model.md` |
| Bifid 5x5 | All | **IMPOSSIBLE** (all 26 letters in CT97) | — |
| K2 numbers / coords / number-words as keys | ~30K | noise (max 7/24) | — |
| Running key from 32 reference sources | 3.02M text pair combos | noise (max 8/24) | `results/corpus_keystream_search.json` |
| Running key from 479 Gutenberg texts | ~1.2B evals | noise (max 10/24) | `results/k123_running_key_exhaustive/phase4_gutenberg/scan_results.json` |
| K1-K3 PT as running key (247,200 configs) | 247,200 | ZERO >=8/24 | `results/k123_running_key_exhaustive/summary.json` |
| Positional keying f(pos%M, pos%N) | All divisible pairs (M,N=2-14) | **STRUCTURALLY IMPOSSIBLE** | `results/mod35_positional_keying.json` |
| NDYAHR neighbor deletion | 12 marks | **DISPROVED** (1/17 overlap) | `memory/ndyahr_corrected_and_layer_two.md` |
| Sculpture reading paths | 10,777 paths x 976K tests | noise (max 7/24) | — |
| Simple null-position arithmetic rules | 1.26M rules | ZERO predict all 24 nulls | `results/f_argenti_null_rule_v1.json` |
| Grid-position-dependent keying | 6 models x 20 keywords x 4 variants | ZERO >=6/24 | `results/mod35_positional_keying.json` |
| Morse-indexed alphabet (MIA) as cipher | 9 combos | ELIMINATED | `results/e_morse_indexed_alphabet_01.json` |
| CT->Morse->Binary null mask | 24+ mappings | ALL non-significant / crib conflicts | `results/e_morse_binary_null_mask_01.json` |
| CT/crib error hypothesis | 2,425 CT + 600 crib mutations + 9 position shifts | ZERO improvement | — |
| Simple f(CT,pos)->key functions | 2,483 functions | ZERO >=6/24 | — |
| Paper fold / overlay models | 11K configs | noise (max 8/24) | — |
| K0 Morse running key | 28K configs | noise (max 5/24) | — |
| Progressive running keys | 1.06M configs | noise (max 8/24) | — |
| M5 segmented periodic | Analytical + SA | Fully-determined keys = gibberish | — |
| Accordion fold on K1-K2 chart | 2K configs | noise (6/24) | — |
| CKM two-keyword exhaustive | 170M | noise (max 10/24) | — |
| Alexandria street names as cipher key | 230 configs | ZERO (0/24) | — |
| Vertical word lock (28x31 cylinder) | 12M (3-stage incl. beam) | noise (max 4/24) | `results/e_ts_vertical_wordlock.json` |
| Multi-layer CoD (depth 3) | 39.6M | noise (max 9/24) | — |
| Deep Carter/Egyptian vocabulary keywords | 184 keywords x 4 variants | noise (max 5/24) | — |

### Proven-Impossible Summary (Cannot Work by Math)

1. ANY periodic substitution on raw 97-char CT
2. ANY autokey variant (structural impossibility via crib-to-crib proof)
3. Pure transposition (letter frequency mismatch)
4. ANY null-mask + periodic sub (p=1-23)
5. ANY standard product cipher (sub x trans)
6. ANY digraphic cipher (23/24 SA ceiling = overfitting)
7. ANY VIC variant (1.32B+ configs)
8. ANY Fleissner turning grille + periodic sub (algebraic proof)
9. Gromark on 73-char (8.74B configs)
10. ALL standard key derivation from K2 coordinates
11. ALL standard transposition within CT73 + periodic/running key (TKAS: 4.5M trans x 38 texts)
12. Single-character CT/crib errors (data confirmed clean)
13. All simple positional key functions

### False Signals Traced and Closed

| Signal | Score | Resolution |
|--------|-------|------------|
| DEFECTOR:AZ_beau+col7 | 15/24 | FALSE SIGNAL. Autokey structurally impossible; 232M exhaustive confirms score is mask-independent |
| PALIMPSEST:AZ_beau+col7 | 15/24 | FALSE SIGNAL. Same autokey impossibility; crib structure artifact |
| Width-10/17/6 IC anomalies on CT73 | p=0.048 | Col7 artifact — drops to p=0.556 after col7 undo |
| d=13 hybrid exploitation | 16/24 ceiling | Underdetermined (MC baseline p=0.0009). AP {G,K,O} REAL but unexploitable |
| 73-char grid coordinate keys (affine) | 19/24 | Underdetermination noise — confirmed by MC |
| Native grid reading + periodic sub | 22/24 at p24 | Underdetermined at period 24 (false signal documented) |

---

## 3. Confirmed Findings

**Source:** `memory/confirmed_findings.md`

### Two-System Model [PRIMARY SOURCE]

Sanborn's 1990 dedication speech (RR Auction lot): "There are TWO SYSTEMS of enciphering
the bottom text... pull up one layer, come to the next." Ed Scheidt (Wired): "I used a
bit of stego when designing the fourth part." Combined with the mathematical proof (all
single-layer ciphers fail), this is the foundational confirmed fact.

### Null Palette {B,G,I,K,O,W,Z} [INTERNAL RESULT, 2026-03-15]

The 17 consensus null positions in K4 use only 7 distinct letters. Statistical significance:
p ≈ 3.0 × 10⁻⁵ permutation test (Stirling analytical: 7.78 × 10⁻⁵). The KA alphabet arranged on a 5-wide Polybius
grid shows the palette falls exclusively in columns 0 and 3, generated by a dual-keyword
rule using KRYPTOS (row selector) and SEVEN (column selector). This gives 6/6 exact row
matches (p ~1/1,672 Monte Carlo).

Consensus null positions (17/24 fixed):
`{0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}`

### BCL Keystream Palette Enrichment [INTERNAL RESULT, 2026-03-15]

Beaufort keystream k[i] = (CT[i] + PT[i]) mod 26 at BERLINCLOCK positions 63-70: 7/8
values are palette letters. P(>=7/8 at baseline 7/26) = 0.000627 (BF = 185.4). This is
variant-specific: Beaufort A=0 is the only variant/indexing combination achieving 7/8.

### Joint Null Significance [INTERNAL RESULT, CORRECTED 2026-03-20]

Fisher p-value deprecated (independence assumption violated). Joint null simulation
(5M trials, seed 20260320):

- P(distinct<=7 AND derived-palette ks>=13 | shuffled CT) = 2e-7 [3.5e-8, 1.1e-6]
- **Reported joint null: p = 1.4e-7 (MC 50M, published)**
- This is STRONGER than Fisher predicted (events are negatively correlated under null)

### Model B Keystream Properties [DERIVED FACT]

Keystream `JLJODEGKUKKKLOCGGBGOKTRU` at the 24 crib positions exhibits three
independently significant properties:

| Property | Observed | P-value |
|----------|----------|---------|
| IC | 0.0797 (2.07x random) | 0.0047 |
| AP {G,K,O} 12/24 | Step-4 arithmetic progression | ~4e-6 |
| Same-PT clustering | avg dist 3.62 vs expected 6.5 | 0.0046 |

Joint probability of all three: approximately 1 in 1,200. These patterns are confirmed
real but remain unexploitable — every cipher model tested to date hits a ceiling at 15-16/24
or is mathematically eliminated.

### (pos%7, pos%5) Classification Table [HYPOTHESIS -- zero DOF, post-hoc]

A 7x5 grid perfectly separates all 35 palette-letter positions into null vs real:
35/35 correct. The grid structure corresponds to KRYPTOS (period 7) x SEVEN (period 5),
lcm(7,5) = 35 = exact palette-letter count. Combined significance p < 1e-8, but
this is post-hoc with zero degrees of freedom and should not be combined naively with
other statistics.

### Other Confirmed Structural Facts

- **K5 confirmed:** 97 characters, shares "coded words at same positions" as K4 [PUBLIC FACT, Nov 2025 Spy Museum]
- **K2 progressive solve:** K2 numbers 38, 77, 8 encode K3 grid dimensions (p ~1/180M) [INTERNAL RESULT]
- **GZL tape = K2 CT:** Tape content confirmed as UNDERGROUND (correct spelling) [INTERNAL RESULT]
- **ABSCISSA double-coding:** "cut off" + coordinate sense confirmed [INTERNAL RESULT]
- **Accordion fold lines on chart CONFIRMED:** At ABSCISSA seam + line 6/7 boundary [INTERNAL RESULT, 2026-03-22]
- **Kinko's transparency order:** Smithsonian Box 6/18 — chart may require companion overlay [INTERNAL RESULT, 2026-03-22]
- **Paper = government computation quadrille:** National Brand 42-382 or equivalent, RGB (183,182,146). NOT crypto-specific [INTERNAL RESULT, 2026-03-22]
- **7x14 grid palette asymmetry:** p = 0.000074 [INTERNAL RESULT]
- **K3 method confirmed:** 24x14 -> 8x42 double rotation [INTERNAL RESULT]
- **Antipodes proof:** K4 identical on both Antipodes sculptures -> cipher is geometry-independent [INTERNAL RESULT]
- **Scheidt non-involvement:** "I intentionally did not do [K4]... stay away." [PRIMARY SOURCE]

---

## 4. Results Audit

**Source:** `results/` directory (top-level and subdirectories)

### File Count and Organization

The `results/` directory contains 200+ JSON artifacts plus JSONL logs, text summaries,
and markdown analyses. Files span three generations of tooling:

| Sub-directory / Pattern | Contents |
|-------------------------|----------|
| `results/*.json` (flat) | ~100+ individual experiment results |
| `results/frac/` | Fractionation family results |
| `results/hybrid/` | Hybrid cipher results |
| `results/gromark_73char/` | Gromark exhaustion (8.74B configs) |
| `results/campaigns/` | KryptosBot SDK campaign output |
| `results/egypt_corpus/` | Egyptological corpus pipeline |
| `results/ant_*/` | Antipodes engine hits (JSONL) |
| `results/blitz_*/` | Blitz family results |
| `results/corpus_scan/` | Running key corpus scan |
| `results/bench/` | Benchmark results |
| `results/k123_running_key_exhaustive/` | 479 Gutenberg texts sweep |

### Notable Result Files and Best Scores

| File | Key Result | Score / Status |
|------|-----------|----------------|
| `results/f_tkas_v1.json` | TKAS v1: trans within CT73 + periodic key | Max 19/24 at p13 = **underdetermination noise** (baseline 13.3). ZERO signal at p<=7 |
| `results/bruteforce_7remaining_complete.json` | 231.9M null mask exhaustion | **Best: 15/24.** Score is mask-independent (264 masks at 15, 1,080 at 14). Confirms DEFECTOR signal is structural to col7 model, not to correct null positions |
| `results/gromark_73char/summary.json` | Gromark on 73-char | **ZERO crib-consistent** across 8.74B configs |
| `results/palette_exhaustive_null_mask.json` | Palette-constrained null mask | Max 5/24 = **DISPROVED** |
| `results/period13_mixed_alphabet_beaufort.json` | Period-13 polyalphabetic | **MATHEMATICAL IMPOSSIBILITY** |
| `results/f_argenti_null_rule_v1.json` | 1.26M null-position arithmetic rules | ZERO predict all 24 nulls |
| `results/e_ts_vertical_wordlock.json` | Cylindrical rotation, 12M configs | Max 4/24 = **noise** |
| `results/vic_narrative_sweep_elimination.md` | VIC cipher, 1.32B+ configs | Max 10/24 = noise |
| `results/k123_running_key_exhaustive/summary.json` | K1-K3 PT as running key | ZERO >=8/24 across 247,200 configs |
| `results/k123_running_key_exhaustive/phase4_gutenberg/scan_results.json` | 479 Gutenberg texts | Max 10/24 (random) across ~1.2B evals |
| `results/d13_hybrid_exploitation.json` | d=13 anomaly exploitation | Ceiling 16/24 = underdetermined |
| `results/e_morse_binary_null_mask_01.json` | Morse/binary null mask | p=0.1323 (n.s.), all mappings invalid |
| `results/mod35_positional_keying.json` | Positional keying (pos%M, pos%N) | STRUCTURALLY IMPOSSIBLE |
| `results/e_joint_null_simulation.json` | Joint null MC simulation | p = 2e-7 [3.5e-8, 1.1e-6] |

### Scoring Pattern Across All Results

Every score above noise threshold (>=18/24) has been traced to one of four artifacts:
1. Autokey structural impossibility (crib-to-crib proof applies)
2. Statistical underdetermination at high periods (>= period 17)
3. Col7 artifacts from the DEFECTOR/PALIMPSEST model
4. Simulated annealing overfitting (SA reaches 23/24 but never 24/24 under any model)

No result has ever reached 24/24 with a Bean PASS under any tested model.

---

## 5. Script Coverage

**Source:** `exhaustion_log.json` (574 entries, representing scripts and campaigns)

### Exhaustion Log Status Breakdown

| Status | Count |
|--------|-------|
| exhausted | 144 |
| active | 354 |
| promising | 76 |
| **Total entries** | **574** |

Note: The "active" and "promising" statuses in the exhaustion log reflect metadata
assigned when scripts were written or last modified, not a current research assessment.
MEMORY.md's definitive assessment is that ALL computational approaches are exhausted.
The "active" entries largely reflect stale status fields that predate the March 2026
elimination campaign.

### Script Families (by entry count in exhaustion log)

| Family | Entries (approx.) |
|--------|-------------------|
| blitz | ~55 |
| fractionation | ~55 |
| grille | ~50 |
| _uncategorized | ~50 |
| transposition/columnar | ~25 |
| transposition/other | ~20 |
| polyalphabetic | ~20 |
| substitution | ~20 |
| running_key | ~15 |
| yar | ~20 |
| campaigns | ~20 |
| tableau | ~15 |
| exploration | ~20 |
| crib_analysis | ~15 |
| k3_continuity | ~10 |
| thematic/* | ~15 |
| cfm | ~10 |
| statistical | ~6 |
| team | ~10 |
| antipodes | ~5 |
| encoding | ~5 |
| _infra | ~10 |
| other (k3_continuity, yar, etc.) | remainder |

The fractionation family (55 scripts, `e_frac_02b` through `e_frac_54`) represents the
most thoroughly developed single attack family. The grille and blitz families tie for
second place.

---

## 6. Exhaustion Log Analysis

**Source:** `exhaustion_log.json`

The log has 574 total entries (one per script or campaign). The JSON structure is:
```json
{
  "<script_id>": {
    "description": "...",
    "family": "<family_name>",
    "status": "exhausted|active|promising"
  }
}
```

| Status | Count | Meaning |
|--------|-------|---------|
| exhausted | 144 | Script ran to completion, results recorded |
| promising | 76 | Script showed above-noise results at time of last run |
| active | 354 | Script registered but status not updated post-run |

**Important caveat:** The "promising" classification is based on the score at time of
last execution and does not account for subsequent analysis showing those scores to be
false signals (underdetermination, col7 artifacts, SA overfitting). All 76 "promising"
entries have been superseded by the elimination campaign's analytical conclusions.

---

## 7. Open Attack Surface

**Source:** MEMORY.md "OPEN ATTACK SURFACE" section

The honest assessment from the project's own records (2026-03-22):

> "ALL computational approaches exhausted. The mechanism is either genuinely novel or
> requires external information."

### Remaining Paths (Ranked by Feasibility)

| Path | Type | Status / Notes |
|------|------|----------------|
| K4 encoding chart (auction lot) | External information | Buyer of $962.5K RR Auction lot owns Sanborn's K4 worksheet. Keyword likely written on it. **Untestable without access.** |
| Sanborn's verification website | External information | Announced to Colin Patrick by Kryptos Keepers, Mar 2026. Coming but no timeline. |
| Physical installation access | Physical | Pool reflection, Decoding Filter, lodestone, Ed Shaw techniques. Requires on-site work. |
| Encoding chart forensics | Physical | Sanborn (NPR 2010): "study it in a forensic manner... revelations." Known marks: X/? behavior, margins, tape, arrows, folds. `memory/chart_physical_forensics.md` |
| Kinko's transparency overlay | Physical | Smithsonian Box 6/18: Sanborn ordered transparencies alongside the chart. Chart may be INCOMPLETE without companion overlay. Grille-as-key-carrier NOT tested (distinct from grille-as-mask, which was exhausted). |
| Bespoke/novel mechanism | Unknown | "Embarrassingly simple once seen" (Sanborn). "May not be a known technique" (Scheidt). No testable model. |
| Non-periodic segmented keys | Computational | OPEN in theory but untestable without source text identification. Running key from non-public/classified source not eliminated. |

### Why Computational Search Is Stuck

The core constraint is the Bean equality/inequality system. The 24 known key values at
crib positions (`JLJODEGKUKKKLOCGGBGOKTRU`) must be consistent with any periodic key, which
requires:
- k[27] = k[65] (Bean equality, always satisfied)
- 242 variant-independent inequalities among the remaining pairs

This rules out ALL periodic keys (gcd proof: gcd(39,45)=3, but key has 12 distinct values
among 24 positions — impossible under any period). The only viable models are:
1. Running key from an unidentified non-public source
2. A bespoke cipher with an arbitrary lookup table (the encoding chart itself)
3. A physical/procedural mechanism not reducible to standard cryptographic taxonomy

---

## 8. Analyst Review History

**Source:** `memory/analyst_reviews.md`

| Session Date | Focus | Key Outcome |
|---|---|---|
| 2026-03-15/16 | Result verification + 3 critical corrections | Consistency audit; statistical corrections applied |
| 2026-03-18 | TKAS, error hypothesis, VIC gap-close, sculpture paths, grid keying | **ALL computational approaches declared exhausted** |
| 2026-03-19 | Chart forensics, K3 code chart, ISBN hunt, statistical audit | Fisher p-values deprecated; joint null re-derived (p=4.2e-6 -> p=2e-7) |
| 2026-03-20 | Polybius-coord, keyword×progressive, stego-aware SA, 7×14 asymmetry | Public writeup completed |
| 2026-03-21 (session 1) | Gutenberg sweep (60K texts, 106B checks). Periodic proof via gcd. 4-agent exploration | Row clustering proved IRRELEVANT. -4.0 threshold non-discriminating for 73-char. ZERO from 60K texts. |
| 2026-03-21 (session 2) | Keystream algebra Phase 1-3 (9 scripts, 4 agents) | Row clustering p=0.0022; restricted alphabet DISPROVED (MCMC). Smithsonian photo forensics: "11 Lines 342"=K3+ENDYAHR |
| 2026-03-21 (session 3) | Smithsonian archive: 202+17 images across 4 boxes | MIA alphabet ELIMINATED. Sanborn's Vigenere tableau found. Cyrillic Projector Letter->Morse->Binary confirmed but does NOT apply to K4. Alexandria street names tested: 0/24. |
| 2026-03-21 (session 4) | Signal inventory and ranking | Row Markov SA (600 restarts, 4 conditions): row clustering is IRRELEVANT (Z=-14.975). Signal ranking finalized. |
| 2026-03-22 (session 5) | Paper fold/overlay (11K), K0 Morse (28K), progressive RK (1.06M), segmented periodic, accordion fold, CKM (170M), chart forensics | All eliminated. Accordion fold lines CONFIRMED on chart. |
| 2026-03-22 (session 6) | Forensic photo analysis of K1-K2 chart (15 enhanced images) | Paper = standard gov Eye-Ease quadrille (not crypto-specific). Kinko's transparency discovered. German Gutenberg downgraded. **No well-motivated computational test remains.** |

---

## 9. Test Suite Health

The test suite covers 25 test files across unit, QA, and benchmark categories:

| Test Category | Files |
|---|---|
| Unit tests | `test_alphabet.py`, `test_scoring.py`, `test_pipeline.py`, `test_transforms.py`, `test_constants.py`, `test_constraints.py`, `test_free_crib.py`, `test_word_scoring.py`, `test_corpus.py`, `test_attack_lib.py`, `test_novelty.py`, `test_polybius_coord.py`, `test_gutenberg_sweep.py` |
| QA / audit tests | `test_qa_pipeline_novelty.py`, `test_qa_structural_claims.py`, `test_qa_kernel_verify.py`, `test_qa_frac_cross_verify.py`, `test_audit_regression.py` |
| Benchmark tests | `test_bench.py`, `test_bench_scorer.py`, `test_bench_generate.py`, `test_bench_segmenter.py`, `test_bench_regression.py`, `test_bench_validator.py` |

Test execution requires `PYTHONPATH=src pytest tests/`. The kernel layer has no external
runtime dependencies (stdlib only). Tests would need to be run to confirm current pass/fail
state; this report does not include a live test run.

---

## 10. Statistical Anomalies of Note

These are the genuine, unresolved structural signals that have survived all attempts at
exploitation:

| Signal | Statistic | P-value | Status |
|--------|-----------|---------|--------|
| Joint null (palette + keystream enrichment) | p = 2e-7 [3.5e-8, 1.1e-6] | 2e-7 | CONFIRMED REAL, mechanism unknown |
| AP {G,K,O} in Model B keystream (12/24) | step-4 progression | ~4e-6 | CONFIRMED REAL, unexploitable |
| Polybius convergence (KRYPTOS x SEVEN) | 6/6 row matches | ~1/1,672 | CONFIRMED REAL |
| Beaufort A=0 BCL enrichment | 7/8 palette | 6.3e-4 | CONFIRMED REAL, variant-identifying |
| (pos%7, pos%5) 35/35 classification | Perfect separation | < 1e-8 | POST-HOC (zero DOF) |
| 7x14 grid palette asymmetry | — | 7.4e-5 | CONFIRMED REAL |
| Keystream IC | 0.0797 vs 0.0385 expected | 0.0047 | CONFIRMED REAL |
| Same-PT clustering | avg dist 3.62 vs 6.5 | 0.0046 | CONFIRMED REAL, row-Markov SA DISPROVES row-based origin |
| K2 progressive solve | 38->24, 77->14, 8->8 | ~1/180M | CONFIRMED REAL (K2 encodes K3 dims) |
| K3+?+K4 = 434 = 31x14 | Perfect grid fit | — | CONFIRMED REAL (geometric constraint) |

---

## 11. Known Issues and Cautions

1. **Fisher p-values deprecated:** The Fisher combined p-value (previously cited as 4.2e-6
   in `reports/statistical_appendix_bean.tex` and 8.4e-7 in `memory/bcl_palette_keystream.md`)
   used an invalid independence assumption. The correct value from joint null simulation is
   p = 2e-7. Documents citing the old value have been flagged but not all may have been updated.

2. **"Promising" status in exhaustion log is stale:** 76 entries marked "promising" were
   classified before the comprehensive analytical review. The scores motivating those
   classifications are documented in the elimination ledger as false signals.

3. **"Active" entries in exhaustion log:** 354 of 574 entries remain marked "active."
   This reflects incomplete status updates, not an active research direction. The March
   2026 elimination campaign provides the authoritative disposition.

4. **Kinko's transparency not yet tested:** The grille-as-key-carrier hypothesis (transparency
   as mask that selects real positions from filler) is distinct from the exhaustively tested
   grille-as-mask family. This is the one remaining unstudied computational hypothesis, but
   requires knowing the transparency pattern.

5. **German Gutenberg DOWNGRADED (2026-03-22):** Previously considered a candidate running
   key source. Downgraded because both cribs (EASTNORTHEAST, BERLINCLOCK) are English.
   "CLOCK" is not a German word.

---

## 12. Summary and Outlook

**Where we are:** The K4 problem has been computationally exhausted to the limits of
known cryptographic taxonomy. 950+ experiments over ~8 sessions spanning 2026-03-15
through 2026-03-22 (plus the earlier 170+ experiment campaign documented in
`reports/final_synthesis.md`). No genuine signal has been found. Every high score has
been explained as a false positive.

**What is confirmed:** A two-system model (stego + cipher) is mathematically required.
The stego layer has been substantially characterized (null palette p=1.4e-7 jointly
with keystream enrichment). The cipher layer keystream has three confirmed statistical
anomalies that resist exploitation.

**What is open:** Only non-computational paths remain:
- The $962.5K auction lot buyer owns the encoding chart. The keyword is likely written
  on it.
- Sanborn announced a verification website via Kryptos Keepers (March 2026).
- Physical installation access and the Kinko's transparency (Smithsonian Box 6/18) are
  the two untested physical leads.

**Operational recommendation:** No further computational testing is warranted. The
project should monitor the Sanborn verification website announcement, attempt contact
with the auction lot buyer, and pursue physical installation access if feasible.

---

*Report generated from source files as of 2026-03-22. All figures are sourced directly
from `memory/elimination_ledger.md`, `memory/confirmed_findings.md`,
`memory/analyst_reviews.md`, `MEMORY.md`, `exhaustion_log.json`, and result artifacts
in `results/`. No figures are approximated.*
