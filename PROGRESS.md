# K4 Agent Team — Progress Tracker
Last updated: 2026-02-20T23:00:00Z by agent_frac

## ALERTS
<!-- Scores ≥18/24 go here. If this section is non-empty, ALL agents should read it. -->

### [2026-02-19T03:20Z] agent_frac — BIMODAL FINGERPRINT IS LIKELY AN ARTIFACT (E-FRAC-11)
**ALL AGENTS READ THIS.** The bimodal fingerprint pre-filter (MANDATORY in AGENT_PROMPT.md) is likely based on a statistical artifact, NOT evidence of transposition structure.

**Evidence:**
1. Per-position crib match rates decline MONOTONICALLY from position 21 (100%) to position 73 (11%) under random permutations. There is no "bimodal" pattern — just a smooth gradient caused by crib ordering.
2. ENE (positions 21-33) matches 3.5x better than BC (positions 63-73) under RANDOM permutations with NO transposition. This is because ENE positions come first and are more likely to be "first assignments" in periodic scoring.
3. 0/500,000 random permutations pass the bimodal check — the constraint is too restrictive.
4. ALL high-scoring random permutations show ENE >> BC regardless of transposition structure.

**Implication:** The bimodal pre-filter eliminates valid candidates based on an unfounded assumption. Agents should consider dropping or relaxing this filter.
**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_11_bimodal_validity.py`
**Artifacts:** results/frac/e_frac_11_bimodal_validity.json

### [2026-02-19T05:00Z] agent_frac — STATISTICAL SIGNALS ARE WEAKER THAN CLAIMED (E-FRAC-13/14)
**ALL AGENTS READ THIS.** Three pillars of the width-9 / structural hypotheses are statistically weak:

1. **K4's IC = 0.036 is NOT unusual.** It's at the 21.5th percentile of random 97-char text (z=-0.84, p=0.21). The "below-random IC" claim is not meaningful at n=97. IC does NOT constrain the cipher family.

2. **Lag-7 autocorrelation does NOT survive Bonferroni correction.** p=0.0077 uncorrected, but with 48 lags tested, the corrected threshold is p<0.001. After correction, ZERO lags are significant. The lag-7 signal is expected to appear at SOME lag by chance.

3. **DFT peak at k=9 is NOT significant.** Magnitude = 162, but the 95th percentile of the maximum random peak is 192. The k=9 peak doesn't even reach the 95th percentile, let alone 99th. Zero DFT peaks are significant.

**Implication:** There is NO strong statistical evidence for any specific transposition width, periodicity, or structural pattern in K4. The CT is statistically consistent with random text of length 97. Previous claims about DFT peaks and lag-7 as evidence for width-9 should be RETRACTED.

**Additional finding:** Bifid 6×6 on English plaintext produces IC ≈ 0.059-0.069 at ALL periods, far above K4's 0.036. K4 is at the 0th percentile. **Bifid is IC-incompatible with K4**, with or without transposition.

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_13_ic_analysis.py && PYTHONPATH=src python3 -u scripts/e_frac_14_autocorrelation.py`

## Active Tasks
| Agent | Task | Started | Status |
|-------|------|---------|--------|

## FRAC Agent Mandate — 28 experiments (E-FRAC-01 through E-FRAC-28)

**Original mandate (E-FRAC-01 to 25): COMPLETE. ZERO positive findings survived.**
**Extended mandate (E-FRAC-26/27/28/29/30): Bean profiling + crib scoring. ALL columnar widths 5-15 ELIMINATED.**

### New Structural Findings (E-FRAC-26/27)

**Width-5 and Width-7 are Bean-ELIMINATED** (exhaustive proof):
- Width-5: 0/120 orderings pass Bean equality
- Width-7: 0/5,040 orderings pass Bean equality, 0/75,600 configs pass full Bean
- This is a HARD STRUCTURAL CONSTRAINT — no ordering at these widths can satisfy CT[inv(27)] = CT[inv(65)]

**Width-9 has significantly better Bean-quadgram compatibility than width-7:**
- Width-9: 67,320 Bean-passing configs (1.24%), best Bean quadgram: -6.238
- Width-9 best quadgram exceeds all 10K random samples (p < 0.0001)
- Width-8: 3,006 full Bean passes (2.49%), best Bean quadgram: -6.371
- Width-6: 127 full Bean passes (5.88%), best Bean quadgram: -6.655

**Bean compatibility profile (widths 5-15):**
- Bean-INCOMPATIBLE: widths 5, 7 (zero Bean passes, exhaustively verified)
- Bean-COMPATIBLE: widths 6, 8, 9, 10, 11, 12, 13, 14, 15
- BUT: all plaintexts are still gibberish. No width produces English text.

### Summary of what FRAC has eliminated/established:
1. **ALL 10 fractionation families** — structurally eliminated (E-FRAC-21)
2. **Width-9 columnar + ALL substitution models** — NOISE at discriminating periods (E-FRAC-01 to 12)
3. **Width-5 and Width-7 columnar** — Bean-ELIMINATED (E-FRAC-26/27)
4. **Width-6 and Width-8 columnar** — NOISE at discriminating periods, width-8 UNDERPERFORMS random (E-FRAC-29)
5. **Width-9 × width-7 compound transposition** — ELIMINATED (E-FRAC-04)
6. **ALL prior statistical claims** — debunked after multiple-testing correction (E-FRAC-13/14)
7. **Bimodal fingerprint pre-filter** — statistical artifact (E-FRAC-11)
8. **Beaufort key entropy signal** — RETRACTED as selection effect (E-FRAC-16→25)
9. **Crib positions** — validated as correct (E-FRAC-18)
10. **Columnar widths 5-15**: ALL ELIMINATED — Bean-impossible (5,7), noise (6,8,9), underperform random (10-15) (E-FRAC-12/26/27/29/30)

**Reports:** `reports/frac_width9_analysis.md`, `reports/frac_statistical_meta_analysis.md`

## Completed (reverse chronological)

### [2026-02-20T23:00Z] agent_frac — E-FRAC-30: Sampled Crib Scoring — Widths 10-15 (ELIMINATION)
- **Hypothesis:** Do Bean-compatible widths 10-15 show crib signal at discriminating periods (2-7)?
- **Configs tested:** 100K sampled orderings per width × 3 variants × 2 models × 6 periods (600K total per width) + 100K random baseline.
- **Key findings:**
  - ALL widths 10-15: max score 14/24 from 100K samples
  - Corrected p = 0.993 for all (99.3% of random 100K-trial experiments also reach 14)
  - ALL widths 10-15 UNDERPERFORM random (random gets max=15, columnar gets max=14)
  - Score distributions nearly identical to random at all widths (means 9.18-9.40 vs random 9.38)
  - Bean pass rates: 2.6-4.7% equality, full pass rates roughly match E-FRAC-27
  - Width-10: 1 Bean-passing ordering scored 14 (Beaufort p=7) — noise
  - Widths 12, 13, 14: ZERO Bean-passing orderings scored ≥12
- **Comprehensive width elimination (5-15):**
  - Width-5, 7: Bean-ELIMINATED (zero orderings pass Bean equality)
  - Width-6: NOISE (exhaustive, corrected p=0.485)
  - Width-8: NOISE, underperforms random (exhaustive, corrected p≈1.0)
  - Width-9: NOISE, underperforms random (exhaustive, corrected p≈1.0)
  - Width-10 through 15: NOISE, all underperform random (sampled, corrected p=0.993)
- **Verdict:** NOISE — ALL columnar widths 5-15 are ELIMINATED for columnar + periodic substitution at discriminating periods. The columnar transposition hypothesis is dead at every practical width.
- **Runtime:** 447 seconds
- **Artifacts:** results/frac/e_frac_30_w10_w15_crib_scoring.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_30_w10_w15_crib_scoring.py`

### [2026-02-20T22:00Z] agent_frac — E-FRAC-29: Exhaustive Crib Scoring — Widths 6 and 8 (ELIMINATION)
- **Hypothesis:** Do Bean-compatible widths 6 and 8 show crib signal at discriminating periods (2-7)?
- **Gap filled:** E-FRAC-27 showed widths 6 and 8 are Bean-compatible, but they were never scored against cribs at discriminating periods. Width-9 was tested in E-FRAC-12.
- **Configs tested:** Width-6: 720 orderings (exhaustive) × 3 variants × 2 models × 6 periods; Width-8: 40,320 orderings (exhaustive) × 3 variants × 2 models × 6 periods; + 100K random baseline.
- **Key findings:**
  - Width-6 max: 13/24 (order=[4,3,2,5,1,0], period 6, Beaufort, model B)
  - Width-8 max: 13/24 (50 orderings tied, all at period 7)
  - Random baseline: max 15/24, mean 9.38, p99=12, p999=12
  - **Raw p=0.0009 is MISLEADING** — must correct for number of trials
  - **Width-6 corrected p=0.485** (48% of random 720-trial experiments reach 13) → NOISE
  - **Width-8 corrected p≈1.0** (100% of random 40K-trial experiments reach 13) → UNDERPERFORMS random
  - Width-8: expected max for 40K trials is ≥14 (87% probability); observed only 13 → BELOW random
  - Width-8: ZERO orderings with score ≥10 AND Bean pass — Bean-compatible orderings score poorly
  - Width-6: 3 Bean-passing orderings with score ≥10, best 13 (Vigenère Bean pass, but score from Beaufort)
- **Cross-width summary (widths 5-9, all at discriminating periods):**
  - Width-5: Bean-ELIMINATED (0/120 orderings)
  - Width-6: NOISE (corrected p=0.485)
  - Width-7: Bean-ELIMINATED (0/5,040 orderings)
  - Width-8: NOISE, underperforms random (corrected p≈1.0)
  - Width-9: NOISE, underperforms random (corrected p≈1.0, E-FRAC-12)
- **Verdict:** NOISE — ALL Bean-compatible widths 5-9 are eliminated for columnar + periodic substitution at discriminating periods. Both width-8 and width-9 score WORSE than random, suggesting columnar structure is ANTI-correlated with crib matching.
- **Runtime:** 97 seconds
- **Artifacts:** results/frac/e_frac_29_w6w8_crib_scoring.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_29_w6w8_crib_scoring.py`

### [2026-02-20T20:00Z] agent_frac — E-FRAC-28: SA Key Optimization on Bean-Passing Orderings (STRUCTURAL)
- **Hypothesis:** Can SA key optimization on top Bean-passing width-8/9 orderings produce readable English?
- **Method:** For top 30 Bean-passing orderings at each width, SA over key values (periods 3-13) to maximize quadgram fitness, with Bean as hard constraint. 3 restarts × 20K steps each.
- **Key findings:**
  - **ALL top results at period 12-13** — classic underdetermination (13 free key values, only ~2 crib constraints per residue)
  - **Crib scores 0-4/24** — SA abandoned crib matching entirely in favor of quadgram optimization
  - Width-8 best: -5.309/char (Beaufort p=13); width-9 best: -5.321/char (Vigenere p=13)
  - Width-8 and width-9 nearly identical (mean -5.525 vs -5.522)
  - Plaintexts are quadgram-optimized gibberish, not English (real English ≈ -4.3/char)
  - Example: "WEOROSTROVISTBUDDINDMANLANGANOTEECTUEBEIFELIONELEEBRANMYBY..."
- **Implications:**
  - Periodic key + columnar transposition does NOT produce readable English at ANY width or period
  - The -5.3 quadgram scores are underdetermination artifacts (too many key variables, too few constraints)
  - Width-8 and width-9 perform identically — no structural advantage for either width
  - The substitution cipher (if K4 has one) is NOT periodic with period ≤13 under columnar transposition
- **Verdict:** NOISE — SA improvement is an underdetermination artifact. Confirms E-FRAC-01 to 12.
- **Runtime:** 4,032 seconds
- **Artifacts:** results/frac/e_frac_28_w9_bean_key_sa.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_28_w9_bean_key_sa.py`

### [2026-02-20T18:30Z] agent_frac — E-FRAC-27: Bean-Compatible Width Profiling (STRUCTURAL)
- **Hypothesis:** Which columnar transposition widths are structurally compatible with the Bean constraint?
- **Widths tested:** 5-15, exhaustive for w≤8, 50K samples for w≥9
- **Key findings:**
  - **Bean-INCOMPATIBLE widths: 5 and 7** (exhaustive proof, ZERO orderings pass Bean equality)
  - **Bean-COMPATIBLE widths: 6, 8, 9, 10, 11, 12, 13, 14, 15** (all have non-zero pass rates)
  - Width-5: common CT letters exist but no ordering maps Bean positions to matching letters
  - Width-7: only 'R' is common but no ordering achieves simultaneous match
  - Width-6 has highest eq pass rate (11.67%), width-8 has highest full pass rate (2.49%)
  - Best Bean-passing quadgrams: w=9 (-6.342/char from 50K sample; -6.238 from E-FRAC-26 exhaustive)
- **Verdict:** STRUCTURAL — width-5 and width-7 are ELIMINATED by Bean constraint
- **Runtime:** 362 seconds
- **Artifacts:** results/frac/e_frac_27_bean_width_profile.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_27_bean_width_profile.py`

### [2026-02-20T17:00Z] agent_frac — E-FRAC-26: Exhaustive Width-9 Quadgram Search (STRUCTURAL)
- **Hypothesis:** Does width-9 show better Bean-quadgram compatibility than width-7?
- **Configs tested:** 5,443,200 (width-9: 362,880 orderings × 3 variants × 5 periods) + 75,600 (width-7 exhaustive) + 150,000 (random baseline)
- **Key findings:**
  - **Width-7: ZERO Bean-passing configs** (0/75,600) — structurally incompatible with Bean
  - **Width-9: 67,320 Bean-passing configs** (1.24%) — structurally compatible
  - Width-9 best quadgram (any): -6.079/char — exceeds all 10K random samples (p < 0.0001)
  - Width-9 best Bean-passing quadgram: -6.238/char — exceeds all random Bean results (-6.435)
  - Width-9 has 1 Bean pass in top-15 quadgram vs 0 for width-7
  - All plaintexts still gibberish (far from English -4.3/char)
- **Verdict:** STORE — width-9 is Bean-compatible with statistically significant quadgram improvement, but plaintext is not English
- **Runtime:** 365 seconds
- **Artifacts:** results/frac/e_frac_26_w9_quadgram.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_26_w9_quadgram.py`

### [2026-02-20T10:00Z] agent_frac — E-FRAC-25: Transposition Effect on Apparent Key Entropy (CRITICAL META-RESULT)
- **Hypothesis:** Does transposition explain the low Beaufort key entropy (p=0.003 from E-FRAC-16)?
- **Models tested:** 200K Monte Carlo for each:
  1. Null (uniform random key, no transposition): Beaufort at 0.33th percentile
  2. Random σ + periodic key (p=5-7): 0.33th percentile
  3. Columnar w7 + periodic: 0.40th percentile
  4. Columnar w9 + periodic: 0.30th percentile
  5. Running key (English) + random σ: 0.32th percentile
  6. **Running key (English) WITHOUT transposition: 21.65th percentile** ← BEST FIT
- **Key findings:**
  - **Transposition does NOT explain the low entropy.** Under ALL transposition models, the Beaufort key entropy remains at ~0.3th percentile. The transposition layer randomizes the displacement term, erasing any pattern.
  - **Running key (no transposition) is the ONLY model where the entropy is normal.** English text has inherently concentrated letter frequencies, matching the observed entropy level.
  - **BUT E-FRAC-24 showed the Beaufort key TEXT is incompatible with natural language** (KKK constraint). Entropy level is English-like, but specific letters are not.
  - **Resolution: The cipher may be Vigenère, not Beaufort.** The Vigenère key entropy (3.66 bits) is at 16.27th percentile — completely unremarkable, with no KKK constraint.
  - **E-FRAC-16's "Beaufort entropy signal" was likely a selection effect,** not evidence for Beaufort variant.
  - **Partial transposition gradient:** At 8/24 fixed positions → 5th percentile; at 12/24 fixed → 27.7th percentile.
- **Verdict:** The low Beaufort key entropy is NOT explained by transposition but IS consistent with running key without transposition. Since the letter distribution rules out natural-text running key under Beaufort, the simpler interpretation is that the cipher variant is Vigenère (where entropy is unremarkable) and the E-FRAC-16 finding was a false alarm.
- **Runtime:** 62 seconds
- **Artifacts:** results/frac/e_frac_25_transposition_entropy.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_25_transposition_entropy.py`

### [2026-02-20T09:00Z] agent_frac — E-FRAC-24: Running Key Language Profile Analysis
- **Hypothesis:** If the Beaufort key comes from a running key text, what can we infer about the source text?
- **Key findings:**
  - **KKK at positions 30-32 is effectively impossible in any natural language:**
    - P(KKK anywhere in 24-char English text) = 0.00% (0/100,000 MC samples)
    - Even DDD (under KRYPTOS alphabet) has P < 0.17%
  - **Language compatibility (Beaufort key as text):**
    - Standard alphabet: 0.0th percentile for English, German, French, AND Latin
    - KRYPTOS alphabet: 0.4th percentile for English, 0.1% for French, 0.0% for German/Latin
    - Under NO alphabet mapping does the key text resemble natural language
  - **Transposition resolves the KKK constraint:**
    - Under transposition + periodic key, P(triple match at 30-32) ≈ 0.15% (matching uniform expectation of 0.148%)
    - The apparent KKK is a ~1-in-676 event — mildly unusual but not dramatic
    - Combined with overall low entropy (p=0.003 from E-FRAC-16) → ~0.3% combined
  - **Digram analysis:** Only repeated digram is KK (standard) / DD (KRYPTOS). No significant n-gram patterns.
- **Implications:**
  - **Without transposition**: running key from natural text is RULED OUT for Beaufort
  - **With transposition**: KKK pattern is explained as chance coincidence of key + displacement values
  - This is weak evidence FOR the existence of a transposition layer
  - The Beaufort key structure (low entropy, KKK run) may be a CONSEQUENCE of transposition rather than a property of the key generation method
- **Verdict:** RUNNING_KEY_UNLIKELY_WITHOUT_TRANSPOSITION — natural-language running key is incompatible with Beaufort under direct correspondence; transposition resolves the constraint
- **Runtime:** 14 seconds
- **Artifacts:** results/frac/e_frac_24_running_key_profile.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_24_running_key_profile.py`

### [2026-02-20T08:00Z] agent_frac — E-FRAC-23: Beaufort Key Reconstruction — Structured Non-Periodic Models
- **Hypothesis:** Can the 24 known Beaufort key values be generated by any structured non-periodic key method?
- **Models tested:** 8 categories:
  1. Progressive keyed (keyword + constant shift per cycle, L=2..15, delta=0..25): 0 consistent
  2. Double-period (a[i mod L1] + b[i mod L2], L1=2..10, L2=3..13): 0 consistent (random baseline: 21.2)
  3. Linear recurrence (order 2-3 within consecutive blocks): none found
  4. Keyword + positional modifier (7 functions × L=2..12): 0 consistent
  5. CT-derived schedules (lag, forward, combo, permuted): best 6/24 = noise
  6. Split-offset model (different key alignment for ENE vs BC): 0 consistent
  7. Key difference pattern analysis: no periodicity, no constant 2nd difference
  8. Key values through alternative alphabets (standard, KRYPTOS, reversed): no readable text
- **Key findings:**
  - ALL structured non-periodic key generation models ELIMINATED
  - **ANTI-SIGNAL**: Beaufort key has 0 consistent double-period decompositions vs 21.2 for random — key is MORE constrained than random
  - Even/odd bias in key values (16/24 even, p=0.077): not significant
  - 22 equal-value position pairs found; distances 1-2 (adjacent) and 38-45 (ENE-to-BC) are most common
  - Bean equality distance (38) has factors [1, 2, 19, 38] — compatible only with periods that divide 38
  - KKK run at pos 30-32 is SPECIFIC TO BEAUFORT (Vig gives C,K,A; VB gives Y,Q,A) — further evidence for Beaufort variant
- **Implications:**
  - The Beaufort key's low entropy (p=0.003, E-FRAC-16) is NOT explained by any tested structured generation method
  - If the key is from a running key text, that text contains "KKK" — extremely unlikely for any natural language
  - Either: (a) unknown text with unusual distribution, (b) transposition artifact, or (c) coincidence (1-in-333)
- **Verdict:** NO_STRUCTURED_KEY — comprehensive elimination of all tested non-periodic key generation methods
- **Runtime:** 26 seconds
- **Artifacts:** results/frac/e_frac_23_beaufort_key_reconstruction.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_23_beaufort_key_reconstruction.py`

### [2026-02-20T05:20Z] agent_frac — E-FRAC-22: Null Cipher / Interval Reading Analysis
- **Hypothesis:** Does K4 contain a hidden message readable by decimation (every Nth character)?
- **Tests:** 300+ decimation configs (N=2..25, all offsets), Caesar-shifted decimations, grid-based readings, simple transforms
- **Key findings:**
  - K4 has FEWER high-IC decimations than random (6.6th percentile) — K4 is MORE uniform than expected
  - Most "interesting" fragments are at very short lengths (4-14 chars) where word matches are expected by chance
  - Width-9 column 4 with Caesar +8 gives "CATSRIEBLOK" (fcorr=0.567) — recognizable fragments but probably noise given ~5000 tests
  - Reverse CT contains "OUR" — expected by chance (3/26³ ≈ 0.017% per trigram, 95 possible positions)
  - Monte Carlo: K4 is less structured than random at the decimation level, not more
- **Verdict:** NO_NULL_CIPHER — no evidence of hidden interval-readable message. K4 is unusually uniform.
- **Runtime:** 5 seconds
- **Artifacts:** results/frac/e_frac_22_null_cipher_intervals.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_22_null_cipher_intervals.py`

### [2026-02-20T05:10Z] agent_frac — E-FRAC-21: Structural Proofs — Complete Fractionation Elimination
- **Hypothesis:** Are any fractionation families still viable? (Closes Tier 3/4 items assigned to FRAC)
- **Results: ALL 10 fractionation families eliminated by structural proofs:**
  - ADFGVX: **Parity impossible** — output length always 2×N (even), K4=97 (odd)
  - ADFGX: **Parity impossible** — same argument
  - Straddling checkerboard: **Output incompatible** — produces digits (0-9), K4 has 26 letters
  - Bifid 5×5: **Alphabet impossible** — requires 25-letter alphabet, K4 CT has 26 distinct letters
  - Bifid 6×6: **IC-incompatible** — produces IC 0.059-0.069, K4 at 0.036 (0th percentile)
  - Trifid: **Algebraically impossible** — prior proof at all periods
  - VIC cipher: **Component impossible** — contains straddling checkerboard (eliminated)
  - Playfair: **Parity + alphabet** — needs even length + 25-letter alphabet
  - Two-Square: **Parity + alphabet** — same
  - Four-Square: **Parity + alphabet** — same
- **Critical note:** These proofs hold WITH OR WITHOUT a transposition layer. IC is permutation-invariant. Parity and alphabet constraints are preserved by transposition.
- **Verdict:** ALL_FRACTIONATION_STRUCTURALLY_ELIMINATED
- **Runtime:** 0 seconds (pure proofs)
- **Artifacts:** results/frac/e_frac_21_fractionation_proofs.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_21_fractionation_structural_proofs.py`

### [2026-02-20T04:30Z] agent_frac — E-FRAC-20: Residue Conflict Map — Which Positions Block Full Score?
- **Hypothesis:** Which specific crib positions cause periodic scoring to fail? Where must transposition act?
- **Key findings:**
  - Best periodic score at discriminating periods (2-7): **8/24** across all Vig/Beau/VB variants
  - Best config: Vigenere p=5 at 95.2nd percentile of random (z=1.27) — NOT significant
  - BC positions conflict more than ENE (82% vs 54% at Vig p=5; 91% vs 46% at Vig p=7)
  - Every residue class has multiple conflicts — no "clean" residues at any discriminating period
  - 16/24 crib positions are in conflict for any top config — the cipher is deeply incompatible with periodicity
  - If transposition exists, it must move MANY positions (16+/24), not just a few
- **Verdict:** K4_CONSISTENT_WITH_RANDOM — periodic model scores consistent with random CT (z=1.27)
- **Runtime:** 1 second
- **Artifacts:** results/frac/e_frac_20_residue_conflict_map.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_20_residue_conflict_map.py`

### [2026-02-20T04:15Z] agent_frac — E-FRAC-19: Pre-ENE Segment Deep Analysis (RQ-7)
- **Hypothesis:** Is the pre-ENE segment (pos 0-20, IC=0.067) encrypted differently from the rest of K4?
- **Key findings:**
  - Pre-ENE IC = 0.067 is at **97.6th percentile of random 21-char text** (z=2.13) — high but...
  - It ranks **#10 out of 77** contiguous 21-char segments of K4 — 13 segments have IC ≥ 0.067
  - Highest IC segments are pos 23-43 (IC=0.086), NOT pre-ENE — these overlap with the QSS-rich region
  - **Bonferroni-corrected p-value = 1.0** — completely insignificant after multiple testing
  - Pre-ENE letter frequencies have near-zero correlation with English (r=0.018) — NOT English-like
  - Pre-ENE has 4 O's and 4 B's out of 21 chars — the "high IC" is just letter repetition in a short sample
  - Pre-ENE as a key for positions 21-96: 2/24 matches (random baseline)
  - Using pre-ENE as a repeating key for Vig/Beaufort: 2/24 matches
  - Gap segment (pos 34-62): IC at 53.2nd percentile of random — completely unremarkable
  - All segments consistent with random text after length calibration
- **Verdict:** MARGINALLY_INTERESTING — high IC does NOT survive multiple testing. The "English-like pre-ENE" claim from prior work is unfounded.
- **Runtime:** 18 seconds
- **Artifacts:** results/frac/e_frac_19_pre_ene_analysis.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_19_pre_ene_analysis.py`

### [2026-02-20T04:00Z] agent_frac — E-FRAC-18: Crib Position Sensitivity Analysis
- **Hypothesis:** Are any crib positions off by ±1 or ±2? (Meta-risk: if cribs are wrong, all eliminations are invalid)
- **Tests:** Block shifts (ENE ±2, BC ±2), individual position shifts, drop-one analysis
- **Key findings:**
  - Baseline best: 16/24 at period 15 (underdetermination territory — not meaningful)
  - Best shifted: 17/24 (ENE-1 BC-1, period 15) — +1 above baseline, noise
  - At discriminating periods (2-7): NO shift produces improvement above baseline
  - Drop-one analysis: nearly all positions give 16/23 when dropped — no position stands out
  - Self-encrypting positions confirmed: pos 32 (S→S) and pos 73 (K→K) are correct
  - Key entropy at shifted positions: no shift produces notably lower entropy
- **Verdict:** MARGINAL_IMPROVEMENT — crib positions are correct. No shift at any discriminating period improves the score. The published positions (21-33 for ENE, 63-73 for BC) are validated.
- **Runtime:** 0.1 seconds
- **Artifacts:** results/frac/e_frac_18_crib_sensitivity.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_18_crib_sensitivity.py`

### [2026-02-20T00:10Z] agent_frac — E-FRAC-17: Running Key Search Against Reference Texts
- **Hypothesis:** Is K4's key derived from a known text (running key) under Beaufort or Vigenere?
- **Texts searched:** Carter Gutenberg (117K chars), Carter Vol1 extract (288K chars), CIA Charter, JFK Berlin speech, NSA Act 1947, Reagan Berlin speech, UDHR, K1-K3 combined plaintext
- **Best matches:** 7/24 (Carter texts, both Beaufort and Vigenere) — multiple offsets
- **Random baseline:** Expected best for 10K offsets = 6.1/24, for 100K+ offsets ≈ 6.5-7/24
- **Verdict:** NOISE — 7/24 matches is exactly at random expectation for texts of this length. No reference text is the running key source under direct correspondence.
- **Runtime:** ~180 seconds (terminated early; sufficient data)
- **Artifacts:** results/frac/e_frac_17_beaufort_running_key.json (partial)
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_17_beaufort_running_key.py`

### [2026-02-19T05:55Z] agent_frac — E-FRAC-16: Key Value Distribution Analysis
- **Hypothesis:** Does the Beaufort or Vigenere key distribution show significant structure at crib positions?
- **Key findings:**
  - Beaufort key entropy at **0.3rd percentile** of random (p=0.003, p_adj≈0.018 after correction). **HIGHLY CONCENTRATED.**
  - Beaufort key value K(=10) at 5/24 positions (p=0.05): positions 28, 30, 31, 32, 70
  - Three consecutive K's at positions 30-31-32 (p=0.03)
  - Self-encrypting position 32 (S) has Beaufort key = K (first letter of KRYPTOS)
  - Vigenere key entropy at 16.1th percentile — unremarkable
- **Verdict:** The Beaufort key is significantly more concentrated than random. Weak evidence for Beaufort as the cipher variant.
- **Caveat:** Assumes direct correspondence. If transposition exists, this finding may not hold.
- **Runtime:** 15 seconds
- **Artifacts:** results/frac/e_frac_16_key_distribution.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_16_key_distribution.py`
- **Full meta-analysis:** `reports/frac_statistical_meta_analysis.md`

### [2026-02-19T05:25Z] agent_frac — E-FRAC-15: Functional Key Models (Linear, Quadratic, Exponential, Recurrence)
- **Hypothesis:** Is K4's key a simple mathematical function of position?
- **Models tested:** 676 linear (k=ai+b), 17,576 quadratic (k=ai²+bi+c), 600 exponential (k=a·b^i), 676 Fibonacci, 43,264 generalized recurrence — all × Vig/Beau/VB
- **Best scores:** Linear 7/24 (k=4i+20 Vig, ~3σ above best-of-676 random baseline 4.9±0.7), Quadratic 8/24, Exponential <6, Fibonacci <6, Gen. recurrence <8
- **None produce readable plaintext.** Random 3-letter words ("WAY", "ALL") appear by chance.
- **Verdict:** NOISE — the key is NOT a polynomial, exponential, or recurrence function of position
- **Runtime:** 6 seconds
- **Artifacts:** results/frac/e_frac_15_linear_key.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_15_linear_key.py`

### [2026-02-19T04:50Z] agent_frac — E-FRAC-14: Autocorrelation Deep Dive & Statistical Fingerprint (CRITICAL META-RESULT)
- **Hypothesis:** Is K4's lag-7 autocorrelation significant? What other statistical signals exist?
- **Key findings:**
  - Lag-7 has 9 matches (p=0.0077 uncorrected) but does NOT survive Bonferroni correction (48 lags tested, threshold p<0.001)
  - ZERO lags significant after Bonferroni
  - DFT: ZERO peaks exceed 95th percentile of random max (k=9 magnitude=162, threshold=192)
  - Lag-7 positions: [0, 7, 12, 15, 32, 45, 65, 76, 86]; 3 involve cribs
  - 10 repeated bigrams (z=+1.73 vs random, not significant); 0 repeated trigrams
  - First-order differences are UNIFORM (chi2=25.3, p>0.05)
  - Best linear key fit: k=4i+20 matches 7/24 (~3σ above best-of-676 baseline)
  - Best quadratic fit: 8/24 (same as linear + noise floor effect)
  - Beaufort key: positions 29-31 all have value 10 (K) — noteworthy but not conclusive
  - Almost any columnar width (5-10) reduces lag-7; not specific to width-9
- **Verdict:** K4 is statistically consistent with RANDOM TEXT. No significant autocorrelation, DFT, or ngram signals after proper multiple-testing correction.
- **Runtime:** 506 seconds
- **Artifacts:** results/frac/e_frac_14_autocorrelation.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_14_autocorrelation.py`

### [2026-02-19T04:30Z] agent_frac — E-FRAC-13: IC Statistical Analysis (CRITICAL META-RESULT)
- **Hypothesis:** Is K4's below-random IC (0.036) statistically significant? Does it constrain the cipher family?
- **Key findings:**
  - K4 IC = 0.036 is at 21.5th percentile of random text (z=-0.84). NOT significant.
  - Pre-ENE segment (pos 0-20) IC = 0.067 at 97.6th percentile — marginally interesting but not significant after multiple testing (5 segments tested, Bonferroni p≈0.12)
  - Periodic Vigenere at period 5-7: K4 at 2-4th percentile (marginally consistent)
  - Running key / long-period polyalphabetic: K4 at 22nd percentile (perfectly consistent)
  - **Bifid 6×6 is IC-INCOMPATIBLE**: mean IC 0.059-0.069 at ALL periods on English text, K4 at 0th percentile
  - Bifid 5×5: mean IC 0.045, K4 at ~1st percentile (also structurally impossible — 26 letters)
  - K4 letter frequencies NOT different from uniform (chi2=19.1, p>0.05)
  - Transposition preserves IC exactly (verified 10K samples)
- **Verdict:** IC is NOT diagnostic — does not constrain cipher family. Bifid 6×6 is IC-eliminated.
- **Runtime:** 77 seconds
- **Artifacts:** results/frac/e_frac_13_ic_analysis.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_13_ic_analysis.py`

### [2026-02-19T03:40Z] agent_frac — E-FRAC-12: Width-9 Strict Re-evaluation (No Bimodal, Periods 2-7)
- **Hypothesis:** Does width-9 columnar show signal at discriminating periods when bimodal filter is dropped?
- **Configs tested:** 362,880 orderings × 3 variants × 2 models × periods 2-7 (exhaustive)
- **Best score:** 14/24 (20 orderings, all at period 7, ALL fail Bean)
- **Best Bean-passing:** 13/24 (one ordering: [2,0,6,4,1,3,7,5,8], p7 Beaufort model B)
- **Random baseline (N=100K):** max=15/24, mean=9.38, 99.9th=12
- **Distribution comparison:** Width-9 score distribution matches random at ALL levels (ratios 0.97x-1.38x). No structural enhancement.
- **Verdict:** NOISE — width-9 columnar is indistinguishable from random at discriminating periods, even without the bimodal filter.
- **Runtime:** 934 seconds
- **Artifacts:** results/frac/e_frac_12_w9_strict_reeval.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_12_w9_strict_reeval.py`

### [2026-02-19T03:15Z] agent_frac — E-FRAC-11: Bimodal Fingerprint Validity Analysis (CRITICAL)
- **Hypothesis:** Is the bimodal fingerprint a real cryptanalytic constraint or a statistical artifact?
- **Result:** **ARTIFACT.** The "bimodal" pattern (ENE matches better than BC) is caused by crib position ordering in the scoring algorithm. Position 21 matches 100% of the time (first assignment), declining monotonically to position 73 (11%). No bimodal structure — just a smooth gradient.
- **Key finding:** ENE/BC ratio = 3.5x under RANDOM permutations with no transposition. The bimodal pre-filter is filtering out valid candidates based on an unfounded assumption.
- **Additional:** Shifted BC cribs (±1, ±2) show slightly different scores but nothing conclusive about crib indexing errors.
- **Runtime:** 188 seconds
- **Artifacts:** results/frac/e_frac_11_bimodal_validity.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_11_bimodal_validity.py`

### [2026-02-19T03:00Z] agent_frac — E-FRAC-10: Strip Manipulation + Periodic Substitution
- **Hypothesis:** Strip manipulation (bimodal-compatible) + periodic substitution at discriminating periods (2-7)
- **Configs tested:** ~1.8M strip configs across widths 5-20, filtered by bimodal + Bean
- **Best score:** 10/24 (strip width 11, period 7, Beaufort model A)
- **Noise floor:** Random bimodal+Bean baseline: max 12/24, mean 8.3/24
- **Verdict:** NOISE — best strip score within random baseline
- **Runtime:** 60 seconds
- **Artifacts:** results/frac/e_frac_10_strip_bimodal.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_10_strip_bimodal.py`

### [2026-02-19T02:50Z] agent_frac — E-FRAC-09: Structural Characterization of Bimodal-Compatible Permutations
- **Hypothesis:** What kinds of permutations satisfy the bimodal fingerprint? (Guides TRANS/BESPOKE search)
- **Key findings:**
  - 0/1M random permutations pass bimodal — extremely restrictive
  - Strip manipulation passes at 2.0% rate (strip width 11 best at 5.5%)
  - Block swaps pass at 10.5% (swapping blocks in BC region)
  - Local swaps (50 swaps, dist≤5) pass at 4.8%
  - Rail fence, route ciphers, columnar: ALL fail bimodal
- **Verdict:** If bimodal is valid (now questionable per E-FRAC-11), only "patch-based" transpositions are compatible
- **Runtime:** 151 seconds
- **Artifacts:** results/frac/e_frac_09_bimodal_structure.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_09_bimodal_structure.py`

### [2026-02-19T02:45Z] agent_frac — E-FRAC-08: Bimodal Fingerprint Across ALL Widths (CRITICAL)
- **Hypothesis:** H6/H7 — Is ANY columnar transposition width (2-20) compatible with the bimodal fingerprint?
- **Result:** **ZERO widths have ANY compatible columnar orderings.** Exhaustive for w≤10, 100K samples for w>10.
- **Widths tested exhaustively (0 pass):** w=2 (2), w=3 (6), w=4 (24), w=5 (120), w=6 (720), w=7 (5,040), w=8 (40,320), w=9 (362,880), w=10 (3,628,800)
- **Widths sampled (0/100K pass):** w=11 through w=20
- **Implication:** **Columnar transposition at ANY width is structurally incompatible with the bimodal fingerprint.** This is a fundamental result: either (1) the bimodal fingerprint assumption is wrong, or (2) the transposition is not columnar at any width, or (3) the transposition doesn't preserve position-displacement relationships in the expected way.
- **Key distinction:** This eliminates standard columnar transposition. Non-columnar transpositions (route ciphers, grilles, strip methods) remain open.
- **Runtime:** 44 seconds
- **Artifacts:** results/frac/e_frac_08_bimodal_multiwidth.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_08_bimodal_multiwidth.py`

### [2026-02-19T02:15Z] agent_frac — E-FRAC-07: Width-9 Bimodal Fingerprint (CRITICAL)
- **Hypothesis:** H6 — Is width-9 columnar transposition compatible with the bimodal fingerprint constraint?
- **Result:** **ZERO orderings pass at ANY tolerance level** (tested up to ENE≤10, BC≤6)
- **Root cause:** Positions 22-30 span all 9 columns of the width-9 grid. After columnar transposition, CT position 22 always maps to row 0 of some column (PT position 0-8), giving minimum displacement |perm[22]-22| = 14, far exceeding the ±5 tolerance.
- **Implication:** **Width-9 columnar transposition is structurally incompatible with the bimodal fingerprint.** If the bimodal fingerprint is correct (a separate question), width-9 columnar is eliminated as a candidate.
- **Note:** This does NOT eliminate non-columnar width-9 transpositions (e.g., strip manipulation on a 9-wide grid). It specifically eliminates the columnar reading order model.
- **Runtime:** 35 seconds
- **Artifacts:** results/frac/e_frac_07_bimodal.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_07_bimodal_w9.py`

### [2026-02-19T01:50Z] agent_frac — E-FRAC-06: Width-11 and Width-13 Structural Analysis
- **Hypothesis:** H6 — Width-11 (97=11×8+9) and width-13 (97=13×7+6) as alternative transposition widths
- **Configs tested:** 50K samples per width × 6 periods × 3 variants × 2 models = ~1.8M per width + 50K random baseline
- **Best score (w11):** 14/24 (period 7, Beaufort, model B)
- **Best score (w13):** 14/24 (period 7, Vigenère, model A)
- **Random baseline:** 14/24 — identical to both widths
- **Strict passes:** 0 for all three (w11, w13, random)
- **Structural:** Both w11 and w13 reduce lag-7 in 100% of orderings (same as random — not width-specific)
- **Verdict:** NOISE — width-11 and width-13 produce identical results to random permutations. Score distributions match within sampling error.
- **Runtime:** 175 seconds
- **Artifacts:** results/frac/e_frac_06_w11w13.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_06_w11w13_structural.py`

### [2026-02-19T01:25Z] agent_frac — E-FRAC-05: Width-9 + Column-Dependent Mixed Alphabets
- **Hypothesis:** H6 — Width-9 columnar transposition with arbitrary column-dependent substitution alphabets (mixed alphabets, not just shifted)
- **Configs tested:** 362,880 orderings, tested under PT-column and CT-column grouping models, + 50,000 random permutation baseline
- **Key findings:**
  - PT-column model: **0/362,880 orderings pass** (minimum 3 bijection conflicts). This is a hard mathematical elimination.
  - CT-column model: 75,071/362,880 (20.7%) pass bijection check. Random baseline: 12.0%. Ratio: 1.73x (not compelling).
  - CT-col + Bean: only 3,293 orderings pass both constraints
  - All passing orderings have DOF=215 (only 19/234 alphabet entries determined = 8.1%) — massively underdetermined
- **Verdict:** PT-column model ELIMINATED (hard math). CT-column model is NOISE (underdetermined, barely above random baseline).
- **Runtime:** 14 seconds + 1 second (baseline)
- **Artifacts:** results/frac/e_frac_05_mixed_alphabets.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_05_mixed_alphabets.py`

### [2026-02-19T00:55Z] agent_frac — E-FRAC-04: Width-9 × Width-7 Compound Transposition
- **Hypothesis:** H12 — Compound transposition (width-9 columnar followed by width-7 columnar, both directions) + periodic substitution
- **Configs tested:** 50,500,800 (5,010 width-9 samples × 5,040 width-7 × 2 compositions)
- **Best score:** 0/24 above threshold (strict periodic check at periods 2-7)
- **Noise floor:** N/A — zero results above strict-pass threshold 12/24
- **Verdict:** ELIMINATED — compound w9×w7 transposition with periodic substitution shows zero signal at discriminating periods (2-7)
- **Runtime:** 384 seconds
- **Artifacts:** results/frac/e_frac_04_compound_w9w7.json
- **Repro:** `PYTHONPATH=src python3 -u jobs/pending/e_frac_04_compound_w9w7.py --workers 3 --n-w9-samples 5000`

### [2026-02-19T00:40Z] agent_frac — E-FRAC-03: Width-9 Non-Columnar Reading Orders
- **Hypothesis:** H7 — Non-standard reading orders on 9-wide grid (serpentine, diagonal, spiral, column-major, knight-move) as transposition mechanism + periodic substitution
- **Configs tested:** 26 reading orders × 6 periods × 3 variants × 2 models = ~936
- **Best score:** 16/24 (row_major, period 13, Beaufort, model A)
- **Noise floor:** Identity permutation scores 16/24 at period 13 — ALL best scores are at period 13-14
- **Verdict:** ELIMINATED — all high scores are underdetermination artifacts at high periods. No signal at discriminating periods (≤7).
- **Runtime:** 0.1 seconds
- **Artifacts:** results/frac/e_frac_03_w9_reading_orders.json
- **Repro:** `PYTHONPATH=src python3 -u jobs/pending/e_frac_03_w9_reading_orders.py`

### [2026-02-19T00:25Z] agent_frac — E-FRAC-02: Width-9 Columnar + Non-Periodic Substitution
- **Hypothesis:** H6 — Width-9 columnar transposition + non-periodic substitution models (progressive key, CT-autokey, PT-autokey, column-progressive)
- **Configs tested:** 13,464 Bean-passing (from 362,880 orderings × 3 variants)
- **Best score:** Progressive: 8/24, CT-autokey: 6/24, PT-autokey: 7/24, Column-progressive: 20/24
- **Noise floor:** Column-progressive noise floor = 17.7/24 (Monte Carlo, N=10,000 random permutations, max observed 21/24). Progressive noise floor ≈ 5-6/24. All observed results within noise.
- **Verdict:** ELIMINATED — column-progressive 20/24 is a confirmed underdetermination artifact (random permutations score 17-21/24). Progressive, CT-autokey, and PT-autokey all within noise.
- **Runtime:** 31 seconds + 29 seconds (baseline)
- **Artifacts:** results/frac/e_frac_02_w9_nonperiodic.json
- **Repro:** `PYTHONPATH=src python3 -u jobs/pending/e_frac_02_w9_nonperiodic.py --workers 3`
- **Baseline repro:** `PYTHONPATH=src python3 -u scripts/e_frac_02b_colprog_baseline.py`

### [2026-02-19T00:00Z] agent_frac — E-FRAC-01: Width-9 Grid Structural Analysis
- **Hypothesis:** H6/H7 — Width-9 grid structural properties as diagnostic for the transposition hypothesis
- **Configs tested:** 362,880 orderings (IC, lag analysis, Bean constraints)
- **Key findings:**
  - 99.2% of width-9 orderings REDUCE lag-7 in un-transposed text → width-9 transposition naturally CREATES lag-7 correlations (consistent with hypothesis)
  - Bean equality passes: 15,120/362,880 (4.17%, above 3.85% random expectation)
  - Bean full passes (eq + all 21 ineq): 4,860/362,880 (1.34%) for Vigenère
  - CT IC = 0.0361 (below random 0.0385), invariant under permutation
  - Lag-7 raw: 9 matches, z=3.04 (significant)
- **Verdict:** STRUCTURAL ANALYSIS — width-9 explains the lag-7 signal, but no scoring-based signal found
- **Runtime:** 67 seconds
- **Artifacts:** results/frac/e_frac_01_w9_structural.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_01_w9_structural.py`
