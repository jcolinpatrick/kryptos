# K4 Agent Team — Progress Tracker
Last updated: 2026-02-21T02:00:00Z by agent_frac

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

### [2026-02-21T01:00Z] agent_frac — CRIB ORACLE IS INSUFFICIENT FOR ARBITRARY PERMUTATION SEARCH (E-FRAC-33)
**ALL AGENTS READ THIS — especially JTS.**

The 24-crib scoring oracle is **fundamentally insufficient** to identify the correct transposition from arbitrary (unstructured) permutations:

1. **Landscape is smooth** (parent-child correlation ~0.93 at ALL periods 2-7)
2. **Hill-climbing at period 5 reaches 24/24** in 30% of trials (50 climbs × 5K steps). Random max is only 12/24.
3. **Hill-climbing at "best period" reaches 24/24** in 50% of trials — mostly at period 7 (87%) and period 6 (13%).
4. **These are FALSE POSITIVES** — the 97! permutation space is so large that accidental perfect solutions exist at every discriminating period.
5. Even **period 2** (the most constrained) likely has false 24/24 solutions if searched long enough.

**Implication for JTS:** SA/hill-climbing on crib score alone WILL converge to false positives at ANY period. The search MUST combine crib scoring with **plaintext quality metrics** (quadgram fitness, IC, English word detection) to distinguish real solutions from false positives.

**Implication for TRANS:** Structured transposition families (columnar, rail fence, etc.) don't have this problem because their search space is small enough that false 24/24 solutions don't exist (per E-FRAC-12/29/30/32). The underdetermination only occurs in the full 97! space.

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_33_fitness_landscape.py && PYTHONPATH=src python3 -u scripts/e_frac_33b_perperiod_fix.py`

### [2026-02-20T12:00Z] agent_frac — MULTI-OBJECTIVE ORACLE DESIGNED FOR JTS (E-FRAC-34)
**ALL AGENTS READ THIS — especially JTS.**

E-FRAC-34 characterizes false 24/24 solutions and provides **concrete multi-objective thresholds** for distinguishing real solutions from false positives:

**False positive characterization (90 false 24/24 solutions collected):**
- Quadgram/char: mean=-5.96, best=-5.77 (false positives produce gibberish)
- IC: mean=0.038 (same as random — IC does NOT discriminate)
- Word coverage (≥4 chars): mean=29% (vs 99% for real English)
- Periods: 34 at p7, 35 at p5, 16 at p2, 5 at p6 (p2 is hardest to fake)

**Benchmarks:**
- Real English: quadgram=-4.84/char, IC=0.087, word coverage=99.7%
- Random text: quadgram=-6.43/char, IC=0.038, word coverage=6%
- K4 CT: quadgram=-6.38/char, IC=0.036

**The GAP: 0.93/char between best false positive (-5.77) and English (-4.84). Quadgram alone discriminates.**

**RECOMMENDED THRESHOLDS for JTS:**
1. Crib score = 24/24
2. Bean constraint PASS
3. **Quadgram/char > -5.0** (all false positives ≤ -5.77, English ≈ -4.84)
4. IC > 0.055 (English ≈ 0.067)
5. At least one word ≥6 chars in plaintext

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_34_multi_objective_oracle.py`
**Artifacts:** results/frac/e_frac_34_multi_objective_oracle.json

### [2026-02-20T23:00Z] agent_frac — QUADGRAM THRESHOLD TOO WEAK FOR SA-OPTIMIZED SOLUTIONS (E-FRAC-40/41)
**ALL AGENTS READ THIS — especially JTS. UPDATES E-FRAC-34 ORACLE.**

The -5.0/char quadgram threshold from E-FRAC-34 is **ONLY valid for crib-optimized transpositions** (where SA maximizes crib score, not quadgrams). When SA optimizes the transposition for QUADGRAM FITNESS (while holding 24 cribs fixed via bipartite matching), it routinely achieves **-4.27 to -4.55/char** — well above the -5.0 threshold.

**Key evidence (E-FRAC-40/40b):**
- Carter running key + SA quadgram optimization: best=-4.27/char, mean=-4.55, ALL 200 offsets above -5.0
- **RANDOM key + SA quadgram optimization: best=-4.40/char, mean=-4.52** — nearly identical to Carter
- English-freq random key + SA: best=-4.39/char — also nearly identical
- **Carter is NOT special** — the "signal" is an SA optimization artifact

**Word-level discrimination refined (E-FRAC-41 + E-FRAC-42):**
- **Raw word count ≥6 chars is WEAK:** SA gibberish 3-17 words, English 5-20 words (overlap exists due to crib words)
- **Non-crib words ≥7 chars is the BEST automated metric:** Cohen's d = 1.14 (LARGE effect)
  - English: mean 6.3 [1-14], SA gibberish: mean 3.0 [0-11]
  - Excluding crib words improves d from 0.81 → 1.14
- **BUT no perfect separation exists** — SA produces real English words (DISTINGUISHED, LABORATORY, UNIFORMED) via quadgram optimization
- Random/English-freq random: 0-2 words (clear separation from both English and SA)

**Updated JTS thresholds (SUPERSEDES E-FRAC-34, refined by E-FRAC-42):**
1. Crib score = 24/24
2. Bean constraint PASS
3. ~~Quadgram > -5.0/char~~ → Quadgram > -4.84/char (actual English benchmark; -5.0 is too easy when SA optimizes for quadgrams)
4. IC > 0.055
5. **Non-crib words ≥7 chars: at least 3** (exclude NORTHEAST, BERLIN, CLOCK, EAST, NORTH, STERN, ASTER, etc. — 16 crib-derived words)
6. **Semantic coherence** (human evaluation for final candidates — THE ultimate discriminator; no automated metric achieves perfect separation)

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_40_carter_quadgram_screen.py && PYTHONPATH=src python3 -u scripts/e_frac_40b_random_key_control.py && PYTHONPATH=src python3 -u scripts/e_frac_41_word_discriminator.py`

### [2026-02-20T18:00Z] agent_frac — BEAN IMPOSSIBILITY: ALL DISCRIMINATING PERIODS ELIMINATED (E-FRAC-35)
**ALL AGENTS READ THIS — especially JTS and TRANS. This is a PROOF, not an empirical finding.**

**Theorem:** For ANY transposition σ (including identity), periodic substitution at periods 2-12 (and 14, 15, 17, 18, 21, 22, 25) violates at least one Bean inequality constraint. This holds for ALL 97! permutations.

**Two elimination mechanisms:**
1. **Type 1 (same-residue inequality):** If Bean inequality pair (a,b) has a ≡ b (mod p), then k[a] = k[b] under periodic keying, violating k[a] ≠ k[b]. Eliminates periods: {2,3,4,5,6,7,9,10,14,15,17,21,25}.
2. **Type 2 (equality-inequality conflict):** Bean equality forces key[27%p] = key[65%p], but if some Bean inequality pair (a,b) maps to the same residue pair, the equality and inequality directly conflict. Eliminates periods: {11,12,18,22} additionally.

**Combined: 17 of 25 periods (2-26) are ELIMINATED. Only 8 survive: {8, 13, 16, 19, 20, 23, 24, 26}.**

**Critical implications:**
- ALL discriminating periods (2-7) are Bean-impossible for transposition + periodic key
- Period 8 is the FIRST surviving period (3 cribs per key variable)
- Only 3 surviving periods have ≥1.5 cribs/var: {8, 13, 16}
- The 90 false 24/24 solutions from E-FRAC-33/34 were ALL at Bean-eliminated periods
- IF K4 uses periodic keying + transposition, the period MUST be ≥8
- This strongly increases the likelihood of a NON-PERIODIC key model

**For JTS:** Target period 8 as primary search period. Do NOT search periods 2-7 with periodic keying.
**For TRANS:** All prior tests at periods 2-7 were in Bean-impossible territory. This doesn't invalidate eliminations but provides a cleaner structural explanation.

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_35_bean_period_impossibility.py`
**Artifacts:** results/frac/e_frac_35_bean_period_impossibility.json

## Active Tasks
| Agent | Task | Started | Status |
|-------|------|---------|--------|

## FRAC Agent Mandate — 43 experiments (E-FRAC-01 through E-FRAC-43)

**Original mandate (E-FRAC-01 to 25): COMPLETE. ZERO positive findings survived.**
**Extended mandate (E-FRAC-26-31): Bean profiling + crib scoring. ALL columnar widths 5-15 ELIMINATED.**
**Final sweep (E-FRAC-32): Simple transposition families (cyclic, affine, rail fence, swap, reversal) ALL ELIMINATED.**
**Meta-analysis (E-FRAC-33): Fitness landscape smooth, but crib oracle INSUFFICIENT — false 24/24 solutions exist at ALL periods.**
**Oracle design (E-FRAC-34): Multi-objective thresholds for JTS — quadgram gap of 0.93/char discriminates false positives.**
**Bean impossibility (E-FRAC-35): ALL discriminating periods (2-7) + periods up to 12 are Bean-impossible for transposition + periodic key. PROOF.**
**Bean-surviving periods (E-FRAC-36): Period-8 and period-13 hill-climbing with Bean HARD constraint. 175 false 24/24 solutions ALL have quadgram < -5.0. Multi-objective oracle discriminates at Bean-surviving periods too.**
**Autokey + arbitrary transposition (E-FRAC-37): Autokey CANNOT reach 24/24 at any model. PT-autokey max=16/24, CT-autokey max=21/24. Autokey is MORE constrained than periodic keying due to sequential key dependencies.**
**Bean key model analysis (E-FRAC-38): Progressive, quadratic, and Fibonacci keys ALL Bean-eliminated. Running key is the ONLY structured model that survives. FRAC mandate COMPLETE.**
**Running key bipartite feasibility (E-FRAC-39): ~35% of English text offsets achieve 24/24 bipartite matching under SOME transposition. After Bean: ~0.6% feasible. Carter text has ~700-2,000 fully feasible offsets. MASSIVELY UNDERDETERMINED — multi-objective oracle essential.**
**Carter quadgram screening (E-FRAC-40): SA-optimized transposition achieves -4.27/char with Carter key. BUT random key also achieves -4.40/char — Carter is NOT special. E-FRAC-34's -5.0 threshold is too weak for SA-optimized solutions. Word-level detection is the ONLY reliable discriminator.**

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
11. **Bean constraint NOT informative** for transposition identification (E-FRAC-31)
12. **Simple transposition families** (cyclic shifts, affine, reversal, rail fence, single swaps): ALL ELIMINATED — max 13/24, BELOW random baseline 14/24 (E-FRAC-32)
13. **Crib oracle INSUFFICIENT for arbitrary permutations** — hill-climbing reaches false 24/24 at ALL periods including period 5 (E-FRAC-33). Must combine with plaintext quality metrics.
14. **Multi-objective oracle designed** (E-FRAC-34): 90 false 24/24 solutions characterized. Quadgram gap = 0.93/char (FP best: -5.77, English: -4.84). Threshold: quadgram > -5.0/char + IC > 0.055 + Bean PASS.
15. **Bean impossibility proof** (E-FRAC-35): ALL discriminating periods (2-7) are IMPOSSIBLE for transposition + periodic key due to Bean inequality constraints. Also eliminated: periods 9-12, 14, 15, 17, 18, 21, 22, 25. Only 8 periods survive out of 25 (2-26): {8, 13, 16, 19, 20, 23, 24, 26}. This is a universal PROOF holding for all 97! permutations.
16. **Bean-surviving periods tested** (E-FRAC-36): Period-8 (first surviving, 3 cribs/var) and period-13 hill-climbing with Bean as HARD constraint. 175 false 24/24+Bean solutions found. ALL have quadgram < -5.0/char (best: -6.171). Multi-objective oracle from E-FRAC-34 discriminates false positives at Bean-surviving periods too. Random baseline at period 8: max=14/24.
17. **Autokey + arbitrary transposition** (E-FRAC-37): 4 autokey models (PT/CT × Vig/Beau) tested with arbitrary transpositions. Autokey CANNOT reach 24/24 — max 21/24 (CT-autokey) and 16/24 (PT-autokey). Random baseline: PT-autokey max=7/24, CT-autokey max=5-6/24. Autokey is MORE constrained than periodic keying due to sequential key dependencies. Oracle question is moot since 24/24 is unreachable.
18. **Bean constraint analysis for ALL key models** (E-FRAC-38): Comprehensive algebraic + computational analysis of Bean constraints against every key generation model:
    - **Progressive key: BEAN-ELIMINATED** (delta ∈ {0,13} only, both trivial)
    - **Quadratic key: BEAN-ELIMINATED** (0/676 (a,b) pairs survive full Bean)
    - **Fibonacci key: BEAN-ELIMINATED** (0/676 seeds survive full Bean)
    - **General recurrence: 2,892/456,976 survive** (0.63%) but noise from E-FRAC-15
    - **Running key: OPEN** (Bean only constrains ~6.5% of offsets)
    - **Key insight:** Running key is the ONLY non-trivial structured key model that survives Bean constraints. All polynomial/recurrence/progressive models are eliminated.
19. **Running key + transposition bipartite feasibility** (E-FRAC-39): For each running key offset in reference texts, max achievable crib score under ANY transposition = bipartite matching size. Key findings:
    - **~35% of random English text offsets achieve 24/24 matching** — bipartite matching is extremely permissive
    - **After Bean filtering: ~0.6% of offsets are fully feasible** (matching=24 + Bean full pass)
    - **Carter Gutenberg: 699-807 fully feasible offsets** per variant
    - **Carter Vol1 extract: 1,647-2,031 fully feasible offsets** per variant
    - **ALL reference texts have feasible offsets** — none are eliminated as running key sources by bipartite/Bean constraints
    - **Random baseline identical:** ~35% matching rate in random English text, confirming the constraint provides NO discrimination
    - **Running key + transposition is MASSIVELY UNDERDETERMINED** — comparable to periodic key underdetermination (E-FRAC-33-36)
    - **Multi-objective oracle (quadgram > -5.0) is the ONLY viable discriminator** for JTS
20. **Carter running key + SA quadgram screening** (E-FRAC-40): SA-optimized transposition at feasible Carter offsets achieves quadgrams of -4.27 to -4.55/char. BUT:
    - **RANDOM key + SA also achieves -4.40/char** — Carter is NOT special (control experiment E-FRAC-40b)
    - **The "signal" is an SA optimization artifact**, not evidence for Carter as running key source
    - **E-FRAC-34's -5.0 threshold is TOO WEAK** for SA-optimized transpositions (threshold was designed for crib-optimized, not quadgram-optimized search)
    - SA gibberish has English-like quadgrams (-4.3 to -4.5) AND contains dictionary words (mean 8.6 words ≥6 chars)
    - **Updated JTS oracle:** quadgram > -4.84 + IC > 0.055 + non-crib words ≥6 chars + semantic coherence
    - **Implication:** quadgram optimization alone CANNOT distinguish real solutions from SA-crafted false positives
    - **Word-level discrimination is WEAK** (E-FRAC-41): SA gibberish has 3-17 words vs English 5-20 words. Must exclude crib words from count.
21. **Word-level discriminator analysis** (E-FRAC-41): Validates word detection as a JTS discriminator.
    - SA gibberish: mean 8.6 words ≥6 chars (max 17), coverage 42%
    - Real English: mean 10.7 words ≥6 chars (max 20), coverage 48%
    - Random text: 0 words. English-freq random: 0-2 words.
    - **Word count is WEAK discriminator** — significant overlap between SA gibberish and English because cribs (NORTHEAST, BERLIN) and quadgram optimization produce English fragments
    - **Semantic coherence remains the ultimate discriminator** — no automated metric reliably separates SA gibberish from real English at the 97-char scale
22. **Refined word discriminator** (E-FRAC-42): Excludes crib words + tests multiple word-length thresholds.
    - **Non-crib words ≥7 chars is the best automated metric:** Cohen's d = 1.14 (LARGE effect)
    - Excluding crib words significantly improves d: from 0.81 to 1.14 at ≥7 chars
    - **BUT no perfect separation:** SA gibberish can have up to 11 non-crib words ≥7 chars (e.g., DISTINGUISHED, LABORATORY, UNIFORMED, MACHINIST) — these emerge from quadgram optimization
    - English min = 1 non-crib word ≥7 chars in some segments — so a threshold-based filter would produce both false positives AND false negatives
    - **Composite metric** (noncrib_words × (1 + coverage)): Cohen's d = 1.03, still no perfect separation
    - **Verdict: MODERATE_DISCRIMINATOR** — non-crib word count helps but cannot replace semantic evaluation
23. **Bigram/trigram transition discriminator** (E-FRAC-43): Tests n-gram transition scoring as an alternative.
    - **Bigram: Cohen's d = -0.35** — SA gibberish scores BETTER than English (SA optimizes for local coherence)
    - **Trigram: Cohen's d = 0.11** — essentially no discrimination
    - **Quadgram: Cohen's d = -0.65** — SA gibberish scores better (expected — SA optimizes quadgrams)
    - **N-gram scoring provides ZERO additional discrimination** over word counting
    - SA gibberish is locally MORE coherent than real English at all n-gram scales
    - **Confirms: non-crib word count (d=1.14) is the BEST automated metric. N-grams cannot help.**
    - **Semantic coherence is confirmed as the ONLY reliable discriminator** — no n-gram metric can distinguish SA gibberish from real English at 97 chars

**Reports:** `reports/frac_width9_analysis.md`, `reports/frac_statistical_meta_analysis.md`

## Completed (reverse chronological)

### [2026-02-21T02:00Z] agent_frac — E-FRAC-43: Bigram/Trigram Transition Discriminator (NEGATIVE RESULT)
- **Hypothesis:** Do bigram/trigram transition probabilities provide better discrimination than word counting? SA quadgram optimization produces good local coherence, but perhaps bigram/trigram transitions capture different information.
- **Method:** Build bigram/trigram models from Carter text (117K alpha chars), score 97-char segments from English (71 segments), SA gibberish (20), random (100), English-freq random (100). Compare Cohen's d across metrics.
- **Key findings:**
  - **Bigram score: Cohen's d = -0.35** — SA gibberish scores BETTER than English
  - **Trigram score: Cohen's d = 0.11** — essentially zero discrimination
  - **Quadgram score: Cohen's d = -0.65** — SA gibberish scores better (expected — SA optimizes for quadgrams)
  - SA gibberish mean bigram score = -1.096 vs English -1.118 (SA is MORE bigram-coherent)
  - SA gibberish mean trigram score = -1.039 vs English -1.031 (nearly identical)
  - Random text: clearly separated from both (bigram -1.601, trigram -1.411)
- **Critical implications:**
  1. **SA quadgram optimization produces text that is locally English-like at ALL n-gram scales** (bigram, trigram, quadgram)
  2. **N-gram scoring provides ZERO additional discrimination** — in fact, SA gibberish is MORE n-gram-coherent than real English
  3. **Non-crib word counting (d=1.14 from E-FRAC-42) remains the BEST automated metric** — no n-gram metric comes close
  4. **The fundamental limitation is confirmed:** at 97 characters, SA optimization can make ANY text score well on local coherence metrics. Discrimination requires GLOBAL semantic understanding, not local n-gram statistics.
- **For JTS:** Do NOT add bigram/trigram scoring to the oracle. It provides no discrimination. Stick with: crib=24 + Bean + non-crib words ≥7 chars ≥ 3 + human semantic evaluation.
- **Verdict:** NO_IMPROVEMENT — n-gram transitions provide zero discrimination. Non-crib word count remains the best automated metric.
- **Runtime:** 0.3 seconds
- **Artifacts:** results/frac/e_frac_43_bigram_discriminator.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_43_bigram_discriminator.py`

### [2026-02-21T01:00Z] agent_frac — E-FRAC-42: Refined Word Discriminator — Non-Crib Words (JTS ORACLE REFINEMENT)
- **Hypothesis:** Does excluding crib words from the word count improve discrimination? Is there ANY automated metric that achieves perfect separation between SA gibberish and real English?
- **Method:**
  1. Exclude 16 crib-derived words (NORTHEAST, BERLIN, CLOCK, EAST, NORTH, STERN, ASTER, etc.) from non-crib count
  2. Test word-length thresholds: ≥4, ≥5, ≥6, ≥7, ≥8 chars
  3. Compute Cohen's d and overlap coefficient for each metric
  4. Test composite metrics (word count × coverage)
  5. Analyze word-length distribution and max non-crib word length
- **Key findings:**
  - **Best metric: non-crib words ≥7 chars** — Cohen's d = 1.14 (LARGE effect)
  - Excluding crib words: d improved from 0.81 → 1.14 at ≥7 chars (significant improvement)
  - English: mean 6.3 non-crib words ≥7 chars [1-14]
  - SA gibberish: mean 3.0 non-crib words ≥7 chars [0-11]
  - **NO perfect separation at ANY threshold** — SA gibberish produces real English words:
    - DISTINGUISHED, LABORATORY, UNIFORMED, MACHINIST, SPIRATED, MANDATE, DIRECTLY
    - These are NOT crib-derived — they emerge from SA quadgram optimization
  - Overlap coefficient: 0.70 (70% of SA values fall within English range)
  - Composite metric (words × coverage): d=1.03, also no perfect separation
  - Max word length: d=0.81, English mean=10.2, SA mean=8.6
- **Critical implications:**
  1. **Non-crib word count is a MODERATE discriminator** — Cohen's d=1.14 is statistically useful but insufficient for binary classification
  2. **SA quadgram optimization is powerful enough to produce real English words** (DISTINGUISHED, LABORATORY) — this means word counting fundamentally cannot achieve perfect separation
  3. **Semantic coherence remains the ONLY fully reliable discriminator** — automated metrics can reduce candidates but final acceptance requires human evaluation
  4. **Recommended automated filter for JTS:** non-crib words ≥7 chars ≥ 3 (eliminates most SA gibberish while accepting most real English)
- **For JTS:** Use non-crib word count ≥7 chars as a PRE-FILTER (threshold ≥3), then apply human semantic evaluation. No fully automated oracle exists.
- **Verdict:** MODERATE_DISCRIMINATOR — d=1.14, significant improvement over E-FRAC-41, but overlap remains
- **Runtime:** 1.4 seconds
- **Artifacts:** results/frac/e_frac_42_refined_discriminator.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_42_refined_discriminator.py`

### [2026-02-21T00:00Z] agent_frac — E-FRAC-41: Word-Level Discriminator Analysis (JTS ORACLE REFINEMENT)
- **Hypothesis:** Is word-level detection (dictionary words ≥6 chars) a reliable discriminator between real English plaintext and SA-optimized gibberish? Can automated word counting replace semantic coherence evaluation?
- **Method:**
  1. Load 333K dictionary words ≥6 chars from `wordlists/english.txt`
  2. Real English: 71 overlapping 97-char segments from Carter/K1-K3 plaintext (spaces/punctuation removed, uppercased)
  3. SA gibberish: 20 representative SA-optimized plaintexts from E-FRAC-40 (Carter key + random key results)
  4. Random baselines: 100 uniform random + 100 English-frequency random 97-char texts
  5. Metrics: word count (≥6 chars), greedy non-overlapping word coverage fraction
- **Key findings:**
  - **Real English:** 5-20 words ≥6 chars (mean 10.7), coverage 48%
  - **SA gibberish:** 3-17 words ≥6 chars (mean 8.6), coverage 42%
  - **Random text:** 0 words (0% coverage) — clear separation from both
  - **English-freq random:** 0-2 words (0.1 mean) — clear separation
  - **SA gibberish contains crib words** (NORTHEAST, BERLIN, CLOCK) which are dictionary words ≥6 chars, inflating the count
  - **SA quadgram optimization naturally produces English fragments** (3-4 letter sequences that form parts of real words)
  - **Word count distributions OVERLAP significantly** — mean difference is only 2.1 words, and some SA gibberish exceeds some English segments
- **Critical implications:**
  1. **Word count ≥6 chars is a WEAK discriminator** — cannot reliably separate SA gibberish from real English at 97 chars
  2. **The "≥3 complete words ≥6 chars" threshold from E-FRAC-40 is too easy** — SA gibberish routinely exceeds it (mean 8.6)
  3. **Non-crib word count** (excluding NORTHEAST, BERLIN, CLOCK, EAST) may improve discrimination but was not tested
  4. **Semantic coherence remains the ONLY reliable discriminator** — no automated metric tested can reliably separate SA gibberish from real English
  5. **The fundamental challenge:** at 97 characters, even randomly shuffled English fragments produce many dictionary hits. The discriminant is not word PRESENCE but word MEANING in context.
- **For JTS:** Do NOT rely solely on automated word detection. Any candidate passing crib=24 + Bean + quadgram > -4.84 must undergo HUMAN evaluation for semantic coherence. There is no fully automated oracle.
- **Verdict:** WEAK_DISCRIMINATOR — word detection is better than nothing but insufficient as a standalone filter
- **Runtime:** 0.4 seconds
- **Artifacts:** results/frac/e_frac_41_word_discriminator.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_41_word_discriminator.py`

### [2026-02-20T23:00Z] agent_frac — E-FRAC-40: Carter Running Key Quadgram Screening + Random Control (CRITICAL META-RESULT)
- **Hypothesis:** Does Carter's text (the primary running key candidate) produce better plaintext quality than random keys when SA optimizes the transposition for quadgrams? Is the -5.0/char threshold from E-FRAC-34 sufficient?
- **Method:**
  1. E-FRAC-40: For 200 Bean-passing, matching=24 Carter offsets, SA-optimize the transposition (73 non-crib positions) for quadgram fitness. 3 restarts × 5K steps each.
  2. E-FRAC-40b: Same SA optimization with uniform random keys (100 trials, 39 feasible) and English-frequency random keys (100 trials, 39 feasible).
- **Key findings:**
  - **Carter Gutenberg (Vigenère):** best=-4.2685/char, mean=-4.5466. ALL 200 offsets above -5.0.
  - **Carter Gutenberg (Beaufort):** best=-4.3245/char, mean=-4.5311. ALL 200 offsets above -5.0.
  - **Carter Vol1 extract (Vigenère):** best=-4.3293/char, mean=-4.5421. ALL 200 offsets above -5.0.
  - **Uniform random key:** best=-4.4027/char, mean=-4.5172. ALL 39 feasible trials above -5.0.
  - **English-freq random key:** best=-4.3913/char, mean=-4.5340. ALL 39 feasible trials above -5.0.
  - **Carter vs random difference: only 0.13/char** — within noise for different sample sizes (200 vs 39).
  - **ALL "plaintexts" are SA-optimized gibberish** — but they contain dictionary words (mean 8.6 words ≥6 chars per E-FRAC-41, including crib words NORTHEAST/BERLIN).
- **Critical implications:**
  1. **E-FRAC-34's -5.0 threshold is ONLY valid for crib-optimized transpositions.** When SA optimizes for quadgrams (which JTS would naturally do), quadgrams of -4.3 to -4.5 are trivially achievable.
  2. **Carter is NOT special.** Random keys produce the same quadgram range. The bipartite matching + SA optimization is so powerful that any 97-char key can be paired with a transposition producing locally English-looking text.
  3. **Quadgram fitness ALONE cannot discriminate** real solutions from SA-crafted false positives.
  4. **Automated word detection is a WEAK discriminator** (confirmed by E-FRAC-41): SA gibberish contains 3-17 dictionary words ≥6 chars (mean 8.6) vs English 5-20 (mean 10.7). Crib words inflate the count.
  5. **Updated JTS oracle (SUPERSEDES E-FRAC-34, refined by E-FRAC-41):**
     - Crib = 24/24 + Bean PASS (unchanged)
     - Quadgram > -4.84/char (actual English; -5.0 is too easy)
     - IC > 0.055 (unchanged)
     - Non-crib words ≥6 chars: at least 3 (exclude NORTHEAST, BERLIN, CLOCK, EAST)
     - **Semantic coherence (human evaluation) — THE ultimate discriminator** (no automated metric suffices)
- **For JTS:** SA will routinely produce false positives with excellent quadgrams (-4.3). Do NOT use quadgram score alone as the acceptance criterion. Implement word detection as a HARD constraint.
- **Verdict:** CARTER_NOT_SPECIAL — SA optimization artifact. E-FRAC-34 threshold updated.
- **Runtime:** 469s (E-FRAC-40) + 47s (E-FRAC-40b) = 516s
- **Artifacts:** results/frac/e_frac_40_carter_quadgram_screen.json, results/frac/e_frac_40b_random_key_control.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_40_carter_quadgram_screen.py && PYTHONPATH=src python3 -u scripts/e_frac_40b_random_key_control.py`

### [2026-02-20T22:00Z] agent_frac — E-FRAC-39: Running Key + Transposition Bipartite Feasibility (STRUCTURAL)
- **Hypothesis:** For running key from known reference texts + arbitrary transposition, how many (offset, transposition) pairs can achieve 24/24+Bean? Is the bipartite matching constraint (max achievable crib score under ANY transposition) discriminating?
- **Method:** For each offset in 8 reference texts (Carter Gutenberg 117K, Carter Vol1 288K, CIA Charter 9K, JFK Berlin 2.8K, NSA Act 70K, Reagan Berlin 12.7K, UDHR 8.7K, K1-K3 plaintext 710 chars), compute:
  1. Bean equality and inequality pass/fail for the running key
  2. Bipartite matching: 24 crib positions → 97 CT positions (edge exists iff CT[j] has the required letter for crib i at this offset). Max matching = max achievable crib score under ANY transposition.
  3. Both Vigenère and Beaufort variants tested
  4. Monte Carlo baseline: 20 random English texts × 200K chars each
- **Key findings:**
  - **~35% of offsets achieve matching=24** across all texts and both variants. Reference texts: 33-42% matching=24. Random baseline: 35.8% (Vig), 40.2% (Beau). No difference between reference and random.
  - **Bean full pass rate: ~1.7-1.9%** across all texts (matches E-FRAC-38 prediction)
  - **Fully feasible offsets (matching=24 + Bean full pass):**
    - Carter Gutenberg: 699 (Vig), 807 (Beau) — 0.60-0.69% of offsets
    - Carter Vol1 extract: 1,647 (Vig), 2,031 (Beau) — 0.57-0.71%
    - NSA Act: 398 (Vig), 488 (Beau) — 0.57-0.70%
    - K1-K3 plaintext: 3 (Vig), 5 (Beau) — tiny text, still feasible
    - ALL other texts: 12-84 feasible offsets each
  - **Random baseline: ~1,043 (Vig) / ~1,231 (Beau) feasible per 200K-char text** — reference texts are INDISTINGUISHABLE from random
  - **Matching distribution is remarkably stable:** 24/24 ≈ 35-40%, 23/24 ≈ 33%, 22/24 ≈ 18%, 21/24 ≈ 8%, 20/24 ≈ 3%. Nearly identical for all texts.
  - **Per-crib expected CT matches = 3.7** (97/26) — each crib has ~3.7 compatible CT positions, making 24/24 matching common
  - **Beaufort consistently more permissive** than Vigenère (~40% vs ~35% matching=24) due to CT letter distribution interaction
- **Implications:**
  - Running key + transposition is NOT eliminated by bipartite/Bean constraints for ANY tested reference text
  - The bipartite matching constraint provides ZERO discrimination — it eliminates almost nothing
  - This extends the underdetermination theme from E-FRAC-33-36: the 24 cribs are insufficient to constrain the combined (offset × transposition) space
  - **For JTS:** With ~700-2,000 feasible offsets per major text, each having millions of compatible transpositions, the search space is ~10^9+ candidates. SA/hill-climbing WILL find 24/24+Bean solutions at many offsets. The multi-objective oracle (quadgram > -5.0, IC > 0.055, word ≥6 chars) from E-FRAC-34 is ESSENTIAL to distinguish real from false solutions.
  - **For running key search:** The key discriminator is NOT crib matching (too easy to satisfy) but plaintext QUALITY. Only the correct (offset, transposition) pair will produce English plaintext with quadgram > -5.0.
- **Verdict:** MASSIVELY_UNDERDETERMINED — running key + transposition from known texts is feasible at hundreds to thousands of offsets, but bipartite/Bean constraints provide no discrimination. Multi-objective oracle required.
- **Runtime:** 253 seconds
- **Artifacts:** results/frac/e_frac_39_running_key_bipartite.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_39_running_key_bipartite.py`

### [2026-02-20T20:30Z] agent_frac — E-FRAC-38: Bean Constraint Analysis — ALL Key Models (FINAL STRUCTURAL ANALYSIS)
- **Hypothesis:** Which key generation models survive Bean constraints? Comprehensive algebraic + computational analysis.
- **Models analyzed:** Periodic, progressive, quadratic, running key, PT-autokey, CT-autokey, Fibonacci, general recurrence
- **Key findings:**
  - **Progressive key: BEAN-ELIMINATED.** Bean equality → 38δ ≡ 0 (mod 26) → δ ∈ {0, 13}. δ=0 is monoalphabetic (trivially eliminated). δ=13 is effectively period-2 (Bean-eliminated by E-FRAC-35).
  - **Quadratic key: BEAN-ELIMINATED.** 52/676 (a,b) pairs pass Bean equality, but ALL 52 fail at least one Bean inequality. Zero survive.
  - **Fibonacci key: BEAN-ELIMINATED.** 26/676 seeds pass Bean equality, zero pass full Bean.
  - **General recurrence K[i]=(c1·K[i-1]+c2·K[i-2])%26: 2,892/456,976 survive** (0.63%). But max <8/24 from E-FRAC-15 → noise.
  - **Running key: OPEN.** Bean only constrains ~6.5% of offsets in English source text (Bean eq pass), ~1.7% pass full Bean. Minimal constraint.
  - **PT-autokey: COMP. ELIMINATED** (E-FRAC-37, max 16/24).
  - **CT-autokey: COMP. ELIMINATED** (E-FRAC-37, max 21/24).
- **Key insight:** Running key + transposition is the ONLY non-trivial structured key model that survives Bean constraints. All polynomial, recurrence, and progressive models are Bean-eliminated. This strongly focuses remaining search on:
  1. Running key from unknown text + structured transposition
  2. Non-standard key generation (position-dependent, bespoke)
  3. Periodic keying at surviving periods (8,13,16,...) — underdetermined
- **Verdict:** STRUCTURAL_ANALYSIS_COMPLETE — comprehensive Bean constraint taxonomy for all key models
- **Runtime:** 10 seconds
- **Artifacts:** results/frac/e_frac_38_bean_key_model_constraints.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_38_bean_key_model_constraints.py`

### [2026-02-20T20:00Z] agent_frac — E-FRAC-37: Autokey + Arbitrary Transposition (STRUCTURAL ELIMINATION)
- **Hypothesis:** Can autokey (which bypasses the Bean period impossibility proof from E-FRAC-35) reach 24/24 with arbitrary transpositions? Does the multi-objective oracle generalize to non-periodic key models?
- **Method:** 4 autokey models (PT-autokey × Vig/Beau, CT-autokey × Vig/Beau) tested in 3 phases:
  - Phase 1: Random baseline (10K perms × 4 models × 26 seeds)
  - Phase 2: Hill-climbing without Bean (50 climbs × 5K steps × 4 models)
  - Phase 3: Hill-climbing with Bean HARD (50 climbs × 5K steps × 4 models)
- **Key findings:**
  - **PT-autokey CANNOT reach 24/24** — max 15/24 (no Bean), 13/24 (Bean=HARD). Sequential key dependency (K[i]=PT[i-1]) creates tight constraints preventing false 24/24.
  - **CT-autokey reaches 21/24 max** (no Bean), 20-21/24 (Bean=HARD), but NEVER 24/24. Hill-climbing ceiling is well below 24.
  - **Random baseline much lower than periodic**: PT-autokey max=7/24 (vs 14/24 periodic), CT-autokey max=5-6/24. Autokey is dramatically MORE constrained.
  - **All solutions have terrible quadgrams**: best -6.209/char (threshold -5.0). Oracle question is moot.
  - **Bean pass rate ~1.5-1.8%** for random permutations (similar to periodic models)
  - **CT-autokey is inherently more underdetermined** (key depends on CT, not PT — no plaintext feedback loop) but still can't reach 24/24
  - **Seed is always 0** for CT-autokey (K[0] doesn't matter when K[i]=CT[σ(i-1)] for i>0)
- **Implications:**
  - Autokey is NOT a viable route to bypass the Bean period impossibility proof
  - Autokey is MORE constrained than periodic keying, not less — the sequential dependency creates a much tighter space
  - The multi-objective oracle question (does it generalize?) is moot since autokey can't reach 24/24
  - For JTS: autokey + arbitrary transposition is LESS dangerous than periodic + arbitrary transposition for false positives
  - If K4 uses autokey, the transposition must be from a structured family (not arbitrary) — potentially testable by TRANS agent
- **Verdict:** AUTOKEY_CANNOT_REACH_24 — autokey + arbitrary transposition structurally unable to produce false 24/24 solutions
- **Runtime:** 535 seconds
- **Artifacts:** results/frac/e_frac_37_autokey_arbitrary_transposition.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_37_autokey_arbitrary_transposition.py`

### [2026-02-20T19:30Z] agent_frac — E-FRAC-36: Period-8 Hill-Climbing with Bean Constraint (FALSE POSITIVE VALIDATION)
- **Hypothesis:** Can hill-climbing at Bean-surviving periods (8, 13) reach 24/24 with Bean as a HARD constraint? If so, does the E-FRAC-34 multi-objective oracle discriminate them?
- **Method:** 50 hill-climbs × 10K steps each, at periods 8 and 13, both Vigenère and Beaufort, with Bean as non-negotiable constraint. Also 50 climbs without Bean for comparison. Random baseline: 10K samples.
- **Key findings:**
  - **Period 8 Vigenère:** 41/50 climbs reach 24/24 with Bean (82%), max without Bean: 24/24 (96%)
  - **Period 8 Beaufort:** 47/50 reach 24/24 with Bean (94%)
  - **Period 13 Vigenère:** 44/50 reach 24/24 with Bean (88%)
  - **Period 13 Beaufort:** 43/50 reach 24/24 with Bean (86%)
  - **ALL 175 false 24/24+Bean solutions have quadgram < -5.0/char** (best: -6.171/char)
  - **English benchmark: -4.84/char, gap ≥ 0.83/char** — multi-objective oracle discriminates perfectly
  - **Random baseline (period 8):** max=14/24, mean=9.00; Bean-passing random: max=11/24
  - **Bean constraint REDUCES max score** from random baseline (11 vs 14) but does NOT prevent hill-climbing from reaching 24/24
  - **Period 8 vs period 13:** Nearly identical false positive profiles. Period 13 has more underdetermination (1.8 cribs/var vs 3.0) but same quadgram range
- **Implications:**
  - The E-FRAC-34 multi-objective oracle works at ALL tested periods (eliminated AND surviving)
  - Hill-climbing + Bean constraint is NOT sufficient to find the correct transposition — must combine with quadgram/IC/word metrics
  - For JTS: the threshold quadgram > -5.0/char remains valid even at Bean-surviving periods
  - 175 additional false positive solutions confirm and extend E-FRAC-34's characterization
- **Verdict:** FALSE_POSITIVES_AT_P8 — 24/24+Bean is easily achievable at surviving periods, but ALL are false positives discriminated by quadgram score
- **Runtime:** ~300 seconds
- **Artifacts:** results/frac/e_frac_36_period8_bean_hillclimb.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_36_period8_bean_hillclimb.py`

### [2026-02-20T18:00Z] agent_frac — E-FRAC-35: Bean Impossibility Proof (CRITICAL PROOF)
- **Theorem:** For ANY transposition σ and periodic key at period p, Bean constraints eliminate ALL discriminating periods (2-7) plus periods 9-12, 14, 15, 17, 18, 21, 22, 25. Only 8 of 25 periods (2-26) survive: {8, 13, 16, 19, 20, 23, 24, 26}.
- **Method:** Two elimination mechanisms:
  - **Type 1 (same-residue inequality):** Bean inequality pair (a,b) with a ≡ b (mod p) forces k[a]=k[b], violating k[a]≠k[b]. Differences {1,3,4,5,9,34,42,43,45,50} eliminate periods 2-7, 9, 10, 14, 15, 17, 21, 25.
  - **Type 2 (equality-inequality conflict):** Bean equality forces key[27%p]=key[65%p], but inequality pair (71,21) has {71%p,21%p}={5,10}={27%11,65%11}, creating direct contradiction. Similarly for (29,63) at period 12. Eliminates periods 11, 12, 18, 22.
- **Feasibility at surviving periods (bipartite matching, 1M samples):**
  - Period 8: 7,959 feasible key tuples (0.80%) → est. 1.66B total
  - Period 13: 5,890 feasible (0.59%) → est. 14.6 quadrillion total (highly underdetermined)
  - Period 16: 6,164 feasible (0.62%) → est. 269 quintillion total (extremely underdetermined)
  - Periods 11, 12: ZERO Bean-passing from 1M samples (confirmed eq-ineq conflict)
- **Cross-validation:** All 90 false 24/24 solutions from E-FRAC-33/34 were at Bean-eliminated periods (p2, p5, p6, p7). Bean impossibility provides a STRUCTURAL explanation for why these are false positives.
- **Key implication:** If K4 uses periodic keying with transposition, the period must be ≥8. Period 8 is the ONLY viable period with ≥2 cribs/var. This strongly favors NON-PERIODIC key models.
- **Verdict:** PROOF — universal Bean impossibility for transposition + periodic key at discriminating periods
- **Runtime:** 22 seconds
- **Artifacts:** results/frac/e_frac_35_bean_period_impossibility.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_35_bean_period_impossibility.py`

### [2026-02-20T12:00Z] agent_frac — E-FRAC-34: Multi-Objective Oracle Design for JTS (CRITICAL)
- **Hypothesis:** Can plaintext quality metrics distinguish real solutions from false 24/24 positives? What thresholds should JTS use?
- **Method:** Hill-climbing (50 climbs × 10K steps) at best-period, period-5-only, and period-2-only, collecting all solutions ≥20/24 (best), ≥18/24 (p5), ≥16/24 (p2). For each false positive, derive full 97-char plaintext using periodic key, evaluate quadgram fitness, IC, and English word coverage.
- **Key findings:**
  - **90 false 24/24 solutions** collected: 34 at p7, 35 at p5, 16 at p2, 5 at p6
  - **Quadgram gap is CLEAR:** False positive best = -5.77/char, English benchmark = -4.84/char. Gap = 0.93/char.
  - **IC does NOT discriminate:** False positives have IC ≈ 0.038 (same as random). IC measures substitution quality, not permutation correctness.
  - **Word coverage discriminates:** False positives: 29% word coverage (≥4 chars), English: 99.7%
  - All 90 false 24/24 solutions correctly contain ENE and BC in plaintext (expected — they're the cribs)
  - Period 2 produces fewest false positives (16 vs 34-35) — most constrained
  - False positives at ALL score levels (16-24/24) have quadgrams in [-6.1, -5.77] range — far from English
  - No false positive has quadgram better than -5.77/char despite 563K total solutions evaluated
- **Multi-objective thresholds for JTS:**
  1. Crib score = 24/24
  2. Bean constraint PASS
  3. Quadgram/char > -5.0 (all FPs ≤ -5.77, English ≈ -4.84)
  4. IC > 0.055 (English ≈ 0.067, random ≈ 0.038)
  5. At least one word ≥6 chars in plaintext
- **Verdict:** ORACLE_DESIGNED — quadgram fitness alone provides a 0.93/char gap between false positives and real English. Multi-objective thresholds should reliably filter false positives.
- **Runtime:** 441 seconds
- **Artifacts:** results/frac/e_frac_34_multi_objective_oracle.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_34_multi_objective_oracle.py`

### [2026-02-21T01:00Z] agent_frac — E-FRAC-33: Fitness Landscape Analysis (CRITICAL META-RESULT)
- **Hypothesis:** Is the crib-scoring fitness landscape over 97-element permutations smooth enough for SA/hill-climbing? Can the 24-crib oracle identify the correct transposition from arbitrary permutations?
- **Method:** 10K parent-child correlation, 100 mutation chains (200 steps each), Hamming distance analysis, 100 hill-climbing simulations (5K steps), 50 period-5-only hill-climbs, per-period baseline distributions.
- **Key findings:**
  - **Landscape is SMOOTH:** Parent-child correlation r=0.92 (overall), r=0.93 at each individual period (corrected). 89% of swaps leave the score unchanged.
  - **Hill-climbing reaches 24/24 at period 7** in 50% of trials (30 climbs × 5K steps). All 24/24 solutions use period 7 (87%) or period 6 (13%).
  - **Hill-climbing reaches 24/24 at period 5** in 30% of trials (50 climbs × 5K steps). Random baseline max at period 5: 12/24. Hill-climbing advantage: +12 points.
  - **The 24/24 solutions are FALSE POSITIVES** — the 97! permutation space contains enough accidental perfect solutions at every discriminating period.
  - **Per-period per-climb breakdown:** At 24/24 solutions, other periods score normally (p2=6-10, p3=7-14, p4=8-12). Only the "best" period is artificially high.
  - **Hamming distance from identity:** Near-identity perms (1-3 swaps) score LOWER (8.2-8.4/24) than random (9.4/24). Distance from identity does NOT help.
  - **Chain autocorrelation decays:** lag-1=0.92, lag-10=0.49, lag-50=0.03. Memory lasts ~20 swaps.
  - **Per-period baselines:** p2 mean=5.1 max=9, p3 mean=6.2 max=10, p5 mean=7.7 max=12, p7 mean=9.2 max=14.
- **Critical implication:** The 24-crib oracle is **fundamentally insufficient** for identifying the correct transposition from arbitrary permutations. SA WILL converge to false positives. The search MUST combine crib scoring with plaintext quality metrics (quadgrams, IC, English detection).
- **For structured families (columnar, rail fence, etc.):** The small search space prevents false 24/24 solutions — crib scoring IS discriminating within structured families.
- **Verdict:** LANDSCAPE_SMOOTH / ORACLE_INSUFFICIENT — SA over arbitrary permutations converges to false positives at all periods. Multi-objective optimization required.
- **Runtime:** 607 seconds (main + fix)
- **Artifacts:** results/frac/e_frac_33_fitness_landscape.json, results/frac/e_frac_33b_perperiod_fix.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_33_fitness_landscape.py && PYTHONPATH=src python3 -u scripts/e_frac_33b_perperiod_fix.py`

### [2026-02-21T00:30Z] agent_frac — E-FRAC-32: Simple Transposition Family Sweep (ELIMINATION)
- **Hypothesis:** Do simple, non-columnar transposition families show crib signal at discriminating periods?
- **Families tested:**
  - Cyclic shifts σ(i)=(i+k) mod 97: 96 permutations
  - Reverse σ(i)=96-i: 1 permutation
  - Affine σ(i)=(a*i+b) mod 97: 9,215 permutations (97 is prime → all a=2..96 valid)
  - Block reversal (B=2..48): 47 permutations
  - Rail fence (depth 2-20): 19 permutations
  - Single swaps: 4,656 permutations (all C(97,2) pairs)
  - Adjacent pair swaps: 1 permutation
- **Total:** 14,035 permutations × 3 variants × 2 models × 6 periods = 505,260 configs
- **Key findings:**
  - Global max: 13/24 (affine a=5,b=36, period 7, Vigenère, model B)
  - Random baseline max: 14/24 (50K samples) — structured families UNDERPERFORM random
  - Corrected p ≈ 1.0 (100% of random experiments of this size reach 13+)
  - Best affine with Bean pass: 13/24 (a=7,b=78) — still noise
  - Single swaps: 96% Bean eq pass rate (near-identity preserves Bean) but max only 10/24
  - Rail fence depth 3: 12/24 — noise
  - All top results at period 7 (least discriminating of discriminating periods)
  - No family shows any advantage over random permutations
- **Verdict:** NOISE — ALL simple transposition families eliminated. Best score 13/24 is BELOW random baseline (14/24). Simple transpositions ANTI-correlate with crib matching, same pattern as columnar.
- **Runtime:** 40 seconds
- **Artifacts:** results/frac/e_frac_32_simple_transposition_sweep.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_32_simple_transposition_sweep.py`

### [2026-02-20T23:30Z] agent_frac — E-FRAC-31: Bean-Filtered Random Permutation Analysis (STRUCTURAL)
- **Hypothesis:** Do Bean-passing arbitrary permutations score differently from non-Bean ones at discriminating periods?
- **Configs tested:** 500K random permutations, split by Bean constraint status.
- **Key findings:**
  - Bean equality pass rate: 3.66% (≈1/26, as expected); Bean full pass: 2.16%
  - Bean-Eq mean score: 9.447 vs Non-Bean mean: 9.386 (diff +0.06, z=9.38) — statistically significant but practically negligible
  - Bean-Full max: 13/24 (from 10,782 samples) vs Non-Bean max: 15/24 (from 481,679 samples)
  - Bean-Full >=14: ZERO (0/10,782). Expected from Non-Bean rates: ~0.56 → seeing 0 is not unusual
  - The Bean constraint has a tiny positive effect on mean score but REDUCES maximum achievable score
  - Bean is NOT useful as a filter for finding the correct transposition
- **Verdict:** BEAN_NOT_INFORMATIVE — Bean-passing random permutations score identically to non-Bean at discriminating periods. The Bean constraint does not discriminate the correct transposition.
- **Runtime:** 324 seconds
- **Artifacts:** results/frac/e_frac_31_bean_random_perms.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_31_bean_random_perms.py`

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
