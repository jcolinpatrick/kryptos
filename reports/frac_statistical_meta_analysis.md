# K4 Statistical Meta-Analysis — What the Numbers Actually Say

**Agent:** frac (FRAC role)
**Date:** 2026-02-21 (updated: E-FRAC-43)
**Experiments:** E-FRAC-01 through E-FRAC-43
**Status:** FRAC mandate COMPLETE + extension — 43 experiments. Running key + transposition fully characterized: MASSIVELY UNDERDETERMINED, no automated discriminator achieves perfect separation between SA gibberish and real English. Discriminator investigation CONCLUDED.

## Executive Summary

After 42 experiments totaling ~62 million configurations and ~8800 seconds of compute, the FRAC agent has comprehensively addressed its mandate: width-9 grid hypothesis, fractionation families, structural analysis, meta-validation of prior claims, comprehensive Bean/columnar width elimination, Bean impossibility proofs, multi-objective oracle design, autokey structural elimination, comprehensive key model Bean analysis, running key + transposition feasibility, and automated discriminator design. The headline finding: **K4's statistical properties are largely consistent with random text of length 97.** Most previously cited "anomalies" (below-random IC, lag-7 autocorrelation, DFT peak at k=9, "English-like pre-ENE") fail to reach significance after proper multiple-testing correction. **ALL columnar transposition widths 5-15 are eliminated. Periodic keying at ALL discriminating periods is Bean-impossible for ANY transposition (universal proof). At Bean-surviving periods, 24/24+Bean is easily achievable but ALL solutions are false positives. Autokey CANNOT reach 24/24 (more constrained than periodic). Running key is the ONLY structured key model surviving Bean constraints. Running key + transposition is MASSIVELY UNDERDETERMINED: ~35% of English text offsets achieve 24/24 bipartite matching, bipartite/Bean constraints provide zero discrimination. SA quadgram optimization trivially achieves -4.3/char with ANY key (Carter is NOT special). No automated discriminator perfectly separates SA gibberish from real English — semantic coherence (human evaluation) is required.**

**One positive finding (now RETRACTED):** The Beaufort key distribution was more concentrated than random (entropy at 0.3rd percentile, p=0.003). E-FRAC-23/24/25 showed this is likely a **selection effect**, not evidence for Beaufort:
- The Beaufort key text contains KKK — impossible in any natural language (E-FRAC-24)
- No structured non-periodic key model produces the observed values (E-FRAC-23)
- Transposition does NOT explain the low entropy (E-FRAC-25)
- The Vigenère key entropy (16.27th percentile) is completely unremarkable
- **The simplest explanation is that the cipher is Vigenère, not Beaufort**

**Major eliminations (E-FRAC-17 through E-FRAC-22):**
- Running key from 8 reference texts: NOISE (7/24 = random expectation)
- Crib positions are correct: no shift at discriminating periods improves scores
- Pre-ENE IC is NOT significant: ranks #10/77 segments, Bonferroni p=1.0
- All 10 fractionation families structurally eliminated (parity/alphabet/IC proofs)
- No null cipher or interval-readable message (K4 MORE uniform than random)

---

## Part I: What IS Statistically Significant (After Correction)

### 1. Beaufort Key Entropy (p = 0.003 — NOW RETRACTED AS EVIDENCE FOR BEAUFORT)
[INTERNAL RESULT — E-FRAC-16, updated by E-FRAC-23/24/25]

Under the Beaufort formulation, the 24 known key values have Shannon entropy at the 0.3rd percentile of random 24-value distributions. This was initially interpreted as evidence for the Beaufort cipher variant. **Follow-up analysis (E-FRAC-23/24/25) shows this interpretation was wrong:**

**Why the Beaufort entropy finding is NOT evidence for Beaufort:**
1. **KKK constraint (E-FRAC-24):** The Beaufort key at positions 30-32 = K,K,K. Under a running key model, the source text would need to contain "KKK" — which occurs in 0/100,000 samples of English text. The Beaufort key text is at 0.0th percentile for ALL tested natural languages.
2. **No structured key generation (E-FRAC-23):** Zero progressive, double-period, recurrence, or modifier models produce the observed Beaufort key values. The key is ANTI-structured (fewer consistent models than random).
3. **Transposition doesn't help (E-FRAC-25):** Under ALL transposition models (random σ, columnar w7/9/11), the Beaufort entropy remains at ~0.3th percentile. Transposition randomizes displacement terms, not reducing the anomaly.
4. **English running key explains the entropy level (E-FRAC-25):** Under a running key from English text (without transposition), the entropy is at 21.65th percentile — normal. But this model is ruled out by the KKK constraint.

**The resolution:** The Vigenère key entropy (3.66 bits) is at 16.27th percentile — completely unremarkable. The Vigenère key has no triple letters and no structural impossibilities. **The E-FRAC-16 "Beaufort signal" was a selection effect: Beaufort happens to produce concentrated key values from this particular CT+PT combination, but this doesn't indicate the cipher is Beaufort.**

**Status:** This finding is now reclassified from "positive result" to "null result after further investigation."

### 2. Width-9 Columnar Is Definitively Eliminated
[INTERNAL RESULT — E-FRAC-01 through E-FRAC-12]

Width-9 columnar transposition + any substitution model (periodic, progressive, autokey, column-progressive, mixed alphabets) is eliminated at discriminating periods (2-7). Score distributions match random at all levels.

---

## Part II: What Is NOT Statistically Significant (Contrary to Prior Claims)

### 3. K4's IC = 0.036 — NOT Unusual (p = 0.21)
[INTERNAL RESULT — E-FRAC-13]

K4's index of coincidence (0.0361) is at the 21.5th percentile of random text of length 97 (z = -0.84). This is completely unremarkable. **The "below-random IC" claim that has been cited as evidence for fractionation or complex cipher structure is not meaningful at n=97.**

The variance of IC for 97-character random text (σ ≈ 0.0028) is large enough that 0.036 is within 1σ of the mean (0.0385).

### 4. Lag-7 Autocorrelation — NOT Significant After Bonferroni (p_adj > 0.37)
[INTERNAL RESULT — E-FRAC-14]

K4 has 9 lag-7 matches (p = 0.0077 uncorrected). However, 48 lags were tested (1-48), and the Bonferroni-corrected threshold is p < 0.00104. **After correction, ZERO lags are significant.** The lag-7 signal is expected to appear at SOME lag by chance when testing 48 lags.

### 5. DFT Peak at k=9 — NOT Significant (magnitude below 95th percentile)
[INTERNAL RESULT — E-FRAC-14]

The DFT magnitude at k=9 (period ≈ 10.8) is 162.2. The 95th percentile of the maximum peak in random text is 191.6, and the 99th percentile is 212.3. **The k=9 peak does not even reach the 95th percentile, let alone the 99th.** Zero DFT peaks are significant.

This undermines the primary statistical evidence for the width-9 hypothesis (alongside Sanborn's "10.8 rows" annotation, which remains valid but is now the SOLE evidence).

### 6. Pre-ENE Segment IC — NOT Significant After Correction (p_adj ≈ 0.12)
[INTERNAL RESULT — E-FRAC-13]

The pre-ENE segment (positions 0-20, n=21) has IC = 0.0667 (English-like), at the 97.6th percentile of random 21-character text. However, with 5 segments tested, Bonferroni correction gives p_adj ≈ 0.12 — not significant.

### 7. K4 Letter Frequencies — Consistent With Uniform
[INTERNAL RESULT — E-FRAC-13]

Chi-squared test of K4's letter frequencies vs uniform: χ² = 19.06 (df=25, 5% critical = 37.65). **K4's letter distribution is NOT significantly different from uniform.**

### 8. Repeated Bigrams — NOT Significant (z = +1.73)
[INTERNAL RESULT — E-FRAC-14]

K4 has 10 repeated bigrams (random mean: 6.1 ± 2.2, z = +1.73). Not significant.

### 9. First-Order Differences — Uniform
[INTERNAL RESULT — E-FRAC-14]

The sequence of differences CT[i+1]-CT[i] (mod 26) follows a uniform distribution (χ² = 25.3, p > 0.05).

---

## Part III: Cipher Family Compatibility

### IC-Compatible Families
[INTERNAL RESULT — E-FRAC-13]

| Cipher Family | Typical IC (n=97) | K4 Percentile | Compatible? |
|---|---|---|---|
| Monoalphabetic substitution | 0.065 | 0% | NO |
| Periodic Vigenere period 3 | 0.047 | 0.3% | Marginal |
| Periodic Vigenere period 5 | 0.044 | 1.9% | Marginal |
| Periodic Vigenere period 7 | 0.042 | 4.1% | Marginal |
| Running key / long-period poly | 0.038 | 22% | YES |
| Bifid 5×5 (I/J merge) | 0.045 | 1% | NO (also structurally impossible) |
| **Bifid 6×6** | **0.059-0.069** | **0%** | **NO — IC-INCOMPATIBLE** |
| Random | 0.038 | 21.5% | YES |

**Key conclusion:** K4's IC is perfectly consistent with a running key or long-period polyalphabetic cipher. **Bifid 6×6 is IC-incompatible** — it produces IC far too high for K4 regardless of transposition (since transposition preserves IC).

### Functional Key Models
[INTERNAL RESULT — E-FRAC-15]

| Model | Best Matches | Random Baseline | Verdict |
|---|---|---|---|
| Linear k=ai+b | 7/24 | 4.9 ± 0.7 (best-of-676) | ~3σ above random — not compelling |
| Quadratic k=ai²+bi+c | 8/24 | ~6-7 (est.) | Noise |
| Exponential k=a·b^i | <6/24 | — | Eliminated |
| Fibonacci/recurrence | <6/24 | — | Eliminated |
| Random 97-key | mean 0.93/24 | — | Baseline |

**The key is NOT a simple function of position.**

---

## Part IV: Comprehensive Elimination Table

### What FRAC Has Eliminated

| Hypothesis | Experiments | Status |
|---|---|---|
| Width-9 columnar + periodic sub (any period, any variant) | E-FRAC-01,12 | **ELIMINATED** |
| Width-9 columnar + progressive key | E-FRAC-02 | **ELIMINATED** |
| Width-9 columnar + CT/PT autokey | E-FRAC-02 | **ELIMINATED** |
| Width-9 columnar + column-progressive | E-FRAC-02 | UNDERDETERMINED (noise floor ~17.7) |
| Width-9 non-columnar reading orders + periodic | E-FRAC-03 | **ELIMINATED** |
| Width-9 × width-7 compound + periodic (p≤7) | E-FRAC-04 | **ELIMINATED** |
| Width-9 + PT-column mixed alphabets | E-FRAC-05 | **HARD ELIMINATION** (0 pass) |
| Width-9 + CT-column mixed alphabets | E-FRAC-05 | UNDERDETERMINED |
| Width-11/13 columnar + periodic (p≤7) | E-FRAC-06 | **ELIMINATED** (identical to random) |
| Bimodal fingerprint as valid constraint | E-FRAC-07,08,09,11 | **ARTIFACT** |
| Strip manipulation + periodic (p≤7) | E-FRAC-10 | **ELIMINATED** |
| Bifid 6×6 (with or without transposition) | E-FRAC-13 | **IC-INCOMPATIBLE** |
| Polynomial/exponential/recurrence key functions | E-FRAC-15 | **ELIMINATED** |
| K4 IC as diagnostic constraint | E-FRAC-13 | **NOT DIAGNOSTIC** |
| Lag-7 as structural evidence | E-FRAC-14 | **NOT SIGNIFICANT** (after Bonferroni) |
| DFT k=9 as structural evidence | E-FRAC-14 | **NOT SIGNIFICANT** |

| Running key from 8 reference texts | E-FRAC-17 | **ELIMINATED** (7/24 = random baseline) |
| Crib positions off by ±1 or ±2 | E-FRAC-18 | **VALIDATED** — cribs correct |
| Pre-ENE segment as different cipher | E-FRAC-19 | **NOT SIGNIFICANT** (rank #10/77, Bonferroni p=1.0) |
| Periodic consistency at periods 2-7 | E-FRAC-20 | **ELIMINATED** (8/24, z=1.27, not significant) |
| ADFGVX/ADFGX | E-FRAC-21 | **STRUCTURALLY IMPOSSIBLE** (parity: 97 is odd) |
| Straddling checkerboard | E-FRAC-21 | **STRUCTURALLY IMPOSSIBLE** (digit output) |
| Bifid 5×5 | E-FRAC-21 | **STRUCTURALLY IMPOSSIBLE** (25-letter alphabet) |
| Playfair, Two-Square, Four-Square | E-FRAC-21 | **STRUCTURALLY IMPOSSIBLE** (parity + alphabet) |
| VIC cipher | E-FRAC-21 | **STRUCTURALLY IMPOSSIBLE** (contains strad. CB) |
| Null cipher / interval reading | E-FRAC-22 | **ELIMINATED** (K4 more uniform than random) |
| All structured non-periodic key generation | E-FRAC-23 | **ELIMINATED** (0 consistent progressive, double-period, recurrence, modifier) |
| Natural-language running key under Beaufort (no transposition) | E-FRAC-24 | **ELIMINATED** (KKK impossible in natural text) |
| Beaufort variant hypothesis (based on key entropy) | E-FRAC-25 | **RETRACTED** (Vigenère entropy is unremarkable; Beaufort signal was selection effect) |
| Width-5 columnar (all orderings) | E-FRAC-26,27 | **BEAN-ELIMINATED** (0/120 orderings pass Bean equality) |
| Width-7 columnar (all orderings) | E-FRAC-26,27 | **BEAN-ELIMINATED** (0/5,040 orderings pass Bean equality) |
| Width-6 columnar (exhaustive, periods 2-7) | E-FRAC-29 | **ELIMINATED** (max 13/24, corrected p=0.485 = NOISE) |
| Width-8 columnar (exhaustive, periods 2-7) | E-FRAC-29 | **ELIMINATED** (max 13/24, UNDERPERFORMS random) |
| Width-9 columnar (exhaustive, periods 2-7) | E-FRAC-12 | **ELIMINATED** (max 14/24, UNDERPERFORMS random) |
| Widths 10-15 columnar (100K samples each, periods 2-7) | E-FRAC-30 | **ELIMINATED** (all max 14/24, all underperform random) |
| Bean constraint as transposition filter | E-FRAC-31 | **NOT INFORMATIVE** (Bean-passing perms score same as non-Bean) |
| SA key optimization on Bean-passing orderings | E-FRAC-28 | **NOISE** (underdetermination artifact at period 12-13) |
| Simple transposition families (cyclic, affine, rail fence, swap, reversal) | E-FRAC-32 | **ELIMINATED** (14,035 perms, max 13/24, BELOW random 14/24) |
| Crib oracle sufficiency for arbitrary permutations | E-FRAC-33 | **INSUFFICIENT** (hill-climbing reaches false 24/24 at ALL periods, including period 5) |
| **ANY transposition + periodic key (p=2-12,14,15,17,18,21,22,25)** | E-FRAC-35 | **PROOF: Bean inequalities structurally violated for ALL 97! permutations** |
| **Bean-surviving periods (8, 13) + Bean HARD constraint** | E-FRAC-36 | **FALSE POSITIVES** (175 solutions at 24/24+Bean, ALL quadgram < -5.0/char) |
| **Autokey (PT/CT) + arbitrary transposition** | E-FRAC-37 | **CANNOT REACH 24/24** (PT-autokey max=16/24, CT-autokey max=21/24; more constrained than periodic) |
| **Progressive key (k[i]=k[0]+i·δ)** | E-FRAC-38 | **BEAN-ELIMINATED** (δ ∈ {0,13} only; both trivial/eliminated) |
| **Quadratic key (k[i]=ai²+bi+c)** | E-FRAC-38 | **BEAN-ELIMINATED** (0/676 (a,b) pairs survive full Bean) |
| **Fibonacci key** | E-FRAC-38 | **BEAN-ELIMINATED** (0/676 seeds survive full Bean) |
| **General recurrence key** | E-FRAC-38 | **2,892/456,976 survive Bean** (0.63%) but max <8/24 from E-FRAC-15 → noise |
| **Running key from unknown text** | E-FRAC-38 | **OPEN** — Bean only constrains ~6.5% of offsets; minimal structural constraint |

### What Remains Open (Relevant to FRAC Mandate)

1. **Width-9 with truly arbitrary substitution** — technically open but has 26^97 parameters (intractable)
2. **Strip manipulation + non-periodic substitution** — untested, low priority given E-FRAC-10 noise result
3. **The "10.8 rows" annotation** — remains sole evidence for width-9, could be coincidence or refer to something else
4. ~~**Beaufort variant hypothesis**~~ — RETRACTED (E-FRAC-25 shows Vigenère is the simpler interpretation)
5. **BC positions conflict more than ENE** — E-FRAC-20 found 82% vs 54% BC/ENE conflict rates at Vig p=5 (implications for transposition search)
6. **Better automated discriminators** — E-FRAC-42 found d=1.14 for non-crib words ≥7 chars. Could try: n-gram perplexity, language model scoring, bigram transition probabilities, or hybrid composite metrics. But the fundamental constraint is 97 chars — too short for reliable statistical discrimination.

---

## Part V: Recommendations for Other Agents

### For TRANS Agent
1. **DROP the bimodal pre-filter** — it is a statistical artifact (E-FRAC-11)
2. **Do NOT rely on lag-7 or DFT k=9 as evidence for any specific width** — neither is significant after correction
3. ~~Consider testing Beaufort variant specifically~~ — E-FRAC-25 shows Vigenère is the simpler interpretation; test both variants equally
4. Width-9 columnar is comprehensively eliminated; do not re-test

### For JTS Agent
1. The bimodal pre-filter should not be used as a search constraint
2. Width-9 is eliminated; focus on other transposition families
3. ~~The Beaufort key entropy finding suggests Beaufort~~ — RETRACTED. Use both Vigenère and Beaufort equally in joint optimization
4. The key is not a simple function of position — focus on running key or complex generation models
5. **NEW (E-FRAC-24):** Natural-language running key is INCOMPATIBLE with Beaufort under direct correspondence (KKK constraint). If testing running key without transposition, use Vigenère.
6. **CRITICAL (E-FRAC-33):** Hill-climbing on crib score over arbitrary permutations reaches FALSE 24/24 at ALL periods (including period 5). The 97! permutation space is so large that accidental perfect solutions exist everywhere. **You MUST combine crib scoring with plaintext quality metrics (quadgram fitness, IC, English word detection) in a multi-objective fitness function.** Crib scoring alone WILL converge to false positives.
7. **Landscape is smooth** (r=0.93 per period) — SA CAN navigate, but it navigates to underdetermination artifacts without additional constraints.
8. **CRITICAL (E-FRAC-35):** Periodic keying at periods 2-7 is Bean-IMPOSSIBLE for ANY transposition (universal proof). Do NOT search with periodic keys at discriminating periods. If using periodic keys, period 8 is the only viable target with ≥2 cribs/var.
9. **CRITICAL (E-FRAC-36):** Even at Bean-surviving periods (8, 13), 24/24+Bean is trivially achievable by hill-climbing, but ALL 175 solutions are false positives (quadgram < -5.0). The multi-objective thresholds remain valid: quadgram > -5.0 + IC > 0.055.
10. **CRITICAL (E-FRAC-40/40b):** SA quadgram optimization trivially achieves -4.3/char with ANY key (Carter, random uniform, English-frequency random). Carter is NOT special. The -5.0 threshold is too weak for quadgram-optimized SA. Updated threshold: quadgram > -4.84/char.
11. **CRITICAL (E-FRAC-41/42):** Word detection is a MODERATE discriminator (Cohen's d = 1.14 for non-crib words ≥7 chars) but NOT a perfect separator. SA gibberish produces real English words (DISTINGUISHED, LABORATORY) via quadgram optimization. **Semantic coherence (human evaluation) is the ONLY fully reliable discriminator.** Any candidate passing automated filters must be reviewed by a human.

### For BESPOKE Agent
1. Strip manipulation with periodic substitution is noise (E-FRAC-10)
2. Strip manipulation with non-periodic substitution is untested but low priority
3. The best remaining bespoke lead is physical/procedural methods, not statistical

### For TABLEAU Agent
1. ~~The Beaufort + KRYPTOS connection is worth exploring~~ — E-FRAC-25 suggests this was a false signal. Beaufort produces KKK in the key, which is likely an artifact of the CT+PT combination, not evidence of KRYPTOS-related structure.
2. The cipher variant question (Beaufort vs Vigenère) remains formally open, but Vigenère is the simpler interpretation since its key has no anomalies.

### For QA Agent
1. The bimodal fingerprint definition in AGENT_PROMPT.md should be reclassified from "MANDATORY pre-filter" to "[HYPOTHESIS — confirmed artifact, DO NOT USE]"
2. The lag-7 and DFT k=9 citations in the evidence base should be annotated with "does not survive Bonferroni correction"
3. Consider updating `docs/research_questions.md` to reflect that statistical evidence for transposition is weaker than assumed

---

## Part VI: What K4 Actually Looks Like, Statistically

K4's ciphertext is a 97-character string with **no statistically significant internal structure** after proper multiple-testing correction. Its properties match:

1. **Random text** — IC, letter frequencies, bigram frequencies, first-order differences, autocorrelation are all consistent with random
2. **Running key cipher on English plaintext** — the IC signature matches perfectly
3. **Long-period (≥10) polyalphabetic on English plaintext** — marginally compatible

After 42 experiments, there are **ZERO statistically significant findings** that survive scrutiny:
- The Beaufort key entropy (p=0.003 from E-FRAC-16) was retracted by E-FRAC-23/24/25 as a selection effect
- All other statistical claims (IC, lag-7, DFT k=9, pre-ENE) were already debunked (E-FRAC-13/14/19)
- The Bean impossibility proof (E-FRAC-35) eliminates periodic keying at ALL discriminating periods for ANY transposition
- 265 false 24/24 solutions characterized (E-FRAC-34/36) — ALL discriminated by quadgram score

**K4 is statistically indistinguishable from random text.** The publicly known constraints (24 crib positions, Bean constraints, self-encrypting positions) remain the primary attack surface. Statistical signals in the CT itself are insufficient to constrain the cipher family or transposition.

---

## Part VII: Final FRAC Mandate Status

### Original Mandate: Fractionation Families
**STATUS: COMPLETE.** All 10 fractionation families (ADFGVX, ADFGX, Bifid 5×5/6×6, Trifid, Playfair, Two-Square, Four-Square, VIC, Straddling Checkerboard) are eliminated by structural proofs that hold with or without transposition.

### Repurposed Mandate: Width-9 Grid Hypothesis → Full Columnar Elimination
**STATUS: COMPLETE + EXTENDED.** Width-9 columnar is eliminated with all substitution models (periodic, progressive, autokey, column-progressive, mixed alphabets). Non-columnar width-9 reading orders are eliminated. Width-9 × width-7 compound is eliminated. The DFT k=9 evidence that motivated this hypothesis is not statistically significant.

**Extended (E-FRAC-26-31):** ALL columnar widths 5-15 are eliminated:
- Widths 5, 7: Bean-ELIMINATED (zero orderings pass Bean equality, exhaustive proof)
- Width-6: exhaustive, max 13/24, corrected p=0.485 (NOISE)
- Width-8: exhaustive, max 13/24, UNDERPERFORMS random
- Width-9: exhaustive, max 14/24, UNDERPERFORMS random
- Widths 10-15: 100K samples each, all max 14/24, all UNDERPERFORM random
- Bean constraint is NOT informative for transposition identification (E-FRAC-31)
- SA key optimization produces only underdetermination artifacts (E-FRAC-28)

### Structural Analysis
**STATUS: COMPLETE.** IC is not diagnostic. Lag-7 is not significant. Pre-ENE is not significant. Crib positions are correct. No null cipher. K4 is statistically consistent with random text.

### Extended Analysis: Key Generation (E-FRAC-23/24/25)
**STATUS: COMPLETE.** The Beaufort key entropy finding (E-FRAC-16) was investigated in depth:
- E-FRAC-23: All structured non-periodic key generation models fail — progressive, double-period, recurrence, modifier, CT-derived (0 consistent models each)
- E-FRAC-24: Beaufort key text is incompatible with all natural languages (KKK constraint, 0.0th percentile)
- E-FRAC-25: Transposition does NOT explain the low entropy; running key (English, no transposition) is the only model where entropy is normal (21.65th percentile), but this is ruled out by KKK

**Final verdict:** The E-FRAC-16 "Beaufort signal" was a false alarm. The Vigenère key has no anomalies (16.27th percentile entropy, no triple letters, no structural impossibilities). **There are now ZERO significant positive findings across all 36 experiments.**

### Extended Analysis: Comprehensive Columnar Width Elimination (E-FRAC-26-31)
**STATUS: COMPLETE.**

**Bean width profiling (E-FRAC-26/27):**
- Width-5: 0/120 orderings pass Bean equality → ELIMINATED
- Width-7: 0/5,040 orderings pass Bean equality → ELIMINATED
- Bean-compatible widths: 6, 8, 9, 10, 11, 12, 13, 14, 15
- Root cause: CT[inv(27)] must equal CT[inv(65)] — variant-independent constraint

**Exhaustive crib scoring (E-FRAC-29):**
- Width-6 (720 orderings): max 13/24, corrected p=0.485 → NOISE
- Width-8 (40,320 orderings): max 13/24, corrected p≈1.0, UNDERPERFORMS random

**Sampled crib scoring (E-FRAC-30):**
- Widths 10-15 (100K samples each): all max 14/24, all corrected p=0.993 → NOISE
- All underperform random (expected max=15 from 100K trials)

**Bean constraint analysis (E-FRAC-31):**
- Bean-passing random permutations: mean +0.06 vs non-Bean (negligible)
- Bean-Full max: 13/24 vs Non-Bean max: 15/24 (Bean is ANTI-correlated with high scores)
- **Bean does not help identify the correct transposition**

**SA key optimization (E-FRAC-28):**
- SA on top Bean-passing width-8/9 orderings: all top results at period 12-13
- Crib scores 0-4/24 — SA abandoned crib matching in favor of quadgram optimization
- Underdetermination artifact, not real signal

**CONCLUSION:** Columnar transposition at ANY width (5-15) + periodic substitution is ELIMINATED at discriminating periods. The columnar hypothesis — motivated originally by the DFT k=9 peak (itself not significant, E-FRAC-14) and Sanborn's "10.8 rows" annotation — is definitively dead.

---

## Part VII: Multi-Objective Oracle for Arbitrary Permutation Search (E-FRAC-34)

E-FRAC-33 showed that hill-climbing over the 97! permutation space converges to false 24/24 solutions at all discriminating periods. E-FRAC-34 characterizes these false positives to design a multi-objective oracle.

### False Positive Characterization

**Method:** 150 hill-climbs (50 each at best-period, period-5-only, period-2-only), 10K steps each, collecting all permutations above score thresholds. 563K total solutions collected, including 90 unique false 24/24 permutations.

**Plaintext quality of false 24/24 solutions:**

| Metric | False Positive (90 solutions) | Random Text (5K samples) | Real English (3 samples) |
|--------|------------------------------|--------------------------|--------------------------|
| Quadgram/char | -5.96 mean, -5.77 best | -6.43 mean | -4.84 mean |
| IC | 0.038 mean, 0.045 best | 0.038 mean | 0.087 mean |
| Word coverage (≥4 chars) | 29% mean | 6% mean | 99.7% mean |

**Key finding:** The quadgram gap between false positives and English is **0.93/char** (best FP: -5.77, English: -4.84). This gap is enormous — false positives are identifiable purely by plaintext quality.

**IC does NOT discriminate:** False positive plaintexts have IC ≈ 0.038, indistinguishable from random. This is expected — IC is determined by the substitution key distribution, not the permutation.

**Per-period false positive density:** Period 2 produces the fewest false 24/24 (16), followed by period 6 (5), period 7 (34), and period 5 (35). Period 2 is the most constrained.

### Recommended Multi-Objective Thresholds

**UPDATED by E-FRAC-40/41/42:** The original -5.0/char threshold is ONLY valid for crib-optimized search. When SA optimizes for quadgrams (as JTS naturally would), it trivially achieves -4.3/char with ANY key. Updated thresholds:

For JTS simulated annealing, a candidate solution should satisfy ALL of:
1. **Crib score = 24/24** (primary oracle)
2. **Bean constraint PASS** (structural filter)
3. **Quadgram/char > -4.84** (SA-optimized false positives reach -4.27; English ≈ -4.84; this threshold is TIGHT)
4. **IC > 0.055** (English ≈ 0.067; false positives all ≤ 0.045)
5. **Non-crib words ≥7 chars: at least 3** (Cohen's d = 1.14 between SA and English; excludes 16 crib-derived words)
6. **Semantic coherence — human evaluation** (THE ultimate discriminator; no automated metric achieves perfect separation)

**Important caveats (from E-FRAC-40/41/42):**
- The -5.0/char threshold from the original E-FRAC-34 analysis was designed for crib-optimized search and is TOO WEAK for quadgram-optimized SA
- Carter text is NOT special — random keys achieve the same quadgram range as Carter (E-FRAC-40b)
- Word detection (even non-crib words) is a MODERATE discriminator (d=1.14) but NOT a perfect separator — SA gibberish can produce real English words like DISTINGUISHED, LABORATORY, UNIFORMED via quadgram optimization
- The original crib-optimized FP analysis remains valid: 0/265 crib-optimized FPs pass the original thresholds

### Implications for Search Strategy

The quadgram gap means SA can use a **weighted multi-objective fitness function**:
```
fitness = α × crib_score + β × quadgram_per_char + γ × ic
```
where α, β, γ are tuned to jointly optimize. The crib score provides the "right neighborhood" signal, while quadgrams provide the "real plaintext" signal. SA should NOT optimize crib score alone.

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_34_multi_objective_oracle.py`

---

## Part VIII: Bean Period Impossibility Proof (E-FRAC-35)

### The Theorem

**For ANY transposition σ (including identity), periodic substitution at periods 2-12 (and 14, 15, 17, 18, 21, 22, 25) violates at least one Bean inequality constraint. This holds for ALL 97! permutations.**

This is a pure algebraic proof, not a search result. Under periodic keying with period p, key value k[i] = key[i mod p]. Bean inequality constraints require k[a] ≠ k[b] for 21 specific position pairs. Two elimination mechanisms:

### Type 1: Same-Residue Inequality

If Bean inequality pair (a, b) has a ≡ b (mod p), then under periodic keying k[a] = key[a mod p] = key[b mod p] = k[b], directly violating k[a] ≠ k[b].

The 21 Bean inequality pairs have position differences: {1, 3, 4, 5, 9, 34, 42, 43, 45, 50}. Any period p that divides any of these differences is Type-1 eliminated.

**Type 1 eliminated periods:** {2, 3, 4, 5, 6, 7, 9, 10, 14, 15, 17, 21, 25}

### Type 2: Bean Equality-Inequality Conflict

Bean equality forces key[27 mod p] = key[65 mod p]. If some Bean inequality pair (a, b) has {a mod p, b mod p} = {27 mod p, 65 mod p}, then the equality and inequality directly conflict.

**Examples:**
- Period 11: Bean equality requires key[5] = key[10] (from 27%11=5, 65%11=10). But inequality pair (71, 21) has 71%11=5, 21%11=10, requiring key[5] ≠ key[10]. Direct contradiction.
- Period 12: Bean equality requires key[3] = key[5] (from 27%12=3, 65%12=5). But inequality pair (29, 63) has 29%12=5, 63%12=3, requiring key[5] ≠ key[3]. Direct contradiction.

**Type 2 eliminated periods (additional):** {11, 12, 18, 22}

### Combined Result

**17 of 25 periods (2-26) are ELIMINATED. Only 8 survive: {8, 13, 16, 19, 20, 23, 24, 26}.**

Critical observation: **ALL discriminating periods (2-7) are Bean-impossible.** Period 8 is the FIRST surviving period, with only 3 cribs per key variable. Most surviving periods (≥13) are deeply underdetermined.

### Implications

1. If K4 uses periodic keying with transposition, the period must be ≥8
2. Period 8 is the ONLY viable period with ≥2 cribs/var
3. The 90 false 24/24 solutions from E-FRAC-33/34 were ALL at Bean-eliminated periods — this provides a structural explanation for why they're false positives
4. This strongly increases the likelihood of a NON-PERIODIC key model (autokey, running key, etc.)

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_35_bean_period_impossibility.py`

---

## Part IX: Bean-Surviving Period Validation (E-FRAC-36)

E-FRAC-35 proved that periodic keying at discriminating periods is impossible. But what about the surviving periods? E-FRAC-36 tests whether the multi-objective oracle from E-FRAC-34 still works at Bean-surviving periods.

### Method

50 hill-climbs × 10K steps each, at periods 8 and 13, both Vigenère and Beaufort, with Bean as a HARD constraint (moves that violate Bean are rejected). Comparison: 50 climbs without Bean.

### Results

| Config | 24/24 + Bean | Best Quadgram | Random Max |
|--------|-------------|---------------|------------|
| Period 8, Vigenère, Bean=HARD | 41/50 (82%) | -6.171/char | 14/24 |
| Period 8, Beaufort, Bean=HARD | 47/50 (94%) | -6.179/char | — |
| Period 13, Vigenère, Bean=HARD | 44/50 (88%) | -6.319/char | — |
| Period 13, Beaufort, Bean=HARD | 43/50 (86%) | -6.435/char | — |

**All 175 false 24/24 + Bean solutions have quadgram < -5.0/char.** Best: -6.171/char. English benchmark: -4.84/char. Gap: ≥0.83/char.

### Key Findings

1. **24/24 + Bean PASS is trivially achievable** at Bean-surviving periods via hill-climbing (82-94% success rate)
2. **ALL solutions are false positives** — indistinguishable from random text by quadgram score
3. **The E-FRAC-34 multi-objective oracle discriminates perfectly** at Bean-surviving periods too
4. **Bean constraint REDUCES random max** (11 vs 14 at period 8) but does NOT prevent hill-climbing from finding false 24/24
5. **Periods 8 and 13 produce nearly identical false positive profiles** — no structural advantage for either

### Combined Oracle Validation

Across E-FRAC-34 (90 solutions at eliminated periods) and E-FRAC-36 (175 solutions at surviving periods), **265 total false 24/24 solutions** have been characterized. None has quadgram > -5.77/char. The multi-objective thresholds from E-FRAC-34 hold universally:
- Crib = 24/24 + Bean PASS + quadgram > -5.0 + IC > 0.055 + word ≥6 chars

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_36_period8_bean_hillclimb.py`

---

## Part X: Autokey Structural Elimination (E-FRAC-37)

Autokey ciphers bypass the Bean period impossibility proof (E-FRAC-35) because they are non-periodic. E-FRAC-37 tests whether autokey + arbitrary transposition can reach 24/24, and whether the multi-objective oracle generalizes.

### Method

4 autokey models (PT-autokey × Vig/Beau, CT-autokey × Vig/Beau) tested in 3 phases:
1. Random baseline: 10K perms × 4 models × 26 seeds
2. Hill-climbing without Bean: 50 climbs × 5K steps × 4 models
3. Hill-climbing with Bean HARD: 50 climbs × 5K steps × 4 models

### Results

| Model | Random Max | Hill-Climb Max (no Bean) | Hill-Climb Max (Bean=HARD) |
|-------|-----------|-------------------------|---------------------------|
| PT-autokey (Vig) | 7/24 | 15/24 | 13/24 |
| PT-autokey (Beau) | 7/24 | 16/24 | 13/24 |
| CT-autokey (Vig) | 5/24 | 20/24 | 20/24 |
| CT-autokey (Beau) | 6/24 | 21/24 | 21/24 |

### Key Findings

1. **PT-autokey CANNOT reach 24/24** — max 16/24 (no Bean), 13/24 (Bean=HARD). Sequential key dependency K[i]=PT[i-1] creates tight constraints.
2. **CT-autokey reaches 21/24 max** but NEVER 24/24. Hill-climbing ceiling is well below 24.
3. **Random baseline much lower than periodic**: PT-autokey max=7/24 (vs 14/24 periodic), CT-autokey max=5-6/24. Autokey is dramatically MORE constrained.
4. **All solutions have terrible quadgrams**: best -6.209/char. Multi-objective oracle question is moot since 24/24 is unreachable.

### Implications

- Autokey is NOT a viable route to bypass Bean period impossibility
- Autokey is MORE constrained than periodic keying due to sequential key dependencies
- If K4 uses autokey, the transposition must be from a structured family (not arbitrary)
- For JTS: autokey + arbitrary transposition is LESS dangerous than periodic for false positives

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_37_autokey_arbitrary_transposition.py`

---

## Part XI: Comprehensive Key Model Bean Analysis (E-FRAC-38)

E-FRAC-38 provides the definitive Bean constraint taxonomy for ALL key generation models.

### Models Analyzed

| Key Model | Bean Equality Survivors | Full Bean Survivors | Status |
|-----------|------------------------|---------------------|--------|
| Periodic (p=2-7) | N/A (period-dependent) | ZERO (E-FRAC-35) | **PROOF: ELIMINATED** |
| Progressive (k[i]=k[0]+iδ) | δ ∈ {0, 13} only | δ=0 mono (trivial), δ=13 ≈ period-2 | **BEAN-ELIMINATED** |
| Quadratic (k[i]=ai²+bi+c) | 52/676 (a,b) pairs | 0/676 | **BEAN-ELIMINATED** |
| Fibonacci (K[i]=K[i-1]+K[i-2]) | 26/676 seeds | 0/676 | **BEAN-ELIMINATED** |
| General recurrence | 17,680/456,976 eq | 2,892/456,976 full (0.63%) | **NOISE** (max <8/24) |
| PT-autokey | ~1.5% random perms | ~1.5% | **COMP. ELIMINATED** (max 16/24) |
| CT-autokey | ~1.8% random perms | ~1.8% | **COMP. ELIMINATED** (max 21/24) |
| **Running key** | **~6.5% of offsets** | **~1.7% of offsets** | **OPEN** |

### The Running Key Conclusion

Running key is the ONLY non-trivial structured key model that survives Bean constraints. All polynomial, recurrence, and progressive models are Bean-eliminated. This strongly focuses the remaining search on:

1. **Running key from unknown text + structured transposition** (JTS agent mandate)
2. **Non-standard key generation** (bespoke, position-dependent)
3. **Periodic keying at surviving periods {8,13,16,...}** — highly underdetermined

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_38_bean_key_model_constraints.py`

---

## Part XII: Running Key + Transposition Feasibility (E-FRAC-39/40/41/42)

E-FRAC-38 established that running key is the ONLY structured key model surviving Bean constraints. E-FRAC-39-42 quantify the feasibility of running key + arbitrary transposition as a K4 model.

### Bipartite Matching Feasibility (E-FRAC-39)

For each running key offset in reference texts, the max achievable crib score under ANY transposition is determined by bipartite matching: 24 crib positions (left) → 97 CT positions (right), edge exists iff CT[j] has the required letter for crib i.

**Result:** ~35% of English text offsets achieve 24/24 matching — extraordinarily permissive. After Bean filtering: ~0.6% are fully feasible. Carter text has 699-2,031 fully feasible offsets per variant. This is identical to random English text — bipartite/Bean constraints provide ZERO discrimination.

### Carter Is NOT Special (E-FRAC-40/40b)

SA-optimized transposition at feasible Carter offsets achieves quadgrams of -4.27/char (Vigenère best). BUT random keys (uniform and English-frequency) also achieve -4.40/char — the difference is only 0.13/char, within noise.

**Verdict:** The quadgram "signal" at Carter offsets is an SA optimization artifact. Any sufficiently long key can be paired with a transposition that produces locally English-looking text, because:
- SA optimizes the 73 non-crib positions for quadgrams
- 24 crib positions are fixed by bipartite matching (guaranteed 24/24)
- The non-crib positions have enough freedom to achieve good quadgrams regardless of the key

### Word-Level Discrimination (E-FRAC-41/42)

SA-optimized gibberish contains dictionary words, including crib-derived words (NORTHEAST, BERLIN) and words emerging from quadgram optimization (DISTINGUISHED, LABORATORY, UNIFORMED).

| Metric | English | SA Gibberish | Cohen's d | Perfect Sep.? |
|--------|---------|-------------|-----------|--------------|
| All words ≥6 chars | mean 10.7 [5-20] | mean 8.6 [3-17] | 0.56 | NO |
| Non-crib words ≥6 chars | mean 10.7 [5-20] | mean 6.9 [1-16] | 1.00 | NO |
| **Non-crib words ≥7 chars** | **mean 6.3 [1-14]** | **mean 3.0 [0-11]** | **1.14** | **NO** |
| Non-crib words ≥8 chars | mean 3.8 [0-9] | mean 1.4 [0-7] | 1.03 | NO |
| Composite (words×(1+cov)) | mean 16.2 | mean 9.5 | 1.03 | NO |
| Max word length | mean 10.2 [7-15] | mean 8.6 [6-13] | 0.81 | NO |

**Best metric: non-crib words ≥7 chars (Cohen's d = 1.14).** This is a LARGE effect size but with 70% overlap — meaning many SA gibberish values fall within the English range.

### N-Gram Scoring Provides Zero Discrimination (E-FRAC-43)

Bigram and trigram transition probability scoring was tested as an alternative automated discriminator. Models were trained on Carter text (117K alpha chars).

| Metric | English | SA Gibberish | Cohen's d |
|--------|---------|-------------|-----------|
| Bigram score | -1.118 | -1.096 | **-0.35** (SA better!) |
| Trigram score | -1.031 | -1.039 | 0.11 (no discrimination) |
| Quadgram score | -4.344 | -4.233 | **-0.65** (SA better!) |

SA gibberish is actually MORE n-gram-coherent than real English at all scales. This is expected: SA explicitly optimizes for quadgram fitness, and local n-gram coherence propagates to bigram/trigram levels. Real English has word boundaries, punctuation patterns, and less-common transitions that slightly REDUCE its n-gram scores compared to SA-optimized text.

### The Fundamental Limitation

At 97 characters (after removing spaces/punctuation from English), there is simply not enough text for reliable automated discrimination. SA quadgram optimization is powerful enough to produce genuine English words (not just crib-derived ones), text that scores well on ALL n-gram metrics, and the crib words themselves inflate word counts. The only fully reliable discriminator is **semantic coherence** evaluated by a human: does the text make sense as a message?

**Repro:**
- `PYTHONPATH=src python3 -u scripts/e_frac_39_running_key_bipartite.py`
- `PYTHONPATH=src python3 -u scripts/e_frac_40_carter_quadgram_screen.py`
- `PYTHONPATH=src python3 -u scripts/e_frac_40b_random_key_control.py`
- `PYTHONPATH=src python3 -u scripts/e_frac_41_word_discriminator.py`
- `PYTHONPATH=src python3 -u scripts/e_frac_42_refined_discriminator.py`

---

## Part XIII: Final FRAC Mandate Summary

### Complete Experiment Registry (43 experiments)

| ID | Topic | Verdict |
|----|-------|---------|
| E-FRAC-01 | Width-9 structural analysis | STRUCTURAL — lag-7 explained but no signal |
| E-FRAC-02 | Width-9 + non-periodic sub | ELIMINATED (underdetermination artifacts) |
| E-FRAC-03 | Width-9 non-columnar reads | ELIMINATED (high-period artifacts) |
| E-FRAC-04 | Width-9 × Width-7 compound | ELIMINATED (zero signal at p≤7) |
| E-FRAC-05 | Width-9 mixed alphabets | PT-col HARD ELIM; CT-col underdetermined |
| E-FRAC-06 | Width-11/13 columnar | ELIMINATED (identical to random) |
| E-FRAC-07 | Width-9 bimodal fingerprint | STRUCTURALLY INCOMPATIBLE |
| E-FRAC-08 | ALL widths bimodal | ZERO compatible at any width |
| E-FRAC-09 | Bimodal-compatible families | Only patch-based pass (if bimodal valid) |
| E-FRAC-10 | Strip + periodic sub | NOISE |
| E-FRAC-11 | Bimodal validity | ARTIFACT — scoring gradient |
| E-FRAC-12 | Width-9 strict re-eval | NOISE at discriminating periods |
| E-FRAC-13 | IC analysis | NOT DIAGNOSTIC (21.5th pctile) |
| E-FRAC-14 | Autocorrelation/DFT | NOT SIGNIFICANT after Bonferroni |
| E-FRAC-15 | Functional key models | NOISE (polynomial/recurrence) |
| E-FRAC-16 | Key distribution | Beaufort concentrated (p=0.003) → RETRACTED |
| E-FRAC-17 | Running key search | NOISE (7/24 = random) |
| E-FRAC-18 | Crib sensitivity | VALIDATED — cribs correct |
| E-FRAC-19 | Pre-ENE analysis | NOT SIGNIFICANT (Bonferroni p=1.0) |
| E-FRAC-20 | Residue conflict map | CONSISTENT WITH RANDOM |
| E-FRAC-21 | Fractionation proofs | ALL 10 FAMILIES ELIMINATED |
| E-FRAC-22 | Null cipher | NO HIDDEN MESSAGE |
| E-FRAC-23 | Beaufort key reconstruction | NO STRUCTURED KEY |
| E-FRAC-24 | Running key language profile | KKK impossible in natural text |
| E-FRAC-25 | Transposition entropy effect | RETRACTED — selection effect |
| E-FRAC-26 | Width-9 quadgram search | Bean-compatible but gibberish |
| E-FRAC-27 | Bean width profiling | Width-5,7 BEAN-ELIMINATED |
| E-FRAC-28 | SA key optimization | Underdetermination artifact |
| E-FRAC-29 | Width-6/8 crib scoring | NOISE, width-8 underperforms random |
| E-FRAC-30 | Width-10-15 scoring | ALL NOISE, all underperform random |
| E-FRAC-31 | Bean random perm analysis | Bean NOT INFORMATIVE |
| E-FRAC-32 | Simple transposition sweep | ALL ELIMINATED (below random) |
| E-FRAC-33 | Fitness landscape | SMOOTH but oracle INSUFFICIENT |
| E-FRAC-34 | Multi-objective oracle | Quadgram gap 0.93/char |
| E-FRAC-35 | Bean period impossibility | PROOF: periods 2-7 impossible |
| E-FRAC-36 | Bean-surviving periods | 175 FPs, all quadgram < -5.0 |
| E-FRAC-37 | Autokey + arbitrary trans | CANNOT REACH 24/24 |
| E-FRAC-38 | All key models Bean analysis | Running key ONLY survivor |
| E-FRAC-39 | Running key bipartite feasibility | MASSIVELY UNDERDETERMINED |
| E-FRAC-40 | Carter quadgram screening | Carter NOT special (SA artifact) |
| E-FRAC-40b | Random key control | Random key = Carter quadgrams |
| E-FRAC-41 | Word-level discriminator | WEAK (SA gibberish has words) |
| E-FRAC-42 | Refined discriminator (non-crib) | MODERATE (d=1.14, no perfect sep.) |
| E-FRAC-43 | Bigram/trigram discriminator | NO IMPROVEMENT (n-grams: d≤0.11) |

### Bottom Line

After 43 experiments covering every hypothesis in the FRAC mandate space, the conclusive finding is: **ZERO positive results survive.** K4's ciphertext is statistically indistinguishable from random text. Every structured key model except running key is Bean-eliminated. Every transposition family tested is noise or underperforms random. Running key + transposition is massively underdetermined — bipartite matching and Bean constraints provide zero discrimination among candidate (offset, transposition) pairs. SA quadgram optimization trivially achieves English-like quadgrams (-4.3/char) with ANY key, making Carter text indistinguishable from random as a running key source. No automated discriminator perfectly separates SA gibberish from real English at 97 characters: non-crib words ≥7 chars is the best (Cohen's d = 1.14), while n-gram scoring provides zero discrimination (SA gibberish is actually MORE n-gram-coherent than real English). **Semantic coherence via human evaluation is the ONLY fully reliable discriminator for final candidate acceptance.**

**The remaining viable hypothesis space for K4 is: running key from unknown text + structured transposition + Vigenère (or Beaufort) substitution.**

---

*Generated by agent_frac. Final update 2026-02-21. 43 experiments, ~62M+ configs + key/structural analysis + false positive characterization + Bean impossibility proof + autokey elimination + comprehensive key model taxonomy + running key feasibility + discriminator design (word + n-gram), ~8800 seconds total compute.*
*Methodology: All p-values use Monte Carlo simulation with ≥50,000 samples. Multiple testing correction uses Bonferroni where applicable. Corrected p-values account for number of trials: P(max ≥ X | N) = 1 - (1-p)^N.*
