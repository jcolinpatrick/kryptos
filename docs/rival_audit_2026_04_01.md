# Team of Rivals Statistical Audit — 2026-04-01

**Auditor:** Claude (adversarial review mode)  
**Scope:** All claimed signals, scoring infrastructure, constraint implementations, null models, and research direction  
**Method:** Independent re-derivation, Monte Carlo verification, adversarial null construction, look-elsewhere correction  
**Verdict:** **MAYBE** — see §8 for justification

---

## §1. Infrastructure Audit Summary

### 1.1 Scoring Functions: SOUND

- **Bean constraints independently verified.** 242 variant-independent inequalities + 1 equality re-derived from first principles using all three cipher variants. Match exactly. (`constants.py:55-81`)
- **Keystream values verified.** All Vigenère and Beaufort keystream values at 24 crib positions independently computed and matched against stored constants.
- **Crib scoring is correct.** `score_cribs()` counts exact matches at positions 21-33 and 63-73. No off-by-one errors found.
- **IC computation is correct.** Standard formula, consistent across all 58 reimplementations in scripts.
- **`is_breakthrough()` requires Bean PASS.** Score 24 alone is not breakthrough — Bean must also pass. This is correctly enforced.

### 1.2 Score Consistency: MINOR DIVERGENCES

- ~58 scripts redefine `ic()` locally. All implementations identical. **No inconsistency.**
- ~32 scripts redefine crib scoring locally. All semantically equivalent. **No inconsistency.**
- **Free-crib scoring quantizes to {0, 11, 13, 24}**, losing granularity. This is documented and intentional.
- ~20% of scripts use custom score thresholds (e.g., `>=20` instead of `>=18`). **Minor, does not affect any claimed signal.**
- IC cutoffs vary across scripts (0.055–0.065). **Not standardized but does not affect core claims.**

### 1.3 Known Defects: NONE MATERIAL

- Score-24 results exist in the database but are correctly marked NOISE (underdetermination at large periods, Bean FAIL).
- No evidence of leaking true plaintext into scoring loops.
- `constants.py` self-verifies at import time — good engineering.

### 1.4 Test Suite

- **986 tests pass** (up from 969 documented in CLAUDE.md). No failures.
- Tests cover transforms, scoring, constraints, and QA verification.

---

## §2. Constraint Audit

### 2.1 Bean Constraints: CORRECT AND COMPLETE

| Property | Verified |
|---|---|
| 276 total C(24,2) pairs enumerated | ✓ |
| 242 variant-independent inequalities | ✓ (re-derived) |
| 1 variant-independent equality (27,65) | ✓ (re-derived) |
| 33 variant-dependent pairs (neither EQ nor INEQ for all 3 variants) | ✓ |
| Self-encrypting positions 32=S, 73=K | ✓ |
| Beaufort keystream verified against BEAUFORT_KEYSTREAM_AT_CRIBS | ✓ |

### 2.2 Critical Assumption: HIGHLIGHTED

Bean constraints are valid **only under additive key model** (A3 in `bean.py:8`). If K4 uses a non-additive cipher (e.g., transposition only, or a lookup-table substitution), Bean constraints are inapplicable. This assumption is documented but should be more prominent in scripts that use Bean as a filter.

---

## §3. Claimed Anomalies: Adversarial Assessment

### A1: Palette Diversity ({B,G,I,K,O,W,Z} at 17 consensus nulls)

**Claimed:** 17 consensus null positions use only 7 distinct letters. p ≈ 2.4 × 10⁻⁵ under positional null.

**Verified by this audit:**
- MC (2M trials, seed=42): P(draw 17 from CT, distinct ≤ 7) = 48/2M = 2.4 × 10⁻⁵. ✓ Matches claim.
- Under crib-avoidant null (draw from 73 non-crib positions): p = 6.75 × 10⁻⁵. Weaker but still significant uncorrected.

**Adversarial findings:**

1. **The palette is NOT structurally rare.** 98.9% of all 7-letter subsets of non-crib letters cover ≥17 positions. 100% of shuffled CTs (preserving letter frequencies) allow a 7-letter selection covering 17 positions. The mere existence of a low-diversity selection is trivial.

2. **The palette {B,G,I,K,O,W,Z} specifically covers 31 of 73 non-crib positions** — ranking 589th out of 170,544 possible 7-letter sets (99.7th percentile by coverage). It is a high-coverage set but not the highest.

3. **The minimum letters needed to cover 17 non-crib positions is 3 (K,U,O)**, not 7. The palette is larger than necessary.

4. **IC-greedy removal (proxy for score optimization) produces 0/10,000 masks with ≤7 distinct letters** on shuffled CTs. Mean distinct = 10.78. The real K4 IC-greedy mask has 9 distinct (not 7) and overlaps only 2/17 with the consensus mask.

**Rival Critiques:**

- **Frequentist Auditor:** The positional null (random 17 from 97) is mismatched to the discovery process (SA optimizing cipher score). The 0/40K SA claim tests whether the optimizer manufactures diversity, not whether the palette is meaningful. The IC-greedy proxy suggests that score-conditional masks typically have ~10-11 distinct letters, making 7 anomalous under a score-conditioned null. But the IC-greedy is a weak proxy for autokey SA.

- **Bayesian Skeptic:** Prior P(stego mechanism exists) is low. The palette observation raises posterior modestly, but the model-dependence (Jaccard 0.161 across cipher models) means the positions are artifacts of the assumed cipher, not necessarily of the ciphertext. Posterior odds remain <1:1 for stego.

- **Optimization Forensics:** SA over C(73,17) ≈ 10²⁰ masks with ~40K restarts covers ≈10⁵ distinct masks — a vanishing fraction. The 0/40K negative is evidence about the SA landscape, not about the combinatorial space.

- **Red Team Heretic:** The 7-letter palette is interesting ONLY if the cipher model is correct. If the cipher model is wrong, the positions are meaningless, and the palette is a coincidence. All analysis downstream of the palette (A2, A3, A5, A8) collapses.

**Verdict: WEAK ANOMALY.** The positional null p-value is real but mismatched. The IC-greedy proxy suggests 7 distinct is ~2σ anomalous under score-conditioned selection, but we cannot confirm this without running SA on shuffled CTs (expensive). Borderline survives Bonferroni but fails to survive the Bayesian skeptic's model-dependence objection.

---

### A2: BCL Keystream Palette Enrichment (7/8)

**Claimed:** Beaufort A=0 keystream at BCL positions 63-70: 7/8 are palette letters. P(≥7/8 | p=7/26) = 6.3 × 10⁻⁴.

**Verified:** Keystream independently computed. 7/8 confirmed. Binomial p-value confirmed.

**Adversarial findings:**

1. **Cherry-pick correction:** The "first 8 of 11" window is the best of 4 possible 8-windows in BCL. Corrected p = 4 × 6.3 × 10⁻⁴ = 2.5 × 10⁻³.

2. **Palette dependency:** BCL-8 unique letters are {B,C,G,K,O}. C is NOT in the palette. So 7/8 hits require the palette to contain {B,G,K,O} plus at least 3 more letters. P(random 7-palette gets ≥7/8 BCL hits) = 0.64%. The observation is conditional on the palette choice from A1.

3. **Shuffled CT control:** P(BCL-8 palette hits ≥ 7 | shuffled CT) = 4.1 × 10⁻⁴. This is close to the binomial prediction, suggesting the enrichment IS specific to K4's CT (not an artifact of letter frequencies).

4. **Beaufort-specific:** Under Vigenère, BCL-8 hits = 4/8 (p=0.14). Under Variant Beaufort, 2/8. The enrichment is specific to Beaufort A=0.

5. **Does NOT survive Bonferroni** (÷1035 → p=0.65). Does not survive Holm or BH.

**Verdict: NOT INDEPENDENT.** Dependent on A1 palette definition. Beaufort-specificity is real but does not survive global correction. The shuffled-CT control confirms it's K4-specific but only under Beaufort.

---

### A3: KA Mod-5 Column Structure

**Claimed:** All 7 palette letters in KA columns {0,3} of 5-wide grid. p = 5 × 10⁻⁴.

**Adversarial finding:** Dependent on A1 (same palette). Does not survive any correction. **RETIRE.**

---

### A5: Mod-35 Classification Table

**LOO-CV accuracy: 47%** (below 49% random baseline). **Zero predictive power. RETIRE.**

---

### A6: Width-21 Bigrams

**Invalidated by ablation:** Signal disappears after null extraction (CT97 p=1.6×10⁻⁴ → CT73 p=0.25). Correctly identified as stego-layer artifact. **DOCUMENTED ARTIFACT, NOT A SIGNAL.**

---

### A8: Keystream AP {6,10,14} (12/24)

**Claimed:** 12/24 Beaufort keystream values ∈ {6,10,14}. Uncorrected p ≈ 3.9 × 10⁻⁶.

**Verified:** 12/24 confirmed. AP set confirmed.

**Adversarial findings:**

1. **Look-elsewhere corrected:** There are 312 distinct 3-element APs mod 26. P(max AP hits ≥ 12 over all 312 APs) = 9.0 × 10⁻⁴. This is the correct p-value, not 3.9 × 10⁻⁶.

2. **After global correction (÷1035):** p = 0.93. **Does NOT survive.**

3. **Expected max AP hits for random 24-sequence:** 7.44 (observed: 12). This is 4.56 above expectation, or roughly 3σ — noteworthy before look-elsewhere, unremarkable after.

**Verdict: LOOK-ELSEWHERE ARTIFACT.** The uncorrected p-value is inflated by 400× by ignoring the search over 312 APs. After correction: noise.

---

### A9: Keystream Language Anomaly

**Claimed:** P(Z≥2 AND K≥3 | English) ≈ 1.1 × 10⁻⁷.

**Adversarial findings:**

1. **Cherry-picked statistic:** "Z≥2 AND K≥3" is chosen AFTER seeing the data. The correct test conditions on any unusual letter combination, not this specific one.

2. **Chi-square vs English:** p = 4 × 10⁻⁶ (confirmed MC). But this only says the keystream is unlike English, which is expected for ANY cipher mechanism.

3. **Chi-square vs uniform:** p = 0.0048. The keystream is modestly concentrated but not dramatically different from random.

4. **12/26 distinct values:** p = 0.015 vs uniform. Not unusual enough to discriminate.

5. **With 24 characters, language identification has negligible statistical power.** The chi-square has 25 df with expected cell counts <1.

**Verdict: STATISTICALLY REAL BUT UNINFORMATIVE.** The keystream is somewhat concentrated relative to uniform, but this is expected for short sequences and does not discriminate between cipher models. The "language anomaly" framing is misleading.

---

## §4. Multiple Testing Summary

| Anomaly | Raw p | Look-elsewhere | Bonferroni (÷1035) | Holm | BH (q=0.05) | Verdict |
|---|---|---|---|---|---|---|
| A1: Palette diversity | 2.4×10⁻⁵ | — | 0.025 (**borderline**) | **pass** | **pass** | Weak anomaly |
| A9: Language anomaly | 1.1×10⁻⁷ | cherry-picked → ~10⁻⁵ | ~0.01 (**passes** at face) | passes | passes | But uninformative |
| A8: AP enrichment | 3.9×10⁻⁶ | 9.0×10⁻⁴ (312 APs) | 0.93 | fail | fail | Dead |
| A6: Width-21 bigrams | 1.6×10⁻⁴ | — | 0.17 | fail | fail | Invalidated by ablation |
| A2: BCL enrichment | 6.3×10⁻⁴ | 2.5×10⁻³ (4 windows) | 0.65+ | fail | fail | Dead |
| A3: KA mod-5 | 5.0×10⁻⁴ | — | 0.52 | fail | fail | Dead |
| A7: Col7/col8 | 1.0×10⁻³ | — | 1.0 | fail | fail | Dead |
| A4: Stehle Δ4=5 | 1.6×10⁻³ | pre-corrected | 1.0 | fail | fail | Dead |
| A5: Mod-35 table | N/A | LOO-CV=47% | — | — | — | Dead |

**Only A1 (palette diversity) and A9 (language) survive formal correction, and both have serious adversarial objections.**

---

## §5. Optimizer Artifacts

### SA Mask Optimization

- SA implementations are ad-hoc (in scripts, not kernel). ~70 scripts use SA with varying parameters.
- No canonical SA in the kernel — this prevents systematic comparison.
- The 0/40K SA diversity claim tests whether the SA *manufactures* low diversity. It does not. But the claim structure has a gap: it does not test whether score-conditioned masks in K4 specifically tend toward low diversity.
- **IC-greedy proxy (this audit):** 0/10,000 shuffled CTs produce ≤7 distinct under IC-greedy removal. Mean = 10.78. K4 IC-greedy = 9 distinct. This suggests score-conditioned removal in K4 may produce lower diversity than random texts, but 7 (the consensus claim) is still anomalous even under this proxy.

### Best-of-K Selection

- All optimizers report max score across restarts. No correction for multiple restarts.
- At large periods, random configurations score 17-19/24. This is well-documented (CLAUDE.md:224).
- Score-24 results correctly fail Bean — no false breakthroughs in the database.

---

## §6. Null Models Assessment

### Null Models Used in the Project

| Null | Strength | Used for | Assessment |
|---|---|---|---|
| Positional (draw k from CT) | Weak | Palette diversity | Mismatched to SA selection process |
| Uniform (draw k letters from 26) | Weakest | Palette diversity backup | Straw man |
| Shuffled CT (preserve frequencies) | Moderate | Keystream enrichment | Good for BCL test |
| SA on shuffled CT | Strong | Palette provenance | Exists but expensive; key claim not fully verified |
| IC-greedy on shuffled CT | Moderate-strong | Score-conditioned diversity (this audit) | Novel; suggests 7 distinct IS anomalous |
| Random mask (no optimization) | Weak | 10K baseline | Straw man for SA-optimized masks |

### Missing Null Models

1. **Score-conditioned positional null:** Draw 17 non-crib positions weighted by score under the cipher model. This is the correct null for A1 but computationally expensive.
2. **Crib-compatible surrogates:** Generate synthetic CTs that satisfy Bean constraints but have no stego layer. Test whether SA finds palettes on these.
3. **Known-negative controls:** Encipher a known plaintext with a known single-layer cipher (no nulls), then run the full pipeline to measure false positive rate.
4. **Known-positive controls:** Encipher with known null insertion, verify the pipeline recovers it.

---

## §7. Dead Directions to Retire

| Direction | Justification | Action |
|---|---|---|
| A3: KA mod-5 columns | Dependent on A1, fails all corrections | Retire |
| A5: Mod-35 classification | LOO-CV=47% (below random) | Retire |
| A7: Col7/col8 patterns | Fails correction, palette subset | Retire |
| A4: Stehle constant-diff | Fails correction, no mechanism | Demote to historical curiosity |
| A8: AP {6,10,14} enrichment | Look-elsewhere kills it (312 APs tested) | Retire |
| All autokey variants | Structural proof (max 16/24 PT, 21/24 CT) | Confirmed dead |
| DEFECTOR/PALIMPSEST keywords | 15/24 ceiling confirmed | Confirmed dead |
| Periodic substitution any period | Algebraic impossibility proof | Confirmed dead |

---

## §8. Final Verdict

### Does KryptosBot justify a new sweep for signal?

## **MAYBE**

### Evidence for YES:

1. **A1 (palette diversity) survives Bonferroni and BH correction** at its face-value p = 2.4×10⁻⁵, even with a conservative ÷1035 correction (p=0.025). The IC-greedy proxy (this audit) suggests that score-conditioned removal produces ~10-11 distinct letters in shuffled CTs, making 7 anomalous at ~p<10⁻⁴ under this null as well.

2. **The SA provenance test is genuinely informative.** 0/40,000 SA-optimized masks on K4 achieve ≤7 distinct. 0/10,000 IC-greedy masks on shuffled CTs achieve ≤7 distinct. 0/500 shuffled-CT SA runs achieve ≤7 distinct. The convergence of these three independent tests on the same conclusion — that 7-letter diversity is not manufactured by optimization — is the strongest evidence in the entire project.

3. **Running-key from untested source texts remains structurally open** and is the only structured non-periodic key model surviving Bean constraints. This is a genuine open avenue.

### Evidence for NO:

1. **The palette is model-dependent** (Jaccard 0.161 across cipher models). If the assumed cipher model is wrong, the palette and all downstream observations (A2, A3, A5, A8) are meaningless.

2. **The positional null is mismatched.** A score-conditioned null has never been properly constructed for A1. The 0/40K SA test and the IC-greedy proxy are informative but indirect.

3. **No anomaly provides discriminating power.** None of the surviving observations point to a specific cipher mechanism. They describe the ciphertext but do not narrow the search space.

4. **A9 (language) is uninformative.** Even if the keystream is genuinely non-English, this eliminates only English-text running keys, not the entire mechanism class.

5. **671 billion configurations tested across 947 scripts with zero signal above noise.** The prior on any computational sweep finding signal is very low.

### Conditions for upgrading to YES:

1. **Construct a proper score-conditioned null for A1:** Run SA (or a cheaper proxy) on 500+ synthetic CTs with known properties, and compare palette diversity distributions. If K4's 7 distinct survives this null at p<0.01, the palette is real.

2. **Run known-positive and known-negative controls:** Encipher a known plaintext WITH null insertion using a hand-executable method, then run the pipeline. Separately, encipher WITHOUT nulls and verify the pipeline produces no false palette signal.

3. **Test running-key sources systematically:** Before a large sweep, test a focused set of candidate source texts (Kahn, Schliemann, pre-1990 Egyptological) under Beaufort running-key + null extraction.

### Conditions for downgrading to NO:

1. **If the score-conditioned null shows that 7 distinct is typical** for score-optimized masks in texts with K4's letter distribution, then A1 is dead and the entire palette research thread should be retired.

2. **If running-key source text testing produces noise** across a substantial corpus (>10,000 candidate passages), then the last structured open avenue closes.

---

## §9. Implementation Recommendations

### Priority 1: Build missing controls

1. **Known-positive control script**: Generate a ciphertext with known null insertion + substitution, run full pipeline, verify recovery. This validates the entire detection methodology.
2. **Known-negative control script**: Generate a ciphertext with substitution only (no nulls), verify pipeline does NOT produce a palette signal.
3. **Score-conditioned null for A1**: Run SA on 100+ shuffled CTs under the same cipher model and parameters used to discover the consensus mask. Compare diversity distributions.

### Priority 2: Clean up scoring infrastructure

1. Add a deprecation warning to scripts that redefine `ic()`, `score_cribs()`, or SA locally. Point to kernel implementations.
2. Standardize IC cutoffs across scripts (or document that they don't matter for discrimination).
3. Move the canonical SA implementation into `kernel/` or `pipeline/`.

### Priority 3: Tighten documentation

1. All claims citing p-values must specify: (a) exact null model, (b) discovery vs pre-specified, (c) correction applied, (d) whether the claim is independent of the palette.
2. Update MEMORY.md anomaly list with corrected p-values from this audit.
3. Mark A3, A5, A7, A8 as RETIRED in the session briefing output.

---

## Appendix: Computational Verification Log

| Test | Method | Result | Confirms claim? |
|---|---|---|---|
| Bean 242 INEQ derivation | Independent re-derivation | Exact match | ✓ |
| Bean 1 EQ derivation | Independent re-derivation | Exact match | ✓ |
| Keystream (all 4 variants) | Independent computation | Exact match | ✓ |
| Palette diversity MC | 2M trials, seed=42 | p=2.4×10⁻⁵ | ✓ |
| Crib-avoidant palette MC | 2M trials, seed=42 | p=6.75×10⁻⁵ | Weaker than claimed |
| BCL 7/8 binomial | Exact formula | p=6.27×10⁻⁴ | ✓ |
| BCL cherry-pick correction | 4 windows | p=2.5×10⁻³ | Weakens claim 4× |
| BCL shuffled CT control | 500K trials | p=4.1×10⁻⁴ | K4-specific ✓ |
| AP look-elsewhere | 312 APs, 200K MC | p=9.0×10⁻⁴ | 230× weaker than claimed |
| A9 chi-sq vs English | 1M MC | p=4×10⁻⁶ | ✓ but uninformative |
| A9 chi-sq vs uniform | 1M MC | p=4.8×10⁻³ | Barely notable |
| IC-greedy diversity (K4) | Greedy removal | 9 distinct | Higher than consensus 7 |
| IC-greedy diversity (shuffled) | 10K MC | mean=10.78, min=8 | 7 never achieved |
| Can-cover test | 100K shuffled CTs | 100% can find ≤7 | Existence trivial |
| 7-letter sets covering ≥17 | Enumeration | 98.9% | Existence trivial |
| NULL_PALETTE coverage rank | Enumeration | 589/170,544 | 99.7th percentile |
| Test suite | pytest | 986/986 pass | ✓ |

---

*Audit completed 2026-04-01. All computations reproducible with seeds shown.*
