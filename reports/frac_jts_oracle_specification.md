# JTS Oracle Specification — Final FRAC Deliverable

**Agent:** frac (FRAC role)
**Date:** 2026-02-21
**Based on:** E-FRAC-33, 34, 35, 36, 39, 40, 40b, 41, 42, 43
**Status:** FINAL — all discriminator experiments converged

## Purpose

This document specifies the multi-objective oracle for JTS (Joint Transposition Search). It is the synthesis of 11 experiments characterizing the false positive landscape and discriminator performance for arbitrary permutation search over K4's 97! transposition space.

## The Problem

When SA/hill-climbing optimizes over arbitrary transpositions (97! space), it trivially produces false positives that satisfy crib and Bean constraints:
- **Crib-optimized SA** (E-FRAC-33/34): 265 false 24/24+Bean solutions characterized
- **Quadgram-optimized SA** (E-FRAC-40/40b): quadgrams of -4.3/char achievable with ANY key
- **Running key + bipartite matching** (E-FRAC-39): ~700-2,000 feasible (offset, transposition) pairs per major text

The oracle must distinguish the REAL solution from these false positives.

---

## Tier 1: Hard Constraints (PASS/FAIL — filter before scoring)

These are necessary conditions. Any candidate failing these is immediately rejected.

| Constraint | Threshold | False Positive Rate | Source |
|-----------|-----------|-------------------|--------|
| Crib score | = 24/24 | N/A (search target) | Definition |
| Bean equality | k[27] = k[65] | ~3.85% of random perms pass | E-FRAC-26/31 |
| Bean inequality (21 pairs) | All k[a] ≠ k[b] | ~1.7% of random perms pass full Bean | E-FRAC-31 |

### Implementation Notes
- Bean constraints are variant-independent (work the same for Vigenère and Beaufort)
- Bean equality is cheap to check: `CT[inv_perm[27]] = CT[inv_perm[65]]`
- Check Bean equality FIRST (eliminates ~96% of candidates before expensive inequality checks)

---

## Tier 2: Automated Scoring (soft thresholds — rank candidates)

These metrics help rank candidates. None achieves perfect separation alone.

### 2a. Quadgram Score per Character

| Scenario | Best | Mean | Source |
|----------|------|------|--------|
| Real English (no spaces) | -4.12 | -4.34 | E-FRAC-43 |
| SA-optimized (quadgram-targeted) | -4.02 | -4.23 | E-FRAC-40 |
| SA-optimized (crib-targeted) | -5.77 | -5.96 | E-FRAC-34 |
| Random text | — | -6.43 | E-FRAC-34 |
| K4 ciphertext | — | -6.38 | E-FRAC-34 |

**Threshold:** > -4.84/char (actual English mean from K1-K3)

**CRITICAL CAVEAT:** This threshold is ONLY useful for crib-optimized search (where SA maximizes crib score, not quadgrams). If SA co-optimizes quadgrams, it trivially achieves -4.3/char with ANY key (E-FRAC-40b). In that case, quadgram score provides ZERO discrimination (Cohen's d = -0.65; SA gibberish scores BETTER).

**Recommendation:** If JTS uses a multi-objective fitness function that includes quadgrams, the quadgram threshold cannot be used as a discriminator. Use word counting instead.

### 2b. Non-Crib Word Count (≥7 characters)

| Scenario | Mean | Min-Max | Source |
|----------|------|---------|--------|
| Real English (no spaces) | 6.3 | 1-14 | E-FRAC-42 |
| SA-optimized gibberish | 3.0 | 0-11 | E-FRAC-42 |
| Random text | 0.0 | 0-0 | E-FRAC-42 |

**Cohen's d = 1.14 (LARGE effect) — the BEST automated metric.**

**Crib words to exclude** (16 words): EAST, NORTH, NORTHEAST, EASTNORTHEAST, BERLIN, CLOCK, BERLINCLOCK, LINER, LINE, LOCK, BLOC, STERN, ASTER, ASTERN, RLIN, ORTH

**Threshold:** ≥ 3 non-crib words of ≥7 characters

**Caveat:** SA gibberish can produce up to 11 non-crib words ≥7 chars (e.g., DISTINGUISHED, LABORATORY, UNIFORMED emerge from quadgram optimization). This threshold will have both false positives (SA gibberish passing) and false negatives (unusual English failing).

### 2c. Index of Coincidence

| Scenario | Mean | Source |
|----------|------|--------|
| Real English | 0.067 | E-FRAC-34 |
| Crib-optimized FP | 0.038 | E-FRAC-34 |
| K4 ciphertext | 0.036 | E-FRAC-13 |
| Random text | 0.038 | E-FRAC-13 |

**Threshold:** > 0.055

**Note:** IC is determined by the substitution key distribution, NOT the permutation. If the correct substitution produces English-frequency output, IC will be ≈ 0.067. IC is a useful filter for crib-optimized FPs (which have IC ≈ random) but does NOT help when SA co-optimizes for English-like plaintext.

### 2d. Metrics That DO NOT Discriminate

| Metric | Cohen's d | Why Not | Source |
|--------|-----------|---------|--------|
| Bigram transitions | -0.35 | SA gibberish scores BETTER | E-FRAC-43 |
| Trigram transitions | 0.11 | Essentially no discrimination | E-FRAC-43 |
| Quadgram score (SA-optimized) | -0.65 | SA gibberish scores BETTER | E-FRAC-43 |
| All words ≥6 chars (including cribs) | 0.56 | Too weak, crib words inflate | E-FRAC-41 |

**Do NOT add these to the oracle.** They provide no discrimination or anti-discrimination.

---

## Tier 3: Human Evaluation (THE Ultimate Discriminator)

**This is the ONLY tier that achieves PERFECT discrimination.** No automated metric at 97 characters can fully separate SA gibberish from real English.

### What to check:
1. **Does the plaintext read as coherent English?** (not just words, but connected meaning)
2. **Do the known crib regions make sense in context?** (EASTNORTHEAST and BERLINCLOCK should relate to surrounding text)
3. **Is the non-crib text grammatically valid?** (subject-verb-object structure, proper prepositions)
4. **Does the plaintext relate to known K4 themes?** (coordinates, directions, archaeological discovery, clocks)

### Why human evaluation is necessary:
SA quadgram optimization is powerful enough to produce:
- Real English words (DISTINGUISHED, LABORATORY, UNIFORMED)
- Good n-gram coherence at all scales (bigram, trigram, quadgram)
- Dictionary word coverage of up to 42% (vs English's 48%)
- Up to 11 non-crib words ≥7 characters

But SA CANNOT produce:
- Semantic coherence (words that form meaningful sentences)
- Grammatical structure (proper syntax)
- Contextual relevance (text that relates to K4's themes)
- Narrative flow (sentences that follow logically)

**The discriminant is not statistical — it's semantic.**

---

## Decision Tree for JTS Candidates

```
Candidate solution (permutation σ, key K)
│
├── Crib score = 24/24? ──NO──→ REJECT
│
├── Bean equality pass? ──NO──→ REJECT
│
├── Bean inequality pass? ──NO──→ REJECT
│
├── [If crib-optimized search]:
│   ├── Quadgram > -5.0/char? ──NO──→ REJECT (all 265 crib-FPs below -5.77)
│   ├── IC > 0.055? ──NO──→ REJECT
│   └── PASS → Continue to word check
│
├── [If quadgram-co-optimized search]:
│   ├── Quadgram score is NOT discriminating (skip)
│   └── Continue directly to word check
│
├── Non-crib words ≥7 chars ≥ 3? ──NO──→ LOW PRIORITY (but don't reject — some English segments have only 1)
│
└── HUMAN EVALUATION
    ├── Coherent English? ──NO──→ REJECT
    ├── Crib regions contextual? ──NO──→ REJECT
    └── YES → POTENTIAL SOLUTION (verify encryption parameters)
```

---

## Estimated False Positive Volumes

| Search Scenario | 24/24+Bean FPs | Pass Quadgram | Pass Words | Pass Human | Source |
|----------------|---------------|---------------|------------|------------|--------|
| Crib-optimized (period 5) | ~35/50 climbs | 0/35 | N/A | 0 | E-FRAC-34 |
| Crib-optimized (period 8+Bean) | ~44/50 climbs | 0/44 | N/A | 0 | E-FRAC-36 |
| Quadgram-co-optimized | ~100% of climbs | ALL pass | ~50-70% pass | 0 expected | E-FRAC-40 |

**Bottom line:** The automated filters (quadgram + IC for crib-optimized, word count for quadgram-co-optimized) will reduce candidates to a manageable number, but the FINAL acceptance criterion must be human semantic evaluation.

---

## Search Strategy Recommendations for JTS

1. **Use crib-optimized search with quadgram as a SECONDARY metric** (not co-optimized). This makes the automated oracle more effective:
   - 24/24+Bean candidates are rare (~50-90% of climbs at surviving periods)
   - Quadgram > -5.0 eliminates ALL tested FPs (0/265 pass)
   - Human evaluation only needed for the rare quadgram-passing candidate

2. **If co-optimizing quadgrams**, accept that automated filtering is weak:
   - Word count ≥ 3 non-crib words ≥7 chars is the only useful filter
   - ~30-70% of quadgram-co-optimized FPs will pass the word filter
   - Human evaluation will be the bottleneck

3. **Periodic key search should target period 8** (first Bean-surviving period with ≥2 cribs/var). Do NOT search periods 2-7 (Bean-impossible).

4. **Running key search from Carter text is NOT special** — any English text achieves the same results. If testing Carter, run random key control to validate.

5. **The discriminator limitation is fundamental at 97 characters.** No amount of metric refinement can replace semantic evaluation.

---

*Generated by agent_frac, 2026-02-21. Based on 43 experiments.*
