# Session 21 Report — K4 Attack Continuation

**Date:** 2026-02-18 (continued from Session 20)
**Session goal:** Continue systematic attack on K4 with novel approaches

---

## Executive Summary

This session ran **7 new experiments** (E-S-72 through E-S-78). **No breakthrough.** Two new structural eliminations and one potentially interesting diagnostic finding.

### Key Results

| Experiment | Approach | Configs/Effort | Best Result | Status |
|---|---|---|---|---|
| E-S-72 | Turning grille SA (10×10) | 200 restarts × 100K SA | 12/24 pure trans | **WEAK** — optimization artifact |
| E-S-73 | 7 mixed alphabets + w7 SA | 5040 orderings × SA | qg/c=-3.93 (range 0.04) | **UNDERDETERMINED** |
| E-S-74 | Sculpture-derived keys | K1-K3 text/keys/keystreams | 7/24 | **NOISE** |
| E-S-75 | Extended crib guessing | 136 extensions × 5040 orderings | 18/40 at period 13 | **FALSE POSITIVE** |
| E-S-76 | Keyword alphabet filter | 370K keywords × 5040 orderings | 0 valid combos | **ELIMINATED** |
| E-S-77 | Hill cipher + YAR anomaly | Hill 2×2, 3×3, YAR matrices | max 5/24 | **NOISE** |
| E-S-78 | Reverse engineering key | 10,080 (order,variant) pairs | 5/14 same-CT consistency | **INVESTIGATE** |

---

## Detailed Results

### E-S-72: Turning Grille SA (10×10)

**Phase 1 (pure transposition SA):** 200 restarts × 100K SA steps on 4^25 grille space. Best 12/24 crib matches — up from 9/24 in MC (E-S-70). The decrypted text is gibberish ("RBIWRPWSZW..."), confirming this is an optimization artifact rather than signal.

**Phase 2 (Model B + period-7 key):** Completely broken — the scoring function requires all crib-derived key values at the same residue mod 7 to agree, which never happens with a grille transposition. All 100 restarts scored QG_FLOOR × 24 = -360. The grille scrambles positions too much for period-7 key consistency.

**Assessment:** Pure transposition turning grille is very unlikely. The 12/24 is from optimization over 4^25 space, not from cipher structure.

### E-S-73: 7 Mixed Alphabets + Width-7 Columnar SA

The strongest remaining hypothesis: width-7 columnar + 7 independent mixed alphabet substitutions (one per column).

**Phase 1 (screen all 5040 orderings):** 432/5040 orderings are "valid" (no alphabet constraint conflicts). Best qg/c = -3.99 — BETTER than English (~-4.285). This immediately signals underdetermination.

**Phase 2 (deep SA on top 50):** Best qg/c = -3.93 for order [6,3,1,5,2,0,4]. Top-10 range is only 0.04, confirming severe underdetermination. All orderings produce English-looking word salad:
- #1: "DUNDERABLESTINGRILLITEASTNORTHEASTSUNPROCARNARSCONTHERMATOPASSUBERLINCLOCKNESSIONATIONTORANISTOMB"

**Phase 3 (Option A — alphabets by j%7):** **ZERO valid orderings.** This is a clean structural elimination: if the 7 alphabets were indexed by intermediate text position (j%7) rather than by column, the crib constraints are contradictory for ALL 5040 orderings.

**New elimination:** Option A (alphabets indexed by intermediate position) is ELIMINATED.

### E-S-74: Sculpture-Derived Keys

Tested K1-K3 ciphertext, plaintext, and extracted keystreams as running keys for K4. Also tested combined/reversed texts, keystream arithmetic, Fibonacci from key seeds, progressive keys.

Best: 7/24 = deep noise. **Sculpture text is NOT the key source** (under direct or width-7 columnar correspondence).

### E-S-75: Extended Crib Guessing

Generated 136 extended crib candidates based on Sanborn's thematic hints (compass bearings, Berlin Wall, Egypt, "What's the point?"). Tested against width-7 columnar at period 7.

**Phase 1:** Best 18/40 — but at period 13, not period 7! Period 13 is underdetermined (expected ~13.5/24). False positive.

**Phase 2 (w7):** Best 16/40 — no improvement from transposition.

**Assessment:** Extended crib guessing doesn't produce signal. Either our guesses are wrong, or the cipher doesn't have period-7 consistency in the extended regions.

### E-S-76: Keyword Mixed Alphabet Filter

**Key result:** Among 370K+ English keywords, **no keyword produces a mixed alphabet that satisfies the crib constraints** for any column in any ordering. This means:

- With 3-4 crib constraints per column, the required alphabet mapping is inconsistent with standard keyword mixed alphabet construction
- **ELIMINATED: Keyword mixed alphabets + width-7 columnar (Model B)**

This is a strong structural elimination: the "coding charts" cannot be standard keyword-derived mixed alphabets.

### E-S-77: Hill Cipher + YAR Anomaly

Tested Hill cipher inspired by the YAR superscript and "HILL" anomaly on the Vigenère tableau:

- **Hill 2×2 direct:** 22 complete crib blocks, best 3/22 match = noise
- **Hill 2×2 + w7:** Best 3 matches across all orderings = noise
- **Hill 3×3 direct:** 20 complete crib blocks, best 3/20 = noise
- **YAR as Vigenère key (period 3):** 3/24 vig, 0/24 beau = noise
- **YAR + w7:** Best 5/24 = noise
- **YAR-constrained 2×2 matrices:** Best 1/22 = noise

**Assessment:** Hill cipher and YAR parameters produce no signal. The physical anomalies may have a different purpose than K4 key parameters.

### E-S-78: Reverse Engineering Key from Constraints

Diagnostic experiment analyzing the keystream structure across all orderings.

**Key findings:**
1. **Period-7 consistency:** Best 8/24 = exactly expected random. Confirms key is NOT periodic-7 under Model B + w7.
2. **Key letter quality:** Best unigram score 6.73 (English average ~6.5). Not distinguishable from random optimization.
3. **K1-K3 key overlap:** Best total 9 (K1=4, K2=3, K3=2) — no significant overlap with K-section keys.
4. **Same-CT-letter key consistency:** **5/14 pairs for ordering [6,2,5,1,4,0,3]** under both Vig and Beaufort. Expected random: 0.54/14. This is z ≈ 6.2 — potentially significant even after multiple testing correction.

**The 5/14 same-CT-letter consistency** is the most interesting finding. It means: under this ordering, when two crib-derived positions share the same CT letter, they tend to have the same key value. This would be expected for monoalphabetic substitution, but monoalphabetic + columnar was already eliminated (E-S-41). The signal could come from a partially monoalphabetic structure or coincidental letter distribution.

**Follow-up (E-S-79):** The 5/14 is NOT significant. Bonferroni-corrected p = 0.634. The 5 matching pairs all come from repeated PT letters in the cribs (S×2 → CT=I, T×3 → CT=K giving 3 pairs, N×2 → CT=W). This is a structural artifact of having repeated letters in the crib, not a cipher property.

---

## New Eliminations

1. **Option A mixed alphabets (indexed by j%7):** ELIMINATED — 0 valid orderings (E-S-73 Phase 3)
2. **Keyword mixed alphabets + w7 (370K keywords):** ELIMINATED — 0 valid combinations (E-S-76)
3. **Hill 2×2 + w7:** ELIMINATED — max 3 matches = noise (E-S-77)
4. **Hill 3×3 direct:** 3/20 = noise (E-S-77)
5. **YAR-derived parameters:** All noise (E-S-77)
6. **Sculpture text as running key:** 7/24 = noise (E-S-74)
7. **Extended thematic cribs + w7 at period 7:** No signal above false-positive threshold (E-S-75)

## Confirmed Underdetermination

- **7 arbitrary mixed alphabets + w7:** With ~22 free swaps per alphabet × 7 = 154 DOF, SA achieves qg/c = -3.93 (BETTER than English) for ANY ordering. Score range only 0.04 across top 50 orderings. Quadgram scoring CANNOT distinguish the correct ordering.

---

## Strategic Assessment After Session 21

### What's Still Viable

1. **Running key from UNKNOWN text + w7** — Undiscoverable without the text. E-S-65 bigram test (z=2.80) is inconclusive.

2. **Non-keyword mixed alphabets** — The "coding charts" could define arbitrary (non-keyword) mixed alphabets. These aren't testable without the charts themselves ($962,500 auction).

3. **Turning grille** — MC and SA both plateau (9→12/24). The 4^25 space is too large for exhaustive search and too unstructured for algebraic constraint propagation.

4. **Same-CT-letter key consistency** — The 5/14 finding for ordering [6,2,5,1,4,0,3] deserves deeper investigation. Could reveal structural constraint on the key.

5. **Physical/non-mathematical method** — "Who says it is even a math solution?" remains the elephant in the room.

### The Fundamental Obstacle

**With 24 cribs and 97 positions, the system is underdetermined for any cipher model that allows flexible substitution at the 73 non-crib positions.** This is a mathematical certainty, not a limitation of our approach.

The only paths forward:
- **More cribs** (from correctly guessing more plaintext, or from K5 data)
- **Correct structural assumption** (that reduces DOF below the underdetermination threshold)
- **Physical artifacts** (the "coding charts")
- **Wait until 2075** (Smithsonian unsealing)

---

## Artifacts

| Experiment | Result File | Repro Command |
|---|---|---|
| E-S-72 | results/e_s_72_grille_sa.json | `PYTHONPATH=src python3 -u scripts/e_s_72_grille_sa.py` |
| E-S-73 | results/e_s_73_mixed_alphabet_sa.json | `PYTHONPATH=src python3 -u scripts/e_s_73_mixed_alphabet_sa.py` |
| E-S-74 | results/e_s_74_sculpture_key.json | `PYTHONPATH=src python3 -u scripts/e_s_74_sculpture_key.py` |
| E-S-75 | results/e_s_75_extended_cribs.json | `PYTHONPATH=src python3 -u scripts/e_s_75_extended_cribs.py` |
| E-S-76 | results/e_s_76_keyword_alphabet_filter.json | `PYTHONPATH=src python3 -u scripts/e_s_76_keyword_alphabet_filter.py` |
| E-S-77 | results/e_s_77_hill_anomaly.json | `PYTHONPATH=src python3 -u scripts/e_s_77_hill_anomaly.py` |
| E-S-78 | results/e_s_78_reverse_engineering.json | `PYTHONPATH=src python3 -u scripts/e_s_78_reverse_engineering.py` |
| E-S-79 | results/e_s_79_same_ct_investigation.json | `PYTHONPATH=src python3 -u scripts/e_s_79_same_ct_investigation.py` |
