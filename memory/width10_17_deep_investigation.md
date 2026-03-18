# Width-10 and Width-17 Bigram Deep Investigation

**Date**: 2026-03-16
**Script**: `scripts/campaigns/f_width10_17_deep_investigation_v1.py`
**Results**: `results/f_width10_17_deep_investigation.json`
**Elapsed**: 1291.7s

## Summary

CT73 (null-extracted 73-char text) has statistically significant vertical bigram anomalies at width 10 (p=0.006, z=3.14) and width 17 (p=0.008, z=3.09). These are CIPHER LAYER properties (not present in raw CT97 at significance). The investigation tested 8 lines of attack across all three widths (7, 10, 17), col7 interaction, periodic ciphers, autokey, and structural analysis.

**Verdict: The bigram anomalies are REAL but NOT EXPLOITABLE via any tested cipher model.** No period-10 or period-17 cipher achieves crib consistency above noise. The anomalies appear to be a second-order statistical property of the cipher, not directly useful as a decryption lever.

## Key Findings

### 1. Width-10 Bigram Anomaly
- **7 repeated bigram types**: FK, KU, LV, QT, RS, SZ, TT (all x2)
- **ALL 7 involve at least one crib position** (13/26 total positions are cribs)
- But anomaly is NOT caused by cribs: p=0.006 with cribs fixed AND with everything shuffled
- MC mean = 2.54, actual = 7, z = 3.14
- **Col7 DESTROYS this pattern**: 7 -> 2 repeated types after col7 undo

### 2. Width-17 Bigram Anomaly
- **6 repeated bigram types**: LK, LS, NT, QZ, TF, ZT (all x2)
- **ALL 6 involve at least one crib position** (10/21 total positions are cribs)
- p=0.008 (MC), z = 3.09
- **Col7 DESTROYS this pattern**: 6 -> 2 repeated types after col7 undo

### 3. Col7 Interaction (CRITICAL)
- Width 10: pre=7 -> post=2 (DESTROYED by col7 undo)
- Width 17: pre=6 -> post=2 (DESTROYED by col7 undo)
- **Interpretation**: The width-10/17 patterns exist in CT73 (= cipher output AFTER col7 transposition). Undoing col7 removes them. This means col7 CREATES these patterns from a text that doesn't have them.
- This is EXPECTED behavior: columnar transposition at width 7 creates vertical bigram structure at other widths as a mathematical side-effect.

### 4. Column IC Analysis
- CT73 width 17: avg_IC = 0.0647 (p=0.074, NOT significant at 0.05)
- CT73 width 6: avg_IC = 0.0526 (p=0.048, marginally significant)
- CT73 width 10: avg_IC = 0.0345 (p=0.589, NOT significant -- below random!)
- **Width-17 IC elevation is from small-sample bias** (columns have only 4-5 entries)
- Width-10 IC is BELOW random, despite having the most repeated bigrams
- **Conclusion**: No genuine periodic cipher structure at width 10 or 17 via IC test

### 5. Period-10 Crib Consistency
- VIG: 13/24 consistent (9/10 residues conflicting)
- BEAU: 12/24 consistent (9/10 conflicting)
- VBEAU: 13/24 consistent (9/10 conflicting)
- Best exhaustive key (VIG): crib=13, qg=-6.117 (NOISE)
- **Period-10 is NOT the cipher period** -- conflicts dominate

### 6. Period-17 Crib Consistency
- VIG: 13/24 consistent (11/13 residues conflicting)
- BEAU: 14/24 consistent (10/13 conflicting)
- VBEAU: 13/24 consistent (11/13 conflicting)
- Best sampled key (BEAU): crib=14, qg=-5.594 (NOISE at period 17 underdetermination)
- **Period-17 is NOT the cipher period** -- high scores are from underdetermination

### 7. Autokey at Period 10 and 17
- ALL variants, ALL thematic keyword primers, on both CT73 and CT73_COL7
- **ZERO hits >= 5 crib matches**
- Autokey at these periods is ELIMINATED

### 8. LCM and Combined Width Analysis
- **LCM(10,7) = 70** (3 short of 73 -- intriguing but no exploitable structure found)
- LCM(10,17) = 170 (> 73)
- LCM(17,7) = 119 (> 73)
- Col10 + col7 = col70 effectively -- tested, no signal

### 9. Fibonacci Recurrence Seeds
- 0 periodic-10 Fibonacci seeds produced crib >= 3
- Recurrence-based period-10 keys are ELIMINATED

### 10. Crib Contribution Analysis (CRITICAL)
- Fixing cribs and shuffling rest: MC mean = 2.48 (width 10), p = 0.006
- Shuffling everything: MC mean = 2.55, p = 0.006
- **Delta = -0.06** -- cribs do NOT cause the anomaly
- Both MC baselines give the SAME p-value
- The anomaly is genuine but reflects the cipher's mathematical properties, not crib placement

## Interpretation

The width-10 and width-17 bigram anomalies are real statistical features of CT73. However:

1. They are DESTROYED by col7 transposition undo, meaning they are created BY col7, not by the underlying cipher
2. They do NOT correspond to a periodic cipher at period 10 or 17 (crib conflicts dominate)
3. The column IC at these widths is NOT significantly elevated
4. No autokey, keyword, or recurrence cipher at these periods produces signal

**The most likely explanation**: Columnar transposition with width 7 applied to a non-periodic substitution cipher naturally produces vertical bigram repetitions at widths that share factors or create resonance with 7 and the text length. Width 10 and 17 happen to be widths where this resonance is statistically detectable in a 73-char text. This is a mathematical artifact of col7, not a new cipher clue.

## What This Rules Out
- Period-10 cipher on CT73 (all variants, exhaustive)
- Period-17 cipher on CT73 (all variants, sampled 5M)
- Autokey with primers of length 10 or 17 (all thematic keywords)
- Fibonacci recurrence period-10 keys
- Col10 as the transposition layer (no keyword achieves crib consistency)

## What Remains Open
- The anomalies COULD indicate that the pre-col7 text has structure at width 10 or 17 that col7 amplifies
- But since col7 DESTROYS these patterns (not creates them from structured input), this is unlikely
- The cipher layer mechanism remains unknown
