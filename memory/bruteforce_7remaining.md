# Brute-Force 7 Remaining Null Positions (2026-03-15)

## Experiment Summary

With 17 consensus null positions fixed, exhaustively searched for the 7 remaining
positions to complete a 24-null mask.

**Model**: extract 73 -> inv_col7 -> DEFECTOR:AZ_beau autokey -> crib score

## Tasks Completed

### Task 1: Cluster-Constrained (1,344 masks)
- Clusters from SA variation: A={38-45} pick 3, B={55,56} pick 1, C={87,88} pick 1, D={93-96} pick 2
- **Best: 15/24 (264 masks), all ene=7/13 bcl=8/11**
- All remaining 1,080 masks = 14/24

### Task 2: Wider Cluster (11,440 masks)
- Any 7 from union {38-45, 55, 56, 87, 88, 93-96}
- **Best: 15/24 (264 masks)**
- Below-14 scores appear outside cluster constraints

### Task 3: EXHAUSTIVE Unconstrained (231,917,400 masks, 7.0 min, 550K/s)
- Any 7 from all 56 non-consensus, non-crib positions (C(56,7) = 231.9M)
- **Best: 15/24 (396 masks). ZERO masks above 15/24.**
- 24-core multiprocessing, 421.6 seconds total
- Score distribution: 36% at 0/24, 31% at 1/24, 14% at 2/24, tapering to 0.0002% at 15/24

### Task 4: Variant Testing (17 variants on all masks >= 14/24)
- DEFECTOR:AZ_beau:col7 is the ONLY config reaching 15/24
- All other keyword/alphabet/cipher/width combinations <= 14/24
- Tested: DEFECTOR/KRYPTOS/KOMPASS/ABSCISSA/COLOPHON/PARALLAX, AZ/KA, vig/beau, col0/5/6/7/8/9/11/13

## Structural Analysis of 396 15/24 Masks

### Decomposition: 378 + 18 = 396
**88-path (378 masks)**:
- A: any 3 from {38,39,40,41,42,43,44} (C(7,3)=35, but only 21 yield 15/24)
- B: any 1 from {54,55,56}
- C: position 88 (REQUIRED)
- D: any 2 from {93,94,95,96}
- Formula: 21 * 3 * 6 = 378

**87-path (18 masks)**:
- A: EXACTLY (38,39,45) -- the only triple that works with 87
- B: any 1 from {54,55,56}
- C: position 87
- D: any 2 from {93,94,95,96}
- Formula: 1 * 3 * 6 = 18

### CRITICAL INSIGHT: Score is mask-independent
ALL 396 masks produce IDENTICAL crib matches:
- ENE: 7/13 (positions 0,2,3,7,9,10,12 match: E_ST___T_EA_T)
- BCL: 8/11 (positions 2-9 match: __RLINCLOCC, missing B,E at start and K at end)

The 7 varying positions have ZERO EFFECT on which cribs match. The 9 failing positions
(6 ENE + 3 BCL) produce the same wrong letters regardless of mask.

### Stable plaintext (65/73 positions)
`MDZUCHMXLTAHDEPSTUVCTQEAXTGIMZQAKJMORGXCHJBYYXISNRLINCLOCCT_UJ_GL___L__T_`
Only 8 positions vary across masks (all in the tail, positions 59-72).

## Conclusion
The 15/24 ceiling is **structural to the model**, not caused by incorrect null positions.
The DEFECTOR:AZ_beau + col7 + null_mask hypothesis is **exhaustively explored**.
No combination of 7 remaining positions from any of 56 candidates can exceed 15/24.

## Files
- Scripts: `scripts/campaigns/f_bf7_tasks12_v1.py`, `f_bf7_task3_parallel_v1.py`
- Results: `results/bruteforce_7remaining_tasks12.json`, `results/bruteforce_7remaining_task3.json`, `results/bruteforce_7remaining_complete.json`
