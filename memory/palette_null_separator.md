# Palette Null/Non-Null Separator Analysis (2026-03-15)

## Task
Investigate what distinguishes the 17 consensus null palette positions from the 18 non-null palette positions, among the 35 K4 positions where CT[p] is in {B,G,I,K,O,W,Z}.

## Scripts & Results
- `scripts/campaigns/e_palette_null_separator_v1.py` -> `results/palette_null_separator.json`
- `scripts/campaigns/e_palette_null_separator_v2.py` -> `results/palette_null_separator_v2.json`
- `scripts/campaigns/e_col8_null_mask_test.py` -> `results/col8_null_mask_test.json`

## KEY FINDING 1: col%8 in {0,1} => ALL NULL (among palette)
- 8 palette positions have grid column % 8 in {0,1} (cols 0,1,8,9,16,17,24,25)
- ALL 8 are consensus nulls (100%)
- Hypergeometric P = 0.001033 (1 in 968)
- MC confirmed: 0.001054

### CRITICAL: col%8 in {0,1} positions count to exactly 24 in K4
- Grid columns with col%8 in {0,1} = {0,1,8,9,16,17,24,25}
- K4 has exactly 24 positions at these columns
- HOWEVER: this mask REMOVES 5 CRIB POSITIONS (21,28,29,66,67) => INVALIDATED as actual null mask
- The "19/24 at period 20" scores are UNDERDETERMINED NOISE (period >= 17, all keywords produce identical keystream)

## KEY FINDING 2: col7 column 1 (pos%7=1) => ALL NULL (among palette)
- 5 palette positions in col7 column 1 (K4 positions 1,8,36,78,85)
- ALL 5 are consensus nulls (100%)
- Hypergeometric P = 0.019 (1 in 52)
- This is a subset of the col%8 finding

## KEY FINDING 3: col7 row structure
- Row 0: 4 palette, ALL null
- Row 5: 1 palette, null
- Row 7: 1 palette, null
- Row 4: 3 palette, ALL non-null
- Row 6: 4 palette, ALL non-null
- Row 13: 1 palette, non-null
- Mixed rows: 1,2,8,10,11,12

## KEY FINDING 4: No simple separator exists
- Best single feature: position itself (24/35, 11 errors)
- No modular arithmetic, letter identity, or grid coordinate alone achieves < 11 errors
- No 2-feature combination achieves < 3 errors (exhaustive boolean search)
- The null/non-null distinction among palette positions is NOT determined by a simple 1-2 feature rule

## KEY FINDING 5: Structural observations
- 0/17 null palette positions are in cribs (consistent with model)
- 4/18 non-null palette positions are in cribs (30,31,70,73 = forced non-null)
- W is 80% null (4/5); K is 25% null (2/8); Z is 25% null (1/4)
- K4[0,1,2] are all null (first 3 chars = "OBK")
- Null clusters: {0,1,2}, {58,59}, {74,75}, {84,85}
- Null neighbors: null palette positions have 30.3% null neighbors (vs 17.5% expected)

## KEY FINDING 6: Position mod 7 = 1 is null-only (= col7 column 1)
- All 5 palette positions with pos%7=1 are null
- Non-palette positions at pos%7=1 (15,22,29,43,50,57,64,71,92) are NOT null
- The rule applies ONLY within the palette subset

## KEY FINDING 7: col%8 in {0,1} all-null among palette does NOT mean all-null overall
- Of the 24 K4 positions at col%8 in {0,1}, only 8 are consensus nulls
- The remaining 16 include 5 crib positions and 11 other non-null positions
- The col%8 pattern is specific to PALETTE positions, not a general null rule

## Interpretation
The null/non-null distinction within palette positions is NOT determined by any simple geometric, modular, or letter-based rule. The separation requires knowledge of:
1. Whether the position is in a crib (forces non-null for 4 positions)
2. Some additional criterion for the other 31 palette positions (14 non-null + 17 null)
3. The col7 structure partially correlates (col7-col-1 is all-null) but doesn't fully determine

The most likely interpretation is that the null/non-null distinction comes from the CIPHER LAYER, not the STEGANOGRAPHIC LAYER. The palette defines which letters CAN appear at null positions (the eligible set). The actual 24 null positions are determined by the interaction between the plaintext, the cipher key, and the null-insertion algorithm. The palette is a CONSEQUENCE of how nulls are generated (e.g., from a constrained character source), not a PREDICTOR of which positions are null.
