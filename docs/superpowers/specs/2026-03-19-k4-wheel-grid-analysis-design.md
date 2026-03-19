# K4 4×24 Wheel Grid Analysis

## Hypothesis

K1 and K2 share the same grid format and cipher method (Vigenère on 31-col panel), differing only in keyword. If K3 and K4 follow the same parallel, they share the same grid format (24-row code chart) and transformation (double rotation), differing in keyword — with K4 adding "a bit of stego" (null insertion).

K4's 97 characters written into a 4-column × 24-row grid (matching K3's 24-row chart height) produces 96 cells with 1 overflow character. That overflow is a delimiter. Each row is a rotatable ring of 4 letters (Jefferson wheel cipher). The stego layer may be separable by finding the rotation configuration that concentrates null positions into specific columns.

## Grid Construction

### Delimiter handling — test BOTH:

**Model A (last char overflow):** 96 chars fill the 4×24 grid, position 96 (`R`) is the delimiter. CT used = `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCA`.

**Model B (first char overflow):** Position 0 (`O`) is the delimiter, 96 chars fill the grid. CT used = `BKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`.

### Grid filling
Write CT into the grid column-by-column, bottom-to-top (same reading direction as K3's code chart): first 24 chars fill column 1 from row 24 up to row 1, next 24 fill column 2, etc.

## Attack Phases

### Phase 1 — Static Pattern Analysis

For each model (A, B), build the 4×24 grid and annotate every cell:
- Consensus null position (17 fixed: {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
- Null palette letter ({B,G,I,K,O,W,Z})
- W position ([20,36,48,58,74] in CT97)
- Crib position (ENE: 21-33, BCL: 63-73)

Report: distribution of each tag across the 4 columns. Any natural clustering without rotation?

### Phase 2 — Wheel Search

Each row of 4 letters can rotate by {0, 1, 2, 3} positions. Full space: 4^24 ≈ 2.8×10^14 — too large for exhaustive search.

**Phase 2a — Targeted rows only.** Identify which rows contain consensus null positions or W positions. Rotate only those rows exhaustively (typically ~12-15 rows). 4^15 ≈ 1.07B — large but feasible with fast scoring. If too slow, limit to 4^12 ≈ 16.7M by fixing rows that have no special positions.

**Phase 2b — Beam search all rows.** Beam width 2000, assign row offsets one at a time (bottom-up to match K3 reading direction), scoring after each row assignment.

**Phase 2c — Simulated annealing.** Random restarts with null-concentration objective function. 10K restarts × 5K steps.

### Phase 3 — Stego Separation

For every configuration from Phase 2 where null concentration exceeds a threshold:
1. Extract the "clean" columns (fewest consensus nulls)
2. Extract the "dirty" columns (most consensus nulls)
3. Try Vigenère/Beaufort decryption on the clean column text with thematic keywords (KRYPTOS, PALIMPSEST, ABSCISSA, DEFECTOR, etc.)
4. Score the decrypted text for English quality

### Scoring Functions

1. **Null concentration** — Gini coefficient or max-column-share of the 17 consensus null positions across 4 columns. Perfect separation = all 17 in one column (score = 1.0). Uniform = 4.25 per column (score = 0.0).
2. **W alignment** — Number of W positions landing in the same column (max = 5).
3. **Palette concentration** — Same as null concentration but for all 35 null palette positions.
4. **Quadgram quality** — Standard n-gram scoring on vertical 24-char column reads.
5. **Composite** — Weighted sum: 0.4 × null_concentration + 0.3 × quadgram + 0.2 × palette + 0.1 × W_alignment.

### Search Space Summary

| Phase | Configs per model | Total (×2 models) |
|-------|------------------|--------------------|
| 2a (targeted rows, ~12) | ~16.7M | ~33.4M |
| 2b (beam, all 24) | ~192K (pruned) | ~384K |
| 2c (SA, 10K×5K) | ~50M | ~100M |

All feasible on 28 cores.

## Output

### Script
`scripts/k3_continuity/e_k4_wheel_grid_24x4.py` — implements all 3 phases for both models (A, B).

### Viewer
Extend `tools/k3_jefferson_viewer.html` with a K4 tab showing the 4×24 grid with null/W/crib annotations and the same rotation controls.

### Results
Write to `results/e_k4_wheel_grid_24x4.json` with: model (A/B), phase, best configs, scores, column texts.

## Success Criteria

- **Breakthrough**: A rotation configuration where consensus nulls concentrate in 1-2 columns AND the remaining columns produce English-quality text under Vigenère/Beaufort with a thematic keyword.
- **Signal**: Null concentration significantly better than random expectation (>2× Gini).
- **Noise**: All configurations produce uniform null distribution and gibberish columns.

## Constraints

- Import constants from `kryptos.kernel.constants` (never hardcode CT/cribs)
- Use `get_default_scorer()` for n-gram scoring
- Consensus null positions from MEMORY.md (17 fixed + 7 varying)
- Test both A=0 and A=1 for any Beaufort operations
