# Session 11 Elimination Report (Feb 2026)

## Summary

Nine new experiments (E-S-09 through E-S-17) tested in this session.
**ALL returned NOISE or confirmed existing knowledge.** No breakthrough.

## New Eliminations

### E-S-09: Bifid 6×6 Algebraic (ALL periods 2-49)
- **Eliminated**: periods 3, 7, 9, 13, 15, 23, 25, 27, 29, 31 (10/48)
- **Surviving**: 38 periods (insufficient cross-block constraints)
- Period 9 is NEW elimination (grid[row(A),row(S)] forced to W and N simultaneously)
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_09_bifid_algebraic.py`
- Artifact: `results/e_s_09_bifid_algebraic.json`

### E-S-10: Additive Row+Column Grid Key (widths 2-48)
- **Model**: key[i] = row_key[i//W] + col_key[i%W] mod 26
- **ELIMINATED** all meaningful widths (2-21, 32-48 have algebraic contradictions)
- Widths 22-31 "pass" only because ENE and BC blocks share no row/column (disconnected constraint graph)
- Instant algebra (0.003s)
- Artifact: `results/e_s_10_additive_grid_key.json`

### E-S-11: Running Key + Columnar Transposition (widths 5-10)
- **STILL RUNNING** (width 7 in progress)
- Width 5: best 9/24 (Model B Vig, cia_charter)
- Width 6: best 10/24 (Model B Vig, nsa_act_1947)
- Width 7: best 9/24 so far
- 9 running key texts × 4 models × all permutations
- Artifact: `results/e_s_11_running_key_transposition.json` (when complete)

### E-S-12: Non-Standard Reading Orders (102 patterns)
- Tested: identity, reverse, boustrophedon, column-first, spiral, diagonal, S-curve (widths 5-14), plus reverses
- Best at period 7: 11/24 (excess +2.8)
- **VERDICT: NOISE**
- Artifact: `results/e_s_12_reading_orders.json`

### E-S-13: Keyword-Derived Transpositions
- 89 keywords × columnar + Myszkowski + double columnar
- 11,684 total configs (5,700 double columnar pairs)
- Best: 17/24 at period 12 (TABLEAU+FORCES) — **underdetermined period, meaningless**
- At meaningful periods (≤7): all at noise floor
- **VERDICT: NOISE**
- Artifact: `results/e_s_13_keyword_transposition.json`

### E-S-14: Crib Perturbation Test
- Shifted each of 24 crib positions by ±1
- **Maximum improvement: +1** (noise)
- Block shifts (ENE ±3, BC ±3): no improvement over baseline
- Bean constraint verified at (0,0) shift: PASS
- **VERDICT: Cribs are correctly indexed. The 14-17/24 ceiling is NOT from crib errors.**
- Artifact: `results/e_s_14_crib_perturbation.json`

### E-S-15: Creative Key Generation (287 hypotheses)
- Tested: date digits, coordinates, word positions, Fibonacci/primes, K1-K3 CT/PT as running key, keyword + date combos
- Best: 6/24 (K2_CT as Beaufort running key at offset 164) — within extreme-value noise for ~270 offset trials
- **VERDICT: NOISE**
- Artifact: `results/e_s_15_creative_keys.json`

### E-S-16: SA over Keyspace (no transposition)
- 73 free key positions + quadgram fitness
- 50 restarts × 500K steps × 2 variants
- Vigenère: qg/c=-3.533 (BETTER than English -4.285) — confirms underdetermination
- Beaufort: qg/c=-3.548
- PT is English fragments, not coherent: "TIONICATIONABLESSOV..."
- **VERDICT: Underdetermination artifact. 73 free DoF is too many.**
- Artifact: `results/e_s_16_sa_keyspace.json`

### E-S-17: Extraction/Steganographic Patterns
- Skip patterns (every Nth), position-based (primes, Fibonacci), conditional extraction
- Embedded clue search ("POINT", "BERLIN", "EGYPT", etc.) in all skip patterns
- Only trivial 4-letter words found (SOLI, AWIN, RACK, TOSS, FILO)
- **VERDICT: NO HIDDEN ENGLISH in CT**
- Artifact: `results/e_s_17_extraction_patterns.json`

## Key Conclusions

1. **Crib positions are CORRECT** (E-S-14). The persistent ceiling is real.
2. **Underdetermination is severe**: with 73 free positions, SA trivially finds English (E-S-16).
3. **All mathematical cipher models tested fail** at meaningful periods.
4. **No steganographic signal** in the raw CT (E-S-17).
5. **Additive grid keys eliminated** for all meaningful widths (E-S-10).
6. **Keyword-derived transpositions** show no signal beyond noise (E-S-13).

## Remaining Viable Hypotheses

1. Running key from **unknown text** (can't test without the text)
2. **Turning grille** as transposition (partially tested, needs systematic constraint-guided search)
3. **Non-standard cipher** that doesn't fit any tested model
4. **Physical/procedural** cipher ("not even a math solution" — Sanborn)
5. Key derived from **dates/coordinates** combined with an untested cipher structure
6. The lag-7 autocorrelation signal (z=3.036) remains **UNEXPLAINED**

## Experiment Status

| ID | Description | Status | Best Score | Time |
|----|-------------|--------|------------|------|
| E-S-06 | Double columnar + Vig | DONE (noise) | 16/24 p7 | ~8h |
| E-S-08 | SA perm + quadgram | RUNNING | 15/24 p7 | ~2h+ |
| E-S-09 | Bifid algebraic | DONE | 10/48 elim | 0.02s |
| E-S-10 | Additive grid key | DONE (elim) | N/A | 0.003s |
| E-S-11 | Running key + trans | RUNNING (w7) | 10/24 | ~1h+ |
| E-S-12 | Reading orders | DONE (noise) | 11/24 p7 | 0.1s |
| E-S-13 | Keyword transpositions | DONE (noise) | 17/24 p12* | 6.4s |
| E-S-14 | Crib perturbation | DONE (confirmed) | +1 max | 0.05s |
| E-S-15 | Creative keys | DONE (noise) | 6/24 | <1s |
| E-S-16 | SA keyspace | DONE (artifact) | -3.53 qg/c | 217s |
| E-S-17 | Extraction patterns | DONE (no signal) | 4-letter | <1s |

*17/24 at underdetermined periods only; at p≤7 all are at noise floor.
