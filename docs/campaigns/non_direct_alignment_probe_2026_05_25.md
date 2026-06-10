# Non-Direct-Alignment Probe — Pre-Registration (2026-05-25)

**alignment_model:** `non_direct_alignment`
**Tier:** secondary_exploratory (no provenance artifact; motivated by installation grammar, not a disclosed key)
**Author persona:** escape-room / physical-installation analyst
**Runner:** `scripts/_uncategorized/e_non_direct_alignment_probe_2026_05_25.py`
**Output:** `results/non_direct_alignment_probe_2026_05_25.json`

## Hypothesis
An outer layer REORDERS the 97 carved characters before the inner cipher
decrypts, so cribs do NOT sit at carved CT positions in the intermediate text.
Cribs remain at canonical PLAINTEXT positions 21-33 / 63-73 (Sanborn placed
them in the *message*). Bean constraints are RE-DERIVED from each reordered CT
against the canonical crib dictionary.

## Why this slice is OPEN (not the closed proof)
The universal proof closes "ANY transposition + single PERIODIC key" over all
97! permutations. To stay off that surface:
- NO 97! enumeration. Alignment universe is a NAMED bounded set (below).
- NO free period sweep. Inner cipher = a BOUNDED named keyword set (installation
  lore) x 3 variants x 2 alphabets. A fixed small keyword set is materially
  different from "all periods", so the universal periodic proof does not apply.

## Alignment universe (generative rule + exact size)
Deterministic, de-duplicated permutations of indices 0..96:
- `identity` (direct-model control) and `reverse` (reflected read).
- For each motivated width w in {4,5,6,7,8,11,13,14,21,24} (prime-near
  rectangles, carved-panel widths 14/21, Berlin-Clock row counts 4/11, small
  columnar widths): write CT row-wise into a w-wide grid (ghost-padded), then
  read by 5 routes — column LR, column RL, serpentine row, anti-diagonal,
  spiral CW. Ghost cells dropped.
**Resolved at runtime:** n_alignments = **52** (after de-dup), n_inner_keys =
144, universe_size = **7488 cells**.
universe SHA-256 = `7a9ac67336cd37e2f7be75c59d549b75618395c47a4bcd515d652232996ae6aa`
(covers the ordered (name, index-tuple) enumeration of all 52 permutations).

## RESULT (clean null — slice closed)
- Real best crib_score = **6 / 24** (grid6_antidiag / var_beaufort / ABSCISSA,
  Bean FAIL), tied across several alignments.
- Null (B=30 random perms, full 144-key inner universe each): max = 6,
  mean = 4.17. Real best (6) = null max; P(random perm best >= 6) = **0.100**.
- ZERO candidates reached crib >= 12 (Bean never even evaluated as pass).
- **Verdict: CLEAN NULL.** This installation-motivated slice of
  non_direct_alignment (52 named reorderings x 144 lore keywords) carries no
  signal. Scope-explicit, hash-documented closure. The broader
  non_direct_alignment space (other alignments, non-periodic inners) remains
  OPEN.

## Inner cipher universe (bounded)
24 keywords (KRYPTOS, PALIMPSEST, ABSCISSA, BERLIN, CLOCK, BERLINCLOCK, EAST,
NORTHEAST, SHADOW, FORCES, LUCID, MEMORY, INVISIBLE, DIGETAL, INTERPRETATU,
POSITION, IQLUSION, UNDERGROUND, LAYERTWO, SANBORN, LANGLEY, COMPASS, LODESTONE,
MENGENLEHREUHR) x {Vigenere, Beaufort, Var-Beaufort} x {AZ, KA} = 144 inner keys.

## Scoring & thresholds
Per (alignment, inner-key): crib_score (0-24) at 21-33/63-73, bean_passed
(re-derived from CT_perm; only checked when crib>=12), ngram. A candidate is a
DISPROOF target — not a solution — at crib>=18. Promotion requires ALL of:
crib >= 18 AND bean_passed AND beats null max-of-N AND ngram support.

## Null calibration
B=30 random permutations of the 97 chars, each scored over the FULL 144-key
inner universe; record per-perm best crib. p = P(random perm best-inner >=
real best). Expected per-perm best crib under random ~6-9 (24 crib slots,
1/26 chance each, max over 144 correlated keys); a real best in that band is a
clean null.

## Stop rule
Single bounded run. If real best crib does NOT exceed the null max-of-N with a
Bean PASS and ngram support, the slice is a CLEAN NULL — record universe hash +
scope and close this slice of non_direct_alignment. No expansion of the
keyword set or widths post-hoc (that would launder breadth).
