# Width-21 Probe 2 — Row-Major Specificity

**Date:** 2026-05-02
**Predecessors:** `width21_probe1_reproduction_2026_05_02.md`,
`width21_w_removal_disproof_2026_05_02.md`
**Script:** `scratch/probe2_width21_offsets.py`
**Trial budget:** 200,000 MC trials per cell; 16 predeclared cells.

---

## Verdict

**STRONG POSITIVE.** The width-21 anomaly is **row-major-reading-order
specific** and **strengthens under cyclic rotation**. All 4 row-major
tests survive Bonferroni 16× correction; all 12 non-row-major tests are
at baseline null.

This is the fingerprint of a positional / structural mechanism at
width 21 — most plausibly a transposition or route layer with row-major
reading. It is **not** the fingerprint of a substitution-only cipher
(which would show offset-symmetric results across reading orders).

---

## Predeclared parameter set (locked before reading)

- Width: 21
- Reading orders: `rows-then-cols`, `cols-then-rows`, `boustrophedon`,
  `diagonal` (anti-diagonal)
- Row offsets: 0, 3, 7, 11
- Statistic: count of repeated vertical bigrams at width 21 in the
  reordered text
- Null: 200K MC letter-multiset shuffles per cell
- Bonferroni multiplier: 16

## Results

| reading order | offset 0 | offset 3 | offset 7 | offset 11 |
|---|---:|---:|---:|---:|
| **rows-then-cols** | **z=+4.48** (Bonf 0.0025) | **z=+4.49** (Bonf 0.0019) | **z=+5.09** (Bonf 0.0002) | **z=+5.68** (Bonf 0.0001) |
| cols-then-rows | z=+0.30 | z=-0.29 | z=+0.30 | z=-0.89 |
| boustrophedon | z=-0.29 | z=+0.30 | z=-0.29 | z=-0.89 |
| diagonal | z=+1.50 | z=+0.90 | z=+1.50 | z=-0.29 |

The signal is *exclusively* in `rows-then-cols`. Every other reading
order is at baseline null — indistinguishable from random shuffles.

## Three structural findings

### 1. Row-major specificity

`rows-then-cols` is the only reading order where the anomaly survives.
A substitution-only cipher would show offset-symmetric results across
reading orders (because each position's output is independent of any
reading-order choice you impose post-hoc on the CT). A transposition /
route at width 21 would specifically light up under one reading order —
the order that "undoes" or matches the cipher's own grid traversal.

### 2. Cyclic strengthening

Within row-major, the anomaly STRENGTHENS at offsets 7 (z=5.09) and 11
(z=5.68) versus offsets 0 (z=4.48) and 3 (z=4.49). Each offset rotates
CT by that many characters before computing the bigram statistic; the
introduced wrap-around bigrams happen to MATCH the linear-bigram
structure rather than dilute it.

This suggests **cyclic width-21 structure**: the text behaves like a
97-character loop, and certain cuts reveal the structure better than
others. This is consistent with a periodic transposition / route at
width 21 with cyclic key.

### 3. Crib-region row alignment

Both EAST and BERLIN crib regions start at column-0 row boundaries of
the width-21 grid:

- EAST starts at position 21 = 1 × 21 + 0 → row 1, column 0
- BERLIN starts at position 63 = 3 × 21 + 0 → row 3, column 0

This is structurally suggestive but not unique to width 21 (any divisor
of `63 − 21 = 42` does this — divisors are {1, 2, 3, 6, 7, 14, 21, 42}).
The empirical bigram fingerprint distinguishes width 21 from its
co-divisors: width 7 is marginal (p=0.036), width 14 is null (p=0.10),
width 42 is null (3 repeated, MC mean 2.6, p=0.51 in Probe 1).

## What this points at

The cipher hypothesis class consistent with all three findings:

**Width-21 transposition / route, row-major reading, where EAST (start
at row 1) and BERLIN (start at row 3) crib regions land on column-0
boundaries.**

Specific testable variants:

1. **Width-21 columnar transposition** — write PT row-major into a
   21-column grid, reorder columns by some key permutation π,
   read out column-by-column to produce CT. Inverse: write CT into the
   columnar grid, reorder back, read row-major.
2. **Width-21 route cipher** — write PT into a 21-column grid, read out
   along some non-linear route (spiral, diagonal, boustrophedon). The
   routes we tested as *output* readings of CT are all null, but the
   *input* writing route hasn't been tested directly here.
3. **Width-21 cyclic / Wheatstone-like cipher** — the cyclic
   strengthening particularly fits this class.

## What's already tested vs. not

- `e_col_pure_exhaustive.py` covers columnar widths **2–20** with
  crib-position branch-and-bound. **Width 21 is not in that range.**
- `f_width21_bigram_73char_v1.py` (the script we just ran) computes
  statistics at width 21 but does not search the columnar key space.
- The exhaustion log mentions an `e_grid31_k3_widths_keyed_03` script
  with description "Test K4 with K3's exact widths (21, 28) but with
  KEYED column orders" — but the script file is not on disk. Its
  results, if any, are not reachable from current code.

Net: **width-21 columnar transposition with crib-constrained
branch-and-bound has not been exhaustively tested** against the current
kernel.

## Recommended next move

Extend `e_col_pure_exhaustive.py` (or write a focused width-21 variant)
to attack columnar at width 21 with the same crib-position pruning. The
keyspace is `21!` ≈ 5e19 in principle, but the crib constraints
(EAST=positions 21–33, BERLIN=positions 63–73, plus self-encrypting
positions 32 and 73) eliminate the vast majority of permutations early.
Estimated runtime: 10–60 min on 28 workers, depending on pruning
effectiveness.

Pre-launch checklist:
- [ ] Predeclared scoring threshold: `crib_score == 24 AND bean_passed
      AND ngram_score >= -3.5 AND p_adjusted <= 0.01` (Stage A bar).
- [ ] Bonferroni multiplier: keyspace explored × prior search count.
- [ ] Synthetic recovery test: plant a known width-21 columnar key,
      verify the harness recovers it before claiming a negative result
      on the real K4 search.
- [ ] If positive: red-team-disprover before promoting to candidate
      status (per `feedback_red_team_before_swings.md`).
- [ ] If negative: result stays in elimination ledger as "width-21
      columnar with row-major direct positional crib mapping —
      eliminated under crib-constrained branch-and-bound."

The W observation, the palette retirement, the 2026-03-15 stego claim,
and Probe 1+2 results all converge on this single hypothesis class.
Either width-21 columnar (or near variant) decrypts K4, or this entire
line of evidence is a structural coincidence under multi-anomaly search.

That's a clean test. Either outcome is informative.

---

*Last updated 2026-05-02. Probe 2 returns strong positive: width-21
structure is row-major-specific and cyclic. Recommended next step:
crib-constrained columnar attack at width 21.*
