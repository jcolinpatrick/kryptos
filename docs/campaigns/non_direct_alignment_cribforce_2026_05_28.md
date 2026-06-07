# Non-Direct-Alignment Crib-Forcing Closure — Pre-Registration (2026-05-28)

**alignment_model:** `non_direct_alignment`
**Tier:** secondary_exploratory (no provenance artifact; the alignment universe
is installation-grammar-motivated, not a disclosed key).
**Author posture:** disproof-engine closure. Prior is ~0; the expected and
intended outcome is a CLEAN NULL that extends the elimination certificate.
**Runner:** `scripts/campaigns/f_non_direct_alignment_cribforce_2026_05_28.py`
**Output:** `results/non_direct_alignment_cribforce_2026_05_28.json`
**Test:** `tests/test_non_direct_alignment_cribforce.py`

## What this closes that prior work left open

Two prior artifacts bound this region but leave one cell open:

1. **2026-05-25 non_direct_alignment probe**
   (`docs/campaigns/non_direct_alignment_probe_2026_05_25.md`) ran the same 52
   named reorderings but with **fixed keywords** as the inner cipher (best crib
   6/24, clean null, p=0.100). It never crib-FORCED a periodic key.
2. **E-FRAC-36 / E-FRAC-55** ran crib-forcing + n-gram discrimination at the
   Bean-surviving periods, but only under the **identity** reordering (I = CT).
   This produced the project's preregistered-thresholds doctrine (forced
   24/24+Bean solutions are gibberish, quadgram/char < -5.0).

**Open cell:** crib-FORCING a periodic key over the 51 NON-identity reorderings
at the Bean-surviving periods. Neither prior artifact covers it.

## Why this is OPEN, not the closed universal proof

The universal proof eliminates "ANY transposition + single periodic key" at 17
of 25 periods; periods {8,13,16,19,20,23,24,26} **survive** (Bean is not a
filter there). We stay strictly inside that survivor set and use a NAMED,
hash-documented bounded alignment universe (no 97! enumeration, no free period
sweep). At the survivor periods the only discriminator is n-gram on the forced
solution — exactly the discriminator E-FRAC-36 established, here applied across
the previously-untested reordering axis.

## Self-filtering property (why it is cheap and well-posed)

Under reordering π, the forced key residue at class r uses I[j] = CT[π[j]].
When ≥2 cribs share a residue class they must independently force the SAME key
value. For a random π this is satisfied with probability ≈ (1/26)^(#collisions):

| period | free residues | crib collisions | tractability |
|--------|---------------|-----------------|--------------|
| 8      | 0             | 16              | fully forced; consistency ~ (1/26)^16 |
| 13     | 0             | 11              | fully forced |
| 16     | 0             | 8               | fully forced |
| 19     | 4             | 9               | exhaustive (26^4 free), but consistency ~ (1/26)^9 |
| 26     | 3             | 1               | exhaustive (26^3 free), consistency ~ 1/26 (the null-bearing period) |
| 20     | 7             | —               | **SA-DEFERRED** (free > 4 cap in solve_periodic) |
| 23     | 6             | —               | **SA-DEFERRED** |
| 24     | 5             | —               | **SA-DEFERRED** |

Almost every reordering is pruned at the residue-consistency check, so the test
sharply isolates the rare reorderings that are even periodic-key-compatible
with the cribs, then asks whether any reads as English.

## Scope boundary (honest)

- **IN:** periods {8,13,16,19,26} — solved exhaustively by
  `kryptos.kernel.masking.solve.solve_periodic` (free residues ≤ 4) with an
  identity NullMask applied to the reordered text I = π(CT).
- **DEFERRED (NOT closed here):** periods {20,23,24} require SA/local search
  over 5-7 free residues; this mirrors `solve_periodic`'s own
  `max_free_exhaustive=4` boundary. Recorded as SA-deferred with proven free
  counts, not claimed closed.

## Universe

Reuse `build_alignment_universe()` from the 2026-05-25 runner verbatim → 52
de-duplicated named reorderings. Universe SHA-256 of the (name, period-set,
variant, alphabet) enumeration recorded at runtime; the reordering SHA-256 must
equal the 2026-05-25 value
`7a9ac67336cd37e2f7be75c59d549b75618395c47a4bcd515d652232996ae6aa`.

Inner: periods {8,13,16,19,26} × {Vigenere, Beaufort, Var-Beaufort} × {AZ, KA}.

## Discriminator and PRE-REGISTERED promotion gate

Under crib-forcing, crib_score is 24 for every residue-consistent cell and Bean
auto-passes (constraints are derived from the same cribs). Therefore the ONLY
discriminator is n-gram on the plaintext. A cell is promoted to GENUINE
CANDIDATE (stop and escalate) iff ALL hold:

1. residue-consistent (crib_score == 24) AND `bean_passed` (auto, but verified);
2. quadgram **per-char ≥ -4.5** on the full 97-char plaintext
   (`docs/preregistered_thresholds_2026_04_08.md`; E-FRAC-36 false positives
   capped at -5.0);
3. total n-gram score strictly exceeds the reordering-aware null max-of-N
   (see null);
4. E0b K-set mean distance ≤ **2.31**
   (`kryptos.kernel.scoring.e0b.CALIBRATED_SIGNAL_MAX_DISTANCE`, GAP-03 p≤1e-6).

All four are necessary. Any cell clearing all four halts the run for adversarial
review (red-team-disprover + statistical-auditor) BEFORE any further claim.

## Null calibration (reordering-aware)

B = 5000 random permutations of the 97 chars (seed 20260528), each run through
the identical crib-forcing inner universe; per perm record the best n-gram score
(total and per-char) among its residue-consistent + Bean-passing cells (None if
no consistent cell). Report:
- count of consistent null perms (expected concentrated at p=26, ~1/26 ≈ 4%);
- null n-gram distribution (max, mean, percentiles);
- p = P(random perm best n-gram ≥ real best n-gram).
B is large because residue-consistency is rare; parallelized across all cores.

## Stop rule

Single bounded run. If no cell clears the four-part gate, the slice is a CLEAN
NULL: record the universe hash + scope, extend the non_direct_alignment
certificate to the crib-forcing periodic-inner case at the exhaustive survivor
periods, and close. The {20,23,24} SA cell remains explicitly OPEN. NO post-hoc
expansion of the alignment universe, period set, or keyword set (that would
launder breadth).

## RESULT (clean null — slice closed)

Reordering SHA-256 verified equal to the 2026-05-25 value
`7a9ac67336cd37e2f7be75c59d549b75618395c47a4bcd515d652232996ae6aa` (comparable
universe). Of the 52 named reorderings, only **period 26** admits any
residue-consistent cell (12 distinct reorderings, 15 cells); periods
{8,13,16,19} admit **zero** consistent cells — no named grid reordering is
periodic-key-compatible with the cribs there.

- **Best forced plaintext quadgram = -5.575/char**, far below the -4.5
  pre-registered English floor (genuine English runs ~-4.0/char) and below
  E-FRAC-36's -5.0 false-positive cap. This is the decisive, portable
  disqualifier: even the best crib-consistent reordering reads as gibberish off
  the cribs.
- It is also below the random-permutation null **maximum** (-5.483/char;
  total -515.45 vs real best -524.07), so `null_beats_real = True` — the real
  reordering sits *below* the null max under the only well-posed comparison
  (max-of-universe vs max-of-universe). No enrichment.
- E0b K-set mean distance 6.4-7.3 at the top cells (vs the 2.31 calibrated
  internal filter) — a secondary, project-internal disqualifier, not
  independent English evidence.
- **0 cells cleared the four-part promotion gate.**
- **Verdict: CLEAN NULL.**

### Note on the runner's nominal p (non-inferential)

The first run printed `p=0.0066` (real best exceeds 99.3% of random
single-perm bests). Per statistical-auditor review (2026-05-28) this is an
**artifact, not signal**: (i) it compares a max over 12 consistent real
reorderings against per-single-permutation null bests (order-statistic depth
mismatch), and (ii) its denominator was diluted by ~4,277 cipher-incompatible
permutations scored as non-exceeding; conditioned on the 723 consistent null
perms it is ~4.6%, and under a depth-matched reference the real best falls below
the null maximum. The runner now reports `null_beats_real` (the honest
one-number summary) and a clearly-labelled `p_conditioned_on_consistent_null`.
The CLEAN NULL verdict is gate-based and p-independent.

### Scope of this closure

CLOSES: crib-forcing periodic inner over the 52 hash-locked named reorderings at
Bean-surviving **exhaustive** periods {8,13,16,19,26}. Extends the
non_direct_alignment certificate from the 2026-05-25 fixed-keyword arm to the
crib-forcing arm.

**Periods {20,23,24} closed by zero-consistency (stronger than SA-deferred).**
A cipher-free, scorer-free residue-consistency check across all 52 reorderings ×
3 variants × 2 alphabets at every Bean-surviving period found that **only p=26**
admits any residue-consistent cell (15); periods {8,13,16,19,20,23,24} admit
**ZERO**. So {20,23,24} need no SA search — no named reordering is even
periodic-key-compatible there. The periodic-inner arm of non_direct_alignment
over this 52-reordering universe is therefore **completely** characterized: only
p=26 produces candidates, all clean-null gibberish. (Residue-consistency, not
n-gram/SA, is the binding constraint.)

REMAINS OPEN (genuinely): any non-periodic inner; any alignment universe outside
the 52 named reorderings (evidence-motivated reorderings would need GAP-09
physical/archival provenance).
