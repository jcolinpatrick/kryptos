# Pre-registration — C7 segmented (cut) public-tape inner

**Date:** 2026-05-29 (locked before any data; thresholds also locked in the
runner header).
**Runner:** `scripts/campaigns/f_c7_segmented_public_tape_2026_05_29.py`
**Tests:** `tests/test_c7_segmented_public_tape.py` (cut-keystream construction +
positive-control recovery + wrong-cut guard, green).
**Alignment model:** `direct_ct_pt` (CT[i] -> PT[i], no reordering).
**Submodel:** `segmented_cut_public_tape`.

## Motivation

The dynamic-solve C7 lead (`spec_h36`) tested a SINGLE two-segment finite tape at
ONE cut. This extends it: a single PUBLIC key tape T is physically CUT at C and
the second piece RESTARTS the tape: `K[i]=T[i]` for `i<C`, `K[i]=T[i-C]` for
`i>=C`. Motivated by the physical-cut evidence (ABSCISSA = "cut off"; triangle
at the K1/K2 chart boundary). The no-cut case is already covered (identity
reordering in the 2026-05-29 tape-inner run); the CUT is the new DOF.

## Model (convention bundle, Step 0 frozen)

- ALPHABET: AZ (A=0) and KA (A=0); tape carries its own.
- VARIANT: vigenere / beaufort (A=0) / var_beaufort.
- POSITIONS: 0-indexed; cribs 21-33 (EASTNORTHEAST), 63-73 (BERLINCLOCK).
- ALIGNMENT: `direct_ct_pt` (no reordering); CRIB ALIGNMENT (DSL): `direct_positional`.
- NULL RULE: `no_null_mask`.
- SCOPE: GLOBAL over the bounded universe below; CT97.
- BEAN APPLIES? **No** — the cut falls in the inter-crib gap {34..62}, so
  positions 27 and 65 lie in DIFFERENT segments and the equality k[27]=k[65] is
  void by construction; the key is a fixed public cut-tape (not crib-forced).

## Bounded universe (declared before run)

- **Inner:** 16 public finite tapes (8 PUBLIC sources × {AZ, KA}; identical
  corpus to the 2026-05-29 tape-inner run and C6 `gen_tapes`).
- **Cut:** C in {34..62} (29 cuts) — the gap between the two crib groups.
- **Variants:** {vigenere, beaufort, var_beaufort}.
- **Cardinality:** 16 × 29 × 3 = **1392** configs.

## Null model

No crib-forcing => no order-stat trap; the honest lead discriminator is anchored
`crib_score`. The n-gram path uses a **random-length-97-tape matched null**
(NULL_RANDOM_TAPES=64, same cut × variant sweep), reporting `null_beats_real`
and the inferential `mean_equality_permutation_p` (large => public tapes carry no
English advantage over random tapes under this cut model).

## Pre-registered thresholds and decision rule

- N-gram per-char English floor: **−4.5** (lead disqualifier).
- SIGNAL crib_score: **18**.
- PROMOTED iff `crib_score ≥ 18` **OR** (`ngram_per_char ≥ −4.5` **AND**
  `ngram_total > random_tape_null_max`).
- **VERDICT = CLEAN_NULL** iff zero promoted; else CANDIDATE_ESCALATE → adversarial
  review before any further action.

## Kill rule / scope

Single bounded pass; no expansion after results. If CLEAN_NULL, record
`ELIMINATED_UNDER_BOUNDED_SEGMENTED_CUT_PUBLIC_TAPE_UNIVERSE`. Does **not** close:
two independent public tapes (one per segment), cuts outside {34..62},
crib-forced segment keys, non-public tapes, or null-bearing/variable-length models.

## Honesty

Disproof-engine closure with ~0 prior (adjacent public-tape and periodic-segmented
cells already closed/noise). Expected: CLEAN_NULL. **K4 is not expected to be
solved by this campaign.**
