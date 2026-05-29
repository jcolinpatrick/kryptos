# Pre-registration — non_direct_alignment × non-periodic public-tape inner

**Date:** 2026-05-29 (locked before any data; thresholds also locked in the
runner header).
**Runner:** `scripts/campaigns/f_non_direct_alignment_tape_inner_2026_05_29.py`
**Tests:** `tests/test_non_direct_alignment_tape_inner.py` (recovery +
perm-direction guards, green), `tests/test_route_null.py` (family-matched null).
**Alignment model:** `non_direct_alignment` (per `src/kryptos/alignment_models.py`).
**Submodel:** `non_periodic_public_tape_inner`.

## Motivation

The 2026-05-28 crib-forcing closure
(`f_non_direct_alignment_cribforce_2026_05_28.py`) closed the **periodic-inner**
arm of `non_direct_alignment` over the 52 named reorderings (residue-consistency
was the binding constraint; only p=26 admitted any consistent cell; best forced
PT was gibberish). It explicitly left **non-periodic inners** OPEN. This campaign
closes the bounded, public, hand-executable slice of that open arm.

## Model (convention bundle, Step 0 frozen)

- ALPHABET: AZ (A=0) and KA (`KRYPTOSABCDEFGHIJLMNQUVWXZ`, A=0) — tape carries its own.
- VARIANT: `vigenere` K=(CT−PT), `beaufort` K=(CT+PT) A=0, `var_beaufort` K=(PT−CT).
- POSITIONS: 0-indexed; cribs at 21–33 (EASTNORTHEAST), 63–73 (BERLINCLOCK).
- ALIGNMENT: `non_direct_alignment`; ALIGN-CAUSE: transposition-induced (a named
  grid-route outer physically permutes CT, then the inner decrypts **in place**).
- NULL RULE: `no_null_mask` (finite tape, no null insertion).
- SCOPE: GLOBAL over the bounded universe below; CT97.
- BEAN APPLIES? **No** — the inner key is a fixed public tape, not crib-forced;
  the periodic-Bean derivation is irrelevant by construction.
- CRIB ALIGNMENT (DSL): `post_transposition`, realized by physically permuting
  CT first → anchored `score_candidate` is the **correct** kernel-verified
  scorer (this is NOT the unimplemented `free` path).

## Bounded universe (hash-locked, declared before run)

- **Outer:** the 52-route reordering universe, **byte-identical** to the closed
  periodic-inner arm (SHA-256 `7a9ac673…996ae6aa`): identity, reverse, and grid
  routes {colLR, colRL, serpRow, antidiag, spiralCW} at widths
  {4,5,6,7,8,11,13,14,21,24}. Asserted equal at runtime; refuses to run otherwise.
- **Inner:** 16 public finite tapes (length-97) = 8 PUBLIC sources × {AZ, KA}.
  Sources (PUBLIC FACTS, from `kryptosbot.panel_cribs`): solved K1/K2/K3
  plaintexts, public K1/K2/K3 ciphertexts, K1+K2+K3 PT concatenation, the public
  KRYPTOS tableau (row-major). Fit to 97 by TRUNC97 (len≥97) or CYCLE97
  (natural-language len>26). **Never** any leaked/sealed K4 text; **never** a
  short keyword cycled to length (periodic, out of scope). Mirrors
  `tools/workflows/k4_c6_tape_content/gen_tapes.py`.
- **Variants:** {vigenere, beaufort, var_beaufort}.
- **Cardinality:** 52 × 16 × 3 = **2496** configs.

## Null model (family-matched — order-stat-trap fix)

Per `project_non_direct_alignment_null_orderstat_trap_2026_05_28`, a
uniform-random-permutation null is invalid (depth mismatch + dilution by
cipher-incompatible perms). The null here is **family-matched**: the SAME
grid-route generator at **held-out widths** {3,9,10,12,15,16,17,18,19,20,22,23}
(disjoint from the real widths), 5 routes each = 60 null reorderings, each
evaluated over the same 16 tapes × 3 variants. Headline statistic:
**`null_beats_real`** (null max n-gram total ≥ real best n-gram total) — a fair
max-of-universe vs max-of-universe comparison. `p_conditioned_on_consistent_null`
is reported but explicitly NON-INFERENTIAL.

## Pre-registered thresholds and decision rule

- N-gram per-char English floor: **−4.5** (lead disqualifier).
- SIGNAL crib_score: **18** (kernel threshold).
- A config is **PROMOTED** iff: `crib_score ≥ 18` **OR**
  (`ngram_per_char ≥ −4.5` **AND** `ngram_total > family_matched_null_max`).
- **VERDICT = CLEAN_NULL** iff zero promoted configs.
- **VERDICT = CANDIDATE_ESCALATE** iff ≥1 promoted config → adversarial review
  (red-team-disprover + statistical-auditor) before any further action.

## Kill rule / stop condition

Single bounded pass over the 2496-config universe + 60-reordering family-matched
null. No expansion after seeing results. If CLEAN_NULL, record
`ELIMINATED_UNDER_BOUNDED_NONPERIODIC_PUBLIC_TAPE_UNIVERSE` scoped to this
universe hash; do **not** generalize to non-public tapes, crib-forced
free-residue (period-97) inners, or non-named alignments.

## Honesty

Disproof-engine closure with ~0 prior (C6 under boustrophedon-outer already
bottomed at 4/24). Expected outcome: CLEAN_NULL. Value is (a) closing a named
open sub-arm with the correct kernel-verified scorer, and (b) first in-situ use
of the family-matched-null harness (`route_null.py`). **K4 is not expected to be
solved by this campaign.**
