# Pre-registration — non_direct_alignment × Carter Vol.1 offset-swept finite-tape inner

**Date:** 2026-06-05 (thresholds locked BEFORE any data; also locked in the runner header).
**Runner:** `scripts/campaigns/f_non_direct_alignment_carter_tape_2026_06_05.py`
**Alignment model:** `non_direct_alignment`, submodel `non_periodic_public_tape_inner`.
**Reuses (tested):** `scripts/campaigns/f_non_direct_alignment_tape_inner_2026_05_29.py`
(route universe, `decrypt_reordered_tape`, tape format) and
`src/kryptos/kernel/masking/route_null.py` (52-route grammar + family-matched null).

## Motivation (the named gap this closes)

The 2026-05-29 clean-null tape-inner campaign swept the **52-route** outer ×
**16 CLUE-SURFACE public tapes** (K1/K2/K3 PT+CT, concat, tableau) × 3 variants →
CLEAN_NULL. It did **not** include **Carter** — the literal K3 source paraphrase
and the sole remaining admissibility-allowlisted public running-key source
(`source_id=carter_tomb_vol1`, `reference/carter_vol1.txt`).

`E-CARTER-TRANS-OPT-01` (2026-05-15) tested Carter offset-swept BUT only under
**COLUMNAR** transposition (all column orderings), **widths 5–9**, **2 variants**
(vig, beau), **AZ alphabet only** → max 10–11/24 = NOISE. This campaign's
**genuinely new region** (uncovered by E-CARTER): the **non-columnar routes**
(serpRow, antidiag, spiralCW), **wider widths** (11,13,14,21,24), the
**var_beaufort** variant, and the **KA** alphabet. The columnar/AZ/vig-beau subset
overlaps E-CARTER (expected NOISE) and is retained only for harness uniformity.

## Model (convention bundle, frozen)

- ALPHABET: AZ (A=0) and KA (`KRYPTOSABCDEFGHIJLMNQUVWXZ`, A=0).
- VARIANT: vigenere, beaufort, var_beaufort (kernel `CipherVariant`).
- POSITIONS: 0-indexed; cribs at 21–33 (EASTNORTHEAST), 63–73 (BERLINCLOCK).
- ALIGNMENT: `non_direct_alignment`; outer NAMED grid route physically permutes CT
  (gather `I[j]=CT[perm[j]]`), then an inner finite Carter tape decrypts IN PLACE.
  Cribs anchored at canonical PT positions → kernel-correct `score_candidate`
  (post_transposition; NOT the unimplemented `free` path). Bean does NOT apply
  (fixed public tape, not crib-forced).
- TAPE: `tape = carter_idx_alphabet[offset : offset+97]`, offset ∈ 0..287416.
  Carter resolved via `resolve_license_path('carter_tomb_vol1')`. PUBLIC source;
  NEVER leaked/sealed K4 text; NEVER a short keyword cycled (periodic, out of scope).

## Bounded universe (declared before run)

- **Outer (real):** 52 routes = {identity, reverse} ∪ {colLR,colRL,serpRow,antidiag,spiralCW}
  × widths {4,5,6,7,8,11,13,14,21,24}. Byte-identical to the 2026-05-29 closure
  (hash asserted equal at runtime).
- **Inner:** Carter Vol.1, 287,417 offsets, × {AZ, KA}.
- **Variants:** 3.
- **Cardinality:** 52 × 287,417 × 3 × 2 = **89,674,104** configs.

## Null model (family-matched — order-stat-trap fix)

Family-matched grid-route null at **held-out widths** {3,9,10,12,15,16,17,18,19,20,22,23}
(disjoint from real widths), 5 routes each = 60 null reorderings × 3 variants × 2
alphabets, evaluated over the IDENTICAL 287,417-offset Carter sweep (so the null
carries the same offset-multiplicity DOF). Headline statistic: `null_beats_real`
(null max n-gram total ≥ real best); `mean_equality_permutation_p` reported.

## Pre-registered thresholds and decision rule

- N-gram per-char English floor: **−4.5** (lead disqualifier).
- SIGNAL crib_score: **18** (kernel threshold).
- Binomial noise ceiling (verified): over 89.7M iid configs, E[crib≥10]≈0.76,
  E[crib≥13]≈6e-5 — so crib ≥ 13 genuinely exceeds the offset-multiplicity noise floor.
- A config is **PROMOTED** iff `crib_score ≥ 18` **OR**
  (`ngram_per_char ≥ −4.5` AND `ngram_total > family_matched_null_max`).
- **VERDICT = CLEAN_NULL / ELIMINATED** iff: zero promoted configs AND
  real max crib_score < 13 AND `mean_equality_permutation_p > 0.05`.
- **VERDICT = CANDIDATE_ESCALATE** iff ≥1 promoted config → adversarial review
  (red-team-disprover + statistical-auditor) before any further action.

## Kill rule / stop condition

Single bounded pass over the 89,674,104-config universe + 60-reordering
family-matched null. No expansion after seeing results. If CLEAN_NULL, record
`ELIMINATED_UNDER_BOUNDED_CARTER_TAPE_NONDIRECT_UNIVERSE` scoped to this universe
hash; do NOT generalize to non-public tapes, free-residue period-97 inners, or
non-named alignments.

## Correctness guard (TDD, fail-closed)

The numpy crib-led prefilter is validated against the kernel
(`decrypt_reordered_tape` → `score_candidate`) on ≥200 random
(route, variant, alphabet, offset) samples; any mismatch aborts before the sweep.

## Honesty

Disproof-engine closure with **~2–3% prior** (overlapping columnar region already
NOISE; 16-tape sibling arm clean null). Expected outcome: CLEAN_NULL, completing
the last allowlisted-public-source × this-alignment cell. **K4 is not expected to
be solved by this campaign.** This is a narrow bounded retest under a matched null,
NOT a broad campaign (the broad-campaign readiness verdict remains BLOCKED).
