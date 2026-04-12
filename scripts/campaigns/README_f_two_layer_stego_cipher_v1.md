# f_two_layer_stego_cipher_v1

A disciplined two-layer architectural campaign for K4.

## Hypothesis under test

K4 is best modeled as two layers:

1. **OUTER** — a steganographic / masking / selection / projection /
   segmentation layer that operates on position or selection.
2. **INNER** — a weak (near-identity-preserving) encipherment layer
   that operates on letter values.

The campaign asks: can any constrained two-layer family *naturally*
produce the width-21 vertical bigram anomaly, the Stehle delta-5 lag-4
local pattern, and a weak-identity behavior compatible with Bean minor
diffs, WHILE remaining compatible with the cribs and current
eliminations?

## Outer stego layer

Three bounded families:

- `OUTER-MASK-EVERYNTH` — every-nth keep with phase, n in {2,3,4,5,7}
- `OUTER-MASK-PERIODIC` — length-L periodic keep/drop mask, L in {5,7,9},
  weight <= ceil(L/2)
- `OUTER-PROJECT` — rectangle width drawn from justified set {7,10,14,17,21}
  with row-identity, columnar-KRYPTOS, and serpentine read
- `OUTER-SEG` — segmentation at structural break points with fixed reset
  rules

Post-hoc width sweeps are available as `OUTER-PROJECT-SWEPT`, but they
carry an explicit multiplicity penalty and the `is_post_hoc_selected`
flag.

## Weak inner encipherment

All inner layers are NEAR_IDENTITY or WEAKLY_MIXING:

- `INNER-PER-SHORT` — period 2-5 Vig/Beau/VarBeau with K1-K3 keywords
- `INNER-DRIFT` — slowly drifting additive
- `INNER-NEAR-ID` — monoalphabetic w/ 0-2 swaps from identity
- `INNER-LOCAL-CAESAR` — single Caesar shift

## Anti-overfitting controls

1. Generation parameters and evaluation metrics are disjoint.
2. Outer width is drawn from a justified small set; sweeping all widths
   2-30 marks the outer `is_post_hoc_selected` and applies a
   multiplicity penalty.
3. A candidate whose width-21 anomaly is the MAX across the width
   spectrum AND whose outer width came from a sweep is flagged
   `cherry_picked_width` and disqualified from joint success.
4. Stehle / Bean-reported statistics are advisory inputs only. They are
   never used as hard elimination gates.
5. `bean_compatibility` is set to `None` (H1 disabled) for any outer
   layer that rearranges carved CT positions, so mask/projection
   candidates cannot "pass Bean" by accident.

## Joint anomaly success criterion (STRICT)

A candidate is `is_joint_anomaly_success=True` only if ALL of:

- `crib_compatibility_score >= 18`
- `bean_compatibility` is True OR None (legitimate H1 break)
- `width21_zscore >= 3.0`
- `cherry_picked_width` is False
- `stehle_local_delta5_count > 0` OR `stehle_position_55_63_match` is True
- `weak_identity_preservation >= 0.4`
- `english_likeness >= 0.3`
- `flags` is empty

## What counts as a meaningful result

- **Signal:** any instance with `is_joint_anomaly_success == True`.
- **Noise:** everything else, including high soft-ranking scores.

The campaign reports a soft ranking by a weighted metric, but the soft
ranking is NOT a selection gate. Only `is_joint_anomaly_success` is.

## Sampling modes

The campaign supports four sampling modes via `--sampling-mode`. Each mode
carries a different epistemic warrant; a null result in one mode does NOT
support the stronger claim that another mode would allow.

### `exploratory_stride` (default, backward-compat)

Stride sampling across the row-major cartesian product of outer x inner
instances. Approximate coverage only.

- **What it can claim on null:** EXPLORATORY null. Weak negative.
- **Use for:** first looks, rapid smoke tests.

### `stratified_family_cover`

For every eligible outer instance, pair it with one deterministically-
chosen representative from EVERY inner family class present after filters.

- **Coverage guarantee:** every (eligible outer instance, every inner
  family class) pair is tested.
- **Pair count:** `n_outers * n_inner_family_classes` (currently ~2208).
- **What it can claim on null:** FAMILY-COVER null — the two-layer
  hypothesis at the family-class level is dead under the chosen filters.
- **Use for:** ruling out the hypothesis at the family-class level.

### `stratified_low_complexity_bias`

Weighted band sampling. Pairs are bucketed into low/medium/high
complexity bands (centralized thresholds in `sampling.py`), and low-band
is oversampled at weight 5 vs medium 2 vs high 1.

- **Coverage guarantee:** low-complexity band sampled at 5× the rate
  of the high-complexity band.
- **What it can claim on null:** LOW-COMPLEXITY-EMPHASIZED null — the
  lower-complexity end of the parameterized space was probed at an
  elevated rate with no joint success.
- **Use for:** probing the theoretically-cleanest region deeply.

### `full_cartesian`

Enumerate the full constrained cartesian product (optionally filtered by
complexity bound or family).

- **Coverage guarantee:** complete enumeration within filters.
- **What it can claim on null:** FULL-CARTESIAN null *within the
  parameterized two-layer search space the campaign expresses* — every
  outer instance × every inner instance was scored under blind
  evaluation with no joint success. The result is bounded by the
  outer/inner generators, the H1 modeling assumptions where they apply,
  and the joint-success criterion. It is **NOT** a proof that no
  two-layer mechanism can solve K4; it is a bounded negative within a
  bounded search space.
- **Use for:** the strongest *bounded* negative result the parameterized
  framework can produce. Always cite with scope: "within the
  parameterized two-layer search space at the joint-success bar".

## Multiprocessing

- `--workers 0` (default): uses `cpu_count - 2`.
- `--workers 1`: serial in-process (tests, debugging).
- `--workers N`: N worker processes via `multiprocessing.Pool`.

Determinism: results are returned in stable index order regardless of
worker count. Same seed + same mode + same filters + any workers count
produces identical output content and order. This is tested directly
in `tests/test_two_layer_campaign.py::test_parallel_results_match_serial`.

## Resumability

```bash
# On interrupt, the checkpoint lives at
#   results/f_two_layer_stego_cipher_v1.checkpoint.json
# Resume with the same mode + seed:
PYTHONPATH=src python3 scripts/campaigns/f_two_layer_stego_cipher_v1.py \
    --sampling-mode full_cartesian --resume
```

The checkpoint is saved every `--checkpoint-every` pairs (default 500)
and deleted on successful completion. If mode or seed differ from the
checkpoint, the old checkpoint is ignored.

## Running — example commands

```bash
# Default: backward-compat exploratory stride, target_evals=2000
PYTHONPATH=src python3 -u scripts/campaigns/f_two_layer_stego_cipher_v1.py

# Minimum family-cover run (~2208 evals, ~10s on 28 cores)
PYTHONPATH=src python3 -u scripts/campaigns/f_two_layer_stego_cipher_v1.py \
    --sampling-mode stratified_family_cover

# Low-complexity-emphasized run
PYTHONPATH=src python3 -u scripts/campaigns/f_two_layer_stego_cipher_v1.py \
    --sampling-mode stratified_low_complexity_bias \
    --max-complexity 13 --target-evals 5000

# Full-cartesian low-complexity run
PYTHONPATH=src python3 -u scripts/campaigns/f_two_layer_stego_cipher_v1.py \
    --sampling-mode full_cartesian --max-complexity 12

# Full-cartesian everything (~206k evals; ~10-15 min on 28 cores)
PYTHONPATH=src python3 -u scripts/campaigns/f_two_layer_stego_cipher_v1.py \
    --sampling-mode full_cartesian

# Restrict to a single outer or inner family
PYTHONPATH=src python3 -u scripts/campaigns/f_two_layer_stego_cipher_v1.py \
    --sampling-mode full_cartesian \
    --outer-family OUTER-PROJECT \
    --inner-family INNER-LOCAL-CAESAR
```

## Interpreting results

- Check `joint_anomaly_successes` first. If empty, the summary line is
  the honest conclusion AT THE WARRANT OF THE SAMPLING MODE.
- `coverage_report` quantifies exactly what the run can claim. The
  `qualifies_as_*` booleans gate the strong-claim language.
- `family_baselines` shows per-family average crib scores and width-21
  z-scores. Families near random performance are noise.
- `top_candidates_by_metric` is a soft ranking for human inspection
  ONLY — a high soft score without joint-success status is noise.
