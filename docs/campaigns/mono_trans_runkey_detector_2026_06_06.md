# Pre-registration — Mono-Invariant Running-Key Detector (E-FRAC-54 / BIN-D D1)

**Date:** 2026-06-06 (thresholds locked before the real-K4 run).
**Spec:** `docs/superpowers/specs/2026-06-06-mono-invariant-runkey-detector-design.md`
**Plan:** `docs/superpowers/plans/2026-06-06-mono-invariant-runkey-detector.md`
**Modules:** `src/kryptos/detectors/mono_invariant_runkey/`
**Runner:** `scripts/campaigns/f_mono_trans_runkey_detector_2026_06_06.py`
**Result:** `results/mono_trans_runkey_detector_2026_06_06.json`
**Tests:** `tests/test_mono_invariant_runkey_detector.py` (10, green).

## Purpose

Address BIN-D D1 (E-FRAC-54): `Mono + Trans + Running-key` is the one three-layer
case flagged UNDERDETERMINED because "13 mono DOF saturate fragment discrimination."
Build the detector the audit prescribed — one exploiting "positional information Mono
can't swallow" — namely the **mono-invariant forced running-key differences** from
same-letter crib pairs, which are invariant to both the monoalphabetic σ and the
running-key source text. Two-sided verdict; covers both natural model orderings.

## Model & statistic (locked)

- Models: (1) PT→σ→Trans→+K→CT (same-PT-letter forced diffs); (2) PT→+K→Trans→σ→CT
  (collision-gated same-CT-image forced diffs). Variants {vigenere, beaufort, var_beaufort}.
- Statistic: `LLR = Σ log[P_Eng(Δ_i|lag_i)/(1/26)]` over forced differences;
  `P_Eng` from `reference/running_key_texts/kahn_codebreakers_1967.txt` (public English),
  `L_MAX=12`. Matched null = letter-preserving CT shuffles; max-LLR over the full
  transposition universe (real vs null).
- Transposition universe: columnar all-orderings w6/8/9 (403,920) + 52-route grid;
  hash recorded.

## Pre-registered decision rule (two-sided)

1. **Synthetic go/no-go gate (first).** Plant `Mono(Trans(Sub(PT, real English K)))`
   with known (σ, Trans, K-offset); measure the **detection rate** = fraction of
   planted solutions whose true transposition's full-universe max-LLR exceeds the
   95th-percentile of the shuffle-null max-LLR. Pre-registered power floor:
   **Model-1 detection rate ≥ 0.80** to declare the detector trustworthy.
2. **If detection rate < floor → `DETECTOR_UNDERPOWERED`** (a valid, pre-registered
   outcome): report the measured rate and the planted-vs-null gap; the real-K4 LLR is
   descriptive only and CANNOT support an elimination or an escalation. D1 remains
   underdetermined, now with a quantified "no positional detector helps" characterization.
3. **If detection rate ≥ floor → trust the K4 verdict:** `CANDIDATE_ESCALATE` if real-K4
   max-LLR matched-null `p < 0.05`; else `CLEAN_NULL → ELIMINATED_UNDER_BOUNDED_MONO_TRANS_RUNKEY_UNIVERSE`
   (move D1 to bin B).

## Stop rule

Single bounded pass. No universe expansion after results. The synthetic gate outcome
is binding: if `DETECTOR_UNDERPOWERED`, do not relabel the descriptive real-K4 numbers
as an elimination.

## Honesty

Likely outcome is a quantified `DETECTOR_UNDERPOWERED`: ~11 forced-difference
constraints, mostly at large (uniform-regime) lags, against a 404K-transposition
look-elsewhere burden. That is a STRONGER characterization than E-FRAC-54's prose, and
a durable result. K4 is not expected to be solved. A separate prior detector
(`src/kryptos/detectors/efrac54_joint.py`, a two-sided PT+K English-scoring approach)
exists and is NOT what this build tests; this build evaluates the forced-difference
positional statistic specifically.
