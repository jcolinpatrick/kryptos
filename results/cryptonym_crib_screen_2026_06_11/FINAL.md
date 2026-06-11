# FINAL — cryptonym-crib keystream back-derivation screen

- **Verdict:** `MEASURED_NULL` (frozen kill rule; Tier 1)
- **Prereg:** docs/campaigns/cryptonym_crib_screen_2026_06_11.md
- **Date:** 2026-06-11

[INTERNAL RESULT] 270 fragments (KUBARK/FLUTTER/OVERLORD x all fully
contained pre-ENE placements x {vigenere, beaufort, var_beaufort} x
{AZ, KA}): zero exact-dictionary fragments (null expectation 0.030),
zero prefix-of-word fragments (expectation 0.09). Known-answer gate
passed pre-run (derivation reproduces all four kernel keystream
constants at ENE/BC). H1-conditional (direct positional, fixed-97).

Scope NOT closed (declared Tier 2 / engineering): Quagmire III tableau
conventions (the K1/K2 family), nonzero key phases, non-keyword key
sources, gap regions 34-62 / 74-96, broader public cryptonym lists,
free-alignment cryptonym presence (needs a generalized free matcher),
and the use of cryptonym cribs as score-discriminators inside future
bounded family sweeps (a campaign-design decision, not a screen).

Repro: PYTHONPATH=src venv/bin/python3 -u results/cryptonym_crib_screen_2026_06_11/run_screen.py

## Tier 2a addendum — Quagmire III extension (2026-06-11, same day)

- **Verdict:** `MEASURED_NULL` (same frozen rules)
- [INTERNAL RESULT] 810 fragments (3 page-attested cryptonyms x 45 pre-ENE
  placements x 6 QIII tableau keywords {KRYPTOS, PALIMPSEST, ABSCISSA,
  LATITUDE, MAGNETIC, COMPASS} x indicators {K, A, R}): zero exact-word
  derived key fragments (null expectation 0.090), zero prefix hits
  (expectation 0.270). Known-answer gate passed pre-run (exhaustive
  single-char inversion, 18 convention cells x 676 pairs; kernel QIII
  anchored by standing K1/K2 regression tests).
- Cumulative: 1,080 convention cells across Tiers 1 + 2a. If K4's
  plaintext begins with KUBARK, FLUTTER, or OVERLORD under direct
  alignment with key phase 0, the implied key is not a recognizable
  English word under simple additive (AZ/KA) OR K1/K2-family Quagmire III
  conventions.
- Still open: nonzero key phases, gap regions 34-62 / 74-96, Quagmire
  I/II/IV shapes, broader cryptonym lists (Tier 2b), free-alignment
  presence, and the crib-as-score-discriminator role in future bounded
  family sweeps.
- Repro: PYTHONPATH=src venv/bin/python3 -u results/cryptonym_crib_screen_2026_06_11/run_screen_qiii.py
