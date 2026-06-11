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
