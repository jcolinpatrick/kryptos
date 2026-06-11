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

## Tiers 2b + 2c addendum — gap regions + key-phase-robust statistics (2026-06-11)

- **Verdict:** `MEASURED_NULL` (frozen rules; all counts at or below null
  expectation; both decrypt-confirms chance-consistent)
- [INTERNAL RESULT] 3,960 fragments (3 page-attested cryptonyms x 165
  placements across pre-ENE 0-20 / gap 34-62 / tail 74-96 x 24 convention
  cells: 6 additive + 18 QIII), 4 statistics each (exact word, prefix,
  substring-of-word, cyclic-rotation word; the latter two are the
  phase-robust pair). Gates re-passed pre-run (additive constants 4/4;
  QIII inversion spot battery).
- Per region (observed vs expected): pre-ENE words 0/0.12, prefix 0/0.36,
  substring 2/1.09, rotation 0/0.55; gap 34-62 words 0/0.18, prefix
  0/0.54, substring 1/1.63, rotation 1/0.82; tail 74-96 words 0/0.14,
  prefix 1/0.41, substring 2/1.22, rotation 1/0.62. Nothing exceeds
  expectation beyond ordinary fluctuation.
- Both S4 rotation hits ran the frozen decrypt-confirm (candidate word as
  periodic key, all phases, full-97 kernel anchored scoring): CHAWADI via
  qiii:COMPASS:K best 2/24; GUICHE via qiii:MAGNETIC:R best 3/24 — far
  below the 18 escalation threshold; recorded as chance-consistent.
- **Cumulative across all tiers: 5,040 fragment cells, zero signals.** If
  any of KUBARK / FLUTTER / OVERLORD appears as K4 plaintext at ANY fully
  contained position in the three unknown regions, under ANY of the 24
  convention cells and ANY key phase, the implied periodic keyword is not
  a recognizable English word (per the 1M-word list).
- Still open: Quagmire I/II/IV shapes, non-periodic key sources (tapes),
  Tier-2b broader cryptonym lists, free-alignment presence,
  crib-as-discriminator in future bounded sweeps. H1-conditional
  throughout.
- Repro: PYTHONPATH=src venv/bin/python3 -u results/cryptonym_crib_screen_2026_06_11/run_screen_phase_gap.py
