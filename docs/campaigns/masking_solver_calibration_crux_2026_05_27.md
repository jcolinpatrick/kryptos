# Preregistration: Masking-Solver Calibration-Crux Validation (synthetic)

**Date:** 2026-05-27
**Author:** Claude Opus 4.7, under Colin's standing autonomy grant (operator away).
**Status:** PREREGISTERED — thresholds fixed before any run below.
**Posture:** SYNTHETIC calibration of the masking solver. **Not a real-K4
attempt.** Gate-legal: touches no real K4 ciphertext, cannot manufacture a real
K4 positive (sealed-answer / override discipline preserved). **Nothing here is
promotable to canonical memory or the claims registry.** Selected and red-teamed
via the research-chancellor survey of 2026-05-27.

## 0. Why this and not a "blitz"

An undirected brute-force campaign is gate-BLOCKED (only narrow retests
authorized; `docs/methodological_audits/k4_campaign_readiness_gate.md`) and, per
the session's committed determination, has effectively-exhausted marginal yield
under the current framing. A real-K4 masking run over an evidence-free universe
is non-promotable and washes out under the null (implementation brief
`docs/specs/2026-05-27-joint-mask-mechanism-solver-implementation-brief.md` §0,
§7), and unattended would risk an overnight multiplicity artifact. The highest
expected-value, gate-legal, unattended action is to harden the one piece the
brief flags as the epistemic crux (§4): the **mask-universe-aware null** — and to
do it with an **empirically estimated** null instead of the illustrative Gaussian
parameters used in the landed unit tests. This closes brief remaining-item (b).

## 1. Claims under test (preregistered)

For the masking solver (`src/kryptos/kernel/masking/solve.py`) on PLANTED
synthetic masked challenges (known PT, known null mask, known periodic key/variant):

- **C1 Recovery.** The solver recovers the planted `(mask, variant, key)` and
  the planted plaintext, with `crib_score == 24`-equivalent (full crib match for
  the synthetic crib set) and `bean_passed == True` at the true mask.
- **C2 Negative control at scale.** With the true mask EXCLUDED from the bounded
  universe, NO candidate clears the empirically-calibrated solve gate. I.e. the
  solver does not manufacture a solve when the truth is absent, even across a
  large decoy universe.
- **C3 Calibrated null behaviour.** Using an empirically estimated null
  (coincidental crib-consistent decryptions under the same universe):
  (a) the true solve's n-gram score is a far-right outlier of the null;
  (b) the calibrated floor is monotone non-decreasing in `mask_universe_size`;
  (c) the true solve clears the floor at bounded `|U|` but would be DEMOTED at a
  preregistered large `|U|` — the multiplicity penalty bites, so breadth cannot
  be laundered into significance.

## 2. Bounded universe (enumerable, hashed)

- **Universe-size ladder:** `|U| in {1, 8, 64, 512, 4096, 32768}` decoy masks
  (plus the true mask in the C1/C3 arms; excluded in the C2 arm). Each universe
  is enumerated deterministically from a fixed seed and SHA-256-hashed; the hash
  is recorded in the results artifact.
- **Mechanism family:** periodic substitution, variants `{vigenere, beaufort,
  var_beaufort}`, A=0.
- **Periods:** `p in 1..12`. Planted cribs are constructed so free-residue count
  stays `<= max_free_exhaustive = 4` (the solver's deterministic regime; no SA).
- **Alphabets:** `AZ` (identity) and `KA` (keyword-mixed), two planted cases.
- **Empirical null sampling:** per (variant, period) cell, draw `N_null = 200_000`
  random free-residue fills (and, where decoys survive constraint propagation,
  their crib-forced wrong-mask scores) under the fixed forced residues; record the
  n-gram score distribution. `alpha = 0.01`.

## 3. Pre-registered pass thresholds

- **C1 PASS** iff the planted tuple is recovered AND plaintext matches exactly,
  for every (variant, alphabet) planted case.
- **C2 PASS** iff `select_solves(candidates_without_truth, floor) == []` at the
  empirically-calibrated floor for every `|U|` rung.
- **C3 PASS** iff (a) true-solve score exceeds empirical-null mean by `>= 5`
  sample-sigma in the AZ/Vigenere reference case; (b) the floor sequence over the
  `|U|` ladder is non-decreasing and strictly increasing between distinct rungs;
  (c) there exists a preregistered `|U|_demote = 10**9` at which the floor strictly
  exceeds the true-solve score.

## 4. Stop rule

The universe is finite and fully enumerated per rung; null sampling is fixed at
`N_null` per cell. Halt when the declared ladder x periods x variants x alphabets
matrix completes. No adaptive extension, no "one more rung."

## 5. DO NOT RUN (forbidden adjacent expansions)

- DO NOT point `run_guarded_mask_search` at real K4 CT with any evidence-free
  mask universe (gate is GREEN; restraint is deliberate; GAP-09 not closed).
- DO NOT revive PAL_MASK / DEF_MASK / `CONSENSUS_NULL_POSITIONS` / the 7-letter
  palette as a "bounded universe" (retired claim C-PALETTE-01).
- DO NOT re-open the boustrophedon / homophonic-trans / carter-transposition
  OPEN items as compute (direct_ct_pt structural false positives).
- DO NOT extend the solver to transposition / non_direct_alignment families
  (in-place Bean invalid there).
- DO NOT promote, reclassify, or demote anything in MEMORY.md, the claims
  registry, or exhaustion_log.json without Colin's sign-off. Findings are
  quarantined to the results report.
