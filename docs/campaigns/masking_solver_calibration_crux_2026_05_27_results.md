# Results: Masking-Solver Calibration-Crux Validation (synthetic)

**Date:** 2026-05-27 (run while operator away; standing autonomy grant)
**Preregistration:** `docs/campaigns/masking_solver_calibration_crux_2026_05_27.md`
**Artifact:** `results/masking_solver_calibration_crux/calibration_crux_20260527_121245.json`
**Runner:** `scripts/campaigns/masking_solver_calibration_crux_2026_05_27.py`
**Posture:** SYNTHETIC. Not a real-K4 attempt. Touches no real K4 ciphertext.
**Not promotable.** This validates the instrument; it is NOT K4 progress.

## Verdict: ALL PASS (6/6 cells, 5/5 claims), 57.0 s wall, 26 workers

| Claim | Result |
|---|---|
| C1 Recovery | PASS — planted (mask, variant, key) + plaintext recovered in every cell |
| C2 Negative control at scale | PASS — across 32,768 decoy masks (truth excluded), zero cleared the floor |
| C3a True solve is a null outlier | PASS — z = 6.5–6.63 (>= 5 required) |
| C3b Floor monotone in \|U\| | PASS — empirical order-statistic floor non-decreasing across the ladder |
| C3c Multiplicity demotion | PASS — parametric floor demotes the true solve at \|U\| = 1e9 |

## Per-cell summary (true_solve_score = -104.87, n-gram log-prob over 28 chars)

| Cell | C1 | z | maxdecoy | floor@\|U\|max | param floor \|U\|=1 | param floor \|U\|=1e9 |
|---|---|---|---|---|---|---|
| AZ / vigenere | ✓ | 6.58 | -121.39 | -112.94 | -134.31 | -103.99 |
| AZ / beaufort | ✓ | 6.50 | -122.56 | -110.30 | -134.11 | -103.42 |
| AZ / var_beaufort | ✓ | 6.50 | -120.34 | -110.30 | -134.11 | -103.42 |
| KA / vigenere | ✓ | 6.59 | -123.81 | -116.00 | -134.36 | -104.10 |
| KA / beaufort | ✓ | 6.63 | -125.07 | -115.15 | -134.43 | -104.34 |
| KA / var_beaufort | ✓ | 6.63 | -123.66 | -115.15 | -134.43 | -104.34 |

Negative-control prune rate ~0.75 across cells (decoy masks that survived
constraint propagation at some period; the rest pruned before scoring).

## What the numbers mean (and the honest nuances)

1. **The discriminator is language, and it works.** The true solve scores
   ~-104.9; the best of 32,768 coincidental crib-consistent decoy decryptions
   scores ~-120 to -125, a ~16-point gap. The cribs + Bean are satisfied by
   construction for every forced candidate (Bean is non-discriminating in this
   regime, as expected); the n-gram floor is what separates signal from
   coincidence. This is the brief's "cribs verify, not identify" demonstrated at
   scale.

2. **Two floors, two honest behaviors.** The non-parametric (empirical
   order-statistic) floor RISES with \|U\| then SATURATES at the sampled null
   maximum (e.g. -130.7 -> -116.9 -> -112.9 -> -112.9 ...). Because the true
   solve (-104.9) sits above everything 200k random fills produced, the
   empirical floor can never demote it — correctly, since coincidence never came
   close. The parametric (Gaussian, empirically-estimated mean/std) floor CAN
   extrapolate into the tail, and demotes the true solve only at \|U\| ~ 1e9.

3. **The demotion margin at 1e9 is thin** (e.g. AZ/vig: floor -103.99 vs true
   -104.87, ~0.87 apart). Reading: a genuine ~6-sigma English solve is robust to
   the multiplicity penalty until the universe is astronomically large — exactly
   the argument for keeping a mask universe small and evidence-bounded. It is NOT
   a license to search 1e9 masks; it is the proof that doing so would erase the
   signal.

## Limitations (do not over-read)

- Synthetic plants with a clean 28-char English plaintext. Real K4 is 97 carved
  chars, unknown PT length, and the true plaintext may be terser / mixed-case /
  partly non-English — the z-margin could be far smaller.
- The null is estimated for THIS plant geometry (period 6, 3 free residues). A
  real campaign must re-estimate the null at the real mask universe's geometry.
- This validates the periodic-substitution + mask family under
  extract-then-decrypt-in-place ONLY. Transposition / non-direct alignment are
  out of scope and unproven.
- A green calibration crux is NECESSARY infrastructure. It does not constitute,
  imply, or approach a K4 result. The K4 Campaign Readiness Gate remains BLOCKED.

## OPEN-items triage (FLAGGED, not reclassified)

The research-chancellor's read-only triage of the session-briefing's 9 OPEN
results (recorded here for the operator; NO reclassification or ledger edit made
without sign-off):
- `test_..._boustrophedon` ("SUCCESS"): structural false positive (AUDIT-3
  pattern) — crib_score 24 + Bean PASS via the route mechanism, but non-crib PT
  is gibberish and n-gram is below floor. Recommend NOISE on review.
- `e_team_homophonic_trans`, `e_team_targeted_homo_trans`: "contradiction-count"
  metric sits on the random null. Recommend NOISE on review.
- `e_ct_mutation_nullmask_beaufort`: max 16/24 on retired-palette masks.
  Recommend retired on review.

These are recommendations for a future operator-supervised session, not changes.

## Bottom line

The masking solver's calibration crux — the piece the implementation brief
flagged as the epistemic crux — is validated end to end at scale, with an
empirically estimated null (closing brief remaining-item (b)). The platform
provably recovers a planted masked solution, provably refuses to manufacture one
when the truth is absent across 32,768 decoys, and applies a multiplicity
penalty that bites at astronomical universe size. This hardens the instrument;
it is not, and does not claim to be, progress on real K4. A real attempt still
requires a primary-tier evidence-gated mask universe (GAP-09).
