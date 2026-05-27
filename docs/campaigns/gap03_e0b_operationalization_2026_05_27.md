# GAP-03 — BCL E0b Side-Effect Operationalization (partially_closed)

**Date:** 2026-05-27
**Gap:** GAP-03, `docs/REAL_K4_EVIDENCE_GAP_REGISTER.md` (priority 1, the plan's
recommended first analytical action).
**Status:** GAP-03 → **partially_closed**. The side-effect is operationalized,
calibrated, and validated against Bean. Full closure additionally requires a
candidate that clears the gate (none exists yet).
**Code:** `src/kryptos/kernel/scoring/e0b.py` (+ `tests/test_e0b.py`),
`scripts/statistical/gap03_e0b_sideeffect.py`.
**Artifact:** `null_baselines/e0b_sideeffect_calibration.json`.

## What was missing, and is now delivered

E0b (Materna 2020 / Bean 2021 §2.4) was a measured statistic ON the cribs, so it
could not be a bridge side-effect ("matches the cribs" is a tautology). The plan
required turning it into a forward predicate — the **X / p₀ / Y triple**. Prior
work (`e_e0b_noncrib_filter.py`, 2026-05-15) built a variant discriminator and a
historical-candidate filter but **not** the crib-pinned MC null or the Bean
reproduction. Those are delivered here.

## The X / p₀ / Y triple (the side-effect predicate)

> **X** — a candidate's mean minor-distance(PT, CT) at all positions where the
> recovered PT ∈ {K,R,Y,P,T,O,S} (the K-set), is **≤ 2.31**.
> **p₀** — under null **Y** this occurs with probability **≤ 1e-6** (the
> project SIGNAL gate).
> **Y** — the crib-pinned random-plaintext null: crib positions held to the
> disclosed letters, off-crib positions uniform random A-Z.

A true keyword-mixed-near-KRYPTOS solution extends the crib-level clustering
(mean ≈ 2.1) to its off-crib K-set positions; a coincidental crib match leaves
the off-crib K-set distances at the null mean (≈ 5.0).

## Validation (reproduces Bean)

`--validate`: at the 10 K-set crib positions, observed sum=21, mean=2.1; under a
**CT-permutation null** (preserves the carved letter multiset), p ≈ **1.5e-4 ≈
1/6667**, reproducing Bean's reported **1/5520**. The statistic is correctly
implemented (anchored to Bean's published numbers; `tests/test_e0b.py` pins
count=10, sum=21, mean=2.1 exactly).

## Calibration (crib-pinned null, 200k draws)

| quantity | value |
|---|---|
| null mean K-set distance | 5.02 |
| null std | 0.57 |
| null min observed | 2.43 |
| null q01 / q05 | 3.65 / 4.07 |
| **SIGNAL-gate threshold (p≤1e-6, parametric)** | **mean dist ≤ 2.31** |
| crib anchor (target for a true solution) | 2.10 |

**Power note:** the gate threshold (2.31) sits just ABOVE the crib anchor (2.10),
so a genuine solution that preserves E0b globally **would clear** the 1e-6 gate,
while the historical crib_score=24 overfits (which score 4–8 on this metric,
2026-05-15) correctly do **not**. The side-effect is discriminating, not vacuous.

## How the bridge uses it (full closure condition)

A future BCL pseudo-clue pack is admissible (per the admission standard) with the
predeclared success criterion:

> `crib_score >= 18 AND bean_passed=True AND e0b_candidate mean K-set distance
> <= 2.31 (p <= 1e-6 under the crib-pinned null)`.

GAP-03 **fully** closes when some candidate family meets that criterion. Until
then it is `partially_closed`: the instrument exists and is calibrated, but no
candidate has cleared it.

## Honest scope

- This is an analytical operationalization, not a K4 result. No candidate clears
  the gate today.
- The statistic assumes the keyword-mixed-near-KRYPTOS hypothesis; it is a
  side-effect *predicate*, not proof of the cipher class.
- E0b is variant-asymmetric (Vig/VarBeau, not Beaufort; 2026-05-15) — a soft
  prior, not an elimination.
- No promotion to canonical claims without operator sign-off.
