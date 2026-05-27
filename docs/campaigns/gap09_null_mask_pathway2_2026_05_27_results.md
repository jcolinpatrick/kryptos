# Results: GAP-09 Pathway-2 (score-independent null-mask construction)

**Date:** 2026-05-27
**Preregistration:** `docs/campaigns/gap09_null_mask_pathway2_2026_05_27.md`
**Artifact:** `results/gap09_null_mask_pathway2/gap09_pathway2_20260527_190149.json`
**Runner:** `scripts/campaigns/gap09_null_mask_pathway2_2026_05_27.py`
**Posture:** NULL. No GAP-09 candidate. GAP-09 remains OPEN. Not promotable.

## Verdict: GAP-09 cannot be closed from current evidence

Pathway-2 was executed under full anti-circularity discipline (proposer ≠ tester
≠ auditor; zero-score derivation; rules frozen before testing). The outcome is a
clean null, and — more importantly — the **closure bar is structurally
unreachable from current evidence**.

## What ran

- **64 rule-instances** from frozen score-independent rules R1 (doubled letters),
  R2 (Polybius coordinate band), R3 (grid row-take, W∈{7,14}; W=21 banned as a
  derivation input), R4 (every-k-th), R5 (vowel-class). Rule-set SHA-256 in the
  artifact.
- **49 rejected** — 20 because the mask intersects crib positions (cribs cannot
  be nulls), the rest empty/over-large. **15 admissible** (13 R3 grid-rows, 1 R2,
  1 R5). The crib-not-null constraint correctly does most of the filtering.

## T1 — width-21 reduction: NON-DISCRIMINATING (size confound)

The raw CT97 width-21 repeated-vertical-bigram anomaly reproduces exactly
(count 11, MC mean 3.5, z=4.53, p=2e-4). Several masks reduce it, but the
reduction tracks **mask size, not correctness**:

| mask | \|M\| | residual count | z | drop |
|---|---|---|---|---|
| R2 AZ row r=0 | 16 | 2 | -0.86 | 5.39 |
| R5 vowels | 21 | 2 | -0.57 | 5.10 |
| R3 W=7 (small) | 7 | 5-9 | 1.3-4.1 | ~1-3 |
| R3 W=7,R=0 | 7 | 11 | 5.42 | -0.90 (none) |

The biggest reducers are the largest masks; the smallest masks barely move it and
one does not reduce it at all. Removing ~20% of positions trivially degrades
vertical-bigram structure. The discriminating null would be **random masks of the
same size**; it was NOT run because it is **moot given T3** (auditor-confirmed —
T1 was never the closure bar and no reduction is promoted). **No reduction is
treated as signal.**

## T2 — anomaly co-location (the CLOSURE bar): NOT RUNNABLE

GAP-09 closes only via an independent-observable alignment at p≤1e-6. There are
**no K4-relative independent observable positions** to align against:
- YAR is **K3-internal** (`kryptosbot/registries.py`: ENDYAHR positions 3,4,6 of
  K3 CT), not a K4 marker.
- The carved `?` marks and panel line breaks have **no K4-indexed positions**
  in-repo (R6 was data-blocked for the same reason).
- The Stehle window 55-63 is a K4-internal CT statistic, not independent.

**Therefore GAP-09 cannot be closed by any analytical pathway-2 result.**

## T3 — validated solver: ZERO candidates (precise scope)

All 15 admissible masks × periods 1-12 × 3 variants, real cribs, through the
known-answer-gated solver (gate GREEN today). **0 candidates.**

**Precise meaning (auditor-corrected):** T3=0 is NOT "no mask clears the n-gram
floor" — the n-gram floor (`select_solves`) is downstream and was never reached.
T3=0 is the *earlier, stronger* prune: **no score-free mask makes the remapped
cribs residue-consistent for a Bean-valid periodic key** (periods 1-12, 3
variants). This is the known periodic-substitution crib-infeasibility (the empty
mask also returns 0 — auditor positive control) transporting through these masks
too: the masks do not rescue periodic substitution.

**Scope limit (do not over-read):** this null says nothing about masks with free
residues >3, periods >12, or non-periodic / transposition mechanisms (all out of
scope for `solve_periodic` by design). It is a real but narrow null.

## Statistical-auditor verdict

Adversarial audit (2026-05-27): **Auditable; result is an honest null.** Per-claim:
- **T1 size confound — SOUND** (stronger than first stated: width-21 repeats scale
  with text length; same-size-random-mask null is the right discriminator but is
  moot given T3). No T1 number promoted.
- **T3=0 — was OVERSTATED; corrected above** to the residue-consistency/Bean
  framing + scope limit (periods ≤12, free ≤3, periodic-only).
- **T2 unrunnable ⇒ cannot close — SOUND.**
- **NULL, no promotion — SOUND.**
- **Falsely-null bug — RULED OUT** by positive control (empty mask returns 0 for
  the correct reason: periods 1-12 are crib-residue-infeasible; the harness
  detects feasibility and would emit on a consistent config).
- **Multiplicity:** 0 hits needs no correction; the max-of-N floor is the
  protective measure for a hypothetical positive.

## Conclusion and what would actually close GAP-09

- **No GAP-09 candidate emerged.** The analytically-available score-independent
  pathway does not produce a mask universe worth promoting. This is informative:
  it localizes the bottleneck to **evidence acquisition**, not analysis or compute.
- **The missing observable is precise K4-relative physical-position data** — panel
  line breaks per character, quantified `?`-mark / carving-anomaly positions, or
  measured sculpture geometry that deterministically names a position class. This
  is GAP-05-adjacent and requires site or high-resolution archival measurement.
- **Recommended next analytical action (per the acquisition plan):** GAP-03 (BCL
  E0b extended-position side-effect statistic), which is purely analytical and may
  generate the structural insight to constrain GAP-09's solution space. GAP-09
  itself stays OPEN pending a new physical/archival observable.

No promotion, no reclassification, no registry/ledger edit. GAP-09 register row
to be annotated "pathway-2 explored 2026-05-27, null, T2 unrunnable — gap stays
open" (status unchanged: open).
