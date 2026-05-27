# Preregistration: GAP-09 Pathway-2 (score-independent null-mask construction)

**Date:** 2026-05-27
**Author:** Claude Opus 4.7, under Colin's directive ("pursue GAP-09") + autonomy grant.
**Gap:** GAP-09 (null-mask / stego evidence), `docs/REAL_K4_EVIDENCE_GAP_REGISTER.md`.
**Pathway:** #2 — independent-statistical-signal-derived mask
(`docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md` §GAP-09).
**Status:** PREREGISTERED. Methodology below is fixed BEFORE any test is run.
The rule set (§3) is FROZEN from the stego-analyst proposal + audit before the
harness executes; no rule may be added, removed, or edited after the first test.
**Posture:** Evidence-construction attempt. Honest prior: likely null (every
prior bridge campaign closed null). Nothing promotable without operator sign-off.

## 0. The discipline this enforces (why it is not the retired palette)

The BCL palette / 17-position consensus null was retired (C-PALETTE-01) because
its positions were **score-conditioned** — chosen because they improved a K4
score. GAP-09 requires the opposite: positions derived with **zero K4-score
input**. This protocol enforces that with a hard separation of roles:

- **Proposer** (stego-analyst): enumerates candidate rules from CT-intrinsic
  structure only; never sees/uses a K4 score; never tests.
- **Tester** (this harness): applies the FROZEN rules, runs pre-declared
  side-effect tests against permutation nulls.
- **Auditor** (statistical-auditor): vets each survivor for score-leak,
  circularity, and multiplicity before any "candidate" label.

## 1. Invariants (a rule/result violating any is INVALID)

1. **Zero-score derivation.** Each mask is a deterministic function of the
   carved CT (the 97 letters) and/or externally-measured physical quantities
   ONLY. No crib_score, ngram, Bean-pass, or decryption quality enters the
   derivation. (A downstream TEST may use scores; the DERIVATION may not.)
2. **<=3 free parameters** per rule, each with a small (<=8-value) grid and a
   structural/external anchor. Family cardinality recorded and hashed.
3. **width-21 is a TEST, never a derivation input** (the project flags
   width-21-derived masks as circular). No rule may read the width-21 bigram
   structure to choose positions.
4. **Cribs are not nulls** (default). A mask intersecting crib positions
   21-33 / 63-73 is rejected unless an explicit provenance relaxes it.
5. **No retired constructs** (palette, consensus nulls) and no OCR-phantom
   ('4,8,10,26=Col') as a position source.

## 2. Side-effect tests (pre-declared, falsifiable)

For each frozen rule's mask M (extract CT' = carved CT with M removed):

- **T1 width-21 reduction (primary stego signature).** The raw CT97 has a
  width-21 repeated-vertical-bigram anomaly (count=11, MC mean 3.5, sd 1.68,
  p=1.6e-4; `memory/width21_bigram_73char.md`). PREDICTION: if M is the true
  null mask, the residual CT' should NOT carry this anomaly (the nulls created
  it). Metric: repeated-vertical-bigram count of CT' re-gridded at width 21,
  compared to a Monte-Carlo null of random permutations of CT' (>=200k trials).
  PASS direction: residual count regresses to the MC mean (anomaly gone),
  quantified as the drop in z-score from the CT97 baseline.
- **T2 anomaly co-location.** Alignment of M against registered independent
  anomaly positions (the carved `?` marks, YAR window, panel line breaks IF
  cited; Stehle window 55-63), tested against a permutation null over masks of
  the same size. Required bar: **p <= 1e-6** (acquisition-plan GAP-09 closure
  threshold).
- **T3 ngram floor (downstream payoff).** Feed CT' + remapped cribs to the
  VALIDATED masking solver (`solve_periodic` + `select_solves`,
  `calibrated_ngram_floor` with an EMPIRICALLY estimated null at this geometry).
  PREDICTION: a true mask yields a crib-consistent decryption clearing the
  mask-universe-aware floor. (This test uses scores, but only AFTER the
  score-free derivation — it cannot contaminate the construction.)

## 2.1 T2 INFEASIBILITY (determined at freeze, before any test)

A data-availability check (not a result) found that the independent observables
T2 needs do NOT exist with K4-relative precision in this repo:
- **YAR is K3-internal**, not K4 (`kryptosbot/registries.py`: positions 3,4,6 of
  K3 CT inside ENDYAHR). It cannot anchor a K4 null alignment.
- The carved **`?` marks** and **panel line breaks** have no K4-indexed
  per-character positions in-repo (R6 is data-blocked for the same reason).
- The **Stehle window 55-63** is a K4-internal CT statistic, not an independent
  observable.

Therefore **T2 (anomaly co-location at p<=1e-6), which is GAP-09's CLOSURE bar,
cannot be run.** This is recorded as a feasibility determination before testing;
it removes an unrunnable test, it does not bias any outcome. Consequence:
**GAP-09 pathway-2 cannot CLOSE the gap from current evidence.** The supportive
tests T1 and T3 are still run to characterize the score-independent masks, but a
T1/T3 result alone is NOT a GAP-09 closure (it lacks the independent-observable
corroboration the gap requires). This matches the acquisition plan's own
conclusion that GAP-09 ultimately needs a new physical/archival observable.

## 3. Frozen rule set (from stego-analyst proposal, audited)

Frozen 2026-05-27 before the harness ran. SHA-256 of the rule set recorded in
the results artifact. R6 is admissible-in-principle but NOT instantiable
(data-blocked: no K4 line-break positions) and is therefore excluded from the
run, not tested.

| id | selection function (over CT97, 0-indexed) | params (grid) | #params | predicted side-effect | circularity |
|---|---|---|---|---|---|
| R1 | doubled-letter members: CT[i]==CT[i-1] or CT[i]==CT[i+1]; mode∈{both,first,second} | mode (3) | 1 | anomaly co-loc / Bean | LOW |
| R2 | Polybius coord band: row/col of CT[i] under grid == r | grid{KA,AZ}(2), coord{row,col}(2), r{0..4}(5) | 3 | Bean / ngram | MED |
| R3 | grid row-take: floor(i/W)==R | W{7,14}(2), R(≤8) | 2 | anomaly co-loc / Bean | LOW-MED |
| R4 | every-k-th: (i-o)%k==0 | k{3..8}(6), o{0,1,2}(3) | 2 | Bean | LOW |
| R5 | vowel-class members: CT[i]∈V | V{AEIOU,AEIOUY}(2) | 1 | ngram / Bean | LOW-MED |
| R6 | physical line-break positions | boundary{first,last,both}(3) | 1 | anomaly co-loc | LOW (DATA-BLOCKED — excluded) |

W=21 is excluded from R3 by invariant #3 (width-21 may not be a derivation
input). Any rule-instance whose mask intersects crib positions (21-33, 63-73) is
INADMISSIBLE (cribs are not nulls) and reported as rejected, not tested.

## 4. Multiplicity & decision rule

- Let R = number of frozen rules, T = number of side-effect tests applied. The
  family size is R x (parameter-grid size) x T. The permitted per-test alpha is
  Šidák/Bonferroni-corrected against the full family; T2's closure bar stays at
  the raw **p <= 1e-6** (already far below any plausible correction).
- A rule is a **GAP-09 CANDIDATE** iff: (i) zero-score derivation verified by
  the auditor; (ii) T2 alignment p <= 1e-6 after multiplicity correction OR T1
  shows a pre-declared significant width-21 reduction surviving correction;
  (iii) a side-effect prediction is stated. Candidates are then formalized as
  PRIMARY-tier `MaskHypothesis` (`src/kryptos/admissibility/mask_hypothesis.py`)
  and only then fed to the solver (T3).
- **Honest default outcome: NO CANDIDATE.** If nothing clears the bar, the
  deliverable is a no-go memo + the specific new observable that would close
  GAP-09. A null here is information, not failure.

## 5. Stop rule

The frozen rule set x parameter grids is finite and fully enumerated. Permutation
/ MC nulls fixed at >=200k trials. Halt when the matrix completes. No adaptive
rule addition, no threshold relaxation.

## 6. Do-not

- Do not add a rule after seeing any test result.
- Do not relax the p<=1e-6 bar or the zero-score invariant to manufacture a
  candidate.
- Do not promote, reclassify, or edit the claims registry / exhaustion log /
  MEMORY.md without operator sign-off. Output is quarantined.
