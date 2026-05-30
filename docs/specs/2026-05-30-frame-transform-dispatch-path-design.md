# Design Spec: Frame-Transform Dispatch Path (realignment phase)

Status: DRAFT (awaiting human review)
Date: 2026-05-30
Author: Colin Patrick (human lead) + Claude (computational partner)
Scope: kryptosbot controller / dispatcher + hypothesis DSL
Classification of this document: [POLICY] + [HYPOTHESIS] design; contains no K4 ground-truth claims.

## 1. Motivation

A three-way independent agent review (research-chancellor, red-team-disprover,
and an orthogonal design-archaeology pass) converged on a single structural gap
in the controller's six generative personas: all six reason WITHIN two silent
preconditions, and none is chartered to doubt them.

1. Alignment: carved `CT[i]` maps directly to `PT[i]` on a fixed-order,
   fixed-97, no-null string.
2. Construction fidelity: the carved text is a clean, roundtrippable encryption.

The project's own retrospectives name the alignment assumption as the single
load-bearing assumption under all eliminations. The red-team review established
the decisive constraint: a new generative persona alone would be theater,
because the live frontier is blocked at the SCORER/DISPATCHER, not the idea
generator. `crib_alignment='free'` is recorded on a spec but never honored:
the real-K4 scoring call at `kryptosbot/job_dispatcher.py:1807` hardcodes
anchored `score_candidate`.

Decision (human lead, 2026-05-30): build the capability first. This spec is the
first sub-project of that capability, scoped to permutation REALIGNMENT only.
A persona charter and a separate null-mask sub-project are explicit follow-ups.

## 2. What the closure audit changed

The naive fix ("wire `score_candidate_free` at line 1807 when
`crib_alignment=='free'`") was rejected. Reasons, both verified in-repo:

- `score_candidate_free` (`src/kryptos/kernel/scoring/aggregate.py:312`)
  searches the cribs ANYWHERE and uses NO Bean constraints (Bean depends on
  fixed positions). It is structurally inflation-prone and carries no Bean
  gate. It is a diagnostic, not a solve-grade verdict.
- The 2026-05-30 controller-closure integrity audit proved that the
  dispatcher's DECRYPT pipelines already undo every transform
  (`job_dispatcher.py:741`, `direction:"undo"`), so their output is
  natural-order plaintext with cribs back at canonical 21-33 / 63-73.
  Anchored scoring is therefore CORRECT for direct_positional and
  post_transposition (round-trip 24/24). The genuine "free" cases
  (reordered-message / crib-forcing) are handled today by standalone
  harnesses that PERMUTE the CT, RE-DERIVE Bean, then ANCHORED-score
  (`solve_periodic`, `route_null.py`, tape-inner). Cross-refs:
  `project_controller_closure_integrity_audit_2026_05_30`,
  `project_non_direct_alignment_cribforce_closure_2026_05_28`,
  `project_family_matched_null_and_tape_inner_closure_2026_05_29`.

Conclusion: the correct capability is to promote the proven
permute-then-(re-derive-Bean)-then-anchored-score pattern from one-off
standalone harnesses into a first-class, bounded, replayable DISPATCHER path.
`score_candidate_free` is retained only as a cheap, non-gating pre-filter.

## 3. Goals and non-goals

Goals (this spec):
- A bounded `realignment` axis in the DSL: a finite, universe-hashed family of
  CT permutations.
- A dispatcher path that, when a `realignment` is declared, applies the
  permutation to CT, runs the existing decrypt pipeline, RE-DERIVES Bean from
  the permuted CT, and ANCHORED-scores. This is the verdict.
- `score_candidate_free` as a position-free pre-filter with a matched null,
  recorded as a diagnostic only.
- Admissibility gating so realignment specs are Category-A only when finite,
  null-matched, budgeted, and not exhausted; otherwise fail-closed to
  Category-B.
- A regression lock proving the direct_positional path is byte-identical
  before and after.

Non-goals (explicit, deferred to follow-up specs):
- null_mask (character-removing) realignment and its Bean re-derivation.
- The persona charter (the prompt addendum / new frame-breaker persona that
  EMITS realignment specs). This spec only makes the capability exist and be
  correctly scored.
- Enumerating WHICH permutation families are worth searching on real K4.
- Any real-K4 campaign run. This is capability, not a solve attempt.

## 4. Design

### 4.1 DSL surface (`kryptosbot/hypothesis_dsl.py`)

Add one optional field to `HypothesisSpec`:

```
realignment: RealignmentSpec | None = None   # default None => direct_positional, unchanged
```

`RealignmentSpec` declares a finite permutation family over the 97 indices:
- `family`: enum of bounded generators. Initial set (each must be a pure,
  deterministic index permutation of length 97):
  - `named`: one of a curated, enumerated list of named reorderings already
    used in the non-direct-alignment work.
  - `grid_read`: parameterized by `width` (ParamRange) and `order`
    (boustrophedon | columnar | spiral | serpentine), reusing existing kernel
    transposition perms.
- `params`: ParamRange set bounding the family (e.g. width range), so
  `expected_cardinality` is computable and a `universe_hash` is derivable
  exactly as for every other axis.

Invariants enforced at validation:
- A `RealignmentSpec` must resolve to a permutation of exactly 97 indices
  (bijection check); reject otherwise.
- Exactly one alignment mode per spec: absent (direct) XOR realignment.
  Coexistence with a transposition LAYER is allowed (they compose), but the
  realignment is applied to CT before the decrypt pipeline; see 4.2.

### 4.2 Dispatcher path (`kryptosbot/job_dispatcher.py`)

New branch, entered ONLY when `spec.realignment is not None`. The
direct_positional path is untouched.

Per config:
1. Resolve the permutation `pi` for this config from the realignment family.
2. `CT_prime = apply_perm(CT, pi)` (gather convention per kernel
   `invert_perm` doctrine; the exact direction is pinned by the round-trip
   test in 5.3, not assumed).
3. `candidate_pt = decrypt_pipeline(CT_prime)` (existing pipeline builder,
   unchanged).
4. Re-derive Bean from the CT actually consumed; never read from frozen
   `kernel.constants`. Two kernel primitives already exist and MUST be reused
   rather than reimplemented (verified in-repo):
   - `derive_bean_constraints(ct, crib_dict, alphabet=...)`
     (`src/kryptos/kernel/constraints/bean.py:64`) — general CT-parametric
     derivation, imported by `kryptosbot/ct_perturbation.py:230`.
   - `rederive_bean_for_transposition(pt_to_ct, ...)`
     (`src/kryptos/kernel/constraints/bean.py:205`) — takes a length-97
     permutation directly. Since the realignment IS a length-97 permutation,
     this is the natural primitive: the dispatch path largely EXPOSES tested
     kernel code rather than adding new cryptographic code. The plan phase
     must pick exactly one (likely `rederive_bean_for_transposition` for pure
     permutations; `derive_bean_constraints` if the CT string is rewritten)
     and mirror the existing bit-identical guard
     `ct_perturbation.py:758 assert_canonical_bean_reproduction()`.
5. Verdict: anchored `score_candidate(candidate_pt)` plus
   `_candidate_bean_status(CT_prime, candidate_pt)` against the re-derived
   constraints. This is the crib_score / bean_passed of record.
6. Pre-filter (diagnostic only): `score_candidate_free(candidate_pt)` ->
   stored as `free_crib_score` + matched-null `free_p_value`. It NEVER sets
   crib_score, never sets the alert, never drives elimination.

The `JobResult` gains diagnostic fields (`realignment_universe_hash`,
`free_crib_score`, `free_p_value`) without changing the meaning of the
existing verdict fields.

### 4.3 Matched null (`route_null.py` lineage)

The pre-filter's significance and any descriptive comparison of realignment
results use a null population generated under the SAME realignment family
(per the `conditional-null-methodology` skill). Significance uses
`null_beats_real`, NOT naive `P(random best >= real)`, to avoid the
order-statistic / dilution trap fixed on 2026-05-28
(`project_non_direct_alignment_null_orderstat_trap_2026_05_28`). The matched
null is a required attachment for Category-A admission (see 4.4).

### 4.4 Admissibility (fail-closed)

A realignment spec is Category-A (auto-dispatch) only if ALL hold:
- the realignment family is finite and `universe_hash`ed;
- `expected_cardinality` (including the realignment fan-out) is within
  `compute_budget_cpu_minutes`;
- a matched `NullBaselineSpec` (same realignment family) is attached;
- the realignment-augmented universe is not already in `exhaustion_log.json`.

If any fails: `REJECTED_ADMISSIBILITY` with a clear pointer; the hypothesis is
Category-B (manual harness), exactly as today. Anti-inflation hard rule: the
free pre-filter can never raise a SIGNAL or BREAKTHROUGH alert on its own;
only the re-derived-Bean anchored verdict (with the existing p-value gate) can.

## 5. Regression lock and testing

### 5.1 Load-bearing invariant
The direct_positional path (no realignment) must be byte-identical before and
after this change. Golden test: replay a fixed corpus of existing
direct_positional and post_transposition dispatch results and assert
identical `JobResult` verdict fields.

### 5.2 Standing fitness gates
- `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000` stays green (kernel scoring untouched).
- `PYTHONPATH=src python3 -m kryptos doctor` Bean counts unchanged
  (bean_eq=1, bean_ineq=242, bean_linear=101).
- `PYTHONPATH=src pytest kryptosbot/tests/ -q` green.

### 5.3 New-path round-trip proof (correctness of the realignment branch)
Construct a known plaintext, encipher under a known cipher + known permutation
`pi`, hand the carved-order result to the realignment dispatch path declaring
`pi`, and assert it recovers `crib_score == 24` with Bean PASS under the
re-derived constraints. Mirrors the closure audit's 24/24 round-trip. This
test also pins the permutation direction (encode vs decode) so the
implementation cannot silently invert it.

### 5.4 Matched-null calibration
Random configs drawn from the realignment family land near the crib-score
floor; `null_beats_real` behaves and the order-stat trap does not reappear.

### 5.5 Admissibility tests
- realignment family without an attached matched null => REJECTED_ADMISSIBILITY.
- realignment family exceeding budget => REJECTED_ADMISSIBILITY.
- non-bijective realignment (not a permutation of 97) => validation error.
- free pre-filter high score with anchored noise => NO alert raised.

## 6. Follow-ups (separate specs)
1. null_mask realignment + null-mask-aware Bean re-derivation (the deferred
   half of the original capability).
2. Persona charter: a prompt addendum that charters the existing six to emit
   realignment specs, and/or a guarded frame-breaker persona, gated behind the
   frozen-corpus generation-diff theater test (chancellor's proposal).

## 7. Open questions for the plan phase
- Exact `RealignmentSpec` field names and where validation lives
  (`hypothesis_dsl.py` validator vs dispatcher admissibility).
- Which curated `named` reorderings to seed (reuse the non-direct-alignment
  list verbatim; do not invent new ones in this spec).
- Whether realignment fan-out multiplies the existing param product or is a
  separate outer loop (affects `expected_cardinality` and `universe_hash`).

## 8. References (verified in-repo)
- `kryptosbot/job_dispatcher.py:507` (crib_alignment carried),
  `:741` (decrypt undo direction), `:1807` (anchored verdict).
- `src/kryptos/kernel/scoring/aggregate.py:110` (`score_candidate`),
  `:312` (`score_candidate_free`, no Bean, cribs-anywhere).
- `src/kryptos/kernel/constraints/bean.py:64` (`derive_bean_constraints`),
  `:205` (`rederive_bean_for_transposition`, length-97 permutation primitive).
- `kryptosbot/ct_perturbation.py:230` (Bean re-derivation import under the
  explicit-CT contract), `:758` (`assert_canonical_bean_reproduction` guard).
- `kryptosbot/hypothesis_dsl.py:392` (`crib_alignment`), `:449`
  (`_VALID_CRIB_ALIGNMENTS`), `:319` (`NullBaselineSpec`), `:57` (`grille`
  permutation-only gather kind — reuse candidate).
- `kryptosbot/routing.py:53-60` (the six generative personas),
  `.claude/agents/PANTHEON.md` (test #8, team-of-rivals structure).
- Memory: `project_controller_closure_integrity_audit_2026_05_30`,
  `project_non_direct_alignment_null_orderstat_trap_2026_05_28`,
  `project_efficacy_review_and_assumption_boundary_2026_05_24`.
