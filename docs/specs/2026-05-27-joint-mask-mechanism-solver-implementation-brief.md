# Implementation Brief: Joint Mask x Mechanism Solver (synthetic-recovery-first)

**Date:** 2026-05-27
**Status:** Brief, awaiting go/no-go
**Implements:** efficacy-review item #2 (the deferred `solve()` algorithm) from
`memory/project_efficacy_review_and_assumption_boundary_2026_05_24.md`.
**Builds on:** `docs/specs/2026-05-25-null-mask-aware-kernel-design.md` (substrate,
landed). The substrate's `solve(...)` is an intentional `NotImplementedError`
interface stub at `src/kryptos/kernel/masking/verify.py:114`.
**Related skills/doctrine:** `disproof-protocol`, `conditional-null-methodology`,
`known-answer-validation`, `dispatcher-dsl-contract`; `docs/REAL_K4_CURRENT_POSITION.md`;
`docs/methodological_audits.md` AUDIT-1 (direct-mapping assumption).

---

## 0. Framing (the corrected strategic read)

This is NOT a K4 campaign and not a claim that a high-power PC plus an LLM can
solve K4. The accurate posture is: **a PC plus an LLM only becomes
scientifically useful on K4 once three pieces are in place**, and this brief
builds the second one and proves it on synthetic ground.

1. **A bounded non-H1 model class** (mask, selector, non-direct alignment, or
   joint mechanism) with provenance and a finite, hashed universe.
2. **A solver/pruner** (constraint-propagation, not brute force over arbitrary
   masks). *This brief.*
3. **A calibrated verifier**: kernel scoring, Bean applied only at a layer where
   its assumptions hold, n-gram/language tests, side-effect predictions, and
   multiplicity-aware nulls.

Standing corrections this brief honors:

- The exhausted-yield statement is scoped: the demonstrated marginal yield of
  more undirected compute in the already-searched direct-alignment framing is
  effectively exhausted. It is not a theorem that all further direct-alignment
  computation has zero expected value.
- Bean is mandatory only after a candidate sits in a layer where the H1
  assumptions (direct positional crib mapping, canonical 97-char transcription,
  additive family) actually apply. For the mask + periodic-substitution family
  scoped here, the post-extraction `CT'` is exactly such a layer, so per-mask
  Bean re-derivation is legitimate. For the deferred non-direct-alignment
  family it is not, and Bean must move to the post-alignment layer.
- "28 cores is ample" holds only once the model is narrowed enough for
  admissibility. Bounded does not mean small. When a bounded universe is still
  astronomical, the missing ingredient is pruning, not cores.
- A better LLM helps with archival synthesis, mechanism design, and tighter
  bounded hypotheses. It cannot replace evidence, boundedness, or calibration.

## 1. Objective

Implement `solve()` and prove it on a **planted synthetic case**: known
plaintext, known mask, known key, known mechanism. The solver must **recover**
the mask and mechanism from the carved ciphertext plus a bounded mask universe,
not merely verify a supplied answer. K4 itself is explicitly out of scope until
the recovery harness is green and an evidence-gated (primary-tier) mask universe
exists.

## 2. Scope of the first solver

**In scope:** mask + periodic substitution (variant in {vigenere, beaufort,
var_beaufort}, A=0). This is the "extract-then-decrypt-in-place" model the
substrate already encodes: `verify_masked_candidate(ct, mask, variant, key)`.
It is the Bean-prunable case, because after extraction `CT'` is a
direct-positional additive layer.

**Deferred (separate spec, do not attempt here):**
- Transposition-bearing mechanisms and `non_direct_alignment`: an outer reorder
  precedes decrypt, so `remap_position` math and in-place Bean do not hold.
- Mask-universe *generation* from physical/stego evidence (GAP-09). The solver
  consumes a bounded universe; producing a primary-tier one is evidence work.

## 3. Algorithm (per mask, then across the bounded universe)

For a fixed mask M and period p under an additive variant:

1. `CT' = extract_ct(CT, M)`; remap cribs to `CT'` coordinates.
2. Each crib position i forces `k[i] = recover(CT'[i], PT[i])`.
3. Project crib positions onto residue classes mod p. If two crib positions in
   the same class force different k, `(M, p)` is **infeasible**: prune. (This is
   the Bean-inequality logic as a CSP, not a sweep.)
4. Surviving `(M, p)`: crib-covered residue classes are **forced**; the rest are
   **free**. Do not enumerate 26^p keys.
5. Search only the free residues, scored by n-gram quality on the gap positions.
   Free-residue count is small when p is small or cribs cover many classes; use
   exhaustive enumeration when free count is tiny, simulated annealing otherwise.
6. Re-derive Bean on `(CT', cribs')` and require Bean PASS as a necessary filter
   at this layer (legitimate because `CT'` is direct-positional additive).

`solve()` iterates the supplied bounded `MaskUniverse` x mechanism family,
applies steps 1-6 per mask, streams `MaskedCandidate`s, and accumulates
`candidates_evaluated` / `mask_universe_size` for calibration. It generates no
masks of its own.

The combinatorial blowup lives in the mask universe, not the keys. That is why
admissibility hands the solver a pre-bounded, hashed universe and why pruning
(steps 3-4), not core count, is the load-bearing engineering.

## 4. Work breakdown

| # | Item | Size | Risk |
|---|---|---|---|
| 1 | `MechanismFamily` + `MaskedCandidate` contracts (design doc names, never typed) | S | low |
| 2 | Inner per-mask CP solver (steps 1-6): forced-residue solve, free-residue search, n-gram gate | M-L | medium (core) |
| 3 | `solve()` driver: iterate bounded universe x family, stream candidates, accumulate calibration counts | S-M | low |
| 4 | Mask-universe-aware null calibration: expected-max-crib model adjusted for added mask DOF; multiplicity-aware | M | medium (epistemic crux) |
| 5 | Known-answer gate wiring: empty-mask K1/K2/K3 rediscovery green before any K4 entry point (reuse `kryptosbot/self_test.py`) | S | low |
| 6 | **Synthetic recovery harness** (section 5): the real fitness gate | M | medium |
| 7 | TDD + empty-mask reduction regression throughout | S | low |

## 5. Synthetic recovery harness (the central deliverable)

Sealed, K4Bench-style. The sealed answer never reaches solver paths
(`bench_loader` discipline).

**Positive recovery.** Construct a known PT of plausible English, insert known
nulls at known carved positions to form the carved CT, encrypt the non-null
positions with a known `(variant, key)`. Hand the solver ONLY the carved CT plus
a bounded mask universe that contains the true mask among decoy masks. Assert:
- the true `(mask, variant, key)` is recovered,
- the true PT ranks at the top by the combined gate (crib + Bean + n-gram),
- `crib_score == 24` and `bean_passed == True` at the true mask.

**Negative control.** Run the same solver with the true mask **excluded** from
the universe. Assert no candidate reaches the breakthrough gate, i.e. the solver
does not manufacture a false solve when the truth is absent.

**Calibration sanity.** As decoy mask count grows, the mask-universe-aware null
threshold must rise (more masks raise the expected max crib_score by chance).
Assert the null threshold is monotone in `mask_universe_size`, so a fixed
crib_score becomes less significant as the universe grows.

## 6. Acceptance criteria

1. Empty-mask reduction holds exactly (substrate invariant preserved).
2. Known-answer gate: K1/K2/K3 rediscovered at empty mask before any K4 path.
3. Positive recovery, negative control, and calibration-sanity tests all green.
4. No global mutation; no `KRYPTOS_CT_OVERRIDE` / `KRYPTOS_CRIB_DICT_OVERRIDE`
   on real-K4 paths.
5. Multi-core execution for the per-mask sweep (28-core policy) once the universe
   is bounded; serial only for sub-30s smoke tests.

## 7. Explicit non-claims

- This does not assert K4 has nulls, does not revive the retired palette /
  `CONSENSUS_NULL_POSITIONS`, and does not by itself reopen any elimination.
- A green recovery harness proves the platform CAN recover a masked solution
  when one exists in a bounded universe. It is necessary infrastructure, not a
  K4 result. A K4 attempt waits on a primary-tier, evidence-gated mask universe
  (GAP-09) and a separate preregistration.
