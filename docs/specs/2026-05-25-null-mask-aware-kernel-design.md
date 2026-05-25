# Design: Null-Mask-Aware Kernel Substrate + Per-Mask Bean Re-Derivation

**Date:** 2026-05-25
**Status:** Draft, awaiting implementation
**Scope:** Substrate + verification API only. The joint mask x mechanism
search algorithm (SAT / constraint-propagation) is *interface-defined here
but deferred* to a follow-on spec.
**Motivates:** assessment item #1 from the 2026-05-24 efficacy review
(`memory/project_efficacy_review_and_assumption_boundary_2026_05_24.md`);
serves evidence gap GAP-09 (null-mask / stego) in
[`docs/REAL_K4_EVIDENCE_GAP_REGISTER.md`](../REAL_K4_EVIDENCE_GAP_REGISTER.md).
**Related doctrine:** [`docs/REAL_K4_CURRENT_POSITION.md`](../REAL_K4_CURRENT_POSITION.md),
`docs/methodological_audits.md` AUDIT-1 (direct-mapping assumption),
the `disproof-protocol`, `conditional-null-methodology`, `known-answer-validation`,
and `dispatcher-dsl-contract` skills.

---

## 1. Context

Every Bean-based elimination in this project is proven under the **direct
positional crib mapping** `CT[i] -> PT[i]` with fixed `CT_LEN = 97` and fixed
public crib positions (AUDIT-1 resolution; `kernel/constants.py:73`). The K4
plaintext length is an **open question** — nulls remain a real possibility
(`memory/feedback_pt_length_open_question.md`). If K4 is "masked," the cribs do
not sit at fixed CT positions, the 242 Bean inequalities derived from those
positions are invalid, and the bulk of the "eliminated" families are not
actually closed for the masked case.

The session briefing now renders this boundary explicitly (the ASSUMPTION
BOUNDARIES section, 2026-05-24): `arbitrary_null_mask`, `non_direct_alignment`,
and `joint_mask_mechanism` are marked **NOT CLOSED**. This spec builds the
machinery to actually *test* hypotheses in the `arbitrary_null_mask` /
variable-PT space, under the same rigor (bounded universe, re-derived
constraints, null calibration) the project applies everywhere else.

The kernel is already well-positioned. `transforms/vigenere.py::decrypt_text`
takes CT as an explicit argument. `kryptosbot/ct_perturbation.py` already
implements a CT-explicit, no-global-mutation Bean re-derivation
(`derive_bean_constraints(ct, crib_dict, alphabet)`) — the contract this spec
mirrors and the building block it promotes into the core kernel. The only
hardcoded-position surface is the scorer (`scoring/aggregate.py::score_candidate`
checks cribs at the frozen 21-33 / 63-73 positions via `CRIB_DICT`).

## 2. Goal and non-goals

### Goal

Provide a **pure, CT-explicit, stdlib** substrate that lets any consumer:

1. Represent a null mask and extract the implied ciphertext / plaintext length.
2. Re-derive Bean constraints for that mask (single canonical derivation path).
3. Verify a `(mask, mechanism, key)` candidate against cribs (at remapped
   positions) and the per-mask Bean sets, returning the data a
   mask-universe-aware null calibration needs.
4. Express a bounded, provenance-gated, two-tier mask hypothesis for campaigns.

### Non-goals (this spec)

- **No search algorithm.** The joint `solve(...)` interface is defined; the
  SAT / constraint-propagation engine that climbs it is a separate spec
  (efficacy review item #2).
- **No new compute campaign.** This is substrate; running it is a later,
  separately-preregistered step.
- **No revival of the retired palette / `CONSENSUS_NULL_POSITIONS`.** Masks
  here are hypothesis inputs with their own provenance, not the retired
  score-conditioned construct (C-PALETTE-01).
- **No global mutation.** `KRYPTOS_CT_OVERRIDE` / `KRYPTOS_CRIB_DICT_OVERRIDE`
  stay K4Bench-only; real-K4 mask paths never touch them.
- **No relaxation of stdlib-only** in the core kernel.

## 3. Conceptual model

A **NullMask** `M` is a frozenset of carved-CT positions that are nulls
(filler, not cipher output), `M ⊆ {0..96}`. All derived quantities are pure
functions of `(CT, M)`:

| Function | Meaning |
|---|---|
| `extract_ct(CT, M) -> str` | CT with the `M` positions removed; length `97 − |M|`. This *is* the plaintext length under the mask. |
| `remap_position(p, M) -> int` | carved position `p ∉ M` maps to extracted position `p − |{m∈M : m<p}|`. |
| `remap_crib_dict(crib_dict, M) -> dict[int,str]` | cribs at carved positions → cribs at extracted positions. |

The true plaintext is the decryption of `CT′ = extract_ct(CT, M)`. Cribs are
disclosed plaintext spans; under a mask they are checked at the *remapped*
positions in `CT′`.

**Empty-mask reduction (hard invariant).** With `M = ∅`: `extract_ct(CT, ∅) ==
CT`, `remap_position(p, ∅) == p`, `remap_crib_dict(CRIB_DICT, ∅) == CRIB_DICT`,
and the re-derived Bean sets equal the frozen `BEAN_EQ / BEAN_INEQ /
BEAN_LINEAR` exactly. The masked path is a strict generalization of the current
kernel.

## 4. Per-mask Bean re-derivation (the load-bearing change)

Promote `derive_bean_constraints(ct, crib_dict, alphabet=AZ)` into the core
kernel at `src/kryptos/kernel/constraints/bean.py` as the **single canonical
derivation**:

```python
def derive_bean_constraints(
    ct: str,
    crib_dict: Mapping[int, str],
    alphabet: Alphabet = AZ,
) -> BeanConstraints:   # (eq, ineq, linear) tuples, variant-independent
    ...
```

- `constants.py`'s import-time `_derive_bean_eq/ineq/linear()` become *callers*
  of this function for the canonical `(CT, CRIB_DICT)` case. One derivation
  path; the import-time `_verify()` self-check is preserved (it now also
  asserts the promoted function reproduces the frozen sets — a built-in
  parity guard).
- `kryptosbot/ct_perturbation.py::derive_bean_constraints` becomes a thin
  re-export of the kernel function so the bot and kernel cannot drift.
- For a mask: `derive_bean_constraints(extract_ct(CT, M), remap_crib_dict(CRIB_DICT, M), alphabet)`.

Rationale: the Bean edifice is *core* and scripts consume it; a second
derivation path is the exact drift risk the project guards against elsewhere.

## 5. Mask-aware verification interface

### 5.1 Parameterized crib scoring

`scoring/aggregate.py::score_candidate` gains an optional `crib_dict`
parameter, defaulting to the canonical `CRIB_DICT` so every existing caller is
unchanged:

```python
def score_candidate(
    plaintext: str,
    bean_result: Optional[BeanResult] = None,
    ngram_scorer=None,
    word_scorer=None,
    include_p_values: bool = False,
    crib_dict: Optional[Mapping[int, str]] = None,   # NEW; None -> canonical
) -> ScoreBreakdown:
    ...
```

When `crib_dict` is supplied (the remapped dict for a mask), cribs are checked
at its positions against `plaintext` of length `|CT′|`. No new scorer is
introduced; the anchored scorer is generalized.

### 5.2 Masked candidate verification

A pure verifier composes the pieces:

```python
@dataclass(frozen=True)
class MaskedVerification:
    mask: NullMask
    crib_score: int            # 0..24
    bean_passed: bool
    ngram_score: float
    pt_len: int                # == 97 - len(mask)
    # calibration inputs (so the null model is honest by construction):
    mask_universe_size: int    # |declared mask universe| for this run
    candidates_evaluated: int  # running count for max-of-N null

def verify_masked_candidate(
    ct: str,
    mask: NullMask,
    mechanism: MechanismSpec,   # existing DSL/transform spec
    key: Sequence[int],
    *,
    crib_dict: Mapping[int, str] = CRIB_DICT,
    alphabet: Alphabet = AZ,
    ngram_scorer=None,
) -> MaskedVerification:
    ct_prime = extract_ct(ct, mask)
    cribs = remap_crib_dict(crib_dict, mask)
    eq, ineq, linear = derive_bean_constraints(ct_prime, cribs, alphabet)
    pt = decrypt_text(ct_prime, list(key), mechanism.variant, alphabet=...)
    bean = verify_bean(ct_prime, pt, cribs, eq, ineq, linear)
    score = score_candidate(pt, bean_result=bean, ngram_scorer=ngram_scorer,
                            crib_dict=cribs)
    ...
```

This is the **constraint oracle** the future solver consumes. It does not
search; it evaluates one candidate.

### 5.3 Joint-solver interface (defined, deferred)

```python
def solve(
    mask_universe: MaskUniverse,        # bounded, hashed (see §6)
    mechanism_family: MechanismFamily,
    constraint_oracle: Callable[..., MaskedVerification],
) -> Iterator[MaskedCandidate]:
    ...
```

The intended algorithm uses the per-mask Bean sets and crib equations as
**hard constraints to prune** the joint `(mask × key)` space rather than
enumerate it — directly attacking the flat-fitness problem (efficacy review
item #2). **The algorithm is out of scope here.** This spec only fixes the
interface so the substrate is testable and the solver spec can target a stable
contract.

## 6. Gating (outside the pure kernel — `src/kryptos/admissibility/`)

The kernel stays pure compute and assumption-free. Hypothesis gating lives one
layer up, mirroring `disproof-protocol` and `dispatcher-dsl-contract`:

```python
@dataclass(frozen=True)
class MaskHypothesis:
    mask_universe: MaskUniverse          # generator + bound; yields NullMasks
    alignment_model: str                 # one of the 6 boundary-taxonomy keys
    provenance: str                      # artifact pointer / GAP-row reference
    assumption_bundle: tuple[str, ...]   # explicit declared assumptions
    universe_hash: str                   # sha256 of the enumerated universe
    tier: Literal["primary_evidentiary", "secondary_exploratory"]
    stop_rule: str                       # when the search is declared complete
```

**Two-tier discipline** (`feedback_two_tier_preregistration`):

- **primary_evidentiary** — requires a `provenance` artifact that advances a
  GAP row (GAP-09 first). Results may update priors.
- **secondary_exploratory** — allowed with only an `alignment_model` +
  bounded universe, but **quarantined**: never promoted to a global K4 fact,
  always reported with the secondary-tier banner. This honors the "pursue any
  non-zero-probability path" directive without laundering breadth into signal.

A validator (sibling to `scripts/_infra/validate_pseudo_clue_pack_admission.py`)
rejects a `MaskHypothesis` that lacks a bounded universe, a hash, an
`alignment_model`, or (for primary tier) a provenance artifact.

## 7. Invariants and honesty guards (non-negotiable)

1. **Empty-mask reduction** (§3): `M = ∅` reproduces the current kernel
   exactly — Bean sets, crib positions, and scores identical. Regression-tested.
2. **Cribs-not-null default invariant.** Masks intersecting the crib positions
   (21-33, 63-73) are rejected *by default* — cribs are CT-position-anchored
   (`feedback_pt_length_open_question`). But this is a *declared, overridable*
   entry in the `assumption_bundle`, not a hardcoded law: a hypothesis may
   relax it only by stating so explicitly with its own provenance, because
   "cribs aren't nulls" is a Tier-3-derived premise, not proven fact.
3. **No global mutation.** Mirror the `ct_perturbation` contract: every
   CT-dependent computation takes CT explicitly; nothing reads
   `constants.CT` for masked work or sets the override env vars.
4. **Known-answer gate** (`known-answer-validation`). Empty-mask K1/K2/K3
   rediscovery must pass before any K4 mask search runs.
5. **Mask-universe-aware null calibration** (`conditional-null-methodology`).
   Masks *add* coincidental-crib degrees of freedom, so the expected max
   crib_score grows with `mask_universe_size`. `crib_score` alone is never
   promotable; promotion requires Bean PASS and/or ngram support *and* a
   p-value against the mask-universe-aware null. This is enforced at the
   campaign layer, but `MaskedVerification` carries the calibration inputs so
   the null cannot be computed against the wrong N.
6. **Stdlib only** in `kernel/masking/` and `kernel/constraints/bean.py`.

## 8. Module layout

| Path | Responsibility | Layer |
|---|---|---|
| `src/kryptos/kernel/masking/mask.py` | `NullMask`, `extract_ct`, `remap_position`, `remap_crib_dict`, validation | pure kernel |
| `src/kryptos/kernel/constraints/bean.py` | promote `derive_bean_constraints(ct, crib_dict, alphabet)`; `constants._derive_*` call it | pure kernel |
| `src/kryptos/kernel/scoring/aggregate.py` | add `crib_dict` param to `score_candidate` | pure kernel |
| `src/kryptos/kernel/masking/verify.py` | `MaskedVerification`, `verify_masked_candidate`, `solve(...)` interface stub | pure kernel |
| `src/kryptos/admissibility/mask_hypothesis.py` | `MaskHypothesis`, `MaskUniverse`, two-tier validator | gating layer |
| `kryptosbot/ct_perturbation.py` | `derive_bean_constraints` becomes a thin re-export | bot |

## 9. Testing

1. **Empty-mask regression (exact).** `derive_bean_constraints(CT, CRIB_DICT) ==
   (BEAN_EQ, BEAN_INEQ, BEAN_LINEAR)`; `score_candidate(pt)` identical with and
   without the default `crib_dict`.
2. **Extraction / remap properties.** `len(extract_ct(CT,M)) == 97 − |M|`;
   crib positions survive and remap correctly; round-trip consistency.
3. **Synthetic masked challenge (sealed, K4Bench-style).** Build a known PT,
   insert known nulls at known positions, encrypt with a known mechanism;
   confirm the substrate yields `crib_score == 24` and `bean_passed == True` at
   the *true* mask, and fails at wrong masks. Proves the substrate can *verify*
   a masked solution. Sealed answer never reaches search paths
   (`bench_loader` discipline).
4. **Cribs-not-null validation.** Masks hitting crib positions rejected by
   default; accepted only when the assumption is explicitly relaxed.
5. **Bean parity under mask.** `verify_bean` on `(CT′, cribs′)` agrees with an
   independent reference re-derivation.
6. **Gating validator.** `MaskHypothesis` missing universe / hash /
   alignment_model / (primary) provenance is rejected.
7. **Known-answer gate** invocation wired and green before any K4 search entry
   point is exposed.

## 10. Build sequence (for the implementation plan)

1. Promote `derive_bean_constraints` into `constraints/bean.py`; rewire
   `constants._derive_*`; keep import self-verify green. (Pure refactor; the
   empty-mask regression test is the guard.)
2. `kernel/masking/mask.py` + tests (extraction / remap / validation).
3. `crib_dict` parameter on `score_candidate` + tests (default-unchanged).
4. `kernel/masking/verify.py`: `MaskedVerification` + `verify_masked_candidate`
   + the synthetic sealed masked-challenge test.
5. `solve(...)` interface stub (signature + docstring + `NotImplementedError`)
   so the follow-on solver spec has a target.
6. `admissibility/mask_hypothesis.py` + two-tier validator + tests.
7. Re-export shim in `ct_perturbation.py`; confirm its existing tests stay green.

## 11. What this explicitly does NOT claim

This substrate does not assert that K4 has nulls, does not revive any retired
mask, and does not by itself reopen any elimination. It makes the
`arbitrary_null_mask` space *testable under the same rigor as everything else*.
Whether that space contains the solution is exactly what a later, gated,
null-calibrated campaign would measure.
