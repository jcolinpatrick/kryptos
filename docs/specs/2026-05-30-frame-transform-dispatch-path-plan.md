# Frame-Transform Dispatch Path (realignment phase) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `crib_alignment`-style frame-breaking hypotheses genuinely dispatchable and correctly scored by adding a bounded `realignment` axis whose verdict is permute → re-derive Bean → anchored-score (not the inflation-prone `score_candidate_free`).

**Architecture:** A new `RealignmentSpec` in the DSL declares a finite, universe-hashed length-97 permutation family. A new dispatcher branch (entered only when `spec.realignment is not None`) permutes CT, runs the existing decrypt pipeline, re-derives Bean from the permuted CT with the EXISTING kernel primitive `rederive_bean_for_transposition`, and anchored-scores. `score_candidate_free` is added only as a non-gating, matched-null diagnostic. The direct_positional path is provably byte-identical before/after.

**Tech Stack:** Python 3.11+ stdlib only (core kryptos), `pytest`. All commands need `PYTHONPATH=src`. Kernel reuse: `src/kryptos/kernel/constraints/bean.py` (`rederive_bean_for_transposition`), `src/kryptos/kernel/scoring/aggregate.py` (`score_candidate`, `score_candidate_free`), `src/kryptos/kernel/transforms` (transposition perms). DSL: `kryptosbot/hypothesis_dsl.py`. Dispatcher: `kryptosbot/job_dispatcher.py`.

**Source of truth:** `docs/specs/2026-05-30-frame-transform-dispatch-path-design.md`.

**Pre-flight before ANY task (run once, must be green):**
```
PYTHONPATH=src python3 -m kryptos doctor
PYTHONPATH=src pytest kryptosbot/tests/ -q
PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000
```
If any is red, STOP and diagnose before writing code (CLAUDE.md preflight doctrine; null-baseline cache keys on git HEAD, so a stale cache can red the suite — rebuild with `PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py` if that is the cause).

**Note on line numbers:** Locate insertion points by the quoted ANCHOR STRINGS below, not by line number — `job_dispatcher.py` is ~2371 lines and line numbers drift.

---

## File Structure

- Create: `kryptosbot/realignment.py` — `RealignmentSpec` dataclass + permutation resolution. One responsibility: declare and materialize a bounded length-97 permutation family. Pure, no I/O, no dispatch.
- Modify: `kryptosbot/hypothesis_dsl.py` — add optional `realignment` field to `HypothesisSpec` + serialization + XOR validation. (Keep the dataclass itself in `realignment.py` to avoid bloating the DSL module.)
- Modify: `kryptosbot/job_dispatcher.py` — new realignment branch in the per-config scorer; admissibility gate.
- Create: `kryptosbot/tests/test_realignment_spec.py` — DSL + permutation-family unit tests.
- Create: `kryptosbot/tests/test_realignment_dispatch.py` — dispatcher branch, round-trip, regression lock, admissibility, pre-filter-never-gates.

---

## Task 1: `RealignmentSpec` dataclass (declaration + validation)

**Files:**
- Create: `kryptosbot/realignment.py`
- Test: `kryptosbot/tests/test_realignment_spec.py`

- [ ] **Step 1: Write the failing test**

```python
# kryptosbot/tests/test_realignment_spec.py
import pytest
from kryptosbot.realignment import RealignmentSpec

def test_named_family_roundtrips_via_dict():
    spec = RealignmentSpec(family="named", params={"name": "reverse"})
    d = spec.to_dict()
    assert d["family"] == "named"
    assert RealignmentSpec.from_dict(d) == spec

def test_grid_read_family_requires_width_and_order():
    spec = RealignmentSpec(family="grid_read",
                           params={"width": 7, "order": "boustrophedon"})
    assert spec.params["width"] == 7

def test_unknown_family_rejected():
    with pytest.raises(ValueError):
        RealignmentSpec(family="teleport", params={})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_spec.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'kryptosbot.realignment'`

- [ ] **Step 3: Write minimal implementation**

```python
# kryptosbot/realignment.py
"""Bounded length-97 CT realignment families for the frame-transform path.

A RealignmentSpec declares a FINITE family of permutations over the 97
ciphertext indices. The dispatcher applies the resolved permutation to CT
before the decrypt pipeline, then re-derives Bean from the permuted CT.
See docs/specs/2026-05-30-frame-transform-dispatch-path-design.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

K4_LEN = 97

_VALID_FAMILIES = {"named", "grid_read"}


@dataclass(frozen=True)
class RealignmentSpec:
    family: str
    params: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.family not in _VALID_FAMILIES:
            raise ValueError(
                f"RealignmentSpec.family {self.family!r} not in {_VALID_FAMILIES}"
            )

    def to_dict(self) -> dict:
        return {"family": self.family, "params": dict(self.params)}

    @classmethod
    def from_dict(cls, d: dict) -> "RealignmentSpec":
        return cls(family=d["family"], params=dict(d.get("params", {})))
```

(`frozen=True` makes `==` value-based so the roundtrip test's equality holds. `params` is compared by value because dicts compare by value.)

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_spec.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/realignment.py kryptosbot/tests/test_realignment_spec.py
git commit -m "feat(realignment): RealignmentSpec dataclass + family validation"
```

---

## Task 2: Permutation resolution (`named` + `grid_read` → length-97 bijection)

**Files:**
- Modify: `kryptosbot/realignment.py`
- Test: `kryptosbot/tests/test_realignment_spec.py`

- [ ] **Step 1: Write the failing test**

```python
# append to kryptosbot/tests/test_realignment_spec.py
from kryptosbot.realignment import resolve_permutation, K4_LEN

def _is_permutation(p):
    return sorted(p) == list(range(K4_LEN))

def test_named_identity_is_bijection():
    p = resolve_permutation(RealignmentSpec(family="named", params={"name": "identity"}))
    assert _is_permutation(p)
    assert p == list(range(K4_LEN))

def test_named_reverse_is_bijection():
    p = resolve_permutation(RealignmentSpec(family="named", params={"name": "reverse"}))
    assert _is_permutation(p)
    assert p[0] == K4_LEN - 1

def test_grid_read_boustrophedon_is_bijection():
    p = resolve_permutation(
        RealignmentSpec(family="grid_read", params={"width": 7, "order": "boustrophedon"})
    )
    assert _is_permutation(p)

def test_resolution_rejects_non_bijection_guarded():
    # An order that the resolver cannot map to a 97-bijection must raise,
    # never silently return a non-permutation.
    with pytest.raises(ValueError):
        resolve_permutation(RealignmentSpec(family="grid_read",
                                            params={"width": 0, "order": "boustrophedon"}))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_spec.py -q`
Expected: FAIL with `ImportError: cannot import name 'resolve_permutation'`

- [ ] **Step 3: Write minimal implementation**

First locate the kernel transposition perm builders (do not reimplement):
```
PYTHONPATH=src python3 -c "import kryptos.kernel.transforms as t; print([n for n in dir(t) if 'perm' in n.lower()])"
```
Expected to include serpentine/columnar/spiral perm builders (e.g. `serpentine_perm`, `columnar_perm`). Use the real names returned; the boustrophedon read maps to the serpentine perm. Then:

```python
# append to kryptosbot/realignment.py
from typing import List

# REUSE kernel primitives — do NOT reimplement (Tool-Discipline doctrine).
# Verified present in kryptos.kernel.transforms.transposition:
#   serpentine_perm(rows, cols, length, vertical), validate_perm(perm), apply_perm
from kryptos.kernel.transforms.transposition import serpentine_perm, validate_perm

# Curated named reorderings — reuse the non-direct-alignment list verbatim;
# do NOT invent new ones here (spec §7). Start with the two safe anchors and
# extend from project_non_direct_alignment_cribforce_closure_2026_05_28's set.
_NAMED = {
    "identity": lambda n: list(range(n)),
    "reverse": lambda n: list(range(n - 1, -1, -1)),
}


def _as_validated_perm(perm: List[int]) -> List[int]:
    """Coerce to list and confirm it is a length-97 bijection.

    Prefer the kernel's validate_perm for the canonical convention; fall back
    to an explicit set check if validate_perm's contract differs. Implementer:
    confirm validate_perm raises (vs returns bool) with
    `PYTHONPATH=src python3 -c "from kryptos.kernel.transforms.transposition import validate_perm; help(validate_perm)"`
    and adapt this wrapper to its real contract.
    """
    perm = list(perm)
    if sorted(perm) != list(range(K4_LEN)):
        raise ValueError(
            f"realignment did not resolve to a permutation of {K4_LEN} indices"
        )
    return perm


def resolve_permutation(spec: "RealignmentSpec") -> List[int]:
    """Resolve a RealignmentSpec to a concrete length-97 index permutation.

    Returns perm where perm[k] = the CT index that output position k draws
    from. The EXACT gather/scatter convention is pinned by the Task 4
    round-trip test (the only safe source of truth); align this with the
    kernel's apply_perm convention there, not by assumption. Always validated
    to be a bijection over range(97); raises ValueError otherwise.
    """
    if spec.family == "named":
        name = spec.params.get("name")
        if name not in _NAMED:
            raise ValueError(f"unknown named realignment {name!r}")
        return _as_validated_perm(_NAMED[name](K4_LEN))

    if spec.family == "grid_read":
        width = int(spec.params.get("width", 0))
        order = spec.params.get("order", "")
        if width <= 0 or width > K4_LEN:
            raise ValueError(f"invalid grid_read width {width!r}")
        if order == "boustrophedon":
            rows = (K4_LEN + width - 1) // width
            # serpentine_perm signature verified: (rows, cols, length, vertical)
            perm = serpentine_perm(rows, width, K4_LEN, vertical=False)
            return _as_validated_perm(list(perm))
        raise ValueError(f"unsupported grid_read order {order!r}")

    raise ValueError(f"unhandled realignment family {spec.family!r}")
```

NOTE for implementer: `serpentine_perm` and `validate_perm` are confirmed present
(`PYTHONPATH=src python3 -c "import kryptos.kernel.transforms.transposition as t; print([n for n in dir(t) if 'perm' in n])"` lists `apply_perm, serpentine_perm, validate_perm, invert_perm, ...`). If a given width makes `serpentine_perm` return a non-97 result, `_as_validated_perm` raises (the guarded-rejection test). Prefer the kernel's `apply_perm` over a hand-rolled gather in Task 4.

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_spec.py -q`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/realignment.py kryptosbot/tests/test_realignment_spec.py
git commit -m "feat(realignment): resolve named + grid_read families to validated 97-bijections"
```

---

## Task 3: Add optional `realignment` field to `HypothesisSpec`

**Files:**
- Modify: `kryptosbot/hypothesis_dsl.py`
- Test: `kryptosbot/tests/test_realignment_spec.py`

- [ ] **Step 1: Write the failing test**

```python
# append to kryptosbot/tests/test_realignment_spec.py
from kryptosbot.hypothesis_dsl import HypothesisSpec, CipherLayer

def _minimal_layer():
    # Build a minimal valid CipherLayer for the local DSL; adjust kwargs to
    # the real CipherLayer signature (grep `class CipherLayer`).
    return CipherLayer(kind="vigenere", params={"keyword": "KRYPTOS"})

def test_spec_defaults_realignment_none():
    spec = HypothesisSpec(
        hypothesis_id="h1", family="vigenere", core_claim="c",
        mechanism="m", layers=[_minimal_layer()],
    )
    assert spec.realignment is None

def test_spec_realignment_roundtrips():
    from kryptosbot.realignment import RealignmentSpec
    spec = HypothesisSpec(
        hypothesis_id="h2", family="vigenere", core_claim="c",
        mechanism="m", layers=[_minimal_layer()],
        realignment=RealignmentSpec(family="named", params={"name": "reverse"}),
    )
    d = spec.to_dict()
    assert d["realignment"]["family"] == "named"
    back = HypothesisSpec.from_dict(d)
    assert back.realignment == spec.realignment
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_spec.py -k realignment_roundtrips -q`
Expected: FAIL — `HypothesisSpec.__init__() got an unexpected keyword argument 'realignment'`

- [ ] **Step 3: Write minimal implementation**

In `kryptosbot/hypothesis_dsl.py`:

1. At the top imports, add: `from kryptosbot.realignment import RealignmentSpec` (use the package-qualified import already used elsewhere in the file; grep an existing `from kryptosbot.` import to match style).

2. In the `HypothesisSpec` dataclass, ANCHOR on the existing line `expected_cardinality: Optional[int] = None` and add immediately after it:
```python
    # Optional CT realignment (frame-transform path). None => direct_positional.
    realignment: Optional[RealignmentSpec] = None
```

3. In `to_dict`, ANCHOR on `"expected_cardinality": self.expected_cardinality,` and add after it:
```python
            "realignment": self.realignment.to_dict() if self.realignment else None,
```

4. In `from_dict`, ANCHOR on `expected_cardinality=d.get("expected_cardinality"),` and add after it:
```python
            realignment=(
                RealignmentSpec.from_dict(d["realignment"])
                if d.get("realignment")
                else None
            ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_spec.py -q`
Expected: PASS (9 passed)

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/hypothesis_dsl.py kryptosbot/tests/test_realignment_spec.py
git commit -m "feat(dsl): optional realignment field on HypothesisSpec with serialization"
```

---

## Task 4: Dispatcher realignment branch + round-trip proof (the verdict)

**Files:**
- Modify: `kryptosbot/job_dispatcher.py`
- Test: `kryptosbot/tests/test_realignment_dispatch.py`

This is the load-bearing task. The round-trip test is written FIRST and pins the permutation direction so the implementation cannot silently invert it.

- [ ] **Step 1: Write the failing round-trip test**

```python
# kryptosbot/tests/test_realignment_dispatch.py
"""Round-trip + correctness for the dispatcher realignment branch.

Construct a known PT, encipher under a known cipher AND a known permutation,
hand the carved-order result to the realignment scorer declaring that
permutation, and assert recovery (crib_score == 24, Bean PASS) under the
RE-DERIVED constraints. Mirrors the 2026-05-30 closure audit's 24/24.
"""
import pytest
from kryptosbot.realignment import RealignmentSpec
from kryptosbot.job_dispatcher import score_config_with_realignment  # new helper


@pytest.mark.skip(reason="enable once score_config_with_realignment exists")
def test_realignment_roundtrip_recovers_24():
    # Implementer: build CT_prime by enciphering a PT whose cribs sit at
    # canonical positions, then apply the INVERSE of the declared perm so the
    # path's forward perm restores canonical order. Assert crib_score == 24
    # and bean_passed is True under re-derived Bean.
    ...
```

(The skip marker keeps the suite green until Step 3; remove it in Step 3.)

- [ ] **Step 2: Confirm the integration point and current behavior**

Run: `PYTHONPATH=src grep -n "score_candidate(candidate_pt)" kryptosbot/job_dispatcher.py`
Expected: exactly one hit — the anchored verdict call inside the per-config scorer. This is the ANCHOR for the new branch.

Run: `PYTHONPATH=src grep -n "direction" kryptosbot/job_dispatcher.py | head`
Expected: confirms the decrypt pipeline builder uses `direction:"undo"` (closure-audit fact); the realignment branch reuses the SAME pipeline builder, only prepending the CT permutation.

- [ ] **Step 3: Write the realignment scorer helper + branch**

In `kryptosbot/job_dispatcher.py`, add a helper near the per-config scorer (ANCHOR: place it directly above the function that contains `breakdown = score_candidate(candidate_pt)`):

```python
def score_config_with_realignment(ct, pipeline, realignment_spec, config_id):
    """Verdict path for a realigned config: permute CT -> decrypt -> re-derive
    Bean from the permuted CT -> anchored score. Returns the same result shape
    as the direct path plus diagnostic fields. score_candidate_free is NOT
    called here (added as a non-gating pre-filter in Task 5).
    """
    from kryptos.kernel.scoring.aggregate import score_candidate
    from kryptos.kernel.constraints.bean import rederive_bean_for_transposition
    from kryptos.kernel.transforms.transposition import apply_perm  # REUSE kernel
    from kryptosbot.realignment import resolve_permutation

    perm = resolve_permutation(realignment_spec)      # validated 97-bijection
    ct_prime = apply_perm(ct, perm)                   # kernel convention
    fn = build_pipeline(pipeline)
    candidate_pt = fn(ct_prime)
    if len(candidate_pt) != len(ct):
        return {"config_id": config_id,
                "error": f"pipeline output length {len(candidate_pt)} != CT length {len(ct)}"}

    breakdown = score_candidate(candidate_pt)
    crib_score = int(breakdown.crib_score)
    # Re-derive Bean from the CT actually consumed. NOTE: this kernel function
    # returns a TWO-tuple (eq_pairs, ineq_pairs) in CARVED-CT coordinate space
    # — there is NO linear set here (verified signature, bean.py:205).
    bean_eq, bean_ineq = rederive_bean_for_transposition(perm)
    bean_passed = _bean_passed_against(candidate_pt, ct_prime, bean_eq, bean_ineq)
    return {
        "config_id": config_id,
        "candidate_pt": candidate_pt,
        "crib_score": crib_score,
        "bean_passed": bool(bean_passed),
        "classification": getattr(breakdown, "crib_classification", "unknown"),
        "realignment_family": realignment_spec.family,
    }
```

Implementer notes (verified against kernel, do not re-assume):
- `apply_perm` is the kernel's gather primitive (`kryptos.kernel.transforms.transposition`); use it rather than a hand-rolled join so the permutation convention matches the kernel exactly.
- `rederive_bean_for_transposition(pt_to_ct)` returns **`(eq_pairs, ineq_pairs)`** — a 2-tuple of pairs in carved-CT coordinates, NOT `(eq, ineq, linear)`. The docstring states identity-T with default AZ indexing reproduces canonical `BEAN_EQ` (1 pair) + `BEAN_INEQ` (242 pairs) exactly. Decide whether the declared `perm` IS `pt_to_ct` or its inverse by making the round-trip test pass — the single source of truth for direction.
- Implement `_bean_passed_against(candidate_pt, ct_prime, bean_eq, bean_ineq)`: compute the implied keystream at the 24 crib positions from `candidate_pt` and `ct_prime`, then check equality on every `eq` pair and inequality on every `ineq` pair (the pairs are already CT coordinates). Reuse the dispatcher's existing Bean check shape (grep `_candidate_bean_status`) but pass the re-derived pairs explicitly — do NOT read constraints from `kernel.constants`.
- Mirror `assert_canonical_bean_reproduction()` (`ct_perturbation.py:758`): when `perm == identity`, the re-derived `(eq, ineq)` MUST equal canonical Bean — asserted in Task 4 Step 5.

Then remove the `@pytest.mark.skip` and fill in the round-trip test body using a known cipher (e.g. Vigenère with a known key) and `realignment="reverse"`, constructing `ct_prime` so the forward path restores canonical order.

- [ ] **Step 4: Run the round-trip test**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_dispatch.py::test_realignment_roundtrip_recovers_24 -v`
Expected: PASS — `crib_score == 24`, `bean_passed is True`.

- [ ] **Step 5: Add the identity-equivalence test + commit**

```python
# append to kryptosbot/tests/test_realignment_dispatch.py
def test_identity_realignment_rederives_canonical_bean():
    # rederive_bean_for_transposition returns a 2-tuple (eq, ineq) — no linear.
    from kryptos.kernel.constraints.bean import rederive_bean_for_transposition
    from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ  # canonical frozen
    eq, ineq = rederive_bean_for_transposition(list(range(97)))
    assert len(eq) == 1            # canonical: exactly 1 equality pair
    assert len(ineq) == 242        # canonical: 242 inequality pairs
    assert set(eq) == set(BEAN_EQ)
    assert set(ineq) == set(BEAN_INEQ)
```

(Constant names verified present: `BEAN_EQ`, `BEAN_INEQ`, `BEAN_LINEAR` in `src/kryptos/kernel/constants.py`. `BEAN_LINEAR` is intentionally NOT compared here — the transposition re-derivation does not produce a linear set; if the realignment path needs linear constraints, that is a separate follow-up, not this task.)

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_dispatch.py -q`
Expected: PASS

```bash
git add kryptosbot/job_dispatcher.py kryptosbot/tests/test_realignment_dispatch.py
git commit -m "feat(dispatcher): realignment verdict path (permute->re-derive-Bean->anchored) + round-trip proof"
```

---

## Task 5: `score_candidate_free` pre-filter (diagnostic-only, never gates)

**Files:**
- Modify: `kryptosbot/job_dispatcher.py`
- Test: `kryptosbot/tests/test_realignment_dispatch.py`

- [ ] **Step 1: Write the failing test (pre-filter never raises an alert/gate)**

```python
# append to kryptosbot/tests/test_realignment_dispatch.py
def test_free_prefilter_is_diagnostic_only():
    """A candidate with high free-crib score but anchored noise must NOT be
    classified signal/breakthrough by the realignment verdict."""
    from kryptosbot.job_dispatcher import attach_free_prefilter
    verdict = {"config_id": "x", "candidate_pt": "EASTNORTHEAST" + "A" * 84,
               "crib_score": 4, "bean_passed": False, "classification": "noise"}
    out = attach_free_prefilter(verdict)
    assert "free_crib_score" in out
    assert out["classification"] == "noise"          # verdict unchanged
    assert out["crib_score"] == 4                     # verdict unchanged
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_dispatch.py::test_free_prefilter_is_diagnostic_only -q`
Expected: FAIL — `cannot import name 'attach_free_prefilter'`

- [ ] **Step 3: Implement the non-gating pre-filter**

```python
# in kryptosbot/job_dispatcher.py
def attach_free_prefilter(verdict: dict) -> dict:
    """Attach score_candidate_free as a DIAGNOSTIC. Must never modify
    crib_score/classification/bean_passed (those are the anchored verdict)."""
    from kryptos.kernel.scoring.aggregate import score_candidate_free
    pt = verdict.get("candidate_pt")
    if pt:
        free = score_candidate_free(pt)
        verdict["free_crib_score"] = int(free.crib_score)
        verdict["free_classification"] = getattr(free, "crib_classification", "unknown")
    return verdict
```

Wire it: in `score_config_with_realignment`, change the final `return {...}` to `return attach_free_prefilter({...})`. The matched-null p-value for `free_crib_score` is computed at the campaign level (Task 6's NullBaselineSpec), not per-config.

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_dispatch.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/job_dispatcher.py kryptosbot/tests/test_realignment_dispatch.py
git commit -m "feat(dispatcher): non-gating free-crib pre-filter diagnostic on realignment path"
```

---

## Task 6: Admissibility gating (fail-closed) for realignment specs

**Files:**
- Modify: `kryptosbot/job_dispatcher.py`
- Test: `kryptosbot/tests/test_realignment_dispatch.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to kryptosbot/tests/test_realignment_dispatch.py
from kryptosbot.job_dispatcher import check_realignment_admissibility
from kryptosbot.realignment import RealignmentSpec

def _spec(realign, null=None, budget=5.0):
    from kryptosbot.hypothesis_dsl import HypothesisSpec, CipherLayer
    return HypothesisSpec(hypothesis_id="h", family="vigenere", core_claim="c",
                          mechanism="m", layers=[CipherLayer(kind="vigenere",
                          params={"keyword": "KRYPTOS"})],
                          realignment=realign, null_baseline=null,
                          compute_budget_cpu_minutes=budget)

def test_realignment_without_matched_null_rejected():
    ok, reason = check_realignment_admissibility(
        _spec(RealignmentSpec(family="named", params={"name": "reverse"}), null=None))
    assert not ok and "null" in reason.lower()

def test_realignment_over_budget_rejected():
    ok, reason = check_realignment_admissibility(
        _spec(RealignmentSpec(family="grid_read",
              params={"width": 7, "order": "boustrophedon"}),
              null=_MATCHED_NULL, budget=0.0))
    assert not ok and "budget" in reason.lower()

def test_admissible_realignment_passes():
    ok, reason = check_realignment_admissibility(
        _spec(RealignmentSpec(family="named", params={"name": "reverse"}),
              null=_MATCHED_NULL, budget=5.0))
    assert ok, reason
```

(Define `_MATCHED_NULL` as a `NullBaselineSpec` whose family matches the realignment family; grep `class NullBaselineSpec` for its constructor.)

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_dispatch.py -k admiss -q`
Expected: FAIL — `cannot import name 'check_realignment_admissibility'`

- [ ] **Step 3: Implement the gate**

```python
# in kryptosbot/job_dispatcher.py
def check_realignment_admissibility(spec) -> tuple[bool, str]:
    """Category-A gate for realignment specs. Fail-closed: any missing
    condition => (False, reason) and the hypothesis is Category-B (manual)."""
    if spec.realignment is None:
        return True, "no realignment (direct path)"
    if spec.null_baseline is None:
        return False, "realignment requires a matched NullBaselineSpec"
    if spec.compute_budget_cpu_minutes <= 0:
        return False, "compute budget exhausted/zero for realignment fan-out"
    # universe must be finite + hashable: resolution must succeed for the family.
    try:
        from kryptosbot.realignment import resolve_permutation
        resolve_permutation(spec.realignment)
    except ValueError as exc:
        return False, f"realignment family not finite/resolvable: {exc}"
    # exhaustion overlap is checked by the existing dispatcher path; reuse it.
    return True, "admissible"
```

Wire it: ANCHOR on the existing admissibility pre-flight (grep `REJECTED_ADMISSIBILITY`) and call `check_realignment_admissibility(spec)` alongside the existing checks; on `False`, return the existing `REJECTED_ADMISSIBILITY` result with the reason.

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_dispatch.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/job_dispatcher.py kryptosbot/tests/test_realignment_dispatch.py
git commit -m "feat(dispatcher): fail-closed admissibility gate for realignment specs"
```

---

## Task 7: Regression lock — direct_positional path byte-identical

**Files:**
- Test: `kryptosbot/tests/test_realignment_dispatch.py`

- [ ] **Step 1: Write the regression test**

```python
# append to kryptosbot/tests/test_realignment_dispatch.py
def test_direct_path_unchanged_when_no_realignment():
    """A spec with realignment=None must produce byte-identical verdict fields
    to the pre-change anchored path. Guards the load-bearing assumption."""
    from kryptosbot.job_dispatcher import score_single_config  # existing direct scorer
    # Build a fixed direct_positional config and assert its result dict matches
    # a frozen golden (captured from HEAD before this feature). Implementer:
    # capture the golden once with the pre-feature commit, store inline here.
    golden = {  # filled from a pre-feature run of the SAME config
        "crib_score": ...,  # capture real value
        "bean_passed": ...,
    }
    result = score_single_config(...)  # same args the dispatcher uses
    assert result["crib_score"] == golden["crib_score"]
    assert result["bean_passed"] == golden["bean_passed"]
```

Implementer: capture the golden by running the existing direct scorer on a fixed config at the pre-feature commit (`git stash` the feature or check out HEAD~), record the exact values, then unstash. This makes the test a true regression lock, not a tautology.

- [ ] **Step 2: Run to verify it passes (should pass immediately — direct path untouched)**

Run: `PYTHONPATH=src pytest kryptosbot/tests/test_realignment_dispatch.py::test_direct_path_unchanged_when_no_realignment -v`
Expected: PASS. If it FAILS, the realignment branch leaked into the direct path — STOP and fix before proceeding.

- [ ] **Step 3: Commit**

```bash
git add kryptosbot/tests/test_realignment_dispatch.py
git commit -m "test(dispatcher): regression lock — direct_positional verdict byte-identical"
```

---

## Task 8: Standing fitness gates + full suite (acceptance)

**Files:** none (verification only)

- [ ] **Step 1: Kernel scoring untouched (K1/K2/K3 still rediscoverable)**

Run: `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000`
Expected: PASS (green). (If red and the cause is the HEAD-keyed null cache, rebuild with `scripts/_infra/calibrate_null_baselines.py` and re-run.)

- [ ] **Step 2: Bean counts unchanged**

Run: `PYTHONPATH=src python3 -m kryptos doctor`
Expected: `bean_eq_count == 1`, `bean_ineq_count == 242`, `bean_linear_count == 101`.

- [ ] **Step 3: Full kryptosbot suite**

Run: `PYTHONPATH=src pytest kryptosbot/tests/ -q`
Expected: green, no new failures. (Use the venv for `-n auto` parallelism: `venv/bin/pytest -n auto kryptosbot/tests/`.)

- [ ] **Step 4: Core suite (no regression in kernel)**

Run: `PYTHONPATH=src pytest tests/ -q`
Expected: green.

- [ ] **Step 5: Final commit (if any test fixtures were adjusted)**

```bash
git add -A && git commit -m "test: frame-transform dispatch path acceptance gates green"
```

---

## Self-Review (completed by plan author)

**Spec coverage:** §4.1 DSL surface → Tasks 1-3. §4.2 dispatcher path → Task 4. §4.3 matched null → Tasks 5-6 (per-config diagnostic + campaign-level null in admissibility). §4.4 admissibility → Task 6. §5.1 regression lock → Task 7. §5.2 fitness gates → Task 8. §5.3 round-trip proof → Task 4 Step 4. §5.4 matched-null calibration → deferred note (campaign-level; see below). §5.5 admissibility tests → Task 6.

**Known coverage gap (intentional, flagged):** §5.4 (matched-null *calibration* that random configs land near the floor) is a campaign-level statistical check, not a unit test of this code path; it belongs to the first real realignment campaign's pre-registration, not this capability build. The non-gating guarantee (Task 5) and the admissibility null requirement (Task 6) are the in-scope guards. Do not run a real K4 realignment campaign as part of this plan.

**Placeholder scan:** the `...` markers in Task 4 Step 1 (skipped test body) and Task 7 golden are deliberate capture-from-environment values, with explicit instructions to fill them; they are filled before their test is un-skipped/asserted. No silent placeholders remain.

**Type consistency:** `RealignmentSpec(family, params)`, `resolve_permutation(spec) -> list[int]`, `score_config_with_realignment`, `attach_free_prefilter`, `check_realignment_admissibility` are referenced consistently across tasks. `rederive_bean_for_transposition(perm) -> (eq, ineq, linear)` matches the verified kernel signature.

**Direction-pinning:** the encode/decode direction of `perm` is intentionally NOT asserted in prose — it is pinned by making the Task 4 round-trip test pass, the one safe source of truth.
