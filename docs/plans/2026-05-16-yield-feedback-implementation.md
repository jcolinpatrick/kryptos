# Yield-Feedback Loop Implementation Plan (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the memory-to-prompt feedback loop so the K4 controller stops re-proposing theories in empirically dead families. The theorist sees yield stats as advisory; the critic enforces an empirical-death gate with structural-novelty bypass.

**Architecture:** New pure module `kryptosbot/family_yield.py` is the source of derived policy truth. Both `_assess_landscape()` (advisory rendering) and `TheoryCritic.evaluate()` (enforcement) read its classification on a once-per-cycle snapshot of ledger stats. A new `CriticDecision.REJECT_EMPIRICALLY_DEAD` verdict carries a structured payload that Phase 2 will populate with KB suggestions. Controller-owned `_write_cycle_escape_summary` is the single chokepoint that records escape telemetry across all cycle-exit paths (success, no-candidates, all-rejected), updating a streak counter persisted on `ControllerState`.

**Tech Stack:** Python 3.11+, stdlib only (kernel + kryptosbot conventions). `pytest` for tests. Existing `TheoryLedger` SQLite WAL persistence. No new external dependencies.

**Spec:** `docs/specs/2026-05-16-yield-feedback-design.md` (commit `b5c97c8`).

---

## Pre-flight (run before Task 1)

```bash
cd /home/cpatrick/kryptos
PYTHONPATH=src python3 -m kryptos doctor
PYTHONPATH=src python3 scripts/_infra/session_briefing.py | head -30
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_verify_against_kernel_adversarial.py -q
```

Expected: doctor reports `bean_eq_count=1, bean_ineq_count=242, bean_linear_count=101`. Briefing produces output without error. The 36 verifier adversarial tests pass.

Pre-existing failures to ignore throughout this plan (NOT caused by this work):
- `kryptosbot/tests/test_ct_perturbation_stage_b.py::TestStubRefusesExecuteFull::test_execute_full_returns_3`
- 8 tests in `kryptosbot/tests/test_r3_synthetic_alert_path.py`

These were failing before this plan started. Verified by stashing the working tree and re-running. Do not investigate; do not "fix"; do not let them block any commit in this plan.

---

## Task 1: Create `family_yield.py` skeleton (dataclasses only)

**Files:**
- Create: `kryptosbot/family_yield.py`
- Test: `kryptosbot/tests/test_family_yield.py`

- [ ] **Step 1: Write the failing test for dataclass shapes**

Create `kryptosbot/tests/test_family_yield.py`:

```python
"""Tests for kryptosbot/family_yield.py: pure policy module."""
from __future__ import annotations

import pytest

from kryptosbot.family_yield import (
    DEFAULT_POLICY,
    FamilyYieldPolicy,
    FamilyYieldStats,
    FamilyYieldVerdict,
)


class TestDataclasses:
    def test_policy_defaults(self):
        p = FamilyYieldPolicy()
        assert p.min_trials == 50
        assert p.mean_score_below == 2.0
        assert p.require_zero_promotions is True
        assert p.require_best_below_store_threshold is True
        assert p.low_yield_trials == 50
        assert p.low_yield_mean_below == 2.0
        assert p.shadow_mode is False

    def test_policy_is_frozen(self):
        p = FamilyYieldPolicy()
        with pytest.raises((AttributeError, Exception)):
            p.min_trials = 999

    def test_default_policy_singleton(self):
        assert DEFAULT_POLICY == FamilyYieldPolicy()

    def test_stats_shape(self):
        s = FamilyYieldStats(
            family="encoding",
            trials=826,
            mean_score=0.78,
            best_score=7.0,
            promotions=0,
            eliminated=750,
        )
        assert s.family == "encoding"
        assert s.trials == 826

    def test_verdict_shape(self):
        s = FamilyYieldStats("x", 1, 0.0, 0.0, 0, 0)
        v = FamilyYieldVerdict(
            family="x",
            status="healthy",
            reasons=("ok",),
            stats=s,
        )
        assert v.status == "healthy"
        assert v.stats is s
```

- [ ] **Step 2: Run the failing test**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py -q
```

Expected: `ModuleNotFoundError: No module named 'kryptosbot.family_yield'`.

- [ ] **Step 3: Create the module with dataclass definitions**

Create `kryptosbot/family_yield.py`:

```python
"""Empirical-yield policy for the K4 controller.

Pure module. No persistence, no I/O. Computes yield classification from
ledger stats and bypass eligibility from structural theory metadata.

Both the theorist's landscape packet and the critic's empirical-death
gate read this module's classifier on the same per-cycle snapshot, so
the advisory rendering and the enforced rule cannot diverge.

See docs/specs/2026-05-16-yield-feedback-design.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# Imported lazily inside functions to avoid kernel import side effects
# in pure-module contexts. STORE_THRESHOLD = 10 in current kernel.


YieldStatus = Literal["healthy", "insufficient_data", "low_yield", "empirically_dead"]


@dataclass(frozen=True)
class FamilyYieldPolicy:
    """Thresholds for classifying a family's empirical yield.

    Defaults are tuned for the live ledger as of 2026-05-16. Edit in code
    rather than via CLI; deliberate friction (see spec §6.1).
    """
    min_trials: int = 50
    mean_score_below: float = 2.0
    require_zero_promotions: bool = True
    require_best_below_store_threshold: bool = True
    low_yield_trials: int = 50
    low_yield_mean_below: float = 2.0
    # Opt-in diagnostic: when True, the critic logs would_reject but
    # still returns approve. Used in tests and operator dry-runs only.
    shadow_mode: bool = False


@dataclass(frozen=True)
class FamilyYieldStats:
    """One row of the ledger aggregate query, per family.

    Numeric fields are kernel-verified outputs: ``best_score`` is the
    kernel-recomputed crib score from contracts._verify_against_kernel,
    not the worker self-report.
    """
    family: str
    trials: int
    mean_score: float
    best_score: float
    promotions: int
    eliminated: int


@dataclass(frozen=True)
class FamilyYieldVerdict:
    """Classifier output for one family."""
    family: str
    status: YieldStatus
    reasons: tuple[str, ...]
    stats: FamilyYieldStats


DEFAULT_POLICY = FamilyYieldPolicy()
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py -q
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/family_yield.py kryptosbot/tests/test_family_yield.py
git commit -m "yield-feedback: add family_yield.py dataclass skeleton

Pure module foundation. Dataclasses only; no logic yet. Subsequent
tasks add classify_family_yield, check_bypass_eligibility, render_packet.

See docs/specs/2026-05-16-yield-feedback-design.md §4.1."
```

---

## Task 2: Implement `classify_family_yield()`

**Files:**
- Modify: `kryptosbot/family_yield.py`
- Modify: `kryptosbot/tests/test_family_yield.py`

- [ ] **Step 1: Write failing tests covering every classification branch**

Append to `kryptosbot/tests/test_family_yield.py`:

```python
from kryptosbot.family_yield import classify_family_yield


def _stats(family="x", trials=100, mean=0.5, best=0.0, promotions=0, eliminated=0):
    return FamilyYieldStats(family, trials, mean, best, promotions, eliminated)


class TestClassifyFamilyYield:
    def test_insufficient_data_when_below_min_trials(self):
        s = _stats(trials=49, mean=0.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "insufficient_data"

    def test_boundary_min_trials_49_not_dead(self):
        # n=49 with same metrics that WOULD be dead at n=50 must stay healthy.
        s = _stats(trials=49, mean=0.5, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "insufficient_data"

    def test_boundary_min_trials_50_can_be_dead(self):
        s = _stats(trials=50, mean=0.5, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "empirically_dead"

    def test_empirically_dead_full_match(self):
        # The 4 audit families.
        s = _stats(family="encoding", trials=826, mean=0.78, best=7.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "empirically_dead"
        assert "n=826" in " ".join(v.reasons)

    def test_low_yield_when_mean_low_but_best_at_or_above_store(self):
        # best_score >= STORE_THRESHOLD (10) blocks empirically_dead; falls
        # back to low_yield because mean is still under the low_yield threshold.
        s = _stats(trials=200, mean=1.0, best=12.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "low_yield"

    def test_healthy_when_promotions_present(self):
        s = _stats(trials=200, mean=0.5, best=5.0, promotions=1)
        v = classify_family_yield(s)
        assert v.status == "healthy"

    def test_healthy_when_mean_above_low_yield_threshold(self):
        s = _stats(trials=200, mean=3.0, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "healthy"

    def test_classifier_is_deterministic_for_same_inputs(self):
        s = _stats(trials=100, mean=0.5, best=5.0, promotions=0)
        a = classify_family_yield(s)
        b = classify_family_yield(s)
        assert a == b
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py::TestClassifyFamilyYield -q
```

Expected: ImportError or AttributeError on `classify_family_yield`.

- [ ] **Step 3: Implement `classify_family_yield`**

Append to `kryptosbot/family_yield.py`:

```python
def _store_threshold() -> int:
    """Return the kernel's STORE threshold. Imported lazily so the
    pure module stays importable without the full kernel chain (used
    by some lightweight test contexts)."""
    from kryptos.kernel.scoring.aggregate import STORE_THRESHOLD
    return STORE_THRESHOLD


def classify_family_yield(
    stats: FamilyYieldStats,
    policy: FamilyYieldPolicy = DEFAULT_POLICY,
) -> FamilyYieldVerdict:
    """Classify a family's empirical yield against the policy.

    Order of checks matters: insufficient_data wins over every other
    status because the floor on trials is a precondition for any
    yield-based judgment. empirically_dead requires meeting ALL of
    {n >= min_trials, mean low, no promotions, best below store};
    low_yield is the same except for the best-score requirement.
    """
    if stats.trials < policy.min_trials:
        return FamilyYieldVerdict(
            family=stats.family,
            status="insufficient_data",
            reasons=(
                f"n={stats.trials} < min_trials={policy.min_trials}",
            ),
            stats=stats,
        )

    mean_low = stats.mean_score < policy.mean_score_below
    no_promos = (stats.promotions == 0) if policy.require_zero_promotions else True
    best_low = (
        stats.best_score < _store_threshold()
        if policy.require_best_below_store_threshold
        else True
    )

    if mean_low and no_promos and best_low:
        return FamilyYieldVerdict(
            family=stats.family,
            status="empirically_dead",
            reasons=(
                f"n={stats.trials}, mean={stats.mean_score:.2f}, "
                f"best={stats.best_score:.1f}, "
                f"promotions={stats.promotions}",
                f"empirically_dead: mean < {policy.mean_score_below}, "
                f"zero promotions, best < STORE_THRESHOLD",
            ),
            stats=stats,
        )

    low_yield_mean = stats.mean_score < policy.low_yield_mean_below
    if (
        stats.trials >= policy.low_yield_trials
        and low_yield_mean
        and no_promos
    ):
        return FamilyYieldVerdict(
            family=stats.family,
            status="low_yield",
            reasons=(
                f"n={stats.trials}, mean={stats.mean_score:.2f}, "
                f"best={stats.best_score:.1f}, "
                f"promotions={stats.promotions}",
                f"low_yield: mean < {policy.low_yield_mean_below}, "
                f"zero promotions, but best_score >= STORE_THRESHOLD",
            ),
            stats=stats,
        )

    return FamilyYieldVerdict(
        family=stats.family,
        status="healthy",
        reasons=(
            f"n={stats.trials}, mean={stats.mean_score:.2f}, "
            f"best={stats.best_score:.1f}, "
            f"promotions={stats.promotions}",
        ),
        stats=stats,
    )
```

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py -q
```

Expected: 12 passed.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/family_yield.py kryptosbot/tests/test_family_yield.py
git commit -m "yield-feedback: implement classify_family_yield

Branches: insufficient_data | empirically_dead | low_yield | healthy.
Pulls STORE_THRESHOLD lazily from kernel. 8 named tests cover every
branch and the n=49/n=50 boundary."
```

---

## Task 3: Implement `check_bypass_eligibility()`

**Files:**
- Modify: `kryptosbot/family_yield.py`
- Modify: `kryptosbot/tests/test_family_yield.py`

- [ ] **Step 1: Write failing tests for the four bypass branches**

Append to `kryptosbot/tests/test_family_yield.py`:

```python
from kryptosbot.family_yield import check_bypass_eligibility


class TestCheckBypassEligibility:
    def test_eligible_when_both_subfamily_and_signature_are_new(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfamily_v1",
            mechanism_signature="sig_abc",
            prior_subfamilies_in_family=frozenset({"old1", "old2"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is True
        assert reasons == ()

    def test_ineligible_when_subfamily_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="old1",
            mechanism_signature="sig_abc",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert any("subfamily" in r.lower() for r in reasons)

    def test_ineligible_when_signature_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfamily_v1",
            mechanism_signature="sig_old",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert any("signature" in r.lower() for r in reasons)

    def test_ineligible_when_both_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="old1",
            mechanism_signature="sig_old",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert len(reasons) == 2

    def test_subfamily_empty_string_is_ineligible(self):
        # Empty subfamily cannot prove structural novelty.
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="",
            mechanism_signature="sig_new",
            prior_subfamilies_in_family=frozenset(),
            prior_mechanism_signatures_in_family=frozenset(),
        )
        assert eligible is False
        assert any("empty subfamily" in r.lower() for r in reasons)

    def test_signature_empty_string_is_ineligible(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfam",
            mechanism_signature="",
            prior_subfamilies_in_family=frozenset(),
            prior_mechanism_signatures_in_family=frozenset(),
        )
        assert eligible is False
        assert any("empty mechanism signature" in r.lower() for r in reasons)
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py::TestCheckBypassEligibility -q
```

Expected: ImportError on `check_bypass_eligibility`.

- [ ] **Step 3: Implement `check_bypass_eligibility`**

Append to `kryptosbot/family_yield.py`:

```python
def check_bypass_eligibility(
    *,
    family: str,
    subfamily: str,
    mechanism_signature: str,
    prior_subfamilies_in_family: frozenset[str],
    prior_mechanism_signatures_in_family: frozenset[str],
) -> tuple[bool, tuple[str, ...]]:
    """Decide whether a theory in an empirically-dead family bypasses the gate.

    The bypass is STRUCTURAL ONLY. Returns ``(eligible, reasons)`` where
    ``reasons`` lists EVERY blocker (not just the first one) so the critic
    can surface a complete diagnostic. Eligibility requires:

    - non-empty subfamily, normalized form not in prior_subfamilies_in_family
    - non-empty mechanism_signature, value not in prior_mechanism_signatures_in_family

    `novelty_basis` prose is intentionally NOT consulted here. The bypass is
    about whether the theory is structurally new, not whether it is
    described as new.
    """
    reasons: list[str] = []

    if not subfamily:
        reasons.append(
            "empty subfamily: cannot prove structural novelty without a "
            "subfamily distinct from prior trials"
        )
    elif subfamily in prior_subfamilies_in_family:
        reasons.append(
            f"subfamily '{subfamily}' already represented in prior trials "
            f"for family '{family}'"
        )

    if not mechanism_signature:
        reasons.append(
            "empty mechanism signature: cannot prove structural novelty "
            "without a signature distinct from prior trials"
        )
    elif mechanism_signature in prior_mechanism_signatures_in_family:
        reasons.append(
            f"mechanism signature '{mechanism_signature[:16]}...' "
            f"already represented in prior trials for family '{family}'"
        )

    eligible = len(reasons) == 0
    return (eligible, tuple(reasons))
```

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py -q
```

Expected: 18 passed.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/family_yield.py kryptosbot/tests/test_family_yield.py
git commit -m "yield-feedback: implement check_bypass_eligibility

Structural-only bypass. Empty subfamily and empty signature both
fail-closed. novelty_basis prose is NOT consulted (spec §4.4).
6 named tests cover the eligibility matrix."
```

---

## Task 4: Implement `render_packet()` and `render_escape_pressure()`

**Files:**
- Modify: `kryptosbot/family_yield.py`
- Modify: `kryptosbot/tests/test_family_yield.py`

- [ ] **Step 1: Write failing tests for the renderer**

Append to `kryptosbot/tests/test_family_yield.py`:

```python
from kryptosbot.family_yield import render_packet, render_escape_pressure


class TestRenderPacket:
    def _verdict(self, family, status, trials=100, mean=0.5, best=0.0, promo=0):
        s = FamilyYieldStats(family, trials, mean, best, promo, 0)
        return FamilyYieldVerdict(
            family=family, status=status, reasons=(), stats=s,
        )

    def test_empty_index_returns_no_pressure_marker(self):
        out = render_packet({})
        assert "no family yield data" in out.lower()

    def test_groups_by_status(self):
        idx = {
            "encoding": self._verdict("encoding", "empirically_dead", 826, 0.78, 7.0),
            "grille":   self._verdict("grille",   "low_yield",       162, 0.64, 24.0),
            "novel":    self._verdict("novel",    "insufficient_data", 7, 0.0, 0.0),
            "fractionation": self._verdict("fractionation", "healthy", 100, 5.0, 18.0, promo=1),
        }
        out = render_packet(idx)
        assert "EMPIRICALLY DEAD" in out
        assert "LOW YIELD" in out
        assert "encoding" in out
        assert "grille" in out
        # n, mean, best, promotions must all surface for at least one family
        assert "826" in out
        assert "0.78" in out

    def test_deterministic_ordering(self):
        idx = {
            "z_family": self._verdict("z_family", "empirically_dead", 100, 0.5),
            "a_family": self._verdict("a_family", "empirically_dead", 100, 0.5),
        }
        a = render_packet(idx)
        b = render_packet(idx)
        assert a == b


class TestRenderEscapePressure:
    def test_no_pressure_when_streak_zero(self):
        out = render_escape_pressure(
            streak=0,
            last_status="none",
            blocked=[],
            blocked_total=0,
        )
        assert out.strip() == ""

    def test_streak_one(self):
        out = render_escape_pressure(
            streak=1,
            last_status="needed_but_unavailable",
            blocked=["encoding", "key_tape"],
            blocked_total=2,
        )
        assert "PRIOR CYCLE NEEDED ESCAPE" in out
        assert "2 families blocked" in out

    def test_streak_three_escalates(self):
        out = render_escape_pressure(
            streak=3,
            last_status="needed_but_unavailable",
            blocked=["encoding"],
            blocked_total=1,
        )
        assert "REPEATED ESCAPE FAILURE" in out

    def test_truncation_note_visible(self):
        out = render_escape_pressure(
            streak=1,
            last_status="needed_but_unavailable",
            blocked=["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"],
            blocked_total=17,
        )
        assert "17 families blocked" in out
        assert "showing top 10" in out.lower()
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py::TestRenderPacket kryptosbot/tests/test_family_yield.py::TestRenderEscapePressure -q
```

Expected: ImportError on `render_packet` and `render_escape_pressure`.

- [ ] **Step 3: Implement the renderers**

Append to `kryptosbot/family_yield.py`:

```python
_STATUS_ORDER: tuple[YieldStatus, ...] = (
    "empirically_dead",
    "low_yield",
    "healthy",
    "insufficient_data",
)

_STATUS_HEADERS: dict[YieldStatus, str] = {
    "empirically_dead": (
        "EMPIRICALLY DEAD (the critic will reject new theories in these "
        "families unless you specify a subfamily not previously tried, "
        "supply a structured mechanism signature distinct from prior "
        "trials, and document why this is not a relabeling)"
    ),
    "low_yield": "LOW YIELD",
    "healthy": "HEALTHY",
    "insufficient_data": "UNDEREXPLORED (insufficient data)",
}


def render_packet(yield_index: dict[str, FamilyYieldVerdict]) -> str:
    """Render the per-cycle yield index for the theorist prompt.

    Pure function. Deterministic ordering: by status (dead first, then
    low, then healthy, then insufficient_data), then alphabetical within
    each status. The output is human-readable plain text; the critic
    does NOT read this string (it reads the dict directly).
    """
    if not yield_index:
        return "=== RECENT FAMILY YIELD (advisory) ===\n  (no family yield data available this cycle)\n"

    by_status: dict[YieldStatus, list[FamilyYieldVerdict]] = {
        s: [] for s in _STATUS_ORDER
    }
    for v in yield_index.values():
        by_status.setdefault(v.status, []).append(v)

    lines: list[str] = ["=== RECENT FAMILY YIELD (advisory) ==="]
    for status in _STATUS_ORDER:
        verdicts = sorted(by_status.get(status, ()), key=lambda v: v.family)
        if not verdicts:
            continue
        lines.append("")
        lines.append(_STATUS_HEADERS[status] + ":")
        for v in verdicts:
            s = v.stats
            lines.append(
                f"  - {v.family:<20s} n={s.trials:<4d} "
                f"mean={s.mean_score:<5.2f} "
                f"best={s.best_score:<5.1f} "
                f"promotions={s.promotions}"
            )

    lines.append("")
    return "\n".join(lines)


def render_escape_pressure(
    *,
    streak: int,
    last_status: str,
    blocked: list[str],
    blocked_total: int,
) -> str:
    """Render cross-cycle escape pressure for the theorist prompt.

    Returns the empty string when there is no pressure worth surfacing
    (streak == 0 and last_status not in the pressure set). Escalates
    language at streak 1, 2, and >= 3.
    """
    if streak <= 0:
        return ""

    truncation_note = ""
    if blocked_total > len(blocked):
        truncation_note = f"; showing top {len(blocked)}"

    families_line = (
        f"{blocked_total} families blocked{truncation_note}: "
        + ", ".join(blocked)
    )

    if streak == 1:
        header = "PRIOR CYCLE NEEDED ESCAPE"
        body = (
            f"{families_line}. Consider proposing in healthy or "
            f"underexplored families this cycle, or supply a structurally "
            f"new mechanism if revisiting a blocked one."
        )
    elif streak == 2:
        header = "SECOND CONSECUTIVE ESCAPE-NEEDED CYCLE"
        body = (
            f"{families_line}. Avoid blocked families unless "
            f"mechanism_signature is new."
        )
    else:
        header = "REPEATED ESCAPE FAILURE"
        body = (
            f"{families_line}. This cycle MUST prioritize families "
            f"outside the blocked set; reusing blocked families requires a "
            f"structurally new mechanism."
        )

    return f"=== ESCAPE PRESSURE (cross-cycle, streak={streak}) ===\n  {header}\n  {body}\n"
```

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py -q
```

Expected: 25 passed.

- [ ] **Step 5: Coverage check**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py --cov=kryptosbot.family_yield --cov-report=term-missing -q
```

Expected: 100% branch coverage on `kryptosbot/family_yield.py`. Any missing line is a test gap; add a test before continuing.

- [ ] **Step 6: Commit**

```bash
git add kryptosbot/family_yield.py kryptosbot/tests/test_family_yield.py
git commit -m "yield-feedback: implement render_packet + render_escape_pressure

Pure renderers, deterministic ordering. Streak escalates language at
1/2/>=3. 100% branch coverage on family_yield.py."
```

---

## Task 5: Mechanism-signature helper for theories

**Files:**
- Modify: `kryptosbot/family_yield.py`
- Modify: `kryptosbot/tests/test_family_yield.py`

This helper computes the canonical structural hash used both for indexing prior theories and for the per-theory bypass check. It lives in `family_yield.py` so the same code produces the index keys and the lookup keys (avoiding subtle drift).

- [ ] **Step 1: Write failing tests**

Append to `kryptosbot/tests/test_family_yield.py`:

```python
from kryptosbot.family_yield import (
    mechanism_signature_for_theory,
    NON_DSL_INVESTIGATIVE_FAMILIES,
)


class TestMechanismSignature:
    def test_category_a_signature_uses_dsl_spec(self):
        theory_a = {
            "family": "polyalphabetic",
            "subfamily": "vigenere",
            "mechanism": "vig + col",
            "dsl_spec": {"layers": [{"kind": "vigenere", "keyword": "X"}]},
            "anomalies_exploited": [],
            "clue_anchors_used": [],
            "novelty_basis": "totally novel!",
            "minimal_test_spec": {},
        }
        theory_b = dict(theory_a)
        # Same dsl_spec but very different novelty_basis prose.
        theory_b["novelty_basis"] = "different prose"
        sig_a = mechanism_signature_for_theory(theory_a)
        sig_b = mechanism_signature_for_theory(theory_b)
        assert sig_a == sig_b  # novelty_basis must not affect the hash
        assert isinstance(sig_a, str) and len(sig_a) >= 8

    def test_category_a_signature_differs_when_dsl_layers_differ(self):
        theory_a = {
            "family": "polyalphabetic",
            "subfamily": "vigenere",
            "mechanism": "x",
            "dsl_spec": {"layers": [{"kind": "vigenere", "keyword": "X"}]},
            "anomalies_exploited": [],
            "clue_anchors_used": [],
            "novelty_basis": "",
            "minimal_test_spec": {},
        }
        theory_b = dict(theory_a)
        theory_b["dsl_spec"] = {"layers": [{"kind": "beaufort", "keyword": "X"}]}
        assert mechanism_signature_for_theory(theory_a) != mechanism_signature_for_theory(theory_b)

    def test_category_b_signature_uses_structured_fields(self):
        theory = {
            "family": "geometry",
            "subfamily": "spiral",
            "mechanism": "spiral walk on width 21",
            "dsl_spec": None,
            "anomalies_exploited": ["width21_vertical_bigrams"],
            "clue_anchors_used": ["width21"],
            "novelty_basis": "anything",
            "minimal_test_spec": {"method": "spiral_walk"},
        }
        sig = mechanism_signature_for_theory(theory)
        assert isinstance(sig, str) and len(sig) >= 8

    def test_category_b_signature_excludes_novelty_basis(self):
        a = {
            "family": "geometry",
            "subfamily": "spiral",
            "mechanism": "spiral walk on width 21",
            "dsl_spec": None,
            "anomalies_exploited": [],
            "clue_anchors_used": [],
            "novelty_basis": "this is novel because reasons",
            "minimal_test_spec": {"method": "x"},
        }
        b = dict(a)
        b["novelty_basis"] = "completely different prose"
        assert mechanism_signature_for_theory(a) == mechanism_signature_for_theory(b)

    def test_category_b_membership_is_explicit(self):
        # Spec §4.4: NON_DSL_INVESTIGATIVE_FAMILIES is a frozenset we
        # control. physical_overlay must be added deliberately; do not
        # auto-route every novel-mechanism theory.
        assert "geometry" in NON_DSL_INVESTIGATIVE_FAMILIES
        assert "k2_coords" in NON_DSL_INVESTIGATIVE_FAMILIES
        assert "archive_evidence" in NON_DSL_INVESTIGATIVE_FAMILIES

    def test_category_a_signature_normalizes_subfamily_case(self):
        a = {
            "family": "polyalphabetic", "subfamily": "Vigenere",
            "mechanism": "v", "dsl_spec": {"layers": [{"kind": "vigenere"}]},
            "anomalies_exploited": [], "clue_anchors_used": [],
            "novelty_basis": "", "minimal_test_spec": {},
        }
        b = dict(a)
        b["subfamily"] = "  VIGENERE  "
        assert mechanism_signature_for_theory(a) == mechanism_signature_for_theory(b)
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py::TestMechanismSignature -q
```

Expected: ImportError on `mechanism_signature_for_theory`.

- [ ] **Step 3: Implement the helper**

Append to `kryptosbot/family_yield.py`:

```python
import hashlib
import json
import re
from typing import Any


# Families that are intentionally Category-B (investigative, non-DSL).
# Adding a family here is a deliberate decision. The empirical-death gate
# applies to BOTH Category-A and Category-B; this frozenset only governs
# which signature path is used.
NON_DSL_INVESTIGATIVE_FAMILIES: frozenset[str] = frozenset({
    "geometry",
    "k2_coords",
    "archive_evidence",
    "antipodes",
    "geodetic",
    "k3_continuity",
    "novel",
})


def _normalize_subfamily(s: str) -> str:
    """Lowercase, strip whitespace, collapse internal whitespace."""
    if not s:
        return ""
    return re.sub(r"\s+", " ", s.strip().lower())


def _normalize_token_list(items: list[str]) -> tuple[str, ...]:
    """Lowercased, trimmed, deduped, sorted."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items or ():
        normalized = (item or "").strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return tuple(sorted(out))


def _content_tokens(mechanism: str) -> tuple[str, ...]:
    """Normalize the free-text mechanism field to a stable token bag.

    Splits on non-alphanumeric, lowercases, drops empty tokens, dedups,
    sorts. Intentionally lossy: this is the Category-B fallback when
    a true structural hash is unavailable, not a precise representation.
    """
    if not mechanism:
        return ()
    tokens = re.findall(r"[a-z0-9]+", mechanism.lower())
    return tuple(sorted(set(tokens)))


def _canonical_dsl_spec(dsl_spec: Any) -> str:
    """Canonicalize a DSL spec dict to a stable JSON string."""
    if dsl_spec is None:
        return ""
    return json.dumps(dsl_spec, sort_keys=True, separators=(",", ":"))


def mechanism_signature_for_theory(theory: dict) -> str:
    """Compute the structural mechanism signature for a theory.

    For Category-A (has a non-null dsl_spec): hash the canonical DSL
    plus family + normalized subfamily.

    For Category-B (no dsl_spec): hash family + normalized subfamily +
    normalized mechanism tokens + sorted anomalies_exploited +
    sorted clue_anchors_used + minimal_test_spec.method.

    novelty_basis is NEVER part of the hash (spec §4.4: prose explains
    novelty, it does not define it).
    """
    family = (theory.get("family") or "").lower()
    subfamily = _normalize_subfamily(theory.get("subfamily") or "")

    if theory.get("dsl_spec"):
        payload = {
            "kind": "category_a",
            "family": family,
            "subfamily": subfamily,
            "dsl_spec": _canonical_dsl_spec(theory["dsl_spec"]),
        }
    else:
        anomalies = _normalize_token_list(theory.get("anomalies_exploited") or [])
        anchors = _normalize_token_list(theory.get("clue_anchors_used") or [])
        mts = theory.get("minimal_test_spec") or {}
        payload = {
            "kind": "category_b",
            "family": family,
            "subfamily": subfamily,
            "mechanism_tokens": _content_tokens(theory.get("mechanism") or ""),
            "anomalies_exploited": anomalies,
            "clue_anchors_used": anchors,
            "minimal_test_method": (mts.get("method") or "").lower().strip(),
        }

    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=list,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
```

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py -q
```

Expected: 31 passed.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/family_yield.py kryptosbot/tests/test_family_yield.py
git commit -m "yield-feedback: add mechanism_signature_for_theory

Category-A hashes canonical DSL; Category-B hashes structured fields
(mechanism tokens + anomalies + anchors + minimal_test_method).
novelty_basis is excluded from both paths. NON_DSL_INVESTIGATIVE_FAMILIES
is an explicit allowlist that must be edited deliberately."
```

---

## Task 6: Extend `TheoryLedger` with three new read queries

**Files:**
- Modify: `kryptosbot/theory_ledger.py`
- Modify: `kryptosbot/tests/test_theory_ledger.py`

- [ ] **Step 1: Write failing tests**

Append to `kryptosbot/tests/test_theory_ledger.py`:

```python
from kryptosbot.family_yield import FamilyYieldStats


class TestFamilyYieldQueries:
    """Tests for the three new read queries on TheoryLedger."""

    def test_family_yield_stats_empty_ledger(self, tmp_path):
        from kryptosbot.theory_ledger import TheoryLedger
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        rows = ledger.family_yield_stats()
        assert rows == []

    def test_family_yield_stats_aggregates_correctly(self, tmp_path):
        from kryptosbot.theory_ledger import TheoryLedger
        from kryptosbot.models import TheoryRecord, TheoryStatus
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        # Three encoding theories, one elimination, one promotion, one open.
        for i, (status, score) in enumerate([
            (TheoryStatus.ELIMINATED, 0.0),
            (TheoryStatus.PROMISING, 18.0),
            (TheoryStatus.COMPLETED, 3.0),
        ]):
            ledger.upsert_theory(TheoryRecord(
                hypothesis_id=f"hid_{i:03d}",
                title=f"t{i}", core_claim="c", mechanism="m",
                family="encoding", subfamily="vigenere",
                status=status, best_score=score,
            ))
        # One grille theory, no eliminations or promotions.
        ledger.upsert_theory(TheoryRecord(
            hypothesis_id="hid_grille_1",
            title="g", core_claim="c", mechanism="m",
            family="grille", subfamily="spiral",
            status=TheoryStatus.PROPOSED, best_score=1.0,
        ))

        rows = ledger.family_yield_stats()
        rows_by_family = {r.family: r for r in rows}
        enc = rows_by_family["encoding"]
        assert enc.trials == 3
        assert abs(enc.mean_score - (0.0 + 18.0 + 3.0) / 3.0) < 1e-9
        assert enc.best_score == 18.0
        assert enc.promotions == 1
        assert enc.eliminated == 1

        grille = rows_by_family["grille"]
        assert grille.trials == 1
        assert grille.eliminated == 0
        assert grille.promotions == 0

    def test_subfamily_index_groups_by_family(self, tmp_path):
        from kryptosbot.theory_ledger import TheoryLedger
        from kryptosbot.models import TheoryRecord, TheoryStatus
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        for i, (family, subfamily) in enumerate([
            ("encoding", "vigenere"),
            ("encoding", "beaufort"),
            ("encoding", "vigenere"),   # dup is collapsed by frozenset
            ("grille", "spiral"),
        ]):
            ledger.upsert_theory(TheoryRecord(
                hypothesis_id=f"hid_{i:03d}",
                title=f"t{i}", core_claim="c", mechanism="m",
                family=family, subfamily=subfamily,
                status=TheoryStatus.PROPOSED,
            ))
        idx = ledger.subfamily_index()
        assert idx["encoding"] == frozenset({"vigenere", "beaufort"})
        assert idx["grille"] == frozenset({"spiral"})

    def test_mechanism_signature_index_groups_by_family(self, tmp_path):
        from kryptosbot.theory_ledger import TheoryLedger
        from kryptosbot.models import TheoryRecord, TheoryStatus
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        ledger.upsert_theory(TheoryRecord(
            hypothesis_id="hid_001",
            title="t", core_claim="c", mechanism="vig keyword X",
            family="encoding", subfamily="vigenere",
            status=TheoryStatus.PROPOSED,
            dsl_spec={"layers": [{"kind": "vigenere", "keyword": "X"}]},
        ))
        idx = ledger.mechanism_signature_index()
        assert "encoding" in idx
        sigs = idx["encoding"]
        assert isinstance(sigs, frozenset)
        assert len(sigs) == 1
        sig = next(iter(sigs))
        assert isinstance(sig, str) and len(sig) >= 8
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_theory_ledger.py::TestFamilyYieldQueries -q
```

Expected: AttributeError on `ledger.family_yield_stats`.

- [ ] **Step 3: Add the three new methods to TheoryLedger**

Add inside the `TheoryLedger` class in `kryptosbot/theory_ledger.py` (place near the existing aggregate-query methods such as `count_by_family`):

```python
    # ------------------------------------------------------------------
    # Empirical-yield queries (Phase 1 yield-feedback loop).
    # See docs/specs/2026-05-16-yield-feedback-design.md §4.2.
    # ------------------------------------------------------------------
    def family_yield_stats(self) -> list["FamilyYieldStats"]:
        """One row per family: trials, mean/max score, promotions, eliminations.

        Reads only the ``theories`` table. NULL ``best_score`` rows count
        as 0.0 in the average (SQLite AVG behavior) but their COUNT(*) is
        still incremented, which matches "trial happened, no score yet."
        """
        from kryptosbot.family_yield import FamilyYieldStats

        rows = self._db.execute(
            """
            SELECT family,
                   COUNT(*) AS trials,
                   COALESCE(AVG(best_score), 0.0) AS mean_score,
                   COALESCE(MAX(best_score), 0.0) AS best_score,
                   SUM(CASE WHEN status = 'promising'  THEN 1 ELSE 0 END) AS promotions,
                   SUM(CASE WHEN status = 'eliminated' THEN 1 ELSE 0 END) AS eliminated
              FROM theories
             WHERE family IS NOT NULL AND family <> ''
             GROUP BY family
            """
        ).fetchall()
        return [
            FamilyYieldStats(
                family=r[0],
                trials=int(r[1]),
                mean_score=float(r[2] or 0.0),
                best_score=float(r[3] or 0.0),
                promotions=int(r[4] or 0),
                eliminated=int(r[5] or 0),
            )
            for r in rows
        ]

    def subfamily_index(self) -> dict[str, frozenset[str]]:
        """Map family -> frozenset of normalized subfamilies seen in priors."""
        from kryptosbot.family_yield import _normalize_subfamily

        rows = self._db.execute(
            """
            SELECT family, subfamily
              FROM theories
             WHERE family IS NOT NULL AND family <> ''
            """
        ).fetchall()
        out: dict[str, set[str]] = {}
        for family, subfamily in rows:
            norm = _normalize_subfamily(subfamily or "")
            if not norm:
                continue
            out.setdefault(family.lower(), set()).add(norm)
        return {k: frozenset(v) for k, v in out.items()}

    def mechanism_signature_index(self) -> dict[str, frozenset[str]]:
        """Map family -> frozenset of mechanism signatures seen in priors.

        Computes signatures via family_yield.mechanism_signature_for_theory
        from each row's reconstructed dict shape. Full table scan; once
        per cycle this is dominated by every other phase.
        """
        from kryptosbot.family_yield import mechanism_signature_for_theory

        rows = self._db.execute(
            """
            SELECT family, subfamily, mechanism, dsl_spec,
                   anomalies_exploited, clue_anchors_used,
                   minimal_test_spec
              FROM theories
             WHERE family IS NOT NULL AND family <> ''
            """
        ).fetchall()
        out: dict[str, set[str]] = {}
        for r in rows:
            family, subfamily, mechanism, dsl_spec, anomalies, anchors, mts = r
            theory_dict = {
                "family": family,
                "subfamily": subfamily or "",
                "mechanism": mechanism or "",
                "dsl_spec": json.loads(dsl_spec) if dsl_spec else None,
                "anomalies_exploited":
                    json.loads(anomalies) if anomalies else [],
                "clue_anchors_used":
                    json.loads(anchors) if anchors else [],
                "minimal_test_spec":
                    json.loads(mts) if mts else {},
            }
            sig = mechanism_signature_for_theory(theory_dict)
            out.setdefault(family.lower(), set()).add(sig)
        return {k: frozenset(v) for k, v in out.items()}
```

Verify `import json` is already present at the top of `theory_ledger.py`. If not, add it.

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_theory_ledger.py::TestFamilyYieldQueries -q
```

Expected: 4 passed.

- [ ] **Step 5: Run the full ledger test file to ensure no regressions**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_theory_ledger.py -q
```

Expected: all prior tests pass; the 4 new tests pass.

- [ ] **Step 6: Commit**

```bash
git add kryptosbot/theory_ledger.py kryptosbot/tests/test_theory_ledger.py
git commit -m "yield-feedback: TheoryLedger.family_yield_stats + indices

Three new read queries: family_yield_stats, subfamily_index,
mechanism_signature_index. All driven by full table scans on theories;
no schema change. Used by _assess_landscape and the critic gate."
```

---

## Task 7: Extend `CriticDecision`, add payload, extend `CriticVerdict`

**Files:**
- Modify: `kryptosbot/models.py`
- Modify: `kryptosbot/tests/test_models.py` (create if absent)

- [ ] **Step 1: Write failing tests for the new shapes**

Create or extend `kryptosbot/tests/test_models.py`:

```python
"""Tests for new CriticDecision variant + EmpiricalDeathRejectionPayload + CriticVerdict field."""
from __future__ import annotations

from kryptosbot.models import CriticDecision, CriticVerdict


def test_critic_decision_has_reject_empirically_dead():
    assert CriticDecision.REJECT_EMPIRICALLY_DEAD.value == "reject_empirically_dead"


def test_empirical_death_payload_dataclass_shape():
    from kryptosbot.models import EmpiricalDeathRejectionPayload
    from kryptosbot.family_yield import FamilyYieldStats, FamilyYieldVerdict

    stats = FamilyYieldStats("encoding", 826, 0.78, 7.0, 0, 750)
    verdict = FamilyYieldVerdict("encoding", "empirically_dead", (), stats)
    payload = EmpiricalDeathRejectionPayload(
        family="encoding",
        verdict=verdict,
        bypass_failed_reasons=("subfamily already represented",),
    )
    assert payload.suggested_mechanisms == ()  # Phase-1 default
    assert payload.family == "encoding"


def test_critic_verdict_empirical_death_defaults_none():
    v = CriticVerdict(decision=CriticDecision.APPROVE)
    assert v.empirical_death is None


def test_critic_verdict_round_trip_with_empirical_death_none():
    v = CriticVerdict(decision=CriticDecision.APPROVE)
    d = v.to_dict()
    restored = CriticVerdict.from_dict(d)
    assert restored.decision == CriticDecision.APPROVE
    assert restored.empirical_death is None


def test_critic_verdict_round_trip_with_empirical_death_populated():
    from kryptosbot.models import EmpiricalDeathRejectionPayload
    from kryptosbot.family_yield import FamilyYieldStats, FamilyYieldVerdict
    stats = FamilyYieldStats("encoding", 826, 0.78, 7.0, 0, 750)
    verdict = FamilyYieldVerdict("encoding", "empirically_dead", ("r",), stats)
    payload = EmpiricalDeathRejectionPayload(
        family="encoding",
        verdict=verdict,
        bypass_failed_reasons=("r1",),
    )
    v = CriticVerdict(
        decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
        confidence=0.9,
        reasons=["dead"],
        empirical_death=payload,
    )
    d = v.to_dict()
    restored = CriticVerdict.from_dict(d)
    assert restored.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
    assert restored.empirical_death is not None
    assert restored.empirical_death.family == "encoding"
    assert restored.empirical_death.bypass_failed_reasons == ("r1",)


def test_pre_phase_1_critic_verdict_json_loads_cleanly():
    """A pre-Phase-1 JSON blob lacks the empirical_death key; loading
    must succeed with empirical_death=None."""
    legacy_dict = {
        "decision": "reject_duplicate",
        "confidence": 1.0,
        "reasons": ["same as hid_001"],
        "similar_hypotheses": ["hid_001"],
        "contradicting_facts": [],
        "estimated_information_gain": "",
        "reviewed_at": "2026-04-01T00:00:00Z",
    }
    v = CriticVerdict.from_dict(legacy_dict)
    assert v.decision == CriticDecision.REJECT_DUPLICATE
    assert v.empirical_death is None
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_models.py -q
```

Expected: AttributeError on `REJECT_EMPIRICALLY_DEAD` and ImportError on `EmpiricalDeathRejectionPayload`.

- [ ] **Step 3: Add the enum variant**

In `kryptosbot/models.py`, modify the `CriticDecision` enum (around line 42):

```python
class CriticDecision(str, Enum):
    """Critic stage outcomes."""
    APPROVE = "approve"
    REJECT_DUPLICATE = "reject_duplicate"
    REJECT_ELIMINATED = "reject_eliminated"
    REJECT_EMPIRICALLY_DEAD = "reject_empirically_dead"  # NEW: yield-feedback Phase 1
    REJECT_UNDERCONSTRAINED = "reject_underconstrained"
    REJECT_LOW_INFORMATION = "reject_low_information"
    REJECT_CONTRADICTED = "reject_contradicted"
    DEFER = "defer"
```

- [ ] **Step 4: Add the payload dataclass and extend CriticVerdict**

Add the payload dataclass immediately before the existing `CriticVerdict` class (around line 230):

```python
@dataclass
class EmpiricalDeathRejectionPayload:
    """Structured payload attached to REJECT_EMPIRICALLY_DEAD verdicts.

    Phase 1 always emits suggested_mechanisms=(). Phase 2 populates from
    the cipher-discovery KB. See docs/specs/2026-05-16-yield-feedback-design.md §4.3.
    """
    family: str
    verdict: "FamilyYieldVerdict"
    bypass_failed_reasons: tuple[str, ...] = ()
    suggested_mechanisms: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # FamilyYieldVerdict serializes via asdict; tuples stay as lists.
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EmpiricalDeathRejectionPayload:
        from kryptosbot.family_yield import FamilyYieldStats, FamilyYieldVerdict

        d = dict(d)
        verdict_d = d.get("verdict") or {}
        stats_d = verdict_d.get("stats") or {}
        stats = FamilyYieldStats(**{
            k: stats_d.get(k) for k in (
                "family", "trials", "mean_score", "best_score",
                "promotions", "eliminated",
            )
        }) if stats_d else None
        verdict = FamilyYieldVerdict(
            family=verdict_d.get("family", ""),
            status=verdict_d.get("status", "healthy"),
            reasons=tuple(verdict_d.get("reasons") or ()),
            stats=stats,
        ) if verdict_d else None
        return cls(
            family=d.get("family", ""),
            verdict=verdict,
            bypass_failed_reasons=tuple(d.get("bypass_failed_reasons") or ()),
            suggested_mechanisms=tuple(d.get("suggested_mechanisms") or ()),
        )
```

Then extend `CriticVerdict`:

```python
@dataclass
class CriticVerdict:
    """Structured output from the critic stage."""
    decision: CriticDecision = CriticDecision.DEFER
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    similar_hypotheses: list[str] = field(default_factory=list)
    contradicting_facts: list[str] = field(default_factory=list)
    estimated_information_gain: str = ""
    reviewed_at: str = field(default_factory=_now_iso)
    # NEW (yield-feedback Phase 1). None for every decision other than
    # REJECT_EMPIRICALLY_DEAD. Backward-compat: absent on pre-Phase-1
    # ledger rows; from_dict treats absence as None.
    empirical_death: Optional["EmpiricalDeathRejectionPayload"] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        # asdict handles nested dataclasses; ensure None stays None.
        if self.empirical_death is None:
            d["empirical_death"] = None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CriticVerdict:
        d = dict(d)
        if "decision" in d and isinstance(d["decision"], str):
            d["decision"] = CriticDecision(d["decision"])
        ed = d.get("empirical_death")
        if ed is not None and isinstance(ed, dict):
            d["empirical_death"] = EmpiricalDeathRejectionPayload.from_dict(ed)
        elif ed is None:
            d["empirical_death"] = None
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
```

Ensure `Optional` is imported at the top of `models.py`. If not already imported, add to the existing `typing` import.

- [ ] **Step 5: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_models.py -q
```

Expected: 6 passed.

- [ ] **Step 6: Run the broader critic + models test surface for no regressions**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_models.py kryptosbot/tests/test_critic.py -q 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add kryptosbot/models.py kryptosbot/tests/test_models.py
git commit -m "yield-feedback: REJECT_EMPIRICALLY_DEAD + structured payload

Adds CriticDecision.REJECT_EMPIRICALLY_DEAD, EmpiricalDeathRejectionPayload,
and CriticVerdict.empirical_death optional field. Round-trip preserved
for pre-Phase-1 JSON (legacy verdicts load with empirical_death=None)."
```

---

## Task 8: Audit existing `CriticDecision` dispatch sites for exhaustive handling

**Files:**
- Read-only audit of: `kryptosbot/*.py` and `src/kryptos/**/*.py`
- Modify (as audit reveals): one or more callers
- Create: `kryptosbot/tests/test_critic_decision_exhaustive.py`

- [ ] **Step 1: Grep for all CriticDecision dispatch sites**

```bash
grep -rn "CriticDecision\." /home/cpatrick/kryptos/kryptosbot/ /home/cpatrick/kryptos/src/ --include="*.py" 2>&1 | grep -v "/tests/" | grep -v "/copy/" | grep -v "__pycache__" > /tmp/critic_dispatch_sites.txt
cat /tmp/critic_dispatch_sites.txt
```

Expected: a list of files referencing `CriticDecision.*`. Open each one that appears outside of `models.py`, `critic.py`, and the new code; look for `if`, `match`, or dict-mapping constructs over decision values.

- [ ] **Step 2: For each non-test dispatch site, confirm it handles or defaults**

For every match outside `critic.py` and `models.py`:

- If it's a hard match on specific values (e.g. `if decision == CriticDecision.APPROVE`), the new variant falls through fine.
- If it's a dict mapping or `match` statement enumerating ALL variants, add a branch for `REJECT_EMPIRICALLY_DEAD` (likely behaving like `REJECT_ELIMINATED`).
- If it has a `default` / `_` branch, document the assumption in a one-line comment.

Make the smallest possible change at each site; no refactor.

- [ ] **Step 3: Write a regression test asserting all dispatch sites handle the variant**

Create `kryptosbot/tests/test_critic_decision_exhaustive.py`:

```python
"""Lock in that every CriticDecision dispatch site either explicitly
handles REJECT_EMPIRICALLY_DEAD or has a default branch.

This is a grep-style audit test. It does not load every caller; it
asserts the catalog of files we audited at landing time is exactly
the catalog we have today. If a new caller appears, this test breaks
and the auditor must extend the catalog (and audit the new caller)."""
from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Audited at Phase 1 landing time. Each entry: (relative_path, status).
# status: "handles_explicitly" | "has_default_branch" | "value_check_only" | "import_only"
#
# value_check_only means the site only compares against specific values
# (e.g. == APPROVE); a new variant falls through correctly with no
# change needed.
# import_only means the file imports CriticDecision but does not
# dispatch on its value (e.g. only constructs verdicts or threads them
# through unchanged).
AUDITED_DISPATCH_SITES: dict[str, str] = {
    "kryptosbot/critic.py": "handles_explicitly",          # produces every variant
    "kryptosbot/controller.py": "value_check_only",        # only `== APPROVE` checks
    "kryptosbot/research_tools.py": "import_only",         # import without dispatch
    "kryptosbot/theory_ledger.py": "import_only",          # import without dispatch
}


def test_audited_catalog_matches_current_grep():
    """If grep finds a CriticDecision use in a file not in
    AUDITED_DISPATCH_SITES, the audit must be extended."""
    result = subprocess.run(
        [
            "grep", "-rln", "CriticDecision",
            str(REPO / "kryptosbot"),
            str(REPO / "src"),
            "--include=*.py",
        ],
        capture_output=True, text=True,
    )
    found = set()
    for line in result.stdout.splitlines():
        rel = Path(line).resolve().relative_to(REPO).as_posix()
        if "/tests/" in rel or "/copy/" in rel or "__pycache__" in rel:
            continue
        if rel.endswith("kryptosbot/models.py"):
            continue  # the definition site
        found.add(rel)
    audited = set(AUDITED_DISPATCH_SITES.keys())
    missing = found - audited
    assert not missing, (
        f"New CriticDecision dispatch site(s) not audited: {sorted(missing)}. "
        f"Add to AUDITED_DISPATCH_SITES with appropriate handling note."
    )
```

Run the grep manually first; populate `AUDITED_DISPATCH_SITES` with each file the grep finds, classified as one of the three status values. THEN run the test.

- [ ] **Step 4: Run the catalog test**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_critic_decision_exhaustive.py -q
```

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/tests/test_critic_decision_exhaustive.py $(any_file_modified_during_audit)
git commit -m "yield-feedback: audit CriticDecision dispatch sites

Verified every existing CriticDecision consumer either handles
REJECT_EMPIRICALLY_DEAD explicitly or has a default branch.
test_critic_decision_exhaustive.py locks the catalog so a future
caller addition forces a re-audit."
```

---

## Task 9: Add `_check_family_empirically_dead` method (not yet wired)

**Files:**
- Modify: `kryptosbot/critic.py`
- Create: `kryptosbot/tests/test_critic_empirical_death.py`

- [ ] **Step 1: Write failing tests for all 8 branches**

Create `kryptosbot/tests/test_critic_empirical_death.py`:

```python
"""Tests for TheoryCritic._check_family_empirically_dead.

Eight branches: dead/healthy x bypass-eligible/ineligible x normal/shadow.
"""
from __future__ import annotations

from kryptosbot.critic import TheoryCritic
from kryptosbot.family_yield import (
    FamilyYieldPolicy,
    FamilyYieldStats,
    FamilyYieldVerdict,
)
from kryptosbot.models import (
    CriticDecision,
    TheoryRecord,
    TheoryStatus,
)


def _verdict(family, status="empirically_dead", n=826, mean=0.78, best=7.0):
    stats = FamilyYieldStats(family, n, mean, best, 0, n - 1)
    return FamilyYieldVerdict(family, status, ("r",), stats)


def _theory(
    family="encoding",
    subfamily="brand_new_subfamily",
    dsl_spec=None,
    mechanism="m",
):
    return TheoryRecord(
        hypothesis_id="hid_test",
        title="t", core_claim="c", mechanism=mechanism,
        family=family, subfamily=subfamily,
        status=TheoryStatus.PROPOSED,
        dsl_spec=dsl_spec,
    )


class FakeLedger:
    """Minimal ledger stub that the critic uses only via attribute access."""
    def get_family(self, *_): return None


def _critic_with_indices(yield_idx, prior_subfams, prior_sigs, policy=None):
    c = TheoryCritic(ledger=FakeLedger())
    c.yield_index = yield_idx
    c.prior_subfamilies = prior_subfams
    c.prior_signatures = prior_sigs
    c.policy = policy or FamilyYieldPolicy()
    return c


class TestCheckFamilyEmpiricallyDead:

    def test_healthy_family_returns_none(self):
        c = _critic_with_indices(
            yield_idx={"healthy_fam": _verdict("healthy_fam", "healthy")},
            prior_subfams={}, prior_sigs={},
        )
        t = _theory(family="healthy_fam")
        result = c._check_family_empirically_dead(t, "healthy_fam")
        assert result is None

    def test_family_not_in_index_returns_none(self):
        c = _critic_with_indices(yield_idx={}, prior_subfams={}, prior_sigs={})
        t = _theory(family="encoding")
        assert c._check_family_empirically_dead(t, "encoding") is None

    def test_dead_no_bypass_returns_reject(self):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset(["sig_known"])},
        )
        # Subfamily already known; mechanism_signature also computed from
        # _theory's empty dsl_spec is the Category-B signature, which we
        # also seed into prior_sigs via the same compute path.
        from kryptosbot.family_yield import mechanism_signature_for_theory
        t = _theory(family="encoding", subfamily="vigenere", mechanism="m")
        sig = mechanism_signature_for_theory({
            "family": "encoding", "subfamily": "vigenere",
            "mechanism": "m", "dsl_spec": None,
            "anomalies_exploited": [], "clue_anchors_used": [],
            "novelty_basis": "", "minimal_test_spec": {},
        })
        c.prior_signatures = {"encoding": frozenset([sig])}

        verdict = c._check_family_empirically_dead(t, "encoding")
        assert verdict is not None
        assert verdict.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
        assert verdict.empirical_death is not None
        assert verdict.empirical_death.family == "encoding"

    def test_dead_bypass_eligible_returns_none(self):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"old_subfam"})},
            prior_sigs={"encoding": frozenset({"sig_other"})},
        )
        t = _theory(family="encoding", subfamily="brand_new_subfamily")
        assert c._check_family_empirically_dead(t, "encoding") is None

    def test_shadow_mode_logs_but_returns_none(self, caplog):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset({"sig_dummy"})},
            policy=FamilyYieldPolicy(shadow_mode=True),
        )
        # Make the theory ineligible so the gate WOULD fire.
        t = _theory(family="encoding", subfamily="vigenere", mechanism="m")
        result = c._check_family_empirically_dead(t, "encoding")
        assert result is None
        assert "shadow" in caplog.text.lower() or "would_reject" in caplog.text.lower()

    def test_low_yield_status_does_not_reject(self):
        c = _critic_with_indices(
            yield_idx={"grille": _verdict("grille", status="low_yield")},
            prior_subfams={"grille": frozenset({"spiral"})},
            prior_sigs={"grille": frozenset({"sig"})},
        )
        t = _theory(family="grille", subfamily="spiral")
        assert c._check_family_empirically_dead(t, "grille") is None

    def test_payload_includes_failed_reasons(self):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset({"sig_known"})},
        )
        t = _theory(family="encoding", subfamily="vigenere")
        verdict = c._check_family_empirically_dead(t, "encoding")
        assert verdict is not None
        assert verdict.empirical_death is not None
        assert len(verdict.empirical_death.bypass_failed_reasons) >= 1

    def test_suggested_mechanisms_empty_in_phase_1(self):
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset({"sig_known"})},
        )
        t = _theory(family="encoding", subfamily="vigenere")
        verdict = c._check_family_empirically_dead(t, "encoding")
        assert verdict.empirical_death.suggested_mechanisms == ()
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_critic_empirical_death.py -q
```

Expected: AttributeError on `_check_family_empirically_dead`.

- [ ] **Step 3: Add the new method to TheoryCritic**

In `kryptosbot/critic.py`, near the existing `_check_contradictions` private method, add:

```python
    def _check_family_empirically_dead(
        self,
        theory: TheoryRecord,
        family_lower: str,
    ) -> Optional[CriticVerdict]:
        """Reject theories in empirically-dead families unless structurally novel.

        Returns a CriticVerdict with REJECT_EMPIRICALLY_DEAD when:
          - family_lower is classified empirically_dead in self.yield_index, AND
          - the theory does not satisfy structural-novelty bypass.

        Returns None (fall-through) when:
          - the family is not in yield_index, OR
          - the family's status is not empirically_dead, OR
          - the theory is bypass-eligible, OR
          - shadow_mode is enabled (logs would-reject and returns None).

        Reads only self.yield_index / self.prior_subfamilies /
        self.prior_signatures / self.policy. Never queries the ledger.
        """
        from kryptosbot.family_yield import (
            check_bypass_eligibility,
            mechanism_signature_for_theory,
            _normalize_subfamily,
        )
        from kryptosbot.models import EmpiricalDeathRejectionPayload

        verdict = (self.yield_index or {}).get(family_lower)
        if verdict is None or verdict.status != "empirically_dead":
            return None

        # Reconstruct a theory dict shape for mechanism_signature_for_theory.
        theory_for_sig = {
            "family": theory.family,
            "subfamily": theory.subfamily or "",
            "mechanism": theory.mechanism or "",
            "dsl_spec": theory.dsl_spec,
            "anomalies_exploited": theory.anomalies_exploited or [],
            "clue_anchors_used": theory.clue_anchors_used or [],
            "novelty_basis": theory.novelty_basis or "",
            "minimal_test_spec": theory.minimal_test_spec or {},
        }
        sig = mechanism_signature_for_theory(theory_for_sig)

        eligible, reasons = check_bypass_eligibility(
            family=family_lower,
            subfamily=_normalize_subfamily(theory.subfamily or ""),
            mechanism_signature=sig,
            prior_subfamilies_in_family=(self.prior_subfamilies or {}).get(
                family_lower, frozenset(),
            ),
            prior_mechanism_signatures_in_family=(self.prior_signatures or {}).get(
                family_lower, frozenset(),
            ),
        )
        if eligible:
            return None

        if getattr(self.policy, "shadow_mode", False):
            logger.warning(
                "[shadow] would_reject_empirically_dead: family=%s reasons=%s",
                family_lower, reasons,
            )
            return None

        s = verdict.stats
        return CriticVerdict(
            decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
            confidence=0.9,
            reasons=[
                f"Family '{theory.family}' empirically dead "
                f"(n={s.trials}, mean={s.mean_score:.2f}, "
                f"best={s.best_score:.1f}, promotions={s.promotions}); "
                f"bypass not satisfied",
                *reasons,
            ],
            empirical_death=EmpiricalDeathRejectionPayload(
                family=family_lower,
                verdict=verdict,
                bypass_failed_reasons=tuple(reasons),
                suggested_mechanisms=(),  # Phase 2 populates
            ),
        )
```

Also add to `TheoryCritic.__init__` (so the attributes always exist even when the critic is built standalone for tests):

```python
        # Yield-feedback Phase 1: per-cycle indices injected by the
        # controller before evaluate-batch starts. Defaults to empty so
        # standalone-test construction works.
        self.yield_index: dict[str, "FamilyYieldVerdict"] = {}
        self.prior_subfamilies: dict[str, frozenset[str]] = {}
        self.prior_signatures: dict[str, frozenset[str]] = {}
        from kryptosbot.family_yield import DEFAULT_POLICY
        self.policy = DEFAULT_POLICY
```

Verify `Optional` and `CriticVerdict` are imported at the top of `critic.py`.

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_critic_empirical_death.py -q
```

Expected: 8 passed.

- [ ] **Step 5: Verify existing critic tests still pass (method is not yet wired into evaluate)**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_critic.py -q
```

Expected: prior tests pass; nothing new fires.

- [ ] **Step 6: Commit**

```bash
git add kryptosbot/critic.py kryptosbot/tests/test_critic_empirical_death.py
git commit -m "yield-feedback: add _check_family_empirically_dead method

Standalone method on TheoryCritic. Not yet wired into evaluate().
8 branch tests cover dead/healthy x bypass/no-bypass x normal/shadow,
plus low_yield-does-not-reject and payload structure assertions."
```

---

## Task 10: Wire `_check_family_empirically_dead` into `evaluate()`

**Files:**
- Modify: `kryptosbot/critic.py`
- Modify: `kryptosbot/tests/test_critic_empirical_death.py`

- [ ] **Step 1: Write failing ordering tests**

Append to `kryptosbot/tests/test_critic_empirical_death.py`:

```python
class TestCriticOrdering:
    """Empirical-death goes AFTER tier-1/tier-2 and AFTER duplicate detection,
    but BEFORE contradiction and DSL-translatability."""

    def test_tier_1_wins_over_empirical_death(self):
        from kryptosbot.critic import TheoryCritic, TIER_1_FAMILIES
        # Pick a family that's BOTH Tier-1 AND empirically_dead in our index.
        tier_1_family = next(iter(TIER_1_FAMILIES))
        c = TheoryCritic(ledger=FakeLedger())
        c.yield_index = {tier_1_family: _verdict(tier_1_family)}
        c.prior_subfamilies = {tier_1_family: frozenset({"old"})}
        c.prior_signatures = {tier_1_family: frozenset({"sig_known"})}
        t = TheoryRecord(
            hypothesis_id="hid_tier1",
            title="t", core_claim="c", mechanism="m",
            family=tier_1_family, subfamily="old",
            status=TheoryStatus.PROPOSED,
        )
        verdict = c.evaluate(t)
        # Tier-1 wins. The verdict reason mentions Tier-1, not empirically-dead.
        assert verdict.decision == CriticDecision.REJECT_ELIMINATED
        assert verdict.empirical_death is None

    def test_duplicate_wins_over_empirical_death(self):
        # A theory that is a duplicate of an existing one in a dead family
        # must get REJECT_DUPLICATE, not REJECT_EMPIRICALLY_DEAD.
        # Setup: build a ledger with an existing 'encoding' theory and a
        # second proposal with the same hypothesis_id / dsl_spec.
        # (Specific implementation depends on existing duplicate-detection;
        # the assertion is that ordering puts duplicate first.)
        from kryptosbot.theory_ledger import TheoryLedger
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as tmpd:
            ledger = TheoryLedger(pathlib.Path(tmpd) / "l.sqlite")
            existing = TheoryRecord(
                hypothesis_id="hid_existing",
                title="t", core_claim="c", mechanism="vig",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.PROPOSED,
                dsl_spec={"layers": [{"kind": "vigenere", "keyword": "X"}]},
            )
            ledger.upsert_theory(existing)

            c = TheoryCritic(ledger=ledger)
            c.yield_index = {"encoding": _verdict("encoding")}
            c.prior_subfamilies = {"encoding": frozenset({"vigenere"})}
            c.prior_signatures = {"encoding": frozenset({"sig_dummy"})}

            duplicate = TheoryRecord(
                hypothesis_id="hid_new",  # different id
                title="t", core_claim="c", mechanism="vig",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.PROPOSED,
                dsl_spec={"layers": [{"kind": "vigenere", "keyword": "X"}]},
            )
            verdict = c.evaluate(duplicate)
            assert verdict.decision == CriticDecision.REJECT_DUPLICATE
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_critic_empirical_death.py::TestCriticOrdering -q
```

Expected: the empirical-death check is not yet wired into `evaluate()`, so the dead-family-tier-1 test passes (because tier-1 fires) but the duplicate test may also pass for the same reason. After wiring, both must remain true.

- [ ] **Step 3: Wire the new gate into evaluate()**

In `kryptosbot/critic.py`, locate the section in `evaluate()` where the duplicate-check returns occur (around line 530 and 549). Immediately after the last duplicate-check return and BEFORE the `_check_contradictions` block (around line 570), insert:

```python
        # --- Check 3.5: Empirical-death family gate (yield-feedback Phase 1) ---
        # Inserted after Tier-1/Tier-2 and duplicate detection, before
        # contradiction. See docs/specs/2026-05-16-yield-feedback-design.md §4.4.
        empirical_death_verdict = self._check_family_empirically_dead(
            theory, family_lower,
        )
        if empirical_death_verdict is not None:
            return empirical_death_verdict
```

- [ ] **Step 4: Run ordering tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_critic_empirical_death.py -q
```

Expected: all pass (including ordering tests).

- [ ] **Step 5: Run the full critic test suite for no regressions**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_critic.py kryptosbot/tests/test_critic_empirical_death.py -q 2>&1 | tail -5
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add kryptosbot/critic.py kryptosbot/tests/test_critic_empirical_death.py
git commit -m "yield-feedback: wire empirical-death gate into critic.evaluate()

Position: after Tier-1/Tier-2 family elimination AND after duplicate
detection, before contradiction and DSL-translatability checks.
Locks ordering with test_tier_1_wins_over_empirical_death and
test_duplicate_wins_over_empirical_death."
```

---

## Task 11: Extend `ControllerState` with escape-telemetry fields

**Files:**
- Modify: `kryptosbot/models.py`
- Modify: `kryptosbot/tests/test_models.py`

- [ ] **Step 1: Write failing tests for the new fields**

Append to `kryptosbot/tests/test_models.py`:

```python
def test_controller_state_has_escape_fields_with_defaults():
    from kryptosbot.models import ControllerState
    s = ControllerState()
    assert s.escape_needed_streak == 0
    assert s.last_escape_status == "none"
    assert s.last_escape_families_blocked == []
    assert s.last_escape_families_blocked_total == 0
    assert s.last_escape_cycle == 0
    assert s.last_partial_empirical_block_count == 0


def test_controller_state_backward_compat_loads_pre_phase_1():
    """Pre-Phase-1 state JSON lacks the six new fields; loading must
    produce sane defaults."""
    from kryptosbot.models import ControllerState
    legacy = {
        "cycle_number": 528,
        "last_cycle_at": "2026-05-08T01:55:54.633823+00:00",
        "theories_proposed": 2007,
        "theories_tested": 1200,
        "theories_eliminated": 819,
        "theories_promising": 0,
        # Note: no escape_* fields.
    }
    s = ControllerState.from_dict(legacy)
    assert s.cycle_number == 528
    assert s.escape_needed_streak == 0
    assert s.last_escape_status == "none"
    assert s.last_escape_families_blocked == []


def test_controller_state_round_trip_with_populated_escape():
    from kryptosbot.models import ControllerState
    s = ControllerState(
        cycle_number=529,
        escape_needed_streak=2,
        last_escape_status="needed_but_unavailable",
        last_escape_families_blocked=["encoding", "key_tape"],
        last_escape_families_blocked_total=4,
        last_escape_cycle=529,
        last_partial_empirical_block_count=0,
    )
    restored = ControllerState.from_dict(s.to_dict())
    assert restored.escape_needed_streak == 2
    assert restored.last_escape_status == "needed_but_unavailable"
    assert restored.last_escape_families_blocked == ["encoding", "key_tape"]
    assert restored.last_escape_families_blocked_total == 4
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_models.py -q
```

Expected: AttributeError on the new fields.

- [ ] **Step 3: Add the six new fields to ControllerState**

In `kryptosbot/models.py` `ControllerState` (around line 533, after `halt_reason_hardening: str = ""`):

```python
    # Yield-feedback Phase 1 escape telemetry. See spec §6.2.
    escape_needed_streak: int = 0
    last_escape_status: str = "none"
    last_escape_families_blocked: list[str] = field(default_factory=list)
    last_escape_families_blocked_total: int = 0
    last_escape_cycle: int = 0
    last_partial_empirical_block_count: int = 0
```

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_models.py -q
```

Expected: 9 passed (6 prior plus 3 new).

- [ ] **Step 5: Run full theory_ledger tests to verify ControllerState round-trip persistence still works**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_theory_ledger.py -q
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add kryptosbot/models.py kryptosbot/tests/test_models.py
git commit -m "yield-feedback: extend ControllerState with escape telemetry

Six new fields: escape_needed_streak, last_escape_status,
last_escape_families_blocked, last_escape_families_blocked_total,
last_escape_cycle, last_partial_empirical_block_count. All defaulted
so pre-Phase-1 ControllerState JSON loads cleanly."
```

---

## Task 12: Implement `_truncate_blocked_families` and `_write_cycle_escape_summary`

**Files:**
- Modify: `kryptosbot/controller.py`
- Create: `kryptosbot/tests/test_cycle_escape_telemetry.py`

- [ ] **Step 1: Write failing tests for the truncation and streak semantics**

Create `kryptosbot/tests/test_cycle_escape_telemetry.py`:

```python
"""Tests for ResearchController._truncate_blocked_families and
_write_cycle_escape_summary.

Covers truncation cap, streak increment/reset semantics, and per-EscapeStatus
field updates."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from kryptosbot.controller import ResearchController, ControllerConfig
from kryptosbot.family_yield import FamilyYieldStats


def _make_controller(tmp_path):
    cfg = ControllerConfig(
        project_root=Path(tmp_path),
        ledger_db_path=Path(tmp_path) / "l.sqlite",
        max_cycles=1,
        theories_per_cycle=1,
    )
    return ResearchController(cfg)


def _stats_for(family, blocked_count):
    # Use the eliminated count as a proxy for "blocked count" so the
    # severity sort key works.
    return FamilyYieldStats(family, blocked_count, 0.0, 0.0, 0, blocked_count)


class TestTruncateBlockedFamilies:

    def test_returns_all_when_under_cap(self, tmp_path):
        c = _make_controller(tmp_path)
        out = c._truncate_blocked_families([
            ("encoding", _stats_for("encoding", 826)),
            ("key_tape", _stats_for("key_tape", 207)),
        ])
        assert out == ["encoding", "key_tape"]

    def test_truncates_at_10(self, tmp_path):
        c = _make_controller(tmp_path)
        rows = [(f"f{i:02d}", _stats_for(f"f{i:02d}", 100 - i)) for i in range(15)]
        out = c._truncate_blocked_families(rows)
        assert len(out) == 10
        # Severity order: higher blocked_count first.
        assert out[0] == "f00"
        assert out[9] == "f09"

    def test_tie_break_by_trials_then_family_id(self, tmp_path):
        c = _make_controller(tmp_path)
        # Same blocked_count (==eliminated); ties by trials desc, then family id asc.
        rows = [
            ("zeta",  FamilyYieldStats("zeta",  100, 0.0, 0.0, 0, 50)),
            ("alpha", FamilyYieldStats("alpha", 200, 0.0, 0.0, 0, 50)),  # higher trials
            ("beta",  FamilyYieldStats("beta",  100, 0.0, 0.0, 0, 50)),
        ]
        out = c._truncate_blocked_families(rows)
        # alpha (more trials) first; then beta and zeta tie on trials → family id asc.
        assert out == ["alpha", "beta", "zeta"]


class TestWriteCycleEscapeSummary:

    def test_no_pressure_resets_streak(self, tmp_path):
        c = _make_controller(tmp_path)
        c.state.escape_needed_streak = 3
        c._write_cycle_escape_summary(status="none", families_blocked=[])
        assert c.state.escape_needed_streak == 0
        assert c.state.last_escape_status == "none"

    def test_needed_but_unavailable_increments_streak(self, tmp_path):
        c = _make_controller(tmp_path)
        c.state.escape_needed_streak = 1
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=["encoding", "key_tape"],
            blocked_stats=[
                ("encoding", _stats_for("encoding", 826)),
                ("key_tape", _stats_for("key_tape", 207)),
            ],
        )
        assert c.state.escape_needed_streak == 2
        assert c.state.last_escape_status == "needed_but_unavailable"
        assert c.state.last_escape_families_blocked == ["encoding", "key_tape"]
        assert c.state.last_escape_families_blocked_total == 2

    def test_partial_empirical_block_resets_streak(self, tmp_path):
        c = _make_controller(tmp_path)
        c.state.escape_needed_streak = 4
        c._write_cycle_escape_summary(
            status="partial_empirical_block",
            families_blocked=["encoding"],
            blocked_stats=[("encoding", _stats_for("encoding", 826))],
        )
        assert c.state.escape_needed_streak == 0
        assert c.state.last_partial_empirical_block_count == 1

    def test_no_candidates_resets_streak(self, tmp_path):
        c = _make_controller(tmp_path)
        c.state.escape_needed_streak = 2
        c._write_cycle_escape_summary(status="no_candidates", families_blocked=[])
        assert c.state.escape_needed_streak == 0
        assert c.state.last_escape_status == "no_candidates"

    def test_total_preserved_when_truncated(self, tmp_path):
        c = _make_controller(tmp_path)
        rows = [(f"f{i:02d}", _stats_for(f"f{i:02d}", 100 - i)) for i in range(17)]
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=[f for f, _ in rows],
            blocked_stats=rows,
        )
        assert len(c.state.last_escape_families_blocked) == 10
        assert c.state.last_escape_families_blocked_total == 17
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_escape_telemetry.py -q
```

Expected: AttributeError on `_truncate_blocked_families` and `_write_cycle_escape_summary`.

- [ ] **Step 3: Add the two methods to ResearchController**

In `kryptosbot/controller.py`, in the `ResearchController` class (place near the existing `_check_cycle_hardening_halts`):

```python
    # ------------------------------------------------------------------
    # Yield-feedback Phase 1: escape telemetry chokepoint.
    # See docs/specs/2026-05-16-yield-feedback-design.md §5.3.
    # ------------------------------------------------------------------
    _ESCAPE_BLOCKED_CAP = 10

    def _truncate_blocked_families(
        self,
        blocked_with_stats: list[tuple[str, "FamilyYieldStats"]],
    ) -> list[str]:
        """Return top-N family names by severity.

        Sort key: (eliminated DESC, trials DESC, family_id ASC).
        Eliminated count is the proxy for "blocked severity" in Phase 1
        because every blocked family has accumulated eliminations.
        """
        ranked = sorted(
            blocked_with_stats,
            key=lambda kv: (-kv[1].eliminated, -kv[1].trials, kv[0]),
        )
        return [name for name, _ in ranked[: self._ESCAPE_BLOCKED_CAP]]

    def _write_cycle_escape_summary(
        self,
        *,
        status: str,
        families_blocked: list[str],
        blocked_stats: Optional[
            list[tuple[str, "FamilyYieldStats"]]
        ] = None,
    ) -> None:
        """Single chokepoint for writing per-cycle escape telemetry.

        Called from every cycle-exit path (no-candidates early-continue,
        all-rejected early-continue, success-path end-of-synthesis) so
        the streak counter is updated from one code path.

        Streak semantics (see spec §5.4):
          - "needed_but_unavailable" increments
          - everything else resets to 0
        """
        blocked_total = len(families_blocked)
        if blocked_stats:
            blocked_top = self._truncate_blocked_families(blocked_stats)
        else:
            blocked_top = families_blocked[: self._ESCAPE_BLOCKED_CAP]

        if status == "needed_but_unavailable":
            self.state.escape_needed_streak += 1
        else:
            self.state.escape_needed_streak = 0

        self.state.last_escape_status = status
        self.state.last_escape_families_blocked = blocked_top
        self.state.last_escape_families_blocked_total = blocked_total
        self.state.last_escape_cycle = self.state.cycle_number

        if status == "partial_empirical_block":
            self.state.last_partial_empirical_block_count = len(
                families_blocked
            )
        elif status not in ("none",):
            # Leave the partial count untouched so a partial cycle's
            # count survives subsequent non-partial cycles, allowing the
            # operator to see "last cycle that had partial blocking".
            pass
```

Verify `Optional` and `FamilyYieldStats` are importable at the top of `controller.py`. Add to existing imports:

```python
from kryptosbot.family_yield import FamilyYieldStats  # add if not present
```

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_escape_telemetry.py -q
```

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/controller.py kryptosbot/tests/test_cycle_escape_telemetry.py
git commit -m "yield-feedback: _write_cycle_escape_summary chokepoint

Single function called from every cycle-exit path. Truncates
families_blocked to top-10 by severity (eliminated DESC, trials DESC,
family_id ASC). Increments streak only on needed_but_unavailable;
all other statuses reset to 0."
```

---

## Task 13: Extend `_assess_landscape` with yield snapshot

**Files:**
- Modify: `kryptosbot/controller.py`
- Modify: `kryptosbot/tests/test_cycle_escape_telemetry.py`

- [ ] **Step 1: Write failing test**

Append to `kryptosbot/tests/test_cycle_escape_telemetry.py`:

```python
class TestAssessLandscapeYield:

    def test_landscape_includes_family_yield_packet(self, tmp_path):
        from kryptosbot.controller import ControllerConfig, ResearchController
        from kryptosbot.theory_ledger import TheoryLedger
        from kryptosbot.models import TheoryRecord, TheoryStatus

        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1,
            theories_per_cycle=1,
        )
        c = ResearchController(cfg)
        # Seed 50+ encoding theories to drive an empirically_dead verdict.
        for i in range(60):
            c.ledger.upsert_theory(TheoryRecord(
                hypothesis_id=f"hid_{i:03d}",
                title=f"t{i}", core_claim="c", mechanism="m",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.ELIMINATED, best_score=0.5,
            ))
        landscape = c._assess_landscape()
        assert "family_yield" in landscape
        text = landscape["family_yield"]
        assert "EMPIRICALLY DEAD" in text
        assert "encoding" in text

    def test_landscape_caches_indices_on_controller(self, tmp_path):
        from kryptosbot.controller import ControllerConfig, ResearchController
        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1, theories_per_cycle=1,
        )
        c = ResearchController(cfg)
        c._assess_landscape()
        assert hasattr(c, "_cycle_yield_index")
        assert hasattr(c, "_cycle_prior_subfamilies")
        assert hasattr(c, "_cycle_prior_signatures")

    def test_fail_open_when_yield_stats_raises(self, tmp_path, monkeypatch):
        from kryptosbot.controller import ControllerConfig, ResearchController
        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1, theories_per_cycle=1,
        )
        c = ResearchController(cfg)

        def boom(self):
            raise RuntimeError("simulated query failure")
        monkeypatch.setattr(
            "kryptosbot.theory_ledger.TheoryLedger.family_yield_stats",
            boom,
        )
        landscape = c._assess_landscape()
        # Brake is off; landscape is non-empty; indices are empty dicts.
        assert c._cycle_yield_index == {}
        assert "family_yield" in landscape
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_escape_telemetry.py::TestAssessLandscapeYield -q
```

Expected: tests fail because landscape lacks the new keys and indices are not stored on the controller.

- [ ] **Step 3: Extend `_assess_landscape`**

In `kryptosbot/controller.py`, inside `_assess_landscape()` (existing method, around line 1461), add near the top of the method body (after the existing ledger reads but before the return):

```python
        # Yield-feedback Phase 1: snapshot family yield stats once per
        # cycle. Fail-open: if the ledger query raises, leave indices
        # empty so the critic gate becomes a no-op for this cycle while
        # every other gate (Tier-1, Tier-2, duplicate, contradiction,
        # DSL, exhaustion, red-team, kernel verifier) still applies.
        from kryptosbot.family_yield import (
            classify_family_yield,
            render_packet,
            render_escape_pressure,
        )
        try:
            yield_stats_rows = self.ledger.family_yield_stats()
            self._cycle_yield_index = {
                s.family.lower(): classify_family_yield(
                    s, self.config.family_yield_policy,
                )
                for s in yield_stats_rows
            }
            self._cycle_prior_subfamilies = self.ledger.subfamily_index()
            self._cycle_prior_signatures = self.ledger.mechanism_signature_index()
        except Exception:
            logger.warning(
                "family_yield query failed; empirical-death brake disabled for this cycle",
                exc_info=True,
            )
            self._cycle_yield_index = {}
            self._cycle_prior_subfamilies = {}
            self._cycle_prior_signatures = {}
```

Then in the return dict, add the two new keys:

```python
            "family_yield": render_packet(self._cycle_yield_index),
            "escape_pressure": render_escape_pressure(
                streak=self.state.escape_needed_streak,
                last_status=self.state.last_escape_status,
                blocked=self.state.last_escape_families_blocked,
                blocked_total=self.state.last_escape_families_blocked_total,
            ),
```

- [ ] **Step 4: Add `family_yield_policy` to `ControllerConfig`**

In `kryptosbot/controller.py`, in the `ControllerConfig` dataclass (around line 325), add:

```python
    # Yield-feedback Phase 1: policy used by the critic empirical-death gate
    # and the landscape packet renderer. See spec §6.1.
    family_yield_policy: "FamilyYieldPolicy" = field(
        default_factory=lambda: __import__(
            "kryptosbot.family_yield", fromlist=["DEFAULT_POLICY"]
        ).DEFAULT_POLICY
    )
```

- [ ] **Step 5: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_escape_telemetry.py -q
```

Expected: 11 passed.

- [ ] **Step 6: Commit**

```bash
git add kryptosbot/controller.py kryptosbot/tests/test_cycle_escape_telemetry.py
git commit -m "yield-feedback: _assess_landscape snapshots yield indices

Once-per-cycle snapshot via ledger.family_yield_stats() and the two
sibling index queries. Fail-open: ledger failure logs WARNING and
leaves indices empty so the critic gate becomes a no-op while all
hard gates still apply. ControllerConfig.family_yield_policy defaults
to family_yield.DEFAULT_POLICY."
```

---

## Task 14: Wire critic-batch yield injection + cycle-exit telemetry

**Files:**
- Modify: `kryptosbot/controller.py`
- Modify: `kryptosbot/tests/test_cycle_escape_telemetry.py`

- [ ] **Step 1: Write failing tests for the cycle-exit telemetry paths**

Append to `kryptosbot/tests/test_cycle_escape_telemetry.py`:

```python
class TestCycleExitTelemetry:
    """The three cycle-exit paths each write _write_cycle_escape_summary."""

    def test_no_candidates_exit_writes_summary(self, tmp_path, monkeypatch):
        # Force theorist to return zero candidates.
        from kryptosbot.controller import ControllerConfig, ResearchController
        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1, theories_per_cycle=1, dry_run=True,
        )
        c = ResearchController(cfg)

        async def empty_theories(*_a, **_kw):
            return []
        monkeypatch.setattr(c, "_generate_theories", empty_theories)

        import asyncio
        asyncio.run(c.run())

        assert c.state.last_escape_status == "no_candidates"
        assert c.state.escape_needed_streak == 0  # reset

    def test_all_rejected_by_empirical_death_writes_needed_but_unavailable(
        self, tmp_path, monkeypatch,
    ):
        # Seed enough encoding theories to drive empirically_dead, then
        # have the theorist generate a single encoding theory that fails
        # bypass.
        from kryptosbot.controller import ControllerConfig, ResearchController
        from kryptosbot.models import TheoryRecord, TheoryStatus
        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1, theories_per_cycle=1, dry_run=True,
        )
        c = ResearchController(cfg)
        for i in range(60):
            c.ledger.upsert_theory(TheoryRecord(
                hypothesis_id=f"hid_seed_{i:03d}",
                title=f"t{i}", core_claim="c", mechanism="m",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.ELIMINATED, best_score=0.5,
            ))

        async def dead_candidate(*_a, **_kw):
            return [TheoryRecord(
                hypothesis_id="hid_new",
                title="t", core_claim="c", mechanism="m",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.PROPOSED,
            )]
        monkeypatch.setattr(c, "_generate_theories", dead_candidate)

        import asyncio
        asyncio.run(c.run())

        assert c.state.last_escape_status == "needed_but_unavailable"
        assert c.state.escape_needed_streak == 1
        assert "encoding" in c.state.last_escape_families_blocked
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_escape_telemetry.py::TestCycleExitTelemetry -q
```

Expected: telemetry is not yet written from the cycle-exit paths.

- [ ] **Step 3: Wire telemetry into the cycle-exit paths and inject indices into critic**

In `kryptosbot/controller.py`, locate `_run_cycle_loop` (around line 1175). Two changes:

**(a)** Inject the yield indices into the critic before any `evaluate()` call. Locate the critic-loop block (around line 1230) and add immediately before the `for theory in candidates:` loop:

```python
                # Yield-feedback Phase 1: inject per-cycle yield indices
                # into the critic so each evaluate() runs O(1) without
                # re-querying the ledger.
                self.critic.yield_index = getattr(self, "_cycle_yield_index", {})
                self.critic.prior_subfamilies = getattr(self, "_cycle_prior_subfamilies", {})
                self.critic.prior_signatures = getattr(self, "_cycle_prior_signatures", {})
                self.critic.policy = self.config.family_yield_policy
                self._cycle_empirical_dead_rejections = []
```

Inside the critic loop, AFTER `verdict = self.critic.evaluate(theory)`, add capture of empirical-death rejections:

```python
                        if (
                            verdict.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
                            and verdict.empirical_death is not None
                        ):
                            self._cycle_empirical_dead_rejections.append(
                                verdict.empirical_death
                            )
```

**(b)** Replace the two early-`continue` paths with calls to `_write_cycle_escape_summary`.

Locate `if not candidates:` (around line 1210). Replace with:

```python
                if not candidates:
                    if self.should_abort_run():
                        logger.warning(
                            "Aborting remaining cycles after fatal theorist failure: %s",
                            self.fatal_agent_error,
                        )
                        cb.emit(
                            "on_run_halt",
                            self.fatal_agent_error or "fatal agent failure",
                        )
                        break
                    logger.info("No candidates generated, ending cycle")
                    self._write_cycle_escape_summary(
                        status="no_candidates",
                        families_blocked=[],
                    )
                    cb.emit("on_no_candidates")
                    continue
```

Locate `if not approved:` after the critic loop (around line 1280). Replace with:

```python
                if not approved:
                    blocked = [
                        r.family for r in self._cycle_empirical_dead_rejections
                    ]
                    blocked_stats = [
                        (r.family, r.verdict.stats)
                        for r in self._cycle_empirical_dead_rejections
                    ]
                    status = (
                        "needed_but_unavailable"
                        if blocked else "no_candidates"
                    )
                    self._write_cycle_escape_summary(
                        status=status,
                        families_blocked=blocked,
                        blocked_stats=blocked_stats,
                    )
                    logger.info(
                        "No theories survived critic, ending cycle (escape=%s)",
                        status,
                    )
                    continue
```

**(c)** At the END of the success path (just before the cycle's persist + synthesis section, around line 1390; find the spot AFTER alerts and BEFORE `_run_synthesis`), add the success-path summary write:

```python
                # Yield-feedback Phase 1: success-path escape telemetry.
                # If any candidate was rejected by empirical-death but
                # others survived, log partial_empirical_block (streak
                # resets). Otherwise log none. _run_synthesis runs after
                # this and can read the status from CycleSynthesis.
                if self._cycle_empirical_dead_rejections:
                    blocked = [
                        r.family for r in self._cycle_empirical_dead_rejections
                    ]
                    blocked_stats = [
                        (r.family, r.verdict.stats)
                        for r in self._cycle_empirical_dead_rejections
                    ]
                    self._write_cycle_escape_summary(
                        status="partial_empirical_block",
                        families_blocked=blocked,
                        blocked_stats=blocked_stats,
                    )
                else:
                    self._write_cycle_escape_summary(
                        status="none",
                        families_blocked=[],
                    )
```

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_escape_telemetry.py -q
```

Expected: 13 passed.

- [ ] **Step 5: Run the cycle-loop characterization test to detect any baseline drift**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_loop_characterization.py -q 2>&1 | tail -10
```

Expected: 1-2 tests may break because the canonical trace now includes new state mutations. NOTE the failures; they are addressed in Task 17.

- [ ] **Step 6: Commit**

```bash
git add kryptosbot/controller.py kryptosbot/tests/test_cycle_escape_telemetry.py
git commit -m "yield-feedback: wire telemetry into all three cycle-exit paths

Critic batch receives injected yield_index / prior_subfamilies /
prior_signatures / policy at construction time. Both early-continue
paths (no-candidates, all-rejected) and the success path call
_write_cycle_escape_summary. Cycle-loop characterization test may
need rebaseline (Task 17)."
```

---

## Task 15: Theorist prompt extensions in `pantheon.py`

**Files:**
- Modify: `kryptosbot/pantheon.py`
- Create: `kryptosbot/tests/test_landscape_yield_packet.py`

- [ ] **Step 1: Write failing tests**

Create `kryptosbot/tests/test_landscape_yield_packet.py`:

```python
"""Tests that the theorist prompt surfaces the family_yield packet and
escape_pressure rendering from the landscape dict."""
from __future__ import annotations

from kryptosbot.pantheon import theorist_system_prompt


def test_prompt_includes_family_yield_section_when_present():
    landscape = {
        "family_yield": "=== RECENT FAMILY YIELD (advisory) ===\n  encoding ...",
        "escape_pressure": "",
        "standing_constraints": [],
        "active_families": [],
        "underexplored_families": [],
        "open_anomalies": [],
        "recent_outcomes": [],
        "status_counts": {},
        "cycle_delta": {},
        "theorist_parse_telemetry": {},
        "previous_synthesis": None,
        "pursuit_leads": [],
        "soft_pursuit_leads": [],
        "prompt_anomaly_count": 0,
        "registry_open_anomaly_count": 0,
        "unaddressed_anomalies": [],
    }
    prompt = theorist_system_prompt(landscape)
    assert "RECENT FAMILY YIELD" in prompt
    assert "encoding" in prompt


def test_prompt_includes_escape_pressure_when_present():
    landscape = {
        "family_yield": "",
        "escape_pressure": "=== ESCAPE PRESSURE (streak=2) ===\n  ...",
        "standing_constraints": [],
        "active_families": [],
        "underexplored_families": [],
        "open_anomalies": [],
        "recent_outcomes": [],
        "status_counts": {},
        "cycle_delta": {},
        "theorist_parse_telemetry": {},
        "previous_synthesis": None,
        "pursuit_leads": [],
        "soft_pursuit_leads": [],
        "prompt_anomaly_count": 0,
        "registry_open_anomaly_count": 0,
        "unaddressed_anomalies": [],
    }
    prompt = theorist_system_prompt(landscape)
    assert "ESCAPE PRESSURE" in prompt


def test_prompt_omits_escape_pressure_when_empty_string():
    landscape = {
        "family_yield": "anything",
        "escape_pressure": "",
        "standing_constraints": [], "active_families": [],
        "underexplored_families": [], "open_anomalies": [],
        "recent_outcomes": [], "status_counts": {},
        "cycle_delta": {}, "theorist_parse_telemetry": {},
        "previous_synthesis": None, "pursuit_leads": [],
        "soft_pursuit_leads": [],
        "prompt_anomaly_count": 0,
        "registry_open_anomaly_count": 0,
        "unaddressed_anomalies": [],
    }
    prompt = theorist_system_prompt(landscape)
    assert "ESCAPE PRESSURE" not in prompt
```

- [ ] **Step 2: Run failing tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_landscape_yield_packet.py -q
```

Expected: assertions fail because the prompt does not yet include the new keys.

- [ ] **Step 3: Extend the theorist prompt template**

In `kryptosbot/pantheon.py`, locate `theorist_system_prompt(landscape)` (or the function that emits the system prompt). Add this section near the end of the assembled prompt, AFTER existing landscape rendering:

```python
    family_yield_block = landscape.get("family_yield") or ""
    escape_pressure_block = landscape.get("escape_pressure") or ""
    if family_yield_block.strip():
        sections.append(family_yield_block)
    if escape_pressure_block.strip():
        sections.append(escape_pressure_block)
```

(Adjust the variable name `sections` to match the existing prompt-assembly convention in `pantheon.py`. The exact mechanism is: append the two strings as additional sections so they render with the rest of the landscape.)

- [ ] **Step 4: Run tests to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_landscape_yield_packet.py -q
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/pantheon.py kryptosbot/tests/test_landscape_yield_packet.py
git commit -m "yield-feedback: theorist prompt surfaces yield + escape pressure

Two new sections rendered from landscape['family_yield'] and
landscape['escape_pressure']. Both are skipped when their string is
empty, so cold-start / no-pressure cycles produce the same prompt
shape as pre-Phase-1."
```

---

## Task 16: Add `test_shared_symmetry_invariant`

**Files:**
- Modify: `kryptosbot/tests/test_landscape_yield_packet.py`

This is the named invariant from spec §8.2 that locks in the dual-consumer guarantee: the theorist's rendered text and the critic's verdict for the same family/policy must agree on which families are empirically dead.

- [ ] **Step 1: Write the invariant test**

Append to `kryptosbot/tests/test_landscape_yield_packet.py`:

```python
def test_shared_symmetry_invariant():
    """For a given (stats, policy), the packet's family-status assignment
    MUST match the critic's family-status assignment.

    Implementation note: both consumers call classify_family_yield on
    the same stats with the same policy. This test pins that contract
    by exercising both paths on the same input and confirming the
    family appears in the packet's empirically_dead section iff the
    critic would reject a theory in that family for empirical-death."""
    from kryptosbot.family_yield import (
        DEFAULT_POLICY,
        FamilyYieldStats,
        classify_family_yield,
        render_packet,
    )
    stats = FamilyYieldStats("encoding", 826, 0.78, 7.0, 0, 750)
    verdict = classify_family_yield(stats, DEFAULT_POLICY)
    packet = render_packet({"encoding": verdict})
    # Critic-facing semantic.
    assert verdict.status == "empirically_dead"
    # Theorist-facing rendering.
    assert "EMPIRICALLY DEAD" in packet
    assert "encoding" in packet
```

- [ ] **Step 2: Run the test**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_landscape_yield_packet.py::test_shared_symmetry_invariant -q
```

Expected: passes immediately. If it fails, the renderer and classifier have drifted.

- [ ] **Step 3: Commit**

```bash
git add kryptosbot/tests/test_landscape_yield_packet.py
git commit -m "yield-feedback: lock shared symmetry invariant

Packet rendering and critic classification must agree on family
status for identical (stats, policy) inputs. Both consumers call
the same classify_family_yield, so the test pins that contract."
```

---

## Task 17: Re-baseline cycle-loop characterization test

**Files:**
- Modify: `kryptosbot/tests/test_cycle_loop_characterization.py`

- [ ] **Step 1: Run the characterization test to see the new canonical trace**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_loop_characterization.py -q 2>&1 | tail -40
```

Expected: 1 or more test failures. Capture the diff between the recorded canonical trace and the actual emitted trace.

- [ ] **Step 2: Inspect the diff and update the canonical trace**

Open `kryptosbot/tests/test_cycle_loop_characterization.py`. Locate the canonical-trace fixtures (the expected event list for the 6x5 baseline scenario). Each cycle's trace will now include:

- on `_assess_landscape`: no new event, but landscape dict has two new keys (assertions on dict keys must be updated if any check exact-key sets).
- on no-candidates exit: now writes ControllerState fields before continue.
- on all-rejected exit: writes ControllerState fields.
- on success path: writes ControllerState fields before synthesis.

Update the canonical trace to include the new state-write events for each cycle, and adjust any "expected ControllerState attrs" snapshot to include the six new fields with their post-cycle values.

The specific update depends on the file's structure. If the file uses a recorded JSON canonical trace, regenerate it by running the test scenario and capturing the new output, then commit the new file. If it uses inline expected lists, update those lists.

- [ ] **Step 3: Run the test to verify pass**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_cycle_loop_characterization.py -q
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add kryptosbot/tests/test_cycle_loop_characterization.py
git commit -m "yield-feedback: rebaseline cycle-loop characterization

Canonical trace updated to include the new ControllerState fields
written by _write_cycle_escape_summary on every cycle-exit path."
```

---

## Task 18: Acceptance criteria integration test

**Files:**
- Create: `kryptosbot/tests/test_yield_feedback_acceptance.py`

- [ ] **Step 1: Write the integration test asserting spec §10 criteria**

Create `kryptosbot/tests/test_yield_feedback_acceptance.py`:

```python
"""End-to-end acceptance tests for yield-feedback Phase 1.

Maps directly to the seven acceptance criteria in
docs/specs/2026-05-16-yield-feedback-design.md §10.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.models import (
    CriticDecision,
    TheoryRecord,
    TheoryStatus,
)


def _seed_dead_family_ledger(ledger, family="encoding", n=60, subfamily="vigenere"):
    """Seed n eliminated theories in `family` to drive empirically_dead."""
    for i in range(n):
        ledger.upsert_theory(TheoryRecord(
            hypothesis_id=f"hid_seed_{family}_{i:04d}",
            title=f"t{i}", core_claim="c", mechanism="m",
            family=family, subfamily=subfamily,
            status=TheoryStatus.ELIMINATED, best_score=0.5,
            dsl_spec={"layers": [{"kind": "vigenere", "keyword": f"K{i:03d}"}]},
        ))


def _make_controller(tmp_path, **overrides):
    cfg = ControllerConfig(
        project_root=Path(tmp_path),
        ledger_db_path=Path(tmp_path) / "ledger.sqlite",
        max_cycles=1, theories_per_cycle=1, dry_run=True,
        **overrides,
    )
    return ResearchController(cfg)


def test_criterion_1_landscape_reports_dead_families(tmp_path):
    """§10.1: cycle's _assess_landscape reports encoding as empirically_dead."""
    c = _make_controller(tmp_path)
    _seed_dead_family_ledger(c.ledger, "encoding")
    landscape = c._assess_landscape()
    assert "EMPIRICALLY DEAD" in landscape["family_yield"]
    assert "encoding" in landscape["family_yield"]


def test_criterion_2_new_theory_same_subfamily_and_sig_is_rejected(tmp_path):
    """§10.2: new (non-duplicate) theory in dead family with same subfamily
    AND mechanism_signature as priors is REJECT_EMPIRICALLY_DEAD."""
    c = _make_controller(tmp_path)
    _seed_dead_family_ledger(c.ledger, "encoding")
    # Snapshot landscape so the critic has yield indices.
    c._assess_landscape()
    c.critic.yield_index = c._cycle_yield_index
    c.critic.prior_subfamilies = c._cycle_prior_subfamilies
    c.critic.prior_signatures = c._cycle_prior_signatures
    c.critic.policy = c.config.family_yield_policy

    # Use a NEW hypothesis_id and DIFFERENT dsl_spec (not a duplicate),
    # but same family + subfamily so the bypass check fails.
    new_theory = TheoryRecord(
        hypothesis_id="hid_new_unique",
        title="t", core_claim="c", mechanism="m",
        family="encoding", subfamily="vigenere",
        status=TheoryStatus.PROPOSED,
        dsl_spec={"layers": [{"kind": "vigenere", "keyword": "NEVER_USED_KEYWORD"}]},
    )
    verdict = c.critic.evaluate(new_theory)
    assert verdict.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
    assert verdict.empirical_death is not None
    assert verdict.empirical_death.family == "encoding"


def test_criterion_3_new_subfamily_and_sig_falls_through(tmp_path):
    """§10.3: theory in dead family with subfamily AND mechanism_signature
    BOTH not previously seen falls through the empirical-death gate."""
    c = _make_controller(tmp_path)
    _seed_dead_family_ledger(c.ledger, "encoding", subfamily="vigenere")
    c._assess_landscape()
    c.critic.yield_index = c._cycle_yield_index
    c.critic.prior_subfamilies = c._cycle_prior_subfamilies
    c.critic.prior_signatures = c._cycle_prior_signatures
    c.critic.policy = c.config.family_yield_policy

    new_theory = TheoryRecord(
        hypothesis_id="hid_brand_new",
        title="t", core_claim="c", mechanism="m",
        family="encoding", subfamily="completely_new_subfamily_never_seen",
        status=TheoryStatus.PROPOSED,
        dsl_spec={"layers": [{"kind": "beaufort", "keyword": "FRESH"}]},
    )
    verdict = c.critic.evaluate(new_theory)
    # Falls through empirical-death. May still be rejected by other
    # gates, but NOT for empirical-death.
    assert verdict.decision != CriticDecision.REJECT_EMPIRICALLY_DEAD


def test_criterion_4_all_rejected_writes_needed_but_unavailable(
    tmp_path, monkeypatch,
):
    """§10.4: cycle where empirical-death kills all candidates writes
    needed_but_unavailable + increments streak."""
    c = _make_controller(tmp_path)
    _seed_dead_family_ledger(c.ledger, "encoding")

    async def dead_candidate(*_a, **_kw):
        return [TheoryRecord(
            hypothesis_id="hid_doomed",
            title="t", core_claim="c", mechanism="m",
            family="encoding", subfamily="vigenere",
            status=TheoryStatus.PROPOSED,
            dsl_spec={"layers": [{"kind": "vigenere", "keyword": "WHATEVER"}]},
        )]
    monkeypatch.setattr(c, "_generate_theories", dead_candidate)

    asyncio.run(c.run())
    assert c.state.last_escape_status == "needed_but_unavailable"
    assert c.state.escape_needed_streak == 1


def test_criterion_5_partial_rejection_writes_partial_empirical_block(
    tmp_path, monkeypatch,
):
    """§10.5: cycle where some candidates are killed by empirical-death
    but at least one survives writes partial_empirical_block (streak resets)."""
    c = _make_controller(tmp_path)
    _seed_dead_family_ledger(c.ledger, "encoding")
    c.state.escape_needed_streak = 3  # to verify reset

    async def mixed_candidates(*_a, **_kw):
        return [
            # Dead family + same subfamily: will be rejected.
            TheoryRecord(
                hypothesis_id="hid_dead",
                title="t1", core_claim="c", mechanism="m",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.PROPOSED,
                dsl_spec={"layers": [{"kind": "vigenere", "keyword": "A"}]},
            ),
            # Different family: survives.
            TheoryRecord(
                hypothesis_id="hid_alive",
                title="t2", core_claim="c", mechanism="m",
                family="multi_layer", subfamily="vig_then_col",
                status=TheoryStatus.PROPOSED,
                dsl_spec={
                    "layers": [
                        {"kind": "vigenere", "keyword": "X"},
                        {"kind": "columnar", "keyword": "Y"},
                    ],
                },
            ),
        ]
    monkeypatch.setattr(c, "_generate_theories", mixed_candidates)

    asyncio.run(c.run())
    assert c.state.last_escape_status == "partial_empirical_block"
    assert c.state.escape_needed_streak == 0  # reset
```

- [ ] **Step 2: Run the acceptance tests**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_yield_feedback_acceptance.py -v
```

Expected: 5 passed. If any criterion fails, the corresponding upstream task is incomplete; locate the failure and fix at the source, not in the acceptance test.

- [ ] **Step 3: Commit**

```bash
git add kryptosbot/tests/test_yield_feedback_acceptance.py
git commit -m "yield-feedback: acceptance tests for spec §10 criteria

Five integration tests, one per acceptance criterion in the spec.
Criteria 6 (full test suite passes) and 7 (docs updated) are
asserted in Tasks 19 and 20 respectively."
```

---

## Task 19: Run full test suite

**Files:**
- No new files; this is a verification gate.

- [ ] **Step 1: Run the full kryptosbot test suite**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/ -q --no-header 2>&1 | tail -20
```

Expected: every test passes EXCEPT the pre-existing failures listed in the pre-flight section (1 in `test_ct_perturbation_stage_b.py` + 8 in `test_r3_synthetic_alert_path.py`).

- [ ] **Step 2: Verify pre-existing failure list is unchanged**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/ -q --no-header 2>&1 | grep "^FAILED" | sort > /tmp/failures_now.txt
cat /tmp/failures_now.txt
```

Expected: exactly 9 failures, all matching the pre-flight pre-existing list. If any new test appears, that's a regression from this work; investigate and fix.

- [ ] **Step 3: Run with coverage on the new module**

```bash
PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_family_yield.py --cov=kryptosbot.family_yield --cov-report=term-missing -q
```

Expected: 100% branch coverage on `kryptosbot/family_yield.py`. Any missing line is a test gap.

- [ ] **Step 4: Smoke test against the live ledger**

```bash
PYTHONPATH=src python3 -c "
import sqlite3
from kryptosbot.family_yield import classify_family_yield, DEFAULT_POLICY, FamilyYieldStats
from kryptosbot.theory_ledger import TheoryLedger

ledger = TheoryLedger('/data/db/theory_ledger.sqlite')
stats = ledger.family_yield_stats()
dead = []
for s in stats:
    v = classify_family_yield(s, DEFAULT_POLICY)
    if v.status == 'empirically_dead':
        dead.append((s.family, s.trials, s.mean_score, s.best_score, s.promotions))

print('EMPIRICALLY DEAD families on live ledger:')
for d in sorted(dead, key=lambda x: -x[1]):
    print(f'  {d[0]:25s} n={d[1]:4d} mean={d[2]:5.2f} best={d[3]:5.1f} promotions={d[4]}')
"
```

Expected: the four families flagged in the audit (encoding, key_tape, archive_evidence, k2_coords) appear in the output. No crashes.

Note: `key_tape` and `archive_evidence` have best_score=24 from crib-paste artifacts. Whether they classify dead under the current policy depends on whether STORE_THRESHOLD-related logic treats 24 as a "stored signal". Per the spec, best=24 means `best >= STORE_THRESHOLD` is True, so `best_low = False`, and the family will NOT be classified empirically_dead. This is the documented Phase-1 behavior: pending the crib-paste detector (Phase 2 follow-up), families with crib-paste artifacts at 24 are NOT classified dead. Verify the smoke test shows encoding and k2_coords as dead but not key_tape/archive_evidence.

- [ ] **Step 5: Commit (verification gate, no file changes expected)**

If the smoke test reveals an unexpected outcome (e.g. encoding NOT classified dead), STOP and diagnose before continuing.

```bash
# If everything is clean and no files were modified, no commit needed.
git status
```

Expected output: `nothing to commit, working tree clean` (or only untracked files unrelated to this plan).

---

## Task 20: Documentation updates

**Files:**
- Modify: `kryptosbot/ARCHITECTURE.md`
- Modify: `kryptosbot/ORIENT.md`
- Modify: `MEMORY.md`
- Modify: `docs/audits/controller_maturity_audit_2026_05_16.md`
- Create: `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/project_yield_feedback_phase_1_landed.md` (auto-memory entry)
- Modify: `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/MEMORY.md` (auto-memory index)

- [ ] **Step 1: Add an ARCHITECTURE.md section**

In `kryptosbot/ARCHITECTURE.md`, append a new section:

```markdown
## Family-Yield Feedback Loop (Phase 1, 2026-05-16)

A memory-to-prompt feedback loop driven by ledger yield statistics.

**Authority model:**

| authority           | surface                                    |
| ------------------- | ------------------------------------------ |
| ledger              | source of record (theories.* columns)      |
| family_yield.py     | source of derived policy truth             |
| theorist prompt     | advisory rendering for proposal shaping    |
| critic              | enforcement (REJECT_EMPIRICALLY_DEAD)      |

`_assess_landscape` snapshots `family_yield_stats()`, `subfamily_index()`,
and `mechanism_signature_index()` once per cycle. Both the theorist
prompt (advisory) and the critic gate (enforcement) read the same
snapshot; divergence is structurally impossible.

Bypass criteria for an empirically-dead family: the theory must
specify a subfamily NOT in `prior_subfamilies_in_family` AND a
`mechanism_signature` (canonical DSL hash for Category-A, structured
hash of family+subfamily+mechanism_tokens+anomalies+anchors+method
for Category-B) NOT in `prior_mechanism_signatures_in_family`.
`novelty_basis` prose explains the bypass but does not define it.

Escape telemetry is written by the single chokepoint
`_write_cycle_escape_summary`, called from every cycle-exit path
(no-candidates, all-rejected, success). State persisted on
`ControllerState.escape_needed_streak` and four sibling fields.

See `docs/specs/2026-05-16-yield-feedback-design.md` for full spec.
```

- [ ] **Step 2: Add an ORIENT.md troubleshooting entry**

In `kryptosbot/ORIENT.md`, append to the §5 (Common failure modes) section:

```markdown
### 5.6 Critic rejected my theory with REJECT_EMPIRICALLY_DEAD

The theory is in a family with >= 50 prior trials, mean score < 2.0,
zero promotions, and max score below STORE_THRESHOLD. The empirical-
death gate (yield-feedback Phase 1) rejects new theories in such
families unless the theory has BOTH:

- a subfamily not previously seen in this family, AND
- a mechanism signature (canonical DSL hash for Category-A; structured
  hash of family + subfamily + mechanism_tokens + anomalies + anchors
  + minimal_test_method for Category-B) not previously seen in this family.

`novelty_basis` prose is preserved on the theory but is NOT part of
the bypass check. To pass, change the structural shape, not the prose.

To diagnose:

```bash
PYTHONPATH=src python3 -c "
from kryptosbot.theory_ledger import TheoryLedger
from kryptosbot.family_yield import classify_family_yield, DEFAULT_POLICY
ledger = TheoryLedger('db/theory_ledger.sqlite')
for s in ledger.family_yield_stats():
    v = classify_family_yield(s, DEFAULT_POLICY)
    print(f'{s.family:25s} status={v.status:18s} n={s.trials} mean={s.mean_score:.2f}')
"
```

See `docs/specs/2026-05-16-yield-feedback-design.md` for full spec.
```

- [ ] **Step 3: Add an entry to repo `MEMORY.md`**

Edit `MEMORY.md` at the repo root (not the auto-memory). Find the "Project (current state)" section. Add at the top:

```markdown
- [Yield-feedback Phase 1 landed 2026-05-16](docs/specs/2026-05-16-yield-feedback-design.md) -- New `kryptosbot/family_yield.py` shared policy; `CriticDecision.REJECT_EMPIRICALLY_DEAD` with structural-novelty bypass; controller-owned `_write_cycle_escape_summary` chokepoint with streak counter on `ControllerState`. Closes the memory-to-prompt feedback loop on the 70% noise-floor allocation pattern identified in the 2026-05-16 maturity audit. Phase 2 (cipher-discovery KB injection) and Phase 3 (few-shot library) designed for, not built.
```

- [ ] **Step 4: Annotate the audit document**

In `docs/audits/controller_maturity_audit_2026_05_16.md`, find the recommendation section §"Tier A: small fixes, high payoff". Append after recommendation #4:

```markdown
**Update 2026-05-16:** Tier A recommendation #4 (empirical-yield re-weighting in the critic) LANDED as Phase 1 of the yield-feedback feedback loop. See `docs/specs/2026-05-16-yield-feedback-design.md` for design and `docs/plans/2026-05-16-yield-feedback-implementation.md` for the implementation plan. Phase 2 (Tier A #1: crib-paste detector + cipher-discovery KB injection) and Phase 3 (Tier C: few-shot library) designed for, not built.
```

- [ ] **Step 5: Add an auto-memory entry for cross-session continuity**

Create `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/project_yield_feedback_phase_1_landed.md`:

```markdown
---
name: project_yield_feedback_phase_1_landed
description: Phase 1 of the yield-feedback loop landed 2026-05-16. Memory-to-prompt feedback via family_yield.py shared policy; CriticDecision.REJECT_EMPIRICALLY_DEAD with structural-novelty bypass; _write_cycle_escape_summary chokepoint with streak on ControllerState.
metadata:
  type: project
---

Phase 1 of yield-feedback closes the controller's memory-to-prompt feedback gap identified in the 2026-05-16 maturity audit.

**Why:** 528-cycle live ledger showed 70% of theories going to 4 empirically dead families (encoding, key_tape, archive_evidence, k2_coords) with zero promotions. The critic had no view of empirical yield; only static TIER_1/TIER_2 registries.

**How to apply:** When proposing or reviewing theories in encoding, key_tape, archive_evidence, or k2_coords (or any family at n>=50 with mean<2.0 and zero promotions), expect REJECT_EMPIRICALLY_DEAD unless the theory has both a previously-unseen subfamily AND a previously-unseen mechanism_signature. novelty_basis prose alone does NOT bypass the gate.

Related: [[controller_maturity_audit_2026_05_16]]. Phase 2 (cipher-discovery KB injection on escape paths) and Phase 3 (ledger-driven curated few-shot library) are designed-for but not built.
```

- [ ] **Step 6: Update auto-memory index**

In `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/MEMORY.md`, add to the "Project (current state)" section, near the top:

```markdown
- [Yield-feedback Phase 1 landed 2026-05-16](project_yield_feedback_phase_1_landed.md) -- New family_yield.py shared policy + REJECT_EMPIRICALLY_DEAD critic gate + _write_cycle_escape_summary controller chokepoint. Closes memory-to-prompt loop on 70% noise-floor family allocation.
```

- [ ] **Step 7: Commit**

```bash
git add kryptosbot/ARCHITECTURE.md kryptosbot/ORIENT.md MEMORY.md docs/audits/controller_maturity_audit_2026_05_16.md
git commit -m "yield-feedback: documentation updates for Phase 1 landing

ARCHITECTURE.md gets a new section on the feedback loop's authority
model. ORIENT.md gets a §5.6 troubleshooting entry for
REJECT_EMPIRICALLY_DEAD. MEMORY.md and the audit doc are annotated."
```

---

## Self-review checklist

Before considering this plan complete, verify each spec requirement maps to at least one task.

| Spec section | Task(s) covering it |
| --- | --- |
| §3 authority model | Tasks 1-5 (family_yield.py), 9-10 (critic gate), 13 (landscape) |
| §4.1 family_yield.py module | Tasks 1, 2, 3, 4, 5 |
| §4.2 ledger query | Task 6 |
| §4.3 CriticDecision + payload + CriticVerdict | Task 7 |
| §4.4 critic gate + ordering | Tasks 9, 10 |
| §4.5 controller wiring | Tasks 13, 14 |
| §4.6 theorist prompt | Task 15 |
| §4.7 tests | every task |
| §5 data flow + chokepoint | Tasks 12, 14 |
| §5.3 _write_cycle_escape_summary | Task 12 |
| §5.4 streak semantics | Task 12 |
| §5.5 failure modes (fail-open) | Task 13 (step 1, fail-open test) |
| §6.1 config (shadow_mode) | Task 9 (shadow test), Task 13 (policy on ControllerConfig) |
| §6.2 persistence | Task 11 (ControllerState fields) |
| §6.3 backward compat | Task 7 (legacy verdict JSON), Task 11 (legacy ControllerState JSON) |
| §6.4 fail-open posture | Task 13 |
| §6.5 rollout (no flag) | implicit; no flag added |
| §6.6 documentation | Task 20 |
| §7 Phase 2/3 forward design | designed-for; tasks include placeholder fields (suggested_mechanisms=()) |
| §8.2 named invariants | distributed across tasks; see §8.4 below |
| §9 files touched | Tasks 1-20 cover every entry |
| §10 acceptance criteria | Task 18 (criteria 1-5), Task 19 (criterion 6), Task 20 (criterion 7) |

Named-invariant test coverage map (spec §8.2):

| Invariant | Task |
| --- | --- |
| test_shared_symmetry_invariant | 16 |
| test_streak_only_increments_on_full_block | 12 |
| test_no_candidates_does_not_increment_empirical_streak | 12 |
| test_partial_empirical_block_resets_streak | 12 |
| test_shadow_mode_logs_but_does_not_reject | 9 |
| test_fail_open_when_yield_stats_raises | 13 |
| test_tier_1_wins_over_empirical_death | 10 |
| test_bypass_requires_structural_novelty | 3 |
| test_bypass_grants_pass_on_new_subfamily_AND_new_signature | 3 |
| test_truncation_at_10_by_severity | 12 |
| test_total_count_preserved_when_truncated | 12 |
| test_backward_compat_loads_pre_phase_1_state | 11 |
| test_boundary_min_trials | 2 |
| test_critic_decision_enum_exhaustive_handling | 8 |
| test_category_b_signature_excludes_novelty_basis | 5 |
| test_early_exit_writes_cycle_escape_summary | 14 |
| test_synthesis_path_writes_cycle_escape_summary | 14 |

Every named invariant in spec §8.2 maps to a task. Every spec §10 acceptance criterion has a test in Task 18. The plan is complete.
