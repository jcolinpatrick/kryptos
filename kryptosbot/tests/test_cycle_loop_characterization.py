"""
Characterization test for the kryptosbot cycle loop.

This test pins the observable semantics of one cycle's execution as a
canonical trace, then asserts that the two cycle entry points
(``ResearchController.run()`` and ``run_controller.do_run()``) produce
identical traces for identical inputs.

It is the safety gate for the priority-1 cycle-loop refactor identified
in ``memory/project_arch_review_verification_2026_04_26.md``. The test
file is committed BEFORE any refactor begins. Any diverging
implementation must keep this test green or explicitly retire it.

Design rules:

1. Trace events are a closed, narrow contract. The four canonical kinds
   (cycle.start, ledger.write, alert.emit, halt.check) cover the
   observable side effects that the loop must preserve. Anything else
   (logger formatting, Rich console rendering, timestamps, autoincrement
   IDs, object reprs, wall-clock durations) is deliberately excluded.

2. The test pins observable semantics, not private function boundaries.
   Today the instrumentation patches a small set of named methods on
   ``ResearchController`` because that is the only available landmark.
   That coupling is acceptable because the test exists to catch
   divergence DURING the refactor, not to outlive it. After the loop is
   collapsed behind a CycleObserver (or equivalent), the instrumentation
   moves to the new observer interface and this docstring is updated.

3. First commit is test-only. No production code is modified. No
   observer class is added to the controller. No synthetic-mode
   propagation. No dead-config cleanup. Those are separate commits.

This characterization test intentionally ignores pre-cycle bootstrap
events. The trace recorder begins at the first ``cycle.start`` event;
ledger writes, halt checks, or alerts emitted before that boundary are
treated as setup-contract behavior and not pinned by this test.
Divergence injected before ``cycle.start`` is outside the cycle-loop
contract and will not be observed. Bootstrap-phase invariants belong
to a separate test that asserts the setup contract directly.
"""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

# Project bootstrap. Tests are invoked via PYTHONPATH=src pytest from the
# repo root, but make this resilient to direct invocation as well.
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot import run_controller as run_controller_mod
from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.theory_ledger import TheoryLedger


# ──────────────────────────────────────────────────────────────────────
# Canonical trace event set
# ──────────────────────────────────────────────────────────────────────

# These four kinds are the observable contract. A refactor may rearrange
# private methods freely as long as the trace produced under the same
# scenario remains identical.
CANONICAL_EVENT_KINDS = frozenset({
    "cycle.start",   # one per cycle; payload: cycle (int)
    "ledger.write",  # any number per cycle; payload: table, method, key fields
    "alert.emit",    # zero or more per cycle; payload: kind, hypothesis_id
    "halt.check",    # one per cycle; payload: reason (None or str)
})

# Payload fields stripped before canonicalization. These vary across
# runs but never affect cycle semantics.
_NON_DETERMINISTIC_FIELDS = frozenset({
    "created_at", "updated_at", "last_cycle_at", "last_seen_at",
    "started_at", "ended_at", "completed_at",
    "wall_time_sec", "elapsed_ms", "duration", "duration_ms",
    "duration_seconds", "wall_time", "elapsed",
    "id", "rowid", "row_id", "auto_id",
    "turn_count", "tool_count",
    "artifact_path", "log_path", "scratch_path",
})


def _normalize_value(v: Any) -> Any:
    """Strip non-deterministic content from a single payload value."""
    if isinstance(v, str):
        if v.startswith("/") and len(v) > 8:
            return "<path>"
        if " object at 0x" in v:
            return "<object>"
        return v
    if isinstance(v, dict):
        return {
            k: _normalize_value(val)
            for k, val in v.items()
            if k not in _NON_DETERMINISTIC_FIELDS
        }
    if isinstance(v, (list, tuple)):
        return [_normalize_value(item) for item in v]
    return v


def _normalize_payload(payload: dict) -> dict:
    return {
        k: _normalize_value(v)
        for k, v in payload.items()
        if k not in _NON_DETERMINISTIC_FIELDS
    }


def _stable_repr(obj: Any) -> Any:
    """Convert obj to a sorted, hashable canonical form for == comparison."""
    if isinstance(obj, dict):
        return tuple(sorted(
            (k, _stable_repr(v)) for k, v in obj.items()
        ))
    if isinstance(obj, (list, tuple)):
        return tuple(_stable_repr(item) for item in obj)
    return obj


@dataclass
class TraceEvent:
    kind: str
    payload: dict

    def canonical(self) -> tuple:
        return (self.kind, _stable_repr(_normalize_payload(self.payload)))


@dataclass
class TraceRecorder:
    """Captures canonical-trace events emitted during one cycle run.

    Recording is gated to begin at the first ``cycle.start`` event, so
    the trace excludes init-phase bootstrap writes. Both cycle entry
    points run bootstrap identically; including those writes would only
    bloat the trace without changing the equivalence verdict.
    """
    events: list = field(default_factory=list)
    _recording: bool = False

    def record(self, kind: str, **payload) -> None:
        assert kind in CANONICAL_EVENT_KINDS, (
            f"Trace event {kind!r} is not in CANONICAL_EVENT_KINDS. "
            f"Add it to the closed set or use an existing kind."
        )
        if kind == "cycle.start":
            self._recording = True
        if not self._recording:
            return
        self.events.append(TraceEvent(kind, payload))

    def canonical_trace(self) -> list:
        return [e.canonical() for e in self.events]


# ──────────────────────────────────────────────────────────────────────
# Instrumentation
# ──────────────────────────────────────────────────────────────────────

# Each ledger method we wrap maps to a (table, key_fields) tuple. Only
# fields named here are recorded; everything else on the row is stripped.
LEDGER_WRITE_METHODS: dict[str, tuple[str, list[str]]] = {
    "upsert_theory":         ("theories",         ["hypothesis_id", "status", "family"]),
    "update_theory_status":  ("theories",         ["hypothesis_id", "status"]),
    "record_experiment":     ("experiments",      ["hypothesis_id", "tag"]),
    "save_controller_state": ("controller_state", ["cycle_number"]),
    "refresh_family_stats":  ("family_stats",     []),
    "add_evidence":          ("evidence",         ["hypothesis_id", "evidence_type"]),
    "insert_pursuit_lead":   ("pursuit_leads",    ["hypothesis_id", "status"]),
    "close_pursuit_lead":    ("pursuit_leads",    []),
    "upsert_anomaly":        ("anomalies",        ["anomaly_id", "status"]),
    "upsert_family":         ("families",         ["family_name", "status"]),
    "upsert_claim":          ("claims",           ["claim_id", "claim_type"]),
}


def _wrap_ledger(ledger: TheoryLedger, recorder: TraceRecorder) -> None:
    """Monkeypatch ledger writes to emit ledger.write trace events.

    Only public-API write methods are wrapped. Read methods are
    untouched, so query semantics are preserved exactly.
    """
    for method_name, (table_name, key_fields) in LEDGER_WRITE_METHODS.items():
        original = getattr(ledger, method_name, None)
        if original is None:
            continue

        def make_wrapper(name, table, fields, orig):
            def wrapper(*args, **kwargs):
                payload: dict[str, Any] = {"table": table, "method": name}
                if args:
                    record = args[0]
                    for f in fields:
                        if hasattr(record, f):
                            val = getattr(record, f)
                            # Convert enums to their .value for stable comparison
                            if hasattr(val, "value"):
                                val = val.value
                            payload[f] = val
                # close_pursuit_lead takes (lead_id, outcome) as positional args
                if name == "close_pursuit_lead" and len(args) >= 2:
                    payload["outcome"] = (
                        args[1].value if hasattr(args[1], "value") else args[1]
                    )
                recorder.record("ledger.write", **payload)
                return orig(*args, **kwargs)
            return wrapper

        setattr(ledger, method_name, make_wrapper(
            method_name, table_name, key_fields, original
        ))


def _wrap_controller(controller: ResearchController, recorder: TraceRecorder) -> None:
    """Monkeypatch the controller to emit cycle.start, halt.check, alert.emit.

    Couples to private method names (``_begin_cycle_phase_state``,
    ``_check_cycle_hardening_halts``, ``_run_alerts``). This is the only
    coupling to the current implementation. After the cycle-loop refactor
    introduces an observer interface, replace this with observer
    subscription and update the docstring at the top of this file.
    """
    orig_phase_reset = controller._begin_cycle_phase_state

    def phase_reset_wrapper():
        # state.cycle_number is incremented in BOTH cycle loops BEFORE
        # _begin_cycle_phase_state is called, so the value here is the
        # cycle number we are about to start.
        recorder.record("cycle.start", cycle=int(controller.state.cycle_number))
        return orig_phase_reset()

    controller._begin_cycle_phase_state = phase_reset_wrapper

    orig_halt = controller._check_cycle_hardening_halts

    def halt_wrapper(*args, **kwargs):
        result = orig_halt(*args, **kwargs)
        recorder.record("halt.check", reason=result)
        return result

    controller._check_cycle_hardening_halts = halt_wrapper

    orig_run_alerts = controller._run_alerts

    def alerts_wrapper(*args, **kwargs):
        before = len(controller._cycle_alert_events)
        result = orig_run_alerts(*args, **kwargs)
        for ev in controller._cycle_alert_events[before:]:
            kind = (
                getattr(ev, "kind", None)
                or getattr(ev, "level", None)
                or getattr(ev, "alert_type", None)
                or "?"
            )
            hid = getattr(ev, "hypothesis_id", None)
            recorder.record(
                "alert.emit",
                kind=str(kind),
                hypothesis_id=str(hid) if hid is not None else None,
            )
        return result

    controller._run_alerts = alerts_wrapper


# ──────────────────────────────────────────────────────────────────────
# Deterministic mocks
# ──────────────────────────────────────────────────────────────────────

@dataclass
class _FakeTextBlock:
    text: str
    type: str = "text"


@dataclass
class _FakeMessage:
    content: list


def _identity_dsl_spec(hid: str) -> dict:
    return {
        "hypothesis_id": hid,
        "pipeline": [{"kind": "identity", "alphabet": "AZ", "params": []}],
        "compute_budget_cpu_minutes": 1,
    }


def _theorist_response_json() -> str:
    """Single-theory deterministic theorist response.

    The theory uses an identity DSL spec so the worker dispatch path
    runs entirely through job_dispatcher.execute() without any SDK call.
    family='novel' is outside TIER_1/TIER_2 elimination gates, and the
    anomaly is a real one from anomaly_registry so the critic's
    information-gain check passes (though we skip the critic anyway).
    """
    return json.dumps([{
        "title": "Cycle-loop characterization probe",
        "core_claim": "Identity transform exposes loop semantics, not K4 plaintext",
        "mechanism": "DSL identity pipeline; no decryption performed",
        "family": "novel",
        "anomalies_exploited": ["width21_vertical_bigrams"],
        "kill_criteria": ["crib_score < 18"],
        "expected_signal": "test-only; no real signal expected",
        "dsl_spec": _identity_dsl_spec("char-test-001"),
    }])


def _make_safe_query_mock():
    """Return a fake_safe_query that emits a single theorist response.

    Only the theorist phase is exercised in this scenario. All other LLM
    phases (critic, red-team, stat-audit, lead-pursuit, synthesis) are
    skipped via config flags, so they never call safe_query.
    """
    async def fake_safe_query(*, prompt, options):
        yield _FakeMessage([_FakeTextBlock(_theorist_response_json())])
    return fake_safe_query


# ──────────────────────────────────────────────────────────────────────
# Scenario harness
# ──────────────────────────────────────────────────────────────────────

def _make_config(project_root: Path) -> ControllerConfig:
    """Build a single-cycle config that skips every LLM-bound phase
    except the theorist call.

    Skipping the LLM-bound phases keeps the scenario deterministic.
    The orchestration shell (which is what the equivalence test
    actually pins) still runs unchanged.
    """
    return ControllerConfig(
        project_root=project_root,
        ledger_db_path=project_root / "ledger.sqlite",
        max_cycles=1,
        theories_per_cycle=1,
        max_concurrent_workers=1,
        worker_timeout_minutes=1,
        skip_critic=True,
        skip_red_team=True,
        skip_stat_audit=True,
        skip_synthesis=True,
        skip_lead_pursuit=True,
    )


async def _run_via_controller_run(project_root: Path, monkeypatch) -> list:
    """Execute one cycle via ResearchController.run() with instrumentation."""
    project_root.mkdir(parents=True, exist_ok=True)
    cfg = _make_config(project_root)

    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    controller = ResearchController(cfg)
    recorder = TraceRecorder()
    _wrap_ledger(controller.ledger, recorder)
    _wrap_controller(controller, recorder)

    await controller.run()
    return recorder.canonical_trace()


async def _run_via_do_run(project_root: Path, monkeypatch) -> list:
    """Execute one cycle via run_controller.do_run() with instrumentation.

    do_run constructs its own ResearchController, so we patch the class
    constructor to wrap each instance immediately after init.
    """
    project_root.mkdir(parents=True, exist_ok=True)
    cfg = _make_config(project_root)

    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    recorder = TraceRecorder()
    orig_init = ResearchController.__init__

    def init_wrapper(self, c):
        orig_init(self, c)
        _wrap_ledger(self.ledger, recorder)
        _wrap_controller(self, recorder)

    monkeypatch.setattr(ResearchController, "__init__", init_wrapper)

    await run_controller_mod.do_run(cfg)
    return recorder.canonical_trace()


# ──────────────────────────────────────────────────────────────────────
# Test G: equivalence between the two cycle entry points
# ──────────────────────────────────────────────────────────────────────

def test_controller_run_and_do_run_emit_equivalent_canonical_trace(
    tmp_path, monkeypatch,
):
    """The two cycle entry points must produce identical canonical traces.

    This is the load-bearing characterization assertion. Six narrower
    invariant tests (ledger persistence, halt-state ordering, alert
    emission, phase-state lifecycle, parse-failure fail-closed,
    kernel-overrule preservation) come in a follow-up commit — see
    memory/project_arch_review_test_plan_2026_04_26.md.

    Failure modes this test catches:
    - One loop persists controller_state and the other does not
    - One loop calls halt-check and the other skips it
    - One loop emits an alert that the other suppresses
    - The two loops disagree on cycle ordering or phase reset
    - One loop writes a different theories.status than the other under
      the same critic/redteam config
    """
    trace_a = asyncio.run(
        _run_via_controller_run(tmp_path / "controller_run", monkeypatch)
    )
    trace_b = asyncio.run(
        _run_via_do_run(tmp_path / "do_run", monkeypatch)
    )

    # Sanity: both traces include the load-bearing event kinds.
    required_kinds = {"cycle.start", "halt.check"}
    kinds_a = {ev[0] for ev in trace_a}
    kinds_b = {ev[0] for ev in trace_b}

    assert required_kinds.issubset(kinds_a), (
        f"controller.run() trace missing required event kinds: "
        f"missing={required_kinds - kinds_a}, got={sorted(kinds_a)}"
    )
    assert required_kinds.issubset(kinds_b), (
        f"do_run() trace missing required event kinds: "
        f"missing={required_kinds - kinds_b}, got={sorted(kinds_b)}"
    )

    # Equivalence: identical canonical sequences after normalization.
    if trace_a != trace_b:
        # Render a readable diff so failures are debuggable.
        lines_a = "\n  ".join(repr(e) for e in trace_a)
        lines_b = "\n  ".join(repr(e) for e in trace_b)
        pytest.fail(
            f"Canonical traces diverged.\n\n"
            f"controller.run() emitted {len(trace_a)} events:\n  {lines_a}\n\n"
            f"run_controller.do_run() emitted {len(trace_b)} events:\n  {lines_b}\n"
        )


# ──────────────────────────────────────────────────────────────────────
# Test A: ledger persistence invariant
# ──────────────────────────────────────────────────────────────────────

def test_one_cycle_persists_controller_state_experiment_and_theory(
    tmp_path, monkeypatch,
):
    """A 1-cycle run writes the expected rows in the expected order.

    Invariant: at the end of a normal (no-halt) cycle, the ledger
    holds (a) a controller_state row with cycle_number=1, (b) at
    least one experiments row keyed by the dispatched theory, and
    (c) at least one theories row in a terminal status.

    Without this invariant, a refactor could persist controller state
    but skip experiment recording (or vice versa), leaving the ledger
    in an inconsistent shape.
    """
    project_root = tmp_path / "ledger_invariant"
    project_root.mkdir(parents=True, exist_ok=True)
    cfg = _make_config(project_root)

    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    controller = ResearchController(cfg)
    asyncio.run(controller.run())

    # (a) controller_state row written, cycle_number advanced.
    state = controller.ledger.load_controller_state()
    assert state.cycle_number == 1, (
        f"Expected cycle_number=1 after one cycle, got {state.cycle_number}"
    )

    # (b) At least one experiment row exists (the dispatch).
    import sqlite3
    with sqlite3.connect(cfg.ledger_db_path) as conn:
        exp_count = conn.execute(
            "SELECT COUNT(*) FROM experiments"
        ).fetchone()[0]
        theory_count = conn.execute(
            "SELECT COUNT(*) FROM theories"
        ).fetchone()[0]

    assert exp_count >= 1, (
        f"Expected >=1 experiments row after dispatch, got {exp_count}"
    )

    # (c) The theory was persisted (post-absorb)
    assert theory_count >= 1, (
        f"Expected >=1 theories row after absorb, got {theory_count}"
    )


# ──────────────────────────────────────────────────────────────────────
# Test B: hardening halt invariant
# ──────────────────────────────────────────────────────────────────────

def test_hardening_halt_persists_state_before_loop_break(
    tmp_path, monkeypatch,
):
    """When a hardening halt fires, persist must happen before the break.

    Invariant: ``state.halt_reason_hardening`` is durable in the ledger
    before the cycle loop exits. The current ordering is enforced at
    ``controller.py`` step 5b' / step 6 (halt-check populates the field
    on self.state, then save_controller_state writes the state row, then
    the post-loop `if state.halt_reason_hardening: break` triggers).

    A regression that moves the persist call AFTER the break would
    leave the halt reason in memory only, lost on process exit.

    The two-cycle config is used because we need to verify the loop
    stops after cycle 1 (not after cycle 2). With max_cycles=2 plus a
    halt that fires on cycle 1, a correct loop runs exactly one cycle.
    """
    project_root = tmp_path / "halt_invariant"
    project_root.mkdir(parents=True, exist_ok=True)

    # max_cycles=2 so we can detect early break
    cfg = _make_config(project_root)
    cfg.max_cycles = 2

    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    controller = ResearchController(cfg)

    # Patch _check_cycle_hardening_halts to fire on the first cycle.
    halt_reason = "test-induced-halt-cycle-1"

    def fake_halt_check(*args, **kwargs):
        controller.state.halt_reason_hardening = halt_reason
        return halt_reason

    controller._check_cycle_hardening_halts = fake_halt_check

    asyncio.run(controller.run())

    # The cycle counter must be 1, not 2 — proving the loop broke
    # after cycle 1 rather than running both.
    assert controller.state.cycle_number == 1, (
        f"Expected loop to break after cycle 1, but cycle_number={controller.state.cycle_number}"
    )

    # The halt reason must be persisted in the ledger (not just held in
    # the live controller's state). Reload the state from disk to prove
    # save_controller_state ran with the halt reason set.
    fresh = TheoryLedger(cfg.ledger_db_path)
    persisted = fresh.load_controller_state()
    assert persisted.halt_reason_hardening == halt_reason, (
        f"Expected persisted halt_reason_hardening={halt_reason!r}, "
        f"got {persisted.halt_reason_hardening!r}. The halt fired but "
        f"its reason was not durable across reload — persist must run "
        f"BEFORE the loop break."
    )
    assert persisted.cycle_number == 1, (
        f"Expected persisted cycle_number=1, got {persisted.cycle_number}. "
        f"The cycle counter was not saved before the break."
    )


# ──────────────────────────────────────────────────────────────────────
# Test C: alert emission invariant (negative case)
# ──────────────────────────────────────────────────────────────────────

def test_no_alert_emitted_for_below_threshold_outcomes(
    tmp_path, monkeypatch,
):
    """Sub-threshold outcomes (crib_score=0 from identity spec) emit
    zero alerts.

    Invariant: ``_run_alerts`` is invoked once per cycle (after absorb),
    and the resulting ``_cycle_alert_events`` list is empty when no
    contract crosses the configured alert threshold. This is the
    negative case that complements positive alert tests elsewhere
    (test_alerts.py covers the alert-fires-on-signal direction).

    A regression that emits spurious alerts on noise would fire here
    immediately. A regression that suppresses alerts entirely would be
    caught by the corresponding positive test in test_alerts.py.
    """
    project_root = tmp_path / "alert_invariant"
    project_root.mkdir(parents=True, exist_ok=True)
    cfg = _make_config(project_root)
    # Run alerts and stat-audit (alert gate honors stat-audit verdicts).
    cfg.skip_stat_audit = False

    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    controller = ResearchController(cfg)
    asyncio.run(controller.run())

    # The identity spec produces crib_score=0, well below the SIGNAL
    # threshold of 18. No alerts should have been emitted for this
    # cycle. Reading the post-cycle attribute is correct because
    # _begin_cycle_phase_state resets the list at the START of each
    # cycle, so the value at the END of cycle 1 reflects only cycle 1.
    assert controller._cycle_alert_events == [], (
        f"Expected zero alerts for sub-threshold outcomes, got "
        f"{len(controller._cycle_alert_events)} events: "
        f"{controller._cycle_alert_events!r}"
    )


# ──────────────────────────────────────────────────────────────────────
# Callback-safety invariant
# ──────────────────────────────────────────────────────────────────────

def test_raising_callback_does_not_abort_cycle_and_failure_is_logged(
    tmp_path, monkeypatch, caplog,
):
    """A raising display callback must not fail the cycle.

    Invariant: ``CycleCallbacks.emit`` swallows callback exceptions and
    logs them via ``logger.exception``. The cycle continues to a clean
    persist + (optional) halt-break.

    This protects the failure mode where Rich/display incompatibility
    or a buggy custom observer would otherwise abort an in-progress
    cycle and lose research work. The cb.emit guard at
    ``controller.py:CycleCallbacks.emit`` is the single point that
    enforces this contract.

    Pinned behaviors:
      - Cycle reaches the persist step (controller_state row written).
      - Logger captures an exception entry for the callback failure.
      - The exception class and message are present in the log record.
    """
    import logging
    from kryptosbot.controller import CycleCallbacks

    project_root = tmp_path / "callback_safety"
    project_root.mkdir(parents=True, exist_ok=True)
    cfg = _make_config(project_root)

    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    # A callback that always raises. Wired into on_cycle_begin because
    # that's the FIRST callback the loop emits per cycle — if the guard
    # is missing, the cycle aborts before any work happens.
    def boom(_cycle: int, _total_max: int) -> None:
        raise RuntimeError("synthetic display failure for callback safety test")

    callbacks = CycleCallbacks(on_cycle_begin=boom)

    controller = ResearchController(cfg)

    # Capture the kryptosbot.controller logger at INFO+ so the
    # logger.exception inside emit() lands in caplog.records.
    with caplog.at_level(logging.INFO, logger="kryptosbot.controller"):
        asyncio.run(controller.run(callbacks=callbacks))

    # Cycle reached persist despite the callback raising on entry.
    state = controller.ledger.load_controller_state()
    assert state.cycle_number == 1, (
        f"Cycle did not reach persist after callback raised. "
        f"state.cycle_number={state.cycle_number}; expected 1. "
        f"This means CycleCallbacks.emit failed to swallow the "
        f"exception and the cycle aborted."
    )

    # The failure was logged via logger.exception. Find the record.
    callback_failure_records = [
        r for r in caplog.records
        if "Cycle callback" in r.getMessage()
        and r.exc_info is not None
    ]
    assert callback_failure_records, (
        f"Expected at least one logger.exception record for the "
        f"callback failure, got 0. caplog records: "
        f"{[r.getMessage() for r in caplog.records]}"
    )
    # The exception class and message must be reachable from the
    # record's exc_info tuple so an operator debugging a TUI breakage
    # can identify the cause.
    rec = callback_failure_records[0]
    assert rec.exc_info[0] is RuntimeError, (
        f"Expected RuntimeError in exc_info, got {rec.exc_info[0]}"
    )
    assert "synthetic display failure" in str(rec.exc_info[1]), (
        f"Expected synthetic message in exc_info, got {rec.exc_info[1]!r}"
    )


# ──────────────────────────────────────────────────────────────────────
# TUI session-baseline invariant (regression for the surfaced bug)
# ──────────────────────────────────────────────────────────────────────

def test_do_run_snapshots_session_baseline_before_first_cycle(
    tmp_path, monkeypatch,
):
    """do_run must record the pre-session ledger baseline.

    Bug surfaced by the cycle-loop collapse: ``run_controller.do_run``
    historically skipped ``_snapshot_session_baseline``, leaving
    ``_session_baseline_tested`` and ``_session_baseline_eliminated``
    unset. ``_assess_landscape`` reads them via getattr-with-default,
    so cycle_delta values silently degraded to 0 in TUI mode.

    The fix moves baseline initialization into a small helper called
    by both entry points. This test pins the contract: after
    ``do_run`` finishes, the controller MUST have a session baseline
    that reflects ledger state AT THE START of the run, not after.

    Setup: pre-populate the ledger with N completed theories. Run
    do_run with one new theory dispatched via the identity DSL spec.
    Assert the baseline records N (the pre-run count), not N+1.
    """
    from kryptosbot.models import TheoryRecord, TheoryStatus

    project_root = tmp_path / "baseline_invariant"
    project_root.mkdir(parents=True, exist_ok=True)
    cfg = _make_config(project_root)

    # Seed the ledger with two completed theories before do_run starts.
    # The session baseline at do_run launch must equal this seeded count.
    seed_ledger = TheoryLedger(cfg.ledger_db_path)
    seed_ledger.upsert_theory(TheoryRecord(
        hypothesis_id="seed-completed-1",
        title="Seed completed theory 1",
        core_claim="seed", mechanism="seed", family="novel",
        status=TheoryStatus.COMPLETED,
    ))
    seed_ledger.upsert_theory(TheoryRecord(
        hypothesis_id="seed-eliminated-1",
        title="Seed eliminated theory 1",
        core_claim="seed", mechanism="seed", family="novel",
        status=TheoryStatus.ELIMINATED,
    ))

    # Capture the controller built by do_run so we can inspect its
    # baseline attributes after the run.
    captured: dict[str, ResearchController] = {}
    orig_init = ResearchController.__init__

    def init_capturer(self, c):
        orig_init(self, c)
        captured["controller"] = self

    monkeypatch.setattr(ResearchController, "__init__", init_capturer)
    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    asyncio.run(run_controller_mod.do_run(cfg))

    controller = captured["controller"]

    # The baseline must be set (the bug was that these attributes did
    # not exist on the controller after do_run).
    assert hasattr(controller, "_session_baseline_tested"), (
        "do_run did not populate _session_baseline_tested. The TUI "
        "path is still skipping _snapshot_session_baseline."
    )
    assert hasattr(controller, "_session_baseline_eliminated"), (
        "do_run did not populate _session_baseline_eliminated."
    )

    # Pre-run ledger had 1 COMPLETED + 1 ELIMINATED = 2 in the
    # tested-baseline aggregate (completed + eliminated + promising).
    # The cycle then dispatches a third theory, but the baseline must
    # be the value at session START, not the value at session END.
    assert controller._session_baseline_tested == 2, (
        f"Expected baseline_tested=2 (the seeded count), got "
        f"{controller._session_baseline_tested}. The baseline was "
        f"snapshot AFTER the cycle ran instead of BEFORE — the helper "
        f"is being called at the wrong point in the lifecycle."
    )
    # Pre-run ledger had 1 ELIMINATED.
    assert controller._session_baseline_eliminated == 1, (
        f"Expected baseline_eliminated=1, got "
        f"{controller._session_baseline_eliminated}"
    )


# ──────────────────────────────────────────────────────────────────────
# Test H: save_controller_state failure does NOT abort the cycle loop
# ──────────────────────────────────────────────────────────────────────
#
# Added 2026-04-30 after a live-run audit found that
# controller_state.cycle_number was stuck at 197 even though the run
# reached cycle 250. The hypothesis is that an intermittent SQLite I/O
# glitch raised inside save_controller_state and cascaded out of the
# cycle. Pre-patch: the inner save was wrapped in the cycle's outer
# try/except, but the except handler ALSO called save_controller_state,
# which would re-raise and propagate further. Post-patch: each save
# is wrapped in its own swallow-and-log try, plus a final post-loop
# save guarantees the run-end state always lands.

def test_save_controller_state_failure_does_not_abort_loop(
    tmp_path, monkeypatch,
):
    """An exception from save_controller_state must be swallowed and
    the cycle counter must still advance."""
    from kryptosbot.theory_ledger import TheoryLedger

    project_root = tmp_path / "save_failure"
    project_root.mkdir(parents=True, exist_ok=True)
    cfg = _make_config(project_root)
    cfg.max_cycles = 2

    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    controller = ResearchController(cfg)

    # Inject a save failure on the FIRST in-cycle save call only.
    # The post-loop final save still runs and persists state.
    original_save = controller.ledger.save_controller_state
    call_count = {"n": 0}

    def flaky_save(state):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise sqlite3.OperationalError("simulated I/O glitch")
        original_save(state)

    import sqlite3  # local import: error class only used here
    controller.ledger.save_controller_state = flaky_save

    asyncio.run(controller.run())

    # Despite the failure, the loop progressed to cycle 2.
    assert controller.state.cycle_number == 2, (
        f"Expected loop to complete 2 cycles, got "
        f"{controller.state.cycle_number}"
    )

    # Final post-loop save persisted the run-end state.
    fresh = TheoryLedger(cfg.ledger_db_path)
    persisted = fresh.load_controller_state()
    assert persisted.cycle_number == 2, (
        f"Expected persisted cycle_number=2 from post-loop save, "
        f"got {persisted.cycle_number}"
    )
    # And the flaky save was hit at least once (the swallow path fired).
    assert call_count["n"] >= 2, (
        f"Expected save_controller_state to be invoked at least twice "
        f"(once flaky + final), got {call_count['n']}"
    )


# ──────────────────────────────────────────────────────────────────────
# Phase 2 acceptance #9: all-rejected cycles must write escape summary
# BEFORE any early-continue. Architectural regression guard.
# ──────────────────────────────────────────────────────────────────────


class TestPhase2AllRejectedWritesSummaryBeforeContinue:
    """Acceptance #9: an all-critic-rejected cycle writes
    _write_cycle_escape_summary with status='needed_but_unavailable'
    AND last_escape_suggestions populated BEFORE early-continue.

    This is the architectural regression guard. The original Phase 2
    design draft incorrectly threaded rejection aggregation through
    _absorb_outcomes (which is unreachable on all-rejected cycles).
    This test exists to fail loudly if anyone reintroduces that wiring.
    """

    def test_all_rejected_cycle_canonical_trace(
        self, dead_encoding_yield, encoding_theory
    ):
        from pathlib import Path
        from kryptosbot.controller import ResearchController
        from kryptosbot.critic import TheoryCritic
        from kryptosbot.family_yield import mechanism_signature_for_theory
        from kryptosbot.models import ControllerState

        c = ResearchController.__new__(ResearchController)
        c.state = ControllerState(cycle_number=1)
        c._cycle_empirical_dead_rejections = []
        c._kb_db_missing_logged_this_cycle = False

        # Minimal FakeLedger consistent with conftest patterns. Includes
        # ``get_family`` because TheoryCritic.evaluate() consults the
        # family registry for elimination-tier gating BEFORE the
        # empirical-death gate runs.
        class _FakeLedger:
            def get_family(self, *_): return None
            def get_theories_by_family(self, *a, **kw): return []
            def get_theories_by_status(self, *a, **kw): return []

        # Seed priors so the structural-novelty bypass CANNOT fire. The
        # empirical-death gate would otherwise fall through (bypass-eligible)
        # and the architectural invariant under test (rejection-aggregation
        # populates last_escape_suggestions) would never get exercised.
        sig = mechanism_signature_for_theory({
            "family": encoding_theory.family,
            "subfamily": encoding_theory.subfamily,
            "mechanism": encoding_theory.mechanism,
            "dsl_spec": encoding_theory.dsl_spec,
            "anomalies_exploited": [],
            "clue_anchors_used": [],
            "novelty_basis": "",
            "minimal_test_spec": {},
        })
        prior_subs = {encoding_theory.family: frozenset({encoding_theory.subfamily})}
        prior_sigs = {encoding_theory.family: frozenset({sig})}

        critic = TheoryCritic(
            ledger=_FakeLedger(),
            yield_index={"encoding": dead_encoding_yield},
            prior_subfamilies=prior_subs,
            prior_signatures=prior_sigs,
            blocked_families_in_cycle=frozenset({"encoding"}),
            kb_db_path=str(
                Path(__file__).resolve().parent
                / "fixtures"
                / "cipher_discovery_phase2_fixture.sqlite"
            ),
        )
        verdict = critic.evaluate(encoding_theory)
        assert verdict.empirical_death is not None, (
            "Test precondition: critic must produce an empirical_death "
            "payload. Bypass priors are seeded; if this fails, the gate "
            "is no longer reachable from this fixture shape."
        )
        c._cycle_empirical_dead_rejections.append(verdict.empirical_death)

        # Before any early-continue, _write_cycle_escape_summary must run.
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=["encoding"],
            rejections=c._cycle_empirical_dead_rejections,
        )
        # At this point the next cycle's landscape can already see the
        # escape candidates. Any future refactor that moves this call
        # AFTER an early-continue, or routes it through _absorb_outcomes,
        # will leave last_escape_suggestions empty.
        assert c.state.last_escape_suggestions, (
            "_write_cycle_escape_summary must populate "
            "last_escape_suggestions BEFORE any early-continue on "
            "all-rejected cycles. Do NOT route rejection aggregation "
            "through _absorb_outcomes - that path is unreachable on "
            "all-rejected cycles."
        )
