"""
Synthetic-mode taint enforcement (2026-04-26).

A ledger commits to "real" or "synthetic" on the first ``ResearchController``
run that touches it. Subsequent runs in the other mode are refused before
any controller mutation. This is the enforcement layer for
``KRYPTOS_CT_OVERRIDE`` — without it, a synthetic-CT calibration run could
silently append rows to the real K4 ledger and contaminate analysis.

Five invariants pinned here:
  1. Synthetic launch on an empty ledger pins it to synthetic.
  2. Real launch on an empty ledger pins it to real.
  3. Real launch on a synthetic-pinned ledger raises SyntheticModeError
     BEFORE bootstrap mutation.
  4. Synthetic launch on a real-pinned ledger raises the same error.
  5. Re-launch in the same mode is a no-op.

The synthetic-pinned ledger fixture uses the public ``verify_and_pin``
API rather than ``KRYPTOS_CT_OVERRIDE``, so tests do not have to
reload ``kryptos.kernel.constants``. The ``_SYNTHETIC_MODE`` flag is
read once at module import and is stable for the test process; the
mode the controller sees is the one set in the test harness.

Per ``project_arch_review_verification_2026_04_26.md`` §5, this work
addresses the largest remaining correctness gap identified by the
verified architectural review.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.theory_ledger import (
    SyntheticModeError, TheoryLedger,
)
# Reuse the deterministic theorist mock from the cycle-loop tests.
from kryptosbot.tests.test_cycle_loop_characterization import (
    _make_safe_query_mock,
)


def _make_minimal_config(project_root: Path) -> ControllerConfig:
    project_root.mkdir(parents=True, exist_ok=True)
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


# ──────────────────────────────────────────────────────────────────────
# Invariant 1: empty ledger accepts synthetic launch
# ──────────────────────────────────────────────────────────────────────

def test_empty_ledger_accepts_synthetic_launch_and_pins(tmp_path):
    """An unpinned ledger is accepted in synthetic mode and the pin
    is recorded. This is the lazy-init path for fresh calibration
    runs."""
    ledger = TheoryLedger(tmp_path / "fresh_synthetic.sqlite")
    assert ledger.get_pinned_synthetic_mode() is None, (
        "Fresh ledger should have no pinned mode"
    )

    ledger.verify_and_pin_synthetic_mode(synthetic=True)

    assert ledger.get_pinned_synthetic_mode() == "synthetic", (
        "After synthetic launch, the ledger must be pinned to synthetic"
    )


# ──────────────────────────────────────────────────────────────────────
# Invariant 2: empty ledger accepts real launch
# ──────────────────────────────────────────────────────────────────────

def test_empty_ledger_accepts_real_launch_and_pins(tmp_path):
    """An unpinned ledger is accepted in real mode and the pin is
    recorded. This is the dominant path for production K4 work."""
    ledger = TheoryLedger(tmp_path / "fresh_real.sqlite")

    ledger.verify_and_pin_synthetic_mode(synthetic=False)

    assert ledger.get_pinned_synthetic_mode() == "real", (
        "After real launch, the ledger must be pinned to real"
    )


# ──────────────────────────────────────────────────────────────────────
# Invariant 3: real launch refuses synthetic-pinned ledger
# ──────────────────────────────────────────────────────────────────────

def test_real_launch_refuses_synthetic_pinned_ledger(tmp_path):
    """A real-K4 launch against a synthetic-pinned ledger raises
    SyntheticModeError. This is the protection that prevents synthetic
    calibration data from contaminating real K4 analysis."""
    ledger = TheoryLedger(tmp_path / "tainted_synthetic.sqlite")
    ledger.verify_and_pin_synthetic_mode(synthetic=True)
    assert ledger.get_pinned_synthetic_mode() == "synthetic"

    with pytest.raises(SyntheticModeError) as excinfo:
        ledger.verify_and_pin_synthetic_mode(synthetic=False)

    err = excinfo.value
    assert err.existing == "synthetic"
    assert err.attempted == "real"
    assert err.db_path == ledger.db_path
    assert "synthetic" in str(err) and "real" in str(err)


# ──────────────────────────────────────────────────────────────────────
# Invariant 4: synthetic launch refuses real-pinned ledger
# ──────────────────────────────────────────────────────────────────────

def test_synthetic_launch_refuses_real_pinned_ledger(tmp_path):
    """A synthetic-CT calibration launch against a real-pinned ledger
    raises SyntheticModeError. This is the symmetric protection: the
    real ledger is the authoritative research record and synthetic
    runs must not mutate it."""
    ledger = TheoryLedger(tmp_path / "tainted_real.sqlite")
    ledger.verify_and_pin_synthetic_mode(synthetic=False)

    with pytest.raises(SyntheticModeError) as excinfo:
        ledger.verify_and_pin_synthetic_mode(synthetic=True)

    err = excinfo.value
    assert err.existing == "real"
    assert err.attempted == "synthetic"


# ──────────────────────────────────────────────────────────────────────
# Invariant 5: re-launch in the same mode is a no-op
# ──────────────────────────────────────────────────────────────────────

def test_relaunch_in_same_mode_is_idempotent(tmp_path):
    """Calling verify_and_pin twice in the same mode is a no-op.
    This is the steady-state path: every cycle of every run calls
    verify_and_pin, and after the first launch the call must be free."""
    ledger = TheoryLedger(tmp_path / "stable.sqlite")
    ledger.verify_and_pin_synthetic_mode(synthetic=False)
    ledger.verify_and_pin_synthetic_mode(synthetic=False)
    ledger.verify_and_pin_synthetic_mode(synthetic=False)

    assert ledger.get_pinned_synthetic_mode() == "real"


# ──────────────────────────────────────────────────────────────────────
# Integration: refusal happens BEFORE bootstrap mutation
# ──────────────────────────────────────────────────────────────────────

def test_real_launch_refuses_tainted_ledger_before_bootstrap_mutation(
    tmp_path, monkeypatch,
):
    """A real ResearchController launch against a synthetic-pinned
    ledger must refuse BEFORE bootstrap_all writes any rows.

    This is the load-bearing integration: an early refusal protects
    the ledger from contamination. A late refusal (after bootstrap
    has already inserted family/anomaly/claim rows tagged as real)
    leaves the ledger in a mixed-tainted state that is harder to
    recover from than a clean refusal.

    We verify this by counting non-metadata rows before and after
    the refused launch. The two counts must match.
    """
    cfg = _make_minimal_config(tmp_path / "early_refusal")

    # Pre-pin the ledger to synthetic.
    pre_ledger = TheoryLedger(cfg.ledger_db_path)
    pre_ledger.verify_and_pin_synthetic_mode(synthetic=True)

    # Snapshot row counts across all tables (excluding ledger_metadata
    # itself, which we just touched).
    import sqlite3

    def row_counts():
        with sqlite3.connect(cfg.ledger_db_path) as conn:
            tables = [
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name != 'ledger_metadata'"
                )
            ]
            return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    for t in tables}

    counts_before = row_counts()

    # Patch _SYNTHETIC_MODE to False so the controller thinks it is
    # launching in real mode. This is what would happen if an operator
    # accidentally pointed a real-K4 run at a synthetic-tainted DB.
    monkeypatch.setattr(
        "kryptos.kernel.constants._SYNTHETIC_MODE", False,
    )
    monkeypatch.setattr(
        "kryptosbot.controller.safe_query",
        _make_safe_query_mock(),
    )

    controller = ResearchController(cfg)

    with pytest.raises(SyntheticModeError):
        asyncio.run(controller.run())

    counts_after = row_counts()

    assert counts_before == counts_after, (
        f"Row counts changed despite refused launch:\n"
        f"  before: {counts_before}\n"
        f"  after:  {counts_after}\n"
        f"This means bootstrap_all (or some other write) ran before "
        f"the synthetic-mode refusal. The check must move earlier in "
        f"the lifecycle."
    )
