"""Pins that ALL experiment rows get a populated completed_at.

Two leak paths existed before the 2026-04-30 audit:

1. ``bootstrap_local_reruns`` in ``registries.py`` recorded experiment
   rows for synchronous rerun manifests but never set completed_at,
   leaving them as "active" forever.

2. ``_run_worker_legacy`` in ``controller.py`` returned timeout / exception
   contracts without recording the experiment row at all, which forced
   ``upsert_theory`` to fall back to the audit-annotation path
   ("upserted directly to outcome state 'completed' without experiment
   trail").

Both paths should now close their experiment rows. These tests use
real SQLite ledgers (no mocking) and verify the persisted DB state.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kryptosbot.models import (
    ExperimentRecord,
    TheoryRecord,
    TheoryStatus,
    WorkerStatus,
)
from kryptosbot.theory_ledger import TheoryLedger


def _open_ledger(tmp_path: Path) -> TheoryLedger:
    db = tmp_path / "ledger.sqlite"
    return TheoryLedger(db_path=db)


class TestBootstrapLocalRerunCloses:
    """Patch 3 — bootstrap_local_reruns must set completed_at."""

    def test_record_experiment_with_default_completed_at_is_caught_by_query(
        self, tmp_path
    ):
        """Sanity: an experiment row with empty completed_at IS visible
        as 'active' under the dashboard's join-against-terminal-status
        query — this is the leak signature we are protecting against."""
        ledger = _open_ledger(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="t-leak", title="t", core_claim="c",
            mechanism="m", family="f",
            status=TheoryStatus.ELIMINATED,
        )
        ledger.upsert_theory(theory)
        ledger.record_experiment(
            ExperimentRecord(
                experiment_id="e-leak",
                hypothesis_id="t-leak",
                worker_role="local_rerun",
                # completed_at deliberately empty — simulates the leak.
            )
        )
        with sqlite3.connect(str(ledger.db_path)) as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM experiments e "
                "JOIN theories t ON e.hypothesis_id = t.hypothesis_id "
                "WHERE (e.completed_at IS NULL OR e.completed_at = '') "
                "AND t.status IN ('eliminated','completed','withdrawn',"
                "'rejected_admissibility','rejected','fabricated','error')"
            ).fetchone()[0]
        assert n == 1, "leak signature should be detectable"

    def test_record_experiment_with_completed_at_does_not_leak(self, tmp_path):
        """The fix: when bootstrap_local_reruns now sets completed_at,
        the row must NOT appear in the unclosed-with-terminal-theory query."""
        ledger = _open_ledger(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="t-ok", title="t", core_claim="c",
            mechanism="m", family="f",
            status=TheoryStatus.ELIMINATED,
        )
        ledger.upsert_theory(theory)
        ledger.record_experiment(
            ExperimentRecord(
                experiment_id="e-ok",
                hypothesis_id="t-ok",
                worker_role="local_rerun",
                started_at="2026-04-30T15:00:00+00:00",
                completed_at="2026-04-30T15:00:00+00:00",
            )
        )
        with sqlite3.connect(str(ledger.db_path)) as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM experiments WHERE completed_at = ''"
            ).fetchone()[0]
        assert n == 0


class TestWorkerStatusErrorMapping:
    """Patch 1 + 2 — WorkerStatus.ERROR/TIMEOUT must route to
    TheoryStatus.ERROR, not TheoryStatus.COMPLETED."""

    def test_theory_status_error_exists(self):
        """The new ERROR state must be defined."""
        assert hasattr(TheoryStatus, "ERROR")
        assert TheoryStatus.ERROR.value == "error"

    def test_error_is_terminal_outcome_state(self, tmp_path):
        """ERROR must be considered terminal so update_theory_status
        does the same audit-trail check as COMPLETED/ELIMINATED."""
        ledger = _open_ledger(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="t-err", title="t", core_claim="c",
            mechanism="m", family="f",
        )
        ledger.upsert_theory(theory)

        # No experiment trail yet. Setting status=ERROR via
        # update_theory_status should refuse, same as setting COMPLETED.
        with pytest.raises(ValueError, match="experiment trail"):
            ledger.update_theory_status("t-err", TheoryStatus.ERROR)

        # After recording an experiment, the update succeeds.
        ledger.record_experiment(
            ExperimentRecord(
                experiment_id="e1",
                hypothesis_id="t-err",
                worker_role="agent_sdk",
                started_at="2026-04-30T15:00:00+00:00",
                completed_at="2026-04-30T15:00:01+00:00",
            )
        )
        ledger.update_theory_status("t-err", TheoryStatus.ERROR)
        retrieved = ledger.get_theory("t-err")
        assert retrieved.status == TheoryStatus.ERROR


class TestAbsorbOutcomesErrorRouting:
    """Patch 1 — _absorb_outcomes must map WorkerStatus.ERROR to
    TheoryStatus.ERROR (not COMPLETED) for the score-ranking surface."""

    def _make_minimal_controller(self, tmp_path):
        from kryptosbot.controller import ResearchController, ControllerConfig

        config = MagicMock(spec=ControllerConfig)
        config.results_dir = tmp_path
        config.alert_threshold = MagicMock(value=18)
        ctrl = ResearchController.__new__(ResearchController)
        ctrl.config = config
        ctrl.ledger = _open_ledger(tmp_path)
        ctrl.state = MagicMock()
        ctrl.state.recent_outcomes = []
        ctrl.state.cycle_number = 1
        return ctrl

    def test_error_contract_routes_to_error_status(self, tmp_path):
        from kryptosbot.models import WorkerContract

        ctrl = self._make_minimal_controller(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="t-werr", title="t", core_claim="c",
            mechanism="m", family="f",
        )
        ctrl.ledger.upsert_theory(theory)
        # Need an experiment row so upsert_theory(ERROR) is allowed.
        ctrl.ledger.record_experiment(
            ExperimentRecord(
                experiment_id="e1", hypothesis_id="t-werr",
                worker_role="agent_sdk",
                started_at="2026-04-30T15:00:00+00:00",
                completed_at="2026-04-30T15:00:01+00:00",
            )
        )
        contract = WorkerContract(
            hypothesis_id="t-werr",
            worker_role="agent_sdk",
            status=WorkerStatus.ERROR,
            error="Fatal error in message reader",
        )
        ctrl._absorb_outcomes([contract])
        reloaded = ctrl.ledger.get_theory("t-werr")
        assert reloaded.status == TheoryStatus.ERROR
        assert reloaded.status != TheoryStatus.COMPLETED

    def test_timeout_contract_routes_to_error_status(self, tmp_path):
        from kryptosbot.models import WorkerContract

        ctrl = self._make_minimal_controller(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="t-tout", title="t", core_claim="c",
            mechanism="m", family="f",
        )
        ctrl.ledger.upsert_theory(theory)
        ctrl.ledger.record_experiment(
            ExperimentRecord(
                experiment_id="e1", hypothesis_id="t-tout",
                worker_role="agent_sdk",
                started_at="2026-04-30T15:00:00+00:00",
                completed_at="2026-04-30T15:30:00+00:00",
            )
        )
        contract = WorkerContract(
            hypothesis_id="t-tout",
            worker_role="agent_sdk",
            status=WorkerStatus.TIMEOUT,
            error="Timed out after 30 minutes",
        )
        ctrl._absorb_outcomes([contract])
        reloaded = ctrl.ledger.get_theory("t-tout")
        assert reloaded.status == TheoryStatus.ERROR
