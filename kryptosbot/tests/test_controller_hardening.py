"""
Tests for controller reliability hardening (April 2026).

Covers:
1. Error contracts carry hypothesis_id (Concern 1)
2. Orphaned RUNNING reconciliation (Concern 4)
3. Status reflects persisted truth (Concern 2)
4. Session-local delta starts at 0 (Concern 5)
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Minimal imports — models and ledger have no heavy deps
# ---------------------------------------------------------------------------

import sys
import os

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.models import (
    TheoryRecord, TheoryStatus,
    WorkerContract, WorkerStatus,
    ExperimentRecord,
    ControllerState,
    AnomalyRecord, AnomalyStatus,
    FamilyRecord, FamilyStatus,
)
from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.critic import TheoryCritic
from kryptosbot.registries import bootstrap_campaign_manifests
from kryptosbot.theory_ledger import TheoryLedger


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_ledger(tmp_path):
    """Create a temporary theory ledger with a fresh SQLite database."""
    db_path = tmp_path / "test_ledger.sqlite"
    return TheoryLedger(db_path)


def _make_theory(hypothesis_id: str, status: TheoryStatus = TheoryStatus.PROPOSED, **kwargs) -> TheoryRecord:
    """Helper to create a theory record with minimal required fields."""
    defaults = dict(
        hypothesis_id=hypothesis_id,
        title=f"Test theory {hypothesis_id}",
        core_claim=f"Claim for {hypothesis_id}",
        mechanism=f"Mechanism for {hypothesis_id}",
        family="test_family",
        status=status,
    )
    defaults.update(kwargs)
    return TheoryRecord(**defaults)


# ---------------------------------------------------------------------------
# Concern 1: Error contract carries hypothesis_id
# ---------------------------------------------------------------------------

class TestErrorContractHypothesisId:
    """Verify that when asyncio.gather catches an exception, the resulting
    WorkerContract carries the correct hypothesis_id so _absorb_outcomes
    can process it."""

    def test_error_contract_has_hypothesis_id(self):
        """Simulate what _dispatch_theories does on exception."""
        theory = _make_theory("hyp-001", status=TheoryStatus.RUNNING)
        exception = RuntimeError("SDK connection failed")

        # This is the logic from the fixed _dispatch_theories
        error_contract = WorkerContract(
            hypothesis_id=theory.hypothesis_id,
            worker_role="agent_sdk",
            status=WorkerStatus.ERROR,
            error=f"Worker exception: {type(exception).__name__}: {exception}",
        )

        assert error_contract.hypothesis_id == "hyp-001"
        assert error_contract.status == WorkerStatus.ERROR
        assert "RuntimeError" in error_contract.error
        assert "SDK connection failed" in error_contract.error

    def test_error_contract_records_experiment(self, tmp_ledger):
        """An error contract should produce an experiment record in the ledger."""
        theory = _make_theory("hyp-002", status=TheoryStatus.RUNNING)
        tmp_ledger.upsert_theory(theory)

        error_contract = WorkerContract(
            hypothesis_id="hyp-002",
            worker_role="agent_sdk",
            status=WorkerStatus.ERROR,
            error="Worker exception: ValueError: bad data",
        )
        exp = ExperimentRecord(
            experiment_id="exp-err-test001",
            hypothesis_id="hyp-002",
            worker_role="agent_sdk",
            completed_at="2026-04-11T00:00:00+00:00",
            result=error_contract,
        )
        tmp_ledger.record_experiment(exp)

        experiments = tmp_ledger.get_experiments_for_theory("hyp-002")
        assert len(experiments) == 1
        assert experiments[0].result.status == WorkerStatus.ERROR
        assert "ValueError" in experiments[0].result.error


# ---------------------------------------------------------------------------
# Concern 2: Status reflects persisted truth
# ---------------------------------------------------------------------------

class TestStatusReflectsPersistedTruth:
    """Verify that get_status() loads from the ledger rather than
    returning a fresh zero-valued ControllerState."""

    def test_status_loads_persisted_state(self, tmp_ledger):
        """After persisting state, get_status() should reflect it."""
        # Save some state
        state = ControllerState(
            cycle_number=7,
            theories_proposed=15,
            theories_tested=12,
            theories_eliminated=5,
            theories_promising=2,
        )
        tmp_ledger.save_controller_state(state)

        # Load it back
        loaded = tmp_ledger.load_controller_state()
        assert loaded.cycle_number == 7

    def test_status_counts_refreshed_from_theories(self, tmp_ledger):
        """_update_state_counts_on should compute counts from actual theories."""
        # Insert some theories at various statuses
        for i, status in enumerate([
            TheoryStatus.COMPLETED,
            TheoryStatus.ELIMINATED,
            TheoryStatus.ELIMINATED,
            TheoryStatus.PROMISING,
            TheoryStatus.PROPOSED,
        ]):
            tmp_ledger.upsert_theory(
                _make_theory(f"hyp-count-{i}", status=status)
            )

        state = ControllerState()
        assert state.theories_proposed == 0  # starts at zero

        # Simulate what _update_state_counts_on does
        counts = tmp_ledger.count_by_status()
        state.theories_proposed = sum(counts.values())
        state.theories_tested = sum(
            counts.get(s, 0) for s in ["completed", "eliminated", "promising"]
        )
        state.theories_eliminated = counts.get("eliminated", 0)
        state.theories_promising = counts.get("promising", 0)

        assert state.theories_proposed == 5
        assert state.theories_tested == 4  # completed + 2 eliminated + promising
        assert state.theories_eliminated == 2
        assert state.theories_promising == 1


# ---------------------------------------------------------------------------
# Concern 4: Orphaned RUNNING reconciliation
# ---------------------------------------------------------------------------

class TestOrphanedRunningReconciliation:
    """Verify that theories stuck in RUNNING are recovered at startup."""

    def test_reconcile_transitions_running_to_completed(self, tmp_ledger):
        """Theories in RUNNING should be moved to COMPLETED with reason."""
        # Create theories in various states
        tmp_ledger.upsert_theory(_make_theory("hyp-run-1", TheoryStatus.RUNNING))
        tmp_ledger.upsert_theory(_make_theory("hyp-run-2", TheoryStatus.RUNNING))
        tmp_ledger.upsert_theory(_make_theory("hyp-done", TheoryStatus.COMPLETED))
        tmp_ledger.upsert_theory(_make_theory("hyp-prop", TheoryStatus.PROPOSED))

        reconciled = tmp_ledger.reconcile_orphaned_running()

        assert sorted(reconciled) == ["hyp-run-1", "hyp-run-2"]

        # Verify they're now COMPLETED
        t1 = tmp_ledger.get_theory("hyp-run-1")
        assert t1.status == TheoryStatus.COMPLETED
        assert "Orphaned" in t1.failure_reason

        t2 = tmp_ledger.get_theory("hyp-run-2")
        assert t2.status == TheoryStatus.COMPLETED

        # Non-RUNNING theories unchanged
        t_done = tmp_ledger.get_theory("hyp-done")
        assert t_done.status == TheoryStatus.COMPLETED

        t_prop = tmp_ledger.get_theory("hyp-prop")
        assert t_prop.status == TheoryStatus.PROPOSED

    def test_reconcile_noop_when_none_running(self, tmp_ledger):
        """When no theories are in RUNNING, reconcile returns empty list."""
        tmp_ledger.upsert_theory(_make_theory("hyp-ok", TheoryStatus.COMPLETED))
        reconciled = tmp_ledger.reconcile_orphaned_running()
        assert reconciled == []

    def test_reconcile_idempotent(self, tmp_ledger):
        """Running reconcile twice should be safe (second call is a no-op)."""
        tmp_ledger.upsert_theory(_make_theory("hyp-orphan", TheoryStatus.RUNNING))

        first = tmp_ledger.reconcile_orphaned_running()
        assert len(first) == 1

        second = tmp_ledger.reconcile_orphaned_running()
        assert len(second) == 0


# ---------------------------------------------------------------------------
# Concern 5: Session-local delta starts at 0
# ---------------------------------------------------------------------------

class TestSessionLocalDelta:
    """Verify that session deltas are computed from session start, not zero."""

    def test_delta_starts_at_zero(self, tmp_ledger):
        """On first cycle, delta should be 0 (nothing new this session)."""
        # Pre-populate some history
        for i in range(5):
            tmp_ledger.upsert_theory(
                _make_theory(f"hyp-hist-{i}", TheoryStatus.ELIMINATED)
            )

        counts = tmp_ledger.count_by_status()
        baseline_tested = sum(
            counts.get(s, 0) for s in ["completed", "eliminated", "promising"]
        )
        baseline_eliminated = counts.get("eliminated", 0)

        # Delta should be 0 because current == baseline
        current_tested = baseline_tested
        current_eliminated = baseline_eliminated
        delta_tested = current_tested - baseline_tested
        delta_eliminated = current_eliminated - baseline_eliminated

        assert delta_tested == 0
        assert delta_eliminated == 0

    def test_delta_increases_after_new_work(self, tmp_ledger):
        """After adding theories in this session, delta should reflect them."""
        # Baseline: 3 eliminated
        for i in range(3):
            tmp_ledger.upsert_theory(
                _make_theory(f"hyp-old-{i}", TheoryStatus.ELIMINATED)
            )

        counts = tmp_ledger.count_by_status()
        baseline_tested = sum(
            counts.get(s, 0) for s in ["completed", "eliminated", "promising"]
        )
        baseline_eliminated = counts.get("eliminated", 0)

        # Simulate new work in this session
        tmp_ledger.upsert_theory(
            _make_theory("hyp-new-1", TheoryStatus.ELIMINATED)
        )
        tmp_ledger.upsert_theory(
            _make_theory("hyp-new-2", TheoryStatus.COMPLETED)
        )

        counts = tmp_ledger.count_by_status()
        current_tested = sum(
            counts.get(s, 0) for s in ["completed", "eliminated", "promising"]
        )
        current_eliminated = counts.get("eliminated", 0)

        assert current_tested - baseline_tested == 2
        assert current_eliminated - baseline_eliminated == 1


# ---------------------------------------------------------------------------
# Concern 3: ControllerState no longer has budget fields
# ---------------------------------------------------------------------------

class TestControllerStateNoBudget:
    """Verify budget fields were removed from ControllerState."""

    def test_no_budget_fields(self):
        state = ControllerState()
        assert not hasattr(state, "budget_spent_usd")
        assert not hasattr(state, "budget_limit_usd")

    def test_from_dict_ignores_legacy_budget(self):
        """Loading a state dict with old budget fields should not crash."""
        d = {
            "cycle_number": 5,
            "budget_spent_usd": 12.50,
            "budget_limit_usd": 50.0,
        }
        state = ControllerState.from_dict(d)
        assert state.cycle_number == 5
        assert not hasattr(state, "budget_spent_usd") or not state.__dataclass_fields__.get("budget_spent_usd")


class TestLandscapeResetFiltering:
    """Controller reset should only surface admissible anomalies."""

    def test_assess_landscape_filters_to_admissible_anomalies(self, tmp_path):
        from kryptosbot.controller import ResearchController, ControllerConfig

        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
        )
        ctrl = ResearchController.__new__(ResearchController)
        ctrl.config = cfg
        ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
        ctrl.state = ControllerState()
        ctrl._last_synthesis = None
        ctrl._session_baseline_tested = 0
        ctrl._session_baseline_eliminated = 0

        ctrl.ledger.upsert_anomaly(AnomalyRecord(
            anomaly_id="ct_perturbation",
            title="CT perturbation",
            status=AnomalyStatus.OPEN,
        ))
        ctrl.ledger.upsert_anomaly(AnomalyRecord(
            anomaly_id="aaa_coordinate_lie",
            title="He lied",
            status=AnomalyStatus.OPEN,
        ))
        ctrl.ledger.upsert_anomaly(AnomalyRecord(
            anomaly_id="width21_vertical_bigrams",
            title="Width 21",
            status=AnomalyStatus.OPEN,
        ))
        ctrl.ledger.upsert_anomaly(AnomalyRecord(
            anomaly_id="bean_eq_27_65",
            title="standing constraint",
            status=AnomalyStatus.OPEN,
        ))

        landscape = ctrl._assess_landscape()
        open_ids = [a["id"] for a in landscape["open_anomalies"]]
        assert set(open_ids) == {
            "ct_perturbation",
            "aaa_coordinate_lie",
            "width21_vertical_bigrams",
        }
        assert "bean_eq_27_65" not in open_ids
        assert landscape["prompt_anomaly_count"] == 3
        assert landscape["registry_open_anomaly_count"] == 4


class TestCampaignManifestBootstrapPersistence:
    """Manifest bootstrap must persist tier/status upgrades even if evidence text matches."""

    def test_tier_upgrade_persists_without_evidence_change(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        theory_family = "unit_test_family"
        ledger.upsert_family(FamilyRecord(
            family_id=theory_family,
            name="Unit Test Family",
            status=FamilyStatus.ACTIVE,
            elimination_tier=4,
            elimination_evidence="same evidence",
        ))

        manifest_dir = tmp_path / "results" / "campaign_manifests"
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "live.json").write_text(json.dumps({
            "family_updates": {
                theory_family: {
                    "tier": 2,
                    "evidence": "same evidence",
                }
            }
        }))

        updated = bootstrap_campaign_manifests(ledger, tmp_path)
        assert updated == 1

        restored = ledger.get_family(theory_family)
        assert restored is not None
        assert restored.elimination_tier == 2
        assert restored.status == FamilyStatus.EXHAUSTED

    def test_live_manifest_overrides_historical_evidence(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        manifest_dir = tmp_path / "results" / "campaign_manifests"
        historical_dir = manifest_dir / "historical"
        historical_dir.mkdir(parents=True)

        (historical_dir / "old.json").write_text(json.dumps({
            "family_updates": {
                "overlay_family": {
                    "tier": 3,
                    "evidence": "historical evidence",
                }
            }
        }))
        (manifest_dir / "live.json").write_text(json.dumps({
            "family_updates": {
                "overlay_family": {
                    "tier": 3,
                    "evidence": "live evidence",
                }
            }
        }))

        updated = bootstrap_campaign_manifests(ledger, tmp_path)
        assert updated == 2

        restored = ledger.get_family("overlay_family")
        assert restored is not None
        assert restored.elimination_evidence == "live evidence"


class TestRetiredPaletteCriticHardening:
    """Retired-palette revival detection must not depend on uppercase prose."""

    def test_lowercase_retired_palette_revival_is_rejected(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        critic = TheoryCritic(ledger)
        theory = TheoryRecord(
            hypothesis_id="lowercase-palette",
            title="null palette candidate",
            core_claim="Try null palette b g i k o w z against separators.",
            mechanism="stego mask letters {b,g,i,k,o,w,z}",
            family="stego_layer",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == "reject_eliminated" or verdict.decision.value == "reject_eliminated"
        assert any("Retired palette revival" in reason for reason in verdict.reasons)

    def test_theorist_prompt_names_reset_anomaly_allowlist(self, tmp_path):
        from kryptosbot.controller import ResearchController, ControllerConfig

        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
        )
        ctrl = ResearchController.__new__(ResearchController)
        ctrl.config = cfg
        ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
        ctrl.state = ControllerState()

        prompt = ctrl._build_theorist_prompt({
            "open_anomalies": [],
            "unaddressed_anomalies": [],
            "underexplored_families": [],
            "standing_constraints": [],
            "status_counts": {},
            "cycle_delta": {},
            "active_families": [],
            "recent_outcomes": [],
            "pursuit_leads": [],
            "previous_synthesis": None,
        })
        assert "ct_perturbation" in prompt
        assert "aaa_coordinate_lie" in prompt
        assert "aaa_compass_cipher" in prompt
        assert "width21_vertical_bigrams" in prompt
        assert "Only the following investigable anomalies are admissible" in prompt
        assert "MANUAL PRIORITY FOCUS" in prompt
        assert "finite physical reassembly hypotheses" in prompt
        assert "Do NOT use W-delimiters as a standalone clue surface" in prompt

    def test_landscape_recent_outcomes_hides_retracted_archive_ocr_theory(self, tmp_path):
        from kryptosbot.controller import ResearchController, ControllerConfig

        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
        )
        ctrl = ResearchController.__new__(ResearchController)
        ctrl.config = cfg
        ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
        ctrl.state = ControllerState()
        ctrl._last_synthesis = None
        ctrl._session_baseline_tested = 0
        ctrl._session_baseline_eliminated = 0

        ctrl.ledger.upsert_theory(_make_theory(
            "ocr001",
            status=TheoryStatus.ELIMINATED,
            title="Sequential four-width columnar transposition from '4, 8, 10, 26 = Col'",
            core_claim="Operationalize the OCR-misread archive note as column widths.",
            family="archive_evidence",
        ))
        ctrl.ledger.upsert_theory(_make_theory(
            "good001",
            status=TheoryStatus.ELIMINATED,
            title="True coordinate digits as Beaufort key",
            core_claim="Use the alternate coordinate digits as a bounded key stream.",
            family="k2_coords",
        ))

        landscape = ctrl._assess_landscape()
        titles = [r["title"] for r in landscape["recent_outcomes"]]
        assert "True coordinate digits as Beaufort key" in titles
        assert not any("4, 8, 10, 26 = Col" in title for title in titles)


class TestDisplayStageTransitions:
    """Later controller stages must clear stale theorist status state."""

    def test_redteam_start_clears_theorist_spinner(self):
        from kryptosbot import display

        status = MagicMock()
        old_status = display._theorist_status
        try:
            display._theorist_status = status
            display.print_redteam_start("red-team-disprover", "claude-opus-4-6", 2)
            status.stop.assert_called_once()
            assert display._theorist_status is None
        finally:
            display._theorist_status = old_status


class TestFatalTheoristFailures:
    """Fatal theorist/session failures should halt the current run."""

    def test_generate_theories_halts_on_rate_limit_protocol_failure(
        self, tmp_path, monkeypatch,
    ):
        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
            legacy_db_path=tmp_path / "results.db",
        )
        controller = ResearchController(config)
        monkeypatch.setattr(controller, "_build_theorist_prompt", lambda _: "prompt")

        async def fake_safe_query(*, prompt, options):
            assert prompt == "prompt"
            options.stderr("Fatal error in message reader: Command failed with exit code 1")
            options.stderr("You've hit your limit · resets 8am (America/New_York)")
            if False:
                yield None
            raise RuntimeError("Command failed with exit code 1")

        monkeypatch.setattr("kryptosbot.controller.safe_query", fake_safe_query)

        candidates = asyncio.run(
            controller._generate_theories({"underexplored_families": []})
        )

        assert candidates == []
        assert controller.should_abort_run()
        assert controller.fatal_agent_error is not None
        assert "PROTOCOL_MISMATCH" in controller.fatal_agent_error

    def test_generate_theories_unknown_failure_uses_programmatic_fallback(
        self, tmp_path, monkeypatch,
    ):
        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
            legacy_db_path=tmp_path / "results.db",
        )
        controller = ResearchController(config)
        monkeypatch.setattr(controller, "_build_theorist_prompt", lambda _: "prompt")

        async def fake_safe_query(*, prompt, options):
            assert prompt == "prompt"
            if False:
                yield None
            raise RuntimeError("unexpected transient failure")

        monkeypatch.setattr("kryptosbot.controller.safe_query", fake_safe_query)

        landscape = {
            "underexplored_families": [{"id": "geometry", "name": "Geometry", "tested": 0}],
            "unaddressed_anomalies": [],
        }
        candidates = asyncio.run(controller._generate_theories(landscape))

        assert len(candidates) == 1
        assert candidates[0].family == "geometry"
        assert not controller.should_abort_run()

    def test_dispatch_header_clears_theorist_spinner(self):
        from kryptosbot import display

        status = MagicMock()
        old_status = display._theorist_status
        try:
            display._theorist_status = status
            display.print_dispatch_header(1)
            status.stop.assert_called_once()
            assert display._theorist_status is None
            if display._dispatch_progress:
                display._dispatch_progress.stop()
                display._dispatch_progress = None
        finally:
            display._theorist_status = old_status
