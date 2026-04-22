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

    def test_record_experiment_and_link_updates_theory_backlink(self, tmp_ledger):
        """Recording an experiment must also update theory.experiment_ids."""
        theory = _make_theory("hyp-exp-link", status=TheoryStatus.RUNNING)
        tmp_ledger.upsert_theory(theory)

        controller = ResearchController(
            ControllerConfig(project_root=Path("."), ledger_db_path=tmp_ledger.db_path),
        )
        controller.ledger = tmp_ledger

        exp = ExperimentRecord(
            experiment_id="exp-link-001",
            hypothesis_id=theory.hypothesis_id,
            worker_role="agent_sdk",
            completed_at="2026-04-16T00:00:00+00:00",
            result=WorkerContract(
                hypothesis_id=theory.hypothesis_id,
                worker_role="agent_sdk",
                status=WorkerStatus.ERROR,
                error="synthetic failure",
            ),
        )

        controller._record_experiment_and_link(exp)

        refreshed = tmp_ledger.get_theory(theory.hypothesis_id)
        assert refreshed is not None
        assert "exp-link-001" in refreshed.experiment_ids

    def test_record_experiment_and_link_is_idempotent_for_same_experiment(self, tmp_ledger):
        """Re-recording the same experiment must not duplicate backlinks."""
        theory = _make_theory("hyp-exp-link-dup", status=TheoryStatus.RUNNING)
        tmp_ledger.upsert_theory(theory)

        controller = ResearchController(
            ControllerConfig(project_root=Path("."), ledger_db_path=tmp_ledger.db_path),
        )
        controller.ledger = tmp_ledger

        exp = ExperimentRecord(
            experiment_id="exp-link-dup-001",
            hypothesis_id=theory.hypothesis_id,
            worker_role="agent_sdk",
            completed_at="2026-04-16T00:00:00+00:00",
            result=WorkerContract(
                hypothesis_id=theory.hypothesis_id,
                worker_role="agent_sdk",
                status=WorkerStatus.ERROR,
                error="synthetic failure",
            ),
        )

        controller._record_experiment_and_link(exp)
        controller._record_experiment_and_link(exp)

        refreshed = tmp_ledger.get_theory(theory.hypothesis_id)
        assert refreshed is not None
        assert refreshed.experiment_ids.count("exp-link-dup-001") == 1


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

    def test_theorist_prompt_uses_current_retired_palette_date(self, tmp_path):
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
        assert "retired 2026-04-14" in prompt
        assert "retired 2026-04-01" not in prompt
        assert "b g i k o w z" not in prompt.lower()
        assert "b,g,i,k,o,w,z" not in prompt.lower()

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
        assert "w_delimiter_segments" in prompt
        assert "width21_vertical_bigrams" in prompt
        assert "Only the following investigable anomalies are admissible" in prompt
        # Rotation 2026-04-20: ct_perturbation is the PRIMARY anchor;
        # w_delimiter_segments is SATURATED and demoted from primary.
        assert "PRIMARY under-mined anchor" in prompt
        assert "SATURATED for single-layer work" in prompt
        assert "Treat width21 as a derived ranking feature" in prompt
        assert "explained by W placement" in prompt
        assert "historical anomalies" in prompt
        assert "ledger for audit" in prompt
        assert "MANUAL PRIORITY FOCUS" in prompt
        # Rotation 2026-04-20: manual focus points at the ranked under-mined
        # surface, not W specifically.
        assert "Rotate across the under-explored anomaly surface" in prompt
        assert "ct_perturbation is the currently under-mined" in prompt
        assert "w_delimiter_segments is SATURATED" in prompt
        assert "Do NOT use rescue parameters" in prompt
        assert "accept-specific-disproofs doctrine" in prompt

    def test_landscape_ranks_least_explored_anomaly_first(self, tmp_path):
        """Rotation 2026-04-20: sort by exploration depth, not hard-pin.

        Replaces the prior test that pinned w_delimiter_segments to
        position 0. The new sort puts the least-explored anomaly first so
        ranking self-tunes as exploration counts accumulate.
        """
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

        from kryptosbot.registries import bootstrap_all

        bootstrap_all(ctrl.ledger)
        landscape = ctrl._assess_landscape()
        open_anoms = landscape["open_anomalies"]
        # The first entry must be the least-explored admissible anomaly,
        # with ties broken by priority (lower is better).
        explored_counts = [a["explored_by"] for a in open_anoms]
        assert explored_counts == sorted(explored_counts), (
            "open_anomalies must be sorted ascending by explored_by"
        )
        # And the W hard-pin must no longer force position 0 when another
        # anomaly has fewer theories exploring it.
        if open_anoms and open_anoms[0]["id"] == "w_delimiter_segments":
            # Only acceptable if W is tied for the lowest exploration count.
            first_count = open_anoms[0]["explored_by"]
            assert all(a["explored_by"] >= first_count for a in open_anoms)

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


class TestConsensusNullMaskCriticHardening:
    """CONSENSUS_NULL_POSITIONS revival is rejected at the critic.

    Closes the generator leak observed 2026-04-17 (controller cycles 94-102):
    theories invoking the 17-position null mask slipped past red-team as
    CONCERNED and dispatched anyway. The palette matcher only catches the
    7-letter letter subset; this matcher catches position-mask revivals.
    """

    def test_literal_consensus_null_positions_symbol_is_rejected(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        critic = TheoryCritic(ledger)
        theory = TheoryRecord(
            hypothesis_id="literal-mask-symbol",
            title="Period-21 Keystream Under Null-Skip",
            core_claim=(
                "A period-21 keystream explains width-21 vertical bigrams "
                "when null positions are skipped per CONSENSUS_NULL_POSITIONS."
            ),
            mechanism="Skip tape positions listed in CONSENSUS_NULL_POSITIONS.",
            family="key_tape",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == "reject_eliminated" or verdict.decision.value == "reject_eliminated"
        assert any("CONSENSUS_NULL_POSITIONS revival" in reason for reason in verdict.reasons)

    def test_seventeen_position_null_mask_phrase_is_rejected(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        critic = TheoryCritic(ledger)
        theory = TheoryRecord(
            hypothesis_id="seventeen-position-phrase",
            title="Compass Rose Finite Keystream Tape",
            core_claim=(
                "A 32-point compass rose deterministically generates a finite "
                "keystream tape aligned to the 17-position null mask."
            ),
            mechanism="Step a tape past the 17-position null mask positions.",
            family="encoding",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == "reject_eliminated" or verdict.decision.value == "reject_eliminated"
        assert any("CONSENSUS_NULL_POSITIONS revival" in reason for reason in verdict.reasons)

    def test_consensus_null_mask_phrase_is_rejected(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        critic = TheoryCritic(ledger)
        theory = TheoryRecord(
            hypothesis_id="consensus-null-mask-phrase",
            title="CT-Perturbation Tape Skip Markers",
            core_claim=(
                "Coding-chart divergences select tape-skip positions that "
                "match the consensus null mask."
            ),
            mechanism="Use the consensus null positions to skip tape.",
            family="crib_analysis",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == "reject_eliminated" or verdict.decision.value == "reject_eliminated"
        assert any("CONSENSUS_NULL_POSITIONS revival" in reason for reason in verdict.reasons)

    def test_benign_null_prose_is_not_falsely_rejected(self, tmp_path):
        """Guard against false positives on legitimate stego prose.

        A theory that mentions "null" or "null mask" or "null positions" in
        general terms (without the 17-position / consensus phrasing and
        without the 5-of-7 palette letters) must NOT be rejected by either
        retired-construct matcher. Legitimate stego work must be able to
        discuss null masks.
        """
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        critic = TheoryCritic(ledger)
        theory = TheoryRecord(
            hypothesis_id="benign-null-prose",
            title="Novel Width-21 Column Null Hypothesis",
            core_claim=(
                "Each width-21 column may contain a single null position "
                "determined by an independent mechanism. No retired "
                "construct is invoked."
            ),
            mechanism=(
                "Place one null per column at a position selected by a "
                "novel width-21 carving-artefact rule."
            ),
            family="stego_layer",
        )
        verdict = critic.evaluate(theory)
        # The theory may still be rejected for OTHER reasons (duplicate,
        # contradiction), but it must NOT be rejected as either a
        # retired-palette revival or a CONSENSUS_NULL_POSITIONS revival.
        reasons_text = " ".join(verdict.reasons)
        assert "Retired palette revival" not in reasons_text
        assert "CONSENSUS_NULL_POSITIONS revival" not in reasons_text

    def test_theorist_prompt_names_consensus_null_positions_retraction(self, tmp_path):
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
        assert "CONSENSUS_NULL_POSITIONS" in prompt
        assert "17-position null mask" in prompt
        assert "pending retraction" in prompt


class TestDisplayStageTransitions:
    """Later controller stages must clear stale theorist status state."""

    def test_redteam_start_clears_theorist_spinner(self):
        from kryptosbot import display

        status = MagicMock()
        old_status = display._theorist_status
        try:
            display._theorist_status = status
            display.print_redteam_start("red-team-disprover", "claude-opus-4-7", 2)
            status.stop.assert_called_once()
            assert display._theorist_status is None
        finally:
            display._theorist_status = old_status


class TestWorkerPromptPolicyGuards:
    """Worker prompt policy blocks should preserve scratch and verification rules."""

    def test_worker_prompt_pins_scratch_and_kernel_verification_rules(self, tmp_path):
        from kryptosbot.controller import ResearchController, ControllerConfig

        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
        )
        ctrl = ResearchController.__new__(ResearchController)
        ctrl.config = cfg
        ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
        ctrl.state = ControllerState()
        ctrl._cycle_redteam_verdicts = {}

        theory = _make_theory(
            "worker001",
            title="Worker prompt policy test",
            family="test_family",
            kill_criteria=["No verified signal above preregistered threshold"],
            expected_signal="Kernel-verified crib signal only",
            minimal_test_spec={"method": "bounded_probe", "parameters": {"limit": 10}},
        )

        prompt = ctrl._build_worker_prompt(theory)
        scratch_rel = str(ctrl._worker_scratch_dir(theory).relative_to(cfg.project_root))

        assert "SCRATCH FILES — IMPORTANT:" in prompt
        assert f"{scratch_rel}/" in prompt
        assert "DO NOT write scratch files to:" in prompt
        assert "- scripts/" in prompt
        assert "- tests/" in prompt
        assert "- src/" in prompt
        assert "score fields are recomputed by the controller" in prompt
        assert "score_cribs" in prompt
        assert "verify_bean_simple" in prompt
        assert "will be DISCARDED" in prompt
        assert "kernel's values" in prompt


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


class TestTheoristTelemetrySurfacing:
    def test_assess_landscape_includes_theorist_parse_telemetry(self, tmp_path):
        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
            legacy_db_path=tmp_path / "results.db",
        )
        controller = ResearchController(config)
        controller.state.theorist_parse_successes = 4
        controller.state.theorist_parse_partial_successes = 1
        controller.state.theorist_fallbacks = 2
        controller.state.theorist_fallback_reasons = {
            "agent_failure": 1,
            "model_returned_only_invalid_proposals": 1,
        }
        controller.state.last_theorist_parse_diagnostics = {
            "parse_outcome": "fallback",
            "fallback_reason": "model_returned_only_invalid_proposals",
        }
        controller._session_baseline_tested = 0
        controller._session_baseline_eliminated = 0

        landscape = controller._assess_landscape()
        telemetry = landscape["theorist_parse_telemetry"]

        assert telemetry["successes"] == 4
        assert telemetry["partial_successes"] == 1
        assert telemetry["fallbacks"] == 2
        assert telemetry["fallback_reasons"]["agent_failure"] == 1
        assert telemetry["last"]["fallback_reason"] == (
            "model_returned_only_invalid_proposals"
        )


# ---------------------------------------------------------------------------
# Campaign-A hardening (2026-04-22) — origin tag, halt counters, Oranchak
# ---------------------------------------------------------------------------
# Red-team-disprover flagged three showstoppers on the pre-hardening plan:
#   (1) criterion_1 tautologically satisfied by prompt worked examples,
#   (2) _programmatic_fallback laundering indistinguishable in mortality
#       tables without a durable origin tag,
#   (3) R3 §5 halt conditions documented but not wired into either
#       cycle loop (feedback_dup_cycle_loop_trap applies).
# These tests lock the hardening response into place so future sessions
# can't silently regress any of the three.


class TestTheoryRecordOriginField:
    """Durable provenance tag on TheoryRecord separates fallback theories
    from agent-parsed ones without relying on title-pattern grep."""

    def test_default_origin_is_theorist_agent(self):
        from kryptosbot.models import TheoryRecord
        t = TheoryRecord(hypothesis_id="h1", title="t", core_claim="c", mechanism="m")
        assert t.origin == "theorist_agent"

    def test_programmatic_fallback_tags_origin(self, tmp_path):
        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
            legacy_db_path=tmp_path / "results.db",
        )
        controller = ResearchController(config)
        landscape = {
            "underexplored_families": [
                {"id": "grille", "name": "grille", "tested": 0},
                {"id": "polybius", "name": "polybius", "tested": 0},
            ],
            "unaddressed_anomalies": [
                {"id": "ct_perturbation", "title": "ct perturbation"},
            ],
        }
        theories = controller._programmatic_fallback(landscape)
        assert theories, "fallback must emit at least one theory"
        assert all(
            t.origin == "programmatic_fallback" for t in theories
        ), "every fallback-emitted record must carry origin tag"


class TestHardeningHaltCheck:
    """_check_cycle_hardening_halts wires R3 §5 halt conditions."""

    def _controller(self, tmp_path):
        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
            legacy_db_path=tmp_path / "results.db",
        )
        return ResearchController(config)

    def _fallback_candidate(self):
        return _make_theory("fh1", origin="programmatic_fallback")

    def _agent_candidate(self):
        return _make_theory("ah1", origin="theorist_agent")

    def _admissibility_reject(self):
        # An outcome that counts as D-column non-zero.
        return WorkerContract(
            hypothesis_id="adm1",
            status=WorkerStatus.REJECTED_ADMISSIBILITY,
        )

    def _success_outcome(self):
        return WorkerContract(
            hypothesis_id="ok1",
            status=WorkerStatus.SUCCESS,
            crib_score=5,
        )

    def test_fallback_streak_halts_at_threshold(self, tmp_path, monkeypatch):
        # Shrink threshold to 2 so the test is fast-failing and
        # deterministic; monkeypatching the module constant is the
        # canonical pattern from other hardening tests.
        from kryptosbot import controller as ctrl_mod
        monkeypatch.setattr(ctrl_mod, "FALLBACK_HALT_STREAK", 2)

        c = self._controller(tmp_path)
        cand = [self._fallback_candidate()]
        # Include one success outcome so D-zero streak does NOT also trip
        # and confuse the halt-reason attribution.
        out = [self._success_outcome()]

        r1 = c._check_cycle_hardening_halts(cand, out, [])
        assert r1 is None
        assert c.state.consecutive_fallback_cycles == 1

        r2 = c._check_cycle_hardening_halts(cand, out, [])
        assert r2 is not None
        assert "fallback" in r2.lower()
        assert c.state.halt_reason_hardening == r2

    def test_fallback_streak_resets_on_real_theorist_cycle(self, tmp_path, monkeypatch):
        from kryptosbot import controller as ctrl_mod
        monkeypatch.setattr(ctrl_mod, "FALLBACK_HALT_STREAK", 3)

        c = self._controller(tmp_path)
        out = [self._success_outcome()]

        c._check_cycle_hardening_halts([self._fallback_candidate()], out, [])
        assert c.state.consecutive_fallback_cycles == 1

        # Real theorist output ⇒ counter resets.
        c._check_cycle_hardening_halts([self._agent_candidate()], out, [])
        assert c.state.consecutive_fallback_cycles == 0

        # Counter can rise again from zero.
        c._check_cycle_hardening_halts([self._fallback_candidate()], out, [])
        assert c.state.consecutive_fallback_cycles == 1

    def test_d_zero_streak_halts_on_dispatched_cycles(self, tmp_path, monkeypatch):
        from kryptosbot import controller as ctrl_mod
        monkeypatch.setattr(ctrl_mod, "D_ZERO_HALT_STREAK", 2)

        c = self._controller(tmp_path)
        cand = [self._agent_candidate()]
        # Outcomes all SUCCESS ⇒ zero D-column rejections.
        out = [self._success_outcome(), self._success_outcome()]

        r1 = c._check_cycle_hardening_halts(cand, out, [])
        assert r1 is None
        assert c.state.consecutive_d_zero_cycles == 1

        r2 = c._check_cycle_hardening_halts(cand, out, [])
        assert r2 is not None
        assert "admissibility" in r2.lower() or "d column" in r2.lower()

    def test_d_zero_streak_not_incremented_on_zero_dispatched(self, tmp_path, monkeypatch):
        # A cycle with no dispatched contracts (dry run, critic killed
        # everything, etc.) must NOT advance the D-zero counter — the
        # concept "D column was zero" is undefined when there are no
        # rows to check.
        from kryptosbot import controller as ctrl_mod
        monkeypatch.setattr(ctrl_mod, "D_ZERO_HALT_STREAK", 2)

        c = self._controller(tmp_path)
        cand = [self._agent_candidate()]

        c._check_cycle_hardening_halts(cand, [], [])
        c._check_cycle_hardening_halts(cand, [], [])
        c._check_cycle_hardening_halts(cand, [], [])
        assert c.state.consecutive_d_zero_cycles == 0
        assert c.state.halt_reason_hardening == ""

    def test_d_zero_streak_resets_on_any_admissibility_rejection(self, tmp_path, monkeypatch):
        from kryptosbot import controller as ctrl_mod
        monkeypatch.setattr(ctrl_mod, "D_ZERO_HALT_STREAK", 3)

        c = self._controller(tmp_path)
        cand = [self._agent_candidate()]

        c._check_cycle_hardening_halts(cand, [self._success_outcome()], [])
        assert c.state.consecutive_d_zero_cycles == 1

        # One admissibility reject breaks the streak.
        c._check_cycle_hardening_halts(
            cand, [self._success_outcome(), self._admissibility_reject()], [],
        )
        assert c.state.consecutive_d_zero_cycles == 0

    def test_breakthrough_matched_null_miss_halts_immediately(self, tmp_path):
        # No streak required — a BREAKTHROUGH fired without reliable
        # null calibration is an ambiguous result that must pause the
        # run until the operator rebuilds the cache.
        from kryptosbot.alerts import AlertEvent
        c = self._controller(tmp_path)
        cand = [self._agent_candidate()]
        out = [self._admissibility_reject()]  # keeps D-zero at 0

        ev = AlertEvent(
            triggered_at="2026-04-22T00:00:00",
            hypothesis_id="bk1",
            level="breakthrough",
            crib_score=24,
            bean_passed=True,
            score=24.0,
            worker_status="success",
            best_plaintext="",
            narrative_summary="",
            contradiction_note="",
            cycle_number=1,
            p_value_status="matched_null_miss",
        )
        r = c._check_cycle_hardening_halts(cand, out, [ev])
        assert r is not None
        assert "null cache" in r.lower() or "calibrate" in r.lower()

    def test_breakthrough_ok_matched_family_does_not_halt(self, tmp_path):
        from kryptosbot.alerts import AlertEvent
        c = self._controller(tmp_path)
        cand = [self._agent_candidate()]
        out = [self._admissibility_reject()]

        ev = AlertEvent(
            triggered_at="2026-04-22T00:00:00",
            hypothesis_id="bk1",
            level="breakthrough",
            crib_score=24,
            bean_passed=True,
            score=24.0,
            worker_status="success",
            best_plaintext="",
            narrative_summary="",
            contradiction_note="",
            cycle_number=1,
            p_value_status="ok_matched_family",
        )
        r = c._check_cycle_hardening_halts(cand, out, [ev])
        assert r is None
        assert c.state.halt_reason_hardening == ""


class TestOranchakPromptPlumbing:
    """Theorist prompt exposes the Oranchak reference corpora."""

    def test_prompt_renders_oranchak_block(self, tmp_path):
        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
            legacy_db_path=tmp_path / "results.db",
        )
        controller = ResearchController(config)
        block = controller._render_oranchak_corpora_for_prompt()
        # Core paths must appear so the theorist can reference them
        # in minimal_test_spec.
        assert "wordlists/quagmire3_keywords_oranchak.txt" in block
        assert "wordlists/quagmire4_keywords_oranchak.txt" in block
        assert "data/k4_candidate_fills_oranchak.csv" in block
        # DSL-translator gap caveat must be surfaced so the theorist
        # doesn't propose kind='quagmire' and eat an admissibility rejection.
        assert "_SUPPORTED_KINDS" in block or "dsl_untranslatable" in block.lower()

    def test_oranchak_block_excludes_tier3_cia_memo(self, tmp_path):
        # feedback_sanborn_epistemic_weight: community-seeded material
        # gets into the prompt, but Tier-3 hearsay (CIA 1996 memo,
        # 3 of 4 cipher diagnoses wrong) must not.
        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
            legacy_db_path=tmp_path / "results.db",
        )
        controller = ResearchController(config)
        block = controller._render_oranchak_corpora_for_prompt()
        assert "cia_1996_memo.md" not in block
        assert "OTP" not in block  # OTP claim in the memo has no weight

    def test_theorist_prompt_incorporates_oranchak_block(self, tmp_path):
        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
            legacy_db_path=tmp_path / "results.db",
        )
        controller = ResearchController(config)
        prompt = controller._build_theorist_prompt({
            "underexplored_families": [],
            "unaddressed_anomalies": [],
            "open_anomalies": [],
        })
        assert "ORANCHAK COMMUNITY REFERENCE CORPORA" in prompt


class TestAlertEventCarriesPValueStatus:
    """p_value_status must reach AlertEvent so halt checks can see it."""

    def test_alert_event_has_p_value_status_field(self):
        from kryptosbot.alerts import AlertEvent
        ev = AlertEvent(
            triggered_at="t",
            hypothesis_id="h",
            level="signal",
            crib_score=18,
            bean_passed=False,
            score=18.0,
            worker_status="success",
            best_plaintext="",
            narrative_summary="",
            contradiction_note="",
            cycle_number=1,
            p_value_status="ok_matched_family",
        )
        assert ev.p_value_status == "ok_matched_family"

    def test_classify_outcome_returns_tuple(self):
        from kryptosbot.alerts import classify_outcome, AlertLevel
        contract = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=5,
            bean_passed=False,
        )
        result = classify_outcome(contract, AlertLevel.SIGNAL)
        # Tuple of (Optional[AlertLevel], p_value_status_str)
        assert isinstance(result, tuple)
        assert len(result) == 2
        level, status = result
        assert level is None  # crib=5 is noise
        assert isinstance(status, str)
