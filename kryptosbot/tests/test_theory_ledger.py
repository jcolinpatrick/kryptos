"""
Tests for the theory ledger, models, critic, and registries.

Covers:
- Model serialization/deserialization round-trips
- Ledger CRUD operations
- Deduplication via hypothesis_id
- Critic contract enforcement
- Family and anomaly registry bootstrap
- Controller state persistence
- Worker contract parsing
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure src and repo root are on path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from kryptosbot.models import (
    TheoryRecord, TheoryStatus,
    CriticVerdict, CriticDecision,
    WorkerContract, WorkerStatus,
    ExperimentRecord,
    AnomalyRecord, AnomalyStatus,
    FamilyRecord, FamilyStatus,
    EvidenceLink, EvidenceType,
    ControllerState,
    ContractValidationError,
    _stable_id,
)
from kryptosbot.contracts import (
    ParseResult,
    validate_worker_contract,
    validate_theory_proposals,
    extract_json_block,
)
from kryptosbot.theory_ledger import TheoryLedger
from kryptosbot.critic import TheoryCritic
from kryptosbot.registries import (
    bootstrap_families, bootstrap_anomalies, bootstrap_all,
    KNOWN_FAMILIES, KNOWN_ANOMALIES, STANDING_CONSTRAINTS,
    ADMISSIBLE_PROMPT_ANOMALY_IDS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_ledger(tmp_path):
    """Create a temporary ledger for testing."""
    db_path = tmp_path / "test_ledger.sqlite"
    return TheoryLedger(db_path)


@pytest.fixture
def sample_theory():
    """Create a sample theory for testing."""
    return TheoryRecord(
        title="Test double columnar with KRYPTOS keyword",
        core_claim="K4 uses double columnar transposition with keyword KRYPTOS",
        mechanism="Two consecutive columnar transpositions with widths 7 and 14",
        family="double_columnar",
        subfamily="keyword_derived",
        tags=["transposition", "kryptos"],
        clue_anchors_used=["K3 uses transposition + Vigenère"],
        anomalies_exploited=["bean_eq_27_65"],
        novelty_basis="Untested width combination",
        kill_criteria=["Crib score < 10 for all keyword variations"],
        expected_signal="Crib score >= 18 with Bean pass",
        compute_cost_estimate="medium",
        minimal_test_spec={
            "method": "double_columnar_sweep",
            "parameters": {"widths": [7, 14], "keyword": "KRYPTOS"},
        },
    )


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestModels:
    """Test dataclass serialization and deserialization."""

    def test_theory_record_round_trip(self, sample_theory):
        d = sample_theory.to_dict()
        restored = TheoryRecord.from_dict(d)
        assert restored.title == sample_theory.title
        assert restored.core_claim == sample_theory.core_claim
        assert restored.family == sample_theory.family
        assert restored.status == TheoryStatus.PROPOSED
        assert restored.tags == ["transposition", "kryptos"]
        assert restored.kill_criteria == sample_theory.kill_criteria

    def test_theory_record_stable_id(self):
        t1 = TheoryRecord(
            core_claim="Test claim",
            mechanism="Test mechanism",
            family="test_family",
        )
        t2 = TheoryRecord(
            core_claim="Test claim",
            mechanism="Test mechanism",
            family="test_family",
        )
        assert t1.hypothesis_id == t2.hypothesis_id
        assert len(t1.hypothesis_id) == 12

    def test_theory_record_different_ids(self):
        t1 = TheoryRecord(core_claim="Claim A", mechanism="M1", family="F1")
        t2 = TheoryRecord(core_claim="Claim B", mechanism="M1", family="F1")
        assert t1.hypothesis_id != t2.hypothesis_id

    def test_critic_verdict_round_trip(self):
        v = CriticVerdict(
            decision=CriticDecision.APPROVE,
            confidence=0.85,
            reasons=["Novel approach", "Exploits anomaly"],
            similar_hypotheses=["abc123"],
            estimated_information_gain="high",
        )
        d = v.to_dict()
        restored = CriticVerdict.from_dict(d)
        assert restored.decision == CriticDecision.APPROVE
        assert restored.confidence == 0.85
        assert len(restored.reasons) == 2

    def test_worker_contract_round_trip(self):
        wc = WorkerContract(
            hypothesis_id="test123",
            worker_role="agent_sdk",
            status=WorkerStatus.DISPROVED,
            score=3.0,
            crib_score=3,
            disproof_evidence=["No crib match for any parameter"],
        )
        d = wc.to_dict()
        restored = WorkerContract.from_dict(d)
        assert restored.status == WorkerStatus.DISPROVED
        assert restored.score == 3.0
        assert restored.is_actionable()

    def test_worker_contract_is_actionable(self):
        assert WorkerContract(status=WorkerStatus.SUCCESS).is_actionable()
        assert WorkerContract(status=WorkerStatus.DISPROVED).is_actionable()
        assert not WorkerContract(status=WorkerStatus.INCONCLUSIVE).is_actionable()
        assert not WorkerContract(status=WorkerStatus.ERROR).is_actionable()

    def test_worker_contract_invalid_status_lenient_from_dict(self):
        """Lenient from_dict still produces INCONCLUSIVE for stored data compat,
        but flags the issue in the error field."""
        wc = WorkerContract.from_dict({"status": "bogus_status"})
        assert wc.status == WorkerStatus.INCONCLUSIVE
        assert "[VALIDATION]" in wc.error

    def test_worker_contract_validated_from_dict_rejects_invalid_status(self):
        """Strict validation rejects invalid status outright."""
        from kryptosbot.models import ContractValidationError
        with pytest.raises(ContractValidationError, match="Invalid status"):
            WorkerContract.validated_from_dict({"status": "bogus_status"})

    def test_worker_contract_validated_from_dict_rejects_missing_status(self):
        from kryptosbot.models import ContractValidationError
        with pytest.raises(ContractValidationError, match="Missing required field"):
            WorkerContract.validated_from_dict({"score": 5.0})

    def test_worker_contract_validated_from_dict_rejects_wrong_types(self):
        from kryptosbot.models import ContractValidationError
        with pytest.raises(ContractValidationError, match="must be numeric"):
            WorkerContract.validated_from_dict({"status": "success", "score": "not a number"})

    def test_worker_contract_validated_from_dict_accepts_valid(self):
        wc = WorkerContract.validated_from_dict({
            "status": "disproved",
            "score": 3.0,
            "crib_score": 3,
            "bean_passed": False,
        })
        assert wc.status == WorkerStatus.DISPROVED
        assert wc.score == 3.0

    def test_experiment_record_round_trip(self):
        exp = ExperimentRecord(
            experiment_id="exp-abc",
            hypothesis_id="hyp-123",
            worker_role="oracle",
            config={"method": "keyword_sweep"},
            result=WorkerContract(
                hypothesis_id="hyp-123",
                status=WorkerStatus.SUCCESS,
                score=15.0,
            ),
        )
        d = exp.to_dict()
        restored = ExperimentRecord.from_dict(d)
        assert restored.experiment_id == "exp-abc"
        assert restored.result is not None
        assert restored.result.score == 15.0

    def test_anomaly_record_round_trip(self):
        a = AnomalyRecord(
            anomaly_id="test_anomaly",
            title="Test Anomaly",
            status=AnomalyStatus.OPEN,
        )
        d = a.to_dict()
        restored = AnomalyRecord.from_dict(d)
        assert restored.status == AnomalyStatus.OPEN

    def test_family_record_round_trip(self):
        f = FamilyRecord(
            family_id="test_fam",
            name="Test Family",
            status=FamilyStatus.PARTIALLY_EXPLORED,
            elimination_tier=3,
        )
        d = f.to_dict()
        restored = FamilyRecord.from_dict(d)
        assert restored.status == FamilyStatus.PARTIALLY_EXPLORED
        assert restored.elimination_tier == 3

    def test_controller_state_round_trip(self):
        cs = ControllerState(
            cycle_number=5,
            theories_proposed=20,
            theories_eliminated=8,
            underexplored_families=["novel", "key_tape"],
        )
        d = cs.to_dict()
        restored = ControllerState.from_dict(d)
        assert restored.cycle_number == 5
        assert restored.underexplored_families == ["novel", "key_tape"]

    def test_stable_id_deterministic(self):
        id1 = _stable_id("claim", "mech", "fam")
        id2 = _stable_id("claim", "mech", "fam")
        assert id1 == id2

    def test_stable_id_varies_with_input(self):
        id1 = _stable_id("claim1", "mech", "fam")
        id2 = _stable_id("claim2", "mech", "fam")
        assert id1 != id2


# ---------------------------------------------------------------------------
# Ledger tests
# ---------------------------------------------------------------------------

class TestTheoryLedger:
    """Test SQLite-backed theory ledger operations."""

    def test_upsert_and_get(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        retrieved = tmp_ledger.get_theory(sample_theory.hypothesis_id)
        assert retrieved is not None
        assert retrieved.title == sample_theory.title
        assert retrieved.family == "double_columnar"
        assert retrieved.tags == ["transposition", "kryptos"]

    def test_estimated_compute_minutes_round_trip(self, tmp_ledger):
        """Day 5: estimated_compute_minutes survives the SQLite round-trip.

        Schema field added 2026-04-13 for compute-budget-aware critic
        decisions. Default of 0 must also work for theories that don't
        specify it.
        """
        with_estimate = TheoryRecord(
            title="Costed theory",
            core_claim="cheap kill",
            mechanism="m",
            family="test",
            estimated_compute_minutes=15,
        )
        no_estimate = TheoryRecord(
            title="Uncosted theory",
            core_claim="no estimate",
            mechanism="m",
            family="test",
        )
        tmp_ledger.upsert_theory(with_estimate)
        tmp_ledger.upsert_theory(no_estimate)

        r1 = tmp_ledger.get_theory(with_estimate.hypothesis_id)
        r2 = tmp_ledger.get_theory(no_estimate.hypothesis_id)
        assert r1.estimated_compute_minutes == 15
        assert r2.estimated_compute_minutes == 0

    def test_deduplication(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        sample_theory.notes = "Updated note"
        tmp_ledger.upsert_theory(sample_theory)
        # Should still be one record
        results = tmp_ledger.search_theories(family="double_columnar")
        assert len(results) == 1
        assert results[0].notes == "Updated note"

    def test_get_nonexistent(self, tmp_ledger):
        assert tmp_ledger.get_theory("nonexistent") is None

    def test_exists(self, tmp_ledger, sample_theory):
        assert not tmp_ledger.exists(sample_theory.hypothesis_id)
        tmp_ledger.upsert_theory(sample_theory)
        assert tmp_ledger.exists(sample_theory.hypothesis_id)

    def test_status_update(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        tmp_ledger.record_experiment(ExperimentRecord(
            experiment_id="exp-status-update",
            hypothesis_id=sample_theory.hypothesis_id,
            worker_role="agent_sdk",
            result=WorkerContract(
                hypothesis_id=sample_theory.hypothesis_id,
                status=WorkerStatus.DISPROVED,
            ),
        ))
        tmp_ledger.update_theory_status(
            sample_theory.hypothesis_id,
            TheoryStatus.ELIMINATED,
            failure_reason="Crib score 0/24",
        )
        retrieved = tmp_ledger.get_theory(sample_theory.hypothesis_id)
        assert retrieved.status == TheoryStatus.ELIMINATED
        assert retrieved.failure_reason == "Crib score 0/24"

    def test_outcome_status_update_requires_experiment_trail(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        with pytest.raises(ValueError, match="without a recorded experiment trail"):
            tmp_ledger.update_theory_status(
                sample_theory.hypothesis_id,
                TheoryStatus.ELIMINATED,
            )

    def test_bookkeeping_status_update_does_not_require_experiment_trail(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        tmp_ledger.update_theory_status(
            sample_theory.hypothesis_id,
            TheoryStatus.WITHDRAWN,
            failure_reason="manual quarantine",
        )
        retrieved = tmp_ledger.get_theory(sample_theory.hypothesis_id)
        assert retrieved.status == TheoryStatus.WITHDRAWN
        assert retrieved.failure_reason == "manual quarantine"

    def test_direct_outcome_upsert_without_experiment_is_audit_annotated(self, tmp_ledger):
        theory = TheoryRecord(
            hypothesis_id="audit-upsert-1",
            title="direct eliminated theory",
            core_claim="bootstrap direct outcome",
            mechanism="manual import",
            family="test_family",
            status=TheoryStatus.ELIMINATED,
        )
        tmp_ledger.upsert_theory(theory)
        retrieved = tmp_ledger.get_theory(theory.hypothesis_id)
        assert retrieved is not None
        assert retrieved.status == TheoryStatus.ELIMINATED
        assert "Outcome-state direct upsert without experiment trail" in retrieved.notes

    def test_direct_outcome_upsert_with_experiment_ids_is_not_annotated(self, tmp_ledger):
        theory = TheoryRecord(
            hypothesis_id="audit-upsert-2",
            title="direct promising theory",
            core_claim="imported outcome",
            mechanism="manual import",
            family="test_family",
            status=TheoryStatus.PROMISING,
            experiment_ids=["exp-imported-1"],
        )
        tmp_ledger.upsert_theory(theory)
        retrieved = tmp_ledger.get_theory(theory.hypothesis_id)
        assert retrieved is not None
        assert retrieved.status == TheoryStatus.PROMISING
        assert "Outcome-state direct upsert without experiment trail" not in retrieved.notes

    def test_get_by_status(self, tmp_ledger):
        for i in range(3):
            t = TheoryRecord(
                core_claim=f"Claim {i}", mechanism="M", family="F",
                status=TheoryStatus.PROPOSED,
            )
            tmp_ledger.upsert_theory(t)
        t_elim = TheoryRecord(
            core_claim="Eliminated", mechanism="M", family="F",
            status=TheoryStatus.ELIMINATED,
        )
        tmp_ledger.upsert_theory(t_elim)

        proposed = tmp_ledger.get_theories_by_status(TheoryStatus.PROPOSED)
        assert len(proposed) == 3
        eliminated = tmp_ledger.get_theories_by_status(TheoryStatus.ELIMINATED)
        assert len(eliminated) == 1

    def test_get_by_family(self, tmp_ledger):
        for i, fam in enumerate(["grille", "grille", "running_key"]):
            t = TheoryRecord(
                core_claim=f"Claim {i} for {fam}", mechanism=f"Method {i}", family=fam,
            )
            tmp_ledger.upsert_theory(t)
        grille = tmp_ledger.get_theories_by_family("grille")
        assert len(grille) == 2

    def test_search_by_query(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        results = tmp_ledger.search_theories(query="KRYPTOS")
        assert len(results) >= 1
        assert results[0].hypothesis_id == sample_theory.hypothesis_id

    def test_search_by_min_score(self, tmp_ledger):
        t1 = TheoryRecord(core_claim="Low", mechanism="M", family="F", best_score=3.0)
        t2 = TheoryRecord(core_claim="High", mechanism="M", family="F", best_score=18.0)
        tmp_ledger.upsert_theory(t1)
        tmp_ledger.upsert_theory(t2)
        results = tmp_ledger.search_theories(min_score=10.0)
        assert len(results) == 1
        assert results[0].best_score == 18.0

    def test_count_by_status(self, tmp_ledger):
        for i, status in enumerate([TheoryStatus.PROPOSED, TheoryStatus.PROPOSED, TheoryStatus.ELIMINATED]):
            t = TheoryRecord(
                core_claim=f"Claim {i}", mechanism=f"M{i}", family="F",
                status=status,
            )
            tmp_ledger.upsert_theory(t)
        counts = tmp_ledger.count_by_status()
        assert counts["proposed"] == 2
        assert counts["eliminated"] == 1

    def test_count_by_family(self, tmp_ledger):
        for fam, status in [("A", TheoryStatus.PROPOSED), ("A", TheoryStatus.ELIMINATED), ("B", TheoryStatus.PROPOSED)]:
            t = TheoryRecord(
                core_claim=f"Claim {fam}-{status.value}", mechanism="M",
                family=fam, status=status,
            )
            tmp_ledger.upsert_theory(t)
        counts = tmp_ledger.count_by_family()
        assert counts["A"]["total"] == 2
        assert counts["A"]["eliminated"] == 1
        assert counts["B"]["total"] == 1

    def test_recent_outcomes(self, tmp_ledger):
        for i in range(5):
            t = TheoryRecord(
                core_claim=f"Claim {i}", mechanism="M", family="F",
                status=TheoryStatus.ELIMINATED,
            )
            tmp_ledger.upsert_theory(t)
        recent = tmp_ledger.recent_outcomes(limit=3)
        assert len(recent) == 3

    def test_experiment_crud(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        exp = ExperimentRecord(
            experiment_id="exp-test",
            hypothesis_id=sample_theory.hypothesis_id,
            worker_role="oracle",
            config={"method": "sweep"},
            result=WorkerContract(
                hypothesis_id=sample_theory.hypothesis_id,
                status=WorkerStatus.DISPROVED,
                score=2.0,
            ),
        )
        tmp_ledger.record_experiment(exp)
        exps = tmp_ledger.get_experiments_for_theory(sample_theory.hypothesis_id)
        assert len(exps) == 1
        assert exps[0].result.score == 2.0

    def test_anomaly_crud(self, tmp_ledger):
        a = AnomalyRecord(
            anomaly_id="test_anom",
            title="Test Anomaly",
            description="Something unusual",
            status=AnomalyStatus.OPEN,
        )
        tmp_ledger.upsert_anomaly(a)
        open_anoms = tmp_ledger.get_open_anomalies()
        assert len(open_anoms) == 1
        assert open_anoms[0].title == "Test Anomaly"

    def test_family_crud(self, tmp_ledger):
        f = FamilyRecord(
            family_id="test_fam",
            name="Test Family",
            status=FamilyStatus.ACTIVE,
            elimination_tier=4,
        )
        tmp_ledger.upsert_family(f)
        retrieved = tmp_ledger.get_family("test_fam")
        assert retrieved is not None
        assert retrieved.elimination_tier == 4

        active = tmp_ledger.get_active_families()
        assert len(active) == 1

    def test_evidence_crud(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        link = EvidenceLink(
            evidence_id="ev-test",
            hypothesis_id=sample_theory.hypothesis_id,
            evidence_type=EvidenceType.DISPROOF,
            content="No crib match",
        )
        tmp_ledger.add_evidence(link)
        evidence = tmp_ledger.get_evidence_for_theory(sample_theory.hypothesis_id)
        assert len(evidence) == 1
        assert evidence[0].evidence_type == EvidenceType.DISPROOF

    def test_controller_state_persistence(self, tmp_ledger):
        state = ControllerState(
            cycle_number=5,
            theories_proposed=20,
        )
        tmp_ledger.save_controller_state(state)
        loaded = tmp_ledger.load_controller_state()
        assert loaded.cycle_number == 5
        assert loaded.theories_proposed == 20

    def test_summary(self, tmp_ledger, sample_theory):
        tmp_ledger.upsert_theory(sample_theory)
        summary = tmp_ledger.summary()
        assert summary["total_theories"] == 1
        assert "generated_at" in summary

    def test_context_manager(self, tmp_path):
        db_path = tmp_path / "ctx_test.sqlite"
        with TheoryLedger(db_path) as ledger:
            t = TheoryRecord(core_claim="C", mechanism="M", family="F")
            ledger.upsert_theory(t)
        # Verify data persists after context manager exits
        ledger2 = TheoryLedger(db_path)
        assert ledger2.get_theory(t.hypothesis_id) is not None

    def test_refresh_family_stats(self, tmp_ledger):
        # Add a family
        f = FamilyRecord(family_id="test_fam", name="Test", status=FamilyStatus.ACTIVE)
        tmp_ledger.upsert_family(f)
        # Add theories
        for i, status in enumerate([TheoryStatus.PROPOSED, TheoryStatus.ELIMINATED]):
            t = TheoryRecord(
                core_claim=f"Claim {i}", mechanism="M", family="test_fam",
                status=status, best_score=float(i * 5),
            )
            tmp_ledger.upsert_theory(t)
        tmp_ledger.refresh_family_stats()
        updated = tmp_ledger.get_family("test_fam")
        assert updated.total_theories == 2
        assert updated.eliminated_theories == 1
        assert updated.best_score == 5.0

    def test_theory_with_critic_verdict(self, tmp_ledger):
        t = TheoryRecord(
            core_claim="C", mechanism="M", family="F",
            critic_verdict=CriticVerdict(
                decision=CriticDecision.APPROVE,
                confidence=0.9,
                reasons=["Good theory"],
            ),
        )
        tmp_ledger.upsert_theory(t)
        retrieved = tmp_ledger.get_theory(t.hypothesis_id)
        assert retrieved.critic_verdict is not None
        assert retrieved.critic_verdict.decision == CriticDecision.APPROVE
        assert retrieved.critic_verdict.confidence == 0.9


# ---------------------------------------------------------------------------
# Critic tests
# ---------------------------------------------------------------------------

class TestCritic:
    """Test the theory critic."""

    def test_reject_missing_fields(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord()  # empty
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED

    def test_reject_tier1_family(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            core_claim="K4 uses Caesar", mechanism="Shift by 13",
            family="caesar",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_ELIMINATED
        assert verdict.confidence == 1.0

    def test_reject_tier2_single_layer(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            core_claim="K4 is Vigenère", mechanism="Period-7 Vigenère",
            family="vigenere",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_ELIMINATED

    def test_allow_tier2_as_multi_layer(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            core_claim="K4 uses Vigenère + columnar",
            mechanism="Multi-layer: Vigenère then columnar transposition",
            family="vigenere",
            tags=["multi-layer"],
        )
        verdict = critic.evaluate(theory)
        # Should NOT be rejected because it's multi-layer
        assert verdict.decision != CriticDecision.REJECT_ELIMINATED

    def test_reject_duplicate(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        # Add a family so the theory doesn't get rejected for low info
        f = FamilyRecord(family_id="double_columnar", name="Double Columnar",
                         status=FamilyStatus.PARTIALLY_EXPLORED)
        tmp_ledger.upsert_family(f)
        # Add an existing tested theory
        existing = TheoryRecord(
            core_claim="K4 uses double columnar width 7",
            mechanism="Double columnar transposition width 7 and 14",
            family="double_columnar",
            status=TheoryStatus.ELIMINATED,
        )
        tmp_ledger.upsert_theory(existing)

        # Propose a near-identical theory (same words, minor addition)
        new_theory = TheoryRecord(
            core_claim="K4 uses double columnar width 7 reversed",
            mechanism="Double columnar transposition width 7 and 14",
            family="double_columnar",
        )
        verdict = critic.evaluate(new_theory)
        assert verdict.decision == CriticDecision.REJECT_DUPLICATE

    def test_reject_bifid_contradiction(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            core_claim="K4 uses Bifid cipher",
            mechanism="Bifid with Polybius square",
            family="novel",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_CONTRADICTED

    def test_reject_autokey_contradiction(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            core_claim="K4 uses autokey",
            mechanism="Autokey Vigenère with primer KRYPTOS",
            family="novel",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_CONTRADICTED

    def test_approve_novel_theory(self, tmp_ledger):
        """R3-2: cipher-family theories require a translatable dsl_spec to
        pass the Category-A/C check. Grille is in _SUPPORTED_KINDS after
        R3-0.5-2, so a minimal grille spec satisfies the requirement."""
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            core_claim="K4 uses a turning grille with compass-derived positions",
            mechanism="Turning grille where hole positions derive from compass bearings",
            family="grille",
            anomalies_exploited=["k2_coordinates"],
            kill_criteria=["No crib match for any rotation"],
            expected_signal="Crib score >= 18",
            dsl_spec={
                "hypothesis_id": "novel-grille",
                "pipeline": [{
                    "kind": "grille",
                    "alphabet": "AZ",
                    "params": [{
                        "name": "hole_mask",
                        "values": [list(range(97))],
                    }],
                }],
                "compute_budget_cpu_minutes": 1,
            },
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.APPROVE
        assert verdict.confidence >= 0.8

    def test_reject_width21_anomaly_misused_for_width10_theory(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="Lagged-recurrence keystream with width-10 structure",
            core_claim="The width-10 CT73 structure exposes a lagged recurrence.",
            mechanism="Exploit width 10 on CT73 while citing width21_vertical_bigrams.",
            family="finite_key_tape",
            anomalies_exploited=["width21_vertical_bigrams"],
            kill_criteria=["No recurrence survives full sweep."],
            expected_signal="Score > 10",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("width-10" in reason for reason in verdict.reasons)

    def test_reject_width21_anomaly_when_framed_only_in_ct73_space(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="Width-21-derived tape on CT73",
            core_claim="A CT73-only recurrence explains the anomaly.",
            mechanism="Use CT73 positions only; no full-ciphertext mapping specified.",
            family="finite_key_tape",
            anomalies_exploited=["width21_vertical_bigrams"],
            kill_criteria=["No width-21 support remains after test."],
            expected_signal="Score > 10",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("CT97" in reason or "full-ciphertext" in reason for reason in verdict.reasons)

    def test_reject_ambiguous_quasi_periodic_kill_criteria(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="Cardan grille selects tape-consumption positions from CT97",
            core_claim="A Cardan grille selects positions for tape advance.",
            mechanism="Map CT97 through a grille and score periodicity.",
            family="grille",
            anomalies_exploited=["width21_vertical_bigrams"],
            kill_criteria=["Reject unless the output is periodic or quasi-periodic in a 21-column grid layout."],
            expected_signal="Crib score >= 18",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("quasi-periodic" in reason for reason in verdict.reasons)

    def test_reject_kill_criteria_escape_hatch(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="Compass-walk keystream on KRYPTOS-keyed grid",
            core_claim="A compass walk on a keyed grid generates the tape.",
            mechanism="Walk the keyed grid with compass-derived steps.",
            family="geometry",
            anomalies_exploited=["aaa_compass_cipher"],
            kill_criteria=[
                "If the AP-adjacency explanation fails but the walk model survives with other grids, continue."
            ],
            expected_signal="A clean AP-adjacency explanation survives.",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("escape hatch" in reason for reason in verdict.reasons)

    def test_reject_coordinate_delta_direct_periodic_key_revival(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="Dual-coordinate-derived tape from 'He lied' discrepancy",
            core_claim="Use the coordinate delta digits as a direct Beaufort key on raw K4.",
            mechanism="Apply the false-vs-true discrepancy digits as a repeating Gronsfeld/Beaufort tape with no transposition.",
            family="k2_coords",
            anomalies_exploited=["aaa_coordinate_lie"],
            kill_criteria=["No direct-key score above noise."],
            expected_signal="Crib score >= 18",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("periodic-key" in reason for reason in verdict.reasons)

    def test_reject_vague_physical_reassembly_theory(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="Tape-and-cut worksheet rearrangement",
            core_claim="K4 was cut up and rearranged into chunks before encipherment.",
            mechanism="Use tape and cut-up strips to reorder the text.",
            family="procedural",
            kill_criteria=["No signal remains after trying a few rearrangements."],
            expected_signal="Crib score >= 18",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("boundary rule" in reason for reason in verdict.reasons)

    def test_reject_freeform_delimiter_reassembly_theory(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="W-delimiters mark where to cut and rearrange",
            core_claim="W delimiters mark cut points for chunk rearrangement.",
            mechanism="Treat the delimiters as cut markers, then reassemble strips.",
            family="procedural",
            kill_criteria=["No arrangement works."],
            expected_signal="Crib score >= 18",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("delimiter lore" in reason for reason in verdict.reasons)

    def test_reject_segmented_tape_duplicate_of_active_lane(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="Segmented tape bounded by self-encrypting positions",
            core_claim="The self-encrypting positions 32 and 73 mark segment boundaries in a segmented tape.",
            mechanism="Use the zero-key positions as self-encrypting positions to define segment boundaries.",
            family="key_tape",
            kill_criteria=["No segment assignment survives full sweep."],
            expected_signal="Crib score >= 18",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("e_segmented_tape_01" in reason for reason in verdict.reasons)

    def test_reject_anchored_alignment_that_pastes_known_cribs(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            title="Grille-permuted tape alignment: non-sequential tape-to-message mapping",
            core_claim="A grille alignment maps known tape values to the known crib positions.",
            mechanism="Use non-sequential tape-to-message mapping to align known key values with the known crib positions.",
            family="grille",
            kill_criteria=["No alignment produces a free-crib hit above noise."],
            expected_signal="24/24 anchored crib score",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
        assert any("manufacture 24/24" in reason for reason in verdict.reasons)

    def test_reject_low_information(self, tmp_ledger):
        # Add many theories to the family so it's "well explored"
        for i in range(10):
            t = TheoryRecord(
                core_claim=f"Grille variant {i}",
                mechanism=f"Grille variation {i}",
                family="grille",
                status=TheoryStatus.ELIMINATED,
            )
            tmp_ledger.upsert_theory(t)

        # Mark grille as exhausted
        f = FamilyRecord(
            family_id="grille", name="Grille", status=FamilyStatus.EXHAUSTED,
        )
        tmp_ledger.upsert_family(f)

        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            core_claim="K4 uses yet another grille",
            mechanism="Standard grille rotation",
            family="grille",
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_ELIMINATED

    def test_batch_evaluation(self, tmp_ledger):
        """R3-2: cipher-family 'novel' theory carries a minimal identity
        dsl_spec to satisfy the Category-A translatability check."""
        critic = TheoryCritic(tmp_ledger)
        # Add a family so "novel" doesn't get rejected for low info
        f = FamilyRecord(family_id="novel", name="Novel", status=FamilyStatus.ACTIVE,
                         total_theories=1)
        tmp_ledger.upsert_family(f)
        theories = [
            TheoryRecord(
                core_claim="Claim A", mechanism="M", family="novel",
                kill_criteria=["Test"], expected_signal="Score > 10",
                dsl_spec={
                    "hypothesis_id": "batch-A",
                    "pipeline": [{"kind": "identity", "alphabet": "AZ",
                                   "params": []}],
                    "compute_budget_cpu_minutes": 1,
                },
            ),
            TheoryRecord(core_claim="K4 is Caesar", mechanism="Shift",
                         family="caesar"),
        ]
        results = critic.evaluate_batch(theories)
        assert len(results) == 2
        assert results[0][1].decision == CriticDecision.APPROVE
        assert results[1][1].decision == CriticDecision.REJECT_ELIMINATED


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------

class TestRegistries:
    """Test bootstrap registries."""

    def test_bootstrap_families(self, tmp_ledger):
        count = bootstrap_families(tmp_ledger)
        assert count == len(KNOWN_FAMILIES)
        all_fams = tmp_ledger.get_all_families()
        assert len(all_fams) >= len(KNOWN_FAMILIES)

    def test_bootstrap_anomalies(self, tmp_ledger):
        count = bootstrap_anomalies(tmp_ledger)
        assert count == len(KNOWN_ANOMALIES)
        open_anoms = tmp_ledger.get_open_anomalies()
        assert len(open_anoms) >= 5  # most are open

    def test_bootstrap_idempotent(self, tmp_ledger):
        count1 = bootstrap_families(tmp_ledger)
        count2 = bootstrap_families(tmp_ledger)
        assert count1 > 0
        assert count2 == 0  # no new families on second run

    def test_bootstrap_all(self, tmp_ledger):
        result = bootstrap_all(tmp_ledger, project_root=_ROOT)
        assert result["families_added"] > 0
        assert result["anomalies_added"] > 0

    def test_bootstrap_all_withdraws_stale_queue_items(self, tmp_ledger, tmp_path):
        stale = TheoryRecord(
            hypothesis_id="62c962f23bfc",
            title="Investigate anomaly: retired palette surface",
            core_claim="test",
            mechanism="test",
            family="novel",
            status=TheoryStatus.APPROVED,
        )
        safe = TheoryRecord(
            hypothesis_id="475b5b87239f",
            title="Alexandria street grid overlay",
            core_claim="test2",
            mechanism="test2",
            family="crib_analysis",
            status=TheoryStatus.APPROVED,
        )
        tmp_ledger.upsert_theory(stale)
        tmp_ledger.upsert_theory(safe)

        project_root = tmp_path / "proj"
        project_root.mkdir()
        result = bootstrap_all(tmp_ledger, project_root=project_root)

        assert result["queue_reset_withdrawn"] == 1
        stale_after = tmp_ledger.get_theory("62c962f23bfc")
        safe_after = tmp_ledger.get_theory("475b5b87239f")
        assert stale_after is not None
        assert stale_after.status == TheoryStatus.WITHDRAWN
        assert "[controller-reset 2026-04-15]" in stale_after.notes
        assert safe_after is not None
        assert safe_after.status == TheoryStatus.APPROVED

    def test_admissible_prompt_anomalies_are_narrow_allowlist(self):
        assert ADMISSIBLE_PROMPT_ANOMALY_IDS == {
            "ct_perturbation",
            "aaa_coordinate_lie",
            "aaa_compass_cipher",
            "width21_vertical_bigrams",
            "w_delimiter_segments",
        }

    def test_canonical_anomaly_text_does_not_depend_on_site_alt_text(self):
        blob = "\n".join(
            f"{entry.get('title', '')}\n{entry.get('description', '')}\n{entry.get('source', '')}"
            for entry in KNOWN_ANOMALIES
        )
        lowered = blob.lower()
        assert "kryptosbot.com/archive" not in lowered
        assert "alt-text" not in lowered
        assert "working hypothesis from alt-text" not in lowered

    def test_coordinate_registry_text_does_not_promote_true_coordinate_to_fact(self):
        k2_constraint = next(c for c in STANDING_CONSTRAINTS if c["id"] == "k2_coordinates")
        coord_anom = next(a for a in KNOWN_ANOMALIES if a["anomaly_id"] == "aaa_coordinate_lie")

        text = " ".join([
            k2_constraint["fact"],
            k2_constraint["implication"],
            coord_anom["description"],
        ]).lower()
        assert "known only to sanborn" not in text
        assert "true coordinate" not in text

    def test_bootstrap_all_ingests_local_rerun_manifest(self, tmp_ledger, tmp_path):
        theory = TheoryRecord(
            hypothesis_id="1e7d16753a83",
            title="Systematic transcription-phase perturbation",
            core_claim="test",
            mechanism="test",
            family="archive_evidence",
            status=TheoryStatus.ELIMINATED,
        )
        tmp_ledger.upsert_theory(theory)

        project_root = tmp_path / "proj"
        rerun_dir = project_root / "results" / "reruns" / "20260415T000000Z"
        rerun_dir.mkdir(parents=True)
        (rerun_dir / "rerun_manifest.jsonl").write_text(
            json.dumps({
                "run_dir": str(rerun_dir),
                "target": "one_lie",
                "theory_ids": ["1e7d16753a83"],
                "script_paths": ["scripts/archive_evidence/e_aaa_one_lie_09.py"],
                "log_files": [str(rerun_dir / "one_lie.log")],
                "summary_lines": ["VERDICT: NO SIGNAL", "RESULT: bounded rerun complete"],
                "result_class": "elimination_rerun",
            }) + "\n",
            encoding="utf-8",
        )

        result = bootstrap_all(tmp_ledger, project_root=project_root)
        assert result["local_reruns_applied"] == 1

        refreshed = tmp_ledger.get_theory("1e7d16753a83")
        assert refreshed is not None
        assert any(exp_id.startswith("rerun-") for exp_id in refreshed.experiment_ids)
        assert "[local-rerun:one_lie]" in refreshed.notes

        exps = tmp_ledger.get_experiments_for_theory("1e7d16753a83")
        rerun_exps = [e for e in exps if e.worker_role == "local_rerun"]
        assert len(rerun_exps) == 1
        assert rerun_exps[0].script_id == "rerun:one_lie"

    def test_family_tiers_set_correctly(self, tmp_ledger):
        bootstrap_families(tmp_ledger)
        # Tier 1 families should be exhausted
        caesar = tmp_ledger.get_family("caesar")
        assert caesar is not None
        assert caesar.status == FamilyStatus.EXHAUSTED
        assert caesar.elimination_tier == 1

        # Tier 4 families should be active
        novel = tmp_ledger.get_family("novel")
        assert novel is not None
        assert novel.status == FamilyStatus.ACTIVE
        assert novel.elimination_tier == 4


# ---------------------------------------------------------------------------
# Worker contract parsing tests
# ---------------------------------------------------------------------------

class TestWorkerContractParsing:
    """Test controller's ability to parse worker output via contracts module."""

    def test_parse_valid_fenced_json(self):
        """Valid fenced JSON block is parsed correctly."""
        raw = '''Some narrative text...

```json
{
  "hypothesis_id": "abc123",
  "status": "disproved",
  "score": 3.0,
  "crib_score": 3,
  "bean_passed": false,
  "best_plaintext": "XYZABC...",
  "disproof_evidence": ["No crib match above noise floor"],
  "supporting_evidence": [],
  "next_action": "try different width",
  "family_generalization": "Width 7 is fully eliminated",
  "narrative_summary": "Tested all keyword variations..."
}
```

More text after.'''

        result = validate_worker_contract(raw, "abc123")
        assert result.is_valid
        assert result.value.status == WorkerStatus.DISPROVED
        # Score fields are independently recomputed from best_plaintext.
        # "XYZABC..." is not a CT97-shaped plaintext, so verification zeroes
        # the score fields and flags the discrepancy. Worker self-reports
        # are preserved in worker_self_report for audit. (See contracts.py
        # _verify_against_kernel; policy added 2026-04-13 after the
        # e2784dc9 BREAKTHROUGH-fabrication incident.)
        assert result.value.score == 0.0
        assert result.value.fields_overwritten is True
        assert result.value.worker_self_report["score"] == 3.0
        assert "97" in result.value.verification_error
        assert len(result.value.disproof_evidence) == 1

    def test_parse_minimal_valid_json(self):
        """Minimal valid JSON with just status passes."""
        raw = '```json\n{"status": "success"}\n```'
        result = validate_worker_contract(raw, "hyp1")
        assert result.is_valid
        assert result.value.status == WorkerStatus.SUCCESS


# ---------------------------------------------------------------------------
# Fail-closed contract enforcement tests
# ---------------------------------------------------------------------------

class TestFailClosedWorkerContracts:
    """
    Prove the controller fails closed on invalid worker output.

    These tests verify that prose-only output, malformed JSON,
    missing fields, and wrong types all result in explicit error
    outcomes — never heuristic inference from narrative text.
    """

    def test_prose_only_no_json_block(self):
        """Worker returns prose only → explicit parse failure, no inferred status."""
        raw = """
        I tested the hypothesis thoroughly. The approach was disproved
        conclusively — the best score was 18 and the crib match was promising.
        The result eliminates this entire family.
        """
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert "No fenced JSON block" in result.errors[0]
        # Critically: despite "disproved", "score was 18", "promising" in prose,
        # no status/score is inferred
        assert result.value is None

    def test_prose_with_unfenced_json(self):
        """Bare JSON in prose (no fences) is NOT extracted — prevents false positives."""
        raw = """
        The result was {"status": "disproved", "score": 22.0} but we need to
        verify this further before concluding.
        """
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert "No fenced JSON block" in result.errors[0]

    def test_malformed_json_in_fences(self):
        """Fenced block with invalid JSON → explicit parse error."""
        raw = '```json\n{status: disproved, score: 18}\n```'
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert any("JSON parse error" in e for e in result.errors)

    def test_missing_required_status_field(self):
        """JSON block missing 'status' → rejected."""
        raw = '```json\n{"score": 18.0, "crib_score": 15}\n```'
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert any("Missing required field" in e for e in result.errors)

    def test_invalid_status_enum_value(self):
        """Invalid status enum → rejected, not silently replaced."""
        raw = '```json\n{"status": "maybe_good"}\n```'
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert any("Invalid status" in e for e in result.errors)

    def test_wrong_type_score(self):
        """Non-numeric score → rejected."""
        raw = '```json\n{"status": "success", "score": "eighteen"}\n```'
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert any("'score' must be numeric" in e for e in result.errors)

    def test_wrong_type_bean_passed(self):
        """Non-boolean bean_passed → rejected."""
        raw = '```json\n{"status": "success", "bean_passed": "yes"}\n```'
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert any("'bean_passed' must be boolean" in e for e in result.errors)

    def test_wrong_type_disproof_evidence(self):
        """Non-list disproof_evidence → rejected."""
        raw = '```json\n{"status": "disproved", "disproof_evidence": "a string"}\n```'
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert any("'disproof_evidence' must be a list" in e for e in result.errors)

    def test_empty_output(self):
        """Empty worker output → parse failure."""
        result = validate_worker_contract("", "hyp1")
        assert not result.is_valid

    def test_hypothesis_id_override(self):
        """hypothesis_id from dispatch always overrides whatever the worker sent."""
        raw = '```json\n{"hypothesis_id": "worker_chose_this", "status": "success"}\n```'
        result = validate_worker_contract(raw, "controller_assigned_this")
        assert result.is_valid
        assert result.value.hypothesis_id == "controller_assigned_this"

    def test_valid_contract_passes_all_checks(self):
        """A well-formed contract passes validation end-to-end."""
        raw = '''narrative...
```json
{
  "status": "disproved",
  "score": 2.0,
  "crib_score": 2,
  "bean_passed": false,
  "best_plaintext": "XYZABC",
  "disproof_evidence": ["No match"],
  "supporting_evidence": [],
  "next_action": "try width 9",
  "family_generalization": "All widths < 10 eliminated",
  "narrative_summary": "Tested widths 5-8."
}
```'''
        result = validate_worker_contract(raw, "hyp1")
        assert result.is_valid
        assert result.value.status == WorkerStatus.DISPROVED
        # Score fields are kernel-recomputed; "XYZABC" is not CT97-shaped,
        # so the worker's self-reported score=2.0 is discarded and zeroed.
        # See contracts._verify_against_kernel.
        assert result.value.score == 0.0
        assert result.value.fields_overwritten is True
        assert result.value.worker_self_report["score"] == 2.0
        assert result.value.disproof_evidence == ["No match"]

    def test_raw_preserved_on_failure(self):
        """Raw text is always preserved for audit, even on parse failure."""
        raw = "This is just prose with no JSON at all."
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        assert result.raw == raw

    def test_raw_preserved_on_success(self):
        """Raw text is preserved for audit even on success."""
        raw = '```json\n{"status": "success"}\n```'
        result = validate_worker_contract(raw, "hyp1")
        assert result.is_valid
        assert result.raw == raw

    def test_no_score_extraction_from_prose(self):
        """Score mentioned in prose is never extracted."""
        raw = """
        The best score was 22 and crib score reached 18.
        This is clearly a breakthrough result.
        """
        result = validate_worker_contract(raw, "hyp1")
        assert not result.is_valid
        # Even though "22" and "18" appear in prose, no score is extracted
        assert result.value is None

    def test_multiple_json_blocks_uses_last(self):
        """When multiple fenced JSON blocks exist, the last one is used."""
        raw = '''
```json
{"status": "inconclusive", "score": 1.0}
```

After more work:

```json
{"status": "disproved", "score": 0.0}
```
'''
        result = validate_worker_contract(raw, "hyp1")
        assert result.is_valid
        assert result.value.status == WorkerStatus.DISPROVED


class TestFailClosedTheoryProposals:
    """
    Prove the theorist output parser fails closed on invalid proposals.
    """

    def test_prose_only_no_array(self):
        """Theorist returns prose → no theories, errors recorded."""
        raw = "I think K4 might use a grille cipher with compass bearings."
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 0
        assert len(report.errors) > 0

    def test_malformed_json_array(self):
        """Broken JSON array → no theories, error recorded."""
        # Has [ and ] but content between them is invalid JSON
        raw = '[{"core_claim": "test", "mechanism": "m", "family": "f"]'
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 0
        assert len(report.errors) > 0

    def test_item_missing_required_fields(self):
        """Item without core_claim/mechanism/family → rejected, not guessed."""
        raw = json.dumps([
            {"title": "My theory", "mechanism": "something"},
            {"core_claim": "Valid claim", "mechanism": "valid mech", "family": "novel"},
        ])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1
        assert len(report.invalid) == 1
        assert "Missing required fields" in report.invalid[0]["error"]

    def test_empty_required_fields_rejected(self):
        """Empty string in required field → rejected."""
        raw = json.dumps([
            {"core_claim": "", "mechanism": "m", "family": "f"},
        ])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 0
        assert len(report.invalid) == 1
        assert "Empty or non-string" in report.invalid[0]["error"]

    def test_wrong_type_in_list_field(self):
        """Non-list where list expected → rejected."""
        raw = json.dumps([
            {"core_claim": "c", "mechanism": "m", "family": "f", "tags": "not a list"},
        ])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 0
        assert len(report.invalid) == 1
        assert "'tags' must be a list" in report.invalid[0]["error"]

    def test_anomalies_exploited_accepts_prose_trail_after_canonical_id(self):
        """Policy revision (post-K4-cycle-1, 2026-04-21): the
        anomaly-id validator now normalizes to the first
        whitespace/paren-split token via _normalize_anomaly_id and
        then applies exact-match against the canonical set. A canonical
        id followed by a free-form commentary clause (the theorist's
        natural prose shape) is accepted; the commentary is ignored.
        This was the pre-K4-cycle-1 strict-rejection policy's cost —
        it dropped 4 of 5 theorist cycle-1 theories for cosmetic
        reasons. See K4_RUN_CYCLE1_DIAGNOSTIC.md."""
        raw = json.dumps([
            {
                "core_claim": "c",
                "mechanism": "m",
                "family": "novel",
                "anomalies_exploited": [
                    "width21_vertical_bigrams: same-column positions share identical shifts",
                ],
            },
        ])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1, (
            f"prose trail after canonical id should be accepted; "
            f"got invalid={report.invalid}"
        )

    def test_anomalies_exploited_rejects_non_canonical_first_token(self):
        """The normalizer strips commentary, NOT canonicality. If the
        first token isn't a canonical anomaly_id, the theory is still
        rejected — this is what guards against the theorist inventing
        new anomaly names."""
        raw = json.dumps([
            {
                "core_claim": "c",
                "mechanism": "m",
                "family": "novel",
                "anomalies_exploited": [
                    "some_made_up_anomaly: freeform description follows",
                ],
            },
        ])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 0
        assert len(report.invalid) == 1
        assert "canonical anomaly_ids" in report.invalid[0]["error"]

    def test_anomalies_exploited_accepts_canonical_ids(self):
        """Registered anomaly IDs remain admissible."""
        raw = json.dumps([
            {
                "core_claim": "c",
                "mechanism": "m",
                "family": "f",
                "anomalies_exploited": ["bean_minor_diffs", "width21_vertical_bigrams"],
            },
        ])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1
        assert len(report.invalid) == 0

    def test_w_delimiter_segments_critic_path_accepts_canonical_anomaly_id(self, tmp_ledger):
        critic = TheoryCritic(tmp_ledger)
        theory = TheoryRecord(
            hypothesis_id="wdelim-ok-1",
            title="W-bounded strip reassembly",
            core_claim="The five carved W positions are enciphered delimiters that bound six segments.",
            mechanism="Apply a fixed six-segment route budget anchored to the W boundaries while preserving CT97 crib positions.",
            family="procedural",
            anomalies_exploited=["w_delimiter_segments"],
            kill_criteria=["No survivor above noise under the finite route budget."],
        )

        verdict = critic.evaluate(theory)
        assert not any(
            "Delimiter-driven reassembly theories must cite an explicit finite boundary rule"
            in reason
            for reason in verdict.reasons
        )

    def test_non_dict_item_in_array(self):
        """Array containing non-objects is not selected as a theory array.
        The extractor requires the first element to be a dict (object)."""
        raw = '["just a string", 42]'
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 0
        assert len(report.errors) > 0  # "No JSON array found"

    def test_valid_proposals_pass(self):
        """Well-formed proposals pass validation."""
        raw = json.dumps([
            {
                "title": "Test theory",
                "core_claim": "K4 uses grille",
                "mechanism": "Turning grille with compass",
                "family": "grille",
                "kill_criteria": ["No crib match"],
                "expected_signal": "Score >= 18",
            },
        ])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1
        assert report.valid[0].core_claim == "K4 uses grille"
        assert len(report.invalid) == 0

    def test_mixed_valid_and_invalid(self):
        """Batch with mix of valid/invalid: valid pass, invalid recorded."""
        raw = json.dumps([
            {"core_claim": "Good one", "mechanism": "m1", "family": "f1"},
            {"title": "Bad one — missing fields"},
            {"core_claim": "Another good", "mechanism": "m2", "family": "f2"},
        ])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 2
        assert len(report.invalid) == 1

    def test_embedded_json_in_prose(self):
        """JSON array embedded in narrative prose still extracts."""
        raw = """Here are my proposals:
[
  {"core_claim": "Test", "mechanism": "M", "family": "F"}
]
That's my suggestion."""
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1
