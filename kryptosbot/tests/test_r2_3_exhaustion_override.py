"""R2-3 verification: exhaustion-overlap override + critic duplicate guard.

Phase 8 observed the Phase-4 substring-match admissibility heuristic
rejecting one-third of legitimate procedural proposals. R2-3 introduces
an explicit override knob:

  - HypothesisSpec.override_exhaustion: bool = False
  - HypothesisSpec.override_justification: str = ""

Validation rule: override_exhaustion=True without a non-empty
justification fails at spec.validate(). Dispatcher demotes
exhaustion-overlap from hard rejection to a logged warning when the
override is present. The critic rejects theories whose
override_justification (first 100 chars, tokenized) has Jaccard ≥ 0.7
similarity to a previously-tested theory's justification — preventing
the override from becoming a bypass for re-running noise.

JobResult records the justification + the overridden entries so the
ledger preserves WHY a spec was run anyway.
"""
from __future__ import annotations

import pytest
import tempfile
from pathlib import Path

from kryptosbot.critic import TheoryCritic, SIMILARITY_THRESHOLD
from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec, ParamRange
from kryptosbot.job_dispatcher import (
    JobResult,
    check_admissibility,
    execute,
)
from kryptosbot.models import (
    CriticDecision,
    CriticVerdict,
    TheoryRecord,
    TheoryStatus,
)
from kryptosbot.theory_ledger import TheoryLedger


# ─── HypothesisSpec field + validation ───────────────────────────────────────

class TestHypothesisSpecOverrideFields:
    def test_defaults_are_false_and_empty(self):
        spec = HypothesisSpec(hypothesis_id="T-default")
        assert spec.override_exhaustion is False
        assert spec.override_justification == ""

    def test_override_without_justification_fails_validate(self):
        spec = HypothesisSpec(
            hypothesis_id="T-bad",
            override_exhaustion=True,
            override_justification="",
        )
        errors = spec.validate()
        assert any("override_justification" in e for e in errors), errors

    def test_whitespace_justification_also_fails(self):
        spec = HypothesisSpec(
            hypothesis_id="T-whitespace",
            override_exhaustion=True,
            override_justification="   \n\t  ",
        )
        errors = spec.validate()
        assert any("override_justification" in e for e in errors), errors

    def test_override_with_justification_validates(self):
        spec = HypothesisSpec(
            hypothesis_id="T-good",
            override_exhaustion=True,
            override_justification=(
                "Phase 8 rejection was substring-match on 'beaufort'; "
                "this spec uses a different assumption bundle."
            ),
        )
        errors = spec.validate()
        # Other errors are fine (e.g. about crib_alignment); we just want
        # NO override-related error.
        assert not any("override_justification" in e for e in errors), errors

    def test_justification_without_override_is_benign(self):
        """Non-empty justification without override=True is harmless
        (records rationale for posterity). Only the override path
        requires it."""
        spec = HypothesisSpec(
            hypothesis_id="T-just-note",
            override_exhaustion=False,
            override_justification="Noted for audit; no override claimed.",
        )
        errors = spec.validate()
        assert not any("override_justification" in e for e in errors)

    def test_round_trip_preserves_override_fields(self):
        spec = HypothesisSpec(
            hypothesis_id="T-roundtrip",
            override_exhaustion=True,
            override_justification="Because reasons explained in detail.",
        )
        reconstructed = HypothesisSpec.from_dict(spec.to_dict())
        assert reconstructed.override_exhaustion is True
        assert reconstructed.override_justification == spec.override_justification


# ─── Dispatcher admissibility behaviour ──────────────────────────────────────

class TestAdmissibilityHonorsOverride:
    def _make_exhausted_log_with_columnar(self) -> dict[str, dict[str, object]]:
        """A fake exhaustion log containing a columnar entry that the
        default admissibility check would flag as overlap."""
        return {
            "fake_columnar_exhausted": {
                "family": "columnar_single",
                "status": "exhausted",
                "description": "Phase 7 columnar sweep",
            }
        }

    def _make_columnar_spec(self, **extra) -> HypothesisSpec:
        return HypothesisSpec(
            hypothesis_id="T-overrider",
            pipeline=[
                CipherLayer(
                    kind="columnar",
                    params=[
                        ParamRange(name="width", values=[5]),
                        ParamRange(name="col_order", values=[[0, 1, 2, 3, 4]]),
                    ],
                ),
            ],
            **extra,
        )

    def test_overlap_rejects_without_override(self):
        spec = self._make_columnar_spec()
        admissible, reasons = check_admissibility(
            spec, exhaustion_log=self._make_exhausted_log_with_columnar(),
        )
        assert not admissible
        assert any("exhaustion overlap" in r for r in reasons)
        # The message must also advertise the override to the operator.
        assert any("override_exhaustion" in r for r in reasons)

    def test_overlap_passes_with_override(self):
        spec = self._make_columnar_spec(
            override_exhaustion=True,
            override_justification=(
                "This spec exercises columnar as the INNER layer of a "
                "two-layer composition; the Phase 7 elimination was "
                "columnar-single. Different assumption bundle, different "
                "elimination burden."
            ),
        )
        admissible, reasons = check_admissibility(
            spec, exhaustion_log=self._make_exhausted_log_with_columnar(),
        )
        assert admissible, f"override should have demoted overlap to warning; reasons={reasons}"
        assert not any("exhaustion overlap" in r for r in reasons)

    def test_executed_jobresult_carries_justification(self):
        """When override fires during execute(), the JobResult preserves
        the justification + the overlap entries."""
        spec = self._make_columnar_spec(
            override_exhaustion=True,
            override_justification=(
                "Two-layer outer columnar; Phase 7 elimination was "
                "single-layer only."
            ),
        )
        result = execute(
            spec,
            exhaustion_log=self._make_exhausted_log_with_columnar(),
            parallel=False,
            artifact_root=Path(tempfile.mkdtemp(prefix="r2_3_test_")),
        )
        assert result.admissibility_verdict == "ok"
        assert result.override_justification == spec.override_justification
        assert "fake_columnar_exhausted" in result.override_exhaustion_overlap

    def test_executed_jobresult_without_override_omits_justification(self):
        """If override is not invoked, JobResult has empty justification
        + empty override_exhaustion_overlap."""
        spec = self._make_columnar_spec()  # no override, no overlap
        result = execute(
            spec,
            exhaustion_log={},
            parallel=False,
            artifact_root=Path(tempfile.mkdtemp(prefix="r2_3_test_")),
        )
        assert result.admissibility_verdict == "ok"
        assert result.override_justification == ""
        assert result.override_exhaustion_overlap == []


# ─── Critic duplicate-justification guard ────────────────────────────────────

class TestCriticOverrideDuplicateGuard:
    """R2-3 adds _check_override_duplicate. The critic rejects theories
    whose override_justification duplicates a prior tested theory's
    justification (Jaccard ≥ SIMILARITY_THRESHOLD on first 100 chars)."""

    def _prepare_ledger_with_prior(
        self, justification: str, status: TheoryStatus = TheoryStatus.ELIMINATED,
    ) -> TheoryLedger:
        tmp_db = tempfile.NamedTemporaryFile(
            suffix=".sqlite", delete=False,
        ).name
        ledger = TheoryLedger(tmp_db)
        prior = TheoryRecord(
            hypothesis_id="T-prior",
            title="Prior theory",
            core_claim="Some mechanism",
            mechanism="Some detail",
            family="columnar_double",
            status=TheoryStatus.APPROVED,
            override_justification=justification,
        )
        ledger.upsert_theory(prior)
        # Upsert again with a COMPLETED/ELIMINATED state so the critic
        # treats it as "already tested." Outcome-state upsert requires an
        # experiment trail, so insert one.
        from kryptosbot.models import ExperimentRecord, WorkerStatus
        from kryptosbot.contracts import WorkerContract
        exp = ExperimentRecord(
            experiment_id="E-prior-1",
            hypothesis_id="T-prior",
            started_at="2026-04-21T00:00:00Z",
            completed_at="2026-04-21T00:01:00Z",
            worker_role="test",
            config={},
            result=WorkerContract(status=WorkerStatus.DISPROVED),
            script_id="",
        )
        ledger.record_experiment(exp)
        prior.experiment_ids = ["E-prior-1"]
        prior.status = status
        ledger.upsert_theory(prior)
        return ledger

    def test_no_override_no_collision_check(self):
        """Theories without override_justification never trigger the
        duplicate check."""
        ledger = self._prepare_ledger_with_prior(
            "Prior override: different approach to columnar elimination",
        )
        critic = TheoryCritic(ledger)
        # Access the helper directly for targeted coverage.
        theory = TheoryRecord(
            hypothesis_id="T-new",
            override_justification="",
        )
        assert critic._check_override_duplicate(theory) is None

    def test_distinct_justification_passes(self):
        ledger = self._prepare_ledger_with_prior(
            "Prior override: columnar variant with alternate key "
            "derivation from Bean-linear residue classes.",
        )
        critic = TheoryCritic(ledger)
        theory = TheoryRecord(
            hypothesis_id="T-new",
            family="columnar_double",
            override_justification=(
                "My override: investigating the mod-7 placement rule "
                "on null positions, entirely unrelated to prior work."
            ),
        )
        # Tokenized first-100-char Jaccard should be well below 0.7.
        assert critic._check_override_duplicate(theory) is None

    def test_near_identical_justification_is_rejected(self):
        prior_just = (
            "Phase 8 rejection was advisory exhaustion-overlap on "
            "substring match; these are multi-layer or procedural "
            "compositions not covered by single-layer exhaustion entries."
        )
        ledger = self._prepare_ledger_with_prior(prior_just)
        critic = TheoryCritic(ledger)
        theory = TheoryRecord(
            hypothesis_id="T-launder",
            family="columnar_double",
            override_justification=prior_just,  # verbatim copy
        )
        result = critic._check_override_duplicate(theory)
        assert result is not None
        prior_id, prior_justification = result
        assert prior_id == "T-prior"
        assert prior_justification == prior_just

    def test_critic_evaluate_rejects_override_duplicate(self):
        """The full critic.evaluate() path surfaces REJECT_DUPLICATE
        when an override_justification collision is detected."""
        prior_just = (
            "Phase 8 rejection was substring match on beaufort; my "
            "spec uses a different assumption bundle with procedural "
            "null mask inference."
        )
        ledger = self._prepare_ledger_with_prior(prior_just)
        critic = TheoryCritic(ledger)
        # A full theory record with the required 'complete' fields so
        # earlier critic checks don't short-circuit.
        theory = TheoryRecord(
            hypothesis_id="T-dup-override",
            title="Attempted rerun of prior noise under override",
            core_claim="A novel procedural null mask approach",
            mechanism="Some concrete multi-step decryption procedure",
            family="columnar_double",
            override_justification=prior_just,
        )
        verdict = critic.evaluate(theory)
        assert verdict.decision == CriticDecision.REJECT_DUPLICATE
        assert any("override_justification" in r for r in verdict.reasons)
