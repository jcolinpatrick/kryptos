"""End-to-end acceptance test for Phase 2 yield-feedback.

Fixture-backed; does NOT depend on db/cipher_discovery.sqlite. The live
KB is exercised separately by test_phase2_live_kb_smoke.py.

Spec acceptance criteria #1, #3, #4, #5, #6, #9, #10.

Fixtures (``dead_encoding_yield``, ``encoding_theory``) are provided by
``kryptosbot/tests/conftest.py`` -- promoted there in Task 23 so this
file and ``test_critic_empirical_death.py`` share the same surface.
"""
from __future__ import annotations

from pathlib import Path

import pytest


FIXTURE_DB = (
    Path(__file__).resolve().parent / "fixtures" / "cipher_discovery_phase2_fixture.sqlite"
)


# A minimal ledger stub. The acceptance tests only exercise the
# empirical-death gate inside TheoryCritic.evaluate(); that path queries
# the ledger for similar theories / prior overrides, which we want to
# return empty so the gate is the only signal under test. We deliberately
# reproduce a tiny stub here rather than import the one from
# test_critic_empirical_death so the acceptance suite is independent of
# that file's internal helpers (which are test-private).
class _FakeLedger:
    def get_family(self, *_): return None
    def get_theories_by_family(self, *_): return []
    def get_theories_by_status(self, *_): return []


def _seed_priors_for_encoding(theory) -> tuple[dict, dict]:
    """Compute prior_subfamilies / prior_signatures that make the
    bypass impossible for ``encoding_theory``. Returns the (subs, sigs)
    dicts ready to hand to TheoryCritic.
    """
    from kryptosbot.family_yield import mechanism_signature_for_theory
    sig = mechanism_signature_for_theory({
        "family": theory.family, "subfamily": theory.subfamily,
        "mechanism": theory.mechanism, "dsl_spec": theory.dsl_spec,
        "anomalies_exploited": [], "clue_anchors_used": [],
        "novelty_basis": "", "minimal_test_spec": {},
    })
    return (
        {theory.family: frozenset({theory.subfamily})},
        {theory.family: frozenset({sig})},
    )


class TestPhase2AcceptanceCribPaste:
    """Acceptance #1: a crib-paste worker self-report must NOT survive
    kernel verification. The detector zeroes the score fields, stamps an
    artifact_class, snapshots the pre-detector kernel-verified values,
    and forces WorkerStatus.INCONCLUSIVE.
    """

    def test_paste_pt_is_zeroed_and_inconclusive(self):
        from kryptosbot.contracts import _verify_against_kernel
        from kryptosbot.models import WorkerContract, WorkerStatus

        pt = ["X"] * 97
        for i, ch in enumerate("EASTNORTHEAST"):
            pt[21 + i] = ch
        for i, ch in enumerate("BERLINCLOCK"):
            pt[63 + i] = ch
        pt = "".join(pt)

        c = WorkerContract(
            hypothesis_id="t",
            best_plaintext=pt,
            crib_score=24,
            bean_passed=True,
            score=24.0,
            status=WorkerStatus.SUCCESS,
        )
        _verify_against_kernel(c)

        assert c.crib_score == 0
        assert c.status == WorkerStatus.INCONCLUSIVE
        assert c.raw_artifacts is not None
        assert c.raw_artifacts.get("artifact_class") == "crib_paste"
        snap = c.raw_artifacts.get("kernel_verified_before_artifact_filter")
        assert snap is not None
        assert snap.get("crib_score") == 24


class TestPhase2AcceptanceKBInjection:
    """Acceptance #3: when REJECT_EMPIRICALLY_DEAD fires, the empirical
    death payload must carry KB-derived suggestion records sourced from
    the fixture DB.
    """

    def test_empirical_death_rejection_populates_suggestions(
        self, dead_encoding_yield, encoding_theory
    ):
        from kryptosbot.critic import TheoryCritic

        prior_subs, prior_sigs = _seed_priors_for_encoding(encoding_theory)
        critic = TheoryCritic(
            ledger=_FakeLedger(),
            yield_index={"encoding": dead_encoding_yield},
            prior_subfamilies=prior_subs,
            prior_signatures=prior_sigs,
            blocked_families_in_cycle=frozenset({"encoding"}),
            kb_db_path=str(FIXTURE_DB),
        )
        verdict = critic.evaluate(encoding_theory)

        assert verdict.decision.value == "reject_empirically_dead"
        ed = verdict.empirical_death
        assert ed is not None
        assert ed.suggestion_source == "cipher_discovery_kb"
        assert len(ed.suggested_mechanism_records) >= 1


class TestPhase2AcceptanceFullCycle:
    """Acceptance #4 + #9: an all-rejected cycle must write the escape
    summary (status + suggestions) into ControllerState BEFORE the
    early-continue, and the next cycle's landscape renderer must
    expose those suggestions to the theorist prompt.
    """

    def test_all_rejected_cycle_writes_summary_and_next_landscape_renders(
        self, dead_encoding_yield, encoding_theory
    ):
        from kryptosbot.controller import ResearchController
        from kryptosbot.critic import TheoryCritic
        from kryptosbot.models import ControllerState

        c = ResearchController.__new__(ResearchController)
        c.state = ControllerState(cycle_number=1)
        c._cycle_empirical_dead_rejections = []
        c._kb_db_missing_logged_this_cycle = False

        prior_subs, prior_sigs = _seed_priors_for_encoding(encoding_theory)
        critic = TheoryCritic(
            ledger=_FakeLedger(),
            yield_index={"encoding": dead_encoding_yield},
            prior_subfamilies=prior_subs,
            prior_signatures=prior_sigs,
            blocked_families_in_cycle=frozenset({"encoding"}),
            kb_db_path=str(FIXTURE_DB),
        )
        verdict = critic.evaluate(encoding_theory)
        assert verdict.empirical_death is not None
        c._cycle_empirical_dead_rejections.append(verdict.empirical_death)

        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=["encoding"],
            rejections=c._cycle_empirical_dead_rejections,
        )

        # Storage assertions (acceptance #4 -- summary persisted).
        assert c.state.last_escape_status == "needed_but_unavailable"
        assert c.state.last_escape_suggestions
        # Storage entries are dicts (CipherDiscoverySuggestion.to_dict()).
        first = c.state.last_escape_suggestions[0]
        assert isinstance(first, dict)
        assert "canonical_name" in first

        # Render assertion (acceptance #9 -- the next cycle's landscape
        # surfaces them in the theorist-prompt block).
        rendered = c._render_escape_candidates(
            status=c.state.last_escape_status,
            suggestions=c.state.last_escape_suggestions,
        )
        assert rendered
        assert "ESCAPE CANDIDATES" in rendered


class TestPhase2AcceptanceFailOpen:
    """Acceptance #8: a missing KB DB path must NOT crash the pipeline.
    The empirical-death payload still fires, but with empty suggestion
    records and ``suggestion_source='none'``.
    """

    def test_missing_kb_db_does_not_break_pipeline(
        self, dead_encoding_yield, encoding_theory, tmp_path
    ):
        from kryptosbot.critic import TheoryCritic

        prior_subs, prior_sigs = _seed_priors_for_encoding(encoding_theory)
        critic = TheoryCritic(
            ledger=_FakeLedger(),
            yield_index={"encoding": dead_encoding_yield},
            prior_subfamilies=prior_subs,
            prior_signatures=prior_sigs,
            blocked_families_in_cycle=frozenset({"encoding"}),
            kb_db_path=str(tmp_path / "missing.sqlite"),
        )
        verdict = critic.evaluate(encoding_theory)

        assert verdict.decision.value == "reject_empirically_dead"
        ed = verdict.empirical_death
        assert ed is not None
        assert ed.suggestion_source == "none"
        assert ed.suggested_mechanism_records == ()
