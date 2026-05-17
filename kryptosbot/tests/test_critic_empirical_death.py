"""Tests for TheoryCritic._check_family_empirically_dead.

Eight branches: dead/healthy x bypass-eligible/ineligible x normal/shadow.
"""
from __future__ import annotations

import pytest

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


# ── Shared pytest fixtures consumed by Task-15 KB-injection tests ─────────
# live in ``kryptosbot/tests/conftest.py`` (promoted there in Task 23 so
# the Phase 2 acceptance suite can reuse them without duplication):
#   - dead_encoding_yield
#   - encoding_theory
#   - encoding_theory_with_novel_subfamily_and_signature
#
# The pre-existing class-style tests use the helper functions defined
# below (_verdict, _theory, _critic_with_indices); those stay local
# because they parameterize per-test setup.

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
    """Minimal ledger stub that the critic uses only via attribute access.

    The Task-15 KB-injection tests route through ``TheoryCritic.evaluate``
    (not just ``_check_family_empirically_dead``), which queries the
    ledger for similar theories and prior override justifications. Both
    paths return empty for this stub — sufficient because the tests only
    care about the empirical-death gate's KB-query path.
    """
    def get_family(self, *_): return None
    def get_theories_by_family(self, *_): return []
    def get_theories_by_status(self, *_): return []


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

    def test_suggested_mechanisms_empty_when_kb_db_missing(self, tmp_path):
        # Phase 2 renamed the field to suggested_mechanism_records and
        # Task 15 lands the populate path. When the KB DB does not exist,
        # ``query_suggestions`` returns ``()`` and the gate emits an empty
        # tuple with ``suggestion_source="none"`` — the historical
        # Phase-1 shape preserved as the missing-DB fallback.
        c = _critic_with_indices(
            yield_idx={"encoding": _verdict("encoding")},
            prior_subfams={"encoding": frozenset({"vigenere"})},
            prior_sigs={"encoding": frozenset({"sig_known"})},
        )
        c._kb_db_path = str(tmp_path / "no_such_db.sqlite")
        c._kb_cache.clear()
        t = _theory(family="encoding", subfamily="vigenere")
        verdict = c._check_family_empirically_dead(t, "encoding")
        assert verdict.empirical_death.suggested_mechanism_records == ()
        assert verdict.empirical_death.suggestion_source == "none"


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
                status=TheoryStatus.ELIMINATED,
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


class TestBenchModeBehavior:
    """Phase 1 bench-mode contract: `_check_family_empirically_dead` stays
    inert because `_assess_landscape_bench()` (the bench-mode landscape path)
    does NOT populate `_cycle_yield_index`. The controller injects empty
    dicts via `getattr(..., {})`, so every family lookup returns None and
    the gate returns None.

    This is the documented Phase-1 bench-mode behavior. The bypass is
    achieved by absent attributes defaulting to empty, not by an explicit
    `if self.bench_mode` guard. Final-review note: this is safe today
    because K4Bench ledgers are fresh per challenge, but Phase 2 should
    add either an explicit guard or expand this test if bench ledgers
    ever persist across sessions.
    """

    def test_empty_yield_index_returns_none_regardless_of_family(self):
        """An empirically-dead family in a different (real-K4) context
        would reject, but with an empty yield_index every call falls
        through to None. This pins the bench-mode behavior."""
        c = _critic_with_indices(
            yield_idx={},
            prior_subfams={},
            prior_sigs={},
        )
        t = _theory(family="encoding", subfamily="vigenere")
        assert c._check_family_empirically_dead(t, "encoding") is None

    def test_bench_mode_inert_even_when_priors_present(self):
        """Even if a stale prior-subfamily index leaks through to the
        critic, an empty yield_index means no family is classified
        empirically_dead, so no rejection fires."""
        c = _critic_with_indices(
            yield_idx={},  # bench mode never populates this
            prior_subfams={"encoding": frozenset({"vigenere"})},  # leak simulation
            prior_sigs={"encoding": frozenset({"sig"})},
        )
        t = _theory(family="encoding", subfamily="vigenere")
        assert c._check_family_empirically_dead(t, "encoding") is None


# ── Task 15: KB query + per-cycle cache ─────────────────────────────────────

from pathlib import Path

from kryptosbot.kb_injection import (
    KB_SIGNATURE_SCHEMA_VERSION,
    CipherDiscoverySuggestion,
)


PHASE2_FIXTURE_DB = (
    Path(__file__).resolve().parent / "fixtures" / "cipher_discovery_phase2_fixture.sqlite"
)


class TestKBSuggestionInjection:
    def _critic_under_test(
        self,
        *,
        yield_index,
        prior_subfamilies=None,
        prior_signatures=None,
        blocked_families_in_cycle=None,
        static_exhaustion_blocklist=None,
    ):
        from kryptosbot.critic import TheoryCritic
        critic = TheoryCritic(
            ledger=FakeLedger(),
            yield_index=yield_index,
            prior_subfamilies=prior_subfamilies or {},
            prior_signatures=prior_signatures or {},
            blocked_families_in_cycle=blocked_families_in_cycle or frozenset(),
            static_exhaustion_blocklist=static_exhaustion_blocklist or frozenset(),
            kb_db_path=str(PHASE2_FIXTURE_DB),
        )
        return critic

    def test_kb_query_populates_suggestions_on_empirical_death(
        self, dead_encoding_yield, encoding_theory
    ):
        """Spec acceptance #3: REJECT_EMPIRICALLY_DEAD on encoding yields
        non-empty suggested_mechanism_records when fixture KB has at least
        one record mapped to a non-blocked ledger family with unseen sig."""
        # Seed priors so the bypass cannot fire and the gate must reject.
        from kryptosbot.family_yield import mechanism_signature_for_theory
        sig = mechanism_signature_for_theory({
            "family": "encoding", "subfamily": "vigenere",
            "mechanism": "m", "dsl_spec": None,
            "anomalies_exploited": [], "clue_anchors_used": [],
            "novelty_basis": "", "minimal_test_spec": {},
        })
        critic = self._critic_under_test(
            yield_index={"encoding": dead_encoding_yield},
            prior_subfamilies={"encoding": frozenset({"vigenere"})},
            prior_signatures={"encoding": frozenset({sig})},
            blocked_families_in_cycle=frozenset({"encoding"}),
        )
        verdict = critic.evaluate(encoding_theory)
        assert verdict.decision.value == "reject_empirically_dead"
        ed = verdict.empirical_death
        assert ed is not None
        assert ed.suggestion_source == "cipher_discovery_kb"
        assert len(ed.suggested_mechanism_records) >= 1
        for s in ed.suggested_mechanism_records:
            assert isinstance(s, CipherDiscoverySuggestion)
            assert s.source_verdict == "allow"
            assert s.signature_schema_version == KB_SIGNATURE_SCHEMA_VERSION

    def test_cache_hit_on_repeat_family_signature(
        self, dead_encoding_yield, encoding_theory
    ):
        from kryptosbot.family_yield import mechanism_signature_for_theory
        sig = mechanism_signature_for_theory({
            "family": "encoding", "subfamily": "vigenere",
            "mechanism": "m", "dsl_spec": None,
            "anomalies_exploited": [], "clue_anchors_used": [],
            "novelty_basis": "", "minimal_test_spec": {},
        })
        critic = self._critic_under_test(
            yield_index={"encoding": dead_encoding_yield},
            prior_subfamilies={"encoding": frozenset({"vigenere"})},
            prior_signatures={"encoding": frozenset({sig})},
            blocked_families_in_cycle=frozenset({"encoding"}),
        )
        # First call populates cache; second call must use cache (no
        # re-query). We assert by patching iter_kb_records to fail the
        # second time and confirming we still get suggestions.
        v1 = critic.evaluate(encoding_theory)
        assert v1.empirical_death is not None
        import kryptosbot.kb_injection as kbi

        def _boom(*a, **kw):
            raise RuntimeError("must not re-query")

        orig = kbi.iter_kb_records
        try:
            kbi.iter_kb_records = _boom
            # SAME theory => same (family, signature) cache key.
            v2 = critic.evaluate(encoding_theory)
        finally:
            kbi.iter_kb_records = orig
        assert v2.empirical_death is not None
        assert len(v2.empirical_death.suggested_mechanism_records) == len(
            v1.empirical_death.suggested_mechanism_records
        )

    def test_no_kb_query_when_bypass_satisfied(
        self, dead_encoding_yield, encoding_theory_with_novel_subfamily_and_signature
    ):
        critic = self._critic_under_test(
            yield_index={"encoding": dead_encoding_yield},
            # Empty prior_subfamilies / prior_signatures — bypass should fire.
            blocked_families_in_cycle=frozenset({"encoding"}),
        )
        verdict = critic.evaluate(encoding_theory_with_novel_subfamily_and_signature)
        # Bypass means the empirical-death gate falls through; the gate's
        # KB query does not run; downstream checks may still reject for
        # other reasons, but if they pass, no empirical_death payload.
        if verdict.decision.value == "reject_empirically_dead":
            raise AssertionError("Bypass should have prevented empirical-death rejection")

    def test_kb_db_missing_falls_back_to_none_source(
        self, dead_encoding_yield, encoding_theory, tmp_path
    ):
        from kryptosbot.family_yield import mechanism_signature_for_theory
        sig = mechanism_signature_for_theory({
            "family": "encoding", "subfamily": "vigenere",
            "mechanism": "m", "dsl_spec": None,
            "anomalies_exploited": [], "clue_anchors_used": [],
            "novelty_basis": "", "minimal_test_spec": {},
        })
        missing_path = tmp_path / "no_such_db.sqlite"
        critic = self._critic_under_test(
            yield_index={"encoding": dead_encoding_yield},
            prior_subfamilies={"encoding": frozenset({"vigenere"})},
            prior_signatures={"encoding": frozenset({sig})},
            blocked_families_in_cycle=frozenset({"encoding"}),
        )
        critic._kb_db_path = str(missing_path)
        # Clear any cache populated by a previous suite run.
        critic._kb_cache.clear()
        verdict = critic.evaluate(encoding_theory)
        ed = verdict.empirical_death
        assert ed is not None
        assert ed.suggestion_source == "none"
        assert ed.suggested_mechanism_records == ()
