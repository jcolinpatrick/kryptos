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
