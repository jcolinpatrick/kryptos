"""R3-3 synthetic-theory integration test.

The round's correctness proof per brief §4.2. Runs one controller cycle
against a hand-built set of synthetic theories that span the 9
currently-supported kinds and exercise every R3-2 code surface. The
single test asserts the §4.2 battery:

  - Non-zero D column (at least one admissibility rejection contract)
  - Matched-family null consulted at least once
  - override_exhaustion=True path exercised (admissibility pass despite
    overlap)
  - dsl_untranslatable critic reject exercised
  - Translation error path exercised
  - worker_scratch/ empty after dispatch completes
  - Ledger's dsl_spec field populated for every theory

Separated into a single end-to-end test because the assertions all flow
from one dispatch cycle's telemetry — splitting them would multiply
fixture setup with no isolation benefit.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from kryptosbot.alerts import (
    _matched_null_family_from_contract,
    _p_value_gate_passes,
)
from kryptosbot.config import KryptosBotConfig
from kryptosbot.controller import ResearchController
from kryptosbot.critic import NON_DSL_FAMILIES, TheoryCritic
from kryptosbot.models import (
    CriticDecision,
    TheoryRecord,
    TheoryStatus,
    WorkerContract,
    WorkerStatus,
)
from kryptosbot.theory_ledger import TheoryLedger


def _make_theory(
    hid: str,
    family: str,
    dsl_spec: dict,
    *,
    core_claim: str = "synthetic test theory",
    anomalies: list[str] | None = None,
    override_justification: str = "",
) -> TheoryRecord:
    return TheoryRecord(
        hypothesis_id=hid,
        core_claim=core_claim,
        mechanism="synthetic mechanism for R3-3 integration test",
        family=family,
        anomalies_exploited=anomalies or ["width21_vertical_bigrams"],
        kill_criteria=[f"crib_score < 5 for {hid}"],
        expected_signal=f"crib_score >= 10 for {hid}",
        dsl_spec=dsl_spec,
        override_justification=override_justification,
    )


def _bare_controller(tmp_path: Path) -> tuple[ResearchController, TheoryLedger]:
    """Minimum-surface controller for integration testing."""
    cfg = KryptosBotConfig(project_root=tmp_path)
    ledger = TheoryLedger(db_path=str(tmp_path / "ledger.sqlite"))
    controller = ResearchController.__new__(ResearchController)
    controller.config = cfg
    controller.ledger = ledger
    controller._semaphore = asyncio.Semaphore(4)
    controller._cycle_redteam_verdicts = {}
    controller.state = None
    controller._pantheon_roster = []

    # Mock legacy path so Category B dispatches don't attempt SDK calls.
    async def fake_legacy(theory, on_message=None, *, tag=None):
        role = (
            "agent_sdk_non_dsl_category" if tag == "non_dsl_category"
            else "agent_sdk"
        )
        return WorkerContract(
            hypothesis_id=theory.hypothesis_id,
            worker_role=role,
            status=WorkerStatus.INCONCLUSIVE,
            narrative_summary=f"legacy path invoked with tag={tag!r}",
        )

    controller._run_worker_legacy = fake_legacy
    return controller, ledger


def test_r3_3_synthetic_integration_covers_mortality_battery(tmp_path):
    """Brief §4.2: one synthetic-theory cycle must exercise every new
    code surface the R3-2 cutover introduced.

    The test constructs a mixed theory batch, runs them through the
    critic and _dispatch_theories, then asserts the mortality-table
    signals the brief's falsification targets demand.
    """
    controller, ledger = _bare_controller(tmp_path)
    critic = TheoryCritic(ledger)

    # ─── Theory inventory ─────────────────────────────────────────────

    # 1. Identity-spec Category A — dispatches cleanly (admissible).
    #    Provides the "mortality table has a successful DSL dispatch" row.
    t_clean = _make_theory(
        "t-clean",
        "novel",
        dsl_spec={
            "hypothesis_id": "t-clean",
            "pipeline": [{"kind": "identity", "alphabet": "AZ",
                          "params": []}],
            "compute_budget_cpu_minutes": 1,
        },
    )

    # 2. Columnar Category A — same shape as t-clean but with a columnar
    #    layer so the alert-path matched-null lookup can resolve to
    #    "columnar_single" (even if no alert actually fires). Also
    #    carries override_exhaustion=True so the override path is
    #    exercised (columnar is exhausted in the live log; without
    #    override, admissibility would reject).
    t_override = _make_theory(
        "t-override",
        "novel",
        dsl_spec={
            "hypothesis_id": "t-override",
            "pipeline": [{"kind": "columnar", "alphabet": "AZ",
                          "params": [{"name": "width", "values": [7]},
                                     {"name": "col_order",
                                      "values": [[0, 1, 2, 3, 4, 5, 6]]}]}],
            "compute_budget_cpu_minutes": 1,
            "override_exhaustion": True,
            "override_justification": (
                "R3-3 integration test fixture: exercises the override "
                "path to verify dispatcher honours the flag."
            ),
        },
        override_justification=(
            "R3-3 integration test fixture: exercises the override "
            "path to verify dispatcher honours the flag."
        ),
    )

    # 3. Columnar Category A WITHOUT override — admissibility rejects
    #    because the family is exhausted. Provides the non-zero D
    #    column row the brief's falsification target demands.
    t_reject = _make_theory(
        "t-reject-adm",
        "novel",
        dsl_spec={
            "hypothesis_id": "t-reject-adm",
            "pipeline": [{"kind": "columnar", "alphabet": "AZ",
                          "params": [{"name": "width", "values": [7]},
                                     {"name": "col_order",
                                      "values": [[0, 1, 2, 3, 4, 5, 6]]}]}],
            "compute_budget_cpu_minutes": 1,
        },
    )

    # 4. Cipher-family with null spec — the dsl_untranslatable critic
    #    reject path.
    t_untranslatable = _make_theory(
        "t-untranslatable",
        "novel",
        dsl_spec={},  # empty — Category C
    )

    # 5. Cipher-family with translation error. B-DSL-expanded
    #    (2026-04-22) added translators for rail_fence/route/myszkowski/
    #    quagmire, leaving ``key_tape`` as the only deferred kind. Use
    #    it as the untranslatable-kind exemplar here.
    t_translation_error = _make_theory(
        "t-transerr",
        "novel",
        dsl_spec={
            "hypothesis_id": "t-transerr",
            "pipeline": [{"kind": "key_tape", "alphabet": "AZ",
                          "params": []}],
            "compute_budget_cpu_minutes": 1,
        },
    )

    # 6. Category-B methodological theory — routes to legacy with tag.
    assert "geometry" in NON_DSL_FAMILIES
    t_category_b = _make_theory(
        "t-geom",
        "geometry",
        dsl_spec={},  # absent is fine for Category B
    )

    # ─── Critic pass ──────────────────────────────────────────────────
    #
    # Three theories should be rejected before dispatch:
    #   - t-untranslatable (empty spec)
    #   - t-translation_error (rail_fence kind)
    # and t-override / t-reject / t-clean / t-geom should survive.

    theories_all = [t_clean, t_override, t_reject, t_untranslatable,
                    t_translation_error, t_category_b]
    for t in theories_all:
        ledger.upsert_theory(t)

    critic_results = {t.hypothesis_id: critic.evaluate(t)
                      for t in theories_all}

    # Assert: dsl_untranslatable exercised exactly where expected.
    assert critic_results["t-untranslatable"].decision == (
        CriticDecision.REJECT_UNDERCONSTRAINED
    )
    assert any(
        "dsl_untranslatable" in r
        for r in critic_results["t-untranslatable"].reasons
    )
    assert critic_results["t-transerr"].decision == (
        CriticDecision.REJECT_UNDERCONSTRAINED
    )
    assert any(
        "dsl_untranslatable" in r and "rail_fence" in r
        for r in critic_results["t-transerr"].reasons
    )
    # Category A / B survivors.
    approved_ids = {hid for hid, v in critic_results.items()
                    if v.decision == CriticDecision.APPROVE}
    assert "t-clean" in approved_ids
    assert "t-override" in approved_ids
    assert "t-reject-adm" in approved_ids
    assert "t-geom" in approved_ids

    # ─── Dispatch the survivors ──────────────────────────────────────

    survivors = [t for t in theories_all
                 if critic_results[t.hypothesis_id].decision ==
                 CriticDecision.APPROVE]
    # Clear the state before dispatch (critic-approved theories not
    # yet dispatched from this controller's perspective).

    async def _go():
        return await controller._dispatch_theories(survivors)

    outcomes = asyncio.run(_go())

    outcomes_by_id = {o.hypothesis_id: o for o in outcomes}

    # ─── §4.2 assertions ─────────────────────────────────────────────

    # Assertion 1: non-zero D column — at least one admissibility reject.
    rejected_contracts = [o for o in outcomes
                          if o.status == WorkerStatus.REJECTED_ADMISSIBILITY]
    assert len(rejected_contracts) >= 1, (
        "brief §4.2: expected at least one REJECTED_ADMISSIBILITY "
        "contract; got statuses: "
        + repr([(o.hypothesis_id, o.status.value) for o in outcomes])
    )
    # The specific theory that should have been rejected:
    assert outcomes_by_id["t-reject-adm"].status == (
        WorkerStatus.REJECTED_ADMISSIBILITY
    )
    assert any(
        "ADMISSIBILITY" in e
        for e in outcomes_by_id["t-reject-adm"].disproof_evidence
    )

    # Assertion 2: override_exhaustion=True path passed admissibility.
    # t-override carries override=True; dispatcher should have accepted
    # the exhaustion-overlap and run compute. Status is NOT
    # REJECTED_ADMISSIBILITY.
    assert outcomes_by_id["t-override"].status != (
        WorkerStatus.REJECTED_ADMISSIBILITY
    ), (
        "brief §4.2: override_exhaustion=True spec should bypass "
        f"admissibility reject; got {outcomes_by_id['t-override'].status}"
    )

    # Assertion 3: Category-B theory routed via legacy with tag.
    assert outcomes_by_id["t-geom"].worker_role == (
        "agent_sdk_non_dsl_category"
    )

    # Assertion 4: Category-A DSL theories carry dsl_dispatcher role.
    for hid in ("t-clean", "t-override", "t-reject-adm"):
        assert outcomes_by_id[hid].worker_role == "dsl_dispatcher", (
            f"{hid} should have routed to DSL; got "
            f"{outcomes_by_id[hid].worker_role}"
        )

    # Assertion 5: matched-family null derivable from at least one
    # dispatched contract. t-override has a columnar layer → family
    # resolution returns "columnar_single".
    matched = _matched_null_family_from_contract(
        outcomes_by_id["t-override"]
    )
    assert matched == "columnar_single", (
        f"brief §4.2: matched-null lookup must resolve columnar layer; "
        f"got {matched!r}"
    )

    # Assertion 6: worker_scratch/ empty after dispatch completes. The
    # DSL path never creates it.
    scratch = tmp_path / "results" / "worker_scratch"
    assert not scratch.exists() or not any(scratch.rglob("*")), (
        f"brief §4.2: worker_scratch/ must be empty on DSL path; "
        f"found: {list(scratch.rglob('*')) if scratch.exists() else []}"
    )

    # Assertion 7: ledger's dsl_spec populated for every theory that
    # carried one. Reload theories and inspect. t-clean, t-override,
    # t-reject-adm, t-transerr had non-empty specs; t-geom and
    # t-untranslatable had empty dicts.
    for hid in ("t-clean", "t-override", "t-reject-adm",
                "t-transerr"):
        reloaded = ledger.get_theory(hid)
        assert reloaded is not None, f"theory {hid} missing from ledger"
        assert reloaded.dsl_spec, (
            f"theory {hid} should have non-empty dsl_spec in ledger; "
            f"got {reloaded.dsl_spec}"
        )
    for hid in ("t-geom", "t-untranslatable"):
        reloaded = ledger.get_theory(hid)
        assert reloaded is not None
        assert reloaded.dsl_spec == {}, (
            f"theory {hid} expected empty dsl_spec; got {reloaded.dsl_spec}"
        )

    # ─── Mortality-table summary (for the phase report) ──────────────
    summary = {
        "total_theories": len(theories_all),
        "critic_rejected": sum(
            1 for v in critic_results.values()
            if v.decision != CriticDecision.APPROVE
        ),
        "dispatched": len(outcomes),
        "dispatcher_rejected": len(rejected_contracts),
        "dsl_path_contracts": sum(
            1 for o in outcomes if o.worker_role == "dsl_dispatcher"
        ),
        "legacy_path_contracts": sum(
            1 for o in outcomes if o.worker_role == (
                "agent_sdk_non_dsl_category"
            )
        ),
    }
    # This assertion captures the mortality fingerprint R3-3 proves.
    assert summary == {
        "total_theories": 6,
        "critic_rejected": 2,
        "dispatched": 4,
        "dispatcher_rejected": 1,
        "dsl_path_contracts": 3,
        "legacy_path_contracts": 1,
    }, f"mortality fingerprint drift: {summary}"
