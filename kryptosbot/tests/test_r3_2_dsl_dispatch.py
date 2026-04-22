"""R3-2 tests: DSL dispatch on the controller worker path.

Covers the rewired _run_worker, the Category-A/B dispatch fan-out in
_dispatch_theories, the new WorkerStatus.REJECTED_ADMISSIBILITY value,
the TheoryRecord.dsl_spec field round-trip, and alert-path matched-null
keying from DSL pipeline metadata.

Adversarial-first per brief §0.5: every happy-path test is paired with
at least one negative path exercising the same code surface.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from kryptos.kernel.constants import CT
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptosbot.alerts import (
    _matched_null_family_from_contract,
    _p_value_gate_passes,
)
from kryptosbot.contracts import validate_theory_proposals
from kryptosbot.critic import NON_DSL_FAMILIES, TheoryCritic
from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec, ParamRange
from kryptosbot.job_dispatcher import (
    DispatcherError,
    execute,
    job_result_to_worker_contract,
)
from kryptosbot.models import (
    CriticDecision,
    CriticVerdict,
    TheoryRecord,
    TheoryStatus,
    WorkerContract,
    WorkerStatus,
)
from kryptosbot.theory_ledger import TheoryLedger


def _identity_dsl_spec(hid: str = "test-identity") -> dict:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "identity", "alphabet": "AZ", "params": [],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _vigenere_ka_spec(hid: str = "test-vig-ka") -> dict:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "vigenere",
            "alphabet": "KA",
            "params": [{"name": "keyword",
                        "values": ["KRYPTOS", "PALIMPSEST"]}],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _double_columnar_spec(hid: str = "test-dcol") -> dict:
    return {
        "hypothesis_id": hid,
        "pipeline": [
            {"kind": "columnar", "alphabet": "AZ",
             "params": [{"name": "width", "values": [7]},
                        {"name": "col_order",
                         "values": [[0, 1, 2, 3, 4, 5, 6]]}]},
            {"kind": "columnar", "alphabet": "AZ",
             "params": [{"name": "width", "values": [5]},
                        {"name": "col_order",
                         "values": [[0, 1, 2, 3, 4]]}]},
        ],
        "compute_budget_cpu_minutes": 1,
    }


def _cipher_family_theory_fully_valid(hid: str = "t-good") -> TheoryRecord:
    """A cipher-family theory that should pass all critic checks.

    Uses family='novel' (outside TIER_1/TIER_2) to avoid family-elim
    gates. Exploits an anomaly so information-gain check passes.
    """
    return TheoryRecord(
        hypothesis_id=hid,
        core_claim="K4 uses Vigenere over KA alphabet",
        mechanism="Vigenere with KRYPTOS-keyed alphabet",
        family="novel",
        anomalies_exploited=["width21_vertical_bigrams"],
        kill_criteria=["Crib score < 18"],
        expected_signal="Crib score >= 18",
        dsl_spec=_vigenere_ka_spec(hid),
    )


def _tmp_ledger() -> TheoryLedger:
    """Fresh in-tempdir ledger for isolated tests."""
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    return TheoryLedger(db_path=tmp.name)


# ═══════════════════════════════════════════════════════════════════════════
# models.py — enum + field additions
# ═══════════════════════════════════════════════════════════════════════════


def test_worker_status_rejected_admissibility_value_exists():
    assert WorkerStatus.REJECTED_ADMISSIBILITY.value == "rejected_admissibility"


def test_theory_record_has_dsl_spec_default_empty_dict():
    t = TheoryRecord(core_claim="x", mechanism="y", family="vigenere")
    assert t.dsl_spec == {}


def test_theory_record_dsl_spec_serializes_and_deserializes():
    ledger = _tmp_ledger()
    spec = _identity_dsl_spec("hid-roundtrip")
    t = TheoryRecord(
        hypothesis_id="hid-roundtrip",
        core_claim="x", mechanism="y", family="vigenere",
        dsl_spec=spec,
    )
    ledger.upsert_theory(t)
    reloaded = ledger.get_theory("hid-roundtrip")
    assert reloaded is not None
    assert reloaded.dsl_spec == spec


# ═══════════════════════════════════════════════════════════════════════════
# contracts.validate_theory_proposals — dsl_spec parsing
# ═══════════════════════════════════════════════════════════════════════════


def test_validate_theory_proposals_accepts_null_dsl_spec():
    raw = json.dumps([{
        "title": "t", "core_claim": "c", "mechanism": "m",
        "family": "geometry",  # Category B — no spec required
        "dsl_spec": None,
    }])
    report = validate_theory_proposals(raw)
    assert report.valid and not report.invalid
    assert report.valid[0].dsl_spec == {}


def test_validate_theory_proposals_accepts_valid_dsl_spec():
    raw = json.dumps([{
        "title": "t", "core_claim": "c", "mechanism": "m", "family": "vigenere",
        "dsl_spec": _identity_dsl_spec("valid"),
    }])
    report = validate_theory_proposals(raw)
    assert report.valid and not report.invalid
    assert report.valid[0].dsl_spec["hypothesis_id"] == "valid"


def test_validate_theory_proposals_rejects_non_dict_dsl_spec():
    raw = json.dumps([{
        "title": "t", "core_claim": "c", "mechanism": "m", "family": "vigenere",
        "dsl_spec": "not a dict",
    }])
    report = validate_theory_proposals(raw)
    assert not report.valid
    assert report.invalid
    assert "dsl_spec" in report.invalid[0]["error"]


def test_validate_theory_proposals_passes_loose_dsl_spec_to_critic():
    """R3-2 design: boundary validation is lenient on dsl_spec shape
    (accepts any dict). Structural validation runs in the critic's
    Category-A/C check, which produces the canonical 'dsl_untranslatable'
    reason. This keeps minor schema variance (theorist-placeholder
    hypothesis_id, missing optional fields) from dropping the whole
    theory at parse time."""
    loose_spec = {
        "pipeline": [{"kind": "vigenere", "alphabet": "AZ",
                      "params": [{"name": "keyword", "values": ["K"]}]}],
        # hypothesis_id deliberately missing — critic will substitute
    }
    raw = json.dumps([{
        "title": "t", "core_claim": "c", "mechanism": "m", "family": "vigenere",
        "dsl_spec": loose_spec,
    }])
    report = validate_theory_proposals(raw)
    assert report.valid and not report.invalid
    # Spec stored verbatim — no mutation at boundary time.
    assert report.valid[0].dsl_spec == loose_spec


# ═══════════════════════════════════════════════════════════════════════════
# Critic — Category-A/B/C classification (hybrid fallback)
# ═══════════════════════════════════════════════════════════════════════════


def test_critic_rejects_cipher_family_without_dsl_spec():
    """Category C: cipher family + empty dsl_spec → reject.

    Uses family='novel' to avoid the Tier-1/Tier-2 elimination paths
    which would reject first. The Category-A/C check runs after family
    elimination (see critic.py Check 4.6), so this test needs a family
    that survives the earlier gates."""
    critic = TheoryCritic(_tmp_ledger())
    t = TheoryRecord(
        hypothesis_id="t-no-spec",
        core_claim="c", mechanism="m", family="novel",
        anomalies_exploited=["width21_vertical_bigrams"],  # avoid low-info
        kill_criteria=["x"], expected_signal="y",
        dsl_spec={},  # empty — Category C
    )
    verdict = critic.evaluate(t)
    assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
    assert any("dsl_untranslatable" in r for r in verdict.reasons)


def test_critic_rejects_cipher_family_with_untranslatable_kind():
    """Category C: cipher family + spec uses a deferred kind → reject.

    B-DSL-expanded (2026-04-22) promoted rail_fence, route, myszkowski,
    and quagmire out of the deferred set, so this test now uses
    ``key_tape`` — the only remaining kind in _VALID_CIPHER_KINDS
    that is NOT in _SUPPORTED_KINDS."""
    critic = TheoryCritic(_tmp_ledger())
    bad_spec = {
        "hypothesis_id": "t-kt",
        "pipeline": [{"kind": "key_tape", "alphabet": "AZ", "params": []}],
        "compute_budget_cpu_minutes": 1,
    }
    t = TheoryRecord(
        hypothesis_id="t-kt",
        core_claim="c", mechanism="m", family="novel",
        kill_criteria=["x"], expected_signal="y",
        dsl_spec=bad_spec,
    )
    verdict = critic.evaluate(t)
    assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
    assert any("dsl_untranslatable" in r and "key_tape" in r
               for r in verdict.reasons)


def test_critic_rejects_deferred_family_with_supported_kind_spec():
    """Deferred family names must not launder themselves through a supported
    pipeline kind. key_tape is explicitly deferred, so a vigenere dsl_spec
    is a family/spec mismatch and must reject at the critic."""
    critic = TheoryCritic(_tmp_ledger())
    bad_spec = {
        "hypothesis_id": "t-key-tape",
        "pipeline": [{"kind": "vigenere", "alphabet": "AZ", "params": []}],
        "compute_budget_cpu_minutes": 1,
    }
    t = TheoryRecord(
        hypothesis_id="t-key-tape",
        core_claim="A deferred family proposal is represented by a supported DSL spec",
        mechanism="bounded additive execution over a declared finite family",
        family="key_tape",
        kill_criteria=["x"],
        expected_signal="y",
        dsl_spec=bad_spec,
    )
    verdict = critic.evaluate(t)
    assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
    assert any("kind smuggling" in r or "family/spec mismatch" in r
               for r in verdict.reasons)


def test_critic_skips_dsl_check_for_non_dsl_family():
    """Category B: family in NON_DSL_FAMILIES → no dsl_spec required,
    the theory falls through to the remaining checks on its merits."""
    critic = TheoryCritic(_tmp_ledger())
    # Confirm the fixture family is actually in NON_DSL_FAMILIES.
    assert "geometry" in NON_DSL_FAMILIES
    t = TheoryRecord(
        hypothesis_id="t-geom",
        core_claim="K2 coordinate line points at a K4 layout feature",
        mechanism="Spatial analysis of pool-sculpture relationships",
        family="geometry",
        kill_criteria=["No alignment within measurement uncertainty"],
        expected_signal="Alignment within 1 meter at p < 0.05",
        dsl_spec={},  # absent — correct for Category B
    )
    verdict = critic.evaluate(t)
    # Approves (passes completeness, no family elimination for geometry,
    # has kill criteria and expected signal, exploits no anomaly but
    # that's not a hard reject).
    assert verdict.decision != CriticDecision.REJECT_UNDERCONSTRAINED or (
        "dsl_untranslatable" not in " ".join(verdict.reasons)
    )


def test_critic_approves_cipher_family_with_valid_translatable_spec():
    """Category A: cipher family + valid translatable spec → approve."""
    critic = TheoryCritic(_tmp_ledger())
    t = _cipher_family_theory_fully_valid()
    verdict = critic.evaluate(t)
    assert verdict.decision == CriticDecision.APPROVE


# ═══════════════════════════════════════════════════════════════════════════
# job_result_to_worker_contract — new REJECTED_ADMISSIBILITY mapping
# ═══════════════════════════════════════════════════════════════════════════


def test_job_result_admissibility_reject_maps_to_rejected_admissibility(tmp_path):
    """R3-2 changed mapping from INCONCLUSIVE to REJECTED_ADMISSIBILITY."""
    spec = HypothesisSpec(
        hypothesis_id="T", pipeline=[CipherLayer(kind="rail_fence")],
        compute_budget_cpu_minutes=1,
    )
    result = execute(
        spec, artifact_root=tmp_path / "dsl_jobs",
        parallel=False, exhaustion_log={},
    )
    contract = job_result_to_worker_contract(result)
    assert contract.status == WorkerStatus.REJECTED_ADMISSIBILITY


# ═══════════════════════════════════════════════════════════════════════════
# Alert-path matched-null family keying
# ═══════════════════════════════════════════════════════════════════════════


def test_matched_null_family_from_contract_columnar_double():
    c = WorkerContract(
        hypothesis_id="x",
        raw_artifacts={"dsl_pipeline_kinds": ["columnar", "columnar"]},
    )
    assert _matched_null_family_from_contract(c) == "columnar_double"


def test_matched_null_family_from_contract_columnar_single():
    c = WorkerContract(
        hypothesis_id="x",
        raw_artifacts={"dsl_pipeline_kinds": ["columnar"]},
    )
    assert _matched_null_family_from_contract(c) == "columnar_single"


def test_matched_null_family_from_contract_beaufort():
    c = WorkerContract(
        hypothesis_id="x",
        raw_artifacts={"dsl_pipeline_kinds": ["beaufort"]},
    )
    assert _matched_null_family_from_contract(c) == "beaufort"


def test_matched_null_family_from_contract_legacy_contract_returns_empty():
    """Contract with no DSL metadata (legacy SDK path) must yield "".
    The alert path then falls back to random_text null."""
    c = WorkerContract(hypothesis_id="x")
    assert _matched_null_family_from_contract(c) == ""


def test_matched_null_family_mixed_pipeline_returns_empty():
    """Unrecognized shapes (grille, polybius, or multi-kind mixes) fall
    back to random_text rather than fabricating a matched family."""
    for kinds in (
        ["grille"],
        ["polybius"],
        ["vigenere", "beaufort"],
        ["columnar", "vigenere"],
    ):
        c = WorkerContract(
            hypothesis_id="x",
            raw_artifacts={"dsl_pipeline_kinds": kinds},
        )
        assert _matched_null_family_from_contract(c) == "", (
            f"expected empty family for kinds={kinds}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Live _run_worker semantics (synchronous pieces only)
# ═══════════════════════════════════════════════════════════════════════════


def test_run_worker_does_not_create_scratch_directory(monkeypatch, tmp_path):
    """Brief §3.4 critical assertion: the DSL Category-A path does NOT
    write to results/worker_scratch/. Verify by dispatching a synthetic
    Category-A theory and asserting the scratch dir was never created."""
    from kryptosbot.controller import ResearchController
    from kryptosbot.config import KryptosBotConfig

    # Minimal config — disable SDK entirely; we're only exercising the
    # DSL path which doesn't call the SDK.
    cfg = KryptosBotConfig(project_root=tmp_path)
    cfg.worker_timeout_minutes = 1  # short
    ledger_path = tmp_path / "ledger.sqlite"
    ledger = TheoryLedger(db_path=str(ledger_path))

    # Build a controller without running its init loop. Use direct
    # attribute assignment for the minimum surface needed.
    controller = ResearchController.__new__(ResearchController)
    controller.config = cfg
    controller.ledger = ledger
    controller._semaphore = asyncio.Semaphore(1)
    controller._cycle_redteam_verdicts = {}
    controller.state = None
    controller._pantheon_roster = []
    # Build a Category-A theory and dispatch via _run_worker directly.
    theory = TheoryRecord(
        hypothesis_id="noscratch",
        core_claim="x", mechanism="y", family="novel",
        kill_criteria=["z"], expected_signal="w",
        dsl_spec=_identity_dsl_spec("noscratch"),
    )
    ledger.upsert_theory(theory)
    scratch_root = tmp_path / "results" / "worker_scratch"

    async def _go():
        return await controller._run_worker(theory)

    contract = asyncio.run(_go())
    assert contract.worker_role == "dsl_dispatcher"
    # Status may be INCONCLUSIVE (no configs stored), SUCCESS, or
    # DISPROVED — any is fine as long as it's NOT the legacy path.
    assert contract.status in (
        WorkerStatus.INCONCLUSIVE,
        WorkerStatus.SUCCESS,
        WorkerStatus.DISPROVED,
    )
    # The key assertion: no scratch directory was created.
    assert not scratch_root.exists() or not any(scratch_root.iterdir()), (
        f"worker_scratch/ should be empty/missing on the DSL path; "
        f"found: {list(scratch_root.rglob('*'))}"
    )


def test_run_worker_kernel_overrule_preserved(tmp_path):
    """DSL-path contract still routes through _verify_against_kernel.
    Verify by dispatching an identity spec (output == CT) and checking
    crib_score matches kernel's direct computation."""
    from kryptosbot.controller import ResearchController
    from kryptosbot.config import KryptosBotConfig

    cfg = KryptosBotConfig(project_root=tmp_path)
    ledger = TheoryLedger(db_path=str(tmp_path / "ledger.sqlite"))
    controller = ResearchController.__new__(ResearchController)
    controller.config = cfg
    controller.ledger = ledger
    controller._semaphore = asyncio.Semaphore(1)
    controller._cycle_redteam_verdicts = {}
    controller.state = None
    controller._pantheon_roster = []

    theory = TheoryRecord(
        hypothesis_id="kernel-check",
        core_claim="x", mechanism="y", family="novel",
        kill_criteria=["z"], expected_signal="w",
        dsl_spec=_identity_dsl_spec("kernel-check"),
    )
    ledger.upsert_theory(theory)

    async def _go():
        return await controller._run_worker(theory)

    contract = asyncio.run(_go())
    # identity → output is CT → kernel score on CT is crib_score=2 (the
    # self-encrypting positions 32 and 73). Anything else is a bug in
    # either the translator or the overrule.
    kernel_score = int(score_candidate(CT).crib_score)
    assert contract.crib_score == kernel_score


def test_run_worker_admissibility_reject_produces_rejected_admissibility_status(tmp_path):
    """Category-A theory with exhaustion-overlap (no override) → the
    dispatcher admissibility rejects → contract is REJECTED_ADMISSIBILITY
    with no compute spent. This is the postmortem §6.1.6 "Row D = 0"
    falsification — R3-2 demands this column be non-zero in live runs."""
    from kryptosbot.controller import ResearchController
    from kryptosbot.config import KryptosBotConfig

    cfg = KryptosBotConfig(project_root=tmp_path)
    ledger = TheoryLedger(db_path=str(tmp_path / "ledger.sqlite"))
    controller = ResearchController.__new__(ResearchController)
    controller.config = cfg
    controller.ledger = ledger
    controller._semaphore = asyncio.Semaphore(1)
    controller._cycle_redteam_verdicts = {}
    controller.state = None
    controller._pantheon_roster = []

    # Grille family has exhaustion-log overlap per the live catalogue
    # (blitz_grille_geometry_* scripts). Without override, admissibility
    # rejects.
    grille_spec = {
        "hypothesis_id": "rejected",
        "pipeline": [{
            "kind": "grille", "alphabet": "AZ",
            "params": [{"name": "hole_mask", "values": [list(range(97))]}],
        }],
        "compute_budget_cpu_minutes": 1,
    }
    theory = TheoryRecord(
        hypothesis_id="rejected",
        core_claim="x", mechanism="y", family="novel",
        kill_criteria=["z"], expected_signal="w",
        dsl_spec=grille_spec,
    )
    ledger.upsert_theory(theory)

    async def _go():
        return await controller._run_worker(theory)

    contract = asyncio.run(_go())
    assert contract.status == WorkerStatus.REJECTED_ADMISSIBILITY
    assert any("ADMISSIBILITY" in e for e in contract.disproof_evidence)
    # raw_artifacts carries the pipeline kinds for alert-path lookup
    # even on admissibility reject.
    assert contract.raw_artifacts.get("dsl_pipeline_kinds") == ["grille"]


# ═══════════════════════════════════════════════════════════════════════════
# Hybrid-split scenarios (brief §9 acceptance: 3+ required)
# ═══════════════════════════════════════════════════════════════════════════


def test_hybrid_category_b_theory_dispatches_via_legacy_tag(tmp_path):
    """Category-B (family in NON_DSL_FAMILIES) routes through
    _run_worker_legacy with tag='non_dsl_category'. Verified by
    checking the resulting contract's worker_role."""
    from kryptosbot.controller import ResearchController
    from kryptosbot.config import KryptosBotConfig

    cfg = KryptosBotConfig(project_root=tmp_path)
    ledger = TheoryLedger(db_path=str(tmp_path / "ledger.sqlite"))
    controller = ResearchController.__new__(ResearchController)
    controller.config = cfg
    controller.ledger = ledger
    controller._semaphore = asyncio.Semaphore(1)
    controller._cycle_redteam_verdicts = {}
    controller.state = None
    controller._pantheon_roster = []

    # Mock _run_worker_legacy so we don't actually launch an SDK
    # subprocess in tests. The test verifies the dispatch routing, not
    # the legacy path's internals (covered by pre-R3 tests).
    async def fake_legacy(theory, on_message=None, *, tag=None):
        role = (
            "agent_sdk_non_dsl_category" if tag == "non_dsl_category"
            else "agent_sdk"
        )
        return WorkerContract(
            hypothesis_id=theory.hypothesis_id,
            worker_role=role,
            status=WorkerStatus.INCONCLUSIVE,
        )

    controller._run_worker_legacy = fake_legacy

    # Also mock _run_worker to ensure Category-A isn't accidentally
    # used for this test (confirms the fan-out is selecting correctly).
    async def unused_dsl_worker(theory, on_message=None):
        raise AssertionError(
            f"Category-B theory {theory.hypothesis_id!r} incorrectly "
            "routed to DSL _run_worker"
        )

    controller._run_worker = unused_dsl_worker

    cat_b_theory = TheoryRecord(
        hypothesis_id="cat-b", core_claim="x", mechanism="y",
        family="geometry",  # in NON_DSL_FAMILIES
        kill_criteria=["z"], expected_signal="w",
    )
    ledger.upsert_theory(cat_b_theory)

    async def _go():
        return await controller._dispatch_theories([cat_b_theory])

    outcomes = asyncio.run(_go())
    assert len(outcomes) == 1
    assert outcomes[0].worker_role == "agent_sdk_non_dsl_category"


def test_hybrid_category_a_theory_dispatches_via_dsl(tmp_path):
    """Category-A (cipher family) routes through the new _run_worker,
    not the legacy path. Verified by worker_role='dsl_dispatcher'."""
    from kryptosbot.controller import ResearchController
    from kryptosbot.config import KryptosBotConfig

    cfg = KryptosBotConfig(project_root=tmp_path)
    ledger = TheoryLedger(db_path=str(tmp_path / "ledger.sqlite"))
    controller = ResearchController.__new__(ResearchController)
    controller.config = cfg
    controller.ledger = ledger
    controller._semaphore = asyncio.Semaphore(1)
    controller._cycle_redteam_verdicts = {}
    controller.state = None
    controller._pantheon_roster = []

    # Fail loudly if the legacy path is taken for this cipher-family theory.
    async def unused_legacy(theory, on_message=None, *, tag=None):
        raise AssertionError(
            f"Category-A theory {theory.hypothesis_id!r} incorrectly "
            "routed to legacy path"
        )

    controller._run_worker_legacy = unused_legacy

    theory = TheoryRecord(
        hypothesis_id="cat-a", core_claim="x", mechanism="y",
        family="novel",  # cipher-family (not in NON_DSL_FAMILIES), Category A
        kill_criteria=["z"], expected_signal="w",
        dsl_spec=_identity_dsl_spec("cat-a"),
    )
    ledger.upsert_theory(theory)

    async def _go():
        return await controller._dispatch_theories([theory])

    outcomes = asyncio.run(_go())
    assert len(outcomes) == 1
    assert outcomes[0].worker_role == "dsl_dispatcher"


def test_hybrid_mortality_distinguishes_categories(tmp_path):
    """Mixed batch of Category-A and Category-B theories produces
    contracts whose worker_role tags let the mortality table distinguish
    the two dispatch paths."""
    from kryptosbot.controller import ResearchController
    from kryptosbot.config import KryptosBotConfig

    cfg = KryptosBotConfig(project_root=tmp_path)
    ledger = TheoryLedger(db_path=str(tmp_path / "ledger.sqlite"))
    controller = ResearchController.__new__(ResearchController)
    controller.config = cfg
    controller.ledger = ledger
    controller._semaphore = asyncio.Semaphore(1)
    controller._cycle_redteam_verdicts = {}
    controller.state = None
    controller._pantheon_roster = []

    async def fake_legacy(theory, on_message=None, *, tag=None):
        role = (
            "agent_sdk_non_dsl_category" if tag == "non_dsl_category"
            else "agent_sdk"
        )
        return WorkerContract(
            hypothesis_id=theory.hypothesis_id,
            worker_role=role,
            status=WorkerStatus.INCONCLUSIVE,
        )

    controller._run_worker_legacy = fake_legacy

    theories = [
        TheoryRecord(
            hypothesis_id="mixed-A",
            core_claim="x", mechanism="y", family="novel",
            kill_criteria=["z"], expected_signal="w",
            dsl_spec=_identity_dsl_spec("mixed-A"),
        ),
        TheoryRecord(
            hypothesis_id="mixed-B",
            core_claim="a", mechanism="b", family="geometry",
            kill_criteria=["c"], expected_signal="d",
        ),
    ]
    for t in theories:
        ledger.upsert_theory(t)

    async def _go():
        return await controller._dispatch_theories(theories)

    outcomes = asyncio.run(_go())
    assert len(outcomes) == 2
    roles = {o.worker_role for o in outcomes}
    assert "dsl_dispatcher" in roles, (
        f"Category-A not in dispatch tags: {roles}"
    )
    assert "agent_sdk_non_dsl_category" in roles, (
        f"Category-B not in dispatch tags: {roles}"
    )
