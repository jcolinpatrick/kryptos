from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_bean_constraint_counts_and_624_vectors_are_independently_derived():
    from scripts.audit import audit_bean_constraints as audit

    derived = audit.derive_constraints()
    valid = audit.count_valid_vectors(
        derived["positions"],
        derived["eq"],
        derived["ineq"],
        derived["linear"],
    )

    assert derived["eq"] == ((27, 65),)
    assert len(derived["ineq"]) == 242
    assert len(derived["linear"]) == 101
    assert valid["valid_vectors_after_inequalities"] == 624
    assert valid["explicitly_not_done"] == "No enumeration over 26^24 was performed."


def test_bean_equality_count_is_not_self_consistent_under_index_mutation():
    from scripts.audit import audit_bean_constraints as audit

    derived = audit.derive_constraints()
    mutated_eq = ((27, 64),)

    valid = audit.count_valid_vectors(
        derived["positions"],
        mutated_eq,
        derived["ineq"],
        derived["linear"],
    )

    assert mutated_eq != derived["eq"]
    assert valid["valid_vectors_after_inequalities"] == 0


@pytest.mark.parametrize("claim_id", ["stehle_delta5", "bean_minor_diffs", "bean_repeated_pt_distances"])
def test_bean_reported_statistics_are_not_hard_constraints_or_elimination_bases(claim_id):
    from kryptosbot.claim_policy import can_use_as_elimination_basis, can_use_as_hard_constraint
    from kryptosbot.claims_registry import get_canonical_claim

    claim = get_canonical_claim(claim_id)
    assert claim is not None

    hard, hard_reason = can_use_as_hard_constraint(claim, h1_context=True)
    elim, elim_reason = can_use_as_elimination_basis(claim, h1_context=True)

    assert not hard, hard_reason
    assert not elim, elim_reason


@pytest.mark.parametrize("claim_id", ["width21_bigrams", "stehle_delta5", "bean_minor_diffs"])
def test_project_statistical_anomaly_cannot_be_promoted_to_must_explain(claim_id):
    from kryptosbot.claim_policy import can_promote_to_must_explain
    from kryptosbot.claims_registry import get_canonical_claim
    from kryptosbot.provenance import EpistemicClass

    claim = get_canonical_claim(claim_id)
    assert claim is not None
    assert claim.epistemic_class is EpistemicClass.PROJECT_REVERIFIED_STATISTICAL_ANOMALY

    allowed, reason = can_promote_to_must_explain(claim)
    assert not allowed, reason


def test_retired_null_palette_claim_is_blocked_from_live_prompt_use():
    from kryptosbot.claim_policy import can_use_in_prompt
    from kryptosbot.claims_registry import get_canonical_claim
    from kryptosbot.provenance import EpistemicClass

    claim = get_canonical_claim("null_palette_retired")
    assert claim is not None
    assert claim.epistemic_class is EpistemicClass.RETIRED_CLAIM

    allowed, reason = can_use_in_prompt(claim)
    assert not allowed, reason


def test_worker_contract_fabricated_scores_are_overruled_by_kernel():
    from kryptosbot.contracts import validate_worker_contract

    raw = "```json\n" + json.dumps(
        {
            "hypothesis_id": "audit-fabricated",
            "worker_role": "unit-test",
            "status": "success",
            "score": 99,
            "crib_score": 24,
            "bean_passed": True,
            "best_plaintext": "A" * 97,
        }
    ) + "\n```"

    result = validate_worker_contract(raw, "audit-fabricated")

    assert result.is_valid
    assert result.value is not None
    assert result.value.fields_overwritten is True
    assert result.value.worker_self_report["crib_score"] == 24
    assert result.value.crib_score != 24
    assert result.value.bean_passed is False


def test_stale_null_baseline_cache_warns_and_is_not_consumed(monkeypatch, caplog):
    from kryptosbot import null_baselines
    from kryptosbot.null_baselines import NullDistribution

    stale = NullDistribution(
        scorer_name="crib_score",
        method="random_text",
        n_chars=97,
        alphabet="AZ",
        n_samples=100,
        seed=1,
        kernel_commit="definitely-not-current",
        sorted_scores=[0.0, 1.0, 2.0],
    )

    monkeypatch.setattr(null_baselines, "get_cached", lambda *args, **kwargs: stale)

    with caplog.at_level("WARNING", logger="kryptosbot.null_baselines"):
        p_value, status = null_baselines.p_value_for_alert("A" * 97, 18)

    assert p_value is None
    assert status == "stale_cache"
    assert "refusing to consume stale calibration" in caplog.text


def test_alert_event_persists_full_calibration_metadata(tmp_path, monkeypatch):
    from kryptosbot.alerts import AlertLevel, process_alerts
    from kryptosbot.models import WorkerContract, WorkerStatus

    monkeypatch.setenv("KRYPTOSBOT_DISABLE_NTFY", "1")
    contract = WorkerContract(
        hypothesis_id="audit-alert-metadata",
        worker_role="unit-test",
        status=WorkerStatus.SUCCESS,
        crib_score=18,
        bean_passed=False,
        score=18.0,
        best_plaintext="A" * 97,
        raw_artifacts={
            "universe_hash": "audituniverse123",
            "total_tested": 37,
        },
    )

    events = process_alerts(
        [contract],
        AlertLevel.SIGNAL,
        cycle_number=1,
        results_dir=tmp_path,
    )

    assert len(events) == 1
    event = events[0]
    assert event.p_value_status == "ok_gated"
    assert event.p_value_null_method == "random_text"
    assert event.p_value_null_cache_key
    assert event.p_value_null_n_samples > 0
    assert event.p_value_sample_floor == 0.0
    assert event.candidate_p_value_vs_null is not None
    assert event.family_wise_p_value_vs_null["n_tests"] == 37
    assert event.family_wise_p_value_vs_null["universe_hash"] == "audituniverse123"
    assert event.universe_hash == "audituniverse123"

    persisted = json.loads(next(tmp_path.glob("alert_*.json")).read_text())
    assert persisted["p_value_null_method"] == "random_text"
    assert persisted["family_wise_p_value_vs_null"]["n_tests"] == 37
    assert persisted["universe_hash"] == "audituniverse123"


def test_family_wise_p_value_reports_search_universe_corrections():
    from kryptosbot.null_baselines import family_wise_p_value

    got = family_wise_p_value(0.001, n_tests=25, universe_hash="abc123")

    assert got["candidate_p_value"] == 0.001
    assert got["n_tests"] == 25
    assert got["universe_hash"] == "abc123"
    assert got["bonferroni_p_value"] == pytest.approx(0.025)
    assert got["sidak_p_value"] == pytest.approx(1 - (1 - 0.001) ** 25)
    assert "post-hoc" in got["caveat"]


def test_every_dsl_cipher_kind_except_key_tape_has_dispatcher_translation():
    from kryptosbot.hypothesis_dsl import _VALID_CIPHER_KINDS
    from kryptosbot.job_dispatcher import _SUPPORTED_KINDS

    assert sorted(set(_VALID_CIPHER_KINDS) - set(_SUPPORTED_KINDS)) == ["key_tape"]
    assert not (set(_SUPPORTED_KINDS) - set(_VALID_CIPHER_KINDS))


def test_dispatcher_caesar_translation_preserves_tiny_known_answer_semantics():
    from kryptos.kernel.transforms.compose import (
        PipelineConfig,
        TransformConfig,
        TransformType,
        build_pipeline,
    )
    from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec, ParamRange
    from kryptosbot.job_dispatcher import _build_pipeline_config, _enumerate_bindings

    spec = HypothesisSpec(
        hypothesis_id="audit-caesar",
        pipeline=[CipherLayer(kind="caesar", params=[ParamRange(name="shift", values=[3])])],
        compute_budget_cpu_minutes=1,
    )
    pipe = _build_pipeline_config(spec, next(_enumerate_bindings(spec)))
    steps = tuple(
        TransformConfig(
            transform_type=TransformType(step["type"]),
            params=dict(step["params"]),
            description=step.get("description", ""),
        )
        for step in pipe["steps"]
    )
    decrypt = build_pipeline(
        PipelineConfig(name=pipe["name"], steps=steps, direction=pipe["direction"])
    )

    assert decrypt("DEFABC") == "ABCXYZ"


def test_spiral_route_top_right_corner_matches_external_oracle():
    from kryptos.kernel.transforms.transposition import apply_perm, spiral_perm

    plaintext = "BRIGHTONANDHOVE"
    top_right = spiral_perm(
        5,
        3,
        len(plaintext),
        clockwise=True,
        start_corner="top_right",
    )
    top_left = spiral_perm(
        5,
        3,
        len(plaintext),
        clockwise=True,
        start_corner="top_left",
    )

    assert apply_perm(plaintext, top_right) == "ITAHEVONOGBRHND"
    assert apply_perm(plaintext, top_left) != "ITAHEVONOGBRHND"


def test_synthetic_vigenere_fixture_is_not_solved_by_wrong_variant():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    idx = {ch: i for i, ch in enumerate(alphabet)}

    def clean(text: str) -> str:
        return "".join(ch for ch in text.upper() if ch in idx)

    def vig_encrypt(pt: str, key: str) -> str:
        nums = [idx[ch] for ch in clean(key)]
        return "".join(
            alphabet[(idx[ch] + nums[i % len(nums)]) % 26]
            for i, ch in enumerate(clean(pt))
        )

    def beaufort_decrypt(ct: str, key: str) -> str:
        nums = [idx[ch] for ch in clean(key)]
        return "".join(
            alphabet[(nums[i % len(nums)] - idx[ch]) % 26]
            for i, ch in enumerate(clean(ct))
        )

    plaintext = "ATTACKATDAWN"
    ciphertext = vig_encrypt(plaintext, "LEMON")

    assert beaufort_decrypt(ciphertext, "LEMON") != plaintext


def test_self_test_known_answer_keys_are_not_imported_by_production_modules():
    repo = Path(__file__).resolve().parents[2]
    forbidden_imports = (
        "from kryptosbot.self_test import",
        "from .self_test import",
        "import kryptosbot.self_test",
    )
    offenders = []
    for path in (repo / "kryptosbot").glob("*.py"):
        if path.name in {"self_test.py", "self_test_real_api.py"}:
            continue
        text = path.read_text(errors="replace")
        if any(token in text for token in forbidden_imports):
            offenders.append(path.name)

    assert offenders == []


def test_stehle_registry_entry_does_not_promote_local_pattern_to_fingerprint():
    from kryptosbot.registries import KNOWN_ANOMALIES

    entry = next(a for a in KNOWN_ANOMALIES if a["anomaly_id"] == "stehle_delta5_lag4")
    text = f"{entry['title']} {entry['description']}".lower()

    assert "cipher fingerprint" not in text
    assert "weakness to exploit" not in text
    assert "not currently a hard cryptanalytic constraint" in text


def test_stehle_mechanism_audit_does_not_promote_pattern_to_constraint():
    from scripts.audit import audit_stehle_mechanisms as audit

    result = audit.run_audit()
    finite = {
        item["family"]: item
        for item in result["finite_family_falsifications"]
    }

    assert result["observed"]["deltas"] == [5, 5, 5, 5, 5]
    assert result["additive_leakage"]["constraint_on_noncrib_keystream"] is False
    assert finite["width21_same_row_lag4_forces_delta5"]["falsified"] is True
    assert finite["width21_same_row_lag4_forces_delta5"]["evidence"]["all_same_row_pairs_delta5"] is False
    assert finite["width21_same_row_lag4_forces_delta5"]["evidence"]["delta5_pair_count"] < finite["width21_same_row_lag4_forces_delta5"]["evidence"]["same_row_pair_count"]
    assert result["conclusion"]["hard_cryptanalytic_constraint"] is False
    assert result["conclusion"]["local_anomaly_no_current_exploit"] is True


def test_elimination_harness_accounting_audit_proves_resume_and_coverage():
    from scripts.audit import audit_elimination_harness_accounting as audit

    result = audit.run_audit()

    assert result["all_passed"] is True
    assert {h["id"] for h in result["harnesses"]} == {
        "h_624_73_nullmask",
        "h_pretransposition_layer",
        "h_624_nonword_key_schedule",
    }
    for harness in result["harnesses"]:
        assert harness["full"]["invariants"]["coverage_total_matches_inventory"] is True
        assert harness["full"]["invariants"]["coverage_tested_matches_audit_processed"] is True
        assert harness["partial"]["status"] == "INCONCLUSIVE_BUDGET"
        assert harness["resume"]["coverage"]["tested"] == harness["resume"]["coverage"]["total"]
        assert harness["resume_invariants"]["resume_audit_processed_matches_coverage"] is True
        assert harness["mismatch"]["invariants"]["hash_mismatch_refused"] is True


def test_provenance_live_surface_check_is_ci_clean():
    from scripts.audit import check_provenance_live_surfaces as check

    result = check.run_check()

    assert result["ok"] is True
    assert result["violations"] == []
    assert result["guard_checks"]["pantheon_guardrail_present"] is True
    assert result["guard_checks"]["api_bean_section_soft_context"] is True


def test_loaded_pantheon_agent_prompts_prepend_provenance_guardrail():
    from kryptosbot.pantheon import AgentSpec

    agent = AgentSpec(
        name="audit",
        description="desc",
        body="Use the null palette {B,G,I,K,O,W,Z} as proof.",
    )
    prompt = agent.system_prompt()

    assert "Project Provenance Guardrail" in prompt
    assert prompt.index("Project Provenance Guardrail") < prompt.index("Use the null palette")
    assert "must not be revived" in prompt
    assert ".claude/agent-memory/" in prompt
    assert "archival evidence only" in prompt


def test_pantheon_roster_does_not_load_archival_agent_memory_as_live_prompts():
    from kryptosbot.pantheon import load_roster

    repo = Path(__file__).resolve().parents[2]
    roster = load_roster(repo / ".claude" / "agents")

    assert roster
    assert all(spec.source_path is not None for spec in roster.values())
    assert all(".claude/agents" in spec.source_path.as_posix() for spec in roster.values())
    assert not any("agent-memory" in spec.source_path.as_posix() for spec in roster.values())


def test_api_prompt_does_not_call_bean_statistics_hard_constraints():
    from kryptosbot.api_client import K4_SYSTEM_PROMPT

    bean_section = K4_SYSTEM_PROMPT.split("## Bean 2021 Statistical Insights", 1)[1]

    assert "Soft Context, Not Constraints" in bean_section
    assert "not hard constraints" in bean_section
    assert "They constrain the substitution layer" not in bean_section


def test_live_claude_null_palette_surfaces_are_quarantined():
    repo = Path(__file__).resolve().parents[2]
    live_files = [
        ".claude/agents/keystream-forensics.md",
        ".claude/agents/stego-analyst.md",
        ".claude/skills/cipher-beaufort/SKILL.md",
        ".claude/skills/cipher-running-key-beaufort/SKILL.md",
        ".claude/skills/k4-stego-cracker/SKILL.md",
        ".claude/skills/otp-null-keystream-forensics/SKILL.md",
    ]

    for rel in live_files:
        text = (repo / rel).read_text(errors="replace").lower()
        assert "retired" in text, rel
        assert "hard constraint" in text, rel
        assert "must-explain" in text or "must explain" in text, rel

    combined = "\n".join((repo / rel).read_text(errors="replace") for rel in live_files)
    assert "strongest statistical signal linking" not in combined
