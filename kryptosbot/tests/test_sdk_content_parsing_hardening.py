from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.models import TheoryRecord, WorkerStatus
from kryptosbot.pantheon import AgentSpec
from kryptosbot.pantheon_siblings import run_red_team_precheck


@dataclass
class FakeTextBlock:
    text: str
    type: str = "text"


@dataclass
class FakeThinkingBlock:
    thinking: str
    type: str = "thinking"


@dataclass
class FakeMessage:
    content: list[object]


def _make_controller(tmp_path: Path) -> ResearchController:
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "ledger.sqlite",
        worker_timeout_minutes=1,
    )
    return ResearchController(cfg)


def test_generate_theories_parses_textblock_content_and_records_success(
    tmp_path, monkeypatch,
):
    controller = _make_controller(tmp_path)
    monkeypatch.setattr(controller, "_build_theorist_prompt", lambda _: "prompt")

    theorist_json = json.dumps([
        {
            "title": "Geometry lead",
            "core_claim": "Compass geometry explains K4",
            "mechanism": "bounded geometric analysis",
            "family": "geometry",
            "dsl_spec": None,
        }
    ])

    async def fake_safe_query(*, prompt, options):
        assert prompt == "prompt"
        yield FakeMessage([
            FakeThinkingBlock("private"),
            FakeTextBlock(theorist_json),
        ])

    monkeypatch.setattr("kryptosbot.controller.safe_query", fake_safe_query)

    theories = asyncio.run(controller._generate_theories({}))

    assert len(theories) == 1
    assert theories[0].family == "geometry"
    assert controller.state.theorist_parse_successes == 1
    assert controller.state.theorist_fallbacks == 0
    assert controller.state.last_theorist_parse_diagnostics["parse_outcome"] == "success"


def test_generate_theories_partial_valid_output_does_not_fallback(
    tmp_path, monkeypatch,
):
    controller = _make_controller(tmp_path)
    monkeypatch.setattr(controller, "_build_theorist_prompt", lambda _: "prompt")

    theorist_json = json.dumps([
        {
            "title": "Valid geometry lead",
            "core_claim": "Compass geometry explains K4",
            "mechanism": "bounded geometric analysis",
            "family": "geometry",
            "dsl_spec": None,
        },
        {
            "title": "Invalid lead",
            "core_claim": "missing mechanism field",
            "family": "geometry",
            "dsl_spec": None,
        },
    ])

    async def fake_safe_query(*, prompt, options):
        yield FakeMessage([FakeTextBlock(theorist_json)])

    monkeypatch.setattr("kryptosbot.controller.safe_query", fake_safe_query)

    theories = asyncio.run(controller._generate_theories({}))

    assert len(theories) == 1
    assert theories[0].title == "Valid geometry lead"
    assert controller.state.theorist_parse_partial_successes == 1
    assert controller.state.theorist_fallbacks == 0
    assert controller.state.last_theorist_parse_diagnostics["invalid_count"] == 1


def test_generate_theories_suspicious_fallback_records_reason(
    tmp_path, monkeypatch,
):
    controller = _make_controller(tmp_path)
    monkeypatch.setattr(controller, "_build_theorist_prompt", lambda _: "prompt")

    theorist_json = json.dumps([
        {
            "title": "Broken lead",
            "core_claim": "missing required fields",
        }
    ])

    async def fake_safe_query(*, prompt, options):
        yield FakeMessage([FakeTextBlock(theorist_json)])

    monkeypatch.setattr("kryptosbot.controller.safe_query", fake_safe_query)
    monkeypatch.setattr(
        controller,
        "_programmatic_fallback",
        lambda landscape: [
            TheoryRecord(
                title="fallback",
                core_claim="fallback",
                mechanism="fallback",
                family="geometry",
            )
        ],
    )

    theories = asyncio.run(controller._generate_theories({}))

    assert len(theories) == 1
    diagnostics = controller.state.last_theorist_parse_diagnostics
    assert diagnostics["used_fallback"] is True
    assert diagnostics["fallback_reason"] == "model_returned_only_invalid_proposals"
    assert diagnostics["suspicious_fallback"] is True
    assert controller.state.theorist_fallback_reasons["model_returned_only_invalid_proposals"] == 1


def test_run_worker_legacy_parses_textblock_contract_output(
    tmp_path, monkeypatch,
):
    controller = _make_controller(tmp_path)
    monkeypatch.setattr(controller, "_build_worker_prompt", lambda theory: "worker prompt")
    monkeypatch.setattr(controller, "_cleanup_worker_artifacts", lambda theory, contract: None)

    payload = {
        "status": "inconclusive",
        "score": 0.0,
        "crib_score": 0,
        "bean_passed": False,
        "best_plaintext": "",
    }
    raw = f"```json\n{json.dumps(payload)}\n```"

    async def fake_safe_query(*, prompt, options):
        assert prompt == "worker prompt"
        yield FakeMessage([
            FakeThinkingBlock("private"),
            FakeTextBlock(raw),
        ])

    monkeypatch.setattr("kryptosbot.controller.safe_query", fake_safe_query)

    theory = TheoryRecord(
        title="Geometry worker",
        core_claim="c",
        mechanism="m",
        family="geometry",
    )
    controller.ledger.upsert_theory(theory)
    contract = asyncio.run(
        controller._run_worker_legacy(theory, tag="non_dsl_category")
    )

    assert contract.status == WorkerStatus.INCONCLUSIVE
    assert contract.worker_role == "agent_sdk_non_dsl_category"
    assert contract.error == ""


def test_redteam_precheck_parses_textblock_json_output(tmp_path, monkeypatch):
    async def fake_safe_query(*, prompt, options):
        yield FakeMessage([
            FakeThinkingBlock("private"),
            FakeTextBlock(json.dumps({
                "verdict": "reject",
                "confidence": 0.9,
                "reasons": ["bounded rehash"],
                "search_space_risk": "duplicate_family",
            })),
        ])

    monkeypatch.setattr("kryptosbot.pantheon_siblings.safe_query", fake_safe_query)

    theory = TheoryRecord(
        title="Key tape idea",
        core_claim="c",
        mechanism="m",
        family="key_tape",
    )
    redteam = AgentSpec(
        name="red-team-disprover",
        description="desc",
        body="body",
    )

    verdict = asyncio.run(
        run_red_team_precheck(
            theory,
            redteam_spec=redteam,
            project_root=tmp_path,
            allowed_tools=[],
            permission_mode="bypassPermissions",
        )
    )

    assert verdict.verdict == "reject"
    assert verdict.confidence == 0.9
    assert verdict.search_space_risk == "duplicate_family"
