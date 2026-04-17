from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.pantheon import AgentSpec
from kryptosbot.routing import (
    select_chancellor,
    select_pursuit_evaluator,
    select_redteam,
    select_results_analyst,
    select_stat_auditor,
    select_theorist,
    select_worker,
)


def _agent(name: str) -> AgentSpec:
    return AgentSpec(
        name=name,
        description=f"{name} description",
        body=f"{name} body",
    )


@pytest.fixture
def full_roster() -> dict[str, AgentSpec]:
    names = [
        "cryptanalyst",
        "escape-room-cryptanalyst",
        "stego-analyst",
        "archivist-historian",
        "keystream-forensics",
        "cipher-discovery-builder",
        "red-team-disprover",
        "statistical-auditor",
        "research-chancellor",
        "results-analyst",
    ]
    return {name: _agent(name) for name in names}


def test_select_theorist_starts_with_first_rotation_slot(full_roster):
    assert select_theorist(1, full_roster).name == "cryptanalyst"
    assert select_theorist(2, full_roster).name == "escape-room-cryptanalyst"
    assert select_theorist(6, full_roster).name == "cipher-discovery-builder"
    assert select_theorist(7, full_roster).name == "cryptanalyst"


def test_select_theorist_falls_back_to_cryptanalyst_when_preferred_missing(full_roster):
    del full_roster["escape-room-cryptanalyst"]
    assert select_theorist(2, full_roster).name == "cryptanalyst"


def test_select_worker_normalizes_family_names_before_dispatch(full_roster):
    assert select_worker("null mask", full_roster).name == "stego-analyst"
    assert select_worker("finite key tape", full_roster).name == "keystream-forensics"
    assert select_worker("crib/analysis", full_roster).name == "cryptanalyst"


def test_select_worker_falls_back_to_cryptanalyst_when_specialist_missing(full_roster):
    del full_roster["stego-analyst"]
    assert select_worker("null_mask", full_roster).name == "cryptanalyst"


def test_audit_and_synthesis_selectors_return_expected_personas(full_roster):
    assert select_redteam(full_roster).name == "red-team-disprover"
    assert select_stat_auditor(full_roster).name == "statistical-auditor"
    assert select_results_analyst(full_roster).name == "results-analyst"
    assert select_chancellor(full_roster).name == "research-chancellor"


def test_pursuit_evaluator_falls_back_to_chancellor(full_roster):
    del full_roster["results-analyst"]
    assert select_pursuit_evaluator(full_roster).name == "research-chancellor"


def test_optional_selectors_return_none_when_persona_missing(full_roster):
    del full_roster["red-team-disprover"]
    del full_roster["statistical-auditor"]
    del full_roster["results-analyst"]
    del full_roster["research-chancellor"]
    assert select_redteam(full_roster) is None
    assert select_stat_auditor(full_roster) is None
    assert select_results_analyst(full_roster) is None
    assert select_pursuit_evaluator(full_roster) is None
    assert select_chancellor(full_roster) is None
