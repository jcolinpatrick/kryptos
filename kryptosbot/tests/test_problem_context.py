"""Tests for the ProblemContext gating layer.

ProblemContext is the single funnel that routes real-K4 registry /
anomaly / family / exhaustion access. The contract under test:

  - In ``mode=real_k4``, every accessor returns the live registry
    data (preserving prior behavior).
  - In ``mode=k4bench``, every accessor returns an empty container.
  - The accessors are the ONLY sanctioned path to real-K4 state from
    the controller / critic / dispatcher / display / prompt builders
    — anything else is a contamination bug.

Tests pin both directions: the empty-in-bench contract AND the
live-in-real-K4 contract, so a future change that flips the
direction is caught immediately.
"""

from __future__ import annotations

import os
import pytest

from kryptosbot.problem_context import (
    MODE_K4BENCH,
    MODE_REAL_K4,
    ProblemContext,
)


# ---------------------------------------------------------------------------
# Constructor invariants
# ---------------------------------------------------------------------------


def test_real_k4_constructor_sets_mode_and_no_bench_payload():
    pc = ProblemContext.real_k4()
    assert pc.mode == MODE_REAL_K4
    assert pc.is_real_k4 is True
    assert pc.is_bench is False
    assert pc.bench_payload is None
    assert pc.bench_prompt_block is None


def test_k4bench_constructor_requires_payload_and_prompt_block():
    payload = {
        "bench_id": "K4B-001",
        "suite_id": "K4BENCH-V1",
        "title": "Test",
        "ct_length": 97,
        "n_crib_chars": 24,
    }
    pc = ProblemContext.k4bench(payload=payload, prompt_block="block")
    assert pc.mode == MODE_K4BENCH
    assert pc.is_bench is True
    assert pc.is_real_k4 is False
    assert pc.bench_id == "K4B-001"


def test_k4bench_rejects_missing_payload():
    with pytest.raises(ValueError, match="bench_payload"):
        ProblemContext(mode=MODE_K4BENCH, bench_payload=None, bench_prompt_block="x")


def test_k4bench_rejects_missing_prompt_block():
    with pytest.raises(ValueError, match="bench_prompt_block"):
        ProblemContext(
            mode=MODE_K4BENCH, bench_payload={"bench_id": "x"}, bench_prompt_block=None,
        )


def test_real_k4_rejects_bench_payload():
    with pytest.raises(ValueError, match="must not carry"):
        ProblemContext(
            mode=MODE_REAL_K4,
            bench_payload={"bench_id": "leak"},
            bench_prompt_block=None,
        )


def test_invalid_mode_rejected():
    with pytest.raises(ValueError, match="ProblemContext.mode"):
        ProblemContext(mode="hybrid", bench_payload=None, bench_prompt_block=None)


def test_problem_context_is_frozen():
    pc = ProblemContext.real_k4()
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        pc.mode = MODE_K4BENCH


# ---------------------------------------------------------------------------
# Real-K4 mode: registry accessors return live data
# ---------------------------------------------------------------------------


def test_real_k4_standing_constraints_live():
    pc = ProblemContext.real_k4()
    sc = pc.standing_constraints()
    assert isinstance(sc, list)
    assert len(sc) > 0, (
        "real-K4 standing_constraints() must return the live "
        "STANDING_CONSTRAINTS registry, not an empty list"
    )


def test_real_k4_known_anomalies_live():
    pc = ProblemContext.real_k4()
    ka = pc.known_anomalies()
    assert isinstance(ka, list)
    assert len(ka) > 0, (
        "real-K4 known_anomalies() must return the live KNOWN_ANOMALIES "
        "registry"
    )


def test_real_k4_known_families_live():
    pc = ProblemContext.real_k4()
    kf = pc.known_families()
    assert isinstance(kf, list)
    assert len(kf) > 0


def test_real_k4_externally_evidenced_families_live():
    pc = ProblemContext.real_k4()
    eef = pc.externally_evidenced_families()
    assert isinstance(eef, frozenset)
    # At least the documented externally-evidenced families should
    # be present.
    assert "w_delimiter" in eef


def test_real_k4_admissible_prompt_anomaly_ids_live():
    pc = ProblemContext.real_k4()
    aid = pc.admissible_prompt_anomaly_ids()
    assert isinstance(aid, frozenset)
    assert len(aid) > 0


def test_real_k4_known_anomaly_ids_live():
    pc = ProblemContext.real_k4()
    kai = pc.known_anomaly_ids()
    assert isinstance(kai, set)
    assert len(kai) > 0


def test_real_k4_exhaustion_log_live():
    """Real-K4 mode reads the live exhaustion log (or {} if file missing).

    We do not assert non-empty here — the log file may be empty in a
    fresh checkout. The contract is "reads through to the file" not
    "returns non-empty".
    """
    pc = ProblemContext.real_k4()
    log = pc.exhaustion_log()
    assert isinstance(log, dict)


def test_real_k4_bench_accessors_empty():
    pc = ProblemContext.real_k4()
    assert pc.bench_context_dict() == {}
    assert pc.bench_prompt() == ""
    assert pc.bench_id is None


# ---------------------------------------------------------------------------
# K4Bench mode: every real-K4 accessor returns empty
# ---------------------------------------------------------------------------


def _make_bench_pc(bench_id: str = "K4B-001") -> ProblemContext:
    payload = {
        "bench_id": bench_id,
        "suite_id": "K4BENCH-V1",
        "title": "Synthetic Test",
        "ct_length": 97,
        "n_crib_chars": 24,
    }
    return ProblemContext.k4bench(
        payload=payload, prompt_block="(challenge prompt block)",
    )


def test_bench_standing_constraints_empty():
    pc = _make_bench_pc()
    assert pc.standing_constraints() == []


def test_bench_known_anomalies_empty():
    pc = _make_bench_pc()
    assert pc.known_anomalies() == []


def test_bench_known_families_empty():
    pc = _make_bench_pc()
    assert pc.known_families() == []


def test_bench_externally_evidenced_families_empty():
    pc = _make_bench_pc()
    assert pc.externally_evidenced_families() == frozenset()


def test_bench_admissible_prompt_anomaly_ids_empty():
    pc = _make_bench_pc()
    assert pc.admissible_prompt_anomaly_ids() == frozenset()


def test_bench_known_anomaly_ids_empty():
    pc = _make_bench_pc()
    assert pc.known_anomaly_ids() == set()


def test_bench_exhaustion_log_empty():
    pc = _make_bench_pc()
    assert pc.exhaustion_log() == {}


def test_bench_context_dict_carries_only_allowed_fields():
    pc = _make_bench_pc(bench_id="K4B-042")
    bc = pc.bench_context_dict()
    # Allow-list per the K4Bench isolation contract.
    expected_keys = {
        "bench_id",
        "suite_id",
        "title",
        "ct_length",
        "n_cribs",
        "synthetic_ledger_pin",
    }
    assert set(bc.keys()) == expected_keys
    assert bc["bench_id"] == "K4B-042"
    assert bc["ct_length"] == 97
    assert bc["n_cribs"] == 24
    # synthetic_ledger_pin is None until the controller injects it
    # from the bench-scoped ledger.
    assert bc["synthetic_ledger_pin"] is None


def test_bench_prompt_returns_block():
    payload = {
        "bench_id": "K4B-001",
        "suite_id": "K4BENCH-V1",
        "title": "T",
        "ct_length": 97,
        "n_crib_chars": 24,
    }
    pc = ProblemContext.k4bench(
        payload=payload, prompt_block="EXACT PROMPT TEXT"
    )
    assert pc.bench_prompt() == "EXACT PROMPT TEXT"


# ---------------------------------------------------------------------------
# Forbidden-string contract: bench accessors must never leak real-K4
# anomaly / family identifiers
# ---------------------------------------------------------------------------

# Same forbidden list as test_bench_mode_pipeline.py — duplicated
# intentionally so this test file is self-contained (the ProblemContext
# layer is the gate, so its tests must not depend on the surface
# tests for the gate-property contract).
_FORBIDDEN_REAL_K4_PHRASES = [
    "Width-21",
    "width-21",
    "width21",
    "W segmentation",
    "w_delimiter_segments",
    "He lied",
    "aaa_coordinate_lie",
    "compass cipher",
    "aaa_compass_cipher",
    "CT perturbation",
    "ct_perturbation",
    "K2 Coords",
    "k2_coords",
    "Geodetic",
    "geodetic",
    "Mirror KA",
    "mirror_ka",
    "Overlay",
    "Antipodes",
    "antipodes",
    "K3 continuity",
    "k3_continuity",
    "Archive Evidence",
    "archive_evidence",
    "null mask",
    "EASTNORTHEAST",
    "BERLINCLOCK",
    "PALIMPSEST",
    "ABSCISSA",
]


def test_bench_accessors_emit_no_real_k4_phrases():
    """Every bench-mode accessor's output, serialized, must be free of
    real-K4 anomaly/family identifier strings."""
    pc = _make_bench_pc()

    serialized = repr({
        "standing_constraints": pc.standing_constraints(),
        "known_anomalies": pc.known_anomalies(),
        "known_families": pc.known_families(),
        "externally_evidenced": list(pc.externally_evidenced_families()),
        "admissible_anom_ids": list(pc.admissible_prompt_anomaly_ids()),
        "known_anom_ids": list(pc.known_anomaly_ids()),
        "exhaustion_log": pc.exhaustion_log(),
        "bench_context": pc.bench_context_dict(),
        "bench_prompt": pc.bench_prompt(),
    })

    for phrase in _FORBIDDEN_REAL_K4_PHRASES:
        assert phrase not in serialized, (
            f"bench-mode ProblemContext accessor leaked real-K4 phrase "
            f"{phrase!r} in serialized output: "
            f"{serialized[:200]}..."
        )


# ---------------------------------------------------------------------------
# ControllerConfig integration: the .problem property is the seam
# ---------------------------------------------------------------------------


def test_controller_config_problem_returns_real_k4_by_default(tmp_path):
    from kryptosbot.controller import ControllerConfig

    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "ledger.sqlite",
    )
    assert cfg.problem.is_real_k4 is True
    assert cfg.problem.bench_id is None


def test_controller_config_problem_returns_bench_when_payload_set(tmp_path):
    from kryptosbot.controller import ControllerConfig

    payload = {
        "bench_id": "K4B-CFG-001",
        "suite_id": "K4BENCH-V1",
        "title": "Config Test",
        "ct_length": 97,
        "n_crib_chars": 24,
    }
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "k4bench" / "ledger.sqlite",
        bench_challenge_payload=payload,
        bench_challenge_prompt_block="BENCH PROMPT",
    )
    pc = cfg.problem
    assert pc.is_bench is True
    assert pc.is_real_k4 is False
    assert pc.bench_id == "K4B-CFG-001"
    assert pc.bench_prompt() == "BENCH PROMPT"
    # Real-K4 accessors are empty even though the live registries
    # are still importable in this process.
    assert pc.standing_constraints() == []
    assert pc.known_anomaly_ids() == set()
    assert pc.exhaustion_log() == {}
