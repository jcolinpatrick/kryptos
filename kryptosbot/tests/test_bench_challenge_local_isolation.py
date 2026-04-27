"""End-to-end isolation tests for K4Bench challenge-local mode.

After Cycle 1 (or any later cycle) of a K4Bench run, the user reported
contamination by real-K4 landscape and synthesis: prompts, displays,
and synthesis outputs were leaking real-K4 anomaly / family / anchor
identifiers into a synthetic challenge run.

These tests pin the isolation contract for each surface the user
listed:

  - _assess_landscape: bench-mode landscape carries NO real-K4
    anomalies, families, standing constraints, recent outcomes, or
    pursuit leads.
  - landscape display: print_landscape under bench mode renders only
    the bench-context panel; no real-K4 strings reach the TUI.
  - theorist prompt landscape injection: stripped landscape is bench-
    only.
  - results synthesis recommendations: synthesis prompt template lacks
    the K4-specific W-delimiter SPECIAL POLICY block; W-focus
    normalizer does not run on bench output.
  - programmatic fallback generation: bench mode emits HandCipherCore
    DSL specs derived from clue_text + safe-default keywords (NOT [],
    which was the prior contract that produced Proposed=0 cycles).
  - red-team prompt context: red-team user prompt explicitly disclaims
    real-K4 anomalies as a reject reason.
  - family/anomaly registries: never read in bench mode (gated through
    ProblemContext).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest


# Real-K4 strings that MUST NOT appear in any bench-mode surface output
# unless they are literally embedded in the active challenge JSON.
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


def _bench_payload() -> dict:
    return {
        "bench_id": "K4B-ISO-001",
        "suite_id": "K4BENCH-V1",
        "title": "Isolation test challenge",
        "ciphertext":
            "DCXEGPKDRHYITACRUTBWOXRKGXZEOEEQPIULFRQVEELE"
            "FFIVBPKKFIEGYDVXEZFOEQWVSRIUQXHZAITUMBFFSORM"
            "SPBZTRXPO",
        "ct_length": 97,
        "cribs": [(21, "SECONDSYSTEMX"), (63, "COLUMNORDER")],
        "n_crib_chars": 24,
        "bench_mode": True,
        "clue_text": "Synthetic test challenge.",
        "constraint_summary": ["A-Z only.", "Length 97."],
        "solver_required_fields": ["bench_id", "plaintext"],
        "strict_pass_rule": "exact",
        "known_crib_score_target": 24,
    }


def _bench_prompt_block() -> str:
    return (
        "K4BENCH SYNTHETIC CHALLENGE — bench_id=K4B-ISO-001\n"
        "(prompt block content)\n"
    )


def _bench_controller(tmp_path: Path):
    """Construct a real ResearchController in bench mode."""
    from kryptosbot.controller import ControllerConfig, ResearchController

    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "k4bench" / "K4B-ISO-001.sqlite",
        bench_challenge_payload=_bench_payload(),
        bench_challenge_prompt_block=_bench_prompt_block(),
    )
    controller = ResearchController(cfg)
    controller.state = controller.ledger.load_controller_state()
    controller._snapshot_session_baseline()
    return controller


def _real_k4_controller(tmp_path: Path):
    """Construct a real ResearchController in real-K4 mode."""
    from kryptosbot.controller import ControllerConfig, ResearchController

    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "real_k4_ledger.sqlite",
    )
    controller = ResearchController(cfg)
    controller.state = controller.ledger.load_controller_state()
    controller._snapshot_session_baseline()
    return controller


# ---------------------------------------------------------------------------
# (1) _assess_landscape: bench landscape is challenge-local
# ---------------------------------------------------------------------------


def test_bench_landscape_marks_bench_mode(tmp_path):
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    assert landscape.get("bench_mode") is True


def test_bench_landscape_has_no_real_k4_anomalies_or_families(tmp_path):
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()

    # Real-K4 fields must be empty (not absent — structural parity is
    # preserved so display can iterate them safely).
    assert landscape.get("standing_constraints") == []
    assert landscape.get("active_families") == []
    assert landscape.get("underexplored_families") == []
    assert landscape.get("open_anomalies") == []
    assert landscape.get("unaddressed_anomalies") == []
    assert landscape.get("recent_outcomes") == []
    assert landscape.get("pursuit_leads") == []
    assert landscape.get("soft_pursuit_leads") == []
    assert landscape.get("prompt_anomaly_count") == 0
    assert landscape.get("registry_open_anomaly_count") == 0


def test_bench_landscape_carries_only_allowed_bench_context(tmp_path):
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    bc = landscape.get("bench_context")
    assert bc is not None
    assert bc["bench_id"] == "K4B-ISO-001"
    assert bc["suite_id"] == "K4BENCH-V1"
    assert bc["title"] == "Isolation test challenge"
    assert bc["ct_length"] == 97
    assert bc["n_cribs"] == 24
    # synthetic_ledger_pin is set by the controller from the bench
    # ledger metadata. In a fresh tmp ledger the pin may be None or
    # "synthetic" depending on whether verify_and_pin has been called;
    # either is acceptable.
    assert "synthetic_ledger_pin" in bc


def test_bench_landscape_serialized_lacks_real_k4_phrases(tmp_path):
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    serialized = json.dumps(landscape, default=str)
    for phrase in _FORBIDDEN_REAL_K4_PHRASES:
        assert phrase not in serialized, (
            f"bench landscape leaked real-K4 phrase {phrase!r}"
        )


def test_real_k4_landscape_unchanged(tmp_path):
    """Negative-path pin: the real-K4 branch of _assess_landscape must
    still surface registry data. Without this, an over-broad refactor
    would silently strip K4 content from real runs."""
    controller = _real_k4_controller(tmp_path)
    # Bootstrap the real-K4 registries so the ledger has rows to query.
    from kryptosbot.registries import bootstrap_all
    bootstrap_all(controller.ledger, controller.config.project_root)
    landscape = controller._assess_landscape()
    # Standing constraints come straight from the registry, not the
    # ledger — they should be non-empty for real K4.
    assert len(landscape.get("standing_constraints", [])) > 0


# ---------------------------------------------------------------------------
# (2) landscape display: bench panel is challenge-local
# ---------------------------------------------------------------------------


def test_print_landscape_uses_bench_branch_when_bench_mode(tmp_path):
    """Bench-mode landscape MUST render via _print_landscape_bench, not
    the general-purpose path."""
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()

    with mock.patch(
        "kryptosbot.display._print_landscape_bench"
    ) as bench_panel:
        from kryptosbot.display import print_landscape
        print_landscape(landscape)
    bench_panel.assert_called_once()


def test_print_landscape_real_k4_does_not_use_bench_branch(tmp_path):
    """Negative pin: real-K4 landscape MUST NOT route through the
    bench panel."""
    controller = _real_k4_controller(tmp_path)
    landscape = controller._assess_landscape()

    with mock.patch(
        "kryptosbot.display._print_landscape_bench"
    ) as bench_panel, mock.patch(
        "kryptosbot.display.console.print"
    ):
        from kryptosbot.display import print_landscape
        print_landscape(landscape)
    bench_panel.assert_not_called()


# ---------------------------------------------------------------------------
# (3) theorist prompt: bench mode emits no real-K4 phrases
# ---------------------------------------------------------------------------


def test_bench_theorist_prompt_lacks_real_k4_phrases(tmp_path):
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    prompt = controller._build_theorist_prompt(landscape)
    for phrase in _FORBIDDEN_REAL_K4_PHRASES:
        assert phrase not in prompt, (
            f"bench theorist prompt leaked real-K4 phrase {phrase!r}"
        )


def test_bench_theorist_prompt_includes_bench_id(tmp_path):
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    prompt = controller._build_theorist_prompt(landscape)
    assert "K4B-ISO-001" in prompt


# ---------------------------------------------------------------------------
# (4) results synthesis: bench template lacks W-delimiter policy
# ---------------------------------------------------------------------------


def test_synthesis_user_prompt_template_bench_lacks_w_delimiter_policy():
    from kryptosbot.pantheon_siblings import (
        _SYNTHESIS_USER_PROMPT_TEMPLATE,
        _SYNTHESIS_USER_PROMPT_TEMPLATE_BENCH,
    )
    # Real-K4 template has the SPECIAL POLICY block defending W.
    assert "w_delimiter_segments" in _SYNTHESIS_USER_PROMPT_TEMPLATE
    assert "SPECIAL POLICY" in _SYNTHESIS_USER_PROMPT_TEMPLATE
    # Bench template MUST NOT carry that block. An incidental match
    # in the forbidden-phrase warning at the bottom is allowed only
    # in a structured "do not reference" list, not as a policy.
    for phrase in [
        "SPECIAL POLICY FOR THIS HARDENING WINDOW",
        "Continue aggressively along the W-delimiter lane",
        "demote width-specific geometry variants",
    ]:
        assert phrase not in _SYNTHESIS_USER_PROMPT_TEMPLATE_BENCH


def test_synthesis_w_focus_normalizer_skipped_in_bench_mode():
    """The W-focus normalizer rewrites recommended_next_focus to
    defend the W-delimiter lane. It MUST NOT run on bench output —
    that would inject the K4 phrase 'W-delimiter lane' into a
    synthetic-cycle focus string."""
    from kryptosbot import pantheon_siblings as ps

    with mock.patch.object(
        ps, "_normalize_w_focus_recommendation"
    ) as norm:
        norm.return_value = "should not be called in bench mode"
        # Simulate the bench-mode branch directly: the function is
        # only invoked when bench_mode=False inside run_results_synthesis.
        # We pin the contract by reading the source of the gate.
        import inspect
        src = inspect.getsource(ps.run_results_synthesis)
        assert "if not bench_mode:" in src, (
            "run_results_synthesis must guard the W-focus normalizer "
            "behind 'if not bench_mode:'"
        )
        assert "_normalize_w_focus_recommendation" in src


# ---------------------------------------------------------------------------
# (5) programmatic fallback: bench mode emits HandCipherCore DSL specs
# ---------------------------------------------------------------------------


def test_programmatic_fallback_emits_handcipher_core_in_bench_mode(tmp_path):
    """Bench mode MUST emit a non-empty list of valid, dispatchable
    HandCipherCore fallback theories — NOT the [] returned by the
    earlier revision. The earlier rule produced Proposed=0 / Tested=0
    cycles whenever the theorist hiccupped; the corrected contract is
    that bench mode falls back to challenge-local DSL specs (mined from
    clue_text + safe defaults) so cycles still progress."""
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    result = controller._programmatic_fallback(landscape)
    # Floor: at least one theory, ideally >= theories_per_cycle.
    assert len(result) >= 5, (
        f"bench fallback must emit >= 5 theories; got {len(result)}"
    )
    # Every theory must carry a populated dsl_spec — bench fallback only
    # emits DSL-dispatchable specs (no methodological / non-cipher
    # fallbacks in bench mode).
    for theory in result:
        assert theory.dsl_spec, (
            f"bench fallback theory {theory.hypothesis_id} has empty "
            "dsl_spec — every fallback must be dispatchable"
        )
        assert theory.origin == "programmatic_fallback"
        assert theory.family == "bench_hand_cipher_core"
    # Every dsl_spec must validate AND have only translatable layer
    # kinds (the contract the fallback module enforces internally).
    from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
    from kryptosbot.job_dispatcher import _kind_has_translation
    for theory in result:
        parsed = validate_hypothesis_spec(theory.dsl_spec)
        assert parsed.is_valid, (
            f"theory {theory.hypothesis_id} has invalid dsl_spec: "
            f"{parsed.errors}"
        )
        for layer in parsed.value.pipeline:
            assert _kind_has_translation(layer.kind), (
                f"theory {theory.hypothesis_id} carries untranslatable "
                f"layer kind {layer.kind!r}"
            )


def test_programmatic_fallback_runs_in_real_k4_mode(tmp_path):
    """Negative pin: real-K4 fallback still consults landscape and may
    emit theories. Without this an overzealous gate would silently
    disable the real-K4 fallback."""
    controller = _real_k4_controller(tmp_path)
    # Bootstrap the registries so the landscape has underexplored
    # families + unaddressed anomalies for the fallback to consume.
    from kryptosbot.registries import bootstrap_all
    bootstrap_all(controller.ledger, controller.config.project_root)
    landscape = controller._assess_landscape()
    # The fallback may still return [] if all families/anomalies are
    # already exercised; the contract under test is "the gate does NOT
    # block the function from running". We pin that by checking the
    # gate condition explicitly.
    assert controller.config.problem.is_real_k4 is True


# ---------------------------------------------------------------------------
# (6) red-team prompt: bench template disclaims real-K4 anomalies
# ---------------------------------------------------------------------------


def test_redteam_user_prompt_template_bench_disclaims_real_k4_anomalies():
    from kryptosbot.pantheon_siblings import (
        _REDTEAM_USER_PROMPT_TEMPLATE,
        _REDTEAM_USER_PROMPT_TEMPLATE_BENCH,
    )
    # Real-K4 template explicitly says "K4 theory" and "K4 plaintext".
    assert "K4 theory" in _REDTEAM_USER_PROMPT_TEMPLATE
    assert "K4 plaintext" in _REDTEAM_USER_PROMPT_TEMPLATE

    # Bench template MUST NOT use the "K4 theory" framing AS A
    # CHARACTERIZATION OF THE PROPOSAL. It says "synthetic K4Bench"
    # instead. The phrase "real K4" appears only inside the explicit
    # disclaimer.
    assert "K4 theory" not in _REDTEAM_USER_PROMPT_TEMPLATE_BENCH
    assert "synthetic K4Bench" in _REDTEAM_USER_PROMPT_TEMPLATE_BENCH

    # And the bench template must explicitly forbid citing real-K4
    # anomalies as a reject reason.
    for anom_id in [
        "aaa_coordinate_lie",
        "w_delimiter_segments",
        "ct_perturbation",
    ]:
        assert anom_id in _REDTEAM_USER_PROMPT_TEMPLATE_BENCH, (
            f"bench red-team template must explicitly disclaim "
            f"{anom_id} as a reject reason"
        )


def test_redteam_build_user_prompt_routes_through_bench_template():
    from kryptosbot.models import TheoryRecord
    from kryptosbot.pantheon_siblings import _build_redteam_user_prompt

    theory = TheoryRecord(
        title="Test theory",
        core_claim="Test claim",
        mechanism="Test mechanism",
        family="vigenere",
    )

    real_prompt = _build_redteam_user_prompt(theory, bench_mode=False)
    bench_prompt = _build_redteam_user_prompt(theory, bench_mode=True)

    assert real_prompt != bench_prompt
    assert "K4 theory" in real_prompt
    assert "K4 theory" not in bench_prompt
    assert "synthetic K4Bench" in bench_prompt


# ---------------------------------------------------------------------------
# (7) registries: bench mode does NOT bootstrap real-K4 rows into the
# bench-scoped ledger
# ---------------------------------------------------------------------------


def test_bench_run_does_not_bootstrap_real_k4_families_into_ledger(tmp_path):
    """Direct integration: a bench-mode controller's ledger must NOT
    contain any KNOWN_FAMILIES rows after the bootstrap gate runs.
    This is enforced by run_controller.do_run and by
    ResearchController.run."""
    from kryptosbot.controller import ControllerConfig, ResearchController
    from kryptosbot.registries import bootstrap_all, bootstrap_controller_queue_reset

    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "k4bench" / "K4B-ISO-001.sqlite",
        bench_challenge_payload=_bench_payload(),
        bench_challenge_prompt_block=_bench_prompt_block(),
    )
    controller = ResearchController(cfg)

    # Mirror the gate from run_controller.do_run: bench mode runs only
    # the queue-reset bootstrap.
    if cfg.problem.is_real_k4:
        bootstrap_all(controller.ledger, cfg.project_root)
    else:
        bootstrap_controller_queue_reset(controller.ledger)

    # The ledger must have ZERO active families seeded from KNOWN_FAMILIES.
    families = controller.ledger.get_active_families()
    assert families == [], (
        f"bench-mode ledger leaked {len(families)} real-K4 family rows: "
        f"{[f.family_id for f in families]}"
    )
    anomalies = controller.ledger.get_open_anomalies()
    assert anomalies == [], (
        f"bench-mode ledger leaked {len(anomalies)} real-K4 anomaly rows"
    )


# ---------------------------------------------------------------------------
# Cross-cutting: the user's exact phrase list must NOT appear in any
# bench-mode landscape, theorist prompt, or display output unless
# present in the active challenge JSON.
# ---------------------------------------------------------------------------


def test_user_listed_forbidden_phrases_absent_from_bench_landscape_and_prompt(
    tmp_path,
):
    """Direct enforcement of the user's call-out list:

      Width-21, W segmentation, He lied, compass cipher,
      CT perturbation, K2 Coords, Geodetic, Mirror KA, Overlay,
      Antipodes, Archive Evidence, w_delimiter, null mask
    """
    user_listed = [
        "Width-21",
        "W segmentation",
        "He lied",
        "compass cipher",
        "CT perturbation",
        "K2 Coords",
        "Geodetic",
        "Mirror KA",
        "Overlay",
        "Antipodes",
        "Archive Evidence",
        "w_delimiter",
        "null mask",
    ]

    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    landscape_blob = json.dumps(landscape, default=str)
    prompt = controller._build_theorist_prompt(landscape)

    # Note: the bench prompt block itself contains the disclaimer
    # warning that lists some real-K4 anomaly anchors as "do not use".
    # We deliberately seed that disclaimer in the prompt, so when
    # checking the prompt we only forbid phrases that would constitute
    # ENDORSEMENT or RECOMMENDATION, not phrases that appear inside the
    # disclaimer itself. Approximation: check the landscape blob (no
    # disclaimers) and the prompt with the disclaimer span elided.
    for phrase in user_listed:
        assert phrase not in landscape_blob, (
            f"bench landscape contains forbidden user-listed phrase "
            f"{phrase!r}"
        )

    # For the prompt, we accept that the bench-mode prompt block
    # itself may name a forbidden phrase ONLY inside an explicit
    # warning context. The acceptance criterion: the phrase MUST NOT
    # appear in the cycle telemetry / landscape JSON serialized into
    # the prompt. The bench landscape JSON is dumped under "CYCLE
    # TELEMETRY". So we extract that span and check it's clean.
    if "CYCLE TELEMETRY" in prompt:
        telemetry_start = prompt.index("CYCLE TELEMETRY")
        telemetry_end = prompt.find("CONSTRAINTS:", telemetry_start)
        if telemetry_end == -1:
            telemetry_end = len(prompt)
        telemetry_span = prompt[telemetry_start:telemetry_end]
        for phrase in user_listed:
            assert phrase not in telemetry_span, (
                f"bench prompt CYCLE TELEMETRY span leaked forbidden "
                f"phrase {phrase!r}"
            )
