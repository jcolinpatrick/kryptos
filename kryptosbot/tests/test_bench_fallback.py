"""K4Bench HandCipherCore fallback acceptance tests.

Pins the contract introduced 2026-04-26 v2: when the K4Bench theorist
returns invalid output, ``ResearchController._programmatic_fallback``
MUST emit a non-empty list of validated, dispatchable DSL specs. The
prior revision returned ``[]`` in bench mode and produced Proposed=0 /
Tested=0 cycles whenever the theorist hiccupped.

The tests cover:

  1. Pure module: ``hand_cipher_core_fallback`` emits >= 5 valid DSL
     specs from a K4B-001-shaped payload. Every spec validates and
     every layer kind has a dispatcher translation.
  2. Pure module: empty / clue-less payloads still produce a working
     catalogue from the safe-default keyword pool.
  3. Controller integration: ``_programmatic_fallback`` in bench mode
     returns the same HandCipherCore catalogue (gated on
     ``problem.is_real_k4 is False``).
  4. End-to-end: at least one bench fallback spec dispatches via
     ``execute(bench_mode=True)`` with ``total_tested > 0``.
  5. Empty-theorist-output round-trip: a deliberately-invalid raw
     theorist string parses to zero valid theories, then the fallback
     is invoked and emits a non-empty dispatchable list.

These tests do not call out to the SDK and do not require API keys.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from kryptosbot.bench_fallback import (
    _extract_clue_keywords,
    _resolve_keyword_pool,
    hand_cipher_core_fallback,
)
from kryptosbot.contracts import validate_theory_proposals
from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
from kryptosbot.job_dispatcher import _kind_has_translation, execute
from kryptosbot.models import TheoryRecord


# K4B-001-shape inline payload (matches bench/k4bench/challenges/K4B-001.json
# without taking a runtime dependency on the file).
_BENCH_CT = (
    "DCXEGPKDRHYITACRUTBWO"
    "XRKGXZEOEEQPI"
    "ULFRQVEELEFFIVBPKKFIEGYDVXEZFOEQ"
    "WVSRIUQXHZA"
    "ITUMBFFSORMSPBZTRXPO"
)
assert len(_BENCH_CT) == 97

_K4B001_PAYLOAD: dict[str, Any] = {
    "ciphertext": _BENCH_CT,
    "ct_length": 97,
    "cribs": [(21, "SECONDSYSTEMX"), (63, "COLUMNORDER")],
    "n_crib_chars": 24,
    "bench_mode": True,
    "bench_id": "K4B-001",
    "suite_id": "K4BENCH-2026-04-26-V1",
    "title": "Lantern over cedar",
    "clue_text": (
        "A field sketch labels two objects: CEDAR posts below a LANTERN. "
        "Seven post marks appear in the margin."
    ),
    "constraint_summary": ["A-Z only.", "Length 97."],
    "solver_required_fields": ["bench_id", "plaintext"],
    "strict_pass_rule": "exact",
    "known_crib_score_target": 24,
}


_K4B001_PROMPT_BLOCK = (
    "K4BENCH SYNTHETIC CHALLENGE — bench_id=K4B-001\n"
    f"CIPHERTEXT: {_BENCH_CT}\n"
    "CRIB SPANS: SECONDSYSTEMX @ 21-33; COLUMNORDER @ 63-73\n"
    "PUBLIC CLUE TEXT: A field sketch ... CEDAR ... LANTERN ...\n"
)


# ---------------------------------------------------------------------------
# (1) Pure module: HandCipherCore catalogue from K4B-001
# ---------------------------------------------------------------------------


def test_hand_cipher_core_emits_at_least_five_validated_specs():
    """Acceptance: with a K4B-001-shaped payload the fallback emits at
    least 5 theories; every theory has a dsl_spec that validates and
    every layer kind has a dispatcher translation."""
    theories = hand_cipher_core_fallback(_K4B001_PAYLOAD, n_target=5)
    assert len(theories) >= 5, (
        f"floor violated: {len(theories)} theories from K4B-001 payload"
    )
    # Spec-shape contract.
    for t in theories:
        assert isinstance(t, TheoryRecord)
        assert t.dsl_spec, f"theory {t.hypothesis_id} has empty dsl_spec"
        assert t.origin == "programmatic_fallback"
        assert t.family == "bench_hand_cipher_core"
        parsed = validate_hypothesis_spec(t.dsl_spec)
        assert parsed.is_valid, (
            f"theory {t.hypothesis_id} dsl_spec failed validation: "
            f"{parsed.errors}"
        )
        for layer in parsed.value.pipeline:
            assert _kind_has_translation(layer.kind), (
                f"theory {t.hypothesis_id} has untranslatable layer "
                f"kind {layer.kind!r}"
            )


def test_hand_cipher_core_uses_clue_anchor_words_when_present():
    """Acceptance: ALL-CAPS clue-text words (CEDAR, LANTERN on K4B-001)
    must surface as keys in the catalogue. The K4Bench challenge
    convention is to capitalize the intended anchor words; the fallback
    prioritizes those above the safe default pool."""
    theories = hand_cipher_core_fallback(_K4B001_PAYLOAD, n_target=5)
    keywords_used: set[str] = set()
    for t in theories:
        for layer in t.dsl_spec.get("pipeline", []):
            for param in layer.get("params", []):
                if param.get("name") == "keyword":
                    for v in param.get("values", []):
                        keywords_used.add(str(v).upper())
    # At least one of CEDAR / LANTERN should appear in keywords used.
    assert keywords_used & {"CEDAR", "LANTERN"}, (
        f"clue anchors CEDAR/LANTERN missing from fallback keys; "
        f"got {keywords_used}"
    )


def test_hand_cipher_core_covers_diverse_cipher_kinds():
    """Acceptance: the catalogue exercises the supported cipher kinds
    called out in the brief — vigenere, beaufort, variant_beaufort,
    columnar, rail_fence, route, myszkowski, quagmire, plus at least
    one two-layer combination."""
    theories = hand_cipher_core_fallback(_K4B001_PAYLOAD, n_target=5)

    kinds_seen: set[str] = set()
    multilayer_seen = False
    for t in theories:
        layer_kinds = [
            layer["kind"] for layer in t.dsl_spec.get("pipeline", [])
        ]
        kinds_seen.update(layer_kinds)
        if len(layer_kinds) >= 2:
            multilayer_seen = True

    expected_kinds = {
        "vigenere", "beaufort", "variant_beaufort",
        "columnar", "rail_fence", "myszkowski", "route", "quagmire",
    }
    missing = expected_kinds - kinds_seen
    assert not missing, f"catalogue missing cipher kinds: {missing}"
    assert multilayer_seen, "catalogue missing any two-layer composition"


def test_hand_cipher_core_emits_specs_with_distinct_hypothesis_ids():
    """Each catalogue entry has a unique hypothesis_id so the ledger's
    primary-key uniqueness invariant holds."""
    theories = hand_cipher_core_fallback(_K4B001_PAYLOAD, n_target=5)
    ids = [t.hypothesis_id for t in theories]
    assert len(ids) == len(set(ids)), (
        f"duplicate hypothesis_ids in catalogue: {ids}"
    )


def test_hand_cipher_core_deterministic_for_same_payload():
    """Same payload → same catalogue (pure function). Stable IDs are
    needed so the controller's ledger-existence dedup works."""
    a = hand_cipher_core_fallback(_K4B001_PAYLOAD, n_target=5)
    b = hand_cipher_core_fallback(_K4B001_PAYLOAD, n_target=5)
    assert [t.hypothesis_id for t in a] == [t.hypothesis_id for t in b]


# ---------------------------------------------------------------------------
# (2) Pure module: degraded payloads still emit a working catalogue
# ---------------------------------------------------------------------------


def test_hand_cipher_core_handles_empty_payload():
    """Empty payload (no clue_text, no title) falls back to the safe
    default keyword pool and still emits a valid catalogue."""
    theories = hand_cipher_core_fallback({}, n_target=5)
    assert len(theories) >= 5
    # Specs still validate.
    for t in theories:
        parsed = validate_hypothesis_spec(t.dsl_spec)
        assert parsed.is_valid, parsed.errors


def test_hand_cipher_core_handles_clueless_payload():
    """Payload with title only (no clue_text) still emits a catalogue
    using the title as the keyword pool seed."""
    theories = hand_cipher_core_fallback(
        {"bench_id": "K4B-099", "title": "BLANK CHALLENGE"},
        n_target=5,
    )
    assert len(theories) >= 5


def test_extract_clue_keywords_drops_stopwords_and_short_tokens():
    """Pure-function unit test on the keyword extractor."""
    payload = {
        "clue_text": "The CEDAR is a tree. The LANTERN sits on POSTS.",
        "title": "A test",
    }
    kws = _extract_clue_keywords(payload)
    # ALL-CAPS anchors come first.
    assert kws[:2] == ["CEDAR", "LANTERN"]
    # Stopwords are dropped: "the", "is" both excluded.
    assert "THE" not in kws
    assert "IS" not in kws


def test_resolve_keyword_pool_always_returns_minimum():
    """Even when the payload yields no clue-mined keywords, the pool
    contract is len >= minimum (default 4)."""
    pool = _resolve_keyword_pool({}, minimum=4)
    assert len(pool) >= 4


# ---------------------------------------------------------------------------
# (3) Controller integration: bench-mode _programmatic_fallback emits
# ---------------------------------------------------------------------------


def _bench_controller(tmp_path: Path) -> ResearchController:
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "k4bench" / "fallback-test.sqlite",
        max_cycles=1,
        theories_per_cycle=5,
        dry_run=True,
        bench_challenge_payload=_K4B001_PAYLOAD,
        bench_challenge_prompt_block=_K4B001_PROMPT_BLOCK,
        include_oranchak_corpora=False,
        include_serpentine_anchor=False,
    )
    controller = ResearchController(cfg)
    controller.state = controller.ledger.load_controller_state()
    controller._snapshot_session_baseline()
    return controller


def test_controller_programmatic_fallback_in_bench_mode_returns_specs(tmp_path):
    """Acceptance: in bench mode, ``_programmatic_fallback`` emits the
    HandCipherCore catalogue. This is the controller-level fix to the
    Proposed=0 regression — the prior gate returned [] here."""
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    result = controller._programmatic_fallback(landscape)
    assert len(result) >= 5, (
        f"bench fallback emitted {len(result)} theories; expected >= 5"
    )
    for theory in result:
        assert theory.dsl_spec
        assert theory.origin == "programmatic_fallback"
        assert theory.family == "bench_hand_cipher_core"


def test_controller_programmatic_fallback_real_k4_unchanged(tmp_path):
    """Negative pin: real-K4 mode does NOT route to HandCipherCore.
    The bench fallback path is gated on ``problem.is_real_k4 is False``;
    real-K4 controllers must still see the original
    underexplored_families / unaddressed_anomalies generator. This test
    pins the gate by checking that no real-K4 fallback theory carries
    the bench family label."""
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "real_k4_test.sqlite",
        max_cycles=1,
        theories_per_cycle=5,
        dry_run=True,
    )
    controller = ResearchController(cfg)
    controller.state = controller.ledger.load_controller_state()
    controller._snapshot_session_baseline()
    landscape = controller._assess_landscape()
    result = controller._programmatic_fallback(landscape)
    # May be empty (depends on registry bootstrap state), but if any
    # entries exist they MUST NOT carry the bench family label.
    for theory in result:
        assert theory.family != "bench_hand_cipher_core", (
            "real-K4 fallback emitted a bench HandCipherCore theory; "
            "the bench gate is leaking into real-K4 mode"
        )


# ---------------------------------------------------------------------------
# (4) End-to-end: a fallback spec dispatches with total_tested > 0
# ---------------------------------------------------------------------------


def test_bench_fallback_spec_dispatches_end_to_end(tmp_path):
    """Acceptance: pluck the first HandCipherCore spec, hand it to
    ``execute(bench_mode=True)``, and confirm total_tested > 0. This is
    the ultimate end-to-end test the brief calls out: when the theorist
    fails in bench mode, fallback specs must actually reach the kernel
    and produce a non-zero ``total_tested`` count."""
    theories = hand_cipher_core_fallback(_K4B001_PAYLOAD, n_target=5)
    assert theories, "fallback emitted nothing — cannot dispatch"

    # Pick the first single-layer Vigenere spec (cheapest to dispatch
    # under parallel=False; the test should finish in well under a
    # second).
    target = None
    for t in theories:
        layers = t.dsl_spec.get("pipeline", [])
        if len(layers) == 1 and layers[0].get("kind") == "vigenere":
            target = t
            break
    assert target is not None, "no single-layer vigenere fallback found"

    parsed = validate_hypothesis_spec(target.dsl_spec)
    assert parsed.is_valid, parsed.errors
    spec = parsed.value

    artifact_root = tmp_path / "fallback_dispatch"
    result = execute(
        spec,
        artifact_root=artifact_root,
        parallel=False,
        bench_mode=True,
    )
    assert result.admissibility_verdict == "ok", (
        f"fallback spec rejected at admissibility: "
        f"{result.admissibility_reasons}"
    )
    assert result.total_tested > 0, (
        f"fallback spec produced total_tested={result.total_tested}; "
        "spec did not actually reach the kernel"
    )


# ---------------------------------------------------------------------------
# (5) Round-trip: invalid theorist output → fallback emits dispatchable
# ---------------------------------------------------------------------------


def test_invalid_theorist_output_routes_to_fallback_with_dispatchable_specs(tmp_path):
    """Acceptance: simulate the failure mode the brief describes —
    theorist returns 5 JSON-like-but-invalid proposals. Confirm that:
      a) the validator parses zero valid theories from the raw output;
      b) the controller's fallback then emits a non-empty list;
      c) every fallback theory carries a translatable dsl_spec.

    This is the exact regression the brief was filed against:
    ``Proposed=0 and Tested=0`` after a bad theorist response in bench
    mode."""
    # Step (a): invalid raw output. Each item is missing required
    # fields (no core_claim / mechanism / family) so the validator
    # rejects all five.
    invalid_raw = """[
      {"title": "noise"},
      {"title": "more noise"},
      {"title": "still nothing"},
      {"title": "nope"},
      {"title": "zero"}
    ]"""
    report = validate_theory_proposals(invalid_raw)
    assert report.valid == [], (
        f"fixture expected zero valid theories from invalid raw; "
        f"got {len(report.valid)}"
    )
    assert len(report.invalid) == 5

    # Step (b): controller's bench-mode fallback runs and emits.
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    fallback_theories = controller._programmatic_fallback(landscape)
    assert len(fallback_theories) >= 5, (
        f"fallback emitted {len(fallback_theories)} after invalid "
        "theorist output; expected >= 5"
    )

    # Step (c): every fallback theory is dispatchable.
    for theory in fallback_theories:
        parsed = validate_hypothesis_spec(theory.dsl_spec)
        assert parsed.is_valid, (
            f"fallback theory {theory.hypothesis_id} dsl_spec failed "
            f"validation: {parsed.errors}"
        )
        for layer in parsed.value.pipeline:
            assert _kind_has_translation(layer.kind)


def test_invalid_theorist_output_then_fallback_dispatches_to_kernel(tmp_path):
    """End-to-end version of the prior test: invalid theorist →
    fallback emits → at least one emitted spec runs through
    ``execute(bench_mode=True)`` with total_tested > 0.

    This is the strict acceptance criterion from the brief: the bench
    pipeline must not stall at total_tested=0 when the theorist
    returns garbage."""
    invalid_raw = '[{"title": "x"}, {"title": "y"}, {"title": "z"}]'
    report = validate_theory_proposals(invalid_raw)
    assert not report.valid

    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    fallback_theories = controller._programmatic_fallback(landscape)
    assert fallback_theories

    # Find a single-layer spec to dispatch (cheapest).
    target = None
    for t in fallback_theories:
        layers = t.dsl_spec.get("pipeline", [])
        if len(layers) == 1:
            target = t
            break
    assert target is not None

    parsed = validate_hypothesis_spec(target.dsl_spec)
    assert parsed.is_valid

    result = execute(
        parsed.value,
        artifact_root=tmp_path / "round_trip",
        parallel=False,
        bench_mode=True,
    )
    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.total_tested > 0, (
        f"round-trip total_tested={result.total_tested}; the brief's "
        "regression (Proposed=0/Tested=0) is still present"
    )
