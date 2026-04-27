"""Tests for kryptosbot/bench_attempts.py.

Verifies the layer-source priority order patched in 2026-04-27 to fix
the layers=[] bug in the K4B-001 attempt artifact:

  1. result.raw_artifacts['dispatched_dsl_spec']['pipeline']
  2. experiment.config['dsl_spec']['pipeline']
  3. theory.minimal_test_spec['dsl_spec']['pipeline']

Per the user spec, layers must surface non-empty for the six cipher
families currently dispatched on K4Bench challenges:

    Vigenere, Beaufort, Columnar, Rail Fence, Route, supported Quagmire

Tests use synthetic TheoryRecord / ExperimentRecord / WorkerContract
fixtures so we don't need to spin up the controller; the
``_safe_dsl_layers`` resolver is pure with respect to its inputs.
"""
from __future__ import annotations

from typing import Any

import pytest

from kryptosbot.bench_attempts import (
    _coerce_pipeline,
    _safe_best_bindings,
    _safe_dsl_layers,
)
from kryptosbot.hypothesis_dsl import (
    CipherLayer,
    HypothesisSpec,
    ParamRange,
)
from kryptosbot.models import (
    ExperimentRecord,
    TheoryRecord,
    TheoryStatus,
    WorkerContract,
    WorkerStatus,
)


# --- Spec-builder helpers ----------------------------------------------------


def _hypothesis_spec(layers: list[CipherLayer]) -> HypothesisSpec:
    """Wrap layers in a minimal valid HypothesisSpec dict."""
    return HypothesisSpec(
        hypothesis_id="T-test",
        pipeline=layers,
        compute_budget_cpu_minutes=1,
    )


def _vigenere_spec_dict() -> dict[str, Any]:
    return _hypothesis_spec([
        CipherLayer(
            kind="vigenere",
            params=[ParamRange(name="keyword", values=["CEDAR"])],
        ),
    ]).to_dict()


def _beaufort_spec_dict() -> dict[str, Any]:
    return _hypothesis_spec([
        CipherLayer(
            kind="beaufort",
            params=[ParamRange(name="keyword", values=["LANTERN"])],
        ),
    ]).to_dict()


def _columnar_spec_dict() -> dict[str, Any]:
    return _hypothesis_spec([
        CipherLayer(
            kind="columnar",
            params=[
                ParamRange(name="width", values=[7]),
                ParamRange(name="col_order", values=[[0, 1, 2, 3, 4, 5, 6]]),
            ],
        ),
    ]).to_dict()


def _rail_fence_spec_dict() -> dict[str, Any]:
    return _hypothesis_spec([
        CipherLayer(
            kind="rail_fence",
            params=[ParamRange(name="depth", values=[7])],
        ),
    ]).to_dict()


def _route_spec_dict() -> dict[str, Any]:
    return _hypothesis_spec([
        CipherLayer(
            kind="route",
            params=[
                ParamRange(name="variant", values=["serpentine"]),
                ParamRange(name="rows", values=[7]),
                ParamRange(name="cols", values=[14]),
            ],
        ),
    ]).to_dict()


def _quagmire_spec_dict() -> dict[str, Any]:
    """Quagmire III with full K1/K2 convention.

    Both pt_alphabet_keyword and ct_alphabet_keyword are required by
    the dispatcher (see job_dispatcher._translate_layer for the
    rationale). A bare ct_alphabet_keyword would silently run a
    different mechanism that cannot reproduce K1/K2.
    """
    return _hypothesis_spec([
        CipherLayer(
            kind="quagmire",
            params=[
                ParamRange(name="period_keyword", values=["KRYPTOS"]),
                ParamRange(name="ct_alphabet_keyword", values=["KRYPTOS"]),
                ParamRange(name="pt_alphabet_keyword", values=["KRYPTOS"]),
                ParamRange(name="indicator", values=["K"]),
                ParamRange(name="variant", values=["quagmire_iii"]),
            ],
        ),
    ]).to_dict()


# --- Fixture builders for the resolver --------------------------------------


def _make_theory(
    *,
    minimal_test_spec: dict[str, Any] | None = None,
) -> TheoryRecord:
    return TheoryRecord(
        hypothesis_id="t-test",
        title="test theory",
        family="test",
        status=TheoryStatus.COMPLETED,
        best_plaintext="A" * 97,
        best_score=4.0,
        minimal_test_spec=minimal_test_spec or {},
    )


def _make_contract_with_dispatched_spec(
    spec_dict: dict[str, Any],
    *,
    bindings: list[list[Any]] | None = None,
) -> WorkerContract:
    return WorkerContract(
        hypothesis_id="t-test",
        worker_role="dsl_dispatcher",
        status=WorkerStatus.DISPROVED,
        raw_artifacts={
            "dispatched_dsl_spec": spec_dict,
            "best_config_bindings": bindings or [],
        },
    )


def _make_experiment(
    *,
    config: dict[str, Any] | None = None,
    contract: WorkerContract | None = None,
) -> ExperimentRecord:
    return ExperimentRecord(
        experiment_id="exp-test",
        hypothesis_id="t-test",
        worker_role="dsl_dispatcher",
        config=config or {},
        result=contract,
    )


# --- Per-cipher-family layer-population tests --------------------------------


@pytest.mark.parametrize(
    "spec_builder, expected_kind",
    [
        (_vigenere_spec_dict, "vigenere"),
        (_beaufort_spec_dict, "beaufort"),
        (_columnar_spec_dict, "columnar"),
        (_rail_fence_spec_dict, "rail_fence"),
        (_route_spec_dict, "route"),
        (_quagmire_spec_dict, "quagmire"),
    ],
)
def test_layers_non_empty_for_supported_cipher_kinds(spec_builder, expected_kind):
    """User-mandated: attempt artifact layers MUST be non-empty for
    Vigenere, Beaufort, Columnar, Rail Fence, Route, and supported
    Quagmire specs. The bug being fixed: historical artifacts had
    layers=[] for every attempt because the resolver was reading the
    wrong key (``layers``/``steps``) instead of ``pipeline``.
    """
    spec_dict = spec_builder()
    theory = _make_theory(minimal_test_spec={"dsl_spec": spec_dict})
    contract = _make_contract_with_dispatched_spec(spec_dict)
    experiment = _make_experiment(
        config={"dsl_spec": spec_dict},
        contract=contract,
    )

    layers = _safe_dsl_layers(
        theory, contract=contract, experiment=experiment,
    )
    assert isinstance(layers, list)
    assert len(layers) >= 1, f"{expected_kind} layers came out empty"
    assert layers[0]["kind"] == expected_kind, (
        f"Expected first layer kind to be {expected_kind!r}; "
        f"got {layers[0].get('kind')!r}"
    )
    # The params field must survive the resolver; otherwise the
    # evaluator can't replay with concrete values.
    assert "params" in layers[0]


# --- Source-priority tests ---------------------------------------------------


def test_priority_contract_beats_experiment_and_theory():
    """Source 1 (contract.raw_artifacts.dispatched_dsl_spec) wins
    when all three are present.
    """
    contract_spec = _vigenere_spec_dict()
    experiment_spec = _beaufort_spec_dict()
    theory_spec = _columnar_spec_dict()

    theory = _make_theory(minimal_test_spec={"dsl_spec": theory_spec})
    contract = _make_contract_with_dispatched_spec(contract_spec)
    experiment = _make_experiment(
        config={"dsl_spec": experiment_spec},
        contract=contract,
    )

    layers = _safe_dsl_layers(
        theory, contract=contract, experiment=experiment,
    )
    assert layers[0]["kind"] == "vigenere"


def test_priority_experiment_beats_theory_when_no_contract_spec():
    """When contract has no dispatched_dsl_spec, source 2 wins."""
    experiment_spec = _beaufort_spec_dict()
    theory_spec = _columnar_spec_dict()

    theory = _make_theory(minimal_test_spec={"dsl_spec": theory_spec})
    contract = WorkerContract(
        hypothesis_id="t-test",
        worker_role="dsl_dispatcher",
        status=WorkerStatus.DISPROVED,
        raw_artifacts={},  # no dispatched_dsl_spec
    )
    experiment = _make_experiment(
        config={"dsl_spec": experiment_spec},
        contract=contract,
    )

    layers = _safe_dsl_layers(
        theory, contract=contract, experiment=experiment,
    )
    assert layers[0]["kind"] == "beaufort"


def test_priority_theory_used_when_no_contract_or_experiment_spec():
    """When neither contract nor experiment carry a spec, source 3
    is used. This is the legacy path for pre-2026-04-27 ledger rows.
    """
    theory_spec = _columnar_spec_dict()
    theory = _make_theory(minimal_test_spec={"dsl_spec": theory_spec})

    layers = _safe_dsl_layers(theory, contract=None, experiment=None)
    assert layers[0]["kind"] == "columnar"


def test_resolver_returns_empty_when_no_source_has_pipeline():
    """All three sources empty / wrong-shaped → empty list."""
    theory = _make_theory(minimal_test_spec={"dsl_spec": {}})
    contract = WorkerContract(
        hypothesis_id="t-test",
        worker_role="dsl_dispatcher",
        status=WorkerStatus.DISPROVED,
        raw_artifacts={},
    )
    experiment = _make_experiment(config={}, contract=contract)
    assert _safe_dsl_layers(
        theory, contract=contract, experiment=experiment,
    ) == []


# --- Backward-compat tolerance ----------------------------------------------


def test_coerce_pipeline_accepts_legacy_layers_key():
    """Some pre-2026-04-27 code emitted ``layers`` instead of
    ``pipeline``; the resolver tolerates it for read-back compat.
    """
    legacy = {"layers": [{"kind": "vigenere", "alphabet": "AZ", "params": []}]}
    result = _coerce_pipeline(legacy)
    assert len(result) == 1
    assert result[0]["kind"] == "vigenere"


def test_coerce_pipeline_accepts_legacy_steps_key():
    """The kernel pipeline_dict uses ``steps`` rather than ``pipeline``
    or ``layers``; tolerate that too for partial-fallback robustness.
    """
    legacy = {"steps": [{"kind": "beaufort", "alphabet": "AZ", "params": []}]}
    result = _coerce_pipeline(legacy)
    assert len(result) == 1
    assert result[0]["kind"] == "beaufort"


def test_coerce_pipeline_returns_empty_on_missing_keys():
    assert _coerce_pipeline({}) == []
    assert _coerce_pipeline(None) == []
    assert _coerce_pipeline("not a dict") == []
    # A dict without any of pipeline/layers/steps keys → empty list,
    # but no raise.
    assert _coerce_pipeline({"unrelated": "keys"}) == []


# --- best_config_bindings resolver -------------------------------------------


def test_best_bindings_from_contract():
    contract = _make_contract_with_dispatched_spec(
        _vigenere_spec_dict(),
        bindings=[["layer0.keyword", "CEDAR"]],
    )
    theory = _make_theory()
    bindings = _safe_best_bindings(theory, contract=contract)
    assert bindings == [["layer0.keyword", "CEDAR"]]


def test_best_bindings_fallback_to_theory():
    theory = _make_theory(minimal_test_spec={
        "dsl_spec": _vigenere_spec_dict(),
        "best_config_bindings": [["layer0.keyword", "LANTERN"]],
    })
    bindings = _safe_best_bindings(theory, contract=None)
    assert bindings == [["layer0.keyword", "LANTERN"]]


def test_best_bindings_empty_when_neither_present():
    theory = _make_theory()
    contract = WorkerContract(
        hypothesis_id="t-test",
        worker_role="dsl_dispatcher",
        status=WorkerStatus.DISPROVED,
        raw_artifacts={},
    )
    assert _safe_best_bindings(theory, contract=contract) == []


# --- Defensive: theory without minimal_test_spec at all ---------------------


def test_resolver_tolerates_missing_minimal_test_spec():
    theory = _make_theory()
    theory.minimal_test_spec = {}  # explicit empty
    assert _safe_dsl_layers(theory) == []


def test_resolver_tolerates_non_dict_minimal_test_spec():
    """Defensive: a corrupted ledger row may carry a non-dict
    minimal_test_spec. The resolver must not raise.
    """
    theory = _make_theory()
    # Bypass the dataclass typing to simulate corruption
    object.__setattr__(theory, "minimal_test_spec", "not a dict")
    assert _safe_dsl_layers(theory) == []
