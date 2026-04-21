"""R3-0.5-1 tests: procedural translator.

Covers the procedural layer expansion path in
``kryptosbot.job_dispatcher`` and the ``NON_DSL_FAMILIES`` constant
landed by R3-0.5-1 for the R3-2 cutover to consume.

Every test either exercises the happy path (expansion succeeds,
dispatch runs, kernel scores) or an adversarial path (malformed input,
missing recipe, physical-only rejection, bug-catching defensive guard).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from kryptosbot.critic import NON_DSL_FAMILIES
from kryptosbot.hypothesis_dsl import (
    CipherLayer,
    HypothesisSpec,
    NullBaselineSpec,
    ParamRange,
)
from kryptosbot.job_dispatcher import (
    DispatcherError,
    _SUPPORTED_KINDS,
    _expand_procedural_layers,
    _load_recipes_by_id,
    _translate_layer,
    execute,
)
from kryptosbot.procedural_enumerator import load_recipes


# ─── NON_DSL_FAMILIES ────────────────────────────────────────────────────────


def test_non_dsl_families_constant_present_and_frozen():
    """R3-2 cutover depends on this constant. Verify shape."""
    assert isinstance(NON_DSL_FAMILIES, frozenset)
    # Exact membership per R3-1 §3.5 Option γ.
    assert NON_DSL_FAMILIES == frozenset({
        "geometry",
        "k2_coords",
        "geodetic",
        "antipodes",
        "archive_evidence",
        "crib_analysis",
        "k3_continuity",
    })


def test_non_dsl_families_does_not_overlap_with_tier1_or_tier2():
    """A family cannot be simultaneously 'eliminated cipher' and
    'non-cipher methodological'. Regression guard if the sets ever
    overlap: R3-2 dispatch classification would become ambiguous.
    """
    from kryptosbot.critic import TIER_1_FAMILIES, TIER_2_FAMILIES
    assert NON_DSL_FAMILIES.isdisjoint(TIER_1_FAMILIES)
    assert NON_DSL_FAMILIES.isdisjoint(TIER_2_FAMILIES)


# ─── _SUPPORTED_KINDS ────────────────────────────────────────────────────────


def test_procedural_in_supported_kinds():
    assert "procedural" in _SUPPORTED_KINDS


# ─── _load_recipes_by_id ──────────────────────────────────────────────────────


def test_load_recipes_by_id_returns_dict_keyed_by_recipe_id():
    recipes_by_id = _load_recipes_by_id()
    assert isinstance(recipes_by_id, dict)
    assert recipes_by_id, "catalogue is empty — fixture regression"
    for rid, recipe in recipes_by_id.items():
        assert rid == recipe.recipe_id
    # At least a handful of non-physical recipes must exist.
    non_physical = [r for r in recipes_by_id.values()
                    if not r.physical_only]
    assert len(non_physical) >= 5, (
        f"catalogue has only {len(non_physical)} non-physical recipes; "
        "R3-0.5-1 needs at least 5 translatable recipes"
    )


def test_load_recipes_by_id_custom_path():
    """Test-hook: callers can pass a custom catalogue path."""
    recipes = load_recipes()
    tmp_recipes = [r for r in recipes if r.recipe_id == "P-BASELINE-1"]
    assert tmp_recipes, "P-BASELINE-1 not in default catalogue"
    with tempfile.TemporaryDirectory() as tmpdir:
        fixture = Path(tmpdir) / "recipes.json"
        fixture.write_text(json.dumps({
            "recipes": [
                {
                    "recipe_id": "TEST-ONLY-1",
                    "title": "Fixture identity recipe",
                    "anomaly_id": "test_anomaly",
                    "physical_only": False,
                    "procedure": "identity",
                    "dsl_template": {
                        "pipeline": [{"kind": "identity", "alphabet": "AZ",
                                       "params": []}],
                        "assumption_bundle": ["test_bundle"],
                        "compute_budget_cpu_minutes": 1,
                        "scoring": "composite",
                    },
                    "known_eliminations": [],
                    "tested_status": "untested",
                    "priority": 99,
                }
            ]
        }))
        by_id = _load_recipes_by_id(path=fixture)
        assert "TEST-ONLY-1" in by_id
        assert "P-BASELINE-1" not in by_id


# ─── _expand_procedural_layers: happy path ───────────────────────────────────


def test_expansion_identity_shortcircuit_returns_same_spec():
    """A spec with no procedural layers is returned verbatim (same
    object, no copy). Important: preserves spec_hash identity."""
    spec = HypothesisSpec(
        hypothesis_id="no-procedural",
        pipeline=[CipherLayer(kind="vigenere", alphabet="AZ")],
    )
    result = _expand_procedural_layers(spec)
    assert result is spec


def test_expansion_single_layer_baseline_identity():
    """P-BASELINE-1 has a single identity layer. Expansion produces
    a spec with exactly that layer."""
    spec = HypothesisSpec(
        hypothesis_id="proc-baseline-1",
        pipeline=[CipherLayer(kind="procedural",
                              recipe_id="P-BASELINE-1")],
    )
    expanded = _expand_procedural_layers(spec)
    assert expanded is not spec  # new object
    assert len(expanded.pipeline) == 1
    assert expanded.pipeline[0].kind == "identity"
    assert expanded.hypothesis_id == "proc-baseline-1"


def test_expansion_single_layer_with_params():
    """P-F1-1 has a vigenere layer with 5 enumerated keywords. The
    expanded spec's cardinality must reflect those 5 — not the outer
    procedural layer's cardinality of 1."""
    spec = HypothesisSpec(
        hypothesis_id="proc-f1-1",
        pipeline=[CipherLayer(kind="procedural", recipe_id="P-F1-1")],
    )
    # Pre-expansion the outer procedural layer has cardinality 1.
    assert spec.expected_cardinality() == 1
    expanded = _expand_procedural_layers(spec)
    # Post-expansion the inner vigenere contributes its keyword sweep.
    assert expanded.pipeline[0].kind == "vigenere"
    assert expanded.expected_cardinality() == 5


def test_expansion_preserves_non_procedural_layers_in_order():
    """A mixed pipeline expands procedural layers in place; other
    layers pass through untouched and keep their position."""
    spec = HypothesisSpec(
        hypothesis_id="mixed",
        pipeline=[
            CipherLayer(kind="vigenere", alphabet="AZ",
                        params=[ParamRange(name="keyword",
                                            values=["ABC"])]),
            CipherLayer(kind="procedural", recipe_id="P-BASELINE-1"),
            CipherLayer(kind="atbash", alphabet="AZ"),
        ],
    )
    expanded = _expand_procedural_layers(spec)
    kinds = [layer.kind for layer in expanded.pipeline]
    assert kinds == ["vigenere", "identity", "atbash"]


def test_expansion_preserves_toplevel_fields():
    """Expansion rewrites `pipeline` but must preserve every other
    top-level field so downstream (spec_hash, scoring, etc.) match
    what the theorist declared."""
    spec = HypothesisSpec(
        hypothesis_id="preserve-top-fields",
        pipeline=[CipherLayer(kind="procedural",
                              recipe_id="P-BASELINE-1")],
        crib_alignment="direct_positional",
        scoring="crib_plus_bean",
        null_baseline=NullBaselineSpec(method="shuffled_ct"),
        information_gain_bits_estimate=2.5,
        compute_budget_cpu_minutes=7,
        assumption_bundle=["preserve_test"],
        notes="test notes",
        override_exhaustion=True,
        override_justification="test override",
    )
    expanded = _expand_procedural_layers(spec)
    assert expanded.hypothesis_id == "preserve-top-fields"
    assert expanded.crib_alignment == "direct_positional"
    assert expanded.scoring == "crib_plus_bean"
    assert expanded.null_baseline is not None
    assert expanded.null_baseline.method == "shuffled_ct"
    assert expanded.information_gain_bits_estimate == 2.5
    assert expanded.compute_budget_cpu_minutes == 7
    assert expanded.assumption_bundle == ["preserve_test"]
    assert expanded.notes == "test notes"
    assert expanded.override_exhaustion is True
    assert expanded.override_justification == "test override"


def test_expansion_produces_valid_spec_that_passes_kernel_roundtrip():
    """The expanded spec must pass HypothesisSpec.validate() and
    produce a spec_hash — this guards against malformed expansions."""
    spec = HypothesisSpec(
        hypothesis_id="valid-after-expand",
        pipeline=[CipherLayer(kind="procedural", recipe_id="P-F1-1")],
    )
    expanded = _expand_procedural_layers(spec)
    assert expanded.validate() == [], (
        f"expanded spec invalid: {expanded.validate()}"
    )
    # spec_hash is a property; must be deterministic & non-empty.
    assert len(expanded.spec_hash) == 16


# ─── _expand_procedural_layers: adversarial paths ────────────────────────────


def test_expansion_missing_recipe_id_raises():
    spec = HypothesisSpec(
        hypothesis_id="bad-no-rid",
        pipeline=[CipherLayer(kind="procedural", recipe_id=None)],
    )
    with pytest.raises(DispatcherError, match="requires recipe_id"):
        _expand_procedural_layers(spec)


def test_expansion_empty_recipe_id_raises():
    spec = HypothesisSpec(
        hypothesis_id="bad-empty-rid",
        pipeline=[CipherLayer(kind="procedural", recipe_id="")],
    )
    with pytest.raises(DispatcherError, match="requires recipe_id"):
        _expand_procedural_layers(spec)


def test_expansion_unknown_recipe_id_raises_with_suggestion():
    spec = HypothesisSpec(
        hypothesis_id="bad-unknown-rid",
        pipeline=[CipherLayer(kind="procedural",
                              recipe_id="NOT-A-REAL-RECIPE")],
    )
    with pytest.raises(DispatcherError) as exc_info:
        _expand_procedural_layers(spec)
    msg = str(exc_info.value)
    assert "not in" in msg and "catalogue" in msg
    assert "available:" in msg, (
        "error message must list available recipe_ids so the "
        "caller can self-correct"
    )


def test_expansion_physical_only_recipe_raises():
    """physical_only recipes have no DSL realization — the
    dispatcher must refuse them (the enumerator already filters
    them for controller-level enumeration, but direct calls still
    need to be rejected)."""
    recipes = load_recipes()
    physical = next((r for r in recipes if r.physical_only), None)
    assert physical is not None, "no physical_only recipes to test with"
    spec = HypothesisSpec(
        hypothesis_id="bad-physical",
        pipeline=[CipherLayer(kind="procedural",
                              recipe_id=physical.recipe_id)],
    )
    with pytest.raises(DispatcherError, match="physical_only"):
        _expand_procedural_layers(spec)


def test_expansion_recipe_id_strict_no_whitespace_normalization():
    """We don't silently strip or case-fold recipe_ids. A caller
    passing 'P-F1-1 ' (trailing space) must fail explicitly rather
    than matching 'P-F1-1' — loose matching would be a failure
    mode."""
    spec = HypothesisSpec(
        hypothesis_id="bad-spacey-rid",
        pipeline=[CipherLayer(kind="procedural",
                              recipe_id="P-F1-1 ")],
    )
    with pytest.raises(DispatcherError, match="not in"):
        _expand_procedural_layers(spec)


def test_expansion_with_injected_malformed_recipe_raises():
    """Simulate an enumerator that returns a recipe whose
    dsl_template is malformed (recipe_to_spec returns None).
    Expansion must raise a clear error rather than silently
    producing a broken spec."""
    class _FakeRecipe:
        recipe_id = "FAKE-BAD"
        physical_only = False
        dsl_template = None  # recipe_to_spec returns None for this

    spec = HypothesisSpec(
        hypothesis_id="fake-bad",
        pipeline=[CipherLayer(kind="procedural", recipe_id="FAKE-BAD")],
    )
    with pytest.raises(DispatcherError, match="no valid|malformed|missing"):
        _expand_procedural_layers(
            spec, recipes_by_id={"FAKE-BAD": _FakeRecipe()},
        )


# ─── _translate_layer defensive guard ────────────────────────────────────────


def test_translate_layer_procedural_raises_defensive_error():
    """A procedural layer reaching _translate_layer means expansion
    was skipped. Guard raises with a pointer at the bug."""
    layer = CipherLayer(kind="procedural", recipe_id="P-F1-1")
    with pytest.raises(DispatcherError,
                        match="reached _translate_layer without being expanded"):
        _translate_layer(layer, {})


# ─── End-to-end dispatch integration ─────────────────────────────────────────


def test_execute_procedural_baseline_runs_kernel_scoring():
    """P-BASELINE-1 expands to identity — dispatching it runs the
    kernel scoring on the raw CT. The result is admissible and
    kernel-verified."""
    spec = HypothesisSpec(
        hypothesis_id="e2e-baseline",
        pipeline=[CipherLayer(kind="procedural",
                              recipe_id="P-BASELINE-1")],
    )
    result = execute(spec, parallel=False)
    assert result.admissibility_verdict == "ok"
    assert result.total_tested >= 1
    # best_candidate is a dict carrying kernel-computed fields.
    assert result.best_candidate is not None
    assert "crib_score" in result.best_candidate
    assert "bean_passed" in result.best_candidate


def test_execute_procedural_with_param_sweep_enumerates_all_configs():
    """P-F1-1 expands to a vigenere with 5 keyword candidates.
    Dispatch must enumerate all 5 and kernel-score each."""
    spec = HypothesisSpec(
        hypothesis_id="e2e-f1-1",
        pipeline=[CipherLayer(kind="procedural", recipe_id="P-F1-1")],
    )
    result = execute(spec, parallel=False)
    assert result.admissibility_verdict == "ok"
    assert result.total_tested == 5, (
        "expected 5 configs (5 keyword candidates); "
        f"got {result.total_tested}"
    )


def test_execute_procedural_bad_recipe_id_surfaces_in_admissibility_reasons():
    """Bad procedural expansion surfaces as an admissibility
    rejection (not a silent crash). The error message is in
    admissibility_reasons for ledger audit."""
    spec = HypothesisSpec(
        hypothesis_id="e2e-bad-rid",
        pipeline=[CipherLayer(kind="procedural",
                              recipe_id="DEFINITELY-NOT-REAL")],
    )
    result = execute(spec, parallel=False)
    assert result.admissibility_verdict == "rejected"
    assert result.admissibility_reasons
    assert any("procedural expansion" in r
               for r in result.admissibility_reasons)


def test_execute_kernel_overrule_preserved_on_procedural_path():
    """Phase 3 kernel overrule: the best_candidate's crib_score and
    bean_passed must come from kryptos.kernel.scoring.aggregate, not
    from any worker self-report. Dispatch through procedural path
    must not bypass the overrule."""
    from kryptos.kernel.constants import CT
    from kryptos.kernel.scoring.aggregate import score_candidate
    spec = HypothesisSpec(
        hypothesis_id="e2e-overrule",
        pipeline=[CipherLayer(kind="procedural",
                              recipe_id="P-BASELINE-1")],
    )
    result = execute(spec, parallel=False)
    assert result.best_candidate is not None
    # Identity on CT → candidate_pt == CT. Kernel score on CT.
    kernel_breakdown = score_candidate(CT)
    assert result.best_candidate["crib_score"] == int(
        kernel_breakdown.crib_score
    )
    assert result.best_candidate["bean_passed"] == bool(
        kernel_breakdown.bean_passed
    )
