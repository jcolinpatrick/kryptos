"""Tests for kryptosbot.hypothesis_dsl.

Framework maturation Phase 4 (2026-04-21). Exercises:
- ParamRange, CipherLayer, NullBaselineSpec, HypothesisSpec construction
- JSON round-trip
- .validate() catches every stated failure mode
- spec_hash is stable across equivalent specs
- expected_cardinality is the product of param ranges
- validate_hypothesis_spec() fail-closed behaviour on malformed input
"""

from __future__ import annotations

import json

import pytest

from kryptosbot.hypothesis_dsl import (
    CipherLayer,
    HypothesisSpec,
    NullBaselineSpec,
    ParamRange,
    _VALID_CIPHER_KINDS,
    validate_hypothesis_spec,
)
from kryptosbot.contracts import ParseResult


# ─── ParamRange ──────────────────────────────────────────────────────────────

class TestParamRange:
    def test_values_mode_cardinality(self):
        p = ParamRange(name="keyword", values=["PALIMPSEST", "ABSCISSA", "KRYPTOS"])
        assert p.cardinality() == 3
        assert p.validate() == []
        assert p.enumerate() == ["PALIMPSEST", "ABSCISSA", "KRYPTOS"]

    def test_range_mode_cardinality(self):
        p = ParamRange(name="width", start=5, stop=15)
        assert p.cardinality() == 10
        assert p.validate() == []
        assert p.enumerate() == list(range(5, 15))

    def test_empty_param_range_is_invalid(self):
        p = ParamRange(name="bogus")
        errors = p.validate()
        assert any("must set either values or start+stop" in e for e in errors)

    def test_both_modes_set_is_invalid(self):
        p = ParamRange(name="x", values=[1, 2], start=0, stop=3)
        errors = p.validate()
        assert any("cannot set both" in e for e in errors)

    def test_stop_must_exceed_start(self):
        p = ParamRange(name="width", start=10, stop=5)
        errors = p.validate()
        assert any("must exceed start" in e for e in errors)

    def test_empty_name_is_invalid(self):
        p = ParamRange(name="", values=[1])
        errors = p.validate()
        assert any("non-empty string" in e for e in errors)

    def test_cardinality_cap_enforced(self):
        p = ParamRange(name="huge", start=0, stop=100_000, cardinality_cap=50)
        errors = p.validate()
        assert any("exceeds cardinality_cap" in e for e in errors)

    def test_enumerate_raises_on_ill_defined(self):
        p = ParamRange(name="x")
        with pytest.raises(ValueError, match="must set either"):
            p.enumerate()

    def test_to_dict_roundtrip(self):
        p = ParamRange(name="keyword", values=["A", "B"], source_corpus="thematic")
        d = p.to_dict()
        p2 = ParamRange.from_dict(d)
        assert p2.name == p.name
        assert p2.values == p.values
        assert p2.source_corpus == p.source_corpus


# ─── CipherLayer ─────────────────────────────────────────────────────────────

class TestCipherLayer:
    def test_simple_vigenere_layer(self):
        layer = CipherLayer(
            kind="vigenere", alphabet="KA",
            params=[ParamRange(name="keyword", values=["K"])],
        )
        assert layer.validate() == []
        assert layer.cardinality() == 1

    def test_unknown_kind_rejected(self):
        layer = CipherLayer(kind="qubic_cipher", alphabet="AZ")
        errors = layer.validate()
        assert any("not a recognized CipherKind" in e for e in errors)

    def test_unknown_alphabet_rejected(self):
        layer = CipherLayer(kind="vigenere", alphabet="EBCDIC")
        errors = layer.validate()
        assert any("alphabet" in e and "not recognized" in e for e in errors)

    def test_procedural_kind_requires_recipe_id(self):
        layer = CipherLayer(kind="procedural")
        errors = layer.validate()
        assert any("recipe_id" in e for e in errors)

    def test_recipe_id_without_procedural_is_rejected(self):
        layer = CipherLayer(kind="vigenere", recipe_id="P-042")
        errors = layer.validate()
        assert any("only valid when kind=='procedural'" in e for e in errors)

    def test_duplicate_param_names_rejected(self):
        layer = CipherLayer(
            kind="vigenere",
            params=[
                ParamRange(name="kw", values=["A"]),
                ParamRange(name="kw", values=["B"]),
            ],
        )
        errors = layer.validate()
        assert any("duplicate name" in e for e in errors)

    def test_cardinality_is_product_of_params(self):
        layer = CipherLayer(
            kind="columnar",
            params=[
                ParamRange(name="width", start=5, stop=10),          # 5
                ParamRange(name="keyword", values=["ABC", "DEF"]),   # 2
            ],
        )
        assert layer.cardinality() == 5 * 2

    def test_to_dict_preserves_params(self):
        layer = CipherLayer(
            kind="vigenere",
            params=[ParamRange(name="keyword", values=["K"])],
        )
        d = layer.to_dict()
        layer2 = CipherLayer.from_dict(d)
        assert layer2.kind == layer.kind
        assert len(layer2.params) == 1
        assert layer2.params[0].name == "keyword"


# ─── NullBaselineSpec ────────────────────────────────────────────────────────

class TestNullBaselineSpec:
    def test_default_is_valid(self):
        nb = NullBaselineSpec()
        assert nb.validate() == []
        assert nb.method == "random_text"
        assert nb.n_samples == 10_000

    def test_unknown_method_rejected(self):
        nb = NullBaselineSpec(method="bogus")
        errors = nb.validate()
        assert any("not recognized" in e for e in errors)

    def test_zero_samples_rejected(self):
        nb = NullBaselineSpec(n_samples=0)
        errors = nb.validate()
        assert any("must be positive" in e for e in errors)


# ─── HypothesisSpec ──────────────────────────────────────────────────────────

def _make_minimal_spec() -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id="T-TEST",
        pipeline=[
            CipherLayer(
                kind="vigenere", alphabet="KA",
                params=[ParamRange(name="keyword", values=["KRYPTOS"])],
            )
        ],
    )


class TestHypothesisSpec:
    def test_minimal_spec_is_valid(self):
        spec = _make_minimal_spec()
        assert spec.is_valid(), f"expected valid; errors: {spec.validate()}"

    def test_empty_hypothesis_id_rejected(self):
        spec = HypothesisSpec(hypothesis_id="")
        errors = spec.validate()
        assert any("non-empty string" in e for e in errors)

    def test_invalid_crib_alignment_rejected(self):
        spec = _make_minimal_spec()
        spec.crib_alignment = "bogus"
        errors = spec.validate()
        assert any("crib_alignment" in e and "not recognized" in e for e in errors)

    def test_invalid_scoring_rejected(self):
        spec = _make_minimal_spec()
        spec.scoring = "bogus"
        errors = spec.validate()
        assert any("scoring" in e and "not recognized" in e for e in errors)

    def test_negative_compute_budget_rejected(self):
        spec = _make_minimal_spec()
        spec.compute_budget_cpu_minutes = 0
        errors = spec.validate()
        assert any("compute_budget_cpu_minutes must be positive" in e for e in errors)

    def test_nested_layer_errors_are_surfaced(self):
        spec = HypothesisSpec(
            hypothesis_id="T",
            pipeline=[CipherLayer(kind="not_a_cipher")],
        )
        errors = spec.validate()
        assert any("pipeline[0]" in e for e in errors)

    def test_null_baseline_errors_are_surfaced(self):
        spec = _make_minimal_spec()
        spec.null_baseline = NullBaselineSpec(method="bogus")
        errors = spec.validate()
        assert any("null_baseline" in e for e in errors)

    def test_expected_cardinality_is_product(self):
        spec = HypothesisSpec(
            hypothesis_id="T",
            pipeline=[
                CipherLayer(
                    kind="columnar",
                    params=[ParamRange(name="width", start=5, stop=10)],  # 5
                ),
                CipherLayer(
                    kind="vigenere",
                    params=[ParamRange(name="keyword", values=["A", "B", "C"])],  # 3
                ),
            ],
        )
        assert spec.expected_cardinality() == 5 * 3

    def test_expected_cardinality_empty_pipeline_is_one(self):
        spec = HypothesisSpec(hypothesis_id="T")
        assert spec.expected_cardinality() == 1

    def test_spec_hash_is_deterministic(self):
        s1 = _make_minimal_spec()
        s2 = _make_minimal_spec()
        assert s1.spec_hash == s2.spec_hash

    def test_spec_hash_changes_on_material_change(self):
        s1 = _make_minimal_spec()
        s2 = _make_minimal_spec()
        s2.pipeline[0].params[0].values = ["ABSCISSA"]  # changed
        assert s1.spec_hash != s2.spec_hash

    def test_spec_hash_is_order_independent_in_fields(self):
        """to_dict + sort_keys produces the same bytes regardless of
        field insertion order on equivalent specs."""
        s1 = _make_minimal_spec()
        # Rebuild from shuffled JSON representation.
        d = s1.to_dict()
        reordered = {k: d[k] for k in reversed(list(d.keys()))}
        s2 = HypothesisSpec.from_dict(reordered)
        assert s1.spec_hash == s2.spec_hash

    def test_json_roundtrip(self):
        s1 = _make_minimal_spec()
        s1.success_criteria = {"crib_score": 24, "bean_passed": True}
        s1.kill_criteria = {"max_crib_score": 5}
        s1.null_baseline = NullBaselineSpec(method="shuffled_ct", n_samples=1000)
        s1.assumption_bundle = ["H1_direct_positional"]

        raw = s1.to_json()
        s2 = HypothesisSpec.from_json(raw)

        assert s1.spec_hash == s2.spec_hash
        assert s2.null_baseline is not None
        assert s2.null_baseline.method == "shuffled_ct"
        assert s2.assumption_bundle == ["H1_direct_positional"]
        assert s2.success_criteria == s1.success_criteria


# ─── validate_hypothesis_spec ────────────────────────────────────────────────

class TestValidateHypothesisSpec:
    def test_valid_json_string_yields_ok(self):
        spec = _make_minimal_spec()
        raw = spec.to_json()
        result = validate_hypothesis_spec(raw)
        assert result.is_valid
        assert result.value is not None
        assert result.value.spec_hash == spec.spec_hash

    def test_valid_dict_yields_ok(self):
        spec = _make_minimal_spec()
        result = validate_hypothesis_spec(spec.to_dict())
        assert result.is_valid

    def test_malformed_json_fails_closed(self):
        result = validate_hypothesis_spec("{this is not json")
        assert not result.is_valid
        assert any("JSON parse error" in e for e in result.errors)

    def test_nonobject_top_level_fails_closed(self):
        result = validate_hypothesis_spec("[1, 2, 3]")
        assert not result.is_valid
        assert any("Expected JSON object" in e for e in result.errors)

    def test_non_str_non_dict_input_rejected(self):
        result = validate_hypothesis_spec(42)  # type: ignore[arg-type]
        assert not result.is_valid
        assert any("Expected str or dict" in e for e in result.errors)

    def test_validation_errors_are_surfaced(self):
        result = validate_hypothesis_spec({
            "hypothesis_id": "",
            "pipeline": [{"kind": "bogus_cipher"}],
            "crib_alignment": "not_a_real_alignment",
            "scoring": "not_a_real_mode",
            "compute_budget_cpu_minutes": 0,
        })
        assert not result.is_valid
        # Every independent error should be surfaced.
        joined = " | ".join(result.errors)
        assert "hypothesis_id" in joined
        assert "bogus_cipher" in joined
        assert "crib_alignment" in joined
        assert "scoring" in joined
        assert "compute_budget_cpu_minutes" in joined

    def test_raw_preserved_on_failure(self):
        raw = '{"hypothesis_id": ""}'
        result = validate_hypothesis_spec(raw)
        assert not result.is_valid
        assert result.raw == raw


# ─── Cipher-kind registry coverage ───────────────────────────────────────────

class TestCipherKindRegistry:
    def test_every_valid_kind_validates(self):
        """Every kind in _VALID_CIPHER_KINDS must construct cleanly
        (modulo recipe_id for procedural)."""
        for kind in _VALID_CIPHER_KINDS:
            recipe_id = "P-042" if kind == "procedural" else None
            layer = CipherLayer(kind=kind, recipe_id=recipe_id)
            errors = layer.validate()
            assert errors == [], f"kind {kind!r} failed validation: {errors}"

    def test_registry_contains_expected_families(self):
        # Sanity: the kinds mentioned in the brief must all be registered.
        for expected in [
            "identity", "vigenere", "beaufort", "variant_beaufort",
            "columnar", "rail_fence", "route", "myszkowski",
            "polybius", "quagmire", "atbash", "procedural",
        ]:
            assert expected in _VALID_CIPHER_KINDS
