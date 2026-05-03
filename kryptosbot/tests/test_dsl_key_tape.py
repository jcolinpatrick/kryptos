"""DSL validation tests for the key_tape kind."""
import pytest

from kryptosbot.hypothesis_dsl import validate_layer_for_kind


def _layer(**params):
    """Minimal layer params for key_tape; tests override fields."""
    base = {
        "tape": (1, 2, 3),
        "variant": "vigenere",
        "alphabet": "AZ",
    }
    base.update(params)
    return base


class TestKeyTapeDslValidation:
    def test_minimal_valid_layer_accepted(self):
        errors = validate_layer_for_kind("key_tape", _layer())
        assert errors == [], errors

    def test_valid_with_nulls(self):
        errors = validate_layer_for_kind("key_tape", _layer(
            null_positions=(0, 2),
            null_rule="skip",
        ))
        assert errors == [], errors

    def test_missing_tape_rejected(self):
        params = _layer()
        del params["tape"]
        errors = validate_layer_for_kind("key_tape", params)
        assert any("tape" in e for e in errors), errors

    def test_empty_tape_rejected(self):
        errors = validate_layer_for_kind("key_tape", _layer(tape=()))
        assert any("tape" in e and ("non-empty" in e or "empty" in e) for e in errors), errors

    def test_unknown_variant_rejected(self):
        errors = validate_layer_for_kind("key_tape", _layer(variant="quagmire"))
        assert any("variant" in e for e in errors), errors

    def test_tape_value_out_of_range_rejected(self):
        errors = validate_layer_for_kind("key_tape", _layer(tape=(0, 99, 5)))
        assert any("tape" in e and "range" in e for e in errors), errors

    def test_null_positions_out_of_range_rejected(self):
        errors = validate_layer_for_kind("key_tape", _layer(
            null_positions=(0, 999),
            null_rule="skip",
        ))
        assert any("null_positions" in e for e in errors), errors

    def test_null_positions_without_rule_rejected(self):
        errors = validate_layer_for_kind("key_tape", _layer(
            null_positions=(0, 2),
            # null_rule omitted
        ))
        assert any("null_rule" in e for e in errors), errors

    def test_unknown_alphabet_rejected(self):
        errors = validate_layer_for_kind("key_tape", _layer(alphabet="ZZ"))
        assert any("alphabet" in e for e in errors), errors
