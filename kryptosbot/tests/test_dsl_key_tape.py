"""DSL validation tests for the key_tape kind."""
import pytest

from kryptosbot.hypothesis_dsl import coerce_key_tape, validate_layer_for_kind


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


class TestCoerceKeyTape:
    """coerce_key_tape normalizes theorist letter-tapes to integer offsets.

    Letters map to the STANDARD alphabet shift A=0..Z=25 (the conventional
    Vigenere key-letter interpretation), matching apply_key_tape which uses
    the tape value directly as the additive offset. Entries it cannot
    unambiguously coerce are left verbatim so validate_layer_for_kind still
    reports a precise error.
    """

    def test_letter_string_mapped_to_standard_shifts(self):
        # K=10 R=17 Y=24 P=15 T=19 O=14 S=18
        assert coerce_key_tape("KRYPTOS") == (10, 17, 24, 15, 19, 14, 18)

    def test_letter_list_mapped(self):
        assert coerce_key_tape(["K", "R", "Y"]) == (10, 17, 24)

    def test_lowercase_letters_case_insensitive(self):
        assert coerce_key_tape("abc") == (0, 1, 2)

    def test_int_tape_passthrough(self):
        assert coerce_key_tape((1, 2, 3)) == (1, 2, 3)

    def test_out_of_range_ints_left_unchanged(self):
        # 99 is preserved so validate_layer_for_kind catches it precisely.
        assert coerce_key_tape((0, 99, 5)) == (0, 99, 5)

    def test_mixed_ints_and_letters(self):
        assert coerce_key_tape((1, "C", 3)) == (1, 2, 3)

    def test_none_returned_unchanged(self):
        assert coerce_key_tape(None) is None

    def test_empty_returned_unchanged(self):
        assert coerce_key_tape(()) == ()

    def test_non_letter_chars_preserved_for_validator(self):
        # Digits are NOT treated as offsets (ambiguous vs letter A=0); kept
        # verbatim so the validator rejects them with a clear message.
        out = coerce_key_tape("A1B")
        assert out[0] == 0 and out[2] == 1 and not isinstance(out[1], int)

    def test_coerced_letter_tape_passes_validation(self):
        params = _layer(tape=coerce_key_tape("KRYPTOS"))
        assert validate_layer_for_kind("key_tape", params) == []
