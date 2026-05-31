"""Dispatcher integration tests for the key_tape kind."""
import pytest

from kryptosbot.job_dispatcher import (
    _SUPPORTED_KINDS,
    _kind_has_translation,
    _translate_layer,
)


class TestKeyTapeDispatcher:
    def test_kind_in_supported_set(self):
        assert "key_tape" in _SUPPORTED_KINDS

    def test_kind_has_translation(self):
        assert _kind_has_translation("key_tape") is True

    def test_translator_emits_dict(self):
        # Concrete params live in `binding` (the resolved dict from the
        # Cartesian enumeration step), not on layer.params (which is the
        # ParamRange list at spec time). The translator returns a nested
        # dict matching the convention of other translators:
        #   {"type": "key_tape", "params": {tape, variant, ...}}
        class _Layer:
            kind = "key_tape"
            params = []  # ParamRange list — not exercised in this test

        binding = {
            "tape": (1, 2, 3, 4, 5),
            "variant": "vigenere",
            "direction": "decrypt",
            "null_positions": (),
            "null_rule": "skip",
            "alphabet": "AZ",
        }
        cfg = _translate_layer(_Layer(), binding=binding, text_length=97)
        assert isinstance(cfg, dict)
        assert cfg["type"] == "key_tape"
        assert cfg["params"]["tape"] == (1, 2, 3, 4, 5)
        assert cfg["params"]["variant"] == "vigenere"
        assert cfg["params"]["alphabet"] == "AZ"

    def test_translator_rejects_empty_tape(self):
        class _Layer:
            kind = "key_tape"
            params = []

        binding = {"tape": (), "variant": "vigenere", "alphabet": "AZ"}
        with pytest.raises(ValueError, match="tape"):
            _translate_layer(_Layer(), binding=binding, text_length=97)

    def test_translator_coerces_letter_tape_string(self):
        # The theorist commonly emits a tape as a letter key (Vigenere-style)
        # rather than integer offsets. The translator should coerce it to
        # standard A=0..Z=25 shifts and dispatch, not raise.
        class _Layer:
            kind = "key_tape"
            params = []

        binding = {
            "tape": "KRYPTOS",
            "variant": "vigenere",
            "direction": "decrypt",
            "null_positions": (),
            "null_rule": "skip",
            "alphabet": "AZ",
        }
        cfg = _translate_layer(_Layer(), binding=binding, text_length=97)
        assert cfg["params"]["tape"] == (10, 17, 24, 15, 19, 14, 18)

    def test_translator_coerces_letter_tape_list(self):
        class _Layer:
            kind = "key_tape"
            params = []

        binding = {
            "tape": ["K", "R", "Y"],
            "variant": "vigenere",
            "alphabet": "AZ",
        }
        cfg = _translate_layer(_Layer(), binding=binding, text_length=97)
        assert cfg["params"]["tape"] == (10, 17, 24)

    def test_translator_still_rejects_genuinely_bad_tape(self):
        # Coercion is best-effort; an out-of-range int is still a hard error.
        class _Layer:
            kind = "key_tape"
            params = []

        binding = {"tape": (0, 99, 5), "variant": "vigenere", "alphabet": "AZ"}
        with pytest.raises(ValueError, match="range"):
            _translate_layer(_Layer(), binding=binding, text_length=97)
