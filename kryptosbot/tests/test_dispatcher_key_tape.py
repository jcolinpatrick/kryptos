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
