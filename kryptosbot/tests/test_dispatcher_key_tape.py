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
        # Minimal duck-typed mock: layer.params is a dict (not a list of
        # ParamRange) so validate_layer_for_kind can call .get() on it
        # directly without requiring the full CipherLayer machinery.
        class _Layer:
            def __init__(self, params):
                self.kind = "key_tape"
                self.params = params

        layer = _Layer({
            "tape": (1, 2, 3, 4, 5),
            "variant": "vigenere",
            "direction": "decrypt",
            "null_positions": (),
            "null_rule": "skip",
            "alphabet": "AZ",
        })
        cfg = _translate_layer(layer, binding={}, text_length=97)
        assert isinstance(cfg, dict)
        assert cfg["type"] == "key_tape"
        assert cfg["tape"] == (1, 2, 3, 4, 5)
        assert cfg["variant"] == "vigenere"
        assert cfg["alphabet"] == "AZ"

    def test_translator_rejects_empty_tape(self):
        class _Layer:
            def __init__(self, params):
                self.kind = "key_tape"
                self.params = params

        layer = _Layer({"tape": (), "variant": "vigenere", "alphabet": "AZ"})
        with pytest.raises(ValueError):
            _translate_layer(layer, binding={}, text_length=97)
