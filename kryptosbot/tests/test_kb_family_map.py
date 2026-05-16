"""Tests for kryptosbot/kb_family_map.py: curated namespace bridge."""
from __future__ import annotations

import pytest

from kryptosbot.kb_family_map import (
    KB_TO_DSL_KIND,
    KB_TO_LEDGER_FAMILY,
)


class TestConstants:
    def test_kb_to_ledger_family_keys_are_normalized_lowercase(self):
        for k in KB_TO_LEDGER_FAMILY:
            assert k == k.lower(), f"{k!r} should be lowercase"

    def test_kb_to_ledger_family_values_are_frozensets(self):
        for v in KB_TO_LEDGER_FAMILY.values():
            assert isinstance(v, frozenset)
            assert v, "value must be non-empty"

    def test_kb_to_ledger_family_has_expected_keys(self):
        # Spec §4.1 — minimum committed set. Additions are fine; removals
        # need a doc note. We assert presence, not equality, to keep growth
        # additive without test churn.
        expected = {
            "columnar",
            "polybius transposition",
            "positional",
            "steganographic",
            "running key",
            "substitution",
            "polyalphabetic",
            "fractionation",
            "route transposition",
            "monoalphabetic",
            "delastelle",
            "playfair family",
        }
        assert expected <= set(KB_TO_LEDGER_FAMILY)

    def test_kb_to_dsl_kind_values_are_strings(self):
        for v in KB_TO_DSL_KIND.values():
            assert isinstance(v, str)
            assert v
