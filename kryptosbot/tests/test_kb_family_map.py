"""Tests for kryptosbot/kb_family_map.py: curated namespace bridge."""
from __future__ import annotations

from kryptosbot.kb_family_map import (
    KB_TO_DSL_KIND,
    KB_TO_LEDGER_FAMILY,
    map_kb_family_to_ledger_families,
    normalize_kb_family,
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


class TestNormalize:
    def test_lowercases(self):
        assert normalize_kb_family("Columnar") == "columnar"

    def test_collapses_whitespace(self):
        assert normalize_kb_family("Polybius   Transposition") == "polybius transposition"

    def test_strips(self):
        assert normalize_kb_family("  columnar  ") == "columnar"

    def test_empty(self):
        assert normalize_kb_family("") == ""
        assert normalize_kb_family("   ") == ""

    def test_none_safe(self):
        # KB rows may have NULL family; treat as empty string.
        assert normalize_kb_family(None) == ""


class TestMapKBFamily:
    def test_known_family(self):
        assert map_kb_family_to_ledger_families("columnar") == frozenset(
            {"columnar_single", "double_columnar", "route_cipher"}
        )

    def test_case_insensitive(self):
        assert map_kb_family_to_ledger_families("COLUMNAR") == frozenset(
            {"columnar_single", "double_columnar", "route_cipher"}
        )

    def test_whitespace_insensitive(self):
        assert map_kb_family_to_ledger_families("polybius  transposition") == frozenset(
            {"fractionation", "multi_layer"}
        )

    def test_unmapped_returns_none(self):
        # Phase 2 invariant 3: unmapped KB family → defer, not silent allow.
        assert map_kb_family_to_ledger_families("xyzzy never seen") is None

    def test_empty_returns_none(self):
        assert map_kb_family_to_ledger_families("") is None
        assert map_kb_family_to_ledger_families(None) is None
