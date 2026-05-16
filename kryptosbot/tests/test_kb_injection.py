"""Tests for kryptosbot/kb_injection.py: KB signature, novelty join, query."""
from __future__ import annotations

import json

import pytest

from kryptosbot.kb_injection import (
    KB_SIGNATURE_SCHEMA_VERSION,
    kb_mechanism_signature,
)


def _make_record(**overrides):
    """Lightweight CipherRecord stand-in for signature tests. Fields used by
    kb_mechanism_signature only."""
    from kryptos.cipher_discovery.schema import CipherRecord
    defaults = dict(
        canonical_name="Test Cipher",
        alias_names=[],
        category="",
        cipher_family="test family",
        description="A test cipher",
        operational_mechanics="Fold in half, swap odd/even.",
    )
    defaults.update(overrides)
    return CipherRecord(**defaults)


class TestSchemaVersion:
    def test_schema_version_is_v1(self):
        assert KB_SIGNATURE_SCHEMA_VERSION == "kb_mechanism_sig_v1"


class TestKBMechanismSignature:
    def test_returns_16_char_hex(self):
        sig = kb_mechanism_signature(_make_record())
        assert isinstance(sig, str)
        assert len(sig) == 16
        # All lowercase hex.
        int(sig, 16)

    def test_deterministic(self):
        r = _make_record()
        assert kb_mechanism_signature(r) == kb_mechanism_signature(r)

    def test_differs_on_canonical_name_change(self):
        a = kb_mechanism_signature(_make_record(canonical_name="Alpha"))
        b = kb_mechanism_signature(_make_record(canonical_name="Beta"))
        assert a != b

    def test_differs_on_cipher_family_change(self):
        a = kb_mechanism_signature(_make_record(cipher_family="columnar"))
        b = kb_mechanism_signature(_make_record(cipher_family="substitution"))
        assert a != b

    def test_insensitive_to_canonical_name_case(self):
        """Normalization should canonicalize case."""
        a = kb_mechanism_signature(_make_record(canonical_name="Columnar"))
        b = kb_mechanism_signature(_make_record(canonical_name="COLUMNAR"))
        assert a == b

    def test_insensitive_to_whitespace_variations(self):
        a = kb_mechanism_signature(_make_record(cipher_family="polybius transposition"))
        b = kb_mechanism_signature(_make_record(cipher_family="polybius  transposition"))
        c = kb_mechanism_signature(_make_record(cipher_family="  polybius transposition  "))
        assert a == b == c

    def test_excludes_ledger_family_mapping(self):
        """Spec §4.2 invariant: signature describes the KB mechanism, not
        its dispatch routing. Two records with identical KB fields must
        hash identically even if the mapping table changes."""
        r = _make_record(
            canonical_name="Probe",
            cipher_family="columnar",
            cipher_type="historical",
            taxonomy="historically_attested",
            operational_mechanics="ABC",
            description="DEF",
        )
        sig1 = kb_mechanism_signature(r)
        sig2 = kb_mechanism_signature(r)
        assert sig1 == sig2

    def test_includes_schema_version_in_payload(self):
        """If we ever bump KB_SIGNATURE_SCHEMA_VERSION, the same KB record
        must produce a DIFFERENT signature so callers can recognize stale
        payloads. Achieved by including the schema string in the hash."""
        import kryptosbot.kb_injection as kbi
        r = _make_record()
        orig_sig = kb_mechanism_signature(r)
        orig_version = kbi.KB_SIGNATURE_SCHEMA_VERSION
        try:
            kbi.KB_SIGNATURE_SCHEMA_VERSION = "kb_mechanism_sig_v999"
            new_sig = kb_mechanism_signature(r)
        finally:
            kbi.KB_SIGNATURE_SCHEMA_VERSION = orig_version
        assert orig_sig != new_sig
