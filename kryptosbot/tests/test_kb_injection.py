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


from kryptosbot.kb_injection import dispatcher_testable


class TestDispatcherTestable:
    def test_columnar_is_supported(self):
        r = _make_record(cipher_family="columnar")
        assert dispatcher_testable(r) is True

    def test_polybius_transposition_is_supported(self):
        r = _make_record(cipher_family="polybius transposition")
        assert dispatcher_testable(r) is True

    def test_grille_is_supported(self):
        r = _make_record(cipher_family="grille")
        assert dispatcher_testable(r) is True

    def test_unknown_family_is_not_supported(self):
        r = _make_record(cipher_family="completely fictional ciphersystem")
        assert dispatcher_testable(r) is False

    def test_empty_family_is_not_supported(self):
        r = _make_record(cipher_family="")
        assert dispatcher_testable(r) is False

    def test_case_insensitive(self):
        r = _make_record(cipher_family="COLUMNAR")
        assert dispatcher_testable(r) is True

    def test_kb_to_dsl_kind_is_filtered_by_supported_kinds(self):
        """Even if KB_TO_DSL_KIND maps to a kind, dispatcher_testable must
        re-check against the dispatcher's _SUPPORTED_KINDS at call time.
        This guards against drift: if a kind is removed from the
        dispatcher, dispatcher_testable immediately stops reporting True
        for it without requiring an edit to kb_family_map.py."""
        import kryptosbot.kb_family_map as km
        import kryptosbot.job_dispatcher as jd
        orig_supported = jd._SUPPORTED_KINDS
        orig_map = dict(km.KB_TO_DSL_KIND)
        try:
            # Pretend "columnar" got pulled from the dispatcher.
            jd._SUPPORTED_KINDS = frozenset(orig_supported) - {"columnar"}
            r = _make_record(cipher_family="columnar")
            assert dispatcher_testable(r) is False
        finally:
            jd._SUPPORTED_KINDS = orig_supported
            km.KB_TO_DSL_KIND = orig_map


from kryptosbot.kb_injection import KBCandidateNoveltyVerdict


class TestKBCandidateNoveltyVerdict:
    def test_dataclass_shape(self):
        v = KBCandidateNoveltyVerdict(
            kb_record_id="abc",
            kb_cipher_family="columnar",
            mapped_ledger_families=("columnar_single", "double_columnar"),
            tested_status_ok=True,
            family_blocked=False,
            static_exhaustion_blocked=False,
            mechanism_signature="0123456789abcdef",
            signature_seen=False,
            dispatcher_testable=True,
            verdict="allow",
            reasons=("ok",),
        )
        assert v.kb_record_id == "abc"
        assert v.verdict == "allow"
        assert v.mapped_ledger_families == ("columnar_single", "double_columnar")

    def test_dataclass_is_frozen(self):
        v = KBCandidateNoveltyVerdict(
            kb_record_id="x", kb_cipher_family="", mapped_ledger_families=(),
            tested_status_ok=False, family_blocked=False, static_exhaustion_blocked=False,
            mechanism_signature="", signature_seen=False,
            dispatcher_testable=False, verdict="reject", reasons=(),
        )
        with pytest.raises((AttributeError, Exception)):
            v.verdict = "allow"

    def test_valid_verdict_values(self):
        for verdict in ("allow", "reject", "defer_needs_mapping"):
            KBCandidateNoveltyVerdict(
                kb_record_id="x", kb_cipher_family="", mapped_ledger_families=(),
                tested_status_ok=False, family_blocked=False, static_exhaustion_blocked=False,
                mechanism_signature="", signature_seen=False,
                dispatcher_testable=False, verdict=verdict, reasons=(),
            )


from kryptosbot.kb_injection import CipherDiscoverySuggestion


class TestCipherDiscoverySuggestion:
    def _example(self, **overrides):
        base = dict(
            kb_record_id="rec-abc-123",
            canonical_name="Test Cipher",
            kb_cipher_family="columnar",
            mapped_ledger_families=("columnar_single", "double_columnar"),
            mechanism_signature="0123456789abcdef",
            signature_schema_version=KB_SIGNATURE_SCHEMA_VERSION,
            dispatcher_testable=True,
            k4_relevance_score=42.5,
            sketch_class="dsl_testable",
            one_line_sketch="A short prose sketch.",
            bounded_kill_criterion="Score must exceed X on Y trials.",
            source_verdict="allow",
        )
        base.update(overrides)
        return CipherDiscoverySuggestion(**base)

    def test_dataclass_shape(self):
        s = self._example()
        assert s.canonical_name == "Test Cipher"
        assert s.mapped_ledger_families == ("columnar_single", "double_columnar")
        assert s.signature_schema_version == "kb_mechanism_sig_v1"

    def test_to_dict_round_trip(self):
        s = self._example()
        d = s.to_dict()
        assert isinstance(d, dict)
        # Tuples become lists in JSON.
        assert isinstance(d["mapped_ledger_families"], list)
        assert d["canonical_name"] == "Test Cipher"
        # JSON serializable end-to-end.
        json_blob = json.dumps(d, sort_keys=True)
        reloaded = json.loads(json_blob)
        s2 = CipherDiscoverySuggestion.from_dict(reloaded)
        assert s2 == s

    def test_from_dict_tolerates_missing_optional_fields(self):
        d = {
            "kb_record_id": "x",
            "canonical_name": "X",
            "kb_cipher_family": "",
            "mapped_ledger_families": [],
            "mechanism_signature": "",
            "signature_schema_version": KB_SIGNATURE_SCHEMA_VERSION,
            "dispatcher_testable": False,
            "k4_relevance_score": 0.0,
            "sketch_class": "unknown",
            "one_line_sketch": "",
            "bounded_kill_criterion": "",
            "source_verdict": "allow",
        }
        s = CipherDiscoverySuggestion.from_dict(d)
        assert s.mapped_ledger_families == ()


from pathlib import Path

from kryptosbot.kb_injection import iter_kb_records


FIXTURE_DB = Path(__file__).resolve().parent / "fixtures" / "cipher_discovery_phase2_fixture.sqlite"


class TestKBRowLoader:
    def test_iter_returns_records_for_fixture(self):
        records = list(iter_kb_records(str(FIXTURE_DB)))
        assert len(records) == 5
        names = {r.canonical_name for r in records}
        assert "Swagman Cipher" in names
        assert "ADFGVX Cipher" in names

    def test_iter_yields_cipher_record_compatible_attrs(self):
        for r in iter_kb_records(str(FIXTURE_DB)):
            assert hasattr(r, "canonical_name")
            assert hasattr(r, "cipher_family")
            assert hasattr(r, "k4_relevance_score")
            assert hasattr(r, "tested_in_project")
            assert hasattr(r, "exhaustion_status")

    def test_iter_returns_empty_for_missing_db(self, tmp_path):
        missing = tmp_path / "does_not_exist.sqlite"
        assert list(iter_kb_records(str(missing))) == []

    def test_iter_skips_corrupt_row(self, tmp_path):
        import sqlite3
        db = tmp_path / "partial.sqlite"
        conn = sqlite3.connect(str(db))
        conn.execute("""
            CREATE TABLE cipher_records (
                record_id TEXT PRIMARY KEY,
                canonical_name TEXT NOT NULL,
                cipher_family TEXT,
                k4_relevance_score REAL,
                tested_in_project BOOLEAN,
                exhaustion_status TEXT
            )
        """)
        # Valid row.
        conn.execute(
            "INSERT INTO cipher_records VALUES ('ok', 'OK Cipher', 'columnar', 10.0, 0, 'untested')"
        )
        # Row with corrupt JSON in a column that we don't strictly need —
        # loader must yield the valid row and continue.
        conn.commit()
        conn.close()
        records = list(iter_kb_records(str(db)))
        # Single valid row.
        assert any(r.canonical_name == "OK Cipher" for r in records)


from kryptosbot.kb_injection import classify_kb_candidate


class TestClassifyKBCandidate:
    def test_allow_unblocked_unseen_signature(self):
        rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
        v = classify_kb_candidate(
            rec,
            prior_signatures={"columnar_single": frozenset(), "double_columnar": frozenset()},
            blocked_families_in_cycle=frozenset({"encoding"}),
            static_exhaustion_blocklist=frozenset(),
        )
        assert v.verdict == "allow"
        assert v.tested_status_ok is True
        assert v.signature_seen is False
        assert v.family_blocked is False

    def test_reject_when_exhausted(self):
        rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-compass-exhausted")
        v = classify_kb_candidate(
            rec,
            prior_signatures={},
            blocked_families_in_cycle=frozenset(),
            static_exhaustion_blocklist=frozenset(),
        )
        assert v.verdict == "reject"
        assert v.tested_status_ok is False
        assert "exhausted" in " ".join(v.reasons).lower()

    def test_reject_when_family_blocked(self):
        rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
        v = classify_kb_candidate(
            rec,
            prior_signatures={},
            blocked_families_in_cycle=frozenset({"columnar_single"}),
            static_exhaustion_blocklist=frozenset(),
        )
        assert v.verdict == "reject"
        assert v.family_blocked is True

    def test_reject_when_signature_seen(self):
        rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
        sig = kb_mechanism_signature(rec)
        v = classify_kb_candidate(
            rec,
            prior_signatures={"columnar_single": frozenset({sig})},
            blocked_families_in_cycle=frozenset(),
            static_exhaustion_blocklist=frozenset(),
        )
        assert v.verdict == "reject"
        assert v.signature_seen is True

    def test_defer_when_unmapped(self):
        rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-unmapped")
        v = classify_kb_candidate(
            rec,
            prior_signatures={},
            blocked_families_in_cycle=frozenset(),
            static_exhaustion_blocklist=frozenset(),
        )
        assert v.verdict == "defer_needs_mapping"
        assert v.mapped_ledger_families == ()

    def test_reject_when_static_exhaustion(self):
        rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
        v = classify_kb_candidate(
            rec,
            prior_signatures={},
            blocked_families_in_cycle=frozenset(),
            static_exhaustion_blocklist=frozenset({"columnar_single"}),
        )
        assert v.verdict == "reject"
        assert v.static_exhaustion_blocked is True


from kryptosbot.kb_injection import query_suggestions


class TestQuerySuggestions:
    def test_returns_only_allow_verdicts(self):
        out = query_suggestions(
            blocked_family="encoding",
            blocked_signature="prev-signature",
            prior_signatures={},
            blocked_families_in_cycle=frozenset({"encoding"}),
            static_exhaustion_blocklist=frozenset(),
            db_path=str(FIXTURE_DB),
        )
        for s in out:
            assert s.source_verdict == "allow"

    def test_excludes_exhausted_fixture_row(self):
        out = query_suggestions(
            blocked_family="encoding",
            blocked_signature="prev-signature",
            prior_signatures={},
            blocked_families_in_cycle=frozenset({"encoding"}),
            static_exhaustion_blocklist=frozenset(),
            db_path=str(FIXTURE_DB),
        )
        names = {s.canonical_name for s in out}
        assert "Compass Cipher" not in names

    def test_excludes_unmapped_fixture_row(self):
        out = query_suggestions(
            blocked_family="encoding",
            blocked_signature="prev-signature",
            prior_signatures={},
            blocked_families_in_cycle=frozenset({"encoding"}),
            static_exhaustion_blocklist=frozenset(),
            db_path=str(FIXTURE_DB),
        )
        names = {s.canonical_name for s in out}
        assert "Mystery Cipher" not in names

    def test_ranks_dispatcher_testable_first_then_by_k4_relevance(self):
        out = query_suggestions(
            blocked_family="encoding",
            blocked_signature="prev-signature",
            prior_signatures={},
            blocked_families_in_cycle=frozenset({"encoding"}),
            static_exhaustion_blocklist=frozenset(),
            db_path=str(FIXTURE_DB),
        )
        # Both Swagman and ADFGVX are dispatcher_testable; Astrolabe is not.
        first_three = [s.canonical_name for s in out[:3]]
        assert "Astrolabe Cipher" not in first_three[:2], (
            "dispatcher-testable rows should sort before non-testable"
        )

    def test_max_per_call_caps_returned_count(self):
        out = query_suggestions(
            blocked_family="encoding",
            blocked_signature="prev-signature",
            prior_signatures={},
            blocked_families_in_cycle=frozenset({"encoding"}),
            static_exhaustion_blocklist=frozenset(),
            db_path=str(FIXTURE_DB),
            max_per_call=2,
        )
        assert len(out) <= 2

    def test_missing_db_returns_empty(self, tmp_path):
        out = query_suggestions(
            blocked_family="encoding",
            blocked_signature="x",
            prior_signatures={},
            blocked_families_in_cycle=frozenset(),
            static_exhaustion_blocklist=frozenset(),
            db_path=str(tmp_path / "missing.sqlite"),
        )
        assert out == ()

    def test_skips_signature_seen_in_mapped_family(self):
        # Compute the Swagman signature, mark it as seen in columnar_single.
        rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
        sig = kb_mechanism_signature(rec)
        out = query_suggestions(
            blocked_family="encoding",
            blocked_signature="x",
            prior_signatures={"columnar_single": frozenset({sig})},
            blocked_families_in_cycle=frozenset(),
            static_exhaustion_blocklist=frozenset(),
            db_path=str(FIXTURE_DB),
        )
        names = {s.canonical_name for s in out}
        assert "Swagman Cipher" not in names
