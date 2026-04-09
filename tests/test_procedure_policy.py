"""Tests for the cipher-procedure admissibility policy.

Covers:
    - ProcedureLicense dataclass validation (required fields enforced)
    - Default allowlist shape and content
    - Gate semantics: accept known, reject unknown
    - Rejection certificate is well-formed and JSON-roundtrippable
    - Override loading: valid and invalid entries handled correctly
    - __init__ re-exports work
    - The PROCEDURE_POLICY_VIOLATION reason code is part of the closed enum
"""
from __future__ import annotations

import json

import pytest

from kryptos.admissibility import (
    EliminationCertificate,
    EliminationReason,
    PROCEDURE_ALLOWLIST,
    ProcedureJustification,
    ProcedureLicense,
    ProcedurePolicyError,
    certificate_from_json,
    certificate_to_json,
    check_cipher_procedure,
    get_procedure_license,
    load_procedure_allowlist_override,
)


# ── Dataclass validation ─────────────────────────────────────────────────

class TestProcedureLicenseDataclass:

    def _valid_kwargs(self, **overrides):
        base = dict(
            procedure_id="test_proc",
            name="Test Procedure",
            family="substitution",
            justification=ProcedureJustification.CLUE_SURFACE,
            provenance_uri="reference/Notes/test.txt",
            evidence_refs=("docs/example.md",),
            parametric_spec="src/kryptos/kernel/transforms/vigenere.py",
            added_at="2026-04-09T00:00:00+00:00",
            notes="test",
        )
        base.update(overrides)
        return base

    def test_valid_license_constructs(self):
        lic = ProcedureLicense(**self._valid_kwargs())
        assert lic.procedure_id == "test_proc"
        assert lic.justification is ProcedureJustification.CLUE_SURFACE

    def test_empty_procedure_id_rejected(self):
        with pytest.raises(ValueError, match="procedure_id required"):
            ProcedureLicense(**self._valid_kwargs(procedure_id=""))

    def test_empty_provenance_uri_rejected(self):
        with pytest.raises(ValueError, match="provenance_uri required"):
            ProcedureLicense(**self._valid_kwargs(provenance_uri=""))

    def test_empty_evidence_refs_rejected(self):
        with pytest.raises(ValueError, match="evidence_refs required"):
            ProcedureLicense(**self._valid_kwargs(evidence_refs=()))

    def test_empty_parametric_spec_rejected(self):
        with pytest.raises(ValueError, match="parametric_spec required"):
            ProcedureLicense(**self._valid_kwargs(parametric_spec=""))

    def test_as_dict_serialises_justification_and_refs(self):
        lic = ProcedureLicense(**self._valid_kwargs())
        d = lic.as_dict()
        assert d["justification"] == "clue_surface"
        assert d["evidence_refs"] == ["docs/example.md"]
        assert d["parametric_spec"] == (
            "src/kryptos/kernel/transforms/vigenere.py"
        )


# ── Default allowlist shape ──────────────────────────────────────────────

class TestDefaultProcedureAllowlist:

    def test_allowlist_nonempty(self):
        assert len(PROCEDURE_ALLOWLIST) >= 4

    def test_entries_well_formed(self):
        for lic in PROCEDURE_ALLOWLIST.values():
            assert isinstance(lic, ProcedureLicense)
            assert isinstance(lic.justification, ProcedureJustification)
            assert lic.evidence_refs
            assert lic.provenance_uri
            assert lic.parametric_spec

    def test_core_procedures_present(self):
        assert "quagmire_iii_family" in PROCEDURE_ALLOWLIST
        assert "k3_columnar_transposition" in PROCEDURE_ALLOWLIST
        assert "abscissa_as_keyword" in PROCEDURE_ALLOWLIST
        assert "atbash_substitution_layer" in PROCEDURE_ALLOWLIST

    def test_clue_surface_entries_have_kryptos_uri(self):
        # CLUE_SURFACE procedures must point at an in-sculpture
        # derivation pointer (the kryptos:// scheme is our convention
        # for 'this is derivable from the sculpture itself').
        for lic in PROCEDURE_ALLOWLIST.values():
            if lic.justification is ProcedureJustification.CLUE_SURFACE:
                assert lic.provenance_uri.startswith("kryptos://"), (
                    f"{lic.procedure_id} has CLUE_SURFACE justification "
                    f"but non-kryptos provenance_uri {lic.provenance_uri!r}"
                )

    def test_archive_evidence_entries_cite_archive(self):
        # ARCHIVE_EVIDENCE procedures must point at an archive source.
        # The initial allowlist uses reference/Notes/ as the canonical
        # archive location; if that convention changes, this test
        # should be updated.
        for lic in PROCEDURE_ALLOWLIST.values():
            if lic.justification is ProcedureJustification.ARCHIVE_EVIDENCE:
                assert "reference/" in lic.provenance_uri or (
                    lic.provenance_uri.startswith("http")
                ), (
                    f"{lic.procedure_id} has ARCHIVE_EVIDENCE justification "
                    f"but provenance_uri {lic.provenance_uri!r} does not "
                    f"point at an archive source."
                )


# ── Gate semantics ───────────────────────────────────────────────────────

class TestProcedureGate:

    def test_get_license_hit(self):
        lic = get_procedure_license("quagmire_iii_family")
        assert lic is not None
        assert lic.procedure_id == "quagmire_iii_family"

    def test_get_license_miss_returns_none(self):
        assert get_procedure_license("no_such_procedure_xyz") is None

    def test_accept_known_procedure(self):
        ok, cert = check_cipher_procedure("quagmire_iii_family")
        assert ok is True
        assert cert is None

    def test_reject_unknown_procedure(self):
        ok, cert = check_cipher_procedure("bespoke_fantasy_cipher_42")
        assert ok is False
        assert cert is not None
        assert cert.reason is EliminationReason.PROCEDURE_POLICY_VIOLATION
        assert "allowlist" in cert.summary.lower()
        assert cert.evidence["procedure_id"] == "bespoke_fantasy_cipher_42"

    def test_reject_empty_procedure_id(self):
        ok, cert = check_cipher_procedure("")
        assert ok is False
        assert cert is not None
        assert cert.reason is EliminationReason.PROCEDURE_POLICY_VIOLATION
        assert "empty" in cert.summary.lower()

    def test_family_override_passes_through(self):
        ok, cert = check_cipher_procedure(
            "bespoke_unknown", family="test/custom_family",
        )
        assert ok is False
        assert cert.family == "test/custom_family"

    def test_rejection_certificate_is_json_roundtrippable(self):
        ok, cert = check_cipher_procedure("not_a_real_procedure")
        assert not ok
        payload = certificate_to_json(cert)
        parsed = certificate_from_json(payload)
        assert isinstance(parsed, EliminationCertificate)
        assert parsed.reason is EliminationReason.PROCEDURE_POLICY_VIOLATION
        assert parsed.evidence["procedure_id"] == "not_a_real_procedure"

    def test_rejection_evidence_lists_allowlist(self):
        # A rejected caller should be able to discover what WAS allowed
        # by reading the certificate. This prevents the "what can I
        # actually use?" guessing game when a procedure is rejected.
        ok, cert = check_cipher_procedure("unknown")
        assert not ok
        allowed = cert.evidence["allowlisted_ids"]
        assert "quagmire_iii_family" in allowed
        assert sorted(allowed) == allowed  # deterministic ordering


# ── Override loading ─────────────────────────────────────────────────────

class TestOverrideLoading:

    def test_nonexistent_override_file_returns_zero(self, tmp_path):
        count = load_procedure_allowlist_override(
            tmp_path / "nonexistent.json"
        )
        assert count == 0

    def test_valid_override_entry_is_added(self, tmp_path, monkeypatch):
        override = [
            {
                "procedure_id": "test_override_entry",
                "name": "Test Override Procedure",
                "family": "substitution",
                "justification": "archive_evidence",
                "provenance_uri": "reference/test.txt",
                "evidence_refs": ["docs/test.md"],
                "parametric_spec": "src/test.py",
                "notes": "test override",
            }
        ]
        p = tmp_path / "override.json"
        p.write_text(json.dumps(override))
        try:
            added = load_procedure_allowlist_override(p)
            assert added == 1
            lic = get_procedure_license("test_override_entry")
            assert lic is not None
            assert lic.name == "Test Override Procedure"
        finally:
            # Clean up runtime registry so other tests are unaffected.
            PROCEDURE_ALLOWLIST.pop("test_override_entry", None)

    def test_invalid_override_raises(self, tmp_path):
        override = [
            {
                "procedure_id": "broken_override",
                "name": "Missing fields",
                # missing family, justification, provenance_uri, etc.
            }
        ]
        p = tmp_path / "override.json"
        p.write_text(json.dumps(override))
        with pytest.raises(ProcedurePolicyError, match="invalid entries"):
            load_procedure_allowlist_override(p)
        # Partial success must NOT leak a half-registered entry.
        assert get_procedure_license("broken_override") is None

    def test_override_duplicate_procedure_id_rejected(self, tmp_path):
        override = [
            {
                "procedure_id": "quagmire_iii_family",  # already in default
                "name": "Collision",
                "family": "substitution",
                "justification": "clue_surface",
                "provenance_uri": "kryptos://x",
                "evidence_refs": ["docs/x.md"],
                "parametric_spec": "src/x.py",
            }
        ]
        p = tmp_path / "override.json"
        p.write_text(json.dumps(override))
        with pytest.raises(ProcedurePolicyError, match="duplicate"):
            load_procedure_allowlist_override(p)

    def test_override_non_list_rejected(self, tmp_path):
        p = tmp_path / "override.json"
        p.write_text(json.dumps({"not": "a list"}))
        with pytest.raises(ProcedurePolicyError, match="JSON list"):
            load_procedure_allowlist_override(p)


# ── Derivation-pointer discipline (aspirational invariants) ─────────────

class TestDerivationPointerDiscipline:
    """The allowlist should never admit procedures whose justification
    is purely "Sanborn/Scheidt read about this" without a Kryptos-
    internal derivation pointer. These tests are the teeth of the
    mechanics-vs-construction distinction documented in the
    ProcedureJustification docstring."""

    def test_no_mechanics_only_entries(self):
        # Mechanics-only entries are flagged by notes or provenance
        # pointing solely at "the creator read this during design".
        # This is a soft check: we assert no entry contains a known
        # mechanics-only phrase in its notes.
        forbidden_phrases = [
            "read this while designing",
            "mechanics consultation",
            "design reference only",
        ]
        for lic in PROCEDURE_ALLOWLIST.values():
            lower_notes = lic.notes.lower()
            for phrase in forbidden_phrases:
                assert phrase not in lower_notes, (
                    f"{lic.procedure_id} notes contain mechanics-only "
                    f"phrase {phrase!r}; this suggests the license is "
                    f"grounded in cipher-design consultation rather "
                    f"than in an actual K4 construction claim."
                )

    def test_every_entry_pins_a_parametric_spec(self):
        # Every license must name a parametric spec so that scripts
        # claiming the license cannot operationalize it in ad-hoc
        # ways. This is the analog of the corpus policy reading bytes
        # exclusively from the license path.
        for lic in PROCEDURE_ALLOWLIST.values():
            assert lic.parametric_spec, (
                f"{lic.procedure_id} has no parametric_spec; scripts "
                f"using this license would have no pinned operational "
                f"definition."
            )
            # Must at least LOOK like a repo path or URI. We don't
            # enforce file existence here because parametric specs
            # may live in docs/ files that are not guaranteed to be
            # present at test time.
            assert "/" in lic.parametric_spec or "://" in lic.parametric_spec
