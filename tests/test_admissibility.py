"""Tests for the admissibility-first layer.

Covers:
    - EliminationCertificate / AdmissibilityCertificate roundtrip
    - Corpus policy allowlist semantics (accept known, reject unknown)
    - Corpus policy produces well-formed certificates on rejection
    - Periodic additive admissibility: known-feasible and known-UNSAT cases
    - CP-SAT / pure-Python agreement (when ortools is installed)
    - Triage gate: running-key hypothesis with unlicensed source is
      eliminated with a JSON certificate in `elimination_reason`
"""
from __future__ import annotations

import json

import pytest

from kryptos.admissibility import (
    AdmissibilityCertificate,
    CORPUS_ALLOWLIST,
    CorpusLicense,
    CorpusJustification,
    EliminationCertificate,
    EliminationReason,
    certificate_from_json,
    certificate_to_json,
    check_corpus_source,
    check_periodic_additive,
    get_license,
    sweep_periodic_additive,
)
from kryptos.admissibility.periodic_admissibility import HAS_CP_SAT
from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ


# ── Certificate serialisation ───────────────────────────────────────────

class TestCertificateRoundtrip:

    def test_elimination_roundtrip(self):
        cert = EliminationCertificate(
            family="test/family",
            reason=EliminationReason.BEAN_UNSAT,
            summary="contrived",
            assumptions=["A1", "A2"],
            evidence={"period": 7, "residue": 3},
            solver="cp_sat",
            is_exact=True,
        )
        payload = certificate_to_json(cert)
        parsed = certificate_from_json(payload)
        assert isinstance(parsed, EliminationCertificate)
        assert parsed.family == "test/family"
        assert parsed.reason is EliminationReason.BEAN_UNSAT
        assert parsed.assumptions == ["A1", "A2"]
        assert parsed.evidence == {"period": 7, "residue": 3}
        assert parsed.is_exact is True

    def test_admissibility_roundtrip(self):
        cert = AdmissibilityCertificate(
            family="test/family",
            summary="survives",
            assumptions=["A1"],
            evidence={"free_residues": [0, 1]},
            solver="pure_python",
        )
        payload = certificate_to_json(cert)
        parsed = certificate_from_json(payload)
        assert isinstance(parsed, AdmissibilityCertificate)
        assert parsed.family == "test/family"
        assert parsed.evidence["free_residues"] == [0, 1]

    def test_legacy_plain_string_is_not_a_certificate(self):
        # Old `elimination_reason` rows are plain strings; parser must
        # return None rather than raise, preserving backward compatibility.
        assert certificate_from_json("noise floor") is None
        assert certificate_from_json("") is None
        assert certificate_from_json("{\"broken\": true}") is None

    def test_reason_enum_is_closed(self):
        # The admissibility layer's contract is that reason codes are
        # a closed, documented set.  Anyone adding a new reason must
        # update this test deliberately.
        expected = {
            "bean_unsat",
            "crib_position_contradiction",
            "insufficient_key_dof",
            "empty_parameter_space",
            "topology_contradiction",
            "corpus_policy_violation",
            "assumption_unmet",
            "no_hits_full_enum",
            "no_hits_under_budget",
            "runtime_exhausted",
        }
        assert {r.value for r in EliminationReason} == expected


# ── Corpus policy ───────────────────────────────────────────────────────

class TestCorpusPolicy:

    def test_default_allowlist_nonempty_and_well_formed(self):
        assert len(CORPUS_ALLOWLIST) >= 3
        for lic in CORPUS_ALLOWLIST.values():
            assert isinstance(lic, CorpusLicense)
            assert isinstance(lic.justification, CorpusJustification)
            assert lic.evidence_refs  # at least one reference
            assert lic.provenance_uri

    def test_known_source_ids_present(self):
        assert "k1_plaintext" in CORPUS_ALLOWLIST
        assert "carter_tomb_vol1" in CORPUS_ALLOWLIST
        assert "kahn_codebreakers" in CORPUS_ALLOWLIST
        assert "panel_ciphertext" in CORPUS_ALLOWLIST

    def test_panel_ciphertext_license_shape(self):
        """panel_ciphertext must be CLUE_SURFACE and evidence-ref'd."""
        from kryptos.admissibility.corpus_policy import CorpusJustification
        lic = get_license("panel_ciphertext")
        assert lic is not None
        assert lic.justification is CorpusJustification.CLUE_SURFACE
        assert lic.author == "Jim Sanborn"
        # Must carry at least one evidence ref and one be the constants file
        assert len(lic.evidence_refs) >= 1
        assert any("constants.py" in ref for ref in lic.evidence_refs)
        # Opaque kryptos:// URI — not file-backed by design
        assert lic.provenance_uri.startswith("kryptos://")

    def test_get_license_miss_returns_none(self):
        assert get_license("no_such_source_id_xyz") is None

    def test_reject_unknown_source_id(self):
        ok, cert = check_corpus_source(
            "random_unknown_book", family="running_key", is_source_id=True,
        )
        assert ok is False
        assert cert is not None
        assert cert.reason is EliminationReason.CORPUS_POLICY_VIOLATION
        assert "allowlist" in cert.summary.lower()
        assert cert.evidence["mapped_source_id"] == "random_unknown_book"

    def test_reject_arbitrary_path(self):
        ok, cert = check_corpus_source(
            "/tmp/some_random_novel.txt", family="running_key",
        )
        assert ok is False
        assert cert is not None
        assert cert.reason is EliminationReason.CORPUS_POLICY_VIOLATION
        assert cert.evidence["mapped_source_id"] is None

    def test_accept_known_source_id(self):
        ok, cert = check_corpus_source(
            "carter_tomb_vol1", family="running_key", is_source_id=True,
        )
        assert ok is True
        assert cert is None

    def test_accept_heuristic_path_mapping(self):
        ok, cert = check_corpus_source(
            "reference/carter_vol1.txt", family="running_key",
        )
        assert ok is True
        assert cert is None

    def test_rejection_certificate_is_json_serialisable(self):
        ok, cert = check_corpus_source(
            "random_book", family="running_key", is_source_id=True,
        )
        assert not ok
        payload = certificate_to_json(cert)
        parsed = certificate_from_json(payload)
        assert isinstance(parsed, EliminationCertificate)
        assert parsed.reason is EliminationReason.CORPUS_POLICY_VIOLATION


# ── Periodic additive admissibility ─────────────────────────────────────

class TestPeriodicAdmissibility:

    def test_period_1_beaufort_unsat(self):
        # Period 1 means a single global key byte for all 97 positions.
        # All 24 crib positions would need the same derived key value;
        # they don't.  Expect a CRIB_POSITION_CONTRADICTION certificate.
        cert = check_periodic_additive("beaufort", 1)
        assert isinstance(cert, EliminationCertificate)
        assert cert.is_exact is True
        assert cert.reason in (
            EliminationReason.CRIB_POSITION_CONTRADICTION,
            EliminationReason.BEAN_UNSAT,
        )
        assert cert.family == "periodic_additive/beaufort/p1"
        # Must carry all base assumptions
        assert any("A1" in a for a in cert.assumptions)
        assert any("A2" in a for a in cert.assumptions)
        assert any("A3" in a for a in cert.assumptions)

    def test_period_1_all_variants_unsat(self):
        for v in ("vigenere", "beaufort", "var_beaufort"):
            cert = check_periodic_additive(v, 1)
            assert isinstance(cert, EliminationCertificate), (
                f"{v}/p1 should be infeasible"
            )
            assert cert.is_exact is True

    def test_period_large_is_admissible(self):
        # With period ~= crib span, each residue class is essentially a
        # singleton and the family trivially survives cheap checks.
        # Pick a period larger than the max crib separation that still
        # places all crib positions in distinct residue classes.
        cert = check_periodic_additive("beaufort", 97)
        assert isinstance(cert, AdmissibilityCertificate)

    def test_period_2_bean_ineq_self_contradicts(self):
        # For period 2, any Bean inequality pair (a, b) with a%2 == b%2
        # forces k[a%2] != k[a%2] — trivially UNSAT.  Verify there IS
        # such a pair in the known Bean inequality set (sanity of input).
        has_same_parity_pair = any(
            (a % 2) == (b % 2) for a, b in BEAN_INEQ
        )
        assert has_same_parity_pair, (
            "Precondition: BEAN_INEQ must contain a same-parity pair"
        )
        cert = check_periodic_additive("beaufort", 2)
        assert isinstance(cert, EliminationCertificate)
        assert cert.is_exact is True

    def test_sweep_has_all_expected_entries(self):
        certs = sweep_periodic_additive(
            periods=tuple(range(1, 8)),
            variants=("beaufort",),
        )
        assert len(certs) == 7
        families = [c.family for c in certs]
        assert families == [
            f"periodic_additive/beaufort/p{p}" for p in range(1, 8)
        ]

    @pytest.mark.skipif(not HAS_CP_SAT, reason="ortools not installed")
    def test_cp_sat_and_pure_python_agree(self):
        # Cross-verify on a modest grid.  Any disagreement is a modelling
        # bug and must fail loudly.
        for variant in ("vigenere", "beaufort", "var_beaufort"):
            for period in (1, 2, 3, 5, 7, 11, 13, 26):
                cert = check_periodic_additive(
                    variant, period, cross_verify=True,
                )
                # If the call returns, backends agreed.
                assert cert.family == (
                    f"periodic_additive/{variant}/p{period}"
                )

    def test_certificate_carries_solver_tag(self):
        cert = check_periodic_additive("beaufort", 1, use_cp_sat=False)
        assert cert.solver == "pure_python"


class TestCtOverrideAndComposition:
    """Tests for the ct_override extension that powers composition sweeps."""

    def test_ct_override_identity_matches_raw(self):
        """ct_override equal to the raw CT should produce the same UNSAT
        verdict as the default raw-CT path, modulo the `include_bean`
        default switch (which is off when ct_override is set)."""
        from kryptos.kernel.constants import CT, ALPH_IDX
        raw_ints = tuple(ALPH_IDX[c] for c in CT)
        for v in ("vigenere", "beaufort", "var_beaufort"):
            cert_raw = check_periodic_additive(v, 1, use_cp_sat=False)
            cert_ovr = check_periodic_additive(
                v, 1, use_cp_sat=False, ct_override=raw_ints,
            )
            # Both should be UNSAT at period 1 (any crib-collision
            # survives even with Bean removed).
            assert isinstance(cert_raw, EliminationCertificate)
            assert isinstance(cert_ovr, EliminationCertificate)
            assert cert_ovr.family.startswith("periodic_additive/")

    def test_ct_override_bean_default_off(self):
        """When ct_override is supplied and include_bean is not specified,
        the Bean check is skipped (evidence.bean_applied is False).

        At period 97 each crib position has its own residue class, so
        the CSP is trivially SAT regardless of Bean — that lets us
        observe the `bean_applied=False` default cleanly.
        """
        from kryptos.kernel.constants import CT, ALPH_IDX
        raw_ints = tuple(ALPH_IDX[c] for c in CT)
        cert = check_periodic_additive(
            "beaufort", 97, use_cp_sat=False, ct_override=raw_ints,
        )
        assert isinstance(cert, AdmissibilityCertificate)
        assert cert.evidence.get("bean_applied") is False

    def test_ct_override_forces_crib_collision_unsat(self):
        """Construct a ct_override that forces two crib positions in the
        same period=1 residue class to require different key values.
        This must produce CRIB_POSITION_CONTRADICTION regardless of Bean.
        """
        # period=1 has one residue class, so any two cribs with distinct
        # derived key values must collide.  Pick ct_override values that
        # produce distinct derived k values for Beaufort at positions
        # 21 and 22: k = (ct + pt) % 26.  PT[21]=E(4), PT[22]=A(0).
        # Pick ct_override[21]=0 → k=4, ct_override[22]=5 → k=5.
        # Any distinct pair works.
        ct_override = [0] * 97
        ct_override[21] = 0   # k=4
        ct_override[22] = 5   # k=5
        cert = check_periodic_additive(
            "beaufort", 1, use_cp_sat=False, ct_override=ct_override,
        )
        assert isinstance(cert, EliminationCertificate)
        assert cert.reason is EliminationReason.CRIB_POSITION_CONTRADICTION

    def test_family_override_passes_through(self):
        cert = check_periodic_additive(
            "beaufort", 1, use_cp_sat=False,
            family_override="composition/beaufort/w5/co(2,0,4,1,3)/p1",
        )
        assert cert.family == "composition/beaufort/w5/co(2,0,4,1,3)/p1"

    def test_composition_calibration_known_roundtrip(self):
        """End-to-end calibration: construct a PT with cribs at the
        correct positions, encrypt with a known (w, col_order, period,
        key) under the composition direction, then verify that the
        admissibility check on the reindexed CT returns SAT with key
        values consistent with the synthetic key.

        This validates BOTH the columnar reindexing math and the
        ct_override plumbing in one shot.
        """
        from kryptos.kernel.constants import ALPH_IDX, CRIB_DICT, MOD
        from kryptos.kernel.transforms.transposition import (
            columnar_perm, invert_perm,
        )

        # Build a 97-char synthetic PT with the K4 cribs at the correct
        # positions and arbitrary filler ('A') elsewhere.
        pt_chars = ["A"] * 97
        for pos, ch in CRIB_DICT.items():
            pt_chars[pos] = ch
        pt_ints = [ALPH_IDX[c] for c in pt_chars]

        # Synthetic composition: variant=beaufort, w=5, col_order
        # (alphabetical for keyword 'COBRA' -> ranks A=0,B=1,C=2,O=3,R=4
        # placed as C,O,B,R,A -> order=(2,3,1,4,0)), period=7, key=...
        w = 5
        col_order = (2, 3, 1, 4, 0)  # 'COBRA'
        period = 7
        synthetic_key = (3, 1, 4, 1, 5, 9, 2)  # pi-ish

        # Encrypt: additive first, then columnar transposition.
        # Beaufort encrypt: CT_intermediate[j] = (key - PT[j]) mod 26.
        intermediate = [
            (synthetic_key[j % period] - pt_ints[j]) % MOD
            for j in range(97)
        ]
        perm = columnar_perm(w, col_order, length=97)
        # CT[i] = intermediate[perm[i]]
        ct_ints = [intermediate[perm[i]] for i in range(97)]

        # Now run the admissibility check on the reindexed CT:
        # ct_override[j] = CT[inv_perm[j]] = intermediate[j] (identity
        # trivially by construction).  We verify the full pipeline,
        # going through invert_perm as a production caller would.
        inv = invert_perm(perm)
        ct_reindexed = [ct_ints[inv[j]] for j in range(97)]

        cert = check_periodic_additive(
            "beaufort", period,
            use_cp_sat=False,
            ct_override=ct_reindexed,
            family_override=f"calibration/w{w}/co{col_order}/p{period}",
        )
        # Must be SAT — a synthetic key exists by construction.
        assert isinstance(cert, AdmissibilityCertificate)

        # And the derived k values at each crib position must equal
        # the synthetic key at that residue class.
        for pos, pt_ch in CRIB_DICT.items():
            k_derived = (ct_reindexed[pos] + ALPH_IDX[pt_ch]) % MOD
            assert k_derived == synthetic_key[pos % period], (
                f"key mismatch at pos {pos}: "
                f"derived {k_derived}, expected {synthetic_key[pos % period]}"
            )


# ── Triage gate integration ─────────────────────────────────────────────

class TestTriageGate:
    """Verifies that triage_running_key enforces the corpus policy."""

    def test_unlicensed_source_is_rejected_with_certificate(self):
        from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus
        from kryptos.novelty.triage import triage_running_key

        hyp = Hypothesis(
            description="running key from a random novel",
            transform_stack=[{
                "type": "vigenere",
                "params": {
                    "key_source": "running_key",
                    "source_path": "/tmp/random_unknown_book.txt",
                },
            }],
        )
        result = triage_running_key(hyp)
        assert result.status is HypothesisStatus.ELIMINATED
        assert result.elimination_reason  # non-empty

        # Must be a JSON certificate, parseable by the admissibility layer.
        cert = certificate_from_json(result.elimination_reason)
        assert isinstance(cert, EliminationCertificate)
        assert cert.reason is EliminationReason.CORPUS_POLICY_VIOLATION

    def test_adversarial_source_path_is_not_read(self, tmp_path, monkeypatch):
        """Headline regression test for the source_id/source_path bypass.

        A caller passing source_id='k1_plaintext' (licensed) together with
        source_path='/tmp/adversarial.txt' (unrelated) must NOT cause the
        adversarial path to be opened.  The bytes consumed must be
        determined by the license, not by the caller-supplied path.
        """
        from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus
        from kryptos.novelty.triage import triage_running_key

        adversarial = tmp_path / "adversarial.txt"
        adversarial.write_text("A" * 5000)  # long enough to pass len check

        # Spy on Path.read_text to detect any access to the adversarial file.
        import pathlib
        original_read_text = pathlib.Path.read_text
        reads: list[str] = []

        def spy_read_text(self, *args, **kwargs):
            reads.append(str(self.resolve()))
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(pathlib.Path, "read_text", spy_read_text)

        hyp = Hypothesis(
            description="bypass attempt: licensed id + adversarial path",
            transform_stack=[{
                "type": "vigenere",
                "params": {
                    "key_source": "running_key",
                    "source_id": "k1_plaintext",
                    "source_path": str(adversarial),
                },
            }],
        )
        result = triage_running_key(hyp)

        # The adversarial path must never have been opened.
        for r in reads:
            assert str(adversarial.resolve()) != r, (
                f"adversarial path was read: {r}"
            )

        # k1_plaintext uses an opaque kryptos:// URI that has no local
        # resolver, so the gate must emit ASSUMPTION_UNMET — not score
        # arbitrary bytes.
        assert result.status is HypothesisStatus.ELIMINATED
        cert = certificate_from_json(result.elimination_reason or "")
        assert isinstance(cert, EliminationCertificate)
        assert cert.reason is EliminationReason.ASSUMPTION_UNMET
        assert "provenance" in cert.summary.lower()

    def test_licensed_source_is_read_from_license_not_caller_path(
        self, tmp_path, monkeypatch,
    ):
        """A licensed source backed by a real file must be read from the
        license's provenance_uri, regardless of any caller source_path.
        """
        from kryptos.admissibility import corpus_policy as cp
        from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus
        from kryptos.novelty.triage import triage_running_key

        # Install a test-only license pointing at a tmp file with exactly
        # one known character (100 'A's: long enough to pass triage).
        good = tmp_path / "good.txt"
        good.write_text("A" * 500)

        test_lic = cp.CorpusLicense(
            source_id="test_only_source",
            title="test",
            author="test",
            justification=cp.CorpusJustification.ARCHIVE_EVIDENCE,
            provenance_uri=str(good),
            evidence_refs=("test_only",),
            sha256_hash=None,
            added_at="test",
        )
        monkeypatch.setitem(cp.CORPUS_ALLOWLIST, "test_only_source", test_lic)

        # Caller passes an adversarial source_path — it must be ignored.
        adversarial = tmp_path / "adversarial.txt"
        adversarial.write_text("Z" * 500)

        hyp = Hypothesis(
            description="licensed real file, adversarial caller path",
            transform_stack=[{
                "type": "vigenere",
                "params": {
                    "key_source": "running_key",
                    "source_id": "test_only_source",
                    "source_path": str(adversarial),
                },
            }],
        )
        result = triage_running_key(hyp)
        # Triage should have actually scored something (not eliminated
        # with a policy/assumption cert).  "Sampled" is in the detail
        # when scoring ran.
        assert "Sampled" in (result.triage_detail or "")

    def test_resolve_license_path_for_known_file_backed_source(self):
        """resolve_license_path returns a real Path for carter_tomb_vol1."""
        from kryptos.admissibility import resolve_license_path
        p = resolve_license_path("carter_tomb_vol1")
        assert p is not None
        assert p.exists()
        assert p.is_file()

    def test_resolve_license_path_returns_none_for_opaque_uri(self):
        """K1/K2/K3 use kryptos:// opaque URIs with no local resolver."""
        from kryptos.admissibility import resolve_license_path
        assert resolve_license_path("k1_plaintext") is None
        assert resolve_license_path("k2_plaintext") is None
        assert resolve_license_path("k3_plaintext") is None

    def test_resolve_license_path_returns_none_for_unlicensed_source(self):
        from kryptos.admissibility import resolve_license_path
        assert resolve_license_path("no_such_source_id") is None
