"""Tests for the CT-perturbation Stage B framework primitives.

Covers:
    1. AmbiguousPositionsManifest schema validation (positive + negative)
    2. Hamming-2 enumerator correctness, count, determinism, scope
    3. Universe cardinality formula
    4. Scope exclusion: no H1, no H3, no running-key, no corpus

Stage B framework only — full campaign runner is deferred until
operator supplies a predeclared ambiguous-position set per
docs/campaigns/ct_perturbation_stage_b_prereg.md §3.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import pytest

from kryptos.kernel.constants import CT as CANONICAL_CT, CT_LEN, MOD
from kryptosbot.ct_perturbation import (
    AMBIGUOUS_POSITIONS_SCHEMA_VERSION,
    AmbiguousPositionsManifest,
    CAMPAIGN_ID_STAGE_B,
    CTVariantH2,
    STAGE_B_K_MAX_DEFAULT,
    SUPPORTED_ALPHABET_KINDS,
    SUPPORTED_FAMILIES,
    enumerate_hamming2_variants_constrained,
    load_ambiguous_positions,
    stage_b_universe_size,
)


# ── Test fixtures ────────────────────────────────────────────────────────


def _checksum_for(positions):
    payload = ",".join(str(p) for p in sorted(positions)).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _valid_manifest_dict(positions=(0, 5, 96), rationale=None):
    rationale = rationale or {
        str(p): f"position {p} flagged: example archive rationale"
        for p in positions
    }
    return {
        "schema_version": AMBIGUOUS_POSITIONS_SCHEMA_VERSION,
        "archive_provenance": {
            "primary_source": "AAA, Sanborn box X folder Y, image IMG_TEST",
            "image_hashes": ["sha256:" + "0" * 64],
            "evaluator": "test fixture",
            "evaluation_date": "2026-05-02",
            "method": "synthetic test fixture",
        },
        "positions": list(positions),
        "rationale_per_position": rationale,
        "checksum": {
            "sha256_of_positions_sorted": _checksum_for(positions),
        },
    }


def _write_manifest(tmp_path: Path, payload) -> Path:
    path = tmp_path / "ambiguous_positions.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ── Schema validation: positive cases ────────────────────────────────────


class TestManifestLoadPositive:
    def test_loads_valid_minimal_manifest(self, tmp_path):
        path = _write_manifest(tmp_path, _valid_manifest_dict())
        manifest = load_ambiguous_positions(str(path))
        assert isinstance(manifest, AmbiguousPositionsManifest)
        assert manifest.k == 3
        assert manifest.positions == frozenset({0, 5, 96})
        assert manifest.schema_version == AMBIGUOUS_POSITIONS_SCHEMA_VERSION

    def test_loads_at_k_max_boundary(self, tmp_path):
        positions = list(range(STAGE_B_K_MAX_DEFAULT))
        path = _write_manifest(tmp_path, _valid_manifest_dict(positions=positions))
        manifest = load_ambiguous_positions(str(path))
        assert manifest.k == STAGE_B_K_MAX_DEFAULT

    def test_load_with_allow_large_above_default_k_max(self, tmp_path):
        positions = list(range(STAGE_B_K_MAX_DEFAULT + 5))
        path = _write_manifest(tmp_path, _valid_manifest_dict(positions=positions))
        manifest = load_ambiguous_positions(str(path), allow_large=True)
        assert manifest.k == STAGE_B_K_MAX_DEFAULT + 5

    def test_position_pairs_are_sorted_and_unique(self, tmp_path):
        positions = (96, 0, 5)  # unsorted on input
        path = _write_manifest(tmp_path, _valid_manifest_dict(positions=positions))
        manifest = load_ambiguous_positions(str(path))
        pairs = list(manifest.position_pairs())
        assert pairs == [(0, 5), (0, 96), (5, 96)]
        # No duplicates
        assert len(pairs) == len(set(pairs))


# ── Schema validation: negative cases ────────────────────────────────────


class TestManifestLoadNegative:
    def test_rejects_missing_schema_version(self, tmp_path):
        payload = _valid_manifest_dict()
        del payload["schema_version"]
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="schema_version"):
            load_ambiguous_positions(str(path))

    def test_rejects_wrong_schema_version(self, tmp_path):
        payload = _valid_manifest_dict()
        payload["schema_version"] = "ct_perturbation_stage_b.ambiguous_positions.v0"
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="schema_version"):
            load_ambiguous_positions(str(path))

    def test_rejects_empty_provenance(self, tmp_path):
        payload = _valid_manifest_dict()
        payload["archive_provenance"] = {}
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="archive_provenance"):
            load_ambiguous_positions(str(path))

    def test_rejects_missing_provenance_field(self, tmp_path):
        payload = _valid_manifest_dict()
        del payload["archive_provenance"]["primary_source"]
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="primary_source"):
            load_ambiguous_positions(str(path))

    def test_rejects_position_out_of_range(self, tmp_path):
        payload = _valid_manifest_dict(positions=(0, 97))
        # checksum recomputed against the bad set so we hit the range error
        payload["checksum"]["sha256_of_positions_sorted"] = _checksum_for((0, 97))
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="out of range"):
            load_ambiguous_positions(str(path))

    def test_rejects_negative_position(self, tmp_path):
        payload = _valid_manifest_dict(positions=(-1, 5, 10))
        payload["checksum"]["sha256_of_positions_sorted"] = _checksum_for((-1, 5, 10))
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="out of range"):
            load_ambiguous_positions(str(path))

    def test_rejects_duplicate_positions(self, tmp_path):
        payload = _valid_manifest_dict(positions=(0, 5, 5, 10))
        payload["checksum"]["sha256_of_positions_sorted"] = _checksum_for(
            (0, 5, 5, 10)
        )
        # Note: because rationale is keyed by str(p), one of the dupes
        # collapses; build an explicit rationale that survives.
        payload["rationale_per_position"] = {
            "0": "x", "5": "y", "10": "z"
        }
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="unique"):
            load_ambiguous_positions(str(path))

    def test_rejects_k_below_2(self, tmp_path):
        payload = _valid_manifest_dict(positions=(5,))
        payload["checksum"]["sha256_of_positions_sorted"] = _checksum_for((5,))
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="at least 2"):
            load_ambiguous_positions(str(path))

    def test_rejects_k_above_default_kmax_without_allow_large(self, tmp_path):
        positions = list(range(STAGE_B_K_MAX_DEFAULT + 1))
        path = _write_manifest(tmp_path, _valid_manifest_dict(positions=positions))
        with pytest.raises(ValueError, match="k_max"):
            load_ambiguous_positions(str(path))

    def test_rejects_checksum_mismatch(self, tmp_path):
        payload = _valid_manifest_dict()
        payload["checksum"]["sha256_of_positions_sorted"] = "0" * 64
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="checksum mismatch"):
            load_ambiguous_positions(str(path))

    def test_rejects_rationale_missing_a_position(self, tmp_path):
        payload = _valid_manifest_dict(positions=(0, 5, 10))
        del payload["rationale_per_position"]["5"]
        path = _write_manifest(tmp_path, payload)
        with pytest.raises(ValueError, match="rationale"):
            load_ambiguous_positions(str(path))


# ── Hamming-2 enumerator correctness ─────────────────────────────────────


class TestEnumerateHamming2:
    @pytest.fixture
    def manifest_k3(self, tmp_path):
        path = _write_manifest(tmp_path, _valid_manifest_dict(positions=(0, 5, 96)))
        return load_ambiguous_positions(str(path))

    def test_count_matches_formula(self, manifest_k3):
        variants = list(
            enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3)
        )
        # k=3, so C(3,2) = 3 position pairs, each with 25*25 = 625 substitutions
        assert len(variants) == 3 * 25 * 25

    def test_all_variants_have_distance_2(self, manifest_k3):
        for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3):
            assert v.distance == 2
            # CT differs from canonical at exactly the two named positions
            diffs = [i for i in range(CT_LEN) if v.ct[i] != CANONICAL_CT[i]]
            assert diffs == [v.pos1, v.pos2]

    def test_pos1_strictly_less_than_pos2(self, manifest_k3):
        for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3):
            assert v.pos1 < v.pos2

    def test_both_positions_in_manifest(self, manifest_k3):
        for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3):
            assert v.pos1 in manifest_k3.positions
            assert v.pos2 in manifest_k3.positions

    def test_new_chars_differ_from_old(self, manifest_k3):
        for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3):
            assert v.old1 != v.new1
            assert v.old2 != v.new2

    def test_old_chars_match_canonical_ct(self, manifest_k3):
        for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3):
            assert v.old1 == CANONICAL_CT[v.pos1]
            assert v.old2 == CANONICAL_CT[v.pos2]

    def test_variant_ids_are_unique(self, manifest_k3):
        ids = [
            v.variant_id
            for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3)
        ]
        assert len(ids) == len(set(ids))

    def test_enumeration_is_deterministic(self, manifest_k3):
        a = [
            v.variant_id
            for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3)
        ]
        b = [
            v.variant_id
            for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3)
        ]
        assert a == b

    def test_ct_sha256_is_unique_per_variant(self, manifest_k3):
        hashes = [
            v.ct_sha256
            for v in enumerate_hamming2_variants_constrained(CANONICAL_CT, manifest_k3)
        ]
        assert len(hashes) == len(set(hashes))

    def test_rejects_invalid_ct(self, manifest_k3):
        with pytest.raises(ValueError):
            list(enumerate_hamming2_variants_constrained("TOO SHORT", manifest_k3))

    def test_rejects_alphabet_with_duplicates(self, manifest_k3):
        with pytest.raises(ValueError, match="duplicates"):
            list(
                enumerate_hamming2_variants_constrained(
                    CANONICAL_CT, manifest_k3, alphabet="AAB"
                )
            )


# ── Universe cardinality ─────────────────────────────────────────────────


class TestStageBUniverseSize:
    @pytest.fixture
    def manifest_k5(self, tmp_path):
        path = _write_manifest(
            tmp_path, _valid_manifest_dict(positions=(10, 20, 30, 40, 50))
        )
        return load_ambiguous_positions(str(path))

    def test_cardinality_for_k5_719_keywords(self, manifest_k5):
        result = stage_b_universe_size(manifest_k5, n_keywords=719)
        assert result["k"] == 5
        assert result["position_pairs"] == 10  # C(5,2)
        assert result["substitution_pairs"] == 625  # 25 * 25
        assert result["h2_variants"] == 6_250
        assert result["configs_per_variant"] == 3 * 2 * 719  # 4,314
        assert result["total_configs"] == 6_250 * 4_314

    def test_cardinality_matches_prereg_table_row_k10(self, tmp_path):
        positions = list(range(10))
        path = _write_manifest(tmp_path, _valid_manifest_dict(positions=positions))
        manifest = load_ambiguous_positions(str(path))
        # Prereg §3.3 row: k=10, 28,125 H2 variants, 121,331,250 total configs
        result = stage_b_universe_size(manifest, n_keywords=719)
        assert result["h2_variants"] == 28_125
        assert result["total_configs"] == 121_331_250


# ── Scope exclusion (mirrors Stage A test class) ─────────────────────────


class TestScopeExclusion:
    def test_supported_families_unchanged_from_stage_a(self):
        # Stage B inherits Stage A's family set verbatim (prereg §2).
        from kryptos.kernel.transforms.vigenere import CipherVariant
        assert SUPPORTED_FAMILIES == (
            CipherVariant.VIGENERE,
            CipherVariant.BEAUFORT,
            CipherVariant.VAR_BEAUFORT,
        )

    def test_supported_alphabets_unchanged_from_stage_a(self):
        assert SUPPORTED_ALPHABET_KINDS == ("AZ", "KA")

    def test_no_running_key_module_imported(self):
        import kryptosbot.ct_perturbation as cp
        text = Path(cp.__file__).read_text()
        # Hard imports of running_key / corpus modules forbidden.
        assert "from kryptos.running_key" not in text
        assert "import kryptos.running_key" not in text
        assert "from kryptos.corpus" not in text
        assert "import kryptos.corpus" not in text

    def test_campaign_id_constant_present(self):
        assert CAMPAIGN_ID_STAGE_B == "ct_perturbation_stage_b"


class TestSweepConfig:
    def test_sweep_config_defaults(self):
        from scripts.campaigns.ct_perturbation_stage_b import SweepConfig
        from kryptosbot.ct_perturbation import SUPPORTED_FAMILIES, SUPPORTED_ALPHABET_KINDS

        cfg = SweepConfig(ct="A" * 97, keywords=["TEST"], manifest=None)
        assert cfg.families == SUPPORTED_FAMILIES
        assert cfg.alphabet_kinds == SUPPORTED_ALPHABET_KINDS
        assert cfg.universe_size == 1
        assert cfg.include_h0 is False
        assert cfg.max_h2_variants is None
        assert cfg.max_configs is None
        assert cfg.keyword_limit is None


class TestSweepResults:
    def test_sweep_results_defaults(self):
        from scripts.campaigns.ct_perturbation_stage_b import SweepResults
        r = SweepResults()
        assert r.candidates_evaluated == 0
        assert r.alerts == []
        assert r.watchlist == []
        assert r.bean_pass_count == 0
        assert r.variants_completed == 0
        assert r.last_completed_variant_id is None
        assert r.errors == []

    def test_variant_eval_result_shape(self):
        from scripts.campaigns.ct_perturbation_stage_b import VariantEvalResult
        v = VariantEvalResult(
            variant_id="H2_test", n_evaluated=4, alerts=[], watchlist=[],
            top_candidates=[], bean_pass_count=0, rejection_reason_counts={},
            trace_rows=[],
        )
        assert v.variant_id == "H2_test"
        assert v.n_evaluated == 4


class TestH2CandidateRow:
    def test_h2_candidate_row_schema(self):
        from scripts.campaigns.ct_perturbation_stage_b import _h2_candidate_row
        from kryptosbot.ct_perturbation import CTVariantH2, CandidateScore, _ct_sha256
        from kryptos.kernel.constants import CT
        from kryptos.kernel.transforms.vigenere import CipherVariant

        new_ct = "A" + CT[1:21] + "Z" + CT[22:]
        v = CTVariantH2(
            variant_id="H2_p00_F->A_p21_F->Z", distance=2,
            pos1=0, old1=CT[0], new1="A", pos2=21, old2=CT[21], new2="Z",
            ct=new_ct, ct_sha256=_ct_sha256(new_ct),
        )
        score = CandidateScore(
            crib_score=18, crib_total=24, bean_passed=True, bean_variant="vigenere",
            ngram_score=-3.4, crib_p_raw=1e-10, ngram_p_raw=1e-3,
            ngram_null_available=True, p_combined_raw=1e-13, p_adjusted=1e-7,
            alert_class="watchlist", rejection_reason="",
        )
        row = _h2_candidate_row(
            run_id="test_run", variant=v, family=CipherVariant.VIGENERE,
            alphabet_kind="AZ", keyword="PALIMPSEST", score=score, pt="X" * 97,
        )
        assert row["run_id"] == "test_run"
        assert row["distance"] == 2
        assert row["pos_pair"] == [0, 21]
        # pos 21 is a crib position; pos 0 is not. crib_overlapping == 1
        assert row["crib_overlapping"] == 1
        assert row["family"] == "vigenere"
        assert row["score"]["crib_score"] == 18
