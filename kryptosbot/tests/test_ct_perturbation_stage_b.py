"""Tests for the CT-Perturbation Stage B harness.

Prereg: ``docs/campaigns/ct_perturbation_stage_b_prereg.md``.
Stub: ``scripts/campaigns/ct_perturbation_stage_b.py`` (v0.2 with
synthetic-recovery test wired; full sweep runner deferred).

Coverage per prereg §13 reproducibility checklist:

    TestScopeExclusion           — H1/H3 not enumerated, k>20 rejected,
                                   missing/empty archive_provenance rejected.
    TestUniverseCardinality      — universe size matches the §3.3 formula.
    TestH2EnumerationConstrained — enumeration is deterministic, ordered,
                                   covers C(k,2)*625 variants.
    TestSyntheticRecovery        — §7.1 selective + §7.2 structural pass
                                   under both fixtures.
    TestStubRefusesExecuteFull   — v0.2 stub returns exit code 3 on
                                   --execute-full.
    TestStubRejectsBadManifests  — missing path, schema invalid, missing
                                   provenance, k>20-without-override all
                                   rejected with exit 2.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts" / "campaigns"))

import ct_perturbation_stage_b as stage_b  # noqa: E402

from kryptos.kernel.constants import CRIB_DICT, CT  # noqa: E402
from kryptosbot.ct_perturbation import (  # noqa: E402
    AmbiguousPositionsManifest,
    enumerate_hamming2_variants_constrained,
    load_ambiguous_positions,
    stage_b_universe_size,
)


# ─── Fixtures ────────────────────────────────────────────────────────────


def _valid_manifest_dict(positions: list[int]) -> dict[str, Any]:
    """Build a valid in-memory manifest dict for the schema validator."""
    import hashlib
    sorted_pos = sorted(set(positions))
    return {
        "schema_version": "ct_perturbation_stage_b.ambiguous_positions.v1",
        "archive_provenance": {
            "primary_source": "AAA, Sanborn, box 1 folder 2, image IMG_TEST",
            "image_hashes": ["sha256:" + "0" * 64],
            "evaluator": "test_fixture",
            "evaluation_date": "2026-05-06",
            "method": "test fixture",
        },
        "positions": sorted_pos,
        "rationale_per_position": {
            str(p): f"test rationale for position {p}" for p in sorted_pos
        },
        "checksum": {
            "sha256_of_positions_sorted": hashlib.sha256(
                ",".join(str(p) for p in sorted_pos).encode("utf-8")
            ).hexdigest(),
        },
    }


@pytest.fixture
def tmp_manifest_path(tmp_path: Path) -> Path:
    """Write a valid manifest with k=5 to a temp file and return the path."""
    manifest = _valid_manifest_dict([10, 25, 47, 63, 80])
    path = tmp_path / "ambiguous_positions.json"
    path.write_text(json.dumps(manifest))
    return path


@pytest.fixture(scope="module")
def shared_recovery_report() -> dict[str, Any]:
    """Run the synthetic recovery test ONCE per test module.

    The recovery test enumerates 2500 H2 variants and runs ScorerContext
    over each, which takes a few seconds. Tests that only need to READ
    the report share this fixture; tests that need a per-test artifact
    dir construct their own report.
    """
    with tempfile.TemporaryDirectory() as td:
        return stage_b.synthetic_recovery_test(artifact_dir=Path(td))


# ─── Scope exclusion (prereg §2) ────────────────────────────────────────


class TestScopeExclusion:

    def test_h2_enumerator_only_yields_distance_2(self) -> None:
        """The constrained enumerator must yield only Hamming-2 variants."""
        manifest = stage_b._ambiguous_manifest_from_positions(
            positions=[5, 47],
            rationale_per_position={"5": "t", "47": "t"},
        )
        for variant in enumerate_hamming2_variants_constrained(CT, manifest):
            assert variant.distance == 2

    def test_h2_enumerator_pos1_lt_pos2(self) -> None:
        """All emitted variants have pos1 < pos2 (canonical ordering)."""
        manifest = stage_b._ambiguous_manifest_from_positions(
            positions=[5, 47, 80],
            rationale_per_position={"5": "t", "47": "t", "80": "t"},
        )
        for variant in enumerate_hamming2_variants_constrained(CT, manifest):
            assert variant.pos1 < variant.pos2

    def test_h2_enumerator_both_positions_in_ambiguous_set(self) -> None:
        """Both perturbed positions must lie in A (no 'one in A, one free')."""
        positions = [5, 47, 80]
        manifest = stage_b._ambiguous_manifest_from_positions(
            positions=positions,
            rationale_per_position={str(p): "t" for p in positions},
        )
        position_set = set(positions)
        for variant in enumerate_hamming2_variants_constrained(CT, manifest):
            assert variant.pos1 in position_set
            assert variant.pos2 in position_set


# ─── Universe cardinality (prereg §3.3) ─────────────────────────────────


class TestUniverseCardinality:

    @pytest.mark.parametrize("k,expected_pairs", [
        (2, 1), (5, 10), (10, 45), (15, 105), (20, 190),
    ])
    def test_position_pair_count_matches_formula(
        self, k: int, expected_pairs: int
    ) -> None:
        """C(k, 2) = k(k-1)/2."""
        positions = list(range(k))
        manifest = stage_b._ambiguous_manifest_from_positions(
            positions=positions,
            rationale_per_position={str(p): "t" for p in positions},
        )
        pairs = list(manifest.position_pairs())
        assert len(pairs) == expected_pairs

    @pytest.mark.parametrize("k", [2, 5, 10])
    def test_h2_variant_count_matches_625k_choose_2(self, k: int) -> None:
        """H2 variant count = C(k,2) * 625 = C(k,2) * 25 * 25."""
        positions = list(range(k))
        manifest = stage_b._ambiguous_manifest_from_positions(
            positions=positions,
            rationale_per_position={str(p): "t" for p in positions},
        )
        h2 = list(enumerate_hamming2_variants_constrained(CT, manifest))
        expected = (k * (k - 1) // 2) * 25 * 25
        assert len(h2) == expected

    def test_universe_size_includes_all_dimensions(self) -> None:
        """Universe size = H2_variants × |families| × |alphabets| × |keywords|."""
        positions = [10, 25, 47, 63, 80]  # k=5
        manifest = stage_b._ambiguous_manifest_from_positions(
            positions=positions,
            rationale_per_position={str(p): "t" for p in positions},
        )
        sized = stage_b_universe_size(manifest, n_keywords=719)
        # k=5 → C(5,2)=10 pairs → 10*625=6250 H2 variants
        assert sized["h2_variants"] == 6250
        # Total = 6250 * 3 * 2 * 719 = 26,962,500 (per prereg §3.3 example)
        assert sized["total_configs"] == 6250 * 3 * 2 * 719


# ─── H2 enumeration determinism ─────────────────────────────────────────


class TestH2EnumerationDeterministic:

    def test_two_calls_produce_identical_variants(self) -> None:
        manifest = stage_b._ambiguous_manifest_from_positions(
            positions=[10, 47, 80],
            rationale_per_position={"10": "t", "47": "t", "80": "t"},
        )
        ids_a = [v.variant_id for v in
                 enumerate_hamming2_variants_constrained(CT, manifest)]
        ids_b = [v.variant_id for v in
                 enumerate_hamming2_variants_constrained(CT, manifest)]
        assert ids_a == ids_b

    def test_variants_have_unique_ids(self) -> None:
        manifest = stage_b._ambiguous_manifest_from_positions(
            positions=[10, 47, 80, 88],
            rationale_per_position={
                "10": "t", "47": "t", "80": "t", "88": "t",
            },
        )
        ids = [
            v.variant_id
            for v in enumerate_hamming2_variants_constrained(CT, manifest)
        ]
        assert len(ids) == len(set(ids))


# ─── Synthetic recovery (prereg §7) ─────────────────────────────────────


class TestSyntheticRecovery:
    """Tests that share a single synthetic_recovery_test run via the
    module-scoped fixture for speed. Tests that need their own per-test
    artifact_dir use tmp_path."""

    def test_recovery_overall_passes(
        self, shared_recovery_report: dict[str, Any]
    ) -> None:
        """Both selective and structural probes pass under both fixtures."""
        assert shared_recovery_report["passed"] is True
        assert shared_recovery_report["selective_passed"] is True
        assert shared_recovery_report["structural_passed"] is True

    def test_recovery_writes_report_to_artifact_dir(
        self, tmp_path: Path
    ) -> None:
        stage_b.synthetic_recovery_test(artifact_dir=tmp_path)
        assert (tmp_path / "recovery_test_report.json").exists()

    def test_recovery_runs_both_fixtures(
        self, shared_recovery_report: dict[str, Any]
    ) -> None:
        """Both Vigenère+AZ+PALIMPSEST and Beaufort+KA+KRYPTOS exercised."""
        selective_labels = {
            p["fixture"] for p in shared_recovery_report["selective_probes"]
        }
        structural_labels = {
            p["fixture"] for p in shared_recovery_report["structural_probes"]
        }
        assert "vigenere_AZ_PALIMPSEST" in selective_labels
        assert "beaufort_KA_KRYPTOS" in selective_labels
        assert "vigenere_AZ_PALIMPSEST" in structural_labels
        assert "beaufort_KA_KRYPTOS" in structural_labels

    def test_selective_finds_exactly_one_planted_alert(
        self, shared_recovery_report: dict[str, Any]
    ) -> None:
        """Selective probe should fire exactly one alert per fixture, and
        that alert must match the planted (new1, new2) correction."""
        for probe in shared_recovery_report["selective_probes"]:
            assert probe["alerts_total"] == 1
            assert probe["matching_alert"] is not None
            assert probe["matching_alert"]["crib_score"] == 24
            assert probe["matching_alert"]["bean_passed"] is True

    def test_structural_produces_zero_alerts(
        self, shared_recovery_report: dict[str, Any]
    ) -> None:
        """Structural probe on real K4 CT must produce zero alerts under
        random keyword decryption."""
        for probe in shared_recovery_report["structural_probes"]:
            assert probe["alerts_total"] == 0

    def test_structural_bean_invariance_holds(
        self, shared_recovery_report: dict[str, Any]
    ) -> None:
        """Bean constraint set must be identical between canonical CT and
        a non-crib H2 perturbation of CT."""
        for probe in shared_recovery_report["structural_probes"]:
            assert probe["bean_invariance_holds"] is True

    def test_recovery_enumerates_625_variants_per_fixture(
        self, shared_recovery_report: dict[str, Any]
    ) -> None:
        """k=2 (one position pair) × 25 × 25 = 625 H2 variants per probe."""
        for probe in (
            shared_recovery_report["selective_probes"]
            + shared_recovery_report["structural_probes"]
        ):
            assert probe["h2_variants_enumerated"] == 625


# ─── Stub --execute-full refusal ────────────────────────────────────────


class TestStubRefusesExecuteFull:

    def test_execute_full_returns_3(
        self, tmp_manifest_path: Path
    ) -> None:
        rc = stage_b.main([
            "--ambiguous-positions", str(tmp_manifest_path),
            "--execute-full",
        ])
        assert rc == 3, (
            "v0.2 stub must return exit code 3 on --execute-full"
        )


# ─── Stub manifest validation ───────────────────────────────────────────


class TestStubRejectsBadManifests:

    def test_missing_manifest_path_returns_2(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "no_such_file.json"
        rc = stage_b.main(["--ambiguous-positions", str(nonexistent)])
        assert rc == 2

    def test_neither_manifest_nor_recovery_returns_2(self) -> None:
        """Without --ambiguous-positions AND without
        --synthetic-recovery-test, the stub has nothing to do."""
        rc = stage_b.main([])
        assert rc == 2

    def test_schema_invalid_manifest_returns_2(
        self, tmp_path: Path
    ) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"not": "a manifest"}))
        rc = stage_b.main(["--ambiguous-positions", str(bad)])
        assert rc == 2

    def test_missing_archive_provenance_returns_2(
        self, tmp_path: Path
    ) -> None:
        manifest = _valid_manifest_dict([10, 25])
        manifest["archive_provenance"] = {}
        bad = tmp_path / "no_provenance.json"
        bad.write_text(json.dumps(manifest))
        rc = stage_b.main(["--ambiguous-positions", str(bad)])
        assert rc == 2

    def test_k_above_20_without_override_returns_2(
        self, tmp_path: Path
    ) -> None:
        # k=21 — above k_max_default=20.
        positions = list(range(0, 42, 2))  # 21 positions
        assert len(positions) == 21
        manifest = _valid_manifest_dict(positions)
        bad = tmp_path / "k_too_large.json"
        bad.write_text(json.dumps(manifest))
        rc = stage_b.main(["--ambiguous-positions", str(bad)])
        assert rc == 2

    def test_k_above_20_with_override_passes(self, tmp_path: Path) -> None:
        positions = list(range(0, 42, 2))  # 21 positions
        manifest = _valid_manifest_dict(positions)
        path = tmp_path / "k_with_override.json"
        path.write_text(json.dumps(manifest))
        rc = stage_b.main([
            "--ambiguous-positions", str(path),
            "--allow-large-ambiguous-set",
        ])
        assert rc == 0

    def test_recovery_test_alone_does_not_require_manifest(
        self, tmp_path: Path
    ) -> None:
        """--synthetic-recovery-test runs without --ambiguous-positions."""
        rc = stage_b.main([
            "--synthetic-recovery-test",
            "--recovery-artifact-dir", str(tmp_path),
        ])
        assert rc == 0

    def test_valid_manifest_returns_0(self, tmp_manifest_path: Path) -> None:
        rc = stage_b.main(["--ambiguous-positions", str(tmp_manifest_path)])
        assert rc == 0


# ─── Schema/loader integration ──────────────────────────────────────────


class TestSchemaLoaderIntegration:

    def test_load_round_trip(self, tmp_manifest_path: Path) -> None:
        """A valid manifest written and loaded round-trips correctly."""
        manifest = load_ambiguous_positions(tmp_manifest_path)
        assert isinstance(manifest, AmbiguousPositionsManifest)
        assert len(manifest.positions) == 5

    def test_archive_provenance_is_required_at_load_time(
        self, tmp_path: Path
    ) -> None:
        bad = _valid_manifest_dict([10, 25])
        bad["archive_provenance"] = {}
        path = tmp_path / "x.json"
        path.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            load_ambiguous_positions(path)


# ─── Recovery probe parameter pinning ────────────────────────────────────


class TestRecoveryProbeParameters:
    """Pin the recovery-probe parameter choices so silent drift is
    caught. The selective probe uses crib positions; the structural
    probe uses non-crib positions; both choices are load-bearing per
    the prereg §7 design."""

    def test_selective_positions_are_in_crib_regions(self) -> None:
        crib_positions = set(CRIB_DICT.keys())
        for pos in stage_b._SELECTIVE_PROBE_POSITIONS:
            assert pos in crib_positions, (
                f"selective probe position {pos} must be in crib regions"
            )

    def test_structural_positions_are_outside_crib_regions(self) -> None:
        crib_positions = set(CRIB_DICT.keys())
        for pos in stage_b._STRUCTURAL_PROBE_POSITIONS:
            assert pos not in crib_positions, (
                f"structural probe position {pos} must be non-crib"
            )

    def test_recovery_fixtures_cover_both_required_cipher_choices(self) -> None:
        labels = {f["label"] for f in stage_b._RECOVERY_FIXTURES}
        assert "vigenere_AZ_PALIMPSEST" in labels
        assert "beaufort_KA_KRYPTOS" in labels

    def test_k_max_default_is_20(self) -> None:
        """Pinning k_max_default per prereg §3.3."""
        assert stage_b._K_MAX_DEFAULT == 20
