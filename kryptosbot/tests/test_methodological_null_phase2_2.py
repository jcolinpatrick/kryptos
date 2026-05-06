"""Tests for Phase 2.2 of the methodological-family conditional null calibration.

Design memo: ``docs/methodological_audits/methodological_null_phase2_2_design.md``.
Calibrator (v2): ``scripts/_infra/calibrate_methodological_null_phase2_2.py``.

The v2 generators run real cipher mechanisms through the canonical
kernel scoring path (replacing the v1 attempt's PT-construction
shortcut, which was rejected by red-team review for not modeling any
mechanism). The tests below verify:

    test_generators_are_deterministic_under_seed
    test_generators_produce_variable_scores         (was: admissibility passes)
    test_generators_run_real_cipher_operations      (was: do_not_solve_k4)
    test_max_ratio_meets_threshold_per_family       (skipped pending data)
    test_phase_2_1_outputs_unchanged                (regression invariant)
    test_per_family_mechanism_metadata_complete
    test_calibrator_quick_run_end_to_end

The Phase 2.1 invariant is critical: Phase 2.2 must NOT mutate any
artifact under ``null_baselines/methodological_null_manifest.json`` or
``results/null_baselines/methodological_null/``. The regression test
checks that Phase 2.1 manifest content is byte-stable across a fresh
Phase 2.2 quick run.
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts" / "_infra"))

import calibrate_methodological_null_phase2_2 as calib  # noqa: E402

from kryptos.kernel.constants import CRIB_DICT, CT  # noqa: E402

CRIB_POSITIONS = frozenset(CRIB_DICT.keys())
NON_CRIB_POSITIONS = frozenset(range(len(CT))) - CRIB_POSITIONS


# Keywords loaded once at module level — generators take a list[str].
_KEYWORDS = calib._load_keywords()


# ─── deterministic-under-seed ─────────────────────────────────────────────


class TestGeneratorsAreDeterministicUnderSeed:

    @pytest.mark.parametrize("family", list(calib._GENERATORS.keys()))
    def test_same_seed_gives_same_first_sample(self, family: str) -> None:
        gen = calib._GENERATORS[family]
        a = gen(random.Random(42), _KEYWORDS)
        b = gen(random.Random(42), _KEYWORDS)
        assert a == b, (
            f"{family} generator must be deterministic under seed; "
            f"got two different samples from random.Random(42)"
        )

    @pytest.mark.parametrize("family", list(calib._GENERATORS.keys()))
    def test_different_seed_gives_different_sample(self, family: str) -> None:
        gen = calib._GENERATORS[family]
        a = gen(random.Random(42), _KEYWORDS)
        b = gen(random.Random(43), _KEYWORDS)
        assert a["params"] != b["params"], (
            f"{family} seeds 42 and 43 produced identical params"
        )


# ─── variable-score-distribution ─────────────────────────────────────────


class TestGeneratorsProduceVariableScores:
    """v2 generators must produce VARIABLE crib_scores. The v1 attempt
    forced every sample to crib_score=24 via PT-construction, which the
    red-team correctly identified as a degenerate non-null. v2 runs real
    cipher mechanisms and produces a distribution.
    """

    @pytest.mark.parametrize("family", list(calib._GENERATORS.keys()))
    def test_score_distribution_has_nonzero_stdev(self, family: str) -> None:
        gen = calib._GENERATORS[family]
        rng = random.Random(42)
        scores = [gen(rng, _KEYWORDS)["crib_score"] for _ in range(100)]
        if len(set(scores)) <= 1:
            pytest.fail(
                f"{family} produced constant crib_score across 100 samples "
                f"(value={scores[0]}). v2 generators must run real cipher "
                f"mechanisms; constant score indicates degenerate null."
            )

    @pytest.mark.parametrize("family", list(calib._GENERATORS.keys()))
    def test_score_max_is_below_24(self, family: str) -> None:
        """Real-cipher samples with random parameters should not
        accidentally hit crib_score=24 in 100 samples. Hitting 24 by
        chance under any of these mechanisms requires probability
        ≈ 26^-24, vastly less than 100 samples can produce."""
        gen = calib._GENERATORS[family]
        rng = random.Random(42)
        scores = [gen(rng, _KEYWORDS)["crib_score"] for _ in range(100)]
        assert max(scores) < 24, (
            f"{family} hit crib_score=24 in a 100-sample run — generator "
            f"likely back-solving from cribs (degenerate null)"
        )

    @pytest.mark.parametrize("family", list(calib._GENERATORS.keys()))
    def test_breakthrough_classification_is_rare(self, family: str) -> None:
        """Random-parameter cipher operations rarely produce
        breakthrough classification. The v1 attempt produced 100%
        breakthrough rate; v2 should be ~0%."""
        gen = calib._GENERATORS[family]
        rng = random.Random(42)
        n = 100
        breakthroughs = sum(
            1 for _ in range(n)
            if gen(rng, _KEYWORDS)["classification"] == "breakthrough"
        )
        rate = breakthroughs / n
        assert rate < 0.05, (
            f"{family} breakthrough_rate={rate:.2f} is suspiciously high; "
            f"random-parameter samples should rarely hit breakthrough"
        )


# ─── real cipher operations (no PT-construction shortcut) ─────────────


class TestGeneratorsRunRealCipherOperations:
    """v2 generators must score plaintext that arises from kernel cipher
    transforms, NOT from a PT-construction trick that places canonical
    cribs at canonical positions. We can detect this by checking that
    the resulting PT does NOT carry the cribs at canonical positions on
    every sample."""

    def _reconstruct_pt_for_family(
        self, family: str, rng: random.Random
    ) -> str:
        """Re-run the family's mechanism with the given rng to recover
        the PT. The generators do not expose PT in their output dict
        (only the score breakdown), so we replicate the relevant bits.
        """
        gen = calib._GENERATORS[family]
        # Snapshot rng state, run generator, restore
        # The PT is not directly returned, but we can verify cribs by
        # checking crib_score directly.
        sample = gen(rng, _KEYWORDS)
        return sample  # not actually a PT, but the sample dict

    @pytest.mark.parametrize("family", list(calib._GENERATORS.keys()))
    def test_most_samples_do_not_match_all_cribs(self, family: str) -> None:
        """A real cipher with random params almost never hits 24/24
        cribs. If even 10% of samples report crib_score=24, the
        generator is back-solving."""
        gen = calib._GENERATORS[family]
        rng = random.Random(42)
        n = 500
        full_crib_matches = sum(
            1 for _ in range(n)
            if gen(rng, _KEYWORDS)["crib_score"] == 24
        )
        rate = full_crib_matches / n
        assert rate < 0.10, (
            f"{family} produced crib_score=24 at rate {rate:.2f} "
            f"({full_crib_matches}/{n}) — generator likely back-solving"
        )


# ─── per-family verdict acceptance (data-conditional) ────────────────────


class TestMaxRatioMeetsThresholdPerFamily:
    """Acceptance criterion: synthetic_max / ledger_max ≥ 0.80 per family.

    Loads the most recent ledger_comparison.json. For v2 mechanism-aware
    sampling, the honest expectation is that the four target families
    will NOT meet 0.80 (the ledger's score-24 BREAKTHROUGHs come from
    flawed-admissibility theorist proposals, not random-parameter
    exploration). Tests here record what the comparison says rather
    than asserting a specific verdict — Phase 2.2's design Option 2
    allows "inconclusive due to invalid synthetic model" as a
    structurally-correct outcome.
    """

    @pytest.fixture
    def comparison(self) -> dict:
        path = (
            _ROOT
            / "results"
            / "null_baselines"
            / "methodological_null_phase2_2"
            / "ledger_comparison.json"
        )
        if not path.exists():
            pytest.skip(
                "Phase 2.2 ledger_comparison.json not present; run "
                "calibrate_methodological_null_phase2_2.py first"
            )
        return json.loads(path.read_text())

    @pytest.mark.parametrize(
        "family", ["k3_continuity", "archive_evidence", "key_tape", "geometry"]
    )
    def test_per_family_verdict_recorded(
        self, comparison: dict, family: str
    ) -> None:
        """Each Phase 2.2 family has a recorded verdict from the
        directive's allowed answer set."""
        per_family = {
            c["family"]: c
            for c in comparison.get("per_family", [])
            if c["null_source"] == "phase_2_2"
        }
        if family not in per_family:
            pytest.skip(f"family {family} absent from latest comparison")
        verdict = per_family[family]["per_family_verdict"]
        assert verdict in {"yes", "no", "inconclusive"}, (
            f"{family} verdict={verdict} not in allowed answer set"
        )

    def test_aggregate_headline_in_allowed_set(
        self, comparison: dict
    ) -> None:
        allowed = {
            "yes",
            "no",
            "inconclusive due to insufficient sampling or invalid synthetic model",
        }
        headline = comparison.get("headline_answer", "")
        assert headline in allowed, (
            f"headline_answer={headline} not in directive's allowed set"
        )

    def test_inconclusive_in_any_family_implies_inconclusive_headline(
        self, comparison: dict
    ) -> None:
        """v3 aggregation rule: any 'inconclusive' family → headline
        'inconclusive'. Matches Phase 2.1's reasoning that an invalid
        synthetic model in any family blocks a definitive global
        answer."""
        per_family = comparison.get("per_family", [])
        verdicts = [c["per_family_verdict"] for c in per_family]
        if "inconclusive" in verdicts:
            assert comparison["headline_answer"].startswith("inconclusive"), (
                f"per-family has inconclusive but headline is "
                f"{comparison['headline_answer']}"
            )

    def test_bernoulli_fields_present(self, comparison: dict) -> None:
        """v3 schema includes Bernoulli rate-test fields per family."""
        for c in comparison.get("per_family", []):
            assert "n_ledger_score_24" in c
            assert "n_null_score_24" in c
            assert "bernoulli_p_value_one_sided" in c
            assert "bernoulli_significant_at_bonf6" in c
            assert "bernoulli_null_rate_upper_95ci" in c

    def test_random_text_baseline_comparison_present(
        self, comparison: dict
    ) -> None:
        """v3 schema includes per-family cross-comparison vs the
        random_text__AZ__n97 baseline."""
        assert "random_text_baseline_anchor" in comparison
        for c in comparison.get("per_family", []):
            assert "vs_random_text_baseline" in c
            rt = c["vs_random_text_baseline"]
            assert "mean_diff" in rt
            assert "stdev_diff" in rt
            assert "max_diff" in rt
            assert "indistinguishable" in rt


# ─── Phase 2.1 outputs unchanged ─────────────────────────────────────────


class TestPhase21OutputsUnchanged:
    """Phase 2.2 must not mutate any Phase 2.1 artifact."""

    def _file_hash(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_phase_2_2_does_not_mutate_phase_2_1_manifest(
        self, tmp_path: Path
    ) -> None:
        manifest = (
            _ROOT / "null_baselines" / "methodological_null_manifest.json"
        )
        if not manifest.exists():
            pytest.skip("Phase 2.1 manifest not present in this checkout")
        before = self._file_hash(manifest)

        argv = [
            "--quick",
            "--ledger-comparison",
            "--output-root",
            str(tmp_path / "out"),
            "--manifest-path",
            str(tmp_path / "out_manifest.json"),
        ]
        rc = calib.main(argv)
        assert rc == 0, f"calibrator exited with {rc}"

        after = self._file_hash(manifest)
        assert before == after, (
            "Phase 2.2 mutated Phase 2.1 manifest — "
            "reproducibility invariant broken"
        )

    def test_phase_2_2_outputs_to_separate_paths(self) -> None:
        assert calib.DEFAULT_OUTPUT_ROOT != calib.PHASE_2_1_OUTPUT_ROOT
        assert calib.DEFAULT_MANIFEST != calib.PHASE_2_1_MANIFEST


# ─── per-family metadata completeness ────────────────────────────────────


class TestPerFamilyMechanismMetadataComplete:
    """Each generator records the mechanism keyword and family-specific
    parameter dict appropriate to v2's real-cipher implementation."""

    EXPECTED_MECHANISM = {
        "k3_continuity": "k3_grid_extension_with_reflow",
        "archive_evidence": "non_crib_hamming_perturbation_plus_real_cipher",
        "key_tape": "primer_extension_finite_tape",
        "geometry": "grid_route_with_post_hoc_search",
    }

    EXPECTED_PARAM_KEYS = {
        "k3_continuity": {
            "width", "rows", "reflow",
            "outer_keyword", "inner_keyword", "variant",
        },
        "archive_evidence": {
            "edit_count", "edit_positions", "edit_values",
            "archive_term", "inner_keyword", "variant", "alphabet",
        },
        "key_tape": {
            "primer", "primer_length", "null_rule", "variant", "alphabet",
        },
        "geometry": {
            "grid_width", "rows", "grid_route", "column_order",
            "search_cap", "post_hoc", "inner_keyword", "variant",
        },
    }

    @pytest.mark.parametrize("family", list(EXPECTED_MECHANISM.keys()))
    def test_mechanism_field_matches_v2_design(self, family: str) -> None:
        gen = calib._GENERATORS[family]
        sample = gen(random.Random(42), _KEYWORDS)
        assert sample["mechanism"] == self.EXPECTED_MECHANISM[family]

    @pytest.mark.parametrize("family", list(EXPECTED_PARAM_KEYS.keys()))
    def test_param_keys_match_v2_design(self, family: str) -> None:
        gen = calib._GENERATORS[family]
        sample = gen(random.Random(42), _KEYWORDS)
        assert set(sample["params"].keys()) == self.EXPECTED_PARAM_KEYS[family]

    def test_archive_evidence_edits_at_non_crib_positions(self) -> None:
        """Critical non-circularity check: archive_evidence edit_positions
        must lie OUTSIDE the canonical crib regions (per the design
        memo's bean-invariance argument)."""
        gen = calib.gen_archive_evidence_phase2_2
        rng = random.Random(42)
        for _ in range(50):
            sample = gen(rng, _KEYWORDS)
            for pos in sample["params"]["edit_positions"]:
                assert pos in NON_CRIB_POSITIONS, (
                    f"archive_evidence edited crib position {pos} — "
                    f"violates bean-invariance design"
                )

    def test_key_tape_does_not_back_solve_from_canonical_pt(self) -> None:
        """Critical non-circularity check: key_tape's tape must come
        from the primer alone, not from canonical-PT back-solving."""
        gen = calib.gen_key_tape_phase2_2
        rng = random.Random(42)
        sample = gen(rng, _KEYWORDS)
        # The primer + length + null_rule + variant + alphabet must
        # fully determine the tape (no canonical-PT input). We can
        # verify this indirectly by re-running with the SAME primer
        # but different rng and checking the score arises from
        # cipher operations rather than crib-placement.
        # Direct check: sample should not always produce crib_score=24.
        scores = [
            gen(random.Random(s), _KEYWORDS)["crib_score"]
            for s in range(50)
        ]
        assert max(scores) < 24, (
            "key_tape sample hit crib_score=24 — likely back-solving"
        )


# ─── end-to-end smoke ────────────────────────────────────────────────────


class TestCalibratorQuickRunEndToEnd:
    """Full calibrator round-trip with --quick."""

    def test_quick_run_produces_all_artifacts(self, tmp_path: Path) -> None:
        out_root = tmp_path / "out"
        manifest_path = tmp_path / "out_manifest.json"
        argv = [
            "--quick",
            "--ledger-comparison",
            "--output-root",
            str(out_root),
            "--manifest-path",
            str(manifest_path),
        ]
        rc = calib.main(argv)
        assert rc == 0

        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert (
            manifest["schema_version"]
            == "methodological_null_phase2_2.manifest.v1"
        )
        assert manifest["script_version"] == calib.SCRIPT_VERSION
        family_names = {f["family"] for f in manifest["families"]}
        assert family_names == {
            "k3_continuity", "archive_evidence", "key_tape", "geometry",
        }

        # v2 produces non-zero stdev in every family.
        for fam in manifest["families"]:
            assert fam["stdev"] > 0.0, (
                f"family {fam['family']} stdev={fam['stdev']} — "
                f"degenerate null detected"
            )

        for family in family_names:
            jsonl = out_root / f"{family}__v1.jsonl"
            assert jsonl.exists(), f"missing {jsonl}"
            lines = jsonl.read_text().strip().splitlines()
            assert len(lines) >= 3

        comparison_path = out_root / "ledger_comparison.json"
        assert comparison_path.exists()
        comparison = json.loads(comparison_path.read_text())
        assert "headline_answer" in comparison
        assert "per_family" in comparison
        assert (
            comparison["schema_version"]
            == "methodological_null_phase2_2.ledger_comparison.v3"
        )

    def test_geometry_search_cap_is_pinned(self) -> None:
        """The geometry post-hoc-search depth is a calibration parameter
        that affects the upper-tail inflation. A future change that
        silently raises the cap would shift the null distribution
        without changing tests; this test pins the value."""
        assert calib._GEOM_POSTHOC_SEARCH_CAP == 50, (
            "geometry post-hoc search cap drift detected — review "
            "calibration design before changing"
        )

    def test_bernoulli_p_value_helper(self) -> None:
        """The Bernoulli p-value helper handles the basic edge cases."""
        # k=0 always returns 1.0
        assert calib._binomial_p_value_at_least_k(100, 0, 0.01) == 1.0
        # p=0 with k>0 returns 0.0
        assert calib._binomial_p_value_at_least_k(100, 1, 0.0) == 0.0
        # p=1 always returns 1.0
        assert calib._binomial_p_value_at_least_k(100, 1, 1.0) == 1.0
        # Sanity: P(X >= 1 | n=100, p=0.01) ≈ 0.634
        p = calib._binomial_p_value_at_least_k(100, 1, 0.01)
        assert 0.5 < p < 0.7, f"got {p}, expected ~0.634"

    def test_only_family_filter_works(self, tmp_path: Path) -> None:
        argv = [
            "--quick",
            "--only-family",
            "key_tape",
            "--output-root",
            str(tmp_path / "out"),
            "--manifest-path",
            str(tmp_path / "out_manifest.json"),
        ]
        rc = calib.main(argv)
        assert rc == 0
        manifest = json.loads((tmp_path / "out_manifest.json").read_text())
        assert len(manifest["families"]) == 1
        assert manifest["families"][0]["family"] == "key_tape"
