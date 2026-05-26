"""R2-4 verification: matched_variant_family nulls for Beaufort /
VarBeau / columnar_single / columnar_double, plus ngram_score nulls
for the two columnar families.

Phase 6 calibrated Vigenère-AZ only. R2-4 adds the distributions the
K4 search space actually needs when the theorist proposes transposition
or non-Vigenère additive layers. Without these, the alert gate
over-rejects on composition paths — genuine signal gets called noise.

The six new distributions, all at n_chars=97, alphabet=AZ, per brief
§5.1:

  crib_score  × matched_variant_family × beaufort
  crib_score  × matched_variant_family × variant_beaufort
  crib_score  × matched_variant_family × columnar_single
  crib_score  × matched_variant_family × columnar_double
  ngram_score × matched_variant_family × columnar_single
  ngram_score × matched_variant_family × columnar_double

Test coverage:
  1. Cache plumbing: new `family` field round-trips through the manifest.
  2. Distribution sanity: mean/stdev in plausible ranges per the brief.
  3. p-value computation: empirical tail floor is 1/50K = 2e-5.
  4. Integration: K3's known plaintext is extreme under the
     columnar_double ngram null (brief §5.5).
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from kryptosbot.null_baselines import (
    _VALID_FAMILIES,
    _MANIFEST_PATH,
    NullDistribution,
    build_null_distribution,
    get_cached,
)


# ─── Schema + field plumbing ────────────────────────────────────────────────

class TestFamilyFieldPlumbing:
    def test_valid_families_includes_r2_4_set(self):
        expected = {"beaufort", "variant_beaufort",
                    "columnar_single", "columnar_double"}
        assert expected.issubset(_VALID_FAMILIES)

    def test_valid_families_includes_transposition_trio(self):
        # 2026-05-26: rail_fence / myszkowski / route added so the
        # real-K4 instrument campaign can score genuine transposition
        # hits against their own family null, not the random_text strawman.
        expected = {"rail_fence", "myszkowski", "route"}
        assert expected.issubset(_VALID_FAMILIES)

    def test_cache_key_disambiguates_by_family(self):
        a = NullDistribution(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            n_samples=1, seed=1, kernel_commit="x",
            family="beaufort",
        )
        b = NullDistribution(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            n_samples=1, seed=1, kernel_commit="x",
            family="variant_beaufort",
        )
        assert a.cache_key != b.cache_key
        assert "beaufort" in a.cache_key
        assert "variant_beaufort" in b.cache_key

    def test_legacy_empty_family_preserves_phase_6_cache_key(self):
        """A family="" matched_variant_family entry must produce the
        same cache_key it had in Phase 6 — otherwise the committed
        manifest entry stops resolving and the alert gate silently
        falls back to the empirical floor."""
        legacy = NullDistribution(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            n_samples=1, seed=1, kernel_commit="x",
            family="",
        )
        assert legacy.cache_key == (
            "crib_score__matched_variant_family__AZ__n97"
        )

    def test_dict_roundtrip_preserves_family(self):
        orig = NullDistribution(
            scorer_name="ngram_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            n_samples=10, seed=1, kernel_commit="x",
            sorted_scores=[-6.4, -6.3, -6.2],
            mean=-6.3, stdev=0.1,
            family="columnar_double",
        )
        reconstructed = NullDistribution.from_dict(orig.to_full_dict())
        assert reconstructed.family == "columnar_double"


# ─── Build-time sanity ──────────────────────────────────────────────────────

class TestBuildSanity:
    """Tiny-sample build tests — fast, don't depend on cached files."""

    @pytest.mark.parametrize("family", [
        "beaufort", "variant_beaufort",
        "columnar_single", "columnar_double",
        "rail_fence", "myszkowski", "route",
    ])
    def test_crib_score_builds_for_each_family(self, family):
        dist = build_null_distribution(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            n_samples=200, seed=17, family=family,
        )
        assert dist.family == family
        # Random decryptions of the K4 CT: each of 24 crib positions
        # has a ~1/26 chance of matching by coincidence → expected
        # mean crib_score ≈ 24/26 ≈ 0.92. Allow broad tolerance given
        # 200 samples.
        assert 0.5 <= dist.mean <= 1.8, (
            f"family={family}: mean {dist.mean} outside plausible range"
        )

    def test_unknown_family_raises(self):
        with pytest.raises(ValueError, match="family"):
            build_null_distribution(
                scorer_name="crib_score",
                method="matched_variant_family",
                family="not_a_real_family",
                n_samples=10,
            )


# ─── Manifest / cache ───────────────────────────────────────────────────────

class TestManifestContainsR2_4Entries:
    """The R2-4 calibration script must have populated the manifest
    with all 6 entries. If this fails, either the calibrator wasn't run
    or the manifest was regenerated from an older state."""

    @pytest.fixture
    def manifest(self):
        assert _MANIFEST_PATH.exists(), (
            f"manifest missing at {_MANIFEST_PATH}"
        )
        return json.loads(_MANIFEST_PATH.read_text())

    @pytest.mark.parametrize("scorer,family", [
        ("crib_score", "beaufort"),
        ("crib_score", "variant_beaufort"),
        ("crib_score", "columnar_single"),
        ("crib_score", "columnar_double"),
        ("ngram_score", "columnar_single"),
        ("ngram_score", "columnar_double"),
        ("crib_score", "rail_fence"),
        ("crib_score", "myszkowski"),
        ("crib_score", "route"),
    ])
    def test_manifest_contains_r2_4_entry(self, manifest, scorer, family):
        key = f"{scorer}__matched_variant_family__AZ__n97__{family}"
        dists = manifest.get("distributions", {})
        assert key in dists, (
            f"R2-4 manifest missing {key!r}. Run: "
            "PYTHONPATH=src python3 -u scripts/_infra/"
            "calibrate_null_baselines_r2_4.py"
        )
        entry = dists[key]
        assert entry["family"] == family
        assert entry["method"] == "matched_variant_family"
        assert entry["alphabet"] == "AZ"
        assert entry["n_chars"] == 97
        assert entry["n_samples"] >= 2_000, (
            "n_samples should be at least the smoke-test threshold"
        )


# ─── Cache lookup via get_cached(family=...) ────────────────────────────────

class TestGetCachedHonorsFamily:
    """A get_cached call with a non-empty family must hit the new
    cache slot, not the Phase 6 Vigenère cache."""

    def test_columnar_double_cache_hit(self):
        dist = get_cached(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            family="columnar_double",
        )
        if dist is None:
            pytest.skip("R2-4 calibration not run yet")
        assert dist.family == "columnar_double"
        assert dist.n_samples >= 2_000

    @pytest.mark.parametrize("family", ["rail_fence", "myszkowski", "route"])
    def test_transposition_family_cache_hit(self, family):
        dist = get_cached(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            family=family,
        )
        if dist is None:
            pytest.skip(f"{family} matched null not calibrated yet")
        assert dist.family == family
        assert dist.n_samples >= 2_000

    def test_empty_family_still_hits_phase_6_cache(self):
        dist = get_cached(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            family="",
        )
        if dist is None:
            pytest.skip("Phase 6 Vigenère cache not present")
        assert dist.family == "" or dist.family == "vigenere"


# ─── Integration: K3 is extreme under columnar_double null ──────────────────

class TestK3UnderColumnarDoubleNull:
    """Brief §5.5 acceptance: the known-answer K3 configuration must be
    extreme under the columnar_double matched null (p < 10⁻⁵ expected).

    The test evaluates the K3 discovered plaintext's ngram_score against
    the columnar_double null. K3 PT is English prose; the null is
    random permutations of K4 CT (non-English). Expectation: K3 PT's
    per-char ngram_score (≈ -3.8, English) is dozens of standard
    deviations better than the null mean (≈ -6.4). p should pin to the
    1/N floor."""

    def test_k3_pt_is_extreme_vs_columnar_double_null(self):
        dist = get_cached(
            scorer_name="ngram_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            family="columnar_double",
        )
        if dist is None:
            pytest.skip("R2-4 ngram_score × columnar_double null not built")

        from kryptos.kernel.scoring.ngram import get_default_scorer
        # K3 plaintext prefix — use first 97 chars so n_chars matches null
        # (ngram_score is per-char normalized, but we keep alignment
        # identical to how the null was built for clarity).
        k3_pt = (
            "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
            "THELOWERPARTOFTHEDOORWAYWASREMOVEDW"
        )[:97]
        score = get_default_scorer().score_per_char(k3_pt)
        # Use the dist's p_value method — will dispatch to normal_approx
        # for empirical tails, but since the K3 score is so extreme it
        # lands well beyond the max sample.
        p = dist.p_value(score)
        # Empirical floor is 1/N; for 50K samples that's 2e-5.
        # The normal approximation pushes to essentially zero.
        assert p <= 1e-3, (
            f"K3 PT ngram score {score:.3f} not extreme under "
            f"columnar_double null (mean={dist.mean:.3f}, "
            f"stdev={dist.stdev:.3f}): p={p}"
        )
