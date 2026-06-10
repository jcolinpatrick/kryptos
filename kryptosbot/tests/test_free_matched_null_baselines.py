"""G-1: free-matched null baselines — the scoring_mode dimension.

Free-alignment crib scores (``score_candidate_free`` / ``score_free``)
have a completely different null geometry from anchored scores: the free
crib score has support {0, 11, 13, 24} (BERLINCLOCK found anywhere /
EASTNORTHEAST found anywhere / both), so comparing a free score against
an anchored null misstates the chance rate in BOTH directions:

* an anchored empirical null's 1/N floor (2e-5 at 50k samples) would
  SUPPRESS a genuine free 24/24 at the 1e-6 alert gate, and
* the anchored Binomial(24, 1/26) tail misstates the chance of free
  scores by orders of magnitude (different event entirely).

These tests pin the ``scoring_mode`` dimension end to end:

1. ``NullDistribution.scoring_mode`` field + cache_key/back-compat.
2. ``build_null_distribution(scoring_mode="free")`` — sampling and the
   analytic ``free_crib_substring`` tail (uniform-letter model for
   random_text/additive families; CT-permutation model for shuffled_ct
   and transposition families, where free 24 is EXACTLY impossible:
   [DERIVED FACT] CT has 2 E's, the two cribs jointly need 3).
3. Cache round-trip isolation from anchored entries.
4. ``p_value_for_alert(..., scoring_mode="free")`` — never consults an
   anchored cache; explicit free_null_miss degradation.
5. ``classify_outcome`` reads the contract's boundary_scoring_mode.
6. Dispatcher best-candidate annotation routes scoring_mode.
7. Controller halt 1 covers free-mode uncalibrated BREAKTHROUGH.
"""
from __future__ import annotations

import pytest

from kryptosbot import null_baselines as nb
from kryptosbot.null_baselines import (
    NullDistribution,
    build_null_distribution,
    get_cached,
    p_value_for_alert,
    save_to_cache,
)


FREE_SUPPORT = {0.0, 11.0, 13.0, 24.0}

# A 97-char plaintext with both cribs at canonical positions.
PT_BOTH_CRIBS = "X" * 21 + "EASTNORTHEAST" + "X" * 29 + "BERLINCLOCK" + "X" * 23
assert len(PT_BOTH_CRIBS) == 97


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    """Isolate the on-disk cache + manifest from the repo's real ones."""
    monkeypatch.setattr(nb, "_FULL_CACHE_DIR", tmp_path / "full")
    monkeypatch.setattr(nb, "_MANIFEST_PATH", tmp_path / "manifest.json")
    return tmp_path


# ─── 1. scoring_mode field, cache_key, validation ───────────────────────────


class TestScoringModeField:
    def test_default_is_anchored(self):
        d = NullDistribution(
            scorer_name="crib_score", method="random_text", n_chars=97,
            alphabet="AZ", n_samples=10, seed=1, kernel_commit="x",
        )
        assert d.scoring_mode == "anchored"

    def test_legacy_from_dict_defaults_anchored(self):
        # Pre-G-1 cache files carry no scoring_mode key.
        d = NullDistribution.from_dict({
            "scorer_name": "crib_score", "method": "random_text",
            "n_chars": 97, "alphabet": "AZ", "n_samples": 10, "seed": 1,
        })
        assert d.scoring_mode == "anchored"

    def test_anchored_cache_key_unchanged(self):
        d = NullDistribution(
            scorer_name="crib_score", method="random_text", n_chars=97,
            alphabet="AZ", n_samples=10, seed=1, kernel_commit="x",
        )
        assert d.cache_key == "crib_score__random_text__AZ__n97"

    def test_free_cache_key_has_suffix(self):
        d = NullDistribution(
            scorer_name="crib_score", method="random_text", n_chars=97,
            alphabet="AZ", n_samples=10, seed=1, kernel_commit="x",
            scoring_mode="free",
        )
        assert d.cache_key == "crib_score__random_text__AZ__n97__free"

    def test_free_matched_family_cache_key(self):
        d = NullDistribution(
            scorer_name="crib_score", method="matched_variant_family",
            n_chars=97, alphabet="AZ", n_samples=10, seed=1,
            kernel_commit="x", family="vigenere", scoring_mode="free",
        )
        assert d.cache_key == (
            "crib_score__matched_variant_family__AZ__n97__vigenere__free"
        )

    def test_build_rejects_unknown_scoring_mode(self):
        with pytest.raises(ValueError):
            build_null_distribution(
                "crib_score", "random_text", n_samples=5,
                scoring_mode="sideways",
            )

    def test_build_rejects_free_with_non_crib_scorer(self):
        # Free alignment changes the CRIB event geometry only; ngram and
        # composite have no free variant. Reject loudly instead of
        # producing a mislabeled distribution.
        with pytest.raises(ValueError):
            build_null_distribution(
                "ngram_score", "random_text", n_samples=5,
                scoring_mode="free",
            )

    def test_summary_dict_round_trips_scoring_mode(self):
        d = build_null_distribution(
            "crib_score", "random_text", n_samples=20, scoring_mode="free",
        )
        summary = d.to_summary_dict()
        assert summary["scoring_mode"] == "free"
        full = d.to_full_dict()
        d2 = NullDistribution.from_dict(full)
        assert d2.scoring_mode == "free"
        # The parametric tail must survive the round trip.
        assert d2.p_value(24.0) == d.p_value(24.0)


# ─── 2. Free-mode distribution + analytic substring tail ────────────────────


class TestFreeRandomTextNull:
    def test_samples_live_on_free_support(self):
        d = build_null_distribution(
            "crib_score", "random_text", n_samples=300, seed=7,
            scoring_mode="free",
        )
        assert set(d.sorted_scores) <= FREE_SUPPORT

    def test_parametric_model_is_free_substring(self):
        d = build_null_distribution(
            "crib_score", "random_text", n_samples=50, scoring_mode="free",
        )
        assert d.parametric_model == "free_crib_substring"
        assert d.scoring_mode == "free"

    def test_tail_values_match_substring_geometry(self):
        # Uniform letters: P(ENE anywhere) ~ 85 * 26^-13 ~ 3.4e-17;
        # P(BC anywhere) ~ 87 * 26^-11 ~ 2.4e-14; both ~ 8e-31.
        d = build_null_distribution(
            "crib_score", "random_text", n_samples=50, scoring_mode="free",
        )
        assert d.p_value(0.0) == 1.0
        p11 = d.p_value(11.0)
        p13 = d.p_value(13.0)
        p24 = d.p_value(24.0)
        assert 1e-15 < p11 < 1e-12
        assert 1e-18 < p13 < 1e-15
        assert 0.0 < p24 < 1e-25
        # Monotone right tail.
        assert d.p_value(0.0) >= p11 >= p13 >= p24
        # No support between 14 and 23: the tail is flat there.
        assert d.p_value(14.0) == p24

    def test_free_24_passes_alert_gate_where_empirical_floor_would_not(self):
        # The motivating bug: an empirical-only null floors at 1/N
        # (2e-5 at 50k) which FAILS the 1e-6 gate and suppresses a
        # genuine free 24/24 find. The analytic tail must clear it.
        d = build_null_distribution(
            "crib_score", "random_text", n_samples=100, scoring_mode="free",
        )
        assert d.p_value(24.0) <= 1e-6

    def test_anchored_binomial_branch_not_hijacked(self):
        # crib_score+random_text+ANCHORED keeps the exact Binomial tail.
        anchored = build_null_distribution(
            "crib_score", "random_text", n_samples=50,
        )
        assert anchored.scoring_mode == "anchored"
        # Binomial(24, 1/26) right tail at 24 is 26^-24.
        assert anchored.p_value(24.0) == pytest.approx(26.0 ** -24, rel=1e-6)
        # The free tail at 24 is the joint substring probability — a
        # completely different (much larger) number.
        free = build_null_distribution(
            "crib_score", "random_text", n_samples=50, scoring_mode="free",
        )
        assert free.p_value(24.0) > anchored.p_value(24.0)


class TestFreePermutationNull:
    def test_shuffled_ct_free_24_is_exactly_impossible(self):
        # [DERIVED FACT] CT has 2 E's; EASTNORTHEAST+BERLINCLOCK need 3.
        # Any permutation-of-CT source therefore has P(free 24) == 0.
        d = build_null_distribution(
            "crib_score", "shuffled_ct", n_samples=200, seed=3,
            scoring_mode="free",
        )
        assert d.p_value(24.0) == 0.0
        # Single cribs are multiset-feasible: tails must be positive.
        assert d.p_value(13.0) > 0.0
        assert d.p_value(11.0) > 0.0

    def test_transposition_family_free_uses_permutation_model(self):
        d = build_null_distribution(
            "crib_score", "matched_variant_family", n_samples=100, seed=5,
            family="route", scoring_mode="free",
        )
        assert d.p_value(24.0) == 0.0
        assert d.p_value(13.0) > 0.0


class TestFreeMatchedAdditiveNull:
    def test_vigenere_free_builds_and_blends_empirical(self):
        # Additive families decrypt the real CT under random keys. The
        # analytic uniform model is a lower bound; if the empirical run
        # surfaces single-crib hits, the presence estimates must not be
        # smaller than the observed rates.
        d = build_null_distribution(
            "crib_score", "matched_variant_family", n_samples=500, seed=11,
            family="vigenere", scoring_mode="free",
        )
        assert d.scoring_mode == "free"
        assert d.parametric_model == "free_crib_substring"
        n = len(d.sorted_scores)
        emp_ene = sum(1 for s in d.sorted_scores if s in (13.0, 24.0)) / n
        emp_bc = sum(1 for s in d.sorted_scores if s in (11.0, 24.0)) / n
        assert d.p_value(13.0) >= emp_ene
        assert d.p_value(11.0) >= emp_bc


# ─── 3. Cache round-trip isolation ───────────────────────────────────────────


class TestFreeCacheRoundTrip:
    def test_save_and_load_free(self, tmp_cache):
        d = build_null_distribution(
            "crib_score", "random_text", n_samples=30, scoring_mode="free",
        )
        save_to_cache(d)
        loaded = get_cached(
            "crib_score", "random_text", 97, "AZ", scoring_mode="free",
        )
        assert loaded is not None
        assert loaded.scoring_mode == "free"
        assert loaded.p_value(24.0) == d.p_value(24.0)

    def test_free_and_anchored_do_not_collide(self, tmp_cache):
        free = build_null_distribution(
            "crib_score", "random_text", n_samples=30, scoring_mode="free",
        )
        save_to_cache(free)
        # The anchored slot must remain a miss — separate cache file.
        assert get_cached("crib_score", "random_text", 97, "AZ") is None
        anchored = build_null_distribution(
            "crib_score", "random_text", n_samples=30,
        )
        save_to_cache(anchored)
        a = get_cached("crib_score", "random_text", 97, "AZ")
        f = get_cached(
            "crib_score", "random_text", 97, "AZ", scoring_mode="free",
        )
        assert a is not None and a.scoring_mode == "anchored"
        assert f is not None and f.scoring_mode == "free"


# ─── 4. Alert-path p-value lookup ────────────────────────────────────────────


class TestPValueForAlertFreeMode:
    def test_free_matched_family_hit(self, tmp_cache):
        d = build_null_distribution(
            "crib_score", "matched_variant_family", n_samples=50, seed=2,
            family="vigenere", scoring_mode="free",
        )
        save_to_cache(d)
        p, status = p_value_for_alert(
            PT_BOTH_CRIBS, 24, family="vigenere", scoring_mode="free",
        )
        assert status == "ok_free_matched"
        assert p is not None and p <= 1e-6

    def test_free_random_text_hit_without_family(self, tmp_cache):
        d = build_null_distribution(
            "crib_score", "random_text", n_samples=50, scoring_mode="free",
        )
        save_to_cache(d)
        p, status = p_value_for_alert(
            PT_BOTH_CRIBS, 24, family="", scoring_mode="free",
        )
        assert status == "ok_free"
        assert p is not None and p <= 1e-6

    def test_free_matched_miss_falls_back_to_free_random_text(self, tmp_cache):
        d = build_null_distribution(
            "crib_score", "random_text", n_samples=50, scoring_mode="free",
        )
        save_to_cache(d)
        p, status = p_value_for_alert(
            PT_BOTH_CRIBS, 24, family="route", scoring_mode="free",
        )
        assert status == "free_matched_null_miss"
        assert p is not None

    def test_free_mode_never_consults_anchored_cache(self, tmp_cache):
        # Anchored caches present, NO free cache: the lookup must report
        # free_null_miss with p=None — using the anchored null here is
        # exactly the G-1 bug.
        save_to_cache(build_null_distribution(
            "crib_score", "random_text", n_samples=50,
        ))
        save_to_cache(build_null_distribution(
            "crib_score", "matched_variant_family", n_samples=50,
            family="vigenere",
        ))
        p, status = p_value_for_alert(
            PT_BOTH_CRIBS, 24, family="vigenere", scoring_mode="free",
        )
        assert status == "free_null_miss"
        assert p is None

    def test_anchored_default_behavior_unchanged(self, tmp_cache):
        save_to_cache(build_null_distribution(
            "crib_score", "random_text", n_samples=50,
        ))
        p, status = p_value_for_alert("A" * 97, 18)
        assert status == "ok"
        assert p is not None


# ─── 5. classify_outcome reads boundary_scoring_mode ─────────────────────────


def _free_contract(crib: int = 24):
    from kryptosbot.models import WorkerContract, WorkerStatus
    return WorkerContract(
        hypothesis_id="T-FREE-G1",
        status=WorkerStatus.SUCCESS,
        crib_score=crib,
        bean_passed=False,  # Bean is N/A under free alignment
        best_plaintext=PT_BOTH_CRIBS,
        raw_artifacts={
            "boundary_scoring_mode": "free",
            "dsl_pipeline_kinds": ["vigenere"],
        },
    )


class TestClassifyOutcomeFreeMode:
    def test_free_24_alerts_signal_against_free_null(self, tmp_cache):
        from kryptosbot.alerts import AlertLevel, classify_outcome
        save_to_cache(build_null_distribution(
            "crib_score", "matched_variant_family", n_samples=50, seed=2,
            family="vigenere", scoring_mode="free",
        ))
        level, status = classify_outcome(_free_contract(), AlertLevel.SIGNAL)
        assert level == AlertLevel.SIGNAL
        assert status == "ok_free_matched"

    def test_free_24_fails_open_when_uncalibrated(self, tmp_cache):
        # No free null cached: alert still fires (legacy fail-open, the
        # framework never goes silent on a high score) but the status
        # records the missing free calibration.
        from kryptosbot.alerts import AlertLevel, classify_outcome
        level, status = classify_outcome(_free_contract(), AlertLevel.SIGNAL)
        assert level == AlertLevel.SIGNAL
        assert status == "free_null_miss"

    def test_anchored_contract_unaffected(self, tmp_cache):
        from kryptosbot.alerts import AlertLevel, classify_outcome
        from kryptosbot.models import WorkerContract, WorkerStatus
        contract = WorkerContract(
            hypothesis_id="T-ANCH",
            status=WorkerStatus.SUCCESS,
            crib_score=18,
            bean_passed=False,
            best_plaintext="A" * 97,
        )
        level, status = classify_outcome(contract, AlertLevel.SIGNAL)
        assert level == AlertLevel.SIGNAL
        assert status == "cache_miss"


# ─── 6. Dispatcher annotation routes scoring_mode ────────────────────────────


class TestDispatcherAnnotation:
    def _spec(self):
        from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec
        return HypothesisSpec(
            hypothesis_id="H-FREE-G1",
            pipeline=[CipherLayer(kind="vigenere", params={"keyword": "ABC"})],
            crib_alignment="free",
        )

    def test_free_best_candidate_uses_free_null(self, tmp_cache):
        from kryptosbot.job_dispatcher import _annotate_best_candidate_p_values
        save_to_cache(build_null_distribution(
            "crib_score", "matched_variant_family", n_samples=50, seed=2,
            family="vigenere", scoring_mode="free",
        ))
        best = {
            "candidate_pt": PT_BOTH_CRIBS,
            "crib_score": 24,
            "scoring_mode": "free",
        }
        _annotate_best_candidate_p_values(
            best=best, spec=self._spec(), n_tests=1000,
            universe_hash="u" * 16, challenge_mode=False,
        )
        assert best["p_value_status"] == "ok_free_matched"
        assert best["candidate_p_value_vs_null"] <= 1e-6

    def test_free_best_candidate_misses_loudly_without_free_null(self, tmp_cache):
        from kryptosbot.job_dispatcher import _annotate_best_candidate_p_values
        # Anchored cache present — must NOT be consulted.
        save_to_cache(build_null_distribution(
            "crib_score", "matched_variant_family", n_samples=50,
            family="vigenere",
        ))
        best = {
            "candidate_pt": PT_BOTH_CRIBS,
            "crib_score": 24,
            "scoring_mode": "free",
        }
        _annotate_best_candidate_p_values(
            best=best, spec=self._spec(), n_tests=1000,
            universe_hash="u" * 16, challenge_mode=False,
        )
        assert best["p_value_status"] == "free_null_miss"
        assert "candidate_p_value_vs_null" not in best


# ─── 7. Controller halt 1 covers free-mode uncalibrated BREAKTHROUGH ────────


class TestControllerHaltCoversFreeMode:
    def test_breakthrough_with_free_null_miss_halts(self, tmp_path):
        from kryptosbot.controller import ControllerConfig, ResearchController

        config = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
        )
        c = ResearchController(config)

        class _Ev:
            level = "breakthrough"
            p_value_status = "free_null_miss"
            hypothesis_id = "T-FREE-G1"

        reason = c._check_cycle_hardening_halts([], [], [_Ev()])
        assert reason is not None
        assert "free_null_miss" in reason
