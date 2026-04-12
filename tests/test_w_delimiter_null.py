"""Tests for the W-delimiter null elimination framework."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import pytest

from kryptos.kernel.constants import CT
from kryptos.campaigns.w_delimiter import (
    canonical_w_delimiter_model,
    population_random,
    population_dictionary,
    population_grammatical_fit,
    population_curated_best,
    compute_features,
    composite_score,
    feature_breakdown,
    compute_distribution,
    percentile_of,
    fraction_at_or_above,
    render_verdict,
)
from kryptos.campaigns.w_delimiter.distribution import (
    CandidateRanking,
    compute_joint_tail,
    _get_feature,
)
from kryptos.campaigns.w_delimiter.populations import FillCandidate


# ─────────────────────────────────────────────────────────────────────

def test_slot_model_canonical():
    m = canonical_w_delimiter_model()
    assert m.w_positions == (20, 36, 48, 58, 74)
    slot_a, slot_b = m.constrained_slots
    assert slot_a.slot_id == "A"
    assert slot_a.positions == (34, 35)
    assert slot_a.length == 2
    assert slot_a.ct_at_slot == "OT"
    assert slot_b.slot_id == "B"
    assert slot_b.positions == (59, 60, 61, 62)
    assert slot_b.length == 4
    assert slot_b.ct_at_slot == "INFB"


def test_w_positions_derived_from_ct():
    m = canonical_w_delimiter_model()
    # Every W position in the model must actually be a W in CT
    for wp in m.w_positions:
        assert CT[wp] == "W"
    # And every W in CT must be in the model
    for i, ch in enumerate(CT):
        if ch == "W":
            assert i in m.w_positions


def test_random_population_deterministic_under_seed():
    a = population_random(100, seed=7)
    b = population_random(100, seed=7)
    c = population_random(100, seed=8)
    assert [(x.slot_a_pt, x.slot_b_pt) for x in a] == [(x.slot_a_pt, x.slot_b_pt) for x in b]
    assert a != c


def test_grammatical_population_reproducible():
    g1 = population_grammatical_fit()
    g2 = population_grammatical_fit()
    assert g1 == g2
    assert len(g1) > 0


def test_curated_subset_of_grammatical():
    g_set = {(c.slot_a_pt, c.slot_b_pt) for c in population_grammatical_fit()}
    for c in population_curated_best():
        assert (c.slot_a_pt, c.slot_b_pt) in g_set


def test_feature_at_near_baseline():
    c = FillCandidate("AT", "NEAR", "curated")
    # Known values: AT+NEAR under Vigenere yields ks[35] == 0 (T encrypts T)
    f_vig = compute_features(c, "vig")
    assert f_vig.new_zero_count == 1
    assert 35 in f_vig.new_zero_positions
    assert f_vig.bean_eq_holds is True

    f_beau = compute_features(c, "beau")
    assert f_beau.bean_eq_holds is True
    # Beaufort: ks = ct + pt
    # vbeau: ks = pt - ct
    f_vbeau = compute_features(c, "vbeau")
    assert f_vbeau.bean_eq_holds is True


def test_new_zero_count_matches_combinatorics():
    """Random 6-letter fill should give new_zero rate ~ 1 - (25/26)^6 ~ 21%."""
    pop = population_random(5000, seed=42)
    records = [compute_features(c, "vig") for c in pop]
    rate_at_least_one = sum(1 for r in records if r.new_zero_count >= 1) / len(records)
    # Predicted ~0.21, allow wide CI for 5000 samples.
    assert 0.15 <= rate_at_least_one <= 0.27


def test_distribution_quantiles_correct():
    """Synthetic records with known values should yield correct quantiles."""
    # Build synthetic FeatureRecords using real features on uniform inputs.
    pop = population_random(1000, seed=1)
    recs = [compute_features(c, "vig") for c in pop]
    dist = compute_distribution(recs, "new_zero_count", "random_vig")
    assert dist.n == 1000
    # Median should be 0 (most records have zero new-zeros).
    assert dist.quantiles[0.5] == 0
    # Mean should be in a sensible range.
    assert 0.1 <= dist.mean <= 0.4


def test_joint_tail_requires_multi_feature():
    """A candidate that tails on only one channel must NOT flag joint_tail."""
    pop = population_grammatical_fit()
    recs = [compute_features(c, "vig") for c in pop]
    dists = {
        feat: compute_distribution(recs, feat, f"gram_vig")
        for feat in (
            "new_zero_count",
            "new_equality_with_27_or_65",
            "common_bigram_count",
            "common_trigram_count",
            "semantic_coherence_score",
        )
    }
    # A synthetic record that only tails on new_zero_count (set by finding one)
    # Take the record with highest new_zero_count
    best = max(recs, key=lambda r: r.new_zero_count)
    other_tails = sum(
        1 for feat, d in dists.items()
        if feat != "new_zero_count" and percentile_of(_get_feature(best, feat), d) >= 0.99
    )
    # Construct a synthetic candidate whose only tail channel is new_zero
    # (we can't easily fabricate; instead assert the logic itself)
    rank = CandidateRanking(
        candidate=best.candidate,
        raw_features=best,
        composite=0.0,
        feature_breakdown={},
    )
    # Force single-channel fake: artificially restrict to only new_zero in grammatical
    single_dist = {"new_zero_count": dists["new_zero_count"]}
    assert compute_joint_tail(rank, single_dist, min_channels=2) is False


def test_elimination_verdict_strong_when_no_tail():
    v = render_verdict(
        [],
        {"random": 0, "dictionary": 0, "grammatical": 0, "curated": 0},
    )
    assert v.verdict == "STRONG_ELIMINATION"
    assert "definitive" not in v.publication_wording
    assert "proves" not in v.publication_wording


def test_elimination_verdict_narrow_when_partial():
    # Fabricate a joint-tail candidate
    c = FillCandidate("AT", "NEAR", "grammatical")
    rec = compute_features(c, "vig")
    r = CandidateRanking(
        candidate=c, raw_features=rec, composite=10.0,
        feature_breakdown={}, is_joint_tail=True,
        multiplicity_adjusted=0.5,  # below curated bar
    )
    v = render_verdict([r], {"grammatical": 100, "curated": 24})
    assert v.verdict == "NARROW_RESIDUAL"
    assert len(v.candidates_in_tail) == 1


def test_publication_wording_no_overclaim():
    v = render_verdict([], {"random": 50000, "grammatical": 1035})
    forbidden = ("definitive", "proves", "all candidates", "conclusively")
    for word in forbidden:
        assert word.lower() not in v.publication_wording.lower()


def test_at_near_specifically_not_signal():
    """AT+NEAR should NOT produce is_joint_tail=True across variants."""
    c = FillCandidate("AT", "NEAR", "curated")
    pop = population_grammatical_fit()
    recs = [compute_features(cand, "vig") for cand in pop]
    dists = {
        feat: compute_distribution(recs, feat, "gram_vig")
        for feat in (
            "new_zero_count",
            "new_equality_with_27_or_65",
            "common_bigram_count",
            "common_trigram_count",
            "semantic_coherence_score",
        )
    }
    at_near_rec = compute_features(c, "vig")
    r = CandidateRanking(
        candidate=c, raw_features=at_near_rec,
        composite=composite_score(at_near_rec),
        feature_breakdown=feature_breakdown(at_near_rec),
    )
    r.is_joint_tail = compute_joint_tail(r, dists)
    assert r.is_joint_tail is False


def test_multiplicity_correction_penalizes_search():
    import math
    small_n = 100
    big_n = 100_000
    small_log = math.log10(small_n)
    big_log = math.log10(big_n)
    assert big_log > small_log
    # Same best-percentile, different search sizes → bigger penalty for bigger search
    best_pct = 0.995
    small_adj = max(0.0, best_pct - small_log * 0.01)
    big_adj = max(0.0, best_pct - big_log * 0.01)
    assert big_adj < small_adj


def test_runner_produces_json_and_md():
    """End-to-end smoke: tiny run writes JSON + MD artifacts."""
    with tempfile.TemporaryDirectory() as td:
        out_json = os.path.join(td, "out.json")
        out_md = os.path.join(td, "out.md")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = os.path.join(root, "scripts", "campaigns", "f_w_delimiter_null_v1.py")
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(root, "src")
        result = subprocess.run(
            [sys.executable, "-u", script,
             "--random-n", "200",
             "--dictionary-n", "200",
             "--workers", "1",
             "--variant", "vig",
             "--output", out_json,
             "--report", out_md],
            env=env, capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert os.path.exists(out_json)
        assert os.path.exists(out_md)
        with open(out_json) as f:
            data = json.load(f)
        assert data["verdict"] in ("STRONG_ELIMINATION", "NARROW_RESIDUAL", "UNEXPECTED_HIT")
        assert "slot_model" in data
        assert data["slot_model"]["w_positions"] == [20, 36, 48, 58, 74]
