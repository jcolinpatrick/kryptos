"""Tests for swing_k1_calibration."""
import pytest


def test_shuffle_preserves_length_and_letter_distribution():
    import random
    from kryptos.kernel.constants import CT
    from kryptosbot.swing_k1_calibration import shuffle_ct
    shuffled = shuffle_ct(rng=random.Random(0))
    assert len(shuffled) == len(CT)
    assert sorted(shuffled) == sorted(CT)


def test_two_calls_with_same_seed_match():
    import random
    from kryptosbot.swing_k1_calibration import shuffle_ct
    a = shuffle_ct(rng=random.Random(123))
    b = shuffle_ct(rng=random.Random(123))
    assert a == b


def test_baseline_returns_distribution():
    from kryptosbot.swing_k1_calibration import run_baseline_calibration
    # Small N for test speed
    dist = run_baseline_calibration(n_trials=50, n_sampled_configs=5, seed=0)
    assert dist.n_trials == 50
    assert len(dist.joint_event_counts) == 50
    assert all(c >= 0 for c in dist.joint_event_counts)


def test_analytical_binomial_p_value():
    from kryptosbot.swing_k1_calibration import analytical_binomial_pvalue
    # n=1000, k=0, p=0.001 -> P(X >= 0) = 1.0 trivially
    p = analytical_binomial_pvalue(n=1000, k=0, single_trial_p=0.001)
    assert p == 1.0
    # n=1000, k=10, p=0.001 -> very tight tail
    p = analytical_binomial_pvalue(n=1000, k=10, single_trial_p=0.001)
    assert p < 1e-3


def test_escalation_chooses_analytical_when_binomial_supported():
    from kryptosbot.swing_k1_calibration import escalate_to_stage_2
    result = escalate_to_stage_2(
        observed_joint_event_count=5,
        baseline_max=0,
        n_baseline_trials=10_000,
        method_preference="analytical",
        single_trial_p_estimate=1e-5,
    )
    assert result.method == "analytical_binomial"
    assert 0.0 <= result.p_value <= 1.0


def test_escalation_falls_back_to_monte_carlo_when_no_binomial_support():
    from kryptosbot.swing_k1_calibration import escalate_to_stage_2
    result = escalate_to_stage_2(
        observed_joint_event_count=5,
        baseline_max=0,
        n_baseline_trials=10_000,
        method_preference="monte_carlo",
        single_trial_p_estimate=None,
    )
    assert result.method == "monte_carlo_1m"
