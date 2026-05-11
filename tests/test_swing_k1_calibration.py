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
