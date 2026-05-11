"""Tests for swing_k1_universe."""
import pytest


def test_universe_emits_one_config_per_axis_combo():
    from kryptosbot.swing_k1_universe import enumerate_universe
    configs = list(enumerate_universe())
    assert len(configs) > 0
    # Check axis coverage: every model appears, every variant appears.
    models = {c.model_variant for c in configs}
    assert models == {"M1", "M2", "M3", "M4", "M5"}
    variants = {c.variant for c in configs}
    assert variants == {"vigenere", "beaufort", "var_beaufort"}
    alphabets = {c.alphabet for c in configs}
    assert alphabets == {"AZ", "KA"}


def test_m1_configs_are_control_arm():
    from kryptosbot.swing_k1_universe import enumerate_universe
    for c in enumerate_universe():
        if c.model_variant == "M1":
            assert c.control_arm is True
            assert c.mask_id == "EMPTY_MASK"
        else:
            assert c.control_arm is False


def test_m2_uses_consume_m3_uses_skip():
    from kryptosbot.swing_k1_universe import enumerate_universe
    for c in enumerate_universe():
        if c.model_variant == "M2":
            assert c.null_consumption_mode == "consume"
        elif c.model_variant == "M3":
            assert c.null_consumption_mode == "skip"


def test_m4_only_six_tape_lengths():
    from kryptosbot.swing_k1_universe import enumerate_universe
    m4_lengths = {c.tape_length for c in enumerate_universe() if c.model_variant == "M4"}
    assert m4_lengths == {24, 30, 36, 49, 60, 73}


def test_m5_only_seven_segmentation_sets():
    from kryptosbot.swing_k1_universe import enumerate_universe
    m5_segs = {c.segment_boundaries for c in enumerate_universe() if c.model_variant == "M5"}
    expected = {
        (21,), (34,), (63,),
        (21, 34), (21, 63), (34, 63),
        (21, 34, 63),
    }
    assert m5_segs == expected


def test_each_config_has_spec_hash():
    from kryptosbot.swing_k1_universe import enumerate_universe
    hashes = {c.spec_hash for c in enumerate_universe()}
    configs = list(enumerate_universe())
    assert len(hashes) == len(configs), "spec_hashes must be unique per config"
    for h in hashes:
        assert len(h) == 64  # SHA-256 hex


def test_universe_size_bounded_below_50k():
    from kryptosbot.swing_k1_universe import enumerate_universe
    # Phase A target ~20K; verify the universe is in the order-of-magnitude range.
    n = sum(1 for _ in enumerate_universe())
    assert 5_000 <= n <= 50_000, f"universe size out of range: {n}"
