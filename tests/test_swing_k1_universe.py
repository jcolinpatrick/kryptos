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


def test_m1_uses_sentinel_class_label():
    """M1 control arm must not bucket into mod_n or boundary_region for downstream grouping."""
    from kryptosbot.swing_k1_universe import enumerate_universe, _EMPTY_MASK
    assert _EMPTY_MASK.class_label == "sentinel"
    # And reachable through a config:
    m1_configs = [c for c in enumerate_universe() if c.model_variant == "M1"]
    assert len(m1_configs) == 6
    # All M1 configs reuse the sentinel mask_id
    assert {c.mask_id for c in m1_configs} == {"EMPTY_MASK"}


def test_universe_hash_stable_across_calls():
    """spec §8.3 required test: test_runner_universe_hash_stable."""
    from kryptosbot.swing_k1_universe import compute_universe_hash
    h1 = compute_universe_hash()
    h2 = compute_universe_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_universe_hash_changes_when_target_counts_change():
    from kryptosbot.swing_k1_universe import compute_universe_hash
    h_default = compute_universe_hash()
    # Forcing a different mask-catalog null-count set must change the hash.
    h_alt = compute_universe_hash(target_null_counts=(20,))
    assert h_default != h_alt


def test_universe_size_reported():
    from kryptosbot.swing_k1_universe import universe_summary
    summary = universe_summary()
    assert summary["total_config_count"] > 0
    assert summary["per_model"]["M1"] == 6  # 3 variants x 2 alphabets, control arm
    for model in ("M2", "M3", "M4", "M5"):
        assert summary["per_model"][model] > 0


def test_universe_hash_pinned_exact_value():
    """Pin the exact universe hash so any silent drift in the universe is caught immediately."""
    from kryptosbot.swing_k1_universe import compute_universe_hash
    # Captured at Plan Task 9 landing; any change here means the universe changed.
    assert compute_universe_hash() == "e6c61157db433da121113ab82b86e3f3893116e559857a8bc5ba253836f470fe"


def test_universe_hash_independent_of_pythonhashseed():
    """The universe hash must not depend on Python hash randomization."""
    import subprocess
    import sys
    out = subprocess.check_output(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, 'src'); "
         "from kryptosbot.swing_k1_universe import compute_universe_hash; "
         "print(compute_universe_hash())"],
        env={"PATH": "/usr/bin", "PYTHONHASHSEED": "0", "PYTHONPATH": "src"},
        text=True,
        cwd="/home/cpatrick/kryptos",
    ).strip()
    from kryptosbot.swing_k1_universe import compute_universe_hash
    assert out == compute_universe_hash()
