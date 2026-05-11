"""Tests for swing_k1_masks."""
import pytest


def test_mod_n_mask_emits_positions_in_range():
    from kryptosbot.swing_k1_masks import enumerate_mod_n_masks
    masks = list(enumerate_mod_n_masks(target_null_counts=(17, 20, 24, 28)))
    assert len(masks) > 0
    for m in masks:
        assert 17 <= len(m.positions) <= 28
        assert all(0 <= p < 97 for p in m.positions)
        assert m.class_label == "mod_n"


def test_mod_n_mask_ids_are_unique():
    from kryptosbot.swing_k1_masks import enumerate_mod_n_masks
    masks = list(enumerate_mod_n_masks(target_null_counts=(17, 20, 24, 28)))
    ids = [m.mask_id for m in masks]
    assert len(ids) == len(set(ids))


def test_mod_n_known_pattern_2_in_4():
    """N=4, S={0,1}: positions 0,1,4,5,8,9,... so 49 positions. Filtered out (> 28)."""
    from kryptosbot.swing_k1_masks import _mod_n_positions
    pos = _mod_n_positions(N=4, residues=frozenset({0, 1}), text_len=97)
    assert len(pos) == 49


def test_mod_n_known_pattern_1_in_5():
    """N=5, S={0}: every 5th position -- 0,5,10,...,95 = 20 positions."""
    from kryptosbot.swing_k1_masks import _mod_n_positions
    pos = _mod_n_positions(N=5, residues=frozenset({0}), text_len=97)
    assert len(pos) == 20
    assert pos == frozenset({0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95})
