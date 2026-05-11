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


def test_boundary_masks_only_in_gap_regions():
    from kryptosbot.swing_k1_masks import enumerate_boundary_region_masks
    crib_positions = frozenset(range(21, 34)) | frozenset(range(63, 74))
    for m in enumerate_boundary_region_masks(target_null_counts=(17, 20, 24, 28)):
        # No null position may coincide with a crib position.
        assert not (m.positions & crib_positions)
        assert all(p in range(0, 21) or p in range(34, 63) or p in range(74, 97)
                   for p in m.positions)


def test_boundary_masks_distinct_patterns():
    from kryptosbot.swing_k1_masks import enumerate_boundary_region_masks
    masks = list(enumerate_boundary_region_masks(target_null_counts=(17, 20, 24, 28)))
    assert len(masks) >= 4  # at minimum one per null count
    positions_sets = {m.positions for m in masks}
    assert len(positions_sets) == len(masks)  # no duplicates


def test_boundary_masks_target_null_counts_respected():
    from kryptosbot.swing_k1_masks import enumerate_boundary_region_masks
    for m in enumerate_boundary_region_masks(target_null_counts=(20,)):
        assert m.null_count == 20


def test_full_catalog_is_union_of_classes():
    from kryptosbot.swing_k1_masks import build_mask_catalog
    catalog = build_mask_catalog()
    mod_n = [m for m in catalog if m.class_label == "mod_n"]
    boundary = [m for m in catalog if m.class_label == "boundary_region"]
    assert len(mod_n) > 0
    assert len(boundary) > 0
    assert len(catalog) == len(mod_n) + len(boundary)


def test_full_catalog_no_crib_collisions_strict_when_required():
    """Strict catalog (no crib-position collisions) keeps only crib-safe masks."""
    from kryptosbot.swing_k1_masks import build_mask_catalog
    crib_positions = frozenset(range(21, 34)) | frozenset(range(63, 74))
    catalog = build_mask_catalog(strict_crib_safe=True)
    for m in catalog:
        assert not (m.positions & crib_positions), f"mask {m.mask_id} collides with cribs"


def test_full_catalog_default_is_inclusive():
    """Default catalog allows mod-N masks that may overlap cribs (M3 handles via projection)."""
    from kryptosbot.swing_k1_masks import build_mask_catalog
    catalog_default = build_mask_catalog()
    catalog_strict = build_mask_catalog(strict_crib_safe=True)
    assert len(catalog_default) >= len(catalog_strict)


def test_catalog_serializes_to_json():
    import json
    from kryptosbot.swing_k1_masks import build_mask_catalog, serialize_catalog
    catalog = build_mask_catalog()
    serialized = serialize_catalog(catalog)
    rt = json.loads(json.dumps(serialized))  # round-trip safe
    assert "masks" in rt
    assert len(rt["masks"]) == len(catalog)
    assert all("mask_id" in m and "positions" in m for m in rt["masks"])
