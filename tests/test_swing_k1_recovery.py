"""Tests for swing_k1_recovery."""
import pytest


def test_ct97_derives_24_keystream_values_for_full_cribs():
    from kryptosbot.swing_k1_recovery import derive_keystream_ct97
    # No nulls; all 24 crib positions are recoverable.
    k = derive_keystream_ct97(variant="vigenere", alphabet="AZ", null_positions=frozenset())
    assert len(k) == 24


def test_ct97_skips_null_crib_positions():
    """If a null sits on a crib position, that crib slot is dropped from recovery."""
    from kryptosbot.swing_k1_recovery import derive_keystream_ct97
    nulls_on_crib = frozenset({21, 22})
    k = derive_keystream_ct97(variant="vigenere", alphabet="AZ", null_positions=nulls_on_crib)
    # 24 - 2 = 22 surviving crib positions
    assert len(k) == 22


def test_keystream_values_in_range():
    from kryptosbot.swing_k1_recovery import derive_keystream_ct97
    k = derive_keystream_ct97(variant="vigenere", alphabet="AZ", null_positions=frozenset())
    for pos, val in k.items():
        assert 0 <= val <= 25
        assert 21 <= pos <= 33 or 63 <= pos <= 73


def test_vig_vs_beau_vs_varbeau_give_different_keystreams():
    """Variant arithmetic differs: vig k = CT-PT, beau k = CT+PT, varbeau k = PT-CT."""
    from kryptosbot.swing_k1_recovery import derive_keystream_ct97
    k_vig = derive_keystream_ct97(variant="vigenere", alphabet="AZ", null_positions=frozenset())
    k_beau = derive_keystream_ct97(variant="beaufort", alphabet="AZ", null_positions=frozenset())
    k_varbeau = derive_keystream_ct97(variant="var_beaufort", alphabet="AZ", null_positions=frozenset())
    # At least one position must differ between any two variants.
    assert any(k_vig[p] != k_beau[p] for p in k_vig)
    assert any(k_vig[p] != k_varbeau[p] for p in k_vig)
