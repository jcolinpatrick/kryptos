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


def test_m3_projection_worked_example_from_spec():
    """spec §8.3 required test: test_runner_m3_ct73_projection.

    Worked example from spec §5.1:
    Mask = {2, 11, 27, 40, 55, 68, 80} (7 nulls).
    ENE CT97 [21..33] -> CT73 [19..30] (one position dropped: 27 is a null).
    BCL CT97 [63..73] -> CT73 [58..67] (no nulls in [63..73]).
    """
    from kryptosbot.swing_k1_recovery import project_crib_positions_ct73
    nulls = frozenset({2, 11, 27, 40, 55, 68, 80})
    projection = project_crib_positions_ct73(nulls)
    # ENE positions in CT97 are 21..33 inclusive
    ene_ct97 = set(range(21, 34))
    # Of those, position 27 is a null -- it does not appear in the CT73 mapping
    expected_ene = ene_ct97 - {27}
    assert set(projection.keys()) >= expected_ene
    # The 21..33 positions (minus 27) map to CT73 indices 19..30 (minus 27's slot)
    # 21 -> CT73 index = 21 - n_lt_21 = 21 - 2 = 19
    # 22 -> 22 - 2 = 20
    # ...
    # 26 -> 26 - 2 = 24
    # 27 -> dropped
    # 28 -> 28 - 3 = 25  (now n_lt_or_eq_27 = 3)
    # 33 -> 33 - 3 = 30
    assert projection[21] == 19
    assert projection[26] == 24
    assert projection[28] == 25
    assert projection[33] == 30
    # BCL: n_lt_63 = 5 (2, 11, 27, 40, 55), n_lt_or_eq_73 = 6 (add 68)
    # 63 -> 63 - 5 = 58
    # 73 -> 73 - 6 = 67
    assert projection[63] == 58
    assert projection[73] == 67


def test_m3_no_nulls_identity_projection():
    from kryptosbot.swing_k1_recovery import project_crib_positions_ct73
    projection = project_crib_positions_ct73(frozenset())
    for pos in list(range(21, 34)) + list(range(63, 74)):
        assert projection[pos] == pos


def test_m3_keystream_uses_ct73_indices():
    """For M3, keystream dict keys are CT73 indices, not CT97."""
    from kryptosbot.swing_k1_recovery import derive_keystream_ct73
    nulls = frozenset()  # no nulls: CT73 == CT97 here
    k = derive_keystream_ct73(variant="vigenere", alphabet="AZ", null_positions=nulls)
    assert len(k) == 24
