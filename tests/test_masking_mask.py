import pytest
from kryptos.kernel.masking.mask import (
    validate_mask, extract_ct, remap_position, remap_crib_dict,
)
from kryptos.kernel.constants import CT, CRIB_DICT, CT_LEN

def test_empty_mask_is_identity():
    assert extract_ct(CT, frozenset()) == CT
    assert remap_position(50, frozenset()) == 50
    assert remap_crib_dict(CRIB_DICT, frozenset()) == CRIB_DICT

def test_extract_removes_null_positions_and_shrinks_length():
    mask = frozenset({0, 1, 2})
    out = extract_ct(CT, mask)
    assert out == CT[3:]
    assert len(out) == CT_LEN - 3

def test_remap_shifts_by_nulls_before_position():
    mask = frozenset({5, 10})
    assert remap_position(4, mask) == 4     # no nulls before
    assert remap_position(7, mask) == 6     # one null (5) before
    assert remap_position(11, mask) == 9    # two nulls (5,10) before

def test_remap_crib_dict_relocates_cribs_into_extracted_coords():
    mask = frozenset({0})  # one null before everything
    remapped = remap_crib_dict(CRIB_DICT, mask)
    assert remapped[20] == CRIB_DICT[21]
    assert remapped[62] == CRIB_DICT[63]
    assert len(remapped) == len(CRIB_DICT)

def test_validate_rejects_null_on_crib_position_by_default():
    with pytest.raises(ValueError):
        validate_mask(frozenset({21}), CT_LEN)

def test_validate_allows_crib_null_when_explicitly_relaxed():
    validate_mask(frozenset({21}), CT_LEN, allow_crib_nulls=True)  # no raise

def test_validate_rejects_out_of_range():
    with pytest.raises(ValueError):
        validate_mask(frozenset({CT_LEN}), CT_LEN)
