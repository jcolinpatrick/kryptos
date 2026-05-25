"""Tests for optional crib_dict parameter in crib scorer and score_candidate.

Task 6: parameterize crib scoring so masked decryption can supply remapped
crib positions without disturbing any existing caller (default = None -> uses
canonical CRIB_DICT).

Task 7: verify_masked_candidate + solve stub (appended below).
"""
from kryptos.kernel.scoring.crib_score import score_cribs_detailed
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constants import CRIB_DICT


def test_crib_scorer_default_unchanged():
    """Default call (no crib_dict) must use canonical CRIB_DICT.

    All-D text scores 0 because no canonical crib position expects 'D'.
    """
    assert score_cribs_detailed("D" * 97)["score"] == 0


def test_crib_scorer_accepts_custom_crib_dict():
    """Custom crib_dict: both positions match, score should be 2."""
    text = "SE"            # positions 0, 1
    cd = {0: "S", 1: "E"}  # both match
    result = score_cribs_detailed(text, crib_dict=cd)
    assert result["score"] == 2


def test_score_candidate_threads_crib_dict():
    """score_candidate forwards crib_dict; one match should give crib_score=1."""
    text = "SE"
    cd = {0: "S", 1: "X"}  # position 0 matches, position 1 does not
    result = score_candidate(text, crib_dict=cd)
    assert result.crib_score == 1


# ---------------------------------------------------------------------------
# Task 7: verify_masked_candidate + solve stub
# ---------------------------------------------------------------------------

import pytest
from kryptos.kernel.alphabet import AZ
from kryptos.kernel.transforms.vigenere import CipherVariant, encrypt_text
from kryptos.kernel.masking.verify import verify_masked_candidate, solve


def _build_masked_ct():
    """Construct a synthetic carved CT with 2 known nulls.

    PT = "SXEYZ", Vigenere key [1,2,3,4,5] -> core_ct = "TZHCE".
    Insert null 'Q' at carved positions 2 and 5:
        carved = "TZQHCQE"  (len 7, nulls at {2,5})
    After stripping nulls: ct_prime = "TZHCE" -> decrypts back to "SXEYZ".

    Crib dict in CARVED coordinates:
        carved 0 -> ct' 0 -> pt[0] = 'S'   => crib {0: 'S'}
        carved 3 -> ct' 2 -> pt[2] = 'E'   => crib {3: 'E'}
    (carved 3 shifts by 1 because one null at carved 2 precedes it.)
    """
    pt = "SXEYZ"
    key = [1, 2, 3, 4, 5]
    core_ct = encrypt_text(pt, key, CipherVariant.VIGENERE, alphabet=AZ)  # "TZHCE"
    carved = core_ct[:2] + "Q" + core_ct[2:4] + "Q" + core_ct[4:]        # "TZQHCQE"
    true_mask = frozenset({2, 5})
    # carved 0 -> ct'[0] -> pt[0]='S'; carved 3 -> ct'[2] -> pt[2]='E'
    crib_dict = {0: "S", 3: "E"}
    return carved, key, true_mask, crib_dict


def test_true_mask_recovers_cribs():
    carved, key, true_mask, crib_dict = _build_masked_ct()
    res = verify_masked_candidate(
        carved, true_mask, CipherVariant.VIGENERE, key,
        crib_dict=crib_dict, alphabet=AZ,
    )
    assert res.pt_len == len(carved) - len(true_mask)
    assert res.crib_score == 2


def test_wrong_mask_fails_cribs():
    carved, key, _true, crib_dict = _build_masked_ct()
    res = verify_masked_candidate(
        carved, frozenset({0, 1}), CipherVariant.VIGENERE, key,
        crib_dict=crib_dict, alphabet=AZ,
    )
    assert res.crib_score < 2


def test_solve_interface_is_defined_but_deferred():
    with pytest.raises(NotImplementedError):
        next(solve(mask_universe=[frozenset()], mechanism_family=None,
                   constraint_oracle=verify_masked_candidate))
