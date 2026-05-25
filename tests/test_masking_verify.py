"""Tests for optional crib_dict parameter in crib scorer and score_candidate.

Task 6: parameterize crib scoring so masked decryption can supply remapped
crib positions without disturbing any existing caller (default = None → uses
canonical CRIB_DICT).
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
