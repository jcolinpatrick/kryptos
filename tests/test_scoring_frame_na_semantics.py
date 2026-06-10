"""Suite-assurance Task B — Bean N/A encoding and cross-frame crib scoring.

Pins the kernel's "N/A, not False" contract for Bean:

* ``score_candidate(..., bean_result=None)`` means "Bean NOT EVALUATED",
  encoded as ``bean_passed=False`` + ``bean_detail is None``. The detail
  field is the tri-state discriminator (None = not evaluated; a summary
  string = evaluated). The conservative False can never inflate: an
  unevaluated Bean must never mint a BREAKTHROUGH.
* Crib scoring is frame-explicit via ``crib_dict``: the same plaintext
  scores 24/24 in its own frame and 0 in the wrong frame — both
  directions, so a frame mix-up can neither hide nor fake a solve.
"""
from __future__ import annotations

from kryptos.kernel.constants import CRIB_DICT, CT_LEN
from kryptos.kernel.constraints.bean import BeanResult
from kryptos.kernel.scoring.aggregate import score_candidate

_ENGLISH = (
    "THETIMEHASCOMETHEWALRUSSAIDTOTALKOFMANYTHINGSOFSHOESANDSHIPS"
    "ANDSEALINGWAXOFCABBAGESANDKINGS"
)


def _pt_with_cribs_at(offset_map: dict[int, str]) -> str:
    chars = list((_ENGLISH * 2)[:CT_LEN])
    for pos, ch in offset_map.items():
        chars[pos] = ch
    return "".join(chars)


def _shifted_crib_dict(shift: int) -> dict[int, str]:
    return {pos + shift: ch for pos, ch in CRIB_DICT.items()}


def test_bean_not_evaluated_is_distinguishable_from_bean_failed():
    pt = _pt_with_cribs_at(dict(CRIB_DICT))
    na = score_candidate(pt, bean_result=None)
    assert na.bean_passed is False
    assert na.bean_detail is None, (
        "bean_detail must be None when Bean was not evaluated (the N/A marker)"
    )
    failed = BeanResult(
        passed=False, eq_satisfied=0, eq_total=1,
        ineq_satisfied=242, ineq_total=242,
        linear_satisfied=101, linear_total=101,
        eq_failures=[(27, 65, 1, 2)], ineq_failures=[], linear_failures=[],
    )
    evald = score_candidate(pt, bean_result=failed)
    assert evald.bean_passed is False
    assert evald.bean_detail is not None and "FAIL" in evald.bean_detail, (
        "an EVALUATED failing Bean must carry a non-None detail summary"
    )


def test_bean_na_never_mints_breakthrough_even_at_crib_24():
    pt = _pt_with_cribs_at(dict(CRIB_DICT))
    b = score_candidate(pt, bean_result=None)
    assert b.crib_score == 24
    assert b.is_breakthrough is False, (
        "unevaluated Bean (N/A) must not satisfy the BREAKTHROUGH gate"
    )


def test_crib_scoring_is_frame_explicit_both_directions():
    """A candidate scores 24 only in ITS OWN frame: canonical PT vs the
    shifted frame scores ~0, shifted PT vs the canonical frame scores ~0."""
    # shift=23 keeps both shifted spans (44-56, 86-96) disjoint from the
    # canonical spans (21-33, 63-73), so cross-frame matches are pure chance
    # against the English filler — bounded by the NOISE floor (6).
    shift = 23
    canonical_pt = _pt_with_cribs_at(dict(CRIB_DICT))
    shifted_dict = _shifted_crib_dict(shift)
    shifted_pt = _pt_with_cribs_at(shifted_dict)

    in_frame_canonical = score_candidate(canonical_pt).crib_score
    in_frame_shifted = score_candidate(shifted_pt, crib_dict=shifted_dict).crib_score
    cross_a = score_candidate(canonical_pt, crib_dict=shifted_dict).crib_score
    cross_b = score_candidate(shifted_pt).crib_score

    assert in_frame_canonical == 24
    assert in_frame_shifted == 24
    assert cross_a <= 6, f"wrong-frame score above chance: {cross_a}"
    assert cross_b <= 6, f"wrong-frame score above chance: {cross_b}"


def test_crib_total_follows_the_declared_frame():
    partial = {21: "E", 22: "A", 23: "S", 24: "T"}
    pt = _pt_with_cribs_at(partial)
    b = score_candidate(pt, crib_dict=partial)
    assert b.crib_total == 4
    assert b.crib_score == 4
