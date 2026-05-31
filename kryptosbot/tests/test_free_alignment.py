"""Lever B1: wire free / non-direct crib-alignment scoring into the dispatcher.

The DSL accepts crib_alignment="free" but the dispatcher always scored anchored
(direct_positional), silently ignoring it — so a whole frontier class (the
disclosed cribs land somewhere OTHER than positions 21-33 / 63-73, e.g. under a
non-direct alignment or null-shifted model) was untestable. This wires
score_candidate_free for crib_alignment="free".

CAVEAT (pinned here): free scoring matches cribs ANYWHERE, so its chance rate is
far higher than anchored — a free crib_score is only meaningful against a
free-matched null, and ``canonical_positions`` distinguishes a real
at-position solve from a weaker found-elsewhere hit.
"""

from kryptosbot.job_dispatcher import _score_real_k4_candidate

_CT = "A" * 97  # only used by the anchored/Bean path; irrelevant to free scoring

# EASTNORTHEAST (13) at index 0, BERLINCLOCK (11) at index 50 — both present but
# NOT at the canonical anchored positions (21-33 / 63-73).
_PT_OFFANCHOR = ("EASTNORTHEAST" + "X" * 37 + "BERLINCLOCK" + "X" * 36)
# Cribs at the canonical anchored positions.
_PT_ANCHORED = ("X" * 21 + "EASTNORTHEAST" + "X" * 29 + "BERLINCLOCK" + "X" * 23)


def test_offanchor_cribs_found_only_by_free():
    assert len(_PT_OFFANCHOR) == 97 and len(_PT_ANCHORED) == 97
    free = _score_real_k4_candidate(_CT, _PT_OFFANCHOR, "free")
    direct = _score_real_k4_candidate(_CT, _PT_OFFANCHOR, "direct_positional")
    assert free["crib_score"] == 24, free          # both cribs found anywhere
    assert free["canonical_positions"] is False     # but not at disclosed positions
    assert free["scoring_mode"] == "free"
    assert direct["crib_score"] < 24                # anchored misses off-position cribs


def test_anchored_solve_scores_under_both_modes():
    free = _score_real_k4_candidate(_CT, _PT_ANCHORED, "free")
    direct = _score_real_k4_candidate(_CT, _PT_ANCHORED, "direct_positional")
    assert direct["crib_score"] == 24
    assert free["crib_score"] == 24
    assert free["canonical_positions"] is True      # free agrees it's at-position


def test_free_scoring_does_not_assert_bean():
    # Bean depends on fixed positions; it is N/A under free alignment.
    free = _score_real_k4_candidate(_CT, _PT_ANCHORED, "free")
    assert free["bean_passed"] is False
