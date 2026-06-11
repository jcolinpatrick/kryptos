"""TDD tests for the GAP-10 positional-measurement statistics library.

Prereg: docs/campaigns/gap10_positional_measurement_2026_06_11.md.
The #1 bug sources for this kind of measurement are off-by-one region
boundaries, wrong residue pairing, and null samplers that don't actually
preserve what they claim to preserve — each is pinned here with hand-computed
known answers. Component-1 real-CT known answers (C(2)=117, C(13)=7, C(26)=1)
were ground-truthed against the kernel constants + audit enumerator on
2026-06-11 before the lib existed.
"""
from __future__ import annotations

import importlib.util
import os
import random

from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_INEQ

_LIB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "statistical", "gap10_lib.py",
)
_spec = importlib.util.spec_from_file_location("gap10_lib", _LIB_PATH)
g10 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g10)

POSITIONS = sorted(CRIB_DICT)


# ── IC ────────────────────────────────────────────────────────────────────

def test_ic_hand_example():
    # "AABB": sum c(c-1) = 2+2 = 4; n(n-1) = 12 -> 1/3
    assert abs(g10.ic("AABB") - (1 / 3)) < 1e-12


def test_ic_all_distinct_is_zero():
    assert g10.ic("ABCDE") == 0.0


def test_region_ic_matches_direct_computation():
    region = list(range(34, 63))  # gap region R2, n=29
    sub = "".join(CT[i] for i in region)
    assert abs(g10.region_ic(CT, region) - g10.ic(sub)) < 1e-12


# ── Residue machinery (component 1) ──────────────────────────────────────

def test_same_residue_pairs_small():
    # positions 0,2,4 mod 2 -> all residue 0 -> C(3,2)=3 pairs
    assert g10.same_residue_pair_count([0, 2, 4], 2) == 3
    # mod 3: residues 0,2,1 -> no pairs
    assert g10.same_residue_pair_count([0, 2, 4], 3) == 0


def test_conflict_count_planted():
    ineq = [(0, 2), (1, 3), (0, 4)]
    # mod 2: (0,2) same, (1,3) same, (0,4) same -> 3
    assert g10.conflict_count(ineq, 2) == 3
    # mod 4: (0,4) only -> 1
    assert g10.conflict_count(ineq, 4) == 1


def test_ineq_from_crib_letters_reproduces_kernel_on_real_ct():
    letters = [CT[p] for p in POSITIONS]
    ineq = g10.ineq_from_crib_letters(letters)
    assert set(ineq) == set(BEAN_INEQ)


def test_cp_profile_real_ct_known_answers():
    letters = [CT[p] for p in POSITIONS]
    prof = g10.cp_profile(g10.ineq_from_crib_letters(letters))
    assert prof[2] == 117
    assert prof[13] == 7
    assert prof[26] == 1
    assert set(prof) == set(range(2, 27))


def test_perm_null_preserves_composition_and_varies():
    letters = [CT[p] for p in POSITIONS]
    rng = random.Random(123)
    draw = g10.perm_crib_letters(rng)
    assert sorted(draw) == sorted(letters)  # composition preserved
    draws = {tuple(g10.perm_crib_letters(rng)) for _ in range(20)}
    assert len(draws) > 1  # actually varies


def test_iid_null_letters_in_range():
    rng = random.Random(123)
    draw = g10.iid_crib_letters(rng)
    assert len(draw) == len(POSITIONS)
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in draw)


# ── Boundary change statistic (component 3) ──────────────────────────────

def test_tv_distance_extremes():
    assert g10.tv_distance("AAAA", "AAAA") == 0.0
    assert g10.tv_distance("AAAA", "BBBB") == 1.0


def test_dw_boundary_detects_planted_change():
    # 20 A's then 20 B's: center x=20 with w=10 compares pure-A vs pure-B.
    s = "A" * 20 + "B" * 20
    prof = g10.dw_profile(s, w=10)
    assert prof[20] == 1.0
    # far from boundary the flanks are identical
    assert prof[10] == 0.0
    # valid centers are [w, len-w]
    assert min(prof) == 10 and max(prof) == 30


# ── Tail machinery ────────────────────────────────────────────────────────

def test_two_sided_tail_add_one():
    null = [1, 2, 3, 4, 5, 6, 7, 8, 9]  # M=9
    # obs=9: #{>=}=1 -> (1+1)/10=0.2 ; #{<=}=9 -> 1.0 ; two-sided=min(1, 0.4)
    assert abs(g10.two_sided_tail(9, null) - 0.4) < 1e-12
    # obs=5 (median): both sides 5/9 -> (5+1)/10=0.6 each -> capped at 1.0
    assert g10.two_sided_tail(5, null) == 1.0


def test_one_sided_high_tail():
    null = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert abs(g10.one_sided_high_tail(9, null) - 0.2) < 1e-12  # (1+1)/10
    assert abs(g10.one_sided_high_tail(10, null) - 0.1) < 1e-12  # (0+1)/10


def test_holm_hand_example():
    # p = {a: 0.001, b: 0.02, c: 0.5}, alpha=0.01, n=3
    # sorted: a(0.001*3=0.003 adj), b(0.02*2=0.04), c(0.5*1=0.5)
    # rejections: a passes (0.001 <= 0.01/3), b fails (0.02 > 0.01/2) -> stop
    out = g10.holm({"a": 0.001, "b": 0.02, "c": 0.5}, alpha=0.01)
    assert abs(out["a"][1] - 0.003) < 1e-12 and out["a"][2] is True
    assert abs(out["b"][1] - 0.04) < 1e-12 and out["b"][2] is False
    assert out["c"][2] is False and out["c"][1] == 0.5
