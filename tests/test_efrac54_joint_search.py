"""Tests for the strong cold-start joint search (efrac54_joint two-sided detector)."""
import math
import os
import random

from kryptos.kernel.constants import ALPH, ALPH_IDX, CRIB_DICT, CRIB_POSITIONS, CT_LEN
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.detectors.efrac54_joint import CandidateTuple, score_joint, encrypt_with_model
from kryptos.detectors import efrac54_joint_search as js

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KAHN = os.path.join(_ROOT, "reference", "running_key_texts", "kahn_codebreakers_1967.txt")
_NONCRIB = [i for i in range(CT_LEN) if i not in set(CRIB_POSITIONS)]


def _rand_ct(rng):
    return "".join(ALPH[rng.randrange(26)] for _ in range(CT_LEN))


def _full_pt(rng):
    pt = [ALPH[rng.randrange(26)] for _ in range(CT_LEN)]
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ch
    return "".join(pt)


def test_incremental_matches_score_joint_random_states():
    rng = random.Random(11)
    scorer = get_default_scorer()
    for _ in range(15):
        ct = _rand_ct(rng)
        width = rng.choice((6, 8, 9))
        kappa = tuple(rng.sample(range(width), width))
        variant = rng.choice(("vigenere", "beaufort", "var_beaufort"))
        sigma = list(range(26))
        rng.shuffle(sigma)
        pt = _full_pt(rng)
        pt_ints = [ALPH_IDX[c] for c in pt]
        ct_idx = [ALPH_IDX[c] for c in ct]
        pi = js._pi_for(width, kappa, CT_LEN)
        st = js.JointState(ct_idx, pi, variant, scorer)
        st.set_state(sigma, pt_ints)
        pt_nc = "".join(pt[i] for i in _NONCRIB)
        ref = score_joint(ct, CandidateTuple(tuple(sigma), width, kappa, pt_nc), scorer, variant).t
        assert abs(st.t() - ref) < 1e-9, (st.t(), ref, variant)


def test_incremental_deltas_consistent_after_moves():
    rng = random.Random(22)
    scorer = get_default_scorer()
    ct = _rand_ct(rng)
    width, kappa, variant = 8, tuple(rng.sample(range(8), 8)), "vigenere"
    sigma = list(range(26))
    rng.shuffle(sigma)
    pt = _full_pt(rng)
    ct_idx = [ALPH_IDX[c] for c in ct]
    pi = js._pi_for(width, kappa, CT_LEN)
    st = js.JointState(ct_idx, pi, variant, scorer)
    st.set_state(sigma, [ALPH_IDX[c] for c in pt])
    cur = st.t()
    for _ in range(300):
        if rng.random() < 0.7:
            i = _NONCRIB[rng.randrange(len(_NONCRIB))]
            cur += st.apply_pt_move(i, rng.randrange(26))
        else:
            a, b = rng.randrange(26), rng.randrange(26)
            cur += st.apply_sigma_swap(a, b)
    # tracked delta-sum must match a fresh full recompute, and score_joint
    assert abs(cur - st.t()) < 1e-7, (cur, st.t())
    pt_nc = "".join(ALPH[st.pt[i]] for i in _NONCRIB)
    ref = score_joint(ct, CandidateTuple(tuple(st.sigma), width, kappa, pt_nc), scorer, variant).t
    assert abs(st.t() - ref) < 1e-7, (st.t(), ref)


def test_search_recovers_planted_near_oracle():
    """A strong cold-start search on a planted solution should reach a t close to the
    true (oracle) t -- i.e. the search is strong enough to find the basin."""
    rng = random.Random(42)
    eng = [c for c in open(_KAHN, encoding="utf-8", errors="ignore").read().upper() if "A" <= c <= "Z"]
    eng_idx = [ALPH_IDX[c] for c in eng]
    off, koff, width = 5000, 9000, 8
    pt_list = eng[off:off + CT_LEN][:]
    for pos, ch in CRIB_DICT.items():
        pt_list[pos] = ch
    pt = "".join(pt_list)
    key_nums = eng_idx[koff:koff + CT_LEN]
    sigma_true = list(range(26))
    rng.shuffle(sigma_true)
    kappa = tuple(rng.sample(range(width), width))
    ct = encrypt_with_model(pt, sigma_true, width, list(kappa), key_nums, "vigenere")
    scorer = get_default_scorer()
    pt_nc_true = "".join(pt[i] for i in _NONCRIB)
    oracle = score_joint(ct, CandidateTuple(tuple(sigma_true), width, kappa, pt_nc_true), scorer, "vigenere").t
    found = js.joint_search(ct, width, kappa, "vigenere", scorer,
                            n_iters=120000, restarts=3, rng=random.Random(7)).t
    # The search must land within a small margin of the oracle (strong search).
    assert found >= oracle - 1.0, (found, oracle)
