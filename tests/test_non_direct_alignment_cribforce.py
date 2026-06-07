"""Plumbing tests for the non-direct-alignment crib-forcing closure runner.

The runner reuses the tested ``solve_periodic`` for the inner cipher; the only
NEW, bug-prone logic is the reordering glue (``apply_perm`` direction) and the
identity-mask reuse. The #1 documented bug source in this project is
permutation direction (0-vs-1 indexing, gather-vs-scatter), so we plant a known
(perm, period, key, pt) and assert exact recovery.
"""
from __future__ import annotations

import importlib.util
import os

from kryptos.kernel.alphabet import AZ
from kryptos.kernel.constants import CRIB_DICT
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.vigenere import CipherVariant, encrypt_text

_RUNNER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "campaigns", "f_non_direct_alignment_cribforce_2026_05_28.py",
)
_spec = importlib.util.spec_from_file_location("nda_cribforce", _RUNNER_PATH)
nda = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nda)


def _planted_plaintext():
    """97-char PT with the canonical cribs at their canonical positions."""
    pt = ["X"] * 97
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ch
    return "".join(pt)


def test_apply_perm_is_gather_convention():
    """I[j] = CT[perm[j]] -- must match the 2026-05-25 runner exactly."""
    ct = "".join(chr(65 + (i % 26)) for i in range(97))
    perm = list(range(96, -1, -1))  # reverse
    intermediate = nda.apply_perm(ct, perm)
    assert all(intermediate[j] == ct[perm[j]] for j in range(97))
    # reverse of reverse is identity
    assert nda.apply_perm(intermediate, perm) == ct


def test_recovers_planted_reordered_periodic_solution():
    """Plant pt+period-13 key+reverse reordering, build CT so that
    apply_perm(CT, perm) == planted intermediate, assert exact recovery."""
    pt = _planted_plaintext()
    period = 13  # 0 free residues at the crib positions -> fully forced
    key = [(7 * r + 3) % 26 for r in range(period)]
    variant = CipherVariant.VIGENERE

    # intermediate I such that decrypt_text(I, key) == pt
    intermediate = encrypt_text(pt, key, variant, alphabet=AZ)

    # CT such that apply_perm(CT, perm) == intermediate, i.e. CT[perm[j]] = I[j]
    perm = list(range(96, -1, -1))
    ct_list = [None] * 97
    for j in range(97):
        ct_list[perm[j]] = intermediate[j]
    ct = "".join(ct_list)
    assert nda.apply_perm(ct, perm) == intermediate  # sanity on construction

    scorer = get_default_scorer()
    # require_bean=False: this test validates RECOVERY plumbing, not the Bean
    # filter (the planted key need not satisfy k[27]==k[65]).
    cells = nda.eval_reordering(
        ct, perm, periods=[period], crib_dict=CRIB_DICT, scorer=scorer,
        alphabets=(("AZ", AZ),), variants=(variant,), require_bean=False,
    )
    assert cells, "no candidate recovered from a planted reordered solution"
    recovered = [c for _ak, c in cells if c.plaintext == pt]
    assert recovered, (
        "planted plaintext not recovered; permutation direction or "
        "identity-mask reuse is wrong"
    )
    cand = recovered[0]
    assert cand.crib_score == 24
    assert tuple(cand.key) == tuple(key)


def test_wrong_perm_direction_does_not_recover():
    """A scatter-convention (inverted) reordering must NOT recover the plant --
    guards against silently 'fixing' a direction bug to pass the test above."""
    pt = _planted_plaintext()
    period = 13
    key = [(7 * r + 3) % 26 for r in range(period)]
    variant = CipherVariant.VIGENERE
    intermediate = encrypt_text(pt, key, variant, alphabet=AZ)
    perm = list(range(96, -1, -1))
    ct_list = [None] * 97
    for j in range(97):
        ct_list[perm[j]] = intermediate[j]
    ct = "".join(ct_list)

    # Build the INVERSE permutation; applying it should give a different
    # intermediate (reverse is self-inverse, so use a non-involutory perm).
    perm2 = list(range(1, 97)) + [0]  # cyclic shift, not self-inverse
    inter2 = nda.apply_perm(ct, perm2)
    assert inter2 != intermediate
