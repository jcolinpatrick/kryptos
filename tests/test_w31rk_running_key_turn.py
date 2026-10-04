"""Tests for E-W31RK-01 (scripts/transposition/e_w31rk_01_running_key_turn.py)."""
import importlib.util
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "kryptosbot"))
_spec = importlib.util.spec_from_file_location(
    "w31rk", os.path.join(ROOT, "scripts", "transposition", "e_w31rk_01_running_key_turn.py"))
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

import panel_cribs as pc  # noqa: E402


def test_prereg_frozen_values():
    assert M.PREREG["bar_tier1"] == -4.924 and M.PREREG["tau"] == -4.924
    assert M.PREREG["bar_tier2a"] == -1.272 and M.PREREG["bar_tier2b"] == -4.941
    assert M.PREREG["tier1_width"] == 31 and len(M.PREREG["cells"]) == 7


def test_distinct_orderings_counts():
    assert len(M.distinct_orderings([31])) == 16
    labels = sum(len(o["aliases"]) for o in M.distinct_orderings([31]))
    assert labels == 64


def test_turn_is_a_permutation():
    for w in (2, 7, 31, 37, 96):
        for o in M.distinct_orderings([w]):
            assert sorted(o["src"]) == list(range(97))


def test_k3_reproduced_by_two_turns():
    s1 = M.turn_perm(336, 42, "LR-TB", "BT-LR", False)
    i1 = "".join(pc._K3_PT[s] for s in s1)
    s2 = M.turn_perm(336, 14, "LR-TB", "BT-LR", False)
    assert "".join(i1[s] for s in s2) == pc._K3_CT.replace("?", "")


def test_ka_tableau_convention_and_k1_k2_keywords():
    assert M.ENC["KA-vig"]("B", "P") == "E"
    f, a = M.DERIVE["KA-vig"]
    k1 = "".join(a[f(c, p)] for c, p in zip(pc._K1_CT, pc._K1_PT.replace("IQLUSION", "ILLUSION")))
    assert k1.startswith("PALIMPSESTPALIMPSEST") and k1[56] == "C"
    k2 = "".join(a[f(c, p)] for c, p in zip(pc._K2_CT.replace("?", ""), pc._K2_PT))
    assert k2.startswith("ABSCISSAABSCISSA")


def test_enc_derive_inverse_all_cells():
    for cell in M.PREREG["cells"]:
        f, a = M.DERIVE[cell]
        assert all(a[f(M.ENC[cell](p, k), p)] == k for p in M.AZ for k in M.AZ)


def _synth(order, cell, src, seed=7):
    r = random.Random(seed)
    pt = list("".join(r.choice(M.AZ) for _ in range(97)))
    pt[21:34] = "EASTNORTHEAST"
    pt[63:74] = "BERLINCLOCK"
    pt = "".join(pt)
    key = "".join(r.choice(M.AZ) for _ in range(97))
    if order == "A":
        x = "".join(M.ENC[cell](pt[q], key[q]) for q in range(97))
        ct = "".join(x[s] for s in src)
    else:
        y = "".join(pt[s] for s in src)
        ct = "".join(M.ENC[cell](y[j], key[j]) for j in range(97))
    return ct, {q: pt[q] for q in M.CRIB_DICT}, key


def test_forced_key_recovers_true_key_both_orders():
    src = M.distinct_orderings([31])[5]["src"]
    for cell in M.PREREG["cells"]:
        for order in ("A", "B"):
            ct, cribs, key = _synth(order, cell, src)
            fk = M.forced_key(ct, cribs, src, cell, order)
            assert all(key[i] == ch for i, ch in fk.items())


def test_statistic_separates_english_from_random():
    M._init_scorers(None)
    eng = "THEWHOLEPOINTOFTHEWORKSHEETISTOKEEPTHELETTERSLINEDUP" * 2
    assert M.s_frag(eng[:13], eng[20:31]) > -5.0
    r = random.Random(3)
    rnd = [M.s_frag("".join(r.choice(M.AZ) for _ in range(13)), "".join(r.choice(M.AZ) for _ in range(11))) for _ in range(200)]
    assert sum(v > -5.0 for v in rnd) == 0


def test_universe_hash_is_deterministic():
    u = M.build_universe()
    assert M.universe_hash(u) == M.universe_hash(M.build_universe())
