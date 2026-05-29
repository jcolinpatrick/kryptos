"""Plumbing tests for the C7 segmented (cut) public-tape closure.

C7 model (direct_positional): a single PUBLIC key tape T is physically CUT at
position C in {34..62} (the gap between the two crib groups) and the second
piece RESTARTS the tape -- keystream K[i] = T[i] for i<C, K[i] = T[i-C] for
i>=C. This breaks the Bean equality k[27]=k[65] (the cut falls between the
EAST/NORTHEAST group ending at 33 and the BERLIN/CLOCK group starting at 63), so
it is a genuinely distinct degree of freedom from the no-cut public-tape case.

The new bug-prone logic is the cut-keystream construction. Per CLAUDE.md
(indexing / boundary inclusivity are top bug sources) we plant a known
(tape, cut, variant, pt), assert exact recovery, and assert a WRONG cut does NOT
recover.
"""
from __future__ import annotations

import importlib.util
import os

from kryptos.kernel.alphabet import AZ
from kryptos.kernel.constants import CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.key_tape import apply_key_tape
from kryptos.kernel.transforms.vigenere import CipherVariant

_RUNNER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "campaigns", "f_c7_segmented_public_tape_2026_05_29.py",
)
_spec = importlib.util.spec_from_file_location("c7_seg", _RUNNER_PATH)
c7 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c7)

N = 97


def _planted_plaintext():
    pt = ["X"] * N
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ch
    return "".join(pt)


def test_cut_keystream_construction():
    """K = T[:C] ++ T[:N-C]: full length N, second segment restarts the tape."""
    tape = tuple(range(N))  # 0..96 so positions are self-identifying
    C = 40
    K = c7.cut_keystream(tape, C, N)
    assert len(K) == N
    assert list(K[:C]) == list(range(C))             # segment 1: T[0..C-1]
    assert list(K[C:]) == list(range(N - C))          # segment 2: T restarted


def test_cut_in_gap_window_only():
    """The pre-registered cut window is the inter-crib gap {34..62}."""
    assert min(c7.CUT_POSITIONS) == 34 and max(c7.CUT_POSITIONS) == 62
    assert len(c7.CUT_POSITIONS) == 29


def test_recovery_positive_control():
    pt = _planted_plaintext()
    tape = tuple((5 * i + 2) % 26 for i in range(N))
    C = 45
    variant = CipherVariant.VIGENERE

    K = c7.cut_keystream(tape, C, N)
    ct_synth = apply_key_tape(pt, K, variant=variant, direction="encrypt", alphabet=AZ)

    recovered = c7.decrypt_cut_tape(ct_synth, tape, C, variant=variant, alphabet=AZ)
    assert recovered == pt
    assert int(score_candidate(recovered).crib_score) == 24


def test_wrong_cut_does_not_recover():
    pt = _planted_plaintext()
    tape = tuple((5 * i + 2) % 26 for i in range(N))
    variant = CipherVariant.VIGENERE
    K = c7.cut_keystream(tape, 45, N)
    ct_synth = apply_key_tape(pt, K, variant=variant, direction="encrypt", alphabet=AZ)
    # decrypt with a different cut -> second segment misaligned -> not recovered
    recovered = c7.decrypt_cut_tape(ct_synth, tape, 50, variant=variant, alphabet=AZ)
    assert int(score_candidate(recovered).crib_score) < 24


def test_public_tapes_are_public_only():
    tapes = c7.public_tapes()
    assert len(tapes) == 16
    for rec in tapes:
        assert len(rec["values"]) == N
        assert rec["source"].split("__")[0] in {
            "K1_PT", "K2_PT", "K3_PT", "K1_CT", "K2_CT", "K3_CT",
            "K1K2K3_PT", "KRYPTOS_TABLEAU_ROWMAJOR",
        }
