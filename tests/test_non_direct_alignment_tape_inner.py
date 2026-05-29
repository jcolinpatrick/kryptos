"""Plumbing tests for the non-direct-alignment NON-PERIODIC public-tape runner.

This runner closes the still-open non-periodic-inner sub-arm of
``non_direct_alignment`` (the crib-forced periodic-inner arm was closed
2026-05-28 over the same 52-route universe). Model: an outer named grid-route
reordering ``pi`` maps CT -> I = pi(CT); an inner FINITE PUBLIC KEY TAPE decrypts
I IN PLACE -> PT, cribs at canonical PLAINTEXT positions 21-33 / 63-73.

The only NEW, bug-prone logic is the reordering glue + the tape decrypt wiring.
Per CLAUDE.md the #1 documented bug source is permutation direction
(gather-vs-scatter); so we plant a known (perm, tape, variant, pt) and assert
exact recovery, and we assert a WRONG perm does NOT recover.
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
    "scripts", "campaigns", "f_non_direct_alignment_tape_inner_2026_05_29.py",
)
_spec = importlib.util.spec_from_file_location("nda_tape_inner", _RUNNER_PATH)
nda = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nda)

N = 97


def _planted_plaintext():
    """97-char PT with the canonical cribs at their canonical positions."""
    pt = ["X"] * N
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ch
    return "".join(pt)


def _scatter(intermediate, perm):
    """Inverse of gather: CT[perm[j]] = I[j]. Used only to synthesize CT."""
    out = [None] * len(perm)
    for j, src in enumerate(perm):
        out[src] = intermediate[j]
    assert None not in out
    return "".join(out)


def test_route_universe_matches_closed_periodic_arm():
    aligns = nda.build_reordering_universe()
    assert len(aligns) == 52
    # byte-identical universe to the closed periodic-inner arm -> comparable
    assert nda.reordering_hash(aligns) == nda.EXPECTED_REORDERING_HASH


def test_apply_perm_is_gather_convention():
    ct = "".join(chr(65 + (i % 26)) for i in range(N))
    perm = list(range(N - 1, -1, -1))  # reverse
    intermediate = nda.apply_perm(ct, perm)
    assert intermediate == ct[::-1]


def test_recovery_positive_control():
    """Plant PT with cribs, encrypt under (tape, variant, perm), synthesize CT,
    then assert the runner recovers crib_score == 24 for that exact config."""
    pt = _planted_plaintext()
    tape = tuple((7 * i + 3) % 26 for i in range(N))  # arbitrary length-97 tape
    perm = [name_perm[1] for name_perm in nda.build_reordering_universe()
            if name_perm[0] == "grid7_colLR"][0]
    variant = CipherVariant.VIGENERE

    # forward: PT --tape encrypt--> I --scatter(perm)--> CT
    intermediate = apply_key_tape(pt, tape, variant=variant,
                                  direction="encrypt", alphabet=AZ)
    ct_synth = _scatter(intermediate, perm)

    # runner: CT --gather(perm)--> I --tape decrypt--> PT'
    recovered = nda.decrypt_reordered_tape(ct_synth, perm, tape,
                                           variant=variant, alphabet=AZ)
    assert recovered == pt
    assert int(score_candidate(recovered).crib_score) == 24


def test_wrong_perm_does_not_recover():
    """A different reordering must NOT recover the cribs -- guards against a
    silent gather/scatter or identity collapse making every run look like a hit."""
    pt = _planted_plaintext()
    tape = tuple((7 * i + 3) % 26 for i in range(N))
    universe = dict(nda.build_reordering_universe())
    right = universe["grid7_colLR"]
    wrong = universe["grid8_colLR"]
    variant = CipherVariant.VIGENERE

    intermediate = apply_key_tape(pt, tape, variant=variant,
                                  direction="encrypt", alphabet=AZ)
    ct_synth = _scatter(intermediate, right)
    recovered = nda.decrypt_reordered_tape(ct_synth, wrong, tape,
                                           variant=variant, alphabet=AZ)
    assert int(score_candidate(recovered).crib_score) < 24


def test_public_tapes_are_length_97_and_public_only():
    tapes = nda.public_tapes()
    assert len(tapes) == 16  # 8 public sources x {AZ, KA}
    for rec in tapes:
        assert len(rec["values"]) == N
        assert all(0 <= v <= 25 for v in rec["values"])
        # provenance guard: only solved-panel / tableau sources, never K4
        assert rec["source"].split("__")[0] in {
            "K1_PT", "K2_PT", "K3_PT", "K1_CT", "K2_CT", "K3_CT",
            "K1K2K3_PT", "KRYPTOS_TABLEAU_ROWMAJOR",
        }
