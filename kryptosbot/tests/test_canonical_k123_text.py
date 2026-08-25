"""Guard the canonical K1-K3 panel text against silent corruption.

On 2026-08-25 kryptosbot/compute.py was found to carry a FABRICATED K3
plaintext -- a paraphrase containing phrases absent from K3 and five invented
'X' separators -- as the last of three K3_PT bindings, so it shadowed the
correct ones and was the copy exported in SPLIT_TEXT_SOURCES and K123_PT.
It had been used, among other things, to characterise Sanborn's separator
conventions, producing a wrong clause-length distribution.

The decisive test is cheap and is the reason this file exists: K3 is a keyed
double columnar TRANSPOSITION, so its plaintext must be an exact anagram of
its ciphertext. Any paraphrase fails immediately.
"""
from __future__ import annotations

import os
import re
import sys
from collections import Counter

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_BOT = os.path.dirname(_HERE)
sys.path.insert(0, _BOT)

import compute  # noqa: E402

K3_TAIL = "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"


def test_k3_plaintext_is_anagram_of_k3_ciphertext():
    """K3 is a pure transposition. This is necessary and nearly sufficient."""
    assert Counter(compute.K3_PT) == Counter(compute.K3_CT), (
        "K3_PT is not an anagram of K3_CT, so it cannot be a decryption of it"
    )


def test_k3_separator_is_before_the_question_not_after():
    """K3 reads '...FROM THE MIST X CAN YOU SEE ANYTHING Q'. The X brackets the
    question on the LEFT and Q closes it. The fabricated text had 'ANYTHINGXQ'."""
    assert compute.K3_PT.endswith(K3_TAIL), compute.K3_PT[-40:]
    assert compute.K3_PT.count("X") == 1, "K3 has exactly one X, and it is a separator"


def test_k3_has_no_fabricated_phrases():
    for bad in ("THATLAYATTHEBOTTOMOFTHESTAIRCASE", "ATFIRSTICOULDNTSEEANYTHING",
                "ANCIENTCIVILIZATION", "CANDELIGHT"):
        assert bad not in compute.K3_PT, f"fabricated phrase present: {bad}"


def test_panel_lengths():
    assert len(compute.K1_PT) == 63
    assert len(compute.K2_PT) == 369
    assert len(compute.K3_PT) == 336
    assert len(compute.K3_CT) == 336


def test_k2_deliberate_misspellings_preserved_and_corruptions_absent():
    """Sanborn's real misspellings must stay; transcription corruptions must not."""
    for good in ("UNDERGRUUND", "IQLUSION" if False else "ITWASTOTALLYINVISIBLE"):
        assert good in compute.K2_PT
    for bad in ("DOESTLANGLEY", "BURIEDDOUT", "EIGLZT"):
        assert bad not in compute.K2_PT, f"transcription corruption present: {bad}"


def test_k1_misspelling_preserved():
    assert compute.K1_PT.endswith("IQLUSION")


def test_compute_defines_k3_pt_exactly_once():
    """Three bindings is how the fabrication hid: the last one silently won."""
    src = open(os.path.join(_BOT, "compute.py"), encoding="utf-8").read()
    assert len(re.findall(r"^K3_PT = ", src, re.M)) == 1


def test_matches_self_test_panel():
    """compute.py must agree with the standing falsification gate's panels."""
    import self_test
    panels = getattr(self_test, "_PANELS", None)
    if panels is None:
        pytest.skip("self_test._PANELS not exposed")
    assert panels["k3"].known_plaintext == compute.K3_PT
    assert panels["k1"].known_plaintext == compute.K1_PT
    assert panels["k2"].known_plaintext == compute.K2_PT
