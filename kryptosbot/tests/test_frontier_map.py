from kryptosbot.frontier_map import (
    FrontierCell, alignment_models_for_row,
)
from kryptos.alignment_models import DIRECT_CARVING_MODELS


def test_default_row_is_direct_carving():
    assert alignment_models_for_row("vigenere", "periodic vigenere sweep", []) \
        == DIRECT_CARVING_MODELS


def test_null_mask_hint_routes_to_arbitrary_null_mask():
    got = alignment_models_for_row("key_tape", "finite tape with null_mask insertion", [])
    assert got == frozenset({"arbitrary_null_mask"})


def test_non_direct_hint_routes_to_non_direct_alignment():
    got = alignment_models_for_row("transposition", "outer transposition reorders CT then decrypt", ["non_direct"])
    assert got == frozenset({"non_direct_alignment"})


def test_cell_is_frozen_dataclass():
    c = FrontierCell("vigenere", "direct_ct_pt", "open", 0, 0)
    assert c.family == "vigenere" and c.status == "open"
