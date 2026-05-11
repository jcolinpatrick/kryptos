"""Swing K-1 keystream recovery and Bean filter wrapper.

CT97 path (M2 / M4 / M5): cribs stay at their disclosed positions.
CT73 path (M3): cribs re-project after null extraction; see derive_keystream_ct73.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Literal, Tuple

from kryptos.kernel.alphabet import AZ, KA, Alphabet
from kryptos.kernel.constants import CT, CRIB_DICT

Variant = Literal["vigenere", "beaufort", "var_beaufort"]
AlphaName = Literal["AZ", "KA"]

_ALPHA: Dict[AlphaName, Alphabet] = {"AZ": AZ, "KA": KA}


def _ks_value(ct_idx: int, pt_idx: int, variant: Variant) -> int:
    """Derive single keystream symbol from (CT idx, PT idx) under variant."""
    if variant == "vigenere":
        return (ct_idx - pt_idx) % 26
    if variant == "beaufort":
        return (ct_idx + pt_idx) % 26
    if variant == "var_beaufort":
        return (pt_idx - ct_idx) % 26
    raise ValueError(f"unknown variant {variant!r}")


def derive_keystream_ct97(
    variant: Variant,
    alphabet: AlphaName,
    null_positions: FrozenSet[int],
) -> Dict[int, int]:
    """Derive partial keystream {position: keystream_value} at crib positions in CT97 space.

    Crib positions that coincide with null positions are dropped.
    """
    alpha = _ALPHA[alphabet]
    out: Dict[int, int] = {}
    for pos, pt_char in CRIB_DICT.items():
        if pos in null_positions:
            continue
        ct_char = CT[pos]
        ct_idx = alpha.char_to_idx(ct_char)
        pt_idx = alpha.char_to_idx(pt_char)
        out[pos] = _ks_value(ct_idx, pt_idx, variant)
    return out
