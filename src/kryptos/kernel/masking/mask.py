"""Null-mask representation and pure extraction / remap helpers.

A NullMask is a frozenset of carved-CT positions that are NULLS (filler, not
cipher output). Extracting the non-null positions yields the implied
ciphertext CT' of length 97-|mask|; its decryption is the plaintext, so the
plaintext length is variable and equal to len(CT'). All functions are pure and
take CT / crib_dict explicitly -- no global state, no env overrides.
"""
from __future__ import annotations

from typing import FrozenSet, Mapping

from kryptos.kernel.constants import CRIB_POSITIONS, CT_LEN

NullMask = FrozenSet[int]


def validate_mask(
    mask: NullMask,
    ct_len: int = CT_LEN,
    crib_positions: FrozenSet[int] = CRIB_POSITIONS,
    allow_crib_nulls: bool = False,
) -> None:
    """Raise ValueError if the mask is malformed.

    Default invariant (overridable): crib positions are NOT nulls -- cribs are
    CT-position-anchored disclosures (feedback_pt_length_open_question). This is
    a declared assumption, not proven law; relax only with explicit provenance.
    """
    for p in mask:
        if p < 0 or p >= ct_len:
            raise ValueError(f"mask position {p} out of range [0,{ct_len})")
    if not allow_crib_nulls:
        hit = sorted(mask & crib_positions)
        if hit:
            raise ValueError(
                f"mask intersects crib positions {hit}; cribs are not nulls by "
                f"default (pass allow_crib_nulls=True with provenance to relax)"
            )


def extract_ct(ct: str, mask: NullMask) -> str:
    """Return ct with all null positions removed (length len(ct)-|mask|)."""
    return "".join(ch for i, ch in enumerate(ct) if i not in mask)


def remap_position(pos: int, mask: NullMask) -> int:
    """Map a carved (non-null) position to its index in the extracted CT'."""
    return pos - sum(1 for m in mask if m < pos)


def remap_crib_dict(crib_dict: Mapping[int, str], mask: NullMask) -> dict[int, str]:
    """Relocate cribs from carved coordinates to extracted-CT' coordinates."""
    return {remap_position(p, mask): ch for p, ch in crib_dict.items()}
