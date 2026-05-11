"""Swing K-1 keystream recovery and Bean filter wrapper.

CT97 path (M2 / M4 / M5): cribs stay at their disclosed positions.
CT73 path (M3): cribs re-project after null extraction; see derive_keystream_ct73.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Literal, Tuple

from kryptos.kernel.alphabet import AZ, KA, Alphabet
from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR
from kryptos.kernel.constraints.bean import verify_bean_from_implied

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


def project_crib_positions_ct73(null_positions: FrozenSet[int]) -> Dict[int, int]:
    """Map each crib CT97 position to its CT73 index after null extraction.

    Crib positions that coincide with nulls are NOT in the output (they are dropped).
    """
    sorted_nulls = sorted(null_positions)
    projection: Dict[int, int] = {}
    for ct97_pos in sorted(CRIB_DICT.keys()):
        if ct97_pos in null_positions:
            continue
        # Count nulls strictly less than ct97_pos to compute the shift.
        n_lt = sum(1 for n in sorted_nulls if n < ct97_pos)
        projection[ct97_pos] = ct97_pos - n_lt
    return projection


def derive_keystream_ct73(
    variant: Variant,
    alphabet: AlphaName,
    null_positions: FrozenSet[int],
) -> Dict[int, int]:
    """Derive 24-position keystream in CT73 space (M3, null-skip semantics).

    The dict keys are CT73 indices. Crib positions that coincide with nulls are dropped.
    """
    alpha = _ALPHA[alphabet]
    projection = project_crib_positions_ct73(null_positions)
    out: Dict[int, int] = {}
    # CT73 is CT97 with null positions removed
    ct97_positions_kept = sorted(p for p in range(len(CT)) if p not in null_positions)
    ct73 = "".join(CT[p] for p in ct97_positions_kept)
    for ct97_pos, ct73_idx in projection.items():
        pt_char = CRIB_DICT[ct97_pos]
        ct_char = ct73[ct73_idx]
        ct_idx = alpha.char_to_idx(ct_char)
        pt_idx = alpha.char_to_idx(pt_char)
        out[ct73_idx] = _ks_value(ct_idx, pt_idx, variant)
    return out


@dataclass(frozen=True)
class BeanVerdict:
    passed: bool
    eq_checked: int
    ineq_checked: int
    linear_checked: int
    failures: Tuple[str, ...]


def _count_checkable(constraints, available_positions):
    """Count how many constraints have ALL required positions in available_positions."""
    count = 0
    for c in constraints:
        if hasattr(c, "positions"):
            positions_required = set(c.positions)
        elif isinstance(c, tuple):
            # Fallback for tuple-shaped constraints; pull integer fields.
            positions_required = {x for x in c if isinstance(x, int) and 0 <= x < 97}
        else:
            positions_required = set()
        if positions_required.issubset(available_positions):
            count += 1
    return count


def bean_filter(implied: Dict[int, int]) -> BeanVerdict:
    """Wrap verify_bean_from_implied with per-constraint accounting.

    The kernel function returns bool (skipping constraints with missing positions).
    This wrapper additionally counts how many constraints were checkable so the
    artifact can record per-constraint detail.
    """
    passed = verify_bean_from_implied(implied)
    available = set(implied.keys())
    eq_checked = (
        _count_checkable(BEAN_EQ, available)
        if isinstance(BEAN_EQ, (list, tuple))
        else (1 if 27 in available and 65 in available else 0)
    )
    ineq_checked = (
        _count_checkable(BEAN_INEQ, available)
        if isinstance(BEAN_INEQ, (list, tuple))
        else 0
    )
    linear_checked = (
        _count_checkable(BEAN_LINEAR, available)
        if isinstance(BEAN_LINEAR, (list, tuple))
        else 0
    )
    return BeanVerdict(
        passed=passed,
        eq_checked=eq_checked,
        ineq_checked=ineq_checked,
        linear_checked=linear_checked,
        failures=tuple(),  # populated by escalation if/when needed
    )
