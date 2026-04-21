"""Cardano-grille transform — permutation-only interpretation.

Added in framework maturation R3-0.5-2 (2026-04-21). A Cardano grille
is a physical mask with holes; held over a text, it selects positions
in a specific read order. Mathematically, under the permutation-only
interpretation (brief §3.2), the mask is a permutation of the full-text
positions and the operation is a gather:

    output[i] = input[mask_order[i]]

This is identical in shape to ``apply_perm(text, perm)`` in
``kryptos.kernel.transforms.transposition``. This module exists so the
kernel has a named surface for grille semantics, with mask validation
that specifically targets the grille use case — but the heavy lifting
is done by the existing transposition primitive.

Scope of this module:
    - ``apply_grille_permutation(text, mask_order)`` — gather in mask order
    - ``validate_grille_mask(mask_order, expected_len)`` — explicit mask validator

Out of scope (deferred to a later brief):
    - Turning grilles (4-rotation variant where mask rotates between reads)
    - Partial grilles (len(mask) < expected_len; the rest unread or padded)
    - Mask discovery from anomaly hints
"""
from __future__ import annotations

from typing import Iterable, List, Sequence

from kryptos.kernel.transforms.transposition import apply_perm


def validate_grille_mask(
    mask_order: Sequence[int],
    expected_len: int,
) -> List[str]:
    """Return a list of validation errors (empty list = valid).

    A grille mask under the permutation-only interpretation must:
      1. Be a finite list of non-negative integers.
      2. Have exactly ``expected_len`` entries.
      3. Contain no duplicate positions.
      4. Cover every position in ``range(expected_len)`` exactly once
         (i.e. be a permutation of that range).

    Rule 4 follows from rules 2+3: a list of ``expected_len`` distinct
    non-negative integers all < ``expected_len`` is necessarily a
    permutation of ``range(expected_len)``. We assert it explicitly
    anyway as a belt-and-braces check against off-by-one surprises.
    """
    errors: List[str] = []
    if not hasattr(mask_order, "__iter__"):
        return [
            f"mask_order must be iterable; got {type(mask_order).__name__}"
        ]
    mask_list = list(mask_order)
    if not all(isinstance(i, int) and not isinstance(i, bool)
               for i in mask_list):
        errors.append("mask_order entries must be non-bool ints")
    if errors:
        # Can't safely continue numerical checks with non-int entries.
        return errors
    if len(mask_list) != expected_len:
        errors.append(
            f"mask_order length {len(mask_list)} != expected_len {expected_len}"
        )
    if any(i < 0 for i in mask_list):
        errors.append("mask_order contains negative positions")
    if any(i >= expected_len for i in mask_list):
        errors.append(
            f"mask_order contains out-of-range positions "
            f"(valid: 0..{expected_len - 1})"
        )
    if len(set(mask_list)) != len(mask_list):
        errors.append("mask_order contains duplicates")
    # Belt and braces: confirm permutation coverage when the length and
    # range checks have passed.
    if not errors and set(mask_list) != set(range(expected_len)):
        errors.append(
            "mask_order is not a permutation of range(expected_len)"
        )
    return errors


def apply_grille_permutation(
    text: str,
    mask_order: Sequence[int],
) -> str:
    """Apply a grille mask: return ``text`` read in ``mask_order``.

    Semantics: ``output[i] = text[mask_order[i]]``. Bijective under
    the permutation-only interpretation — the inverse mask reconstructs
    the original text.

    No validation here (callers should call ``validate_grille_mask``
    first if the mask came from an untrusted source). This keeps the
    hot path fast; the kernel's other transform primitives follow the
    same "validate once, apply many" convention.
    """
    return apply_perm(text, list(mask_order))


__all__ = [
    "apply_grille_permutation",
    "validate_grille_mask",
]
