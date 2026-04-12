"""W-delimiter slot model — machine-readable segmentation.

Derives the canonical slot model from kernel constants. Nothing that can be
computed is hardcoded; the W positions, segment boundaries, and free-fill
slots are all computed from CT and CRIB_DICT.

Documented assumptions (each one is a research H_i, not a fact):
  H1. The carved 97-character CT is the cipher input.
  H2. The letter W in CT acts as a delimiter (or null) — W positions are
      not part of any English word or cipher payload span.
  H3. The cribs EASTNORTHEAST (21-33) and BERLINCLOCK (63-73) are at their
      canonical 0-indexed positions.
  H4. Slots A (34-35) and B (59-62) are the ONLY free-fill slots covered
      by the cribs. Segments 0, 2, 3, 5 are unconstrained and NOT tested.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_WORDS


@dataclass(frozen=True)
class WDelimiterSlot:
    """A W-delimited fill slot in K4 under the W-as-delimiter hypothesis."""

    slot_id: str
    positions: Tuple[int, ...]
    length: int
    ct_at_slot: str
    context_before: Optional[str]
    context_after: Optional[str]
    grammatical_role: str


@dataclass(frozen=True)
class WDelimiterModel:
    """The full W-delimiter segmentation hypothesis for K4."""

    w_positions: Tuple[int, ...]
    segments: Tuple[Tuple[int, int], ...]  # inclusive (start, end)
    constrained_slots: Tuple[WDelimiterSlot, ...]
    unconstrained_segment_positions: Tuple[Tuple[int, int], ...]
    notes: str = ""

    # Explicit hypothesis register. Do not remove.
    assumptions: Tuple[str, ...] = (
        "H1: carved 97-char CT is the cipher input",
        "H2: W in CT is a delimiter or null, not a payload letter",
        "H3: cribs at canonical 0-indexed positions",
        "H4: only slots A (34-35) and B (59-62) are testable under cribs; segments 0/2/3/5 are unconstrained",
    )


def _derive_w_positions(ct: str) -> Tuple[int, ...]:
    return tuple(i for i, ch in enumerate(ct) if ch == "W")


def _derive_segments(w_positions: Tuple[int, ...], ct_len: int) -> Tuple[Tuple[int, int], ...]:
    """Segments between W markers (W positions themselves are removed).

    Returns inclusive (start, end) ranges for each run between W's (or
    between start/end of CT and W).
    """
    segs = []
    prev = 0
    for wp in w_positions:
        if wp > prev:
            segs.append((prev, wp - 1))
        prev = wp + 1
    if prev <= ct_len - 1:
        segs.append((prev, ct_len - 1))
    return tuple(segs)


def canonical_w_delimiter_model() -> WDelimiterModel:
    """Return the canonical slot model derived from CT and CRIB_DICT."""
    w_positions = _derive_w_positions(CT)
    segments = _derive_segments(w_positions, CT_LEN)
    crib_positions = set(CRIB_DICT.keys())

    # Identify slot A: inside the segment containing EASTNORTHEAST (21-33),
    # the positions AFTER the crib but still within the segment.
    # Identify slot B: inside the segment containing BERLINCLOCK (63-73),
    # the positions BEFORE the crib but still within the segment.
    east_start, east_end = 21, 33  # EASTNORTHEAST
    berlin_start, berlin_end = 63, 73  # BERLINCLOCK

    slot_a_positions: list[int] = []
    slot_b_positions: list[int] = []
    unconstrained: list[Tuple[int, int]] = []

    for (s, e) in segments:
        if s <= east_start and e >= east_end:
            # segment contains EASTNORTHEAST
            free = [p for p in range(s, e + 1) if p not in crib_positions]
            # "Slot A" = free positions AFTER the crib
            after = [p for p in free if p > east_end]
            slot_a_positions.extend(after)
            # any free positions BEFORE the crib are separately unconstrained
            before = [p for p in free if p < east_start]
            if before:
                unconstrained.append((before[0], before[-1]))
        elif s <= berlin_start and e >= berlin_end:
            # segment contains BERLINCLOCK
            free = [p for p in range(s, e + 1) if p not in crib_positions]
            before = [p for p in free if p < berlin_start]
            slot_b_positions.extend(before)
            after = [p for p in free if p > berlin_end]
            if after:
                unconstrained.append((after[0], after[-1]))
        else:
            unconstrained.append((s, e))

    slot_a = WDelimiterSlot(
        slot_id="A",
        positions=tuple(slot_a_positions),
        length=len(slot_a_positions),
        ct_at_slot="".join(CT[p] for p in slot_a_positions),
        context_before="EASTNORTHEAST",
        context_after=None,  # followed by W delimiter
        grammatical_role="follows direction phrase, precedes W delimiter",
    )
    slot_b = WDelimiterSlot(
        slot_id="B",
        positions=tuple(slot_b_positions),
        length=len(slot_b_positions),
        ct_at_slot="".join(CT[p] for p in slot_b_positions),
        context_before=None,  # preceded by W delimiter
        context_after="BERLINCLOCK",
        grammatical_role="follows W delimiter, precedes location name",
    )

    return WDelimiterModel(
        w_positions=w_positions,
        segments=segments,
        constrained_slots=(slot_a, slot_b),
        unconstrained_segment_positions=tuple(unconstrained),
        notes=(
            "Slot A and Slot B are the only fillable positions covered by cribs. "
            "Segments 0/2/3/5 are unconstrained and NOT tested by this null."
        ),
    )
