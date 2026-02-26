"""Position-free crib scoring — searches for cribs anywhere in candidate text.

Unlike the anchored scorer (crib_score.py) which checks fixed positions 21-33
and 63-73, this module searches for EASTNORTHEAST and BERLINCLOCK as substrings
at any offset. This addresses the fundamental audit concern: if crib positions
are wrong (due to transposition, nulls, insertions, or non-linear reading order),
the anchored scorer will reject true positives as noise.

Scoring philosophy:
- Content first, indices second
- Both cribs present anywhere = strong signal
- Gap and ordering between cribs = secondary diagnostic
- Compatible with any transposition, selection, or geometric method
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple


# The crib strings themselves are ground truth (PUBLIC FACT).
# Their positions in the final plaintext stream are the assumption under test.
CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"

# All substrings of length >= MIN_FRAG to also search for partial matches
MIN_FRAG = 5


@dataclass
class FreeCribMatch:
    """A single crib occurrence found in candidate text."""
    crib: str           # which crib word
    offset: int         # start position in candidate
    length: int         # always len(crib)

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass
class FreeCribResult:
    """Complete position-free crib analysis of a candidate."""
    # Full crib matches
    ene_offsets: List[int]      # all positions where EASTNORTHEAST starts
    bc_offsets: List[int]       # all positions where BERLINCLOCK starts

    # Best pairing (if both present)
    best_ene_offset: Optional[int] = None
    best_bc_offset: Optional[int] = None
    gap: Optional[int] = None   # distance between end of ENE and start of BC

    # Partial matches (fragments >= MIN_FRAG)
    ene_fragments: List[Tuple[str, int]] = None  # (fragment, offset)
    bc_fragments: List[Tuple[str, int]] = None

    # Summary scores
    ene_found: bool = False
    bc_found: bool = False
    both_found: bool = False
    canonical_positions: bool = False  # True if found at standard 21, 63

    @property
    def score(self) -> int:
        """Simple numeric score: 0=nothing, 13=ENE only, 11=BC only, 24=both."""
        s = 0
        if self.ene_found:
            s += len(CRIB_ENE)
        if self.bc_found:
            s += len(CRIB_BC)
        return s

    @property
    def summary(self) -> str:
        parts = []
        if self.ene_found:
            parts.append(f"ENE@{self.ene_offsets}")
        else:
            nf = len(self.ene_fragments) if self.ene_fragments else 0
            parts.append(f"ENE=no({nf} frags)")
        if self.bc_found:
            parts.append(f"BC@{self.bc_offsets}")
        else:
            nf = len(self.bc_fragments) if self.bc_fragments else 0
            parts.append(f"BC=no({nf} frags)")
        if self.both_found and self.gap is not None:
            parts.append(f"gap={self.gap}")
        if self.canonical_positions:
            parts.append("CANONICAL")
        return " | ".join(parts)


def find_all_occurrences(text: str, pattern: str) -> List[int]:
    """Find all starting positions of pattern in text (overlapping allowed)."""
    positions = []
    start = 0
    while True:
        idx = text.find(pattern, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions


def find_fragments(text: str, crib: str, min_len: int = MIN_FRAG) -> List[Tuple[str, int]]:
    """Find all substrings of crib (length >= min_len) that appear in text.

    Returns list of (fragment, offset) sorted by fragment length descending.
    Only returns fragments that are NOT part of a full crib match.
    """
    full_matches = set()
    for pos in find_all_occurrences(text, crib):
        for i in range(len(crib)):
            full_matches.add(pos + i)

    results = []
    seen = set()  # avoid reporting substrings of longer fragments
    for flen in range(len(crib) - 1, min_len - 1, -1):
        for start_in_crib in range(len(crib) - flen + 1):
            frag = crib[start_in_crib:start_in_crib + flen]
            if frag in seen:
                continue
            for pos in find_all_occurrences(text, frag):
                # Skip if this is part of a full match
                if all((pos + i) in full_matches for i in range(flen)):
                    continue
                results.append((frag, pos))
                seen.add(frag)
                break  # one occurrence per fragment is enough for diagnostics
    return results


def score_free(text: str, find_fragments_flag: bool = True) -> FreeCribResult:
    """Position-free crib scoring.

    Searches for EASTNORTHEAST and BERLINCLOCK anywhere in the candidate text.
    Reports all occurrences, best pairing, gap, and partial fragment matches.

    Args:
        text: Candidate plaintext (uppercase A-Z expected)
        find_fragments_flag: If True, also search for partial crib fragments

    Returns:
        FreeCribResult with full diagnostic information
    """
    text = text.upper()

    ene_offsets = find_all_occurrences(text, CRIB_ENE)
    bc_offsets = find_all_occurrences(text, CRIB_BC)

    ene_found = len(ene_offsets) > 0
    bc_found = len(bc_offsets) > 0
    both_found = ene_found and bc_found

    # Find best pairing: ENE before BC, closest gap
    best_ene = None
    best_bc = None
    best_gap = None

    if both_found:
        # Try ENE before BC first (expected order)
        for ene_pos in ene_offsets:
            ene_end = ene_pos + len(CRIB_ENE)
            for bc_pos in bc_offsets:
                if bc_pos >= ene_end:  # non-overlapping, ENE first
                    g = bc_pos - ene_end
                    if best_gap is None or g < best_gap:
                        best_ene = ene_pos
                        best_bc = bc_pos
                        best_gap = g

        # If no ENE-before-BC pairing, try any non-overlapping
        if best_gap is None:
            for ene_pos in ene_offsets:
                for bc_pos in bc_offsets:
                    ene_end = ene_pos + len(CRIB_ENE)
                    bc_end = bc_pos + len(CRIB_BC)
                    if ene_end <= bc_pos or bc_end <= ene_pos:
                        g = bc_pos - (ene_pos + len(CRIB_ENE))
                        if best_gap is None or abs(g) < abs(best_gap):
                            best_ene = ene_pos
                            best_bc = bc_pos
                            best_gap = g

    # Check canonical positions
    canonical = (21 in ene_offsets and 63 in bc_offsets)

    # Fragment search
    ene_frags = None
    bc_frags = None
    if find_fragments_flag:
        ene_frags = find_fragments(text, CRIB_ENE) if not ene_found else []
        bc_frags = find_fragments(text, CRIB_BC) if not bc_found else []

    return FreeCribResult(
        ene_offsets=ene_offsets,
        bc_offsets=bc_offsets,
        best_ene_offset=best_ene,
        best_bc_offset=best_bc,
        gap=best_gap,
        ene_fragments=ene_frags,
        bc_fragments=bc_frags,
        ene_found=ene_found,
        bc_found=bc_found,
        both_found=both_found,
        canonical_positions=canonical,
    )


def score_free_fast(text: str) -> int:
    """Fast position-free score: 0/11/13/24 based on crib substring presence.

    Use as a prefilter when you don't need diagnostics.
    """
    s = 0
    if CRIB_ENE in text.upper():
        s += len(CRIB_ENE)
    if CRIB_BC in text.upper():
        s += len(CRIB_BC)
    return s
