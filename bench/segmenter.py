"""Ciphertext segmentation detector for mixed/adversarial inputs.

Slides a window across the ciphertext computing per-window IOC and
chi-square distance from English letter frequencies.  When a window's
statistics deviate sharply from its neighbours, a segment boundary is
placed.  Known alphabet runs (A-Z sequential, QWERTY rows) are flagged
as ``padding`` segments.

Usage::

    from bench.segmenter import segment_ciphertext

    result = segment_ciphertext("ZICVTWQNG...ABCDEFGHIJKLMNOP...QRSTUVWXYZ...")
    for seg in result.segments:
        print(seg.start, seg.end, seg.label, seg.ioc)
    print(result.is_mixed)
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── English frequency table ─────────────────────────────────────────────

ENGLISH_FREQ: Dict[str, float] = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253,
    "E": 0.12702, "F": 0.02228, "G": 0.02015, "H": 0.06094,
    "I": 0.06966, "J": 0.00153, "K": 0.00772, "L": 0.04025,
    "M": 0.02406, "N": 0.06749, "O": 0.07507, "P": 0.01929,
    "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150,
    "Y": 0.01974, "Z": 0.00074,
}

# ── Known alphabet patterns ─────────────────────────────────────────────

_AZ_FORWARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_AZ_REVERSE = _AZ_FORWARD[::-1]
_QWERTY_ROWS = [
    "QWERTYUIOP",
    "ASDFGHJKL",
    "ZXCVBNM",
]
_QWERTY_FULL = "QWERTYUIOPASDFGHJKLZXCVBNM"

# Minimum run length to flag as a known alphabet
_MIN_ALPHABET_RUN: int = 10

# ── Tunable thresholds ───────────────────────────────────────────────────

# Default sliding-window size
DEFAULT_WINDOW: int = 20

# IOC boundary: a window with IOC this far below the text average triggers
# a potential boundary.  Also used for absolute anomaly detection.
IOC_ALPHABET_CEILING: float = 0.020  # sequential alphabets have IOC=0.0
IOC_ENGLISH_FLOOR: float = 0.050    # typical English > 0.05
IOC_DEVIATION_FACTOR: float = 0.50  # window IOC < factor * text_avg → anomaly

# Chi-square threshold for "looks like English"
CHI2_ANOMALY: float = 0.015  # per-letter chi2 above this → not English-like

# Minimum segment length worth reporting
MIN_SEGMENT_LEN: int = 8

# ── Statistics ───────────────────────────────────────────────────────────


def _ioc(text: str) -> float:
    """Index of coincidence for A-Z text."""
    freq = Counter(text)
    n = sum(freq.values())
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def _chi2_english(text: str) -> float:
    """Per-letter chi-square distance from English frequencies.

    Returns sum((observed_frac - expected_frac)^2 / expected_frac) / 26.
    Lower is more English-like.  Typical English ≈ 0.002–0.005.
    """
    n = len(text)
    if n == 0:
        return 1.0
    freq = Counter(text)
    total = 0.0
    for ch, expected in ENGLISH_FREQ.items():
        observed = freq.get(ch, 0) / n
        total += (observed - expected) ** 2 / expected
    return total / 26


# ── Known-alphabet run detection ─────────────────────────────────────────


def _find_alphabet_runs(text: str) -> List[Tuple[int, int, str]]:
    """Find runs that match known alphabet patterns.

    Returns list of (start, end, pattern_name) tuples.
    ``end`` is exclusive.
    """
    runs: list[tuple[int, int, str]] = []

    patterns: list[tuple[str, str]] = [
        (_AZ_FORWARD, "az_forward"),
        (_AZ_REVERSE, "az_reverse"),
        (_QWERTY_FULL, "qwerty"),
    ]
    for row_i, row in enumerate(_QWERTY_ROWS):
        patterns.append((row, f"qwerty_row{row_i + 1}"))

    for pattern, name in patterns:
        plen = len(pattern)
        # Search for substrings of the pattern of length >= _MIN_ALPHABET_RUN
        for start in range(len(text)):
            remaining = len(text) - start
            if remaining < _MIN_ALPHABET_RUN:
                break
            # Try matching a substring of the pattern starting from any offset
            for pat_offset in range(plen):
                match_len = 0
                while (match_len < remaining
                       and pat_offset + match_len < plen
                       and text[start + match_len] == pattern[pat_offset + match_len]):
                    match_len += 1
                if match_len >= _MIN_ALPHABET_RUN:
                    end = start + match_len
                    # Check we don't already have a run covering this
                    overlaps = False
                    for rs, re_, _ in runs:
                        if start < re_ and end > rs:
                            # Keep the longer one
                            overlaps = True
                            break
                    if not overlaps:
                        runs.append((start, end, name))
                    break  # found a pattern match at this start, move on

    # Sort by start position and deduplicate overlaps (keep longest)
    runs.sort(key=lambda r: (r[0], -(r[1] - r[0])))
    merged: list[tuple[int, int, str]] = []
    for run in runs:
        if merged and run[0] < merged[-1][1]:
            # Overlapping — keep the longer one
            if run[1] - run[0] > merged[-1][1] - merged[-1][0]:
                merged[-1] = run
        else:
            merged.append(run)
    return merged


# ── Segment dataclass ────────────────────────────────────────────────────


@dataclass
class Segment:
    """One segment of a ciphertext."""

    start: int              # inclusive, 0-indexed into the ciphertext
    end: int                # exclusive
    label: str              # "cipher" | "padding" | "anomaly"
    ioc: float = 0.0        # IOC for this segment
    chi2: float = 0.0       # chi-square vs English
    notes: str = ""         # e.g. "az_forward", "qwerty"
    best_family: str = ""   # populated downstream if segment is solved
    validated: bool = False  # populated downstream

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def text(self) -> str:
        """Not stored — must be recovered from the source ciphertext."""
        return ""  # placeholder; actual text passed separately

    def to_dict(self) -> Dict:
        d: Dict = {
            "start": self.start,
            "end": self.end,
            "label": self.label,
            "ioc": round(self.ioc, 6),
            "chi2": round(self.chi2, 6),
        }
        if self.notes:
            d["notes"] = self.notes
        if self.best_family:
            d["best_family"] = self.best_family
        d["validated"] = self.validated
        return d

    @classmethod
    def from_dict(cls, data: Dict) -> Segment:
        return cls(
            start=data["start"],
            end=data["end"],
            label=data["label"],
            ioc=data.get("ioc", 0.0),
            chi2=data.get("chi2", 0.0),
            notes=data.get("notes", ""),
            best_family=data.get("best_family", ""),
            validated=data.get("validated", False),
        )


@dataclass
class SegmentationResult:
    """Full segmentation analysis of a ciphertext."""

    is_mixed: bool = False
    segments: List[Segment] = field(default_factory=list)
    global_ioc: float = 0.0
    window_size: int = DEFAULT_WINDOW

    def to_dict(self) -> Dict:
        return {
            "is_mixed": self.is_mixed,
            "global_ioc": round(self.global_ioc, 6),
            "window_size": self.window_size,
            "n_segments": len(self.segments),
            "segments": [s.to_dict() for s in self.segments],
        }

    @classmethod
    def from_dict(cls, data: Dict) -> SegmentationResult:
        return cls(
            is_mixed=data.get("is_mixed", False),
            segments=[Segment.from_dict(s) for s in data.get("segments", [])],
            global_ioc=data.get("global_ioc", 0.0),
            window_size=data.get("window_size", DEFAULT_WINDOW),
        )


# ── Sliding-window analysis ─────────────────────────────────────────────


def _sliding_window_stats(
    text: str,
    window: int = DEFAULT_WINDOW,
) -> List[Tuple[int, float, float]]:
    """Compute (start_pos, ioc, chi2) for each window position.

    Windows are non-overlapping for efficiency.  Each window is
    ``window`` characters wide, positioned at multiples of ``window // 2``
    (50% overlap) for better boundary detection.
    """
    n = len(text)
    if n < window:
        return [(0, _ioc(text), _chi2_english(text))]

    step = max(window // 2, 1)
    stats: list[tuple[int, float, float]] = []
    pos = 0
    while pos + window <= n:
        w = text[pos:pos + window]
        stats.append((pos, _ioc(w), _chi2_english(w)))
        pos += step
    # Tail window if text doesn't divide evenly
    if pos < n and n - pos >= MIN_SEGMENT_LEN:
        tail = text[pos:]
        stats.append((pos, _ioc(tail), _chi2_english(tail)))

    return stats


def _detect_boundaries(
    text: str,
    window_stats: List[Tuple[int, float, float]],
    alphabet_runs: List[Tuple[int, int, str]],
    global_ioc: float,
) -> List[int]:
    """Identify boundary positions where segment character changes.

    A boundary is placed when:
    1. A window's IOC deviates strongly from the global average.
    2. A window straddles an alphabet run boundary.
    """
    boundaries: set[int] = set()

    # Boundaries from alphabet runs
    for start, end, _ in alphabet_runs:
        boundaries.add(start)
        boundaries.add(end)

    # Boundaries from IOC deviation
    if len(window_stats) >= 2:
        ioc_threshold = max(global_ioc * IOC_DEVIATION_FACTOR, IOC_ALPHABET_CEILING)
        for i in range(1, len(window_stats)):
            prev_ioc = window_stats[i - 1][1]
            curr_ioc = window_stats[i][1]
            # Sharp IOC drop or rise
            if ((prev_ioc > ioc_threshold and curr_ioc <= ioc_threshold) or
                    (curr_ioc > ioc_threshold and prev_ioc <= ioc_threshold)):
                boundaries.add(window_stats[i][0])

    # Always include start and end
    boundaries.add(0)
    boundaries.add(len(text))

    return sorted(boundaries)


# ── Public API ───────────────────────────────────────────────────────────


def segment_ciphertext(
    ciphertext: str,
    *,
    window: int = DEFAULT_WINDOW,
) -> SegmentationResult:
    """Analyze a ciphertext for mixed structure.

    Args:
        ciphertext: A-Z ciphertext string.
        window: Sliding window size (default 20).

    Returns:
        SegmentationResult with segments and is_mixed flag.
    """
    text = re.sub(r"[^A-Z]", "", ciphertext.upper())
    n = len(text)

    if n == 0:
        return SegmentationResult(window_size=window)

    global_ioc = _ioc(text)

    # Short texts → single segment, no windowing
    if n < window + MIN_SEGMENT_LEN:
        label = "cipher"
        notes = ""
        # Still check for alphabet runs in the whole text
        runs = _find_alphabet_runs(text)
        if runs and runs[0][1] - runs[0][0] >= n * 0.8:
            label = "padding"
            notes = runs[0][2]
        seg = Segment(
            start=0, end=n, label=label,
            ioc=global_ioc, chi2=_chi2_english(text),
            notes=notes,
        )
        return SegmentationResult(
            is_mixed=(label != "cipher"),
            segments=[seg],
            global_ioc=global_ioc,
            window_size=window,
        )

    # Full analysis
    alphabet_runs = _find_alphabet_runs(text)
    window_stats = _sliding_window_stats(text, window)
    boundaries = _detect_boundaries(text, window_stats, alphabet_runs, global_ioc)

    # Build segments from boundaries
    raw_segments: list[Segment] = []
    for i in range(len(boundaries) - 1):
        s, e = boundaries[i], boundaries[i + 1]
        if e - s < 1:
            continue
        seg_text = text[s:e]
        seg_ioc = _ioc(seg_text)
        seg_chi2 = _chi2_english(seg_text)

        # Classify this segment
        label = "cipher"
        notes = ""

        # Check if it overlaps an alphabet run
        for rs, re_, rname in alphabet_runs:
            overlap = min(e, re_) - max(s, rs)
            if overlap > 0 and overlap >= (e - s) * 0.7:
                label = "padding"
                notes = rname
                break

        # Check for anomalous IOC (very low = possible flat-distribution padding)
        if label == "cipher" and seg_ioc < IOC_ALPHABET_CEILING and e - s >= MIN_SEGMENT_LEN:
            label = "anomaly"
            notes = f"ioc={seg_ioc:.4f}"

        raw_segments.append(Segment(
            start=s, end=e, label=label,
            ioc=seg_ioc, chi2=seg_chi2, notes=notes,
        ))

    # Merge adjacent segments with the same label (avoid fragmentation)
    segments: list[Segment] = []
    for seg in raw_segments:
        if (segments
                and segments[-1].label == seg.label
                and segments[-1].end == seg.start
                and segments[-1].notes == seg.notes):
            # Merge: extend previous segment
            merged_text = text[segments[-1].start:seg.end]
            segments[-1] = Segment(
                start=segments[-1].start,
                end=seg.end,
                label=seg.label,
                ioc=_ioc(merged_text),
                chi2=_chi2_english(merged_text),
                notes=seg.notes,
            )
        else:
            segments.append(seg)

    # Drop tiny segments (< MIN_SEGMENT_LEN) by merging into neighbours
    final: list[Segment] = []
    for seg in segments:
        if seg.length < MIN_SEGMENT_LEN and final:
            # Merge into previous
            prev = final[-1]
            merged_text = text[prev.start:seg.end]
            final[-1] = Segment(
                start=prev.start,
                end=seg.end,
                label=prev.label,
                ioc=_ioc(merged_text),
                chi2=_chi2_english(merged_text),
                notes=prev.notes,
            )
        else:
            final.append(seg)

    # Determine if the text is mixed
    labels = set(s.label for s in final)
    is_mixed = len(labels) > 1 or "padding" in labels or "anomaly" in labels

    return SegmentationResult(
        is_mixed=is_mixed,
        segments=final,
        global_ioc=global_ioc,
        window_size=window,
    )
