"""Swing K-1 4-channel structural-identification suite."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from kryptos.kernel.alphabet import AZ


def _str_to_idx_seq(s: str) -> List[int]:
    return [AZ.char_to_idx(c) for c in s if c.isalpha()]


def _text_to_idx_seq(text: str) -> List[int]:
    return [AZ.char_to_idx(c) for c in text if c.isalpha()]


@dataclass(frozen=True)
class S1Hit:
    source_id: str
    offset: int
    match_len: int


def scan_source_text(
    keystream_idx: Sequence[int],
    corpus_entries: Iterable,
    threshold_len: int = 24,
) -> Optional[S1Hit]:
    """Slide-scan the keystream against each corpus entry's text. Returns first hit at threshold_len."""
    ks_len = len(keystream_idx)
    if ks_len < threshold_len:
        return None
    target = list(keystream_idx[:threshold_len])
    for entry in corpus_entries:
        text_idx = _text_to_idx_seq(entry.text())
        if len(text_idx) < threshold_len:
            continue
        for off in range(0, len(text_idx) - threshold_len + 1):
            if text_idx[off:off + threshold_len] == target:
                return S1Hit(source_id=entry.id, offset=off, match_len=threshold_len)
    return None
