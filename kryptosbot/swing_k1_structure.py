"""Swing K-1 4-channel structural-identification suite."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from kryptos.kernel.alphabet import AZ


def _str_to_idx_seq(s: str) -> List[int]:
    return [AZ.char_to_idx(c) for c in s if c.isalpha()]


def _text_to_idx_seq(text: str) -> List[int]:
    return [AZ.char_to_idx(c) for c in text if c.isalpha()]


def _text_to_idx_bytes(text: str) -> bytes:
    """Pack a text's A..Z letter indices (0..25) into a contiguous bytes buffer.

    Non-ASCII letters (e.g. accented characters that survive unicode-aware
    .isalpha() filtering upstream) are skipped — they cannot encode a 0..25
    keystream byte and must not crash the scan.
    """
    return bytes(ord(c) - 65 for c in text if "A" <= c <= "Z")


@dataclass(frozen=True)
class S1Hit:
    source_id: str
    offset: int
    match_len: int


@dataclass(frozen=True)
class PreparedCorpusEntry:
    """Per-entry indexed representation cached once for fast substring scan."""
    id: str
    idx_bytes: bytes


def prepare_corpus(corpus_entries: Iterable) -> Tuple[PreparedCorpusEntry, ...]:
    """Precompute a 0..25 byte representation for every corpus entry.

    Call this ONCE per corpus and reuse the result across every keystream scan.
    Each PreparedCorpusEntry holds the entry's id plus its text encoded as a
    bytes buffer where every position carries the letter's 0..25 index.
    """
    return tuple(
        PreparedCorpusEntry(id=entry.id, idx_bytes=_text_to_idx_bytes(entry.text()))
        for entry in corpus_entries
    )


def scan_source_text(
    keystream_idx: Sequence[int],
    corpus_entries: Iterable,
    threshold_len: int = 24,
) -> Optional[S1Hit]:
    """Slide-scan the keystream against each corpus entry's text. Returns first hit at threshold_len.

    (SLOW; for tests / small corpora; use scan_source_text_prepared for production runs.)
    """
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


def scan_source_text_prepared(
    keystream_idx: Sequence[int],
    prepared_entries: Sequence[PreparedCorpusEntry],
    threshold_len: int = 24,
) -> Optional[S1Hit]:
    """Fast variant of scan_source_text using precomputed bytes buffers and bytes.find.

    The corpus is prepared ONCE via prepare_corpus(); this function packs the
    leading threshold_len indices of the keystream into a bytes needle and
    delegates the slide to bytes.find (C-implemented substring search).
    """
    ks_len = len(keystream_idx)
    if ks_len < threshold_len:
        return None
    needle = bytes(keystream_idx[:threshold_len])
    for entry in prepared_entries:
        if len(entry.idx_bytes) < threshold_len:
            continue
        off = entry.idx_bytes.find(needle)
        if off != -1:
            return S1Hit(source_id=entry.id, offset=off, match_len=threshold_len)
    return None
