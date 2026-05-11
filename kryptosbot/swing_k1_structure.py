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


VETTED_KEYWORDS: Tuple[str, ...] = (
    "KRYPTOS",
    "ABSCISSA",
    "BERLIN",
    "CLOCK",
    "BERLINCLOCK",
    "NORTHEAST",
    "EAST",
    "SCHEIDT",
    "PALIMPSEST",
    "NDYAHR",
    "DYAHR",
    "SCIREALM",
    "MUENCHEN",
)
# Self-referential keywords (SCULPTOR, ARTIST) explicitly excluded.


@dataclass(frozen=True)
class S2Hit:
    keyword: str
    match_len: int


def match_keyword_expansion(
    keystream_idx: Sequence[int],
    candidate_keywords: Tuple[str, ...] = VETTED_KEYWORDS,
    min_match_len: int = 8,
) -> Optional[S2Hit]:
    """Test whether the keystream is a prefix or substring of any candidate keyword's expansion.

    The expansion is the keyword repeated to length 24, AZ-indexed.
    """
    if len(keystream_idx) < min_match_len:
        return None
    for kw in candidate_keywords:
        if not kw:
            continue
        expansion = (kw * (24 // len(kw) + 2))[:24]
        exp_idx = _str_to_idx_seq(expansion)
        # Sliding match: find longest run-prefix of keystream matching any offset in expansion.
        best = 0
        for off in range(len(exp_idx)):
            run = 0
            while (
                off + run < len(exp_idx)
                and run < len(keystream_idx)
                and exp_idx[off + run] == keystream_idx[run]
            ):
                run += 1
            if run > best:
                best = run
        if best >= min_match_len:
            return S2Hit(keyword=kw, match_len=best)
    return None


@dataclass(frozen=True)
class S3Hit:
    generator: str
    seed: Tuple[int, ...]
    match_strength: float  # 1.0 = perfect, fraction otherwise


def _try_fibonacci(seq: Sequence[int]) -> Optional[S3Hit]:
    if len(seq) < 3:
        return None
    # Test ALL (k0, k1) seeds; the seed is the first two values of seq
    k0, k1 = seq[0], seq[1]
    a, b = k0, k1
    for i in range(2, len(seq)):
        expected = (a + b) % 26
        if seq[i] != expected:
            return None
        a, b = b, seq[i]
    return S3Hit(generator="fibonacci_mod_26", seed=(k0, k1), match_strength=1.0)


def _try_gronsfeld(seq: Sequence[int]) -> Optional[S3Hit]:
    if all(0 <= v <= 9 for v in seq):
        return S3Hit(generator="gronsfeld_0_9", seed=tuple(seq[:1]), match_strength=1.0)
    return None


def _try_autokey(seq: Sequence[int], primer_lens: Tuple[int, ...] = tuple(range(4, 13))) -> Optional[S3Hit]:
    """Autokey: k[i] = primer[i] for i < L, k[i] = seq[i - L] for i >= L.
    Check whether the observed sequence is self-consistent for any primer length L.
    """
    for L in primer_lens:
        if len(seq) < L + 1:
            continue
        consistent = all(seq[i] == seq[i - L] for i in range(L, len(seq)))
        if consistent:
            return S3Hit(
                generator=f"autokey_primer_{L}",
                seed=tuple(seq[:L]),
                match_strength=1.0,
            )
    return None


def match_generator(seq: Sequence[int]) -> Optional[S3Hit]:
    """Try generators in priority order: Fibonacci > Autokey > Gronsfeld."""
    for fn in (_try_fibonacci, _try_autokey, _try_gronsfeld):
        hit = fn(seq)
        if hit is not None:
            return hit
    return None
