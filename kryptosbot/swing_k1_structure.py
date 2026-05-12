"""Swing K-1 4-channel structural-identification suite."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from kryptos.kernel.alphabet import AZ


def _str_to_idx_seq(s: str) -> List[int]:
    return [AZ.char_to_idx(c) for c in s if c.isalpha()]


def _text_to_idx_seq(text: str) -> List[int]:
    # Restrict to ASCII A..Z so unicode-aware .isalpha() does not let accented
    # characters (e.g. È, É, Cyrillic К) through and crash AZ.char_to_idx.
    # Mirrors the guard in _text_to_idx_bytes used by scan_source_text_prepared.
    return [AZ.char_to_idx(c) for c in text if "A" <= c <= "Z"]


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


def _try_period_repeat(seq: Sequence[int], primer_lens: Tuple[int, ...] = tuple(range(4, 13))) -> Optional[S3Hit]:
    """Keystream period-L self-repeat detector: k[i] == k[i - L] for all i >= L.

    NOTE: This is NOT autokey detection. True Vigenere autokey is
    k[i] = pt[i - L] where pt is the plaintext, not the keystream.
    This check fires only when the recovered keystream is itself
    L-periodic, which is a sibling property to S2 keyword expansion
    (a periodic keystream is what S2 already covers structurally).
    Kept as a fallback channel in case S2 misses a period not in the
    VETTED_KEYWORDS list.
    """
    for L in primer_lens:
        if len(seq) < L + 1:
            continue
        consistent = all(seq[i] == seq[i - L] for i in range(L, len(seq)))
        if consistent:
            return S3Hit(
                generator=f"period_{L}",
                seed=tuple(seq[:L]),
                match_strength=1.0,
            )
    return None


def match_generator(seq: Sequence[int]) -> Optional[S3Hit]:
    """Try generators in priority order: Fibonacci > Period > Gronsfeld."""
    for fn in (_try_fibonacci, _try_period_repeat, _try_gronsfeld):
        hit = fn(seq)
        if hit is not None:
            return hit
    return None


# Simple letter-bigram log-probabilities derived from English. For Phase A we
# use a small static table; refinement via the quadgram corpus is a Phase B
# improvement.
_ENGLISH_BIGRAM_LOGP = {
    "TH": -1.8, "HE": -2.0, "IN": -2.2, "ER": -2.3, "AN": -2.4, "RE": -2.4,
    "ON": -2.5, "AT": -2.5, "EN": -2.6, "ND": -2.6, "TI": -2.7, "ES": -2.7,
    "OR": -2.7, "TE": -2.8, "OF": -2.8, "ED": -2.8, "IS": -2.9, "IT": -2.9,
    "AL": -3.0, "AR": -3.0, "ST": -3.0, "TO": -3.0, "NT": -3.0,
    # Mid-frequency bigrams covering common letter pairs in English prose.
    "NG": -3.1, "SE": -3.1, "HA": -3.1, "AS": -3.1, "OU": -3.1, "IO": -3.1,
    "LE": -3.2, "VE": -3.2, "CO": -3.2, "ME": -3.2, "DE": -3.2, "HI": -3.2,
    "RI": -3.3, "RO": -3.3, "IC": -3.3, "NE": -3.3, "EA": -3.3, "RA": -3.3,
    "CE": -3.4, "LI": -3.4, "CH": -3.4, "LL": -3.4, "BE": -3.4, "MA": -3.4,
    "SI": -3.5, "OM": -3.5, "UR": -3.5, "CA": -3.5, "EL": -3.5, "TA": -3.5,
    "LA": -3.6, "NS": -3.6, "DI": -3.6, "FO": -3.6, "HO": -3.6, "PE": -3.6,
    "EC": -3.7, "PR": -3.7, "NO": -3.7, "CT": -3.7, "US": -3.7, "AC": -3.7,
    "OT": -3.8, "IL": -3.8, "TR": -3.8, "LY": -3.8, "NA": -3.8, "NI": -3.8,
    "SS": -3.9, "MO": -3.9, "MI": -3.9, "PA": -3.9, "OL": -3.9, "UN": -3.9,
    # Cover Q-U specifically — Q is almost always followed by U in English.
    "QU": -3.2,
    # Other bigrams found in common English: BROWN FOX JUMPS OVER LAZY DOG etc.
    "OW": -3.5, "WN": -3.7, "BR": -3.7, "OX": -4.2, "JU": -4.2, "UM": -3.8,
    "MP": -3.8, "PS": -3.8, "SO": -3.6, "OV": -3.8, "CK": -3.7, "UI": -4.0,
}


def ngram_score(seq: Sequence[int]) -> float:
    if len(seq) < 2:
        return 0.0
    total = 0.0
    for a, b in zip(seq[:-1], seq[1:]):
        bigram = AZ.idx_to_char(a) + AZ.idx_to_char(b)
        total += _ENGLISH_BIGRAM_LOGP.get(bigram, -5.0)
    return total / (len(seq) - 1)


@dataclass(frozen=True)
class StructureVerdict:
    s1: Optional[S1Hit]
    s2: Optional[S2Hit]
    s3: Optional[S3Hit]
    s4_score: float


def evaluate_structure_promotion(v: StructureVerdict) -> Tuple[bool, str]:
    """Return (promote_eligible, reason). Per spec §5.4, S4 alone is not signal."""
    reasons = []
    if v.s1 is not None and v.s1.match_len >= 24:
        reasons.append("S1 source-text full match")
    if v.s2 is not None and v.s2.match_len >= 8:
        reasons.append("S2 keyword-expansion prefix match")
    if v.s3 is not None and v.s3.match_strength >= 0.95:
        reasons.append("S3 generator match")
    if reasons:
        return True, "; ".join(reasons)
    return False, "no structure channel fired at promotion threshold"
