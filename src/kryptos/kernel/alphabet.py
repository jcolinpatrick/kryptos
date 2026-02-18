"""Alphabet models, validation, and keyword mixing.

Provides a canonical Alphabet class that all transforms and scorers consume.
Supports standard A-Z, keyed alphabets, and merged-letter alphabets.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET


@dataclass(frozen=True)
class Alphabet:
    """An immutable, validated substitution alphabet."""

    label: str
    sequence: str

    def __post_init__(self) -> None:
        if len(self.sequence) != MOD or len(set(self.sequence)) != MOD:
            raise ValueError(
                f"Alphabet '{self.label}' must have {MOD} unique chars, "
                f"got {len(self.sequence)} ({len(set(self.sequence))} unique)"
            )
        if set(self.sequence) != set(ALPH):
            raise ValueError(
                f"Alphabet '{self.label}' must contain exactly A-Z, "
                f"got: {self.sequence!r}"
            )

    @property
    def index_table(self) -> List[int]:
        """index_table[ord(ch)-65] -> position of ch in this alphabet."""
        tbl = [0] * MOD
        for i, ch in enumerate(self.sequence):
            tbl[ord(ch) - 65] = i
        return tbl

    def char_to_idx(self, ch: str) -> int:
        """Convert a character to its index in this alphabet."""
        return self.index_table[ord(ch) - 65]

    def idx_to_char(self, idx: int) -> str:
        """Convert an index to the character at that position."""
        return self.sequence[idx % MOD]

    def encode(self, text: str) -> List[int]:
        """Convert text to list of indices in this alphabet."""
        tbl = self.index_table
        return [tbl[ord(ch) - 65] for ch in text.upper()]

    def decode(self, indices: List[int]) -> str:
        """Convert list of indices back to text."""
        return "".join(self.sequence[i % MOD] for i in indices)


# ── Standard alphabets ────────────────────────────────────────────────────

AZ = Alphabet("AZ", ALPH)
KA = Alphabet("KA", KRYPTOS_ALPHABET)


# ── Keyword mixing ────────────────────────────────────────────────────────

def keyword_mixed_alphabet(keyword: str, base: str = ALPH) -> str:
    """Build a keyword-mixed alphabet string.

    Places unique letters of keyword first, then remaining letters of base
    in their original order. Returns a 26-char string.

    >>> keyword_mixed_alphabet("KRYPTOS")
    'KRYPTOSABCDEFGHIJLMNQUVWXZ'
    """
    seen: set[str] = set()
    out: list[str] = []
    for ch in keyword.upper():
        if ch in set(base) and ch not in seen:
            seen.add(ch)
            out.append(ch)
    for ch in base:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    result = "".join(out)
    assert len(result) == MOD, f"alphabet length {len(result)} for kw={keyword!r}"
    return result


def make_alphabet(keyword: str, base: str = ALPH) -> Alphabet:
    """Create a named Alphabet from a keyword."""
    seq = keyword_mixed_alphabet(keyword, base)
    label = f"{keyword.upper()}({'KA' if base == KRYPTOS_ALPHABET else 'AZ'})"
    return Alphabet(label, seq)


# ── Thematic keywords ─────────────────────────────────────────────────────

THEMATIC_KEYWORDS: Tuple[str, ...] = (
    "SANBORN", "SCHEIDT", "BERLIN", "URANIA", "WELTZEITUHR",
    "MENGENLEHREUHR", "ENIGMA", "SHADOW", "PALIMPSEST", "ABSCISSA",
    "KRYPTOS", "ALEXANDERPLATZ", "QUARTZ", "COMPASS", "TUTANKHAMUN",
    "CARTER", "EGYPT", "HIEROGLYPH", "PHARAOH", "SPHINX",
    "POINT", "CLOCK", "BERLIN", "LODESTONE",
)


def build_alphabet_pairs(
    keywords: Tuple[str, ...] = THEMATIC_KEYWORDS,
) -> List[Tuple[Alphabet, Alphabet]]:
    """Generate all (PA, CA) pairs from base alphabets + keyword-mixed variants.

    Deduplicates by sequence content. Returns list of
    (plaintext_alphabet, ciphertext_alphabet) pairs.
    """
    bases = [AZ, KA]
    extended: list[Alphabet] = list(bases)
    seen_seqs: set[str] = {a.sequence for a in bases}

    for kw in keywords:
        for base in bases:
            seq = keyword_mixed_alphabet(kw, base.sequence)
            if seq not in seen_seqs:
                seen_seqs.add(seq)
                extended.append(Alphabet(f"{kw}({base.label})", seq))

    pairs: list[tuple[Alphabet, Alphabet]] = []
    pair_keys: set[tuple[str, str]] = set()

    for pa in extended:
        for ca in extended:
            key = (pa.sequence, ca.sequence)
            if key not in pair_keys:
                pair_keys.add(key)
                pairs.append((pa, ca))

    return pairs
