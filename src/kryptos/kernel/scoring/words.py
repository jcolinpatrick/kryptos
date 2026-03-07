"""Word-level English scoring for candidate plaintexts.

Uses dynamic programming to find the maximum-coverage segmentation of a text
into English words. This catches near-miss decryptions that quadgram scoring
misses — e.g., "SLOWLYDESPARATLY" scores high here but may not on n-grams
if surrounding context is noisy.

Scoring:
  word_coverage  — fraction of characters covered by valid words (0.0 to 1.0)
  word_score     — weighted score favoring longer words (sum of len^1.5)
  longest_word   — length of the longest English word found
  word_count     — number of distinct words in the best segmentation
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class WordScorer:
    """Score text by how well it segments into English words."""

    def __init__(self, words: Set[str], min_word_len: int = 4) -> None:
        self.words = words
        self.min_word_len = min_word_len
        # Precompute max word length for DP bounds
        self.max_word_len = max((len(w) for w in words), default=0)
        # Precompute prefix set for early termination in DP
        self._prefixes: Set[str] = set()
        for w in words:
            for i in range(1, len(w) + 1):
                self._prefixes.add(w[:i])

    @classmethod
    def from_file(cls, path: str | Path, min_word_len: int = 4) -> "WordScorer":
        """Load words from a newline-delimited file. Filters to A-Z only."""
        words: Set[str] = set()
        az_only = re.compile(r'^[A-Z]+$')
        with open(path) as f:
            for line in f:
                w = line.strip().upper()
                if len(w) >= min_word_len and az_only.match(w):
                    words.add(w)
        return cls(words, min_word_len)

    def score(self, text: str) -> "WordResult":
        """Find the maximum-coverage segmentation into English words.

        Uses DP: dp[i] = max characters covered in text[:i].
        Returns WordResult with coverage, word list, and quality metrics.
        """
        text = text.upper()
        n = len(text)
        if n == 0:
            return WordResult(text="", coverage=0.0, weighted_score=0.0,
                              words=[], longest=0, word_count=0, covered_chars=0)

        # dp[i] = (max_covered_chars, best_prev_index, word_len_if_word_ends_here)
        dp = [0] * (n + 1)
        backtrack = [(-1, 0)] * (n + 1)  # (prev_pos, word_len)

        for i in range(1, n + 1):
            # Option 1: skip this character (not part of any word)
            dp[i] = dp[i - 1]
            backtrack[i] = (i - 1, 0)

            # Option 2: end a word at position i
            max_len = min(i, self.max_word_len)
            for wlen in range(self.min_word_len, max_len + 1):
                start = i - wlen
                candidate = text[start:i]
                if candidate in self.words:
                    new_covered = dp[start] + wlen
                    if new_covered > dp[i]:
                        dp[i] = new_covered
                        backtrack[i] = (start, wlen)

        # Reconstruct the segmentation
        words: List[str] = []
        pos = n
        while pos > 0:
            prev, wlen = backtrack[pos]
            if wlen > 0:
                words.append(text[prev:pos])
            pos = prev
        words.reverse()

        covered = dp[n]
        longest = max((len(w) for w in words), default=0)
        # Weighted score: longer words are exponentially more significant
        weighted = sum(len(w) ** 1.5 for w in words)

        return WordResult(
            text=text,
            coverage=covered / n if n > 0 else 0.0,
            weighted_score=weighted,
            words=words,
            longest=longest,
            word_count=len(words),
            covered_chars=covered,
        )

    def score_coverage(self, text: str) -> float:
        """Quick coverage-only score (0.0 to 1.0). For use as a prefilter."""
        text = text.upper()
        n = len(text)
        if n == 0:
            return 0.0

        dp = [0] * (n + 1)
        prefixes = self._prefixes
        words = self.words
        min_wl = self.min_word_len
        for i in range(n):
            if dp[i + 1] < dp[i]:
                dp[i + 1] = dp[i]
            # Extend forward from position i
            for j in range(i + 1, min(i + self.max_word_len, n) + 1):
                substr = text[i:j]
                if substr not in prefixes:
                    break  # no word starts with this prefix
                if j - i >= min_wl and substr in words:
                    new_covered = dp[i] + (j - i)
                    if new_covered > dp[j]:
                        dp[j] = new_covered
        return dp[n] / n


class WordResult:
    """Result of word segmentation scoring."""

    def __init__(self, text: str, coverage: float, weighted_score: float,
                 words: List[str], longest: int, word_count: int,
                 covered_chars: int) -> None:
        self.text = text
        self.coverage = coverage
        self.weighted_score = weighted_score
        self.words = words
        self.longest = longest
        self.word_count = word_count
        self.covered_chars = covered_chars

    @property
    def summary(self) -> str:
        pct = f"{self.coverage:.0%}"
        top_words = [w for w in self.words if len(w) >= 5][:5]
        parts = [f"words={pct}({self.covered_chars}/{len(self.text)})",
                 f"n={self.word_count}", f"longest={self.longest}"]
        if top_words:
            parts.append(f"top={','.join(top_words)}")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        return {
            "coverage": round(self.coverage, 4),
            "weighted_score": round(self.weighted_score, 2),
            "words": self.words,
            "longest": self.longest,
            "word_count": self.word_count,
            "covered_chars": self.covered_chars,
        }


# ── Singleton loader ──────────────────────────────────────────────────────

_default_scorer: Optional[WordScorer] = None


def get_default_word_scorer() -> WordScorer:
    """Get or create the default word scorer from the project wordlist."""
    global _default_scorer
    if _default_scorer is not None:
        return _default_scorer

    search_paths = [
        Path("wordlists/english.txt"),
        Path(__file__).parent.parent.parent.parent.parent / "wordlists/english.txt",
    ]

    for p in search_paths:
        if p.exists():
            _default_scorer = WordScorer.from_file(p, min_word_len=4)
            return _default_scorer

    raise FileNotFoundError(
        f"Could not find wordlist at any of: {[str(p) for p in search_paths]}"
    )
