"""Text normalization and encoding utilities.

All text processing should go through these functions to ensure consistency.
"""
from __future__ import annotations

import re
from typing import List

from kryptos.kernel.constants import ALPH, ALPH_IDX, MOD


def sanitize(text: str) -> str:
    """Normalize text to uppercase A-Z only, stripping all other characters."""
    return re.sub(r"[^A-Z]", "", text.upper())


def text_to_nums(text: str) -> List[int]:
    """Convert uppercase text to list of 0-25 integers."""
    return [ALPH_IDX[ch] for ch in text.upper() if ch in ALPH_IDX]


def nums_to_text(nums: List[int]) -> str:
    """Convert list of 0-25 integers back to uppercase text."""
    return "".join(ALPH[n % MOD] for n in nums)


def char_to_num(ch: str) -> int:
    """Convert a single uppercase character to 0-25."""
    return ord(ch.upper()) - 65


def num_to_char(n: int) -> str:
    """Convert a 0-25 integer to an uppercase character."""
    return chr((n % MOD) + 65)
