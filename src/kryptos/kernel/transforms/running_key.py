"""Running-key cipher.

Uses a passage of text (same length as the message) as the key.
Equivalent to Vigenère/Beaufort with a non-repeating key derived from
a known text (book, document, etc.).

The key difficulty is identifying which text and offset were used.
"""
from __future__ import annotations

import re

from kryptos.kernel.constants import MOD


def running_key_decrypt(
    ct: str,
    key_text: str,
    variant: str = "vigenere",
    offset: int = 0,
) -> str:
    """Decrypt CT using a running key from key_text starting at offset.

    Returns as many characters as min(len(ct), len(key_text) - offset).
    """
    ct = ct.upper()
    # Sanitize key_text to uppercase alpha only
    key_clean = re.sub(r"[^A-Z]", "", key_text.upper())
    if offset >= len(key_clean):
        return ""

    available = len(key_clean) - offset
    n = min(len(ct), available)
    result = []

    for i in range(n):
        c = ord(ct[i]) - 65
        k = ord(key_clean[offset + i]) - 65

        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        result.append(chr(p + 65))
    return "".join(result)


def running_key_encrypt(
    pt: str,
    key_text: str,
    variant: str = "vigenere",
    offset: int = 0,
) -> str:
    """Encrypt PT using a running key from key_text starting at offset."""
    pt = pt.upper()
    key_clean = re.sub(r"[^A-Z]", "", key_text.upper())
    if offset >= len(key_clean):
        return ""

    available = len(key_clean) - offset
    n = min(len(pt), available)
    result = []

    for i in range(n):
        p = ord(pt[i]) - 65
        k = ord(key_clean[offset + i]) - 65

        if variant == "vigenere":
            c = (p + k) % MOD
        elif variant == "beaufort":
            c = (k - p) % MOD
        elif variant == "var_beaufort":
            c = (p - k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        result.append(chr(c + 65))
    return "".join(result)
