"""Autokey cipher (Vigenère and Beaufort variants).

The autokey cipher uses a short primer as the initial key, then extends
the keystream using plaintext characters. This makes it non-periodic and
resistant to Kasiski/IC analysis, but with a small primer keyspace.

Conventions match vigenere.py:
  - Vigenere:         C = (P + K) mod 26,  K = (C - P) mod 26
  - Beaufort:         C = (K - P) mod 26,  K = (C + P) mod 26
  - Variant Beaufort: C = (P - K) mod 26,  K = (P - C) mod 26
"""
from __future__ import annotations

from kryptos.kernel.constants import MOD


def autokey_encrypt(pt: str, primer: str, variant: str = "vigenere") -> str:
    """Autokey encrypt: primer starts the key, then PT extends it."""
    pt = pt.upper()
    key_chars = [ord(c) - 65 for c in primer.upper()]
    result = []

    for i, p_ch in enumerate(pt):
        p = ord(p_ch) - 65
        if i < len(key_chars):
            k = key_chars[i]
        else:
            k = ord(pt[i - len(primer)]) - 65

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


def autokey_decrypt(ct: str, primer: str, variant: str = "vigenere") -> str:
    """Autokey decrypt: recover PT using primer, then use recovered PT as key."""
    ct = ct.upper()
    key_chars = [ord(c) - 65 for c in primer.upper()]
    result = []

    for i, c_ch in enumerate(ct):
        c = ord(c_ch) - 65
        if i < len(key_chars):
            k = key_chars[i]
        else:
            k = ord(result[i - len(primer)]) - 65

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
