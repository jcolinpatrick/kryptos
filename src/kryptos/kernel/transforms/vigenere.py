"""Vigenere, Beaufort, and Variant Beaufort cipher families.

All substitution operations are defined here with consistent conventions:
  - Vigenere:         C = (P + K) mod 26,  K = (C - P) mod 26
  - Beaufort:         C = (K - P) mod 26,  K = (C + P) mod 26
  - Variant Beaufort: C = (P - K) mod 26,  K = (P - C) mod 26
"""
from __future__ import annotations

from enum import Enum
from typing import Callable, List, Optional, Tuple

from kryptos.kernel.constants import ALPH, ALPH_IDX, MOD
from kryptos.kernel.alphabet import Alphabet


class CipherVariant(str, Enum):
    VIGENERE = "vigenere"
    BEAUFORT = "beaufort"
    VAR_BEAUFORT = "var_beaufort"


# ── Key recovery functions: given (C, P) -> K ────────────────────────────

def vig_recover_key(c: int, p: int) -> int:
    """Vigenere: K = (C - P) mod 26."""
    return (c - p) % MOD


def beau_recover_key(c: int, p: int) -> int:
    """Beaufort: K = (C + P) mod 26."""
    return (c + p) % MOD


def varbeau_recover_key(c: int, p: int) -> int:
    """Variant Beaufort: K = (P - C) mod 26."""
    return (p - c) % MOD


KEY_RECOVERY: dict[CipherVariant, Callable[[int, int], int]] = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}


# ── Decrypt functions: given (C, K) -> P ─────────────────────────────────

def vig_decrypt(c: int, k: int) -> int:
    """Vigenere decrypt: P = (C - K) mod 26."""
    return (c - k) % MOD


def beau_decrypt(c: int, k: int) -> int:
    """Beaufort decrypt: P = (K - C) mod 26."""
    return (k - c) % MOD


def varbeau_decrypt(c: int, k: int) -> int:
    """Variant Beaufort decrypt: P = (C + K) mod 26."""
    return (c + k) % MOD


DECRYPT_FN: dict[CipherVariant, Callable[[int, int], int]] = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}


# ── Encrypt functions: given (P, K) -> C ─────────────────────────────────

def vig_encrypt(p: int, k: int) -> int:
    """Vigenere encrypt: C = (P + K) mod 26."""
    return (p + k) % MOD


def beau_encrypt(p: int, k: int) -> int:
    """Beaufort encrypt: C = (K - P) mod 26."""
    return (k - p) % MOD


def varbeau_encrypt(p: int, k: int) -> int:
    """Variant Beaufort encrypt: C = (P - K) mod 26."""
    return (p - k) % MOD


ENCRYPT_FN: dict[CipherVariant, Callable[[int, int], int]] = {
    CipherVariant.VIGENERE: vig_encrypt,
    CipherVariant.BEAUFORT: beau_encrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_encrypt,
}


# ── High-level operations ────────────────────────────────────────────────

def decrypt_text(
    ct: str,
    key: List[int],
    variant: CipherVariant = CipherVariant.VIGENERE,
) -> str:
    """Decrypt ciphertext with a (possibly repeating) numeric key."""
    fn = DECRYPT_FN[variant]
    klen = len(key)
    return "".join(
        chr(fn(ord(c) - 65, key[i % klen]) + 65)
        for i, c in enumerate(ct)
    )


def encrypt_text(
    pt: str,
    key: List[int],
    variant: CipherVariant = CipherVariant.VIGENERE,
) -> str:
    """Encrypt plaintext with a (possibly repeating) numeric key."""
    fn = ENCRYPT_FN[variant]
    klen = len(key)
    return "".join(
        chr(fn(ord(p) - 65, key[i % klen]) + 65)
        for i, p in enumerate(pt)
    )


def recover_key_at_positions(
    ct: str,
    pt_positions: dict[int, str],
    variant: CipherVariant = CipherVariant.VIGENERE,
    pa: Optional[Alphabet] = None,
    ca: Optional[Alphabet] = None,
) -> dict[int, int]:
    """Recover key values at known plaintext positions.

    If pa/ca alphabets are provided, uses their index tables for lookup.
    Otherwise uses standard A-Z (ord - 65).
    """
    fn = KEY_RECOVERY[variant]
    result: dict[int, int] = {}

    if pa is not None and ca is not None:
        pa_idx = pa.index_table
        ca_idx = ca.index_table
        for pos, pt_ch in pt_positions.items():
            if pos < len(ct):
                c = ca_idx[ord(ct[pos]) - 65]
                p = pa_idx[ord(pt_ch) - 65]
                result[pos] = fn(c, p)
    else:
        for pos, pt_ch in pt_positions.items():
            if pos < len(ct):
                c = ord(ct[pos]) - 65
                p = ord(pt_ch) - 65
                result[pos] = fn(c, p)

    return result


def apply_additive_mask(text: str, keyword: str) -> str:
    """Apply additive mask: text[i] = (text[i] + keyword[i % len]) mod 26."""
    if not keyword or keyword == "NONE":
        return text
    kw = [ALPH_IDX[c] for c in keyword.upper()]
    klen = len(kw)
    return "".join(
        ALPH[(ALPH_IDX[ch] + kw[i % klen]) % MOD]
        for i, ch in enumerate(text)
    )


def remove_additive_mask(text: str, keyword: str) -> str:
    """Remove additive mask: text[i] = (text[i] - keyword[i % len]) mod 26."""
    if not keyword or keyword == "NONE":
        return text
    kw = [ALPH_IDX[c] for c in keyword.upper()]
    klen = len(kw)
    return "".join(
        ALPH[(ALPH_IDX[ch] - kw[i % klen]) % MOD]
        for i, ch in enumerate(text)
    )
