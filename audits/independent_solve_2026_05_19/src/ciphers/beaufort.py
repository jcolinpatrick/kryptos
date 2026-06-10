"""Beaufort and Variant Beaufort over an arbitrary 26-letter alphabet.

Beaufort (reciprocal):    CT[i] = alpha[(idx(KEY[i]) - idx(PT[i])) mod 26]
                          PT[i] = alpha[(idx(KEY[i]) - idx(CT[i])) mod 26]

Variant Beaufort (a.k.a. minuend Beaufort, *not* reciprocal):
                          CT[i] = alpha[(idx(PT[i]) - idx(KEY[i])) mod 26]
                          PT[i] = alpha[(idx(CT[i]) + idx(KEY[i])) mod 26]

These conventions match the convention used by the kernel; see CLAUDE.md
"Vigenère vs Beaufort sign conventions" gotcha.
"""

from ..alphabets import index_in, char_at


def _expand_key(key: str, n: int) -> str:
    if not key:
        raise ValueError("empty key")
    return (key * ((n // len(key)) + 1))[:n]


def beaufort_encrypt(plaintext: str, key: str, alpha: str) -> str:
    if len(alpha) != 26 or len(set(alpha)) != 26:
        raise ValueError("alpha must be a 26-letter permutation of A-Z")
    pt = plaintext.upper()
    k = _expand_key(key.upper(), len(pt))
    out = []
    for p_ch, k_ch in zip(pt, k):
        if not p_ch.isalpha():
            out.append(p_ch)
            continue
        out.append(char_at(alpha, index_in(alpha, k_ch) - index_in(alpha, p_ch)))
    return "".join(out)


def beaufort_decrypt(ciphertext: str, key: str, alpha: str) -> str:
    # reciprocal: same operation
    return beaufort_encrypt(ciphertext, key, alpha)


def variant_beaufort_encrypt(plaintext: str, key: str, alpha: str) -> str:
    if len(alpha) != 26 or len(set(alpha)) != 26:
        raise ValueError("alpha must be a 26-letter permutation of A-Z")
    pt = plaintext.upper()
    k = _expand_key(key.upper(), len(pt))
    out = []
    for p_ch, k_ch in zip(pt, k):
        if not p_ch.isalpha():
            out.append(p_ch)
            continue
        out.append(char_at(alpha, index_in(alpha, p_ch) - index_in(alpha, k_ch)))
    return "".join(out)


def variant_beaufort_decrypt(ciphertext: str, key: str, alpha: str) -> str:
    if len(alpha) != 26 or len(set(alpha)) != 26:
        raise ValueError("alpha must be a 26-letter permutation of A-Z")
    ct = ciphertext.upper()
    k = _expand_key(key.upper(), len(ct))
    out = []
    for c_ch, k_ch in zip(ct, k):
        if not c_ch.isalpha():
            out.append(c_ch)
            continue
        out.append(char_at(alpha, index_in(alpha, c_ch) + index_in(alpha, k_ch)))
    return "".join(out)
