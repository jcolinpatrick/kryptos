"""Vigenere encryption / decryption parametrized by an arbitrary 26-letter
alphabet. Used to test KA, AZ, reversed-AZ, reversed-KA, keyword-mixed
alphabets, all on the same primitive.

Convention: ENCRYPT  CT[i] = alpha[(idx(KEY[i]) + idx(PT[i])) mod 26]
            DECRYPT  PT[i] = alpha[(idx(CT[i]) - idx(KEY[i])) mod 26]

Where idx() means the position within the provided `alpha` string.
"""

from ..alphabets import index_in, char_at


def _expand_key(key: str, n: int) -> str:
    if not key:
        raise ValueError("empty key")
    return (key * ((n // len(key)) + 1))[:n]


def encrypt(plaintext: str, key: str, alpha: str) -> str:
    if len(alpha) != 26 or len(set(alpha)) != 26:
        raise ValueError("alpha must be a 26-letter permutation of A-Z")
    pt = plaintext.upper()
    k = _expand_key(key.upper(), len(pt))
    out = []
    for p_ch, k_ch in zip(pt, k):
        if not p_ch.isalpha():
            out.append(p_ch)
            continue
        out.append(char_at(alpha, index_in(alpha, k_ch) + index_in(alpha, p_ch)))
    return "".join(out)


def decrypt(ciphertext: str, key: str, alpha: str) -> str:
    if len(alpha) != 26 or len(set(alpha)) != 26:
        raise ValueError("alpha must be a 26-letter permutation of A-Z")
    ct = ciphertext.upper()
    k = _expand_key(key.upper(), len(ct))
    out = []
    for c_ch, k_ch in zip(ct, k):
        if not c_ch.isalpha():
            out.append(c_ch)
            continue
        out.append(char_at(alpha, index_in(alpha, c_ch) - index_in(alpha, k_ch)))
    return "".join(out)
