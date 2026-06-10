"""The Kryptos tableau used on the K1/K2 sections.

The carved tableau is a Vigenere table where both the row header and the
column header are the KA alphabet (KRYPTOSABCDEFGHIJLMNQUVWXZ). The cell
at (row=key, col=plaintext) is KA[(KA.index(key) + KA.index(pt)) % 26].

Decryption is the inverse: PT = KA[(KA.index(CT) - KA.index(KEY)) % 26].

This is exactly "Vigenere arithmetic on the KA alphabet" — i.e. translate
into KA-indices, add/subtract mod 26, translate back.
"""

from .alphabets import KA, index_in, char_at


def _expand_key(key: str, n: int) -> str:
    if not key:
        raise ValueError("empty key")
    return (key * ((n // len(key)) + 1))[:n]


def encrypt_k1k2(plaintext: str, key: str) -> str:
    """Kryptos-tableau Vigenere encryption used on K1 and K2."""
    pt = plaintext.upper()
    k = _expand_key(key.upper(), len(pt))
    out = []
    for p_ch, k_ch in zip(pt, k):
        if not p_ch.isalpha():
            out.append(p_ch)
            continue
        out.append(char_at(KA, index_in(KA, k_ch) + index_in(KA, p_ch)))
    return "".join(out)


def decrypt_k1k2(ciphertext: str, key: str) -> str:
    """Inverse of encrypt_k1k2."""
    ct = ciphertext.upper()
    k = _expand_key(key.upper(), len(ct))
    out = []
    for c_ch, k_ch in zip(ct, k):
        if not c_ch.isalpha():
            out.append(c_ch)
            continue
        out.append(char_at(KA, index_in(KA, c_ch) - index_in(KA, k_ch)))
    return "".join(out)
