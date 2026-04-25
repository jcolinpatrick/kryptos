"""Quagmire cipher family (mixed-alphabet periodic substitution).

Quagmire I:   keyword-mixed PT alphabet, standard CT alphabet
Quagmire II:  standard PT alphabet, keyword-mixed CT alphabet
Quagmire III: SAME keyword-mixed alphabet used as both PT and CT alphabet
Quagmire IV:  keyword-mixed PT and CT alphabets (different keywords)

For K4, Quagmire III is most relevant — K1 and K2 use Quagmire III with
the KRYPTOS-mixed tableau.

=== K1/K2 CALLING CONVENTION (IMPORTANT) ===

K1 and K2 are Quagmire III under the canonical ACA definition: both PT and
CT use the same keyword-mixed alphabet. To reproduce K1/K2 with the
functions below, you MUST pass the keyword-mixed alphabet for BOTH
``ct_alphabet_keyword`` AND ``pt_alphabet_keyword``, and use
``indicator='K'`` (the first letter of the mixed alphabet):

    quagmire_decrypt(
        K1_CT, period_keyword="PALIMPSEST",
        ct_alphabet_keyword="KRYPTOS",
        pt_alphabet_keyword="KRYPTOS",
        indicator="K",
    )

Calling the function with only ``ct_alphabet_keyword`` set (leaving
``pt_alphabet_keyword`` at its default ``""``, i.e. standard A-Z) implements
a DIFFERENT mechanism — not the Quagmire III that K1/K2 use. It does not
reproduce K1 or K2 regardless of ``indicator`` value. This is a real
distinction, not an API quirk: the underlying math is different.

The ``indicator`` parameter selects which letter of the CT (and PT)
keyword-mixed alphabet aligns with the zero-shift row. ``indicator='K'``
means "the first letter of the KRYPTOS-mixed alphabet is the zero-shift
reference"; ``indicator='A'`` means "the letter A of the mixed alphabet
(which sits at position 7 for KRYPTOS) is the zero-shift reference".
These produce different ciphertexts and only one of them is the K1/K2
ground truth for a given ``period_keyword``.

The K1/K2 round-trip is pinned by ``test_transforms.py`` tests named
``test_k1_groundtruth`` and ``test_k2_groundtruth``; if you change this
module's math, those will fail first.
"""
from __future__ import annotations

from kryptos.kernel.constants import ALPH, MOD
from kryptos.kernel.alphabet import keyword_mixed_alphabet


def quagmire_encrypt(
    pt: str,
    period_keyword: str,
    indicator: str = "A",
    ct_alphabet_keyword: str = "",
    pt_alphabet_keyword: str = "",
) -> str:
    """Quagmire III encrypt: mixed CT alphabet shifted by period keyword.

    - ct_alphabet_keyword: keyword for the CT alphabet (mixed row)
    - period_keyword: repeating key that selects shift per position
    - indicator: letter in CT alphabet that aligns with 'A' at shift 0
    """
    ct_alpha = keyword_mixed_alphabet(ct_alphabet_keyword) if ct_alphabet_keyword else ALPH
    pt_alpha = keyword_mixed_alphabet(pt_alphabet_keyword) if pt_alphabet_keyword else ALPH

    # Build index tables
    ct_idx = {ch: i for i, ch in enumerate(ct_alpha)}
    pt_idx = {ch: i for i, ch in enumerate(pt_alpha)}

    indicator_pos = ct_idx.get(indicator, 0)
    kw = period_keyword.upper()
    klen = len(kw)

    result = []
    for i, p in enumerate(pt.upper()):
        p_pos = pt_idx.get(p, 0)
        k_char = kw[i % klen]
        k_pos = ct_idx.get(k_char, 0)
        shift = (k_pos - indicator_pos) % MOD
        c_pos = (p_pos + shift) % MOD
        result.append(ct_alpha[c_pos])
    return "".join(result)


def quagmire_decrypt(
    ct: str,
    period_keyword: str,
    indicator: str = "A",
    ct_alphabet_keyword: str = "",
    pt_alphabet_keyword: str = "",
) -> str:
    """Quagmire III decrypt: inverse of encrypt."""
    ct_alpha = keyword_mixed_alphabet(ct_alphabet_keyword) if ct_alphabet_keyword else ALPH
    pt_alpha = keyword_mixed_alphabet(pt_alphabet_keyword) if pt_alphabet_keyword else ALPH

    ct_idx = {ch: i for i, ch in enumerate(ct_alpha)}
    indicator_pos = ct_idx.get(indicator, 0)
    kw = period_keyword.upper()
    klen = len(kw)

    result = []
    for i, c in enumerate(ct.upper()):
        c_pos = ct_idx.get(c, 0)
        k_char = kw[i % klen]
        k_pos = ct_idx.get(k_char, 0)
        shift = (k_pos - indicator_pos) % MOD
        p_pos = (c_pos - shift) % MOD
        result.append(pt_alpha[p_pos])
    return "".join(result)


def quagmire_recover_key(
    ct_char: str,
    pt_char: str,
    ct_alphabet_keyword: str = "",
    pt_alphabet_keyword: str = "",
    indicator: str = "A",
) -> int:
    """Recover the shift value at a single position given CT and PT chars."""
    ct_alpha = keyword_mixed_alphabet(ct_alphabet_keyword) if ct_alphabet_keyword else ALPH
    pt_alpha = keyword_mixed_alphabet(pt_alphabet_keyword) if pt_alphabet_keyword else ALPH

    ct_idx = {ch: i for i, ch in enumerate(ct_alpha)}
    pt_idx = {ch: i for i, ch in enumerate(pt_alpha)}

    c_pos = ct_idx.get(ct_char, 0)
    p_pos = pt_idx.get(pt_char, 0)
    shift = (c_pos - p_pos) % MOD
    return shift
