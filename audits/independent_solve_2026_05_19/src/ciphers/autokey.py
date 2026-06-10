"""Autokey ciphers (PT-autokey and CT-autokey, Vigenere and Beaufort).

Recorded here for completeness. CLAUDE.md tags all autokey variants as
PROVEN IMPOSSIBLE on K4 (structural contradictions from crib feedback).
Use these only for the cross-kernel parity test and as reference, not as
a serious solve hypothesis.
"""

from ..alphabets import index_in, char_at


def pt_autokey_vigenere_decrypt(ciphertext: str, primer: str, alpha: str) -> str:
    """PT extends keystream after primer: K[i] = primer[i] if i<len(primer),
    else K[i] = PT[i - len(primer)]."""
    ct = ciphertext.upper()
    primer = primer.upper()
    out = []
    for i, c_ch in enumerate(ct):
        if i < len(primer):
            k_ch = primer[i]
        else:
            k_ch = out[i - len(primer)]
        p_ch = char_at(alpha, index_in(alpha, c_ch) - index_in(alpha, k_ch))
        out.append(p_ch)
    return "".join(out)


def ct_autokey_vigenere_decrypt(ciphertext: str, primer: str, alpha: str) -> str:
    """CT extends keystream after primer."""
    ct = ciphertext.upper()
    primer = primer.upper()
    out = []
    for i, c_ch in enumerate(ct):
        if i < len(primer):
            k_ch = primer[i]
        else:
            k_ch = ct[i - len(primer)]
        p_ch = char_at(alpha, index_in(alpha, c_ch) - index_in(alpha, k_ch))
        out.append(p_ch)
    return "".join(out)
