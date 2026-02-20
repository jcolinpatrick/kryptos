"""General consistency checks for cipher candidates.

Provides checks that apply across cipher types:
- Alphabet bijection verification
- Round-trip encryption/decryption verification
- Self-encryption position checks
- Monoalphabetic consistency
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from kryptos.kernel.constants import (
    ALPH, CT, CRIB_DICT, CRIB_POSITIONS, SELF_ENCRYPTING,
)
from kryptos.kernel.alphabet import Alphabet
from kryptos.kernel.scoring.ic import ic


def check_self_encrypting(text: str) -> List[Tuple[int, str, str]]:
    """Check self-encrypting positions. Returns list of failures.

    Each failure is (position, expected_char, actual_char).
    Empty list means all self-encrypting positions are correct.
    """
    failures: list[tuple[int, str, str]] = []
    for pos, expected in SELF_ENCRYPTING.items():
        if pos < len(text) and text[pos] != expected:
            failures.append((pos, expected, text[pos]))
    return failures


def check_mono_consistency(text: str) -> Tuple[Dict[str, str], List[Tuple[int, str, str, str]]]:
    """Check monoalphabetic consistency at crib positions.

    If the cipher is monoalphabetic, each plaintext letter should map to
    exactly one ciphertext letter. Returns (mapping, conflicts).
    """
    pt_to_ct: dict[str, str] = {}
    conflicts: list[tuple[int, str, str, str]] = []
    for pos in sorted(CRIB_POSITIONS):
        if pos >= len(text):
            continue
        pt = CRIB_DICT[pos]
        ct = text[pos]
        if pt in pt_to_ct:
            if pt_to_ct[pt] != ct:
                conflicts.append((pos, pt, pt_to_ct[pt], ct))
        else:
            pt_to_ct[pt] = ct
    return pt_to_ct, conflicts


def check_alphabet_bijection(alphabet: Alphabet) -> bool:
    """Verify that an alphabet is a valid bijection of A-Z."""
    return (
        len(alphabet.sequence) == 26
        and len(set(alphabet.sequence)) == 26
        and set(alphabet.sequence) == set(ALPH)
    )


# ic() is imported from kryptos.kernel.scoring.ic above
# (was previously a duplicate definition here)
