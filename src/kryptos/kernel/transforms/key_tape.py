"""Finite-tape additive cipher with optional null insertion.

Implements the M1-M5 hypothesis class from the keystream-forensics
agent (memory/keystream_forensics_v2.md). The tape is finite; nulls
either skip the tape (M4 default, "skip" rule) or consume it without
contributing to plaintext ("consume" rule).

Spec: docs/campaigns/key_tape_dsl_implementation_plan.md
"""
from typing import FrozenSet, Literal, Tuple

from kryptos.kernel.alphabet import AZ, Alphabet
from kryptos.kernel.transforms.vigenere import CipherVariant, DECRYPT_FN, ENCRYPT_FN

NullRule = Literal["skip", "consume"]
Direction = Literal["encrypt", "decrypt"]

_OP_TABLE = {
    "decrypt": DECRYPT_FN,
    "encrypt": ENCRYPT_FN,
}


def apply_key_tape(
    text: str,
    tape: Tuple[int, ...],
    *,
    variant: CipherVariant,
    direction: Direction = "decrypt",
    null_positions: FrozenSet[int] = frozenset(),
    null_rule: NullRule = "skip",
    alphabet: Alphabet = AZ,
) -> str:
    """Apply finite-tape additive cipher with null insertion.

    Parameters
    ----------
    text:
        Input text (uppercase A-Z).
    tape:
        Finite sequence of key values (integers 0-25 in alphabet-index space).
    variant:
        Cipher variant: VIGENERE, BEAUFORT, or VAR_BEAUFORT.
    direction:
        "decrypt" (CT -> PT) or "encrypt" (PT -> CT).
    null_positions:
        0-indexed positions in *text* that are null characters.
        Nulls are emitted as '?' in the output.
    null_rule:
        "skip"    -- nulls do not advance the tape index (default, M4 semantics).
        "consume" -- nulls advance the tape index without contributing to output.
    alphabet:
        Alphabet instance for index lookup and character emission.

    Returns
    -------
    str
        Transformed text; null positions are replaced with '?'.
    """
    fn = _OP_TABLE[direction][variant]
    idx_table = alphabet.index_table
    seq = alphabet.sequence
    out: list[str] = []
    tape_idx = 0
    for pos, ch in enumerate(text):
        if pos in null_positions:
            out.append("?")
            if null_rule == "consume":
                tape_idx += 1
            continue
        key_val = tape[tape_idx]
        raw_idx = idx_table[ord(ch) - 65]
        out_idx = fn(raw_idx, key_val)
        out.append(seq[out_idx % 26])
        tape_idx += 1
    return "".join(out)
