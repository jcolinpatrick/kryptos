"""Synthetic recovery test for the key_tape kind.

Mirror of Stage A/B's synthetic recovery pattern. Encrypts a known
PT through apply_key_tape, then decrypts with the same parameters
and asserts roundtrip on non-null positions.

Spec: docs/campaigns/key_tape_dsl_implementation_plan.md §7.
"""
import pytest

from kryptos.kernel.alphabet import AZ
from kryptos.kernel.transforms.key_tape import apply_key_tape
from kryptos.kernel.transforms.vigenere import CipherVariant


PT = "KRYPTOSEXAMPLEAB"  # 16 chars
TAPE = (7, 3, 1, 2, 5, 8, 11, 4, 9, 0)  # 10 elements
NULLS = frozenset({2, 5, 8, 11, 14, 15})  # 6 nulls -> 10 non-null

VARIANTS = [
    CipherVariant.VIGENERE,
    CipherVariant.BEAUFORT,
    CipherVariant.VAR_BEAUFORT,
]


@pytest.mark.parametrize("variant", VARIANTS)
def test_synthetic_recovery_skip(variant):
    ct = apply_key_tape(
        PT, tape=TAPE, variant=variant,
        direction="encrypt",
        null_positions=NULLS, null_rule="skip", alphabet=AZ,
    )
    pt_recovered = apply_key_tape(
        ct, tape=TAPE, variant=variant,
        direction="decrypt",
        null_positions=NULLS, null_rule="skip", alphabet=AZ,
    )
    # Non-null positions roundtrip exactly; null positions become '?'.
    assert len(pt_recovered) == len(PT)
    for i in range(len(PT)):
        if i in NULLS:
            assert pt_recovered[i] == "?", f"null pos {i} should be '?'"
        else:
            assert pt_recovered[i] == PT[i], (
                f"non-null pos {i} roundtrip failed: "
                f"expected {PT[i]!r}, got {pt_recovered[i]!r}"
            )

    # Encrypt should change at least one non-null letter under any
    # non-trivial tape (TAPE contains some non-zero values).
    assert ct != PT


def test_synthetic_recovery_consume_full_tape():
    # CONSUME requires tape length >= total positions (16).
    tape16 = TAPE + (12, 22, 18, 6, 17, 21)  # length 16
    ct = apply_key_tape(
        PT, tape=tape16, variant=CipherVariant.VIGENERE,
        direction="encrypt",
        null_positions=NULLS, null_rule="consume", alphabet=AZ,
    )
    pt_recovered = apply_key_tape(
        ct, tape=tape16, variant=CipherVariant.VIGENERE,
        direction="decrypt",
        null_positions=NULLS, null_rule="consume", alphabet=AZ,
    )
    for i in range(len(PT)):
        if i in NULLS:
            assert pt_recovered[i] == "?"
        else:
            assert pt_recovered[i] == PT[i]
