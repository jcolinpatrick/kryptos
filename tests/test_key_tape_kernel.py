"""Tests for the key_tape finite-tape additive cipher with null insertion."""
import pytest

from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.transforms.vigenere import CipherVariant
from kryptos.kernel.transforms.key_tape import apply_key_tape


class TestKeyTapeBasic:
    def test_vigenere_decrypt_no_nulls_az(self):
        # Vigenère: K = (CT - PT) mod 26; PT = (CT - K) mod 26.
        # Tape (0,0,0,0,0) is the identity for Vigenère, so PT == CT.
        pt = apply_key_tape(
            "ABCDE",
            tape=(0, 0, 0, 0, 0),
            variant=CipherVariant.VIGENERE,
            direction="decrypt",
            alphabet=AZ,
        )
        assert pt == "ABCDE"

    def test_vigenere_decrypt_known_value(self):
        # CT = "BCDEF", tape = (1,1,1,1,1), Vigenère decrypt -> "ABCDE"
        pt = apply_key_tape(
            "BCDEF",
            tape=(1, 1, 1, 1, 1),
            variant=CipherVariant.VIGENERE,
            direction="decrypt",
            alphabet=AZ,
        )
        assert pt == "ABCDE"
