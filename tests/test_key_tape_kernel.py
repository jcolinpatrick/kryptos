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


class TestKeyTapeEncrypt:
    def test_vigenere_encrypt_known_value(self):
        # PT = "ABCDE", tape = (1,1,1,1,1), Vigenère encrypt -> "BCDEF"
        ct = apply_key_tape(
            "ABCDE",
            tape=(1, 1, 1, 1, 1),
            variant=CipherVariant.VIGENERE,
            direction="encrypt",
            alphabet=AZ,
        )
        assert ct == "BCDEF"

    def test_vigenere_roundtrip(self):
        pt = "KRYPTOSEXAMPLE"
        tape = (3, 7, 1, 14, 22, 5, 19, 0, 11, 8, 6, 25, 13, 4)
        ct = apply_key_tape(
            pt, tape=tape,
            variant=CipherVariant.VIGENERE,
            direction="encrypt", alphabet=AZ,
        )
        recovered = apply_key_tape(
            ct, tape=tape,
            variant=CipherVariant.VIGENERE,
            direction="decrypt", alphabet=AZ,
        )
        assert recovered == pt
