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


class TestKeyTapeBeaufort:
    def test_beaufort_self_reciprocal(self):
        # Beaufort: out = (K - in) mod 26. Same formula for encrypt and decrypt.
        pt = "ABCDE"
        tape = (5, 10, 15, 20, 25)
        ct = apply_key_tape(
            pt, tape=tape,
            variant=CipherVariant.BEAUFORT,
            direction="encrypt", alphabet=AZ,
        )
        recovered = apply_key_tape(
            ct, tape=tape,
            variant=CipherVariant.BEAUFORT,
            direction="decrypt", alphabet=AZ,
        )
        assert recovered == pt

    def test_beaufort_known_value(self):
        # PT='A' (0), K=1 -> Beaufort out = (1-0) mod 26 = 1 -> 'B'
        ct = apply_key_tape(
            "A", tape=(1,),
            variant=CipherVariant.BEAUFORT,
            direction="encrypt", alphabet=AZ,
        )
        assert ct == "B"


class TestKeyTapeVarBeaufort:
    def test_var_beaufort_decrypt_known_value(self):
        # VarBeau decrypt: PT = (CT + K) mod 26 (per
        # src/kryptos/kernel/transforms/vigenere.py::varbeau_decrypt).
        # CT='B' (1), K=2 -> PT = (1+2) mod 26 = 3 -> 'D'.
        pt = apply_key_tape(
            "B", tape=(2,),
            variant=CipherVariant.VAR_BEAUFORT,
            direction="decrypt", alphabet=AZ,
        )
        assert pt == "D"

    def test_var_beaufort_roundtrip(self):
        pt = "HELLO"
        tape = (3, 1, 4, 1, 5)
        ct = apply_key_tape(
            pt, tape=tape,
            variant=CipherVariant.VAR_BEAUFORT,
            direction="encrypt", alphabet=AZ,
        )
        recovered = apply_key_tape(
            ct, tape=tape,
            variant=CipherVariant.VAR_BEAUFORT,
            direction="decrypt", alphabet=AZ,
        )
        assert recovered == pt


class TestKeyTapeAlphabet:
    def test_ka_differs_from_az(self):
        pt = "KRYPTOS"
        tape = (1, 2, 3, 4, 5, 6, 7)
        ct_az = apply_key_tape(
            pt, tape=tape,
            variant=CipherVariant.VIGENERE,
            direction="encrypt", alphabet=AZ,
        )
        ct_ka = apply_key_tape(
            pt, tape=tape,
            variant=CipherVariant.VIGENERE,
            direction="encrypt", alphabet=KA,
        )
        # KA reorders the alphabet, so identical tape under same variant
        # produces a different CT under different alphabets.
        assert ct_az != ct_ka

    def test_ka_roundtrip(self):
        pt = "KRYPTOS"
        tape = (1, 2, 3, 4, 5, 6, 7)
        ct = apply_key_tape(
            pt, tape=tape,
            variant=CipherVariant.VIGENERE,
            direction="encrypt", alphabet=KA,
        )
        recovered = apply_key_tape(
            ct, tape=tape,
            variant=CipherVariant.VIGENERE,
            direction="decrypt", alphabet=KA,
        )
        assert recovered == pt
