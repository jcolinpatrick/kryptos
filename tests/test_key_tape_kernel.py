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


class TestKeyTapeNulls:
    def test_skip_null_rule(self):
        # 6-char text, 2 nulls at {1,4}, 4 non-null positions.
        # Tape length = 4 (matches non-null count under SKIP).
        ct = apply_key_tape(
            "ABCDEF",
            tape=(0, 0, 0, 0),
            variant=CipherVariant.VIGENERE,
            direction="decrypt",
            null_positions=frozenset({1, 4}),
            null_rule="skip",
            alphabet=AZ,
        )
        # tape (0,0,0,0) is identity for Vigenere; non-null positions
        # decrypt to themselves; null positions become '?'.
        assert ct == "A?CD?F"

    def test_consume_null_rule(self):
        # CONSUME advances tape on every position (including nulls).
        # 6-char text, 2 nulls at {1,4}, tape length = 6 (full).
        # All-zero tape: identity for Vigenère. Tape values at null
        # positions are still range-validated by the kernel (so we use
        # 0, not arbitrary "ignored" values like 99 -- those would fail
        # the [0,25] validation rule in apply_key_tape's preflight).
        ct = apply_key_tape(
            "ABCDEF",
            tape=(0, 0, 0, 0, 0, 0),
            variant=CipherVariant.VIGENERE,
            direction="decrypt",
            null_positions=frozenset({1, 4}),
            null_rule="consume",
            alphabet=AZ,
        )
        assert ct == "A?CD?F"

    def test_skip_short_tape_raises(self):
        # 6 non-null positions, tape length 3 -> exhaustion -> ValueError.
        with pytest.raises(ValueError, match="tape exhausted"):
            apply_key_tape(
                "ABCDEF",
                tape=(0, 0, 0),
                variant=CipherVariant.VIGENERE,
                null_positions=frozenset(),
                null_rule="skip",
                alphabet=AZ,
            )

    def test_consume_short_tape_raises(self):
        # 6 positions total under CONSUME, tape length 3 -> exhaustion at pos 3.
        with pytest.raises(ValueError, match="tape exhausted"):
            apply_key_tape(
                "ABCDEF",
                tape=(0, 0, 0),
                variant=CipherVariant.VIGENERE,
                null_positions=frozenset({1, 4}),
                null_rule="consume",
                alphabet=AZ,
            )

    def test_tape_value_out_of_range_raises(self):
        with pytest.raises(ValueError, match=r"tape\[\d+\]"):
            apply_key_tape(
                "AB", tape=(26,),  # 26 is out of range
                variant=CipherVariant.VIGENERE, alphabet=AZ,
            )

    def test_null_position_out_of_range_raises(self):
        with pytest.raises(ValueError, match="null_positions"):
            apply_key_tape(
                "AB", tape=(0, 0),
                variant=CipherVariant.VIGENERE,
                null_positions=frozenset({99}),
                null_rule="skip",
                alphabet=AZ,
            )

    def test_empty_tape_raises(self):
        with pytest.raises(ValueError, match="tape must be non-empty"):
            apply_key_tape(
                "AB", tape=(),
                variant=CipherVariant.VIGENERE, alphabet=AZ,
            )

    def test_consume_null_exhaustion_in_null_branch(self):
        # Tape used at pos 0 (non-null). At pos 1 (null, consume rule),
        # the tape is already exhausted -> ValueError from the consume-null branch.
        with pytest.raises(ValueError, match="under consume rule"):
            apply_key_tape(
                "AB", tape=(0,),
                variant=CipherVariant.VIGENERE,
                null_positions=frozenset({1}),
                null_rule="consume",
                alphabet=AZ,
            )


class TestKeyTapeCompose:
    def test_transform_type_key_tape_exists(self):
        from kryptos.kernel.transforms.compose import TransformType
        assert TransformType.KEY_TAPE.value == "key_tape"

    def test_compose_pipeline_with_key_tape(self):
        # Build a single-step pipeline that applies key_tape and confirm
        # it produces the same output as direct apply_key_tape.
        from kryptos.kernel.transforms.compose import (
            TransformConfig, TransformType, PipelineConfig, build_pipeline,
        )
        ct = "BCDEF"
        tape = (1, 1, 1, 1, 1)
        cfg = TransformConfig(
            transform_type=TransformType.KEY_TAPE,
            params={
                "tape": tape,
                "variant": "vigenere",
                "direction": "decrypt",
                "null_positions": frozenset(),
                "null_rule": "skip",
                "alphabet": "AZ",
            },
        )
        pipeline_cfg = PipelineConfig(name="test_key_tape", steps=(cfg,))
        pipeline = build_pipeline(pipeline_cfg)
        assert pipeline(ct) == "ABCDE"

    def test_compose_rejects_unknown_alphabet(self):
        from kryptos.kernel.transforms.compose import (
            TransformConfig, TransformType, PipelineConfig, build_pipeline,
        )
        cfg = TransformConfig(
            transform_type=TransformType.KEY_TAPE,
            params={
                "tape": (1, 1, 1),
                "variant": "vigenere",
                "direction": "decrypt",
                "null_positions": frozenset(),
                "null_rule": "skip",
                "alphabet": "ASCII",  # invalid
            },
        )
        with pytest.raises(ValueError, match="unsupported alphabet"):
            build_pipeline(PipelineConfig(name="test_bad_alpha", steps=(cfg,)))

    def test_compose_rejects_nulls_without_rule(self):
        from kryptos.kernel.transforms.compose import (
            TransformConfig, TransformType, PipelineConfig, build_pipeline,
        )
        cfg = TransformConfig(
            transform_type=TransformType.KEY_TAPE,
            params={
                "tape": (1, 1, 1),
                "variant": "vigenere",
                "direction": "decrypt",
                "null_positions": frozenset({0}),
                # null_rule omitted — must raise
                "alphabet": "AZ",
            },
        )
        with pytest.raises(ValueError, match="null_rule required"):
            build_pipeline(PipelineConfig(name="test_missing_rule", steps=(cfg,)))
