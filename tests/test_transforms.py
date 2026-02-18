"""Tests for cipher transforms — substitution and transposition."""
import pytest

from kryptos.kernel.transforms.vigenere import (
    CipherVariant,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
    vig_decrypt, vig_encrypt,
    beau_decrypt, beau_encrypt,
    varbeau_decrypt, varbeau_encrypt,
    decrypt_text, encrypt_text,
    apply_additive_mask, remove_additive_mask,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, myszkowski_perm, rail_fence_perm,
    serpentine_perm, spiral_perm,
    invert_perm, apply_perm, compose_perms, validate_perm,
    unmask_block_transposition, BLOCK_SIZE,
)
from kryptos.kernel.constants import CT


class TestVigenereFamily:
    """Test all three cipher variants for correctness and round-trip."""

    def test_vig_encrypt_decrypt(self):
        for p in range(26):
            for k in range(26):
                c = vig_encrypt(p, k)
                assert vig_decrypt(c, k) == p

    def test_beau_encrypt_decrypt(self):
        for p in range(26):
            for k in range(26):
                c = beau_encrypt(p, k)
                assert beau_decrypt(c, k) == p

    def test_varbeau_encrypt_decrypt(self):
        for p in range(26):
            for k in range(26):
                c = varbeau_encrypt(p, k)
                assert varbeau_decrypt(c, k) == p

    def test_vig_key_recovery(self):
        assert vig_recover_key(7, 4) == 3  # H encrypted with E -> key C
        assert vig_recover_key(0, 0) == 0

    def test_beau_key_recovery(self):
        assert beau_recover_key(7, 4) == 11

    def test_varbeau_key_recovery(self):
        assert varbeau_recover_key(7, 4) == 23  # (4-7) mod 26

    def test_text_roundtrip_vig(self):
        pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        key = [3, 7, 11, 2, 5, 17, 21]
        ct = encrypt_text(pt, key, CipherVariant.VIGENERE)
        assert decrypt_text(ct, key, CipherVariant.VIGENERE) == pt

    def test_text_roundtrip_beau(self):
        pt = "KRYPTOSISASCULPTURE"
        key = [1, 2, 3, 4, 5]
        ct = encrypt_text(pt, key, CipherVariant.BEAUFORT)
        assert decrypt_text(ct, key, CipherVariant.BEAUFORT) == pt

    def test_text_roundtrip_varbeau(self):
        pt = "BERLINCLOCKKRYPTOS"
        key = [10, 20, 15]
        ct = encrypt_text(pt, key, CipherVariant.VAR_BEAUFORT)
        assert decrypt_text(ct, key, CipherVariant.VAR_BEAUFORT) == pt


class TestAdditiveMask:
    def test_roundtrip(self):
        text = "HELLOWORLD"
        masked = apply_additive_mask(text, "KEY")
        unmasked = remove_additive_mask(masked, "KEY")
        assert unmasked == text

    def test_none_passthrough(self):
        assert apply_additive_mask("HELLO", "NONE") == "HELLO"
        assert remove_additive_mask("HELLO", "NONE") == "HELLO"

    def test_empty_passthrough(self):
        assert apply_additive_mask("HELLO", "") == "HELLO"
        assert remove_additive_mask("HELLO", "") == "HELLO"


class TestPermutations:
    def test_validate_valid(self):
        assert validate_perm([2, 0, 4, 1, 3], 5)

    def test_validate_invalid(self):
        assert not validate_perm([0, 1, 1, 3, 4], 5)

    def test_invert_roundtrip(self):
        perm = [3, 0, 4, 1, 2]
        inv = invert_perm(perm)
        text = "ABCDE"
        ct = apply_perm(text, perm)
        pt = apply_perm(ct, inv)
        assert pt == text

    def test_compose_identity(self):
        perm = [2, 0, 3, 1]
        inv = invert_perm(perm)
        composed = compose_perms(perm, inv)
        assert composed == list(range(4))

    def test_columnar_valid(self):
        p = columnar_perm(5, [2, 0, 4, 1, 3], 20)
        assert validate_perm(p, 20)

    def test_columnar_97(self):
        p = columnar_perm(7, [3, 0, 6, 1, 5, 2, 4])
        assert validate_perm(p, 97)

    def test_rail_fence_valid(self):
        p = rail_fence_perm(20, 3)
        assert validate_perm(p, 20)

    def test_rail_fence_depth1_identity(self):
        p = rail_fence_perm(10, 1)
        assert p == list(range(10))

    def test_serpentine_valid(self):
        p = serpentine_perm(5, 4, 20)
        assert validate_perm(p, 20)

    def test_spiral_valid(self):
        p = spiral_perm(5, 4, 20)
        assert validate_perm(p, 20)

    def test_myszkowski_valid(self):
        p = myszkowski_perm("TOMATO", 20)
        assert validate_perm(p, 20)


class TestBlockTransposition:
    def test_identity_unchanged(self):
        perm = list(range(BLOCK_SIZE))
        result = unmask_block_transposition(CT, perm)
        assert result == CT

    def test_roundtrip(self):
        # Apply permutation in forward direction: out[j] = input[perm[j]]
        perm = [3, 0, 4, 1, 2] + list(range(5, BLOCK_SIZE))
        out = list(CT)
        for block in range(len(CT) // BLOCK_SIZE):
            base = block * BLOCK_SIZE
            for j in range(BLOCK_SIZE):
                out[base + j] = CT[base + perm[j]]
        ct_permuted = "".join(out)

        # Undo via unmask (which applies inverse)
        result = unmask_block_transposition(ct_permuted, perm)
        assert result == CT

    def test_remainder_preserved(self):
        # Position 96 should be unchanged
        perm = list(range(1, BLOCK_SIZE)) + [0]  # shift by 1
        result = unmask_block_transposition(CT, perm)
        assert result[96] == CT[96]  # Remainder preserved
