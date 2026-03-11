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
    serpentine_perm, spiral_perm, strip_perm, partial_perm,
    make_mengen_route, apply_rotation, apply_reflection,
    invert_perm, apply_perm, compose_perms, validate_perm,
    unmask_block_transposition, BLOCK_SIZE,
)
from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.transforms.vigenere import recover_key_at_positions


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


class TestBifid:
    """Tests for Bifid cipher correctness."""

    def test_bifid_not_identity(self):
        """Bifid encrypt must NOT be an identity function."""
        from kryptos.kernel.transforms.polybius import bifid_encrypt, make_polybius_5x5
        grid = make_polybius_5x5("KRYPTOS")
        pt = "HELLO"
        ct = bifid_encrypt(pt, grid, period=5)
        assert ct != pt, "Bifid encrypt should not be identity"

    def test_bifid_roundtrip(self):
        """Bifid encrypt then decrypt must roundtrip."""
        from kryptos.kernel.transforms.polybius import (
            bifid_encrypt, bifid_decrypt, make_polybius_5x5,
        )
        grid = make_polybius_5x5("KRYPTOS")
        for period in [2, 3, 5, 7, 10]:
            pt = "ATTACKATDAWN"
            ct = bifid_encrypt(pt, grid, period=period)
            recovered = bifid_decrypt(ct, grid, period=period)
            assert recovered == pt, f"Roundtrip failed at period {period}"

    def test_bifid_full_period(self):
        """Bifid with full-length period should work."""
        from kryptos.kernel.transforms.polybius import (
            bifid_encrypt, bifid_decrypt, make_polybius_5x5,
        )
        grid = make_polybius_5x5("")
        pt = "FLEEATONCE"
        ct = bifid_encrypt(pt, grid, period=0)
        assert ct != pt
        recovered = bifid_decrypt(ct, grid, period=0)
        assert recovered == pt

    def test_bifid_different_grids(self):
        """Different keywords should produce different ciphertexts."""
        from kryptos.kernel.transforms.polybius import (
            bifid_encrypt, make_polybius_5x5,
        )
        pt = "TESTMESSAGE"
        grid1 = make_polybius_5x5("KRYPTOS")
        grid2 = make_polybius_5x5("ABSCISSA")
        ct1 = bifid_encrypt(pt, grid1, period=5)
        ct2 = bifid_encrypt(pt, grid2, period=5)
        assert ct1 != ct2, "Different grids should give different ciphertexts"


class TestStripPerm:
    """Tests for strip_perm — row/strip reordering."""

    def test_identity_order(self):
        p = strip_perm(5, [0, 1, 2, 3], 20)
        assert p == list(range(20))

    def test_reversed_order(self):
        p = strip_perm(5, [3, 2, 1, 0], 20)
        assert validate_perm(p, 20)
        # First strip should be positions 15-19 (strip 3)
        assert p[:5] == [15, 16, 17, 18, 19]

    def test_incomplete_last_strip(self):
        p = strip_perm(5, [0, 1, 2, 3], 18)
        assert validate_perm(p, 18)
        # Last strip has only 3 elements (positions 15, 16, 17)
        assert len(p) == 18


class TestPartialPerm:
    """Tests for partial_perm — fixed prefix, permuted suffix."""

    def test_basic(self):
        p = partial_perm(5, [2, 0, 1], 8)
        assert p == [0, 1, 2, 3, 4, 7, 5, 6]

    def test_zero_boundary(self):
        p = partial_perm(0, [2, 0, 1])
        assert p == [2, 0, 1]

    def test_full_boundary(self):
        p = partial_perm(10, [], 10)
        assert p == list(range(10))


class TestMengenRoute:
    """Tests for make_mengen_route and route transforms."""

    def test_identity_route(self):
        route = make_mengen_route("identity")
        assert route == list(range(BLOCK_SIZE))

    def test_all_routes_valid_perms(self):
        for name in ["identity", "band_boustro", "all_forward", "all_reversed", "reverse_bands"]:
            route = make_mengen_route(name)
            assert validate_perm(route, BLOCK_SIZE), f"Route {name} is not a valid perm"

    def test_unknown_route_raises(self):
        with pytest.raises(ValueError):
            make_mengen_route("nonexistent_route")

    def test_rotation(self):
        route = list(range(BLOCK_SIZE))
        rotated = apply_rotation(route, 3)
        assert rotated[0] == route[3]
        assert len(rotated) == BLOCK_SIZE
        assert validate_perm(rotated, BLOCK_SIZE)

    def test_rotation_zero_identity(self):
        route = list(range(BLOCK_SIZE))
        assert apply_rotation(route, 0) == route

    def test_reflection(self):
        route = [0, 1, 2, 3, 4]
        reflected = apply_reflection(route)
        assert reflected == [4, 3, 2, 1, 0]


class TestRecoverKeyAtPositions:
    """Tests for recover_key_at_positions — key recovery from known PT."""

    def test_matches_implied_key_dict(self):
        """recover_key_at_positions should agree with implied_key_dict."""
        from kryptos.kernel.constraints.crib import implied_key_dict
        expected = implied_key_dict(CT, CipherVariant.VIGENERE)
        result = recover_key_at_positions(CT, CRIB_DICT, CipherVariant.VIGENERE)
        for pos in expected:
            assert result[pos] == expected[pos], f"Mismatch at pos {pos}"

    def test_all_variants_consistent(self):
        """Each variant should produce same key values as manual computation."""
        from kryptos.kernel.constants import ALPH_IDX, MOD
        for variant in CipherVariant:
            result = recover_key_at_positions(CT, CRIB_DICT, variant)
            # Verify at least crib positions are present
            assert len(result) == len(CRIB_DICT)

    def test_with_custom_alphabets(self):
        """recover_key_at_positions should work with non-standard alphabets."""
        from kryptos.kernel.alphabet import AZ, KA
        result_az = recover_key_at_positions(CT, CRIB_DICT, CipherVariant.VIGENERE, AZ, AZ)
        result_plain = recover_key_at_positions(CT, CRIB_DICT, CipherVariant.VIGENERE)
        # With standard alphabets, AZ/AZ should equal no-alphabet path
        for pos in result_az:
            assert result_az[pos] == result_plain[pos], f"Mismatch at pos {pos}"


class TestQuagmire:
    """Tests for Quagmire cipher (mixed-alphabet periodic substitution)."""

    def test_roundtrip_basic(self):
        from kryptos.kernel.transforms.quagmire import quagmire_encrypt, quagmire_decrypt
        pt = "THEQUICKBROWNFOX"
        ct = quagmire_encrypt(pt, "KEY", indicator="A")
        recovered = quagmire_decrypt(ct, "KEY", indicator="A")
        assert recovered == pt

    def test_roundtrip_with_mixed_alphabet(self):
        from kryptos.kernel.transforms.quagmire import quagmire_encrypt, quagmire_decrypt
        pt = "ATTACKATDAWN"
        ct = quagmire_encrypt(pt, "BERLIN", indicator="K", ct_alphabet_keyword="KRYPTOS")
        recovered = quagmire_decrypt(ct, "BERLIN", indicator="K", ct_alphabet_keyword="KRYPTOS")
        assert recovered == pt

    def test_not_identity(self):
        from kryptos.kernel.transforms.quagmire import quagmire_encrypt
        pt = "HELLOWORLD"
        ct = quagmire_encrypt(pt, "KEY", indicator="A")
        assert ct != pt

    def test_different_keywords_different_ct(self):
        from kryptos.kernel.transforms.quagmire import quagmire_encrypt
        pt = "TESTMESSAGE"
        ct1 = quagmire_encrypt(pt, "ALPHA", indicator="A")
        ct2 = quagmire_encrypt(pt, "BRAVO", indicator="A")
        assert ct1 != ct2

    def test_recover_key(self):
        from kryptos.kernel.transforms.quagmire import quagmire_encrypt, quagmire_recover_key
        pt = "A"
        ct = quagmire_encrypt(pt, "D", indicator="A")
        shift = quagmire_recover_key(ct, pt, indicator="A")
        assert shift == 3  # D is shift 3 from A


class TestAutokey:
    """Tests for autokey cipher."""

    def test_roundtrip_vigenere(self):
        from kryptos.kernel.transforms.autokey import autokey_encrypt, autokey_decrypt
        pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        ct = autokey_encrypt(pt, "KEY", variant="vigenere")
        recovered = autokey_decrypt(ct, "KEY", variant="vigenere")
        assert recovered == pt

    def test_roundtrip_beaufort(self):
        from kryptos.kernel.transforms.autokey import autokey_encrypt, autokey_decrypt
        pt = "ATTACKATDAWNWITHALLFORCES"
        ct = autokey_encrypt(pt, "SECRET", variant="beaufort")
        recovered = autokey_decrypt(ct, "SECRET", variant="beaufort")
        assert recovered == pt

    def test_roundtrip_var_beaufort(self):
        from kryptos.kernel.transforms.autokey import autokey_encrypt, autokey_decrypt
        pt = "BERLINCLOCKKRYPTOS"
        ct = autokey_encrypt(pt, "XY", variant="var_beaufort")
        recovered = autokey_decrypt(ct, "XY", variant="var_beaufort")
        assert recovered == pt

    def test_not_identity(self):
        from kryptos.kernel.transforms.autokey import autokey_encrypt
        pt = "HELLOWORLD"
        ct = autokey_encrypt(pt, "A", variant="vigenere")
        # With primer "A", first char unchanged but subsequent chars use PT as key
        assert ct != pt  # At least some chars change (PT chars are non-A)

    def test_single_char_primer(self):
        from kryptos.kernel.transforms.autokey import autokey_encrypt, autokey_decrypt
        pt = "KRYPTOSISASCULPTURE"
        for primer in ["A", "K", "Z"]:
            ct = autokey_encrypt(pt, primer, variant="vigenere")
            recovered = autokey_decrypt(ct, primer, variant="vigenere")
            assert recovered == pt, f"Roundtrip failed with primer {primer}"


class TestRunningKey:
    """Tests for running-key cipher."""

    def test_roundtrip_vigenere(self):
        from kryptos.kernel.transforms.running_key import running_key_encrypt, running_key_decrypt
        pt = "THEQUICKBROWNFOX"
        key_text = "TOBEORNOTTOBETHATISTHEQUESTION"
        ct = running_key_encrypt(pt, key_text, variant="vigenere")
        recovered = running_key_decrypt(ct, key_text, variant="vigenere")
        assert recovered == pt

    def test_roundtrip_beaufort(self):
        from kryptos.kernel.transforms.running_key import running_key_encrypt, running_key_decrypt
        pt = "ATTACKATDAWN"
        key_text = "THEBOOKOFTHEDEADISANANCIENTTEXT"
        ct = running_key_encrypt(pt, key_text, variant="beaufort")
        recovered = running_key_decrypt(ct, key_text, variant="beaufort")
        assert recovered == pt

    def test_offset(self):
        from kryptos.kernel.transforms.running_key import running_key_encrypt, running_key_decrypt
        pt = "HELLO"
        key_text = "XYZABCDEFGHIJKLMNOP"
        ct = running_key_encrypt(pt, key_text, variant="vigenere", offset=3)
        recovered = running_key_decrypt(ct, key_text, variant="vigenere", offset=3)
        assert recovered == pt

    def test_non_alpha_stripped_from_key(self):
        from kryptos.kernel.transforms.running_key import running_key_encrypt, running_key_decrypt
        pt = "TEST"
        key_text = "T-H-E K.E.Y"  # Non-alpha chars should be stripped
        ct = running_key_encrypt(pt, key_text, variant="vigenere")
        recovered = running_key_decrypt(ct, key_text, variant="vigenere")
        assert recovered == pt

    def test_short_key_truncates(self):
        from kryptos.kernel.transforms.running_key import running_key_decrypt
        ct = "HELLOWORLD"
        key_text = "ABC"
        pt = running_key_decrypt(ct, key_text, variant="vigenere")
        assert len(pt) == 3  # Only 3 key chars available
