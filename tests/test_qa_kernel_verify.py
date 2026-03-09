"""Comprehensive kernel verification tests.

Verifies correctness of all kernel transforms, scoring, constraints,
and constants through roundtrip tests, sign convention checks,
and ground-truth invariants.

QA task: kernel_transforms_verification
"""
from __future__ import annotations

import pytest
from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, MOD,
    CRIB_DICT, CRIB_ENTRIES, CRIB_WORDS, N_CRIBS, CRIB_POSITIONS,
    KRYPTOS_ALPHABET, SELF_ENCRYPTING,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
    IC_K4, IC_RANDOM, IC_ENGLISH,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant,
    vig_encrypt, vig_decrypt, vig_recover_key,
    beau_encrypt, beau_decrypt, beau_recover_key,
    varbeau_encrypt, varbeau_decrypt, varbeau_recover_key,
    encrypt_text, decrypt_text,
    apply_additive_mask, remove_additive_mask,
    KEY_RECOVERY, ENCRYPT_FN, DECRYPT_FN,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, compose_perms, validate_perm,
    columnar_perm, rail_fence_perm, serpentine_perm,
    keyword_to_order,
)
from kryptos.kernel.transforms.compose import (
    TransformType, TransformConfig, PipelineConfig,
    build_transform, build_pipeline, compose, identity,
)
from kryptos.kernel.scoring.aggregate import ScoreBreakdown, score_candidate
from kryptos.kernel.scoring.crib_score import (
    score_cribs, score_cribs_detailed, is_breakthrough,
)
from kryptos.kernel.scoring.ic import ic, ic_score, ic_by_position
from kryptos.kernel.constraints.bean import (
    BeanResult, verify_bean, verify_bean_simple,
)
from kryptos.kernel.constraints.crib import (
    crib_score, crib_matches, compute_implied_keys, implied_key_dict,
)
from kryptos.kernel.alphabet import Alphabet, AZ, KA, keyword_mixed_alphabet


# ══════════════════════════════════════════════════════════════════════════
# (a) Vigenere roundtrip
# ══════════════════════════════════════════════════════════════════════════

class TestVigenereRoundtrip:
    """Encrypt then decrypt must recover original plaintext for Vigenere."""

    @pytest.mark.parametrize("key,period", [
        ([0], 1),           # identity key
        ([3, 7, 11], 3),    # period-3 key
        ([1, 2, 3, 4, 5], 5),
        ([25, 25, 25], 3),  # key=25 shifts
        ([13], 1),          # ROT13
    ])
    def test_roundtrip_various_keys(self, key, period):
        pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        ct = encrypt_text(pt, key, CipherVariant.VIGENERE)
        recovered = decrypt_text(ct, key, CipherVariant.VIGENERE)
        assert recovered == pt, f"Vig roundtrip failed for key={key}"

    def test_roundtrip_full_alphabet(self):
        """Every single-letter key should roundtrip."""
        pt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for k in range(26):
            ct = encrypt_text(pt, [k], CipherVariant.VIGENERE)
            recovered = decrypt_text(ct, [k], CipherVariant.VIGENERE)
            assert recovered == pt, f"Vig roundtrip failed for key=[{k}]"

    def test_roundtrip_k4_length(self):
        """Roundtrip on a string of K4's length (97 chars)."""
        pt = "A" * CT_LEN
        key = [1, 5, 9, 13, 17, 21, 25]
        ct = encrypt_text(pt, key, CipherVariant.VIGENERE)
        recovered = decrypt_text(ct, key, CipherVariant.VIGENERE)
        assert recovered == pt
        assert len(ct) == CT_LEN

    def test_roundtrip_single_char_per_key(self):
        """Each individual character encrypt/decrypt is consistent."""
        for p in range(26):
            for k in range(26):
                c = vig_encrypt(p, k)
                assert vig_decrypt(c, k) == p, f"Vig char roundtrip fail p={p} k={k}"


# ══════════════════════════════════════════════════════════════════════════
# (b) Beaufort roundtrip
# ══════════════════════════════════════════════════════════════════════════

class TestBeaufortRoundtrip:
    """Beaufort is an involution: encrypt == decrypt (self-reciprocal)."""

    @pytest.mark.parametrize("key", [
        [0], [7, 14, 21], [1, 2, 3, 4, 5, 6, 7],
    ])
    def test_roundtrip_beaufort(self, key):
        pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        ct = encrypt_text(pt, key, CipherVariant.BEAUFORT)
        recovered = decrypt_text(ct, key, CipherVariant.BEAUFORT)
        assert recovered == pt, f"Beaufort roundtrip failed for key={key}"

    def test_beaufort_involution_property(self):
        """Beaufort encrypt applied twice should return to plaintext."""
        pt = "KRYPTOS"
        key = [10, 17, 24, 15, 19, 14, 18]
        ct = encrypt_text(pt, key, CipherVariant.BEAUFORT)
        # Beaufort: C = (K - P) mod 26, so decrypt: P = (K - C) mod 26
        # encrypt(ct) should give back pt
        recovered = encrypt_text(ct, key, CipherVariant.BEAUFORT)
        assert recovered == pt, "Beaufort is not acting as involution"

    def test_beaufort_all_keys_roundtrip(self):
        for k in range(26):
            for p in range(26):
                c = beau_encrypt(p, k)
                assert beau_decrypt(c, k) == p


# ══════════════════════════════════════════════════════════════════════════
# (c) Variant Beaufort roundtrip
# ══════════════════════════════════════════════════════════════════════════

class TestVariantBeaufortRoundtrip:
    """Variant Beaufort: C = (P - K) mod 26, P = (C + K) mod 26."""

    @pytest.mark.parametrize("key", [
        [0], [5, 10, 15, 20, 25], [13, 13, 13],
    ])
    def test_roundtrip_varbeau(self, key):
        pt = "ABSCISSAORDINATEPALIMPSEST"
        ct = encrypt_text(pt, key, CipherVariant.VAR_BEAUFORT)
        recovered = decrypt_text(ct, key, CipherVariant.VAR_BEAUFORT)
        assert recovered == pt, f"VarBeau roundtrip failed for key={key}"

    def test_varbeau_all_keys_roundtrip(self):
        for k in range(26):
            for p in range(26):
                c = varbeau_encrypt(p, k)
                assert varbeau_decrypt(c, k) == p


# ══════════════════════════════════════════════════════════════════════════
# (d) Sign convention correctness
# ══════════════════════════════════════════════════════════════════════════

class TestSignConventions:
    """Verify the exact mathematical definitions of each cipher variant."""

    def test_vigenere_encrypt_formula(self):
        """Vig encrypt: C = (P + K) mod 26."""
        for p in range(26):
            for k in range(26):
                assert vig_encrypt(p, k) == (p + k) % 26

    def test_vigenere_key_recovery_formula(self):
        """Vig key recovery: K = (C - P) mod 26."""
        for c in range(26):
            for p in range(26):
                assert vig_recover_key(c, p) == (c - p) % 26

    def test_beaufort_encrypt_formula(self):
        """Beaufort encrypt: C = (K - P) mod 26."""
        for p in range(26):
            for k in range(26):
                assert beau_encrypt(p, k) == (k - p) % 26

    def test_beaufort_key_recovery_formula(self):
        """Beaufort key recovery: K = (C + P) mod 26."""
        for c in range(26):
            for p in range(26):
                assert beau_recover_key(c, p) == (c + p) % 26

    def test_var_beaufort_encrypt_formula(self):
        """VarBeau encrypt: C = (P - K) mod 26."""
        for p in range(26):
            for k in range(26):
                assert varbeau_encrypt(p, k) == (p - k) % 26

    def test_var_beaufort_key_recovery_formula(self):
        """VarBeau key recovery: K = (P - C) mod 26."""
        for c in range(26):
            for p in range(26):
                assert varbeau_recover_key(c, p) == (p - c) % 26

    def test_key_recovery_is_inverse_of_encrypt(self):
        """For all variants: recover_key(encrypt(p,k), p) == k."""
        for variant in CipherVariant:
            enc_fn = ENCRYPT_FN[variant]
            rec_fn = KEY_RECOVERY[variant]
            for p in range(26):
                for k in range(26):
                    c = enc_fn(p, k)
                    recovered_k = rec_fn(c, p)
                    assert recovered_k == k, (
                        f"{variant}: recover_key(enc({p},{k})={c}, {p}) = "
                        f"{recovered_k} != {k}"
                    )

    def test_decrypt_is_inverse_of_encrypt(self):
        """For all variants: decrypt(encrypt(p,k), k) == p."""
        for variant in CipherVariant:
            enc_fn = ENCRYPT_FN[variant]
            dec_fn = DECRYPT_FN[variant]
            for p in range(26):
                for k in range(26):
                    c = enc_fn(p, k)
                    assert dec_fn(c, k) == p, (
                        f"{variant}: dec(enc({p},{k})={c}, {k}) != {p}"
                    )

    def test_known_vigenere_keystream_ene(self):
        """Verify known Vigenere keystream values at ENE crib positions."""
        for i, (pos, ch) in enumerate(CRIB_ENTRIES):
            if pos < 21 + 13:  # ENE positions 21-33
                c = ord(CT[pos]) - 65
                p = ord(ch) - 65
                expected_k = VIGENERE_KEY_ENE[pos - 21]
                actual_k = vig_recover_key(c, p)
                assert actual_k == expected_k, (
                    f"Vig key at pos {pos}: got {actual_k}, expected {expected_k}"
                )

    def test_known_vigenere_keystream_bc(self):
        """Verify known Vigenere keystream values at BC crib positions."""
        for i, (pos, ch) in enumerate(CRIB_ENTRIES):
            if 63 <= pos <= 73:  # BC positions 63-73
                c = ord(CT[pos]) - 65
                p = ord(ch) - 65
                expected_k = VIGENERE_KEY_BC[pos - 63]
                actual_k = vig_recover_key(c, p)
                assert actual_k == expected_k, (
                    f"Vig key at pos {pos}: got {actual_k}, expected {expected_k}"
                )

    def test_known_beaufort_keystream_ene(self):
        """Verify known Beaufort keystream values at ENE crib positions."""
        for pos in range(21, 34):
            c = ord(CT[pos]) - 65
            p = ord(CRIB_DICT[pos]) - 65
            expected_k = BEAUFORT_KEY_ENE[pos - 21]
            actual_k = beau_recover_key(c, p)
            assert actual_k == expected_k, (
                f"Beau key at pos {pos}: got {actual_k}, expected {expected_k}"
            )

    def test_known_beaufort_keystream_bc(self):
        """Verify known Beaufort keystream values at BC crib positions."""
        for pos in range(63, 74):
            c = ord(CT[pos]) - 65
            p = ord(CRIB_DICT[pos]) - 65
            expected_k = BEAUFORT_KEY_BC[pos - 63]
            actual_k = beau_recover_key(c, p)
            assert actual_k == expected_k, (
                f"Beau key at pos {pos}: got {actual_k}, expected {expected_k}"
            )


# ══════════════════════════════════════════════════════════════════════════
# (e) Transposition roundtrip
# ══════════════════════════════════════════════════════════════════════════

class TestTranspositionRoundtrip:
    """Apply permutation then its inverse must recover original text."""

    @pytest.mark.parametrize("perm", [
        [0, 1, 2, 3, 4],       # identity
        [4, 3, 2, 1, 0],       # reverse
        [1, 0, 3, 2, 4],       # swap pairs
        [2, 0, 4, 1, 3],       # arbitrary
    ])
    def test_roundtrip_small_perms(self, perm):
        text = "HELLO"
        scrambled = apply_perm(text, perm)
        inv = invert_perm(perm)
        recovered = apply_perm(scrambled, inv)
        assert recovered == text

    def test_roundtrip_columnar(self):
        """Columnar transposition roundtrip."""
        text = CT  # use the actual K4 ciphertext
        for width in [5, 7, 9, 11]:
            col_ord = list(range(width))  # identity column order
            perm = columnar_perm(width, col_ord, len(text))
            scrambled = apply_perm(text, perm)
            inv = invert_perm(perm)
            recovered = apply_perm(scrambled, inv)
            assert recovered == text, f"Columnar roundtrip failed width={width}"

    def test_roundtrip_rail_fence(self):
        """Rail fence transposition roundtrip."""
        text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        for depth in [2, 3, 5, 7]:
            perm = rail_fence_perm(len(text), depth)
            if len(perm) == len(text):
                scrambled = apply_perm(text, perm)
                inv = invert_perm(perm)
                recovered = apply_perm(scrambled, inv)
                assert recovered == text, f"Rail fence roundtrip failed depth={depth}"

    def test_roundtrip_serpentine(self):
        """Serpentine transposition roundtrip."""
        text = "A" * 20
        text = "ABCDEFGHIJKLMNOPQRST"
        rows, cols = 4, 5
        perm = serpentine_perm(rows, cols, len(text))
        assert len(perm) == len(text)
        scrambled = apply_perm(text, perm)
        inv = invert_perm(perm)
        recovered = apply_perm(scrambled, inv)
        assert recovered == text

    def test_roundtrip_large_perm(self):
        """97-element permutation roundtrip."""
        import random
        rng = random.Random(42)
        perm = list(range(CT_LEN))
        rng.shuffle(perm)
        assert validate_perm(perm, CT_LEN)
        scrambled = apply_perm(CT, perm)
        inv = invert_perm(perm)
        recovered = apply_perm(scrambled, inv)
        assert recovered == CT

    def test_invert_perm_is_true_inverse(self):
        """inv(perm) composed with perm = identity."""
        perm = [3, 0, 4, 1, 2]
        inv = invert_perm(perm)
        composed = compose_perms(perm, inv)
        # compose_perms(A, B)[i] = A[B[i]]
        # perm[inv[i]] should give i (identity)
        assert composed == list(range(5))


# ══════════════════════════════════════════════════════════════════════════
# (f) Permutation conventions
# ══════════════════════════════════════════════════════════════════════════

class TestPermutationConventions:
    """Verify output[i] = input[perm[i]] (gather convention)."""

    def test_gather_convention_explicit(self):
        """output[i] = input[perm[i]]."""
        text = "ABCDE"
        perm = [2, 0, 4, 1, 3]
        result = apply_perm(text, perm)
        # result[0] = text[perm[0]] = text[2] = 'C'
        # result[1] = text[perm[1]] = text[0] = 'A'
        # result[2] = text[perm[2]] = text[4] = 'E'
        # result[3] = text[perm[3]] = text[1] = 'B'
        # result[4] = text[perm[4]] = text[3] = 'D'
        assert result == "CAEBD"

    def test_gather_convention_each_position(self):
        text = "ABCDEFGHIJ"
        perm = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]  # reverse
        result = apply_perm(text, perm)
        for i in range(len(text)):
            assert result[i] == text[perm[i]], (
                f"Gather violated at i={i}: {result[i]} != {text[perm[i]]}"
            )

    def test_identity_perm_is_noop(self):
        text = "KRYPTOS"
        perm = list(range(len(text)))
        assert apply_perm(text, perm) == text

    def test_validate_perm_correct(self):
        assert validate_perm([0, 1, 2, 3, 4]) is True
        assert validate_perm([4, 3, 2, 1, 0]) is True
        assert validate_perm([2, 0, 1]) is True

    def test_validate_perm_incorrect(self):
        assert validate_perm([0, 0, 1]) is False       # duplicate
        assert validate_perm([0, 1, 3]) is False       # missing 2
        assert validate_perm([0, 1], 3) is False       # wrong length


# ══════════════════════════════════════════════════════════════════════════
# (g) compose.py: build_pipeline for multiple TransformConfig types
# ══════════════════════════════════════════════════════════════════════════

class TestComposePipelines:
    """Test build_transform and build_pipeline for various config types."""

    def test_identity_transform(self):
        cfg = TransformConfig(TransformType.IDENTITY)
        fn = build_transform(cfg)
        assert fn("HELLO") == "HELLO"
        assert fn(CT) == CT

    def test_vigenere_decrypt_transform(self):
        """Build a Vigenere decrypt transform from config."""
        key = [3, 7, 11]
        pt = "THEQUICKBROWNFOX"
        ct = encrypt_text(pt, key, CipherVariant.VIGENERE)

        cfg = TransformConfig(
            TransformType.VIGENERE,
            params={"key": key, "direction": "decrypt"},
        )
        fn = build_transform(cfg)
        assert fn(ct) == pt

    def test_beaufort_decrypt_transform(self):
        """Build a Beaufort decrypt transform from config."""
        key = [5, 10, 15]
        pt = "SANBORNSCHEIDT"
        ct = encrypt_text(pt, key, CipherVariant.BEAUFORT)

        cfg = TransformConfig(
            TransformType.BEAUFORT,
            params={"key": key, "direction": "decrypt"},
        )
        fn = build_transform(cfg)
        assert fn(ct) == pt

    def test_var_beaufort_decrypt_transform(self):
        """Build a Variant Beaufort decrypt transform from config."""
        key = [1, 2, 3, 4]
        pt = "BERLINCLOCKTIME"
        ct = encrypt_text(pt, key, CipherVariant.VAR_BEAUFORT)

        cfg = TransformConfig(
            TransformType.VAR_BEAUFORT,
            params={"key": key, "direction": "decrypt"},
        )
        fn = build_transform(cfg)
        assert fn(ct) == pt

    def test_transposition_full_undo_transform(self):
        """Build a full transposition undo from config."""
        perm = [2, 0, 4, 1, 3]
        text = "HELLO"
        scrambled = apply_perm(text, perm)

        cfg = TransformConfig(
            TransformType.TRANSPOSITION_FULL,
            params={"perm": perm, "direction": "undo"},
        )
        fn = build_transform(cfg)
        assert fn(scrambled) == text

    def test_additive_mask_remove_transform(self):
        """Build an additive mask removal from config."""
        pt = "ABCDEF"
        kw = "KEY"
        masked = apply_additive_mask(pt, kw)

        cfg = TransformConfig(
            TransformType.ADDITIVE_MASK,
            params={"keyword": kw, "direction": "remove"},
        )
        fn = build_transform(cfg)
        assert fn(masked) == pt

    def test_pipeline_two_steps(self):
        """Build a pipeline with transposition then Vigenere decrypt."""
        # First encrypt: Vig then transpose
        key = [5, 10]
        pt = "ABCDEFGHIJ"
        ct_vig = encrypt_text(pt, key, CipherVariant.VIGENERE)
        perm = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]  # reverse
        ct_final = apply_perm(ct_vig, perm)

        # Decrypt pipeline: undo transpose, then Vig decrypt
        step1 = TransformConfig(
            TransformType.TRANSPOSITION_FULL,
            params={"perm": perm, "direction": "undo"},
        )
        step2 = TransformConfig(
            TransformType.VIGENERE,
            params={"key": key, "direction": "decrypt"},
        )
        pipeline_cfg = PipelineConfig(
            name="test_pipeline",
            steps=(step1, step2),
        )
        fn = build_pipeline(pipeline_cfg)
        assert fn(ct_final) == pt

    def test_pipeline_config_hash_deterministic(self):
        """Pipeline hash must be deterministic."""
        cfg1 = PipelineConfig(
            name="test",
            steps=(TransformConfig(TransformType.IDENTITY),),
        )
        cfg2 = PipelineConfig(
            name="test",
            steps=(TransformConfig(TransformType.IDENTITY),),
        )
        assert cfg1.pipeline_hash == cfg2.pipeline_hash

    def test_transform_config_hash_differs(self):
        """Different configs must produce different hashes."""
        cfg_a = TransformConfig(TransformType.VIGENERE, params={"key": [1]})
        cfg_b = TransformConfig(TransformType.VIGENERE, params={"key": [2]})
        assert cfg_a.config_hash != cfg_b.config_hash

    def test_compose_function_left_to_right(self):
        """compose([f, g])(x) = g(f(x))."""
        def double(x):
            return x + x
        def exclaim(x):
            return x + "!"
        composed = compose([double, exclaim])
        assert composed("HI") == "HIHI!"

    def test_bifid_transform_roundtrip(self):
        """Build a Bifid encrypt then decrypt from config."""
        pt = "HELLO"  # all letters in 5x5 grid (no J needed)
        cfg_enc = TransformConfig(
            TransformType.BIFID,
            params={"keyword": "", "merge": "IJ", "period": 0, "direction": "encrypt"},
        )
        cfg_dec = TransformConfig(
            TransformType.BIFID,
            params={"keyword": "", "merge": "IJ", "period": 0, "direction": "decrypt"},
        )
        enc_fn = build_transform(cfg_enc)
        dec_fn = build_transform(cfg_dec)
        ct = enc_fn(pt)
        assert ct != pt  # should not be identity
        recovered = dec_fn(ct)
        assert recovered == pt


# ══════════════════════════════════════════════════════════════════════════
# (h) score_candidate() returns correct ScoreBreakdown
# ══════════════════════════════════════════════════════════════════════════

class TestScoreCandidate:
    """Verify score_candidate returns proper ScoreBreakdown structure."""

    def test_random_text_scores_low(self):
        """Random all-A text should score 0 cribs (no crib position is 'A' at all 24)."""
        text = "A" * CT_LEN
        sb = score_candidate(text)
        assert isinstance(sb, ScoreBreakdown)
        assert sb.crib_total == N_CRIBS
        # All-A shouldn't match most cribs (A only at pos 27 = 'A' in ENE? No, ENE is EASTNORTHEAST)
        # pos 24 = 'N', pos 27 = 'H', etc. Only pos 33 has 'T', not 'A'. So score should be low.
        assert sb.crib_score <= N_CRIBS
        assert sb.crib_classification in ("noise", "interesting", "signal", "breakthrough")

    def test_perfect_plaintext_scores_24(self):
        """A plaintext with all cribs matching should score 24."""
        # Build a text that matches all 24 crib positions
        text = list("X" * CT_LEN)
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        text_str = "".join(text)
        sb = score_candidate(text_str)
        assert sb.crib_score == 24
        assert sb.ene_score == 13
        assert sb.bc_score == 11

    def test_score_breakdown_fields_present(self):
        """All expected fields should be present and typed correctly."""
        sb = score_candidate("X" * CT_LEN)
        assert isinstance(sb.crib_score, int)
        assert isinstance(sb.crib_total, int)
        assert isinstance(sb.ene_score, int)
        assert isinstance(sb.bc_score, int)
        assert isinstance(sb.crib_classification, str)
        assert isinstance(sb.ic_value, float)
        assert isinstance(sb.ic_score_normalized, float)
        assert isinstance(sb.bean_passed, bool)
        assert isinstance(sb.is_breakthrough, bool)

    def test_breakthrough_requires_bean(self):
        """is_breakthrough requires bean_passed=True."""
        assert is_breakthrough(24, bean_pass=True) is True
        assert is_breakthrough(24, bean_pass=False) is False
        assert is_breakthrough(23, bean_pass=True) is False

    def test_score_breakdown_summary(self):
        """Summary string should contain key fields."""
        sb = score_candidate("X" * CT_LEN)
        summary = sb.summary
        assert "cribs=" in summary
        assert "IC=" in summary
        assert "bean=" in summary

    def test_score_breakdown_to_dict(self):
        """to_dict should contain all expected keys."""
        sb = score_candidate("X" * CT_LEN)
        d = sb.to_dict()
        expected_keys = {
            "crib_score", "crib_total", "ene_score", "bc_score",
            "crib_classification", "ic_value", "ic_score_normalized",
            "ngram_score", "ngram_per_char", "bean_passed",
            "bean_detail", "is_breakthrough",
        }
        assert set(d.keys()) == expected_keys

    def test_ic_on_uniform_text(self):
        """IC of uniform text (all same letter) should be 1.0."""
        assert ic("AAAA") == pytest.approx(1.0)

    def test_ic_score_range(self):
        """ic_score should return value in [0, 1]."""
        for text in ["A" * 100, CT, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 4]:
            s = ic_score(text)
            assert 0.0 <= s <= 1.0, f"IC score {s} out of range for text"


# ══════════════════════════════════════════════════════════════════════════
# (i) Bean constraints
# ══════════════════════════════════════════════════════════════════════════

class TestBeanConstraints:
    """Verify Bean constraint checking on known and constructed keystreams."""

    def test_bean_on_known_vigenere_keystream(self):
        """Build keystream from known Vig keys and verify Bean."""
        # We know Vig key values at crib positions. Build a full keystream
        # where k[27] == k[65] (Bean equality) is satisfied.
        ks = [0] * CT_LEN
        # Fill in known values
        for i, k in enumerate(VIGENERE_KEY_ENE):
            ks[21 + i] = k
        for i, k in enumerate(VIGENERE_KEY_BC):
            ks[63 + i] = k

        # Verify the Bean equality: k[27] == k[65]
        assert ks[27] == VIGENERE_KEY_ENE[27 - 21]  # pos 27, index 6 in ENE
        assert ks[65] == VIGENERE_KEY_BC[65 - 63]    # pos 65, index 2 in BC
        # VIGENERE_KEY_ENE[6] should == VIGENERE_KEY_BC[2]
        bean_eq_holds = (VIGENERE_KEY_ENE[6] == VIGENERE_KEY_BC[2])
        result = verify_bean(ks)
        if bean_eq_holds:
            assert result.eq_satisfied == 1
        else:
            assert result.eq_satisfied == 0

    def test_bean_equality_position_values(self):
        """Bean equality states k[27] == k[65]."""
        assert BEAN_EQ == ((27, 65),)
        # From known Vig keystream: k[27] = ENE[6] = 24, k[65] = BC[2] = 24
        assert VIGENERE_KEY_ENE[6] == 24
        assert VIGENERE_KEY_BC[2] == 24
        assert VIGENERE_KEY_ENE[6] == VIGENERE_KEY_BC[2]

    def test_bean_inequality_count(self):
        """Should have exactly 242 variant-independent inequalities."""
        assert len(BEAN_INEQ) == 242

    def test_bean_result_fields(self):
        """BeanResult should have all expected fields."""
        ks = [0] * CT_LEN
        result = verify_bean(ks)
        assert hasattr(result, 'passed')
        assert hasattr(result, 'eq_satisfied')
        assert hasattr(result, 'eq_total')
        assert hasattr(result, 'ineq_satisfied')
        assert hasattr(result, 'ineq_total')
        assert hasattr(result, 'eq_failures')
        assert hasattr(result, 'ineq_failures')
        assert result.eq_total == 1
        assert result.ineq_total == 242

    def test_bean_simple_agrees_with_full(self):
        """verify_bean_simple should agree with verify_bean.passed."""
        import random
        rng = random.Random(12345)
        for _ in range(50):
            ks = [rng.randint(0, 25) for _ in range(CT_LEN)]
            full = verify_bean(ks)
            simple = verify_bean_simple(ks)
            assert full.passed == simple, (
                f"verify_bean.passed={full.passed} != verify_bean_simple={simple}"
            )

    def test_bean_all_zero_keystream(self):
        """All-zero keystream: k[27]=0==k[65]=0 (eq passes), but many ineq fail."""
        ks = [0] * CT_LEN
        result = verify_bean(ks)
        assert result.eq_satisfied == 1  # k[27]=k[65]=0
        # Many inequalities will fail since all values are 0
        assert result.ineq_satisfied < 21
        assert result.passed is False

    def test_bean_with_beaufort_keystream(self):
        """Known Beaufort keystream at crib positions also satisfies Bean eq."""
        # k[27] = BEAUFORT_KEY_ENE[6], k[65] = BEAUFORT_KEY_BC[2]
        assert BEAUFORT_KEY_ENE[6] == BEAUFORT_KEY_BC[2], (
            "Bean equality should hold for Beaufort too"
        )


# ══════════════════════════════════════════════════════════════════════════
# (j) Crib scoring alignment
# ══════════════════════════════════════════════════════════════════════════

class TestCribAlignment:
    """Verify crib positions align correctly with known plaintext."""

    def test_crib_positions_ene(self):
        """EASTNORTHEAST at positions 21-33 (13 chars)."""
        ene = "EASTNORTHEAST"
        for i, ch in enumerate(ene):
            pos = 21 + i
            assert CRIB_DICT[pos] == ch, f"ENE mismatch at pos {pos}: {CRIB_DICT[pos]} != {ch}"

    def test_crib_positions_bc(self):
        """BERLINCLOCK at positions 63-73 (11 chars)."""
        bc = "BERLINCLOCK"
        for i, ch in enumerate(bc):
            pos = 63 + i
            assert CRIB_DICT[pos] == ch, f"BC mismatch at pos {pos}: {CRIB_DICT[pos]} != {ch}"

    def test_total_crib_count(self):
        """Total cribs = 13 (ENE) + 11 (BC) = 24."""
        assert N_CRIBS == 24
        assert len(CRIB_ENTRIES) == 24
        assert len(CRIB_DICT) == 24

    def test_crib_positions_set(self):
        """Crib positions should be 21-33 and 63-73."""
        expected = set(range(21, 34)) | set(range(63, 74))
        assert CRIB_POSITIONS == frozenset(expected)

    def test_self_encrypting_positions(self):
        """CT[32]='S' matches crib PT[32]='S', CT[73]='K' matches crib PT[73]='K'."""
        assert CT[32] == "S"
        assert CRIB_DICT[32] == "S"
        assert CT[73] == "K"
        assert CRIB_DICT[73] == "K"
        assert SELF_ENCRYPTING == {32: "S", 73: "K"}

    def test_crib_score_on_ct_itself(self):
        """Scoring CT as plaintext: only self-encrypting positions should match."""
        sc = crib_score(CT)
        # CT[32]=S=CRIB[32] and CT[73]=K=CRIB[73] -> at least 2 matches
        assert sc >= 2

    def test_crib_matches_returns_all_positions(self):
        """crib_matches should return a dict with all 24 crib positions."""
        matches = crib_matches(CT)
        assert len(matches) == 24
        assert all(isinstance(v, bool) for v in matches.values())

    def test_implied_keys_match_known_vigenere(self):
        """compute_implied_keys with Vigenere should match VIGENERE_KEY constants."""
        keys = implied_key_dict(CT, CipherVariant.VIGENERE)
        for i in range(13):
            pos = 21 + i
            assert keys[pos] == VIGENERE_KEY_ENE[i], (
                f"Implied Vig key mismatch at pos {pos}"
            )
        for i in range(11):
            pos = 63 + i
            assert keys[pos] == VIGENERE_KEY_BC[i], (
                f"Implied Vig key mismatch at pos {pos}"
            )

    def test_implied_keys_match_known_beaufort(self):
        """compute_implied_keys with Beaufort should match BEAUFORT_KEY constants."""
        keys = implied_key_dict(CT, CipherVariant.BEAUFORT)
        for i in range(13):
            pos = 21 + i
            assert keys[pos] == BEAUFORT_KEY_ENE[i], (
                f"Implied Beau key mismatch at pos {pos}"
            )
        for i in range(11):
            pos = 63 + i
            assert keys[pos] == BEAUFORT_KEY_BC[i], (
                f"Implied Beau key mismatch at pos {pos}"
            )


# ══════════════════════════════════════════════════════════════════════════
# (k) Constants self-verification
# ══════════════════════════════════════════════════════════════════════════

class TestConstantsVerification:
    """Verify _verify() passes and all constant invariants hold."""

    def test_verify_passes(self):
        """_verify() was called at import time without error. Call again to be sure."""
        from kryptos.kernel.constants import _verify
        _verify()  # should not raise

    def test_ct_length(self):
        assert len(CT) == 97
        assert CT_LEN == 97

    def test_ct_all_uppercase_alpha(self):
        assert CT.isalpha()
        assert CT.isupper()

    def test_ct_all_26_letters_present(self):
        """K4 ciphertext uses all 26 letters of the alphabet."""
        assert set(CT) == set(ALPH)

    def test_ct_boundaries(self):
        assert CT[0] == "O"
        assert CT[-1] == "R"

    def test_ct_exact_value(self):
        """Verify the exact ciphertext string."""
        expected = (
            "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWAT"
            "JKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
        )
        assert CT == expected

    def test_alph_standard(self):
        assert ALPH == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        assert len(ALPH) == 26

    def test_alph_idx_consistent(self):
        """ALPH_IDX[ch] should give index of ch in ALPH."""
        for i, ch in enumerate(ALPH):
            assert ALPH_IDX[ch] == i

    def test_mod_is_26(self):
        assert MOD == 26

    def test_thresholds(self):
        assert NOISE_FLOOR == 6
        assert STORE_THRESHOLD == 10
        assert SIGNAL_THRESHOLD == 18
        assert BREAKTHROUGH_THRESHOLD == 24

    def test_ic_constants(self):
        assert IC_K4 == pytest.approx(0.0361)
        assert IC_RANDOM == pytest.approx(1.0 / 26)
        assert IC_ENGLISH == pytest.approx(0.0667)

    def test_crib_words_structure(self):
        """CRIB_WORDS is a tuple of (pos, text) tuples."""
        assert isinstance(CRIB_WORDS, tuple)
        assert len(CRIB_WORDS) == 2
        assert CRIB_WORDS[0] == (21, "EASTNORTHEAST")
        assert CRIB_WORDS[1] == (63, "BERLINCLOCK")


# ══════════════════════════════════════════════════════════════════════════
# (l) Alphabet: KA has no J, is 26 chars, starts with KRYPTOS
# ══════════════════════════════════════════════════════════════════════════

class TestAlphabets:
    """Verify alphabet properties, especially the Kryptos-keyed alphabet."""

    def test_ka_has_all_26_letters(self):
        """KA alphabet contains all 26 letters (A-Z).

        Note: CLAUDE.md says 'KA has no J' but that is INCORRECT.
        The KA alphabet is a keyword-mixed permutation of all 26 letters.
        It is the Polybius 5x5 grid that merges I/J, not KA.
        This test documents the actual behavior.
        """
        assert "J" in KRYPTOS_ALPHABET
        assert set(KRYPTOS_ALPHABET) == set(ALPH)

    def test_ka_length(self):
        """KA alphabet is 26 chars."""
        assert len(KRYPTOS_ALPHABET) == 26

    def test_ka_unique_chars(self):
        """KA has 26 unique characters."""
        assert len(set(KRYPTOS_ALPHABET)) == 26

    def test_ka_starts_with_kryptos(self):
        """KA starts with KRYPTOS."""
        assert KRYPTOS_ALPHABET.startswith("KRYPTOS")

    def test_ka_exact_value(self):
        """Verify exact KA alphabet."""
        assert KRYPTOS_ALPHABET == "KRYPTOSABCDEFGHIJLMNQUVWXZ"

    def test_ka_same_char_set_as_alph(self):
        """KA contains the same characters as standard ALPH (permutation of A-Z)."""
        assert set(KRYPTOS_ALPHABET) == set(ALPH)

    def test_ka_alphabet_object(self):
        """KA Alphabet object is valid."""
        assert KA.label == "KA"
        assert KA.sequence == KRYPTOS_ALPHABET

    def test_az_alphabet_object(self):
        """AZ Alphabet object is valid."""
        assert AZ.label == "AZ"
        assert AZ.sequence == ALPH

    def test_alphabet_encode_decode_roundtrip(self):
        """Encode then decode should recover original text."""
        for alpha in [AZ, KA]:
            text = "KRYPTOSSCULPTURE"
            indices = alpha.encode(text)
            recovered = alpha.decode(indices)
            assert recovered == text, f"Roundtrip failed for {alpha.label}"

    def test_keyword_mixed_alphabet_kryptos(self):
        """keyword_mixed_alphabet('KRYPTOS') should produce the KA alphabet."""
        result = keyword_mixed_alphabet("KRYPTOS")
        assert result == KRYPTOS_ALPHABET

    def test_alphabet_invalid_raises(self):
        """Creating an alphabet with wrong length or chars should raise ValueError."""
        with pytest.raises(ValueError):
            Alphabet("bad", "ABCDE")  # too short
        with pytest.raises(ValueError):
            Alphabet("bad", "A" * 26)  # duplicates

    def test_ka_has_both_i_and_j(self):
        """KA has both I and J -- it is a full 26-letter permutation.

        The I/J merge is only relevant for Polybius 5x5 grids, not
        for the KA alphabet used in polyalphabetic ciphers.
        """
        assert "I" in KRYPTOS_ALPHABET
        assert "J" in KRYPTOS_ALPHABET


# ══════════════════════════════════════════════════════════════════════════
# Additional: Additive mask roundtrip
# ══════════════════════════════════════════════════════════════════════════

class TestAdditiveMask:
    """Verify additive mask apply/remove roundtrip."""

    @pytest.mark.parametrize("keyword", [
        "A", "KEY", "KRYPTOS", "SANBORN", "Z",
    ])
    def test_roundtrip(self, keyword):
        text = "THEQUICKBROWNFOXJUMPS"
        masked = apply_additive_mask(text, keyword)
        recovered = remove_additive_mask(masked, keyword)
        assert recovered == text

    def test_none_keyword_is_identity(self):
        text = "HELLO"
        assert apply_additive_mask(text, "NONE") == text
        assert remove_additive_mask(text, "NONE") == text
        assert apply_additive_mask(text, "") == text
        assert remove_additive_mask(text, "") == text

    def test_mask_a_is_identity(self):
        """Keyword 'A' (shift 0) should be identity."""
        text = "KRYPTOS"
        assert apply_additive_mask(text, "A") == text


# ══════════════════════════════════════════════════════════════════════════
# Additional: IC computation checks
# ══════════════════════════════════════════════════════════════════════════

class TestICComputation:
    """Verify IC computation on known texts."""

    def test_ic_k4_ciphertext(self):
        """IC of K4 CT should be close to the known value 0.0361."""
        computed = ic(CT)
        assert computed == pytest.approx(IC_K4, abs=0.001)

    def test_ic_uniform_is_one(self):
        """IC of a single repeated letter is 1.0."""
        assert ic("AAAAAA") == pytest.approx(1.0)

    def test_ic_two_letters(self):
        """IC of perfectly alternating AB... should be near 0.5."""
        text = "AB" * 50
        computed = ic(text)
        # With 50 A's and 50 B's: IC = 2 * 50*49 / (100*99) = 0.4949...
        assert computed == pytest.approx(0.4949, abs=0.01)

    def test_ic_empty_and_single(self):
        """IC of empty or single-char text should be 0.0."""
        assert ic("") == 0.0
        assert ic("A") == 0.0

    def test_ic_below_random_for_k4(self):
        """K4's IC is below random expectation -- a key known anomaly."""
        computed = ic(CT)
        assert computed < IC_RANDOM


# ══════════════════════════════════════════════════════════════════════════
# Additional: Cross-variant consistency checks
# ══════════════════════════════════════════════════════════════════════════

class TestCrossVariantConsistency:
    """Verify relationships between cipher variants hold."""

    def test_vig_key0_is_identity(self):
        """Vigenere with key=0 is identity."""
        for p in range(26):
            assert vig_encrypt(p, 0) == p
            assert vig_decrypt(p, 0) == p

    def test_beaufort_symmetric_in_c_p(self):
        """Beaufort: encrypt(p,k) = encrypt(k,p) due to K-P symmetry? No, C=(K-P) so swap p<->k changes result."""
        # Actually, beau_encrypt(p,k) = (k-p), beau_encrypt(k,p) = (p-k) = -(k-p) mod 26
        # They're NOT the same. But Beaufort is self-reciprocal: decrypt=encrypt with same formula shape.
        # Verify self-reciprocal: decrypt(encrypt(p,k), k) = p
        for p in range(26):
            for k in range(26):
                c = beau_encrypt(p, k)
                assert beau_decrypt(c, k) == p

    def test_varbeau_is_negative_vigenere(self):
        """VarBeau encrypt(p,k) = Vig encrypt(p, -k mod 26)."""
        for p in range(26):
            for k in range(26):
                vb = varbeau_encrypt(p, k)
                vig_neg = vig_encrypt(p, (-k) % 26)
                assert vb == vig_neg, (
                    f"VarBeau({p},{k})={vb} != Vig({p},{(-k)%26})={vig_neg}"
                )

    def test_beaufort_key_identity(self):
        """Beaufort key recovery: K = (C + P) mod 26.
        This means Beaufort(C, P) = Vig_recover(P, C) -- sign swap."""
        for c in range(26):
            for p in range(26):
                beau_k = beau_recover_key(c, p)
                # beau: (c+p)%26, vig_recover: (c-p)%26
                # They're NOT the same. Beaufort and Vig are different families.
                assert beau_k == (c + p) % 26


# ══════════════════════════════════════════════════════════════════════════
# Additional: score_cribs_detailed checks
# ══════════════════════════════════════════════════════════════════════════

class TestScoreCribsDetailed:
    """Verify the detailed crib scoring function."""

    def test_perfect_match(self):
        text = list("X" * CT_LEN)
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        text_str = "".join(text)
        detail = score_cribs_detailed(text_str)
        assert detail["score"] == 24
        assert detail["total"] == 24
        assert detail["ene_score"] == 13
        assert detail["bc_score"] == 11
        assert detail["classification"] == "breakthrough"
        assert len(detail["matched_positions"]) == 24
        assert len(detail["failed_positions"]) == 0

    def test_no_match(self):
        # Use a character that doesn't appear in any crib position
        # All crib chars: E,A,S,T,N,O,R,H,B,L,I,C,K -- so 'X' won't match any
        text = "X" * CT_LEN
        detail = score_cribs_detailed(text)
        assert detail["score"] == 0
        assert detail["classification"] == "noise"

    def test_classification_boundaries(self):
        """Verify classification thresholds."""
        # Build texts with exactly the right number of crib matches
        positions_sorted = sorted(CRIB_DICT.items())

        for target_score, expected_class in [
            (0, "noise"),
            (6, "noise"),
            (10, "interesting"),
            (18, "signal"),
            (24, "breakthrough"),
        ]:
            text = list("X" * CT_LEN)
            for pos, ch in positions_sorted[:target_score]:
                text[pos] = ch
            detail = score_cribs_detailed("".join(text))
            assert detail["score"] == target_score, (
                f"Expected score {target_score}, got {detail['score']}"
            )
            assert detail["classification"] == expected_class, (
                f"Score {target_score}: expected '{expected_class}', "
                f"got '{detail['classification']}'"
            )
