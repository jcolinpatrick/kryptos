"""Tests for bench.generate — cipher correctness and deterministic generation."""
from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from bench.generate import (
    _caesar_encrypt,
    _affine_encrypt,
    _atbash_encrypt,
    _vigenere_encrypt,
    _rail_fence_encrypt,
    _columnar_encrypt,
    _keyword_to_order,
    _simple_sub_encrypt,
    _random_sub_perm,
    _sub_perm_to_key,
    _insert_nulls,
    _load_corpus,
    generate_suite,
    write_suite,
    AFFINE_VALID_A,
)


# ── Cipher correctness ──────────────────────────────────────────────────

class TestCaesar:
    def test_rot13(self):
        assert _caesar_encrypt("HELLO", 13) == "URYYB"

    def test_rot1(self):
        assert _caesar_encrypt("ABC", 1) == "BCD"

    def test_rot25(self):
        assert _caesar_encrypt("B", 25) == "A"

    def test_roundtrip(self):
        pt = "THEQUICKBROWNFOX"
        for shift in range(1, 26):
            ct = _caesar_encrypt(pt, shift)
            recovered = _caesar_encrypt(ct, 26 - shift)
            assert recovered == pt, f"Failed at shift={shift}"

    def test_identity(self):
        assert _caesar_encrypt("HELLO", 0) == "HELLO"


class TestAffine:
    def test_identity(self):
        assert _affine_encrypt("HELLO", 1, 0) == "HELLO"

    def test_shift_only(self):
        # a=1, b=3 is Caesar+3
        assert _affine_encrypt("ABC", 1, 3) == "DEF"

    def test_known_value(self):
        # a=5, b=8: E(x) = (5x + 8) mod 26
        # A(0) → 8 → I, B(1) → 13 → N, C(2) → 18 → S
        assert _affine_encrypt("ABC", 5, 8) == "INS"

    def test_valid_a_values_coprime(self):
        from math import gcd
        for a in AFFINE_VALID_A:
            assert gcd(a, 26) == 1, f"a={a} is not coprime with 26"


class TestAtbash:
    def test_known(self):
        # A→Z, B→Y, C→X
        assert _atbash_encrypt("ABC") == "ZYX"

    def test_involution(self):
        pt = "THEQUICKBROWNFOX"
        assert _atbash_encrypt(_atbash_encrypt(pt)) == pt


class TestVigenere:
    def test_known_textbook(self):
        # Classic Sinkov example: key DECEPTIVE
        pt = "WEAREDISCOVEREDSAVEYOURSELF"
        key = "DECEPTIVE"
        ct = _vigenere_encrypt(pt, key)
        assert ct == "ZICVTWQNGRZGVTWAVZHCQYGLMGJ"

    def test_single_char_key(self):
        # Key "D" (shift 3) = Caesar+3
        assert _vigenere_encrypt("ABC", "D") == "DEF"

    def test_roundtrip(self):
        pt = "HELLOWORLD"
        key = "KEY"
        ct = _vigenere_encrypt(pt, key)
        # Decrypt: shift by 26-k
        key_inv = "".join(chr((26 - (ord(c) - 65)) % 26 + 65) for c in key)
        recovered = _vigenere_encrypt(ct, key_inv)
        assert recovered == pt


class TestRailFence:
    def test_depth_2(self):
        # HELLO with 2 rails: H.L.O / .E.L. → HLOEL
        assert _rail_fence_encrypt("HELLO", 2) == "HLOEL"

    def test_depth_3(self):
        # WEAREDISCOVERED with 3 rails:
        # W...R...S...R..
        # .E.A.E.I.C.V.E.E.D
        # ..A...D...O...
        # Wait, let me compute more carefully for a short string
        # ABCDEF depth 3:
        # A...E. → A,E
        # .B.D.F → B,D,F
        # ..C... → C
        # → AEBDFC
        assert _rail_fence_encrypt("ABCDEF", 3) == "AEBDFC"

    def test_depth_1_identity(self):
        assert _rail_fence_encrypt("HELLO", 1) == "HELLO"

    def test_depth_ge_length_identity(self):
        assert _rail_fence_encrypt("ABC", 5) == "ABC"


class TestColumnar:
    def test_known_order(self):
        # "ABCDEF" with col_order [1, 0, 2] (3 cols, column 1 first)
        # Fill:  A B C | D E F
        # Col 0: A,D  Col 1: B,E  Col 2: C,F
        # Read by rank: rank 0 → col 1 (B,E), rank 1 → col 0 (A,D), rank 2 → col 2 (C,F)
        assert _columnar_encrypt("ABCDEF", [1, 0, 2]) == "BEADCF"

    def test_keyword_order(self):
        order = _keyword_to_order("ZEBRA")
        # Z=4, E=1, B=0, R=3, A=2 → sorted: A(4)=0, B(2)=1, E(1)=2, R(3)=3, Z(0)=4
        # Wait: sorted by (char, idx): (A,4)→0, (B,2)→1, (E,1)→2, (R,3)→3, (Z,0)→4
        # order[4]=0, order[2]=1, order[1]=2, order[3]=3, order[0]=4
        assert order == [4, 2, 1, 3, 0]


class TestSimpleSubstitution:
    def test_identity_perm(self):
        perm = list(range(26))
        assert _simple_sub_encrypt("HELLO", perm) == "HELLO"

    def test_rot13_perm(self):
        perm = [(i + 13) % 26 for i in range(26)]
        assert _simple_sub_encrypt("HELLO", perm) == "URYYB"

    def test_perm_to_key_roundtrip(self):
        rng = random.Random(42)
        perm = _random_sub_perm(rng)
        key = _sub_perm_to_key(perm)
        assert len(key) == 26
        assert len(set(key)) == 26  # bijection

    def test_random_perm_is_valid(self):
        rng = random.Random(99)
        perm = _random_sub_perm(rng)
        assert sorted(perm) == list(range(26))


class TestNullInsertion:
    def test_no_nulls_at_rate_0(self):
        rng = random.Random(0)
        result, _ = _insert_nulls("HELLO", rng, rate=0.0)
        assert result == "HELLO"

    def test_original_chars_preserved(self):
        rng = random.Random(42)
        pt = "THEQUICKBROWNFOX"
        result, _ = _insert_nulls(pt, rng, rate=0.3)
        # All original chars must appear in order
        j = 0
        for ch in result:
            if j < len(pt) and ch == pt[j]:
                j += 1
        assert j == len(pt), "Original chars not all present in order"


# ── Corpus ───────────────────────────────────────────────────────────────

class TestCorpus:
    def test_loads(self):
        corpus = _load_corpus()
        assert len(corpus) > 1000
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in corpus)

    def test_no_spaces_or_punctuation(self):
        corpus = _load_corpus()
        assert " " not in corpus
        assert "." not in corpus


# ── Suite generation ─────────────────────────────────────────────────────

class TestGenerate:
    def test_deterministic(self):
        s1 = generate_suite(tiers=[0], n=5, seed=123)
        s2 = generate_suite(tiers=[0], n=5, seed=123)
        assert s1 == s2

    def test_different_seeds_differ(self):
        s1 = generate_suite(tiers=[0], n=5, seed=1)
        s2 = generate_suite(tiers=[0], n=5, seed=2)
        assert s1 != s2

    def test_tier_count(self):
        s = generate_suite(tiers=[0, 1], n=10, seed=42)
        assert len(s[0]) == 10
        assert len(s[1]) == 10

    def test_all_tiers(self):
        s = generate_suite(tiers=[0, 1, 2, 3], n=5, seed=42)
        assert set(s.keys()) == {0, 1, 2, 3}
        for tier_cases in s.values():
            assert len(tier_cases) == 5

    def test_case_ids_unique(self):
        s = generate_suite(tiers=[0, 1, 2, 3], n=10, seed=42)
        all_ids = [c["case_id"] for cases in s.values() for c in cases]
        assert len(all_ids) == len(set(all_ids))

    def test_required_fields_present(self):
        s = generate_suite(tiers=[0], n=3, seed=42)
        for case in s[0]:
            assert "case_id" in case
            assert "ciphertext" in case
            assert "script" in case
            assert "expected_plaintext" in case
            assert "expected_key" in case
            assert "expected_family" in case

    def test_ciphertext_differs_from_plaintext(self):
        s = generate_suite(tiers=[0], n=20, seed=42)
        for case in s[0]:
            # Atbash with all-N input could theoretically be same, but very unlikely
            # Just check they're not ALL identical
            if case["label"] != "Atbash" or case["ciphertext"] != case["expected_plaintext"]:
                continue
        # At least some should differ
        diffs = sum(1 for c in s[0] if c["ciphertext"] != c["expected_plaintext"])
        assert diffs > 0

    def test_tier2_short_texts(self):
        s = generate_suite(tiers=[2], n=20, seed=42)
        for case in s[2]:
            assert len(case["expected_plaintext"]) <= 30

    def test_invalid_tier(self):
        with pytest.raises(ValueError, match="Unknown tier"):
            generate_suite(tiers=[5], n=1, seed=42)


class TestWriteSuite:
    def test_write_read_roundtrip(self, tmp_path):
        cases = generate_suite(tiers=[0], n=3, seed=42)[0]
        out_path = tmp_path / "test.jsonl"
        write_suite(cases, out_path)

        # Read back
        lines = out_path.read_text().strip().split("\n")
        assert len(lines) == 3
        for line, orig in zip(lines, cases):
            parsed = json.loads(line)
            assert parsed["case_id"] == orig["case_id"]
            assert parsed["ciphertext"] == orig["ciphertext"]

    def test_creates_parent_dirs(self, tmp_path):
        cases = [{"case_id": "t", "ciphertext": "A", "script": "s.py"}]
        out_path = tmp_path / "deep" / "nested" / "suite.jsonl"
        write_suite(cases, out_path)
        assert out_path.exists()


# ── Cipher verification against kernel (if available) ────────────────────

class TestCipherVsKernel:
    """Cross-check our standalone cipher impls against the kernel."""

    def test_vigenere_vs_kernel(self):
        try:
            from kryptos.kernel.transforms.vigenere import encrypt_text, CipherVariant
        except ImportError:
            pytest.skip("kernel not on path")

        pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        key_str = "KRYPTOS"
        key_nums = [ord(c) - 65 for c in key_str]

        ours = _vigenere_encrypt(pt, key_str)
        kernel = encrypt_text(pt, key_nums, CipherVariant.VIGENERE)
        assert ours == kernel

    def test_rail_fence_vs_kernel(self):
        try:
            from kryptos.kernel.transforms.transposition import rail_fence_perm, apply_perm
        except ImportError:
            pytest.skip("kernel not on path")

        pt = "THEQUICKBROWNFOXJUMPS"
        for depth in [2, 3, 4, 5]:
            ours = _rail_fence_encrypt(pt, depth)
            perm = rail_fence_perm(len(pt), depth)
            kernel = apply_perm(pt, perm)
            assert ours == kernel, f"Mismatch at depth={depth}"

    def test_columnar_vs_kernel(self):
        try:
            from kryptos.kernel.transforms.transposition import columnar_perm, apply_perm
        except ImportError:
            pytest.skip("kernel not on path")

        pt = "THEQUICKBROWNFOXJUMPS"
        col_order = [2, 0, 3, 1]
        ours = _columnar_encrypt(pt, col_order)
        perm = columnar_perm(len(col_order), col_order, len(pt))
        kernel = apply_perm(pt, perm)
        assert ours == kernel
