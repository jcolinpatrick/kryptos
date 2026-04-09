"""Tests for the Atbash kernel transform.

This module is the pinned parametric spec for the
`atbash_substitution_layer` procedure license
(src/kryptos/admissibility/procedure_policy.py). Any change to Atbash
semantics must pass this test file.
"""
from __future__ import annotations

import pytest

from kryptos.kernel.transforms.atbash import (
    decrypt_atbash,
    encrypt_atbash,
)


class TestAtbashInvolution:

    def test_endpoints_swap(self):
        assert encrypt_atbash("A") == "Z"
        assert encrypt_atbash("Z") == "A"

    def test_middle_pair_swaps(self):
        assert encrypt_atbash("M") == "N"
        assert encrypt_atbash("N") == "M"

    def test_full_alphabet_reverses(self):
        assert encrypt_atbash("ABCDEFGHIJKLMNOPQRSTUVWXYZ") == (
            "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        )

    def test_self_reciprocal_on_every_letter(self):
        for ch_val in range(26):
            ch = chr(ord("A") + ch_val)
            assert decrypt_atbash(encrypt_atbash(ch)) == ch
            assert encrypt_atbash(decrypt_atbash(ch)) == ch

    def test_decrypt_alias_matches_encrypt(self):
        # Atbash is self-reciprocal: encrypt and decrypt must be
        # identical functions. This test pins that invariant so a
        # future refactor cannot silently break it.
        sample = "HELLO"
        assert encrypt_atbash(sample) == decrypt_atbash(sample)

    def test_known_word_mapping(self):
        # HELLO -> SVOOL is a canonical Atbash example used in
        # pedagogical sources. If this ever fails, either the
        # alphabet constant is wrong or the involution formula drifted.
        assert encrypt_atbash("HELLO") == "SVOOL"

    def test_kryptos_ct_roundtrip(self):
        # The K4 ciphertext is a 97-char uppercase ASCII string; Atbash
        # must roundtrip it without modification. This is a smoke test,
        # not a claim that K4 IS Atbash-encrypted.
        from kryptos.kernel.constants import CT
        assert decrypt_atbash(encrypt_atbash(CT)) == CT


class TestAtbashParametricSpec:
    """The procedure_policy.py atbash_substitution_layer license pins
    this module as its parametric spec. These tests pin the public
    surface that scripts claiming the license rely on."""

    def test_module_exposes_encrypt_and_decrypt(self):
        from kryptos.kernel.transforms import atbash
        assert callable(atbash.encrypt_atbash)
        assert callable(atbash.decrypt_atbash)

    def test_functions_are_deterministic(self):
        sample = "KRYPTOS"
        assert encrypt_atbash(sample) == encrypt_atbash(sample)

    def test_no_key_parameter(self):
        # Atbash is parameter-free by construction. If someone ever
        # adds a key argument to these functions, this test will
        # become a signature mismatch, which is the right failure
        # mode (it forces a deliberate license-spec update).
        import inspect
        sig = inspect.signature(encrypt_atbash)
        assert list(sig.parameters) == ["plaintext"]
        sig = inspect.signature(decrypt_atbash)
        assert list(sig.parameters) == ["ciphertext"]
