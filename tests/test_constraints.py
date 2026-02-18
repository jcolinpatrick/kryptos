"""Tests for constraint checking — cribs and Bean."""
import pytest

from kryptos.kernel.constants import CT, CRIB_DICT, N_CRIBS, VIGENERE_KEY_ENE, VIGENERE_KEY_BC
from kryptos.kernel.constraints.crib import (
    crib_score, crib_matches, compute_implied_keys, implied_key_dict,
    periodicity_score, best_periodicity,
)
from kryptos.kernel.constraints.bean import (
    verify_bean, verify_bean_simple, expand_keystream_vimark,
    verify_bean_from_primer, BeanResult,
)
from kryptos.kernel.transforms.vigenere import CipherVariant, decrypt_text


class TestCribScore:
    def test_random_text_low_score(self):
        assert crib_score("A" * 97) < 10

    def test_perfect_plaintext(self):
        # Build text that matches all cribs
        text = list("A" * 97)
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        assert crib_score("".join(text)) == N_CRIBS

    def test_ene_only(self):
        text = list("A" * 97)
        for i, ch in enumerate("EASTNORTHEAST"):
            text[21 + i] = ch
        sc = crib_score("".join(text))
        assert sc >= 13  # At least ENE matches

    def test_crib_matches_detail(self):
        text = list("X" * 97)  # X to avoid matching crib 'A' at pos 22/31
        text[21] = "E"
        result = crib_matches("".join(text))
        assert result[21] is True
        assert result[22] is False  # X != A expected


class TestImpliedKeys:
    def test_ct_produces_known_keystream(self):
        """Verify that implied keys from CT match known Vigenere keystream."""
        kv = implied_key_dict(CT, CipherVariant.VIGENERE)
        for i, val in enumerate(VIGENERE_KEY_ENE):
            pos = 21 + i
            assert kv[pos] == val, f"pos {pos}: expected {val}, got {kv[pos]}"
        for i, val in enumerate(VIGENERE_KEY_BC):
            pos = 63 + i
            assert kv[pos] == val, f"pos {pos}: expected {val}, got {kv[pos]}"


class TestPeriodicity:
    def test_periodic_key_detected(self):
        # Create a key with period 5
        key = [1, 2, 3, 4, 5] * 20
        kv = {i: key[i] for i in range(0, 100, 3)}  # Sample positions
        agree, total, contra = periodicity_score(kv, 5)
        assert contra == 0  # Should have no contradictions

    def test_best_period_found(self):
        key = [1, 2, 3, 4] * 25
        kv = {i: key[i] for i in range(0, 97, 2)}
        period, agree, total, contra = best_periodicity(kv)
        assert period == 4


class TestBean:
    def test_verify_known_keystream(self):
        """Bean equality k[27]=k[65] should hold for known keystream."""
        # Build keystream from known values
        kv = implied_key_dict(CT, CipherVariant.VIGENERE)
        # k[27] should equal k[65] = 24
        assert kv[27] == 24
        assert kv[65] == 24

    def test_expand_vimark(self):
        primer = (1, 2, 3, 4, 5)
        ks = expand_keystream_vimark(primer, 20)
        assert len(ks) == 20
        # Verify recurrence: k[i] = k[i-5] + k[i-4] mod 26
        for i in range(5, 20):
            assert ks[i] == (ks[i - 5] + ks[i - 4]) % 26

    def test_bean_result_fields(self):
        ks = [0] * 97
        result = verify_bean(ks)
        assert isinstance(result, BeanResult)
        assert result.eq_total == 1
        assert result.ineq_total == 21

    def test_bean_simple_matches_full(self):
        ks = list(range(97))
        full = verify_bean(ks)
        simple = verify_bean_simple(ks)
        assert full.passed == simple

    def test_bean_all_zeros_fails(self):
        """All-zero keystream fails Bean inequalities (k[a]==k[b] for all)."""
        ks = [0] * 97
        assert not verify_bean_simple(ks)
