"""Tests for constraint checking — cribs and Bean."""
import pytest

from kryptos.kernel.constants import (
    CT, CRIB_DICT, CRIB_ENTRIES, N_CRIBS, MOD,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.constraints.crib import (
    crib_score, crib_matches, compute_implied_keys, implied_key_dict,
    periodicity_score, best_periodicity, check_vimark_consistency,
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
        assert result.ineq_total == 242

    def test_bean_simple_matches_full(self):
        ks = list(range(97))
        full = verify_bean(ks)
        simple = verify_bean_simple(ks)
        assert full.passed == simple

    def test_bean_all_zeros_fails(self):
        """All-zero keystream fails Bean inequalities (k[a]==k[b] for all)."""
        ks = [0] * 97
        assert not verify_bean_simple(ks)

    def test_bean_from_primer_roundtrip(self):
        """verify_bean_from_primer should produce same result as manual expand+verify."""
        primer = (1, 2, 3, 4, 5)
        result_manual = verify_bean(expand_keystream_vimark(primer))
        result_auto = verify_bean_from_primer(primer)
        assert result_manual.passed == result_auto.passed
        assert result_manual.eq_satisfied == result_auto.eq_satisfied
        assert result_manual.ineq_satisfied == result_auto.ineq_satisfied

    def test_vimark_recurrence_all_periods(self):
        """expand_keystream_vimark recurrence holds for periods 2-10."""
        for period in range(2, 11):
            primer = tuple(range(period))
            ks = expand_keystream_vimark(primer, 97)
            assert len(ks) == 97
            for i in range(period, 97):
                expected = (ks[i - period] + ks[i - (period - 1)]) % MOD
                assert ks[i] == expected, (
                    f"Recurrence failed at period={period}, i={i}: "
                    f"ks[{i}]={ks[i]} != ({ks[i-period]}+{ks[i-(period-1)]})%26={expected}"
                )

    def test_vimark_rejects_period_1(self):
        """expand_keystream_vimark raises ValueError for period < 2."""
        import pytest
        with pytest.raises(ValueError, match="period >= 2"):
            expand_keystream_vimark((0,), 97)


class TestVimarkConsistency:
    """Tests for check_vimark_consistency — the core crib-matching function."""

    def test_perfect_periodic_key_scores_24(self):
        """A perfectly periodic keystream at the right period should score 24/24."""
        # Build implied keys from CT using Vigenere
        implied = compute_implied_keys(CT, CipherVariant.VIGENERE)
        # At period 97, every position is unique — trivially consistent
        n, total, primer = check_vimark_consistency(implied, 97)
        assert n == N_CRIBS
        # But primer should be None (not all 97 residues are filled)
        assert primer is None

    def test_identity_period_1(self):
        """Period 1: all key values must be identical to be consistent."""
        # With period 1, all values go to residue 0
        implied = [(0, 5), (1, 5), (2, 5)]
        n, total, primer = check_vimark_consistency(implied, 1)
        assert n == 3  # All agree

    def test_conflicting_values_counted(self):
        """Majority voting should count only the most common value per residue."""
        # Period 2: residue 0 has [5, 5, 7], residue 1 has [3, 3]
        implied = [(0, 5), (2, 5), (4, 7), (1, 3), (3, 3)]
        n, total, primer = check_vimark_consistency(implied, 2)
        # Residue 0: majority=5 with count=2, residue 1: majority=3 with count=2
        assert n == 4  # 2 + 2

    def test_empty_implied_keys(self):
        """Empty implied keys should produce score 0."""
        n, total, primer = check_vimark_consistency([], 5)
        assert n == 0
        assert primer is None
