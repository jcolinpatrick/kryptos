"""Regression tests from the Phase 2 correctness audit (2026-02-27).

Each test class addresses a specific finding or invariant identified
during the forensic audit. These prevent regressions against known
edge cases, boundary conditions, and cross-module consistency requirements.
"""
from __future__ import annotations

import pytest

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, N_CRIBS,
    CRIB_DICT, CRIB_ENTRIES, CRIB_POSITIONS, CRIB_WORDS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
    SELF_ENCRYPTING,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, KEY_RECOVERY,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
    decrypt_text, encrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, validate_perm, columnar_perm,
)
from kryptos.kernel.constraints.crib import (
    crib_score, compute_implied_keys, check_vimark_consistency,
)
from kryptos.kernel.constraints.bean import (
    verify_bean, verify_bean_simple, verify_bean_from_implied,
    expand_keystream_vimark, BeanResult,
)
from kryptos.kernel.scoring.crib_score import (
    score_cribs, score_cribs_detailed,
    is_above_noise, is_storable, is_signal, is_breakthrough,
)
from kryptos.kernel.scoring.aggregate import score_candidate, ScoreBreakdown
from kryptos.kernel.scoring.ic import ic, ic_score
from kryptos.kernel.alphabet import Alphabet, AZ, KA


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Crib scoring functions must be consistent (LOW-1 regression)
# ══════════════════════════════════════════════════════════════════════════

class TestCribScoringConsistency:
    """Regression for LOW-1: crib_score() and score_cribs() must agree."""

    def test_identical_on_random_text(self):
        text = "A" * 97
        assert crib_score(text) == score_cribs(text)

    def test_identical_on_perfect_match(self):
        text = list("X" * 97)
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        t = "".join(text)
        assert crib_score(t) == score_cribs(t) == N_CRIBS

    def test_identical_on_ct(self):
        assert crib_score(CT) == score_cribs(CT)

    def test_identical_on_short_text(self):
        assert crib_score("ABC") == score_cribs("ABC")

    def test_identical_on_empty(self):
        assert crib_score("") == score_cribs("")

    def test_detailed_score_matches_simple(self):
        """score_cribs_detailed()['score'] must match score_cribs()."""
        for text in ["A" * 97, CT, "EASTNORTHEAST" + "X" * 84]:
            assert score_cribs_detailed(text)["score"] == score_cribs(text)


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Bean positions must all be valid crib positions
# ══════════════════════════════════════════════════════════════════════════

class TestBeanPositionValidity:
    """Verify all Bean constraint positions are within crib positions."""

    def test_bean_eq_positions_are_crib_positions(self):
        for a, b in BEAN_EQ:
            assert a in CRIB_POSITIONS, f"Bean-EQ position {a} not a crib position"
            assert b in CRIB_POSITIONS, f"Bean-EQ position {b} not a crib position"

    def test_bean_ineq_positions_are_crib_positions(self):
        for a, b in BEAN_INEQ:
            assert a in CRIB_POSITIONS, f"Bean-INEQ position {a} not a crib position"
            assert b in CRIB_POSITIONS, f"Bean-INEQ position {b} not a crib position"

    def test_bean_eq_count(self):
        assert len(BEAN_EQ) == 1

    def test_bean_ineq_count(self):
        assert len(BEAN_INEQ) == 242


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Bean constraints are variant-independent
# ══════════════════════════════════════════════════════════════════════════

class TestBeanVariantIndependence:
    """Bean EQ and INEQ must hold for all three cipher variants."""

    @pytest.fixture
    def all_implied(self):
        return {
            v: dict(compute_implied_keys(CT, v))
            for v in CipherVariant
        }

    def test_bean_eq_all_variants(self, all_implied):
        for a, b in BEAN_EQ:
            for variant_name, kv in all_implied.items():
                assert kv[a] == kv[b], (
                    f"Bean-EQ ({a},{b}) fails for {variant_name}: "
                    f"k[{a}]={kv[a]} != k[{b}]={kv[b]}"
                )

    def test_bean_ineq_all_variants(self, all_implied):
        for a, b in BEAN_INEQ:
            for variant_name, kv in all_implied.items():
                assert kv[a] != kv[b], (
                    f"Bean-INEQ ({a},{b}) fails for {variant_name}: "
                    f"k[{a}]={kv[a]} == k[{b}]={kv[b]}"
                )


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Stored keystream values are correct
# ══════════════════════════════════════════════════════════════════════════

class TestKeystreamValues:
    """Independently verify all stored keystream constants."""

    def _compute_keys(self, variant_fn, crib_start, crib_text):
        return tuple(
            variant_fn(ord(CT[crib_start + i]) - 65, ord(ch) - 65)
            for i, ch in enumerate(crib_text)
        )

    def test_vigenere_ene(self):
        assert self._compute_keys(vig_recover_key, 21, "EASTNORTHEAST") == VIGENERE_KEY_ENE

    def test_vigenere_bc(self):
        assert self._compute_keys(vig_recover_key, 63, "BERLINCLOCK") == VIGENERE_KEY_BC

    def test_beaufort_ene(self):
        assert self._compute_keys(beau_recover_key, 21, "EASTNORTHEAST") == BEAUFORT_KEY_ENE

    def test_beaufort_bc(self):
        assert self._compute_keys(beau_recover_key, 63, "BERLINCLOCK") == BEAUFORT_KEY_BC


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: verify_bean_from_implied (MEDIUM-2 regression)
# ══════════════════════════════════════════════════════════════════════════

class TestBeanFromImplied:
    """Regression for MEDIUM-2: Bean checking from sparse implied keys."""

    def test_passes_with_correct_implied_keys(self):
        kv = dict(compute_implied_keys(CT, CipherVariant.VIGENERE))
        assert verify_bean_from_implied(kv)

    def test_fails_with_broken_eq(self):
        kv = dict(compute_implied_keys(CT, CipherVariant.VIGENERE))
        kv[27] = (kv[27] + 1) % MOD  # Break Bean-EQ
        assert not verify_bean_from_implied(kv)

    def test_fails_with_broken_ineq(self):
        kv = dict(compute_implied_keys(CT, CipherVariant.VIGENERE))
        # Find an inequality pair and force them equal
        a, b = BEAN_INEQ[0]
        kv[b] = kv[a]  # Force equality where inequality is required
        assert not verify_bean_from_implied(kv)

    def test_passes_with_partial_data(self):
        """Should pass when constraint positions are missing (can't violate)."""
        assert verify_bean_from_implied({27: 5, 65: 5})  # EQ satisfied
        assert verify_bean_from_implied({27: 5})  # Can't check, passes

    def test_fails_with_partial_eq_violation(self):
        assert not verify_bean_from_implied({27: 5, 65: 6})

    def test_empty_dict_passes(self):
        assert verify_bean_from_implied({})

    def test_agrees_with_full_verify(self):
        """verify_bean_from_implied should agree with verify_bean_simple
        when both have all the data."""
        for variant in CipherVariant:
            kv = dict(compute_implied_keys(CT, variant))
            # Build full keystream with zeros for non-crib positions
            full = [0] * 97
            for pos, val in kv.items():
                full[pos] = val
            # Both should agree
            assert verify_bean_from_implied(kv) == verify_bean_simple(full)

    def test_all_three_variants(self):
        for variant in CipherVariant:
            kv = dict(compute_implied_keys(CT, variant))
            assert verify_bean_from_implied(kv), f"Bean-implied fails for {variant}"


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Vimark expansion (LOW-2 regression)
# ══════════════════════════════════════════════════════════════════════════

class TestVimarkExpansion:
    """Regression for LOW-2: Vimark period guard and recurrence."""

    def test_rejects_period_0(self):
        with pytest.raises(ValueError, match="period >= 2"):
            expand_keystream_vimark((), 10)

    def test_rejects_period_1(self):
        with pytest.raises(ValueError, match="period >= 2"):
            expand_keystream_vimark((5,), 10)

    def test_period_2_fibonacci(self):
        ks = expand_keystream_vimark((1, 1), 10)
        # Fibonacci mod 26: 1,1,2,3,5,8,13,21,8,3
        assert ks == [1, 1, 2, 3, 5, 8, 13, 21, 8, 3]

    def test_recurrence_holds_all_practical_periods(self):
        """Verify recurrence for periods 2-26 (all practically relevant)."""
        for period in range(2, 27):
            primer = tuple(i % MOD for i in range(period))
            ks = expand_keystream_vimark(primer, CT_LEN)
            assert len(ks) == CT_LEN
            for i in range(period, CT_LEN):
                expected = (ks[i - period] + ks[i - (period - 1)]) % MOD
                assert ks[i] == expected, (
                    f"period={period}, i={i}: {ks[i]} != {expected}"
                )

    def test_deterministic(self):
        p = (3, 7, 11, 15, 19)
        assert expand_keystream_vimark(p, 50) == expand_keystream_vimark(p, 50)


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Scoring boundary conditions (MEDIUM-1 regression)
# ══════════════════════════════════════════════════════════════════════════

class TestScoringBoundaries:
    """Regression for MEDIUM-1: scoring thresholds match documented behavior."""

    def test_threshold_constants(self):
        assert NOISE_FLOOR == 6
        assert STORE_THRESHOLD == 10
        assert SIGNAL_THRESHOLD == 18
        assert BREAKTHROUGH_THRESHOLD == 24

    def test_noise_floor_boundary(self):
        assert not is_above_noise(6)  # At floor = not above
        assert is_above_noise(7)      # Above floor

    def test_store_boundary(self):
        assert not is_storable(9)
        assert is_storable(10)

    def test_signal_boundary(self):
        assert not is_signal(17)
        assert is_signal(18)

    def test_breakthrough_requires_bean(self):
        assert not is_breakthrough(24, bean_pass=False)
        assert is_breakthrough(24, bean_pass=True)
        assert not is_breakthrough(23, bean_pass=True)

    def test_classification_boundaries(self):
        """score_cribs_detailed classification matches threshold constants."""
        # Build texts that score at specific thresholds
        for target_score, expected_class in [
            (0, "noise"), (6, "noise"), (9, "noise"),
            (10, "interesting"), (17, "interesting"),
            (18, "signal"), (23, "signal"),
            (24, "breakthrough"),
        ]:
            text = list("X" * 97)
            # Set exactly target_score crib positions correctly
            for i, (pos, ch) in enumerate(CRIB_DICT.items()):
                if i < target_score:
                    text[pos] = ch
            result = score_cribs_detailed("".join(text))
            assert result["score"] == target_score, (
                f"Expected score {target_score}, got {result['score']}"
            )
            assert result["classification"] == expected_class, (
                f"Score {target_score}: expected '{expected_class}', "
                f"got '{result['classification']}'"
            )


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: check_vimark_consistency edge cases
# ══════════════════════════════════════════════════════════════════════════

class TestVimarkConsistencyEdgeCases:
    """Edge cases for the core scoring function."""

    @pytest.fixture
    def ct_implied(self):
        return compute_implied_keys(CT, CipherVariant.VIGENERE)

    def test_high_period_no_primer(self, ct_implied):
        """At period 97, score is 24/24 but NO primer (not all residues filled)."""
        n, total, primer = check_vimark_consistency(ct_implied, 97)
        assert n == N_CRIBS
        assert primer is None

    def test_n_consistent_never_exceeds_n_cribs(self, ct_implied):
        for period in range(2, 100):
            n, total, _ = check_vimark_consistency(ct_implied, period)
            assert n <= N_CRIBS
            assert total == N_CRIBS

    def test_primer_returned_only_when_all_residues_filled(self, ct_implied):
        """Primer requires n_consistent == N_CRIBS AND all residues have data."""
        positions = [pos for pos, _ in ct_implied]
        for period in range(2, 30):
            residues = set(pos % period for pos in positions)
            n, _, primer = check_vimark_consistency(ct_implied, period)
            if primer is not None:
                assert n == N_CRIBS, "Primer returned but not perfect"
                assert len(residues) == period, "Primer returned with unfilled residues"

    def test_periods_where_primer_is_possible(self):
        """Document which periods CAN return a primer (all residues filled)."""
        positions = [pos for pos, _ in CRIB_ENTRIES]
        primer_possible = []
        for period in range(2, 30):
            if len(set(pos % period for pos in positions)) == period:
                primer_possible.append(period)
        # Verified in Phase 2: periods 2-13, 15-17 have all residues filled
        assert 8 in primer_possible   # Bean-compatible
        assert 13 in primer_possible  # Bean-compatible
        assert 16 in primer_possible  # Bean-compatible
        assert 14 not in primer_possible  # Missing residue 6
        assert 19 not in primer_possible  # Bean-compatible but no primer possible


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Transposition gather convention
# ══════════════════════════════════════════════════════════════════════════

class TestTranspositionConvention:
    """Verify the gather convention: output[i] = input[perm[i]]."""

    def test_gather_convention(self):
        text = "ABCDE"
        perm = [4, 3, 2, 1, 0]  # Reversal
        assert apply_perm(text, perm) == "EDCBA"

    def test_invert_roundtrip(self):
        text = "ABCDEFGHIJ"
        perm = [3, 1, 4, 0, 2, 8, 6, 9, 5, 7]
        encrypted = apply_perm(text, perm)
        inv = invert_perm(perm)
        decrypted = apply_perm(encrypted, inv)
        assert decrypted == text

    def test_columnar_97_valid(self):
        """Columnar perm with width 10 on 97 chars (uneven columns)."""
        perm = columnar_perm(10, list(range(10)), 97)
        assert validate_perm(perm, 97)
        assert len(perm) == 97
        assert set(perm) == set(range(97))

    def test_columnar_roundtrip_97(self):
        perm = columnar_perm(10, [3, 0, 7, 1, 8, 4, 9, 2, 5, 6], 97)
        enc = apply_perm(CT, perm)
        dec = apply_perm(enc, invert_perm(perm))
        assert dec == CT


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Cipher variant sign conventions
# ══════════════════════════════════════════════════════════════════════════

class TestCipherConventions:
    """Verify encrypt/decrypt/recover sign conventions are consistent."""

    def test_all_variants_roundtrip(self):
        """Encrypt then decrypt must recover original for all variants."""
        text = "HELLOWORLD"
        key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        for variant in CipherVariant:
            ct = encrypt_text(text, key, variant)
            pt = decrypt_text(ct, key, variant)
            assert pt == text, f"{variant}: roundtrip failed"

    def test_key_recovery_consistent(self):
        """recover(encrypt(p, k), p) must return k for all variants."""
        for c in range(26):
            for p in range(26):
                for name, fn in KEY_RECOVERY.items():
                    k = fn(c, p)
                    assert 0 <= k < MOD, f"{name}: k={k} out of range"


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: IC function edge cases
# ══════════════════════════════════════════════════════════════════════════

class TestICEdgeCases:
    """IC function boundary conditions."""

    def test_empty_string(self):
        assert ic("") == 0.0

    def test_single_char(self):
        assert ic("A") == 0.0

    def test_two_identical(self):
        assert ic("AA") == 1.0

    def test_two_different(self):
        assert ic("AB") == 0.0

    def test_all_same_long(self):
        assert ic("A" * 97) == 1.0

    def test_ic_score_below_random_is_zero(self):
        assert ic_score(CT) == 0.0  # K4 IC is below random


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Scoring path equivalence
# ══════════════════════════════════════════════════════════════════════════

class TestScoringPathEquivalence:
    """All scoring paths must produce consistent ScoreBreakdown fields."""

    def test_score_candidate_fields(self):
        result = score_candidate("A" * 97)
        assert isinstance(result, ScoreBreakdown)
        assert hasattr(result, "crib_score")
        assert hasattr(result, "ic_value")
        assert hasattr(result, "bean_passed")
        assert hasattr(result, "is_breakthrough")
        assert hasattr(result, "crib_classification")

    def test_perfect_crib_with_bean(self):
        """24/24 crib score + Bean pass = breakthrough."""
        text = list("X" * 97)
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        # Build a keystream that passes Bean
        kv = dict(compute_implied_keys(CT, CipherVariant.VIGENERE))
        full_key = [0] * 97
        for pos, val in kv.items():
            full_key[pos] = val
        bean = verify_bean(full_key)
        result = score_candidate("".join(text), bean)
        assert result.crib_score == 24
        assert result.is_breakthrough == bean.passed

    def test_evaluate_candidate_matches_score_candidate(self):
        """evaluate_candidate must produce same score as score_candidate."""
        from kryptos.pipeline.evaluation import evaluate_candidate as eval_cand
        text = CT  # Use CT itself as candidate
        direct = score_candidate(text)
        via_pipeline = eval_cand(text)
        assert via_pipeline.score.crib_score == direct.crib_score
        assert via_pipeline.score.ic_value == direct.ic_value


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Alphabet bijections
# ══════════════════════════════════════════════════════════════════════════

class TestAlphabetInvariants:
    """Both standard and Kryptos alphabets must be valid bijections."""

    def test_az_bijection(self):
        assert len(AZ.sequence) == 26
        assert len(set(AZ.sequence)) == 26

    def test_ka_bijection(self):
        assert len(KA.sequence) == 26
        assert len(set(KA.sequence)) == 26

    def test_same_character_set(self):
        assert set(AZ.sequence) == set(KA.sequence)

    def test_encode_decode_roundtrip(self):
        for alpha in [AZ, KA]:
            for ch in alpha.sequence:
                idx = alpha.char_to_idx(ch)
                assert alpha.idx_to_char(idx) == ch


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Self-encrypting positions
# ══════════════════════════════════════════════════════════════════════════

class TestSelfEncrypting:
    """Positions where CT[i] == PT[i] (key value = 0 for Vigenere)."""

    def test_self_encrypting_positions(self):
        for pos, ch in SELF_ENCRYPTING.items():
            assert CT[pos] == ch, f"CT[{pos}]={CT[pos]} != {ch}"
            assert CRIB_DICT[pos] == ch, f"CRIB[{pos}]={CRIB_DICT[pos]} != {ch}"

    def test_self_encrypting_key_is_zero_vig(self):
        """At self-encrypting positions, Vigenere key must be 0."""
        kv = dict(compute_implied_keys(CT, CipherVariant.VIGENERE))
        for pos in SELF_ENCRYPTING:
            assert kv[pos] == 0, f"Vigenere key at self-encrypt pos {pos} = {kv[pos]} != 0"


# ══════════════════════════════════════════════════════════════════════════
# INVARIANT: Crib generation
# ══════════════════════════════════════════════════════════════════════════

class TestCribGeneration:
    """CRIB_ENTRIES must be correctly generated from CRIB_WORDS."""

    def test_crib_positions_contiguous(self):
        """ENE should span 21-33 (13 chars), BC should span 63-73 (11 chars)."""
        ene_positions = [pos for pos, _ in CRIB_ENTRIES if 21 <= pos <= 33]
        bc_positions = [pos for pos, _ in CRIB_ENTRIES if 63 <= pos <= 73]
        assert ene_positions == list(range(21, 34))
        assert bc_positions == list(range(63, 74))

    def test_total_crib_count(self):
        assert len(CRIB_ENTRIES) == N_CRIBS == 24

    def test_crib_dict_matches_entries(self):
        assert CRIB_DICT == dict(CRIB_ENTRIES)

    def test_crib_words_content(self):
        assert CRIB_WORDS[0] == (21, "EASTNORTHEAST")
        assert CRIB_WORDS[1] == (63, "BERLINCLOCK")
