"""Tests for numba-accelerated kernels.

Verifies that accelerated functions produce identical results to the
pure-Python originals. This is the critical correctness gate — if any
accelerated function disagrees with the original, it cannot be used.
"""
import numpy as np
import pytest

from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.accel import (
    HAS_NUMBA,
    text_to_int8, int8_to_text,
    fast_decrypt_vigenere, fast_decrypt_beaufort, fast_decrypt_var_beaufort,
    fast_score_cribs, fast_bean_simple, fast_decrypt_and_score,
    build_quadgram_table, fast_quadgram_score,
    _build_crib_arrays, _build_bean_arrays,
)


# ── Conversion tests ────────────────────────────────────────────────────

def test_text_roundtrip():
    assert int8_to_text(text_to_int8("KRYPTOS")) == "KRYPTOS"
    assert int8_to_text(text_to_int8(CT)) == CT


def test_text_to_int8_values():
    arr = text_to_int8("ABCZ")
    assert list(arr) == [0, 1, 2, 25]


# ── Decrypt equivalence tests ───────────────────────────────────────────

KEYWORDS = ["KRYPTOS", "ABSCISSA", "COMPASS", "PALIMPSEST", "A", "ZZ"]


@pytest.mark.parametrize("keyword", KEYWORDS)
def test_decrypt_vigenere_matches(keyword):
    key = [ord(c) - 65 for c in keyword]
    expected = decrypt_text(CT, key, CipherVariant.VIGENERE)

    ct_arr = text_to_int8(CT)
    key_arr = np.array(key, dtype=np.int8)
    result = int8_to_text(fast_decrypt_vigenere(ct_arr, key_arr))

    assert result == expected, f"Vigenere mismatch with key={keyword}"


@pytest.mark.parametrize("keyword", KEYWORDS)
def test_decrypt_beaufort_matches(keyword):
    key = [ord(c) - 65 for c in keyword]
    expected = decrypt_text(CT, key, CipherVariant.BEAUFORT)

    ct_arr = text_to_int8(CT)
    key_arr = np.array(key, dtype=np.int8)
    result = int8_to_text(fast_decrypt_beaufort(ct_arr, key_arr))

    assert result == expected, f"Beaufort mismatch with key={keyword}"


@pytest.mark.parametrize("keyword", KEYWORDS)
def test_decrypt_var_beaufort_matches(keyword):
    key = [ord(c) - 65 for c in keyword]
    expected = decrypt_text(CT, key, CipherVariant.VAR_BEAUFORT)

    ct_arr = text_to_int8(CT)
    key_arr = np.array(key, dtype=np.int8)
    result = int8_to_text(fast_decrypt_var_beaufort(ct_arr, key_arr))

    assert result == expected, f"VarBeaufort mismatch with key={keyword}"


# ── Crib scoring equivalence ───────────────────────────────────────────

@pytest.mark.parametrize("keyword", KEYWORDS)
def test_crib_score_matches(keyword):
    key = [ord(c) - 65 for c in keyword]
    pt = decrypt_text(CT, key, CipherVariant.BEAUFORT)
    expected = score_cribs(pt)

    pt_arr = text_to_int8(pt)
    crib_pos, crib_vals = _build_crib_arrays()
    result = fast_score_cribs(pt_arr, crib_pos, crib_vals)

    assert result == expected, f"Crib score mismatch: {result} vs {expected}"


# ── Bean constraint equivalence ────────────────────────────────────────

def test_bean_simple_matches_pass():
    """Test Bean verification with a known-passing keystream."""
    # Build a keystream that satisfies Bean equality: k[27] = k[65]
    ks = list(range(97))  # arbitrary, will likely fail Bean ineq
    ks[27] = ks[65] = 5  # force equality

    ks_arr = np.array(ks, dtype=np.int8)
    eq_a, eq_b, ineq_a, ineq_b = _build_bean_arrays()

    expected = verify_bean_simple(ks)
    result = fast_bean_simple(ks_arr, eq_a, eq_b, ineq_a, ineq_b)

    assert result == expected


def test_bean_simple_matches_fail():
    """Test Bean verification with a known-failing keystream."""
    ks = [0] * 97  # All zeros — equality passes but many inequalities fail
    ks_arr = np.array(ks, dtype=np.int8)
    eq_a, eq_b, ineq_a, ineq_b = _build_bean_arrays()

    expected = verify_bean_simple(ks)
    result = fast_bean_simple(ks_arr, eq_a, eq_b, ineq_a, ineq_b)

    assert result == expected
    assert result is False  # All-zeros should fail Bean inequalities


# ── Combined decrypt+score ──────────────────────────────────────────────

@pytest.mark.parametrize("keyword", KEYWORDS[:3])
def test_decrypt_and_score_beaufort(keyword):
    key = [ord(c) - 65 for c in keyword]
    pt = decrypt_text(CT, key, CipherVariant.BEAUFORT)
    expected_score = score_cribs(pt)

    ct_arr = text_to_int8(CT)
    key_arr = np.array(key, dtype=np.int8)
    crib_pos, crib_vals = _build_crib_arrays()
    score, pt_arr = fast_decrypt_and_score(ct_arr, key_arr, 1, crib_pos, crib_vals)

    assert score == expected_score
    assert int8_to_text(pt_arr) == pt


# ── Quadgram scoring ────────────────────────────────────────────────────

def test_quadgram_table_builds():
    """Verify quadgram table builds without error and has correct size."""
    table = build_quadgram_table()
    assert table.shape == (26**4,)
    assert table.dtype == np.float64
    # TION should have a high value (common quadgram)
    idx = 19 * 17576 + 8 * 676 + 14 * 26 + 13  # T=19,I=8,O=14,N=13
    assert table[idx] > table[0]  # TION should score higher than AAAA


@pytest.mark.parametrize("text", ["THEQUICKBROWNFOXJUMPS", "XZQWKPLMVBN", CT])
def test_quadgram_fast_vs_original(text):
    """Verify fast quadgram scoring matches original scorer."""
    from kryptos.kernel.scoring.ngram import get_default_scorer
    scorer = get_default_scorer()

    original = scorer.score(text)
    table = build_quadgram_table(scorer)
    arr = text_to_int8(text)
    fast = fast_quadgram_score(arr, table)

    assert abs(fast - original) < 1e-6, f"Quadgram mismatch: {fast} vs {original}"
