"""Numba-accelerated kernels for hot inner loops.

Provides JIT-compiled versions of the most frequently called functions:
  - decrypt (Vigenere, Beaufort, Variant Beaufort)
  - crib scoring
  - Bean constraint verification
  - quadgram scoring

These functions operate on numpy int8 arrays (0-25) rather than strings.
The pure-Python originals in transforms/ and scoring/ remain canonical;
these are optional accelerators that produce identical results.

Usage:
    from kryptos.kernel.accel import fast_decrypt_beaufort, fast_score_cribs

    ct_nums = text_to_nums(CT)  # numpy int8 array
    key_nums = np.array([...], dtype=np.int8)
    pt_nums = fast_decrypt_beaufort(ct_nums, key_nums)
    score = fast_score_cribs(pt_nums, CRIB_NUMS, CRIB_POS)

All functions have a pure-Python fallback if numba is not available.
"""
from __future__ import annotations

import numpy as np
from typing import Optional

try:
    import numba
    HAS_NUMBA = True
except ImportError:
    HAS_NUMBA = False


# ── Array conversion helpers ────────────────────────────────────────────

def text_to_int8(text: str) -> np.ndarray:
    """Convert uppercase letter string to int8 array (A=0, Z=25)."""
    return np.frombuffer(text.encode('ascii'), dtype=np.uint8).astype(np.int8) - 65


def int8_to_text(arr: np.ndarray) -> str:
    """Convert int8 array (0-25) back to uppercase string."""
    return (arr.astype(np.uint8) + 65).tobytes().decode('ascii')


# ── Precomputed constants for crib scoring ──────────────────────────────

def _build_crib_arrays():
    """Build numpy arrays from CRIB_DICT for fast scoring."""
    from kryptos.kernel.constants import CRIB_DICT
    positions = np.array(sorted(CRIB_DICT.keys()), dtype=np.int32)
    values = np.array([ord(CRIB_DICT[p]) - 65 for p in positions], dtype=np.int8)
    return positions, values


def _build_bean_arrays():
    """Build numpy arrays from Bean constraints."""
    from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ
    eq_a = np.array([a for a, b in BEAN_EQ], dtype=np.int32)
    eq_b = np.array([b for a, b in BEAN_EQ], dtype=np.int32)
    ineq_a = np.array([a for a, b in BEAN_INEQ], dtype=np.int32)
    ineq_b = np.array([b for a, b in BEAN_INEQ], dtype=np.int32)
    return eq_a, eq_b, ineq_a, ineq_b


# ── Pure-Python fallbacks ───────────────────────────────────────────────

def _py_decrypt_vigenere(ct: np.ndarray, key: np.ndarray) -> np.ndarray:
    n = len(ct)
    klen = len(key)
    out = np.empty(n, dtype=np.int8)
    for i in range(n):
        out[i] = (ct[i] - key[i % klen]) % 26
    return out


def _py_decrypt_beaufort(ct: np.ndarray, key: np.ndarray) -> np.ndarray:
    n = len(ct)
    klen = len(key)
    out = np.empty(n, dtype=np.int8)
    for i in range(n):
        out[i] = (key[i % klen] - ct[i]) % 26
    return out


def _py_decrypt_var_beaufort(ct: np.ndarray, key: np.ndarray) -> np.ndarray:
    n = len(ct)
    klen = len(key)
    out = np.empty(n, dtype=np.int8)
    for i in range(n):
        out[i] = (ct[i] + key[i % klen]) % 26
    return out


def _py_score_cribs(pt: np.ndarray, crib_pos: np.ndarray, crib_vals: np.ndarray) -> int:
    score = 0
    for i in range(len(crib_pos)):
        pos = crib_pos[i]
        if pos < len(pt) and pt[pos] == crib_vals[i]:
            score += 1
    return score


def _py_bean_simple(keystream: np.ndarray,
                    eq_a: np.ndarray, eq_b: np.ndarray,
                    ineq_a: np.ndarray, ineq_b: np.ndarray) -> bool:
    for i in range(len(eq_a)):
        if keystream[eq_a[i]] != keystream[eq_b[i]]:
            return False
    for i in range(len(ineq_a)):
        if keystream[ineq_a[i]] == keystream[ineq_b[i]]:
            return False
    return True


def _py_quadgram_score(pt: np.ndarray, table: np.ndarray, floor: float) -> float:
    """Score using precomputed 26^4 lookup table."""
    total = 0.0
    n = len(pt)
    for i in range(n - 3):
        idx = pt[i] * 17576 + pt[i+1] * 676 + pt[i+2] * 26 + pt[i+3]
        total += table[idx]
    return total


# ── Numba-accelerated versions ──────────────────────────────────────────

if HAS_NUMBA:
    @numba.njit
    def _nb_decrypt_vigenere(ct, key):
        n = len(ct)
        klen = len(key)
        out = np.empty(n, dtype=numba.int8)
        for i in range(n):
            out[i] = (ct[i] - key[i % klen]) % 26
        return out

    @numba.njit
    def _nb_decrypt_beaufort(ct, key):
        n = len(ct)
        klen = len(key)
        out = np.empty(n, dtype=numba.int8)
        for i in range(n):
            out[i] = (key[i % klen] - ct[i]) % 26
        return out

    @numba.njit
    def _nb_decrypt_var_beaufort(ct, key):
        n = len(ct)
        klen = len(key)
        out = np.empty(n, dtype=numba.int8)
        for i in range(n):
            out[i] = (ct[i] + key[i % klen]) % 26
        return out

    @numba.njit
    def _nb_score_cribs(pt, crib_pos, crib_vals):
        score = 0
        for i in range(len(crib_pos)):
            pos = crib_pos[i]
            if pos < len(pt) and pt[pos] == crib_vals[i]:
                score += 1
        return score

    @numba.njit
    def _nb_bean_simple(keystream, eq_a, eq_b, ineq_a, ineq_b):
        for i in range(len(eq_a)):
            if keystream[eq_a[i]] != keystream[eq_b[i]]:
                return False
        for i in range(len(ineq_a)):
            if keystream[ineq_a[i]] == keystream[ineq_b[i]]:
                return False
        return True

    @numba.njit
    def _nb_quadgram_score(pt, table, floor):
        total = 0.0
        n = len(pt)
        for i in range(n - 3):
            idx = pt[i] * 17576 + pt[i+1] * 676 + pt[i+2] * 26 + pt[i+3]
            total += table[idx]
        return total

    @numba.njit
    def _nb_decrypt_and_score(ct, key, crib_pos, crib_vals, variant):
        """Combined decrypt + crib score in a single pass.

        variant: 0=vigenere, 1=beaufort, 2=var_beaufort
        Returns (score, pt_array).
        """
        n = len(ct)
        klen = len(key)
        pt = np.empty(n, dtype=numba.int8)

        for i in range(n):
            k = key[i % klen]
            if variant == 0:
                pt[i] = (ct[i] - k) % 26
            elif variant == 1:
                pt[i] = (k - ct[i]) % 26
            else:
                pt[i] = (ct[i] + k) % 26

        score = 0
        for i in range(len(crib_pos)):
            pos = crib_pos[i]
            if pos < n and pt[pos] == crib_vals[i]:
                score += 1

        return score, pt


# ── Public API (auto-selects numba or fallback) ─────────────────────────

def fast_decrypt_vigenere(ct: np.ndarray, key: np.ndarray) -> np.ndarray:
    """Decrypt with Vigenere: P = (C - K) mod 26. Returns int8 array."""
    if HAS_NUMBA:
        return _nb_decrypt_vigenere(ct, key)
    return _py_decrypt_vigenere(ct, key)


def fast_decrypt_beaufort(ct: np.ndarray, key: np.ndarray) -> np.ndarray:
    """Decrypt with Beaufort: P = (K - C) mod 26. Returns int8 array."""
    if HAS_NUMBA:
        return _nb_decrypt_beaufort(ct, key)
    return _py_decrypt_beaufort(ct, key)


def fast_decrypt_var_beaufort(ct: np.ndarray, key: np.ndarray) -> np.ndarray:
    """Decrypt with Variant Beaufort: P = (C + K) mod 26. Returns int8 array."""
    if HAS_NUMBA:
        return _nb_decrypt_var_beaufort(ct, key)
    return _py_decrypt_var_beaufort(ct, key)


def fast_score_cribs(pt: np.ndarray,
                     crib_pos: Optional[np.ndarray] = None,
                     crib_vals: Optional[np.ndarray] = None) -> int:
    """Fast crib scoring on int8 array. Returns 0-24."""
    if crib_pos is None or crib_vals is None:
        crib_pos, crib_vals = _build_crib_arrays()
    if HAS_NUMBA:
        return int(_nb_score_cribs(pt, crib_pos, crib_vals))
    return _py_score_cribs(pt, crib_pos, crib_vals)


def fast_bean_simple(keystream: np.ndarray,
                     eq_a: Optional[np.ndarray] = None,
                     eq_b: Optional[np.ndarray] = None,
                     ineq_a: Optional[np.ndarray] = None,
                     ineq_b: Optional[np.ndarray] = None) -> bool:
    """Fast Bean verification. Returns True if all constraints pass."""
    if eq_a is None:
        eq_a, eq_b, ineq_a, ineq_b = _build_bean_arrays()
    if HAS_NUMBA:
        return bool(_nb_bean_simple(keystream, eq_a, eq_b, ineq_a, ineq_b))
    return _py_bean_simple(keystream, eq_a, eq_b, ineq_a, ineq_b)


def fast_decrypt_and_score(ct: np.ndarray, key: np.ndarray,
                           variant: int = 1,
                           crib_pos: Optional[np.ndarray] = None,
                           crib_vals: Optional[np.ndarray] = None):
    """Combined decrypt + score in one call.

    variant: 0=vigenere, 1=beaufort, 2=var_beaufort
    Returns (score: int, pt: np.ndarray).
    """
    if crib_pos is None or crib_vals is None:
        crib_pos, crib_vals = _build_crib_arrays()
    if HAS_NUMBA:
        score, pt = _nb_decrypt_and_score(ct, key, crib_pos, crib_vals, variant)
        return int(score), pt
    # Fallback: two separate calls
    if variant == 0:
        pt = _py_decrypt_vigenere(ct, key)
    elif variant == 1:
        pt = _py_decrypt_beaufort(ct, key)
    else:
        pt = _py_decrypt_var_beaufort(ct, key)
    score = _py_score_cribs(pt, crib_pos, crib_vals)
    return score, pt


def build_quadgram_table(scorer=None) -> np.ndarray:
    """Build a flat 26^4 lookup table for fast quadgram scoring.

    Returns a numpy float64 array of size 456976 (26^4).
    Index = a*17576 + b*676 + c*26 + d for quadgram (a,b,c,d).
    """
    if scorer is None:
        from kryptos.kernel.scoring.ngram import get_default_scorer
        scorer = get_default_scorer()

    table = np.full(26**4, scorer._floor, dtype=np.float64)
    for gram, logp in scorer.log_probs.items():
        if len(gram) == 4:
            a, b, c, d = [ord(ch) - 65 for ch in gram]
            idx = a * 17576 + b * 676 + c * 26 + d
            table[idx] = logp
    return table


def fast_quadgram_score(pt: np.ndarray, table: np.ndarray) -> float:
    """Score int8 array using precomputed quadgram table."""
    if HAS_NUMBA:
        return float(_nb_quadgram_score(pt, table, 0.0))
    return _py_quadgram_score(pt, table, 0.0)
