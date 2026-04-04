"""Benchmarks for accelerated kernels vs pure-Python originals.

Run with: PYTHONPATH=src pytest tests/test_bench_accel.py -v -s
These are marked as benchmarks and print timing comparisons.
"""
import time
import numpy as np
import pytest

from kryptos.kernel.constants import CT
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.accel import (
    HAS_NUMBA,
    text_to_int8, int8_to_text,
    fast_decrypt_beaufort, fast_score_cribs,
    fast_decrypt_and_score,
    build_quadgram_table, fast_quadgram_score,
    _build_crib_arrays,
)


N_ITERS = 100_000


@pytest.fixture(scope="module")
def arrays():
    ct_arr = text_to_int8(CT)
    key_arr = np.array([ord(c) - 65 for c in "KRYPTOS"], dtype=np.int8)
    crib_pos, crib_vals = _build_crib_arrays()
    return ct_arr, key_arr, crib_pos, crib_vals


def test_bench_decrypt_beaufort(arrays):
    """Benchmark: Beaufort decrypt — Python vs accelerated."""
    ct_arr, key_arr, _, _ = arrays
    key_list = [ord(c) - 65 for c in "KRYPTOS"]

    # Warmup numba
    if HAS_NUMBA:
        fast_decrypt_beaufort(ct_arr, key_arr)

    # Python baseline
    t0 = time.time()
    for _ in range(N_ITERS):
        decrypt_text(CT, key_list, CipherVariant.BEAUFORT)
    py_time = time.time() - t0

    # Accelerated
    t0 = time.time()
    for _ in range(N_ITERS):
        fast_decrypt_beaufort(ct_arr, key_arr)
    fast_time = time.time() - t0

    speedup = py_time / fast_time if fast_time > 0 else float('inf')
    print(f"\n  Beaufort decrypt {N_ITERS:,} iterations:")
    print(f"    Python:      {py_time:.3f}s ({N_ITERS/py_time:.0f} ops/s)")
    print(f"    Accelerated: {fast_time:.3f}s ({N_ITERS/fast_time:.0f} ops/s)")
    print(f"    Speedup:     {speedup:.1f}x")

    # Verify correctness
    py_result = decrypt_text(CT, key_list, CipherVariant.BEAUFORT)
    fast_result = int8_to_text(fast_decrypt_beaufort(ct_arr, key_arr))
    assert py_result == fast_result


def test_bench_combined_decrypt_score(arrays):
    """Benchmark: Combined decrypt+score — two calls vs fused."""
    ct_arr, key_arr, crib_pos, crib_vals = arrays
    key_list = [ord(c) - 65 for c in "KRYPTOS"]

    # Warmup
    if HAS_NUMBA:
        fast_decrypt_and_score(ct_arr, key_arr, 1, crib_pos, crib_vals)

    # Python: decrypt then score (two separate calls)
    t0 = time.time()
    for _ in range(N_ITERS):
        pt = decrypt_text(CT, key_list, CipherVariant.BEAUFORT)
        s = score_cribs(pt)
    py_time = time.time() - t0

    # Accelerated: fused
    t0 = time.time()
    for _ in range(N_ITERS):
        fast_decrypt_and_score(ct_arr, key_arr, 1, crib_pos, crib_vals)
    fast_time = time.time() - t0

    speedup = py_time / fast_time if fast_time > 0 else float('inf')
    print(f"\n  Combined decrypt+score {N_ITERS:,} iterations:")
    print(f"    Python:      {py_time:.3f}s ({N_ITERS/py_time:.0f} ops/s)")
    print(f"    Accelerated: {fast_time:.3f}s ({N_ITERS/fast_time:.0f} ops/s)")
    print(f"    Speedup:     {speedup:.1f}x")
