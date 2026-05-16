"""K4B-006: at 14/24 with columnar(FENCE)+beaufort(MIRROR)+rail_fence(4),
crib_a positions 21-24 'LAYE' match exactly. Try every possible
columnar permutation (not just keyword-derived) for widths 2..8.
"""
from __future__ import annotations

import math
import sys
import time
from itertools import permutations
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src"))

from kryptosbot.bench_loader import load_k4bench_challenge
ch = load_k4bench_challenge(_REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-006.json")
ch.install_kernel_overrides()

from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.transforms.transposition import columnar_perm

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_reverse_ct import (
    vigenere_decrypt, beaufort_decrypt, variant_beaufort_decrypt,
    apply_perm, invert_perm, rail_fence_undo,
    keyword_mixed, KA_ALPHABET, REVERSED_AZ, REVERSED_KA,
    crib_score, CRIB_A_EXPECTED, CRIB_B_EXPECTED,
    apply_pipeline, make_rail_fence_layer,
)


def columnar_undo_perm(s, width, col_order):
    perm = columnar_perm(width, list(col_order), len(s))
    inv = invert_perm(perm)
    return apply_perm(s, inv)


def probe_all_columnar_permutations():
    print("=" * 70)
    print("PROBE 26: every columnar permutation, sub=beaufort(MIRROR|AZ),")
    print("         rail=2..8, all 6 layer orderings")
    print("=" * 70)
    sub = ("beaufort", lambda s: beaufort_decrypt(s, "MIRROR", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    best_list = []
    n_tested = 0
    t0 = time.monotonic()
    # For each width, enumerate all permutations (factorial growth)
    for width in range(2, 8):  # 2!=2, 3!=6, 4!=24, 5!=120, 6!=720, 7!=5040
        for col_order in permutations(range(width)):
            col = ("columnar", lambda s, w=width, co=col_order: columnar_undo_perm(s, w, co))
            for depth in range(2, 11):
                rf = make_rail_fence_layer(depth)
                for perm_pipe in permutations([sub, col, rf]):
                    pt = apply_pipeline(CT, list(perm_pipe))
                    cs = crib_score(pt)
                    n_tested += 1
                    if cs >= 14:
                        names = "->".join(l[0] for l in perm_pipe)
                        best_list.append((
                            cs, names, width, col_order, depth, pt[21:34], pt[63:74],
                        ))
    elapsed = time.monotonic() - t0
    print(f"  tested {n_tested:,} compositions in {elapsed:.1f}s")
    best_list.sort(key=lambda x: -x[0])
    print(f"  hits >= 14: {len(best_list)}")
    for h in best_list[:30]:
        cs, names, w, co, dp, pa, pb = h
        a_match = "".join("X" if pa[j] == CRIB_A_EXPECTED[j] else "." for j in range(13))
        b_match = "".join("X" if pb[j] == CRIB_B_EXPECTED[j] else "." for j in range(11))
        print(f"    cs={cs:2d}  {names}  width={w} col_order={co} rail={dp}")
        print(f"         a={pa!r} {a_match}")
        print(f"         b={pb!r} {b_match}")
    return best_list[0][0] if best_list else 0


def main():
    print(f"K4B-006 ciphertext: {CT}")
    print()
    t0 = time.monotonic()
    result = probe_all_columnar_permutations()
    print()
    print(f"max_crib: {result}/24")
    if result == 24:
        print("*** 24/24 ACHIEVED ***")
    print(f"  total wall time: {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()
