"""Round-trip and bijection tests for the new non-columnar transpositions."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(ROOT))

from independent_solve_2026_05_19.src.ciphers.transposition import (
    apply_perm, invert_perm,
    myszkowski_perm, rail_fence_perm,
    route_spiral_perm, route_serpentine_perm,
)


SAMPLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRS"
assert len(SAMPLE) == 97


def check_perm(perm, n, label):
    assert len(perm) == n, f"{label}: perm length {len(perm)} != n {n}"
    assert sorted(perm) == list(range(n)), f"{label}: not a permutation of [0..n-1]"


def check_roundtrip(perm, label):
    encoded = apply_perm(SAMPLE, perm)
    decoded = apply_perm(encoded, invert_perm(perm))
    assert decoded == SAMPLE, f"{label}: round-trip mismatch\n  enc={encoded}\n  dec={decoded}"


def main():
    n = 97

    # Myszkowski
    for kw in ["KRYPTOS", "PALIMPSEST", "EASTNORTHEAST", "TUTANKHAMUN", "CLOCK"]:
        perm = myszkowski_perm(kw, n)
        check_perm(perm, n, f"myszkowski {kw}")
        check_roundtrip(perm, f"myszkowski {kw}")
    print("  OK myszkowski (5 keywords) - bijection and round-trip clean")

    # Rail-fence
    for d in range(2, 16):
        perm = rail_fence_perm(d, n)
        check_perm(perm, n, f"rail_fence depth={d}")
        check_roundtrip(perm, f"rail_fence depth={d}")
    print("  OK rail_fence (depths 2..15) - bijection and round-trip clean")

    # Route-spiral
    rectangles = [(7, 14), (8, 13), (9, 11), (10, 10), (11, 9), (13, 8), (14, 7)]
    directions = ["CW_from_NW", "CW_from_NE", "CCW_from_NW", "CCW_from_NE"]
    for (rows, cols) in rectangles:
        for d in directions:
            perm = route_spiral_perm(rows, cols, n, d)
            check_perm(perm, n, f"spiral {rows}x{cols} {d}")
            check_roundtrip(perm, f"spiral {rows}x{cols} {d}")
    print(f"  OK route_spiral ({len(rectangles) * len(directions)} configs) - bijection and round-trip clean")

    # Route-serpentine
    for w in range(5, 14):
        perm = route_serpentine_perm(w, n)
        check_perm(perm, n, f"serpentine width={w}")
        check_roundtrip(perm, f"serpentine width={w}")
    print("  OK route_serpentine (widths 5..13) - bijection and round-trip clean")

    print("\nTRANSPOSITION PRIMITIVES: PASS")


if __name__ == "__main__":
    main()
