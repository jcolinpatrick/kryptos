"""Extended structural probes for K4B-006 Gap B.

Probe 1 (reverse_ct hypothesis) falsified — max_crib stayed at 6.
This script tests additional structural hypotheses:
- Inverse-direction skip_route (step values in [24, 96])
- Column-major route over grids
- Reflect-around-midpoint
- TWO reverse layers
- "Spiral" route from center outward
- Combined mirror = reverse_ct + atbash
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

from kryptos.kernel.constants import CT, CRIB_DICT, CT_LEN
from kryptos.kernel.transforms.transposition import (
    rail_fence_perm,
    serpentine_perm,
    spiral_perm,
)


# Reuse primitives from probe 1
sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_reverse_ct import (
    reverse_ct, skip_route, atbash, caesar_decrypt,
    vigenere_decrypt, beaufort_decrypt, variant_beaufort_decrypt,
    apply_perm, invert_perm, rail_fence_undo, serpentine_undo,
    keyword_mixed, KA_ALPHABET, REVERSED_AZ, REVERSED_KA,
    crib_score, report_match, CRIB_A_EXPECTED, CRIB_B_EXPECTED,
    apply_pipeline, make_skip_route_layer, make_rail_fence_layer,
    make_reverse_ct_layer, make_atbash_layer, make_caesar_layer,
    make_vigenere_layer,
)


def column_major_undo(s: str, rows: int, cols: int) -> str:
    """Column-major route: encryption fills grid row-by-row, reads
    column-by-column. To undo, reverse the operation.
    """
    L = len(s)
    if rows * cols < L:
        return s
    # Encryption: fill a rows×cols grid row-major, read column-major.
    # If s is the column-major-read CT, then to recover row-major PT:
    # We need to "fill" a rows×cols grid column-major from s, then
    # read it row-major.
    # Build CT->PT mapping:
    # PT position (r, c) → row-major index r*cols + c
    # CT position k → column-major: c = k // rows, r = k % rows
    # So PT[r*cols + c] = CT[c*rows + r]
    out = [""] * L
    k = 0
    for c in range(cols):
        for r in range(rows):
            pt_pos = r * cols + c
            if pt_pos < L and k < L:
                out[pt_pos] = s[k]
                k += 1
    return "".join(out)


def reverse_around_midpoint(s: str) -> str:
    """For odd L, swap pairs (i, L-1-i) for i < L//2; midpoint
    fixed. Equivalent to reverse_ct over odd-length strings."""
    return s[::-1]


def reflect_left_right(s: str, axis: int) -> str:
    """Reflect left/right around a given axis position."""
    L = len(s)
    out = list(s)
    for i in range(L):
        mirror = 2 * axis - i
        if 0 <= mirror < L:
            out[i] = s[mirror]
    return "".join(out)


def spiral_undo(s: str, rows: int, cols: int, clockwise: bool = True) -> str:
    perm = spiral_perm(rows, cols, len(s), clockwise=clockwise)
    inv = invert_perm(perm)
    return apply_perm(s, inv)


def probe_inverse_direction_skip_route():
    """skip_route with step values in [24, 96] — these are the
    inverses of the standard small steps mod 97."""
    print("=" * 70)
    print("PROBE 7: skip_route with step in [24, 96] (inverse-direction)")
    print("=" * 70)
    best = (0, None)
    for step in range(24, 97):
        if math.gcd(step, 97) != 1:
            continue
        for offset in range(0, 97):
            sk = make_skip_route_layer(step, offset)
            pt = apply_pipeline(CT, [sk])
            cs = crib_score(pt)
            if cs > best[0]:
                best = (cs, (step, offset, pt[21:34], pt[63:74]))
    print(f"  best skip_route alone in [24, 96]: cs={best[0]}/24")
    if best[1]:
        s, o, pa, pb = best[1]
        print(f"    step={s}, offset={o}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_column_major_routes():
    """Column-major route over various grid shapes."""
    print()
    print("=" * 70)
    print("PROBE 8: column-major route over grid shapes")
    print("=" * 70)
    best = (0, None)
    for rows in range(2, 25):
        cols = 97 // rows + (1 if 97 % rows else 0)
        if rows * cols < 97:
            continue
        pt = column_major_undo(CT, rows, cols)
        cs = crib_score(pt)
        if cs > best[0]:
            best = (cs, (rows, cols, pt[21:34], pt[63:74]))
    print(f"  best column-major: cs={best[0]}/24")
    if best[1]:
        r, c, pa, pb = best[1]
        print(f"    grid=({r},{c})")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_two_reverse_layers():
    """Pipeline with TWO reverse_ct layers — net identity, but
    when interspersed with other layers might produce something
    structural.
    """
    print()
    print("=" * 70)
    print("PROBE 9: rev + skip + rev (sandwich) various step/offset")
    print("=" * 70)
    rev = make_reverse_ct_layer()
    best = (0, None)
    for step in [s for s in range(2, 25) if math.gcd(s, 97) == 1]:
        for offset in range(0, 12):
            sk = make_skip_route_layer(step, offset)
            for label, pipe in [
                ("rev->skip->rev", [rev, sk, rev]),
                ("rev->skip", [rev, sk]),
                ("skip->rev", [sk, rev]),
            ]:
                pt = apply_pipeline(CT, pipe)
                cs = crib_score(pt)
                if cs > best[0]:
                    best = (cs, (label, step, offset, pt[21:34], pt[63:74]))
    print(f"  best two-rev: cs={best[0]}/24")
    if best[1]:
        lbl, s, o, pa, pb = best[1]
        print(f"    {lbl}  step={s}, offset={o}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_atbash_combined_mirror():
    """Hypothesis: MIRROR = atbash + reverse_ct combined (i.e.
    reflect both alphabet AND position)."""
    print()
    print("=" * 70)
    print("PROBE 10: combined-mirror (atbash + reverse_ct) + skip + rail")
    print("=" * 70)
    def combined_mirror(s):
        return atbash(reverse_ct(s))
    cm = ("combined_mirror", combined_mirror)
    best = (0, None)
    for step in [s for s in range(2, 25) if math.gcd(s, 97) == 1]:
        for offset in range(0, 12):
            sk = make_skip_route_layer(step, offset)
            for depth in [3, 4, 5]:
                rf = make_rail_fence_layer(depth)
                # 6 orderings of {cm, sk, rf}
                for perm in permutations([cm, sk, rf]):
                    pt = apply_pipeline(CT, list(perm))
                    cs = crib_score(pt)
                    if cs > best[0]:
                        names = " -> ".join(l[0] for l in perm)
                        best = (cs, (names, step, offset, depth, pt[21:34], pt[63:74]))
    print(f"  best combined-mirror: cs={best[0]}/24")
    if best[1]:
        n, s, o, d, pa, pb = best[1]
        print(f"    {n}  step={s}, offset={o}, depth={d}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_grid_routes_with_skip():
    """Various route variants (column-major, serpentine, spiral)
    composed with skip_route + rail_fence in all orderings."""
    print()
    print("=" * 70)
    print("PROBE 11: grid_route + skip + rail (various route variants)")
    print("=" * 70)
    best = (0, None)
    n_tested = 0
    grids = [(7, 14), (10, 10), (8, 13), (5, 20), (4, 25), (14, 7)]
    route_variants = []
    for rows, cols in grids:
        if rows * cols < 97:
            continue
        # column-major
        route_variants.append((
            f"colmaj_{rows}x{cols}",
            (lambda s, r=rows, c=cols: column_major_undo(s, r, c)),
        ))
        # serpentine horizontal
        route_variants.append((
            f"serp_h_{rows}x{cols}",
            (lambda s, r=rows, c=cols: serpentine_undo(s, r, c, vertical=False)),
        ))
        # serpentine vertical
        route_variants.append((
            f"serp_v_{rows}x{cols}",
            (lambda s, r=rows, c=cols: serpentine_undo(s, r, c, vertical=True)),
        ))
        # spiral CW
        route_variants.append((
            f"spiral_cw_{rows}x{cols}",
            (lambda s, r=rows, c=cols: spiral_undo(s, r, c, clockwise=True)),
        ))
    for label, fn in route_variants:
        rt = (label, fn)
        for step in [s for s in range(2, 12) if math.gcd(s, 97) == 1]:
            for offset in [0, 3, 5]:
                sk = make_skip_route_layer(step, offset)
                for depth in [3, 4, 5]:
                    rf = make_rail_fence_layer(depth)
                    for perm in permutations([rt, sk, rf]):
                        pt = apply_pipeline(CT, list(perm))
                        cs = crib_score(pt)
                        n_tested += 1
                        if cs > best[0]:
                            names = " -> ".join(l[0] for l in perm)
                            best = (cs, (names, step, offset, depth, pt[21:34], pt[63:74]))
    print(f"  tested {n_tested} combinations")
    print(f"  best: cs={best[0]}/24")
    if best[1]:
        n, s, o, d, pa, pb = best[1]
        print(f"    {n}  step={s}, offset={o}, depth={d}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_step_five_with_partial_inverse_offset():
    """The clue says 'three steps from the start with step five'.
    What if 'step five' is the actual step but 'three' specifies
    something else (e.g. number of times to repeat the cycle, or
    a rail_fence depth)?"""
    print()
    print("=" * 70)
    print("PROBE 12: step=5 fixed, full offset range, various other layers")
    print("=" * 70)
    best = (0, None)
    sk = make_skip_route_layer(5, 0)  # We'll override offset below
    # Iterate offsets 0..96
    for offset in range(0, 97):
        sk_o = make_skip_route_layer(5, offset)
        # Try alone
        pt = apply_pipeline(CT, [sk_o])
        cs = crib_score(pt)
        if cs > best[0]:
            best = (cs, ("alone", 5, offset, None, pt[21:34], pt[63:74]))
        # With rail_fence
        for depth in range(2, 11):
            rf = make_rail_fence_layer(depth)
            for perm in [[sk_o, rf], [rf, sk_o]]:
                pt = apply_pipeline(CT, perm)
                cs = crib_score(pt)
                if cs > best[0]:
                    label = " -> ".join(l[0] for l in perm)
                    best = (cs, (label, 5, offset, depth, pt[21:34], pt[63:74]))
        # With atbash
        for perm in [
            [sk_o, ("atbash", atbash)],
            [("atbash", atbash), sk_o],
        ]:
            pt = apply_pipeline(CT, perm)
            cs = crib_score(pt)
            if cs > best[0]:
                label = " -> ".join(l[0] for l in perm)
                best = (cs, (label, 5, offset, None, pt[21:34], pt[63:74]))
    print(f"  best step=5, all offsets: cs={best[0]}/24")
    if best[1]:
        n, s, o, d, pa, pb = best[1]
        print(f"    {n}  step={s}, offset={o}, depth={d}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_step_5_offset_3_with_keyed_alphabet():
    """Pin (step=5, offset=3) and exhaustively test substitutions
    over MIRROR-related alphabets with various keys."""
    print()
    print("=" * 70)
    print("PROBE 13: step=5 offset=3 fixed + keyed substitution exhaustive")
    print("=" * 70)
    sk = make_skip_route_layer(5, 3)
    best = (0, None)
    keywords = ["MIRROR", "MARGINS", "TUNNEL", "ROUTE", "FENCE", "RAILS",
                "PATH", "LAYER", "HIDES", "STEP", "STEPS"]
    alphabets = [
        ("AZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("KA", KA_ALPHABET),
        ("mirrored_az", REVERSED_AZ),
        ("mirrored_ka", REVERSED_KA),
        ("kw_MIRROR", keyword_mixed("MIRROR")),
        ("kw_MARGINS", keyword_mixed("MARGINS")),
        ("kw_TUNNEL", keyword_mixed("TUNNEL")),
        ("kw_ROUTE", keyword_mixed("ROUTE")),
        ("kw_RAILS", keyword_mixed("RAILS")),
        ("kw_FENCE", keyword_mixed("FENCE")),
    ]
    for kw in keywords:
        for alpha_label, alphabet in alphabets:
            if not all(c in alphabet for c in kw):
                continue
            for sub_kind, fn in [
                ("vigenere", vigenere_decrypt),
                ("beaufort", beaufort_decrypt),
                ("variant_beaufort", variant_beaufort_decrypt),
            ]:
                sub = (sub_kind, lambda s, k=kw, a=alphabet, f=fn: f(s, k, a))
                # Try sub-first, sub-last, and 3-layer with rail_fence
                for label_pipe, pipe in [
                    (f"{sub_kind}({kw}|{alpha_label})->skip", [sub, sk]),
                    (f"skip->{sub_kind}({kw}|{alpha_label})", [sk, sub]),
                ]:
                    pt = apply_pipeline(CT, pipe)
                    cs = crib_score(pt)
                    if cs > best[0]:
                        best = (cs, (label_pipe, pt[21:34], pt[63:74]))
                # 3-layer with rail_fence(4)
                rf = make_rail_fence_layer(4)
                for perm in permutations([sub, sk, rf]):
                    pt = apply_pipeline(CT, list(perm))
                    cs = crib_score(pt)
                    if cs > best[0]:
                        names = "->".join(l[0] for l in perm) + f"({kw}|{alpha_label})"
                        best = (cs, (names, pt[21:34], pt[63:74]))
    print(f"  best step=5,offset=3 + sub: cs={best[0]}/24")
    if best[1]:
        n, pa, pb = best[1]
        print(f"    {n}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def main():
    print(f"K4B-006 ciphertext: {CT}")
    print(f"crib_a (21-33): {CRIB_A_EXPECTED}")
    print(f"crib_b (63-73): {CRIB_B_EXPECTED}")
    print(f"clue: {ch.clue_text}")
    print()

    t0 = time.monotonic()
    results = {}
    results["inverse_direction_skip"] = probe_inverse_direction_skip_route()
    results["column_major_routes"] = probe_column_major_routes()
    results["two_reverse_sandwich"] = probe_two_reverse_layers()
    results["combined_mirror"] = probe_atbash_combined_mirror()
    results["grid_routes_skip_rail"] = probe_grid_routes_with_skip()
    results["step5_full_offset"] = probe_step_five_with_partial_inverse_offset()
    results["step5_offset3_sub_exhaustive"] = probe_step_5_offset_3_with_keyed_alphabet()

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for k, v in results.items():
        marker = " <-- 24/24!" if v == 24 else ""
        print(f"  {k}: max_crib={v}/24{marker}")
    print(f"  total wall time: {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()
