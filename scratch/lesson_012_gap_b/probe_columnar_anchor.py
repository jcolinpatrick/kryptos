"""K4B-006 STRONG SIGNAL anchor: columnar(THREE) + beaufort(MIRROR)
+ rail_fence(4) reaches 12/24 with contiguous crib matches at
positions 25-28 (RHID) and 64-65, 69-72 (EN..ATHX).

This script iterates from that anchor:
- Try different columnar keywords (especially numeric-named: THREE,
  FOUR, FIVE, etc., plus all clue keywords)
- Try every keyword × alphabet combination for the substitution
- Try with/without rail_fence layer
- Try 4-layer compositions adding skip_route or caesar
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
    columnar_perm, rail_fence_perm,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_reverse_ct import (
    reverse_ct, skip_route, atbash, caesar_decrypt,
    vigenere_decrypt, beaufort_decrypt, variant_beaufort_decrypt,
    apply_perm, invert_perm, rail_fence_undo,
    keyword_mixed, KA_ALPHABET, REVERSED_AZ, REVERSED_KA,
    crib_score, CRIB_A_EXPECTED, CRIB_B_EXPECTED,
    apply_pipeline, make_skip_route_layer, make_rail_fence_layer,
    make_reverse_ct_layer, make_atbash_layer, make_caesar_layer,
)


def keyword_to_col_order(keyword):
    kw = keyword.upper()
    width = len(kw)
    indexed = [(c, i) for i, c in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def columnar_undo(s, keyword):
    if len(keyword) < 2:
        return s
    col_order = keyword_to_col_order(keyword)
    perm = columnar_perm(len(keyword), col_order, len(s))
    inv = invert_perm(perm)
    return apply_perm(s, inv)


def myszkowski_undo(s, keyword):
    from kryptos.kernel.transforms.transposition import myszkowski_perm
    perm = myszkowski_perm(keyword.upper(), len(s))
    inv = invert_perm(perm)
    return apply_perm(s, inv)


def report_per_position(pt, expected_crib_a="LAYERHIDESONE", expected_crib_b="FENCEPATHXX"):
    a_match = "".join(
        "X" if pt[21+j] == expected_crib_a[j] else "." for j in range(13)
    )
    b_match = "".join(
        "X" if pt[63+j] == expected_crib_b[j] else "." for j in range(11)
    )
    return a_match, b_match


def probe_columnar_keywords_exhaustive():
    """Try every clue keyword + project default + numeric word as
    columnar key, paired with every keyword × alphabet × sub_kind.
    """
    print("=" * 70)
    print("PROBE 21: exhaustive columnar(kw) + sub(kw, alpha) + rail_fence")
    print("=" * 70)

    columnar_keys = [
        # Numeric words (matches the 12/24 hit pattern)
        "THREE", "FOUR", "FIVE", "EIGHT", "TEN",
        "FIFTH", "FOURTH", "THIRD",
        # Clue keywords
        "MIRROR", "MARGINS", "SHOW", "RAILS", "WORD", "ROUTE",
        "BEGINNING", "STEPS", "START", "STEP", "LESSON",
        "TUNNEL", "FENCE", "PATH", "LAYER",
        # Project defaults
        "KRYPTOS", "PALIMPSEST", "ABSCISSA",
    ]
    sub_keys = columnar_keys + ["KEY"]
    alphabets = [
        ("AZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("KA", KA_ALPHABET),
        ("mirrored_az", REVERSED_AZ),
        ("kw_MIRROR", keyword_mixed("MIRROR")),
        ("kw_MARGINS", keyword_mixed("MARGINS")),
        ("kw_RAILS", keyword_mixed("RAILS")),
        ("kw_ROUTE", keyword_mixed("ROUTE")),
    ]
    sub_fns = [
        ("vigenere", vigenere_decrypt),
        ("beaufort", beaufort_decrypt),
        ("variant_beaufort", variant_beaufort_decrypt),
    ]
    depths = [3, 4, 5]

    best_list = []
    n_tested = 0
    t0 = time.monotonic()

    for col_kw in columnar_keys:
        if len(col_kw) < 2:
            continue
        col_layer = ("columnar", lambda s, k=col_kw: columnar_undo(s, k))
        for sub_kw in sub_keys:
            for alpha_label, alphabet in alphabets:
                if not all(c in alphabet for c in sub_kw):
                    continue
                for sub_kind, fn in sub_fns:
                    sub = (sub_kind, lambda s, k=sub_kw, a=alphabet, f=fn: f(s, k, a))
                    for depth in depths:
                        rf = make_rail_fence_layer(depth)
                        # 3-layer: all 6 orderings
                        for perm in permutations([sub, col_layer, rf]):
                            pt = apply_pipeline(CT, list(perm))
                            cs = crib_score(pt)
                            n_tested += 1
                            if cs >= 10:
                                best_list.append((
                                    cs, perm[0][0] + "->" + perm[1][0] + "->" + perm[2][0],
                                    sub_kind, sub_kw, alpha_label,
                                    col_kw, depth, pt[21:34], pt[63:74],
                                ))
                    # 2-layer: skip rail_fence
                    for perm in permutations([sub, col_layer]):
                        pt = apply_pipeline(CT, list(perm))
                        cs = crib_score(pt)
                        n_tested += 1
                        if cs >= 10:
                            best_list.append((
                                cs, perm[0][0] + "->" + perm[1][0],
                                sub_kind, sub_kw, alpha_label,
                                col_kw, None, pt[21:34], pt[63:74],
                            ))

    elapsed = time.monotonic() - t0
    print(f"  tested {n_tested:,} compositions in {elapsed:.1f}s")
    best_list.sort(key=lambda x: -x[0])
    print(f"  hits >= 10: {len(best_list)}")
    for h in best_list[:20]:
        cs, names, sk, skw, a, cw, dp, pa, pb = h
        a_match, b_match = report_per_position(
            "".join(["?"] * 21) + pa + "".join(["?"] * (63 - 34)) + pb + "".join(["?"] * (97 - 74))
        )
        print(f"    cs={cs}  {names}  sub={sk}({skw}|{a})  col={cw}  rail={dp}")
        print(f"      a={pa!r} match={a_match}")
        print(f"      b={pb!r} match={b_match}")
    return best_list[0][0] if best_list else 0


def probe_4layer_with_skip_or_caesar():
    """Add a 4th layer to the 12/24 anchor: skip_route or caesar."""
    print()
    print("=" * 70)
    print("PROBE 22: 4-layer based on the 12/24 anchor")
    print("=" * 70)

    # The anchor:
    # columnar(THREE) -> beaufort(MIRROR) -> rail_fence(4)
    # Add skip_route or caesar as a 4th layer in any position.

    col = ("columnar", lambda s: columnar_undo(s, "THREE"))
    sub = ("beaufort", lambda s: beaufort_decrypt(s, "MIRROR", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    rf = make_rail_fence_layer(4)
    rev = make_reverse_ct_layer()
    at = make_atbash_layer()

    best_list = []
    n_tested = 0

    # Try adding skip_route at any position
    for step in [s for s in range(2, 25) if math.gcd(s, 97) == 1]:
        for offset in range(0, 12):
            sk = make_skip_route_layer(step, offset)
            for perm in permutations([col, sub, rf, sk]):
                pt = apply_pipeline(CT, list(perm))
                cs = crib_score(pt)
                n_tested += 1
                if cs >= 10:
                    names = "->".join(l[0] for l in perm)
                    best_list.append((cs, names, step, offset, pt[21:34], pt[63:74]))

    # Also try with caesar
    for shift in range(1, 26):
        cs_layer = make_caesar_layer(shift)
        for perm in permutations([col, sub, rf, cs_layer]):
            pt = apply_pipeline(CT, list(perm))
            cs = crib_score(pt)
            n_tested += 1
            if cs >= 10:
                names = "->".join(l[0] for l in perm)
                best_list.append((cs, names, None, None, pt[21:34], pt[63:74]))

    print(f"  tested {n_tested:,} 4-layer compositions")
    best_list.sort(key=lambda x: -x[0])
    print(f"  hits >= 10: {len(best_list)}")
    for h in best_list[:15]:
        cs, names, st, of, pa, pb = h
        print(f"    cs={cs}  {names}  step={st} off={of}")
        print(f"      pt[21:34]={pa!r}")
        print(f"      pt[63:74]={pb!r}")
    return best_list[0][0] if best_list else 0


def probe_anchor_variants():
    """Vary just the col keyword and sub keyword around the anchor;
    also vary alphabet and sub kind. The anchor scored 12/24 with
    columnar(THREE) + beaufort(MIRROR | AZ) + rail_fence(4)."""
    print()
    print("=" * 70)
    print("PROBE 23: variants of the 12/24 anchor")
    print("=" * 70)

    # Try MIRROR + various col keys (numeric anchor)
    sub_kw = "MIRROR"
    sub_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sub = ("beaufort", lambda s: beaufort_decrypt(s, sub_kw, sub_alpha))

    best_list = []
    n_tested = 0

    # Iterate columnar keywords AND rail_fence depths
    col_keys = ["THREE", "FOUR", "FIVE", "FIRST", "SECOND", "THIRD",
                "FOURTH", "FIFTH", "RAILS", "STEP", "STEPS",
                "MIRROR", "MARGINS", "ROUTE", "TUNNEL", "FENCE",
                "LAYER", "PATH", "HIDES", "LESSON",
                "MIRRORROUTE", "FOURRAILS"]

    for col_kw in col_keys:
        if len(col_kw) < 2:
            continue
        col_layer = ("columnar", lambda s, k=col_kw: columnar_undo(s, k))
        for depth in range(2, 11):
            rf = make_rail_fence_layer(depth)
            for perm in permutations([sub, col_layer, rf]):
                pt = apply_pipeline(CT, list(perm))
                cs = crib_score(pt)
                n_tested += 1
                if cs >= 8:
                    best_list.append((cs, perm[0][0] + "->" + perm[1][0] + "->" + perm[2][0],
                                       col_kw, depth, pt[21:34], pt[63:74]))
        # Also try with myszkowski instead of columnar
        myz_layer = ("myszkowski", lambda s, k=col_kw: myszkowski_undo(s, k))
        for depth in range(2, 11):
            rf = make_rail_fence_layer(depth)
            for perm in permutations([sub, myz_layer, rf]):
                pt = apply_pipeline(CT, list(perm))
                cs = crib_score(pt)
                n_tested += 1
                if cs >= 8:
                    best_list.append((cs, perm[0][0] + "->" + perm[1][0] + "->" + perm[2][0],
                                       col_kw, depth, pt[21:34], pt[63:74]))

    print(f"  tested {n_tested:,} anchor variants")
    best_list.sort(key=lambda x: -x[0])
    print(f"  hits >= 8: {len(best_list)}")
    for h in best_list[:20]:
        cs, names, ck, dp, pa, pb = h
        print(f"    cs={cs}  {names}  trans_kw={ck}  rail={dp}")
        print(f"      pt[21:34]={pa!r}")
        print(f"      pt[63:74]={pb!r}")
    return best_list[0][0] if best_list else 0


def main():
    print(f"K4B-006 ciphertext: {CT}")
    print()
    t0 = time.monotonic()
    results = {}
    results["columnar_exhaustive"] = probe_columnar_keywords_exhaustive()
    results["4layer_anchor"] = probe_4layer_with_skip_or_caesar()
    results["anchor_variants"] = probe_anchor_variants()
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
