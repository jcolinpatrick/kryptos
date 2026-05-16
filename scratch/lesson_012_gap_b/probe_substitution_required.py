"""K4B-006 character histogram analysis proves a SUBSTITUTION layer
is required (CT lacks 'S', 'X' that PT cribs need; CT has only 3
'E's but PT needs 5).

This script does the targeted brute force: for every (step, offset)
+ rail_fence(depth) + Vigenere/Beaufort/var_beau over every clue
keyword and alphabet combination, find the max crib_score.

Pipeline focus: 3-layer compositions of {skip_route, rail_fence, sub}
in all 6 orderings, plus 2-layer subsets.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_reverse_ct import (
    reverse_ct, skip_route, atbash, caesar_decrypt,
    vigenere_decrypt, beaufort_decrypt, variant_beaufort_decrypt,
    rail_fence_undo,
    keyword_mixed, KA_ALPHABET, REVERSED_AZ, REVERSED_KA,
    crib_score, CRIB_A_EXPECTED, CRIB_B_EXPECTED,
    apply_pipeline, make_skip_route_layer, make_rail_fence_layer,
)


def probe_targeted_brute_force():
    """For every (step, offset, depth, sub_kind, kw, alphabet),
    test all 6 orderings of the 3 layers."""
    print("=" * 70)
    print("PROBE 18: targeted brute-force {sub, skip, rail} all orderings")
    print("=" * 70)
    print("CT character availability proves substitution is REQUIRED:")
    print("  PT needs 'S'×1, CT has 0 'S' — pure transposition impossible")
    print("  PT needs 'X'×2, CT has 0 'X'")
    print("  PT needs 'E'×5, CT has 3 'E'")
    print()

    keywords = [
        # Clue keywords
        "MIRROR", "MARGINS", "SHOW", "RAILS", "WORD", "ROUTE",
        "BEGINNING", "STEPS", "START", "STEP", "LESSON",
        # Title keywords
        "MIRRORROUTE", "ROUTELESSON", "MIRRORROUTELESSON",
        # Project-wide defaults
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "KEY",
        # Phrase-extracted
        "FOUR", "THREE", "FIVE",
    ]
    alphabets = [
        ("AZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("KA", KA_ALPHABET),
        ("mirrored_az", REVERSED_AZ),
        ("mirrored_ka", REVERSED_KA),
        ("kw_MIRROR", keyword_mixed("MIRROR")),
        ("kw_MARGINS", keyword_mixed("MARGINS")),
        ("kw_RAILS", keyword_mixed("RAILS")),
        ("kw_ROUTE", keyword_mixed("ROUTE")),
        ("kw_LESSON", keyword_mixed("LESSON")),
    ]
    sub_fns = [
        ("vigenere", vigenere_decrypt),
        ("beaufort", beaufort_decrypt),
        ("variant_beaufort", variant_beaufort_decrypt),
    ]
    # Bound: clue numerals + a small grid around them
    steps = [3, 4, 5, 6, 7, 8]
    offsets = [0, 1, 2, 3, 4, 5, 6, 7]
    depths = [3, 4, 5]

    best = (0, None)
    n_tested = 0
    t0 = time.monotonic()
    for kw in keywords:
        for alpha_label, alphabet in alphabets:
            if not all(c in alphabet for c in kw):
                continue
            for sub_kind, fn in sub_fns:
                sub = (sub_kind, lambda s, k=kw, a=alphabet, f=fn: f(s, k, a))
                for step in steps:
                    if math.gcd(step, 97) != 1:
                        continue
                    for offset in offsets:
                        sk = make_skip_route_layer(step, offset)
                        for depth in depths:
                            rf = make_rail_fence_layer(depth)
                            for perm in permutations([sub, sk, rf]):
                                pt = apply_pipeline(CT, list(perm))
                                cs = crib_score(pt)
                                n_tested += 1
                                if cs > best[0]:
                                    names = "->".join(l[0] for l in perm)
                                    best = (cs, (names, kw, alpha_label, sub_kind, step, offset, depth, pt[21:34], pt[63:74]))
    elapsed = time.monotonic() - t0
    print(f"  tested {n_tested:,} compositions in {elapsed:.1f}s")
    print(f"  best: cs={best[0]}/24")
    if best[1]:
        n, kw, a, sk_, st, of, dp, pa, pb = best[1]
        print(f"    pipeline: {n}")
        print(f"    sub={sk_}({kw} | {a})  skip=({st},{of})  rail={dp}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_two_layer_sub_skip():
    """The clue says 'two to three layers'. Test 2-layer
    sub + skip_route only (no rail_fence)."""
    print()
    print("=" * 70)
    print("PROBE 19: 2-layer sub + skip_route, exhaustive over keywords")
    print("=" * 70)
    keywords = [
        "MIRROR", "MARGINS", "SHOW", "RAILS", "WORD", "ROUTE",
        "BEGINNING", "STEPS", "START", "STEP", "LESSON",
        "MIRRORROUTE", "ROUTELESSON",
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "KEY",
        "FOUR", "THREE", "FIVE", "FOURRAILS",
    ]
    alphabets = [
        ("AZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("KA", KA_ALPHABET),
        ("mirrored_az", REVERSED_AZ),
        ("mirrored_ka", REVERSED_KA),
        ("kw_MIRROR", keyword_mixed("MIRROR")),
        ("kw_MARGINS", keyword_mixed("MARGINS")),
        ("kw_RAILS", keyword_mixed("RAILS")),
        ("kw_ROUTE", keyword_mixed("ROUTE")),
        ("kw_LESSON", keyword_mixed("LESSON")),
    ]
    sub_fns = [
        ("vigenere", vigenere_decrypt),
        ("beaufort", beaufort_decrypt),
        ("variant_beaufort", variant_beaufort_decrypt),
    ]
    best = (0, None)
    n_tested = 0
    for kw in keywords:
        for alpha_label, alphabet in alphabets:
            if not all(c in alphabet for c in kw):
                continue
            for sub_kind, fn in sub_fns:
                sub = (sub_kind, lambda s, k=kw, a=alphabet, f=fn: f(s, k, a))
                for step in range(2, 25):
                    if math.gcd(step, 97) != 1:
                        continue
                    for offset in range(0, 12):
                        sk = make_skip_route_layer(step, offset)
                        for label, pipe in [
                            (f"{sub_kind}->skip", [sub, sk]),
                            (f"skip->{sub_kind}", [sk, sub]),
                        ]:
                            pt = apply_pipeline(CT, pipe)
                            cs = crib_score(pt)
                            n_tested += 1
                            if cs > best[0]:
                                best = (cs, (label, kw, alpha_label, step, offset, pt[21:34], pt[63:74]))
    print(f"  tested {n_tested:,} 2-layer combinations")
    print(f"  best: cs={best[0]}/24")
    if best[1]:
        n, kw, a, st, of, pa, pb = best[1]
        print(f"    {n}({kw} | {a})  skip=({st},{of})")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_columnar_substitution():
    """Maybe the route layer is COLUMNAR (keyword-based) not skip_route."""
    print()
    print("=" * 70)
    print("PROBE 20: 3-layer sub + columnar(kw) + rail_fence")
    print("=" * 70)
    from kryptos.kernel.transforms.transposition import columnar_perm

    def keyword_to_col_order(keyword):
        # Stable rank order
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
        # Apply perm via undo direction
        inv = [0] * len(perm)
        for i, j in enumerate(perm):
            inv[j] = i
        return "".join(s[inv[i]] for i in range(len(s)))

    keywords_for_sub = ["MIRROR", "MARGINS", "RAILS", "ROUTE", "STEP",
                         "TUNNEL", "LESSON", "KRYPTOS"]
    keywords_for_col = ["MIRROR", "MARGINS", "RAILS", "ROUTE",
                         "TUNNEL", "LESSON", "STEP", "STEPS",
                         "FOUR", "THREE", "FIVE"]
    alphabets = [
        ("AZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("KA", KA_ALPHABET),
        ("mirrored_az", REVERSED_AZ),
    ]
    sub_fns = [
        ("vigenere", vigenere_decrypt),
        ("beaufort", beaufort_decrypt),
        ("variant_beaufort", variant_beaufort_decrypt),
    ]
    best = (0, None)
    n_tested = 0
    for sub_kw in keywords_for_sub:
        for col_kw in keywords_for_col:
            if len(col_kw) < 2:
                continue
            col_layer = ("columnar", lambda s, k=col_kw: columnar_undo(s, k))
            for alpha_label, alphabet in alphabets:
                if not all(c in alphabet for c in sub_kw):
                    continue
                for sub_kind, fn in sub_fns:
                    sub = (sub_kind, lambda s, k=sub_kw, a=alphabet, f=fn: f(s, k, a))
                    for depth in [3, 4, 5]:
                        rf = make_rail_fence_layer(depth)
                        # 3-layer: sub + columnar + rail_fence
                        for perm in permutations([sub, col_layer, rf]):
                            pt = apply_pipeline(CT, list(perm))
                            cs = crib_score(pt)
                            n_tested += 1
                            if cs > best[0]:
                                names = "->".join(l[0] for l in perm)
                                best = (cs, (names, sub_kw, col_kw, alpha_label, sub_kind, depth, pt[21:34], pt[63:74]))
                    # 2-layer: sub + columnar (no rail_fence)
                    for perm in permutations([sub, col_layer]):
                        pt = apply_pipeline(CT, list(perm))
                        cs = crib_score(pt)
                        n_tested += 1
                        if cs > best[0]:
                            names = "->".join(l[0] for l in perm)
                            best = (cs, (names, sub_kw, col_kw, alpha_label, sub_kind, None, pt[21:34], pt[63:74]))
    print(f"  tested {n_tested:,} columnar combinations")
    print(f"  best: cs={best[0]}/24")
    if best[1]:
        n, sk, ck, a, skind, dp, pa, pb = best[1]
        print(f"    {n}  sub={skind}({sk}|{a}) col={ck} rail={dp}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def main():
    print(f"K4B-006 ciphertext: {CT}")
    print(f"clue: {ch.clue_text}")
    print()

    t0 = time.monotonic()
    results = {}
    results["targeted_3layer_sub_skip_rail"] = probe_targeted_brute_force()
    results["2layer_sub_skip"] = probe_two_layer_sub_skip()
    results["3layer_sub_columnar_rail"] = probe_columnar_substitution()

    print()
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    for k, v in results.items():
        marker = " <-- 24/24!" if v == 24 else ""
        print(f"  {k}: max_crib={v}/24{marker}")
    print(f"  total wall time: {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()
