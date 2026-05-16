"""K4B-006: ZOOM IN on the 14/24 anchor.

Pipeline: columnar(FENCE) + beaufort(MIRROR | AZ) + rail_fence(4)
- pt[21:34] = 'LAYEFFVDEXWNE' (crib_a 'LAYERHIDESONE': 8 matches)
- pt[63:74] = 'FVNCEPMJXCX' (crib_b 'FENCEPATHXX': 6 matches)

Iterate all keys + alphabets + rail-fence depths + sub kinds with
a wider keyword pool.
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
from kryptos.kernel.transforms.transposition import (
    columnar_perm, rail_fence_perm,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_reverse_ct import (
    vigenere_decrypt, beaufort_decrypt, variant_beaufort_decrypt,
    apply_perm, invert_perm, rail_fence_undo,
    keyword_mixed, KA_ALPHABET, REVERSED_AZ, REVERSED_KA,
    crib_score, CRIB_A_EXPECTED, CRIB_B_EXPECTED,
    apply_pipeline, make_rail_fence_layer,
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


def report_per_position(pt):
    a_match = "".join(
        "X" if pt[21+j] == CRIB_A_EXPECTED[j] else "." for j in range(13)
    )
    b_match = "".join(
        "X" if pt[63+j] == CRIB_B_EXPECTED[j] else "." for j in range(11)
    )
    return a_match, b_match


def build_keyword_pool():
    """All keys to try as col / sub keys. Avoid using crib chars
    AS keys directly to keep the search hypothesis-driven, but we
    do include words that appear in EITHER the public clue OR are
    standard project defaults."""
    return [
        # Clue text keywords (public)
        "MIRROR", "MARGINS", "SHOW", "RAILS", "WORD", "ROUTE",
        "BEGINNING", "STEPS", "START", "STEP", "LESSON",
        # Numeric words from clue
        "FOUR", "THREE", "FIVE",
        # Title keywords
        "MIRRORROUTE", "ROUTELESSON", "MIRRORROUTELESSON",
        # Project defaults (already in HCC fallback pool)
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "KEY",
        # Variations / phrase compositions
        "MIRRORROUTE", "FOURRAILS", "STEPFIVE", "OFFSETTHREE",
        "MARGINSHOW", "SHOWMARGINS",
        # Cribs are public via known_plaintext_spans; the K4Bench
        # author may have keyed off them.
        "LAYER", "HIDES", "FENCE", "PATH", "TUNNEL",
        "LAYERHIDES", "FENCEPATH",
    ]


def probe_zoom():
    print("=" * 70)
    print("PROBE 24: ZOOM on 14/24 anchor — wider keyword pool, all params")
    print("=" * 70)
    keys = build_keyword_pool()
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
        ("kw_FENCE", keyword_mixed("FENCE")),
        ("kw_PATH", keyword_mixed("PATH")),
    ]
    sub_fns = [
        ("vigenere", vigenere_decrypt),
        ("beaufort", beaufort_decrypt),
        ("variant_beaufort", variant_beaufort_decrypt),
    ]
    depths = list(range(2, 11))

    best_list = []
    n_tested = 0
    t0 = time.monotonic()

    for col_kw in keys:
        if len(col_kw) < 2:
            continue
        col_layer = ("columnar", lambda s, k=col_kw: columnar_undo(s, k))
        myz_layer = ("myszkowski", lambda s, k=col_kw: myszkowski_undo(s, k))
        for trans_kind, trans_layer in [("columnar", col_layer), ("myszkowski", myz_layer)]:
            for sub_kw in keys:
                for alpha_label, alphabet in alphabets:
                    if not all(c in alphabet for c in sub_kw):
                        continue
                    for sub_kind, fn in sub_fns:
                        sub = (sub_kind, lambda s, k=sub_kw, a=alphabet, f=fn: f(s, k, a))
                        for depth in depths:
                            rf = make_rail_fence_layer(depth)
                            for perm in permutations([sub, trans_layer, rf]):
                                pt = apply_pipeline(CT, list(perm))
                                cs = crib_score(pt)
                                n_tested += 1
                                if cs >= 12:
                                    names = "->".join(l[0] for l in perm)
                                    best_list.append((
                                        cs, names, sub_kind, sub_kw,
                                        alpha_label, trans_kind, col_kw,
                                        depth, pt[21:34], pt[63:74],
                                    ))
    elapsed = time.monotonic() - t0
    print(f"  tested {n_tested:,} compositions in {elapsed:.1f}s")
    best_list.sort(key=lambda x: -x[0])
    print(f"  hits >= 12: {len(best_list)}")
    seen_top_score = best_list[0][0] if best_list else 0
    for h in best_list[:25]:
        cs, names, sk, skw, a, tk, ckw, dp, pa, pb = h
        a_match, b_match = report_per_position(
            "?" * 21 + pa + "?" * (63 - 34) + pb + "?" * (97 - 74)
        )
        print(f"    cs={cs:2d}  {names}")
        print(f"         sub={sk}({skw}|{a}) trans={tk}({ckw}) rail={dp}")
        print(f"         a={pa!r} {a_match}")
        print(f"         b={pb!r} {b_match}")
    return seen_top_score


def probe_2layer_no_rail():
    """Maybe rail_fence isn't part of the cipher — try sub + columnar
    only.
    """
    print()
    print("=" * 70)
    print("PROBE 25: 2-layer sub + columnar (no rail_fence)")
    print("=" * 70)
    keys = build_keyword_pool()
    alphabets = [
        ("AZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("KA", KA_ALPHABET),
        ("mirrored_az", REVERSED_AZ),
        ("kw_MIRROR", keyword_mixed("MIRROR")),
    ]
    sub_fns = [
        ("vigenere", vigenere_decrypt),
        ("beaufort", beaufort_decrypt),
        ("variant_beaufort", variant_beaufort_decrypt),
    ]
    best_list = []
    n_tested = 0
    for col_kw in keys:
        if len(col_kw) < 2:
            continue
        col_layer = ("columnar", lambda s, k=col_kw: columnar_undo(s, k))
        for sub_kw in keys:
            for alpha_label, alphabet in alphabets:
                if not all(c in alphabet for c in sub_kw):
                    continue
                for sub_kind, fn in sub_fns:
                    sub = (sub_kind, lambda s, k=sub_kw, a=alphabet, f=fn: f(s, k, a))
                    for perm in permutations([sub, col_layer]):
                        pt = apply_pipeline(CT, list(perm))
                        cs = crib_score(pt)
                        n_tested += 1
                        if cs >= 10:
                            names = "->".join(l[0] for l in perm)
                            best_list.append((cs, names, sub_kind, sub_kw, alpha_label, col_kw, pt[21:34], pt[63:74]))
    print(f"  tested {n_tested:,} 2-layer compositions")
    best_list.sort(key=lambda x: -x[0])
    print(f"  hits >= 10: {len(best_list)}")
    for h in best_list[:10]:
        cs, names, sk, skw, a, ckw, pa, pb = h
        print(f"    cs={cs:2d}  {names}  sub={sk}({skw}|{a}) col={ckw}")
        print(f"      a={pa!r}")
        print(f"      b={pb!r}")
    return best_list[0][0] if best_list else 0


def main():
    print(f"K4B-006 ciphertext: {CT}")
    print(f"clue: {ch.clue_text}")
    print()
    t0 = time.monotonic()
    results = {}
    results["zoom_3layer"] = probe_zoom()
    results["zoom_2layer"] = probe_2layer_no_rail()
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
