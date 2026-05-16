"""4-layer compositions with MIRROR as a 'collapsed' reversal layer.

The K4B-006 challenge constraint summary says: "Layer count is
between two and three UNLESS a clue explicitly collapses a layer
into a simple reversal or mirror." If MIRROR is a collapsed layer,
the budget becomes 4 layers: rail_fence + skip_route + sub + MIRROR.

Also tries:
- Title keyword "LESSON" / "MIRROR ROUTE LESSON"
- Caesar shifts in the substitution slot (instead of keyed Vigenere)
- All 6 orderings of the 4 components
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
    apply_perm, invert_perm, rail_fence_undo,
    keyword_mixed, KA_ALPHABET, REVERSED_AZ, REVERSED_KA,
    crib_score, CRIB_A_EXPECTED, CRIB_B_EXPECTED,
    apply_pipeline, make_skip_route_layer, make_rail_fence_layer,
    make_reverse_ct_layer, make_atbash_layer, make_caesar_layer,
)


def probe_four_layer():
    """sub + skip + rail + reverse, all 24 orderings of 4 layers."""
    print("=" * 70)
    print("PROBE 14: 4-layer (sub + skip + rail + reverse), all 24 orders")
    print("=" * 70)
    rev = make_reverse_ct_layer()
    best = (0, None)
    n_tested = 0

    keywords = ["MIRROR", "MARGINS", "TUNNEL", "ROUTE", "FENCE", "RAILS",
                "PATH", "LAYER", "LESSON", "MIRRORROUTE", "ROUTELESSON"]
    alphabets = [
        ("AZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("KA", KA_ALPHABET),
        ("mirrored_az", REVERSED_AZ),
        ("kw_MIRROR", keyword_mixed("MIRROR")),
    ]
    # Pin clue-derived (step=5, offset=3) and rail_fence(4)
    sk = make_skip_route_layer(5, 3)
    rf = make_rail_fence_layer(4)

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
                for perm in permutations([sub, sk, rf, rev]):
                    pt = apply_pipeline(CT, list(perm))
                    cs = crib_score(pt)
                    n_tested += 1
                    if cs > best[0]:
                        names = " -> ".join(l[0] for l in perm)
                        best = (cs, (names, kw, alpha_label, sub_kind, pt[21:34], pt[63:74]))
    print(f"  tested {n_tested} 4-layer compositions")
    print(f"  best 4-layer: cs={best[0]}/24")
    if best[1]:
        n, kw, a, sk_, pa, pb = best[1]
        print(f"    pipeline: {n}")
        print(f"    sub={sk_}({kw} | {a})")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_caesar_shifts_with_skip_rail():
    """Replace Vigenere with Caesar shift in the substitution slot."""
    print()
    print("=" * 70)
    print("PROBE 15: caesar(shift) + skip(5,3) + rail_fence(4) all orderings")
    print("=" * 70)
    sk = make_skip_route_layer(5, 3)
    rf = make_rail_fence_layer(4)
    best = (0, None)
    for shift in range(1, 26):
        cs_layer = make_caesar_layer(shift)
        for perm in permutations([cs_layer, sk, rf]):
            pt = apply_pipeline(CT, list(perm))
            cs = crib_score(pt)
            if cs > best[0]:
                names = " -> ".join(l[0] for l in perm)
                best = (cs, (names, shift, pt[21:34], pt[63:74]))
    # Also try with reverse_ct as 4th layer
    rev = make_reverse_ct_layer()
    for shift in range(1, 26):
        cs_layer = make_caesar_layer(shift)
        for perm in permutations([cs_layer, sk, rf, rev]):
            pt = apply_pipeline(CT, list(perm))
            cs = crib_score(pt)
            if cs > best[0]:
                names = " -> ".join(l[0] for l in perm)
                best = (cs, (names, shift, pt[21:34], pt[63:74]))
    print(f"  best caesar + skip + rail (+/-rev): cs={best[0]}/24")
    if best[1]:
        n, sh, pa, pb = best[1]
        print(f"    {n}  shift={sh}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_atbash_skip_rail():
    """atbash + skip(5,3) + rail_fence(4) — most parsimonious
    interpretation if MIRROR == atbash and the cipher is just
    a 3-layer composition."""
    print()
    print("=" * 70)
    print("PROBE 16: atbash + skip(5,3) + rail_fence(d) all orderings, all d")
    print("=" * 70)
    at = make_atbash_layer()
    best = (0, None)
    for step in [s for s in range(2, 25) if math.gcd(s, 97) == 1]:
        for offset in range(0, 12):
            sk = make_skip_route_layer(step, offset)
            for depth in range(2, 11):
                rf = make_rail_fence_layer(depth)
                for perm in permutations([at, sk, rf]):
                    pt = apply_pipeline(CT, list(perm))
                    cs = crib_score(pt)
                    if cs > best[0]:
                        names = " -> ".join(l[0] for l in perm)
                        best = (cs, (names, step, offset, depth, pt[21:34], pt[63:74]))
    print(f"  best atbash + skip + rail: cs={best[0]}/24")
    if best[1]:
        n, s, o, d, pa, pb = best[1]
        print(f"    {n}  step={s}, offset={o}, depth={d}")
        print(f"    pt[21:34]={pa!r}")
        print(f"    pt[63:74]={pb!r}")
    return best[0]


def probe_position_dependent_match():
    """Try every (step, offset) and check ANY layer combination
    that gives consecutive crib chars at positions 21-23 (LAY)."""
    print()
    print("=" * 70)
    print("PROBE 17: scan for ANY pipeline that matches PT[21:24]='LAY'")
    print("=" * 70)
    best_consecutive = 0
    best_meta = None

    candidates = []
    # Try simple skip_route with various step/offset
    for step in range(1, 97):
        if math.gcd(step, 97) != 1:
            continue
        for offset in range(0, 97):
            sk = make_skip_route_layer(step, offset)
            pt = apply_pipeline(CT, [sk])
            if pt[21:24] == "LAY":
                candidates.append(("skip_alone", step, offset, pt[21:34], pt[63:74]))

    print(f"  skip_route alone candidates with PT[21:24]='LAY': {len(candidates)}")
    for c in candidates[:10]:
        print(f"    {c}")
    return len(candidates)


def main():
    print(f"K4B-006 ciphertext: {CT}")
    print(f"clue: {ch.clue_text}")
    print()

    t0 = time.monotonic()
    results = {}
    results["four_layer_with_reverse"] = probe_four_layer()
    results["caesar_skip_rail"] = probe_caesar_shifts_with_skip_rail()
    results["atbash_skip_rail"] = probe_atbash_skip_rail()
    n_lay = probe_position_dependent_match()

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for k, v in results.items():
        marker = " <-- 24/24!" if v == 24 else ""
        print(f"  {k}: max_crib={v}/24{marker}")
    print(f"  skip_route alone candidates with PT[21:24]='LAY': {n_lay}")
    print(f"  total wall time: {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()
