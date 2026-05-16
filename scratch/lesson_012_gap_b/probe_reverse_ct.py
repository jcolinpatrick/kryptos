"""Scratch experimental probe for K4B-006 Gap B.

Hypothesis: the unmapped clue token "MIRROR" denotes a CT-reversal
layer (PT[i] = source[L-1-i]) rather than only an alphabet modifier.
Combined with skip_route(5,3) and rail_fence(4), this would give a
3-layer composition matching the challenge's "two-to-three layers"
budget.

This script does NOT commit production changes. It runs a brute-
force search over reverse_ct compositions against the K4B-006
cribs and reports max_crib + the exact winning composition (if any).

Usage:
    PYTHONPATH=src python3 scratch/lesson_012_gap_b/probe_reverse_ct.py
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

# Install K4B-006 kernel overrides BEFORE importing kernel
from kryptosbot.bench_loader import load_k4bench_challenge
ch = load_k4bench_challenge(_REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-006.json")
ch.install_kernel_overrides()

from kryptos.kernel.constants import CT, CRIB_DICT, CT_LEN
from kryptos.kernel.transforms.transposition import (
    rail_fence_perm,
    serpentine_perm,
)


# ---------------------------------------------------------------------------
# Pure-Python primitives for the experimental search
# ---------------------------------------------------------------------------


def reverse_ct(s: str) -> str:
    """Full-text reversal: output[i] = input[L-1-i]."""
    return s[::-1]


def skip_route(s: str, step: int, offset: int) -> str:
    """Modular skip-step walk: output[i] = input[(offset + i*step) mod L]."""
    L = len(s)
    return "".join(s[(offset + i * step) % L] for i in range(L))


def apply_perm(s: str, perm: list[int]) -> str:
    """Apply a permutation: output[i] = input[perm[i]]."""
    return "".join(s[perm[i]] for i in range(len(s)))


def invert_perm(perm: list[int]) -> list[int]:
    out = [0] * len(perm)
    for i, j in enumerate(perm):
        out[j] = i
    return out


def rail_fence_undo(s: str, depth: int) -> str:
    """Apply rail_fence undo (encryption-inverse), matching the
    dispatcher convention for direction='undo'."""
    perm = rail_fence_perm(len(s), depth)
    inv = invert_perm(perm)
    return apply_perm(s, inv)


def serpentine_undo(s: str, rows: int, cols: int, vertical: bool = False) -> str:
    perm = serpentine_perm(rows, cols, len(s), vertical=vertical)
    inv = invert_perm(perm)
    return apply_perm(s, inv)


def vigenere_decrypt(s: str, key: str, alphabet: str = None) -> str:
    """Vigenere decrypt over canonical or mixed alphabet.
    alphabet=None means standard A-Z."""
    if alphabet is None:
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    else:
        alpha = alphabet
    L = len(s)
    K = len(key)
    out = []
    for i, c in enumerate(s):
        ci = alpha.index(c)
        ki = alpha.index(key[i % K])
        out.append(alpha[(ci - ki) % 26])
    return "".join(out)


def beaufort_decrypt(s: str, key: str, alphabet: str = None) -> str:
    """Beaufort decrypt: P = (K - C) mod 26 (self-reciprocal)."""
    if alphabet is None:
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    else:
        alpha = alphabet
    K = len(key)
    out = []
    for i, c in enumerate(s):
        ci = alpha.index(c)
        ki = alpha.index(key[i % K])
        out.append(alpha[(ki - ci) % 26])
    return "".join(out)


def variant_beaufort_decrypt(s: str, key: str, alphabet: str = None) -> str:
    """Variant Beaufort decrypt: P = (C + K) mod 26
    (encryption: C = P - K)."""
    if alphabet is None:
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    else:
        alpha = alphabet
    K = len(key)
    out = []
    for i, c in enumerate(s):
        ci = alpha.index(c)
        ki = alpha.index(key[i % K])
        out.append(alpha[(ci + ki) % 26])
    return "".join(out)


def atbash(s: str) -> str:
    """Atbash: A->Z, B->Y, ..., self-inverse over canonical alphabet."""
    return "".join(chr(ord("A") + 25 - (ord(c) - ord("A"))) for c in s)


def caesar_decrypt(s: str, shift: int) -> str:
    """Caesar decrypt: P = (C - shift) mod 26."""
    out = []
    for c in s:
        out.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
    return "".join(out)


# Mixed alphabet generation (matches kernel's keyword_mixed_alphabet)
def keyword_mixed(keyword: str) -> str:
    """KRYPTOS-style mixed alphabet: keyword first (deduplicated),
    then remaining A-Z letters in order."""
    seen = []
    seen_set = set()
    for c in keyword.upper():
        if c.isalpha() and c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    return "".join(seen)


KA_ALPHABET = keyword_mixed("KRYPTOS")
REVERSED_AZ = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
REVERSED_KA = KA_ALPHABET[::-1]


# ---------------------------------------------------------------------------
# Score against K4B-006 cribs
# ---------------------------------------------------------------------------


def crib_score(pt: str) -> int:
    if len(pt) < 74:
        return 0
    return sum(1 for pos, ch in CRIB_DICT.items() if pt[pos] == ch)


CRIB_A_EXPECTED = "LAYERHIDESONE"
CRIB_B_EXPECTED = "FENCEPATHXX"


def report_match(pt: str) -> tuple[int, str, str]:
    cs = crib_score(pt)
    a_match = "".join(
        "X" if pt[21 + j] == CRIB_A_EXPECTED[j] else "."
        for j in range(13)
    )
    b_match = "".join(
        "X" if pt[63 + j] == CRIB_B_EXPECTED[j] else "."
        for j in range(11)
    )
    return cs, a_match, b_match


# ---------------------------------------------------------------------------
# Layer factory + composition
# ---------------------------------------------------------------------------


def make_skip_route_layer(step: int, offset: int):
    return ("skip_route", lambda s, k=step, o=offset: skip_route(s, k, o))


def make_rail_fence_layer(depth: int):
    return ("rail_fence", lambda s, d=depth: rail_fence_undo(s, d))


def make_reverse_ct_layer():
    return ("reverse_ct", lambda s: reverse_ct(s))


def make_atbash_layer():
    return ("atbash", lambda s: atbash(s))


def make_caesar_layer(shift: int):
    return ("caesar", lambda s, k=shift: caesar_decrypt(s, k))


def make_vigenere_layer(key: str, alphabet: str | None = None):
    a = "vigenere"
    return (a, lambda s, k=key, alph=alphabet: vigenere_decrypt(s, k, alph))


def make_beaufort_layer(key: str, alphabet: str | None = None):
    return ("beaufort", lambda s, k=key, alph=alphabet: beaufort_decrypt(s, k, alph))


def make_variant_beaufort_layer(key: str, alphabet: str | None = None):
    return (
        "variant_beaufort",
        lambda s, k=key, alph=alphabet: variant_beaufort_decrypt(s, k, alph),
    )


def apply_pipeline(ct: str, pipeline: list) -> str:
    """Apply a pipeline of (name, fn) tuples in order. The pipeline
    is the DECRYPTION direction, so the first layer fires first."""
    cur = ct
    for _, fn in pipeline:
        cur = fn(cur)
    return cur


def pipeline_label(pipeline: list) -> str:
    return " -> ".join(name for name, _ in pipeline)


# ---------------------------------------------------------------------------
# Brute-force probes
# ---------------------------------------------------------------------------


def probe_reverse_only():
    print("=" * 70)
    print("PROBE 1: reverse_ct alone")
    print("=" * 70)
    pipe = [make_reverse_ct_layer()]
    pt = apply_pipeline(CT, pipe)
    cs, a, b = report_match(pt)
    print(f"  cs={cs}/24  crib_a:{a}  crib_b:{b}")
    print(f"  pt[21:34]={pt[21:34]!r}  expected={CRIB_A_EXPECTED!r}")
    print(f"  pt[63:74]={pt[63:74]!r}  expected={CRIB_B_EXPECTED!r}")
    return cs


def probe_two_layer_with_reverse():
    """reverse_ct combined with each existing primitive in both orders."""
    print()
    print("=" * 70)
    print("PROBE 2: reverse_ct + (single primitive) in both orders")
    print("=" * 70)
    best = (0, None)

    other_layers = []
    # skip_route across all coprime steps and offsets
    for step in range(2, 24):
        if math.gcd(step, 97) != 1:
            continue
        for offset in range(min(step, 6)):
            other_layers.append(
                ("skip_route", make_skip_route_layer(step, offset), {"step": step, "offset": offset}),
            )
    # rail_fence depths 2..10
    for depth in range(2, 11):
        other_layers.append(("rail_fence", make_rail_fence_layer(depth), {"depth": depth}))
    # atbash, caesar shifts
    other_layers.append(("atbash", make_atbash_layer(), {}))
    for shift in range(1, 26):
        other_layers.append(("caesar", make_caesar_layer(shift), {"shift": shift}))

    rev = make_reverse_ct_layer()
    for kind, layer, params in other_layers:
        for label, pipe in [
            (f"reverse->{kind}", [rev, layer]),
            (f"{kind}->reverse", [layer, rev]),
        ]:
            pt = apply_pipeline(CT, pipe)
            cs, a, b = report_match(pt)
            if cs > best[0]:
                best = (cs, (label, params, a, b, pt[21:34], pt[63:74]))
    print(f"  best 2-layer with reverse: cs={best[0]}/24")
    if best[1]:
        print(f"    label={best[1][0]}  params={best[1][1]}")
        print(f"    crib_a: {best[1][2]}  pt[21:34]={best[1][4]!r}")
        print(f"    crib_b: {best[1][3]}  pt[63:74]={best[1][5]!r}")
    return best[0]


def probe_three_layer_reverse_skip_rail():
    """The clue suggests rail_fence(4) + skip_route(5,3) + reverse_ct.
    Try all 6 orderings of these three layers, for all (step, offset, depth)
    combos around clue values.
    """
    print()
    print("=" * 70)
    print("PROBE 3: reverse_ct + skip_route + rail_fence in all 6 orderings")
    print("=" * 70)
    rev = make_reverse_ct_layer()
    best = (0, None)
    n_tested = 0
    # Bound search space
    steps = [s for s in range(2, 25) if math.gcd(s, 97) == 1]
    offsets = list(range(0, 12))
    depths = list(range(2, 11))
    for step in steps:
        for offset in offsets:
            sk = make_skip_route_layer(step, offset)
            for depth in depths:
                rf = make_rail_fence_layer(depth)
                # All 6 orderings of {rev, sk, rf}
                for perm in permutations([rev, sk, rf]):
                    pt = apply_pipeline(CT, list(perm))
                    cs = crib_score(pt)
                    n_tested += 1
                    if cs > best[0]:
                        names = " -> ".join(l[0] for l in perm)
                        best = (cs, (names, step, offset, depth, pt[21:34], pt[63:74]))
    print(f"  tested {n_tested} combinations")
    print(f"  best 3-layer (rev + skip + rail): cs={best[0]}/24")
    if best[1]:
        names, step, offset, depth, pt_a, pt_b = best[1]
        print(f"    pipeline: {names}")
        print(f"    step={step}, offset={offset}, depth={depth}")
        print(f"    pt[21:34]={pt_a!r}  expected={CRIB_A_EXPECTED!r}")
        print(f"    pt[63:74]={pt_b!r}  expected={CRIB_B_EXPECTED!r}")
    return best[0]


def probe_three_layer_with_substitution():
    """sub + skip_route + reverse_ct — replacing rail_fence with a
    substitution layer. Tests whether MIRROR + step five suffices
    without rail_fence (the "four rails" anchor might still bind to
    a different parameter).
    """
    print()
    print("=" * 70)
    print("PROBE 4: substitution + skip_route + reverse_ct, all orderings")
    print("=" * 70)
    rev = make_reverse_ct_layer()
    best = (0, None)
    keywords = ["MIRROR", "MARGINS", "TUNNEL", "ROUTE", "FENCE", "RAILS", "PATH", "LAYER"]
    alphabet_modes = [
        ("AZ", None),
        ("KA", KA_ALPHABET),
        ("mirrored_az", REVERSED_AZ),
        ("mirrored_ka", REVERSED_KA),
    ]
    for kw in keywords:
        for alpha_label, alpha in alphabet_modes:
            kw_for_alpha = kw if alpha is None else None  # use given alpha
            for sub_kind, factory in [
                ("vigenere", lambda k, a=alpha: make_vigenere_layer(k, a)),
                ("beaufort", lambda k, a=alpha: make_beaufort_layer(k, a)),
                ("variant_beaufort", lambda k, a=alpha: make_variant_beaufort_layer(k, a)),
            ]:
                # Build layer with this keyword × alphabet
                # For mixed alphabets, we use the alphabet permutation
                # directly; key letters look up indices in that alphabet
                # which is what kernel keyword_mixed_alphabet does.
                if alpha is None:
                    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                else:
                    alphabet = alpha
                # Skip if keyword has letters not in the alphabet
                if not all(c in alphabet for c in kw):
                    continue
                if sub_kind == "vigenere":
                    sub_layer = (sub_kind, lambda s, k=kw, a=alphabet: vigenere_decrypt(s, k, a))
                elif sub_kind == "beaufort":
                    sub_layer = (sub_kind, lambda s, k=kw, a=alphabet: beaufort_decrypt(s, k, a))
                else:
                    sub_layer = (sub_kind, lambda s, k=kw, a=alphabet: variant_beaufort_decrypt(s, k, a))
                # Iterate skip_route params (step=5, offset=3) and a
                # small grid around it
                for step in [3, 5, 7]:
                    if math.gcd(step, 97) != 1:
                        continue
                    for offset in range(0, 8):
                        sk = make_skip_route_layer(step, offset)
                        for perm in permutations([rev, sk, sub_layer]):
                            pt = apply_pipeline(CT, list(perm))
                            cs = crib_score(pt)
                            if cs > best[0]:
                                names = " -> ".join(l[0] for l in perm)
                                best = (cs, (names, kw, alpha_label, sub_kind, step, offset, pt[21:34], pt[63:74]))
    print(f"  best 3-layer (sub + skip + rev): cs={best[0]}/24")
    if best[1]:
        names, kw, alpha, sub_kind, step, offset, pt_a, pt_b = best[1]
        print(f"    pipeline: {names}")
        print(f"    sub={sub_kind}({kw}, alpha={alpha})  skip=({step},{offset})")
        print(f"    pt[21:34]={pt_a!r}")
        print(f"    pt[63:74]={pt_b!r}")
    return best[0]


def probe_two_layer_skip_then_reverse():
    """skip_route + reverse_ct in 2-layer form. Tests whether the
    cipher might be just skip_route + reverse without rail_fence."""
    print()
    print("=" * 70)
    print("PROBE 5: skip_route + reverse_ct in 2-layer form (no rail_fence)")
    print("=" * 70)
    rev = make_reverse_ct_layer()
    best = (0, None)
    steps = [s for s in range(2, 25) if math.gcd(s, 97) == 1]
    for step in steps:
        for offset in range(0, 25):
            sk = make_skip_route_layer(step, offset)
            for perm_label, perm in [
                ("rev->skip", [rev, sk]),
                ("skip->rev", [sk, rev]),
            ]:
                pt = apply_pipeline(CT, perm)
                cs = crib_score(pt)
                if cs > best[0]:
                    best = (cs, (perm_label, step, offset, pt[21:34], pt[63:74]))
    print(f"  best 2-layer: cs={best[0]}/24")
    if best[1]:
        label, step, offset, pt_a, pt_b = best[1]
        print(f"    {label}  step={step}, offset={offset}")
        print(f"    pt[21:34]={pt_a!r}")
        print(f"    pt[63:74]={pt_b!r}")
    return best[0]


def probe_serpentine_route_with_reverse():
    """Maybe MIRROR doesn't mean reverse_ct, but the route is a
    serpentine and "mirror" refers to alternating direction. Try
    serpentine_route over various grids + reverse + rail_fence.
    """
    print()
    print("=" * 70)
    print("PROBE 6: serpentine_route + reverse_ct + rail_fence")
    print("=" * 70)
    rev = make_reverse_ct_layer()
    best = (0, None)
    grids = [(7, 14), (10, 10), (8, 13), (14, 7), (13, 8), (5, 20)]
    for rows, cols in grids:
        if rows * cols < 97:
            continue
        for vertical in [False, True]:
            sr = ("route", lambda s, r=rows, c=cols, v=vertical: serpentine_undo(s, r, c, v))
            for depth in [3, 4, 5]:
                rf = make_rail_fence_layer(depth)
                for perm in permutations([rev, sr, rf]):
                    pt = apply_pipeline(CT, list(perm))
                    cs = crib_score(pt)
                    if cs > best[0]:
                        names = " -> ".join(l[0] for l in perm)
                        best = (cs, (names, rows, cols, vertical, depth, pt[21:34], pt[63:74]))
    print(f"  best: cs={best[0]}/24")
    if best[1]:
        names, rows, cols, vert, depth, pt_a, pt_b = best[1]
        print(f"    {names}  grid=({rows},{cols},vert={vert})  depth={depth}")
        print(f"    pt[21:34]={pt_a!r}")
        print(f"    pt[63:74]={pt_b!r}")
    return best[0]


def main():
    print(f"K4B-006 ciphertext (97 chars): {CT}")
    print(f"crib_a (21-33): {CRIB_A_EXPECTED}")
    print(f"crib_b (63-73): {CRIB_B_EXPECTED}")
    print(f"clue: {ch.clue_text}")
    print()

    t0 = time.monotonic()
    results = {}
    results["reverse_only"] = probe_reverse_only()
    results["reverse_two_layer"] = probe_two_layer_with_reverse()
    results["skip_then_reverse_2_layer"] = probe_two_layer_skip_then_reverse()
    results["reverse_skip_rail_3_layer"] = probe_three_layer_reverse_skip_rail()
    results["sub_skip_reverse_3_layer"] = probe_three_layer_with_substitution()
    results["serpentine_reverse_rail"] = probe_serpentine_route_with_reverse()

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
