#!/usr/bin/env python3
"""
Layer-peeling search inspired by Call of Duty cipher solutions (colski).

Principle: K4 was built by applying multiple simple operations in sequence.
Each layer uses a KNOWN key (from the sculpture) and a KNOWN method.
We search ordered combinations up to depth 4, pruning by IC improvement.

Cipher: multi-layer
Family: multi_layer
Status: active
Keyspace: ~100 ops/layer × depth 4 with IC pruning
Last run: never
Best score: n/a
"""

import sys
import time
from collections import defaultdict
from typing import List, Tuple, Callable

sys.path.insert(0, "src")

from kryptos.kernel.constants import CT
from kryptos.kernel.text import sanitize, text_to_nums
from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.free_crib import score_free_fast
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
    rail_fence_perm, myszkowski_perm,
)


# ── Known keywords from the sculpture ──────────────────────────────────

KEYWORDS = [
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "LAYERTWO",
    "SHADOW",
    "IDBYROWS",
    "DYAHRO",
    "EQUINOX",
    "FIVE",
    "BERLINCLOCK",
    "EASTNORTHEAST",
    "SANBORN",
    "SCHEIDT",
    "WEBSTER",
]


# ── Build operation catalog ────────────────────────────────────────────

def build_operations() -> List[Tuple[str, Callable[[str], str]]]:
    """Build all single-layer operations (name, function)."""
    ops: List[Tuple[str, Callable[[str], str]]] = []

    # 1. Substitution: decrypt with each keyword × variant × alphabet
    for kw in KEYWORDS:
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                key_nums = [alpha.char_to_idx(c) for c in kw]
                vname = variant.value[:3]
                name = f"sub/{vname}/{alpha_name}/{kw}"

                def make_fn(k=key_nums, v=variant):
                    def fn(text):
                        return decrypt_text(text, k, v)
                    return fn

                ops.append((name, make_fn()))

    # 2. Caesar shifts (0-25)
    for shift in range(1, 26):
        name = f"caesar/{shift}"

        def make_caesar(s=shift):
            def fn(text):
                return "".join(chr((ord(c) - 65 + s) % 26 + 65) for c in text)
            return fn

        ops.append((name, make_caesar()))

    # 3. Reverse string
    ops.append(("reverse", lambda text: text[::-1]))

    # 4. Columnar transposition reversal with keyword-derived column orders
    for kw in KEYWORDS:
        width = len(kw)
        if width < 2 or width > 50:
            continue
        order = keyword_to_order(kw, width)
        if order is None:
            continue
        perm = columnar_perm(width, order, 97)
        inv = invert_perm(perm)
        name = f"col_inv/{kw}"

        def make_col(p=inv):
            def fn(text):
                if len(text) != len(p):
                    return text
                return apply_perm(text, p)
            return fn

        ops.append((name, make_col()))

    # 5. Myszkowski reversal with keywords
    for kw in KEYWORDS:
        if len(kw) < 2 or len(kw) > 50:
            continue
        perm = myszkowski_perm(kw, 97)
        if len(perm) != 97:
            continue
        inv = invert_perm(perm)
        name = f"mysz_inv/{kw}"

        def make_mysz(p=inv):
            def fn(text):
                if len(text) != len(p):
                    return text
                return apply_perm(text, p)
            return fn

        ops.append((name, make_mysz()))

    # 6. Rail fence reversal (depths 2-6)
    for depth in range(2, 7):
        perm = rail_fence_perm(97, depth)
        inv = invert_perm(perm)
        name = f"rail_inv/{depth}"

        def make_rail(p=inv):
            def fn(text):
                if len(text) != len(p):
                    return text
                return apply_perm(text, p)
            return fn

        ops.append((name, make_rail()))

    # 7. Columnar with numeric widths (no keyword, natural order)
    for width in [7, 8, 10, 14, 24, 31]:
        order = tuple(range(width))
        perm = columnar_perm(width, order, 97)
        inv = invert_perm(perm)
        name = f"col_inv/w{width}_natural"

        def make_coln(p=inv):
            def fn(text):
                if len(text) != len(p):
                    return text
                return apply_perm(text, p)
            return fn

        ops.append((name, make_coln()))

    return ops


# ── Signature detection ────────────────────────────────────────────────

def compute_signature(text: str) -> dict:
    """Compute statistical signatures for intermediate text."""
    ic_val = ic(text)
    crib_anchored = score_cribs(text)
    crib_free = score_free_fast(text)
    return {
        "ic": ic_val,
        "crib_anchored": crib_anchored,
        "crib_free": crib_free,
    }


# ── Main search ────────────────────────────────────────────────────────

def attack(ciphertext: str, max_depth: int = 3, ic_prune: float = 0.034,
           crib_report: int = 10) -> list:
    """
    Layer-peeling search.

    At each depth, apply every operation and check signatures.
    Prune paths where IC doesn't improve above threshold.
    Report any path that produces crib hits.
    """
    ops = build_operations()
    print(f"Operations per layer: {len(ops)}")
    print(f"Max depth: {max_depth}")
    print(f"IC prune threshold: {ic_prune}")
    print()

    results = []
    best_ic = 0.0
    best_crib_anchored = 0
    best_crib_free = 0
    total_evals = 0

    # BFS with pruning
    # State: (text, path, depth)
    queue = [(ciphertext, [], 0)]

    baseline_sig = compute_signature(ciphertext)
    print(f"Baseline: IC={baseline_sig['ic']:.4f}, "
          f"crib_anchored={baseline_sig['crib_anchored']}/24, "
          f"crib_free={baseline_sig['crib_free']}/24")
    print()

    for depth in range(1, max_depth + 1):
        next_queue = []
        depth_best_ic = 0.0
        depth_best_crib = 0
        depth_evals = 0
        depth_survivors = 0

        print(f"=== Depth {depth} === ({len(queue)} inputs × {len(ops)} ops = {len(queue)*len(ops):,} evals)")

        for text, path, _ in queue:
            for op_name, op_fn in ops:
                try:
                    result = op_fn(text)
                except Exception:
                    continue

                if len(result) != 97 or not result.isalpha():
                    continue

                result = result.upper()
                total_evals += 1
                depth_evals += 1

                # Fast scoring
                ic_val = ic(result)
                crib_a = score_cribs(result)
                crib_f = score_free_fast(result)

                new_path = path + [op_name]

                # Track bests
                if ic_val > best_ic:
                    best_ic = ic_val
                if crib_a > best_crib_anchored:
                    best_crib_anchored = crib_a
                if crib_f > best_crib_free:
                    best_crib_free = crib_f
                if ic_val > depth_best_ic:
                    depth_best_ic = ic_val
                if crib_a > depth_best_crib:
                    depth_best_crib = crib_a

                # Report significant results
                if crib_a >= crib_report or crib_f >= crib_report:
                    chain = " → ".join(new_path)
                    print(f"  *** CRIB HIT: anchored={crib_a}/24 free={crib_f}/24 "
                          f"IC={ic_val:.4f} path=[{chain}]")
                    print(f"      text: {result}")
                    results.append((crib_a + crib_f, result, chain, ic_val))

                if ic_val >= 0.055:
                    chain = " → ".join(new_path)
                    print(f"  *** HIGH IC: {ic_val:.4f} crib_a={crib_a}/24 "
                          f"path=[{chain}]")
                    print(f"      text: {result}")

                # Pruning: keep for next depth if IC is above threshold
                # or if any crib hits
                if depth < max_depth:
                    if ic_val >= ic_prune or crib_a >= 5 or crib_f >= 5:
                        next_queue.append((result, new_path, depth))
                        depth_survivors += 1

        print(f"  Evaluated: {depth_evals:,} | Survivors: {depth_survivors:,} | "
              f"Best IC: {depth_best_ic:.4f} | Best crib: {depth_best_crib}/24")
        print(f"  Running totals: {total_evals:,} evals, best IC={best_ic:.4f}, "
              f"best crib_a={best_crib_anchored}/24, best crib_f={best_crib_free}/24")
        print()

        queue = next_queue

    # Sort results
    results.sort(key=lambda x: x[0], reverse=True)
    return results


def main():
    t0 = time.time()
    print("=" * 70)
    print("Layer-Peeling Search (CoD Method)")
    print("Inspired by colski's multi-layer cipher solving framework")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Length: {len(CT)}")
    print()

    results = attack(CT, max_depth=3, ic_prune=0.034, crib_report=8)

    elapsed = time.time() - t0
    print("=" * 70)
    print(f"COMPLETE in {elapsed:.1f}s")
    print(f"Top results:")
    for score, text, chain, ic_val in results[:20]:
        print(f"  score={score} IC={ic_val:.4f} path=[{chain}]")
        print(f"    {text}")
    if not results:
        print("  No results above threshold.")
    print("=" * 70)


if __name__ == "__main__":
    main()
