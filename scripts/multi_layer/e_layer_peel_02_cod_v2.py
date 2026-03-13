#!/usr/bin/env python3
"""
Layer-peeling search v2 — expanded operation set.

Adds: autokey, Quagmire III, route/spiral transpositions, atbash,
keyed-alphabet substitution, 73-char null extraction masks,
forward columnar (encipher direction), and reversed text variants.

Cipher: multi-layer
Family: multi_layer
Status: active
Keyspace: ~350 ops/layer × depth 3 with adaptive pruning
Last run: never
Best score: n/a
"""

import sys
import time
import itertools
from collections import defaultdict
from typing import List, Tuple, Callable, Optional

sys.path.insert(0, "src")

from kryptos.kernel.constants import CT
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.free_crib import score_free_fast
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, encrypt_text, CipherVariant,
)
from kryptos.kernel.transforms.autokey import autokey_decrypt
from kryptos.kernel.transforms.quagmire import quagmire_decrypt
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
    rail_fence_perm, myszkowski_perm, serpentine_perm, spiral_perm,
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
    "KOMPASS",
    "DEFECTOR",
    "COLOPHON",
    "FLOWCHART",
    "HOROLOGE",
    "VERDIGRIS",
    "CLOCK",
    "BERLIN",
]

# Shorter keywords for autokey primers
AUTOKEY_PRIMERS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LAYERTWO", "SHADOW",
    "IDBYROWS", "DYAHRO", "EQUINOX", "FIVE", "SANBORN", "SCHEIDT",
    "WEBSTER", "KOMPASS", "DEFECTOR",
]

# 73-char null extraction: candidate null position sets
# W positions as nulls (5 W's)
W_POSITIONS = [i for i, c in enumerate(CT) if c == "W"]  # [20, 36, 48, 58, 74]


def build_operations() -> List[Tuple[str, Callable[[str], str]]]:
    """Build expanded operation catalog."""
    ops: List[Tuple[str, Callable[[str], str]]] = []

    # ═══════════════════════════════════════════════════════════
    # 1. SUBSTITUTION: Vig/Beau/VarBeau × keywords × AZ/KA
    # ═══════════════════════════════════════════════════════════
    for kw in KEYWORDS:
        for variant in CipherVariant:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                key_nums = [alpha.char_to_idx(c) for c in kw]
                vname = variant.value[:3]
                name = f"sub/{vname}/{alpha_name}/{kw}"

                def make_fn(k=key_nums, v=variant):
                    return lambda text: decrypt_text(text, k, v)

                ops.append((name, make_fn()))

    # ═══════════════════════════════════════════════════════════
    # 2. AUTOKEY: decrypt with each primer × variant
    # ═══════════════════════════════════════════════════════════
    for primer in AUTOKEY_PRIMERS:
        for variant in ["vigenere", "beaufort", "var_beaufort"]:
            name = f"autokey/{variant[:3]}/{primer}"

            def make_ak(p=primer, v=variant):
                return lambda text: autokey_decrypt(text, p, v)

            ops.append((name, make_ak()))

    # ═══════════════════════════════════════════════════════════
    # 3. QUAGMIRE III: mixed CT alphabet × period keyword
    # ═══════════════════════════════════════════════════════════
    ct_alpha_kws = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
    period_kws = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "LAYERTWO", "SHADOW"]
    for ct_kw in ct_alpha_kws:
        for per_kw in period_kws:
            for indicator in ["A", "K"]:
                name = f"quag3/{ct_kw}/{per_kw}/{indicator}"

                def make_q(ck=ct_kw, pk=per_kw, ind=indicator):
                    return lambda text: quagmire_decrypt(
                        text, pk, indicator=ind, ct_alphabet_keyword=ck
                    )

                ops.append((name, make_q()))

    # ═══════════════════════════════════════════════════════════
    # 4. SIMPLE SUBSTITUTIONS
    # ═══════════════════════════════════════════════════════════

    # Caesar shifts (1-25)
    for shift in range(1, 26):
        name = f"caesar/{shift}"

        def make_c(s=shift):
            return lambda text: "".join(
                chr((ord(c) - 65 + s) % 26 + 65) for c in text
            )

        ops.append((name, make_c()))

    # Atbash (A↔Z, B↔Y, ...)
    ops.append((
        "atbash",
        lambda text: "".join(chr(155 - ord(c)) for c in text),  # 155 = 65+90
    ))

    # Keyed-alphabet simple substitution (monoalphabetic)
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        mixed = keyword_mixed_alphabet(kw)
        fwd_map = {chr(65 + i): mixed[i] for i in range(26)}
        rev_map = {v: k for k, v in fwd_map.items()}
        name = f"keyed_mono/{kw}"

        def make_mono(rm=rev_map):
            return lambda text: "".join(rm.get(c, c) for c in text)

        ops.append((name, make_mono()))

    # ═══════════════════════════════════════════════════════════
    # 5. TRANSPOSITIONS (inverse = undo encryption)
    # ═══════════════════════════════════════════════════════════

    # Reverse string
    ops.append(("reverse", lambda text: text[::-1]))

    # Columnar with keyword order (INVERSE = undo encipher)
    for kw in KEYWORDS:
        width = len(kw)
        if width < 2 or width > 50:
            continue
        order = keyword_to_order(kw, width)
        if order is None:
            continue
        perm = columnar_perm(width, order, 97)
        inv = invert_perm(perm)

        # Inverse (undo columnar encipher)
        name = f"col_inv/{kw}"
        def make_ci(p=inv):
            return lambda text: apply_perm(text, p) if len(text) == len(p) else text
        ops.append((name, make_ci()))

        # Forward (apply columnar as if it were the next layer)
        name = f"col_fwd/{kw}"
        def make_cf(p=perm):
            return lambda text: apply_perm(text, p) if len(text) == len(p) else text
        ops.append((name, make_cf()))

    # Myszkowski
    for kw in KEYWORDS:
        if len(kw) < 2 or len(kw) > 50:
            continue
        perm = myszkowski_perm(kw, 97)
        if len(perm) != 97:
            continue
        inv = invert_perm(perm)
        name = f"mysz_inv/{kw}"
        def make_mi(p=inv):
            return lambda text: apply_perm(text, p) if len(text) == len(p) else text
        ops.append((name, make_mi()))

    # Rail fence (depths 2-8)
    for depth in range(2, 9):
        perm = rail_fence_perm(97, depth)
        inv = invert_perm(perm)
        name = f"rail_inv/{depth}"
        def make_ri(p=inv):
            return lambda text: apply_perm(text, p) if len(text) == len(p) else text
        ops.append((name, make_ri()))

    # Columnar with numeric widths (natural order)
    for width in [7, 8, 10, 14, 24, 31]:
        order = tuple(range(width))
        perm = columnar_perm(width, order, 97)
        inv = invert_perm(perm)
        name = f"col_inv/w{width}_nat"
        def make_cn(p=inv):
            return lambda text: apply_perm(text, p) if len(text) == len(p) else text
        ops.append((name, make_cn()))

    # Route ciphers: spiral reading on various grids
    for rows, cols in [(7, 14), (14, 7), (8, 13), (13, 8), (10, 10)]:
        if rows * cols < 97:
            continue
        for cw in [True, False]:
            perm = spiral_perm(rows, cols, 97, clockwise=cw)
            if len(perm) != 97:
                continue
            inv = invert_perm(perm)
            d = "cw" if cw else "ccw"
            name = f"spiral_inv/{rows}x{cols}_{d}"
            def make_sp(p=inv):
                return lambda text: apply_perm(text, p) if len(text) == len(p) else text
            ops.append((name, make_sp()))

    # Serpentine on various grids
    for rows, cols in [(7, 14), (14, 7), (8, 13), (13, 8)]:
        if rows * cols < 97:
            continue
        for vert in [False, True]:
            perm = serpentine_perm(rows, cols, 97, vertical=vert)
            if len(perm) != 97:
                continue
            inv = invert_perm(perm)
            d = "vert" if vert else "horiz"
            name = f"serp_inv/{rows}x{cols}_{d}"
            def make_se(p=inv):
                return lambda text: apply_perm(text, p) if len(text) == len(p) else text
            ops.append((name, make_se()))

    # ═══════════════════════════════════════════════════════════
    # 6. NULL EXTRACTION: remove characters at candidate positions
    #    (outputs 73-char text — changes length!)
    # ═══════════════════════════════════════════════════════════
    # These are special: they change length from 97 to 73.
    # They can only be applied once and only to 97-char text.

    # Strategy: several structured null position sets
    null_sets = _build_null_sets()
    for ns_name, null_pos in null_sets:
        name = f"null_extract/{ns_name}"

        def make_null(npos=null_pos):
            def fn(text):
                if len(text) != 97:
                    return text  # can't extract from non-97
                keep = sorted(set(range(97)) - set(npos))
                return "".join(text[i] for i in keep)
            return fn

        ops.append((name, make_null()))

    return ops


def _build_null_sets() -> List[Tuple[str, List[int]]]:
    """Build candidate null position sets (24 positions each)."""
    sets = []

    # W positions + 19 evenly spaced
    w_pos = [i for i, c in enumerate(CT) if c == "W"]
    if len(w_pos) == 5:
        # Fill remaining 19 nulls at regular intervals avoiding W positions
        remaining = sorted(set(range(97)) - set(w_pos))
        step = len(remaining) // 19
        extra = [remaining[i * step] for i in range(19)]
        sets.append(("W_plus_even", sorted(w_pos + extra)))

    # Every 4th position (97/4 ≈ 24)
    sets.append(("every4_off0", list(range(0, 97, 4))[:24]))
    sets.append(("every4_off1", list(range(1, 97, 4))[:24]))
    sets.append(("every4_off2", list(range(2, 97, 4))[:24]))
    sets.append(("every4_off3", list(range(3, 97, 4))[:24]))

    # First 24, last 24, middle 24
    sets.append(("first24", list(range(24))))
    sets.append(("last24", list(range(73, 97))))
    sets.append(("mid24", list(range(37, 61))))

    # Positions outside crib regions (non-crib positions as nulls)
    # Cribs at 21-33 and 63-73 (24 positions) — remove everything ELSE
    crib_pos = list(range(21, 34)) + list(range(63, 74))
    non_crib = sorted(set(range(97)) - set(crib_pos))
    # Take first 24 non-crib positions as nulls
    sets.append(("non_crib_first24", non_crib[:24]))
    # Take last 24 non-crib positions
    sets.append(("non_crib_last24", non_crib[-24:]))
    # Take evenly spaced 24 from non-crib
    step_nc = max(1, len(non_crib) // 24)
    sets.append(("non_crib_even24", [non_crib[i * step_nc] for i in range(24) if i * step_nc < len(non_crib)][:24]))

    # Column-based: positions in specific columns of width-31 grid
    for col in range(31):
        positions = list(range(col, 97, 31))
        if len(positions) >= 3:
            # Only if we can fill close to 24
            pass  # too many variants, skip for now

    # Diagonal positions on 7x14 grid
    diag = [r * 14 + (r % 14) for r in range(7)] + [r * 14 + ((r + 7) % 14) for r in range(7)]
    diag = sorted(set(d for d in diag if d < 97))
    if len(diag) < 24:
        extra_d = sorted(set(range(97)) - set(diag))
        diag = diag + extra_d[:24 - len(diag)]
    sets.append(("diag_7x14", sorted(diag[:24])))

    return sets


def compute_score(text: str) -> Tuple[float, int, int]:
    """Fast composite scoring: (ic, crib_anchored, crib_free)."""
    # Handle variable-length text (73 or 97)
    ic_val = ic(text)
    if len(text) == 97:
        crib_a = score_cribs(text)
    else:
        crib_a = 0  # anchored cribs only work at 97 chars
    crib_f = score_free_fast(text)
    return ic_val, crib_a, crib_f


def attack(ciphertext: str, max_depth: int = 3, ic_prune: float = 0.033,
           crib_report: int = 8) -> list:
    """Layer-peeling search with expanded operations."""
    ops = build_operations()

    # Separate length-preserving ops from null-extraction ops
    ops_97 = [(n, f) for n, f in ops if not n.startswith("null_extract/")]
    ops_null = [(n, f) for n, f in ops if n.startswith("null_extract/")]

    print(f"Operations: {len(ops_97)} length-preserving + {len(ops_null)} null-extraction = {len(ops)} total")
    print(f"Max depth: {max_depth}")
    print(f"IC prune threshold: {ic_prune}")
    print()

    results = []
    best_ic = 0.0
    best_crib_a = 0
    best_crib_f = 0
    total_evals = 0

    baseline = compute_score(ciphertext)
    print(f"Baseline: IC={baseline[0]:.4f}, crib_a={baseline[1]}/24, crib_f={baseline[2]}/24")
    print()

    # Queue: (text, path, depth, length)
    queue = [(ciphertext, [], 0, 97)]

    for depth in range(1, max_depth + 1):
        next_queue = []
        d_best_ic = 0.0
        d_best_crib = 0
        d_evals = 0
        d_survivors = 0

        # Determine which ops to use
        applicable_ops = []
        for text, path, _, text_len in queue:
            if text_len == 97:
                these_ops = ops  # all ops (including null extraction)
            else:
                these_ops = ops_97  # only length-preserving
            applicable_ops.append((text, path, these_ops))

        total_this_depth = sum(len(o) for _, _, o in applicable_ops)
        print(f"=== Depth {depth} === ({len(queue)} inputs, ~{total_this_depth:,} evals)")

        for text, path, these_ops in applicable_ops:
            for op_name, op_fn in these_ops:
                try:
                    result = op_fn(text)
                except Exception:
                    continue

                if not result or not result.isalpha():
                    continue
                result = result.upper()
                rlen = len(result)
                if rlen not in (73, 97):
                    # null extraction can produce 73; others should preserve
                    if rlen != len(text):
                        continue

                total_evals += 1
                d_evals += 1

                ic_val, crib_a, crib_f = compute_score(result)
                new_path = path + [op_name]

                if ic_val > best_ic:
                    best_ic = ic_val
                if crib_a > best_crib_a:
                    best_crib_a = crib_a
                if crib_f > best_crib_f:
                    best_crib_f = crib_f
                if ic_val > d_best_ic:
                    d_best_ic = ic_val
                if crib_a > d_best_crib:
                    d_best_crib = crib_a

                # Report
                if crib_a >= crib_report or crib_f >= crib_report:
                    chain = " -> ".join(new_path)
                    print(f"  *** CRIB: a={crib_a}/24 f={crib_f}/24 IC={ic_val:.4f} "
                          f"len={rlen} [{chain}]")
                    print(f"      {result}")
                    results.append((crib_a + crib_f, result, chain, ic_val, rlen))

                if ic_val >= 0.060:
                    chain = " -> ".join(new_path)
                    print(f"  *** IC={ic_val:.4f} a={crib_a}/24 f={crib_f}/24 "
                          f"len={rlen} [{chain}]")

                # Pruning
                if depth < max_depth:
                    if ic_val >= ic_prune or crib_a >= 5 or crib_f >= 5:
                        next_queue.append((result, new_path, depth, rlen))
                        d_survivors += 1

        print(f"  Evals: {d_evals:,} | Survive: {d_survivors:,} | "
              f"IC: {d_best_ic:.4f} | Crib: {d_best_crib}/24")
        print(f"  Totals: {total_evals:,}, best IC={best_ic:.4f}, "
              f"a={best_crib_a}/24, f={best_crib_f}/24")
        print()

        queue = next_queue

    results.sort(key=lambda x: x[0], reverse=True)
    return results


def main():
    t0 = time.time()
    print("=" * 70)
    print("Layer-Peeling Search v2 (CoD Method — Expanded)")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Len: {len(CT)}")
    print()

    results = attack(CT, max_depth=3, ic_prune=0.033, crib_report=8)

    elapsed = time.time() - t0
    print("=" * 70)
    print(f"DONE in {elapsed:.1f}s | {len(results)} results above threshold")
    for score, text, chain, ic_val, rlen in results[:20]:
        print(f"  [{score}] IC={ic_val:.4f} len={rlen} [{chain}]")
        print(f"    {text}")
    if not results:
        print("  No results above threshold.")
    print("=" * 70)


if __name__ == "__main__":
    main()
