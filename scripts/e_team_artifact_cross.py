#!/usr/bin/env python3
"""E-TEAM-ARTIFACT-CROSS: Cross-product of artifact keys x physical transpositions.

Tests every combination of artifact-derived keys with physically-derived
transpositions. Since V1 and V3 both produced noise individually,
this tests whether any two-layer combination (transposition + substitution)
produces signal.

Results saved to results/e_team_artifact_cross.json.
"""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
    spiral_perm, serpentine_perm, rail_fence_perm, validate_perm,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


# ── Reuse key generators from V1 ──────────────────────────────────────────

def digits_to_key(digits_str: str) -> list[int]:
    return [int(d) % MOD for d in digits_str]

def string_to_key(s: str) -> list[int]:
    return [ALPH_IDX[c] for c in s.upper() if c in ALPH_IDX]

def repeat_key(key: list[int], length: int = CT_LEN) -> list[int]:
    if not key:
        return [0] * length
    return [key[i % len(key)] for i in range(length)]


# ── Build key catalog ─────────────────────────────────────────────────────

def build_keys() -> list[tuple[str, list[int]]]:
    """Build all artifact-derived keys as (name, 97-element list) pairs."""
    keys = []

    # Date keys
    for ds in ["1986", "1989", "11091989", "03111990", "05261987",
                "08082025", "19870526", "19891109", "19900311", "20250808",
                "1990", "2025", "07041776", "17760704", "11031990"]:
        keys.append((f"date_{ds}", repeat_key(digits_to_key(ds))))

    # Coordinate keys
    for cs in ["389517", "771467", "5252", "13405", "2574", "3260"]:
        keys.append((f"coord_{cs}", repeat_key(digits_to_key(cs))))

    # String keywords
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "LAYERTWO", "IDBYROWS",
                "SHADOW", "IQLUSION", "DESPARATLY", "BERLIN", "CLOCK",
                "WELTZEITUHR", "EASTNORTHEAST", "BERLINCLOCK", "SANBORN",
                "SCHEIDT", "WEBSTER", "DRUSILLA", "NORTHEASTEAST", "EGYPT",
                "PHARAOH", "CARTER", "TUTANKHAMUN", "ALEXANDERPLATZ",
                "HIRSHHORN", "ANTIPODES", "SMITHSONIAN", "LANGLEY",
                "LUCIFER", "UNDERGROUND", "XLAYERTWO"]:
        keys.append((f"kw_{kw}", repeat_key(string_to_key(kw))))

    # YAR
    keys.append(("YAR", repeat_key([24, 0, 17])))
    keys.append(("RAY", repeat_key([17, 0, 24])))

    # Numeric
    keys.append(("fibonacci", repeat_key(_fibonacci())))
    keys.append(("primes", repeat_key(_primes())))

    # Keyword combos
    for name, combo in [
        ("KRYPTOS_PALIMPSEST", "KRYPTOSPALIMPSEST"),
        ("KRYPTOS_ABSCISSA", "KRYPTOSABSCISSA"),
        ("SANBORN_SCHEIDT", "SANBORNSCHEIDT"),
        ("BERLIN_CLOCK", "BERLINCLOCK"),
        ("KRYPTOS_BERLIN", "KRYPTOSBERLIN"),
    ]:
        keys.append((f"combo_{name}", repeat_key(string_to_key(combo))))

    return keys

def _fibonacci() -> list[int]:
    key = [1, 1]
    while len(key) < CT_LEN:
        key.append((key[-1] + key[-2]) % MOD)
    return key[:CT_LEN]

def _primes() -> list[int]:
    actual_primes = []
    result = []
    n = 2
    while len(result) < CT_LEN:
        if all(n % p != 0 for p in actual_primes if p * p <= n):
            actual_primes.append(n)
            result.append(n % MOD)
        n += 1
    return result


# ── Build transposition catalog ───────────────────────────────────────────

def diagonal_perm(rows, cols, length=97, direction="tl_br"):
    diags = {}
    for r in range(rows):
        for c in range(cols):
            pos = r * cols + c
            if pos >= length:
                continue
            key = (r + c) if direction == "tl_br" else (r + (cols - 1 - c))
            diags.setdefault(key, []).append(pos)
    return [p for k in sorted(diags) for p in diags[k]]

def column_first_perm(rows, cols, length=97):
    perm = []
    for c in range(cols):
        for r in range(rows):
            pos = r * cols + c
            if pos < length:
                perm.append(pos)
    return perm

def block_reverse_perm(length, block_size):
    perm = []
    for start in range(0, length, block_size):
        end = min(start + block_size, length)
        perm.extend(range(end - 1, start - 1, -1))
    return perm

def build_transpositions() -> list[tuple[str, list[int]]]:
    """Build all physically-derived permutations."""
    perms = []

    GRID_DIMS = [
        (7, 14), (8, 13), (9, 11), (10, 10), (11, 9), (13, 8), (14, 7),
        (5, 20), (6, 17), (16, 7), (17, 6), (20, 5),
    ]

    for rows, cols in GRID_DIMS:
        label = f"{rows}x{cols}"
        # Spiral
        for cw, d in [(True, "CW"), (False, "CCW")]:
            try:
                p = spiral_perm(rows, cols, CT_LEN, cw)
                if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                    perms.append((f"spiral_{d}_{label}", p))
            except Exception:
                pass

        # Serpentine
        for vert, d in [(False, "H"), (True, "V")]:
            try:
                p = serpentine_perm(rows, cols, CT_LEN, vert)
                if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                    perms.append((f"serp_{d}_{label}", p))
            except Exception:
                pass

        # Diagonal
        for dirn, d in [("tl_br", "NWSE"), ("tr_bl", "NESW")]:
            p = diagonal_perm(rows, cols, CT_LEN, dirn)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                perms.append((f"diag_{d}_{label}", p))

        # Column-first
        p = column_first_perm(rows, cols, CT_LEN)
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            perms.append((f"col_{label}", p))

    # Rail fence
    for depth in range(2, 11):
        p = rail_fence_perm(CT_LEN, depth)
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            perms.append((f"rail_d{depth}", p))

    # Simple patterns
    perms.append(("even_odd", list(range(0, CT_LEN, 2)) + list(range(1, CT_LEN, 2))))
    perms.append(("reverse", list(range(CT_LEN - 1, -1, -1))))
    for bs in [4, 7, 8, 9, 11, 13, 24]:
        p = block_reverse_perm(CT_LEN, bs)
        if validate_perm(p, CT_LEN):
            perms.append((f"blkrev_B{bs}", p))

    # Keyword columnar
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
                "BERLIN", "SHADOW", "WEBSTER", "LAYERTWO", "DRUSILLA"]:
        w = len(kw)
        if 5 <= w <= 13:
            order = keyword_to_order(kw, w)
            if order:
                p = columnar_perm(w, order, CT_LEN)
                perms.append((f"colkw_{kw}", p))

    return perms


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    start_time = time.time()

    keys = build_keys()
    perms = build_transpositions()

    print(f"Keys: {len(keys)}, Transpositions: {len(perms)}, Variants: {len(VARIANTS)}")
    total = len(keys) * len(perms) * len(VARIANTS)
    print(f"Total cross-product: {total:,} evaluations")
    print()
    sys.stdout.flush()

    results = []
    best_score = 0
    best_result = None
    configs_tested = 0

    for pi, (pname, perm) in enumerate(perms):
        if pi % 20 == 0:
            print(f"  Perm {pi+1}/{len(perms)} ({pname})... [{configs_tested:,} configs done]")
            sys.stdout.flush()

        inv = invert_perm(perm)
        intermediate = apply_perm(CT, inv)

        for kname, key97 in keys:
            for variant in VARIANTS:
                configs_tested += 1
                pt = decrypt_text(intermediate, key97, variant)
                sc = score_candidate(pt)
                score = sc.crib_score

                if score >= 6:
                    entry = {
                        "perm_name": pname,
                        "key_name": kname,
                        "variant": variant.value,
                        "crib_score": score,
                        "ic": round(sc.ic_value, 4),
                        "classification": sc.crib_classification,
                        "plaintext_preview": pt[:40],
                    }
                    results.append(entry)

                if score >= 10:
                    print(f"  ** STORE: {pname}+{kname}/{variant.value}: {sc.summary}")
                    print(f"     PT: {pt[:60]}")

                if score > best_score:
                    best_score = score
                    best_result = {
                        "perm_name": pname,
                        "key_name": kname,
                        "variant": variant.value,
                        "crib_score": score,
                        "plaintext_preview": pt[:40] if score >= 6 else pt[:20],
                    }

    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"FINAL SUMMARY — E-TEAM-ARTIFACT-CROSS")
    print("=" * 70)
    print(f"Keys: {len(keys)}, Perms: {len(perms)}")
    print(f"Configs tested: {configs_tested:,}")
    above_noise = [r for r in results if r['crib_score'] >= 6]
    print(f"Above noise (>=6): {len(above_noise)}")
    store_worthy = [r for r in results if r['crib_score'] >= 10]
    print(f"Store-worthy (>=10): {len(store_worthy)}")
    signal = [r for r in results if r['crib_score'] >= 18]
    print(f"Signal (>=18): {len(signal)}")
    print(f"Best score: {best_score}/24")
    if best_result:
        print(f"Best: {best_result['perm_name']} + {best_result['key_name']} / {best_result['variant']}")
        if 'plaintext_preview' in best_result:
            print(f"Best PT: {best_result['plaintext_preview']}")
    print(f"Elapsed: {elapsed:.1f}s")

    output = {
        "experiment": "e_team_artifact_cross",
        "n_keys": len(keys),
        "n_perms": len(perms),
        "configs_tested": configs_tested,
        "above_noise": len(above_noise),
        "store_worthy": len(store_worthy),
        "best_score": best_score,
        "best_result": best_result,
        "elapsed_seconds": round(elapsed, 1),
        "top_results": sorted(results, key=lambda x: -x["crib_score"])[:50],
    }

    out_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_artifact_cross.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")

    if best_score >= 18:
        print("\n*** SIGNAL DETECTED ***")
    elif best_score >= 10:
        print("\n** INTERESTING **")
    else:
        print("\nVerdict: NOISE — no artifact key + physical transposition combination produces signal")


if __name__ == "__main__":
    main()
