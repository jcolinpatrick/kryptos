#!/usr/bin/env python3
"""
E-K2-RESIDUAL-PARAMS: Test K2 coordinate numbers 44 and 57 as K4 cipher parameters.

Hypothesis: K2 coordinates encode K3 dimensions (38→24, 77→14, 8→8).
The "residual" numbers 44, 57, and 6.5 may encode K4 parameters.

Tests 44 and 57 as:
  - Columnar widths (on both raw 97 and extracted 73)
  - Caesar/rotation shifts (mod 26)
  - Affine parameters (a=57%26=5, b=44%26=18; and permutations)
  - Autokey primer offsets
  - Rail fence depths
  - Combined: col44 + sub, col57%26 + sub, etc.
  - Also test 6, 5, 65, 45, 47, 74, 85 (digit rearrangements)

Against both the DEFECTOR best-lead mask and no mask.

Cipher: k2-residual-params
Family: grille
Status: active
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

# --- Masks ---
DEFECTOR_NULLS = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
NO_NULLS = []

# --- Helpers ---
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

def extract_ct(null_pos):
    ns = set(null_pos)
    return "".join(c for i, c in enumerate(CT) if i not in ns)

def remap_cribs(null_pos):
    ns = set(null_pos)
    cribs = {}
    new_idx = 0
    for i in range(len(CT)):
        if i not in ns:
            if i in CRIB_DICT:
                cribs[new_idx] = CRIB_DICT[i]
            new_idx += 1
    return cribs

def score(pt, cribs):
    s = sorted(cribs.keys())
    ene_p, bc_p = s[:13], s[13:]
    ene = sum(1 for p in ene_p if p < len(pt) and pt[p] == cribs[p])
    bc = sum(1 for p in bc_p if p < len(pt) and pt[p] == cribs[p])
    return ene + bc, ene, bc

# --- Ciphers ---
def vig(ct, key, a):
    return "".join(a[(a.index(c) - a.index(key[i%len(key)])) % 26] for i, c in enumerate(ct))

def beau(ct, key, a):
    return "".join(a[(a.index(key[i%len(key)]) - a.index(c)) % 26] for i, c in enumerate(ct))

def vbeau(ct, key, a):
    return "".join(a[(a.index(c) + a.index(key[i%len(key)])) % 26] for i, c in enumerate(ct))

def avig(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(c) - a.index(fk[i])) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)

def abeau(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(fk[i]) - a.index(c)) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)

def caesar(ct, shift, a):
    return "".join(a[(a.index(c) - shift) % 26] for c in ct)

def affine_dec(ct, a_val, b_val):
    a_inv = -1
    for i in range(1, 26):
        if (a_val * i) % 26 == 1:
            a_inv = i; break
    if a_inv < 0:
        return None
    return "".join(chr((a_inv * (ord(c) - 65 - b_val)) % 26 + 65) for c in ct)

# --- Transpositions ---
def col_undo(ct, w):
    n = len(ct); rows = -(-n // w); rem = n % w
    r = [''] * n; pos = 0
    for c in range(w):
        cl = rows if (rem == 0 or c < rem) else rows - 1
        for row in range(cl):
            r[row * w + c] = ct[pos]; pos += 1
    return "".join(r)

def rail_undo(ct, depth):
    n = len(ct)
    if depth <= 1 or depth >= n: return ct
    rl = [0] * depth; rail = 0; d = 1
    for _ in range(n):
        rl[rail] += 1
        if rail == 0: d = 1
        elif rail == depth - 1: d = -1
        rail += d
    rails = []; pos = 0
    for r in range(depth):
        rails.append(ct[pos:pos+rl[r]]); pos += rl[r]
    result = []; indices = [0]*depth; rail = 0; d = 1
    for _ in range(n):
        result.append(rails[rail][indices[rail]]); indices[rail] += 1
        if rail == 0: d = 1
        elif rail == depth - 1: d = -1
        rail += d
    return "".join(result)

# --- Main ---
KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
            "COLOPHON", "SHADOW", "INVISIBLE", "POSITION", "LAYERTWO",
            "BERLINCLOCK", "EASTNORTHEAST", "NORTHEAST", "COMPASS",
            "FORTYFOUR", "FIFTYSEVEN", "POINTFIVE", "SIXPOINTFIVE"]

# K2 residual numbers and their derivations
PARAM_NUMBERS = {
    44: "K2 longitude seconds",
    57: "K2 latitude minutes",
    5:  "57 mod 26, or 6.5→5",
    18: "44 mod 26",
    6:  "from 6.5",
    13: "6.5 × 2 = 13 (ENE length)",
    11: "6+5 or 4+4+3",
    65: "6.5 as integer",
    45: "44+1 or 4×5+25",
    47: "reverse of 74",
    74: "K4 end position",
    19: "T=19 (T IS YOUR POSITION)",
    20: "T=20 (1-indexed)",
}

def main():
    print("=" * 70)
    print("K2 RESIDUAL PARAMETERS — 44 AND 57 AS K4 CIPHER PARAMS")
    print("=" * 70)

    results = []

    for mask_name, null_pos in [("DEFECTOR_MASK", DEFECTOR_NULLS), ("NO_MASK", NO_NULLS)]:
        ect = extract_ct(null_pos)
        cribs = remap_cribs(null_pos) if null_pos else CRIB_DICT
        ct_len = len(ect)

        print(f"\n{'='*70}")
        print(f"MASK: {mask_name} — CT length: {ct_len}")
        print(f"{'='*70}")

        # --- Test 1: Columnar transposition with residual widths ---
        print("\n[1] Columnar transposition widths from K2 residuals...")
        for width_val, desc in PARAM_NUMBERS.items():
            if width_val < 2 or width_val >= ct_len:
                continue
            transposed = col_undo(ect, width_val)
            for kw in KEYWORDS:
                for cn, cf, alpha in [("vig", vig, AZ), ("beau", beau, AZ),
                                       ("vig", vig, KA), ("beau", beau, KA),
                                       ("avig", avig, AZ), ("abeau", abeau, AZ),
                                       ("avig", avig, KA), ("abeau", abeau, KA)]:
                    try:
                        pt = cf(transposed, kw, alpha)
                    except:
                        continue
                    s, ene, bc = score(pt, cribs)
                    if s >= 6:
                        an = "KA" if alpha == KA else "AZ"
                        results.append((s, ene, bc, f"{mask_name} col{width_val}({desc})+{kw}:{an}_{cn}"))

        # --- Test 2: Rail fence with residual depths ---
        print("[2] Rail fence depths from K2 residuals...")
        for depth_val, desc in PARAM_NUMBERS.items():
            if depth_val < 2 or depth_val >= ct_len:
                continue
            transposed = rail_undo(ect, depth_val)
            for kw in KEYWORDS:
                for cn, cf, alpha in [("vig", vig, AZ), ("beau", beau, AZ),
                                       ("avig", avig, AZ), ("abeau", abeau, AZ)]:
                    try:
                        pt = cf(transposed, kw, alpha)
                    except:
                        continue
                    s, ene, bc = score(pt, cribs)
                    if s >= 6:
                        an = "KA" if alpha == KA else "AZ"
                        results.append((s, ene, bc, f"{mask_name} rail{depth_val}({desc})+{kw}:{an}_{cn}"))

        # --- Test 3: Caesar shifts from residual numbers ---
        print("[3] Caesar shifts...")
        for shift_val, desc in PARAM_NUMBERS.items():
            shift = shift_val % 26
            pt = caesar(ect, shift, AZ)
            s, ene, bc = score(pt, cribs)
            if s >= 4:
                results.append((s, ene, bc, f"{mask_name} caesar({shift_val}%26={shift}) [{desc}]"))
            # With transposition first
            for w in [5, 6, 7, 8, 9, 11, 13, 19, 44]:
                if w >= ct_len: continue
                tp = col_undo(ect, w)
                pt2 = caesar(tp, shift, AZ)
                s2, ene2, bc2 = score(pt2, cribs)
                if s2 >= 6:
                    results.append((s2, ene2, bc2, f"{mask_name} col{w}+caesar({shift}) [{desc}]"))

        # --- Test 4: Affine with residual numbers ---
        print("[4] Affine cipher with K2 residual params...")
        affine_pairs = [
            (5, 18, "a=57%26, b=44%26"),
            (5, 44, "a=5, b=44"),
            (5, 57, "a=5, b=57%26=5 → skip"),
            (7, 44, "a=7, b=44%26=18"),
            (7, 18, "a=7, b=18"),
            (9, 18, "a=9, b=18"),
            (11, 18, "a=11, b=18"),
            (11, 44, "a=11, b=44%26=18"),
            (19, 5, "a=T=19, b=5"),
            (5, 19, "a=5, b=T=19"),
            (3, 8, "a=3, b=8 (from 38)"),
            (5, 8, "a=5, b=8"),
        ]
        for a_val, b_val, desc in affine_pairs:
            b_mod = b_val % 26
            pt = affine_dec(ect, a_val, b_mod)
            if pt is None: continue
            s, ene, bc = score(pt, cribs)
            if s >= 4:
                results.append((s, ene, bc, f"{mask_name} affine(a={a_val},b={b_mod}) [{desc}]"))
            # With col7 transposition
            tp = col_undo(ect, 7)
            pt2 = affine_dec(tp, a_val, b_mod)
            if pt2:
                s2, ene2, bc2 = score(pt2, cribs)
                if s2 >= 6:
                    results.append((s2, ene2, bc2, f"{mask_name} col7+affine(a={a_val},b={b_mod}) [{desc}]"))

        # --- Test 5: Autokey with numeric primers from residuals ---
        print("[5] Autokey with numeric primers derived from K2 residuals...")
        # Convert numbers to letter primers
        primers = {
            "E": "57→5→F? no, 5=F in A0, E in A1",
            "S": "18→S (44%26=18, S=18 in A0)",
            "F": "5=F in A0",
            "ES": "5,18 → E,S",
            "SE": "18,5 → S,E",
            "FEST": "5,4,18,19 → digits of 57,44 mapped",
        }
        for primer, desc in primers.items():
            for cn, cf, alpha in [("avig", avig, AZ), ("abeau", abeau, AZ),
                                   ("avig", avig, KA), ("abeau", abeau, KA)]:
                try:
                    pt = cf(ect, primer, alpha)
                except:
                    continue
                s, ene, bc = score(pt, cribs)
                if s >= 5:
                    an = "KA" if alpha == KA else "AZ"
                    results.append((s, ene, bc, f"{mask_name} {cn}_{an}(primer={primer}) [{desc}]"))
                # With col7
                tp = col_undo(ect, 7)
                try:
                    pt2 = cf(tp, primer, alpha)
                except:
                    continue
                s2, ene2, bc2 = score(pt2, cribs)
                if s2 >= 6:
                    results.append((s2, ene2, bc2, f"{mask_name} col7+{cn}_{an}(primer={primer}) [{desc}]"))

    # --- Report ---
    results.sort(key=lambda x: (-x[0], -x[1]))

    print(f"\n{'='*70}")
    print(f"RESULTS: {len(results)} configs scored >= 6 (or >= 4 for simple ciphers)")
    print(f"{'='*70}")

    if results:
        print("\nTOP 25:")
        print("-" * 70)
        for s, ene, bc, desc in results[:25]:
            print(f"  {s:2d}/24 (ene={ene:2d}/13 bc={bc:2d}/11) {desc}")
        print("-" * 70)
        best = results[0]
        print(f"\nBEST: {best[0]}/24 — {best[3]}")
        if best[0] >= 10:
            print("*** ABOVE NOISE THRESHOLD ***")
    else:
        print("\nNo results above threshold.")


if __name__ == "__main__":
    main()
