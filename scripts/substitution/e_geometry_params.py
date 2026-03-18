#!/usr/bin/env python3
"""
E-GEOMETRY-PARAMS: Test physical installation geometry as cipher parameters.

Four installation points encode K4 constants in their spatial relationships.
Test the bearing angles, distances, and angular differences as:
  - Vigenere/Beaufort shifts and keys
  - Column widths
  - Autokey primers
  - Gronsfeld-style numeric keys
  - Rotation offsets
  - Combined with thematic keywords

Key bearings:
  LOOMIS→LODESTONE: 74.5° (ENE!)
  LOOMIS→KRYPTOS: 56.5°
  KRYPTOS→K2: 162.3°
  KRYPTOS→LODESTONE: 231.8°
  LODESTONE→KRYPTOS: 51.8°
  Triangle angle at LOOMIS: 18.0°

Cipher: geometry-params
Family: substitution
Status: active
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

DEFECTOR_NULLS = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]

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

def vig(ct, key, a):
    return "".join(a[(a.index(c) - a.index(key[i%len(key)])) % 26] for i, c in enumerate(ct))
def beau(ct, key, a):
    return "".join(a[(a.index(key[i%len(key)]) - a.index(c)) % 26] for i, c in enumerate(ct))
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

def col_undo(ct, w):
    n = len(ct); rows = -(-n // w); rem = n % w
    r = [''] * n; pos = 0
    for c in range(w):
        cl = rows if (rem == 0 or c < rem) else rows - 1
        for row in range(cl):
            r[row * w + c] = ct[pos]; pos += 1
    return "".join(r)

def rotate(ct, offset):
    n = len(ct); offset = offset % n
    return ct[offset:] + ct[:offset]

# === GEOMETRIC VALUES ===
# All bearing angles (rounded to integers for mod operations)
BEARINGS = {
    75: "LOOMIS→LODESTONE (74.5° ENE)",
    57: "LOOMIS→KRYPTOS (56.5°)",
    81: "LOOMIS→K2 (80.5°)",
    52: "LODESTONE→KRYPTOS (51.8°)",
    82: "LODESTONE→K2 (82.2°)",
    162: "KRYPTOS→K2 (162.3°)",
    232: "KRYPTOS→LODESTONE (231.8°)",
    237: "KRYPTOS→LOOMIS (236.5°)",
    342: "K2→KRYPTOS (342.3°)",
    255: "LODESTONE→LOOMIS (254.5°)",
}

# Triangle angles
ANGLES = {
    18: "angle at LOOMIS",
    157: "angle at LODESTONE",
    5: "angle at KRYPTOS (4.7°)",
}

# Distances in meters (rounded)
DISTANCES_M = {
    28: "LOOMIS→LODESTONE (27.7m)",
    131: "LOOMIS→KRYPTOS (130.8m)",
    127: "LOOMIS→K2 (127.1m)",
    105: "LODESTONE→KRYPTOS (104.9m)",
    100: "LODESTONE→K2 (99.7m)",
    54: "KRYPTOS→K2 (53.8m)",
}

# Distances in feet (rounded)
DISTANCES_FT = {
    91: "LOOMIS→LODESTONE (90.8ft)",
    429: "LOOMIS→KRYPTOS (429.3ft)",
    417: "LOOMIS→K2 (417.1ft)",
    344: "LODESTONE→KRYPTOS (344.0ft)",
    327: "LODESTONE→K2 (327.0ft)",
    177: "KRYPTOS→K2 (176.6ft)",
}

# Angular differences (between bearings from same point)
BEARING_DIFFS = {
    24: "LOOMIS: bearing to KRYPTOS minus bearing to LODESTONE (56.5-74.5=18→no, |74.5-56.5|=18)",
    # Recompute
    6: "LOOMIS: |KRYPTOS - K2| = |56.5-80.5| = 24... wait",
}
# Let me compute properly
import math
bearing_pairs = [
    ("LOOMIS: LODESTONE vs KRYPTOS", 74.5, 56.5),
    ("LOOMIS: LODESTONE vs K2", 74.5, 80.5),
    ("LOOMIS: KRYPTOS vs K2", 56.5, 80.5),
    ("LODESTONE: KRYPTOS vs K2", 51.8, 82.2),
    ("LODESTONE: KRYPTOS vs LOOMIS", 51.8, 254.5),
    ("KRYPTOS: K2 vs LODESTONE", 162.3, 231.8),
    ("KRYPTOS: K2 vs LOOMIS", 162.3, 236.5),
    ("KRYPTOS: LODESTONE vs LOOMIS", 231.8, 236.5),
]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
            "COLOPHON", "SHADOW", "COPPER", "HIDDEN", "SECRET",
            "LANGLEY", "POSITION", "LAYERTWO", "COMPASS", "POINT",
            "LOOMIS", "LODESTONE", "NORTHEAST", "BEARING"]

CIPHERS = [
    ("vig_AZ", vig, AZ), ("beau_AZ", beau, AZ),
    ("vig_KA", vig, KA), ("beau_KA", beau, KA),
    ("avig_AZ", avig, AZ), ("abeau_AZ", abeau, AZ),
    ("avig_KA", avig, KA), ("abeau_KA", abeau, KA),
]

results = []
tested = 0

for mask_name, null_pos in [("raw97", []), ("defector73", DEFECTOR_NULLS)]:
    ect = extract_ct(null_pos)
    cribs = remap_cribs(null_pos) if null_pos else CRIB_DICT
    ct_len = len(ect)

    print(f"\n{'='*70}")
    print(f"MASK: {mask_name} (CT={ct_len})")
    print(f"{'='*70}")

    all_nums = {}
    all_nums.update({v: f"bearing {k}° {desc}" for k, desc in BEARINGS.items() for v in [k % 26]})
    # Actually let's be more systematic

    # 1. Bearings as shifts
    print("\n[1] Bearing angles mod 26 as Caesar shifts...")
    for brg, desc in BEARINGS.items():
        shift = brg % 26
        for trans_name, trans_fn in [("none", lambda ct: ct), ("col7", lambda ct: col_undo(ct, 7))]:
            wct = trans_fn(ect)
            for kw in KEYWORDS:
                for cn, cf, alpha in CIPHERS:
                    try: pt = cf(wct, kw, alpha)
                    except: continue
                    tested += 1
                    s, ene, bc = score(pt, cribs)
                    if s >= 6:
                        results.append((s, ene, bc, f"{mask_name} {trans_name}+{kw}:{cn} [brg={brg}°,{desc}]"))

    # 2. Bearings as column widths
    print("[2] Bearing-derived column widths...")
    for brg, desc in BEARINGS.items():
        for w in [brg % 26, brg % ct_len]:
            if w < 2 or w >= ct_len: continue
            wct = col_undo(ect, w)
            for kw in KEYWORDS[:10]:
                for cn, cf, alpha in CIPHERS:
                    try: pt = cf(wct, kw, alpha)
                    except: continue
                    tested += 1
                    s, ene, bc = score(pt, cribs)
                    if s >= 6:
                        results.append((s, ene, bc, f"{mask_name} col{w}(brg{brg}%)+{kw}:{cn}"))

    # 3. Bearing angles as Gronsfeld digits
    print("[3] Bearing digit sequences as Gronsfeld keys...")
    gronsfeld_keys = [
        ([7,4,5], "LOOMIS→LODESTONE 74.5°"),
        ([5,6,5], "LOOMIS→KRYPTOS 56.5°"),
        ([1,6,2,3], "KRYPTOS→K2 162.3°"),
        ([5,1,8], "LODESTONE→KRYPTOS 51.8°"),
        ([2,3,1,8], "KRYPTOS→LODESTONE 231.8°"),
        ([7,4,5,6,5], "LOOMIS bearings combined"),
        ([1,8], "triangle angle at LOOMIS"),
        ([7,4,5,1,8], "ENE bearing 74.5 + angle 18"),
        ([5,6,5,1,8], "56.5° + 18° angle"),
        ([1,6,2,2,3,2], "KRYPTOS bearings: 162, 232"),
    ]
    for digits, desc in gronsfeld_keys:
        for trans_name, trans_fn in [("none", lambda ct: ct), ("col7", lambda ct: col_undo(ct, 7))]:
            wct = trans_fn(ect)
            pt_chars = []
            for i, c in enumerate(wct):
                shift = digits[i % len(digits)]
                pt_chars.append(AZ[(AZ.index(c) - shift) % 26])
            pt = "".join(pt_chars)
            tested += 1
            s, ene, bc = score(pt, cribs)
            if s >= 5:
                results.append((s, ene, bc, f"{mask_name} {trans_name}+gronsfeld({digits}) [{desc}]"))

    # 4. Bearing angles as rotation offsets
    print("[4] Rotation by bearing angles...")
    for brg, desc in BEARINGS.items():
        for offset in [brg % ct_len, brg % 26]:
            if offset == 0: continue
            rot_ct = rotate(ect, offset)
            rot_cribs = {(k - offset) % ct_len: v for k, v in cribs.items()}
            for kw in KEYWORDS[:8]:
                for cn, cf, alpha in CIPHERS:
                    try: pt = cf(rot_ct, kw, alpha)
                    except: continue
                    tested += 1
                    s, ene, bc = score(pt, rot_cribs)
                    if s >= 6:
                        results.append((s, ene, bc, f"{mask_name} rot{offset}(brg{brg})+{kw}:{cn}"))

    # 5. Angular differences between bearings as keys
    print("[5] Angular differences as cipher parameters...")
    for desc, b1, b2 in bearing_pairs:
        diff = abs(b2 - b1)
        if diff > 180: diff = 360 - diff
        diff_int = round(diff)
        shift = diff_int % 26
        # As Vigenere shift combined with keywords
        for kw in KEYWORDS[:8]:
            for cn, cf, alpha in CIPHERS:
                try: pt = cf(ect, kw, alpha)
                except: continue
                # Not very useful alone, but test col of that width
                if 2 <= diff_int < ct_len:
                    wct = col_undo(ect, diff_int)
                    try: pt2 = cf(wct, kw, alpha)
                    except: continue
                    tested += 1
                    s, ene, bc = score(pt2, cribs)
                    if s >= 6:
                        results.append((s, ene, bc, f"{mask_name} col{diff_int}(Δ{desc})+{kw}:{cn}"))

    # 6. Distance-derived primers for autokey
    print("[6] Distance-derived autokey primers...")
    dist_primers = [
        ("ENE", "LOOMIS→LODESTONE = ENE bearing"),
        ("NE", "LODESTONE→KRYPTOS = NE bearing"),
        ("SSE", "KRYPTOS→K2 = SSE"),
        ("WSW", "KRYPTOS→LOOMIS = WSW"),
        ("E", "LODESTONE→K2 = E"),
        ("ENESEW", "all bearings from LOOMIS/LODESTONE"),
    ]
    for primer, desc in dist_primers:
        for trans_name, trans_fn in [("none", lambda ct: ct), ("col7", lambda ct: col_undo(ct, 7))]:
            wct = trans_fn(ect)
            for cn, cf, alpha in CIPHERS:
                if "avig" not in cn and "abeau" not in cn: continue
                try: pt = cf(wct, primer, alpha)
                except: continue
                tested += 1
                s, ene, bc = score(pt, cribs)
                if s >= 5:
                    results.append((s, ene, bc, f"{mask_name} {trans_name}+{cn}(primer={primer}) [{desc}]"))

results.sort(key=lambda x: (-x[0], -x[1]))

print(f"\n{'='*70}")
print(f"TOTAL TESTED: {tested:,}")
print(f"SCORES >= 5: {len(results)}")
print(f"{'='*70}")

if results:
    print("\nTOP 20:")
    print("-" * 70)
    for s, ene, bc, desc in results[:20]:
        print(f"  {s:2d}/24 (ene={ene:2d}/13 bc={bc:2d}/11) {desc}")
    print("-" * 70)
    best = results[0]
    if best[0] >= 10:
        print(f"\n*** ABOVE NOISE ({best[0]}/24) — INVESTIGATE ***")
    elif best[0] >= 7:
        print(f"\nBest: {best[0]}/24 — marginal.")
    else:
        print(f"\nBest: {best[0]}/24 — noise floor.")
else:
    print("\nNo results above threshold.")
