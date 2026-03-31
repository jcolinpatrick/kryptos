#!/usr/bin/env python3
"""
E-K2-OFFSET-PARAMS: Test K2 coordinate offset vector as cipher parameters.

From Google Earth measurements, the K2 point is ~53m SSE of the sculpture.
Key numbers from the offset:
  - 1.6 arcsecond latitude delta (8.1 - 6.5)
  - 16 = 1.6 × 10 (Q in A=0)
  - 180 feet (from tableau)
  - 53-55 meters
  - 162 degrees bearing
  - Bearing mod 97 = 65 (Bean EQ position)
  - Distance mod 26 = 24 (null count)

Test these as: shifts, column widths, autokey primers, affine params.
Also test: 8, 1, 6, 5 as individual digits.
Also test: the real latitude seconds (8.1 → 81, or 8) vs encoded (6.5 → 65, or 6).

Cipher: k2-offset-params
Family: substitution
Status: active
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


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

def caesar(ct, shift, a):
    return "".join(a[(a.index(c) - shift) % 26] for c in ct)

def rotate(ct, offset):
    n = len(ct); offset = offset % n
    return ct[offset:] + ct[:offset]

# --- Offset-derived numbers ---
OFFSET_NUMBERS = {
    16: "1.6 arcsec × 10 = Q in A=0",
    160: "1.6 × 100",
    65: "6.5 as integer / bearing mod 97 / Bean EQ pos",
    81: "8.1 real latitude seconds as integer",
    180: "distance in feet from tableau",
    53: "distance in meters",
    55: "distance from tableau in meters",
    162: "bearing in degrees",
    24: "distance mod 26 from tableau / null count",
    21: "distance mod 26 from pool / ENE start",
    8: "real latitude seconds (integer part)",
    6: "encoded latitude seconds (integer part)",
    1: "delta integer part",
    5: "from 6.5",
    77: "from K2 longitude (→ 7+7=14, K3 dim)",
}

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
            "COLOPHON", "SHADOW", "COPPER", "HIDDEN", "SECRET",
            "LANGLEY", "POSITION", "LAYERTWO", "NORTHWEST", "POINT"]

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

    # 1. Caesar shifts from offset numbers
    print("\n[1] Caesar shifts from offset numbers...")
    for num, desc in OFFSET_NUMBERS.items():
        shift = num % 26
        pt = caesar(ect, shift, AZ)
        s, ene, bc = score(pt, cribs)
        tested += 1
        if s >= 4:
            results.append((s, ene, bc, f"{mask_name} caesar({num}%26={shift}) [{desc}]"))
        # With col7
        pt2 = caesar(col_undo(ect, 7), shift, AZ)
        s2, ene2, bc2 = score(pt2, cribs)
        tested += 1
        if s2 >= 5:
            results.append((s2, ene2, bc2, f"{mask_name} col7+caesar({shift}) [{desc}]"))

    # 2. Column widths from offset numbers
    print("[2] Columnar widths from offset numbers...")
    for num, desc in OFFSET_NUMBERS.items():
        if num < 2 or num >= ct_len:
            continue
        trans_ct = col_undo(ect, num)
        for kw in KEYWORDS:
            for cn, cf, alpha in CIPHERS:
                try:
                    pt = cf(trans_ct, kw, alpha)
                except:
                    continue
                tested += 1
                s, ene, bc = score(pt, cribs)
                if s >= 6:
                    results.append((s, ene, bc, f"{mask_name} col{num}({desc})+{kw}:{cn}"))

    # 3. Rotation by offset numbers
    print("[3] CT rotation by offset numbers...")
    for num, desc in OFFSET_NUMBERS.items():
        offset = num % ct_len
        if offset == 0:
            continue
        rot_ct = rotate(ect, offset)
        rot_cribs = {(k - offset) % ct_len: v for k, v in cribs.items()}
        for kw in KEYWORDS[:8]:  # subset for speed
            for cn, cf, alpha in CIPHERS:
                try:
                    pt = cf(rot_ct, kw, alpha)
                except:
                    continue
                tested += 1
                s, ene, bc = score(pt, rot_cribs)
                if s >= 6:
                    results.append((s, ene, bc, f"{mask_name} rot{num}({desc})+{kw}:{cn}"))

    # 4. Autokey primers from offset-derived letters
    print("[4] Autokey primers from offset letters...")
    # 1.6 → 16 → Q(A=0), or P(A=1)
    # 65 → N(A=0, mod 26=13), or M
    # 162 → 162%26=6 → G
    # 180 → 180%26=24 → Y
    # Combine: Q, N, G, Y and permutations
    primers_offset = [
        ("Q", "16→Q (1.6 arcsec)"),
        ("QN", "16→Q + 65%26=13→N"),
        ("QNG", "Q+N+G(162%26=6)"),
        ("QNGY", "Q+N+G+Y(180%26=24)"),
        ("GY", "bearing+distance letters"),
        ("YQ", "distance+delta letters"),
        ("YNQG", "reversed"),
        ("SSE", "bearing direction"),
        ("SOUTH", "primary offset direction"),
    ]
    for primer, desc in primers_offset:
        for cn, cf, alpha in CIPHERS:
            if "avig" not in cn and "abeau" not in cn:
                continue
            try:
                pt = cf(ect, primer, alpha)
            except:
                continue
            tested += 1
            s, ene, bc = score(pt, cribs)
            if s >= 5:
                results.append((s, ene, bc, f"{mask_name} {cn}(primer={primer}) [{desc}]"))
            # With col7
            try:
                pt2 = cf(col_undo(ect, 7), primer, alpha)
            except:
                continue
            tested += 1
            s2, ene2, bc2 = score(pt2, cribs)
            if s2 >= 5:
                results.append((s2, ene2, bc2, f"{mask_name} col7+{cn}(primer={primer}) [{desc}]"))

    # 5. Digit sequence as Gronsfeld-style numeric key
    print("[5] Digit sequences as numeric shifts...")
    digit_keys = [
        ([1,6], "1.6 arcsec delta"),
        ([1,6,5], "1.6 + .5 (half arcsec precision)"),
        ([8,1,6,5], "8.1 real, 6.5 encoded"),
        ([6,5,8,1], "6.5 encoded, 8.1 real"),
        ([1,6,2], "162 degree bearing"),
        ([1,8,0], "180 feet"),
        ([5,3], "53 meters"),
        ([1,6,0,6,5], "delta=1.6, value=6.5"),
        ([3,8,5,7,6,5,7,7,8,4,4], "full coordinate digits"),
        ([6,5,4,4], "seconds only: 6.5, 44"),
    ]
    for digits, desc in digit_keys:
        pt_chars = []
        for i, c in enumerate(ect):
            shift = digits[i % len(digits)]
            pt_chars.append(AZ[(AZ.index(c) - shift) % 26])
        pt = "".join(pt_chars)
        tested += 1
        s, ene, bc = score(pt, cribs)
        if s >= 4:
            results.append((s, ene, bc, f"{mask_name} gronsfeld({digits}) [{desc}]"))
        # With col7
        wct = col_undo(ect, 7)
        pt_chars2 = []
        for i, c in enumerate(wct):
            shift = digits[i % len(digits)]
            pt_chars2.append(AZ[(AZ.index(c) - shift) % 26])
        pt2 = "".join(pt_chars2)
        tested += 1
        s2, ene2, bc2 = score(pt2, cribs)
        if s2 >= 4:
            results.append((s2, ene2, bc2, f"{mask_name} col7+gronsfeld({digits}) [{desc}]"))

results.sort(key=lambda x: (-x[0], -x[1]))

print(f"\n{'='*70}")
print(f"TOTAL TESTED: {tested}")
print(f"SCORES >= 4: {len(results)}")
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
