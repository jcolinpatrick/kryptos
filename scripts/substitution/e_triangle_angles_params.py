#!/usr/bin/env python3
"""
E-TRIANGLE-ANGLES-PARAMS: Test triangle interior angles from physical installation as cipher params.

Four installation points (KRYPTOS sculpture, LODESTONE, LOOMIS destroyed survey station,
K2 decoded coordinate target) form triangles. Interior angles:

  KRYPTOS-K2-LOOMIS:     74.1, 81.8, 24.0
  KRYPTOS-LODESTONE-K2:  69.5, 30.4, 80.2
  KRYPTOS-LODESTONE-LOOMIS: 4.7, 157.3, 18.0

Tests:
  1. Each angle (rounded) as Caesar shift mod 26
  2. Each angle as columnar width (2 <= w < CT_LEN)
  3. Angle triplets as 3-digit Gronsfeld keys (digit decomposition)
  4. All three angles per triangle combined as longer Gronsfeld key
  5. Angles as rotation offsets
  6. Angles mod 26 as letter primers for autokey Vig/Beau

All tested with and without DEFECTOR null mask, and with col7 transposition.

Cipher: triangle-angles-params
Family: substitution
Status: active
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

DEFECTOR_NULLS = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59,
                  74, 75, 78, 84, 85, 88, 94, 96]


# === Triangle data ===
TRIANGLES = {
    "KRYPTOS-K2-LOOMIS": [74.1, 81.8, 24.0],
    "KRYPTOS-LODESTONE-K2": [69.5, 30.4, 80.2],
    "KRYPTOS-LODESTONE-LOOMIS": [4.7, 157.3, 18.0],
}

# All unique angles (rounded)
ALL_ANGLES_RAW = []
for angles in TRIANGLES.values():
    ALL_ANGLES_RAW.extend(angles)

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
    "COLOPHON", "SHADOW", "COPPER", "HIDDEN", "LANGLEY",
    "POSITION", "COMPASS", "LOOMIS", "LODESTONE", "BEARING", "TRIANGLE",
]


# === Helper functions ===

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
    return "".join(a[(a.index(c) - a.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))


def beau(ct, key, a):
    return "".join(a[(a.index(key[i % len(key)]) - a.index(c)) % 26]
                   for i, c in enumerate(ct))


def vbeau(ct, key, a):
    return "".join(a[(a.index(c) + a.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))


def avig(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(c) - a.index(fk[i])) % 26
        pt.append(a[p])
        fk.append(a[p])
    return "".join(pt)


def abeau(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(fk[i]) - a.index(c)) % 26
        pt.append(a[p])
        fk.append(a[p])
    return "".join(pt)


def avbeau(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(c) + a.index(fk[i])) % 26
        pt.append(a[p])
        fk.append(a[p])
    return "".join(pt)


def col_undo(ct, w):
    n = len(ct)
    rows = -(-n // w)
    rem = n % w
    r = [''] * n
    pos = 0
    for c in range(w):
        cl = rows if (rem == 0 or c < rem) else rows - 1
        for row in range(cl):
            r[row * w + c] = ct[pos]
            pos += 1
    return "".join(r)


def caesar(ct, shift, a):
    return "".join(a[(a.index(c) - shift) % 26] for c in ct)


def rotate(ct, offset):
    n = len(ct)
    offset = offset % n
    return ct[offset:] + ct[:offset]


def gronsfeld_decrypt(ct, digits, a):
    return "".join(a[(a.index(c) - digits[i % len(digits)]) % 26]
                   for i, c in enumerate(ct))


def digits_of(angle):
    """Extract digits from an angle value, e.g. 74.1 -> [7,4,1], 157.3 -> [1,5,7,3]."""
    s = str(angle).replace('.', '')
    return [int(d) for d in s]


CIPHERS = [
    ("vig_AZ", vig, AZ),
    ("beau_AZ", beau, AZ),
    ("vbeau_AZ", vbeau, AZ),
    ("vig_KA", vig, KA),
    ("beau_KA", beau, KA),
    ("vbeau_KA", vbeau, KA),
    ("avig_AZ", avig, AZ),
    ("abeau_AZ", abeau, AZ),
    ("avbeau_AZ", avbeau, AZ),
    ("avig_KA", avig, KA),
    ("abeau_KA", abeau, KA),
    ("avbeau_KA", avbeau, KA),
]

AUTOKEY_NAMES = {"avig_AZ", "abeau_AZ", "avbeau_AZ", "avig_KA", "abeau_KA", "avbeau_KA"}

# === Main ===

results = []
tested = 0
REPORT_THRESHOLD = 7  # report scores >= 7/24

print("=" * 70)
print("E-TRIANGLE-ANGLES-PARAMS: Triangle interior angles as cipher parameters")
print("=" * 70)

for mask_name, null_pos in [("raw97", []), ("defector73", DEFECTOR_NULLS)]:
    ect = extract_ct(null_pos)
    cribs = remap_cribs(null_pos) if null_pos else CRIB_DICT
    ct_len = len(ect)

    print(f"\n{'=' * 70}")
    print(f"MASK: {mask_name} (CT={ct_len})")
    print(f"{'=' * 70}")

    # ---------------------------------------------------------------
    # 1. Each angle (rounded) as Caesar shift mod 26
    # ---------------------------------------------------------------
    print("\n[1] Each angle (rounded) as Caesar shift mod 26...")
    angle_shifts_seen = set()
    for tri_name, angles in TRIANGLES.items():
        for angle in angles:
            shift = round(angle) % 26
            if shift in angle_shifts_seen:
                continue
            angle_shifts_seen.add(shift)
            for trans_label, trans_fn in [("none", None), ("col7", 7)]:
                wct = col_undo(ect, 7) if trans_fn else ect
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    pt = caesar(wct, shift, alpha)
                    tested += 1
                    s, ene, bc = score(pt, cribs)
                    if s >= REPORT_THRESHOLD:
                        results.append((s, ene, bc,
                            f"{mask_name} {trans_label}+caesar({shift}) "
                            f"[{alpha_name}, angle={angle}° from {tri_name}]"))

    # ---------------------------------------------------------------
    # 2. Each angle as columnar width (2 <= w < ct_len)
    # ---------------------------------------------------------------
    print("[2] Each angle as columnar width...")
    widths_seen = set()
    for tri_name, angles in TRIANGLES.items():
        for angle in angles:
            w = round(angle)
            if w < 2 or w >= ct_len or w in widths_seen:
                continue
            widths_seen.add(w)
            wct = col_undo(ect, w)
            for kw in KEYWORDS:
                for cn, cf, alpha in CIPHERS:
                    try:
                        pt = cf(wct, kw, alpha)
                    except Exception:
                        continue
                    tested += 1
                    s, ene, bc = score(pt, cribs)
                    if s >= REPORT_THRESHOLD:
                        results.append((s, ene, bc,
                            f"{mask_name} col{w}(angle={angle}° {tri_name})+{kw}:{cn}"))

    # ---------------------------------------------------------------
    # 3. Angle triplets as 3-digit Gronsfeld keys
    # ---------------------------------------------------------------
    print("[3] Angle digit decompositions as Gronsfeld keys...")
    gronsfeld_keys = []
    for tri_name, angles in TRIANGLES.items():
        for angle in angles:
            digs = digits_of(angle)
            gronsfeld_keys.append((digs, f"{angle}° from {tri_name}"))

    for digits, desc in gronsfeld_keys:
        for trans_label, trans_fn in [("none", None), ("col7", 7)]:
            wct = col_undo(ect, 7) if trans_fn else ect
            pt = gronsfeld_decrypt(wct, digits, AZ)
            tested += 1
            s, ene, bc = score(pt, cribs)
            if s >= REPORT_THRESHOLD:
                results.append((s, ene, bc,
                    f"{mask_name} {trans_label}+gronsfeld({digits}) [{desc}]"))
            # Also with KA
            pt_ka = gronsfeld_decrypt(wct, digits, KA)
            tested += 1
            s, ene, bc = score(pt_ka, cribs)
            if s >= REPORT_THRESHOLD:
                results.append((s, ene, bc,
                    f"{mask_name} {trans_label}+gronsfeld_KA({digits}) [{desc}]"))

    # ---------------------------------------------------------------
    # 4. All three angles from each triangle combined as longer Gronsfeld key
    # ---------------------------------------------------------------
    print("[4] Full triangle angle triplets as combined Gronsfeld keys...")
    for tri_name, angles in TRIANGLES.items():
        # Combine all angle digits
        combined = []
        for angle in angles:
            combined.extend(digits_of(angle))
        # Also try rounded integers as individual digit groups
        rounded_combined = [round(a) for a in angles]

        combined_keys = [
            (combined, f"all digits from {tri_name}"),
            (rounded_combined, f"rounded angles from {tri_name}"),
        ]

        # Cross-triangle: all 9 angles
        all_digits = []
        all_rounded = []
        for a in ALL_ANGLES_RAW:
            all_digits.extend(digits_of(a))
            all_rounded.append(round(a))

        for trans_label, trans_fn in [("none", None), ("col7", 7)]:
            wct = col_undo(ect, 7) if trans_fn else ect
            for digits, desc in combined_keys:
                pt = gronsfeld_decrypt(wct, digits, AZ)
                tested += 1
                s, ene, bc = score(pt, cribs)
                if s >= REPORT_THRESHOLD:
                    results.append((s, ene, bc,
                        f"{mask_name} {trans_label}+gronsfeld({digits}) [{desc}]"))
                pt_ka = gronsfeld_decrypt(wct, digits, KA)
                tested += 1
                s, ene, bc = score(pt_ka, cribs)
                if s >= REPORT_THRESHOLD:
                    results.append((s, ene, bc,
                        f"{mask_name} {trans_label}+gronsfeld_KA({digits}) [{desc}]"))

        # All 9 angles combined (only once per mask/trans combo, outside tri loop)
    # Do the all-9 angles keys here (once per mask)
    all_digits_combined = []
    all_rounded_combined = []
    for a in ALL_ANGLES_RAW:
        all_digits_combined.extend(digits_of(a))
        all_rounded_combined.append(round(a))

    all_combined_keys = [
        (all_digits_combined, "all 9 angle digits combined"),
        (all_rounded_combined, "all 9 rounded angles combined"),
    ]
    for trans_label, trans_fn in [("none", None), ("col7", 7)]:
        wct = col_undo(ect, 7) if trans_fn else ect
        for digits, desc in all_combined_keys:
            for a_name, alpha in [("AZ", AZ), ("KA", KA)]:
                pt = gronsfeld_decrypt(wct, digits, alpha)
                tested += 1
                s, ene, bc = score(pt, cribs)
                if s >= REPORT_THRESHOLD:
                    results.append((s, ene, bc,
                        f"{mask_name} {trans_label}+gronsfeld_{a_name}({digits[:8]}...) [{desc}]"))

    # ---------------------------------------------------------------
    # 5. Angles as rotation offsets
    # ---------------------------------------------------------------
    print("[5] Angles as rotation offsets...")
    offsets_seen = set()
    for tri_name, angles in TRIANGLES.items():
        for angle in angles:
            for off_val in [round(angle), round(angle) % 26]:
                offset = off_val % ct_len
                if offset == 0 or offset in offsets_seen:
                    continue
                offsets_seen.add(offset)
                rot_ct = rotate(ect, offset)
                rot_cribs = {(k - offset) % ct_len: v for k, v in cribs.items()}
                for kw in KEYWORDS:
                    for cn, cf, alpha in CIPHERS:
                        try:
                            pt = cf(rot_ct, kw, alpha)
                        except Exception:
                            continue
                        tested += 1
                        s, ene, bc = score(pt, rot_cribs)
                        if s >= REPORT_THRESHOLD:
                            results.append((s, ene, bc,
                                f"{mask_name} rot{offset}(angle={angle}° {tri_name})+{kw}:{cn}"))

    # ---------------------------------------------------------------
    # 6. Angles mod 26 as letter primers for autokey Vig/Beau
    # ---------------------------------------------------------------
    print("[6] Angle-derived letter primers for autokey...")
    # Convert each angle mod 26 to a letter
    primer_sets = []
    for tri_name, angles in TRIANGLES.items():
        letters = [AZ[round(a) % 26] for a in angles]
        primer = "".join(letters)
        primer_sets.append((primer, f"letters from {tri_name}"))
        # Also individual letters
        for i, (a, l) in enumerate(zip(angles, letters)):
            primer_sets.append((l, f"letter from {a}° ({tri_name})"))

    # All 9 angle letters combined
    all_letters = "".join(AZ[round(a) % 26] for a in ALL_ANGLES_RAW)
    primer_sets.append((all_letters, "all 9 angle letters"))

    # Also try angle pairs
    flat_angles = [round(a) for a in ALL_ANGLES_RAW]
    for i in range(len(flat_angles)):
        for j in range(i + 1, len(flat_angles)):
            p = AZ[flat_angles[i] % 26] + AZ[flat_angles[j] % 26]
            primer_sets.append((p, f"pair({ALL_ANGLES_RAW[i]}°,{ALL_ANGLES_RAW[j]}°)"))

    # Deduplicate primers
    seen_primers = set()
    unique_primers = []
    for primer, desc in primer_sets:
        if primer not in seen_primers:
            seen_primers.add(primer)
            unique_primers.append((primer, desc))

    for primer, desc in unique_primers:
        for trans_label, trans_fn in [("none", None), ("col7", 7)]:
            wct = col_undo(ect, 7) if trans_fn else ect
            for cn, cf, alpha in CIPHERS:
                if cn not in AUTOKEY_NAMES:
                    continue
                try:
                    pt = cf(wct, primer, alpha)
                except Exception:
                    continue
                tested += 1
                s, ene, bc = score(pt, cribs)
                if s >= REPORT_THRESHOLD:
                    results.append((s, ene, bc,
                        f"{mask_name} {trans_label}+{cn}(primer={primer}) [{desc}]"))

    # ---------------------------------------------------------------
    # BONUS: Angles combined with keywords as Vigenere/Beaufort keys
    # ---------------------------------------------------------------
    print("[BONUS] Angle-shifted keywords...")
    for tri_name, angles in TRIANGLES.items():
        for angle in angles:
            shift = round(angle) % 26
            for kw in KEYWORDS:
                # Shift keyword by angle amount
                shifted_kw = "".join(AZ[(AZ.index(c) + shift) % 26] for c in kw)
                for trans_label, trans_fn in [("none", None), ("col7", 7)]:
                    wct = col_undo(ect, 7) if trans_fn else ect
                    for cn, cf, alpha in CIPHERS[:6]:  # non-autokey only
                        try:
                            pt = cf(wct, shifted_kw, alpha)
                        except Exception:
                            continue
                        tested += 1
                        s, ene, bc = score(pt, cribs)
                        if s >= REPORT_THRESHOLD:
                            results.append((s, ene, bc,
                                f"{mask_name} {trans_label}+{shifted_kw}(={kw}+{shift}):{cn} "
                                f"[angle={angle}° {tri_name}]"))

    # ---------------------------------------------------------------
    # BONUS 2: Column width from one angle + keyword sub
    # with rotation from another angle (combining two angles)
    # ---------------------------------------------------------------
    print("[BONUS 2] Two-angle combinations (col width + rotation)...")
    for tri_name, angles in TRIANGLES.items():
        for i, a1 in enumerate(angles):
            w = round(a1)
            if w < 2 or w >= ct_len:
                continue
            for j, a2 in enumerate(angles):
                if i == j:
                    continue
                offset = round(a2) % ct_len
                if offset == 0:
                    continue
                # col_undo then rotate
                wct = col_undo(ect, w)
                wct = rotate(wct, offset)
                rot_cribs = {(k - offset) % ct_len: v for k, v in cribs.items()}
                for kw in KEYWORDS[:8]:
                    for cn, cf, alpha in CIPHERS[:6]:
                        try:
                            pt = cf(wct, kw, alpha)
                        except Exception:
                            continue
                        tested += 1
                        s, ene, bc = score(pt, rot_cribs)
                        if s >= REPORT_THRESHOLD:
                            results.append((s, ene, bc,
                                f"{mask_name} col{w}+rot{offset}+{kw}:{cn} "
                                f"[{tri_name}: w={a1}°, rot={a2}°]"))

# === Report ===
results.sort(key=lambda x: (-x[0], -x[1]))

print(f"\n{'=' * 70}")
print(f"TOTAL TESTED: {tested:,}")
print(f"SCORES >= {REPORT_THRESHOLD}: {len(results)}")
print(f"{'=' * 70}")

if results:
    print(f"\nTOP 30 (threshold >= {REPORT_THRESHOLD}/24):")
    print("-" * 80)
    for s, ene, bc, desc in results[:30]:
        print(f"  {s:2d}/24 (ene={ene:2d}/13 bc={bc:2d}/11) {desc}")
    print("-" * 80)
    best = results[0]
    if best[0] >= 10:
        print(f"\n*** ABOVE NOISE ({best[0]}/24) --- INVESTIGATE ***")
    elif best[0] >= 7:
        print(f"\nBest: {best[0]}/24 --- marginal, worth noting.")
    else:
        print(f"\nBest: {best[0]}/24 --- noise floor.")
else:
    print("\nNo results above threshold.")

# Summary of angle values tested
print(f"\n{'=' * 70}")
print("ANGLE SUMMARY:")
for tri_name, angles in TRIANGLES.items():
    rounded = [round(a) for a in angles]
    mod26 = [r % 26 for r in rounded]
    letters = [AZ[m] for m in mod26]
    print(f"  {tri_name}: {angles} -> rounded {rounded} -> mod26 {mod26} -> letters {''.join(letters)}")
print(f"{'=' * 70}")
