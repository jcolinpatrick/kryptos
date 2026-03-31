#!/usr/bin/env python3
"""
E-K2-COORDS-RUNNING-KEY: Test the spelled-out K2 coordinate phrase as a
running key for K4 decryption.

Hypothesis: The K2 "coordinates" aren't geographic — they encode K3/K4
parameters. The ENGLISH TEXT of the coordinates ("THIRTY EIGHT DEGREES...")
may serve as a running key for K4's substitution layer.

Tests:
  - Full coordinate phrase as running key
  - With/without XLAYERTWO suffix
  - Various starting offsets within the phrase
  - All 3 cipher variants (Vig, Beau, VarBeau) × 2 alphabets
  - With/without null mask (DEFECTOR mask)
  - With/without transposition (col5-13, rail3-7)
  - Also test substrings: just NORTH, just WEST, NORTHWEST, etc.
  - Also test the phrase reversed

Cipher: k2-coords-running-key
Family: substitution
Status: active
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

# --- The coordinate phrase(s) ---
# K2 plaintext contains the coordinates spelled out. Several possible renderings:
COORD_PHRASES = {
    "full": "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGRESEIGHTMINUTESFORTYFOURSECONDWEST",
    "full_fixed": "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDE GRESEIGHTMINUTESFORTYFOURSECONDWEST",
    "with_layer": "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGRESEIGHTMINUTESFORTYFOURSECONDWESTXLAYERTWO",
    "coords_only_nums": "THIRTYEIGHTFIFTYSEVENXSIXPOINTFIVESEVENTYSEVENTEIGHTFORTYFOUR",
    "directions": "NORTHWEST",
    "north": "NORTH",
    "west": "WEST",
    "northwestx": "NORTHWESTX",
    "eastnortheast": "EASTNORTHEAST",
    "degrees": "DEGREES",
    "point": "POINT",
    "whatisyourposition": "WHATISYOURPOSITION",
    "tisyourposition": "TISYOURPOSITION",
    # The phrase without function words — just the content
    "numbers_only": "THIRTYEIGHTFIFTYSEVENSIXPOINTFIVESEVENTYSEVENEIGHTFORTYFOUR",
    # Reversed
    "full_rev": "TSEWTSDNOCESRUOFRYTROFSETUNIEMTHGIESERGEDNEVE STNEVESHTRONSDNOCESEVIFTNIOPXISSETUNIMNEVES YTFIFSEERGEDDTHGIEYTRIH",
    # Just the "leftover" numbers (not consumed by K3)
    "residual": "SIXPOINTFIVESECONDSFORTYFOURSECONDSWEST",
    "residual_nums": "SIXPOINTFIVEFORTYFOUR",
}

# Clean up spaces/typos
COORD_PHRASES = {k: v.replace(" ", "").upper() for k, v in COORD_PHRASES.items()}

# --- Masks ---
DEFECTOR_NULLS = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]

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

CIPHERS = [
    ("vig", vig), ("beau", beau), ("vbeau", vbeau),
    ("avig", avig), ("abeau", abeau),
]

TRANSPOSITIONS = [
    ("none", lambda ct: ct),
    ("col5", lambda ct: col_undo(ct, 5)),
    ("col6", lambda ct: col_undo(ct, 6)),
    ("col7", lambda ct: col_undo(ct, 7)),
    ("col8", lambda ct: col_undo(ct, 8)),
    ("col9", lambda ct: col_undo(ct, 9)),
    ("col10", lambda ct: col_undo(ct, 10)),
    ("col11", lambda ct: col_undo(ct, 11)),
    ("col13", lambda ct: col_undo(ct, 13)),
    ("rail3", lambda ct: rail_undo(ct, 3)),
    ("rail4", lambda ct: rail_undo(ct, 4)),
    ("rail5", lambda ct: rail_undo(ct, 5)),
    ("rail7", lambda ct: rail_undo(ct, 7)),
]


def main():
    print("=" * 70)
    print("K2 COORDINATE PHRASE AS RUNNING KEY")
    print("=" * 70)

    for name, phrase in sorted(COORD_PHRASES.items()):
        print(f"  {name}: {phrase[:60]}{'...' if len(phrase)>60 else ''} ({len(phrase)} chars)")
    print()

    results = []
    tested = 0

    for mask_name, null_pos in [("raw97", []), ("defector73", DEFECTOR_NULLS)]:
        ect = extract_ct(null_pos)
        cribs = remap_cribs(null_pos) if null_pos else CRIB_DICT
        ct_len = len(ect)

        for phrase_name, phrase in COORD_PHRASES.items():
            if len(phrase) < 2:
                continue

            # Test at multiple starting offsets within the phrase
            max_offset = min(len(phrase) - ct_len, 30) if len(phrase) > ct_len else 0
            offsets = list(range(max(max_offset + 1, 1)))

            for offset in offsets:
                key = phrase[offset:offset + ct_len]
                if len(key) < ct_len:
                    key = key + phrase[:ct_len - len(key)]  # wrap around

                for tn, tf in TRANSPOSITIONS:
                    wct = tf(ect)
                    for cn, cf in CIPHERS:
                        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                            try:
                                pt = cf(wct, key, alpha)
                            except:
                                continue
                            tested += 1
                            s, ene, bc = score(pt, cribs)
                            if s >= 6:
                                desc = f"{mask_name} {phrase_name}[{offset}:]+{tn}+{cn}_{alpha_name}"
                                results.append((s, ene, bc, desc, pt[:50], key[:30]))

    results.sort(key=lambda x: (-x[0], -x[1]))

    print(f"\nTested: {tested} configs")
    print(f"Scores >= 6: {len(results)}")

    print(f"\n{'='*70}")
    print("TOP 20 RESULTS:")
    print("-" * 70)
    for s, ene, bc, desc, pt, key in results[:20]:
        print(f"  {s:2d}/24 (ene={ene:2d}/13 bc={bc:2d}/11) {desc}")
        print(f"      Key: {key}...")
        print(f"      PT:  {pt}...")
    print("=" * 70)

    if results:
        best = results[0]
        print(f"\nBEST: {best[0]}/24 — {best[3]}")
        if best[0] >= 10:
            print("*** ABOVE NOISE — INVESTIGATE ***")
        elif best[0] >= 7:
            print("Marginal — slightly above noise floor.")
        else:
            print("At noise floor.")
    else:
        print("\nNo results >= 6. Coordinate phrase as running key = noise.")


if __name__ == "__main__":
    main()
