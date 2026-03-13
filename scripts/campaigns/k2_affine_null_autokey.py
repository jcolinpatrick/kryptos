#!/usr/bin/env python3
"""
Cipher: Affine null mask (crib-safe) + autokey on 73-char Model B extract
Family: campaigns
Status: active
Keyspace: ~9312 affine maps × crib-safe filter × autokey primers

Novel combination NOT yet tested:
  1. Find ALL affine maps y=ax+b (mod 97) where null positions don't conflict with cribs
  2. For each valid null mask, extract 73-char CT at "real" positions
  3. Apply autokey Beaufort/Vigenère with K2-derived primers
  4. Score by crib matches at SHIFTED positions in the 73-char text

Key insight: y=27x+21 (mod 97) was confirmed as encoding ENE start (21 = intercept),
but its null mask conflicts with 5 crib positions. Valid affine maps may exist that
encode K4 structure AND have crib-safe null masks.

Also tests: valid maps where slope/intercept ∈ K2 numbers {3,5,6,7,8,11,13,24,38,44,57,77}
"""
import sys, time
from math import gcd
sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, ALPH, ALPH_IDX

CRIB_SET = set(CRIB_POSITIONS)

def crib_score_shifted(pt73: str, orig_to_73: dict) -> int:
    """Score 73-char PT against cribs using position mapping."""
    return sum(1 for p, ch in CRIB_DICT.items()
               if p in orig_to_73 and orig_to_73[p] < len(pt73)
               and pt73[orig_to_73[p]] == ch)

def autokey_beau_decrypt(ct: str, primer: list) -> str:
    """Beaufort autokey decrypt: CT[i] = (k[i]-PT[i])%26, k=primer||PT."""
    pt, key = [], list(primer)
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else ALPH_IDX[pt[i - len(primer)]]
        v = (k - ALPH_IDX[c]) % 26
        pt.append(ALPH[v])
    return "".join(pt)

def autokey_vig_decrypt(ct: str, primer: list) -> str:
    """Vigenère autokey decrypt: CT[i] = (k[i]+PT[i])%26, k=primer||PT."""
    pt, key = [], list(primer)
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else ALPH_IDX[pt[i - len(primer)]]
        v = (ALPH_IDX[c] - k) % 26
        pt.append(ALPH[v])
    return "".join(pt)

def periodic_beau(ct: str, key: list) -> str:
    n = len(key)
    return "".join(ALPH[(key[i%n] - ALPH_IDX[c]) % 26] for i, c in enumerate(ct))

def periodic_vig(ct: str, key: list) -> str:
    n = len(key)
    return "".join(ALPH[(ALPH_IDX[c] - key[i%n]) % 26] for i, c in enumerate(ct))

print("=" * 70)
print("AFFINE NULL MASK (CRIB-SAFE) + AUTOKEY ATTACK")
print("=" * 70)
print(f"CT: {CT}")
print()

# K2-relevant parameters for affine search
K2_SLOPES = [3, 5, 6, 7, 8, 11, 13, 24, 27, 38, 44, 57, 77 % 97]
K2_INTERCEPTS = [0, 3, 5, 8, 11, 13, 21, 24, 27, 38, 44, 57, 63, 74, 79]

# Find all affine maps y=ax+b (mod 97) where NULL positions don't conflict with cribs
# null positions = {x : (ax+b)%97 >= 73}
print("--- Finding crib-safe affine null masks ---")
valid_maps = []
all_maps_tested = 0

for a in range(1, 97):
    if gcd(a, 97) != 1:
        continue  # Not a bijection
    for b in range(97):
        # Compute null positions
        null_pos = set(x for x in range(97) if (a * x + b) % 97 >= 73)
        assert len(null_pos) == 24

        # Check no conflict with crib positions
        if null_pos & CRIB_SET:
            all_maps_tested += 1
            continue

        # Valid map!
        all_maps_tested += 1
        # Score how many K2 numbers appear as slope or intercept
        k2_score = sum([a in K2_SLOPES, b in K2_INTERCEPTS,
                        a % 26 in [v % 26 for v in K2_SLOPES],
                        b % 26 in [v % 26 for v in K2_INTERCEPTS]])
        valid_maps.append((a, b, null_pos, k2_score))

print(f"Total affine maps tested: {all_maps_tested}")
print(f"Crib-safe affine maps: {len(valid_maps)}")
if valid_maps:
    k2_maps = [(a, b, np, ks) for a, b, np, ks in valid_maps if ks >= 2]
    print(f"Maps with K2-related slope/intercept (score≥2): {len(k2_maps)}")
    if k2_maps:
        for a, b, np, ks in sorted(k2_maps, key=lambda x: -x[3])[:10]:
            print(f"  a={a}, b={b}, K2-score={ks}: nulls={sorted(np)[:6]}...")

print()

# --- Autokey testing ---
# Primers to test: K2-derived + KRYPTOS keywords
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW",
    "KOMPASS", "COLOPHON", "DEFECTOR",
    "KRYPTA", "KLEPSYDRA",
    "NORTH", "WEST", "NORTHWEST",
]
# K2 digit primers
K2_PRIMERS_NUM = [
    [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],  # digits 11
    [38 % 26, 57 % 26, 6, 5, 77 % 26, 8, 44 % 26],  # K2 nums mod 26
    [3, 8],  [8, 3],  [3, 8, 11],  [3, 8, 11, 13],  [11, 13],
]
primers = [(w, [ALPH_IDX[c] for c in w]) for w in KEYWORDS]
primers += [(f"K2_{i}", p) for i, p in enumerate(K2_PRIMERS_NUM)]

# Use top valid maps (all crib-safe) + K2-priority maps
# To keep runtime manageable, test all crib-safe maps with a short primer list
maps_to_test = valid_maps  # all crib-safe maps
print(f"Testing {len(maps_to_test)} crib-safe maps × {len(primers)} primers × 2 ciphers × 73-char autokey")
print()

results = []
t_start = time.time()
tested = 0

for a, b, null_pos, k2_sc in maps_to_test:
    # Build 73-char CT and position mapping
    real_pos = sorted(x for x in range(97) if x not in null_pos)
    assert len(real_pos) == 73

    ct73 = "".join(CT[x] for x in real_pos)
    orig_to_73 = {real_pos[i]: i for i in range(73)}

    # Try all primers with autokey and periodic sub
    for pname, primer_nums in primers:
        # Autokey
        for cipher_name, fn in [("AK-Beau", autokey_beau_decrypt), ("AK-Vig", autokey_vig_decrypt)]:
            pt73 = fn(ct73, primer_nums)
            sc = crib_score_shifted(pt73, orig_to_73)
            if sc > 7:
                results.append((sc, f"affine_a={a}_b={b}_{cipher_name}_primer={pname}", pt73,
                                 sorted(null_pos)[:8]))
            tested += 1

        # Also try short periodic sub for the primer (as non-autokey comparison)
        for p_len in range(max(1, len(primer_nums)-2), min(len(primer_nums)+3, 15)):
            key = (primer_nums * (p_len // max(len(primer_nums), 1) + 1))[:p_len]
            for cipher_name, fn in [("PBeau", periodic_beau), ("PVig", periodic_vig)]:
                pt73 = fn(ct73, key)
                sc = crib_score_shifted(pt73, orig_to_73)
                if sc > 8:  # Higher threshold for periodic (already heavily tested)
                    results.append((sc, f"affine_a={a}_b={b}_{cipher_name}_p={p_len}_{pname}", pt73,
                                     sorted(null_pos)[:8]))
                tested += 1

# Report
elapsed = time.time() - t_start
results.sort(key=lambda x: -x[0])
above_noise = [r for r in results if r[0] > 7]

print(f"Total configs tested: {tested:,} in {elapsed:.1f}s")
print(f"Above noise (>7): {len(above_noise)}")

if above_noise:
    print("\nABOVE-NOISE RESULTS:")
    for sc, label, pt73, nulls in above_noise[:20]:
        matches = {}
        for orig_p, ch in CRIB_DICT.items():
            from kryptos.kernel.constants import ALPH_IDX as AX
            if orig_p not in null_pos and orig_p in {real_pos[i]: i for i in range(73)}:
                pass
        print(f"  Score {sc:2d}/24+: {label}")
        print(f"    PT73: {pt73[:60]}")
        print(f"    Nulls: {nulls}...")
        print()

if results:
    print("Top 10 results:")
    for sc, label, pt73, nulls in results[:10]:
        print(f"  {sc:2d}: {label}")
        print(f"    {pt73[:50]}")
else:
    print("No results above threshold.")

print("\nCONCLUSION:")
print(f"  Valid (crib-safe) affine null masks found: {len(valid_maps)}")
if not above_noise:
    print("  ALL crib-safe affine null masks + autokey = NOISE.")
    print("  → Affine null mask + autokey DISPROVED for K2 range of parameters.")
print("\nDONE")
