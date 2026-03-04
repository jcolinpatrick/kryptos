#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_yar_selective.py — Test the YAR Selective Substitution Theory for K4.

HYPOTHESIS: At the 9 positions in K4 where Y, A, or R appear in the carved text,
the cipher character is REPLACED by the tableau character visible through a grille
hole. At the other 88 positions, cipher text passes through unchanged.

Replace those 9 chars with the KA (or AZ) tableau char at the corresponding grid
position, then try Vigenère/Beaufort decryption.

Tests:
  A.  Replace all 9 YAR positions with KA tableau chars
  A2. Replace all 9 YAR positions with AZ tableau chars
  B.  All 2^9 = 512 subsets of YAR positions (KA tableau)
  C.  All single-letter replacements (each letter class → tableau)
  D.  All 2-letter combination replacements
  E.  All 3-letter combination replacements (C(26,3) = 2600)
  F.  All 4-letter combination replacements (expensive, top-K only)
  G.  YAR positions define key override (row key letter as Vig key)
  H.  Full tableau as running key (Vig CT-tableau)
  I.  Reverse: use tableau everywhere except at YAR positions
  J.  Grille-based: use tableau at positions where cipher==tableau
  K.  Crib-pinned: at YAR positions, compute what tableau→CT would need to be
"""
from __future__ import annotations

import sys
import time
from collections import Counter
from itertools import combinations

sys.path.insert(0, 'scripts')
from kbot_harness import (
    score_text, score_text_per_char, has_cribs,
    vig_decrypt, beau_decrypt,
    K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
)

# ─────────────────────────────────────────────────────────────────────────────
# Grid constants and tableau
# ─────────────────────────────────────────────────────────────────────────────

K4_GRID_START = 24 * 31 + 27  # = 771 (row 24, col 27)


def tableau_char_ka(r: int, c: int) -> str:
    """KA Vigenère tableau at cipher grid position (r, c), 0-indexed.
    Row key = AZ[r%26]. Col 0 = key letter. Cols 1-30 = KA body chars.
    """
    key_letter = AZ[r % 26]
    if c == 0:
        return key_letter
    key_idx = KA.index(key_letter)
    return KA[(key_idx + (c - 1)) % 26]


def tableau_char_az(r: int, c: int) -> str:
    """Standard AZ Vigenère tableau at cipher grid position (r, c)."""
    if c == 0:
        return AZ[r % 26]
    return AZ[(r % 26 + c - 1) % 26]


# Precompute tableau chars and grid coords for all K4 positions
K4_TABLEAU_KA = []
K4_TABLEAU_AZ = []
K4_GRID_COORDS = []
for _i in range(97):
    _gp = K4_GRID_START + _i
    _row, _col = _gp // 31, _gp % 31
    K4_GRID_COORDS.append((_row, _col))
    K4_TABLEAU_KA.append(tableau_char_ka(_row, _col))
    K4_TABLEAU_AZ.append(tableau_char_az(_row, _col))

# YAR positions
YAR_CHARS = frozenset("YAR")
YAR_POSITIONS = [i for i, c in enumerate(K4_CARVED) if c in YAR_CHARS]
YAR_CHARS_LIST = [K4_CARVED[i] for i in YAR_POSITIONS]
YAR_TAB_KA = [K4_TABLEAU_KA[i] for i in YAR_POSITIONS]
YAR_TAB_AZ = [K4_TABLEAU_AZ[i] for i in YAR_POSITIONS]
YAR_COORDS = [K4_GRID_COORDS[i] for i in YAR_POSITIONS]

# Known crib positions (0-indexed in K4)
CRIB_ENE_START = 21   # EASTNORTHEAST at K4[21:34]
CRIB_BC_START  = 63   # BERLINCLOCK at K4[63:74]

# ─────────────────────────────────────────────────────────────────────────────
# Core helpers
# ─────────────────────────────────────────────────────────────────────────────

def apply_replacements(positions: list[int], replacements: list[str]) -> str:
    """Apply pos→char replacements to K4_CARVED."""
    chars = list(K4_CARVED)
    for pos, rep in zip(positions, replacements):
        chars[pos] = rep
    return ''.join(chars)


def try_all(ct: str, label: str = "") -> dict:
    """Try all keyword × cipher × alpha combinations. Return best result."""
    best: dict = {"score": -1e9, "HIT": False}
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = fn(ct, kw, alpha)
                except (ValueError, IndexError):
                    continue
                cribs = has_cribs(pt)
                sc = score_text_per_char(pt)
                if cribs:
                    r = {"pt": pt, "score": sc, "key": kw, "cipher": cipher_name,
                         "alpha": alpha_name, "cribs": cribs, "HIT": True, "ct": ct}
                    print(f"\n🎯 CRIB HIT [{label}] {cipher_name}/{kw}/{alpha_name}")
                    print(f"   CT: {ct}")
                    print(f"   PT: {pt}")
                    print(f"   Cribs: {cribs}")
                    return r
                if sc > best["score"]:
                    best = {"pt": pt, "score": sc, "key": kw, "cipher": cipher_name,
                            "alpha": alpha_name, "cribs": [], "HIT": False, "ct": ct}
    return best


def fmt(r: dict, prefix: str = "") -> str:
    return (f"{prefix}{r.get('cipher','?')}/{r.get('key','?')}/{r.get('alpha','?')} "
            f"score={r.get('score',-99):.4f}  PT: {r.get('pt','')[:60]}")


# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────

print("=" * 70)
print("K4 YAR SELECTIVE SUBSTITUTION — COMPREHENSIVE ANALYSIS")
print("=" * 70)
print(f"K4 (carved):     {K4_CARVED}")
print(f"YAR positions:   {YAR_POSITIONS}")
print(f"YAR chars:       {YAR_CHARS_LIST}")
print(f"Grid coords:     {YAR_COORDS}")
print(f"KA tableau vals: {YAR_TAB_KA}")
print(f"AZ tableau vals: {YAR_TAB_AZ}")

# Show where KA/AZ tableau coincides with K4
same_ka = [i for i in range(97) if K4_CARVED[i] == K4_TABLEAU_KA[i]]
same_az = [i for i in range(97) if K4_CARVED[i] == K4_TABLEAU_AZ[i]]
print(f"\nK4==KA_tab at {len(same_ka)} positions: {same_ka}")
print(f"K4==AZ_tab at {len(same_az)} positions: {same_az}")

# ─────────────────────────────────────────────────────────────────────────────
# TEST A: Replace all 9 YAR positions with KA tableau
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST A: Replace ALL 9 YAR positions with KA tableau chars")
print("─" * 70)

MOD_A = apply_replacements(YAR_POSITIONS, YAR_TAB_KA)
print(f"Modified K4: {MOD_A}")
print(f"Changes:     {list(zip(YAR_POSITIONS, YAR_CHARS_LIST, YAR_TAB_KA))}")

r_A = try_all(MOD_A, "A-KA")
print(fmt(r_A, "  Best: "))

# ─────────────────────────────────────────────────────────────────────────────
# TEST A2: Replace all 9 YAR positions with AZ tableau
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST A2: Replace ALL 9 YAR positions with AZ (standard) tableau chars")
print("─" * 70)

MOD_A2 = apply_replacements(YAR_POSITIONS, YAR_TAB_AZ)
print(f"Modified K4: {MOD_A2}")
print(f"Changes:     {list(zip(YAR_POSITIONS, YAR_CHARS_LIST, YAR_TAB_AZ))}")

r_A2 = try_all(MOD_A2, "A2-AZ")
print(fmt(r_A2, "  Best: "))

# ─────────────────────────────────────────────────────────────────────────────
# TEST B: All 2^9 = 512 subsets of YAR positions (KA tableau)
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST B: All 2^9 = 512 subsets of YAR positions (KA tableau)")
print("─" * 70)

best_B = {"score": -1e9}
crib_hits_B: list = []

for mask in range(1, 512):  # skip mask=0 (no change = original)
    subset_idx = [j for j in range(9) if (mask >> j) & 1]
    positions = [YAR_POSITIONS[j] for j in subset_idx]
    replacements = [YAR_TAB_KA[j] for j in subset_idx]
    mod = apply_replacements(positions, replacements)
    res = try_all(mod, f"B-mask{mask:09b}")
    if res.get("HIT"):
        crib_hits_B.append({"mask": mask, "positions": positions, "res": res})
    if res["score"] > best_B["score"]:
        best_B = dict(res, mask=mask, positions=positions)

print(f"Tested 511 subsets.")
print(f"Best subset: mask={best_B.get('mask',0):09b}  positions={best_B.get('positions',[])}")
print(fmt(best_B, "  Best: "))
if crib_hits_B:
    print(f"  🎯 {len(crib_hits_B)} CRIB HIT(S)!")
    for h in crib_hits_B:
        print(f"     mask={h['mask']:09b}  pos={h['positions']}  {fmt(h['res'])}")

# ─────────────────────────────────────────────────────────────────────────────
# TEST B2: All 2^9 = 512 subsets of YAR positions (AZ tableau)
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST B2: All 2^9 = 512 subsets of YAR positions (AZ tableau)")
print("─" * 70)

best_B2 = {"score": -1e9}
crib_hits_B2: list = []

for mask in range(1, 512):
    subset_idx = [j for j in range(9) if (mask >> j) & 1]
    positions = [YAR_POSITIONS[j] for j in subset_idx]
    replacements = [YAR_TAB_AZ[j] for j in subset_idx]
    mod = apply_replacements(positions, replacements)
    res = try_all(mod, f"B2-mask{mask:09b}")
    if res.get("HIT"):
        crib_hits_B2.append({"mask": mask, "positions": positions, "res": res})
    if res["score"] > best_B2["score"]:
        best_B2 = dict(res, mask=mask, positions=positions)

print(f"Tested 511 subsets.")
print(f"Best subset: mask={best_B2.get('mask',0):09b}  positions={best_B2.get('positions',[])}")
print(fmt(best_B2, "  Best: "))
if crib_hits_B2:
    print(f"  🎯 {len(crib_hits_B2)} CRIB HIT(S)!")

# ─────────────────────────────────────────────────────────────────────────────
# TEST C: Single-letter replacements (each letter class → KA tableau)
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST C: Single-letter replacements (each letter in K4 → KA tableau)")
print("─" * 70)

best_C = {"score": -1e9}
crib_hits_C: list = []
top5_C: list = []

for letter in AZ:
    positions = [i for i, c in enumerate(K4_CARVED) if c == letter]
    if not positions:
        continue
    reps = [K4_TABLEAU_KA[i] for i in positions]
    mod = apply_replacements(positions, reps)
    res = try_all(mod, f"C-{letter}")
    if res.get("HIT"):
        crib_hits_C.append({"letter": letter, "positions": positions, "res": res})
        print(f"  🎯 Letter {letter} ({len(positions)} pos): HIT!")
    if res["score"] > best_C["score"]:
        best_C = dict(res, letter=letter, positions=positions)
    top5_C.append((res["score"], letter, res))

top5_C.sort(key=lambda x: -x[0])
print(f"Top 5 single-letter replacements:")
for sc, let, res in top5_C[:5]:
    print(f"  Letter {let}: {fmt(res)}")
if crib_hits_C:
    print(f"  🎯 {len(crib_hits_C)} CRIB HIT(S)!")

# ─────────────────────────────────────────────────────────────────────────────
# TEST D: All 2-letter combinations → KA tableau replacement
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST D: All C(26,2)=325 two-letter combinations → KA tableau")
print("─" * 70)

best_D = {"score": -1e9}
crib_hits_D: list = []
top5_D: list = []
count_D = 0

for combo in combinations(AZ, 2):
    target = frozenset(combo)
    positions = [i for i, c in enumerate(K4_CARVED) if c in target]
    if not positions:
        continue
    reps = [K4_TABLEAU_KA[i] for i in positions]
    mod = apply_replacements(positions, reps)
    res = try_all(mod, f"D-{''.join(sorted(combo))}")
    count_D += 1
    if res.get("HIT"):
        crib_hits_D.append({"combo": combo, "positions": positions, "res": res})
        print(f"  🎯 {combo}: HIT!")
    if res["score"] > best_D["score"]:
        best_D = dict(res, combo=combo, positions=positions)
    top5_D.append((res["score"], combo, res))

top5_D.sort(key=lambda x: -x[0])
print(f"Tested {count_D} 2-letter combos.")
print(f"Top 5 two-letter replacements:")
for sc, combo, res in top5_D[:5]:
    print(f"  {''.join(sorted(combo))}: {fmt(res)}")
if crib_hits_D:
    print(f"  🎯 {len(crib_hits_D)} CRIB HIT(S)!")

# ─────────────────────────────────────────────────────────────────────────────
# TEST E: All 3-letter combinations → KA tableau replacement (C(26,3)=2600)
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST E: All C(26,3)=2600 three-letter combinations → KA tableau")
print("─" * 70)

best_E = {"score": -1e9}
crib_hits_E: list = []
top5_E: list = []
count_E = 0

for combo in combinations(AZ, 3):
    target = frozenset(combo)
    positions = [i for i, c in enumerate(K4_CARVED) if c in target]
    if not positions or len(positions) > 35:
        count_E += 1
        continue
    reps = [K4_TABLEAU_KA[i] for i in positions]
    mod = apply_replacements(positions, reps)
    res = try_all(mod, f"E-{''.join(sorted(combo))}")
    count_E += 1
    if res.get("HIT"):
        crib_hits_E.append({"combo": combo, "positions": positions, "res": res})
        print(f"  🎯 {combo}: HIT!")
    if res["score"] > best_E["score"]:
        best_E = dict(res, combo=combo, positions=positions)
    top5_E.append((res["score"], combo, res))

top5_E.sort(key=lambda x: -x[0])
print(f"Tested {count_E} 3-letter combos (≤35 positions each).")
print(f"Top 5 three-letter replacements:")
for sc, combo, res in top5_E[:5]:
    print(f"  {''.join(sorted(combo))}: {fmt(res)}")
if crib_hits_E:
    print(f"  🎯 {len(crib_hits_E)} CRIB HIT(S)!")

# ─────────────────────────────────────────────────────────────────────────────
# TEST F: 4-letter combinations — only combos with 5-25 total positions
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST F: All C(26,4)=14950 four-letter combinations → KA tableau (filtered)")
print("─" * 70)

best_F = {"score": -1e9}
crib_hits_F: list = []
top5_F: list = []
count_F = 0

for combo in combinations(AZ, 4):
    target = frozenset(combo)
    positions = [i for i, c in enumerate(K4_CARVED) if c in target]
    if len(positions) < 4 or len(positions) > 25:
        continue
    reps = [K4_TABLEAU_KA[i] for i in positions]
    mod = apply_replacements(positions, reps)
    res = try_all(mod, f"F-{''.join(sorted(combo))}")
    count_F += 1
    if res.get("HIT"):
        crib_hits_F.append({"combo": combo, "positions": positions, "res": res})
        print(f"  🎯 {combo}: HIT!")
    if res["score"] > best_F["score"]:
        best_F = dict(res, combo=combo, positions=positions)
    top5_F.append((res["score"], combo, res))

top5_F.sort(key=lambda x: -x[0])
print(f"Tested {count_F} 4-letter combos (4-25 positions each).")
print(f"Top 5 four-letter replacements:")
for sc, combo, res in top5_F[:5]:
    print(f"  {''.join(sorted(combo))}: {fmt(res)}")
if crib_hits_F:
    print(f"  🎯 {len(crib_hits_F)} CRIB HIT(S)!")

# ─────────────────────────────────────────────────────────────────────────────
# TEST G: YAR positions use TABLEAU ROW KEY LETTER as cipher key
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST G: YAR positions override Vigenère key with tableau row-key-letter")
print("─" * 70)

# At YAR position i, use AZ[row % 26] as the key letter instead of keyword[i%len]
yar_row_keys = {i: AZ[K4_GRID_COORDS[i][0] % 26] for i in YAR_POSITIONS}
print(f"YAR row key overrides: {yar_row_keys}")

def vig_decrypt_override(ct: str, base_key: str, override: dict, alpha: str = AZ) -> str:
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki_letter = override.get(i, base_key[i % len(base_key)])
        ki = alpha.index(ki_letter)
        result.append(alpha[(ci - ki) % 26])
    return "".join(result)

def beau_decrypt_override(ct: str, base_key: str, override: dict, alpha: str = AZ) -> str:
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki_letter = override.get(i, base_key[i % len(base_key)])
        ki = alpha.index(ki_letter)
        result.append(alpha[(ki - ci) % 26])
    return "".join(result)

best_G = {"score": -1e9}
crib_hits_G: list = []

for kw in KEYWORDS:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, fn in [("vig", vig_decrypt_override),
                                 ("beau", beau_decrypt_override)]:
            try:
                pt = fn(K4_CARVED, kw, yar_row_keys, alpha)
            except (ValueError, IndexError):
                continue
            cribs = has_cribs(pt)
            sc = score_text_per_char(pt)
            if cribs:
                r = {"pt": pt, "score": sc, "key": kw, "cipher": cipher_name,
                     "alpha": alpha_name, "cribs": cribs, "HIT": True}
                print(f"  🎯 HIT! {cipher_name}/{kw}/{alpha_name}: {pt}")
                crib_hits_G.append(r)
            if sc > best_G["score"]:
                best_G = {"pt": pt, "score": sc, "key": kw, "cipher": cipher_name,
                          "alpha": alpha_name, "cribs": cribs, "HIT": bool(cribs)}

print(fmt(best_G, "  Best: "))
if crib_hits_G:
    print(f"  🎯 {len(crib_hits_G)} CRIB HIT(S)!")

# ─────────────────────────────────────────────────────────────────────────────
# TEST H: Full KA tableau as running key
# Use the tableau char at each K4 position as the Vigenère key for that position
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST H: Full KA tableau as running key (each position gets tableau key)")
print("─" * 70)

def vig_decrypt_runkey(ct: str, key_stream: list[str], alpha: str = AZ) -> str:
    result = []
    for i, c in enumerate(ct):
        try:
            ci = alpha.index(c)
            ki = alpha.index(key_stream[i])
            result.append(alpha[(ci - ki) % 26])
        except ValueError:
            result.append('?')
    return "".join(result)

def beau_decrypt_runkey(ct: str, key_stream: list[str], alpha: str = AZ) -> str:
    result = []
    for i, c in enumerate(ct):
        try:
            ci = alpha.index(c)
            ki = alpha.index(key_stream[i])
            result.append(alpha[(ki - ci) % 26])
        except ValueError:
            result.append('?')
    return "".join(result)

best_H = {"score": -1e9}
crib_hits_H: list = []

for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for cipher_name, fn in [("vig", vig_decrypt_runkey), ("beau", beau_decrypt_runkey)]:
        # Running key from KA tableau
        pt = fn(K4_CARVED, K4_TABLEAU_KA, alpha)
        cribs = has_cribs(pt)
        sc = score_text_per_char(pt)
        label = f"H-{cipher_name}-KArunkey-{alpha_name}"
        if cribs:
            print(f"  🎯 HIT! {label}: {pt}")
            crib_hits_H.append({"label": label, "pt": pt, "cribs": cribs})
        if sc > best_H["score"]:
            best_H = {"pt": pt, "score": sc, "label": label, "cribs": cribs, "HIT": bool(cribs)}
        # Running key from AZ tableau
        pt2 = fn(K4_CARVED, K4_TABLEAU_AZ, alpha)
        cribs2 = has_cribs(pt2)
        sc2 = score_text_per_char(pt2)
        label2 = f"H-{cipher_name}-AZrunkey-{alpha_name}"
        if cribs2:
            print(f"  🎯 HIT! {label2}: {pt2}")
            crib_hits_H.append({"label": label2, "pt": pt2, "cribs": cribs2})
        if sc2 > best_H["score"]:
            best_H = {"pt": pt2, "score": sc2, "label": label2, "cribs": cribs2,
                      "HIT": bool(cribs2)}
        # Also try modified (YAR replaced) K4 with tableau running key
        pt3 = fn(MOD_A, K4_TABLEAU_KA, alpha)
        cribs3 = has_cribs(pt3)
        sc3 = score_text_per_char(pt3)
        label3 = f"H-{cipher_name}-KAmod-{alpha_name}"
        if cribs3:
            print(f"  🎯 HIT! {label3}: {pt3}")
            crib_hits_H.append({"label": label3, "pt": pt3, "cribs": cribs3})
        if sc3 > best_H["score"]:
            best_H = {"pt": pt3, "score": sc3, "label": label3, "cribs": cribs3,
                      "HIT": bool(cribs3)}

print(f"  Best: label={best_H.get('label','')}  score={best_H['score']:.4f}")
print(f"  PT:   {best_H.get('pt','')[:60]}")
if crib_hits_H:
    print(f"  🎯 {len(crib_hits_H)} CRIB HIT(S)!")

# ─────────────────────────────────────────────────────────────────────────────
# TEST I: Reverse — use TABLEAU everywhere EXCEPT at YAR positions (as holes)
# Model: solid positions show TABLEAU; holes show CIPHER TEXT
# So the 9 YAR positions are where cipher text (Y/A/R) shows through
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST I: Reverse model — tableau everywhere EXCEPT at YAR positions")
print("─" * 70)

# Use KA tableau for all positions, override with K4 chars at YAR positions
chars_I_ka = list(K4_TABLEAU_KA)
for i in YAR_POSITIONS:
    chars_I_ka[i] = K4_CARVED[i]
MOD_I_KA = ''.join(chars_I_ka)

chars_I_az = list(K4_TABLEAU_AZ)
for i in YAR_POSITIONS:
    chars_I_az[i] = K4_CARVED[i]
MOD_I_AZ = ''.join(chars_I_az)

print(f"Mostly-KA-tableau (with YAR overrides): {MOD_I_KA}")
print(f"Mostly-AZ-tableau (with YAR overrides): {MOD_I_AZ}")

r_I_ka = try_all(MOD_I_KA, "I-reverse-KA")
r_I_az = try_all(MOD_I_AZ, "I-reverse-AZ")
print(fmt(r_I_ka, "  Best (KA tab): "))
print(fmt(r_I_az, "  Best (AZ tab): "))

# ─────────────────────────────────────────────────────────────────────────────
# TEST J: Grille at ambiguous positions (K4[i] == tableau[i])
# Use those positions as the "grille holes" for replacement
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST J: Use cipher==tableau positions as grille holes")
print("─" * 70)

# same_ka and same_az computed above
print(f"Ambiguous KA positions: {same_ka}  chars: {[K4_CARVED[i] for i in same_ka]}")
print(f"Ambiguous AZ positions: {same_az}  chars: {[K4_CARVED[i] for i in same_az]}")

if same_ka:
    # Try all 2^|same_ka| subsets — if small enough
    if len(same_ka) <= 12:
        best_J = {"score": -1e9}
        crib_hits_J: list = []
        for mask in range(1, 2**len(same_ka)):
            subset_idx = [j for j in range(len(same_ka)) if (mask >> j) & 1]
            positions = [same_ka[j] for j in subset_idx]
            # At these ambiguous positions, substitute with something different
            # Here we try: replace with each possible letter
            # But since cipher==tableau at these positions, replacing with tableau = no change
            # Instead, try replacing with the "reverse" — what would make the crib work?
            # For now: just try replacing with surrounding key-derived char
            pass
    else:
        print(f"  Too many ({len(same_ka)}) ambiguous KA positions, skipping subset test")

# Modified: replace ambiguous positions with the tableau char (which = cipher, so no change)
# Instead, let's try replacing them with K4_TABLEAU_AZ (different from KA tableau)
pos_switch = same_ka  # positions where cipher==KA_tableau
reps_switch = [K4_TABLEAU_AZ[i] for i in pos_switch]  # replace with AZ tableau
mod_J = apply_replacements(pos_switch, reps_switch)
print(f"Ambiguous KA→AZ switch: {mod_J}")
r_J = try_all(mod_J, "J-amb-switch")
print(fmt(r_J, "  Best: "))

# ─────────────────────────────────────────────────────────────────────────────
# TEST K: Crib-back analysis — what would the modified K4 need to be?
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST K: Crib-back analysis — compute required CT from cribs+YAR theory")
print("─" * 70)

# If K4[21:34] should decrypt to EASTNORTHEAST under Vig/KRYPTOS/AZ, then:
# CT[21:34] = [AZ[(AZ.index(pt)+AZ.index(key[i%7]))%26] for each pos]
# Any YAR positions in range 21-33 and 63-73 need to match the YAR replacements

K4_PT_ENE = "EASTNORTHEAST"  # positions 21-33
K4_PT_BC  = "BERLINCLOCK"    # positions 63-73

# YAR positions intersecting with cribs
yar_in_ene = [i for i in YAR_POSITIONS if 21 <= i <= 33]
yar_in_bc  = [i for i in YAR_POSITIONS if 63 <= i <= 73]
print(f"YAR positions in EASTNORTHEAST range [21-33]: {yar_in_ene}")
print(f"YAR positions in BERLINCLOCK range [63-73]: {yar_in_bc}")

print(f"\nFor each YAR pos in crib range, what tableau value is substituted?")
for i in yar_in_ene:
    crib_char = K4_PT_ENE[i - 21]
    print(f"  K4[{i}]={K4_CARVED[i]} (crib needs '{crib_char}' at PT)")
    print(f"    KA_tab={K4_TABLEAU_KA[i]}, AZ_tab={K4_TABLEAU_AZ[i]}")
    # Under Vig: CT = KA_tab[i] = Vig_encrypt(PT, key)
    # So PT = Vig_decrypt(KA_tab, key)
    for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            try:
                pt_from_ka = vig_decrypt(K4_TABLEAU_KA[i], kw[i % len(kw)], alpha)
                match_ka = " ← CRIB MATCH!" if pt_from_ka == crib_char else ""
                pt_from_az = vig_decrypt(K4_TABLEAU_AZ[i], kw[i % len(kw)], alpha)
                match_az = " ← CRIB MATCH!" if pt_from_az == crib_char else ""
                if match_ka or match_az:
                    print(f"    [{kw}/{alpha_name}] KA_tab→{pt_from_ka}{match_ka}  AZ_tab→{pt_from_az}{match_az}")
            except (ValueError, IndexError):
                pass

for i in yar_in_bc:
    crib_char = K4_PT_BC[i - 63]
    print(f"  K4[{i}]={K4_CARVED[i]} (crib needs '{crib_char}' at PT)")
    print(f"    KA_tab={K4_TABLEAU_KA[i]}, AZ_tab={K4_TABLEAU_AZ[i]}")
    for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            try:
                pt_from_ka = vig_decrypt(K4_TABLEAU_KA[i], kw[i % len(kw)], alpha)
                match_ka = " ← CRIB MATCH!" if pt_from_ka == crib_char else ""
                pt_from_az = vig_decrypt(K4_TABLEAU_AZ[i], kw[i % len(kw)], alpha)
                match_az = " ← CRIB MATCH!" if pt_from_az == crib_char else ""
                if match_ka or match_az:
                    print(f"    [{kw}/{alpha_name}] KA_tab→{pt_from_ka}{match_ka}  AZ_tab→{pt_from_az}{match_az}")
            except (ValueError, IndexError):
                pass

# ─────────────────────────────────────────────────────────────────────────────
# TEST L: YAR + full-text Beaufort (self-reciprocal) special cases
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST L: YAR replacement + extended keyword list (all KEYWORDS + variants)")
print("─" * 70)

EXTENDED_KEYWORDS = list(KEYWORDS) + [
    "NORTHEASTERNORTHEAST",  # repeated crib
    "CLOCK", "EAST", "NORTH", "BERLINCLOCK",
    "ABSCISSA",  # period 8 — "8 lines 73"
    "KRYPTOSABSCISSA", "ABSCISSAKRYPTOS",
    "A", "B", "K", "Y", "Z",  # single-char keys
    "SHADOW", "SANBORN", "SCHEIDT",
    "YES", "YESW", "YESWONDERFUL",
]

# Deduplicate
EXTENDED_KEYWORDS = list(dict.fromkeys(EXTENDED_KEYWORDS))

best_L = {"score": -1e9}
crib_hits_L: list = []

for kw in EXTENDED_KEYWORDS:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            for test_ct, test_label in [(MOD_A, "KA-replaced"), (MOD_A2, "AZ-replaced"),
                                         (K4_CARVED, "original")]:
                try:
                    pt = fn(test_ct, kw, alpha)
                except (ValueError, IndexError):
                    continue
                cribs = has_cribs(pt)
                sc = score_text_per_char(pt)
                if cribs:
                    r = {"pt": pt, "score": sc, "key": kw, "cipher": cipher_name,
                         "alpha": alpha_name, "cribs": cribs, "HIT": True,
                         "label": test_label}
                    print(f"  🎯 HIT! {cipher_name}/{kw}/{alpha_name}/{test_label}: {pt}")
                    crib_hits_L.append(r)
                if sc > best_L["score"]:
                    best_L = {"pt": pt, "score": sc, "key": kw, "cipher": cipher_name,
                               "alpha": alpha_name, "cribs": cribs, "HIT": bool(cribs),
                               "label": test_label}

print(fmt(best_L, f"  Best (label={best_L.get('label','')}): "))
if crib_hits_L:
    print(f"  🎯 {len(crib_hits_L)} CRIB HIT(S)!")

# ─────────────────────────────────────────────────────────────────────────────
# TEST M: Period-8 special test — YAR positions alignment with ABSCISSA period
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST M: YAR positions vs ABSCISSA/period-8 key alignment")
print("─" * 70)

print("YAR positions mod 7 (KRYPTOS), mod 8 (ABSCISSA), mod 10 (PALIMPSEST):")
for i in YAR_POSITIONS:
    print(f"  pos={i:2d}  char={K4_CARVED[i]}  mod7={i%7}→key={KA[i%7]}  "
          f"mod8={i%8}→ABSCISSA[{i%8}]={'ABSCISSA'[i%8]}  "
          f"mod10={i%10}→PALIMPSEST[{i%10}]={'PALIMPSEST'[i%10]}")

# Check if any YAR positions share same mod-k value (would indicate periodic key)
print("\nCheck: multiple YAR positions with same ABSCISSA key letter?")
abscissa_groups: dict = {}
for i in YAR_POSITIONS:
    k = 'ABSCISSA'[i%8]
    abscissa_groups.setdefault(k, []).append(i)
for k, positions in abscissa_groups.items():
    if len(positions) > 1:
        print(f"  Key letter '{k}' of ABSCISSA maps to positions: {positions}  chars: {[K4_CARVED[p] for p in positions]}")

# Period-8 test: for each period-8 Beaufort key, check YAR replaced K4
for kw in ['ABSCISSA', 'SCHEIDT', 'KRYPTOS', 'BERLINCLOCK']:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for test_ct, label in [(MOD_A, "KA-rep"), (K4_CARVED, "orig")]:
            try:
                pt_v = vig_decrypt(test_ct, kw, alpha)
                pt_b = beau_decrypt(test_ct, kw, alpha)
            except (ValueError, IndexError):
                continue
            sc_v = score_text_per_char(pt_v)
            sc_b = score_text_per_char(pt_b)
            if sc_v > -5.5 or sc_b > -5.5:
                print(f"  Notable: [{kw}/{alpha_name}/{label}] "
                      f"vig={sc_v:.3f}  beau={sc_b:.3f}")

# ─────────────────────────────────────────────────────────────────────────────
# TEST N: Structural test — 180° rotation on K4 after YAR replacement
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST N: 180° rotation on modified K4 (r,c)→(27-r,30-c)")
print("─" * 70)

# The 28×31 grid 180° rotation: position p → (27-(p//31))*31 + (30-(p%31)) = 27*31+30 - p = 867-p
# For K4: position i in K4 = grid position 771+i
# 180° rotation of K4[i] (at grid pos 771+i) → grid pos 867-(771+i) = 96-i
# So K4[i] ↔ K4[96-i] under 180° rotation (K4 maps to itself reversed!)

# Wait: K4 occupies grid positions 771..867. Under 180° rotation: 771+i → 867-(771+i) = 96-i
# But 96-i is within 0..96, so it's also in K4! That means K4 self-maps under 180° rotation.
# K4_rotated[i] = K4_CARVED[96-i] (reversal of K4)

K4_REVERSED = K4_CARVED[::-1]
print(f"K4 reversed: {K4_REVERSED}")
r_N = try_all(K4_REVERSED, "N-180deg")
print(fmt(r_N, "  Best (reversed K4): "))

# Also try reversed modified K4
MOD_A_REV = MOD_A[::-1]
r_N2 = try_all(MOD_A_REV, "N-180deg-modA")
print(fmt(r_N2, "  Best (reversed mod-A K4): "))

# ─────────────────────────────────────────────────────────────────────────────
# TEST O: YAR positions in K4 define a GRILLE that selects K1/K2 characters
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "─" * 70)
print("TEST O: K4 YAR positions select specific chars from K1+K2")
print("─" * 70)

# Full cipher text for reference
FULL_CT = ("EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMF"
           "DVFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKQDQMCPFQZDQMMIAGPFXHQRLG"
           "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCETBJDFHR"
           "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZER"
           "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK"
           "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
           "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG")

# YAR positions relative to various alignments
print(f"K4 YAR positions (abs in full CT): {[768+i for i in YAR_POSITIONS]}")
print(f"Those positions in full CT: {[FULL_CT[768+i] if 768+i<len(FULL_CT) else '?' for i in YAR_POSITIONS]}")

# ─────────────────────────────────────────────────────────────────────────────
# OVERALL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("OVERALL SUMMARY — ALL TESTS")
print("=" * 70)

all_results = [
    ("A  - YAR→KA tableau (all 9)", r_A),
    ("A2 - YAR→AZ tableau (all 9)", r_A2),
    ("B  - Best KA subset (511)",   best_B),
    ("B2 - Best AZ subset (511)",   best_B2),
    ("C  - Best single-letter",     best_C),
    ("D  - Best 2-letter combo",    best_D),
    ("E  - Best 3-letter combo",    best_E),
    ("F  - Best 4-letter combo",    best_F),
    ("G  - YAR row-key override",   best_G),
    ("H  - Tableau running key",    best_H),
    ("I  - Reverse (KA)", r_I_ka),
    ("I  - Reverse (AZ)", r_I_az),
    ("J  - Ambiguous switch",       r_J),
    ("L  - Extended keywords",      best_L),
    ("N  - 180° reversed K4",       r_N),
    ("N2 - 180° reversed mod-A",    r_N2),
]

# Sort by score
for name, res in sorted(all_results, key=lambda x: x[1].get('score', -99), reverse=True):
    score = res.get('score', -99)
    hit   = "🎯 HIT!" if res.get('HIT') else ""
    kstr  = f"{res.get('cipher','?')}/{res.get('key','?')}/{res.get('alpha','?')}"
    print(f"  {name:45s} {score:7.4f}  {kstr}  {hit}")

total_hits = sum([
    len(crib_hits_B), len(crib_hits_B2), len(crib_hits_C), len(crib_hits_D),
    len(crib_hits_E), len(crib_hits_F), len(crib_hits_G), len(crib_hits_H),
    len(crib_hits_L),
    int(bool(r_A.get("HIT"))), int(bool(r_A2.get("HIT"))),
    int(bool(r_I_ka.get("HIT"))), int(bool(r_I_az.get("HIT"))),
    int(bool(r_J.get("HIT"))), int(bool(r_N.get("HIT"))), int(bool(r_N2.get("HIT"))),
])

baseline = score_text_per_char(K4_CARVED)
print(f"\nBaseline (raw K4, best decrypt): ~-8.0 to -9.0 per char")
print(f"Raw K4 score (no decrypt): {baseline:.4f}")
print(f"\nTotal crib hits across all tests: {total_hits}")

if total_hits > 0:
    print("VERDICT: PROMISING — crib hits found!")
else:
    best_overall_score = max(r.get('score', -99) for _, r in all_results)
    print(f"Best score across all tests: {best_overall_score:.4f}")
    if best_overall_score > -5.0:
        print("VERDICT: INCONCLUSIVE — no cribs but some structure above random")
    else:
        print("VERDICT: DISPROVED — no crib hits, all scores near random baseline")

print("\nDone.")
