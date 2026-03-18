#!/usr/bin/env python3
"""Quick verification and analysis of the mod 49 palette separator and KA mod 5 structure."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET, ALPH_IDX
from math import comb
from collections import Counter

CT97 = CT
KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}

PALETTE = frozenset('BGIKOWZ')
CONSENSUS_NULLS = [0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85]
ALL_PALETTE_POS = [i for i in range(97) if CT97[i] in PALETTE]
NONNULL_PALETTE_POS = [p for p in ALL_PALETTE_POS if p not in set(CONSENSUS_NULLS)]

# ═══════════════════════════════════════════════════════════════
# VERIFY MOD 49 SEPARATOR
# ═══════════════════════════════════════════════════════════════
print("=" * 72)
print("MOD 49 SEPARATOR — VERIFICATION")
print("=" * 72)
print()

# 97 = 49 + 48. So pos mod 49 essentially partitions:
# positions 0-48 -> residues 0-48 (1:1)
# positions 49-96 -> residues 0-47 (1:1 again, with 48 unused)
# For 35 palette positions spread across 0-96, the mod-49 residues
# are unique for most, with some collisions for positions in [49-96]
# that share residues with positions in [0-48].

print("Null palette positions and their mod 49 residues:")
for p in CONSENSUS_NULLS:
    r = p % 49
    same_residue = [q for q in ALL_PALETTE_POS if q % 49 == r and q != p]
    print(f"  pos={p:2d} ({CT97[p]}) mod 49 = {r:2d}  other pal pos with same residue: {same_residue}")

print("\nNon-null palette positions and their mod 49 residues:")
for p in NONNULL_PALETTE_POS:
    r = p % 49
    same_residue = [q for q in ALL_PALETTE_POS if q % 49 == r and q != p]
    print(f"  pos={p:2d} ({CT97[p]}) mod 49 = {r:2d}  other pal pos with same residue: {same_residue}")

# The key question: is mod 49 meaningful, or is it TRIVIALLY true because
# 49 > 97/2 means most positions have unique residues?
# With 35 palette positions, mod 49 gives at most 49 distinct residues.
# 35 positions -> at most 35-49 = some collisions.
# Positions that collide: pos and pos+49 (both < 97)
# pos+49 < 97 => pos < 48, so positions 0-47 collide with 49-96
colliding_pairs = []
for p in ALL_PALETTE_POS:
    partner = p + 49
    if partner < 97 and CT97[partner] in PALETTE:
        colliding_pairs.append((p, partner))
    partner2 = p - 49
    if partner2 >= 0 and partner2 < p and CT97[partner2] in PALETTE:
        pass  # already counted

print(f"\nPalette position pairs that collide mod 49:")
for p1, p2 in colliding_pairs:
    null1 = p1 in set(CONSENSUS_NULLS)
    null2 = p2 in set(CONSENSUS_NULLS)
    print(f"  {p1}({CT97[p1]},{'null' if null1 else 'real'}) <-> {p2}({CT97[p2]},{'null' if null2 else 'real'})")
    # For the separator to work, these must have SAME null status
    if null1 != null2:
        print(f"    *** CONFLICT: same mod-49 residue but different null status! ***")

# So the mod 49 separator is only interesting if NO colliding pair has
# different null status. Let's check exhaustively.
conflicts = 0
for p in ALL_PALETTE_POS:
    r = p % 49
    for q in ALL_PALETTE_POS:
        if q != p and q % 49 == r:
            p_null = p in set(CONSENSUS_NULLS)
            q_null = q in set(CONSENSUS_NULLS)
            if p_null != q_null:
                conflicts += 1

print(f"\nTotal mod-49 conflicts (same residue, different null status): {conflicts // 2} pairs")
# If 0 conflicts, the separator works.
# But it's TRIVIALLY guaranteed when there are few collisions and the collisions
# happen to agree on null status.

# How many palette pairs share a mod-49 residue?
shared = sum(1 for i in range(len(ALL_PALETTE_POS)) for j in range(i+1, len(ALL_PALETTE_POS))
             if ALL_PALETTE_POS[i] % 49 == ALL_PALETTE_POS[j] % 49)
print(f"Palette pairs sharing mod-49 residue: {shared}")
print(f"Total palette pairs: {len(ALL_PALETTE_POS) * (len(ALL_PALETTE_POS)-1) // 2}")

# STATISTICAL SIGNIFICANCE
# If mod 49 has K colliding pairs, and each pair has independent P(same null status),
# then P(all agree) = P(same)^K
# P(same null status for a random pair) = P(both null) + P(both non-null)
# = (17/35 * 16/34) + (18/35 * 17/34) = (17*16 + 18*17) / (35*34)
p_same = (17*16 + 18*17) / (35*34)
print(f"\nP(random pair has same null status): {p_same:.4f}")
print(f"Number of colliding pairs: {shared}")
print(f"P(all {shared} pairs agree): {p_same**shared:.6f}")
print(f"= 1 in {1/(p_same**shared):.0f}")
print()

# So mod 49 works because there are very few collisions, and those few
# happen to agree. It's NOT a deep structure — it's ~50% chance per collision.
# CONCLUSION: mod 49 is NOT a meaningful generating rule.
print("CONCLUSION: mod 49 separator is TRIVIAL (few collisions, each ~50%")
print("chance of agreeing on null status). NOT a generating rule.")
print()

# ═══════════════════════════════════════════════════════════════
# DEEPER: KA MOD 5 = {0,3} — THE 4 EXCLUDED LETTERS
# ═══════════════════════════════════════════════════════════════
print("=" * 72)
print("KA MOD 5 = {0,3} — DEEPER ANALYSIS OF 4 EXCLUDED LETTERS {D,M,P,Q}")
print("=" * 72)
print()

# From the 11-letter superset (KA mod 5 ∈ {0,3}), palette excludes {D,M,P,Q}
# with KA positions {10,18,3,20}
# What do D,M,P,Q have in common?
excluded = ['D', 'M', 'P', 'Q']
excluded_ka = [KA_IDX[c] for c in excluded]
excluded_az = [ALPH_IDX[c] for c in excluded]
print(f"Excluded: {excluded}")
print(f"  KA positions: {excluded_ka} -> sorted: {sorted(excluded_ka)}")
print(f"  AZ positions: {excluded_az} -> sorted: {sorted(excluded_az)}")
print()

# KA positions {3, 10, 18, 20}
# Mod 5: all in {0,3} (by construction, since they're in the superset)
# Row in 5-wide grid: {0, 2, 3, 4} (one per row except rows 1 and 5)
# But Z is alone in row 5. So: one excluded per row from rows {0,2,3,4}
# Row 1 has no excluded (both col 0 and col 3 are palette: O, B)
# Row 5 has no col-3 entry (only Z at col 0, which is palette)

# Could the excluded letters be determined by WHICH column they're in?
# Col 0 excluded: D(row 2), Q(row 4) — rows 2 and 4
# Col 3 excluded: P(row 0), M(row 3) — rows 0 and 3
# Col 0 palette: K(row 0), O(row 1), I(row 3), Z(row 5) — rows 0,1,3,5
# Col 3 palette: B(row 1), G(row 2), W(row 4) — rows 1,2,4

# PATTERN CHECK: In column 0, excluded at EVEN rows {2,4}; palette at rows {0,1,3,5}
# In column 3, excluded at rows {0,3}; palette at rows {1,2,4}
# Column 0: excluded at {2,4}, palette at {0,1,3,5}
# Column 3: excluded at {0,3}, palette at {1,2,4}

# Another way: palette picks from col 0 at rows {0,1,3,5} and col 3 at rows {1,2,4}
# Together: col 0 rows = {0,1,3,5}, col 3 rows = {1,2,4}
# Interleaved: row 0=col0, row 1=both, row 2=col3, row 3=col0, row 4=col3, row 5=col0
# ALTERNATING pattern: col0, both, col3, col0, col3, col0
# Not quite alternating but close

# More interesting: the palette picks EXACTLY ONE from each available row
# Row 0: col 0 only (K, not P) -> 1 pick
# Row 1: both cols (O and B) -> 2 picks
# Row 2: col 3 only (G, not D) -> 1 pick
# Row 3: col 0 only (I, not M) -> 1 pick
# Row 4: col 3 only (W, not Q) -> 1 pick
# Row 5: col 0 only (Z, no col 3) -> 1 pick
# Total: 1+2+1+1+1+1 = 7 = palette size!

# In rows 0,2,3,4: one of two candidates is selected, the other excluded
# The selection: row 0 picks col 0, row 2 picks col 3, row 3 picks col 0, row 4 picks col 3
# Pattern: 0, 3, 0, 3 — ALTERNATING between col 0 and col 3!
print("5-wide KA grid palette selection pattern:")
print("  Row 0: K(col 0) selected, P(col 3) excluded -> col 0")
print("  Row 1: O(col 0) selected, B(col 3) selected -> BOTH")
print("  Row 2: D(col 0) excluded, G(col 3) selected -> col 3")
print("  Row 3: I(col 0) selected, M(col 3) excluded -> col 0")
print("  Row 4: Q(col 0) excluded, W(col 3) selected -> col 3")
print("  Row 5: Z(col 0) selected, [no col 3]         -> col 0")
print()
print("  Selection column for rows 0,2,3,4: 0, 3, 0, 3 = ALTERNATING!")
print("  Row 1 = BOTH (unique: only row with 2 picks)")
print("  Row 5 = FORCED (only one candidate)")
print()

# The alternating pattern (col 0, col 3, col 0, col 3) for rows 0,2,3,4
# is a clean structural rule!
# But wait: the rows involved are 0,2,3,4 — NOT evenly spaced.
# Let me re-examine: in the "choice rows" (rows that have both col 0 and col 3):
# Rows 0,1,2,3,4 all have both columns. Row 5 has only col 0.
# Excluding row 1 (which picks both) and row 5 (forced):
# Rows 0,2,3,4 alternate: col 0, col 3, col 0, col 3
# Rows are consecutive when excluding 1 (which is a BOTH-row).
# So the rule is:
# - In the 5-wide KA grid, columns 0 and 3 are "eligible"
# - Row 1 (containing OSAB C) takes BOTH candidates -> contributes 2
# - Other rows alternate: col 0, skip, col 3, col 0, col 3, col 0
# This is clean but somewhat ad hoc.

# Let me check if this pattern has a simpler description.
# Palette KA positions: {0, 5, 8, 13, 15, 23, 25}
# Excluded KA positions: {3, 10, 18, 20}
# ALL in superset: {0, 3, 5, 8, 10, 13, 15, 18, 20, 23, 25}

# Within the superset, palette and excluded differ:
# Palette: positions whose KA INDEX has certain property
# Excluded: {3, 10, 18, 20}. Diffs: 10-3=7, 18-10=8, 20-18=2
# Palette: {0, 5, 8, 13, 15, 23, 25}

# Check: excluded positions are {3, 10, 18, 20}
# Are these KRYPTOS positions? KRYPTOS = KA[0:7], so 3 is in range.
# KA[3] = P (part of KRYPTOS). P is excluded from palette.
# Actually P IS in "KRYPTOS": K=0,R=1,Y=2,P=3,T=4,O=5,S=6
# So P(KA=3) is the 4th letter of KRYPTOS and is EXCLUDED from palette.
# The only KRYPTOS letters IN the palette are K(0) and O(5).
# K and O are at KA positions 0 and 5, both mod 5 = 0.
# The KRYPTOS letters at KA mod 5 = 3 are P(3) -> EXCLUDED.
# Other KRYPTOS letters: R(1,mod5=1), Y(2,mod5=2), T(4,mod5=4), S(6,mod5=1)
# These are in columns 1,2,4 of the 5-wide grid -> NOT in the superset at all.

print("KRYPTOS letters in the mod-5 superset:")
for c in "KRYPTOS":
    ka = KA_IDX[c]
    in_sup = ka % 5 in (0, 3)
    in_pal = c in PALETTE
    print(f"  {c}(KA={ka}, mod5={ka%5}): superset={'YES' if in_sup else 'NO'}, palette={'YES' if in_pal else 'NO'}")

print()
print("Summary: Only K(mod5=0) and O(mod5=0) from KRYPTOS are in superset.")
print("P(mod5=3) is in superset but EXCLUDED from palette.")
print("The other 4 KRYPTOS letters (R,Y,T,S) are not in the superset at all.")
print()

# ═══════════════════════════════════════════════════════════════
# KEY INSIGHT: EXCLUDED = KA positions ≡ 0 or 3 mod 5 BUT ALSO ≡ 3 mod 5 in the 10-period
# ═══════════════════════════════════════════════════════════════
# Excluded KA: {3, 10, 18, 20}
# mod 10: {3, 0, 8, 0}
# Palette KA: {0, 5, 8, 13, 15, 23, 25}
# mod 10: {0, 5, 8, 3, 5, 3, 5}
# Hmm, both have 3 and 0.
# Not clean.

# Try: excluded KA modulo various
print("Excluded KA positions {3,10,18,20} modular analysis:")
for m in range(2, 20):
    residues = set(x % m for x in excluded_ka)
    print(f"  mod {m}: {sorted(residues)} ({len(residues)} distinct)")
    if len(residues) <= 2:
        # Check if palette's superset positions NOT excluded have different residues
        pal_in_sup = [KA_IDX[c] for c in PALETTE if KA_IDX[c] % 5 in (0,3)]
        pal_residues = set(x % m for x in pal_in_sup)
        overlap = residues & pal_residues
        if not overlap:
            print(f"    *** DISJOINT from palette mod {m}! ***")

# ═══════════════════════════════════════════════════════════════
# BEAUFORT KEY=N VERIFICATION — IT DOES NOT WORK
# ═══════════════════════════════════════════════════════════════
print()
print("=" * 72)
print("BEAUFORT KEY=N VERIFICATION — CORRECTING EARLIER FINDING")
print("=" * 72)
print()

# The earlier code said "Beaufort key=N: PT={E,H,N,Q,S,T,V} -> palette CT"
# but the verification showed different results. Let me re-verify.
# The KA Vigenere tableau was being used, not AZ Beaufort.
# In the original code Test 1b:
# For Vigenere, CT = E_KA(PT, key) where E_KA(pt, k) = KA[(KA_IDX[pt] + KA_IDX[key]) mod 26]
# For Beaufort (KA), CT = E_KA(pt, k) = KA[(KA_IDX[key] - KA_IDX[pt]) mod 26]

# The finding was from the KA tableau, which maps differently than AZ.
# Let me verify which mapping is being used.

# Beaufort on KA: CT = KA[(KA_IDX[key] - KA_IDX[pt]) mod 26]
key = 'N'
key_ka = KA_IDX[key]  # N = 19
print(f"Key = N, KA index = {key_ka}")
print(f"Beaufort KA: CT = KA[(19 - KA_IDX[PT]) mod 26]")
print()

# For each of 26 PT letters, compute CT
pt_to_ct = {}
ct_to_pt = {}
for pt_val in range(26):
    pt_letter = KA_STR[pt_val]
    ct_ka = (key_ka - pt_val) % 26
    ct_letter = KA_STR[ct_ka]
    pt_to_ct[pt_letter] = ct_letter
    ct_to_pt.setdefault(ct_letter, []).append(pt_letter)

print("Beaufort KA with key N:")
# Which PT letters map to palette?
palette_preimage = []
for c in PALETTE:
    preimage = [pt for pt, ct in pt_to_ct.items() if ct == c]
    palette_preimage.extend(preimage)
    print(f"  palette {c} <- PT {preimage}")

print(f"\nPreimage of palette under Beau(KA, key=N): {sorted(set(palette_preimage))}")
print(f"Count: {len(set(palette_preimage))}")

# Check Vigenere KA with key N
print(f"\nVigenere KA with key N:")
pt_to_ct_vig = {}
for pt_val in range(26):
    pt_letter = KA_STR[pt_val]
    ct_ka = (pt_val + key_ka) % 26
    ct_letter = KA_STR[ct_ka]
    pt_to_ct_vig[pt_letter] = ct_letter

palette_preimage_vig = []
for c in PALETTE:
    preimage = [pt for pt, ct in pt_to_ct_vig.items() if ct == c]
    palette_preimage_vig.extend(preimage)
    print(f"  palette {c} <- PT {preimage}")

print(f"\nPreimage of palette under Vig(KA, key=N): {sorted(set(palette_preimage_vig))}")
print()

# The Test 1b finding was about the KA tableau. Let me trace what it actually found.
# The code said: "Beaufort key=N: PT=['E', 'H', 'N', 'Q', 'S', 'T', 'V'] -> palette CT"
# These PT letters are: {E,H,N,Q,S,T,V}
# Contains SEVEN: S,E,V,E,N -> {E,N,S,V} subset of {E,H,N,Q,S,T,V}? YES
# But does this actually produce palette?

# The original code in Test 1b used THIS logic:
# for variant_name, variant_fn in [
#     ("Vigenere", lambda pt, key: (pt + key) % 26),
#     ("Beaufort", lambda pt, key: (key - pt) % 26),
# ]:
#     for key_val in range(26):
#         pt_producing_pal = []
#         for pt_val in range(26):
#             pt_ka = KA_IDX[AZ[pt_val]]  # Convert AZ letter to KA index
#             key_ka = KA_IDX[key_letter]  # Convert key letter to KA index
#             ct_ka = variant_fn(pt_ka, key_ka)
#             ct_letter = KA_STR[ct_ka]
#             if ct_letter in PALETTE:
#                 pt_producing_pal.append(AZ[pt_val])

# So it iterates over AZ letters as plaintext, converts to KA, operates, converts back.
# Key = N(AZ=13) -> KA_IDX['N'] = 19
# Beaufort: ct_ka = (19 - pt_ka) mod 26
# For pt = E(AZ=4) -> pt_ka = KA_IDX['E'] = 11 -> ct_ka = (19-11)%26 = 8 -> KA[8] = B -> PALETTE!
# For pt = H(AZ=7) -> pt_ka = KA_IDX['H'] = 14 -> ct_ka = (19-14)%26 = 5 -> KA[5] = O -> PALETTE!
# For pt = N(AZ=13) -> pt_ka = KA_IDX['N'] = 19 -> ct_ka = (19-19)%26 = 0 -> KA[0] = K -> PALETTE!
# For pt = Q(AZ=16) -> pt_ka = KA_IDX['Q'] = 20 -> ct_ka = (19-20)%26 = 25 -> KA[25] = Z -> PALETTE!
# For pt = S(AZ=18) -> pt_ka = KA_IDX['S'] = 6 -> ct_ka = (19-6)%26 = 13 -> KA[13] = G -> PALETTE!
# For pt = T(AZ=19) -> pt_ka = KA_IDX['T'] = 4 -> ct_ka = (19-4)%26 = 15 -> KA[15] = I -> PALETTE!
# For pt = V(AZ=21) -> pt_ka = KA_IDX['V'] = 22 -> ct_ka = (19-22)%26 = 23 -> KA[23] = W -> PALETTE!

print("VERIFIED: Beaufort KA with key N maps these 7 AZ-plaintext letters to palette:")
for pt_c in "EHNQSTV":
    pt_ka = KA_IDX[pt_c]
    ct_ka = (19 - pt_ka) % 26
    ct_letter = KA_STR[ct_ka]
    print(f"  PT={pt_c}(AZ={ALPH_IDX[pt_c]},KA={pt_ka}) -> CT={ct_letter}(KA={ct_ka}) {'PALETTE' if ct_letter in PALETTE else ''}")

print(f"\nMapping: E->B, H->O, N->K, Q->Z, S->G, T->I, V->W")
print(f"{{E,H,N,Q,S,T,V}} contains SEVEN: {set('SEVEN').issubset(set('EHNQSTV'))}")
print()

# But how many of the 26 keys produce a set containing a meaningful word?
# This was checked in the followup but the code had no output, meaning
# no key produced a source set containing SEVEN or other target words.
# The issue: the followup checked AZ Beaufort, not KA Beaufort.
# Let me check KA Beaufort for all 26 keys.
print("ALL 26 keys for KA Beaufort -> preimage sets containing meaningful words:")
for key_val in range(26):
    key_letter = KA_STR[key_val]
    # For each AZ plaintext letter, check if KA Beaufort produces a palette letter
    preimage = []
    for pt_az_val in range(26):
        pt_letter = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[pt_az_val]
        pt_ka = KA_IDX[pt_letter]
        ct_ka = (key_val - pt_ka) % 26
        ct_letter = KA_STR[ct_ka]
        if ct_letter in PALETTE:
            preimage.append(pt_letter)

    if len(preimage) == 7:
        preimage_set = set(preimage)
        for word in ["SEVEN", "FIVE", "THREE", "EIGHT", "QUEST", "THESE", "SHEET",
                     "STONE", "TENTH", "EVENT", "HENCE", "SENT", "NEST", "VEST",
                     "NET", "SET", "VET", "TEN"]:
            if set(word).issubset(preimage_set):
                print(f"  Key={key_letter}(KA={key_val}): preimage={sorted(preimage)} contains '{word}'")
                break

# ═══════════════════════════════════════════════════════════════
# THE BEAUFORT BC KEYSTREAM ENRICHMENT — DETAILED
# ═══════════════════════════════════════════════════════════════
print()
print("=" * 72)
print("BEAUFORT BC KEYSTREAM PALETTE ENRICHMENT — DETAILED")
print("=" * 72)
print()

# BC keystream (Beaufort): O,C,G,G,B,G,O,K,T,R,U
# 7/11 are palette (O,G,G,B,G,O,K)
# The NON-palette ones are at positions 64(C), 71(T), 72(R), 73(U)
# = positions 1,8,9,10 within BCL (0-indexed)
# So BCL first 8 positions have keystream 7/8 palette (!), last 3 are all non-palette

print("BCL position-by-position (Beaufort keystream):")
bcl_keys_beau = [14, 2, 6, 6, 1, 6, 14, 10, 19, 17, 20]
for i, k in enumerate(bcl_keys_beau):
    letter = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[k]
    ct = CT97[63+i]
    pt = "BERLINCLOCK"[i]
    in_pal = letter in PALETTE
    print(f"  BCL[{i}]: pos={63+i}, CT={ct}, PT={pt}, key={letter}({k}) {'PALETTE' if in_pal else 'NOT'}")

print(f"\nFirst 8 keys (pos 63-70): {[chr(k+65) for k in bcl_keys_beau[:8]]}")
print(f"  Palette count: {sum(1 for k in bcl_keys_beau[:8] if chr(k+65) in PALETTE)}/8")
print(f"Last 3 keys (pos 71-73): {[chr(k+65) for k in bcl_keys_beau[8:]]}")
print(f"  Palette count: {sum(1 for k in bcl_keys_beau[8:] if chr(k+65) in PALETTE)}/3")

# P(7/8 palette in first 8) is much more significant than 7/11
from math import comb as C
p_binom = sum(C(8, k) * (7/26)**k * (19/26)**(8-k) for k in range(7, 9))
print(f"\nP(>= 7/8 palette at p=7/26): {p_binom:.8f} = 1 in {1/p_binom:.0f}")

# The last 3 (pos 71,72,73) are ALL non-palette. 73 is K(self-encrypting), key=U(20).
# At pos 73: CT=K, PT=K (self-encrypting), so key=(CT+PT)%26 = (10+10)%26 = 20 = U
# U is NOT palette. So the self-encrypting position inherently has a non-palette key.

# At pos 72: CT=C(2), PT=C(2) -> wait, BCL[9]=O? No, BCL = BERLINCLOCK
# BCL[9] = C, CT[72] = A. Key Beau = (CT+PT)%26 = (0+2)%26 = 2 = C? No.
# Beaufort: K = (CT + PT) mod 26. CT[72] = A(0), PT = BCL[9] = C(2).
# Wait, that gives K = (0 + 2) = 2 = C. But the stored key is 17 = R.
# Hmm, let me check. Beaufort: K = (CT - PT) mod 26? No.
# Beaufort: CT = (K - PT) mod 26, so K = (CT + PT) mod 26
# CT[72] = what? Let me check.
print(f"\nVerification of Beaufort keystream at BCL:")
for i, (ct_pos, pt_char) in enumerate(zip(range(63, 74), "BERLINCLOCK")):
    ct_val = ALPH_IDX[CT97[ct_pos]]
    pt_val = ALPH_IDX[pt_char]
    k_beau = (ct_val + pt_val) % 26
    print(f"  pos={ct_pos}: CT={CT97[ct_pos]}({ct_val}), PT={pt_char}({pt_val}), K_beau=(CT+PT)%26={k_beau}={chr(k_beau+65)}")

print()
# Actually this matches the stored values. Good.

# ═══════════════════════════════════════════════════════════════
# FINAL: KA 5x5+1 GRID HYPOTHESIS SUMMARY
# ═══════════════════════════════════════════════════════════════
print("=" * 72)
print("KA 5-WIDE GRID HYPOTHESIS — COMPREHENSIVE SUMMARY")
print("=" * 72)
print()

print("""
The Kryptos Alphabet (KA = KRYPTOSABCDEFGHIJLMNQUVWXZ) arranged in a 5-wide grid:

     col0  col1  col2  col3  col4
row0:  K*    R     Y     P     T
row1:  O*    S     A     B*    C
row2:  D     E     F     G*    H
row3:  I*    J     L     M     N
row4:  Q     U     V     W*    X
row5:  Z*                           (only col 0)

Stars (*) mark palette members. The palette occupies ONLY columns 0 and 3.

STRUCTURAL FINDINGS:
1. KA mod 5 ∈ {0, 3} for ALL 7 palette letters (P = 1/1993)
2. Palette picks from columns 0 and 3 with this alternating pattern:
   - Row 0: col 0 (K), exclude col 3 (P)
   - Row 1: BOTH col 0 (O) AND col 3 (B)
   - Row 2: col 3 (G), exclude col 0 (D)
   - Row 3: col 0 (I), exclude col 3 (M)
   - Row 4: col 3 (W), exclude col 0 (Q)
   - Row 5: col 0 (Z), no col 3 entry
3. Excluded letters {D, M, P, Q} have KA positions {10, 18, 3, 20}
4. The 4 excluded letters follow a zigzag: col3, col0, col3, col0
   (P at row 0 col 3, D at row 2 col 0, M at row 3 col 3, Q at row 4 col 0)

OPEN QUESTIONS:
- Why columns 0 and 3 specifically? (3 = col7/2 - 0.5? Or 3 mod 5 relationship?)
- What determines the row-by-row selection between col 0 and col 3?
- Is this an artifact of the KA alphabet structure or a deliberate design?
- Does the 5-wide grid connect to the Polybius square used elsewhere in Kryptos?

SIGNIFICANCE: P = 0.000502 (1 in 1993) for the mod-5 constraint.
Combined with the overall palette probability P = 0.000024 (1 in 41,667),
the mod-5 finding EXPLAINS much of the palette's low diversity.
If nulls are drawn from KA columns {0,3}, the expected distinct count
from 17 draws is: E[distinct from 11] ≈ 8.8, much closer to 7 than
E[distinct from 26] ≈ 14.0 explains.
""")
