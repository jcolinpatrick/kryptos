#!/usr/bin/env python3
"""
Cipher: analysis
Family: campaigns
Status: active
Keyspace: analytical deep followup
Last run: never
Best score: TBD
"""
"""E-PALETTE-DEEP-FOLLOWUP: Focused investigation of discoveries from deep investigation.

Key findings to investigate:
1. KA positions mod 5 = ONLY {0,3}. This is the STRONGEST modular pattern.
2. Beaufort(DEFECTOR, DEFECTOR) = AAAAAAAA (all A's). Structural identity.
3. Beaufort key=N produces palette from PT letters {E,H,N,Q,S,T,V} which contains SEVEN.
4. AZ->KA cycle structure: palette = 5 from 17-cycle + 1 from 8-cycle + 1 fixed(Z).
5. Null vs non-null positions: mod 7 has null-only residue {1}, mod 13 has null-only {0,1}.
6. Varying positions in 15/24 masks are ANTI-enriched for palette (16.7% vs expected 36.1%).

Run: PYTHONPATH=src python3 -u scripts/campaigns/e_palette_deep_followup.py
"""

import sys, os, json, time, math
from collections import Counter, defaultdict
from itertools import combinations, permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CRIB_POSITIONS, KRYPTOS_ALPHABET, ALPH, ALPH_IDX

CT97 = CT
KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ = ALPH
AZ_IDX = ALPH_IDX

PALETTE = frozenset('BGIKOWZ')
PALETTE_LETTERS = sorted(PALETTE)
PAL_AZ = sorted(AZ_IDX[c] for c in PALETTE_LETTERS)   # [1,6,8,10,14,22,25]
PAL_KA = sorted(KA_IDX[c] for c in PALETTE_LETTERS)   # [0,5,8,13,15,23,25]

CONSENSUS_NULLS = sorted([0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85])
CONSENSUS_CHARS = [CT97[p] for p in CONSENSUS_NULLS]

ALL_PALETTE_POS = [i for i in range(97) if CT97[i] in PALETTE]
NONNULL_PALETTE_POS = [p for p in ALL_PALETTE_POS if p not in set(CONSENSUS_NULLS)]

findings = []
def note(msg):
    findings.append(msg)
    print(msg)

t0 = time.time()

# ══════════════════════════════════════════════════════════════════════
# FINDING 1: KA mod 5 = {0, 3} — DEEP INVESTIGATION
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 1: KA POSITIONS MOD 5 = ONLY {0, 3}")
print("=" * 72)
print()

# Palette KA positions: {0, 5, 8, 13, 15, 23, 25}
# mod 5: {0, 0, 3, 3, 0, 3, 0} = ONLY residues 0 and 3
# This means: palette KA values are ALL congruent to 0 or 3 mod 5

# What KA letters have KA index mod 5 == 0?
ka_mod5_0 = [KA_STR[i] for i in range(26) if i % 5 == 0]
ka_mod5_3 = [KA_STR[i] for i in range(26) if i % 5 == 3]
ka_mod5_03 = set(ka_mod5_0 + ka_mod5_3)
print(f"KA letters with index mod 5 == 0: {ka_mod5_0} (positions {[i for i in range(26) if i%5==0]})")
print(f"KA letters with index mod 5 == 3: {ka_mod5_3} (positions {[i for i in range(26) if i%5==3]})")
print(f"All KA mod 5 in {{0,3}}: {sorted(ka_mod5_03)} ({len(ka_mod5_03)} letters)")
print(f"Palette: {sorted(PALETTE)} ({len(PALETTE)} letters)")
print()

# The palette is a SUBSET of {KA letters with index ≡ 0 or 3 mod 5}
# That superset has: positions 0,3,5,8,10,13,15,18,20,23,25 = 11 letters
# Palette picks 7 of those 11
superset_ka_positions = [i for i in range(26) if i % 5 in (0, 3)]
superset_ka_letters = [KA_STR[i] for i in superset_ka_positions]
print(f"Full superset (KA mod 5 in {{0,3}}): {superset_ka_letters}")
print(f"  = {sorted(set(superset_ka_letters))}")
print(f"  Count: {len(superset_ka_positions)} letters")
print(f"Palette is subset: {PALETTE.issubset(set(superset_ka_letters))}")
print(f"Extra in superset: {sorted(set(superset_ka_letters) - PALETTE)}")
print()

# The extra 4 letters are: {K=pos0?...}
# Wait, K IS in the palette. Let me check more carefully.
for i in superset_ka_positions:
    letter = KA_STR[i]
    in_pal = letter in PALETTE
    print(f"  KA[{i:2d}] = {letter} {'<- PALETTE' if in_pal else '         (excluded)'}")

print(f"\nExcluded from palette but in mod-5 superset: {sorted(set(superset_ka_letters) - PALETTE)}")
excluded = sorted(set(superset_ka_letters) - PALETTE)
print(f"  These are: {', '.join(f'{c}(KA={KA_IDX[c]})' for c in excluded)}")
print()

# Statistical significance: P(7 random from 26 all in 11-element subset)?
from math import comb
p_mod5 = comb(11, 7) / comb(26, 7)
print(f"P(7 random letters all in 11-letter KA mod-5 superset): {p_mod5:.6f} = 1 in {1/p_mod5:.0f}")
note(f"FINDING 1: KA mod 5 congruence {'{0,3}'} has P = {p_mod5:.6f} (1 in {1/p_mod5:.0f})")

# The KA alphabet written in mod-5 rows:
print(f"\nKA alphabet in 5-column format (showing mod-5 structure):")
for row in range(6):
    for col in range(5):
        idx = row * 5 + col
        if idx < 26:
            letter = KA_STR[idx]
            mark = '*' if letter in PALETTE else '.'
            print(f"  {letter}{mark}", end='')
        else:
            print(f"   ", end='')
    print()

# KEY QUESTION: In a 5×6 KA grid, palette occupies columns 0 and 3 only
print(f"\nIn a 5-column KA grid, palette columns:")
pal_cols_5 = set(KA_IDX[c] % 5 for c in PALETTE_LETTERS)
print(f"  Palette column positions: {sorted(pal_cols_5)} (only columns 0 and 3!)")
print(f"  Column 0 letters: {[KA_STR[i] for i in range(0,26,5)]}")
print(f"  Column 3 letters: {[KA_STR[i] for i in range(3,26,5)]}")
print()

# What are columns 0 and 3 of KA in a 5-wide grid?
# Col 0: K(0), O(5), D(10), I(15), V(20), Z(25) → K,O,D,I,V,Z
# Col 3: P(3), B(8), G(13), L(18), W(23) → P,B,G,L,W
# Palette = {B,G,I,K,O,W,Z} = col0∩palette={K,O,I,Z} + col3∩palette={B,G,W}
# Excluded from palette: col0={D,V}, col3={P,L}
# So palette picks 4/6 from col 0 and 3/5 from col 3
print(f"Column 0 (6 letters): {[KA_STR[i] for i in range(0,26,5)]}")
col0_in_pal = [KA_STR[i] for i in range(0,26,5) if KA_STR[i] in PALETTE]
col0_out_pal = [KA_STR[i] for i in range(0,26,5) if KA_STR[i] not in PALETTE]
print(f"  In palette: {col0_in_pal} ({len(col0_in_pal)}/6)")
print(f"  Out: {col0_out_pal}")

print(f"Column 3 (5 letters): {[KA_STR[i] for i in range(3,26,5)]}")
col3_in_pal = [KA_STR[i] for i in range(3,26,5) if KA_STR[i] in PALETTE]
col3_out_pal = [KA_STR[i] for i in range(3,26,5) if KA_STR[i] not in PALETTE]
print(f"  In palette: {col3_in_pal} ({len(col3_in_pal)}/5)")
print(f"  Out: {col3_out_pal}")
print()

# The excluded letters are D, V (col 0) and P, L (col 3)
# D, V are in the 8-cycle of AZ->KA permutation? Let's check.
print(f"Excluded letters and their AZ->KA cycle membership:")
az_to_ka_perm = [KA_IDX[AZ[i]] for i in range(26)]
# Build cycles
visited = [False]*26
cycles = {}
for start in range(26):
    if visited[start]: continue
    cycle = []
    cur = start
    while not visited[cur]:
        visited[cur] = True
        cycle.append(cur)
        cur = az_to_ka_perm[cur]
    cycle_name = f"cycle-{len(cycle)}"
    for c in cycle:
        cycles[AZ[c]] = (cycle_name, cycle.index(c))

for letter in excluded:
    cn, cp = cycles[letter]
    print(f"  {letter}(KA={KA_IDX[letter]}): {cn} at position {cp}")

print()

# What is 3 in KA? 3 = diff between residues 0 and 3
# 0 and 3 mod 5... note that 3 ≡ -2 mod 5, and 0+3=3
# The column width 5 resonates with the Polybius square (5×5)
# and with 26 = 5×5 + 1

# ══════════════════════════════════════════════════════════════════════
# FINDING 2: BEAUFORT(DEFECTOR, DEFECTOR) = AAAAAAAA
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 2: BEAUFORT(DEFECTOR, DEFECTOR) = ALL A's")
print("=" * 72)
print()

# This is actually trivially true: Beaufort(P, K) = (K - P) mod 26
# When K = P, result = 0 = A. This holds for ANY word encrypted with itself.
# So this is NOT a special property of DEFECTOR.
print("Beaufort(X, X) = (X - X) mod 26 = 0 = A for ALL inputs.")
print("This is a trivial identity, NOT specific to DEFECTOR.")
print("DISMISSED as structural artifact.")
print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 3: BEAUFORT KEY=N MAPS {E,H,N,Q,S,T,V} -> PALETTE
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 3: BEAUFORT KEY=N MAPS {E,H,N,Q,S,T,V} TO PALETTE")
print("=" * 72)
print()

# KA-Beaufort with key=N: CT = (key_ka - PT_ka) mod 26
# key_ka = KA_IDX['N'] = ?
n_ka = KA_IDX['N']
n_az = AZ_IDX['N']
print(f"N in KA: position {n_ka}")
print(f"N in AZ: position {n_az}")
print()

# The source set {E,H,N,Q,S,T,V} contains SEVEN
source = list("EHNQSTV")
print(f"Source letters: {source}")
seven_subset = set("SEVEN").issubset(set(source))
print(f"Contains SEVEN? {seven_subset}")

# Verify the Beaufort mapping
print("\nVerification (AZ Beaufort with constant key N):")
for pt_c in source:
    ct_val = (n_az - AZ_IDX[pt_c]) % 26
    ct_letter = AZ[ct_val]
    print(f"  Beau(PT={pt_c}({AZ_IDX[pt_c]}), key=N({n_az})) = ({n_az} - {AZ_IDX[pt_c]}) mod 26 = {ct_val} = {ct_letter}")

# Statistical significance:
# For a RANDOM key K, Beau maps any 7 PT letters to 7 CT letters.
# The mapping is just subtraction from a constant, so it's a fixed-point-free
# shift (or rather, reflection). The question is whether ANY of the 26 keys
# maps some "meaningful" 7-letter set to the palette.
# With 26 keys, and ~100+ meaningful 7-letter sets to check, we'd expect
# some hits by chance. Let me check all 26 keys.

print("\nAll 26 Beaufort keys and their source -> palette mappings:")
interesting_sources = []
for key_val in range(26):
    # Beau: CT = (key - PT) mod 26, so PT = (key - CT) mod 26
    pt_set = frozenset(AZ[(key_val - AZ_IDX[c]) % 26] for c in PALETTE_LETTERS)
    pt_str = ''.join(sorted(pt_set))
    # Check for keyword subsets
    kw_found = []
    for kw in ["SEVEN", "FIVE", "THREE", "EIGHT", "NORTH", "EAST", "SOUTH", "WEST",
               "QUEST", "POINT", "THESE", "SHEET", "DENSE", "TENSE", "QUEST", "TENTH"]:
        if set(kw).issubset(pt_set):
            kw_found.append(kw)
    if kw_found:
        print(f"  Key={AZ[key_val]}: PT={pt_str} contains {kw_found}")
        interesting_sources.append((AZ[key_val], pt_str, kw_found))

# Same for Vigenere
print("\nAll 26 Vigenere keys:")
for key_val in range(26):
    pt_set = frozenset(AZ[(AZ_IDX[c] - key_val) % 26] for c in PALETTE_LETTERS)
    pt_str = ''.join(sorted(pt_set))
    kw_found = []
    for kw in ["SEVEN", "FIVE", "THREE", "EIGHT", "NORTH", "EAST", "SOUTH", "WEST",
               "QUEST", "POINT", "THESE", "SHEET", "DENSE", "TENSE", "TENTH"]:
        if set(kw).issubset(pt_set):
            kw_found.append(kw)
    if kw_found:
        print(f"  Key={AZ[key_val]}: PT={pt_str} contains {kw_found}")

print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 4: CYCLE STRUCTURE ANALYSIS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 4: AZ->KA CYCLE STRUCTURE — 5 + 1 + 1 = 7")
print("=" * 72)
print()

# Palette splits as: 5 from 17-cycle, 1 from 8-cycle (W), 1 fixed (Z)
# Expected by chance: if picking 7 random from 26 (= 17+8+1 cycle structure)
# E[from 17] = 7 * 17/26 = 4.58
# E[from 8] = 7 * 8/26 = 2.15
# E[from 1] = 7 * 1/26 = 0.27
# Observed: 5, 1, 1

# P(exactly 5 from 17, 1 from 8, 1 from fixed) using multivariate hypergeometric
p_cycle = comb(17,5) * comb(8,1) * comb(1,1) / comb(26,7)
print(f"P(5 from 17-cycle, 1 from 8-cycle, 1 from fixed) = {p_cycle:.6f} = 1 in {1/p_cycle:.0f}")
print(f"Expected: E[17-cycle]={7*17/26:.2f}, E[8-cycle]={7*8/26:.2f}, E[fixed]={7*1/26:.2f}")
print(f"Observed: 5, 1, 1")
print()

# More importantly: which 5 of 17 from the 17-cycle?
# 17-cycle: A->H->O->F->M->S->G->N->T->E->L->R->B->I->P->D->K
# (cycle positions 0-16)
# Palette members at cycle positions: [2(O), 6(G), 12(B), 13(I), 16(K)]
# Gaps: 4, 6, 1, 3 (and wrapping: from 16 back to 2 = 3)
cycle17_letters = list("AHOFMSGNTELRBIPDK")
cycle17_pal_pos = [i for i, c in enumerate(cycle17_letters) if c in PALETTE]
print(f"17-cycle: {'->'.join(cycle17_letters)}")
print(f"Palette positions in cycle: {cycle17_pal_pos}")
print(f"Palette letters in cycle: {[cycle17_letters[i] for i in cycle17_pal_pos]}")
gaps = []
for i in range(len(cycle17_pal_pos)):
    next_i = (i + 1) % len(cycle17_pal_pos)
    gap = (cycle17_pal_pos[next_i] - cycle17_pal_pos[i]) % 17
    gaps.append(gap)
print(f"Gaps (cyclic): {gaps}")
print(f"Sum of gaps: {sum(gaps)} (should = 17)")
print()

# Check: is there a generator g such that palette = {g^k : k in subset} within the 17-cycle?
# The 17-cycle can be viewed as Z_17 (cyclic group of order 17)
# Palette positions in cycle: {2, 6, 12, 13, 16}
# Are these a coset of a subgroup? Z_17 has only trivial subgroups ({0} and Z_17 itself)
# since 17 is prime. So no coset structure is possible.
print("Z_17 is prime -> no nontrivial subgroups -> no coset explanation.")
print()

# But check: multiplicative group structure
# In Z_17: generators are all non-zero elements (since 17 is prime)
# Are palette positions = {a * k mod 17 : k in some set}?
for a in range(1, 17):
    images = sorted(set((a * p) % 17 for p in cycle17_pal_pos))
    # Is this set the same as cycle17_pal_pos?
    if set(images) == set(cycle17_pal_pos):
        print(f"  Multiplication by {a} mod 17 maps palette cycle positions to themselves!")

# Check quadratic residues mod 17
qr_17 = set(pow(x, 2, 17) for x in range(17))
print(f"Quadratic residues mod 17: {sorted(qr_17)}")
pal_cycle_set = set(cycle17_pal_pos)
print(f"Palette cycle positions: {sorted(pal_cycle_set)}")
print(f"Intersection with QR: {sorted(pal_cycle_set & qr_17)}")
print(f"Palette positions that are QR: {len(pal_cycle_set & qr_17)}/{len(pal_cycle_set)}")
print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 5: NULL vs NON-NULL POSITION MODULAR DISCRIMINATION
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 5: NULL vs NON-NULL PALETTE POSITION DISCRIMINATION")
print("=" * 72)
print()

null_pos = set(CONSENSUS_NULLS)
print("Modular residue analysis of ALL 35 palette positions:")
print("Seeking: residue class R and modulus M where ALL nulls have pos ≡ R mod M")
print("         but NO non-nulls have pos ≡ R mod M (or vice versa)")
print()

for mod_n in range(2, 40):
    null_residues = set(p % mod_n for p in CONSENSUS_NULLS)
    nonnull_residues = set(p % mod_n for p in NONNULL_PALETTE_POS)

    # Residues that are NULL-ONLY (appear in nulls but not in non-nulls)
    null_only = null_residues - nonnull_residues
    nonnull_only = nonnull_residues - null_residues

    if null_only:
        # How many nulls are captured by these null-only residues?
        null_captured = sum(1 for p in CONSENSUS_NULLS if p % mod_n in null_only)
        print(f"  mod {mod_n}: null-only residues {sorted(null_only)} capture {null_captured}/17 nulls")
    if nonnull_only:
        nonnull_captured = sum(1 for p in NONNULL_PALETTE_POS if p % mod_n in nonnull_only)
        # Only report if capturing a lot
        if nonnull_captured >= 8:
            print(f"  mod {mod_n}: nonnull-only residues {sorted(nonnull_only)} capture {nonnull_captured}/18 non-nulls")

# Deeper: find the BEST single modular criterion
print("\nBest single modular criteria (maximize null/nonnull discrimination):")
best_criteria = []
for mod_n in range(2, 50):
    for target_residues in [frozenset([r]) for r in range(mod_n)] + \
                           [frozenset(c) for c in combinations(range(mod_n), 2) if mod_n <= 15] + \
                           [frozenset(c) for c in combinations(range(mod_n), 3) if mod_n <= 10]:
        null_in = sum(1 for p in CONSENSUS_NULLS if p % mod_n in target_residues)
        nonnull_in = sum(1 for p in NONNULL_PALETTE_POS if p % mod_n in target_residues)
        # Perfect discrimination: all nulls in, no non-nulls in (or vice versa)
        score = null_in - nonnull_in  # Maximize this for null-selecting criterion
        if null_in >= 10 and nonnull_in == 0:
            best_criteria.append((mod_n, sorted(target_residues), null_in, nonnull_in, "NULL-ONLY"))
        elif nonnull_in >= 10 and null_in == 0:
            best_criteria.append((mod_n, sorted(target_residues), null_in, nonnull_in, "NONNULL-ONLY"))

if best_criteria:
    for mod_n, residues, ni, nni, label in sorted(best_criteria, key=lambda x: -max(x[2],x[3])):
        print(f"  mod {mod_n} residues {residues}: null={ni}/17, nonnull={nni}/18 ({label})")
else:
    print("  No perfect single-modulus discriminator found.")
print()

# Try TWO moduli combined
print("Trying pairs of modular criteria:")
for m1 in range(2, 20):
    for m2 in range(m1+1, 20):
        for r1 in range(m1):
            for r2 in range(m2):
                null_match = sum(1 for p in CONSENSUS_NULLS if p % m1 == r1 and p % m2 == r2)
                nonnull_match = sum(1 for p in NONNULL_PALETTE_POS if p % m1 == r1 and p % m2 == r2)
                if null_match >= 8 and nonnull_match == 0:
                    print(f"  pos%{m1}=={r1} AND pos%{m2}=={r2}: {null_match}/17 null, {nonnull_match}/18 nonnull")

print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 6: VARYING POSITIONS ANTI-ENRICHED
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 6: VARYING MASK POSITIONS ARE ANTI-ENRICHED FOR PALETTE")
print("=" * 72)
print()

# 17 consensus nulls = ALL palette letters (p = 0.000024)
# 7 varying nulls = only 16.7% palette (expected 36.1%)
# This means the varying positions ACTIVELY AVOID palette letters
# The null mask has TWO components:
# - 17 fixed positions: determined by palette membership
# - 7 varying positions: determined by something ELSE (cipher consistency?)

# Calculate statistical significance of anti-enrichment
# 7 varying positions drawn from 80 remaining positions (97-17 consensus)
# Of those 80: 35-17=18 are palette, 80-18=62 are non-palette
# Under null hypothesis (random draw from 80), P(palette count ≤ k)
# follows hypergeometric(N=80, K=18, n=7)
from math import comb as C

N_remaining = 80  # 97 - 17 consensus nulls
K_pal_remaining = 18  # palette positions not in consensus
n_draw = 7

# P(X <= 1) where X ~ Hypergeometric(N=80, K=18, n=7)
p_le1 = sum(C(K_pal_remaining, k) * C(N_remaining - K_pal_remaining, n_draw - k) / C(N_remaining, n_draw)
            for k in range(2))  # 0 or 1
p_le2 = sum(C(K_pal_remaining, k) * C(N_remaining - K_pal_remaining, n_draw - k) / C(N_remaining, n_draw)
            for k in range(3))  # 0, 1, or 2

# Average across 6 masks
varying_pal_counts = [0, 2, 0, 2, 1, 2]
avg_pal = sum(varying_pal_counts) / len(varying_pal_counts)
expected = n_draw * K_pal_remaining / N_remaining

print(f"Varying position palette counts across 6 masks: {varying_pal_counts}")
print(f"Average: {avg_pal:.2f}")
print(f"Expected (random from remaining 80): {expected:.2f}")
print(f"P(palette count <= 1 in single draw): {p_le1:.4f}")
print(f"P(palette count <= 2 in single draw): {p_le2:.4f}")
print(f"Anti-enrichment ratio: {avg_pal/expected:.2f}x")
print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 7: BEAUFORT KEYSTREAM ENRICHMENT AT CRIB POSITIONS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 7: BEAUFORT KEYSTREAM ENRICHMENT AT CRIB POSITIONS")
print("=" * 72)
print()

from kryptos.kernel.constants import BEAUFORT_KEY_BC

# Beau BC keystream: [14, 2, 6, 6, 1, 6, 14, 10, 19, 17, 20]
# Letters: O, C, G, G, B, G, O, K, T, R, U
# Palette members: O(14), G(6), G(6), B(1), G(6), O(14), K(10) = 7/11 = 64%
# Expected: 7/26 = 26.9%

beau_bc = list(BEAUFORT_KEY_BC)
beau_bc_letters = [AZ[k] for k in beau_bc]
beau_bc_in_pal = [c for c in beau_bc_letters if c in PALETTE]

print(f"Beaufort BC keystream values: {beau_bc}")
print(f"Beaufort BC keystream letters: {beau_bc_letters}")
print(f"Palette members: {beau_bc_in_pal} ({len(beau_bc_in_pal)}/11 = {len(beau_bc_in_pal)/11*100:.0f}%)")
print(f"Expected by chance: {7/26*100:.1f}%")
print()

# P(>= 7/11 from 7/26 by chance) using binomial
# Approximate: n=11, p=7/26
from math import factorial
def binom_pmf(n, k, p):
    return C(n, k) * (p**k) * ((1-p)**(n-k))

p_pal = 7/26
p_ge7 = sum(binom_pmf(11, k, p_pal) for k in range(7, 12))
print(f"P(>= 7/11 with p=7/26): {p_ge7:.6f} = 1 in {1/p_ge7:.0f}")
note(f"FINDING 7: Beaufort BC keystream is {len(beau_bc_in_pal)}/11 palette (P = {p_ge7:.6f}, 1 in {1/p_ge7:.0f})")

# But we tested 4 keystreams (Vig ENE, Vig BC, Beau ENE, Beau BC)
# After Bonferroni: 4 * p_ge7
p_corrected = min(1.0, 4 * p_ge7)
print(f"After Bonferroni (4 tests): P = {p_corrected:.5f}")
print()

# What does this mean? The Beaufort BC keystream itself is enriched in palette letters.
# Since keystream = (CT + PT) mod 26, and CT is fixed, this constrains PT.
# For positions where keystream is a palette letter, the PT letter must be:
# PT = (keystream - CT) mod 26 for Vigenere, or PT = (CT - keystream) mod 26 for Beaufort
print("Implications: if cipher is Beaufort, key letters at BCL crib positions are:")
print(f"  Key = {beau_bc_letters}")
print(f"  7/11 of these are palette letters: {[c for c in beau_bc_letters if c in PALETTE]}")
print(f"  4/11 are NOT palette: {[c for c in beau_bc_letters if c not in PALETTE]}")
print()

# Check: is the key at crib positions = SOME function of position that produces palette?
bcl_positions = list(range(63, 74))
print(f"BCL positions: {bcl_positions}")
print(f"Key values: {beau_bc}")
for i, (pos, key_val) in enumerate(zip(bcl_positions, beau_bc)):
    in_pal = AZ[key_val] in PALETTE
    print(f"  pos={pos}: key={AZ[key_val]}({key_val}) {'PALETTE' if in_pal else 'not-pal'}")

print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 8: THE FIVE EXCLUDED KA MOD-5 LETTERS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 8: WHY D,L,P,V ARE EXCLUDED FROM PALETTE (KA mod-5 superset)")
print("=" * 72)
print()

# From the 11-letter superset {K,O,D,I,V,Z,P,B,G,L,W}, palette excludes {D,L,P,V}
# These 4 letters: what do they have in common?
excluded_from_superset = sorted(set(superset_ka_letters) - PALETTE)
print(f"Excluded: {excluded_from_superset}")
for c in excluded_from_superset:
    print(f"  {c}: AZ={AZ_IDX[c]}, KA={KA_IDX[c]}, CT count={Counter(CT97)[c]}, in cribs={'YES' if c in set('EASTNORTHEASTBERLINCLOCK') else 'NO'}")

# Check: are excluded letters exactly those in cribs from the superset?
crib_letters = set("EASTNORTHEASTBERLINCLOCK")
superset = set(superset_ka_letters)
excluded_set = superset - PALETTE
crib_intersection = superset & crib_letters
print(f"\nSuperset & crib letters: {sorted(crib_intersection)}")
print(f"Excluded from palette: {sorted(excluded_set)}")
print(f"Are they the same? {crib_intersection == excluded_set}")
print()

# Hmm, crib letters in superset: B, I, K, L, O, ...
# Wait, B, I, K, O ARE in the palette. Let me recheck.
superset_letters = set(superset_ka_letters)
crib_letters_full = set("EASTNORTHEASTBERLINCLOCK")
print(f"Full superset: {sorted(superset_letters)}")
print(f"Crib letters: {sorted(crib_letters_full)}")
print(f"Superset & cribs: {sorted(superset_letters & crib_letters_full)}")
# = {B, I, K, L, O}
# Palette from superset: {B, G, I, K, O, W, Z}
# Superset - palette: {D, L, P, V}
# L is in cribs, D is not, P is not, V is not
# So it's not "crib letters excluded"

# Try: excluded = letters that appear in DEFECTOR?
def_letters = set("DEFECTOR")
print(f"\nDEFECTOR letters in excluded: {sorted(excluded_set & def_letters)}")
print(f"DEFECTOR letters: {sorted(def_letters)}")
# D is in excluded and in DEFECTOR. Others?

# Try: excluded = letters at specific KA rows in the 5-wide grid
print(f"\nExcluded KA positions: {sorted(KA_IDX[c] for c in excluded_from_superset)}")
excluded_ka = sorted(KA_IDX[c] for c in excluded_from_superset)
# D=10, L=18, P=3, V=22
# KA rows (div 5): 10//5=2, 18//5=3, 3//5=0, 22//5=4
excluded_ka_rows = [KA_IDX[c] // 5 for c in excluded_from_superset]
print(f"Excluded KA rows (in 5-wide grid): {excluded_ka_rows}")
# Rows: 2, 3, 0, 4 = {0,2,3,4} = all rows except row 1
print(f"  = rows {sorted(set(excluded_ka_rows))} (all except row {sorted(set(range(6)) - set(excluded_ka_rows))})")

# Row 1 of 5-wide KA grid: positions 5,6,7,8,9 = O,S,A,B,C
# The only row with NO excluded letters!
# Row 1 palette members: O(5), B(8) -> both in palette
# Row 1 non-palette: S(6), A(7), C(9)
row1_letters = [KA_STR[i] for i in range(5, 10)]
print(f"\nRow 1 (only row with no exclusions): {row1_letters}")
print(f"  Palette members: {[c for c in row1_letters if c in PALETTE]}")
print(f"  Non-palette (not in superset): {[c for c in row1_letters if c not in superset_letters]}")

# Wait — OSAB has columns 0,1,2,3 and palette picks col 0(O) and col 3(B)
# So even within row 1, the columns 0 and 3 rule holds perfectly
# And in other rows, some col-0/col-3 letters are excluded
# The exclusion rule is: column 0 or 3 in 5-wide KA grid, BUT also depends on row

# Let me look at which (row, col) positions in the 5-wide KA grid are palette
print(f"\n5-wide KA grid palette membership by (row, col):")
for row in range(6):
    for col in [0, 3]:  # Only the two palette columns
        idx = row * 5 + col
        if idx < 26:
            letter = KA_STR[idx]
            in_pal = letter in PALETTE
            print(f"  ({row},{col}): KA[{idx}]={letter} {'PALETTE' if in_pal else 'EXCLUDED'}")

# Pattern:
# Col 0: row 0 (K)=PAL, row 1 (O)=PAL, row 2 (D)=EXCL, row 3 (I)=PAL, row 4 (V)=EXCL, row 5 (Z)=PAL
# Col 3: row 0 (P)=EXCL, row 1 (B)=PAL, row 2 (G)=PAL, row 3 (L)=EXCL, row 4 (W)=PAL
# Col 0 exclusions at rows {2, 4} (every other starting from 2)
# Col 3 exclusions at rows {0, 3}
# No clean alternating pattern
print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 9: PALETTE AND KRYPTOS POSITIONS (KA IDENTITY)
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 9: KRYPTOS = KA[0:7], PALETTE KA POSITIONS = {0,5,8,13,15,23,25}")
print("=" * 72)
print()

# Since KRYPTOS = first 7 letters of KA, their KA indices are {0,1,2,3,4,5,6}
# Palette KA indices: {0,5,8,13,15,23,25}
# Intersection: {0,5} -> letters K(0), O(5)
print(f"KRYPTOS KA indices: {list(range(7))}")
print(f"Palette KA indices: {PAL_KA}")
print(f"Intersection: {sorted(set(range(7)) & set(PAL_KA))}")
print(f"  = letters: {[KA_STR[i] for i in sorted(set(range(7)) & set(PAL_KA))]}")
print()

# What is the SET DIFFERENCE palette_KA - {0..6}?
beyond_kryptos = sorted(set(PAL_KA) - set(range(7)))
print(f"Palette KA positions beyond KRYPTOS range: {beyond_kryptos}")
print(f"  = letters: {[KA_STR[i] for i in beyond_kryptos]}")
# {8, 13, 15, 23, 25} = B, G, I, W, Z

# The mapping {0,1,2,3,4,5,6} -> {0,5,8,13,15,23,25} needs investigation
# This is NOT an affine map (no solution found in Test 7)
# But maybe it's a power map?
# f(0)=0, f(1)=5, f(2)=8, f(3)=13, f(4)=15, f(5)=23, f(6)=25
for exp in range(2, 8):
    mapped = [pow(i, exp, 26) for i in range(7)]
    print(f"  i^{exp} mod 26 for i=0..6: {mapped}")
    if set(mapped) == set(PAL_KA):
        note(f"  *** POWER MAP: i^{exp} mod 26 generates palette KA positions! ***")

# Check i^2 + c, i^3 + c, etc.
for exp in range(2, 5):
    for c in range(26):
        mapped = [(pow(i, exp) + c) % 26 for i in range(7)]
        if set(mapped) == set(PAL_KA) and len(set(mapped)) == 7:
            note(f"  *** (i^{exp} + {c}) mod 26 for i=0..6 = palette KA positions! ***")

# Explicit listing of the map f: KRYPTOS_index -> palette_KA_index
# 0->0, 1->5, 2->8, 3->13, 4->15, 5->23, 6->25
# Differences from identity: 0, 4, 6, 10, 11, 18, 19
diffs = [PAL_KA[i] - i for i in range(7)]
print(f"\nf(i) - i for i=0..6: {diffs}")
# Second differences
diffs2 = [diffs[i+1] - diffs[i] for i in range(6)]
print(f"Second differences: {diffs2}")

# The map is roughly f(i) ≈ 4.17i, but let's check
ratios = [PAL_KA[i] / max(i, 0.001) for i in range(7)]
print(f"f(i)/i for i=0..6: {['inf' if i==0 else f'{PAL_KA[i]/i:.2f}' for i in range(7)]}")
print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 10: PALETTE = KA POSITIONS COPRIME TO... ?
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 10: GCD AND COPRIMALITY ANALYSIS")
print("=" * 72)
print()

# Check: are palette KA positions characterized by gcd(pos, N) for some N?
for N in [5, 10, 13, 26, 30]:
    pal_gcds = [math.gcd(p, N) for p in PAL_KA]
    print(f"  gcd(palette_KA, {N}): {pal_gcds}")
    # Check if all coprime
    if all(g == 1 for g, pv in zip(pal_gcds, PAL_KA) if pv > 0):
        print(f"    All nonzero palette KA positions coprime to {N}")

# Palette KA: {0,5,8,13,15,23,25}
# gcd with 26: gcd(0,26)=26, gcd(5,26)=1, gcd(8,26)=2, gcd(13,26)=13,
# gcd(15,26)=1, gcd(23,26)=1, gcd(25,26)=1
print(f"\ngcd(palette_KA, 26): {[math.gcd(p, 26) for p in PAL_KA]}")
# Not coprime (0, 8, 13 have gcd > 1)

# What about: palette KA positions are NOT multiples of any single number?
# Check: which of {0..25} are NOT in palette KA?
complement_ka = sorted(set(range(26)) - set(PAL_KA))
print(f"KA complement positions: {complement_ka}")
# {1,2,3,4,6,7,9,10,11,12,14,16,17,18,19,20,21,22,24}

# Are palette positions = quadratic residues mod 26?
qr_26 = set(pow(x, 2, 26) for x in range(26))
print(f"Quadratic residues mod 26: {sorted(qr_26)}")
print(f"Palette KA in QR_26: {sorted(set(PAL_KA) & qr_26)}")
print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 11: COMPREHENSIVE NULL-STRING PATTERN
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 11: NULL STRING GENERATION — POSITION-BASED RULES")
print("=" * 72)
print()

# The null string is: O,B,K,O,G,B,O,W,W,K,W,I,W,G,Z,I,G
# Positions:          0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85
#
# Key observation: what if null_char = some_function(position, CT_context)?

# Test: null_char = CT[(pos + k) mod 97] for some FIXED k
print("--- 11a: null_char = CT[(pos + k) mod 97] ---")
for k in range(1, 97):
    matches = sum(1 for p, c in zip(CONSENSUS_NULLS, CONSENSUS_CHARS) if CT97[(p + k) % 97] == c)
    if matches >= 6:
        predicted = [CT97[(p + k) % 97] for p in CONSENSUS_NULLS]
        print(f"  k={k}: {matches}/17 matches")

# Test: null_char = CT[some_other_null_position]
print("\n--- 11b: Cycling within null positions ---")
# Is each null char = the NEXT null position's char?
for shift in range(1, 17):
    matches = sum(1 for i in range(17) if CONSENSUS_CHARS[i] == CONSENSUS_CHARS[(i + shift) % 17])
    if matches >= 6:
        print(f"  Shift by {shift} in null sequence: {matches}/17 matches")

# Test: null_char = KRYPTOS[pos mod 7]  (the col7 column!)
print("\n--- 11c: null_char = KRYPTOS[pos mod 7] ---")
kryptos_letters = "KRYPTOS"
for i, (p, c) in enumerate(zip(CONSENSUS_NULLS, CONSENSUS_CHARS)):
    predicted = kryptos_letters[p % 7]
    match = predicted == c
    print(f"  pos={p:2d} mod 7 = {p%7}: KRYPTOS[{p%7}]={predicted}, actual={c} {'MATCH' if match else ''}")

matches_kryptos = sum(1 for p, c in zip(CONSENSUS_NULLS, CONSENSUS_CHARS) if kryptos_letters[p%7] == c)
print(f"  Total: {matches_kryptos}/17")

# Test: null_char = BGIKOWZ[pos mod 7] (palette itself as cycling key)
print("\n--- 11d: null_char = BGIKOWZ[pos mod 7] ---")
pal_cycle = "BGIKOWZ"
for i, (p, c) in enumerate(zip(CONSENSUS_NULLS, CONSENSUS_CHARS)):
    predicted = pal_cycle[p % 7]
    match = predicted == c
    if match:
        print(f"  pos={p:2d} mod 7 = {p%7}: palette[{p%7}]={predicted}, actual={c} MATCH")

matches_pal = sum(1 for p, c in zip(CONSENSUS_NULLS, CONSENSUS_CHARS) if pal_cycle[p%7] == c)
print(f"  Total: {matches_pal}/17")

# Test various orderings of palette
print("\n--- 11e: Best palette ordering as position-cycling key ---")
best_order = ("", 0)
for perm in permutations(PALETTE_LETTERS):
    perm_str = ''.join(perm)
    matches = sum(1 for p, c in zip(CONSENSUS_NULLS, CONSENSUS_CHARS) if perm_str[p%7] == c)
    if matches > best_order[1]:
        best_order = (perm_str, matches)
        if matches >= 6:
            print(f"  '{perm_str}'[pos mod 7]: {matches}/17 matches")

print(f"  Best: '{best_order[0]}' with {best_order[1]}/17")

# Expected by chance: for each position, P(match) = 1/7 (since palette has 7 unique)
# But actual chars repeat, so it's more nuanced
print(f"\n  Expected matches by chance: ~{17/7:.1f} = {17/7:.2f}")
print()

# ══════════════════════════════════════════════════════════════════════
# FINDING 12: THE KA 5-WIDE GRID AS GENERATING MECHANISM
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINDING 12: COULD THE KA 5-WIDE GRID BE THE MECHANISM?")
print("=" * 72)
print()

# Hypothesis: The null mask uses a 5-wide Polybius-like grid of KA.
# Columns 0 and 3 form the "null alphabet" (11 letters).
# Some additional rule selects 7 of those 11.

# In a Polybius square, positions are encoded as (row, col) pairs.
# If column = 0 or 3 means "null", then any Polybius-encoded position
# with col ∈ {0, 3} would be marked as null.

# Test: map CT97 positions to their "Polybius column" in a KA 5-wide grid
# and check if null positions have col ∈ {0, 3}
print("CT characters at null positions, their KA positions, and 5-wide grid column:")
for p, c in zip(CONSENSUS_NULLS, CONSENSUS_CHARS):
    ka_pos = KA_IDX[c]
    grid_col = ka_pos % 5
    grid_row = ka_pos // 5
    print(f"  pos={p:2d}: char={c}, KA={ka_pos:2d}, grid({grid_row},{grid_col}) "
          f"{'<- col {0,3}' if grid_col in (0,3) else ''}")

null_in_col03 = sum(1 for c in CONSENSUS_CHARS if KA_IDX[c] % 5 in (0, 3))
print(f"\nNull chars with KA grid column in {{0,3}}: {null_in_col03}/17 = ALL")
print(f"This is exactly the mod 5 finding: KA mod 5 ∈ {{0,3}} for ALL null chars.")
print()

# Now check NON-null palette positions
print("NON-null palette positions, KA grid analysis:")
for p in NONNULL_PALETTE_POS:
    c = CT97[p]
    ka_pos = KA_IDX[c]
    grid_col = ka_pos % 5
    grid_row = ka_pos // 5
    print(f"  pos={p:2d}: char={c}, KA={ka_pos:2d}, grid({grid_row},{grid_col}) "
          f"{'<- col {0,3}' if grid_col in (0,3) else ''}")

nonnull_in_col03 = sum(1 for p in NONNULL_PALETTE_POS if KA_IDX[CT97[p]] % 5 in (0, 3))
print(f"\nNon-null palette with KA grid col in {{0,3}}: {nonnull_in_col03}/18 = ALL")
print("(This is tautological: palette letters ALL have KA mod 5 ∈ {0,3})")
print()

# The REAL question: what distinguishes null palette positions from non-null palette positions?
# Both have the SAME KA column property. The discriminator must be something ELSE.
print("Null vs Non-null palette positions — searching for discriminator:")
print(f"  Null positions: {CONSENSUS_NULLS}")
print(f"  Non-null positions: {NONNULL_PALETTE_POS}")

# Test: is it the KA ROW that matters?
null_ka_rows = [KA_IDX[CT97[p]] // 5 for p in CONSENSUS_NULLS]
nonnull_ka_rows = [KA_IDX[CT97[p]] // 5 for p in NONNULL_PALETTE_POS]
print(f"\n  Null KA rows: {Counter(null_ka_rows)}")
print(f"  Non-null KA rows: {Counter(nonnull_ka_rows)}")
# Not a clean discriminator if rows overlap

# Test: is it the SPECIFIC letter that matters?
null_letter_freq = Counter(CONSENSUS_CHARS)
nonnull_chars = [CT97[p] for p in NONNULL_PALETTE_POS]
nonnull_letter_freq = Counter(nonnull_chars)
print(f"\n  Null letter frequencies: {dict(null_letter_freq)}")
print(f"  Non-null letter frequencies: {dict(nonnull_letter_freq)}")
# Letters ONLY in nulls vs ONLY in non-nulls
null_only_letters = set(null_letter_freq.keys()) - set(nonnull_letter_freq.keys())
nonnull_only_letters = set(nonnull_letter_freq.keys()) - set(null_letter_freq.keys())
print(f"  Letters ONLY in nulls: {sorted(null_only_letters)}")
print(f"  Letters ONLY in non-nulls: {sorted(nonnull_only_letters)}")
print(f"  Letters in both: {sorted(set(null_letter_freq.keys()) & set(nonnull_letter_freq.keys()))}")
print()

# W appears in nulls (4x) and non-nulls (1x=W@48).
# Z appears in nulls (1x) and non-nulls (3x).
# All other palette letters appear in both.
# So the letter alone doesn't determine null/non-null.

# CRITICAL TEST: Position-based formula
# Null palette positions: [0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85]
# Non-null palette pos:   [7,16,18,19,30,31,34,45,46,47,48,56,62,70,73,77,86,93]
#
# Null positions tend to be at the BOUNDARIES of segments.
# The crib-relative analysis shows: 8 before ENE, 4 between, 5 after BCL
# The non-nulls: 7 in row 25, 6 in row 26, 5 in row 27

# BOOLEAN FORMULA SEARCH
# Try: is_null(p) iff (p % a) ∈ S for some (a, S)
print("Boolean formula search: is_null(p) iff (p % a) in target_set")
for a in range(2, 50):
    # What residues mod a do ALL null palette positions have?
    null_residues = set(p % a for p in CONSENSUS_NULLS)
    nonnull_residues = set(p % a for p in NONNULL_PALETTE_POS)

    # Perfect separator: null_residues and nonnull_residues are DISJOINT
    if not null_residues & nonnull_residues:
        print(f"  *** mod {a}: PERFECT SEPARATOR! null={sorted(null_residues)}, nonnull={sorted(nonnull_residues)}")
        note(f"FINDING: mod {a} perfectly separates null from non-null palette positions!")

# If no perfect separator, find best
print("\nBest approximate separators (minimize overlap):")
best_sep = (0, 0, 0)
for a in range(2, 50):
    null_residues = set(p % a for p in CONSENSUS_NULLS)
    nonnull_residues = set(p % a for p in NONNULL_PALETTE_POS)
    overlap = len(null_residues & nonnull_residues)
    total = len(null_residues | nonnull_residues)
    separation = 1 - overlap / total if total > 0 else 0
    if overlap < best_sep[1] or (overlap == best_sep[1] and a < best_sep[0]):
        best_sep = (a, overlap, separation)
    if overlap <= 3:
        print(f"  mod {a}: null={sorted(null_residues)}, nonnull={sorted(nonnull_residues)}, overlap={overlap}")

print()

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("COMPREHENSIVE SUMMARY")
print("=" * 72)
print()

for i, f in enumerate(findings, 1):
    print(f"  {i}. {f}")

elapsed = time.time() - t0
print(f"\nTotal runtime: {elapsed:.1f}s")

out_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'palette_deep_followup.json'))
with open(out_path, 'w') as f_out:
    json.dump({"findings": findings, "elapsed": elapsed, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}, f_out, indent=2)
print(f"Results saved to: {out_path}")
