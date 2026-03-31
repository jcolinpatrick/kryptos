#!/usr/bin/env python3
"""
Debug: why does the derivation script report distance 0 but verification
shows 23-25/26?

The issue is likely in how mixed cells are handled.
In the derivation: hamming_full treats mixed as null (bit=1).
In the verification: compares predicted_null to actual null-ish status.

Let me trace through TOWER AZ_vig step by step.
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import sys, os
from collections import defaultdict
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, KRYPTOS_ALPHABET, ALPH

PALETTE = frozenset('BGIKOWZ')
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(ALPH)}
KRYPTOS_AZ = [AZ_IDX[c] for c in 'KRYPTOS']

palette_positions = sorted(p for p in range(CT_LEN) if CT[p] in PALETTE)
labels = {p: p in CONSENSUS_NULLS for p in palette_positions}

cell_positions = defaultdict(list)
for p in palette_positions:
    cell_positions[(p % 7, p % 5)].append(p)

target_table = {}
for r in range(7):
    for c in range(5):
        positions = cell_positions.get((r, c), [])
        if not positions:
            target_table[(r, c)] = None
        else:
            null_count = sum(1 for p in positions if labels[p])
            real_count = len(positions) - null_count
            if null_count > 0 and real_count == 0:
                target_table[(r, c)] = True
            elif real_count > 0 and null_count == 0:
                target_table[(r, c)] = False
            else:
                target_table[(r, c)] = 'mixed'

occupied_cells = [(r, c) for r in range(7) for c in range(5) if target_table[(r, c)] is not None]
target_nullish = set()
target_realish = set()
for (r, c) in occupied_cells:
    if target_table[(r, c)] is True or target_table[(r, c)] == 'mixed':
        target_nullish.add((r, c))
    else:
        target_realish.add((r, c))

print("Occupied cells (26):")
for r in range(7):
    for c in range(5):
        v = target_table[(r, c)]
        if v is not None:
            status = 'N' if v is True else 'R' if v is False else '?'
            nullish = (r, c) in target_nullish
            print(f"  ({r},{c}): {status}  (nullish={nullish})")

# TOWER AZ_vig
word = 'TOWER'
w_vals = [AZ_IDX[c] for c in word]
variant_func = lambda k, p: (k - p) % 26

print(f"\nKRYPTOS x TOWER (AZ_vig):")
print(f"KRYPTOS_AZ = {KRYPTOS_AZ}")
print(f"TOWER_AZ = {w_vals}")

# Compute all outputs
outputs = {}
for r in range(7):
    for c in range(5):
        out_idx = variant_func(KRYPTOS_AZ[r], w_vals[c])
        out_letter = ALPH[out_idx]
        outputs[(r, c)] = (out_idx, out_letter)

print(f"\nOutput table:")
for r in range(7):
    for c in range(5):
        if (r, c) in [(rc[0], rc[1]) for rc in occupied_cells]:
            idx, letter = outputs[(r, c)]
            status = target_table[(r, c)]
            tag = 'N' if status is True else 'R' if status is False else '?'
            print(f"  ({r},{c})[{tag}] -> {letter}({idx})")

# From the derivation script output:
# null_outs=[2, 3, 13, 19, 21, 24, 25] = {C, D, N, T, V, Y, Z}
# real_outs=[1, 5, 10, 11, 14, 15, 22, 23] = {B, F, K, L, O, P, W, X}
# mixed_outs=[17, 18, 20] = {R, S, U}

null_outs = {2, 3, 13, 19, 21, 24, 25}
real_outs = {1, 5, 10, 11, 14, 15, 22, 23}
mixed_outs = {17, 18, 20}

print(f"\nnull output indices: {sorted(null_outs)}")
print(f"real output indices: {sorted(real_outs)}")
print(f"mixed output indices: {sorted(mixed_outs)}")

# The derivation script's approach 2c checks:
# "null_outputs and real_outputs are disjoint" -- YES (disjoint)
# Then it says: null_set = null_outputs | mixed_outputs
# And classifies: output in null_set -> null, else real

# But verification uses: expected_null_letters = ['C','D','N','T','V','Y','Z']
# which is null_outs only (7 letters), NOT including mixed_outs (3 letters)

# The derivation found dist=0 because it INCLUDED mixed outputs in null set
# But verification excluded them

# Key question: are mixed_outs really at mixed cells?
print(f"\nMixed cells: {[(r,c) for (r,c) in occupied_cells if target_table[(r,c)] == 'mixed']}")
for r, c in occupied_cells:
    if target_table[(r, c)] == 'mixed':
        idx, letter = outputs[(r, c)]
        print(f"  ({r},{c}) -> {letter}({idx})")

# So the derivation correctly identifies that outputs at mixed cells
# are in mixed_outs = {17, 18, 20}, and since these DON'T overlap
# with real_outs, it classifies them as null (including in null set).
# This is correct for the 26-cell table level:
# mixed cells are treated as null-leaning.

# But verification used only the 7 null letters (not including mixed),
# so mixed cell outputs were classified as "real" -> wrong for 3 cells
# 26 - 3 = 23. That explains the 23/26.

# CORRECTED verification:
null_letters_full = set(ALPH[i] for i in null_outs | mixed_outs)
print(f"\nCorrected null letters (including mixed outputs): {sorted(null_letters_full)}")
correct = 0
for (r, c) in occupied_cells:
    idx, letter = outputs[(r, c)]
    predicted_null = letter in null_letters_full
    actual_nullish = (r, c) in target_nullish
    ok = predicted_null == actual_nullish
    if ok:
        correct += 1
    else:
        status = target_table[(r, c)]
        print(f"  MISMATCH: ({r},{c})[{status}] -> {letter} predicted_null={predicted_null} actual={actual_nullish}")
print(f"Corrected accuracy: {correct}/26")

# So the derivation IS correct: with 10 null letters (7 pure + 3 mixed),
# all 26 cells are correctly classified.

# But wait -- this means the "null letter set" has 10 members, not 7.
# The 10 letters are: C, D, N, R, S, T, U, V, Y, Z (AZ indices 2,3,13,17,18,19,20,21,24,25)

# And the real set has 16 members? No -- the output produces only 18 distinct
# values across 26 cells. Some letters never appear.
all_outputs = set(idx for (r, c) in occupied_cells for idx, _ in [outputs[(r, c)]])
print(f"\nAll distinct output values at occupied cells: {sorted(all_outputs)}")
print(f"Count: {len(all_outputs)}")
print(f"Null set: {sorted(null_outs | mixed_outs)} ({len(null_outs | mixed_outs)})")
print(f"Real set: {sorted(real_outs)} ({len(real_outs)})")
print(f"Total used: {len((null_outs | mixed_outs) | real_outs)}")

# The question is: is there a SIMPLE characterization of the null set?
# Null indices: {2, 3, 13, 17, 18, 19, 20, 21, 24, 25}
# Real indices: {1, 5, 10, 11, 14, 15, 22, 23}
# Not used: {0, 4, 6, 7, 8, 9, 12, 16}

null_set_full = sorted(null_outs | mixed_outs)
real_set_full = sorted(real_outs)
print(f"\nNull output indices: {null_set_full}")
print(f"Real output indices: {real_set_full}")

# Check patterns:
print(f"Null mod 2: {[x%2 for x in null_set_full]}")
print(f"Real mod 2: {[x%2 for x in real_set_full]}")
print(f"Null mod 3: {[x%3 for x in null_set_full]}")
print(f"Real mod 3: {[x%3 for x in real_set_full]}")
print(f"Null mod 5: {[x%5 for x in null_set_full]}")
print(f"Real mod 5: {[x%5 for x in real_set_full]}")
print(f"Null mod 7: {[x%7 for x in null_set_full]}")
print(f"Real mod 7: {[x%7 for x in real_set_full]}")
print(f"Null mod 13: {[x%13 for x in null_set_full]}")
print(f"Real mod 13: {[x%13 for x in real_set_full]}")

# The real question: what is the STRUCTURAL constraint?
# For AZ_vig, output = (KRYPTOS_AZ[r] - TOWER_AZ[c]) mod 26
# Null cells require: all outputs at null rows land in null_set
#                     all outputs at real rows land in real_set

# But the partition into null/real letters has 18 elements total.
# The null set has 10, real has 8. The other 8 indices don't appear.
# So the constraint is: outputs must land in a 10-element set (null) or 8-element set (real).

# This is a very loose constraint -- almost any partition will have SOME word that works.
# That's why 0.5% of random words succeed.

# HOWEVER, the thematic resonance of TOWER, CHART, LAYER is the interesting part.
# The question is whether Sanborn could have used one of these as a keyword.

# Let's count how many ENGLISH words match each variant:
print("\n\nKey finding: The 7x5 table CAN be generated by a cipher operation")
print("KRYPTOS x <word>, but ~0.5% of all 5-letter words work.")
print("This means ~58K words work for any given variant.")
print("The statistical significance is LOW for any individual match.")
print("")
print("HOWEVER: finding thematically relevant words (TOWER, CHART, LAYER)")
print("among the matches is potentially meaningful.")
print("")
print("The real test is whether the null letter set has a simple description")
print("that Sanborn could have used without a computer.")

# For TOWER AZ_vig: null letters = {C,D,N,R,S,T,U,V,Y,Z}
# These are AZ indices 2,3,13,17,18,19,20,21,24,25
# Note: indices 17-21 form a contiguous block (RSTUV)
# And 24-25 (YZ), 2-3 (CD), 13 (N)
# The NULL set in KA ordering:
null_letters_tower_vig = set('CDNRSTUVYZ')
null_ka_indices = sorted(KA_IDX[c] for c in null_letters_tower_vig)
print(f"TOWER AZ_vig null letters in KA order: {null_ka_indices}")
print(f"= {[KA[i] for i in null_ka_indices]}")

# For CHART AZ_beau: null set includes mixed outputs too
# From the output: null_outs=[3, 8, 12, 15, 16, 19, 20, 24]
# mixed_outs=[12, 14, 15] -- wait, 12 and 15 are already in null_outs!
# So mixed_outs adds only 14.
chart_null_outs = {3, 8, 12, 14, 15, 16, 19, 20, 24}
chart_real_outs = {0, 5, 6, 7, 9, 10, 11, 17, 18, 22}
print(f"\nCHART AZ_beau full null set: {sorted(chart_null_outs)} = {sorted(ALPH[i] for i in chart_null_outs)}")
print(f"CHART AZ_beau real set: {sorted(chart_real_outs)} = {sorted(ALPH[i] for i in chart_real_outs)}")

# CHART has 9 null + 10 real = 19 distinct outputs
# Similar to TOWER: about half null, half real

# LAYER KA_vig: null_outs = {0,1,2,3,10,14,15,16,20,25}
# mixed = {D,H,I,J,K,P,Q,R,Y,Z} -> in KA these are indices...
# Actually the output text said:
# null_letters=['D', 'H', 'I', 'J', 'K', 'P', 'Q', 'R', 'Y', 'Z']
# KA indices: D=10, H=14, I=15, J=16, K=0, P=3, Q=20, R=1, Y=2, Z=25
# = {0,1,2,3,10,14,15,16,20,25}
# And real_letters=['E', 'F', 'M', 'N', 'O', 'T', 'U', 'V', 'W', 'X']
# KA: E=11, F=12, M=18, N=19, O=5, T=4, U=21, V=22, W=23, X=24
# = {4,5,11,12,18,19,21,22,23,24}

# In KA ordering:
# Null KA: 0,1,2,3,10,14,15,16,20,25
# Real KA: 4,5,11,12,18,19,21,22,23,24
# Neither: 6,7,8,9,13,17

# Null = {0-3} + {10} + {14-16} + {20} + {25}
# = first 4 (KRYP) + D + IJL + Q + Z
# In the KA Polybius (5-wide):
# Row 0: K(0) R(1) Y(2) P(3) T(4) -> null: 0,1,2,3 (4/5)
# Row 1: O(5) S(6) A(7) B(8) C(9) -> null: none
# Row 2: D(10) E(11) F(12) G(13) H(14) -> null: 10, 14 (2/5)
# Row 3: I(15) J(16) L(17) M(18) N(19) -> null: 15, 16 (2/5)
# Row 4: Q(20) U(21) V(22) W(23) X(24) -> null: 20 (1/5)
# Row 5: Z(25) -> null: 25 (1/1)
print("\nLAYER KA_vig null set in KA Polybius (5-wide):")
layer_null_ka = {0,1,2,3,10,14,15,16,20,25}
for row in range(6):
    start = row * 5
    end = min(start + 5, 26)
    indices = list(range(start, end))
    null_in_row = [i for i in indices if i in layer_null_ka]
    real_in_row = [i for i in indices if i not in layer_null_ka]
    letters_null = [KA[i] for i in null_in_row]
    letters_real = [KA[i] for i in real_in_row]
    print(f"  Row {row}: null={letters_null} real={letters_real}")

# Interesting: Row 0 has 4/5 null (all but T), Row 1 has 0/5 null,
# Row 5 has 1/1 null. Not a simple row-based rule.

# What about the KA column?
print("\nLAYER KA_vig null set by KA Polybius column:")
for col in range(5):
    indices = [row * 5 + col for row in range(6) if row * 5 + col < 26]
    null_in_col = [i for i in indices if i in layer_null_ka]
    real_in_col = [i for i in indices if i not in layer_null_ka]
    letters_null = [KA[i] for i in null_in_col]
    letters_real = [KA[i] for i in real_in_col]
    print(f"  Col {col}: null={letters_null} real={letters_real}")

# Col 0: KDIQ null, OZ mixed -> 4 null, 1 real (O), 1 boundary (Z null)
# Wait, Z is index 25 = row 5, col 0. And it IS null.
# Col 0: K(0)N, O(5)R, D(10)N, I(15)N, Q(20)N, Z(25)N = 5 null, 1 real
# Col 1: R(1)N, S(6)-, E(11)R, J(16)N, U(21)R = 2 null, 2 real
# Col 2: Y(2)N, A(7)-, F(12)R, L(17)-, V(22)R = 1 null, 2 real
# Col 3: P(3)N, B(8)-, G(13)-, M(18)R, W(23)R = 1 null, 2 real
# Col 4: T(4)R, C(9)-, H(14)N, N(19)R, X(24)R = 1 null, 2 real

# Hmm, col 0 is heavily null (5/6). But the other columns are more balanced.
# Not a simple column rule either.

print("\n\nCONCLUSION:")
print("The 7x5 table CAN be generated by KRYPTOS x <word> cipher operations,")
print("but ~0.5% of random 5-letter words produce valid separations.")
print("This makes any individual match statistically weak (p ~ 1/200).")
print("")
print("Thematic words found: TOWER (AZ_vig), CHART (AZ_beau), LAYER (KA_vig)")
print("Also SOUTH (AZ_beau, dist=1), HEAST (AZ_beau, dist=1)")
print("")
print("The null letter sets have no obvious simple structure (not a threshold,")
print("not row-based or column-based in KA Polybius).")
print("")
print("The 7x5 table itself remains the simplest and most economical description")
print("of the null selection rule. Whether it was generated by a keyword cipher")
print("or is a hand-written lookup table remains OPEN.")
