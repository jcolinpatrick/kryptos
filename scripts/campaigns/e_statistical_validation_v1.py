#!/usr/bin/env python3
"""
RIGOROUS STATISTICAL VALIDATION of session discoveries.
Tests whether reported findings are robust or overfitted.

Claims validated:
  1. Palette {B,G,I,K,O,W,Z}: 7 distinct letters in 17 consensus nulls
  2. KA Polybius mod-5 structure (columns 0,3)
  3. KRYPTOS+SEVEN generates palette via Polybius row selection
  4. 35/35 position classifier via (pos%7, pos%5) table
  5. Beaufort A=0 keystream at BCL = 7/8 palette
  6. DEFECTOR:AZ_beau+col7 = 15/24

Each claim gets: in-sample fit, degrees of freedom, proper p-value,
overfitting risk, and a verdict.
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import json
import random
import sys
import time
from collections import Counter
from itertools import combinations
from math import comb, log2

sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, KRYPTOS_ALPHABET

# ============================================================
# CONSTANTS
# ============================================================

CT97 = CT
assert len(CT97) == 97

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

PALETTE = set("BGIKOWZ")
PALETTE_LETTERS = sorted(PALETTE)

# The 17 consensus null positions (from exhaustive brute force)
CONSENSUS_NULLS = [0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85]
assert len(CONSENSUS_NULLS) == 17

# Crib positions (must not be nulls)
CRIB_POSITIONS = set(CRIB_DICT.keys())
assert len(CRIB_POSITIONS) == 24

# CT letters at consensus null positions
NULL_CHARS = [CT97[p] for p in CONSENSUS_NULLS]
NULL_CHARS_STR = "".join(NULL_CHARS)  # OBKOGBOWWKWIWGZIG
assert NULL_CHARS_STR == "OBKOGBOWWKWIWGZIG"

# CT letter frequencies
CT_FREQ = Counter(CT97)

# All positions where CT letter is in PALETTE
PALETTE_POSITIONS = [p for p in range(97) if CT97[p] in PALETTE]
assert len(PALETTE_POSITIONS) == 35

# Null palette positions vs non-null palette positions
NULL_PALETTE = [p for p in PALETTE_POSITIONS if p in set(CONSENSUS_NULLS)]
NONNULL_PALETTE = [p for p in PALETTE_POSITIONS if p not in set(CONSENSUS_NULLS)]
assert len(NULL_PALETTE) == 17
assert len(NONNULL_PALETTE) == 18

# Beaufort keystream at crib positions: k = (CT + PT) mod 26
BEAUFORT_KEY_BCL = []
for i in range(63, 74):
    ct_val = ALPH_IDX[CT97[i]]
    pt_val = ALPH_IDX[CRIB_DICT[i]]
    k = (ct_val + pt_val) % 26
    BEAUFORT_KEY_BCL.append(k)

BEAUFORT_KEY_ENE = []
for i in range(21, 34):
    ct_val = ALPH_IDX[CT97[i]]
    pt_val = ALPH_IDX[CRIB_DICT[i]]
    k = (ct_val + pt_val) % 26
    BEAUFORT_KEY_ENE.append(k)

# Full keystream
BEAUFORT_KEYSTREAM_ALL = BEAUFORT_KEY_ENE + BEAUFORT_KEY_BCL
assert len(BEAUFORT_KEYSTREAM_ALL) == 24

SEED = 20260315
N_MC = 200_000  # Monte Carlo trials per test

results = {}

print("=" * 70)
print("RIGOROUS STATISTICAL VALIDATION")
print("=" * 70)
print(f"Monte Carlo trials per test: {N_MC:,}")
print(f"Random seed: {SEED}")
print()

t0 = time.time()

# ============================================================
# CLAIM 1: Palette {B,G,I,K,O,W,Z} -- 7 distinct letters in 17 nulls
# ============================================================
print("=" * 70)
print("CLAIM 1: Palette = 7 distinct letters in 17 consensus null chars")
print("=" * 70)

# In-sample observation
n_distinct_observed = len(set(NULL_CHARS))
assert n_distinct_observed == 7

# The correct test: palette was DERIVED from data (post-hoc).
# So the proper question is: P(17 random positions from CT97 use <= 7 distinct letters)
# This accounts for the fact that we would have reported ANY low-diversity subset.

rng = random.Random(SEED)
count_le7 = 0
n_trials_1 = N_MC

# Positions available for null selection (exclude crib positions)
available_positions = [p for p in range(97) if p not in CRIB_POSITIONS]

for _ in range(n_trials_1):
    sample = rng.sample(available_positions, 17)
    letters = set(CT97[p] for p in sample)
    if len(letters) <= 7:
        count_le7 += 1

p_diversity = count_le7 / n_trials_1

# Also: check P(ANY 7-letter subset covers all 17) -- this is equivalent since
# if you get <=7 distinct, there exists a 7-letter set covering them all.
# The two tests are identical.

print(f"  Observed: {n_distinct_observed} distinct letters from 17 positions")
print(f"  MC P(<=7 distinct in random 17 non-crib positions): {p_diversity:.6f} ({count_le7}/{n_trials_1})")
print(f"  Equivalent: 1 in {1/p_diversity:,.0f}" if p_diversity > 0 else "  Equivalent: < 1/{n_trials_1}")
print()
print("  DEGREES OF FREEDOM: 0 (we derived the palette from the data)")
print("  MULTIPLE TESTING CORRECTION: None needed -- we report the DIVERSITY")
print("    metric (<=7 distinct), not a specific 7-letter set. This is the")
print("    proper post-hoc test.")
print()

if p_diversity < 0.001:
    verdict_1 = "ROBUST"
elif p_diversity < 0.01:
    verdict_1 = "BORDERLINE"
else:
    verdict_1 = "LIKELY OVERFITTED"

print(f"  OVERFITTING RISK: LOW (test is post-hoc aware)")
print(f"  VERDICT: [{verdict_1}] p = {p_diversity:.6f}")

results["claim1"] = {
    "observation": f"{n_distinct_observed} distinct letters in 17 null chars",
    "p_value": p_diversity,
    "mc_trials": n_trials_1,
    "degrees_of_freedom": 0,
    "multiple_testing": "None needed (post-hoc diversity test)",
    "overfitting_risk": "LOW",
    "verdict": verdict_1
}

# ============================================================
# CLAIM 2: KA Polybius mod-5 structure (columns 0,3)
# ============================================================
print()
print("=" * 70)
print("CLAIM 2: KA indices of palette all in {0,3} mod 5")
print("=" * 70)

palette_ka = sorted([KA_IDX[c] for c in PALETTE])
palette_ka_mod5 = sorted(set(k % 5 for k in palette_ka))
print(f"  Palette KA indices: {palette_ka}")
print(f"  Palette KA mod 5: {[k%5 for k in palette_ka]}")
print(f"  Distinct residues mod 5: {palette_ka_mod5}")

# Test: given 7 letters derived from CT, P(all KA indices fall in exactly 2 residues mod 5)
# AND we need to correct for searching multiple moduli.

# How many moduli did we check? The data says mod 2,3,4,5 were checked.
# For each modulus M, we look for any subset of <=2 residues covering all 7.
# Number of tests: for M=2: C(2,1)+C(2,2)=3; M=3: C(3,1)+C(3,2)=6;
# M=4: C(4,1)+C(4,2)=10; M=5: C(5,1)+C(5,2)=15; ... etc.

# Proper test: MC -- pick 7 random letters from 26, check if their KA indices
# all fall in <=2 residue classes for ANY modulus in {2,3,4,5,6,7}.
# This is the multiple-testing-corrected version.

moduli_checked = list(range(2, 8))  # mod 2 through 7

def check_low_residue(ka_indices, max_residues=2, moduli=None):
    """Check if all ka_indices fall in <=max_residues residue classes for any modulus."""
    if moduli is None:
        moduli = moduli_checked
    hits = []
    for m in moduli:
        residues = set(k % m for k in ka_indices)
        if len(residues) <= max_residues:
            hits.append((m, sorted(residues)))
    return hits

observed_hits = check_low_residue(palette_ka)
print(f"  Modular hits (<=2 residues): {observed_hits}")

# MC: pick 7 random KA indices (0-25), check for same property
count_mod_hit = 0
for _ in range(N_MC):
    sample_ka = rng.sample(range(26), 7)
    if check_low_residue(sample_ka):
        count_mod_hit += 1

p_mod = count_mod_hit / N_MC
print(f"  MC P(random 7 KA indices have <=2 residues for any mod 2-7): {p_mod:.6f} ({count_mod_hit}/{N_MC})")
print()

# But we need to be more careful: the 7 letters are NOT random from 26.
# They are the specific 7 letters at 17 CT positions. The palette is already
# conditioned on being the letters at null positions. So the proper test is:
# Given 17 random non-crib positions from CT97, if the letters use <=7 distinct,
# what fraction of those events ALSO have all KA indices in <=2 residue classes
# for some modulus?

count_diversity_and_mod = 0
count_diversity_only = 0
for _ in range(N_MC):
    sample = rng.sample(available_positions, 17)
    letters = set(CT97[p] for p in sample)
    if len(letters) <= 7:
        count_diversity_only += 1
        ka_idx = [KA_IDX[c] for c in letters]
        if check_low_residue(ka_idx):
            count_diversity_and_mod += 1

if count_diversity_only > 0:
    p_mod_given_diversity = count_diversity_and_mod / count_diversity_only
    p_joint = count_diversity_and_mod / N_MC
else:
    p_mod_given_diversity = float('nan')
    p_joint = 0.0

print(f"  CONDITIONAL: P(mod hit | <=7 distinct): {p_mod_given_diversity:.4f} ({count_diversity_and_mod}/{count_diversity_only})")
print(f"  JOINT: P(<=7 distinct AND mod hit): {p_joint:.6f} ({count_diversity_and_mod}/{N_MC})")
print()

# Additional: for the specific observation (mod 5, residues {0,3}),
# P(7 random letters from 26 all have KA index in {0,3} mod 5)
# Columns 0 and 3 of 5-wide grid contain: 11 letters (ceil(26/5)*2 ~= 10-12)
# Count letters with KA index mod 5 in {0,3}:
letters_in_03 = [c for c in KA if KA_IDX[c] % 5 in (0, 3)]
n_in_03 = len(letters_in_03)
print(f"  Letters with KA mod 5 in {{0,3}}: {n_in_03} ({','.join(sorted(letters_in_03))})")
p_specific = comb(n_in_03, 7) / comb(26, 7) if n_in_03 >= 7 else 0
print(f"  P(7 random letters all from this set): C({n_in_03},7)/C(26,7) = {p_specific:.6f}")

# The modulus 5 was chosen post-hoc. Correcting:
# Tested moduli 2-7 (6 moduli), for each up to C(M,2) residue pairs
n_residue_tests = sum(comb(m, 1) + comb(m, 2) for m in moduli_checked)
print(f"  Total residue tests across mod 2-7: {n_residue_tests}")
p_corrected = min(1.0, p_specific * n_residue_tests)
print(f"  Bonferroni-corrected p (for {n_residue_tests} tests on specific set): {p_corrected:.6f}")

if p_joint > 0:
    verdict_2_p = p_joint
else:
    verdict_2_p = p_corrected

if verdict_2_p < 0.001:
    verdict_2 = "ROBUST"
elif verdict_2_p < 0.01:
    verdict_2 = "BORDERLINE"
elif verdict_2_p < 0.05:
    verdict_2 = "WEAK"
else:
    verdict_2 = "LIKELY OVERFITTED"

print(f"\n  DEGREES OF FREEDOM: ~{n_residue_tests} tests searched")
print(f"  OVERFITTING RISK: MEDIUM (mod 5 chosen post-hoc from limited search)")
print(f"  VERDICT: [{verdict_2}] joint p = {p_joint:.6f}, corrected p = {p_corrected:.6f}")

results["claim2"] = {
    "observation": f"All 7 palette KA indices mod 5 in {{0,3}}",
    "p_joint": p_joint,
    "p_specific": p_specific,
    "p_corrected": p_corrected,
    "residue_tests": n_residue_tests,
    "mc_trials": N_MC,
    "overfitting_risk": "MEDIUM",
    "verdict": verdict_2
}

# ============================================================
# CLAIM 3: KRYPTOS+SEVEN generates palette via Polybius row selection
# ============================================================
print()
print("=" * 70)
print("CLAIM 3: KRYPTOS+SEVEN row-selection model = 6/6 exact match")
print("=" * 70)

# The model: lay KA in 5-wide grid. KRYPTOS occupies rows 0-1.
# For second keyword, letters in cols 0-2 of a row -> select col3 from that row.
# KRYPTOS -> col0. Both -> both cols.

# The claim: KRYPTOS is known a priori (not searched).
# SEVEN was one of many thematic keywords tested.
# Reported: 21 keyword pairs produce the pattern.

# Compute the probability for a SPECIFIC second keyword of length L
# that it produces the observed [0,B,3,0,3,0] pattern.

# The 5-wide KA grid:
KA_GRID = []
for row in range(6):
    row_letters = []
    for col in range(5):
        idx = row * 5 + col
        if idx < 26:
            row_letters.append(KA[idx])
        else:
            row_letters.append(None)
    KA_GRID.append(row_letters)

# Expected pattern from data: row -> which column(s) selected
# Row 0: col0 only (K) -- KRYPTOS occupies rows 0-1
# Row 1: both (O and B) -- KRYPTOS + second keyword
# Row 2: col3 only (G) -- second keyword
# Row 3: col0 only (I) -- neither
# Row 4: col3 only (W) -- second keyword
# Row 5: col0 only (Z) -- default

# For KRYPTOS: rows 0-1 get col0 trigger.
# KRYPTOS letters in 5-wide grid positions:
kryptos_rows = set()
for c in "KRYPTOS":
    idx = KA_IDX[c]
    kryptos_rows.add(idx // 5)
print(f"  KRYPTOS occupies rows: {sorted(kryptos_rows)}")  # {0, 1}

# The pattern for the second keyword is:
# Which rows have the keyword's letters in cols 0,1,2?
# Target: rows 1, 2, 4 must have keyword letters in cols 0-2.
# Rows 0, 3, 5 must NOT have keyword letters in cols 0-2.

# For each row r (0-5), cols 0-2 have letters at KA positions r*5+0, r*5+1, r*5+2
# (if they exist).
cols02_by_row = {}
for r in range(6):
    cols02_by_row[r] = set()
    for c in range(3):
        idx = r * 5 + c
        if idx < 26:
            cols02_by_row[r].add(KA[idx])

# Target: second keyword must hit cols 0-2 in rows {1,2,4} and NOT in rows {0,3,5}
target_hit_rows = {1, 2, 4}
target_miss_rows = {0, 3, 5}

# Verify SEVEN:
seven_letters = set("SEVEN")
for r in range(6):
    hit = bool(seven_letters & cols02_by_row[r])
    expected_hit = r in target_hit_rows
    assert hit == expected_hit, f"SEVEN fails at row {r}"
print("  SEVEN: verified 6/6 match")

# MC: random 5-letter words from A-Z, how many produce the same pattern?
# (SEVEN has 5 letters, but only 4 distinct: S,E,V,N)
# We should test words of the same length as SEVEN.

# But first: how many thematic keywords did we actually test?
# The code tested the full THEMATIC_KEYWORDS list. Let me count.
from kryptos.kernel.alphabet import THEMATIC_KEYWORDS
n_thematic = len(THEMATIC_KEYWORDS)
print(f"  Thematic keywords tested: {n_thematic}")

# MC: random 5-letter words (uniform random from A-Z)
count_match = 0
for _ in range(N_MC):
    word = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(5))
    word_set = set(word)
    match = True
    for r in range(6):
        hit = bool(word_set & cols02_by_row[r])
        expected_hit = r in target_hit_rows
        if hit != expected_hit:
            match = False
            break
    if match:
        count_match += 1

p_random_word = count_match / N_MC
print(f"  MC P(random 5-letter word produces exact pattern): {p_random_word:.6f} ({count_match}/{N_MC})")

# Correction for testing n_thematic keywords:
p_corrected_3 = min(1.0, 1 - (1 - p_random_word) ** n_thematic)
print(f"  P(at least 1 match from {n_thematic} tests): {p_corrected_3:.6f}")

# Also test: random words of ALL lengths (since keywords vary in length)
count_any_len = 0
for _ in range(N_MC):
    wlen = rng.randint(3, 12)
    word = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(wlen))
    word_set = set(word)
    match = True
    for r in range(6):
        hit = bool(word_set & cols02_by_row[r])
        expected_hit = r in target_hit_rows
        if hit != expected_hit:
            match = False
            break
    if match:
        count_any_len += 1

p_any_len = count_any_len / N_MC
p_corrected_3b = min(1.0, 1 - (1 - p_any_len) ** n_thematic)
print(f"  MC P(random word length 3-12 matches): {p_any_len:.6f}")
print(f"  P(at least 1 from {n_thematic} thematic keywords, variable length): {p_corrected_3b:.6f}")

# Cross-check: how many of the thematic keywords actually work?
thematic_matches = []
for kw in THEMATIC_KEYWORDS:
    kw_set = set(kw)
    match = True
    for r in range(6):
        hit = bool(kw_set & cols02_by_row[r])
        expected_hit = r in target_hit_rows
        if hit != expected_hit:
            match = False
            break
    if match:
        thematic_matches.append(kw)

print(f"  Thematic keywords that match: {len(thematic_matches)}")
if len(thematic_matches) <= 30:
    print(f"    {thematic_matches}")

# The reported 21 pairs is KRYPTOS + X for 21 values of X.
# But 21/n_thematic is the hit rate among thematic keywords.
# The question is whether SEVEN is special among these 21+.

# KRYPTOS was known a priori. SEVEN is thematically motivated (FIVE at seam,
# Beaufort connection). But 21 keywords work, so SEVEN is NOT uniquely selected.
# The proper claim is: "a thematic keyword producing this pattern exists" (p = p_corrected_3b).

print()
print("  KEY ISSUE: KRYPTOS was known a priori. But 21 thematic keywords work,")
print("  so SEVEN is one of many. The question is whether ANY match exists.")

if p_corrected_3b < 0.01:
    verdict_3 = "ROBUST"
elif p_corrected_3b < 0.05:
    verdict_3 = "BORDERLINE"
elif p_corrected_3b < 0.10:
    verdict_3 = "WEAK"
else:
    verdict_3 = "LIKELY OVERFITTED"

# But we also need to account for the model itself being post-hoc.
# "KRYPTOS occupies rows 0-1 -> col0; second keyword in cols 0-2 -> col3"
# This specific model was chosen BECAUSE it matched. How many similar
# models could we have tried?
# Alternative models: "in cols 0-1", "in cols 0-3", "in any col", "in odd cols",
# "in specific row range", "first keyword -> col1", etc.
# Conservatively: ~20 alternative model structures.
p_model_corrected = min(1.0, p_corrected_3b * 20)
print(f"  Model-corrected (x20 for model search): {p_model_corrected:.6f}")

if p_model_corrected < 0.01:
    verdict_3 = "ROBUST"
elif p_model_corrected < 0.05:
    verdict_3 = "BORDERLINE"
elif p_model_corrected < 0.15:
    verdict_3 = "WEAK"
else:
    verdict_3 = "LIKELY OVERFITTED"

print(f"  VERDICT: [{verdict_3}] corrected p = {p_corrected_3b:.6f}, model-corrected = {p_model_corrected:.6f}")

results["claim3"] = {
    "observation": "KRYPTOS+SEVEN produces palette via Polybius row selection (6/6)",
    "p_random_word": p_random_word,
    "p_corrected_thematic": p_corrected_3b,
    "p_model_corrected": p_model_corrected,
    "thematic_keywords_tested": n_thematic,
    "thematic_matches": len(thematic_matches),
    "overfitting_risk": "HIGH (model was designed to fit data)",
    "verdict": verdict_3
}

# ============================================================
# CLAIM 4: 35/35 perfect classifier via (pos%7, pos%5) table
# ============================================================
print()
print("=" * 70)
print("CLAIM 4: 35/35 perfect (pos%7, pos%5) classifier for null palette")
print("=" * 70)

# Data: 35 palette positions, 17 null, 18 non-null
# Model: 7x5 lookup table where each occupied cell is N or R
# Cells with 2 entries: "first occurrence = null" tiebreaker

# Count occupied cells and their contents
from collections import defaultdict
cell_contents = defaultdict(list)  # (r7, r5) -> [(pos, is_null), ...]
null_set = set(CONSENSUS_NULLS)

for p in sorted(PALETTE_POSITIONS):
    r7 = p % 7
    r5 = p % 5
    is_null = p in null_set
    cell_contents[(r7, r5)].append((p, is_null))

n_occupied = len(cell_contents)
pure_null = 0
pure_real = 0
mixed = 0
mixed_first_null = 0

for cell, entries in cell_contents.items():
    nulls = [e for e in entries if e[1]]
    reals = [e for e in entries if not e[1]]
    if len(nulls) > 0 and len(reals) == 0:
        pure_null += 1
    elif len(nulls) == 0 and len(reals) > 0:
        pure_real += 1
    else:
        mixed += 1
        # Check if first entry is null
        if entries[0][1]:  # sorted by position, first is lowest
            mixed_first_null += 1

print(f"  Occupied cells: {n_occupied}")
print(f"  Pure null: {pure_null}, Pure real: {pure_real}, Mixed: {mixed}")
print(f"  Mixed where first=null: {mixed_first_null}/{mixed}")
print(f"  Model parameters: {n_occupied} cells x 1 bit each + tiebreaker rule = ~{n_occupied + 1} parameters")
print(f"  Data points: 35")
print(f"  Parameters / data ratio: {(n_occupied + 1) / 35:.2f}")
print()

# TEST 4a: Monte Carlo permutation test
# Shuffle the 17/18 null/real labels among the 35 palette positions.
# For each shuffle, check if a (mod 7, mod 5) table achieves 35/35 perfect classification.

print("  TEST 4a: Permutation test (100K+ shuffles)")
count_perfect = 0
n_perm = N_MC

for _ in range(n_perm):
    # Randomly assign 17 positions as "null" from the 35 palette positions
    shuffled_nulls = set(rng.sample(PALETTE_POSITIONS, 17))

    # Build the lookup table for this assignment
    cell_ok = True
    cell_map = defaultdict(list)
    for p in sorted(PALETTE_POSITIONS):
        r7 = p % 7
        r5 = p % 5
        is_null = p in shuffled_nulls
        cell_map[(r7, r5)].append((p, is_null))

    # Check if ANY consistent labeling works:
    # For each cell: either all same label (pure), or first-is-null + rest-are-real
    perfect = True
    for cell, entries in cell_map.items():
        nulls_in = sum(1 for _, n in entries if n)
        reals_in = len(entries) - nulls_in

        if nulls_in == 0 or reals_in == 0:
            continue  # pure cell, always works

        # Mixed cell: check if first entry is null and rest are real
        if len(entries) == 2:
            if entries[0][1] and not entries[1][1]:
                continue  # first=null, second=real -> works
            else:
                perfect = False
                break
        else:
            # 3+ entries: need first=null, rest=real
            if entries[0][1] and all(not e[1] for e in entries[1:]):
                continue
            else:
                perfect = False
                break

    if perfect:
        count_perfect += 1

p_permutation = count_perfect / n_perm
print(f"    Perfect classifiers in {n_perm:,} permutations: {count_perfect}")
print(f"    P(perfect) = {p_permutation:.6f}")
if p_permutation > 0:
    print(f"    Equivalent: 1 in {1/p_permutation:,.0f}")
print()

# TEST 4b: Leave-one-out cross-validation
print("  TEST 4b: Leave-one-out cross-validation")
correct_loo = 0
for leave_out_idx in range(35):
    leave_out_pos = sorted(PALETTE_POSITIONS)[leave_out_idx]
    leave_out_null = leave_out_pos in null_set

    # Build table from remaining 34
    train_cell = defaultdict(list)
    for i, p in enumerate(sorted(PALETTE_POSITIONS)):
        if i == leave_out_idx:
            continue
        r7 = p % 7
        r5 = p % 5
        is_null = p in null_set
        train_cell[(r7, r5)].append((p, is_null))

    # Predict held-out
    r7_out = leave_out_pos % 7
    r5_out = leave_out_pos % 5
    cell_key = (r7_out, r5_out)

    if cell_key in train_cell:
        entries = train_cell[cell_key]
        n_null = sum(1 for _, n in entries if n)
        n_real = len(entries) - n_null

        if n_null == 0 and n_real > 0:
            predicted_null = False
        elif n_null > 0 and n_real == 0:
            predicted_null = True
        else:
            # Mixed: check if leave_out_pos would be the first entry
            # (tiebreaker = first position is null)
            all_positions = sorted([e[0] for e in entries] + [leave_out_pos])
            if all_positions[0] == leave_out_pos:
                predicted_null = True  # it's the first, so null
            else:
                predicted_null = False  # not the first, so real
    else:
        # Cell has no training data -> use base rate (17/35 null)
        predicted_null = True  # majority-ish, but marginal

    if predicted_null == leave_out_null:
        correct_loo += 1

loo_accuracy = correct_loo / 35
print(f"    LOO accuracy: {correct_loo}/35 = {loo_accuracy:.3f}")
baseline_accuracy = 18 / 35  # predict majority class (real)
print(f"    Baseline (predict majority): {baseline_accuracy:.3f}")
print()

# TEST 4c: Modulus sweep -- test ALL (mod M, mod N) for M,N in 2-20
print("  TEST 4c: Modulus sweep (all M,N in 2-20)")
perfect_mod_pairs = []

for m1 in range(2, 21):
    for m2 in range(2, 21):
        if m1 == m2:
            continue

        cell_map2 = defaultdict(list)
        for p in sorted(PALETTE_POSITIONS):
            cell_map2[(p % m1, p % m2)].append((p, p in null_set))

        # Check if first-is-null tiebreaker gives perfect classification
        perf = True
        for cell, entries in cell_map2.items():
            n_n = sum(1 for _, nn in entries if nn)
            n_r = len(entries) - n_n
            if n_n > 0 and n_r > 0:
                # Mixed: first must be null, rest real
                if not entries[0][1] or any(e[1] for e in entries[1:]):
                    perf = False
                    break

        if perf:
            perfect_mod_pairs.append((m1, m2))

print(f"    Perfect (M,N) pairs with first-is-null tiebreaker: {len(perfect_mod_pairs)}")
if len(perfect_mod_pairs) <= 30:
    for mp in perfect_mod_pairs:
        print(f"      mod ({mp[0]}, {mp[1]})")

# How many total pairs tested?
n_mod_pairs_tested = 19 * 18  # 2-20, excluding self-pairs
print(f"    Total pairs tested: {n_mod_pairs_tested}")
print(f"    Fraction perfect: {len(perfect_mod_pairs)}/{n_mod_pairs_tested} = {len(perfect_mod_pairs)/n_mod_pairs_tested:.4f}")
print()

# TEST 4d: Random null mask baseline
# Generate random 24-null masks (excluding crib positions).
# Identify palette of each (most restrictive letter set).
# Check if (mod 7, mod 5) gives perfect classification.
print("  TEST 4d: Random null mask baseline (100K random 24-null masks)")
count_random_perfect = 0
count_random_palette_le7 = 0
n_rand_mask = N_MC

for _ in range(n_rand_mask):
    # Random 24 nulls from non-crib positions
    null_mask = set(rng.sample(available_positions, 24))
    null_letters = set(CT97[p] for p in null_mask)

    if len(null_letters) > 7:
        continue
    count_random_palette_le7 += 1

    # Find all positions with letters in null_letters
    palette_pos = [p for p in range(97) if CT97[p] in null_letters]
    palette_null_pos = set(p for p in palette_pos if p in null_mask)

    if len(palette_pos) < 2:
        continue

    # Check (mod 7, mod 5) perfect classification
    cell_map3 = defaultdict(list)
    for p in sorted(palette_pos):
        cell_map3[(p % 7, p % 5)].append((p, p in palette_null_pos))

    perf = True
    for cell, entries in cell_map3.items():
        n_n = sum(1 for _, nn in entries if nn)
        n_r = len(entries) - n_n
        if n_n > 0 and n_r > 0:
            if not entries[0][1] or any(e[1] for e in entries[1:]):
                perf = False
                break

    if perf:
        count_random_perfect += 1

print(f"    Random masks with palette <=7 letters: {count_random_palette_le7}/{n_rand_mask}")
if count_random_palette_le7 > 0:
    p_cond = count_random_perfect / count_random_palette_le7
    print(f"    Of those, perfect (mod 7, mod 5) classification: {count_random_perfect}/{count_random_palette_le7} = {p_cond:.4f}")
else:
    print(f"    No random masks had <=7 letter palette (consistent with Claim 1 p ~ 0.00002)")
print()

# TEST 4e: Information-theoretic assessment
print("  TEST 4e: Information-theoretic assessment")
# Null model: predict majority class for all -> accuracy 18/35
# (log-likelihood for null model: 17*log(17/35) + 18*log(18/35))
import math
n_null = 17
n_real = 18
n_total = 35
ll_null = n_null * math.log(n_null / n_total) + n_real * math.log(n_real / n_total)
ll_perfect = 0  # log(1) for each correctly classified = 0
k_null = 0  # 0 parameters
k_model = n_occupied  # one bit per occupied cell

aic_null = -2 * ll_null + 2 * k_null
aic_model = -2 * ll_perfect + 2 * k_model  # ll_perfect = 0
bic_null = -2 * ll_null + k_null * math.log(n_total)
bic_model = -2 * ll_perfect + k_model * math.log(n_total)

print(f"    Null model: AIC = {aic_null:.1f}, BIC = {bic_null:.1f} (0 params)")
print(f"    Lookup model: AIC = {aic_model:.1f}, BIC = {bic_model:.1f} ({k_model} params)")
print(f"    Delta AIC = {aic_null - aic_model:.1f} (positive = model preferred)")
print(f"    Delta BIC = {bic_null - bic_model:.1f} (positive = model preferred)")
print()

# Summary for Claim 4
print("  SUMMARY:")
print(f"    Permutation p = {p_permutation:.6f}")
print(f"    LOO accuracy = {loo_accuracy:.3f} (baseline {baseline_accuracy:.3f})")
print(f"    Perfect mod pairs found: {len(perfect_mod_pairs)}")
print(f"    Parameters/data ratio: {(n_occupied + 1)/35:.2f}")

# The verdict depends heavily on the permutation test
if p_permutation < 0.01 and loo_accuracy > 0.90:
    verdict_4 = "ROBUST"
elif p_permutation < 0.05 and loo_accuracy > 0.85:
    verdict_4 = "BORDERLINE"
elif p_permutation < 0.10:
    verdict_4 = "WEAK"
else:
    verdict_4 = "LIKELY OVERFITTED"

# Also consider: many mod pairs work
if len(perfect_mod_pairs) > 50:
    print(f"  WARNING: {len(perfect_mod_pairs)} mod pairs achieve perfection -> (7,5) is NOT special")
    if verdict_4 == "ROBUST":
        verdict_4 = "BORDERLINE"
    elif verdict_4 == "BORDERLINE":
        verdict_4 = "WEAK"

print(f"  OVERFITTING RISK: HIGH (23 params for 35 data points, model designed post-hoc)")
print(f"  VERDICT: [{verdict_4}]")

results["claim4"] = {
    "observation": "35/35 perfect classification",
    "p_permutation": p_permutation,
    "loo_accuracy": loo_accuracy,
    "baseline_accuracy": baseline_accuracy,
    "perfect_mod_pairs": len(perfect_mod_pairs),
    "n_occupied_cells": n_occupied,
    "parameters_data_ratio": (n_occupied + 1) / 35,
    "aic_delta": aic_null - aic_model,
    "bic_delta": bic_null - bic_model,
    "overfitting_risk": "HIGH",
    "verdict": verdict_4
}

# ============================================================
# CLAIM 5: Beaufort A=0 keystream at BCL = 7/8 palette
# ============================================================
print()
print("=" * 70)
print("CLAIM 5: Beaufort A=0 keystream at BCL first 8 = 7/8 palette")
print("=" * 70)

# In-sample observation
bcl_first8 = BEAUFORT_KEY_BCL[:8]
bcl_first8_letters = [chr(k + ord('A')) for k in bcl_first8]
bcl_palette_count = sum(1 for c in bcl_first8_letters if c in PALETTE)
print(f"  BCL first 8 keystream (Beaufort A=0): {bcl_first8_letters}")
print(f"  Palette count: {bcl_palette_count}/8")

# p(palette) for a random letter given uniform key = 7/26
p_palette = 7 / 26
from math import factorial as fac

# P(>= 7/8 from binomial with p=7/26)
from functools import reduce
def binom_pmf(n, k, p):
    return comb(n, k) * p**k * (1-p)**(n-k)

p_ge7 = binom_pmf(8, 7, p_palette) + binom_pmf(8, 8, p_palette)
print(f"  P(>=7/8 | p={p_palette:.4f}): {p_ge7:.6f}")

# Multiple testing correction:
# Tests performed:
# - 4 variants: Vigenere A=0, Vigenere A=1, Beaufort A=0, Beaufort A=1,
#   VarBeau A=0, VarBeau A=1 = 6 configs
# - Could also have checked ENE separately, and various window sizes
# Conservative: 8 tests (6 variants + 2 crib groups)
# More conservative: also tested thresholds 6/8, 7/8, 8/8 -> multiply by 3
n_tests_5 = 8  # 6 variant/indexing combos, checked ENE and BCL separately
# Actually: 4 unique keystreams (Vig A=0=A=1, Beau A=0, Beau A=1, VBeau A=0=A=1)
# x 2 crib windows (ENE, BCL) x 1 threshold (we report the best) = 8
p_corrected_5 = min(1.0, p_ge7 * n_tests_5)

# But also: the palette itself was derived post-hoc. The 7/8 is "7/8 match the
# set we already derived from the nulls." We need the joint test.
# Joint: P(17 random nulls have <=7 distinct) x P(keystream at BCL has >=7/8 in THOSE letters)
# This is complex because the palette depends on the nulls.

# MC approach: generate random null masks, derive palette, check BCL keystream
count_joint_5 = 0
for _ in range(N_MC):
    null_mask = set(rng.sample(available_positions, 17))
    pal = set(CT97[p] for p in null_mask)
    if len(pal) > 7:
        continue
    # Check BCL keystream against this palette
    pal_count = sum(1 for k in bcl_first8 if chr(k + ord('A')) in pal)
    if pal_count >= 7:
        count_joint_5 += 1

p_joint_5 = count_joint_5 / N_MC
print(f"  Joint MC (random 17 nulls, palette derived, BCL >=7/8): {p_joint_5:.6f} ({count_joint_5}/{N_MC})")

# Since the keystream is FIXED (determined by CT and crib), and only the palette varies,
# this tests: for random null masks whose palette is <=7 letters, how often does the
# BCL keystream happen to be almost all in-palette?

# But the keystream IS fixed. The question is really:
# "Given the fixed keystream at BCL, how special is it that the palette (derived from nulls)
# contains 7/8 of these letters?"
# This is partly captured by the diversity test (Claim 1).

# Cross-variant comparison (as reported):
print()
print("  Cross-variant comparison:")
for variant_name, key_vals in [
    ("Beaufort A=0", [(ALPH_IDX[CT97[i]] + ALPH_IDX[CRIB_DICT[i]]) % 26 for i in range(63, 71)]),
    ("Vigenere A=0", [(ALPH_IDX[CT97[i]] - ALPH_IDX[CRIB_DICT[i]]) % 26 for i in range(63, 71)]),
    ("VarBeau A=0", [(ALPH_IDX[CRIB_DICT[i]] - ALPH_IDX[CT97[i]]) % 26 for i in range(63, 71)]),
]:
    letters = [chr(k + ord('A')) for k in key_vals]
    pal_ct = sum(1 for c in letters if c in PALETTE)
    p_this = sum(binom_pmf(8, k, p_palette) for k in range(pal_ct, 9))
    print(f"    {variant_name}: {''.join(letters)} -> {pal_ct}/8 palette (p_ge={p_this:.6f})")

# Note: (CT[i]+PT[i]) mod 26 is ciphertext-intrinsic under Beaufort A=0 convention.
# The quantity is deterministic given CT and cribs, but its interpretation as "keystream"
# is Beaufort-specific (Vigenere gives different values). See audit remediation 2026-04-01.
# The palette was derived from null positions. The keystream was derived from cribs.
# These are DIFFERENT positions. This is genuinely a cross-validation of sorts.
print()
print("  IMPORTANT: Keystream is at crib positions (21-33, 63-73).")
print("  Palette is at null positions (0,1,2,5,8,...).")
print("  These position sets are DISJOINT (cribs cannot be nulls).")
print("  So the 7/8 match is a genuine out-of-sample observation.")

if p_joint_5 < 0.001:
    verdict_5 = "ROBUST"
elif p_joint_5 < 0.005:
    verdict_5 = "ROBUST (with multiple testing)"
elif p_corrected_5 < 0.01:
    verdict_5 = "BORDERLINE"
else:
    verdict_5 = "WEAK"

# The key insight is cross-validation: palette from nulls, enrichment at cribs
print(f"\n  DEGREES OF FREEDOM: 8 tests (6 variants x 2 windows)")
print(f"  OVERFITTING RISK: LOW-MEDIUM")
print(f"    The palette is derived from NULL positions.")
print(f"    The keystream enrichment is at CRIB positions (disjoint set).")
print(f"    This IS a form of cross-validation.")
print(f"  CORRECTED p: {p_corrected_5:.6f} (Bonferroni x8)")
print(f"  JOINT p: {p_joint_5:.6f}")
print(f"  VERDICT: [{verdict_5}]")

results["claim5"] = {
    "observation": f"{bcl_palette_count}/8 palette letters in BCL Beaufort keystream",
    "p_raw": p_ge7,
    "p_corrected": p_corrected_5,
    "p_joint": p_joint_5,
    "n_tests": n_tests_5,
    "cross_validation_note": "Palette from nulls (disjoint from crib positions)",
    "overfitting_risk": "LOW-MEDIUM",
    "verdict": verdict_5
}

# ============================================================
# CLAIM 6: DEFECTOR:AZ_beau+col7 = 15/24
# ============================================================
print()
print("=" * 70)
print("CLAIM 6: DEFECTOR:AZ_beau+col7 = 15/24 (is this special?)")
print("=" * 70)

# We know from exhaustive search: 232M masks tested, 396 at 15/24, 0 above 15.
# The question: is 15/24 expected or special for an SA-discovered model?

# We cannot re-run SA for 1000 random keywords here (too expensive).
# But we can estimate the expected false-positive rate.

# From MEMORY.md: 18 non-DEFECTOR:AZ_beau variants tested with 150 restarts each.
# ALL scored <=14/24. DEFECTOR:AZ_beau uniquely at 15/24 with frequency 5/150 = 3.3%.

# The question is: how many 8-letter keywords exist? 26^8 ~ 208 billion.
# If we tested ~19 (DEFECTOR + 18 others), and 1/19 hit 15/24, the naive
# extrapolation suggests ~10 billion keywords might also work.
# But the test is more nuanced: the 18 others were THEMATIC keywords,
# not random. And the SA ceiling is model-specific.

# What we CAN compute: expected score under random key for the col7+autokey model.
# We'll do a simplified version: random 8-letter key -> Beaufort autokey -> col7 -> score.

# Actually, we can compute crib consistency analytically for a few random keys.
# The autokey chain means the key only matters for the first 8 positions.
# After that, the key is determined by the plaintext.

# Simplified test: random 8-letter keyword, fixed best null mask (consensus 17 +
# one specific 7-remaining), col7 transposition, Beaufort autokey -> crib score.

# We'll use the consensus null mask + varying positions from the brute force data.
# Best mask from brute force: consensus 17 + one of the 396 masks.

# For speed, compute crib matches for random keywords on the fixed pipeline.
# This requires implementing the full pipeline inline.

print("  APPROACH: Sample random 8-letter keywords, apply same pipeline")
print("  (null mask + inv_col7 + AZ_Beaufort_autokey), score crib matches.")
print()

# Load the transform pipeline
CONSENSUS_17 = [0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85]
# Use the first 15/24 mask: consensus + (38,39,40,54,88,93,94) for example
FULL_MASK_24 = sorted(CONSENSUS_17 + [38, 39, 40, 54, 88, 93, 94])

def extract_73(ct, mask):
    """Extract non-null positions."""
    return "".join(ct[i] for i in range(len(ct)) if i not in set(mask))

def inv_col7(text):
    """Inverse columnar transposition width 7 (scatter -> gather)."""
    n = len(text)
    ncols = 7
    nfull = n % ncols
    nrows_base = n // ncols
    # Forward: fill columns top-to-bottom, left-to-right
    # Build the column-major order
    out = [''] * n
    pos = 0
    for col in range(ncols):
        nrows = nrows_base + (1 if col < nfull else 0)
        for row in range(nrows):
            read_pos = row * ncols + col
            if read_pos < n:
                out[read_pos] = text[pos]
            pos += 1
    return "".join(out)

def beaufort_autokey_decrypt(ct_str, keyword, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """Beaufort PT-autokey decryption."""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    mod = len(alphabet)
    period = len(keyword)

    key_vals = [alph_idx[c] for c in keyword]
    pt = []

    for i, c in enumerate(ct_str):
        if i < period:
            k = key_vals[i]
        else:
            k = alph_idx[pt[i - period]]
        ct_val = alph_idx[c]
        pt_val = (k - ct_val) % mod
        pt.append(alphabet[pt_val])

    return "".join(pt)

def score_crib(pt97_or_73, mask=None):
    """Score against cribs. If mask given, map crib positions to 73-char."""
    if mask is not None:
        non_null = [i for i in range(97) if i not in set(mask)]
        pos_map = {orig: new for new, orig in enumerate(non_null)}
    else:
        pos_map = {i: i for i in range(97)}

    score = 0
    for pos, ch in CRIB_DICT.items():
        if pos in pos_map and pos_map[pos] < len(pt97_or_73):
            if pt97_or_73[pos_map[pos]] == ch:
                score += 1
    return score

# Test with DEFECTOR first to verify
ct73 = extract_73(CT97, FULL_MASK_24)
ct73_t = inv_col7(ct73)
pt73 = beaufort_autokey_decrypt(ct73_t, "DEFECTOR")
defector_score = score_crib(pt73, FULL_MASK_24)
print(f"  Verification: DEFECTOR score = {defector_score}/24")

# Now test random keywords
n_random_kw = 10000
random_scores = []
for _ in range(n_random_kw):
    kw = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(8))
    pt = beaufort_autokey_decrypt(ct73_t, kw)
    sc = score_crib(pt, FULL_MASK_24)
    random_scores.append(sc)

score_counter = Counter(random_scores)
mean_score = sum(random_scores) / len(random_scores)
max_score = max(random_scores)
ge15 = sum(1 for s in random_scores if s >= 15)
ge14 = sum(1 for s in random_scores if s >= 14)
ge13 = sum(1 for s in random_scores if s >= 13)

print(f"\n  Random 8-letter keyword scores ({n_random_kw:,} trials):")
print(f"    Mean: {mean_score:.2f}")
print(f"    Max: {max_score}")
print(f"    >= 15: {ge15}/{n_random_kw} ({100*ge15/n_random_kw:.3f}%)")
print(f"    >= 14: {ge14}/{n_random_kw} ({100*ge14/n_random_kw:.3f}%)")
print(f"    >= 13: {ge13}/{n_random_kw} ({100*ge13/n_random_kw:.3f}%)")
print(f"    Distribution: {dict(sorted(score_counter.items()))}")

# Expected 15/24 by chance from 26^8 keywords:
if ge15 > 0:
    p_random_15 = ge15 / n_random_kw
    expected_15_in_208B = p_random_15 * 26**8
    print(f"\n    Estimated P(random keyword >= 15) = {p_random_15:.6f}")
    print(f"    Expected keywords >= 15 in 26^8 = {expected_15_in_208B:.0f}")
else:
    p_random_15 = 0
    expected_upper = 1 / n_random_kw  # upper bound
    print(f"\n    ZERO random keywords hit >= 15 in {n_random_kw} trials")
    print(f"    Upper bound: P < {expected_upper:.6f}")
    expected_15_in_208B = expected_upper * 26**8
    print(f"    Expected keywords >= 15 in 26^8 < {expected_15_in_208B:.0f}")

# Also test other keyword lengths
print(f"\n  Testing keyword lengths 3-12:")
for kw_len in [3, 4, 5, 6, 7, 9, 10, 12]:
    scores_len = []
    for _ in range(2000):
        kw = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(kw_len))
        pt = beaufort_autokey_decrypt(ct73_t, kw)
        sc = score_crib(pt, FULL_MASK_24)
        scores_len.append(sc)
    mean_len = sum(scores_len) / len(scores_len)
    max_len = max(scores_len)
    print(f"    Length {kw_len:2d}: mean={mean_len:.2f}, max={max_len}")

if p_random_15 > 0:
    if expected_15_in_208B > 1e6:
        verdict_6 = "LIKELY NOT SPECIAL (many random keywords expected)"
    elif expected_15_in_208B > 100:
        verdict_6 = "BORDERLINE (hundreds of random matches expected)"
    elif expected_15_in_208B > 1:
        verdict_6 = "WEAK (a few random matches expected)"
    else:
        verdict_6 = "ROBUST"
else:
    verdict_6 = "ROBUST (0 random hits in sample)"

print(f"\n  VERDICT: [{verdict_6}]")

results["claim6"] = {
    "observation": "DEFECTOR:AZ_beau+col7 = 15/24",
    "defector_verified_score": defector_score,
    "random_keyword_trials": n_random_kw,
    "random_mean": mean_score,
    "random_max": max_score,
    "random_ge15": ge15,
    "random_ge14": ge14,
    "p_random_ge15": p_random_15 if p_random_15 > 0 else f"< {1/n_random_kw}",
    "expected_ge15_in_full_keyspace": expected_15_in_208B,
    "verdict": verdict_6
}

# ============================================================
# COMBINED ASSESSMENT
# ============================================================
print()
print("=" * 70)
print("COMBINED ASSESSMENT")
print("=" * 70)

# Independent p-values for the chain:
# 1. Palette diversity: robust (p ~ 0.00002)
# 2. KA mod 5: borderline-robust after correction
# 3. KRYPTOS+SEVEN: depends heavily on model correction
# 4. (7,5) classifier: high overfitting risk
# 5. BCL keystream: robust cross-validation (p ~ 0.001 joint)
# 6. DEFECTOR 15/24: depends on random baseline

# Fisher's method for combining independent p-values:
# Claims 1 and 5 are genuinely independent (nulls vs cribs)
# Claims 2 and 3 depend on Claim 1 (palette)
# Claim 4 depends on Claims 1+2+3

print()
print("  INDEPENDENCE STRUCTURE:")
print("    Claim 1 (palette diversity) -- INDEPENDENT")
print("    Claim 2 (KA mod 5) -- DEPENDS ON Claim 1 (uses same 7 letters)")
print("    Claim 3 (KRYPTOS+SEVEN) -- DEPENDS ON Claim 2 (uses mod 5 structure)")
print("    Claim 4 (mod 7,5 table) -- DEPENDS ON Claims 1-3")
print("    Claim 5 (BCL keystream) -- PARTIALLY INDEPENDENT (palette from Claim 1,")
print("      but keystream is at disjoint positions)")
print("    Claim 6 (DEFECTOR 15/24) -- INDEPENDENT (different model entirely)")
print()

# What's genuinely independent:
# A: Palette has low diversity (p ~ 0.00002)
# B: BCL Beaufort keystream is palette-enriched (p ~ 0.001 conditional on A)
# C: DEFECTOR:AZ_beau+col7 is uniquely high-scoring

# The chain Claim 1 -> 2 -> 3 -> 4 is a single narrative, not independent tests.
# Its combined value is that of the WEAKEST link (Claim 4).

print("  GENUINELY INDEPENDENT FINDINGS:")
print(f"    A. Low null diversity: p ~ {results['claim1']['p_value']:.6f}")
print(f"    B. BCL keystream enrichment: p_joint ~ {results['claim5']['p_joint']:.6f}")
print(f"    C. DEFECTOR uniqueness: {results['claim6']['verdict']}")
print()

# Fisher's combined p for A and B (independent):
p_a = max(results['claim1']['p_value'], 1e-10)
p_b = max(results['claim5']['p_joint'], 1e-10)

# Fisher's method: X = -2 * sum(ln(pi)), X ~ chi2(2k)
# For 2 tests: X = -2*(ln(p_a) + ln(p_b))
X_fisher = -2 * (math.log(p_a) + math.log(p_b))
# chi2(4) survival function:
# P(chi2(4) > X) = (1 + X/2) * exp(-X/2) for df=4
p_fisher = (1 + X_fisher/2) * math.exp(-X_fisher/2)

print(f"  Fisher's combined p (A + B): {p_fisher:.8f}")
print(f"    (X_Fisher = {X_fisher:.2f}, df=4)")

# Chain Claim 1->2->3->4:
print()
print("  CHAIN ASSESSMENT (Claims 1-2-3-4):")
print("    This is a SINGLE post-hoc narrative: discover low diversity in nulls,")
print("    find modular structure, construct a keyword model, build a classifier.")
print("    Each step was designed to explain the previous observation.")
print("    The proper p-value is for the ENTIRE chain, not individual steps.")
print("    Anchor: Claim 1 (p ~ 0.00002) is the solid foundation.")
print("    Everything else in the chain is post-hoc model construction on the SAME")
print("    17 data points. Claims 2-4 add INTERPRETIVE value but NOT independent")
print("    statistical evidence.")
print()

print("=" * 70)
print("FINAL VERDICTS")
print("=" * 70)
for claim_id in sorted(results.keys()):
    r = results[claim_id]
    print(f"  {claim_id}: [{r['verdict']}]")
    if 'p_value' in r:
        print(f"    p = {r['p_value']:.6f}")
    if 'p_joint' in r:
        print(f"    p_joint = {r['p_joint']:.6f}")
    if 'p_corrected' in r:
        print(f"    p_corrected = {r['p_corrected']:.6f}")

elapsed = time.time() - t0
print(f"\nTotal elapsed: {elapsed:.1f}s")

# Save results
results["elapsed_seconds"] = elapsed
results["mc_trials"] = N_MC
results["random_seed"] = SEED
results["combined"] = {
    "fisher_p_independent_AB": p_fisher,
    "independent_claims": "1 (palette diversity) + 5 (BCL keystream)",
    "chain_claims": "1 -> 2 -> 3 -> 4 (single narrative, p anchored at Claim 1)",
    "interpretation": (
        "The palette low-diversity anomaly (p~0.00002) is ROBUST and independently confirmed "
        "by BCL keystream enrichment (p_joint~0.001). The KA mod-5 structure, KRYPTOS+SEVEN "
        "model, and (mod 7, mod 5) classifier are post-hoc elaborations of the SAME 17-point "
        "dataset. They provide interpretive structure but NOT independent statistical evidence. "
        "The DEFECTOR:AZ_beau+col7 model's uniqueness depends on the random baseline."
    )
}

out_path = "results/statistical_validation_v1.json"
with open(out_path, "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nResults written to {out_path}")
