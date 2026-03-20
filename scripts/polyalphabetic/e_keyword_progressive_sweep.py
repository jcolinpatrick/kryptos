#!/usr/bin/env python3
"""
Cipher:     Beaufort/Vigenere progressive keyword
Family:     polyalphabetic
Status:     active
Keyspace:   ~200K words × 30 functions × 2 alphabets × 2 targets = ~24M
Last run:   2026-03-20
Best score: TBD

Two-part analysis:
  Part 1: Resolve 7 varying null positions from the 8 stego table-generating words
  Part 2: Keyword × progressive function sweep on CT97 and CT73
"""

import sys, os, json, time
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, KRYPTOS_ALPHABET, ALPH, ALPH_IDX, MOD
)

# ── Constants ────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
PALETTE = frozenset("BGIKOWZ")

# 17 consensus null positions (from MEMORY.md)
CONSENSUS_NULLS = frozenset({0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85})

# 7 varying positions — these 16 candidates must yield exactly 7 nulls
VARYING_CANDIDATES = sorted({38, 39, 40, 41, 42, 43, 44, 45, 55, 56, 87, 88, 93, 94, 95, 96})

# Crib positions
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_POS_SET = frozenset(CRIB_POS)

# Required Beaufort keystream at crib positions: k = (CT_AZ + PT_AZ) mod 26
REQUIRED_KEY_97 = {}
for pos in CRIB_POS:
    ct_idx = ALPH_IDX[CT[pos]]
    pt_idx = ALPH_IDX[CRIB_DICT[pos]]
    REQUIRED_KEY_97[pos] = (ct_idx + pt_idx) % 26  # Beaufort A=0

# Also compute Vigenere keystream: k = (CT_AZ - PT_AZ) mod 26
REQUIRED_VIG_97 = {}
for pos in CRIB_POS:
    ct_idx = ALPH_IDX[CT[pos]]
    pt_idx = ALPH_IDX[CRIB_DICT[pos]]
    REQUIRED_VIG_97[pos] = (ct_idx - pt_idx) % 26

print("=" * 70)
print("K4 Keyword Progressive Function Sweep")
print("=" * 70)
print(f"CT: {CT}")
print(f"Crib positions: {CRIB_POS}")
print(f"Required Beaufort key (AZ): {[REQUIRED_KEY_97[p] for p in CRIB_POS]}")
print(f"  = {[ALPH[REQUIRED_KEY_97[p]] for p in CRIB_POS]}")
print(f"Required Vigenere key (AZ): {[REQUIRED_VIG_97[p] for p in CRIB_POS]}")
print(f"  = {[ALPH[REQUIRED_VIG_97[p]] for p in CRIB_POS]}")
print()

# ═══════════════════════════════════════════════════════════════════════
# PART 1: Stego Table-Generating Words — Vary 7 positions
# ═══════════════════════════════════════════════════════════════════════

print("=" * 70)
print("PART 1: Stego Table-Generating Words → Null Mask Prediction")
print("=" * 70)
print()

# The 8 matching rules from results/mod35_table_derivation.json
# Format: (word, alphabet, variant, null_letters_set)
TABLE_RULES = [
    ("TOWER", "AZ", "vig",   set("CDNRSTUVYZ")),    # TABLEAU approach, 10 null letters
    ("TOWER", "AZ", "vbeau", set("BCFHINXY")),       # TABLEAU approach (corrected from file: 7)
    ("CHART", "AZ", "beau",  set("DIMNOPQTUY")),     # TABLEAU approach, 10 null letters
    ("LAYER", "KA", "vig",   set("DHIJKPQRYZ")),     # KA_CIPHER approach, 10 null letters
    ("LAYER", "KA", "vbeau", set("DEFJKRSWXZ")),     # KA_CIPHER approach, 10 null letters
    ("TOWER", "AZ", "vig_ka", set("CDNTVYZ")),       # KA_CIPHER: AZ_vig, 7 null letters
    ("TOWER", "AZ", "vbeau_ka", set("BCFHNXY")),     # KA_CIPHER: AZ_vbeau, 7 null letters
    ("CHART", "AZ", "beau_ka", set("DIMPQTUY")),     # KA_CIPHER: AZ_beau, 8 null letters
]

# Recompute from scratch to be sure
KRYPTOS_WORD = "KRYPTOS"
def compute_cipher_output(kw_char, word_char, alph_name, variant):
    """Compute the cipher output for KRYPTOS[pos%7] op WORD[pos%5]."""
    if alph_name == "AZ":
        a = ALPH_IDX[kw_char]
        b = ALPH_IDX[word_char]
    else:  # KA
        a = KA_IDX[kw_char]
        b = KA_IDX[word_char]

    if variant == "vig":
        return (a + b) % 26
    elif variant == "beau":
        return (a - b) % 26  # Beaufort: K = (A - B) mod 26
    elif variant == "vbeau":
        return (b - a) % 26  # Variant Beaufort: K = (B - A) mod 26
    else:
        raise ValueError(f"Unknown variant: {variant}")

def classify_position(pos, word, alph_name, variant, null_letters):
    """Given the rule, is position pos null or real?"""
    kw_char = KRYPTOS_WORD[pos % 7]
    w_char = word[pos % 5]
    output_val = compute_cipher_output(kw_char, w_char, alph_name, variant)
    if alph_name == "AZ":
        output_char = ALPH[output_val]
    else:
        output_char = KA[output_val]
    return output_char in null_letters

# First, verify each rule on the 17 consensus nulls
# All 35 palette positions and their consensus status
palette_positions = [p for p in range(97) if CT[p] in PALETTE]
assert len(palette_positions) == 35, f"Expected 35 palette positions, got {len(palette_positions)}"

# Build the ground truth for all 35 palette positions
# Consensus nulls at these palette positions
palette_null_status = {}
for p in palette_positions:
    if p in CONSENSUS_NULLS:
        palette_null_status[p] = True  # null
    else:
        palette_null_status[p] = False  # real

# Now for each rule, recompute and verify on the 35 palette positions
# Then predict the 7 varying positions
print("Recomputing 8 table rules from scratch...")
print()

# The rules as extracted: we need the 5 unique word+alph+variant combos
# from the results file. Let me reconstruct them properly.
# The results file shows TABLEAU and KA_CIPHER approaches are different:
# - TABLEAU: takes cipher output VALUE (0-25), checks if in null_outs set (integers)
# - KA_CIPHER: takes cipher output LETTER (in some alphabet), checks if in null_letters set

# Let me reimplement both approaches
def tableau_cipher(kw_char, word_char, variant):
    """Tableau approach: use AZ indices, get output as integer."""
    a = ALPH_IDX[kw_char]
    b = ALPH_IDX[word_char]
    if variant == "vig":
        return (a + b) % 26
    elif variant == "beau":
        return (a - b) % 26  # Beaufort convention: (key - plaintext) or (a - b)
    elif variant == "vbeau":
        return (b - a) % 26
    raise ValueError(variant)

def ka_cipher(kw_char, word_char, alph_name, variant):
    """KA cipher approach: use specified alphabet indices, get output as letter in that alphabet."""
    if alph_name == "AZ":
        a = ALPH_IDX[kw_char]
        b = ALPH_IDX[word_char]
    else:
        a = KA_IDX[kw_char]
        b = KA_IDX[word_char]

    if variant == "vig":
        val = (a + b) % 26
    elif variant == "beau":
        val = (a - b) % 26
    elif variant == "vbeau":
        val = (b - a) % 26
    else:
        raise ValueError(variant)

    if alph_name == "AZ":
        return ALPH[val]
    else:
        return KA[val]

# Reconstruct exact rules from the JSON
# TABLEAU matches (use integer null_outs):
TABLEAU_RULES = [
    ("TOWER", "vig",   {2, 3, 13, 19, 21, 24, 25}, {17, 18, 20}),   # null_outs
    ("TOWER", "vbeau", {1, 2, 5, 7, 13, 23, 24},   {6, 8, 9}),       # null_outs
    ("CHART", "beau",  {3, 8, 12, 15, 16, 19, 20, 24}, {12, 14, 15}), # null_outs (note overlap!)
]

# KA_CIPHER matches (use letter null_letters):
KA_CIPHER_RULES = [
    ("LAYER", "KA", "vig",   set("DHIJKPQRYZ")),
    ("LAYER", "KA", "vbeau", set("DEFJKRSWXZ")),
    ("TOWER", "AZ", "vig",   set("CDNTVYZ")),
    ("TOWER", "AZ", "vbeau", set("BCFHNXY")),
    ("CHART", "AZ", "beau",  set("DIMPQTUY")),
]

# Wait — looking at the JSON more carefully:
# TABLEAU entries have integer null_outs and mixed_outs
# KA_CIPHER entries have letter null_letters and real_letters
# But ALL produce the same 7×5 table. Let me just use the approach from the original script.

# Simpler approach: for each rule, compute the output for all 35 palette positions
# and check against the known classification.

def evaluate_rule_on_positions(positions, word, approach, alph_name, variant, null_set, mixed_set=None):
    """
    Evaluate a stego rule on a set of positions.
    Returns dict: pos -> predicted_null (True/False)
    For mixed outputs, the "first occurrence is null" tiebreaker applies.
    """
    predictions = {}
    # Track which cells we've seen (for mixed tiebreaker)
    seen_cells = {}  # (pos%7, pos%5) -> first_pos

    # Process positions in order (for tiebreaker)
    for p in sorted(positions):
        kw_char = KRYPTOS_WORD[p % 7]
        w_char = word[p % 5]
        cell = (p % 7, p % 5)

        if approach == "TABLEAU":
            output = tableau_cipher(kw_char, w_char, variant)
            is_null_output = output in null_set
            is_mixed = mixed_set is not None and output in mixed_set
        else:  # KA_CIPHER
            output_letter = ka_cipher(kw_char, w_char, alph_name, variant)
            is_null_output = output_letter in null_set
            is_mixed = False  # KA_CIPHER doesn't have mixed — uses letter classification

        if is_mixed:
            # Tiebreaker: first occurrence in this cell is null
            if cell not in seen_cells:
                predictions[p] = True  # null
                seen_cells[cell] = p
            else:
                predictions[p] = False  # real
        else:
            predictions[p] = is_null_output
            if cell not in seen_cells:
                seen_cells[cell] = p

    return predictions

# Actually, looking at this more carefully, the table derivation found rules that
# perfectly classify the 26 OCCUPIED cells (not 35 positions — the 7×5 table has
# 26 occupied cells). The table itself is what classifies all 35 positions.
# The rules generate the TABLE, and the table + tiebreaker classify positions.

# Let me take the simpler approach: just compute the 7×5 table from each rule,
# then use it to predict ALL positions including the varying ones.

# Build the ground truth 7×5 table
# N=1 (null), R=0 (real), from the memory file
GROUND_TRUTH_TABLE = {
    # (row, col): 1=null, 0=real, None=empty
    (0, 0): None,  # mixed -> first=null
    (0, 1): 0,     # R
    (0, 2): 0,     # R
    (0, 3): None,  # empty (-)
    (0, 4): 1,     # N
    (1, 0): 1,     # N
    (1, 1): 1,     # N
    (1, 2): None,  # empty (-)
    (1, 3): 1,     # N
    (1, 4): None,  # empty (-)
    (2, 0): 0,     # R
    (2, 1): 0,     # R
    (2, 2): 1,     # N
    (2, 3): None,  # mixed -> first=null
    (2, 4): None,  # empty (-)
    (3, 0): 0,     # R
    (3, 1): 0,     # R
    (3, 2): 1,     # N
    (3, 3): 0,     # R
    (3, 4): 1,     # N
    (4, 0): None,  # empty (-)
    (4, 1): 0,     # R
    (4, 2): None,  # empty (-)
    (4, 3): 0,     # R
    (4, 4): 1,     # N
    (5, 0): 1,     # N
    (5, 1): None,  # empty (-)
    (5, 2): None,  # mixed -> first=null
    (5, 3): None,  # empty (-)
    (5, 4): 0,     # R
    (6, 0): 1,     # N
    (6, 1): None,  # empty (-)
    (6, 2): 0,     # R
    (6, 3): 0,     # R
    (6, 4): 0,     # R
}

def compute_table_from_rule(word, approach, alph_name, variant, null_set):
    """Compute the 7×5 N/R table from a rule. Returns dict (r,c) -> 1(null)/0(real) for occupied cells."""
    table = {}
    for r in range(7):
        for c in range(5):
            kw_char = KRYPTOS_WORD[r]
            w_char = word[c]
            if approach == "TABLEAU":
                output = tableau_cipher(kw_char, w_char, variant)
                table[(r, c)] = 1 if output in null_set else 0
            else:
                output_letter = ka_cipher(kw_char, w_char, alph_name, variant)
                table[(r, c)] = 1 if output_letter in null_set else 0
    return table

def predict_position(pos, table):
    """Predict null/real for a position using the 7×5 table + first-occurrence tiebreaker."""
    cell = (pos % 7, pos % 5)
    return table[cell] == 1  # 1 = null

# Now evaluate each rule
print("─" * 70)
print("Verifying 8 rules on consensus null positions and predicting varying positions")
print("─" * 70)

# Reconstruct the full rule set more carefully
ALL_RULES = []

# From the JSON results: TABLEAU matches
# TOWER vig: null_outs=[2, 3, 13, 19, 21, 24, 25]
ALL_RULES.append({
    "word": "TOWER", "approach": "TABLEAU", "alph": "AZ", "variant": "vig",
    "null_set": {2, 3, 13, 19, 21, 24, 25}
})
# TOWER vbeau: null_outs=[1, 2, 5, 7, 13, 23, 24]
ALL_RULES.append({
    "word": "TOWER", "approach": "TABLEAU", "alph": "AZ", "variant": "vbeau",
    "null_set": {1, 2, 5, 7, 13, 23, 24}
})
# CHART beau: null_outs=[3, 8, 12, 15, 16, 19, 20, 24]
ALL_RULES.append({
    "word": "CHART", "approach": "TABLEAU", "alph": "AZ", "variant": "beau",
    "null_set": {3, 8, 12, 15, 16, 19, 20, 24}
})
# KA_CIPHER matches
ALL_RULES.append({
    "word": "LAYER", "approach": "KA_CIPHER", "alph": "KA", "variant": "vig",
    "null_set": set("DHIJKPQRYZ")
})
ALL_RULES.append({
    "word": "LAYER", "approach": "KA_CIPHER", "alph": "KA", "variant": "vbeau",
    "null_set": set("DEFJKRSWXZ")
})
ALL_RULES.append({
    "word": "TOWER", "approach": "KA_CIPHER", "alph": "AZ", "variant": "vig",
    "null_set": set("CDNTVYZ")
})
ALL_RULES.append({
    "word": "TOWER", "approach": "KA_CIPHER", "alph": "AZ", "variant": "vbeau",
    "null_set": set("BCFHNXY")
})
ALL_RULES.append({
    "word": "CHART", "approach": "KA_CIPHER", "alph": "AZ", "variant": "beau",
    "null_set": set("DIMPQTUY")
})

part1_results = []

for rule_idx, rule in enumerate(ALL_RULES):
    word = rule["word"]
    approach = rule["approach"]
    alph = rule["alph"]
    variant = rule["variant"]
    null_set = rule["null_set"]

    label = f"{word}:{alph}_{variant}" + (f" ({approach})" if approach == "TABLEAU" else "")

    # Compute the full 7×5 table
    table = compute_table_from_rule(word, approach, alph, variant, null_set)

    # Verify against ground truth (occupied cells only)
    occupied = [(r, c) for (r, c), v in GROUND_TRUTH_TABLE.items() if v is not None]
    matches = sum(1 for (r, c) in occupied if table[(r, c)] == GROUND_TRUTH_TABLE[(r, c)])
    total = len(occupied)

    # Verify on the 17 consensus null positions (palette only)
    palette_correct = 0
    palette_total = 0
    for p in palette_positions:
        if p in CONSENSUS_NULLS:
            expected = True
        elif p not in CONSENSUS_NULLS and p not in {pos for pos in VARYING_CANDIDATES}:
            expected = False
        else:
            continue  # skip varying
        palette_total += 1

        predicted = predict_position(p, table)
        # Apply tiebreaker for mixed cells
        cell = (p % 7, p % 5)
        # Check if this cell is mixed (has both null and real palette positions)
        cell_positions = [pp for pp in palette_positions if pp % 7 == cell[0] and pp % 5 == cell[1]]
        if len(cell_positions) > 1:
            # Mixed cell — first is null, rest are real
            if p == min(cell_positions):
                predicted = True
            else:
                predicted = False

        if predicted == expected:
            palette_correct += 1

    # Now predict the varying positions
    # The varying positions are NOT palette positions (per MEMORY: "varying positions are NOT palette characters")
    # So the stego table can still predict them IF we extend the table to non-palette positions
    # Actually, looking more carefully: the table classifies ALL positions, not just palette ones
    # The table says: for ANY position p, if table[p%7, p%5] = null, the position is null

    varying_predictions = {}
    for p in VARYING_CANDIDATES:
        cell = (p % 7, p % 5)
        is_null = table[cell] == 1

        # For mixed cells, apply tiebreaker across ALL positions (not just palette)
        # Need to find all positions 0-96 that map to this cell
        all_cell_positions = [pp for pp in range(97) if pp % 7 == cell[0] and pp % 5 == cell[1]]
        # Check if this cell has BOTH null and real positions among consensus
        cell_consensus_status = set()
        for pp in all_cell_positions:
            if pp in CONSENSUS_NULLS:
                cell_consensus_status.add("null")
            elif pp not in {pos for pos in VARYING_CANDIDATES}:
                cell_consensus_status.add("real")

        varying_predictions[p] = is_null

    predicted_nulls = sorted([p for p, v in varying_predictions.items() if v])
    predicted_reals = sorted([p for p, v in varying_predictions.items() if not v])

    # Check: do predicted nulls remove any crib position?
    total_nulls = CONSENSUS_NULLS | set(predicted_nulls)
    crib_conflicts = total_nulls & CRIB_POS_SET

    # Must have exactly 24 nulls total (97 - 73 = 24)
    n_nulls_total = len(CONSENSUS_NULLS) + len(predicted_nulls)

    # Check CT characters at predicted null positions
    null_chars = [CT[p] for p in predicted_nulls]

    result = {
        "rule": label,
        "word": word,
        "approach": approach,
        "alphabet": alph,
        "variant": variant,
        "table_match": f"{matches}/{total}",
        "palette_correct": f"{palette_correct}/{palette_total}",
        "predicted_null_positions": predicted_nulls,
        "predicted_real_positions": predicted_reals,
        "null_chars": null_chars,
        "total_nulls": n_nulls_total,
        "crib_conflicts": sorted(crib_conflicts) if crib_conflicts else [],
        "valid": len(crib_conflicts) == 0 and n_nulls_total == 24,
    }
    part1_results.append(result)

    valid_str = "VALID" if result["valid"] else "INVALID"
    conflict_str = f" CRIB CONFLICT at {sorted(crib_conflicts)}" if crib_conflicts else ""

    print(f"\n  Rule {rule_idx+1}: {label}")
    print(f"    Table cells: {matches}/{total} match ground truth")
    print(f"    Palette verification: {palette_correct}/{palette_total}")
    print(f"    Predicted nulls from varying: {predicted_nulls} = {null_chars}")
    print(f"    Predicted reals from varying: {predicted_reals}")
    print(f"    Total nulls: 17 + {len(predicted_nulls)} = {n_nulls_total} (need 24)")
    print(f"    [{valid_str}]{conflict_str}")

# Also: check which (pos%7, pos%5) cells the varying candidates map to
print("\n" + "─" * 70)
print("Varying candidate position cells:")
print("─" * 70)
for p in VARYING_CANDIDATES:
    cell = (p % 7, p % 5)
    ct_char = CT[p]
    in_palette = ct_char in PALETTE
    in_crib = p in CRIB_POS_SET
    print(f"  pos={p:2d}  CT[{p}]={ct_char}  (p%7,p%5)={cell}  "
          f"KRYPTOS[{cell[0]}]={KRYPTOS_WORD[cell[0]]}  SEVEN[{cell[1]}]={'SEVEN'[cell[1]]}  "
          f"palette={'Y' if in_palette else 'N'}  crib={'Y' if in_crib else 'N'}")

# Summary of unique predictions across all 8 rules
print("\n" + "─" * 70)
print("Summary: Unique null mask predictions across all 8 rules")
print("─" * 70)
unique_masks = {}
for r in part1_results:
    key = tuple(r["predicted_null_positions"])
    if key not in unique_masks:
        unique_masks[key] = []
    unique_masks[key].append(r["rule"])

for mask, rules in sorted(unique_masks.items()):
    all_nulls = sorted(CONSENSUS_NULLS | set(mask))
    total = 17 + len(mask)
    valid = total == 24 and not (set(mask) & CRIB_POS_SET)
    print(f"\n  Null positions from varying: {list(mask)} ({len(mask)} positions)")
    print(f"    Total nulls: {total}")
    print(f"    Valid: {valid}")
    print(f"    Rules: {rules}")


# ═══════════════════════════════════════════════════════════════════════
# PART 2: Keyword × Progressive Function Sweep — OPTIMIZED
# ═══════════════════════════════════════════════════════════════════════

print("\n\n" + "=" * 70)
print("PART 2: Keyword × Progressive Function Sweep")
print("=" * 70)

# ── Precompute required values at each crib position ──────────────────
# For each function type, precompute the position-dependent addend/multiplier
# so the inner loop only needs K-dependent values.

# Golden ratio multiples for positions
GOLDEN = 1.618033988749895
GOLDEN_POS = {pos: int(pos * GOLDEN) for pos in CRIB_POS}

def make_progressive_functions():
    """Return list of (name, func) where func(K, i, p) -> key_value mod 26.
    These are used for correctness verification and CT73 (smaller keyword set)."""
    funcs = []
    funcs.append(("periodic",              lambda K,i,p: K[i%p]))
    funcs.append(("linear_progressive",    lambda K,i,p: (K[i%p] + i) % 26))
    funcs.append(("step_per_cycle",        lambda K,i,p: (K[i%p] + i//p) % 26))
    funcs.append(("kw_modulated_linear",   lambda K,i,p: (K[i%p] + i*K[(i+1)%p]) % 26))
    funcs.append(("cumulative_kw_sum",     lambda K,i,p: (K[i%p] + sum(K[j] for j in range(i%p))) % 26))
    funcs.append(("adjacent_sum",          lambda K,i,p: (K[i%p] + K[(i+1)%p]) % 26))
    funcs.append(("prev_pair_sum",         lambda K,i,p: (K[i%p] + K[(i-1)%p]) % 26))
    funcs.append(("adjacent_product",      lambda K,i,p: (K[i%p] * K[(i+1)%p]) % 26))
    funcs.append(("adjacent_diff",         lambda K,i,p: (K[i%p] - K[(i+1)%p]) % 26))
    funcs.append(("cycle_indexed_add",     lambda K,i,p: (K[i%p] + K[(i//p)%p]) % 26))
    funcs.append(("multiplicative",        lambda K,i,p: (K[i%p] * (i+1)) % 26))
    funcs.append(("cycle_multiplicative",  lambda K,i,p: (K[i%p] * (i//p + 1)) % 26))
    funcs.append(("quadratic_residue",     lambda K,i,p: (K[i%p] + (i%p)*(i%p)) % 26))
    funcs.append(("row_col_interleave",    lambda K,i,p: (K[i%p]//5 * 5 + K[(i+1)%p]%5) % 26))
    funcs.append(("row_scaled_pos",        lambda K,i,p: (K[i%p] + K[i%p]//5 * (i%5)) % 26))
    funcs.append(("kryptos_seven_mod",     lambda K,i,p: (K[i%p] + (i%7)*(i%5)) % 26))
    funcs.append(("reversed_alt_cycle",    lambda K,i,p: K[i%p] if (i//p)%2==0 else K[(p-1-i%p)]))
    funcs.append(("progressive_plus_res",  lambda K,i,p: (K[i%p] + i + i%p) % 26))
    funcs.append(("double_progressive",    lambda K,i,p: (K[i%p] + 2*i) % 26))
    funcs.append(("shift_by_pos_in_kw",    lambda K,i,p: (K[i%p] + K[i%p]*(i%p)) % 26))
    funcs.append(("vig_progressive",       lambda K,i,p: (K[i%p] - i) % 26))
    funcs.append(("vig_step",              lambda K,i,p: (K[i%p] - i//p) % 26))
    funcs.append(("vig_adjacent",          lambda K,i,p: (K[i%p] - K[(i+1)%p]) % 26))
    funcs.append(("triple_progressive",    lambda K,i,p: (K[i%p] + 3*i) % 26))
    funcs.append(("golden_progressive",    lambda K,i,p: (K[i%p] + GOLDEN_POS[i]) % 26))
    funcs.append(("square_progressive",    lambda K,i,p: (K[i%p] + i*i) % 26))
    funcs.append(("xor_adjacent",          lambda K,i,p: (K[i%p] ^ K[(i+1)%p]) % 26))
    funcs.append(("sum_all_prev_kw",       lambda K,i,p: (sum(K[j%p] for j in range(i+1))) % 26))
    funcs.append(("pos_times_kw_idx",      lambda K,i,p: (i * K[i%p]) % 26))
    funcs.append(("kw_sum_plus_pos",       lambda K,i,p: (sum(K) + i) % 26))
    return funcs

def running_sum_check(keyword_indices, p, required_key, crib_positions):
    """key[0..p-1] = keyword, key[i] = (key[i-1] + keyword[i%p]) mod 26 for i >= p."""
    max_pos = max(crib_positions)
    key = list(keyword_indices[:p])
    for i in range(p, max_pos + 1):
        key.append((key[-1] + keyword_indices[i % p]) % 26)
    return sum(1 for pos in crib_positions if pos < len(key) and key[pos] == required_key[pos])

def fibonacci_check(keyword_indices, p, required_key, crib_positions):
    """key[0..p-1] = keyword, key[i] = (key[i-1] + key[i-2]) mod 26 for i >= p."""
    if p < 2:
        return 0
    max_pos = max(crib_positions)
    key = list(keyword_indices[:p])
    for i in range(p, max_pos + 1):
        key.append((key[-1] + key[-2]) % 26)
    return sum(1 for pos in crib_positions if pos < len(key) and key[pos] == required_key[pos])

def gromark_check(keyword_indices, p, required_key, crib_positions):
    """key[0..p-1] = keyword, key[i] = (key[i-p] + key[i-p+1]) mod 26 for i >= p."""
    if p < 2:
        return 0
    max_pos = max(crib_positions)
    key = list(keyword_indices[:p])
    for i in range(p, max_pos + 1):
        key.append((key[i-p] + key[i-p+1]) % 26)
    return sum(1 for pos in crib_positions if pos < len(key) and key[pos] == required_key[pos])

# ── Optimized batch sweep for CT97 ──────────────────────────────────────
# Strategy: For each function, precompute what the REQUIRED keyword letter
# must be at each crib position. Then for each word, check in O(p) whether
# there are contradictions among what's required for keyword positions.
#
# For simple functions like f(K,i,p) = (K[i%p] + i) % 26, the required
# K[i%p] = (required_key[pos] - i) % 26.  All crib positions with the
# same (pos%p) must agree on K[pos%p].  This is O(24) per word per function,
# but with early exit it's usually O(1).

def fast_sweep_ct(required_key_dict, crib_positions, words_list, label="CT97"):
    """
    Optimized sweep: for each function, for each (cipher_mode, alphabet),
    for each keyword, check all 24 crib positions with early exit.
    Returns (hits, best_score, configs_tested).
    """
    hits = []
    best_score = 0
    configs_tested = 0

    cp = crib_positions  # sorted list of crib positions
    n_cribs = len(cp)

    funcs = make_progressive_functions()
    func_names = [name for name, _ in funcs]

    # For progress reporting
    total_words = len(words_list)
    report_interval = max(1, total_words // 10)

    for cipher_mode, required_key in required_key_dict:
        for alph_name, alph_idx_map in [("AZ", ALPH_IDX), ("KA", KA_IDX)]:
            word_count = 0
            for word in words_list:
                word_count += 1
                if word_count % report_interval == 0:
                    pct = word_count * 100 // total_words
                    elapsed = time.time() - t0
                    print(f"    [{label}] {cipher_mode}/{alph_name}: {pct}% ({word_count}/{total_words}) elapsed={elapsed:.0f}s best={best_score}/24", flush=True)

                p = len(word)
                try:
                    K = [alph_idx_map[ch] for ch in word]
                except KeyError:
                    continue

                # Precompute cumulative sums for cumulative_kw_sum
                cum_sums = [0] * p
                for j in range(1, p):
                    cum_sums[j] = (cum_sums[j-1] + K[j-1]) % 26

                kw_sum = sum(K) % 26

                # Test all lambda functions with early-exit
                for fi, (func_name, func) in enumerate(funcs):
                    configs_tested += 1
                    matches = 0
                    for ci, pos in enumerate(cp):
                        try:
                            key_val = func(K, pos, p) % 26
                        except Exception:
                            break
                        if key_val == required_key[pos]:
                            matches += 1
                        elif matches + (n_cribs - ci - 1) < 18:
                            # Can't reach 18 even if all remaining match
                            break

                    if matches > best_score:
                        best_score = matches

                    if matches >= 18:
                        hits.append((matches, word, func_name, alph_name, cipher_mode))
                        print(f"  SIGNAL: {matches}/{n_cribs} keyword={word} func={func_name} alph={alph_name} cipher={cipher_mode}", flush=True)

                    if matches == n_cribs:
                        print(f"\n  *** BREAKTHROUGH: {n_cribs}/{n_cribs} keyword={word} func={func_name} alph={alph_name} cipher={cipher_mode} ***", flush=True)
                        full_key = [func(K, i, p) % 26 for i in range(97)]
                        print(f"  Full keystream: {''.join(ALPH[k] for k in full_key)}", flush=True)

                # Test stateful functions
                for state_name, state_func in [
                    ("running_sum", running_sum_check),
                    ("fibonacci", fibonacci_check),
                    ("gromark", gromark_check),
                ]:
                    configs_tested += 1
                    matches = state_func(K, p, required_key, cp)

                    if matches > best_score:
                        best_score = matches

                    if matches >= 18:
                        hits.append((matches, word, state_name, alph_name, cipher_mode))
                        print(f"  SIGNAL: {matches}/{n_cribs} keyword={word} func={state_name} alph={alph_name} cipher={cipher_mode}", flush=True)

    return hits, best_score, configs_tested


# Load wordlist
print("\nLoading wordlist...")
words = set()
with open(os.path.join(_ROOT, "wordlists", "english.txt")) as f:
    for line in f:
        w = line.strip().upper()
        if 3 <= len(w) <= 12 and w.isalpha() and all(c in ALPH for c in w):
            words.add(w)

# Add thematic priority list
thematic = [
    "ROSETTA", "PHARAOH", "PASSAGE", "PYRAMID", "OBELISK",
    "CARTOUCHE", "DISCOVERY", "EXCAVATE", "TREASURE", "SARCOPHAGUS",
    "CARTER", "HOWARD", "TUTANKHAMUN", "THEBES", "LUXOR", "KARNAK",
    "VALLEY", "TOMB", "CRYPT", "MUMMY", "ANKH", "SCARAB", "PAPYRUS",
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "INVISIBLE",
    "ILLUSION", "NUANCE", "LAYERS", "MAGNETIC", "POSITION",
    "KOMPASS", "DEFECTOR", "COLOPHON", "SEVEN", "ROSETTASTONE",
    "HIEROGLYPH", "SPHINX", "WONDERFUL", "ANTECHAMBER",
    "TOWER", "CHART", "LAYER", "HOROLOGE", "ENIGMA",
    "MASKING", "STEGANOGRAPHY", "CIPHER", "MATRIX",
    "BERLINCLOCK", "EASTNORTHEAST",
]
words.update(w for w in thematic if 3 <= len(w) <= 12 and w.isalpha())

# Also load thematic keywords file if it exists
thematic_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
if os.path.exists(thematic_path):
    with open(thematic_path) as f:
        for line in f:
            w = line.strip().upper()
            if 3 <= len(w) <= 12 and w.isalpha() and all(c in ALPH for c in w):
                words.add(w)

words_sorted = sorted(words)
print(f"Loaded {len(words_sorted)} candidate keywords (3-12 letters)")

funcs = make_progressive_functions()
print(f"Testing {len(funcs)} progressive functions + 3 stateful (running_sum, fibonacci, gromark)")
print(f"Testing 2 cipher modes (Beaufort, Vigenere) x 2 alphabets (AZ, KA)")
print()

# ── CT97 Sweep ──────────────────────────────────────────────────────────

print("-" * 70)
print("CT97 Sweep (Model B: cipher on all 97 positions)")
print("-" * 70)

t0 = time.time()

ct97_required = [("beaufort", REQUIRED_KEY_97), ("vigenere", REQUIRED_VIG_97)]
hits_97, best_score_97, configs_tested = fast_sweep_ct(ct97_required, CRIB_POS, words_sorted, "CT97")

t97 = time.time() - t0
print(f"\nCT97 sweep complete: {configs_tested:,} configs in {t97:.1f}s")
print(f"Best score: {best_score_97}/24")
print(f"Signals (>=18): {len(hits_97)}")

# ── CT73 Sweep (Model A: cipher after null extraction) ──────────────────

print("\n" + "-" * 70)
print("CT73 Sweep (Model A: cipher after null extraction)")
print("-" * 70)

# Collect all valid 24-null masks from Part 1
valid_masks_73 = []
for r in part1_results:
    if r["valid"]:
        null_set = frozenset(CONSENSUS_NULLS | set(r["predicted_null_positions"]))
        if null_set not in [frozenset(m) for m in valid_masks_73]:
            valid_masks_73.append(sorted(null_set))

for mask_nulls, rules in unique_masks.items():
    total = 17 + len(mask_nulls)
    if total == 24:
        null_set = sorted(CONSENSUS_NULLS | set(mask_nulls))
        if not (set(mask_nulls) & CRIB_POS_SET):
            if null_set not in valid_masks_73:
                valid_masks_73.append(null_set)

# If Part 1 produced no valid masks, use fallback masks for CT73 testing
# Build CT73 from COMMON null predictions across rules (pick 7 most frequent)
if not valid_masks_73:
    print("No valid 24-null masks from Part 1.")
    # Count how often each varying candidate is predicted null
    null_freq = {}
    for r in part1_results:
        for p in r["predicted_null_positions"]:
            null_freq[p] = null_freq.get(p, 0) + 1

    # Sort by frequency descending, take top 7
    sorted_candidates = sorted(null_freq.items(), key=lambda x: -x[1])
    print(f"  Null frequency across 8 rules: {sorted_candidates}")

    # Try all C(16,7) = 11440 combinations? No, just use most frequent 7
    top7 = sorted([p for p, _ in sorted_candidates[:7]])
    if not (set(top7) & CRIB_POS_SET) and len(top7) == 7:
        valid_masks_73.append(sorted(CONSENSUS_NULLS | set(top7)))
        print(f"  Using most-frequent 7: {top7}")

    # Also try: all non-palette varying positions as nulls (since varying ARE non-palette per MEMORY)
    # Non-palette candidates
    non_palette_varying = [p for p in VARYING_CANDIDATES if CT[p] not in PALETTE]
    print(f"  Non-palette varying candidates: {non_palette_varying} (count={len(non_palette_varying)})")
    if len(non_palette_varying) >= 7:
        # Take top 7 non-palette by frequency
        np_freq = [(p, null_freq.get(p, 0)) for p in non_palette_varying]
        np_freq.sort(key=lambda x: -x[1])
        top7np = sorted([p for p, _ in np_freq[:7]])
        if not (set(top7np) & CRIB_POS_SET):
            mask_np = sorted(CONSENSUS_NULLS | set(top7np))
            if mask_np not in valid_masks_73:
                valid_masks_73.append(mask_np)
                print(f"  Using top-7 non-palette: {top7np}")

if not valid_masks_73:
    print("Still no valid masks. Skipping CT73 sweep.")
else:
    print(f"Testing {len(valid_masks_73)} null masks for CT73")

hits_73 = []
best_score_73 = 0
configs_tested_73 = 0

for mask_idx, null_mask in enumerate(valid_masks_73):
    null_set = frozenset(null_mask)

    ct73_chars = []
    pos_map = {}
    for p in range(97):
        if p not in null_set:
            pos_map[len(ct73_chars)] = p
            ct73_chars.append(CT[p])
    ct73 = "".join(ct73_chars)

    if len(ct73) != 73:
        print(f"  Mask {mask_idx}: length={len(ct73)}, expected 73. Skipping.")
        continue

    crib_73 = {}
    for ct97_pos, pt_char in CRIB_DICT.items():
        for ct73_idx, ct97_p in pos_map.items():
            if ct97_p == ct97_pos:
                crib_73[ct73_idx] = pt_char
                break

    if len(crib_73) != 24:
        print(f"  Mask {mask_idx}: only {len(crib_73)}/24 cribs survive. INVALID mask.")
        continue

    crib_pos_73 = sorted(crib_73.keys())

    req_beau_73 = {}
    req_vig_73 = {}
    for pos73 in crib_pos_73:
        ct_char = ct73[pos73]
        pt_char = crib_73[pos73]
        ct_i = ALPH_IDX[ct_char]
        pt_i = ALPH_IDX[pt_char]
        req_beau_73[pos73] = (ct_i + pt_i) % 26
        req_vig_73[pos73] = (ct_i - pt_i) % 26

    varying_in_mask = sorted(set(null_mask) - CONSENSUS_NULLS)
    print(f"\n  Mask {mask_idx}: varying nulls={varying_in_mask}")
    print(f"    CT73 length: {len(ct73)}")
    print(f"    Crib positions in CT73: {crib_pos_73}")

    ct73_required = [("beaufort", req_beau_73), ("vigenere", req_vig_73)]
    # Update GOLDEN_POS for CT73 positions
    for pos73 in crib_pos_73:
        if pos73 not in GOLDEN_POS:
            GOLDEN_POS[pos73] = int(pos73 * GOLDEN)

    h73, bs73, ct73_configs = fast_sweep_ct(ct73_required, crib_pos_73, words_sorted, f"CT73-mask{mask_idx}")

    for hit in h73:
        hits_73.append((*hit, mask_idx))
    if bs73 > best_score_73:
        best_score_73 = bs73
    configs_tested_73 += ct73_configs

    print(f"  Mask {mask_idx} complete: {ct73_configs:,} configs, best={bs73}/24")

total_time = time.time() - t0

# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════

print("\n\n" + "=" * 70)
print("FINAL SUMMARY")
print("=" * 70)

print(f"\nPart 1: Stego Table Rules")
print(f"  8 rules evaluated")
for r in part1_results:
    status = "VALID" if r["valid"] else "INVALID"
    reason = ""
    if r["crib_conflicts"]:
        reason = f" (removes cribs at {r['crib_conflicts']})"
    elif r["total_nulls"] != 24:
        reason = f" (gives {r['total_nulls']} nulls, need 24)"
    print(f"    {r['rule']:40s} → nulls={r['predicted_null_positions']!s:30s} [{status}]{reason}")

print(f"\n  Unique valid masks: {len(valid_masks_73)}")

print(f"\nPart 2: Keyword Progressive Sweep")
print(f"  CT97: {configs_tested:,} configs, best={best_score_97}/24, signals(≥18)={len(hits_97)}")
if valid_masks_73:
    print(f"  CT73: {configs_tested_73:,} configs, best={best_score_73}/24, signals(≥18)={len(hits_73)}")
print(f"  Total time: {total_time:.1f}s")

if hits_97:
    print(f"\n  CT97 hits:")
    for score, word, func, alph, cipher in sorted(hits_97, reverse=True):
        print(f"    {score}/24  {word:15s}  {func:25s}  {alph}  {cipher}")

if hits_73:
    print(f"\n  CT73 hits:")
    for hit in sorted(hits_73, reverse=True):
        score, word, func, alph, cipher = hit[:5]
        mask_idx = hit[5] if len(hit) > 5 else "?"
        print(f"    {score}/24  {word:15s}  {func:25s}  {alph}  {cipher}  mask={mask_idx}")

if not hits_97 and not hits_73:
    print("\n  NO SIGNALS ≥18/24. All progressive keyword functions produce NOISE.")
    print("  This eliminates simple progressive key generation from a single keyword.")

# ── Save results ────────────────────────────────────────────────────────

results = {
    "experiment": "e_keyword_progressive_sweep",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "description": "Two-part analysis: (1) stego table-generating words predict varying null positions, (2) keyword × progressive function sweep on CT97 and CT73",
    "part1_stego_rules": part1_results,
    "part1_unique_valid_masks": [list(m) for m in valid_masks_73],
    "part2_ct97": {
        "configs_tested": configs_tested,
        "best_score": best_score_97,
        "signals_ge18": [list(h) for h in hits_97],
        "functions_tested": [name for name, _ in make_progressive_functions()] + ["running_sum", "fibonacci", "gromark"],
        "alphabets_tested": ["AZ", "KA"],
        "cipher_modes_tested": ["beaufort", "vigenere"],
        "keywords_tested": len(words_sorted),
    },
    "part2_ct73": {
        "masks_tested": len(valid_masks_73),
        "configs_tested": configs_tested_73,
        "best_score": best_score_73 if valid_masks_73 else None,
        "signals_ge18": [list(h) for h in hits_73] if hits_73 else [],
    },
    "total_configs": configs_tested + configs_tested_73,
    "total_time_seconds": round(total_time, 1),
    "conclusion": "NOISE" if not hits_97 and not hits_73 else "SIGNAL_FOUND",
}

results_path = os.path.join(_ROOT, "results", "e_keyword_progressive_sweep.json")
with open(results_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {results_path}")
