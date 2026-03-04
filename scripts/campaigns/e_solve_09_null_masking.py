#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-SOLVE-09: Null Insertion Masking Hypothesis

THE STRONGEST STRUCTURAL HYPOTHESIS: K4 has 73 real characters + 24 nulls = 97.

Evidence:
  - Sanborn's yellow pad: "8 Lines 73" = 73-char plaintext
  - 97 - 73 = 24 = exactly the number of known crib positions (coincidence?)
  - Scheidt: "I masked the English language" = null insertion destroys frequency
  - This INVALIDATES E-FRAC-35's Bean impossibility proof at periods 2-7
  - Nulls at 24 positions change the residue class mapping for Bean constraints
  - IC below random (0.0361) explained: nulls add uniform characters

The attack:
  1. Determine which 24 of the 73 non-crib positions are nulls
  2. Cribs MUST be at non-null positions (they decrypt correctly)
  3. Remove nulls → 73-char CT
  4. The 73-char CT under periodic key should show structure at periods 2-7

Constraints:
  - All 24 crib positions (21-33, 63-73) are NON-NULL
  - Bean EQ: positions 27 and 65 (both cribs, both non-null) must have equal
    key values. In the reduced (null-free) domain, what matters is whether
    their reduced positions are in the same residue class mod period.
  - Self-encrypting: positions 32 (S) and 73 (K) are cribs, both non-null.

Key insight: if we number the non-null positions 0..72, the crib positions
get new indices. The Bean EQ k[27]=k[65] in the original becomes
k[new_27]=k[new_65] in the reduced domain. For period p, this requires
new_27 ≡ new_65 (mod p). The number of nulls between pos 27 and 65
determines whether this holds.
"""

import sys
import itertools
from collections import Counter

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

CT_VALS = [ALPH_IDX[c] for c in CT]

# All crib positions (must be non-null)
CRIB_POS_SET = set(CRIB_DICT.keys())
assert len(CRIB_POS_SET) == 24

# Non-crib positions (candidates for nulls)
NON_CRIB = sorted(set(range(CT_LEN)) - CRIB_POS_SET)
assert len(NON_CRIB) == 73  # We need exactly 24 nulls from these 73 positions

# Known keystream
VIG_KEY = {}
for i, v in enumerate(VIGENERE_KEY_ENE):
    VIG_KEY[21 + i] = v
for i, v in enumerate(VIGENERE_KEY_BC):
    VIG_KEY[63 + i] = v

BEAU_KEY = {}
from kryptos.kernel.constants import BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC
for i, v in enumerate(BEAUFORT_KEY_ENE):
    BEAU_KEY[21 + i] = v
for i, v in enumerate(BEAUFORT_KEY_BC):
    BEAU_KEY[63 + i] = v


def ic(text):
    n = len(text)
    if n < 2:
        return 0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def vowel_pct(text):
    return sum(1 for c in text if c in "AEIOU") / max(len(text), 1) * 100


print("E-SOLVE-09: Null Insertion Masking Hypothesis")
print(f"CT: {CT[:50]}...")
print(f"Non-crib positions (null candidates): {len(NON_CRIB)}")
print(f"Need to choose 24 of {len(NON_CRIB)} as nulls")
print()

total_tested = 0
above_noise = 0
best_score = 0
best_config = ""
best_pt = ""

# ======================================================================
# TEST 1: Keyword-derived null patterns
# Write keyword repeatedly, mark positions where keyword letter meets criterion
# ======================================================================
print("=" * 70)
print("TEST 1: Keyword-Derived Null Patterns")
print("=" * 70)

keywords = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN", "CLOCK",
    "SANBORN", "SCHEIDT", "MATRIX", "CIPHER", "SECRET", "HIDDEN",
    "LIGHT", "DARKNESS", "BETWEEN", "SUBTLE", "SHADING", "ABSENCE",
    "LAYERTWO", "EQUINOX", "VICTORIA", "LOOMIS", "BOWEN",
    "EASTNORTHEAST", "BERLINCLOCK", "IQLUSION", "DESPARATLY",
    "UNDERGRUUND", "SLOWLYDESPARATLY",
    "KRYPTOSABCDEFGHIJLMNQUVWXZ",  # KA alphabet
    "POINT", "COORDINATES", "LATITUDE", "LONGITUDE",
    "HOWARD", "CARTER", "TOMB", "TUTANKHAMUN",
    "WEBSTER", "LANGLEY", "VIRGINIA",
    "WHOWHATWHENWHEREWHYX",
]

# Null rules: what makes a position "null"
def is_vowel(ch): return ch in "AEIOU"
def is_consonant(ch): return ch not in "AEIOU"
def is_in_kryptos(ch): return ch in "KRYPTOS"
def is_not_in_kryptos(ch): return ch not in "KRYPTOS"
def is_first_half(ch): return ALPH_IDX.get(ch, 0) < 13
def is_second_half(ch): return ALPH_IDX.get(ch, 0) >= 13

null_rules = {
    "vowel": is_vowel,
    "consonant": is_consonant,
    "in_KRYPTOS": is_in_kryptos,
    "not_in_KRYPTOS": is_not_in_kryptos,
    "first_half_A-M": is_first_half,
    "second_half_N-Z": is_second_half,
}

t1_count = 0
t1_hits = 0

for kw in keywords:
    for rule_name, rule_fn in null_rules.items():
        # Repeat keyword across 97 positions
        expanded = (kw * (CT_LEN // len(kw) + 1))[:CT_LEN]

        # Mark null positions
        null_positions = set()
        for i in range(CT_LEN):
            if i in CRIB_POS_SET:
                continue  # Crib positions cannot be null
            if rule_fn(expanded[i]):
                null_positions.add(i)

        # Check if we have exactly 24 nulls
        if len(null_positions) != 24:
            continue  # Skip non-matching patterns

        # We have a valid null pattern! Test it.
        # Build the reduced (non-null) positions
        non_null_pos = sorted(set(range(CT_LEN)) - null_positions)
        assert len(non_null_pos) == 73

        # Map original crib positions to reduced positions
        orig_to_reduced = {orig: idx for idx, orig in enumerate(non_null_pos)}

        # Extract reduced CT
        reduced_ct_vals = [CT_VALS[p] for p in non_null_pos]

        # Get reduced crib positions
        reduced_cribs = {}
        for orig_pos, pt_char in CRIB_DICT.items():
            reduced_cribs[orig_to_reduced[orig_pos]] = ALPH_IDX[pt_char]

        # Check Bean EQ in reduced domain
        bean_eq_orig = BEAN_EQ[0]  # (27, 65)
        reduced_27 = orig_to_reduced[bean_eq_orig[0]]
        reduced_65 = orig_to_reduced[bean_eq_orig[1]]

        # Test periods 2-13 for periodic key in reduced domain
        for period in range(2, 14):
            # Check if Bean EQ holds: reduced positions must be same mod period
            if reduced_27 % period != reduced_65 % period:
                continue  # Bean EQ impossible at this period

            # Check Bean INEQ
            bean_ineq_ok = True
            for a, b in BEAN_INEQ:
                if a in orig_to_reduced and b in orig_to_reduced:
                    ra = orig_to_reduced[a]
                    rb = orig_to_reduced[b]
                    if ra % period == rb % period:
                        bean_ineq_ok = False
                        break

            # Check if crib keystream values are consistent with period
            residue_vals = {}
            consistent = True
            for reduced_pos, pt_val in reduced_cribs.items():
                ct_val = reduced_ct_vals[reduced_pos]
                r = reduced_pos % period

                # Vigenère key
                vig_key_val = (ct_val - pt_val) % MOD

                if r in residue_vals:
                    if residue_vals[r] != vig_key_val:
                        consistent = False
                        break
                else:
                    residue_vals[r] = vig_key_val

            t1_count += 1

            if consistent:
                # Build the full periodic key for reduced domain
                key_word = [0] * period
                for r, v in residue_vals.items():
                    key_word[r] = v
                key_text = "".join(ALPH[v] for v in key_word)

                # Count constrained vs free residues
                constrained = len(residue_vals)
                free = period - constrained

                # Decrypt the full reduced CT
                pt_vals = [(reduced_ct_vals[i] - key_word[i % period]) % MOD
                           for i in range(73)]
                pt_text = "".join(ALPH[v] for v in pt_vals)

                # Score
                pt_ic = ic(pt_text)
                vp = vowel_pct(pt_text)

                # Check for English words
                english_score = 0
                for w in ["THE", "AND", "FOR", "THAT", "WITH", "THIS", "FROM",
                           "HAVE", "BEEN", "WERE", "THEY", "WILL", "EACH",
                           "NORTH", "EAST", "SOUTH", "WEST", "LIGHT", "DARK",
                           "SHADOW", "BETWEEN", "POINT", "LOCATION", "ENTRANCE",
                           "COULD", "WOULD", "SLOWLY", "BURIED", "VISIBLE",
                           "SECRET", "HIDDEN", "CLOCK", "BERLIN", "WATER",
                           "STONE", "TOMB", "DOOR", "LAYER", "UNDER", "GROUND"]:
                    if w in pt_text:
                        english_score += len(w)

                t1_hits += 1
                above_noise += 1

                # Print everything that looks remotely interesting
                if (bean_ineq_ok and (pt_ic > 0.05 or english_score > 6 or vp > 30)) or \
                   (free <= 2 and bean_ineq_ok):
                    print(f"\n  *** kw={kw} rule={rule_name} period={period}")
                    print(f"      Nulls: {sorted(null_positions)[:10]}... ({len(null_positions)} total)")
                    print(f"      Reduced Bean: pos {reduced_27} ≡ {reduced_65} (mod {period})")
                    print(f"      Bean INEQ: {'PASS' if bean_ineq_ok else 'FAIL'}")
                    print(f"      Key: {key_text} (constrained={constrained}, free={free})")
                    print(f"      PT: {pt_text}")
                    print(f"      IC={pt_ic:.4f}, vowels={vp:.0f}%, english={english_score}")

                    if pt_ic > 0.05 and bean_ineq_ok and english_score > 10:
                        print(f"      *** SIGNAL! ***")
                        if english_score > best_score:
                            best_score = english_score
                            best_config = f"kw={kw} rule={rule_name} p={period}"

total_tested += t1_count
print(f"\n  Keyword null patterns: {t1_count} tested (only exact-24 null patterns), "
      f"{t1_hits} consistent with periodic key")


# ======================================================================
# TEST 2: Structured null positions (every-N, Fibonacci, primes, etc.)
# ======================================================================
print("\n" + "=" * 70)
print("TEST 2: Structured Null Positions")
print("=" * 70)

t2_count = 0
t2_hits = 0

def generate_null_patterns():
    """Generate various structured sets of 24 null positions from non-crib positions."""
    patterns = {}

    # Every-N from non-crib positions
    for n in range(2, 10):
        for offset in range(n):
            nulls = set()
            for i, pos in enumerate(NON_CRIB):
                if i % n == offset:
                    nulls.add(pos)
            if len(nulls) == 24:
                patterns[f"every_{n}_off{offset}"] = nulls

    # First 24 non-crib positions
    patterns["first_24"] = set(NON_CRIB[:24])

    # Last 24 non-crib positions
    patterns["last_24"] = set(NON_CRIB[-24:])

    # Middle 24
    start = (73 - 24) // 2
    patterns["middle_24"] = set(NON_CRIB[start:start+24])

    # Alternating blocks: first 24 even-indexed non-crib positions
    patterns["even_idx"] = set(NON_CRIB[i] for i in range(0, 73, 3) if i < 73)

    # Positions where CT letter appears in a specific set
    for letter_set_name, letter_set in [
        ("vowels", "AEIOU"),
        ("KRYPTOS", "KRYPTOS"),
        ("first_6", "ABCDEF"),
    ]:
        nulls = set()
        for pos in NON_CRIB:
            if CT[pos] in letter_set:
                nulls.add(pos)
        if len(nulls) == 24:
            patterns[f"ct_{letter_set_name}"] = nulls

    # Positions where KA index is < 24/73 * 26
    for threshold in range(5, 22):
        KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
        nulls = set()
        for pos in NON_CRIB:
            if KA_IDX[CT[pos]] < threshold:
                nulls.add(pos)
        if len(nulls) == 24:
            patterns[f"ka_below_{threshold}"] = nulls

    # Fibonacci-indexed positions
    fib = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89]
    fib_nulls = set()
    for f in fib:
        if f < CT_LEN and f not in CRIB_POS_SET:
            fib_nulls.add(f)
    # Not exactly 24, so skip

    # Fixed gap patterns
    for gap in range(3, 8):
        for start_off in range(gap):
            nulls = set()
            pos = start_off
            while pos < CT_LEN and len(nulls) < 24:
                if pos not in CRIB_POS_SET:
                    nulls.add(pos)
                pos += gap
            if len(nulls) == 24:
                patterns[f"gap_{gap}_start{start_off}"] = nulls

    # 8-row grid patterns (since "8 Lines 73")
    # In an 8-row grid with width 12-13:
    # Null the last position in each row, or specific columns
    for width in [12, 13]:
        # Null positions from specific columns
        for null_col in range(width):
            nulls = set()
            for row in range(8):
                pos = row * width + null_col
                if pos < CT_LEN and pos not in CRIB_POS_SET:
                    nulls.add(pos)
            if len(nulls) == 24:
                patterns[f"grid_w{width}_col{null_col}"] = nulls

        # Null bottom row(s) for grids that overflow
        if width == 13:  # 8*13=104, need to pick 97
            # "8 Lines 73": maybe nulls are the extra 24 positions in a 97-char grid
            # arranged in 8 rows, with some rows shorter
            pass

    return patterns

null_patterns = generate_null_patterns()
print(f"  Generated {len(null_patterns)} structured null patterns")

for pattern_name, null_positions in null_patterns.items():
    non_null_pos = sorted(set(range(CT_LEN)) - null_positions)
    if len(non_null_pos) != 73:
        continue

    orig_to_reduced = {orig: idx for idx, orig in enumerate(non_null_pos)}

    # Check all crib positions are non-null
    if not all(p in orig_to_reduced for p in CRIB_POS_SET):
        continue

    reduced_ct_vals = [CT_VALS[p] for p in non_null_pos]

    reduced_cribs = {}
    for orig_pos, pt_char in CRIB_DICT.items():
        reduced_cribs[orig_to_reduced[orig_pos]] = ALPH_IDX[pt_char]

    reduced_27 = orig_to_reduced[27]
    reduced_65 = orig_to_reduced[65]

    for period in range(2, 14):
        if reduced_27 % period != reduced_65 % period:
            continue

        # Check Bean INEQ
        bean_ineq_ok = True
        for a, b in BEAN_INEQ:
            if a in orig_to_reduced and b in orig_to_reduced:
                ra = orig_to_reduced[a]
                rb = orig_to_reduced[b]
                if ra % period == rb % period:
                    bean_ineq_ok = False
                    break

        if not bean_ineq_ok:
            continue

        # Check periodic key consistency
        residue_vals = {}
        consistent = True
        for reduced_pos, pt_val in reduced_cribs.items():
            ct_val = reduced_ct_vals[reduced_pos]
            r = reduced_pos % period
            vig_key_val = (ct_val - pt_val) % MOD

            if r in residue_vals:
                if residue_vals[r] != vig_key_val:
                    consistent = False
                    break
            else:
                residue_vals[r] = vig_key_val

        t2_count += 1

        if consistent:
            key_word = [0] * period
            for r, v in residue_vals.items():
                key_word[r] = v
            key_text = "".join(ALPH[v] for v in key_word)
            constrained = len(residue_vals)
            free = period - constrained

            pt_vals = [(reduced_ct_vals[i] - key_word[i % period]) % MOD
                       for i in range(73)]
            pt_text = "".join(ALPH[v] for v in pt_vals)
            pt_ic = ic(pt_text)
            vp = vowel_pct(pt_text)

            t2_hits += 1

            # Also test Beaufort
            beau_residues = {}
            beau_consistent = True
            for reduced_pos, pt_val in reduced_cribs.items():
                ct_val = reduced_ct_vals[reduced_pos]
                r = reduced_pos % period
                beau_key_val = (ct_val + pt_val) % MOD
                if r in beau_residues:
                    if beau_residues[r] != beau_key_val:
                        beau_consistent = False
                        break
                else:
                    beau_residues[r] = beau_key_val

            if free <= 2:
                print(f"\n  *** {pattern_name} period={period} (Vig)")
                print(f"      Nulls: {sorted(null_positions)[:10]}...")
                print(f"      Key: {key_text} (free={free})")
                print(f"      PT: {pt_text}")
                print(f"      IC={pt_ic:.4f}, vowels={vp:.0f}%")

                if beau_consistent:
                    beau_key = [0] * period
                    for r, v in beau_residues.items():
                        beau_key[r] = v
                    beau_pt_vals = [(beau_key[i % period] - reduced_ct_vals[i]) % MOD
                                    for i in range(73)]
                    beau_pt = "".join(ALPH[v] for v in beau_pt_vals)
                    beau_ic = ic(beau_pt)
                    print(f"      Beaufort PT: {beau_pt}")
                    print(f"      Beaufort IC={beau_ic:.4f}")

total_tested += t2_count
above_noise += t2_hits
print(f"\n  Structured patterns: {t2_count} tested, {t2_hits} Bean+periodic consistent")


# ======================================================================
# TEST 3: Exhaustive null position search for small periods
# For period p, we need:
#   1. reduced_27 ≡ reduced_65 (mod p)   [Bean EQ]
#   2. All Bean INEQ satisfied in reduced domain
#   3. Crib keystream consistent with period p
# Work backwards: for each period, find how many nulls must be between
# specific positions to satisfy constraints.
# ======================================================================
print("\n" + "=" * 70)
print("TEST 3: Constraint-Driven Null Search (periods 3-7)")
print("=" * 70)

t3_count = 0
t3_hits = 0

# For each target period, we need to find null distributions
# Let's think about it differently:
# - Between pos 27 and 65 (exclusive), there are positions 28-64 = 37 positions
# - Of these, some are cribs: 28,29,30,31,32,33,63,64,65 -> wait, 65 is the end
# - Between 28 and 64 inclusive: positions 28-33 are cribs (6 positions), 63-64 are cribs (2)
# - So 37 total, 8 are cribs (non-null), 29 are non-crib (null candidates)
# - n_nulls_between = number of nulls in positions 28-64
# - reduced_27 = 27 - (nulls before 27)
# - reduced_65 = 65 - (nulls before 65) = 65 - (nulls before 27) - n_nulls_between
# - Bean EQ requires: reduced_27 ≡ reduced_65 (mod p)
# - i.e., (27 - n_before_27) ≡ (65 - n_before_27 - n_between) (mod p)
# - Simplifies to: 27 ≡ 65 - n_between (mod p)
# - i.e., n_between ≡ 65 - 27 (mod p) = 38 (mod p)

for period in range(3, 8):
    required_n_between = 38 % period  # nulls between pos 27 and 65 (exclusive)
    # Actually n_between ≡ 38 - 0 = 38 mod p? Let me redo this.
    # reduced_27 = 27 - nulls_before_27
    # reduced_65 = 65 - nulls_before_65 = 65 - (nulls_before_27 + nulls_28_to_64)
    # Need: reduced_27 ≡ reduced_65 (mod p)
    # 27 - nb27 ≡ 65 - nb27 - nb28_64 (mod p)
    # 27 ≡ 65 - nb28_64 (mod p)
    # nb28_64 ≡ 65 - 27 = 38 (mod p)
    # nb28_64 ≡ 38 mod p

    # Positions 28-64 that are non-crib (null candidates)
    between_noncrib = [pos for pos in NON_CRIB if 28 <= pos <= 64]

    # Total nulls needed: 24
    # Nulls between 28-64: must be ≡ 38 mod p
    # Nulls elsewhere: 24 - nulls_between

    # Count non-crib positions in each region
    before_27_noncrib = [pos for pos in NON_CRIB if pos < 27]
    between_noncrib = [pos for pos in NON_CRIB if 28 <= pos <= 64]
    after_65_noncrib = [pos for pos in NON_CRIB if pos > 65]

    # Note: positions 21-26 are ENE cribs, 27 is a crib
    # Non-crib before 27: positions 0-20 minus any cribs
    # Cribs before 27: positions 21-26 (6 positions)
    # So before_27_noncrib = positions 0-20 = 21 positions (all non-crib)
    # Between 28-64: 37 positions, 6 cribs (28-33), = 31 non-crib... wait
    # Cribs in 28-64: 28,29,30,31,32,33 = 6 from ENE, plus 63,64 = 2 from BC = 8
    # So non-crib between 28-64 = 37 - 8 = 29

    n_before = len(before_27_noncrib)
    n_between = len(between_noncrib)
    n_after = len(after_65_noncrib)

    print(f"\n  Period {period}: need nulls_between ≡ {38 % period} (mod {period})")
    print(f"    Non-crib slots: before_27={n_before}, between_28_64={n_between}, after_65={n_after}")
    print(f"    Total non-crib: {n_before + n_between + n_after}")

    # For each valid number of between-nulls
    valid_n_betweens = []
    for nb in range(max(0, 24 - n_before - n_after), min(24, n_between) + 1):
        if nb % period == 38 % period:
            valid_n_betweens.append(nb)

    print(f"    Valid between-null counts: {valid_n_betweens}")

    # For each valid count, we need to also check Bean INEQ
    # This is a combinatorial search — for large counts, sample

    for nb in valid_n_betweens:
        n_elsewhere = 24 - nb
        # n_elsewhere distributed between before_27 and after_65
        # Constraint: n_elsewhere <= n_before + n_after

        if n_elsewhere > n_before + n_after:
            continue

        # For each split (n_before_nulls, n_after_nulls) where sum = n_elsewhere
        for n_before_nulls in range(max(0, n_elsewhere - n_after),
                                     min(n_elsewhere, n_before) + 1):
            n_after_nulls = n_elsewhere - n_before_nulls

            # Sample: pick random subsets of each region
            # For computational feasibility, only check Bean INEQ constraint
            # and periodic key consistency for sampled null patterns

            import random
            random.seed(42 + period * 1000 + nb * 100 + n_before_nulls)

            n_samples = min(500, 1)  # Start with systematic if small

            # If search space is small enough, enumerate
            from math import comb
            space_size = comb(n_before, n_before_nulls) * comb(n_between, nb) * comb(n_after, n_after_nulls)

            if space_size == 0:
                continue

            if space_size <= 1000:
                # Enumerate all
                samples_to_check = space_size
                use_enumeration = True
            else:
                samples_to_check = 500
                use_enumeration = False

            checked = 0
            found = 0

            for sample_idx in range(samples_to_check):
                if use_enumeration and sample_idx == 0:
                    # Generate all combinations... but this is too large for most cases
                    # For now, just sample
                    pass

                # Sample random null positions
                b_nulls = set(random.sample(before_27_noncrib, n_before_nulls))
                m_nulls = set(random.sample(between_noncrib, nb))
                a_nulls = set(random.sample(after_65_noncrib, n_after_nulls))
                null_positions = b_nulls | m_nulls | a_nulls

                if len(null_positions) != 24:
                    continue

                non_null_pos = sorted(set(range(CT_LEN)) - null_positions)
                if len(non_null_pos) != 73:
                    continue

                orig_to_reduced = {orig: idx for idx, orig in enumerate(non_null_pos)}

                # All cribs must be non-null
                if not all(p in orig_to_reduced for p in CRIB_POS_SET):
                    continue

                # Check Bean EQ
                r27 = orig_to_reduced[27]
                r65 = orig_to_reduced[65]
                if r27 % period != r65 % period:
                    continue

                # Check Bean INEQ
                bean_ok = True
                for a, b in BEAN_INEQ:
                    if a in orig_to_reduced and b in orig_to_reduced:
                        ra = orig_to_reduced[a]
                        rb = orig_to_reduced[b]
                        if ra % period == rb % period:
                            bean_ok = False
                            break

                if not bean_ok:
                    continue

                # Check periodic key consistency
                reduced_ct_vals = [CT_VALS[p] for p in non_null_pos]
                residue_vals = {}
                consistent = True
                for orig_pos, pt_char in CRIB_DICT.items():
                    rp = orig_to_reduced[orig_pos]
                    ct_v = reduced_ct_vals[rp]
                    pt_v = ALPH_IDX[pt_char]
                    r = rp % period
                    kv = (ct_v - pt_v) % MOD

                    if r in residue_vals:
                        if residue_vals[r] != kv:
                            consistent = False
                            break
                    else:
                        residue_vals[r] = kv

                t3_count += 1
                checked += 1

                if consistent:
                    found += 1
                    t3_hits += 1

                    key_word = [0] * period
                    for r, v in residue_vals.items():
                        key_word[r] = v
                    key_text = "".join(ALPH[v] for v in key_word)
                    constrained = len(residue_vals)
                    free = period - constrained

                    pt_vals = [(reduced_ct_vals[i] - key_word[i % period]) % MOD
                               for i in range(73)]
                    pt_text = "".join(ALPH[v] for v in pt_vals)
                    pt_ic = ic(pt_text)
                    vp = vowel_pct(pt_text)

                    if free <= 1 or pt_ic > 0.05:
                        print(f"\n    *** Period {period}, nb={nb}, split=({n_before_nulls},{nb},{n_after_nulls})")
                        print(f"        Key: {key_text} (free={free})")
                        print(f"        PT: {pt_text}")
                        print(f"        IC={pt_ic:.4f}, vowels={vp:.0f}%")
                        print(f"        Nulls before: {sorted(b_nulls)}")
                        print(f"        Nulls between: {sorted(m_nulls)[:10]}...")
                        print(f"        Nulls after: {sorted(a_nulls)}")

            if checked > 0:
                pass  # quiet unless hits

    if t3_hits == 0:
        print(f"    No consistent+Bean-passing patterns found at period {period}")

total_tested += t3_count
above_noise += t3_hits
print(f"\n  Constraint-driven: {t3_count} tested, {t3_hits} fully consistent")


# ======================================================================
# TEST 4: "8 Lines" grid interpretation
# If plaintext is 73 chars in 8 lines, that's ~9.125 chars per line.
# Could be 8 lines of 9 (72) + 1, or variable.
# Nulls are padding to fill grid to 97 positions.
# ======================================================================
print("\n" + "=" * 70)
print("TEST 4: 8-Line Grid Null Interpretation")
print("=" * 70)

# 97 in an 8-row grid: widths 12 (12*8=96+1=97 with extra) or 13 (13*7+6=97)
# If PT is 73 chars, padding to 97 = 24 nulls
# Various grid arrangements:

grid_configs = []

# Width 12: 8 rows × 12 = 96, need 1 more → 8 full rows + 1 extra
# But we need 97 total. 97/8 = 12.125 → 8 rows, first row has 13, rest 12
# Or 5 rows of 13, 3 rows of 12... wait let's think differently.
# Grid width w: rows = ceil(97/w)
# For "8 lines": w = ceil(97/8) = 13 → 7 rows of 13 + 1 row of 6

# Width 13, 8 rows: 7×13 + 6 = 97. Last row has 6 chars.
# Nulls could be at specific positions in the grid

for width in [12, 13]:
    # Fill grid row by row
    n_rows = 8
    # Total cells: will vary
    for null_strategy in ["end_of_rows", "start_of_rows", "specific_column", "checker"]:
        if null_strategy == "end_of_rows":
            # Null = last positions of rows that are "too long"
            nulls = set()
            for row in range(n_rows):
                # In a width-w grid, position at row r, col c = r*w + c
                row_end = row * width + width - 1
                if row_end < CT_LEN:
                    if row_end not in CRIB_POS_SET:
                        nulls.add(row_end)

        elif null_strategy == "start_of_rows":
            nulls = set()
            for row in range(n_rows):
                row_start = row * width
                if row_start < CT_LEN:
                    if row_start not in CRIB_POS_SET:
                        nulls.add(row_start)

        elif null_strategy == "specific_column":
            # Try each column as "null column"
            for col in range(width):
                nulls = set()
                for row in range(n_rows):
                    pos = row * width + col
                    if pos < CT_LEN and pos not in CRIB_POS_SET:
                        nulls.add(pos)
                if len(nulls) == 24:
                    grid_configs.append((f"grid_w{width}_nullcol{col}", nulls))

            continue  # handled above

        elif null_strategy == "checker":
            nulls = set()
            for row in range(n_rows):
                for col in range(width):
                    pos = row * width + col
                    if pos < CT_LEN and (row + col) % 2 == 0 and pos not in CRIB_POS_SET:
                        nulls.add(pos)

        if len(nulls) == 24:
            grid_configs.append((f"grid_w{width}_{null_strategy}", nulls))

    # Also: null every 4th position in each row
    for step in [3, 4]:
        nulls = set()
        for row in range(n_rows):
            for s in range(0, width, step):
                pos = row * width + s
                if pos < CT_LEN and pos not in CRIB_POS_SET:
                    nulls.add(pos)
        if len(nulls) == 24:
            grid_configs.append((f"grid_w{width}_every{step}", nulls))

print(f"  Generated {len(grid_configs)} grid-based null patterns")

t4_count = 0
t4_hits = 0

for config_name, null_positions in grid_configs:
    non_null_pos = sorted(set(range(CT_LEN)) - null_positions)
    if len(non_null_pos) != 73:
        continue

    orig_to_reduced = {orig: idx for idx, orig in enumerate(non_null_pos)}

    if not all(p in orig_to_reduced for p in CRIB_POS_SET):
        continue

    reduced_ct_vals = [CT_VALS[p] for p in non_null_pos]

    for period in range(2, 14):
        r27 = orig_to_reduced[27]
        r65 = orig_to_reduced[65]
        if r27 % period != r65 % period:
            continue

        # Bean INEQ
        bean_ok = True
        for a, b in BEAN_INEQ:
            if a in orig_to_reduced and b in orig_to_reduced:
                if orig_to_reduced[a] % period == orig_to_reduced[b] % period:
                    bean_ok = False
                    break
        if not bean_ok:
            continue

        # Periodic key consistency
        residue_vals = {}
        consistent = True
        for orig_pos, pt_char in CRIB_DICT.items():
            rp = orig_to_reduced[orig_pos]
            ct_v = reduced_ct_vals[rp]
            pt_v = ALPH_IDX[pt_char]
            r = rp % period
            kv = (ct_v - pt_v) % MOD
            if r in residue_vals:
                if residue_vals[r] != kv:
                    consistent = False
                    break
            else:
                residue_vals[r] = kv

        t4_count += 1

        if consistent:
            t4_hits += 1
            key_word = [0] * period
            for r, v in residue_vals.items():
                key_word[r] = v
            key_text = "".join(ALPH[v] for v in key_word)
            constrained = len(residue_vals)
            free = period - constrained

            pt_vals = [(reduced_ct_vals[i] - key_word[i % period]) % MOD
                       for i in range(73)]
            pt_text = "".join(ALPH[v] for v in pt_vals)
            pt_ic = ic(pt_text)
            vp = vowel_pct(pt_text)

            print(f"\n  *** {config_name} period={period}")
            print(f"      Key: {key_text} (constrained={constrained}, free={free})")
            print(f"      PT: {pt_text}")
            print(f"      IC={pt_ic:.4f}, vowels={vp:.0f}%")

total_tested += t4_count
above_noise += t4_hits
print(f"\n  Grid patterns: {t4_count} tested, {t4_hits} fully consistent")


# ======================================================================
# TEST 5: Beaufort convention for all above (repeat best patterns)
# ======================================================================
print("\n" + "=" * 70)
print("TEST 5: Combined Summary — All Null Patterns × Both Conventions")
print("=" * 70)

# Collect all patterns that passed Bean EQ + INEQ + periodic consistency
# under Vigenère, and retest under Beaufort
# (Already partially tested above, but let's do a final sweep)

# Quick stats
print(f"\n  Total configs tested across all tests: {total_tested}")
print(f"  Total above noise / consistent: {above_noise}")
print(f"  Best config: {best_config}")
print()


# ======================================================================
# TEST 6: Adaptive search — for each period, optimize null placement
# to maximize PT quality (IC, vowel %, English words)
# Use hill-climbing: start from random null placement, swap nulls to
# improve plaintext quality
# ======================================================================
print("=" * 70)
print("TEST 6: Hill-Climbing Null Placement Optimization")
print("=" * 70)

import random
random.seed(2026)

def evaluate_null_pattern(null_set, period, convention="vig"):
    """Evaluate a null pattern: returns (consistent, score_dict)"""
    non_null = sorted(set(range(CT_LEN)) - null_set)
    if len(non_null) != 73:
        return False, {}

    o2r = {orig: idx for idx, orig in enumerate(non_null)}

    # Check all cribs are non-null
    if not all(p in o2r for p in CRIB_POS_SET):
        return False, {}

    reduced_ct = [CT_VALS[p] for p in non_null]

    # Bean EQ
    if o2r[27] % period != o2r[65] % period:
        return False, {}

    # Bean INEQ
    for a, b in BEAN_INEQ:
        if a in o2r and b in o2r:
            if o2r[a] % period == o2r[b] % period:
                return False, {}

    # Periodic key consistency
    residue_vals = {}
    for orig_pos, pt_char in CRIB_DICT.items():
        rp = o2r[orig_pos]
        ct_v = reduced_ct[rp]
        pt_v = ALPH_IDX[pt_char]
        r = rp % period

        if convention == "vig":
            kv = (ct_v - pt_v) % MOD
        else:
            kv = (ct_v + pt_v) % MOD

        if r in residue_vals:
            if residue_vals[r] != kv:
                return False, {}
        else:
            residue_vals[r] = kv

    # Decrypt
    key_word = [0] * period
    for r, v in residue_vals.items():
        key_word[r] = v

    if convention == "vig":
        pt_vals = [(reduced_ct[i] - key_word[i % period]) % MOD for i in range(73)]
    else:
        pt_vals = [(key_word[i % period] - reduced_ct[i]) % MOD for i in range(73)]

    pt_text = "".join(ALPH[v] for v in pt_vals)
    pt_ic = ic(pt_text)
    vp = vowel_pct(pt_text)

    # English word count
    word_score = 0
    for w in ["THE", "AND", "FOR", "THAT", "WITH", "THIS", "FROM",
               "HAVE", "BEEN", "WERE", "THEY", "WILL", "SLOW",
               "LIGHT", "DARK", "SHADOW", "POINT", "LOCATION",
               "COULD", "WOULD", "BURIED", "VISIBLE", "NEAR",
               "EAST", "NORTH", "SOUTH", "WEST", "BERLIN",
               "CLOCK", "BETWEEN", "UNDER", "GROUND", "LAYER",
               "ENTRANCE", "TOMB", "SECRET", "HIDDEN", "OPEN",
               "WATER", "STONE", "COPPER", "TIME", "DOOR"]:
        if w in pt_text:
            word_score += len(w)

    constrained = len(residue_vals)
    free = period - constrained
    key_text = "".join(ALPH[v] for v in key_word)

    return True, {
        "pt": pt_text, "ic": pt_ic, "vp": vp,
        "words": word_score, "key": key_text,
        "free": free, "constrained": constrained,
        "score": pt_ic * 100 + word_score + (1 if vp > 30 else 0),
    }

t6_count = 0
t6_best = {}

for period in range(3, 8):
    for convention in ["vig", "beau"]:
        best_local_score = -1
        best_local_result = None

        for trial in range(200):
            # Random initial null pattern: pick 24 from NON_CRIB
            null_set = set(random.sample(NON_CRIB, 24))

            consistent, result = evaluate_null_pattern(null_set, period, convention)

            if consistent:
                # Hill climbing: try swapping one null with one non-null
                improved = True
                while improved:
                    improved = False
                    current_score = result["score"]

                    null_list = sorted(null_set)
                    nonnull_noncrib = sorted(set(NON_CRIB) - null_set)

                    for ni in range(len(null_list)):
                        for nni in range(len(nonnull_noncrib)):
                            new_null = set(null_set)
                            new_null.remove(null_list[ni])
                            new_null.add(nonnull_noncrib[nni])

                            c2, r2 = evaluate_null_pattern(new_null, period, convention)
                            if c2 and r2["score"] > current_score:
                                null_set = new_null
                                result = r2
                                current_score = r2["score"]
                                improved = True
                                break
                        if improved:
                            break

                t6_count += 1

                if result["score"] > best_local_score:
                    best_local_score = result["score"]
                    best_local_result = result

        if best_local_result:
            t6_best[f"p{period}_{convention}"] = best_local_result
            if best_local_result["ic"] > 0.05 or best_local_result["words"] > 10:
                print(f"\n  Period {period} ({convention}): BEST IC={best_local_result['ic']:.4f}, "
                      f"vowels={best_local_result['vp']:.0f}%, words={best_local_result['words']}")
                print(f"    Key: {best_local_result['key']} (free={best_local_result['free']})")
                print(f"    PT: {best_local_result['pt']}")

total_tested += t6_count

# Print summary of best across all periods
print(f"\n  Hill climbing: {t6_count} optimized patterns")
print("  Best by period:")
for key in sorted(t6_best.keys()):
    r = t6_best[key]
    print(f"    {key}: IC={r['ic']:.4f}, vowels={r['vp']:.0f}%, "
          f"words={r['words']}, key={r['key']} (free={r['free']})")


# ======================================================================
# SUMMARY
# ======================================================================
print("\n" + "=" * 70)
print("E-SOLVE-09 COMPLETE")
print("=" * 70)
print(f"  Total configs tested: {total_tested}")
print(f"  Above noise / consistent: {above_noise}")
print(f"  Best config: {best_config if best_config else 'None above threshold'}")
print()
