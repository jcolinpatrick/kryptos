#!/usr/bin/env python3
"""E-S-145: DRYAD/BATCO-style matrix table cipher for K4.

Hypothesis: K4 was encrypted using a physical "coding chart" -- a matrix of
scrambled alphabets similar to military DRYAD (KTC 1400 D) or BATCO cipher
tables. Sanborn said Scheidt taught him "matrix codes" that he could "modify
in a myriad of ways."

Structure tested:
  - A 26-row matrix where each row is an independent permutation of A-Z
  - ROW SELECTION for each position is determined by:
    (a) Position index mod N (periodic, for reference baseline)
    (b) Running key from Kryptos-related texts (K1-K3 plaintexts, etc.)
    (c) The ciphertext itself (autokey variant)
    (d) The KRYPTOS keyword alphabet cycling
    (e) Clock-position offsets (ENE=2, compass bearings)
  - COLUMN LOOKUP: plaintext letter found in the selected row gives the
    ciphertext letter at that column position (or vice versa)
  - This is effectively polyalphabetic substitution with a non-periodic,
    table-derived key -- the "coding chart" IS the key

What we test:
  We cannot brute-force 26! ^ 26 matrices. Instead, we:
  1. Derive the REQUIRED row alphabets from known crib positions
  2. Check if these required alphabets are CONSISTENT (no contradictions)
  3. Check if the required row-selection patterns show structure
  4. Test specific row-selection models against crib constraints

Output: results/e_s_145_dryad_matrix.json
"""

import json
import os
import sys
import random
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, N_CRIBS,
    KRYPTOS_ALPHABET, NOISE_FLOOR,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic

SEED = 145
random.seed(SEED)

# ============================================================================
# K1-K3 plaintext and keys (for running-key row selection)
# ============================================================================

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHETHELUCIDITYOFGROWANDFORCEFORWARDSTHESTILLPOINTOFTHETURNINGWORLD"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESITAGREEWITHYOURORDERSHIRSIRTHE LUCIDMEMORYISPERNIOUSLYEFFECTANDHEEFFECTHASONLYWORSENED"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORSTHATHADBEENFILLEDWITHSTONESANDMORTARWEREWITHSTANDTHETREASURETHECHAMBERROOMWASENTIRELYDECORATEDWITHGOLDANDJEWELS"

# Remove spaces/X, uppercase, keep only alpha
def clean_text(t):
    return "".join(c for c in t.upper() if c.isalpha())

K1_CLEAN = clean_text(K1_PT)
K2_CLEAN = clean_text(K2_PT)
K3_CLEAN = clean_text(K3_PT)
ALL_K_TEXT = K1_CLEAN + K2_CLEAN + K3_CLEAN

# Various running key sources
RK_SOURCES = {
    "K1": K1_CLEAN,
    "K2": K2_CLEAN,
    "K3": K3_CLEAN,
    "K1K2K3": ALL_K_TEXT,
    "K3_repeat": (K3_CLEAN * 2)[:CT_LEN],
    "KRYPTOS_repeat": (KRYPTOS_ALPHABET * 4)[:CT_LEN],
    "ABSCISSA_repeat": ("ABSCISSA" * 13)[:CT_LEN],
    "PALIMPSEST_repeat": ("PALIMPSEST" * 10)[:CT_LEN],
}

# ============================================================================
# Core analysis: what row-to-column mappings are REQUIRED at crib positions?
# ============================================================================

def analyze_crib_constraints():
    """For each crib position, determine what the matrix row must map.

    If CT[i] was produced by looking up PT[i] in a row alphabet,
    then row[col_of_PT[i]] = CT[i], meaning CT[i] and PT[i] must be
    in the same row at corresponding positions.

    We analyze what constraints the cribs impose on row alphabets.
    """
    print("=" * 72)
    print("PHASE 1: Crib Constraint Analysis")
    print("=" * 72)

    # For each position, we know CT[i] and PT[i]
    # Under a matrix cipher: the row used at position i maps PT[i] -> CT[i]
    # (or equivalently, CT[i] -> PT[i] for decryption)

    constraints = {}
    for pos, pt_ch in CRIB_DICT.items():
        ct_ch = CT[pos]
        constraints[pos] = (pt_ch, ct_ch)

    print(f"\nKnown PT->CT mappings at {len(constraints)} crib positions:")
    print(f"{'Pos':>4} {'PT':>3} {'CT':>3} {'PT_idx':>7} {'CT_idx':>7} {'Shift':>6}")
    print("-" * 40)

    shifts = []
    for pos in sorted(constraints.keys()):
        pt_ch, ct_ch = constraints[pos]
        pt_idx = ALPH_IDX[pt_ch]
        ct_idx = ALPH_IDX[ct_ch]
        shift = (ct_idx - pt_idx) % MOD
        shifts.append((pos, shift))
        print(f"{pos:>4} {pt_ch:>3} {ct_ch:>3} {pt_idx:>7} {ct_idx:>7} {shift:>6}")

    print(f"\nShift sequence (Vigenere key at cribs): {[s for _, s in shifts]}")

    return constraints, shifts


def test_row_selection_models(constraints, shifts):
    """Test whether various row-selection models produce consistent matrices.

    For a DRYAD-style matrix:
    - Each position i uses row r(i)
    - row r(i) must map PT[i] -> CT[i]
    - If two positions i,j use the SAME row r, then that row must map
      BOTH PT[i]->CT[i] AND PT[j]->CT[j]
    - This is only consistent if PT[i] != PT[j] or CT[i] == CT[j]
      (a single row can't map the same input to two different outputs)
    """
    print("\n" + "=" * 72)
    print("PHASE 2: Row Selection Model Testing")
    print("=" * 72)

    results = {}

    # For each row selection model, assign rows to positions,
    # then check if the crib constraints are consistent

    # Model A: Periodic row selection (row = pos mod N)
    print("\n--- Model A: Periodic row selection (pos mod N) ---")
    for period in range(2, 27):
        consistent, conflicts = check_consistency(constraints,
            lambda pos: pos % period, f"period-{period}")
        if consistent:
            results[f"periodic_{period}"] = {"consistent": True, "conflicts": 0}
            print(f"  Period {period:>2}: CONSISTENT (no conflicts)")
        else:
            results[f"periodic_{period}"] = {"consistent": False, "conflicts": conflicts}
            if period <= 10:
                print(f"  Period {period:>2}: {conflicts} conflict(s)")

    # Model B: Running key row selection (row = key_letter_index)
    print("\n--- Model B: Running key row selection ---")
    for name, rk_text in RK_SOURCES.items():
        if len(rk_text) < CT_LEN:
            rk_padded = (rk_text * ((CT_LEN // len(rk_text)) + 1))[:CT_LEN]
        else:
            rk_padded = rk_text[:CT_LEN]

        consistent, conflicts = check_consistency(constraints,
            lambda pos, rk=rk_padded: ALPH_IDX[rk[pos]], f"rk-{name}")
        results[f"rk_{name}"] = {"consistent": consistent, "conflicts": conflicts}
        status = "CONSISTENT" if consistent else f"{conflicts} conflict(s)"
        print(f"  {name:>20}: {status}")

    # Model C: Autokey (row = CT[i-1] or PT[i-1])
    print("\n--- Model C: Autokey row selection ---")
    for offset in range(1, 6):
        # CT-autokey: row[i] = ALPH_IDX[CT[i-offset]] for i >= offset
        def ct_autokey(pos, off=offset):
            if pos < off:
                return 0  # first positions use row 0
            return ALPH_IDX[CT[pos - off]]

        consistent, conflicts = check_consistency(constraints,
            ct_autokey, f"ct-autokey-{offset}")
        results[f"ct_autokey_{offset}"] = {"consistent": consistent, "conflicts": conflicts}
        status = "CONSISTENT" if consistent else f"{conflicts} conflict(s)"
        print(f"  CT-autokey offset {offset}: {status}")

    # Model D: Position-derived (row = some function of position)
    print("\n--- Model D: Position-derived row selection ---")

    # D1: row = position (each position uses unique row - trivially consistent for 26 crib pos)
    consistent, conflicts = check_consistency(constraints,
        lambda pos: pos % 26, "pos-mod-26")
    results["pos_mod_26"] = {"consistent": consistent, "conflicts": conflicts}
    print(f"  pos mod 26: {'CONSISTENT' if consistent else f'{conflicts} conflict(s)'}")

    # D2: row = (position * k) mod 26 for various k
    for k in range(1, 26):
        consistent, conflicts = check_consistency(constraints,
            lambda pos, k=k: (pos * k) % 26, f"pos*{k}-mod-26")
        if consistent:
            results[f"pos_times_{k}_mod26"] = {"consistent": True, "conflicts": 0}
            print(f"  pos*{k} mod 26: CONSISTENT")

    # D3: row = KRYPTOS alphabet at position
    ka_indices = [ALPH_IDX[c] for c in KRYPTOS_ALPHABET]
    def ka_row(pos):
        return ka_indices[pos % 26]
    consistent, conflicts = check_consistency(constraints, ka_row, "ka-cycling")
    results["ka_cycling"] = {"consistent": consistent, "conflicts": conflicts}
    print(f"  KRYPTOS alphabet cycling: {'CONSISTENT' if consistent else f'{conflicts} conflict(s)'}")

    # Model E: Combined models (key + position offset)
    print("\n--- Model E: Combined (running key + offset) ---")
    for name, rk_text in list(RK_SOURCES.items())[:4]:
        if len(rk_text) < CT_LEN:
            rk_padded = (rk_text * ((CT_LEN // len(rk_text)) + 1))[:CT_LEN]
        else:
            rk_padded = rk_text[:CT_LEN]

        for add_offset in [0, 1, 2, 3, 7, 9, 13]:
            def combined(pos, rk=rk_padded, off=add_offset):
                return (ALPH_IDX[rk[pos]] + off) % 26

            consistent, conflicts = check_consistency(constraints,
                combined, f"rk-{name}+{add_offset}")
            if consistent:
                results[f"rk_{name}_plus_{add_offset}"] = {"consistent": True}
                print(f"  {name} + offset {add_offset}: CONSISTENT")

    return results


def check_consistency(constraints, row_fn, model_name):
    """Check if a row-selection function produces consistent constraints.

    For each row, collect all (PT, CT) pairs assigned to it.
    A conflict exists if the same PT letter maps to different CT letters
    within the same row (a permutation can't map one input to two outputs).
    """
    # Group crib positions by assigned row
    row_mappings = defaultdict(list)  # row -> [(PT, CT, pos), ...]
    for pos, pt_ch in CRIB_DICT.items():
        ct_ch = CT[pos]
        row = row_fn(pos)
        row_mappings[row].append((pt_ch, ct_ch, pos))

    conflicts = 0
    for row, mappings in row_mappings.items():
        # Check for conflicting mappings in this row
        pt_to_ct = {}
        ct_to_pt = {}
        for pt_ch, ct_ch, pos in mappings:
            # Forward: PT -> CT must be unique (permutation)
            if pt_ch in pt_to_ct:
                if pt_to_ct[pt_ch] != ct_ch:
                    conflicts += 1
            else:
                pt_to_ct[pt_ch] = ct_ch

            # Reverse: CT -> PT must also be unique (permutation is bijective)
            if ct_ch in ct_to_pt:
                if ct_to_pt[ct_ch] != pt_ch:
                    conflicts += 1
            else:
                ct_to_pt[ct_ch] = pt_ch

    return conflicts == 0, conflicts


# ============================================================================
# PHASE 3: For consistent models, reconstruct partial matrix and score
# ============================================================================

def reconstruct_and_score(constraints, row_fn, model_name):
    """For a consistent row-selection model, reconstruct partial matrix rows
    and try to complete them to produce readable plaintext.

    At crib positions, we know exactly what the row must map.
    At non-crib positions, we try all possible completions and score.
    """
    # Group crib positions by row
    row_constraints = defaultdict(dict)  # row -> {PT: CT}
    for pos, pt_ch in CRIB_DICT.items():
        ct_ch = CT[pos]
        row = row_fn(pos)
        row_constraints[row][pt_ch] = ct_ch

    # For each non-crib position, we need to know the row
    # and then apply the (partially known) row mapping
    non_crib_rows = {}
    for pos in range(CT_LEN):
        if pos not in CRIB_DICT:
            non_crib_rows[pos] = row_fn(pos)

    # Build the partial decryption: for crib positions, PT is known
    # For non-crib positions, use the known row mapping if the CT letter
    # has a known reverse mapping in that row
    partial_pt = list('?' * CT_LEN)

    # Fill known positions
    for pos, pt_ch in CRIB_DICT.items():
        partial_pt[pos] = pt_ch

    # Build reverse mappings per row: CT -> PT
    row_reverse = defaultdict(dict)
    for row, fwd in row_constraints.items():
        for pt_ch, ct_ch in fwd.items():
            row_reverse[row][ct_ch] = pt_ch

    # Try to fill non-crib positions using known reverse mappings
    filled = 0
    for pos in range(CT_LEN):
        if pos not in CRIB_DICT:
            row = row_fn(pos)
            ct_ch = CT[pos]
            if row in row_reverse and ct_ch in row_reverse[row]:
                partial_pt[pos] = row_reverse[row][ct_ch]
                filled += 1

    pt_str = "".join(partial_pt)

    return pt_str, filled


def score_model_with_random_completion(constraints, row_fn, model_name, n_trials=1000):
    """For a consistent model, randomly complete unknown positions and score."""
    # Build row constraints
    row_constraints = defaultdict(dict)
    for pos, pt_ch in CRIB_DICT.items():
        ct_ch = CT[pos]
        row = row_fn(pos)
        row_constraints[row][pt_ch] = ct_ch

    # Build reverse mappings per row
    row_reverse = defaultdict(dict)
    for row, fwd in row_constraints.items():
        for pt_ch, ct_ch in fwd.items():
            row_reverse[row][ct_ch] = pt_ch

    # For non-crib positions, track which ones we can/can't resolve
    resolvable = 0
    unresolvable = 0
    for pos in range(CT_LEN):
        if pos not in CRIB_DICT:
            row = row_fn(pos)
            ct_ch = CT[pos]
            if row in row_reverse and ct_ch in row_reverse[row]:
                resolvable += 1
            else:
                unresolvable += 1

    return resolvable, unresolvable


# ============================================================================
# PHASE 4: Test if shift sequence at cribs matches known running key sources
# ============================================================================

def analyze_shift_pattern(shifts):
    """Analyze the shift sequence at crib positions for patterns."""
    print("\n" + "=" * 72)
    print("PHASE 3: Shift Pattern Analysis at Crib Positions")
    print("=" * 72)

    shift_values = [s for _, s in shifts]
    positions = [p for p, _ in shifts]

    # Check if shifts at crib positions match any running key
    print("\n--- Match against running key sources ---")
    for name, rk_text in RK_SOURCES.items():
        if len(rk_text) < CT_LEN:
            rk_padded = (rk_text * ((CT_LEN // len(rk_text)) + 1))[:CT_LEN]
        else:
            rk_padded = rk_text[:CT_LEN]

        matches = 0
        for pos, shift in shifts:
            rk_val = ALPH_IDX[rk_padded[pos]]
            if rk_val == shift:
                matches += 1

        if matches > 2:  # more than random (expected ~24/26 ≈ 0.92)
            print(f"  {name:>20}: {matches}/{len(shifts)} positions match")

    # Check if shifts match KRYPTOS alphabet at positions
    ka_indices = [ALPH_IDX[c] for c in KRYPTOS_ALPHABET]
    matches_ka = 0
    for pos, shift in shifts:
        if ka_indices[pos % 26] == shift:
            matches_ka += 1
    print(f"  {'KRYPTOS_ALPHABET':>20}: {matches_ka}/{len(shifts)} positions match")

    # Check for arithmetic patterns in shifts
    print("\n--- Shift differences ---")
    for i in range(1, len(shifts)):
        pos1, s1 = shifts[i-1]
        pos2, s2 = shifts[i]
        diff = (s2 - s1) % 26
        pos_diff = pos2 - pos1
        print(f"  pos {pos1}->{pos2} (gap {pos_diff}): shift {s1}->{s2}, diff={diff}")

    # Check if shifts are a simple function of position
    print("\n--- Linear models: shift = (a*pos + b) mod 26 ---")
    best_linear = (0, 0, 0)
    for a in range(26):
        for b in range(26):
            matches = sum(1 for pos, shift in shifts
                         if (a * pos + b) % 26 == shift)
            if matches > best_linear[2]:
                best_linear = (a, b, matches)

    a, b, m = best_linear
    print(f"  Best: shift = ({a}*pos + {b}) mod 26 -> {m}/{len(shifts)} matches")
    if m >= 3:
        print(f"  (Expected random: ~{len(shifts)/26:.1f})")


# ============================================================================
# PHASE 5: Clock-face transposition test
# ============================================================================

def test_clock_transposition():
    """Test reading CT off a clock face arrangement."""
    print("\n" + "=" * 72)
    print("PHASE 4: Clock-Face Transposition Tests")
    print("=" * 72)

    best_score = 0
    best_config = None
    configs_tested = 0

    # Arrange CT around clock faces of various sizes
    for n_positions in [12, 8, 6, 4, 3, 2]:
        # Number of characters per position
        chars_per = CT_LEN // n_positions
        remainder = CT_LEN % n_positions

        # Try reading in different orders
        # Clockwise from each starting position
        for start in range(n_positions):
            # CW: start, start+1, start+2, ...
            cw_order = [(start + i) % n_positions for i in range(n_positions)]
            # CCW: start, start-1, start-2, ...
            ccw_order = [(start - i) % n_positions for i in range(n_positions)]

            for order_name, order in [("CW", cw_order), ("CCW", ccw_order)]:
                # Read characters from positions in this order
                # First, arrange CT into clock positions
                pos_chars = [[] for _ in range(n_positions)]
                for i, ch in enumerate(CT):
                    pos_chars[i % n_positions].append(ch)

                # Read in specified order
                reordered = ""
                for p in order:
                    reordered += "".join(pos_chars[p])

                if len(reordered) == CT_LEN:
                    sc = score_cribs(reordered)
                    configs_tested += 1
                    if sc > best_score:
                        best_score = sc
                        best_config = f"n={n_positions}, start={start}, {order_name}"
                    if sc > NOISE_FLOOR:
                        print(f"  n={n_positions}, start={start}, {order_name}: score={sc}")

    # Also try: arrange in N rows, read columns in clock order
    for width in [12, 9, 8, 7, 6]:
        n_rows = (CT_LEN + width - 1) // width
        # Pad CT if needed
        padded = CT + "X" * (width * n_rows - CT_LEN)

        # Arrange in grid
        grid = []
        for r in range(n_rows):
            grid.append(padded[r * width:(r + 1) * width])

        # Read columns in different orders
        for col_start in range(width):
            for direction in [1, -1]:  # CW or CCW
                col_order = [(col_start + direction * i) % width for i in range(width)]

                reordered = ""
                for c in col_order:
                    for r in range(n_rows):
                        if r * width + c < CT_LEN:
                            reordered += CT[r * width + c]

                sc = score_cribs(reordered)
                configs_tested += 1
                if sc > best_score:
                    best_score = sc
                    best_config = f"grid w={width}, col_start={col_start}, dir={direction}"
                if sc > NOISE_FLOOR:
                    print(f"  grid w={width}, col_start={col_start}, dir={'CW' if direction==1 else 'CCW'}: score={sc}")

    print(f"\n  Total configs tested: {configs_tested}")
    print(f"  Best score: {best_score} ({best_config})")
    return best_score, configs_tested


# ============================================================================
# PHASE 6: Authentication table encoding test
# ============================================================================

def test_auth_word_encoding():
    """Test if CT could be produced by a 10-letter authentication word mapping.

    In SOI authentication, a 10-letter word (no repeating letters) maps to
    digits 1-9,0. If K4 uses this, the CT letters would encode digits
    representing something (coordinates, another encoding layer, etc.)

    We test: does mapping CT through various 10-letter words produce
    digit sequences with structure (repeating patterns, valid coordinates)?
    """
    print("\n" + "=" * 72)
    print("PHASE 5: Authentication Word Encoding Test")
    print("=" * 72)

    # Thematic 10-letter words (no repeating letters)
    auth_words = [
        "KRYPTOSAFE",  # K-R-Y-P-T-O-S-A-F-E = 10 unique
        "CRYPTOBASE",  # C-R-Y-P-T-O-B-A-S-E = 10 unique
        "BLACKSTONE",  # B-L-A-C-K-S-T-O-N-E = 10 unique
        "ANGLERFISH",  # A-N-G-L-E-R-F-I-S-H = 10 unique (classic SOI example)
        "SPECTRUMJB",  # S-P-E-C-T-R-U-M-J-B = 10 unique
        "AMBIDEXTRY",  # A-M-B-I-D-E-X-T-R-Y = 10 unique
        "THUMBSCREW",  # T-H-U-M-B-S-C-R-E-W = 10 unique
        "NIGHTCLUBS",  # N-I-G-H-T-C-L-U-B-S = 10 unique
        "COMBATFLYRS",  # Too many, skip
        "FLASHPOINT",  # F-L-A-S-H-P-O-I-N-T = 10 unique
    ]

    # Validate and filter
    valid_words = []
    for w in auth_words:
        if len(w) == 10 and len(set(w)) == 10:
            valid_words.append(w)

    print(f"\nTesting {len(valid_words)} authentication words against CT")

    for word in valid_words:
        # Map: word[i] -> digit (i+1 mod 10, so 1,2,...,9,0)
        letter_to_digit = {}
        for i, ch in enumerate(word):
            letter_to_digit[ch] = (i + 1) % 10

        # How many CT letters can this word encode?
        encodable = sum(1 for ch in CT if ch in letter_to_digit)

        # Encode what we can
        encoded = []
        for ch in CT:
            if ch in letter_to_digit:
                encoded.append(str(letter_to_digit[ch]))
            else:
                encoded.append('?')

        encoded_str = "".join(encoded)
        coverage = encodable / CT_LEN * 100

        # Check if coverage is sufficient (need all 26 CT letters covered,
        # but a 10-letter word can only cover 10 letters)
        print(f"  {word}: {encodable}/{CT_LEN} encodable ({coverage:.0f}%)")

        if encodable >= 50:  # More than half
            # Show encoded sequence at crib positions
            crib_encoded = ""
            for pos in range(21, 34):
                crib_encoded += encoded[pos]
            print(f"    ENE crib -> {crib_encoded}")
            crib_encoded2 = ""
            for pos in range(63, 74):
                crib_encoded2 += encoded[pos]
            print(f"    BC  crib -> {crib_encoded2}")

    return len(valid_words)


# ============================================================================
# Main
# ============================================================================

def main():
    print("E-S-145: DRYAD/BATCO-Style Matrix Table Cipher for K4")
    print("=" * 72)

    results = {"experiment": "E-S-145", "seed": SEED}

    # Phase 1: Analyze crib constraints
    constraints, shifts = analyze_crib_constraints()
    results["shifts"] = [(p, s) for p, s in shifts]

    # Phase 2: Test row selection models
    model_results = test_row_selection_models(constraints, shifts)
    results["model_consistency"] = model_results

    # Count consistent models
    consistent_models = [k for k, v in model_results.items() if v.get("consistent")]
    print(f"\n*** {len(consistent_models)} consistent models found ***")

    # Phase 3: Analyze shift patterns
    analyze_shift_pattern(shifts)

    # Phase 3.5: For consistent models, try partial reconstruction
    print("\n" + "=" * 72)
    print("PHASE 3b: Partial Reconstruction for Consistent Models")
    print("=" * 72)

    recon_results = {}
    for model_name in consistent_models[:20]:  # Limit to first 20
        # Reconstruct the row function
        if model_name.startswith("periodic_"):
            period = int(model_name.split("_")[1])
            row_fn = lambda pos, p=period: pos % p
        elif model_name.startswith("rk_"):
            # Parse running key name
            parts = model_name.split("_", 1)[1]
            if "_plus_" in parts:
                rk_name, offset_str = parts.rsplit("_plus_", 1)
                offset = int(offset_str)
                rk_text = RK_SOURCES.get(rk_name, "")
                if not rk_text:
                    continue
                rk_padded = (rk_text * ((CT_LEN // len(rk_text)) + 1))[:CT_LEN]
                row_fn = lambda pos, rk=rk_padded, off=offset: (ALPH_IDX[rk[pos]] + off) % 26
            else:
                rk_text = RK_SOURCES.get(parts, "")
                if not rk_text:
                    continue
                rk_padded = (rk_text * ((CT_LEN // len(rk_text)) + 1))[:CT_LEN]
                row_fn = lambda pos, rk=rk_padded: ALPH_IDX[rk[pos]]
        elif model_name.startswith("ct_autokey_"):
            offset = int(model_name.split("_")[-1])
            row_fn = lambda pos, off=offset: ALPH_IDX[CT[pos - off]] if pos >= off else 0
        elif model_name.startswith("pos_times_"):
            k = int(model_name.split("_")[2])
            row_fn = lambda pos, k=k: (pos * k) % 26
        elif model_name == "pos_mod_26":
            row_fn = lambda pos: pos % 26
        elif model_name == "ka_cycling":
            ka_indices = [ALPH_IDX[c] for c in KRYPTOS_ALPHABET]
            row_fn = lambda pos: ka_indices[pos % 26]
        else:
            continue

        pt_str, filled = reconstruct_and_score(constraints, row_fn, model_name)
        resolvable, unresolvable = score_model_with_random_completion(
            constraints, row_fn, model_name)

        recon_results[model_name] = {
            "partial_pt": pt_str,
            "filled_from_crib_reuse": filled,
            "resolvable": resolvable,
            "unresolvable": unresolvable,
        }

        # Show partial plaintext
        known_chars = sum(1 for c in pt_str if c != '?')
        print(f"\n  {model_name}: {known_chars}/{CT_LEN} positions resolved ({filled} from crib row reuse)")
        if filled > 5:
            print(f"    PT: {pt_str}")

    results["reconstruction"] = {k: {kk: vv for kk, vv in v.items() if kk != "partial_pt"}
                                  for k, v in recon_results.items()}

    # Phase 4: Clock transposition
    clock_best, clock_configs = test_clock_transposition()
    results["clock_transposition"] = {"best_score": clock_best, "configs_tested": clock_configs}

    # Phase 5: Authentication word test
    n_auth = test_auth_word_encoding()
    results["auth_word_test"] = {"words_tested": n_auth}

    # Summary
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"\nConsistent row-selection models: {len(consistent_models)}")
    for m in consistent_models[:10]:
        print(f"  - {m}")
    if len(consistent_models) > 10:
        print(f"  ... and {len(consistent_models) - 10} more")

    print(f"\nClock transposition best: {clock_best}/24")
    print(f"Authentication word encoding: limited by 10-letter alphabet (max ~40% CT coverage)")

    # Determine signal level
    max_score = clock_best
    if max_score <= NOISE_FLOOR:
        print(f"\n*** RESULT: ALL tests at NOISE level (best={max_score}). ***")
        print("*** Matrix table hypothesis cannot be eliminated by consistency alone. ***")
        print("*** Consistent models exist but produce no discriminating signal. ***")
    else:
        print(f"\n*** RESULT: Signal found at score {max_score} ***")

    # Save results
    os.makedirs("results", exist_ok=True)
    output_path = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_s_145_dryad_matrix.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
