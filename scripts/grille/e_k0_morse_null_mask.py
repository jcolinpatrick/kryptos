#!/usr/bin/env python3
"""
E-K0-MORSE-NULL-MASK: Derive K4 null masks from K0 Morse code oddities.

Hypothesis: The 26 extra E's in K0 Morse code encode the null mask for K4.
Since we need exactly 24 nulls (97-73=24), we test all ways to drop 2 of the
26 E's, and all plausible mapping mechanisms.

Mapping mechanisms tested:
  1. Run-length: E-groups = null runs, inter-group message counts = skip runs
  2. Cumulative E-positions in the 107-char K0 text, mapped mod 97
  3. E-group sizes as direct position offsets (cumulative)
  4. Binary: full K0 text as 97-length binary (E=null, other=real) via truncation/wrap
  5. Inter-group message counts as position generators

For each mapping × each (26 choose 2) = 325 ways to drop 2 E's:
  - Generate 24 null positions
  - Check: do ANY fall on crib positions {21-33, 63-73}?
  - If clean (no conflicts): score with the DEFECTOR:AZ_beau+col7 pipeline

Cipher: null-mask-from-K0
Family: grille
Status: active
Keyspace: ~10K mappings
Last run: never
Best score: n/a
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate_free

# --- K0 Morse structure ---
# Decoded K0 text with E's as lowercase 'e', message letters as uppercase
# Reconstructed from anomaly_registry.md and kryptosfan_findings.md
K0_PANELS = [
    "eeVIRTUALLYeeeeeINVISIBLE",
    "eDIGETALeeeINTERPRETATIU",
    "eeSHADOWeeFORCESeeeee",
    "LUCIDeeeNEMORYe",           # Note: some sources say MEMORY not NEMORY
    "TISYOURPOSITIONe",
    "SOS",
    "RQ",
]

# Build the full K0 text
K0_FULL = "".join(K0_PANELS)

# Correct MEMORY panel (sources vary on exact letters)
# Try both variants
K0_PANELS_ALT = list(K0_PANELS)
K0_PANELS_ALT[3] = "LUCIDeeeMEMORYe"
K0_FULL_ALT = "".join(K0_PANELS_ALT)

# E-group sizes (from anomaly_registry)
E_GROUP_SIZES = [2, 1, 5, 1, 3, 2, 2, 5, 3, 1, 1]
assert sum(E_GROUP_SIZES) == 26

# Inter-group message letter counts
INTER_GROUP_MSG = [0, 9, 9, 7, 13, 6, 6, 5, 6, 15, 3, 2]
assert sum(INTER_GROUP_MSG) == 81

# Crib positions (0-indexed)
CRIB_SET = set(range(21, 34)) | set(range(63, 74))  # 24 positions
assert len(CRIB_SET) == 24

# All 97 K4 positions
ALL_POS = set(range(97))
SAFE_POS = ALL_POS - CRIB_SET  # 73 positions where nulls are allowed

print(f"K4 CT: {CT}")
print(f"CT length: {len(CT)}")
print(f"Crib positions: {sorted(CRIB_SET)}")
print(f"Safe positions (can be null): {len(SAFE_POS)}")
print(f"K0 full text length: {len(K0_FULL)}")
print(f"K0 E count: {sum(1 for c in K0_FULL if c == 'e')}")
print(f"K0 message letter count: {sum(1 for c in K0_FULL if c != 'e')}")
print()

# --- Identify E positions in K0 text ---
def get_e_positions(text):
    """Return 0-indexed positions of all lowercase 'e' in K0 text."""
    return [i for i, c in enumerate(text) if c == 'e']

def get_e_groups(text):
    """Return list of (start_pos, size) for each contiguous E group."""
    groups = []
    i = 0
    while i < len(text):
        if text[i] == 'e':
            start = i
            while i < len(text) and text[i] == 'e':
                i += 1
            groups.append((start, i - start))
        else:
            i += 1
    return groups

# --- Mapping mechanisms ---

def mapping_runlength(e_groups, inter_msg, n_ct=97):
    """
    Run-length mapping: alternate null-runs and skip-runs.
    E-group sizes = how many consecutive nulls to place.
    Inter-group message counts = how many positions to skip (real chars).
    Try all starting offsets 0..96.
    """
    results = []
    for start in range(n_ct):
        nulls = []
        pos = start
        for gi in range(len(e_groups)):
            # Place nulls
            for _ in range(e_groups[gi]):
                nulls.append(pos % n_ct)
                pos += 1
            # Skip message chars
            if gi < len(inter_msg):
                pos += inter_msg[gi]
        if len(nulls) >= 24:
            results.append((start, "fwd", nulls[:24]))

    # Also try reversed group order
    rev_groups = list(reversed(e_groups))
    rev_msg = list(reversed(inter_msg))
    for start in range(n_ct):
        nulls = []
        pos = start
        for gi in range(len(rev_groups)):
            for _ in range(rev_groups[gi]):
                nulls.append(pos % n_ct)
                pos += 1
            if gi < len(rev_msg):
                pos += rev_msg[gi]
        if len(nulls) >= 24:
            results.append((start, "rev", nulls[:24]))

    return results


def mapping_e_positions_mod97(e_positions):
    """
    Direct mapping: position of each E in K0 text, taken mod 97.
    """
    return [p % 97 for p in e_positions]


def mapping_cumulative_group_sizes(e_groups):
    """
    Cumulative sum of E-group sizes as positions.
    E.g., [2,1,5,...] → positions [2, 3, 8, ...]
    Try with different multipliers/offsets.
    """
    results = []
    cumsum = []
    s = 0
    for g in e_groups:
        s += g
        cumsum.append(s)
    # cumsum = [2, 3, 8, 9, 12, 14, 16, 21, 24, 25, 26]

    # Direct cumulative
    for offset in range(97):
        mapped = [(c + offset) % 97 for c in cumsum]
        results.append((offset, "cumsum", mapped))

    # Cumulative with inter-group added
    cumsum2 = []
    s = 0
    for i in range(len(e_groups)):
        s += e_groups[i]
        cumsum2.append(s)
        if i < len(INTER_GROUP_MSG):
            s += INTER_GROUP_MSG[i]
    for offset in range(97):
        mapped = [(c + offset) % 97 for c in cumsum2]
        results.append((offset, "cumsum+msg", mapped))

    return results


def mapping_intergroup_as_positions(inter_msg):
    """
    Inter-group message counts as cumulative positions.
    [0, 9, 9, 7, 13, 6, 6, 5, 6, 15, 3, 2] → cumulative [0, 9, 18, 25, 38, 44, 50, 55, 61, 76, 79, 81]
    """
    results = []
    cumsum = []
    s = 0
    for m in inter_msg:
        s += m
        cumsum.append(s)
    for offset in range(97):
        mapped = [(c + offset) % 97 for c in cumsum]
        results.append((offset, "intergroupcum", mapped))
    return results


def mapping_binary_97(text, n_ct=97):
    """
    Binary mapping: encode K0 as binary string (e=1/null, other=0/real).
    Since K0 has 107 chars and K4 has 97, try:
    - Truncate to first 97
    - Truncate to last 97
    - Wrap (mod 97)
    """
    results = []
    binary = [1 if c == 'e' else 0 for c in text]

    # Truncate first 97
    if len(binary) >= n_ct:
        b97 = binary[:n_ct]
        nulls = [i for i, v in enumerate(b97) if v == 1]
        results.append(("trunc_first97", nulls))

    # Truncate last 97
    if len(binary) >= n_ct:
        b97 = binary[-n_ct:]
        nulls = [i for i, v in enumerate(b97) if v == 1]
        results.append(("trunc_last97", nulls))

    # Wrap: XOR positions mod 97
    wrapped = [0] * n_ct
    for i, v in enumerate(binary):
        if v == 1:
            wrapped[i % n_ct] ^= 1  # Toggle
    nulls = [i for i, v in enumerate(wrapped) if v == 1]
    results.append(("wrap_xor", nulls))

    # Wrap: OR positions mod 97
    wrapped_or = [0] * n_ct
    for i, v in enumerate(binary):
        if v == 1:
            wrapped_or[i % n_ct] = 1
    nulls = [i for i, v in enumerate(wrapped_or) if v == 1]
    results.append(("wrap_or", nulls))

    return results


def mapping_e_group_starts(e_groups_with_pos):
    """
    Use the starting position of each E-group, mapped mod 97.
    11 groups → 11 positions. Not enough for 24, but check anyway.
    """
    results = []
    starts = [g[0] for g in e_groups_with_pos]
    for offset in range(97):
        mapped = [(s + offset) % 97 for s in starts]
        results.append((offset, "groupstarts", mapped))
    return results


def mapping_individual_e_positions_offset(e_positions, n_ct=97):
    """
    Each E position mapped to K4 with various offsets and scaling.
    """
    results = []
    for offset in range(n_ct):
        mapped = [(p + offset) % n_ct for p in e_positions]
        results.append((offset, "direct+offset", mapped))
    # Scaled by common factors
    for scale in [2, 3, 4, 5, 7]:
        for offset in range(n_ct):
            mapped = [(p * scale + offset) % n_ct for p in e_positions]
            results.append((offset, f"scale{scale}+offset", mapped))
    return results


# --- Drop-2 combinations ---
from itertools import combinations

def drop_2_from_26(positions_26):
    """Generate all C(26,2)=325 ways to drop 2 positions, yielding 24."""
    for drop in combinations(range(len(positions_26)), 2):
        yield [p for i, p in enumerate(positions_26) if i not in drop], drop


# --- Main search ---
def check_crib_conflict(null_positions):
    """Return True if ANY null position conflicts with a crib position."""
    return bool(set(null_positions) & CRIB_SET)


def extract_ct(null_pos):
    """Extract CT with nulls removed."""
    ns = set(null_pos)
    return "".join(c for i, c in enumerate(CT) if i not in ns)


# Score using the kernel
def score_with_pipeline(null_pos):
    """Quick score: extract CT, apply no transposition, check free crib."""
    extracted = extract_ct(null_pos)
    # Just check if extracted text has any crib fragments
    result = score_candidate_free(extracted)
    return result


def main():
    print("=" * 70)
    print("K0 MORSE NULL MASK SEARCH")
    print("=" * 70)

    # Get E positions for both K0 variants
    for label, k0_text in [("primary", K0_FULL), ("alt_MEMORY", K0_FULL_ALT)]:
        e_pos = get_e_positions(k0_text)
        e_groups = get_e_groups(k0_text)

        print(f"\n--- K0 variant: {label} ---")
        print(f"E positions in K0: {e_pos}")
        print(f"E groups: {e_groups}")
        print(f"E group sizes: {[g[1] for g in e_groups]}")
        print(f"Total E's: {len(e_pos)}")

        clean_masks = []  # (mechanism, params, null_positions)

        # === MECHANISM 1: Run-length mapping ===
        print("\n[1] Run-length mapping (E-groups=nulls, inter-group=skips)...")
        group_sizes = [g[1] for g in e_groups]
        rl_results = mapping_runlength(group_sizes, INTER_GROUP_MSG)
        rl_clean = 0
        for start, direction, nulls in rl_results:
            # This gives 24 nulls if we use first 24 from 26 total
            # But actually the run-length gives 26 nulls, need to drop 2
            unique_nulls = list(dict.fromkeys(nulls))  # dedup preserving order
            if len(unique_nulls) < 24:
                continue
            unique_nulls = unique_nulls[:24]
            if not check_crib_conflict(unique_nulls):
                rl_clean += 1
                clean_masks.append(("runlength", f"start={start},{direction}", unique_nulls))
        print(f"  Tested: {len(rl_results)}, Clean (no crib conflict): {rl_clean}")

        # === MECHANISM 2: E positions mod 97, drop 2 ===
        print("\n[2] E positions mod 97 (drop 2 of 26)...")
        e_mod97 = mapping_e_positions_mod97(e_pos)
        m2_clean = 0
        m2_tested = 0
        for positions_24, dropped in drop_2_from_26(e_mod97):
            m2_tested += 1
            unique = list(dict.fromkeys(positions_24))
            if len(unique) < 24:
                continue
            if not check_crib_conflict(unique[:24]):
                m2_clean += 1
                clean_masks.append(("e_mod97", f"dropped_indices={dropped}", unique[:24]))
        print(f"  Tested: {m2_tested}, Clean: {m2_clean}")

        # === MECHANISM 2b: E positions with offset, mod 97, drop 2 ===
        print("\n[2b] E positions + offset mod 97 (drop 2)...")
        m2b_clean = 0
        m2b_tested = 0
        for offset in range(97):
            shifted = [(p + offset) % 97 for p in e_pos]
            for positions_24, dropped in drop_2_from_26(shifted):
                m2b_tested += 1
                unique = list(dict.fromkeys(positions_24))
                if len(unique) < 24:
                    continue
                if not check_crib_conflict(unique[:24]):
                    m2b_clean += 1
                    if m2b_clean <= 20:  # Limit stored
                        clean_masks.append(("e_mod97+offset", f"offset={offset},dropped={dropped}", unique[:24]))
        print(f"  Tested: {m2b_tested}, Clean: {m2b_clean}")

        # === MECHANISM 3: Binary mapping (107→97) ===
        print("\n[3] Binary mapping (E=null in 107-char text → 97)...")
        bin_results = mapping_binary_97(k0_text)
        m3_clean = 0
        for method, nulls in bin_results:
            n = len(nulls)
            print(f"  {method}: {n} nulls", end="")
            if n == 24:
                if not check_crib_conflict(nulls):
                    m3_clean += 1
                    clean_masks.append(("binary", method, sorted(nulls)))
                    print(" → CLEAN!", end="")
                else:
                    conflicts = set(nulls) & CRIB_SET
                    print(f" → CONFLICTS at {sorted(conflicts)}", end="")
            elif n > 24:
                # Try dropping extras
                for positions_24, dropped in drop_2_from_26(nulls) if n == 26 else []:
                    unique = list(dict.fromkeys(positions_24))
                    if len(unique) >= 24 and not check_crib_conflict(unique[:24]):
                        m3_clean += 1
                        clean_masks.append(("binary_drop2", method, unique[:24]))
                print(f" (need 24, got {n})", end="")
            else:
                print(f" (need 24, got {n})", end="")
            print()
        print(f"  Clean: {m3_clean}")

        # === MECHANISM 4: Run-length with full drop-2 combinatorics ===
        print("\n[4] Run-length with drop-2 from 26 E's...")
        # Build all 26 null positions from run-length at each start, then drop 2
        m4_clean = 0
        m4_tested = 0
        for start in range(97):
            nulls_26 = []
            pos = start
            for gi in range(len(group_sizes)):
                for _ in range(group_sizes[gi]):
                    nulls_26.append(pos % 97)
                    pos += 1
                if gi < len(INTER_GROUP_MSG):
                    pos += INTER_GROUP_MSG[gi]

            # Check uniqueness
            if len(set(nulls_26)) < 26:
                continue  # Wrapped positions collide

            for positions_24, dropped in drop_2_from_26(nulls_26):
                m4_tested += 1
                unique = list(dict.fromkeys(positions_24))
                if len(unique) < 24:
                    continue
                if not check_crib_conflict(unique[:24]):
                    m4_clean += 1
                    if m4_clean <= 20:
                        clean_masks.append(("runlength_drop2", f"start={start},dropped={dropped}", unique[:24]))

        print(f"  Tested: {m4_tested}, Clean: {m4_clean}")

        # === MECHANISM 5: Reversed binary (read K0 backwards) ===
        print("\n[5] Reversed K0 binary mapping...")
        rev_text = k0_text[::-1]
        rev_results = mapping_binary_97(rev_text)
        m5_clean = 0
        for method, nulls in rev_results:
            n = len(nulls)
            print(f"  rev_{method}: {n} nulls", end="")
            if n == 24 and not check_crib_conflict(nulls):
                m5_clean += 1
                clean_masks.append(("binary_rev", method, sorted(nulls)))
                print(" → CLEAN!", end="")
            elif n == 24:
                conflicts = set(nulls) & CRIB_SET
                print(f" → CONFLICTS at {sorted(conflicts)}", end="")
            else:
                print(f" (need 24, got {n})", end="")
            print()

        # === MECHANISM 6: Numeric values from oddities ===
        print("\n[6] Numeric values from K0 oddities...")
        # T=19, R=17, Q=16, S=18, O=14 (A=0 numbering)
        # DIGETAL position 4 change, group sizes, etc.
        oddity_numbers = [
            19,  # T (T IS YOUR POSITION)
            17,  # R (from RQ)
            16,  # Q (from RQ)
            4,   # DIGETAL: position of I→E change
            24, 0, 17,  # Y, A, R values (YAR superscript)
            5, 8,  # DESPARATLY: positions of changes
        ]
        # These are only 9 numbers, not enough for 24
        print(f"  Oddity numbers: {oddity_numbers} (only {len(oddity_numbers)}, need 24)")

        # === Report results ===
        print("\n" + "=" * 70)
        print(f"TOTAL CLEAN MASKS (no crib conflicts): {len(clean_masks)}")
        print("=" * 70)

        if clean_masks:
            # Show first 30 clean masks
            shown = 0
            for mechanism, params, nulls in clean_masks[:30]:
                sorted_nulls = sorted(nulls)
                extracted = extract_ct(sorted_nulls)
                print(f"\n  [{mechanism}] {params}")
                print(f"  Null positions: {sorted_nulls}")
                print(f"  Extracted CT ({len(extracted)} chars): {extracted}")

                # Quick check: do W positions appear as nulls?
                w_pos = {20, 36, 48, 58, 74}
                w_nulls = w_pos & set(sorted_nulls)
                print(f"  W positions as nulls: {sorted(w_nulls)} ({len(w_nulls)}/5)")

                # Check consensus null overlap
                consensus = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
                overlap = set(sorted_nulls) & consensus
                print(f"  Consensus overlap: {len(overlap)}/17 ({sorted(overlap)})")

                shown += 1

            if len(clean_masks) > 30:
                print(f"\n  ... and {len(clean_masks) - 30} more clean masks")

            # Summary statistics
            print("\n" + "-" * 70)
            print("SUMMARY BY MECHANISM:")
            from collections import Counter
            mech_counts = Counter(m[0] for m in clean_masks)
            for mech, count in mech_counts.most_common():
                print(f"  {mech}: {count} clean masks")
        else:
            print("\nNo clean masks found — all mappings conflict with crib positions.")
            print("This means K0 E-positions cannot directly encode the null mask")
            print("without additional transformation or a different mapping mechanism.")


if __name__ == "__main__":
    main()
