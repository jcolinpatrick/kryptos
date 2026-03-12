#!/usr/bin/env python3
"""Geometric Null Position Rules — What pattern selects 24 of 97?

Family:    geodetic
Cipher:    geometry-defined null mask + keyword substitution
Status:    active
Keyspace:  ~500K (structural rules × top keywords × cipher variants)
Last run:  never
Best score: n/a

The geometry likely defines the READING RULE (which 73 of 97 are real),
not the substitution key. Tests structural rules for null placement
derived from geometric relationships, then applies keyword decryption
to the 73-char extract.

Key insight: 73 mod 26 = 21 = EASTNORTHEAST crib start position.
The geometry encodes the 73-char model AND the crib location.
"""
import math
import sys
import os
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT, N_CRIBS, ALPH, CT_LEN
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.crib_score import score_cribs

# ── Geometric constants ──

# Key geometric values
LOOMIS_ABBOTT_AZ = 45.58    # published geodetic azimuth (degrees)
LOOMIS_SCULPTURE_BEARING = 52.77
LOOMIS_K2_BEARING = 85.03
LOOMIS_COMPASS_BEARING = 141.90
LOOMIS_SCULPTURE_DIST = 64.7   # meters
LOOMIS_COMPASS_DIST = 8.6
LOOMIS_K2_DIST = 99.9
INTERSECTION_73_BEARING = 73.4  # SC×K2 ∩ lodestone ENE

# Known special positions
W_POSITIONS = [20, 36, 48, 58, 74]  # W-as-delimiter hypothesis
CRIB_START_POSITIONS = [21, 63]     # ENE at 21, BC at 63

# Top keyword candidates (from prior analysis)
KEYWORDS = [
    'KRYPTOS', 'KOMPASS', 'DEFECTOR', 'COLOPHON', 'ABSCISSA',
    'LOOMIS', 'ABBOTT', 'COMPASS', 'AZIMUTH', 'BEARING',
    'SURVEY', 'LODESTONE', 'MAGNETIC', 'BERLIN', 'QUARTZ',
    'PALIMPSEST', 'ENIGMA', 'SHADOW', 'SANBORN',
    'INVISIBLE', 'FORCES', 'TRIANGLE', 'STATION',
]


def extract_and_test(null_positions, rule_name):
    """Extract 73 chars by removing null positions, test with keywords."""
    null_set = set(null_positions)
    if len(null_set) != 24:
        return []

    # Map original positions to extracted positions
    kept_positions = [i for i in range(CT_LEN) if i not in null_set]
    if len(kept_positions) != 73:
        return []

    extracted = ''.join(CT[i] for i in kept_positions)

    # Build crib dict for extracted text
    # If original crib position p is in kept_positions, find its new position
    extracted_crib = {}
    pos_map = {orig: new for new, orig in enumerate(kept_positions)}
    for orig_pos, ch in CRIB_DICT.items():
        if orig_pos in pos_map:
            extracted_crib[pos_map[orig_pos]] = ch

    results = []

    # Test identity (no substitution — cribs in extracted text?)
    identity_hits = sum(1 for p, c in extracted_crib.items()
                       if p < len(extracted) and extracted[p] == c)
    if identity_hits >= 3:
        results.append((identity_hits, 'identity', rule_name, extracted[:40]))

    # Test with keyword substitution
    for keyword in KEYWORDS:
        key = [ord(c) - 65 for c in keyword]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(extracted, key, variant)
            # Score against extracted crib positions
            hits = sum(1 for p, c in extracted_crib.items()
                      if p < len(pt) and pt[p] == c)
            if hits >= 5:
                results.append((hits, f"{variant.value}({keyword})", rule_name,
                              pt[:40]))

    # Test with single-letter keys
    for k in range(26):
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(extracted, [k], variant)
            hits = sum(1 for p, c in extracted_crib.items()
                      if p < len(pt) and pt[p] == c)
            if hits >= 5:
                results.append((hits, f"{variant.value}(k={ALPH[k]})", rule_name,
                              pt[:40]))

    return results


def generate_geometric_null_rules():
    """Generate null position sets based on geometric structural rules."""
    rules = {}

    # ── Rule 1: Grid-based (write into grid, null specific cells) ──
    for width in [7, 8, 13, 14, 31]:
        nrows = (CT_LEN + width - 1) // width

        # Null the last column (short column)
        nulls = [r * width + (width - 1) for r in range(nrows) if r * width + (width - 1) < CT_LEN]
        if len(nulls) == 24:
            rules[f"grid({width})_last_col"] = nulls

        # Null every width-th position
        for offset in range(width):
            nulls = [r * width + offset for r in range(nrows) if r * width + offset < CT_LEN]
            if len(nulls) == 24:
                rules[f"grid({width})_col{offset}"] = nulls

        # Null diagonal positions
        nulls = [(r * width + r % width) for r in range(nrows) if (r * width + r % width) < CT_LEN]
        if len(nulls) <= 24:
            # Pad with remaining positions
            need = 24 - len(nulls)
            extras = [(r * width + (r + 1) % width) for r in range(nrows)
                     if (r * width + (r + 1) % width) < CT_LEN
                     and (r * width + (r + 1) % width) not in nulls]
            nulls = sorted(set(nulls + extras[:need]))
            if len(nulls) == 24:
                rules[f"grid({width})_diag"] = nulls

    # ── Rule 2: Modular rules ──
    for mod_val in range(3, 30):
        for remainder in range(mod_val):
            nulls = [i for i in range(CT_LEN) if i % mod_val == remainder]
            if len(nulls) == 24:
                rules[f"mod{mod_val}_r{remainder}"] = nulls

    # ── Rule 3: Geometric bearing thresholds ──
    # Position i is null if i maps to a bearing below threshold
    # (treating position as angle: i * 360/97)
    for threshold in range(0, 360, 5):
        nulls = [i for i in range(CT_LEN)
                if (i * 360.0 / CT_LEN) % 360 < threshold
                and (i * 360.0 / CT_LEN) % 360 >= threshold - 90]
        if len(nulls) == 24:
            rules[f"angle_sector_{threshold-90}_{threshold}"] = nulls

    # ── Rule 4: W positions + regular fill ──
    # Start with 5 W positions, add 19 more by a rule
    base_W = set(W_POSITIONS)
    for step in range(2, 20):
        for offset in range(step):
            extras = [i for i in range(offset, CT_LEN, step) if i not in base_W]
            nulls = sorted(base_W | set(extras[:19]))
            if len(nulls) == 24:
                rules[f"W+step{step}_off{offset}"] = nulls

    # ── Rule 5: Fibonacci/geometric sequences ──
    # Fibonacci: 1,1,2,3,5,8,13,21,34,55,89
    fib = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]
    fib_nulls = sorted(set(f for f in fib if f < CT_LEN))
    if len(fib_nulls) < 24:
        # Add reflected positions
        reflected = sorted(set(CT_LEN - 1 - f for f in fib if CT_LEN - 1 - f >= 0
                             and CT_LEN - 1 - f not in fib_nulls))
        fib_nulls = sorted(set(fib_nulls + reflected[:24 - len(fib_nulls)]))
    if len(fib_nulls) == 24:
        rules["fibonacci+reflected"] = fib_nulls

    # Primes up to 97
    primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89]
    if len(primes) == 24:
        rules["primes<97"] = primes

    # ── Rule 6: Bearing-derived positions ──
    # Use LOOMIS bearings to derive null positions
    bearings = [45.47, 52.77, 54.09, 85.03, 141.90]
    for scale in [1.0, 0.5, 2.0]:
        nulls = sorted(set(round(b * scale) % CT_LEN for b in bearings))
        # Extend by cycling
        while len(nulls) < 24:
            new = sorted(set((n + round(bearings[0])) % CT_LEN for n in nulls) - set(nulls))
            if not new:
                break
            nulls = sorted(set(nulls + new[:24 - len(nulls)]))
        if len(nulls) == 24:
            rules[f"bearing_scale{scale}"] = nulls

    # ── Rule 7: 28×31 grid positions ──
    # K4 starts at row 24, col 27 in the 28×31 master grid
    # Null positions might correspond to specific grid cells
    k4_start_row, k4_start_col = 24, 27
    for pattern in ['checkerboard', 'border', 'cross']:
        nulls = []
        for i in range(CT_LEN):
            # Map position i to (row, col) in 28×31 grid
            abs_pos = (k4_start_row * 31 + k4_start_col) + i
            grid_row = abs_pos // 31
            grid_col = abs_pos % 31
            if pattern == 'checkerboard' and (grid_row + grid_col) % 2 == 0:
                nulls.append(i)
            elif pattern == 'border' and (grid_row in [24, 27] or grid_col in [27, 30]):
                nulls.append(i)
            elif pattern == 'cross' and (grid_col == 28 or grid_row == 25):
                nulls.append(i)
        nulls = nulls[:24]
        if len(nulls) == 24:
            rules[f"grid28x31_{pattern}"] = nulls

    # ── Rule 8: ABBOTT azimuth = 45.58 → every 4th starting at position 45%97 ──
    for start in [round(LOOMIS_ABBOTT_AZ) % CT_LEN,
                  round(LOOMIS_SCULPTURE_BEARING) % CT_LEN,
                  round(LOOMIS_K2_BEARING) % CT_LEN,
                  round(INTERSECTION_73_BEARING) % CT_LEN]:
        for step in [3, 4, 5]:
            nulls = sorted(set((start + i * step) % CT_LEN for i in range(24)))
            if len(nulls) == 24:
                rules[f"start{start}_step{step}"] = nulls

    return rules


def main():
    print("=" * 80)
    print("GEOMETRIC NULL POSITION RULES")
    print("=" * 80)
    print(f"CT ({CT_LEN} chars): {CT}")
    print(f"73 mod 26 = {73 % 26} = position of EASTNORTHEAST crib start")
    print(f"Searching for structural rules that select exactly 24 null positions")
    print()

    rules = generate_geometric_null_rules()
    print(f"Generated {len(rules)} null position rules")

    # Special: test primes explicitly
    primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89]
    print(f"\nPrimes < 97: {primes} (count={len(primes)})")
    if len(primes) == 24:
        kept = [CT[i] for i in range(CT_LEN) if i not in primes]
        print(f"  Extracted ({len(kept)} chars): {''.join(kept)}")
        # Check if cribs survive
        kept_set = set(range(CT_LEN)) - set(primes)
        crib_survivors = sum(1 for p in CRIB_DICT if p in kept_set)
        print(f"  Crib positions surviving: {crib_survivors}/24")
        destroyed = [p for p in sorted(CRIB_DICT) if p not in kept_set]
        print(f"  Destroyed crib positions: {destroyed}")

    # Test all rules
    print(f"\n{'=' * 80}")
    print(f"TESTING ALL RULES (73-char extract + keyword substitution)")
    print(f"{'=' * 80}")

    all_results = []
    tested = 0

    for rule_name, null_positions in rules.items():
        tested += 1
        results = extract_and_test(null_positions, rule_name)
        all_results.extend(results)

        if tested % 100 == 0:
            print(f"  Tested {tested}/{len(rules)} rules...")

    # Sort by score
    all_results.sort(key=lambda x: -x[0])

    print(f"\nTotal rules tested: {tested}")
    print(f"Total results with score >= 5: {len(all_results)}")

    if all_results:
        print(f"\nTop results:")
        print(f"{'Score':>5}  {'Method':<30}  {'Rule':<35}  {'Preview'}")
        print("-" * 110)
        for sc, method, rule, preview in all_results[:30]:
            print(f"{sc:5d}  {method:<30}  {rule:<35}  {preview}")
    else:
        print(f"No results scored >= 5")

    # Also check: which rules preserve ALL 24 crib positions?
    print(f"\n{'=' * 80}")
    print(f"RULES PRESERVING ALL 24 CRIB POSITIONS")
    print(f"{'=' * 80}")
    crib_safe_rules = []
    for rule_name, null_positions in rules.items():
        null_set = set(null_positions)
        if all(p not in null_set for p in CRIB_DICT):
            crib_safe_rules.append(rule_name)

    print(f"  {len(crib_safe_rules)} of {len(rules)} rules preserve all cribs")
    for r in crib_safe_rules[:20]:
        print(f"    {r}: nulls={rules[r][:8]}...")

    # For crib-safe rules, test with ORIGINAL crib positions
    print(f"\n{'=' * 80}")
    print(f"CRIB-SAFE RULES — TESTING WITH MAPPED CRIB POSITIONS")
    print(f"{'=' * 80}")

    safe_results = []
    for rule_name in crib_safe_rules:
        null_positions = rules[rule_name]
        null_set = set(null_positions)
        kept = [i for i in range(CT_LEN) if i not in null_set]
        pos_map = {orig: new for new, orig in enumerate(kept)}
        extracted = ''.join(CT[i] for i in kept)

        # Map cribs to new positions
        mapped_crib = {pos_map[p]: c for p, c in CRIB_DICT.items() if p in pos_map}

        for keyword in KEYWORDS:
            key = [ord(c) - 65 for c in keyword]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(extracted, key, variant)
                hits = sum(1 for p, c in mapped_crib.items()
                          if p < len(pt) and pt[p] == c)
                if hits >= 5:
                    safe_results.append((hits, f"{variant.value}({keyword})",
                                       rule_name, pt[:40]))

        # Also test single-letter keys
        for k in range(26):
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(extracted, [k], variant)
                hits = sum(1 for p, c in mapped_crib.items()
                          if p < len(pt) and pt[p] == c)
                if hits >= 5:
                    safe_results.append((hits, f"{variant.value}(k={ALPH[k]})",
                                       rule_name, pt[:40]))

    safe_results.sort(key=lambda x: -x[0])
    if safe_results:
        print(f"\nTop crib-safe results:")
        for sc, method, rule, preview in safe_results[:20]:
            print(f"  {sc:5d}  {method:<30}  {rule:<35}  {preview}")
    else:
        print(f"  No crib-safe results scored >= 5")

    best = max((r[0] for r in all_results), default=0)
    best_safe = max((r[0] for r in safe_results), default=0)
    print(f"\n{'=' * 80}")
    print(f"SUMMARY")
    print(f"{'=' * 80}")
    print(f"Rules generated: {len(rules)}")
    print(f"Crib-safe rules: {len(crib_safe_rules)}")
    print(f"Best overall: {best}/24")
    print(f"Best crib-safe: {best_safe}/24")


if __name__ == '__main__':
    main()
