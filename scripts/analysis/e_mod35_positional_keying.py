#!/usr/bin/env python3
"""
Cipher: positional_keying
Family: analysis
Status: active
Keyspace: see implementation
Last run: 2026-03-17
Best score: TBD

E-MOD35-POSKEY: Positional Keying via (pos%7, pos%5) Lookup Table

HYPOTHESIS: The stego layer uses a (pos%7, pos%5) framework (KRYPTOS x SEVEN).
Maybe the CIPHER layer also uses position-dependent keying based on the same
modular arithmetic. The key at position i is determined by a lookup table
indexed by (i%7, i%5).

Under Model B Beaufort (K = (CT+PT) mod 26), the 24 crib keystream is:
  JLJODEGKUKKKLOCGGBGOKTRU
with a striking AP: G(6), K(10), O(14) cover 12/24 positions.

TESTS:
1. Check if crib positions with same (pos%M, pos%N) cell have same key value
   (necessary for lookup table to work).
2. Try all modular frameworks: pos%N, (pos%M, pos%N) for various M,N.
3. For consistent frameworks, count free cells and enumerate/score solutions.
4. Also test on CT73 positions after null removal.

Output: results/mod35_positional_keying.json
"""

import json
import sys
import os
import time
import itertools
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN

# Constants
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Cribs (0-indexed in CT97)
ENE_POS = list(range(21, 34))  # positions 21-33
BCL_POS = list(range(63, 74))  # positions 63-73
ENE_PT = "EASTNORTHEAST"
BCL_PT = "BERLINCLOCK"
CRIB_POS = ENE_POS + BCL_POS
CRIB_PT = ENE_PT + BCL_PT

assert len(CRIB_POS) == 24
assert len(CRIB_PT) == 24
assert len(CT) == 97

# Load quadgrams for scoring
QUADGRAMS = None
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'english_quadgrams.json')
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0


def qg_score(text):
    """Score text by quadgram log-probabilities."""
    if QUADGRAMS is None:
        load_quadgrams()
    s = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        s += QUADGRAMS.get(qg, QG_FLOOR)
    if len(text) <= 3:
        return -10.0
    return s / max(1, len(text) - 3)


def c2n(c):
    """Char to number (A=0)."""
    return ord(c) - ord('A')

def n2c(n):
    """Number to char (A=0)."""
    return chr((n % 26) + ord('A'))


# Model B Beaufort keystream: key[i] = (CT[i] + PT[i]) mod 26
def beaufort_key(ct_char, pt_char):
    return (c2n(ct_char) + c2n(pt_char)) % 26

# Compute keystream at crib positions
CRIB_KEYS = []
for i, (pos, pt_ch) in enumerate(zip(CRIB_POS, CRIB_PT)):
    k = beaufort_key(CT[pos], pt_ch)
    CRIB_KEYS.append(k)

KEY_STR = ''.join(n2c(k) for k in CRIB_KEYS)
print(f"Model B Beaufort keystream at cribs: {KEY_STR}")
print(f"Key values: {CRIB_KEYS}")
print()

# Consensus null positions (17 known)
CONSENSUS_NULLS = [0, 2, 5, 8, 12, 14, 20, 36, 48, 52, 58, 59, 74, 75, 78, 85, 91]

# ========================================================================
# STEP 1+2: Test all (pos%M, pos%N) frameworks for M,N in interesting ranges
# A framework is "consistent" if all crib positions mapping to the same cell
# have the same key value.
# ========================================================================

def test_modular_framework(mod_a, mod_b, positions, keys, label=""):
    """
    Test if (pos%mod_a, pos%mod_b) is consistent: positions with same cell must
    have same key value. Returns dict with consistency info.
    """
    cell_keys = defaultdict(set)
    cell_positions = defaultdict(list)
    for pos, k in zip(positions, keys):
        cell = (pos % mod_a, pos % mod_b)
        cell_keys[cell].add(k)
        cell_positions[cell].append((pos, k))

    conflicts = []
    constrained = 0
    for cell, kset in sorted(cell_keys.items()):
        if len(kset) > 1:
            conflicts.append({
                'cell': cell,
                'keys': sorted(kset),
                'positions': cell_positions[cell]
            })
        constrained += 1

    total_cells = mod_a * mod_b
    free_cells = total_cells - constrained
    is_consistent = len(conflicts) == 0

    return {
        'consistent': is_consistent,
        'mod': (mod_a, mod_b),
        'total_cells': total_cells,
        'constrained_cells': constrained,
        'free_cells': free_cells,
        'n_conflicts': len(conflicts),
        'conflicts': conflicts[:5] if conflicts else [],
        'label': label
    }


def test_single_mod(mod_n, positions, keys, label=""):
    """Test if pos%N alone is consistent."""
    cell_keys = defaultdict(set)
    cell_positions = defaultdict(list)
    for pos, k in zip(positions, keys):
        r = pos % mod_n
        cell_keys[r].add(k)
        cell_positions[r].append((pos, k))

    conflicts = []
    constrained = 0
    for r, kset in sorted(cell_keys.items()):
        if len(kset) > 1:
            conflicts.append({
                'residue': r,
                'keys': sorted(kset),
                'positions': cell_positions[r]
            })
        constrained += 1

    free_cells = mod_n - constrained
    is_consistent = len(conflicts) == 0

    return {
        'consistent': is_consistent,
        'mod': mod_n,
        'total_cells': mod_n,
        'constrained_cells': constrained,
        'free_cells': free_cells,
        'n_conflicts': len(conflicts),
        'conflicts': conflicts[:5] if conflicts else [],
        'label': label
    }


print("=" * 70)
print("STEP 1-2: Testing modular frameworks on CT97 positions")
print("=" * 70)

results = {
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'hypothesis': 'Positional keying via (pos%M, pos%N) lookup table',
    'ciphertext': CT,
    'model': 'Model B Beaufort (K = (CT+PT) mod 26)',
    'keystream': KEY_STR,
    'keystream_values': CRIB_KEYS,
    'tests': {}
}

# Test single moduli
print("\n--- Single modulus pos%N ---")
single_results = {}
for n in range(2, 36):
    r = test_single_mod(n, CRIB_POS, CRIB_KEYS, "pos%{}".format(n))
    single_results[n] = r
    status = "CONSISTENT" if r['consistent'] else "CONFLICT ({} cells)".format(r['n_conflicts'])
    if r['consistent']:
        print("  pos%{:2d}: {} | {} constrained, {} free".format(n, status, r['constrained_cells'], r['free_cells']))
    elif r['n_conflicts'] <= 2:
        print("  pos%{:2d}: {} | {} constrained, {} free".format(n, status, r['constrained_cells'], r['free_cells']))

results['tests']['single_mod_ct97'] = single_results

# Test (mod_a, mod_b) pairs
print("\n--- (pos%M, pos%N) pairs ---")
pair_results = {}
interesting_pairs = []
for a in range(2, 15):
    for b in range(2, 15):
        if a == b:
            continue
        r = test_modular_framework(a, b, CRIB_POS, CRIB_KEYS, "({},{})".format(a, b))
        pair_results["{}x{}".format(a, b)] = r
        if r['consistent']:
            interesting_pairs.append((a, b, r))
            print("  ({:2d},{:2d}): CONSISTENT | total={}, constrained={}, free={}".format(
                a, b, r['total_cells'], r['constrained_cells'], r['free_cells']))

results['tests']['pair_mod_ct97'] = pair_results

# Specifically highlight (7,5) and (5,7)
for a, b in [(7, 5), (5, 7), (13, 2), (13, 3), (7, 13), (5, 13)]:
    key = "{}x{}".format(a, b)
    r = pair_results.get(key)
    if r:
        if not r['consistent']:
            nc = r['n_conflicts']
            print("\n  KEY PAIR ({},{}): {} CONFLICTS out of {} constrained cells".format(a, b, nc, r['constrained_cells']))
            for c in r['conflicts'][:3]:
                print("    Cell {}: keys={}, positions={}".format(c['cell'], c['keys'], c['positions']))

# ========================================================================
# STEP 2b: Test on CT73 positions (after null removal)
# ========================================================================
print("\n" + "=" * 70)
print("STEP 2b: Testing on CT73 positions (after consensus null removal)")
print("=" * 70)

# CT73: remove consensus null positions, get positions in 0-72 space
ct73_chars = []
ct97_to_ct73 = {}
ct73_idx = 0
for i in range(97):
    if i not in CONSENSUS_NULLS:
        ct73_chars.append(CT[i])
        ct97_to_ct73[i] = ct73_idx
        ct73_idx += 1

CT73 = ''.join(ct73_chars)
print("CT73 ({} chars): {}".format(len(CT73), CT73))

# Map crib positions to CT73 space
ct73_crib_pos = []
for pos in CRIB_POS:
    if pos in ct97_to_ct73:
        ct73_crib_pos.append(ct97_to_ct73[pos])
    else:
        print("  WARNING: crib position {} is a consensus null!".format(pos))
        ct73_crib_pos.append(None)

# Filter out any None values
valid_ct73 = [(p, k) for p, k in zip(ct73_crib_pos, CRIB_KEYS) if p is not None]
ct73_positions = [p for p, k in valid_ct73]
ct73_keys = [k for p, k in valid_ct73]

print("CT73 crib positions: {}".format(ct73_positions))
print("CT73 crib keys: {}".format(ct73_keys))

# Test single moduli on CT73
print("\n--- Single modulus pos%N on CT73 ---")
ct73_single_results = {}
for n in range(2, 36):
    r = test_single_mod(n, ct73_positions, ct73_keys, "ct73_pos%{}".format(n))
    ct73_single_results[n] = r
    if r['consistent']:
        print("  ct73 pos%{:2d}: CONSISTENT | {} constrained, {} free".format(n, r['constrained_cells'], r['free_cells']))
    elif r['n_conflicts'] <= 2:
        print("  ct73 pos%{:2d}: CONFLICT ({}) | {} constrained".format(n, r['n_conflicts'], r['constrained_cells']))

results['tests']['single_mod_ct73'] = ct73_single_results

# Test pairs on CT73
print("\n--- (pos%M, pos%N) pairs on CT73 ---")
ct73_pair_results = {}
ct73_interesting = []
for a in range(2, 15):
    for b in range(2, 15):
        if a == b:
            continue
        r = test_modular_framework(a, b, ct73_positions, ct73_keys, "ct73_({},{})".format(a, b))
        ct73_pair_results["{}x{}".format(a, b)] = r
        if r['consistent']:
            ct73_interesting.append((a, b, r))
            print("  ct73 ({:2d},{:2d}): CONSISTENT | total={}, constrained={}, free={}".format(
                a, b, r['total_cells'], r['constrained_cells'], r['free_cells']))

results['tests']['pair_mod_ct73'] = ct73_pair_results

# ========================================================================
# STEP 3: For consistent frameworks, attempt to enumerate/solve
# ========================================================================
print("\n" + "=" * 70)
print("STEP 3: Enumerate solutions for consistent frameworks")
print("=" * 70)


def decrypt_beaufort(ct_text, key_table_func):
    """Decrypt using Beaufort: PT[i] = (key[i] - CT[i]) mod 26."""
    result = []
    for i, c in enumerate(ct_text):
        k = key_table_func(i)
        pt = (k - c2n(c)) % 26
        result.append(n2c(pt))
    return ''.join(result)


def decrypt_vigenere(ct_text, key_table_func):
    """Decrypt using Vigenere: PT[i] = (CT[i] - key[i]) mod 26."""
    result = []
    for i, c in enumerate(ct_text):
        k = key_table_func(i)
        pt = (c2n(c) - k) % 26
        result.append(n2c(pt))
    return ''.join(result)


def check_cribs(pt_text, ct_text, positions, expected_pt):
    """Check how many crib positions match."""
    matches = 0
    for pos, exp in zip(positions, expected_pt):
        if pos < len(pt_text) and pt_text[pos] == exp:
            matches += 1
    return matches


# Collect ALL consistent single-mod frameworks with manageable free space
consistent_frameworks = []

# Single mod on CT97
for n, r in single_results.items():
    if r['consistent'] and r['free_cells'] <= 20:
        consistent_frameworks.append(('single_ct97', n, r))

# Pair mod on CT97
for key, r in pair_results.items():
    if r['consistent'] and r['free_cells'] <= 20:
        a, b = key.split('x')
        consistent_frameworks.append(('pair_ct97', (int(a), int(b)), r))

# Single mod on CT73
for n, r in ct73_single_results.items():
    if r['consistent'] and r['free_cells'] <= 20:
        consistent_frameworks.append(('single_ct73', n, r))

# Pair mod on CT73
for key, r in ct73_pair_results.items():
    if r['consistent'] and r['free_cells'] <= 20:
        a, b = key.split('x')
        consistent_frameworks.append(('pair_ct73', (int(a), int(b)), r))

print("\nConsistent frameworks with <=20 free cells: {}".format(len(consistent_frameworks)))
for ftype, fmod, fr in consistent_frameworks:
    print("  {} mod={}: {} free, {} constrained".format(ftype, fmod, fr['free_cells'], fr['constrained_cells']))

# For each consistent framework, build the known table and enumerate
enumeration_results = []
load_quadgrams()

for ftype, fmod, fr in consistent_frameworks:
    if ftype.startswith('single'):
        is_ct73 = 'ct73' in ftype
        mod_n = fmod
        positions = ct73_positions if is_ct73 else CRIB_POS
        keys = ct73_keys if is_ct73 else CRIB_KEYS
        text = CT73 if is_ct73 else CT
        crib_pos_for_check = ct73_positions if is_ct73 else CRIB_POS

        # Build known table
        table = {}
        for pos, k in zip(positions, keys):
            r = pos % mod_n
            table[r] = k

        free_residues = [r for r in range(mod_n) if r not in table]
        n_free = len(free_residues)

        if n_free > 12:
            print("\n  Skipping {} mod={}: {} free cells (too many to enumerate)".format(ftype, mod_n, n_free))
            continue

        total_configs = 26 ** n_free
        if total_configs > 5_000_000:
            print("\n  Skipping {} mod={}: 26^{} = {} configs (too many)".format(ftype, mod_n, n_free, total_configs))
            continue

        print("\n  Enumerating {} mod={}: {} free cells, {} configs".format(ftype, mod_n, n_free, total_configs))

        best_score = -999
        best_pt = ""
        best_config = None
        checked = 0

        for combo in itertools.product(range(26), repeat=n_free):
            trial_table = dict(table)
            for r, v in zip(free_residues, combo):
                trial_table[r] = v

            key_func = lambda i, tt=trial_table, mn=mod_n: tt[i % mn]

            # Quick crib check first (Beaufort)
            pt_chars = []
            crib_match = 0
            for pos, exp in zip(crib_pos_for_check, CRIB_PT):
                k = key_func(pos)
                pt_val = (k - c2n(text[pos])) % 26
                if n2c(pt_val) == exp:
                    crib_match += 1

            if crib_match >= 24:
                pt_text = decrypt_beaufort(text, key_func)
                sc = qg_score(pt_text)
                if sc > best_score:
                    best_score = sc
                    best_pt = pt_text
                    best_config = {r: v for r, v in zip(free_residues, combo)}
                    key_vals = [trial_table[r] for r in range(mod_n)]
                    print("    24/24 CRIB MATCH! qg={:.4f}, key={}".format(sc, key_vals))
                    print("    PT: {}...".format(pt_text[:50]))

            checked += 1
            if checked % 1_000_000 == 0:
                print("    ... checked {}/{}".format(checked, total_configs))

        # Also try Vigenere
        for combo in itertools.product(range(26), repeat=n_free):
            trial_table = dict(table)
            for r, v in zip(free_residues, combo):
                trial_table[r] = v

            key_func_vig = lambda i, tt=trial_table, mn=mod_n: tt[i % mn]
            crib_match_v = 0
            for pos, exp in zip(crib_pos_for_check, CRIB_PT):
                k = key_func_vig(pos)
                pt_val = (c2n(text[pos]) - k) % 26
                if n2c(pt_val) == exp:
                    crib_match_v += 1

            if crib_match_v >= 24:
                pt_text = decrypt_vigenere(text, key_func_vig)
                sc = qg_score(pt_text)
                key_vals = [trial_table[r] for r in range(mod_n)]
                print("    VIG 24/24 CRIB MATCH! qg={:.4f}, key={}".format(sc, key_vals))
                print("    PT: {}...".format(pt_text[:50]))

        er = {
            'framework': "{}_mod{}".format(ftype, mod_n),
            'free_cells': n_free,
            'total_configs': total_configs,
            'checked': checked * 2,
            'best_score': best_score,
            'best_pt': best_pt[:50] if best_pt else "",
            'best_config': best_config
        }
        enumeration_results.append(er)

    elif ftype.startswith('pair'):
        is_ct73 = 'ct73' in ftype
        mod_a, mod_b = fmod
        positions = ct73_positions if is_ct73 else CRIB_POS
        keys = ct73_keys if is_ct73 else CRIB_KEYS
        text = CT73 if is_ct73 else CT
        crib_pos_for_check = ct73_positions if is_ct73 else CRIB_POS

        # Build known table
        table = {}
        for pos, k in zip(positions, keys):
            cell = (pos % mod_a, pos % mod_b)
            table[cell] = k

        all_cells = [(a, b) for a in range(mod_a) for b in range(mod_b)]
        free_cells_list = [c for c in all_cells if c not in table]
        n_free = len(free_cells_list)

        total_configs = 26 ** n_free
        if total_configs > 5_000_000:
            print("\n  Skipping {} mod=({},{}): {} free cells, 26^{} = {:.1e}".format(
                ftype, mod_a, mod_b, n_free, n_free, total_configs))
            continue

        if n_free == 0:
            print("\n  {} mod=({},{}): 0 free cells -- fully determined by cribs".format(ftype, mod_a, mod_b))
            key_func = lambda i, tt=table, ma=mod_a, mb=mod_b: tt[(i % ma, i % mb)]
            pt_beau = decrypt_beaufort(text, key_func)
            sc_beau = qg_score(pt_beau)
            crib_match = check_cribs(pt_beau, text, crib_pos_for_check, CRIB_PT)
            print("    Beaufort: cribs={}/24, qg={:.4f}".format(crib_match, sc_beau))
            print("    PT: {}".format(pt_beau))
            pt_vig = decrypt_vigenere(text, key_func)
            sc_vig = qg_score(pt_vig)
            crib_match_v = check_cribs(pt_vig, text, crib_pos_for_check, CRIB_PT)
            print("    Vigenere: cribs={}/24, qg={:.4f}".format(crib_match_v, sc_vig))
            print("    PT: {}".format(pt_vig))

            er = {
                'framework': "{}_mod({},{})".format(ftype, mod_a, mod_b),
                'free_cells': 0,
                'total_configs': 1,
                'checked': 2,
                'best_score_beau': sc_beau,
                'best_score_vig': sc_vig,
                'pt_beau': pt_beau,
                'pt_vig': pt_vig,
                'crib_match_beau': crib_match,
                'crib_match_vig': crib_match_v
            }
            enumeration_results.append(er)
            continue

        print("\n  Enumerating {} mod=({},{}): {} free cells, {} configs".format(
            ftype, mod_a, mod_b, n_free, total_configs))

        best_score = -999
        best_pt = ""
        best_config = None
        checked = 0

        for combo in itertools.product(range(26), repeat=n_free):
            trial_table = dict(table)
            for cell, v in zip(free_cells_list, combo):
                trial_table[cell] = v

            key_func = lambda i, tt=trial_table, ma=mod_a, mb=mod_b: tt[(i % ma, i % mb)]

            # Beaufort check
            crib_match = 0
            for pos, exp in zip(crib_pos_for_check, CRIB_PT):
                k = key_func(pos)
                pt_val = (k - c2n(text[pos])) % 26
                if n2c(pt_val) == exp:
                    crib_match += 1

            if crib_match >= 24:
                pt_text = decrypt_beaufort(text, key_func)
                sc = qg_score(pt_text)
                if sc > best_score:
                    best_score = sc
                    best_pt = pt_text
                    best_config = {str(cell): v for cell, v in zip(free_cells_list, combo)}
                    print("    BEAU 24/24! qg={:.4f}".format(sc))
                    print("    PT: {}...".format(pt_text[:60]))

            # Vigenere check
            crib_match_v = 0
            for pos, exp in zip(crib_pos_for_check, CRIB_PT):
                k = key_func(pos)
                pt_val = (c2n(text[pos]) - k) % 26
                if n2c(pt_val) == exp:
                    crib_match_v += 1

            if crib_match_v >= 24:
                pt_text = decrypt_vigenere(text, key_func)
                sc = qg_score(pt_text)
                print("    VIG 24/24! qg={:.4f}".format(sc))
                print("    PT: {}...".format(pt_text[:60]))

            checked += 1
            if checked % 500_000 == 0:
                print("    ... checked {}/{}".format(checked, total_configs))

        er = {
            'framework': "{}_mod({},{})".format(ftype, mod_a, mod_b),
            'free_cells': n_free,
            'total_configs': total_configs,
            'checked': checked,
            'best_score': best_score,
            'best_pt': best_pt[:50] if best_pt else ""
        }
        enumeration_results.append(er)

results['tests']['enumerations'] = enumeration_results

# ========================================================================
# STEP 4: Detailed analysis of (7,5) specifically -- the stego framework
# ========================================================================
print("\n" + "=" * 70)
print("STEP 4: Detailed (pos%7, pos%5) analysis")
print("=" * 70)

# Show the cell mapping for all 24 crib positions
print("\nCrib position -> (pos%7, pos%5) -> key value:")
cell_map = defaultdict(list)
for pos, k in zip(CRIB_POS, CRIB_KEYS):
    cell = (pos % 7, pos % 5)
    cell_map[cell].append((pos, k, n2c(k)))
    pt_ch = CRIB_PT[CRIB_POS.index(pos)]
    print("  pos={:2d} CT={} PT={} -> cell=({},{}) -> key={}({})".format(
        pos, CT[pos], pt_ch, pos % 7, pos % 5, n2c(k), k))

print("\nCell conflicts in (pos%7, pos%5):")
n_conflict_75 = 0
for cell in sorted(cell_map.keys()):
    entries = cell_map[cell]
    keys = set(k for _, k, _ in entries)
    if len(keys) > 1:
        n_conflict_75 += 1
        print("  CONFLICT at {}: {}".format(cell, [(p, kc) for p, k, kc in entries]))
    elif len(entries) > 1:
        print("  CONSISTENT at {}: {} (all key={})".format(
            cell, [(p, kc) for p, k, kc in entries], entries[0][2]))

print("\nTotal conflicts in (7,5) framework: {}".format(n_conflict_75))

# Show the full 7x5 key table (known values)
print("\n7x5 Key Table (KRYPTOS x SEVEN, Beaufort Model B):")
print("       S(0)  E(1)  V(2)  E(3)  N(4)")
for r in range(7):
    row_str = "{}({}):  ".format("KRYPTOS"[r], r)
    for c in range(5):
        cell = (r, c)
        if cell in cell_map:
            entries = cell_map[cell]
            keys = set(k for _, k, _ in entries)
            if len(keys) == 1:
                row_str += " {}    ".format(entries[0][2])
            else:
                conflict_str = "!".join(sorted(set(kc for _, _, kc in entries)))
                row_str += " {}  ".format(conflict_str)
        else:
            row_str += " -    "
    print(row_str)

# ========================================================================
# STEP 5: Check if the known key values have AP/table structure
# ========================================================================
print("\n" + "=" * 70)
print("STEP 5: Look for structure in the (pos%7, pos%5) key table")
print("=" * 70)

# Check (7,5) on CT73
print("\n--- (pos%7, pos%5) on CT73 ---")
ct73_cell_map = defaultdict(list)
for pos, k in zip(ct73_positions, ct73_keys):
    cell = (pos % 7, pos % 5)
    ct73_cell_map[cell].append((pos, k, n2c(k)))

n_conflict_73 = 0
for cell in sorted(ct73_cell_map.keys()):
    entries = ct73_cell_map[cell]
    keys = set(k for _, k, _ in entries)
    if len(keys) > 1:
        n_conflict_73 += 1
        print("  CONFLICT at {}: {}".format(cell, [(p, kc) for p, k, kc in entries]))
    elif len(entries) > 1:
        print("  CONSISTENT at {}: {}".format(cell, [(p, kc) for p, k, kc in entries]))

print("Total conflicts in (7,5) on CT73: {}".format(n_conflict_73))

# Also show the CT73 7x5 table
print("\n7x5 Key Table on CT73:")
print("       c0    c1    c2    c3    c4")
for r in range(7):
    row_str = "r{}:    ".format(r)
    for c in range(5):
        cell = (r, c)
        if cell in ct73_cell_map:
            entries = ct73_cell_map[cell]
            keys = set(k for _, k, _ in entries)
            if len(keys) == 1:
                row_str += " {}    ".format(entries[0][2])
            else:
                conflict_str = "!".join(sorted(set(kc for _, _, kc in entries)))
                row_str += " {}  ".format(conflict_str)
        else:
            row_str += " -    "
    print(row_str)

# ========================================================================
# STEP 6: Test larger moduli that are consistent
# ========================================================================
print("\n" + "=" * 70)
print("STEP 6: Test all moduli up to 97 for consistency")
print("=" * 70)

# Test pos%N for N up to 97
big_consistent = []
for n in range(2, 98):
    r = test_single_mod(n, CRIB_POS, CRIB_KEYS)
    if r['consistent']:
        big_consistent.append((n, r['constrained_cells'], r['free_cells']))
        if n <= 50 or r['free_cells'] <= 10:
            print("  pos%{}: CONSISTENT, {} constrained, {} free".format(n, r['constrained_cells'], r['free_cells']))

print("\nAll consistent single moduli (CT97): {}".format([x[0] for x in big_consistent]))

# Same on CT73
big_consistent_73 = []
for n in range(2, 74):
    r = test_single_mod(n, ct73_positions, ct73_keys)
    if r['consistent']:
        big_consistent_73.append((n, r['constrained_cells'], r['free_cells']))
        if n <= 50 or r['free_cells'] <= 10:
            print("  ct73 pos%{}: CONSISTENT, {} constrained, {} free".format(n, r['constrained_cells'], r['free_cells']))

print("\nAll consistent single moduli (CT73): {}".format([x[0] for x in big_consistent_73]))

# ========================================================================
# STEP 7: For manageable consistent moduli, do exhaustive key search
# ========================================================================
print("\n" + "=" * 70)
print("STEP 7: Exhaustive search for consistent moduli with small free space")
print("=" * 70)

for mod_type, mod_val, n_const, n_free in [
    *[('ct97', n, nc, nf) for n, nc, nf in big_consistent if nf <= 4],
    *[('ct73', n, nc, nf) for n, nc, nf in big_consistent_73 if nf <= 4]
]:
    text = CT73 if mod_type == 'ct73' else CT
    positions = ct73_positions if mod_type == 'ct73' else CRIB_POS
    keys = ct73_keys if mod_type == 'ct73' else CRIB_KEYS
    crib_pos_check = ct73_positions if mod_type == 'ct73' else CRIB_POS
    crib_pt_check = CRIB_PT

    # Build known table
    table = {}
    for pos, k in zip(positions, keys):
        r = pos % mod_val
        table[r] = k

    free_residues = [r for r in range(mod_val) if r not in table]
    total_configs = 26 ** len(free_residues)

    if total_configs > 10_000_000:
        print("\n  Skipping {} pos%{}: 26^{} = {}".format(mod_type, mod_val, len(free_residues), total_configs))
        continue

    print("\n  Searching {} pos%{}: {} free, {} configs".format(
        mod_type, mod_val, len(free_residues), total_configs))
    print("  Known table: {}".format(dict(sorted(table.items()))))
    print("  Free residues: {}".format(free_residues))

    best_qg = -999
    best_pt_text = ""
    hits_24 = 0

    for combo in itertools.product(range(26), repeat=len(free_residues)):
        trial_table = dict(table)
        for r, v in zip(free_residues, combo):
            trial_table[r] = v

        key_func = lambda i, tt=trial_table, mn=mod_val: tt[i % mn]

        # Beaufort decrypt
        pt = decrypt_beaufort(text, key_func)

        # Quick crib check
        crib_ok = all(pt[p] == e for p, e in zip(crib_pos_check, crib_pt_check))
        if crib_ok:
            hits_24 += 1
            sc = qg_score(pt)
            if sc > best_qg:
                best_qg = sc
                best_pt_text = pt
                key_str = ''.join(n2c(trial_table[r]) for r in range(mod_val))
                if sc > -6.0:
                    print("    BEAU 24/24 qg={:.4f} key={} PT={}...".format(sc, key_str, pt[:40]))

        # Vigenere decrypt
        pt_v = decrypt_vigenere(text, key_func)
        crib_ok_v = all(pt_v[p] == e for p, e in zip(crib_pos_check, crib_pt_check))
        if crib_ok_v:
            hits_24 += 1
            sc_v = qg_score(pt_v)
            if sc_v > best_qg:
                best_qg = sc_v
                best_pt_text = pt_v
                key_str = ''.join(n2c(trial_table[r]) for r in range(mod_val))
                if sc_v > -6.0:
                    print("    VIG 24/24 qg={:.4f} key={} PT={}...".format(sc_v, key_str, pt_v[:40]))

    print("  Result: {} configs with 24/24 cribs, best qg={:.4f}".format(hits_24, best_qg))
    if best_pt_text:
        print("  Best PT: {}".format(best_pt_text[:60]))

    enumeration_results.append({
        'framework': "{}_mod{}_exhaustive".format(mod_type, mod_val),
        'free_cells': len(free_residues),
        'total_configs': total_configs * 2,
        'hits_24': hits_24,
        'best_qg': best_qg,
        'best_pt': best_pt_text[:60] if best_pt_text else ""
    })

# ========================================================================
# STEP 8: Summary
# ========================================================================
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

# Count consistent frameworks
n_ct97_single = sum(1 for n, r in single_results.items() if r['consistent'])
n_ct97_pair = sum(1 for r in pair_results.values() if r['consistent'])
n_ct73_single = sum(1 for n, r in ct73_single_results.items() if r['consistent'])
n_ct73_pair = sum(1 for r in ct73_pair_results.values() if r['consistent'])

print("Consistent single moduli (CT97, mod 2-35): {}".format(n_ct97_single))
print("Consistent pair moduli (CT97, mod 2-14): {}".format(n_ct97_pair))
print("Consistent single moduli (CT73, mod 2-35): {}".format(n_ct73_single))
print("Consistent pair moduli (CT73, mod 2-14): {}".format(n_ct73_pair))

# Key result: is (7,5) consistent?
r_75 = pair_results.get("7x5")
if r_75:
    status = "CONSISTENT" if r_75['consistent'] else "CONFLICT ({} cells)".format(r_75['n_conflicts'])
    print("\n(pos%7, pos%5) on CT97: {}".format(status))
    if not r_75['consistent']:
        print("  -> (pos%7, pos%5) positional keying is DISPROVED for Model B Beaufort on CT97")

r_75_73 = ct73_pair_results.get("7x5")
if r_75_73:
    status73 = "CONSISTENT" if r_75_73['consistent'] else "CONFLICT ({} cells)".format(r_75_73['n_conflicts'])
    print("(pos%7, pos%5) on CT73: {}".format(status73))
    if not r_75_73['consistent']:
        print("  -> (pos%7, pos%5) positional keying is DISPROVED for Model B Beaufort on CT73")

# Check specific key moduli
for m in [5, 7, 13, 35]:
    r_m = single_results.get(m)
    if r_m:
        s = "CONSISTENT" if r_m['consistent'] else "CONFLICT ({})".format(r_m['n_conflicts'])
        print("pos%{} on CT97: {}".format(m, s))
    r_m73 = ct73_single_results.get(m)
    if r_m73:
        s73 = "CONSISTENT" if r_m73['consistent'] else "CONFLICT ({})".format(r_m73['n_conflicts'])
        print("pos%{} on CT73: {}".format(m, s73))

# Save results
results['summary'] = {
    'consistent_single_ct97': n_ct97_single,
    'consistent_pair_ct97': n_ct97_pair,
    'consistent_single_ct73': n_ct73_single,
    'consistent_pair_ct73': n_ct73_pair,
    'mod_7_5_ct97_consistent': r_75['consistent'] if r_75 else None,
    'mod_7_5_ct73_consistent': r_75_73['consistent'] if r_75_73 else None,
    'enumerations': len(enumeration_results),
    'all_consistent_single_ct97': [x[0] for x in big_consistent],
    'all_consistent_single_ct73': [x[0] for x in big_consistent_73]
}

outpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results', 'mod35_positional_keying.json')

def make_serializable(obj):
    if isinstance(obj, dict):
        return {str(k): make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_serializable(x) for x in obj]
    elif isinstance(obj, set):
        return sorted(list(obj))
    else:
        return obj

with open(outpath, 'w') as f:
    json.dump(make_serializable(results), f, indent=2)

print("\nResults saved to {}".format(outpath))
