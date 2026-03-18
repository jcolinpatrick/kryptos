#!/usr/bin/env python3
"""
72+1 Delimiter Hypothesis: Remove 1 char from ct73 to get 72 = 6x12.

Hypothesis: One character in ct73 is a delimiter (stray W, Q, X, or any
letter). Removing it gives 72 = 6 * 12, enabling width-6 ciphers.

Tests:
  A) Period-6 Beaufort/Vigenere/VBeau direct (crib consistency)
  B) Width-6 columnar transposition + period-6 cipher
  C) Width-6 columnar + autokey feasibility
  D) 25-null model (remove 25 from CT97 -> 72 chars directly)

Cipher: grille/e_72plus1_delimiter_v1
Family: grille
Status: active
Keyspace: ~49 delim x 720 col6 x 6 cipher x keywords
Last run: never
Best score: N/A
"""
import sys
import os
import json
import time
import itertools
import math
from collections import defaultdict
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, CRIB_POSITIONS

# ── Constants ──────────────────────────────────────────────────────────────

# Standard null mask (consensus 17 + 7 varying from mask 0)
MASK_24 = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
MASK_SET = set(MASK_24)

# Extract ct73
ct73 = ''.join(CT[i] for i in range(CT_LEN) if i not in MASK_SET)
assert len(ct73) == 73, f"ct73 length {len(ct73)} != 73"

# Map CT97 crib positions to ct73 positions
def ct97_to_ct73(pos97):
    """Map CT97 position to ct73 position (accounting for removed nulls)."""
    if pos97 in MASK_SET:
        return None
    return pos97 - sum(1 for n in MASK_24 if n < pos97)

# Crib positions in ct73 space
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START_73 = ct97_to_ct73(21)  # should be 13
BCL_START_73 = ct97_to_ct73(63)  # should be 47

assert ENE_START_73 == 13, f"ENE start in ct73 = {ENE_START_73}, expected 13"
assert BCL_START_73 == 47, f"BCL start in ct73 = {BCL_START_73}, expected 47"

ENE_POSITIONS_73 = list(range(ENE_START_73, ENE_START_73 + len(ENE_WORD)))  # 13-25
BCL_POSITIONS_73 = list(range(BCL_START_73, BCL_START_73 + len(BCL_WORD)))  # 47-57
CRIB_POSITIONS_73 = set(ENE_POSITIONS_73 + BCL_POSITIONS_73)

# Build ct73 crib dict
CRIB_73 = {}
for i, ch in enumerate(ENE_WORD):
    CRIB_73[ENE_START_73 + i] = ch
for i, ch in enumerate(BCL_WORD):
    CRIB_73[BCL_START_73 + i] = ch

# Cipher variants
VARIANTS = ['vigenere', 'beaufort', 'var_beaufort']

def key_recover(c, p, variant):
    """Recover key value from (ciphertext, plaintext) pair."""
    if variant == 'vigenere':
        return (c - p) % MOD
    elif variant == 'beaufort':
        return (c + p) % MOD
    elif variant == 'var_beaufort':
        return (p - c) % MOD

def decrypt_char(c, k, variant):
    """Decrypt single character."""
    if variant == 'vigenere':
        return (c - k) % MOD
    elif variant == 'beaufort':
        return (k - c) % MOD
    elif variant == 'var_beaufort':
        return (c + k) % MOD

# ── KA alphabet ────────────────────────────────────────────────────────────
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── Keywords ───────────────────────────────────────────────────────────────
KEYWORDS_6 = [
    "KRYPTO", "DEFECT", "ABSCIS", "SHADOW", "COMPAS",
    "ENIGMA", "CLOCKS", "BERLIN", "CIPHER", "PALIMB",
    "SANBOR", "COLOPH", "NEEDLE", "COPPER", "LODEST",
    "TWELVE", "TWENTY", "THIRTY", "ELEVEN", "MASTER",
]

AUTOKEY_PRIMERS = [
    "DEFECTOR", "PALIMPSEST", "KRYPTOS", "ABSCISSA", "SHADOW",
    "SANBORN", "BERLIN", "SEVEN", "CLOCK", "TWELVE",
    "COMPASS", "ENIGMA", "COLOPHON", "KOMPASS",
]

def keyword_to_col_order(kw, width):
    """Convert keyword to column reading order."""
    kw = kw[:width].upper()
    if len(kw) < width:
        return None
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return tuple(order)

def columnar_perm(width, col_order, length):
    """Columnar transposition permutation."""
    cols = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        perm.extend(cols[col_idx])
    return perm

def invert_perm(perm):
    """Inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def apply_perm(text, perm):
    """Apply permutation: output[i] = text[perm[i]]."""
    return ''.join(text[p] for p in perm)


# ══════════════════════════════════════════════════════════════════════════
# Test A: Period-6 direct on ct72 (no transposition)
# ══════════════════════════════════════════════════════════════════════════

def test_period6_direct(ct72, ene_s, bcl_s, alph_name='AZ'):
    """Test period-6 crib consistency on ct72."""
    results = []

    if alph_name == 'AZ':
        idx_fn = lambda c: ord(c) - 65
    else:
        idx_fn = lambda c: KA_IDX[c]

    # Build ct72 crib positions
    crib72 = {}
    for i, ch in enumerate(ENE_WORD):
        crib72[ene_s + i] = ch
    for i, ch in enumerate(BCL_WORD):
        crib72[bcl_s + i] = ch

    for variant in VARIANTS:
        # Derive key at each crib position
        key_at = {}
        for pos, pt_ch in crib72.items():
            if pos >= len(ct72):
                continue
            c = idx_fn(ct72[pos])
            p = idx_fn(pt_ch)
            k = key_recover(c, p, variant)
            key_at[pos] = k

        # Check period-6 consistency
        residue_keys = defaultdict(set)
        for pos, k in key_at.items():
            residue_keys[pos % 6].add(k)

        conflicts = sum(1 for r in residue_keys.values() if len(r) > 1)
        consistent = sum(len(v) for v in residue_keys.values() if len(v) == 1)
        total_constrained = sum(len(v) for v in residue_keys.values())

        # Score: number of consistent crib positions
        score = 0
        for pos, k in key_at.items():
            r = pos % 6
            if len(residue_keys[r]) == 1:
                score += 1

        if conflicts == 0:
            # PERFECT consistency! Derive full key and decrypt
            key6 = [0] * 6
            for r, ks in residue_keys.items():
                if ks:
                    key6[r] = list(ks)[0]

            if alph_name == 'AZ':
                pt = ''.join(chr(decrypt_char(ord(c) - 65, key6[i % 6], variant) + 65)
                            for i, c in enumerate(ct72))
            else:
                pt = ''.join(KA[decrypt_char(KA_IDX[c], key6[i % 6], variant)]
                            for i, c in enumerate(ct72))

            key_str = ''.join(chr(k + 65) for k in key6)
            results.append({
                'type': 'period6_direct',
                'variant': variant,
                'alph': alph_name,
                'conflicts': 0,
                'score': score,
                'total_crib': len(key_at),
                'key': key_str,
                'pt': pt,
            })
        elif score >= 10:
            results.append({
                'type': 'period6_direct',
                'variant': variant,
                'alph': alph_name,
                'conflicts': conflicts,
                'score': score,
                'total_crib': len(key_at),
            })

    return results


# ══════════════════════════════════════════════════════════════════════════
# Test B: Width-6 columnar + period-6 cipher
# ══════════════════════════════════════════════════════════════════════════

def test_col6_period6(ct72, ene_s, bcl_s, alph_name='AZ'):
    """Test all 720 col6 orderings + period-6 crib check."""
    results = []

    if alph_name == 'AZ':
        idx_fn = lambda c: ord(c) - 65
    else:
        idx_fn = lambda c: KA_IDX[c]

    crib72 = {}
    for i, ch in enumerate(ENE_WORD):
        crib72[ene_s + i] = ch
    for i, ch in enumerate(BCL_WORD):
        crib72[bcl_s + i] = ch

    for perm_tuple in itertools.permutations(range(6)):
        col_order = list(perm_tuple)
        perm = columnar_perm(6, col_order, 72)
        inv = invert_perm(perm)

        # Undo transposition: intermediate[i] = ct72[perm[i]]
        # But we need: map crib positions through inverse
        # If CT72 = columnar(intermediate), then intermediate = inv_columnar(ct72)
        # intermediate[inv[i]] = ct72[i]  => intermediate[j] = ct72[perm[j]]
        intermediate = apply_perm(ct72, perm)

        # Now check period-6 on intermediate
        for variant in VARIANTS:
            residue_keys = defaultdict(set)
            score = 0
            total = 0

            for pos, pt_ch in crib72.items():
                # Map crib position through inverse transposition
                inter_pos = inv[pos]
                c = idx_fn(intermediate[inter_pos])
                p = idx_fn(pt_ch)
                k = key_recover(c, p, variant)
                residue_keys[inter_pos % 6].add(k)
                total += 1

            conflicts = sum(1 for r in residue_keys.values() if len(r) > 1)

            if conflicts == 0:
                # Perfect! Derive key and decrypt
                key6 = [0] * 6
                for r, ks in residue_keys.items():
                    if ks:
                        key6[r] = list(ks)[0]

                if alph_name == 'AZ':
                    pt_inter = ''.join(chr(decrypt_char(ord(c) - 65, key6[i % 6], variant) + 65)
                                      for i, c in enumerate(intermediate))
                else:
                    pt_inter = ''.join(KA[decrypt_char(KA_IDX[c], key6[i % 6], variant)]
                                      for i, c in enumerate(intermediate))

                key_str = ''.join(chr(k + 65) for k in key6)
                results.append({
                    'type': 'col6_period6',
                    'variant': variant,
                    'alph': alph_name,
                    'col_order': col_order,
                    'conflicts': 0,
                    'score': total,
                    'key': key_str,
                    'pt': pt_inter,
                })

            # Count consistent positions
            consistent_count = 0
            for pos, pt_ch in crib72.items():
                inter_pos = inv[pos]
                r = inter_pos % 6
                if len(residue_keys[r]) == 1:
                    consistent_count += 1

            if consistent_count >= 14:
                results.append({
                    'type': 'col6_period6_partial',
                    'variant': variant,
                    'alph': alph_name,
                    'col_order': col_order,
                    'conflicts': conflicts,
                    'score': consistent_count,
                    'total_crib': total,
                })

    return results


# ══════════════════════════════════════════════════════════════════════════
# Test C: Width-6 columnar + autokey feasibility
# ══════════════════════════════════════════════════════════════════════════

def test_col6_autokey(ct72, ene_s, bcl_s, alph_name='AZ'):
    """Test col6 + autokey (check crib-to-crib conflicts)."""
    results = []

    if alph_name == 'AZ':
        idx_fn = lambda c: ord(c) - 65
    else:
        idx_fn = lambda c: KA_IDX[c]

    crib72 = {}
    for i, ch in enumerate(ENE_WORD):
        crib72[ene_s + i] = ch
    for i, ch in enumerate(BCL_WORD):
        crib72[bcl_s + i] = ch

    best_results = []

    for perm_tuple in itertools.permutations(range(6)):
        col_order = list(perm_tuple)
        perm = columnar_perm(6, col_order, 72)
        inv = invert_perm(perm)

        intermediate = apply_perm(ct72, perm)

        # Map crib positions to intermediate space
        crib_inter = {}
        for pos, pt_ch in crib72.items():
            inter_pos = inv[pos]
            crib_inter[inter_pos] = pt_ch

        # For each autokey offset (primer length)
        for offset in range(1, 25):
            for variant in VARIANTS:
                # Check autokey consistency:
                # key[i] = PT[i - offset] for i >= offset
                # At two crib positions i,j where i-offset and j-offset are also cribs:
                # key[i] = known, PT[i] = known => CT[i] determined
                # key[j] = known, PT[j] = known => CT[j] determined
                # But also k[i] = PT[i-offset] must equal the known crib char

                conflicts = 0
                checks = 0

                for pos_i, pt_i in crib_inter.items():
                    src = pos_i - offset
                    if src >= 0 and src in crib_inter:
                        # key[pos_i] should be idx of PT[src] (for Vig autokey)
                        expected_key = idx_fn(crib_inter[src])
                        # Actual key from (CT, PT)
                        c = idx_fn(intermediate[pos_i])
                        p = idx_fn(pt_i)
                        actual_key = key_recover(c, p, variant)

                        checks += 1
                        if expected_key != actual_key:
                            conflicts += 1

                if checks >= 3 and conflicts == 0:
                    best_results.append({
                        'type': 'col6_autokey',
                        'variant': variant,
                        'alph': alph_name,
                        'col_order': col_order,
                        'offset': offset,
                        'checks': checks,
                        'conflicts': 0,
                    })
                elif checks >= 3 and conflicts <= 1:
                    best_results.append({
                        'type': 'col6_autokey_near',
                        'variant': variant,
                        'alph': alph_name,
                        'col_order': col_order,
                        'offset': offset,
                        'checks': checks,
                        'conflicts': conflicts,
                    })

    return best_results


# ══════════════════════════════════════════════════════════════════════════
# Worker function for parallel processing
# ══════════════════════════════════════════════════════════════════════════

def process_delimiter(args):
    """Process a single delimiter position."""
    d, ct73_str = args

    all_results = []

    # Remove position d from ct73
    ct72 = ct73_str[:d] + ct73_str[d+1:]
    assert len(ct72) == 72, f"ct72 length {len(ct72)} != 72"

    # Adjust crib positions
    ene_s = 13 - (1 if d < 13 else 0)
    bcl_s = 47 - (1 if d < 47 else 0)

    removed_char = ct73_str[d]

    # Test A: Period-6 direct (AZ and KA)
    for alph in ['AZ', 'KA']:
        res = test_period6_direct(ct72, ene_s, bcl_s, alph)
        for r in res:
            r['delimiter_pos'] = d
            r['removed_char'] = removed_char
        all_results.extend(res)

    # Test B: Width-6 columnar + period-6 (AZ and KA)
    for alph in ['AZ', 'KA']:
        res = test_col6_period6(ct72, ene_s, bcl_s, alph)
        for r in res:
            r['delimiter_pos'] = d
            r['removed_char'] = removed_char
        all_results.extend(res)

    # Test C: Width-6 columnar + autokey (AZ only for speed)
    res = test_col6_autokey(ct72, ene_s, bcl_s, 'AZ')
    for r in res:
        r['delimiter_pos'] = d
        r['removed_char'] = removed_char
    all_results.extend(res)

    return d, all_results


def process_25null(args):
    """Process a 25-null mask (remove 25 from CT97 -> 72 chars)."""
    mask_25, mask_id = args
    mask_set = set(mask_25)

    ct72 = ''.join(CT[i] for i in range(CT_LEN) if i not in mask_set)
    if len(ct72) != 72:
        return mask_id, []

    # Compute crib positions in 72-char space
    ene_s = 21 - sum(1 for n in mask_25 if n < 21)
    bcl_s = 63 - sum(1 for n in mask_25 if n < 63)

    # Verify cribs don't overlap nulls
    for pos in range(21, 34):
        if pos in mask_set:
            return mask_id, []
    for pos in range(63, 74):
        if pos in mask_set:
            return mask_id, []

    all_results = []

    # Test A: Period-6 direct
    for alph in ['AZ', 'KA']:
        res = test_period6_direct(ct72, ene_s, bcl_s, alph)
        for r in res:
            r['mask_id'] = mask_id
            r['extra_null'] = [n for n in mask_25 if n not in MASK_SET]
        all_results.extend(res)

    # Test B: Width-6 col + period-6 (AZ only for speed, 720 perms per mask)
    res = test_col6_period6(ct72, ene_s, bcl_s, 'AZ')
    for r in res:
        r['mask_id'] = mask_id
        r['extra_null'] = [n for n in mask_25 if n not in MASK_SET]
    all_results.extend(res)

    return mask_id, all_results


# ══════════════════════════════════════════════════════════════════════════
# Full autokey decrypt + score for promising configs
# ══════════════════════════════════════════════════════════════════════════

def full_autokey_decrypt_score(ct72, primer, variant, alph_name='AZ'):
    """Full autokey decryption with scoring."""
    if alph_name == 'AZ':
        idx_fn = lambda c: ord(c) - 65
        chr_fn = lambda v: chr(v + 65)
    else:
        idx_fn = lambda c: KA_IDX[c]
        chr_fn = lambda v: KA[v]

    primer_vals = [idx_fn(c) for c in primer.upper()]
    pt = []

    for i, c_ch in enumerate(ct72):
        c = idx_fn(c_ch)
        if i < len(primer_vals):
            k = primer_vals[i]
        else:
            k = idx_fn(pt[i - len(primer)])

        p = decrypt_char(c, k, variant)
        pt.append(chr_fn(p))

    pt_str = ''.join(pt)
    return pt_str


def score_against_cribs(pt, ene_s, bcl_s):
    """Score plaintext against cribs."""
    score = 0
    for i, ch in enumerate(ENE_WORD):
        pos = ene_s + i
        if pos < len(pt) and pt[pos] == ch:
            score += 1
    for i, ch in enumerate(BCL_WORD):
        pos = bcl_s + i
        if pos < len(pt) and pt[pos] == ch:
            score += 1
    return score


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()

    print("=" * 70)
    print("72+1 DELIMITER HYPOTHESIS")
    print("=" * 70)
    print(f"CT97: {CT}")
    print(f"ct73: {ct73}")
    print(f"ct73 length: {len(ct73)}")
    print(f"ENE crib at ct73[{ENE_START_73}:{ENE_START_73+13}]")
    print(f"BCL crib at ct73[{BCL_START_73}:{BCL_START_73+11}]")
    print()

    # Identify W, Q, X positions in ct73
    w_positions = [i for i, c in enumerate(ct73) if c == 'W']
    q_positions = [i for i, c in enumerate(ct73) if c == 'Q']
    x_positions = [i for i, c in enumerate(ct73) if c == 'X']

    print(f"W positions in ct73: {w_positions}")
    print(f"Q positions in ct73: {q_positions}")
    print(f"X positions in ct73: {x_positions}")
    print()

    # All non-crib positions (valid delimiter candidates)
    valid_delimiters = [d for d in range(73) if d not in CRIB_POSITIONS_73]
    print(f"Valid delimiter positions: {len(valid_delimiters)} of 73")
    print(f"Crib positions (excluded): {sorted(CRIB_POSITIONS_73)}")
    print()

    # ── Phase 1: Test all 49 delimiter positions ──────────────────────────

    print("=" * 70)
    print("PHASE 1: Delimiter removal from ct73 (49 positions)")
    print("=" * 70)

    tasks = [(d, ct73) for d in valid_delimiters]

    all_results = []
    zero_conflict_results = []
    high_score_results = []
    autokey_feasible = []

    n_workers = min(cpu_count(), 12)
    print(f"Using {n_workers} workers")

    with Pool(n_workers) as pool:
        for d, results in pool.imap_unordered(process_delimiter, tasks):
            for r in results:
                all_results.append(r)

                if r.get('conflicts') == 0 and r['type'] in ('period6_direct', 'col6_period6'):
                    zero_conflict_results.append(r)
                    print(f"  *** ZERO CONFLICTS: d={d} removed='{ct73[d]}' "
                          f"type={r['type']} variant={r['variant']} alph={r['alph']}")
                    if 'key' in r:
                        print(f"      key={r['key']}")
                    if 'pt' in r:
                        print(f"      PT={r['pt'][:60]}...")
                    if 'col_order' in r:
                        print(f"      col_order={r['col_order']}")

                if r.get('score', 0) >= 10:
                    high_score_results.append(r)

                if r['type'] in ('col6_autokey', 'col6_autokey_near'):
                    autokey_feasible.append(r)

    print(f"\nPhase 1 complete: {len(all_results)} total results")
    print(f"  Zero-conflict period6/col6: {len(zero_conflict_results)}")
    print(f"  High score (>=10): {len(high_score_results)}")
    print(f"  Autokey feasible (0-1 conflicts): {len(autokey_feasible)}")

    # ── Phase 2: Full autokey decrypt for feasible configs ────────────────

    print("\n" + "=" * 70)
    print("PHASE 2: Full autokey decryption for feasible configs")
    print("=" * 70)

    autokey_results = []

    for cfg in autokey_feasible:
        if cfg['conflicts'] > 0:
            continue  # Only process zero-conflict

        d = cfg['delimiter_pos']
        ct72 = ct73[:d] + ct73[d+1:]
        ene_s = 13 - (1 if d < 13 else 0)
        bcl_s = 47 - (1 if d < 47 else 0)
        col_order = cfg['col_order']
        variant = cfg['variant']
        offset = cfg['offset']

        perm = columnar_perm(6, col_order, 72)
        intermediate = apply_perm(ct72, perm)

        for primer_kw in AUTOKEY_PRIMERS:
            if len(primer_kw) < offset:
                continue
            primer = primer_kw[:offset]

            pt = full_autokey_decrypt_score(intermediate, primer, variant)
            score = score_against_cribs(pt, ene_s, bcl_s)

            if score >= 6:
                autokey_results.append({
                    'type': 'col6_autokey_full',
                    'delimiter_pos': d,
                    'removed_char': ct73[d],
                    'col_order': col_order,
                    'variant': variant,
                    'offset': offset,
                    'primer': primer,
                    'score': score,
                    'pt': pt[:60],
                })
                print(f"  Autokey score {score}/24: d={d} col={col_order} "
                      f"v={variant} primer={primer}")

    # Also try autokey on ALL delimiter positions with keyword col6 orderings
    print("\n  Testing keyword-col6 + autokey across all delimiters...")

    autokey_kw_results = []
    for d in valid_delimiters:
        ct72 = ct73[:d] + ct73[d+1:]
        ene_s = 13 - (1 if d < 13 else 0)
        bcl_s = 47 - (1 if d < 47 else 0)

        for kw6 in KEYWORDS_6[:8]:  # Top 8 keywords
            col_order = keyword_to_col_order(kw6, 6)
            if col_order is None:
                continue
            perm = columnar_perm(6, list(col_order), 72)
            intermediate = apply_perm(ct72, perm)

            for primer in AUTOKEY_PRIMERS[:8]:  # Top 8 primers
                for variant in VARIANTS:
                    pt = full_autokey_decrypt_score(intermediate, primer, variant)
                    score = score_against_cribs(pt, ene_s, bcl_s)

                    if score >= 6:
                        autokey_kw_results.append({
                            'type': 'col6_kw_autokey',
                            'delimiter_pos': d,
                            'removed_char': ct73[d],
                            'col_kw': kw6,
                            'col_order': list(col_order),
                            'variant': variant,
                            'primer': primer,
                            'score': score,
                            'pt': pt[:60],
                        })
                        print(f"  KW-Autokey score {score}/24: d={d} kw={kw6} "
                              f"v={variant} primer={primer}")

    # ── Phase 3: 25-null model ────────────────────────────────────────────

    print("\n" + "=" * 70)
    print("PHASE 3: 25-null model (remove 25 from CT97 -> 72 chars)")
    print("=" * 70)

    # Candidate 25th null positions: all non-crib positions not already in mask
    non_null_non_crib = [i for i in range(CT_LEN)
                         if i not in MASK_SET
                         and i not in range(21, 34)
                         and i not in range(63, 74)]

    print(f"Candidate positions for 25th null: {len(non_null_non_crib)}")

    # Palette positions: those with CT letter in {B,G,I,K,O,W,Z}
    PALETTE = set('BGIKOW Z')
    palette_candidates = [i for i in non_null_non_crib if CT[i] in PALETTE]
    non_palette_candidates = [i for i in non_null_non_crib if CT[i] not in PALETTE]

    print(f"  Palette candidates: {len(palette_candidates)} {palette_candidates}")
    print(f"  Non-palette candidates: {len(non_palette_candidates)}")

    # Test ALL candidates
    mask25_tasks = []
    for extra_pos in non_null_non_crib:
        mask_25 = sorted(MASK_24 + [extra_pos])
        mask25_tasks.append((mask_25, extra_pos))

    phase3_results = []
    phase3_zero_conflicts = []

    with Pool(n_workers) as pool:
        for mask_id, results in pool.imap_unordered(process_25null, mask25_tasks):
            for r in results:
                phase3_results.append(r)
                if r.get('conflicts') == 0 and r['type'] in ('period6_direct', 'col6_period6'):
                    phase3_zero_conflicts.append(r)
                    print(f"  *** 25-NULL ZERO CONFLICTS: extra={mask_id} "
                          f"type={r['type']} variant={r['variant']} alph={r['alph']}")
                    if 'key' in r:
                        print(f"      key={r['key']}")
                    if 'pt' in r:
                        print(f"      PT={r['pt'][:60]}...")

    print(f"\nPhase 3 complete: {len(phase3_results)} results")
    print(f"  Zero-conflict: {len(phase3_zero_conflicts)}")

    # ── Phase 4: Direct period-6 on ct73 (no removal, for baseline) ──────

    print("\n" + "=" * 70)
    print("PHASE 4: Baseline period-6 on ct73 (73 chars, no removal)")
    print("=" * 70)

    baseline_results = []
    for alph in ['AZ', 'KA']:
        res = test_period6_direct(ct73, ENE_START_73, BCL_START_73, alph)
        for r in res:
            r['delimiter_pos'] = 'none'
            r['removed_char'] = 'none'
        baseline_results.extend(res)

    # Also try period-6 col on ct73 (73 chars = incomplete grid)
    # Quick test with keyword orderings only
    for kw6 in KEYWORDS_6[:5]:
        col_order = keyword_to_col_order(kw6, 6)
        if col_order is None:
            continue
        perm = columnar_perm(6, list(col_order), 73)
        inv = invert_perm(perm)
        intermediate = apply_perm(ct73, perm)

        for variant in VARIANTS:
            residue_keys = defaultdict(set)
            for pos, pt_ch in CRIB_73.items():
                inter_pos = inv[pos]
                c = ord(intermediate[inter_pos]) - 65
                p = ord(pt_ch) - 65
                k = key_recover(c, p, variant)
                residue_keys[inter_pos % 6].add(k)

            conflicts = sum(1 for r in residue_keys.values() if len(r) > 1)
            consistent = sum(1 for pos in CRIB_73
                           if len(residue_keys[inv[pos] % 6]) == 1)

            baseline_results.append({
                'type': 'baseline_col6_73',
                'col_kw': kw6,
                'variant': variant,
                'conflicts': conflicts,
                'score': consistent,
            })

    print(f"Baseline results: {len(baseline_results)}")
    for r in baseline_results:
        if r.get('score', 0) >= 10:
            print(f"  Baseline score {r['score']}: {r}")

    # ── Summary ───────────────────────────────────────────────────────────

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Total configs tested: {len(all_results) + len(phase3_results) + len(baseline_results)}")
    print()

    # Aggregate score distribution
    scores = defaultdict(int)
    for r in all_results + phase3_results + baseline_results:
        s = r.get('score', 0)
        scores[s] += 1

    print("Score distribution:")
    for s in sorted(scores.keys(), reverse=True):
        if scores[s] > 0:
            print(f"  {s}/24: {scores[s]} configs")

    print(f"\nZero-conflict (period6 direct): {len([r for r in zero_conflict_results if r['type']=='period6_direct'])}")
    print(f"Zero-conflict (col6+period6): {len([r for r in zero_conflict_results if r['type']=='col6_period6'])}")
    print(f"Zero-conflict (25-null): {len(phase3_zero_conflicts)}")
    print(f"Autokey feasible (0 conflicts): {len([r for r in autokey_feasible if r['conflicts']==0])}")
    print(f"Autokey near (1 conflict): {len([r for r in autokey_feasible if r['conflicts']==1])}")
    print(f"Full autokey >=6/24: {len(autokey_results)}")
    print(f"KW autokey >=6/24: {len(autokey_kw_results)}")

    if high_score_results:
        print(f"\nHigh-score results (>=10/24):")
        for r in sorted(high_score_results, key=lambda x: -x.get('score', 0)):
            print(f"  {r}")

    if zero_conflict_results:
        print(f"\nZERO-CONFLICT results (REPORT IMMEDIATELY):")
        for r in zero_conflict_results:
            print(f"  d={r['delimiter_pos']} removed='{r['removed_char']}' "
                  f"type={r['type']} variant={r['variant']} alph={r['alph']}")
            if 'key' in r:
                print(f"    key={r['key']}")
            if 'pt' in r:
                pt = r['pt']
                # Check for English words
                print(f"    PT={pt}")

    if phase3_zero_conflicts:
        print(f"\n25-NULL ZERO-CONFLICT results:")
        for r in phase3_zero_conflicts:
            print(f"  extra_null={r.get('extra_null')} type={r['type']} "
                  f"variant={r['variant']} key={r.get('key')}")
            if 'pt' in r:
                print(f"    PT={r['pt']}")

    # Save results
    output = {
        'experiment': '72+1 delimiter hypothesis',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'elapsed_s': elapsed,
        'ct73': ct73,
        'ct73_len': len(ct73),
        'null_mask_24': MASK_24,
        'ene_start_73': ENE_START_73,
        'bcl_start_73': BCL_START_73,
        'phase1_total': len(all_results),
        'phase1_zero_conflicts': len(zero_conflict_results),
        'phase1_high_scores': len(high_score_results),
        'phase2_autokey_feasible': len(autokey_feasible),
        'phase2_autokey_zero': len([r for r in autokey_feasible if r['conflicts']==0]),
        'phase2_full_autokey_ge6': len(autokey_results),
        'phase2_kw_autokey_ge6': len(autokey_kw_results),
        'phase3_total': len(phase3_results),
        'phase3_zero_conflicts': len(phase3_zero_conflicts),
        'zero_conflict_results': zero_conflict_results[:50],
        'high_score_results': sorted(high_score_results, key=lambda x: -x.get('score', 0))[:50],
        'autokey_feasible_zero': [r for r in autokey_feasible if r['conflicts']==0][:50],
        'autokey_full_results': autokey_results[:50],
        'autokey_kw_results': autokey_kw_results[:50],
        'phase3_zero_conflict_details': phase3_zero_conflicts[:50],
        'score_distribution': {str(k): v for k, v in sorted(scores.items())},
    }

    outpath = os.path.join(os.path.dirname(__file__), '..', '..', 'results',
                           'e_72plus1_delimiter_v1.json')
    outpath = os.path.abspath(outpath)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")


if __name__ == '__main__':
    main()
