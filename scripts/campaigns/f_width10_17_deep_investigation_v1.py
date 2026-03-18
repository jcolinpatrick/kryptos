#!/usr/bin/env python3
"""
Deep investigation of width-10 and width-17 bigram anomalies in CT73.

Investigations:
1. Width-10 deep dive: which bigrams, positions, crib overlap
2. Width-17 deep dive: which bigrams, positions, crib overlap
3. Interaction with col7 transposition
4. Combined width analysis (LCM, grid layouts)
5. Period-10 Beaufort/Vig/VBeau keyword search via crib consistency
6. Period-17 Beaufort/Vig/VBeau keyword search via crib consistency
7. Non-standard ciphers (Quagmire II, autokey, bifid) at periods 10/17
8. Structural analysis of the repeated bigrams

Metadata:
  Cipher: periodic_sub + bigram_analysis
  Family: campaigns
  Status: active
  Keyspace: ~500M
  Last run: 2026-03-16
  Best score: TBD
"""
import sys, os, json, time, math
from collections import Counter, defaultdict
from itertools import product as iprod
from pathlib import Path
from multiprocessing import Pool, cpu_count

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.transforms.vigenere import (
    vig_decrypt, beau_decrypt, varbeau_decrypt,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
    decrypt_text, CipherVariant,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
)
from kryptos.kernel.scoring.ngram import NgramScorer

# ── Constants ──────────────────────────────────────────────────────────────
MASK = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
MASK_SET = set(MASK)

# Build CT73 and mapping
ct73_chars = []
ct97_to_ct73 = {}  # ct97 pos -> ct73 pos
ct73_to_ct97 = {}  # ct73 pos -> ct97 pos
idx73 = 0
for i in range(97):
    if i not in MASK_SET:
        ct73_chars.append(CT[i])
        ct97_to_ct73[i] = idx73
        ct73_to_ct97[idx73] = i
        idx73 += 1
CT73 = ''.join(ct73_chars)
assert len(CT73) == 73, f"CT73 length {len(CT73)} != 73"

# Shifted crib positions in CT73 space
ENE_SHIFTED = {}  # ct73_pos -> plaintext char
BCL_SHIFTED = {}
for pos97, ch in CRIB_DICT.items():
    if pos97 not in MASK_SET:
        pos73 = ct97_to_ct73[pos97]
        if 21 <= pos97 <= 33:
            ENE_SHIFTED[pos73] = ch
        else:
            BCL_SHIFTED[pos73] = ch

ALL_CRIBS_73 = {**ENE_SHIFTED, **BCL_SHIFTED}
# ENE shifted to 13-25, BCL shifted to 47-57

# Col7 transposition on CT73
COL7_ORDER = list(range(7))  # ascending = identity column order
col7_perm = columnar_perm(7, COL7_ORDER, 73)
col7_inv = invert_perm(col7_perm)
CT73_COL7 = apply_perm(CT73, col7_inv)  # undo col7

# Load quadgrams
QG_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
scorer = NgramScorer.from_file(QG_PATH) if QG_PATH.exists() else None

RECOVER_FN = {
    'vig': vig_recover_key,
    'beau': beau_recover_key,
    'vbeau': varbeau_recover_key,
}
DECRYPT_FN = {
    'vig': vig_decrypt,
    'beau': beau_decrypt,
    'vbeau': varbeau_decrypt,
}
VARIANT_MAP = {
    'vig': CipherVariant.VIGENERE,
    'beau': CipherVariant.BEAUFORT,
    'vbeau': CipherVariant.VAR_BEAUFORT,
}

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION 1 & 2: Width-10 and Width-17 Deep Dives
# ══════════════════════════════════════════════════════════════════════════

def vertical_bigrams(text, width):
    """Find all vertical bigrams (pairs in same column, adjacent rows)."""
    n = len(text)
    bigrams = []
    for i in range(n):
        j = i + width
        if j < n:
            bg = text[i] + text[j]
            bigrams.append((i, j, bg))
    return bigrams

def analyze_width(text, width, crib_positions=None, label=""):
    """Detailed analysis of vertical bigrams at given width."""
    bgs = vertical_bigrams(text, width)
    counter = Counter(bg for _, _, bg in bgs)
    repeated = {bg: cnt for bg, cnt in counter.items() if cnt > 1}

    # Find positions of repeated bigrams
    repeated_positions = defaultdict(list)
    for i, j, bg in bgs:
        if bg in repeated:
            repeated_positions[bg].append((i, j))

    # Check crib overlap
    crib_overlap = {}
    if crib_positions:
        for bg, positions in repeated_positions.items():
            for i, j in positions:
                i_crib = i in crib_positions
                j_crib = j in crib_positions
                if i_crib or j_crib:
                    if bg not in crib_overlap:
                        crib_overlap[bg] = []
                    crib_overlap[bg].append((i, j, i_crib, j_crib))

    # Grid layout
    nrows = math.ceil(len(text) / width)
    grid = []
    for r in range(nrows):
        row = text[r*width : (r+1)*width]
        grid.append(row)

    # Residue class analysis
    residue_analysis = {}
    if crib_positions:
        for res in range(width):
            crib_at_res = {p: crib_positions[p] for p in crib_positions if p % width == res}
            residue_analysis[res] = crib_at_res

    return {
        'label': label,
        'width': width,
        'text_length': len(text),
        'total_vertical_bigrams': len(bgs),
        'unique_bigrams': len(counter),
        'repeated_count': sum(cnt for cnt in counter.values() if cnt > 1),
        'n_repeated_types': len(repeated),
        'repeated_bigrams': {bg: {'count': cnt, 'positions': repeated_positions[bg]}
                            for bg, cnt in sorted(repeated.items(), key=lambda x: -x[1])},
        'crib_overlap': {bg: locs for bg, locs in crib_overlap.items()},
        'grid': grid,
        'residue_crib_positions': {str(k): v for k, v in residue_analysis.items()},
    }

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION 3: Interaction with Col7
# ══════════════════════════════════════════════════════════════════════════

def col7_interaction(ct73, ct73_col7):
    """Check if col7 preserves or destroys width-10/17 patterns."""
    results = {}
    for width in [10, 17]:
        pre_bgs = Counter(bg for _, _, bg in vertical_bigrams(ct73, width))
        pre_repeated = sum(1 for cnt in pre_bgs.values() if cnt > 1)

        post_bgs = Counter(bg for _, _, bg in vertical_bigrams(ct73_col7, width))
        post_repeated = sum(1 for cnt in post_bgs.values() if cnt > 1)

        results[width] = {
            'pre_col7_repeated': pre_repeated,
            'post_col7_repeated': post_repeated,
            'preserved': post_repeated >= pre_repeated,
            'delta': post_repeated - pre_repeated,
        }
    return results

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION 4: Combined Width Analysis
# ══════════════════════════════════════════════════════════════════════════

def combined_width_analysis():
    """Analyze LCM relationships and grid layouts."""
    results = {}

    # LCM analysis
    from math import gcd
    pairs = [(10, 17), (10, 7), (17, 7)]
    for a, b in pairs:
        lcm_val = a * b // gcd(a, b)
        results[f'lcm({a},{b})'] = {
            'value': lcm_val,
            'relation_to_73': 73 - lcm_val if lcm_val < 73 else lcm_val - 73,
            'fits_in_73': lcm_val <= 73,
        }

    # 10x7 grid (70 chars + 3 overflow)
    grid_10x7 = []
    for r in range(8):  # ceil(73/10) = 8
        row = CT73[r*10 : (r+1)*10]
        grid_10x7.append(row)

    # 7x10 grid (70 chars + 3 overflow)
    grid_7x10 = []
    for r in range(11):  # ceil(73/7) = 11
        row = CT73[r*7 : (r+1)*7]
        grid_7x10.append(row)

    results['grid_10x7'] = grid_10x7
    results['grid_7x10'] = grid_7x10

    # Column readings from 10-wide grid
    col_readings_w10 = []
    for c in range(10):
        col = ''
        for r in range(8):
            pos = r * 10 + c
            if pos < 73:
                col += CT73[pos]
        col_readings_w10.append(col)
    results['col_readings_w10'] = col_readings_w10

    # Column readings from 17-wide grid
    col_readings_w17 = []
    for c in range(17):
        col = ''
        for r in range(5):
            pos = r * 17 + c
            if pos < 73:
                col += CT73[pos]
        col_readings_w17.append(col)
    results['col_readings_w17'] = col_readings_w17

    return results

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION 5 & 6: Period-10 and Period-17 Keyword Search
# ══════════════════════════════════════════════════════════════════════════

def crib_consistency_at_period(text, period, crib_positions, variant='beau'):
    """Check if crib positions sharing residue mod period have consistent keystream.

    Returns: (n_consistent, n_total, key_array, conflicts_per_residue)
    """
    recover = RECOVER_FN[variant]

    # Group crib positions by residue mod period
    residue_groups = defaultdict(list)
    for pos, pt_ch in crib_positions.items():
        res = pos % period
        ct_val = ord(text[pos]) - 65
        pt_val = ord(pt_ch) - 65
        k = recover(ct_val, pt_val)
        residue_groups[res].append((pos, k))

    key = [None] * period
    consistent = 0
    conflicting = 0
    conflicts = {}

    for res, entries in residue_groups.items():
        key_vals = set(k for _, k in entries)
        if len(key_vals) == 1:
            key[res] = list(key_vals)[0]
            consistent += len(entries)
        else:
            # Take majority vote
            counter = Counter(k for _, k in entries)
            best_k, best_cnt = counter.most_common(1)[0]
            key[res] = best_k
            consistent += best_cnt
            conflicting += len(entries) - best_cnt
            conflicts[res] = {
                'key_values': {chr(k+65): cnt for k, cnt in counter.items()},
                'positions': [(p, chr(k+65)) for p, k in entries],
            }

    n_total = sum(len(v) for v in residue_groups.values())

    return consistent, n_total, key, conflicts

def full_period_keyword_search(text, period, crib_positions, variant='beau'):
    """Try period-N keyword: extract key from cribs, decrypt, score."""
    consistent, total, key, conflicts = crib_consistency_at_period(
        text, period, crib_positions, variant)

    # Fill gaps with brute force (small periods only)
    unfilled = [i for i in range(period) if key[i] is None]

    results = {
        'period': period,
        'variant': variant,
        'crib_consistent': consistent,
        'crib_total': total,
        'conflicts': conflicts,
        'unfilled_residues': unfilled,
        'partial_key': [chr(k+65) if k is not None else '?' for k in key],
    }

    if len(unfilled) <= 3 and scorer is not None:
        # Brute force unfilled positions
        best_score = -999
        best_pt = ''
        best_key_str = ''
        decrypt_fn = DECRYPT_FN[variant]

        ranges = [range(26) if key[i] is None else [key[i]] for i in range(period)]
        count = 0
        for combo in iprod(*ranges):
            full_key = list(combo)
            pt = ''
            for i, ch in enumerate(text):
                ct_val = ord(ch) - 65
                k_val = full_key[i % period]
                pt_val = decrypt_fn(ct_val, k_val)
                pt += chr(pt_val + 65)

            # Check crib match
            crib_match = sum(1 for p, c in crib_positions.items() if pt[p] == c)

            if scorer:
                qg = scorer.score_per_char(pt)
            else:
                qg = -10

            if qg > best_score:
                best_score = qg
                best_pt = pt
                best_key_str = ''.join(chr(k+65) for k in full_key)
            count += 1

        results['brute_force_count'] = count
        results['best_qg'] = best_score
        results['best_pt'] = best_pt
        results['best_key'] = best_key_str

        # Check crib match for best
        results['best_crib_match'] = sum(1 for p, c in crib_positions.items()
                                         if best_pt[p] == c)

    return results

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION 5b: Exhaustive period-10 keyword search with scoring
# ══════════════════════════════════════════════════════════════════════════

def _score_period_key(args):
    """Worker: try one key tuple, return (score, key, pt, crib_match)."""
    key_tuple, text, period, variant, crib_positions = args
    decrypt_fn = DECRYPT_FN[variant]

    pt_chars = []
    for i, ch in enumerate(text):
        ct_val = ord(ch) - 65
        k_val = key_tuple[i % period]
        pt_val = decrypt_fn(ct_val, k_val)
        pt_chars.append(chr(pt_val + 65))
    pt = ''.join(pt_chars)

    crib_match = sum(1 for p, c in crib_positions.items() if pt[p] == c)

    return (crib_match, key_tuple, pt)


def exhaustive_period_search_crib_constrained(text, period, crib_positions, variant='beau'):
    """For each residue class, determine required key values from cribs.
    Then brute force only the unconstrained residues."""
    recover = RECOVER_FN[variant]

    # Determine key constraints per residue
    residue_constraints = {}
    for res in range(period):
        crib_at_res = [(pos, crib_positions[pos]) for pos in crib_positions if pos % period == res]
        if crib_at_res:
            key_vals = set()
            for pos, pt_ch in crib_at_res:
                ct_val = ord(text[pos]) - 65
                pt_val = ord(pt_ch) - 65
                k = recover(ct_val, pt_val)
                key_vals.add(k)
            residue_constraints[res] = key_vals

    # Build search space
    free_residues = []
    constrained_residues = {}

    for res in range(period):
        if res in residue_constraints:
            vals = residue_constraints[res]
            if len(vals) == 1:
                constrained_residues[res] = list(vals)[0]
            else:
                # Conflict — try each possible value
                free_residues.append((res, list(vals)))
        else:
            free_residues.append((res, list(range(26))))

    # Count search space
    search_size = 1
    for _, vals in free_residues:
        search_size *= len(vals)

    print(f"  Period {period} {variant}: {len(constrained_residues)} constrained, "
          f"{len(free_residues)} free residues, search space = {search_size:,}")

    # Build key templates
    best_results = []
    decrypt_fn = DECRYPT_FN[variant]

    if search_size > 50_000_000:
        print(f"  Search space too large ({search_size:,}), sampling...")
        import random
        random.seed(42)
        sample_size = 5_000_000

        for _ in range(sample_size):
            key = [0] * period
            for res, val in constrained_residues.items():
                key[res] = val
            for res, vals in free_residues:
                key[res] = random.choice(vals)

            pt = ''
            for i, ch in enumerate(text):
                ct_val = ord(ch) - 65
                pt_val = decrypt_fn(ct_val, key[i % period])
                pt += chr(pt_val + 65)

            crib_match = sum(1 for p, c in crib_positions.items() if pt[p] == c)
            if crib_match >= max(period // 2, 5):
                qg = scorer.score_per_char(pt) if scorer else -10
                best_results.append((crib_match, qg, ''.join(chr(k+65) for k in key), pt))

        best_results.sort(key=lambda x: (-x[0], -x[1]))
        return {
            'period': period,
            'variant': variant,
            'search_type': 'sampled',
            'sample_size': sample_size,
            'constrained_count': len(constrained_residues),
            'free_count': len(free_residues),
            'hits': best_results[:20],
        }

    # Exhaustive for manageable search space
    ranges = []
    for res in range(period):
        if res in constrained_residues:
            ranges.append([constrained_residues[res]])
        else:
            found = False
            for r, vals in free_residues:
                if r == res:
                    ranges.append(vals)
                    found = True
                    break
            if not found:
                ranges.append(list(range(26)))

    evaluated = 0
    for combo in iprod(*ranges):
        key = list(combo)
        pt = ''
        for i, ch in enumerate(text):
            ct_val = ord(ch) - 65
            pt_val = decrypt_fn(ct_val, key[i % period])
            pt += chr(pt_val + 65)

        crib_match = sum(1 for p, c in crib_positions.items() if pt[p] == c)
        if crib_match >= max(period // 2, 5):
            qg = scorer.score_per_char(pt) if scorer else -10
            best_results.append((crib_match, qg, ''.join(chr(k+65) for k in key), pt))

        evaluated += 1
        if evaluated % 1_000_000 == 0:
            print(f"    ... {evaluated:,}/{search_size:,} evaluated, {len(best_results)} hits")

    best_results.sort(key=lambda x: (-x[0], -x[1]))
    return {
        'period': period,
        'variant': variant,
        'search_type': 'exhaustive',
        'total_evaluated': evaluated,
        'constrained_count': len(constrained_residues),
        'free_count': len(free_residues),
        'hits': best_results[:20],
    }

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION 7: Non-Standard Ciphers at Period 10 and 17
# ══════════════════════════════════════════════════════════════════════════

def autokey_decrypt_period(text, primer, variant='beau'):
    """Autokey decrypt with given primer (PT-autokey)."""
    decrypt_fn = DECRYPT_FN[variant]
    pt = []
    key_stream = list(primer)
    for i, ch in enumerate(text):
        ct_val = ord(ch) - 65
        k_val = key_stream[i]
        pt_val = decrypt_fn(ct_val, k_val)
        pt.append(pt_val)
        key_stream.append(pt_val)
    return ''.join(chr(v+65) for v in pt)

def ct_autokey_decrypt_period(text, primer, variant='beau'):
    """CT-autokey decrypt with given primer."""
    decrypt_fn = DECRYPT_FN[variant]
    pt = []
    key_stream = list(primer)
    for i, ch in enumerate(text):
        ct_val = ord(ch) - 65
        k_val = key_stream[i]
        pt_val = decrypt_fn(ct_val, k_val)
        pt.append(pt_val)
        key_stream.append(ct_val)
    return ''.join(chr(v+65) for v in pt)

def test_autokey_primers(text, primer_length, crib_positions, variant='beau'):
    """Test autokey with all primers of given length, score by crib match."""
    best = []
    # Sample primers using crib-derived key values
    recover = RECOVER_FN[variant]

    # Get key values at first primer_length crib positions
    known_keys = {}
    for pos, pt_ch in sorted(crib_positions.items()):
        ct_val = ord(text[pos]) - 65
        pt_val = ord(pt_ch) - 65
        k = recover(ct_val, pt_val)
        known_keys[pos] = k

    # Try primers from thematic keywords
    from kryptos.kernel.alphabet import THEMATIC_KEYWORDS

    for kw in THEMATIC_KEYWORDS:
        if len(kw) >= primer_length:
            primer = [ord(c) - 65 for c in kw[:primer_length]]

            for ak_type in ['pt', 'ct']:
                if ak_type == 'pt':
                    pt = autokey_decrypt_period(text, primer, variant)
                else:
                    pt = ct_autokey_decrypt_period(text, primer, variant)

                crib_match = sum(1 for p, c in crib_positions.items() if pt[p] == c)
                if crib_match >= 5:
                    qg = scorer.score_per_char(pt) if scorer else -10
                    best.append((crib_match, qg, f"{kw[:primer_length]}:{variant}:{ak_type}", pt))

    best.sort(key=lambda x: (-x[0], -x[1]))
    return best[:10]

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION 8: Structural Analysis
# ══════════════════════════════════════════════════════════════════════════

def structural_analysis(text, widths, crib_positions):
    """Analyze whether repeated bigrams relate to crib regions, null positions, etc."""
    results = {}

    for width in widths:
        bgs = vertical_bigrams(text, width)
        counter = Counter(bg for _, _, bg in bgs)
        repeated = {bg for bg, cnt in counter.items() if cnt > 1}

        # Positions of repeated bigrams
        rep_positions = set()
        for i, j, bg in bgs:
            if bg in repeated:
                rep_positions.add(i)
                rep_positions.add(j)

        # Map back to CT97 positions
        ct97_positions = set()
        for p73 in rep_positions:
            if p73 in ct73_to_ct97:
                ct97_positions.add(ct73_to_ct97[p73])

        # Check overlap with crib positions
        crib_pos_set = set(crib_positions.keys())
        crib_overlap = rep_positions & crib_pos_set

        # Residue distribution
        residue_dist = Counter(p % width for p in rep_positions)

        # Check if repeated bigrams are at positions that were near nulls in CT97
        near_null = 0
        for p97 in ct97_positions:
            for null_p in MASK:
                if abs(p97 - null_p) <= 1:
                    near_null += 1
                    break

        results[width] = {
            'n_repeated_positions': len(rep_positions),
            'repeated_positions_ct73': sorted(rep_positions),
            'repeated_positions_ct97': sorted(ct97_positions),
            'crib_overlap_count': len(crib_overlap),
            'crib_overlap_positions': sorted(crib_overlap),
            'residue_distribution': dict(sorted(residue_dist.items())),
            'near_null_count': near_null,
            'near_null_fraction': near_null / len(ct97_positions) if ct97_positions else 0,
        }

    return results

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION: Seriated Column IC at various widths
# ══════════════════════════════════════════════════════════════════════════

def column_ic(text, width):
    """Compute IC per column when text is laid out at given width."""
    cols = defaultdict(list)
    for i, ch in enumerate(text):
        cols[i % width].append(ch)

    col_ics = {}
    for c, letters in cols.items():
        n = len(letters)
        if n < 2:
            col_ics[c] = 0
            continue
        freq = Counter(letters)
        ic = sum(f * (f-1) for f in freq.values()) / (n * (n-1))
        col_ics[c] = ic

    avg_ic = sum(col_ics.values()) / len(col_ics)
    return avg_ic, col_ics

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    results = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'ct73': CT73,
        'ct73_col7': CT73_COL7,
        'mask': MASK,
        'ene_shifted_positions': {str(k): v for k, v in ENE_SHIFTED.items()},
        'bcl_shifted_positions': {str(k): v for k, v in BCL_SHIFTED.items()},
    }

    print("=" * 70)
    print("INVESTIGATION 1: Width-10 Deep Dive on CT73")
    print("=" * 70)
    w10 = analyze_width(CT73, 10, ALL_CRIBS_73, "CT73_width10")
    results['inv1_width10'] = w10

    print(f"\nCT73 at width 10:")
    for i, row in enumerate(w10['grid']):
        row_positions = list(range(i*10, min(i*10+10, 73)))
        crib_marks = ''.join('*' if p in ALL_CRIBS_73 else ' ' for p in row_positions)
        print(f"  {row}   {crib_marks}  (pos {i*10}-{min(i*10+9, 72)})")

    print(f"\nRepeated vertical bigrams at width 10 ({w10['n_repeated_types']} types):")
    for bg, info in w10['repeated_bigrams'].items():
        positions_str = ', '.join(f"({a},{b})" for a, b in info['positions'])
        overlap = bg in w10['crib_overlap']
        print(f"  {bg} x{info['count']}: at {positions_str} {'[CRIB OVERLAP]' if overlap else ''}")

    print(f"\nCrib positions by residue mod 10:")
    for res in range(10):
        cribs = {p: c for p, c in ALL_CRIBS_73.items() if p % 10 == res}
        if cribs:
            print(f"  res={res}: {cribs}")

    print("\n" + "=" * 70)
    print("INVESTIGATION 2: Width-17 Deep Dive on CT73")
    print("=" * 70)
    w17 = analyze_width(CT73, 17, ALL_CRIBS_73, "CT73_width17")
    results['inv2_width17'] = w17

    print(f"\nCT73 at width 17:")
    for i, row in enumerate(w17['grid']):
        row_positions = list(range(i*17, min(i*17+17, 73)))
        crib_marks = ''.join('*' if p in ALL_CRIBS_73 else ' ' for p in row_positions)
        print(f"  {row}   {crib_marks}  (pos {i*17}-{min(i*17+16, 72)})")

    print(f"\nRepeated vertical bigrams at width 17 ({w17['n_repeated_types']} types):")
    for bg, info in w17['repeated_bigrams'].items():
        positions_str = ', '.join(f"({a},{b})" for a, b in info['positions'])
        overlap = bg in w17['crib_overlap']
        print(f"  {bg} x{info['count']}: at {positions_str} {'[CRIB OVERLAP]' if overlap else ''}")

    print(f"\nCrib positions by residue mod 17:")
    for res in range(17):
        cribs = {p: c for p, c in ALL_CRIBS_73.items() if p % 17 == res}
        if cribs:
            print(f"  res={res}: {cribs}")

    print("\n" + "=" * 70)
    print("INVESTIGATION 3: Interaction with Col7")
    print("=" * 70)
    col7_int = col7_interaction(CT73, CT73_COL7)
    results['inv3_col7_interaction'] = col7_int

    for width, info in col7_int.items():
        status = "PRESERVED" if info['preserved'] else "DESTROYED"
        print(f"  Width {width}: pre={info['pre_col7_repeated']} -> post={info['post_col7_repeated']} ({status})")

    # Also check width-10 and 17 on CT73_COL7
    w10_col7 = analyze_width(CT73_COL7, 10, {}, "CT73_COL7_width10")
    w17_col7 = analyze_width(CT73_COL7, 17, {}, "CT73_COL7_width17")
    results['inv3_w10_col7'] = w10_col7
    results['inv3_w17_col7'] = w17_col7

    print(f"\n  CT73_COL7 width-10 repeated: {w10_col7['n_repeated_types']} types")
    for bg, info in w10_col7['repeated_bigrams'].items():
        print(f"    {bg} x{info['count']}")
    print(f"  CT73_COL7 width-17 repeated: {w17_col7['n_repeated_types']} types")
    for bg, info in w17_col7['repeated_bigrams'].items():
        print(f"    {bg} x{info['count']}")

    print("\n" + "=" * 70)
    print("INVESTIGATION 4: Combined Width Analysis")
    print("=" * 70)
    cw = combined_width_analysis()
    results['inv4_combined'] = cw

    for key_str, info in cw.items():
        if key_str.startswith('lcm'):
            print(f"  {key_str} = {info['value']} (diff from 73: {info['relation_to_73']})")

    print(f"\n  CT73 in 10-wide grid (7 full rows + 3 overflow):")
    for i, row in enumerate(cw['grid_10x7']):
        print(f"    row {i}: {row}")

    print(f"\n  CT73 in 7-wide grid (10 full rows + 3 overflow):")
    for i, row in enumerate(cw['grid_7x10']):
        print(f"    row {i}: {row}")

    print("\n" + "=" * 70)
    print("INVESTIGATION 4b: Column IC at various widths")
    print("=" * 70)
    ic_results = {}
    for w in range(3, 30):
        avg_ic, col_ics = column_ic(CT73, w)
        ic_results[w] = {'avg_ic': avg_ic, 'per_col': {str(k): v for k, v in col_ics.items()}}
        if avg_ic > 0.045:
            print(f"  Width {w}: avg_ic = {avg_ic:.4f} ** ELEVATED **")
        elif avg_ic > 0.040:
            print(f"  Width {w}: avg_ic = {avg_ic:.4f} (slightly elevated)")
        elif w in [7, 10, 17]:
            print(f"  Width {w}: avg_ic = {avg_ic:.4f}")
    results['inv4b_column_ic'] = ic_results

    # Also on CT73_COL7
    print("\n  Column IC on CT73_COL7:")
    ic_results_col7 = {}
    for w in range(3, 30):
        avg_ic, col_ics = column_ic(CT73_COL7, w)
        ic_results_col7[w] = {'avg_ic': avg_ic}
        if avg_ic > 0.045:
            print(f"  Width {w}: avg_ic = {avg_ic:.4f} ** ELEVATED **")
        elif avg_ic > 0.040 or w in [7, 10, 17]:
            print(f"  Width {w}: avg_ic = {avg_ic:.4f}")
    results['inv4b_column_ic_col7'] = ic_results_col7

    print("\n" + "=" * 70)
    print("INVESTIGATION 5: Period-10 Crib Consistency & Keyword Search")
    print("=" * 70)
    inv5_results = {}

    for variant in ['vig', 'beau', 'vbeau']:
        print(f"\n  === {variant.upper()} period 10 on CT73 ===")
        cons, total, key, conflicts = crib_consistency_at_period(
            CT73, 10, ALL_CRIBS_73, variant)
        key_str = ''.join(chr(k+65) if k is not None else '?' for k in key)
        print(f"  Consistent: {cons}/{total}, Key: {key_str}")
        if conflicts:
            print(f"  Conflicts at residues: {list(conflicts.keys())}")
            for res, info in conflicts.items():
                print(f"    res={res}: {info['key_values']}")

        # Full search
        search = exhaustive_period_search_crib_constrained(
            CT73, 10, ALL_CRIBS_73, variant)
        inv5_results[f'ct73_{variant}'] = search

        if search['hits']:
            print(f"  Top hit: crib={search['hits'][0][0]}, "
                  f"qg={search['hits'][0][1]:.3f}, key={search['hits'][0][2]}")
        else:
            print(f"  No hits with crib >= {max(5, 5)}")

    # Also on CT73_COL7 (pre-transposition text)
    # Remap cribs for col7-undone text
    col7_crib_positions = {}
    for p73, ch in ALL_CRIBS_73.items():
        # After undoing col7, position p73 in CT73 maps to col7_inv[p73] in the original
        # But we need: which positions in CT73_COL7 correspond to the crib plaintext?
        # CT73_COL7[i] = CT73[col7_inv[i]], so CT73[p73] = CT73_COL7[col7_perm[p73]]
        # The crib says: CT73[p73] encrypts to PT[p73]
        # After col7 undo: CT73_COL7[i] was at position col7_inv[i] in the cipher output
        # So crib at position p73 in CT73 = position col7_perm[p73] in CT73_COL7? No...
        # CT73_COL7 = apply_perm(CT73, col7_inv) means CT73_COL7[i] = CT73[col7_inv[i]]
        # So if the cipher operates BEFORE col7, then CT73_COL7 is the cipher output
        # and the positions shift. The crib in CT73 at position p73 means:
        # the letter CT73[p73] encrypts plaintext crib_ch.
        # CT73[p73] = CT73_COL7[col7_perm[p73]] (since CT73_COL7 uses col7_inv gather)
        # Wait: CT73_COL7[i] = CT73[col7_inv[i]], so CT73[j] = CT73_COL7[col7_perm[j]]
        # Hmm, that's wrong. Let me think...
        # col7_perm = columnar fill-by-row, read-by-column
        # apply_perm(text, perm): output[i] = text[perm[i]]
        # So CT73_COL7[i] = CT73[col7_inv[i]]
        # To find where CT73[p73] appears in CT73_COL7:
        #   CT73_COL7[x] = CT73[p73] when col7_inv[x] = p73, i.e., x = col7_perm[p73]
        # Wait no: col7_inv[x] = p73 means x is such that invert_perm(col7_perm)[x] = p73
        # If inv = invert_perm(perm), then inv[perm[i]] = i for all i
        # So if col7_inv[x] = p73, then x = col7_perm[p73]
        # Hmm, that's only true if perm and inv are truly inverses: inv[perm[j]]=j
        # col7_inv = invert_perm(col7_perm), so col7_inv[col7_perm[j]] = j
        # We want: col7_inv[x] = p73 => x = ?
        # From inv[perm[j]]=j: if j = p73, then inv[perm[p73]] = p73
        # So col7_inv[col7_perm[p73]] = p73, meaning x = col7_perm[p73]
        new_pos = col7_perm[p73] if p73 < len(col7_perm) else None
        if new_pos is not None:
            col7_crib_positions[new_pos] = ch

    for variant in ['vig', 'beau', 'vbeau']:
        print(f"\n  === {variant.upper()} period 10 on CT73_COL7 (undone col7) ===")
        cons, total, key, conflicts = crib_consistency_at_period(
            CT73_COL7, 10, col7_crib_positions, variant)
        key_str = ''.join(chr(k+65) if k is not None else '?' for k in key)
        print(f"  Consistent: {cons}/{total}, Key: {key_str}")
        if conflicts:
            print(f"  Conflicts at residues: {list(conflicts.keys())}")

        search = exhaustive_period_search_crib_constrained(
            CT73_COL7, 10, col7_crib_positions, variant)
        inv5_results[f'ct73col7_{variant}'] = search

        if search['hits']:
            print(f"  Top hit: crib={search['hits'][0][0]}, "
                  f"qg={search['hits'][0][1]:.3f}, key={search['hits'][0][2]}")
        else:
            print(f"  No hits with crib >= {max(5, 5)}")

    results['inv5_period10'] = inv5_results

    print("\n" + "=" * 70)
    print("INVESTIGATION 6: Period-17 Crib Consistency & Keyword Search")
    print("=" * 70)
    inv6_results = {}

    for variant in ['vig', 'beau', 'vbeau']:
        print(f"\n  === {variant.upper()} period 17 on CT73 ===")
        cons, total, key, conflicts = crib_consistency_at_period(
            CT73, 17, ALL_CRIBS_73, variant)
        key_str = ''.join(chr(k+65) if k is not None else '?' for k in key)
        print(f"  Consistent: {cons}/{total}, Key: {key_str}")
        if conflicts:
            print(f"  Conflicts at residues: {list(conflicts.keys())}")
            for res, info in conflicts.items():
                print(f"    res={res}: {info['key_values']}")

        search = exhaustive_period_search_crib_constrained(
            CT73, 17, ALL_CRIBS_73, variant)
        inv6_results[f'ct73_{variant}'] = search

        if search['hits']:
            print(f"  Top hit: crib={search['hits'][0][0]}, "
                  f"qg={search['hits'][0][1]:.3f}, key={search['hits'][0][2]}")
        else:
            print(f"  No hits with crib >= threshold")

    for variant in ['vig', 'beau', 'vbeau']:
        print(f"\n  === {variant.upper()} period 17 on CT73_COL7 ===")
        cons, total, key, conflicts = crib_consistency_at_period(
            CT73_COL7, 17, col7_crib_positions, variant)
        key_str = ''.join(chr(k+65) if k is not None else '?' for k in key)
        print(f"  Consistent: {cons}/{total}, Key: {key_str}")
        if conflicts:
            print(f"  Conflicts at residues: {list(conflicts.keys())}")

        search = exhaustive_period_search_crib_constrained(
            CT73_COL7, 17, col7_crib_positions, variant)
        inv6_results[f'ct73col7_{variant}'] = search

        if search['hits']:
            print(f"  Top hit: crib={search['hits'][0][0]}, "
                  f"qg={search['hits'][0][1]:.3f}, key={search['hits'][0][2]}")
        else:
            print(f"  No hits with crib >= threshold")

    results['inv6_period17'] = inv6_results

    print("\n" + "=" * 70)
    print("INVESTIGATION 7: Non-Standard Ciphers at Period 10 and 17")
    print("=" * 70)
    inv7_results = {}

    for primer_len in [10, 17]:
        for variant in ['vig', 'beau', 'vbeau']:
            print(f"\n  Autokey primer_len={primer_len}, {variant} on CT73:")
            hits = test_autokey_primers(CT73, primer_len, ALL_CRIBS_73, variant)
            key_name = f'autokey_ct73_{variant}_p{primer_len}'
            inv7_results[key_name] = hits
            if hits:
                print(f"    Best: crib={hits[0][0]}, qg={hits[0][1]:.3f}, config={hits[0][2]}")
            else:
                print(f"    No hits >= 5 crib")

            print(f"  Autokey primer_len={primer_len}, {variant} on CT73_COL7:")
            hits = test_autokey_primers(CT73_COL7, primer_len, col7_crib_positions, variant)
            key_name = f'autokey_ct73col7_{variant}_p{primer_len}'
            inv7_results[key_name] = hits
            if hits:
                print(f"    Best: crib={hits[0][0]}, qg={hits[0][1]:.3f}, config={hits[0][2]}")
            else:
                print(f"    No hits >= 5 crib")

    results['inv7_nonstandard'] = inv7_results

    print("\n" + "=" * 70)
    print("INVESTIGATION 8: Structural Analysis of Repeated Bigrams")
    print("=" * 70)
    inv8 = structural_analysis(CT73, [10, 17], ALL_CRIBS_73)
    results['inv8_structural'] = inv8

    for width, info in inv8.items():
        print(f"\n  Width {width}:")
        print(f"    Repeated bigram positions in CT73: {info['repeated_positions_ct73']}")
        print(f"    Mapped to CT97: {info['repeated_positions_ct97']}")
        print(f"    Crib overlap: {info['crib_overlap_count']} positions ({info['crib_overlap_positions']})")
        print(f"    Near-null fraction: {info['near_null_fraction']:.2f}")
        print(f"    Residue distribution: {info['residue_distribution']}")

    # ── Additional: Check Bean d=10 and d=17 ──
    print("\n" + "=" * 70)
    print("ADDITIONAL: Bean-style consecutive bigram test at d=10 and d=17")
    print("=" * 70)

    for d in [10, 17]:
        consec_ct73 = 0
        consec_ct97 = 0
        for i in range(len(CT73) - 2*d):
            if CT73[i] == CT73[i+d] and CT73[i+1] == CT73[i+d+1]:
                consec_ct73 += 1
                print(f"  CT73 d={d}: consecutive bigram repeat at pos {i}: "
                      f"{CT73[i]}{CT73[i+1]} == {CT73[i+d]}{CT73[i+d+1]}")
        for i in range(len(CT) - 2*d):
            if CT[i] == CT[i+d] and CT[i+1] == CT[i+d+1]:
                consec_ct97 += 1
                print(f"  CT97 d={d}: consecutive bigram repeat at pos {i}: "
                      f"{CT[i]}{CT[i+1]} == {CT[i+d]}{CT[i+d+1]}")
        print(f"  d={d}: CT73 consecutive repeats = {consec_ct73}, CT97 = {consec_ct97}")
        results[f'bean_d{d}'] = {'ct73': consec_ct73, 'ct97': consec_ct97}

    # ── INVESTIGATION: 2-letter seed recurrence for period 10 ──
    print("\n" + "=" * 70)
    print("INVESTIGATION 5e: Period-10 via 2-letter seed recurrence")
    print("=" * 70)

    # Try all 676 seeds that generate period-10 keys via Fibonacci-like recurrence
    # k[i+2] = (k[i] + k[i+1]) mod 26, and check if period divides 10
    inv5e_results = []
    for a in range(26):
        for b in range(26):
            # Generate sequence
            seq = [a, b]
            for _ in range(100):
                seq.append((seq[-2] + seq[-1]) % 26)

            # Check if periodic with period 10
            periodic_10 = all(seq[i] == seq[i+10] for i in range(50))
            if periodic_10:
                key10 = seq[:10]
                # Try decrypting CT73
                for variant in ['vig', 'beau', 'vbeau']:
                    decrypt_fn = DECRYPT_FN[variant]
                    pt = ''
                    for i, ch in enumerate(CT73):
                        ct_val = ord(ch) - 65
                        pt_val = decrypt_fn(ct_val, key10[i % 10])
                        pt += chr(pt_val + 65)

                    crib_match = sum(1 for p, c in ALL_CRIBS_73.items() if pt[p] == c)
                    if crib_match >= 3:
                        qg = scorer.score_per_char(pt) if scorer else -10
                        inv5e_results.append({
                            'seed': (a, b),
                            'key': ''.join(chr(k+65) for k in key10),
                            'variant': variant,
                            'crib_match': crib_match,
                            'qg': qg,
                        })

    inv5e_results.sort(key=lambda x: (-x['crib_match'], -x['qg']))
    results['inv5e_recurrence'] = inv5e_results[:20]
    print(f"  Found {len(inv5e_results)} periodic-10 Fibonacci seeds with crib >= 3")
    if inv5e_results:
        for r in inv5e_results[:5]:
            print(f"    seed={r['seed']}, key={r['key']}, {r['variant']}, "
                  f"crib={r['crib_match']}, qg={r['qg']:.3f}")

    # ── Width-10 special: 10 = 2*5 = Polybius grid width ──
    print("\n" + "=" * 70)
    print("INVESTIGATION 8b: Width-10 = 2*Polybius?")
    print("=" * 70)

    # Check if repeated bigrams encode Polybius pairs
    w10_bgs = vertical_bigrams(CT73, 10)
    w10_repeated = Counter(bg for _, _, bg in w10_bgs)
    repeated_bgs_w10 = {bg for bg, cnt in w10_repeated.items() if cnt > 1}

    print(f"  Repeated bigrams at width 10: {sorted(repeated_bgs_w10)}")
    print(f"  Number of unique letters in first chars: {len(set(bg[0] for bg in repeated_bgs_w10))}")
    print(f"  Number of unique letters in second chars: {len(set(bg[1] for bg in repeated_bgs_w10))}")

    # Check relationship to 5*5 Polybius
    # If text was fractionated via Polybius, even positions = row, odd = col
    # Width 10 would pair (pos, pos+10), which is 2 rows apart in a 5-wide grid

    elapsed = time.time() - t0
    results['elapsed_s'] = elapsed

    # Save results
    outpath = Path(__file__).resolve().parents[2] / "results" / "f_width10_17_deep_investigation.json"

    # Clean up non-serializable items
    def make_serializable(obj):
        if isinstance(obj, dict):
            return {str(k): make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [make_serializable(v) for v in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)

    with open(outpath, 'w') as f:
        json.dump(make_serializable(results), f, indent=2)

    print(f"\n{'=' * 70}")
    print(f"COMPLETE in {elapsed:.1f}s")
    print(f"Results: {outpath}")
    print(f"{'=' * 70}")

    return results

if __name__ == '__main__':
    main()
