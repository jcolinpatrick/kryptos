#!/usr/bin/env python3
"""
E-S-52: Width-7 Columnar + Carter Running Key (OPTIMIZED)

Model: CT[i] = (INTERMEDIATE[i] + CARTER[offset + i]) mod 26
Where INTERMEDIATE = columnar_transpose(PT, ordering)

KEY OPTIMIZATION: For each ordering, pre-compute the 24 "mapped positions"
in the intermediate text where crib characters land. Then for each offset,
only check those 24 specific Carter text positions (early rejection after
first mismatch → average O(3) checks per offset instead of O(97)).

Two directions:
 D1: CT = RunKey(Transpose(PT)) → INTER = CT - CARTER, PT = undo_trans(INTER)
 D2: CT = Transpose(RunKey(PT)) → INTER = undo_trans(CT), PT = INTER - CARTER

Search: 5040 orderings × 2 directions × ~287K offsets × 3 Carter versions

Output: results/e_s_52_carter_columnar_rk.json
"""

import json
import sys
import os
import re
import time
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX

N = CT_LEN
CT_IDX = [ALPH_IDX[c] for c in CT]
CRIB_LIST = sorted(CRIB_DICT.items())  # (pos, char) sorted by pos
N_CRIBS = len(CRIB_LIST)

# Load Carter texts
def load_carter(path):
    with open(path) as f:
        raw = f.read()
    clean = re.sub(r'[^A-Za-z]', '', raw).upper()
    return [ALPH_IDX[c] for c in clean]

print("Loading Carter texts...", flush=True)
CARTER_TEXTS = {
    'vol1': load_carter("reference/carter_vol1.txt"),
    'cache': load_carter("reference/carter_text_cache.txt"),
    'gutenberg': load_carter("reference/carter_gutenberg.txt"),
}
for name, idx in CARTER_TEXTS.items():
    print(f"  {name}: {len(idx)} chars")


def compute_column_mapping(width, ordering):
    """Compute the position mapping for columnar transposition.

    Returns two mappings:
    - encrypt_map[i] = j means PT[i] → INTER[j]  (write row-by-row, read col-by-col)
    - decrypt_map[j] = i means INTER[j] → PT[i]
    """
    n = N
    n_full_rows = n // width
    n_extra = n % width

    # Column lengths: first n_extra columns have n_full_rows+1, rest have n_full_rows
    col_lengths = [n_full_rows + (1 if c < n_extra else 0) for c in range(width)]

    # The k-th column read is ordering[k]
    # Position in INTER where column ordering[k] starts
    col_start = [0] * width
    pos = 0
    for k in range(width):
        orig_col = ordering[k]
        col_start[orig_col] = pos
        pos += col_lengths[orig_col]

    # Build encrypt_map: PT pos i → INTER pos j
    encrypt_map = [0] * n
    col_offset = [0] * width  # current offset within each column
    pt_pos = 0
    for row in range(n_full_rows + (1 if n_extra > 0 else 0)):
        for col in range(width):
            if col_offset[col] < col_lengths[col]:
                inter_pos = col_start[col] + col_offset[col]
                encrypt_map[pt_pos] = inter_pos
                col_offset[col] += 1
                pt_pos += 1

    # decrypt_map: INTER pos j → PT pos i (inverse)
    decrypt_map = [0] * n
    for i in range(n):
        decrypt_map[encrypt_map[i]] = i

    return encrypt_map, decrypt_map


def search_direction1(ordering, carter_idx, width=7):
    """Direction 1: CT = RunKey(Transpose(PT))
    INTER[i] = CT[i] - CARTER[offset+i] mod 26
    PT[decrypt_map[i]] = INTER[i]

    So for crib (p, expected_pt_val):
      PT[p] = INTER[encrypt_map[p]] = CT[encrypt_map[p]] - CARTER[offset + encrypt_map[p]] mod 26
      Required: CARTER[offset + encrypt_map[p]] ≡ CT[encrypt_map[p]] - expected_pt_val mod 26
    """
    encrypt_map, _ = compute_column_mapping(width, ordering)

    # For each crib, compute the required carter value and the mapped position
    # Sort by mapped position for cache-friendly access
    constraints = []
    for pos, char in CRIB_LIST:
        inter_pos = encrypt_map[pos]  # position in INTER text
        pt_val = ALPH_IDX[char]
        required = (CT_IDX[inter_pos] - pt_val) % 26
        constraints.append((inter_pos, required))

    # Sort by inter_pos to enable early rejection on first mismatch
    # Actually, sorting doesn't help with random access. Just use as-is.

    max_offset = len(carter_idx) - N
    best_matches = 0
    best_offset = -1
    hits = []

    for offset in range(max_offset):
        matches = 0
        for inter_pos, required in constraints:
            if carter_idx[offset + inter_pos] == required:
                matches += 1
            elif matches == 0:
                break  # early reject: first crib failed

        if matches > best_matches:
            best_matches = matches
            best_offset = offset

        if matches >= 16:
            hits.append((offset, matches))

    return best_matches, best_offset, hits


def search_direction2(ordering, carter_idx, width=7):
    """Direction 2: CT = Transpose(RunKey(PT))
    INTER = undo_trans(CT)  (fixed per ordering)
    PT[i] = INTER[i] - CARTER[offset+i] mod 26

    For crib (p, expected_pt_val):
      INTER[p] - CARTER[offset+p] ≡ expected_pt_val mod 26
      Required: CARTER[offset + p] ≡ INTER[p] - expected_pt_val mod 26
    """
    _, decrypt_map = compute_column_mapping(width, ordering)

    # Compute INTER = undo_trans(CT)
    inter = [0] * N
    for j in range(N):
        inter[decrypt_map[j]] = CT_IDX[j]

    # For each crib, compute required carter value
    constraints = []
    for pos, char in CRIB_LIST:
        pt_val = ALPH_IDX[char]
        required = (inter[pos] - pt_val) % 26
        constraints.append((pos, required))

    max_offset = len(carter_idx) - N
    best_matches = 0
    best_offset = -1
    hits = []

    for offset in range(max_offset):
        matches = 0
        for crib_pos, required in constraints:
            if carter_idx[offset + crib_pos] == required:
                matches += 1
            elif matches == 0:
                break

        if matches > best_matches:
            best_matches = matches
            best_offset = offset

        if matches >= 16:
            hits.append((offset, matches))

    return best_matches, best_offset, hits


def full_decrypt_d1(ordering, carter_idx, offset, width=7):
    """Full decryption for Direction 1."""
    encrypt_map, decrypt_map = compute_column_mapping(width, ordering)
    inter = [(CT_IDX[i] - carter_idx[offset + i]) % 26 for i in range(N)]
    pt = [0] * N
    for j in range(N):
        pt[decrypt_map[j]] = inter[j]
    return ''.join(ALPH[x] for x in pt)


def full_decrypt_d2(ordering, carter_idx, offset, width=7):
    """Full decryption for Direction 2."""
    _, decrypt_map = compute_column_mapping(width, ordering)
    inter = [0] * N
    for j in range(N):
        inter[decrypt_map[j]] = CT_IDX[j]
    pt = [(inter[i] - carter_idx[offset + i]) % 26 for i in range(N)]
    return ''.join(ALPH[x] for x in pt)


def main():
    print("=" * 70)
    print("E-S-52: Width-7 Columnar + Carter Running Key (optimized)")
    print("=" * 70)

    t0_global = time.time()
    all_results = {'experiment': 'E-S-52', 'tests': []}

    overall_best = 0

    for carter_name, carter_idx in CARTER_TEXTS.items():
        max_offset = len(carter_idx) - N

        print(f"\n{'='*60}")
        print(f"Carter: {carter_name} ({len(carter_idx)} chars, {max_offset} offsets)")
        print(f"{'='*60}")

        t0 = time.time()
        test_best = 0
        test_best_config = None
        all_hits = []
        n_orderings_done = 0

        for oi, ordering in enumerate(permutations(range(7))):
            ordering = list(ordering)

            # Direction 1
            bm1, bo1, h1 = search_direction1(ordering, carter_idx)
            if bm1 > test_best:
                test_best = bm1
                test_best_config = {'dir': 1, 'ordering': ordering, 'offset': bo1, 'matches': bm1}
            for off, m in h1:
                all_hits.append({'dir': 1, 'ordering': ordering[:], 'offset': off, 'matches': m})

            # Direction 2
            bm2, bo2, h2 = search_direction2(ordering, carter_idx)
            if bm2 > test_best:
                test_best = bm2
                test_best_config = {'dir': 2, 'ordering': ordering, 'offset': bo2, 'matches': bm2}
            for off, m in h2:
                all_hits.append({'dir': 2, 'ordering': ordering[:], 'offset': off, 'matches': m})

            n_orderings_done += 1
            if n_orderings_done % 500 == 0:
                elapsed = time.time() - t0
                rate = n_orderings_done / elapsed if elapsed > 0 else 0
                print(f"  Ordering {n_orderings_done}/5040: best={test_best}/24 "
                      f"hits(≥16)={len(all_hits)} ({rate:.1f} ord/s) [{elapsed:.0f}s]",
                      flush=True)

        elapsed = time.time() - t0
        print(f"  Done ({carter_name}): best={test_best}/24 "
              f"hits(≥16)={len(all_hits)} [{elapsed:.1f}s]")

        if test_best_config:
            cfg = test_best_config
            if cfg['dir'] == 1:
                pt = full_decrypt_d1(cfg['ordering'], carter_idx, cfg['offset'])
            else:
                pt = full_decrypt_d2(cfg['ordering'], carter_idx, cfg['offset'])
            print(f"  Best: dir={cfg['dir']} ordering={cfg['ordering']} "
                  f"offset={cfg['offset']} matches={cfg['matches']}/24")
            print(f"  PT: {pt[:60]}...")
            cfg['pt'] = pt

        # Sort hits by matches descending
        all_hits.sort(key=lambda x: -x['matches'])
        top_hits = all_hits[:10]
        for h in top_hits:
            if h['dir'] == 1:
                h['pt'] = full_decrypt_d1(h['ordering'], carter_idx, h['offset'])
            else:
                h['pt'] = full_decrypt_d2(h['ordering'], carter_idx, h['offset'])

        all_results['tests'].append({
            'carter_version': carter_name,
            'orderings_tested': 5040,
            'offsets_tested': max_offset,
            'best_matches': test_best,
            'best_config': test_best_config,
            'hits_ge16': len(all_hits),
            'top_hits': top_hits,
            'time': round(elapsed, 1),
        })

        overall_best = max(overall_best, test_best)

    elapsed_total = time.time() - t0_global

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    for t in all_results['tests']:
        print(f"  {t['carter_version']}: best={t['best_matches']}/24 "
              f"hits(≥16)={t['hits_ge16']} [{t['time']:.1f}s]")

    # Expected: ~1/26 per crib match. For ~3B configs:
    # P(>=k) per config ~ binom(24, k) * (1/26)^k * (25/26)^(24-k)
    # Max expected over 3B configs: ~8/24
    if overall_best >= 18:
        verdict = "SIGNAL — investigate"
    elif overall_best >= 12:
        verdict = "MARGINAL — above expected max"
    else:
        verdict = "NOISE — Carter + columnar eliminated"

    all_results['verdict'] = verdict
    all_results['overall_best'] = overall_best
    all_results['elapsed_seconds'] = round(elapsed_total, 1)

    print(f"\n  Overall best: {overall_best}/24")
    print(f"  Verdict: {verdict}")
    print(f"  Time: {elapsed_total:.1f}s")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_52_carter_columnar_rk.json", "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"  Artifact: results/e_s_52_carter_columnar_rk.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_52_carter_columnar_running_key.py")


if __name__ == "__main__":
    main()
