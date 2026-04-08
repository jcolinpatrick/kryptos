#!/usr/bin/env python3
"""
Cipher: columnar transposition + running key
Family: running_key
Status: active
Keyspace: widths 5-9, all permutations, 2 directions, 2 variants, ~287K offsets
Last run:
Best score:
"""
"""
E-CARTER-TRANS-OPT-01: Pair-Index Optimized Carter + Columnar Transposition + Running Key

Model:
  D1: CT = RunKey(Trans(PT), Carter)
  D2: CT = Trans(RunKey(PT, Carter))

Pair-index optimization (~676x speedup over naive scan):
  For each (ordering, direction, variant):
    1. Compute 24 constraints: (carter_relative_pos, required_value)
    2. Pick first 2 constraints (pos_a, val_a), (pos_b, val_b)
    3. Look up in pre-built pair-index: map[(carter[off+pos_a], carter[off+pos_b])] -> offsets
    4. Only check offsets where first 2 constraints match
    5. For surviving offsets, check remaining 22 constraints

Key insight for D2: carter relative positions are always crib positions {21-33, 63-73}
regardless of ordering. Only required values change. So the pair-index can be REUSED
across all orderings for D2 (just change the lookup key). Massive speedup.

For D1: carter relative positions change per ordering (they are encrypt_map[crib_pos]).
Must rebuild pair-index per ordering, but still ~676x speedup per ordering.

Widths tested: 5 (120), 6 (720), 7 (5040), 8 (40320)
Variants: vig (K = CT - PT), beau (K = CT + PT)
Directions: D1 (encrypt then running key), D2 (running key then encrypt)

Output: results/e_carter_transposition_optimized_01.json
"""

import json
import sys
import os
import re
import time
from itertools import permutations
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX, N_CRIBS

# Corpus policy declaration — Carter Vol 1 (allowlisted as `carter_tomb_vol1`).
SOURCE_ID = "carter_tomb_vol1"

N = CT_LEN
CT_IDX = [ALPH_IDX[c] for c in CT]
CRIB_LIST = sorted(CRIB_DICT.items())  # (pos, char) sorted by pos
CRIB_POSITIONS_SORTED = [pos for pos, _ in CRIB_LIST]
CRIB_PT_VALS = [ALPH_IDX[ch] for _, ch in CRIB_LIST]
CRIB_CT_VALS = [CT_IDX[pos] for pos, _ in CRIB_LIST]


def load_carter(path):
    """Load and clean a Carter text file, return list of int indices."""
    with open(path) as f:
        raw = f.read()
    clean = re.sub(r'[^A-Za-z]', '', raw).upper()
    return [ALPH_IDX[c] for c in clean]


def compute_column_mapping(width, ordering, n=N):
    """Compute encrypt_map for columnar transposition.

    encrypt_map[i] = j means: PT written at row-major position i
    appears at position j in the ciphertext (reading columns in key order).
    """
    n_full_rows = n // width
    n_extra = n % width

    # Column lengths
    col_lengths = [n_full_rows + (1 if c < n_extra else 0) for c in range(width)]

    # Column start positions in output (reading columns in ordering)
    col_start = [0] * width
    pos = 0
    for k in range(width):
        orig_col = ordering[k]
        col_start[orig_col] = pos
        pos += col_lengths[orig_col]

    # Build encrypt_map
    encrypt_map = [0] * n
    col_offset = [0] * width
    pt_pos = 0
    n_rows = n_full_rows + (1 if n_extra > 0 else 0)
    for row in range(n_rows):
        for col in range(width):
            if pt_pos >= n:
                break
            if row < col_lengths[col]:
                encrypt_map[pt_pos] = col_start[col] + col_offset[col]
                col_offset[col] += 1
                pt_pos += 1

    return encrypt_map


def build_pair_index(carter_idx, pos_a, pos_b, max_offset):
    """Build index: (carter[off+pos_a], carter[off+pos_b]) -> list of offsets."""
    idx = defaultdict(list)
    for off in range(max_offset):
        key = (carter_idx[off + pos_a], carter_idx[off + pos_b])
        idx[key].append(off)
    return idx


def search_d1_paired(ordering, carter_idx, max_offset, width, variant):
    """D1: CT = RunKey(Trans(PT), Carter)

    At crib position k: CT[encrypt_map[k]] = f(PT[k], Carter[off + encrypt_map[k]])
    Vig: required Carter value = (CT[encrypt_map[k]] - PT[k]) mod 26
    Beau: required Carter value = (CT[encrypt_map[k]] + PT[k]) mod 26

    Carter relative positions are encrypt_map[crib_pos] -- change per ordering.
    """
    encrypt_map = compute_column_mapping(width, ordering)

    # Build constraints: (carter_relative_pos, required_value)
    constraints = []
    for i in range(N_CRIBS):
        crib_pos = CRIB_POSITIONS_SORTED[i]
        pt_val = CRIB_PT_VALS[i]
        inter_pos = encrypt_map[crib_pos]
        ct_val = CT_IDX[inter_pos]
        if variant == 'vig':
            req = (ct_val - pt_val) % 26
        else:  # beau
            req = (ct_val + pt_val) % 26
        constraints.append((inter_pos, req))

    # Pick first 2 constraints for pair index
    pos_a, val_a = constraints[0]
    pos_b, val_b = constraints[1]

    # Build pair index for these positions
    pair_idx = build_pair_index(carter_idx, pos_a, pos_b, max_offset)

    # Look up offsets matching first 2 constraints
    candidate_offsets = pair_idx.get((val_a, val_b), [])

    # Check remaining constraints
    remaining = constraints[2:]

    best_matches = 0
    best_offset = -1
    hits = []

    for off in candidate_offsets:
        matches = 2  # first 2 already match
        for c_pos, c_req in remaining:
            if carter_idx[off + c_pos] == c_req:
                matches += 1

        if matches > best_matches:
            best_matches = matches
            best_offset = off
        if matches >= 10:
            hits.append((off, matches))

    return best_matches, best_offset, hits, len(candidate_offsets)


def search_d2_with_index(ordering, carter_idx, max_offset, width, variant, pair_idx, pos_a, pos_b):
    """D2: CT = Trans(RunKey(PT, Carter))

    At crib position k: CT[encrypt_map[k]] = (PT[k] + Carter[off + k]) mod 26 [vig]
    Required: Carter[off + k] = (CT[encrypt_map[k]] - PT[k]) mod 26 [vig]
    Required: Carter[off + k] = (CT[encrypt_map[k]] + PT[k]) mod 26 [beau]

    Carter relative positions are always the crib positions (k) -- SAME for all orderings!
    Only required values change because CT[encrypt_map[k]] depends on ordering.
    So pair_idx is REUSED across orderings. Only need to change the lookup key.
    """
    encrypt_map = compute_column_mapping(width, ordering)

    # Build constraints: (crib_pos, required_value)
    constraints = []
    for i in range(N_CRIBS):
        crib_pos = CRIB_POSITIONS_SORTED[i]
        pt_val = CRIB_PT_VALS[i]
        ct_at_mapped = CT_IDX[encrypt_map[crib_pos]]
        if variant == 'vig':
            req = (ct_at_mapped - pt_val) % 26
        else:  # beau
            req = (ct_at_mapped + pt_val) % 26
        constraints.append((crib_pos, req))

    # First 2 constraints use pos_a, pos_b (the fixed crib positions for D2)
    val_a = constraints[0][1]
    val_b = constraints[1][1]

    candidate_offsets = pair_idx.get((val_a, val_b), [])

    remaining = constraints[2:]

    best_matches = 0
    best_offset = -1
    hits = []

    for off in candidate_offsets:
        matches = 2
        for c_pos, c_req in remaining:
            if carter_idx[off + c_pos] == c_req:
                matches += 1

        if matches > best_matches:
            best_matches = matches
            best_offset = off
        if matches >= 10:
            hits.append((off, matches))

    return best_matches, best_offset, hits, len(candidate_offsets)


def full_decrypt(ordering, carter_idx, offset, width, direction, variant):
    """Full decryption given parameters."""
    encrypt_map = compute_column_mapping(width, ordering)
    decrypt_map = [0] * N
    for i in range(N):
        decrypt_map[encrypt_map[i]] = i

    if direction == 1:
        # D1: CT = RunKey(Trans(PT))
        # INTER[i] = CT[i] op_inv Carter[off+i]
        # PT = undo_trans(INTER)
        if variant == 'vig':
            inter = [(CT_IDX[i] - carter_idx[offset + i]) % 26 for i in range(N)]
        else:
            inter = [(carter_idx[offset + i] - CT_IDX[i]) % 26 for i in range(N)]
        pt = [0] * N
        for j in range(N):
            pt[decrypt_map[j]] = inter[j]
    else:
        # D2: CT = Trans(RunKey(PT))
        # INTER = undo_trans(CT), PT[i] = INTER[i] op_inv Carter[off+i]
        inter = [0] * N
        for j in range(N):
            inter[decrypt_map[j]] = CT_IDX[j]
        if variant == 'vig':
            pt = [(inter[i] - carter_idx[offset + i]) % 26 for i in range(N)]
        else:
            pt = [(carter_idx[offset + i] - inter[i]) % 26 for i in range(N)]

    return ''.join(ALPH[x] for x in pt)


def run_width(width, carter_name, carter_idx):
    """Run all orderings for a given width."""
    n_perms = 1
    for i in range(1, width + 1):
        n_perms *= i

    max_offset = len(carter_idx) - N
    if max_offset <= 0:
        print(f"  Carter text too short for width {width}", flush=True)
        return None

    print(f"\n  Width {width}: {n_perms} orderings x {max_offset} offsets x 2 dirs x 2 variants", flush=True)
    print(f"  Total configs: {n_perms * 2 * 2:,}", flush=True)

    # Pre-build D2 pair indices (reusable across all orderings)
    # D2 always uses crib positions 21 and 22 as the first two constraints
    d2_pos_a = CRIB_POSITIONS_SORTED[0]  # 21
    d2_pos_b = CRIB_POSITIONS_SORTED[1]  # 22

    print(f"  Building D2 pair indices (pos {d2_pos_a}, {d2_pos_b})...", flush=True)
    t_idx = time.time()
    d2_pair_idx = build_pair_index(carter_idx, d2_pos_a, d2_pos_b, max_offset)
    print(f"  D2 pair index built in {time.time() - t_idx:.1f}s ({len(d2_pair_idx)} unique pairs)", flush=True)

    # Stats
    total_d2_candidates = sum(len(v) for v in d2_pair_idx.values())
    avg_per_key = total_d2_candidates / max(len(d2_pair_idx), 1)
    print(f"  D2 avg offsets per pair: {avg_per_key:.1f} (expected ~{max_offset/676:.1f})", flush=True)

    t0 = time.time()
    best_score = 0
    best_config = None
    all_hits = []
    n_done = 0
    total_candidates_checked = 0

    for ordering in permutations(range(width)):
        ordering = list(ordering)

        for variant in ('vig', 'beau'):
            # D1: positions change per ordering, must build pair index each time
            bm, bo, h, nc = search_d1_paired(ordering, carter_idx, max_offset, width, variant)
            total_candidates_checked += nc
            if bm > best_score:
                best_score = bm
                best_config = {'dir': 1, 'ordering': ordering[:], 'offset': bo,
                               'matches': bm, 'variant': variant, 'width': width}
            for off, m in h:
                all_hits.append({'dir': 1, 'ordering': ordering[:], 'offset': off,
                                 'matches': m, 'variant': variant, 'width': width})

            # D2: reuse pair index
            bm, bo, h, nc = search_d2_with_index(ordering, carter_idx, max_offset, width,
                                                   variant, d2_pair_idx, d2_pos_a, d2_pos_b)
            total_candidates_checked += nc
            if bm > best_score:
                best_score = bm
                best_config = {'dir': 2, 'ordering': ordering[:], 'offset': bo,
                               'matches': bm, 'variant': variant, 'width': width}
            for off, m in h:
                all_hits.append({'dir': 2, 'ordering': ordering[:], 'offset': off,
                                 'matches': m, 'variant': variant, 'width': width})

        n_done += 1
        if n_done % max(n_perms // 10, 1) == 0 or n_done == n_perms:
            elapsed = time.time() - t0
            rate = n_done / elapsed if elapsed > 0 else 0
            print(f"    {n_done}/{n_perms} orderings: best={best_score}/24 "
                  f"hits(>=10)={len(all_hits)} ({rate:.0f} ord/s) [{elapsed:.1f}s]", flush=True)

    elapsed = time.time() - t0

    # Decrypt best and top hits
    if best_config:
        best_config['pt'] = full_decrypt(best_config['ordering'], carter_idx,
                                          best_config['offset'], width,
                                          best_config['dir'], best_config['variant'])

    all_hits.sort(key=lambda x: -x['matches'])
    top_hits = all_hits[:20]
    for h in top_hits:
        h['pt'] = full_decrypt(h['ordering'], carter_idx, h['offset'],
                                width, h['dir'], h['variant'])

    result = {
        'width': width,
        'carter_version': carter_name,
        'n_orderings': n_perms,
        'max_offset': max_offset,
        'total_configs': n_perms * 2 * 2,
        'total_candidates_checked': total_candidates_checked,
        'best_score': best_score,
        'best_config': best_config,
        'hits_ge10': len(all_hits),
        'top_hits': top_hits,
        'time_seconds': round(elapsed, 1),
    }

    print(f"  Width {width} done: best={best_score}/24 hits(>=10)={len(all_hits)} "
          f"candidates={total_candidates_checked:,} [{elapsed:.1f}s]", flush=True)

    return result


def main():
    print("=" * 72, flush=True)
    print("E-CARTER-TRANS-OPT-01: Pair-Index Carter + Columnar Transposition", flush=True)
    print("=" * 72, flush=True)

    # Load Carter text (canonical allowlist path)
    carter_path = os.path.join(_ROOT, "reference", "carter_vol1.txt")
    print(f"Loading Carter text from {carter_path}...", flush=True)
    carter_idx = load_carter(carter_path)
    carter_name = "Carter_Tomb"
    print(f"  {carter_name}: {len(carter_idx)} alpha chars", flush=True)

    max_offset = len(carter_idx) - N
    print(f"  Max offset: {max_offset}", flush=True)

    t0_global = time.time()
    all_results = {
        'experiment': 'E-CARTER-TRANS-OPT-01',
        'description': 'Pair-index optimized Carter + columnar transposition + running key',
        'carter_file': 'reference/Carter_Tomb.txt',
        'carter_chars': len(carter_idx),
        'ct': CT,
        'cribs': {str(k): v for k, v in CRIB_DICT.items()},
        'widths': {},
    }

    overall_best = 0
    overall_best_config = None

    # Test widths in priority order: 7, 5, 6, 8
    # Width 9 = 362880 perms -- try if time permits
    for width in [7, 5, 6, 8]:
        print(f"\n{'='*60}", flush=True)
        print(f"WIDTH {width}", flush=True)
        print(f"{'='*60}", flush=True)

        result = run_width(width, carter_name, carter_idx)
        if result:
            all_results['widths'][str(width)] = result
            if result['best_score'] > overall_best:
                overall_best = result['best_score']
                overall_best_config = result['best_config']

    # Try width 9 if total time so far is under 10 minutes
    elapsed_so_far = time.time() - t0_global
    if elapsed_so_far < 600:
        print(f"\n{'='*60}", flush=True)
        print(f"WIDTH 9 (elapsed so far: {elapsed_so_far:.0f}s, attempting...)", flush=True)
        print(f"{'='*60}", flush=True)
        result = run_width(9, carter_name, carter_idx)
        if result:
            all_results['widths']['9'] = result
            if result['best_score'] > overall_best:
                overall_best = result['best_score']
                overall_best_config = result['best_config']
    else:
        print(f"\nSkipping width 9 (elapsed {elapsed_so_far:.0f}s > 600s)", flush=True)

    elapsed_total = time.time() - t0_global

    # Verdict
    if overall_best >= 18:
        verdict = "SIGNAL -- investigate immediately"
    elif overall_best >= 10:
        verdict = "INTERESTING -- above expected random max, worth logging"
    else:
        verdict = "NOISE -- Carter + columnar transposition + running key eliminated for widths 5-8"

    # Expected random max: for N configs, expected max matches ~ log(N)/log(26) + 1
    # Width 7: 5040 * 287K * 4 = ~5.8B configs. E[max] ~ 7-8/24

    all_results['overall_best'] = overall_best
    all_results['overall_best_config'] = overall_best_config
    all_results['verdict'] = verdict
    all_results['elapsed_seconds'] = round(elapsed_total, 1)

    print(f"\n{'='*72}", flush=True)
    print(f"SUMMARY", flush=True)
    print(f"{'='*72}", flush=True)
    for w, r in sorted(all_results['widths'].items(), key=lambda x: int(x[0])):
        print(f"  Width {w}: best={r['best_score']}/24 hits(>=10)={r['hits_ge10']} "
              f"configs={r['total_configs']:,} [{r['time_seconds']}s]", flush=True)
    print(f"\n  Overall best: {overall_best}/24", flush=True)
    if overall_best_config:
        cfg = overall_best_config
        print(f"  Config: width={cfg['width']} dir=D{cfg['dir']} variant={cfg['variant']} "
              f"ordering={cfg['ordering']} offset={cfg['offset']}", flush=True)
        print(f"  PT: {cfg.get('pt', 'N/A')}", flush=True)
    print(f"  Verdict: {verdict}", flush=True)
    print(f"  Total time: {elapsed_total:.1f}s", flush=True)

    os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
    outpath = os.path.join(_ROOT, "results", "e_carter_transposition_optimized_01.json")
    with open(outpath, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"  Artifact: {outpath}", flush=True)
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/running_key/e_carter_transposition_optimized_01.py", flush=True)


if __name__ == "__main__":
    main()
