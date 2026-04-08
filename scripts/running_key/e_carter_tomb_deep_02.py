#!/usr/bin/env python3
"""
Cipher: running_key + transposition + mixed_alphabet
Family: running_key
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""
E-CARTER-TOMB-DEEP-02: Carter Running Key with Intervening Layers

Tests four models combining Carter's "Tomb of Tut-Ankh-Amen" Vol 1
as a running key with:
  A) Columnar transposition + AZ alphabet (direction D2: CT = Trans(RK(PT)))
  B) KA mixed alphabet, no transposition
  C) KA mixed alphabet + columnar transposition
  D) AZ alphabet + transposition (direction D1: CT = RK(Trans(PT)))

For each model, tests Vigenere and Beaufort variants across all Carter offsets.

Transposition widths: {5,6,7,8,9,10,11,12,13}
  - Width 7: all 5040 permutations (highest priority)
  - Widths 5-9: all permutations
  - Widths 10-13: too many permutations (>3.6M), skipped

KA alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ

Output: results/e_carter_tomb_deep_02.json
Repro: PYTHONPATH=src python3 -u scripts/running_key/e_carter_tomb_deep_02.py
"""

import json
import sys
import os
import re
import time
import math
from itertools import permutations
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX, MOD
from kryptos.kernel.alphabet import KA

# Corpus policy declaration — this script consumes Carter Vol 1 as a
# running key, which is on the default allowlist as `carter_tomb_vol1`.
# See src/kryptos/admissibility/corpus_policy.py::DEFAULT_ALLOWLIST and
# docs/admissibility_architecture.md.
SOURCE_ID = "carter_tomb_vol1"

# ── Constants ──────────────────────────────────────────────────────────────
N = CT_LEN  # 97
CT_AZ = [ALPH_IDX[c] for c in CT]

# KA alphabet indexing
KA_SEQ = KA.sequence  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {}
for i, ch in enumerate(KA_SEQ):
    KA_IDX[ch] = i
CT_KA = [KA_IDX[c] for c in CT]

CRIB_LIST = sorted(CRIB_DICT.items())  # [(pos, char), ...]
N_CRIBS = len(CRIB_LIST)
CRIB_AZ = {pos: ALPH_IDX[ch] for pos, ch in CRIB_LIST}
CRIB_KA = {pos: KA_IDX[ch] for pos, ch in CRIB_LIST}

print(f"KA alphabet: {KA_SEQ}", flush=True)
print(f"CT length: {N}", flush=True)
print(f"Cribs: {N_CRIBS} positions", flush=True)


# ── Load Carter text ───────────────────────────────────────────────────────
def load_text(path):
    with open(path) as f:
        raw = f.read()
    clean = re.sub(r'[^A-Za-z]', '', raw).upper()
    az = [ALPH_IDX[c] for c in clean]
    ka = [KA_IDX[c] for c in clean]
    return clean, az, ka

print("Loading carter_vol1.txt (canonical allowlist path)...", flush=True)
CARTER_PATH = os.path.join(_ROOT, "reference", "carter_vol1.txt")
carter_str, carter_az, carter_ka = load_text(CARTER_PATH)
CARTER_LEN = len(carter_az)
print(f"  Carter text: {CARTER_LEN} alpha chars", flush=True)

MAX_OFFSET = CARTER_LEN - N


# ── Columnar transposition ─────────────────────────────────────────────────
def compute_column_mapping(width, ordering):
    """Returns encrypt_map, decrypt_map for columnar transposition.
    encrypt_map[i] = j means PT written at row-position i goes to CT position j.
    """
    n = N
    n_full_rows = n // width
    n_extra = n % width

    col_lengths = [n_full_rows + (1 if c < n_extra else 0) for c in range(width)]

    col_start = [0] * width
    pos = 0
    for k in range(width):
        orig_col = ordering[k]
        col_start[orig_col] = pos
        pos += col_lengths[orig_col]

    encrypt_map = [0] * n
    col_offset = [0] * width
    pt_pos = 0
    for row in range(n_full_rows + (1 if n_extra > 0 else 0)):
        for col in range(width):
            if row < col_lengths[col]:
                inter_pos = col_start[col] + col_offset[col]
                encrypt_map[pt_pos] = inter_pos
                col_offset[col] += 1
                pt_pos += 1

    decrypt_map = [0] * n
    for i in range(n):
        decrypt_map[encrypt_map[i]] = i

    return encrypt_map, decrypt_map


def full_decrypt(cfg, ct_idx, carter_idx, alph_seq):
    """Full decrypt given a config dict."""
    width = cfg['width']
    ordering = cfg['ordering']
    offset = cfg['offset']
    variant = cfg['variant']
    direction = cfg['dir']

    encrypt_map, decrypt_map = compute_column_mapping(width, ordering)

    if direction == 'D1':
        # CT = RK(Trans(PT))
        # INTER[j] = decrypt(CT[j], Carter[offset+j])
        inter = [0] * N
        for j in range(N):
            if variant == 'vig':
                inter[j] = (ct_idx[j] - carter_idx[offset + j]) % 26
            else:
                inter[j] = (carter_idx[offset + j] - ct_idx[j]) % 26
        # PT = inv_transpose(INTER)
        pt = [0] * N
        for j in range(N):
            pt[decrypt_map[j]] = inter[j]
        return ''.join(alph_seq[v % 26] for v in pt)
    else:  # D2
        # CT = Trans(RK(PT))
        # INTER = inv_transpose(CT)
        inter = [0] * N
        for j in range(N):
            inter[decrypt_map[j]] = ct_idx[j]
        # PT[i] = decrypt(INTER[i], Carter[offset+i])
        pt = [0] * N
        for i in range(N):
            if variant == 'vig':
                pt[i] = (inter[i] - carter_idx[offset + i]) % 26
            else:
                pt[i] = (carter_idx[offset + i] - inter[i]) % 26
        return ''.join(alph_seq[v % 26] for v in pt)


# ── Fast offset scanner with pair-index ────────────────────────────────────
def build_pair_index(arr, pos0, pos1, max_off):
    """Build dict: (arr[off+pos0], arr[off+pos1]) -> [off, ...] for off in range(max_off)."""
    idx = defaultdict(list)
    for off in range(max_off):
        key = (arr[off + pos0], arr[off + pos1])
        idx[key].append(off)
    return idx


def scan_constraints_fast(carter_idx, constraints, pair_idx, threshold=10):
    """Scan offsets using pair index for fast filtering.

    constraints: list of (carter_relative_pos, required_value) for all 24 cribs.
    pair_idx: prebuilt on first two constraint positions.

    Returns (best_score, best_offset, hits_list).
    """
    if len(constraints) < 2:
        return 0, -1, []

    c0_pos, c0_req = constraints[0]
    c1_pos, c1_req = constraints[1]
    rest = constraints[2:]

    candidates = pair_idx.get((c0_req, c1_req), [])

    best = 0
    best_off = -1
    hits = []

    for off in candidates:
        # Already matched 2
        matches = 2
        for cpos, creq in rest:
            if carter_idx[off + cpos] == creq:
                matches += 1
        if matches > best:
            best = matches
            best_off = off
        if matches >= threshold:
            hits.append((off, matches))

    return best, best_off, hits


def scan_constraints_brute(carter_idx, constraints, max_offset, threshold=10):
    """Brute-force scan all offsets. For cases where pair index isn't built."""
    best = 0
    best_off = -1
    hits = []

    for off in range(max_offset):
        matches = 0
        for cpos, creq in constraints:
            if carter_idx[off + cpos] == creq:
                matches += 1
        if matches > best:
            best = matches
            best_off = off
        if matches >= threshold:
            hits.append((off, matches))

    return best, best_off, hits


# ══════════════════════════════════════════════════════════════════════════
# TEST B: Carter + KA Mixed Alphabet (no transposition)
# ══════════════════════════════════════════════════════════════════════════
def test_b_ka_running_key():
    """Direct running key with KA alphabet. No transposition."""
    print("\n" + "=" * 70)
    print("TEST B: Carter + KA Mixed Alphabet (no transposition)")
    print("=" * 70)
    t0 = time.time()

    results_b = {'test': 'B', 'description': 'Carter + KA mixed alphabet (no transposition)'}

    for variant in ['vig', 'beau']:
        # Compute required carter KA values at each crib position
        constraints = []
        for pos, ch in CRIB_LIST:
            ct_val = CT_KA[pos]
            pt_val = KA_IDX[ch]
            if variant == 'vig':
                req = (ct_val - pt_val) % 26
            else:  # beaufort
                req = (ct_val + pt_val) % 26
            constraints.append((pos, req))

        best, best_off, hits = scan_constraints_brute(
            carter_ka, constraints, MAX_OFFSET, threshold=10)

        elapsed = time.time() - t0
        print(f"  {variant}: best={best}/24 at offset {best_off}, hits(>=10)={len(hits)} [{elapsed:.1f}s]")

        if best_off >= 0:
            pt_chars = []
            for i in range(N):
                ct_val = CT_KA[i]
                key_val = carter_ka[best_off + i]
                if variant == 'vig':
                    pt_val = (ct_val - key_val) % 26
                else:
                    pt_val = (key_val - ct_val) % 26
                pt_chars.append(KA_SEQ[pt_val])
            pt_str = ''.join(pt_chars)
            print(f"    PT: {pt_str[:60]}...")
        else:
            pt_str = ""

        results_b[f'best_{variant}'] = best
        results_b[f'best_{variant}_offset'] = best_off
        results_b[f'best_{variant}_pt'] = pt_str
        results_b[f'hits_{variant}'] = len(hits)

    results_b['offsets_tested'] = MAX_OFFSET
    results_b['total_configs'] = MAX_OFFSET * 2
    results_b['elapsed'] = round(time.time() - t0, 1)
    results_b['best_score'] = max(results_b.get('best_vig', 0), results_b.get('best_beau', 0))
    return results_b


# ══════════════════════════════════════════════════════════════════════════
# TESTS A/C/D: Carter + Columnar Transposition
# ══════════════════════════════════════════════════════════════════════════
def test_transposition_width(width, use_ka=False):
    """Test all permutations of given width with Carter running key.

    Two directions:
      D1: CT = RunKey(Transpose(PT))
      D2: CT = Transpose(RunKey(PT))
    """
    alph_name = "KA" if use_ka else "AZ"
    ct_idx = CT_KA if use_ka else CT_AZ
    carter_idx = carter_ka if use_ka else carter_az
    crib_vals = CRIB_KA if use_ka else CRIB_AZ
    alph_seq = KA_SEQ if use_ka else ALPH

    n_perms = math.factorial(width)

    # Skip widths with too many permutations
    if n_perms > 400000:
        print(f"\n  Width {width} ({alph_name}): {n_perms:,} perms -- SKIPPING", flush=True)
        return None

    test_name = f"{'C' if use_ka else 'A/D'}"
    print(f"\n{'='*60}")
    print(f"Test {test_name}: width={width} alph={alph_name}: "
          f"{n_perms} orderings x ~{MAX_OFFSET:,} offsets x 2 variants x 2 dirs")
    print(f"{'='*60}")

    t0 = time.time()

    # Build pair indices for D2 direction (crib positions 21 and 22 are first two)
    # D2 constraints use raw crib positions, so pair index on (21, 22) works for all orderings
    # But for D1, mapped positions change per ordering, so we can't pre-build a single pair index.

    # For D2: pair index on positions (21, 22)
    d2_pair_idx = build_pair_index(carter_idx, 21, 22, MAX_OFFSET)

    overall_best = 0
    overall_best_config = None
    total_hits = []
    n_done = 0
    report_interval = max(1, n_perms // 5)

    for ordering in permutations(range(width)):
        ordering = list(ordering)
        encrypt_map, decrypt_map = compute_column_mapping(width, ordering)

        for variant in ['vig', 'beau']:
            # ── D1: CT = RunKey(Transpose(PT)) ──
            # Crib at PT pos p -> INTER pos encrypt_map[p]
            # carter[offset + encrypt_map[p]] must == required
            d1_constraints = []
            for pos, ch in CRIB_LIST:
                mapped = encrypt_map[pos]
                crib_val = crib_vals[pos]
                ct_val = ct_idx[mapped]
                if variant == 'vig':
                    req = (ct_val - crib_val) % 26
                else:
                    req = (crib_val + ct_val) % 26
                d1_constraints.append((mapped, req))

            # Sort by position for pair index
            d1_sorted = sorted(d1_constraints, key=lambda x: x[0])
            p0, r0 = d1_sorted[0]
            p1, r1 = d1_sorted[1]

            # Build a pair index for D1 on the fly is expensive; use brute with early exit
            d1_best = 0
            d1_best_off = -1
            for off in range(MAX_OFFSET):
                if carter_idx[off + p0] != r0:
                    continue
                if carter_idx[off + p1] != r1:
                    continue
                matches = 2
                for cpos, creq in d1_sorted[2:]:
                    if carter_idx[off + cpos] == creq:
                        matches += 1
                if matches > d1_best:
                    d1_best = matches
                    d1_best_off = off
                if matches >= 10:
                    total_hits.append({
                        'dir': 'D1', 'variant': variant, 'width': width,
                        'ordering': ordering[:], 'offset': off,
                        'score': matches, 'alph': alph_name
                    })

            if d1_best > overall_best:
                overall_best = d1_best
                overall_best_config = {
                    'dir': 'D1', 'variant': variant, 'width': width,
                    'ordering': ordering[:], 'offset': d1_best_off,
                    'score': d1_best, 'alph': alph_name
                }

            # ── D2: CT = Transpose(RunKey(PT)) ──
            # INTER = inv_transpose(CT) -- fixed per ordering
            inter_d2 = [0] * N
            for j in range(N):
                inter_d2[decrypt_map[j]] = ct_idx[j]

            d2_constraints = []
            for pos, ch in CRIB_LIST:
                crib_val = crib_vals[pos]
                if variant == 'vig':
                    req = (inter_d2[pos] - crib_val) % 26
                else:
                    req = (crib_val + inter_d2[pos]) % 26
                d2_constraints.append((pos, req))

            # Use pair index on positions 21, 22
            d2_req_21 = d2_constraints[0][1]  # crib_list sorted, first is pos 21
            d2_req_22 = d2_constraints[1][1]  # second is pos 22

            d2_best, d2_best_off, d2_hits = scan_constraints_fast(
                carter_idx, d2_constraints, d2_pair_idx, threshold=10)

            for off, score in d2_hits:
                total_hits.append({
                    'dir': 'D2', 'variant': variant, 'width': width,
                    'ordering': ordering[:], 'offset': off,
                    'score': score, 'alph': alph_name
                })

            if d2_best > overall_best:
                overall_best = d2_best
                overall_best_config = {
                    'dir': 'D2', 'variant': variant, 'width': width,
                    'ordering': ordering[:], 'offset': d2_best_off,
                    'score': d2_best, 'alph': alph_name
                }

        n_done += 1
        if n_done % report_interval == 0:
            elapsed = time.time() - t0
            rate = n_done / elapsed if elapsed > 0 else 0
            print(f"  {n_done}/{n_perms}: best={overall_best}/24 "
                  f"hits(>=10)={len(total_hits)} ({rate:.1f} ord/s) [{elapsed:.0f}s]",
                  flush=True)

    elapsed = time.time() - t0
    print(f"  Done: best={overall_best}/24 hits(>=10)={len(total_hits)} [{elapsed:.1f}s]")

    if overall_best_config:
        cfg = overall_best_config
        pt_str = full_decrypt(cfg, ct_idx, carter_idx, alph_seq)
        print(f"  Best: dir={cfg['dir']} {cfg['variant']} ordering={cfg['ordering']} "
              f"offset={cfg['offset']} score={cfg['score']}/24")
        print(f"  PT: {pt_str[:60]}...")
        cfg['pt'] = pt_str

    return {
        'test': test_name,
        'width': width,
        'alphabet': alph_name,
        'orderings_tested': n_perms,
        'offsets_per_ordering': MAX_OFFSET,
        'total_configs': n_perms * MAX_OFFSET * 2 * 2,
        'best_score': overall_best,
        'best_config': overall_best_config,
        'hits_ge10': len(total_hits),
        'top_hits': sorted(total_hits, key=lambda x: -x['score'])[:10],
        'elapsed': round(elapsed, 1),
    }


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
def main():
    print("=" * 70)
    print("E-CARTER-TOMB-DEEP-02: Carter Running Key with Intervening Layers")
    print("=" * 70)
    print(f"Carter text: {CARTER_LEN} alpha chars, max offset: {MAX_OFFSET}")
    print(f"Ciphertext: {CT[:40]}... ({N} chars)")

    t0_global = time.time()
    all_results = {
        'experiment': 'E-CARTER-TOMB-DEEP-02',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'ciphertext': CT,
        'carter_chars': CARTER_LEN,
        'max_offset': MAX_OFFSET,
        'tests': [],
    }

    # ── Test B: KA alphabet, no transposition ──────────────────────────
    result_b = test_b_ka_running_key()
    all_results['tests'].append(result_b)

    # ── Tests A/D: AZ alphabet + columnar transposition ────────────────
    print("\n" + "#" * 70)
    print("# TESTS A/D: AZ alphabet + columnar transposition")
    print("#" * 70)
    for width in [7, 5, 6, 8]:
        result = test_transposition_width(width, use_ka=False)
        if result is not None:
            all_results['tests'].append(result)

    # ── Test C: KA alphabet + columnar transposition ───────────────────
    print("\n" + "#" * 70)
    print("# TEST C: KA alphabet + columnar transposition")
    print("#" * 70)
    for width in [7, 5, 6, 8]:
        result = test_transposition_width(width, use_ka=True)
        if result is not None:
            all_results['tests'].append(result)

    elapsed_total = time.time() - t0_global

    # ── Summary ────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"FULL SUMMARY")
    print(f"{'='*70}")

    overall_best = 0
    total_configs = 0

    for t in all_results['tests']:
        test_label = t.get('test', '?')
        width = t.get('width', 'N/A')
        alph = t.get('alphabet', 'N/A')
        best = t.get('best_score', 0)
        hits = t.get('hits_ge10', 0)
        configs = t.get('total_configs', 0)
        elapsed = t.get('elapsed', 0)

        print(f"  Test {test_label:4s} w={str(width):3s} alph={alph:2s}: "
              f"best={best:2d}/24 hits(>=10)={hits:4d} configs={configs:>14,} [{elapsed:.1f}s]")

        overall_best = max(overall_best, best)
        total_configs += configs

    if overall_best >= 18:
        verdict = "SIGNAL"
    elif overall_best >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    all_results['overall_best'] = overall_best
    all_results['verdict'] = verdict
    all_results['total_configs'] = total_configs
    all_results['elapsed_seconds'] = round(elapsed_total, 1)

    print(f"\n  OVERALL BEST: {overall_best}/24")
    print(f"  TOTAL CONFIGS: {total_configs:,}")
    print(f"  VERDICT: {verdict}")
    print(f"  TIME: {elapsed_total:.1f}s ({elapsed_total/60:.1f} min)")

    # Save
    os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
    outpath = os.path.join(_ROOT, "results", "e_carter_tomb_deep_02.json")
    with open(outpath, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n  Artifact: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/running_key/e_carter_tomb_deep_02.py")


if __name__ == "__main__":
    main()
