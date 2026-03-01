#!/usr/bin/env python3
"""
E-EGYPT-01: Egypt Corpus x Columnar Transposition Sweep

Tests the running-key + columnar-transposition model:
  CT[sigma(j)] = Enc(PT[j], Source[j + offset])

where sigma is a columnar transposition of width 5-11.

Sweeps all w! column orderings x 3 cipher variants (Vigenere, Beaufort,
Variant Beaufort) x 9 Egyptological corpus variants, with Bean pre-filtering
and triple-index acceleration.

Search space: ~44M permutations (widths 5-11), ~1.6M after Bean-EQ filtering.
With 3 variants x 9 corpora = ~42.7M equivalent configurations.

Algorithm:
  1. For each width, enumerate all column orderings
  2. Bean-EQ pre-filter (variant-independent): CT[sigma(27)] == CT[sigma(65)]
  3. For each surviving perm x variant, compute 24 required source values
  4. Bean-INEQ check (21 pairs) on required values
  5. Triple-index lookup: (req[21], req[22], req[23]) -> candidate offsets
  6. Verify remaining ENE (positions 24-33) + BC (positions 63-73)
  7. Any 24/24 = BREAKTHROUGH. Any 18+/24 = SIGNAL.

Output: results/e_egypt_01_columnar_sweep.json
Repro:  PYTHONPATH=src python3 -u scripts/e_egypt_01_columnar_sweep.py
"""

import json
import os
import sys
import time
import array
from collections import defaultdict, deque
from itertools import permutations, islice
from math import factorial
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

# ── Constants ──────────────────────────────────────────────────────────
N = CT_LEN  # 97
CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())  # 24 positions (21-33, 63-73)
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
ENE_RANGE = list(range(21, 34))  # 13 positions
BC_RANGE = list(range(63, 74))   # 11 positions

# Variant encoding: (name, ct_sign, pt_sign)
# Required source value = (ct_sign * CT_val + pt_sign * PT_val) % 26
VARIANTS = [
    ("vig",      1, -1),  # Source = (CT - PT) % 26
    ("beau",     1,  1),  # Source = (CT + PT) % 26
    ("var_beau", -1,  1), # Source = (PT - CT) % 26
]

BEAN_EQ_A, BEAN_EQ_B = BEAN_EQ[0]  # (27, 65)
CORPUS_DIR = "results/egypt_corpus/testing"
N_WORKERS = min(28, cpu_count() or 28)
WIDTHS = list(range(5, 12))  # 5 through 11

# ── Globals (populated before fork, shared via COW) ────────────────────
_corpora = []          # [(name, bytes_obj), ...]
_triple_indices = []   # [dict((int,int,int) -> array.array('I')), ...]


def load_corpora():
    """Load 9 corpus files and build triple indices for fast lookups."""
    global _corpora, _triple_indices

    fnames = sorted(f for f in os.listdir(CORPUS_DIR) if f.endswith('.txt'))
    print(f"Loading {len(fnames)} corpus variants from {CORPUS_DIR}")

    for fname in fnames:
        name = fname.replace('.txt', '')
        path = os.path.join(CORPUS_DIR, fname)
        with open(path) as f:
            text = f.read().strip()
        # Store as bytes for memory efficiency (1 byte/char vs 28 for Python int)
        nums = bytes(ord(c) - ord('A') for c in text if c.isalpha())
        _corpora.append((name, nums))

        max_off = len(nums) - 74
        if max_off < 0:
            _triple_indices.append({})
            print(f"  {name}: {len(nums):,} chars -- TOO SHORT, skipped")
            continue

        # Build triple index: (nums[21+off], nums[22+off], nums[23+off]) -> offsets
        idx = defaultdict(lambda: array.array('I'))
        for off in range(max_off + 1):
            p = 21 + off
            key = (nums[p], nums[p + 1], nums[p + 2])
            idx[key].append(off)

        # Convert to regular dict (lambda can't survive pickle)
        idx = dict(idx)
        _triple_indices.append(idx)

        avg_bucket = (max_off + 1) / max(1, len(idx))
        print(f"  {name}: {len(nums):,} chars, {max_off + 1:,} offsets, "
              f"{len(idx):,} triple keys (avg {avg_bucket:.0f}/key)")


def self_test():
    """Verify columnar permutation logic and Bean-EQ invariants."""
    print("Running self-tests...")

    for width in WIDTHS:
        n_rows = (N + width - 1) // width
        n_long = N % width or width

        for col_order in [tuple(range(width)), tuple(range(width - 1, -1, -1))]:
            col_offsets = [0] * width
            pos = 0
            for c in col_order:
                col_offsets[c] = pos
                pos += n_rows if c < n_long else n_rows - 1
            assert pos == N, f"Width {width}: total positions {pos} != {N}"

            sigma = [col_offsets[j % width] + j // width for j in range(N)]
            assert sorted(sigma) == list(range(N)), \
                f"Width {width}, order {col_order}: sigma not a bijection"
    print("  Bijection check: PASS (all widths, forward + reverse orderings)")

    # Verify Bean-EQ positions: both map to 'R' in plaintext, 'P' in ciphertext
    assert BEAN_EQ_A == 27 and BEAN_EQ_B == 65
    assert CRIB_DICT[27] == 'R' and CRIB_DICT[65] == 'R'
    assert CT[27] == 'P' and CT[65] == 'P'
    print("  Bean-EQ invariant: PASS (pos 27,65 both PT=R, CT=P)")

    # Verify all Bean-INEQ pairs are within crib positions
    for a, b in BEAN_INEQ:
        assert a in CRIB_DICT and b in CRIB_DICT, \
            f"Bean-INEQ pair ({a},{b}) not in crib positions"
    print(f"  Bean-INEQ: PASS (all 21 pairs within crib range)")

    # Verify known sigma value: width 7, identity order
    # Position 27: col=27%7=6, row=27//7=3
    # n_rows=14, n_long=6 (97%7=6), so cols 0-5 have 14 rows, col 6 has 13
    # Identity order col_offsets = [0, 14, 28, 42, 56, 70, 84]
    width = 7
    n_rows_7 = 14
    expected_offsets = [0, 14, 28, 42, 56, 70, 84]
    col_offsets = [0] * 7
    pos = 0
    for c in range(7):
        col_offsets[c] = pos
        pos += n_rows_7 if c < 6 else 13
    assert col_offsets == expected_offsets, f"Got {col_offsets}"
    assert col_offsets[27 % 7] + 27 // 7 == 84 + 3  # sigma[27] = 87
    assert col_offsets[65 % 7] + 65 // 7 == 28 + 9   # sigma[65] = 37
    # CT[87] and CT[37]: check they're different (Bean-EQ should reject this perm)
    assert CT_NUM[87] != CT_NUM[37], "Expected Bean-EQ rejection for w7 identity"
    print("  Width-7 identity ordering: PASS (Bean-EQ correctly rejects)")
    print()


def worker(args):
    """Process a chunk of permutations for a given width.

    Returns (hits_list, stats_dict).
    """
    width, chunk_id, n_chunks = args

    total_perms = factorial(width)
    chunk_size = (total_perms + n_chunks - 1) // n_chunks
    start = chunk_id * chunk_size
    end = min(start + chunk_size, total_perms)
    n_my_perms = end - start
    if n_my_perms <= 0:
        return [], {'perms_tested': 0, 'bean_eq_pass': 0,
                    'bean_ineq_pass': 0, 'scans': 0}

    # Grid parameters
    n_rows = (N + width - 1) // width
    n_long = N % width or width

    # Bean-EQ positions (column, row)
    eq_a_col = BEAN_EQ_A % width
    eq_a_row = BEAN_EQ_A // width
    eq_b_col = BEAN_EQ_B % width
    eq_b_row = BEAN_EQ_B // width

    # Precompute crib (col, row) pairs, ordered by CRIB_POS
    crib_col_row = [(j % width, j // width) for j in CRIB_POS]

    # Bean-INEQ as index pairs into the req[] array (indexed 0..23)
    crib_pos_to_idx = {pos: i for i, pos in enumerate(CRIB_POS)}
    bean_ineq_idx = [(crib_pos_to_idx[a], crib_pos_to_idx[b])
                     for a, b in BEAN_INEQ]

    # Pre-extract crib PT values in CRIB_POS order
    crib_pt = [CRIB_PT_NUM[j] for j in CRIB_POS]

    # Local refs for speed
    ct_num = CT_NUM
    corpora = _corpora
    tri_indices = _triple_indices
    n_corpora = len(corpora)
    variants = VARIANTS

    hits = []
    stats = {'perms_tested': 0, 'bean_eq_pass': 0,
             'bean_ineq_pass': 0, 'scans': 0}

    # Skip to our chunk
    gen = permutations(range(width))
    if start > 0:
        deque(islice(gen, start), maxlen=0)

    for perm_tuple in islice(gen, n_my_perms):
        stats['perms_tested'] += 1

        # Compute column start offsets
        col_offsets = [0] * width
        pos = 0
        for c in perm_tuple:
            col_offsets[c] = pos
            pos += n_rows if c < n_long else n_rows - 1

        # Bean-EQ quick check (variant-independent)
        # CT[sigma(27)] must equal CT[sigma(65)]
        sigma_a = col_offsets[eq_a_col] + eq_a_row
        sigma_b = col_offsets[eq_b_col] + eq_b_row
        if ct_num[sigma_a] != ct_num[sigma_b]:
            continue
        stats['bean_eq_pass'] += 1

        # Compute CT values at sigma(crib positions)
        ct_at_crib = [ct_num[col_offsets[c] + r] for c, r in crib_col_row]

        for var_name, sc, sp in variants:
            # Compute required source values for all 24 crib positions
            req = [(sc * ct_at_crib[i] + sp * crib_pt[i]) % 26
                   for i in range(24)]

            # Bean-INEQ check: all 21 pairs must have unequal required values
            bean_ok = True
            for ai, bi in bean_ineq_idx:
                if req[ai] == req[bi]:
                    bean_ok = False
                    break
            if not bean_ok:
                continue
            stats['bean_ineq_pass'] += 1

            # ENE required values (indices 0-12 = positions 21-33)
            # BC required values (indices 13-23 = positions 63-73)
            triple_key = (req[0], req[1], req[2])

            # Pre-extract for inner loop unrolling (ENE positions 24-26)
            re3, re4, re5 = req[3], req[4], req[5]
            # Remaining ENE: req[6] through req[12] (positions 27-33)
            req_ene_tail = req[6:13]
            # BC: req[13] through req[23] (positions 63-73)
            req_bc = req[13:]

            for ci in range(n_corpora):
                stats['scans'] += 1
                candidates = tri_indices[ci].get(triple_key)
                if candidates is None:
                    continue

                cn = corpora[ci][1]  # bytes object

                for off in candidates:
                    # Verify remaining ENE positions (24-33)
                    # Positions 24, 25, 26 unrolled for speed
                    p = 24 + off
                    if cn[p] != re3:
                        continue
                    if cn[p + 1] != re4:
                        continue
                    if cn[p + 2] != re5:
                        continue
                    # Positions 27-33 (7 more checks)
                    ene_ok = True
                    base = 27 + off
                    for k in range(7):
                        if cn[base + k] != req_ene_tail[k]:
                            ene_ok = False
                            break
                    if not ene_ok:
                        continue

                    # Full ENE match (13/13)! Check BC (positions 63-73)
                    bc_count = 0
                    base_bc = 63 + off
                    for k in range(11):
                        if cn[base_bc + k] == req_bc[k]:
                            bc_count += 1

                    total_score = 13 + bc_count
                    if total_score >= 18:
                        hits.append({
                            'corpus': corpora[ci][0],
                            'width': width,
                            'order': list(perm_tuple),
                            'variant': var_name,
                            'offset': off,
                            'score': total_score,
                            'ene_match': 13,
                            'bc_match': bc_count,
                        })

    return hits, stats


def main():
    print("=" * 70)
    print("E-EGYPT-01: Egypt Corpus x Columnar Transposition Sweep")
    print("=" * 70)
    print(f"Model: CT[sigma(j)] = Enc(PT[j], Source[j + offset])")
    print(f"Widths: {WIDTHS[0]}-{WIDTHS[-1]} (exhaustive)")
    print(f"Variants: vig, beau, var_beau")
    print(f"Workers: {N_WORKERS}")
    print()

    # Load corpora and build triple indices
    t_load = time.time()
    load_corpora()
    load_time = time.time() - t_load
    total_chars = sum(len(c[1]) for c in _corpora)
    print(f"\n  Load + index time: {load_time:.1f}s")
    print(f"  Corpora: {len(_corpora)}, total chars: {total_chars:,}")
    print()

    # Self-tests
    self_test()

    # Compute total search space
    total_configs = sum(factorial(w) * 3 * len(_corpora) for w in WIDTHS)
    total_perms_all = sum(factorial(w) for w in WIDTHS)
    print(f"Total search space: {total_perms_all:,} permutations x 3 variants x "
          f"{len(_corpora)} corpora = {total_configs:,} configs")
    print()

    # Sweep
    t0 = time.time()
    all_hits = []
    grand_stats = {
        'total_perms': 0,
        'total_bean_eq': 0,
        'total_bean_ineq': 0,
        'total_scans': 0,
    }

    pool = Pool(N_WORKERS)

    try:
        for width in WIDTHS:
            tw = time.time()
            n_perms = factorial(width)
            n_chunks = min(N_WORKERS, n_perms)

            print(f"Width {width}: {n_perms:,} permutations, {n_chunks} chunks",
                  flush=True)

            tasks = [(width, i, n_chunks) for i in range(n_chunks)]
            results = pool.map(worker, tasks)

            # Aggregate
            w_hits = []
            w_stats = {'perms_tested': 0, 'bean_eq_pass': 0,
                       'bean_ineq_pass': 0, 'scans': 0}
            for chunk_hits, chunk_stats in results:
                w_hits.extend(chunk_hits)
                for k in w_stats:
                    w_stats[k] += chunk_stats[k]

            all_hits.extend(w_hits)
            grand_stats['total_perms'] += w_stats['perms_tested']
            grand_stats['total_bean_eq'] += w_stats['bean_eq_pass']
            grand_stats['total_bean_ineq'] += w_stats['bean_ineq_pass']
            grand_stats['total_scans'] += w_stats['scans']

            eq_pct = 100 * w_stats['bean_eq_pass'] / max(1, w_stats['perms_tested'])
            # INEQ pass rate: relative to (EQ-pass perms * 3 variants)
            ineq_denom = max(1, w_stats['bean_eq_pass'] * 3)
            ineq_pct = 100 * w_stats['bean_ineq_pass'] / ineq_denom

            elapsed_w = time.time() - tw
            print(f"  Tested: {w_stats['perms_tested']:,} perms")
            print(f"  Bean-EQ pass: {w_stats['bean_eq_pass']:,} ({eq_pct:.1f}%)")
            print(f"  Bean-INEQ pass: {w_stats['bean_ineq_pass']:,} "
                  f"({ineq_pct:.1f}% of EQ x variant)")
            print(f"  Corpus scans: {w_stats['scans']:,}")
            print(f"  Hits >= 18: {len(w_hits)}")
            print(f"  Time: {elapsed_w:.1f}s")

            if w_hits:
                for h in sorted(w_hits, key=lambda x: -x['score'])[:5]:
                    print(f"    *** HIT: {h['corpus']} {h['variant']} "
                          f"w={h['width']} order={h['order']} "
                          f"off={h['offset']} score={h['score']}/24")
            print(flush=True)
    finally:
        pool.close()
        pool.join()

    elapsed = time.time() - t0

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Widths tested: {WIDTHS[0]}-{WIDTHS[-1]}")
    print(f"  Total permutations: {grand_stats['total_perms']:,}")
    print(f"  Bean-EQ survivors: {grand_stats['total_bean_eq']:,}")
    print(f"  Bean-INEQ survivors: {grand_stats['total_bean_ineq']:,}")
    print(f"  Corpus scans: {grand_stats['total_scans']:,}")
    print(f"  Equivalent configs: {total_configs:,}")
    print(f"  Total hits >= 18: {len(all_hits)}")
    print(f"  Time: {elapsed:.1f}s ({elapsed / 60:.1f} min)")

    if all_hits:
        all_hits.sort(key=lambda x: -x['score'])
        print(f"\n  Top results:")
        for h in all_hits[:20]:
            print(f"    {h['corpus']} {h['variant']} w={h['width']} "
                  f"order={h['order']} off={h['offset']} "
                  f"score={h['score']}/24 ene={h['ene_match']} "
                  f"bc={h['bc_match']}")
    else:
        print(f"\n  No hits above threshold.")
        print(f"  P(random ENE 13/13 match) ~ 1e-18 per offset. "
              f"Zero false positives expected.")

    verdict = "SIGNAL" if all_hits else "NOISE"
    print(f"\n  Verdict: {verdict}")

    # Save artifact
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment": "E-EGYPT-01",
        "description": ("Egypt corpus x columnar transposition sweep "
                        "(widths 5-11, 3 variants, 9 corpora)"),
        "model": "CT[sigma(j)] = Enc(PT[j], Source[j+offset]), "
                 "sigma = columnar transposition",
        "widths": WIDTHS,
        "variants": [v[0] for v in VARIANTS],
        "corpora": [c[0] for c in _corpora],
        "corpus_total_chars": total_chars,
        "total_permutations": grand_stats['total_perms'],
        "bean_eq_survivors": grand_stats['total_bean_eq'],
        "bean_ineq_survivors": grand_stats['total_bean_ineq'],
        "total_corpus_scans": grand_stats['total_scans'],
        "total_configs_equiv": total_configs,
        "hits_ge_18": len(all_hits),
        "verdict": verdict,
        "top_results": all_hits[:20],
        "elapsed_seconds": round(elapsed, 1),
        "workers": N_WORKERS,
    }

    out_path = "results/e_egypt_01_columnar_sweep.json"
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: {out_path}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_egypt_01_columnar_sweep.py")


if __name__ == "__main__":
    main()
