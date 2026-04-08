#!/usr/bin/env python3 -u
"""
Cipher: running key
Family: running_key
Status: active

CIA DIGRAPH RUNNING-KEY CONSTRAINT TEST v3 (numpy vectorized)

For each hypothesis (digraph placement + variant), we have ~26-30
required key-text values at specific positions. For each text, we
precompute a numpy array of character indices and use vectorized
sliding-window comparison to count matches at all offsets simultaneously.
"""

import sys
import os
import json
import time
import glob
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path

import numpy as np

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT

CT_NUM = tuple(ALPH_IDX[c] for c in CT)

CIA_DIGRAPHS = [
    "KU", "AE", "DT", "GT", "CA", "ZR", "SR", "SM", "CK",
    "HT", "AM", "MK", "OD", "LC", "PB", "QR", "BG",
]
CRYPTONYMS = [
    "KUBARK", "RYBAT", "KUDESK", "DTLINEN",
    "AELADLE", "ZRRIFLE", "GTBEARD", "AESCREEN",
]

CRIB_POSITIONS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POSITIONS}


def derive_key(ct_val, pt_val, variant):
    if variant == 'vig':
        return (ct_val - pt_val) % 26
    elif variant == 'beau':
        return (ct_val + pt_val) % 26
    else:
        return (pt_val - ct_val) % 26


def build_hypotheses():
    """Returns list of (label, positions_array, values_array, n_constraints)."""
    hypotheses = []
    for variant in ['vig', 'beau', 'vbeau']:
        # Base crib key values
        crib_keys = {}
        for pos in CRIB_POSITIONS:
            crib_keys[pos] = derive_key(CT_NUM[pos], CRIB_PT[pos], variant)

        # Digraphs
        for digraph in CIA_DIGRAPHS:
            d_nums = [ALPH_IDX[c] for c in digraph]
            for start_pos in range(20):
                if start_pos + 1 >= 21:
                    continue
                combined = dict(crib_keys)
                for i, ch_num in enumerate(d_nums):
                    p = start_pos + i
                    combined[p] = derive_key(CT_NUM[p], ch_num, variant)
                sorted_items = sorted(combined.items())
                positions = np.array([p for p, v in sorted_items], dtype=np.int32)
                values = np.array([v for p, v in sorted_items], dtype=np.int8)
                hypotheses.append((f"{digraph}@{start_pos}_{variant}", positions, values, len(sorted_items)))

        # Cryptonyms
        for cryptonym in CRYPTONYMS:
            c_nums = [ALPH_IDX[c] for c in cryptonym]
            max_start = 21 - len(cryptonym)
            for start_pos in range(max(0, max_start) + 1):
                combined = dict(crib_keys)
                for i, ch_num in enumerate(c_nums):
                    p = start_pos + i
                    combined[p] = derive_key(CT_NUM[p], ch_num, variant)
                sorted_items = sorted(combined.items())
                positions = np.array([p for p, v in sorted_items], dtype=np.int32)
                values = np.array([v for p, v in sorted_items], dtype=np.int8)
                hypotheses.append((f"{cryptonym}@{start_pos}_{variant}", positions, values, len(sorted_items)))

    return hypotheses


def load_text_paths():
    paths = []
    ref_dir = os.path.join(_ROOT, "reference")
    for ext in ["*.txt", "*.md"]:
        paths.extend(glob.glob(os.path.join(ref_dir, "**", ext), recursive=True))
    wl_dir = os.path.join(_ROOT, "wordlists")
    paths.extend(glob.glob(os.path.join(wl_dir, "*.txt")))
    cache_dir = Path("/data/tmp/gutenberg_cache")
    if cache_dir.exists():
        paths.extend(sorted(str(p) for p in cache_dir.glob("*.txt"))[:500])
    return paths


def scan_text_file(fpath):
    """Load one text, scan all hypotheses against it using numpy vectorization.
    Returns dict of label -> (best_match, offset) plus any hits."""
    try:
        with open(fpath, encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        sanitized = ''.join(c.upper() for c in raw if c.isascii() and c.isalpha())
        if len(sanitized) < 97:
            return os.path.basename(fpath), {}, []
    except Exception:
        return os.path.basename(fpath), {}, []

    text_name = os.path.basename(fpath)
    text_arr = np.array([ALPH_IDX[c] for c in sanitized], dtype=np.int8)
    text_len = len(text_arr)

    results = {}
    hits = []

    for label, positions, values, n_constraints in ALL_HYPOTHESES:
        max_pos = int(positions[-1])
        n_offsets = text_len - max_pos
        if n_offsets <= 0:
            continue

        # Build matrix of text values at each (offset, constraint_position)
        # Shape: (n_offsets, n_constraints)
        indices = np.arange(n_offsets, dtype=np.int32)[:, None] + positions[None, :]
        extracted = text_arr[indices]

        # Count matches per offset
        matches_per_offset = np.sum(extracted == values[None, :], axis=1)

        best_idx = np.argmax(matches_per_offset)
        best_match = int(matches_per_offset[best_idx])
        best_offset = int(best_idx)

        results[label] = (best_match, best_offset)

        # Check for full or near matches
        full_mask = matches_per_offset == n_constraints
        if np.any(full_mask):
            for off in np.where(full_mask)[0]:
                hits.append((label, text_name, int(off), n_constraints))

        near_mask = (matches_per_offset >= n_constraints - 2) & (matches_per_offset >= 24) & ~full_mask
        if np.any(near_mask):
            for off in np.where(near_mask)[0]:
                hits.append((label, text_name, int(off), int(matches_per_offset[off])))

    return text_name, results, hits


# Global for multiprocessing (set in main, forked to workers)
ALL_HYPOTHESES = []


def _init_worker(hypotheses):
    global ALL_HYPOTHESES
    ALL_HYPOTHESES = hypotheses


def _scan_wrapper(fpath):
    return scan_text_file(fpath)


def main():
    global ALL_HYPOTHESES

    print("=" * 70)
    print("CIA DIGRAPH RUNNING-KEY CONSTRAINT TEST v3 (numpy)")
    print("=" * 70)
    t0 = time.time()

    print("\nPhase 1: Building hypotheses...")
    ALL_HYPOTHESES = build_hypotheses()
    print(f"  {len(ALL_HYPOTHESES)} configurations")

    print("\nPhase 2: Discovering text files...")
    all_paths = load_text_paths()
    print(f"  {len(all_paths)} files")

    n_workers = min(max(1, cpu_count() - 2), 26)
    print(f"\nPhase 3: Scanning with {n_workers} workers (numpy vectorized)...")

    global_results = {}  # label -> (best_match, text_name, offset)
    all_hits = []
    done = 0

    with Pool(n_workers, initializer=_init_worker, initargs=(ALL_HYPOTHESES,)) as pool:
        for text_name, results, hits in pool.imap_unordered(_scan_wrapper, all_paths, chunksize=4):
            done += 1
            for label, (best, offset) in results.items():
                if label not in global_results or best > global_results[label][0]:
                    global_results[label] = (best, text_name, offset)
            all_hits.extend(hits)
            if done % 50 == 0:
                print(f"    {done}/{len(all_paths)} texts ({time.time()-t0:.0f}s)")

    elapsed = time.time() - t0
    print(f"\n  Done in {elapsed:.1f}s ({done} texts)")

    # Results
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    full_hits = [h for h in all_hits if h[3] >= 26]  # all constraints met
    near_hits = [h for h in all_hits if h[3] < 26]

    print(f"\n  FULL MATCHES: {len(full_hits)}")
    for label, text_name, offset, count in full_hits[:20]:
        print(f"    {label}: {text_name} @ {offset} ({count}/{count})")

    near_hits.sort(key=lambda x: -x[3])
    print(f"\n  NEAR MISSES (>= 24 of N constraints): {len(near_hits)}")
    for label, text_name, offset, count in near_hits[:20]:
        print(f"    {label}: {text_name} @ {offset} ({count})")

    sorted_hyps = sorted(global_results.items(), key=lambda x: -x[1][0])

    print(f"\n  TOP 30 BY BEST MATCH:")
    for label, (best, text_name, offset) in sorted_hyps[:30]:
        # Find constraint count
        nc = 26
        for h in ALL_HYPOTHESES:
            if h[0] == label:
                nc = h[3]
                break
        print(f"    {label}: {best}/{nc} in {text_name} @ {offset}")

    match_dist = defaultdict(int)
    for label, (best, _, _) in global_results.items():
        match_dist[best] += 1
    print(f"\n  BEST-MATCH DISTRIBUTION:")
    for score in sorted(match_dist.keys(), reverse=True):
        print(f"    {score}: {match_dist[score]} hypotheses")

    # KU / KUBARK specific
    print(f"\n  KUBARK RESULTS:")
    for label, (best, text_name, offset) in sorted_hyps:
        if 'KUBARK' in label:
            nc = 30
            for h in ALL_HYPOTHESES:
                if h[0] == label:
                    nc = h[3]
                    break
            print(f"    {label}: {best}/{nc} in {text_name} @ {offset}")

    print(f"\n  KU DIGRAPH RESULTS:")
    for label, (best, text_name, offset) in sorted_hyps:
        if label.startswith('KU@'):
            nc = 26
            for h in ALL_HYPOTHESES:
                if h[0] == label:
                    nc = h[3]
                    break
            print(f"    {label}: {best}/{nc} in {text_name} @ {offset}")

    out = {
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "hypotheses": len(ALL_HYPOTHESES),
        "texts": len(all_paths),
        "runtime_s": round(elapsed, 1),
        "full_hits": len(full_hits),
        "near_misses": len(near_hits),
        "top_30": [
            {"label": l, "best": b, "text": t, "offset": o}
            for l, (b, t, o) in sorted_hyps[:30]
        ],
    }
    out_path = os.path.join(_ROOT, "results", "e_digraph_running_key_03.json")
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\n  Saved to {out_path}")
    print(f"  Total: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
