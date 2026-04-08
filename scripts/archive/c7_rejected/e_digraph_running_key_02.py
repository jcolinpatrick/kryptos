#!/usr/bin/env python3 -u
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: 17 digraphs x 20 positions x 3 variants + KUBARK/RYBAT extended cribs
Last run:
Best score:

CIA DIGRAPH RUNNING-KEY CONSTRAINT TEST v2 (memory-efficient)

Each worker owns a shard of texts and scans all hypotheses locally.
No large data transfer between processes.
"""

import sys
import os
import json
import time
import glob
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT

CT_NUM = tuple(ALPH_IDX[c] for c in CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

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


def get_crib_key_values(variant):
    result = {}
    for pos in CRIB_POSITIONS:
        ct = CT_NUM[pos]
        pt = CRIB_PT[pos]
        if variant == 'vig':
            result[pos] = (ct - pt) % MOD
        elif variant == 'beau':
            result[pos] = (ct + pt) % MOD
        elif variant == 'vbeau':
            result[pos] = (pt - ct) % MOD
    return result


def build_hypotheses():
    hypotheses = []
    for variant in ['vig', 'beau', 'vbeau']:
        crib_keys = get_crib_key_values(variant)
        for digraph in CIA_DIGRAPHS:
            d_nums = [ALPH_IDX[c] for c in digraph]
            for start_pos in range(20):
                if start_pos + 1 >= 21:
                    continue
                d_keys = {}
                for i, ch_num in enumerate(d_nums):
                    p = start_pos + i
                    ct = CT_NUM[p]
                    if variant == 'vig':
                        d_keys[p] = (ct - ch_num) % MOD
                    elif variant == 'beau':
                        d_keys[p] = (ct + ch_num) % MOD
                    elif variant == 'vbeau':
                        d_keys[p] = (ch_num - ct) % MOD
                combined = {**crib_keys, **d_keys}
                hypotheses.append((f"{digraph}@{start_pos}_{variant}", combined))
        for cryptonym in CRYPTONYMS:
            c_nums = [ALPH_IDX[c] for c in cryptonym]
            max_start = 21 - len(cryptonym)
            for start_pos in range(max(0, max_start) + 1):
                d_keys = {}
                for i, ch_num in enumerate(c_nums):
                    p = start_pos + i
                    ct = CT_NUM[p]
                    if variant == 'vig':
                        d_keys[p] = (ct - ch_num) % MOD
                    elif variant == 'beau':
                        d_keys[p] = (ct + ch_num) % MOD
                    elif variant == 'vbeau':
                        d_keys[p] = (ch_num - ct) % MOD
                combined = {**crib_keys, **d_keys}
                hypotheses.append((f"{cryptonym}@{start_pos}_{variant}", combined))
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


def sanitize_file(fpath):
    try:
        with open(fpath, encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        return ''.join(c.upper() for c in raw if c.isascii() and c.isalpha())
    except Exception:
        return ""


def scan_shard(args):
    """Each worker loads and scans its own shard of text files."""
    file_paths, hypotheses_packed = args

    # Unpack hypotheses: list of (label, {pos: val})
    # Convert pos:val dicts to sorted lists for fast checking
    hyp_compiled = []
    for label, req_dict in hypotheses_packed:
        sorted_items = sorted(req_dict.items())
        positions = tuple(p for p, v in sorted_items)
        values = tuple(v for p, v in sorted_items)
        max_pos = positions[-1]
        n = len(positions)
        hyp_compiled.append((label, positions, values, max_pos, n))

    results = {}  # label -> (best_match, text_name, offset)
    full_hits = []
    near_misses = []

    for fpath in file_paths:
        text = sanitize_file(fpath)
        if len(text) < 97:
            continue
        text_name = os.path.basename(fpath)
        text_nums = tuple(ALPH_IDX[c] for c in text)
        text_len = len(text_nums)

        for label, positions, values, max_pos, n_constraints in hyp_compiled:
            max_offset = text_len - max_pos - 1
            if max_offset < 0:
                continue

            best_match = 0
            best_offset = -1

            for offset in range(max_offset + 1):
                match_count = 0
                for i in range(n_constraints):
                    if text_nums[offset + positions[i]] == values[i]:
                        match_count += 1
                    elif n_constraints - (i - match_count) < best_match:
                        break  # early exit: can't beat current best

                if match_count > best_match:
                    best_match = match_count
                    best_offset = offset

                if match_count == n_constraints:
                    full_hits.append((label, text_name, offset, match_count))
                elif match_count >= n_constraints - 2 and match_count >= 24:
                    near_misses.append((label, text_name, offset, match_count))

            if label not in results or best_match > results[label][0]:
                results[label] = (best_match, text_name, best_offset)

    return results, full_hits, near_misses


def main():
    print("=" * 70)
    print("CIA DIGRAPH RUNNING-KEY CONSTRAINT TEST v2")
    print("=" * 70)
    t0 = time.time()

    print("\nPhase 1: Building hypotheses...")
    hypotheses = build_hypotheses()
    print(f"  {len(hypotheses)} hypothesis configurations")

    print("\nPhase 2: Discovering text files...")
    all_paths = load_text_paths()
    print(f"  {len(all_paths)} text files found")

    n_workers = min(max(1, cpu_count() - 2), 26)
    print(f"\nPhase 3: Scanning with {n_workers} workers (each loads own texts)...")

    # Shard files across workers
    shards = [[] for _ in range(n_workers)]
    for i, path in enumerate(all_paths):
        shards[i % n_workers].append(path)

    work_items = [(shard, hypotheses) for shard in shards]

    all_results = {}  # label -> (best_match, text, offset)
    all_full_hits = []
    all_near_misses = []

    with Pool(n_workers) as pool:
        for shard_results, shard_hits, shard_near in pool.imap_unordered(scan_shard, work_items):
            for label, (best, text_name, offset) in shard_results.items():
                if label not in all_results or best > all_results[label][0]:
                    all_results[label] = (best, text_name, offset)
            all_full_hits.extend(shard_hits)
            all_near_misses.extend(shard_near)

    elapsed = time.time() - t0
    print(f"\n  Scan complete in {elapsed:.1f}s")

    # Results
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    print(f"\n  FULL MATCHES: {len(all_full_hits)}")
    for label, text_name, offset, count in all_full_hits:
        print(f"    {label}: {text_name} @ offset {offset} ({count}/{count})")

    all_near_misses.sort(key=lambda x: -x[3])
    print(f"\n  NEAR MISSES (>= 24 matches): {len(all_near_misses)}")
    for label, text_name, offset, count in all_near_misses[:20]:
        print(f"    {label}: {text_name} @ offset {offset} ({count})")

    sorted_hyps = sorted(all_results.items(), key=lambda x: -x[1][0])
    print(f"\n  TOP 30 HYPOTHESES BY BEST MATCH:")
    for label, (best, text_name, offset) in sorted_hyps[:30]:
        for h_label, h_keys in hypotheses:
            if h_label == label:
                n_constraints = len(h_keys)
                break
        else:
            n_constraints = "?"
        print(f"    {label}: {best}/{n_constraints} in {text_name} @ offset {offset}")

    match_dist = defaultdict(int)
    for label, (best, _, _) in all_results.items():
        match_dist[best] += 1
    print(f"\n  BEST-MATCH DISTRIBUTION:")
    for score in sorted(match_dist.keys(), reverse=True):
        print(f"    {score}: {match_dist[score]} hypotheses")

    print(f"\n  KUBARK-SPECIFIC RESULTS:")
    for label, (best, text_name, offset) in sorted_hyps:
        if 'KUBARK' in label:
            for h_label, h_keys in hypotheses:
                if h_label == label:
                    n_constraints = len(h_keys)
                    break
            else:
                n_constraints = "?"
            print(f"    {label}: {best}/{n_constraints} in {text_name} @ offset {offset}")

    print(f"\n  KU DIGRAPH RESULTS:")
    for label, (best, text_name, offset) in sorted_hyps:
        if label.startswith('KU@'):
            for h_label, h_keys in hypotheses:
                if h_label == label:
                    n_constraints = len(h_keys)
                    break
            else:
                n_constraints = "?"
            print(f"    {label}: {best}/{n_constraints} in {text_name} @ offset {offset}")

    out = {
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "hypotheses": len(hypotheses),
        "texts": len(all_paths),
        "runtime_s": round(elapsed, 1),
        "full_hits": len(all_full_hits),
        "near_misses": len(all_near_misses),
        "top_30": [
            {"label": l, "best": b, "text": t, "offset": o}
            for l, (b, t, o) in sorted_hyps[:30]
        ],
    }
    out_path = os.path.join(_ROOT, "results", "e_digraph_running_key_02.json")
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\n  Saved to {out_path}")
    print(f"  Total runtime: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
