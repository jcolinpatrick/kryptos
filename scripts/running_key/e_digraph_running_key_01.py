#!/usr/bin/env python3 -u
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: 17 digraphs x 20 positions x 3 variants + KUBARK/RYBAT extended cribs
Last run:
Best score:

CIA DIGRAPH RUNNING-KEY CONSTRAINT TEST

Hypothesis: K4 plaintext positions 0-20 contain a CIA cryptonym digraph
(e.g., KU from KUBARK, which Sanborn wrote in his notebook). Under a
running-key model, each assumed plaintext character constrains the
corresponding running-key text character. Adding 2-6 digraph/cryptonym
characters to the 24 existing crib constraints gives 26-30 total
constraints on the source text, enabling much tighter corpus filtering.

This is NOT a periodic cipher test (those are Tier 1 eliminated).
This tests running-key from a corpus, using digraph-derived key values
as additional filter constraints.

Phase 1: Compute required key-text values for each digraph placement
Phase 2: Scan local text corpus for matches against 26-30 constraints
Phase 3: Score any hits with full running-key decryption
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

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

# ── Constants ──────────────────────────────────────────────────────────

CT_NUM = tuple(ALPH_IDX[c] for c in CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# CIA cryptonym digraphs (Cold War / Berlin relevant)
CIA_DIGRAPHS = [
    "KU",  # CIA itself (KUBARK - in Sanborn's notebook)
    "AE",  # Soviet/Eastern Europe operations
    "DT",  # East Germany
    "GT",  # Soviet Union
    "CA",  # West Germany
    "ZR",  # Counterintelligence / intercept ops
    "SR",  # Soviet Russia
    "SM",  # Soviet Military
    "CK",  # CIA internal
    "HT",  # Cuba
    "AM",  # Cuba
    "MK",  # Mind control (MKULTRA)
    "OD",  # Near East
    "LC",  # Latin America
    "PB",  # Latin America
    "QR",  # Unidentified
    "BG",  # Bulgaria
]

# Extended cryptonyms (full words, not just digraphs)
CRYPTONYMS = [
    "KUBARK",     # CIA itself (6 chars) - IN SANBORN'S NOTEBOOK
    "RYBAT",      # Highly classified handling (5 chars)
    "KUDESK",     # CIA Counterintelligence dept (6 chars)
    "DTLINEN",    # East Germany op (7 chars)
    "AELADLE",    # Soviet source (7 chars)
    "ZRRIFLE",    # Assassination program (7 chars)
    "GTBEARD",    # Soviet-related (7 chars)
    "AESCREEN",   # Soviet ops (8 chars)
]

# Known crib positions (0-indexed)
CRIB_POSITIONS = sorted(CRIB_DICT.keys())  # 21-33, 63-73
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POSITIONS}

# ── Key-text derivation ────────────────────────────────────────────────

def derive_key_values(ct_nums, pt_nums, positions, variant):
    """Derive running-key text values at given positions.

    variant: 'vig' -> key = (CT - PT) mod 26
             'beau' -> key = (CT + PT) mod 26
             'vbeau' -> key = (PT - CT) mod 26
    """
    result = {}
    for pos, pt in zip(positions, pt_nums):
        ct = ct_nums[pos]
        if variant == 'vig':
            result[pos] = (ct - pt) % MOD
        elif variant == 'beau':
            result[pos] = (ct + pt) % MOD
        elif variant == 'vbeau':
            result[pos] = (pt - ct) % MOD
    return result


def get_crib_key_values(variant):
    """Get running-key text values at the 24 known crib positions."""
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


# ── Build all hypothesis configurations ────────────────────────────────

def build_hypotheses():
    """Build list of (label, variant, {pos: required_key_value}) dicts."""
    hypotheses = []

    for variant in ['vig', 'beau', 'vbeau']:
        crib_keys = get_crib_key_values(variant)

        # Digraphs at positions 0-19
        for digraph in CIA_DIGRAPHS:
            d_nums = [ALPH_IDX[c] for c in digraph]
            for start_pos in range(20):  # digraph at start_pos, start_pos+1
                if start_pos + 1 >= 21:
                    continue  # don't overlap with ENE crib
                d_positions = [start_pos, start_pos + 1]
                d_keys = derive_key_values(CT_NUM, d_nums, d_positions, variant)
                combined = {**crib_keys, **d_keys}
                label = f"{digraph}@{start_pos}_{variant}"
                hypotheses.append((label, variant, combined))

        # Extended cryptonyms
        for cryptonym in CRYPTONYMS:
            c_nums = [ALPH_IDX[c] for c in cryptonym]
            max_start = min(20, 21 - len(cryptonym))
            for start_pos in range(max_start + 1):
                if start_pos + len(cryptonym) > 21:
                    continue
                c_positions = list(range(start_pos, start_pos + len(cryptonym)))
                c_keys = derive_key_values(CT_NUM, c_nums, c_positions, variant)
                combined = {**crib_keys, **c_keys}
                label = f"{cryptonym}@{start_pos}_{variant}"
                hypotheses.append((label, variant, combined))

    return hypotheses


# ── Corpus loading ─────────────────────────────────────────────────────

def load_corpus_texts():
    """Load all available text files from wordlists, reference, and cached corpus."""
    texts = []

    # Reference texts
    ref_dir = os.path.join(_ROOT, "reference")
    for ext in ["*.txt", "*.md"]:
        for fpath in glob.glob(os.path.join(ref_dir, "**", ext), recursive=True):
            try:
                with open(fpath, encoding='utf-8', errors='ignore') as f:
                    raw = f.read()
                sanitized = ''.join(c.upper() for c in raw if c.isascii() and c.isalpha())
                if len(sanitized) >= 97:
                    texts.append((os.path.basename(fpath), sanitized))
            except Exception:
                pass

    # Wordlists directory
    wl_dir = os.path.join(_ROOT, "wordlists")
    for fpath in glob.glob(os.path.join(wl_dir, "*.txt")):
        try:
            with open(fpath, encoding='utf-8', errors='ignore') as f:
                raw = f.read()
            sanitized = ''.join(c.upper() for c in raw if c.isascii() and c.isalpha())
            if len(sanitized) >= 97:
                texts.append((os.path.basename(fpath), sanitized))
        except Exception:
            pass

    # Gutenberg cache if available
    cache_dir = Path("/data/tmp/gutenberg_cache")
    if cache_dir.exists():
        for fpath in sorted(cache_dir.glob("*.txt"))[:500]:  # cap at 500 texts
            try:
                with open(fpath, encoding='utf-8', errors='ignore') as f:
                    raw = f.read()
                sanitized = ''.join(c.upper() for c in raw if c.isascii() and c.isalpha())
                if len(sanitized) >= 97:
                    texts.append((fpath.name, sanitized))
            except Exception:
                pass

    # Known thematic texts
    thematic = [
        os.path.join(_ROOT, "reference", "carter_tomb.txt"),
        os.path.join(_ROOT, "reference", "codebreakers_excerpt.txt"),
    ]
    for fpath in thematic:
        if os.path.exists(fpath):
            try:
                with open(fpath, encoding='utf-8', errors='ignore') as f:
                    raw = f.read()
                sanitized = ''.join(c.upper() for c in raw if c.isascii() and c.isalpha())
                if len(sanitized) >= 97:
                    texts.append((os.path.basename(fpath), sanitized))
            except Exception:
                pass

    return texts


# ── Matching engine ────────────────────────────────────────────────────

def scan_text_for_hypothesis(args):
    """Check if any offset in a text matches all required key values."""
    text_name, text_nums, label, required_keys = args

    sorted_positions = sorted(required_keys.keys())
    min_pos = sorted_positions[0]
    max_pos = sorted_positions[-1]
    span = max_pos - min_pos + 1
    n_constraints = len(required_keys)

    best_match = 0
    best_offset = -1
    hits = []

    max_offset = len(text_nums) - max_pos - 1
    if max_offset < 0:
        return label, text_name, 0, -1, []

    for offset in range(max_offset + 1):
        match_count = 0
        for pos, req_val in required_keys.items():
            text_idx = offset + pos
            if text_idx < len(text_nums) and text_nums[text_idx] == req_val:
                match_count += 1

        if match_count > best_match:
            best_match = match_count
            best_offset = offset

        # Full match = all constraints satisfied
        if match_count == n_constraints:
            hits.append((offset, match_count))

        # Near-miss: report if >= n_constraints - 2
        elif match_count >= n_constraints - 2 and match_count >= 24:
            hits.append((offset, match_count))

    return label, text_name, best_match, best_offset, hits


def main():
    print("=" * 70)
    print("CIA DIGRAPH RUNNING-KEY CONSTRAINT TEST")
    print("=" * 70)
    t0 = time.time()

    # Phase 1: Build hypotheses
    print("\nPhase 1: Building hypotheses...")
    hypotheses = build_hypotheses()
    print(f"  {len(hypotheses)} hypothesis configurations")
    print(f"  (17 digraphs x 20 positions + {len(CRYPTONYMS)} cryptonyms) x 3 variants")

    # Phase 2: Load corpus
    print("\nPhase 2: Loading corpus...")
    texts = load_corpus_texts()
    print(f"  {len(texts)} texts loaded")
    for name, text in texts[:10]:
        print(f"    {name}: {len(text)} chars")
    if len(texts) > 10:
        print(f"    ... and {len(texts) - 10} more")

    # Pre-convert texts to numeric
    texts_num = [(name, tuple(ALPH_IDX[c] for c in text)) for name, text in texts]

    # Phase 3: Scan
    print("\nPhase 3: Scanning corpus against all hypotheses...")
    n_workers = max(1, cpu_count() - 2)

    # Build work items: each (text, hypothesis) pair
    work_items = []
    for label, variant, required_keys in hypotheses:
        for text_name, text_nums in texts_num:
            work_items.append((text_name, text_nums, label, required_keys))

    print(f"  {len(work_items)} scan tasks ({len(hypotheses)} hypotheses x {len(texts_num)} texts)")
    print(f"  Using {n_workers} workers")

    # Track results
    best_by_hypothesis = defaultdict(lambda: (0, "", -1))
    full_hits = []
    near_misses = []

    batch_size = 10000
    processed = 0
    with Pool(n_workers) as pool:
        for result in pool.imap_unordered(scan_text_for_hypothesis, work_items, chunksize=100):
            label, text_name, best_match, best_offset, hits = result
            processed += 1

            if best_match > best_by_hypothesis[label][0]:
                best_by_hypothesis[label] = (best_match, text_name, best_offset)

            for offset, count in hits:
                if count == len([h for h in hypotheses if h[0] == label][0][2]):
                    full_hits.append((label, text_name, offset, count))
                else:
                    near_misses.append((label, text_name, offset, count))

            if processed % batch_size == 0:
                elapsed = time.time() - t0
                print(f"    {processed}/{len(work_items)} ({elapsed:.0f}s)")

    elapsed = time.time() - t0
    print(f"\n  Scan complete in {elapsed:.1f}s")

    # Phase 4: Results
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    # Full hits
    print(f"\n  FULL MATCHES (all constraints satisfied): {len(full_hits)}")
    for label, text_name, offset, count in full_hits:
        print(f"    {label}: {text_name} @ offset {offset} ({count} matches)")

    # Near misses
    near_misses.sort(key=lambda x: -x[3])
    print(f"\n  NEAR MISSES (>= 24 matches): {len(near_misses)}")
    for label, text_name, offset, count in near_misses[:20]:
        print(f"    {label}: {text_name} @ offset {offset} ({count} matches)")

    # Top hypotheses by best match count
    sorted_hyps = sorted(best_by_hypothesis.items(), key=lambda x: -x[1][0])
    print(f"\n  TOP 30 HYPOTHESES BY BEST MATCH:")
    for label, (best, text_name, offset) in sorted_hyps[:30]:
        n_constraints = len(label.split('_')[0]) if '@' not in label else 26
        # Get actual constraint count
        for h_label, _, h_keys in hypotheses:
            if h_label == label:
                n_constraints = len(h_keys)
                break
        print(f"    {label}: {best}/{n_constraints} in {text_name} @ offset {offset}")

    # Distribution of best matches
    match_dist = defaultdict(int)
    for label, (best, _, _) in best_by_hypothesis.items():
        match_dist[best] += 1
    print(f"\n  BEST-MATCH DISTRIBUTION:")
    for score in sorted(match_dist.keys(), reverse=True):
        print(f"    {score}: {match_dist[score]} hypotheses")

    # KUBARK-specific results
    print(f"\n  KUBARK-SPECIFIC RESULTS:")
    for label, (best, text_name, offset) in sorted_hyps:
        if 'KUBARK' in label:
            for h_label, _, h_keys in hypotheses:
                if h_label == label:
                    n_constraints = len(h_keys)
                    break
            print(f"    {label}: {best}/{n_constraints} in {text_name} @ offset {offset}")

    # KU digraph results
    print(f"\n  KU DIGRAPH RESULTS:")
    for label, (best, text_name, offset) in sorted_hyps:
        if label.startswith('KU@'):
            for h_label, _, h_keys in hypotheses:
                if h_label == label:
                    n_constraints = len(h_keys)
                    break
            print(f"    {label}: {best}/{n_constraints} in {text_name} @ offset {offset}")

    # Save results
    results = {
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "hypotheses_tested": len(hypotheses),
        "texts_scanned": len(texts_num),
        "total_scans": len(work_items),
        "full_hits": len(full_hits),
        "near_misses": len(near_misses),
        "top_30": [
            {"label": label, "best_match": best, "text": text_name, "offset": offset}
            for label, (best, text_name, offset) in sorted_hyps[:30]
        ],
        "kubark_results": [
            {"label": label, "best_match": best, "text": text_name, "offset": offset}
            for label, (best, text_name, offset) in sorted_hyps
            if 'KUBARK' in label
        ],
    }

    out_path = os.path.join(_ROOT, "results", "e_digraph_running_key_01.json")
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to {out_path}")

    print(f"\n  Total runtime: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
