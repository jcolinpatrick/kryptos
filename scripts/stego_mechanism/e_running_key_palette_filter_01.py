#!/usr/bin/env python3
"""
Cipher:   Stego mechanism (running-key palette filter)
Family:   stego_mechanism
Status:   active
Keyspace: ~300MB corpus × 6 cipher configs × top-8 masks
Last run:
Best score:

PURPOSE: Use the BCL keystream palette enrichment (13/24 palette letters
under Beaufort AZ) as a filter to search for running-key source texts.

PRIOR RESULTS:
  - Exhaustive palette sweep found optimal joint mask with 17-position core
  - Beaufort AZ has 13/24 palette-enriched keystream at crib positions
  - This enrichment is unique to Beaufort AZ (next best: 9/24 for Vigenere AZ)

DESIGN:
  For each cipher config (3 variants × 2 alphabets = 6):
    For each mask (top-8 joint masks from exhaustive sweep):
      Compute shifted crib positions and required key letters
      For each source text in corpus:
        Slide window of length = extracted text length
        Count matches at crib positions
        Report any window with matches >= threshold

STATISTICAL FRAMEWORK:
  Under random, each position matches with p = 1/26
  For 24 positions: E[matches] = 24/26 = 0.923
  Significance thresholds (Bonferroni-corrected for ~4M windows):
    >= 7 matches: p_single ~ 5.5e-5, p_corrected ~ 0.22 (suggestive)
    >= 9 matches: p_single ~ 1.1e-6, p_corrected ~ 0.004 (significant)
    >= 11 matches: p_single ~ 2e-9, p_corrected ~ 8e-3 (highly significant)
"""

import sys
import os
import time
import json
import re
from collections import Counter
from math import comb, log, factorial
from multiprocessing import Pool, cpu_count
from pathlib import Path

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET, NULL_PALETTE,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    CONSENSUS_NULL_POSITIONS,
)

# ── Constants ────────────────────────────────────────────────────────────────

N = CT_LEN
N_NULLS = 24
N_PT = N - N_NULLS  # 73

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

N_WORKERS = max(1, cpu_count() - 2)
REPORT_THRESHOLD = 5  # Report matches >= this
PALETTE_SET = frozenset(NULL_PALETTE)

# Top-8 joint masks from exhaustive palette sweep (differ only in last 7 positions)
TOP_JOINT_MASKS = [
    [2, 5, 7, 8, 12, 14, 16, 20, 34, 36, 45, 46, 47, 52, 56, 58, 59, 75, 77, 78, 84, 85, 86, 93],
    [2, 5, 7, 8, 12, 14, 16, 20, 34, 36, 45, 46, 47, 52, 56, 58, 59, 74, 77, 78, 84, 85, 86, 93],
    [2, 5, 7, 8, 12, 14, 16, 20, 34, 36, 45, 46, 47, 52, 56, 58, 59, 74, 75, 78, 84, 85, 86, 93],
    [2, 5, 7, 8, 12, 14, 16, 20, 34, 36, 45, 46, 47, 52, 56, 58, 59, 74, 75, 77, 84, 85, 86, 93],
    [2, 5, 7, 8, 12, 14, 16, 20, 34, 36, 45, 46, 47, 52, 56, 58, 59, 74, 75, 77, 78, 85, 86, 93],
    [2, 5, 7, 8, 12, 14, 16, 20, 34, 36, 45, 46, 47, 52, 56, 58, 59, 74, 75, 77, 78, 84, 86, 93],
    [2, 5, 7, 8, 12, 14, 16, 20, 34, 36, 45, 46, 47, 52, 56, 58, 59, 74, 75, 77, 78, 84, 85, 93],
    [2, 5, 7, 8, 12, 14, 16, 20, 34, 36, 45, 46, 47, 52, 56, 58, 59, 74, 75, 77, 78, 84, 85, 86],
]

# Also test consensus mask (17 positions → need to pick 7 more from palette)
# and a "balanced" mask (top by min(B,V,VB) from exhaustive sweep)
BALANCED_MASKS = [
    [0, 1, 2, 5, 7, 16, 20, 34, 36, 45, 46, 47, 48, 52, 56, 58, 59, 75, 77, 78, 84, 85, 86, 93],
]


# ── Cipher configurations ───────────────────────────────────────────────────

def compute_constraints(mask, alph_str, alph_idx):
    """Compute running-key constraints for a mask under each cipher variant.

    Returns dict: variant -> list of (shifted_position, required_letter)
    """
    mask_set = frozenset(mask)
    crib_pos = sorted(CRIB_DICT.keys())
    mod = len(alph_str)

    results = {}
    for var_name, key_fn in [
        ('beaufort', lambda ci, pi: (ci + pi) % mod),
        ('vigenere', lambda ci, pi: (ci - pi) % mod),
        ('var_beaufort', lambda ci, pi: (pi - ci) % mod),
    ]:
        constraints = []
        for pos in crib_pos:
            # Shifted position in extracted text
            n_before = sum(1 for m in mask if m < pos)
            shifted = pos - n_before

            c_idx = alph_idx[CT[pos]]
            p_idx = alph_idx[CRIB_DICT[pos]]
            k_idx = key_fn(c_idx, p_idx)
            req_letter = alph_str[k_idx]

            constraints.append((shifted, req_letter))

        results[var_name] = constraints

    return results


# ── Text sanitization ────────────────────────────────────────────────────────

def sanitize(text):
    """Convert text to uppercase A-Z only."""
    return re.sub(r'[^A-Z]', '', text.upper())


# ── Source text collection ───────────────────────────────────────────────────

def collect_sources():
    """Collect all available source texts for running-key search."""
    sources = []

    # Reference texts
    ref_dir = os.path.join(_ROOT, 'reference')
    for fname in ['Carter_Tomb.txt', 'carter_gutenberg.txt', 'carter_vol1.txt',
                   'Wikipedia OTP.txt', 'LEMMiNO Transcript.txt',
                   'NPR Interviews.txt',
                   'great_big_story_cracking_the_uncrackable_code_2019.txt']:
        path = os.path.join(ref_dir, fname)
        if os.path.exists(path):
            sources.append(('reference/' + fname, path))

    # Running key texts
    rk_dir = os.path.join(ref_dir, 'running_key_texts')
    if os.path.isdir(rk_dir):
        for fname in sorted(os.listdir(rk_dir)):
            if fname.endswith('.txt'):
                sources.append(('rk_texts/' + fname, os.path.join(rk_dir, fname)))

    # Gutenberg corpus
    gut_dir = os.path.join(_ROOT, 'results', 'k123_running_key_exhaustive',
                           'phase4_gutenberg', 'downloads')
    if os.path.isdir(gut_dir):
        for fname in sorted(os.listdir(gut_dir)):
            if fname.endswith('.txt'):
                sources.append(('gutenberg/' + fname, os.path.join(gut_dir, fname)))

    return sources


# ── Search engine ────────────────────────────────────────────────────────────

def search_text(sanitized_text, constraints, window_len):
    """Search a sanitized text for running-key matches.

    constraints: list of (position_in_window, required_letter)
    window_len: length of the extracted text (73)

    Returns list of (offset, n_matches, matched_positions) for matches >= threshold.

    Optimized: uses bytearray vote-counting instead of per-offset Python loop.
    For each constraint, marks all valid offsets in a count array, then scans
    for positions exceeding the threshold. ~100x faster than naive Python loop.
    """
    text_len = len(sanitized_text)
    if text_len < window_len:
        return []

    max_offset = text_len - window_len
    text_bytes = sanitized_text.encode('ascii')

    # Vote array: counts[offset] = number of constraints matched at this offset
    counts = bytearray(max_offset + 1)

    for pos, req in constraints:
        req_byte = ord(req)
        # For each position in text where text[i] == req, the offset i - pos is valid
        # This means: scan text[pos : max_offset + pos + 1] for req_byte
        start = pos
        end = max_offset + pos + 1
        idx = text_bytes.find(req_byte, start, end)
        while idx != -1:
            counts[idx - pos] += 1
            idx = text_bytes.find(req_byte, idx + 1, end)

    # Collect hits above threshold
    hits = []
    for offset in range(max_offset + 1):
        if counts[offset] >= REPORT_THRESHOLD:
            # Reconstruct which positions matched
            matched = []
            for pos, req in constraints:
                if sanitized_text[offset + pos] == req:
                    matched.append(pos)
            hits.append((offset, counts[offset], tuple(matched)))

    return hits


def _search_worker(args):
    """Worker: search one source file under one configuration."""
    source_name, source_path, config_name, constraints, window_len = args

    try:
        with open(source_path, 'r', errors='replace') as f:
            raw = f.read()
        text = sanitize(raw)
    except Exception as e:
        return {'source': source_name, 'config': config_name,
                'error': str(e), 'hits': []}

    hits = search_text(text, constraints, window_len)

    # For each hit, extract context
    hit_details = []
    for offset, n_match, matched_pos in hits:
        window = text[offset:offset + window_len]
        # Find the approximate raw text location
        raw_pos = -1  # approximate
        alpha_count = 0
        for i, c in enumerate(raw):
            if c.upper().isalpha():
                alpha_count += 1
            if alpha_count >= offset:
                raw_pos = i
                break

        hit_details.append({
            'offset': offset,
            'n_matches': n_match,
            'matched_positions': list(matched_pos),
            'key_fragment': window,
            'raw_approx_pos': raw_pos,
        })

    return {
        'source': source_name,
        'config': config_name,
        'text_len': len(text),
        'n_windows': max(0, len(text) - window_len + 1),
        'n_hits': len(hit_details),
        'max_matches': max((h['n_matches'] for h in hit_details), default=0),
        'hits': sorted(hit_details, key=lambda h: -h['n_matches'])[:20],  # top 20
    }


# ── Statistical significance ────────────────────────────────────────────────

def binomial_sf(k, n, p):
    """P(X >= k) for X ~ Binomial(n, p). Exact computation."""
    prob = 0.0
    for i in range(k, n + 1):
        coeff = comb(n, i)
        prob += coeff * (p ** i) * ((1 - p) ** (n - i))
    return prob


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 78)
    print("RUNNING-KEY PALETTE FILTER: Corpus Search")
    print("=" * 78)

    # Collect sources
    sources = collect_sources()
    total_size = 0
    for name, path in sources:
        try:
            total_size += os.path.getsize(path)
        except:
            pass
    print(f"Sources: {len(sources)} files, {total_size/1e6:.1f} MB")

    # Build configurations: top masks × 6 cipher configs
    masks_to_test = TOP_JOINT_MASKS[:4] + BALANCED_MASKS  # 5 masks
    configs = []

    for mask_idx, mask in enumerate(masks_to_test):
        mask_name = f"joint_{mask_idx}" if mask_idx < 4 else "balanced_0"
        for alph_name, alph_str, alph_idx in [('AZ', ALPH, ALPH_IDX), ('KA', KA, KA_IDX)]:
            all_constraints = compute_constraints(mask, alph_str, alph_idx)
            for var_name, constraints in all_constraints.items():
                config_name = f"{mask_name}_{var_name}_{alph_name}"

                # Compute palette enrichment for this config
                pal_count = sum(1 for _, c in constraints if c in PALETTE_SET)
                key_str = ''.join(c for _, c in constraints)

                configs.append({
                    'name': config_name,
                    'mask': mask,
                    'variant': var_name,
                    'alphabet': alph_name,
                    'constraints': constraints,
                    'key_string': key_str,
                    'palette_count': pal_count,
                })

    print(f"Configurations: {len(configs)} (5 masks × 3 variants × 2 alphabets)")
    print()

    # Show configurations sorted by palette enrichment
    print("── CONFIGURATIONS BY PALETTE ENRICHMENT ───────────────────────────")
    for cfg in sorted(configs, key=lambda c: -c['palette_count'])[:10]:
        print(f"  {cfg['name']:<40s} key={cfg['key_string']} pal={cfg['palette_count']}/24")
    print("  ...")
    print()

    # Build work items: each source × each config
    # For efficiency, only test top configs (highest palette enrichment) on the
    # full corpus, and test all configs on the smaller reference texts
    small_sources = [(n, p) for n, p in sources if not n.startswith('gutenberg/')]
    gut_sources = [(n, p) for n, p in sources if n.startswith('gutenberg/')]

    # Top configs by palette enrichment
    top_configs = sorted(configs, key=lambda c: -c['palette_count'])[:6]
    all_config_names = set(c['name'] for c in top_configs)

    work_items = []
    # All configs on small sources
    for source_name, source_path in small_sources:
        for cfg in configs:
            work_items.append((
                source_name, source_path, cfg['name'],
                cfg['constraints'], N_PT
            ))
    # Top configs on Gutenberg
    for source_name, source_path in gut_sources:
        for cfg in top_configs:
            work_items.append((
                source_name, source_path, cfg['name'],
                cfg['constraints'], N_PT
            ))

    print(f"Work items: {len(work_items)} ({len(small_sources)} small × {len(configs)} configs "
          f"+ {len(gut_sources)} Gutenberg × {len(top_configs)} top configs)")
    print(f"Workers: {N_WORKERS}")
    print()

    # Execute
    t_start = time.time()
    all_results = []
    total_windows = 0

    with Pool(N_WORKERS) as pool:
        for i, result in enumerate(pool.imap_unordered(_search_worker, work_items)):
            all_results.append(result)
            total_windows += result.get('n_windows', 0)
            if (i + 1) % 500 == 0 or i + 1 == len(work_items):
                elapsed = time.time() - t_start
                print(f"\r  Progress: {i+1:>6,}/{len(work_items):,} "
                      f"({100*(i+1)/len(work_items):.1f}%) "
                      f"Windows: {total_windows:,}  "
                      f"Time: {elapsed:.0f}s", end='', flush=True)

    t_total = time.time() - t_start
    print(f"\n\nComplete in {t_total:.1f}s. Total windows searched: {total_windows:,}")

    # ── Analysis ─────────────────────────────────────────────────────────────

    print("\n" + "=" * 78)
    print("RESULTS")
    print("=" * 78)

    # Aggregate: max matches per config
    config_maxes = {}
    for r in all_results:
        cfg = r['config']
        mx = r['max_matches']
        if cfg not in config_maxes or mx > config_maxes[cfg]['max']:
            config_maxes[cfg] = {
                'max': mx,
                'source': r['source'],
                'n_windows': r['n_windows'],
            }

    # Also track per-config total hits
    config_hits = Counter()
    config_windows = Counter()
    for r in all_results:
        config_hits[r['config']] += r['n_hits']
        config_windows[r['config']] += r['n_windows']

    print("\n── BEST MATCH PER CONFIGURATION ──────────────────────────────────")
    print(f"  {'Config':<40s} {'Max':>4s} {'Hits':>6s} {'Windows':>10s} {'Source'}")
    for cfg_name in sorted(config_maxes.keys(),
                            key=lambda c: -config_maxes[c]['max']):
        cm = config_maxes[cfg_name]
        nh = config_hits[cfg_name]
        nw = config_windows[cfg_name]
        print(f"  {cfg_name:<40s} {cm['max']:>4d} {nh:>6,} {nw:>10,} {cm['source']}")

    # Top individual hits across all configs
    print("\n── TOP HITS (all configs, sorted by match count) ─────────────────")
    all_hits = []
    for r in all_results:
        for h in r.get('hits', []):
            all_hits.append({
                'config': r['config'],
                'source': r['source'],
                **h,
            })

    all_hits.sort(key=lambda h: -h['n_matches'])
    print(f"  {'#':>3s} {'Mat':>4s} {'Config':<35s} {'Source':<30s} {'Key fragment (positions 10-30)'}")
    for i, h in enumerate(all_hits[:30]):
        frag = h['key_fragment'][10:30] if len(h['key_fragment']) > 30 else h['key_fragment'][:20]
        print(f"  {i+1:>3d} {h['n_matches']:>4d} {h['config']:<35s} {h['source']:<30s} {frag}")

    # Statistical significance
    print("\n── STATISTICAL SIGNIFICANCE ──────────────────────────────────────")
    if all_hits:
        best_match = all_hits[0]['n_matches']
        p_single = binomial_sf(best_match, N_CRIBS, 1.0 / 26)
        p_corrected = min(1.0, p_single * total_windows * len(configs))
        print(f"  Best match: {best_match}/24")
        print(f"  P(X >= {best_match}) single window: {p_single:.2e}")
        print(f"  Total windows × configs: {total_windows * len(configs):,}")
        print(f"  Bonferroni-corrected p-value: {p_corrected:.2e}")

        if p_corrected < 0.01:
            print(f"  *** STATISTICALLY SIGNIFICANT (p < 0.01) ***")
        elif p_corrected < 0.05:
            print(f"  ** Suggestive (p < 0.05) **")
        else:
            print(f"  Not significant after correction (p = {p_corrected:.2e})")

        # Expected distribution
        print(f"\n  Expected match distribution (Binomial(24, 1/26)):")
        for k in range(8):
            p_k = binomial_sf(k, 24, 1/26) - binomial_sf(k+1, 24, 1/26)
            expected = p_k * total_windows
            print(f"    k={k}: P={p_k:.4f}, expected {expected:,.0f} windows")
    else:
        print("  No hits found above threshold.")

    # Verdict
    print("\n── VERDICT ──────────────────────────────────────────────────────")
    if all_hits and all_hits[0]['n_matches'] >= 11:
        print("  SIGNAL: Potential running-key source identified.")
        print("  Next step: verify with full decryption and manual inspection.")
    elif all_hits and all_hits[0]['n_matches'] >= 7:
        print("  SUGGESTIVE: Some matches above random, but not conclusive.")
        print("  Could indicate: (a) near-miss source text, (b) related key,")
        print("  or (c) statistical fluctuation. Needs larger corpus or")
        print("  independent confirmation.")
    else:
        best = all_hits[0]['n_matches'] if all_hits else 0
        print(f"  NO SIGNAL: Best match {best}/24 is consistent with random.")
        print("  The source text is not in the tested corpus, OR the running-key")
        print("  model is wrong, OR the mask/variant is wrong.")
        print("  This is an INFORMATIVE NEGATIVE — it constrains the search space.")

    # ── Save results ─────────────────────────────────────────────────────────

    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'config': {
            'n_sources': len(sources),
            'n_configs': len(configs),
            'n_work_items': len(work_items),
            'total_windows': total_windows,
            'report_threshold': REPORT_THRESHOLD,
            'elapsed_seconds': round(t_total, 1),
        },
        'best_match': all_hits[0] if all_hits else None,
        'top_30_hits': all_hits[:30],
        'config_maxes': {k: v for k, v in config_maxes.items()},
        'statistical_significance': {
            'best_match': all_hits[0]['n_matches'] if all_hits else 0,
            'p_single': p_single if all_hits else 1.0,
            'p_corrected': p_corrected if all_hits else 1.0,
            'total_trials': total_windows * len(configs),
        } if all_hits else {},
    }

    outpath = os.path.join(_ROOT, 'results', 'running_key_palette_filter_01.json')
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {outpath}")


if __name__ == '__main__':
    main()
