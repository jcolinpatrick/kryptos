#!/usr/bin/env python3 -u
"""
=================================================================
CT MUTATION — NULL-MASK COL7 BEAUFORT WITH PALIMPSEST/DEFECTOR
=================================================================
Cipher:     Null mask + col7 transposition + Beaufort (autokey & periodic)
Family:     campaigns
Status:     active
Keyspace:   2,425 mutations × 8 configs = 19,400 decryptions (+8 baseline)
Last run:   never
Best score: --

HYPOTHESIS
----------
The 15/24 ceiling for PALIMPSEST/DEFECTOR null-mask+col7+Beaufort is due
to exactly one transcription error in K4. If the correct letter is
restored, crib score will exceed 15/24.

For each of 97×25=2,425 single-letter mutations:
  For each of {DEFECTOR_MASK, PALIMPSEST_MASK}:
    1. Extract 73 chars (remove 24 null positions)
    2. Apply inverse col7 columnar transposition
    3. Beaufort autokey decrypt with keyword
    4. Beaufort periodic decrypt with keyword
    5. Score crib hits (adjusted positions)

MATERIALLY NEW ASSUMPTION: single-letter CT error (not tested in prior
15/24 elimination which used canonical CT only).

NOTE: Autokey is structurally impossible (Tier 1), but we include it
as a baseline comparison since the 15/24 was reported in that context.
=================================================================
"""

import sys
import os
import json
import time
import statistics
from multiprocessing import Pool, cpu_count
from collections import Counter

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX

# ── Constants (from f_combined_defector_palimpsest_v1.py) ─────────

N = 97
N_NULLS = 24
N_PT = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63

# Known best masks from prior SA optimization
DEF_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
PAL_MASK = frozenset([6,8,9,12,14,18,19,35,37,38,46,50,57,60,61,74,75,76,77,78,79,81,84,96])

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DEFECTOR_NUMS = [ord(c)-65 for c in "DEFECTOR"]
PALIMPSEST_NUMS = [ord(c)-65 for c in "PALIMPSEST"]


# ── Col7 permutation ─────────────────────────────────────────────

def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))


# ── Cipher operations ────────────────────────────────────────────

def extract_73(ct_str, mask):
    """Extract 73 chars from CT by removing nulls at mask positions."""
    return ''.join(ct_str[i] for i in range(len(ct_str)) if i not in mask)

def apply_col7(text):
    """Apply col7 inverse transposition."""
    nums = [ord(c)-65 for c in text]
    return [nums[PERM_COL7[i]] for i in range(len(nums))]

def autokey_beau_az(ct_nums, kw_nums):
    """Beaufort PT-autokey decrypt."""
    L = len(kw_nums)
    pt = []
    for i, ci in enumerate(ct_nums):
        ki = kw_nums[i] if i < L else pt[i - L]
        pt.append((ki - ci) % 26)
    return pt

def periodic_beau(ct_nums, key_nums):
    """Periodic Beaufort decrypt (no autokey)."""
    L = len(key_nums)
    return [(key_nums[i % L] - ci) % 26 for i, ci in enumerate(ct_nums)]

def nums_to_text(nums):
    return ''.join(chr(n + 65) for n in nums)

def count_crib_hits_73(pt_str, null_set):
    """Score crib matches in 73-char plaintext (adjusted positions)."""
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s + j < len(pt_str) and pt_str[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s + j < len(pt_str) and pt_str[bcl_s + j] == c)
    return e + b, e, b


# ── Evaluation ────────────────────────────────────────────────────

def eval_ct(ct_str):
    """Evaluate one CT string across all mask/keyword/mode combos.
    Returns (best_score, best_ene, best_bcl, best_label, best_pt_preview)."""
    best = (0, 0, 0, "", "")

    for mask, mask_name in [(DEF_MASK, "DEF_MASK"), (PAL_MASK, "PAL_MASK")]:
        ct73 = extract_73(ct_str, mask)
        ct73_t = apply_col7(ct73)

        for kw_nums, kw_name in [(DEFECTOR_NUMS, "DEFECTOR"), (PALIMPSEST_NUMS, "PALIMPSEST")]:
            # Autokey Beaufort
            pt_nums = autokey_beau_az(ct73_t, kw_nums)
            pt_str = nums_to_text(pt_nums)
            total, e, b = count_crib_hits_73(pt_str, mask)
            if total > best[0]:
                best = (total, e, b, f"{mask_name}+col7+autokey_beau+{kw_name}", pt_str[:40])

            # Periodic Beaufort
            pt_nums = periodic_beau(ct73_t, kw_nums)
            pt_str = nums_to_text(pt_nums)
            total, e, b = count_crib_hits_73(pt_str, mask)
            if total > best[0]:
                best = (total, e, b, f"{mask_name}+col7+periodic_beau+{kw_name}", pt_str[:40])

    return best


def process_mutation(args):
    """Process a single CT mutation."""
    pos, orig, alt = args
    mut_ct = CT[:pos] + alt + CT[pos + 1:]
    score, ene, bcl, label, pt_preview = eval_ct(mut_ct)
    return (pos, orig, alt, score, ene, bcl, label, pt_preview)


def main():
    t0 = time.time()
    print("=" * 70)
    print("CT MUTATION — NULL-MASK COL7 BEAUFORT WITH PALIMPSEST/DEFECTOR")
    print("=" * 70)
    print(f"CT ({CT_LEN} chars): {CT}")
    print(f"DEF_MASK ({len(DEF_MASK)} pos): {sorted(DEF_MASK)}")
    print(f"PAL_MASK ({len(PAL_MASK)} pos): {sorted(PAL_MASK)}")
    print(f"Configs per mutation: 2 masks x 2 keywords x 2 modes = 8")
    print(f"Total mutations: {CT_LEN * 25}")
    print(f"Total decryptions: {CT_LEN * 25 * 8}")

    # ── Baseline ──────────────────────────────────────────────────
    print("\n--- BASELINE (unmutated CT) ---")
    base_score, base_ene, base_bcl, base_label, base_pt = eval_ct(CT)
    print(f"  Best score: {base_score}/24 (ene={base_ene}/13, bcl={base_bcl}/11)")
    print(f"  Config: {base_label}")
    print(f"  PT preview: {base_pt}")
    sys.stdout.flush()

    # ── Build work items ──────────────────────────────────────────
    work = []
    for pos in range(CT_LEN):
        orig = CT[pos]
        for alt_idx in range(26):
            alt = ALPHA[alt_idx]
            if alt == orig:
                continue
            work.append((pos, orig, alt))

    n_workers = max(1, min(cpu_count() - 2, 26))
    print(f"\n--- RUNNING {len(work)} mutations on {n_workers} workers ---")
    sys.stdout.flush()

    with Pool(n_workers) as pool:
        results = pool.map(process_mutation, work, chunksize=64)

    elapsed = time.time() - t0

    # ── Analysis ──────────────────────────────────────────────────
    scores = [r[3] for r in results]
    score_dist = Counter(scores)
    results_sorted = sorted(results, key=lambda x: x[3], reverse=True)

    print(f"\n{'=' * 70}")
    print(f"RESULTS (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")

    # Q1: Any score > 15?
    above_15 = [r for r in results if r[3] > 15]
    above_base = [r for r in results if r[3] > base_score]
    print(f"\n  Mutations with score > 15/24: {len(above_15)}")
    print(f"  Mutations with score > baseline ({base_score}): {len(above_base)}")
    if above_15:
        print("\n  ABOVE-15 DETAILS:")
        for r in sorted(above_15, key=lambda x: x[3], reverse=True)[:20]:
            print(f"    pos={r[0]:>2} {r[1]}->{r[2]} score={r[3]:>2}/24 (ene={r[4]}, bcl={r[5]}) {r[6]}")
            print(f"      PT: {r[7]}")

    # Q2: Top 20 mutations
    print(f"\n  TOP 20 MUTATIONS BY SCORE:")
    for i, r in enumerate(results_sorted[:20]):
        print(f"    {i+1:>2}. pos={r[0]:>2} {r[1]}->{r[2]} score={r[3]:>2}/24 (ene={r[4]}, bcl={r[5]}) {r[6]}")
        print(f"        PT: {r[7]}")

    # Q3: Score distribution
    print(f"\n  SCORE DISTRIBUTION (across {len(results)} mutations):")
    for score_val in sorted(score_dist.keys(), reverse=True):
        bar = "#" * min(score_dist[score_val], 60)
        print(f"    score={score_val:>2}: {score_dist[score_val]:>5} {bar}")

    # Summary statistics
    mean_s = statistics.mean(scores)
    med_s = statistics.median(scores)
    max_s = max(scores)
    std_s = statistics.stdev(scores)
    print(f"\n  Mean best score: {mean_s:.2f}")
    print(f"  Median: {med_s:.1f}")
    print(f"  Max: {max_s}")
    print(f"  Std dev: {std_s:.2f}")
    print(f"  Baseline: {base_score}/24 (ene={base_ene}, bcl={base_bcl})")

    # Position analysis: which CT positions produce highest scores when mutated?
    pos_best = {}
    for r in results:
        p = r[0]
        if p not in pos_best or r[3] > pos_best[p][3]:
            pos_best[p] = r
    pos_sorted = sorted(pos_best.values(), key=lambda x: x[3], reverse=True)
    print(f"\n  TOP 10 CT POSITIONS BY BEST MUTATION SCORE:")
    for i, r in enumerate(pos_sorted[:10]):
        in_def = r[0] in DEF_MASK
        in_pal = r[0] in PAL_MASK
        mask_note = f"{'DEF_null' if in_def else ''} {'PAL_null' if in_pal else ''}".strip()
        print(f"    pos={r[0]:>2} (CT={r[1]}) best_mut={r[2]} score={r[3]:>2}/24 {mask_note}")

    # Verdict
    print(f"\n  VERDICT:")
    if max_s > 15:
        print(f"  ** {len(above_15)} mutations exceed 15/24 ceiling — INVESTIGATE **")
        verdict = "INVESTIGATE"
    elif max_s > base_score:
        print(f"  Some mutations improve over baseline ({base_score} -> {max_s})")
        print(f"  but none exceed 15/24. Single-letter error does NOT break ceiling.")
        verdict = "NO_SIGNAL"
    else:
        print(f"  No mutation exceeds baseline ({base_score}/24).")
        print(f"  Single-letter CT error does NOT unlock null-mask Beaufort.")
        verdict = "NO_SIGNAL"

    # ── Save results ──────────────────────────────────────────────
    output = {
        "experiment": "e_ct_mutation_nullmask_beaufort",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_s": round(elapsed, 1),
        "baseline_score": base_score,
        "baseline_ene": base_ene,
        "baseline_bcl": base_bcl,
        "baseline_method": base_label,
        "masks": {
            "DEF_MASK": sorted(DEF_MASK),
            "PAL_MASK": sorted(PAL_MASK),
        },
        "n_mutations": len(work),
        "n_configs_per_mutation": 8,
        "n_decryptions": len(work) * 8,
        "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
        "max_score": max_s,
        "mean_score": round(mean_s, 2),
        "median_score": round(med_s, 1),
        "std_score": round(std_s, 2),
        "above_15_count": len(above_15),
        "above_baseline_count": len(above_base),
        "top_20": [
            {
                "pos": r[0], "orig": r[1], "alt": r[2],
                "score": r[3], "ene": r[4], "bcl": r[5],
                "method": r[6], "pt_preview": r[7]
            }
            for r in results_sorted[:20]
        ],
        "verdict": verdict,
    }
    out_path = os.path.join(_ROOT, "results", "e_ct_mutation_nullmask_beaufort.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved: {out_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
