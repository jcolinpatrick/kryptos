#!/usr/bin/env python3
"""
Cipher: stego_analysis
Family: analysis
Status: active
Keyspace: C(14,7) = 3,432 candidate masks
Last run:
Best score:
"""
"""
E-WIDTH21-MASK-RESOLUTION: Phase 5 — Resolve 7 Unknown Null Positions

Given:
  - 17 consensus null positions (confirmed)
  - 24 total nulls (from Sanborn's working notes)
  - 7 unknown nulls must come from 14 non-crib palette positions
  - C(14,7) = 3,432 candidate masks

For each candidate 24-null mask, score on multiple criteria:
  1. Width-21 repeated bigram count (stego signature, p=0.015 for actual)
  2. Width-7 repeated bigram count (cipher layer signal)
  3. CT73 IC (index of coincidence of extracted text)
  4. CT73 width-10 and width-17 bigram anomalies (cipher layer)
  5. Bean constraint compatibility on CT73
  6. Crib survival (all 24 crib positions must be non-null)

Output: results/width21_mask_resolution.json
Repro: PYTHONPATH=src python3 -u scripts/analysis/e_width21_mask_resolution.py
"""

import json
import sys
import os
import time
from itertools import combinations
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, CRIB_DICT, BEAN_EQ, BEAN_INEQ
)

# ── Setup ──
CT_NUM = [ALPH_IDX[c] for c in CT]
CONSENSUS = sorted(CONSENSUS_NULL_POSITIONS)

# All palette positions in CT
palette_positions = [i for i in range(CT_LEN) if CT[i] in NULL_PALETTE]

# Non-crib, non-consensus palette positions = candidates for 7 unknowns
candidates = [i for i in palette_positions
              if i not in CONSENSUS_NULL_POSITIONS and i not in CRIB_POSITIONS]

N_CHOOSE = 7
N_CANDIDATES = len(candidates)

print("=" * 70)
print("E-WIDTH21-MASK-RESOLUTION: Phase 5 — Resolve 7 Unknown Null Positions")
print("=" * 70)
print(f"Consensus nulls (17): {CONSENSUS}")
print(f"Candidate positions for 7 unknowns ({N_CANDIDATES}): {candidates}")
print(f"  Letters: {[CT[i] for i in candidates]}")
print(f"Search space: C({N_CANDIDATES},{N_CHOOSE}) = {len(list(combinations(candidates, N_CHOOSE)))}")
print()


# ── Scoring functions ──

def count_width_bigrams(text, width):
    """Count repeated vertical bigrams at given width."""
    bigrams = Counter()
    for i in range(len(text) - width):
        bg = (text[i], text[i + width])
        bigrams[bg] += 1
    return sum(v - 1 for v in bigrams.values() if v > 1)


def compute_ic(text):
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    numerator = sum(f * (f - 1) for f in freq.values())
    return numerator / (n * (n - 1))


def extract_ct(null_mask):
    """Extract ciphertext by removing null positions."""
    return "".join(CT[i] for i in range(CT_LEN) if i not in null_mask)


def check_bean_on_extracted(null_mask):
    """Check Bean constraints on the extracted text.

    Bean EQ: k[27] = k[65] in CT97 space. Both must survive null extraction.
    Bean INEQ: pairs of crib positions with distinct keystream values.

    For Bean to apply, the crib positions must map correctly in the extracted text.
    We check: do CT97 positions 27 and 65 both survive (not null)?
    """
    # Bean EQ positions
    for a, b in BEAN_EQ:
        if a in null_mask or b in null_mask:
            return None  # Can't evaluate — Bean position is null

    # All crib positions must survive
    for pos in CRIB_POSITIONS:
        if pos in null_mask:
            return False  # Crib destroyed

    return True  # Bean evaluable


def max_const_diff_window(ct_str):
    """Find max constant-difference window at any lag in the text."""
    n = len(ct_str)
    vals = [ALPH_IDX[c] for c in ct_str]
    best = 0
    for lag in range(1, min(49, n)):
        diffs = [(vals[i + lag] - vals[i]) % MOD for i in range(n - lag)]
        # Find longest run of same diff
        if not diffs:
            continue
        run = 1
        for j in range(1, len(diffs)):
            if diffs[j] == diffs[j - 1]:
                run += 1
                best = max(best, run + lag)  # window = run positions + lag
            else:
                run = 1
    return best


# ══════════════════════════════════════════════════════════════════════════
# MAIN SWEEP
# ══════════════════════════════════════════════════════════════════════════
print("Sweeping all 3,432 candidate masks...")
print("-" * 50)

t0 = time.time()
results = []

for combo in combinations(candidates, N_CHOOSE):
    # Build full 24-null mask
    null_mask = frozenset(CONSENSUS_NULL_POSITIONS | set(combo))
    assert len(null_mask) == 24, f"Expected 24, got {len(null_mask)}"

    # Verify no crib positions
    if null_mask & CRIB_POSITIONS:
        continue

    # Extract CT73
    ct73 = extract_ct(null_mask)
    assert len(ct73) == 73, f"Expected 73, got {len(ct73)}"

    # Score
    w21 = count_width_bigrams(ct73, 21)
    w7 = count_width_bigrams(ct73, 7)
    w10 = count_width_bigrams(ct73, 10)
    w17 = count_width_bigrams(ct73, 17)
    ic = compute_ic(ct73)

    # Width-21 on CT97 (with this mask's nulls in place)
    w21_ct97 = count_width_bigrams(CT, 21)  # Same for all masks (CT97 is fixed)

    # Bean check
    bean_ok = check_bean_on_extracted(null_mask)

    results.append({
        "extra_nulls": list(combo),
        "null_mask": sorted(null_mask),
        "ct73": ct73,
        "w21_ct73": w21,
        "w7_ct73": w7,
        "w10_ct73": w10,
        "w17_ct73": w17,
        "ic_ct73": round(ic, 6),
        "bean_ok": bean_ok,
        "combined_score": w21 * 3 + w10 * 2 + w17 * 2 + w7,  # Weighted sum
    })

elapsed = time.time() - t0
print(f"  Evaluated {len(results)} masks in {elapsed:.1f}s")

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("ANALYSIS")
print("=" * 70)

# Sort by width-21 bigrams on CT73 (primary), then combined score
results.sort(key=lambda r: (-r["w21_ct73"], -r["combined_score"]))

# Width-21 distribution
w21_dist = Counter(r["w21_ct73"] for r in results)
print(f"\nWidth-21 bigram distribution on CT73:")
for k in sorted(w21_dist.keys(), reverse=True):
    print(f"  w21={k}: {w21_dist[k]} masks ({100*w21_dist[k]/len(results):.1f}%)")

# What was the consensus-only (17 null) width-21?
ct80 = extract_ct(CONSENSUS_NULL_POSITIONS)
w21_consensus = count_width_bigrams(ct80, 21)
print(f"\nConsensus-only (17 nulls, 80-char): w21={w21_consensus}")

# Top masks by width-21
print(f"\n{'=' * 70}")
print("TOP 20 MASKS BY WIDTH-21 BIGRAMS ON CT73")
print("-" * 70)
for i, r in enumerate(results[:20]):
    print(f"  #{i+1}: w21={r['w21_ct73']}  w10={r['w10_ct73']}  w17={r['w17_ct73']}  "
          f"w7={r['w7_ct73']}  IC={r['ic_ct73']:.4f}  bean={r['bean_ok']}")
    print(f"       extra: {r['extra_nulls']} = {[CT[p] for p in r['extra_nulls']]}")
    print(f"       CT73: {r['ct73'][:60]}...")

# IC distribution
ics = [r["ic_ct73"] for r in results]
print(f"\nIC distribution: min={min(ics):.4f} max={max(ics):.4f} mean={sum(ics)/len(ics):.4f}")

# Sort by IC (highest = most likely to be real English-encrypted text)
results_by_ic = sorted(results, key=lambda r: -r["ic_ct73"])
print(f"\nTop 10 by IC:")
for i, r in enumerate(results_by_ic[:10]):
    print(f"  #{i+1}: IC={r['ic_ct73']:.4f}  w21={r['w21_ct73']}  w10={r['w10_ct73']}  "
          f"w17={r['w17_ct73']}  extra={r['extra_nulls']}")

# Combined analysis: masks that are top in BOTH w21 AND IC
print(f"\n{'=' * 70}")
print("COMBINED RANKING: w21 * IC")
print("-" * 50)
for r in results:
    r["joint_score"] = r["w21_ct73"] * r["ic_ct73"] * 1000

results_joint = sorted(results, key=lambda r: -r["joint_score"])
for i, r in enumerate(results_joint[:20]):
    print(f"  #{i+1}: joint={r['joint_score']:.2f}  w21={r['w21_ct73']}  IC={r['ic_ct73']:.4f}  "
          f"w10={r['w10_ct73']}  w17={r['w17_ct73']}  extra={r['extra_nulls']}")

# ══════════════════════════════════════════════════════════════════════════
# BEAN CONSTRAINT DEEP CHECK ON TOP MASKS
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("BEAN CONSTRAINT CHECK ON TOP 20 MASKS")
print("-" * 50)

# For the top masks by w21, check if Bean EQ position (27,65) is affected
for i, r in enumerate(results[:20]):
    mask = frozenset(r["null_mask"])
    eq_ok = all(a not in mask and b not in mask for a, b in BEAN_EQ)

    # Check which Bean INEQ pairs survive (both positions non-null)
    ineq_surviving = sum(1 for a, b in BEAN_INEQ if a not in mask and b not in mask)

    print(f"  #{i+1}: Bean EQ evaluable: {eq_ok}  INEQ surviving: {ineq_surviving}/{len(BEAN_INEQ)}  "
          f"extra={r['extra_nulls']}")


# ══════════════════════════════════════════════════════════════════════════
# WIDTH-21 BIGRAM DETAIL ON BEST MASK
# ══════════════════════════════════════════════════════════════════════════
if results:
    best = results[0]
    print(f"\n{'=' * 70}")
    print(f"BEST MASK DETAIL (w21={best['w21_ct73']})")
    print("-" * 50)
    print(f"  Full 24-null mask: {best['null_mask']}")
    print(f"  Extra 7 nulls: {best['extra_nulls']} = {[CT[p] for p in best['extra_nulls']]}")
    print(f"  CT73 ({len(best['ct73'])} chars): {best['ct73']}")
    print(f"  IC: {best['ic_ct73']:.4f}")

    # Show width-21 bigrams
    ct73 = best['ct73']
    bigrams_21 = Counter()
    for i in range(len(ct73) - 21):
        bg = (ct73[i], ct73[i + 21])
        bigrams_21[bg] += 1
    repeated = {bg: cnt for bg, cnt in bigrams_21.items() if cnt > 1}
    print(f"  Width-21 repeated bigrams: {len(repeated)}")
    for bg, cnt in sorted(repeated.items(), key=lambda x: -x[1]):
        positions = [i for i in range(len(ct73) - 21) if (ct73[i], ct73[i+21]) == bg]
        print(f"    {''.join(bg)} x{cnt} at CT73 positions {positions}")


# ══════════════════════════════════════════════════════════════════════════
# COMPARE CONSENSUS 6 KNOWN MASKS
# ══════════════════════════════════════════════════════════════════════════
# From prior work, 6 masks scored 15/24 with DEFECTOR model.
# Check if any of our top candidates match known masks.
print(f"\n{'=' * 70}")
print("SUMMARY")
print("=" * 70)
print(f"  Total masks evaluated: {len(results)}")
print(f"  Max w21 on CT73: {results[0]['w21_ct73']}")
print(f"  Masks achieving max w21: {sum(1 for r in results if r['w21_ct73'] == results[0]['w21_ct73'])}")
print(f"  Max IC: {max(ics):.4f}")
print(f"  Mean IC: {sum(ics)/len(ics):.4f}")
print(f"  Elapsed: {elapsed:.1f}s")


# ── Save artifact ──
os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
artifact = {
    "experiment": "E-WIDTH21-MASK-RESOLUTION",
    "description": "Phase 5: Width-21 based mask resolution — C(14,7)=3,432 candidate masks",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "consensus_nulls": CONSENSUS,
    "candidate_positions": candidates,
    "n_masks_evaluated": len(results),
    "w21_distribution": {str(k): v for k, v in sorted(w21_dist.items())},
    "top_20_by_w21": results[:20],
    "top_10_by_ic": results_by_ic[:10],
    "top_20_by_joint": results_joint[:20],
    "elapsed_seconds": round(elapsed, 1),
}

outpath = os.path.join(_ROOT, "results", "width21_mask_resolution.json")
with open(outpath, "w") as f:
    json.dump(artifact, f, indent=2, default=str)
print(f"\n  Artifact saved: {outpath}")
