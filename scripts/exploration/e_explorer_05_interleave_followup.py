#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-EXPLORER-05: Follow-up on H3 dual-system interleave 24/24 results.

E-EXPLORER-04 H3 found 81 configs scoring 24/24 with 4-way interleave
at period 7. This script investigates:

1. Why do these score 24/24? Is it underdetermination?
   - Count cribs per stream and per residue class
   - Check how many constraints each residue actually has

2. Decrypt all 81 configs and check language quality
   - Quadgram scoring
   - IC analysis
   - English word count

3. Monte Carlo baseline: what fraction of random 4-stream/p7 configs
   score 24/24?

4. If any survive language quality filtering, report them as genuine signals.

Constants from kryptos.kernel.constants. Scoring via score_candidate().
"""
from __future__ import annotations

import json
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ic import ic

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)

CT_NUMS = [ALPH_IDX[c] for c in CT]

SEED = 42
random.seed(SEED)


# ── Cipher functions ────────────────────────────────────────────────────

def decrypt_fn(variant: str, c: int, k: int) -> int:
    if variant == "vigenere":
        return (c - k) % MOD
    elif variant == "beaufort":
        return (k - c) % MOD
    else:  # var_beaufort
        return (c + k) % MOD


def recover_key(variant: str, c: int, p: int) -> int:
    if variant == "vigenere":
        return (c - p) % MOD
    elif variant == "beaufort":
        return (c + p) % MOD
    else:  # var_beaufort
        return (p - c) % MOD


# ── Analysis 1: Understand the underdetermination ───────────────────────

def analyze_underdetermination():
    """Analyze why 4-stream interleave at period 7 hits 24/24."""
    print("=" * 70)
    print("ANALYSIS 1: Underdetermination in 4-stream interleave")
    print("=" * 70)

    n_streams = 4
    period = 7

    # For each stream, figure out which crib positions land in it
    # and which residue class (mod period) they fall into within that stream
    for s in range(n_streams):
        print(f"\nStream {s} (CT positions {s}, {s+n_streams}, {s+2*n_streams}, ...):")
        stream_len = len(range(s, CT_LEN, n_streams))
        print(f"  Stream length: {stream_len}")

        # Map original positions to stream positions
        stream_pos_map = {}
        for i, orig_pos in enumerate(range(s, CT_LEN, n_streams)):
            stream_pos_map[orig_pos] = i

        # Find cribs in this stream
        stream_cribs = {}
        for pos, ch in CRIB_DICT.items():
            if pos in stream_pos_map:
                sp = stream_pos_map[pos]
                residue = sp % period
                stream_cribs[pos] = (sp, residue, ch)

        print(f"  Crib positions in this stream: {len(stream_cribs)}")

        # Group by residue
        by_residue = defaultdict(list)
        for pos, (sp, res, ch) in stream_cribs.items():
            by_residue[res].append((pos, sp, ch))

        for res in sorted(by_residue.keys()):
            entries = by_residue[res]
            print(f"    Residue {res}: {len(entries)} constraints")
            for pos, sp, ch in entries:
                ct_ch = CT[pos]
                print(f"      CT[{pos}]={ct_ch}, PT={ch}, stream_pos={sp}")

        # Count: how many residues have >= 2 constraints?
        multi_constraint = sum(1 for entries in by_residue.values() if len(entries) >= 2)
        single_constraint = sum(1 for entries in by_residue.values() if len(entries) == 1)
        unconstrained = period - len(by_residue)
        print(f"  Residues with >=2 constraints: {multi_constraint}")
        print(f"  Residues with 1 constraint: {single_constraint}")
        print(f"  Unconstrained residues: {unconstrained}")

    # Key insight: a periodic key at period p has p free parameters per stream.
    # Each crib position in a given residue class provides one equation.
    # If no residue class has >1 constraint, the key is completely underdetermined
    # and ANY key will score 24/24.
    print("\n--- KEY INSIGHT ---")
    print("If every residue class has at most 1 crib constraint,")
    print("then the key is ALWAYS consistent (1 equation, 1 unknown per residue).")
    print("This means 24/24 is GUARANTEED for any variant choice.")
    print("The 81 configs are a combinatorial artifact, not a signal.")


# ── Analysis 2: Decrypt the 24/24 configs and score language quality ────

def decrypt_interleave_config(
    n_streams: int,
    variants: List[str],
    periods: List[int],
) -> str:
    """Decrypt CT using interleaved multi-system cipher.

    For each stream s (positions s, s+n, s+2n, ...):
      Use variant[s] with periodic key of period[s].
      Key is derived from crib constraints (or arbitrary for unconstrained positions).
    """
    # Build key for each stream from crib constraints
    stream_keys = []
    for s in range(n_streams):
        variant = variants[s]
        period = periods[s]
        key = [None] * period  # None = unconstrained

        for i, orig_pos in enumerate(range(s, CT_LEN, n_streams)):
            if orig_pos in CRIB_DICT:
                residue = i % period
                c = CT_NUMS[orig_pos]
                p = ALPH_IDX[CRIB_DICT[orig_pos]]
                k = recover_key(variant, c, p)
                if key[residue] is not None and key[residue] != k:
                    return None  # inconsistent
                key[residue] = k

        # Fill unconstrained residues with 0 (arbitrary)
        for j in range(period):
            if key[j] is None:
                key[j] = 0

        stream_keys.append(key)

    # Decrypt
    pt = ['?'] * CT_LEN
    for s in range(n_streams):
        variant = variants[s]
        period = periods[s]
        key = stream_keys[s]
        for i, orig_pos in enumerate(range(s, CT_LEN, n_streams)):
            k = key[i % period]
            p = decrypt_fn(variant, CT_NUMS[orig_pos], k)
            pt[orig_pos] = ALPH[p]

    return "".join(pt)


def score_top_configs():
    """Decrypt and score the 24/24 interleave configs."""
    print("\n" + "=" * 70)
    print("ANALYSIS 2: Language quality of 24/24 interleave configs")
    print("=" * 70)

    # Load quadgram scorer
    try:
        from kryptos.kernel.scoring.ngram import NgramScorer
        qg_path = REPO_ROOT / "data" / "english_quadgrams.json"
        ngram_scorer = NgramScorer(str(qg_path))
        has_ngram = True
        print("Quadgram scorer loaded.")
    except Exception as e:
        print(f"No quadgram scorer available: {e}")
        has_ngram = False
        ngram_scorer = None

    variants_list = ["vigenere", "beaufort", "var_beaufort"]
    n_streams = 4
    period = 7

    results = []
    seen_pts = set()

    # Generate all 3^4 = 81 variant combos
    import itertools
    for var_combo in itertools.product(variants_list, repeat=n_streams):
        pt = decrypt_interleave_config(n_streams, list(var_combo), [period]*n_streams)
        if pt is None or pt in seen_pts:
            continue
        seen_pts.add(pt)

        ic_val = ic(pt)
        score = score_candidate(pt, ngram_scorer=ngram_scorer)

        result = {
            "variants": list(var_combo),
            "pt": pt,
            "ic": ic_val,
            "crib_score": score.crib_score,
            "ngram_per_char": score.ngram_per_char,
        }
        results.append(result)

    # Sort by ngram quality (best first)
    if has_ngram:
        results.sort(key=lambda x: x["ngram_per_char"] if x["ngram_per_char"] is not None else -999, reverse=True)
    else:
        results.sort(key=lambda x: x["ic"], reverse=True)

    print(f"\nUnique plaintexts generated: {len(results)}")

    # Show top 10
    print("\nTop 10 by language quality:")
    for i, r in enumerate(results[:10]):
        print(f"\n  #{i+1}: variants={r['variants']}")
        print(f"    PT: {r['pt'][:50]}...")
        print(f"    IC: {r['ic']:.4f}, crib={r['crib_score']}/24", end="")
        if r['ngram_per_char'] is not None:
            print(f", qg/c={r['ngram_per_char']:.3f}", end="")
        print()

    # Check if any pass the multi-objective thresholds
    # IC > 0.055, quadgram > -4.84/char
    survivors = [r for r in results
                 if r['ic'] > 0.055
                 and r.get('ngram_per_char') is not None
                 and r['ngram_per_char'] > -4.84]

    print(f"\nSurvivors (IC > 0.055 AND qg/c > -4.84): {len(survivors)}")
    if survivors:
        for r in survivors:
            print(f"  {r['variants']}: IC={r['ic']:.4f}, qg/c={r['ngram_per_char']:.3f}")
            print(f"    PT: {r['pt']}")

    return results


# ── Analysis 3: Monte Carlo baseline ─────────────────────────────────

def monte_carlo_interleave_baseline(n_trials: int = 10000):
    """What fraction of random 4-stream/p7 configs score 24/24?"""
    print("\n" + "=" * 70)
    print(f"ANALYSIS 3: Monte Carlo baseline ({n_trials} trials)")
    print("=" * 70)

    variants_list = ["vigenere", "beaufort", "var_beaufort"]
    n_streams = 4
    periods = [7, 7, 7, 7]

    hits_24 = 0
    score_dist = Counter()

    for trial in range(n_trials):
        # Random variant combo
        var_combo = [random.choice(variants_list) for _ in range(n_streams)]
        # Random periods (test varying periods too)
        if trial < n_trials // 2:
            trial_periods = [7, 7, 7, 7]
        else:
            trial_periods = [random.randint(1, 7) for _ in range(n_streams)]

        # Check consistency with cribs
        total_score = 0
        consistent = True

        for s in range(n_streams):
            variant = var_combo[s]
            period = trial_periods[s]

            # Recover key at crib positions
            key_residues: Dict[int, int] = {}

            for i, orig_pos in enumerate(range(s, CT_LEN, n_streams)):
                if orig_pos in CRIB_DICT:
                    residue = i % period
                    c = CT_NUMS[orig_pos]
                    p = ALPH_IDX[CRIB_DICT[orig_pos]]
                    k = recover_key(variant, c, p)

                    if residue in key_residues:
                        if key_residues[residue] != k:
                            consistent = False
                            break
                    else:
                        key_residues[residue] = k

            if not consistent:
                break

            # Count cribs in this stream
            stream_score = sum(1 for pos in CRIB_DICT if pos % n_streams == s)
            total_score += stream_score

        if not consistent:
            total_score = 0

        score_dist[total_score] += 1
        if total_score == 24:
            hits_24 += 1

    pct_24 = hits_24 / n_trials * 100
    print(f"Score distribution:")
    for score in sorted(score_dist.keys()):
        pct = score_dist[score] / n_trials * 100
        print(f"  {score}/24: {score_dist[score]} ({pct:.1f}%)")
    print(f"\nFraction scoring 24/24: {hits_24}/{n_trials} ({pct_24:.1f}%)")
    print(f"This {'IS' if pct_24 > 50 else 'is NOT'} consistent with pure underdetermination.")

    return {"n_trials": n_trials, "hits_24": hits_24, "pct_24": pct_24, "distribution": dict(score_dist)}


# ── Analysis 4: What about smaller n_streams? ───────────────────────────

def test_smaller_interleave():
    """Test 2-way and 3-way interleave more carefully.

    For 2-way interleave, each stream has ~48 chars and more crib constraints.
    These might NOT be underdetermined.
    """
    print("\n" + "=" * 70)
    print("ANALYSIS 4: 2-way and 3-way interleave (better constrained)")
    print("=" * 70)

    variants_list = ["vigenere", "beaufort", "var_beaufort"]

    for n_streams in [2, 3]:
        print(f"\n--- {n_streams}-way interleave ---")

        # Enumerate crib distribution
        for s in range(n_streams):
            crib_count = sum(1 for pos in CRIB_DICT if pos % n_streams == s)
            stream_len = len(range(s, CT_LEN, n_streams))
            print(f"  Stream {s}: {stream_len} chars, {crib_count} cribs")

        # Test all variant combos with periods 1-7
        best_score = 0
        best_cfg = None
        consistent_24 = 0
        total_tested = 0

        import itertools
        for var_combo in itertools.product(variants_list, repeat=n_streams):
            for periods in itertools.product(range(1, 8), repeat=n_streams):
                total_tested += 1
                all_consistent = True
                total_crib_score = 0

                for s in range(n_streams):
                    variant = var_combo[s]
                    period = periods[s]
                    key_residues: Dict[int, int] = {}
                    consistent = True

                    for i, orig_pos in enumerate(range(s, CT_LEN, n_streams)):
                        if orig_pos in CRIB_DICT:
                            residue = i % period
                            c = CT_NUMS[orig_pos]
                            p = ALPH_IDX[CRIB_DICT[orig_pos]]
                            k = recover_key(variant, c, p)
                            if residue in key_residues:
                                if key_residues[residue] != k:
                                    consistent = False
                                    break
                            else:
                                key_residues[residue] = k

                    if not consistent:
                        all_consistent = False
                        break
                    total_crib_score += sum(1 for pos in CRIB_DICT if pos % n_streams == s)

                if all_consistent:
                    if total_crib_score > best_score:
                        best_score = total_crib_score
                        best_cfg = {"variants": list(var_combo), "periods": list(periods)}
                    if total_crib_score == 24:
                        consistent_24 += 1

        print(f"  Total tested: {total_tested}")
        print(f"  Best score: {best_score}/24")
        print(f"  Configs scoring 24/24: {consistent_24}")
        pct = consistent_24 / total_tested * 100
        print(f"  Fraction: {pct:.2f}%")

        if consistent_24 > 0 and consistent_24 < 50:
            print(f"  NOTE: Only {consistent_24} configs at 24/24 — worth investigating!")
        elif consistent_24 == 0:
            print(f"  NOTE: ZERO configs at 24/24 — eliminates {n_streams}-way interleave + periodic p<=7.")


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("E-EXPLORER-05: Interleave Follow-up Investigation")
    print(f"CT: {CT[:20]}...{CT[-10:]}")

    t0 = time.time()

    # 1. Understand the structure
    analyze_underdetermination()

    # 2. Score the "winners"
    top_results = score_top_configs()

    # 3. Monte Carlo
    mc = monte_carlo_interleave_baseline(n_trials=10000)

    # 4. Smaller interleaves
    test_smaller_interleave()

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print("FINAL VERDICT")
    print("=" * 70)
    print(f"Time: {elapsed:.1f}s")
    print()

    if mc["pct_24"] > 50:
        print("VERDICT: 4-way interleave / period 7 is MASSIVELY UNDERDETERMINED.")
        print("  24/24 scores are combinatorial artifacts, not signals.")
        print("  The effective period per stream is too large relative to the")
        print("  number of crib constraints per stream.")
    else:
        print("VERDICT: Some structural constraint exists. Investigate further.")

    # Check 2/3-way results
    print("\nSmaller interleaves provide genuine constraints when")
    print("enough cribs fall in the same residue class per stream.")

    # Save
    out_path = ARTIFACTS_DIR / "explorer_05_interleave_followup.json"
    with open(out_path, "w") as f:
        json.dump({
            "monte_carlo": mc,
            "top_configs": [{"variants": r["variants"], "ic": r["ic"],
                             "ngram_per_char": r["ngram_per_char"],
                             "pt_preview": r["pt"][:50]}
                            for r in top_results[:10]],
        }, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
