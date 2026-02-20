#!/usr/bin/env python3
"""E-FRAC-02: Width-9 Columnar + Non-Periodic Substitution Models.

Tests all 362,880 width-9 column orderings against substitution models
that E-S-133 did NOT cover:

1. Progressive key: key[i] = (a + b*i) mod 26. 676 params per ordering.
2. CT-autokey: key[0] = seed, key[i+1] = CT[i]. 26 seeds per ordering.
3. PT-autokey: key[0] = seed, key[i+1] = PT[i]. Algebraically determined.
4. Running key quality: derive key at crib positions, score for English
   plausibility (IC of key fragment, repeated-letter rate).
5. Column-progressive: key[i] = base[col] + row*step[col], independent
   per column. Tests position-dependent alphabets with linear structure.

Strategy:
- First pass: all 362,880 orderings × cheap tests (Bean filter + progressive + autokey)
- Focus analysis on Bean-passing orderings (~4,860)
- Report any score above noise for deeper investigation

Usage: PYTHONPATH=src python3 -u jobs/pending/e_frac_02_w9_nonperiodic.py [--workers N]
"""
import argparse
import itertools
import json
import math
import os
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

WIDTH = 9
N_ROWS_FULL = CT_LEN // WIDTH      # 10
REMAINDER = CT_LEN % WIDTH          # 7
COL_HEIGHTS = [N_ROWS_FULL + 1 if j < REMAINDER else N_ROWS_FULL
               for j in range(WIDTH)]


def build_columnar_perm(order):
    """Build gather permutation: output[i] = input[perm[i]]."""
    perm = []
    for c in range(WIDTH):
        col = order[c]
        height = COL_HEIGHTS[col]
        for row in range(height):
            perm.append(row * WIDTH + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ═══════════════════════════════════════════════════════════════════════════
# Model B: trans→sub. CT[i] = sub(PT[perm[i]], key[i])
# Key recovery: key[i] = variant(CT[i], PT[perm[i]])
# ═══════════════════════════════════════════════════════════════════════════

def derive_keys_model_b(perm, variant):
    """Derive key values at crib-constrained positions. Model B."""
    keys = {}
    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = CT_NUM[i]
            if variant == 0:    # Vigenère: key = (CT - PT) mod 26
                keys[i] = (ct_val - pt_val) % MOD
            elif variant == 1:  # Beaufort: key = (CT + PT) mod 26
                keys[i] = (ct_val + pt_val) % MOD
            else:               # Variant Beaufort: key = (PT - CT) mod 26
                keys[i] = (pt_val - ct_val) % MOD
    return keys


def check_bean_model_b(perm, variant):
    """Check Bean constraints under Model B."""
    inv_perm = invert_perm(perm)
    # Bean equality: key at CT positions corresponding to PT positions 27, 65
    ct_27 = inv_perm[27]
    ct_65 = inv_perm[65]
    pt27 = CRIB_PT_NUM[27]
    pt65 = CRIB_PT_NUM[65]

    if variant == 0:
        k27 = (CT_NUM[ct_27] - pt27) % MOD
        k65 = (CT_NUM[ct_65] - pt65) % MOD
    elif variant == 1:
        k27 = (CT_NUM[ct_27] + pt27) % MOD
        k65 = (CT_NUM[ct_65] + pt65) % MOD
    else:
        k27 = (pt27 - CT_NUM[ct_27]) % MOD
        k65 = (pt65 - CT_NUM[ct_65]) % MOD

    if k27 != k65:
        return False

    # Bean inequalities
    for a, b in BEAN_INEQ:
        if a in CRIB_SET and b in CRIB_SET:
            ct_a = inv_perm[a]
            ct_b = inv_perm[b]
            if variant == 0:
                ka = (CT_NUM[ct_a] - CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] - CRIB_PT_NUM[b]) % MOD
            elif variant == 1:
                ka = (CT_NUM[ct_a] + CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] + CRIB_PT_NUM[b]) % MOD
            else:
                ka = (CRIB_PT_NUM[a] - CT_NUM[ct_a]) % MOD
                kb = (CRIB_PT_NUM[b] - CT_NUM[ct_b]) % MOD
            if ka == kb:
                return False
    return True


# ═══════════════════════════════════════════════════════════════════════════
# Test 1: Progressive key — key[i] = (a + b*i) mod 26
# ═══════════════════════════════════════════════════════════════════════════

def test_progressive_key(keys_dict):
    """Test if derived keys fit key[pos] = (a + b*pos) mod 26.

    Returns (best_matches, best_a, best_b, total_constrained).
    """
    positions = sorted(keys_dict.keys())
    values = [keys_dict[p] for p in positions]
    n = len(positions)
    if n < 2:
        return 0, 0, 0, n

    best_matches = 0
    best_a = 0
    best_b = 0

    for a in range(MOD):
        for b in range(MOD):
            matches = sum(1 for p, v in zip(positions, values)
                          if (a + b * p) % MOD == v)
            if matches > best_matches:
                best_matches = matches
                best_a = a
                best_b = b

    return best_matches, best_a, best_b, n


# ═══════════════════════════════════════════════════════════════════════════
# Test 2: CT-autokey — key[0] = seed, key[i] = CT[i-1] for i > 0
# ═══════════════════════════════════════════════════════════════════════════

def test_ct_autokey(keys_dict, variant):
    """Test if keys are consistent with CT-autokey.

    Under CT-autokey: key[i] = CT[i-1] for i > 0, key[0] = seed.
    Check how many constrained positions have key[i] == CT_NUM[i-1].
    """
    best_matches = 0
    best_seed = 0

    for seed in range(MOD):
        matches = 0
        for pos, kval in keys_dict.items():
            if pos == 0:
                if kval == seed:
                    matches += 1
            else:
                expected = CT_NUM[pos - 1]
                if kval == expected:
                    matches += 1
        if matches > best_matches:
            best_matches = matches
            best_seed = seed

    return best_matches, best_seed, len(keys_dict)


# ═══════════════════════════════════════════════════════════════════════════
# Test 3: PT-autokey — key[0] = seed, key[i] = PT[i-1]
# Under Model B: PT[perm[i]] is the plaintext at CT position i.
# key[i] = PT_at_ct_pos[i-1] (the PT value that was at CT position i-1)
# PT_at_ct_pos[i] = decrypted via key[i]:
#   Vig: PT = (CT[i] - key[i]) mod 26
#   Beau: PT = (key[i] - CT[i]) mod 26
#   VB: PT = (CT[i] + key[i]) mod 26
#
# Chain: key[0] = seed
#        PT_at_ct_pos[0] = decrypt(CT[0], key[0])
#        key[1] = PT_at_ct_pos[0]
#        PT_at_ct_pos[1] = decrypt(CT[1], key[1])
#        key[2] = PT_at_ct_pos[1]
#        ...
# This is fully determined by the seed.
# ═══════════════════════════════════════════════════════════════════════════

def test_pt_autokey(perm, variant):
    """Test PT-autokey consistency.

    For each seed (0-25), generate the full key sequence and check
    how many crib positions match.
    """
    best_matches = 0
    best_seed = 0

    for seed in range(MOD):
        key = [0] * CT_LEN
        key[0] = seed

        # Generate key and plaintext chain
        for i in range(CT_LEN):
            ct_val = CT_NUM[i]
            k = key[i]
            if variant == 0:    # Vig: PT = (CT - key) mod 26
                pt_val = (ct_val - k) % MOD
            elif variant == 1:  # Beau: PT = (key - CT) mod 26
                pt_val = (k - ct_val) % MOD
            else:               # VB: PT = (CT + key) mod 26
                pt_val = (ct_val + k) % MOD

            if i + 1 < CT_LEN:
                key[i + 1] = pt_val  # Next key = this plaintext

        # Check crib consistency
        matches = 0
        for i, src in enumerate(perm):
            if src in CRIB_SET:
                ct_val = CT_NUM[i]
                k = key[i]
                if variant == 0:
                    pt_val = (ct_val - k) % MOD
                elif variant == 1:
                    pt_val = (k - ct_val) % MOD
                else:
                    pt_val = (ct_val + k) % MOD
                if pt_val == CRIB_PT_NUM[src]:
                    matches += 1

        if matches > best_matches:
            best_matches = matches
            best_seed = seed

    return best_matches, best_seed, 24


# ═══════════════════════════════════════════════════════════════════════════
# Test 4: Running key quality — IC and bigram plausibility of key fragment
# ═══════════════════════════════════════════════════════════════════════════

def assess_key_quality(keys_dict):
    """Assess whether derived key values look like English text.

    Metrics:
    - IC of key fragment (English ~0.067, random ~0.038)
    - Repeated-letter rate (consecutive key positions with same value)
    - Unique value ratio (English text has fewer unique letters per unit)
    """
    positions = sorted(keys_dict.keys())
    values = [keys_dict[p] for p in positions]
    n = len(values)

    if n < 4:
        return {"ic": 0.0, "repeats": 0, "unique_ratio": 1.0, "n": n}

    # IC of key values
    freq = Counter(values)
    ic_num = sum(f * (f - 1) for f in freq.values())
    ic_den = n * (n - 1)
    ic_val = ic_num / ic_den if ic_den > 0 else 0.0

    # Repeated consecutive values (but positions may not be consecutive)
    # Check adjacent constrained positions
    repeats = 0
    for i in range(len(positions) - 1):
        if positions[i + 1] == positions[i] + 1:  # truly consecutive
            if values[i] == values[i + 1]:
                repeats += 1

    unique_ratio = len(set(values)) / n

    return {"ic": ic_val, "repeats": repeats, "unique_ratio": unique_ratio, "n": n}


# ═══════════════════════════════════════════════════════════════════════════
# Test 5: Column-progressive key
# key[i] = base[col(i)] + step[col(i)] * row(i), where col/row come from
# the position in the PT grid: col = perm[i] % WIDTH, row = perm[i] // WIDTH
# ═══════════════════════════════════════════════════════════════════════════

def test_column_progressive(keys_dict, perm):
    """Test column-progressive key model.

    For each column (0-8), independently fit key = base + step*row.
    Count total matches across all columns.
    """
    # Group constrained positions by their PT column
    col_groups = defaultdict(list)  # pt_col -> [(ct_pos, key_val, pt_row)]
    for ct_pos, kval in keys_dict.items():
        pt_pos = perm[ct_pos]
        pt_col = pt_pos % WIDTH
        pt_row = pt_pos // WIDTH
        col_groups[pt_col].append((ct_pos, kval, pt_row))

    total_matches = 0
    total_constrained = 0

    for col in range(WIDTH):
        entries = col_groups[col]
        if len(entries) < 2:
            total_matches += len(entries)  # Trivially matches
            total_constrained += len(entries)
            continue

        total_constrained += len(entries)
        best_col_matches = 0

        # Try all (base, step) for this column
        for base in range(MOD):
            for step in range(MOD):
                matches = sum(1 for _, kval, row in entries
                              if (base + step * row) % MOD == kval)
                if matches > best_col_matches:
                    best_col_matches = matches

        total_matches += best_col_matches

    return total_matches, total_constrained


# ═══════════════════════════════════════════════════════════════════════════
# Worker function for parallel processing
# ═══════════════════════════════════════════════════════════════════════════

def process_ordering_batch(orderings):
    """Process a batch of orderings, return best results."""
    VARIANT_NAMES = ["vigenere", "beaufort", "variant_beaufort"]

    results = []
    for order in orderings:
        perm = build_columnar_perm(order)

        for variant in range(3):
            # Bean filter first
            if not check_bean_model_b(perm, variant):
                continue

            keys = derive_keys_model_b(perm, variant)

            # Test 1: Progressive key
            prog_matches, prog_a, prog_b, prog_n = test_progressive_key(keys)

            # Test 2: CT-autokey
            ct_ak_matches, ct_ak_seed, ct_ak_n = test_ct_autokey(keys, variant)

            # Test 3: PT-autokey
            pt_ak_matches, pt_ak_seed, pt_ak_n = test_pt_autokey(perm, variant)

            # Test 4: Key quality
            quality = assess_key_quality(keys)

            # Test 5: Column-progressive
            col_prog_matches, col_prog_n = test_column_progressive(keys, perm)

            # Record if any test shows interesting results
            max_score = max(prog_matches, ct_ak_matches, pt_ak_matches, col_prog_matches)
            if max_score >= 8:  # Only record interesting results
                results.append({
                    "order": list(order),
                    "variant": VARIANT_NAMES[variant],
                    "progressive": {"matches": prog_matches, "a": prog_a,
                                    "b": prog_b, "n": prog_n},
                    "ct_autokey": {"matches": ct_ak_matches, "seed": ct_ak_seed,
                                   "n": ct_ak_n},
                    "pt_autokey": {"matches": pt_ak_matches, "seed": pt_ak_seed,
                                   "n": pt_ak_n},
                    "key_quality": quality,
                    "col_progressive": {"matches": col_prog_matches,
                                        "n": col_prog_n},
                    "max_score": max_score,
                })

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--fast", action="store_true",
                        help="Sample 10% of orderings for quick test")
    args = parser.parse_args()

    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-02: Width-9 Columnar + Non-Periodic Substitution Models")
    print("=" * 70)
    print(f"Workers: {args.workers}")
    print(f"Fast mode: {args.fast}")
    print()

    # Generate all orderings
    all_orderings = list(itertools.permutations(range(WIDTH)))
    if args.fast:
        import random
        random.seed(42)
        all_orderings = random.sample(all_orderings, len(all_orderings) // 10)
    print(f"Orderings to test: {len(all_orderings):,}")

    # First pass: count Bean-passing orderings per variant
    print("\nPhase 1: Bean filtering...")
    bean_counts = {0: 0, 1: 0, 2: 0}
    for order in all_orderings:
        perm = build_columnar_perm(order)
        for v in range(3):
            if check_bean_model_b(perm, v):
                bean_counts[v] += 1
    print(f"  Bean passes: Vig={bean_counts[0]}, Beau={bean_counts[1]}, VB={bean_counts[2]}")
    total_bean = sum(bean_counts.values())
    print(f"  Total configs after Bean filter: {total_bean:,}")

    # Batch orderings for parallel processing
    print(f"\nPhase 2: Testing non-periodic substitution models...")
    batch_size = max(1, len(all_orderings) // (args.workers * 20))
    batches = []
    for i in range(0, len(all_orderings), batch_size):
        batches.append(all_orderings[i:i + batch_size])
    print(f"  Batches: {len(batches)} × ~{batch_size}")

    all_results = []
    completed_batches = 0
    last_report = t0

    if args.workers <= 1:
        # Single-process mode
        for batch in batches:
            batch_results = process_ordering_batch(batch)
            all_results.extend(batch_results)
            completed_batches += 1
            now = time.time()
            if now - last_report > 30:
                pct = 100 * completed_batches / len(batches)
                elapsed = now - t0
                rate = completed_batches / elapsed
                eta = (len(batches) - completed_batches) / rate if rate > 0 else 0
                print(f"  [{pct:5.1f}%] {completed_batches}/{len(batches)} batches, "
                      f"results so far: {len(all_results)}, ETA: {eta:.0f}s")
                last_report = now
    else:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_ordering_batch, batch): i
                       for i, batch in enumerate(batches)}
            for future in as_completed(futures):
                batch_results = future.result()
                all_results.extend(batch_results)
                completed_batches += 1
                now = time.time()
                if now - last_report > 30:
                    pct = 100 * completed_batches / len(batches)
                    elapsed = now - t0
                    rate = completed_batches / elapsed
                    eta = (len(batches) - completed_batches) / rate if rate > 0 else 0
                    print(f"  [{pct:5.1f}%] {completed_batches}/{len(batches)} batches, "
                          f"results so far: {len(all_results)}, ETA: {eta:.0f}s")
                    last_report = now

    elapsed = time.time() - t0

    # ── Analysis ──────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total results (score >= 8): {len(all_results)}")
    print(f"Total orderings tested: {len(all_orderings):,}")
    print(f"Time: {elapsed:.1f}s")
    print()

    if not all_results:
        print("NO results above threshold 8/24.")
        print("VERDICT: ELIMINATED — no non-periodic model shows signal")
    else:
        # Sort by max score
        all_results.sort(key=lambda r: r["max_score"], reverse=True)

        # Best by each test
        best_prog = max(all_results, key=lambda r: r["progressive"]["matches"])
        best_ct_ak = max(all_results, key=lambda r: r["ct_autokey"]["matches"])
        best_pt_ak = max(all_results, key=lambda r: r["pt_autokey"]["matches"])
        best_col_prog = max(all_results, key=lambda r: r["col_progressive"]["matches"])

        print("BEST BY TEST:")
        print(f"  Progressive: {best_prog['progressive']['matches']}/24 "
              f"(a={best_prog['progressive']['a']}, b={best_prog['progressive']['b']}) "
              f"order={best_prog['order']} {best_prog['variant']}")
        print(f"  CT-autokey:  {best_ct_ak['ct_autokey']['matches']}/24 "
              f"(seed={best_ct_ak['ct_autokey']['seed']}) "
              f"order={best_ct_ak['order']} {best_ct_ak['variant']}")
        print(f"  PT-autokey:  {best_pt_ak['pt_autokey']['matches']}/24 "
              f"(seed={best_pt_ak['pt_autokey']['seed']}) "
              f"order={best_pt_ak['order']} {best_pt_ak['variant']}")
        print(f"  Col-prog:    {best_col_prog['col_progressive']['matches']}/24 "
              f"order={best_col_prog['order']} {best_col_prog['variant']}")
        print()

        # Distribution of max scores
        max_score_dist = Counter(r["max_score"] for r in all_results)
        print("MAX SCORE DISTRIBUTION (across all non-periodic tests):")
        for sc in sorted(max_score_dist.keys(), reverse=True):
            print(f"  {sc:2d}/24: {max_score_dist[sc]:,}")
        print()

        # Top 20 overall
        print("TOP 20 RESULTS:")
        for i, r in enumerate(all_results[:20]):
            print(f"  #{i+1}: max={r['max_score']}/24 order={r['order']} "
                  f"{r['variant']} "
                  f"prog={r['progressive']['matches']} "
                  f"ct_ak={r['ct_autokey']['matches']} "
                  f"pt_ak={r['pt_autokey']['matches']} "
                  f"col_prog={r['col_progressive']['matches']}")
        print()

        # Key quality statistics
        print("KEY QUALITY STATISTICS (for Bean-passing orderings):")
        ics = [r["key_quality"]["ic"] for r in all_results]
        if ics:
            print(f"  Key IC: mean={sum(ics)/len(ics):.4f}, "
                  f"min={min(ics):.4f}, max={max(ics):.4f}")
            print(f"  (English ~0.067, random ~0.038)")

        uniq_ratios = [r["key_quality"]["unique_ratio"] for r in all_results]
        if uniq_ratios:
            print(f"  Unique ratio: mean={sum(uniq_ratios)/len(uniq_ratios):.3f}, "
                  f"min={min(uniq_ratios):.3f}, max={max(uniq_ratios):.3f}")

        # Compute noise floor
        # For progressive key with 24 constrained positions, expected random:
        # Each position has 1/26 chance of matching. With 676 (a,b) pairs,
        # expected max matches ≈ ???
        print()
        print("NOISE FLOOR ESTIMATES:")
        print("  Progressive: ~24*(1/26)*676_trials ≈ expect max ~5-6 from random")
        print("  CT-autokey: ~24*(1/26) ≈ 0.92 expected, max from 26 seeds ~2-3")
        print("  PT-autokey: similar to CT-autokey")
        print("  Col-prog: higher due to per-column fitting (up to 676 params per column)")

        # Verdict
        best_overall = all_results[0]["max_score"]
        if best_overall >= 18:
            verdict = "SIGNAL — investigate further"
        elif best_overall >= 10:
            verdict = f"STORE — best {best_overall}/24, above noise but needs calibration"
        else:
            verdict = f"NOISE — best {best_overall}/24, within expected range"

        print()
        print(f"VERDICT: {verdict}")

    # ── Save artifacts ─────────────────────────────────────────────────
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-02",
        "description": "Width-9 columnar + non-periodic substitution models",
        "width": WIDTH,
        "n_orderings": len(all_orderings),
        "bean_passes": bean_counts,
        "n_results_above_8": len(all_results),
        "top_results": [r for r in all_results[:100]],
        "elapsed_seconds": round(elapsed, 1),
        "fast_mode": args.fast,
    }
    if all_results:
        artifact["best_progressive"] = best_prog
        artifact["best_ct_autokey"] = best_ct_ak
        artifact["best_pt_autokey"] = best_pt_ak
        artifact["best_col_progressive"] = best_col_prog
        artifact["verdict"] = verdict

    path = "results/frac/e_frac_02_w9_nonperiodic.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")

    best_score = all_results[0]["max_score"] if all_results else 0
    print(f"\nRESULT: best={best_score}/24 configs={total_bean} "
          f"verdict={'SIGNAL' if best_score >= 18 else 'ELIMINATED' if best_score <= 8 else 'STORE'}")


if __name__ == "__main__":
    main()
