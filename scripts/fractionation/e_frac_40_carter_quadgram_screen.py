#!/usr/bin/env python3
"""
Cipher: running key
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-40: Carter Running Key + Transposition Quadgram Screening

For each Bean-passing, matching=24 offset in Carter's text, optimize the
transposition permutation for quadgram fitness using simulated annealing.
This directly tests whether Carter's text could be the running key source
by checking if ANY (offset, transposition) pair produces English-like
plaintext (quadgram > -5.0/char, per E-FRAC-34 threshold).

Method:
  1. Find all feasible offsets (matching=24 + Bean full pass) from E-FRAC-39
  2. For each, find one bipartite matching for 24 crib positions
  3. SA over remaining 73 position assignments to maximize quadgram score
  4. Report best quadgram per offset and overall

If best quadgram across all offsets < -5.0/char, Carter running key +
arbitrary transposition is LIKELY NOT the answer (same pattern as
E-FRAC-34 false positives).
"""
import json
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

# Convert CT to numbers
CT_NUM = [ALPH_IDX[c] for c in CT]
CT_LETTER_POSITIONS = {}
for j, v in enumerate(CT_NUM):
    CT_LETTER_POSITIONS.setdefault(v, []).append(j)

# Crib data
CRIB_POS = [pos for pos, _ in CRIB_ENTRIES]
CRIB_PT_NUM = [ALPH_IDX[ch] for _, ch in CRIB_ENTRIES]
CRIB_SET = set(CRIB_POS)
NON_CRIB_POS = sorted(set(range(CT_LEN)) - CRIB_SET)

# Load quadgrams
BASE = os.path.dirname(os.path.dirname(__file__))
with open(os.path.join(BASE, 'data', 'english_quadgrams.json')) as f:
    QUADGRAMS = json.load(f)

# Default score for unknown quadgrams (floor)
QG_FLOOR = -7.0


def quadgram_score(text_nums: list[int]) -> float:
    """Compute quadgram fitness score (log-probability per character)."""
    total = 0.0
    n_quads = 0
    for i in range(len(text_nums) - 3):
        qg = chr(text_nums[i] + 65) + chr(text_nums[i+1] + 65) + \
             chr(text_nums[i+2] + 65) + chr(text_nums[i+3] + 65)
        total += QUADGRAMS.get(qg, QG_FLOOR)
        n_quads += 1
    return total / n_quads if n_quads > 0 else QG_FLOOR


def check_bean(key_nums: list[int]) -> tuple[bool, bool]:
    """Check Bean constraints. Returns (eq_pass, full_pass)."""
    for eq_a, eq_b in BEAN_EQ:
        if key_nums[eq_a] != key_nums[eq_b]:
            return False, False
    for ineq_a, ineq_b in BEAN_INEQ:
        if key_nums[ineq_a] == key_nums[ineq_b]:
            return True, False
    return True, True


def max_bipartite_matching_with_assignment(adj, n_left, n_right):
    """Find max matching and return (size, assignment).
    assignment[i] = right-node matched to left-node i, or -1.
    """
    match_right = [-1] * n_right
    match_left = [-1] * n_left

    def augment(u, visited):
        for v in adj[u]:
            if not visited[v]:
                visited[v] = True
                if match_right[v] == -1 or augment(match_right[v], visited):
                    match_right[v] = u
                    match_left[u] = v
                    return True
        return False

    matching = 0
    for u in range(n_left):
        visited = [False] * n_right
        if augment(u, visited):
            matching += 1
    return matching, match_left


def find_matching(source_nums, offset, variant):
    """Find bipartite matching for crib positions.
    Returns (matching_size, crib_assignments) where
    crib_assignments[i] = CT position for crib i.
    """
    adj = []
    for i in range(N_CRIBS):
        crib_pos = CRIB_POS[i]
        pt_val = CRIB_PT_NUM[i]
        key_val = source_nums[offset + crib_pos]
        if variant == 'vigenere':
            required = (pt_val + key_val) % MOD
        else:  # beaufort
            required = (key_val - pt_val) % MOD
        adj.append(CT_LETTER_POSITIONS.get(required, []))

    size, assignment = max_bipartite_matching_with_assignment(adj, N_CRIBS, CT_LEN)
    return size, assignment


def derive_plaintext(source_nums, offset, inv_perm, variant):
    """Derive full 97-char plaintext given offset and inverse permutation."""
    pt = [0] * CT_LEN
    for i in range(CT_LEN):
        ct_pos = inv_perm[i]
        key_val = source_nums[offset + i]
        if variant == 'vigenere':
            pt[i] = (CT_NUM[ct_pos] - key_val) % MOD
        else:  # beaufort
            pt[i] = (key_val - CT_NUM[ct_pos]) % MOD
    return pt


def sa_optimize(source_nums, offset, variant, crib_ct_assignments,
                n_restarts=3, n_steps=5000, t_start=2.0, t_end=0.01):
    """SA over non-crib position assignments to maximize quadgram score.

    crib_ct_assignments: dict mapping crib_position -> CT_position
    Returns (best_score, best_plaintext_str, best_inv_perm)
    """
    # Fixed assignments from crib matching
    used_ct = set(crib_ct_assignments.values())
    available_ct = sorted(set(range(CT_LEN)) - used_ct)
    assert len(available_ct) == len(NON_CRIB_POS), \
        f"Expected {len(NON_CRIB_POS)} available, got {len(available_ct)}"

    best_score = -999
    best_pt_str = ""
    best_inv_perm = None

    for restart in range(n_restarts):
        # Random initial assignment for non-crib positions
        assignment = list(available_ct)
        random.shuffle(assignment)

        # Build full inv_perm
        inv_perm = [0] * CT_LEN
        for pos, ct_pos in crib_ct_assignments.items():
            inv_perm[pos] = ct_pos
        for idx, pos in enumerate(NON_CRIB_POS):
            inv_perm[pos] = assignment[idx]

        # Derive plaintext
        pt = derive_plaintext(source_nums, offset, inv_perm, variant)
        score = quadgram_score(pt)

        # SA
        for step in range(n_steps):
            t = t_start * (t_end / t_start) ** (step / n_steps)

            # Swap two non-crib assignments
            i = random.randint(0, len(NON_CRIB_POS) - 1)
            j = random.randint(0, len(NON_CRIB_POS) - 2)
            if j >= i:
                j += 1

            pos_i = NON_CRIB_POS[i]
            pos_j = NON_CRIB_POS[j]

            # Swap in inv_perm
            inv_perm[pos_i], inv_perm[pos_j] = inv_perm[pos_j], inv_perm[pos_i]

            # Recompute plaintext at affected positions
            old_pt_i = pt[pos_i]
            old_pt_j = pt[pos_j]
            key_i = source_nums[offset + pos_i]
            key_j = source_nums[offset + pos_j]

            if variant == 'vigenere':
                pt[pos_i] = (CT_NUM[inv_perm[pos_i]] - key_i) % MOD
                pt[pos_j] = (CT_NUM[inv_perm[pos_j]] - key_j) % MOD
            else:
                pt[pos_i] = (key_i - CT_NUM[inv_perm[pos_i]]) % MOD
                pt[pos_j] = (key_j - CT_NUM[inv_perm[pos_j]]) % MOD

            new_score = quadgram_score(pt)
            delta = new_score - score

            if delta > 0 or random.random() < math.exp(delta / t):
                score = new_score
                if score > best_score:
                    best_score = score
                    best_pt_str = ''.join(chr(c + 65) for c in pt)
                    best_inv_perm = list(inv_perm)
            else:
                # Revert
                inv_perm[pos_i], inv_perm[pos_j] = inv_perm[pos_j], inv_perm[pos_i]
                pt[pos_i] = old_pt_i
                pt[pos_j] = old_pt_j

    return best_score, best_pt_str, best_inv_perm


def load_text(filepath):
    with open(filepath, 'r', errors='replace') as f:
        raw = f.read().upper()
    return [ALPH_IDX[c] for c in raw if c in ALPH_IDX]


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-40: Carter Running Key + Transposition Quadgram Screening")
    print("=" * 70)

    variants = ['vigenere', 'beaufort']

    # Load Carter texts
    texts = {
        'carter_gutenberg': load_text(os.path.join(BASE, 'reference', 'carter_gutenberg.txt')),
        'carter_vol1_extract': load_text(os.path.join(BASE, 'reference', 'carter_vol1_extract.txt')),
    }

    all_results = {}
    english_threshold = -5.0  # From E-FRAC-34

    for text_name, source_nums in texts.items():
        n = len(source_nums)
        max_offset = n - CT_LEN
        print(f"\n{'='*70}")
        print(f"Analyzing: {text_name} ({n} letters, {max_offset+1} offsets)")
        print(f"{'='*70}")

        text_results = {'name': text_name, 'length': n, 'variants': {}}

        for variant in variants:
            print(f"\n  --- {variant.upper()} ---")

            # Phase 1: Find all feasible offsets (matching=24 + Bean full pass)
            feasible = []
            t1 = time.time()
            for o in range(max_offset + 1):
                key_nums = source_nums[o:o + CT_LEN]
                _, bean_full = check_bean(key_nums)
                if not bean_full:
                    continue

                # Check matching
                size, assignment = find_matching(source_nums, o, variant)
                if size == 24:
                    # Build crib_ct_assignments
                    crib_ct = {}
                    for i in range(N_CRIBS):
                        crib_ct[CRIB_POS[i]] = assignment[i]
                    feasible.append((o, crib_ct))

            phase1_time = time.time() - t1
            print(f"  Phase 1: {len(feasible)} feasible offsets found ({phase1_time:.1f}s)")

            if not feasible:
                text_results['variants'][variant] = {
                    'feasible_count': 0,
                    'best_quadgram': None,
                    'verdict': 'NO_FEASIBLE_OFFSETS'
                }
                continue

            # Phase 2: SA optimization for each feasible offset
            # Sample if too many
            max_offsets_to_test = 200
            if len(feasible) > max_offsets_to_test:
                print(f"  Sampling {max_offsets_to_test} of {len(feasible)} feasible offsets")
                # Take evenly spaced sample + first/last
                indices = sorted(set(
                    [0, len(feasible)-1] +
                    [i * len(feasible) // max_offsets_to_test for i in range(max_offsets_to_test)]
                ))
                sampled = [feasible[i] for i in indices[:max_offsets_to_test]]
            else:
                sampled = feasible

            print(f"  Phase 2: SA optimization on {len(sampled)} offsets "
                  f"(3 restarts × 5K steps each)...")

            results = []
            t2 = time.time()
            for idx, (o, crib_ct) in enumerate(sampled):
                best_score, best_pt, best_perm = sa_optimize(
                    source_nums, o, variant, crib_ct,
                    n_restarts=3, n_steps=5000
                )
                results.append({
                    'offset': o,
                    'best_quadgram': round(best_score, 4),
                    'plaintext': best_pt,
                })

                if (idx + 1) % 50 == 0 or idx == len(sampled) - 1:
                    elapsed = time.time() - t2
                    print(f"    Processed {idx+1}/{len(sampled)} "
                          f"({elapsed:.1f}s, best so far: "
                          f"{max(r['best_quadgram'] for r in results):.4f}/char)")

            phase2_time = time.time() - t2

            # Sort by quadgram score
            results.sort(key=lambda r: -r['best_quadgram'])

            best_overall = results[0]
            scores = [r['best_quadgram'] for r in results]
            above_threshold = [r for r in results if r['best_quadgram'] > english_threshold]

            print(f"\n  Phase 2 complete ({phase2_time:.1f}s)")
            print(f"  Best quadgram: {best_overall['best_quadgram']:.4f}/char "
                  f"(offset={best_overall['offset']})")
            print(f"  Mean quadgram: {sum(scores)/len(scores):.4f}/char")
            print(f"  Worst quadgram: {min(scores):.4f}/char")
            print(f"  Above {english_threshold} threshold: {len(above_threshold)}")

            print(f"\n  Top-10 offsets:")
            for r in results[:10]:
                # Show a snippet of the plaintext around cribs
                pt = r['plaintext']
                print(f"    offset={r['offset']:6d}: qg={r['best_quadgram']:.4f} "
                      f"| ...{pt[18:36]}...{pt[60:76]}...")

            if above_threshold:
                print(f"\n  *** OFFSETS ABOVE THRESHOLD ({english_threshold}) ***")
                for r in above_threshold:
                    print(f"    offset={r['offset']}: qg={r['best_quadgram']:.4f}")
                    print(f"    PT: {r['plaintext']}")

            text_results['variants'][variant] = {
                'feasible_count': len(feasible),
                'tested_count': len(sampled),
                'best_quadgram': best_overall['best_quadgram'],
                'best_offset': best_overall['offset'],
                'best_plaintext': best_overall['plaintext'],
                'mean_quadgram': round(sum(scores)/len(scores), 4),
                'worst_quadgram': round(min(scores), 4),
                'above_threshold': len(above_threshold),
                'top_10': [{'offset': r['offset'], 'quadgram': r['best_quadgram'],
                           'plaintext': r['plaintext']} for r in results[:10]],
            }

        all_results[text_name] = text_results

    # Summary
    total_time = time.time() - t0
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    any_above = False
    for text_name, tr in all_results.items():
        for variant, vr in tr.get('variants', {}).items():
            if vr.get('best_quadgram') is not None:
                status = "SIGNAL" if vr['above_threshold'] > 0 else "NOISE"
                if vr['above_threshold'] > 0:
                    any_above = True
                print(f"  {text_name} ({variant}): best={vr['best_quadgram']:.4f}/char, "
                      f"mean={vr['mean_quadgram']:.4f}, "
                      f"above -5.0: {vr['above_threshold']} → {status}")
            else:
                print(f"  {text_name} ({variant}): NO_FEASIBLE_OFFSETS")

    print(f"\n  E-FRAC-34 benchmarks:")
    print(f"    English text:  -4.84/char")
    print(f"    False positives (best): -5.77/char")
    print(f"    Threshold: -5.0/char")
    print(f"    Random text:   -6.43/char")

    if any_above:
        verdict = "SIGNAL_DETECTED — some Carter offsets produce quadgrams above -5.0 threshold"
    else:
        best_all = max(
            vr.get('best_quadgram', -999)
            for tr in all_results.values()
            for vr in tr.get('variants', {}).values()
        )
        gap = english_threshold - best_all
        verdict = (f"NOISE — best quadgram {best_all:.4f}/char is {gap:.2f} below "
                   f"threshold ({english_threshold}). Carter running key + transposition "
                   f"produces gibberish, not English.")

    print(f"\n  VERDICT: {verdict}")
    print(f"  Total runtime: {total_time:.1f}s")

    # Save
    summary = {
        'experiment': 'E-FRAC-40',
        'description': 'Carter running key + transposition quadgram screening',
        'total_time_seconds': round(total_time, 1),
        'english_threshold': english_threshold,
        'verdict': verdict,
        'results': {},
    }
    for text_name, tr in all_results.items():
        summary['results'][text_name] = {
            'length': tr['length'],
            'variants': {v: {k: vr[k] for k in ['feasible_count', 'tested_count',
                            'best_quadgram', 'best_offset', 'mean_quadgram',
                            'worst_quadgram', 'above_threshold']
                            if k in vr}
                        for v, vr in tr.get('variants', {}).items()}
        }

    results_dir = os.path.join(BASE, 'results', 'frac')
    os.makedirs(results_dir, exist_ok=True)
    outpath = os.path.join(results_dir, 'e_frac_40_carter_quadgram_screen.json')
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Results saved to: {outpath}")

    print("\n" + "=" * 70)
    print("RESULT: " + verdict)
    print("=" * 70)


if __name__ == '__main__':
    main()
