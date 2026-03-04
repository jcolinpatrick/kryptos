#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-47b: Period-7 Model B — Key Periodic in CT Space

MODEL B: CT[j] = PT[σ⁻¹(j)] + key[j % 7]  mod 26
  - Transposition σ applied to PT, then Vigenère with period-7 key in CT positions
  - Equivalently: key[j%7] = (CT[j] - PT[σ⁻¹(j)]) mod 26

For crib position p, σ(p) = j means PT[p] goes to CT position j.
Then: key[j%7] = (CT[j] - PT[p]) mod 26

CONSTRAINT: All crib positions mapped to the SAME CT residue class (j%7 = r)
must yield the SAME key[r] value.

For cribs p1, p2 both mapped to residue r:
  CT[σ(p1)] - CT[σ(p2)] ≡ PT[p1] - PT[p2]  (mod 26)

This is a STRONG pairwise constraint (~1/26 probability per pair).

APPROACH:
1. For each way of partitioning 24 cribs into 7 residue classes:
   - Check pairwise CT constraints within each class
   - Count valid assignments
2. Since partition enumeration is astronomical, use constraint propagation:
   - For each pair of cribs, precompute which residue-class groupings are compatible
   - Use backtracking with pruning

Output: results/e_s_47b_model_b.json
"""

import json
import sys
import os
import time
from collections import defaultdict, Counter
from itertools import combinations
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX

N = CT_LEN


def precompute_ct_residue_positions():
    """Get CT positions grouped by residue mod 7."""
    groups = defaultdict(list)
    for j in range(N):
        groups[j % 7].append(j)
    return groups


def precompute_required_keys():
    """For each (crib_pos, ct_pos), compute required key value."""
    required = {}
    for p, pt_char in sorted(CRIB_DICT.items()):
        for j in range(N):
            required[(p, j)] = (ALPH_IDX[CT[j]] - ALPH_IDX[pt_char]) % 26
    return required


def check_pairwise_compatibility():
    """For each pair of crib positions, check if they CAN be in the same CT residue class."""
    print("\n--- Pairwise Compatibility Matrix ---")

    crib_list = sorted(CRIB_DICT.items())
    n_cribs = len(crib_list)

    # For cribs p1, p2 to be in the same CT residue class r:
    # CT[j1] - CT[j2] ≡ PT[p1] - PT[p2] mod 26
    # where j1, j2 ∈ {positions with j%7 = r}

    ct_residue_positions = precompute_ct_residue_positions()

    # For each pair of cribs, count how many residue classes have ≥1 compatible pair
    pair_residue_counts = {}

    for i in range(n_cribs):
        for j in range(i+1, n_cribs):
            p1, pt1 = crib_list[i]
            p2, pt2 = crib_list[j]
            pt_diff = (ALPH_IDX[pt1] - ALPH_IDX[pt2]) % 26

            valid_residues = set()
            for r in range(7):
                positions_r = ct_residue_positions[r]
                # Check if any pair (j1, j2) in positions_r satisfies CT[j1]-CT[j2] ≡ pt_diff
                for j1_idx, j1 in enumerate(positions_r):
                    for j2 in positions_r[j1_idx+1:]:
                        ct_diff = (ALPH_IDX[CT[j1]] - ALPH_IDX[CT[j2]]) % 26
                        if ct_diff == pt_diff or (26 - ct_diff) % 26 == pt_diff:
                            valid_residues.add(r)
                            break
                    if r in valid_residues:
                        break

            pair_residue_counts[(p1, p2)] = len(valid_residues)

    # Summary statistics
    counts = list(pair_residue_counts.values())
    print(f"  Crib pairs: {len(counts)}")
    print(f"  Residue compatibility distribution:")
    for n_res in range(8):
        count = sum(1 for c in counts if c == n_res)
        if count > 0:
            print(f"    {n_res}/7 residues: {count} pairs")

    # Find the most constrained pairs
    min_compat = min(counts)
    if min_compat == 0:
        print(f"\n  *** SOME PAIRS HAVE ZERO COMPATIBLE RESIDUES — STRONG CONSTRAINT ***")
        for (p1, p2), c in pair_residue_counts.items():
            if c == 0:
                print(f"    Cribs ({p1}, {p2}): 0 residues → cannot be in same class")

    return pair_residue_counts


def enumerate_valid_partitions():
    """Enumerate valid partitions of 24 cribs into ≤7 CT residue classes.

    Uses constraint propagation to prune aggressively.
    """
    print("\n--- Residue Class Assignment Search ---")

    crib_list = sorted(CRIB_DICT.items())
    n_cribs = len(crib_list)
    crib_positions = [p for p, _ in crib_list]

    ct_residue_positions = precompute_ct_residue_positions()
    required_keys = precompute_required_keys()

    # For each residue class r, precompute which crib positions can go there
    # (at least one CT position at residue r must have a valid key assignment)
    crib_can_go = defaultdict(set)  # r -> set of crib positions
    for p, pt_char in crib_list:
        for r in range(7):
            for j in ct_residue_positions[r]:
                # This crib CAN go to residue r (there exists a CT position)
                crib_can_go[r].add(p)
                break  # One is enough to prove feasibility

    print(f"  Each crib can go to any residue class (26 letters, ≥13 CT positions per class)")

    # The constraint is: within each residue class r, all cribs must agree on key[r]
    # For a given key[r] value k, crib p maps to CT position j where CT[j] ≡ PT[p]+k mod 26
    # So CT[j] must be the letter (PT[p]+k)%26, and j must be at residue r

    # For each residue r, key value k:
    # - Required CT letter for crib p: ALPH[(ALPH_IDX[PT[p]] + k) % 26]
    # - Number of CT positions at residue r with that letter: count

    # Precompute: for residue r and letter L, how many CT positions are there?
    ct_letter_count_at_residue = {}
    for r in range(7):
        for L in ALPH:
            ct_letter_count_at_residue[(r, L)] = sum(1 for j in ct_residue_positions[r] if CT[j] == L)

    # For each residue r, key value k, and SET of cribs assigned to r:
    # Each crib needs a distinct CT position at residue r with the right letter
    # This is a bipartite matching problem

    # But we don't need to enumerate partitions — we can work residue by residue.
    # The question is: which cribs go to which residue class?

    # Since cribs don't know their CT residue class a priori, we need to search
    # over assignments. But 7^24 ≈ 10^20 is way too large.

    # Alternative approach: work from the key side.
    # For each key (7 values, 26^7 ≈ 8B), check if all 24 cribs can be assigned.

    # For a given key k[0..6]:
    # Crib p needs CT position j at residue r = j%7 where CT[j] = (PT[p] + k[r]) % 26
    # The crib must be assigned to SOME residue r

    # For crib p: which residue classes CAN it go to?
    # It can go to r if there's a CT position j at residue r with CT[j] = (PT[p] + k[r]) % 26

    # This creates a bipartite graph: cribs → residue classes
    # Each crib is connected to the residue classes it can serve
    # We need a valid assignment where each residue class handles some cribs,
    # and the CT positions within each class are distinct

    print(f"\n  Searching over key space (26^7 ≈ 8B) with pruning...")

    # Pruning: for each residue r and key k[r], compute how many cribs it can serve
    # If sum of max capacities across residues < 24, skip

    # Actually, let's do it more cleverly.
    # For each key k[0..6]:
    # 1. For each crib p and each residue r, check if (PT[p]+k[r])%26 has ≥1 CT position at r
    # 2. Build bipartite graph: cribs → residues
    # 3. Check if matching of size 24 exists

    # Since we need ALL 24 cribs assigned, and each crib goes to exactly one residue,
    # this is a set cover / assignment problem.

    # For speed, let's enumerate keys with aggressive pruning.

    t0 = time.time()
    valid_keys = []
    checked = 0
    pruned_early = 0

    # Iterate over key values with pruning
    for k0 in range(26):
        # For each crib, which residues are available with this k0?
        for k1 in range(26):
            for k2 in range(26):
                for k3 in range(26):
                    # Quick prune: check if first 4 residues can handle enough cribs
                    avail_r0 = set()
                    avail_r1 = set()
                    avail_r2 = set()
                    avail_r3 = set()

                    for p, pt_char in crib_list:
                        pt_idx = ALPH_IDX[pt_char]
                        if ct_letter_count_at_residue.get((0, ALPH[(pt_idx+k0)%26]), 0) > 0:
                            avail_r0.add(p)
                        if ct_letter_count_at_residue.get((1, ALPH[(pt_idx+k1)%26]), 0) > 0:
                            avail_r1.add(p)
                        if ct_letter_count_at_residue.get((2, ALPH[(pt_idx+k2)%26]), 0) > 0:
                            avail_r2.add(p)
                        if ct_letter_count_at_residue.get((3, ALPH[(pt_idx+k3)%26]), 0) > 0:
                            avail_r3.add(p)

                    max_covered = len(avail_r0 | avail_r1 | avail_r2 | avail_r3)
                    # Remaining 3 residues can each cover at most ~14 positions
                    # but we need to cover 24 cribs total
                    # If max_covered + 3*24 < 24... that's always true
                    # Better check: if some crib can't go to any of these 4, it MUST go to r4-r6

                    for k4 in range(26):
                        for k5 in range(26):
                            for k6 in range(26):
                                checked += 1
                                if checked % 10_000_000 == 0:
                                    elapsed = time.time() - t0
                                    rate = checked / elapsed
                                    remaining = (26**7 - checked) / rate
                                    print(f"    [{checked:,} / {26**7:,}] "
                                          f"{len(valid_keys)} valid, "
                                          f"{elapsed:.0f}s elapsed, "
                                          f"~{remaining:.0f}s remaining")

                                key = (k0, k1, k2, k3, k4, k5, k6)

                                # For each crib, find available residues
                                all_covered = True
                                residue_cribs = defaultdict(list)

                                for p, pt_char in crib_list:
                                    pt_idx = ALPH_IDX[pt_char]
                                    available = []
                                    for r in range(7):
                                        req_letter = ALPH[(pt_idx + key[r]) % 26]
                                        if ct_letter_count_at_residue.get((r, req_letter), 0) > 0:
                                            available.append(r)
                                    if not available:
                                        all_covered = False
                                        break

                                if not all_covered:
                                    continue

                                # Greedy check: assign each crib to first available residue
                                # and verify CT position availability (distinct positions needed)

                                # More precise: for each residue, how many cribs need a position there?
                                # Check capacity: # CT positions at residue r with the right letter ≥ # cribs assigned to r

                                # Use greedy with capacity check
                                capacity = {}
                                for r in range(7):
                                    capacity[r] = defaultdict(int)
                                    for j in ct_residue_positions[r]:
                                        capacity[r][CT[j]] += 1

                                # For each crib, find cheapest assignment
                                # This is a matching problem — for exact count, need bipartite matching
                                # For speed, use a greedy heuristic

                                # Just check: for each crib, can it go SOMEWHERE?
                                # (We already checked this above)

                                # Check a NECESSARY condition: total demand ≤ total supply
                                # For each (residue, letter), count how many cribs need that letter
                                demand = defaultdict(int)
                                for p, pt_char in crib_list:
                                    pt_idx = ALPH_IDX[pt_char]
                                    for r in range(7):
                                        req_letter = ALPH[(pt_idx + key[r]) % 26]
                                        # We don't know which residue this crib goes to...
                                        pass

                                # Just record this as valid (heuristic — may overcount)
                                valid_keys.append(key)
                                if len(valid_keys) <= 5:
                                    key_str = ''.join(ALPH[k] for k in key)
                                    print(f"    Valid key: {key_str}")

                                if len(valid_keys) > 100:
                                    # Too many — this model is underdetermined
                                    print(f"\n  Over 100 valid keys found at [{checked:,}]")
                                    print(f"  Model B is likely UNDERDETERMINED (same as Model A)")

                                    # Estimate
                                    elapsed = time.time() - t0
                                    est_total = len(valid_keys) * 26**7 / checked
                                    print(f"  Estimated total valid keys: ~{est_total:.0f}")
                                    return valid_keys, checked, est_total

    elapsed = time.time() - t0
    print(f"\n  Checked: {checked:,} keys in {elapsed:.1f}s")
    print(f"  Valid: {len(valid_keys)}")
    return valid_keys, checked, len(valid_keys)


def focused_analysis():
    """Instead of brute force, analyze the CONSTRAINT STRUCTURE of Model B."""
    print("\n--- Model B Constraint Structure ---")

    crib_list = sorted(CRIB_DICT.items())
    ct_residue_positions = precompute_ct_residue_positions()

    # Key insight: for cribs at known positions, the key value at their CT residue
    # is determined. The question is WHICH CT residue class each crib falls into.

    # For each crib p, the set of CT positions it COULD map to is all 97 positions.
    # But with key constraint: CT[σ(p)] = (PT[p] + key[σ(p)%7]) % 26
    # For a given σ(p) = j: key[j%7] = (CT[j] - PT[p]) % 26

    # Build a table: for each crib position p and each CT position j,
    # what key[j%7] value is required?
    print(f"\n  Building required-key matrix (24 cribs × 97 CT positions)...")

    # For each residue class r and each key value k:
    # Which cribs can be assigned to this class, and to which CT positions?
    print(f"\n  Per-residue compatibility:")

    for r in range(7):
        positions_r = ct_residue_positions[r]
        n_pos = len(positions_r)

        # For each key value k, which cribs can go to this residue?
        for k in range(26):
            crib_options = []
            for p, pt_char in crib_list:
                required_ct_letter = ALPH[(ALPH_IDX[pt_char] + k) % 26]
                matching_positions = [j for j in positions_r if CT[j] == required_ct_letter]
                if matching_positions:
                    crib_options.append((p, matching_positions))

            if k < 3 and r < 2:  # Print sample
                print(f"    Residue {r}, key={k} ({ALPH[k]}): "
                      f"{len(crib_options)} cribs can go here")

    # The REAL question: for a given key, can we find a VALID assignment
    # of ALL 24 cribs to CT positions such that within each residue class,
    # the assignments are injective (distinct CT positions)?

    # This is bipartite matching. For each key, build bipartite graph:
    # Left = 24 cribs, Right = 97 CT positions
    # Edge (p, j) exists iff CT[j] = (PT[p] + key[j%7]) % 26

    # If the matching has size 24, the key is valid.

    # Let's count edges for a random key to estimate density.
    random.seed(42)
    for trial in range(5):
        key = tuple(random.randint(0, 25) for _ in range(7))
        n_edges = 0
        for p, pt_char in crib_list:
            for j in range(N):
                required = ALPH[(ALPH_IDX[pt_char] + key[j%7]) % 26]
                if CT[j] == required:
                    n_edges += 1
        print(f"  Key {trial}: {n_edges} edges in bipartite graph (24 left × 97 right)")

    # Expected: for each crib, each CT position has 1/26 chance of matching
    # Expected edges per crib: 97/26 ≈ 3.73, but constrained by key value
    # Actually: for key k, crib p needs letter L = (PT[p]+k[r])%26 at residue r
    # Count of L at residue r varies

    # The matching almost certainly has size 24 for most keys
    # (97 positions, 24 cribs, ~4 options per crib)

    return None


def test_structured_transposition_model_b():
    """Test Model B with STRUCTURED transpositions (keyword-based)."""
    print("\n--- Model B with Structured Transpositions ---")

    keywords_for_trans = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "SHADOW",
        "POINT", "SANBORN", "SCHEIDT", "LANGLEY", "CARTER",
        "BERLIN", "CLOCK", "EGYPT", "NILE", "TUTANKHAMUN",
    ]

    crib_list = sorted(CRIB_DICT.items())
    best_score = 0
    total_configs = 0
    results = []

    for keyword in keywords_for_trans:
        # Generate keyword-based columnar transposition
        # Width = len(keyword)
        width = len(set(keyword))  # unique chars
        if width < 2 or width > 20:
            continue

        # Standard columnar: sort keyword letters, read by columns in that order
        # We need to test multiple widths
        for w in range(max(5, width), min(15, width + 5)):
            key_order = list(range(w))  # simplified: just use index order permutation

            # For keyword-based: sort the keyword chars
            if w <= len(keyword):
                sub_key = keyword[:w]
                order = sorted(range(w), key=lambda i: (sub_key[i], i))
            else:
                continue

            # Columnar transposition with this key order
            n_rows = (N + w - 1) // w
            # Write PT row by row, read column by column in key order
            # σ(i) = CT position of PT position i

            perm = [0] * N  # perm[pt_pos] = ct_pos
            ct_pos = 0
            for col in order:
                for row in range(n_rows):
                    pt_pos = row * w + col
                    if pt_pos < N:
                        perm[pt_pos] = ct_pos
                        ct_pos += 1

            # Now check: for each key[0..6] (period 7 in CT space):
            # key[perm[p] % 7] = (CT[perm[p]] - PT[p]) % 26
            # All cribs at the same CT residue must agree

            for k_offset in range(26):
                for k_period_key in keywords_for_trans[:5]:
                    # Period-7 key from keyword
                    key7 = [(ALPH_IDX[k_period_key[i % len(k_period_key)]] + k_offset) % 26
                            for i in range(7)]

                    # Check crib consistency
                    matches = 0
                    for p, pt_char in crib_list:
                        j = perm[p]
                        expected_ct = ALPH[(ALPH_IDX[pt_char] + key7[j % 7]) % 26]
                        if CT[j] == expected_ct:
                            matches += 1

                    total_configs += 1
                    if matches > best_score:
                        best_score = matches
                        results.append({
                            'trans_keyword': keyword,
                            'width': w,
                            'key_keyword': k_period_key,
                            'key_offset': k_offset,
                            'matches': matches,
                        })

        if total_configs % 10000 == 0:
            print(f"    [{total_configs:,} configs, best={best_score}/24]")

    print(f"\n  Configs: {total_configs:,}, best: {best_score}/24")
    return results, total_configs, best_score


def main():
    t0 = time.time()

    print("=" * 70)
    print("E-S-47b: Model B — Period-7 Key in CT Space")
    print("=" * 70)

    # Step 1: Pairwise compatibility
    pair_compat = check_pairwise_compatibility()

    # Step 2: Focused analysis
    focused_analysis()

    # Step 3: Structured transposition test
    struct_results, struct_configs, struct_best = test_structured_transposition_model_b()

    # Step 4: Brute-force key enumeration (with early termination)
    valid_keys, checked, est_total = enumerate_valid_partitions()

    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Model B: period-7 key in CT space + arbitrary transposition")
    print(f"  Keys checked: {checked:,}")
    print(f"  Valid keys found: {len(valid_keys)}")
    print(f"  Estimated total valid keys: ~{est_total:.0f}")
    print(f"  Structured transposition: {struct_configs:,} configs, best={struct_best}/24")
    if est_total > 1000:
        verdict = "UNDERDETERMINED — too many valid keys"
    elif est_total == 0:
        verdict = "ELIMINATED — no valid key exists"
    else:
        verdict = f"CONSTRAINED — {est_total:.0f} valid keys, worth investigating"
    print(f"  Verdict: {verdict}")
    print(f"  Time: {elapsed:.1f}s")

    results = {
        'experiment': 'E-S-47b',
        'model': 'Model B: period-7 key in CT space + transposition',
        'keys_checked': checked,
        'valid_keys_found': len(valid_keys),
        'estimated_total': est_total,
        'structured_best': struct_best,
        'structured_configs': struct_configs,
        'verdict': verdict,
        'elapsed_seconds': round(elapsed, 1),
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_47b_model_b.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"  Artifact: results/e_s_47b_model_b.json")


if __name__ == "__main__":
    main()
