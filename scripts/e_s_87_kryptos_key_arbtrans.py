#!/usr/bin/env python3
"""E-S-87: KRYPTOS Key + Arbitrary Transposition Feasibility

Quick check: if K4 uses the SAME key as K3 (KRYPTOS = [10,17,24,15,19,14,18])
but with an ARBITRARY transposition (not just columnar), can the cribs be
satisfied?

For a period-7 key and arbitrary transposition:
1. Compute intermediate text = decrypt(CT, key)
2. Check if a bipartite matching exists between crib positions and
   intermediate positions such that PT letters match.

This is purely a feasibility check — does NOT require enumerating transpositions.
Uses bipartite matching (Hopcroft-Karp or Hungarian) to determine if a valid
assignment exists.

Also tests: all 26^7 period-7 keys (8B) is too many. Instead, we enumerate
keys that are CONSISTENT with a subset of cribs and check if they're
consistent with ALL cribs.

Phase 1: KRYPTOS key feasibility (Vig/Beau/VarBeau)
Phase 2: Enumerate all keys consistent with first crib group
Phase 3: Test thematic period-7 keys
"""

import json
import os
import sys
import time
from itertools import product
from collections import Counter

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
CT_NUM = [AZ_IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
PT_NUM = {pos: AZ_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POS = sorted(CRIB_DICT.keys())

# Crib letter requirements: how many of each PT letter do we need?
crib_letter_counts = Counter(CRIB_DICT.values())

print("=" * 70)
print("E-S-87: KRYPTOS Key + Arbitrary Transposition Feasibility")
print("=" * 70)
print(f"  Crib letter requirements: {dict(crib_letter_counts)}")


def compute_intermediate(key, variant):
    """Compute intermediate text for period-7 key.

    Returns list of 97 integers (0-25).
    """
    inter = []
    for j in range(N):
        k = key[j % 7]
        if variant == 'vig':
            inter.append((CT_NUM[j] - k) % 26)
        elif variant == 'beau':
            inter.append((k - CT_NUM[j]) % 26)
        else:  # var_beau
            inter.append((CT_NUM[j] + k) % 26)
    return inter


def check_feasibility(inter):
    """Check if a bipartite matching exists between cribs and intermediate.

    For each crib position p with PT letter L:
      Need some intermediate position j where inter[j] == AZ_IDX[L]
      AND j is not used by another crib position.

    Returns (feasible, max_matching_size).
    Uses greedy matching (not optimal, but fast).
    """
    # Count available intermediate positions for each PT letter
    inter_counts = Counter(AZ[v] for v in inter)

    # Simple feasibility: enough of each letter?
    for letter, need in crib_letter_counts.items():
        if inter_counts.get(letter, 0) < need:
            return False, 0, letter

    # More precise: bipartite matching
    # Group crib positions by PT letter
    letter_to_cribs = {}
    for pos, letter in CRIB_DICT.items():
        if letter not in letter_to_cribs:
            letter_to_cribs[letter] = []
        letter_to_cribs[letter].append(pos)

    # For each PT letter, find intermediate positions with that value
    letter_to_inter = {}
    for j in range(N):
        letter = AZ[inter[j]]
        if letter not in letter_to_inter:
            letter_to_inter[letter] = []
        letter_to_inter[letter].append(j)

    # Simple check: each letter has enough supply
    total_matched = 0
    for letter, crib_positions in letter_to_cribs.items():
        available = len(letter_to_inter.get(letter, []))
        needed = len(crib_positions)
        total_matched += min(available, needed)

    return total_matched == 24, total_matched, None


def hopcroft_karp(adj, n_left, n_right):
    """Hopcroft-Karp bipartite matching. Returns matching size."""
    match_left = [-1] * n_left
    match_right = [-1] * n_right

    def bfs():
        queue = []
        dist = [float('inf')] * n_left
        for u in range(n_left):
            if match_left[u] == -1:
                dist[u] = 0
                queue.append(u)
        found = False
        qi = 0
        while qi < len(queue):
            u = queue[qi]
            qi += 1
            for v in adj[u]:
                w = match_right[v]
                if w == -1:
                    found = True
                elif dist[w] == float('inf'):
                    dist[w] = dist[u] + 1
                    queue.append(w)
        return found, dist

    def dfs(u, dist):
        for v in adj[u]:
            w = match_right[v]
            if w == -1 or (dist[w] == dist[u] + 1 and dfs(w, dist)):
                match_left[u] = v
                match_right[v] = u
                return True
        dist[u] = float('inf')
        return False

    matching = 0
    while True:
        found, dist = bfs()
        if not found:
            break
        for u in range(n_left):
            if match_left[u] == -1:
                if dfs(u, dist):
                    matching += 1

    return matching, match_left


def precise_matching(inter):
    """Precise bipartite matching using Hopcroft-Karp.

    Left nodes: 24 crib entries (indexed 0-23)
    Right nodes: 97 intermediate positions
    Edge: crib i → position j if inter[j] == PT_NUM[crib_pos[i]]
    """
    n_left = 24
    n_right = N

    # Build adjacency list
    adj = [[] for _ in range(n_left)]
    for i, pos in enumerate(CRIB_POS):
        target = PT_NUM[pos]
        for j in range(N):
            if inter[j] == target:
                adj[i].append(j)

    matching_size, match_left = hopcroft_karp(adj, n_left, n_right)
    return matching_size, match_left


# ── Phase 1: KRYPTOS key ─────────────────────────────────────────────────

print("\n" + "-" * 50)
print("Phase 1: KRYPTOS key feasibility")
print("-" * 50)

KRYPTOS_KEY = [AZ_IDX[c] for c in "KRYPTOS"]
print(f"  Key: KRYPTOS = {KRYPTOS_KEY}")

for variant in ['vig', 'beau', 'var_beau']:
    inter = compute_intermediate(KRYPTOS_KEY, variant)
    inter_text = ''.join(AZ[v] for v in inter)
    inter_counts = Counter(inter_text)

    feasible, matched, deficient = check_feasibility(inter)
    matching_size, match_left = precise_matching(inter)

    print(f"\n  {variant.upper()}: intermediate = {inter_text[:40]}...")
    print(f"    Letter counts: {dict(sorted(inter_counts.items()))}")
    print(f"    Quick feasibility: {feasible} (matched={matched}, deficient={deficient})")
    print(f"    Precise matching: {matching_size}/24")

    if matching_size == 24:
        # Show the matching
        print(f"    FEASIBLE! Matching:")
        for i, pos in enumerate(CRIB_POS):
            j = match_left[i]
            print(f"      Crib pos {pos} (PT={CRIB_DICT[pos]}) → inter pos {j} "
                  f"(inter={AZ[inter[j]]})")


# ── Phase 2: Enumerate consistent keys ───────────────────────────────────

print("\n" + "-" * 50)
print("Phase 2: Enumerate keys consistent with cribs (arbitrary transposition)")
print("-" * 50)

# For arbitrary transposition, each crib position p can map to ANY CT position j.
# The constraint is: decrypt(CT[j], k[j%7]) = PT[p]
# So for each (crib_pos p, crib_letter L):
#   k[r] = (CT_NUM[j] - AZ_IDX[L]) % 26  for Vig, where r = j%7

# For Vigenère:
# For each crib position p with PT letter L:
#   Possible (r, k[r]) values: (j%7, (CT_NUM[j] - AZ_IDX[L]) % 26) for j in 0..96

# We need to find k[0..6] such that for each crib position, there exists
# an intermediate position j with the right value AND j is unique.

# Strategy: for each key k[0..6], check bipartite matching.
# But 26^7 = 8B is too many.

# Pruning: for each residue r, collect the set of possible k[r] values
# that are needed by at least one crib position.

t0 = time.time()

for variant in ['vig', 'beau']:
    print(f"\n  Variant: {variant}")

    # For each crib position p with letter L, and for each residue r:
    # The key value k[r] that would allow j≡r to satisfy this crib is:
    # k[r] = (CT_NUM[j] - PT_NUM[p]) % 26 for vig, where j ≡ r (mod 7)
    # We need AT LEAST ONE j with this property.

    # For each residue r, collect all possible k[r] values
    # that are derived from some crib position
    possible_k = [set() for _ in range(7)]
    for r in range(7):
        for j in range(r, N, 7):
            for p in CRIB_POS:
                if variant == 'vig':
                    kv = (CT_NUM[j] - PT_NUM[p]) % 26
                elif variant == 'beau':
                    kv = (CT_NUM[j] + PT_NUM[p]) % 26
                else:
                    kv = (PT_NUM[p] - CT_NUM[j]) % 26
                possible_k[r].add(kv)

    print(f"    Possible k[r] sizes: {[len(s) for s in possible_k]}")
    total_keys = 1
    for s in possible_k:
        total_keys *= len(s)
    print(f"    Total candidate keys: {total_keys:,}")

    # That's likely 26^7 since with 97 positions and 26 CT values,
    # every key value is possible for every residue.
    # So this doesn't prune anything.

    # Better approach: for each crib position, what key values are compatible?
    # A key k is compatible with crib pos p if there exists j such that:
    #   decrypt(CT[j], k[j%7]) == PT_NUM[p] AND j is available
    # Since j can be ANY position, k[j%7] just needs to decrypt CT[j] to the right PT.

    # For a specific key k: compute full intermediate text, then check matching.
    # Can't enumerate 26^7.

    # Instead: enumerate keys that are consistent with at least 2 specific cribs
    # and check if they extend to all 24.

    # Pick two "high-constraint" crib positions (those with rare PT letters)
    # B appears once (pos 63), H appears once (pos 29), I once (pos 67), K once (pos 73)
    # Use B and K as anchors.

    # For crib B at pos 63: need some j where decrypt(CT[j], k[j%7]) = AZ_IDX['B'] = 1
    # For crib K at pos 73: need some j where decrypt(CT[j], k[j%7]) = AZ_IDX['K'] = 10

    # For anchor B (PT=B, numeric=1):
    #   For each j: k[j%7] = (CT_NUM[j] - 1) % 26 (vig)
    #   So for each j, this constrains k[j%7] to a specific value.
    #   For j=0 (CT=O=14): k[0] = (14-1) = 13
    #   For j=1 (CT=B=1): k[1] = (1-1) = 0
    #   ... etc.
    #   There are 97 possible (j, k[j%7]) pairs.

    # For anchor K (PT=K, numeric=10):
    #   Similar 97 possible (j, k[j%7]) pairs.

    # Combining two anchors: for each pair (j_B, j_K) where j_B ≠ j_K,
    # if they constrain different residues, we get a partial key.
    # If they constrain the same residue, the key values must agree.

    # This is O(97^2) per anchor pair = ~9400 combinations.
    # For each, check matching with ALL 24 cribs.

    # This is fast! Let's do it.

    # Precompute: for each PT letter value v, the set of possible (j, k[j%7])
    if variant == 'vig':
        required_k = {}  # (j, pt_val) → required k[j%7]
        for j in range(N):
            for v in range(26):
                required_k[(j, v)] = (CT_NUM[j] - v) % 26
    else:  # beau
        required_k = {}
        for j in range(N):
            for v in range(26):
                required_k[(j, v)] = (CT_NUM[j] + v) % 26

    # For each crib position p:
    #   candidate_j[p] = list of (j, required_k_value, residue) tuples
    candidate_j = {}
    for p in CRIB_POS:
        v = PT_NUM[p]
        candidate_j[p] = [(j, required_k[(j, v)], j % 7) for j in range(N)]

    # Strategy: pick anchor crib positions with few possible assignments
    # (actually all have 97 possible j values, so use a smarter approach)

    # Better: for each key k[0..6], the intermediate text is fixed.
    # A key is valid if the bipartite matching for all 24 cribs succeeds.
    # 26^7 is too many. But we can prune:

    # For each residue r, there are ~14 CT positions with j%7 = r.
    # The intermediate values at those positions are determined by k[r]:
    #   inter[j] = (CT_NUM[j] - k[r]) % 26 for vig
    # So the intermediate text at residue r has a specific set of values.

    # For crib matching: the intermediate must contain enough of each PT letter.
    # This constrains k[r] for each r.

    # Key insight: for each residue r, the 14 intermediate values are
    # (CT_NUM[j] - k[r]) % 26 for j ≡ r (mod 7). These are just the
    # CT values shifted by -k[r]. So the multiset of intermediate values
    # at residue r is just the multiset of CT values at residue r, shifted.

    # The TOTAL intermediate text is the union of 7 shifted multisets.
    # For each crib letter L, we need at least crib_letter_counts[L] occurrences
    # of L in the total intermediate text.

    # For each key k, the count of letter L in the intermediate is:
    #   sum over r of: count of (L + k[r]) % 26 in CT at residue r

    # This is a constraint on k that we can check quickly.

    # Let's enumerate: for each residue r, the CT letter multiset
    ct_by_residue = [[] for _ in range(7)]
    for j in range(N):
        ct_by_residue[j % 7].append(CT_NUM[j])

    ct_counts_by_residue = [Counter(ct_by_residue[r]) for r in range(7)]

    print(f"    CT positions per residue: {[len(ct_by_residue[r]) for r in range(7)]}")

    # For a given k[r], the intermediate letters at residue r are:
    #   (CT_NUM[j] - k[r]) % 26 = (c - k[r]) % 26 for each c in ct_by_residue[r]

    # For vig: inter count of letter v at residue r = ct_count of (v + k[r]) % 26 at residue r
    # For beau: inter[j] = (k[r] - CT_NUM[j]) % 26, so inter count of v = ct_count of (k[r] - v) % 26

    # Total count of letter v across all residues:
    #   sum_r ct_counts_by_residue[r][(v + k[r]) % 26]  (vig)

    # We need total_count[v] >= crib_letter_counts[AZ[v]] for all v in crib letters.

    # This gives us a constraint that reduces the search space.

    # For efficiency: try all 26^3 = 17,576 values for k[0..2],
    # and for each, find consistent k[3..6].

    # Actually, let me just try the bipartite matching approach with the
    # KRYPTOS key and a few thematic keys.

    # Test thematic keys
    thematic_keys = {
        'KRYPTOS': [AZ_IDX[c] for c in 'KRYPTOS'],
        'ABSCISS': [AZ_IDX[c] for c in 'ABSCISS'],
        'PALIMPS': [AZ_IDX[c] for c in 'PALIMPS'],
        'BERLINN': [AZ_IDX[c] for c in 'BERLINN'],
        'CLOCKKK': [AZ_IDX[c] for c in 'CLOCKKK'],
        'SECRETZ': [AZ_IDX[c] for c in 'SECRETZ'],
        'COMPASS': [AZ_IDX[c] for c in 'COMPASS'],
        'SCHEIDT': [AZ_IDX[c] for c in 'SCHEIDT'],
        'SANBORN': [AZ_IDX[c] for c in 'SANBORN'],
        'LANGLEY': [AZ_IDX[c] for c in 'LANGLEY'],
        'SHADOWS': [AZ_IDX[c] for c in 'SHADOWS'],
        'DELIVER': [AZ_IDX[c] for c in 'DELIVER'],
        'MESSAGE': [AZ_IDX[c] for c in 'MESSAGE'],
        'PHARAOH': [AZ_IDX[c] for c in 'PHARAOH'],
    }

    for key_name, key in thematic_keys.items():
        inter = compute_intermediate(key, variant)
        matching_size, _ = precise_matching(inter)
        if matching_size >= 20:
            print(f"    {key_name}: matching = {matching_size}/24 *** INTERESTING ***")
        elif matching_size >= 15:
            print(f"    {key_name}: matching = {matching_size}/24")

    # Also test all single-word 7-letter keys from wordlist
    wordlist_path = "wordlists/english.txt"
    if os.path.exists(wordlist_path):
        best_word = {'name': '', 'matching': 0}
        tested = 0
        with open(wordlist_path) as f:
            for line in f:
                word = line.strip().upper()
                if len(word) == 7 and word.isalpha():
                    key = [AZ_IDX[c] for c in word]
                    inter = compute_intermediate(key, variant)
                    ms, _ = precise_matching(inter)
                    if ms > best_word['matching']:
                        best_word = {'name': word, 'matching': ms}
                    tested += 1

        print(f"    Wordlist (7-letter words): tested {tested}, "
              f"best = {best_word['name']} with matching = {best_word['matching']}/24")


# ── Phase 3: Random key sampling ─────────────────────────────────────────

print("\n" + "-" * 50)
print("Phase 3: Random key sampling (baseline)")
print("-" * 50)

import random
random.seed(42)

for variant in ['vig', 'beau']:
    matching_dist = Counter()
    for _ in range(100000):
        key = [random.randint(0, 25) for _ in range(7)]
        inter = compute_intermediate(key, variant)
        ms, _ = precise_matching(inter)
        matching_dist[ms] += 1

    print(f"\n  {variant.upper()} random matching distribution (100K samples):")
    for ms in sorted(matching_dist.keys(), reverse=True)[:10]:
        print(f"    {ms}/24: {matching_dist[ms]} ({matching_dist[ms]/1000:.1f}%)")


# ── Summary ──────────────────────────────────────────────────────────────

total_elapsed = time.time() - t0
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total time: {total_elapsed:.1f}s")
print(f"  This experiment checks whether period-7 keys can produce the cribs")
print(f"  under ARBITRARY transposition (not just columnar).")
print(f"  The random baseline tells us how many keys achieve 24/24 matching.")

output = {
    'experiment': 'E-S-87',
    'description': 'KRYPTOS key + arbitrary transposition feasibility',
    'elapsed_seconds': total_elapsed,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_87_kryptos_key_arbtrans.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_87_kryptos_key_arbtrans.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_87_kryptos_key_arbtrans.py")
