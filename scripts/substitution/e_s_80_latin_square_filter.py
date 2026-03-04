#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: substitution
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-80: Latin Square Tableau Filter for Width-7 Columnar

If K4 uses a custom Vigenère-like tableau (the "coding charts") that forms
a proper Latin square, then cross-column constraints dramatically reduce
the number of valid column orderings under Model B (trans→sub).

Latin square constraints on the 26×26 tableau T:
  Row uniqueness:  T[r][a] = T[r][b] ⟹ a = b  (each row is a permutation)
  Column uniqueness: T[r][a] = T[s][a] ⟹ r = s  (each column is a permutation)

For cribs at positions p1, p2 with the same PT letter but different columns:
  → T[K[c1]][PT] ≠ T[K[c2]][PT]  (column uniqueness, if K[c1] ≠ K[c2])
  → The CT letters at their transposed positions must differ

For cribs in the same column with different PT letters:
  → T[K[c]][PT1] ≠ T[K[c]][PT2]  (row uniqueness)
  → The CT letters at their transposed positions must differ

For cribs in different columns mapping to the same CT letter:
  → T[K[c1]][PT1] = T[K[c2]][PT2] with K[c1] ≠ K[c2]
  → PT1 ≠ PT2  (row uniqueness of transpose)
  → The PT letters must differ (which they may or may not)
"""

import json
import os
import sys
import time
from itertools import permutations
from collections import Counter

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
CRIB_POS = sorted(CRIB_DICT.keys())

WIDTH = 7
NROWS_FULL = N // WIDTH   # 13
NROWS_EXTRA = N % WIDTH   # 6

print("=" * 70)
print("E-S-80: Latin Square Tableau Filter")
print("=" * 70)
print(f"CT length: {N}, Width: {WIDTH}")
col_lengths = [NROWS_FULL + 1 if c < NROWS_EXTRA else NROWS_FULL for c in range(WIDTH)]
print(f"Column lengths: {col_lengths}")

# ── Crib column assignments ─────────────────────────────────────────────

print("\n" + "-" * 50)
print("Crib column assignments (original grid, width 7):")
print("-" * 50)

col_cribs = {}
for p in CRIB_POS:
    col = p % WIDTH
    row = p // WIDTH
    if col not in col_cribs:
        col_cribs[col] = []
    col_cribs[col].append(p)

for col in range(WIDTH):
    if col in col_cribs:
        entries = [(p, CRIB_DICT[p]) for p in col_cribs[col]]
        print(f"  Col {col}: {entries}")

# ── Pre-compute constraint pairs ────────────────────────────────────────

# Type A: Same column, different PT → CT must differ (row injectivity)
# Note: all PT letters within each column happen to be distinct,
# so this constraint requires all CT values within each column to be distinct.
same_col_pairs = []
for col in range(WIDTH):
    if col in col_cribs:
        positions = col_cribs[col]
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                p1, p2 = positions[i], positions[j]
                # Verify PT letters differ (they do for all columns)
                assert CRIB_DICT[p1] != CRIB_DICT[p2], f"Same PT in same col: {p1},{p2}"
                same_col_pairs.append((p1, p2, col))

print(f"\n  Within-column distinctness pairs: {len(same_col_pairs)}")

# Type B: Different column, same PT → CT must differ (column uniqueness)
cross_col_same_pt = []
for i in range(len(CRIB_POS)):
    for j in range(i + 1, len(CRIB_POS)):
        p1, p2 = CRIB_POS[i], CRIB_POS[j]
        if CRIB_DICT[p1] == CRIB_DICT[p2] and p1 % WIDTH != p2 % WIDTH:
            cross_col_same_pt.append((p1, p2, CRIB_DICT[p1]))

print(f"  Cross-column same-PT pairs: {len(cross_col_same_pt)}")
for p1, p2, pt in cross_col_same_pt:
    print(f"    PT={pt}: pos {p1} (col {p1 % WIDTH}) vs pos {p2} (col {p2 % WIDTH})")

# Type C: Different column, same CT → PT must differ (transpose uniqueness)
# This is checked dynamically since CT values depend on the ordering.

# ── Build columnar transposition ────────────────────────────────────────

def build_inv_perm(order):
    """Build inverse permutation: inv_perm[pt_pos] = ct_pos."""
    inv_perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        c = order[rank]
        clen = col_lengths[c]
        for row in range(clen):
            pt_pos = row * WIDTH + c
            inv_perm[pt_pos] = j
            j += 1
    return inv_perm


# ── Phase 1: Filter all 5040 orderings ──────────────────────────────────

print("\n" + "-" * 50)
print("Phase 1: Filter 5040 orderings by Latin Square constraints")
print("-" * 50)

t0 = time.time()
all_orders = list(permutations(range(WIDTH)))
survivors = []
violation_type_counts = Counter()
violation_dist = Counter()

for order in all_orders:
    order = list(order)
    inv_perm = build_inv_perm(order)

    violations = 0
    vtype = []

    # Constraint A: Within same column, different PT → different CT
    for p1, p2, col in same_col_pairs:
        j1 = inv_perm[p1]
        j2 = inv_perm[p2]
        if CT[j1] == CT[j2]:
            violations += 1
            vtype.append('A')

    # Constraint B: Cross-column, same PT → different CT
    for p1, p2, pt in cross_col_same_pt:
        j1 = inv_perm[p1]
        j2 = inv_perm[p2]
        if CT[j1] == CT[j2]:
            violations += 1
            vtype.append('B')

    # Constraint C: Cross-column, same CT → different PT (dynamic)
    ct_groups = {}
    for p in CRIB_POS:
        j = inv_perm[p]
        ct_letter = CT[j]
        col = p % WIDTH
        if ct_letter not in ct_groups:
            ct_groups[ct_letter] = []
        ct_groups[ct_letter].append((p, CRIB_DICT[p], col))

    for ct_l, entries in ct_groups.items():
        for i in range(len(entries)):
            for k in range(i + 1, len(entries)):
                p1, pt1, c1 = entries[i]
                p2, pt2, c2 = entries[k]
                if c1 != c2 and pt1 == pt2:
                    # This is actually the same as Constraint B
                    # (same PT, different col → same CT is a violation)
                    # Already counted above; but let's verify
                    pass
                # NEW: same CT, different col, same PT → double violation
                # We only need: same CT, different col → PT must differ
                # If PT is the same AND CT is the same AND different col:
                # that's already caught by B.
                # The NEW constraint is: same CT + different col is FINE
                # as long as PT differs. We only flag if they fail B.

    violation_dist[violations] += 1
    for v in vtype:
        violation_type_counts[v] += 1

    if violations == 0:
        survivors.append(order)

elapsed = time.time() - t0
print(f"\n  Filtered {len(all_orders)} orderings in {elapsed:.1f}s")
print(f"\n  Violation distribution:")
for v in sorted(violation_dist.keys()):
    print(f"    {v} violations: {violation_dist[v]} ({100 * violation_dist[v] / len(all_orders):.1f}%)")

print(f"\n  Violation types: A={violation_type_counts['A']}, B={violation_type_counts['B']}")
print(f"\n  SURVIVORS: {len(survivors)} orderings ({100 * len(survivors) / len(all_orders):.1f}%)")

# ── Phase 2: Cross-reference with E-S-73 valid orderings ────────────────

print("\n" + "-" * 50)
print("Phase 2: Cross-reference with E-S-73 crib-consistent orderings")
print("-" * 50)

# E-S-73 found 432/5040 orderings where all 24 cribs are consistent
# (i.e., within each column, no two cribs with the same PT letter
#  map to different CT letters).
# The Latin square filter is ADDITIONAL.
# Let's check: how many of the 432 survive the Latin square filter?

# Recompute the 432 "crib-consistent" orderings
crib_consistent = []
for order in all_orders:
    order = list(order)
    inv_perm = build_inv_perm(order)

    # For each column, check that same PT letter → same CT letter
    ok = True
    for col in range(WIDTH):
        if col not in col_cribs:
            continue
        mapping = {}  # PT letter → CT letter
        for p in col_cribs[col]:
            j = inv_perm[p]
            ct = CT[j]
            pt = CRIB_DICT[p]
            if pt in mapping:
                if mapping[pt] != ct:
                    ok = False
                    break
            else:
                mapping[pt] = ct
        if not ok:
            break

    if ok:
        crib_consistent.append(tuple(order))

crib_consistent_set = set(crib_consistent)
ls_survivor_set = set(tuple(o) for o in survivors)

both = crib_consistent_set & ls_survivor_set
ls_only = ls_survivor_set - crib_consistent_set
crib_only = crib_consistent_set - ls_survivor_set

print(f"  Crib-consistent orderings (E-S-73 style): {len(crib_consistent)}")
print(f"  Latin square survivors: {len(survivors)}")
print(f"  Both crib-consistent AND LS-valid: {len(both)}")
print(f"  LS-valid but NOT crib-consistent: {len(ls_only)}")
print(f"  Crib-consistent but NOT LS-valid: {len(crib_only)}")

# The interesting set: orderings that satisfy BOTH crib consistency AND Latin square
joint_survivors = sorted(both)
print(f"\n  JOINT SURVIVORS: {len(joint_survivors)}")

if len(joint_survivors) <= 50:
    for i, order in enumerate(joint_survivors):
        print(f"    #{i + 1}: {list(order)}")


# ── Phase 3: Keystream analysis of joint survivors ──────────────────────

if joint_survivors:
    print("\n" + "-" * 50)
    print("Phase 3: Keystream analysis of joint survivors")
    print("-" * 50)

    for variant in ['vig', 'beau']:
        print(f"\n  Variant: {variant.upper()}")

        for oi, order in enumerate(joint_survivors[:20]):
            order = list(order)
            inv_perm = build_inv_perm(order)

            # Compute keystream at crib positions, grouped by column
            col_keys = {}
            for p in CRIB_POS:
                j = inv_perm[p]
                pt_v = IDX[CRIB_DICT[p]]
                ct_v = IDX[CT[j]]
                if variant == 'vig':
                    kv = (ct_v - pt_v) % 26
                else:
                    kv = (ct_v + pt_v) % 26
                col = p % WIDTH
                if col not in col_keys:
                    col_keys[col] = []
                col_keys[col].append((p, kv))

            # Check period-7 consistency (all values in same column are equal)
            all_consistent = True
            key_vals = {}
            for col in range(WIDTH):
                if col in col_keys:
                    kvs = [kv for _, kv in col_keys[col]]
                    if len(set(kvs)) > 1:
                        all_consistent = False
                    else:
                        key_vals[col] = kvs[0]

            if oi < 10 or all_consistent:
                consistency = "PERIOD-7 ✓" if all_consistent else "NOT period-7"
                print(f"\n    Order {list(order)}: {consistency}")
                for col in range(WIDTH):
                    if col in col_keys:
                        vals = [f"k[{p}]={kv}" for p, kv in sorted(col_keys[col])]
                        kvs = [kv for _, kv in col_keys[col]]
                        n_unique = len(set(kvs))
                        print(f"      Col {col}: {', '.join(vals)}"
                              f" → {n_unique} unique val{'s' if n_unique > 1 else ''}")

                if all_consistent and key_vals:
                    key = [key_vals.get(c, -1) for c in range(WIDTH)]
                    key_letters = ''.join(AZ[k] if k >= 0 else '?' for k in key)
                    print(f"      Period-7 key: {key} = '{key_letters}'")


# ── Phase 4: Extended crib filter on joint survivors ────────────────────

if joint_survivors:
    print("\n" + "-" * 50)
    print("Phase 4: Extended crib filtering with thematic words")
    print("-" * 50)

    candidate_phrases = [
        "WHATSTHEPOINT",
        "WHATISTHEPOINT",
        "DEGREES",
        "BURIED",
        "UNDERGROUND",
        "IQLUSION",
        "TOWER",
    ]

    for phrase in candidate_phrases:
        phrase_len = len(phrase)
        best_count = len(joint_survivors)
        best_pos = -1

        for start in range(N - phrase_len + 1):
            # Build extended crib dict
            extended = dict(CRIB_DICT)
            conflict = False
            for i, ch in enumerate(phrase):
                pos = start + i
                if pos in extended:
                    if extended[pos] != ch:
                        conflict = True
                        break
                else:
                    extended[pos] = ch

            if conflict:
                continue

            ext_pos = sorted(extended.keys())

            # Apply all Latin square constraints with extended cribs
            count_survive = 0
            for order in joint_survivors:
                order = list(order)
                inv_perm = build_inv_perm(order)
                ok = True

                # Constraint A: within column, different PT → different CT
                col_maps = {}
                for p in ext_pos:
                    col = p % WIDTH
                    j = inv_perm[p]
                    ct = CT[j]
                    pt = extended[p]
                    if col not in col_maps:
                        col_maps[col] = {}
                    if pt in col_maps[col]:
                        if col_maps[col][pt] != ct:
                            ok = False
                            break
                    else:
                        # Check bijectivity: different PT → different CT
                        if ct in col_maps[col].values():
                            # Another PT already maps to this CT in this column
                            # Check if it's the same PT (which would be caught above)
                            existing_pts = [p2 for p2, c2 in col_maps[col].items() if c2 == ct]
                            if existing_pts and existing_pts[0] != pt:
                                ok = False
                                break
                        col_maps[col][pt] = ct

                if not ok:
                    continue

                # Constraint B: cross-column, same PT → different CT
                for i in range(len(ext_pos)):
                    if not ok:
                        break
                    for k in range(i + 1, len(ext_pos)):
                        p1, p2 = ext_pos[i], ext_pos[k]
                        if extended[p1] == extended[p2] and p1 % WIDTH != p2 % WIDTH:
                            j1 = inv_perm[p1]
                            j2 = inv_perm[p2]
                            if CT[j1] == CT[j2]:
                                ok = False
                                break

                if ok:
                    count_survive += 1

            if count_survive < best_count:
                best_count = count_survive
                best_pos = start

        reduction = len(joint_survivors) - best_count
        if reduction > 0:
            print(f"  '{phrase}' at pos {best_pos}: {best_count}/{len(joint_survivors)} survive"
                  f" (eliminated {reduction})")
        else:
            print(f"  '{phrase}': no additional filtering")


# ── Phase 5: Test if any known keyword produces the column ordering ─────

if joint_survivors:
    print("\n" + "-" * 50)
    print("Phase 5: Keyword-derived column orderings")
    print("-" * 50)

    def keyword_to_order(keyword7):
        """Convert a 7-letter keyword to column reading order."""
        indexed = [(ch, i) for i, ch in enumerate(keyword7)]
        sorted_idx = sorted(indexed, key=lambda x: (x[0], x[1]))
        order = [0] * 7
        for rank, (ch, orig_idx) in enumerate(sorted_idx):
            order[rank] = orig_idx
        return tuple(order)

    # Test some thematic keywords
    test_keywords = [
        "KRYPTOS", "PALIMPS", "SANBORN", "SCHEIDT", "BERLIN",
        "LANGLEY", "SCULPTR", "ARTISAN", "ENCRYPT", "DECODED",
        "COMPASS", "BEARING", "LIBRARY", "QUARTER", "CABINET",
    ]

    # Also test: for each joint survivor, what 7-letter keywords produce that ordering?
    survivor_orders = set(tuple(o) for o in joint_survivors)

    matches = []
    for kw in test_keywords:
        if len(kw) == 7:
            order = keyword_to_order(kw)
            is_survivor = order in survivor_orders
            if is_survivor:
                matches.append((kw, list(order)))
                print(f"  '{kw}' → {list(order)} — IN SURVIVORS ✓")
            else:
                print(f"  '{kw}' → {list(order)} — not a survivor")

    # Brute-force: check all 7-letter words from wordlist
    wordlist_path = "wordlists/english.txt"
    if os.path.exists(wordlist_path):
        print(f"\n  Checking 7-letter words from wordlist...")
        word_matches = []
        with open(wordlist_path) as f:
            for line in f:
                word = line.strip().upper()
                if len(word) == 7 and word.isalpha():
                    order = keyword_to_order(word)
                    if order in survivor_orders:
                        word_matches.append((word, list(order)))

        print(f"  Found {len(word_matches)} 7-letter keywords matching survivor orderings")
        if len(word_matches) <= 100:
            for kw, order in sorted(word_matches):
                print(f"    '{kw}' → {order}")
        else:
            # Group by ordering
            order_words = {}
            for kw, order in word_matches:
                key = tuple(order)
                if key not in order_words:
                    order_words[key] = []
                order_words[key].append(kw)
            for order, words in sorted(order_words.items()):
                sample = words[:5]
                extra = f" +{len(words) - 5} more" if len(words) > 5 else ""
                print(f"    {list(order)}: {', '.join(sample)}{extra}")


# ── Summary ──────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total orderings: {len(all_orders)}")
print(f"  Crib-consistent: {len(crib_consistent)}")
print(f"  Latin square valid: {len(survivors)}")
print(f"  JOINT (both): {len(joint_survivors)}")

if len(joint_survivors) == 0:
    verdict = "ELIMINATED — Latin square tableau + width-7 columnar is IMPOSSIBLE"
elif len(joint_survivors) <= 10:
    verdict = f"HIGHLY CONSTRAINED — only {len(joint_survivors)} orderings survive"
elif len(joint_survivors) <= 50:
    verdict = f"WELL CONSTRAINED — {len(joint_survivors)} orderings survive"
elif len(joint_survivors) <= 200:
    verdict = f"MODERATELY CONSTRAINED — {len(joint_survivors)} orderings survive"
else:
    verdict = f"WEAKLY CONSTRAINED — {len(joint_survivors)} orderings survive"

print(f"  Verdict: {verdict}")

output = {
    'experiment': 'E-S-80',
    'description': 'Latin Square Tableau Filter for Width-7 Columnar',
    'total_orderings': len(all_orders),
    'crib_consistent': len(crib_consistent),
    'ls_survivors': len(survivors),
    'joint_survivors': len(joint_survivors),
    'joint_orderings': [list(o) for o in joint_survivors[:200]],
    'violation_distribution': {str(k): v for k, v in sorted(violation_dist.items())},
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_80_latin_square.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_80_latin_square.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_80_latin_square_filter.py")
