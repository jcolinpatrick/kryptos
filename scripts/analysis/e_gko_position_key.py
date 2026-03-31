#!/usr/bin/env python3
"""
E-GKO-POSITION-KEY: Position-Dependent Key Functions Producing GKO at Crib Positions

The Beaufort A=0 keystream at 24 crib positions has 12 values in {G,K,O} = {6,10,14}.
This script tests what position-dependent functions key[i] = f(i) could produce
that specific pattern, and whether the key depends on position, CT letter, or both.

Seven tests:
  T1: Linear key functions key[i] = (a*i + b) mod 26
  T2: Quadratic key functions key[i] = (a*i^2 + b*i + c) mod 26
  T3: Modular key patterns key[i] = lookup[i mod P]
  T4: Key as function of CT letter
  T5: Position mod M predicting even/odd keystream
  T6: Difference patterns in GKO sequence
  T7: Position-to-GKO-index mapping (G=0, K=1, O=2)

Attack-type: analysis
Family: keystream-review
Status: active
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, json
from datetime import datetime, timezone
from collections import Counter, defaultdict

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.alphabet import AZ

# ── Setup ────────────────────────────────────────────────────────────────────

ENE_POS = list(range(21, 34))   # 13 positions
BCL_POS = list(range(63, 74))   # 11 positions
ALL_CRIB_POS = sorted(ENE_POS + BCL_POS)  # 24 positions

ENE_PT = "EASTNORTHEAST"
BCL_PT = "BERLINCLOCK"
FULL_PT_AT_CRIBS = ENE_PT + BCL_PT  # 24 chars

# Beaufort A=0 keystream: k[i] = (CT[i] + PT[i]) mod 26
keystream = {}  # pos -> key value
for i, pos in enumerate(ALL_CRIB_POS):
    ct_val = AZ.char_to_idx(CT[pos])
    pt_val = AZ.char_to_idx(FULL_PT_AT_CRIBS[i])
    keystream[pos] = (ct_val + pt_val) % 26

GKO = {6, 10, 14}

# Separate GKO and non-GKO positions
gko_positions = [p for p in ALL_CRIB_POS if keystream[p] in GKO]
non_gko_positions = [p for p in ALL_CRIB_POS if keystream[p] not in GKO]

print("=" * 70)
print("E-GKO-POSITION-KEY: Position-Dependent Key Functions")
print("=" * 70)
print(f"\nAll 24 crib positions with keystream values:")
for pos in ALL_CRIB_POS:
    kv = keystream[pos]
    kc = AZ.idx_to_char(kv)
    gko_mark = " <-GKO" if kv in GKO else ""
    print(f"  pos {pos:3d}: key={kc}({kv:2d}){gko_mark}")

print(f"\n12 GKO positions: {gko_positions}")
print(f"  Key values: {[keystream[p] for p in gko_positions]}")
print(f"  Key chars:  {''.join(AZ.idx_to_char(keystream[p]) for p in gko_positions)}")
print(f"\n12 non-GKO positions: {non_gko_positions}")
print(f"  Key values: {[keystream[p] for p in non_gko_positions]}")
print(f"  Key chars:  {''.join(AZ.idx_to_char(keystream[p]) for p in non_gko_positions)}")

results = {"timestamp": datetime.now(timezone.utc).isoformat(), "tests": {}}

# ── Test 1: Linear key functions ──────────────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 1: Linear key functions key[i] = (a*i + b) mod 26")
print("=" * 70)

best_linear = []
for a in range(26):
    for b in range(26):
        correct_gko = 0
        false_gko = 0
        total_correct = 0
        for pos in ALL_CRIB_POS:
            predicted = (a * pos + b) % 26
            actual = keystream[pos]
            if pos in gko_positions:
                if predicted in GKO:
                    correct_gko += 1
                if predicted == actual:
                    total_correct += 1
            else:
                if predicted in GKO:
                    false_gko += 1
                if predicted == actual:
                    total_correct += 1
        # Classification score: correctly classify GKO vs non-GKO
        class_score = correct_gko - false_gko
        # Exact match score: how many positions have exactly the right key value
        best_linear.append({
            'a': a, 'b': b,
            'correct_gko': correct_gko,
            'false_gko': false_gko,
            'class_score': class_score,
            'exact_match': total_correct,
        })

best_linear.sort(key=lambda x: (-x['class_score'], -x['exact_match']))

print(f"\nTop 10 by GKO classification score (correct_GKO - false_GKO):")
print(f"  {'a':>3s} {'b':>3s}  correct_GKO  false_GKO  class_score  exact_match")
for entry in best_linear[:10]:
    print(f"  {entry['a']:3d} {entry['b']:3d}  {entry['correct_gko']:11d}  {entry['false_gko']:9d}  {entry['class_score']:11d}  {entry['exact_match']:11d}")
    # Show what this function produces at all crib positions
    vals = [(a_pos, (entry['a'] * a_pos + entry['b']) % 26) for a_pos in ALL_CRIB_POS]

# Also find best by exact match
best_exact = sorted(best_linear, key=lambda x: -x['exact_match'])
print(f"\nTop 10 by exact key value match:")
print(f"  {'a':>3s} {'b':>3s}  correct_GKO  false_GKO  class_score  exact_match")
for entry in best_exact[:10]:
    print(f"  {entry['a']:3d} {entry['b']:3d}  {entry['correct_gko']:11d}  {entry['false_gko']:9d}  {entry['class_score']:11d}  {entry['exact_match']:11d}")

# Expected under random: a linear function hits GKO (3/26 chance) at each position
# Expected correct_gko = 12 * 3/26 = 1.385, expected false_gko = 12 * 3/26 = 1.385
# Expected class_score = 0
print(f"\nBaseline: random function hits GKO at each pos with prob 3/26 = {3/26:.4f}")
print(f"  Expected correct_GKO = {12 * 3/26:.2f}, expected false_GKO = {12 * 3/26:.2f}")
print(f"  Best observed class_score = {best_linear[0]['class_score']}")
print(f"  Best observed exact_match = {best_exact[0]['exact_match']}")

results["tests"]["T1_linear"] = {
    "best_by_class_score": best_linear[:5],
    "best_by_exact_match": best_exact[:5],
    "baseline_expected_correct_gko": round(12 * 3/26, 3),
}

# ── Test 2: Quadratic key functions ───────────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 2: Quadratic key functions key[i] = (a*i^2 + b*i + c) mod 26")
print("=" * 70)

# For each (a,b), fix c so key[24] = 14 (since pos 24 has key O=14)
# c = (14 - a*576 - b*24) mod 26

best_quadratic = []
for a in range(26):
    for b in range(26):
        c = (14 - a * 576 - b * 24) % 26
        correct_gko = 0
        false_gko = 0
        total_correct = 0
        for pos in ALL_CRIB_POS:
            predicted = (a * pos * pos + b * pos + c) % 26
            actual = keystream[pos]
            if pos in gko_positions:
                if predicted in GKO:
                    correct_gko += 1
                if predicted == actual:
                    total_correct += 1
            else:
                if predicted in GKO:
                    false_gko += 1
                if predicted == actual:
                    total_correct += 1
        class_score = correct_gko - false_gko
        best_quadratic.append({
            'a': a, 'b': b, 'c': c,
            'correct_gko': correct_gko,
            'false_gko': false_gko,
            'class_score': class_score,
            'exact_match': total_correct,
        })

best_quadratic.sort(key=lambda x: (-x['class_score'], -x['exact_match']))

print(f"\nTop 10 by GKO classification score (c constrained by pos 24 -> O):")
print(f"  {'a':>3s} {'b':>3s} {'c':>3s}  correct_GKO  false_GKO  class_score  exact_match")
for entry in best_quadratic[:10]:
    print(f"  {entry['a']:3d} {entry['b']:3d} {entry['c']:3d}  {entry['correct_gko']:11d}  {entry['false_gko']:9d}  {entry['class_score']:11d}  {entry['exact_match']:11d}")

# Also try unconstrained: sweep all c values for the best (a,b)
print(f"\nUnconstrained sweep (all a,b,c in 0-25):")
best_quad_free = []
for a in range(26):
    for b in range(26):
        for c in range(26):
            correct_gko = 0
            false_gko = 0
            total_correct = 0
            for pos in ALL_CRIB_POS:
                predicted = (a * pos * pos + b * pos + c) % 26
                actual = keystream[pos]
                if pos in gko_positions:
                    if predicted in GKO:
                        correct_gko += 1
                    if predicted == actual:
                        total_correct += 1
                else:
                    if predicted in GKO:
                        false_gko += 1
                    if predicted == actual:
                        total_correct += 1
            class_score = correct_gko - false_gko
            if class_score >= 8 or total_correct >= 5:
                best_quad_free.append({
                    'a': a, 'b': b, 'c': c,
                    'correct_gko': correct_gko,
                    'false_gko': false_gko,
                    'class_score': class_score,
                    'exact_match': total_correct,
                })

best_quad_free.sort(key=lambda x: (-x['class_score'], -x['exact_match']))
print(f"  Configs with class_score >= 8 or exact_match >= 5: {len(best_quad_free)}")
if best_quad_free:
    print(f"  Top 10:")
    print(f"  {'a':>3s} {'b':>3s} {'c':>3s}  correct_GKO  false_GKO  class_score  exact_match")
    for entry in best_quad_free[:10]:
        print(f"  {entry['a']:3d} {entry['b']:3d} {entry['c']:3d}  {entry['correct_gko']:11d}  {entry['false_gko']:9d}  {entry['class_score']:11d}  {entry['exact_match']:11d}")

results["tests"]["T2_quadratic"] = {
    "constrained_top5": best_quadratic[:5],
    "unconstrained_count_high": len(best_quad_free),
    "unconstrained_top5": best_quad_free[:5] if best_quad_free else [],
}

# ── Test 3: Modular key patterns ─────────────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 3: Modular key patterns key[i] = lookup[i mod P]")
print("=" * 70)

for P in range(2, 14):
    # Group crib positions by residue mod P
    residue_groups = defaultdict(list)
    for pos in ALL_CRIB_POS:
        residue_groups[pos % P].append(pos)

    # Count conflicts: positions in same residue class with different key values
    conflicts = 0
    total_pairs = 0
    residue_detail = {}
    for r in sorted(residue_groups.keys()):
        positions = residue_groups[r]
        vals = [keystream[p] for p in positions]
        unique_vals = set(vals)
        n_conflicts = 0
        for i in range(len(vals)):
            for j in range(i + 1, len(vals)):
                total_pairs += 1
                if vals[i] != vals[j]:
                    n_conflicts += 1
                    conflicts += 1
        residue_detail[r] = {
            'positions': positions,
            'key_values': vals,
            'key_chars': [AZ.idx_to_char(v) for v in vals],
            'unique_values': len(unique_vals),
            'conflicts': n_conflicts,
        }

    # Minimum conflicts needed for a valid lookup table: 0 means period P works perfectly
    print(f"\n  Period {P}: {conflicts} conflicts across {total_pairs} pairs")
    for r in sorted(residue_detail.keys()):
        d = residue_detail[r]
        if len(d['positions']) > 1:
            conflict_mark = " CONFLICT" if d['conflicts'] > 0 else " OK"
            print(f"    r={r}: pos={d['positions']} keys={''.join(d['key_chars'])} unique={d['unique_values']}{conflict_mark}")

results["tests"]["T3_modular"] = {}
for P in range(2, 14):
    residue_groups = defaultdict(list)
    for pos in ALL_CRIB_POS:
        residue_groups[pos % P].append(pos)
    conflicts = 0
    for r in residue_groups:
        vals = [keystream[p] for p in residue_groups[r]]
        for i in range(len(vals)):
            for j in range(i + 1, len(vals)):
                if vals[i] != vals[j]:
                    conflicts += 1
    results["tests"]["T3_modular"][f"period_{P}"] = {"conflicts": conflicts}

# ── Test 4: Key as function of CT letter ─────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 4: Key as function of CT letter — key[i] = f(CT[i])")
print("=" * 70)

# Build mapping: CT letter -> list of key values
ct_to_key = defaultdict(list)
for pos in ALL_CRIB_POS:
    ct_letter = CT[pos]
    ct_to_key[ct_letter].append(keystream[pos])

consistent = 0
inconsistent = 0
multi_ct = 0
print(f"\n  CT letter -> key values at crib positions:")
for ct_letter in sorted(ct_to_key.keys()):
    vals = ct_to_key[ct_letter]
    unique = set(vals)
    chars = [AZ.idx_to_char(v) for v in vals]
    if len(vals) > 1:
        multi_ct += 1
        if len(unique) == 1:
            consistent += 1
            status = "CONSISTENT"
        else:
            inconsistent += 1
            status = "INCONSISTENT"
    else:
        status = "single"
    print(f"    {ct_letter} -> {chars} = {vals} [{status}]")

print(f"\n  CT letters appearing multiple times: {multi_ct}")
print(f"  Consistent mappings: {consistent}")
print(f"  Inconsistent mappings: {inconsistent}")
print(f"  -> {'KEY DEPENDS ON POSITION, NOT JUST CT' if inconsistent > 0 else 'CT-DEPENDENT KEY POSSIBLE'}")

# For consistent ones, what are the mappings?
clean_map = {}
for ct_letter in ct_to_key:
    vals = ct_to_key[ct_letter]
    if len(set(vals)) == 1:
        clean_map[ct_letter] = vals[0]

print(f"\n  Clean (single-valued) CT->key mappings:")
for ct_letter in sorted(clean_map.keys()):
    kv = clean_map[ct_letter]
    print(f"    {ct_letter}({AZ.char_to_idx(ct_letter):2d}) -> {AZ.idx_to_char(kv)}({kv:2d})")

results["tests"]["T4_ct_function"] = {
    "multi_ct_letters": multi_ct,
    "consistent": consistent,
    "inconsistent": inconsistent,
    "clean_mappings": {k: v for k, v in clean_map.items()},
    "all_mappings": {k: v for k, v in ct_to_key.items()},
}

# ── Test 5: Position mod M predicting even/odd keystream ─────────────────────

print("\n" + "=" * 70)
print("TEST 5: Position mod M predicting even/odd keystream")
print("=" * 70)

# GKO values are all EVEN (6,10,14). Check if position mod M predicts parity.
even_positions = [pos for pos in ALL_CRIB_POS if keystream[pos] % 2 == 0]
odd_positions = [pos for pos in ALL_CRIB_POS if keystream[pos] % 2 == 1]

print(f"\n  Even keystream (16 positions): {even_positions}")
print(f"  Odd keystream  (8 positions):  {odd_positions}")

for M in range(2, 14):
    # For each residue class mod M, compute fraction that are even
    residue_even = defaultdict(lambda: [0, 0])  # [even_count, total_count]
    for pos in ALL_CRIB_POS:
        r = pos % M
        residue_even[r][1] += 1
        if keystream[pos] % 2 == 0:
            residue_even[r][0] += 1

    # Check if any residue class perfectly predicts parity
    perfect_even = []  # residues that are 100% even
    perfect_odd = []   # residues that are 100% odd
    for r in sorted(residue_even.keys()):
        e, t = residue_even[r]
        if t > 0:
            if e == t:
                perfect_even.append(r)
            elif e == 0:
                perfect_odd.append(r)

    # Overall prediction accuracy if we use majority vote per residue
    correct = 0
    total = 0
    for r in residue_even:
        e, t = residue_even[r]
        o = t - e
        correct += max(e, o)
        total += t
    accuracy = correct / total if total > 0 else 0

    # Check chi-squared-like measure
    chi2_parts = []
    for r in residue_even:
        e, t = residue_even[r]
        if t > 0:
            expected_e = t * 16 / 24  # overall even rate
            if expected_e > 0 and (t - expected_e) > 0:
                chi2_parts.append((e - expected_e)**2 / expected_e + ((t - e) - (t - expected_e))**2 / (t - expected_e))

    if perfect_even or perfect_odd or accuracy > 0.75:
        print(f"\n  mod {M}: accuracy={accuracy:.3f}, perfect_even_residues={perfect_even}, perfect_odd_residues={perfect_odd}")
        for r in sorted(residue_even.keys()):
            e, t = residue_even[r]
            print(f"    r={r}: {e}/{t} even ({100*e/t:.0f}%)" if t > 0 else f"    r={r}: empty")

results["tests"]["T5_parity_prediction"] = {}
for M in range(2, 14):
    residue_even = defaultdict(lambda: [0, 0])
    for pos in ALL_CRIB_POS:
        r = pos % M
        residue_even[r][1] += 1
        if keystream[pos] % 2 == 0:
            residue_even[r][0] += 1
    correct = sum(max(e, t - e) for r, (e, t) in residue_even.items())
    total = sum(t for _, (_, t) in residue_even.items())
    results["tests"]["T5_parity_prediction"][f"mod_{M}"] = {
        "accuracy": round(correct / total, 4) if total > 0 else 0,
        "residue_detail": {str(r): {"even": e, "total": t} for r, (e, t) in residue_even.items()},
    }

# ── Test 6: Difference patterns in GKO sequence ─────────────────────────────

print("\n" + "=" * 70)
print("TEST 6: Difference patterns in GKO sequence")
print("=" * 70)

gko_vals = [keystream[p] for p in gko_positions]
gko_chars = [AZ.idx_to_char(v) for v in gko_vals]

print(f"\n  GKO positions: {gko_positions}")
print(f"  GKO values:    {gko_vals}")
print(f"  GKO chars:     {''.join(gko_chars)}")

# Consecutive differences in key values
diffs = [gko_vals[i+1] - gko_vals[i] for i in range(len(gko_vals) - 1)]
print(f"\n  Value differences: {diffs}")
print(f"  All multiples of 4: {all(d % 4 == 0 for d in diffs)}")

# Divide by 4
diffs_div4 = [d // 4 for d in diffs]
print(f"  Differences / 4:   {diffs_div4}")

# Map to GKO indices: G=6->0, K=10->1, O=14->2
gko_index_map = {6: 0, 10: 1, 14: 2}
gko_indices = [gko_index_map[v] for v in gko_vals]
gko_index_labels = ['G', 'K', 'O']
print(f"\n  GKO index sequence (G=0,K=1,O=2): {gko_indices}")
print(f"  As letters: {''.join(gko_index_labels[i] for i in gko_indices)}")

# Index differences
idx_diffs = [gko_indices[i+1] - gko_indices[i] for i in range(len(gko_indices) - 1)]
print(f"  Index differences: {idx_diffs}")

# Position gaps between consecutive GKO positions
pos_gaps = [gko_positions[i+1] - gko_positions[i] for i in range(len(gko_positions) - 1)]
print(f"\n  Position gaps: {pos_gaps}")

# Check if position gap correlates with value change
print(f"\n  Position gap -> value change:")
for i in range(len(pos_gaps)):
    gap = pos_gaps[i]
    vdiff = diffs[i]
    idiff = idx_diffs[i]
    print(f"    gap={gap:2d}: {gko_chars[i]}->{gko_chars[i+1]} diff={vdiff:+3d} idx_diff={idiff:+2d}")

# Check if gko_index = f(position) mod 3
print(f"\n  GKO index vs position mod 3:")
for i, pos in enumerate(gko_positions):
    gi = gko_indices[i]
    pm3 = pos % 3
    match = "MATCH" if gi == pm3 else ""
    print(f"    pos {pos:3d} mod 3 = {pm3}, GKO index = {gi} ({gko_index_labels[gi]}) {match}")

matches_mod3 = sum(1 for i, pos in enumerate(gko_positions) if gko_indices[i] == pos % 3)
print(f"  Matches: {matches_mod3}/12 (expected: 4.0)")

# Check various position functions
print(f"\n  Systematic check: GKO_index vs (pos * a + b) mod 3 for all a,b in 0-2:")
best_mod3 = []
for a in range(3):
    for b in range(3):
        matches = sum(1 for i, pos in enumerate(gko_positions) if gko_indices[i] == (pos * a + b) % 3)
        best_mod3.append((a, b, matches))
        if matches >= 6:
            print(f"    a={a}, b={b}: {matches}/12 matches")

results["tests"]["T6_differences"] = {
    "gko_positions": gko_positions,
    "gko_values": gko_vals,
    "gko_chars": ''.join(gko_chars),
    "value_diffs": diffs,
    "all_diffs_mult4": all(d % 4 == 0 for d in diffs),
    "diffs_div4": diffs_div4,
    "gko_indices": gko_indices,
    "index_diffs": idx_diffs,
    "position_gaps": pos_gaps,
    "mod3_matches": matches_mod3,
}

# ── Test 7: Position-to-GKO-index mapping ────────────────────────────────────

print("\n" + "=" * 70)
print("TEST 7: Position-to-GKO-index mapping (G=0, K=1, O=2)")
print("=" * 70)

print(f"\n  Testing: does (pos mod M) determine the GKO index?")
print(f"\n  GKO positions and indices:")
for i, pos in enumerate(gko_positions):
    print(f"    pos {pos:3d}: GKO index = {gko_indices[i]} ({gko_index_labels[gko_indices[i]]})")

for M in range(2, 14):
    # For each residue class, check if all GKO positions in that class have the same GKO index
    residue_to_gko = defaultdict(list)
    for i, pos in enumerate(gko_positions):
        residue_to_gko[pos % M].append(gko_indices[i])

    conflicts = 0
    total_multi = 0
    for r in residue_to_gko:
        vals = residue_to_gko[r]
        if len(vals) > 1:
            total_multi += 1
            if len(set(vals)) > 1:
                conflicts += 1

    # Also compute prediction accuracy using majority vote
    correct = 0
    for r in residue_to_gko:
        vals = residue_to_gko[r]
        counter = Counter(vals)
        correct += counter.most_common(1)[0][1]
    accuracy = correct / 12

    if conflicts <= total_multi // 2 or accuracy >= 0.6:
        print(f"\n  mod {M}: accuracy={accuracy:.3f}, conflicted_residues={conflicts}/{total_multi}")
        for r in sorted(residue_to_gko.keys()):
            vals = residue_to_gko[r]
            labels = [gko_index_labels[v] for v in vals]
            consistent = "OK" if len(set(vals)) == 1 else "CONFLICT"
            print(f"    r={r}: {''.join(labels)} [{consistent}]")

# Also try: (a*pos + b) mod 3 as predictor of GKO index
print(f"\n  Full linear search: GKO_index = (a*pos + b) mod 3")
best_linear_gko = []
for a in range(26):
    for b in range(26):
        matches = sum(1 for i, pos in enumerate(gko_positions)
                      if gko_indices[i] == (a * pos + b) % 3)
        if matches >= 8:
            best_linear_gko.append((a, b, matches))

best_linear_gko.sort(key=lambda x: -x[2])
if best_linear_gko:
    print(f"  {len(best_linear_gko)} (a,b) pairs with >= 8/12 matches")
    print(f"  Top 10:")
    for a, b, m in best_linear_gko[:10]:
        predictions = [(a * p + b) % 3 for p in gko_positions]
        pred_str = ''.join(gko_index_labels[p] for p in predictions)
        actual_str = ''.join(gko_index_labels[g] for g in gko_indices)
        print(f"    a={a:2d} b={b:2d}: {m}/12 matches, pred={pred_str} actual={actual_str}")
else:
    print(f"  No (a,b) achieved >= 8/12 matches")

# Also: (a*pos^2 + b*pos + c) mod 3
print(f"\n  Quadratic: GKO_index = (a*pos^2 + b*pos + c) mod 3")
best_quad_gko = []
for a in range(3):
    for b in range(26):
        for c in range(3):
            matches = sum(1 for i, pos in enumerate(gko_positions)
                          if gko_indices[i] == (a * pos * pos + b * pos + c) % 3)
            if matches >= 9:
                best_quad_gko.append((a, b, c, matches))

best_quad_gko.sort(key=lambda x: -x[3])
if best_quad_gko:
    print(f"  {len(best_quad_gko)} (a,b,c) with >= 9/12 matches")
    for a, b, c, m in best_quad_gko[:10]:
        predictions = [(a * p * p + b * p + c) % 3 for p in gko_positions]
        pred_str = ''.join(gko_index_labels[p] for p in predictions)
        actual_str = ''.join(gko_index_labels[g] for g in gko_indices)
        print(f"    a={a} b={b:2d} c={c}: {m}/12 matches, pred={pred_str} actual={actual_str}")
else:
    print(f"  No (a,b,c) achieved >= 9/12 matches")

results["tests"]["T7_gko_index_mapping"] = {
    "best_linear_mod3": best_linear_gko[:10] if best_linear_gko else [],
    "best_quadratic_mod3": [(a, b, c, m) for a, b, c, m in best_quad_gko[:10]] if best_quad_gko else [],
}

# ── Summary ──────────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

t1_best = best_linear[0]
t2_best_c = best_quadratic[0]
t2_best_f = best_quad_free[0] if best_quad_free else None

print(f"""
Test 1 (Linear key[i] = a*i + b mod 26):
  Best classification: a={t1_best['a']}, b={t1_best['b']}
    correct_GKO={t1_best['correct_gko']}/12, false_GKO={t1_best['false_gko']}/12
    class_score={t1_best['class_score']}, exact_match={t1_best['exact_match']}/24
  Best exact match: a={best_exact[0]['a']}, b={best_exact[0]['b']}, exact={best_exact[0]['exact_match']}/24
  -> {'PROMISING' if t1_best['class_score'] >= 8 else 'WEAK' if t1_best['class_score'] >= 4 else 'NO SIGNAL'}

Test 2 (Quadratic key[i] = a*i^2 + b*i + c mod 26):
  Constrained best: a={t2_best_c['a']}, b={t2_best_c['b']}, c={t2_best_c['c']}
    class_score={t2_best_c['class_score']}, exact_match={t2_best_c['exact_match']}/24
  {'Unconstrained best: a=' + str(t2_best_f['a']) + ', b=' + str(t2_best_f['b']) + ', c=' + str(t2_best_f['c']) + ' class_score=' + str(t2_best_f['class_score']) + ', exact_match=' + str(t2_best_f['exact_match']) + '/24' if t2_best_f else 'No unconstrained results above threshold'}

Test 3 (Modular patterns):
  See above for conflict counts per period.
  Perfect period (0 conflicts) would mean key is purely periodic.

Test 4 (Key depends on CT letter):
  {inconsistent} CT letters have inconsistent key mappings.
  {consistent} CT letters have consistent mappings.
  -> {'CT letter does NOT determine key alone' if inconsistent > 0 else 'CT-dependent key POSSIBLE'}

Test 5 (Position mod M predicts parity):
  See above for per-modulus accuracy.
  Overall even rate: 16/24 = 67%.
  Baseline majority-vote accuracy: 67%.

Test 6 (GKO difference patterns):
  All value differences are multiples of 4: {all(d % 4 == 0 for d in diffs)}
  (This is trivially true since all GKO values are in AP step 4)
  GKO index sequence: {gko_indices}
  Differences/4: {diffs_div4}

Test 7 (Position -> GKO index):
  Best linear (a*pos+b) mod 3: {'none >= 8/12' if not best_linear_gko else f'{best_linear_gko[0][2]}/12'}
  Best quadratic mod 3: {'none >= 9/12' if not best_quad_gko else f'{best_quad_gko[0][3]}/12'}
""")

# ── Save results ─────────────────────────────────────────────────────────────

output_path = os.path.join(_ROOT, 'results', 'gko_position_key.json')
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)

print(f"Results saved to: {output_path}")
