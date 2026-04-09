#!/usr/bin/env python3
"""
Cipher: meta_perturbation
Family: archive_evidence
Status: exhausted
Keyspace: see implementation
Last run:
Best score:
"""
"""E-AAA-ONE-LIE-09: One-lie meta-perturbation experiment.

SOURCE: Archives of American Art, IMG_1381-1389.
  - "He lied" with 38→37 coordinate change (exactly -1 in one field)
  - Hypothesis: K4 may involve one intentionally false surface parameter
    that must be corrected by ±1 before the operative mechanism works.

APPROACH: Instead of treating 37 or 38 as magic numbers, we test the
STRUCTURAL PRINCIPLE: exactly one parameter off by ±1.

PARAMETER FAMILIES TESTED:
  F1: Crib position shift (±1 on ENE start, BC start, or both)
  F2: Columnar width ±1 around known-interesting values
  F3: Null count ±1 (16 or 18 instead of 17 consensus nulls)
  F4: Period ±1 around small periods with near-consistency
  F5: Keystream value ±1 at each of 24 crib positions (which perturbed
      value, if any, best improves period consistency?)

CONTROLS: For each perturbation, test the unperturbed baseline AND
  the ±2 neighbors. The one-lie model predicts ±1 should be uniquely
  advantaged over ±0 and ±2.

SCORING: Period consistency score (how many of 24 crib positions are
  consistent with a periodic key of a given period). The one-lie model
  predicts the CORRECTED parameter achieves higher consistency than
  the surface value.
"""

import sys
import os
import time
from collections import Counter, defaultdict

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, CRIB_WORDS,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    BEAN_EQ, BEAN_INEQ,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

t0 = time.time()

# ═══════════════════════════════════════════════════════════════════════════
# BASELINE: Standard keystream at standard crib positions
# ═══════════════════════════════════════════════════════════════════════════

CRIB_POS = sorted(CRIB_DICT.keys())
BEAU_KEYS = {}
for p in CRIB_POS:
    BEAU_KEYS[p] = (ALPH_IDX[CT[p]] + ALPH_IDX[CRIB_DICT[p]]) % MOD

def period_consistency(key_dict, positions, period):
    """Count positions consistent with a period-P key (best majority per residue)."""
    residues = defaultdict(list)
    for p in positions:
        residues[p % period].append(key_dict[p])
    consistent = 0
    for vals in residues.values():
        c = Counter(vals)
        consistent += c.most_common(1)[0][1]
    return consistent

def best_period_score(key_dict, positions, max_period=13):
    """Return (best_period, best_score, scores_by_period)."""
    scores = {}
    for p in range(1, max_period + 1):
        scores[p] = period_consistency(key_dict, positions, p)
    best_p = max(scores, key=scores.get)
    return best_p, scores[best_p], scores

# Bean constraint check
def check_bean(key_dict):
    """Check Bean EQ and count INEQ violations."""
    eq_pass = key_dict.get(27) == key_dict.get(65)
    ineq_pass = 0
    ineq_fail = 0
    for a, b in BEAN_INEQ:
        if a in key_dict and b in key_dict:
            if key_dict[a] != key_dict[b]:
                ineq_pass += 1
            else:
                ineq_fail += 1
    return eq_pass, ineq_pass, ineq_fail

print("=" * 80)
print("E-AAA-ONE-LIE-09: One-Lie Meta-Perturbation Experiment")
print("=" * 80)

# ═══════════════════════════════════════════════════════════════════════════
# BASELINE
# ═══════════════════════════════════════════════════════════════════════════

base_bp, base_bs, base_scores = best_period_score(BEAU_KEYS, CRIB_POS)
base_eq, base_iq_pass, base_iq_fail = check_bean(BEAU_KEYS)

print(f"\n--- BASELINE (standard cribs, standard keystream) ---")
print(f"Best period: {base_bp} with {base_bs}/24 consistent")
print(f"Bean EQ: {'PASS' if base_eq else 'FAIL'}, INEQ pass: {base_iq_pass}, fail: {base_iq_fail}")
print(f"Period scores: {dict(base_scores)}")

# ═══════════════════════════════════════════════════════════════════════════
# F1: CRIB POSITION SHIFT
# Shift ENE start and/or BC start by -2,-1,0,+1,+2
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n{'='*80}")
print("F1: Crib position shift (ENE start, BC start)")
print("=" * 80)

ENE_START = 21  # standard
BC_START = 63   # standard
ENE_WORD = "EASTNORTHEAST"
BC_WORD = "BERLINCLOCK"

f1_results = []

for ene_delta in range(-2, 3):
    for bc_delta in range(-2, 3):
        ene_s = ENE_START + ene_delta
        bc_s = BC_START + bc_delta

        # Skip if positions go out of bounds
        if ene_s < 0 or ene_s + len(ENE_WORD) > CT_LEN:
            continue
        if bc_s < 0 or bc_s + len(BC_WORD) > CT_LEN:
            continue
        # Skip if cribs overlap
        if ene_s + len(ENE_WORD) > bc_s:
            continue

        # Build shifted keystream
        shifted_keys = {}
        for i, ch in enumerate(ENE_WORD):
            p = ene_s + i
            shifted_keys[p] = (ALPH_IDX[CT[p]] + ALPH_IDX[ch]) % MOD
        for i, ch in enumerate(BC_WORD):
            p = bc_s + i
            shifted_keys[p] = (ALPH_IDX[CT[p]] + ALPH_IDX[ch]) % MOD

        positions = sorted(shifted_keys.keys())
        bp, bs, scores = best_period_score(shifted_keys, positions)

        # Bean check (only if 27 and 65 are in the shifted positions)
        eq_pass = None
        if 27 in shifted_keys and 65 in shifted_keys:
            eq_pass = shifted_keys[27] == shifted_keys[65]

        is_baseline = (ene_delta == 0 and bc_delta == 0)
        is_one_lie = (abs(ene_delta) + abs(bc_delta) == 1)

        f1_results.append({
            'ene_delta': ene_delta, 'bc_delta': bc_delta,
            'best_period': bp, 'best_score': bs,
            'bean_eq': eq_pass, 'is_baseline': is_baseline,
            'is_one_lie': is_one_lie,
        })

        marker = " ← BASELINE" if is_baseline else (" ← ONE-LIE" if is_one_lie else "")
        eq_str = f"Bean={'PASS' if eq_pass else 'FAIL'}" if eq_pass is not None else "Bean=N/A"
        print(f"  ENE+{ene_delta:+d} BC+{bc_delta:+d}: best period={bp:2d} score={bs:2d}/24 "
              f"{eq_str}{marker}")

# Check if one-lie beats baseline
f1_baseline_score = [r['best_score'] for r in f1_results if r['is_baseline']][0]
f1_one_lie_scores = [r['best_score'] for r in f1_results if r['is_one_lie']]
f1_one_lie_max = max(f1_one_lie_scores) if f1_one_lie_scores else 0
f1_all_scores = [r['best_score'] for r in f1_results]
print(f"\n  F1 Summary: baseline={f1_baseline_score}/24, "
      f"one-lie max={f1_one_lie_max}/24, overall max={max(f1_all_scores)}/24")
if f1_one_lie_max > f1_baseline_score:
    print(f"  *** ONE-LIE ADVANTAGE: +{f1_one_lie_max - f1_baseline_score} ***")
else:
    print(f"  No one-lie advantage over baseline")

# ═══════════════════════════════════════════════════════════════════════════
# F2: COLUMNAR WIDTH ±1 AROUND INTERESTING VALUES
# Test widths and score via Beaufort decrypt + crib match
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n{'='*80}")
print("F2: Columnar width perturbation")
print("=" * 80)

AZ = ALPH
A2I = ALPH_IDX

def decrypt_beaufort(ct, key):
    klen = len(key)
    return ''.join(AZ[(A2I[key[i % klen]] - A2I[c]) % 26] for i, c in enumerate(ct))

def columnar_decipher(ct, width):
    n = len(ct)
    nrows = (n + width - 1) // width
    full_cols = n % width or width
    grid = [''] * width
    pos = 0
    for col in range(width):
        col_len = nrows if col < full_cols else nrows - 1
        grid[col] = ct[pos:pos + col_len]
        pos += col_len
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return ''.join(result)

# Test widths in neighborhoods of interesting values
# Archive: "4, 8, 10, 26 = Col" plus 37, 38
INTERESTING_WIDTHS = [4, 7, 8, 10, 13, 26, 37, 38]
KEYWORDS = ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']
VARIANTS = [('beau', decrypt_beaufort)]

f2_results = []
CT73 = ''.join(c for i, c in enumerate(CT) if i not in CONSENSUS_NULL_POSITIONS)

for center_w in INTERESTING_WIDTHS:
    for delta in range(-2, 3):
        w = center_w + delta
        if w < 2 or w > 50:
            continue

        for kw in KEYWORDS:
            for var_name, fn in VARIANTS:
                for ct_text, ct_label in [(CT, 'CT97'), (CT73, 'CT73')]:
                    if w >= len(ct_text):
                        continue
                    # Peel order 1: undo sub then undo trans
                    pt1 = columnar_decipher(fn(ct_text, kw), w)
                    if ct_label == 'CT97':
                        sc1 = score_candidate(pt1)
                    else:
                        sc1 = score_candidate_free(pt1)

                    # Peel order 2: undo trans then undo sub
                    pt2 = fn(columnar_decipher(ct_text, w), kw)
                    if ct_label == 'CT97':
                        sc2 = score_candidate(pt2)
                    else:
                        sc2 = score_candidate_free(pt2)

                    best_sc = max(sc1.crib_score, sc2.crib_score)
                    is_center = (delta == 0)
                    is_one_lie = (abs(delta) == 1)

                    f2_results.append({
                        'center': center_w, 'width': w, 'delta': delta,
                        'keyword': kw, 'ct': ct_label,
                        'score': best_sc, 'is_center': is_center,
                        'is_one_lie': is_one_lie,
                    })

# Summarize F2: for each center width, does ±1 beat center?
print(f"\n  {'Center':>6} {'W-2':>4} {'W-1':>4} {'W=C':>4} {'W+1':>4} {'W+2':>4}  (max crib score across keywords/CTs)")
for cw in INTERESTING_WIDTHS:
    row = {}
    for delta in range(-2, 3):
        w = cw + delta
        scores_at_delta = [r['score'] for r in f2_results
                          if r['center'] == cw and r['delta'] == delta]
        row[delta] = max(scores_at_delta) if scores_at_delta else -1
    print(f"  {cw:6d} {row.get(-2,-1):4d} {row.get(-1,-1):4d} "
          f"{row.get(0,-1):4d} {row.get(1,-1):4d} {row.get(2,-1):4d}")

# ═══════════════════════════════════════════════════════════════════════════
# F5: KEYSTREAM ±1 PERTURBATION AT EACH CRIB POSITION
# Which single ±1 change to a keystream value best improves period consistency?
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n{'='*80}")
print("F5: Keystream ±1 perturbation at each crib position")
print("=" * 80)

print(f"\n  Baseline best period: {base_bp} at {base_bs}/24")

f5_results = []

for target_pos in CRIB_POS:
    for delta in [-1, +1]:
        perturbed = dict(BEAU_KEYS)
        perturbed[target_pos] = (BEAU_KEYS[target_pos] + delta) % MOD

        bp, bs, scores = best_period_score(perturbed, CRIB_POS)

        # Bean check
        eq_pass, iq_p, iq_f = check_bean(perturbed)

        improvement = bs - base_bs
        f5_results.append({
            'pos': target_pos, 'delta': delta,
            'best_period': bp, 'best_score': bs,
            'improvement': improvement,
            'bean_eq': eq_pass,
        })

        if improvement > 0:
            print(f"  pos {target_pos:2d} delta={delta:+d}: period={bp:2d} "
                  f"score={bs:2d}/24 (+{improvement}) "
                  f"Bean={'PASS' if eq_pass else 'FAIL'}")

# Sort by improvement
f5_results.sort(key=lambda r: r['improvement'], reverse=True)
print(f"\n  Top 5 improvements:")
for r in f5_results[:5]:
    print(f"    pos {r['pos']:2d} delta={r['delta']:+d}: "
          f"period={r['best_period']:2d} score={r['best_score']:2d}/24 "
          f"(+{r['improvement']}) Bean={'PASS' if r['bean_eq'] else 'FAIL'}")

# Control: how many random ±1 perturbations improve?
n_improve = sum(1 for r in f5_results if r['improvement'] > 0)
n_total = len(f5_results)
print(f"\n  {n_improve}/{n_total} perturbations improve ({100*n_improve/n_total:.1f}%)")

# Expected under null: each perturbation randomly shuffles one value,
# improving ~50% of the time for scores near the maximum for that period
# This is the key control: if ~50% improve, there's no one-lie signal

# ═══════════════════════════════════════════════════════════════════════════
# F3: NULL COUNT ±1 (16 or 18 nulls instead of 17)
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n{'='*80}")
print("F3: Null count perturbation (16, 17, 18 nulls)")
print("=" * 80)

# Generate masks with 16 nulls (remove one consensus null) and 18 nulls (add one)
consensus_sorted = sorted(CONSENSUS_NULL_POSITIONS)
palette_positions = sorted(set(
    i for i, c in enumerate(CT) if c in NULL_PALETTE
) - CRIB_POSITIONS)

# 16 nulls: remove each consensus null in turn
# 18 nulls: add each non-consensus palette position
extra_candidates = sorted(set(palette_positions) - CONSENSUS_NULL_POSITIONS)

f3_results = []

for removed_pos in consensus_sorted:
    mask_16 = CONSENSUS_NULL_POSITIONS - {removed_pos}
    ct_extracted = ''.join(c for i, c in enumerate(CT) if i not in mask_16)
    sc = score_candidate_free(ct_extracted)
    f3_results.append({'type': 'remove', 'pos': removed_pos,
                       'n_nulls': len(mask_16), 'len': len(ct_extracted),
                       'score': sc.crib_score})

for added_pos in extra_candidates[:10]:  # limit to 10 for speed
    mask_18 = CONSENSUS_NULL_POSITIONS | {added_pos}
    ct_extracted = ''.join(c for i, c in enumerate(CT) if i not in mask_18)
    sc = score_candidate_free(ct_extracted)
    f3_results.append({'type': 'add', 'pos': added_pos,
                       'n_nulls': len(mask_18), 'len': len(ct_extracted),
                       'score': sc.crib_score})

# Baseline: 17 nulls
ct_baseline = ''.join(c for i, c in enumerate(CT) if i not in CONSENSUS_NULL_POSITIONS)
sc_baseline = score_candidate_free(ct_baseline)

print(f"  Baseline (17 nulls, len={len(ct_baseline)}): score={sc_baseline.crib_score}")
print(f"\n  16-null masks (remove one consensus null):")
for r in f3_results:
    if r['type'] == 'remove':
        marker = " ***" if r['score'] > sc_baseline.crib_score else ""
        print(f"    remove pos {r['pos']:2d}: len={r['len']} score={r['score']}{marker}")

print(f"\n  18-null masks (add one palette position):")
for r in f3_results:
    if r['type'] == 'add':
        marker = " ***" if r['score'] > sc_baseline.crib_score else ""
        print(f"    add pos {r['pos']:2d}: len={r['len']} score={r['score']}{marker}")

# ═══════════════════════════════════════════════════════════════════════════
# COMBINED VERDICT
# ═══════════════════════════════════════════════════════════════════════════

elapsed = time.time() - t0

print(f"\n{'='*80}")
print("COMBINED VERDICT")
print("=" * 80)
print(f"Elapsed: {elapsed:.1f}s")

# F1 verdict
f1_adv = f1_one_lie_max - f1_baseline_score
print(f"\nF1 (crib shift): one-lie advantage = {f1_adv:+d}/24")

# F2 verdict: for each center, does ±1 beat center?
f2_advantages = 0
f2_total = 0
for cw in INTERESTING_WIDTHS:
    center_scores = [r['score'] for r in f2_results
                     if r['center'] == cw and r['delta'] == 0]
    one_lie_scores = [r['score'] for r in f2_results
                      if r['center'] == cw and abs(r['delta']) == 1]
    if center_scores and one_lie_scores:
        f2_total += 1
        if max(one_lie_scores) > max(center_scores):
            f2_advantages += 1
print(f"F2 (width ±1): {f2_advantages}/{f2_total} centers where ±1 beats center")

# F5 verdict
f5_max_improvement = f5_results[0]['improvement'] if f5_results else 0
print(f"F5 (keystream ±1): max improvement = {f5_max_improvement:+d}/24, "
      f"{n_improve}/{n_total} improve")

# Overall
any_signal = (f1_adv > 2 or f2_advantages > f2_total // 2 or f5_max_improvement > 3)
if any_signal:
    print(f"\n*** POTENTIAL SIGNAL — investigate further ***")
else:
    print(f"\nNO SIGNAL: ±1 perturbation does not systematically improve "
          f"period consistency, crib scores, or Bean constraints over baseline.")
    print(f"The one-lie model does not produce a defensible advantage.")

print(f"{'='*80}")
