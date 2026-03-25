#!/usr/bin/env python3
"""
E-GKO-REVERSE-PLAINTEXT: Reverse the GKO Pattern to Predict Non-Crib Plaintext

The Beaufort A=0 keystream k[i] = (CT[i] + PT[i]) mod 26 at 24 crib positions
has 12/24 values in {G,K,O} = {6,10,14}. For non-crib positions, we know CT
but not PT. This script asks: what PT letters at non-crib positions would make
the keystream fall in {6,10,14}? Is the result consistent with English?

Seven phases:
  1. Per-position GKO candidate letters
  2. Best-case GKO plaintext (frequency-optimized)
  3. Mixed model: GKO compatibility at non-crib positions
  4. Constant keystream test (K=10, G=6, O=14 everywhere)
  5. Sliding window English quality of GKO-forced plaintext
  6. GKO pattern vs null positions
  7. English-optimal keystream distribution at non-crib positions

Attack-type: analysis
Family: keystream-forensics
Status: active
"""

import sys, os, json
from datetime import datetime, timezone
from collections import Counter

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, CRIB_POSITIONS, CONSENSUS_NULL_POSITIONS
from kryptos.kernel.alphabet import AZ
from kryptos.kernel.scoring.aggregate import score_candidate_free

# ── Constants ────────────────────────────────────────────────────────────────

ENE_POS = list(range(21, 34))
BCL_POS = list(range(63, 74))
ALL_CRIB_POS = sorted(ENE_POS + BCL_POS)
CRIB_SET = set(ALL_CRIB_POS)
NULL_SET = set(CONSENSUS_NULL_POSITIONS)

ENE_PT = "EASTNORTHEAST"
BCL_PT = "BERLINCLOCK"
CRIB_PT = {}
for i, pos in enumerate(ENE_POS):
    CRIB_PT[pos] = ENE_PT[i]
for i, pos in enumerate(BCL_POS):
    CRIB_PT[pos] = BCL_PT[i]

NON_CRIB_POS = sorted([i for i in range(97) if i not in CRIB_SET])

GKO_VALS = [6, 10, 14]  # G, K, O in AZ indexing
GKO_SET = set(GKO_VALS)
GKO_CHARS = ['G', 'K', 'O']

# English letter frequency ranking
FREQ_RANK = "ETAOINSHRDLCUMWFGYPBVKXJQZ"
FREQ_SCORE = {ch: 26 - i for i, ch in enumerate(FREQ_RANK)}  # E=26, Z=1
TOP8 = set("ETAOINSHR")  # Removed H from top8 to get exactly 8... actually ETAOINSR is 8
TOP8 = set(FREQ_RANK[:8])  # E,T,A,O,I,N,S,H

# ── Compute known keystream at crib positions ────────────────────────────────

crib_keystream = {}
for pos in ALL_CRIB_POS:
    ct_val = AZ.char_to_idx(CT[pos])
    pt_val = AZ.char_to_idx(CRIB_PT[pos])
    crib_keystream[pos] = (ct_val + pt_val) % 26

gko_crib_count = sum(1 for v in crib_keystream.values() if v in GKO_SET)
print("=" * 80)
print("E-GKO-REVERSE-PLAINTEXT: What Non-Crib Plaintext Extends the GKO Pattern?")
print("=" * 80)
print(f"\nKnown: {gko_crib_count}/24 crib keystream values are in GKO={{6,10,14}}")
print(f"GKO rate at cribs: {gko_crib_count/24:.1%}")
print(f"Non-crib positions: {len(NON_CRIB_POS)}")
print(f"Null positions: {len(NULL_SET)}")

results = {"timestamp": datetime.now(timezone.utc).isoformat(), "phases": {}}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: For each non-crib position, find PT letters that produce GKO keystream
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE 1: GKO Candidate Letters at Each Position")
print("=" * 80)

phase1 = {}
print(f"\n{'Pos':>3} CT  | G(6)->PT  K(10)->PT  O(14)->PT | Null? | Crib?")
print("-" * 72)

for pos in range(97):
    ct_ch = CT[pos]
    ct_val = AZ.char_to_idx(ct_ch)
    is_crib = pos in CRIB_SET
    is_null = pos in NULL_SET

    candidates = {}
    for gko_val, gko_name in zip(GKO_VALS, GKO_CHARS):
        pt_val = (gko_val - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        candidates[gko_name] = {"pt_char": pt_ch, "pt_val": pt_val,
                                 "freq_rank": FREQ_RANK.index(pt_ch) + 1}

    tag = ""
    if is_crib:
        known_ks = crib_keystream[pos]
        known_pt = CRIB_PT[pos]
        in_gko = "GKO" if known_ks in GKO_SET else "---"
        tag = f"CRIB: PT={known_pt}, ks={known_ks}({AZ.idx_to_char(known_ks)}) [{in_gko}]"
    elif is_null:
        tag = "NULL"

    g_pt = candidates['G']['pt_char']
    k_pt = candidates['K']['pt_char']
    o_pt = candidates['O']['pt_char']
    g_r = candidates['G']['freq_rank']
    k_r = candidates['K']['freq_rank']
    o_r = candidates['O']['freq_rank']

    if not is_crib:
        print(f"{pos:3d}  {ct_ch}   | G->{g_pt}(#{g_r:2d})  K->{k_pt}(#{k_r:2d})  O->{o_pt}(#{o_r:2d}) | {'NULL' if is_null else '    '} |")
    else:
        print(f"{pos:3d}  {ct_ch}   | G->{g_pt}(#{g_r:2d})  K->{k_pt}(#{k_r:2d})  O->{o_pt}(#{o_r:2d}) | {'NULL' if is_null else '    '} | {tag}")

    phase1[pos] = {
        "ct": ct_ch,
        "candidates": candidates,
        "is_crib": is_crib,
        "is_null": is_null,
    }
    if is_crib:
        phase1[pos]["known_pt"] = CRIB_PT[pos]
        phase1[pos]["known_ks"] = crib_keystream[pos]
        phase1[pos]["ks_in_gko"] = crib_keystream[pos] in GKO_SET

results["phases"]["P1_candidates"] = {"count": 97, "data": "see grid output"}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Best-case GKO plaintext (pick GKO value producing most common letter)
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE 2: Best-Case GKO Plaintext (Frequency-Optimized)")
print("=" * 80)

best_gko_pt = []
best_gko_choices = []
for pos in range(97):
    if pos in CRIB_SET:
        best_gko_pt.append(CRIB_PT[pos])
        best_gko_choices.append(("CRIB", crib_keystream[pos]))
        continue

    ct_val = AZ.char_to_idx(CT[pos])
    best_ch = None
    best_rank = 999
    best_ks = None
    for gko_val in GKO_VALS:
        pt_val = (gko_val - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        rank = FREQ_RANK.index(pt_ch) + 1
        if rank < best_rank:
            best_rank = rank
            best_ch = pt_ch
            best_ks = gko_val
    best_gko_pt.append(best_ch)
    best_gko_choices.append(("GKO", best_ks))

best_gko_str = "".join(best_gko_pt)
print(f"\nBest-case GKO plaintext:")
# Print in rows of ~30 for readability
for start in range(0, 97, 30):
    chunk = best_gko_str[start:start+30]
    positions = "".join(f"{(start+i)%10}" for i in range(len(chunk)))
    print(f"  [{start:2d}-{start+len(chunk)-1:2d}] {chunk}")
    print(f"          {positions}")

# Letter frequency analysis
freq_count = Counter(best_gko_str)
in_top8 = sum(1 for ch in best_gko_str if ch in TOP8)
print(f"\nLetter frequency: {dict(freq_count.most_common())}")
print(f"Top-8 letters (ETAOINSHR): {in_top8}/97 ({in_top8/97:.1%})")
print(f"  English expected: ~70%")

# Quadgram score (rough)
try:
    qg_path = os.path.join(_ROOT, 'data', 'english_quadgrams.json')
    with open(qg_path) as f:
        quadgrams = json.load(f)
    total_qg = 0
    n_qg = 0
    for i in range(len(best_gko_str) - 3):
        qg = best_gko_str[i:i+4]
        total_qg += quadgrams.get(qg, -10.0)
        n_qg += 1
    avg_qg = total_qg / n_qg if n_qg > 0 else -10.0
    print(f"Average quadgram score: {avg_qg:.3f}/char (English ~-4.84, random ~-7.5)")
    results["phases"]["P2_best_gko"] = {
        "plaintext": best_gko_str,
        "top8_pct": in_top8 / 97,
        "avg_quadgram": avg_qg
    }
except Exception as e:
    print(f"Quadgram scoring not available: {e}")
    results["phases"]["P2_best_gko"] = {
        "plaintext": best_gko_str,
        "top8_pct": in_top8 / 97
    }

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3: GKO compatibility score at non-crib positions
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE 3: GKO Compatibility at Non-Crib Positions")
print("=" * 80)

compatible_count = 0
compatible_positions = []
incompatible_positions = []

for pos in NON_CRIB_POS:
    ct_val = AZ.char_to_idx(CT[pos])
    best_rank = 999
    best_ch = None
    for gko_val in GKO_VALS:
        pt_val = (gko_val - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        rank = FREQ_RANK.index(pt_ch) + 1
        if rank < best_rank:
            best_rank = rank
            best_ch = pt_ch

    # Also compute best from ANY keystream
    any_best_rank = 999
    any_best_ch = None
    for ks in range(26):
        pt_val = (ks - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        rank = FREQ_RANK.index(pt_ch) + 1
        if rank < any_best_rank:
            any_best_rank = rank
            any_best_ch = pt_ch

    is_compat = best_ch in TOP8
    if is_compat:
        compatible_count += 1
        compatible_positions.append(pos)
    else:
        incompatible_positions.append(pos)

    is_null = pos in NULL_SET
    print(f"  pos {pos:2d}: CT={CT[pos]}, best GKO->{best_ch}(#{best_rank:2d}), "
          f"best ANY->{any_best_ch}(#{any_best_rank:2d})  "
          f"{'COMPAT' if is_compat else '      '} {'NULL' if is_null else ''}")

print(f"\nGKO-compatible (best GKO letter in top 8): {compatible_count}/{len(NON_CRIB_POS)} "
      f"({compatible_count/len(NON_CRIB_POS):.1%})")
print(f"Expected if random (top 8 of 26, picking best of 3): "
      f"~{1 - (1 - 8/26)**3:.1%}")

results["phases"]["P3_compatibility"] = {
    "compatible": compatible_count,
    "total": len(NON_CRIB_POS),
    "pct": compatible_count / len(NON_CRIB_POS),
    "expected_random_pct": 1 - (1 - 8/26)**3,
    "compatible_positions": compatible_positions,
    "incompatible_positions": incompatible_positions
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Constant keystream test (K=10, G=6, O=14 at all non-crib positions)
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE 4: Constant Keystream Tests")
print("=" * 80)

phase4_results = {}
for ks_val, ks_name in [(10, "K"), (6, "G"), (14, "O")]:
    pt_chars = []
    for pos in range(97):
        if pos in CRIB_SET:
            pt_chars.append(CRIB_PT[pos])
        else:
            ct_val = AZ.char_to_idx(CT[pos])
            pt_val = (ks_val - ct_val) % 26
            pt_chars.append(AZ.idx_to_char(pt_val))
    pt_str = "".join(pt_chars)

    # Score with score_candidate_free
    try:
        score_result = score_candidate_free(pt_str)
        score_val = score_result.total if hasattr(score_result, 'total') else str(score_result)
    except Exception as e:
        score_val = f"error: {e}"

    print(f"\n  Keystream = {ks_name} ({ks_val}) at all non-crib positions:")
    for start in range(0, 97, 50):
        print(f"    [{start:2d}-{min(start+49,96):2d}] {pt_str[start:start+50]}")
    print(f"    Score: {score_val}")

    phase4_results[f"ks_{ks_name}_{ks_val}"] = {
        "plaintext": pt_str,
        "score": str(score_val)
    }

results["phases"]["P4_constant_ks"] = phase4_results

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Sliding window English quality of GKO-forced plaintext
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE 5: Sliding Window English Quality (GKO-Forced Plaintext)")
print("=" * 80)

# Use best_gko_str from Phase 2
phase5_results = {}
for width in [5, 7, 10]:
    scores = []
    for start in range(97 - width + 1):
        window = best_gko_str[start:start + width]
        common_count = sum(1 for ch in window if ch in TOP8)
        scores.append((start, common_count, window))

    # Find best and worst windows
    scores.sort(key=lambda x: -x[1])
    print(f"\n  Width {width}: Top 5 windows (most common letters):")
    for start, count, window in scores[:5]:
        crib_overlap = sum(1 for p in range(start, start + width) if p in CRIB_SET)
        print(f"    pos {start:2d}-{start+width-1:2d}: {window} ({count}/{width} common) "
              f"[crib overlap: {crib_overlap}]")

    print(f"  Width {width}: Bottom 5 windows (least common letters):")
    for start, count, window in scores[-5:]:
        crib_overlap = sum(1 for p in range(start, start + width) if p in CRIB_SET)
        print(f"    pos {start:2d}-{start+width-1:2d}: {window} ({count}/{width} common) "
              f"[crib overlap: {crib_overlap}]")

    avg_common = sum(s[1] for s in scores) / len(scores)
    print(f"  Average common letters per window: {avg_common:.2f}/{width} ({avg_common/width:.1%})")

    phase5_results[f"width_{width}"] = {
        "avg_common_pct": avg_common / width,
        "best": [(s[0], s[1], s[2]) for s in scores[:5]],
        "worst": [(s[0], s[1], s[2]) for s in scores[-5:]]
    }

results["phases"]["P5_sliding_window"] = phase5_results

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6: GKO pattern vs null positions
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE 6: GKO Pattern at Null Positions")
print("=" * 80)

null_pos_list = sorted(NULL_SET)
non_null_non_crib = sorted([p for p in NON_CRIB_POS if p not in NULL_SET])

# For null positions: what are the GKO candidate PT letters?
null_best_ranks = []
nonnull_best_ranks = []

print("\n  Null positions — GKO candidates:")
for pos in null_pos_list:
    ct_val = AZ.char_to_idx(CT[pos])
    candidates = []
    best_rank = 999
    for gko_val, gko_name in zip(GKO_VALS, GKO_CHARS):
        pt_val = (gko_val - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        rank = FREQ_RANK.index(pt_ch) + 1
        candidates.append(f"{gko_name}->{pt_ch}(#{rank:2d})")
        if rank < best_rank:
            best_rank = rank
    null_best_ranks.append(best_rank)
    is_crib = pos in CRIB_SET
    print(f"    pos {pos:2d}: CT={CT[pos]}  {', '.join(candidates)}  "
          f"best_rank={best_rank} {'(also CRIB)' if is_crib else ''}")

print(f"\n  Non-null, non-crib positions — GKO best ranks:")
for pos in non_null_non_crib:
    ct_val = AZ.char_to_idx(CT[pos])
    best_rank = 999
    for gko_val in GKO_VALS:
        pt_val = (gko_val - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        rank = FREQ_RANK.index(pt_ch) + 1
        if rank < best_rank:
            best_rank = rank
    nonnull_best_ranks.append(best_rank)

# Exclude nulls that are also cribs for fair comparison
pure_null = [p for p in null_pos_list if p not in CRIB_SET]
pure_null_ranks = []
for pos in pure_null:
    ct_val = AZ.char_to_idx(CT[pos])
    best_rank = 999
    for gko_val in GKO_VALS:
        pt_val = (gko_val - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        rank = FREQ_RANK.index(pt_ch) + 1
        if rank < best_rank:
            best_rank = rank
    pure_null_ranks.append(best_rank)

avg_null_rank = sum(pure_null_ranks) / len(pure_null_ranks) if pure_null_ranks else 0
avg_nonnull_rank = sum(nonnull_best_ranks) / len(nonnull_best_ranks) if nonnull_best_ranks else 0

print(f"\n  Average best-rank at null positions (non-crib): {avg_null_rank:.1f} (n={len(pure_null_ranks)})")
print(f"  Average best-rank at non-null non-crib positions: {avg_nonnull_rank:.1f} (n={len(nonnull_best_ranks)})")
print(f"  If nulls have HIGHER rank (less common), GKO is less compatible there.")
diff = avg_null_rank - avg_nonnull_rank
if diff > 0:
    print(f"  -> Null positions are LESS GKO-compatible (diff={diff:.1f}): supports filler model")
elif diff < 0:
    print(f"  -> Null positions are MORE GKO-compatible (diff={diff:.1f}): contradicts filler model")
else:
    print(f"  -> No difference")

results["phases"]["P6_nulls"] = {
    "avg_null_best_rank": avg_null_rank,
    "avg_nonnull_best_rank": avg_nonnull_rank,
    "difference": diff,
    "interpretation": "null_less_compatible" if diff > 0 else "null_more_compatible" if diff < 0 else "equal",
    "n_pure_null": len(pure_null_ranks),
    "n_nonnull_noncrib": len(nonnull_best_ranks)
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 7: English-optimal keystream distribution at non-crib positions
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PHASE 7: English-Optimal Keystream Distribution")
print("=" * 80)

# For each non-crib non-null position, what keystream value produces E (most common)?
# More generally, what keystream produces the highest-frequency letter?
optimal_ks_values = []
optimal_for_E = []

non_null_non_crib_sorted = sorted(non_null_non_crib)
print(f"\n  Analyzing {len(non_null_non_crib_sorted)} non-crib, non-null positions...")

for pos in non_null_non_crib_sorted:
    ct_val = AZ.char_to_idx(CT[pos])

    # What ks produces E (rank 1)?
    e_val = AZ.char_to_idx('E')
    ks_for_E = (e_val + ct_val) % 26  # Beaufort: ks = CT + PT
    optimal_for_E.append(ks_for_E)

    # What ks produces best letter overall?
    best_ks = None
    best_rank = 999
    for ks in range(26):
        pt_val = (ks - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        rank = FREQ_RANK.index(pt_ch) + 1
        if rank < best_rank:
            best_rank = rank
            best_ks = ks
    optimal_ks_values.append(best_ks)

# Histogram of optimal keystream values
ks_counter = Counter(optimal_ks_values)
print("\n  Histogram of 'English-optimal' keystream values (what ks makes the best PT letter):")
print(f"  {'KS':>3} {'Char':>4} {'Count':>5} {'In GKO':>6}")
for ks_val in range(26):
    count = ks_counter.get(ks_val, 0)
    ch = AZ.idx_to_char(ks_val)
    in_gko = "***" if ks_val in GKO_SET else ""
    if count > 0:
        print(f"  {ks_val:3d}   {ch:>2}   {count:5d}  {in_gko}")

gko_optimal_count = sum(ks_counter.get(v, 0) for v in GKO_VALS)
print(f"\n  Positions where GKO keystream is English-optimal: {gko_optimal_count}/{len(non_null_non_crib_sorted)}")
print(f"  Expected if random (3/26): {3/26:.1%}")
print(f"  Actual: {gko_optimal_count/len(non_null_non_crib_sorted):.1%}")

# Distribution of ks values that would produce 'E' at each position
e_counter = Counter(optimal_for_E)
gko_e_count = sum(e_counter.get(v, 0) for v in GKO_VALS)
print(f"\n  Positions where GKO keystream produces 'E': {gko_e_count}/{len(non_null_non_crib_sorted)}")
print(f"  (This depends on CT distribution, not on the cipher)")

# Full histogram of all 26 ks values: how many positions give top-8 letter?
print("\n  For each keystream value, how many positions produce a top-8 PT letter?")
ks_top8_count = {}
for ks_val in range(26):
    count = 0
    for pos in non_null_non_crib_sorted:
        ct_val = AZ.char_to_idx(CT[pos])
        pt_val = (ks_val - ct_val) % 26
        pt_ch = AZ.idx_to_char(pt_val)
        if pt_ch in TOP8:
            count += 1
    ks_top8_count[ks_val] = count
    ch = AZ.idx_to_char(ks_val)
    in_gko = "***" if ks_val in GKO_SET else ""
    print(f"    ks={ks_val:2d}({ch}): {count}/{len(non_null_non_crib_sorted)} produce top-8 letter  {in_gko}")

gko_top8_total = sum(ks_top8_count[v] for v in GKO_VALS)
all_top8_total = sum(ks_top8_count.values())
print(f"\n  GKO top-8 sum: {gko_top8_total}/{3*len(non_null_non_crib_sorted)} "
      f"({gko_top8_total/(3*len(non_null_non_crib_sorted)):.1%})")
print(f"  All-ks top-8 avg: {all_top8_total/26:.1f}/{len(non_null_non_crib_sorted)} "
      f"({all_top8_total/(26*len(non_null_non_crib_sorted)):.1%})")

results["phases"]["P7_optimal_ks"] = {
    "gko_optimal_count": gko_optimal_count,
    "total_positions": len(non_null_non_crib_sorted),
    "gko_optimal_pct": gko_optimal_count / len(non_null_non_crib_sorted),
    "expected_random_pct": 3 / 26,
    "ks_top8_histogram": {str(k): v for k, v in ks_top8_count.items()},
    "gko_top8_sum": gko_top8_total,
    "gko_top8_pct": gko_top8_total / (3 * len(non_null_non_crib_sorted))
}

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"""
  Phase 1: Computed GKO candidate PT letters for all 97 positions
  Phase 2: Best-case GKO plaintext: {best_gko_str[:40]}...
           Top-8 letter rate: {in_top8/97:.1%} (English ~70%)
  Phase 3: GKO-compatible positions: {compatible_count}/{len(NON_CRIB_POS)} ({compatible_count/len(NON_CRIB_POS):.1%})
           Expected (random, best-of-3): {1-(1-8/26)**3:.1%}
  Phase 4: Constant keystream tests completed (G, K, O)
  Phase 5: Sliding window analysis of GKO-forced plaintext
  Phase 6: Null vs non-null GKO compatibility: diff={diff:.1f}
           {'Nulls less compatible (supports filler model)' if diff > 0 else 'Nulls more/equally compatible (no filler signal)'}
  Phase 7: GKO as English-optimal keystream: {gko_optimal_count}/{len(non_null_non_crib_sorted)} ({gko_optimal_count/len(non_null_non_crib_sorted):.1%})
           Expected random: {3/26:.1%}
""")

# ── Save results ─────────────────────────────────────────────────────────────

out_path = os.path.join(_ROOT, 'results', 'gko_reverse_plaintext.json')
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"Results saved to {out_path}")
