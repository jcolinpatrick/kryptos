"""
Cipher: Stego Oracle — Model-independent null mask discrimination
Family: multi_layer
Status: active
Keyspace: 11,440 masks (C(16,7) from varying null positions)
Last run: 2026-03-19
Best score: TBD

Test all 11,440 candidate null masks on model-independent criteria:
1. Periodic consistency of Beaufort keystream at crib positions in CT73 space
2. Bean equality preservation (k[27]=k[65]) under periodic keyword
3. Bean inequality hard constraints (242 pairs)
4. IC of the resulting 73-char ciphertext
5. Combined ranking to identify the most "cipher-like" mask
"""
import sys, os, json, time
from itertools import combinations
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_POSITIONS, BEAN_EQ, BEAN_INEQ

# ── CONSTANTS ────────────────────────────────────────────────────────

CT97 = CT
CONSENSUS_17 = frozenset({0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59,
                           74, 75, 78, 84, 85})

# Varying null candidate ranges (from SA variation analysis)
CLUSTER_A = list(range(38, 46))   # {38..45}, 8 positions
CLUSTER_B = [55, 56]              # 2 positions
CLUSTER_C = [87, 88]              # 2 positions
CLUSTER_D = [93, 94, 95, 96]     # 4 positions
CANDIDATES_16 = sorted(CLUSTER_A + CLUSTER_B + CLUSTER_C + CLUSTER_D)

# Crib definitions (0-indexed in CT97)
ENE_POSITIONS = list(range(21, 34))   # 13 chars
BCL_POSITIONS = list(range(63, 74))   # 11 chars
CRIB_POS_LIST = ENE_POSITIONS + BCL_POSITIONS  # 24 positions

ENE_TEXT = "EASTNORTHEAST"
BCL_TEXT = "BERLINCLOCK"
CRIB_PT = {}
for i, c in enumerate(ENE_TEXT):
    CRIB_PT[21 + i] = ord(c) - 65
for i, c in enumerate(BCL_TEXT):
    CRIB_PT[63 + i] = ord(c) - 65

# Pre-compute Beaufort keystream at crib positions (FIXED for all masks)
# k[i] = (CT[i] + PT[i]) mod 26
CT_NUMS = [ord(c) - 65 for c in CT97]
CRIB_KEYS = {}
for pos in CRIB_POS_LIST:
    CRIB_KEYS[pos] = (CT_NUMS[pos] + CRIB_PT[pos]) % 26

# Bean equality positions (in CT97 space)
BEAN_EQ_POS = (27, 65)  # k[27] = k[65] = 6 (G)


# ── MASK ENUMERATION ─────────────────────────────────────────────────

def enumerate_masks():
    """Generate all C(16,7) = 11,440 candidate masks."""
    for combo in combinations(CANDIDATES_16, 7):
        yield CONSENSUS_17 | frozenset(combo)


# ── SCORING FUNCTIONS ────────────────────────────────────────────────

def compute_pos73_mapping(mask):
    """Map CT97 positions to CT73 positions after null removal.
    Returns dict: ct97_pos -> ct73_pos (only for non-null positions)."""
    mapping = {}
    ct73_idx = 0
    for i in range(97):
        if i not in mask:
            mapping[i] = ct73_idx
            ct73_idx += 1
    return mapping


def periodic_consistency(pos73_map, period):
    """Score periodic consistency of Beaufort keystream at crib positions.

    Groups crib positions by (pos73 mod period). Within each group,
    a periodic cipher requires all key values to be identical.

    Returns (matches, conflicts, n_groups_with_data).
    matches = number of crib positions consistent with majority key per residue.
    """
    residue_groups = {}
    for ct97_pos in CRIB_POS_LIST:
        p73 = pos73_map[ct97_pos]
        r = p73 % period
        if r not in residue_groups:
            residue_groups[r] = []
        residue_groups[r].append(CRIB_KEYS[ct97_pos])

    matches = 0
    conflicts = 0
    for r, vals in residue_groups.items():
        if len(vals) == 1:
            matches += 1
        else:
            counts = Counter(vals)
            majority = counts.most_common(1)[0][1]
            matches += majority
            conflicts += len(vals) - majority

    return matches, conflicts, len(residue_groups)


def bean_eq_check(pos73_map, period):
    """Check if Bean equality k[27]=k[65] is preserved at this period.
    Both must map to the same residue class in CT73 space."""
    p1 = pos73_map[BEAN_EQ_POS[0]]
    p2 = pos73_map[BEAN_EQ_POS[1]]
    return (p1 % period) == (p2 % period)


def bean_ineq_check(pos73_map, period):
    """Check Bean inequalities: for each pair (c1,c2) with k[c1]!=k[c2],
    they must NOT share a residue mod period in CT73 space.

    Returns (violations, total_checked)."""
    violations = 0
    total = 0
    for (c1, c2) in BEAN_INEQ:
        if c1 in CRIB_KEYS and c2 in CRIB_KEYS:
            if CRIB_KEYS[c1] != CRIB_KEYS[c2]:
                total += 1
                p1 = pos73_map[c1]
                p2 = pos73_map[c2]
                if (p1 % period) == (p2 % period):
                    violations += 1
    return violations, total


def ic_of_text(text):
    """Compute index of coincidence."""
    n = len(text)
    if n <= 1:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


# ── MAIN ANALYSIS ────────────────────────────────────────────────────

def analyze_all_masks():
    """Score all 11,440 masks on multiple independent criteria."""
    results = []
    total = 11440
    best_by_period = {}  # period -> (score, mask, details)

    print("STEGO ORACLE — Model-Independent Null Mask Discrimination")
    print("=" * 65)
    print(f"\nSearching {total} masks (C(16,7) from varying null positions)")
    print(f"Crib keystream (fixed): {['ABCDEFGHIJKLMNOPQRSTUVWXYZ'[CRIB_KEYS[p]] for p in CRIB_POS_LIST]}")
    print(f"  = {''.join('ABCDEFGHIJKLMNOPQRSTUVWXYZ'[CRIB_KEYS[p]] for p in CRIB_POS_LIST)}")
    print()

    for mask_idx, mask in enumerate(enumerate_masks()):
        varying_7 = sorted(mask - CONSENSUS_17)
        pos73_map = compute_pos73_mapping(mask)

        # Extract CT73
        ct73 = ''.join(CT97[i] for i in range(97) if i not in mask)
        ct73_ic = ic_of_text(ct73)

        # Score each period
        best_period = None
        best_score = -1
        best_details = None

        for p in range(1, 24):  # periods 1-23 (24+ underdetermined)
            matches, conflicts, n_groups = periodic_consistency(pos73_map, p)
            eq_ok = bean_eq_check(pos73_map, p)
            ineq_violations, ineq_total = bean_ineq_check(pos73_map, p)

            # Combined score:
            # - Start with match count (0-24)
            # - Bean equality is a hard requirement (multiply by 0 if fails)
            # - Each inequality violation is a hard fail for this period
            if not eq_ok or ineq_violations > 0:
                effective_score = 0
            else:
                effective_score = matches

            if effective_score > best_score:
                best_score = effective_score
                best_period = p
                best_details = {
                    'period': p,
                    'matches': matches,
                    'conflicts': conflicts,
                    'bean_eq': eq_ok,
                    'bean_ineq_violations': ineq_violations,
                    'bean_ineq_total': ineq_total,
                }

        entry = {
            'mask_idx': mask_idx,
            'varying_7': varying_7,
            'ct73_ic': ct73_ic,
            'best_period': best_period,
            'best_score': best_score,
            'details': best_details,
        }
        results.append(entry)

        # Track best per period
        if best_period is not None:
            key = best_period
            if key not in best_by_period or best_score > best_by_period[key][0]:
                best_by_period[key] = (best_score, varying_7, best_details)

        if (mask_idx + 1) % 2000 == 0:
            print(f"  ... {mask_idx + 1}/{total} masks scored", flush=True)

    return results, best_by_period


def report_results(results, best_by_period):
    """Print analysis results."""
    print(f"\n{'=' * 65}")
    print("RESULTS")
    print("=" * 65)

    # Score distribution
    scores = [r['best_score'] for r in results]
    score_dist = Counter(scores)
    print(f"\nScore distribution (best effective score per mask):")
    for s in sorted(score_dist.keys(), reverse=True):
        bar = '#' * min(score_dist[s] // 10, 50)
        print(f"  {s:2d}/24: {score_dist[s]:6d} masks  {bar}")

    # How many masks have ANY period that passes Bean constraints?
    passing = [r for r in results if r['best_score'] > 0]
    print(f"\nMasks with ANY period passing Bean eq+ineq: {len(passing)}/{len(results)}")

    # Top masks
    results_sorted = sorted(results, key=lambda r: (
        r['best_score'], -r['details']['bean_ineq_violations'] if r['details'] else 0,
        r['ct73_ic']
    ), reverse=True)

    print(f"\nTop 30 masks:")
    print(f"  {'Varying 7':40s} Score  Period  BeanEq  Ineq  CT73-IC")
    print(f"  {'-'*40} {'-'*5}  {'-'*6}  {'-'*6}  {'-'*4}  {'-'*7}")
    for r in results_sorted[:30]:
        d = r['details']
        if d:
            print(f"  {str(r['varying_7']):40s} {r['best_score']:2d}/24  p={d['period']:<4d}  "
                  f"{'PASS' if d['bean_eq'] else 'FAIL':6s}  {d['bean_ineq_violations']:4d}  "
                  f"{r['ct73_ic']:.4f}")

    # Best by period
    print(f"\nBest mask per period:")
    for p in sorted(best_by_period.keys()):
        score, varying, details = best_by_period[p]
        if score > 0:
            print(f"  p={p:2d}: {score:2d}/24 mask={varying} "
                  f"ineq_violations={details['bean_ineq_violations']}")

    # Specifically check period 7 (KRYPTOS length)
    print(f"\n{'=' * 65}")
    print("PERIOD 7 ANALYSIS (keyword length = KRYPTOS)")
    print("=" * 65)
    p7_results = []
    for r in results:
        mask = CONSENSUS_17 | frozenset(r['varying_7'])
        pos73_map = compute_pos73_mapping(mask)
        matches, conflicts, n_groups = periodic_consistency(pos73_map, 7)
        eq_ok = bean_eq_check(pos73_map, 7)
        ineq_v, ineq_t = bean_ineq_check(pos73_map, 7)
        p7_results.append({
            'varying_7': r['varying_7'],
            'matches': matches,
            'conflicts': conflicts,
            'bean_eq': eq_ok,
            'bean_ineq_violations': ineq_v,
            'ct73_ic': r['ct73_ic'],
            'pass': eq_ok and ineq_v == 0,
        })

    p7_pass = [x for x in p7_results if x['pass']]
    print(f"  Masks passing Bean eq+ineq at p=7: {len(p7_pass)}/{len(p7_results)}")

    if p7_pass:
        p7_pass.sort(key=lambda x: x['matches'], reverse=True)
        print(f"\n  Top 20 (by consistency score):")
        print(f"  {'Varying 7':40s} Match  Confl  CT73-IC")
        print(f"  {'-'*40} {'-'*5}  {'-'*5}  {'-'*7}")
        for x in p7_pass[:20]:
            print(f"  {str(x['varying_7']):40s} {x['matches']:2d}/24  "
                  f"{x['conflicts']:2d}     {x['ct73_ic']:.4f}")

    # Also check periods 5 and 6
    for check_p in [5, 6, 8, 9, 10, 11, 12, 13]:
        pp_results = []
        for r in results:
            mask = CONSENSUS_17 | frozenset(r['varying_7'])
            pos73_map = compute_pos73_mapping(mask)
            eq_ok = bean_eq_check(pos73_map, check_p)
            ineq_v, _ = bean_ineq_check(pos73_map, check_p)
            if eq_ok and ineq_v == 0:
                matches, conflicts, _ = periodic_consistency(pos73_map, check_p)
                pp_results.append({
                    'varying_7': r['varying_7'],
                    'matches': matches,
                    'conflicts': conflicts,
                })
        if pp_results:
            pp_results.sort(key=lambda x: x['matches'], reverse=True)
            top = pp_results[0]
            print(f"\n  Period {check_p:2d}: {len(pp_results)} masks pass Bean. "
                  f"Best: {top['matches']}/24 (conflicts={top['conflicts']}) "
                  f"mask={top['varying_7']}")
        else:
            print(f"\n  Period {check_p:2d}: 0 masks pass Bean constraints")

    return results_sorted


if __name__ == "__main__":
    t0 = time.time()
    results, best_by_period = analyze_all_masks()
    results_sorted = report_results(results, best_by_period)
    elapsed = time.time() - t0

    print(f"\n{'=' * 65}")
    print(f"Completed in {elapsed:.1f}s")

    # Save results
    out = {
        'experiment': 'e_stego_oracle_01',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_masks': len(results),
        'elapsed_seconds': round(elapsed, 1),
        'top_50': [
            {'varying_7': r['varying_7'], 'best_score': r['best_score'],
             'best_period': r['best_period'], 'ct73_ic': round(r['ct73_ic'], 5),
             'details': r['details']}
            for r in results_sorted[:50]
        ],
    }
    out_path = os.path.join(_ROOT, 'results', 'e_stego_oracle_01.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"Results saved to {out_path}")
