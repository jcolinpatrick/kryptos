#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-52: Three-Layer Model Test (Sub + Trans + Sub)

MODEL: CT = Enc2(sigma(Enc1(PT, K1)), K2)
  - K1 has period p1 (polyalphabetic substitution BEFORE transposition)
  - sigma is a transposition (columnar at widths 6, 8, 9)
  - K2 has period p2 (polyalphabetic substitution AFTER transposition)

EFFECTIVE KEY: K_eff[j] = K1[j%p1] + K2[inv(j)%p2]  (non-periodic in general!)

WHY THIS MATTERS:
  - E-FRAC-35 proved ALL discriminating periods (2-7) are Bean-impossible for
    transposition + SINGLE periodic key
  - Three-layer produces NON-PERIODIC effective key that BYPASSES Bean impossibility
  - This is a genuinely untested hypothesis class (H12)

METHOD:
  For each Bean-eq-passing columnar sigma (widths 6,8,9):
    For each c-type (A: CT-PT, B: CT+PT) — covers all 9 inner/outer variant combos:
      Precheck Bean inequality on effective key values at 24 crib positions
      For each (p1,p2) in {1..12}x{1..12} excl (1,1):
        1. Group 24 crib equations by (j%p1, inv(j)%p2)
        2. Within-group consistency: all c-values in same group must agree
        3. BFS solve bipartite system K1[r1]+K2[r2]=c — detect cycle contradictions
        4. Derive 97-char plaintext and score (quadgrams)

EXPECTED:
  For p1*p2 <= 24: ~10^-16 FP per config -> ZERO false positives
  For p1*p2 <= 50: ~10^-8 FP per config -> borderline
  For p1*p2 > 100: many FP -> plaintext scoring filters
"""

import json
import os
import sys
import time
import random
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, ALPH, MOD,
    CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

# Crib data
CRIB_POS = [pos for pos, _ in CRIB_ENTRIES]
CRIB_PT = [ALPH_IDX[ch] for _, ch in CRIB_ENTRIES]
CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN  # 97

QUADGRAM_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')


class QuadgramScorer:
    def __init__(self, filepath):
        with open(filepath) as f:
            data = json.load(f)
        self.logp = data['logp'] if isinstance(data, dict) and 'logp' in data else data
        self.floor = min(self.logp.values()) - 1.0

    def score_per_char(self, text):
        text = text.upper()
        if len(text) < 4:
            return self.floor
        total = sum(self.logp.get(text[i:i+4], self.floor) for i in range(len(text) - 3))
        return total / len(text)


def generate_columnar_perm(width, col_order):
    nrows = (N + width - 1) // width
    full_cols = N - (nrows - 1) * width
    perm = []
    for col in col_order:
        rows = nrows if col < full_cols else nrows - 1
        for row in range(rows):
            pos = row * width + col
            if pos < N:
                perm.append(pos)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_eq(inv_perm):
    for eq_a, eq_b in BEAN_EQ:
        if CT[inv_perm[eq_a]] != CT[inv_perm[eq_b]]:
            return False
    return True


def bfs_solve(groups, p1, p2):
    """BFS solve bipartite system K1[r1] + K2[r2] = c.
    Returns (K1, K2, n_components) or None if cycle-inconsistent."""
    adj = defaultdict(list)
    for (r1, r2), c in groups.items():
        adj[('K1', r1)].append((('K2', r2), c))
        adj[('K2', r2)].append((('K1', r1), c))

    vals = {}
    n_components = 0
    all_nodes = set()
    for (r1, r2) in groups:
        all_nodes.add(('K1', r1))
        all_nodes.add(('K2', r2))

    for start in sorted(all_nodes):
        if start in vals:
            continue
        n_components += 1
        vals[start] = 0
        queue = [start]
        while queue:
            node = queue.pop(0)
            v = vals[node]
            for neighbor, c_eq in adj[node]:
                expected = (c_eq - v) % MOD
                if neighbor in vals:
                    if vals[neighbor] != expected:
                        return None  # cycle inconsistency
                    continue
                vals[neighbor] = expected
                queue.append(neighbor)

    K1 = [vals.get(('K1', r), 0) for r in range(p1)]
    K2 = [vals.get(('K2', r), 0) for r in range(p2)]
    return K1, K2, n_components


def derive_plaintext(inv_perm, K1, K2, p1, p2, c_type):
    """Derive 97-char plaintext from solved K1, K2."""
    pt = []
    for j in range(N):
        ct_pos = inv_perm[j]
        ct_val = CT_NUM[ct_pos]
        k_eff = (K1[j % p1] + K2[ct_pos % p2]) % MOD
        if c_type == 'A':
            pt_val = (ct_val - k_eff) % MOD
        else:
            pt_val = (k_eff - ct_val) % MOD
        pt.append(ALPH[pt_val])
    return ''.join(pt)


def main():
    print("=" * 70)
    print("E-FRAC-52: Three-Layer Model Test (Sub + Trans + Sub)")
    print("=" * 70)
    t0 = time.time()

    scorer = QuadgramScorer(QUADGRAM_FILE)
    print("Quadgram scorer loaded")

    # ── Phase 1: Generate Bean-eq-passing transpositions ──────────────
    print("\n--- Phase 1: Generate Bean-eq-passing transpositions ---")
    configs = []
    for width in [6, 8, 9]:
        count = 0
        bean_pass = 0
        for col_order in permutations(range(width)):
            count += 1
            perm = generate_columnar_perm(width, col_order)
            inv = invert_perm(perm)
            if check_bean_eq(inv):
                bean_pass += 1
                configs.append((f"col-{width}", inv))
        print(f"  Width {width}: {count} orderings, {bean_pass} Bean-eq passes")
    print(f"  Total: {len(configs)}")

    # ── Phase 2: Three-layer consistency + solve ──────────────────────
    MAX_P = 12
    period_pairs = [(p1, p2) for p1 in range(1, MAX_P + 1)
                    for p2 in range(1, MAX_P + 1) if not (p1 == 1 and p2 == 1)]

    print(f"\n--- Phase 2: Three-layer consistency check ---")
    print(f"  Period pairs: {len(period_pairs)} (p1,p2 in 1..{MAX_P}, excl (1,1))")
    print(f"  C-types: 2 (A=CT-PT covers Vig+Vig/Beau+Beau/VB+Vig/Vig+VB;")
    print(f"              B=CT+PT covers Beau+Vig/VB+Beau/Vig+Beau/Beau+VB)")

    bean_ineq_skip = 0
    consistency_checks = 0
    consistent_count = 0
    cycle_fail_count = 0
    candidates = []

    # Per period-product stats
    pp_consistent = defaultdict(int)
    pp_checked = defaultdict(int)

    for config_idx, (label, inv_perm) in enumerate(configs):
        if config_idx % 3000 == 0:
            elapsed = time.time() - t0
            print(f"  ... {config_idx}/{len(configs)} configs ({elapsed:.1f}s, "
                  f"{consistent_count} consistent, {len(candidates)} candidates)")

        # Precompute per-config values
        ct_pos = [inv_perm[CRIB_POS[i]] for i in range(N_CRIBS)]
        c_A = [(CT_NUM[ct_pos[i]] - CRIB_PT[i]) % MOD for i in range(N_CRIBS)]
        c_B = [(CT_NUM[ct_pos[i]] + CRIB_PT[i]) % MOD for i in range(N_CRIBS)]

        for c_idx, c_vals in enumerate([c_A, c_B]):
            c_label = 'AB'[c_idx]

            # Bean inequality precheck on effective key values
            c_dict = {CRIB_POS[i]: c_vals[i] for i in range(N_CRIBS)}
            bean_ok = True
            for a, b in BEAN_INEQ:
                if a in c_dict and b in c_dict and c_dict[a] == c_dict[b]:
                    bean_ok = False
                    break
            if not bean_ok:
                bean_ineq_skip += 1
                continue

            for p1, p2 in period_pairs:
                prod = p1 * p2
                pp_checked[prod] += 1
                consistency_checks += 1

                # Group by (r1, r2) and check within-group consistency
                groups = {}
                n_redundant = 0
                ok = True
                for i in range(N_CRIBS):
                    r1 = CRIB_POS[i] % p1
                    r2 = ct_pos[i] % p2
                    key = (r1, r2)
                    if key in groups:
                        if groups[key] != c_vals[i]:
                            ok = False
                            break
                        n_redundant += 1
                    else:
                        groups[key] = c_vals[i]

                if not ok:
                    continue

                # BFS solve — also detects cycle contradictions
                result = bfs_solve(groups, p1, p2)
                if result is None:
                    cycle_fail_count += 1
                    continue

                K1, K2, n_components = result
                consistent_count += 1
                pp_consistent[prod] += 1

                # Derive plaintext and score
                pt = derive_plaintext(inv_perm, K1, K2, p1, p2, c_label)
                q = scorer.score_per_char(pt)

                candidates.append({
                    'label': label,
                    'p1': p1, 'p2': p2,
                    'c_type': c_label,
                    'n_redundant': n_redundant,
                    'n_groups': len(groups),
                    'n_components': n_components,
                    'quadgram': q,
                    'plaintext': pt,
                })

    elapsed = time.time() - t0
    print(f"\n  Processing complete ({elapsed:.1f}s)")
    print(f"  Bean-ineq skips: {bean_ineq_skip} (of {len(configs)*2} config×c_type)")
    print(f"  Consistency checks: {consistency_checks:,}")
    print(f"  Within-group fails: {consistency_checks - consistent_count - cycle_fail_count:,}")
    print(f"  Cycle fails: {cycle_fail_count}")
    print(f"  Consistent (full pass): {consistent_count}")
    print(f"  Candidates: {len(candidates)}")

    # ── Phase 3: Per-period-product analysis ──────────────────────────
    print(f"\n--- Phase 3: Per-period-product analysis ---")
    print(f"  {'Prod':>5} {'Checked':>9} {'Consist':>9} {'Rate':>10}")
    print(f"  {'-----':>5} {'--------':>9} {'--------':>9} {'---------':>10}")

    for prod in sorted(set(pp_checked.keys())):
        checked = pp_checked[prod]
        consist = pp_consistent.get(prod, 0)
        rate = consist / checked if checked > 0 else 0
        # Show all products ≤ 30, and any with nonzero consistent count
        if prod <= 30 or consist > 0:
            print(f"  {prod:5d} {checked:9d} {consist:9d} {rate:10.2e}")

    # Separate small vs large product candidates
    small_cands = [c for c in candidates if c['p1'] * c['p2'] <= 24]
    mid_cands = [c for c in candidates if 24 < c['p1'] * c['p2'] <= 50]
    large_cands = [c for c in candidates if c['p1'] * c['p2'] > 50]
    print(f"\n  Candidates by period product:")
    print(f"    p1*p2 <= 24 (strongly constrained): {len(small_cands)}")
    print(f"    24 < p1*p2 <= 50 (moderately constrained): {len(mid_cands)}")
    print(f"    p1*p2 > 50 (weakly constrained): {len(large_cands)}")

    # ── Phase 4: Candidate analysis ───────────────────────────────────
    print(f"\n--- Phase 4: Candidate analysis ---")

    if not candidates:
        print("  NO candidates found!")
        print("  Three-layer Sub+Trans+Sub is ELIMINATED for columnar widths 6,8,9")
        print(f"  with periods 1-{MAX_P}.")
    else:
        candidates.sort(key=lambda x: x['quadgram'], reverse=True)
        n_show = min(20, len(candidates))
        print(f"  Top {n_show} by quadgram score:")
        print(f"  {'#':>3} {'Label':>7} {'p1':>3} {'p2':>3} {'Prod':>4} {'Type':>4} "
              f"{'Q/chr':>7} {'Red':>4} {'Comp':>4}")
        for i, c in enumerate(candidates[:n_show]):
            print(f"  {i+1:3d} {c['label']:>7} {c['p1']:3d} {c['p2']:3d} "
                  f"{c['p1']*c['p2']:4d} {c['c_type']:>4} {c['quadgram']:7.3f} "
                  f"{c['n_redundant']:4d} {c['n_components']:4d}")
            if i < 5:
                print(f"      PT: {c['plaintext']}")

        all_q = [c['quadgram'] for c in candidates]
        q_mean = sum(all_q) / len(all_q)
        q_max = max(all_q)
        n_english = sum(1 for q in all_q if q > -4.84)

        print(f"\n  Score stats: N={len(candidates)}, mean={q_mean:.3f}, max={q_max:.3f}")
        print(f"  Above English threshold (-4.84/char): {n_english}")

    # ── Phase 5: Validation — p2=1 should match E-FRAC-35 ────────────
    print(f"\n--- Phase 5: E-FRAC-35 validation (p2=1 = single periodic key) ---")
    p2_1_counts = defaultdict(int)
    for c in candidates:
        if c['p2'] == 1:
            p2_1_counts[c['p1']] += 1
    if p2_1_counts:
        print(f"  p2=1 candidates by p1: {dict(sorted(p2_1_counts.items()))}")
        discriminating = {2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 14, 15, 17, 18, 21, 22, 25}
        p2_1_disc = {p for p in p2_1_counts if p in discriminating}
        if p2_1_disc:
            print(f"  WARNING: candidates at discriminating periods: {p2_1_disc}")
        else:
            print(f"  All p2=1 candidates at non-discriminating periods — matches E-FRAC-35")
    else:
        print(f"  No p2=1 candidates — consistent with E-FRAC-35 (all periods eliminated)")

    # Same for p1=1 (key after transposition — genuinely new)
    p1_1_counts = defaultdict(int)
    for c in candidates:
        if c['p1'] == 1:
            p1_1_counts[c['p2']] += 1
    print(f"\n  p1=1 candidates (key after trans — NEW territory):")
    if p1_1_counts:
        print(f"    By p2: {dict(sorted(p1_1_counts.items()))}")
    else:
        print(f"    None found")

    # ── Phase 6: Random baseline ──────────────────────────────────────
    print(f"\n--- Phase 6: Random baseline ---")
    random.seed(42)
    N_RAND = 2000
    indices = list(range(N))
    rand_consistent = 0
    rand_total = 0
    test_pairs = [(2, 3), (3, 4), (4, 5), (2, 5), (3, 5), (5, 7)]

    for _ in range(N_RAND):
        perm = indices[:]
        random.shuffle(perm)
        inv = invert_perm(perm)
        if not check_bean_eq(inv):
            continue

        ct_pos = [inv[CRIB_POS[i]] for i in range(N_CRIBS)]
        c_A = [(CT_NUM[ct_pos[i]] - CRIB_PT[i]) % MOD for i in range(N_CRIBS)]
        c_B = [(CT_NUM[ct_pos[i]] + CRIB_PT[i]) % MOD for i in range(N_CRIBS)]

        for c_vals in [c_A, c_B]:
            # Bean-ineq precheck
            c_dict = {CRIB_POS[i]: c_vals[i] for i in range(N_CRIBS)}
            bean_ok = True
            for a, b in BEAN_INEQ:
                if a in c_dict and b in c_dict and c_dict[a] == c_dict[b]:
                    bean_ok = False
                    break
            if not bean_ok:
                continue

            for p1, p2 in test_pairs:
                rand_total += 1
                groups = {}
                ok = True
                for i in range(N_CRIBS):
                    key = (CRIB_POS[i] % p1, ct_pos[i] % p2)
                    if key in groups:
                        if groups[key] != c_vals[i]:
                            ok = False
                            break
                    else:
                        groups[key] = c_vals[i]
                if ok:
                    result = bfs_solve(groups, p1, p2)
                    if result is not None:
                        rand_consistent += 1

    print(f"  Random Bean-eq-passing perms tested: {N_RAND}")
    print(f"  Total checks (small period pairs): {rand_total}")
    print(f"  Consistent: {rand_consistent}")
    if rand_total > 0:
        print(f"  Rate: {rand_consistent/rand_total:.2e}")
    print(f"  Expected: ~0 (FP rate ~10^-16 for these products)")

    # ── Phase 7: Verdict ──────────────────────────────────────────────
    print(f"\n--- Phase 7: Verdict ---")
    runtime = time.time() - t0

    n_small = len(small_cands)
    n_english = sum(1 for c in candidates if c['quadgram'] > -4.84) if candidates else 0

    if len(candidates) == 0:
        verdict = "ELIMINATED"
        print(f"  VERDICT: {verdict}")
        print(f"  ZERO candidates survive consistency + Bean filters.")
    elif n_english > 0:
        verdict = "SIGNAL"
        print(f"  VERDICT: {verdict}")
        print(f"  {n_english} candidates exceed English quadgram threshold!")
    elif n_small > 0:
        verdict = "INVESTIGATE"
        print(f"  VERDICT: {verdict}")
        print(f"  {n_small} strongly-constrained candidates (p1*p2 <= 24).")
    else:
        verdict = "NOISE"
        print(f"  VERDICT: {verdict}")
        print(f"  All {len(candidates)} candidates at large period products (underdetermined)")
        print(f"  and score below English threshold (-4.84/char).")
        print(f"  Three-layer Sub+Trans+Sub produces ONLY random-quality plaintext.")

    # ── Save results ──────────────────────────────────────────────────
    out_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'frac')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'e_frac_52_three_layer.json')

    output = {
        'experiment': 'E-FRAC-52',
        'description': 'Three-layer model: Sub + Trans + Sub',
        'model': 'CT = Enc2(sigma(Enc1(PT, K1)), K2), K1 period p1, K2 period p2',
        'effective_key': 'K_eff[j] = K1[j%p1] + K2[inv(j)%p2] — non-periodic',
        'gap_filled': 'E-FRAC-35 eliminated single periodic key; three-layer bypasses via non-periodic K_eff',
        'transpositions': f'Columnar widths 6,8,9 Bean-eq-passing ({len(configs)} configs)',
        'period_range': f'p1,p2 in 1..{MAX_P}, excl (1,1) — {len(period_pairs)} pairs',
        'c_types': '2 (A=CT-PT, B=CT+PT) — covers all 9 inner/outer variant combinations',
        'bean_ineq_skips': bean_ineq_skip,
        'consistency_checks': consistency_checks,
        'cycle_failures': cycle_fail_count,
        'consistent_count': consistent_count,
        'n_candidates': len(candidates),
        'n_small_product': n_small,
        'n_english_q': n_english,
        'random_baseline': {
            'n_perms': N_RAND,
            'total_checks': rand_total,
            'consistent': rand_consistent,
        },
        'verdict': verdict,
        'runtime_seconds': runtime,
    }

    if candidates:
        output['top_candidates'] = [{
            'label': c['label'],
            'p1': c['p1'], 'p2': c['p2'],
            'c_type': c['c_type'],
            'quadgram': round(c['quadgram'], 4),
            'n_redundant': c['n_redundant'],
            'n_components': c['n_components'],
            'plaintext': c['plaintext'],
        } for c in sorted(candidates, key=lambda x: x['quadgram'], reverse=True)[:50]]

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved to: {out_path}")
    print(f"  Runtime: {runtime:.1f}s")
    print("=" * 70)
    print(f"RESULT: consistent={consistent_count} candidates={len(candidates)} "
          f"small_product={n_small} english_q={n_english} verdict={verdict}")
    print("=" * 70)


if __name__ == '__main__':
    main()
