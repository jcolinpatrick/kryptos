#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-53: Monoalphabetic Inner + Periodic Outer Model

MODEL: CT[inv(j)] = (Sub[PT[j]] + K[inv(j)%p]) % 26
  - Sub is a monoalphabetic substitution (unknown permutation of 26 letters)
  - sigma is a transposition (columnar at widths 6, 8, 9)
  - K has period p (polyalphabetic substitution AFTER transposition)

WHY THIS MATTERS — E-FRAC-35 BYPASS:
  E-FRAC-35 proved ALL discriminating periods (2-7) are Bean-impossible for
  transposition + single periodic key. BUT the proof relies on 9 Bean inequality
  pairs where PT[a] != PT[b] (different plaintext letters). Adding a monoalphabetic
  inner layer AUTO-SATISFIES these 9 pairs (since Sub[L1] != Sub[L2] for L1 != L2).

  Only 12 same-letter pairs remain (where PT[a] = PT[b]):
    T: (24,28), (28,33), (24,33)  —  E: (21,30), (21,64), (30,64)
    N: (68,25)  A: (22,31)  L: (66,70)  O: (26,71)  C: (69,72)  S: (23,32)

  PIGEONHOLE: Period 2 is still impossible (T has 3 positions in 2 bins).
  Periods 3-7: NOT pigeonhole-impossible! Max letter group size is 3, and p >= 3.
  Whether a specific transposition is Bean-viable at p=3-7 depends on the
  residue pattern inv(a)%p for same-letter pairs.

  AT PERIODS 6 AND 7 (identity transposition): ALL 12 same-letter pairs have
  different residues! These periods are NEWLY VIABLE with the mono inner layer.

METHOD:
  For each Bean-eq-passing columnar sigma:
    For each period p in {3, 4, 5, 6, 7, 8, 9, 10, 11, 12}:
      1. Same-letter Bean-ineq precheck: inv(a)%p != inv(b)%p for all 12 pairs
      2. Build bipartite system: s_{PT[j]} + k_{inv(j)%p} = CT[inv(j)]
         Left nodes: 13 distinct crib letters, Right nodes: p residue classes
      3. Consistency check + BFS solve
      4. Different-letter Bean-ineq check on solved values
      5. Validate mono substitution (all 13 known s_L values distinct)
      6. Derive partial plaintext and score

  Unknowns: 13 + p - 1 = 12 + p (shift invariance)
  Equations: 24 (one per crib position)
  Redundant: 12 - p (for p <= 12)

  Expected FP rates:
    p=3: (1/26)^9 ~ 2e-13 -> ZERO FP
    p=6: (1/26)^6 ~ 3e-9  -> ZERO FP
    p=7: (1/26)^5 ~ 8e-8  -> marginal
    p=12: (1/26)^0 ~ 1    -> many FP (underdetermined)
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
CRIB_PT_IDX = [ALPH_IDX[ch] for _, ch in CRIB_ENTRIES]
CRIB_PT_CHAR = [ch for _, ch in CRIB_ENTRIES]
CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN  # 97

QUADGRAM_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')

# Identify same-letter and different-letter Bean inequality pairs
SAME_LETTER_INEQ = []  # (a, b) where PT[a] = PT[b]
DIFF_LETTER_INEQ = []  # (a, b) where PT[a] != PT[b]

_crib_dict = dict(CRIB_ENTRIES)
for a, b in BEAN_INEQ:
    if a in _crib_dict and b in _crib_dict:
        if _crib_dict[a] == _crib_dict[b]:
            SAME_LETTER_INEQ.append((a, b))
        else:
            DIFF_LETTER_INEQ.append((a, b))

# Distinct crib letters (used as bipartite left nodes)
CRIB_LETTERS = sorted(set(CRIB_PT_CHAR))  # 13 distinct letters


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


def bfs_solve(groups, n_left, n_right, left_prefix='L', right_prefix='R'):
    """BFS solve bipartite system: left[a] + right[b] = c.
    Returns (left_vals, right_vals, n_components) or None if inconsistent."""
    adj = defaultdict(list)
    for (a, b), c in groups.items():
        adj[(left_prefix, a)].append(((right_prefix, b), c))
        adj[(right_prefix, b)].append(((left_prefix, a), c))

    vals = {}
    n_components = 0
    all_nodes = set()
    for (a, b) in groups:
        all_nodes.add((left_prefix, a))
        all_nodes.add((right_prefix, b))

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
                        return None
                    continue
                vals[neighbor] = expected
                queue.append(neighbor)

    left_vals = [vals.get((left_prefix, i), 0) for i in range(n_left)]
    right_vals = [vals.get((right_prefix, i), 0) for i in range(n_right)]
    return left_vals, right_vals, n_components


def main():
    print("=" * 70)
    print("E-FRAC-53: Monoalphabetic Inner + Periodic Outer Model")
    print("=" * 70)
    t0 = time.time()

    scorer = QuadgramScorer(QUADGRAM_FILE)
    print("Quadgram scorer loaded")

    # Print Bean inequality analysis
    print(f"\n--- Bean Inequality Analysis ---")
    print(f"  Total Bean inequality pairs: {len(BEAN_INEQ)}")
    print(f"  Same-letter pairs (relevant for mono+periodic model): {len(SAME_LETTER_INEQ)}")
    for a, b in SAME_LETTER_INEQ:
        print(f"    ({a},{b}): PT={_crib_dict[a]}={_crib_dict[b]}")
    print(f"  Different-letter pairs (auto-satisfied by mono substitution): {len(DIFF_LETTER_INEQ)}")
    for a, b in DIFF_LETTER_INEQ:
        print(f"    ({a},{b}): PT={_crib_dict[a]}!={_crib_dict[b]}")
    print(f"  Distinct crib letters: {len(CRIB_LETTERS)} = {','.join(CRIB_LETTERS)}")

    # Pigeonhole analysis
    print(f"\n--- Pigeonhole Analysis ---")
    letter_positions = defaultdict(list)
    for i in range(N_CRIBS):
        letter_positions[CRIB_PT_CHAR[i]].append(CRIB_POS[i])
    max_group = max(len(v) for v in letter_positions.values())
    print(f"  Max letter group size: {max_group} (letter T and E each have 3 positions)")
    print(f"  Period 2: IMPOSSIBLE by pigeonhole (3 T-positions in 2 bins)")
    print(f"  Periods 3+: NOT pigeonhole-impossible (3 positions in 3+ bins)")

    # ── Phase 1: Generate Bean-eq-passing transpositions ──────────────
    print(f"\n--- Phase 1: Generate Bean-eq-passing transpositions ---")
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

    # ── Phase 2: Build letter-index mapping ───────────────────────────
    # Map each crib letter to an index for the bipartite system
    letter_to_idx = {L: i for i, L in enumerate(CRIB_LETTERS)}
    N_LETTERS = len(CRIB_LETTERS)  # 13

    # ── Phase 3: Test mono+trans+periodic model ───────────────────────
    periods = list(range(3, 13))  # 3 through 12

    print(f"\n--- Phase 3: Mono+Trans+Periodic consistency check ---")
    print(f"  Periods tested: {periods}")
    print(f"  Configs × periods: {len(configs)} × {len(periods)} = {len(configs)*len(periods):,}")

    # Stats
    same_letter_skip = 0
    consistency_checks = 0
    consistency_pass = 0
    cycle_fail = 0
    diff_letter_fail = 0
    mono_invalid = 0
    candidates = []

    # Per-period stats
    p_stats = {p: {'checked': 0, 'same_letter_pass': 0, 'consistent': 0,
                    'diff_bean_pass': 0, 'mono_valid': 0}
               for p in periods}

    for config_idx, (label, inv_perm) in enumerate(configs):
        if config_idx % 3000 == 0:
            elapsed = time.time() - t0
            print(f"  ... {config_idx}/{len(configs)} configs ({elapsed:.1f}s, "
                  f"{consistency_pass} consistent, {len(candidates)} candidates)")

        # Precompute transposed CT positions for crib positions
        ct_pos = [inv_perm[CRIB_POS[i]] for i in range(N_CRIBS)]
        ct_vals = [CT_NUM[ct_pos[i]] for i in range(N_CRIBS)]

        for p in periods:
            p_stats[p]['checked'] += 1

            # Step 1: Same-letter Bean-ineq precheck
            # For each same-letter pair (a,b), check inv(a)%p != inv(b)%p
            same_letter_ok = True
            for a, b in SAME_LETTER_INEQ:
                if inv_perm[a] % p == inv_perm[b] % p:
                    same_letter_ok = False
                    break

            if not same_letter_ok:
                same_letter_skip += 1
                continue

            p_stats[p]['same_letter_pass'] += 1
            consistency_checks += 1

            # Step 2: Build bipartite system
            # s_{PT[j]} + k_{inv(j)%p} = CT[inv(j)]
            # Left nodes: letter indices (0..12), Right nodes: residues (0..p-1)
            groups = {}
            n_redundant = 0
            ok = True
            for i in range(N_CRIBS):
                letter_idx = letter_to_idx[CRIB_PT_CHAR[i]]
                residue = ct_pos[i] % p
                c_val = ct_vals[i]
                key = (letter_idx, residue)

                if key in groups:
                    if groups[key] != c_val:
                        ok = False
                        break
                    n_redundant += 1
                else:
                    groups[key] = c_val

            if not ok:
                continue

            # Step 3: BFS solve
            result = bfs_solve(groups, N_LETTERS, p, 'S', 'K')
            if result is None:
                cycle_fail += 1
                continue

            s_vals, k_vals, n_components = result
            consistency_pass += 1
            p_stats[p]['consistent'] += 1

            # Step 4: Different-letter Bean-ineq check
            # For pairs (a,b) with PT[a] != PT[b]:
            # Need s_{PT[a]} + k_{inv(a)%p} != s_{PT[b]} + k_{inv(b)%p}
            diff_ok = True
            for a, b in DIFF_LETTER_INEQ:
                la = letter_to_idx[_crib_dict[a]]
                lb = letter_to_idx[_crib_dict[b]]
                ra = inv_perm[a] % p
                rb = inv_perm[b] % p
                eff_a = (s_vals[la] + k_vals[ra]) % MOD
                eff_b = (s_vals[lb] + k_vals[rb]) % MOD
                if eff_a == eff_b:
                    diff_ok = False
                    break

            if not diff_ok:
                diff_letter_fail += 1
                continue

            p_stats[p]['diff_bean_pass'] += 1

            # Step 5: Validate mono substitution (all 13 s_L values distinct)
            known_s = set()
            s_distinct = True
            for li in range(N_LETTERS):
                sv = s_vals[li] % MOD
                if sv in known_s:
                    s_distinct = False
                    break
                known_s.add(sv)

            if not s_distinct:
                mono_invalid += 1
                continue

            p_stats[p]['mono_valid'] += 1

            # Step 6: Derive partial plaintext
            # Build inverse mono table for known letters
            inv_sub = {}  # s_val -> letter
            for li, L in enumerate(CRIB_LETTERS):
                inv_sub[s_vals[li] % MOD] = L

            # Derive plaintext at all 97 positions
            pt_chars = []
            n_known = 0
            for j in range(N):
                ct_j = inv_perm[j]
                target = (CT_NUM[ct_j] - k_vals[ct_j % p]) % MOD
                if target in inv_sub:
                    pt_chars.append(inv_sub[target])
                    n_known += 1
                else:
                    pt_chars.append('?')

            plaintext = ''.join(pt_chars)

            # Score the known positions (replace ? with random for scoring)
            # Better: just score what we have
            q_score = scorer.score_per_char(plaintext.replace('?', 'X'))

            # Verify cribs match
            crib_ok = True
            for i in range(N_CRIBS):
                if plaintext[CRIB_POS[i]] != CRIB_PT_CHAR[i]:
                    crib_ok = False
                    break

            candidates.append({
                'label': label,
                'period': p,
                'n_redundant': n_redundant,
                'n_components': n_components,
                'n_known': n_known,
                'crib_ok': crib_ok,
                'quadgram': q_score,
                'plaintext': plaintext,
                's_vals': {L: s_vals[letter_to_idx[L]] for L in CRIB_LETTERS},
                'k_vals': k_vals[:],
            })

    elapsed = time.time() - t0
    print(f"\n  Processing complete ({elapsed:.1f}s)")
    print(f"  Same-letter Bean-ineq skips: {same_letter_skip}")
    print(f"  Consistency checks: {consistency_checks}")
    print(f"  Cycle failures: {cycle_fail}")
    print(f"  Consistent (pass): {consistency_pass}")
    print(f"  Different-letter Bean-ineq fail: {diff_letter_fail}")
    print(f"  Mono substitution invalid: {mono_invalid}")
    print(f"  Final candidates: {len(candidates)}")

    # ── Phase 4: Per-period analysis ──────────────────────────────────
    print(f"\n--- Phase 4: Per-period analysis ---")
    print(f"  {'p':>3} {'Checked':>8} {'SameLtr':>8} {'Consist':>8} {'DiffBean':>8} "
          f"{'MonoOK':>7} {'Redund':>7} {'ExpFP':>10}")
    print(f"  {'---':>3} {'-------':>8} {'-------':>8} {'-------':>8} {'-------':>8} "
          f"{'------':>7} {'------':>7} {'-----':>10}")
    for p in periods:
        s = p_stats[p]
        redundant = max(0, 12 - p)
        exp_fp = (1.0 / 26) ** redundant * s['same_letter_pass'] if s['same_letter_pass'] > 0 else 0
        print(f"  {p:3d} {s['checked']:8d} {s['same_letter_pass']:8d} {s['consistent']:8d} "
              f"{s['diff_bean_pass']:8d} {s['mono_valid']:7d} {redundant:7d} {exp_fp:10.2e}")

    # Highlight discriminating periods
    print(f"\n  KEY PERIODS (newly viable in mono+periodic model):")
    for p in [3, 4, 5, 6, 7]:
        s = p_stats[p]
        print(f"    Period {p}: {s['same_letter_pass']} configs pass same-letter Bean-ineq, "
              f"{s['mono_valid']} final candidates")

    # ── Phase 5: Candidate analysis ───────────────────────────────────
    print(f"\n--- Phase 5: Candidate analysis ---")

    if not candidates:
        print("  NO candidates found!")
        print("  Mono+Trans+Periodic model produces ZERO consistent solutions")
        print("  at ANY period 3-12 for columnar widths 6,8,9.")
    else:
        # Separate by period range
        disc_cands = [c for c in candidates if c['period'] <= 7]
        other_cands = [c for c in candidates if c['period'] > 7]

        print(f"  Discriminating periods (3-7): {len(disc_cands)} candidates")
        print(f"  Other periods (8-12): {len(other_cands)} candidates")

        candidates.sort(key=lambda x: (-1 if x['period'] <= 7 else 0, x['quadgram']), reverse=True)

        n_show = min(30, len(candidates))
        print(f"\n  Top {n_show} candidates:")
        print(f"  {'#':>3} {'Label':>7} {'p':>3} {'Q/chr':>7} {'Known':>5} {'Crib':>5} "
              f"{'Red':>4} {'Comp':>4}")
        for i, c in enumerate(candidates[:n_show]):
            crib_str = "OK" if c['crib_ok'] else "FAIL"
            print(f"  {i+1:3d} {c['label']:>7} {c['period']:3d} {c['quadgram']:7.3f} "
                  f"{c['n_known']:5d} {crib_str:>5} {c['n_redundant']:4d} {c['n_components']:4d}")
            if i < 10:
                print(f"      PT: {c['plaintext']}")

        all_q = [c['quadgram'] for c in candidates]
        n_english = sum(1 for q in all_q if q > -4.84)
        print(f"\n  Score stats: N={len(candidates)}, max={max(all_q):.3f}, "
              f"mean={sum(all_q)/len(all_q):.3f}")
        print(f"  Above English threshold (-4.84): {n_english}")

    # ── Phase 6: Random baseline ──────────────────────────────────────
    print(f"\n--- Phase 6: Random baseline ---")
    random.seed(42)
    N_RAND = 2000
    indices = list(range(N))
    rand_consistent = 0
    rand_total = 0

    for _ in range(N_RAND):
        perm = indices[:]
        random.shuffle(perm)
        inv = invert_perm(perm)
        if not check_bean_eq(inv):
            continue

        ct_pos_r = [inv[CRIB_POS[i]] for i in range(N_CRIBS)]
        ct_vals_r = [CT_NUM[ct_pos_r[i]] for i in range(N_CRIBS)]

        for p in [3, 4, 5, 6, 7]:
            # Same-letter precheck
            sl_ok = True
            for a, b in SAME_LETTER_INEQ:
                if inv[a] % p == inv[b] % p:
                    sl_ok = False
                    break
            if not sl_ok:
                continue

            rand_total += 1
            groups = {}
            ok = True
            for i in range(N_CRIBS):
                li = letter_to_idx[CRIB_PT_CHAR[i]]
                r = ct_pos_r[i] % p
                key = (li, r)
                if key in groups:
                    if groups[key] != ct_vals_r[i]:
                        ok = False
                        break
                else:
                    groups[key] = ct_vals_r[i]
            if ok:
                result = bfs_solve(groups, N_LETTERS, p, 'S', 'K')
                if result is not None:
                    rand_consistent += 1

    print(f"  Random Bean-eq-passing perms: {N_RAND}")
    print(f"  Checks at periods 3-7: {rand_total}")
    print(f"  Consistent: {rand_consistent}")
    if rand_total > 0:
        print(f"  Rate: {rand_consistent/rand_total:.2e}")

    # ── Phase 7: Verdict ──────────────────────────────────────────────
    print(f"\n--- Phase 7: Verdict ---")
    runtime = time.time() - t0

    n_disc = sum(1 for c in candidates if c['period'] <= 7)
    n_english = sum(1 for c in candidates if c['quadgram'] > -4.84)

    if n_english > 0:
        verdict = "SIGNAL"
        print(f"  VERDICT: {verdict}")
        print(f"  {n_english} candidates exceed English quadgram threshold!")
    elif n_disc > 0:
        verdict = "INVESTIGATE"
        print(f"  VERDICT: {verdict}")
        print(f"  {n_disc} candidates at discriminating periods 3-7!")
    elif len(candidates) == 0:
        verdict = "ELIMINATED"
        print(f"  VERDICT: {verdict}")
        print(f"  ZERO candidates at ANY period 3-12.")
        print(f"  Mono+Trans+Periodic ELIMINATED for columnar widths 6,8,9.")
    else:
        verdict = "NOISE"
        print(f"  VERDICT: {verdict}")
        print(f"  All {len(candidates)} candidates at non-discriminating periods (8-12)")
        print(f"  and below English threshold.")

    # ── Save results ──────────────────────────────────────────────────
    out_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'frac')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'e_frac_53_mono_inner_periodic.json')

    output = {
        'experiment': 'E-FRAC-53',
        'description': 'Monoalphabetic inner + periodic outer model',
        'model': 'CT[inv(j)] = (Sub[PT[j]] + K[inv(j)%p]) % 26',
        'gap_filled': (
            'E-FRAC-35 proof relies on 9 different-letter Bean pairs at periods 6,7. '
            'Mono inner layer auto-satisfies these, making periods 3-7 potentially viable.'
        ),
        'same_letter_pairs': len(SAME_LETTER_INEQ),
        'diff_letter_pairs': len(DIFF_LETTER_INEQ),
        'transpositions': f'Columnar widths 6,8,9 ({len(configs)} configs)',
        'periods': periods,
        'stats': {
            'same_letter_skip': same_letter_skip,
            'consistency_checks': consistency_checks,
            'consistency_pass': consistency_pass,
            'cycle_fail': cycle_fail,
            'diff_letter_fail': diff_letter_fail,
            'mono_invalid': mono_invalid,
            'n_candidates': len(candidates),
        },
        'per_period': {str(p): p_stats[p] for p in periods},
        'random_baseline': {
            'n_perms': N_RAND,
            'checks': rand_total,
            'consistent': rand_consistent,
        },
        'verdict': verdict,
        'runtime_seconds': runtime,
    }

    if candidates:
        output['top_candidates'] = [{
            'label': c['label'],
            'period': c['period'],
            'quadgram': round(c['quadgram'], 4),
            'n_known': c['n_known'],
            'crib_ok': c['crib_ok'],
            'n_redundant': c['n_redundant'],
            'n_components': c['n_components'],
            'plaintext': c['plaintext'],
        } for c in sorted(candidates, key=lambda x: x['quadgram'], reverse=True)[:50]]

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved to: {out_path}")
    print(f"  Runtime: {runtime:.1f}s")
    print("=" * 70)
    print(f"RESULT: consistent={consistency_pass} disc_cands={n_disc} "
          f"english_q={n_english} verdict={verdict}")
    print("=" * 70)


if __name__ == '__main__':
    main()
