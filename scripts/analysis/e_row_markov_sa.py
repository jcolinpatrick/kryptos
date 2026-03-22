#!/usr/bin/env python3
"""Row-Markov Regularized Keystream SA: does Polybius row structure help decode?

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   SA exploration (26^49 at unknown positions, Markov-guided)
Last run:   2026-03-21
Best score: TBD

DESIGN:
  The known 24-value keystream shows strong row clustering on the 5-wide KA
  Polybius grid (10/23 same-row transitions vs 4.3 expected, p=0.005).  This
  test asks: does USING that structure as an SA prior improve decryption toward
  English?

  Four conditions (same 300 restarts × 1M steps each):
    A) Pure English SA (quadgrams only, no row prior) — baseline
    B) Mild row prior (λ=0.05)
    C) Moderate row prior (λ=0.15)
    D) Strong row prior (λ=0.30)

  If B/C/D produce significantly better English than A, the row structure is
  real and useful. If not, it's either a crib artifact or irrelevant to the
  cipher mechanism.

  All conditions enforce:
    - 24 known keystream values fixed at crib positions
    - Bean equality k[27]=k[65]
    - 242 Bean inequalities as rejection filter

  Unlike prior e_constrained_keystream_mcmc (which hard-restricted to 12
  letters), this allows ALL 26 values at unknown positions.
"""
import sys, os, json, random, math
from collections import Counter
from datetime import datetime
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {ch: i for i, ch in enumerate(KA)}

def az(ch):    return ALPH_IDX[ch]
def az_chr(v): return ALPH[v % 26]
def ka_row(v): return KA_IDX[az_chr(v)] // 5   # AZ value → KA Polybius row

# ── Known keystream (Model B: Beaufort A=0 on raw CT97) ───────────────
# These are k[i] = (CT[i] + PT[i]) mod 26 at each crib position
KNOWN_KS = {}
for i, val in enumerate(BEAUFORT_KEY_ENE):
    KNOWN_KS[21 + i] = val     # positions 21-33
for i, val in enumerate(BEAUFORT_KEY_BC):
    KNOWN_KS[63 + i] = val     # positions 63-73
assert len(KNOWN_KS) == 24

# Full ordered keystream at crib positions (for Markov estimation)
CRIB_KS_ORDERED = [KNOWN_KS[p] for p in sorted(KNOWN_KS.keys())]

# ── Null mask: consensus 17 + one specific 7-varying config ───────────
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
VARYING_NULLS   = frozenset({38,44,55,87,93,94,95})
NULL_POSITIONS   = CONSENSUS_NULLS | VARYING_NULLS
assert len(NULL_POSITIONS) == 24

CIPHER_POSITIONS = [p for p in range(97) if p not in NULL_POSITIONS]
assert len(CIPHER_POSITIONS) == 73
POS_TO_IDX = {p: i for i, p in enumerate(CIPHER_POSITIONS)}

# Map CT97 crib positions → CT73 indices
KNOWN_73 = {}
for pos, val in KNOWN_KS.items():
    if pos in POS_TO_IDX:
        KNOWN_73[POS_TO_IDX[pos]] = val

# Bean equality: CT97 positions 27,65 → CT73 indices
BEAN_EQ_73 = []
for a, b in BEAN_EQ:
    if a in POS_TO_IDX and b in POS_TO_IDX:
        BEAN_EQ_73.append((POS_TO_IDX[a], POS_TO_IDX[b]))

# Bean inequalities: CT97 position pairs → CT73 index pairs
BEAN_INEQ_73 = []
for a, b in BEAN_INEQ:
    if a in POS_TO_IDX and b in POS_TO_IDX:
        BEAN_INEQ_73.append((POS_TO_IDX[a], POS_TO_IDX[b]))

UNKNOWN_INDICES = sorted(i for i in range(73) if i not in KNOWN_73)
N_UNKNOWN = len(UNKNOWN_INDICES)

# ── Empirical Markov transition matrix from known 24 keystream values ──
# Row sequence from the 24 known values (sorted by CT97 position)
ROW_SEQ = [ka_row(v) for v in CRIB_KS_ORDERED]
N_ROWS = 6  # KA has 6 Polybius rows (row 5 has only Z)

# Row sizes in KA grid
ROW_SIZES = [5, 5, 5, 5, 5, 1]

# Count transitions
TRANS_COUNTS = [[0]*N_ROWS for _ in range(N_ROWS)]
for i in range(len(ROW_SEQ) - 1):
    TRANS_COUNTS[ROW_SEQ[i]][ROW_SEQ[i+1]] += 1

# Smoothed transition log-probs (Laplace smoothing, α=0.5)
ALPHA_SMOOTH = 0.5
TRANS_LOGPROB = [[0.0]*N_ROWS for _ in range(N_ROWS)]
for r in range(N_ROWS):
    total = sum(TRANS_COUNTS[r]) + ALPHA_SMOOTH * N_ROWS
    for c in range(N_ROWS):
        prob = (TRANS_COUNTS[r][c] + ALPHA_SMOOTH) / total
        TRANS_LOGPROB[r][c] = math.log(prob)

# Uniform (null model) transition log-probs (based on row sizes)
TOTAL_LETTERS = 26
UNIFORM_LOGPROB = [math.log(ROW_SIZES[r] / TOTAL_LETTERS) for r in range(N_ROWS)]

# ── Load quadgrams ────────────────────────────────────────────────────
quadgram_file = os.path.join(_ROOT, "data", "english_quadgrams.json")
with open(quadgram_file) as f:
    QUADGRAMS = json.load(f)
FLOOR = -10.0

# ── CT letters at cipher positions ────────────────────────────────────
CT73 = [CT[p] for p in CIPHER_POSITIONS]

# ── Scoring functions ─────────────────────────────────────────────────

def qg_score(ks73):
    """Quadgram score per character for Beaufort decryption."""
    total = 0.0
    n = 0
    # Build plaintext directly
    pt = [None] * 73
    for i in range(73):
        pt[i] = (ks73[i] - az(CT73[i])) % 26
    # Score quadgrams on AZ-letter plaintext
    for i in range(70):
        gram = ALPH[pt[i]] + ALPH[pt[i+1]] + ALPH[pt[i+2]] + ALPH[pt[i+3]]
        total += QUADGRAMS.get(gram, FLOOR)
        n += 1
    return total / n if n else FLOOR

def row_markov_logprob(ks73):
    """Log probability of keystream row sequence under empirical Markov model,
    MINUS the log probability under uniform. Returns excess log-prob."""
    excess = 0.0
    prev_row = ka_row(ks73[0])
    for i in range(1, 73):
        curr_row = ka_row(ks73[i])
        excess += TRANS_LOGPROB[prev_row][curr_row] - UNIFORM_LOGPROB[curr_row]
        prev_row = curr_row
    return excess

def bean_ineq_violations(ks73):
    """Count Bean inequality violations."""
    violations = 0
    for a, b in BEAN_INEQ_73:
        if ks73[a] == ks73[b]:
            violations += 1
    return violations

def combined_score(ks73, lam):
    """Combined objective: English quality + λ × row Markov prior."""
    qg = qg_score(ks73)
    if lam == 0.0:
        return qg, qg, 0.0
    markov = row_markov_logprob(ks73)
    return qg + lam * markov, qg, markov

# ── SA worker ─────────────────────────────────────────────────────────

def sa_run(args):
    """One SA run. Returns best result."""
    run_id, n_steps, seed, lam, condition_name = args
    rng = random.Random(seed)

    # Initialize keystream
    ks = [0] * 73
    for idx, val in KNOWN_73.items():
        ks[idx] = val

    # Random init for unknown positions (full 26)
    for idx in UNKNOWN_INDICES:
        ks[idx] = rng.randint(0, 25)

    # Enforce Bean equality
    for a, b in BEAN_EQ_73:
        if a in UNKNOWN_INDICES and b in UNKNOWN_INDICES:
            ks[b] = ks[a]
        elif a in UNKNOWN_INDICES:
            ks[a] = ks[b]
        elif b in UNKNOWN_INDICES:
            ks[b] = ks[a]

    # Repair Bean inequality violations
    for _ in range(100):
        v = bean_ineq_violations(ks)
        if v == 0:
            break
        for a, b in BEAN_INEQ_73:
            if ks[a] == ks[b]:
                if b in UNKNOWN_INDICES:
                    ks[b] = (ks[b] + rng.randint(1, 25)) % 26
                elif a in UNKNOWN_INDICES:
                    ks[a] = (ks[a] + rng.randint(1, 25)) % 26

    current_combined, current_qg, current_markov = combined_score(ks, lam)
    best_combined = current_combined
    best_qg = current_qg
    best_ks = ks[:]

    T_start = 2.0
    T_end = 0.005

    bean_eq_set = set()
    for a, b in BEAN_EQ_73:
        bean_eq_set.add((a, b))

    # Build lookup: which Bean ineq pairs involve each index
    ineq_by_idx = {}
    for a, b in BEAN_INEQ_73:
        ineq_by_idx.setdefault(a, []).append(b)
        ineq_by_idx.setdefault(b, []).append(a)

    for step in range(n_steps):
        T = T_start * (T_end / T_start) ** (step / n_steps)

        idx = UNKNOWN_INDICES[rng.randint(0, N_UNKNOWN - 1)]
        old_val = ks[idx]
        new_val = rng.randint(0, 25)
        if new_val == old_val:
            new_val = (old_val + rng.randint(1, 25)) % 26

        ks[idx] = new_val

        # Enforce Bean equality
        partner_idx = None
        partner_old = None
        for a, b in BEAN_EQ_73:
            if idx == a and b in UNKNOWN_INDICES:
                partner_idx, partner_old = b, ks[b]
                ks[b] = new_val
            elif idx == b and a in UNKNOWN_INDICES:
                partner_idx, partner_old = a, ks[a]
                ks[a] = new_val

        # Check Bean inequality violations for changed position(s)
        bean_ok = True
        changed = [idx]
        if partner_idx is not None:
            changed.append(partner_idx)
        for ci in changed:
            for other in ineq_by_idx.get(ci, []):
                if ks[ci] == ks[other]:
                    bean_ok = False
                    break
            if not bean_ok:
                break

        if not bean_ok:
            ks[idx] = old_val
            if partner_idx is not None:
                ks[partner_idx] = partner_old
            continue

        new_combined, new_qg, new_markov = combined_score(ks, lam)
        delta = new_combined - current_combined

        if delta > 0 or rng.random() < math.exp(delta / T):
            current_combined = new_combined
            current_qg = new_qg
            current_markov = new_markov
            if new_combined > best_combined:
                best_combined = new_combined
                best_qg = new_qg
                best_ks = ks[:]
        else:
            ks[idx] = old_val
            if partner_idx is not None:
                ks[partner_idx] = partner_old

    # Final stats on best
    rows = [ka_row(v) for v in best_ks]
    row_pairs = sum(1 for i in range(72) if rows[i] == rows[i+1])
    ap_count = sum(1 for v in best_ks if v in {6, 10, 14})
    distinct = len(set(best_ks))
    _, final_qg, final_markov = combined_score(best_ks, lam)

    # Decrypt for plaintext
    pt_chars = []
    for i in range(73):
        pt_val = (best_ks[i] - az(CT73[i])) % 26
        pt_chars.append(ALPH[pt_val])
    pt = ''.join(pt_chars)

    return {
        'run_id': run_id,
        'condition': condition_name,
        'lambda': lam,
        'best_qg': final_qg,
        'best_markov': final_markov,
        'best_combined': best_combined,
        'plaintext': pt,
        'keystream': ''.join(az_chr(v) for v in best_ks),
        'row_pairs': row_pairs,
        'ap_count': ap_count,
        'distinct': distinct,
        'bean_violations': bean_ineq_violations(best_ks),
    }


# ── Main ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    N_RESTARTS_PER_CONDITION = 150
    N_STEPS = 750_000
    N_WORKERS = min(cpu_count(), 28)

    CONDITIONS = [
        ("A_no_prior",   0.00),
        ("B_mild",       0.05),
        ("C_moderate",   0.15),
        ("D_strong",     0.30),
    ]

    print("=" * 78)
    print("ROW-MARKOV REGULARIZED KEYSTREAM SA")
    print("=" * 78)
    print(f"\nConditions: {len(CONDITIONS)}")
    for name, lam in CONDITIONS:
        print(f"  {name}: λ={lam}")
    print(f"\nRestarts per condition: {N_RESTARTS_PER_CONDITION}")
    print(f"Steps per restart: {N_STEPS:,}")
    print(f"Workers: {N_WORKERS}")
    print(f"Known keystream values: {len(KNOWN_73)}")
    print(f"Unknown positions: {N_UNKNOWN}")
    print(f"Bean equalities (CT73): {len(BEAN_EQ_73)}")
    print(f"Bean inequalities (CT73): {len(BEAN_INEQ_73)}")

    # Show empirical row transition matrix
    print(f"\nEmpirical row transition counts (from 24 known values):")
    print(f"     {'  '.join(f'r{c}' for c in range(N_ROWS))}")
    for r in range(N_ROWS):
        counts = '  '.join(f'{TRANS_COUNTS[r][c]:2d}' for c in range(N_ROWS))
        print(f"  r{r}: {counts}  (Σ={sum(TRANS_COUNTS[r])})")
    same = sum(TRANS_COUNTS[r][r] for r in range(N_ROWS))
    print(f"  Same-row transitions: {same}/23 = {same/23:.1%} (expected ~19%)")

    print(f"\nStarting SA...")
    start_time = datetime.now()

    # Build work items for all conditions
    work_items = []
    for cond_name, lam in CONDITIONS:
        for i in range(N_RESTARTS_PER_CONDITION):
            seed = hash((cond_name, i, 20260321)) & 0xFFFFFFFF
            work_items.append((
                f"{cond_name}_{i:03d}",
                N_STEPS,
                seed,
                lam,
                cond_name,
            ))

    # Shuffle for fair load balancing
    random.shuffle(work_items)

    all_results = []
    condition_bests = {name: None for name, _ in CONDITIONS}

    with Pool(N_WORKERS) as pool:
        for result in pool.imap_unordered(sa_run, work_items):
            all_results.append(result)
            cond = result['condition']
            if (condition_bests[cond] is None or
                    result['best_qg'] > condition_bests[cond]['best_qg']):
                condition_bests[cond] = result

            if len(all_results) % 50 == 0:
                elapsed = (datetime.now() - start_time).total_seconds()
                total = len(work_items)
                best_any = max(r['best_qg'] for r in all_results)
                print(f"  {len(all_results)}/{total} done, "
                      f"best QG={best_any:.4f}/char, "
                      f"{elapsed:.0f}s elapsed")

    elapsed = (datetime.now() - start_time).total_seconds()

    # ── Analysis ──────────────────────────────────────────────────────────
    print(f"\n{'='*78}")
    print(f"RESULTS ({elapsed:.0f}s total, {len(all_results)} restarts)")
    print(f"{'='*78}")

    # Per-condition statistics
    condition_results = {name: [] for name, _ in CONDITIONS}
    for r in all_results:
        condition_results[r['condition']].append(r)

    summary = {}
    for cond_name, lam in CONDITIONS:
        results = condition_results[cond_name]
        qg_scores = [r['best_qg'] for r in results]
        markov_scores = [r['best_markov'] for r in results]
        row_pairs = [r['row_pairs'] for r in results]
        ap_counts = [r['ap_count'] for r in results]
        distinct_vals = [r['distinct'] for r in results]
        bean_v = [r['bean_violations'] for r in results]

        qg_mean = sum(qg_scores) / len(qg_scores)
        qg_best = max(qg_scores)
        qg_std = (sum((x - qg_mean)**2 for x in qg_scores) / len(qg_scores))**0.5
        rp_mean = sum(row_pairs) / len(row_pairs)
        ap_mean = sum(ap_counts) / len(ap_counts)
        dist_mean = sum(distinct_vals) / len(distinct_vals)

        english_hits = sum(1 for s in qg_scores if s >= -4.0)

        summary[cond_name] = {
            "lambda": lam,
            "n_restarts": len(results),
            "qg_best": qg_best,
            "qg_mean": qg_mean,
            "qg_std": qg_std,
            "qg_median": sorted(qg_scores)[len(qg_scores)//2],
            "english_hits": english_hits,
            "row_pairs_mean": rp_mean,
            "ap_mean": ap_mean,
            "distinct_mean": dist_mean,
            "bean_violations_total": sum(bean_v),
        }

        print(f"\n── Condition {cond_name} (λ={lam}) ──")
        print(f"   QG best:   {qg_best:.4f}/char  (threshold: -4.0)")
        print(f"   QG mean:   {qg_mean:.4f} ± {qg_std:.4f}")
        print(f"   QG median: {sorted(qg_scores)[len(qg_scores)//2]:.4f}")
        print(f"   English hits (≥-4.0): {english_hits}/{len(results)}")
        print(f"   Row pairs mean: {rp_mean:.1f}/72 (random ~14)")
        print(f"   AP mean: {ap_mean:.1f}/73")
        print(f"   Distinct mean: {dist_mean:.1f}/26")
        print(f"   Bean violations: {sum(bean_v)}")

    # ── Cross-condition comparison ────────────────────────────────────────
    print(f"\n{'='*78}")
    print("CROSS-CONDITION COMPARISON")
    print(f"{'='*78}")
    print(f"\n{'Condition':<18} {'λ':>5} {'Best QG':>10} {'Mean QG':>10} "
          f"{'≥-4.0':>6} {'RowPairs':>9} {'AP':>6}")
    print("-" * 70)
    for cond_name, lam in CONDITIONS:
        s = summary[cond_name]
        print(f"  {cond_name:<16} {lam:>5.2f} {s['qg_best']:>10.4f} "
              f"{s['qg_mean']:>10.4f} {s['english_hits']:>6} "
              f"{s['row_pairs_mean']:>9.1f} {s['ap_mean']:>6.1f}")

    # ── Mann-Whitney U test: A vs each other condition ────────────────────
    print(f"\n── Statistical comparison (A_no_prior vs others) ──")
    baseline_qg = sorted(r['best_qg'] for r in condition_results['A_no_prior'])
    for cond_name, lam in CONDITIONS[1:]:
        other_qg = sorted(r['best_qg'] for r in condition_results[cond_name])

        # Simple rank-sum comparison (approximate Mann-Whitney)
        combined = [(v, 'A') for v in baseline_qg] + [(v, cond_name) for v in other_qg]
        combined.sort()
        rank_sum_other = sum(i + 1 for i, (v, grp) in enumerate(combined) if grp == cond_name)
        n1, n2 = len(baseline_qg), len(other_qg)
        expected_rank = n2 * (n1 + n2 + 1) / 2
        std_rank = (n1 * n2 * (n1 + n2 + 1) / 12) ** 0.5
        z = (rank_sum_other - expected_rank) / std_rank if std_rank > 0 else 0

        # Direction: positive z means other has higher ranks (better scores)
        direction = "BETTER" if z > 0 else "WORSE" if z < 0 else "SAME"
        print(f"  {cond_name} vs A_no_prior: Z={z:+.3f} ({direction})")

    # ── Top 5 overall ─────────────────────────────────────────────────────
    print(f"\n{'='*78}")
    print("TOP 5 OVERALL (by English quality)")
    print(f"{'='*78}")
    all_results.sort(key=lambda r: -r['best_qg'])
    for i, r in enumerate(all_results[:5]):
        pt = r['plaintext']
        print(f"\n  #{i+1} [{r['condition']}] QG={r['best_qg']:.4f}/char "
              f"RP={r['row_pairs']} AP={r['ap_count']} D={r['distinct']}")
        # Show with crib markers (approximate positions in 73-char space)
        ene_start = POS_TO_IDX.get(21, 13)
        ene_end = POS_TO_IDX.get(33, 25) + 1
        bcl_start = POS_TO_IDX.get(63, 47)
        bcl_end = POS_TO_IDX.get(73, 57) + 1
        print(f"    ...{pt[ene_start:ene_end]}...{pt[bcl_start:bcl_end]}...")
        print(f"    Full: {pt}")

    # ── Save ──────────────────────────────────────────────────────────────
    outfile = os.path.join(_ROOT, "results", "e_row_markov_sa.json")
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    output = {
        "experiment": "e_row_markov_sa",
        "timestamp": datetime.now().isoformat(),
        "description": "Row-Markov regularized keystream SA: 4 conditions testing "
                       "whether Polybius row structure helps decode K4",
        "design": {
            "conditions": {name: lam for name, lam in CONDITIONS},
            "restarts_per_condition": N_RESTARTS_PER_CONDITION,
            "steps_per_restart": N_STEPS,
            "workers": N_WORKERS,
            "known_positions": len(KNOWN_73),
            "unknown_positions": N_UNKNOWN,
            "bean_eq_73": len(BEAN_EQ_73),
            "bean_ineq_73": len(BEAN_INEQ_73),
            "alphabet": "full 26 (no restriction)",
            "key_difference_from_prior": "Prior test restricted to 12 letters; "
                                          "this allows all 26 with row Markov prior",
        },
        "empirical_markov": {
            "same_row_rate_observed": f"{same}/23 = {same/23:.3f}",
            "same_row_rate_expected": "~0.19",
            "transition_counts": TRANS_COUNTS,
        },
        "summary": summary,
        "top_10": [
            {
                "rank": i + 1,
                "condition": r['condition'],
                "lambda": r['lambda'],
                "qg_per_char": r['best_qg'],
                "markov_excess": r['best_markov'],
                "plaintext": r['plaintext'],
                "keystream": r['keystream'],
                "row_pairs": r['row_pairs'],
                "ap_count": r['ap_count'],
                "distinct": r['distinct'],
                "bean_violations": r['bean_violations'],
            }
            for i, r in enumerate(all_results[:10])
        ],
        "elapsed_seconds": elapsed,
        "verdict": "",  # Will be filled after examining results
    }

    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outfile}")
