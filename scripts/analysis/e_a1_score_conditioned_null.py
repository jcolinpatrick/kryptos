#!/usr/bin/env python3
"""
Cipher:   Score-conditioned null for A1 palette diversity
Family:   analysis
Status:   active

PURPOSE: Definitive matched-null experiment for anomaly A1.
QUESTION: Does the SA discovery process produce unusually low palette
diversity on real K4 compared to null ciphertexts?

Design: Each SA restart is a separate parallel task for maximum throughput.
Results are aggregated per-CT after all restarts complete.
"""

import sys, os, random, math, time, json
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS

# ── Configuration ────────────────────────────────────────────────────────
N_NULL_CTS = 100          # per family
N_RESTARTS = 30           # per CT (sufficient for consensus)
SA_STEPS = 300_000
T0, TF = 0.5, 0.01
SCORE_THRESHOLD = 8
N_NULLS = 24
CONSENSUS_K = 17
N_WORKERS = max(1, cpu_count() - 2)

# ── Cipher (exact copy from f_consensus_null_v1.py) ─────────────────────
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[c] for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63
NON_CRIB = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
NC_SET = frozenset(NON_CRIB)

KW_KA = tuple(KA_IDX[c] for c in "KRYPTOS")
KW_LEN = len(KW_KA)
ENE_KA = tuple(KA_IDX[c] for c in ENE_WORD)
BCL_KA = tuple(KA_IDX[c] for c in BCL_WORD)
N_PT = CT_LEN - N_NULLS

def score_mask(ct_str, null_set):
    ct_inner = [AZ_TO_KA[ord(ct_str[i])-65] for i in range(len(ct_str)) if i not in null_set]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    pt = []
    for i, ci in enumerate(ct_inner):
        ki = KW_KA[i] if i < KW_LEN else pt[i - KW_LEN]
        pt.append((ci - ki) % 26)
    hits = 0
    for j in range(13):
        pos = ene_s + j
        if pos < len(pt) and pt[pos] == ENE_KA[j]: hits += 1
    for j in range(11):
        pos = bcl_s + j
        if pos < len(pt) and pt[pos] == BCL_KA[j]: hits += 1
    return hits

def sa_one_restart(ct_str, seed, non_crib=NON_CRIB):
    rng = random.Random(seed)
    nc_set = frozenset(non_crib)
    null_set = set(rng.sample(non_crib, N_NULLS))
    non_null = nc_set - null_set
    score = score_mask(ct_str, frozenset(null_set))
    best_sc = score; best_null = frozenset(null_set)
    for step in range(SA_STEPS):
        T = T0 * (TF / T0) ** (step / SA_STEPS)
        cands = list(null_set); nn = list(non_null)
        if not cands or not nn: break
        out = rng.choice(cands); into = rng.choice(nn)
        null_set = (null_set - {out}) | {into}
        non_null = (non_null - {into}) | {out}
        new_sc = score_mask(ct_str, frozenset(null_set))
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / T):
            score = new_sc
            if score > best_sc: best_sc = score; best_null = frozenset(null_set)
        else:
            null_set = (null_set - {into}) | {out}
            non_null = (non_null - {out}) | {into}
    return best_sc, sorted(best_null)

# ── Worker: one SA restart ───────────────────────────────────────────────
def _worker(args):
    ct_key, ct_str, seed = args
    sc, mask = sa_one_restart(ct_str, seed)
    return ct_key, sc, mask

# ── Null generators ──────────────────────────────────────────────────────
def make_letter_shuffled(rng):
    ct_list = list(CT)
    nc_letters = [ct_list[i] for i in NON_CRIB]
    rng.shuffle(nc_letters)
    for idx, pos in enumerate(NON_CRIB):
        ct_list[pos] = nc_letters[idx]
    return ''.join(ct_list)

def make_block_shuffled(rng, block_size=7):
    ct_list = list(CT)
    blocks = []; cur = []
    for pos in NON_CRIB:
        cur.append(pos)
        if len(cur) == block_size: blocks.append(cur); cur = []
    if cur: blocks.append(cur)
    rng.shuffle(blocks)
    shuffled = []
    for b in blocks:
        for p in b: shuffled.append(CT[p])
    for idx, pos in enumerate(NON_CRIB):
        ct_list[pos] = shuffled[idx]
    return ''.join(ct_list)

def make_crib_planted(rng):
    ct_list = [chr(rng.randint(65, 90)) for _ in range(CT_LEN)]
    for pos in CRIB_POSITIONS:
        ct_list[pos] = CT[pos]
    return ''.join(ct_list)

# ── Consensus builder (from restart results) ─────────────────────────────
def build_consensus(ct_str, restart_results):
    qualifying = [(sc, mask) for sc, mask in restart_results if sc >= SCORE_THRESHOLD]
    all_scores = [sc for sc, _ in restart_results]
    best_score = max(all_scores) if all_scores else 0

    if not qualifying:
        min_d_any = min(len(set(ct_str[p] for p in mask)) for _, mask in restart_results) if restart_results else 26
        return {
            'best_score': best_score, 'n_qualifying': 0,
            'consensus_positions': [], 'consensus_distinct': 26,
            'consensus_letters': '', 'mean_score': sum(all_scores)/max(1,len(all_scores)),
            'score_distribution': dict(Counter(int(s) for s in all_scores)),
            'min_distinct_qualifying': 26, 'min_distinct_any': min_d_any,
            'position_stability': 0.0,
        }

    pos_freq = Counter()
    for sc, mask in qualifying:
        for p in mask: pos_freq[p] += 1
    consensus = [p for p, _ in pos_freq.most_common(CONSENSUS_K)]
    letters = [ct_str[p] for p in consensus]
    cd = len(set(letters))
    mdq = min(len(set(ct_str[p] for p in mask)) for _, mask in qualifying)
    mda = min(len(set(ct_str[p] for p in mask)) for _, mask in restart_results)

    masks_sets = [set(mask) for _, mask in qualifying]
    jaccards = []
    for i in range(min(len(masks_sets), 50)):
        for j in range(i+1, min(len(masks_sets), 50)):
            inter = len(masks_sets[i] & masks_sets[j])
            union = len(masks_sets[i] | masks_sets[j])
            if union > 0: jaccards.append(inter / union)
    stab = sum(jaccards) / len(jaccards) if jaccards else 0.0

    return {
        'best_score': best_score, 'n_qualifying': len(qualifying),
        'consensus_positions': consensus, 'consensus_distinct': cd,
        'consensus_letters': ''.join(sorted(set(letters))),
        'mean_score': sum(all_scores) / len(all_scores),
        'score_distribution': dict(Counter(int(s) for s in all_scores)),
        'min_distinct_qualifying': mdq, 'min_distinct_any': mda,
        'position_stability': round(stab, 4),
    }

# ── Main ─────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("A1 SCORE-CONDITIONED NULL EXPERIMENT")
    print("=" * 70)
    print(f"Config: {N_NULL_CTS} null CTs/family × 3 families + 1 K4")
    print(f"        {N_RESTARTS} SA restarts/CT × {SA_STEPS:,} steps")
    print(f"        {N_WORKERS} workers, threshold={SCORE_THRESHOLD}")
    print(f"Total SA runs: {(N_NULL_CTS * 3 + 1) * N_RESTARTS:,}")
    print()
    print("PRE-REGISTERED DECISION RULE:")
    print("  SURVIVES: K4 consensus_distinct < 2.5th percentile of null")
    print("  FAILS:    K4 consensus_distinct >= 5th percentile of null")
    print("  INCONCLUSIVE: between, or <30 qualifying nulls")
    print()

    t0 = time.time()
    rng = random.Random(42)

    # Generate all CTs and restart seeds
    cts = {}  # key -> (ct_str, family)
    cts['k4'] = (CT, 'real_k4')

    for family, gen in [('letter_shuffled', make_letter_shuffled),
                        ('block_shuffled', make_block_shuffled),
                        ('crib_planted', make_crib_planted)]:
        for i in range(N_NULL_CTS):
            key = f'{family}_{i}'
            fr = random.Random(rng.randint(0, 2**32))
            cts[key] = (gen(fr), family)

    # Build all SA tasks: (ct_key, ct_str, seed)
    tasks = []
    for ct_key, (ct_str, _) in cts.items():
        for r in range(N_RESTARTS):
            seed = rng.randint(0, 2**31)
            tasks.append((ct_key, ct_str, seed))

    print(f"Generated {len(tasks):,} SA restart tasks for {len(cts)} CTs")
    print(f"Estimated runtime: {len(tasks) * 10.4 / N_WORKERS / 60:.0f} min")
    print()

    # Run all in parallel
    print(f"Running {len(tasks):,} SA restarts across {N_WORKERS} workers...")
    restart_data = {}  # ct_key -> [(score, mask), ...]
    for k in cts: restart_data[k] = []

    with Pool(N_WORKERS) as pool:
        for i, (ct_key, sc, mask) in enumerate(pool.imap_unordered(_worker, tasks)):
            restart_data[ct_key].append((sc, mask))
            done = i + 1
            if done % 200 == 0 or done == len(tasks):
                elapsed = time.time() - t0
                rate = done / elapsed
                eta = (len(tasks) - done) / rate
                print(f"\r  {done:,}/{len(tasks):,} ({100*done/len(tasks):.1f}%) "
                      f"rate={rate:.0f}/s ETA={eta/60:.1f}min", end='', flush=True)

    t_total = time.time() - t0
    print(f"\n  Done in {t_total/60:.1f} min ({len(tasks)/t_total:.1f} restarts/s)")
    print()

    # Build consensus for each CT
    print("Building consensus for each CT...")
    consensus_results = {}
    for ct_key, (ct_str, family) in cts.items():
        res = build_consensus(ct_str, restart_data[ct_key])
        res['family'] = family
        res['ct_key'] = ct_key
        consensus_results[ct_key] = res

    k4 = consensus_results['k4']

    # ── Report ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"\nK4:")
    print(f"  Best score:         {k4['best_score']}")
    print(f"  Qualifying masks:   {k4['n_qualifying']}")
    print(f"  Consensus distinct: {k4['consensus_distinct']}")
    print(f"  Consensus letters:  {k4['consensus_letters']}")
    print(f"  Consensus pos:      {k4['consensus_positions']}")
    print(f"  Min distinct (qual):{k4['min_distinct_qualifying']}")
    print(f"  Min distinct (any): {k4['min_distinct_any']}")
    print(f"  Position stability: {k4['position_stability']}")
    print()

    k4_cd = k4['consensus_distinct']
    k4_bs = k4['best_score']
    k4_mdq = k4['min_distinct_qualifying']
    k4_mda = k4['min_distinct_any']

    verdicts = {}
    for family in ['letter_shuffled', 'block_shuffled', 'crib_planted']:
        fam_res = [v for k, v in consensus_results.items() if v['family'] == family]
        valid = [r for r in fam_res if r['n_qualifying'] > 0]

        print(f"\n── {family} ({len(fam_res)} total, {len(valid)} qualifying) ──")

        if len(valid) < 10:
            verdicts[family] = 'INCONCLUSIVE'
            print(f"  INCONCLUSIVE: only {len(valid)} qualifying nulls")
            continue

        cd_list = sorted([r['consensus_distinct'] for r in valid])
        mdq_list = sorted([r['min_distinct_qualifying'] for r in valid])
        mda_list = sorted([r['min_distinct_any'] for r in fam_res])
        bs_list = [r['best_score'] for r in fam_res]

        mean_cd = sum(cd_list) / len(cd_list)
        p2_5 = cd_list[max(0, int(len(cd_list) * 0.025))]
        p5 = cd_list[max(0, int(len(cd_list) * 0.05))]
        p50 = cd_list[len(cd_list) // 2]

        n_le = sum(1 for d in cd_list if d <= k4_cd)
        p_val = (n_le + 1) / (len(cd_list) + 1)

        print(f"  Consensus distinct: mean={mean_cd:.1f} median={p50} "
              f"2.5th={p2_5} 5th={p5}")
        print(f"  K4={k4_cd}  p-value={n_le}/{len(cd_list)} = {p_val:.4f}")

        dist = Counter(cd_list)
        for d in sorted(dist):
            bar = '#' * min(40, dist[d] * 40 // max(dist.values()))
            tag = " ◄K4" if d == k4_cd else ""
            print(f"    {d:2d}: {dist[d]:3d} ({100*dist[d]/len(cd_list):5.1f}%) {bar}{tag}")

        # Score-conditioned
        sm = [r for r in valid if r['best_score'] >= k4_bs - 1]
        if sm:
            sm_cd = [r['consensus_distinct'] for r in sm]
            n_le_sm = sum(1 for d in sm_cd if d <= k4_cd)
            p_sm = (n_le_sm + 1) / (len(sm_cd) + 1)
            print(f"  Score-matched (score>={k4_bs-1}): {len(sm)} CTs")
            print(f"    mean_cd={sum(sm_cd)/len(sm_cd):.1f} p={n_le_sm}/{len(sm_cd)}={p_sm:.4f}")

        # Min distinct any mask
        n_le_mda = sum(1 for d in mda_list if d <= k4_mda)
        p_mda = (n_le_mda + 1) / (len(mda_list) + 1)
        print(f"  Min distinct (any mask): K4={k4_mda} null_mean={sum(mda_list)/len(mda_list):.1f} "
              f"p={n_le_mda}/{len(mda_list)}={p_mda:.4f}")

        # Best score distribution
        bs_dist = Counter(int(s) for s in bs_list)
        print(f"  Best scores: " + " ".join(f"{s}:{c}" for s, c in sorted(bs_dist.items())))

        # Position stability
        null_stab = [r['position_stability'] for r in valid]
        print(f"  Stability: K4={k4['position_stability']:.4f} "
              f"null_mean={sum(null_stab)/len(null_stab):.4f}")

        # Verdict
        if k4_cd <= p2_5:
            verdicts[family] = 'SURVIVES'
        elif k4_cd >= p5:
            verdicts[family] = 'FAILS'
        else:
            verdicts[family] = 'INCONCLUSIVE'
        print(f"  VERDICT: {verdicts[family]}")

    # Overall
    print("\n" + "=" * 70)
    print("OVERALL")
    print("=" * 70)
    for f, v in verdicts.items():
        print(f"  {f}: {v}")

    if all(v == 'SURVIVES' for v in verdicts.values()):
        overall = 'SURVIVES'
    elif any(v == 'FAILS' for v in verdicts.values()):
        overall = 'FAILS'
    else:
        overall = 'INCONCLUSIVE'

    print(f"\n  A1 {'survives' if overall == 'SURVIVES' else 'fails' if overall == 'FAILS' else 'remains inconclusive'} under the matched null.")
    print()

    # ── Save ─────────────────────────────────────────────────────────────
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'config': {
            'n_null_cts': N_NULL_CTS, 'n_restarts': N_RESTARTS,
            'sa_steps': SA_STEPS, 'T0': T0, 'Tf': TF,
            'threshold': SCORE_THRESHOLD, 'consensus_k': CONSENSUS_K,
            'workers': N_WORKERS, 'elapsed_min': round(t_total/60, 1),
        },
        'decision_rule': {
            'SURVIVES': 'K4 consensus_distinct < 2.5th pctile all families',
            'FAILS': 'K4 consensus_distinct >= 5th pctile any family',
        },
        'k4': {k: v for k, v in k4.items() if k != 'score_distribution'},
        'family_verdicts': verdicts,
        'overall_verdict': overall,
        'null_per_run': [
            {
                'key': k, 'family': v['family'],
                'best_score': v['best_score'], 'n_qualifying': v['n_qualifying'],
                'consensus_distinct': v['consensus_distinct'],
                'min_distinct_qualifying': v['min_distinct_qualifying'],
                'min_distinct_any': v['min_distinct_any'],
                'position_stability': v['position_stability'],
                'mean_score': round(v['mean_score'], 2),
            }
            for k, v in consensus_results.items() if v['family'] != 'real_k4'
        ],
    }
    outpath = os.path.join(_ROOT, 'results', 'a1_score_conditioned_null.json')
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Saved to {outpath}")

if __name__ == '__main__':
    main()
