#!/usr/bin/env python3
"""CIA cryptonym digraph-constrained null mask search for K4.

Cipher:  Beaufort autokey (keyword DEFECTOR) + col7 transposition + 24-null mask
Family:  analysis
Status:  active
Keyspace: ~3M (SA over null masks with digraph reward + baseline)
Last run: never
Best score: n/a

IDEA: If K4 plaintext is a CIA cable about Berlin/Cold War, it likely contains
cryptonyms with known two-letter digraph prefixes (e.g., AE=Soviet Union,
DT=East Germany, CA=West Germany). These give additional known-plaintext
constraints beyond the 24 crib positions.

Phase 0: Baseline -- crib-only SA (100 restarts), record digraph frequency
Phase 1: SA with digraph reward bonus (200 restarts)
Phase 2: Analytical constraint propagation
Phase 3: Deep SA with fixed digraph constraints at viable positions (30 restarts/case)
Phase 4: W-delimiter segment analysis
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, random, math, time, json
from collections import defaultdict

sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97     = CT
N        = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START= 21; BCL_START = 63
NON_CRIB = sorted(i for i in range(N) if i not in CRIB_POSITIONS)
NC_SET   = frozenset(NON_CRIB)
DIGRAPH_SET = frozenset(["AE","DT","CA","BG","GT","CK","KU","HT","OD","ZR","LC","QR","PB","MK","AM"])
DIGRAPHS = sorted(DIGRAPH_SET)

CONSENSUS_17 = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
SEED_15_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])

def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start+width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0]*len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))

def autokey_decrypt_az(ct_list, kw, beau=True):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct_list):
        ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e = sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j < len(pt) and pt[ene_s+j]==c)
    b = sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j < len(pt) and pt[bcl_s+j]==c)
    return e+b, e, b

def find_digraphs(pt):
    hits = []
    for i in range(len(pt)-1):
        pair = pt[i:i+2]
        if pair in DIGRAPH_SET:
            hits.append((pair, i))
    return hits

def eval_mask(null_set, perm=PERM_COL7, kw='DEFECTOR', beau=True):
    null_set = frozenset(null_set)
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az  = [ord(c)-65 for c in ct73_raw]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    ct73_t = [ct73_az[perm[i]] for i in range(N_PT)]
    pt = autokey_decrypt_az(ct73_t, kw, beau)
    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    dg_hits = find_digraphs(pt)
    return total, e, b, pt, dg_hits, ene_s, bcl_s

def sa_run(n_restarts, n_steps, score_fn, seed_consensus_frac=0.1, rng_offset=0):
    """Generic SA runner. score_fn(null_set) -> (score, crib_score)."""
    results = []
    NC_LIST = sorted(NC_SET)
    for restart in range(n_restarts):
        rng = random.Random((restart + rng_offset) * 37 + 7)
        if restart % int(1/seed_consensus_frac) == 0 if seed_consensus_frac > 0 else False:
            varying_pool = sorted(NC_SET - CONSENSUS_17)
            null_set = set(CONSENSUS_17) | set(rng.sample(varying_pool, N_NULLS - len(CONSENSUS_17)))
        else:
            null_set = set(rng.sample(NC_LIST, N_NULLS))
        non_null = NC_SET - null_set
        sc, crib_sc = score_fn(frozenset(null_set))
        best_sc = sc; best_null = frozenset(null_set); best_crib = crib_sc
        T0 = 0.5; Tf = 0.005
        for step in range(n_steps):
            T = T0 * (Tf/T0) ** (step/n_steps)
            out = rng.choice(list(null_set))
            into = rng.choice(list(non_null))
            null_set = (null_set - {out}) | {into}
            non_null = (non_null - {into}) | {out}
            new_sc, new_crib = score_fn(frozenset(null_set))
            delta = new_sc - sc
            if delta > 0 or rng.random() < math.exp(delta/T):
                sc = new_sc; crib_sc = new_crib
                if sc > best_sc:
                    best_sc = sc; best_null = frozenset(null_set); best_crib = new_crib
            else:
                null_set = (null_set - {into}) | {out}
                non_null = (non_null - {out}) | {into}
        total, e, b, pt, dg_hits, ene_s, bcl_s = eval_mask(best_null)
        distinct_dg = len(set(d for d, p in dg_hits))
        results.append({
            'restart': restart, 'crib_score': total, 'ene': e, 'bcl': b,
            'digraph_count': distinct_dg,
            'digraphs': [(d,p) for d,p in dg_hits],
            'pt': pt, 'mask': sorted(best_null),
        })
    return results

# ============================================================================
# PHASE 0: BASELINE (crib-only SA)
# ============================================================================
def run_phase0(n_restarts=100, n_steps=60000):
    print("="*70)
    print(f"PHASE 0: BASELINE — crib-only SA ({n_restarts} x {n_steps})")
    print("  Purpose: measure digraph frequency in crib-optimized masks")
    print("="*70)
    t0 = time.time()
    def score_crib_only(ns):
        total, e, b, pt, dg, ene_s, bcl_s = eval_mask(ns)
        return float(total), total
    results = sa_run(n_restarts, n_steps, score_crib_only, seed_consensus_frac=0.1)
    elapsed = time.time() - t0
    # Analysis
    crib_dist = defaultdict(int)
    dg_by_crib = defaultdict(list)
    all_dg_counts = []
    for r in results:
        crib_dist[r['crib_score']] += 1
        dg_by_crib[r['crib_score']].append(r['digraph_count'])
        all_dg_counts.append(r['digraph_count'])
    avg_dg = sum(all_dg_counts)/len(all_dg_counts) if all_dg_counts else 0
    print(f"\n  Baseline complete: {elapsed:.1f}s")
    print(f"  Crib score distribution: {dict(sorted(crib_dist.items()))}")
    print(f"  Average digraph count (crib-optimized): {avg_dg:.2f}")
    for cs in sorted(dg_by_crib.keys(), reverse=True):
        dgs = dg_by_crib[cs]
        if dgs:
            avg = sum(dgs)/len(dgs)
            print(f"    crib={cs}: n={len(dgs)}, avg digraphs={avg:.2f}")
    # Best crib-score results
    results.sort(key=lambda x: -x['crib_score'])
    print(f"\n  TOP 10 by crib score:")
    for r in results[:10]:
        dg_str = ','.join(f'{d}@{p}' for d,p in r['digraphs']) if r['digraphs'] else 'none'
        print(f"    crib={r['crib_score']}/24 (e={r['ene']}/13 b={r['bcl']}/11) dg={r['digraph_count']} [{dg_str}]")
    return results, avg_dg

# ============================================================================
# PHASE 1: SA with digraph reward
# ============================================================================
def run_phase1(n_restarts=200, n_steps=60000, digraph_weight=2.0):
    print("\n" + "="*70)
    print(f"PHASE 1: DIGRAPH-REWARD SA ({n_restarts} x {n_steps}, weight={digraph_weight})")
    print("="*70)
    t0 = time.time()
    def score_with_dg(ns):
        total, e, b, pt, dg_hits, ene_s, bcl_s = eval_mask(ns)
        distinct_dg = len(set(d for d, p in dg_hits))
        combined = total + digraph_weight * distinct_dg
        return combined, total
    results = sa_run(n_restarts, n_steps, score_with_dg, seed_consensus_frac=0.1, rng_offset=1000)
    elapsed = time.time() - t0
    # Analysis
    crib_dist = defaultdict(int)
    for r in results:
        crib_dist[r['crib_score']] += 1
    results.sort(key=lambda x: (-r_combined(r, digraph_weight), -x['crib_score']))
    print(f"\n  Phase 1 complete: {elapsed:.1f}s")
    print(f"  Crib score distribution: {dict(sorted(crib_dist.items()))}")
    # Digraph frequency
    dg_freq = defaultdict(int)
    for r in results:
        for dg, pos in r['digraphs']:
            dg_freq[dg] += 1
    print(f"\n  Digraph frequency across all {n_restarts} restarts:")
    for dg in sorted(dg_freq, key=lambda x: -dg_freq[x]):
        print(f"    {dg}: {dg_freq[dg]}")
    # Correlation
    with_dg = [r['crib_score'] for r in results if r['digraph_count'] > 0]
    without_dg = [r['crib_score'] for r in results if r['digraph_count'] == 0]
    if with_dg and without_dg:
        print(f"\n  WITH digraphs: n={len(with_dg)}, avg crib={sum(with_dg)/len(with_dg):.2f}")
        print(f"  WITHOUT digraphs: n={len(without_dg)}, avg crib={sum(without_dg)/len(without_dg):.2f}")
    # Top by crib
    by_crib = sorted(results, key=lambda x: -x['crib_score'])
    print(f"\n  TOP 10 by crib score:")
    for r in by_crib[:10]:
        dg_str = ','.join(f'{d}@{p}' for d,p in r['digraphs']) if r['digraphs'] else 'none'
        print(f"    crib={r['crib_score']}/24 (e={r['ene']}/13 b={r['bcl']}/11) dg={r['digraph_count']} [{dg_str}]")
    # Top by combined
    print(f"\n  TOP 10 by combined score:")
    results.sort(key=lambda x: -(x['crib_score'] + digraph_weight * x['digraph_count']))
    for r in results[:10]:
        combined = r['crib_score'] + digraph_weight * r['digraph_count']
        dg_str = ','.join(f'{d}@{p}' for d,p in r['digraphs']) if r['digraphs'] else 'none'
        print(f"    combined={combined:.0f} crib={r['crib_score']}/24 dg={r['digraph_count']} [{dg_str}]")
    return results

def r_combined(r, w=2.0):
    return r['crib_score'] + w * r['digraph_count']

# ============================================================================
# PHASE 2: Analytical constraint propagation
# ============================================================================
def run_phase2():
    print("\n" + "="*70)
    print("PHASE 2: DIGRAPH CONSTRAINT PROPAGATION")
    print("="*70)

    kw = 'DEFECTOR'
    kw_nums = [ord(c)-65 for c in kw]
    L = len(kw)  # 8
    viable = []

    # Mask-independent: positions 0-6 where both chars use keyword (not autokey)
    print("\n--- Positions 0-6 (keyword-determined, mask-independent) ---")
    for dg in DIGRAPHS:
        d0, d1 = ord(dg[0])-65, ord(dg[1])-65
        for p in range(7):  # p+1 <= 7 < L=8
            required_ct73_t_p   = (kw_nums[p] - d0) % 26
            required_ct73_t_p1  = (kw_nums[p+1] - d1) % 26
            ct73_pos_p  = PERM_COL7[p]
            ct73_pos_p1 = PERM_COL7[p+1]
            req_letter_p  = chr(required_ct73_t_p + 65)
            req_letter_p1 = chr(required_ct73_t_p1 + 65)
            # Check if CT97 has these letters in the valid position range
            candidates_p = [ct73_pos_p + off for off in range(25)
                          if ct73_pos_p + off < N and CT97[ct73_pos_p + off] == req_letter_p]
            candidates_p1 = [ct73_pos_p1 + off for off in range(25)
                           if ct73_pos_p1 + off < N and CT97[ct73_pos_p1 + off] == req_letter_p1]
            if candidates_p and candidates_p1:
                viable.append({
                    'digraph': dg, 'pt_pos': p,
                    'required': (req_letter_p, req_letter_p1),
                    'ct73_idx': (ct73_pos_p, ct73_pos_p1),
                    'ct97_candidates': (candidates_p, candidates_p1),
                })

    n_eliminated = 15*7 - len(viable)
    print(f"  {len(viable)} viable / {15*7} possible = {n_eliminated} ELIMINATED analytically")
    for v in viable:
        print(f"    {v['digraph']} @ pt73[{v['pt_pos']}:{v['pt_pos']+2}]: "
              f"need ct73_t=({v['required'][0]},{v['required'][1]}) "
              f"at ct73 idx ({v['ct73_idx'][0]},{v['ct73_idx'][1]}) "
              f"ct97 candidates: {v['ct97_candidates']}")

    # Check against known 15/24 masks
    known_masks = [
        SEED_15_MASK,
        frozenset([0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,96]),
        frozenset([0,1,2,5,8,12,14,20,36,38,39,43,52,55,58,59,74,75,78,84,85,87,93,96]),
    ]

    print(f"\n--- Digraphs in {len(known_masks)} known 15/24 mask PTs ---")
    mask_results = []
    full_viable = defaultdict(list)
    for mi, mask in enumerate(known_masks):
        total, e, b, pt, dg_hits, ene_s, bcl_s = eval_mask(mask)
        print(f"  Mask {mi} (crib={total}/24): PT={pt[:40]}...")
        for dg, pos in dg_hits:
            print(f"    {dg} @ pt73[{pos}] context='...{pt[max(0,pos-3):pos+5]}...'")
            mask_results.append({'mask_idx': mi, 'digraph': dg, 'pt_pos': pos, 'crib': total})
            full_viable[(dg, pos)].append(mi)

    # Any digraphs shared across ALL masks?
    if full_viable:
        sorted_v = sorted(full_viable.items(), key=lambda x: -len(x[1]))
        print(f"\n  {len(sorted_v)} distinct (digraph, position) pairs found")
        shared = [(k,v) for k,v in sorted_v if len(v) > 1]
        if shared:
            print(f"  SHARED across multiple masks:")
            for (dg, pos), mask_ids in shared:
                print(f"    {dg} @ pt73[{pos}]: in masks {mask_ids}")
        else:
            print(f"  NO digraph appears at the same position in multiple masks")

    return viable, mask_results, full_viable

# ============================================================================
# PHASE 3: Deep SA with fixed digraph constraints
# ============================================================================
def run_phase3(phase2_results, n_restarts=30, n_steps=60000):
    viable_kw, mask_results, full_viable = phase2_results

    # Build test cases from Phase 2 results + systematic positions
    test_cases = []
    # From keyword-determined viable positions
    for v in viable_kw[:30]:  # limit
        test_cases.append((v['digraph'], v['pt_pos'], 'keyword_viable'))
    # From mask-viable positions
    for (dg, pos), mask_ids in sorted(full_viable.items(), key=lambda x: -len(x[1])):
        test_cases.append((dg, pos, f'in_{len(mask_ids)}_masks'))
    # Systematic: top 5 digraphs at key positions
    for dg in ['AE','DT','CA','CK','KU']:
        for pos in [3, 8, 15, 35, 45, 55]:
            test_cases.append((dg, pos, 'systematic'))

    # Deduplicate
    seen = set()
    unique_cases = []
    for dg, pos, src in test_cases:
        if (dg, pos) not in seen:
            seen.add((dg, pos))
            unique_cases.append((dg, pos, src))
    unique_cases = unique_cases[:60]

    print("\n" + "="*70)
    print(f"PHASE 3: DEEP SA WITH DIGRAPH CONSTRAINTS ({len(unique_cases)} cases, {n_restarts} restarts)")
    print("="*70)
    t0 = time.time()
    results = []

    for ci, (dg, pt_pos, source) in enumerate(unique_cases):
        best_total = 0
        best_result = None
        for restart in range(n_restarts):
            rng = random.Random(ci * 1000 + restart * 41 + 13)
            NC_LIST = sorted(NC_SET)
            if restart % 5 == 0:
                varying_pool = sorted(NC_SET - CONSENSUS_17)
                null_set = set(CONSENSUS_17) | set(rng.sample(varying_pool, N_NULLS - len(CONSENSUS_17)))
            else:
                null_set = set(rng.sample(NC_LIST, N_NULLS))
            non_null = NC_SET - null_set

            def score_fn(ns, _dg=dg, _pos=pt_pos):
                total, e, b, pt, dg_hits, ene_s, bcl_s = eval_mask(ns)
                bonus = 0
                if _pos + 1 < len(pt):
                    if pt[_pos] == _dg[0]: bonus += 3.0
                    if pt[_pos+1] == _dg[1]: bonus += 3.0
                return total + bonus, total

            sc, crib_sc = score_fn(frozenset(null_set))
            best_sc = sc; best_null = frozenset(null_set)
            T0_sa = 0.4; Tf_sa = 0.008
            for step in range(n_steps):
                T = T0_sa * (Tf_sa/T0_sa) ** (step/n_steps)
                out = rng.choice(list(null_set))
                into = rng.choice(list(non_null))
                null_set = (null_set - {out}) | {into}
                non_null = (non_null - {into}) | {out}
                new_sc, new_crib = score_fn(frozenset(null_set))
                delta = new_sc - sc
                if delta > 0 or rng.random() < math.exp(delta/T):
                    sc = new_sc
                    if sc > best_sc: best_sc = sc; best_null = frozenset(null_set)
                else:
                    null_set = (null_set - {into}) | {out}
                    non_null = (non_null - {out}) | {into}

            total, e, b, pt, dg_hits, ene_s, bcl_s = eval_mask(best_null)
            if total > best_total:
                best_total = total
                best_result = {
                    'digraph': dg, 'pt_pos': pt_pos, 'source': source,
                    'crib_score': total, 'ene': e, 'bcl': b,
                    'digraphs_found': [(d,p) for d,p in dg_hits],
                    'target_match': pt[pt_pos:pt_pos+2] == dg if pt_pos+1 < len(pt) else False,
                    'pt': pt, 'mask': sorted(best_null),
                }

        if best_result:
            results.append(best_result)
            elapsed = time.time() - t0
            if best_total >= 13 or ci % 15 == 0:
                dg_match = 'YES' if best_result['target_match'] else 'no'
                print(f"  [{ci+1}/{len(unique_cases)}] {dg}@{pt_pos} ({source}): "
                      f"crib={best_total}/24 target={dg_match} [{elapsed:.0f}s]")
                if best_total >= 15:
                    print(f"  *** HIGH SCORE {best_total}/24 ***")
                    print(f"  PT = {best_result['pt']}")

    elapsed = time.time() - t0
    results.sort(key=lambda x: -x['crib_score'])
    print(f"\n  Phase 3 complete: {elapsed:.1f}s, {len(results)} cases")
    print(f"\n  TOP 15 by crib score:")
    for r in results[:15]:
        dg_str = ','.join(f'{d}@{p}' for d,p in r['digraphs_found'][:5]) if r['digraphs_found'] else 'none'
        print(f"    {r['digraph']}@{r['pt_pos']} ({r['source']}): crib={r['crib_score']}/24 "
              f"target={'HIT' if r['target_match'] else 'miss'} dgs=[{dg_str}]")

    # Digraph success rates
    dg_success = defaultdict(lambda: {'n': 0, 'match': 0, 'high': 0})
    for r in results:
        dg_success[r['digraph']]['n'] += 1
        if r['target_match']: dg_success[r['digraph']]['match'] += 1
        if r['crib_score'] >= 14 and r['target_match']: dg_success[r['digraph']]['high'] += 1
    print(f"\n  Digraph success rates:")
    for dg in sorted(dg_success, key=lambda x: -dg_success[x]['high']):
        s = dg_success[dg]
        print(f"    {dg}: {s['n']} tested, {s['match']} matched, {s['high']} at crib>=14")
    return results

# ============================================================================
# PHASE 4: W-delimiter segment analysis
# ============================================================================
def run_phase4():
    print("\n" + "="*70)
    print("PHASE 4: W-DELIMITER SEGMENT ANALYSIS")
    print("="*70)

    w_positions = [i for i, c in enumerate(CT97) if c == 'W']
    print(f"  W positions in CT97: {w_positions}")
    boundaries = [-1] + w_positions + [N]
    segments = []
    for i in range(len(boundaries)-1):
        start = boundaries[i] + 1
        end = boundaries[i+1]
        seg = CT97[start:end]
        segments.append((start, end, seg))
        print(f"  Segment {i}: CT97[{start}:{end}] = '{seg}' (len={len(seg)})")

    known_masks = [
        SEED_15_MASK,
        frozenset([0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,96]),
    ]

    segment_results = []
    for mi, mask in enumerate(known_masks):
        total, e, b, pt, dg_hits, ene_s, bcl_s = eval_mask(mask)
        print(f"\n  Mask {mi} (crib={total}/24):")
        print(f"  Full PT: {pt}")

        ct97_to_pt73 = {}
        pt73_idx = 0
        for pos97 in range(N):
            if pos97 not in mask:
                ct97_to_pt73[pos97] = pt73_idx
                pt73_idx += 1

        for wp in w_positions:
            if wp in mask:
                print(f"    W@{wp}: NULL (in mask)")
            else:
                pt73_p = ct97_to_pt73[wp]
                print(f"    W@{wp}: maps to pt73[{pt73_p}] = '{pt[pt73_p]}'")

        print(f"  Digraphs in PT: {[(dg, pos) for dg, pos in dg_hits]}")

        for si, (start, end, seg) in enumerate(segments):
            first_two_pt = []
            for pos97 in range(start, end):
                if pos97 not in mask and pos97 in ct97_to_pt73:
                    first_two_pt.append(ct97_to_pt73[pos97])
                if len(first_two_pt) >= 2:
                    break
            if len(first_two_pt) >= 2:
                p0, p1 = first_two_pt[0], first_two_pt[1]
                if p0 < len(pt) and p1 < len(pt):
                    actual_pair = pt[p0] + pt[p1]
                    is_dg = actual_pair in DIGRAPH_SET
                    segment_results.append({
                        'segment': si, 'ct97_range': f'{start}-{end}',
                        'mask_idx': mi, 'pt_pair': actual_pair,
                        'is_digraph': is_dg,
                    })
                    status = "VALID DIGRAPH!" if is_dg else ""
                    print(f"    Seg {si} start pair: '{actual_pair}' {status}")

    return segment_results

# ============================================================================
# EXPECTED DIGRAPH RATE (analytical)
# ============================================================================
def compute_expected_digraph_rate():
    """How many CIA digraphs would appear in random 73-char uppercase text?"""
    # Each position has P(pair matches any of 15 digraphs) = 15/676
    # 72 positions for digraphs in 73 chars
    # Expected = 72 * 15/676 = 1.598
    expected = 72 * len(DIGRAPHS) / (26*26)
    print(f"\n--- EXPECTED DIGRAPH RATE IN RANDOM TEXT ---")
    print(f"  15 digraphs, 72 candidate positions in 73-char text")
    print(f"  P(any digraph at position i) = 15/676 = {15/676:.4f}")
    print(f"  Expected count: 72 * 15/676 = {expected:.3f}")
    print(f"  Poisson P(>= 3): {1 - sum(expected**k * math.exp(-expected) / math.factorial(k) for k in range(3)):.4f}")
    return expected

# ============================================================================
# MAIN
# ============================================================================
if __name__ == '__main__':
    t_start = time.time()

    print("CIA CRYPTONYM DIGRAPH-CONSTRAINED NULL MASK SEARCH")
    print(f"CT97: {CT97}")
    print(f"Digraphs ({len(DIGRAPHS)}): {DIGRAPHS}")
    print(f"Model: DEFECTOR:AZ_beau + col7 + 24-null mask")
    print(f"Consensus 17 nulls: {sorted(CONSENSUS_17)}")
    print()

    # Verify seed
    total, e, b, pt, dg_hits, ene_s, bcl_s = eval_mask(SEED_15_MASK)
    print(f"Seed verification: {total}/24 (e={e}/13 b={b}/11)")
    print(f"  PT: {pt}")
    print(f"  Digraphs in seed PT: {dg_hits}")
    assert total == 15, f"Seed verification failed: {total}"
    print("  VERIFIED")
    print()

    expected_rate = compute_expected_digraph_rate()
    print()

    # Run all phases
    phase0_results, baseline_avg_dg = run_phase0(n_restarts=100, n_steps=60000)
    phase1_results = run_phase1(n_restarts=200, n_steps=60000, digraph_weight=2.0)
    phase2_results = run_phase2()
    phase3_results = run_phase3(phase2_results, n_restarts=30, n_steps=60000)
    phase4_results = run_phase4()

    total_time = time.time() - t_start

    # ========================================================================
    # Comprehensive analysis
    # ========================================================================
    print("\n" + "="*70)
    print("COMPREHENSIVE ANALYSIS")
    print("="*70)

    # Phase 0 vs Phase 1 comparison
    p0_cribs = [r['crib_score'] for r in phase0_results]
    p0_dgs = [r['digraph_count'] for r in phase0_results]
    p1_cribs = [r['crib_score'] for r in phase1_results]
    p1_dgs = [r['digraph_count'] for r in phase1_results]

    print(f"\n  Phase 0 (crib-only SA): avg crib={sum(p0_cribs)/len(p0_cribs):.2f}, "
          f"avg dg={sum(p0_dgs)/len(p0_dgs):.2f}, max crib={max(p0_cribs)}")
    print(f"  Phase 1 (digraph SA):   avg crib={sum(p1_cribs)/len(p1_cribs):.2f}, "
          f"avg dg={sum(p1_dgs)/len(p1_dgs):.2f}, max crib={max(p1_cribs)}")
    print(f"  Expected random dg:     {expected_rate:.2f}")

    # Key question: do high-crib masks have MORE digraphs than random?
    p0_high = [r for r in phase0_results if r['crib_score'] >= 13]
    p0_high_dg = [r['digraph_count'] for r in p0_high] if p0_high else []
    p0_low = [r for r in phase0_results if r['crib_score'] <= 5]
    p0_low_dg = [r['digraph_count'] for r in p0_low] if p0_low else []
    if p0_high_dg:
        print(f"\n  Baseline high-crib (>=13): n={len(p0_high_dg)}, avg dg={sum(p0_high_dg)/len(p0_high_dg):.2f}")
    if p0_low_dg:
        print(f"  Baseline low-crib (<=5):   n={len(p0_low_dg)}, avg dg={sum(p0_low_dg)/len(p0_low_dg):.2f}")

    # Phase 3 best
    p3_best_crib = max(r['crib_score'] for r in phase3_results) if phase3_results else 0

    best_crib_overall = max(max(p0_cribs), max(p1_cribs), p3_best_crib)

    # ========================================================================
    # Save results
    # ========================================================================
    output = {
        'experiment': 'digraph_constrained_sa',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'model': 'DEFECTOR:AZ_beau + col7 + 24-null mask',
        'digraphs_tested': DIGRAPHS,
        'expected_random_digraph_rate': round(expected_rate, 3),
        'total_time_s': round(total_time, 1),
        'phase0_baseline': {
            'description': 'Crib-only SA baseline',
            'restarts': 100, 'steps': 60000,
            'avg_crib': round(sum(p0_cribs)/len(p0_cribs), 2),
            'max_crib': max(p0_cribs),
            'avg_digraphs': round(sum(p0_dgs)/len(p0_dgs), 2),
            'crib_distribution': dict(sorted(defaultdict(int, {k: sum(1 for r in phase0_results if r['crib_score']==k) for k in set(p0_cribs)}).items())),
            'top_5': [{k: r[k] for k in ['crib_score','ene','bcl','digraph_count','digraphs','pt']} for r in sorted(phase0_results, key=lambda x: -x['crib_score'])[:5]],
        },
        'phase1_digraph_sa': {
            'description': 'SA with digraph reward bonus (weight=2.0)',
            'restarts': 200, 'steps': 60000,
            'avg_crib': round(sum(p1_cribs)/len(p1_cribs), 2),
            'max_crib': max(p1_cribs),
            'avg_digraphs': round(sum(p1_dgs)/len(p1_dgs), 2),
            'crib_distribution': dict(sorted(defaultdict(int, {k: sum(1 for r in phase1_results if r['crib_score']==k) for k in set(p1_cribs)}).items())),
            'top_5': [{k: r[k] for k in ['crib_score','ene','bcl','digraph_count','digraphs','pt']} for r in sorted(phase1_results, key=lambda x: -x['crib_score'])[:5]],
        },
        'phase2_analytical': {
            'description': 'Keyword-determined constraint propagation (positions 0-6)',
            'viable_count': len(phase2_results[0]),
            'eliminated_count': 15*7 - len(phase2_results[0]),
            'viable': [{k: v[k] for k in ['digraph','pt_pos','required','ct73_idx']} for v in phase2_results[0][:20]],
            'digraphs_in_known_masks': phase2_results[1],
        },
        'phase3_constrained': {
            'description': 'Deep SA with fixed digraph constraints',
            'cases_tested': len(phase3_results),
            'best_crib': p3_best_crib,
            'top_10': [{k: r[k] for k in ['digraph','pt_pos','source','crib_score','ene','bcl','target_match']}
                      for r in sorted(phase3_results, key=lambda x: -x['crib_score'])[:10]],
        },
        'phase4_w_delimiter': {
            'description': 'W-delimiter segment digraph analysis',
            'results': phase4_results[:10],
        },
        'correlation_analysis': {
            'baseline_high_crib_avg_dg': round(sum(p0_high_dg)/len(p0_high_dg), 2) if p0_high_dg else None,
            'baseline_low_crib_avg_dg': round(sum(p0_low_dg)/len(p0_low_dg), 2) if p0_low_dg else None,
            'expected_random': round(expected_rate, 3),
        },
    }

    if best_crib_overall > 15:
        output['verdict'] = 'PROMISING'
        output['verdict_detail'] = f'Digraph constraint pushed score to {best_crib_overall}/24, above baseline 15/24'
    elif best_crib_overall >= 15:
        output['verdict'] = 'NO_IMPROVEMENT'
        output['verdict_detail'] = 'Digraph constraints did NOT exceed the 15/24 ceiling'
    else:
        output['verdict'] = 'NOISE'
        output['verdict_detail'] = f'Best {best_crib_overall}/24, below 15/24 baseline (digraph-weighted SA trades crib accuracy for digraph matches)'

    with open('results/digraph_constrained_sa.json', 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*70}")
    print(f"FINAL VERDICT: {output['verdict']}")
    print(f"  {output['verdict_detail']}")
    print(f"  Best crib score overall: {best_crib_overall}/24")
    print(f"  Phase 0 baseline max crib: {max(p0_cribs)}/24 (avg dg={sum(p0_dgs)/len(p0_dgs):.2f})")
    print(f"  Phase 1 digraph SA max crib: {max(p1_cribs)}/24 (avg dg={sum(p1_dgs)/len(p1_dgs):.2f})")
    print(f"  Phase 3 constrained max crib: {p3_best_crib}/24")
    print(f"  Expected random digraph rate: {expected_rate:.2f} per 73-char text")
    print(f"  Total time: {total_time:.1f}s")
    print(f"  Results saved to results/digraph_constrained_sa.json")
    print(f"{'='*70}")
