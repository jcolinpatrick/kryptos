#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_model2_novel.py — Novel K4 unscrambling experiments (Model 2 confirmed)

NEW approaches not covered by prior scripts:

Part A: EXHAUSTIVE W10 columnar (10! = 3,628,800 perms × 2 conventions)
         Prior exhaustive: W7,W8,W9,W11,W12,W13. W10 is the gap.

Part B: Period-key multiset validator (NOVEL)
         For each period p (1..16) and cipher (vig/beau) and alphabet (AZ/KA):
           - For each key position r: enumerate valid key values k where
             {(PT[j]+k)%26 for crib j with j%p=r} is a submultiset of K4_CARVED.
           - Report which (period,cipher,alpha) combinations have ANY valid key.
           - List best candidates (most constrained).
         This gives a DEFINITIVE test of period-p Vigenere/Beaufort viability
         under Model 2 WITHOUT enumerating permutations.

Part C: Boustrophedon-column variant (NOVEL)
         Standard columnar reads each column top-to-bottom.
         Here, alternating columns are read bottom-to-top.
         For widths 5-15 and all keyword column orders.

Part D: Modular-group permutation (NOVEL)
         Split 97 positions into p groups by position mod p.
         Permute the ORDER of these groups (p! permutations for small p).
         Equivalent to "interleave stride" permutation families.
         Tests p=2..8 exhaustively, p=9..13 with keywords.

Part E: Self-referential / Index-of-K4 permutation (NOVEL)
         sigma[j] = AZ.index(K4[j]) — use K4's own characters as indices.
         Various numeric mappings of K4 characters → permutation.

Part F: Extended strip lengths L=17..24 with keyword constraints
         Prior work: L=8..16. Extend to L=17..24.

Usage: PYTHONPATH=src python3 -u scripts/blitz_model2_novel.py
"""

import numpy as np
import json, os, sys, time, math
import multiprocessing as mp
from itertools import permutations, product
from collections import Counter, defaultdict

os.makedirs('results/blitz_model2_novel', exist_ok=True)
RESULTS_DIR = 'results/blitz_model2_novel'

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N  = 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ENE = "EASTNORTHEAST"    # PT[21:34]
BC  = "BERLINCLOCK"      # PT[63:74]
ENE_START = 21
BC_START  = 63

KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA']

assert len(K4) == N

# Numpy arrays for fast computation
ct_np  = np.array([ord(c)-65 for c in K4],  dtype=np.int32)
ene_np = np.array([ord(c)-65 for c in ENE], dtype=np.int32)
bc_np  = np.array([ord(c)-65 for c in BC],  dtype=np.int32)

# Crib positions and plaintext chars (0-indexed)
CRIB_CHARS = (
    [(ENE_START + i, ord(c)-65) for i, c in enumerate(ENE)] +
    [(BC_START  + i, ord(c)-65) for i, c in enumerate(BC)]
)  # list of (pos, pt_int), length 24

# K4 character frequencies (multiset)
K4_FREQ = Counter(ord(c)-65 for c in K4)  # {int: count}

# ─── QUADGRAMS ────────────────────────────────────────────────────────────────
QG = {}
for p_q in ['data/english_quadgrams.json']:
    if os.path.exists(p_q):
        with open(p_q) as f: QG = json.load(f)
        break
if not QG:
    print("WARNING: No quadgram file — scores will be 0")

def qscore(t):
    return sum(QG.get(t[i:i+4], -10.0) for i in range(len(t)-3)) if QG else 0.0

# ─── GLOBAL RESULTS TRACKING ──────────────────────────────────────────────────
ALL_HITS = []
TOP_BY_SCORE = []  # (score, label, pt)

def log_hit(label, pt, real_ct, kw, alpha, cipher, ene_pos, bc_pos, extra=""):
    sc = qscore(pt)
    msg = (f"\n{'='*70}\n*** CRIB HIT ***  {label}\n"
           f"KW={kw}  Alpha={alpha}  Cipher={cipher}\n"
           f"ENE@{ene_pos}  BC@{bc_pos}\n"
           f"RealCT: {real_ct}\nPT:     {pt}\nScore:  {sc:.2f}\n{extra}")
    print(msg, flush=True)
    ALL_HITS.append(msg)
    with open(f'{RESULTS_DIR}/CRIB_HITS.txt', 'a') as f:
        f.write(msg + "\n")

def update_top(sc, label, pt, n=50):
    TOP_BY_SCORE.append((sc, label, pt))
    TOP_BY_SCORE.sort(reverse=True)
    if len(TOP_BY_SCORE) > n*3: del TOP_BY_SCORE[n*3:]

def test_candidate_str(label, real_ct_str):
    """Test a real-CT string against all configs. Print and return True on crib hit."""
    found = False
    for kw in KEYWORDS:
        for aname, astr in [('AZ',AZ),('KA',KA)]:
            idx = {c: i for i, c in enumerate(astr)}
            kw_ints = [idx.get(kw[i % len(kw)], 0) for i in range(N)]
            ct_arr = np.array([ord(c)-65 for c in real_ct_str], dtype=np.int32)
            kw_arr = np.array(kw_ints, dtype=np.int32)
            for cname, fn in [('vig', lambda c,k: (c-k)%26),
                               ('beau', lambda c,k: (k-c)%26)]:
                pt_arr = fn(ct_arr, kw_arr)
                pt = ''.join(chr(v+65) for v in pt_arr)
                ep = pt.find(ENE); bp = pt.find(BC)
                sc = qscore(pt)
                update_top(sc, label, pt)
                if ep >= 0 or bp >= 0:
                    log_hit(label, pt, real_ct_str, kw, aname, cname, ep, bp)
                    found = True
    return found

# ─── COLUMNAR HELPERS ─────────────────────────────────────────────────────────
def kw_col_order(kw):
    return sorted(range(len(kw)), key=lambda i: (kw[i], i))

def build_perm_batch_np(col_orders_arr, W, convention=1):
    B = col_orders_arr.shape[0]
    R     = (N + W - 1) // W
    extra = N % W
    if extra == 0: extra = W
    if convention == 1:
        col_len_nat = np.array([R if c < extra else R-1 for c in range(W)], dtype=np.int32)
        ordered_lengths = col_len_nat[col_orders_arr]
    else:
        col_len_key = np.array([R if i < extra else R-1 for i in range(W)], dtype=np.int32)
        ordered_lengths = np.tile(col_len_key, (B,1))

    starts_carved = np.zeros((B, W), dtype=np.int32)
    if W > 1:
        starts_carved[:, 1:] = np.cumsum(ordered_lengths[:, :-1], axis=1)

    rank = np.argsort(col_orders_arr, axis=1)
    start_nat = np.take_along_axis(starts_carved, rank, axis=1)

    col_of_pos = np.arange(N, dtype=np.int32) % W
    row_of_pos = np.arange(N, dtype=np.int32) // W
    perm = start_nat[:, col_of_pos] + row_of_pos
    return np.clip(perm, 0, N-1)

def build_required_patterns_for_worker():
    """Build ENE/BC required-pattern arrays for fast constraint checking."""
    ene_pats, ene_pos_list, ene_meta = [], [], []
    bc_pats,  bc_pos_list,  bc_meta  = [], [], []
    for kw in KEYWORDS:
        for aname, astr in [('AZ',AZ),('KA',KA)]:
            idx = {c: i for i, c in enumerate(astr)}
            kw_ints = [idx.get(kw[i % len(kw)], 0) for i in range(N)]
            for j in range(N - len(ENE) + 1):
                req_vig  = np.array([(ene_np[k] + kw_ints[j+k]) % 26 for k in range(len(ENE))], dtype=np.int32)
                req_beau = np.array([(kw_ints[j+k] - ene_np[k]) % 26 for k in range(len(ENE))], dtype=np.int32)
                ene_pats.append(req_vig);  ene_pos_list.append(j); ene_meta.append((kw,aname,'vig'))
                ene_pats.append(req_beau); ene_pos_list.append(j); ene_meta.append((kw,aname,'beau'))
            for j in range(N - len(BC) + 1):
                req_vig  = np.array([(bc_np[k] + kw_ints[j+k]) % 26 for k in range(len(BC))], dtype=np.int32)
                req_beau = np.array([(kw_ints[j+k] - bc_np[k]) % 26 for k in range(len(BC))], dtype=np.int32)
                bc_pats.append(req_vig);  bc_pos_list.append(j); bc_meta.append((kw,aname,'vig'))
                bc_pats.append(req_beau); bc_pos_list.append(j); bc_meta.append((kw,aname,'beau'))
    return (np.array(ene_pats,dtype=np.int32), np.array(ene_pos_list,dtype=np.int32), ene_meta,
            np.array(bc_pats,dtype=np.int32),  np.array(bc_pos_list,dtype=np.int32),  bc_meta)

def fast_batch_check_worker(col_orders_list, W, ene_pats, ene_pos_arr, ene_meta,
                             bc_pats, bc_pos_arr, bc_meta, convention=1):
    if not col_orders_list: return []
    B = len(col_orders_list)
    col_orders_arr = np.array(col_orders_list, dtype=np.int32)
    perm = build_perm_batch_np(col_orders_arr, W, convention)
    unscrambled = ct_np[perm]  # (B, N)
    hits = []
    L_ene = len(ENE)
    ene_by_pos = defaultdict(list)
    for i, j in enumerate(ene_pos_arr.tolist()):
        ene_by_pos[j].append(i)
    for j, pat_indices in ene_by_pos.items():
        window = unscrambled[:, j:j+L_ene]
        pats_at_j = ene_pats[np.array(pat_indices)]
        match = np.all(window[:, np.newaxis, :] == pats_at_j[np.newaxis, :, :], axis=2)
        hit_b, hit_p = np.where(match)
        for b_idx, p_local in zip(hit_b, hit_p):
            g_idx = pat_indices[p_local]
            kw, alpha, cipher = ene_meta[g_idx]
            real_ct = ''.join(K4[perm[b_idx, pos]] for pos in range(N))
            hits.append({'W': W, 'conv': convention, 'col_order': tuple(col_orders_list[b_idx]),
                         'crib': 'ENE', 'pos': int(j), 'kw': kw, 'alpha': alpha, 'cipher': cipher,
                         'real_ct': real_ct})
    L_bc = len(BC)
    bc_by_pos = defaultdict(list)
    for i, j in enumerate(bc_pos_arr.tolist()):
        bc_by_pos[j].append(i)
    for j, pat_indices in bc_by_pos.items():
        window = unscrambled[:, j:j+L_bc]
        pats_at_j = bc_pats[np.array(pat_indices)]
        match = np.all(window[:, np.newaxis, :] == pats_at_j[np.newaxis, :, :], axis=2)
        hit_b, hit_p = np.where(match)
        for b_idx, p_local in zip(hit_b, hit_p):
            g_idx = pat_indices[p_local]
            kw, alpha, cipher = bc_meta[g_idx]
            real_ct = ''.join(K4[perm[b_idx, pos]] for pos in range(N))
            hits.append({'W': W, 'conv': convention, 'col_order': tuple(col_orders_list[b_idx]),
                         'crib': 'BC', 'pos': int(j), 'kw': kw, 'alpha': alpha, 'cipher': cipher,
                         'real_ct': real_ct})
    return hits

def _worker_w10(args):
    W, prefix_tuple, batch_size = args
    prefix = list(prefix_tuple)
    remaining = [c for c in range(W) if c not in prefix]
    ep, ep2, em, bp, bp2, bm = build_required_patterns_for_worker()
    all_hits, batch, count = [], [], 0
    for rest in permutations(remaining):
        batch.append(prefix + list(rest))
        count += 1
        if len(batch) >= batch_size:
            for conv in [1, 2]:
                h = fast_batch_check_worker(batch, W, ep, ep2, em, bp, bp2, bm, conv)
                all_hits.extend(h)
            if all_hits:
                print(f"  [W{W} pfx={prefix_tuple}] {len(all_hits)} hits!", flush=True)
            batch = []
    if batch:
        for conv in [1, 2]:
            h = fast_batch_check_worker(batch, W, ep, ep2, em, bp, bp2, bm, conv)
            all_hits.extend(h)
    return all_hits, count

# ═══════════════════════════════════════════════════════════════════════════════
# PART A: EXHAUSTIVE W10 COLUMNAR
# ═══════════════════════════════════════════════════════════════════════════════
def part_a_exhaustive_w10():
    W = 10
    total = math.factorial(W)
    print(f"\n{'='*70}")
    print(f"PART A: Exhaustive W{W} columnar ({total:,} perms × 2 conventions)")
    print(f"  Prior exhaustive: W7,W8,W9,W11,W12,W13. W10 is the gap.")
    t0 = time.time()

    prefixes = [(i, j) for i in range(W) for j in range(W) if i != j]
    n_cores = min(mp.cpu_count(), len(prefixes))
    batch_size = 10000
    print(f"  {len(prefixes)} tasks → {n_cores} cores, batch={batch_size}", flush=True)

    args = [(W, p, batch_size) for p in prefixes]
    with mp.Pool(n_cores, maxtasksperchild=1) as pool:
        results = pool.map(_worker_w10, args)

    all_hits, total_count = [], 0
    for hits, cnt in results:
        all_hits.extend(hits)
        total_count += cnt

    elapsed = time.time() - t0
    rate = total_count / max(elapsed, 0.001)
    print(f"  Done: {total_count:,} perms in {elapsed:.1f}s ({rate:,.0f}/s)", flush=True)
    print(f"  Hits: {len(all_hits)}", flush=True)

    for h in all_hits:
        # Verify and log
        test_candidate_str(f"W10/conv{h['conv']}/col_order={h['col_order']}", h['real_ct'])
        with open(f'{RESULTS_DIR}/W10_hits.txt', 'a') as f:
            f.write(str(h) + "\n")

    if not all_hits:
        print(f"  W10 ELIMINATED: No crib hits in all {total_count:,} perms × 2 conventions", flush=True)
        with open(f'{RESULTS_DIR}/W10_result.txt', 'w') as f:
            f.write(f"W10 ELIMINATED: {total_count:,} perms × 2 conventions, {elapsed:.1f}s, ZERO crib hits\n")

    return all_hits

# ═══════════════════════════════════════════════════════════════════════════════
# PART B: PERIOD-KEY MULTISET VALIDATOR (NOVEL)
# ═══════════════════════════════════════════════════════════════════════════════
def multiset_contains(big_freq, small_list):
    """Check if small_list (list of ints) is a submultiset of big_freq (Counter of ints)."""
    need = Counter(small_list)
    for val, cnt in need.items():
        if big_freq.get(val, 0) < cnt:
            return False
    return True

def part_b_period_key_validator():
    print(f"\n{'='*70}")
    print("PART B: Period-Key Multiset Validator (NOVEL)")
    print("  For each (period, cipher, alphabet), enumerate valid key values")
    print("  at each residue class using the 24 crib character constraints.")
    print("  Tests whether ANY key of this period is consistent with K4_CARVED.")
    t0 = time.time()

    results_b = {}

    for period in range(1, 17):
        for aname, astr in [('AZ', AZ), ('KA', KA)]:
            aidx = {c: i for i, c in enumerate(astr)}

            # Group crib positions by residue mod period
            groups = defaultdict(list)  # residue → [(pos, pt_int)]
            for pos, pt_int in CRIB_CHARS:
                pt_in_alpha = pt_int  # AZ indices, same for both since cribs are standard letters
                groups[pos % period].append((pos, pt_in_alpha))

            for cname in ['vig', 'beau']:
                # For each residue class: find valid key values
                residue_valid_keys = {}  # residue → list of valid k values

                for r in range(period):
                    valid_ks = []
                    crib_positions_here = groups.get(r, [])

                    if not crib_positions_here:
                        # No crib constraint → all 26 values valid
                        valid_ks = list(range(26))
                    else:
                        for k in range(26):
                            # Required real_CT chars at these positions
                            if cname == 'vig':
                                required = [(pt_int + k) % 26 for _, pt_int in crib_positions_here]
                            else:  # beau: PT = (k - CT) → CT = (k - PT)
                                required = [(k - pt_int) % 26 for _, pt_int in crib_positions_here]

                            if multiset_contains(K4_FREQ, required):
                                valid_ks.append(k)

                    residue_valid_keys[r] = valid_ks

                # Count total valid key combinations
                total_combos = 1
                for r in range(period):
                    total_combos *= len(residue_valid_keys[r])

                key_label = (period, cname, aname)
                results_b[key_label] = {
                    'period': period,
                    'cipher': cname,
                    'alpha': aname,
                    'valid_keys_per_residue': {r: residue_valid_keys[r] for r in range(period)},
                    'total_combos': total_combos,
                    'impossible': total_combos == 0,
                }

                # For small total combos: enumerate all valid key combinations
                # and check the JOINT constraint (all 24 chars must fit together)
                joint_valid = 0
                joint_examples = []

                if 0 < total_combos <= 500000:
                    # Enumerate all combinations
                    residue_lists = [residue_valid_keys[r] for r in range(period)]
                    for key_combo in product(*residue_lists):
                        # Compute required real_CT at all 24 crib positions
                        if cname == 'vig':
                            required_all = [(pt_int + key_combo[pos % period]) % 26
                                           for pos, pt_int in CRIB_CHARS]
                        else:
                            required_all = [(key_combo[pos % period] - pt_int) % 26
                                           for pos, pt_int in CRIB_CHARS]

                        # Check ALL 24 together as a submultiset of K4_CARVED
                        if multiset_contains(K4_FREQ, required_all):
                            joint_valid += 1
                            if len(joint_examples) < 5:
                                # Represent key as string
                                key_str = ''.join(AZ[k] for k in key_combo)
                                joint_examples.append(key_str)

                    results_b[key_label]['joint_valid'] = joint_valid
                    results_b[key_label]['joint_examples'] = joint_examples
                else:
                    results_b[key_label]['joint_valid'] = None  # not enumerated (too many)

    elapsed = time.time() - t0
    print(f"\n  Period-key validation complete ({elapsed:.1f}s)")
    print(f"\n  {'Period':>7} {'Cipher':>6} {'Alpha':>4} {'PerResidueTotal':>16} {'JointValid':>11} {'Status'}")
    print(f"  {'-'*65}")

    # Save full results
    out_lines = []
    impossible_count = 0
    joint_zero_count = 0
    for period in range(1, 17):
        for cname in ['vig', 'beau']:
            for aname in ['AZ', 'KA']:
                r = results_b.get((period, cname, aname), {})
                tc = r.get('total_combos', 0)
                jv = r.get('joint_valid', None)
                impossible = r.get('impossible', True)
                examples = r.get('joint_examples', [])

                if impossible:
                    status = "IMPOSSIBLE (no per-residue keys)"
                    impossible_count += 1
                elif jv == 0:
                    status = "ELIMINATED (no valid joint keys)"
                    joint_zero_count += 1
                elif jv is None:
                    status = f"UNCHECKED ({tc:,} combos, too many to enumerate)"
                else:
                    status = f"VIABLE: {jv} joint keys found"
                    if examples:
                        status += f"  e.g. {examples[:3]}"

                print(f"  {period:>7} {cname:>6} {aname:>4} {tc:>16,} {str(jv):>11}  {status}",
                      flush=True)
                out_lines.append(f"period={period:2d} {cname} {aname}: total={tc:10,} "
                                  f"joint={str(jv):>8}  {status}")

    with open(f'{RESULTS_DIR}/period_key_validation.txt', 'w') as f:
        f.write("K4 Period-Key Multiset Validation (Model 2)\n")
        f.write(f"={'='*70}\n")
        f.write(f"K4_CARVED = {K4}\n")
        f.write(f"Cribs: ENE@{ENE_START} BC@{BC_START}\n\n")
        for line in out_lines:
            f.write(line + "\n")

    print(f"\n  Summary: {impossible_count} (period,cipher,alpha) combos IMPOSSIBLE per-residue")
    print(f"           {joint_zero_count} additional ELIMINATED by joint check")

    # Show viable (period, cipher, alpha) combinations
    viable = [(period, cname, aname) for period in range(1, 17)
              for cname in ['vig', 'beau']
              for aname in ['AZ', 'KA']
              if not results_b.get((period, cname, aname), {}).get('impossible', True)
              and results_b.get((period, cname, aname), {}).get('joint_valid', 1) != 0]

    print(f"\n  VIABLE (period,cipher,alpha) combinations: {len(viable)}")
    for v in viable[:20]:
        r = results_b[v]
        jv = r.get('joint_valid', '?')
        print(f"    period={v[0]:2d} {v[1]} {v[2]}: {jv} joint-valid keys")
        if r.get('joint_examples'):
            print(f"      Examples: {r['joint_examples'][:5]}")

    return results_b

# ═══════════════════════════════════════════════════════════════════════════════
# PART C: BOUSTROPHEDON-COLUMN VARIANT (NOVEL)
# ═══════════════════════════════════════════════════════════════════════════════
def columnar_boustrophedon_cols(ct_str, col_order):
    """
    Variant columnar: alternating columns read bottom-to-top / top-to-bottom.
    col_order[i] = natural col index read at position i in key order.
    Even-indexed key positions: top-to-bottom (normal).
    Odd-indexed key positions: bottom-to-top (reversed).
    """
    W = len(col_order)
    n = len(ct_str)
    R     = (n + W - 1) // W
    extra = n % W
    if extra == 0: extra = W
    col_len = [R if c < extra else R-1 for c in range(W)]

    cols = {}
    offset = 0
    for key_pos, c in enumerate(col_order):
        chunk = ct_str[offset: offset + col_len[c]]
        if key_pos % 2 == 1:  # reverse alternating
            chunk = chunk[::-1]
        cols[c] = chunk
        offset += col_len[c]

    result = []
    for r in range(R):
        for c in range(W):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return ''.join(result)

def part_c_boustrophedon_cols():
    print(f"\n{'='*70}")
    print("PART C: Boustrophedon-column columnar variant (NOVEL)")
    n_tested = 0
    seen = set()

    for W in range(5, 16):
        for kw in KEYWORDS:
            co = kw_col_order(kw)
            real_ct = columnar_boustrophedon_cols(K4, co)
            key = real_ct
            if key not in seen:
                seen.add(key)
                test_candidate_str(f"BoustCol/W{W}/{kw}", real_ct)
                n_tested += 1

            # Also reverse keyword order
            co_rev = kw_col_order(kw[::-1])
            real_ct2 = columnar_boustrophedon_cols(K4, co_rev)
            key2 = real_ct2
            if key2 not in seen:
                seen.add(key2)
                test_candidate_str(f"BoustCol/W{W}/{kw}rev", real_ct2)
                n_tested += 1

        # Natural and reverse column orders
        for co_name, co in [('natural', list(range(W))),
                              ('reverse', list(range(W-1,-1,-1))),
                              ('odds_first', list(range(1,W,2))+list(range(0,W,2))),
                              ('evens_first', list(range(0,W,2))+list(range(1,W,2)))]:
            real_ct = columnar_boustrophedon_cols(K4, co)
            key = real_ct
            if key not in seen:
                seen.add(key)
                test_candidate_str(f"BoustCol/W{W}/{co_name}", real_ct)
                n_tested += 1

    print(f"  Boustrophedon-column: {n_tested} tested", flush=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PART D: MODULAR-GROUP PERMUTATION (NOVEL)
# ═══════════════════════════════════════════════════════════════════════════════
def modular_group_perm(ct_str, period, group_order):
    """
    Split positions 0..N-1 into groups by pos % period.
    group_order[i] = which residue class goes to output position i.
    Result: concatenate the characters of each residue class in group_order order.
    This is equivalent to specific columnar transpositions.
    """
    n = len(ct_str)
    groups = defaultdict(list)
    for pos in range(n):
        groups[pos % period].append(ct_str[pos])

    result = []
    for r in group_order:
        result.extend(groups[r])
    return ''.join(result)

def part_d_modular_group():
    print(f"\n{'='*70}")
    print("PART D: Modular-group permutation (NOVEL)")
    print("  Split K4 into p groups by position mod p, permute group ORDER")
    n_tested = 0
    seen = set()

    # For small p: exhaustive (all p! orderings)
    for period in range(2, 9):
        n_perms = math.factorial(period)
        print(f"  Period {period}: {n_perms} permutations", flush=True)
        for group_order in permutations(range(period)):
            real_ct = modular_group_perm(K4, period, list(group_order))
            key = real_ct
            if key not in seen:
                seen.add(key)
                test_candidate_str(f"ModGrp/p{period}/order={group_order}", real_ct)
                n_tested += 1

    # For larger p: keyword-derived orderings
    for period in range(9, 14):
        print(f"  Period {period}: keyword-derived orderings", flush=True)
        for kw in KEYWORDS:
            # Use keyword to determine group ordering
            group_order = sorted(range(period), key=lambda i: kw[i % len(kw)])
            real_ct = modular_group_perm(K4, period, group_order)
            key = real_ct
            if key not in seen:
                seen.add(key)
                test_candidate_str(f"ModGrp/p{period}/{kw}", real_ct)
                n_tested += 1

            # Reverse ordering
            group_order_rev = list(reversed(group_order))
            real_ct2 = modular_group_perm(K4, period, group_order_rev)
            if real_ct2 not in seen:
                seen.add(real_ct2)
                test_candidate_str(f"ModGrp/p{period}/{kw}rev", real_ct2)
                n_tested += 1

    print(f"  Modular-group: {n_tested} tested", flush=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PART E: SELF-REFERENTIAL / INDEX-OF-K4 PERMUTATIONS (NOVEL)
# ═══════════════════════════════════════════════════════════════════════════════
def part_e_self_referential():
    """
    Use K4's own character values to construct permutations.
    Novel: the ciphertext encodes its own reading order.
    """
    print(f"\n{'='*70}")
    print("PART E: Self-referential permutations from K4 character values (NOVEL)")
    n_tested = 0
    seen = set()

    # E1: sigma[j] = ct_np[j] mod 97 — direct index (unlikely to be a valid perm)
    # (but K4 chars range 0-25, mod 97 = same, not a perm of 97)

    # E2: Sort K4 chars by value → reading order of real_CT
    # sigma: position in sorted K4 = real_CT position
    sorted_k4_idx = sorted(range(N), key=lambda i: (ct_np[i], i))
    real_ct = ''.join(K4[sorted_k4_idx[j]] for j in range(N))
    if real_ct not in seen:
        seen.add(real_ct)
        test_candidate_str("SelfRef/sort_by_val", real_ct)
        n_tested += 1

    # E3: Inverse — sigma = argsort(K4)
    argsort_k4 = np.argsort(ct_np, kind='stable')
    real_ct = ''.join(K4[argsort_k4[j]] for j in range(N))
    if real_ct not in seen:
        seen.add(real_ct)
        test_candidate_str("SelfRef/argsort", real_ct)
        n_tested += 1

    # E4: Running index mod period (key index derivation)
    # Use K4 chars as cyclic key to index into carved text
    for period in [7, 8, 10, 11, 13]:
        # key_vals[j] = K4_char_val[j % period] (average of chars at that residue class)
        for offset in range(period):
            sigma = [(j + ct_np[(j + offset) % N]) % N for j in range(N)]
            if len(set(sigma)) == N:
                real_ct = ''.join(K4[sigma[j]] for j in range(N))
                if real_ct not in seen:
                    seen.add(real_ct)
                    test_candidate_str(f"SelfRef/shift_p{period}_off{offset}", real_ct)
                    n_tested += 1

    # E5: Use K4's character pairs to form permutation indices
    # Sum of adjacent pairs → indices
    pair_sums = [(ct_np[i] + ct_np[(i+1) % N]) % N for i in range(N)]
    if len(set(pair_sums)) == N:
        real_ct = ''.join(K4[pair_sums[j]] for j in range(N))
        if real_ct not in seen:
            seen.add(real_ct)
            test_candidate_str("SelfRef/pair_sum_mod97", real_ct)
            n_tested += 1

    # E6: K4_KA: use KA alphabet indices instead of AZ
    KA_IDX = {c: i for i, c in enumerate(KA)}
    ct_ka = np.array([KA_IDX.get(c, 0) for c in K4], dtype=np.int32)
    sorted_ka_idx = sorted(range(N), key=lambda i: (ct_ka[i], i))
    real_ct = ''.join(K4[sorted_ka_idx[j]] for j in range(N))
    if real_ct not in seen:
        seen.add(real_ct)
        test_candidate_str("SelfRef/sort_by_KA_val", real_ct)
        n_tested += 1

    print(f"  Self-referential: {n_tested} tested", flush=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PART F: EXTENDED STRIP LENGTHS L=17..24 (NOVEL)
# ═══════════════════════════════════════════════════════════════════════════════
def strip_perm_keyword(ct_str, L, kw):
    """
    Block/strip permutation: divide ct_str into strips of length L (last may be shorter),
    then reorder strips according to keyword-derived order.
    """
    n = len(ct_str)
    n_strips = math.ceil(n / L)
    strips = [ct_str[i*L:(i+1)*L] for i in range(n_strips)]
    if len(strips) < len(kw):
        strip_order = sorted(range(len(strips)), key=lambda i: (kw[i % len(kw)], i))
    else:
        strip_order = sorted(range(len(strips)), key=lambda i: (kw[i % len(kw)], i))
    return ''.join(strips[i] for i in strip_order)

def part_f_extended_strips():
    print(f"\n{'='*70}")
    print("PART F: Extended strip lengths L=17..24 (prior: L=8..16)")
    n_tested = 0
    seen = set()

    for L in range(17, 25):
        n_strips = math.ceil(N / L)
        print(f"  L={L}: {n_strips} strips", flush=True)
        for kw in KEYWORDS:
            real_ct = strip_perm_keyword(K4, L, kw)
            if real_ct not in seen:
                seen.add(real_ct)
                test_candidate_str(f"StripL{L}/{kw}", real_ct)
                n_tested += 1
            # Reverse strip order
            real_ct_rev = strip_perm_keyword(K4[::-1], L, kw)
            if real_ct_rev not in seen:
                seen.add(real_ct_rev)
                test_candidate_str(f"StripL{L}/{kw}/rev", real_ct_rev)
                n_tested += 1

        # Natural and reverse strip orders
        strips = [K4[i*L:(i+1)*L] for i in range(n_strips)]
        for sname, sorder in [('natural', list(range(n_strips))),
                               ('reverse', list(range(n_strips-1,-1,-1)))]:
            real_ct = ''.join(strips[i] for i in sorder)
            if real_ct not in seen:
                seen.add(real_ct)
                test_candidate_str(f"StripL{L}/{sname}", real_ct)
                n_tested += 1

    print(f"  Extended strips: {n_tested} tested", flush=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PART G: PERIOD-KEY FULL DECRYPTION FOR VIABLE COMBINATIONS
# ═══════════════════════════════════════════════════════════════════════════════
def part_g_viable_key_decryption(results_b):
    """
    For each viable (period, cipher, alpha) combination with enumerable joint-valid keys:
    - Compute the expected real_CT at crib positions
    - Try to find a permutation via CSP (greedy + random fills)
    - Score results
    """
    print(f"\n{'='*70}")
    print("PART G: Decryption attempts for viable period-key combinations")
    n_tested = 0

    for period in range(1, 14):
        for cname in ['vig', 'beau']:
            for aname in ['AZ', 'KA']:
                r = results_b.get((period, cname, aname), {})
                if r.get('impossible', True):
                    continue
                jv = r.get('joint_valid', None)
                if jv is None or jv == 0:
                    continue

                examples = r.get('joint_examples', [])
                if not examples:
                    continue

                astr = AZ if aname == 'AZ' else KA
                aidx = {c: i for i, c in enumerate(astr)}

                for key_str in examples[:3]:  # test up to 3 example keys
                    key_ints = [aidx.get(c, 0) for c in key_str]

                    # Compute expected real_CT at each crib position
                    expected_ct = {}
                    for pos, pt_int in CRIB_CHARS:
                        k = key_ints[pos % period]
                        if cname == 'vig':
                            expected_ct[pos] = (pt_int + k) % 26
                        else:
                            expected_ct[pos] = (k - pt_int) % 26

                    # Check which K4_CARVED positions have the required chars
                    # Build assignment: crib_pos → list of valid K4 positions
                    k4_positions_with_char = defaultdict(list)
                    for i, c in enumerate(K4):
                        k4_positions_with_char[ord(c)-65].append(i)

                    # Try a greedy assignment
                    remaining_k4 = list(range(N))
                    sigma = [None] * N

                    # Assign crib positions first
                    k4_used = set()
                    feasible = True
                    for pos, pt_int in CRIB_CHARS:
                        req_ct = expected_ct[pos]
                        # Find available K4 position with this char
                        found = False
                        for k4_pos in k4_positions_with_char[req_ct]:
                            if k4_pos not in k4_used:
                                sigma[pos] = k4_pos
                                k4_used.add(k4_pos)
                                found = True
                                break
                        if not found:
                            feasible = False
                            break

                    if not feasible:
                        continue

                    # Fill remaining positions
                    free_k4 = [i for i in range(N) if i not in k4_used]
                    free_pos = [i for i in range(N) if sigma[i] is None]
                    import random
                    random.shuffle(free_k4)
                    for pos, k4_pos in zip(free_pos, free_k4):
                        sigma[pos] = k4_pos

                    # Decrypt and score
                    real_ct_str = ''.join(K4[sigma[j]] for j in range(N))
                    kw_ints = [key_ints[j % period] for j in range(N)]
                    if cname == 'vig':
                        pt_ints = [(ord(K4[sigma[j]])-65 - kw_ints[j]) % 26 for j in range(N)]
                    else:
                        pt_ints = [(kw_ints[j] - (ord(K4[sigma[j]])-65)) % 26 for j in range(N)]
                    pt = ''.join(chr(v+65) for v in pt_ints)
                    sc = qscore(pt)
                    ep = pt.find(ENE); bp = pt.find(BC)
                    update_top(sc, f"PartG/p{period}/{cname}/{aname}/key={key_str}", pt)

                    if ep >= 0 or bp >= 0:
                        log_hit(f"PartG/p{period}/{cname}/{aname}/key={key_str}",
                                pt, real_ct_str, key_str, aname, cname, ep, bp)
                    n_tested += 1

    print(f"  Part G: {n_tested} candidate keys tested with greedy CSP", flush=True)

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
def save_final_summary():
    top50 = TOP_BY_SCORE[:50]
    with open(f'{RESULTS_DIR}/top_results.txt', 'w') as f:
        f.write("Top results by quadgram score\n" + "="*70 + "\n")
        for i, (sc, label, pt) in enumerate(top50):
            f.write(f"{i+1:3d}. Score={sc:8.2f}  {label}\n      PT: {pt}\n\n")
    print(f"\nSaved top {len(top50)} results to {RESULTS_DIR}/top_results.txt")
    print(f"Total crib hits: {len(ALL_HITS)}")
    if ALL_HITS:
        print("\n*** ALL CRIB HITS ***")
        for h in ALL_HITS:
            print(h)
    else:
        if top50:
            print(f"Best score: {top50[0][0]:.2f}  {top50[0][1]}")
            print(f"  PT: {top50[0][2]}")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print(f"K4 Model2 Novel Experiments | N={N} | CPUs={mp.cpu_count()}")
    print(f"K4: {K4}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    t_global = time.time()

    # ── Fast targeted tests (non-exhaustive) ────────────────────────────────
    print("\n--- Running Parts B-G first (fast) ---", flush=True)

    results_b = part_b_period_key_validator()
    save_final_summary()

    part_c_boustrophedon_cols()
    save_final_summary()

    part_d_modular_group()
    save_final_summary()

    part_e_self_referential()
    save_final_summary()

    part_f_extended_strips()
    save_final_summary()

    part_g_viable_key_decryption(results_b)
    save_final_summary()

    # ── Main exhaustive search ───────────────────────────────────────────────
    print(f"\n--- Running Part A: Exhaustive W10 ({math.factorial(10):,} perms) ---", flush=True)
    hits_a = part_a_exhaustive_w10()
    save_final_summary()

    elapsed = time.time() - t_global
    print(f"\n{'='*70}")
    print(f"DONE — Total time: {elapsed:.1f}s")
    print(f"Total crib hits: {len(ALL_HITS)}")
    if ALL_HITS:
        print("\n*** HITS FOUND! ***")
        for h in ALL_HITS:
            print(h)
    else:
        print("No crib hits found.")
        print(f"Check {RESULTS_DIR}/ for detailed results.")
