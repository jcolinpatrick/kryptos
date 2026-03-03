#!/usr/bin/env python3
"""
blitz_constraint_solver_v2.py — Model 2 Constraint-Based K4 Search

PARADIGM (confirmed Model 2):
  PT → Cipher(key) → real_CT → Scramble(σ) → carved text (K4)

Crib positions are PLAINTEXT positions (not carved text positions):
  PT[21..33] = EASTNORTHEAST
  PT[63..73] = BERLINCLOCK

Key insight: Given a key assumption, we compute expected real_CT at 24 crib
positions. Constraint: carved_text[σ(j)] = expected_CT[j] for each crib pos j.

This script implements:
  Phase 1: CSP to enumerate valid partial σ for fixed cribs at (21,63),
           then deep SA (300K+ steps) on free positions.
  Phase 2: Model-free period search — find σ where keystream at crib positions
           is periodic with period p, without assuming a specific key.
  Phase 3: Focused high-iteration SA on best configs from existing runs.

Run: PYTHONPATH=src python3 -u scripts/blitz_constraint_solver_v2.py
"""

import json, os, sys, time, random, math
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count
import numpy as np

sys.path.insert(0, 'src')

OUTDIR = 'blitz_results/constraint_solver'
os.makedirs(OUTDIR, exist_ok=True)

def log(msg):
    ts = time.strftime('%H:%M:%S')
    print(f"[{ts}] {msg}", flush=True)

# ── Constants ──────────────────────────────────────────────────────────────────
K4  = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA  = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ENE = "EASTNORTHEAST"
BC  = "BERLINCLOCK"
N   = 97
assert len(K4) == N

# Fixed crib positions (Model 2: these are PLAINTEXT positions)
ENE_START = 21
BC_START  = 63
CRIB_POS  = list(range(ENE_START, ENE_START + len(ENE))) + \
            list(range(BC_START,  BC_START  + len(BC)))
CRIB_PT   = list(ENE) + list(BC)
assert len(CRIB_POS) == 24

AZ_IDX  = {c: i for i, c in enumerate(AZ)}
KA_IDX  = {c: i for i, c in enumerate(KA)}
K4_INT  = np.array([AZ_IDX[c] for c in K4], dtype=np.int32)
K4_CHAR = Counter(K4)
K4_POS  = defaultdict(list)
for _i, _c in enumerate(K4):
    K4_POS[_c].append(_i)

KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN',
            'SCHEIDT', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT',
            'ANTIPODES', 'MEDUSA', 'ENIGMA']

# ── Quadgrams ──────────────────────────────────────────────────────────────────
def load_qg(path='data/english_quadgrams.json'):
    with open(path) as f:
        return json.load(f)

def make_qg_arr(qg_dict):
    A = np.full((26, 26, 26, 26), -10.0, dtype=np.float32)
    for k, v in qg_dict.items():
        if len(k) == 4 and k.isalpha():
            ix = [AZ_IDX.get(c, -1) for c in k.upper()]
            if all(0 <= x < 26 for x in ix):
                A[ix[0], ix[1], ix[2], ix[3]] = float(v)
    return A

# ── Cipher / expected CT ───────────────────────────────────────────────────────
def make_dec(kw, cipher, alpha):
    """Dec table: dec[phase, ct_az_idx] = pt_az_idx. Shape (period, 26)."""
    period = len(kw)
    astr   = AZ if alpha == 'AZ' else KA
    aidx   = AZ_IDX if alpha == 'AZ' else KA_IDX
    D = np.zeros((period, 26), dtype=np.int32)
    for ph in range(period):
        ki = aidx.get(kw[ph], -1)
        if ki < 0:
            continue
        for ca in range(26):
            ci = aidx.get(AZ[ca], -1)
            if ci < 0:
                continue
            pi = ((ci - ki) if cipher == 'vig' else (ki - ci)) % 26
            D[ph, ca] = AZ_IDX[astr[pi]]
    return D

def expected_ct_at_cribs(kw, cipher, alpha):
    """
    Returns dict: crib_pos → required carved letter.
    Under Model 2: real_CT[j] = Enc(PT[j], key[j % period]).
    So carved[σ(j)] = expected_CT[j].
    """
    astr  = AZ if alpha == 'AZ' else KA
    aidx  = AZ_IDX if alpha == 'AZ' else KA_IDX
    per   = len(kw)
    out   = {}
    for pos, pt_char in zip(CRIB_POS, CRIB_PT):
        pi = aidx.get(pt_char, -1)
        ki = aidx.get(kw[pos % per], -1)
        if pi < 0 or ki < 0:
            return None
        ci = ((pi + ki) if cipher == 'vig' else (ki - pi)) % 26
        out[pos] = astr[ci]
    return out

# ── CSP backtracking ───────────────────────────────────────────────────────────
def csp_partial_sigmas(constraints, maxr=5000, randomize=True, seed=42):
    """
    Find all (up to maxr) valid partial σ assignments.
    constraints: dict {pos → required_carved_char}
    Returns list of dicts {pos → carved_idx}.
    """
    rng = random.Random(seed)

    # Sort positions by domain size (most constrained first)
    pos_list = sorted(constraints.keys(),
                      key=lambda p: len(K4_POS.get(constraints[p], [])))
    domains  = {}
    for p in pos_list:
        dom = list(K4_POS.get(constraints[p], []))
        if not dom:
            return []
        if randomize:
            rng.shuffle(dom)
        domains[p] = dom

    results = []

    def bt(idx, asgn, used):
        if len(results) >= maxr:
            return
        if idx == len(pos_list):
            results.append(dict(asgn))
            return
        p = pos_list[idx]
        for cp in domains[p]:
            if cp not in used:
                asgn[p] = cp
                used.add(cp)
                bt(idx + 1, asgn, used)
                del asgn[p]
                used.remove(cp)

    bt(0, {}, set())
    return results

def count_csp_solutions(constraints):
    """Quick count of CSP solutions (up to 100K)."""
    count = [0]
    pos_list = sorted(constraints.keys(),
                      key=lambda p: len(K4_POS.get(constraints[p], [])))
    domains  = {p: list(K4_POS.get(constraints[p], [])) for p in pos_list}

    def bt(idx, used):
        if count[0] >= 100000:
            return
        if idx == len(pos_list):
            count[0] += 1
            return
        p = pos_list[idx]
        for cp in domains[p]:
            if cp not in used:
                used.add(cp)
                bt(idx + 1, used)
                used.remove(cp)

    bt(0, set())
    return count[0]

# ── Scoring ────────────────────────────────────────────────────────────────────
def score_sigma(sig, D, QA):
    ph = np.arange(N, dtype=np.int32) % D.shape[0]
    ct = K4_INT[sig]
    pt = D[ph, ct]
    s  = 0.0
    for i in range(N - 3):
        s += float(QA[pt[i], pt[i+1], pt[i+2], pt[i+3]])
    return s

def pt_from_sigma(sig, D):
    ph = np.arange(N, dtype=np.int32) % D.shape[0]
    ct = K4_INT[sig]
    pt = D[ph, ct]
    return ''.join(AZ[x] for x in pt)

# ── SA (deep, fixed partial positions) ────────────────────────────────────────
def sa_deep(partial, D, QA, n_steps=300000, T0=6.0, Tf=0.05, seed=None):
    """
    SA over free (non-crib) positions.
    partial: dict {real_CT_pos → carved_idx} (crib positions, fixed)
    D: decryption table (period x 26)
    Returns (best_sig as np array, best_score, best_pt_str)
    """
    if seed is None:
        seed = random.randint(0, 2**31)
    random.seed(seed)
    np.random.seed(seed % (2**31))

    fixed_real   = set(partial.keys())
    fixed_carved = set(partial.values())
    free_real    = [j for j in range(N) if j not in fixed_real]
    free_carved  = [i for i in range(N) if i not in fixed_carved]

    assert len(free_real)   == N - 24
    assert len(free_carved) == N - 24

    # Random initial assignment for free positions
    fc = list(free_carved)
    random.shuffle(fc)

    # Build sigma
    sig = np.zeros(N, dtype=np.int32)
    for j, c in partial.items():
        sig[j] = c
    for j, c in zip(free_real, fc):
        sig[j] = c

    ph  = np.arange(N, dtype=np.int32) % D.shape[0]
    ct  = K4_INT[sig].copy()
    pt  = D[ph, ct].copy()

    free_arr = np.array(free_real, dtype=np.int32)
    nf       = len(free_arr)

    def qsum_local(p):
        s = 0.0
        for st in range(max(0, p - 3), min(N - 3, p + 1)):
            s += float(QA[pt[st], pt[st+1], pt[st+2], pt[st+3]])
        return s

    cur  = sum(float(QA[pt[i], pt[i+1], pt[i+2], pt[i+3]]) for i in range(N - 3))
    best = cur
    bsig = sig.copy()

    lr = math.log(Tf / T0)

    for step in range(n_steps):
        T  = T0 * math.exp(lr * step / n_steps)
        ia = random.randint(0, nf - 1)
        ib = random.randint(0, nf - 2)
        if ib >= ia:
            ib += 1
        i = int(free_arr[ia])
        j = int(free_arr[ib])

        oi = qsum_local(i)
        oj = qsum_local(j)

        sig[i], sig[j] = sig[j], sig[i]
        ct[i], ct[j]   = ct[j], ct[i]
        pt[i] = int(D[ph[i], ct[i]])
        pt[j] = int(D[ph[j], ct[j]])

        if abs(i - j) < 4:
            new_sc = sum(float(QA[pt[k], pt[k+1], pt[k+2], pt[k+3]])
                         for k in range(N - 3))
        else:
            new_sc = cur + qsum_local(i) + qsum_local(j) - oi - oj

        d = new_sc - cur
        if d > 0 or (T > 1e-12 and random.random() < math.exp(d / T)):
            cur = new_sc
            if new_sc > best:
                best = new_sc
                bsig = sig.copy()
        else:
            sig[i], sig[j] = sig[j], sig[i]
            ct[i], ct[j]   = ct[j], ct[i]
            pt[i] = int(D[ph[i], ct[i]])
            pt[j] = int(D[ph[j], ct[j]])

    best_pt = pt_from_sigma(bsig, D)
    return bsig, best, best_pt

# ── Check crib presence ────────────────────────────────────────────────────────
def check(pt):
    return (pt[ENE_START:ENE_START + len(ENE)] == ENE,
            pt[BC_START:BC_START  + len(BC)]   == BC,
            pt.find(ENE), pt.find(BC))

# ── Model-free periodic keystream analysis ────────────────────────────────────
def analyze_forced_constraints(kw, cipher, alpha):
    """
    Print the forced assignments for this key config.
    Useful for understanding the constraint structure.
    """
    exp = expected_ct_at_cribs(kw, cipher, alpha)
    if exp is None:
        return

    log(f"\n  Forced constraints for {cipher}/{kw}/{alpha}:")
    letter_needs = Counter(exp.values())
    forced = []
    for ch, need in sorted(letter_needs.items()):
        have = len(K4_POS.get(ch, []))
        status = "FORCED" if have == need else f"choose {need} of {have}"
        log(f"    {ch}: need {need}, have {have} → {status}  positions={K4_POS.get(ch, [])}")
        if have == need:
            forced.append((ch, need, K4_POS[ch]))
    return forced

def periodic_keystream_search(period, cipher='vig', max_solutions=2000, seed=42):
    """
    Find partial σ assignments (for 24 crib positions) such that the
    derived keystream is periodic with the given period.

    Under Vigenère: k[j] = (carved[σ(j)] - PT[j]) mod 26 = key[j % period]
    Under Beaufort: k[j] = (PT[j]   + carved[σ(j)]) mod 26 = key[j % period]

    For each period slot s, all crib positions j with j%period==s must have:
      carved[σ(j)] = (key_s + PT[j]) mod 26  for Vig
      carved[σ(j)] = (key_s - PT[j]) mod 26  for Beau

    We enumerate over all 26^(# unique slots) key combinations that have
    solutions, with backtracking.
    """
    rng = random.Random(seed)

    # Group crib positions by their period slot
    slots = defaultdict(list)  # slot → list of (crib_pos, pt_char_idx)
    for pos, pt_char in zip(CRIB_POS, CRIB_PT):
        slots[pos % period].append((pos, AZ_IDX[pt_char]))
    unique_slots = sorted(slots.keys())
    n_slots = len(unique_slots)

    log(f"\n  Period-{period}/{cipher}: {n_slots} unique slots among {period} possible")
    for s, members in sorted(slots.items()):
        log(f"    slot {s}: positions {[m[0] for m in members]}")

    # For each slot and each key value v (0-25), find valid carved positions
    # for all members of that slot simultaneously (all-different within slot)
    def slot_assignments(slot_members, key_val):
        """
        For a slot with key_val, return list of assignment dicts
        {pos → carved_idx} satisfying:
          vig:  carved[σ(pos)] = (key_val + pt_idx) % 26
          beau: carved[σ(pos)] = (key_val - pt_idx) % 26
        and all-different.
        """
        # Required carved value for each member
        reqs = []
        for pos, pt_idx in slot_members:
            if cipher == 'vig':
                req_val = (key_val + pt_idx) % 26
            else:
                req_val = (key_val - pt_idx) % 26
            # Carved positions with this AZ value
            req_char = AZ[req_val]
            options  = list(K4_POS.get(req_char, []))
            if not options:
                return []
            reqs.append((pos, options))

        # All-different backtracking within this slot
        results = []
        def bt_slot(idx, asgn, used):
            if idx == len(reqs):
                results.append(dict(asgn))
                return
            pos, opts = reqs[idx]
            for cp in opts:
                if cp not in used:
                    asgn[pos] = cp
                    used.add(cp)
                    bt_slot(idx + 1, asgn, used)
                    del asgn[pos]
                    used.remove(cp)
        bt_slot(0, {}, set())
        return results

    # Enumerate solutions across all slots (combining with all-different across slots)
    solutions = []

    def bt_slots(slot_idx, combined_asgn, used_carved):
        if len(solutions) >= max_solutions:
            return
        if slot_idx == n_slots:
            solutions.append(dict(combined_asgn))
            return
        s      = unique_slots[slot_idx]
        smembs = slots[s]

        # Try each key value for this slot
        kv_order = list(range(26))
        rng.shuffle(kv_order)
        for kv in kv_order:
            slot_assgns = slot_assignments(smembs, kv)
            rng.shuffle(slot_assgns)
            for sa_partial in slot_assgns:
                # Check all-different with already assigned
                if any(v in used_carved for v in sa_partial.values()):
                    continue
                for pos, cp in sa_partial.items():
                    combined_asgn[pos] = cp
                    used_carved.add(cp)
                bt_slots(slot_idx + 1, combined_asgn, used_carved)
                for pos in sa_partial:
                    del combined_asgn[pos]
                    used_carved.remove(sa_partial[pos])
            if len(solutions) >= max_solutions:
                break

    bt_slots(0, {}, set())
    log(f"  Found {len(solutions)} period-{period}/{cipher} solutions")
    return solutions

def recover_key_from_partial(partial, cipher, period, alpha='AZ'):
    """
    Given a partial σ that satisfies period-p keystream constraint,
    recover the key character for each slot.
    Returns key string of length period (using slot assignments from crib positions).
    """
    aidx = AZ_IDX if alpha == 'AZ' else KA_IDX
    slots = defaultdict(list)
    for pos, pt_char in zip(CRIB_POS, CRIB_PT):
        slots[pos % period].append((pos, AZ_IDX[pt_char]))

    key_chars = ['?'] * period
    for s, members in slots.items():
        pos0, pt_idx0 = members[0]
        if pos0 not in partial:
            continue
        carved_val = AZ_IDX[K4[partial[pos0]]]
        if cipher == 'vig':
            kv = (carved_val - pt_idx0) % 26
        else:
            kv = (carved_val + pt_idx0) % 26
        key_chars[s] = AZ[kv]
    return ''.join(key_chars)

# ── Phase 1: Key-specific CSP + Deep SA ───────────────────────────────────────
_GQA = None  # global quadgram array for worker pool

def _init_worker(qa):
    global _GQA
    _GQA = qa
    random.seed()
    np.random.seed()

def _worker_phase1(args):
    """Worker: (kw, cipher, alpha, partial_dict, sa_steps, seed) → result dict."""
    kw, cipher, alpha, partial_dict, sa_steps, seed = args
    QA = _GQA
    D  = make_dec(kw, cipher, alpha)

    bsig, bsc, bpt = sa_deep(partial_dict, D, QA, n_steps=sa_steps, seed=seed)

    ene_at, bc_at, ene_any, bc_any = check(bpt)
    return {
        'kw': kw, 'cipher': cipher, 'alpha': alpha,
        'pt': bpt, 'sc': bsc, 'spc': bsc / (N - 3),
        'ene_at': ene_at, 'bc_at': bc_at,
        'ene_any': ene_any, 'bc_any': bc_any,
        'hit': (ene_any >= 0 or bc_any >= 0),
        'sig': bsig.tolist(),
    }

def run_phase1(QA, configs, n_partials_per_config=30, n_seeds=5,
               sa_steps=300000, workers=None):
    """
    Phase 1: For each (kw, cipher, alpha), do CSP to get partial σ,
    then deep SA on free positions.
    """
    if workers is None:
        workers = max(1, cpu_count() - 1)

    log(f"\n{'='*70}")
    log(f"PHASE 1: Key-specific CSP + Deep SA ({sa_steps:,} steps)")
    log(f"  Configs: {len(configs)}  partials_each: {n_partials_per_config}  "
        f"seeds_each: {n_seeds}  workers: {workers}")
    log(f"  CRIB POSITIONS FIXED: ENE@{ENE_START}, BC@{BC_START}")
    log(f"{'='*70}")

    all_results = []
    all_hits    = []

    for kw, cipher, alpha in configs:
        t0 = time.time()

        # Compute expected CT at crib positions
        exp = expected_ct_at_cribs(kw, cipher, alpha)
        if exp is None:
            log(f"  SKIP {kw}/{cipher}/{alpha}: key chars not in alphabet")
            continue

        # Feasibility check
        needs = Counter(exp.values())
        feasible = True
        for ch, cnt in needs.items():
            if K4_CHAR.get(ch, 0) < cnt:
                log(f"  INFEASIBLE {kw}/{cipher}/{alpha}: "
                    f"need {cnt} '{ch}', have {K4_CHAR.get(ch, 0)}")
                feasible = False
                break
        if not feasible:
            continue

        # Log forced constraints
        log(f"\n  Config: {kw}/{cipher}/{alpha}")
        forced_info = {}
        for ch, cnt in sorted(needs.items()):
            have = K4_CHAR.get(ch, 0)
            forced_info[ch] = (cnt, have)
            if have == cnt:
                log(f"    FORCED: {ch} ×{cnt} → positions {K4_POS[ch]}")
            else:
                log(f"    {ch}: need {cnt}, have {have}")

        # CSP to get partial σ assignments
        csp_t0 = time.time()
        partials = csp_partial_sigmas(exp, maxr=n_partials_per_config * 10,
                                      randomize=True, seed=42)
        log(f"    CSP: {len(partials)} solutions in {time.time()-csp_t0:.2f}s")

        if not partials:
            log(f"    No CSP solutions!")
            continue

        # Sample partials
        random.shuffle(partials)
        selected = partials[:n_partials_per_config]

        # Build task list for worker pool
        tasks = []
        for i, partial in enumerate(selected):
            for seed in range(n_seeds):
                tasks.append((kw, cipher, alpha, partial, sa_steps,
                               i * 1000 + seed))

        log(f"    Running {len(tasks)} SA tasks ({len(selected)} partials × {n_seeds} seeds)...")

        config_results = []
        with Pool(workers, initializer=_init_worker, initargs=(QA,)) as pool:
            for r in pool.imap_unordered(_worker_phase1, tasks, chunksize=4):
                config_results.append(r)
                if r['hit']:
                    log(f"\n    {'!'*60}")
                    log(f"    !!! CRIB HIT: {kw}/{cipher}/{alpha}")
                    log(f"    !!! ENE@21={r['ene_at']} BC@63={r['bc_at']}")
                    log(f"    !!! ENE_any@{r['ene_any']} BC_any@{r['bc_any']}")
                    log(f"    !!! PT: {r['pt']}")
                    log(f"    {'!'*60}")
                    all_hits.append(r)
                    # Save immediately
                    with open(os.path.join(OUTDIR,
                              f"CRIB_HIT_{kw}_{cipher}_{alpha}.json"), 'w') as f:
                        json.dump(r, f, indent=2)

        config_results.sort(key=lambda x: -x['spc'])
        all_results.extend(config_results)

        # Summary for this config
        best = config_results[0] if config_results else None
        elapsed = time.time() - t0
        if best:
            log(f"    Best spc={best['spc']:.4f}  "
                f"ENE_at={best['ene_at']} BC_at={best['bc_at']}  "
                f"ENE_any={best['ene_any']} BC_any={best['bc_any']}")
            log(f"    Best PT: {best['pt']}")
            log(f"    Elapsed: {elapsed:.1f}s")

        # Save intermediate
        all_results.sort(key=lambda x: -x['spc'])
        with open(os.path.join(OUTDIR, 'phase1_results.json'), 'w') as f:
            json.dump(all_results[:200], f, indent=2)

    return all_results, all_hits

# ── Phase 2: Model-free periodic keystream + key recovery + SA ────────────────
def run_phase2(QA, periods=(7, 10, 8, 6, 5), ciphers=('vig', 'beau'),
               n_solutions=500, sa_steps=300000, workers=None):
    """
    Phase 2: Model-free period search.
    For each (period, cipher): enumerate partial σ where keystream at crib
    positions is periodic. Recover candidate key, then run SA.
    """
    if workers is None:
        workers = max(1, cpu_count() - 1)

    log(f"\n{'='*70}")
    log("PHASE 2: Model-free periodic keystream search")
    log(f"{'='*70}")

    all_results = []
    all_hits    = []

    for period in periods:
        for cipher in ciphers:
            log(f"\n  Testing period={period}, cipher={cipher}")
            partials = periodic_keystream_search(period, cipher=cipher,
                                                 max_solutions=n_solutions)
            if not partials:
                log(f"    No solutions found")
                continue

            # For each partial, recover the key and run SA
            tasks = []
            for i, partial in enumerate(partials[:50]):  # top 50 solutions
                kw = recover_key_from_partial(partial, cipher, period)
                if '?' in kw:
                    continue  # incomplete key recovery
                for seed in range(3):
                    tasks.append((kw, cipher, 'AZ', partial, sa_steps,
                                  i * 100 + seed))

                # Also try KA alphabet
                kw_ka = recover_key_from_partial(partial, cipher, period, alpha='KA')
                if '?' not in kw_ka:
                    for seed in range(2):
                        tasks.append((kw_ka, cipher, 'KA', partial, sa_steps,
                                      i * 100 + seed + 50))

            if not tasks:
                continue

            log(f"    Running {len(tasks)} SA tasks for period-{period}/{cipher}...")

            config_results = []
            with Pool(workers, initializer=_init_worker, initargs=(QA,)) as pool:
                for r in pool.imap_unordered(_worker_phase1, tasks, chunksize=4):
                    r['period'] = period
                    config_results.append(r)
                    if r['hit']:
                        log(f"\n    !!! CRIB HIT (period-{period}/{cipher}): "
                            f"{r['kw']}/{r['cipher']}/{r['alpha']}")
                        log(f"    !!! PT: {r['pt']}")
                        all_hits.append(r)
                        with open(os.path.join(OUTDIR,
                                  f"CRIB_HIT_p{period}_{cipher}_{r['kw']}.json"), 'w') as f:
                            json.dump(r, f, indent=2)

            config_results.sort(key=lambda x: -x['spc'])
            all_results.extend(config_results)

            if config_results:
                best = config_results[0]
                log(f"    Best spc={best['spc']:.4f}  key={best['kw']}  "
                    f"ENE_at={best['ene_at']} BC_at={best['bc_at']}")
                log(f"    Best PT: {best['pt'][:60]}...")

    return all_results, all_hits

# ── Phase 3: Focused deep SA on top configs ───────────────────────────────────
def run_phase3_focused(QA, top_configs=None, n_partials=50, n_seeds=10,
                       sa_steps=500000, workers=None):
    """
    Phase 3: Deep SA with even more iterations on the most promising configs.
    Uses KRYPTOS/vig/AZ as primary, Beaufort variants as secondary.
    """
    if workers is None:
        workers = max(1, cpu_count() - 1)

    if top_configs is None:
        top_configs = [
            ('KRYPTOS', 'vig',  'AZ'),
            ('KRYPTOS', 'beau', 'AZ'),
            ('KRYPTOS', 'vig',  'KA'),
        ]

    log(f"\n{'='*70}")
    log(f"PHASE 3: Focused deep SA ({sa_steps:,} steps)")
    log(f"  Top configs: {top_configs}")
    log(f"{'='*70}")

    all_results = []
    all_hits    = []

    for kw, cipher, alpha in top_configs:
        exp = expected_ct_at_cribs(kw, cipher, alpha)
        if exp is None:
            continue

        needs = Counter(exp.values())
        feasible = all(K4_CHAR.get(ch, 0) >= cnt for ch, cnt in needs.items())
        if not feasible:
            continue

        log(f"\n  {kw}/{cipher}/{alpha}: generating {n_partials} diverse partials...")

        # Get many diverse CSP solutions
        partials = csp_partial_sigmas(exp, maxr=n_partials * 10,
                                      randomize=True, seed=99)
        random.shuffle(partials)
        selected = partials[:n_partials]
        log(f"    Got {len(partials)} CSP solutions, using {len(selected)}")

        tasks = [(kw, cipher, alpha, p, sa_steps, i * 10000 + s)
                 for i, p in enumerate(selected)
                 for s in range(n_seeds)]

        log(f"    {len(tasks)} SA tasks...")

        config_results = []
        with Pool(workers, initializer=_init_worker, initargs=(QA,)) as pool:
            for idx, r in enumerate(pool.imap_unordered(_worker_phase1, tasks, chunksize=2)):
                config_results.append(r)
                if r['hit']:
                    log(f"\n    !!! PHASE 3 CRIB HIT: {kw}/{cipher}/{alpha}")
                    log(f"    !!! PT: {r['pt']}")
                    all_hits.append(r)
                    with open(os.path.join(OUTDIR,
                              f"P3_CRIB_HIT_{kw}_{cipher}_{alpha}.json"), 'w') as f:
                        json.dump(r, f, indent=2)
                if (idx + 1) % 20 == 0:
                    done = config_results
                    done.sort(key=lambda x: -x['spc'])
                    log(f"    [{idx+1}/{len(tasks)}] best spc={done[0]['spc']:.4f}  "
                        f"PT: {done[0]['pt'][:55]}")

        config_results.sort(key=lambda x: -x['spc'])
        all_results.extend(config_results)

        log(f"  {kw}/{cipher}/{alpha} done. "
            f"Best spc={config_results[0]['spc']:.4f}")
        log(f"  Best PT: {config_results[0]['pt']}")

        # Save
        all_results.sort(key=lambda x: -x['spc'])
        with open(os.path.join(OUTDIR, 'phase3_results.json'), 'w') as f:
            json.dump(all_results[:200], f, indent=2)

    return all_results, all_hits

# ── Keystream periodicity checker (diagnostic) ────────────────────────────────
def keystream_period_diagnostic(partial, cipher='vig'):
    """
    Given a partial σ (24 crib positions), compute keystream values
    and check which periods are consistent.
    """
    ks = {}
    for pos, pt_char in zip(CRIB_POS, CRIB_PT):
        if pos not in partial:
            continue
        carved_char = K4[partial[pos]]
        cv = AZ_IDX[carved_char]
        pv = AZ_IDX[pt_char]
        if cipher == 'vig':
            ks[pos] = (cv - pv) % 26
        else:
            ks[pos] = (cv + pv) % 26

    results = {}
    for p in range(2, 14):
        # Check period-p consistency
        slots = defaultdict(set)
        for pos, kv in ks.items():
            slots[pos % p].add(kv)
        consistent = all(len(v) == 1 for v in slots.values())
        if consistent:
            key = ''.join(AZ[list(slots[s])[0]] for s in range(p))
            results[p] = key
    return results

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    log("=" * 70)
    log("K4 Model 2 Constraint-Based Solver v2")
    log(f"K4  = {K4}")
    log(f"N   = {N}")
    log(f"CPUs = {cpu_count()}")
    log(f"CRIB POSITIONS: ENE@{ENE_START}-{ENE_START+len(ENE)-1}  "
        f"BC@{BC_START}-{BC_START+len(BC)-1}")
    log("=" * 70)
    T_global = time.time()

    # Load quadgrams
    log("\nLoading quadgrams...")
    qgd = load_qg('data/english_quadgrams.json')
    QA  = make_qg_arr(qgd)
    log(f"  {len(qgd):,} quadgrams loaded")

    workers = max(1, cpu_count() - 1)
    log(f"  Using {workers} worker processes")

    # ── Pre-analysis: forced constraints for top configs ──
    log("\n=== PRE-ANALYSIS: Forced constraints ===")
    for kw, cipher, alpha in [('KRYPTOS','vig','AZ'), ('KRYPTOS','beau','AZ'),
                               ('KRYPTOS','vig','KA'), ('KRYPTOS','beau','KA')]:
        exp = expected_ct_at_cribs(kw, cipher, alpha)
        if exp is None:
            continue
        log(f"\n  {cipher}/{kw}/{alpha}:")
        needs = Counter(exp.values())
        for ch, cnt in sorted(needs.items()):
            have = K4_CHAR.get(ch, 0)
            marker = " ← FORCED" if have == cnt else ""
            marker += " ← IMPOSSIBLE" if have < cnt else ""
            log(f"    {ch}: need {cnt}, have {have}{marker}  "
                f"carved_positions={K4_POS.get(ch,'none')}")

    # Count CSP solutions for Vig/KRYPTOS/AZ
    log("\n=== CSP solution count for KRYPTOS/vig/AZ ===")
    exp_kryptos = expected_ct_at_cribs('KRYPTOS', 'vig', 'AZ')
    csp_count = count_csp_solutions(exp_kryptos)
    log(f"  KRYPTOS/vig/AZ CSP solutions (capped at 100K): {csp_count}")

    # ── Phase 1: Key-specific CSP + Deep SA ──
    p1_configs = [
        ('KRYPTOS',    'vig',  'AZ'),
        ('KRYPTOS',    'beau', 'AZ'),
        ('KRYPTOS',    'vig',  'KA'),
        ('KRYPTOS',    'beau', 'KA'),
        ('PALIMPSEST', 'vig',  'AZ'),
        ('PALIMPSEST', 'beau', 'AZ'),
        ('ABSCISSA',   'vig',  'AZ'),
        ('ABSCISSA',   'beau', 'AZ'),
        ('SHADOW',     'vig',  'AZ'),
        ('ANTIPODES',  'vig',  'AZ'),
    ]

    p1_results, p1_hits = run_phase1(
        QA, p1_configs,
        n_partials_per_config=25,
        n_seeds=6,
        sa_steps=300000,
        workers=workers,
    )

    log(f"\nPhase 1 done. {len(p1_hits)} crib hits, "
        f"{len(p1_results)} total results.")

    # ── Phase 2: Model-free periodic search ──
    p2_results, p2_hits = run_phase2(
        QA,
        periods=(7, 10, 8, 6),
        ciphers=('vig', 'beau'),
        n_solutions=500,
        sa_steps=200000,
        workers=workers,
    )

    log(f"\nPhase 2 done. {len(p2_hits)} crib hits, "
        f"{len(p2_results)} total results.")

    # ── Phase 3: Focused deep SA on top configs ──
    # Only if Phase 1 didn't find hits
    if not (p1_hits or p2_hits):
        p3_results, p3_hits = run_phase3_focused(
            QA,
            top_configs=[('KRYPTOS', 'vig', 'AZ'),
                         ('KRYPTOS', 'beau', 'AZ'),
                         ('KRYPTOS', 'vig', 'KA')],
            n_partials=50,
            n_seeds=8,
            sa_steps=600000,
            workers=workers,
        )
    else:
        p3_results, p3_hits = [], []
        log("\nPhase 3 SKIPPED (Phase 1/2 found hits)")

    # ── Final summary ──
    all_results = p1_results + p2_results + p3_results
    all_hits    = p1_hits    + p2_hits    + p3_hits
    all_results.sort(key=lambda x: -x['spc'])

    log("\n" + "=" * 70)
    log("FINAL SUMMARY")
    log(f"Total elapsed: {time.time() - T_global:.0f}s")
    log(f"Total results: {len(all_results)}")
    log(f"Crib hits: {len(all_hits)}")

    if all_hits:
        log("\n*** CRIB HITS ***")
        for h in all_hits:
            log(f"  {h['kw']}/{h['cipher']}/{h['alpha']}  "
                f"spc={h['spc']:.4f}  "
                f"ENE@21={h['ene_at']} BC@63={h['bc_at']}  "
                f"ENE_any={h['ene_any']} BC_any={h['bc_any']}")
            log(f"  PT: {h['pt']}")

    log("\nTop 20 by qg/char:")
    for r in all_results[:20]:
        log(f"  {r['kw']:<12}/{r['cipher']}/{r['alpha']}  "
            f"spc={r['spc']:.4f}  "
            f"ENE_at={r.get('ene_at', False)}  BC_at={r.get('bc_at', False)}  "
            f"ENE_any={r.get('ene_any', -1)}  BC_any={r.get('bc_any', -1)}")
        log(f"    PT: {r['pt']}")

    # Save final
    with open(os.path.join(OUTDIR, 'v2_final_results.json'), 'w') as f:
        json.dump(all_results[:300], f, indent=2)
    with open(os.path.join(OUTDIR, 'v2_hits.json'), 'w') as f:
        json.dump(all_hits, f, indent=2)
    log(f"\nSaved results to {OUTDIR}/v2_*.json")

if __name__ == '__main__':
    main()
