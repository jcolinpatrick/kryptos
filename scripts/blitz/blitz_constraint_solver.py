#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_constraint_solver.py — Constraint-based K4 permutation search.

PARADIGM (ground truth):
  PT → simple substitution (Vig/Beau) → REAL CT → SCRAMBLE (sigma) → K4 carved

Goal: find sigma s.t. real_CT[i] = K4[sigma[i]] and
  decrypt(real_CT, key, cipher) contains EASTNORTHEAST and BERLINCLOCK

CRIB POSITIONS IN REAL CT ARE UNKNOWN  — we search all (p1, p2) × all params.

Phases:
  1  Diagnostic + Approach B (frequency chi2)
  2  Approach A/D: crib-constrained partial perm + SA (KRYPTOS, all positions)
  3  Approach A/D: all 14 keywords (fast scan)
  4  Approach F:  genetic algorithm (long, top configs)
  5  Approach G:  Monte Carlo baseline

Run: PYTHONPATH=src python3 -u scripts/blitz_constraint_solver.py
"""

import json, os, sys, time, random, math
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count
import numpy as np

# ── I/O ────────────────────────────────────────────────────────────────────────
OUTDIR  = 'blitz_results/constraint_solver'
os.makedirs(OUTDIR, exist_ok=True)
_LFH    = None          # log file handle (set in main)

def log(msg):
    ts   = time.strftime('%H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    if _LFH:
        _LFH.write(line + '\n')
        _LFH.flush()

def save(name, obj):
    path = os.path.join(OUTDIR, name)
    with open(path, 'w') as fh:
        json.dump(obj, fh, indent=2)
    log(f"  Saved {path}")

# ── Constants ─────────────────────────────────────────────────────────────────
K4   = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA   = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ENE  = "EASTNORTHEAST"
BC   = "BERLINCLOCK"
N    = 97

KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN',
            'SCHEIDT','BERLIN','CLOCK','EAST','NORTH','LIGHT',
            'ANTIPODES','MEDUSA','ENIGMA']

AZ_IDX  = {c: i for i, c in enumerate(AZ)}
KA_IDX  = {c: i for i, c in enumerate(KA)}
K4_INT  = np.array([AZ_IDX[c] for c in K4], dtype=np.int32)
K4_CHAR = Counter(K4)
K4_POS  = defaultdict(list)
for _i, _c in enumerate(K4):
    K4_POS[_c].append(_i)

# ── Quadgrams ─────────────────────────────────────────────────────────────────
def load_qg(path='data/english_quadgrams.json'):
    with open(path) as f:
        return json.load(f)

def make_qg_arr(qg_dict):
    A = np.full((26,26,26,26), -10.0, dtype=np.float32)
    for k, v in qg_dict.items():
        if len(k) == 4 and k.isalpha():
            ix = [AZ_IDX.get(c,-1) for c in k.upper()]
            if all(0 <= x < 26 for x in ix):
                A[ix[0],ix[1],ix[2],ix[3]] = float(v)
    return A

# ── Decryption table ──────────────────────────────────────────────────────────
def make_dec(kw, cipher, alpha):
    """dec[phase, ct_az] = pt_az.  Shape (period, 26)."""
    period   = len(kw)
    astr     = AZ if alpha == 'AZ' else KA
    aidx     = AZ_IDX if alpha == 'AZ' else KA_IDX
    D        = np.zeros((period, 26), dtype=np.int32)
    for ph in range(period):
        ki = aidx.get(kw[ph], -1)
        if ki < 0: continue
        for ca in range(26):
            ci = aidx.get(AZ[ca], -1)
            if ci < 0: continue
            pi = ((ci - ki) if cipher == 'vig' else (ki - ci)) % 26
            D[ph, ca] = AZ_IDX[astr[pi]]
    return D

# ── Expected CT chars for a crib ─────────────────────────────────────────────
def crib_expected_ct(crib, start, kw, cipher, alpha):
    """Return [(real_ct_pos, required_k4_char), ...] or None."""
    astr  = AZ if alpha == 'AZ' else KA
    aidx  = AZ_IDX if alpha == 'AZ' else KA_IDX
    per   = len(kw)
    out   = []
    for k, c in enumerate(crib):
        pos = start + k
        pi  = aidx.get(c, -1)
        ki  = aidx.get(kw[pos % per], -1)
        if pi < 0 or ki < 0: return None
        ci  = ((pi + ki) if cipher == 'vig' else (ki - pi)) % 26
        out.append((pos, astr[ci]))
    return out

# ── Scoring ───────────────────────────────────────────────────────────────────
def score_sigma(sig, D, QA):
    ph  = np.arange(N, dtype=np.int32) % D.shape[0]
    ct  = K4_INT[sig]
    pt  = D[ph, ct]
    s   = 0.0
    for i in range(N - 3):
        s += float(QA[pt[i], pt[i+1], pt[i+2], pt[i+3]])
    return s

def pt_str(sig, D):
    ph = np.arange(N, dtype=np.int32) % D.shape[0]
    ct = K4_INT[sig]
    pt = D[ph, ct]
    return ''.join(AZ[x] for x in pt)

# ── SA with delta scoring ─────────────────────────────────────────────────────
def sa(sig0, fixed, D, QA, n=2000, T0=7.0, Tf=0.05):
    """SA over free positions; fixed positions pinned. Returns (best_sig, score)."""
    sig    = sig0.copy()
    ph     = np.arange(N, dtype=np.int32) % D.shape[0]
    free   = np.array([i for i in range(N) if i not in fixed], dtype=np.int32)
    nf     = len(free)
    if nf < 2:
        return sig.copy(), score_sigma(sig, D, QA)

    ct  = K4_INT[sig].copy()
    pt  = D[ph, ct].copy()

    def qsum(p):
        s = 0.0
        for st in range(max(0, p-3), min(N-3, p+1)):
            s += float(QA[pt[st],pt[st+1],pt[st+2],pt[st+3]])
        return s

    cur  = sum(float(QA[pt[i],pt[i+1],pt[i+2],pt[i+3]]) for i in range(N-3))
    best = cur;  bsig = sig.copy()
    lr   = math.log(Tf / T0)

    for step in range(n):
        T  = T0 * math.exp(lr * step / n)
        ia = random.randint(0, nf-1)
        ib = random.randint(0, nf-2)
        if ib >= ia: ib += 1
        i  = int(free[ia]);  j = int(free[ib])

        oi = qsum(i);  oj = qsum(j)
        sig[i],sig[j] = sig[j],sig[i]
        ct[i],ct[j]   = ct[j],ct[i]
        pt[i] = int(D[ph[i], ct[i]]);  pt[j] = int(D[ph[j], ct[j]])

        if abs(i-j) < 4:
            new = sum(float(QA[pt[k],pt[k+1],pt[k+2],pt[k+3]]) for k in range(N-3))
        else:
            new = cur + qsum(i) + qsum(j) - oi - oj

        d = new - cur
        if d > 0 or (T > 1e-12 and random.random() < math.exp(d / T)):
            cur = new
            if new > best: best = new;  bsig = sig.copy()
        else:
            sig[i],sig[j] = sig[j],sig[i]
            ct[i],ct[j]   = ct[j],ct[i]
            pt[i] = int(D[ph[i], ct[i]]);  pt[j] = int(D[ph[j], ct[j]])

    return bsig, best

# ── Backtracking for valid partial sigmas ─────────────────────────────────────
def partial_sigmas(constraints, maxr=15):
    """
    constraints: [(real_ct_pos, k4_char), ...]
    Returns list of dicts {pos: k4_idx} satisfying all-different.
    """
    pos_l  = [c[0] for c in constraints]
    ch_l   = [c[1] for c in constraints]
    needed = Counter(ch_l)
    for ch, cnt in needed.items():
        if K4_CHAR.get(ch, 0) < cnt: return []

    avail   = [list(K4_POS[ch]) for ch in ch_l]
    results = []

    def bt(idx, used, asgn):
        if len(results) >= maxr: return
        if idx == len(pos_l):
            results.append(asgn.copy()); return
        for kp in avail[idx]:
            if kp not in used:
                used.add(kp);  asgn[pos_l[idx]] = kp
                bt(idx+1, used, asgn)
                used.discard(kp);  del asgn[pos_l[idx]]

    bt(0, set(), {})
    return results

# ── Worker (pool) ─────────────────────────────────────────────────────────────
_GQA = None   # global quadgram array per worker

def _init(qa):
    global _GQA
    _GQA = qa
    random.seed()
    np.random.seed()

def _worker(args):
    """Process one (p1, p2, kw, cipher, alpha, sa_iters, max_partials) config."""
    p1, p2, kw, cipher, alpha, sa_iters, max_partials = args
    QA = _GQA

    ec = crib_expected_ct(ENE, p1, kw, cipher, alpha)
    if ec is None: return []
    bc = crib_expected_ct(BC,  p2, kw, cipher, alpha)
    if bc is None: return []

    cd  = {};  ok = True
    for pos, ch in ec + bc:
        if pos in cd and cd[pos] != ch: ok = False; break
        cd[pos] = ch
    if not ok: return []

    needed = Counter(cd.values())
    for ch, cnt in needed.items():
        if K4_CHAR.get(ch, 0) < cnt: return []

    parts = partial_sigmas(list(cd.items()), maxr=max_partials)
    if not parts: return []

    D       = make_dec(kw, cipher, alpha)
    all_k4  = set(range(N))
    results = []

    for part in parts:
        used   = set(part.values())
        free_k = list(all_k4 - used)
        free_r = [i for i in range(N) if i not in part]
        random.shuffle(free_k)
        sig = np.zeros(N, dtype=np.int32)
        for rp, kp in part.items(): sig[rp] = kp
        for idx, rp in enumerate(free_r): sig[rp] = free_k[idx]

        bsig, bsc = sa(sig, set(part.keys()), D, QA, n=sa_iters)
        pt        = pt_str(bsig, D)
        ene       = pt.find(ENE)
        bc_p      = pt.find(BC)

        results.append({
            'p1': p1, 'p2': p2, 'kw': kw, 'cipher': cipher, 'alpha': alpha,
            'pt': pt, 'sc': bsc, 'spc': bsc/(N-3),
            'ene': ene, 'bc': bc_p,
            'hit': (ene >= 0 or bc_p >= 0),
            'sig': bsig.tolist(),
        })

    return results

# ── Approach A/D ──────────────────────────────────────────────────────────────
def run_AD(QA, workers, keyword_subset=None, sa_iters=500, max_partials=10,
           label='AD'):
    kws = keyword_subset if keyword_subset else KEYWORDS
    log(f"=== {label}: kws={kws}  sa_iters={sa_iters}  max_partials={max_partials} ===")

    params = []
    for p1 in range(N - len(ENE) + 1):
        for p2 in range(N - len(BC) + 1):
            if not (p2 >= p1 + len(ENE) or p2 + len(BC) <= p1): continue
            for kw in kws:
                for ci in ['vig','beau']:
                    for al in ['AZ','KA']:
                        params.append((p1, p2, kw, ci, al, sa_iters, max_partials))

    log(f"  Param sets: {len(params):,}   workers: {workers}")

    hits = [];  best_all = [];  nd = 0;  t0 = time.time()
    CHUNK = max(1, min(200, len(params) // (workers * 8)))

    with Pool(workers, initializer=_init, initargs=(QA,)) as pool:
        for batch in pool.imap_unordered(_worker, params, chunksize=CHUNK):
            nd += 1
            if nd % 5000 == 0:
                el   = time.time() - t0
                rate = nd / el
                eta  = (len(params) - nd) / max(rate, 0.001)
                log(f"  {nd:,}/{len(params):,}  {100*nd/len(params):.1f}%  "
                    f"rate={rate:.0f}/s  ETA={eta:.0f}s  hits={len(hits)}")
            for r in batch:
                if r['hit']:
                    hits.append(r)
                    log(f"  *** HIT p1={r['p1']} p2={r['p2']} "
                        f"{r['kw']}/{r['cipher']}/{r['alpha']}  "
                        f"ENE@{r['ene']} BC@{r['bc']}")
                    log(f"      {r['pt']}")
                best_all.append(r)

    best_all.sort(key=lambda r: -r['spc'])
    el = time.time() - t0
    log(f"  Done {el:.0f}s  hits={len(hits)}")
    log(f"  Top-10 spc:")
    for r in best_all[:10]:
        log(f"    p1={r['p1']:2d} p2={r['p2']:2d} {r['kw']:<12} "
            f"{r['cipher']}/{r['alpha']}  spc={r['spc']:.3f}  "
            f"ENE={r['ene']}  BC={r['bc']}  {r['pt'][:55]}")
    save(f'{label}_results.json', {'hits': hits, 'top30': best_all[:30]})
    return hits, best_all

# ── Approach F: Genetic algorithm ────────────────────────────────────────────
def run_GA(kw, cipher, alpha, QA, pop=350, gens=4000, mut=0.025):
    log(f"=== GA {kw}/{cipher}/{alpha} pop={pop} gens={gens} ===")
    random.seed(); np.random.seed()
    D = make_dec(kw, cipher, alpha)

    def fit(s): return score_sigma(np.array(s, dtype=np.int32), D, QA)

    pop_list = [random.sample(range(N), N) for _ in range(pop)]
    scores   = [fit(s) for s in pop_list]
    best_s   = max(scores);  bi = scores.index(best_s)
    best_p   = pop_list[bi][:];  best_pt = pt_str(np.array(best_p, dtype=np.int32), D)
    last_log = time.time()
    nelite   = max(2, int(pop * 0.05))

    def ox(a, b):
        lo, hi = sorted(random.sample(range(N), 2))
        child  = [-1]*N;  child[lo:hi+1] = a[lo:hi+1]
        cset   = set(a[lo:hi+1])
        rem    = [x for x in b if x not in cset]
        j = 0
        for k in list(range(hi+1, N)) + list(range(hi+1)):
            if child[k] < 0: child[k] = rem[j]; j += 1
        return child

    for g in range(gens):
        order  = sorted(range(pop), key=lambda x: -scores[x])
        elite  = [pop_list[o][:] for o in order[:nelite]]
        new_p  = elite[:]
        while len(new_p) < pop:
            def t():
                cs = random.sample(range(pop), 4)
                return pop_list[max(cs, key=lambda x: scores[x])]
            child = ox(t(), t())
            if random.random() < mut:
                a, b = random.sample(range(N), 2); child[a],child[b]=child[b],child[a]
            if random.random() < mut*0.4:
                a, b = sorted(random.sample(range(N), 2)); child[a:b+1]=child[a:b+1][::-1]
            new_p.append(child)
        pop_list = new_p;  scores = [fit(s) for s in pop_list]
        cb = max(scores)
        if cb > best_s:
            best_s  = cb;  bi = scores.index(cb)
            best_p  = pop_list[bi][:];  best_pt = pt_str(np.array(best_p,dtype=np.int32),D)
            en, bc_ = best_pt.find(ENE), best_pt.find(BC)
            log(f"  [GA g={g:4d}] NEW BEST spc={best_s/(N-3):.3f}  "
                f"ENE={en} BC={bc_}  {best_pt[:45]}")
            if en >= 0 or bc_ >= 0:
                log(f"  *** GA CRIB HIT! PT: {best_pt}")
        if time.time()-last_log > 20:
            log(f"  [GA g={g:4d}/{gens}] best={best_s/(N-3):.3f}")
            last_log = time.time()

    en, bc_ = best_pt.find(ENE), best_pt.find(BC)
    return best_p, best_s, best_pt, en, bc_

# ── Approach B: Chi-squared frequency filter ─────────────────────────────────
def run_B():
    log("=== Approach B: chi-squared frequency filter ===")
    EF = {'E':0.127,'T':0.091,'A':0.082,'O':0.075,'I':0.070,'N':0.067,
          'S':0.063,'H':0.061,'R':0.060,'D':0.043,'L':0.040,'C':0.028,
          'U':0.028,'M':0.024,'W':0.024,'F':0.022,'G':0.020,'Y':0.020,
          'P':0.019,'B':0.015,'V':0.010,'K':0.008,'J':0.002,'X':0.002,
          'Q':0.001,'Z':0.001}
    ech = list(EF.keys());  ep = [EF[c] for c in ech]
    res = []
    for kw in KEYWORDS:
        for ci in ['vig','beau']:
            for al in ['AZ','KA']:
                astr = AZ if al=='AZ' else KA
                aidx = AZ_IDX if al=='AZ' else KA_IDX
                per  = len(kw);  cnt = Counter()
                for trial in range(6000):
                    pos = trial % N
                    r = random.random(); cum=0.0; pc='E'
                    for c,p in zip(ech,ep):
                        cum+=p
                        if r<=cum: pc=c; break
                    pi = aidx.get(pc,0); ki = aidx.get(kw[pos%per],0)
                    ci_ = ((pi+ki) if ci=='vig' else (ki-pi))%26
                    cnt[astr[ci_]] += 1
                tot = sum(cnt.values())
                chi2 = sum((K4_CHAR.get(c,0)-cnt.get(c,0)/tot*N)**2/max(cnt.get(c,0)/tot*N,0.01)
                           for c in AZ)
                res.append({'kw':kw,'cipher':ci,'alpha':al,'chi2':chi2})
    res.sort(key=lambda r:r['chi2'])
    log("  Top-10:")
    for r in res[:10]:
        log(f"    {r['kw']:<12} {r['cipher']}/{r['alpha']}  chi2={r['chi2']:.2f}")
    save('approach_B.json', res)
    return res

# ── Approach G: Monte Carlo baseline ─────────────────────────────────────────
def run_G(QA):
    log("=== Approach G: Monte Carlo baseline ===")
    configs = [('KRYPTOS','vig','KA'),('KRYPTOS','beau','KA'),
               ('KRYPTOS','vig','AZ'),('PALIMPSEST','vig','AZ'),('ABSCISSA','beau','AZ')]
    res = []
    for kw,ci,al in configs:
        D = make_dec(kw,ci,al)
        best=-1e9; bpt=None; base=list(range(N))
        for _ in range(40000):
            sig = np.array(random.sample(base,N),dtype=np.int32)
            sc  = score_sigma(sig,D,QA)
            if sc>best: best=sc; bpt=pt_str(sig,D)
        en,bc_=bpt.find(ENE),bpt.find(BC)
        log(f"  [MC] {kw}/{ci}/{al}  spc={best/(N-3):.3f}  ENE={en} BC={bc_}  {bpt[:40]}")
        res.append({'kw':kw,'cipher':ci,'alpha':al,'sc':best,'spc':best/(N-3),
                    'pt':bpt,'ene':en,'bc':bc_})
    save('approach_G.json', res)
    return res

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global _LFH
    _LFH = open(os.path.join(OUTDIR,'run_log.txt'),'w',buffering=1)

    log("="*70)
    log("K4 Constraint Solver")
    log(f"K4 = {K4}")
    log(f"CPUs = {cpu_count()}")
    log("="*70)
    T0 = time.time()

    # Load quadgrams
    log("Loading quadgrams...")
    qgd  = load_qg(path='data/english_quadgrams.json')
    QA   = make_qg_arr(qgd)
    log(f"  {len(qgd):,} quadgrams loaded")

    ncpu = max(1, cpu_count() - 1)

    # Phase 1: Approach B
    b_res = run_B()
    top_kws = list(dict.fromkeys(r['kw'] for r in b_res[:8]))[:4]
    log(f"  Top 4 keywords from B: {top_kws}")
    log("")

    # Phase 1b: MC baseline
    g_res = run_G(QA)
    log("")

    # Phase 2: A/D fast scan — KRYPTOS only, all positions
    ad2_hits, ad2_best = run_AD(QA, ncpu, keyword_subset=['KRYPTOS'],
                                sa_iters=800, max_partials=15, label='AD_KRYPTOS')
    log("")

    # Phase 3: A/D fast scan — top 4 keywords (skip KRYPTOS already done)
    extra_kws = [k for k in top_kws if k != 'KRYPTOS']
    if extra_kws:
        ad3_hits, ad3_best = run_AD(QA, ncpu, keyword_subset=extra_kws,
                                    sa_iters=500, max_partials=10, label='AD_TOP4')
    else:
        ad3_hits, ad3_best = [], []
    log("")

    # Phase 4: A/D — remaining keywords
    rem_kws = [k for k in KEYWORDS if k not in top_kws]
    ad4_hits, ad4_best = run_AD(QA, ncpu, keyword_subset=rem_kws,
                                sa_iters=400, max_partials=8, label='AD_REST')
    log("")

    # Phase 5: Genetic algorithm — top configs from B
    ga_configs = [
        ('KRYPTOS',    'vig',  'KA'),
        ('KRYPTOS',    'beau', 'KA'),
        ('KRYPTOS',    'vig',  'AZ'),
        ('KRYPTOS',    'beau', 'AZ'),
        ('PALIMPSEST', 'vig',  'AZ'),
        ('ABSCISSA',   'beau', 'AZ'),
        ('SHADOW',     'vig',  'AZ'),
        ('ANTIPODES',  'vig',  'AZ'),
    ]
    log("=== Approach F: Genetic Algorithm ===")
    ga_res = []
    for kw, ci, al in ga_configs:
        perm, sc, pt, en, bc_ = run_GA(kw, ci, al, QA, pop=400, gens=5000, mut=0.025)
        r = {'kw':kw,'cipher':ci,'alpha':al,'sc':sc,'spc':sc/(N-3),
             'pt':pt,'ene':en,'bc':bc_,'perm':perm}
        ga_res.append(r)
        log(f"  GA done {kw}/{ci}/{al}  spc={sc/(N-3):.3f}  ENE={en} BC={bc_}  {pt[:50]}")
        if en>=0 or bc_>=0:
            log(f"  *** GA CRIB HIT: {pt}")
    save('approach_F.json', ga_res)
    log("")

    # Summary
    all_hits = list(ad2_hits) + list(ad3_hits) + list(ad4_hits)
    for r in g_res + ga_res:
        if r.get('ene',-1)>=0 or r.get('bc',-1)>=0: all_hits.append(r)

    log("="*70)
    log("FINAL SUMMARY")
    log(f"Total crib hits: {len(all_hits)}")
    for h in all_hits:
        log(f"  {h.get('kw','?')}/{h.get('cipher','?')}/{h.get('alpha','?')} "
            f"ENE={h.get('ene',-1)} BC={h.get('bc',-1)}  {h.get('pt','?')}")

    all_scored = (ad2_best + ad3_best + ad4_best + ga_res + g_res)
    all_scored.sort(key=lambda r:-r.get('spc',r.get('sc',0)/(N-3)))
    log("\nTop-15 by qg/char:")
    for r in all_scored[:15]:
        log(f"  {r.get('kw','?'):<12} {r.get('cipher','?')}/{r.get('alpha','?')}  "
            f"spc={r.get('spc',0):.3f}  ENE={r.get('ene',-1)} BC={r.get('bc',-1)}  "
            f"{r.get('pt','?')[:55]}")

    log(f"\nTotal elapsed: {time.time()-T0:.0f}s")
    save('summary.json', {'hits':all_hits,'top20':all_scored[:20]})
    _LFH.close()

if __name__ == '__main__':
    main()
