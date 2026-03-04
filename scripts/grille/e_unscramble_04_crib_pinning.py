#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-UNSCRAMBLE-04: Crib-Pinning Simulated Annealing
===================================================
Paradigm: carved_K4 = SCRAMBLE(real_CT)
          perm[i] = j  →  real_CT[i] = K4[j]
          Then: PT = decrypt(real_CT, keyword)

KEY INSIGHT from E-UNSCRAMBLE-03:
  - Constraint-driven search → cribs present, surrounding text random/incoherent
  - Hill climbing → coherent English, no cribs
  THIS SCRIPT: pin 24 crib positions (so cribs are guaranteed), then SA-optimize
  the remaining 73 free positions to maximize quadgram score of full 97-char PT.

Expected behavior:
  - If correct cipher/keyword/positions: SA converges to coherent English WITH cribs
  - Score threshold: -4.5+ indicates English-quality text
  - The FORCED constraint (K4[64]=Y → real_CT[29] for KRYPTOS-vig+ENE@21) narrows search

Strategy:
  Phase 1: Quick scan (800 SA iters) over ALL feasible (ene_s, bc_s) pairs per config
  Phase 2: Deep dive (50000 SA iters × 15 seeds) on top-20 pairs + ENE@21/BC@63
"""

import sys, json, math, os, time, random
from collections import Counter, defaultdict

sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as K4_CT

K4 = K4_CT
N  = 97
assert len(K4) == N

AZ  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
KA  = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'

CRIB_ENE = 'EASTNORTHEAST'   # length 13
CRIB_BC  = 'BERLINCLOCK'     # length 11
L_ENE, L_BC = len(CRIB_ENE), len(CRIB_BC)  # 13, 11

# ── Quadgrams ─────────────────────────────────────────────────────────────────
print("[E-04] Loading quadgrams...", flush=True)
_QG = json.load(open('data/english_quadgrams.json'))
_MISS = min(_QG.values()) - 2.0   # penalty for unknown quadgrams

def qscore_str(s):
    """Average log10-prob quadgram score for string s."""
    n = len(s)
    if n < 4: return _MISS
    return sum(_QG.get(s[i:i+4], _MISS) for i in range(n-3)) / (n-3)

print(f"  {len(_QG)} quadgrams loaded, MISS={_MISS:.2f}", flush=True)

# ── Lookup tables ─────────────────────────────────────────────────────────────
_AZI = {c: i for i, c in enumerate(AZ)}   # 'A'→0 … 'Z'→25

def make_kv(keyword, alpha=AZ):
    """Convert keyword string to list of int key values in given alphabet."""
    ai = {c: i for i, c in enumerate(alpha)}
    return [ai[c] for c in keyword if c in ai]

# ── K4 inventory ──────────────────────────────────────────────────────────────
K4_COUNTS  = Counter(K4)
K4_BY_CHAR = defaultdict(list)
for _j, _c in enumerate(K4):
    K4_BY_CHAR[_c].append(_j)

print("K4 inventory:", dict(sorted(K4_COUNTS.items())), flush=True)

# ── Single-character encrypt/decrypt ──────────────────────────────────────────
def pt_char_vig(ct_c, ki):
    """Vigenère decrypt: PT = (CT - KEY) mod 26"""
    return AZ[(_AZI[ct_c] - ki) % 26]

def pt_char_beau(ct_c, ki):
    """Beaufort decrypt: PT = (KEY - CT) mod 26"""
    return AZ[(ki - _AZI[ct_c]) % 26]

def exp_ct_vig(crib, kv, start):
    """Expected real-CT chars for crib at real-CT position `start` under Vigenère."""
    kl = len(kv)
    return [AZ[(_AZI[c] + kv[(start+k)%kl]) % 26] for k, c in enumerate(crib)]

def exp_ct_beau(crib, kv, start):
    """Expected real-CT chars for crib at real-CT position `start` under Beaufort."""
    kl = len(kv)
    return [AZ[(kv[(start+k)%kl] - _AZI[c]) % 26] for k, c in enumerate(crib)]

# ── Feasibility ────────────────────────────────────────────────────────────────
def find_feasible_pairs(kv, is_vig):
    """Return list of (ene_s, bc_s, ene_exp, bc_exp) that are character-feasible."""
    exp_fn = exp_ct_vig if is_vig else exp_ct_beau
    pairs  = []
    for es in range(N - L_ENE + 1):
        ee = exp_fn(CRIB_ENE, kv, es)
        for bs in range(N - L_BC + 1):
            # Non-overlapping check
            if not (bs >= es + L_ENE or es >= bs + L_BC):
                continue
            be     = exp_fn(CRIB_BC, kv, bs)
            needed = Counter(ee + be)
            if all(K4_COUNTS.get(c, 0) >= n for c, n in needed.items()):
                pairs.append((es, bs, ee, be))
    return pairs

# ── Build pinned permutation ───────────────────────────────────────────────────
def build_pinned_perm(es, ee, bs, be, rng):
    """
    Build a permutation with the 24 crib positions assigned to character-matching
    K4 positions. Remaining 73 positions filled randomly.
    Returns (perm, pinned_set) or (None, None) if infeasible.
    """
    perm   = [-1] * N
    used   = set()
    pinned = set()

    for start, exp in [(es, ee), (bs, be)]:
        for k, ch in enumerate(exp):
            rp     = start + k                          # real-CT position
            cands  = [j for j in K4_BY_CHAR.get(ch, []) if j not in used]
            if not cands:
                return None, None                       # infeasible (shouldn't happen)
            chosen = rng.choice(cands)
            perm[rp] = chosen
            used.add(chosen)
            pinned.add(rp)

    # Fill remaining positions randomly
    free_r = [i for i in range(N) if perm[i] == -1]
    free_k = [j for j in range(N) if j not in used]
    rng.shuffle(free_k)
    for i, j in zip(free_r, free_k):
        perm[i] = j

    assert all(x >= 0 for x in perm), "Unfilled perm positions"
    assert len(set(perm)) == N,        "Duplicate K4 positions in perm"
    return perm, pinned

# ── Simulated Annealing (incremental quadgram scoring) ────────────────────────
def sa_pinned(perm_in, pinned, kv, is_vig, n_iter, rng, T0=10.0, Tf=0.1):
    """
    SA with crib positions pinned. Only free (non-pinned) positions are swapped.
    Uses INCREMENTAL quadgram scoring: only recompute affected quadgrams on each swap.

    Returns (best_perm, best_avg_score, best_pt_str).
    """
    kl     = len(kv)
    free   = [i for i in range(N) if i not in pinned]
    nf     = len(free)
    pt_fn  = pt_char_vig if is_vig else pt_char_beau

    p      = perm_in[:]

    # Build PT list (list of single chars for fast mutation)
    pt = [pt_fn(K4[p[i]], kv[i % kl]) for i in range(N)]

    # Initial total score (sum, not avg — we track sum for incremental updates)
    total_s = sum(_QG.get(pt[i]+pt[i+1]+pt[i+2]+pt[i+3], _MISS)
                  for i in range(N-3))

    best_p, best_s, best_pt = p[:], total_s, pt[:]
    cur_s  = total_s

    # Precompute log-decay rate for temperature schedule
    log_r = math.log(Tf / T0) if (n_iter > 1 and Tf != T0) else 0.0

    def region_score(lo, hi):
        return sum(_QG.get(pt[i]+pt[i+1]+pt[i+2]+pt[i+3], _MISS)
                   for i in range(lo, hi+1))

    for step in range(n_iter):
        T  = T0 * math.exp(log_r * step / n_iter)

        # Pick two distinct free positions
        i1 = rng.randint(0, nf-1)
        i2 = rng.randint(0, nf-2)
        if i2 >= i1:
            i2 += 1
        a, b = free[i1], free[i2]

        # Compute new PT chars after swapping perm[a] ↔ perm[b]
        new_a = pt_fn(K4[p[b]], kv[a % kl])   # K4[new_perm[a]] with key for pos a
        new_b = pt_fn(K4[p[a]], kv[b % kl])   # K4[new_perm[b]] with key for pos b

        if new_a == pt[a] and new_b == pt[b]:
            continue                            # no change, skip

        # Compute affected quadgram ranges
        # Quadgrams using position x: indices max(0,x-3) to min(N-4,x)
        lo_a, hi_a = max(0, a-3), min(N-4, a)
        lo_b, hi_b = max(0, b-3), min(N-4, b)

        old_a, old_b = pt[a], pt[b]

        if hi_a < lo_b:
            # Non-overlapping: compute old scores, swap, compute new scores
            old_c_a = region_score(lo_a, hi_a)
            old_c_b = region_score(lo_b, hi_b)
            pt[a] = new_a
            pt[b] = new_b
            new_c_a = region_score(lo_a, hi_a)
            new_c_b = region_score(lo_b, hi_b)
            delta   = (new_c_a - old_c_a) + (new_c_b - old_c_b)
        else:
            # Overlapping or adjacent: use combined range
            lo, hi      = min(lo_a, lo_b), max(hi_a, hi_b)
            old_contrib = region_score(lo, hi)
            pt[a] = new_a
            pt[b] = new_b
            new_contrib = region_score(lo, hi)
            delta       = new_contrib - old_contrib

        # Accept / reject
        if delta > 0 or (T > 1e-12 and rng.random() < math.exp(delta / T)):
            p[a], p[b] = p[b], p[a]
            cur_s += delta
            if cur_s > best_s:
                best_s  = cur_s
                best_p  = p[:]
                best_pt = pt[:]
        else:
            pt[a] = old_a
            pt[b] = old_b

    return best_p, best_s / (N-3), ''.join(best_pt)

# ── Single-pair attack ─────────────────────────────────────────────────────────
def attack_pair(es, ee, bs, be, kv, is_vig, keyword, n_iter, n_seeds, base_seed=0):
    """Run SA with multiple seeds on a single (es, bs) pair. Return list of result dicts."""
    cipher  = 'vig' if is_vig else 'beau'
    results = []
    for seed in range(n_seeds):
        rng         = random.Random(base_seed + seed * 98765 + es * 103 + bs * 7)
        perm, pinned = build_pinned_perm(es, ee, bs, be, rng)
        if perm is None:
            continue
        best_p, best_s, best_pt = sa_pinned(perm, pinned, kv, is_vig, n_iter, rng)
        ene_ok = best_pt[es:es+L_ENE] == CRIB_ENE
        bc_ok  = best_pt[bs:bs+L_BC]  == CRIB_BC
        results.append({
            'keyword': keyword, 'cipher': cipher,
            'ene_s': es, 'bc_s': bs,
            'score': best_s, 'pt': best_pt,
            'perm': best_p, 'pinned': sorted(pinned),
            'ene_ok': ene_ok, 'bc_ok': bc_ok,
            'both': ene_ok and bc_ok,
            'seed': seed,
        })
    return results

# ── Full attack for one (keyword, cipher) config ──────────────────────────────
def full_attack(keyword, is_vig,
                n_p1=800,   n_p1_seeds=1,
                n_p2=50000, n_p2_seeds=15,
                n_top=20):
    """
    Phase 1: Quick scan over all feasible pairs.
    Phase 2: Deep SA on top-N pairs + the historically motivated ENE@21/BC@63.
    """
    cipher = 'vig' if is_vig else 'beau'
    sep    = '='*70
    print(f"\n{sep}", flush=True)
    print(f"ATTACK: {keyword}/{cipher}", flush=True)
    print(sep, flush=True)

    kv = make_kv(keyword)

    # ─ Feasible pairs ─
    t0    = time.time()
    pairs = find_feasible_pairs(kv, is_vig)
    print(f"  {len(pairs)} feasible (ene_s, bc_s) pairs [{time.time()-t0:.1f}s]", flush=True)
    if not pairs:
        return []

    # ─ Phase 1: Quick scan ─
    print(f"Phase 1: {n_p1} SA iters × {n_p1_seeds} seed(s) per pair ...", flush=True)
    t0 = time.time()
    phase1 = []

    for idx, (es, bs, ee, be) in enumerate(pairs):
        if idx % 300 == 0 and idx > 0:
            print(f"  {idx}/{len(pairs)} [{time.time()-t0:.0f}s]", flush=True)
        best_s = -999.0
        for sd in range(n_p1_seeds):
            rng = random.Random(sd * 7777 + es * 97 + bs)
            pm, pn = build_pinned_perm(es, ee, bs, be, rng)
            if pm is None:
                continue
            _, s, _ = sa_pinned(pm, pn, kv, is_vig, n_p1, rng)
            best_s   = max(best_s, s)
        phase1.append((best_s, es, bs, ee, be))

    phase1.sort(key=lambda x: x[0], reverse=True)
    elapsed = time.time() - t0
    print(f"  Phase 1 done [{elapsed:.0f}s]. Top-5 pairs:", flush=True)
    for s, es, bs, _, _ in phase1[:5]:
        print(f"    ENE@{es:2d} BC@{bs:2d}: {s:.4f}", flush=True)

    # ─ Phase 2: Deep dive ─
    print(f"\nPhase 2: {n_p2} SA iters × {n_p2_seeds} seeds on top-{n_top} ...", flush=True)
    t0 = time.time()

    # Always include the historically motivated ENE@21, BC@63
    hist   = next((x for x in phase1 if x[1] == 21 and x[2] == 63), None)
    top    = list(phase1[:n_top])
    if hist and hist not in top:
        top.append(hist)

    all_res = []

    for rank, (p1s, es, bs, ee, be) in enumerate(top):
        # Extra seeds for the historically motivated pair
        seeds = n_p2_seeds + (10 if es == 21 and bs == 63 else 0)
        print(f"  [{rank+1:2d}/{len(top)}] ENE@{es:2d} BC@{bs:2d} p1={p1s:.4f} seeds={seeds}",
              flush=True, end='')

        res = attack_pair(es, ee, bs, be, kv, is_vig, keyword,
                          n_p2, seeds, base_seed=rank * 100000)
        if not res:
            print(" → no valid assignments", flush=True)
            continue

        res.sort(key=lambda x: x['score'], reverse=True)
        best = res[0]
        print(f" → best={best['score']:.4f} both={best['both']}", flush=True)

        if best['score'] > -4.5:
            print(f"  *** HIGH SCORE *** PT: {best['pt']}", flush=True)
            print(f"    ENE_ok={best['ene_ok']} BC_ok={best['bc_ok']}", flush=True)

        all_res.extend(res)

    print(f"\nPhase 2 done [{time.time()-t0:.0f}s]", flush=True)

    # Sort and print top-5
    all_res.sort(key=lambda x: x['score'], reverse=True)
    print(f"\nTop-5 {keyword}/{cipher}:", flush=True)
    for r in all_res[:5]:
        print(f"  score={r['score']:.4f} both={r['both']} "
              f"ENE@{r['ene_s']:2d} BC@{r['bc_s']:2d} seed={r['seed']}", flush=True)
        print(f"  PT: {r['pt']}", flush=True)

    return all_res

# ── Main ───────────────────────────────────────────────────────────────────────
print(f"\n{'#'*70}", flush=True)
print("E-UNSCRAMBLE-04: Crib-Pinning Simulated Annealing")
print(f"{'#'*70}\n", flush=True)

# Summarise forced constraints for the historically motivated case
print("─── Forced constraint analysis: KRYPTOS/vig, ENE@21, BC@63 ───", flush=True)
_kv_k = make_kv('KRYPTOS')
_ee21  = exp_ct_vig(CRIB_ENE, _kv_k, 21)
_be63  = exp_ct_beau(CRIB_BC,  make_kv('KRYPTOS'), 63)  # wrong—use vig
_be63  = exp_ct_vig(CRIB_BC,  _kv_k, 63)
print(f"  ENE expected real-CT: {''.join(_ee21)}", flush=True)
print(f"  BC  expected real-CT: {''.join(_be63)}", flush=True)
_comb  = Counter(_ee21 + _be63)
print(f"  Character demands:", flush=True)
for c in sorted(_comb):
    have = K4_COUNTS.get(c, 0)
    mark = " ← FORCED (only 1 in K4)" if have == _comb[c] else ""
    print(f"    {c}: need {_comb[c]}, have {have}{mark}", flush=True)
_feasible = all(K4_COUNTS.get(c,0) >= n for c,n in _comb.items())
print(f"  Feasible: {_feasible}\n", flush=True)

# ── Run configs ───────────────────────────────────────────────────────────────
CONFIGS = [
    ('KRYPTOS',    True),    # Vigenère  — most likely
    ('KRYPTOS',    False),   # Beaufort  — strong hill-climb result
    ('ABSCISSA',   True),    # Vigenère
    ('ABSCISSA',   False),   # Beaufort
    ('PALIMPSEST', True),    # Vigenère
    ('BERLIN',     True),    # Vigenère
    ('SHADOW',     True),    # Vigenère
    ('CLOCK',      True),    # Vigenère
]

all_results = []

for keyword, is_vig in CONFIGS:
    try:
        res = full_attack(
            keyword, is_vig,
            n_p1=800,    n_p1_seeds=1,
            n_p2=50000,  n_p2_seeds=15,
            n_top=20,
        )
        all_results.extend(res)
    except Exception as exc:
        import traceback
        print(f"\nERROR in {keyword}/{'vig' if is_vig else 'beau'}: {exc}", flush=True)
        traceback.print_exc()

# ── Global summary ────────────────────────────────────────────────────────────
all_results.sort(key=lambda x: x['score'], reverse=True)

print(f"\n{'='*70}", flush=True)
print("GLOBAL TOP-15 RESULTS", flush=True)
print('='*70, flush=True)
for i, r in enumerate(all_results[:15]):
    print(f"#{i+1:2d}: {r['keyword']}/{r['cipher']} ENE@{r['ene_s']:2d} BC@{r['bc_s']:2d} "
          f"score={r['score']:.4f} both={r['both']} seed={r['seed']}", flush=True)
    print(f"      PT: {r['pt']}", flush=True)

# ── Any results with BOTH cribs ───────────────────────────────────────────────
crib_hits = [r for r in all_results if r['both']]
if crib_hits:
    print(f"\n{'='*70}", flush=True)
    print(f"RESULTS WITH BOTH CRIBS CORRECT ({len(crib_hits)} total)", flush=True)
    print('='*70, flush=True)
    for i, r in enumerate(crib_hits[:10]):
        print(f"#{i+1}: {r['keyword']}/{r['cipher']} ENE@{r['ene_s']} BC@{r['bc_s']} "
              f"score={r['score']:.4f}", flush=True)
        print(f"  PT: {r['pt']}", flush=True)
else:
    print("\n[no results with both cribs confirmed by SA]", flush=True)

# ── Save ──────────────────────────────────────────────────────────────────────
os.makedirs('kbot_results', exist_ok=True)
save = {
    'experiment':    'E-UNSCRAMBLE-04',
    'description':   'Crib-pinning SA: 24 crib positions fixed, 73 free positions optimized',
    'timestamp':     time.strftime('%Y-%m-%dT%H:%M:%S'),
    'n_total':       len(all_results),
    'n_crib_hits':   len(crib_hits),
    'global_best':   {k: v for k, v in all_results[0].items() if k != 'perm'} if all_results else None,
    'crib_hits':     [{k: v for k, v in r.items() if k != 'perm'} for r in crib_hits[:50]],
    'top_100':       [{k: v for k, v in r.items() if k != 'perm'} for r in all_results[:100]],
}
with open('kbot_results/unscramble_04.json', 'w') as f:
    json.dump(save, f, indent=2)
print(f"\nSaved {len(all_results)} results to kbot_results/unscramble_04.json", flush=True)
