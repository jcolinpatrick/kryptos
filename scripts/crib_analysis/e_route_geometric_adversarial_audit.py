#!/usr/bin/env python3
"""ADVERSARIAL AUDIT of e_route_geometric_periodic_ceiling.

ID:     e_route_geometric_adversarial_audit
Family: crib_analysis
Status: active
Origin: 2026-08-25

WHAT THIS IS
------------
An independent refutation attempt against the geometric-route x periodic-substitution
attainable-crib-ceiling sweep at
scripts/crib_analysis/e_route_geometric_periodic_ceiling.py, whose headline is:

    "every period from 1 to 19 is soundly eliminated at the released-crib level L0
     for every key, and no configuration at any period 1-30 is left unEliminated at
     crib levels L1-L5"

This script does NOT re-run that sweep's own code path to agree with itself. Where it
recounts, it recounts through scripts/lib/crib_filter.ceiling (the control-verified
library), not through the sweep's inlined fast path.

CHECKS
------
 A  UNIVERSE INTEGRITY. Every emitted route is a bijection of range(97); the store is
    genuinely deduplicated.
 B  FAST PATH vs LIBRARY. The sweep inlines its own `_ceil`. Cross-check it against
    crib_filter.ceiling on random full configurations.
 C  INVERSE CLOSURE. A route cipher is "write along path A, read along path B". The sweep
    enumerates ONE gather per named construction. The mirrored convention is the inverse
    permutation. Measure how much of the declared universe contains its own inverse.
 D  INVERSE SWEEP. Run the identical machinery over the inverse universe, i.e. the part of
    the family the sweep never evaluated and never declared as untested.
 E  INDEPENDENT RECOUNT. Recount L0 survivors at selected periods per peel order through
    the library, and compare against results/route_geometric_periodic_ceiling.json.
 F  ALPHABET ROBUSTNESS. The sweep fixes ct/pt alphabets to {AZ,KA}^2; the alphabet is part
    of the TABLEAU, not the key, so "for every key" does not cover it. Two probes:
      F1 an alphabet-INDEPENDENT upper bound on the ceiling (maximum bipartite matching per
         key class), valid for ALL bijective alphabet pairs simultaneously;
      F2 an explicit CONSTRUCTION of bijective (ct_alpha, pt_alpha) pairs that drive the L0
         ceiling to 24/24 at LOW period for routes inside the swept universe.
 G  ACCOUNTING. Recount the route-construction totals quoted in the reviewed caveats.

PRE-REGISTERED INTERPRETATION (fixed before running)
----------------------------------------------------
  * Any disagreement in B or E is a defect in the reviewed sweep and refutes it.
  * A non-bijection in A invalidates every ceiling derived from that route.
  * D returning survivors at period <= 19 at L0 would REFUTE the headline outright.
    D returning none extends the elimination and demotes C to a disclosure defect.
  * F2 finding even ONE bijective alphabet pair with ceiling == n at period <= 19 shows the
    headline's low-period claim is scoped to its four alphabet pairs and is NOT a statement
    about every key of a periodic additive cipher.
  * ceiling == n is NOT a solution, NOT a candidate, NOT evidence a plaintext exists. The
    F2 alphabets are counterexamples to a COVERAGE CLAIM, nothing else. No key was searched,
    no plaintext was read, nothing was scored.
  * Bean equality / inequality / linear sets are not touched anywhere in this audit, in the
    sweep under review, or in crib_filter. Every route here is crib-moving.

MEASURED (2026-08-25, this machine)
-----------------------------------
  A  65,905 routes, 0 non-bijective, 65,905 distinct permutations. PASS.
  B  4,000 random configurations, 0 mismatches. PASS.
  C  2,376 / 65,905 = 3.6% of the universe contains its own inverse.
  D  63,529 routes never evaluated by the sweep. L0 first surviving period 21;
     L1-L5 zero survivors, max ceilings 35/42, 36/45, 36/46, 42/74, 41/74.
     The eliminations EXTEND to the mirrored family. C is a disclosure defect, not a
     substantive one.
  E  18 (peel, period) cells recounted through the library: exact match, including
     sub_inner survival 790,860/790,860 = 1.0000 at p=27 and p=28 (vacuous, as claimed).
  F1 The alphabet-independent bound reaches 24/24 at p=7,8,10,13 (both peels) -- there is
     NO structural obstruction to a low-period tableau.
  F2 CONSTRUCTED. serpH11 sub_inner p=8, serpH11 sub_inner p=10, serpH11 sub_outer p=10,
     raggedturn12_cw sub_inner p=10 all reach ceiling 24/24 under explicit bijective mixed
     alphabets. The headline's "periods 1-19 eliminated for every key" holds for AZ/KA only.
  G  5,673 named constructions (not 5,576) collapse to 2,674 unique BASE bijections
     (not 3,464); 3,464 is base + reflections.

RUN
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_route_geometric_adversarial_audit.py
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_route_geometric_adversarial_audit.py --skip-inverse-sweep
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from collections import defaultdict
from multiprocessing import Pool

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "crib_analysis"))

from crib_filter import AZ, ceiling, index_table, inverse, sub_inner, sub_outer  # noqa: E402
import crib_sets  # noqa: E402
import e_route_geometric_periodic_ceiling as S  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402

D0 = crib_sets.level("L0_released")
QS = sorted(D0)
N0 = len(D0)
TABS = {"AZ": index_table(AZ), "KA": index_table(S.KA)}
RECOUNT_PERIODS = [7, 8, 10, 19, 20, 25, 26, 27, 28]
BOUND_PERIODS = [5, 7, 8, 10, 13, 17, 19]


# ── E: independent recount worker ─────────────────────────────────────────
def _recount(chunk):
    out, mx = defaultdict(int), defaultdict(int)
    for _nm, _fam, perm in chunk:
        lp = list(perm)
        for peel, b in (("sub_outer", sub_outer), ("sub_inner", sub_inner)):
            for p in RECOUNT_PERIODS:
                a, c = b(lp, p)
                for ctal in ("AZ", "KA"):
                    for ptal in ("AZ", "KA"):
                        for var in ("vig", "beau", "vbeau"):
                            cl, _ = ceiling(CT, D0, a, c, ct_tab=TABS[ctal],
                                            pt_tab=TABS[ptal], variant=var)
                            if cl > mx[p]:
                                mx[p] = cl
                            if cl == N0:
                                out[(peel, p)] += 1
    return dict(out), dict(mx)


# ── F1: alphabet-independent bound ────────────────────────────────────────
def _matching_size(pairs) -> int:
    adj = defaultdict(set)
    for L, c in set(pairs):
        adj[L].add(c)
    match: dict = {}

    def aug(u, vis):
        for v in adj[u]:
            if v in vis:
                continue
            vis.add(v)
            if v not in match or aug(match[v], vis):
                match[v] = u
                return True
        return False

    return sum(1 for u in adj if aug(u, set()))


def alphabet_free_bound(perm, period: int, peel: str) -> int:
    """Upper bound on the ceiling valid for EVERY bijective (ct, pt) alphabet pair."""
    ip = inverse(list(perm))
    cls = defaultdict(list)
    for q in QS:
        j = ip[q]
        cls[(q % period) if peel == "sub_inner" else (j % period)].append((CT[j], D0[q]))
    return sum(_matching_size(v) for v in cls.values())


def _bound_work(chunk):
    best = defaultdict(int)
    for _nm, _fam, perm in chunk:
        for peel in ("sub_outer", "sub_inner"):
            for p in BOUND_PERIODS:
                b = alphabet_free_bound(perm, p, peel)
                if b > best[(peel, p)]:
                    best[(peel, p)] = b
    return dict(best)


# ── F2: construct a defeating tableau ─────────────────────────────────────
def construct_tableau(perm, period: int, peel: str, seed: int = 1,
                      node_cap: int = 4_000_000):
    """Search for bijective (ct_alpha, pt_alpha) with L0 ceiling == 24 under vig.

    Returns (ct_alpha, pt_alpha), None (proved unsatisfiable within the model), or
    "TIMEOUT" (node cap hit -> INCONCLUSIVE, never an elimination)."""
    ip = inverse(list(perm))
    items = sorted((((q % period) if peel == "sub_inner" else (ip[q] % period)),
                    CT[ip[q]], D0[q]) for q in QS)
    rng = random.Random(seed)
    x: dict = {}
    y: dict = {}
    s: dict = {}
    xu: set = set()
    yu: set = set()
    nodes = [0]

    def bt(k: int) -> bool:
        nodes[0] += 1
        if nodes[0] > node_cap:
            raise TimeoutError
        if k == len(items):
            return True
        cl, L, c = items[k]
        if cl in s and L in x:
            cands = [(x[L], (x[L] - s[cl]) % 26, s[cl])]
        elif cl in s and c in y:
            cands = [((y[c] + s[cl]) % 26, y[c], s[cl])]
        elif L in x and c in y:
            cands = [(x[L], y[c], (x[L] - y[c]) % 26)]
        elif cl in s:
            cands = [((v + s[cl]) % 26, v, s[cl]) for v in range(26)]
        elif L in x:
            cands = [(x[L], v, (x[L] - v) % 26) for v in range(26)]
        elif c in y:
            cands = [(v, y[c], (v - y[c]) % 26) for v in range(26)]
        else:
            cands = [(a, b, (a - b) % 26) for a in range(26) for b in range(26)]
        rng.shuffle(cands)
        for xv, yv, sv in cands:
            if (L in x and x[L] != xv) or (c in y and y[c] != yv) or (cl in s and s[cl] != sv):
                continue
            ax, ay, asg = L not in x, c not in y, cl not in s
            if (ax and xv in xu) or (ay and yv in yu):
                continue
            if ax:
                x[L] = xv; xu.add(xv)
            if ay:
                y[c] = yv; yu.add(yv)
            if asg:
                s[cl] = sv
            if bt(k + 1):
                return True
            if ax:
                xu.discard(xv); x.pop(L)
            if ay:
                yu.discard(yv); y.pop(c)
            if asg:
                s.pop(cl)
        return False

    try:
        if not bt(0):
            return None
    except TimeoutError:
        return "TIMEOUT"

    def fill(tab, used):
        free = [v for v in range(26) if v not in used]
        rest = [chr(65 + i) for i in range(26) if chr(65 + i) not in tab]
        for L, v in zip(rest, free):
            tab[L] = v
        a = [None] * 26
        for L, v in tab.items():
            a[v] = L
        return "".join(a)

    return fill(dict(x), set(xu)), fill(dict(y), set(yu))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--skip-inverse-sweep", action="store_true")
    ap.add_argument("--ref", default=os.path.join(
        _ROOT, "results", "route_geometric_periodic_ceiling.json"))
    args = ap.parse_args()
    try:
        usable = len(os.sched_getaffinity(0))
    except AttributeError:
        usable = os.cpu_count() or 1
    W = args.workers or max(1, usable - 4)
    sys.setrecursionlimit(20000)

    routes = S.build_routes(rotations=True)
    print(f"[A] universe: {len(routes)} routes, {len(S._BAD_ROUTES)} rejected by the sweep")
    bad = sum(1 for _n, _f, p in routes if len(p) != 97 or sorted(p) != list(range(97)))
    perms = {p for _n, _f, p in routes}
    print(f"[A] independent bijection check: {bad} non-bijective; "
          f"{len(perms)} distinct permutations (dedup {'OK' if len(perms)==len(routes) else 'BROKEN'})")

    # B
    rng = random.Random(7)
    lv = {n: crib_sets.level(n) for n in crib_sets.LEVELS}
    mism = 0
    for _ in range(4000):
        _nm, _fam, perm = rng.choice(routes)
        lname = rng.choice(crib_sets.LEVELS)
        d = lv[lname]; qs = sorted(d)
        ctal = rng.choice(["AZ", "KA"]); ptal = rng.choice(["AZ", "KA"])
        var = rng.choice(["vig", "beau", "vbeau"])
        peel = rng.choice(["sub_outer", "sub_inner"])
        p_ = rng.randint(1, 30)
        ip = inverse(list(perm))
        jl = [ip[q] for q in qs]
        cvals = [TABS[ctal][ord(CT[j]) - 65] for j in jl]
        pvals = [TABS[ptal][ord(d[q]) - 65] for q in qs]
        if var == "vig":
            ts = [(a - b) % 26 for a, b in zip(cvals, pvals)]
        elif var == "beau":
            ts = [(a + b) % 26 for a, b in zip(cvals, pvals)]
        else:
            ts = [(b - a) % 26 for a, b in zip(cvals, pvals)]
        mods = [j % p_ for j in jl] if peel == "sub_outer" else [q % p_ for q in qs]
        b = sub_outer if peel == "sub_outer" else sub_inner
        a, c = b(list(perm), p_)
        lib, _ = ceiling(CT, d, a, c, ct_tab=TABS[ctal], pt_tab=TABS[ptal], variant=var)
        if S._ceil(mods, ts) != lib:
            mism += 1
    print(f"[B] sweep fast path vs crib_filter.ceiling: 4000 configs, {mism} mismatches")

    # C
    inv_in = sum(1 for p in perms if tuple(inverse(list(p))) in perms)
    print(f"[C] inverse closure: {inv_in}/{len(perms)} = {100*inv_in/len(perms):.1f}% of the "
          f"declared universe contains its own inverse")

    # E
    t = time.perf_counter()
    chunks = [routes[i:i + 250] for i in range(0, len(routes), 250)]
    tot, mx = defaultdict(int), defaultdict(int)
    with Pool(W) as pool:
        for o, m in pool.imap_unordered(_recount, chunks):
            for k, v in o.items():
                tot[k] += v
            for k, v in m.items():
                mx[k] = max(mx[k], v)
    ref = json.load(open(args.ref))
    rp = ref["by_level"]["L0_released"]["survivors_by_peel_period"]
    ok = True
    print(f"[E] independent L0 recount through the library ({time.perf_counter()-t:.0f}s)")
    for p in RECOUNT_PERIODS:
        for peel in ("sub_outer", "sub_inner"):
            mine, rep = tot.get((peel, p), 0), rp[peel][str(p)]
            if mine != rep:
                ok = False
            print(f"      p={p:<3} {peel:<10} mine={mine:<8} reported={rep:<8} "
                  f"max_ceiling={mx[p]}/24{'' if mine == rep else '   <<< MISMATCH'}")
    tot_inner = len(routes) * 3 * 4
    for p in (27, 28):
        r = tot.get(("sub_inner", p), 0) / tot_inner
        print(f"      vacuity check sub_inner p={p}: {r:.4f}")
    print(f"[E] VERDICT: {'exact match' if ok else 'MISMATCH -- sweep refuted'}")

    # F1
    t = time.perf_counter()
    best = defaultdict(int)
    bchunks = [routes[i:i + 400] for i in range(0, len(routes), 400)]
    with Pool(W) as pool:
        for d in pool.imap_unordered(_bound_work, bchunks):
            for k, v in d.items():
                best[k] = max(best[k], v)
    print(f"[F1] alphabet-INDEPENDENT max ceiling bound, whole universe ({time.perf_counter()-t:.0f}s)")
    for p in BOUND_PERIODS:
        row = " ".join(f"{peel}={best[(peel,p)]}" for peel in ("sub_outer", "sub_inner"))
        print(f"      p={p:<3} {row}  (24 => no structural obstruction to a low-period tableau)")

    # F2
    byname = {nm: p for nm, _f, p in routes}
    print("[F2] explicit mixed-tableau construction (vig, L0). ceiling==24 means NOT ELIMINATED "
          "by the filter -- it is NOT a solution and no key was searched.")
    for nm in ("serpH11", "raggedturn12_cw"):
        if nm not in byname:
            continue
        for peel in ("sub_inner", "sub_outer"):
            for period in (8, 10):
                r = construct_tableau(byname[nm], period, peel, seed=1)
                if r in (None, "TIMEOUT"):
                    tag = "unsatisfiable" if r is None else "TIMEOUT (INCONCLUSIVE, not an elimination)"
                    print(f"      {nm:<16} {peel:<10} p={period:<3} {tag}")
                    continue
                ca, pa = r
                b = sub_inner if peel == "sub_inner" else sub_outer
                a, c = b(list(byname[nm]), period)
                cl, _ = ceiling(CT, D0, a, c, ct_tab=index_table(ca),
                                pt_tab=index_table(pa), variant="vig")
                print(f"      {nm:<16} {peel:<10} p={period:<3} ceiling={cl}/24"
                      f"{'  *** NOT ELIMINATED under this tableau ***' if cl == N0 else ''}")
                if cl == N0:
                    print(f"          ct_alpha={ca}")
                    print(f"          pt_alpha={pa}")

    # G
    named = {"rail": 47, "serpentine": 2 * 97, "spiral": 2 * 4 * 97,
             "diagonal": 97 * 24 + 97, "ragged_turn": 2 * 97,
             "grid_op": 16 * 97, "named_grid": 5 * 97}
    nr = S.build_routes(rotations=False)
    fam = defaultdict(int)
    for _n, f, _p in nr:
        fam[f] += 1
    base_only = sum(v for k, v in fam.items() if not k.endswith("_refl"))
    print(f"[G] named constructions = {sum(named.values())} (caveat says 5,576)")
    print(f"[G] unique BASE bijections before transforms = {base_only} (caveat says 3,464)")
    print(f"[G] unique base + reflections = {len(nr)}  <- this is what 3,464 actually is")

    # D
    if not args.skip_inverse_sweep:
        novel = []
        ded = set()
        for nm, f, p in routes:
            ip = tuple(inverse(list(p)))
            if ip in ded or ip in perms:
                continue
            ded.add(ip)
            novel.append((nm + "^-1", f + "_inv", ip))
        print(f"[D] inverse sweep over {len(novel)} routes the sweep never evaluated")
        periods = list(range(1, 31))
        levels = list(crib_sets.LEVELS)
        ichunks = [novel[i:i + 250] for i in range(0, len(novel), 250)]
        surv = defaultdict(int); maxc = defaultdict(int); tc = defaultdict(int)
        t = time.perf_counter()
        with Pool(W, initializer=S._init, initargs=(periods, levels)) as pool:
            for s_, t_, m_, _sf, _sp, _sl, _ex in pool.imap_unordered(S._work, ichunks):
                for k, v in s_.items():
                    surv[k] += v
                for k, v in t_.items():
                    tc[k] += v
                for k, v in m_.items():
                    maxc[k] = max(maxc[k], v)
        print(f"[D] {time.perf_counter()-t:.0f}s")
        for lname in levels:
            n = len(crib_sets.level(lname))
            s_tot = sum(v for (l, _p), v in surv.items() if l == lname)
            pp = {p: surv.get((lname, p), 0) for p in periods}
            first = min([p for p in periods if pp[p]], default=None)
            print(f"      {lname:<18} n={n:<3} configs={tc[lname]:,} survivors={s_tot:,} "
                  f"max_ceiling={maxc[lname]}/{n} first_surviving_period={first}")
    else:
        print("[D] inverse sweep SKIPPED by flag -- coverage claim not re-tested this run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
