#!/usr/bin/env python3
"""Bounded robustness probe on the ALPHABET dimension of
e_route_geometric_periodic_ceiling.

The main sweep fixes ct/pt alphabets to {AZ, KA}. The ceiling depends on the
alphabets, so a low-period elimination there is an elimination for THOSE FOUR
alphabet pairs only. This probe re-runs the same filter over the non-rotation
base route set against keyword-mixed alphabets drawn from the project's
thematic keyword pool, to measure whether ANY periodic-substitution period in
1..19 becomes non-eliminated once the tableau alphabets are allowed to vary.

SAMPLED, NOT EXHAUSTIVE. The full alphabet space is 26! per side.
"""
from __future__ import annotations
import argparse, os, random, sys
from collections import defaultdict
from multiprocessing import Pool
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "crib_analysis"))
from crib_filter import AZ, MOD, index_table, inverse, keyword_mixed  # noqa: E402
import crib_sets  # noqa: E402
from e_route_geometric_periodic_ceiling import KA, N, PEELS, VARIANTS, build_routes, _ceil  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402

_G = {}


def _init(alphas, periods, levels):
    _G["ctidx"] = {a: [index_table(s)[ord(ch) - 65] for ch in CT] for a, s in alphas}
    lv = []
    for nm in levels:
        d = crib_sets.level(nm)
        qs = sorted(d)
        ptv = {a: [index_table(s)[ord(d[q]) - 65] for q in qs] for a, s in alphas}
        lv.append((nm, qs, len(qs), ptv, {p: [q % p for q in qs] for p in periods}))
    _G["levels"] = lv
    _G["periods"] = list(periods)
    _G["names"] = [a for a, _ in alphas]


def _work(chunk):
    surv = defaultdict(int); tot = defaultdict(int); mx = defaultdict(int)
    ex = defaultdict(list)
    for rname, fam, perm in chunk:
        ip = inverse(perm)
        for lname, qs, n, ptv, qmod in _G["levels"]:
            jl = [ip[q] for q in qs]
            jmod = {p: [j % p for j in jl] for p in _G["periods"]}
            for ca in _G["names"]:
                cvals = [_G["ctidx"][ca][j] for j in jl]
                for pa in _G["names"]:
                    pvals = ptv[pa]
                    for var in VARIANTS:
                        if var == "vig":
                            ts = [(c - x) % MOD for c, x in zip(cvals, pvals)]
                        elif var == "beau":
                            ts = [(c + x) % MOD for c, x in zip(cvals, pvals)]
                        else:
                            ts = [(x - c) % MOD for c, x in zip(cvals, pvals)]
                        for peel in PEELS:
                            mods = jmod if peel == "sub_outer" else qmod
                            for p in _G["periods"]:
                                c = _ceil(mods[p], ts)
                                tot[lname] += 1
                                if c > mx[lname]:
                                    mx[lname] = c
                                if c == n:
                                    surv[(lname, p)] += 1
                                    if len(ex[lname]) < 30:
                                        ex[lname].append(f"{rname}|{peel}|p={p}|{var}|ct={ca}|pt={pa}")
    return dict(surv), dict(tot), dict(mx), {k: v for k, v in ex.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--n-alphabets", type=int, default=14)
    ap.add_argument("--max-period", type=int, default=19)
    args = ap.parse_args()

    pool_kw = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT", "LANGLEY",
               "BERLIN", "CLOCK", "NORTHEAST", "IQLUSION", "UNDERGRUUND", "DESPARATLY",
               "SHADOWFORCES", "LUCIDMEMORY", "TISYOURPOSITION", "WESTIDBYROWS",
               "ORDINATE", "PENTIMENTO", "VERDIGRIS", "OCHRE", "COPPER", "GRANITE",
               "MERIDIAN", "LODESTONE", "MAGNETIC", "COMPASS"]
    rng = random.Random(20260825)
    kws = pool_kw[:args.n_alphabets - 2]
    alphas = [("AZ", AZ), ("KA", KA)] + [(k, keyword_mixed(k)) for k in kws]
    # dedup alphabets
    seen = {}
    for nm, s in alphas:
        seen.setdefault(s, nm)
    alphas = [(nm, s) for s, nm in seen.items()]

    routes = [r for r in build_routes(rotations=False)]
    periods = list(range(1, args.max_period + 1))
    levels = list(crib_sets.LEVELS)
    ncfg = len(routes) * len(alphas) ** 2 * len(VARIANTS) * len(PEELS) * len(periods)
    print(f"[probe] routes={len(routes)} alphabets={len(alphas)} "
          f"({', '.join(n for n, _ in alphas)})")
    print(f"[probe] periods 1..{args.max_period}; configs per level = {ncfg:,}; "
          f"total = {ncfg*len(levels):,}  SAMPLED over alphabets, exhaustive over the rest")
    chunks = [routes[i:i + 100] for i in range(0, len(routes), 100)]
    surv = defaultdict(int); tot = defaultdict(int); mx = defaultdict(int); ex = defaultdict(list)
    with Pool(args.workers, initializer=_init, initargs=(alphas, periods, levels)) as pl:
        for s, t, m, e in pl.imap_unordered(_work, chunks):
            for k, v in s.items(): surv[k] += v
            for k, v in t.items(): tot[k] += v
            for k, v in m.items(): mx[k] = max(mx[k], v)
            for k, v in e.items():
                if len(ex[k]) < 30: ex[k].extend(v)
    for lname in levels:
        n = len(crib_sets.level(lname))
        s = sum(v for (l, _p), v in surv.items() if l == lname)
        fp = min([p for p in periods if surv.get((lname, p), 0)], default=None)
        print(f"{lname:<18} n={n:<3} configs={tot[lname]:,} survivors={s:,} "
              f"max_ceiling={mx[lname]}/{n} first_surviving_period={fp}")
        if s:
            print("   ", ex[lname][:5])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
