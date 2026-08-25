"""Attainable-crib-ceiling sweep: DIRECT ALIGNMENT + PERIODIC SUBSTITUTION.

HYPOTHESIS UNDER TEST
---------------------
K4 is a single periodic polyalphabetic substitution applied positionally to the
carved ciphertext with NO transposition of any kind (identity permutation, so
CT[i] decrypts to PT[i]):

    PT[i] = pt_alpha[ ( ct_idx[ CT[i] ] - shift[ i mod P ] ) mod 26 ]      (vig)
    PT[i] = pt_alpha[ ( shift[ i mod P ] - ct_idx[ CT[i] ] ) mod 26 ]      (beau)
    PT[i] = pt_alpha[ ( ct_idx[ CT[i] ] + shift[ i mod P ] ) mod 26 ]      (vbeau)

`shift` is a FREE vector of P values -- i.e. we quantify over every possible
key of that period, not over a keyword list.  The alphabet PAIR
(ct_alpha, pt_alpha) is what a Vigenere / KRYPTOS-tableau / Quagmire shape
actually is:

    Vigenere      (AZ,      AZ)
    KRYPTOS tab   (KA,      AZ)   and   (AZ, KA)
    Quagmire I    (AZ,      M(kw))
    Quagmire II   (M(kw),   AZ)
    Quagmire III  (M(kw),   M(kw))          same keyword both sides
    Quagmire IV   (M(kw1),  M(kw2))         kw1 != kw2

so sweeping the full cross product ALPHAS x ALPHAS with
ALPHAS = [AZ] + [keyword_mixed(kw) for kw in pool] covers all six shapes at
once, exhaustively over the keyword pool.

SCOPE
-----
  periods   P = 1..48                                    (48)
  variants  vig / beau / vbeau                           (3)
  alphabets full cross product of deduplicated ALPHAS    (n_alpha^2 ordered pairs)
  cribs     all six levels of scripts/lib/crib_sets.py
  keys      ALL of them, by construction -- the ceiling quantifies over keys.

PRE-REGISTERED INTERPRETATION  (fixed before the run)
-----------------------------------------------------
  ceiling <  n_cribs  ->  that (P, variant, alphabet pair) is IMPOSSIBLE for
                          every key.  SOUND ELIMINATION.
  ceiling == n_cribs  ->  NOT ELIMINATED BY THIS FILTER.  This is not evidence
                          for the configuration and must never be written up as
                          "possible" or "a candidate solution".

  A period P is called STRUCTURALLY UNINFORMATIVE at a given crib level when
  every crib position lands in its own residue class mod P (surplus = 0).  Then
  ceiling == n_cribs identically, for every alphabet and variant, as a matter of
  counting rather than of cryptanalysis.  Survivors at such periods are reported
  separately and carry zero evidential weight either way.

  L0 is the only EVIDENCE level.  Every elimination reported at L1..L5 is
  CONDITIONAL on the unproven plaintext hypothesis that defines that level.

Expected (pre-registered) L0 outcome: reproduce the published Bean result that
direct-alignment periodic substitution is dead for periods 1..26 on AZ/AZ.  The
open question this script answers is whether a mixed alphabet, a Beaufort sign
convention, or a period in 27..48 rescues it.

Run:
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_50_direct_periodic_ceiling.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

import numpy as np

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import AZ, ceiling, identity_perm, index_table, keyword_mixed, sub_outer  # noqa: E402
from crib_sets import LEVELS, level as crib_level  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402

MAX_PERIOD = 48
VARIANTS = ("vig", "beau", "vbeau")
CLASSIC = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "IQLUSION", "UNDERGRUUND",
           "DESPARATLY", "LUCIDMEMORY", "SHADOW", "LODESTONE", "TENTATIVE"]


def build_alphabets() -> tuple[list[str], list[str], int]:
    """Deduplicated alphabet list + human names. Returns (alphas, names, n_keywords)."""
    path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    pool: list[str] = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue          # header/category comments are NOT keywords
            w = "".join(c for c in line.upper() if c.isalpha())
            if w:
                pool.append(w)
    for kw in CLASSIC:
        if kw not in pool:
            pool.append(kw)
    n_keywords = len(set(pool))
    alphas = {AZ: "AZ"}
    for kw in pool:
        a = keyword_mixed(kw)
        if a not in alphas:
            alphas[a] = kw
    return list(alphas.keys()), list(alphas.values()), n_keywords


def shape_of(ct_name: str, pt_name: str) -> str:
    if ct_name == "AZ" and pt_name == "AZ":
        return "vigenere"
    if pt_name == "AZ":
        return "quagmire_II"
    if ct_name == "AZ":
        return "quagmire_I"
    if ct_name == pt_name:
        return "quagmire_III"
    return "quagmire_IV"


def _classes(positions: list[int], period: int) -> list[list[int]]:
    g: dict[int, list[int]] = defaultdict(list)
    for k, q in enumerate(positions):
        g[q % period].append(k)      # index into the crib-order arrays
    return list(g.values())


def sweep_one(args) -> dict:
    """One (level, variant) cell: all periods x all alphabet pairs, vectorised."""
    lvl, variant, alphas, names = args
    cribs = crib_level(lvl)
    positions = sorted(cribs)
    n = len(positions)
    na = len(alphas)

    tabs = np.array([index_table(a) for a in alphas], dtype=np.int16)   # (na,26)
    ct_at = np.array([ord(CT[q]) - 65 for q in positions])
    pt_at = np.array([ord(cribs[q]) - 65 for q in positions])
    A = tabs[:, ct_at]            # (na,n)  ct_idx[CT[q]]
    B = tabs[:, pt_at]            # (na,n)  pt_idx[crib[q]]

    # t[i,j,q] for pair (ct_alpha=i, pt_alpha=j)
    if variant == "vig":
        T = (A[:, None, :] - B[None, :, :]) % 26
    elif variant == "beau":
        T = (A[:, None, :] + B[None, :, :]) % 26
    else:                                             # vbeau
        T = (B[None, :, :] - A[:, None, :]) % 26
    M = na * na
    T = T.reshape(M, n).astype(np.int8)

    rows = np.arange(M)
    out = {}
    for period in range(1, MAX_PERIOD + 1):
        groups = _classes(positions, period)
        multi = [g for g in groups if len(g) > 1]
        surplus = n - len(groups)
        if surplus == 0:
            out[period] = dict(surplus=0, max_ceiling=n, survivors=M, sample=[],
                               shapes={"ALL_SHAPES_trivially": M})
            continue
        ceil = np.full(M, len(groups) - len(multi), dtype=np.int16)
        counts = np.empty((M, 26), dtype=np.int8)
        for g in multi:
            counts.fill(0)
            for k in g:
                tv = T[:, k]
                counts[rows, tv] += 1
            ceil += counts.max(axis=1)
        surv = np.flatnonzero(ceil == n)
        sample = []
        shapes: dict[str, int] = defaultdict(int)
        for idx in surv:
            i, j = divmod(int(idx), na)
            sh = shape_of(names[i], names[j])
            shapes[sh] += 1
            if len(sample) < 5:
                sample.append(f"P={period} {variant} ct={names[i]} pt={names[j]} [{sh}]")
        out[period] = dict(surplus=int(surplus), max_ceiling=int(ceil.max()),
                           survivors=int(surv.size), sample=sample,
                           shapes=dict(shapes))
    return dict(level=lvl, variant=variant, n=n, n_pairs=M, periods=out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=max(1, len(os.sched_getaffinity(0)) - 2))
    ap.add_argument("--out", default=os.path.join(_ROOT, "results",
                                                  "crib_ceiling_direct_periodic.json"))
    a = ap.parse_args()

    alphas, names, n_keywords = build_alphabets()
    na = len(alphas)
    print(f"keywords in pool          : {n_keywords} "
          f"(372 thematic-file entries + {len(CLASSIC)} classic, deduplicated)")
    print(f"distinct alphabets        : {na} (AZ + {na-1} keyword-mixed)")
    print(f"ordered alphabet pairs    : {na*na}")
    print(f"periods                   : 1..{MAX_PERIOD}")
    print(f"variants                  : {', '.join(VARIANTS)}")
    print(f"configs per crib level    : {na*na*MAX_PERIOD*len(VARIANTS):,}")
    print(f"crib levels               : {len(LEVELS)}")
    print(f"TOTAL ceiling evaluations : {na*na*MAX_PERIOD*len(VARIANTS)*len(LEVELS):,}")
    print()

    # ---- independent scalar cross-check against the library, non-vectorised ----
    print("cross-check vs scripts/lib/crib_filter.ceiling (scalar path):")
    ip = identity_perm(97)
    for lvl in ("L0_released", "L4_layoutA_reset"):
        cr = crib_level(lvl)
        for period in (3, 11, 26, 31, 47):
            for var in VARIANTS:
                for ci, pi in ((0, 0), (1, 0), (1, 1), (2, 5)):
                    al, cl = sub_outer(ip, period)
                    c, _ = ceiling(CT, cr, al, cl, ct_tab=index_table(alphas[ci]),
                                   pt_tab=index_table(alphas[pi]), variant=var)
                    # recompute the vectorised way for this single pair
                    pos = sorted(cr)
                    ta, tb = index_table(alphas[ci]), index_table(alphas[pi])
                    tv = []
                    for q in pos:
                        A_ = ta[ord(CT[q]) - 65]; B_ = tb[ord(cr[q]) - 65]
                        tv.append((A_ - B_) % 26 if var == "vig" else
                                  (A_ + B_) % 26 if var == "beau" else (B_ - A_) % 26)
                    g = defaultdict(list)
                    for k, q in enumerate(pos):
                        g[q % period].append(tv[k])
                    c2 = sum(max(np.bincount(v, minlength=26)) for v in g.values())
                    assert c == c2, (lvl, period, var, ci, pi, c, c2)
    print("  OK - scalar and vectorised ceilings agree on 120 spot checks\n")

    tasks = [(lvl, var, alphas, names) for lvl in LEVELS for var in VARIANTS]
    t0 = time.perf_counter()
    results = []
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        for r in ex.map(sweep_one, tasks):
            results.append(r)
            print(f"  done {r['level']:<18} {r['variant']:<6} "
                  f"({time.perf_counter()-t0:6.1f}s)")
    print(f"\nsweep wall time: {time.perf_counter()-t0:.1f}s with {a.workers} workers\n")

    by_level = {}
    for lvl in LEVELS:
        rs = [r for r in results if r["level"] == lvl]
        n = rs[0]["n"]
        tot_surv = tot_surv_inf = 0
        maxc = 0
        elim_periods, surv_periods, uninf_periods = [], [], []
        samples = []
        for period in range(1, MAX_PERIOD + 1):
            ps = sum(r["periods"][period]["survivors"] for r in rs)
            surplus = rs[0]["periods"][period]["surplus"]
            mc = max(r["periods"][period]["max_ceiling"] for r in rs)
            maxc = max(maxc, mc)
            tot_surv += ps
            if surplus == 0:
                uninf_periods.append(period)
            else:
                tot_surv_inf += ps
                (surv_periods if ps else elim_periods).append(period)
            for r in rs:
                if r["periods"][period]["survivors"] and len(samples) < 12:
                    samples.extend(r["periods"][period]["sample"][:2])
        by_level[lvl] = dict(
            n_cribs=n, max_ceiling=maxc, survivors=tot_surv,
            survivors_informative_periods=tot_surv_inf,
            periods_uninformative=uninf_periods,
            periods_fully_eliminated=elim_periods,
            periods_with_survivors=surv_periods,
            example_survivors=samples[:12],
            configs=len(rs) * na * na * MAX_PERIOD)
        print("=" * 78)
        print(f"{lvl}   n_cribs={n}   max ceiling over ALL configs = {maxc}/{n}")
        print(f"  configs tested                      : {by_level[lvl]['configs']:,}")
        print(f"  survivors (ceiling == n)            : {tot_surv:,}")
        print(f"  ... of which at informative periods : {tot_surv_inf:,}")
        print(f"  structurally uninformative periods  : {uninf_periods or 'none'}")
        print(f"  periods FULLY eliminated (all cfgs) : {elim_periods or 'none'}")
        print(f"  periods with >=1 survivor           : {surv_periods or 'none'}")
        for period in surv_periods:
            agg: dict[str, int] = defaultdict(int)
            per_var = {}
            for r in rs:
                per_var[r["variant"]] = r["periods"][period]["survivors"]
                for k2, v2 in r["periods"][period]["shapes"].items():
                    agg[k2] += v2
            tot = sum(per_var.values())
            sp = rs[0]['periods'][period]['surplus']
            chance = 26.0 ** (-sp)
            print(f"    P={period:<3} surplus={sp:<3}"
                  f" survivors={tot:>7,} of {3*na*na:,} = {tot/(3*na*na):.4%}"
                  f"  (chance 26^-surplus = {chance:.4%})")
            print(f"          by variant={per_var}  by shape={dict(agg)}")
        for s in samples[:6]:
            print(f"      survivor: {s}")
    print("=" * 78)

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump(dict(family="direct_alignment_periodic_substitution",
                       n_keywords=n_keywords, n_alphabets=na, n_pairs=na * na,
                       max_period=MAX_PERIOD, variants=list(VARIANTS),
                       by_level=by_level,
                       raw=[{k: v for k, v in r.items()} for r in results]), fh, indent=1)
    print(f"\nwrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
