#!/usr/bin/env python3
"""Attainable-crib-ceiling sweep: COLUMNAR TRANSPOSITION x PERIODIC SUBSTITUTION,
single and double columnar, both peel orders, over the L0-L5 crib ladder.

HYPOTHESIS UNDER TEST
---------------------
K4 = a columnar transposition composed with a periodic (Vigenere / Beaufort /
variant-Beaufort) substitution, in either peel order:

    Model A  "sub_outer"   CT = Sub( Transpose(PT) )   key runs in the CT frame
    Model B  "sub_inner"   CT = Transpose( Sub(PT) )   key runs in the PT frame

and the same with a DOUBLE columnar transposition (two columnar perms composed).

WHAT IS COMPUTED
----------------
For every configuration (transposition permutation, peel order, period,
substitution variant, tableau alphabet pair) the ATTAINABLE CRIB CEILING is
evaluated with scripts/lib/crib_filter.py's closed form: the maximum number of
cribs any key whatsoever could satisfy.  No key search is performed and none is
needed -- the bound quantifies over all keys at once.

PRE-REGISTERED INTERPRETATION  (fixed before the run; no post-hoc rescoring)
---------------------------------------------------------------------------
    ceiling <  n_cribs   ->  the configuration is IMPOSSIBLE for EVERY key.
                             This is a sound elimination.
    ceiling == n_cribs   ->  the configuration is NOT ELIMINATED BY THIS FILTER.
                             It is NOT a candidate solution, NOT "possible",
                             and NOT evidence of anything.  It survived one
                             cheap necessary condition, nothing more.

A cell (level, period, peel, variant, alphabet) with ZERO survivors across every
permutation tested is the headline result: for that cell, no tested
transposition admits any key at all.  Where the permutation set for a width is
sampled rather than exhaustive, a zero count is evidence about the sample, NOT a
proof about the width -- widths are labelled exhaustive / sampled throughout.

CONDITIONALITY
--------------
L0_released is the only EVIDENCE level; its results are unconditional.
Every elimination at L1-L5 is conditional on an unproven plaintext hypothesis
(the YESWONDERFULTHINGS opening, the XGO filler, the Layout A/B bridge).  A
false plaintext hypothesis makes the corresponding eliminations meaningless.
Report the level with every claim taken from this script.

SCOPE
-----
  single columnar : widths 2-14.
      w =  2- 8  ALL w! column orderings                     -> EXHAUSTIVE
      w =  9-14  keyword-derived orderings (keyword_to_order over a thematic /
                 Quagmire / English pool) + >= 200,000 uniformly random
                 orderings per width                          -> SAMPLED
  double columnar : width pair grid w1,w2 in 2-12.
      per width: all w! orderings for w <= 5, else a keyword+random pool
      capped at --dbl-pool orderings                          -> SAMPLED
  periods 1-30, variants vig / beau / vbeau,
  tableau alphabet pairs (ct_alphabet, pt_alphabet) in
      az_az = (AZ, AZ), ka_az = (KA, AZ), ka_ka = (KA, KA)
  crib levels L0..L5 from scripts/lib/crib_sets.py.

NOT COVERED (stated so the sample never reads as a proof)
---------------------------------------------------------
  * widths 9-14 are sampled: 200k of 9! = 3.6e5 (that width IS effectively
    covered) up to 200k of 14! = 8.7e10 (a ~2e-6 fraction).  See the run's
    "coverage" table for the exact fraction per width.
  * double columnar is a bounded grid, a vanishing fraction of (w1! x w2!).
  * widths > 14 single / > 12 double are untested.
  * periods > 30 and aperiodic / finite-tape keys are OUT OF SCOPE and cannot
    be addressed by this filter at all.
  * incomplete-column / irregular columnar variants, Myszkowski ties, and
    route/serpentine reads are NOT this family.
  * the ceiling is a NECESSARY condition only; nothing here searches keys or
    scores English.

CORRECTNESS
-----------
The numba kernel is a performance rewrite of the ceiling arithmetic, so it is
differential-tested against scripts/lib/crib_filter.ceiling() on randomly drawn
configurations before the sweep runs, and the script ABORTS on any mismatch.
scripts/lib/test_crib_filter.py (72/72 positive control, 0/2000 negative) is the
upstream guarantee for the formula itself.

USAGE
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_40_columnar_periodic_ceiling.py \
        [--workers N] [--random-per-width 200000] [--dbl-pool 144] \
        [--batch 60000] [--out results/crib40.json] [--resume] [--smoke]
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import random
import sys
import time
from typing import Dict, List, Sequence, Tuple

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

import numpy as np  # noqa: E402
import numba  # noqa: E402
from numba import njit, prange  # noqa: E402

import crib_filter as CF  # noqa: E402
import crib_sets as CS  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    columnar_perm, compose_perms, keyword_to_order,
)

N = 97
MOD = 26
AZ = CF.AZ
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

VARIANTS = ("vig", "beau", "vbeau")
ALPHAS = (("az_az", AZ, AZ), ("ka_az", KA, AZ), ("ka_ka", KA, KA))
VA = [(v, a[0]) for v in VARIANTS for a in ALPHAS]      # 9 combos, index = vi*3+ai
PERIODS = list(range(1, 31))
PEELS = ("sub_outer", "sub_inner")                       # 0, 1
LEVELS = CS.LEVELS


# ══════════════════════════════════════════════════════════════════════════
# static tables
# ══════════════════════════════════════════════════════════════════════════

def vacuous_periods(lev: str) -> List[int]:
    """Periods at which the sub_inner filter has NO purchase at all.

    Under sub_inner the class label is q % period, independent of the
    permutation.  If every crib position lands in its own residue class then
    no two cribs ever share a class, the ceiling is n by construction, and a
    "survivor" count there is an artefact of the crib geometry, not a fact
    about any cipher.  Such cells must never be read as a positive result.
    """
    qs = sorted(CS.level(lev))
    return [p for p in PERIODS if len(set(q % p for q in qs)) == len(qs)]


def build_level_tables() -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[int]]:
    """qpos[lev,k], nlen[lev], T[va,lev,k,j] = shift crib k demands if it lands on CT[j]."""
    crib_maps = [CS.level(lv) for lv in LEVELS]
    nlen = np.array([len(m) for m in crib_maps], dtype=np.int32)
    nmax = int(nlen.max())
    qpos = np.zeros((len(LEVELS), nmax), dtype=np.int8)
    T = np.zeros((len(VA), len(LEVELS), nmax, N), dtype=np.int8)
    for li, m in enumerate(crib_maps):
        items = sorted(m.items())
        for k, (q, _c) in enumerate(items):
            qpos[li, k] = q
        for vi, variant in enumerate(VARIANTS):
            for ai, (_name, ct_a, pt_a) in enumerate(ALPHAS):
                ct_tab, pt_tab = CF.index_table(ct_a), CF.index_table(pt_a)
                va = vi * len(ALPHAS) + ai
                for k, (_q, c) in enumerate(items):
                    for j in range(N):
                        T[va, li, k, j] = CF.required_shift(CT[j], c, ct_tab, pt_tab, variant)
    return qpos, nlen, T, [int(x) for x in nlen]


MODTAB = np.zeros((N, max(PERIODS) + 1), dtype=np.int8)
for _j in range(N):
    for _p in range(1, max(PERIODS) + 1):
        MODTAB[_j, _p] = _j % _p


# ══════════════════════════════════════════════════════════════════════════
# kernel
# ══════════════════════════════════════════════════════════════════════════

@njit(parallel=True, cache=True, fastmath=False, nogil=True)
def sweep_kernel(IP, qpos, nlen, T, periods, modtab, nthreads,
                 acc, maxc, first):
    """IP[b, i] = inverse-perm; acc/maxc are per-thread accumulators.

    acc[tid, lev, pi, peel, va] counts configurations whose ceiling == nlen[lev].
    maxc[tid, lev, pi, peel, va] is the max ceiling seen in that cell.
    first[b, lev] = ((pi*2+peel)*nva + va) of the first surviving cell, else -1.
    """
    B = IP.shape[0]
    nlev = qpos.shape[0]
    nmax = qpos.shape[1]
    nva = T.shape[0]
    nper = periods.shape[0]
    pmax = modtab.shape[1] - 1

    for tid in prange(nthreads):
        lo = (B * tid) // nthreads
        hi = (B * (tid + 1)) // nthreads
        jv = np.zeros(nmax, dtype=np.int64)
        tv = np.zeros(nmax, dtype=np.int64)
        cq = np.zeros(nmax, dtype=np.int64)
        cnt = np.zeros((pmax + 1) * MOD, dtype=np.int16)
        clsmax = np.zeros(pmax + 1, dtype=np.int16)
        for b in range(lo, hi):
            for lev in range(nlev):
                n = nlen[lev]
                for k in range(n):
                    jv[k] = IP[b, qpos[lev, k]]
                for va in range(nva):
                    for k in range(n):
                        tv[k] = T[va, lev, k, jv[k]]
                    for pi in range(nper):
                        p = periods[pi]
                        for peel in range(2):
                            if peel == 0:
                                for k in range(n):
                                    cq[k] = modtab[jv[k], p]
                            else:
                                for k in range(n):
                                    cq[k] = modtab[qpos[lev, k], p]
                            for k in range(n):
                                code = cq[k] * MOD + tv[k]
                                v = cnt[code] + 1
                                cnt[code] = v
                                if v > clsmax[cq[k]]:
                                    clsmax[cq[k]] = v
                            tot = 0
                            for c in range(p):
                                tot += clsmax[c]
                                clsmax[c] = 0
                            for k in range(n):
                                cnt[cq[k] * MOD + tv[k]] = 0
                            if tot > maxc[tid, lev, pi, peel, va]:
                                maxc[tid, lev, pi, peel, va] = tot
                            if tot == n:
                                acc[tid, lev, pi, peel, va] += 1
                                if first[b, lev] < 0:
                                    first[b, lev] = (pi * 2 + peel) * nva + va


# ══════════════════════════════════════════════════════════════════════════
# reference (slow, library) implementation for differential testing
# ══════════════════════════════════════════════════════════════════════════

def ref_ceiling(perm: Sequence[int], lev: str, period: int, peel: str,
                variant: str, ct_a: str, pt_a: str) -> int:
    cribs = CS.level(lev)
    builder = CF.sub_outer if peel == "sub_outer" else CF.sub_inner
    align, cls = builder(perm, period)
    c, _ = CF.ceiling(CT, cribs, align, cls,
                      ct_tab=CF.index_table(ct_a), pt_tab=CF.index_table(pt_a),
                      variant=variant)
    return c


def differential_test(qpos, nlen, T, trials: int = 400, seed: int = 20260825) -> None:
    rng = random.Random(seed)
    perms = []
    for _ in range(trials):
        w = rng.randint(2, 14)
        order = list(range(w))
        rng.shuffle(order)
        perms.append(columnar_perm(w, tuple(order), N))
    IP = np.array([CF.inverse(p) for p in perms], dtype=np.int8)
    nthreads = 1
    acc = np.zeros((nthreads, len(LEVELS), len(PERIODS), 2, len(VA)), dtype=np.int64)
    maxc = np.zeros_like(acc, dtype=np.int8)
    first = np.full((len(perms), len(LEVELS)), -1, dtype=np.int32)
    per = np.array(PERIODS, dtype=np.int64)
    # kernel gives per-cell maxima only; recompute cell-by-cell against the library
    # on a random subset of (b, lev, period, peel, va) coordinates.
    sweep_kernel(IP, qpos, nlen, T, per, MODTAB, nthreads, acc, maxc, first)
    bad = 0
    checked = 0
    for _ in range(3000):
        b = rng.randrange(len(perms))
        li = rng.randrange(len(LEVELS))
        pi = rng.randrange(len(PERIODS))
        peel = rng.randrange(2)
        vi = rng.randrange(len(VARIANTS))
        ai = rng.randrange(len(ALPHAS))
        got = ref_ceiling(perms[b], LEVELS[li], PERIODS[pi], PEELS[peel],
                          VARIANTS[vi], ALPHAS[ai][1], ALPHAS[ai][2])
        checked += 1
        if got > int(maxc[0, li, pi, peel, vi * 3 + ai]):
            bad += 1
    if bad:
        raise SystemExit(f"DIFFERENTIAL TEST FAILED: {bad}/{checked} library ceilings "
                         f"exceed the kernel's recorded cell maximum")
    # exact per-config agreement on a small grid
    exact_bad = 0
    exact_n = 0
    for b in range(12):
        for li in range(len(LEVELS)):
            for pi in (0, 4, 11, 23, 29):
                for peel in range(2):
                    for vi in range(3):
                        for ai in range(3):
                            want = ref_ceiling(perms[b], LEVELS[li], PERIODS[pi],
                                               PEELS[peel], VARIANTS[vi],
                                               ALPHAS[ai][1], ALPHAS[ai][2])
                            got = _kernel_single(IP[b], qpos, nlen, T, li, PERIODS[pi],
                                                 peel, vi * 3 + ai)
                            exact_n += 1
                            if want != got:
                                exact_bad += 1
    if exact_bad:
        raise SystemExit(f"DIFFERENTIAL TEST FAILED: {exact_bad}/{exact_n} exact mismatches")
    print(f"  differential test OK: {exact_n} exact ceilings match "
          f"scripts/lib/crib_filter.ceiling(), {checked} cell-max checks consistent")


def _kernel_single(ip_row, qpos, nlen, T, lev, p, peel, va) -> int:
    """Single-config replay of the kernel's arithmetic, in pure numpy/python."""
    n = int(nlen[lev])
    jv = [int(ip_row[qpos[lev, k]]) for k in range(n)]
    tv = [int(T[va, lev, k, jv[k]]) for k in range(n)]
    cq = [(jv[k] % p) if peel == 0 else (int(qpos[lev, k]) % p) for k in range(n)]
    from collections import defaultdict
    d = defaultdict(lambda: defaultdict(int))
    for k in range(n):
        d[cq[k]][tv[k]] += 1
    return sum(max(x.values()) for x in d.values())


# ══════════════════════════════════════════════════════════════════════════
# vectorised inverse-permutation construction
# ══════════════════════════════════════════════════════════════════════════

def _collen(w: int) -> np.ndarray:
    return np.array([(N - c + w - 1) // w for c in range(w)], dtype=np.int64)


def ip_batch_columnar(w: int, ORD: np.ndarray) -> np.ndarray:
    """ORD[b, c] = rank of column c.  Returns IP[b, q] = inverse(columnar_perm).

    Derivation: columnar_perm reads whole columns in rank order, so the output
    index of input position q is  (start of q's column) + (q // w), and the
    start of a column is the cumulative length of all lower-ranked columns.
    Checked against CF.inverse(columnar_perm(...)) in verify_ip_builder().
    """
    B = ORD.shape[0]
    collen = _collen(w)
    colbyrank = np.argsort(ORD, axis=1, kind="stable")          # (B,w)
    lens = collen[colbyrank]
    starts = np.zeros((B, w), dtype=np.int64)
    if w > 1:
        starts[:, 1:] = np.cumsum(lens, axis=1)[:, :-1]
    offset = np.empty((B, w), dtype=np.int64)
    np.put_along_axis(offset, colbyrank, starts, axis=1)         # offset[b, col]
    q = np.arange(N)
    IP = offset[:, q % w] + (q // w)
    return IP.astype(np.int8)


def verify_ip_builder(rng: random.Random, trials: int = 200) -> None:
    for _ in range(trials):
        w = rng.randint(2, 14)
        o = list(range(w))
        rng.shuffle(o)
        want = np.array(CF.inverse(columnar_perm(w, tuple(o), N)), dtype=np.int8)
        got = ip_batch_columnar(w, np.array([o], dtype=np.int64))[0]
        if not np.array_equal(want, got):
            raise SystemExit(f"IP BUILDER MISMATCH at w={w} order={o}")
    # composition identity: ip_of(compose(p1,p2))[q] == ip2[ip1[q]]
    for _ in range(80):
        w1, w2 = rng.randint(2, 12), rng.randint(2, 12)
        o1 = list(range(w1)); rng.shuffle(o1)
        o2 = list(range(w2)); rng.shuffle(o2)
        p1 = columnar_perm(w1, tuple(o1), N)
        p2 = columnar_perm(w2, tuple(o2), N)
        want = np.array(CF.inverse(compose_perms(p1, p2)), dtype=np.int8)
        ip1 = ip_batch_columnar(w1, np.array([o1], dtype=np.int64))[0]
        ip2 = ip_batch_columnar(w2, np.array([o2], dtype=np.int64))[0]
        got = ip2[ip1]
        if not np.array_equal(want, got):
            raise SystemExit(f"IP COMPOSITION MISMATCH w1={w1} w2={w2}")
    print(f"  IP builder OK: {trials} single + 80 composed permutations match "
          f"columnar_perm/compose_perms exactly")


# ══════════════════════════════════════════════════════════════════════════
# permutation generators
# ══════════════════════════════════════════════════════════════════════════

def keyword_pool() -> List[str]:
    words: List[str] = []
    for rel in ("wordlists/thematic_keywords.txt", "wordlists/thematic_keywords_v2.txt",
                "wordlists/quagmire3_keywords_oranchak.txt",
                "wordlists/quagmire4_keywords_oranchak.txt"):
        p = os.path.join(_ROOT, rel)
        if not os.path.exists(p):
            continue
        with open(p) as fh:
            for line in fh:
                s = line.strip().upper()
                if s and not s.startswith("#") and s.isalpha():
                    words.append(s)
    eng = os.path.join(_ROOT, "wordlists/english.txt")
    if os.path.exists(eng):
        with open(eng) as fh:
            for line in fh:
                s = line.strip().upper()
                if 6 <= len(s) <= 20 and s.isalpha():
                    words.append(s)
    seen, out = set(), []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def orderings_for_width(w: int, pool: List[str], n_random: int,
                        rng: random.Random,
                        exhaustive_max: int = 400_000) -> Tuple[np.ndarray, str, int]:
    """Return (ORD array (B,w), coverage_label, n_keyword_derived)."""
    fact = math.factorial(w)
    if fact <= max(n_random, exhaustive_max):
        return (np.array(list(itertools.permutations(range(w))), dtype=np.int64),
                "exhaustive", 0)
    seen: set = set()
    out: List[Tuple[int, ...]] = []
    kw_cap = n_random // 2
    for kw in pool:
        if len(out) >= kw_cap:
            break
        if len(kw) >= w:
            o = keyword_to_order(kw, w)
            if o is not None and o not in seen:
                seen.add(o)
                out.append(o)
    n_kw = len(out)
    base = list(range(w))
    target = n_kw + n_random
    while len(out) < target:
        rng.shuffle(base)
        o = tuple(base)
        if o not in seen:
            seen.add(o)
            out.append(o)
    return np.array(out, dtype=np.int64), "sampled", n_kw


def capped_orderings(w: int, pool: List[str], cap: int,
                     rng: random.Random) -> Tuple[np.ndarray, str]:
    fact = math.factorial(w)
    if fact <= cap:
        return np.array(list(itertools.permutations(range(w))), dtype=np.int64), "exhaustive"
    seen: set = set()
    out: List[Tuple[int, ...]] = []
    for kw in pool:
        if len(out) >= cap // 2:
            break
        if len(kw) >= w:
            o = keyword_to_order(kw, w)
            if o is not None and o not in seen:
                seen.add(o)
                out.append(o)
    base = list(range(w))
    while len(out) < cap:
        rng.shuffle(base)
        o = tuple(base)
        if o not in seen:
            seen.add(o)
            out.append(o)
    return np.array(out, dtype=np.int64), "sampled"


# ══════════════════════════════════════════════════════════════════════════
# driver
# ══════════════════════════════════════════════════════════════════════════

class Accumulator:
    def __init__(self, nthreads: int):
        shape = (nthreads, len(LEVELS), len(PERIODS), 2, len(VA))
        self.acc = np.zeros(shape, dtype=np.int64)
        self.maxc = np.zeros(shape, dtype=np.int8)
        self.nthreads = nthreads
        self.examples: Dict[str, List[str]] = {lv: [] for lv in LEVELS}
        self.n_perms = 0

    def totals(self):
        return self.acc.sum(axis=0), self.maxc.max(axis=0)


def save_ckpt(path: str, acc: "Accumulator", done: List[str], coverage_rows: List[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    np.savez(tmp, acc=acc.acc, maxc=acc.maxc, n_perms=acc.n_perms,
             done=np.array(done, dtype=object),
             examples=np.array(json.dumps(acc.examples), dtype=object),
             coverage=np.array(json.dumps(coverage_rows), dtype=object))
    os.replace(tmp + ".npz", path)


def load_ckpt(path: str, acc: "Accumulator"):
    d = np.load(path, allow_pickle=True)
    if d["acc"].shape != acc.acc.shape:
        raise SystemExit("checkpoint thread-count mismatch; rerun with the same --workers "
                         "or delete the checkpoint")
    acc.acc[:] = d["acc"]
    acc.maxc[:] = d["maxc"]
    acc.n_perms = int(d["n_perms"])
    acc.examples = json.loads(str(d["examples"]))
    return list(d["done"]), json.loads(str(d["coverage"]))


def run_batch(IP: np.ndarray, tables, acc: Accumulator, descs, per):
    qpos, nlen, T = tables
    first = np.full((IP.shape[0], len(LEVELS)), -1, dtype=np.int32)
    sweep_kernel(IP, qpos, nlen, T, per, MODTAB, acc.nthreads,
                 acc.acc, acc.maxc, first)
    acc.n_perms += IP.shape[0]
    nva = len(VA)
    for li, lv in enumerate(LEVELS):
        if len(acc.examples[lv]) >= 6:
            continue
        hits = np.nonzero(first[:, li] >= 0)[0]
        for b in hits[:6 - len(acc.examples[lv])]:
            code = int(first[b, li])
            va = code % nva
            rest = code // nva
            peel, pi = rest % 2, rest // 2
            acc.examples[lv].append(
                f"{descs(int(b))} | peel={PEELS[peel]} period={PERIODS[pi]} "
                f"variant={VARIANTS[va // 3]} alphabet={ALPHAS[va % 3][0]}"
            )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workers", type=int, default=0,
                    help="numba threads (0 = len(os.sched_getaffinity(0)) - 2)")
    ap.add_argument("--random-per-width", type=int, default=200_000)
    ap.add_argument("--dbl-pool", type=int, default=144)
    ap.add_argument("--dbl-max-width", type=int, default=12)
    ap.add_argument("--batch", type=int, default=60_000)
    ap.add_argument("--out", default=os.path.join(_ROOT, "results",
                                                  "crib40_columnar_periodic_ceiling.json"))
    ap.add_argument("--checkpoint", default=os.path.join(
        _ROOT, "checkpoints", "crib40_columnar_periodic.npz"))
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--smoke", action="store_true",
                    help="tiny run: widths 2-6 exhaustive only, no double columnar")
    ap.add_argument("--skip-difftest", action="store_true")
    args = ap.parse_args()

    avail = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 1)
    nthreads = args.workers if args.workers > 0 else max(1, avail - 2)
    nthreads = min(nthreads, numba.config.NUMBA_NUM_THREADS)
    numba.set_num_threads(nthreads)

    t0 = time.perf_counter()
    print("=" * 78)
    print("CRIB-CEILING SWEEP — columnar transposition x periodic substitution")
    print("=" * 78)
    print(f"  CPUs visible {avail}, numba threads {nthreads}, numpy {np.__version__}, "
          f"numba {numba.__version__}, python {sys.version.split()[0]}")

    qpos, nlen, T, nlist = build_level_tables()
    per = np.array(PERIODS, dtype=np.int64)
    tables = (qpos, nlen, T)

    if not args.skip_difftest:
        print("\n[control] differential-testing the numba kernel against "
              "scripts/lib/crib_filter.ceiling() ...")
        differential_test(qpos, nlen, T)
        verify_ip_builder(random.Random(99))

    rng = random.Random(20260825)
    pool = keyword_pool()
    print(f"\n  keyword pool: {len(pool)} words")

    acc = Accumulator(nthreads)
    coverage_rows: List[dict] = []
    done: List[str] = []
    if args.resume and os.path.exists(args.checkpoint):
        done, coverage_rows = load_ckpt(args.checkpoint, acc)
        print(f"\n  resumed from {args.checkpoint}: {len(done)} stages already done, "
              f"{acc.n_perms:,} permutations")

    # ── single columnar ───────────────────────────────────────────────────
    single_widths = list(range(2, 7)) if args.smoke else list(range(2, 15))
    n_rand = 2000 if args.smoke else args.random_per_width
    print("\n" + "-" * 78)
    print("STAGE 1 — single columnar")
    print("-" * 78)
    for w in single_widths:
        key = f"single:{w}"
        if key in done:
            print(f"  w={w:>2}  (checkpoint: already done)")
            continue
        ORD, cov, n_kw = orderings_for_width(w, pool, n_rand, rng)
        fact = math.factorial(w)
        coverage_rows.append({"stage": "single", "width": w, "orderings": int(ORD.shape[0]),
                              "keyword_derived": n_kw,
                              "space": fact, "fraction": ORD.shape[0] / fact,
                              "coverage": cov})
        tw = time.perf_counter()
        for st in range(0, ORD.shape[0], args.batch):
            sub = ORD[st:st + args.batch]
            IP = ip_batch_columnar(w, sub)
            run_batch(IP, tables, acc,
                      lambda b, w=w, c=sub: f"single w={w} order={tuple(int(x) for x in c[b])}",
                      per)
        done.append(key)
        save_ckpt(args.checkpoint, acc, done, coverage_rows)
        print(f"  w={w:>2}  {ORD.shape[0]:>7} orderings  ({cov:<10} "
              f"{ORD.shape[0]/fact:.3e} of {fact})  kw={n_kw:>6}  "
              f"{time.perf_counter()-tw:6.1f}s")

    # ── double columnar ───────────────────────────────────────────────────
    if not args.smoke:
        print("\n" + "-" * 78)
        print(f"STAGE 2 — double columnar, width grid 2-{args.dbl_max_width}")
        print("-" * 78)
        dwidths = list(range(2, args.dbl_max_width + 1))
        dords = {}
        dips = {}
        for w in dwidths:
            o, cov = capped_orderings(w, pool, args.dbl_pool, rng)
            dords[w] = (o, cov)
            dips[w] = ip_batch_columnar(w, o)
            print(f"    width {w:>2}: {o.shape[0]:>4} orderings ({cov})")
        total_pairs = sum(dords[a1][0].shape[0] * dords[b1][0].shape[0]
                          for a1 in dwidths for b1 in dwidths)
        space = sum(math.factorial(a1) * math.factorial(b1)
                    for a1 in dwidths for b1 in dwidths)
        if not any(r.get("stage") == "double" for r in coverage_rows):
            coverage_rows.append({"stage": "double", "width": f"2-{args.dbl_max_width} grid",
                                  "orderings": int(total_pairs), "keyword_derived": None,
                                  "space": space, "fraction": total_pairs / space,
                                  "coverage": "sampled"})
        print(f"    -> {total_pairs:,} composed permutations "
              f"({total_pairs/space:.3e} of the {space:.3e} grid space)")
        for w1 in dwidths:
            key = f"double:{w1}"
            if key in done:
                print(f"  w1={w1:>2} (checkpoint: already done)")
                continue
            tw = time.perf_counter()
            IP1 = dips[w1]
            for w2 in dwidths:
                IP2 = dips[w2]
                # composed inverse: ipc[q] = ip2[ip1[q]]
                blk = IP2[:, IP1].transpose(1, 0, 2).reshape(-1, N)
                A2 = IP2.shape[0]
                blk = np.ascontiguousarray(blk)
                for st in range(0, blk.shape[0], args.batch):
                    sub = blk[st:st + args.batch]
                    run_batch(sub, tables, acc,
                              lambda b, st=st, A2=A2, w1=w1, w2=w2,
                              o1=dords[w1][0], o2=dords[w2][0]:
                              (f"double w1={w1} order1="
                               f"{tuple(int(x) for x in o1[(st + b) // A2])} "
                               f"w2={w2} order2={tuple(int(x) for x in o2[(st + b) % A2])}"),
                              per)
            done.append(key)
            save_ckpt(args.checkpoint, acc, done, coverage_rows)
            print(f"  w1={w1:>2} done  {time.perf_counter()-tw:6.1f}s")

    # ── report ────────────────────────────────────────────────────────────
    surv, maxc = acc.totals()      # shape (lev, per, peel, va)
    elapsed = time.perf_counter() - t0
    n_perms = acc.n_perms
    cfg_per_perm = len(PERIODS) * 2 * len(VA)
    configs_tested = n_perms * cfg_per_perm

    print("\n" + "=" * 78)
    print("RESULTS")
    print("=" * 78)
    print(f"  permutations swept        : {n_perms:,}")
    print(f"  configs per permutation   : {cfg_per_perm} (30 periods x 2 peels x 9 variant/alphabet)")
    print(f"  configurations tested     : {configs_tested:,} per crib level")
    print(f"  ceiling evaluations total : {configs_tested*len(LEVELS):,}")
    print(f"  wall time                 : {elapsed:.1f}s")

    out_levels = []
    for li, lv in enumerate(LEVELS):
        n = nlist[li]
        s = int(surv[li].sum())
        m = int(maxc[li].max())
        vac = vacuous_periods(lv)
        out_levels.append({"level": lv, "n_cribs": n, "survivors": s, "max_ceiling": m,
                           "sub_inner_vacuous_periods": vac,
                           "example_survivors": acc.examples[lv]})
        print(f"\n  {lv}  (n={n}, {CS.DESCRIPTIONS[lv]})")
        print(f"    max ceiling over all {configs_tested:,} configs : {m}/{n}")
        print(f"    configs NOT eliminated (ceiling == n)          : {s:,} "
              f"({s/configs_tested:.3e})")
        print(f"    configs ELIMINATED (ceiling < n, sound)        : "
              f"{configs_tested-s:,}")
        # per-period survivor profile, summed over peel/variant/alphabet
        prof = surv[li].sum(axis=(1, 2))
        zero_p = [PERIODS[i] for i in range(len(PERIODS)) if prof[i] == 0]
        print(f"    periods with ZERO survivors (all peels/variants/alphabets, "
              f"all tested perms): {zero_p if zero_p else 'none'}")
        for peel_i, peel in enumerate(PEELS):
            pp = surv[li, :, peel_i, :].sum(axis=1)
            zp = [PERIODS[i] for i in range(len(PERIODS)) if pp[i] == 0]
            mx = int(maxc[li, :, peel_i, :].max())
            print(f"      {peel:<10} max={mx}/{n}  zero-survivor periods: "
                  f"{zp if zp else 'none'}")
        if vac:
            print(f"    VACUOUS under sub_inner at periods {vac}: every crib occupies its "
                  f"own\n      residue class there, so the ceiling is n by construction and "
                  f"the survivor\n      counts at those periods carry NO information.")

    print("\n  COVERAGE")
    for r in coverage_rows:
        print(f"    {r['stage']:<7} w={str(r['width']):<10} {r['orderings']:>9,} of "
              f"{r['space']:.3e}  = {r['fraction']:.3e}   [{r['coverage']}]")

    payload = {
        "script": os.path.abspath(__file__),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "family": "columnar transposition x periodic substitution (single + double)",
        "wall_seconds": elapsed,
        "threads": nthreads,
        "n_permutations": n_perms,
        "configs_per_permutation": cfg_per_perm,
        "configs_tested_per_level": configs_tested,
        "ceiling_evaluations": configs_tested * len(LEVELS),
        "periods": PERIODS, "peels": list(PEELS), "variants": list(VARIANTS),
        "alphabets": [a[0] for a in ALPHAS],
        "coverage": coverage_rows,
        "by_level": out_levels,
        "survivor_cube_shape": "[level][period][peel][variant*3+alphabet]",
        "survivor_cube": surv.tolist(),
        "maxceiling_cube": maxc.tolist(),
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(payload, fh, indent=1)
    print(f"\n  wrote {args.out}")
    print("\n  REMINDER: 'not eliminated' means the configuration survived one "
          "necessary\n  condition. It is not a candidate solution and not evidence "
          "of anything.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
