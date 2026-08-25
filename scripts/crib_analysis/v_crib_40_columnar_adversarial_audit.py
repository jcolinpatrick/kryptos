#!/usr/bin/env python3
"""ADVERSARIAL AUDIT of e_crib_40_columnar_periodic_ceiling.py.

HYPOTHESIS UNDER TEST
---------------------
Not a cipher hypothesis. The claim under test is the *reviewed agent's* claim:
that the attainable-crib-ceiling filter, applied to columnar x periodic
substitution, soundly eliminates L0 at periods 1-20 and eliminates L1-L5
entirely, with survivor counts as reported.

METHOD
------
An INDEPENDENT numpy re-implementation of the ceiling (no numba, no reuse of
the reviewed script's kernel or its IP builder), built only on
scripts/lib/crib_filter.required_shift and kryptos.kernel.transforms.
transposition.columnar_perm / compose_perms.  Checks:

  C1  bijection audit of every permutation the reviewed script feeds the kernel
      at exhaustive widths, built its way and mine, compared.
  C2  independent ceiling formula validated against crib_filter.ceiling().
  C3  END-TO-END validation of the reviewed script's compiled numba kernel
      (which its own difftest never touches -- its "exact" arm compares the
      library to _kernel_single, a separate pure-python replica).
  C4  full independent recomputation of the survivor / max-ceiling cube over
      the exhaustive single-columnar widths, all levels, periods, peels,
      variants, alphabets.
  C5  brute-force key search at small periods: does max-over-all-keys equal
      the ceiling?  (soundness AND tightness of the bound)
  C6  a reported survivor reconstructed into an explicit key and verified to
      reproduce the cribs.
  C7  double-columnar composed-index audit of the reviewed script's blk trick.
  C8  vacuous-period audit at every level, not just L0.

PRE-REGISTERED INTERPRETATION
-----------------------------
  any mismatch in C1/C3/C4/C7      -> the reviewed numbers are not reproducible
  any survivor found at L1-L5      -> the reviewed elimination is REFUTED
  max-over-keys != ceiling in C5   -> the filter itself is wrong
  agreement                        -> the arithmetic is confirmed; the review
                                      then turns on scope and wording, not maths
"""
from __future__ import annotations

import itertools, math, os, random, sys, time
from collections import defaultdict

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

import numpy as np
import crib_filter as CF
import crib_sets as CS
from kryptos.kernel.constants import CT
from kryptos.kernel.transforms.transposition import (
    columnar_perm, compose_perms, validate_perm, apply_perm, invert_perm)

N, MOD = 97, 26
AZ = CF.AZ
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
VARIANTS = ("vig", "beau", "vbeau")
ALPHAS = (("az_az", AZ, AZ), ("ka_az", KA, AZ), ("ka_ka", KA, KA))
PERIODS = list(range(1, 31))
PEELS = ("sub_outer", "sub_inner")
LEVELS = CS.LEVELS

fails: list[str] = []
def check(ok, msg):
    print(("  OK   " if ok else "  FAIL ") + msg)
    if not ok:
        fails.append(msg)


# ---------------------------------------------------------------- my tables
def my_tables():
    qs, Ts = [], []
    for lv in LEVELS:
        m = CS.level(lv)
        items = sorted(m.items())
        qs.append(np.array([q for q, _ in items], dtype=np.int64))
        T = np.zeros((len(VARIANTS) * len(ALPHAS), len(items), N), dtype=np.int64)
        for vi, var in enumerate(VARIANTS):
            for ai, (_n, ca, pa) in enumerate(ALPHAS):
                ct_tab, pt_tab = CF.index_table(ca), CF.index_table(pa)
                for k, (_q, c) in enumerate(items):
                    for j in range(N):
                        T[vi * 3 + ai, k, j] = CF.required_shift(CT[j], c, ct_tab, pt_tab, var)
        Ts.append(T)
    return qs, Ts


def my_ceiling_batch(IP, qs_lev, T_va, period, peel):
    """IP (B,97) int64 -> (B,) ceilings, my own vectorised formula."""
    B, n = IP.shape[0], qs_lev.shape[0]
    j = IP[:, qs_lev]                                   # (B,n)
    t = T_va[np.arange(n)[None, :], j]                  # (B,n)
    cls = (j % period) if peel == 0 else np.broadcast_to(qs_lev % period, (B, n))
    code = cls * MOD + t                                # (B,n) < period*26
    W = period * MOD
    flat = (np.arange(B, dtype=np.int64)[:, None] * W + code).ravel()
    cnt = np.bincount(flat, minlength=B * W).reshape(B, period, MOD)
    return cnt.max(axis=2).sum(axis=1)


# ---------------------------------------------------------------- my IP build
def my_survivor_batch(IP, qs_lev, T_va, period, peel):
    """ceiling == n  iff every class holds a single distinct demanded shift,
    i.e. #distinct(class,shift) codes == #distinct classes.  O(n log n), exact."""
    B, n = IP.shape[0], qs_lev.shape[0]
    j = IP[:, qs_lev]
    t = T_va[np.arange(n)[None, :], j]
    cls = (j % period) if peel == 0 else np.broadcast_to(qs_lev % period, (B, n))
    code = np.sort(cls * MOD + t, axis=1)
    ncode = (np.diff(code, axis=1) != 0).sum(axis=1) + 1
    cs = np.sort(cls, axis=1)
    ncls = (np.diff(cs, axis=1) != 0).sum(axis=1) + 1
    return ncode == ncls


def my_ip(w, order):
    return np.array(CF.inverse(columnar_perm(w, tuple(order), N)), dtype=np.int64)


def main():
    t0 = time.perf_counter()
    print("=" * 78); print("ADVERSARIAL AUDIT — e_crib_40_columnar_periodic_ceiling.py"); print("=" * 78)

    sys.path.insert(0, os.path.join(_ROOT, "scripts", "crib_analysis"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "reviewed", os.path.join(_ROOT, "scripts", "crib_analysis",
                                 "e_crib_40_columnar_periodic_ceiling.py"))
    R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)

    qs, Ts = my_tables()

    # ---- C0 does the reviewed script's own control actually test its kernel? --
    print("\n[C0] sabotage test of the reviewed script's differential_test()")
    _qp, _nl, _T, _ = R.build_level_tables()
    _real = R.sweep_kernel

    def _stub(IP, qpos, nlen, T, periods, modtab, nthreads, acc, maxc, first):
        acc[...] = 0
        maxc[...] = 127          # absurd values; a real control must reject these
        first[...] = -1
    R.sweep_kernel = _stub
    caught = False
    try:
        R.differential_test(_qp, _nl, _T)
    except SystemExit:
        caught = True
    R.sweep_kernel = _real
    check(caught, "differential_test() rejects a fully sabotaged numba kernel "
                  "(it does NOT: its 6,480 'exact' checks compare the library to "
                  "_kernel_single, a pure-python replica, and its 3,000 remaining "
                  "checks are one-sided 'library <= recorded max')")

    # ---- C2 my formula vs crib_filter.ceiling ----------------------------
    print("\n[C2] independent formula vs scripts/lib/crib_filter.ceiling()")
    rng = random.Random(7)
    bad = 0; tot = 0
    for _ in range(300):
        w = rng.randint(2, 14); o = list(range(w)); rng.shuffle(o)
        perm = columnar_perm(w, tuple(o), N)
        ip = np.array(CF.inverse(perm), dtype=np.int64)[None, :]
        li = rng.randrange(6); p = rng.choice(PERIODS); peel = rng.randrange(2)
        vi = rng.randrange(3); ai = rng.randrange(3)
        mine = int(my_ceiling_batch(ip, qs[li], Ts[li][vi * 3 + ai], p, peel)[0])
        builder = CF.sub_outer if peel == 0 else CF.sub_inner
        al, cl = builder(perm, p)
        lib, _ = CF.ceiling(CT, CS.level(LEVELS[li]), al, cl,
                            ct_tab=CF.index_table(ALPHAS[ai][1]),
                            pt_tab=CF.index_table(ALPHAS[ai][2]), variant=VARIANTS[vi])
        tot += 1; bad += (mine != lib)
    check(bad == 0, f"my vectorised ceiling matches library on {tot} random configs ({bad} bad)")

    # ---- C1 bijection audit ---------------------------------------------
    print("\n[C1] bijection audit of the reviewed script's IP builder")
    nbad = 0; nperm = 0
    for w in range(2, 10):
        ORD = np.array(list(itertools.permutations(range(w))), dtype=np.int64)
        for st in range(0, ORD.shape[0], 20000):
            IP = R.ip_batch_columnar(w, ORD[st:st + 20000]).astype(np.int64)
            nperm += IP.shape[0]
            srt = np.sort(IP, axis=1)
            if not np.array_equal(srt, np.broadcast_to(np.arange(N), srt.shape)):
                nbad += 1
        # and agreement with the kernel primitive on a random subset
        idx = rng.sample(range(ORD.shape[0]), min(60, ORD.shape[0]))
        for i in idx:
            if not np.array_equal(R.ip_batch_columnar(w, ORD[i:i + 1])[0].astype(np.int64),
                                  my_ip(w, ORD[i])):
                nbad += 1
    check(nbad == 0, f"all {nperm:,} exhaustive-width IP rows are bijections of 0..96 "
                     f"and match columnar_perm ({nbad} bad blocks)")
    # sampled widths 10-14 as the reviewed script actually generates them
    pool = R.keyword_pool()
    nb2 = 0; ns = 0
    for w in range(10, 15):
        ORD, cov, nkw = R.orderings_for_width(w, pool, 3000, random.Random(1))
        IP = R.ip_batch_columnar(w, ORD).astype(np.int64)
        ns += IP.shape[0]
        srt = np.sort(IP, axis=1)
        if not np.array_equal(srt, np.broadcast_to(np.arange(N), srt.shape)):
            nb2 += 1
        if len(set(map(tuple, ORD.tolist()))) != ORD.shape[0]:
            nb2 += 1
    check(nb2 == 0, f"sampled-width generator: {ns:,} IP rows bijective and orderings distinct")

    # ---- C7 double-columnar composed index audit -------------------------
    print("\n[C7] double-columnar composed-permutation indexing")
    db = 0; dn = 0
    for w1, w2 in [(2, 3), (4, 5), (7, 12), (12, 7), (9, 9), (3, 11)]:
        o1 = np.array(list(itertools.islice(itertools.permutations(range(w1)), 5)), dtype=np.int64)
        o2 = np.array(list(itertools.islice(itertools.permutations(range(w2)), 4)), dtype=np.int64)
        IP1 = R.ip_batch_columnar(w1, o1); IP2 = R.ip_batch_columnar(w2, o2)
        A2 = IP2.shape[0]
        blk = np.ascontiguousarray(IP2[:, IP1].transpose(1, 0, 2).reshape(-1, N))
        for r in range(blk.shape[0]):
            a1, a2 = r // A2, r % A2
            p1 = columnar_perm(w1, tuple(int(x) for x in o1[a1]), N)
            p2 = columnar_perm(w2, tuple(int(x) for x in o2[a2]), N)
            want = np.array(CF.inverse(compose_perms(p1, p2)), dtype=np.int64)
            dn += 1
            if not np.array_equal(blk[r].astype(np.int64), want):
                db += 1
            if not validate_perm([int(x) for x in blk[r]], N):
                db += 1
    check(db == 0, f"{dn} composed rows match inverse(compose_perms(p1,p2)) and are bijections "
                   f"(descriptor mapping a1=r//A2, a2=r%A2 confirmed)")

    # ---- C3 END-TO-END numba kernel validation ---------------------------
    print("\n[C3] reviewed NUMBA kernel vs my independent formula (end-to-end)")
    qpos, nlen, T, _ = R.build_level_tables()
    # build the smoke perm set exactly as the reviewed script does (widths 2-6)
    IPs = []
    for w in range(2, 7):
        O = np.array(list(itertools.permutations(range(w))), dtype=np.int64)
        IPs.append(R.ip_batch_columnar(w, O))
    IPall = np.concatenate(IPs, axis=0)
    import numba
    numba.set_num_threads(1)
    acc = np.zeros((1, 6, 30, 2, 9), dtype=np.int64)
    maxc = np.zeros((1, 6, 30, 2, 9), dtype=np.int8)
    first = np.full((IPall.shape[0], 6), -1, dtype=np.int32)
    R.sweep_kernel(IPall, qpos, nlen, T, np.array(PERIODS, dtype=np.int64),
                   R.MODTAB, 1, acc, maxc, first)
    IP64 = IPall.astype(np.int64)
    mine_acc = np.zeros((6, 30, 2, 9), dtype=np.int64)
    mine_max = np.zeros((6, 30, 2, 9), dtype=np.int64)
    for li in range(6):
        n = int(nlen[li])
        for va in range(9):
            for pi, p in enumerate(PERIODS):
                for peel in range(2):
                    c = my_ceiling_batch(IP64, qs[li], Ts[li][va], p, peel)
                    mine_acc[li, pi, peel, va] = int((c == n).sum())
                    mine_max[li, pi, peel, va] = int(c.max())
    check(np.array_equal(acc[0], mine_acc),
          f"survivor cube matches over {IPall.shape[0]} perms x 540 cells x 6 levels "
          f"({IPall.shape[0]*540*6:,} ceilings); kernel total={int(acc.sum())}, "
          f"mine={int(mine_acc.sum())}")
    check(np.array_equal(maxc[0].astype(np.int64), mine_max), "max-ceiling cube matches exactly")

    # ---- C4 independent full recomputation, exhaustive widths ------------
    print("\n[C4] independent EXACT recomputation, exhaustive single widths 2-8")
    tot_acc = np.zeros((6, 30, 2, 9), dtype=np.int64)
    tot_max = np.zeros((6, 30, 2, 9), dtype=np.int64)
    nperms = 0
    for w in range(2, 9):
        O = np.array(list(itertools.permutations(range(w))), dtype=np.int64)
        for st in range(0, O.shape[0], 8000):
            IP = np.array([my_ip(w, o) for o in O[st:st + 8000]], dtype=np.int64)
            nperms += IP.shape[0]
            for li in range(6):
                n = int(nlen[li])
                for va in range(9):
                    for pi, p in enumerate(PERIODS):
                        for peel in range(2):
                            c = my_ceiling_batch(IP, qs[li], Ts[li][va], p, peel)
                            tot_acc[li, pi, peel, va] += int((c == n).sum())
                            m = int(c.max())
                            if m > tot_max[li, pi, peel, va]:
                                tot_max[li, pi, peel, va] = m
        print(f"    w={w} done, cumulative perms {nperms:,}  ({time.perf_counter()-t0:.0f}s)")
    print(f"\n  MY exact cube over {nperms:,} perms (widths 2-8 exhaustive):")
    for li, lv in enumerate(LEVELS):
        n = int(nlen[li])
        prof = tot_acc[li].sum(axis=(1, 2))
        nz = [PERIODS[i] for i in range(30) if prof[i] > 0]
        print(f"    {lv:<18} n={n:<3} survivors={int(tot_acc[li].sum()):>10,} "
              f"max_ceiling={int(tot_max[li].max())}/{n}  periods with survivors: {nz}")
        for peel_i, peel in enumerate(PEELS):
            pp = tot_acc[li, :, peel_i, :].sum(axis=1)
            nzp = [PERIODS[i] for i in range(30) if pp[i] > 0]
            print(f"    {'':<18}   {peel:<10} max={int(tot_max[li,:,peel_i,:].max())}  "
                  f"survivor periods: {nzp}")
    check(int(tot_acc[1:].sum()) == 0,
          f"L1-L5 ZERO survivors on widths 2-8 exhaustive ({int(tot_acc[1:].sum())} found)")
    check(int(tot_acc[0, :20].sum()) == 0,
          f"L0 ZERO survivors at periods 1-20 on widths 2-8 exhaustive "
          f"({int(tot_acc[0,:20].sum())} found)")

    print("\n[C4b] independent SURVIVOR-ONLY recomputation, widths 2-8 exhaustive "
          "+ regenerated 10-14 sample")
    fast = np.zeros((6, 30, 2, 9), dtype=np.int64)
    fperms = 0
    widthsets = []
    for w in range(2, 9):
        widthsets.append((w, np.array(list(itertools.permutations(range(w))), dtype=np.int64)))
    for w in range(10, 15):
        O, cov, nkw = R.orderings_for_width(w, pool, 6000, random.Random(20260825 + w))
        widthsets.append((w, O))
    for w, O in widthsets:
        for st in range(0, O.shape[0], 20000):
            IP = R.ip_batch_columnar(w, O[st:st + 20000]).astype(np.int64)
            fperms += IP.shape[0]
            for li in range(6):
                for va in range(9):
                    for pi, p in enumerate(PERIODS):
                        for peel in range(2):
                            fast[li, pi, peel, va] += int(
                                my_survivor_batch(IP, qs[li], Ts[li][va], p, peel).sum())
        print(f"    w={w} done ({O.shape[0]:,} orderings), cumulative {fperms:,} "
              f"({time.perf_counter()-t0:.0f}s)")
    print(f"\n  MY survivor counts over {fperms:,} perms:")
    for li, lv in enumerate(LEVELS):
        prof = fast[li].sum(axis=(1, 2))
        nz = [(PERIODS[i], int(prof[i])) for i in range(30) if prof[i] > 0]
        print(f"    {lv:<18} survivors={int(fast[li].sum()):>12,}  (period,count): {nz}")
        for peel_i, peel in enumerate(PEELS):
            pp = fast[li, :, peel_i, :].sum(axis=1)
            nzp = [(PERIODS[i], int(pp[i])) for i in range(30) if pp[i] > 0]
            print(f"    {'':<18}   {peel:<10} {nzp}")
    check(int(fast[1:].sum()) == 0,
          f"L1-L5 ZERO survivors on the wider independent set ({int(fast[1:].sum())} found)")
    check(int(fast[0, :20].sum()) == 0,
          f"L0 ZERO survivors at periods 1-20 on the wider independent set "
          f"({int(fast[0,:20].sum())} found)")
    # sub_inner p=27,28,29 must be 100%
    for p in (27, 28, 29):
        pi = p - 1
        got = int(fast[0, pi, 1, :].sum())
        want = fperms * 9
        check(got == want, f"L0 sub_inner p={p} is 100% vacuous: {got:,} of {want:,}")

    # ---- C8 vacuous periods at every level -------------------------------
    print("\n[C8] vacuous-period audit (sub_inner class = q % p, permutation-free)")
    for lv in LEVELS:
        qsl = sorted(CS.level(lv))
        vac = [p for p in PERIODS if len(set(q % p for q in qsl)) == len(qsl)]
        print(f"    {lv:<18} n={len(qsl):<3} vacuous sub_inner periods: {vac}")
    check(sorted(vacs := [p for p in PERIODS
                          if len(set(q % p for q in sorted(CS.level('L0_released'))))
                          == 24]) == [27, 28, 29],
          f"L0 sub_inner vacuous periods are exactly {vacs}")
    # near-vacuous: how many collisions at each L0 sub_inner period
    q0 = sorted(CS.level("L0_released"))
    nearv = []
    for p in PERIODS:
        d = defaultdict(int)
        for q in q0:
            d[q % p] += 1
        coll = sum(v - 1 for v in d.values())
        if 0 < coll <= 3:
            nearv.append((p, coll))
    print(f"    L0 sub_inner NEAR-vacuous periods (<=3 forced collisions): {nearv}")

    # ---- C5 brute-force key search: is the ceiling attained? -------------
    print("\n[C5] brute-force key search vs the ceiling (soundness AND tightness)")
    kbad = 0; kn = 0
    for trial in range(14):
        w = rng.randint(2, 9); o = list(range(w)); rng.shuffle(o)
        perm = columnar_perm(w, tuple(o), N)
        ip = CF.inverse(perm)
        p = rng.choice([1, 2, 3])
        peel = rng.randrange(2); vi = rng.randrange(3); ai = rng.randrange(3)
        lv = LEVELS[rng.randrange(6)]
        cribs = CS.level(lv)
        ct_tab, pt_tab = CF.index_table(ALPHAS[ai][1]), CF.index_table(ALPHAS[ai][2])
        best = -1
        for key in itertools.product(range(MOD), repeat=p):
            hit = 0
            for q, ch in cribs.items():
                j = ip[q]
                cls = (j % p) if peel == 0 else (q % p)
                if CF.required_shift(CT[j], ch, ct_tab, pt_tab, VARIANTS[vi]) == key[cls]:
                    hit += 1
            if hit > best:
                best = hit
        builder = CF.sub_outer if peel == 0 else CF.sub_inner
        al, cl = builder(perm, p)
        ceil_, _ = CF.ceiling(CT, cribs, al, cl, ct_tab=ct_tab, pt_tab=pt_tab,
                              variant=VARIANTS[vi])
        kn += 1
        if best != ceil_:
            kbad += 1
            print(f"      MISMATCH w={w} p={p} peel={PEELS[peel]} lv={lv} "
                  f"best_over_keys={best} ceiling={ceil_}")
    check(kbad == 0, f"max-over-all-keys == ceiling on {kn} exhaustively key-searched configs "
                     f"(bound is sound and tight)")

    # ---- C6 reconstruct an actual key for a reported survivor ------------
    print("\n[C6] reconstruct an explicit key for a reported L0 survivor")
    # reported: single w=3 order=(0,1,2) peel=sub_outer period=28 variant=vig alphabet=az_az
    perm = columnar_perm(3, (0, 1, 2), N)
    ip = CF.inverse(perm)
    p = 28
    ct_tab = pt_tab = CF.index_table(AZ)
    cribs = CS.level("L0_released")
    keyv = {}
    consistent = True
    for q, ch in cribs.items():
        j = ip[q]; c = j % p
        t = CF.required_shift(CT[j], ch, ct_tab, pt_tab, "vig")
        if c in keyv and keyv[c] != t:
            consistent = False
        keyv[c] = t
    key = [keyv.get(c, 0) for c in range(p)]
    # decrypt with that key and count crib hits
    hits = 0
    for q, ch in cribs.items():
        j = ip[q]
        ptc = AZ[(ct_tab[ord(CT[j]) - 65] - key[j % p]) % MOD]
        hits += (ptc == ch)
    ceil_, _ = CF.ceiling(CT, cribs, *CF.sub_outer(perm, p),
                          ct_tab=ct_tab, pt_tab=pt_tab, variant="vig")
    check(consistent and hits == 24 and ceil_ == 24,
          f"reported survivor reconstructs a real key: consistent={consistent} "
          f"crib hits={hits}/24 ceiling={ceil_}  key={''.join(AZ[k] for k in key)}")
    print("       NOTE: 24/24 crib hits here is NOT evidence of a solution. The key is "
          "28 free\n       symbols fitted to 24 constraints; it is an artefact of "
          "underdetermination.")
    # count how many of the 28 key slots are actually pinned
    print(f"       key slots pinned by cribs: {len(keyv)}/{p} "
          f"({p-len(keyv)} slots wholly free)")

    # ---- L0 sub_inner 100% claim ----------------------------------------
    print("\n[C9] L0 sub_inner p=27/28/29 100%-survivor arithmetic")
    exp = 4984308 * 9
    print(f"    reported per-period cell total 44,858,772 ; 4,984,308 perms x 9 = {exp:,}")
    check(exp == 44858772, "the reported 100% figure is exactly n_perms x 9 variant/alphabet")

    print("\n" + "=" * 78)
    print(f"AUDIT COMPLETE in {time.perf_counter()-t0:.0f}s — "
          f"{'ALL CHECKS PASSED' if not fails else str(len(fails)) + ' FAILURES'}")
    for f in fails:
        print("   FAILED: " + f)
    print("=" * 78)
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
