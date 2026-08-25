#!/usr/bin/env python3
"""SCOPE PROBES for the columnar x periodic ceiling result under review.

HYPOTHESIS UNDER TEST
---------------------
Two claims the reviewed sweep makes implicitly and does not test:

  S1 "the elimination is about COLUMNAR transposition".
     Probe: run the identical ceiling on UNIFORMLY RANDOM permutations of
     0..96 (a matched null that is not columnar at all).  If random
     permutations give the same zero-survivor pattern and comparable survivor
     rates, the result is a fact about CRIB GEOMETRY plus counting, and the
     4,984,308-permutation columnar sweep adds no discriminating information.

  S2 "the family is eliminated at L1-L5".
     The sweep fixes the tableau to three alphabet pairs (AZ,AZ), (KA,AZ),
     (KA,KA).  The natural Quagmire tableau space is far larger and includes
     (AZ,KA) and arbitrary keyword-mixed alphabets.  Adding alphabets can only
     ADD survivors.  Probe: the omitted pair plus random keyword-mixed pairs.

  S3 the columnar family is not closed under inversion: the sweep's model is
     out[i] = in[perm[i]] with perm = columnar_perm.  The other conventional
     direction (write down the columns, read across the rows) is the INVERSE
     permutation, which for w>2 is NOT itself a columnar_perm.  Probe: sweep
     the inverses and see whether they behave the same.

PRE-REGISTERED INTERPRETATION
-----------------------------
  random-perm survivor rate ~= columnar rate  -> S1 claim is uninformative
  any L1-L5 survivor under a new alphabet     -> S2 elimination is scope-bound
  inverse-direction differs materially        -> S3 is a real uncovered cell
Nothing here is a solution claim; ceiling == n remains only NOT ELIMINATED.
"""
from __future__ import annotations
import itertools, os, random, sys, time
import numpy as np

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

import crib_filter as CF
import crib_sets as CS
from kryptos.kernel.constants import CT
from kryptos.kernel.transforms.transposition import columnar_perm

N, MOD = 97, 26
AZ = CF.AZ
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
PERIODS = list(range(1, 31))
LEVELS = CS.LEVELS


def build_T(lv, variant, ca, pa):
    items = sorted(CS.level(lv).items())
    qsl = np.array([q for q, _ in items], dtype=np.int64)
    ct_tab, pt_tab = CF.index_table(ca), CF.index_table(pa)
    T = np.zeros((len(items), N), dtype=np.int64)
    for k, (_q, c) in enumerate(items):
        for j in range(N):
            T[k, j] = CF.required_shift(CT[j], c, ct_tab, pt_tab, variant)
    return qsl, T


def ceil_batch(IP, qsl, T, p, peel):
    B, n = IP.shape[0], qsl.shape[0]
    j = IP[:, qsl]
    t = T[np.arange(n)[None, :], j]
    cls = (j % p) if peel == 0 else np.broadcast_to(qsl % p, (B, n))
    code = cls * MOD + t
    W = p * MOD
    flat = (np.arange(B, dtype=np.int64)[:, None] * W + code).ravel()
    return np.bincount(flat, minlength=B * W).reshape(B, p, MOD).max(2).sum(1)


def sweep(IP, levels, alph_pairs, variants=("vig", "beau", "vbeau")):
    """-> dict[(lv, variant, alphname)] = (survivors_by_period_peel, maxceil)"""
    out = {}
    for lv in levels:
        n = len(CS.level(lv))
        for var in variants:
            for aname, ca, pa in alph_pairs:
                qsl, T = build_T(lv, var, ca, pa)
                surv = np.zeros((30, 2), dtype=np.int64)
                mx = 0
                for pi, p in enumerate(PERIODS):
                    for peel in (0, 1):
                        c = ceil_batch(IP, qsl, T, p, peel)
                        surv[pi, peel] = int((c == n).sum())
                        mx = max(mx, int(c.max()))
                out[(lv, var, aname)] = (surv, mx, n)
    return out


def main():
    t0 = time.perf_counter()
    rng = random.Random(4242)
    print("=" * 78); print("SCOPE PROBES — columnar x periodic ceiling"); print("=" * 78)

    # permutation sets, all the same size for a like-for-like rate comparison
    NP = 12000
    cols = []
    for w in range(2, 15):
        for _ in range(NP // 13 + 1):
            o = list(range(w)); rng.shuffle(o)
            cols.append(CF.inverse(columnar_perm(w, tuple(o), N)))
    cols = cols[:NP]
    IP_col = np.array(cols, dtype=np.int64)

    IP_rnd = np.array([np.random.default_rng(1000 + i).permutation(N) for i in range(NP)],
                      dtype=np.int64)

    # S3: inverse-direction columnar -> ip becomes the forward columnar perm
    invs = []
    for w in range(2, 15):
        for _ in range(NP // 13 + 1):
            o = list(range(w)); rng.shuffle(o)
            invs.append(columnar_perm(w, tuple(o), N))     # ip = perm itself
    IP_inv = np.array(invs[:NP], dtype=np.int64)

    A3 = [("az_az", AZ, AZ), ("ka_az", KA, AZ), ("ka_ka", KA, KA)]

    print(f"\n[S1] matched null: {NP:,} columnar vs {NP:,} uniformly random perms, L0, "
          f"3 alphabets x 3 variants")
    for tag, IP in (("columnar", IP_col), ("random-perm", IP_rnd),
                    ("columnar-INVERSE", IP_inv)):
        r = sweep(IP, ["L0_released"], A3)
        tot = np.zeros((30, 2), dtype=np.int64)
        for v in r.values():
            tot += v[0]
        cells = NP * 9
        print(f"  {tag:<18} total survivors {int(tot.sum()):>10,}  "
              f"of {cells*60:,} configs")
        for peel_i, peel in enumerate(("sub_outer", "sub_inner")):
            nz = [(PERIODS[i], int(tot[i, peel_i]), f"{tot[i,peel_i]/cells:.4%}")
                  for i in range(30) if tot[i, peel_i] > 0]
            print(f"     {peel:<10} periods with survivors: {nz}")

    print(f"\n[S2] alphabet scope at L1 and L5: the omitted pair (AZ,KA) plus "
          f"random keyword-mixed pairs")
    kws = ["PALIMPSEST", "ABSCISSA", "KRYPTOS", "BERLINCLOCK", "SHADOW", "LUCID",
           "IQLUSION", "UNDERGRUUND", "DESPARATLY", "TISYOURPOSITION"]
    extra = [("az_ka", AZ, KA)]
    for i in range(10):
        k1 = rng.choice(kws); k2 = rng.choice(kws)
        extra.append((f"kw_{k1[:4]}_{k2[:4]}", CF.keyword_mixed(k1), CF.keyword_mixed(k2)))
    IPsub = IP_col[:8000]
    for lv in ("L1_opening", "L2_opening_xgo", "L3_layoutB_x34",
               "L4_layoutA_reset", "L5_layoutA_rekey"):
        r = sweep(IPsub, [lv], A3 + extra)
        n = len(CS.level(lv))
        s3 = sum(int(v[0].sum()) for k, v in r.items() if k[2] in ("az_az", "ka_az", "ka_ka"))
        sx = sum(int(v[0].sum()) for k, v in r.items() if k[2] not in ("az_az", "ka_az", "ka_ka"))
        m3 = max(v[1] for k, v in r.items() if k[2] in ("az_az", "ka_az", "ka_ka"))
        mx = max(v[1] for k, v in r.items() if k[2] not in ("az_az", "ka_az", "ka_ka"))
        print(f"  {lv:<18} n={n:<3} | swept alphabets: surv={s3} max={m3}  "
              f"| 11 UNSWEPT alphabet pairs: surv={sx} max={mx}")

    print(f"\n[S1b] how much of the L0 survivor mass sits in near-vacuous cells")
    q0 = sorted(CS.level("L0_released"))
    for p in range(21, 31):
        from collections import Counter
        c = Counter(q % p for q in q0)
        coll = sum(v - 1 for v in c.values())
        print(f"    sub_inner p={p:<3} forced collisions={coll:<3} "
              f"chance survival ~ 26^-{coll} = {26.0**-coll:.3e}")

    print(f"\ndone in {time.perf_counter()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
