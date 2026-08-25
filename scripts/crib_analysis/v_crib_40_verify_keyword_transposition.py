"""ADVERSARIAL VERIFICATION of e_crib_40_keyword_transposition_variants.py.

HYPOTHESIS UNDER TEST
---------------------
Not a cipher hypothesis. The claim under test is the *reported result* of
scripts/crib_analysis/e_crib_40_keyword_transposition_variants.py:

  (C1) L0_released, periods 1-21: ZERO non-eliminations over the whole grid.
  (C2) L1..L5: 100% elimination at every period 1-30.
  (C3) L0 sub-outer non-eliminations at p<=25 number exactly 1,161 over 191
       distinct permutations, {22:3, 23:74, 24:820, 25:264}.
  (C4) The sub-inner peel is provably vacuous at p=27,28,29.
  (C5) Every enumerated permutation is a bijection of 0..96.
  (C6) "the ceiling formula was not reimplemented."
  (C7) 16,918 distinct permutations / 73,085,760 configurations tested.

SCOPE
-----
  1. Equivalence: the target's vectorised numpy ceiling path is compared
     cell-for-cell against scripts/lib/crib_filter.ceiling() + sub_outer /
     sub_inner (the control-verified path the target does NOT call).
  2. Independent re-derivation of C1 in pure Python via crib_filter only,
     over every GLOBALLY distinct permutation, periods 1-21, both peels,
     4 alphabet pairs, 3 variants.
  3. Global (cross-sub-family) permutation dedup count.
  4. Vacuity arithmetic for C4 recomputed from the crib positions directly.
  5. Crib-set nesting + deficit monotonicity: whether C2's five rows are five
     results or one.
  6. Byte-comparison of a fresh run against the published JSON.

PRE-REGISTERED INTERPRETATION -- fixed before the run
-----------------------------------------------------
  ceiling <  n_cribs  =>  IMPOSSIBLE for every key.  SOUND ELIMINATION.
  ceiling == n_cribs  =>  NOT ELIMINATED BY THIS FILTER. Never "possible",
                          never a candidate solution.
  A verification that reproduces a number CONFIRMS arithmetic only. It cannot
  upgrade a filter survival into evidence, and it cannot make a CONDITIONAL
  (L1-L5) elimination unconditional.
  Disagreement in any cell of step 1 or 2 REFUTES the reported result.
  Agreement leaves the reported eliminations standing as sound within their
  declared grid, and says nothing about the untested remainder.

Run:
    PYTHONPATH=src python3 -u scripts/crib_analysis/v_crib_40_verify_keyword_transposition.py
    PYTHONPATH=src python3 -u scripts/crib_analysis/v_crib_40_verify_keyword_transposition.py --quick
"""
from __future__ import annotations

import argparse
import importlib.util
import multiprocessing as mp
import os
import random
import sys
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import AZ, ceiling, index_table, sub_inner, sub_outer  # noqa: E402
from crib_sets import LEVELS, level as crib_level  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402
from kryptos.kernel.transforms.transposition import validate_perm  # noqa: E402

TARGET = os.path.join(_ROOT, "scripts", "crib_analysis",
                      "e_crib_40_keyword_transposition_variants.py")
_spec = importlib.util.spec_from_file_location("_tgt", TARGET)
TGT = importlib.util.module_from_spec(_spec)
_saved_argv, sys.argv = sys.argv, ["_tgt"]
_spec.loader.exec_module(TGT)
sys.argv = _saved_argv

TAB = {"AZ": index_table(AZ), "KA": index_table(TGT.KA)}
VARIANTS = ("vig", "beau", "vbeau")
LV = {k: crib_level(k) for k in LEVELS}


def _equiv_worker(chunk):
    bad, n = 0, 0
    for perm in chunk:
        res = TGT.ceilings_for_perm(perm)
        pl = list(perm)
        for lv in LEVELS:
            for peel, fn in (("outer", sub_outer), ("inner", sub_inner)):
                for p_i, per in enumerate(TGT.PERIODS):
                    al, cl = fn(pl, per)
                    for ctn in ("AZ", "KA"):
                        for ptn in ("AZ", "KA"):
                            for var in VARIANTS:
                                c, _ = ceiling(CT, LV[lv], al, cl, ct_tab=TAB[ctn],
                                               pt_tab=TAB[ptn], variant=var)
                                n += 1
                                if c != int(res[(lv, peel, ctn, ptn, var)][p_i]):
                                    bad += 1
    return bad, n


def _c1_worker(chunk):
    """Independent pure-Python re-derivation of C1 (and the same grid at L1)."""
    best = surv = cfg = best1 = surv1 = 0
    n0, n1 = len(LV["L0_released"]), len(LV["L1_opening"])
    for perm in chunk:
        pl = list(perm)
        for per in range(1, 22):
            for fn in (sub_outer, sub_inner):
                al, cl = fn(pl, per)
                for ctn in ("AZ", "KA"):
                    for ptn in ("AZ", "KA"):
                        for var in VARIANTS:
                            kw = dict(ct_tab=TAB[ctn], pt_tab=TAB[ptn], variant=var)
                            c, _ = ceiling(CT, LV["L0_released"], al, cl, **kw)
                            cfg += 1
                            best = max(best, c)
                            surv += (c == n0)
                            c1, _ = ceiling(CT, LV["L1_opening"], al, cl, **kw)
                            best1 = max(best1, c1)
                            surv1 += (c1 == n1)
    return best, surv, cfg, best1, surv1


def _surv_worker(chunk):
    """Re-enumerate L0 non-eliminations at p<=25, BOTH peels (the target's own
    enumerator covers sub-outer only)."""
    hits = []
    for fam, label, perm in chunk:
        pl = list(perm)
        for per in range(22, 26):
            for peel, fn in (("outer", sub_outer), ("inner", sub_inner)):
                al, cl = fn(pl, per)
                for ctn in ("AZ", "KA"):
                    for ptn in ("AZ", "KA"):
                        for var in VARIANTS:
                            c, _ = ceiling(CT, LV["L0_released"], al, cl,
                                           ct_tab=TAB[ctn], pt_tab=TAB[ptn],
                                           variant=var)
                            if c == 24:
                                hits.append((peel, per, fam, label, ctn, ptn, var))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 4))
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    os.environ.setdefault("OMP_NUM_THREADS", "1")

    kws = TGT.load_keywords(os.path.join(_ROOT, "wordlists", "thematic_keywords.txt"))
    perms, raw = TGT.enumerate_perms(kws)
    uniq = sorted({p for _, _, p in perms})

    print("=" * 78)
    print("STEP 0  provenance / frame safety")
    print("=" * 78)
    src = open(TARGET).read()
    print(f"  target references BEAN_EQ/BEAN_INEQ/BEAN_LINEAR : "
          f"{any(t in src for t in ('BEAN_EQ', 'BEAN_INEQ', 'BEAN_LINEAR'))}  (must be False)")
    for name in ("ceiling(", "sub_outer(", "sub_inner("):
        print(f"  target calls crib_filter.{name:<12} : "
              f"{('from crib_filter import' in src) and (name in src.split('import crib_filter')[-1] if False else name in src)}")
    print("  NOTE: target imports only AZ, index_table, inverse from crib_filter;")
    print("        the ceiling itself is re-implemented in numpy (ceilings_for_perm).")

    print("\n" + "=" * 78)
    print("STEP 1  numpy ceiling path  vs  scripts/lib/crib_filter.ceiling()")
    print("=" * 78)
    random.seed(20260825)
    samp = random.sample(uniq, 12 if args.quick else 40)
    samp += [tuple(random.sample(range(97), 97)) for _ in range(8 if args.quick else 20)]
    t = time.perf_counter()
    with mp.Pool(args.workers) as pool:
        rs = pool.map(_equiv_worker, [samp[i::args.workers] for i in range(args.workers)])
    bad, n = sum(r[0] for r in rs), sum(r[1] for r in rs)
    print(f"  compared {n:,} ceilings over {len(samp)} permutations "
          f"(real + uniform-random): mismatches = {bad}   [{time.perf_counter()-t:.1f}s]")

    print("\n" + "=" * 78)
    print("STEP 2  bijection + global dedup")
    print("=" * 78)
    nb = sum(1 for _, _, p in perms if not validate_perm(list(p), 97))
    print(f"  non-bijections among the {len(perms):,} swept rows : {nb}")
    print(f"  rows swept (within-sub-family dedup) : {len(perms):,}   "
          f"raw before dedup: {sum(raw.values()):,}")
    print(f"  GLOBALLY distinct permutations       : {len(uniq):,}   "
          f"(cross-sub-family duplicate rows: {len(perms)-len(uniq)})")
    real_cfgs = len(uniq) * 2 * 4 * 3 * len(TGT.PERIODS)
    print(f"  distinct CIPHER configurations (perm x peel x alphabet-pair x")
    print(f"    variant x period), crib level NOT counted as an axis : {real_cfgs:,}")
    print(f"  target's reported configs_tested                       : "
          f"{len(perms)*len(LEVELS)*2*4*3*len(TGT.PERIODS):,}")

    print("\n" + "=" * 78)
    print("STEP 3  independent re-derivation of C1 (L0, periods 1-21), pure Python")
    print("=" * 78)
    pool_in = uniq[::37] if args.quick else uniq
    ch = [pool_in[i:i + 64] for i in range(0, len(pool_in), 64)]
    t = time.perf_counter()
    B = S = C = B1 = S1 = 0
    with mp.Pool(args.workers) as pool:
        for b, s, c, b1, s1 in pool.imap_unordered(_c1_worker, ch):
            B = max(B, b); S += s; C += c; B1 = max(B1, b1); S1 += s1
    print(f"  perms {len(pool_in):,}  configs {C:,}  [{time.perf_counter()-t:.1f}s]")
    print(f"  L0 max ceiling {B}/24   non-eliminations {S}   "
          f"-> C1 {'CONFIRMED' if S == 0 else 'REFUTED'}")
    print(f"  L1 max ceiling {B1}/42  non-eliminations {S1}")

    print("\n" + "=" * 78)
    print("STEP 4  C4 vacuity arithmetic, recomputed from crib positions")
    print("=" * 78)
    qs = sorted(LV["L0_released"])
    for p in range(22, 31):
        d = len({q % p for q in qs})
        print(f"  p={p:<3} distinct(q mod p) = {d}/24   sub-inner ceiling forced to 24: "
              f"{'YES - filter is VACUOUS' if d == 24 else 'no'}")

    print("\n" + "=" * 78)
    print("STEP 5  are L2..L5 five results, or one?")
    print("=" * 78)
    for a, b in (("L0_released", "L1_opening"), ("L1_opening", "L2_opening_xgo"),
                 ("L2_opening_xgo", "L3_layoutB_x34"),
                 ("L2_opening_xgo", "L4_layoutA_reset"),
                 ("L2_opening_xgo", "L5_layoutA_rekey")):
        print(f"  {a:<16} is a subset of {b:<18}: "
              f"{set(LV[a].items()) <= set(LV[b].items())}")
    print("  Adding one crib raises one class max by at most 1, so the DEFICIT")
    print("  n - ceiling is monotone non-decreasing under crib-set extension.")
    viol = 0
    random.seed(3)
    for perm in random.sample(uniq, 200):
        pl = list(perm)
        for per in random.sample(range(1, 31), 5):
            for fn in (sub_outer, sub_inner):
                al, cl = fn(pl, per)
                d = {k: len(LV[k]) - ceiling(CT, LV[k], al, cl, ct_tab=TAB["AZ"],
                                             pt_tab=TAB["KA"], variant="beau")[0]
                     for k in LEVELS}
                for a, b in (("L0_released", "L1_opening"),
                             ("L1_opening", "L2_opening_xgo"),
                             ("L2_opening_xgo", "L3_layoutB_x34"),
                             ("L2_opening_xgo", "L4_layoutA_reset"),
                             ("L2_opening_xgo", "L5_layoutA_rekey")):
                    viol += d[a] > d[b]
    print(f"  monotonicity violations on 2,000 sampled cells: {viol}")
    print("  => the L1 elimination LOGICALLY IMPLIES L2, L3, L4, L5.")
    print("     Those four rows are corollaries, not independent evidence.")

    print("\n" + "=" * 78)
    print("STEP 6  C3 re-enumeration at p<=25, BOTH peels")
    print("=" * 78)
    ch2 = [perms[i:i + 64] for i in range(0, len(perms), 64)]
    if args.quick:
        ch2 = ch2[::11]
    H = []
    with mp.Pool(args.workers) as pool:
        for r in pool.imap_unordered(_surv_worker, ch2):
            H.extend(r)
    ho = [h for h in H if h[0] == "outer"]
    hi = [h for h in H if h[0] == "inner"]
    print(f"  sub-OUTER non-eliminations p<=25 : {len(ho)} over "
          f"{len({h[3] for h in ho})} distinct permutation labels")
    print(f"    by period {dict(sorted(Counter(h[1] for h in ho).items()))}")
    print(f"    by family {dict(sorted(Counter(h[2] for h in ho).items()))}")
    print(f"  sub-INNER non-eliminations p<=25 : {len(hi)}  "
          f"(NOT enumerated by the target's survivor_worker, which filters peel=='outer')")
    for h in sorted(hi):
        print(f"      p={h[1]} {h[3]} ct={h[4]} pt={h[5]} {h[6]}")
    print("\n  Every item above SURVIVED A FILTER. None is a solution, a candidate,")
    print("  or evidence of anything. Not eliminated != possible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
