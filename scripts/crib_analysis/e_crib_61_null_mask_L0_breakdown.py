#!/usr/bin/env python3
"""L0 breakdown for the null-mask sweep of e_crib_60.

L0_released is the only EVIDENCE level, so the survivors there are the result
that matters. This companion pass re-runs the L0 slice and reports, for every
(period, convention, mechanism, variant, ct-alphabet) cell, how many masks are
NOT eliminated -- and which mask families they belong to.

PRE-REGISTERED INTERPRETATION (unchanged from e_crib_60):
  ceiling <  n  => IMPOSSIBLE for every key (sound elimination)
  ceiling == n  => NOT ELIMINATED BY THIS FILTER.  Never "possible", never
                   "a candidate solution".
A cell where every crib lands in its own key class is VACUOUS: the filter
cannot say anything there, and its survivors are an artefact of the filter's
resolution, not evidence for the model.
"""
from __future__ import annotations
import json, os, sys, time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "sweep60", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "e_crib_60_null_mask_ceiling_sweep.py"))
S = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(S)


def _chunk(masks):
    cell = defaultdict(int)          # (period,conv,mech,var,ct) -> surviving masks
    vac = defaultdict(int)           # (period,conv,mech) -> masks in vacuous cells
    fam_surv = defaultdict(int)      # (family, min_surviving_period)
    for ns in masks:
        K = [p for p in range(S.N) if not (ns >> p) & 1]
        L = len(K); rank = {p: i for i, p in enumerate(K)}
        for conv in S.CONVS:
            ctc, info = S.canonical(K, L, rank, ns, "L0_released", conv)
            if ctc is None:
                continue
            kA, kB = S.canon_keys(ctc, info)
            n_eff = len(ctc)
            for mech, key in zip(S.MECHS, (kA, kB)):
                bases = [b for b, _, _ in key]
                tsl = []
                for (v, ctn, ptn) in S.CIPHERS:
                    ctt, ptt = S._TAB[ctn], S._TAB[ptn]
                    if v == "vig":
                        tsl.append([(ctt[ord(c)-65]-ptt[ord(q)-65]) % 26 for _, c, q in key])
                    elif v == "beau":
                        tsl.append([(ctt[ord(c)-65]+ptt[ord(q)-65]) % 26 for _, c, q in key])
                    else:
                        tsl.append([(ptt[ord(q)-65]-ctt[ord(c)-65]) % 26 for _, c, q in key])
                for period in S.PERIODS:
                    cls = [b % period for b in bases]
                    if len(set(cls)) == len(cls):
                        vac[(period, conv, mech)] += 1
                        for (v, ctn, ptn) in S.CIPHERS:
                            cell[(period, conv, mech, v, ctn)] += 1
                        continue
                    for ci, (v, ctn, ptn) in enumerate(S.CIPHERS):
                        if S._ceiling_from(cls, tsl[ci]) == n_eff:
                            cell[(period, conv, mech, v, ctn)] += 1
                            fam_surv[(period, conv, mech)] += 1
    return dict(cell), dict(vac), dict(fam_surv)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 2))
    ap.add_argument("--out", default=os.path.join(_ROOT, "results",
                                                  "null_mask_L0_breakdown.json"))
    a = ap.parse_args()
    t0 = time.perf_counter()
    seen, _ = S.build_masks()
    masks = list(seen)
    print(f"masks: {len(masks):,}")
    step = max(1, len(masks) // (a.workers * 8))
    parts = [masks[i:i+step] for i in range(0, len(masks), step)]
    cell = defaultdict(int); vac = defaultdict(int); nonvac = defaultdict(int)
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        for c, v, f in ex.map(_chunk, parts):
            for k, n in c.items(): cell[k] += n
            for k, n in v.items(): vac[k] += n
            for k, n in f.items(): nonvac[k] += n
    print(f"[{time.perf_counter()-t0:.1f}s]")

    print("\nL0_released survivors by period "
          "(masks NOT eliminated; 'vacuous' = every crib in its own key class)")
    print(f"{'per':>4} {'conv':<18} {'mech':<18} {'survivors':>10} "
          f"{'vacuous':>10} {'non-vacuous':>12}")
    rows = []
    for period in S.PERIODS:
        for conv in S.CONVS:
            for mech in S.MECHS:
                sv = sum(cell.get((period, conv, mech, v, ctn), 0)
                         for (v, ctn, _) in S.CIPHERS)
                vv = vac.get((period, conv, mech), 0) * len(S.CIPHERS)
                nv = nonvac.get((period, conv, mech), 0)
                rows.append((period, conv, mech, sv, vv, nv))
                if sv:
                    print(f"{period:>4} {conv:<18} {mech:<18} {sv:>10,} "
                          f"{vv:>10,} {nv:>12,}")
    tot_nv = sum(r[5] for r in rows)
    print(f"\nTOTAL non-vacuous L0 survivors across every period/cipher: {tot_nv:,}")
    minp = min([r[0] for r in rows if r[3]], default=None)
    print(f"Smallest period with ANY L0 survivor: {minp}")
    minp_nv = min([r[0] for r in rows if r[5]], default=None)
    print(f"Smallest period with a NON-VACUOUS L0 survivor: {minp_nv}")
    json.dump({"rows": rows, "total_non_vacuous": tot_nv,
               "min_period_any": minp, "min_period_non_vacuous": minp_nv},
              open(a.out, "w"), indent=2)
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
