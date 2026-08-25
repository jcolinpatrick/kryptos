#!/usr/bin/env python3
"""
e_crib_32_sub_then_strip
========================

FAMILY: crib_analysis
STATUS: active

HYPOTHESIS (proposed externally, 2026-08-25)
--------------------------------------------
    CT = StripTranspose( PeriodicSubstitution( PT ) )

Substitution FIRST with a short key, in the PLAINTEXT frame, then a STRIP
transposition that reorders contiguous blocks. The crib-derived key letters are
then correct values sitting at unknown block offsets, so for each period and
strip length the question is whether an assignment of blocks exists that makes
them mutually consistent.

WHY IT IS A GENUINE GAP
-----------------------
The plaintext-frame key order (sub_inner) IS already swept for columnar,
keyword-transposition and geometric-route permutations. STRIP transposition --
reordering contiguous blocks, kernel `strip_perm` -- is NOT among those
families. Columnar reads down columns and scatters neighbours; a strip
permutation keeps each block contiguous and in order. Different permutation
group, so the prior sweeps do not cover it.

METHOD
------
For strip length L, PT position q lies in PT-block a = q // L at offset
t = q % L. A strip permutation pi sends PT-block a to CT-block pi(a), so the
crib at q is enciphered into CT[pi(a)*L + t] and demands

    shift[q mod p] == required_shift( CT[pi(a)*L + t], crib_q )

Rather than enumerate all (n_blocks)! permutations, this does exact
backtracking over the CRIB-BEARING blocks only, propagating the partial
key map class -> shift and pruning on the first contradiction. Blocks holding
no crib are unconstrained and never branched on. That is what makes L = 2
tractable at all: 49 blocks, but only a handful carry cribs.

CONVENTIONS, stated because they are choices
--------------------------------------------
  * 97 is prime, so for L not dividing 97 the final block is short. A strip
    permutation may only exchange EQUAL-LENGTH blocks, so the ragged tail block
    is held fixed in place. Reported separately as `ragged`.
  * Both the identity assignment and all non-identity assignments are searched;
    the identity is the no-transposition control.

PRE-REGISTERED INTERPRETATION
-----------------------------
  ceiling/consistency is an EXISTENCE result over ALL keys:
      no consistent assignment  =>  IMPOSSIBLE for every key. SOUND ELIMINATION.
      a consistent assignment   =>  NOT ELIMINATED. Never "possible".
  Every cell is reported alongside a MATCHED NULL: the rate at which a RANDOM
  block assignment is consistent for the same (level, L, period). A cell whose
  null rate is ~1 is vacuous; a cell whose null rate is ~0 and which also finds
  nothing has learned something. This is mandatory per
  scripts/crib_analysis/e_crib_31_filter_power_analysis.py.

Repro:
  PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_32_sub_then_strip.py --workers 14
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from concurrent.futures import ProcessPoolExecutor

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import AZ, index_table, keyword_mixed, required_shift  # noqa: E402
from crib_sets import LEVELS, level  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402

N = 97
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ALPHAS = [("AZ/AZ", AZ, AZ), ("KA/AZ", KA, AZ), ("AZ/KA", AZ, KA),
          ("KA/PALIMPSEST", KA, keyword_mixed("PALIMPSEST"))]
VARIANTS = ("vig", "beau", "vbeau")


def blocks_for(L: int):
    """(list of block start indices, length of each, index of ragged block or None)"""
    starts = list(range(0, N, L))
    lens = [min(L, N - s) for s in starts]
    ragged = None
    for i, ln in enumerate(lens):
        if ln != L:
            ragged = i
    return starts, lens, ragged


def search(cribs, L, p, ct_tab, pt_tab, variant, forced=None, budget=400_000):
    """Exact backtracking: does ANY equal-length block assignment admit a key?

    Returns (found, exhausted). exhausted=False means the node budget ran out,
    in which case the cell is INCONCLUSIVE and must never be read as an
    elimination -- a timeout is not a disproof.
    """
    starts, lens, ragged = blocks_for(L)
    nb = len(starts)
    full = [i for i in range(nb) if lens[i] == L]
    # group cribs by PT block
    by_block: dict[int, list[tuple[int, int, str]]] = {}
    for q, c in cribs.items():
        a = q // L
        by_block.setdefault(a, []).append((q % L, q % p, c))
    crib_blocks = sorted(by_block, key=lambda a: -len(by_block[a]))

    def demands(a, b):
        """(class, shift) pairs if PT-block a sits at CT-block b; None if impossible."""
        out = []
        for t, cls, ch in by_block[a]:
            j = starts[b] + t
            if j >= N or t >= lens[b]:
                return None
            out.append((cls, required_shift(CT[j], ch, ct_tab, pt_tab, variant)))
        return out

    used = set()
    key: dict[int, int] = {}
    nodes = [0]

    def bt(k):
        nodes[0] += 1
        if nodes[0] > budget:
            raise TimeoutError
        if k == len(crib_blocks):
            return True
        a = crib_blocks[k]
        # the ragged block cannot move, and nothing can move into it
        cands = [a] if (ragged is not None and a == ragged) else \
                [b for b in (full if lens[a] == L else [a]) if b not in used]
        if forced is not None:
            cands = [b for b in cands if forced(a, b)]
        for b in cands:
            d = demands(a, b)
            if d is None:
                continue
            added = []
            ok = True
            for cls, sh in d:
                if cls in key:
                    if key[cls] != sh:
                        ok = False
                        break
                else:
                    key[cls] = sh
                    added.append(cls)
            if ok:
                used.add(b)
                if bt(k + 1):
                    return True
                used.discard(b)
            for cls in added:
                del key[cls]
        return False

    try:
        return bt(0), True
    except TimeoutError:
        return False, False


def null_rate(cribs, L, p, ct_tab, pt_tab, variant, trials, rng):
    """Fraction of RANDOM block assignments that are key-consistent."""
    starts, lens, ragged = blocks_for(L)
    nb = len(starts)
    full = [i for i in range(nb) if lens[i] == L]
    hit = 0
    for _ in range(trials):
        perm = full[:]
        rng.shuffle(perm)
        mapping = {a: perm[i] for i, a in enumerate(full)}
        if ragged is not None:
            mapping[ragged] = ragged
        key: dict[int, int] = {}
        ok = True
        for q, c in cribs.items():
            a, t = q // L, q % L
            b = mapping[a]
            j = starts[b] + t
            if j >= N or t >= lens[b]:
                ok = False
                break
            sh = required_shift(CT[j], c, ct_tab, pt_tab, variant)
            cls = q % p
            if cls in key and key[cls] != sh:
                ok = False
                break
            key[cls] = sh
        hit += ok
    return hit / trials


def _job(args):
    lname, L, p = args
    cribs = level(lname)
    n = len(cribs)
    vac = len({q % p for q in cribs}) == n     # every crib in its own class
    rng = random.Random(hash((lname, L, p)) & 0xFFFF)
    rows = []
    for aname, ca, pa in ALPHAS:
        ct_tab, pt_tab = index_table(ca), index_table(pa)
        for v in VARIANTS:
            found, done = search(cribs, L, p, ct_tab, pt_tab, v)
            nr = null_rate(cribs, L, p, ct_tab, pt_tab, v, 120, rng)
            rows.append({"alpha": aname, "variant": v, "consistent": bool(found),
                         "exhausted": bool(done), "null_rate": nr})
    return {"level": lname, "L": L, "period": p, "n_cribs": n,
            "vacuous": bool(vac), "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 2))
    ap.add_argument("--periods", type=int, default=20)
    ap.add_argument("--lmax", type=int, default=14)
    args = ap.parse_args()

    jobs = [(lv, L, p) for lv in LEVELS
            for L in range(2, args.lmax + 1) for p in range(1, args.periods + 1)]
    print("=" * 88)
    print("SUB-THEN-STRIP:  CT = StripTranspose( PeriodicSub( PT ) )")
    print("=" * 88)
    print(f"  levels {len(LEVELS)} x strip lengths 2-{args.lmax} x periods 1-{args.periods}"
          f" x {len(ALPHAS)} alphabet pairs x {len(VARIANTS)} variants")
    print(f"  = {len(jobs) * len(ALPHAS) * len(VARIANTS):,} exact existence searches"
          f"  ({args.workers} workers)")
    print()
    out = []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(_job, jobs, chunksize=4):
            out.append(r)

    for lv in LEVELS:
        rs = [r for r in out if r["level"] == lv]
        n = rs[0]["n_cribs"]
        tot = sum(len(r["rows"]) for r in rs)
        cons = sum(sum(x["consistent"] for x in r["rows"]) for r in rs)
        incon = sum(sum(not x["exhausted"] for x in r["rows"]) for r in rs)
        vcons = sum(sum(x["consistent"] for x in r["rows"]) for r in rs if r["vacuous"])
        maxnull = max((x["null_rate"] for r in rs for x in r["rows"]), default=0)
        print(f"  {lv:<18} n={n:>3}  consistent {cons:>6}/{tot:<6}"
              f"  (vacuous-period: {vcons})  inconclusive(budget): {incon}"
              f"  max null {maxnull:.3f}")
        live = [(r["L"], r["period"], x["alpha"], x["variant"], x["null_rate"])
                for r in rs if not r["vacuous"] for x in r["rows"]
                if x["consistent"] and x["exhausted"]]
        if live:
            print(f"       NOT ELIMINATED at informative periods: {len(live)}")
            for L, p, a, v, nr in sorted(live)[:12]:
                print(f"         L={L:>2} p={p:>2} {a:<14} {v:<6} null_rate={nr:.3f}")
        else:
            print("       nothing survives at any informative period")
    art = os.path.join(_ROOT, "results", "e_crib_32_sub_then_strip.json")
    with open(art, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nartifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
