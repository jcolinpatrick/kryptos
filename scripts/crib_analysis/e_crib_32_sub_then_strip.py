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

RESULT (2026-08-25)
-------------------
  L0 (24 released cribs): 100 of 3120 cells not eliminated, 12 inconclusive.
  Survivors sit ONLY at strip length 2 (96) and 3 (4), and ONLY at periods
  11-20. Strip lengths 4-14 are eliminated at every period 1-20, for every
  key, across 4 alphabet pairs and 3 variants. L3 (46 cribs): 0 of 3120.

  THE SURVIVORS ARE AN ARTEFACT, AND THE null_rate BELOW DOES NOT SHOW IT.
  `null_rate` samples random ASSIGNMENTS against the real ciphertext, and
  reports 0.000 everywhere. But this sweep never samples assignments -- it
  SEARCHES for the best one over 48! of them at L=2. The matched null must
  therefore be: on a RANDOM ciphertext, does the same search still succeed?

      L=2 p=11   shuffled-CT search succeeds  97/120  = 80.8%
      L=2 p=15   shuffled-CT search succeeds 120/120  = 100.0%
      L=2 p=20   shuffled-CT search succeeds  13/15   = 86.7%
      L=3 p=13   shuffled-CT search succeeds   0/120  = 0.0%
      L=4 p=11   shuffled-CT search succeeds   0/120  = 0.0%

  So K4 surviving at L=2 is unremarkable: 49 blocks and a period above 10
  leave the search enough freedom that almost any ciphertext survives.
  The ELIMINATIONS are unaffected -- the true configuration satisfies the
  constraints by construction (162/162 positive controls), so a cell that
  fails to admit any assignment is a sound closure regardless of null rate.
  Null rates govern the reading of SURVIVORS, not of ELIMINATIONS.

  HEADLINE: strip lengths 4-14 closed on the released cribs alone; strip
  lengths 2-3 underdetermined, not evidence.

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


def search(cribs, L, p, ct_tab, pt_tab, variant, budget=150_000):
    """Exact CSP over block assignments, with forward checking.

    Variables  = PT blocks that contain at least one crib.
    Domain     = CT blocks of the same length, minus those already used.
    Constraint = the induced (key-class -> shift) demands must agree, both
                 within a block and across every pair of blocks.

    Returns (found, exhausted). exhausted=False means the node budget ran out,
    so the cell is INCONCLUSIVE and must never be read as an elimination.

    The naive version without forward checking does not terminate at L=2
    (49 blocks, 13 of them crib-bearing); pruning domains on every assignment
    is what makes small strip lengths tractable at all.
    """
    starts, lens, ragged = blocks_for(L)
    nb = len(starts)
    full = [i for i in range(nb) if lens[i] == L]

    by_block: dict[int, list[tuple[int, int, str]]] = {}
    for q, c in cribs.items():
        by_block.setdefault(q // L, []).append((q % L, q % p, c))
    variables = sorted(by_block)

    # demand[a][b] = list of (class, shift), or None if (a,b) is self-inconsistent
    demand: dict[int, dict[int, list]] = {}
    for a in variables:
        dom = {}
        cands = [a] if lens[a] != L else full
        for b in cands:
            if lens[b] != lens[a]:
                continue
            ds, ok, seen = [], True, {}
            for t, cls, ch in by_block[a]:
                j = starts[b] + t
                if t >= lens[b] or j >= N:
                    ok = False
                    break
                sh = required_shift(CT[j], ch, ct_tab, pt_tab, variant)
                if cls in seen and seen[cls] != sh:
                    ok = False
                    break
                seen[cls] = sh
                ds.append((cls, sh))
            if ok:
                dom[b] = ds
        demand[a] = dom

    if any(not demand[a] for a in variables):
        return False, True

    nodes = [0]

    def compatible(a, b, a2, b2):
        da, db = demand[a][b], demand[a2][b2]
        m = dict(da)
        for cls, sh in db:
            if m.get(cls, sh) != sh:
                return False
        return True

    def bt(assigned, used, domains):
        nodes[0] += 1
        if nodes[0] > budget:
            raise TimeoutError
        rest = [a for a in variables if a not in assigned]
        if not rest:
            return True
        a = min(rest, key=lambda x: len(domains[x]))      # most-constrained variable
        for b in list(domains[a]):
            if b in used:
                continue
            # forward check: prune every other variable's domain
            nd, dead = {}, False
            for a2 in rest:
                if a2 == a:
                    continue
                keep = [b2 for b2 in domains[a2]
                        if b2 != b and compatible(a, b, a2, b2)]
                if not keep:
                    dead = True
                    break
                nd[a2] = keep
            if dead:
                continue
            assigned[a] = b
            used.add(b)
            merged = dict(domains)
            merged.update(nd)
            if bt(assigned, used, merged):
                return True
            used.discard(b)
            del assigned[a]
        return False

    try:
        return bt({}, set(), {a: list(demand[a]) for a in variables}), True
    except TimeoutError:
        return False, False


def null_rate(cribs, L, p, ct_tab, pt_tab, variant, trials, rng):
    """Fraction of RANDOM block assignments that are key-consistent.

    WARNING: this is NOT the matched null for a survivor. It samples
    assignments while the sweep searches them. It reports 0.000 for cells
    where a shuffled-ciphertext SEARCH succeeds 80-100% of the time. Read it
    only as "a blind assignment does not happen to work"; for survivors use
    the shuffled-ciphertext search null recorded in the module docstring.
    """
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
            nr = null_rate(cribs, L, p, ct_tab, pt_tab, v, 60, rng)
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
    ap.add_argument("--levels", type=str, default=None,
                    help="comma-separated subset of crib levels; default all")
    args = ap.parse_args()

    levels = args.levels.split(",") if args.levels else list(LEVELS)
    jobs = [(lv, L, p) for lv in levels
            for L in range(2, args.lmax + 1) for p in range(1, args.periods + 1)]
    print("=" * 88)
    print("SUB-THEN-STRIP:  CT = StripTranspose( PeriodicSub( PT ) )")
    print("=" * 88)
    print(f"  levels {len(levels)} x strip lengths 2-{args.lmax} x periods 1-{args.periods}"
          f" x {len(ALPHAS)} alphabet pairs x {len(VARIANTS)} variants")
    print(f"  = {len(jobs) * len(ALPHAS) * len(VARIANTS):,} exact existence searches"
          f"  ({args.workers} workers)")
    print()
    out = []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(_job, jobs, chunksize=1):   # dynamic: cells vary 1000x in cost
            out.append(r)

    for lv in levels:
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
