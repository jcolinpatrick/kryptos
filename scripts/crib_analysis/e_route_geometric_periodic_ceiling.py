#!/usr/bin/env python3
"""Attainable-crib-ceiling sweep over GEOMETRIC ROUTE TRANSPOSITION x PERIODIC SUBSTITUTION.

ID:     e_route_geometric_periodic_ceiling
Family: crib_analysis
Status: active
Origin: 2026-08-25

HYPOTHESIS UNDER TEST
---------------------
K4 is a two-layer cipher combining ONE geometric route transposition of the 97
carved characters with ONE periodic additive substitution (Vigenere / Beaufort /
variant Beaufort) of period p, in either peel order:

    Model A (sub_outer)  CT = Sub( Route( PT ) )    key indexed in the CT frame
    Model B (sub_inner)  CT = Route( Sub( PT ) )    key indexed in the PT frame

"Geometric route" here means a route whose permutation is fixed by GEOMETRY
alone (grid shape, direction, corner, traversal rule) with NO secret column
ordering. Keyed columnar / Myszkowski are a different, larger family and are
deliberately OUT of scope here; they are covered elsewhere.

WHAT IS COMPUTED
----------------
For each configuration we compute the ATTAINABLE CRIB CEILING via
scripts/lib/crib_filter.ceiling(): the maximum number of cribs that could be
satisfied simultaneously, maximised over ALL keys of that period. No key search
is performed and none is needed -- the bound is closed form.

    ceiling <  n_cribs  =>  IMPOSSIBLE for every key.   SOUND ELIMINATION.
    ceiling == n_cribs  =>  NOT ELIMINATED BY THIS FILTER.

"ceiling == n" is NOT evidence that a solution exists. A configuration reported
as a "survivor" has survived one filter and nothing more.

L0_released is the only EVIDENCE level. Any elimination reported at L1-L5 is
conditional on an unproven plaintext hypothesis (the YESWONDERFULTHINGS opening
and/or a Layout-A/B bridge) and must be stated as conditional.

Bean equality / inequality / linear sets are NEVER used. Every route in this
sweep is crib-MOVING, and the frozen Bean sets are frame-bound to the carved-CT
pairing (systemic defect recorded 2026-08-24). The ceiling filter re-derives
everything from (CT, crib map, alignment) on every call.

ROUTE UNIVERSE AND RAGGED CONVENTION
------------------------------------
97 is PRIME, so no grid shape except 1x97 / 97x1 divides it exactly. The
convention used throughout, stated explicitly:

  GHOST-CELL CONVENTION. For a route of width w we build a grid of
  rows = ceil(97/w) by w cells, fill it ROW-MAJOR with indices 0..rows*w-1,
  traverse the full rectangular grid according to the route rule, and DROP any
  visited cell whose index is >= 97. The blanks therefore sit in the last row,
  which is the physically natural "he ran out of letters" raggedness. Every
  emitted route is asserted to be a bijection of range(97) before use; any
  candidate that is not is discarded and counted, never silently accepted.

Families enumerated (see build_routes()):
  rail_fence_perm            depths 2..48
  serpentine_perm            horizontal + vertical, widths 1..97
  spiral_perm                cw + ccw x 4 start corners, widths 1..97
  diagonal_perm              axis{main,anti} x order{fwd,rev} x start_edge{2}
                             x cell_order{fwd,rev,alternate}, widths 1..97
                             (canonical_diagonal_perm is a named member)
  ragged_turn_perm           K3's MEASURED primitive (f_ragged_turn_v1), cw+ccw,
                             widths 1..97
  grid_op_perm               fill x read over {ROW_LR,ROW_RL,COL_TD,COL_BU},
                             widths 1..97 (superset of the ragged turn)
  named grid routes          colLR / colRL / serpRow / antidiag / spiral from
                             scripts/_infra/named_route_universe_97
  apply_reflection           applied to every base route above
  apply_rotation             r = 1..96 applied to a CURATED subset (rail fence,
                             ragged turn, serpentine H/V, canonical diagonal,
                             spiral top-left cw/ccw). Rotating every base route
                             would be ~450k routes; the subset is declared so
                             the untested remainder is honest.

Cross product: routes x peel{2} x period{1..30} x variant{vig,beau,vbeau}
x ct_alphabet{AZ,KA} x pt_alphabet{AZ,KA} x crib level{L0..L5}.

PRE-REGISTERED INTERPRETATION (fixed before the run)
----------------------------------------------------
  * The ceiling filter is trivially satisfiable when the period is large enough
    that crib positions rarely collide in a class. At period p the expected
    ceiling under a random assignment rises toward n_cribs. Survivors at large p
    are therefore a PARAMETER COUNT, not a cipher. The informative regime is
    small p.
  * PRIMARY band: periods 7-11 (Sanborn's demonstrated band, K1=10, K2=8).
  * A result is reported as an ELIMINATION only when ceiling < n_cribs.
  * Zero survivors at a level/period is a sound elimination of that whole
    slice of the family for EVERY key.
  * Nonzero survivors are reported as "not eliminated", never as candidates.
  * Stop rule: exhaustive over the declared universe. Anything outside it is
    reported as untested.

MATCHED NULL
------------
scripts/crib_analysis/e_route_geometric_matched_null.py runs the identical
filter on uniformly random 97-permutations. MEASURED: under sub_inner the
filter is COMPLETELY VACUOUS at periods 27, 28 and 29 (survival rate 1.0000)
because the released crib positions 21-33 and 63-73 then occupy 24 distinct
residue classes and no two cribs can ever conflict. Survivor counts at those
periods carry ZERO information. Under sub_outer the random-permutation rate is
0.0000 at every period 1-30 over 20,000 trials.

ALPHABET ROBUSTNESS
-------------------
This sweep fixes ct/pt alphabets to {AZ, KA}, so its eliminations are
eliminations for those four pairs. scripts/crib_analysis/e_route_geometric_alphabet_probe.py
re-runs the identical filter over the 3,464 non-rotation base routes against 13
keyword-mixed alphabets (AZ, KA, PALIMPSEST, ABSCISSA, SANBORN, SCHEIDT,
LANGLEY, BERLIN, CLOCK, NORTHEAST, IQLUSION, UNDERGRUUND, DESPARATLY) at
periods 1..19. MEASURED: 400,424,544 configurations, ZERO survivors at every
crib level, L0 max ceiling 23/24. SAMPLED over alphabets, not exhaustive.

POSITIVE CONTROL
----------------
scripts/crib_analysis/e_route_geometric_positive_control.py synthesises
ciphertexts from 1,080 KNOWN route+period+variant+alphabet+peel configurations
and requires the filter never to eliminate the truth and to recover the true
key from per-class majority. MEASURED: 1,080 configurations x 6 crib levels,
0 failures; 0/2000 uniform random permutations survive L0 at period 7.

RUN
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_route_geometric_periodic_ceiling.py
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_route_geometric_periodic_ceiling.py --workers 14
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import sys
import time
from collections import defaultdict
from multiprocessing import Pool

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "_infra"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "campaigns"))

from crib_filter import AZ, MOD, index_table, inverse  # noqa: E402
import crib_sets  # noqa: E402
from kryptos.kernel.constants import CT, CT_LEN  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    apply_reflection, apply_rotation, canonical_diagonal_perm, diagonal_perm,
    rail_fence_perm, serpentine_perm, spiral_perm,
)

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N = CT_LEN
VARIANTS = ("vig", "beau", "vbeau")
ALPHAS = (("AZ", AZ), ("KA", KA))
PEELS = ("sub_outer", "sub_inner")

# ── route universe ────────────────────────────────────────────────────────

_BAD_ROUTES: list[str] = []


def _cell_sequence(rows: int, cols: int, order: str):
    if order == "ROW_LR":
        return [(r, c) for r in range(rows) for c in range(cols)]
    if order == "ROW_RL":
        return [(r, c) for r in range(rows) for c in range(cols - 1, -1, -1)]
    if order == "COL_TD":
        return [(r, c) for c in range(cols) for r in range(rows)]
    if order == "COL_BU":
        return [(r, c) for c in range(cols) for r in range(rows - 1, -1, -1)]
    raise ValueError(order)


def grid_op_perm(n: int, width: int, fill: str, read: str) -> list[int]:
    """Write n letters into a width-column grid in `fill` order, read in `read`
    order, skipping never-filled cells. Copied in spirit from
    scripts/campaigns/f_ragged_turn_v1.py (K3's measured grammar)."""
    rows = math.ceil(n / width)
    fseq = _cell_sequence(rows, width, fill)
    filled = {cell: i for i, cell in enumerate(fseq[:n])}
    return [filled[cell] for cell in _cell_sequence(rows, width, read) if cell in filled]


def ragged_turn_perm(n: int, width: int, direction: str = "cw") -> list[int]:
    """Physical 90-degree turn of a row-filled ragged grid (f_ragged_turn_v1)."""
    rows = math.ceil(n / width)
    out: list[int] = []
    if direction == "cw":
        col_iter, row_iter = range(width), range(rows - 1, -1, -1)
    else:
        col_iter, row_iter = range(width - 1, -1, -1), range(rows)
    for col in col_iter:
        for row in row_iter:
            idx = row * width + col
            if idx < n:
                out.append(idx)
    return out


def _named_grid_routes(width: int):
    """The five historical ragged-grid gathers (scripts/_infra/named_route_universe_97)."""
    rows = -(-N // width)
    grid = [[None] * width for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(width):
            if idx < N:
                grid[r][c] = idx
                idx += 1

    def dg(vals):
        return [v for v in vals if v is not None]

    yield f"grid{width}_colLR", dg(grid[r][c] for c in range(width) for r in range(rows))
    yield f"grid{width}_colRL", dg(grid[r][c] for c in range(width - 1, -1, -1) for r in range(rows))
    yield f"grid{width}_serpRow", dg(
        grid[r][c] for r in range(rows)
        for c in (range(width) if r % 2 == 0 else range(width - 1, -1, -1)))
    yield f"grid{width}_antidiag", dg(
        grid[r][d - r] for d in range(rows + width - 1) for r in range(rows)
        if 0 <= d - r < width)
    top, bot, left, right = 0, rows - 1, 0, width - 1
    spi: list = []
    while top <= bot and left <= right:
        spi.extend(grid[top][c] for c in range(left, right + 1))
        top += 1
        spi.extend(grid[r][right] for r in range(top, bot + 1))
        right -= 1
        if top <= bot:
            spi.extend(grid[bot][c] for c in range(right, left - 1, -1))
            bot -= 1
        if left <= right:
            spi.extend(grid[r][left] for r in range(bot, top - 1, -1))
            left += 1
    yield f"grid{width}_spiral", dg(spi)


def _emit(store: dict, name: str, family: str, perm) -> None:
    p = tuple(perm)
    if len(p) != N or sorted(p) != list(range(N)):
        _BAD_ROUTES.append(name)
        return
    if p not in store:
        store[p] = (name, family)


def build_routes(rotations: bool = True) -> list[tuple[str, str, tuple[int, ...]]]:
    store: dict[tuple[int, ...], tuple[str, str]] = {}
    curated: list[tuple[str, str, tuple[int, ...]]] = []

    def cur(name, family, perm):
        p = tuple(perm)
        if len(p) == N and sorted(p) == list(range(N)):
            curated.append((name, family, p))

    # rail fence
    for d in range(2, 49):
        p = rail_fence_perm(N, d)
        _emit(store, f"rail{d}", "rail_fence", p)
        cur(f"rail{d}", "rail_fence", p)
    # serpentine
    for c in range(1, N + 1):
        r = math.ceil(N / c)
        for vert, tag in ((False, "H"), (True, "V")):
            p = serpentine_perm(r, c, N, vert)
            _emit(store, f"serp{tag}{c}", "serpentine", p)
            cur(f"serp{tag}{c}", "serpentine", p)
    # spiral
    for c in range(1, N + 1):
        r = math.ceil(N / c)
        for cw in (True, False):
            for corner in ("top_left", "top_right", "bottom_right", "bottom_left"):
                nm = f"spiral{c}_{'cw' if cw else 'ccw'}_{corner}"
                p = spiral_perm(r, c, N, cw, start_corner=corner)
                _emit(store, nm, "spiral", p)
                if corner == "top_left":
                    cur(nm, "spiral", p)
    # diagonal
    for c in range(1, N + 1):
        r = math.ceil(N / c)
        for axis, ses in (("main", ("top_then_left", "left_then_top")),
                          ("anti", ("top_then_right", "right_then_top"))):
            for order in ("forward", "reverse"):
                for se in ses:
                    for co in ("forward", "reverse", "alternate"):
                        _emit(store, f"diag{c}_{axis}_{order}_{se}_{co}", "diagonal",
                              diagonal_perm(r, c, N, axis=axis, order=order,
                                            start_edge=se, cell_order=co))
        cur(f"canondiag{c}", "diagonal", canonical_diagonal_perm(c, N))
        _emit(store, f"canondiag{c}", "diagonal", canonical_diagonal_perm(c, N))
    # ragged turn (K3 measured primitive) + full grid-op grammar
    for w in range(1, N + 1):
        for d in ("cw", "ccw"):
            p = ragged_turn_perm(N, w, d)
            _emit(store, f"raggedturn{w}_{d}", "ragged_turn", p)
            cur(f"raggedturn{w}_{d}", "ragged_turn", p)
        for fill in ("ROW_LR", "ROW_RL", "COL_TD", "COL_BU"):
            for read in ("ROW_LR", "ROW_RL", "COL_TD", "COL_BU"):
                _emit(store, f"gridop{w}_{fill}_{read}", "grid_op",
                      grid_op_perm(N, w, fill, read))
        for nm, p in _named_grid_routes(w):
            _emit(store, nm, "named_grid", p)

    base = [(nm, fam, p) for p, (nm, fam) in store.items()]
    # reflections of every base route
    for nm, fam, p in list(base):
        _emit(store, f"{nm}~refl", fam + "_refl", apply_reflection(list(p)))
    # rotations of the curated subset
    if rotations:
        for nm, fam, p in curated:
            lp = list(p)
            for r in range(1, N):
                _emit(store, f"{nm}~rot{r}", fam + "_rot", apply_rotation(lp, r))
    return [(nm, fam, p) for p, (nm, fam) in store.items()]


# ── ceiling machinery ─────────────────────────────────────────────────────

_G: dict = {}


def _init(periods, levels):
    ctidx = {al: [tab[ord(ch) - 65] for ch in CT]
             for al, tab in ((a, index_table(s)) for a, s in ALPHAS)}
    lv = []
    for name in levels:
        d = crib_sets.level(name)
        qs = sorted(d)
        ptv = {al: [index_table(s)[ord(d[q]) - 65] for q in qs] for al, s in ALPHAS}
        qmod = {p: [q % p for q in qs] for p in periods}
        lv.append((name, qs, len(qs), ptv, qmod))
    _G["ctidx"] = ctidx
    _G["levels"] = lv
    _G["periods"] = list(periods)


def _ceil(cm, ts):
    """Attainable ceiling: sum over classes of max multiplicity of demanded shift."""
    cnt: dict = {}
    mx: dict = {}
    tot = 0
    for cl, t in zip(cm, ts):
        key = cl * 26 + t
        c = cnt.get(key, 0) + 1
        cnt[key] = c
        if c > mx.get(cl, 0):
            mx[cl] = c
            tot += 1
    return tot


def _work(chunk):
    ctidx = _G["ctidx"]
    levels = _G["levels"]
    periods = _G["periods"]
    # counters
    surv = defaultdict(int)              # (level, period) -> survivors
    tot_cfg = defaultdict(int)           # level -> configs
    maxc = defaultdict(int)              # level -> max ceiling seen
    surv_fam = defaultdict(int)          # (level, family) -> survivors
    surv_peel = defaultdict(int)         # (level, peel) -> survivors
    surv_pp = defaultdict(int)           # (level, peel, period) -> survivors
    examples: dict = defaultdict(list)   # level -> [(period, desc)]

    for rname, fam, perm in chunk:
        ip = inverse(perm)
        for lname, qs, n, ptv, qmod in levels:
            jl = [ip[q] for q in qs]
            jmod = {p: [j % p for j in jl] for p in periods}
            for ctal in ("AZ", "KA"):
                ci = ctidx[ctal]
                cvals = [ci[j] for j in jl]
                for ptal in ("AZ", "KA"):
                    pvals = ptv[ptal]
                    for var in VARIANTS:
                        if var == "vig":
                            ts = [(c - p_) % MOD for c, p_ in zip(cvals, pvals)]
                        elif var == "beau":
                            ts = [(c + p_) % MOD for c, p_ in zip(cvals, pvals)]
                        else:
                            ts = [(p_ - c) % MOD for c, p_ in zip(cvals, pvals)]
                        for peel in PEELS:
                            mods = jmod if peel == "sub_outer" else qmod
                            for p_ in periods:
                                cl = _ceil(mods[p_], ts)
                                tot_cfg[lname] += 1
                                if cl > maxc[lname]:
                                    maxc[lname] = cl
                                if cl == n:
                                    surv[(lname, p_)] += 1
                                    surv_fam[(lname, fam)] += 1
                                    surv_peel[(lname, peel)] += 1
                                    surv_pp[(lname, peel, p_)] += 1
                                    ex = examples[lname]
                                    if len(ex) < 400:
                                        ex.append((p_, f"{rname}|{peel}|p={p_}|{var}|ct={ctal}|pt={ptal}"))
    return (dict(surv), dict(tot_cfg), dict(maxc), dict(surv_fam),
            dict(surv_peel), dict(surv_pp),
            {k: sorted(v)[:40] for k, v in examples.items()})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=0,
                    help="0 = auto (usable CPUs - 2)")
    ap.add_argument("--chunk", type=int, default=200)
    ap.add_argument("--max-period", type=int, default=30)
    ap.add_argument("--no-rotations", action="store_true")
    ap.add_argument("--limit-routes", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(
        _ROOT, "results", "route_geometric_periodic_ceiling.json"))
    args = ap.parse_args()

    try:
        usable = len(os.sched_getaffinity(0))
    except AttributeError:
        usable = os.cpu_count() or 1
    workers = args.workers or max(1, usable - 2)

    periods = list(range(1, args.max_period + 1))
    levels = list(crib_sets.LEVELS)

    t0 = time.perf_counter()
    routes = build_routes(rotations=not args.no_rotations)
    if args.limit_routes:
        routes = routes[:args.limit_routes]
    print(f"[routes] {len(routes)} unique bijective routes "
          f"({len(_BAD_ROUTES)} rejected as non-bijective) "
          f"in {time.perf_counter()-t0:.1f}s")
    fam_counts = defaultdict(int)
    for _, f, _p in routes:
        fam_counts[f] += 1
    for f in sorted(fam_counts):
        print(f"    {f:<22} {fam_counts[f]}")

    cfgs_per_level = len(routes) * len(PEELS) * len(periods) * len(VARIANTS) * 4
    print(f"[scope] configs per level = {cfgs_per_level:,}; "
          f"total across {len(levels)} levels = {cfgs_per_level*len(levels):,}")
    print(f"[compute] workers={workers} usable_cpus={usable}")

    chunks = [routes[i:i + args.chunk] for i in range(0, len(routes), args.chunk)]
    surv = defaultdict(int); tot_cfg = defaultdict(int); maxc = defaultdict(int)
    surv_fam = defaultdict(int); surv_peel = defaultdict(int)
    surv_pp = defaultdict(int); examples = defaultdict(list)

    ckpt = args.out + ".partial"
    t1 = time.perf_counter()
    with Pool(workers, initializer=_init, initargs=(periods, levels)) as pool:
        for i, res in enumerate(pool.imap_unordered(_work, chunks), 1):
            s, tc, mc, sf, sp, sl, ex = res
            for k, v in s.items(): surv[k] += v
            for k, v in tc.items(): tot_cfg[k] += v
            for k, v in mc.items(): maxc[k] = max(maxc[k], v)
            for k, v in sf.items(): surv_fam[k] += v
            for k, v in sp.items(): surv_peel[k] += v
            for k, v in sl.items(): surv_pp[k] += v
            for k, v in ex.items():
                if len(examples[k]) < 200:
                    examples[k].extend(v)
            if i % 20 == 0 or i == len(chunks):
                el = time.perf_counter() - t1
                print(f"  chunk {i}/{len(chunks)}  {el:.0f}s  "
                      f"eta {el/i*(len(chunks)-i):.0f}s", flush=True)
                with open(ckpt, "w") as fh:
                    json.dump({"chunks_done": i, "chunks_total": len(chunks)}, fh)

    print(f"[done] {time.perf_counter()-t1:.1f}s")

    out = {
        "script": os.path.abspath(__file__),
        "family": "geometric route transposition x periodic substitution",
        "routes": len(routes),
        "rejected_non_bijective": len(_BAD_ROUTES),
        "route_families": dict(fam_counts),
        "periods": [periods[0], periods[-1]],
        "variants": list(VARIANTS),
        "alphabets": ["AZ", "KA"],
        "peel_orders": list(PEELS),
        "configs_per_level": cfgs_per_level,
        "configs_total": cfgs_per_level * len(levels),
        "by_level": {},
    }
    print()
    print("=" * 78)
    for lname, qs, n, _ptv, _qm in [(l[0], l[1], l[2], l[3], l[4]) for l in
                                    [(nm, sorted(crib_sets.level(nm)),
                                      len(crib_sets.level(nm)), None, None)
                                     for nm in levels]]:
        tot = tot_cfg[lname]
        s_tot = sum(v for (lv, _p), v in surv.items() if lv == lname)
        per_period = {p: surv.get((lname, p), 0) for p in periods}
        per_fam = {f: surv_fam.get((lname, f), 0) for f in sorted(fam_counts)}
        per_peel = {pl: surv_peel.get((lname, pl), 0) for pl in PEELS}
        ex = sorted(examples[lname])[:15]
        first_p = min([p for p in periods if per_period[p]], default=None)
        print(f"{lname:<18} n={n:<3} configs={tot:,}  survivors={s_tot:,}  "
              f"max_ceiling={maxc[lname]}/{n}  first_surviving_period={first_p}")
        print(f"{'':<18} per-period: " +
              " ".join(f"{p}:{per_period[p]}" for p in periods))
        out["by_level"][lname] = {
            "n_cribs": n,
            "configs": tot,
            "survivors": s_tot,
            "max_ceiling": maxc[lname],
            "first_surviving_period": first_p,
            "survivors_by_period": per_period,
            "survivors_by_family": per_fam,
            "survivors_by_peel": per_peel,
            "examples": [d for _p, d in ex],
            "survivors_by_peel_period": {
                pl: {p: surv_pp.get((lname, pl, p), 0) for p in periods}
                for pl in PEELS},
        }
    print("=" * 78)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=2)
    if os.path.exists(ckpt):
        os.remove(ckpt)
    print(f"[out] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
