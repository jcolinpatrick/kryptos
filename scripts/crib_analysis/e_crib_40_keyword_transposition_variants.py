"""Attainable-crib-ceiling sweep: KEYWORD-DRIVEN TRANSPOSITION VARIANTS
   composed with a PERIODIC SUBSTITUTION.

HYPOTHESIS UNDER TEST
---------------------
K4 is a two-layer cipher

    Model A (sub outer)   CT = Sub_periodic( Transpose_kw( PT ) )
    Model B (sub inner)   CT = Transpose_kw( Sub_periodic( PT ) )

where Transpose_kw is a keyword-driven transposition from one of four
sub-families -- Myszkowski, AMSCO, Nihilist (square) transposition, and a set
of "swapped" columnar variants -- and Sub_periodic is an arbitrary periodic
additive substitution (Vigenere / Beaufort / variant Beaufort) of period 1-30
over a fixed ciphertext alphabet and a fixed plaintext alphabet drawn from
{AZ, KA}.

SCOPE
-----
  transposition sub-families
    MYSZ   myszkowski_perm(kw, 97)                    [repo kernel builder]
    AMSCO  1/2-chunk fill, keyword column read-out    [implemented here]
    NIHIL  n x n square, key permutes rows AND cols   [implemented here]
    SWAPC  five columnar read/fill variants           [implemented here,
           built on the repo kernel columnar_perm]
  every permutation is tested in BOTH orientations (perm and its inverse),
  because a transposition hypothesis does not fix which direction is the
  encryption direction.
  keyword pool  : wordlists/thematic_keywords.txt, 369 unique A-Z keywords
  periods       : 1..30
  variants      : vig, beau, vbeau
  alphabets     : (ct_alpha, pt_alpha) over {AZ, KA} -- all 4 pairings
  crib levels   : L0..L5 from scripts/lib/crib_sets.py
  peel orders   : both (sub_outer / sub_inner)

PRE-REGISTERED INTERPRETATION -- fixed before the run
-----------------------------------------------------
The attainable-crib ceiling is an UPPER BOUND over ALL keys of the stated
period. The implication runs one way only:

    ceiling <  n_cribs  =>  the configuration is IMPOSSIBLE for every key.
                            SOUND ELIMINATION.
    ceiling == n_cribs  =>  the configuration is NOT ELIMINATED BY THIS
                            FILTER. This is NOT evidence that a solution
                            exists, and will not be reported as one.

A configuration with ceiling == n_cribs "survived a filter". Nothing more.

L0_released is the only EVIDENCE level; its results are unconditional. Any
elimination reported at L1..L5 is CONDITIONAL on an unproven plaintext
hypothesis and is stated as such.

Known weakness, declared in advance: the filter loses power as the period
grows, because more crib positions fall into distinct residue classes. At
large period relative to crib count the filter is near-vacuous and a
"survivor" there carries essentially no information. The per-period table in
the output is the honest way to read this, not the aggregate survivor count.

OUT OF FRAMEWORK
----------------
The Nihilist SUBSTITUTION cipher (Polybius digraph + additive numeric key) is
not an additive mod-26 shift per residue class and does not fit this filter.
It is handled separately and analytically: it requires a 25-cell Polybius
square (I/J merged), while K4's 97-character ciphertext contains all 26
letters. That is checked at runtime and eliminates the classical 5x5 Nihilist
substitution for K4 outright, at every crib level, without a sweep.

Run:
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_40_keyword_transposition_variants.py
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_40_keyword_transposition_variants.py --selftest
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

import numpy as np

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import AZ, index_table, inverse  # noqa: E402
from crib_sets import LEVELS, level as crib_level  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    columnar_perm, invert_perm, keyword_to_order, myszkowski_perm, validate_perm,
)

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N = 97
PERIODS = list(range(1, 31))
VARIANTS = ("vig", "beau", "vbeau")
ALPHAS = (("AZ", AZ), ("KA", KA))


# ══════════════════════════════════════════════════════════════════════════
# Permutation builders implemented here (AMSCO, Nihilist, swapped columnar)
# Every one of these is bijection-checked in selftest() before any filtering.
# ══════════════════════════════════════════════════════════════════════════

def amsco_perm(width: int, col_order: Sequence[int], length: int = N,
               *, start_two: bool = False, row_alt: bool = True) -> List[int]:
    """AMSCO: fill a grid with alternating 1- and 2-letter chunks, read columns
    out in keyword order.

    row_alt=True  -- each row restarts the 1/2 alternation with the opposite
                     size from the previous row (the classical checkerboard).
    row_alt=False -- the 1/2 toggle simply continues across the row boundary.
    """
    cells: List[List[List[int]]] = [[] for _ in range(width)]
    pos = 0
    row = 0
    size = 2 if start_two else 1
    while pos < length:
        if row_alt:
            size = (2 if start_two else 1) if row % 2 == 0 else (1 if start_two else 2)
        for c in range(width):
            if pos >= length:
                break
            take = min(size, length - pos)
            cells[c].append(list(range(pos, pos + take)))
            pos += take
            size = 3 - size
        row += 1
    rank_to_col = {r: i for i, r in enumerate(col_order)}
    perm: List[int] = []
    for rank in range(width):
        for cell in cells[rank_to_col[rank]]:
            perm.extend(cell)
    return perm


def nihilist_perm(order: Sequence[int], length: int = N, *, n: int = 10,
                  read_cols: bool = False) -> List[int]:
    """Nihilist (square) transposition: an n x n grid is filled row-wise, then
    the SAME key order permutes the rows and the columns; the result is read
    out row-wise (or column-wise).  Cells beyond `length` are blanks and are
    skipped on read-out, which keeps the map a bijection of 0..length-1.
    """
    if len(order) != n:
        raise ValueError("order length must equal n")
    src = [0] * n
    for i, r in enumerate(order):          # order[i] = rank of key letter i
        src[r] = i                         # output slot r takes input line i
    perm: List[int] = []
    if not read_cols:
        for r in range(n):
            for c in range(n):
                p = src[r] * n + src[c]
                if p < length:
                    perm.append(p)
    else:
        for c in range(n):
            for r in range(n):
                p = src[r] * n + src[c]
                if p < length:
                    perm.append(p)
    return perm


def columnar_variant_perm(width: int, col_order: Sequence[int], length: int,
                          mode: str) -> List[int]:
    """Five keyword-driven columnar read/fill variants.

    std      standard: row-wise fill, columns read top-to-bottom in key order
    revcol   as std but every column is read bottom-to-top
    boustcol as std but column direction alternates by key rank
    boustrow boustrophedon row fill, then standard column read-out
    revkey   as std but columns are read in DESCENDING key rank
    """
    cols: List[List[int]] = [[] for _ in range(width)]
    if mode == "boustrow":
        nrows = math.ceil(length / width)
        pos = 0
        for r in range(nrows):
            rng = range(width) if r % 2 == 0 else range(width - 1, -1, -1)
            for c in rng:
                if pos < length:
                    cols[c].append(pos)
                    pos += 1
        for c in range(width):
            cols[c].sort()
    else:
        for pos in range(length):
            cols[pos % width].append(pos)

    rank_to_col = {r: i for i, r in enumerate(col_order)}
    ranks = list(range(width))
    if mode == "revkey":
        ranks = ranks[::-1]
    perm: List[int] = []
    for k, rank in enumerate(ranks):
        col = cols[rank_to_col[rank]]
        if mode == "revcol":
            col = col[::-1]
        elif mode == "boustcol" and k % 2 == 1:
            col = col[::-1]
        perm.extend(col)
    return perm


# ══════════════════════════════════════════════════════════════════════════
# Configuration enumeration
# ══════════════════════════════════════════════════════════════════════════

def load_keywords(path: str) -> List[str]:
    out = []
    with open(path) as fh:
        for line in fh:
            s = line.strip().upper()
            if not s or s.startswith("#"):
                continue
            s = "".join(ch for ch in s if ch.isalpha())
            if 4 <= len(s) <= 20:
                out.append(s)
    return sorted(set(out))


def enumerate_perms(keywords: Sequence[str]) -> Tuple[List[Tuple[str, str, Tuple[int, ...]]], Dict[str, int]]:
    """Return [(subfamily, label, perm_tuple), ...] deduplicated per subfamily,
    plus a dict of raw (pre-dedup) counts per subfamily."""
    raw = defaultdict(int)
    seen: Dict[str, set] = defaultdict(set)
    out: List[Tuple[str, str, Tuple[int, ...]]] = []

    def add(fam: str, label: str, perm: List[int]) -> None:
        for tag, p in (("fwd", perm), ("inv", invert_perm(perm))):
            raw[fam] += 1
            t = tuple(p)
            if t in seen[fam]:
                continue
            seen[fam].add(t)
            out.append((fam, f"{label}|{tag}", t))

    for kw in keywords:
        L = len(kw)

        # --- MYSZKOWSKI: width is the keyword length, ties read across rows
        add("MYSZ", f"mysz:{kw}", myszkowski_perm(kw, N))

        # --- AMSCO: width = keyword length, 4 chunk-phase modes
        order = keyword_to_order(kw, L)
        for st in (False, True):
            for ra in (False, True):
                add("AMSCO", f"amsco:{kw}:w{L}:st{int(st)}:ra{int(ra)}",
                    amsco_perm(L, order, N, start_two=st, row_alt=ra))

        # --- NIHILIST square transposition: n=10 (100 cells) and n=11 (121)
        for n in (10, 11):
            if L >= n:
                o = keyword_to_order(kw, n)
                for rc in (False, True):
                    add("NIHIL", f"nihil:{kw}:n{n}:{'col' if rc else 'row'}",
                        nihilist_perm(o, N, n=n, read_cols=rc))

        # --- SWAPPED COLUMNAR variants: widths 4..14 plus the keyword length
        widths = sorted({w for w in range(4, 15) if w <= L} | ({L} if L <= 20 else set()))
        for w in widths:
            o = keyword_to_order(kw, w)
            if o is None:
                continue
            for mode in ("std", "revcol", "boustcol", "boustrow", "revkey"):
                add("SWAPC", f"swapc:{kw}:w{w}:{mode}",
                    columnar_variant_perm(w, o, N, mode))

    return out, dict(raw)


# ══════════════════════════════════════════════════════════════════════════
# Vectorised ceiling evaluation
# ══════════════════════════════════════════════════════════════════════════

CTCODE = np.frombuffer(CT.encode(), dtype=np.uint8).astype(np.int64) - 65
_OFF = np.cumsum([0] + [26 * p for p in PERIODS])[:-1]
_TOTBINS = int(26 * sum(PERIODS))
_PARR = np.array(PERIODS, dtype=np.int64)


def _level_arrays():
    out = {}
    for lv in LEVELS:
        d = crib_level(lv)
        qs = np.array(sorted(d), dtype=np.int64)
        pc = np.array([ord(d[int(q)]) - 65 for q in qs], dtype=np.int64)
        out[lv] = (qs, pc, len(qs))
    return out


LEVEL_ARRAYS = _level_arrays()
TABS = {name: np.array(index_table(a), dtype=np.int64) for name, a in ALPHAS}


def ceilings_for_perm(perm: Tuple[int, ...]) -> Dict[Tuple[str, str, str, str, str], np.ndarray]:
    """(level, peel, ct_alpha, pt_alpha, variant) -> array of ceilings, one per period."""
    ip = np.array(inverse(list(perm)), dtype=np.int64)
    res = {}
    for lv, (qs, pc, n) in LEVEL_ARRAYS.items():
        j = ip[qs]
        ccode = CTCODE[j]
        for ctn, _ in ALPHAS:
            cidx = TABS[ctn][ccode]
            for ptn, _ in ALPHAS:
                pidx = TABS[ptn][pc]
                tmap = {"vig": (cidx - pidx) % 26,
                        "beau": (cidx + pidx) % 26,
                        "vbeau": (pidx - cidx) % 26}
                for peel, src in (("outer", j), ("inner", qs)):
                    cls = (src[None, :] % _PARR[:, None])       # (30, n)
                    base = _OFF[:, None] + cls * 26             # (30, n)
                    for var, t in tmap.items():
                        keys = (base + t[None, :]).ravel()
                        cnt = np.bincount(keys, minlength=_TOTBINS)
                        ceils = np.empty(len(PERIODS), dtype=np.int64)
                        for k, p in enumerate(PERIODS):
                            o = int(_OFF[k])
                            ceils[k] = cnt[o:o + 26 * p].reshape(p, 26).max(axis=1).sum()
                        res[(lv, peel, ctn, ptn, var)] = ceils
    return res


def survivor_worker(chunk):
    """Enumerate every NOT-ELIMINATED configuration at L0 with the sub-outer
    peel and period <= SURV_MAXP -- i.e. the region where the filter still has
    real discriminating power. Returns full labels so each can be re-derived."""
    out = []
    for fam, label, perm in chunk:
        res = ceilings_for_perm(perm)
        for (lv, peel, ctn, ptn, var), ceils in res.items():
            if lv != "L0_released" or peel != "outer":
                continue
            for k, p in enumerate(PERIODS):
                if p <= SURV_MAXP and int(ceils[k]) == 24:
                    out.append((fam, label, ctn, ptn, var, p))
    return out


SURV_MAXP = 25


def _set_maxp(v: int) -> None:
    globals()["SURV_MAXP"] = v


def worker(chunk):
    """Aggregate over a chunk of permutations. Returns compact summaries."""
    # per (fam, level): total configs, survivors, max ceiling
    agg = defaultdict(lambda: [0, 0, 0])
    # per (fam, level, period): total, survivors
    per_period = defaultdict(lambda: [0, 0])
    examples = defaultdict(list)
    for fam, label, perm in chunk:
        res = ceilings_for_perm(perm)
        for (lv, peel, ctn, ptn, var), ceils in res.items():
            n = LEVEL_ARRAYS[lv][2]
            a = agg[(fam, lv)]
            a[0] += len(PERIODS)
            mx = int(ceils.max())
            if mx > a[2]:
                a[2] = mx
            surv_mask = ceils == n
            ns = int(surv_mask.sum())
            a[1] += ns
            for k, p in enumerate(PERIODS):
                pp = per_period[(fam, lv, peel, p)]
                pp[0] += 1
                if ceils[k] == n:
                    pp[1] += 1
            if ns and len(examples[(fam, lv)]) < 40:
                for k in np.nonzero(surv_mask)[0]:
                    if len(examples[(fam, lv)]) >= 40:
                        break
                    examples[(fam, lv)].append(
                        f"{label} peel={peel} ct={ctn} pt={ptn} {var} p={PERIODS[k]}")
    return (dict(agg), dict(per_period), dict(examples))


# ══════════════════════════════════════════════════════════════════════════
# Self-test: every builder must be a bijection of 0..96
# ══════════════════════════════════════════════════════════════════════════

def selftest(keywords: Sequence[str]) -> int:
    fails = 0
    checked = 0
    perms, raw = enumerate_perms(keywords)
    for fam, label, p in perms:
        checked += 1
        if not validate_perm(list(p), N):
            fails += 1
            print(f"  NOT A BIJECTION: {fam} {label}")
            if fails > 5:
                return 1
    print(f"  bijection check: {checked - fails}/{checked} distinct permutations "
          f"are valid bijections of 0..{N-1}")

    # AMSCO round-trip against a naive chunk model
    txt = "".join(chr(65 + i % 26) for i in range(N))
    o = keyword_to_order("CARGO", 5)
    pm = amsco_perm(5, o, N, start_two=False, row_alt=True)
    enc = "".join(txt[i] for i in pm)
    dec = [""] * N
    for i, s in enumerate(pm):
        dec[s] = enc[i]
    assert "".join(dec) == txt, "AMSCO round-trip failed"

    # Nihilist: identity key must be the identity permutation
    idp = nihilist_perm(list(range(10)), N, n=10, read_cols=False)
    assert idp == list(range(N)), "Nihilist identity key is not the identity perm"

    # columnar 'std' variant must agree with the repo kernel builder
    for kw, w in (("PALIMPSEST", 7), ("ABSCISSA", 8), ("KRYPTOS", 7)):
        oo = keyword_to_order(kw, w)
        assert columnar_variant_perm(w, oo, N, "std") == columnar_perm(w, oo, N), \
            f"columnar std diverges from kernel for {kw}/{w}"

    # Myszkowski with an all-distinct keyword must equal standard columnar
    kw = "CHARMS"
    assert myszkowski_perm(kw, N) == columnar_perm(len(kw), keyword_to_order(kw, len(kw)), N), \
        "Myszkowski/columnar degeneracy check failed"

    # 26-letter check that kills classical 5x5 Nihilist SUBSTITUTION
    assert len(set(CT)) == 26, "CT does not use all 26 letters"
    print("  builder cross-checks: AMSCO round-trip, Nihilist identity, "
          "columnar==kernel, Myszkowski degeneracy — all OK")
    print(f"  CT uses {len(set(CT))}/26 letters -> classical 5x5 Nihilist "
          f"SUBSTITUTION is impossible for K4 (no 25-letter Polybius fits)")
    return 1 if fails else 0


# ══════════════════════════════════════════════════════════════════════════

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=max(1, len(os.sched_getaffinity(0)) - 2))
    ap.add_argument("--batch-size", type=int, default=64)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--limit-keywords", type=int, default=0)
    ap.add_argument("--survivors-maxp", type=int, default=25,
                    help="fully enumerate L0/sub-outer non-eliminated configs "
                         "up to this period (0 to skip)")
    ap.add_argument("--null", type=int, default=0,
                    help="number of uniform random permutations to run as a "
                         "vacuity/null baseline for the same filter")
    ap.add_argument("--out", default="results/crib_ceiling_keyword_transposition.json")
    args = ap.parse_args()

    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")

    kws = load_keywords(os.path.join(_ROOT, "wordlists", "thematic_keywords.txt"))
    if args.limit_keywords:
        kws = kws[:args.limit_keywords]
    print(f"keyword pool: {len(kws)} unique A-Z keywords, lengths "
          f"{min(map(len,kws))}-{max(map(len,kws))}")

    print("\n=== SELF-TEST ===")
    rc = selftest(kws)
    if rc:
        print("SELF-TEST FAILED — aborting, no filtering performed")
        return 1
    if args.selftest:
        return 0

    perms, raw = enumerate_perms(kws)
    by_fam = defaultdict(int)
    for fam, _, _ in perms:
        by_fam[fam] += 1
    n_cfg_axes = len(LEVELS) * 2 * 4 * 3 * len(PERIODS)
    print(f"\n=== SWEEP ===")
    for fam in sorted(by_fam):
        print(f"  {fam:<6} {by_fam[fam]:>7} distinct perms "
              f"({raw[fam]} enumerated before dedup)")
    print(f"  total distinct perms: {len(perms)}")
    print(f"  per-perm config axes: 6 levels x 2 peel x 4 alphabet pairs "
          f"x 3 variants x 30 periods = {n_cfg_axes}")
    total_cfgs = len(perms) * n_cfg_axes
    print(f"  total configurations: {total_cfgs:,}")

    import multiprocessing as mp
    chunks = [perms[i:i + args.batch_size] for i in range(0, len(perms), args.batch_size)]
    t0 = time.perf_counter()
    agg = defaultdict(lambda: [0, 0, 0])
    per_period = defaultdict(lambda: [0, 0])
    examples = defaultdict(list)
    with mp.Pool(args.workers) as pool:
        done = 0
        for a, pp, ex in pool.imap_unordered(worker, chunks):
            for k, v in a.items():
                s = agg[k]
                s[0] += v[0]; s[1] += v[1]; s[2] = max(s[2], v[2])
            for k, v in pp.items():
                s = per_period[k]
                s[0] += v[0]; s[1] += v[1]
            for k, v in ex.items():
                if len(examples[k]) < 12:
                    examples[k].extend(v[:12 - len(examples[k])])
            done += 1
            if done % 50 == 0:
                print(f"    {done}/{len(chunks)} chunks  "
                      f"{time.perf_counter()-t0:.1f}s", flush=True)
    dt = time.perf_counter() - t0
    print(f"  swept in {dt:.1f}s with {args.workers} workers "
          f"({total_cfgs/dt/1e6:.2f}M configs/s)")

    fams = sorted(by_fam)
    print("\n" + "=" * 78)
    print("RESULTS  — ceiling < n_cribs is a SOUND ELIMINATION for every key.")
    print("           ceiling == n_cribs means NOT ELIMINATED, nothing more.")
    print("=" * 78)
    out = {"levels": {}, "per_family": {}, "per_period": {}}
    for lv in LEVELS:
        n = LEVEL_ARRAYS[lv][2]
        tot = sum(agg[(f, lv)][0] for f in fams)
        sur = sum(agg[(f, lv)][1] for f in fams)
        mx = max(agg[(f, lv)][2] for f in fams)
        tag = "EVIDENCE" if lv == "L0_released" else "CONDITIONAL on unproven PT"
        print(f"\n{lv}  n_cribs={n}   [{tag}]")
        print(f"  configs {tot:,}   eliminated {tot-sur:,} ({(tot-sur)/tot:.4%})"
              f"   not-eliminated {sur:,}   max ceiling {mx}/{n}")
        for f in fams:
            a = agg[(f, lv)]
            print(f"    {f:<6} cfgs {a[0]:>10,}  not-elim {a[1]:>9,} "
                  f"({a[1]/a[0]:>8.4%})  max ceiling {a[2]}/{n}")
        # per-period, aggregated over families
        rows = []
        for p in PERIODS:
            t = sum(per_period[(f, lv, pe, p)][0] for f in fams for pe in ("outer", "inner"))
            s = sum(per_period[(f, lv, pe, p)][1] for f in fams for pe in ("outer", "inner"))
            to = sum(per_period[(f, lv, "outer", p)][0] for f in fams)
            so = sum(per_period[(f, lv, "outer", p)][1] for f in fams)
            ti = sum(per_period[(f, lv, "inner", p)][0] for f in fams)
            si = sum(per_period[(f, lv, "inner", p)][1] for f in fams)
            rows.append((p, t, s, to, so, ti, si))
        print(f"    periods with ANY non-eliminated config: "
              f"{', '.join(str(p) for p, t, s, *_ in rows if s) or 'NONE'}")
        if sur:
            print(f"    {'p':>3} {'sub-OUTER not-elim':>26} {'sub-INNER not-elim':>26}"
                  f"  {'inner vacuous?':>15}")
            for p, t, s, to, so, ti, si in rows:
                if not s:
                    continue
                vac = len({int(q) % p for q in LEVEL_ARRAYS[lv][0]}) == n
                print(f"    {p:>3} {so:>10,}/{to:<12,} {si:>10,}/{ti:<12,}"
                      f"  {'YES (all crib q distinct mod p)' if vac else 'no':>15}")
        out["levels"][lv] = {"n_cribs": n, "configs": tot, "not_eliminated": sur,
                             "max_ceiling": mx,
                             "examples": examples.get((fams[0], lv), [])[:5]}
        out["per_period"][lv] = {
            str(p): {"configs": t, "not_eliminated": s,
                     "outer": [so, to], "inner": [si, ti]}
            for p, t, s, to, so, ti, si in rows}
        for f in fams:
            out["per_family"].setdefault(lv, {})[f] = {
                "configs": agg[(f, lv)][0], "not_eliminated": agg[(f, lv)][1],
                "max_ceiling": agg[(f, lv)][2],
                "examples": examples.get((f, lv), [])[:8]}

    print("\n" + "=" * 78)
    print("EXAMPLE NON-ELIMINATED CONFIGURATIONS (survived a filter — NOT solutions)")
    print("=" * 78)
    for lv in LEVELS:
        for f in fams:
            ex = examples.get((f, lv), [])
            if ex:
                print(f"  {lv} / {f}:")
                for e in ex[:4]:
                    print(f"      {e}")
    if args.null:
        print("\n" + "=" * 78)
        print(f"RANDOM-PERMUTATION NULL ({args.null:,} uniform random perms of 0..96)")
        print("  How often does an ARBITRARY permutation survive the same filter?")
        print("  A survival rate near 1.0 means the filter is vacuous at that setting")
        print("  and a 'survivor' there carries no information whatsoever.")
        print("=" * 78)
        rng = np.random.default_rng(20260825)
        nulls = []
        for _ in range(args.null):
            pp = rng.permutation(N)
            nulls.append(("NULL", "random", tuple(int(x) for x in pp)))
        nchunks = [nulls[i:i + args.batch_size]
                   for i in range(0, len(nulls), args.batch_size)]
        nper = defaultdict(lambda: [0, 0])
        with mp.Pool(args.workers) as pool:
            for a, pq, ex in pool.imap_unordered(worker, nchunks):
                for k, v in pq.items():
                    t2 = nper[k]
                    t2[0] += v[0]; t2[1] += v[1]
        for lv in ("L0_released", "L1_opening"):
            n = LEVEL_ARRAYS[lv][2]
            print(f"\n  {lv} (n={n}) — random-perm survival rate by period")
            hdr = "   p  " + "  ".join(f"{p:>5}" for p in PERIODS)
            print(hdr)
            for peel in ("outer", "inner"):
                cells = []
                for p in PERIODS:
                    t2 = nper[("NULL", lv, peel, p)]
                    cells.append(f"{(t2[1]/t2[0] if t2[0] else 0):>5.2f}")
                print(f"  {peel:<4}" + "  ".join(cells))
            out.setdefault("null", {})[lv] = {
                peel: {str(p): nper[("NULL", lv, peel, p)] for p in PERIODS}
                for peel in ("outer", "inner")}

    if args.survivors_maxp:
        globals()["SURV_MAXP"] = args.survivors_maxp
        print("\n" + "=" * 78)
        print(f"FULL ENUMERATION of NOT-ELIMINATED configurations at "
              f"L0_released, peel=sub_outer, period <= {args.survivors_maxp}")
        print("  This is the region where the filter still discriminates. These")
        print("  configurations SURVIVED A FILTER. They are not solutions, not")
        print("  candidates, and carry no positive evidence of anything.")
        print("=" * 78)
        surv = []
        with mp.Pool(args.workers, initializer=_set_maxp,
                     initargs=(args.survivors_maxp,)) as pool:
            for r in pool.imap_unordered(survivor_worker, chunks):
                surv.extend(r)
        surv.sort(key=lambda x: (x[5], x[0], x[1]))
        from collections import Counter
        print(f"  count: {len(surv)}  over {len({x[1] for x in surv})} distinct permutations")
        print(f"  by period : {dict(sorted(Counter(x[5] for x in surv).items()))}")
        print(f"  by family : {dict(sorted(Counter(x[0] for x in surv).items()))}")
        for x in surv[:40]:
            print(f"    p={x[5]:<3} {x[0]:<6} {x[1]:<44} ct={x[2]} pt={x[3]} {x[4]}")
        if len(surv) > 40:
            print(f"    ... {len(surv)-40} more (full list in the JSON)")
        out["survivors_L0_outer"] = {
            "max_period": args.survivors_maxp,
            "count": len(surv),
            "configs": [{"family": a, "perm": b, "ct_alpha": c, "pt_alpha": d,
                         "variant": e, "period": f} for a, b, c, d, e, f in surv]}

    outp = os.path.join(_ROOT, args.out)
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    with open(outp, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote {outp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
