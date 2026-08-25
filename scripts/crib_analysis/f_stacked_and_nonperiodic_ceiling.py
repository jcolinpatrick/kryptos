#!/usr/bin/env python3
"""
ID: f_crib_stacked_nonperiodic_01
FAMILY: crib_analysis
STATUS: active
SUMMARY: Attainable-crib-ceiling sweep over (1) stacked additive layers with two
         periods, and (2) the non-additive / non-periodic families, with an
         explicit applicability verdict for each.

HYPOTHESIS UNDER TEST
---------------------
PART 1 -- STACKED ADDITIVE LAYERS.
    K4 = two additive (Vigenere / Beaufort / variant-Beaufort) layers of periods
    p1, p2 in 2..14, optionally separated by a transposition. Three placements:
        AA  both additive layers AFTER  the transposition (key in the CT frame)
        BB  both additive layers BEFORE the transposition (key in the PT frame)
        AB  "sandwich": layer 1 before, layer 2 after
    A crib at plaintext index q, landing on ciphertext index j = ip[q], demands
        s1[a_q] + s2[b_q] == t_q          (a_q, b_q the two class labels)
    with t_q free of key material.

PART 2 -- FAMILIES OUTSIDE THE PLAIN ADDITIVE-CLASS MODEL.
    Porta, Gronsfeld, progressive key, PT-autokey, CT-autokey, Hill,
    Playfair / four-square, running key, finite free key tape.
    For each, the script states whether a SOUND filter exists and, if so, runs it.

TWO BOUNDS ARE COMPUTED FOR PART 1, AND THEY DIFFER
---------------------------------------------------
    ceil_pair  -- relax the additive structure: give every distinct class PAIR
                  (a_q, b_q) its own free shift. For same-frame stacks this is
                  exactly the j-mod-lcm(p1,p2) bound named in the brief. It is a
                  LOOSER upper bound, because the achievable shift vectors
                  s1[a]+s2[b] form a PROPER SUBGROUP of the class-constant
                  vectors. Sound for elimination, weak for survival.
    feasible   -- EXACT. Because a "survivor" is defined as ceiling == n_cribs,
                  survival needs only the feasibility of the FULL crib system,
                  and that is decidable in polynomial time: the constraints
                  s1[a] - (-s2[b]) = t are potential differences on a bipartite
                  graph, so union-find with Z/26 offsets settles them exactly.
                  feasible == False  =>  true ceiling <= n_cribs - 1.
    Reported ceiling = ceil_pair if feasible else min(ceil_pair, n_cribs - 1).
    This is sound in both directions and strictly tighter than the lcm bound.

VARIANT REDUCTION (stated so it can be checked)
-----------------------------------------------
    Composing additive layers gives CT = eps*PT + S with eps = +-1. eps=+1 is
    Vigenere-like (t = c - p); eps=-1 is Beaufort-like (t = c + p). Variant
    Beaufort demands t = p - c = -(c - p): the negation of the Vigenere demand
    vector, and since the shift vector is sign-free the feasibility is
    identical. So exactly TWO net variants are swept, not 3^2 = 9.

PRE-REGISTERED INTERPRETATION -- FIXED BEFORE THE RUN
-----------------------------------------------------
    ceiling <  n_cribs  ->  IMPOSSIBLE for every key. SOUND ELIMINATION.
    ceiling == n_cribs  ->  NOT ELIMINATED BY THIS FILTER. This is NOT evidence
                            that a solution exists and will never be written as
                            "possible" or "a candidate solution". It survived a
                            filter; that is the whole claim.
    L0_released is the only EVIDENCE level. Every elimination at L1..L5 is
    CONDITIONAL on an unproven plaintext hypothesis and is reported as such.
    Because the additive layers with a large lcm have many free parameters, the
    PRIOR EXPECTATION is that most large-lcm stacked configurations survive at
    L0. Survival there is uninformative and is pre-registered as such. The
    informative outcomes are (a) eliminations at small lcm, (b) eliminations
    that the lcm bound misses but the exact bipartite test catches, and (c) the
    behaviour of the extended levels.

FRAME SAFETY
------------
    Nothing here reads the frozen BEAN_EQ / BEAN_INEQ / BEAN_LINEAR sets. Those
    are carved-CT-frame artefacts and do not transfer across a crib-moving
    layer (systemic defect recorded 2026-08-24). Every demand value is
    re-derived from (CT, crib map, alignment) at evaluation time.
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
from collections import defaultdict
from multiprocessing import Pool

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import (  # noqa: E402
    AZ, MOD, ceiling, identity_perm, index_table, inverse, keyword_mixed,
)
import crib_sets  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    columnar_perm, myszkowski_perm, rail_fence_perm,
)

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

ALPHABETS = [
    ("AZ/AZ", AZ, AZ),
    ("KA/AZ", KA, AZ),
    ("KA/PALIMPSEST", KA, keyword_mixed("PALIMPSEST")),
]

# ── permutation library ──────────────────────────────────────────────────────


def _kw_order(kw: str):
    ranked = sorted([(ch, i) for i, ch in enumerate(kw)], key=lambda x: (x[0], x[1]))
    order = [0] * len(kw)
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def build_perms(n: int = 97):
    """A declared, reproducible SAMPLE of transpositions. Not exhaustive."""
    out = [("identity", identity_perm(n))]
    rng = random.Random(20260825)
    for w in range(2, 17):
        base = list(range(w))
        orders = [("id", base), ("rev", base[::-1])]
        for k in range(4):
            o = base[:]
            rng.shuffle(o)
            orders.append((f"r{k}", o))
        for tag, o in orders:
            out.append((f"col{w}.{tag}", columnar_perm(w, o, n)))
    for kw in ("KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
               "NORTHEAST", "MERIDIAN", "LODESTONE", "SHADOW", "ILLUSION",
               "IQLUSION", "UNDERGROUND", "TWENTY", "LAYERTWO"):
        out.append((f"colkw.{kw}", columnar_perm(len(kw), _kw_order(kw), n)))
        out.append((f"mysz.{kw}", myszkowski_perm(kw, n)))
    for d in range(2, 10):
        out.append((f"rail{d}", rail_fence_perm(n, d)))
    return out


# ── exact bipartite feasibility over Z/26 ────────────────────────────────────


def bipartite_feasible(edges) -> bool:
    """edges: iterable of (a, b, t) meaning  s1[a] + s2[b] == t  (mod 26).

    Substituting u[b] = -s2[b] turns each edge into the potential difference
    s1[a] - u[b] = t, so the whole system is feasible iff every cycle in the
    bipartite graph has zero alternating sum. Weighted union-find decides that
    exactly. EXACT: no relaxation, no search.
    """
    parent, pot = {}, {}

    def find(x):
        if x not in parent:
            parent[x], pot[x] = x, 0
            return x, 0
        root, acc = x, 0
        while parent[root] != root:
            acc = (acc + pot[root]) % MOD
            root = parent[root]
        # path compression
        cur, cacc = x, acc
        while parent[cur] != cur:
            nxt, npot = parent[cur], pot[cur]
            parent[cur], pot[cur] = root, cacc
            cacc = (cacc - npot) % MOD
            cur = nxt
        return root, acc

    for a, b, t in edges:
        na, nb = ("L", a), ("R", b)
        ra, pa = find(na)
        rb, pb = find(nb)
        # value(na) = pa + val(ra); constraint value(na) - value(nb) = t
        if ra == rb:
            if (pa - pb) % MOD != t % MOD:
                return False
        else:
            parent[ra] = rb
            pot[ra] = (t + pb - pa) % MOD
    return True


def demand(ct_ch: str, pt_ch: str, ct_tab, pt_tab, net: str) -> int:
    c = ct_tab[ord(ct_ch) - 65]
    p = pt_tab[ord(pt_ch) - 65]
    return (c - p) % MOD if net == "vig" else (c + p) % MOD


# ── PART 1 worker ────────────────────────────────────────────────────────────

_G = {}


def _init(perms, levels):
    _G["perms"] = perms
    _G["levels"] = levels
    _G["ip"] = {name: inverse(p) for name, p in perms}


def part1_chunk(task):
    """task = (perm_name, list of (mode, p1, p2, level, net, alpha_idx))."""
    pname, jobs = task
    ip = _G["ip"][pname]
    rows = []
    for mode, p1, p2, lname, net, ai in jobs:
        alab, ct_alpha, pt_alpha = ALPHABETS[ai]
        ct_tab, pt_tab = index_table(ct_alpha), index_table(pt_alpha)
        cribs = _G["levels"][lname]
        n = len(cribs)
        pair_of = {}
        edges = []
        for q, ch in cribs.items():
            j = ip[q]
            if mode == "AA":
                a, b = j % p1, j % p2
            elif mode == "BB":
                a, b = q % p1, q % p2
            else:  # AB sandwich
                a, b = q % p1, j % p2
            pair_of[q] = (a, b)
            edges.append((a, b, demand(CT[j], ch, ct_tab, pt_tab, net)))
        # loose pair-class bound, computed through the SHARED module (not
        # reimplemented here). For the same-frame modes this pair class is
        # exactly j mod lcm(p1, p2).
        ceil_pair, _ = ceiling(
            CT, cribs, (lambda q: ip[q]), (lambda q: pair_of[q]),
            ct_tab=ct_tab, pt_tab=pt_tab, variant=net)
        feas = bipartite_feasible(edges)
        ceil = ceil_pair if feas else min(ceil_pair, n - 1)
        rows.append((pname, mode, p1, p2, lname, net, alab, n,
                     ceil_pair, int(feas), ceil))
    return rows


# ── PART 2 filters ───────────────────────────────────────────────────────────

def porta_ct_from_pt(pt_val: int, g: int) -> int:
    return ((pt_val + g) % 13) + 13 if pt_val < 13 else (pt_val - 13 - g) % 13


def porta_ceiling(cribs, ip, period, frame, ct_tab, pt_tab):
    """EXACT. Each class picks one of 13 reciprocal alphabets, independently."""
    cls = defaultdict(list)
    half_flip_ok = True
    for q, ch in cribs.items():
        j = ip[q]
        c = ct_tab[ord(CT[j]) - 65]
        p = pt_tab[ord(ch) - 65]
        if (c < 13) == (p < 13):
            half_flip_ok = False           # no Porta key of any period can fix this
        k = (j if frame == "ct" else q) % period
        cls[k].append((c, p))
    total = 0
    for _, items in cls.items():
        total += max(sum(1 for c, p in items if porta_ct_from_pt(p, g) == c)
                     for g in range(13))
    return total, half_flip_ok


def gronsfeld_ceiling(cribs, ip, period, frame, ct_tab, pt_tab, net):
    """EXACT. Shift restricted to the digits 0..9."""
    cls = defaultdict(list)
    for q, ch in cribs.items():
        j = ip[q]
        cls[(j if frame == "ct" else q) % period].append(
            demand(CT[j], ch, ct_tab, pt_tab, net))
    return sum(max(sum(1 for t in ts if t == d) for d in range(10))
               for ts in cls.values())


def progressive_ceiling(cribs, ip, period, frame, ct_tab, pt_tab, net, delta):
    """EXACT for shift[j] = k[j mod p] + delta*floor(j/p)."""
    cls = defaultdict(lambda: defaultdict(int))
    for q, ch in cribs.items():
        j = ip[q]
        idx = j if frame == "ct" else q
        t = (demand(CT[j], ch, ct_tab, pt_tab, net) - delta * (idx // period)) % MOD
        cls[idx % period][t] += 1
    return sum(max(d.values()) for d in cls.values())


def autokey_ceiling(cribs, perm, ip, m, net, kind, ct_tab, pt_tab):
    """EXACT ceiling for autokey with primer length m.

    The additive layer runs positionally on the sequence Y, where Y[j] is the
    letter that becomes CT[j]; with a transposition, Y[j] = PT[perm[j]].
      PT-autokey  vig :  Y[j] = CT[j] - Y[j-m]      -> the whole chain is fixed
                                                        by the primer letter
      PT-autokey  beau:  Y[j] = Y[j-m] - CT[j]
      CT-autokey  vig :  Y[j] = CT[j] - CT[j-m]     -> no freedom at all
      CT-autokey  beau:  Y[j] = CT[j-m] - CT[j]
    For PT-autokey the chains j, j+m, j+2m, ... are independent and each is a
    function of ONE primer letter, so 26 trials per chain is exhaustive.
    """
    L = len(CT)
    ctv = [ct_tab[ord(c) - 65] for c in CT]
    known = {}
    for q, ch in cribs.items():
        known[ip[q]] = pt_tab[ord(ch) - 65]     # Y index -> required value
    if kind == "ct":
        hit = 0
        for j, want in known.items():
            if j < m:
                hit += 1                        # primer letter is free
            else:
                got = (ctv[j] - ctv[j - m]) % MOD if net == "vig" \
                    else (ctv[j - m] - ctv[j]) % MOD
                hit += int(got == want)
        return hit
    total = 0
    for r in range(m):
        chain = list(range(r, L, m))
        if not any(j in known for j in chain):
            total += 0
            continue
        best = 0
        for seed in range(MOD):
            v = seed
            cnt = 0
            for k, j in enumerate(chain):
                if k > 0:
                    v = (ctv[j] - v) % MOD if net == "vig" else (v - ctv[j]) % MOD
                if j in known:
                    cnt += int(v == known[j])
            best = max(best, cnt)
            if best == sum(1 for j in chain if j in known):
                break
        total += best
    return total


def _solve_mod_p(rows, rhs, p):
    """Consistency of A x = b over GF(p). Returns True iff consistent."""
    A = [r[:] + [b] for r, b in zip(rows, rhs)]
    ncols = len(rows[0]) if rows else 0
    piv = 0
    for col in range(ncols):
        sel = None
        for r in range(piv, len(A)):
            if A[r][col] % p:
                sel = r
                break
        if sel is None:
            continue
        A[piv], A[sel] = A[sel], A[piv]
        inv = pow(A[piv][col], p - 2, p)
        A[piv] = [(v * inv) % p for v in A[piv]]
        for r in range(len(A)):
            if r != piv and A[r][col] % p:
                f = A[r][col]
                A[r] = [(a - f * b) % p for a, b in zip(A[r], A[piv])]
        piv += 1
        if piv == len(A):
            break
    for r in range(len(A)):
        if all(v % p == 0 for v in A[r][:ncols]) and A[r][ncols] % p:
            return False
    return True


def hill_feasible(cribs, b, ct_tab, pt_tab, affine):
    """Feasibility over Z/26 of PT_block = M*CT_block (+v), by CRT on GF(2),GF(13).

    Rows of M are independent, so the system splits by q mod b. Cribs in an
    incomplete trailing block are DROPPED -- a relaxation, so the verdict stays
    a sound upper bound. Invertibility of M is not imposed -- also a relaxation.
    Returns (feasible_all, n_used, n_dropped).
    """
    L = len(CT)
    full = (L // b) * b
    byrow = defaultdict(lambda: ([], []))
    dropped = 0
    for q, ch in cribs.items():
        if q >= full:
            dropped += 1
            continue
        B = q // b
        coef = [ct_tab[ord(CT[B * b + k]) - 65] for k in range(b)]
        if affine:
            coef.append(1)
        byrow[q % b][0].append(coef)
        byrow[q % b][1].append(pt_tab[ord(ch) - 65])
    used = sum(len(v[1]) for v in byrow.values())
    for _, (rows, rhs) in byrow.items():
        if not rows:
            continue
        if not (_solve_mod_p(rows, rhs, 2) and _solve_mod_p(rows, rhs, 13)):
            return False, used, dropped
    return True, used, dropped


# ── drivers ──────────────────────────────────────────────────────────────────

def run_part1(args, perms, levels):
    modes = ("AA", "BB", "AB")
    pairs = [(a, b) for a in range(2, 15) for b in range(a, 15)]
    tasks = []
    for pname, _ in perms:
        jobs = []
        use_modes = ("AA",) if pname == "identity" else modes
        for mode in use_modes:
            for (p1, p2) in pairs:
                for lname in crib_sets.LEVELS:
                    for net in ("vig", "beau"):
                        for ai in range(len(ALPHABETS)):
                            jobs.append((mode, p1, p2, lname, net, ai))
        tasks.append((pname, jobs))
    total = sum(len(j) for _, j in tasks)
    print(f"[part1] {len(perms)} perms x modes x {len(pairs)} period pairs "
          f"x {len(crib_sets.LEVELS)} levels x 2 net variants x "
          f"{len(ALPHABETS)} alphabets = {total:,} configs")
    t0 = time.perf_counter()
    rows = []
    with Pool(args.workers, initializer=_init, initargs=(perms, levels)) as pool:
        for k, res in enumerate(pool.imap_unordered(part1_chunk, tasks,
                                                    chunksize=1), 1):
            rows.extend(res)
            if k % 20 == 0:
                print(f"  .. {k}/{len(tasks)} perms  "
                      f"{time.perf_counter()-t0:.1f}s", flush=True)
    print(f"[part1] done {len(rows):,} rows in {time.perf_counter()-t0:.1f}s")
    return rows, total


def summarise_part1(rows):
    by_level = {}
    for lname in crib_sets.LEVELS:
        sub = [r for r in rows if r[4] == lname]
        n = sub[0][7]
        surv = [r for r in sub if r[10] == n]
        lcm_surv = [r for r in sub if r[8] == n]
        by_level[lname] = {
            "level": lname, "n_cribs": n, "tested": len(sub),
            "survivors": len(surv), "max_ceiling": max(r[10] for r in sub),
            "lcm_bound_survivors": len(lcm_surv),
            "caught_only_by_exact": len(lcm_surv) - len(surv),
            "min_lcm_surviving": (min(math.lcm(r[2], r[3]) for r in surv)
                                  if surv else None),
            "survivors_by_lcm": dict(sorted(
                __import__("collections").Counter(
                    math.lcm(r[2], r[3]) for r in surv).items())),
            "survivors_by_mode": dict(__import__("collections").Counter(
                r[1] for r in surv)),
            "survivors_by_alphabet": dict(__import__("collections").Counter(
                r[6] for r in surv)),
            "eliminated_all_perms_at_lcm_le": max(
                [L for L in range(1, 200)
                 if all(r[10] < r[7] for r in sub
                        if math.lcm(r[2], r[3]) <= L)] or [0]),
            "example_survivors": [
                f"{r[0]}|{r[1]}|p={r[2]},{r[3]}(lcm{math.lcm(r[2],r[3])})|{r[5]}|{r[6]}"
                for r in sorted(surv, key=lambda r: (math.lcm(r[2], r[3]),
                                                     r[2], r[3]))[:6]],
        }
    return by_level


def run_part2(levels, perms):
    """Every Part-2 subfamily, with an explicit applicability verdict."""
    out = {}
    small_perms = [(nm, p) for nm, p in perms
                   if nm == "identity" or nm.startswith(("col7", "col8", "col10",
                                                         "colkw", "rail"))]
    ips = {nm: inverse(p) for nm, p in small_perms}

    # -- 0. alphabet exclusion: any 25-letter square (Playfair, four-square, bifid)
    out["playfair_foursquare_25letter"] = {
        "applicable": True, "mechanism": "alphabet exclusion, not a ceiling",
        "distinct_ct_letters": len(set(CT)),
        "verdict": ("ELIMINATED unconditionally: K4 ciphertext uses all 26 "
                    "letters, and any cipher whose output alphabet is a "
                    "25-letter square (Playfair, four-square, two-square, "
                    "bifid 5x5) can emit at most 25 distinct letters. Uses no "
                    "crib hypothesis, so it holds at L0."),
        "coverage": "exhaustive",
    }

    # -- 1. Porta
    porta = {"applicable": True, "coverage": "exhaustive over declared grid",
             "by_level": {}}
    for lname in crib_sets.LEVELS:
        cribs = levels[lname]
        n = len(cribs)
        best, surv, flipfail = 0, 0, 0
        tested = 0
        for nm, p in small_perms:
            ip = ips[nm]
            for frame in ("ct", "pt"):
                for alab, ca, pa in ALPHABETS[:2]:
                    ct_tab, pt_tab = index_table(ca), index_table(pa)
                    for period in range(1, 27):
                        tested += 1
                        c, ok = porta_ceiling(cribs, ip, period, frame,
                                              ct_tab, pt_tab)
                        best = max(best, c)
                        surv += int(c == n)
                        if not ok:
                            flipfail += 1
        porta["by_level"][lname] = {"n_cribs": n, "tested": tested,
                                    "survivors": surv, "max_ceiling": best}
    # key-free half-flip test at direct alignment
    ct_tab, pt_tab = index_table(AZ), index_table(AZ)
    hf = {}
    for lname in crib_sets.LEVELS:
        bad = sum(1 for q, ch in levels[lname].items()
                  if (ct_tab[ord(CT[q]) - 65] < 13) ==
                     (pt_tab[ord(ch) - 65] < 13))
        hf[lname] = bad
    porta["direct_alignment_half_flip_violations"] = hf
    porta["note"] = ("Porta IS filterable: each class picks one of 13 fixed "
                     "reciprocal alphabets, so 'max over 13 alphabets' replaces "
                     "'max multiplicity of a free shift'. Strictly tighter than "
                     "Vigenere. Porta additionally forces a half-alphabet flip "
                     "at EVERY position regardless of key or period, which is a "
                     "key-free per-crib test.")
    out["porta"] = porta

    # -- 2. Gronsfeld
    gron = {"applicable": True, "coverage": "exhaustive over declared grid",
            "by_level": {},
            "note": ("Gronsfeld is Vigenere with the shift confined to 0..9, so "
                     "the same class structure applies with a restricted key "
                     "alphabet. Strictly tighter than Vigenere.")}
    for lname in crib_sets.LEVELS:
        cribs = levels[lname]
        n = len(cribs)
        best, surv, tested = 0, 0, 0
        for nm, p in small_perms:
            ip = ips[nm]
            for frame in ("ct", "pt"):
                for alab, ca, pa in ALPHABETS[:2]:
                    ct_tab, pt_tab = index_table(ca), index_table(pa)
                    for net in ("vig", "beau"):
                        for period in range(1, 27):
                            tested += 1
                            c = gronsfeld_ceiling(cribs, ip, period, frame,
                                                  ct_tab, pt_tab, net)
                            best = max(best, c)
                            surv += int(c == n)
        gron["by_level"][lname] = {"n_cribs": n, "tested": tested,
                                   "survivors": surv, "max_ceiling": best}
    out["gronsfeld"] = gron

    # -- 3. progressive key
    prog = {"applicable": True, "coverage": "exhaustive over declared grid",
            "by_level": {},
            "note": ("shift[j] = k[j mod p] + delta*floor(j/p). Subtracting the "
                     "known progression term returns it to a free-shift-per-"
                     "class problem, so the ceiling formula applies exactly for "
                     "each (p, delta).")}
    for lname in crib_sets.LEVELS:
        cribs = levels[lname]
        n = len(cribs)
        best, surv, tested = 0, 0, 0
        for nm, p in small_perms:
            ip = ips[nm]
            for frame in ("ct", "pt"):
                ct_tab, pt_tab = index_table(AZ), index_table(AZ)
                for net in ("vig", "beau"):
                    for period in range(1, 27):
                        for delta in range(MOD):
                            tested += 1
                            c = progressive_ceiling(cribs, ip, period, frame,
                                                    ct_tab, pt_tab, net, delta)
                            best = max(best, c)
                            surv += int(c == n)
        prog["by_level"][lname] = {"n_cribs": n, "tested": tested,
                                   "survivors": surv, "max_ceiling": best}
    out["progressive_key"] = prog

    # -- 4/5. autokey, both feedback sources
    for kind, label in (("pt", "autokey_plaintext"), ("ct", "autokey_ciphertext")):
        ak = {"applicable": True, "coverage": "exhaustive over declared grid",
              "by_level": {}}
        for lname in crib_sets.LEVELS:
            cribs = levels[lname]
            n = len(cribs)
            best, surv, tested = 0, 0, 0
            for nm, p in small_perms:
                ip = ips[nm]
                for alab, ca, pa in ALPHABETS[:2]:
                    ct_tab, pt_tab = index_table(ca), index_table(pa)
                    for net in ("vig", "beau"):
                        for m in range(1, 41):
                            tested += 1
                            c = autokey_ceiling(cribs, p, ip, m, net, kind,
                                                ct_tab, pt_tab)
                            best = max(best, c)
                            surv += int(c == n)
            ak["by_level"][lname] = {"n_cribs": n, "tested": tested,
                                     "survivors": surv, "max_ceiling": best}
        ak["note"] = (
            "PT-autokey: the keystream after the primer is the plaintext itself, "
            "so each residue chain mod m is a deterministic function of ONE "
            "primer letter; 26 trials per chain is exhaustive, giving an EXACT "
            "ceiling. CT-autokey: the keystream past the primer is fully known "
            "from the ciphertext, so every crib at index >= m is a hard check "
            "with zero key freedom."
            if kind == "pt" else
            "CT-autokey: past the primer the keystream is entirely determined by "
            "the ciphertext, so only the m primer positions carry any freedom. "
            "The ceiling is therefore exact and very tight.")
        out[label] = ak

    # -- 6. Hill
    hill = {"applicable": True, "coverage": "partial (relaxed)", "by_level": {},
            "note": ("Hill is linear, not a per-class shift, so the shift-"
                     "ceiling formula does NOT apply. A different sound filter "
                     "does: PT_block = M*CT_block splits into independent rows, "
                     "each row giving linear equations in b unknowns over Z/26 "
                     "whose coefficients are fully known ciphertext. "
                     "Consistency is decided exactly by CRT onto GF(2) and "
                     "GF(13). Relaxations, both in the safe direction: cribs in "
                     "an incomplete trailing block are dropped, and "
                     "invertibility of M is not imposed.")}
    for lname in crib_sets.LEVELS:
        cribs = levels[lname]
        n = len(cribs)
        recs = []
        for b in range(2, 9):
            for affine in (False, True):
                for alab, ca, pa in ALPHABETS[:2]:
                    f, used, drop = hill_feasible(cribs, b, index_table(ca),
                                                  index_table(pa), affine)
                    recs.append({"b": b, "affine": affine, "alpha": alab,
                                 "feasible": f, "cribs_used": used,
                                 "cribs_dropped": drop})
        hill["by_level"][lname] = {
            "n_cribs": n, "tested": len(recs),
            "survivors": sum(1 for r in recs if r["feasible"]),
            "max_ceiling": n if any(r["feasible"] for r in recs) else n - 1,
            "detail": recs}
    out["hill"] = hill

    # -- 7/8. genuinely unfilterable
    out["running_key_unconstrained"] = {
        "applicable": False, "coverage": "inapplicable",
        "verdict": ("INAPPLICABLE. With an unspecified source text the keystream "
                    "is free at every one of the 97 positions, so every crib "
                    "sits in its own class and the ceiling is n_cribs by "
                    "construction, at every level L0..L5. The filter returns no "
                    "information. It becomes a filter only once the source text "
                    "is pinned to a declared corpus, at which point it is a "
                    "search over offsets, not a ceiling argument."),
    }
    out["finite_free_key_tape"] = {
        "applicable": False, "coverage": "inapplicable",
        "verdict": ("INAPPLICABLE as stated. A non-periodic key tape with every "
                    "position free is the 97-free-parameters case: ceiling == "
                    "n_cribs identically, at every level. The framework starts "
                    "to bite only when the position->tape-cell map is MANY-TO-"
                    "ONE and known -- a tape shorter than 97 with a declared "
                    "consumption rule, an interrupted-advance rule, or a null "
                    "mask. Then the tape cell IS the class label and the "
                    "existing ceiling() call applies unchanged. Nothing in L1..L5 "
                    "changes this: adding known plaintext adds equations and "
                    "unknowns at the same rate, so the degrees of freedom never "
                    "go negative."),
    }
    return out



# ── POSITIVE / NEGATIVE CONTROL ──────────────────────────────────────────────
# A filter that only ever says "impossible" is worthless and wrong in the
# dangerous direction. Every filter below is required to pass a ciphertext it
# actually generated.

def _set_ct(new):
    globals()["CT"] = new


def selftest() -> int:
    rng = random.Random(20260825)
    fails = 0
    real_ct = CT
    npos = len(real_ct)
    cribpos = list(range(0, 21)) + list(range(21, 34)) + list(range(63, 74))
    print("=" * 74)
    print("CONTROLS")
    print("=" * 74)

    # ---- Part 1 positive control: stacked additive layers ------------------
    ok = tot = 0
    for trial in range(240):
        alab, ca, pa = ALPHABETS[rng.randrange(len(ALPHABETS))]
        ct_tab, pt_tab = index_table(ca), index_table(pa)
        mode = rng.choice(["AA", "BB", "AB"])
        net = rng.choice(["vig", "beau"])
        p1, p2 = rng.randrange(2, 15), rng.randrange(2, 15)
        w = rng.randrange(2, 15)
        order = list(range(w)); rng.shuffle(order)
        perm = columnar_perm(w, order, npos)
        ip = inverse(perm)
        s1 = [rng.randrange(MOD) for _ in range(p1)]
        s2 = [rng.randrange(MOD) for _ in range(p2)]
        pt = "".join(rng.choice(AZ) for _ in range(npos))
        buf = [None] * npos
        for q in range(npos):
            j = ip[q]
            a, b = ((j % p1, j % p2) if mode == "AA" else
                    (q % p1, q % p2) if mode == "BB" else (q % p1, j % p2))
            pv = pt_tab[ord(pt[q]) - 65]
            tot_s = (s1[a] + s2[b]) % MOD
            cv = (pv + tot_s) % MOD if net == "vig" else (tot_s - pv) % MOD
            buf[j] = ca[cv]
        _set_ct("".join(buf))
        cribs = {q: pt[q] for q in cribpos}
        edges, pair_of = [], {}
        for q, ch in cribs.items():
            j = ip[q]
            a, b = ((j % p1, j % p2) if mode == "AA" else
                    (q % p1, q % p2) if mode == "BB" else (q % p1, j % p2))
            pair_of[q] = (a, b)
            edges.append((a, b, demand(CT[j], ch, ct_tab, pt_tab, net)))
        cp, _ = ceiling(CT, cribs, (lambda q: ip[q]), (lambda q: pair_of[q]),
                        ct_tab=ct_tab, pt_tab=pt_tab, variant=net)
        tot += 1
        ok += int(bipartite_feasible(edges) and cp == len(cribs))
    print(f"  part1 stacked positive control : {ok}/{tot} true configs survived")
    fails += (tot - ok)

    # ---- Part 1 negative control: wrong period pair on a truth CT ----------
    # regenerate one truth, then test it against wrong small periods
    p1, p2 = 3, 4
    perm = identity_perm(npos)
    ip = inverse(perm)
    s1 = [rng.randrange(MOD) for _ in range(p1)]
    s2 = [rng.randrange(MOD) for _ in range(p2)]
    pt = "".join(rng.choice(AZ) for _ in range(npos))
    buf = [None] * npos
    for q in range(npos):
        buf[q] = AZ[(AZ.index(pt[q]) + s1[q % p1] + s2[q % p2]) % MOD]
    _set_ct("".join(buf))
    cribs = {q: pt[q] for q in cribpos}
    tt = index_table(AZ)
    killed = 0
    trials = 0
    for q1 in range(2, 15):
        for q2 in range(q1, 15):
            if math.lcm(q1, q2) % math.lcm(p1, p2) == 0:
                continue           # a refinement of the truth cannot be killed
            trials += 1
            edges = [(q % q1, q % q2, demand(CT[q], c, tt, tt, "vig"))
                     for q, c in cribs.items()]
            killed += int(not bipartite_feasible(edges))
    print(f"  part1 negative control         : {killed}/{trials} wrong period "
          f"pairs eliminated on a p=(3,4) truth ciphertext")
    if killed == 0:
        fails += 1

    # ---- Porta ------------------------------------------------------------
    period = 7
    g = [rng.randrange(13) for _ in range(period)]
    pt = "".join(rng.choice(AZ) for _ in range(npos))
    _set_ct("".join(AZ[porta_ct_from_pt(AZ.index(pt[j]), g[j % period])]
                    for j in range(npos)))
    cribs = {q: pt[q] for q in cribpos}
    c, flip = porta_ceiling(cribs, list(range(npos)), period, "ct", tt, tt)
    print(f"  porta positive control         : ceiling {c}/{len(cribs)}, "
          f"half-flip ok={flip}")
    fails += int(c != len(cribs) or not flip)

    # ---- Gronsfeld --------------------------------------------------------
    period = 6
    d = [rng.randrange(10) for _ in range(period)]
    pt = "".join(rng.choice(AZ) for _ in range(npos))
    _set_ct("".join(AZ[(AZ.index(pt[j]) + d[j % period]) % MOD]
                    for j in range(npos)))
    cribs = {q: pt[q] for q in cribpos}
    c = gronsfeld_ceiling(cribs, list(range(npos)), period, "ct", tt, tt, "vig")
    print(f"  gronsfeld positive control     : ceiling {c}/{len(cribs)}")
    fails += int(c != len(cribs))

    # ---- progressive key --------------------------------------------------
    period, delta = 5, 3
    k = [rng.randrange(MOD) for _ in range(period)]
    pt = "".join(rng.choice(AZ) for _ in range(npos))
    _set_ct("".join(AZ[(AZ.index(pt[j]) + k[j % period]
                        + delta * (j // period)) % MOD] for j in range(npos)))
    cribs = {q: pt[q] for q in cribpos}
    c = progressive_ceiling(cribs, list(range(npos)), period, "ct", tt, tt,
                            "vig", delta)
    cbad = progressive_ceiling(cribs, list(range(npos)), period, "ct", tt, tt,
                               "vig", (delta + 1) % MOD)
    print(f"  progressive positive control   : ceiling {c}/{len(cribs)} "
          f"(wrong delta gives {cbad})")
    fails += int(c != len(cribs))

    # ---- PT-autokey -------------------------------------------------------
    m = 5
    pt = "".join(rng.choice(AZ) for _ in range(npos))
    primer = [rng.randrange(MOD) for _ in range(m)]
    ctv = [0] * npos
    for j in range(npos):
        kv = primer[j] if j < m else AZ.index(pt[j - m])
        ctv[j] = (AZ.index(pt[j]) + kv) % MOD
    _set_ct("".join(AZ[v] for v in ctv))
    cribs = {q: pt[q] for q in cribpos}
    c = autokey_ceiling(cribs, list(range(npos)), list(range(npos)), m, "vig",
                        "pt", tt, tt)
    cbad = autokey_ceiling(cribs, list(range(npos)), list(range(npos)), m + 1,
                           "vig", "pt", tt, tt)
    print(f"  pt-autokey positive control    : ceiling {c}/{len(cribs)} "
          f"(wrong primer len gives {cbad})")
    fails += int(c != len(cribs))

    # ---- CT-autokey -------------------------------------------------------
    m = 4
    ctv = [rng.randrange(MOD) for _ in range(npos)]
    ptv = [0] * npos
    for j in range(npos):
        kv = 0 if j < m else ctv[j - m]
        ptv[j] = (ctv[j] - kv) % MOD
    _set_ct("".join(AZ[v] for v in ctv))
    cribs = {q: AZ[ptv[q]] for q in cribpos}
    c = autokey_ceiling(cribs, list(range(npos)), list(range(npos)), m, "vig",
                        "ct", tt, tt)
    print(f"  ct-autokey positive control    : ceiling {c}/{len(cribs)}")
    fails += int(c != len(cribs))

    # ---- Hill -------------------------------------------------------------
    b = 3
    ctv = [rng.randrange(MOD) for _ in range(npos)]
    M = [[rng.randrange(MOD) for _ in range(b)] for _ in range(b)]
    _set_ct("".join(AZ[v] for v in ctv))
    full = (npos // b) * b
    ptv = [0] * npos
    for q in range(full):
        B, r = q // b, q % b
        ptv[q] = sum(M[r][kk] * ctv[B * b + kk] for kk in range(b)) % MOD
    cribs = {q: AZ[ptv[q]] for q in cribpos if q < full}
    f, used, drop = hill_feasible(cribs, b, tt, tt, False)
    fb, _, _ = hill_feasible(cribs, b + 1, tt, tt, False)
    print(f"  hill positive control          : feasible={f} on {used} cribs "
          f"(wrong block size b={b+1} gives feasible={fb})")
    fails += int(not f)

    _set_ct(real_ct)
    print(f"\n  CONTROL FAILURES: {fails}")
    return fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 2))
    ap.add_argument("--part", choices=["1", "2", "both"], default="both")
    ap.add_argument("--out", default=None)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(1 if selftest() else 0)

    perms = build_perms()
    levels = {nm: crib_sets.level(nm) for nm in crib_sets.LEVELS}
    print(f"CT len {len(CT)}, distinct letters {len(set(CT))}, "
          f"workers {args.workers}, perms {len(perms)}")
    report = {"ct_len": len(CT), "workers": args.workers,
              "n_perms_sampled": len(perms)}

    if args.part in ("1", "both"):
        rows, total = run_part1(args, perms, levels)
        report["part1"] = {"configs_tested": total,
                           "by_level": summarise_part1(rows)}
        print("\n=== PART 1: stacked additive layers ===")
        for lname, d in report["part1"]["by_level"].items():
            print(f"{lname:<18} n={d['n_cribs']:>3}  tested={d['tested']:>7,}  "
                  f"exact-survivors={d['survivors']:>7,}  "
                  f"lcm-bound-survivors={d['lcm_bound_survivors']:>7,}  "
                  f"(exact kills {d['caught_only_by_exact']:,} more)  "
                  f"max_ceiling={d['max_ceiling']}")
            if d["example_survivors"]:
                print(f"{'':<18}   min surviving lcm = {d['min_lcm_surviving']}; "
                      f"e.g. {d['example_survivors'][0]}")

    if args.part in ("2", "both"):
        p2 = run_part2(levels, perms)
        report["part2"] = p2
        print("\n=== PART 2: non-additive / non-periodic families ===")
        for fam, d in p2.items():
            if not d.get("applicable", True):
                print(f"{fam:<32} INAPPLICABLE")
                continue
            if "by_level" not in d:
                print(f"{fam:<32} {d.get('verdict','')[:90]}")
                continue
            print(f"{fam}:")
            for lname in crib_sets.LEVELS:
                e = d["by_level"][lname]
                print(f"   {lname:<18} n={e['n_cribs']:>3} tested={e['tested']:>7,} "
                      f"survivors={e['survivors']:>7,} max_ceiling={e['max_ceiling']}")

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=1, default=str)
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
