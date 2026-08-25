#!/usr/bin/env python3
"""
ID: v_crib_stacked_nonperiodic_audit_01
FAMILY: crib_analysis
STATUS: active
SUMMARY: Adversarial re-verification of f_stacked_and_nonperiodic_ceiling.py.
         Independently re-derives its filters, reproduces one elimination and
         one survivor by round-trip, and sweeps the two composition sub-spaces
         the original grid silently omitted.

HYPOTHESIS UNDER TEST
---------------------
Not a cipher hypothesis. The hypothesis is METHODOLOGICAL:

    H_audit : the eliminations reported by f_stacked_and_nonperiodic_ceiling.py
              hold over the model space its headline quantifies over.

Five independent attacks, cheapest first:

  A1 BIJECTION      every permutation in the shared library is a genuine
                    bijection of 0..96 (a dropped/repeated index would
                    invalidate every ceiling derived from it).
  A2 ORACLE         the union-find Z/26 feasibility test agrees with exhaustive
                    brute force over all 26^p1 x 26^p2 key pairs, on the REAL
                    ciphertext, for small periods.
  A3 REPRODUCE      one reported elimination (true ceiling by brute force) and
                    one reported survivor (explicit key constructed, then
                    re-encrypted) must both come out identical.
  A4 AB-GRID GAP    in the "sandwich" mode p1 is the PLAINTEXT-frame period and
                    p2 the CIPHERTEXT-frame period, so the two are NOT
                    interchangeable -- yet the original grid enumerates only
                    p1 <= p2. Sweep the missing p1 > p2 half.
  A5 PEEL-ORDER GAP the original autokey filter runs the feedback along the
                    ciphertext index j only, i.e. CT = Autokey(Transpose(PT)).
                    The other order, CT = Transpose(Autokey(PT)), is never
                    tested. Sweep it.

SCOPE
-----
A4 covers 126 non-identity permutations x 78 missing (p1,p2) pairs x 6 levels
x 2 net variants x 3 alphabet pairs = 353,808 configurations. A5 covers 41
permutations x 40 primer lengths x 2 nets x 2 alphabet pairs x 6 levels x 2
feedback sources = 39,360 configurations. Both are EXHAUSTIVE over the stated
grid and PARTIAL with respect to the permutation space (97! transpositions
exist; 127 are in the shared library). Nothing here samples.

PRE-REGISTERED INTERPRETATION -- FIXED BEFORE THE RUN
-----------------------------------------------------
    ceiling <  n_cribs  ->  IMPOSSIBLE for every key. SOUND ELIMINATION.
    ceiling == n_cribs  ->  NOT ELIMINATED BY THIS FILTER. Never "possible",
                            never a candidate solution. A survivor survived a
                            filter and nothing else; no plaintext outside the
                            crib positions is claimed, checked, or implied.
    L0_released is the only EVIDENCE level. Any L1..L5 result is CONDITIONAL on
    an unproven plaintext hypothesis.
    A single survivor found inside A4 or A5 at a parameter the original report
    declared eliminated REFUTES that elimination. Zero survivors there leaves
    the elimination standing but still corrects the coverage statement.

FRAME SAFETY
------------
    Reads no BEAN_EQ / BEAN_INEQ / BEAN_LINEAR. Every demand value is
    re-derived from (CT, crib map, alignment) at evaluation time.
"""
from __future__ import annotations

import argparse
import itertools
import math
import os
import sys
import time
from collections import Counter
from multiprocessing import Pool

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

import crib_sets                                    # noqa: E402
from kryptos.kernel.constants import CT             # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    columnar_perm, myszkowski_perm, rail_fence_perm,
)

MOD = 26
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
L = len(CT)


def kwmix(kw: str, base: str = AZ) -> str:
    s: list[str] = []
    for c in kw.upper():
        if c.isalpha() and c not in s:
            s.append(c)
    for c in base:
        if c not in s:
            s.append(c)
    return "".join(s)


def tab(alpha: str) -> list[int]:
    t = [0] * 26
    for i, c in enumerate(alpha):
        t[ord(c) - 65] = i
    return t


def inv(perm) -> list[int]:
    ip = [0] * len(perm)
    for j, q in enumerate(perm):
        ip[q] = j
    return ip


ALPH = [("AZ/AZ", AZ, AZ), ("KA/AZ", KA, AZ),
        ("KA/PALIMPSEST", KA, kwmix("PALIMPSEST"))]


def build_perms(n: int = 97):
    """Rebuilt to match the library the audited script declares."""
    import random
    out = [("identity", list(range(n)))]
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
        ranked = sorted([(c, i) for i, c in enumerate(kw)], key=lambda x: (x[0], x[1]))
        order = [0] * len(kw)
        for rank, (_, pos) in enumerate(ranked):
            order[pos] = rank
        out.append((f"colkw.{kw}", columnar_perm(len(kw), order, n)))
        out.append((f"mysz.{kw}", myszkowski_perm(kw, n)))
    for d in range(2, 10):
        out.append((f"rail{d}", rail_fence_perm(n, d)))
    return out


PERMS = build_perms()
IP = {nm: inv(p) for nm, p in PERMS}
LEV = {nm: crib_sets.level(nm) for nm in crib_sets.LEVELS}
SMALL = [nm for nm, _ in PERMS
         if nm == "identity" or nm.startswith(("col7", "col8", "col10",
                                               "colkw", "rail"))]

# ── exact feasibility, written from scratch (no import from the audited file) ─


def uf_feasible(edges) -> bool:
    par: dict = {}
    pot: dict = {}

    def find(x):
        if x not in par:
            par[x], pot[x] = x, 0
            return x, 0
        r, acc = x, 0
        while par[r] != r:
            acc = (acc + pot[r]) % MOD
            r = par[r]
        return r, acc

    for a, b, t in edges:
        ra, pa = find(("L", a))
        rb, pb = find(("R", b))
        if ra == rb:
            if (pa - pb) % MOD != t % MOD:
                return False
        else:
            par[ra] = rb
            pot[ra] = (t + pb - pa) % MOD
    return True


def edges_for(cribs, ip, mode, p1, p2, net, ct_tab, pt_tab):
    out = []
    for q, ch in cribs.items():
        j = ip[q]
        a, b = ((j % p1, j % p2) if mode == "AA" else
                (q % p1, q % p2) if mode == "BB" else (q % p1, j % p2))
        c = ct_tab[ord(CT[j]) - 65]
        p = pt_tab[ord(ch) - 65]
        out.append((a, b, (c - p) % MOD if net == "vig" else (c + p) % MOD))
    return out


def brute_ceiling(cribs, ip, mode, p1, p2, net, ct_tab, pt_tab) -> int:
    """TRUE ceiling by exhaustion over every (s1, s2). No relaxation."""
    dem = edges_for(cribs, ip, mode, p1, p2, net, ct_tab, pt_tab)
    best = 0
    for s1 in itertools.product(range(MOD), repeat=p1):
        cnt: dict = {}
        for a, b, t in dem:
            cnt.setdefault(b, Counter())[(t - s1[a]) % MOD] += 1
        tot = sum(max(d.values()) for d in cnt.values())
        if tot > best:
            best = tot
    return best


# ── A5: autokey with the substitution INNER (transposition applied last) ─────

def autokey_inner_ceiling(cribs, ip, m, net, kind, ct_tab, pt_tab) -> int:
    """CT = Transpose(Autokey(PT)).  C'[q] = CT[ip[q]] is the pre-transposition
    ciphertext, so the feedback chain runs along the PLAINTEXT index q."""
    d = [ct_tab[ord(CT[ip[q]]) - 65] for q in range(L)]
    known = {q: pt_tab[ord(ch) - 65] for q, ch in cribs.items()}
    if kind == "ct":
        hit = 0
        for q, want in known.items():
            if q < m:
                hit += 1
            else:
                got = (d[q] - d[q - m]) % MOD if net == "vig" else (d[q - m] - d[q]) % MOD
                hit += int(got == want)
        return hit
    total = 0
    for r in range(m):
        chain = list(range(r, L, m))
        ks = [q for q in chain if q in known]
        if not ks:
            continue
        best = 0
        for seed in range(MOD):
            v, cnt = seed, 0
            for k, q in enumerate(chain):
                if k > 0:
                    v = (d[q] - v) % MOD if net == "vig" else (v - d[q]) % MOD
                if q in known:
                    cnt += int(v == known[q])
            if cnt > best:
                best = cnt
            if best == len(ks):
                break
        total += best
    return total


# ── attacks ──────────────────────────────────────────────────────────────────

def a1_bijection() -> int:
    bad = [nm for nm, p in PERMS if sorted(p) != list(range(L))]
    print(f"[A1] permutations checked {len(PERMS)}; non-bijections {len(bad)} {bad}")
    print(f"[A1] Part-2 permutation subset actually used: {len(SMALL)} "
          f"(the audited report states 21)")
    return len(bad)


def a2_oracle(trials: int = 60) -> int:
    import random
    rng = random.Random(1)
    cribs = LEV["L0_released"]
    n = len(cribs)
    tt = tab(AZ)
    names = [nm for nm, _ in PERMS]
    mism = 0
    for _ in range(trials):
        nm = rng.choice(names)
        ip = IP[nm]
        mode = rng.choice(["AA", "BB", "AB"])
        net = rng.choice(["vig", "beau"])
        p1, p2 = rng.randrange(2, 5), rng.randrange(2, 5)
        bc = brute_ceiling(cribs, ip, mode, p1, p2, net, tt, tt)
        uf = uf_feasible(edges_for(cribs, ip, mode, p1, p2, net, tt, tt))
        mism += int((bc == n) != uf)
    print(f"[A2] union-find vs exhaustive brute force on real CT: "
          f"{trials} configs, {mism} mismatches")
    return mism


def a3_reproduce() -> int:
    fails = 0
    tt = tab(AZ)
    cribs = LEV["L0_released"]
    ident = list(range(L))
    print("[A3] brute-forced TRUE ceilings at direct alignment, L0:")
    for (p1, p2), claim in zip([(2, 2), (3, 3), (2, 3), (3, 4), (4, 5)],
                               [5, 6, 7, 9, 11]):
        got = brute_ceiling(cribs, ident, "AA", p1, p2, "vig", tt, tt)
        flag = "ok" if got == claim else "MISMATCH"
        fails += int(got != claim)
        print(f"     p=({p1},{p2})  true ceiling {got}/24   report claims {claim}  [{flag}]")

    # reported survivor rail6 | AB | p=(12,12) | beau | AZ/AZ -> build the key
    ip = IP["rail6"]
    E = edges_for(cribs, ip, "AB", 12, 12, "beau", tt, tt)
    par: dict = {}
    pot: dict = {}

    def find(x):
        if x not in par:
            par[x], pot[x] = x, 0
            return x, 0
        r, acc = x, 0
        while par[r] != r:
            acc = (acc + pot[r]) % MOD
            r = par[r]
        return r, acc

    for a, b, t in E:
        ra, pa = find(("L", a))
        rb, pb = find(("R", b))
        if ra != rb:
            par[ra] = rb
            pot[ra] = (t + pb - pa) % MOD
    val = {k: find(k)[1] for k in list(par)}
    s1 = [val.get(("L", a), 0) for a in range(12)]
    s2 = [(-val.get(("R", b), 0)) % MOD for b in range(12)]
    hits = sum(int(AZ[(-AZ.index(ch) + s1[q % 12] + s2[ip[q] % 12]) % MOD] == CT[ip[q]])
               for q, ch in cribs.items())
    print(f"[A3] reported survivor rail6|AB|p=(12,12)|beau|AZ/AZ: explicit key "
          f"re-encrypts {hits}/{len(cribs)} released cribs")
    fails += int(hits != len(cribs))
    return fails


def _a4_job(nm):
    ip = IP[nm]
    res = []
    for alab, ca, pa in ALPH:
        ct_tab, pt_tab = tab(ca), tab(pa)
        for lname in crib_sets.LEVELS:
            cribs = LEV[lname]
            n = len(cribs)
            for net in ("vig", "beau"):
                base = []
                for q, ch in cribs.items():
                    j = ip[q]
                    c = ct_tab[ord(CT[j]) - 65]
                    p = pt_tab[ord(ch) - 65]
                    base.append((q, j, (c - p) % MOD if net == "vig" else (c + p) % MOD))
                for p1 in range(2, 15):
                    for p2 in range(2, 15):
                        if p1 <= p2:
                            continue          # this half WAS tested by the original
                        if uf_feasible([(q % p1, j % p2, t) for q, j, t in base]):
                            res.append((nm, p1, p2, lname, net, alab))
    return res


def a4_ab_gap(workers: int):
    names = [nm for nm, _ in PERMS if nm != "identity"]
    total = len(names) * 78 * len(crib_sets.LEVELS) * 2 * len(ALPH)
    t0 = time.perf_counter()
    with Pool(workers) as pool:
        rows = [r for chunk in pool.imap_unordered(_a4_job, names) for r in chunk]
    print(f"[A4] mode-AB p1>p2 half: {total:,} configs NEVER tested by the "
          f"original grid, swept in {time.perf_counter()-t0:.1f}s")
    bylev = Counter(r[3] for r in rows)
    print(f"[A4] survivors {len(rows)} -> by level {dict(bylev)}")
    l0 = [r for r in rows if r[3] == "L0_released"]
    if l0:
        lc = Counter(math.lcm(r[1], r[2]) for r in l0)
        print(f"[A4] L0 survivors by lcm(p1,p2): {dict(sorted(lc.items()))}")
        print(f"[A4] L0 survivors with lcm<=11: "
              f"{sum(1 for r in l0 if math.lcm(r[1], r[2]) <= 11)}")
    return rows


def a5_peel_gap():
    print("[A5] autokey substitution-INNER order (never tested by the original):")
    hits_all = {}
    for kind in ("pt", "ct"):
        for lname in crib_sets.LEVELS:
            cribs = LEV[lname]
            n = len(cribs)
            tested = surv = best = 0
            hits = []
            for nm in SMALL:
                ip = IP[nm]
                for alab, ca, pa in (("AZ/AZ", AZ, AZ), ("KA/AZ", KA, AZ)):
                    ct_tab, pt_tab = tab(ca), tab(pa)
                    for net in ("vig", "beau"):
                        for m in range(1, 41):
                            tested += 1
                            c = autokey_inner_ceiling(cribs, ip, m, net, kind,
                                                      ct_tab, pt_tab)
                            best = max(best, c)
                            if c == n:
                                surv += 1
                                hits.append((nm, alab, net, m))
            hits_all[(kind, lname)] = hits
            print(f"     {kind}-autokey {lname:<18} n={n:<3} tested={tested:<6} "
                  f"survivors={surv:<5} max_ceiling={best}")
    l0 = hits_all[("pt", "L0_released")]
    low = [h for h in l0 if h[3] <= 26]
    print(f"[A5] PT-autokey INNER, L0, primer m<=26 survivors: {len(low)}  "
          f"(the report declares m=1..26 ELIMINATED)")
    for h in sorted(low, key=lambda h: h[3]):
        print(f"       {h}")
    return low


def a5_roundtrip(nm="rail9", m=26):
    """Full re-encryption of one A5 survivor back to the carved ciphertext."""
    perm = dict(PERMS)[nm]
    ip = IP[nm]
    cribs = LEV["L0_released"]
    known = {q: AZ.index(c) for q, c in cribs.items()}
    d = [AZ.index(CT[ip[q]]) for q in range(L)]
    pt = [None] * L
    for r in range(m):
        chain = list(range(r, L, m))
        ks = [q for q in chain if q in known]
        for seed in range(MOD):
            v, vals = seed, {}
            for k, q in enumerate(chain):
                if k > 0:
                    v = (d[q] - v) % MOD
                vals[q] = v
            if all(vals[q] == known[q] for q in ks):
                for q, vv in vals.items():
                    pt[q] = vv
                break
        else:
            print(f"[A5] round-trip: chain {r} unsatisfiable")
            return 1
    PT = "".join(AZ[v] for v in pt)
    primer = [(d[r] - pt[r]) % MOD for r in range(m)]
    cp = [(pt[q] + (primer[q] if q < m else pt[q - m])) % MOD for q in range(L)]
    ct_re = "".join(AZ[cp[perm[j]]] for j in range(L))
    ok = ct_re == CT
    nc = sum(1 for q, c in cribs.items() if PT[q] == c)
    print(f"[A5] ROUND-TRIP {nm} + PT-autokey vig primer {m} AZ/AZ:")
    print(f"       primer      = {''.join(AZ[v] for v in primer)}")
    print(f"       recovered PT= {PT}")
    print(f"       re-encrypted CT == carved K4 CT : {ok}")
    print(f"       released cribs matched          : {nc}/{len(cribs)}")
    print("       NOT a solution and not claimed as one: the plaintext outside "
          "the crib positions is gibberish and no language check was run. It is "
          "a ceiling survivor, which is exactly what refutes the elimination.")
    return 0 if (ok and nc == len(cribs)) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 2))
    args = ap.parse_args()
    print("=" * 78)
    print("ADVERSARIAL AUDIT of f_stacked_and_nonperiodic_ceiling.py")
    print("=" * 78)
    bad = a1_bijection()
    mism = a2_oracle()
    rep = a3_reproduce()
    a4 = a4_ab_gap(args.workers)
    low = a5_peel_gap()
    rt = a5_roundtrip()
    print("\n" + "=" * 78)
    print(f"A1 bijection failures        : {bad}")
    print(f"A2 oracle mismatches         : {mism}")
    print(f"A3 reproduction failures     : {rep}")
    print(f"A4 untested AB-half survivors: {len(a4)}  (grid omission, "
          f"353,808 configs)")
    print(f"A5 refuting survivors        : {len(low)}  (PT-autokey inner order, "
          f"primer m<=26 at L0)")
    print(f"A5 round-trip failures       : {rt}")
    print("=" * 78)


if __name__ == "__main__":
    main()
