#!/usr/bin/env python3
"""k4_exact_closures.py  --  exact (non-enumerative) crib-constraint tests for Kryptos K4.

The idea: several cipher families are LINEAR in their unknowns over Z_26, so the crib
equations can be solved exactly instead of sweeping keyword lists. Each test below returns
"contradicted", "vacuous" (no equation ever constrains two unknowns together), or a solution
space. No keyword list is involved anywhere; a contradiction closes the whole family for that
period, for every possible key or alphabet at once.

Tests
  1. single     one additive periodic key, direct alignment, 4 tableau conventions
  2. tiling     one additive periodic key, but the four crib WORDS may sit at any offsets
                relative to each other (covers nulls / code groups / run-preserving
                transposition between the words), 8 conventions
  3. twokey     key = a[i mod P] + b[i mod Q]  (any cascade of two additive layers with the
                same tableau collapses to this), solved by Gaussian elimination mod 2 and
                mod 13, 4 conventions
  4. quagmire   Quagmire I / II with a completely free mixed alphabet (all 26! at once):
                each crib position is one equation pi(x) + k'[r] = e over Z_26, i.e. an edge in
                a graph; components carry one free parameter; injectivity is a post-filter

Usage
  python3 k4_exact_closures.py                 # cribs only
  python3 k4_exact_closures.py --opening YESWONDERFULTHINGSXGOEASTNORTHEAST   # add a hypothesis

All positions are 1-indexed (O=1 ... R=97) to match Sanborn's public statements.
"""
import argparse
import itertools
import math
import random
from collections import defaultdict

CT = ("OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPK"
      "WGDKZXTJCDIGKUHUAUEKCAR")
assert len(CT) == 97
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KRY = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
WORDS = [(22, "EAST"), (26, "NORTHEAST"), (64, "BERLIN"), (70, "CLOCK")]   # artist-confirmed


def known_positions(opening=None):
    """dict position -> plaintext letter. The four cribs, plus an optional hypothesised opening."""
    kp = {start + i: ch for start, word in WORDS for i, ch in enumerate(word)}
    if opening:
        for i, ch in enumerate(opening):
            pos = i + 1
            if pos in kp and kp[pos] != ch:
                raise SystemExit(f"opening conflicts with crib at position {pos}")
            kp[pos] = ch
    return kp


def key_value(pos, plain, alpha_p, alpha_c, mode):
    """Additive key implied by one (plaintext, ciphertext) pair.
    vig : c = p + k   ->  k = c - p        beau : c = k - p  ->  k = c + p
    (variant Beaufort is the negation of Vigenere and gives identical consistency results)"""
    c, p = alpha_c.index(CT[pos - 1]), alpha_p.index(plain)
    return (c - p) % 26 if mode == "vig" else (c + p) % 26


# ----------------------------------------------------------------------------- test 1
def test_single_period(kp, max_period=97):
    """Which periods admit ANY key consistent with all known positions (direct alignment)?"""
    results = {}
    for name, (ap, ac, mode) in FOUR.items():
        ks = {pos: key_value(pos, pl, ap, ac, mode) for pos, pl in kp.items()}
        alive = []
        for p in range(1, max_period + 1):
            res, ok = {}, True
            for pos, k in ks.items():
                if res.get(pos % p, k) != k:
                    ok = False
                    break
                res[pos % p] = k
            if ok:
                alive.append(p)
        results[name] = alive
    return results


# ----------------------------------------------------------------------------- test 2
def test_word_tiling(max_period=23):
    """Each crib word becomes a run of key values; runs may sit at ANY offset on a period-p key.
    A contradiction here rules out the period no matter what happens between the words."""
    def place(key, run, r, p):
        k = dict(key)
        for j, v in enumerate(run):
            if k.get((r + j) % p, v) != v:
                return None
            k[(r + j) % p] = v
        return k

    results = {}
    for name, (ap, ac, mode) in EIGHT.items():
        runs = [[key_value(s + i, ch, ap, ac, mode) for i, ch in enumerate(w)] for s, w in WORDS]
        alive = []
        for p in range(1, max_period + 1):
            frontier = [place({}, runs[0], 0, p)]          # first run at offset 0, WLOG
            if frontier[0] is None:
                continue
            for run in runs[1:]:
                frontier = [k2 for key in frontier for r in range(p)
                            if (k2 := place(key, run, r, p)) is not None]
                if not frontier:
                    break
            if frontier:
                alive.append(p)
        results[name] = alive
    return results


# ----------------------------------------------------------------------------- test 3
def gauss_mod_p(rows, rhs, n, p):
    """Solve rows * x = rhs over GF(p). Returns (particular, nullspace_basis) or None if inconsistent."""
    m = len(rows)
    a = [r[:] + [v % p] for r, v in zip(rows, rhs)]
    pivots, r = [], 0
    for c in range(n):
        piv = next((i for i in range(r, m) if a[i][c] % p), None)
        if piv is None:
            continue
        a[r], a[piv] = a[piv], a[r]
        inv = pow(a[r][c], -1, p)
        a[r] = [(x * inv) % p for x in a[r]]
        for i in range(m):
            if i != r and a[i][c]:
                f = a[i][c]
                a[i] = [(x - f * y) % p for x, y in zip(a[i], a[r])]
        pivots.append(c)
        r += 1
        if r == m:
            break
    if any(a[i][n] % p for i in range(r, m)):
        return None
    part = [0] * n
    for i, c in enumerate(pivots):
        part[c] = a[i][n]
    null = []
    for f in (c for c in range(n) if c not in pivots):
        v = [0] * n
        v[f] = 1
        for i, c in enumerate(pivots):
            v[c] = (-a[i][f]) % p
        null.append(v)
    return part, null


def test_two_keys(kp, max_period=23):
    """key_i = a[i mod P] + b[i mod Q]. P+Q unknowns, one equation per known position.
    Feasible only if the mod-2 and mod-13 systems are both consistent (CRT)."""
    results = {}
    for name, (ap, ac, mode) in FOUR.items():
        sign = 1 if mode == "vig" else -1
        feasible = []
        for P in range(2, max_period + 1):
            for Q in range(P, max_period + 1):
                if Q % P == 0:                      # Q a multiple of P collapses to one period
                    continue
                rows, rhs = [], []
                for pos, pl in kp.items():
                    row = [0] * (P + Q)
                    row[pos % P] = 1
                    row[P + pos % Q] = 1
                    rows.append(row)
                    rhs.append((ac.index(CT[pos - 1]) - sign * ap.index(pl)) % 26)
                if gauss_mod_p(rows, rhs, P + Q, 2) and gauss_mod_p(rows, rhs, P + Q, 13):
                    feasible.append((P, Q))
        results[name] = feasible
    return results


# ----------------------------------------------------------------------------- test 4
def quagmire_equations(kp, period, variant, mode):
    """Quagmire I : idx(c) = pi(p) + k      Quagmire II : pi(c) = idx(p) + k     (Beaufort: k - .)
    Every case rewrites as  pi(letter) + k'[residue] = e  with k' a relabelled key."""
    eqs = []
    for pos, pl in kp.items():
        c, r = CT[pos - 1], pos % period
        if variant == "Q1":
            e = STD.index(c) if mode == "vig" else -STD.index(c)
            eqs.append((pl, r, e % 26))
        else:
            e = STD.index(pl) if mode == "vig" else -STD.index(pl)
            eqs.append((c, r, e % 26))
    return eqs


def quagmire_status(kp, period, variant, mode):
    """'contradicted' | 'consistent (n components)'. Each connected component of the
    pi/k graph carries exactly one free parameter; a cycle with the wrong sum is a contradiction."""
    adj = defaultdict(list)
    for letter, r, e in quagmire_equations(kp, period, variant, mode):
        adj[("pi", letter)].append((("k", r), e))
        adj[("k", r)].append((("pi", letter), e))
    assign, components = {}, 0
    for v in adj:
        if v in assign:
            continue
        components += 1
        assign[v] = (1, 0)                          # value = a * t + b
        stack = [v]
        while stack:
            u = stack.pop()
            a, b = assign[u]
            for w, e in adj[u]:
                cand = (-a, (e - b) % 26)           # u + w = e
                if w in assign:
                    if assign[w] != cand:
                        return "contradicted"
                else:
                    assign[w] = cand
                    stack.append(w)
    return f"consistent ({components} components)"


def quagmire_null_rate(period, variant, trials=200, seed=1):
    """How often does a RANDOM ciphertext at the crib positions pass the same consistency test?
    If this is ~100%, survival at that period is structural and carries no information."""
    global CT
    original, rng, passed = CT, random.Random(seed), 0
    kp = known_positions()
    try:
        for _ in range(trials):
            ct = list(original)
            for pos in kp:
                ct[pos - 1] = rng.choice(STD)
            CT = "".join(ct)
            passed += quagmire_status(kp, period, variant, "vig") != "contradicted"
    finally:
        CT = original
    return passed / trials


FOUR = {"Vig  std": (STD, STD, "vig"), "Beau std": (STD, STD, "beau"),
        "Vig  kry": (KRY, KRY, "vig"), "Beau kry": (KRY, KRY, "beau")}
EIGHT = dict(FOUR, **{"Vig  std/kry": (STD, KRY, "vig"), "Beau std/kry": (STD, KRY, "beau"),
                      "Vig  kry/std": (KRY, STD, "vig"), "Beau kry/std": (KRY, STD, "beau")})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--opening", help="hypothesised plaintext from position 1, e.g. YESWONDERFULTHINGSXGOEASTNORTHEAST")
    args = ap.parse_args()
    kp = known_positions(args.opening)
    print(f"known positions: {len(kp)} of 97" + (f"  (cribs + opening '{args.opening}')" if args.opening else "  (cribs only)"))

    print("\n[1] single additive periodic key, direct alignment: periods that survive (others contradicted)")
    for name, alive in test_single_period(kp).items():
        print(f"    {name}: {alive if len(alive) < 30 else str(alive[:12])[:-1] + ', ...]'}")

    print("\n[2] crib words tiled at free offsets on a period-p key: periods 1-23 that survive")
    for name, alive in test_word_tiling().items():
        print(f"    {name:13s}: {alive or 'none'}")

    print("\n[3] key = a[i mod P] + b[i mod Q], P<=Q<=23: feasible pairs, smallest P+Q first")
    for name, feas in test_two_keys(kp).items():
        feas.sort(key=lambda t: (t[0] + t[1], t))
        print(f"    {name}: {len(feas)} feasible; smallest P+Q: {feas[:5] or 'none'}   (unknowns P+Q vs {len(kp)} equations)")

    print("\n[4] Quagmire I / II with a free mixed alphabet, periods 1-20")
    for variant in ("Q1", "Q2"):
        for mode in ("vig", "beau"):
            status = {p: quagmire_status(kp, p, variant, mode) for p in range(1, 21)}
            alive = {p: s for p, s in status.items() if s != "contradicted"}
            print(f"    {variant} {mode:4s}: surviving periods {list(alive) or 'none'}")
    if not args.opening:
        print(f"    null check: random ciphertext at the crib positions passes Q1 period 13 in "
              f"{quagmire_null_rate(13, 'Q1'):.0%} of trials (survival there is structural, not evidence)")


if __name__ == "__main__":
    main()
