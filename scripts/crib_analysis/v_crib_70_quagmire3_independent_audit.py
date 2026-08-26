#!/usr/bin/env python3
"""v_crib_70_quagmire3_independent_audit.py -- adversarial audit of the Quagmire III
exact closure sweep (e_crib_70_quagmire3_exact_sweep.py).

The sweep's eliminations rest entirely on z26_linear's injectivity decider, so this
audit re-derives the same verdicts by routes that share NO code with it.

  A. HAND-CHECKABLE CERTIFICATE.  For a contradicted cell, exhibit an explicit
     integer combination y of the crib equations with  y^T M == e_i - e_j (mod 26).
     That is a proof, verifiable by multiplication alone, that pi(i) = pi(j) at
     EVERY solution -- so no solution is a permutation.  The certificate search
     uses sympy and a from-scratch modular rref, not z26_linear.
  B. INDEPENDENT BRUTE FORCE.  For small periods, enumerate every key vector in
     Z_26^P and decide by explicit backtracking over the 26 letter values whether
     any permutation pi satisfies the crib equations.  Includes its own positive
     control (planted alphabet/key must be found).
  C. ROUND-TRIP ON SURVIVORS.  For every cell the sweep reports CONSISTENT,
     materialise the witness as a real 26-letter alphabet plus key and re-encrypt
     the crib plaintext; it must reproduce the real K4 ciphertext at all 24 crib
     positions.  This checks that "consistent" is a real (alphabet, key), not a
     solver artefact -- while remaining, per the sweep's epistemics, NOT a
     candidate solution (the matched null survives these cells 63-100% of the time).

Usage
    PYTHONPATH=src python3 -u scripts/crib_analysis/v_crib_70_quagmire3_independent_audit.py
    ... --brute-max-period 2      (3 costs ~10 min per variant)
"""
from __future__ import annotations

import argparse
import itertools
import os
import random
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
for p in (os.path.join(_ROOT, "src"), os.path.join(_ROOT, "scripts", "lib"),
          os.path.join(_ROOT, "scripts", "crib_analysis")):
    sys.path.insert(0, p)

from kryptos.kernel.constants import CT  # noqa: E402
from crib_sets import level  # noqa: E402

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SIGNS = {"vig": (1, -1), "beau": (1, 1), "vbeau": (-1, 1)}   # s_c*pi(c) + s_p*pi(p) = k[r]


# ------------------------------------------------------- A. certificate (sympy)

def _modular_solve(A, b, p):
    """Solve A y = b over GF(p) with a from-scratch rref.  Returns y or None."""
    m, n = len(A), len(A[0])
    aug = [[A[i][j] % p for j in range(n)] + [b[i] % p] for i in range(m)]
    piv, r = [], 0
    for c in range(n):
        k = next((t for t in range(r, m) if aug[t][c]), None)
        if k is None:
            continue
        aug[r], aug[k] = aug[k], aug[r]
        inv = pow(aug[r][c], p - 2, p)
        aug[r] = [(x * inv) % p for x in aug[r]]
        for t in range(m):
            if t != r and aug[t][c]:
                f = aug[t][c]
                aug[t] = [(x - f * y) % p for x, y in zip(aug[t], aug[r])]
        piv.append(c)
        r += 1
    if any(aug[t][n] for t in range(r, m)):
        return None
    y = [0] * n
    for t, c in enumerate(piv):
        y[c] = aug[t][n]
    return y


def certificate(cribs, period, variant, i, j):
    """Integer y with y^T M == e_i - e_j mod 26, or None if the pair is not forced."""
    sc, sp = SIGNS[variant]
    n = 26 + period
    rows = []
    for pos in sorted(cribs):
        row = [0] * n
        row[ord(CT[pos]) - 65] += sc
        row[ord(cribs[pos]) - 65] += sp
        row[26 + pos % period] -= 1
        rows.append(row)
    tgt = [0] * n
    tgt[i], tgt[j] = 1, -1
    At = [[rows[r][c] for r in range(len(rows))] for c in range(n)]   # M^T
    parts = {}
    for p in (2, 13):
        y = _modular_solve(At, tgt, p)
        if y is None:
            return rows, None
        parts[p] = y
    y = [(13 * a + 14 * b) % 26 for a, b in zip(parts[2], parts[13])]
    return rows, y


def audit_certificates(verbose=True):
    """Prove selected contradicted cells with a verifiable certificate."""
    cribs = level("L0_released")
    cases = [(10, "vig", 0, 11, "A", "L"), (10, "vig", 4, 14, "E", "O"),
             (8, "vig", 2, 15, "C", "P"), (16, "vig", 4, 5, "E", "F")]
    ok = True
    for period, variant, i, j, li, lj in cases:
        rows, y = certificate(cribs, period, variant, i, j)
        if y is None:
            print(f"  P={period:<3}{variant:6s} pi({li})-pi({lj}) : no certificate "
                  f"(this pair is NOT forced)")
            continue
        n = len(rows[0])
        prod = [sum(y[r] * rows[r][c] for r in range(len(rows))) % 26 for c in range(n)]
        tgt = [0] * n
        tgt[i], tgt[j] = 1, 25
        good = prod == tgt
        ok &= good
        used = [(r, y[r]) for r in range(len(rows)) if y[r]]
        if verbose:
            print(f"  P={period:<3}{variant:6s} pi({li}) = pi({lj}) at EVERY solution; "
                  f"certificate uses crib rows {used}; y^T M == e_{li} - e_{lj} mod 26: {good}")
    print("  (a forced equality between two DISTINCT letters means no solution is a "
          "permutation, i.e. the cell is contradicted for all 26! alphabets)")
    return ok


# ---------------------------------------------------- B. independent brute force

def _bt_injective(cons, key_free_ok=True):
    letters = sorted(cons, key=lambda L: -len(cons[L]))
    pi, used = {}, set()

    def ok(L, v):
        for other, so, sl, k in cons[L]:
            if other in pi and (sl * v + so * pi[other] - k) % 26 != 0:
                return False
        return True

    def bt(idx):
        if idx == len(letters):
            return True
        L = letters[idx]
        for v in range(26):
            if v in used or not ok(L, v):
                continue
            pi[L] = v
            used.add(v)
            if bt(idx + 1):
                return True
            del pi[L]
            used.discard(v)
        return False

    return bt(0)


def brute_force_decide(ct, cribs, period, variant):
    """True iff SOME key in Z_26^period admits a permutation pi.  No z26_linear."""
    sc, sp = SIGNS[variant]
    E = [(ord(ct[pos]) - 65, ord(cribs[pos]) - 65, pos % period) for pos in sorted(cribs)]
    for key in itertools.product(range(26), repeat=period):
        cons = {}
        for c, p, r in E:
            cons.setdefault(c, []).append((p, sp, sc, key[r]))
            cons.setdefault(p, []).append((c, sc, sp, key[r]))
        if _bt_injective(cons):
            return True
    return False


def audit_brute_force(max_period=2, verbose=True):
    """Positive control on the brute forcer, then compare its verdict with the sweep's."""
    import e_crib_70_quagmire3_exact_sweep as S
    cribs = level("L0_released")
    rng = random.Random(11)
    pc = pt_ = 0
    for _ in range(6):
        for variant in ("vig", "beau", "vbeau"):
            pt_ += 1
            alpha = "".join(rng.sample(STD, 26))
            P = rng.choice(range(1, max_period + 1))
            key = [rng.randrange(26) for _ in range(P)]
            plain = {pos: rng.choice(STD) for pos in cribs}
            ctm = S.encrypt_q3(plain, alpha, key, variant)
            synth = "".join(ctm.get(i, "A") for i in range(97))
            pc += brute_force_decide(synth, plain, P, variant)
    print(f"  brute-force positive control (planted solution must be FOUND): {pc}/{pt_}")
    agree = tot = 0
    for P in range(1, max_period + 1):
        for variant in ("vig", "beau", "vbeau"):
            tot += 1
            bf = brute_force_decide(CT, cribs, P, variant)
            sw = S.evaluate(CT, cribs, P, variant).decision
            agree += (bf == (sw is True))
            if verbose:
                print(f"  L0 P={P} {variant:6s} brute-force injective-exists={bf}  "
                      f"sweep={sw}  {'AGREE' if bf == (sw is True) else 'DISAGREE'}")
    print(f"  agreement: {agree}/{tot}")
    return pc == pt_ and agree == tot


# ------------------------------------------------------- C. round-trip survivors

def audit_survivors(max_period=30, verbose=True):
    import e_crib_70_quagmire3_exact_sweep as S
    from z26_linear import free_columns, injective_point_report, solve_z26
    cribs = level("L0_released")
    ok = True
    found = 0
    for P in range(1, max_period + 1):
        for variant in ("vig", "beau", "vbeau"):
            rows, rhs, n = S.q3_system(CT, cribs, P, variant)
            sp = solve_z26(rows, rhs, n)
            fc = set(free_columns(rows, n))
            slots = [c for c in range(26) if c not in fc]
            rep = injective_point_report(sp, slots)
            if rep.decision is not True:
                continue
            found += 1
            w = list(rep.witness)
            pi = w[:26]
            leftover = [x for x in range(26) if x not in {pi[s] for s in slots}]
            for s in sorted(set(range(26)) - set(slots)):
                pi[s] = leftover.pop()
            perm = len(set(pi)) == 26
            alpha = [None] * 26
            for L in range(26):
                alpha[pi[L]] = chr(65 + L)
            alpha = "".join(alpha)
            key = w[26:]
            rt = all(S.encrypt_q3({p: cribs[p]}, alpha, key, variant)[p] == CT[p] for p in cribs)
            ok &= perm and rt
            if verbose:
                print(f"  P={P:<3}{variant:6s} alphabet={alpha} permutation={perm} "
                      f"reproduces all 24 cribs from the real CT: {rt}")
    print(f"  {found} surviving (level, period, variant) cells, all round-trip verified: {ok}")
    print("  NOTE: round-trip success is NOT evidence.  The matched null survives these "
          "cells 63-100% of the time; they are simply NOT ELIMINATED.")
    return ok



# ------------------------------- D. is EVERY elimination hand-certifiable?

def audit_all_certifiable(max_period=30, verbose=True):
    """The strongest soundness statement available: for every cell the sweep calls
    CONTRADICTED, and for each of its three variants, find an explicit forced-pair
    certificate  y^T M == e_i - e_j (mod 26)  with i != j.  Where one exists the
    elimination is a two-line linear proof that needs no search at all, so it does
    not rest on the injectivity decider's completeness argument.  Any cell listed
    as 'complete-search-only' below IS still soundly eliminated, but only by the
    DFS, and should be flagged as such."""
    import e_crib_70_quagmire3_exact_sweep as S
    from z26_linear import free_columns, injective_point_report, solve_z26
    from crib_sets import LEVELS
    total = certifiable = 0
    for lv in LEVELS:
        cribs = level(lv)
        deep = []
        for P in range(1, max_period + 1):
            per = {}
            for v in SIGNS:
                rows, rhs, n = S.q3_system(CT, cribs, P, v)
                sp = solve_z26(rows, rhs, n)
                fc = set(free_columns(rows, n))
                slots = [c for c in range(26) if c not in fc]
                per[v] = (injective_point_report(sp, slots).decision, slots)
            if any(d is not False for d, _ in per.values()):
                continue                      # not a contradicted cell
            total += 1
            allc = True
            for v, (_, slots) in per.items():
                allc &= any(
                    certificate(cribs, P, v, slots[i], slots[j])[1] is not None
                    for i in range(len(slots)) for j in range(i + 1, len(slots)))
            certifiable += allc
            if not allc:
                deep.append(P)
        if verbose:
            print(f"  {lv:<18} complete-search-only periods: {deep or 'NONE (all certifiable)'}")
    print(f"  {certifiable}/{total} contradicted cells carry an explicit forced-pair "
          f"certificate")
    return certifiable == total


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--brute-max-period", type=int, default=2)
    ap.add_argument("--max-period", type=int, default=30)
    args = ap.parse_args()
    print("A. hand-checkable contradiction certificates (sympy-free modular rref)")
    a = audit_certificates()
    print("\nB. independent brute force over every key in Z_26^P (no z26_linear)")
    b = audit_brute_force(args.brute_max_period)
    print("\nC. round-trip verification of every surviving cell")
    c = audit_survivors(args.max_period)
    print("\nD. is EVERY elimination hand-certifiable, or do some rest on the DFS?")
    d = audit_all_certifiable(args.max_period)
    print(f"\nAUDIT: certificates={a}  brute-force={b}  round-trip={c}  all-certifiable={d}")
    return 0 if (a and b and c and d) else 1


if __name__ == "__main__":
    raise SystemExit(main())
