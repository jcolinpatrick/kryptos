#!/usr/bin/env python3
"""e_crib_70_quagmire3_exact_sweep.py -- exact Quagmire III closure sweep over Z_26.

WHAT THIS DOES
--------------
Quagmire III with a FREE mixed alphabet is linear over Z_26 once the alphabet is
treated as 26 unknowns instead of a keyword to enumerate:

    pi(c_i) - pi(p_i) - k[r_i] = 0        (vig)
    pi(c_i) + pi(p_i) - k[r_i] = 0        (beau)
   -pi(c_i) + pi(p_i) - k[r_i] = 0        (vbeau)

with r_i = pos_i mod P.  Unknowns: 26 alphabet values + P key values.  Solving
this exactly closes ALL 26! alphabets AND all 26^P keys at once for a period,
which no keyword enumeration can do.

The equation form is PINNED, not rederived here: it is validated in
scripts/lib/test_z26_linear.py against K1 (Quagmire III, PALIMPSEST, period 10)
and K2 (ABSCISSA, period 8), where pi(c)-pi(p) is constant on every residue
class and the recovered shift vector reads the keyword in the KRYPTOS alphabet.

TWO STRUCTURAL FACTS THIS SWEEP CARRIES
---------------------------------------
1. THE SYSTEM IS HOMOGENEOUS.  Every rhs is 0, so pi = const, k = 0 always
   solves it.  `solve_z26` can therefore NEVER return None here and "linearly
   consistent" carries exactly zero information.  All discriminating power is in
   INJECTIVITY: does the affine solution space contain a point where pi is a
   permutation?
2. DIMENSION IS NOT EVIDENCE.  Gauge freedom (add a constant to every pi) plus
   the global scalar already give a 676-point trivial orbit, and a key sharing a
   factor with 26 inflates it further.  Dimension is reported for the record, not
   as a result.

REDUCTION USED FOR INJECTIVITY
------------------------------
Only letters whose alphabet column is nonzero in some equation are constrained
(`free_columns`).  If the constrained letters can be made pairwise distinct, the
unconstrained ones are free columns over Z_26 and can absorb the leftover values,
so "pi is a permutation" reduces exactly to "the constrained slots are pairwise
distinct".  That decision is delegated to z26_linear.injective_point_report,
whose True and False are both sound and whose None is INCONCLUSIVE.

INDEXING NOTE.  Positions are 0-indexed (kernel convention).  Using 1-indexed
positions instead would replace r_i by (r_i + 1) mod P, which is a cyclic
relabelling of the key unknowns and changes nothing about consistency or
injectivity.

EPISTEMICS.  "contradicted" = sound elimination for every key and every one of
the 26! alphabets, at that period, for that variant, under DIRECT alignment.
"consistent" = NOT ELIMINATED.  It is never "possible" and never a candidate.
A budget-out is INCONCLUSIVE, never an elimination.  Every elimination at crib
level L1..L5 is CONDITIONAL on that hypothesised plaintext.

Usage
    PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_70_quagmire3_exact_sweep.py
    ... --trials 300 --workers 26 --max-period 30 --json out.json
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
from dataclasses import dataclass

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
sys.path.insert(0, os.path.join(_ROOT, "kryptosbot"))
sys.path.insert(0, _ROOT)

from z26_linear import (  # noqa: E402
    free_columns, injective_point_report, solve_z26,
)
from crib_sets import DESCRIPTIONS, LEVELS, level  # noqa: E402
from kryptos.kernel.constants import CT as K4_CT  # noqa: E402

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KRY = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KRY_IDX = {ch: i for i, ch in enumerate(KRY)}
VARIANTS = ("vig", "beau", "vbeau")
UNITS = [a for a in range(26) if math.gcd(a, 26) == 1]

# (coefficient on pi(c), coefficient on pi(p)) for each additive variant
_COEF = {"vig": (1, 25), "beau": (1, 1), "vbeau": (25, 1)}


# --------------------------------------------------------------------- systems

def q3_system(ct: str, cribs: dict[int, str], period: int, variant: str):
    """Rows/rhs/n for the Quagmire III crib system.  Unknowns 0..25 = pi, 26.. = k."""
    n = 26 + period
    cc, cp = _COEF[variant]
    rows, rhs = [], []
    for pos in sorted(cribs):
        p = cribs[pos]
        c = ct[pos]
        row = [0] * n
        row[ord(c) - 65] = (row[ord(c) - 65] + cc) % 26
        row[ord(p) - 65] = (row[ord(p) - 65] + cp) % 26
        row[26 + pos % period] = (row[26 + pos % period] + 25) % 26
        rows.append(row)
        rhs.append(0)
    return rows, rhs, n


def q4_system(ct: str, cribs: dict[int, str], period: int, variant: str):
    """Quagmire IV (two alphabets).  Included ONLY as a positive control; the Q4
    sweep is a separate job.  Unknowns 0..25 = pi_p, 26..51 = pi_c, 52.. = k."""
    n = 52 + period
    rows, rhs = [], []
    for pos in sorted(cribs):
        p, c = cribs[pos], ct[pos]
        row = [0] * n
        ci, pi_ = 26 + ord(c) - 65, ord(p) - 65
        cc, cp = _COEF[variant]
        row[ci] = (row[ci] + cc) % 26
        row[pi_] = (row[pi_] + cp) % 26
        row[52 + pos % period] = 25
        rows.append(row)
        rhs.append(0)
    return rows, rhs, n


def gauge_shift(x, t, period, variant, n_alpha=26):
    """Adding t to every pi value is a symmetry only if the key absorbs it:
    vig/vbeau leave k alone (coefficients sum to 0), beau needs k + 2t."""
    dk = 2 * t if variant == "beau" else 0
    return ([(v + t) % 26 for v in x[:n_alpha]]
            + [(v + dk) % 26 for v in x[n_alpha:]])


@dataclass
class Cell:
    decision: bool | None       # injectivity: True survives, False eliminated, None inconclusive
    dim2: int
    dim13: int
    n_slots: int
    reason: str
    nodes: int


def evaluate(ct: str, cribs: dict[int, str], period: int, variant: str,
             *, node_budget: int = 200_000, restarts: int = 8) -> Cell:
    rows, rhs, n = q3_system(ct, cribs, period, variant)
    sp = solve_z26(rows, rhs, n)
    if sp is None:                      # cannot happen: the system is homogeneous
        raise AssertionError("homogeneous Q3 system reported inconsistent -- solver bug")
    freec = set(free_columns(rows, n))
    slots = [c for c in range(26) if c not in freec]
    rep = injective_point_report(sp, slots, node_budget=node_budget, restarts=restarts)
    return Cell(rep.decision, sp.dim2, sp.dim13, len(slots), rep.reason, rep.nodes)


def cell_status(decisions) -> str:
    """Aggregate the three variants.  A period is ELIMINATED for the Quagmire III
    family only if every additive variant is eliminated."""
    if any(d is True for d in decisions):
        return "consistent"
    if any(d is None for d in decisions):
        return "inconclusive"
    return "contradicted"


# ------------------------------------------------------------- synthetic data

def encrypt_q3(pt_by_pos: dict[int, str], alpha: str, key, variant: str) -> dict[int, str]:
    """Encrypt position-wise with direct alignment r = pos mod len(key)."""
    ip = {ch: i for i, ch in enumerate(alpha)}
    P = len(key)
    out = {}
    for pos, p in pt_by_pos.items():
        k = key[pos % P]
        if variant == "vig":
            v = (ip[p] + k) % 26
        elif variant == "beau":
            v = (k - ip[p]) % 26
        else:
            v = (ip[p] - k) % 26
        out[pos] = alpha[v]
    return out


def encrypt_q4(pt_by_pos, alpha_p, alpha_c, key, variant):
    ip = {ch: i for i, ch in enumerate(alpha_p)}
    P = len(key)
    out = {}
    for pos, p in pt_by_pos.items():
        k = key[pos % P]
        if variant == "vig":
            v = (ip[p] + k) % 26
        elif variant == "beau":
            v = (k - ip[p]) % 26
        else:
            v = (ip[p] - k) % 26
        out[pos] = alpha_c[v]
    return out


def _ct_string(ct_map: dict[int, str], length: int = 97) -> str:
    return "".join(ct_map.get(i, "A") for i in range(length))


# --------------------------------------------------------------- 1. positive control

def positive_controls(verbose: bool = True):
    """MANDATORY CONTROL 1.  Synthesise from a KNOWN random mixed alphabet, known
    key and known period and require the procedure to report the cell CONSISTENT
    (space contains the planted point, including its gauge translate) AND
    INJECTIVE-SATISFIABLE.  A test that over-eliminates is worthless.

    Three regimes:
      dense   -- 400 contiguous characters (the classical Quagmire regime)
      sparse  -- exactly the crib positions of each level, on a 97-char carrier.
                 This is the ACTUAL regime of the K4 sweep and is the one that
                 could plausibly over-eliminate, so it dominates the count.
      q4      -- Quagmire IV dense, all variants (out of scope for this sweep,
                 kept so the shared decider is exercised on two alphabets too).
    """
    rng = random.Random(20260825)
    passed = total = 0
    failures = []

    # -- dense
    for _ in range(12):
        for variant in VARIANTS:
            total += 1
            alpha = "".join(rng.sample(STD, 26))
            P = rng.randrange(3, 11)
            key = [rng.randrange(26) for _ in range(P)]
            pt = {i: rng.choice(STD) for i in range(400)}
            ctm = encrypt_q3(pt, alpha, key, variant)
            ct = "".join(ctm[i] for i in range(400))
            rows, rhs, n = q3_system(ct, pt, P, variant)
            sp = solve_z26(rows, rhs, n)
            idx = {ch: i for i, ch in enumerate(alpha)}
            truth = [idx[STD[i]] for i in range(26)] + list(key)
            ok = (sp is not None and sp.contains(truth)
                  and sp.contains(gauge_shift(truth, 7, P, variant)))
            if ok:
                freec = set(free_columns(rows, n))
                slots = [c for c in range(26) if c not in freec]
                ok = injective_point_report(sp, slots).decision is True
            passed += ok
            if not ok:
                failures.append(f"dense {variant} P={P}")

    # -- sparse, at the real crib geometry of every level
    for lv in LEVELS:
        cribs_pos = sorted(level(lv))
        for _ in range(6):
            for variant in VARIANTS:
                total += 1
                alpha = "".join(rng.sample(STD, 26))
                P = rng.randrange(3, 15)
                key = [rng.randrange(26) for _ in range(P)]
                pt = {pos: rng.choice(STD) for pos in cribs_pos}
                ctm = encrypt_q3(pt, alpha, key, variant)
                ct = _ct_string(ctm)
                cell = evaluate(ct, pt, P, variant)
                rows, rhs, n = q3_system(ct, pt, P, variant)
                sp = solve_z26(rows, rhs, n)
                idx = {ch: i for i, ch in enumerate(alpha)}
                truth = [idx[STD[i]] for i in range(26)] + list(key)
                ok = (sp.contains(truth)
                      and sp.contains(gauge_shift(truth, 5, P, variant))
                      and cell.decision is True)
                passed += ok
                if not ok:
                    failures.append(f"sparse {lv} {variant} P={P} dec={cell.decision}")

    # -- Q4 dense (shared decider, two alphabets)
    for _ in range(6):
        for variant in VARIANTS:
            total += 1
            ap = "".join(rng.sample(STD, 26))
            ac = "".join(rng.sample(STD, 26))
            P = rng.randrange(3, 9)
            key = [rng.randrange(26) for _ in range(P)]
            pt = {i: rng.choice(STD) for i in range(400)}
            ctm = encrypt_q4(pt, ap, ac, key, variant)
            ct = "".join(ctm[i] for i in range(400))
            rows, rhs, n = q4_system(ct, pt, P, variant)
            sp = solve_z26(rows, rhs, n)
            ipp = {ch: i for i, ch in enumerate(ap)}
            ipc = {ch: i for i, ch in enumerate(ac)}
            truth = ([ipp[STD[i]] for i in range(26)] + [ipc[STD[i]] for i in range(26)]
                     + list(key))
            ok = sp is not None and sp.contains(truth)
            if ok:
                ok = injective_point_report(
                    sp, [list(range(26)), list(range(26, 52))]).decision is True
            passed += ok
            if not ok:
                failures.append(f"q4 {variant} P={P}")

    if verbose:
        print(f"[control 1] positive controls: {passed}/{total} pass")
        for f in failures:
            print(f"            FAIL {f}")
    return passed, total, failures


# --------------------------------------------------------------- 2. real-data control

def _affine_of_kry(pi_vals) -> tuple[int, int] | None:
    """Is the recovered alphabet an affine image  a * idx_KRY + t  of KRYPTOS?
    a=1 is the pure gauge shift; other units are the global-scalar symmetry of
    the homogeneous system."""
    for a in UNITS:
        for t in range(26):
            if all(pi_vals[ord(L) - 65] == (a * KRY_IDX[L] + t) % 26 for L in STD):
                return a, t
    return None


def real_data_control(verbose: bool = True):
    """MANDATORY CONTROL 2.  K1 (Quagmire III, PALIMPSEST, period 10) and K2
    (ABSCISSA, period 8) must be RECOVERED: the KRYPTOS alphabet with the true
    keyword must lie in the solution space, the gauge translate must lie there
    too, injectivity must be True, and -- the strong form -- EVERY injective
    point of the space must be an affine image of the KRYPTOS alphabet, i.e. the
    alphabet is recovered exactly up to the gauge/scalar symmetry.  We also
    require power (only multiples of the true period survive) and a matched
    shuffled-CT null.
    """
    import compute as C
    from test_crib_filter_real_panels import K2_CT

    panels = [("K1", C.K1_CT, C.K1_PT, "PALIMPSEST", 10),
              ("K2", K2_CT, C.K2_PT, "ABSCISSA", 8)]
    out = {}
    all_ok = True
    for name, ct, pt, kw, period in panels:
        m = min(len(ct), len(pt))
        cribs = {i: pt[i] for i in range(m)}
        rows, rhs, n = q3_system(ct[:m], cribs, period, "vig")
        sp = solve_z26(rows, rhs, n)
        truth = [KRY_IDX[STD[i]] for i in range(26)] + [KRY_IDX[kw[r]] for r in range(period)]
        contains_truth = sp is not None and sp.contains(truth)
        contains_gauge = sp is not None and sp.contains(gauge_shift(truth, 7, period, "vig"))
        rep = injective_point_report(sp, list(range(26)))
        witness_perm = rep.witness is not None and len(set(rep.witness[:26])) == 26
        wit_aff = _affine_of_kry(rep.witness[:26]) if witness_perm else None

        # strong recovery: enumerate the whole space when it is small enough and
        # check every injective point is an affine image of KRYPTOS
        strong = None
        if sp.size <= 200_000:
            bad = 0
            n_inj = 0
            for c2 in itertools.product(range(2), repeat=sp.dim2):
                for c13 in itertools.product(range(13), repeat=sp.dim13):
                    x = sp.point(c2, c13)
                    if len(set(x[:26])) == 26:
                        n_inj += 1
                        if _affine_of_kry(x[:26]) is None:
                            bad += 1
            strong = {"injective_points": n_inj, "not_affine_images_of_KRYPTOS": bad}

        # power: which periods 1..20 survive
        surviving = []
        for p in range(1, 21):
            if evaluate(ct[:m], cribs, p, "vig").decision is not False:
                surviving.append(p)
        expected = [p for p in range(1, 21) if p % period == 0]

        # matched null on this control
        rng = random.Random(7)
        shuffled_survive = 0
        trials = 100
        for _ in range(trials):
            lst = list(ct[:m])
            rng.shuffle(lst)
            if evaluate("".join(lst), cribs, period, "vig").decision is True:
                shuffled_survive += 1

        ok = (contains_truth and contains_gauge and rep.decision is True and witness_perm
              and wit_aff is not None and surviving == expected
              and (strong is None or strong["not_affine_images_of_KRYPTOS"] == 0))
        all_ok &= ok
        out[name] = {
            "keyword": kw, "period": period, "chars": m,
            "space": sp.describe(), "contains_truth": contains_truth,
            "contains_gauge_translate": contains_gauge,
            "injective": rep.decision, "witness_is_permutation": witness_perm,
            "witness_affine_a_t": wit_aff, "strong_recovery": strong,
            "surviving_periods_1_20": surviving, "expected_multiples": expected,
            "shuffled_ct_survival": f"{shuffled_survive}/{trials}",
            "PASS": ok,
        }
        if verbose:
            print(f"[control 2] {name}: kw={kw} P={period}  {sp.describe()}")
            print(f"            truth in space={contains_truth}  gauge in space={contains_gauge}"
                  f"  injective={rep.decision}  witness=affine{wit_aff} of KRYPTOS")
            if strong is not None:
                print(f"            strong recovery: {strong['injective_points']} injective points "
                      f"in the space, {strong['not_affine_images_of_KRYPTOS']} of them NOT "
                      f"affine images of KRYPTOS")
            print(f"            power: surviving periods {surviving} (expected {expected})")
            print(f"            matched null: shuffled CT survives {shuffled_survive}/{trials}")
            print(f"            -> {'PASS' if ok else 'FAIL'}")
    return all_ok, out


# --------------------------------------------------------------- 3. matched null

_NULL_CTX: dict = {}


def _null_init(cribs_by_level, max_period, ct):
    _NULL_CTX["cribs"] = cribs_by_level
    _NULL_CTX["max_period"] = max_period
    _NULL_CTX["ct"] = ct


def _null_trial(seed: int):
    """One shuffled-ciphertext replicate of the ENTIRE sweep procedure.

    The null shuffles the 97 carved letters (preserving the letter multiset) and
    re-runs exactly the same pipeline: all three variants, the same
    free-column reduction, the same injectivity decider, the same aggregation.
    No sampling shortcut -- if the real procedure searches, the null searches.
    """
    rng = random.Random(seed)
    lst = list(_NULL_CTX["ct"])
    rng.shuffle(lst)
    ct = "".join(lst)
    res = {}
    for lv, cribs in _NULL_CTX["cribs"].items():
        for P in range(1, _NULL_CTX["max_period"] + 1):
            decisions = [evaluate(ct, cribs, P, v, node_budget=50_000, restarts=2).decision
                         for v in VARIANTS]
            res[(lv, P)] = cell_status(decisions)
    return res


# --------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-period", type=int, default=30)
    ap.add_argument("--trials", type=int, default=300, help="shuffled-CT null replicates")
    ap.add_argument("--workers", type=int, default=0, help="0 = auto")
    ap.add_argument("--affinity", choices=["auto", "none", "pin"], default="none")
    ap.add_argument("--node-budget", type=int, default=200_000)
    ap.add_argument("--restarts", type=int, default=8)
    ap.add_argument("--skip-null", action="store_true")
    ap.add_argument("--benchmark", action="store_true", help="controls only, tiny null")
    ap.add_argument("--json", default=os.path.join(_ROOT, "results",
                                                   "quagmire3_exact_sweep.json"))
    args = ap.parse_args()

    if args.benchmark:
        args.trials, args.max_period = 10, 12

    try:
        avail = len(os.sched_getaffinity(0))
    except AttributeError:
        avail = os.cpu_count() or 1
    workers = args.workers or max(1, avail - 2)

    t0 = time.perf_counter()
    print("=" * 78)
    print("QUAGMIRE III EXACT CLOSURE SWEEP  --  free mixed alphabet, all 26! at once")
    print("=" * 78)
    print(f"CT: K4 carved 97 chars, direct alignment r = pos mod P (0-indexed)")
    print(f"periods 1..{args.max_period} x variants {VARIANTS} x levels {len(LEVELS)}")
    print(f"workers={workers} of {avail} logical CPUs; null trials={args.trials}\n")

    # ---- controls first; a failing control aborts the sweep
    p_pass, p_total, p_fail = positive_controls()
    print()
    rd_ok, rd = real_data_control()
    print()
    if not rd_ok:
        print("REAL-DATA CONTROL FAILED -- refusing to report a sweep.  "
              "The solver does not recover K1/K2 Quagmire III; no elimination below "
              "would be trustworthy.")
        return 2
    if p_pass != p_total:
        print("POSITIVE CONTROL FAILED (over-elimination) -- refusing to report a sweep.")
        return 2

    # ---- the sweep
    cribs_by_level = {lv: level(lv) for lv in LEVELS}
    sweep = {}
    print("[sweep] real K4")
    for lv in LEVELS:
        cribs = cribs_by_level[lv]
        row = []
        for P in range(1, args.max_period + 1):
            cells = {v: evaluate(K4_CT, cribs, P, v,
                                 node_budget=args.node_budget, restarts=args.restarts)
                     for v in VARIANTS}
            st = cell_status([c.decision for c in cells.values()])
            sweep[(lv, P)] = {
                "status": st,
                "per_variant": {v: c.decision for v, c in cells.items()},
                "reason": {v: c.reason for v, c in cells.items()},
                "dim2": cells["vig"].dim2, "dim13": cells["vig"].dim13,
                "n_slots": cells["vig"].n_slots,
            }
            row.append({"contradicted": ".", "consistent": "O", "inconclusive": "?"}[st])
        surv = [P for P in range(1, args.max_period + 1)
                if sweep[(lv, P)]["status"] != "contradicted"]
        print(f"  {lv:<18} n_cribs={len(cribs):>2}  {''.join(row)}   surviving: {surv or 'NONE'}")
    print("  legend: '.' contradicted (all 3 variants)  'O' consistent  '?' inconclusive\n")

    # ---- matched null
    null_counts = {k: 0 for k in sweep}
    if args.skip_null:
        print("[null] SKIPPED (--skip-null): no cell may be interpreted without it")
        ntrials = 0
    else:
        ntrials = args.trials
        print(f"[null] matched shuffled-CT null: {ntrials} replicates of the full "
              f"procedure on {workers} workers")
        import multiprocessing as mp
        ctx = mp.get_context("fork")
        with ctx.Pool(workers, initializer=_null_init,
                      initargs=(cribs_by_level, args.max_period, K4_CT)) as pool:
            for res in pool.imap_unordered(_null_trial, range(ntrials), chunksize=4):
                for k, st in res.items():
                    if st != "contradicted":
                        null_counts[k] += 1
        for lv in LEVELS:
            row = "".join(
                ("%X" % min(15, round(15 * null_counts[(lv, P)] / max(1, ntrials))))
                for P in range(1, args.max_period + 1))
            print(f"  {lv:<18} null survival (0=never .. F=always): {row}")
        print()

    # ---- saturation
    print("[saturation]")
    sat = {}
    for lv in LEVELS:
        pos = sorted(cribs_by_level[lv])
        N = len(pos)
        naive = max(1, N - 26 + 1)          # 26 + P unknowns > N equations
        collide_free = None
        for P in range(1, 200):
            if len({p % P for p in pos}) == len(pos):
                collide_free = P
                break
        sat[lv] = {"n_cribs": N, "naive_unknowns_exceed_equations_at": naive,
                   "collision_free_period": collide_free}
        print(f"  {lv:<18} N={N:>2}  naive 26+P>N at P={naive:<3} "
              f"collision-free (every crib its own key slot) at P={collide_free}")
    print()

    # ---- assemble
    by_period = []
    for lv in LEVELS:
        for P in range(1, args.max_period + 1):
            c = sweep[(lv, P)]
            by_period.append({
                "level": lv, "period": P, "status": c["status"],
                "injective_ok": c["status"] == "consistent",
                "shuffled_null_rate": (round(null_counts[(lv, P)] / ntrials, 4)
                                       if ntrials else None),
                "solution_dim": c["dim2"] + c["dim13"],
                "per_variant": c["per_variant"],
                "constrained_slots": c["n_slots"],
            })

    payload = {
        "script": os.path.abspath(__file__),
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "variant_family": ("Quagmire III, one shared free mixed alphabet (all 26! at once), "
                           "periodic additive key, direct alignment r = pos mod P, "
                           "variants vigenere / beaufort / variant-beaufort"),
        "max_period": args.max_period,
        "null_trials": ntrials,
        "positive_controls": {"pass": p_pass, "total": p_total, "failures": p_fail},
        "real_data_control": rd,
        "saturation": sat,
        "by_period": by_period,
        "runtime_s": round(time.perf_counter() - t0, 1),
    }
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w") as fh:
        json.dump(payload, fh, indent=1)
    print(f"wrote {args.json}   ({payload['runtime_s']}s)")

    # ---- surviving cells, with their null
    print("\n[surviving cells]  status != contradicted; null = shuffled-CT survival rate")
    any_surv = False
    for e in by_period:
        if e["status"] != "contradicted":
            any_surv = True
            print(f"  {e['level']:<18} P={e['period']:>2}  {e['status']:<13} "
                  f"variants={e['per_variant']}  null={e['shuffled_null_rate']}")
    if not any_surv:
        print("  none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
