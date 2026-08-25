#!/usr/bin/env python3
"""
e_crib_33_verify_exact_closures
===============================

FAMILY: crib_analysis
STATUS: active

POSITIVE CONTROLS for scripts/k4_exact_closures.py (contributed externally,
2026-08-25), which replaces keyword enumeration with exact linear closure over
Z_26 and therefore emits ELIMINATIONS rather than counts.

An elimination script fails dangerously in one direction only: over-elimination.
A bug that reports "contradicted" for a family that in fact admits a solution
would silently close live search space. Reproducing the script's own numbers
(which I did) does not test for that. Only a positive control does.

METHOD: synthesise a ciphertext from a KNOWN configuration of each family, install
it in place of K4, and require the test to report that configuration as surviving.
If any control fails, the corresponding closure must not be trusted.
"""
from __future__ import annotations

import importlib.util
import os
import random
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

_spec = importlib.util.spec_from_file_location(
    "k4x", os.path.join(_ROOT, "scripts", "k4_exact_closures.py"))
K4X = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(K4X)

STD, KRY = K4X.STD, K4X.KRY
WORDS = K4X.WORDS


def install(ct: str):
    K4X.CT = ct


def synth_single(kp, period, key, ap, ac, mode, base):
    ct = list(base)
    for pos, pl in kp.items():
        p = ap.index(pl)
        k = key[pos % period]
        c = (p + k) % 26 if mode == "vig" else (k - p) % 26
        ct[pos - 1] = ac[c]
    return "".join(ct)


def synth_twokey(kp, P, Q, a, b, ap, ac, mode, base):
    ct = list(base)
    sign = 1 if mode == "vig" else -1
    for pos, pl in kp.items():
        k = (a[pos % P] + b[pos % Q]) % 26
        ct[pos - 1] = ac[(sign * ap.index(pl) + k) % 26]
    return "".join(ct)


def synth_quagmire(kp, period, key, pi, variant, mode, base):
    """Q1: idx(c) = pi(p) + k      Q2: pi(c) = idx(p) + k     (beau negates the idx side)"""
    ct = list(base)
    inv = {v: i for i, v in enumerate(pi)}          # inv[value] -> letter index
    for pos, pl in kp.items():
        r = pos % period
        if variant == "Q1":
            val = (pi[STD.index(pl)] + key[r]) % 26
            ct[pos - 1] = STD[val if mode == "vig" else (-val) % 26]
        else:
            e = STD.index(pl) if mode == "vig" else (-STD.index(pl)) % 26
            ct[pos - 1] = STD[inv[(e + key[r]) % 26]]
    return "".join(ct)


def main() -> int:
    rng = random.Random(20260825)
    base = K4X.CT
    kp = K4X.known_positions()
    fails = []
    print("=" * 84)
    print("POSITIVE CONTROLS FOR k4_exact_closures.py")
    print("=" * 84)

    print("\n[1] single additive periodic key — true period must survive")
    for name, (ap, ac, mode) in K4X.FOUR.items():
        for period in (5, 8, 11, 17, 23):
            key = [rng.randrange(26) for _ in range(period)]
            install(synth_single(kp, period, key, ap, ac, mode, base))
            alive = K4X.test_single_period(kp, max_period=30)[name]
            ok = period in alive
            if not ok:
                fails.append(f"[1] {name} p={period}")
            print(f"    {name}  p={period:>2}  true period recovered: {ok}"
                  f"   (survivors <=30: {[x for x in alive if x<=30][:8]})")
    install(base)

    print("\n[2] word tiling — true period must survive when words sit at their real offsets")
    for name, (ap, ac, mode) in list(K4X.EIGHT.items())[:4]:
        for period in (7, 13, 19):
            key = [rng.randrange(26) for _ in range(period)]
            install(synth_single(kp, period, key, ap, ac, mode, base))
            alive = K4X.test_word_tiling(max_period=23)[name]
            ok = period in alive
            if not ok:
                fails.append(f"[2] {name} p={period}")
            print(f"    {name:<13} p={period:>2}  recovered: {ok}   survivors: {alive}")
    install(base)

    print("\n[3] two additive layers — true (P,Q) must be feasible")
    for name, (ap, ac, mode) in K4X.FOUR.items():
        for (P, Q) in ((5, 7), (9, 16), (4, 11)):
            a = [rng.randrange(26) for _ in range(P)]
            b = [rng.randrange(26) for _ in range(Q)]
            install(synth_twokey(kp, P, Q, a, b, ap, ac, mode, base))
            feas = K4X.test_two_keys(kp, max_period=max(Q, 17))[name]
            ok = (P, Q) in feas
            if not ok:
                fails.append(f"[3] {name} ({P},{Q})")
            print(f"    {name}  (P,Q)=({P},{Q})  feasible: {ok}   total feasible: {len(feas)}")
    install(base)

    print("\n[4] Quagmire I/II, free mixed alphabet — true period must survive")
    for variant in ("Q1", "Q2"):
        for mode in ("vig", "beau"):
            for period in (5, 9, 14, 17):
                pi = list(range(26))
                rng.shuffle(pi)
                key = [rng.randrange(26) for _ in range(period)]
                install(synth_quagmire(kp, period, key, pi, variant, mode, base))
                st = K4X.quagmire_status(kp, period, variant, mode)
                ok = st != "contradicted"
                if not ok:
                    fails.append(f"[4] {variant} {mode} p={period}")
                print(f"    {variant} {mode:<5} p={period:>2}  status: {st}")
    install(base)

    print("\n" + "=" * 84)
    if fails:
        print(f"FAILED CONTROLS ({len(fails)}) — the corresponding closures are NOT trustworthy:")
        for f in fails:
            print("   ", f)
        return 1
    print("ALL POSITIVE CONTROLS PASSED.")
    print("Every synthesised true configuration was reported as surviving, so the")
    print("script does not over-eliminate on these families. Its contradictions can")
    print("be read as sound eliminations within the stated conventions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
