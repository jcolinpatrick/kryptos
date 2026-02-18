#!/usr/bin/env python3
"""E-S-02: Stride-based transposition sweep.

Since 97 is prime, every stride s (1 ≤ s ≤ 96) generates a valid
permutation of all 97 positions: perm[i] = (start + s*i) % 97.

This covers 96 strides × 97 starting positions = 9,312 distinct
transpositions — none of which are columnar.

Motivation:
  - S = 19 in A=1 numbering; gcd(19, 97) = 1 since 97 is prime
  - Stride-19 through 97 chars visits every position exactly once
  - The S-shape of the sculpture may encode a stride/step instruction
  - KRYPTOS = 7 letters → stride 7 also valid and thematically motivated

For each (stride, start):
  1. Build permutation: perm[i] = (start + stride*i) % 97
  2. Un-transpose CT to get intermediate text
  3. Check crib positions under Vig/Beaufort/VarBeau (AZ + KRYPTOS alphabets)
  4. Check Bean equality and period consistency

Also tests compound strides:
  - Two sequential strides (e.g., stride-7 then stride-19)
  - Stride with additive offset per row (if we lay text in a grid)
"""
import sys
import os
import json
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)

# ── Constants ─────────────────────────────────────────────────────────
CT_NUM = [ord(c) - 65 for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = [ord(CRIB_DICT[p]) - 65 for p in CRIB_POS]
N = CT_LEN  # 97

# Alphabet maps
AZ_MAP = list(range(26))
KA_MAP = [0] * 26
for _i, _c in enumerate(KRYPTOS_ALPHABET):
    KA_MAP[ord(_c) - 65] = _i

BEAN_A, BEAN_B = 27, 65  # crib positions for Bean equality
PERIODS = list(range(2, 15))
VARIANT_NAMES = ['vig', 'beau', 'varbeau']

# ── Precompute group indices for ST model ─────────────────────────────
ST_GRPS = {}
for _p in PERIODS:
    groups = defaultdict(list)
    for _j, _pos in enumerate(CRIB_POS):
        groups[_pos % _p].append(_j)
    ST_GRPS[_p] = [list(g) for g in groups.values()]


def expected_random(grp_indices):
    """Approximate expected random consistency."""
    e = 0.0
    for g in grp_indices:
        n = len(g)
        e += 1.0 + n * (n - 1) / (2 * MOD)
    return e


# Precompute expected randoms for ST model
ST_EXP = {p: expected_random(ST_GRPS[p]) for p in PERIODS}


def fast_score(kvs, grp_indices):
    """Period consistency score using precomputed groups."""
    s = 0
    for indices in grp_indices:
        cnts = [0] * 26
        mx = 0
        for j in indices:
            v = kvs[j]
            cnts[v] += 1
            if cnts[v] > mx:
                mx = cnts[v]
        s += mx
    return s


# ── Stride permutation ────────────────────────────────────────────────

def stride_perm(stride, start, length=N):
    """Build stride permutation: perm[i] = (start + stride*i) % length."""
    return [(start + stride * i) % length for i in range(length)]


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── Phase 1: Single stride sweep ──────────────────────────────────────

def sweep_single_strides():
    """Test all 96 strides × 97 starts × 3 variants × 2 alphabets."""
    print(f"\n{'=' * 72}")
    print("PHASE 1: Single Stride Sweep")
    print(f"{'=' * 72}")
    print(f"Strides: 1-96, Starts: 0-96 = {96 * 97} permutations")
    print(f"× 3 variants × 2 alphabets × {len(PERIODS)} periods")

    best = 0
    best_cfg = None
    signals = []
    bean_ct = 0
    total = 0
    t0 = time.time()

    for stride in range(1, N):
        for start in range(N):
            perm = stride_perm(stride, start)
            inv = invert_perm(perm)
            total += 1

            # Un-transpose: intermediate[j] = CT[inv[j]]
            # Check Bean: intermediate[BEAN_A] == intermediate[BEAN_B]?
            # No — Bean checks KEY equality, not CT equality.
            # For ST model: K[c] = Recover(CT[inv[c]], PT[c])
            # Bean: K[BEAN_A] == K[BEAN_B]
            # Since PT[27]='R' and PT[65]='R', Bean holds iff
            # CT[inv[27]] == CT[inv[65]] (for any variant)
            if CT_NUM[inv[BEAN_A]] != CT_NUM[inv[BEAN_B]]:
                continue
            bean_ct += 1

            # Extract CT values at un-transposed crib positions
            raw = [CT_NUM[inv[c]] for c in CRIB_POS]

            for ai, amap in enumerate([AZ_MAP, KA_MAP]):
                for vi in range(3):
                    kvs = [0] * N_CRIBS
                    for j in range(N_CRIBS):
                        cv = amap[raw[j]]
                        pv = amap[CRIB_PT[j]]
                        if vi == 0:
                            kvs[j] = (cv - pv) % MOD
                        elif vi == 1:
                            kvs[j] = (cv + pv) % MOD
                        else:
                            kvs[j] = (pv - cv) % MOD

                    for p in PERIODS:
                        sc = fast_score(kvs, ST_GRPS[p])
                        if sc > best:
                            best = sc
                            best_cfg = dict(
                                stride=stride, start=start,
                                var=VARIANT_NAMES[vi],
                                alph=['AZ', 'KA'][ai],
                                period=p, score=sc,
                            )
                        if sc >= SIGNAL_THRESHOLD:
                            er = ST_EXP[p]
                            signals.append(dict(
                                stride=stride, start=start,
                                var=VARIANT_NAMES[vi],
                                alph=['AZ', 'KA'][ai],
                                period=p, score=sc,
                                expected_random=round(er, 1),
                                excess=round(sc - er, 1),
                            ))

        if stride % 20 == 0:
            el = time.time() - t0
            print(f"  Stride {stride}/96, best={best}/24, bean={bean_ct}, {el:.1f}s")

    el = time.time() - t0
    print(f"\n  Total: {total}, Bean passes: {bean_ct} ({100*bean_ct/max(total,1):.1f}%)")
    print(f"  Best: {best}/24, Signals≥{SIGNAL_THRESHOLD}: {len(signals)}")
    print(f"  Elapsed: {el:.1f}s")
    if best_cfg:
        print(f"  Best config: {best_cfg}")

    return best, best_cfg, signals, el


# ── Phase 2: Compound strides (two sequential) ───────────────────────

def sweep_compound_strides():
    """Test compound transpositions: stride-a then stride-b.

    Focused on thematically motivated strides: 7, 19, and their neighbors.
    """
    print(f"\n{'=' * 72}")
    print("PHASE 2: Compound Strides (stride-a then stride-b)")
    print(f"{'=' * 72}")

    # Priority strides: 7 (KRYPTOS), 19 (S=19), plus small primes
    priority_strides = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    print(f"Testing {len(priority_strides)}² = {len(priority_strides)**2} "
          f"stride pairs × 97 starts")

    best = 0
    best_cfg = None
    signals = []
    bean_ct = 0
    total = 0
    t0 = time.time()

    for s1 in priority_strides:
        for s2 in priority_strides:
            # Compound: apply stride-s1 then stride-s2
            # Equivalent to single stride with step = (s1 * s2) % 97
            # But with different starting positions
            compound_stride = (s1 * s2) % N
            if compound_stride == 0:
                continue  # degenerate

            for start in range(N):
                perm = stride_perm(compound_stride, start)
                inv = invert_perm(perm)
                total += 1

                if CT_NUM[inv[BEAN_A]] != CT_NUM[inv[BEAN_B]]:
                    continue
                bean_ct += 1

                raw = [CT_NUM[inv[c]] for c in CRIB_POS]

                for ai, amap in enumerate([AZ_MAP, KA_MAP]):
                    for vi in range(3):
                        kvs = [0] * N_CRIBS
                        for j in range(N_CRIBS):
                            cv = amap[raw[j]]
                            pv = amap[CRIB_PT[j]]
                            if vi == 0:
                                kvs[j] = (cv - pv) % MOD
                            elif vi == 1:
                                kvs[j] = (cv + pv) % MOD
                            else:
                                kvs[j] = (pv - cv) % MOD

                        for p in PERIODS:
                            sc = fast_score(kvs, ST_GRPS[p])
                            if sc > best:
                                best = sc
                                best_cfg = dict(
                                    s1=s1, s2=s2,
                                    compound=(s1 * s2) % N,
                                    start=start,
                                    var=VARIANT_NAMES[vi],
                                    alph=['AZ', 'KA'][ai],
                                    period=p, score=sc,
                                )
                            if sc >= SIGNAL_THRESHOLD:
                                er = ST_EXP[p]
                                signals.append(dict(
                                    s1=s1, s2=s2,
                                    compound=(s1 * s2) % N,
                                    start=start,
                                    var=VARIANT_NAMES[vi],
                                    alph=['AZ', 'KA'][ai],
                                    period=p, score=sc,
                                    expected_random=round(er, 1),
                                    excess=round(sc - er, 1),
                                ))

    el = time.time() - t0
    print(f"\n  Total: {total}, Bean: {bean_ct}")
    print(f"  Best: {best}/24, Signals: {len(signals)}")
    print(f"  Elapsed: {el:.1f}s")
    if best_cfg:
        print(f"  Best config: {best_cfg}")

    return best, best_cfg, signals, el


# ── Phase 3: Stride + missing character ───────────────────────────────

def sweep_stride_plus_insertion():
    """Test stride transposition on 98-char CT (with S inserted).

    Only tests S insertion (the primary hypothesis) at all 98 positions.
    For a 98-char text, strides coprime with 98 generate full permutations.
    98 = 2 × 7 × 7. Coprime strides: odd numbers not divisible by 7.
    """
    print(f"\n{'=' * 72}")
    print("PHASE 3: Stride + Missing 'S' (98-char CT)")
    print(f"{'=' * 72}")

    S_VAL = ord('S') - 65
    TARGET_LEN = 98

    # Valid strides: coprime with 98
    valid_strides = [s for s in range(1, TARGET_LEN) if gcd(s, TARGET_LEN) == 1]
    print(f"Valid strides (coprime with 98): {len(valid_strides)}")
    print(f"× 98 insertion positions × 98 starts × 3 var × 2 alph")

    best = 0
    best_cfg = None
    signals = []
    bean_ct = 0
    total = 0
    t0 = time.time()

    for ip in range(TARGET_LEN):
        ct98 = list(CT_NUM)
        ct98.insert(ip, S_VAL)

        for stride in valid_strides:
            for start in range(TARGET_LEN):
                perm = [(start + stride * i) % TARGET_LEN
                        for i in range(TARGET_LEN)]
                inv = [0] * TARGET_LEN
                for i, p in enumerate(perm):
                    inv[p] = i
                total += 1

                # Bean check
                if BEAN_A >= TARGET_LEN or BEAN_B >= TARGET_LEN:
                    continue
                if ct98[inv[BEAN_A]] != ct98[inv[BEAN_B]]:
                    continue
                bean_ct += 1

                raw = []
                ok = True
                for c in CRIB_POS:
                    if c >= TARGET_LEN or inv[c] >= TARGET_LEN:
                        ok = False
                        break
                    raw.append(ct98[inv[c]])
                if not ok or len(raw) != N_CRIBS:
                    continue

                for ai, amap in enumerate([AZ_MAP, KA_MAP]):
                    for vi in range(3):
                        kvs = [0] * N_CRIBS
                        for j in range(N_CRIBS):
                            cv = amap[raw[j]]
                            pv = amap[CRIB_PT[j]]
                            if vi == 0:
                                kvs[j] = (cv - pv) % MOD
                            elif vi == 1:
                                kvs[j] = (cv + pv) % MOD
                            else:
                                kvs[j] = (pv - cv) % MOD

                        for p in PERIODS:
                            sc = fast_score(kvs, ST_GRPS[p])
                            if sc > best:
                                best = sc
                                best_cfg = dict(
                                    insert_pos=ip, stride=stride,
                                    start=start,
                                    var=VARIANT_NAMES[vi],
                                    alph=['AZ', 'KA'][ai],
                                    period=p, score=sc,
                                )
                            if sc >= SIGNAL_THRESHOLD:
                                er = ST_EXP[p]
                                signals.append(dict(
                                    insert_pos=ip, stride=stride,
                                    start=start,
                                    var=VARIANT_NAMES[vi],
                                    alph=['AZ', 'KA'][ai],
                                    period=p, score=sc,
                                    expected_random=round(er, 1),
                                ))

        if (ip + 1) % 20 == 0:
            el = time.time() - t0
            rate = (ip + 1) / el if el > 0 else 1
            eta = (TARGET_LEN - ip - 1) / rate
            print(f"  Insert {ip + 1}/{TARGET_LEN}, best={best}/24, "
                  f"bean={bean_ct}, {el:.0f}s ETA={eta:.0f}s")

    el = time.time() - t0
    print(f"\n  Total: {total:,}, Bean: {bean_ct:,}")
    print(f"  Best: {best}/24, Signals: {len(signals)}")
    print(f"  Elapsed: {el:.1f}s")
    if best_cfg:
        print(f"  Best config: {best_cfg}")

    return best, best_cfg, signals, el


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("E-S-02: Stride-Based Transposition Sweep")
    print(f"CT: {CT} (len={CT_LEN}, prime={CT_LEN})")
    print(f"Note: 97 is prime → every stride 1-96 generates a full permutation")

    # Show expected random baselines
    print("\nExpected random consistency (ST model):")
    for p in [4, 5, 6, 7, 8, 10, 14]:
        print(f"  Period {p:2d}: {ST_EXP[p]:.1f}/24")

    # Highlight special strides
    print(f"\nSpecial strides:")
    print(f"  S=19 (A=1 numbering)")
    print(f"  7 (KRYPTOS length)")
    print(f"  19×7=133≡36 mod 97 (compound)")

    t_start = time.time()

    # Phase 1: All single strides
    p1_best, p1_cfg, p1_sigs, p1_t = sweep_single_strides()

    # Phase 2: Compound strides
    p2_best, p2_cfg, p2_sigs, p2_t = sweep_compound_strides()

    # Phase 3: Stride + missing S (expensive — only if Phases 1-2 show promise)
    if max(p1_best, p2_best) >= STORE_THRESHOLD + 2:
        p3_best, p3_cfg, p3_sigs, p3_t = sweep_stride_plus_insertion()
    else:
        print(f"\nSkipping Phase 3 (stride + insertion): "
              f"Phases 1-2 best = {max(p1_best, p2_best)}/24 < {STORE_THRESHOLD + 2}")
        p3_best, p3_cfg, p3_sigs, p3_t = 0, None, [], 0.0

    overall = max(p1_best, p2_best, p3_best)
    all_sigs = p1_sigs + p2_sigs + p3_sigs
    total_t = time.time() - t_start

    # Summary
    print(f"\n{'=' * 72}")
    print("FINAL SUMMARY")
    print(f"{'=' * 72}")
    print(f"Phase 1 (single strides): best={p1_best}/24, signals={len(p1_sigs)}, "
          f"time={p1_t:.1f}s")
    print(f"Phase 2 (compound strides): best={p2_best}/24, signals={len(p2_sigs)}, "
          f"time={p2_t:.1f}s")
    print(f"Phase 3 (stride + S insertion): best={p3_best}/24, signals={len(p3_sigs)}, "
          f"time={p3_t:.1f}s")
    print(f"Overall best: {overall}/24")
    print(f"Total time: {total_t:.1f}s")

    if all_sigs:
        meaningful = [s for s in all_sigs if s.get('excess', s['score'] - s['expected_random']) > 6]
        print(f"\nSignals: {len(all_sigs)} total, {len(meaningful)} meaningful (excess > 6)")
        if meaningful:
            print("Top meaningful:")
            for s in sorted(meaningful, key=lambda x: -x['score'])[:10]:
                print(f"  {s}")
    else:
        print(f"\nNo signals ≥ {SIGNAL_THRESHOLD}")

    if overall <= NOISE_FLOOR:
        print("\nCONCLUSION: Stride-based transposition + periodic sub ELIMINATED")
    elif overall >= BREAKTHROUGH_THRESHOLD:
        print(f"\nBREAKTHROUGH at {overall}/24!")
    else:
        n_m = len([s for s in all_sigs if s.get('excess', 0) > 6])
        if n_m == 0 and all_sigs:
            print(f"\nAll {len(all_sigs)} signals are underdetermination artifacts")
            print("ELIMINATED: Stride transposition + periodic sub (all strides)")
        elif n_m > 0:
            print(f"\n{n_m} meaningful signals — investigate further")

    # Save
    summary = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_seconds': total_t,
        'phase1_best': p1_best,
        'phase1_signals': len(p1_sigs),
        'phase2_best': p2_best,
        'phase2_signals': len(p2_sigs),
        'phase3_best': p3_best,
        'phase3_signals': len(p3_sigs),
        'overall_best': overall,
        'top_signals': sorted(all_sigs, key=lambda x: -x['score'])[:50],
    }
    out = os.path.join(os.path.dirname(__file__), '..', 'results',
                       'e_s_02_stride_transposition.json')
    with open(out, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved to {out}")
