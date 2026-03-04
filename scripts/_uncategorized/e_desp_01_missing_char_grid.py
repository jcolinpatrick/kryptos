#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-DESP-01: Missing character + 7×14 transposition grid.

Hypothesis: K4's true CT is 98 characters (= 7 × 14). One character was
omitted during engraving (following the DESPARATLY omission pattern from K3).
When the correct letter is inserted at the correct position, the 98-char text
fits a 7×14 grid and the interval-7 transposition + substitution resolves.

Five converging evidence lines:
  1. DESPARATLY: only K-section misspelling that omits a character
  2. Sanborn uniquely evasive about DESPARATLY
  3. K2 precedent: missing S changed entire K2 ending
  4. NSA analyst independently raised missing-char hypothesis
  5. 98 = 7 × 14: explains lag-7 autocorrelation (z=3.036)

Cipher model tested:
  ST (Substitute-then-Transpose): CT = Transpose(Vigenere(PT, K))
  TS (Transpose-then-Substitute): CT = Vigenere(Transpose(PT), K)

For ST: un-transpose CT, then check key periodicity at crib positions.
For TS: key applies at transposed positions; check periodicity there.

Bean check (model-independent): CT[inv_perm[27]] == CT[inv_perm[65]]

Phase 1: E and S only (196 candidates)
Phase 2: All 26 letters (2,548 candidates)
"""
import sys
import os
import json
import time
from itertools import permutations
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
CRIB_PT = [ord(CRIB_DICT[p]) - 65 for p in CRIB_POS]  # parallel array

# Alphabet maps: standard_value → alphabet_index
AZ_MAP = list(range(26))
KA_MAP = [0] * 26
for _i, _c in enumerate(KRYPTOS_ALPHABET):
    KA_MAP[ord(_c) - 65] = _i

BEAN_A, BEAN_B = 27, 65  # plaintext positions for Bean equality
WIDTH, ROWS, GRID_LEN = 7, 14, 98
PERIODS = list(range(2, 15))
VARIANT_NAMES = ['vig', 'beau', 'varbeau']

# ── Permutation helpers ───────────────────────────────────────────────

def build_col_perm(col_order, btt=False):
    """7×14 columnar transposition permutation (gather convention)."""
    cols = [[] for _ in range(WIDTH)]
    for pos in range(GRID_LEN):
        cols[pos % WIDTH].append(pos)
    if btt:
        cols = [c[::-1] for c in cols]
    perm = []
    for rank in range(WIDTH):
        ci = list(col_order).index(rank)
        perm.extend(cols[ci])
    return perm


def invert(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── Precompute ────────────────────────────────────────────────────────

def make_groups(positions, period):
    """Group indices by position mod period."""
    groups = defaultdict(list)
    for j, pos in enumerate(positions):
        groups[pos % period].append(j)
    return [g for g in groups.values()]


def precompute():
    """Precompute all 10,080 permutations with group indices."""
    # ST groups are fixed (crib positions don't change)
    st_grps = {p: make_groups(CRIB_POS, p) for p in PERIODS}

    perms = []
    for co in permutations(range(WIDTH)):
        for btt in [False, True]:
            perm = build_col_perm(co, btt)
            inv = invert(perm)
            crib_ct = [inv[c] for c in CRIB_POS]
            ts_grps = {p: make_groups(crib_ct, p) for p in PERIODS}
            perms.append((
                co, btt, inv,
                inv[BEAN_A], inv[BEAN_B],
                crib_ct,
                ts_grps,
            ))
    return perms, st_grps


# ── Scoring ───────────────────────────────────────────────────────────

def fast_score(kvs, grp_indices):
    """Score using precomputed group indices. kvs is a list of key values."""
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


def expected_random(grp_indices):
    """Approximate expected random consistency from group sizes."""
    e = 0.0
    for g in grp_indices:
        n = len(g)
        e += 1.0 + n * (n - 1) / (2 * MOD)
    return e


# ── Main sweep ────────────────────────────────────────────────────────

def sweep(letter_vals, label, all_perms, st_grps):
    print(f"\n{'=' * 72}")
    print(label)
    print(f"{'=' * 72}")
    n_letters = len(letter_vals)
    n_total = n_letters * 98
    print(f"Candidates: {n_letters} letters × 98 positions = {n_total}")
    print(f"Per candidate: {len(all_perms)} perms × 3 var × 2 alph × 2 models × {len(PERIODS)} periods")

    best = 0
    best_cfg = None
    signals = []
    bean_ct = 0
    checks = 0
    t0 = time.time()

    for li, lv in enumerate(letter_vals):
        lc = chr(lv + 65)
        for ip in range(98):
            ct98 = list(CT_NUM)
            ct98.insert(ip, lv)

            for co, btt, inv, ba, bb, crib_ct, ts_grps in all_perms:
                checks += 1
                # Fast Bean check
                if ct98[ba] != ct98[bb]:
                    continue
                bean_ct += 1

                # Extract CT values at un-transposed crib positions
                raw = [ct98[p] for p in crib_ct]

                for ai, amap in enumerate([AZ_MAP, KA_MAP]):
                    for vi in range(3):
                        # Compute key values
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

                        # ST model
                        for p in PERIODS:
                            sc = fast_score(kvs, st_grps[p])
                            if sc > best:
                                best = sc
                                best_cfg = dict(
                                    letter=lc, pos=ip, col=list(co),
                                    btt=btt, var=VARIANT_NAMES[vi],
                                    alph=['AZ', 'KA'][ai], model='ST',
                                    period=p, score=sc,
                                )
                            if sc >= SIGNAL_THRESHOLD:
                                er = expected_random(st_grps[p])
                                signals.append(dict(
                                    letter=lc, pos=ip, col=list(co),
                                    btt=btt, var=VARIANT_NAMES[vi],
                                    alph=['AZ', 'KA'][ai], model='ST',
                                    period=p, score=sc,
                                    expected_random=round(er, 1),
                                ))
                                if len(signals) <= 20:
                                    print(f"  *** [{sc}/24](exp={er:.1f}) ST p={p} "
                                          f"{VARIANT_NAMES[vi]} {'AZ' if ai==0 else 'KA'} "
                                          f"ins='{lc}'@{ip} col={list(co)} "
                                          f"{'↑' if btt else '↓'}")

                        # TS model
                        for p in PERIODS:
                            sc = fast_score(kvs, ts_grps[p])
                            if sc > best:
                                best = sc
                                best_cfg = dict(
                                    letter=lc, pos=ip, col=list(co),
                                    btt=btt, var=VARIANT_NAMES[vi],
                                    alph=['AZ', 'KA'][ai], model='TS',
                                    period=p, score=sc,
                                )
                            if sc >= SIGNAL_THRESHOLD:
                                er = expected_random(ts_grps[p])
                                signals.append(dict(
                                    letter=lc, pos=ip, col=list(co),
                                    btt=btt, var=VARIANT_NAMES[vi],
                                    alph=['AZ', 'KA'][ai], model='TS',
                                    period=p, score=sc,
                                    expected_random=round(er, 1),
                                ))
                                if len(signals) <= 20:
                                    print(f"  *** [{sc}/24](exp={er:.1f}) TS p={p} "
                                          f"{VARIANT_NAMES[vi]} {'AZ' if ai==0 else 'KA'} "
                                          f"ins='{lc}'@{ip} col={list(co)} "
                                          f"{'↑' if btt else '↓'}")

            done = li * 98 + ip + 1
            if done % 49 == 0:
                el = time.time() - t0
                rate = done / el if el > 0 else 1
                eta = (n_total - done) / rate
                print(f"  [{done}/{n_total}] best={best}/24 bean={bean_ct} "
                      f"{el:.0f}s ETA={eta:.0f}s")

    el = time.time() - t0
    print(f"\n  Checks: {checks:,}, Bean: {bean_ct:,} ({100*bean_ct/max(checks,1):.2f}%)")
    print(f"  Best: {best}/24, Signals≥{SIGNAL_THRESHOLD}: {len(signals)}")
    print(f"  Elapsed: {el:.1f}s")
    if best_cfg:
        print(f"  Best config: {best_cfg}")
    return best, best_cfg, signals, el


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("E-DESP-01: Missing Character + 7×14 Transposition Grid")
    print(f"CT: {CT} (len={CT_LEN})")
    print(f"Grid: {WIDTH}×{ROWS} = {GRID_LEN}")

    print(f"\nPrecomputing {5040 * 2} permutations + group indices...")
    t_pre = time.time()
    all_perms, st_grps = precompute()
    print(f"  Done in {time.time() - t_pre:.1f}s")

    # Expected random baselines (ST model)
    print("\nExpected random consistency (ST model, fixed crib positions):")
    for p in [4, 5, 6, 7, 8, 10, 14]:
        er = expected_random(st_grps[p])
        print(f"  Period {p:2d}: {er:.1f}/24")

    t_start = time.time()

    # Phase 1: E and S
    E_VAL = ord('E') - 65
    S_VAL = ord('S') - 65
    p1_best, p1_cfg, p1_sigs, p1_t = sweep(
        [E_VAL, S_VAL],
        "PHASE 1: E and S (DESPARATLY + K2 precedent)",
        all_perms, st_grps,
    )

    # Phase 2: All 26 letters (skip if breakthrough)
    if p1_best < BREAKTHROUGH_THRESHOLD:
        p2_best, p2_cfg, p2_sigs, p2_t = sweep(
            list(range(26)),
            "PHASE 2: All 26 letters",
            all_perms, st_grps,
        )
    else:
        p2_best, p2_cfg, p2_sigs, p2_t = p1_best, p1_cfg, p1_sigs, 0.0

    overall = max(p1_best, p2_best)
    all_sigs = p1_sigs + p2_sigs
    total_t = time.time() - t_start

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("FINAL SUMMARY")
    print(f"{'=' * 72}")
    print(f"Phase 1 (E,S): best={p1_best}/24, signals={len(p1_sigs)}, time={p1_t:.1f}s")
    print(f"Phase 2 (A-Z): best={p2_best}/24, signals={len(p2_sigs)}, time={p2_t:.1f}s")
    print(f"Overall best: {overall}/24")
    print(f"Total time: {total_t:.1f}s")

    # Classify signals
    if all_sigs:
        meaningful = [s for s in all_sigs
                      if s['score'] - s['expected_random'] > 6]
        artifact = [s for s in all_sigs
                    if s['score'] - s['expected_random'] <= 6]
        print(f"\nSignals: {len(all_sigs)} total")
        print(f"  Meaningful (excess > 6): {len(meaningful)}")
        print(f"  Artifacts (excess ≤ 6): {len(artifact)}")
        if meaningful:
            print("\nTop meaningful signals:")
            for s in sorted(meaningful, key=lambda x: -x['score'])[:10]:
                print(f"  [{s['score']}/24](exp={s['expected_random']}) "
                      f"{s['model']} p={s['period']} {s['var']} {s['alph']} "
                      f"ins='{s['letter']}'@{s['pos']} col={s['col']}")

    if overall <= NOISE_FLOOR:
        print("\nCONCLUSION: ELIMINATED — no signal above noise floor")
    elif overall >= BREAKTHROUGH_THRESHOLD:
        print(f"\nBREAKTHROUGH at {overall}/24!")
    else:
        n_meaningful = len([s for s in all_sigs
                           if s['score'] - s['expected_random'] > 6])
        if n_meaningful > 0:
            print(f"\nSIGNAL: {n_meaningful} meaningful hits above random expectation")
        else:
            print(f"\nAll {len(all_sigs)} signals are underdetermination artifacts")
            print("ELIMINATED: Missing char + 7×14 transposition + periodic sub")

    # Save
    summary = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_seconds': total_t,
        'phase1_best': p1_best,
        'phase1_signals': len(p1_sigs),
        'phase2_best': p2_best,
        'phase2_signals': len(p2_sigs),
        'overall_best': overall,
        'top_signals': sorted(all_sigs, key=lambda x: -x['score'])[:50],
    }
    out = os.path.join(os.path.dirname(__file__), '..', 'results',
                       'e_desp_01_missing_char_grid.json')
    with open(out, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved to {out}")
