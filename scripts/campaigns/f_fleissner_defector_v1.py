#!/usr/bin/env python3
"""
Cipher: Fleissner turning grille + DEFECTOR:AZ_beau autokey
Family: campaigns
Status: active
Keyspace: 2^36 grille configs × C(97,24) null masks (SA-sampled) × 3 grids × 3 keywords
Last run: never
Best score: N/A

Fleissner 180° turning grille + DEFECTOR:AZ_beau autokey on inner text.

MODEL:
  CT97 → remove 24/25 nulls → CT73/CT72 → pad to grid → Fleissner inverse → CT'
  → Beaufort autokey (DEFECTOR, AZ alphabet) → PT

GRIDS:
  8×9 = 72 cells (72 chars, exact — the 72+1 model where 1 char is a delimiter)
  9×9 = 81 cells (73 chars + 8 padding)
  8×10 = 80 cells (73 chars + 7 padding)

Q2 autokey reached 13/24 (KRYPTOS:9×9). DEFECTOR:AZ_beau is the strongest
cipher model (15/24 with col7). This tests whether Fleissner transposition
can match or exceed col7.

WARNING: historical / reproducibility artifact. This script still warm-starts
from a retired consensus-null construct and must not be used as live evidence
without explicit operator intent.

Use `--allow-retired-construct` to run it.

Consensus null mask (17 fixed positions from the retired 15/24 col7 result)
used as warm-start seed for SA.
"""

import argparse
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS

N = 97
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
NON_CRIB = sorted(i for i in range(N) if i not in CRIB_POSITIONS)
NC_SET = frozenset(NON_CRIB)

# Consensus null positions from 15/24 col7 result
CONSENSUS_17 = frozenset([0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85])

# Known 24-null masks
MASKS_24 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
]

KEYWORDS = {
    'DEFECTOR': [ord(c) - 65 for c in 'DEFECTOR'],
    'KRYPTOS': [ord(c) - 65 for c in 'KRYPTOS'],
    'KOMPASS': [ord(c) - 65 for c in 'KOMPASS'],
}

SA_RESTARTS = 40
SA_STEPS = 6000
SA_T0 = 1.5
SA_TF = 0.005
N_GRILLES = 3  # random grilles per restart


# ── Fleissner grille mechanics ──────────────────────────────────────────

def build_180_pairs(rows, cols):
    pairs, fixed = [], []
    visited = set()
    for r in range(rows):
        for c in range(cols):
            if (r, c) in visited:
                continue
            partner = (rows - 1 - r, cols - 1 - c)
            if partner == (r, c):
                fixed.append((r, c))
            else:
                pairs.append(((r, c), partner))
            visited.add((r, c))
            visited.add(partner)
    return pairs, fixed


def build_fleissner_perm(choices, pairs, fixed, rows, cols):
    pass0, pass1 = [], []
    for i, (a, b) in enumerate(pairs):
        a_lin = a[0] * cols + a[1]
        b_lin = b[0] * cols + b[1]
        if choices[i] == 0:
            pass0.append(a_lin)
            pass1.append(b_lin)
        else:
            pass0.append(b_lin)
            pass1.append(a_lin)
    for f in fixed:
        pass0.append(f[0] * cols + f[1])
    pass0.sort()
    pass1.sort()
    return pass0 + pass1


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── DEFECTOR:AZ_beau autokey ────────────────────────────────────────────

def autokey_beau_az(ct_nums, kw_nums):
    """Beaufort autokey: P = (K - C) mod 26, PT-feedback."""
    L = len(kw_nums)
    pt = []
    for i, ci in enumerate(ct_nums):
        ki = kw_nums[i] if i < L else pt[i - L]
        pt.append((ki - ci) % 26)
    return pt


def autokey_vig_az(ct_nums, kw_nums):
    """Vigenère autokey: P = (C - K) mod 26, PT-feedback."""
    L = len(kw_nums)
    pt = []
    for i, ci in enumerate(ct_nums):
        ki = kw_nums[i] if i < L else pt[i - L]
        pt.append((ci - ki) % 26)
    return pt


# ── Scoring ──────────────────────────────────────────────────────────────

ENE_NUMS = [ord(c) - 65 for c in ENE_WORD]
BCL_NUMS = [ord(c) - 65 for c in BCL_WORD]


def count_hits(pt, ene_s, bcl_s):
    e = sum(1 for j, c in enumerate(ENE_NUMS) if ene_s + j < len(pt) and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_NUMS) if bcl_s + j < len(pt) and pt[bcl_s + j] == c)
    return e + b, e, b


# ── Full evaluation ──────────────────────────────────────────────────────

def evaluate(null_set, fleissner_perm, kw_nums, grid_size, n_real, beau=True):
    ct_real = [ord(CT[i]) - 65 for i in range(N) if i not in null_set]
    n_pad = grid_size - len(ct_real)
    ct_grid = ct_real + [23] * n_pad  # pad with X

    inv_p = invert_perm(fleissner_perm)
    untrans = [ct_grid[inv_p[i]] for i in range(grid_size)]
    ct_inner = untrans[:n_real]

    pt = autokey_beau_az(ct_inner, kw_nums) if beau else autokey_vig_az(ct_inner, kw_nums)

    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    total, e, b = count_hits(pt, ene_s, bcl_s)
    return total, e, b, pt


# ── Grid configurations ──────────────────────────────────────────────────

GRID_CONFIGS = [
    # name, rows, cols, grid_size, n_real, n_nulls
    ("8x9", 8, 9, 72, 72, 25),    # 72+1 model: 25 nulls
    ("9x9", 9, 9, 81, 73, 24),    # 73-char model
    ("8x10", 8, 10, 80, 73, 24),  # 73-char model
]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--allow-retired-construct",
        action="store_true",
        help="Acknowledge that this script is a historical artifact using a retired construct.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.allow_retired_construct:
        raise SystemExit(
            "Refusing to run retired-construct historical artifact without "
            "--allow-retired-construct."
        )

    t_start = time.time()
    random.seed(42)

    total_evals = (len(KEYWORDS) * len(GRID_CONFIGS) * SA_RESTARTS *
                   N_GRILLES * SA_STEPS * 2)  # ×2 for beau+vig

    print("=" * 70)
    print("F-FLEISSNER-DEFECTOR-V1")
    print("Fleissner 180° turning grille + DEFECTOR:AZ_beau/vig autokey")
    print("=" * 70)
    print(f"Grids: {[g[0] for g in GRID_CONFIGS]}")
    print(f"Keywords: {list(KEYWORDS.keys())}")
    print(f"SA: {SA_RESTARTS} restarts × {N_GRILLES} grilles × {SA_STEPS} steps")
    print(f"Est. evals: {total_evals:,}")
    print(flush=True)

    global_best = 0
    all_results = []

    for grid_name, rows, cols, grid_size, n_real, n_nulls in GRID_CONFIGS:
        pairs, fixed = build_180_pairs(rows, cols)
        n_pairs = len(pairs)

        print(f"\n{'=' * 70}")
        print(f"GRID: {grid_name} ({rows}×{cols}={grid_size}, "
              f"nulls={n_nulls}, {n_pairs} pairs, {len(fixed)} fixed)")
        print(f"{'=' * 70}", flush=True)

        for kw_name, kw_nums in KEYWORDS.items():
            for beau in [True, False]:
                var_tag = "beau" if beau else "vig"
                tag = f"{kw_name}:AZ_{var_tag}:{grid_name}"
                kw_best = 0

                for restart in range(SA_RESTARTS):
                    best_restart = 0
                    best_result = None

                    for gi in range(N_GRILLES):
                        # Random Fleissner grille
                        choices = [random.randint(0, 1) for _ in range(n_pairs)]
                        perm = build_fleissner_perm(choices, pairs, fixed, rows, cols)

                        # Null mask: seed first 2 restarts with consensus
                        if restart < 2 and n_nulls == 24:
                            null_list = sorted(MASKS_24[restart % len(MASKS_24)])
                        elif restart < 2 and n_nulls == 25:
                            # Start from 24-null consensus + one random extra
                            base = list(MASKS_24[restart % len(MASKS_24)])
                            extra = random.choice([p for p in NON_CRIB
                                                   if p not in base])
                            null_list = sorted(base + [extra])
                        else:
                            null_list = sorted(random.sample(NON_CRIB, n_nulls))

                        null_set = frozenset(null_list)
                        cur_null = set(null_list)
                        cur_nonnull = set(p for p in NON_CRIB if p not in cur_null)
                        cur_choices = choices[:]

                        score, e, b, pt = evaluate(
                            null_set, perm, kw_nums, grid_size, n_real, beau)
                        cur_score = score
                        best_sa = score
                        best_sa_null = null_set
                        best_sa_choices = choices[:]
                        best_sa_pt = pt
                        best_sa_e = e
                        best_sa_b = b

                        for step in range(SA_STEPS):
                            T = SA_T0 * (SA_TF / SA_T0) ** (step / SA_STEPS)

                            if random.random() < 0.7:
                                # Null mask swap
                                out = random.choice(list(cur_null))
                                into = random.choice(list(cur_nonnull))
                                cur_null.discard(out)
                                cur_null.add(into)
                                cur_nonnull.discard(into)
                                cur_nonnull.add(out)

                                trial_perm = build_fleissner_perm(
                                    cur_choices, pairs, fixed, rows, cols)
                                ns, ne, nb, npt = evaluate(
                                    frozenset(cur_null), trial_perm,
                                    kw_nums, grid_size, n_real, beau)

                                delta = ns - cur_score
                                if delta > 0 or random.random() < math.exp(
                                        delta / max(T, 0.001)):
                                    cur_score = ns
                                    if ns > best_sa:
                                        best_sa = ns
                                        best_sa_null = frozenset(cur_null)
                                        best_sa_choices = cur_choices[:]
                                        best_sa_pt = npt
                                        best_sa_e = ne
                                        best_sa_b = nb
                                else:
                                    cur_null.discard(into)
                                    cur_null.add(out)
                                    cur_nonnull.discard(out)
                                    cur_nonnull.add(into)
                            else:
                                # Grille flip
                                idx = random.randint(0, n_pairs - 1)
                                cur_choices[idx] ^= 1
                                trial_perm = build_fleissner_perm(
                                    cur_choices, pairs, fixed, rows, cols)
                                ns, ne, nb, npt = evaluate(
                                    frozenset(cur_null), trial_perm,
                                    kw_nums, grid_size, n_real, beau)

                                delta = ns - cur_score
                                if delta > 0 or random.random() < math.exp(
                                        delta / max(T, 0.001)):
                                    cur_score = ns
                                    if ns > best_sa:
                                        best_sa = ns
                                        best_sa_null = frozenset(cur_null)
                                        best_sa_choices = cur_choices[:]
                                        best_sa_pt = npt
                                        best_sa_e = ne
                                        best_sa_b = nb
                                else:
                                    cur_choices[idx] ^= 1

                        if best_sa > best_restart:
                            best_restart = best_sa
                            pt_str = ''.join(chr(p + 65) for p in best_sa_pt)
                            best_result = {
                                'score': best_sa, 'e': best_sa_e, 'b': best_sa_b,
                                'pt': pt_str, 'mask': sorted(best_sa_null),
                                'tag': tag,
                            }

                    if best_restart > kw_best:
                        kw_best = best_restart
                    if best_restart > global_best:
                        global_best = best_restart

                    if best_restart >= 10 or restart % 10 == 0:
                        elapsed = time.time() - t_start
                        flag = " ***" if best_restart >= 13 else ""
                        print(f"  {tag} r={restart:2d}: {best_restart}/24 "
                              f"(kw={kw_best}, global={global_best}) "
                              f"[{elapsed:.0f}s]{flag}", flush=True)
                        if best_restart >= 10 and best_result:
                            r = best_result
                            print(f"    e={r['e']}/13 b={r['b']}/11 "
                                  f"PT={r['pt'][:50]}")

                if kw_best >= 8:
                    all_results.append({
                        'tag': tag, 'best': kw_best
                    })

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t_start
    print(f"\n{'=' * 70}")
    print(f"FINAL SUMMARY ({elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Global best: {global_best}/24")

    if global_best >= 15:
        print("!!! MATCHES OR EXCEEDS COL7 CEILING — INVESTIGATE !!!")
    elif global_best >= 13:
        print("Matches Q2 autokey ceiling (13/24) — interesting but not signal")
    elif global_best >= 10:
        print("Above noise — worth investigating")
    else:
        print("Noise floor — Fleissner + DEFECTOR:AZ_beau shows no signal")


if __name__ == '__main__':
    main()
