#!/usr/bin/env python3
"""
Cipher: Fleissner turning grille + Q2 autokey
Family: campaigns
Status: active
Keyspace: C(73,24) null masks (SA-sampled) x random Fleissner grilles x 5 keywords
Last run:
Best score:
"""
"""
F-FLEISSNER-Q2-AUTOKEY-V1: Fleissner Turning Grille + Quagmire II Autokey

MODEL:
  CT97 -> remove 24 nulls -> CT73 -> Fleissner inverse transposition -> CT73'
  -> Q2 autokey decryption (KA body, AZ key column, PT-feedback) -> PT73

Q2 AUTOKEY DECRYPTION (Kryptos sculpture tableau):
  The Kryptos tableau is Quagmire II: CT looked up in KA body, key from AZ column.
  Decrypt: PT[i] = KA[(KA.index(CT[i]) - key_num[i]) % 26]
  Autokey PT-feedback: key_num[i] = AZ.index(PT[i-L]) for i >= L
  Primer = keyword, primer values = AZ indices of keyword letters.

FLEISSNER TURNING GRILLE:
  For 73 chars we try grid sizes:
    9x9 = 81 cells (73 real + 8 padding)
    8x10 = 80 cells (73 real + 7 padding)
  A 180-degree Fleissner on rectangular NxM grid pairs (r,c) with (N-1-r, M-1-c).
  For 9x9: center cell (4,4) is fixed; 40 pairs + 1 fixed = 81 cells.
  For 8x10: 40 pairs = 80 cells.
  Each pair has a binary choice -> 2^40 configs (SA-sampled).

SA OPTIMIZATION:
  Outer loop: SA on null mask (swap one null with one non-null).
  Inner: for each null mask, try multiple random valid Fleissner grilles.
  Score = number of crib characters matching at mapped positions (max 24).

KEYWORDS: KRYPTOS, DEFECTOR, KOMPASS, ABSCISSA, COLOPHON
"""

import math
import os
import random
import sys
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS,
)

# ── Constants ─────────────────────────────────────────────────────────────
N = 97
N_NULLS = 24
N_PT = 73

KA_STR = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_STR = ALPH
AZ_IDX = ALPH_IDX

ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63

NON_CRIB = sorted(i for i in range(N) if i not in CRIB_POSITIONS)
NC_SET = frozenset(NON_CRIB)

KEYWORDS = ["KRYPTOS", "DEFECTOR", "KOMPASS", "ABSCISSA", "COLOPHON"]

# SA parameters
SA_RESTARTS = 30
SA_STEPS = 5000
SA_T0 = 1.5
SA_TF = 0.005
N_GRILLES_PER_RESTART = 5  # random Fleissner grilles per SA restart


# ── Fleissner grille mechanics ────────────────────────────────────────────

def build_180_pairs(rows, cols):
    """Build position pairs for 180-degree rotation on rows x cols grid.
    (r,c) pairs with (rows-1-r, cols-1-c). For odd grids, center is fixed.
    Returns (pairs, fixed) where pairs=list of ((r1,c1),(r2,c2)) and
    fixed=list of single positions that map to themselves.
    """
    pairs = []
    fixed = []
    visited = set()
    for r in range(rows):
        for c in range(cols):
            if (r, c) in visited:
                continue
            partner = (rows - 1 - r, cols - 1 - c)
            if partner == (r, c):
                fixed.append((r, c))
                visited.add((r, c))
            else:
                pairs.append(((r, c), partner))
                visited.add((r, c))
                visited.add(partner)
    return pairs, fixed


def build_fleissner_perm(choices, pairs, fixed, rows, cols):
    """Build a reading-order permutation for 180-degree Fleissner grille.

    Encryption writes PT through holes in pass 0, then rotates 180 and
    writes remaining PT through newly revealed holes in pass 1.
    Reading the filled grid row-by-row gives CT.

    Decryption reverses this: arrange CT in grid, read pass 0 holes
    (row-major order) then pass 1 holes (row-major order) to get PT.

    choices[i] = 0: hole at pairs[i][0] in pass 0, pairs[i][1] in pass 1
    choices[i] = 1: hole at pairs[i][1] in pass 0, pairs[i][0] in pass 1

    Returns permutation p where PT[i] = grid[p[i]], i.e. p is the
    reading order through the grille.
    """
    pass0 = []
    pass1 = []
    for i, (a, b) in enumerate(pairs):
        a_lin = a[0] * cols + a[1]
        b_lin = b[0] * cols + b[1]
        if choices[i] == 0:
            pass0.append(a_lin)
            pass1.append(b_lin)
        else:
            pass0.append(b_lin)
            pass1.append(a_lin)

    # Fixed positions (center of odd grids) go in pass 0
    for f in fixed:
        pass0.append(f[0] * cols + f[1])

    pass0.sort()  # row-major reading order
    pass1.sort()

    return pass0 + pass1


def invert_perm(perm):
    """Compute inverse permutation: inv[perm[i]] = i."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── Q2 autokey decryption ────────────────────────────────────────────────

def q2_autokey_decrypt(ct_chars, keyword):
    """Q2 (Quagmire II) PT-autokey decryption.

    Kryptos tableau semantics:
      - CT is looked up in KA (body of tableau)
      - Key comes from AZ (left column of tableau)
      - Decrypt: PT[i] = KA[(KA.index(CT[i]) - key_num[i]) % 26]
      - Autokey PT-feedback: key_num[i] = AZ.index(PT[i-L]) for i >= L
      - Primer = keyword letters, primer values = their AZ indices

    Args:
        ct_chars: list of uppercase characters (the ciphertext after untransposition)
        keyword: string keyword for the primer

    Returns:
        plaintext string
    """
    L = len(keyword)
    # Primer key values = AZ indices of keyword letters
    key_vals = [AZ_IDX[c] for c in keyword.upper()]

    pt_chars = []
    for i, ct_ch in enumerate(ct_chars):
        if i < L:
            ki = key_vals[i]
        else:
            # PT-feedback: key from previous PT character's AZ index
            ki = AZ_IDX[pt_chars[i - L]]

        ct_idx = KA_IDX[ct_ch]
        pt_idx = (ct_idx - ki) % 26
        pt_ch = KA_STR[pt_idx]
        pt_chars.append(pt_ch)

    return ''.join(pt_chars)


# ── Scoring ──────────────────────────────────────────────────────────────

def count_crib_hits(pt, ene_start_73, bcl_start_73):
    """Count crib character matches at mapped positions."""
    e = 0
    for j, c in enumerate(ENE_WORD):
        pos = ene_start_73 + j
        if 0 <= pos < len(pt) and pt[pos] == c:
            e += 1
    b = 0
    for j, c in enumerate(BCL_WORD):
        pos = bcl_start_73 + j
        if 0 <= pos < len(pt) and pt[pos] == c:
            b += 1
    return e + b, e, b


# ── Full evaluation ──────────────────────────────────────────────────────

def evaluate(null_set, fleissner_perm_order, keyword, grid_size, n_real):
    """Full pipeline: null removal -> pad to grid -> Fleissner untranspose -> Q2 autokey.

    Returns (total_score, ene_score, bcl_score, plaintext).
    """
    # Step 1: Remove nulls from CT97 -> CT73
    ct73 = [CT[i] for i in range(N) if i not in null_set]
    assert len(ct73) == N_PT, f"Expected {N_PT} chars after null removal, got {len(ct73)}"

    # Step 2: Pad to grid size with dummy chars (X)
    n_pad = grid_size - N_PT
    ct_grid = ct73 + ['X'] * n_pad

    # Step 3: Fleissner inverse transposition
    # The Fleissner perm gives the reading order: PT[i] = grid[perm[i]]
    # To UNDO the transposition (given CT was transposed), we need the inverse:
    # untransposed[perm[i]] = ct_grid[i], i.e. untransposed[j] = ct_grid[inv_perm[j]]
    inv_perm = invert_perm(fleissner_perm_order)
    untransposed = [ct_grid[inv_perm[i]] for i in range(grid_size)]

    # Take first n_real chars as the untransposed ciphertext
    ct73_untrans = untransposed[:n_real]

    # Step 4: Q2 autokey decryption
    pt = q2_autokey_decrypt(ct73_untrans, keyword)

    # Step 5: Compute crib positions in 73-char text
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    return total, e, b, pt


# ── Grid configurations ──────────────────────────────────────────────────

GRID_CONFIGS = [
    # (name, rows, cols, grid_size, n_real_chars_to_use)
    ("9x9", 9, 9, 81, 73),
    ("8x10", 8, 10, 80, 73),
]


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()

    print("=" * 70)
    print("F-FLEISSNER-Q2-AUTOKEY-V1")
    print("Fleissner turning grille (180deg) + Quagmire II PT-autokey")
    print("=" * 70)
    print(f"CT97 = {CT}")
    print(f"Keywords: {KEYWORDS}")
    print(f"Grid configs: {[g[0] for g in GRID_CONFIGS]}")
    print(f"SA: {SA_RESTARTS} restarts x {SA_STEPS} steps, "
          f"{N_GRILLES_PER_RESTART} grilles/restart")
    print(f"Total evals estimate: {len(KEYWORDS)} kw x {len(GRID_CONFIGS)} grids x "
          f"{SA_RESTARTS} restarts x {N_GRILLES_PER_RESTART} grilles x {SA_STEPS} steps "
          f"= {len(KEYWORDS)*len(GRID_CONFIGS)*SA_RESTARTS*N_GRILLES_PER_RESTART*SA_STEPS:,}")
    print(flush=True)

    all_results = []
    global_best = 0

    for grid_name, rows, cols, grid_size, n_real in GRID_CONFIGS:
        pairs, fixed = build_180_pairs(rows, cols)
        n_pairs = len(pairs)

        print(f"\n{'='*70}")
        print(f"GRID: {grid_name} ({rows}x{cols}={grid_size} cells, "
              f"{n_pairs} pairs, {len(fixed)} fixed, pad={grid_size - N_PT})")
        print(f"{'='*70}", flush=True)

        # Verify coverage
        all_cells = set()
        for (a, b) in pairs:
            all_cells.add(a[0] * cols + a[1])
            all_cells.add(b[0] * cols + b[1])
        for f in fixed:
            all_cells.add(f[0] * cols + f[1])
        assert len(all_cells) == grid_size, (
            f"Pairs+fixed cover {len(all_cells)} cells, expected {grid_size}")

        for keyword in KEYWORDS:
            print(f"\n  --- Keyword: {keyword} (grid={grid_name}) ---", flush=True)

            kw_best = 0
            kw_best_result = None

            for restart in range(SA_RESTARTS):
                rng = random.Random(
                    restart * 997 + hash(keyword + grid_name) % 100000)

                # Try N_GRILLES_PER_RESTART random Fleissner configurations
                best_restart_score = 0
                best_restart_result = None

                for grille_idx in range(N_GRILLES_PER_RESTART):
                    # Random Fleissner grille
                    choices = [rng.randint(0, 1) for _ in range(n_pairs)]
                    perm_order = build_fleissner_perm(
                        choices, pairs, fixed, rows, cols)

                    # Random null mask
                    null_list = sorted(rng.sample(NON_CRIB, N_NULLS))
                    null_set = frozenset(null_list)
                    non_null_cands = sorted(NC_SET - null_set)

                    # Evaluate initial config
                    score, e, b, pt = evaluate(
                        null_set, perm_order, keyword, grid_size, n_real)
                    best_sa_score = score
                    best_sa_null = null_set
                    best_sa_choices = choices[:]
                    current_score = score
                    current_null_set = set(null_list)
                    current_non_null = set(non_null_cands)
                    current_choices = choices[:]

                    # SA loop: jointly optimize null mask and Fleissner grille
                    for step in range(SA_STEPS):
                        T = SA_T0 * (SA_TF / SA_T0) ** (step / SA_STEPS)

                        # Decide move type: 70% null swap, 30% grille flip
                        if rng.random() < 0.7:
                            # Null mask swap
                            out = rng.choice(list(current_null_set))
                            into = rng.choice(list(current_non_null))
                            current_null_set.discard(out)
                            current_null_set.add(into)
                            current_non_null.discard(into)
                            current_non_null.add(out)

                            trial_perm = build_fleissner_perm(
                                current_choices, pairs, fixed, rows, cols)
                            new_score, ne, nb, npt = evaluate(
                                frozenset(current_null_set), trial_perm,
                                keyword, grid_size, n_real)

                            delta = new_score - current_score
                            if delta > 0 or rng.random() < math.exp(
                                    delta / max(T, 0.001)):
                                current_score = new_score
                                if current_score > best_sa_score:
                                    best_sa_score = current_score
                                    best_sa_null = frozenset(current_null_set)
                                    best_sa_choices = current_choices[:]
                            else:
                                current_null_set.discard(into)
                                current_null_set.add(out)
                                current_non_null.discard(out)
                                current_non_null.add(into)
                        else:
                            # Fleissner grille flip
                            idx = rng.randint(0, n_pairs - 1)
                            current_choices[idx] ^= 1

                            trial_perm = build_fleissner_perm(
                                current_choices, pairs, fixed, rows, cols)
                            new_score, ne, nb, npt = evaluate(
                                frozenset(current_null_set), trial_perm,
                                keyword, grid_size, n_real)

                            delta = new_score - current_score
                            if delta > 0 or rng.random() < math.exp(
                                    delta / max(T, 0.001)):
                                current_score = new_score
                                if current_score > best_sa_score:
                                    best_sa_score = current_score
                                    best_sa_null = frozenset(current_null_set)
                                    best_sa_choices = current_choices[:]
                            else:
                                current_choices[idx] ^= 1

                    if best_sa_score > best_restart_score:
                        best_restart_score = best_sa_score
                        # Re-evaluate to get full info
                        final_perm = build_fleissner_perm(
                            best_sa_choices, pairs, fixed, rows, cols)
                        ts, te, tb, tpt = evaluate(
                            best_sa_null, final_perm,
                            keyword, grid_size, n_real)
                        best_restart_result = {
                            'score': ts, 'e': te, 'b': tb, 'pt': tpt,
                            'mask': sorted(best_sa_null),
                            'choices': best_sa_choices,
                            'keyword': keyword,
                            'grid': grid_name,
                        }

                if best_restart_score > kw_best:
                    kw_best = best_restart_score
                    kw_best_result = best_restart_result

                if best_restart_score > global_best:
                    global_best = best_restart_score

                # Report periodically or on high scores
                if best_restart_score >= 10 or restart % 10 == 0:
                    elapsed = time.time() - t_start
                    tag = " ***" if best_restart_score >= 10 else ""
                    print(f"    {keyword}:{grid_name} r={restart:2d}: "
                          f"{best_restart_score}/24 "
                          f"(kw_best={kw_best}/24, global={global_best}/24) "
                          f"[{elapsed:.0f}s]{tag}", flush=True)
                    if best_restart_score >= 10 and best_restart_result:
                        r = best_restart_result
                        print(f"      ene={r['e']}/13 bcl={r['b']}/11 "
                              f"PT={r['pt'][:50]}...")
                        print(f"      mask={r['mask']}")

            # Summary for this keyword+grid
            if kw_best_result:
                all_results.append(kw_best_result)
                r = kw_best_result
                print(f"  >> {keyword}:{grid_name} BEST: {r['score']}/24 "
                      f"(ene={r['e']}/13 bcl={r['b']}/11)")
                print(f"     PT = {r['pt']}")
                print(f"     mask = {r['mask']}", flush=True)

    # ── Final Summary ────────────────────────────────────────────────────
    elapsed = time.time() - t_start
    all_results.sort(key=lambda x: -x['score'])

    print(f"\n{'='*70}")
    print(f"FINAL SUMMARY (elapsed {elapsed:.1f}s)")
    print(f"{'='*70}")
    print(f"Global best: {global_best}/24")
    print(f"\nTop 10 results:")
    for i, r in enumerate(all_results[:10]):
        print(f"  {i+1}. {r['score']}/24 ene={r['e']}/13 bcl={r['b']}/11 "
              f"{r['keyword']}:{r['grid']}")
        print(f"     PT   = {r['pt']}")
        print(f"     mask = {r['mask']}")
        print()

    # Verdict
    best = all_results[0] if all_results else {
        'score': 0, 'pt': '', 'keyword': 'none', 'e': 0, 'b': 0, 'grid': ''}
    verdict = {
        "experiment": "F-FLEISSNER-Q2-AUTOKEY-V1",
        "model": "null_mask + Fleissner_180 + Q2_PT_autokey",
        "keywords_tested": KEYWORDS,
        "grids_tested": [g[0] for g in GRID_CONFIGS],
        "sa_restarts": SA_RESTARTS,
        "sa_steps": SA_STEPS,
        "grilles_per_restart": N_GRILLES_PER_RESTART,
        "global_best": global_best,
        "best_score": best['score'],
        "best_keyword": best.get('keyword', ''),
        "best_grid": best.get('grid', ''),
        "best_ene": best.get('e', 0),
        "best_bcl": best.get('b', 0),
        "best_pt": best.get('pt', ''),
        "best_mask": best.get('mask', []),
        "elapsed_s": round(elapsed, 1),
        "verdict_status": (
            "breakthrough" if global_best >= 24
            else "signal" if global_best >= 18
            else "interesting" if global_best >= 10
            else "noise"
        ),
        "summary": (
            f"Fleissner(180)+Q2_autokey: best {global_best}/24 "
            f"({best.get('keyword','')}:{best.get('grid','')}) "
            f"ene={best.get('e',0)}/13 bcl={best.get('b',0)}/11"
        ),
    }

    print(f"\nverdict: {json.dumps(verdict, indent=2)}")

    # Save artifact
    os.makedirs("results", exist_ok=True)
    outfile = "results/f_fleissner_q2_autokey_v1.json"
    with open(outfile, "w") as f:
        json.dump(verdict, f, indent=2)
    print(f"\nArtifact: {outfile}")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/campaigns/"
          f"f_fleissner_q2_autokey_v1.py")


if __name__ == '__main__':
    main()
