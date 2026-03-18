#!/usr/bin/env python3
"""
# Cipher: four-square-inner-layer
# Family: substitution
# Status: active
# Keyspace: 6 masks × (73+1) delimiter positions × 20 kw-pairs × 2 parities × 2 trans = ~35K deterministic + SA
# Last run: never
# Best score: N/A

Four-Square as INNER layer of two-system model.

Tests:
  97 CT → remove 24 nulls → 73 chars → [optional col7] → remove delimiter → 72 chars → Four-Square decrypt → PT

Key insight: 72 = 8×9 (Fleissner), 72 = 36 digraphs (Four-Square).
The +1 char is a delimiter/breadcrumb for K5.

Uses consensus null mask from DEFECTOR:AZ_beau+col7 15/24 result.
Tests with and without col7 transposition.
Both parities (start=0 proven consistent, start=1 for completeness).
"""

import sys
import time
import math
import random
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CRIB_DICT, CT_LEN

# ── Constants ─────────────────────────────────────────────────────────────

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
N = 97
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63

# Known 15/24 null masks (24 nulls each → 73 chars)
MASKS_24 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],
    [0,1,2,5,8,12,14,20,36,39,41,42,52,55,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,95],
    [0,1,2,5,8,12,14,20,36,41,42,44,52,55,58,59,74,75,78,84,85,88,93,96],
]

# Consensus null positions (17/24 invariant across all masks)
CONSENSUS = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}

# Thematic keyword pairs to test (c1, c2)
KEYWORD_PAIRS = [
    ("KRYPTOS", "DEFECTOR"), ("DEFECTOR", "KRYPTOS"),
    ("KRYPTOS", "KRYPTOS"), ("DEFECTOR", "DEFECTOR"),
    ("KRYPTOS", "PALIMPSEST"), ("PALIMPSEST", "KRYPTOS"),
    ("KRYPTOS", "ABSCISSA"), ("ABSCISSA", "KRYPTOS"),
    ("KRYPTOS", "KOMPASS"), ("KOMPASS", "KRYPTOS"),
    ("DEFECTOR", "PALIMPSEST"), ("DEFECTOR", "KOMPASS"),
    ("DEFECTOR", "COLOPHON"), ("COLOPHON", "DEFECTOR"),
    ("PALIMPSEST", "ABSCISSA"), ("ABSCISSA", "PALIMPSEST"),
    ("KOMPASS", "COLOPHON"), ("SHADOW", "KRYPTOS"),
    ("BERLINCLOCK", "KRYPTOS"), ("KRYPTOS", "BERLINCLOCK"),
]

# ── Quadgrams ─────────────────────────────────────────────────────────────

QG_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    _QG = json.load(f)
QG_FLOOR = min(_QG.values()) - 1.0


def qg_score(text):
    return sum(_QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))


def qg_per_char(text):
    n = len(text) - 3
    return qg_score(text) / n if n > 0 else QG_FLOOR


# ── Four-Square ───────────────────────────────────────────────────────────

def merge_ij(ch):
    return "I" if ch == "J" else ch


def keyword_square(kw):
    seen = set()
    result = []
    for ch in kw.upper().replace("J", "I"):
        if ch in set(ALPHA25) and ch not in seen:
            result.append(ch)
            seen.add(ch)
    for ch in ALPHA25:
        if ch not in seen:
            result.append(ch)
            seen.add(ch)
    return "".join(result)


def make_grid(s):
    return [list(s[i*5:(i+1)*5]) for i in range(5)]


def make_lookup(grid):
    return {grid[r][c]: (r, c) for r in range(5) for c in range(5)}


def fs_decrypt(ct_text, p1, p2, c1, c2, start=0):
    """Four-Square decrypt. Handles odd length by passing through last char."""
    c1_lk = make_lookup(c1)
    c2_lk = make_lookup(c2)
    pt = []
    i = start
    while i + 1 < len(ct_text):
        a, b = ct_text[i], ct_text[i + 1]
        r1, j1 = c1_lk[a]
        r2, j2 = c2_lk[b]
        pt.append(p1[r1][j2])
        pt.append(p2[r2][j1])
        i += 2
    if i < len(ct_text):
        pt.append(ct_text[i])
    return "".join(pt)


# ── Transposition ─────────────────────────────────────────────────────────

def col7_inv_perm(n):
    """Inverse of width-7 columnar transposition (ascending order)."""
    width = 7
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    inv = [0] * n
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── Crib scoring ──────────────────────────────────────────────────────────

def score_cribs(pt, ene_s, bcl_s, ene_len=13, bcl_len=11):
    """Score against cribs at given shifted positions."""
    e = sum(1 for j in range(ene_len)
            if ene_s + j < len(pt) and merge_ij(pt[ene_s + j]) == merge_ij(ENE_WORD[j]))
    b = sum(1 for j in range(bcl_len)
            if bcl_s + j < len(pt) and merge_ij(pt[bcl_s + j]) == merge_ij(BCL_WORD[j]))
    return e + b, e, b


# ── Main attack ───────────────────────────────────────────────────────────

def main():
    random.seed(42)
    t0 = time.time()

    # Pre-build grids for all keyword pairs
    p1_grid = make_grid(ALPHA25)
    p2_grid = make_grid(ALPHA25)

    kw_grids = {}
    for kw1, kw2 in KEYWORD_PAIRS:
        key = (kw1, kw2)
        if key not in kw_grids:
            c1 = make_grid(keyword_square(kw1))
            c2 = make_grid(keyword_square(kw2))
            kw_grids[key] = (c1, c2)

    # Pre-compute col7 inverse permutations
    inv73 = col7_inv_perm(73)
    inv72 = col7_inv_perm(72)

    all_results = []
    total_configs = 0
    global_max = 0  # track actual max including scores < 6

    print("Four-Square as INNER LAYER of two-system model")
    print(f"CT: {CT}")
    print(f"Masks: {len(MASKS_24)} (24 nulls → 73 chars)")
    print(f"Keyword pairs: {len(KEYWORD_PAIRS)}")
    print(f"{'=' * 72}")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: 73-char model (no delimiter removal)
    #   null mask → [optional col7] → Four-Square decrypt (36 digraphs + 1)
    # ═══════════════════════════════════════════════════════════════════
    print("\nPHASE 1: 73-char extract (24 nulls, no delimiter removal)")
    print("-" * 72)

    for mi, mask in enumerate(MASKS_24):
        null_set = frozenset(mask)
        ct73 = "".join(merge_ij(CT[i]) for i in range(N) if i not in null_set)
        n1 = sum(1 for p in null_set if p < ENE_START)
        n2 = sum(1 for p in null_set if p < BCL_START)
        ene_s = ENE_START - n1
        bcl_s = BCL_START - n2

        for use_col7 in [False, True]:
            if use_col7:
                ct_work = "".join(ct73[inv73[i]] for i in range(73))
                trans_tag = "+col7"
            else:
                ct_work = ct73
                trans_tag = ""

            for parity in [0, 1]:
                for kw1, kw2 in KEYWORD_PAIRS:
                    c1, c2 = kw_grids[(kw1, kw2)]
                    pt = fs_decrypt(ct_work, p1_grid, p2_grid, c1, c2, parity)
                    total, e, b = score_cribs(pt, ene_s, bcl_s)
                    total_configs += 1
                    if total > global_max:
                        global_max = total

                    if total >= 6:
                        tag = f"73ch mask={mi} par={parity}{trans_tag} c1={kw1} c2={kw2}"
                        all_results.append((total, e, b, pt, tag))
                        if total >= 8:
                            print(f"  {total:2d}/24 (e={e}/13 b={b}/11) {tag}")
                            print(f"    PT: {pt[:60]}")

    t1 = time.time()
    print(f"\nPhase 1: {total_configs} configs in {t1 - t0:.1f}s, max={global_max}/24")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: 72-char model (remove delimiter → perfect digraphs)
    #   null mask → [optional col7] → remove 1 delimiter → 72 chars → FS
    #
    #   72 = 36 digraphs. Perfect for Four-Square.
    #   Delimiter position tested: all non-crib positions in the 73-char text.
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 72}")
    print("PHASE 2: 72-char model (remove 1 delimiter → 36 perfect digraphs)")
    print("-" * 72)

    for mi, mask in enumerate(MASKS_24):
        null_set = frozenset(mask)
        ct73 = "".join(merge_ij(CT[i]) for i in range(N) if i not in null_set)
        n1 = sum(1 for p in null_set if p < ENE_START)
        n2 = sum(1 for p in null_set if p < BCL_START)
        ene_s_73 = ENE_START - n1   # = 13
        bcl_s_73 = BCL_START - n2   # = 47

        for use_col7 in [False, True]:
            if use_col7:
                ct_pre = "".join(ct73[inv73[i]] for i in range(73))
                trans_tag = "+col7"
            else:
                ct_pre = ct73
                trans_tag = ""

            # Try removing each non-crib position as delimiter
            crib_positions_73 = set(range(ene_s_73, ene_s_73 + 13)) | set(range(bcl_s_73, bcl_s_73 + 11))

            for delim_pos in range(73):
                if delim_pos in crib_positions_73:
                    continue  # don't remove crib characters

                # Remove delimiter → 72 chars
                ct72 = ct_pre[:delim_pos] + ct_pre[delim_pos + 1:]
                assert len(ct72) == 72

                # Adjust crib positions for removal
                ene_s = ene_s_73 - (1 if delim_pos < ene_s_73 else 0)
                bcl_s = bcl_s_73 - (1 if delim_pos < bcl_s_73 else 0)

                for parity in [0, 1]:
                    for kw1, kw2 in KEYWORD_PAIRS:
                        c1, c2 = kw_grids[(kw1, kw2)]
                        pt = fs_decrypt(ct72, p1_grid, p2_grid, c1, c2, parity)
                        total, e, b = score_cribs(pt, ene_s, bcl_s)
                        total_configs += 1
                        if total > global_max:
                            global_max = total

                        if total >= 6:
                            delim_ch = ct_pre[delim_pos]
                            tag = (f"72ch mask={mi} delim@{delim_pos}='{delim_ch}' "
                                   f"par={parity}{trans_tag} c1={kw1} c2={kw2}")
                            all_results.append((total, e, b, pt, tag))
                            if total >= 8:
                                print(f"  {total:2d}/24 (e={e}/13 b={b}/11) {tag}")
                                print(f"    PT: {pt[:60]}")

        if (mi + 1) % 2 == 0:
            elapsed = time.time() - t0
            print(f"  [{elapsed:.0f}s] mask {mi+1}/{len(MASKS_24)} done, "
                  f"{total_configs:,} configs, max={global_max}/24")
            sys.stdout.flush()

    t2 = time.time()
    phase2_count = total_configs
    print(f"\nPhase 2 total: {total_configs:,} configs in {t2 - t0:.1f}s")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3: 25-null model (remove 25 nulls → 72 chars directly)
    #   Consensus 17 + try each additional 8th null from remaining positions
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 72}")
    print("PHASE 3: 25-null model (72 chars directly, no delimiter)")
    print("-" * 72)

    # Build 25-null masks: take each 24-null mask, add one more null
    # from non-crib, non-existing-null positions
    phase3_count = 0
    for mi, mask in enumerate(MASKS_24):
        null_set = set(mask)
        crib_set = set(range(21, 34)) | set(range(63, 74))
        candidates = [p for p in range(N) if p not in null_set and p not in crib_set]

        for extra_null in candidates:
            null_25 = frozenset(null_set | {extra_null})
            ct72 = "".join(merge_ij(CT[i]) for i in range(N) if i not in null_25)
            assert len(ct72) == 72

            n1 = sum(1 for p in null_25 if p < ENE_START)
            n2 = sum(1 for p in null_25 if p < BCL_START)
            ene_s = ENE_START - n1
            bcl_s = BCL_START - n2

            for use_col7 in [False, True]:
                if use_col7:
                    ct_work = "".join(ct72[inv72[i]] for i in range(72))
                    trans_tag = "+col7"
                else:
                    ct_work = ct72
                    trans_tag = ""

                for parity in [0]:  # start=0 only for Phase 3 (proven consistent)
                    for kw1, kw2 in KEYWORD_PAIRS[:10]:  # top 10 pairs
                        c1, c2 = kw_grids[(kw1, kw2)]
                        pt = fs_decrypt(ct_work, p1_grid, p2_grid, c1, c2, parity)
                        total, e, b = score_cribs(pt, ene_s, bcl_s)
                        total_configs += 1
                        phase3_count += 1
                        if total > global_max:
                            global_max = total

                        if total >= 6:
                            tag = (f"25null mask={mi}+{extra_null} "
                                   f"par=0{trans_tag} c1={kw1} c2={kw2}")
                            all_results.append((total, e, b, pt, tag))
                            if total >= 8:
                                print(f"  {total:2d}/24 (e={e}/13 b={b}/11) {tag}")
                                print(f"    PT: {pt[:60]}")

    t3 = time.time()
    print(f"\nPhase 3: {phase3_count:,} configs in {t3 - t2:.1f}s")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4: SA refinement on top hits
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 72}")
    print("PHASE 4: SA grid optimization on top hits")
    print("-" * 72)

    # Take the best deterministic results and try SA over grids
    all_results.sort(key=lambda x: -x[0])

    # Always run SA — keyword grids are a tiny fraction of the search space.
    # Random grid SA is the real test of Four-Square inner layer.
    if True:
        det_best = max((r[0] for r in all_results), default=0)
        print(f"Best deterministic: {det_best}/24")
        print(f"Running SA over random grids with consensus masks...")

        sa_best = 0
        for mi, mask in enumerate(MASKS_24[:3]):  # top 3 masks
            null_set = frozenset(mask)
            ct73 = "".join(merge_ij(CT[i]) for i in range(N) if i not in null_set)
            n1 = sum(1 for p in null_set if p < ENE_START)
            n2 = sum(1 for p in null_set if p < BCL_START)
            ene_s = ENE_START - n1
            bcl_s = BCL_START - n2

            for use_col7 in [False, True]:
                if use_col7:
                    ct_work = "".join(ct73[inv73[i]] for i in range(73))
                else:
                    ct_work = ct73

                for restart in range(30):
                    # Random grids
                    g = [list(ALPHA25) for _ in range(4)]
                    for gi in g:
                        random.shuffle(gi)
                    grids = ["".join(gi) for gi in g]

                    gp1, gc1, gc2, gp2 = [make_grid(s) for s in grids]
                    pt = fs_decrypt(ct_work, gp1, gp2, gc1, gc2, 0)
                    total, e, b = score_cribs(pt, ene_s, bcl_s)
                    cur_qg = qg_score(pt)
                    cur_score = cur_qg + total * 15.0
                    best_local = total

                    for step in range(20000):
                        t = 2.0 * (0.005 / 2.0) ** (step / 19999)
                        new_grids = list(grids)
                        gi = random.randint(0, 3)
                        lst = list(new_grids[gi])
                        a, b_idx = random.sample(range(25), 2)
                        lst[a], lst[b_idx] = lst[b_idx], lst[a]
                        new_grids[gi] = "".join(lst)

                        ngp1, ngc1, ngc2, ngp2 = [make_grid(s) for s in new_grids]
                        npt = fs_decrypt(ct_work, ngp1, ngp2, ngc1, ngc2, 0)
                        nt, ne, nb = score_cribs(npt, ene_s, bcl_s)
                        nqg = qg_score(npt)
                        nscore = nqg + nt * 15.0

                        delta = nscore - cur_score
                        if delta > 0 or (t > 0 and random.random() < math.exp(delta / t)):
                            grids = new_grids
                            cur_score = nscore
                            if nt > best_local:
                                best_local = nt
                                if nt > sa_best:
                                    sa_best = nt
                                    trans_tag = "+col7" if use_col7 else ""
                                    tag = f"SA mask={mi}{trans_tag} r={restart}"
                                    print(f"  SA NEW BEST: {nt}/24 (e={ne}/13 b={nb}/11) [{tag}]")
                                    print(f"    PT: {npt[:60]}")
                                    print(f"    qg/c: {qg_per_char(npt):.3f}")
                                    all_results.append((nt, ne, nb, npt, f"SA:{tag}"))
                                    sys.stdout.flush()

        print(f"\nSA best: {sa_best}/24")

    # ═══════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0
    all_results.sort(key=lambda x: -x[0])

    print(f"\n{'=' * 72}")
    print(f"FINAL SUMMARY ({total_configs:,} configs, {elapsed:.1f}s)")
    print(f"{'=' * 72}")

    if all_results:
        print(f"\nTop 20 results:")
        for total, e, b, pt, tag in all_results[:20]:
            print(f"  {total:2d}/24 (e={e}/13 b={b}/11) {tag}")
            print(f"    PT: {pt[:50]}")
        best = all_results[0][0]
        if best >= 16:
            print(f"\n!!! EXCEEDS 15/24 CEILING — INVESTIGATE !!!")
        elif best >= 13:
            print(f"\n*** Matches current ceiling range ({best}/24) ***")
        elif best >= 8:
            print(f"\nAbove noise ({best}/24) — worth investigating")
        else:
            print(f"\nBest {best}/24 — noise floor for Four-Square inner layer")
    else:
        print("\nNo results ≥ 6/24. Four-Square inner layer shows no signal.")

    return all_results


if __name__ == "__main__":
    main()
