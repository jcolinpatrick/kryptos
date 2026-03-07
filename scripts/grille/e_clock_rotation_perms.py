#!/usr/bin/env python3
"""
# Cipher: Vigenere/Beaufort + rotational permutation
# Family: grille
# Status: active
# Keyspace: 478104 configs (power + inverse + swap + spiral + columnar + composed)
# Last run: 2026-03-06
# Best score: 0 (no hits above noise)

Clock-inspired rotational/cyclical permutations combined with HOROLOGE keyword.

Tests seven permutation families exploiting GF(97) structure and clock mechanics:

1. GF(97) Power Permutations (~55K): i -> a*i^k + b mod 97.
   The natural nonlinear "rotational" maps in the prime field. k must satisfy
   gcd(k,96)=1 (32 valid exponents). b sampled from HOROLOGE letter values
   and clock-significant numbers.

2. Modular Inverse Permutations (9312): i -> a*i^(-1) + b mod 97.
   The multiplicative inverse is a fundamental involution (self-inverse map).
   Combined with affine transform. Clock analogy: "going backwards in time."

3. Swap-Based Permutations (~9500): Start with identity, swap every 8th
   position (HOROLOGE period) by distance k. Plus HOROLOGE-keyed swaps
   and rotate+segment-reverse combinations.

4. 24-Hour Partitioning (~280): Divide 97 into blocks of 24 (clock hours),
   reorder blocks, reverse within, interleave, zigzag.

5. Spiral/Rotational Grid Reading (~200): CW/CCW spirals on 10x10, 7x14,
   etc. from corners and center. Row-fill, column-fill, spiral-fill variants.

6. Columnar Transposition (~100): HOROLOGE-ordered column reading on 8/13/24
   column grids. Zigzag rows, diagonal reading.

7. Composed Permutations (~2000): Pairs of simple permutations applied in
   sequence (e.g., affine then spiral, reverse then columnar).

All permutations applied to CT, then decrypted with Vig/Beau/VBeau on AZ/KA
(6 configs each). Scored with score_candidate_free() (position-free crib search).
"""
from __future__ import annotations

import sys
import time
import itertools
from math import gcd
from typing import List, Tuple

sys.path.insert(0, "/home/cpatrick/kryptos/src")

from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.scoring.aggregate import score_candidate_free
from kryptos.kernel.scoring.free_crib import score_free_fast

# ── Constants ──────────────────────────────────────────────────────────────

KEYWORD = "HOROLOGE"
N = CT_LEN  # 97 (prime)

KEY_AZ = [AZ.char_to_idx(c) for c in KEYWORD]  # [7,14,17,14,11,14,6,4]
KEY_KA = [KA.char_to_idx(c) for c in KEYWORD]  # [14,5,1,5,17,5,13,11]

DECRYPT_CONFIGS = [
    (CipherVariant.VIGENERE, KEY_AZ, "Vig/AZ"),
    (CipherVariant.VIGENERE, KEY_KA, "Vig/KA"),
    (CipherVariant.BEAUFORT, KEY_AZ, "Beau/AZ"),
    (CipherVariant.BEAUFORT, KEY_KA, "Beau/KA"),
    (CipherVariant.VAR_BEAUFORT, KEY_AZ, "VBeau/AZ"),
    (CipherVariant.VAR_BEAUFORT, KEY_KA, "VBeau/KA"),
]

REPORT_THRESHOLD = 6
DETAIL_THRESHOLD = 10

# ── Utility ────────────────────────────────────────────────────────────────

def apply_perm(text: str, perm: List[int]) -> str:
    """output[i] = text[perm[i]] (gather)."""
    return "".join(text[perm[i]] for i in range(len(perm)))


def invert_perm(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def compose_perms(p1: List[int], p2: List[int]) -> List[int]:
    """result[i] = p1[p2[i]]."""
    return [p1[p2[i]] for i in range(len(p1))]


def test_perm(perm: List[int], desc: str, results: list, stats: dict) -> None:
    """Apply perm to CT, try all decrypt configs, score with free cribs."""
    reordered = apply_perm(CT, perm)
    for variant, key_nums, alabel in DECRYPT_CONFIGS:
        pt = decrypt_text(reordered, key_nums, variant)
        stats["total"] += 1

        fast = score_free_fast(pt)
        if fast > 0:
            sb = score_candidate_free(pt)
            sc = sb.crib_score
            if sc > REPORT_THRESHOLD:
                full_desc = f"{desc} | {alabel}"
                results.append((sc, pt, full_desc, sb))
                if sc >= DETAIL_THRESHOLD:
                    print(f"  *** SIGNAL: score={sc} | {full_desc}")
                    print(f"      PT: {pt}")
                    print(f"      {sb.summary}")
            if sc > stats["best_score"]:
                stats["best_score"] = sc
                stats["best_desc"] = f"{desc} | {alabel}"
                stats["best_pt"] = pt


def run_family(name: str, perms: List[Tuple[List[int], str]],
               all_results: list, gstats: dict) -> None:
    t0 = time.time()
    n_configs = len(perms) * len(DECRYPT_CONFIGS)
    print(f"\n{'='*70}")
    print(f"Family: {name}")
    print(f"{'='*70}")
    print(f"  {len(perms)} permutations x {len(DECRYPT_CONFIGS)} decrypts = {n_configs} configs")

    fres: list = []
    fs = {"total": 0, "best_score": 0, "best_desc": "", "best_pt": ""}

    for perm, desc in perms:
        test_perm(perm, desc, fres, fs)

    dt = time.time() - t0
    rate = fs["total"] / dt if dt > 0 else 0
    print(f"  Done: {fs['total']} configs in {dt:.1f}s ({rate:.0f}/s)")
    print(f"  Best score: {fs['best_score']}")
    if fs["best_desc"]:
        print(f"  Best: {fs['best_desc']}")

    if fres:
        print(f"  Above threshold: {len(fres)}")
        for sc, pt, desc, sb in sorted(fres, key=lambda x: -x[0])[:5]:
            print(f"    {sc}: {desc}")
            print(f"       {pt[:60]}...")

    all_results.extend(fres)
    gstats["total"] += fs["total"]
    if fs["best_score"] > gstats["best_score"]:
        gstats["best_score"] = fs["best_score"]
        gstats["best_desc"] = fs["best_desc"]
        gstats["best_pt"] = fs["best_pt"]


# ══════════════════════════════════════════════════════════════════════════
# Family 1: GF(97) Power Permutations
# ══════════════════════════════════════════════════════════════════════════

def gen_power_perms() -> List[Tuple[List[int], str]]:
    """perm[i] = (a * i^k + b) mod 97.  gcd(k,96)=1 => 32 valid exponents."""
    perms = []
    valid_k = [k for k in range(1, 96) if gcd(k, 96) == 1]

    # b values: HOROLOGE letter indices + clock numbers
    b_vals = sorted(set(
        [0, 1, 4, 6, 7, 8, 11, 12, 14, 17, 20, 24, 48, 60, 73, 96]
        + KEY_AZ + KEY_KA
    ))

    for k in valid_k:
        pows = [0] + [pow(i, k, N) for i in range(1, N)]
        for a in range(1, N):
            for b in b_vals:
                pos = [(a * pows[i] + b) % N for i in range(N)]
                if len(set(pos)) == N:
                    perms.append((pos, f"Pow(k={k},a={a},b={b})"))

    return perms


# ══════════════════════════════════════════════════════════════════════════
# Family 2: Modular Inverse Permutations
# ══════════════════════════════════════════════════════════════════════════

def gen_inverse_perms() -> List[Tuple[List[int], str]]:
    """perm[i] = (a * i^(-1) + b) mod 97.  9312 valid permutations."""
    perms = []
    inv_table = [0] + [pow(i, N - 2, N) for i in range(1, N)]

    for a in range(1, N):
        for b in range(N):
            pos = [(a * inv_table[i] + b) % N for i in range(N)]
            if len(set(pos)) == N:
                perms.append((pos, f"Inv(a={a},b={b})"))

    return perms


# ══════════════════════════════════════════════════════════════════════════
# Family 3: Swap-Based & Rotate+Reverse
# ══════════════════════════════════════════════════════════════════════════

def gen_swap_perms() -> List[Tuple[List[int], str]]:
    """Swap-every-8 + HOROLOGE-keyed swaps + rotate+segment-reverse."""
    perms = []

    # 3a. Swap every 8th position by distance k
    for k in range(1, N):
        for start in range(N):
            perm = list(range(N))
            for j in range(start, N, 8):
                target = (j + k) % N
                perm[j], perm[target] = perm[target], perm[j]
            if sorted(perm) == list(range(N)):
                perms.append((perm, f"Swap8(k={k},s={start})"))

    # 3b. HOROLOGE-keyed conditional swaps
    for offset in range(N):
        perm = list(range(N))
        for i in range(N):
            kv = KEY_AZ[i % 8]
            target = (i + kv) % N
            perm[i], perm[target] = perm[target], perm[i]
        if sorted(perm) == list(range(N)):
            perms.append((perm, f"HoroSwap(off={offset})"))

    # 3c. HOROLOGE-keyed pair swaps
    for offset in range(N):
        perm = list(range(N))
        for i in range(0, N, 2):
            kv = KEY_AZ[(i // 2) % 8]
            a_pos = (i + offset) % N
            b_pos = (a_pos + kv) % N
            perm[a_pos], perm[b_pos] = perm[b_pos], perm[a_pos]
        if sorted(perm) == list(range(N)):
            perms.append((perm, f"HoroPairSwap(off={offset})"))

    # 3d. Rotate + reverse segments
    for rot in range(N):
        for seg in [8, 12, 13, 24]:
            perm = [(i + rot) % N for i in range(N)]
            result = []
            for s in range(0, N, seg):
                segment = perm[s:min(s + seg, N)]
                result.extend(reversed(segment))
            if len(result) == N and len(set(result)) == N:
                perms.append((result, f"RotSegRev(rot={rot},seg={seg})"))

    return perms


# ══════════════════════════════════════════════════════════════════════════
# Family 4: 24-Hour Partitioning
# ══════════════════════════════════════════════════════════════════════════

def gen_partition_perms() -> List[Tuple[List[int], str]]:
    """Block-based reordering inspired by clock divisions."""
    perms = []

    for ps in [4, 6, 8, 12, 24]:
        ng = N // ps
        rem = N % ps
        groups = [list(range(g * ps, (g + 1) * ps)) for g in range(ng)]
        if rem > 0:
            groups.append(list(range(ng * ps, N)))

        # Group reverse, reverse order, both, interleave, rev interleave, zigzag
        for label, transform in [
            ("GrpRev", lambda gs: [list(reversed(g)) for g in gs]),
            ("RevOrd", lambda gs: list(reversed(gs))),
            ("RevBoth", lambda gs: [list(reversed(g)) for g in reversed(gs)]),
        ]:
            tg = transform(groups)
            perm = [x for g in tg for x in g]
            if len(perm) == N and len(set(perm)) == N:
                perms.append((perm, f"Part_{label}(ps={ps})"))

        # Interleave
        perm = []
        for j in range(ps):
            for g in groups:
                if j < len(g):
                    perm.append(g[j])
        if len(perm) == N and len(set(perm)) == N:
            perms.append((perm, f"Part_Interleave(ps={ps})"))

        perm = []
        for j in range(ps - 1, -1, -1):
            for g in groups:
                if j < len(g):
                    perm.append(g[j])
        if len(perm) == N and len(set(perm)) == N:
            perms.append((perm, f"Part_RevIntr(ps={ps})"))

        # Zigzag
        perm = []
        for j in range(ps):
            for gi, g in enumerate(groups):
                idx = j if gi % 2 == 0 else (len(g) - 1 - j)
                if 0 <= idx < len(g):
                    perm.append(g[idx])
        if len(perm) == N and len(set(perm)) == N:
            perms.append((perm, f"Part_Zigzag(ps={ps})"))

    # Region-first reading
    for s, e, lab in [(60, 73, "BC"), (21, 33, "ENE"), (20, 24, "Win20")]:
        region = list(range(s, min(e + 1, N)))
        rest = [i for i in range(N) if i not in region]
        for r_order, r_lab in [(region, ""), (list(reversed(region)), "_rev")]:
            for rest_o, rest_lab in [(rest, ""), (list(reversed(rest)), "_rrev")]:
                perm = r_order + rest_o
                if len(perm) == N and len(set(perm)) == N:
                    perms.append((perm, f"Region_{lab}{r_lab}{rest_lab}"))

    # Block-24 permutations (5! = 120 each direction)
    blocks = [list(range(i * 24, min((i + 1) * 24, N))) for i in range(5)]
    for bo in itertools.permutations(range(5)):
        perm = [x for bi in bo for x in blocks[bi]]
        if len(perm) == N:
            perms.append((perm, f"Blk24({','.join(map(str,bo))})"))

        perm_r = [x for bi in bo for x in reversed(blocks[bi])]
        if len(perm_r) == N:
            perms.append((perm_r, f"Blk24Rev({','.join(map(str,bo))})"))

    # Block-8 with HOROLOGE column order
    blocks8 = [list(range(i * 8, min((i + 1) * 8, N))) for i in range(13)]
    hco = sorted(range(8), key=lambda i: (KEYWORD[i], i))
    for co in [hco, list(reversed(hco)), list(range(8)), list(range(7, -1, -1))]:
        for rem_o in [list(range(8, 13)), list(range(12, 7, -1))]:
            full = list(co) + rem_o
            perm = [x for bi in full for x in blocks8[bi]]
            if len(perm) == N and len(set(perm)) == N:
                perms.append((perm, f"Blk8({','.join(map(str,full[:4]))},...)"))

            perm_r = [x for bi in full for x in reversed(blocks8[bi])]
            if len(perm_r) == N and len(set(perm_r)) == N:
                perms.append((perm_r, f"Blk8Rev({','.join(map(str,full[:4]))},...)"))

    return perms


# ══════════════════════════════════════════════════════════════════════════
# Family 5: Spiral/Rotational Grid Reading
# ══════════════════════════════════════════════════════════════════════════

def _spiral_cw(rows, cols, corner):
    """Clockwise spiral from corner, returns linear indices."""
    vis = [[False]*cols for _ in range(rows)]
    res = []
    dr, dc = [0,1,0,-1], [1,0,-1,0]
    starts = {'TL':(0,0,0),'TR':(0,cols-1,1),'BL':(rows-1,0,3),'BR':(rows-1,cols-1,2)}
    r, c, d = starts[corner]
    for _ in range(rows*cols):
        vis[r][c] = True
        res.append(r*cols+c)
        nr, nc = r+dr[d], c+dc[d]
        if 0<=nr<rows and 0<=nc<cols and not vis[nr][nc]:
            r, c = nr, nc
        else:
            d = (d+1)%4
            r, c = r+dr[d], c+dc[d]
    return res


def _spiral_ccw(rows, cols, corner):
    """Counter-clockwise spiral from corner."""
    vis = [[False]*cols for _ in range(rows)]
    res = []
    dm = {
        'TL': ([1,0,-1,0],[0,1,0,-1],0,0),
        'TR': ([0,-1,0,1],[-1,0,1,0],0,cols-1),
        'BL': ([0,1,0,-1],[1,0,-1,0],rows-1,0),
        'BR': ([-1,0,1,0],[0,-1,0,1],rows-1,cols-1),
    }
    dr, dc, r, c = dm[corner]
    d = 0
    for _ in range(rows*cols):
        if 0<=r<rows and 0<=c<cols and not vis[r][c]:
            vis[r][c] = True
            res.append(r*cols+c)
        nr, nc = r+dr[d], c+dc[d]
        if 0<=nr<rows and 0<=nc<cols and not vis[nr][nc]:
            r, c = nr, nc
        else:
            d = (d+1)%4
            r, c = r+dr[d], c+dc[d]
    return res


def _spiral_center(rows, cols):
    """Spiral from center outward."""
    vis = [[False]*cols for _ in range(rows)]
    res = []
    r, c = rows//2, cols//2
    dr, dc = [0,1,0,-1], [1,0,-1,0]
    d = 0
    vis[r][c] = True
    res.append(r*cols+c)
    step = 1
    while len(res) < rows*cols:
        for _ in range(2):
            for _ in range(step):
                r, c = r+dr[d], c+dc[d]
                if 0<=r<rows and 0<=c<cols and not vis[r][c]:
                    vis[r][c] = True
                    res.append(r*cols+c)
            d = (d+1)%4
        step += 1
        if step > rows+cols:
            break
    return res[:rows*cols]


def gen_spiral_perms() -> List[Tuple[List[int], str]]:
    perms = []
    grids = [(10,10),(7,14),(14,7),(11,9),(9,11),(8,13),(13,8)]
    corners = ['TL','TR','BL','BR']

    for rows, cols in grids:
        tot = rows * cols
        if tot < N:
            continue
        gl = f"{rows}x{cols}"

        for corner in corners:
            for spiral_fn, sl in [(_spiral_cw, "CW"), (_spiral_ccw, "CCW")]:
                order = spiral_fn(rows, cols, corner)
                if len(order) < N:
                    continue

                # Row-fill reading
                perm = [p for p in order if p < N]
                if len(perm) == N and len(set(perm)) == N:
                    perms.append((perm, f"Sp{sl}_{corner}_{gl}_rf"))

                # Reverse
                perm_r = [p for p in reversed(order) if p < N]
                if len(perm_r) == N and len(set(perm_r)) == N:
                    perms.append((perm_r, f"Sp{sl}_{corner}_{gl}_rf_rev"))

                # Spiral-fill (inverse)
                if sl == "CW":
                    inv = [0] * tot
                    for i, p in enumerate(order):
                        inv[p] = i
                    perm_sf = [inv[i] for i in range(N)]
                    if len(set(perm_sf)) == N and all(0 <= x < N for x in perm_sf):
                        perms.append((perm_sf, f"Sp{sl}_{corner}_{gl}_sf"))

                    # Column-fill
                    perm_cf = []
                    for sp in order:
                        r, c = sp // cols, sp % cols
                        ci = c * rows + r
                        if ci < N:
                            perm_cf.append(ci)
                    if len(perm_cf) == N and len(set(perm_cf)) == N:
                        perms.append((perm_cf, f"Sp{sl}_{corner}_{gl}_cf"))

        # Center spiral
        if abs(rows - cols) <= 3:
            order = _spiral_center(rows, cols)
            if len(order) >= N:
                perm = [p for p in order if p < N]
                if len(perm) == N and len(set(perm)) == N:
                    perms.append((perm, f"SpCtr_{gl}_rf"))

                perm_r = [p for p in reversed(order) if p < N]
                if len(perm_r) == N and len(set(perm_r)) == N:
                    perms.append((perm_r, f"SpCtr_{gl}_rf_rev"))

    return perms


# ══════════════════════════════════════════════════════════════════════════
# Family 6: Columnar Transposition with HOROLOGE
# ══════════════════════════════════════════════════════════════════════════

def gen_columnar_perms() -> List[Tuple[List[int], str]]:
    perms = []
    hco = sorted(range(8), key=lambda i: (KEYWORD[i], i))
    hco_r = list(reversed(hco))

    for ncols, dl in [(8,"8c"),(10,"10c"),(11,"11c"),(13,"13c"),(14,"14c"),(24,"24c")]:
        nrows = (N + ncols - 1) // ncols

        # Column orders
        if ncols == 8:
            cos = [hco, hco_r, list(range(8)), list(range(7,-1,-1))]
        else:
            ident = list(range(ncols))
            rev = list(range(ncols-1,-1,-1))
            ext_kw = (KEYWORD * ((ncols//8)+2))[:ncols]
            hco_ext = sorted(range(ncols), key=lambda i: (ext_kw[i], i))
            cos = [ident, rev, hco_ext]

        for co in cos:
            # Standard columnar
            perm = []
            for c in co:
                for r in range(nrows):
                    p = r * ncols + c
                    if p < N:
                        perm.append(p)
            if len(perm) == N and len(set(perm)) == N:
                perms.append((perm, f"Col_{dl}({co[:4]})"))

            # Columns read bottom-to-top
            perm2 = []
            for c in co:
                cp = [r*ncols+c for r in range(nrows) if r*ncols+c < N]
                perm2.extend(reversed(cp))
            if len(perm2) == N and len(set(perm2)) == N:
                perms.append((perm2, f"ColRev_{dl}({co[:4]})"))

        # Zigzag rows
        perm = []
        for r in range(nrows):
            rp = [r*ncols+c for c in range(ncols) if r*ncols+c < N]
            if r % 2 == 1:
                rp = list(reversed(rp))
            perm.extend(rp)
        if len(perm) == N and len(set(perm)) == N:
            perms.append((perm, f"Zigzag_{dl}"))

        # Row reverse
        perm = []
        for r in range(nrows-1,-1,-1):
            for c in range(ncols):
                p = r*ncols+c
                if p < N:
                    perm.append(p)
        if len(perm) == N and len(set(perm)) == N:
            perms.append((perm, f"RowRev_{dl}"))

        # Diagonal TL->BR and TR->BL
        for lab, cfn in [("DTlbr", lambda d,r: d-r), ("DTrbl", lambda d,r: (ncols-1)-(d-r))]:
            perm = []
            for d in range(nrows+ncols-1):
                for r in range(nrows):
                    c = cfn(d, r)
                    if 0 <= c < ncols:
                        p = r*ncols+c
                        if p < N:
                            perm.append(p)
            if len(perm) == N and len(set(perm)) == N:
                perms.append((perm, f"{lab}_{dl}"))

    return perms


# ══════════════════════════════════════════════════════════════════════════
# Family 7: Composed Permutations
# ══════════════════════════════════════════════════════════════════════════

def gen_composed_perms() -> List[Tuple[List[int], str]]:
    """Compose pairs of simple permutations from different families."""
    perms = []

    rev = list(range(N-1,-1,-1))

    # Building blocks: affine maps with clock multipliers
    affines = []
    for a in [2, 3, 5, 7, 12, 24, 48, 60, 73, 96]:
        for b in [0, 1, 8, 24]:
            perm = [(a*i+b) % N for i in range(N)]
            affines.append((perm, f"A({a},{b})"))

    # A few spirals
    spirals = []
    for corner in ['TL', 'TR', 'BL', 'BR']:
        order = _spiral_cw(10, 10, corner)
        perm = [p for p in order if p < N]
        if len(perm) == N and len(set(perm)) == N:
            spirals.append((perm, f"Sp{corner}"))

    # A few columnar
    cols = []
    for nc in [8, 10, 13]:
        nr = (N + nc - 1) // nc
        perm = []
        for c in range(nc):
            for r in range(nr):
                p = r*nc+c
                if p < N:
                    perm.append(p)
        if len(perm) == N and len(set(perm)) == N:
            cols.append((perm, f"C{nc}"))

    # Modular inverse
    inv_table = [0] + [pow(i, N-2, N) for i in range(1, N)]
    inv_perm = inv_table
    if len(set(inv_perm)) == N:
        inv_perms = [(inv_perm, "ModInv")]
    else:
        inv_perms = []

    blocks = [(rev, "Rev")] + affines + spirals + cols + inv_perms

    for (p1, l1), (p2, l2) in itertools.product(blocks, repeat=2):
        if l1 == l2:
            continue
        c = compose_perms(p1, p2)
        if len(set(c)) == N:
            perms.append((c, f"{l1}+{l2}"))

        # Also compose with inverse
        ip2 = invert_perm(p2)
        c2 = compose_perms(p1, ip2)
        if len(set(c2)) == N:
            perms.append((c2, f"{l1}+inv({l2})"))

    return perms


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def attack(ciphertext: str, **params) -> List[Tuple[float, str, str]]:
    """Standard attack() interface."""
    all_res: list = []
    gs = {"total": 0, "best_score": 0, "best_desc": "", "best_pt": ""}

    families = [
        ("1. GF(97) Power Permutations", gen_power_perms),
        ("2. Modular Inverse Permutations", gen_inverse_perms),
        ("3. Swap/Rotate+Reverse", gen_swap_perms),
        ("4. 24-Hour Partitioning", gen_partition_perms),
        ("5. Spiral Grid Reading", gen_spiral_perms),
        ("6. Columnar Transposition", gen_columnar_perms),
        ("7. Composed Permutations", gen_composed_perms),
    ]

    for name, gen in families:
        print(f"\nGenerating {name}...")
        t_gen = time.time()
        pms = gen()
        print(f"  Generation: {time.time()-t_gen:.1f}s")
        run_family(name, pms, all_res, gs)

    # Final summary
    print(f"\n{'='*70}")
    print("FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"Total configs tested: {gs['total']}")
    print(f"Best score: {gs['best_score']}")
    if gs["best_desc"]:
        print(f"Best: {gs['best_desc']}")
        print(f"Best PT: {gs['best_pt']}")

    if all_res:
        print(f"\nAll above threshold ({REPORT_THRESHOLD}):")
        for sc, pt, desc, sb in sorted(all_res, key=lambda x: -x[0]):
            print(f"  {sc}: {desc}")
            print(f"     {pt}")
            print(f"     {sb.summary}")
    else:
        print(f"\nNo results above threshold ({REPORT_THRESHOLD})")

    return [(float(sc), pt, desc) for sc, pt, desc, sb in all_res]


if __name__ == "__main__":
    print(f"CT: {CT}")
    print(f"Len: {CT_LEN}")
    print(f"Keyword: {KEYWORD}")
    print(f"KEY_AZ: {KEY_AZ}")
    print(f"KEY_KA: {KEY_KA}")
    print(f"Decrypt configs: {len(DECRYPT_CONFIGS)}")
    print()

    t0 = time.time()
    attack(CT)
    print(f"\nTotal wall time: {time.time()-t0:.1f}s")
