#!/usr/bin/env python3
"""
E-S-05: Algebraic Fractionation & Hill Cipher Sweep

Deterministic algebraic analysis:
  Part A: Hill cipher n=2,3,4 — solve from crib blocks (mod 26)
  Part B: Trifid 3x3x3 periods 2-49 — algebraic contradiction check
  Part C: Bifid 5x5 — impossibility proof (26 unique CT letters)
  Part D: Bifid 6x6 periods 2-49 — algebraic contradiction check

All deterministic.  No randomness.  No heuristics.

Usage: PYTHONPATH=src python3 -u scripts/e_s_05_algebraic_fractionation.py
"""

import sys, os, json, hashlib, time
from datetime import datetime, timezone
from math import gcd
from itertools import combinations

# ── Constants ────────────────────────────────────────────────────────────────

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
CT_NUM = [ord(c) - ord('A') for c in CT]
CTLEN = len(CT)  # 97

CRIB_RANGES = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
PT_NUM = [None] * CTLEN
for _start, _text in CRIB_RANGES:
    for _i, _ch in enumerate(_text):
        PT_NUM[_start + _i] = ord(_ch) - ord('A')

CRIB_POSITIONS = [i for i in range(CTLEN) if PT_NUM[i] is not None]
print(f"[init] CT length={CTLEN}, crib positions={len(CRIB_POSITIONS)}")

# ── Math helpers ─────────────────────────────────────────────────────────────

def ext_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = ext_gcd(b % a, a)
    return g, y - (b // a) * x, x

def mod_inv(a, m):
    g, x, _ = ext_gcd(a % m, m)
    return x % m if g == 1 else None

def det_nxn(M, n, m):
    """Determinant of n×n matrix M modulo m (Leibniz / cofactor expansion)."""
    if n == 1:
        return M[0][0] % m
    if n == 2:
        return (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % m
    d = 0
    for j in range(n):
        minor = [[M[r][c] for c in range(n) if c != j] for r in range(1, n)]
        d = (d + ((-1) ** j) * M[0][j] * det_nxn(minor, n - 1, m)) % m
    return d % m

def adjugate(M, n, m):
    """Classical adjoint (transposed cofactor matrix) modulo m."""
    adj = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [[M[r][c] for c in range(n) if c != j]
                     for r in range(n) if r != i]
            adj[j][i] = (((-1) ** (i + j)) * det_nxn(minor, n - 1, m)) % m
    return adj

def mat_mul(A, B, n, m):
    return [[(sum(A[i][k] * B[k][j] for k in range(n))) % m
             for j in range(n)] for i in range(n)]

def mat_vec(M, v, n, m):
    return [(sum(M[i][j] * v[j] for j in range(n))) % m for i in range(n)]

# ── Part A: Hill Cipher ──────────────────────────────────────────────────────

def hill_extract_blocks(n, offset):
    """Extract all complete PT/CT block pairs of size n at given offset."""
    blocks = []
    for bs in range(offset, CTLEN, n):
        if bs + n > CTLEN:
            break
        pt_blk, ct_blk = [], []
        ok = True
        for i in range(n):
            if PT_NUM[bs + i] is None:
                ok = False
                break
            pt_blk.append(PT_NUM[bs + i])
            ct_blk.append(CT_NUM[bs + i])
        if ok:
            blocks.append((bs, pt_blk, ct_blk))
    return blocks

def hill_solve(n, offset):
    """
    Try to find an n×n Hill cipher matrix (mod 26) consistent with all
    crib blocks at the given offset.

    Returns (status, info_dict).
    status: 'eliminated' | 'solution' | 'underdetermined'
    """
    blocks = hill_extract_blocks(n, offset)
    if len(blocks) < n:
        return ('underdetermined', {'blocks': len(blocks), 'need': n})

    # Try every n-subset of blocks as the "basis" for solving M
    best_mismatch = len(blocks)
    tried_invertible = 0

    for combo in combinations(range(len(blocks)), n):
        # P[row][col] = PT value at row-th element of col-th block
        P = [[blocks[combo[j]][1][i] for j in range(n)] for i in range(n)]
        C = [[blocks[combo[j]][2][i] for j in range(n)] for i in range(n)]

        d = det_nxn(P, n, 26)
        dinv = mod_inv(d, 26)
        if dinv is None:
            continue
        tried_invertible += 1

        adj_P = adjugate(P, n, 26)
        Pinv = [[(adj_P[i][j] * dinv) % 26 for j in range(n)] for i in range(n)]
        M = mat_mul(C, Pinv, n, 26)

        # Verify against ALL blocks
        mismatches = 0
        for _, pt_b, ct_b in blocks:
            if mat_vec(M, pt_b, n, 26) != ct_b:
                mismatches += 1

        if mismatches == 0:
            dM = det_nxn(M, n, 26)
            if mod_inv(dM, 26) is not None:
                # SOLUTION — decrypt full CT
                plaintext = hill_decrypt(M, n)
                return ('solution', {
                    'matrix': M, 'det_M': dM,
                    'blocks_verified': len(blocks),
                    'plaintext': plaintext
                })
            else:
                return ('non_invertible_M',
                        {'matrix': M, 'det_M': dM, 'blocks': len(blocks)})

        best_mismatch = min(best_mismatch, mismatches)

    if tried_invertible == 0:
        return ('eliminated', {
            'reason': 'no invertible PT submatrix among all block combos',
            'blocks': len(blocks),
            'combos_tried': len(list(combinations(range(len(blocks)), n)))
        })

    return ('eliminated', {
        'reason': f'best matrix still has {best_mismatch}/{len(blocks)} mismatches',
        'blocks': len(blocks),
        'invertible_combos': tried_invertible,
        'best_mismatch': best_mismatch
    })

def hill_decrypt(M, n):
    """Decrypt full CT with Hill matrix M (mod 26). Returns plaintext string."""
    dM = det_nxn(M, n, 26)
    dinv = mod_inv(dM, 26)
    adj_M = adjugate(M, n, 26)
    Minv = [[(adj_M[i][j] * dinv) % 26 for j in range(n)] for i in range(n)]

    pt = []
    for bs in range(0, CTLEN, n):
        blk = CT_NUM[bs:bs + n]
        if len(blk) < n:
            # Incomplete final block — leave as-is
            pt.extend(blk)
        else:
            pt.extend(mat_vec(Minv, blk, n, 26))
    return ''.join(chr(v + ord('A')) for v in pt)

def run_part_a():
    """Hill cipher n=2,3,4 — algebraic solve from crib blocks."""
    print("\n" + "=" * 60)
    print("PART A: Hill Cipher  n=2, 3, 4  (mod 26)")
    print("=" * 60)

    results = []
    for n in [2, 3, 4]:
        for offset in range(n):
            status, info = hill_solve(n, offset)
            tag = {'eliminated': 'X', 'solution': '*', 'underdetermined': '?',
                   'non_invertible_M': '~'}
            sym = tag.get(status, '?')
            blk_count = info.get('blocks', info.get('blocks_verified', '?'))
            detail_str = info.get('reason', '')
            if status == 'eliminated':
                detail_str = info.get('reason', '')
            elif status == 'solution':
                detail_str = f"SOLUTION FOUND — decrypt in artifacts"
            print(f"  [{sym}] Hill {n}x{n} off={offset}: {status}  "
                  f"(blocks={blk_count}) {detail_str[:50]}")
            results.append({
                'n': n, 'offset': offset, 'status': status,
                'info': {k: v for k, v in info.items() if k != 'plaintext'}
            })
            if status == 'solution':
                print(f"      PT[0:40] = {info['plaintext'][:40]}...")

    summary = {
        'configs': len(results),
        'eliminated': sum(1 for r in results if r['status'] == 'eliminated'),
        'solutions': sum(1 for r in results if r['status'] == 'solution'),
        'underdetermined': sum(1 for r in results if r['status'] == 'underdetermined'),
        'detail': results,
    }
    e, s, u = summary['eliminated'], summary['solutions'], summary['underdetermined']
    print(f"\n  Hill summary: {e} eliminated, {s} solutions, {u} underdetermined")
    return summary

# ── Union-Find ───────────────────────────────────────────────────────────────

class UnionFind:
    def __init__(self):
        self.parent = {}
        self.rank = {}

    def find(self, x):
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0
        # Path compression
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1

# ── Fractionation checker (Bifid / Trifid) ──────────────────────────────────

def find_full_groups(period):
    """Return list of (start_pos, pt_nums, ct_nums) for fully-known groups."""
    groups = []
    for gs in range(0, CTLEN, period):
        ge = gs + period
        if ge > CTLEN:
            break
        pt_grp, ct_grp = [], []
        ok = True
        for pos in range(gs, ge):
            if PT_NUM[pos] is None:
                ok = False
                break
            pt_grp.append(PT_NUM[pos])
            ct_grp.append(CT_NUM[pos])
        if ok:
            groups.append((gs, pt_grp, ct_grp))
    return groups

def check_fractionation(k, period, grid_dims):
    """
    Check algebraic consistency of a fractionation cipher with cribs.

    k : number of coordinate dimensions (2=Bifid, 3=Trifid)
    period : block size
    grid_dims : tuple of dimension sizes, e.g. (6,6) or (3,3,3)

    Returns (eliminated: bool, reason: str, details: dict)
    """
    coord_names = ['R', 'C'] if k == 2 else ['L', 'R', 'C']
    assert len(grid_dims) == k

    groups = find_full_groups(period)
    if not groups:
        return (False, 'no_data', {'groups': 0})

    uf = UnionFind()

    for _gs, pt_grp, ct_grp in groups:
        p = len(pt_grp)  # == period

        # The fractionation concatenates k coordinate sequences of length p,
        # then regroups them into p k-tuples.
        #
        # Concatenated val[j] for j in [0, k*p):
        #   coord_type_idx = j // p      (which coordinate: 0..k-1)
        #   pt_index       = j % p       (which letter in the group)
        #   variable       = (pt_grp[pt_index], coord_names[coord_type_idx])
        #
        # k-tuple i (i=0..p-1) occupies positions k*i .. k*i+k-1 and
        # maps to CT letter ct_grp[i] with coordinates coord_names[0..k-1].

        for i in range(p):
            for d in range(k):
                j_flat = k * i + d
                ct_idx = j_flat // p       # which coordinate type of PT letter
                pt_idx = j_flat % p        # which PT letter in group

                pt_letter = pt_grp[pt_idx]
                pt_coord = coord_names[ct_idx]
                ct_coord = coord_names[d]

                uf.union((pt_letter, pt_coord), (ct_grp[i], ct_coord))

    # Collect all involved letters and their coordinate equivalence classes
    all_letters = set()
    for _gs, pt_grp, ct_grp in groups:
        all_letters.update(pt_grp)
        all_letters.update(ct_grp)

    letter_classes = {}
    for letter in all_letters:
        letter_classes[letter] = tuple(uf.find((letter, cn)) for cn in coord_names)

    # ── Check 1: same-cell contradiction ──
    # Two different letters with identical class tuple → forced to same cell
    class_to_letters = {}
    for letter, cls in letter_classes.items():
        class_to_letters.setdefault(cls, []).append(letter)

    for cls, letters in class_to_letters.items():
        if len(letters) > 1:
            names = sorted(chr(l + 65) for l in letters)
            return (True, 'same_cell', {
                'letters': names,
                'count': len(letters),
                'groups': len(groups),
                'proof': f"Letters {','.join(names)} forced to same cell"
            })

    # ── Check 2: pigeonhole on (k-1)-dimensional projections ──
    # For each dimension to "project out", count letters sharing the remaining dims.
    # If count > grid_dims[projected_dim], impossible.
    for skip_dim in range(k):
        proj_to_letters = {}
        for letter, cls in letter_classes.items():
            proj = tuple(cls[d] for d in range(k) if d != skip_dim)
            proj_to_letters.setdefault(proj, []).append(letter)

        dim_size = grid_dims[skip_dim]
        for proj, letters in proj_to_letters.items():
            if len(letters) > dim_size:
                names = sorted(chr(l + 65) for l in letters)
                return (True, f'pigeonhole_dim{skip_dim}', {
                    'letters': names,
                    'count': len(letters),
                    'dim_size': dim_size,
                    'groups': len(groups),
                    'proof': (f"{len(letters)} letters share "
                              f"{''.join(coord_names[d] for d in range(k) if d != skip_dim)}"
                              f"-projection but only {dim_size} slots in dim "
                              f"{coord_names[skip_dim]}")
                })

    # No contradiction found — collect diagnostics
    max_sharings = {}
    for skip_dim in range(k):
        proj_to_letters = {}
        for letter, cls in letter_classes.items():
            proj = tuple(cls[d] for d in range(k) if d != skip_dim)
            proj_to_letters.setdefault(proj, []).append(letter)
        max_sharings[coord_names[skip_dim]] = max(
            len(v) for v in proj_to_letters.values())

    return (False, 'no_contradiction', {
        'groups': len(groups),
        'letters': len(all_letters),
        'max_sharings': max_sharings
    })

def run_part_b():
    """Trifid 3×3×3, periods 2-49."""
    print("\n" + "=" * 60)
    print("PART B: Trifid 3x3x3 (periods 2-49)")
    print("=" * 60)

    results = []
    elim_periods = []
    feas_periods = []
    nodata_periods = []

    for p in range(2, 50):
        eliminated, reason, details = check_fractionation(3, p, (3, 3, 3))
        entry = {'period': p, 'eliminated': eliminated,
                 'reason': reason, 'details': details}
        results.append(entry)

        if eliminated:
            elim_periods.append(p)
            proof = details.get('proof', reason)
            print(f"  p={p:2d}: [X] {proof}")
        elif details.get('groups', 0) > 0:
            feas_periods.append(p)
            ms = details.get('max_sharings', {})
            print(f"  p={p:2d}: [?] not eliminated  "
                  f"(groups={details['groups']}, max_share={ms})")
        else:
            nodata_periods.append(p)

    print(f"\n  Trifid summary: {len(elim_periods)} eliminated, "
          f"{len(feas_periods)} not eliminated (with data), "
          f"{len(nodata_periods)} no fully-known groups")
    if nodata_periods:
        print(f"  No-data periods: {nodata_periods}")

    return {
        'eliminated_periods': elim_periods,
        'feasible_periods': feas_periods,
        'no_data_periods': nodata_periods,
        'detail': results
    }

def run_part_c():
    """Bifid 5×5 impossibility proof."""
    print("\n" + "=" * 60)
    print("PART C: Bifid 5x5 Impossibility Proof")
    print("=" * 60)

    unique = sorted(set(CT))
    n_unique = len(unique)
    impossible = n_unique > 25
    proof = (f"K4 CT contains {n_unique} unique letters "
             f"({','.join(unique)}). A 5x5 Polybius grid holds at most 25 "
             f"(one letter pair merged). Since all 26 appear, no 5x5 Bifid "
             f"variant can produce this CT.")

    if impossible:
        print(f"  [X] IMPOSSIBLE: {proof}")
    else:
        print(f"  [?] Not proven impossible ({n_unique} unique)")

    return {
        'unique_ct': n_unique,
        'letters': unique,
        'eliminated': impossible,
        'proof': proof
    }

def run_part_d():
    """Bifid 6×6, periods 2-49."""
    print("\n" + "=" * 60)
    print("PART D: Bifid 6x6 (periods 2-49)")
    print("=" * 60)

    results = []
    elim_periods = []
    feas_periods = []
    nodata_periods = []

    for p in range(2, 50):
        eliminated, reason, details = check_fractionation(2, p, (6, 6))
        entry = {'period': p, 'eliminated': eliminated,
                 'reason': reason, 'details': details}
        results.append(entry)

        if eliminated:
            elim_periods.append(p)
            proof = details.get('proof', reason)
            print(f"  p={p:2d}: [X] {proof}")
        elif details.get('groups', 0) > 0:
            feas_periods.append(p)
            ms = details.get('max_sharings', {})
            print(f"  p={p:2d}: [?] not eliminated  "
                  f"(groups={details['groups']}, max_share={ms})")
        else:
            nodata_periods.append(p)

    print(f"\n  Bifid 6x6 summary: {len(elim_periods)} eliminated, "
          f"{len(feas_periods)} not eliminated (with data), "
          f"{len(nodata_periods)} no fully-known groups")

    return {
        'eliminated_periods': elim_periods,
        'feasible_periods': feas_periods,
        'no_data_periods': nodata_periods,
        'detail': results
    }

# ── Report writer ────────────────────────────────────────────────────────────

def write_report(all_results, elapsed):
    """Write human-readable markdown report."""
    pa = all_results['A_hill']
    pb = all_results['B_trifid']
    pc = all_results['C_bifid_5x5']
    pd = all_results['D_bifid_6x6']

    lines = [
        "# E-S-05: Algebraic Fractionation & Hill Cipher Sweep — Report",
        "",
        f"**Elapsed:** {elapsed:.2f}s  ",
        f"**Deterministic:** yes (no randomness)  ",
        "",
        "## Part A: Hill Cipher n=2,3,4 (mod 26)",
        "",
        f"- Configs tested: {pa['configs']}",
        f"- Eliminated: {pa['eliminated']}",
        f"- Solutions: {pa['solutions']}",
        f"- Underdetermined: {pa['underdetermined']}",
        "",
    ]

    # Hill detail table
    lines.append("| n | offset | status | detail |")
    lines.append("|---|--------|--------|--------|")
    for r in pa['detail']:
        info_str = str(r['info']).replace('|', '\\|')[:60]
        lines.append(f"| {r['n']} | {r['offset']} | {r['status']} | {info_str} |")

    lines += [
        "",
        "## Part B: Trifid 3x3x3 (periods 2-49)",
        "",
        f"- Eliminated: {len(pb['eliminated_periods'])} periods",
        f"- Not eliminated (with crib data): {len(pb['feasible_periods'])} periods",
        f"- No fully-known groups: {len(pb['no_data_periods'])} periods",
        "",
        f"**Eliminated periods:** {pb['eliminated_periods']}",
        "",
        f"**Feasible periods (need deeper analysis):** {pb['feasible_periods']}",
        "",
        f"**No-data periods:** {pb['no_data_periods']}",
        "",
        "## Part C: Bifid 5x5",
        "",
        f"- **{'ELIMINATED' if pc['eliminated'] else 'NOT eliminated'}**",
        f"- {pc['proof']}",
        "",
        "## Part D: Bifid 6x6 (periods 2-49)",
        "",
        f"- Eliminated: {len(pd['eliminated_periods'])} periods",
        f"- Not eliminated (with crib data): {len(pd['feasible_periods'])} periods",
        f"- No fully-known groups: {len(pd['no_data_periods'])} periods",
        "",
        f"**Eliminated periods:** {pd['eliminated_periods']}",
        "",
        f"**Feasible periods (need deeper analysis):** {pd['feasible_periods']}",
        "",
        "## Summary of New Eliminations",
        "",
    ]

    # Build summary
    new_elims = []
    if pa['eliminated'] > 0:
        new_elims.append(f"- Hill cipher n=2,3,4 (all offsets, mod 26): "
                         f"**{pa['eliminated']} configs ELIMINATED**")
    if pa['solutions'] > 0:
        new_elims.append(f"- Hill cipher: **{pa['solutions']} SOLUTIONS FOUND** "
                         f"(check artifacts)")
    if pc['eliminated']:
        new_elims.append("- Bifid 5x5 (all variants): **ELIMINATED** "
                         "(26 unique CT letters)")
    if pb['eliminated_periods']:
        new_elims.append(f"- Trifid 3x3x3: **{len(pb['eliminated_periods'])} "
                         f"periods ELIMINATED** out of 48")
    if pd['eliminated_periods']:
        new_elims.append(f"- Bifid 6x6: **{len(pd['eliminated_periods'])} "
                         f"periods ELIMINATED** out of 48")

    lines.extend(new_elims if new_elims else ["- No new eliminations"])
    lines += [
        "",
        "## Repro Command",
        "",
        "```bash",
        "PYTHONPATH=src python3 -u scripts/e_s_05_algebraic_fractionation.py",
        "```",
        "",
        f"Artifacts: `artifacts/e_s_05_results.json`",
    ]

    report_path = "reports/e_s_05_report.md"
    with open(report_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    return report_path

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[start] E-S-05 Algebraic Fractionation & Hill Cipher Sweep")
    print(f"[start] timestamp={ts}")

    all_results = {}

    # Part A
    all_results['A_hill'] = run_part_a()

    # Part B
    all_results['B_trifid'] = run_part_b()

    # Part C
    all_results['C_bifid_5x5'] = run_part_c()

    # Part D
    all_results['D_bifid_6x6'] = run_part_d()

    elapsed = time.time() - t0

    # ── Write artifacts ──
    os.makedirs('artifacts', exist_ok=True)
    os.makedirs('reports', exist_ok=True)

    full_output = {
        'experiment': 'E-S-05',
        'description': 'Algebraic Fractionation & Hill Cipher Sweep',
        'timestamp': ts,
        'elapsed_seconds': round(elapsed, 3),
        'parts': all_results
    }

    results_path = 'artifacts/e_s_05_results.json'
    with open(results_path, 'w') as f:
        json.dump(full_output, f, indent=2, default=str)

    manifest = {
        'experiment': 'E-S-05',
        'description': 'Algebraic Fractionation & Hill Cipher Sweep',
        'timestamp': ts,
        'script': 'scripts/e_s_05_algebraic_fractionation.py',
        'repro': 'PYTHONPATH=src python3 -u scripts/e_s_05_algebraic_fractionation.py',
        'seed': None,
        'deterministic': True,
        'elapsed_seconds': round(elapsed, 3),
        'inputs': {
            'ciphertext': CT,
            'cribs': {str(s): t for s, t in CRIB_RANGES},
        }
    }
    manifest_path = 'artifacts/run_manifest.json'
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    report_path = write_report(all_results, elapsed)

    # ── Hashes ──
    hash_path = 'artifacts/hashes.txt'
    with open(hash_path, 'w') as f:
        for fp in [results_path, manifest_path, report_path]:
            with open(fp, 'rb') as rf:
                h = hashlib.sha256(rf.read()).hexdigest()
            f.write(f"{h}  {fp}\n")

    # ── Final summary ──
    print("\n" + "=" * 60)
    print(f"DONE  elapsed={elapsed:.2f}s")
    print(f"  artifacts: {results_path}")
    print(f"  manifest:  {manifest_path}")
    print(f"  report:    {report_path}")
    print(f"  hashes:    {hash_path}")
    print("=" * 60)

if __name__ == '__main__':
    main()
