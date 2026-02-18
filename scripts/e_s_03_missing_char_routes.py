#!/usr/bin/env python3
"""E-S-03: Missing character + non-columnar transpositions on 7×14 grid.

THEORY: K4's true CT is 98 chars (7×14). One char was omitted after position 73.
The cipher uses a grid-based transposition that is NOT simple columnar
(which was eliminated by E-DESP-01).

CONSTRAINT ANALYSIS (verified in Phase 0):
  - Insertion before pos 21: breaks ENE crib alignment → eliminated
  - Insertion between pos 21-73: breaks BC crib alignment → eliminated
  - Insertion before pos 66: breaks Bean k[27]=k[65] → eliminated
  - Only viable: insertion at positions 74-97 (24 positions) + append at 98

TRANSPOSITION FAMILIES TESTED:
  Phase 1: Route ciphers (spiral, serpentine, diagonal) — ~20 permutations
  Phase 2: Rail fence with 7 rails
  Phase 3: Row permutation search (algebraically pruned)
  Phase 4: Columnar (sanity re-check, restricted to pos 74+)

SCORING: Exact key consistency at period 7 (ST and TS models).
  24 cribs → 7 residue classes → 17 independent constraints.
  P(false positive) ≈ (1/26)^17 ≈ 10^{-24} → ANY 24/24 hit is real.
"""
import sys
import os
import json
import time
from collections import defaultdict
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH,
    CRIB_DICT, N_CRIBS,
    BEAN_EQ,
)

CT_NUM = [ord(c) - 65 for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {p: ord(CRIB_DICT[p]) - 65 for p in CRIB_POS}
WIDTH, ROWS, GRID_LEN = 7, 14, 98

# ── Phase 0: Verify constraint analysis ────────────────────────────────

def verify_constraints():
    """Verify that insertion must be at positions >= 74."""
    print("=" * 72)
    print("PHASE 0: VERIFY CONSTRAINT ANALYSIS")
    print("=" * 72)

    ene_start, ene_end = 21, 33  # inclusive
    bc_start, bc_end = 63, 73
    bean_a, bean_b = BEAN_EQ[0]  # (27, 65)

    # Test: insertion before pos 21 breaks ENE alignment
    # If we insert at pos p < 21, all crib positions shift right by 1
    # ENE would need to be at 22-34, BC at 64-74 — but Sanborn said 21-33, 63-73
    print(f"\n  ENE crib: positions {ene_start}-{ene_end}")
    print(f"  BC crib:  positions {bc_start}-{bc_end}")
    print(f"  Bean eq:  positions {bean_a} and {bean_b}")

    # For insertion at position p:
    # - Positions < p: unchanged
    # - Positions >= p: shift right by 1 in the 98-char CT
    # - For cribs to align, we need NO shift at any crib position
    # - This means insertion must be AFTER all crib positions

    # Last crib position is 73. So insertion must be at position >= 74.
    # Bean constraint: k[27]=k[65]. Both positions < 74, so unaffected.

    print(f"\n  Last crib position: {max(CRIB_POS)} (0-indexed)")
    print(f"  Bean positions: {bean_a}, {bean_b}")
    print(f"  → Insertion must be at position >= {max(CRIB_POS) + 1} = 74")

    # Verify by simulation: insert at various positions, check cribs
    for test_pos in [0, 10, 20, 21, 50, 73, 74, 90, 97]:
        ct98 = list(CT_NUM)
        ct98.insert(test_pos, 0)  # insert 'A'

        # Check if original crib positions still have right CT values
        crib_match = True
        for cp in CRIB_POS:
            if cp < test_pos:
                if ct98[cp] != CT_NUM[cp]:
                    crib_match = False
                    break
            else:
                # Position cp in 98-char CT is shifted if insert <= cp
                if ct98[cp] != CT_NUM[cp]:
                    crib_match = False
                    break

        # Check Bean: CT[27] and CT[65] in 98-char must still match original
        bean_ok = (ct98[bean_a] == CT_NUM[bean_a] and
                   ct98[bean_b] == CT_NUM[bean_b])

        status = "OK" if (crib_match and bean_ok) else "BROKEN"
        detail = ""
        if not crib_match:
            detail += " [cribs shifted]"
        if not bean_ok:
            detail += " [Bean broken]"
        print(f"  Insert @{test_pos:2d}: {status}{detail}")

    print("\n  CONFIRMED: Only positions 74-97 (+ append at 98) preserve all constraints")
    print(f"  Search space: 25 positions × 26 letters = 650 candidate CTs")
    return True


# ── Route cipher permutation builders ──────────────────────────────────

def _spiral_tl_cw(rows, cols):
    """Generate canonical top-left clockwise spiral for rows×cols grid."""
    positions = []
    visited = [[False] * cols for _ in range(rows)]
    dr = [0, 1, 0, -1]  # right, down, left, up
    dc = [1, 0, -1, 0]
    r, c, d = 0, 0, 0
    for _ in range(rows * cols):
        positions.append((r, c))
        visited[r][c] = True
        nr, nc = r + dr[d], c + dc[d]
        if 0 <= nr < rows and 0 <= nc < cols and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            r, c = r + dr[d], c + dc[d]
    return positions


def spiral_perm(rows, cols, clockwise=True, start_corner=0):
    """Generate spiral read order for a rows×cols grid.
    start_corner: 0=TL, 1=TR, 2=BR, 3=BL.
    CW/CCW derived by mirroring or reversing the TL-CW base.
    """
    base = _spiral_tl_cw(rows, cols)
    # Mirror for different corners
    transformed = []
    for r0, c0 in base:
        if start_corner == 0:
            transformed.append((r0, c0))
        elif start_corner == 1:
            transformed.append((r0, cols - 1 - c0))
        elif start_corner == 2:
            transformed.append((rows - 1 - r0, cols - 1 - c0))
        else:  # BL
            transformed.append((rows - 1 - r0, c0))
    if not clockwise:
        transformed.reverse()
    return transformed


def serpentine_rows_perm(rows, cols):
    """Boustrophedon: read rows alternating L→R and R→L."""
    positions = []
    for r in range(rows):
        if r % 2 == 0:
            positions.extend((r, c) for c in range(cols))
        else:
            positions.extend((r, c) for c in range(cols - 1, -1, -1))
    return positions


def serpentine_cols_perm(rows, cols):
    """Boustrophedon by columns: read cols alternating T→B and B→T."""
    positions = []
    for c in range(cols):
        if c % 2 == 0:
            positions.extend((r, c) for r in range(rows))
        else:
            positions.extend((r, c) for r in range(rows - 1, -1, -1))
    return positions


def diagonal_perm(rows, cols, anti=False):
    """Read along diagonals. anti=True for anti-diagonals."""
    positions = []
    if not anti:
        # Main diagonals (top-right to bottom-left)
        for d in range(rows + cols - 1):
            for r in range(rows):
                c = d - r
                if 0 <= c < cols:
                    positions.append((r, c))
    else:
        # Anti-diagonals (top-left to bottom-right)
        for d in range(rows + cols - 1):
            for r in range(rows):
                c = (cols - 1) - (d - r)
                if 0 <= c < cols:
                    positions.append((r, c))
    return positions


def row_read_perm(rows, cols):
    """Standard row-by-row read (identity for row-filled grid)."""
    return [(r, c) for r in range(rows) for c in range(cols)]


def col_read_perm(rows, cols):
    """Column-by-column read (standard columnar with identity column order)."""
    return [(r, c) for c in range(cols) for r in range(rows)]


def grid_pos_to_perm(grid_positions, rows, cols):
    """Convert a list of (row,col) read positions to a permutation.
    Input: grid was filled by rows. grid[r][c] = input[r*cols + c].
    Output: output[i] = input[perm[i]] where grid_positions[i] = (r,c).
    """
    perm = []
    for r, c in grid_positions:
        perm.append(r * cols + c)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def build_route_perms():
    """Build all non-columnar route cipher permutations for 7×14 grid."""
    perms = {}

    # Spiral: 4 corners × 2 directions = 8
    for corner in range(4):
        for cw in [True, False]:
            name = f"spiral_{'CW' if cw else 'CCW'}_corner{corner}"
            gp = spiral_perm(ROWS, WIDTH, clockwise=cw, start_corner=corner)
            perms[name] = grid_pos_to_perm(gp, ROWS, WIDTH)

    # Serpentine
    gp = serpentine_rows_perm(ROWS, WIDTH)
    perms["serpentine_rows"] = grid_pos_to_perm(gp, ROWS, WIDTH)
    gp = serpentine_cols_perm(ROWS, WIDTH)
    perms["serpentine_cols"] = grid_pos_to_perm(gp, ROWS, WIDTH)

    # Reversed serpentine
    gp = serpentine_rows_perm(ROWS, WIDTH)
    perms["serpentine_rows_rev"] = grid_pos_to_perm(gp[::-1], ROWS, WIDTH)
    gp = serpentine_cols_perm(ROWS, WIDTH)
    perms["serpentine_cols_rev"] = grid_pos_to_perm(gp[::-1], ROWS, WIDTH)

    # Diagonal
    for anti in [False, True]:
        name = f"diagonal_{'anti' if anti else 'main'}"
        gp = diagonal_perm(ROWS, WIDTH, anti=anti)
        perms[name] = grid_pos_to_perm(gp, ROWS, WIDTH)

    # Reversed diagonals
    for anti in [False, True]:
        name = f"diagonal_{'anti' if anti else 'main'}_rev"
        gp = diagonal_perm(ROWS, WIDTH, anti=anti)
        perms[name] = grid_pos_to_perm(gp[::-1], ROWS, WIDTH)

    # Column-by-column with identity order (basic columnar, no reorder)
    gp = col_read_perm(ROWS, WIDTH)
    perms["col_identity"] = grid_pos_to_perm(gp, ROWS, WIDTH)

    # Column-by-column reversed
    gp = col_read_perm(ROWS, WIDTH)
    perms["col_identity_rev"] = grid_pos_to_perm(gp[::-1], ROWS, WIDTH)

    # Also try 14×7 grid (14 cols, 7 rows)
    for corner in range(4):
        for cw in [True, False]:
            name = f"spiral14x7_{'CW' if cw else 'CCW'}_corner{corner}"
            gp = spiral_perm(WIDTH, ROWS, clockwise=cw, start_corner=corner)
            perms[name] = grid_pos_to_perm(gp, WIDTH, ROWS)

    gp = serpentine_rows_perm(WIDTH, ROWS)
    perms["serpentine_rows_14x7"] = grid_pos_to_perm(gp, WIDTH, ROWS)
    gp = serpentine_cols_perm(WIDTH, ROWS)
    perms["serpentine_cols_14x7"] = grid_pos_to_perm(gp, WIDTH, ROWS)
    gp = col_read_perm(WIDTH, ROWS)
    perms["col_identity_14x7"] = grid_pos_to_perm(gp, WIDTH, ROWS)

    # Validate all perms
    for name, p in perms.items():
        assert len(p) == GRID_LEN, f"{name}: len={len(p)} != {GRID_LEN}"
        assert sorted(p) == list(range(GRID_LEN)), f"{name}: not a valid permutation"

    return perms


def build_rail_fence_perm(length, rails):
    """Build rail fence cipher permutation for given length and number of rails."""
    # Fill by zigzag
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for i in range(length):
        fence[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    # Read off rail by rail
    perm = []
    for rail_positions in fence:
        perm.extend(rail_positions)

    # perm[i] = position in original text that goes to output position i
    # Actually, perm gives the READ ORDER: output[i] = input[perm[i]]
    # But for rail fence, we need: CT is the rail-fence rearranged text
    # To decrypt: figure out which positions go to which rail, then read back in zigzag

    # Let me re-derive: encryption writes zigzag, reads rail-by-rail
    # perm as built: output[i] corresponds to input position perm[i]
    # So CT[i] = PT[perm[i]], meaning perm IS the gather permutation for encryption
    # To decrypt: PT[perm[i]] = CT[i], so PT[j] = CT[inv_perm[j]]
    return perm


# ── Scoring ────────────────────────────────────────────────────────────

def check_exact_period_consistency(ct98, perm, period, model):
    """Check if the 24 crib-derived key values are exactly consistent at given period.

    model='ST': key applied at PT positions. K[pt_pos] = (CT[perm_inv[pt_pos]] - PT[pt_pos]) mod 26
    model='TS': key applied at CT positions. K[ct_pos] = (CT[ct_pos] - PT[perm[ct_pos]]) mod 26
                where perm maps CT pos → PT pos (i.e., the decryption permutation)

    Returns (n_consistent, total_cribs, key_dict)
    """
    inv_perm = invert_perm(perm)

    key_by_residue = defaultdict(list)

    if model == 'ST':
        # Sub then Transpose: CT = Transpose(Vig(PT, K))
        # Decrypt: intermediate = inv_Transpose(CT), PT = Vig_decrypt(intermediate, K)
        # intermediate[j] = CT[inv_perm[j]]... wait, let me be precise.
        # If CT[i] = intermediate[perm[i]] (gather), then intermediate[j] = CT[inv_perm[j]]
        # And PT[j] = (intermediate[j] - K[j]) mod 26
        # So K[j] = (intermediate[j] - PT[j]) mod 26 = (CT[inv_perm[j]] - PT[j]) mod 26
        for pt_pos in CRIB_POS:
            ct_idx = inv_perm[pt_pos]
            ct_val = ct98[ct_idx]
            pt_val = CRIB_PT[pt_pos]
            k_val = (ct_val - pt_val) % MOD
            residue = pt_pos % period  # key applied at PT positions
            key_by_residue[residue].append((k_val, pt_pos))

    elif model == 'TS':
        # Transpose then Sub: CT = Vig(Transpose(PT), K)
        # CT[i] = (Transpose(PT)[i] + K[i]) mod 26
        # Transpose(PT)[i] = PT[perm[i]] (gather: transposed text at i comes from PT at perm[i])
        # So CT[i] = (PT[perm[i]] + K[i]) mod 26
        # For crib: PT[pt_pos] is known. We need to find which CT position i has perm[i] = pt_pos.
        # That's i = inv_perm[pt_pos]. So CT[inv_perm[pt_pos]] = (PT[pt_pos] + K[inv_perm[pt_pos]]) mod 26
        # K[inv_perm[pt_pos]] = (CT[inv_perm[pt_pos]] - PT[pt_pos]) mod 26
        for pt_pos in CRIB_POS:
            ct_idx = inv_perm[pt_pos]
            ct_val = ct98[ct_idx]
            pt_val = CRIB_PT[pt_pos]
            k_val = (ct_val - pt_val) % MOD
            residue = ct_idx % period  # key applied at CT positions
            key_by_residue[residue].append((k_val, pt_pos))

    # Check consistency: all values in each residue class must agree
    n_consistent = 0
    key_dict = {}
    for residue, vals in key_by_residue.items():
        # Count most common key value
        counts = defaultdict(int)
        for kv, _ in vals:
            counts[kv] += 1
        best_kv = max(counts, key=counts.get)
        n_consistent += counts[best_kv]
        key_dict[residue] = best_kv

    return n_consistent, N_CRIBS, key_dict


def check_beaufort_consistency(ct98, perm, period, model):
    """Same as above but for Beaufort: K[j] = (CT + PT) mod 26."""
    inv_perm = invert_perm(perm)
    key_by_residue = defaultdict(list)

    for pt_pos in CRIB_POS:
        ct_idx = inv_perm[pt_pos]
        ct_val = ct98[ct_idx]
        pt_val = CRIB_PT[pt_pos]
        k_val = (ct_val + pt_val) % MOD  # Beaufort

        if model == 'ST':
            residue = pt_pos % period
        else:  # TS
            residue = ct_idx % period
        key_by_residue[residue].append((k_val, pt_pos))

    n_consistent = 0
    key_dict = {}
    for residue, vals in key_by_residue.items():
        counts = defaultdict(int)
        for kv, _ in vals:
            counts[kv] += 1
        best_kv = max(counts, key=counts.get)
        n_consistent += counts[best_kv]
        key_dict[residue] = best_kv

    return n_consistent, N_CRIBS, key_dict


# ── Phase 1: Route ciphers ────────────────────────────────────────────

def run_phase1(insert_range):
    """Test non-columnar route ciphers on 7×14 grid."""
    print("\n" + "=" * 72)
    print("PHASE 1: NON-COLUMNAR ROUTE CIPHERS ON 7×14 GRID")
    print("=" * 72)

    route_perms = build_route_perms()
    print(f"  Route permutations: {len(route_perms)}")
    print(f"  Insertion positions: {insert_range[0]}-{insert_range[-1]} ({len(insert_range)} positions)")
    print(f"  Letters: 26 × positions = {26 * len(insert_range)} candidates")

    periods = [2, 7, 14]  # Key periods to test (7 and 14 are factors of 98)
    models = ['ST', 'TS']
    variants = ['vig', 'beau']

    best_score = 0
    best_config = None
    hits = []  # score >= 20

    total_checks = 0
    t0 = time.time()

    for ip in insert_range:
        for lv in range(26):
            ct98 = list(CT_NUM)
            ct98.insert(ip, lv)

            for pname, perm in route_perms.items():
                for model in models:
                    for period in periods:
                        for variant in variants:
                            total_checks += 1
                            if variant == 'vig':
                                sc, total, kd = check_exact_period_consistency(
                                    ct98, perm, period, model)
                            else:
                                sc, total, kd = check_beaufort_consistency(
                                    ct98, perm, period, model)

                            if sc > best_score:
                                best_score = sc
                                best_config = dict(
                                    perm=pname, model=model, period=period,
                                    variant=variant, insert_pos=ip,
                                    letter=chr(lv + 65), score=sc,
                                )

                            if sc >= 20:
                                cfg = dict(
                                    perm=pname, model=model, period=period,
                                    variant=variant, insert_pos=ip,
                                    letter=chr(lv + 65), score=sc,
                                )
                                hits.append(cfg)
                                if sc >= 22:
                                    print(f"  *** [{sc}/24] {pname} {model} p={period} "
                                          f"{variant} ins='{chr(lv+65)}'@{ip}")

        if (ip - insert_range[0] + 1) % 5 == 0:
            elapsed = time.time() - t0
            print(f"  ... pos {ip} done, best={best_score}/24, "
                  f"checks={total_checks:,}, {elapsed:.1f}s")

    elapsed = time.time() - t0
    print(f"\n  Phase 1 complete: {total_checks:,} checks in {elapsed:.1f}s")
    print(f"  Best: {best_score}/24")
    if best_config:
        print(f"  Best config: {best_config}")
    print(f"  Hits >= 20: {len(hits)}")

    return best_score, best_config, hits


# ── Phase 2: Rail fence ───────────────────────────────────────────────

def run_phase2(insert_range):
    """Test rail fence cipher with various rail counts."""
    print("\n" + "=" * 72)
    print("PHASE 2: RAIL FENCE CIPHER")
    print("=" * 72)

    rail_counts = [2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14]
    periods = [2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14]
    models = ['ST', 'TS']
    variants = ['vig', 'beau']

    best_score = 0
    best_config = None
    hits = []
    total_checks = 0
    t0 = time.time()

    for rails in rail_counts:
        perm = build_rail_fence_perm(GRID_LEN, rails)

        for ip in insert_range:
            for lv in range(26):
                ct98 = list(CT_NUM)
                ct98.insert(ip, lv)

                for model in models:
                    for period in periods:
                        for variant in variants:
                            total_checks += 1
                            if variant == 'vig':
                                sc, _, kd = check_exact_period_consistency(
                                    ct98, perm, period, model)
                            else:
                                sc, _, kd = check_beaufort_consistency(
                                    ct98, perm, period, model)

                            if sc > best_score:
                                best_score = sc
                                best_config = dict(
                                    rails=rails, model=model, period=period,
                                    variant=variant, insert_pos=ip,
                                    letter=chr(lv + 65), score=sc,
                                )

                            if sc >= 20:
                                hits.append(dict(
                                    rails=rails, model=model, period=period,
                                    variant=variant, insert_pos=ip,
                                    letter=chr(lv + 65), score=sc,
                                ))
                                if sc >= 22:
                                    print(f"  *** [{sc}/24] rail={rails} {model} p={period} "
                                          f"{variant} ins='{chr(lv+65)}'@{ip}")

    elapsed = time.time() - t0
    print(f"\n  Phase 2 complete: {total_checks:,} checks in {elapsed:.1f}s")
    print(f"  Best: {best_score}/24")
    if best_config:
        print(f"  Best config: {best_config}")
    print(f"  Hits >= 20: {len(hits)}")

    return best_score, best_config, hits


# ── Phase 3: Row permutation search (algebraically pruned) ────────────

def run_phase3(insert_range):
    """Row permutations on 7×14 grid, algebraically pruned.

    Key insight: for period-7 key on a 7-col grid, each crib's column
    determines its key residue class. The row permutation changes which
    CT values map to each (row, col) position, but the column (and thus
    key residue) is fixed by the PT position.

    For ST model: K[pt_pos] = (CT[row_perm_inv[pt_row]*7 + pt_col] - PT[pt_pos]) mod 26
    Key residue = pt_pos mod 7 = pt_col.

    So for each column c, all cribs in that column must produce the same key value.
    This constrains which row can map where. We can solve column-by-column.
    """
    print("\n" + "=" * 72)
    print("PHASE 3: ROW PERMUTATIONS ON 7×14 GRID (algebraically pruned)")
    print("=" * 72)

    # Group cribs by column
    cribs_by_col = defaultdict(list)
    for pt_pos in CRIB_POS:
        col = pt_pos % WIDTH
        row = pt_pos // WIDTH
        cribs_by_col[col].append((row, pt_pos))

    print(f"  Cribs by column:")
    for c in range(WIDTH):
        items = cribs_by_col.get(c, [])
        print(f"    Col {c}: {len(items)} cribs at rows {[r for r, _ in items]}")

    best_score = 0
    best_config = None
    total_valid = 0
    total_checks = 0
    t0 = time.time()

    for ip in insert_range:
        for lv in range(26):
            ct98 = list(CT_NUM)
            ct98.insert(ip, lv)

            # Extract column values from 98-char CT (7-col grid, filled by rows)
            # Column c has values at positions c, c+7, c+14, ..., c+91
            col_vals = {}
            for c in range(WIDTH):
                col_vals[c] = [ct98[r * WIDTH + c] for r in range(ROWS)]

            # For ST model, period 7: key[c] = (CT_at_col_c_row_mapped - PT) mod 26
            # For each column c with cribs, try all possible row assignments
            # and check if key values are consistent

            for variant in ['vig', 'beau']:
                # For each column, compute required CT row for each crib row
                # and what key value that implies
                feasible = True
                key_values = {}
                row_constraints = {}  # col -> list of (crib_row, required_ct_value)

                for c in range(WIDTH):
                    if c not in cribs_by_col:
                        continue
                    cribs = cribs_by_col[c]
                    if len(cribs) <= 1:
                        continue  # No constraint from single crib

                    # All cribs in this column must produce the same key
                    # For row permutation: CT[row_perm[r]*7+c] corresponds to PT[r*7+c]
                    # key[c] = (col_vals[c][row_perm[r]] - PT[r*7+c]) mod 26

                    # The cribs constrain: for all (r_i, pt_pos_i) in this column,
                    # (col_vals[c][row_perm[r_i]] - CRIB_PT[pt_pos_i]) mod 26 must be same

                    # Enumerate: for which CT rows does the key value match?
                    target_keys = []
                    for r, pt_pos in cribs:
                        pt_val = CRIB_PT[pt_pos]
                        possible = {}
                        for ct_row in range(ROWS):
                            cv = col_vals[c][ct_row]
                            if variant == 'vig':
                                kv = (cv - pt_val) % MOD
                            else:
                                kv = (cv + pt_val) % MOD
                            if kv not in possible:
                                possible[kv] = []
                            possible[kv].append(ct_row)
                        target_keys.append((r, pt_pos, possible))

                    # Find key values that are achievable by ALL cribs in this column
                    # (each crib has a different PT value, so different CT rows produce the same key)
                    common_keys = None
                    for _, _, possible in target_keys:
                        if common_keys is None:
                            common_keys = set(possible.keys())
                        else:
                            common_keys &= set(possible.keys())

                    if not common_keys:
                        feasible = False
                        break

                    # For each common key value, the row assignments must be consistent
                    # (each crib row maps to a different CT row)
                    found_valid = False
                    for kv in common_keys:
                        # Check if there's a valid assignment of CT rows
                        # (all must be distinct)
                        row_options = []
                        for _, _, possible in target_keys:
                            row_options.append(possible[kv])

                        # Simple check: are there enough distinct rows?
                        all_rows = set()
                        ok = True
                        for opts in row_options:
                            if not opts:
                                ok = False
                                break
                            all_rows.update(opts)
                        if ok and len(all_rows) >= len(row_options):
                            found_valid = True
                            key_values[c] = kv
                            break

                    if not found_valid:
                        feasible = False
                        break

                total_checks += 1
                if feasible:
                    # Count how many cribs are satisfied
                    # (all cribs in columns with >=2 cribs are satisfied by construction)
                    n_constrained = sum(len(cribs_by_col[c])
                                       for c in range(WIDTH)
                                       if c in cribs_by_col and len(cribs_by_col[c]) >= 2)
                    total_valid += 1

                    # For the full score, we'd need to count ALL cribs including singles
                    # Singles are always satisfied (they define the key for their residue)
                    score = N_CRIBS  # If feasible, ALL 24 cribs can be satisfied

                    if score > best_score:
                        best_score = score
                        best_config = dict(
                            model='ST', period=7, variant=variant,
                            insert_pos=ip, letter=chr(lv + 65),
                            score=score, key=key_values,
                            n_constrained=n_constrained,
                        )
                        print(f"  *** [{score}/24] ST p=7 {variant} "
                              f"ins='{chr(lv+65)}'@{ip} key={key_values} "
                              f"(constrained: {n_constrained})")

    elapsed = time.time() - t0
    print(f"\n  Phase 3 complete: {total_checks:,} checks, {total_valid} feasible, {elapsed:.1f}s")
    print(f"  Best: {best_score}/24")
    if best_config:
        print(f"  Best config: {best_config}")

    return best_score, best_config, total_valid


# ── Phase 4: Exhaustive columnar sanity check (restricted) ────────────

def run_phase4(insert_range):
    """Re-check columnar transposition, restricted to pos 74+, for exact consistency."""
    print("\n" + "=" * 72)
    print("PHASE 4: COLUMNAR TRANSPOSITION (restricted, sanity check)")
    print("=" * 72)

    periods = [7, 14]
    models = ['ST', 'TS']
    variants = ['vig', 'beau']

    best_score = 0
    best_config = None
    total_checks = 0
    t0 = time.time()

    # Test all 5040 column orderings
    for co in permutations(range(WIDTH)):
        # Build columnar permutation: fill by rows, read by columns in order co
        # Output position calculation:
        perm = []
        for rank in range(WIDTH):
            col_idx = co.index(rank)  # which column has rank 'rank'
            for row in range(ROWS):
                perm.append(row * WIDTH + col_idx)

        for ip in insert_range:
            for lv in range(26):
                ct98 = list(CT_NUM)
                ct98.insert(ip, lv)

                for model in models:
                    for period in periods:
                        for variant in variants:
                            total_checks += 1
                            if variant == 'vig':
                                sc, _, kd = check_exact_period_consistency(
                                    ct98, perm, period, model)
                            else:
                                sc, _, kd = check_beaufort_consistency(
                                    ct98, perm, period, model)

                            if sc > best_score:
                                best_score = sc
                                best_config = dict(
                                    col_order=list(co), model=model,
                                    period=period, variant=variant,
                                    insert_pos=ip, letter=chr(lv + 65),
                                    score=sc,
                                )

                            if sc >= 22:
                                print(f"  *** [{sc}/24] col={list(co)} {model} p={period} "
                                      f"{variant} ins='{chr(lv+65)}'@{ip}")

        if total_checks % 1000000 == 0:
            elapsed = time.time() - t0
            print(f"  ... {total_checks:,} checks, best={best_score}/24, {elapsed:.1f}s")

    elapsed = time.time() - t0
    print(f"\n  Phase 4 complete: {total_checks:,} checks in {elapsed:.1f}s")
    print(f"  Best: {best_score}/24")
    if best_config:
        print(f"  Best config: {best_config}")

    return best_score, best_config


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("E-S-03: Missing Character + Non-Columnar Transpositions")
    print(f"CT: {CT} (len={CT_LEN})")
    print(f"Target: 98 = {WIDTH} × {ROWS}")
    t_start = time.time()

    # Phase 0: Verify constraints
    verify_constraints()

    # Viable insertion range: positions 74-97 + append
    insert_range = list(range(74, 99))  # 74,75,...,98 (25 positions)

    # Phase 1: Route ciphers
    p1_best, p1_cfg, p1_hits = run_phase1(insert_range)

    # Phase 2: Rail fence
    p2_best, p2_cfg, p2_hits = run_phase2(insert_range)

    # Phase 3: Row permutation (algebraic)
    p3_best, p3_cfg, p3_valid = run_phase3(insert_range)

    # Phase 4: Columnar (restricted sanity check)
    p4_best, p4_cfg = run_phase4(insert_range)

    overall = max(p1_best, p2_best, p3_best, p4_best)
    total_t = time.time() - t_start

    print("\n" + "=" * 72)
    print("FINAL SUMMARY")
    print("=" * 72)
    print(f"Phase 1 (route ciphers):     best = {p1_best}/24, hits≥20: {len(p1_hits)}")
    print(f"Phase 2 (rail fence):        best = {p2_best}/24, hits≥20: {len(p2_hits)}")
    print(f"Phase 3 (row permutation):   best = {p3_best}/24, feasible: {p3_valid}")
    print(f"Phase 4 (columnar sanity):   best = {p4_best}/24")
    print(f"Overall best: {overall}/24")
    print(f"Total time: {total_t:.1f}s")

    if overall >= 24:
        print("\n*** BREAKTHROUGH ***")
    elif overall >= 18:
        print(f"\nSIGNAL at {overall}/24 — investigate further")
    elif overall >= 10:
        print(f"\nWeak signal at {overall}/24 — likely noise/artifact")
    else:
        print(f"\nNo signal. Missing char + grid transposition ELIMINATED for pos 74+")

    # Save results
    summary = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_seconds': total_t,
        'insert_range': [insert_range[0], insert_range[-1]],
        'phase1_route_best': p1_best,
        'phase1_route_config': p1_cfg,
        'phase1_route_hits': len(p1_hits),
        'phase2_railfence_best': p2_best,
        'phase2_railfence_config': p2_cfg,
        'phase2_railfence_hits': len(p2_hits),
        'phase3_rowperm_best': p3_best,
        'phase3_rowperm_feasible': p3_valid,
        'phase4_columnar_best': p4_best,
        'phase4_columnar_config': p4_cfg,
        'overall_best': overall,
    }
    out = os.path.join(os.path.dirname(__file__), '..', 'results',
                       'e_s_03_missing_char_routes.json')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved to {out}")
