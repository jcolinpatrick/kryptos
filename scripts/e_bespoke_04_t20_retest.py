#!/usr/bin/env python3
"""E-BESPOKE-04: Systematic T=20 retest (1-indexed alphabet: A=1, B=2, ... T=20).

Prior experiments all used T=19 (0-indexed programmer convention). But Sanborn is
an artist — he would naturally use A=1, B=2, ... T=20. This corrects a potential
systematic error across multiple experiments.

Six phases:
  1. CT rotation by 20 (not 19) + substitution sweeps with shifted cribs
  2. Grid reads at width 20 + substitution
  3. T=20 as column/start position in transposition schemes
  4. T=20 combined with other sculpture parameters (misspelling shifts, YAR, KRYPTOS)
  5. 98-character hypothesis (insert A-Z at each position) and 96-char (remove one)
  6. T=20 linear transforms j = (20*i + b) mod 97 and j = (m*i + 20) mod 97
"""
from __future__ import annotations

import math
import sys
import time
from collections import defaultdict
from itertools import permutations, product
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    CT,
    CT_LEN,
    CRIB_DICT,
    CRIB_WORDS,
    MOD,
    N_CRIBS,
    NOISE_FLOOR,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.transforms.transposition import (
    apply_perm,
    invert_perm,
    columnar_perm,
    serpentine_perm,
    spiral_perm,
)
from kryptos.kernel.constraints.bean import verify_bean


# ── Helpers ──────────────────────────────────────────────────────────────────

def c2n(c: str) -> int:
    return ord(c) - 65

def n2c(n: int) -> str:
    return chr((n % 26) + 65)

def decrypt_with_key(ct: str, key: List[int], variant: str) -> str:
    """Decrypt ct with numeric key, returning plaintext string."""
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        cv = c2n(c)
        kv = key[i % klen]
        if variant == "vig":
            pt = (cv - kv) % MOD
        elif variant == "beau":
            pt = (kv - cv) % MOD
        elif variant == "varbeau":
            pt = (cv + kv) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        result.append(n2c(pt))
    return "".join(result)


def keyword_to_numeric(kw: str) -> List[int]:
    """Convert keyword string to numeric key values (A=0, B=1, ..., Z=25)."""
    return [ALPH_IDX[c] for c in kw.upper()]


def score_with_shifted_cribs(pt: str, crib_dict: Dict[int, str]) -> int:
    """Score plaintext against a custom crib dictionary."""
    return sum(
        1 for pos, ch in crib_dict.items()
        if 0 <= pos < len(pt) and pt[pos] == ch
    )


def score_shifted_detailed(pt: str, crib_dict: Dict[int, str]) -> Tuple[int, int, int]:
    """Return (total, ene_count, bc_count) for shifted cribs."""
    total = 0
    ene = 0
    bc = 0
    for pos, ch in crib_dict.items():
        if 0 <= pos < len(pt) and pt[pos] == ch:
            total += 1
            # Identify by crib word index: first 13 chars are ENE, next 11 are BC
            # We track by ordering in crib_dict
    # Recalculate with knowledge of which word
    ene_positions = set()
    bc_positions = set()
    idx = 0
    for start, word in CRIB_WORDS:
        for i, ch in enumerate(word):
            if idx < 13:
                ene_positions.add((start + i, ch))
            else:
                bc_positions.add((start + i, ch))
            idx += 1
    # For shifted: we need to know the shift. Just count total.
    return (total, 0, 0)  # Can't easily separate without knowing shift


VARIANT_NAMES = {"vig": "Vigenere", "beau": "Beaufort", "varbeau": "VarBeau"}
VARIANTS = ["vig", "beau", "varbeau"]

# ── Global best tracker ──────────────────────────────────────────────────────

class BestTracker:
    """Track top N results across all phases."""
    def __init__(self, max_entries: int = 20):
        self.results: List[Tuple[int, str, str, str]] = []  # (score, label, phase, pt_snippet)
        self.max_entries = max_entries
        self.total_configs = 0

    def record(self, score: int, label: str, phase: str, pt: str):
        self.total_configs += 1
        if score > NOISE_FLOOR or len(self.results) < self.max_entries:
            self.results.append((score, label, phase, pt[:60]))
            self.results.sort(key=lambda x: -x[0])
            if len(self.results) > self.max_entries:
                self.results = self.results[:self.max_entries]

    @property
    def best_score(self) -> int:
        return self.results[0][0] if self.results else 0

    def print_top(self, n: int = 10):
        print(f"\n  TOP {n} RESULTS (out of {self.total_configs} configs tested):")
        for i, (sc, label, phase, pt_snip) in enumerate(self.results[:n]):
            print(f"  {i+1:3d}. {sc:2d}/24  [{phase}]  {label}")
            print(f"       PT: {pt_snip}")


tracker = BestTracker(max_entries=20)


# ── Keyword definitions ──────────────────────────────────────────────────────

KEYWORDS = {
    "KRYPTOS": keyword_to_numeric("KRYPTOS"),
    "PALIMPSEST": keyword_to_numeric("PALIMPSEST"),
    "ABSCISSA": keyword_to_numeric("ABSCISSA"),
    "BERLINCLOCK": keyword_to_numeric("BERLINCLOCK"),
}

# Misspelling shifts: DIGETAL→DIGITAL(4), IQLUSION→ILLUSION(5), DESPARATLY→DESPERATELY(4), PALIMPCEST(16)
MISSPELLING_SHIFTS = [4, 5, 4, 16]
# YAR 1-indexed: Y=25, A=1, R=18
YAR_1INDEXED = [25, 1, 18]
# YAR 0-indexed: Y=24, A=0, R=17
YAR_0INDEXED = [24, 0, 17]


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: CT Rotation by 20
# ══════════════════════════════════════════════════════════════════════════════

def phase1_ct_rotation():
    """Rotate CT by 20, test with substitution ciphers using shifted cribs."""
    print("\n" + "=" * 78)
    print("  PHASE 1: CT ROTATION BY 20 (not 19)")
    print("=" * 78)

    rotated = CT[20:] + CT[:20]
    print(f"  Original CT: {CT}")
    print(f"  Rotated CT:  {rotated}")
    print(f"  Rotation:    20 positions")
    print(f"  CT[20] = {CT[20]} (start of rotated)")

    # Shifted cribs: original pos N -> new pos (N - 20) mod 97
    shifted_cribs: Dict[int, str] = {}
    for pos, ch in CRIB_DICT.items():
        new_pos = (pos - 20) % CT_LEN
        shifted_cribs[new_pos] = ch

    print(f"\n  Shifted crib positions:")
    ene_shifted = [(pos - 20) % CT_LEN for pos in range(21, 34)]
    bc_shifted = [(pos - 20) % CT_LEN for pos in range(63, 74)]
    print(f"    ENE: positions {ene_shifted[0]}-{ene_shifted[-1]} (was 21-33)")
    print(f"    BC:  positions {bc_shifted[0]}-{bc_shifted[-1]} (was 63-73)")

    # Verify shifted cribs work on original problem
    sanity = score_with_shifted_cribs(rotated, shifted_cribs)
    # After rotation, the letters at shifted positions should NOT match original cribs
    # (unless rotation is identity, which it isn't). They match the ORIGINAL plaintext mapping.
    # Actually: rotated[new_pos] = CT[new_pos + 20] = CT[pos] (for non-crib positions)
    # But we are testing decryptions of the rotated CT.

    configs_tested = 0

    # Phase 1a: Keyword substitution on rotated CT
    print(f"\n  --- Phase 1a: Keyword substitution on rotated CT ---")
    for kw_name, kw_key in KEYWORDS.items():
        for variant in VARIANTS:
            pt = decrypt_with_key(rotated, kw_key, variant)
            sc = score_with_shifted_cribs(pt, shifted_cribs)
            label = f"rot20+{kw_name}(p{len(kw_key)})_{variant}"
            tracker.record(sc, label, "P1a", pt)
            configs_tested += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} → {sc}/24")
                print(f"     PT: {pt[:50]}")

    # Phase 1b: All periodic keys period 1-13 (exhaustive for small periods)
    print(f"\n  --- Phase 1b: Periodic key sweep on rotated CT (period 1-13) ---")
    for period in range(1, 14):
        best_for_period = 0
        # For period 1: try all 26 keys
        if period == 1:
            for k in range(26):
                for variant in VARIANTS:
                    pt = decrypt_with_key(rotated, [k], variant)
                    sc = score_with_shifted_cribs(pt, shifted_cribs)
                    tracker.record(sc, f"rot20+p1_k{k}_{variant}", "P1b", pt)
                    configs_tested += 1
                    best_for_period = max(best_for_period, sc)
        else:
            # For larger periods, use crib constraints to derive key, then check
            # positions where cribs exist tell us what key values must be
            for variant in VARIANTS:
                # Derive key values at crib positions
                required_keys: Dict[int, int] = {}  # residue -> required key value
                consistent = True
                for pos, pt_ch in shifted_cribs.items():
                    residue = pos % period
                    cv = c2n(rotated[pos])
                    pv = c2n(pt_ch)
                    if variant == "vig":
                        kv = (cv - pv) % MOD
                    elif variant == "beau":
                        kv = (cv + pv) % MOD
                    else:  # varbeau
                        kv = (pv - cv) % MOD
                    if residue in required_keys:
                        if required_keys[residue] != kv:
                            consistent = False
                            break
                    else:
                        required_keys[residue] = kv

                if consistent:
                    # Fill remaining residues with all possible values
                    fixed_residues = set(required_keys.keys())
                    free_residues = [r for r in range(period) if r not in fixed_residues]
                    n_free = len(free_residues)

                    if n_free == 0:
                        # Fully determined
                        key = [required_keys.get(r, 0) for r in range(period)]
                        pt = decrypt_with_key(rotated, key, variant)
                        sc = score_with_shifted_cribs(pt, shifted_cribs)
                        tracker.record(sc, f"rot20+p{period}_{variant}_constrained", "P1b", pt)
                        configs_tested += 1
                        best_for_period = max(best_for_period, sc)
                    elif n_free <= 3:
                        # Enumerate free values
                        for combo in product(range(26), repeat=n_free):
                            key = [0] * period
                            for r, v in required_keys.items():
                                key[r] = v
                            for i, r in enumerate(free_residues):
                                key[r] = combo[i]
                            pt = decrypt_with_key(rotated, key, variant)
                            sc = score_with_shifted_cribs(pt, shifted_cribs)
                            tracker.record(sc, f"rot20+p{period}_{variant}_free{n_free}", "P1b", pt)
                            configs_tested += 1
                            best_for_period = max(best_for_period, sc)
                    else:
                        # Too many free residues; just test constrained positions
                        key = [required_keys.get(r, 0) for r in range(period)]
                        pt = decrypt_with_key(rotated, key, variant)
                        sc = score_with_shifted_cribs(pt, shifted_cribs)
                        tracker.record(sc, f"rot20+p{period}_{variant}_partial", "P1b", pt)
                        configs_tested += 1
                        best_for_period = max(best_for_period, sc)

        if best_for_period > NOISE_FLOOR:
            print(f"  Period {period}: best = {best_for_period}/24 ** ABOVE NOISE")
        elif period <= 7:
            print(f"  Period {period}: best = {best_for_period}/24")

    # Phase 1c: Columnar transposition widths 5-14 + keyword substitution
    print(f"\n  --- Phase 1c: Columnar transposition (w5-14) on rotated CT ---")
    for w in range(5, 15):
        # Try identity order and keyword-derived orders
        orders_to_test = [list(range(w))]  # identity
        orders_to_test.append(list(range(w - 1, -1, -1)))  # reverse

        # KRYPTOS-derived order for this width
        if w <= 7:
            kw = "KRYPTOS"[:w]
            indexed = sorted(range(w), key=lambda i: kw[i])
            kw_order = [0] * w
            for rank, orig_idx in enumerate(indexed):
                kw_order[orig_idx] = rank
            orders_to_test.append(kw_order)

        for col_order in orders_to_test:
            try:
                perm = columnar_perm(w, col_order, CT_LEN)
                inv = invert_perm(perm)
                ct_untrans = apply_perm(rotated, inv)
            except Exception:
                continue

            # Raw score (no substitution)
            sc = score_with_shifted_cribs(ct_untrans, shifted_cribs)
            label = f"rot20+col_w{w}_order{col_order[:4]}"
            tracker.record(sc, label, "P1c", ct_untrans)
            configs_tested += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} → {sc}/24")

            # With keyword substitution
            for kw_name, kw_key in KEYWORDS.items():
                for variant in ["vig", "beau"]:
                    pt = decrypt_with_key(ct_untrans, kw_key, variant)
                    sc = score_with_shifted_cribs(pt, shifted_cribs)
                    label = f"rot20+col_w{w}+{kw_name}_{variant}"
                    tracker.record(sc, label, "P1c", pt)
                    configs_tested += 1
                    if sc > NOISE_FLOOR:
                        print(f"  ** ABOVE NOISE: {label} → {sc}/24")

    print(f"\n  Phase 1 summary: {configs_tested} configs tested")
    print(f"  Best so far: {tracker.best_score}/24")


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2: Grid reads at width 20
# ══════════════════════════════════════════════════════════════════════════════

def phase2_grid_width20():
    """Write CT into a 20-column grid, read in various orders."""
    print("\n" + "=" * 78)
    print("  PHASE 2: GRID READS AT WIDTH 20")
    print("=" * 78)

    W = 20
    H = math.ceil(CT_LEN / W)  # 5 rows (97/20 = 4.85)
    print(f"  Grid: {W} columns x {H} rows ({CT_LEN} chars, {W*H - CT_LEN} padding)")

    configs_tested = 0

    # Fill grid row-by-row
    grid = [[''] for _ in range(H)]
    grid_chars = list(CT) + ['X'] * (W * H - CT_LEN)  # pad with X

    # Display grid
    print(f"\n  Grid layout (20 cols x 5 rows):")
    for r in range(H):
        row_str = ""
        for c in range(W):
            idx = r * W + c
            if idx < CT_LEN:
                row_str += CT[idx]
            else:
                row_str += "."
        print(f"    Row {r}: {row_str}")

    # Reading orders
    def read_columns_topdown() -> str:
        """Read columns top to bottom, left to right."""
        result = []
        for c in range(W):
            for r in range(H):
                idx = r * W + c
                if idx < CT_LEN:
                    result.append(CT[idx])
        return "".join(result)

    def read_columns_bottomup() -> str:
        """Read columns bottom to top, left to right."""
        result = []
        for c in range(W):
            for r in range(H - 1, -1, -1):
                idx = r * W + c
                if idx < CT_LEN:
                    result.append(CT[idx])
        return "".join(result)

    def read_serpentine_h() -> str:
        """Serpentine: even rows L-R, odd rows R-L."""
        result = []
        for r in range(H):
            if r % 2 == 0:
                for c in range(W):
                    idx = r * W + c
                    if idx < CT_LEN:
                        result.append(CT[idx])
            else:
                for c in range(W - 1, -1, -1):
                    idx = r * W + c
                    if idx < CT_LEN:
                        result.append(CT[idx])
        return "".join(result)

    def read_serpentine_v() -> str:
        """Serpentine columns: even cols top-down, odd cols bottom-up."""
        result = []
        for c in range(W):
            if c % 2 == 0:
                for r in range(H):
                    idx = r * W + c
                    if idx < CT_LEN:
                        result.append(CT[idx])
            else:
                for r in range(H - 1, -1, -1):
                    idx = r * W + c
                    if idx < CT_LEN:
                        result.append(CT[idx])
        return "".join(result)

    def read_spiral_cw() -> str:
        """Spiral reading clockwise from top-left."""
        perm = spiral_perm(H, W, CT_LEN, clockwise=True)
        return apply_perm(CT, perm) if len(perm) == CT_LEN else ""

    def read_spiral_ccw() -> str:
        """Spiral reading counter-clockwise."""
        perm = spiral_perm(H, W, CT_LEN, clockwise=False)
        return apply_perm(CT, perm) if len(perm) == CT_LEN else ""

    def read_diagonal_down() -> str:
        """Read diagonals top-left to bottom-right."""
        result = []
        for d in range(H + W - 1):
            for r in range(H):
                c = d - r
                if 0 <= c < W:
                    idx = r * W + c
                    if idx < CT_LEN:
                        result.append(CT[idx])
        return "".join(result)

    def read_diagonal_up() -> str:
        """Read anti-diagonals."""
        result = []
        for d in range(H + W - 1):
            for r in range(H - 1, -1, -1):
                c = d - (H - 1 - r)
                if 0 <= c < W:
                    idx = r * W + c
                    if idx < CT_LEN:
                        result.append(CT[idx])
        return "".join(result)

    readings = {
        "col_topdown": read_columns_topdown(),
        "col_bottomup": read_columns_bottomup(),
        "serp_h": read_serpentine_h(),
        "serp_v": read_serpentine_v(),
        "spiral_cw": read_spiral_cw(),
        "spiral_ccw": read_spiral_ccw(),
        "diag_down": read_diagonal_down(),
        "diag_up": read_diagonal_up(),
    }

    for read_name, text in readings.items():
        if not text or len(text) != CT_LEN:
            print(f"  SKIP {read_name}: length={len(text) if text else 0}")
            continue

        # Raw score
        sc = score_cribs(text)
        label = f"w20_{read_name}_raw"
        tracker.record(sc, label, "P2", text)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")

        # With keyword substitution
        for kw_name, kw_key in KEYWORDS.items():
            for variant in ["vig", "beau"]:
                pt = decrypt_with_key(text, kw_key, variant)
                sc = score_cribs(pt)
                label = f"w20_{read_name}+{kw_name}_{variant}"
                tracker.record(sc, label, "P2", pt)
                configs_tested += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} → {sc}/24")

        # Also use the inverse: if CT was written in this reading order, undo it
        # Build inverse permutation
        # Actually we need the permutation that maps reading-order to row-order
        # For column reads: the permutation is columnar_perm with identity order
        # For others, we invert: treat reading as the encryption permutation

    # Also try width 20 with substitution using all 26 single-character keys
    print(f"\n  --- Width 20 column read + all 26 Caesar shifts ---")
    col_text = readings["col_topdown"]
    if col_text and len(col_text) == CT_LEN:
        for k in range(26):
            for variant in ["vig", "beau"]:
                pt = decrypt_with_key(col_text, [k], variant)
                sc = score_cribs(pt)
                tracker.record(sc, f"w20_col+caesar{k}_{variant}", "P2", pt)
                configs_tested += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: w20_col+caesar{k}_{variant} → {sc}/24")

    print(f"\n  Phase 2 summary: {configs_tested} configs tested")
    print(f"  Best so far: {tracker.best_score}/24")


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3: T=20 as column/start/decimation parameter
# ══════════════════════════════════════════════════════════════════════════════

def phase3_transposition_param():
    """T=20 as column priority, start offset, or skip parameter."""
    print("\n" + "=" * 78)
    print("  PHASE 3: T=20 AS TRANSPOSITION PARAMETER")
    print("=" * 78)

    configs_tested = 0

    # Phase 3a: Columnar where column 20 (the 20th, 0-indexed=19) is read first
    print(f"\n  --- Phase 3a: Column 20 read first ---")
    for w in range(21, 30):  # widths where column 20 exists
        # Order where column index 19 (the 20th) gets rank 0
        col_order = list(range(w))
        # Shift so position 19 is rank 0
        col_order = [(i - 19) % w for i in range(w)]
        # This makes col 19 have rank 0, col 20 have rank 1, etc.

        try:
            perm = columnar_perm(w, col_order, CT_LEN)
            inv = invert_perm(perm)
            ct_untrans = apply_perm(CT, inv)
        except Exception:
            continue

        sc = score_cribs(ct_untrans)
        label = f"col_w{w}_col20first"
        tracker.record(sc, label, "P3a", ct_untrans)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")

        # With substitution
        for kw_name, kw_key in [("KRYPTOS", KEYWORDS["KRYPTOS"])]:
            for variant in ["vig", "beau"]:
                pt = decrypt_with_key(ct_untrans, kw_key, variant)
                sc = score_cribs(pt)
                label = f"col_w{w}_col20first+{kw_name}_{variant}"
                tracker.record(sc, label, "P3a", pt)
                configs_tested += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} → {sc}/24")

    # Phase 3b: Start reading at position 20 of each transposition output
    print(f"\n  --- Phase 3b: Start reading at char 20 of transposition output ---")
    for w in range(5, 15):
        for order_name, col_order in [("identity", list(range(w))),
                                       ("reverse", list(range(w-1, -1, -1)))]:
            try:
                perm = columnar_perm(w, col_order, CT_LEN)
                inv = invert_perm(perm)
                ct_untrans = apply_perm(CT, inv)
            except Exception:
                continue

            # Rotate output by 20
            rotated_output = ct_untrans[20:] + ct_untrans[:20]
            shifted_cribs = {(pos - 20) % CT_LEN: ch for pos, ch in CRIB_DICT.items()}

            sc = score_with_shifted_cribs(rotated_output, shifted_cribs)
            label = f"col_w{w}_{order_name}+start20"
            tracker.record(sc, label, "P3b", rotated_output)
            configs_tested += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} → {sc}/24")

    # Phase 3c: Skip-20 decimation
    print(f"\n  --- Phase 3c: Skip-20 decimation (every 20th char mod 97) ---")
    # Since gcd(20, 97) = 1, this visits all 97 positions
    for start in range(CT_LEN):
        decimated = ""
        pos = start
        for _ in range(CT_LEN):
            decimated += CT[pos]
            pos = (pos + 20) % CT_LEN
        sc = score_cribs(decimated)
        label = f"decimate20_start{start}"
        tracker.record(sc, label, "P3c", decimated)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")

        # With KRYPTOS key
        for variant in ["vig", "beau"]:
            pt = decrypt_with_key(decimated, KEYWORDS["KRYPTOS"], variant)
            sc = score_cribs(pt)
            tracker.record(sc, f"decimate20_s{start}+KRYPTOS_{variant}", "P3c", pt)
            configs_tested += 1

    # Also skip-20 with inverse: reconstruct by placing chars at every-20th position
    print(f"\n  --- Phase 3c-inv: Inverse skip-20 (scatter by 20) ---")
    for start in range(min(CT_LEN, 5)):
        result = [''] * CT_LEN
        pos = start
        for i in range(CT_LEN):
            result[pos] = CT[i]
            pos = (pos + 20) % CT_LEN
        scattered = "".join(result)
        sc = score_cribs(scattered)
        label = f"scatter20_start{start}"
        tracker.record(sc, label, "P3c-inv", scattered)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")

    print(f"\n  Phase 3 summary: {configs_tested} configs tested")
    print(f"  Best so far: {tracker.best_score}/24")


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 4: T=20 combined with other sculpture parameters
# ══════════════════════════════════════════════════════════════════════════════

def phase4_combined():
    """T=20 combined with misspelling shifts, YAR values, KRYPTOS keyword."""
    print("\n" + "=" * 78)
    print("  PHASE 4: T=20 COMBINED WITH OTHER SCULPTURE PARAMETERS")
    print("=" * 78)

    rotated = CT[20:] + CT[:20]
    shifted_cribs = {(pos - 20) % CT_LEN: ch for pos, ch in CRIB_DICT.items()}

    configs_tested = 0

    # Phase 4a: T=20 rotation + misspelling shifts as Vigenere key
    print(f"\n  --- Phase 4a: rot20 + misspelling shifts [4,5,4,16] ---")
    for variant in VARIANTS:
        pt = decrypt_with_key(rotated, MISSPELLING_SHIFTS, variant)
        sc = score_with_shifted_cribs(pt, shifted_cribs)
        label = f"rot20+missp[4,5,4,16]_{variant}"
        tracker.record(sc, label, "P4a", pt)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")

    # All permutations of misspelling shifts
    seen = set()
    for perm in permutations(MISSPELLING_SHIFTS):
        key = list(perm)
        key_t = tuple(key)
        if key_t in seen:
            continue
        seen.add(key_t)
        for variant in VARIANTS:
            pt = decrypt_with_key(rotated, key, variant)
            sc = score_with_shifted_cribs(pt, shifted_cribs)
            label = f"rot20+missp_perm{key}_{variant}"
            tracker.record(sc, label, "P4a", pt)
            configs_tested += 1

    # Phase 4b: T=20 rotation + YAR (1-indexed: Y=25, A=1, R=18)
    print(f"\n  --- Phase 4b: rot20 + YAR (1-indexed [25,1,18]) ---")
    for variant in VARIANTS:
        pt = decrypt_with_key(rotated, YAR_1INDEXED, variant)
        sc = score_with_shifted_cribs(pt, shifted_cribs)
        label = f"rot20+YAR1[25,1,18]_{variant}"
        tracker.record(sc, label, "P4b", pt)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")

    # Also 0-indexed YAR
    for variant in VARIANTS:
        pt = decrypt_with_key(rotated, YAR_0INDEXED, variant)
        sc = score_with_shifted_cribs(pt, shifted_cribs)
        label = f"rot20+YAR0[24,0,17]_{variant}"
        tracker.record(sc, label, "P4b", pt)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")

    # Phase 4c: T=20 rotation + KRYPTOS keyword
    print(f"\n  --- Phase 4c: rot20 + KRYPTOS keyword ---")
    for variant in VARIANTS:
        pt = decrypt_with_key(rotated, KEYWORDS["KRYPTOS"], variant)
        sc = score_with_shifted_cribs(pt, shifted_cribs)
        label = f"rot20+KRYPTOS_{variant}"
        tracker.record(sc, label, "P4c", pt)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")
            print(f"     PT: {pt[:50]}")

    # Phase 4d: T=20 as period + exhaustive key at period 20
    print(f"\n  --- Phase 4d: Period 20 exhaustive key search ---")
    # Period 20: for both original and rotated CT
    # Use crib positions to constrain key, then enumerate free residues
    for ct_label, ct_text, crib_d in [("original", CT, CRIB_DICT),
                                        ("rotated", rotated, shifted_cribs)]:
        for variant in VARIANTS:
            required_keys: Dict[int, int] = {}
            consistent = True
            for pos, pt_ch in crib_d.items():
                if pos < 0 or pos >= len(ct_text):
                    continue
                residue = pos % 20
                cv = c2n(ct_text[pos])
                pv = c2n(pt_ch)
                if variant == "vig":
                    kv = (cv - pv) % MOD
                elif variant == "beau":
                    kv = (cv + pv) % MOD
                else:
                    kv = (pv - cv) % MOD
                if residue in required_keys:
                    if required_keys[residue] != kv:
                        consistent = False
                        break
                else:
                    required_keys[residue] = kv

            if not consistent:
                configs_tested += 1
                continue

            fixed_residues = set(required_keys.keys())
            free_residues = [r for r in range(20) if r not in fixed_residues]
            n_free = len(free_residues)

            if n_free == 0:
                key = [required_keys.get(r, 0) for r in range(20)]
                pt = decrypt_with_key(ct_text, key, variant)
                sc_val = score_with_shifted_cribs(pt, crib_d) if ct_label == "rotated" else score_cribs(pt)
                label = f"{ct_label}_p20_{variant}_constrained"
                tracker.record(sc_val, label, "P4d", pt)
                configs_tested += 1
                if sc_val > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} → {sc_val}/24")
                    print(f"     key: {key}")
                    print(f"     PT: {pt[:50]}")
            elif n_free <= 2:
                for combo in product(range(26), repeat=n_free):
                    key = [0] * 20
                    for r, v in required_keys.items():
                        key[r] = v
                    for i, r in enumerate(free_residues):
                        key[r] = combo[i]
                    pt = decrypt_with_key(ct_text, key, variant)
                    sc_val = score_with_shifted_cribs(pt, crib_d) if ct_label == "rotated" else score_cribs(pt)
                    label = f"{ct_label}_p20_{variant}_free{n_free}"
                    tracker.record(sc_val, label, "P4d", pt)
                    configs_tested += 1
            else:
                # Just test the constrained key with zeros for free positions
                key = [required_keys.get(r, 0) for r in range(20)]
                pt = decrypt_with_key(ct_text, key, variant)
                sc_val = score_with_shifted_cribs(pt, crib_d) if ct_label == "rotated" else score_cribs(pt)
                label = f"{ct_label}_p20_{variant}_partial({n_free}free)"
                tracker.record(sc_val, label, "P4d", pt)
                configs_tested += 1
                print(f"  {ct_label} p20 {variant}: {len(fixed_residues)} residues fixed, {n_free} free")
                if sc_val > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} → {sc_val}/24")

    # Phase 4e: Combined keys with T=20
    print(f"\n  --- Phase 4e: Combined key vectors ---")
    combined_keys = {
        "missp+T20": MISSPELLING_SHIFTS + [20],
        "T20+missp": [20] + MISSPELLING_SHIFTS,
        "YAR1+T20": YAR_1INDEXED + [20],
        "T20+YAR1": [20] + YAR_1INDEXED,
        "YAR0+T20": YAR_0INDEXED + [20],
        "missp+YAR1+T20": MISSPELLING_SHIFTS + YAR_1INDEXED + [20],
        "T20+missp+YAR1": [20] + MISSPELLING_SHIFTS + YAR_1INDEXED,
        "T20_only": [20],
        "T20_repeat7": [20] * 7,
    }

    for key_name, key in combined_keys.items():
        for variant in VARIANTS:
            # On original CT
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"orig+{key_name}_{variant}"
            tracker.record(sc, label, "P4e", pt)
            configs_tested += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} → {sc}/24")

            # On rotated CT
            pt = decrypt_with_key(rotated, key, variant)
            sc = score_with_shifted_cribs(pt, shifted_cribs)
            label = f"rot20+{key_name}_{variant}"
            tracker.record(sc, label, "P4e", pt)
            configs_tested += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} → {sc}/24")

    print(f"\n  Phase 4 summary: {configs_tested} configs tested")
    print(f"  Best so far: {tracker.best_score}/24")


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 5: 98-character and 96-character hypotheses
# ══════════════════════════════════════════════════════════════════════════════

def phase5_length_variants():
    """Test 98-char (insert one letter) and 96-char (remove one position)."""
    print("\n" + "=" * 78)
    print("  PHASE 5: LENGTH VARIANT HYPOTHESES (98-char and 96-char)")
    print("=" * 78)

    configs_tested = 0

    # ── 98-char: insert one letter ──
    print(f"\n  --- Phase 5a: 98-char CT (insert one letter A-Z at each position) ---")
    print(f"  98 = 2 x 7^2 = 14 x 7. Key widths: 7 (14 rows), 14 (7 rows).")
    print(f"  Testing 26 letters x 98 positions x 2 widths x 2 orders x 2 variants = ~40K configs")

    best_98 = {"score": 0, "label": "none", "pt": ""}
    kryptos_key = KEYWORDS["KRYPTOS"]  # period 7 — perfect for width 7!

    for insert_pos in range(CT_LEN + 1):
        for insert_char in ALPH:
            ct98 = CT[:insert_pos] + insert_char + CT[insert_pos:]
            assert len(ct98) == 98

            # Adjust crib positions: if insert_pos <= crib_pos, shift crib_pos by +1
            adjusted_cribs: Dict[int, str] = {}
            for pos, ch in CRIB_DICT.items():
                new_pos = pos + 1 if insert_pos <= pos else pos
                adjusted_cribs[new_pos] = ch

            # Width 7: 14 full rows, columnar perm
            for w, w_name in [(7, "w7"), (14, "w14")]:
                for order_name, col_order in [("identity", list(range(w))),
                                               ("reverse", list(range(w-1, -1, -1)))]:
                    try:
                        perm = columnar_perm(w, col_order, 98)
                        inv = invert_perm(perm)
                        ct_untrans = apply_perm(ct98, inv)
                    except Exception:
                        continue

                    # Score against adjusted cribs
                    sc = score_with_shifted_cribs(ct_untrans, adjusted_cribs)
                    configs_tested += 1
                    tracker.total_configs += 1
                    if sc > best_98.get("score", 0):
                        best_98["score"] = sc
                        best_98["label"] = f"98ch_ins{insert_pos}{insert_char}_{w_name}_{order_name}"
                        best_98["pt"] = ct_untrans
                    if sc > NOISE_FLOOR:
                        tracker.record(sc, f"98ch_ins{insert_pos}{insert_char}_{w_name}_{order_name}", "P5a", ct_untrans)
                        print(f"  ** ABOVE NOISE: ins@{insert_pos}+'{insert_char}' {w_name}_{order_name} → {sc}/24")

                    # Width 7 + KRYPTOS Vigenere (period 7 = width 7!)
                    if w == 7:
                        for variant in ["vig", "beau"]:
                            pt = decrypt_with_key(ct_untrans, kryptos_key, variant)
                            sc2 = score_with_shifted_cribs(pt, adjusted_cribs)
                            configs_tested += 1
                            tracker.total_configs += 1
                            if sc2 > best_98.get("score", 0):
                                best_98["score"] = sc2
                                best_98["label"] = f"98ch_ins{insert_pos}{insert_char}_w7_{order_name}+KRYPTOS_{variant}"
                                best_98["pt"] = pt
                            if sc2 > NOISE_FLOOR:
                                tracker.record(sc2, f"98ch_ins{insert_pos}{insert_char}_w7_{order_name}+KRYPTOS_{variant}", "P5a", pt)
                                print(f"  ** ABOVE NOISE: ins@{insert_pos}+'{insert_char}' w7_{order_name}+KRYPTOS_{variant} → {sc2}/24")

    print(f"  Best 98-char: {best_98['score']}/24 — {best_98['label']}")

    # ── 96-char: remove one position ──
    print(f"\n  --- Phase 5b: 96-char CT (remove one position) ---")
    print(f"  96 = 2^5 x 3 = 8 x 12 = 6 x 16 = 4 x 24. Many clean grid widths.")

    best_96 = {"score": 0, "label": "none", "pt": ""}

    for remove_pos in range(CT_LEN):
        ct96 = CT[:remove_pos] + CT[remove_pos + 1:]
        assert len(ct96) == 96

        # Adjust cribs: skip removed position, shift those after it
        adjusted_cribs96: Dict[int, str] = {}
        for pos, ch in CRIB_DICT.items():
            if pos == remove_pos:
                continue  # This crib position was removed
            new_pos = pos - 1 if pos > remove_pos else pos
            adjusted_cribs96[new_pos] = ch

        for w, w_name in [(8, "w8"), (12, "w12"), (6, "w6"), (16, "w16"), (24, "w24")]:
            for order_name, col_order in [("identity", list(range(w))),
                                           ("reverse", list(range(w-1, -1, -1)))]:
                try:
                    perm = columnar_perm(w, col_order, 96)
                    inv = invert_perm(perm)
                    ct_untrans = apply_perm(ct96, inv)
                except Exception:
                    continue

                sc = score_with_shifted_cribs(ct_untrans, adjusted_cribs96)
                configs_tested += 1
                tracker.total_configs += 1
                if sc > best_96.get("score", 0):
                    best_96["score"] = sc
                    best_96["label"] = f"96ch_rm{remove_pos}_{w_name}_{order_name}"
                    best_96["pt"] = ct_untrans
                if sc > NOISE_FLOOR:
                    tracker.record(sc, f"96ch_rm{remove_pos}_{w_name}_{order_name}", "P5b", ct_untrans)
                    print(f"  ** ABOVE NOISE: rm@{remove_pos} {w_name}_{order_name} → {sc}/24")

                # With KRYPTOS or period-matching substitution
                for kw_name, kw_key in [("KRYPTOS", KEYWORDS["KRYPTOS"])]:
                    for variant in ["vig", "beau"]:
                        pt = decrypt_with_key(ct_untrans, kw_key, variant)
                        sc2 = score_with_shifted_cribs(pt, adjusted_cribs96)
                        configs_tested += 1
                        tracker.total_configs += 1
                        if sc2 > best_96.get("score", 0):
                            best_96["score"] = sc2
                            best_96["label"] = f"96ch_rm{remove_pos}_{w_name}_{order_name}+{kw_name}_{variant}"
                            best_96["pt"] = pt
                        if sc2 > NOISE_FLOOR:
                            tracker.record(sc2, f"96ch_rm{remove_pos}_{w_name}_{order_name}+{kw_name}_{variant}", "P5b", pt)
                            print(f"  ** ABOVE NOISE: rm@{remove_pos} {w_name}_{order_name}+{kw_name}_{variant} → {sc2}/24")

    print(f"  Best 96-char: {best_96['score']}/24 — {best_96['label']}")

    # Width 20 with 98 chars
    print(f"\n  --- Phase 5c: 98-char CT at width 20 ---")
    best_w20_98 = {"score": 0, "label": "none"}
    # 98/20 = 4.9, not clean. But still testable.
    for insert_pos in range(0, CT_LEN + 1, 10):  # sample every 10th position to keep tractable
        for insert_char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            ct98 = CT[:insert_pos] + insert_char + CT[insert_pos:]
            adjusted_cribs98: Dict[int, str] = {}
            for pos, ch in CRIB_DICT.items():
                new_pos = pos + 1 if insert_pos <= pos else pos
                adjusted_cribs98[new_pos] = ch

            for order_name, col_order in [("identity", list(range(20))),
                                           ("reverse", list(range(19, -1, -1)))]:
                try:
                    perm = columnar_perm(20, col_order, 98)
                    inv = invert_perm(perm)
                    ct_untrans = apply_perm(ct98, inv)
                except Exception:
                    continue

                sc = score_with_shifted_cribs(ct_untrans, adjusted_cribs98)
                configs_tested += 1
                tracker.total_configs += 1
                if sc > best_w20_98.get("score", 0):
                    best_w20_98["score"] = sc
                    best_w20_98["label"] = f"98ch_ins{insert_pos}{insert_char}_w20_{order_name}"
                if sc > NOISE_FLOOR:
                    tracker.record(sc, f"98ch_ins{insert_pos}{insert_char}_w20_{order_name}", "P5c", ct_untrans)
                    print(f"  ** ABOVE NOISE: 98ch ins@{insert_pos}+'{insert_char}' w20_{order_name} → {sc}/24")

    print(f"  Best w20+98: {best_w20_98['score']}/24 — {best_w20_98['label']}")

    print(f"\n  Phase 5 summary: {configs_tested} configs tested")
    print(f"  Best so far: {tracker.best_score}/24")


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 6: T=20 linear transforms
# ══════════════════════════════════════════════════════════════════════════════

def phase6_linear_transforms():
    """Linear transposition: j = (20*i + b) mod 97 and j = (m*i + 20) mod 97."""
    print("\n" + "=" * 78)
    print("  PHASE 6: T=20 LINEAR TRANSPOSITION TRANSFORMS")
    print("=" * 78)

    configs_tested = 0

    # Since 97 is prime, gcd(20, 97)=1 and gcd(m, 97)=1 for all m in 1..96
    # So all linear transforms are valid permutations of {0..96}

    # Phase 6a: j = (20*i + b) mod 97 — gather convention: output[i] = input[perm[i]]
    print(f"\n  --- Phase 6a: j = (20*i + b) mod 97, gather convention ---")
    for b in range(CT_LEN):
        # Build permutation: perm[i] = (20*i + b) % 97
        perm = [(20 * i + b) % CT_LEN for i in range(CT_LEN)]
        assert len(set(perm)) == CT_LEN, f"Not a valid perm at b={b}"

        # Gather: output[i] = CT[perm[i]]
        text_gather = apply_perm(CT, perm)
        sc = score_cribs(text_gather)
        tracker.record(sc, f"linear_20i+{b}_gather", "P6a", text_gather)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: j=(20i+{b})%97 gather → {sc}/24")
            print(f"     PT: {text_gather[:50]}")

        # Scatter: use inverse perm
        inv = invert_perm(perm)
        text_scatter = apply_perm(CT, inv)
        sc2 = score_cribs(text_scatter)
        tracker.record(sc2, f"linear_20i+{b}_scatter", "P6a", text_scatter)
        configs_tested += 1
        if sc2 > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: j=(20i+{b})%97 scatter → {sc2}/24")
            print(f"     PT: {text_scatter[:50]}")

        # With KRYPTOS key on gather result
        for variant in ["vig", "beau"]:
            pt = decrypt_with_key(text_gather, KEYWORDS["KRYPTOS"], variant)
            sc3 = score_cribs(pt)
            tracker.record(sc3, f"linear_20i+{b}_gather+KRYPTOS_{variant}", "P6a", pt)
            configs_tested += 1
            if sc3 > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: j=(20i+{b})%97 gather+KRYPTOS_{variant} → {sc3}/24")

    # Phase 6b: j = (m*i + 20) mod 97 — both conventions
    print(f"\n  --- Phase 6b: j = (m*i + 20) mod 97 ---")
    for m in range(1, CT_LEN):
        perm = [(m * i + 20) % CT_LEN for i in range(CT_LEN)]
        if len(set(perm)) != CT_LEN:
            continue  # Not a valid permutation (shouldn't happen since 97 is prime)

        # Gather
        text_gather = apply_perm(CT, perm)
        sc = score_cribs(text_gather)
        tracker.record(sc, f"linear_{m}i+20_gather", "P6b", text_gather)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: j=({m}i+20)%97 gather → {sc}/24")
            print(f"     PT: {text_gather[:50]}")

        # Scatter
        inv = invert_perm(perm)
        text_scatter = apply_perm(CT, inv)
        sc2 = score_cribs(text_scatter)
        tracker.record(sc2, f"linear_{m}i+20_scatter", "P6b", text_scatter)
        configs_tested += 1
        if sc2 > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: j=({m}i+20)%97 scatter → {sc2}/24")
            print(f"     PT: {text_scatter[:50]}")

        # With KRYPTOS key on gather result
        for variant in ["vig", "beau"]:
            pt = decrypt_with_key(text_gather, KEYWORDS["KRYPTOS"], variant)
            sc3 = score_cribs(pt)
            tracker.record(sc3, f"linear_{m}i+20_gather+KRYPTOS_{variant}", "P6b", pt)
            configs_tested += 1
            if sc3 > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: j=({m}i+20)%97 gather+KRYPTOS_{variant} → {sc3}/24")

    # Phase 6c: Affine with both T=20 multiplier and offset
    print(f"\n  --- Phase 6c: j = (20*i + 20) mod 97 and close variants ---")
    for offset in [0, 1, 19, 20, 21, 77]:  # 77 = 97-20
        perm = [(20 * i + offset) % CT_LEN for i in range(CT_LEN)]
        text = apply_perm(CT, perm)
        sc = score_cribs(text)
        label = f"affine_20i+{offset}_gather"
        tracker.record(sc, label, "P6c", text)
        configs_tested += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")

        # Inverse
        inv = invert_perm(perm)
        text_inv = apply_perm(CT, inv)
        sc2 = score_cribs(text_inv)
        label2 = f"affine_20i+{offset}_scatter"
        tracker.record(sc2, label2, "P6c", text_inv)
        configs_tested += 1
        if sc2 > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label2} → {sc2}/24")

    print(f"\n  Phase 6 summary: {configs_tested} configs tested")
    print(f"  Best so far: {tracker.best_score}/24")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()

    print("=" * 78)
    print("  E-BESPOKE-04: SYSTEMATIC T=20 RETEST")
    print("  (Correcting T=19 → T=20: 1-indexed alphabet A=1, B=2, ... T=20)")
    print("=" * 78)
    print(f"  CT: {CT}")
    print(f"  CT length: {CT_LEN}")
    print(f"  CT[20] = {CT[20]} (the 21st character, 0-indexed pos 20)")
    print(f"  Cribs (0-indexed): {CRIB_WORDS}")
    print(f"  Rotated CT (by 20): {CT[20:] + CT[:20]}")
    print(f"  Rotated crib positions: ENE @ 1-13, BC @ 43-53")
    print(f"\n  T=19 (old, 0-indexed): used in prior experiments")
    print(f"  T=20 (new, 1-indexed): corrected interpretation for artist Sanborn")

    phase1_ct_rotation()
    phase2_grid_width20()
    phase3_transposition_param()
    phase4_combined()
    phase5_length_variants()
    phase6_linear_transforms()

    # ── Final Summary ──
    elapsed = time.time() - t0
    print("\n" + "#" * 78)
    print("  FINAL SUMMARY — E-BESPOKE-04: T=20 RETEST")
    print("#" * 78)

    tracker.print_top(10)

    print(f"\n  Total configs tested: {tracker.total_configs}")
    print(f"  Elapsed time: {elapsed:.1f}s")

    best = tracker.best_score
    if best <= NOISE_FLOOR:
        print(f"\n  VERDICT: ALL RESULTS AT OR BELOW NOISE FLOOR ({NOISE_FLOOR}/24).")
        print(f"  T=20 interpretation (1-indexed) does NOT change prior eliminations.")
        print(f"  The T=19 vs T=20 distinction is NOT the systematic error we suspected.")
    elif best < 10:
        print(f"\n  VERDICT: Best score {best}/24 is borderline. Likely noise.")
    elif best < 18:
        print(f"\n  VERDICT: Best score {best}/24. Check period — may be false positive.")
    else:
        print(f"\n  VERDICT: Best score {best}/24 — INVESTIGATE IMMEDIATELY.")

    print(f"\n  Done.")


if __name__ == "__main__":
    main()
