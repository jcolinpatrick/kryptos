#!/usr/bin/env python3
# Cipher: periodic substitution × structured transposition
# Family: two_system
# Status: active
# Keyspace: ~150M+ (4.2M transpositions × 19 periods × 3 variants)
# Last run:
# Best score:
#
# MEET-IN-THE-MIDDLE: Periodic Substitution × Structured Transpositions
#
# Model: PT → Transposition T → Intermediate → Periodic Sub S → CT
#
# For any permutation T and periodic key K of period p:
#   CT[i] = encrypt(Intermediate[i], K[i % p])
#   Intermediate[i] = PT[T_inv(i)]  (transposition rearranges PT positions)
#
# At crib position j (where PT[j] is known):
#   Intermediate position = T(j)
#   Key[T(j) % p] = derive(CT[T(j)], PT[j])
#
# CONSISTENCY: All crib positions j1, j2 where T(j1) % p == T(j2) % p
#   must yield the same key value.
#
# This extends e_mitm_mono_transposition.py (which found 0 hits for mono sub)
# to test periodic Vigenère/Beaufort/Variant-Beaufort at periods 2-20.
#
# EXPECTED FALSE POSITIVES by period (with 4.2M transpositions):
#   p=2..13: ~0 (filter is extremely strong)
#   p=14..17: ~0
#   p=18..19: <1
#   p=20: ~8 (manageable — score with quadgrams)
#
# Any genuine hit would be a BREAKTHROUGH.
#
# Usage: PYTHONPATH=src python3 -u scripts/two_system/e_mitm_periodic_transposition.py

from __future__ import annotations

import json
import math
import sys
import time
from collections import defaultdict
from itertools import permutations
from typing import Dict, List, Optional, Set, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)

# ── Precomputed crib data ───────────────────────────────────────────────

CRIB_POS_LIST = sorted(CRIB_POSITIONS)
CRIB_PT_CHARS = [CRIB_DICT[p] for p in CRIB_POS_LIST]
CRIB_PT_NUMS = [ALPH_IDX[c] for c in CRIB_PT_CHARS]
CT_LIST = list(CT)
CT_NUMS = [ALPH_IDX[c] for c in CT]

# Periods to test
MIN_PERIOD = 2
MAX_PERIOD = 20

# Variant key derivation functions (using numeric values for speed)
# Vig:   CT = (PT + K) mod 26  =>  K = (CT - PT) mod 26
# Beau:  CT = (K - PT) mod 26  =>  K = (CT + PT) mod 26
# VBeau: CT = (PT - K) mod 26  =>  K = (PT - CT) mod 26
VARIANT_NAMES = ["Vig", "Beau", "VBeau"]


def derive_keys_vig(ct_nums_at_cribs: List[int]) -> List[int]:
    return [(ct_nums_at_cribs[i] - CRIB_PT_NUMS[i]) % MOD for i in range(N_CRIBS)]


def derive_keys_beau(ct_nums_at_cribs: List[int]) -> List[int]:
    return [(ct_nums_at_cribs[i] + CRIB_PT_NUMS[i]) % MOD for i in range(N_CRIBS)]


def derive_keys_vbeau(ct_nums_at_cribs: List[int]) -> List[int]:
    return [(CRIB_PT_NUMS[i] - ct_nums_at_cribs[i]) % MOD for i in range(N_CRIBS)]


DERIVE_FNS = [derive_keys_vig, derive_keys_beau, derive_keys_vbeau]

# Decrypt functions
def decrypt_vig(ct_num: int, k: int) -> int:
    return (ct_num - k) % MOD

def decrypt_beau(ct_num: int, k: int) -> int:
    return (k - ct_num) % MOD

def decrypt_vbeau(ct_num: int, k: int) -> int:
    return (ct_num + k) % MOD

DECRYPT_FNS = [decrypt_vig, decrypt_beau, decrypt_vbeau]


# ── Periodic consistency check ──────────────────────────────────────────

def check_all_periodic(trans_positions: List[int], ct_nums_at_cribs: List[int]) -> List[Tuple[int, int, List[int]]]:
    """Check periodic consistency for ALL (period, variant) combos.

    Args:
        trans_positions: perm[crib_pos] for each crib position (24 values)
        ct_nums_at_cribs: CT numeric values at transposed positions

    Returns:
        List of (period, variant_idx, key) for consistent combos.
    """
    hits = []

    # Derive key values for all 3 variants at once
    all_keys = [fn(ct_nums_at_cribs) for fn in DERIVE_FNS]

    for var_idx in range(3):
        key_vals = all_keys[var_idx]

        for period in range(MIN_PERIOD, MAX_PERIOD + 1):
            # Group crib indices by residue class (trans_positions[i] % period)
            residue_map: Dict[int, int] = {}  # residue -> required key value
            consistent = True

            for i in range(N_CRIBS):
                r = trans_positions[i] % period
                kv = key_vals[i]

                if r in residue_map:
                    if residue_map[r] != kv:
                        consistent = False
                        break
                else:
                    residue_map[r] = kv

            if consistent:
                # Build full key (fill unoccupied residues with 0)
                key = [0] * period
                for r, kv in residue_map.items():
                    key[r] = kv
                hits.append((period, var_idx, key))

    return hits


def decrypt_full(perm: List[int], key: List[int], var_idx: int) -> str:
    """Decrypt CT using given transposition permutation and periodic key.

    Decryption:
      1. Undo substitution: intermediate[i] = decrypt(CT[i], key[i % p])
      2. Undo transposition: PT[j] = intermediate[perm[j]]
    """
    period = len(key)
    decrypt_fn = DECRYPT_FNS[var_idx]

    # Step 1: Undo substitution
    intermediate = [decrypt_fn(CT_NUMS[i], key[i % period]) for i in range(CT_LEN)]

    # Step 2: Undo transposition
    plaintext = [0] * CT_LEN
    for j in range(CT_LEN):
        plaintext[j] = intermediate[perm[j]]

    return "".join(ALPH[v] for v in plaintext)


# ── Quadgram scorer ─────────────────────────────────────────────────────

def load_quadgrams(path: str = "data/english_quadgrams.json") -> Dict[str, float]:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"  WARNING: Quadgram file not found at {path}")
        return {}


def score_quadgrams(text: str, qg: Dict[str, float]) -> float:
    if not qg or len(text) < 4:
        return -15.0
    total = 0.0
    count = 0
    floor = min(qg.values()) - 1.0
    for i in range(len(text) - 3):
        gram = text[i:i + 4].upper()
        total += qg.get(gram, floor)
        count += 1
    return total / count if count > 0 else -15.0


def score_ic(text: str) -> float:
    from collections import Counter
    freq = Counter(text)
    n = len(text)
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


# ── Transposition generators ────────────────────────────────────────────
# (Copied from e_mitm_mono_transposition.py for self-containment)

def gen_identity():
    yield "identity", list(range(CT_LEN))


def gen_reversal():
    yield "reversal", list(range(CT_LEN - 1, -1, -1))


def gen_stride_decimation():
    for d in range(2, CT_LEN):
        for s in range(CT_LEN):
            perm = [(s + i * d) % CT_LEN for i in range(CT_LEN)]
            yield f"stride(d={d},s={s})", perm


def gen_rail_fence():
    for n_rails in range(2, 31):
        if n_rails >= CT_LEN:
            break
        rails = [[] for _ in range(n_rails)]
        rail = 0
        direction = 1
        for i in range(CT_LEN):
            rails[rail].append(i)
            if rail == 0:
                direction = 1
            elif rail == n_rails - 1:
                direction = -1
            rail += direction

        perm = [0] * CT_LEN
        out_pos = 0
        for rail_positions in rails:
            for pt_pos in rail_positions:
                perm[pt_pos] = out_pos
                out_pos += 1

        yield f"railfence(rails={n_rails})", perm


def gen_columnar_exhaustive(max_width: int = 10):
    for width in range(2, max_width + 1):
        n_rows = math.ceil(CT_LEN / width)
        total_cells = n_rows * width
        short_cols = total_cells - CT_LEN

        for col_perm in permutations(range(width)):
            col_order = list(col_perm)

            col_lengths = []
            for col in range(width):
                if col >= width - short_cols:
                    col_lengths.append(n_rows - 1)
                else:
                    col_lengths.append(n_rows)

            col_starts = {}
            pos = 0
            for order_idx in range(width):
                col_idx = col_order[order_idx]
                col_starts[col_idx] = pos
                pos += col_lengths[col_idx]

            perm = [0] * CT_LEN
            for i in range(CT_LEN):
                row = i // width
                col = i % width
                if row < col_lengths[col]:
                    perm[i] = col_starts[col] + row

            yield f"columnar(w={width},order={col_order})", perm


def gen_reverse_columnar_exhaustive(max_width: int = 8):
    for width in range(2, max_width + 1):
        n_rows = math.ceil(CT_LEN / width)
        total_cells = n_rows * width
        short_cols = total_cells - CT_LEN

        for col_perm in permutations(range(width)):
            col_order = list(col_perm)

            col_lengths = []
            for col in range(width):
                if col >= width - short_cols:
                    col_lengths.append(n_rows - 1)
                else:
                    col_lengths.append(n_rows)

            grid = [[None] * width for _ in range(n_rows)]
            input_pos = 0
            for order_idx in range(width):
                col_idx = col_order[order_idx]
                for row in range(col_lengths[col_idx]):
                    grid[row][col_idx] = input_pos
                    input_pos += 1

            perm = [0] * CT_LEN
            out_pos = 0
            for row in range(n_rows):
                for col in range(width):
                    if grid[row][col] is not None:
                        perm[grid[row][col]] = out_pos
                        out_pos += 1

            yield f"rev_columnar(w={width},order={col_order})", perm


def gen_columnar_keyword(min_width: int = 11, max_width: int = 20):
    thematic = []
    try:
        with open("wordlists/thematic_keywords.txt") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    word = line.upper()
                    if word.isalpha():
                        thematic.append(word)
    except FileNotFoundError:
        pass

    english_words: Dict[int, List[str]] = defaultdict(list)
    try:
        with open("wordlists/english.txt") as f:
            for line in f:
                word = line.strip().upper()
                if word.isalpha() and min_width <= len(word) <= max_width:
                    english_words[len(word)].append(word)
    except FileNotFoundError:
        pass

    for width in range(min_width, max_width + 1):
        n_rows = math.ceil(CT_LEN / width)
        total_cells = n_rows * width
        short_cols = total_cells - CT_LEN

        seen_orders = set()
        keywords_for_width = set()

        for kw in thematic:
            if len(kw) >= width:
                keywords_for_width.add(kw[:width])
            else:
                ext = (kw * ((width // len(kw)) + 1))[:width]
                keywords_for_width.add(ext)

        for word in english_words.get(width, [])[:5000]:
            keywords_for_width.add(word)

        for kw in keywords_for_width:
            col_order = sorted(range(width), key=lambda i: (kw[i], i))

            inv_order = [0] * width
            for i, v in enumerate(col_order):
                inv_order[v] = i

            for order, order_desc in [(col_order, "fwd"), (inv_order, "inv")]:
                ot = tuple(order)
                if ot in seen_orders:
                    continue
                seen_orders.add(ot)

                col_lengths = []
                for col in range(width):
                    if col >= width - short_cols:
                        col_lengths.append(n_rows - 1)
                    else:
                        col_lengths.append(n_rows)

                col_starts = {}
                pos = 0
                for order_idx in range(width):
                    col_idx = order[order_idx]
                    col_starts[col_idx] = pos
                    pos += col_lengths[col_idx]

                perm = [0] * CT_LEN
                for i in range(CT_LEN):
                    row = i // width
                    col = i % width
                    if row < col_lengths[col]:
                        perm[i] = col_starts[col] + row

                yield f"columnar_kw(w={width},kw={kw[:12]}..{order_desc})", perm


def _grid_read_to_perm(read_order, n_rows, n_cols):
    valid_cells = set()
    for i in range(CT_LEN):
        r = i // n_cols
        c = i % n_cols
        valid_cells.add(r * n_cols + c)

    filtered_read = [idx for idx in read_order if idx in valid_cells]
    if len(filtered_read) != CT_LEN:
        return None

    grid_to_write = {}
    for i in range(CT_LEN):
        r = i // n_cols
        c = i % n_cols
        grid_to_write[r * n_cols + c] = i

    perm = [0] * CT_LEN
    for out_pos, grid_idx in enumerate(filtered_read):
        write_pos = grid_to_write[grid_idx]
        perm[write_pos] = out_pos

    if sorted(perm) != list(range(CT_LEN)):
        return None
    return perm


def _spiral_order(n_rows, n_cols, start_corner):
    total = n_rows * n_cols
    visited = [[False] * n_cols for _ in range(n_rows)]
    order = []

    if start_corner == 0:
        dr, dc = [0, 1, 0, -1], [1, 0, -1, 0]
        r, c = 0, 0
    elif start_corner == 1:
        dr, dc = [1, 0, -1, 0], [0, -1, 0, 1]
        r, c = 0, n_cols - 1
    elif start_corner == 2:
        dr, dc = [0, -1, 0, 1], [-1, 0, 1, 0]
        r, c = n_rows - 1, n_cols - 1
    else:
        dr, dc = [-1, 0, 1, 0], [0, 1, 0, -1]
        r, c = n_rows - 1, 0

    d = 0
    for _ in range(total):
        order.append(r * n_cols + c)
        visited[r][c] = True
        nr, nc = r + dr[d], c + dc[d]
        if 0 <= nr < n_rows and 0 <= nc < n_cols and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            r, c = r + dr[d], c + dc[d]
    return order


def _diagonal_order(n_rows, n_cols, direction):
    order = []
    if direction == "tl_br":
        for diag in range(n_rows + n_cols - 1):
            for r in range(max(0, diag - n_cols + 1), min(n_rows, diag + 1)):
                c = diag - r
                if c < n_cols:
                    order.append(r * n_cols + c)
    else:
        for diag in range(n_rows + n_cols - 1):
            for r in range(max(0, diag - n_cols + 1), min(n_rows, diag + 1)):
                c = (n_cols - 1) - (diag - r)
                if 0 <= c < n_cols:
                    order.append(r * n_cols + c)
    return order


def gen_route_ciphers():
    grid_dims = []
    for n_cols in range(4, 25):
        n_rows = math.ceil(CT_LEN / n_cols)
        if n_rows >= 2 and n_cols >= 2:
            grid_dims.append((n_rows, n_cols))

    for n_rows, n_cols in grid_dims:
        for start_corner in range(4):
            try:
                read_order = _spiral_order(n_rows, n_cols, start_corner)
                perm = _grid_read_to_perm(read_order, n_rows, n_cols)
                if perm is not None:
                    yield f"spiral(r={n_rows},c={n_cols},corner={start_corner})", perm
            except (IndexError, ValueError):
                continue

        for col_first in (False, True):
            try:
                read_order = []
                if not col_first:
                    for r in range(n_rows):
                        cols = range(n_cols) if r % 2 == 0 else range(n_cols - 1, -1, -1)
                        for c in cols:
                            read_order.append(r * n_cols + c)
                else:
                    for c in range(n_cols):
                        rows = range(n_rows) if c % 2 == 0 else range(n_rows - 1, -1, -1)
                        for r in rows:
                            read_order.append(r * n_cols + c)

                perm = _grid_read_to_perm(read_order, n_rows, n_cols)
                if perm is not None:
                    yield f"snake(r={n_rows},c={n_cols},col_first={col_first})", perm
            except (IndexError, ValueError):
                continue

        for direction in ("tl_br", "tr_bl"):
            try:
                read_order = _diagonal_order(n_rows, n_cols, direction)
                perm = _grid_read_to_perm(read_order, n_rows, n_cols)
                if perm is not None:
                    yield f"diagonal(r={n_rows},c={n_cols},dir={direction})", perm
            except (IndexError, ValueError):
                continue


def _rotation_perm(length, n_rows, n_cols):
    total = n_rows * n_cols
    if total < length:
        return None
    short_cols = total - length

    col_lengths = []
    for col in range(n_cols):
        if col >= n_cols - short_cols:
            col_lengths.append(n_rows - 1)
        else:
            col_lengths.append(n_rows)

    col_starts = [0] * n_cols
    for c in range(1, n_cols):
        col_starts[c] = col_starts[c - 1] + col_lengths[c - 1]

    perm = [0] * length
    for i in range(length):
        row = i // n_cols
        col = i % n_cols
        if row < col_lengths[col]:
            perm[i] = col_starts[col] + row
        else:
            return None

    if sorted(perm) != list(range(length)):
        return None
    return perm


def gen_double_rotation():
    dim_pairs = []
    for n_cols in range(4, 25):
        n_rows = math.ceil(CT_LEN / n_cols)
        dim_pairs.append((n_rows, n_cols))

    for r1, c1 in dim_pairs:
        perm1 = _rotation_perm(CT_LEN, r1, c1)
        if perm1 is None:
            continue
        for r2, c2 in dim_pairs:
            perm2 = _rotation_perm(CT_LEN, r2, c2)
            if perm2 is None:
                continue
            combined = [perm2[perm1[i]] for i in range(CT_LEN)]
            yield f"double_rot({r1}x{c1},{r2}x{c2})", combined


def gen_myszkowski(max_width: int = 12):
    thematic = []
    try:
        with open("wordlists/thematic_keywords.txt") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    word = line.upper()
                    if word.isalpha() and 3 <= len(word) <= max_width:
                        thematic.append(word)
    except FileNotFoundError:
        pass

    thematic.extend(["KRYPTOS", "KOMPASS", "ABSCISSA", "DEFECTOR", "COLOPHON",
                      "BERLIN", "CLOCK", "POINT", "SHADOW",
                      "COMPASS", "SANBORN", "SCHEIDT", "FIVE", "LUCID",
                      "PALIMPSEST", "QUAGMIRE", "VERDIGRIS"])
    thematic = list(set(thematic))
    seen_keys = set()

    for keyword in thematic:
        width = len(keyword)
        if width < 3 or width > max_width:
            continue
        if len(set(keyword)) == width:
            continue

        sorted_chars = sorted(set(keyword))
        char_rank = {c: i for i, c in enumerate(sorted_chars)}
        key_ranks = [char_rank[c] for c in keyword]
        key_tuple = tuple(key_ranks)
        if key_tuple in seen_keys:
            continue
        seen_keys.add(key_tuple)

        n_rows = math.ceil(CT_LEN / width)
        output = []
        for rank in sorted(set(key_ranks)):
            tied_cols = [c for c in range(width) if key_ranks[c] == rank]
            if len(tied_cols) == 1:
                col = tied_cols[0]
                for row in range(n_rows):
                    idx = row * width + col
                    if idx < CT_LEN:
                        output.append(idx)
            else:
                for row in range(n_rows):
                    for col in tied_cols:
                        idx = row * width + col
                        if idx < CT_LEN:
                            output.append(idx)

        if len(output) != CT_LEN:
            continue

        perm = [0] * CT_LEN
        for out_pos, in_pos in enumerate(output):
            perm[in_pos] = out_pos

        if sorted(perm) == list(range(CT_LEN)):
            yield f"myszkowski(kw={keyword})", perm


def gen_reversed_variants(base_gen):
    rev = list(range(CT_LEN - 1, -1, -1))
    for desc, perm in base_gen:
        combined = [perm[rev[i]] for i in range(CT_LEN)]
        yield f"rev+{desc}", combined


# ── Main attack ──────────────────────────────────────────────────────────

def attack():
    print("=" * 80)
    print("MEET-IN-THE-MIDDLE: PERIODIC SUBSTITUTION × STRUCTURED TRANSPOSITIONS")
    print(f"Model: PT → Transposition T → Intermediate → Periodic Sub (p={MIN_PERIOD}-{MAX_PERIOD}) → CT")
    print(f"Variants: Vigenère, Beaufort, Variant-Beaufort")
    print("Filter: Crib-derived key values must be consistent within each residue class")
    print("=" * 80)
    print(f"\nCT: {CT}")
    print(f"Length: {CT_LEN}")
    print(f"Cribs: {N_CRIBS} positions known")
    print(f"Periods tested: {MIN_PERIOD} to {MAX_PERIOD} ({MAX_PERIOD - MIN_PERIOD + 1} periods × 3 variants = {(MAX_PERIOD - MIN_PERIOD + 1) * 3} checks/transposition)")
    print()

    # Print crib analysis
    pt_groups = defaultdict(list)
    for pos in CRIB_POS_LIST:
        pt_groups[CRIB_DICT[pos]].append(pos)
    print("CRIB ANALYSIS:")
    print(f"  Total crib positions: {N_CRIBS}")
    print(f"  Distinct PT letters:  {len(pt_groups)}")
    for letter, positions in sorted(pt_groups.items()):
        if len(positions) > 1:
            print(f"    {letter}: positions {positions} ({len(positions)} occurrences)")
    print()

    # Load quadgrams
    qg = load_quadgrams()
    if qg:
        print(f"Loaded {len(qg):,} quadgrams for scoring\n")
    else:
        print("No quadgrams loaded — will use IC scoring only\n")

    # Results tracking
    all_hits: List[Tuple[float, int, int, str, str, List[int], str]] = []
    # (qg_score, period, variant_idx, trans_desc, plaintext, key, family)

    total_tested = 0
    total_hits = 0
    hits_by_period: Dict[int, int] = defaultdict(int)
    family_stats: Dict[str, Tuple[int, int, float]] = {}
    t_global_start = time.time()

    def process_generator(gen_name: str, generator, report_interval: int = 10000):
        nonlocal total_tested, total_hits

        t_start = time.time()
        tested = 0
        hits = 0
        best_qg = -15.0

        for desc, perm in generator:
            tested += 1
            total_tested += 1

            # Precompute transposed positions and CT values for crib positions
            trans_positions = [perm[pos] for pos in CRIB_POS_LIST]
            ct_nums_at_cribs = [CT_NUMS[tp] for tp in trans_positions]

            # Check all (period, variant) combos
            periodic_hits = check_all_periodic(trans_positions, ct_nums_at_cribs)

            for period, var_idx, key in periodic_hits:
                hits += 1
                total_hits += 1
                hits_by_period[period] += 1

                # Decrypt and score
                pt = decrypt_full(perm, key, var_idx)
                qg_s = score_quadgrams(pt, qg) if qg else -15.0
                ic_val = score_ic(pt)

                if qg_s > best_qg:
                    best_qg = qg_s

                key_str = "".join(ALPH[k] for k in key)
                var_name = VARIANT_NAMES[var_idx]

                all_hits.append((qg_s, period, var_idx, desc, pt, key, gen_name))

                # Verify cribs
                crib_ok = all(pt[pos] == CRIB_DICT[pos] for pos in CRIB_POS_LIST)

                # Only print for high-quality hits or early hits
                if qg_s > -8.0 or total_hits <= 20:
                    print(f"\n  *** PERIODIC HIT #{total_hits} ***")
                    print(f"  {var_name} p={period} key={key_str}")
                    print(f"  Transposition: {desc}")
                    print(f"  PT: {pt}")
                    print(f"  Quadgram: {qg_s:+.4f}  IC: {ic_val:.4f}  Cribs: {'PASS' if crib_ok else 'FAIL'}")
                    sys.stdout.flush()

            # Progress reporting
            if tested % report_interval == 0:
                elapsed = time.time() - t_start
                rate = tested / elapsed if elapsed > 0 else 0
                print(f"  [{gen_name}] {tested:>10,} tested | {hits} hits | "
                      f"{elapsed:.1f}s ({rate:,.0f}/s)", flush=True)

        elapsed = time.time() - t_start
        rate = tested / elapsed if elapsed > 0 else 0
        print(f"  [{gen_name}] DONE: {tested:>10,} tested | {hits} hits | "
              f"best_qg={best_qg:+.4f} | {elapsed:.1f}s ({rate:,.0f}/s)")
        sys.stdout.flush()

        family_stats[gen_name] = (tested, hits, best_qg)

    # ── Phase 0: Identity ─────────────────────────────────────────────
    print("\n--- Phase 0: Identity (periodic sub only, no transposition) ---")
    process_generator("identity", gen_identity(), report_interval=1)

    # ── Phase 1: Simple reversal ──────────────────────────────────────
    print("\n--- Phase 1: Simple reversal ---")
    process_generator("reversal", gen_reversal(), report_interval=1)

    # ── Phase 2: Stride / Decimation ──────────────────────────────────
    print("\n--- Phase 2: Stride / Decimation (d=2..96, all starts) ---")
    process_generator("stride", gen_stride_decimation(), report_interval=10000)

    # ── Phase 3: Rail Fence ───────────────────────────────────────────
    print("\n--- Phase 3: Rail Fence (2..30 rails) ---")
    process_generator("railfence", gen_rail_fence(), report_interval=10)

    # ── Phase 4: Columnar exhaustive (widths 2-8) ─────────────────────
    print("\n--- Phase 4: Columnar transposition exhaustive (widths 2-8) ---")
    process_generator("columnar_exh", gen_columnar_exhaustive(max_width=8), report_interval=10000)

    # ── Phase 5: Reverse columnar exhaustive (widths 2-7) ─────────────
    print("\n--- Phase 5: Reverse columnar exhaustive (widths 2-7) ---")
    process_generator("rev_columnar", gen_reverse_columnar_exhaustive(max_width=7), report_interval=10000)

    # ── Phase 6: Columnar width 9-10 exhaustive ───────────────────────
    print("\n--- Phase 6: Columnar width 9-10 exhaustive ---")
    for w in [9, 10]:
        print(f"  Starting width {w} ({math.factorial(w):,} permutations)...")
        gen = gen_columnar_exhaustive(max_width=w)
        filtered = ((d, p) for d, p in gen if f"w={w}," in d)
        process_generator(f"columnar_w{w}", filtered, report_interval=100000)

    # ── Phase 7: Columnar keyword (widths 11-20) ──────────────────────
    print("\n--- Phase 7: Columnar keyword-derived (widths 11-20) ---")
    process_generator("columnar_kw", gen_columnar_keyword(11, 20), report_interval=10000)

    # ── Phase 8: Route ciphers ────────────────────────────────────────
    print("\n--- Phase 8: Route ciphers (spiral, snake, diagonal) ---")
    process_generator("route", gen_route_ciphers(), report_interval=100)

    # ── Phase 9: Double rotation (K3-style) ───────────────────────────
    print("\n--- Phase 9: Double rotation (K3-style) ---")
    process_generator("double_rot", gen_double_rotation(), report_interval=10000)

    # ── Phase 10: Myszkowski transposition ────────────────────────────
    print("\n--- Phase 10: Myszkowski transposition ---")
    process_generator("myszkowski", gen_myszkowski(max_width=12), report_interval=100)

    # ── Phase 11: Reversed CT + columnar (widths 2-8) ─────────────────
    print("\n--- Phase 11: Reversed CT + columnar (widths 2-8) ---")
    process_generator("rev+columnar",
                      gen_reversed_variants(gen_columnar_exhaustive(max_width=8)),
                      report_interval=10000)

    # ── Phase 12: Reversed CT + stride ────────────────────────────────
    print("\n--- Phase 12: Reversed CT + stride ---")
    process_generator("rev+stride",
                      gen_reversed_variants(gen_stride_decimation()),
                      report_interval=10000)

    # ── Phase 13: Reversed CT + rail fence ────────────────────────────
    print("\n--- Phase 13: Reversed CT + rail fence ---")
    process_generator("rev+railfence",
                      gen_reversed_variants(gen_rail_fence()),
                      report_interval=10)

    # ── Final Summary ─────────────────────────────────────────────────
    total_elapsed = time.time() - t_global_start

    print(f"\n{'=' * 80}")
    print(f"FINAL SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total transpositions tested:  {total_tested:>12,}")
    print(f"Total periodic hits:          {total_hits:>12,}")
    print(f"Checks per transposition:     {(MAX_PERIOD - MIN_PERIOD + 1) * 3:>12,}")
    print(f"Total (trans × period × var): {total_tested * (MAX_PERIOD - MIN_PERIOD + 1) * 3:>12,}")
    print(f"Total time:                   {total_elapsed:>11.1f}s")
    print()

    if hits_by_period:
        print("HITS BY PERIOD:")
        for p in sorted(hits_by_period.keys()):
            print(f"  p={p:2d}: {hits_by_period[p]:>6,} hits")
        print()

    # Per-family stats
    print("PER-FAMILY BREAKDOWN:")
    print(f"  {'Family':<20s} {'Tested':>12s} {'Hits':>8s} {'Best QG':>10s}")
    print(f"  {'-'*20} {'-'*12} {'-'*8} {'-'*10}")
    for fam, (tested, hits, best) in sorted(family_stats.items()):
        print(f"  {fam:<20s} {tested:>12,} {hits:>8,} {best:>+10.4f}")
    print()

    # Sort all hits by quadgram score
    all_hits.sort(key=lambda x: x[0], reverse=True)

    if all_hits:
        # Show top hits
        n_show = min(50, len(all_hits))
        print(f"TOP {n_show} HITS (by quadgram score):")
        print("-" * 110)
        for rank, (qg_s, period, var_idx, desc, pt, key, family) in enumerate(all_hits[:n_show], 1):
            key_str = "".join(ALPH[k] for k in key)
            var_name = VARIANT_NAMES[var_idx]
            ic_val = score_ic(pt)
            print(f"  #{rank:3d}  qg={qg_s:+.4f}  IC={ic_val:.4f}  {var_name} p={period} key={key_str}")
            print(f"        [{family}] {desc}")
            print(f"        PT: {pt}")

        # Check if any hit has signal-level quality
        best_qg = all_hits[0][0]
        if best_qg > -6.0:
            print(f"\n  *** POTENTIAL BREAKTHROUGH: Best quadgram {best_qg:+.4f} is near English level! ***")
        elif best_qg > -7.5:
            print(f"\n  ** INTERESTING: Best quadgram {best_qg:+.4f} warrants investigation **")
        else:
            print(f"\n  Best quadgram {best_qg:+.4f} is noise level (English ≈ -4.2 to -5.0)")
        print()
    else:
        print("NO periodic-consistent transpositions found across all families.\n")

    # Save results
    import os
    os.makedirs("results", exist_ok=True)
    out_path = "results/mitm_periodic_transposition.json"
    try:
        results_data = {
            "total_tested": total_tested,
            "total_hits": total_hits,
            "hits_by_period": dict(hits_by_period),
            "elapsed_seconds": total_elapsed,
            "periods_tested": list(range(MIN_PERIOD, MAX_PERIOD + 1)),
            "variants_tested": VARIANT_NAMES,
            "family_stats": {k: {"tested": v[0], "hits": v[1], "best_qg": v[2]}
                             for k, v in family_stats.items()},
            "top_hits": [
                {
                    "qg_score": h[0],
                    "period": h[1],
                    "variant": VARIANT_NAMES[h[2]],
                    "transposition": h[3],
                    "plaintext": h[4],
                    "key": "".join(ALPH[k] for k in h[5]),
                    "family": h[6],
                }
                for h in all_hits[:200]
            ],
        }
        with open(out_path, "w") as f:
            json.dump(results_data, f, indent=2)
        print(f"Results saved to {out_path}")
    except Exception as e:
        print(f"Warning: Could not save results: {e}")

    print(f"\n{'=' * 80}")
    print("DONE")
    print(f"{'=' * 80}")

    return all_hits


if __name__ == "__main__":
    attack()
