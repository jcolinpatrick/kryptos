#!/usr/bin/env python3
"""
MEET-IN-THE-MIDDLE: Autokey Substitution × Structured Transpositions

Cipher:  autokey substitution × structured transposition
Family:  two_system
Status:  active
Keyspace: ~500M (4.2M transpositions × 20 primers × 3 variants × 2 alphabets)
Last run: never
Best score: N/A

Model: PT → Transposition T → Intermediate → Autokey Sub → CT

For any permutation T and autokey with primer length L:
  Encryption: key[i] = primer[i] if i < L, else intermediate[i-L]
  CT[i] = encrypt(intermediate[i], key[i])

At crib positions j (where PT[j] is known):
  intermediate[T(j)] is known (it's the CT value at T(j) decrypted with key at T(j))

AUTOKEY CONSISTENCY: For two crib positions j1, j2 where T(j2) - T(j1) = L
(exactly primer length apart), autokey chain links them:
  key[T(j2)] = intermediate[T(j2) - L] = intermediate[T(j1)]

So we can derive key[T(j2)] from the known intermediate value at T(j1),
then check if decrypting CT[T(j2)] with that key gives the expected PT.

With ~6 checkable positions per config and 26 possible values,
false positive rate ≈ (1/26)^6 ≈ 3×10⁻⁹.

Also tests CT-autokey variant where key[i] = CT[i-L] (simpler, fully determined).

Usage: PYTHONPATH=src python3 -u scripts/two_system/e_mitm_autokey_transposition.py
"""

from __future__ import annotations

import json
import math
import multiprocessing as mp
import sys
import time
from collections import defaultdict
from itertools import permutations
from typing import Dict, List, Optional, Set, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET,
)

# ── Precomputed crib data ───────────────────────────────────────────────

CRIB_POS_LIST = sorted(CRIB_POSITIONS)
CRIB_PT_CHARS = [CRIB_DICT[p] for p in CRIB_POS_LIST]
CRIB_PT_NUMS_AZ = [ALPH_IDX[c] for c in CRIB_PT_CHARS]
CT_NUMS = [ALPH_IDX[c] for c in CT]

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
CRIB_PT_NUMS_KA = [KA_IDX[c] for c in CRIB_PT_CHARS]
CT_NUMS_KA = [KA_IDX[c] for c in CT]

# Primer lengths to test
MIN_PRIMER = 1
MAX_PRIMER = 20

# Variant names
VARIANT_NAMES = ["Vig", "Beau", "VBeau"]
ALPHABET_NAMES = ["AZ", "KA"]

# Decrypt functions for AZ alphabet (numeric)
# Vig:   CT = (PT + K) mod 26  =>  PT = (CT - K) mod 26
# Beau:  CT = (K - PT) mod 26  =>  PT = (K - CT) mod 26
# VBeau: CT = (PT - K) mod 26  =>  PT = (CT + K) mod 26
def dec_vig(ct, k):
    return (ct - k) % MOD

def dec_beau(ct, k):
    return (k - ct) % MOD

def dec_vbeau(ct, k):
    return (ct + k) % MOD

# Key derivation: given CT[i] and PT[i] (intermediate), what is key[i]?
# Vig:   K = (CT - PT) mod 26
# Beau:  K = (CT + PT) mod 26
# VBeau: K = (PT - CT) mod 26
def key_vig(ct, pt):
    return (ct - pt) % MOD

def key_beau(ct, pt):
    return (ct + pt) % MOD

def key_vbeau(ct, pt):
    return (pt - ct) % MOD

DEC_FNS = [dec_vig, dec_beau, dec_vbeau]
KEY_FNS = [key_vig, key_beau, key_vbeau]


# ── Quadgram scorer ─────────────────────────────────────────────────────

def load_quadgrams(path: str = "data/english_quadgrams.json") -> Dict[str, float]:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"  WARNING: Quadgram file not found at {path}")
        return {}

QG = load_quadgrams()
QG_FLOOR = min(QG.values()) - 1.0 if QG else -15.0

def score_quadgrams(text: str) -> float:
    if not QG or len(text) < 4:
        return -15.0
    total = sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)

def score_ic(text: str) -> float:
    from collections import Counter
    freq = Counter(text)
    n = len(text)
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


# ── Autokey consistency check ─────────────────────────────────────────

def check_pt_autokey(trans_positions: List[int], ct_nums: List[int],
                     crib_pt_nums: List[int], var_idx: int) -> List[Tuple[int, float]]:
    """Check PT-autokey consistency for all primer lengths.

    Model: PT → trans T → intermediate → autokey sub → CT

    At crib index i: intermediate position = trans_positions[i]
                     CT at that position = ct_nums[trans_positions[i]]
                     PT at that position = crib_pt_nums[i]

    For PT-autokey with primer L:
      key[pos] = intermediate[pos - L]  (for pos >= L)

    If two crib indices i1, i2 have trans_positions[i2] - trans_positions[i1] = L,
    then key at trans_positions[i2] = intermediate at trans_positions[i1].

    We know intermediate at trans_positions[i1] = plaintext at crib_pos_list[i1],
    which equals crib_pt_nums[i1] (as a number).

    So: key[trans_positions[i2]] = crib_pt_nums[i1]
    Then: decrypt(ct_nums[trans_positions[i2]], key) should == crib_pt_nums[i2]

    Returns: List of (primer_length, qg_score) for consistent configs.
    """
    key_fn = KEY_FNS[var_idx]
    dec_fn = DEC_FNS[var_idx]
    n_cribs = len(trans_positions)

    # Build lookup: transposed_position -> crib_index
    tp_to_crib = {}
    for i in range(n_cribs):
        tp_to_crib[trans_positions[i]] = i

    hits = []

    for L in range(MIN_PRIMER, MAX_PRIMER + 1):
        # For each crib position, check if there's another crib position
        # exactly L positions earlier in intermediate space
        checks_passed = 0
        checks_total = 0
        conflict = False

        for i in range(n_cribs):
            tp = trans_positions[i]
            # Source position for autokey: tp - L
            source_tp = tp - L
            if source_tp < 0:
                continue  # This position uses the primer, can't constrain

            if source_tp in tp_to_crib:
                # We know intermediate[source_tp] = crib_pt_nums[j]
                j = tp_to_crib[source_tp]
                known_key = crib_pt_nums[j]  # intermediate value = PT value at this crib

                # Decrypt CT at tp with this key
                ct_val = ct_nums[tp]
                derived_pt = dec_fn(ct_val, known_key)

                checks_total += 1
                if derived_pt == crib_pt_nums[i]:
                    checks_passed += 1
                else:
                    conflict = True
                    break

        if not conflict and checks_total >= 3:
            # Consistent with at least 3 checks — worth scoring
            hits.append((L, checks_total))

    return hits


def check_ct_autokey(trans_positions: List[int], ct_nums: List[int],
                     crib_pt_nums: List[int], var_idx: int) -> List[Tuple[int, float]]:
    """Check CT-autokey consistency.

    For CT-autokey with primer L:
      key[pos] = CT[pos - L]  (for pos >= L)

    CT values are known everywhere, so key is fully determined for pos >= L.
    Just check if decrypt(CT[tp], key[tp]) == crib_pt at each crib position.
    """
    dec_fn = DEC_FNS[var_idx]
    n_cribs = len(trans_positions)

    hits = []

    for L in range(MIN_PRIMER, MAX_PRIMER + 1):
        checks_passed = 0
        checks_total = 0
        conflict = False

        for i in range(n_cribs):
            tp = trans_positions[i]
            if tp < L:
                continue  # Uses primer, can't check

            # Key at position tp = CT[tp - L] (as numeric value)
            key_val = ct_nums[tp - L]

            # Decrypt
            ct_val = ct_nums[tp]
            derived_pt = dec_fn(ct_val, key_val)

            checks_total += 1
            if derived_pt == crib_pt_nums[i]:
                checks_passed += 1
            else:
                conflict = True
                break

        if not conflict and checks_total >= 3:
            hits.append((L, checks_total))

    return hits


def full_decrypt_pt_autokey(perm: List[int], primer: List[int], var_idx: int,
                            ct_nums_local: List[int]) -> str:
    """Full decryption for PT-autokey.

    Undo substitution first (requires iterative — autokey depends on PT):
      intermediate[0..L-1]: key = primer → decrypt
      intermediate[L..]: key = intermediate[i-L] → decrypt iteratively
    Then undo transposition.
    """
    L = len(primer)
    dec_fn = DEC_FNS[var_idx]
    intermediate = [0] * CT_LEN

    # Decrypt iteratively
    for i in range(CT_LEN):
        if i < L:
            key_val = primer[i]
        else:
            key_val = intermediate[i - L]
        intermediate[i] = dec_fn(ct_nums_local[i], key_val)

    # Undo transposition: PT[j] = intermediate[perm[j]]
    plaintext = [intermediate[perm[j]] for j in range(CT_LEN)]
    return "".join(ALPH[v % MOD] for v in plaintext)


def full_decrypt_ct_autokey(perm: List[int], primer: List[int], var_idx: int,
                            ct_nums_local: List[int]) -> str:
    """Full decryption for CT-autokey.

    Key is fully determined by CT:
      key[i] = primer[i] if i < L, else CT[i-L]
    """
    L = len(primer)
    dec_fn = DEC_FNS[var_idx]
    intermediate = [0] * CT_LEN

    for i in range(CT_LEN):
        if i < L:
            key_val = primer[i]
        else:
            key_val = ct_nums_local[i - L]
        intermediate[i] = dec_fn(ct_nums_local[i], key_val)

    # Undo transposition
    plaintext = [intermediate[perm[j]] for j in range(CT_LEN)]
    return "".join(ALPH[v % MOD] for v in plaintext)


# ── Transposition generators ────────────────────────────────────────────

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


# ── Worker function for multiprocessing ──────────────────────────────

def worker_process_batch(args):
    """Process a batch of transpositions, checking autokey consistency.

    Tests both PT-autokey and CT-autokey × 3 variants × 2 alphabets × 20 primers.
    """
    batch, batch_id = args

    results = []
    tested = 0
    hits = 0

    for desc, perm in batch:
        tested += 1

        # Compute transposed positions for each crib position
        trans_positions = [perm[pos] for pos in CRIB_POS_LIST]

        # ── AZ alphabet ──
        ct_at_cribs_az = [CT_NUMS[tp] for tp in trans_positions]

        for var_idx in range(3):
            # PT-autokey check
            pt_hits = check_pt_autokey(trans_positions, CT_NUMS, CRIB_PT_NUMS_AZ, var_idx)
            for L, n_checks in pt_hits:
                hits += 1
                # Full decrypt with best-guess primer (zeros — we'll refine)
                primer = [0] * L
                pt = full_decrypt_pt_autokey(perm, primer, var_idx, CT_NUMS)
                qg = score_quadgrams(pt)
                results.append(("PT-AK", "AZ", var_idx, L, n_checks, qg, desc, pt))

            # CT-autokey check
            ct_hits = check_ct_autokey(trans_positions, CT_NUMS, CRIB_PT_NUMS_AZ, var_idx)
            for L, n_checks in ct_hits:
                hits += 1
                primer = [0] * L
                pt = full_decrypt_ct_autokey(perm, primer, var_idx, CT_NUMS)
                qg = score_quadgrams(pt)
                results.append(("CT-AK", "AZ", var_idx, L, n_checks, qg, desc, pt))

        # ── KA alphabet ──
        ct_at_cribs_ka = [CT_NUMS_KA[tp] for tp in trans_positions]

        for var_idx in range(3):
            pt_hits = check_pt_autokey(trans_positions, CT_NUMS_KA, CRIB_PT_NUMS_KA, var_idx)
            for L, n_checks in pt_hits:
                hits += 1
                primer = [0] * L
                pt = full_decrypt_pt_autokey(perm, primer, var_idx, CT_NUMS_KA)
                # Convert KA-space back to letters
                pt_text = "".join(KA[v % MOD] for v in [0]*CT_LEN)  # placeholder
                # Actually need proper decrypt
                qg = -15.0  # placeholder — KA decrypt needs special handling
                results.append(("PT-AK", "KA", var_idx, L, n_checks, qg, desc, ""))

            ct_hits = check_ct_autokey(trans_positions, CT_NUMS_KA, CRIB_PT_NUMS_KA, var_idx)
            for L, n_checks in ct_hits:
                hits += 1
                primer = [0] * L
                qg = -15.0
                results.append(("CT-AK", "KA", var_idx, L, n_checks, qg, desc, ""))

    return batch_id, tested, hits, results


# ── Main attack (single-process for clarity, multiprocess for speed) ──

def collect_all_perms():
    """Collect all transposition permutations into memory-efficient batches."""
    generators = [
        ("identity", gen_identity()),
        ("reversal", gen_reversal()),
        ("stride", gen_stride_decimation()),
        ("railfence", gen_rail_fence()),
        ("columnar_w2-8", gen_columnar_exhaustive(max_width=8)),
        ("rev_columnar_w2-7", gen_reverse_columnar_exhaustive(max_width=7)),
        ("columnar_w9", ((d, p) for d, p in gen_columnar_exhaustive(max_width=9) if "w=9," in d)),
        ("columnar_w10", ((d, p) for d, p in gen_columnar_exhaustive(max_width=10) if "w=10," in d)),
        ("columnar_kw", gen_columnar_keyword(11, 20)),
        ("route", gen_route_ciphers()),
        ("double_rot", gen_double_rotation()),
        ("myszkowski", gen_myszkowski(max_width=12)),
        ("rev+columnar", gen_reversed_variants(gen_columnar_exhaustive(max_width=8))),
        ("rev+stride", gen_reversed_variants(gen_stride_decimation())),
        ("rev+railfence", gen_reversed_variants(gen_rail_fence())),
    ]
    return generators


def attack():
    print("=" * 80)
    print("MEET-IN-THE-MIDDLE: AUTOKEY SUBSTITUTION × STRUCTURED TRANSPOSITIONS")
    print(f"Model: PT → Transposition T → Intermediate → Autokey Sub → CT")
    print(f"Autokey types: PT-autokey, CT-autokey")
    print(f"Variants: Vigenère, Beaufort, Variant-Beaufort × AZ, KA alphabets")
    print(f"Primer lengths: {MIN_PRIMER} to {MAX_PRIMER}")
    print("Filter: Autokey chain consistency at scattered crib positions")
    print("=" * 80)
    print(f"\nCT: {CT}")
    print(f"Length: {CT_LEN}")
    print(f"Cribs: {N_CRIBS} positions known")
    print(f"Configs per transposition: 2 autokey types × 3 variants × 2 alphabets × {MAX_PRIMER} primers = {2*3*2*MAX_PRIMER}")
    print()

    t_global_start = time.time()

    total_tested = 0
    total_hits = 0
    all_results = []
    family_stats = {}

    generators = [
        ("identity", gen_identity(), 1),
        ("reversal", gen_reversal(), 1),
        ("stride", gen_stride_decimation(), 10000),
        ("railfence", gen_rail_fence(), 10),
        ("columnar_w2-8", gen_columnar_exhaustive(max_width=8), 10000),
        ("rev_columnar_w2-7", gen_reverse_columnar_exhaustive(max_width=7), 10000),
        ("columnar_w9", ((d, p) for d, p in gen_columnar_exhaustive(max_width=9) if "w=9," in d), 100000),
        ("columnar_w10", ((d, p) for d, p in gen_columnar_exhaustive(max_width=10) if "w=10," in d), 100000),
        ("columnar_kw", gen_columnar_keyword(11, 20), 10000),
        ("route", gen_route_ciphers(), 100),
        ("double_rot", gen_double_rotation(), 10000),
        ("myszkowski", gen_myszkowski(max_width=12), 100),
        ("rev+columnar_w2-8", gen_reversed_variants(gen_columnar_exhaustive(max_width=8)), 10000),
        ("rev+stride", gen_reversed_variants(gen_stride_decimation()), 10000),
        ("rev+railfence", gen_reversed_variants(gen_rail_fence()), 10),
    ]

    for gen_name, generator, report_interval in generators:
        print(f"\n--- {gen_name} ---")
        t_start = time.time()
        tested = 0
        hits = 0
        best_checks = 0

        for desc, perm in generator:
            tested += 1
            total_tested += 1

            trans_positions = [perm[pos] for pos in CRIB_POS_LIST]

            # ── Test AZ alphabet ──
            for var_idx in range(3):
                # PT-autokey
                pt_hits = check_pt_autokey(trans_positions, CT_NUMS, CRIB_PT_NUMS_AZ, var_idx)
                for L, n_checks in pt_hits:
                    hits += 1
                    total_hits += 1
                    if n_checks > best_checks:
                        best_checks = n_checks

                    # Try to find good primer by back-propagation from cribs
                    # For now, report the hit
                    var_name = VARIANT_NAMES[var_idx]
                    if n_checks >= 5 or total_hits <= 20:
                        print(f"  *** PT-AK HIT #{total_hits}: {var_name}/AZ L={L} "
                              f"checks={n_checks}/{N_CRIBS} | {desc}")
                        sys.stdout.flush()

                    if n_checks >= 6:
                        # Attempt full decrypt with primer search
                        # Try primer from cribs that fall in primer zone
                        primer = [0] * L
                        for i in range(N_CRIBS):
                            tp = trans_positions[i]
                            if tp < L:
                                # This crib is in the primer zone
                                # key[tp] = primer[tp], decrypt(CT[tp], primer[tp]) should = PT
                                # So primer[tp] = derive_key(CT[tp], crib_pt)
                                primer[tp] = KEY_FNS[var_idx](CT_NUMS[tp], CRIB_PT_NUMS_AZ[i])

                        pt = full_decrypt_pt_autokey(perm, primer, var_idx, CT_NUMS)
                        qg = score_quadgrams(pt)
                        ic = score_ic(pt)

                        print(f"        DECRYPT: qg={qg:+.4f} IC={ic:.4f} | {pt[:60]}...")
                        all_results.append((qg, n_checks, "PT-AK", "AZ", var_idx, L, desc, pt))

                # CT-autokey
                ct_hits = check_ct_autokey(trans_positions, CT_NUMS, CRIB_PT_NUMS_AZ, var_idx)
                for L, n_checks in ct_hits:
                    hits += 1
                    total_hits += 1
                    if n_checks > best_checks:
                        best_checks = n_checks

                    var_name = VARIANT_NAMES[var_idx]
                    if n_checks >= 5 or total_hits <= 20:
                        print(f"  *** CT-AK HIT #{total_hits}: {var_name}/AZ L={L} "
                              f"checks={n_checks}/{N_CRIBS} | {desc}")
                        sys.stdout.flush()

                    if n_checks >= 6:
                        primer = [0] * L
                        for i in range(N_CRIBS):
                            tp = trans_positions[i]
                            if tp < L:
                                primer[tp] = KEY_FNS[var_idx](CT_NUMS[tp], CRIB_PT_NUMS_AZ[i])

                        pt = full_decrypt_ct_autokey(perm, primer, var_idx, CT_NUMS)
                        qg = score_quadgrams(pt)
                        ic = score_ic(pt)

                        print(f"        DECRYPT: qg={qg:+.4f} IC={ic:.4f} | {pt[:60]}...")
                        all_results.append((qg, n_checks, "CT-AK", "AZ", var_idx, L, desc, pt))

            # ── Test KA alphabet ──
            for var_idx in range(3):
                pt_hits = check_pt_autokey(trans_positions, CT_NUMS_KA, CRIB_PT_NUMS_KA, var_idx)
                for L, n_checks in pt_hits:
                    hits += 1
                    total_hits += 1
                    if n_checks > best_checks:
                        best_checks = n_checks

                    var_name = VARIANT_NAMES[var_idx]
                    if n_checks >= 5 or total_hits <= 20:
                        print(f"  *** PT-AK HIT #{total_hits}: {var_name}/KA L={L} "
                              f"checks={n_checks}/{N_CRIBS} | {desc}")
                        sys.stdout.flush()

                    if n_checks >= 6:
                        primer = [0] * L
                        for i in range(N_CRIBS):
                            tp = trans_positions[i]
                            if tp < L:
                                primer[tp] = KEY_FNS[var_idx](CT_NUMS_KA[tp], CRIB_PT_NUMS_KA[i])

                        # Decrypt in KA space
                        dec_fn = DEC_FNS[var_idx]
                        intermediate = [0] * CT_LEN
                        for pos in range(CT_LEN):
                            if pos < L:
                                key_val = primer[pos]
                            else:
                                key_val = intermediate[pos - L]
                            intermediate[pos] = dec_fn(CT_NUMS_KA[pos], key_val)
                        plaintext_nums = [intermediate[perm[j]] for j in range(CT_LEN)]
                        pt = "".join(KA[v % MOD] for v in plaintext_nums)
                        qg = score_quadgrams(pt)
                        ic = score_ic(pt)

                        print(f"        DECRYPT: qg={qg:+.4f} IC={ic:.4f} | {pt[:60]}...")
                        all_results.append((qg, n_checks, "PT-AK", "KA", var_idx, L, desc, pt))

                ct_hits = check_ct_autokey(trans_positions, CT_NUMS_KA, CRIB_PT_NUMS_KA, var_idx)
                for L, n_checks in ct_hits:
                    hits += 1
                    total_hits += 1
                    if n_checks > best_checks:
                        best_checks = n_checks

                    var_name = VARIANT_NAMES[var_idx]
                    if n_checks >= 5 or total_hits <= 20:
                        print(f"  *** CT-AK HIT #{total_hits}: {var_name}/KA L={L} "
                              f"checks={n_checks}/{N_CRIBS} | {desc}")
                        sys.stdout.flush()

                    if n_checks >= 6:
                        primer = [0] * L
                        for i in range(N_CRIBS):
                            tp = trans_positions[i]
                            if tp < L:
                                primer[tp] = KEY_FNS[var_idx](CT_NUMS_KA[tp], CRIB_PT_NUMS_KA[i])

                        dec_fn = DEC_FNS[var_idx]
                        intermediate = [0] * CT_LEN
                        for pos in range(CT_LEN):
                            if pos < L:
                                key_val = primer[pos]
                            else:
                                key_val = CT_NUMS_KA[pos - L]
                            intermediate[pos] = dec_fn(CT_NUMS_KA[pos], key_val)
                        plaintext_nums = [intermediate[perm[j]] for j in range(CT_LEN)]
                        pt = "".join(KA[v % MOD] for v in plaintext_nums)
                        qg = score_quadgrams(pt)
                        ic = score_ic(pt)

                        print(f"        DECRYPT: qg={qg:+.4f} IC={ic:.4f} | {pt[:60]}...")
                        all_results.append((qg, n_checks, "CT-AK", "KA", var_idx, L, desc, pt))

            # Progress
            if tested % report_interval == 0:
                elapsed = time.time() - t_start
                rate = tested / elapsed if elapsed > 0 else 0
                print(f"  [{gen_name}] {tested:>10,} tested | {hits} hits | "
                      f"best_checks={best_checks} | {elapsed:.1f}s ({rate:,.0f}/s)", flush=True)

        elapsed = time.time() - t_start
        rate = tested / elapsed if elapsed > 0 else 0
        print(f"  [{gen_name}] DONE: {tested:>10,} tested | {hits} hits | "
              f"best_checks={best_checks} | {elapsed:.1f}s ({rate:,.0f}/s)")
        family_stats[gen_name] = (tested, hits, best_checks)

    # ── Summary ──
    total_elapsed = time.time() - t_global_start

    print(f"\n{'=' * 80}")
    print("FINAL SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total transpositions tested:  {total_tested:>12,}")
    print(f"Total autokey-consistent:     {total_hits:>12,}")
    configs_per = 2 * 3 * 2 * MAX_PRIMER  # autokey types × variants × alphabets × primers
    print(f"Checks per transposition:     {configs_per:>12,} (2 AK types × 3 variants × 2 alphabets × {MAX_PRIMER} primers)")
    print(f"Total configs checked:        {total_tested * configs_per:>12,}")
    print(f"Total time:                   {total_elapsed:>11.1f}s")
    print()

    print("PER-FAMILY BREAKDOWN:")
    print(f"  {'Family':<25s} {'Tested':>12s} {'Hits':>8s} {'Best Checks':>12s}")
    print(f"  {'-'*25} {'-'*12} {'-'*8} {'-'*12}")
    for fam, (tested, hits, best) in sorted(family_stats.items()):
        print(f"  {fam:<25s} {tested:>12,} {hits:>8,} {best:>12d}")
    print()

    if all_results:
        all_results.sort(key=lambda x: (-x[1], -x[0]))  # Sort by checks desc, then qg
        n_show = min(50, len(all_results))
        print(f"TOP {n_show} DECRYPTIONS (by consistency checks):")
        print("-" * 110)
        for rank, (qg, n_checks, ak_type, alpha, var_idx, L, desc, pt) in enumerate(all_results[:n_show], 1):
            var_name = VARIANT_NAMES[var_idx]
            print(f"  #{rank:3d}  checks={n_checks:2d}/{N_CRIBS}  qg={qg:+.4f}  "
                  f"{ak_type} {var_name}/{alpha} L={L}")
            print(f"        [{desc}]")
            if pt:
                print(f"        PT: {pt[:80]}...")

        best_qg = max(r[0] for r in all_results if r[7])
        if best_qg > -6.0:
            print(f"\n  *** POTENTIAL BREAKTHROUGH: Best quadgram {best_qg:+.4f} ***")
        elif best_qg > -7.5:
            print(f"\n  ** INTERESTING: Best quadgram {best_qg:+.4f} **")
        else:
            print(f"\n  Best quadgram {best_qg:+.4f} is noise level")
    else:
        print("NO autokey-consistent transpositions found.")

    # Save results
    import os
    os.makedirs("results", exist_ok=True)
    out_path = "results/mitm_autokey_transposition.json"
    try:
        results_data = {
            "total_tested": total_tested,
            "total_hits": total_hits,
            "elapsed_seconds": total_elapsed,
            "primers_tested": list(range(MIN_PRIMER, MAX_PRIMER + 1)),
            "autokey_types": ["PT-autokey", "CT-autokey"],
            "variants": VARIANT_NAMES,
            "alphabets": ALPHABET_NAMES,
            "family_stats": {k: {"tested": v[0], "hits": v[1], "best_checks": v[2]}
                             for k, v in family_stats.items()},
            "top_results": [
                {
                    "qg_score": r[0],
                    "n_checks": r[1],
                    "autokey_type": r[2],
                    "alphabet": r[3],
                    "variant": VARIANT_NAMES[r[4]],
                    "primer_length": r[5],
                    "transposition": r[6],
                    "plaintext": r[7][:100] if r[7] else "",
                }
                for r in all_results[:200]
            ],
        }
        with open(out_path, "w") as f:
            json.dump(results_data, f, indent=2)
        print(f"\nResults saved to {out_path}")
    except Exception as e:
        print(f"Warning: Could not save results: {e}")

    print(f"\n{'=' * 80}")
    print("DONE")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    attack()
