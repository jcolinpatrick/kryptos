#!/usr/bin/env python3
"""
RS 44 authentic dimensions (24 rows) on the Kryptos cipher panel.

Cipher:  RS 44 (24-row grid, 10 open cells/row, keyed column reading)
Family:  grille
Status:  exhausted
Keyspace: ~100M+ configs
Last run: never
Best score: N/A

HYPOTHESIS: The cipher panel (868 chars = K1+K2+K3+K4) is arranged in
a 24-row grid with variable width, and an RS 44 stencil selects the
real K4 ciphertext from it.

Key dimensions:
  24 × 25 = 600 (authentic RS 44)
  24 × 31 = 744
  24 × 36 = 864 (close to 868!)
  24 × 37 = 888
  8 × 97 = 776 (Sanborn's "8 lines")
  8 × 109 = 872 (close to 868!)

The 24 × 36 = 864 is only 4 short of 868 — tantalizingly close.
24 × 37 = 888 with 20 padding cells.
Or: use JUST K4 (97 chars) in a 24-row grid: 24 × 5 = 120 (too wide),
but 8 × 13 = 104 (close to 97, 7 padding).

Also tests: RS 44's authentic 10-open-per-row constraint.
"""

import sys
import os
import json
import time
import math
from pathlib import Path
from multiprocessing import Pool, cpu_count
from itertools import permutations

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ========================================================================
# FULL CIPHER PANEL TEXT (K1+K2+K3+K4)
# ========================================================================

# K1-K3 ciphertext from the sculpture (868 total on cipher panel)
# K1: 63 chars, K2: 372 chars, K3: 336 chars, K4: 97 chars = 868
# Using the carved text as it appears on the sculpture

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

FULL_PANEL = K1_CT + K2_CT + K3_CT + CT
PANEL_LEN = len(FULL_PANEL)
print(f"Panel: K1={len(K1_CT)} K2={len(K2_CT)} K3={len(K3_CT)} K4={len(CT)} total={PANEL_LEN}")

# ========================================================================
# RS 44 OPERATIONS
# ========================================================================

def rs44_extract(text, width, open_positions, col_order):
    """Extract open cells from grid by keyed column order.

    text: flat string placed in grid row by row
    width: grid width (number of columns)
    open_positions: set of flat indices that are open (stencil holes)
    col_order: column reading order (list of column indices)

    Returns: string of characters from open positions, read column-by-column.
    """
    n = len(text)
    rows = math.ceil(n / width)
    result = []
    for col in col_order:
        for row in range(rows):
            pos = row * width + col
            if pos < n and pos in open_positions:
                result.append(text[pos])
    return ''.join(result)


def precompute_extraction(n, width, open_positions, col_order):
    """Precompute flat indices for extraction."""
    rows = math.ceil(n / width)
    indices = []
    for col in col_order:
        for row in range(rows):
            pos = row * width + col
            if pos < n and pos in open_positions:
                indices.append(pos)
    return indices


# ========================================================================
# STENCIL GENERATORS (RS 44 authentic: 10 open per row)
# ========================================================================

def generate_rs44_stencils(width, n_rows, n_open_per_row=10, n_stencils=3000, seed=42):
    """Generate RS 44 authentic stencils: exactly n_open_per_row open cells per row."""
    import random
    rng = random.Random(seed)
    stencils = set()
    n = n_rows * width

    for _ in range(n_stencils * 3):
        positions = set()
        for row in range(n_rows):
            if width >= n_open_per_row:
                cols = rng.sample(range(width), n_open_per_row)
            else:
                cols = list(range(width))
            for col in cols:
                pos = row * width + col
                if pos < n:
                    positions.add(pos)
        stencils.add(frozenset(positions))
        if len(stencils) >= n_stencils:
            break

    return list(stencils)


def generate_variable_row_stencils(width, n_rows, n_stencils=2000, seed=123):
    """Variable 9-11 open cells per row (improved RS 44 suggestion)."""
    import random
    rng = random.Random(seed)
    stencils = set()
    n = n_rows * width

    for _ in range(n_stencils * 3):
        positions = set()
        for row in range(n_rows):
            n_open = rng.choice([9, 10, 11])
            n_open = min(n_open, width)
            cols = rng.sample(range(width), n_open)
            for col in cols:
                pos = row * width + col
                if pos < n:
                    positions.add(pos)
        stencils.add(frozenset(positions))
        if len(stencils) >= n_stencils:
            break

    return list(stencils)


def generate_k4_targeting_stencils(width, n_rows, text_len, k4_start, n_stencils=2000, seed=456):
    """Generate stencils where most open cells fall in the K4 region."""
    import random
    rng = random.Random(seed)
    stencils = set()
    n = min(text_len, n_rows * width)

    k4_positions = list(range(k4_start, min(k4_start + 97, n)))
    other_positions = [p for p in range(n) if p not in k4_positions]

    for _ in range(n_stencils * 3):
        # 73-97 cells in K4 region, rest scattered
        n_k4 = rng.randint(73, min(97, len(k4_positions)))
        n_other = rng.randint(0, min(50, len(other_positions)))
        k4_chosen = rng.sample(k4_positions, n_k4)
        other_chosen = rng.sample(other_positions, n_other) if n_other > 0 else []
        positions = frozenset(k4_chosen + other_chosen)
        stencils.add(positions)
        if len(stencils) >= n_stencils:
            break

    return list(stencils)


# ========================================================================
# SUBSTITUTION
# ========================================================================

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

def decrypt_text(ct_str, keyword, variant, alphabet):
    alpha = ALPH if alphabet == "AZ" else KRYPTOS_ALPHABET
    aidx = ALPH_IDX if alphabet == "AZ" else KA_IDX
    klen = len(keyword)
    result = []
    for i, c in enumerate(ct_str):
        ci = aidx.get(c)
        ki = aidx.get(keyword[i % klen])
        if ci is None or ki is None:
            result.append('?')
            continue
        if variant == "beaufort":
            pi = (ki - ci) % 26
        elif variant == "vigenere":
            pi = (ci - ki) % 26
        else:
            pi = (ci + ki) % 26
        result.append(alpha[pi])
    return ''.join(result)


# ========================================================================
# SCORING
# ========================================================================

ENE = "EASTNORTHEAST"
BC = "BERLINCLOCK"

def score_free(pt):
    s = 0
    if ENE in pt:
        s += 13
    if BC in pt:
        s += 11
    return s

def score_anchored(pt):
    total = 0
    if len(pt) >= 34:
        for i, ch in enumerate(ENE):
            if 21 + i < len(pt) and pt[21 + i] == ch:
                total += 1
    if len(pt) >= 74:
        for i, ch in enumerate(BC):
            if 63 + i < len(pt) and pt[63 + i] == ch:
                total += 1
    return total


# ========================================================================
# PARAMETERS
# ========================================================================

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "SEVEN", "BERLIN", "FIVE", "SANBORN", "SCHEIDT",
]

SUB_CONFIGS = []
for kw in KEYWORDS:
    for variant in ["beaufort", "vigenere"]:
        for alpha in ["AZ", "KA"]:
            SUB_CONFIGS.append((variant, kw, alpha))

# Column order keywords
COL_ORDER_KWS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "BERLINCLOCK", "EASTNORTHEAST", "SANBORN", "SCHEIDT",
    "SEVEN", "NDYAHR", "HAYDN", "RHAYDN", "FIVE",
]

def keyword_col_order(keyword, width):
    kw = keyword.upper()
    while len(kw) < width:
        kw += ALPH
    kw = kw[:width]
    indexed = [(kw[i], i) for i in range(width)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    return [x[1] for x in indexed]


# Grid configurations to test
GRID_CONFIGS = [
    # (width, text_source, label)
    # RS 44 authentic: 24 rows
    (25, "panel", "24x25_panel"),   # 24×25=600, uses first 600 of 868
    (36, "panel", "24x36_panel"),   # 24×36=864, almost fits 868
    (37, "panel", "24x37_panel"),   # 24×37=888, fits 868 with 20 pad

    # K4 only in various grids
    (5,  "k4", "20x5_k4"),         # ~20×5=100, close to 97
    (7,  "k4", "14x7_k4"),         # 14×7=98, K4+1 padding
    (8,  "k4", "13x8_k4"),         # 13×8=104, "8 lines" ×13
    (10, "k4", "10x10_k4"),        # 10×10=100
    (13, "k4", "8x13_k4"),         # 8×13=104, "8 lines" ×13
    (25, "k4", "4x25_k4"),         # 4×25=100, RS44 width

    # Full panel at special widths
    (31, "panel", "28x31_panel"),   # The confirmed master grid (865 chars in 28 rows)
    (7,  "panel", "124x7_panel"),   # Col7 connection
]


# ========================================================================
# WORKER
# ========================================================================

def worker(args):
    width, text, label, stencils, col_orders, sub_configs = args

    results = []
    configs = 0

    for stencil in stencils:
        for col_order in col_orders:
            indices = precompute_extraction(len(text), width, stencil, col_order)
            if len(indices) < 20:
                continue

            extracted = ''.join(text[i] for i in indices)

            # Mode 1: extracted text IS plaintext (direct read)
            configs += 1
            fs = score_free(extracted)
            if fs >= 11:
                results.append({
                    'score': fs, 'mode': 'direct', 'grid': label,
                    'width': width, 'col_order_len': len(col_order),
                    'open_cells': len(indices),
                    'pt': extracted[:80], 'pt_len': len(extracted),
                })

            # Mode 2: extracted text is CT, decrypt with keyword
            for variant, keyword, alphabet in sub_configs:
                configs += 1
                pt = decrypt_text(extracted, keyword, variant, alphabet)
                fs2 = score_free(pt)
                if fs2 >= 11:
                    results.append({
                        'score': fs2, 'mode': 'sub_decrypt', 'grid': label,
                        'variant': variant, 'keyword': keyword, 'alphabet': alphabet,
                        'open_cells': len(indices),
                        'pt': pt[:80], 'pt_len': len(pt),
                    })

            # Mode 3: use K4 CT as-is, but use extracted as running key
            if len(extracted) >= CT_LEN:
                for variant in ["beaufort", "vigenere"]:
                    configs += 1
                    pt_rk = decrypt_text(CT, extracted[:CT_LEN], variant, "AZ")
                    fs3 = score_free(pt_rk)
                    anch3 = score_anchored(pt_rk)
                    if fs3 >= 11 or anch3 >= 10:
                        results.append({
                            'score': max(fs3, anch3), 'mode': 'running_key',
                            'grid': label, 'variant': variant,
                            'open_cells': len(indices),
                            'pt': pt_rk[:80], 'pt_len': len(pt_rk),
                        })

    return results, configs


# ========================================================================
# MAIN
# ========================================================================

def run():
    t0 = time.time()
    ncores = min(cpu_count(), 28)

    print("=" * 72)
    print("RS 44 AUTHENTIC (24-ROW) ON CIPHER PANEL")
    print("=" * 72)
    print(f"Full panel: {len(FULL_PANEL)} chars (K1={len(K1_CT)} K2={len(K2_CT)} K3={len(K3_CT)} K4={len(CT)})")
    print(f"K4 starts at panel position: {len(K1_CT) + len(K2_CT) + len(K3_CT)}")
    print(f"Cores: {ncores}")
    print(f"Grid configs: {len(GRID_CONFIGS)}")
    print(f"Sub configs: {len(SUB_CONFIGS)}")
    print(flush=True)

    k4_start = len(K1_CT) + len(K2_CT) + len(K3_CT)

    all_results = []
    total_configs = 0

    for width, text_source, label in GRID_CONFIGS:
        gt0 = time.time()
        text = FULL_PANEL if text_source == "panel" else CT
        n_rows = math.ceil(len(text) / width)

        print(f"\n{'='*50}")
        print(f"{label}: {n_rows}×{width} = {n_rows*width} cells ({len(text)} chars)")
        print(f"{'='*50}")

        # Generate stencils
        stencils_rs44 = generate_rs44_stencils(width, n_rows, 10, 1500, seed=width*100)
        stencils_var = generate_variable_row_stencils(width, n_rows, 1000, seed=width*200)
        if text_source == "panel":
            stencils_k4 = generate_k4_targeting_stencils(width, n_rows, len(text), k4_start, 1000, seed=width*300)
        else:
            stencils_k4 = []

        all_stencils = list({frozenset(s) for s in stencils_rs44 + stencils_var + stencils_k4})
        print(f"  Stencils: {len(all_stencils)} (rs44={len(stencils_rs44)} var={len(stencils_var)} k4tgt={len(stencils_k4)})")

        # Column orders
        col_orders = [tuple(range(width)), tuple(range(width-1, -1, -1))]
        for kw in COL_ORDER_KWS:
            order = keyword_col_order(kw, width)
            col_orders.append(tuple(order))
            col_orders.append(tuple(reversed(order)))
        if width <= 7:
            for perm in permutations(range(width)):
                col_orders.append(perm)
        col_orders = list(set(col_orders))
        print(f"  Column orders: {len(col_orders)}")

        est = len(all_stencils) * len(col_orders) * (len(SUB_CONFIGS) + 3)
        print(f"  Estimated configs: {est:,}")

        # Build work items
        batch_size = max(1, len(all_stencils) // (ncores * 4))
        work_items = []
        for i in range(0, len(all_stencils), batch_size):
            batch = all_stencils[i:i + batch_size]
            work_items.append((width, text, label, batch, col_orders, SUB_CONFIGS))

        print(f"  Running ({len(work_items)} batches)...", flush=True)

        grid_configs = 0
        grid_results = []

        with Pool(ncores) as pool:
            for batch_results, batch_configs in pool.imap_unordered(worker, work_items, chunksize=1):
                grid_results.extend(batch_results)
                grid_configs += batch_configs

        total_configs += grid_configs
        all_results.extend(grid_results)

        gt = time.time() - gt0
        best_g = max((r['score'] for r in grid_results), default=0)
        print(f"  Done: {grid_configs:,} configs, {len(grid_results)} hits, best={best_g}/24, {gt:.1f}s")

    elapsed = time.time() - t0
    all_results.sort(key=lambda r: r['score'], reverse=True)

    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print(f"Total configs: {total_configs:,}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/60:.1f}m)")
    print(f"Hits: {len(all_results)}")

    best_score = all_results[0]['score'] if all_results else 0
    print(f"Best score: {best_score}/24")

    if all_results:
        print(f"\nTop 20:")
        for i, r in enumerate(all_results[:20]):
            print(f"  {i+1:3d}. {r['score']:2d}/24 | {r['grid']} {r['mode']} "
                  f"| {r.get('variant','')}/{r.get('keyword','')} "
                  f"| open={r.get('open_cells','')} "
                  f"| PT: {r.get('pt','')[:45]}")

    verdict = "SIGNAL" if best_score >= 18 else ("INTERESTING" if best_score >= 10 else "NOISE")
    print(f"\nVERDICT: {verdict}")

    out_path = Path(__file__).resolve().parents[2] / "results" / "e_rs44_24row_cipher_panel_v1.json"
    os.makedirs(out_path.parent, exist_ok=True)
    output = {
        'experiment': 'e_rs44_24row_cipher_panel_v1',
        'description': 'RS 44 authentic 24-row grid on cipher panel (868 chars) and K4 alone',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'elapsed_seconds': round(elapsed, 1),
        'best_score': best_score,
        'verdict': verdict,
        'grids_tested': [g[2] for g in GRID_CONFIGS],
        'top_50': all_results[:50],
    }
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    run()
