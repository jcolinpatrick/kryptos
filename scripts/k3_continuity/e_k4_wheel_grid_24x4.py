"""
Cipher: K4 4×24 Wheel Grid (Jefferson vertical cipher on K4)
Family: k3_continuity
Status: active
Keyspace: 4^24 ≈ 2.8e14 (pruned via targeted/beam/SA)
Last run: 2026-03-19
Best score: TBD
"""
import sys, os, json, itertools, random, time
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_POSITIONS, CRIB_DICT
from kryptos.kernel.scoring.ngram import get_default_scorer

COLS = 4
ROWS = 24

# Consensus null positions in CT97 (17 fixed)
CONSENSUS_NULLS = frozenset({0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85})
# Null palette letters
NULL_PALETTE = frozenset('BGIKOWZ')
# W positions in CT97
W_POSITIONS = frozenset({20, 36, 48, 58, 74})
# Crib positions (0-indexed in CT97)
ENE_POSITIONS = frozenset(range(21, 34))
BCL_POSITIONS = frozenset(range(63, 74))


# ── Grid construction ──────────────────────────────────────────────────────

def build_grid(ct_96):
    """Fill 4×24 grid column-by-column, bottom-to-top (K3 chart style)."""
    grid = [['.' for _ in range(COLS)] for _ in range(ROWS)]
    idx = 0
    for c in range(COLS):
        for r in range(ROWS - 1, -1, -1):
            if idx < len(ct_96):
                grid[r][c] = ct_96[idx]
                idx += 1
    return grid


def build_position_map(ct_96, ct97_offset):
    """Map each grid cell (r, c) to its position in CT97.
    ct97_offset: 0 for Model A (drop last), 1 for Model B (drop first)."""
    pos_map = {}
    idx = 0
    for c in range(COLS):
        for r in range(ROWS - 1, -1, -1):
            if idx < 96:
                pos_map[(r, c)] = idx + ct97_offset
                idx += 1
    return pos_map


# ── Phase 1: Static analysis ───────────────────────────────────────────────

def static_analysis(model_name, ct_96, ct97_offset):
    """Phase 1: Build grid and report tag distributions."""
    print(f"\n{'='*60}")
    print(f"PHASE 1 — STATIC ANALYSIS [{model_name}]")
    print(f"{'='*60}")

    grid = build_grid(ct_96)
    pos_map = build_position_map(ct_96, ct97_offset)

    # Print annotated grid
    print(f"\n  {'':4s}" + "  ".join(f"C{c+1}" for c in range(COLS)))
    print(f"  {'':4s}" + "----" * COLS)

    col_nulls = [0] * COLS
    col_palette = [0] * COLS
    col_w = [0] * COLS
    col_crib = [0] * COLS

    for r in range(ROWS):
        row_str = ""
        for c in range(COLS):
            ch = grid[r][c]
            ct97_pos = pos_map.get((r, c), -1)
            tags = []
            if ct97_pos in CONSENSUS_NULLS:
                tags.append('N')
                col_nulls[c] += 1
            if ch in NULL_PALETTE:
                tags.append('P')
                col_palette[c] += 1
            if ct97_pos in W_POSITIONS:
                tags.append('W')
                col_w[c] += 1
            if ct97_pos in ENE_POSITIONS or ct97_pos in BCL_POSITIONS:
                tags.append('C')
                col_crib[c] += 1

            tag_str = ''.join(tags) if tags else ' '
            row_str += f"  {ch}{tag_str:3s}"
        print(f"  R{r+1:02d}:{row_str}")

    print(f"\n  Distribution across 4 columns:")
    print(f"  {'Tag':12s} C1   C2   C3   C4   Total")
    print(f"  {'─'*45}")
    print(f"  {'Cons.Nulls':12s} {col_nulls[0]:3d}  {col_nulls[1]:3d}  {col_nulls[2]:3d}  {col_nulls[3]:3d}  {sum(col_nulls):3d}")
    print(f"  {'Palette':12s} {col_palette[0]:3d}  {col_palette[1]:3d}  {col_palette[2]:3d}  {col_palette[3]:3d}  {sum(col_palette):3d}")
    print(f"  {'W positions':12s} {col_w[0]:3d}  {col_w[1]:3d}  {col_w[2]:3d}  {col_w[3]:3d}  {sum(col_w):3d}")
    print(f"  {'Crib chars':12s} {col_crib[0]:3d}  {col_crib[1]:3d}  {col_crib[2]:3d}  {col_crib[3]:3d}  {sum(col_crib):3d}")

    return grid, pos_map, col_nulls


# ── Scoring functions ──────────────────────────────────────────────────────

def read_columns(grid, offsets, direction='bottom_up'):
    """Read all 4 columns with given row offsets."""
    columns = []
    for c in range(COLS):
        col_str = ""
        for r in range(ROWS):
            ri = (ROWS - 1 - r) if direction == 'bottom_up' else r
            off = offsets[ri]
            src = ((c - off) % COLS + COLS) % COLS
            col_str += grid[ri][src]
        columns.append(col_str)
    return columns


def null_concentration(offsets, pos_map):
    """How unevenly are consensus nulls distributed after rotation?
    Returns (max_share, col_counts).
    max_share=1.0 means all nulls in one column. =0.25 means uniform."""
    col_counts = [0] * COLS
    for (r, c_orig), ct97_pos in pos_map.items():
        if ct97_pos in CONSENSUS_NULLS:
            off = offsets[r]
            c_new = (c_orig + off) % COLS
            col_counts[c_new] += 1
    n = sum(col_counts)
    if n == 0:
        return 0.0, col_counts
    max_share = max(col_counts) / n
    return max_share, col_counts


def w_alignment(offsets, pos_map):
    """How many W positions land in the same column?"""
    col_counts = [0] * COLS
    for (r, c_orig), ct97_pos in pos_map.items():
        if ct97_pos in W_POSITIONS:
            off = offsets[r]
            c_new = (c_orig + off) % COLS
            col_counts[c_new] += 1
    return max(col_counts), col_counts


def palette_concentration(grid, offsets):
    """How unevenly are null palette letters distributed after rotation?"""
    col_counts = [0] * COLS
    total = 0
    for r in range(ROWS):
        off = offsets[r]
        for c in range(COLS):
            src = ((c - off) % COLS + COLS) % COLS
            if grid[r][src] in NULL_PALETTE:
                col_counts[c] += 1
                total += 1
    if total == 0:
        return 0.0, col_counts
    return max(col_counts) / total, col_counts


def score_config(grid, offsets, pos_map, qg):
    """Composite score for a rotation config."""
    nc, nc_cols = null_concentration(offsets, pos_map)
    wa, wa_cols = w_alignment(offsets, pos_map)
    pc, pc_cols = palette_concentration(grid, offsets)

    cols = read_columns(grid, offsets, 'bottom_up')
    qg_total = sum(qg.score(c) for c in cols)
    qg_norm = qg_total / (COLS * ROWS)  # per char

    # Composite: null concentration is primary objective
    composite = 0.4 * nc + 0.1 * (wa / 5.0) + 0.2 * pc + 0.3 * ((qg_norm + 6.0) / 2.0)

    return {
        'null_conc': nc, 'null_cols': nc_cols,
        'w_align': wa, 'w_cols': wa_cols,
        'palette_conc': pc, 'palette_cols': pc_cols,
        'qg_total': qg_total, 'qg_per_char': qg_norm,
        'composite': composite,
        'col_texts': cols,
    }


# ── Phase 2a: Targeted exhaustive search ──────────────────────────────────

def find_target_rows(pos_map):
    """Rows containing consensus nulls or W positions."""
    target = set()
    for (r, c), ct97_pos in pos_map.items():
        if ct97_pos in CONSENSUS_NULLS or ct97_pos in W_POSITIONS:
            target.add(r)
    return sorted(target)


def phase_2a(model_name, grid, pos_map, qg, max_target_rows=10):
    """Exhaustive search on rows with nulls/W, other rows fixed at 0."""
    print(f"\n{'='*60}")
    print(f"PHASE 2a — TARGETED EXHAUSTIVE [{model_name}]")
    print(f"{'='*60}")

    targets = find_target_rows(pos_map)
    if len(targets) > max_target_rows:
        print(f"  {len(targets)} target rows > limit {max_target_rows}, trimming to highest-value rows")
        # Prioritize rows with most null/W positions
        row_value = {}
        for r in targets:
            val = sum(1 for (rr, c), p in pos_map.items()
                      if rr == r and (p in CONSENSUS_NULLS or p in W_POSITIONS))
            row_value[r] = val
        targets = sorted(row_value, key=row_value.get, reverse=True)[:max_target_rows]
        targets.sort()

    n_configs = 4 ** len(targets)
    print(f"  Target rows: {targets} ({len(targets)} rows)")
    print(f"  Configs: {n_configs:,}")

    best = {'composite': float('-inf')}
    best_offsets = [0] * ROWS
    t0 = time.time()

    for i, combo in enumerate(itertools.product(range(4), repeat=len(targets))):
        offsets = [0] * ROWS
        for j, r in enumerate(targets):
            offsets[r] = combo[j]

        sc = score_config(grid, offsets, pos_map, qg)
        if sc['composite'] > best.get('composite', float('-inf')):
            best = sc
            best_offsets = offsets[:]
            if i > 0 and i % 100000 == 0:
                elapsed = time.time() - t0
                print(f"  NEW BEST at {i:,}: null={sc['null_conc']:.3f} "
                      f"w={sc['w_align']} qg={sc['qg_per_char']:.3f} "
                      f"comp={sc['composite']:.4f} [{elapsed:.0f}s]", flush=True)

        if (i + 1) % 1_000_000 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            print(f"  {i+1:,}/{n_configs:,} ({rate:.0f}/s) "
                  f"best_comp={best['composite']:.4f}", flush=True)

    print(f"\n  BEST [{model_name}]:")
    print(f"    Null concentration: {best['null_conc']:.3f} {best['null_cols']}")
    print(f"    W alignment: {best['w_align']}/5 {best['w_cols']}")
    print(f"    Palette: {best['palette_conc']:.3f} {best['palette_cols']}")
    print(f"    Quadgram/char: {best['qg_per_char']:.3f}")
    print(f"    Composite: {best['composite']:.4f}")
    print(f"    Offsets: {best_offsets}")
    print(f"    Columns: {best['col_texts']}")

    return best, best_offsets


# ── Phase 2b: Beam search ──────────────────────────────────────────────────

def phase_2b(model_name, grid, pos_map, qg, beam_width=500):
    """Beam search: assign row offsets one at a time, pruning by composite score."""
    print(f"\n{'='*60}")
    print(f"PHASE 2b — BEAM SEARCH [{model_name}] (beam={beam_width})")
    print(f"{'='*60}")

    beam = [([],  0.0)]  # (partial_offsets, score)

    for row_idx in range(ROWS):
        new_beam = []
        for partial, _ in beam:
            for shift in range(4):
                new_partial = partial + [shift]
                offsets = new_partial + [0] * (ROWS - len(new_partial))
                sc = score_config(grid, offsets, pos_map, qg)
                new_beam.append((new_partial, sc['composite']))

        new_beam.sort(key=lambda x: x[1], reverse=True)
        beam = new_beam[:beam_width]

        if (row_idx + 1) % 6 == 0 or row_idx == ROWS - 1:
            print(f"  Row {row_idx+1}/{ROWS}: top={beam[0][1]:.4f} "
                  f"bottom={beam[-1][1]:.4f}", flush=True)

    # Final scoring of top candidates
    print(f"\n  Top 5:")
    for rank, (offsets_list, comp) in enumerate(beam[:5]):
        sc = score_config(grid, offsets_list, pos_map, qg)
        print(f"  #{rank+1}: null={sc['null_conc']:.3f} w={sc['w_align']} "
              f"qg={sc['qg_per_char']:.3f} comp={comp:.4f}")
        print(f"       offsets={offsets_list}")
        print(f"       cols={sc['col_texts']}")

    best_offsets = beam[0][0]
    return beam[0], best_offsets


# ── Phase 2c: Simulated annealing ─────────────────────────────────────────

def phase_2c(model_name, grid, pos_map, qg, n_restarts=1000, n_steps=1000):
    """Simulated annealing with null-concentration objective."""
    print(f"\n{'='*60}")
    print(f"PHASE 2c — SIMULATED ANNEALING [{model_name}]")
    print(f"  ({n_restarts:,} restarts × {n_steps:,} steps)")
    print(f"{'='*60}")

    global_best_score = float('-inf')
    global_best_offsets = None
    global_best_info = None
    t0 = time.time()

    for restart in range(n_restarts):
        offsets = [random.randint(0, 3) for _ in range(ROWS)]
        sc = score_config(grid, offsets, pos_map, qg)
        current_score = sc['composite']

        for step in range(n_steps):
            temp = 1.0 * (1.0 - step / n_steps)
            r = random.randint(0, ROWS - 1)
            old_val = offsets[r]
            offsets[r] = random.randint(0, 3)

            sc_new = score_config(grid, offsets, pos_map, qg)
            new_score = sc_new['composite']
            delta = new_score - current_score

            if delta > 0 or (temp > 0 and random.random() < 2.718 ** (delta / max(temp, 1e-10))):
                current_score = new_score
                sc = sc_new
            else:
                offsets[r] = old_val

        if current_score > global_best_score:
            global_best_score = current_score
            global_best_offsets = offsets[:]
            global_best_info = sc
            if restart > 0:
                elapsed = time.time() - t0
                print(f"  NEW BEST at restart {restart:,}: "
                      f"null={sc['null_conc']:.3f} w={sc['w_align']} "
                      f"qg={sc['qg_per_char']:.3f} comp={current_score:.4f} "
                      f"[{elapsed:.0f}s]", flush=True)

        if (restart + 1) % 200 == 0:
            elapsed = time.time() - t0
            print(f"  {restart+1:,}/{n_restarts:,} restarts "
                  f"best_comp={global_best_score:.4f} [{elapsed:.0f}s]", flush=True)

    print(f"\n  BEST [{model_name}]:")
    info = global_best_info
    print(f"    Null conc: {info['null_conc']:.3f} {info['null_cols']}")
    print(f"    W align: {info['w_align']}/5 {info['w_cols']}")
    print(f"    Palette: {info['palette_conc']:.3f}")
    print(f"    Qg/char: {info['qg_per_char']:.3f}")
    print(f"    Composite: {global_best_score:.4f}")
    print(f"    Offsets: {global_best_offsets}")
    print(f"    Columns: {info['col_texts']}")

    return global_best_score, global_best_offsets, global_best_info


# ── Phase 3: Stego separation + decryption ────────────────────────────────

def phase_3(model_name, grid, offsets, pos_map, qg):
    """Extract clean columns, try Vigenère/Beaufort with thematic keywords."""
    print(f"\n{'='*60}")
    print(f"PHASE 3 — STEGO SEPARATION [{model_name}]")
    print(f"{'='*60}")

    from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant

    sc = score_config(grid, offsets, pos_map, qg)
    cols = sc['col_texts']
    null_cols = sc['null_cols']

    # Identify clean vs dirty columns
    min_nulls = min(null_cols)
    max_nulls = max(null_cols)
    clean_cols = [i for i, n in enumerate(null_cols) if n <= min_nulls]
    dirty_cols = [i for i, n in enumerate(null_cols) if n >= max_nulls]

    print(f"  Null distribution: {null_cols}")
    print(f"  Clean columns (fewest nulls): {[c+1 for c in clean_cols]}")
    print(f"  Dirty columns (most nulls): {[c+1 for c in dirty_cols]}")

    # Print all column texts
    for ci in range(COLS):
        print(f"  Col {ci+1} ({null_cols[ci]} nulls): {cols[ci]}")

    # Try decryption on each column with thematic keywords
    keywords = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'DEFECTOR', 'COLOPHON',
                'KOMPASS', 'SHADOW', 'ENIGMA', 'BERLIN', 'CLOCK']

    print(f"\n  Decryption attempts on clean columns:")
    best_decrypt = (float('-inf'), '', '', '', '')

    for ci in clean_cols:
        text = cols[ci]
        key_nums_cache = {}
        for kw in keywords:
            # Build numeric key extended to text length
            if kw not in key_nums_cache:
                kw_nums = [ord(c) - 65 for c in kw]
                key_nums_cache[kw] = kw_nums
            key_nums = key_nums_cache[kw]
            n = len(text)
            key_extended = [key_nums[i % len(key_nums)] for i in range(n)]

            for cipher_name, variant in [('vig', CipherVariant.VIGENERE),
                                          ('beau', CipherVariant.BEAUFORT),
                                          ('vbeau', CipherVariant.VAR_BEAUFORT)]:
                try:
                    pt = decrypt_text(text, key_extended, variant)
                    s = qg.score(pt)
                    if s > best_decrypt[0]:
                        best_decrypt = (s, pt, kw, cipher_name, f"col{ci+1}")
                    if s > -85.0:  # report anything promising (threshold for 24-char text)
                        print(f"    Col{ci+1} {cipher_name}/{kw}: {s:.1f} = {pt}")
                except Exception as e:
                    pass

    print(f"\n  Best decryption: {best_decrypt[1]} "
          f"({best_decrypt[3]}/{best_decrypt[2]} on {best_decrypt[4]}, score={best_decrypt[0]:.1f})")

    return best_decrypt


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    random.seed(42)
    print("K4 4×24 Wheel Grid Analysis")
    print("=" * 60)
    print(f"CT97: {CT}")
    print(f"Length: {len(CT)}")

    # Model A: drop last char (R at pos 96)
    ct_a = CT[:96]
    # Model B: drop first char (O at pos 0)
    ct_b = CT[1:97]

    grid_a, pos_a, nulls_a = static_analysis("Model A (drop last R)", ct_a, ct97_offset=0)
    grid_b, pos_b, nulls_b = static_analysis("Model B (drop first O)", ct_b, ct97_offset=1)

    # Load scorer
    print("\nLoading quadgram scorer...", flush=True)
    qg = get_default_scorer()
    print("  Scorer loaded.", flush=True)

    # Baseline scoring (no rotation)
    print("\n" + "="*60)
    print("BASELINE SCORING (no rotation)")
    print("="*60)
    for name, grid, pos_map in [("Model A", grid_a, pos_a), ("Model B", grid_b, pos_b)]:
        baseline = score_config(grid, [0]*ROWS, pos_map, qg)
        print(f"\n  {name} baseline:")
        print(f"    Null concentration: {baseline['null_conc']:.3f} {baseline['null_cols']}")
        print(f"    W alignment: {baseline['w_align']}/5 {baseline['w_cols']}")
        print(f"    Palette conc: {baseline['palette_conc']:.3f} {baseline['palette_cols']}")
        print(f"    Quadgram/char: {baseline['qg_per_char']:.3f}")
        print(f"    Composite: {baseline['composite']:.4f}")
        print(f"    Columns: {baseline['col_texts']}")

    # Phase 2a + 2b + 2c + Phase 3 for each model
    all_results = {}

    for name, grid, pos_map in [("Model A", grid_a, pos_a), ("Model B", grid_b, pos_b)]:
        model_results = {}

        best_2a, offsets_2a = phase_2a(name, grid, pos_map, qg)
        model_results['phase_2a'] = {
            'composite': best_2a['composite'],
            'null_conc': best_2a['null_conc'],
            'w_align': best_2a['w_align'],
            'qg_per_char': best_2a['qg_per_char'],
            'offsets': offsets_2a,
            'col_texts': best_2a['col_texts'],
        }

        beam_result, offsets_2b = phase_2b(name, grid, pos_map, qg)
        sc_2b = score_config(grid, offsets_2b, pos_map, qg)
        model_results['phase_2b'] = {
            'composite': beam_result[1],
            'null_conc': sc_2b['null_conc'],
            'w_align': sc_2b['w_align'],
            'qg_per_char': sc_2b['qg_per_char'],
            'offsets': offsets_2b,
            'col_texts': sc_2b['col_texts'],
        }

        score_2c, offsets_2c, info_2c = phase_2c(name, grid, pos_map, qg)
        model_results['phase_2c'] = {
            'composite': score_2c,
            'null_conc': info_2c['null_conc'],
            'w_align': info_2c['w_align'],
            'qg_per_char': info_2c['qg_per_char'],
            'offsets': offsets_2c,
            'col_texts': info_2c['col_texts'],
        }

        # Phase 3 on best from 2a and 2c
        dec_2a = phase_3(f"{name}/2a-best", grid, offsets_2a, pos_map, qg)
        dec_2b = phase_3(f"{name}/2b-best", grid, offsets_2b, pos_map, qg)
        dec_2c = phase_3(f"{name}/2c-best", grid, offsets_2c, pos_map, qg)

        model_results['phase_3'] = {
            'best_2a': {'score': dec_2a[0], 'pt': dec_2a[1], 'kw': dec_2a[2], 'cipher': dec_2a[3], 'col': dec_2a[4]},
            'best_2b': {'score': dec_2b[0], 'pt': dec_2b[1], 'kw': dec_2b[2], 'cipher': dec_2b[3], 'col': dec_2b[4]},
            'best_2c': {'score': dec_2c[0], 'pt': dec_2c[1], 'kw': dec_2c[2], 'cipher': dec_2c[3], 'col': dec_2c[4]},
        }

        all_results[name] = model_results

    # Save results
    output = {
        'experiment': 'e_k4_wheel_grid_24x4',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'hypothesis': 'K4 in 4x24 grid (matching K3 chart rows), wheel rotation separates stego',
        'models_tested': ['A (drop last R)', 'B (drop first O)'],
        'phases': ['1_static', '2a_targeted', '2b_beam', '2c_sa', '3_stego_separation'],
        'results': all_results,
    }
    results_dir = os.path.join(_ROOT, 'results')
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, 'e_k4_wheel_grid_24x4.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {out_path}")
    print("\nDone.")
