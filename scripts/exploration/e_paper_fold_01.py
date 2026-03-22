#!/usr/bin/env python3
"""
E-PAPER-FOLD-01: Physical Paper Operations on K4 Grids

Cipher:      Beaufort / Vigenere / Variant Beaufort
Family:      exploration
Status:      active
Keyspace:    ~15,000 configurations
Last run:    never
Best score:  n/a

Hypothesis: K4's keystream is derived from physical paper manipulation
(folding, overlaying) of sculpture text written onto grids. The decryptor
copies sculpture text onto graph paper in a known grid format, then
performs a physical operation (fold at a seam, overlay on light table)
that reveals the key or null mask.

The triangle (△) symbol on the K1-K2 encoding chart may indicate the
fold line. ABSCISSA = "cut off" (Latin abscindere) is both keyword and
physical instruction.

Five grid configurations:
  A) K4 in 14×7  (?+K4 = 98 chars) — self-fold
  B) K3+?+K4 in 14×31 (434 chars) — K3-onto-K4 fold at ABSCISSA seam
  C) K4 overlay on KA Vigenère tableau — grid offset
  D) Full panel in 28×31 — section-crossing fold
  E) K4 overlay on K3 chart (14×24) — variable row offset

Operations: fold (horizontal/vertical), overlay, match-indicator null mask.
"""

import sys, os, json, time
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.alphabet import AZ, KA

# ── Constants ──────────────────────────────────────────────────────────

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLGTI"
    "MVMZJANQLVKQEDAGDVFRPJUNGEUNAQZ"
    "GZLECGYUXUEENJTBJLBQCRTBJDFHRRY"
    "IZETKZEMVDUFKSJHKFWHKUWQLSZFTIH"
    "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEV"
    "LDKFEZMOQQJLTTUGSYQPFEUNLAVIDXF"
    "LGGTEZFKZBSFDQVGOGIPUFXHHDRKFFH"
    "QNTGPUAECNUVPDJMQCLQUMUNEDFQELZ"
    "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQ"
    "FMPNZGLFLPMRJQYALMGNUVPDXVKPDQU"
    "MEBEDMHDAFM"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNETP"
    "RNGATIHNRARPESLNNELEBLPIIACAEWMTW"
    "NDITEENRAHCTENEUDRETNHAEOETFOLSED"
    "TIWENHAEIOYTEYQHEENCTAYCREIFTBRSP"
    "AMHHEWENATAMATEGYEERLBTEEFOASFIOT"
    "UETUAEOTOARMAEERTNRTIBSEDDNIAAHTT"
    "MSTEWPIEROAGRIEWFEBAECTDDHILCEIHS"
    "ITEGOEAOSDDRYDLORITRKLMLEHAGTDHAR"
    "DPNEOHMGFMFEUHEECDMRIPFEIMEHNLSS"
    "TTRTVDOHW"
)
K4_CT = CT

# Known cribs (0-indexed in CT97)
CRIBS = {}
ene = "EASTNORTHEAST"
for i, ch in enumerate(ene):
    CRIBS[21 + i] = ord(ch) - ord('A')
bcl = "BERLINCLOCK"
for i, ch in enumerate(bcl):
    CRIBS[63 + i] = ord(ch) - ord('A')

# CT as numbers
CT_NUMS = [ord(c) - ord('A') for c in K4_CT]

# Consensus null positions (17 fixed)
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}

# Known keystreams under each cipher variant
KNOWN_KEY = {}
for variant in ('beaufort', 'vigenere', 'varbeau'):
    KNOWN_KEY[variant] = {}
    for pos, pt_val in CRIBS.items():
        ct_val = CT_NUMS[pos]
        if variant == 'beaufort':
            KNOWN_KEY[variant][pos] = (ct_val + pt_val) % 26
        elif variant == 'vigenere':
            KNOWN_KEY[variant][pos] = (ct_val - pt_val) % 26
        elif variant == 'varbeau':
            KNOWN_KEY[variant][pos] = (pt_val - ct_val) % 26


# ── Grid utilities ────────────────────────────────────────────────────

FILL_ORDERS = ['lr_tb', 'boustrophedon', 'col_major', 'col_boustrophedon', 'bt_lr']


def fill_position(i, rows, cols, fill_order):
    """Map linear text position i to (row, col) for given fill order."""
    if fill_order == 'lr_tb':
        return (i // cols, i % cols)
    elif fill_order == 'boustrophedon':
        row = i // cols
        col_in_row = i % cols
        col = col_in_row if row % 2 == 0 else (cols - 1 - col_in_row)
        return (row, col)
    elif fill_order == 'col_major':
        return (i % rows, i // rows)
    elif fill_order == 'col_boustrophedon':
        col = i // rows
        row_in_col = i % rows
        row = row_in_col if col % 2 == 0 else (rows - 1 - row_in_col)
        return (row, col)
    elif fill_order == 'bt_lr':
        return ((rows - 1) - i // cols, i % cols)
    raise ValueError(f"Unknown fill order: {fill_order}")


def make_grid(text_nums, rows, cols, fill_order):
    """Fill text into grid. Returns (val_grid, pos_grid).
    val_grid[r][c] = letter value (0-25), pos_grid[r][c] = original text index.
    """
    val_grid = [[None] * cols for _ in range(rows)]
    pos_grid = [[None] * cols for _ in range(rows)]
    for i, val in enumerate(text_nums):
        if i >= rows * cols:
            break
        r, c = fill_position(i, rows, cols, fill_order)
        val_grid[r][c] = val
        pos_grid[r][c] = i
    return val_grid, pos_grid


def get_fold_pairs(rows, cols, axis, fold_pos):
    """Get all cell pairs from folding at fold_pos along axis.
    Horizontal fold at fold_pos: fold line between row fold_pos-1 and fold_pos.
    Vertical fold at fold_pos: fold line between col fold_pos-1 and fold_pos.
    Returns list of ((r1,c1), (r2,c2)) pairs.
    """
    pairs = []
    if axis == 'h':
        for k in range(min(fold_pos, rows - fold_pos)):
            for j in range(cols):
                r1 = fold_pos - 1 - k
                r2 = fold_pos + k
                if 0 <= r1 < rows and 0 <= r2 < rows:
                    pairs.append(((r1, j), (r2, j)))
    elif axis == 'v':
        for k in range(min(fold_pos, cols - fold_pos)):
            for i in range(rows):
                c1 = fold_pos - 1 - k
                c2 = fold_pos + k
                if 0 <= c1 < cols and 0 <= c2 < cols:
                    pairs.append(((i, c1), (i, c2)))
    return pairs


# ── Key derivation models ─────────────────────────────────────────────

def derive_keys_at_cribs(pairs, pos_grid, val_grid, crib_positions):
    """For each fold pair, if one position is a crib position,
    derive candidate key values using 4 combination models.
    Returns dict: {model_name: {crib_pos: key_value}}.
    """
    # Build reverse map: text_pos -> (r, c)
    rows = len(pos_grid)
    cols = len(pos_grid[0])
    pos_to_cell = {}
    for r in range(rows):
        for c in range(cols):
            if pos_grid[r][c] is not None:
                pos_to_cell[pos_grid[r][c]] = (r, c)

    # Build pair map: cell -> paired_cell
    pair_map = {}
    for (r1, c1), (r2, c2) in pairs:
        pair_map[(r1, c1)] = (r2, c2)
        pair_map[(r2, c2)] = (r1, c1)

    models = {
        'direct': {},      # key = paired letter value
        'add': {},         # key = (val1 + val2) % 26
        'sub_fwd': {},     # key = (val1 - val2) % 26
        'sub_rev': {},     # key = (val2 - val1) % 26
    }

    for crib_pos in crib_positions:
        if crib_pos not in pos_to_cell:
            continue
        cell = pos_to_cell[crib_pos]
        if cell not in pair_map:
            continue
        paired_cell = pair_map[cell]
        r2, c2 = paired_cell
        if val_grid[r2][c2] is None:
            continue

        v1 = val_grid[cell[0]][cell[1]]
        v2 = val_grid[r2][c2]

        models['direct'][crib_pos] = v2
        models['add'][crib_pos] = (v1 + v2) % 26
        models['sub_fwd'][crib_pos] = (v1 - v2) % 26
        models['sub_rev'][crib_pos] = (v2 - v1) % 26

    return models


def score_model(derived_keys, known_keys):
    """Score derived keys against known keystream. Returns match count."""
    matches = 0
    for pos, val in derived_keys.items():
        if pos in known_keys and val == known_keys[pos]:
            matches += 1
    return matches


def score_null_mask(pairs, pos_grid, val_grid, consensus_nulls, crib_positions):
    """Check if fold-match positions (where aligned letters are equal)
    correspond to null positions. Returns (null_overlap, crib_conflict, total_matches)."""
    rows = len(pos_grid)
    cols = len(pos_grid[0])

    match_positions = set()
    for (r1, c1), (r2, c2) in pairs:
        v1 = val_grid[r1][c1]
        v2 = val_grid[r2][c2]
        if v1 is not None and v2 is not None and v1 == v2:
            p1 = pos_grid[r1][c1]
            p2 = pos_grid[r2][c2]
            if p1 is not None:
                match_positions.add(p1)
            if p2 is not None:
                match_positions.add(p2)

    null_overlap = len(match_positions & consensus_nulls)
    crib_conflict = len(match_positions & crib_positions)
    return null_overlap, crib_conflict, len(match_positions)


# ── Grid A: K4 in 14×7 (?+K4 = 98 chars) ─────────────────────────────

def run_grid_a(results):
    """Self-fold on K4's own 14×7 grid."""
    print("\n=== GRID A: K4 in 14×7 (?+K4 = 98) — Self-fold ===")
    # Pad with placeholder at position 0 (the ? delimiter)
    # Use a sentinel value (26) for ?; it won't match any letter
    text = [26] + CT_NUMS  # 98 chars: ? + 97 CT chars
    rows, cols = 7, 14

    crib_set = set(CRIBS.keys())
    # Crib positions in the ?+K4 text are shifted by +1
    shifted_cribs = {p + 1: v for p, v in CRIBS.items()}
    shifted_crib_positions = set(shifted_cribs.keys())

    # Also build shifted known keys
    shifted_known = {}
    for variant in ('beaufort', 'vigenere', 'varbeau'):
        shifted_known[variant] = {p + 1: v for p, v in KNOWN_KEY[variant].items()}

    # Also test WITHOUT the ? prefix (raw K4 in various grid sizes)
    grid_configs = [
        (7, 14, text, shifted_crib_positions, shifted_known, "14x7_with_prefix"),
        # Also try K4 (97 chars) in near-rectangular grids
        (7, 14, CT_NUMS + [26], shifted_crib_positions, shifted_known, "14x7_padded"),  # pad to 98 with sentinel at end
    ]

    for grid_rows, grid_cols, grid_text, grid_cribs, grid_known, grid_label in grid_configs:
        for fill in FILL_ORDERS:
            val_grid, pos_grid = make_grid(grid_text, grid_rows, grid_cols, fill)

            # Horizontal folds
            for h in range(1, grid_rows):
                pairs = get_fold_pairs(grid_rows, grid_cols, 'h', h)
                models = derive_keys_at_cribs(pairs, pos_grid, val_grid, grid_cribs)
                for model_name, derived in models.items():
                    if not derived:
                        continue
                    for variant in ('beaufort', 'vigenere', 'varbeau'):
                        sc = score_model(derived, grid_known[variant])
                        if sc >= 6:
                            results.append({
                                'grid': 'A', 'label': grid_label, 'fill': fill,
                                'fold': f'h{h}', 'model': model_name,
                                'variant': variant, 'score': sc,
                                'n_pairs': len(derived),
                            })

                # Null mask test
                null_ov, crib_conf, n_match = score_null_mask(
                    pairs, pos_grid, val_grid,
                    {p + 1 for p in CONSENSUS_NULLS},  # shifted
                    grid_cribs
                )
                if null_ov >= 5 and crib_conf == 0:
                    results.append({
                        'grid': 'A', 'label': grid_label, 'fill': fill,
                        'fold': f'h{h}', 'model': 'null_mask',
                        'variant': 'match_indicator', 'score': null_ov,
                        'crib_conflict': crib_conf, 'total_matches': n_match,
                    })

            # Vertical folds
            for v in range(1, grid_cols):
                pairs = get_fold_pairs(grid_rows, grid_cols, 'v', v)
                models = derive_keys_at_cribs(pairs, pos_grid, val_grid, grid_cribs)
                for model_name, derived in models.items():
                    if not derived:
                        continue
                    for variant in ('beaufort', 'vigenere', 'varbeau'):
                        sc = score_model(derived, grid_known[variant])
                        if sc >= 6:
                            results.append({
                                'grid': 'A', 'label': grid_label, 'fill': fill,
                                'fold': f'v{v}', 'model': model_name,
                                'variant': variant, 'score': sc,
                                'n_pairs': len(derived),
                            })

                null_ov, crib_conf, n_match = score_null_mask(
                    pairs, pos_grid, val_grid,
                    {p + 1 for p in CONSENSUS_NULLS},
                    grid_cribs
                )
                if null_ov >= 5 and crib_conf == 0:
                    results.append({
                        'grid': 'A', 'label': grid_label, 'fill': fill,
                        'fold': f'v{v}', 'model': 'null_mask',
                        'variant': 'match_indicator', 'score': null_ov,
                        'crib_conflict': crib_conf, 'total_matches': n_match,
                    })

    # Count configs
    n = len(grid_configs) * len(FILL_ORDERS) * ((7 - 1) + (14 - 1))
    print(f"  Tested {n} fold configurations × 12 scoring models")
    print(f"  Results above threshold: {sum(1 for r in results if r['grid'] == 'A')}")


# ── Grid B: K3+?+K4 in 14×31 ──────────────────────────────────────────

def run_grid_b(results):
    """Fold K3 portion onto K4 portion at ABSCISSA boundary."""
    print("\n=== GRID B: K3+?+K4 in 14×31 (434 chars) — ABSCISSA fold ===")
    k3_nums = [ord(c) - ord('A') for c in K3_CT]
    k4_nums = CT_NUMS
    # ? delimiter = sentinel 26
    combined = k3_nums + [26] + k4_nums  # 336 + 1 + 97 = 434 = 14×31
    assert len(combined) == 434, f"Expected 434, got {len(combined)}"

    rows, cols = 31, 14
    crib_set = set(CRIBS.keys())

    # K4 positions in the combined text start at index 337 (after K3+?)
    k4_offset = 337
    combined_crib_pos = {p + k4_offset for p in CRIBS.keys()}
    combined_known = {}
    for variant in ('beaufort', 'vigenere', 'varbeau'):
        combined_known[variant] = {p + k4_offset: v for p, v in KNOWN_KEY[variant].items()}

    count = 0
    for fill in FILL_ORDERS:
        val_grid, pos_grid = make_grid(combined, rows, cols, fill)

        # Test ALL horizontal folds, with special attention to:
        # - Row 24 (ABSCISSA boundary: K3 is 336 chars = 24 rows × 14 cols)
        # - Row 12 (midpoint of K3)
        # - Row 17 (K3 rows 17-23 fold onto K4 rows 24-30)
        for h in range(1, rows):
            pairs = get_fold_pairs(rows, cols, 'h', h)
            models = derive_keys_at_cribs(pairs, pos_grid, val_grid, combined_crib_pos)
            for model_name, derived in models.items():
                if not derived:
                    continue
                for variant in ('beaufort', 'vigenere', 'varbeau'):
                    sc = score_model(derived, combined_known[variant])
                    if sc >= 6:
                        results.append({
                            'grid': 'B', 'label': '14x31_k3k4', 'fill': fill,
                            'fold': f'h{h}', 'model': model_name,
                            'variant': variant, 'score': sc,
                            'n_pairs': len(derived),
                            'abscissa_fold': (h == 24),
                        })

            null_ov, crib_conf, n_match = score_null_mask(
                pairs, pos_grid, val_grid,
                {p + k4_offset for p in CONSENSUS_NULLS},
                combined_crib_pos
            )
            if null_ov >= 5 and crib_conf == 0:
                results.append({
                    'grid': 'B', 'label': '14x31_k3k4', 'fill': fill,
                    'fold': f'h{h}', 'model': 'null_mask',
                    'variant': 'match_indicator', 'score': null_ov,
                    'crib_conflict': crib_conf, 'total_matches': n_match,
                })

            count += 1

        # Also vertical folds
        for v in range(1, cols):
            pairs = get_fold_pairs(rows, cols, 'v', v)
            models = derive_keys_at_cribs(pairs, pos_grid, val_grid, combined_crib_pos)
            for model_name, derived in models.items():
                if not derived:
                    continue
                for variant in ('beaufort', 'vigenere', 'varbeau'):
                    sc = score_model(derived, combined_known[variant])
                    if sc >= 6:
                        results.append({
                            'grid': 'B', 'label': '14x31_k3k4', 'fill': fill,
                            'fold': f'v{v}', 'model': model_name,
                            'variant': variant, 'score': sc,
                            'n_pairs': len(derived),
                        })
            count += 1

    print(f"  Tested {count} fold configurations × 12 scoring models")
    print(f"  Results above threshold: {sum(1 for r in results if r['grid'] == 'B')}")


# ── Grid C: K4 overlay on KA Vigenère Tableau ─────────────────────────

def run_grid_c(results):
    """Place K4 grid on the KA Vigenère tableau at various offsets."""
    print("\n=== GRID C: K4 on KA Vigenère Tableau (26×26) ===")

    # Build the KA tableau: tableau[r][c] = KA-index (r+c)%26
    # Convert to standard A=0 values
    ka_str = str(KA)
    ka_to_std = {i: ord(ka_str[i]) - ord('A') for i in range(26)}
    tableau = [[None] * 26 for _ in range(26)]
    for r in range(26):
        for c in range(26):
            ka_idx = (r + c) % 26
            tableau[r][c] = ka_to_std[ka_idx]

    # Also build AZ tableau
    tableau_az = [[(r + c) % 26 for c in range(26)] for r in range(26)]

    k4_text = [26] + CT_NUMS  # ?+K4 = 98
    k4_rows, k4_cols = 7, 14
    shifted_known = {}
    for variant in ('beaufort', 'vigenere', 'varbeau'):
        shifted_known[variant] = {p + 1: v for p, v in KNOWN_KEY[variant].items()}
    shifted_cribs = set(p + 1 for p in CRIBS.keys())

    count = 0
    for tab_name, tab in [('KA', tableau), ('AZ', tableau_az)]:
        for fill in FILL_ORDERS:
            val_grid, pos_grid = make_grid(k4_text, k4_rows, k4_cols, fill)

            # Try all offsets where K4 grid fits on 26×26 tableau
            for dr in range(26 - k4_rows + 1):
                for dc in range(26 - k4_cols + 1):
                    # For each K4 cell (r,c), get tableau value at (r+dr, c+dc)
                    derived = {'direct': {}, 'add': {}, 'sub_fwd': {}, 'sub_rev': {}}
                    for r in range(k4_rows):
                        for c in range(k4_cols):
                            txt_pos = pos_grid[r][c]
                            if txt_pos is None or txt_pos not in shifted_cribs:
                                continue
                            v1 = val_grid[r][c]
                            v2 = tab[r + dr][c + dc]
                            if v1 is None or v1 == 26:
                                continue
                            derived['direct'][txt_pos] = v2
                            derived['add'][txt_pos] = (v1 + v2) % 26
                            derived['sub_fwd'][txt_pos] = (v1 - v2) % 26
                            derived['sub_rev'][txt_pos] = (v2 - v1) % 26

                    for model_name, d in derived.items():
                        if not d:
                            continue
                        for variant in ('beaufort', 'vigenere', 'varbeau'):
                            sc = score_model(d, shifted_known[variant])
                            if sc >= 6:
                                results.append({
                                    'grid': 'C', 'label': f'tableau_{tab_name}',
                                    'fill': fill, 'fold': f'offset({dr},{dc})',
                                    'model': model_name, 'variant': variant,
                                    'score': sc, 'n_pairs': len(d),
                                })
                    count += 1

    print(f"  Tested {count} overlay configurations × 12 scoring models")
    print(f"  Results above threshold: {sum(1 for r in results if r['grid'] == 'C')}")


# ── Grid D: Full panel 28×31 ──────────────────────────────────────────

def run_grid_d(results):
    """Fold across sections on the full 28×31 master grid."""
    print("\n=== GRID D: Full Panel 28×31 (K1+K2+K3+K4) ===")
    k1_nums = [ord(c) - ord('A') for c in K1_CT]
    k2_nums = [ord(c) - ord('A') for c in K2_CT]
    k3_nums = [ord(c) - ord('A') for c in K3_CT]

    # Full panel: K1(63) + K2(352) + K3(336) + ?(1) + K4(97) = 849
    # 28×31 = 868 cells, pad with sentinels
    panel = k1_nums + k2_nums + k3_nums + [26] + CT_NUMS
    panel_len = len(panel)
    while len(panel) < 28 * 31:
        panel.append(26)  # sentinel padding

    rows, cols = 28, 31
    k4_start = len(k1_nums) + len(k2_nums) + len(k3_nums) + 1  # 752
    panel_crib_pos = {p + k4_start for p in CRIBS.keys()}
    panel_known = {}
    for variant in ('beaufort', 'vigenere', 'varbeau'):
        panel_known[variant] = {p + k4_start: v for p, v in KNOWN_KEY[variant].items()}

    count = 0
    # Test fewer fills for the large grid (lr_tb, boustrophedon, col_major)
    for fill in ['lr_tb', 'boustrophedon', 'col_major']:
        val_grid, pos_grid = make_grid(panel, rows, cols, fill)

        # Horizontal folds — focus on section boundaries
        # K1+K2 is ~415 chars. In lr_tb fill: row 13 ≈ 403, row 14 ≈ 434
        # K3 starts around row 13-14 depending on fill
        for h in range(1, rows):
            pairs = get_fold_pairs(rows, cols, 'h', h)
            models = derive_keys_at_cribs(pairs, pos_grid, val_grid, panel_crib_pos)
            for model_name, derived in models.items():
                if not derived:
                    continue
                for variant in ('beaufort', 'vigenere', 'varbeau'):
                    sc = score_model(derived, panel_known[variant])
                    if sc >= 6:
                        results.append({
                            'grid': 'D', 'label': '28x31_panel', 'fill': fill,
                            'fold': f'h{h}', 'model': model_name,
                            'variant': variant, 'score': sc,
                            'n_pairs': len(derived),
                        })
            count += 1

        # Vertical folds at key positions: col 7 (half of 14), col 14 (K3 width), col 15
        for v in range(1, cols):
            pairs = get_fold_pairs(rows, cols, 'v', v)
            models = derive_keys_at_cribs(pairs, pos_grid, val_grid, panel_crib_pos)
            for model_name, derived in models.items():
                if not derived:
                    continue
                for variant in ('beaufort', 'vigenere', 'varbeau'):
                    sc = score_model(derived, panel_known[variant])
                    if sc >= 6:
                        results.append({
                            'grid': 'D', 'label': '28x31_panel', 'fill': fill,
                            'fold': f'v{v}', 'model': model_name,
                            'variant': variant, 'score': sc,
                            'n_pairs': len(derived),
                        })
            count += 1

    print(f"  Tested {count} fold configurations × 12 scoring models")
    print(f"  Results above threshold: {sum(1 for r in results if r['grid'] == 'D')}")


# ── Grid E: K4 on K3 chart (14×24) ────────────────────────────────────

def run_grid_e(results):
    """Overlay K4 (14×7) on K3 chart (14×24) at various row offsets."""
    print("\n=== GRID E: K4 overlay on K3 chart (14×24) ===")
    k3_nums = [ord(c) - ord('A') for c in K3_CT]

    # K3 chart is 14×24, filled by columns bottom-to-top
    # K3_CT[i] lives at column i//24, row (23 - i%24) in the chart
    k3_chart = [[None] * 14 for _ in range(24)]
    for i, v in enumerate(k3_nums):
        col = i // 24
        row = 23 - (i % 24)
        if col < 14 and row < 24:
            k3_chart[row][col] = v

    k4_text = [26] + CT_NUMS  # ?+K4 = 98
    k4_rows, k4_cols = 7, 14
    shifted_known = {}
    for variant in ('beaufort', 'vigenere', 'varbeau'):
        shifted_known[variant] = {p + 1: v for p, v in KNOWN_KEY[variant].items()}
    shifted_cribs = set(p + 1 for p in CRIBS.keys())

    count = 0
    for fill in FILL_ORDERS:
        val_grid, pos_grid = make_grid(k4_text, k4_rows, k4_cols, fill)

        # Overlay K4 at row offset dr on K3 chart (same 14 columns)
        for dr in range(24 - k4_rows + 1):
            derived = {'direct': {}, 'add': {}, 'sub_fwd': {}, 'sub_rev': {}}
            for r in range(k4_rows):
                for c in range(k4_cols):
                    txt_pos = pos_grid[r][c]
                    if txt_pos is None or txt_pos not in shifted_cribs:
                        continue
                    v1 = val_grid[r][c]
                    v2 = k3_chart[r + dr][c]
                    if v1 is None or v1 == 26 or v2 is None:
                        continue
                    derived['direct'][txt_pos] = v2
                    derived['add'][txt_pos] = (v1 + v2) % 26
                    derived['sub_fwd'][txt_pos] = (v1 - v2) % 26
                    derived['sub_rev'][txt_pos] = (v2 - v1) % 26

            for model_name, d in derived.items():
                if not d:
                    continue
                for variant in ('beaufort', 'vigenere', 'varbeau'):
                    sc = score_model(d, shifted_known[variant])
                    if sc >= 6:
                        results.append({
                            'grid': 'E', 'label': 'k4_on_k3chart',
                            'fill': fill, 'fold': f'row_offset_{dr}',
                            'model': model_name, 'variant': variant,
                            'score': sc, 'n_pairs': len(d),
                        })
            count += 1

    print(f"  Tested {count} overlay configurations × 12 scoring models")
    print(f"  Results above threshold: {sum(1 for r in results if r['grid'] == 'E')}")


# ── Additional grid sizes (user request: "all permutations") ──────────

def run_additional_grids(results):
    """Test K4 self-fold on additional grid dimensions beyond 14×7."""
    print("\n=== ADDITIONAL GRIDS: K4 in various dimensions ===")
    # Grid sizes where K4 (97 chars) fits with minimal padding
    # 97 is prime, so no exact fit. Try near-rectangular sizes.
    grid_sizes = [
        (4, 25, 100),   # 4×25=100, 3 padding
        (5, 20, 100),   # 5×20=100, 3 padding
        (7, 14, 98),    # 7×14=98, 1 padding (the ? prefix)
        (8, 13, 104),   # 8×13=104, 7 padding
        (10, 10, 100),  # 10×10=100, 3 padding
        (11, 9, 99),    # 11×9=99, 2 padding
        (14, 7, 98),    # 14×7=98 (transposed of 7×14)
        (31, 4, 124),   # 31×4, panel-width rows
        (97, 1, 97),    # single column (trivial, skip)
    ]

    crib_known = {}
    for variant in ('beaufort', 'vigenere', 'varbeau'):
        crib_known[variant] = KNOWN_KEY[variant].copy()
    crib_positions = set(CRIBS.keys())

    count = 0
    for grid_rows, grid_cols, total in grid_sizes:
        if grid_rows <= 1 or grid_cols <= 1:
            continue
        # Pad K4 with sentinels
        text = CT_NUMS + [26] * (total - len(CT_NUMS))
        for fill in FILL_ORDERS:
            val_grid, pos_grid = make_grid(text, grid_rows, grid_cols, fill)

            for h in range(1, grid_rows):
                pairs = get_fold_pairs(grid_rows, grid_cols, 'h', h)
                models = derive_keys_at_cribs(pairs, pos_grid, val_grid, crib_positions)
                for model_name, derived in models.items():
                    if not derived:
                        continue
                    for variant in ('beaufort', 'vigenere', 'varbeau'):
                        sc = score_model(derived, crib_known[variant])
                        if sc >= 6:
                            results.append({
                                'grid': 'extra', 'label': f'{grid_cols}x{grid_rows}',
                                'fill': fill, 'fold': f'h{h}', 'model': model_name,
                                'variant': variant, 'score': sc,
                                'n_pairs': len(derived),
                            })
                count += 1

            for v in range(1, grid_cols):
                pairs = get_fold_pairs(grid_rows, grid_cols, 'v', v)
                models = derive_keys_at_cribs(pairs, pos_grid, val_grid, crib_positions)
                for model_name, derived in models.items():
                    if not derived:
                        continue
                    for variant in ('beaufort', 'vigenere', 'varbeau'):
                        sc = score_model(derived, crib_known[variant])
                        if sc >= 6:
                            results.append({
                                'grid': 'extra', 'label': f'{grid_cols}x{grid_rows}',
                                'fill': fill, 'fold': f'v{v}', 'model': model_name,
                                'variant': variant, 'score': sc,
                                'n_pairs': len(derived),
                            })
                count += 1

    print(f"  Tested {count} fold configurations × 12 scoring models")
    print(f"  Results above threshold: {sum(1 for r in results if r['grid'] == 'extra')}")


# ── Main ───────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("E-PAPER-FOLD-01: Physical Paper Operations on K4 Grids")
    print("=" * 70)
    print(f"CT: {K4_CT}")
    print(f"CT length: {len(K4_CT)}")
    print(f"K3 CT length: {len(K3_CT)}")
    print(f"K2 CT length: {len(K2_CT)}")
    print(f"K1 CT length: {len(K1_CT)}")
    print(f"K3+?+K4 = {len(K3_CT)+1+len(K4_CT)} (should be 434 = 14×31)")
    print(f"Fill orders: {FILL_ORDERS}")
    print(f"Score threshold: >= 6/24 for reporting")
    print(f"\nKey derivation models: direct, add, sub_fwd, sub_rev")
    print(f"Cipher variants: beaufort, vigenere, varbeau")
    print()

    t0 = time.time()
    results = []

    run_grid_a(results)
    run_grid_b(results)
    run_grid_c(results)
    run_grid_d(results)
    run_grid_e(results)
    run_additional_grids(results)

    elapsed = time.time() - t0

    # ── Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"COMPLETE — {elapsed:.1f}s elapsed")
    print(f"Total results above threshold: {len(results)}")

    if results:
        # Sort by score descending
        results.sort(key=lambda r: r['score'], reverse=True)
        print(f"\nBest score: {results[0]['score']}/24")
        print(f"\nTop 20 results:")
        print(f"{'Grid':>5} {'Label':>18} {'Fill':>18} {'Fold':>12} {'Model':>10} {'Var':>10} {'Score':>6} {'Pairs':>6}")
        print("-" * 90)
        for r in results[:20]:
            print(f"{r['grid']:>5} {r['label']:>18} {r['fill']:>18} {r['fold']:>12} "
                  f"{r['model']:>10} {r['variant']:>10} {r['score']:>6} {r.get('n_pairs','?'):>6}")

        # Breakdown by grid
        print("\nResults by grid:")
        grid_counts = defaultdict(list)
        for r in results:
            grid_counts[r['grid']].append(r['score'])
        for g in sorted(grid_counts.keys()):
            scores = grid_counts[g]
            print(f"  Grid {g}: {len(scores)} results, best {max(scores)}/24")
    else:
        print("\nNo results above threshold (6/24). All fold operations produce noise.")

    # Save results
    output = {
        'experiment': 'E-PAPER-FOLD-01',
        'hypothesis': 'K4 keystream derived from physical paper fold/overlay operations',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed_seconds': elapsed,
        'total_configs': 'see per-grid counts above',
        'score_threshold': 6,
        'total_results': len(results),
        'best_score': results[0]['score'] if results else 0,
        'results': results[:100],  # top 100
    }

    os.makedirs(os.path.join(_ROOT, 'results'), exist_ok=True)
    out_path = os.path.join(_ROOT, 'results', 'e_paper_fold_01.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
