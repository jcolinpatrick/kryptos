#!/usr/bin/env python3
"""
Cipher: Crib position reversal — cribs in INTERMEDIATE text, not CT
Family: campaigns
Status: active
Keyspace: exhaustive w5-11, keyword w12-16

OPEN HYPOTHESIS (memory 2026-03-13): "Crib position reversal — Proofs ASSUME
cribs at carved-text positions (21-33, 63-73). If cribs apply to intermediate text
(after transposition undo), proof structure changes. OPEN. Major escape hatch."

Standard MITM (244M configs) assumed:
  PT → trans → CT, cribs at carved CT positions 21-33, 63-73

THIS TEST:
  CT → undo_outer_trans → INTERMEDIATE (cribs at positions 21-33, 63-73)
  INTERMEDIATE → periodic_sub → PT   (any key, not constrained by cribs)

Approach: enumerate outer transpositions; check if undo(CT) has cribs at 21-33, 63-73.
Width 5-11: exhaustive. Width 12-16: keyword alphabet KRYPTOSABCDEFGHIJLMNQUVWXZ variants.

If any configuration gives cribs in intermediate, REPORT IMMEDIATELY.
"""
import sys, time
from itertools import permutations
from math import ceil
sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, N_CRIBS, ALPH, ALPH_IDX,
    KRYPTOS_ALPHABET
)

def undo_columnar(ct: str, order: tuple) -> str:
    """Undo columnar transposition: CT was produced by reading columns in `order`."""
    ncols = len(order)
    nrows = ceil(len(ct) / ncols)
    short_cols = nrows * ncols - len(ct)

    col_len = {}
    for rank, col in enumerate(order):
        col_len[col] = nrows - 1 if rank >= ncols - short_cols else nrows

    grid = {}
    pos = 0
    for rank in range(ncols):
        col = order[rank]
        grid[col] = list(ct[pos: pos + col_len[col]])
        pos += col_len[col]

    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(grid.get(col, [])):
                result.append(grid[col][row])
    return "".join(result)

def crib_score_in_intermediate(intermediate: str) -> int:
    """Count how many crib positions 21-33 and 63-73 match in the intermediate."""
    return sum(1 for pos, ch in CRIB_DICT.items()
               if pos < len(intermediate) and intermediate[pos] == ch)

def keyword_to_order(keyword: str, width: int) -> tuple:
    """Convert keyword to columnar order (standard rank method)."""
    kw = keyword[:width].upper()
    indexed = sorted(range(len(kw)), key=lambda i: (kw[i], i))
    order = [0] * len(kw)
    for rank, orig in enumerate(indexed):
        order[orig] = rank
    return tuple(order)

# ── Keywords to try for large widths ────────────────────────────────────────
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN", "SCHEIDT",
    "BERLIN", "CLOCK", "EAST", "NORTH", "LIGHT", "ANTIPODES",
    "KOMPASS", "COLOPHON", "DEFECTOR", "KRYPTA", "KLEPSYDRA",
    "DEGREES", "SECONDS", "MINUTES", "NORTHWEST", "VERDIGRIS",
    "PARALLAX", "MEDUSA", "ENIGMA",
    # K2 number words
    "THIRTYEIGHT", "FIFTYSEVEN", "FORTYFOUR", "SEVENTYSEVEN",
]

print("=" * 70)
print("CRIB POSITION REVERSAL ATTACK")
print("Model: CT → undo_outer_trans → intermediate (cribs at 21-33, 63-73)")
print("=" * 70)
print(f"CT: {CT}")
print(f"Cribs: EASTNORTHEAST@21, BERLINCLOCK@63 (24 positions)")
print()

hits = []  # Configurations where intermediate has cribs
best_score = 0
total_tested = 0
t_start = time.time()

# ── Phase 1: Exhaustive small widths ────────────────────────────────────────
for width in range(5, 12):
    count, phase_best = 0, 0
    t_w = time.time()

    for perm in permutations(range(width)):
        intermediate = undo_columnar(CT, perm)
        sc = crib_score_in_intermediate(intermediate)

        if sc > phase_best:
            phase_best = sc
        if sc > best_score:
            best_score = sc

        if sc >= 12:  # Significant partial match
            hits.append((sc, f"w{width} perm={perm}", intermediate))
            if sc >= 20:
                print(f"\n*** STRONG HIT: w={width}, score={sc}/24 ***")
                print(f"  Perm: {perm}")
                print(f"  Intermediate: {intermediate}")

        count += 1
        total_tested += 1

    elapsed = time.time() - t_w
    print(f"w={width}: {count:>8,} perms in {elapsed:.1f}s  phase_best={phase_best}/24")
    sys.stdout.flush()

# ── Phase 2: Keyword-based large widths ─────────────────────────────────────
print()
for width in range(12, 20):
    count, phase_best = 0, 0
    for kw in KEYWORDS:
        if len(kw) < width:
            continue
        order = keyword_to_order(kw, width)
        intermediate = undo_columnar(CT, order)
        sc = crib_score_in_intermediate(intermediate)

        if sc > phase_best:
            phase_best = sc
        if sc > best_score:
            best_score = sc
        if sc >= 10:
            hits.append((sc, f"w{width} kw={kw[:width]}", intermediate))

        count += 1
        total_tested += 1

    # Also try KA alphabet rotations
    ka = KRYPTOS_ALPHABET
    for start in range(len(ka)):
        rotated = ka[start:] + ka[:start]
        order = keyword_to_order(rotated, width)
        intermediate = undo_columnar(CT, order)
        sc = crib_score_in_intermediate(intermediate)
        if sc > phase_best:
            phase_best = sc
        if sc >= 10:
            hits.append((sc, f"w{width} KA_rot{start}", intermediate))
        count += 1
        total_tested += 1

    print(f"w={width}: {count:>6,} keyword configs  phase_best={phase_best}/24")
    sys.stdout.flush()

# ── Phase 3: Double columnar — undo two transpositions, check cribs ──────────
print()
print("--- Phase 3: Double columnar (w5×w5 through w7×w7) exhaustive ---")
for w1 in range(5, 8):
    for w2 in range(5, 8):
        count, phase_best = 0, 0
        t_dc = time.time()
        for p1 in permutations(range(w1)):
            # Undo outer (w2) first, then inner (w1)
            for p2 in permutations(range(w2)):
                # Model: intermediate = undo_w1( undo_w2(CT) )
                stage1 = undo_columnar(CT, p2)
                stage2 = undo_columnar(stage1, p1)
                sc = crib_score_in_intermediate(stage2)

                if sc > phase_best:
                    phase_best = sc
                if sc >= 14:
                    hits.append((sc, f"double_w{w1}×{w2} p1={p1} p2={p2}", stage2))
                count += 1
                total_tested += 1

        elapsed = time.time() - t_dc
        print(f"  double w{w1}×{w2}: {count:>10,} in {elapsed:.1f}s  best={phase_best}/24")
        sys.stdout.flush()

# ── Summary ──────────────────────────────────────────────────────────────────
elapsed = time.time() - t_start
print(f"\n{'=' * 70}")
print(f"TOTAL: {total_tested:,} configs in {elapsed:.1f}s")
print(f"Best score: {best_score}/24")
print(f"Hits (score ≥ 10): {len(hits)}")
print(f"{'=' * 70}")

hits.sort(key=lambda x: -x[0])
if hits:
    print(f"\nTOP {min(30, len(hits))} HITS:")
    for sc, label, intermediate in hits[:30]:
        matches = [(pos, CRIB_DICT[pos]) for pos in sorted(CRIB_POSITIONS)
                   if pos < len(intermediate) and intermediate[pos] == CRIB_DICT[pos]]
        print(f"  {sc:2d}/24: {label}")
        print(f"    INTERMED: {intermediate[:60]}...")
        print(f"    Matches: {matches[:8]}")
        print()
else:
    print("\nNo configurations with score ≥ 10 found.")
    print("CONCLUSION: Cribs are NOT at intermediate positions for standard columnar undo.")
    print("         (This rules out simple 'crib reversal' for this transposition family.)")

print("\nDONE")
