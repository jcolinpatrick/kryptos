#!/usr/bin/env python3
"""Row gradient validation: Monte Carlo test of keystream value distribution.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   analytical (Monte Carlo 1M trials)
Last run:   2026-03-21
Best score: N/A (statistical analysis)

Tests whether the observed row gradient in present keystream values
(60%/60%/60%/40%/20%/0% across KA Polybius rows) is statistically
significant, and whether it's explained by AP enrichment alone.
Also tests whether the palette split (rows 0-2 present vs rows 3-5 absent)
is independent of the AP enrichment.
"""
import sys, os, random, json
from collections import Counter
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

KA = KRYPTOS_ALPHABET
KA_IDX = {ch: i for i, ch in enumerate(KA)}

def az(ch): return ALPH_IDX[ch]
def az_chr(v): return ALPH[v % 26]
def ka_row(ch): return KA_IDX[ch] // 5
def ka_col(ch): return KA_IDX[ch] % 5

def beaufort_key(ct_ch, pt_ch):
    return (az(ct_ch) + az(pt_ch)) % 26

# ── Known keystream ─────────────────────────────────────────────────────
ENE_KS = [beaufort_key(c, p) for c, p in zip(CT[21:34], "EASTNORTHEAST")]
BCL_KS = [beaufort_key(c, p) for c, p in zip(CT[63:74], "BERLINCLOCK")]
FULL_KS = ENE_KS + BCL_KS
KS_LETTERS = [az_chr(v) for v in FULL_KS]
PRESENT_SET = set(FULL_KS)  # 12 distinct AZ values

# ── Observed row distribution ───────────────────────────────────────────

# KA grid layout (5-wide):
# Row 0: K R Y P T    Row 3: I J L M N
# Row 1: O S A B C    Row 4: Q U V W X
# Row 2: D E F G H    Row 5: Z
GRID_ROWS = [
    ['K', 'R', 'Y', 'P', 'T'],
    ['O', 'S', 'A', 'B', 'C'],
    ['D', 'E', 'F', 'G', 'H'],
    ['I', 'J', 'L', 'M', 'N'],
    ['Q', 'U', 'V', 'W', 'X'],
    ['Z'],
]
ROW_SIZES = [len(r) for r in GRID_ROWS]

# Observed: which letters are in the 12-value present set?
present_letters = set(az_chr(v) for v in PRESENT_SET)
absent_letters = set(ALPH) - present_letters

print("=" * 78)
print("KA POLYBIUS ROW GRADIENT ANALYSIS")
print("=" * 78)

print(f"\nPresent (12): {sorted(present_letters)}")
print(f"Absent  (14): {sorted(absent_letters)}")

obs_row_counts = []
obs_row_rates = []
for i, row in enumerate(GRID_ROWS):
    present_in_row = sum(1 for ch in row if ch in present_letters)
    obs_row_counts.append(present_in_row)
    rate = present_in_row / len(row)
    obs_row_rates.append(rate)
    markers = ''.join('*' if ch in present_letters else '.' for ch in row)
    print(f"  Row {i} ({','.join(row)}): {present_in_row}/{len(row)} = {rate:.0%}  [{markers}]")

# Gradient metric: sum of (row_index × present_count) — lower = more top-heavy
obs_gradient = sum(i * c for i, c in enumerate(obs_row_counts))
print(f"\nGradient metric (Σ row_idx × count): {obs_gradient}")
print("  (Lower = more top-heavy; random 12-of-26 expected ≈ 24.0)")

# ── Palette split analysis ──────────────────────────────────────────────
# Null palette = {B,G,I,K,O,W,Z}
PALETTE = set('BGIKOWZ')
pal_present = PALETTE & present_letters  # {B,G,K,O}
pal_absent = PALETTE & absent_letters    # {I,W,Z}

print(f"\n── Palette Split ──")
print(f"Palette in keystream:  {sorted(pal_present)} (rows {sorted(set(ka_row(c) for c in pal_present))})")
print(f"Palette NOT in keystream: {sorted(pal_absent)} (rows {sorted(set(ka_row(c) for c in pal_absent))})")
print(f"Split: rows 0-2 → present, rows 3-5 → absent")

# Row boundary: all palette members in rows 0-2 are present, all in rows 3+ absent
pal_boundary_clean = all(ka_row(c) <= 2 for c in pal_present) and all(ka_row(c) >= 3 for c in pal_absent)
print(f"Clean row boundary at row 2/3: {pal_boundary_clean}")

# ── Monte Carlo: random 12-of-26 selections ────────────────────────────
N_TRIALS = 1_000_000
random.seed(20260321)

gradient_leq = 0  # count where gradient ≤ observed (more top-heavy)
monotonic_count = 0  # count where rate decreases row by row
palette_boundary_count = 0  # count where palette splits cleanly at row boundary
top_heavy_3 = 0  # count where rows 0-2 have ≥ 9 out of 15

all_letters = list(range(26))  # KA indices

for _ in range(N_TRIALS):
    chosen = set(random.sample(all_letters, 12))

    # Row counts for this random selection
    row_counts = []
    cumulative = 0
    for i, row_size in enumerate(ROW_SIZES):
        start = sum(ROW_SIZES[:i])
        count = sum(1 for j in range(start, start + row_size) if j in chosen)
        row_counts.append(count)
        cumulative += count

    # Gradient
    grad = sum(i * c for i, c in enumerate(row_counts))
    if grad <= obs_gradient:
        gradient_leq += 1

    # Top-heavy: rows 0-2 have ≥ 9
    top3 = sum(row_counts[:3])
    if top3 >= 9:
        top_heavy_3 += 1

    # Monotonic decrease (allowing ties)
    rates = [row_counts[i] / ROW_SIZES[i] for i in range(len(ROW_SIZES))]
    is_monotonic = all(rates[i] >= rates[i + 1] for i in range(len(rates) - 1))
    if is_monotonic:
        monotonic_count += 1

    # Palette boundary: check if {B,G,K,O} positions are in chosen and {I,W,Z} not
    # B=8 (row1), G=13 (row2), K=0 (row0), O=5 (row1) in KA
    # I=15 (row3), W=23 (row4), Z=25 (row5) in KA
    pal_present_ka = {KA_IDX[c] for c in 'BGKO'}
    pal_absent_ka = {KA_IDX[c] for c in 'IWZ'}
    if pal_present_ka.issubset(chosen) and pal_absent_ka.isdisjoint(chosen):
        palette_boundary_count += 1

print(f"\n{'='*78}")
print(f"MONTE CARLO RESULTS ({N_TRIALS:,} trials)")
print(f"{'='*78}")

p_gradient = gradient_leq / N_TRIALS
p_monotonic = monotonic_count / N_TRIALS
p_top_heavy = top_heavy_3 / N_TRIALS
p_palette = palette_boundary_count / N_TRIALS

print(f"\n  Gradient ≤ {obs_gradient}:    {gradient_leq:>7,}/{N_TRIALS:,} = p={p_gradient:.6f}")
print(f"  Monotonic decrease:    {monotonic_count:>7,}/{N_TRIALS:,} = p={p_monotonic:.6f}")
print(f"  Top 3 rows ≥ 9/15:    {top_heavy_3:>7,}/{N_TRIALS:,} = p={p_top_heavy:.6f}")
print(f"  Palette clean boundary:{palette_boundary_count:>7,}/{N_TRIALS:,} = p={p_palette:.6f}")

# ── AP independence test ────────────────────────────────────────────────
# Test: conditioning on AP = {G,K,O} being present, does the gradient still hold?
print(f"\n{'='*78}")
print("AP INDEPENDENCE TEST")
print(f"{'='*78}")

# AP letters in KA: G=13, K=0, O=5
AP_KA = {KA_IDX['G'], KA_IDX['K'], KA_IDX['O']}

ap_conditioned = 0
ap_and_gradient = 0
ap_and_palette = 0

for _ in range(N_TRIALS):
    chosen = set(random.sample(all_letters, 12))
    if not AP_KA.issubset(chosen):
        continue
    ap_conditioned += 1

    row_counts = []
    for i, row_size in enumerate(ROW_SIZES):
        start = sum(ROW_SIZES[:i])
        count = sum(1 for j in range(start, start + row_size) if j in chosen)
        row_counts.append(count)

    grad = sum(i * c for i, c in enumerate(row_counts))
    if grad <= obs_gradient:
        ap_and_gradient += 1

    # Palette boundary
    pal_present_ka = {KA_IDX[c] for c in 'BGKO'}
    pal_absent_ka = {KA_IDX[c] for c in 'IWZ'}
    if pal_present_ka.issubset(chosen) and pal_absent_ka.isdisjoint(chosen):
        ap_and_palette += 1

p_grad_given_ap = ap_and_gradient / ap_conditioned if ap_conditioned > 0 else 0
p_pal_given_ap = ap_and_palette / ap_conditioned if ap_conditioned > 0 else 0

print(f"\n  Trials with AP⊂chosen: {ap_conditioned:,}/{N_TRIALS:,}")
print(f"  Gradient ≤ {obs_gradient} | AP: {ap_and_gradient:,}/{ap_conditioned:,} = p={p_grad_given_ap:.6f}")
print(f"  Palette boundary | AP: {ap_and_palette:,}/{ap_conditioned:,} = p={p_pal_given_ap:.6f}")
print(f"\n  Unconditional gradient p = {p_gradient:.6f}")
print(f"  AP-conditioned gradient p = {p_grad_given_ap:.6f}")
print(f"  Ratio: {p_grad_given_ap/p_gradient:.2f}x {'(AP explains gradient)' if p_grad_given_ap > 2*p_gradient else '(gradient partially independent of AP)' if p_grad_given_ap < 1.5*p_gradient else '(moderate AP contribution)'}")

# ── Staircase analysis ──────────────────────────────────────────────────
print(f"\n{'='*78}")
print("STAIRCASE PATTERN ANALYSIS")
print(f"{'='*78}")

# The rightmost column position of a present letter in each row
print("\nRightmost present column per row:")
for i, row in enumerate(GRID_ROWS):
    present_cols = [j for j, ch in enumerate(row) if ch in present_letters]
    if present_cols:
        rightmost = max(present_cols)
        print(f"  Row {i}: col {rightmost} ({row[rightmost]})")
    else:
        print(f"  Row {i}: NONE")

# Column distribution of present values
print("\nColumn distribution of present values:")
col_counts = Counter(ka_col(ch) for ch in present_letters)
for col in range(5):
    count = col_counts.get(col, 0)
    members = [ch for ch in present_letters if ka_col(ch) == col]
    print(f"  Col {col}: {count} present — {sorted(members)}")

# ── Two-source decomposition check ─────────────────────────────────────
print(f"\n{'='*78}")
print("KEY VALUE FREQUENCY IN ACTUAL KEYSTREAM")
print(f"{'='*78}")

ks_counts = Counter(FULL_KS)
for val, cnt in sorted(ks_counts.items(), key=lambda x: -x[1]):
    ch = az_chr(val)
    row, col = ka_row(ch), ka_col(ch)
    in_ap = "AP" if val in {6, 10, 14} else "  "
    in_pal = "PAL" if ch in PALETTE else "   "
    print(f"  {ch} (AZ={val:2d}, KA row={row} col={col}): {cnt}× {in_ap} {in_pal}")

# ── Save results ────────────────────────────────────────────────────────
outfile = os.path.join(_ROOT, "results", "e_row_gradient_analysis.json")
os.makedirs(os.path.dirname(outfile), exist_ok=True)

output = {
    "experiment": "e_row_gradient_analysis",
    "timestamp": datetime.now().isoformat(),
    "description": "Row gradient validation for keystream present/absent values on KA Polybius grid",
    "observed": {
        "present_12": sorted(present_letters),
        "absent_14": sorted(absent_letters),
        "row_counts": obs_row_counts,
        "row_rates": obs_row_rates,
        "gradient_metric": obs_gradient,
        "palette_boundary_clean": pal_boundary_clean,
    },
    "monte_carlo": {
        "trials": N_TRIALS,
        "p_gradient": p_gradient,
        "p_monotonic": p_monotonic,
        "p_top_heavy": p_top_heavy,
        "p_palette_boundary": p_palette,
        "p_gradient_given_ap": p_grad_given_ap,
        "p_palette_given_ap": p_pal_given_ap,
    },
}

with open(outfile, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to {outfile}")
