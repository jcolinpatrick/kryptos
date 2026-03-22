#!/usr/bin/env python3
"""Row Sequence Analysis: test the Polybius row sequence for structure.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   analytical
Last run:   2026-03-21
Best score: N/A

The 24 known keystream values map to KA Polybius rows:
  [3,3,3,1,2,2,2,0,4,0,0,0,3,1,1,2,2,1,2,1,0,0,0,4]
This is a 6-symbol sequence (symbols 0-5). Test for:
- Period, autocorrelation, mathematical structure
- Known integer sequences (OEIS patterns)
- Substitution cipher on a 6-symbol alphabet
- Run-length patterns
- Connection to physical grid dimensions
"""
import sys, os, json, random, math
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
def beaufort_key(ct_ch, pt_ch): return (az(ct_ch) + az(pt_ch)) % 26

# ── Known keystream ─────────────────────────────────────────────────────
ENE_KS = [beaufort_key(c, p) for c, p in zip(CT[21:34], "EASTNORTHEAST")]
BCL_KS = [beaufort_key(c, p) for c, p in zip(CT[63:74], "BERLINCLOCK")]
FULL_KS = ENE_KS + BCL_KS
KS_LETTERS = [az_chr(v) for v in FULL_KS]

ROW_SEQ = [ka_row(ch) for ch in KS_LETTERS]
COL_SEQ = [ka_col(ch) for ch in KS_LETTERS]

print("=" * 78)
print("ROW SEQUENCE ANALYSIS")
print("=" * 78)

print(f"\nRow sequence: {ROW_SEQ}")
print(f"Col sequence: {COL_SEQ}")
print(f"Length: {len(ROW_SEQ)}")

# ── Basic statistics ────────────────────────────────────────────────────
row_counts = Counter(ROW_SEQ)
col_counts = Counter(COL_SEQ)

print(f"\nRow value counts: {dict(sorted(row_counts.items()))}")
print(f"Col value counts: {dict(sorted(col_counts.items()))}")

# ── Run-length encoding ─────────────────────────────────────────────────
def rle(seq):
    runs = []
    cur_val, cur_len = seq[0], 1
    for i in range(1, len(seq)):
        if seq[i] == cur_val:
            cur_len += 1
        else:
            runs.append((cur_val, cur_len))
            cur_val, cur_len = seq[i], 1
    runs.append((cur_val, cur_len))
    return runs

row_runs = rle(ROW_SEQ)
col_runs = rle(COL_SEQ)

print(f"\nRow runs: {row_runs}")
print(f"Run lengths: {[r[1] for r in row_runs]}")
print(f"Run values:  {[r[0] for r in row_runs]}")
print(f"Number of runs: {len(row_runs)}")

print(f"\nCol runs: {col_runs}")
print(f"Run lengths: {[r[1] for r in col_runs]}")

# ── Run length statistics ───────────────────────────────────────────────
row_run_lens = [r[1] for r in row_runs]
print(f"\nRow run length distribution: {Counter(row_run_lens)}")
print(f"Max run: {max(row_run_lens)} (at row {row_runs[row_run_lens.index(max(row_run_lens))][0]})")

# Monte Carlo: expected number of runs in a random 24-length sequence over {0,1,2,3,4,5}
N_MC = 100000
random.seed(20260321)
mc_runs = []
mc_max_run = []
for _ in range(N_MC):
    seq = [random.randint(0, 5) for _ in range(24)]
    r = rle(seq)
    mc_runs.append(len(r))
    mc_max_run.append(max(rl for _, rl in r))

print(f"\nMonte Carlo (random 6-symbol, len 24, {N_MC:,} trials):")
print(f"  Expected runs: {sum(mc_runs)/len(mc_runs):.1f} ± {(sum((x-sum(mc_runs)/len(mc_runs))**2 for x in mc_runs)/len(mc_runs))**0.5:.1f}")
print(f"  Observed runs: {len(row_runs)}")
print(f"  p(≤{len(row_runs)} runs): {sum(1 for x in mc_runs if x <= len(row_runs))/N_MC:.4f}")
print(f"  Expected max run: {sum(mc_max_run)/len(mc_max_run):.1f}")
print(f"  Observed max run: {max(row_run_lens)}")
print(f"  p(max run ≥ {max(row_run_lens)}): {sum(1 for x in mc_max_run if x >= max(row_run_lens))/N_MC:.4f}")

# ── Period detection ────────────────────────────────────────────────────
print(f"\n{'='*78}")
print("PERIOD DETECTION")
print("=" * 78)

for period in range(2, 13):
    matches = 0
    total = 0
    for i in range(len(ROW_SEQ) - period):
        if ROW_SEQ[i] == ROW_SEQ[i + period]:
            matches += 1
        total += 1
    rate = matches / total if total > 0 else 0
    expected = 1 / 6  # random: 6 symbols
    bar = '#' * int(rate * 40)
    marker = " ← SIG" if rate > 0.35 else ""
    print(f"  Period {period:2d}: {matches:2d}/{total} = {rate:.3f} (exp {expected:.3f}) {bar}{marker}")

# ── Difference sequence ─────────────────────────────────────────────────
print(f"\n{'='*78}")
print("DIFFERENCE SEQUENCES")
print("=" * 78)

diffs = [(ROW_SEQ[i+1] - ROW_SEQ[i]) % 6 for i in range(23)]
print(f"Row diffs (mod 6): {diffs}")
print(f"Row diffs (signed): {[ROW_SEQ[i+1] - ROW_SEQ[i] for i in range(23)]}")

diff_counts = Counter(diffs)
print(f"Diff distribution: {dict(sorted(diff_counts.items()))}")

# Second differences
diffs2 = [(diffs[i+1] - diffs[i]) % 6 for i in range(22)]
print(f"Second diffs (mod 6): {diffs2}")

col_diffs = [(COL_SEQ[i+1] - COL_SEQ[i]) % 5 for i in range(23)]
print(f"Col diffs (mod 5): {col_diffs}")

# ── KA index sequence as numbers ───────────────────────────────────────
print(f"\n{'='*78}")
print("KA INDEX ANALYSIS")
print("=" * 78)

ka_seq = [KA_IDX[ch] for ch in KS_LETTERS]
print(f"KA indices: {ka_seq}")

# Differences mod 26
ka_diffs = [(ka_seq[i+1] - ka_seq[i]) % 26 for i in range(23)]
print(f"KA diffs mod 26: {ka_diffs}")

# Check for arithmetic progression in KA values
for step in range(1, 26):
    pred = [(ka_seq[0] + step * i) % 26 for i in range(24)]
    match = sum(1 for a, b in zip(ka_seq, pred) if a == b)
    if match >= 8:
        print(f"  AP step {step}: {match}/24 matches")

# ── Fibonacci/Lucas-like test ───────────────────────────────────────────
print(f"\n{'='*78}")
print("FIBONACCI-LIKE PATTERNS")
print("=" * 78)

# Test if row[i+2] = (row[i] + row[i+1]) mod M for various M
for mod in range(5, 13):
    matches = 0
    for i in range(len(ROW_SEQ) - 2):
        if (ROW_SEQ[i] + ROW_SEQ[i+1]) % mod == ROW_SEQ[i+2]:
            matches += 1
    total = len(ROW_SEQ) - 2
    rate = matches / total
    expected = 1 / mod
    if rate > 2 * expected:
        print(f"  Fib mod {mod:2d}: {matches}/{total} = {rate:.3f} (exp {expected:.3f}) ← ELEVATED")
    else:
        print(f"  Fib mod {mod:2d}: {matches}/{total} = {rate:.3f} (exp {expected:.3f})")

# ── ENE vs BCL sub-sequences ───────────────────────────────────────────
print(f"\n{'='*78}")
print("ENE vs BCL ROW PATTERN COMPARISON")
print("=" * 78)

ene_rows = ROW_SEQ[:13]
bcl_rows = ROW_SEQ[13:]

print(f"ENE rows (13): {ene_rows}")
print(f"BCL rows (11): {bcl_rows}")

print(f"\nENE row counts: {dict(sorted(Counter(ene_rows).items()))}")
print(f"BCL row counts: {dict(sorted(Counter(bcl_rows).items()))}")

# Check if BCL rows are a permutation/shift of ENE rows
print(f"\nENE run values:  {[r[0] for r in rle(ene_rows)]}")
print(f"BCL run values:  {[r[0] for r in rle(bcl_rows)]}")

# ── Combined (row,col) as direction vectors ─────────────────────────────
print(f"\n{'='*78}")
print("(ROW,COL) AS DIRECTION VECTORS")
print("=" * 78)

print(f"\nPosition  Letter  AZ  KA  Row  Col  (r,c)")
crib_positions = list(range(21, 34)) + list(range(63, 74))
for i in range(24):
    pos = crib_positions[i]
    region = "ENE" if i < 13 else "BCL"
    print(f"  [{region}] {pos:3d}  {KS_LETTERS[i]}  {FULL_KS[i]:3d}  "
          f"{ka_seq[i]:3d}  {ROW_SEQ[i]}    {COL_SEQ[i]}    ({ROW_SEQ[i]},{COL_SEQ[i]})")

# Direction deltas
print(f"\nDirection deltas (Δrow, Δcol):")
for i in range(23):
    dr = ROW_SEQ[i+1] - ROW_SEQ[i]
    dc = COL_SEQ[i+1] - COL_SEQ[i]
    region = "ENE" if i < 12 else ("ENE→BCL" if i == 12 else "BCL")
    print(f"  {i:2d}→{i+1:2d} [{region:7s}] Δ({dr:+d},{dc:+d})")

# ── Grid walk hypothesis ───────────────────────────────────────────────
print(f"\n{'='*78}")
print("GRID WALK ON 5-WIDE KA POLYBIUS")
print("=" * 78)

# Plot the sequence as a path on the 6×5 grid
grid_5x6 = [['·'] * 5 for _ in range(6)]
for i, ch in enumerate(KS_LETTERS):
    r, c = ka_row(ch), ka_col(ch)
    if grid_5x6[r][c] == '·':
        grid_5x6[r][c] = str(i)
    else:
        grid_5x6[r][c] += f",{i}"

print("\nKA grid with sequence positions:")
for r in range(6):
    row_letters = [KA[r*5+c] if r*5+c < 26 else ' ' for c in range(5)]
    positions = [f"{grid_5x6[r][c]:>10s}" for c in range(5)]
    letters = [f"{row_letters[c]:>10s}" for c in range(5)]
    print(f"  Row {r}: {' '.join(letters)}")
    print(f"         {' '.join(positions)}")

# ── Manhattan distance between consecutive keystream values ─────────────
print(f"\nManhattan distances between consecutive positions:")
distances = []
for i in range(23):
    d = abs(ROW_SEQ[i+1] - ROW_SEQ[i]) + abs(COL_SEQ[i+1] - COL_SEQ[i])
    distances.append(d)
print(f"  Distances: {distances}")
print(f"  Mean: {sum(distances)/len(distances):.2f}")
print(f"  Distribution: {dict(sorted(Counter(distances).items()))}")

# Monte Carlo: expected mean Manhattan distance for random sequence
mc_dists = []
for _ in range(N_MC):
    seq = [random.randint(0, 25) for _ in range(24)]
    rows = [s // 5 for s in seq]
    cols = [s % 5 for s in seq]
    d = sum(abs(rows[i+1]-rows[i]) + abs(cols[i+1]-cols[i]) for i in range(23)) / 23
    mc_dists.append(d)
exp_dist = sum(mc_dists) / len(mc_dists)
obs_dist = sum(distances) / len(distances)
p_leq = sum(1 for x in mc_dists if x <= obs_dist) / N_MC
print(f"  Expected mean distance (random KA): {exp_dist:.2f}")
print(f"  Observed mean distance: {obs_dist:.2f}")
print(f"  p(≤{obs_dist:.2f}): {p_leq:.4f}")

# ── Save results ────────────────────────────────────────────────────────
outfile = os.path.join(_ROOT, "results", "e_row_sequence_analysis.json")
os.makedirs(os.path.dirname(outfile), exist_ok=True)

output = {
    "experiment": "e_row_sequence_analysis",
    "timestamp": datetime.now().isoformat(),
    "description": "Row/column sequence structure analysis for known keystream",
    "row_sequence": ROW_SEQ,
    "col_sequence": COL_SEQ,
    "row_runs": [(v, l) for v, l in row_runs],
    "run_count": len(row_runs),
    "manhattan_mean": obs_dist,
    "manhattan_p": p_leq,
}

with open(outfile, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to {outfile}")
