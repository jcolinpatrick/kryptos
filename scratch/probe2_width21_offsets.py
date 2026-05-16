"""Width-21 Probe 2: 21-column grid with predeclared row offsets.

Predeclared parameter set (locked before observing results):
- Width: 21 (the established anomaly width)
- Reading orders to test:
    rows-then-cols (row-major reading, the default)
    cols-then-rows (column-major reading)
    boustrophedon (rows alternating direction)
    diagonal (anti-diagonal reading)
- Row offsets: 0, 3, 7, 11 (offset = which row of the 21-column grid is
  treated as row 0; remaining text wraps).
- Statistic: count of repeated vertical bigrams at width 21 in the
  reordered text.
- Null model: 200K letter-multiset shuffles of the reordered text.

If a specific (reading_order, offset) combination shows a TIGHTER
anomaly than baseline (CT97 raw at offset 0), that's evidence the
width-21 structure aligns with that reading order. If all
combinations look like baseline, the structure is offset-symmetric.

This probe is PREDECLARED before any reading is computed — the
parameter set above is the search universe. Bonferroni-corrected p
needs to clear the gate at corrected level for any single
(order, offset) to count as signal.

Bonferroni multiplier: 4 reading orders × 4 offsets = 16 tests.
At baseline p ≈ 1.6e-4, baseline survives Bonferroni 16x at
corrected ≈ 2.6e-3 (still notable).

The hypothesis we are testing is positional, not content. A
substitution-only cipher would show offset-symmetric results; a
transposition / route at width 21 would concentrate at a particular
offset.
"""
import sys
import time
import random
from collections import Counter
from multiprocessing import Pool, cpu_count
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from kryptos.kernel.constants import CT


def count_repeated_vbigrams(text, width):
    n = len(text)
    bigrams = Counter()
    for i in range(n - width):
        bigrams[text[i] + text[i + width]] += 1
    return sum(1 for cnt in bigrams.values() if cnt > 1)


def reorder_text(text, width, reading_order, row_offset):
    """Reorder text by writing into a width-column grid then reading
    out under the named reading order. row_offset shifts the start
    row by that many CT positions (so offset=3 means the original
    text starts on what we treat as 'row 0' shifted 3 rows down,
    which equivalently means we cyclically rotate the text by
    3 * width characters first... but for non-divisible lengths we
    just rotate by row_offset characters and re-grid).
    """
    n = len(text)
    # Rotate cyclically by row_offset (treating text as a sequence of
    # rows of `width` characters each). Simplest interpretation:
    # rotate by row_offset characters. For row_offset=3, the first 3
    # characters move to the end.
    text = text[row_offset:] + text[:row_offset]

    # Compute number of complete rows and any partial row.
    rows = (n + width - 1) // width
    grid = [['' for _ in range(width)] for _ in range(rows)]
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[r][c] = ch

    if reading_order == "rows-then-cols":
        # Original layout — just return text (rotation already applied).
        return text
    elif reading_order == "cols-then-rows":
        # Read column by column, top to bottom.
        out = []
        for c in range(width):
            for r in range(rows):
                if grid[r][c]:
                    out.append(grid[r][c])
        return ''.join(out)
    elif reading_order == "boustrophedon":
        # Rows alternate direction.
        out = []
        for r in range(rows):
            row_chars = [g for g in grid[r] if g]
            if r % 2 == 1:
                row_chars = row_chars[::-1]
            out.extend(row_chars)
        return ''.join(out)
    elif reading_order == "diagonal":
        # Anti-diagonal: read characters where r+c=const, from top-left
        # to bottom-right.
        out = []
        for s in range(rows + width - 1):
            for r in range(rows):
                c = s - r
                if 0 <= c < width and grid[r][c]:
                    out.append(grid[r][c])
        return ''.join(out)
    else:
        raise ValueError(f"unknown reading_order: {reading_order}")


def mc_worker(args):
    text, width, n_trials, seed = args
    rng = random.Random(seed)
    text_list = list(text)
    counts = []
    for _ in range(n_trials):
        rng.shuffle(text_list)
        s = ''.join(text_list)
        counts.append(count_repeated_vbigrams(s, width))
    return counts


def evaluate(text, width=21, n_trials=200000, n_workers=None):
    n_workers = n_workers or min(28, cpu_count())
    actual = count_repeated_vbigrams(text, width)
    per_worker = n_trials // n_workers
    args = [(text, width, per_worker, 20260502 + i * 1000 + width)
            for i in range(n_workers)]
    counts = []
    with Pool(n_workers) as pool:
        for batch in pool.imap_unordered(mc_worker, args, chunksize=1):
            counts.extend(batch)
    mean = sum(counts) / len(counts)
    var = sum((x - mean) ** 2 for x in counts) / len(counts)
    std = var ** 0.5
    p_ge = sum(1 for x in counts if x >= actual) / len(counts)
    z = (actual - mean) / std if std > 0 else 0.0
    return {
        "actual": actual,
        "mean": round(mean, 3),
        "std": round(std, 3),
        "p_ge": round(p_ge, 6),
        "z": round(z, 3),
    }


if __name__ == "__main__":
    t0 = time.time()
    width = 21
    reading_orders = ["rows-then-cols", "cols-then-rows", "boustrophedon", "diagonal"]
    row_offsets = [0, 3, 7, 11]
    n_trials = 200000

    print(f"CT97 = {CT}")
    print(f"\nProbe 2: 21-column grid, reading orders × row offsets")
    print(f"Predeclared: {len(reading_orders)} orders × {len(row_offsets)} offsets = "
          f"{len(reading_orders)*len(row_offsets)} tests")
    print(f"Bonferroni multiplier: {len(reading_orders)*len(row_offsets)}")
    print(f"MC trials per cell: {n_trials}")

    print("\n" + "=" * 90)
    fmt = "{:18s} {:7s} {:6s} {:>10s} {:>10s} {:>10s} {:>10s}"
    print(fmt.format("READING ORDER", "OFFSET", "LEN", "ACTUAL", "MC_MEAN", "P", "Z"))
    print("=" * 90)

    cells = []
    for order in reading_orders:
        for offset in row_offsets:
            reordered = reorder_text(CT, width, order, offset)
            r = evaluate(reordered, width=width, n_trials=n_trials)
            cells.append((order, offset, len(reordered), r))
            print(fmt.format(
                order, str(offset), str(len(reordered)),
                str(r["actual"]),
                f"{r['mean']:.2f}",
                f"{r['p_ge']:.4f}",
                f"{r['z']:+.2f}",
            ))

    print("\n" + "=" * 90)
    print("SUMMARY (sorted by p_ge ascending — tighter signals first):")
    print("=" * 90)
    cells_sorted = sorted(cells, key=lambda x: x[3]["p_ge"])
    for order, offset, length, r in cells_sorted:
        bonf = min(1.0, r["p_ge"] * len(cells))
        marker = ""
        if bonf < 0.001:
            marker = "  ← Bonferroni < 0.001"
        elif bonf < 0.01:
            marker = "  ← Bonferroni < 0.01"
        elif bonf < 0.05:
            marker = "  ← Bonferroni < 0.05"
        print(f"  {order:18s} offset={offset}  actual={r['actual']:2d}  "
              f"p={r['p_ge']:.4f}  z={r['z']:+.2f}  Bonf={bonf:.4f}{marker}")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")
