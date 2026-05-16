"""Replace W's instead of removing them — disentangle content vs length.

If anomaly survives W -> X replacement (length stays 97), the W *content*
is not the key — fragility to length shift is. If the anomaly dies under
replacement too, then W has a specific structural role beyond length.
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


def evaluate(text, label, width=21, n_trials=200000, n_workers=None):
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
    return f"{label:30s} len={len(text)} actual={actual:2d}  MC mean={mean:.2f} std={std:.2f}  p={p_ge:.4f}  z={z:+.2f}"


if __name__ == "__main__":
    t0 = time.time()
    print(f"CT97       = {CT}")
    print()
    print("=" * 80)
    print("LENGTH-PRESERVING REPLACEMENTS (W -> {A, X, Q, '?'})")
    print("=" * 80)

    # Replace W with each of several test letters; length unchanged.
    for substitute in ['A', 'X', 'Q', '_']:
        new_ct = CT.replace('W', substitute)
        # Pad to length 97 (already is — replace doesn't change length)
        assert len(new_ct) == 97
        label = f"CT_W_to_{substitute}"
        print("  " + evaluate(new_ct, label, width=21, n_trials=200000))

    print()
    print("=" * 80)
    print("CONTROL: replace each (non-W) letter that ALSO kills under removal")
    print("(K, N, P, J — these all had p > 0.7 under removal)")
    print("=" * 80)

    for letter in ['K', 'N', 'P', 'J']:
        new_ct = CT.replace(letter, 'X')  # replace with X, an uncommon letter
        label = f"CT_{letter}_to_X"
        print("  " + evaluate(new_ct, label, width=21, n_trials=200000))

    print()
    print("=" * 80)
    print("REMOVE ONLY THE 2 'STRUCTURAL' W's (positions 36 and 74)")
    print("=" * 80)
    print("These are the W's involved in repeated bigrams (LW at i=15, 53; WA at i=36, 74).")
    # Position 36 and 74 are W's that are inside repeated-bigram pairs.
    # Removing only these 2 should destroy LW and WA but should NOT shift
    # the other 9 bigrams (length goes 97 -> 95, still shifts but less).
    structural_W = {36, 74}
    new_ct = ''.join(c for i, c in enumerate(CT) if i not in structural_W)
    print("  " + evaluate(new_ct, f"CT_minus_W_at_{sorted(structural_W)}", width=21, n_trials=200000))

    # And remove only the 3 non-structural W's
    nonstructural_W = {20, 48, 58}
    new_ct = ''.join(c for i, c in enumerate(CT) if i not in nonstructural_W)
    print("  " + evaluate(new_ct, f"CT_minus_W_at_{sorted(nonstructural_W)}", width=21, n_trials=200000))

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")
