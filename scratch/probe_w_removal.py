"""Test: does removing all W's from CT97 kill the width-21 bigram anomaly?

Methodology:
1. Build CT_noW = CT97 with all W positions removed (length goes 97 -> 92).
2. Count repeated vertical bigrams at width 21 on CT_noW.
3. MC null: shuffle the CT_noW letter multiset 200K times, count repeated
   bigrams at width 21 each shuffle.
4. Report: actual count, MC mean/std, p(>=), z-score.

Companion test: also run on the OTHER 6 letters of the retired palette
({B,G,I,K,O,Z}) individually to see whether the effect is W-specific or
palette-distributed.

Bonus: also report the same statistic when removing each individual letter
of the alphabet (single-letter ablation) so we can see which single
removal causes the anomaly to vanish.
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
    return {
        "label": label,
        "length": len(text),
        "actual": actual,
        "mc_mean": round(mean, 3),
        "mc_std": round(std, 3),
        "p_ge": round(p_ge, 6),
        "z": round(z, 3),
        "n_trials": len(counts),
    }


if __name__ == "__main__":
    t0 = time.time()
    print(f"CT97   = {CT} ({len(CT)} chars)")

    w_positions = [i for i, c in enumerate(CT) if c == 'W']
    print(f"W positions: {w_positions} (count = {len(w_positions)})")

    print("\n" + "=" * 70)
    print("BASELINE: CT97 width-21 (sanity check vs Probe 1)")
    print("=" * 70)
    result = evaluate(CT, "CT97_baseline", width=21, n_trials=200000)
    print(f"  {result}")

    print("\n" + "=" * 70)
    print("W-REMOVAL: CT_noW width-21")
    print("=" * 70)
    ct_noW = ''.join(c for c in CT if c != 'W')
    print(f"CT_noW = {ct_noW} ({len(ct_noW)} chars)")
    result_noW = evaluate(ct_noW, "CT_noW", width=21, n_trials=200000)
    print(f"  {result_noW}")

    print("\n" + "=" * 70)
    print("SINGLE-LETTER ABLATION: width-21 on CT minus each letter")
    print("=" * 70)
    print("Tests whether the W effect is specific to W or whether ANY")
    print("frequent letter, when removed, kills the anomaly. The retired")
    print("palette is {B,G,I,K,O,W,Z}; 26 letters total in the alphabet.")
    print()

    # For each letter, remove all instances and report width-21 result.
    # Use 50K trials each for speed (still adequate for noise discrimination).
    letters_in_ct = sorted(set(CT))
    ablation = []
    for letter in letters_in_ct:
        text = ''.join(c for c in CT if c != letter)
        if len(text) < 22:
            continue
        n_removed = CT.count(letter)
        in_palette = letter in "BGIKOWZ"
        result_ab = evaluate(text, f"CT_no{letter}", width=21, n_trials=50000)
        result_ab["letter_removed"] = letter
        result_ab["instances_removed"] = n_removed
        result_ab["in_retired_palette"] = in_palette
        ablation.append(result_ab)
        print(
            f"  -{letter} (n={n_removed:2d}, palette={in_palette}): "
            f"len={result_ab['length']} actual={result_ab['actual']:2d} "
            f"MC mean={result_ab['mc_mean']:.2f} std={result_ab['mc_std']:.2f} "
            f"p={result_ab['p_ge']:.4f} z={result_ab['z']:+.2f}"
        )

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    elapsed = time.time() - t0
    print(f"Total time: {elapsed:.1f}s")
    print(f"\nBaseline (CT97):  {result['actual']} repeated, p={result['p_ge']}, z={result['z']}")
    print(f"W-removed (CT92): {result_noW['actual']} repeated, p={result_noW['p_ge']}, z={result_noW['z']}")
    print()
    print("Single-letter ablations sorted by p_ge (largest = anomaly killed most):")
    for r in sorted(ablation, key=lambda x: -x['p_ge']):
        marker = " ← in retired palette" if r["in_retired_palette"] else ""
        print(
            f"  -{r['letter_removed']}: p={r['p_ge']:.4f} z={r['z']:+.2f} "
            f"actual={r['actual']:2d}{marker}"
        )
