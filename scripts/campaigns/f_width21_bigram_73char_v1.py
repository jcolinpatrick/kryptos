#!/usr/bin/env python3
"""Width-21 bigram analysis on 73-char null-extracted K4 text.

Cipher: statistical analysis
Family: campaigns
Status: active
Keyspace: Monte Carlo (100K+ shuffles per width)
Last run: never
Best score: N/A

Bean's most significant ciphertext observation (p=1/6750 on raw 97) has NEVER
been checked on the null-extracted text. If the width-21 property SURVIVES null
extraction, it constrains the cipher. If it DISAPPEARS, the null insertion
created it (stego layer artifact).

Tests:
1. Write 73-char text at width 21. Count vertical repeated bigrams.
2. Monte Carlo: shuffle 73 chars 100K times, count repeated bigrams at each width.
3. Check widths 7, 14, 21, 31 (significant widths).
4. Check col7-transposed text at these widths.
5. Also check original 97-char text for baseline comparison.
"""
import sys, time, json, random
from pathlib import Path
from collections import Counter
from multiprocessing import Pool, cpu_count

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
from kryptos.kernel.constants import CT, CT_LEN

BASE = Path(__file__).resolve().parent.parent.parent

# === CONSTANTS ===
CT97 = CT
USER_MASK = sorted([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
MASK_SET = frozenset(USER_MASK)
KEPT = [i for i in range(97) if i not in MASK_SET]
CT73 = ''.join(CT97[i] for i in KEPT)

# Col7 transposition
def col7_undo(text):
    n = len(text)
    ncols = 7
    nrows_full = n // ncols
    extra = n % ncols
    col_lens = [nrows_full + (1 if c < extra else 0) for c in range(ncols)]
    idx = 0
    cols = []
    for c in range(ncols):
        cols.append(text[idx:idx+col_lens[c]])
        idx += col_lens[c]
    out = []
    for r in range(nrows_full + (1 if extra > 0 else 0)):
        for c in range(ncols):
            if r < col_lens[c]:
                out.append(cols[c][r])
    return ''.join(out)

CT73_COL7 = col7_undo(CT73)

print(f"CT97 = {CT97} ({len(CT97)} chars)")
print(f"CT73 = {CT73} ({len(CT73)} chars)")
print(f"CT73_COL7 = {CT73_COL7} ({len(CT73_COL7)} chars)")

# === BIGRAM ANALYSIS ===
def count_vertical_repeated_bigrams(text, width):
    """Count repeated vertical bigrams when text is written at given width.

    A vertical bigram is (text[i], text[i+width]) for each valid i.
    Count how many distinct vertical bigrams appear more than once.
    """
    n = len(text)
    bigrams = Counter()
    for i in range(n - width):
        bg = text[i] + text[i + width]
        bigrams[bg] += 1

    # Count bigrams appearing more than once
    repeated = sum(1 for bg, cnt in bigrams.items() if cnt > 1)
    total_bigrams = n - width
    unique_bigrams = len(bigrams)
    max_repeat = max(bigrams.values()) if bigrams else 0

    return {
        'repeated_bigrams': repeated,
        'total_bigrams': total_bigrams,
        'unique_bigrams': unique_bigrams,
        'max_repeat': max_repeat,
        'top5': bigrams.most_common(5)
    }

def count_repeated_bigrams_simple(text, width):
    """Just count repeated vertical bigrams (for MC speed)."""
    n = len(text)
    bigrams = Counter()
    for i in range(n - width):
        bg = text[i] + text[i + width]
        bigrams[bg] += 1
    return sum(1 for cnt in bigrams.values() if cnt > 1)

def mc_worker(args):
    """Monte Carlo worker: shuffle text N times, count repeated bigrams at given width."""
    text, width, n_trials, seed = args
    rng = random.Random(seed)
    text_list = list(text)
    counts = []
    for _ in range(n_trials):
        rng.shuffle(text_list)
        shuffled = ''.join(text_list)
        counts.append(count_repeated_bigrams_simple(shuffled, width))
    return counts

# === MAIN ===
if __name__ == '__main__':
    t0 = time.time()
    NWORKERS = min(28, cpu_count())
    MC_TOTAL = 200000  # Total MC trials per test
    MC_PER_WORKER = MC_TOTAL // NWORKERS

    results = {}
    widths_to_test = [7, 14, 21, 31, 3, 5, 11, 13, 24, 8, 9, 10, 15, 17, 19, 23, 26, 28, 29, 30]

    # Test texts
    texts = {
        'CT97': CT97,
        'CT73': CT73,
        'CT73_COL7': CT73_COL7,
    }

    print("\n" + "=" * 70)
    print("WIDTH-N VERTICAL BIGRAM ANALYSIS")
    print("=" * 70)

    for text_name, text in texts.items():
        print(f"\n--- {text_name} ({len(text)} chars) ---")
        text_results = {}

        for width in widths_to_test:
            if width >= len(text):
                continue

            # Actual count
            actual = count_vertical_repeated_bigrams(text, width)
            actual_count = actual['repeated_bigrams']

            # Monte Carlo
            mc_args = [(text, width, MC_PER_WORKER, 42 + i * 1000 + width * 100)
                       for i in range(NWORKERS)]

            mc_counts = []
            with Pool(NWORKERS) as pool:
                for batch in pool.imap_unordered(mc_worker, mc_args, chunksize=1):
                    mc_counts.extend(batch)

            mc_mean = sum(mc_counts) / len(mc_counts)
            mc_std = (sum((x - mc_mean)**2 for x in mc_counts) / len(mc_counts)) ** 0.5
            mc_max = max(mc_counts)
            mc_min = min(mc_counts)

            # p-value: fraction of MC trials >= actual count
            p_ge = sum(1 for x in mc_counts if x >= actual_count) / len(mc_counts)
            p_le = sum(1 for x in mc_counts if x <= actual_count) / len(mc_counts)
            z_score = (actual_count - mc_mean) / mc_std if mc_std > 0 else 0

            verdict = "NORMAL"
            if p_ge < 0.01:
                verdict = "HIGH (p<0.01)"
            elif p_ge < 0.05:
                verdict = "ELEVATED (p<0.05)"
            elif p_le < 0.01:
                verdict = "LOW (p<0.01)"
            elif p_le < 0.05:
                verdict = "DEPRESSED (p<0.05)"

            print(f"  w={width:2d}: actual={actual_count}, "
                  f"MC mean={mc_mean:.1f} std={mc_std:.2f} "
                  f"[{mc_min},{mc_max}], "
                  f"p(>=)={p_ge:.5f}, z={z_score:.2f} "
                  f"-> {verdict}")
            if actual['top5']:
                top5_str = ', '.join(f"{bg}({cnt})" for bg, cnt in actual['top5'][:5])
                print(f"        top bigrams: {top5_str}")

            text_results[str(width)] = {
                'width': width,
                'actual_repeated': actual_count,
                'total_bigrams': actual['total_bigrams'],
                'unique_bigrams': actual['unique_bigrams'],
                'max_repeat': actual['max_repeat'],
                'top5': [(bg, cnt) for bg, cnt in actual['top5']],
                'mc_mean': round(mc_mean, 2),
                'mc_std': round(mc_std, 3),
                'mc_min': mc_min,
                'mc_max': mc_max,
                'mc_trials': len(mc_counts),
                'p_ge': round(p_ge, 6),
                'p_le': round(p_le, 6),
                'z_score': round(z_score, 3),
                'verdict': verdict
            }

        results[text_name] = text_results

    # === SPECIAL: WIDTH-21 DEEP DIVE ===
    print("\n" + "=" * 70)
    print("WIDTH-21 DEEP DIVE: Comparing 97 vs 73 vs 73+col7")
    print("=" * 70)

    for text_name, text in texts.items():
        if 21 >= len(text):
            continue
        info = count_vertical_repeated_bigrams(text, 21)
        print(f"\n{text_name} at width 21:")
        print(f"  Repeated bigrams: {info['repeated_bigrams']}")
        print(f"  Total vertical bigrams: {info['total_bigrams']}")
        print(f"  Unique bigrams: {info['unique_bigrams']}")
        print(f"  Max repeat: {info['max_repeat']}")
        print(f"  All repeated:")
        bg_counter = Counter()
        for i in range(len(text) - 21):
            bg = text[i] + text[i+21]
            bg_counter[bg] += 1
        for bg, cnt in bg_counter.most_common():
            if cnt > 1:
                positions = [i for i in range(len(text)-21) if text[i]+text[i+21] == bg]
                print(f"    {bg} x{cnt} at positions {positions}")

    # === BEAN'S SPECIFIC TEST: Compare to his d=21 result ===
    print("\n" + "=" * 70)
    print("BEAN'S d=21 TEST ON RAW 97 (verification)")
    print("=" * 70)

    # Bean counts pairs (i,j) where i<j, j-i=21, CT[i]=CT[j] AND CT[i+1]=CT[j+1]
    # i.e., consecutive bigram at distance 21
    bean_count = 0
    for i in range(CT_LEN - 22):
        j = i + 21
        if j + 1 < CT_LEN:
            if CT97[i] == CT97[j] and CT97[i+1] == CT97[j+1]:
                bean_count += 1
                print(f"  Bean bigram match: pos {i},{i+1} = {CT97[i]}{CT97[i+1]} == pos {j},{j+1}")

    print(f"\nBean d=21 consecutive bigram matches on raw 97: {bean_count}")

    # MC for Bean's metric
    mc_bean = []
    text_list = list(CT97)
    rng = random.Random(20260315)
    for trial in range(200000):
        rng.shuffle(text_list)
        s = ''.join(text_list)
        c = 0
        for i in range(len(s) - 22):
            j = i + 21
            if j + 1 < len(s):
                if s[i] == s[j] and s[i+1] == s[j+1]:
                    c += 1
        mc_bean.append(c)

    mc_mean = sum(mc_bean) / len(mc_bean)
    mc_std = (sum((x - mc_mean)**2 for x in mc_bean) / len(mc_bean)) ** 0.5
    p_ge = sum(1 for x in mc_bean if x >= bean_count) / len(mc_bean)
    print(f"MC: mean={mc_mean:.3f}, std={mc_std:.3f}, p(>={bean_count})={p_ge:.6f}")

    # Same test on CT73
    print("\n--- Bean d=21 test on CT73 ---")
    bean73 = 0
    for i in range(len(CT73) - 22):
        j = i + 21
        if j + 1 < len(CT73):
            if CT73[i] == CT73[j] and CT73[i+1] == CT73[j+1]:
                bean73 += 1
                print(f"  Bean bigram match: pos {i},{i+1} = {CT73[i]}{CT73[i+1]} == pos {j},{j+1}")
    print(f"Bean d=21 matches on CT73: {bean73}")

    mc_bean73 = []
    text_list73 = list(CT73)
    for trial in range(200000):
        rng.shuffle(text_list73)
        s = ''.join(text_list73)
        c = 0
        for i in range(len(s) - 22):
            j = i + 21
            if j + 1 < len(s):
                if s[i] == s[j] and s[i+1] == s[j+1]:
                    c += 1
        mc_bean73.append(c)
    mc_mean73 = sum(mc_bean73) / len(mc_bean73)
    mc_std73 = (sum((x - mc_mean73)**2 for x in mc_bean73) / len(mc_bean73)) ** 0.5
    p_ge73 = sum(1 for x in mc_bean73 if x >= bean73) / len(mc_bean73)
    print(f"MC: mean={mc_mean73:.3f}, std={mc_std73:.3f}, p(>={bean73})={p_ge73:.6f}")

    # === SAVE RESULTS ===
    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")

    out = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'elapsed_s': round(elapsed, 1),
        'mask': USER_MASK,
        'ct73': CT73,
        'ct73_col7': CT73_COL7,
        'mc_trials_per_test': MC_TOTAL,
        'widths_tested': widths_to_test,
        'results_by_text': results,
        'bean_d21_raw97': {
            'actual': bean_count,
            'mc_mean': round(mc_mean, 4),
            'mc_std': round(mc_std, 4),
            'p_ge': round(p_ge, 6),
        },
        'bean_d21_ct73': {
            'actual': bean73,
            'mc_mean': round(mc_mean73, 4),
            'mc_std': round(mc_std73, 4),
            'p_ge': round(p_ge73, 6),
        },
    }

    out_path = BASE / 'results' / 'f_width21_bigram_73char.json'
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"Results saved to {out_path}")
