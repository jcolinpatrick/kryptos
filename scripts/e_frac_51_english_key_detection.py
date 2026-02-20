#!/usr/bin/env python3
"""E-FRAC-51: English-Like Key Fragment Detection on Structured Transpositions

HYPOTHESIS: If K4 uses a running key from UNKNOWN English text + structured
transposition, the implied key values at the 24 crib positions should form
English-like text fragments. We can detect this without knowing the source text.

GAP FILLED:
  - E-FRAC-49/50: Tested running key from 7 SPECIFIC texts → ZERO matches
  - E-FRAC-12/29/30: Tested PERIODIC keys → noise
  - THIS experiment: Tests whether ANY structured transposition produces key
    fragments that LOOK like English, WITHOUT requiring a specific source text.

Method:
  For each Bean-passing columnar ordering at widths 6, 8, 9:
    1. Compute inverse permutation
    2. Derive implied key values at 24 crib positions (3 cipher variants)
    3. Convert to letters (A=0, ..., Z=25)
    4. Form two key fragments: positions 21-33 (13 chars) and 63-73 (11 chars)
    5. Score each fragment for English-likeness:
       a. Quadgram fitness (per char)
       b. Dictionary word detection (≥4 and ≥5 chars)

  Baselines:
    - Random text: 50K random 24-char strings (scored as 13+11 fragments)
    - English text: 10K contiguous 13+11 char pairs from Carter text
    - Random perms: 50K random permutations (key derivation → scoring)

  If the correct transposition is among tested families and the key is English,
  it should produce significantly higher English-likeness than random.
"""

import json
import os
import sys
import time
import random
from itertools import permutations
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, ALPH, MOD,
    CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

# Crib data
CRIB_POS = [pos for pos, _ in CRIB_ENTRIES]
CRIB_PT = [ALPH_IDX[ch] for _, ch in CRIB_ENTRIES]
CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN  # 97

# Crib position ranges
FRAG1_POSITIONS = list(range(21, 34))  # 13 chars (EASTNORTHEAST key positions)
FRAG2_POSITIONS = list(range(63, 74))  # 11 chars (BERLINCLOCK key positions)

VARIANTS = ['vigenere', 'beaufort', 'variant_beaufort']

QUADGRAM_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
WORDLIST_FILE = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'english.txt')
CARTER_FILE = os.path.join(os.path.dirname(__file__), '..', 'reference', 'carter_gutenberg.txt')


class QuadgramScorer:
    def __init__(self, filepath):
        with open(filepath) as f:
            data = json.load(f)
        if isinstance(data, dict) and 'logp' in data:
            self.logp = data['logp']
        else:
            self.logp = data
        self.floor = min(self.logp.values()) - 1.0

    def score_text(self, text):
        """Total quadgram log-probability."""
        text = text.upper()
        if len(text) < 4:
            return self.floor * max(1, len(text) - 3)
        total = 0.0
        for i in range(len(text) - 3):
            quad = text[i:i+4]
            total += self.logp.get(quad, self.floor)
        return total

    def score_per_char(self, text):
        return self.score_text(text) / max(1, len(text))


def load_wordlist(filepath, min_len=4):
    """Load dictionary words of at least min_len characters."""
    words = set()
    with open(filepath) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= min_len and w.isalpha():
                words.add(w)
    return words


def find_words_greedy(text, wordset, min_len=4):
    """Find dictionary words in text (greedy, longest first, non-overlapping)."""
    text = text.upper()
    found = []
    i = 0
    while i < len(text):
        best = None
        for end in range(min(len(text) + 1, i + 16), i + min_len - 1, -1):
            substr = text[i:end]
            if substr in wordset:
                best = substr
                break
        if best:
            found.append(best)
            i += len(best)
        else:
            i += 1
    return found


def generate_columnar_perm(width, col_order):
    """Generate columnar transposition permutation (gather convention)."""
    n = N
    nrows = (n + width - 1) // width
    full_cols = n - (nrows - 1) * width

    perm = []
    for col in col_order:
        if col < full_cols:
            rows = nrows
        else:
            rows = nrows - 1
        for row in range(rows):
            pos = row * width + col
            if pos < n:
                perm.append(pos)
    return perm


def invert_perm(perm):
    """Compute inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_eq(inv_perm):
    """Check Bean equality: CT[inv_perm[27]] == CT[inv_perm[65]]."""
    for eq_a, eq_b in BEAN_EQ:
        if CT[inv_perm[eq_a]] != CT[inv_perm[eq_b]]:
            return False
    return True


def check_bean_ineq(key_dict):
    """Check Bean inequality constraints on key values."""
    for a, b in BEAN_INEQ:
        if a in key_dict and b in key_dict:
            if key_dict[a] == key_dict[b]:
                return False
    return True


def compute_key_values(inv_perm, variant):
    """Compute key values at all 24 crib positions."""
    key_dict = {}
    for i in range(N_CRIBS):
        pos = CRIB_POS[i]
        pt_val = CRIB_PT[i]
        ct_val = CT_NUM[inv_perm[pos]]
        if variant == 'vigenere':
            key_val = (ct_val - pt_val) % MOD
        elif variant == 'beaufort':
            key_val = (ct_val + pt_val) % MOD
        elif variant == 'variant_beaufort':
            key_val = (pt_val - ct_val) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        key_dict[pos] = key_val
    return key_dict


def key_to_fragments(key_dict):
    """Extract two key fragments as letter strings."""
    frag1 = ''.join(ALPH[key_dict[p]] for p in FRAG1_POSITIONS)
    frag2 = ''.join(ALPH[key_dict[p]] for p in FRAG2_POSITIONS)
    return frag1, frag2


def score_fragments(frag1, frag2, scorer, wordset4, wordset5):
    """Score two key fragments for English-likeness."""
    # Quadgram scores (weighted average by length)
    q1 = scorer.score_per_char(frag1)
    q2 = scorer.score_per_char(frag2)
    total_len = len(frag1) + len(frag2)
    q_combined = (q1 * len(frag1) + q2 * len(frag2)) / total_len

    # Word detection at two thresholds
    words4_1 = find_words_greedy(frag1, wordset4, min_len=4)
    words4_2 = find_words_greedy(frag2, wordset4, min_len=4)
    all_words4 = words4_1 + words4_2

    words5_1 = find_words_greedy(frag1, wordset5, min_len=5)
    words5_2 = find_words_greedy(frag2, wordset5, min_len=5)
    all_words5 = words5_1 + words5_2

    return {
        'quadgram_per_char': q_combined,
        'q_frag1': q1,
        'q_frag2': q2,
        'words4': all_words4,
        'n_words4': len(all_words4),
        'words5': all_words5,
        'n_words5': len(all_words5),
        'frag1': frag1,
        'frag2': frag2,
    }


def percentile(sorted_list, p):
    """Return the p-th percentile (0-1) from a sorted list."""
    idx = int(p * len(sorted_list))
    return sorted_list[min(idx, len(sorted_list) - 1)]


def mean_std(values):
    """Compute mean and standard deviation."""
    n = len(values)
    m = sum(values) / n
    s = (sum((x - m) ** 2 for x in values) / n) ** 0.5
    return m, s


def main():
    print("=" * 70)
    print("E-FRAC-51: English-Like Key Fragment Detection")
    print("            on Structured Transpositions")
    print("=" * 70)
    t0 = time.time()

    # Load resources
    print("\nLoading resources...")
    scorer = QuadgramScorer(QUADGRAM_FILE)
    wordset4 = load_wordlist(WORDLIST_FILE, min_len=4)
    wordset5 = load_wordlist(WORDLIST_FILE, min_len=5)
    print(f"  Quadgrams loaded")
    print(f"  Words ≥4 chars: {len(wordset4)}")
    print(f"  Words ≥5 chars: {len(wordset5)}")

    # ====================================================================
    # Phase 1: Generate all Bean-passing columnar orderings
    # ====================================================================
    print("\n--- Phase 1: Generate Bean-passing columnar orderings ---")
    configs = []  # (width, col_order, inv_perm)
    for width in [6, 8, 9]:
        count = 0
        bean_eq_pass = 0
        for col_order in permutations(range(width)):
            count += 1
            perm = generate_columnar_perm(width, col_order)
            inv_perm = invert_perm(perm)
            if check_bean_eq(inv_perm):
                bean_eq_pass += 1
                configs.append((width, col_order, inv_perm))
        print(f"  Width {width}: {count} orderings, {bean_eq_pass} Bean-eq passes "
              f"({100*bean_eq_pass/count:.2f}%)")
    print(f"  Total Bean-eq configs: {len(configs)}")

    # ====================================================================
    # Phase 2: Score key fragments for all Bean-passing configs
    # ====================================================================
    print("\n--- Phase 2: Score key fragments for English-likeness ---")
    results = []
    bean_ineq_fail = 0
    for width, col_order, inv_perm in configs:
        for variant in VARIANTS:
            key_dict = compute_key_values(inv_perm, variant)
            if not check_bean_ineq(key_dict):
                bean_ineq_fail += 1
                continue
            frag1, frag2 = key_to_fragments(key_dict)
            scores = score_fragments(frag1, frag2, scorer, wordset4, wordset5)
            results.append({
                'width': width,
                'col_order': list(col_order),
                'variant': variant,
                **scores,
            })

    n_results = len(results)
    print(f"  Bean-ineq failures: {bean_ineq_fail}")
    print(f"  Total scored configs (full Bean pass): {n_results}")

    # ====================================================================
    # Phase 3: Baselines
    # ====================================================================
    print("\n--- Phase 3: Compute baselines ---")

    # 3a. Random text baseline (random 13+11 char strings)
    random.seed(42)
    N_RAND_TEXT = 50000
    rand_text_qscores = []
    rand_text_nwords4 = []
    rand_text_nwords5 = []
    for _ in range(N_RAND_TEXT):
        frag1 = ''.join(random.choice(ALPH) for _ in range(13))
        frag2 = ''.join(random.choice(ALPH) for _ in range(11))
        s = score_fragments(frag1, frag2, scorer, wordset4, wordset5)
        rand_text_qscores.append(s['quadgram_per_char'])
        rand_text_nwords4.append(s['n_words4'])
        rand_text_nwords5.append(s['n_words5'])

    rand_text_qscores.sort()
    rt_mean, rt_std = mean_std(rand_text_qscores)
    print(f"\n  Random text baseline ({N_RAND_TEXT} trials):")
    print(f"    Quadgram/char: mean={rt_mean:.3f}, std={rt_std:.3f}, "
          f"max={rand_text_qscores[-1]:.3f}, p95={percentile(rand_text_qscores, 0.95):.3f}")
    print(f"    Words≥4: mean={sum(rand_text_nwords4)/N_RAND_TEXT:.2f}, max={max(rand_text_nwords4)}")
    print(f"    Words≥5: mean={sum(rand_text_nwords5)/N_RAND_TEXT:.2f}, max={max(rand_text_nwords5)}")

    # 3b. English text baseline (contiguous substrings from Carter)
    english_qscores = None
    english_nwords4 = None
    english_nwords5 = None
    if os.path.exists(CARTER_FILE):
        with open(CARTER_FILE) as f:
            carter_text = ''.join(c.upper() for c in f.read() if c.isalpha())

        N_ENG = 10000
        english_qscores = []
        english_nwords4 = []
        english_nwords5 = []
        random.seed(99)
        for _ in range(N_ENG):
            # Running key at offset j: key positions 21-33 and 63-73
            # are contiguous substrings of the running key
            start = random.randint(0, len(carter_text) - 74)
            frag1 = carter_text[start + 21: start + 34]
            frag2 = carter_text[start + 63: start + 74]
            s = score_fragments(frag1, frag2, scorer, wordset4, wordset5)
            english_qscores.append(s['quadgram_per_char'])
            english_nwords4.append(s['n_words4'])
            english_nwords5.append(s['n_words5'])

        english_qscores.sort()
        eng_mean, eng_std = mean_std(english_qscores)
        print(f"\n  English text baseline ({N_ENG} Carter substrings at 13+11 char gap):")
        print(f"    Quadgram/char: mean={eng_mean:.3f}, std={eng_std:.3f}, "
              f"max={english_qscores[-1]:.3f}, min={english_qscores[0]:.3f}, "
              f"p5={percentile(english_qscores, 0.05):.3f}")
        print(f"    Words≥4: mean={sum(english_nwords4)/N_ENG:.2f}, max={max(english_nwords4)}")
        print(f"    Words≥5: mean={sum(english_nwords5)/N_ENG:.2f}, max={max(english_nwords5)}")
    else:
        print("\n  [Carter text not found — skipping English baseline]")

    # 3c. Random permutation baseline (key derivation from random perms)
    random.seed(123)
    N_RAND_PERM = 50000
    randperm_qscores = []
    randperm_nwords4 = []
    randperm_nwords5 = []
    indices = list(range(N))
    for trial in range(N_RAND_PERM):
        perm = indices[:]
        random.shuffle(perm)
        inv_perm = invert_perm(perm)
        variant = VARIANTS[trial % 3]
        key_dict = compute_key_values(inv_perm, variant)
        frag1, frag2 = key_to_fragments(key_dict)
        s = score_fragments(frag1, frag2, scorer, wordset4, wordset5)
        randperm_qscores.append(s['quadgram_per_char'])
        randperm_nwords4.append(s['n_words4'])
        randperm_nwords5.append(s['n_words5'])

    randperm_qscores.sort()
    rp_mean, rp_std = mean_std(randperm_qscores)
    print(f"\n  Random perm baseline ({N_RAND_PERM} random permutations):")
    print(f"    Quadgram/char: mean={rp_mean:.3f}, std={rp_std:.3f}, "
          f"max={randperm_qscores[-1]:.3f}, p95={percentile(randperm_qscores, 0.95):.3f}")
    print(f"    Words≥4: mean={sum(randperm_nwords4)/N_RAND_PERM:.2f}, max={max(randperm_nwords4)}")
    print(f"    Words≥5: mean={sum(randperm_nwords5)/N_RAND_PERM:.2f}, max={max(randperm_nwords5)}")

    # ====================================================================
    # Phase 4: Analysis
    # ====================================================================
    print("\n--- Phase 4: Analysis ---")
    if not results:
        print("  No Bean-passing configs found!")
        return

    # Sort by quadgram score (descending = more English-like)
    results.sort(key=lambda x: x['quadgram_per_char'], reverse=True)

    # Top 20 results
    print(f"\n  Top 20 configs by key fragment quadgram score:")
    print(f"  {'Rank':>4} {'W':>2} {'Var':>4} {'Q/char':>7} {'W4':>3} {'W5':>3} "
          f"{'Frag1 (key[21-33])':>16} {'Frag2 (key[63-73])':>14}")
    print(f"  {'----':>4} {'--':>2} {'---':>4} {'------':>7} {'--':>3} {'--':>3} "
          f"{'----------------':>16} {'--------------':>14}")
    for i, r in enumerate(results[:20]):
        var_short = {'vigenere': 'Vig', 'beaufort': 'Bea', 'variant_beaufort': 'VB'}[r['variant']]
        print(f"  {i+1:4d} {r['width']:2d} {var_short:>4} {r['quadgram_per_char']:7.3f} "
              f"{r['n_words4']:3d} {r['n_words5']:3d} {r['frag1']:>16s} {r['frag2']:>14s}")
        words = r['words4']
        if words:
            print(f"       Words: {', '.join(words)}")

    # Distribution stats
    all_qscores = sorted([r['quadgram_per_char'] for r in results])
    col_mean, col_std = mean_std(all_qscores)
    all_nwords4 = [r['n_words4'] for r in results]
    all_nwords5 = [r['n_words5'] for r in results]

    print(f"\n  Columnar config distribution (N={n_results}):")
    print(f"    Quadgram/char: mean={col_mean:.3f}, std={col_std:.3f}, "
          f"max={all_qscores[-1]:.3f}, p95={percentile(all_qscores, 0.95):.3f}, "
          f"p99={percentile(all_qscores, 0.99):.3f}")
    print(f"    Words≥4: mean={sum(all_nwords4)/n_results:.2f}, max={max(all_nwords4)}")
    print(f"    Words≥5: mean={sum(all_nwords5)/n_results:.2f}, max={max(all_nwords5)}")

    # Statistical comparison
    print(f"\n  Statistical comparison:")
    print(f"    {'Population':>20} {'Mean Q/char':>12} {'Std':>8} {'Max':>8} {'d vs rand_perm':>14}")
    print(f"    {'----':>20} {'----':>12} {'---':>8} {'---':>8} {'----':>14}")
    populations = [
        ('Columnar configs', col_mean, col_std, all_qscores[-1]),
        ('Random perm', rp_mean, rp_std, randperm_qscores[-1]),
        ('Random text', rt_mean, rt_std, rand_text_qscores[-1]),
    ]
    if english_qscores:
        populations.append(('English', eng_mean, eng_std, english_qscores[-1]))

    for name, m, s, mx in populations:
        d = (m - rp_mean) / rp_std if rp_std > 0 else 0
        print(f"    {name:>20} {m:12.3f} {s:8.3f} {mx:8.3f} {d:14.2f}")

    # How many columnar configs exceed random perm max?
    rp_max = randperm_qscores[-1]
    n_exceed_rp = sum(1 for q in all_qscores if q > rp_max)
    print(f"\n  Columnar configs exceeding random perm max ({rp_max:.3f}): "
          f"{n_exceed_rp}/{n_results}")

    # How many are in the English range?
    if english_qscores:
        eng_p5 = percentile(english_qscores, 0.05)
        eng_p50 = percentile(english_qscores, 0.50)
        n_in_english = sum(1 for q in all_qscores if q >= eng_p5)
        n_above_median = sum(1 for q in all_qscores if q >= eng_p50)
        print(f"  Columnar configs ≥ English 5th pctile ({eng_p5:.3f}): "
              f"{n_in_english}/{n_results}")
        print(f"  Columnar configs ≥ English median ({eng_p50:.3f}): "
              f"{n_above_median}/{n_results}")

    # Per-width breakdown
    print(f"\n  Per-width breakdown:")
    for w in [6, 8, 9]:
        w_results = [r for r in results if r['width'] == w]
        if w_results:
            w_qscores = [r['quadgram_per_char'] for r in w_results]
            w_mean = sum(w_qscores) / len(w_qscores)
            w_max = max(w_qscores)
            print(f"    Width {w}: N={len(w_results)}, mean={w_mean:.3f}, max={w_max:.3f}")

    # ====================================================================
    # Phase 5: P-value computation
    # ====================================================================
    print("\n--- Phase 5: P-value and Verdict ---")
    best = results[0]
    best_q = best['quadgram_per_char']

    # Raw p-value: fraction of random perms with quadgram >= best columnar
    n_rand_better = sum(1 for q in randperm_qscores if q >= best_q)
    p_raw = n_rand_better / N_RAND_PERM

    # Corrected p-value (Bonferroni for number of columnar configs tested)
    p_corrected = min(1.0, p_raw * n_results)

    print(f"  Best columnar config:")
    print(f"    Width: {best['width']}, Order: {best['col_order']}, Variant: {best['variant']}")
    print(f"    Key fragment 1 (pos 21-33): {best['frag1']}")
    print(f"    Key fragment 2 (pos 63-73): {best['frag2']}")
    print(f"    Quadgram/char: {best_q:.3f}")
    print(f"    Words≥4: {best['n_words4']} — {', '.join(best['words4']) if best['words4'] else '(none)'}")
    print(f"    Words≥5: {best['n_words5']} — {', '.join(best['words5']) if best['words5'] else '(none)'}")
    print(f"    Raw p-value vs random perms: {p_raw:.6f}")
    print(f"    Corrected p-value ({n_results} trials): {p_corrected:.6f}")

    # Determine verdict
    if english_qscores and best_q >= eng_p5:
        verdict = "SIGNAL"
        print(f"\n  *** SIGNAL: Best config produces key in the English range! ***")
    elif best_q > rp_max:
        verdict = "MARGINAL"
        print(f"\n  MARGINAL: Best config exceeds random perm max "
              f"({rp_max:.3f}) but below English range.")
    else:
        verdict = "NOISE"
        print(f"\n  NOISE: Best columnar config ({best_q:.3f}) is within "
              f"random perm range ({rp_max:.3f}).")
        print(f"  NO structured transposition produces English-like key fragments.")
        print(f"  Running key from unknown English text + columnar transposition")
        print(f"  is ELIMINATED as a hypothesis (complements E-FRAC-49/50).")

    # ====================================================================
    # Phase 6: Cross-check — identity transposition (no transposition)
    # ====================================================================
    print(f"\n--- Phase 6: Identity transposition cross-check ---")
    identity_inv = list(range(N))
    for variant in VARIANTS:
        key_dict = compute_key_values(identity_inv, variant)
        frag1, frag2 = key_to_fragments(key_dict)
        s = score_fragments(frag1, frag2, scorer, wordset4, wordset5)
        var_short = {'vigenere': 'Vig', 'beaufort': 'Bea', 'variant_beaufort': 'VB'}[variant]
        print(f"  Identity ({var_short}): Q/char={s['quadgram_per_char']:.3f}, "
              f"frag1={frag1}, frag2={frag2}, "
              f"words={', '.join(s['words4']) if s['words4'] else '(none)'}")

    # ====================================================================
    # Save results
    # ====================================================================
    runtime = time.time() - t0

    out_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'frac')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'e_frac_51_english_key_detection.json')

    output = {
        'experiment': 'E-FRAC-51',
        'description': 'English-like key fragment detection on structured transpositions',
        'hypothesis': (
            'If K4 uses running key from unknown English text + structured '
            'transposition, the implied key at crib positions should form '
            'English-like fragments detectable by quadgram scoring.'
        ),
        'method': (
            'Compute implied key at 24 crib positions for all Bean-passing '
            'columnar orderings at widths 6,8,9 x 3 cipher variants. Score '
            'key fragments (pos 21-33: 13 chars, pos 63-73: 11 chars) for '
            'English-likeness using quadgrams and word detection.'
        ),
        'total_configs': n_results,
        'bean_ineq_failures': bean_ineq_fail,
        'baselines': {
            'random_text': {
                'n': N_RAND_TEXT,
                'mean_quadgram': rt_mean,
                'std_quadgram': rt_std,
                'max_quadgram': rand_text_qscores[-1],
            },
            'random_perm': {
                'n': N_RAND_PERM,
                'mean_quadgram': rp_mean,
                'std_quadgram': rp_std,
                'max_quadgram': rp_max,
            },
        },
        'columnar_distribution': {
            'n': n_results,
            'mean_quadgram': col_mean,
            'std_quadgram': col_std,
            'max_quadgram': all_qscores[-1],
        },
        'best_config': {
            'width': best['width'],
            'col_order': best['col_order'],
            'variant': best['variant'],
            'quadgram_per_char': best_q,
            'frag1': best['frag1'],
            'frag2': best['frag2'],
            'words4': best['words4'],
            'words5': best['words5'],
        },
        'top_20': [{
            'width': r['width'],
            'col_order': r['col_order'],
            'variant': r['variant'],
            'quadgram_per_char': r['quadgram_per_char'],
            'frag1': r['frag1'],
            'frag2': r['frag2'],
            'words4': r['words4'],
        } for r in results[:20]],
        'p_value_raw': p_raw,
        'p_value_corrected': p_corrected,
        'verdict': verdict,
        'runtime_seconds': runtime,
    }

    if english_qscores:
        output['baselines']['english'] = {
            'n': N_ENG,
            'mean_quadgram': eng_mean,
            'std_quadgram': eng_std,
            'max_quadgram': english_qscores[-1],
            'min_quadgram': english_qscores[0],
            'p5_quadgram': eng_p5,
            'p50_quadgram': eng_p50,
        }

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {out_path}")

    print(f"  Runtime: {runtime:.1f} seconds")
    print("\n" + "=" * 70)
    print(f"RESULT: best_q={best_q:.3f}/char words4={best['n_words4']} "
          f"verdict={verdict}")
    print("=" * 70)


if __name__ == '__main__':
    main()
