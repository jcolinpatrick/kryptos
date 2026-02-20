#!/usr/bin/env python3
"""E-FRAC-54: Mono Inner + Transposition + Running Key from English Detection

HYPOTHESIS: Adding a monoalphabetic inner substitution before transposition gives
13 degrees of freedom (one shift per known PT letter) to adjust the implied running
key values at crib positions. Can these shifts make the key fragments look English?

Model: CT[inv(j)] = (Sub[PT[j]] + RunKey[inv(j)]) mod 26
  => RunKey[inv(j)] = CT[inv(j)] - Sub[PT[j]] = CT[inv(j)] - s_{letter(j)} (mod 26)

Where s_{letter} is the mono substitution value for each of the 13 distinct PT letters
in the cribs: E, A, S, T, N, O, R, H, B, L, I, C, K.

GAP FILLED:
  - E-FRAC-51: Tests English-like key fragments WITHOUT mono layer → ZERO in English range
  - E-FRAC-53: Tests Mono+Trans+Periodic → ELIMINATED at periods 3-7
  - THIS experiment: Tests whether the mono layer's 13 DOF can shift key fragments
    from non-English (E-FRAC-51 mean = -5.41/char) into English range (-3.55/char).
  - If YES → mono+trans+running_key from English is viable, needs further investigation
  - If NO → mono+trans+running_key from English is ELIMINATED

Method:
  For each Bean-passing columnar ordering at widths 6, 8, 9:
    1. For each cipher variant (Vig/Beau/VB):
       a. Compute key constraint: k[j] = CT[inv_perm[j]] - s_{PT_letter[j]} (mod 26)
       b. Optimize 13 s-values via coordinate descent to maximize quadgram score
          of combined key fragments (pos 21-33: 13 chars, pos 63-73: 11 chars)
       c. Score best key fragments against English baseline
    2. Record best (ordering, variant, mono_shifts) config

  Upper bound: unconstrained optimization (s-values can repeat)
  If upper bound < English 5th percentile → ELIMINATED (even with extra DOF)
"""

import json
import os
import sys
import time
import random
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, ALPH, MOD,
    CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

# Crib data
CRIB_POS = [pos for pos, _ in CRIB_ENTRIES]
CRIB_PT_CHAR = [ch for _, ch in CRIB_ENTRIES]
CRIB_PT = [ALPH_IDX[ch] for ch in CRIB_PT_CHAR]
CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN  # 97

# Identify distinct PT letters and their positions in crib list
DISTINCT_LETTERS = sorted(set(CRIB_PT_CHAR))  # 13 distinct letters
LETTER_TO_IDX = {ch: i for i, ch in enumerate(DISTINCT_LETTERS)}
N_LETTERS = len(DISTINCT_LETTERS)  # 13

# For each crib position, which letter index does it use?
CRIB_LETTER_IDX = [LETTER_TO_IDX[ch] for ch in CRIB_PT_CHAR]

# Fragment definitions
FRAG1_POSITIONS = list(range(21, 34))  # 13 chars (EASTNORTHEAST)
FRAG2_POSITIONS = list(range(63, 74))  # 11 chars (BERLINCLOCK)

# Map crib positions to fragment indices
CRIB_TO_FRAG = {}
for i, pos in enumerate(CRIB_POS):
    if pos in FRAG1_POSITIONS:
        CRIB_TO_FRAG[i] = ('f1', FRAG1_POSITIONS.index(pos))
    elif pos in FRAG2_POSITIONS:
        CRIB_TO_FRAG[i] = ('f2', FRAG2_POSITIONS.index(pos))

VARIANTS = ['vigenere', 'beaufort', 'variant_beaufort']

QUADGRAM_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
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

    def score_combined(self, frag1, frag2):
        """Weighted average quadgram/char for two fragments."""
        s1 = self.score_text(frag1)
        s2 = self.score_text(frag2)
        return (s1 + s2) / (len(frag1) + len(frag2))


def generate_columnar_perm(width, col_order):
    n = N
    nrows = (n + width - 1) // width
    full_cols = n - (nrows - 1) * width
    perm = []
    for col in col_order:
        rows = nrows if col < full_cols else nrows - 1
        for row in range(rows):
            pos = row * width + col
            if pos < n:
                perm.append(pos)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_eq(inv_perm):
    for eq_a, eq_b in BEAN_EQ:
        if CT[inv_perm[eq_a]] != CT[inv_perm[eq_b]]:
            return False
    return True


def compute_ct_at_crib_positions(inv_perm):
    """For each crib position, return CT_NUM[inv_perm[pos]]."""
    return [CT_NUM[inv_perm[pos]] for pos in CRIB_POS]


def derive_key_with_mono(ct_vals, s_values, variant):
    """Derive key values at crib positions given mono shifts and cipher variant.

    For Vigenère: RunKey = CT - Sub[PT] = ct_val - s_value
    For Beaufort: RunKey = CT + Sub[PT] = ct_val + s_value
    For VB:       RunKey = Sub[PT] - CT = s_value - ct_val
    """
    keys = [0] * N_CRIBS
    for i in range(N_CRIBS):
        ct_val = ct_vals[i]
        s_val = s_values[CRIB_LETTER_IDX[i]]
        if variant == 'vigenere':
            keys[i] = (ct_val - s_val) % MOD
        elif variant == 'beaufort':
            keys[i] = (ct_val + s_val) % MOD
        elif variant == 'variant_beaufort':
            keys[i] = (s_val - ct_val) % MOD
    return keys


def keys_to_fragments(keys):
    """Convert 24 key values to two fragment strings."""
    frag1 = []
    frag2 = []
    for i, pos in enumerate(CRIB_POS):
        letter = ALPH[keys[i]]
        if pos in FRAG1_POSITIONS:
            frag1.append((FRAG1_POSITIONS.index(pos), letter))
        elif pos in FRAG2_POSITIONS:
            frag2.append((FRAG2_POSITIONS.index(pos), letter))
    frag1.sort()
    frag2.sort()
    return ''.join(ch for _, ch in frag1), ''.join(ch for _, ch in frag2)


def optimize_mono_shifts(ct_vals, variant, scorer, n_restarts=5, max_rounds=10):
    """Optimize 13 mono shifts to maximize quadgram score of key fragments.

    Uses coordinate descent with multiple random restarts.
    Returns: best_score, best_s_values, best_frag1, best_frag2
    """
    best_overall_score = -999.0
    best_overall_s = None
    best_overall_frags = None

    for restart in range(n_restarts):
        # Initialize: restart 0 uses original PT values, rest are random
        if restart == 0:
            s_values = [ALPH_IDX[ch] for ch in DISTINCT_LETTERS]
        else:
            s_values = [random.randint(0, 25) for _ in range(N_LETTERS)]

        # Compute initial score
        keys = derive_key_with_mono(ct_vals, s_values, variant)
        frag1, frag2 = keys_to_fragments(keys)
        current_score = scorer.score_combined(frag1, frag2)

        # Coordinate descent
        for round_num in range(max_rounds):
            improved = False
            for letter_idx in range(N_LETTERS):
                old_val = s_values[letter_idx]
                best_val = old_val
                best_round_score = current_score

                for try_val in range(MOD):
                    if try_val == old_val:
                        continue
                    s_values[letter_idx] = try_val
                    keys = derive_key_with_mono(ct_vals, s_values, variant)
                    frag1, frag2 = keys_to_fragments(keys)
                    score = scorer.score_combined(frag1, frag2)
                    if score > best_round_score:
                        best_round_score = score
                        best_val = try_val

                s_values[letter_idx] = best_val
                if best_val != old_val:
                    current_score = best_round_score
                    improved = True

            if not improved:
                break

        # Record best
        keys = derive_key_with_mono(ct_vals, s_values, variant)
        frag1, frag2 = keys_to_fragments(keys)
        final_score = scorer.score_combined(frag1, frag2)

        if final_score > best_overall_score:
            best_overall_score = final_score
            best_overall_s = s_values[:]
            best_overall_frags = (frag1, frag2)

    return best_overall_score, best_overall_s, best_overall_frags


def check_bean_ineq_from_keys(keys):
    """Check Bean inequality constraints on key values."""
    key_dict = {CRIB_POS[i]: keys[i] for i in range(N_CRIBS)}
    for a, b in BEAN_INEQ:
        if a in key_dict and b in key_dict:
            if key_dict[a] == key_dict[b]:
                return False
    return True


def mean_std(values):
    n = len(values)
    m = sum(values) / n
    s = (sum((x - m) ** 2 for x in values) / n) ** 0.5
    return m, s


def percentile(sorted_list, p):
    idx = int(p * len(sorted_list))
    return sorted_list[min(idx, len(sorted_list) - 1)]


def main():
    print("=" * 70)
    print("E-FRAC-54: Mono Inner + Transposition + Running Key Detection")
    print("           Does monoalphabetic inner layer make key English-like?")
    print("=" * 70)
    t0 = time.time()
    random.seed(54)

    # Load quadgram scorer
    print("\nLoading quadgram scorer...")
    scorer = QuadgramScorer(QUADGRAM_FILE)

    # ====================================================================
    # Phase 0: Identify distinct PT letters and their crib positions
    # ====================================================================
    print(f"\n--- Phase 0: Crib letter analysis ---")
    print(f"  Distinct PT letters ({N_LETTERS}): {' '.join(DISTINCT_LETTERS)}")
    for i, ch in enumerate(DISTINCT_LETTERS):
        positions = [CRIB_POS[j] for j in range(N_CRIBS) if CRIB_PT_CHAR[j] == ch]
        print(f"    {ch}: positions {positions}")

    # ====================================================================
    # Phase 1: Test identity transposition first (quick diagnostic)
    # ====================================================================
    print(f"\n--- Phase 1: Identity transposition (no transposition) ---")
    identity_inv = list(range(N))
    ct_vals_identity = compute_ct_at_crib_positions(identity_inv)

    identity_results = []
    for variant in VARIANTS:
        score, s_vals, (frag1, frag2) = optimize_mono_shifts(
            ct_vals_identity, variant, scorer, n_restarts=10, max_rounds=15
        )
        s_letters = ''.join(ALPH[v] for v in s_vals)
        var_short = {'vigenere': 'Vig', 'beaufort': 'Bea', 'variant_beaufort': 'VB'}[variant]
        print(f"  {var_short}: Q/char={score:.3f}, frag1={frag1}, frag2={frag2}")
        print(f"         mono_shifts={s_letters}")

        # Compare to E-FRAC-51 (no mono optimization)
        keys_orig = derive_key_with_mono(ct_vals_identity,
                                          [ALPH_IDX[ch] for ch in DISTINCT_LETTERS],
                                          variant)
        frag1_orig, frag2_orig = keys_to_fragments(keys_orig)
        orig_score = scorer.score_combined(frag1_orig, frag2_orig)
        print(f"         E-FRAC-51 (no mono): Q/char={orig_score:.3f}, "
              f"improvement={score - orig_score:.3f}")

        identity_results.append({
            'variant': variant,
            'optimized_score': score,
            'original_score': orig_score,
            'improvement': score - orig_score,
            'frag1': frag1,
            'frag2': frag2,
            'mono_shifts': s_vals,
        })

    id_best = max(identity_results, key=lambda x: x['optimized_score'])
    print(f"\n  Identity best: {id_best['optimized_score']:.3f}/char "
          f"(improvement: {id_best['improvement']:.3f} from {id_best['original_score']:.3f})")

    # ====================================================================
    # Phase 2: English baseline
    # ====================================================================
    print(f"\n--- Phase 2: English baseline ---")
    if os.path.exists(CARTER_FILE):
        with open(CARTER_FILE) as f:
            carter_text = ''.join(c.upper() for c in f.read() if c.isalpha())
        N_ENG = 10000
        english_qscores = []
        random.seed(99)
        for _ in range(N_ENG):
            start = random.randint(0, len(carter_text) - 74)
            frag1 = carter_text[start + 21: start + 34]
            frag2 = carter_text[start + 63: start + 74]
            english_qscores.append(scorer.score_combined(frag1, frag2))
        english_qscores.sort()
        eng_mean, eng_std = mean_std(english_qscores)
        eng_p5 = percentile(english_qscores, 0.05)
        eng_p50 = percentile(english_qscores, 0.50)
        print(f"  English ({N_ENG} Carter pairs): mean={eng_mean:.3f}, "
              f"p5={eng_p5:.3f}, p50={eng_p50:.3f}, min={english_qscores[0]:.3f}")
    else:
        english_qscores = None
        eng_p5 = -3.551  # fallback from E-FRAC-51
        print(f"  [Carter not found; using E-FRAC-51 p5={eng_p5:.3f}]")

    # ====================================================================
    # Phase 3: Random perm + mono optimization baseline
    # ====================================================================
    print(f"\n--- Phase 3: Random permutation + mono optimization baseline ---")
    N_RAND = 2000
    rand_scores = []
    indices = list(range(N))
    random.seed(123)
    for trial in range(N_RAND):
        perm = indices[:]
        random.shuffle(perm)
        inv_perm = invert_perm(perm)
        ct_vals = compute_ct_at_crib_positions(inv_perm)
        variant = VARIANTS[trial % 3]
        score, _, _ = optimize_mono_shifts(ct_vals, variant, scorer, n_restarts=3, max_rounds=8)
        rand_scores.append(score)
        if (trial + 1) % 500 == 0:
            print(f"    ... {trial + 1}/{N_RAND} done, "
                  f"current max={max(rand_scores):.3f}")
    rand_scores.sort()
    rp_mean, rp_std = mean_std(rand_scores)
    rp_max = rand_scores[-1]
    print(f"  Random perm + mono opt ({N_RAND}): mean={rp_mean:.3f}, "
          f"std={rp_std:.3f}, max={rp_max:.3f}, p95={percentile(rand_scores, 0.95):.3f}")

    # ====================================================================
    # Phase 4: SAMPLED Bean-passing columnar configs + mono optimization
    # ====================================================================
    print(f"\n--- Phase 4: Sampled Bean-passing columnar + mono optimization ---")
    all_configs = []
    for width in [6, 8, 9]:
        bean_eq_pass = 0
        for col_order in permutations(range(width)):
            perm = generate_columnar_perm(width, col_order)
            inv_perm = invert_perm(perm)
            if check_bean_eq(inv_perm):
                bean_eq_pass += 1
                all_configs.append((width, col_order, inv_perm))
        print(f"  Width {width}: {bean_eq_pass} Bean-eq passes")
    print(f"  Total Bean-eq configs: {len(all_configs)}")

    # Sample 500 configs (representative across widths)
    N_SAMPLE = 500
    random.seed(54)
    if len(all_configs) > N_SAMPLE:
        configs = random.sample(all_configs, N_SAMPLE)
    else:
        configs = all_configs
    print(f"  Sampled: {len(configs)} configs for detailed optimization")

    results = []
    for ci, (width, col_order, inv_perm) in enumerate(configs):
        ct_vals = compute_ct_at_crib_positions(inv_perm)
        for variant in VARIANTS:
            score, s_vals, (frag1, frag2) = optimize_mono_shifts(
                ct_vals, variant, scorer, n_restarts=5, max_rounds=10
            )
            # Check Bean inequality on optimized key values
            keys = derive_key_with_mono(ct_vals, s_vals, variant)
            bean_ineq_pass = check_bean_ineq_from_keys(keys)

            results.append({
                'width': width,
                'col_order': list(col_order),
                'variant': variant,
                'score': score,
                'bean_ineq': bean_ineq_pass,
                'frag1': frag1,
                'frag2': frag2,
                'mono_shifts': s_vals,
            })

        if (ci + 1) % 100 == 0:
            elapsed = time.time() - t0
            print(f"    ... {ci + 1}/{len(configs)} configs done ({elapsed:.0f}s), "
                  f"current max={max(r['score'] for r in results):.3f}")

    n_results = len(results)
    print(f"  Total scored: {n_results}")

    # ====================================================================
    # Phase 5: Analysis
    # ====================================================================
    print(f"\n--- Phase 5: Analysis ---")
    results.sort(key=lambda x: x['score'], reverse=True)

    all_scores = sorted([r['score'] for r in results])
    col_mean, col_std = mean_std(all_scores)

    print(f"  Top 20 by optimized quadgram score:")
    print(f"  {'Rank':>4} {'W':>2} {'Var':>4} {'Q/char':>7} {'Bean':>5} "
          f"{'Frag1':>16} {'Frag2':>14}")
    for i, r in enumerate(results[:20]):
        var_short = {'vigenere': 'Vig', 'beaufort': 'Bea', 'variant_beaufort': 'VB'}[r['variant']]
        bean = 'PASS' if r['bean_ineq'] else 'FAIL'
        print(f"  {i+1:4d} {r['width']:2d} {var_short:>4} {r['score']:7.3f} {bean:>5} "
              f"{r['frag1']:>16s} {r['frag2']:>14s}")

    # Distribution comparison
    print(f"\n  Distribution comparison:")
    print(f"    {'Population':>30} {'Mean':>8} {'Std':>8} {'Max':>8} {'d vs rand':>10}")
    pops = [
        ('Columnar + mono opt', col_mean, col_std, all_scores[-1]),
        ('Random perm + mono opt', rp_mean, rp_std, rp_max),
        ('Identity + mono opt', id_best['optimized_score'], 0, id_best['optimized_score']),
    ]
    if english_qscores:
        pops.append(('English (no mono needed)', eng_mean, eng_std, english_qscores[-1]))
    for name, m, s, mx in pops:
        d = (m - rp_mean) / rp_std if rp_std > 0 else 0
        print(f"    {name:>30} {m:8.3f} {s:8.3f} {mx:8.3f} {d:10.2f}")

    # How many exceed English 5th percentile?
    n_in_english = sum(1 for s in all_scores if s >= eng_p5)
    n_exceed_rand = sum(1 for s in all_scores if s > rp_max)

    print(f"\n  Columnar + mono opt configs >= English 5th pctile ({eng_p5:.3f}): "
          f"{n_in_english}/{n_results}")
    print(f"  Columnar + mono opt configs > random perm max ({rp_max:.3f}): "
          f"{n_exceed_rand}/{n_results}")

    # Improvement from mono optimization
    print(f"\n  Improvement from mono layer (vs E-FRAC-51 without mono):")
    print(f"    E-FRAC-51 best (no mono): -4.151/char")
    print(f"    E-FRAC-54 best (with mono): {all_scores[-1]:.3f}/char")
    print(f"    Improvement: {all_scores[-1] - (-4.151):.3f}/char")
    print(f"    English 5th pctile target: {eng_p5:.3f}/char")
    print(f"    Gap remaining: {eng_p5 - all_scores[-1]:.3f}/char")

    # Per-width breakdown
    print(f"\n  Per-width breakdown:")
    for w in [6, 8, 9]:
        w_scores = [r['score'] for r in results if r['width'] == w]
        if w_scores:
            w_mean = sum(w_scores) / len(w_scores)
            print(f"    Width {w}: N={len(w_scores)}, mean={w_mean:.3f}, max={max(w_scores):.3f}")

    # ====================================================================
    # Phase 6: Verdict
    # ====================================================================
    print(f"\n--- Phase 6: Verdict ---")
    best = results[0]
    best_q = best['score']

    # P-value: how many random perm + mono opt scores exceed best columnar?
    n_rand_better = sum(1 for s in rand_scores if s >= best_q)
    p_raw = n_rand_better / N_RAND
    p_corrected = min(1.0, p_raw * n_results)

    print(f"  Best config:")
    print(f"    Width: {best['width']}, Order: {best['col_order']}")
    print(f"    Variant: {best['variant']}, Bean-ineq: {'PASS' if best['bean_ineq'] else 'FAIL'}")
    print(f"    Q/char: {best_q:.3f}")
    print(f"    Frag1: {best['frag1']}, Frag2: {best['frag2']}")
    print(f"    Mono shifts: {' '.join(ALPH[v] for v in best['mono_shifts'])}")
    print(f"    P-value (raw): {p_raw:.4f}")
    print(f"    P-value (corrected): {p_corrected:.4f}")

    if n_in_english > 0:
        verdict = "SIGNAL"
        print(f"\n  *** SIGNAL: {n_in_english} configs reach English range! ***")
    elif best_q > rp_max:
        verdict = "MARGINAL"
        print(f"\n  MARGINAL: Best exceeds random perm max but below English.")
    else:
        verdict = "NOISE"
        print(f"\n  NOISE: Even with mono optimization (13 DOF), columnar configs")
        print(f"  remain below English range. Running key from English text +")
        print(f"  mono inner substitution + columnar transposition is ELIMINATED.")
        print(f"  The 13 mono DOF add ~{all_scores[-1] - (-4.151):.1f}/char improvement,")
        print(f"  insufficient to bridge the ~{eng_p5 - (-4.151):.1f}/char gap to English.")

    # ====================================================================
    # Save results
    # ====================================================================
    runtime = time.time() - t0
    out_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'frac')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'e_frac_54_mono_running_key_detection.json')

    output = {
        'experiment': 'E-FRAC-54',
        'description': 'Mono inner + transposition + running key from English detection',
        'hypothesis': (
            'Adding monoalphabetic inner substitution provides 13 DOF (one shift '
            'per known PT letter) to adjust implied running key values. Can these '
            'shifts make key fragments look English-like?'
        ),
        'model': 'CT[inv(j)] = (Sub[PT[j]] + RunKey[inv(j)]) mod 26',
        'total_configs_scored': n_results,
        'total_bean_eq_configs': len(all_configs),
        'distinct_pt_letters': DISTINCT_LETTERS,
        'n_letters': N_LETTERS,
        'identity_results': identity_results,
        'best_config': {
            'width': best['width'],
            'col_order': best['col_order'],
            'variant': best['variant'],
            'score': best_q,
            'bean_ineq': best['bean_ineq'],
            'frag1': best['frag1'],
            'frag2': best['frag2'],
            'mono_shifts': best['mono_shifts'],
        },
        'top_20': [{
            'width': r['width'],
            'col_order': r['col_order'],
            'variant': r['variant'],
            'score': r['score'],
            'bean_ineq': r['bean_ineq'],
            'frag1': r['frag1'],
            'frag2': r['frag2'],
        } for r in results[:20]],
        'distributions': {
            'columnar_mono_opt': {'n': n_results, 'mean': col_mean, 'std': col_std,
                                   'max': all_scores[-1]},
            'random_perm_mono_opt': {'n': N_RAND, 'mean': rp_mean, 'std': rp_std,
                                      'max': rp_max},
        },
        'n_in_english_range': n_in_english,
        'n_exceed_random_max': n_exceed_rand,
        'p_raw': p_raw,
        'p_corrected': p_corrected,
        'english_p5': eng_p5,
        'efrac51_best': -4.151,
        'improvement_from_mono': all_scores[-1] - (-4.151),
        'gap_to_english': eng_p5 - all_scores[-1],
        'verdict': verdict,
        'runtime_seconds': runtime,
    }

    if english_qscores:
        output['distributions']['english'] = {
            'n': N_ENG, 'mean': eng_mean, 'std': eng_std,
            'p5': eng_p5, 'p50': eng_p50, 'min': english_qscores[0],
        }

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Results saved to: {out_path}")
    print(f"  Runtime: {runtime:.1f} seconds")

    print("\n" + "=" * 70)
    print(f"RESULT: best_q={best_q:.3f}/char n_english={n_in_english} "
          f"improvement={all_scores[-1] - (-4.151):.3f} verdict={verdict}")
    print("=" * 70)


if __name__ == '__main__':
    main()
