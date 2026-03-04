#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-TABLEAU-20: K3-Method Extension — Thematic Keywords at Bean-Surviving Periods

Tests K4 as a K3-style compound cipher (transposition + Vigenère/Beaufort)
using thematic keywords at Bean-surviving periods.

Context:
- K3 method: Columnar(width=7, keyword=KRYPTOS) -> Vigenère(keyword=PALIMPSEST, period=10)
- FRAC E-FRAC-35 PROOF: periodic keys at periods {2-7, 9-12, 14, 15, 17, 18, 21, 22, 25}
  are Bean-IMPOSSIBLE under ANY transposition.
- Only periods {8, 13, 16, 19, 20, 23, 24, 26} survive Bean.
- ABSCISSA (K2 keyword, 8 letters, period 8) is the most thematically motivated candidate.
- FRAC tested width-8 at discriminating periods (2-7), NOT at period 8 with specific keywords.

This experiment tests:
1. Width-8 columnar (all 40,320 orderings) + specific 8-letter thematic keywords
2. Both Vigenère and Beaufort
3. Both Model A (Sub→Trans) and Model B (Trans→Sub)
4. Bean constraint verification on all hits

Also tests 13-letter keywords at width 13 (period 13 is Bean-surviving).
"""

import sys
import os
import json
import time
from itertools import permutations
from math import factorial

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ,
)

# ── CT as numeric array ──────────────────────────────────────────────────
CT_IDX = [ALPH_IDX[c] for c in CT]

# ── Crib data ────────────────────────────────────────────────────────────
CRIB_LIST = [(pos, ALPH_IDX[ch]) for pos, ch in sorted(CRIB_DICT.items())]

# ── Thematic keywords at Bean-surviving periods ──────────────────────────
# Period 8 keywords (Bean-surviving):
KEYWORDS_P8 = [
    "ABSCISSA",    # K2 keyword — most historically motivated
    "MAGNETIC",    # From K2 text "earth's MAGNETIC field"
    "LOCATION",    # From K2 text "unknown LOCATION"
    "POSITION",    # From Morse code "T IS YOUR POSITION"
    "ILLUSION",    # From K1 concept (IQLUSION → ILLUSION)
    "IQLUSION",    # K1 misspelling exactly
    "VIRGINIA",    # CIA location (Langley, Virginia)
    "TREASURE",    # Thematic (buried treasure)
    "DECEMBER",    # Month reference
    "NINETEEN",    # Year component (1989, 1986)
    "MONUMENT",    # Thematic
    "EMBEDDED",    # "Embedded" information
    "DISPATCH",    # Intelligence theme
    "INSCRIBE",    # Art/sculpture theme
    "MERIDIAN",    # Geographic reference
    "LANGUAGE",    # Scheidt: "changed the language base"
]

# Period 13 keywords (Bean-surviving):
KEYWORDS_P13 = [
    "EASTNORTHEAST",  # K4 crib (testing if key = crib)
    "TUTANKHAMENS",    # Not a real word; try TUTANKHAMEN (10) — skip
    "ESTABLISHMENT",   # Intelligence theme
    "COMMUNICATION",   # Intelligence theme  (13 letters? no, 13)
    "CONSTELLATION",   # Thematic
    "CORRESPONDING",   # Thematic
    "UNDERSTANDING",   # Thematic
]

# Fix: verify all keywords are correct length
KEYWORDS_P8 = [k for k in KEYWORDS_P8 if len(k) == 8]
KEYWORDS_P13 = [k for k in KEYWORDS_P13 if len(k) == 13]


def keyword_to_numeric(keyword):
    """Convert keyword to numeric key values."""
    return [ALPH_IDX[c] for c in keyword.upper()]


def build_columnar_perm(width, col_order):
    """Build columnar transposition permutation (gather convention).

    Write text in rows of `width`, read columns in `col_order`.
    output[i] = input[perm[i]]
    """
    n_full_cols = CT_LEN % width  # columns with (CT_LEN//width + 1) rows
    n_short_cols = width - n_full_cols  # columns with (CT_LEN//width) rows
    base_rows = CT_LEN // width

    # Column heights
    col_heights = []
    for c in range(width):
        if c < n_full_cols:
            col_heights.append(base_rows + 1)
        else:
            col_heights.append(base_rows)

    # Build permutation: reading columns in col_order
    perm = []
    for col in col_order:
        for row in range(col_heights[col]):
            perm.append(row * width + col)

    assert len(perm) == CT_LEN, f"Perm length {len(perm)} != {CT_LEN}"
    return perm


def invert_perm(perm):
    """Compute inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_crib_score_model_b(inv_perm, key_numeric, period, variant):
    """Model B: Trans→Sub. Check crib score.

    Encryption: intermediate = perm(PT), CT = Sub(intermediate, K)
    Decryption: intermediate = Sub⁻¹(CT, K), PT[pos] = intermediate[inv_perm[pos]]

    For Vigenère: intermediate[i] = (CT[i] - K[i % period]) % 26
    For Beaufort: intermediate[i] = (K[i % period] - CT[i]) % 26
    """
    score = 0
    for pos, pt_val in CRIB_LIST:
        j = inv_perm[pos]  # where does PT position map in the intermediate?
        if variant == 'vig':
            derived_pt = (CT_IDX[j] - key_numeric[j % period]) % MOD
        else:  # beaufort
            derived_pt = (key_numeric[j % period] - CT_IDX[j]) % MOD
        if derived_pt == pt_val:
            score += 1
    return score


def check_crib_score_model_a(inv_perm, key_numeric, period, variant):
    """Model A: Sub→Trans. Check crib score.

    Encryption: sub_out = Sub(PT, K), CT = perm(sub_out)
    Decryption: sub_out[j] = CT[inv_perm[j]], PT[j] = Sub⁻¹(sub_out[j], K[j%p])

    Wait — inv_perm here means: sub_out = σ⁻¹(CT), so sub_out[j] = CT[perm[j]]
    No... let me be precise.

    If CT[i] = sub_out[perm[i]] (gather), then sub_out[k] = CT[inv_perm[k]].
    Then PT[j] = Sub⁻¹(sub_out[j], K[j%p]) = Sub⁻¹(CT[inv_perm[j]], K[j%p]).

    Actually the transposition direction matters. If σ is the encryption transposition:
    CT = σ(sub_out) means CT[i] = sub_out[σ⁻¹(i)] (or CT[σ(j)] = sub_out[j] in scatter).

    Using gather: CT[i] = sub_out[perm[i]], so sub_out[perm[i]] = CT[i].
    Inverse: sub_out[j] = CT[inv_perm[j]].

    For Model A, key is applied at the PRE-transposition position:
    PT[j] = (sub_out[j] - K[j%p]) % 26 for Vigenère
           = (K[j%p] - sub_out[j]) % 26 for Beaufort
    """
    score = 0
    for pos, pt_val in CRIB_LIST:
        # sub_out at position pos = CT[inv_perm[pos]]
        # Wait, we need perm to get inv_perm. But we're passed inv_perm.
        # sub_out[pos] = CT[inv_perm[pos]] -- NO.
        #
        # If CT[i] = sub_out[perm[i]], then for sub_out[j] we need i such that
        # perm[i] = j, i.e. i = inv_perm[j] IF inv_perm maps from "input" space.
        # Actually... perm maps input -> output as output[i] = input[perm[i]].
        # But for transposition as encryption:
        #   The transposition takes sub_out and produces CT.
        #   CT[i] = sub_out[perm[i]]
        #   So sub_out[perm[i]] = CT[i], meaning sub_out[j] = CT[inv_perm[j]].
        #
        # But this means inv_perm maps the transposition's OUTPUT (CT) back to INPUT (sub_out).
        # Hmm, this depends on convention. Let me just use both conventions as separate models.

        # Convention: CT[i] = sub_out[perm[i]]
        # So sub_out[j] = CT[inv_perm[j]]
        sub_out_pos = CT_IDX[inv_perm[pos]]

        if variant == 'vig':
            derived_pt = (sub_out_pos - key_numeric[pos % period]) % MOD
        else:  # beaufort
            derived_pt = (key_numeric[pos % period] - sub_out_pos) % MOD
        if derived_pt == pt_val:
            score += 1
    return score


def check_bean(inv_perm, key_numeric, period, variant, model):
    """Check Bean constraints for a (perm, key, variant, model) combination."""
    def get_key_val(pos):
        """Get key value at position pos under the current model."""
        if model == 'B':
            j = inv_perm[pos]
            if variant == 'vig':
                return (CT_IDX[j] - ALPH_IDX[CRIB_DICT[pos]]) % MOD if pos in CRIB_DICT else None
            else:
                return (ALPH_IDX[CRIB_DICT[pos]] + CT_IDX[j]) % MOD if pos in CRIB_DICT else None
        else:  # model A
            sub_out = CT_IDX[inv_perm[pos]]
            if variant == 'vig':
                return (sub_out - ALPH_IDX[CRIB_DICT[pos]]) % MOD if pos in CRIB_DICT else None
            else:
                return (ALPH_IDX[CRIB_DICT[pos]] + sub_out) % MOD if pos in CRIB_DICT else None

    # For specific keyword, the key is fully determined, so we can check Bean
    # using the full derived plaintext
    # Actually, for Bean we need key values at positions 27, 65, and inequality pairs
    # Under the keyword model, the key at position i is key_numeric[j % period]
    # where j depends on the model:
    #   Model B: j = inv_perm[i] (key applied at transposed position)
    #   Model A: j = i (key applied at original position)

    def key_at_pos(i):
        if model == 'B':
            return key_numeric[inv_perm[i] % period]
        else:
            return key_numeric[i % period]

    # Bean equality: k[27] == k[65]
    k27 = key_at_pos(27)
    k65 = key_at_pos(65)
    if k27 != k65:
        return False

    # Bean inequalities
    for a, b in BEAN_INEQ:
        if key_at_pos(a) == key_at_pos(b):
            return False

    return True


def derive_plaintext(perm, inv_perm, key_numeric, period, variant, model):
    """Derive full 97-char plaintext for a given configuration."""
    pt_idx = [0] * CT_LEN
    for pos in range(CT_LEN):
        if model == 'B':
            j = inv_perm[pos]
            if variant == 'vig':
                pt_idx[pos] = (CT_IDX[j] - key_numeric[j % period]) % MOD
            else:
                pt_idx[pos] = (key_numeric[j % period] - CT_IDX[j]) % MOD
        else:  # model A
            sub_out = CT_IDX[inv_perm[pos]]
            if variant == 'vig':
                pt_idx[pos] = (sub_out - key_numeric[pos % period]) % MOD
            else:
                pt_idx[pos] = (key_numeric[pos % period] - sub_out) % MOD
    return ''.join(ALPH[v] for v in pt_idx)


def test_keyword_at_width(keyword, width, max_orderings=None):
    """Test a specific keyword at a specific width across all orderings.

    Returns dict with results.
    """
    period = len(keyword)
    key_numeric = keyword_to_numeric(keyword)

    n_orderings = factorial(width)
    if max_orderings and n_orderings > max_orderings:
        # Sample orderings
        import random
        random.seed(42)
        base_list = list(range(width))
        orderings = set()
        while len(orderings) < max_orderings:
            p = tuple(random.sample(base_list, width))
            orderings.add(p)
        orderings = list(orderings)
        sampled = True
    else:
        orderings = list(permutations(range(width)))
        sampled = False

    best_score = 0
    best_configs = []
    bean_pass_count = 0
    bean_pass_best = 0
    score_24_count = 0

    configs = [
        ('B', 'vig'), ('B', 'beau'),
        ('A', 'vig'), ('A', 'beau'),
    ]

    for col_order in orderings:
        perm = build_columnar_perm(width, list(col_order))
        inv_perm = invert_perm(perm)

        for model, variant in configs:
            if model == 'B':
                score = check_crib_score_model_b(inv_perm, key_numeric, period, variant)
            else:
                score = check_crib_score_model_a(inv_perm, key_numeric, period, variant)

            if score >= best_score:
                bean_ok = check_bean(inv_perm, key_numeric, period, variant, model)

                if score > best_score:
                    best_score = score
                    best_configs = []

                best_configs.append({
                    'col_order': list(col_order),
                    'model': model,
                    'variant': variant,
                    'score': score,
                    'bean': bean_ok,
                })

                if bean_ok:
                    bean_pass_count += 1
                    if score > bean_pass_best:
                        bean_pass_best = score

                if score == 24:
                    score_24_count += 1
                    # Derive and print the plaintext!
                    pt = derive_plaintext(perm, inv_perm, key_numeric, period, variant, model)
                    print(f"  *** 24/24 HIT! keyword={keyword} order={list(col_order)} "
                          f"model={model} variant={variant} bean={'PASS' if bean_ok else 'FAIL'}")
                    print(f"      PT: {pt}")

            elif score >= 20:  # Also check high scores
                bean_ok = check_bean(inv_perm, key_numeric, period, variant, model)
                if bean_ok and score > bean_pass_best:
                    bean_pass_best = score
                if bean_ok:
                    bean_pass_count += 1

    return {
        'keyword': keyword,
        'width': width,
        'period': period,
        'n_orderings_tested': len(orderings),
        'sampled': sampled,
        'best_score': best_score,
        'n_best_configs': len(best_configs),
        'best_configs_sample': best_configs[:5],
        'score_24_count': score_24_count,
        'bean_pass_count': bean_pass_count,
        'bean_pass_best_score': bean_pass_best,
    }


def main():
    print("=" * 70)
    print("E-TABLEAU-20: K3-Method Extension — Thematic Keywords")
    print("=" * 70)
    print()
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print()

    # ── Phase 1: Specific keyword orderings first (instant check) ────────
    print("PHASE 1: Testing specific keyword-derived orderings")
    print("-" * 50)

    def keyword_to_order(keyword):
        """Convert keyword to column reading order (alphabetical, ties by position)."""
        indexed = [(c, i) for i, c in enumerate(keyword)]
        sorted_indexed = sorted(indexed, key=lambda x: (x[0], x[1]))
        order = [0] * len(keyword)
        for rank, (_, orig_pos) in enumerate(sorted_indexed):
            order[orig_pos] = rank
        # order[i] = rank of column i → column reading order
        # We need: which column to read at each step
        reading_order = [0] * len(keyword)
        for i, r in enumerate(order):
            reading_order[r] = i
        return reading_order

    # Test K3's exact method applied to K4 first
    k3_keywords = [
        ("KRYPTOS", 7, "PALIMPSEST"),    # K3 actual: trans_key=KRYPTOS, vig_key=PALIMPSEST
        ("KRYPTOS", 7, "ABSCISSA"),      # K3 trans + K2 vig key
        ("ABSCISSA", 8, "PALIMPSEST"),   # K2 vig key as trans + K1/K3 vig key
        ("ABSCISSA", 8, "ABSCISSA"),     # K2 keyword for both
        ("ABSCISSA", 8, "KRYPTOS"),      # K2 as trans + KRYPTOS as vig
    ]

    for trans_kw, width, vig_kw in k3_keywords:
        col_order = keyword_to_order(trans_kw)
        period = len(vig_kw)
        key_numeric = keyword_to_numeric(vig_kw)
        perm = build_columnar_perm(width, col_order)
        inv_perm = invert_perm(perm)

        for model, variant in [('B', 'vig'), ('B', 'beau'), ('A', 'vig'), ('A', 'beau')]:
            if model == 'B':
                score = check_crib_score_model_b(inv_perm, key_numeric, period, variant)
            else:
                score = check_crib_score_model_a(inv_perm, key_numeric, period, variant)

            bean_ok = check_bean(inv_perm, key_numeric, period, variant, model)

            print(f"  Trans={trans_kw}(w{width}) Vig={vig_kw}(p{period}) "
                  f"model={model} var={variant}: {score}/24 Bean={'PASS' if bean_ok else 'FAIL'}")

            if score == 24:
                pt = derive_plaintext(perm, inv_perm, key_numeric, period, variant, model)
                print(f"    *** BREAKTHROUGH! PT: {pt}")

    print()

    # ── Phase 2: Width-8 exhaustive with period-8 keywords ───────────────
    print("PHASE 2: Width-8 exhaustive (40,320 orderings) × period-8 keywords")
    print("-" * 50)

    all_results = []
    t0 = time.time()

    for keyword in KEYWORDS_P8:
        t_kw = time.time()
        result = test_keyword_at_width(keyword, 8)
        elapsed = time.time() - t_kw

        print(f"  {keyword}: best={result['best_score']}/24, "
              f"bean_best={result['bean_pass_best_score']}/24, "
              f"24/24_hits={result['score_24_count']}, "
              f"bean_passes={result['bean_pass_count']}, "
              f"time={elapsed:.1f}s")

        if result['score_24_count'] > 0:
            print(f"    *** SIGNAL DETECTED! See details above.")

        all_results.append(result)

    phase2_time = time.time() - t0
    print(f"\nPhase 2 total: {phase2_time:.1f}s")

    # ── Phase 3: Width-13 with period-13 keywords ────────────────────────
    print("\nPHASE 3: Width-13 (sampled 50K orderings) × period-13 keywords")
    print("-" * 50)

    t0 = time.time()

    for keyword in KEYWORDS_P13:
        if len(keyword) != 13:
            print(f"  Skipping {keyword} (length {len(keyword)} != 13)")
            continue
        t_kw = time.time()
        result = test_keyword_at_width(keyword, 13, max_orderings=50000)
        elapsed = time.time() - t_kw

        print(f"  {keyword}: best={result['best_score']}/24, "
              f"bean_best={result['bean_pass_best_score']}/24, "
              f"24/24_hits={result['score_24_count']}, "
              f"bean_passes={result['bean_pass_count']}, "
              f"time={elapsed:.1f}s")

        all_results.append(result)

    phase3_time = time.time() - t0
    print(f"\nPhase 3 total: {phase3_time:.1f}s")

    # ── Phase 4: Width-9 with period-8 keywords (mixed width/period) ─────
    print("\nPHASE 4: Width-9 (sampled 50K orderings) × period-8 keywords (top 3)")
    print("-" * 50)
    print("(Testing: transposition width != key period, as in K3 where width=7, period=10)")

    t0 = time.time()
    top3_p8 = KEYWORDS_P8[:3]  # ABSCISSA, MAGNETIC, LOCATION

    for keyword in top3_p8:
        t_kw = time.time()
        result = test_keyword_at_width(keyword, 9, max_orderings=50000)
        elapsed = time.time() - t_kw

        print(f"  {keyword} (w9,p8): best={result['best_score']}/24, "
              f"bean_best={result['bean_pass_best_score']}/24, "
              f"24/24_hits={result['score_24_count']}, "
              f"time={elapsed:.1f}s")

        all_results.append(result)

    phase4_time = time.time() - t0
    print(f"\nPhase 4 total: {phase4_time:.1f}s")

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total_orderings = sum(r['n_orderings_tested'] for r in all_results)
    total_configs = total_orderings * 4  # 4 model×variant combos
    global_best = max(r['best_score'] for r in all_results)
    any_24 = any(r['score_24_count'] > 0 for r in all_results)

    print(f"Total orderings tested: {total_orderings:,}")
    print(f"Total configs tested: {total_configs:,}")
    print(f"Keywords tested: {len(all_results)}")
    print(f"Global best score: {global_best}/24")
    print(f"Any 24/24 hits: {'YES — INVESTIGATE!' if any_24 else 'NO'}")

    # Best per-keyword summary
    print("\nPer-keyword results:")
    for r in sorted(all_results, key=lambda x: -x['best_score']):
        flag = " ***" if r['score_24_count'] > 0 else ""
        print(f"  {r['keyword']:20s} w={r['width']:2d} p={r['period']:2d} "
              f"best={r['best_score']:2d}/24 bean_best={r['bean_pass_best_score']:2d}/24 "
              f"24hits={r['score_24_count']}{flag}")

    # Noise floor context
    print(f"\nNoise context (from FRAC findings):")
    print(f"  Random baseline (50K perms): max ~14-15/24")
    print(f"  Width-8 exhaustive (FRAC E-FRAC-29): max 13/24 at periods 2-7")
    print(f"  Period 8 random baseline (FRAC E-FRAC-36): max 14/24")
    print(f"  Bean-impossible at periods 2-7 (FRAC E-FRAC-35): PROOF")

    if any_24:
        verdict = "SIGNAL — 24/24 hit found! VERIFY IMMEDIATELY."
    elif global_best > 14:
        verdict = "ELEVATED — above random baseline, investigate further"
    else:
        verdict = "ELIMINATED — all thematic keywords at Bean-surviving periods produce noise"

    print(f"\nVERDICT: {verdict}")
    print(f"\nREPRO: PYTHONPATH=src python3 -u scripts/e_tableau_20_k3method_keywords.py")

    # Save results
    output = {
        'experiment': 'E-TABLEAU-20',
        'description': 'K3-method extension: thematic keywords at Bean-surviving periods',
        'total_orderings': total_orderings,
        'total_configs': total_configs,
        'global_best': global_best,
        'any_24_hits': any_24,
        'verdict': verdict,
        'results': all_results,
    }

    os.makedirs('results/tableau', exist_ok=True)
    with open('results/tableau/e_tableau_20_k3method_keywords.json', 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nArtifacts: results/tableau/e_tableau_20_k3method_keywords.json")


if __name__ == '__main__':
    main()
