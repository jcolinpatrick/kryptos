#!/usr/bin/env python3
"""E-FRAC-49: Running Key + Structured Columnar Transposition (DEFINITIVE TEST)

HYPOTHESIS: Does any combination of columnar transposition ordering (widths 6, 8, 9)
and running key offset from known reference texts produce 24/24 crib matches?

GAP FILLED: Prior experiments tested:
  - Columnar + PERIODIC keys → noise (E-FRAC-12/29/30)
  - Running key + ARBITRARY transpositions → underdetermined (E-FRAC-39)
  - But running key + STRUCTURED columnar has NEVER been tested.

Information theory predicts ZERO false positives for structured families:
  362K orderings (2^18.5) × P(24/24) ≈ 10^-34 → expected FP = 0 (E-FRAC-44)
  Any match would be a REAL discovery, not a false positive.

Method:
  For each Bean-compatible columnar ordering σ at widths 6, 8, 9:
    1. Compute inverse permutation σ⁻¹
    2. Check Bean equality: CT[σ⁻¹(27)] == CT[σ⁻¹(65)]
    3. For each crib position j, compute required key: K[j] = f(CT[σ⁻¹(j)], PT[j], variant)
    4. Check Bean inequalities (all crib-crib pairs): required_key[a] ≠ required_key[b]
    5. Scan each reference text for offsets matching all 24 required key values
    6. For any 24/24 hit: compute full plaintext, score quality metrics

  Test both Vigenère and Beaufort variants.
"""
import json
import math
import os
import sys
import time
import numpy as np
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_ENTRIES, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
)

# Convert constants to numpy arrays
CT_NUM = np.array([ALPH_IDX[c] for c in CT], dtype=np.int8)
N = CT_LEN  # 97

# Crib data
CRIB_POS = np.array([pos for pos, _ in CRIB_ENTRIES], dtype=np.int32)
CRIB_PT = np.array([ALPH_IDX[ch] for _, ch in CRIB_ENTRIES], dtype=np.int8)

# Bean constraint positions (all are crib positions)
BEAN_EQ_PAIRS = list(BEAN_EQ)
BEAN_INEQ_PAIRS = list(BEAN_INEQ)


def generate_columnar_perm(width, col_order):
    """Generate the permutation for columnar transposition.

    Convention: CT[i] = intermediate[perm[i]] (gather).
    Columnar writes plaintext row-by-row, reads column-by-column.

    The permutation maps CT position → intermediate position.
    """
    n = N
    nrows = (n + width - 1) // width
    full_cols = n - (nrows - 1) * width  # columns with nrows entries

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
    """Compute inverse permutation. inv_perm[perm[i]] = i."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def compute_required_key(inv_perm, variant):
    """Compute required key values at all 24 crib positions.

    Given transposition σ with inverse σ⁻¹:
      intermediate[j] = CT[σ⁻¹(j)] = CT[inv_perm[j]]
      Vigenère: intermediate[j] = (PT[j] + K[j]) mod 26
        → K[j] = (CT[inv_perm[j]] - PT[j]) mod 26
      Beaufort: intermediate[j] = (K[j] - PT[j]) mod 26
        → K[j] = (CT[inv_perm[j]] + PT[j]) mod 26
    """
    required = {}
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
        required[pos] = int(key_val)
    return required


def check_bean_transposition(inv_perm):
    """Check Bean equality constraint on the transposition.
    CT[inv_perm[27]] must equal CT[inv_perm[65]].
    """
    for eq_a, eq_b in BEAN_EQ_PAIRS:
        if CT_NUM[inv_perm[eq_a]] != CT_NUM[inv_perm[eq_b]]:
            return False
    return True


def check_bean_ineq_on_key(required_key):
    """Check Bean inequalities on the derived key values.
    All Bean inequality positions are crib positions, so all values are known.
    """
    for a, b in BEAN_INEQ_PAIRS:
        if required_key.get(a) is not None and required_key.get(b) is not None:
            if required_key[a] == required_key[b]:
                return False
    return True


def load_text_as_nums(filepath):
    """Load text file, extract alpha characters, convert to numpy int8 array."""
    with open(filepath, 'r', errors='replace') as f:
        raw = f.read().upper()
    nums = [ALPH_IDX[c] for c in raw if c in ALPH_IDX]
    return np.array(nums, dtype=np.int8)


def scan_text_for_matches(source, crib_positions, required_values):
    """Scan source text for offsets where source[offset + pos] == val for all 24 cribs.

    Uses numpy vectorization with progressive filtering for efficiency.
    Returns list of matching offsets.
    """
    n_offsets = len(source) - N + 1
    if n_offsets <= 0:
        return []

    # Progressive filtering: check each position, eliminating non-matches early
    mask = np.ones(n_offsets, dtype=bool)

    # Sort by position to be cache-friendly (positions are already sorted in cribs)
    for pos, val in zip(crib_positions, required_values):
        mask &= (source[pos:pos + n_offsets] == val)
        if not mask.any():
            return []

    return np.where(mask)[0].tolist()


def derive_plaintext(source, offset, inv_perm, variant):
    """Derive the full 97-character plaintext given a source text offset and transposition.

    K[j] = source[offset + j]
    intermediate[j] = CT[inv_perm[j]]
    Vigenère: PT[j] = (intermediate[j] - K[j]) mod 26
    Beaufort: PT[j] = (K[j] - intermediate[j]) mod 26
    """
    pt = []
    for j in range(N):
        key_val = int(source[offset + j])
        ct_val = int(CT_NUM[inv_perm[j]])
        if variant == 'vigenere':
            pt_val = (ct_val - key_val) % MOD
        elif variant == 'beaufort':
            pt_val = (key_val - ct_val) % MOD
        elif variant == 'variant_beaufort':
            pt_val = (ct_val + key_val) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        pt.append(chr(pt_val + ord('A')))
    return ''.join(pt)


def compute_quadgram_score(text, quadgrams):
    """Compute quadgram log-probability score per character."""
    if len(text) < 4:
        return -10.0
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += quadgrams.get(qg, -10.0)
        count += 1
    return total / count if count > 0 else -10.0


def compute_ic(text):
    """Compute index of coincidence."""
    from collections import Counter
    counts = Counter(text)
    n = len(text)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def main():
    t_start = time.time()
    print("=" * 70)
    print("E-FRAC-49: Running Key + Structured Columnar Transposition")
    print("=" * 70)

    # Load quadgrams for quality scoring (in case of hits)
    quadgrams = {}
    qg_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            quadgrams = json.load(f)
        print(f"Loaded {len(quadgrams)} quadgrams")

    # Reference texts
    ref_dir = os.path.join(os.path.dirname(__file__), '..', 'reference')
    rk_dir = os.path.join(ref_dir, 'running_key_texts')

    text_files = [
        ('Carter Gutenberg', os.path.join(ref_dir, 'carter_gutenberg.txt')),
        ('Carter Vol1', os.path.join(ref_dir, 'carter_vol1_extract.txt')),
        ('CIA Charter', os.path.join(rk_dir, 'cia_charter.txt')),
        ('JFK Berlin', os.path.join(rk_dir, 'jfk_berlin.txt')),
        ('NSA Act 1947', os.path.join(rk_dir, 'nsa_act_1947.txt')),
        ('Reagan Berlin', os.path.join(rk_dir, 'reagan_berlin.txt')),
        ('UDHR', os.path.join(rk_dir, 'udhr.txt')),
    ]

    # Load texts
    texts = {}
    for name, path in text_files:
        if os.path.exists(path):
            nums = load_text_as_nums(path)
            texts[name] = nums
            print(f"  {name}: {len(nums)} alpha chars, {len(nums) - N + 1} possible offsets")
        else:
            print(f"  {name}: FILE NOT FOUND at {path}")

    print()

    # Widths to test (Bean-compatible, exhaustive)
    widths = [6, 8, 9]
    variants = ['vigenere', 'beaufort', 'variant_beaufort']

    results = {
        'experiment': 'E-FRAC-49',
        'description': 'Running key + structured columnar transposition',
        'widths': widths,
        'variants': variants,
        'texts': {name: len(nums) for name, nums in texts.items()},
        'width_results': {},
        'total_orderings_tested': 0,
        'total_bean_passing': 0,
        'total_text_scans': 0,
        'total_hits': 0,
        'hits': [],
    }

    grand_total_orderings = 0
    grand_total_bean = 0
    grand_total_scans = 0

    for width in widths:
        print(f"\n{'='*60}")
        print(f"WIDTH {width}: {math.factorial(width)} total orderings")
        print(f"{'='*60}")

        t_width_start = time.time()

        width_result = {
            'width': width,
            'total_orderings': int(math.factorial(width)),
            'bean_eq_pass': 0,
            'bean_full_pass': 0,
            'text_scans': 0,
            'per_text_hits': {},
        }

        bean_passing_orderings = []

        # Phase 1: Generate all orderings, filter by Bean constraints
        print(f"\nPhase 1: Generating and filtering orderings by Bean constraints...")
        n_orderings = 0
        for col_order in permutations(range(width)):
            n_orderings += 1
            perm = generate_columnar_perm(width, list(col_order))
            inv = invert_perm(perm)

            # Check Bean equality on transposition
            if not check_bean_transposition(inv):
                continue

            width_result['bean_eq_pass'] += 1

            # Check both variants
            for variant in variants:
                required_key = compute_required_key(inv, variant)

                # Check Bean inequalities on derived key values
                if not check_bean_ineq_on_key(required_key):
                    continue

                width_result['bean_full_pass'] += 1
                bean_passing_orderings.append((list(col_order), perm, inv, variant, required_key))

        print(f"  Orderings tested: {n_orderings}")
        print(f"  Bean equality pass: {width_result['bean_eq_pass']}")
        print(f"  Bean full pass (both variants): {width_result['bean_full_pass']}")
        print(f"  Bean-passing (ordering, variant) configs: {len(bean_passing_orderings)}")

        grand_total_orderings += n_orderings

        # Phase 2: Scan reference texts
        print(f"\nPhase 2: Scanning {len(texts)} reference texts...")

        for text_name, source in texts.items():
            n_offsets = len(source) - N + 1
            if n_offsets <= 0:
                print(f"  {text_name}: too short, skipping")
                continue

            text_hits = []

            for col_order, perm, inv, variant, required_key in bean_passing_orderings:
                # Build position-value pairs for scanning
                positions = np.array(sorted(required_key.keys()), dtype=np.int32)
                values = np.array([required_key[p] for p in positions], dtype=np.int8)

                # Scan source text
                hits = scan_text_for_matches(source, positions, values)
                grand_total_scans += 1
                width_result['text_scans'] += 1

                for offset in hits:
                    # MATCH FOUND — this is significant!
                    pt = derive_plaintext(source, offset, inv, variant)
                    qg = compute_quadgram_score(pt, quadgrams) if quadgrams else -99.0
                    ic = compute_ic(pt)

                    hit = {
                        'width': width,
                        'col_order': col_order,
                        'variant': variant,
                        'text': text_name,
                        'offset': offset,
                        'plaintext': pt,
                        'quadgram_per_char': round(qg, 4),
                        'ic': round(ic, 4),
                        'crib_check_ENE': pt[21:34],
                        'crib_check_BC': pt[63:74],
                    }
                    text_hits.append(hit)
                    results['hits'].append(hit)
                    results['total_hits'] += 1

                    print(f"\n  *** MATCH FOUND ***")
                    print(f"  Width: {width}, Order: {col_order}, Variant: {variant}")
                    print(f"  Text: {text_name}, Offset: {offset}")
                    print(f"  Plaintext: {pt}")
                    print(f"  Quadgram/char: {qg:.4f}")
                    print(f"  IC: {ic:.4f}")
                    print(f"  ENE region: {pt[21:34]}")
                    print(f"  BC region:  {pt[63:74]}")

            width_result['per_text_hits'][text_name] = len(text_hits)
            if not text_hits:
                pass  # No hits, expected

        grand_total_bean += len(bean_passing_orderings)

        t_width_elapsed = time.time() - t_width_start
        width_result['runtime_seconds'] = round(t_width_elapsed, 1)
        results['width_results'][str(width)] = width_result

        print(f"\n  Width {width} complete in {t_width_elapsed:.1f}s")
        print(f"  Bean-passing configs scanned: {len(bean_passing_orderings)}")
        print(f"  Text scans performed: {width_result['text_scans']}")
        hits_at_width = sum(width_result['per_text_hits'].values())
        print(f"  Hits found: {hits_at_width}")

    # Summary
    t_total = time.time() - t_start
    results['total_orderings_tested'] = grand_total_orderings
    results['total_bean_passing'] = grand_total_bean
    results['total_text_scans'] = grand_total_scans
    results['runtime_seconds'] = round(t_total, 1)

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Widths tested: {widths}")
    print(f"Total orderings: {grand_total_orderings}")
    print(f"Bean-passing (ordering × variant): {grand_total_bean}")
    print(f"Text scans performed: {grand_total_scans}")
    print(f"Reference texts: {len(texts)} ({sum(len(t) for t in texts.values())} total chars)")
    print(f"Total hits: {results['total_hits']}")
    print(f"Runtime: {t_total:.1f}s")

    # Information-theoretic context
    total_checks = grand_total_bean * sum(len(source) - N + 1 for source in texts.values())
    prob_per_check = (1.0 / 26) ** 24
    expected_fp = total_checks * prob_per_check
    print(f"\nInformation-theoretic context:")
    print(f"  Total (ordering × variant × offset) checks: {total_checks:,.0f}")
    print(f"  P(random match) per check: {prob_per_check:.2e}")
    print(f"  Expected false positives: {expected_fp:.2e}")

    if results['total_hits'] == 0:
        print(f"\nVERDICT: ELIMINATED — running key from {len(texts)} reference texts + "
              f"columnar widths {widths} produces ZERO 24/24 matches.")
        print(f"Combined with E-FRAC-12/29/30 (periodic keys) and E-FRAC-39 (arbitrary transpositions),")
        print(f"columnar transposition + running key from known texts is COMPREHENSIVELY ELIMINATED.")
        results['verdict'] = 'ELIMINATED'
    else:
        print(f"\n*** {results['total_hits']} HITS FOUND — REQUIRES IMMEDIATE ANALYSIS ***")
        results['verdict'] = 'SIGNAL' if any(h['quadgram_per_char'] > -5.0 for h in results['hits']) else 'NOISE_HITS'

    print(f"\nRESULT: best={'24/24' if results['total_hits'] > 0 else '0/24'} "
          f"configs={grand_total_bean} verdict={results['verdict']}")

    # Save results
    out_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'frac')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'e_frac_49_running_key_columnar.json')
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
