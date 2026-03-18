#!/usr/bin/env python3
"""Secondary filtering of all 396 masks scoring 15/24 with DEFECTOR:AZ_beau+col7.

From bruteforce_7remaining_complete.json:
  - 17 consensus nulls fixed: {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
  - 7 varying positions from specific clusters
  - 396 total masks = 378 (88-path) + 18 (87-path)

NOTE: DEFECTOR:AZ_beau+col7 autokey is PROVEN a FALSE SIGNAL (structural
impossibility proof in keystream_forensics_v2.md). This analysis characterizes
the structural properties of the 396 masks for research documentation, NOT
to validate this cipher model.

Filters applied:
  a) Bean constraint (k[27]=k[65] equality, 242 inequalities)
  b) Quadgram score (English log-probability)
  c) IC of plaintext
  d) Common trigram/bigram frequency
  e) Self-encrypting positions (PT[i]=CT73[i])
  f) Letter frequency chi-squared vs English
  g) Which 9 cribs fail (and whether they're the same across all masks)
"""

import sys, json, time, math, os
from itertools import combinations
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, BEAN_EQ, BEAN_INEQ

CT97 = CT
CT97_NUM = tuple(ord(c) - 65 for c in CT97)

CONSENSUS_17 = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
N_PT = 73

# Crib data
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_NUMS = tuple(ord(c) - 65 for c in ENE_WORD)
BCL_NUMS = tuple(ord(c) - 65 for c in BCL_WORD)

DEFECTOR_KW = tuple(ord(c) - 65 for c in "DEFECTOR")

# Pre-count consensus nulls before 21 and 63
C17_BEFORE_21 = sum(1 for p in CONSENSUS_17 if p < 21)  # 8
C17_BEFORE_63 = sum(1 for p in CONSENSUS_17 if p < 63)  # 12

# English letter frequencies (standard)
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074,
}

# Common English trigrams/bigrams
COMMON_TRIGRAMS = ['THE', 'AND', 'ING', 'HER', 'ERE', 'ENT', 'THA', 'NTH',
                   'WAS', 'ETH', 'FOR', 'DTH', 'HAT', 'STH', 'ITH', 'TER',
                   'EST', 'OFT', 'ION', 'ATE', 'VER', 'ALL', 'HIS', 'NOT']
COMMON_BIGRAMS = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN',
                  'ND', 'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT',
                  'AL', 'AR', 'ST', 'TO', 'NT', 'NG', 'SE', 'HA', 'AS']

# ── Col7 inverse permutation ──────────────────────────────────────────────

def columnar_perm(n, width):
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = tuple(reverse_perm(columnar_perm(N_PT, 7)))
# Forward col7 permutation (for mapping CT97 positions to PT positions)
FWD_COL7 = tuple(columnar_perm(N_PT, 7))

# ── Generate all 396 masks algebraically ──────────────────────────────────

def generate_all_396_masks():
    """Generate all 396 masks from the structural decomposition."""
    masks = []

    # 88-path (378 masks):
    # A: 3 from {38,39,40,41,42,43,44}, only 21 specific triples produce 15/24
    # B: 1 from {54,55,56}
    # C: 88 (required)
    # D: 2 from {93,94,95,96}
    cluster_A_pool = [38, 39, 40, 41, 42, 43, 44]
    cluster_B = [54, 55, 56]
    cluster_D = [93, 94, 95, 96]

    # Find which A-triples work by testing them
    valid_A_triples_88 = []
    for triple in combinations(cluster_A_pool, 3):
        # Quick test: use B=54, C=88, D=(93,94)
        varying = triple + (54, 88, 93, 94)
        score = quick_score(varying)
        if score == 15:
            valid_A_triples_88.append(triple)

    print(f"  88-path: {len(valid_A_triples_88)} valid A-triples (expected 21)")

    for triple in valid_A_triples_88:
        for b in cluster_B:
            for d_pair in combinations(cluster_D, 2):
                varying = triple + (b, 88) + d_pair
                masks.append(tuple(sorted(varying)))

    # 87-path (18 masks):
    # A: exactly (38,39,45)
    # B: 1 from {54,55,56}
    # C: 87
    # D: 2 from {93,94,95,96}
    for b in cluster_B:
        for d_pair in combinations(cluster_D, 2):
            varying = (38, 39, 45, b, 87) + d_pair
            masks.append(tuple(sorted(varying)))

    return masks

def quick_score(varying_tuple):
    """Quick crib score for a mask."""
    ns = CONSENSUS_17 | frozenset(varying_tuple)
    ct73 = [CT97_NUM[i] for i in range(97) if i not in ns]
    ct73_t = [ct73[PERM_COL7[i]] for i in range(73)]
    pt = [0] * 73
    for i in range(8):
        pt[i] = (DEFECTOR_KW[i] - ct73_t[i]) % 26
    for i in range(8, 73):
        pt[i] = (pt[i - 8] - ct73_t[i]) % 26

    eb21 = sum(1 for p in varying_tuple if p < 21)
    eb63 = sum(1 for p in varying_tuple if p < 63)
    ene_s = 21 - C17_BEFORE_21 - eb21
    bcl_s = 63 - C17_BEFORE_63 - eb63

    total = 0
    for j in range(13):
        pos = ene_s + j
        if pos < 73 and pt[pos] == ENE_NUMS[j]:
            total += 1
    for j in range(11):
        pos = bcl_s + j
        if pos < 73 and pt[pos] == BCL_NUMS[j]:
            total += 1
    return total


# ── Full pipeline evaluation ──────────────────────────────────────────────

def full_evaluate(varying_tuple, quadgrams=None):
    """Full evaluation of a mask with all secondary filters."""
    ns = CONSENSUS_17 | frozenset(varying_tuple)
    full_mask = sorted(ns)

    # Step 1: Extract 73 chars (remove nulls)
    ct73_raw = []
    ct97_to_ct73 = {}  # maps CT97 position -> CT73 position
    ct73_idx = 0
    for i in range(97):
        if i not in ns:
            ct73_raw.append(CT97_NUM[i])
            ct97_to_ct73[i] = ct73_idx
            ct73_idx += 1

    # Step 2: Apply inverse col7 (undo columnar transposition)
    ct73_t = [ct73_raw[PERM_COL7[i]] for i in range(73)]

    # Step 3: Beaufort autokey decrypt with DEFECTOR
    pt_nums = [0] * 73
    for i in range(8):
        pt_nums[i] = (DEFECTOR_KW[i] - ct73_t[i]) % 26
    for i in range(8, 73):
        pt_nums[i] = (pt_nums[i - 8] - ct73_t[i]) % 26

    pt_str = ''.join(chr(p + 65) for p in pt_nums)

    # Compute keystream: k[i] = (primer_or_pt[i-8] - ct73_t[i]) is NOT what we want
    # For Beaufort: CT = (K - PT) mod 26, so K = (CT + PT) mod 26
    keystream_73 = [(ct73_t[i] + pt_nums[i]) % 26 for i in range(73)]

    # ── a) Bean constraint ──
    # Bean operates on CT97 positions. We need to map CT97[27] and CT97[65]
    # to their positions in the 73-char intermediate space, then check
    # the keystream at those positions.
    # CT97[27] and CT97[65] are crib positions, so they're NOT nulls.
    bean_pos27_in_ct73 = ct97_to_ct73.get(27)
    bean_pos65_in_ct73 = ct97_to_ct73.get(65)

    # After col7 transpose, the intermediate positions change
    # ct73_t[i] = ct73_raw[PERM_COL7[i]], so ct73_raw position maps to
    # intermediate position via the FORWARD col7 permutation
    # If ct73_raw[j] = ct97_to_ct73[27], then intermediate pos = FWD_COL7[j]
    # Wait: PERM_COL7 is the INVERSE of the forward columnar.
    # ct73_t[i] = ct73_raw[PERM_COL7[i]] means output[i] = input[PERM_COL7[i]]
    # So if we want to find which intermediate position i corresponds to
    # ct73_raw position j, we need: i such that PERM_COL7[i] = j
    # That is: i = forward_perm[j] where forward_perm inverts PERM_COL7
    forward_perm = [0] * 73
    for i in range(73):
        forward_perm[PERM_COL7[i]] = i

    # Position of CT97[27] in intermediate (transposed) space
    if bean_pos27_in_ct73 is not None:
        bean_intermediate_27 = forward_perm[bean_pos27_in_ct73]
    else:
        bean_intermediate_27 = None

    if bean_pos65_in_ct73 is not None:
        bean_intermediate_65 = forward_perm[bean_pos65_in_ct73]
    else:
        bean_intermediate_65 = None

    # Bean equality: k at intermediate positions for CT97[27] and CT97[65]
    bean_eq_pass = None
    bean_k27 = None
    bean_k65 = None
    if bean_intermediate_27 is not None and bean_intermediate_65 is not None:
        bean_k27 = keystream_73[bean_intermediate_27]
        bean_k65 = keystream_73[bean_intermediate_65]
        bean_eq_pass = (bean_k27 == bean_k65)

    # Bean inequalities: map all 24 crib positions to intermediate space
    # and check all 242 variant-independent inequalities
    crib_to_intermediate = {}
    for ct97_pos in sorted(ct97_to_ct73.keys()):
        if ct97_pos in range(21, 34) or ct97_pos in range(63, 74):
            ct73_pos = ct97_to_ct73[ct97_pos]
            intermed_pos = forward_perm[ct73_pos]
            crib_to_intermediate[ct97_pos] = intermed_pos

    # Now for Bean inequalities, we need keystream at CT97 positions
    # mapped through the pipeline. Build a mapping: ct97_pos -> key_value
    ct97_key_values = {}
    for ct97_pos, intermed_pos in crib_to_intermediate.items():
        ct97_key_values[ct97_pos] = keystream_73[intermed_pos]

    bean_ineq_pass_count = 0
    bean_ineq_fail_count = 0
    bean_ineq_failures = []
    for a, b in BEAN_INEQ:
        if a in ct97_key_values and b in ct97_key_values:
            if ct97_key_values[a] != ct97_key_values[b]:
                bean_ineq_pass_count += 1
            else:
                bean_ineq_fail_count += 1
                bean_ineq_failures.append((a, b, ct97_key_values[a]))

    # ── Shifted crib positions ──
    eb21 = sum(1 for p in varying_tuple if p < 21)
    eb63 = sum(1 for p in varying_tuple if p < 63)
    ene_s = 21 - C17_BEFORE_21 - eb21
    bcl_s = 63 - C17_BEFORE_63 - eb63

    # ── g) Which cribs fail ──
    ene_match = []
    ene_fail = []
    for j in range(13):
        pos = ene_s + j
        if pos < 73 and pt_nums[pos] == ENE_NUMS[j]:
            ene_match.append(j)
        else:
            ene_fail.append(j)

    bcl_match = []
    bcl_fail = []
    for j in range(11):
        pos = bcl_s + j
        if pos < 73 and pt_nums[pos] == BCL_NUMS[j]:
            bcl_match.append(j)
        else:
            bcl_fail.append(j)

    # What PT actually appears at failing positions
    ene_fail_details = []
    for j in ene_fail:
        pos = ene_s + j
        actual = chr(pt_nums[pos] + 65) if pos < 73 else '?'
        expected = ENE_WORD[j]
        ene_fail_details.append({'crib_idx': j, 'pt_pos': pos,
                                  'expected': expected, 'actual': actual})
    bcl_fail_details = []
    for j in bcl_fail:
        pos = bcl_s + j
        actual = chr(pt_nums[pos] + 65) if pos < 73 else '?'
        expected = BCL_WORD[j]
        bcl_fail_details.append({'crib_idx': j, 'pt_pos': pos,
                                  'expected': expected, 'actual': actual})

    # What key would be needed to fix failing positions
    fix_needed = []
    for j in ene_fail:
        pt_pos = ene_s + j
        if pt_pos < 73:
            needed_pt = ENE_NUMS[j]
            ct_at_pos = ct73_t[pt_pos]
            needed_key = (ct_at_pos + needed_pt) % 26  # Beaufort: K = CT + PT mod 26
            actual_key = keystream_73[pt_pos]
            fix_needed.append({
                'crib': 'ENE', 'crib_idx': j, 'pt_pos': pt_pos,
                'needed_key': needed_key, 'actual_key': actual_key,
                'delta': (needed_key - actual_key) % 26
            })
    for j in bcl_fail:
        pt_pos = bcl_s + j
        if pt_pos < 73:
            needed_pt = BCL_NUMS[j]
            ct_at_pos = ct73_t[pt_pos]
            needed_key = (ct_at_pos + needed_pt) % 26
            actual_key = keystream_73[pt_pos]
            fix_needed.append({
                'crib': 'BCL', 'crib_idx': j, 'pt_pos': pt_pos,
                'needed_key': needed_key, 'actual_key': actual_key,
                'delta': (needed_key - actual_key) % 26
            })

    # ── b) Quadgram score ──
    qg_score = None
    qg_per_char = None
    if quadgrams is not None:
        qg_score = quadgrams.score(pt_str)
        qg_per_char = quadgrams.score_per_char(pt_str)

    # ── c) IC of plaintext ──
    freq_counts = Counter(pt_nums)
    ic_num = sum(c * (c - 1) for c in freq_counts.values())
    ic_denom = 73 * 72
    ic_value = ic_num / ic_denom if ic_denom > 0 else 0

    # ── d) Common trigram/bigram count ──
    trigram_count = 0
    trigram_list = []
    for i in range(len(pt_str) - 2):
        tri = pt_str[i:i+3]
        if tri in COMMON_TRIGRAMS:
            trigram_count += 1
            trigram_list.append((i, tri))

    bigram_count = 0
    bigram_list = []
    for i in range(len(pt_str) - 1):
        bi = pt_str[i:i+2]
        if bi in COMMON_BIGRAMS:
            bigram_count += 1
            bigram_list.append((i, bi))

    # ── e) Self-encrypting positions ──
    # In 73-char space: PT[i] == CT73_transposed[i]
    self_encrypt_count = 0
    self_encrypt_positions = []
    for i in range(73):
        if pt_nums[i] == ct73_t[i]:
            self_encrypt_count += 1
            self_encrypt_positions.append(i)

    # ── f) Letter frequency chi-squared ──
    observed = Counter(pt_str)
    chi_sq = 0
    for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        obs = observed.get(c, 0)
        exp = ENGLISH_FREQ[c] * 73
        chi_sq += (obs - exp) ** 2 / exp

    return {
        'varying': sorted(varying_tuple),
        'full_mask': full_mask,
        'pt': pt_str,
        'ene_score': len(ene_match),
        'bcl_score': len(bcl_match),
        'total_score': len(ene_match) + len(bcl_match),
        'ene_match_indices': ene_match,
        'ene_fail_indices': ene_fail,
        'bcl_match_indices': bcl_match,
        'bcl_fail_indices': bcl_fail,
        'ene_fail_details': ene_fail_details,
        'bcl_fail_details': bcl_fail_details,
        'fix_needed': fix_needed,
        'bean_eq_pass': bean_eq_pass,
        'bean_k27': bean_k27,
        'bean_k65': bean_k65,
        'bean_intermediate_27': bean_intermediate_27,
        'bean_intermediate_65': bean_intermediate_65,
        'bean_ineq_pass': bean_ineq_pass_count,
        'bean_ineq_fail': bean_ineq_fail_count,
        'bean_ineq_total': bean_ineq_pass_count + bean_ineq_fail_count,
        'bean_ineq_failures_sample': bean_ineq_failures[:10],
        'bean_all_pass': bean_eq_pass and bean_ineq_fail_count == 0,
        'qg_score': qg_score,
        'qg_per_char': qg_per_char,
        'ic': ic_value,
        'trigram_count': trigram_count,
        'trigrams': trigram_list[:20],
        'bigram_count': bigram_count,
        'bigrams': bigram_list[:20],
        'self_encrypt_count': self_encrypt_count,
        'self_encrypt_positions': self_encrypt_positions,
        'chi_squared': chi_sq,
        'letter_freq': dict(observed),
        'ene_start_73': ene_s,
        'bcl_start_73': bcl_s,
        'ct97_key_values_at_cribs': {str(k): v for k, v in ct97_key_values.items()},
    }


# ── Main ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 70)
    print("FILTER 396 MASKS: Secondary analysis of DEFECTOR:AZ_beau+col7")
    print("NOTE: This model is a CONFIRMED FALSE SIGNAL (autokey impossibility)")
    print("=" * 70)
    print()

    # Load quadgrams
    from kryptos.kernel.scoring.ngram import NgramScorer
    qg_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
    if not os.path.exists(qg_path):
        qg_path = '/home/cpatrick/kryptos/data/english_quadgrams.json'
    quadgrams = NgramScorer.from_file(qg_path)
    print(f"Loaded quadgrams from {qg_path}")

    # Step 1: Generate all 396 masks
    print("\nStep 1: Generating all 396 masks algebraically...")
    t0 = time.time()
    all_masks = generate_all_396_masks()
    print(f"  Generated {len(all_masks)} masks in {time.time()-t0:.2f}s")

    # Verify all score 15/24
    print("\n  Verifying all masks score 15/24...")
    verified = 0
    for varying in all_masks:
        sc = quick_score(varying)
        if sc != 15:
            print(f"  WARNING: mask {varying} scores {sc}/24 (expected 15)")
        else:
            verified += 1
    print(f"  Verified: {verified}/{len(all_masks)} masks score 15/24")

    # Check for duplicates
    unique_masks = set(all_masks)
    print(f"  Unique masks: {len(unique_masks)}")
    if len(unique_masks) != len(all_masks):
        print(f"  WARNING: {len(all_masks) - len(unique_masks)} duplicates found!")

    # Step 2: Full evaluation
    print(f"\nStep 2: Full evaluation of {len(all_masks)} masks...")
    t1 = time.time()
    results = []
    for i, varying in enumerate(all_masks):
        r = full_evaluate(varying, quadgrams)
        results.append(r)
        if (i + 1) % 100 == 0:
            print(f"  Evaluated {i+1}/{len(all_masks)}...")

    print(f"  Completed in {time.time()-t1:.2f}s")

    # ═══════════════════════════════════════════════════════════════════════
    # ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════

    print()
    print("=" * 70)
    print("ANALYSIS RESULTS")
    print("=" * 70)

    # ── a) Bean constraint ──
    print("\n--- a) Bean Constraint ---")
    bean_eq_pass = sum(1 for r in results if r['bean_eq_pass'])
    bean_eq_fail = sum(1 for r in results if not r['bean_eq_pass'])
    print(f"  Bean EQ (k[27]=k[65]):")
    print(f"    PASS: {bean_eq_pass}/{len(results)}")
    print(f"    FAIL: {bean_eq_fail}/{len(results)}")
    if results:
        r0 = results[0]
        print(f"    k[27] intermediate pos={r0['bean_intermediate_27']}, value={r0['bean_k27']}")
        print(f"    k[65] intermediate pos={r0['bean_intermediate_65']}, value={r0['bean_k65']}")

    # Check if Bean values vary across masks
    bean_k27_values = set(r['bean_k27'] for r in results if r['bean_k27'] is not None)
    bean_k65_values = set(r['bean_k65'] for r in results if r['bean_k65'] is not None)
    print(f"    k[27] distinct values across masks: {sorted(bean_k27_values)}")
    print(f"    k[65] distinct values across masks: {sorted(bean_k65_values)}")

    bean_ineq_stats = Counter(r['bean_ineq_fail'] for r in results)
    print(f"\n  Bean inequalities:")
    for n_fail, count in sorted(bean_ineq_stats.items()):
        print(f"    {n_fail} failures: {count} masks")

    bean_all_pass = sum(1 for r in results if r['bean_all_pass'])
    print(f"\n  Bean ALL PASS (eq + ineq): {bean_all_pass}/{len(results)}")

    # ── b) Quadgram score ──
    print("\n--- b) Quadgram Score ---")
    qg_scores = sorted(results, key=lambda r: r['qg_per_char'] or -999, reverse=True)
    print(f"  Best:  {qg_scores[0]['qg_per_char']:.4f} varying={qg_scores[0]['varying']}")
    print(f"         PT: {qg_scores[0]['pt']}")
    print(f"  Worst: {qg_scores[-1]['qg_per_char']:.4f} varying={qg_scores[-1]['varying']}")
    print(f"  Mean:  {sum(r['qg_per_char'] for r in results)/len(results):.4f}")
    print(f"  Stdev: {(sum((r['qg_per_char'] - sum(r2['qg_per_char'] for r2 in results)/len(results))**2 for r in results)/len(results))**0.5:.4f}")
    print(f"  (English baseline: ~-4.2, random: ~-6.0)")

    # Top 10 by quadgram
    print(f"\n  Top 10 by quadgram score:")
    for i, r in enumerate(qg_scores[:10]):
        print(f"    {i+1}. qg={r['qg_per_char']:.4f} ic={r['ic']:.4f} "
              f"bean_eq={'P' if r['bean_eq_pass'] else 'F'} "
              f"bean_ineq_fail={r['bean_ineq_fail']} "
              f"varying={r['varying']}")

    # ── c) IC ──
    print("\n--- c) Index of Coincidence ---")
    ic_values = [r['ic'] for r in results]
    ic_distinct = sorted(set(f"{v:.6f}" for v in ic_values))
    print(f"  Distinct IC values: {len(ic_distinct)}")
    print(f"  Min:  {min(ic_values):.6f}")
    print(f"  Max:  {max(ic_values):.6f}")
    print(f"  Mean: {sum(ic_values)/len(ic_values):.6f}")
    print(f"  (English: ~0.0667, random: ~0.0385)")

    # Top 5 by IC
    ic_sorted = sorted(results, key=lambda r: r['ic'], reverse=True)
    print(f"\n  Top 5 by IC:")
    for i, r in enumerate(ic_sorted[:5]):
        print(f"    {i+1}. ic={r['ic']:.6f} qg={r['qg_per_char']:.4f} varying={r['varying']}")

    # ── d) Common trigrams/bigrams ──
    print("\n--- d) Common Trigrams/Bigrams ---")
    tri_counts = [r['trigram_count'] for r in results]
    bi_counts = [r['bigram_count'] for r in results]
    print(f"  Trigrams: min={min(tri_counts)}, max={max(tri_counts)}, mean={sum(tri_counts)/len(tri_counts):.1f}")
    print(f"  Bigrams:  min={min(bi_counts)}, max={max(bi_counts)}, mean={sum(bi_counts)/len(bi_counts):.1f}")

    # Top 5 by trigram count
    tri_sorted = sorted(results, key=lambda r: r['trigram_count'], reverse=True)
    print(f"\n  Top 5 by trigram count:")
    for i, r in enumerate(tri_sorted[:5]):
        print(f"    {i+1}. tri={r['trigram_count']} bi={r['bigram_count']} "
              f"qg={r['qg_per_char']:.4f} varying={r['varying']}")
        if r['trigrams']:
            print(f"       trigrams: {r['trigrams'][:10]}")

    # ── e) Self-encrypting positions ──
    print("\n--- e) Self-Encrypting Positions (PT[i]=CT73_transposed[i]) ---")
    se_counts = [r['self_encrypt_count'] for r in results]
    print(f"  Min: {min(se_counts)}, Max: {max(se_counts)}, Mean: {sum(se_counts)/len(se_counts):.1f}")
    print(f"  (Random expected: 73/26 = {73/26:.1f})")

    se_sorted = sorted(results, key=lambda r: r['self_encrypt_count'], reverse=True)
    if se_sorted:
        print(f"  Top: {se_sorted[0]['self_encrypt_count']} self-encrypting positions")
        print(f"       at positions: {se_sorted[0]['self_encrypt_positions']}")

    # Check if self-encrypting positions include CT97 positions 32 (S) and 73 (K)
    print(f"\n  CT97 self-encrypting check (pos 32=S, pos 73=K):")
    for r in results[:5]:
        # Map CT97[32] to CT73 to intermediate
        ct73_pos_32 = None
        ct73_pos_73 = None
        ct73_idx = 0
        mask_set = set(r['full_mask'])
        for i in range(97):
            if i not in mask_set:
                if i == 32:
                    ct73_pos_32 = ct73_idx
                if i == 73:
                    ct73_pos_73 = ct73_idx
                ct73_idx += 1

        if ct73_pos_32 is not None:
            intermed_32 = [idx for idx in range(73) if PERM_COL7[idx] == ct73_pos_32]
            if intermed_32:
                pt_at_32 = r['pt'][intermed_32[0]]
                print(f"    CT97[32]=S -> CT73[{ct73_pos_32}] -> intermed[{intermed_32[0]}] -> PT={pt_at_32} "
                      f"({'SELF-ENCRYPT' if pt_at_32 == 'S' else 'NO'})")

        if ct73_pos_73 is not None:
            intermed_73 = [idx for idx in range(73) if PERM_COL7[idx] == ct73_pos_73]
            if intermed_73:
                pt_at_73 = r['pt'][intermed_73[0]]
                print(f"    CT97[73]=K -> CT73[{ct73_pos_73}] -> intermed[{intermed_73[0]}] -> PT={pt_at_73} "
                      f"({'SELF-ENCRYPT' if pt_at_73 == 'K' else 'NO'})")
        break  # Same for all masks with identical structure

    # ── f) Chi-squared ──
    print("\n--- f) Letter Frequency Chi-Squared ---")
    chi_values = [r['chi_squared'] for r in results]
    print(f"  Min:  {min(chi_values):.2f}")
    print(f"  Max:  {max(chi_values):.2f}")
    print(f"  Mean: {sum(chi_values)/len(chi_values):.2f}")
    print(f"  (Lower = more English-like, English text ~25-50, random ~50-100)")

    chi_sorted = sorted(results, key=lambda r: r['chi_squared'])
    print(f"\n  Top 5 by chi-squared (lowest):")
    for i, r in enumerate(chi_sorted[:5]):
        print(f"    {i+1}. chi2={r['chi_squared']:.2f} qg={r['qg_per_char']:.4f} varying={r['varying']}")

    # ── g) Which 9 cribs fail ──
    print("\n--- g) Failing Crib Positions ---")

    # Collect all failure patterns
    ene_fail_patterns = Counter()
    bcl_fail_patterns = Counter()
    for r in results:
        ene_fail_patterns[tuple(r['ene_fail_indices'])] += 1
        bcl_fail_patterns[tuple(r['bcl_fail_indices'])] += 1

    print(f"\n  ENE failure patterns: {len(ene_fail_patterns)} distinct")
    for pattern, count in ene_fail_patterns.most_common():
        letters = ''.join(ENE_WORD[j] for j in pattern)
        print(f"    fail@{list(pattern)} ({letters}): {count} masks")

    print(f"\n  BCL failure patterns: {len(bcl_fail_patterns)} distinct")
    for pattern, count in bcl_fail_patterns.most_common():
        letters = ''.join(BCL_WORD[j] for j in pattern)
        print(f"    fail@{list(pattern)} ({letters}): {count} masks")

    # Are the SAME 9 cribs failing across all 396?
    combined_patterns = Counter()
    for r in results:
        combined_patterns[
            (tuple(r['ene_fail_indices']), tuple(r['bcl_fail_indices']))
        ] += 1

    print(f"\n  Combined (ENE+BCL) failure patterns: {len(combined_patterns)} distinct")
    all_same = len(combined_patterns) == 1
    print(f"  ALL 396 MASKS FAIL SAME 9 CRIBS: {'YES' if all_same else 'NO'}")

    if all_same:
        pattern = list(combined_patterns.keys())[0]
        print(f"    ENE failing: {list(pattern[0])} = {''.join(ENE_WORD[j] for j in pattern[0])}")
        print(f"    BCL failing: {list(pattern[1])} = {''.join(BCL_WORD[j] for j in pattern[1])}")
    else:
        for (ep, bp), count in combined_patterns.most_common(5):
            print(f"    ENE fail {list(ep)} + BCL fail {list(bp)}: {count} masks")

    # Detail on what's needed to fix the failing cribs
    print(f"\n  Fix analysis (from first mask):")
    r0 = results[0]
    print(f"    ENE failing details:")
    for d in r0['ene_fail_details']:
        print(f"      crib[{d['crib_idx']}]='{d['expected']}' at PT pos {d['pt_pos']}: "
              f"got '{d['actual']}'")
    print(f"    BCL failing details:")
    for d in r0['bcl_fail_details']:
        print(f"      crib[{d['crib_idx']}]='{d['expected']}' at PT pos {d['pt_pos']}: "
              f"got '{d['actual']}'")

    print(f"\n    Key corrections needed at failing positions:")
    for f in r0['fix_needed']:
        needed_letter = chr(f['needed_key'] + 65)
        actual_letter = chr(f['actual_key'] + 65)
        delta_letter = chr(f['delta'] + 65)
        print(f"      {f['crib']}[{f['crib_idx']}] PT pos {f['pt_pos']}: "
              f"need key={needed_letter}({f['needed_key']}) "
              f"have key={actual_letter}({f['actual_key']}) "
              f"delta={delta_letter}({f['delta']})")

    # Check if different transposition widths fix some failing cribs
    print(f"\n  Can different col widths fix any failures? (testing col5-13)")
    # This would require the full pipeline with different widths
    # Just test the first mask with different widths
    for width in [5, 6, 8, 9, 10, 11, 13]:
        perm_w = tuple(reverse_perm(columnar_perm(N_PT, width)))
        ns = CONSENSUS_17 | frozenset(r0['varying'])
        ct73_raw = [CT97_NUM[i] for i in range(97) if i not in ns]
        ct73_t = [ct73_raw[perm_w[i]] for i in range(73)]
        pt = [0] * 73
        for i in range(8):
            pt[i] = (DEFECTOR_KW[i] - ct73_t[i]) % 26
        for i in range(8, 73):
            pt[i] = (pt[i - 8] - ct73_t[i]) % 26

        eb21 = sum(1 for p in r0['varying'] if p < 21)
        eb63 = sum(1 for p in r0['varying'] if p < 63)
        ene_s = 21 - C17_BEFORE_21 - eb21
        bcl_s = 63 - C17_BEFORE_63 - eb63

        e = sum(1 for j in range(13) if ene_s+j < 73 and pt[ene_s+j] == ENE_NUMS[j])
        b = sum(1 for j in range(11) if bcl_s+j < 73 and pt[bcl_s+j] == BCL_NUMS[j])
        pt_str = ''.join(chr(p+65) for p in pt)
        print(f"    col{width}: {e+b}/24 (ene={e}/13 bcl={b}/11)")

    # ═══════════════════════════════════════════════════════════════════════
    # CROSS-FILTER
    # ═══════════════════════════════════════════════════════════════════════

    print()
    print("=" * 70)
    print("CROSS-FILTER RESULTS")
    print("=" * 70)

    # Bean pass + top 10% quadgram
    qg_threshold = sorted(r['qg_per_char'] for r in results)[int(0.9 * len(results))]
    print(f"\n  Quadgram top 10% threshold: {qg_threshold:.4f}")

    survivors = [r for r in results
                 if r['bean_eq_pass'] and r['bean_ineq_fail'] == 0
                 and r['qg_per_char'] >= qg_threshold]
    print(f"  Bean ALL PASS + top 10% quadgram: {len(survivors)} masks")

    if survivors:
        for i, r in enumerate(sorted(survivors, key=lambda x: -x['qg_per_char'])[:10]):
            print(f"    {i+1}. qg={r['qg_per_char']:.4f} ic={r['ic']:.4f} "
                  f"chi2={r['chi_squared']:.1f} varying={r['varying']}")
            print(f"       PT: {r['pt']}")

    # Bean pass + top IC
    bean_pass_results = [r for r in results if r['bean_all_pass']]
    print(f"\n  Bean ALL PASS masks: {len(bean_pass_results)}")
    if bean_pass_results:
        bp_qg = sorted(bean_pass_results, key=lambda r: -r['qg_per_char'])
        print(f"  Best quadgram among Bean-passing: {bp_qg[0]['qg_per_char']:.4f}")
        print(f"    varying={bp_qg[0]['varying']}")
        print(f"    PT: {bp_qg[0]['pt']}")

    # Relaxed: Bean EQ pass only + top 10% qg + top 10% IC
    ic_threshold = sorted(r['ic'] for r in results)[int(0.9 * len(results))]
    relaxed = [r for r in results
               if r['bean_eq_pass']
               and r['qg_per_char'] >= qg_threshold
               and r['ic'] >= ic_threshold]
    print(f"\n  Bean EQ + top 10% qg + top 10% IC: {len(relaxed)} masks")
    for r in sorted(relaxed, key=lambda x: -x['qg_per_char'])[:5]:
        print(f"    qg={r['qg_per_char']:.4f} ic={r['ic']:.4f} "
              f"bean_ineq_fail={r['bean_ineq_fail']} varying={r['varying']}")

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 4: Analyze 7 varying positions of top masks
    # ═══════════════════════════════════════════════════════════════════════

    print()
    print("=" * 70)
    print("STEP 4: VARYING POSITION ANALYSIS")
    print("=" * 70)

    # Frequency of each position across all 396 masks
    pos_freq = Counter()
    for r in results:
        for p in r['varying']:
            pos_freq[p] += 1

    print(f"\n  Position frequency across {len(results)} masks:")
    for p, count in sorted(pos_freq.items()):
        ct_letter = CT97[p]
        pct = count / len(results) * 100
        grid_row = (p + 27) // 31  # approximate grid row for K4 starting at row 24 col 27
        grid_col = (p + 27) % 31
        palette = ct_letter in 'BGIKOWZ'
        print(f"    pos {p:2d} (CT='{ct_letter}', {'PAL' if palette else '   '}): "
              f"{count:4d}/{len(results)} ({pct:5.1f}%)")

    # For top masks, check spatial patterns
    print(f"\n  Spatial analysis of varying positions:")
    print(f"  (Using 28x31 grid, K4 starts at row 24 col 27)")
    for r in sorted(results, key=lambda x: -x['qg_per_char'])[:5]:
        positions = r['varying']
        print(f"\n    varying={positions} (qg={r['qg_per_char']:.4f})")
        for p in positions:
            # K4 linear position -> grid position
            # K4 starts at position 769 (row 24, col 27) in the 868-char grid
            grid_pos = 769 + p
            grid_row = grid_pos // 31
            grid_col = grid_pos % 31
            ct_letter = CT97[p]
            palette = ct_letter in 'BGIKOWZ'
            print(f"      pos {p:2d}: CT='{ct_letter}' grid({grid_row},{grid_col}) "
                  f"pos%7={p%7} pos%5={p%5} pos%6={p%6} {'PALETTE' if palette else ''}")

    # Check NDYAHR adjacency
    NDYAHR = set('NDYAHR')
    print(f"\n  NDYAHR adjacency check:")
    for p, count in sorted(pos_freq.items()):
        ct_letter = CT97[p]
        is_ndyahr = ct_letter in NDYAHR
        # Check neighbors in CT97
        left = CT97[p-1] if p > 0 else '-'
        right = CT97[p+1] if p < 96 else '-'
        left_ndy = left in NDYAHR
        right_ndy = right in NDYAHR
        if is_ndyahr or left_ndy or right_ndy:
            print(f"    pos {p:2d} CT='{ct_letter}': "
                  f"{'IS NDYAHR' if is_ndyahr else ''} "
                  f"{'left='+left+'(NDYAHR)' if left_ndy else ''} "
                  f"{'right='+right+'(NDYAHR)' if right_ndy else ''}")

    # W-adjacent positions
    w_positions = [i for i, c in enumerate(CT97) if c == 'W']
    print(f"\n  W-adjacency check (W at positions {w_positions}):")
    for p in sorted(pos_freq.keys()):
        for wp in w_positions:
            if abs(p - wp) <= 1:
                print(f"    pos {p:2d} is adjacent to W at {wp} (distance {abs(p-wp)})")

    # Width-6 and width-7 patterns
    print(f"\n  Modular patterns of varying positions:")
    for mod in [5, 6, 7, 31]:
        residues = Counter()
        for r in results:
            for p in r['varying']:
                residues[p % mod] += 1
        print(f"    mod {mod}: {dict(sorted(residues.items()))}")

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 5: Can failing cribs be fixed?
    # ═══════════════════════════════════════════════════════════════════════

    print()
    print("=" * 70)
    print("STEP 5: FAILING CRIB FIXABILITY ANALYSIS")
    print("=" * 70)

    r0 = results[0]
    print(f"\n  9 failing positions have these key corrections needed:")
    deltas = []
    for f in r0['fix_needed']:
        deltas.append(f['delta'])
        print(f"    PT pos {f['pt_pos']:2d}: delta={f['delta']:2d} ({chr(f['delta']+65)})")

    # Check for patterns in deltas
    print(f"\n  Delta values: {deltas}")
    print(f"  Delta letters: {''.join(chr(d+65) for d in deltas)}")
    print(f"  Distinct deltas: {len(set(deltas))}")
    print(f"  Constant? {len(set(deltas)) == 1}")

    # Check if deltas form a periodic pattern
    for period in range(2, 6):
        if len(deltas) >= 2 * period:
            periodic = all(deltas[i] == deltas[i % period] for i in range(len(deltas)))
            if periodic:
                print(f"  Period-{period} pattern detected!")

    # Check if a simple key offset would fix multiple positions
    print(f"\n  Single-offset fix check:")
    for offset in range(26):
        fixed = sum(1 for d in deltas if d == offset)
        if fixed >= 2:
            print(f"    offset={offset} ({chr(offset+65)}): fixes {fixed}/9 positions")

    # Check if the failing positions correspond to specific autokey feedback positions
    print(f"\n  Failing PT positions and their autokey feedback sources:")
    for f in r0['fix_needed']:
        pos = f['pt_pos']
        if pos >= 8:
            source = pos - 8
            source_pt = r0['pt'][source]
            print(f"    PT[{pos}] <- PT[{source}]='{source_pt}' ({ord(source_pt)-65})")
        else:
            source = pos
            kw_letter = chr(DEFECTOR_KW[source] + 65)
            print(f"    PT[{pos}] <- DEFECTOR[{source}]='{kw_letter}'")

    # ═══════════════════════════════════════════════════════════════════════
    # Save results
    # ═══════════════════════════════════════════════════════════════════════

    # Prepare summary
    summary = {
        'experiment': 'Filter 396 masks: secondary analysis of DEFECTOR:AZ_beau+col7',
        'date': time.strftime('%Y-%m-%d'),
        'note': 'This model is a CONFIRMED FALSE SIGNAL (autokey impossibility proof). Analysis for structural characterization only.',
        'total_masks': len(results),
        'verified_15_24': verified,

        'bean_eq_pass': bean_eq_pass,
        'bean_eq_fail': bean_eq_fail,
        'bean_all_pass': bean_all_pass,
        'bean_ineq_failure_distribution': dict(bean_ineq_stats),

        'quadgram_stats': {
            'best': qg_scores[0]['qg_per_char'],
            'worst': qg_scores[-1]['qg_per_char'],
            'mean': sum(r['qg_per_char'] for r in results) / len(results),
            'best_varying': qg_scores[0]['varying'],
            'best_pt': qg_scores[0]['pt'],
        },

        'ic_stats': {
            'min': min(ic_values),
            'max': max(ic_values),
            'mean': sum(ic_values) / len(ic_values),
        },

        'chi_sq_stats': {
            'min': min(chi_values),
            'max': max(chi_values),
            'mean': sum(chi_values) / len(chi_values),
        },

        'failing_cribs_same_for_all': all_same,
        'ene_failing_indices': list(combined_patterns.keys())[0][0] if all_same else None,
        'bcl_failing_indices': list(combined_patterns.keys())[0][1] if all_same else None,
        'combined_failure_pattern_count': len(combined_patterns),

        'cross_filter': {
            'bean_all_pass_and_top10pct_qg': len(survivors),
            'bean_eq_and_top10pct_qg_and_top10pct_ic': len(relaxed),
        },

        'fix_needed_from_first_mask': r0['fix_needed'],
        'correction_deltas': deltas,
        'correction_delta_letters': ''.join(chr(d+65) for d in deltas),

        'position_frequency': {str(p): c for p, c in sorted(pos_freq.items())},

        'top_10_by_quadgram': [
            {
                'rank': i+1,
                'qg_per_char': r['qg_per_char'],
                'ic': r['ic'],
                'chi_squared': r['chi_squared'],
                'bean_eq_pass': r['bean_eq_pass'],
                'bean_ineq_fail': r['bean_ineq_fail'],
                'varying': r['varying'],
                'pt': r['pt'],
                'trigram_count': r['trigram_count'],
                'bigram_count': r['bigram_count'],
                'self_encrypt_count': r['self_encrypt_count'],
            }
            for i, r in enumerate(qg_scores[:10])
        ],

        'all_396_masks': [
            {
                'varying': r['varying'],
                'full_mask': r['full_mask'],
                'pt': r['pt'],
                'qg_per_char': r['qg_per_char'],
                'ic': r['ic'],
                'chi_squared': r['chi_squared'],
                'bean_eq_pass': r['bean_eq_pass'],
                'bean_ineq_fail': r['bean_ineq_fail'],
                'trigram_count': r['trigram_count'],
                'bigram_count': r['bigram_count'],
                'self_encrypt_count': r['self_encrypt_count'],
                'ene_score': r['ene_score'],
                'bcl_score': r['bcl_score'],
            }
            for r in results
        ],
    }

    out_path = '/home/cpatrick/kryptos/results/filter_396_masks.json'
    with open(out_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved results to {out_path}")

    print()
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"  Total masks: {len(results)}")
    print(f"  Bean EQ pass: {bean_eq_pass}/{len(results)}")
    print(f"  Bean ALL pass: {bean_all_pass}/{len(results)}")
    print(f"  Failing cribs same for all: {all_same}")
    print(f"  Best quadgram: {qg_scores[0]['qg_per_char']:.4f}")
    print(f"  Cross-filter survivors (Bean ALL + top 10% qg): {len(survivors)}")
    print(f"  NOTE: DEFECTOR:AZ_beau+col7 is a CONFIRMED FALSE SIGNAL")
