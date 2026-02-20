#!/usr/bin/env python3
"""E-FRAC-39: Running Key + Transposition Bipartite Feasibility Analysis

STRUCTURAL ANALYSIS: For each running key offset in reference texts,
compute the maximum possible crib score achievable under ANY transposition
using bipartite matching. This is a necessary condition — if the max
matching is < 24, no transposition can produce 24/24 cribs at that offset.

Key insight: Running key is the ONLY structured key model surviving Bean
constraints (E-FRAC-38). This experiment determines whether running key +
transposition from known reference texts is FEASIBLE.

Method:
  For each offset o in source text:
    1. K[i] = source_letter_num[o + i] for i = 0..96
    2. Check Bean equality: K[27] == K[65]
    3. Check Bean inequalities: K[a] != K[b] for all 21 pairs
    4. For each cipher variant (Vigenère, Beaufort):
       - Compute required intermediate at each crib position
       - Build bipartite graph: crib_positions → CT positions
       - Maximum matching = max achievable crib score under ANY transposition
    5. Offset is "fully feasible" only if Bean passes AND matching = 24
"""
import json
import os
import sys
import time
from collections import Counter

# Ensure we can import kryptos
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

# Convert CT to numbers
CT_NUM = [ALPH_IDX[c] for c in CT]

# Count CT letter frequencies (for bipartite graph construction)
CT_LETTER_POSITIONS = {}  # letter_num -> list of CT positions
for j, v in enumerate(CT_NUM):
    CT_LETTER_POSITIONS.setdefault(v, []).append(j)

# Crib data
CRIB_POS = [pos for pos, _ in CRIB_ENTRIES]
CRIB_PT = [ALPH_IDX[ch] for _, ch in CRIB_ENTRIES]


def max_bipartite_matching(adj: list[list[int]], n_left: int, n_right: int) -> int:
    """Find maximum bipartite matching using augmenting paths.

    adj[i] = list of right-node indices that left-node i can match to.
    Returns the size of the maximum matching.
    """
    match_right = [-1] * n_right

    def augment(u: int, visited: list[bool]) -> bool:
        for v in adj[u]:
            if not visited[v]:
                visited[v] = True
                if match_right[v] == -1 or augment(match_right[v], visited):
                    match_right[v] = u
                    return True
        return False

    matching = 0
    for u in range(n_left):
        visited = [False] * n_right
        if augment(u, visited):
            matching += 1
    return matching


def check_bean(key_nums: list[int]) -> tuple[bool, bool]:
    """Check Bean equality and full Bean (eq + all ineq).
    Returns (eq_pass, full_pass).
    """
    # Bean equality
    for eq_a, eq_b in BEAN_EQ:
        if key_nums[eq_a] != key_nums[eq_b]:
            return False, False

    # Bean inequalities
    for ineq_a, ineq_b in BEAN_INEQ:
        if key_nums[ineq_a] == key_nums[ineq_b]:
            return True, False

    return True, True


def compute_required_ct(pt_num: int, key_num: int, variant: str) -> int:
    """Compute required CT letter given PT and key, for each variant.

    Encryption model: intermediate[i] = Enc(PT[i], K[i])
    CT = transposition(intermediate), so intermediate = inv_transposition(CT)

    For Vigenère: intermediate = (PT + K) mod 26
    For Beaufort: intermediate = (K - PT) mod 26
    """
    if variant == 'vigenere':
        return (pt_num + key_num) % MOD
    elif variant == 'beaufort':
        return (key_num - pt_num) % MOD
    else:
        raise ValueError(f"Unknown variant: {variant}")


def analyze_offset(source_nums: list[int], offset: int, variant: str) -> int:
    """For a given source text offset and cipher variant, compute max matching.

    Returns the maximum number of cribs that can simultaneously match
    under ANY transposition permutation.
    """
    # Build adjacency list: for each crib position, which CT positions
    # have the required letter?
    adj = []
    for i in range(N_CRIBS):
        crib_pos = CRIB_POS[i]
        pt_val = CRIB_PT[i]
        key_val = source_nums[offset + crib_pos]
        required_ct_letter = compute_required_ct(pt_val, key_val, variant)
        # Find all CT positions with this letter
        matching_positions = CT_LETTER_POSITIONS.get(required_ct_letter, [])
        adj.append(matching_positions)

    return max_bipartite_matching(adj, N_CRIBS, CT_LEN)


def load_text(filepath: str) -> list[int]:
    """Load a text file and convert to list of letter numbers (A=0, ..., Z=25).
    Only uppercase letters are kept.
    """
    with open(filepath, 'r', errors='replace') as f:
        raw = f.read().upper()
    return [ALPH_IDX[c] for c in raw if c in ALPH_IDX]


def analyze_text(name: str, source_nums: list[int], variants: list[str]) -> dict:
    """Analyze all offsets in a source text for running key feasibility."""
    n = len(source_nums)
    max_offset = n - CT_LEN
    if max_offset < 0:
        return {'name': name, 'length': n, 'error': 'Text too short'}

    results = {
        'name': name,
        'length': n,
        'total_offsets': max_offset + 1,
    }

    for variant in variants:
        var_results = {
            'bean_eq_pass': 0,
            'bean_full_pass': 0,
            'matching_distribution': Counter(),
            'max_matching': 0,
            'feasible_24': 0,           # matching == 24
            'feasible_24_bean': 0,      # matching == 24 AND bean full pass
            'feasible_23_plus': 0,      # matching >= 23
            'feasible_22_plus': 0,      # matching >= 22
            'top_offsets': [],           # top-10 by matching score
        }

        for o in range(max_offset + 1):
            # Extract running key for this offset
            key_nums = source_nums[o:o + CT_LEN]

            # Check Bean constraints
            bean_eq, bean_full = check_bean(key_nums)
            if bean_eq:
                var_results['bean_eq_pass'] += 1
            if bean_full:
                var_results['bean_full_pass'] += 1

            # Compute max matching
            matching = analyze_offset(source_nums, o, variant)
            var_results['matching_distribution'][matching] += 1

            if matching > var_results['max_matching']:
                var_results['max_matching'] = matching

            if matching >= 22:
                var_results['feasible_22_plus'] += 1
            if matching >= 23:
                var_results['feasible_23_plus'] += 1
            if matching == 24:
                var_results['feasible_24'] += 1
                if bean_full:
                    var_results['feasible_24_bean'] += 1

            # Track top offsets
            if matching >= 20 or (len(var_results['top_offsets']) < 10):
                var_results['top_offsets'].append({
                    'offset': o,
                    'matching': matching,
                    'bean_eq': bean_eq,
                    'bean_full': bean_full,
                })
                # Keep only top 50 by matching score
                var_results['top_offsets'].sort(
                    key=lambda x: (-x['matching'], x['offset'])
                )
                var_results['top_offsets'] = var_results['top_offsets'][:50]

        # Convert Counter to sorted dict for JSON
        var_results['matching_distribution'] = dict(
            sorted(var_results['matching_distribution'].items(), reverse=True)
        )

        results[variant] = var_results

    return results


def generate_random_english(length: int) -> list[int]:
    """Generate random text with English letter frequencies."""
    import random
    # English letter frequencies (approximate)
    freqs = [
        0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609,
        0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193,
        0.0010, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015,
        0.0197, 0.0007
    ]
    # Build cumulative distribution
    cumulative = []
    total = 0
    for f in freqs:
        total += f
        cumulative.append(total)

    result = []
    for _ in range(length):
        r = random.random()
        for i, c in enumerate(cumulative):
            if r <= c:
                result.append(i)
                break
        else:
            result.append(25)  # Z
    return result


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-39: Running Key + Transposition Bipartite Feasibility")
    print("=" * 70)

    # Pre-analysis: CT letter frequency profile
    ct_freq = Counter(CT_NUM)
    print(f"\nCT letter frequencies (most common):")
    for val, count in ct_freq.most_common(10):
        letter = chr(val + ord('A'))
        print(f"  {letter}={count}", end="")
    print()

    # For each crib position, show how many CT positions have each
    # required letter under identity key (K=0, i.e., PT = intermediate)
    print(f"\nCrib positions: {N_CRIBS}")
    print(f"CT length: {CT_LEN}")

    variants = ['vigenere', 'beaufort']

    # Load reference texts
    base = os.path.dirname(os.path.dirname(__file__))
    texts = {}

    text_files = [
        ('carter_gutenberg', os.path.join(base, 'reference', 'carter_gutenberg.txt')),
        ('carter_vol1_extract', os.path.join(base, 'reference', 'carter_vol1_extract.txt')),
        ('cia_charter', os.path.join(base, 'reference', 'running_key_texts', 'cia_charter.txt')),
        ('jfk_berlin', os.path.join(base, 'reference', 'running_key_texts', 'jfk_berlin.txt')),
        ('nsa_act_1947', os.path.join(base, 'reference', 'running_key_texts', 'nsa_act_1947.txt')),
        ('reagan_berlin', os.path.join(base, 'reference', 'running_key_texts', 'reagan_berlin.txt')),
        ('udhr', os.path.join(base, 'reference', 'running_key_texts', 'udhr.txt')),
    ]

    for name, path in text_files:
        if os.path.exists(path):
            texts[name] = load_text(path)
            print(f"Loaded {name}: {len(texts[name])} letters")
        else:
            print(f"MISSING: {path}")

    # Also load K1-K3 combined plaintext
    k1k3_pt = (
        "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
        "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHS"
        "MAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTO"
        "ANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUT"
        "THERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
        "THIRTYEIGHTNORTHLATITUDESIXTYSEVENWESTLONGITUDEXTWOTIMESXLAYERTWO"
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
        "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY"
        "BREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE"
        "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
        "CAUSEDTHEFLAMETOFLICKERBUTSOONDETAILSOFTHEROOMWITHINEMERGED"
        "FROMTHEMISTXCANYOUSEEANYTHINGQ"
    )
    texts['k1k3_plaintext'] = [ALPH_IDX[c] for c in k1k3_pt if c in ALPH_IDX]
    print(f"Loaded k1k3_plaintext: {len(texts['k1k3_plaintext'])} letters")

    print("\n" + "=" * 70)
    print("PHASE 1: Reference Text Analysis")
    print("=" * 70)

    all_results = {}
    for name, source_nums in texts.items():
        print(f"\n--- Analyzing: {name} ({len(source_nums)} letters) ---")
        t1 = time.time()
        result = analyze_text(name, source_nums, variants)
        elapsed = time.time() - t1
        all_results[name] = result

        for variant in variants:
            vr = result.get(variant, {})
            if 'error' in result:
                print(f"  ERROR: {result['error']}")
                continue
            total = result['total_offsets']
            print(f"\n  {variant.upper()}:")
            print(f"    Total offsets: {total}")
            print(f"    Bean eq pass: {vr['bean_eq_pass']} ({100*vr['bean_eq_pass']/total:.2f}%)")
            print(f"    Bean full pass: {vr['bean_full_pass']} ({100*vr['bean_full_pass']/total:.2f}%)")
            print(f"    Max matching: {vr['max_matching']}/24")
            print(f"    Offsets with matching=24: {vr['feasible_24']}")
            print(f"    Offsets with matching=24 + Bean: {vr['feasible_24_bean']}")
            print(f"    Offsets with matching>=23: {vr['feasible_23_plus']}")
            print(f"    Offsets with matching>=22: {vr['feasible_22_plus']}")

            # Distribution summary
            dist = vr['matching_distribution']
            print(f"    Matching distribution (top 8):")
            for score in sorted(dist.keys(), reverse=True)[:8]:
                print(f"      {score}/24: {dist[score]} offsets ({100*dist[score]/total:.2f}%)")

            # Top offsets
            if vr['top_offsets']:
                top = vr['top_offsets'][:5]
                print(f"    Top-5 offsets:")
                for t in top:
                    print(f"      offset={t['offset']}: matching={t['matching']}/24, "
                          f"bean_eq={t['bean_eq']}, bean_full={t['bean_full']}")

        print(f"  Time: {elapsed:.1f}s")

    print("\n" + "=" * 70)
    print("PHASE 2: Random English Baseline (Monte Carlo)")
    print("=" * 70)

    import random
    random.seed(42)

    n_mc_texts = 20
    mc_length = 200000  # 200K chars each
    mc_results = {v: {'max_matching_list': [], 'feasible_24_list': [],
                      'feasible_24_bean_list': [], 'matching_dist': Counter()}
                  for v in variants}

    for trial in range(n_mc_texts):
        source = generate_random_english(mc_length)
        result = analyze_text(f"random_{trial}", source, variants)
        for v in variants:
            vr = result[v]
            mc_results[v]['max_matching_list'].append(vr['max_matching'])
            mc_results[v]['feasible_24_list'].append(vr['feasible_24'])
            mc_results[v]['feasible_24_bean_list'].append(vr['feasible_24_bean'])
            for score, count in vr['matching_distribution'].items():
                mc_results[v]['matching_dist'][score] += count

    for variant in variants:
        mcr = mc_results[variant]
        max_scores = mcr['max_matching_list']
        f24 = mcr['feasible_24_list']
        f24b = mcr['feasible_24_bean_list']
        total_offsets = n_mc_texts * (mc_length - CT_LEN + 1)

        print(f"\n  {variant.upper()} — {n_mc_texts} texts × {mc_length} chars:")
        print(f"    Max matching across all: max={max(max_scores)}/24, "
              f"mean={sum(max_scores)/len(max_scores):.1f}")
        print(f"    Feasible 24: total={sum(f24)}, "
              f"per-text mean={sum(f24)/len(f24):.1f}")
        print(f"    Feasible 24+Bean: total={sum(f24b)}, "
              f"per-text mean={sum(f24b)/len(f24b):.1f}")
        print(f"    Matching distribution (per {total_offsets} total offsets):")
        dist = mcr['matching_dist']
        for score in sorted(dist.keys(), reverse=True)[:8]:
            print(f"      {score}/24: {dist[score]} ({100*dist[score]/total_offsets:.3f}%)")

    print("\n" + "=" * 70)
    print("PHASE 3: Structural Analysis")
    print("=" * 70)

    # Expected matching per crib position: how many CT positions have
    # a given letter?
    print(f"\nCT letter count distribution:")
    for val in sorted(ct_freq.keys()):
        letter = chr(val + ord('A'))
        count = ct_freq[val]
        print(f"  {letter}: {count}", end="")
        if (val + 1) % 13 == 0:
            print()
    print()

    # For a random key value (0-25), what's the expected number of
    # CT positions matching each required letter?
    print(f"\nPer-crib expected CT matches (under random key):")
    for i in range(N_CRIBS):
        crib_pos = CRIB_POS[i]
        pt_val = CRIB_PT[i]
        # Average over all possible key values
        avg_matches = 0
        for k in range(MOD):
            required_vig = (pt_val + k) % MOD
            avg_matches += len(CT_LETTER_POSITIONS.get(required_vig, []))
        avg_matches /= MOD
        print(f"  pos {crib_pos} (PT={chr(pt_val + ord('A'))}): "
              f"avg CT matches = {avg_matches:.1f} / {CT_LEN}")

    # Average expected matching per crib position
    total_avg = sum(len(positions) for positions in CT_LETTER_POSITIONS.values()) / MOD
    print(f"\n  Overall average CT positions per required letter: {total_avg:.1f}")
    print(f"  Expected matching per crib (independent): {total_avg}/{CT_LEN} = "
          f"{total_avg/CT_LEN:.3f}")

    # Summary
    total_time = time.time() - t0
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    # Compile summary
    summary = {
        'experiment': 'E-FRAC-39',
        'description': 'Running key + transposition bipartite feasibility analysis',
        'total_time_seconds': round(total_time, 1),
        'reference_texts': {},
        'monte_carlo': {},
    }

    for name, result in all_results.items():
        if 'error' in result:
            continue
        text_summary = {'length': result['length'], 'offsets': result['total_offsets']}
        for variant in variants:
            vr = result[variant]
            text_summary[variant] = {
                'max_matching': vr['max_matching'],
                'feasible_24': vr['feasible_24'],
                'feasible_24_bean': vr['feasible_24_bean'],
                'bean_eq_pass': vr['bean_eq_pass'],
                'bean_full_pass': vr['bean_full_pass'],
            }
        summary['reference_texts'][name] = text_summary

    for variant in variants:
        mcr = mc_results[variant]
        summary['monte_carlo'][variant] = {
            'n_texts': n_mc_texts,
            'chars_per_text': mc_length,
            'max_matching_max': max(mcr['max_matching_list']),
            'max_matching_mean': sum(mcr['max_matching_list']) / len(mcr['max_matching_list']),
            'feasible_24_total': sum(mcr['feasible_24_list']),
            'feasible_24_per_text_mean': sum(mcr['feasible_24_list']) / len(mcr['feasible_24_list']),
            'feasible_24_bean_total': sum(mcr['feasible_24_bean_list']),
        }

    # Print key findings
    print()
    for name, ts in summary['reference_texts'].items():
        for variant in variants:
            vs = ts[variant]
            status = "FEASIBLE" if vs['feasible_24_bean'] > 0 else "INFEASIBLE" if vs['max_matching'] < 24 else "NO_BEAN_MATCH"
            print(f"  {name} ({variant}): max={vs['max_matching']}/24, "
                  f"24/24={vs['feasible_24']}, 24/24+Bean={vs['feasible_24_bean']} → {status}")

    print(f"\n  Monte Carlo baseline (per 200K-char random English text):")
    for variant in variants:
        mc = summary['monte_carlo'][variant]
        print(f"    {variant}: max={mc['max_matching_max']}/24, "
              f"24/24 per text={mc['feasible_24_per_text_mean']:.1f}, "
              f"24/24+Bean total={mc['feasible_24_bean_total']}")

    # Verdict
    any_feasible = any(
        ts[v]['feasible_24_bean'] > 0
        for ts in summary['reference_texts'].values()
        for v in variants
    )

    if any_feasible:
        verdict = "FEASIBLE_OFFSETS_EXIST — some reference text offsets can reach 24/24+Bean under some transposition"
    else:
        # Check if any reach 24 without Bean
        any_24_no_bean = any(
            ts[v]['feasible_24'] > 0
            for ts in summary['reference_texts'].values()
            for v in variants
        )
        if any_24_no_bean:
            verdict = "MATCHING_24_EXISTS_BUT_NO_BEAN — offsets exist with matching=24 but none pass Bean"
        else:
            max_overall = max(
                ts[v]['max_matching']
                for ts in summary['reference_texts'].values()
                for v in variants
            )
            verdict = f"STRUCTURALLY_INFEASIBLE — max matching {max_overall}/24 across all reference texts, no offset can reach 24/24 under ANY transposition"

    summary['verdict'] = verdict
    print(f"\n  VERDICT: {verdict}")
    print(f"\n  Total runtime: {total_time:.1f}s")

    # Save results
    results_dir = os.path.join(base, 'results', 'frac')
    os.makedirs(results_dir, exist_ok=True)
    outpath = os.path.join(results_dir, 'e_frac_39_running_key_bipartite.json')
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Results saved to: {outpath}")

    print("\n" + "=" * 70)
    print("RESULT: " + verdict)
    print("=" * 70)


if __name__ == '__main__':
    main()
