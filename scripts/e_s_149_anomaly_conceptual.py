#!/usr/bin/env python3
"""E-S-149: Anomaly "Enactment" Model — Cut-point rearrangements.

Tests whether anomalies in K0/K1 encode the ORDER of operations or
cut-point locations for segment rearrangement of K4 CT, rather than
literal cipher parameters.

Three sub-experiments:

1. LITERAL CUT POSITIONS: The position of each anomaly within its word:
   - WHAT: cut at position 0 (W removed from start)
   - DIGITAL: cut at position 3 (I→E at 4th char)
   - INTERPRETATION: cut at position 12-13 (end truncated)
   - ILLUSION: cut at position 1 (L→Q at 2nd char)
   Cut points: [0, 1, 3, 13] (sorted). Split CT into 5 segments,
   test all 120 permutations (5!) with Vig/Beau using ABSCISSA and PALIMPSEST.

2. PROPORTIONAL CUT POSITIONS: Scale to K4 length (97/14 ≈ 6.93):
   0→0, 3→21, 12→83, 1→7 → sorted: [0, 7, 21, 83]
   Note: 21 and 83 are near crib boundaries! Segments: [0:7],[7:21],[21:83],[83:97]
   Test all 24 permutations (4 segments) with Vig/Beau using ABSCISSA and PALIMPSEST.

3. FOUR-SEGMENT MODEL (explicit cuts at crib boundaries):
   Also try: [0, 21, 34, 63] and [0, 21, 63, 74] — exact crib-word boundaries.
   These test whether anomalies hint at "cut around the cribs."
   24 perms each x 2 keywords x 2 variants.

Scoring: crib_score from kryptos.kernel.scoring.crib_score.

Output: artifacts/e_s_149/
Repro: PYTHONPATH=src python3 -u scripts/e_s_149_anomaly_conceptual.py
"""

import itertools
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

# ── Constants ────────────────────────────────────────────────────────────────

N = CT_LEN  # 97
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Keywords to test as repeating Vigenere/Beaufort keys
KEYWORDS = {
    "ABSCISSA": [ALPH_IDX[c] for c in "ABSCISSA"],
    "PALIMPSEST": [ALPH_IDX[c] for c in "PALIMPSEST"],
    "KRYPTOS": [ALPH_IDX[c] for c in "KRYPTOS"],
}

# Cipher variants
def vig_decrypt_char(c_idx, k_idx):
    return (c_idx - k_idx) % MOD

def beau_decrypt_char(c_idx, k_idx):
    return (k_idx - c_idx) % MOD

VARIANTS = {
    "vigenere": vig_decrypt_char,
    "beaufort": beau_decrypt_char,
}


def decrypt_with_keyword(ct_text, keyword_nums, variant_fn):
    """Decrypt ct_text with repeating keyword under given variant."""
    klen = len(keyword_nums)
    result = []
    for i, ch in enumerate(ct_text):
        c_idx = ALPH_IDX[ch]
        k_idx = keyword_nums[i % klen]
        p_idx = variant_fn(c_idx, k_idx)
        result.append(ALPH[p_idx])
    return ''.join(result)


def rearrange_segments(ct_text, cut_points, perm):
    """Split ct_text at cut_points, rearrange segments per perm.

    cut_points: sorted list of positions where segments start (excluding 0 if it's implicit).
    We always include 0 as start and len(ct_text) as end.

    perm: permutation of segment indices [0..n_segments-1]
    """
    # Build segment boundaries
    boundaries = sorted(set([0] + list(cut_points) + [len(ct_text)]))
    segments = []
    for i in range(len(boundaries) - 1):
        seg = ct_text[boundaries[i]:boundaries[i + 1]]
        if seg:  # skip empty segments
            segments.append(seg)

    if len(perm) != len(segments):
        return None

    return ''.join(segments[p] for p in perm)


def test_cut_point_set(label, ct_text, cut_points, keywords, variants, max_perms=None):
    """Test all segment rearrangements for a set of cut points.

    Returns list of results sorted by best crib score.
    """
    # Build segments
    boundaries = sorted(set([0] + list(cut_points) + [len(ct_text)]))
    segments = []
    seg_ranges = []
    for i in range(len(boundaries) - 1):
        seg = ct_text[boundaries[i]:boundaries[i + 1]]
        if seg:
            segments.append(seg)
            seg_ranges.append((boundaries[i], boundaries[i + 1]))

    n_seg = len(segments)
    print(f"\n  {label}: {n_seg} segments, boundaries={boundaries}")
    for i, (start, end) in enumerate(seg_ranges):
        print(f"    Seg {i}: [{start}:{end}] len={end-start} = {segments[i][:20]}{'...' if len(segments[i])>20 else ''}")

    all_perms = list(itertools.permutations(range(n_seg)))
    if max_perms and len(all_perms) > max_perms:
        print(f"    {len(all_perms)} permutations (capped at {max_perms})")
        all_perms = all_perms[:max_perms]
    else:
        print(f"    {len(all_perms)} permutations")

    results = []
    best_score = 0
    best_config = None
    configs_tested = 0

    for perm in all_perms:
        rearranged = ''.join(segments[p] for p in perm)
        assert len(rearranged) == len(ct_text), f"Length mismatch: {len(rearranged)} vs {len(ct_text)}"

        for kw_name, kw_nums in keywords.items():
            for var_name, var_fn in variants.items():
                pt = decrypt_with_keyword(rearranged, kw_nums, var_fn)
                detail = score_cribs_detailed(pt)
                sc = detail['score']
                configs_tested += 1

                if sc > NOISE_FLOOR:
                    results.append({
                        'perm': list(perm),
                        'keyword': kw_name,
                        'variant': var_name,
                        'crib_score': sc,
                        'ene_score': detail['ene_score'],
                        'bc_score': detail['bc_score'],
                        'classification': detail['classification'],
                        'plaintext': pt,
                    })

                if sc > best_score:
                    best_score = sc
                    best_config = {
                        'perm': list(perm),
                        'keyword': kw_name,
                        'variant': var_name,
                        'crib_score': sc,
                        'ene_score': detail['ene_score'],
                        'bc_score': detail['bc_score'],
                        'plaintext': pt,
                    }

    print(f"    Configs tested: {configs_tested}")
    print(f"    Best crib score: {best_score}/24")
    if best_config:
        print(f"    Best config: perm={best_config['perm']} "
              f"kw={best_config['keyword']} var={best_config['variant']}")
        print(f"    ENE={best_config['ene_score']}/13 BC={best_config['bc_score']}/11")
        if best_score >= SIGNAL_THRESHOLD:
            print(f"    *** SIGNAL: PT={best_config['plaintext']}")
        elif best_score > NOISE_FLOOR:
            print(f"    PT preview: {best_config['plaintext'][:50]}...")

    # Count by score tier
    above_noise = [r for r in results if r['crib_score'] > NOISE_FLOOR]
    above_store = [r for r in results if r['crib_score'] >= 10]
    above_signal = [r for r in results if r['crib_score'] >= SIGNAL_THRESHOLD]
    print(f"    Score distribution: >6={len(above_noise)}, >=10={len(above_store)}, >=18={len(above_signal)}")

    return {
        'label': label,
        'cut_points': list(cut_points),
        'boundaries': boundaries,
        'n_segments': n_seg,
        'segment_lengths': [len(s) for s in segments],
        'configs_tested': configs_tested,
        'best_score': best_score,
        'best_config': best_config,
        'above_noise_count': len(above_noise),
        'above_signal_count': len(above_signal),
        'top_results': sorted(results, key=lambda r: -r['crib_score'])[:10],
    }


def main():
    t0 = time.time()

    print("=" * 70)
    print("E-S-149: Anomaly 'Enactment' Model — Cut-Point Rearrangements")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Length: {N}")
    print(f"Keywords: {list(KEYWORDS.keys())}")
    print(f"Variants: {list(VARIANTS.keys())}")

    all_experiment_results = {}

    # ═══════════════════════════════════════════════════════════════════════
    # Sub-experiment 1: LITERAL cut positions from anomaly word positions
    # ═══════════════════════════════════════════════════════════════════════

    print(f"\n{'='*70}")
    print("SUB-EXPERIMENT 1: Literal Anomaly Cut Positions")
    print(f"{'='*70}")
    print("Anomaly positions within words: WHAT@0, ILLUSION@1, DIGITAL@3, INTERPRETATION@12")
    print("Sorted cut points: [1, 3, 13] (0 is always a boundary)")

    # Cut points (positions where we split CT)
    # With 0 always being a boundary, cuts at 1, 3, 13 give segments:
    # [0:1], [1:3], [3:13], [13:97]
    literal_cuts = [1, 3, 13]
    result_1 = test_cut_point_set(
        "Literal cuts [0,1,3,13]",
        CT, literal_cuts, KEYWORDS, VARIANTS,
    )
    all_experiment_results['literal_cuts'] = result_1

    # Also test with all 5 segments including the 0-position as a real cut
    # (i.e., the anomaly says "cut at these character positions in K4 CT")
    literal_cuts_v2 = [1, 3, 12, 13]
    result_1b = test_cut_point_set(
        "Literal cuts v2 [0,1,3,12,13]",
        CT, literal_cuts_v2, KEYWORDS, VARIANTS, max_perms=120,
    )
    all_experiment_results['literal_cuts_v2'] = result_1b

    # ═══════════════════════════════════════════════════════════════════════
    # Sub-experiment 2: PROPORTIONAL cut positions (scaled by 97/14)
    # ═══════════════════════════════════════════════════════════════════════

    print(f"\n{'='*70}")
    print("SUB-EXPERIMENT 2: Proportional Cut Positions (scaled to K4 length)")
    print(f"{'='*70}")

    # Scale factor: 97/14 ≈ 6.929 (INTERPRETATION is 14 chars, longest anomaly word)
    # Actually the task says scale by 97/14:
    # 0 * 97/14 ≈ 0, 1 * 97/14 ≈ 7, 3 * 97/14 ≈ 21, 12 * 97/14 ≈ 83
    # Rounded: [0, 7, 21, 83]
    scale = N / 14.0
    raw_positions = [0, 1, 3, 12]
    scaled = [round(p * scale) for p in raw_positions]
    print(f"Raw positions: {raw_positions} x {scale:.3f} = {scaled}")
    print(f"NOTE: 21 = ENE crib start, 83 near BC crib end (73+10)")

    proportional_cuts = sorted(set(scaled) - {0})  # [7, 21, 83]
    result_2 = test_cut_point_set(
        f"Proportional cuts {sorted(set(scaled))}",
        CT, proportional_cuts, KEYWORDS, VARIANTS,
    )
    all_experiment_results['proportional_cuts'] = result_2

    # ═══════════════════════════════════════════════════════════════════════
    # Sub-experiment 3: Crib-boundary cut points
    # ═══════════════════════════════════════════════════════════════════════

    print(f"\n{'='*70}")
    print("SUB-EXPERIMENT 3: Crib-Boundary Cut Points")
    print(f"{'='*70}")

    # 3a: Cut at ENE start, ENE end+1, BC start
    crib_cuts_a = [21, 34, 63]
    result_3a = test_cut_point_set(
        "Crib boundaries [0,21,34,63]",
        CT, crib_cuts_a, KEYWORDS, VARIANTS,
    )
    all_experiment_results['crib_boundaries_a'] = result_3a

    # 3b: Cut at ENE start, BC start, BC end+1
    crib_cuts_b = [21, 63, 74]
    result_3b = test_cut_point_set(
        "Crib boundaries [0,21,63,74]",
        CT, crib_cuts_b, KEYWORDS, VARIANTS,
    )
    all_experiment_results['crib_boundaries_b'] = result_3b

    # 3c: Cut at all crib word boundaries
    crib_cuts_c = [21, 34, 63, 74]
    result_3c = test_cut_point_set(
        "All crib boundaries [0,21,34,63,74]",
        CT, crib_cuts_c, KEYWORDS, VARIANTS,
        max_perms=120,
    )
    all_experiment_results['crib_boundaries_all'] = result_3c

    # ═══════════════════════════════════════════════════════════════════════
    # Sub-experiment 4: Proportional cuts with more keyword variants
    # ═══════════════════════════════════════════════════════════════════════

    print(f"\n{'='*70}")
    print("SUB-EXPERIMENT 4: Proportional Cuts + Extended Keywords")
    print(f"{'='*70}")

    # Add more thematic keywords
    extended_keywords = dict(KEYWORDS)
    for extra_kw in ["IQLUSION", "DIGETAL", "SHADOW", "KRYPTOS", "BERLINCLOCK"]:
        extended_keywords[extra_kw] = [ALPH_IDX[c] for c in extra_kw]

    # Use the proportional cut points that hit near crib boundaries
    result_4 = test_cut_point_set(
        f"Proportional + extended keywords",
        CT, proportional_cuts, extended_keywords, VARIANTS,
    )
    all_experiment_results['proportional_extended'] = result_4

    # ═══════════════════════════════════════════════════════════════════════
    # Sub-experiment 5: Two-step model (rearrange THEN decrypt, vs decrypt THEN rearrange)
    # ═══════════════════════════════════════════════════════════════════════

    print(f"\n{'='*70}")
    print("SUB-EXPERIMENT 5: Decrypt-First Model (sub-trans vs trans-sub)")
    print(f"{'='*70}")
    print("Previous tests: rearrange CT segments, then decrypt (trans-sub).")
    print("Now test: decrypt CT first with keyword, then rearrange segments (sub-trans).")

    best_score_5 = 0
    best_config_5 = None
    configs_5 = 0
    results_5 = []

    for kw_name, kw_nums in KEYWORDS.items():
        for var_name, var_fn in VARIANTS.items():
            # Decrypt first
            decrypted = decrypt_with_keyword(CT, kw_nums, var_fn)

            # Then rearrange using proportional cuts (the most promising set)
            for cut_label, cuts in [
                ("proportional", proportional_cuts),
                ("crib_a", crib_cuts_a),
                ("crib_b", crib_cuts_b),
            ]:
                boundaries = sorted(set([0] + list(cuts) + [N]))
                segments = []
                for i in range(len(boundaries) - 1):
                    seg = decrypted[boundaries[i]:boundaries[i + 1]]
                    if seg:
                        segments.append(seg)

                n_seg = len(segments)
                for perm in itertools.permutations(range(n_seg)):
                    rearranged = ''.join(segments[p] for p in perm)
                    sc = score_cribs(rearranged)
                    configs_5 += 1

                    if sc > NOISE_FLOOR:
                        results_5.append({
                            'perm': list(perm),
                            'keyword': kw_name,
                            'variant': var_name,
                            'cuts': cut_label,
                            'crib_score': sc,
                            'plaintext': rearranged,
                        })

                    if sc > best_score_5:
                        best_score_5 = sc
                        best_config_5 = {
                            'perm': list(perm),
                            'keyword': kw_name,
                            'variant': var_name,
                            'cuts': cut_label,
                            'crib_score': sc,
                            'plaintext': rearranged,
                        }

    print(f"  Configs tested (sub-trans): {configs_5}")
    print(f"  Best crib score: {best_score_5}/24")
    if best_config_5:
        print(f"  Best config: kw={best_config_5['keyword']} var={best_config_5['variant']} "
              f"cuts={best_config_5['cuts']} perm={best_config_5['perm']}")
        if best_score_5 >= SIGNAL_THRESHOLD:
            print(f"  *** SIGNAL: PT={best_config_5['plaintext']}")

    above_noise_5 = len([r for r in results_5 if r['crib_score'] > NOISE_FLOOR])
    above_signal_5 = len([r for r in results_5 if r['crib_score'] >= SIGNAL_THRESHOLD])
    print(f"  Score distribution: >6={above_noise_5}, >=18={above_signal_5}")

    all_experiment_results['sub_trans_model'] = {
        'label': 'Decrypt-first (sub-trans)',
        'configs_tested': configs_5,
        'best_score': best_score_5,
        'best_config': best_config_5,
        'above_noise_count': above_noise_5,
        'above_signal_count': above_signal_5,
        'top_results': sorted(results_5, key=lambda r: -r['crib_score'])[:10],
    }

    # ═══════════════════════════════════════════════════════════════════════
    # GLOBAL SUMMARY
    # ═══════════════════════════════════════════════════════════════════════

    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print("GLOBAL SUMMARY")
    print(f"{'='*70}")

    total_configs = sum(r.get('configs_tested', 0) for r in all_experiment_results.values())
    global_best = 0
    global_best_label = None

    print(f"{'Sub-experiment':<40s} {'Configs':>8s} {'Best':>5s} {'>6':>4s} {'>=18':>4s}")
    print("-" * 65)
    for label, data in all_experiment_results.items():
        best = data.get('best_score', 0)
        configs = data.get('configs_tested', 0)
        above_n = data.get('above_noise_count', 0)
        above_s = data.get('above_signal_count', 0)
        marker = " ***" if above_s > 0 else ""
        print(f"{label:<40s} {configs:>8d} {best:>4d}/24 {above_n:>4d} {above_s:>4d}{marker}")
        if best > global_best:
            global_best = best
            global_best_label = label

    print(f"\nTotal configurations: {total_configs:,}")
    print(f"Global best score: {global_best}/24 (from {global_best_label})")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Interpretation ──────────────────────────────────────────────────────

    print(f"\nINTERPRETATION:")
    if global_best < NOISE_FLOOR:
        print(f"All scores at or below noise floor ({NOISE_FLOOR}). The anomaly-derived")
        print(f"cut positions produce NO signal under segment rearrangement with")
        print(f"standard keywords. The 'enactment' model is ELIMINATED for these")
        print(f"specific cut-point interpretations.")
    elif global_best < SIGNAL_THRESHOLD:
        print(f"Best score {global_best}/24 is above noise but below signal threshold")
        print(f"({SIGNAL_THRESHOLD}). Likely coincidental crib overlap. No actionable signal.")
    else:
        print(f"*** SIGNAL DETECTED: {global_best}/24 — requires investigation! ***")

    print(f"\nExpected random scores for segment rearrangement:")
    print(f"  4 segments, 24 perms: ~0-2 crib matches per config (most get 0)")
    print(f"  5 segments, 120 perms: slightly higher due to more configs")
    print(f"  Threshold for concern: consistent scores >6 across many configs")

    # ── VERDICT ──────────────────────────────────────────────────────────────

    verdict = "NOISE" if global_best < SIGNAL_THRESHOLD else "INVESTIGATE"
    print(f"\nVERDICT: {verdict}")

    # ── Save artifacts ──────────────────────────────────────────────────────

    artifact_dir = os.path.join(REPO_ROOT, "artifacts", "e_s_149")
    os.makedirs(artifact_dir, exist_ok=True)

    # Serialize results (strip long plaintext from non-top results)
    serializable = {}
    for label, data in all_experiment_results.items():
        entry = dict(data)
        # Keep only top 10 results with plaintext
        if 'top_results' in entry:
            for r in entry['top_results']:
                if 'plaintext' in r and len(r['plaintext']) > 100:
                    r['plaintext'] = r['plaintext'][:50] + '...'
        serializable[label] = entry

    artifact = {
        "experiment_id": "e_s_149",
        "title": "Anomaly 'Enactment' Model — Cut-Point Rearrangements",
        "total_configs": total_configs,
        "global_best_score": global_best,
        "global_best_source": global_best_label,
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "sub_experiments": serializable,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_149_anomaly_conceptual.py",
    }

    out_path = os.path.join(artifact_dir, "e_s_149_results.json")
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifact saved: {out_path}")


if __name__ == "__main__":
    main()
