#!/usr/bin/env python3
"""Mono-invariant running-key discriminator for the surviving structured model.

Cipher:   Mono + Trans + Running Key (E-FRAC-54 branch)
Family:   analysis
Status:   active
Keyspace: 36 triples × widths 2-10 × orderings × 3 variants
Last run: 2026-03-27
Best score: TBD

MODEL: CT73 = Mono(Trans(Sub(PT73, K_text)))
  - K_text is English running key (73 chars)
  - Sub is Beaufort/Vigenère
  - Trans is columnar transposition
  - Mono is a letter permutation (26! possibilities)

KEY INSIGHT: The 24 keystream values at crib positions are linear in 14
unknown Mono parameters (one per distinct CT letter at crib positions).
Positions sharing the same CT letter impose MONO-INVARIANT forced-difference
constraints on the running key. These constraints hold regardless of Mono.

DISCRIMINATOR DESIGN:
Phase A — Mono-invariant structural constraints:
  For same-CT-letter crib pairs at adjacent key positions, the key
  difference is FIXED. Check against English bigram-difference probabilities.

Phase B — Hill-climb quadgram optimization:
  For fragments of length ≥6, hill-climb over the 14 M variables to
  maximize quadgram score. Compare best achieved score to a null
  distribution from random permutations.

Phase C — Cross-fragment global consistency:
  For configs with multiple long fragments sharing M variables, check
  whether the best M assignment from one fragment also scores well
  in others.

ASSUMPTIONS (from repo doctrine):
  - Beaufort A=0 is the default variant (CLAUDE.md Key Gotchas)
  - All positions 0-indexed
  - Constants imported from kryptos.kernel.constants
"""

import sys
import os
import time
import random
import json
from collections import defaultdict
from itertools import combinations, permutations as iterperms

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_DICT, CRIB_POSITIONS,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.transposition import (
    columnar_perm, keyword_to_order,
)

random.seed(20260327)

# ═══════════════════════════════════════════════════════════════════════════
# CRIB DATA
# ═══════════════════════════════════════════════════════════════════════════

ORIG_CRIB_POS = list(range(21, 34)) + list(range(63, 74))
CRIB_CT_LETTERS = [CT[p] for p in ORIG_CRIB_POS]
CRIB_PT_LETTERS = [CRIB_DICT[p] for p in ORIG_CRIB_POS]
CRIB_PT_NUMS = [ALPH_IDX[c] for c in CRIB_PT_LETTERS]

# For each variant, the raw keystream value K_raw[i] = f(CT[crib_i], PT[crib_i])
# With mono: K_actual[j] = (Mono_inv_num(CT[crib_i]) + PT_num[i]) mod 26  [Beaufort]
# So K[perm[s_i]] = (M_{CT_letter_i} + PT_num_i) mod 26
# where M_c is the unknown Mono⁻¹ numeric value for CT letter c.

# Distinct CT letters at crib positions
DISTINCT_CT = sorted(set(CRIB_CT_LETTERS))
CT_LETTER_IDX = {c: i for i, c in enumerate(DISTINCT_CT)}
N_M = len(DISTINCT_CT)

print(f"Distinct CT letters at crib positions: {DISTINCT_CT} ({N_M} total)")

# For each crib position, record (CT_letter_index, PT_offset)
CRIB_INFO = []
for i in range(24):
    ct_idx = CT_LETTER_IDX[CRIB_CT_LETTERS[i]]
    pt_num = CRIB_PT_NUMS[i]
    CRIB_INFO.append((ct_idx, pt_num))

# ═══════════════════════════════════════════════════════════════════════════
# (a1, a2, a3) TRIPLE ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════

# Segment null counts from consensus
SEG1_CONSENSUS = len([p for p in CONSENSUS_NULL_POSITIONS if p < 21])
SEG2_CONSENSUS = len([p for p in CONSENSUS_NULL_POSITIONS if 34 <= p <= 62])
SEG3_CONSENSUS = len([p for p in CONSENSUS_NULL_POSITIONS if p >= 74])

# Available extra positions per segment
EXTRA_CANDIDATES = sorted(set(
    i for i, c in enumerate(CT) if c in NULL_PALETTE
) - CRIB_POSITIONS - CONSENSUS_NULL_POSITIONS)

SEG1_EXTRA_AVAIL = len([p for p in EXTRA_CANDIDATES if p < 21])
SEG2_EXTRA_AVAIL = len([p for p in EXTRA_CANDIDATES if 34 <= p <= 62])
SEG3_EXTRA_AVAIL = len([p for p in EXTRA_CANDIDATES if p >= 74])

ADDITIONAL_NEEDED = 7

def generate_triples():
    """Generate all valid (a1, a2, a3) triples."""
    triples = []
    for a1 in range(min(ADDITIONAL_NEEDED, SEG1_EXTRA_AVAIL) + 1):
        for a2 in range(min(ADDITIONAL_NEEDED - a1, SEG2_EXTRA_AVAIL) + 1):
            a3 = ADDITIONAL_NEEDED - a1 - a2
            if 0 <= a3 <= SEG3_EXTRA_AVAIL:
                triples.append((a1, a2, a3))
    return triples

def shifted_cribs_for_triple(a1, a2, a3):
    """Compute shifted crib positions for a given (a1,a2,a3) triple."""
    nulls_before_ene = SEG1_CONSENSUS + a1
    ene_start = 21 - nulls_before_ene
    nulls_before_bcl = SEG1_CONSENSUS + a1 + SEG2_CONSENSUS + a2
    bcl_start = 63 - nulls_before_bcl
    ene_positions = list(range(ene_start, ene_start + 13))
    bcl_positions = list(range(bcl_start, bcl_start + 11))
    return ene_positions + bcl_positions

# ═══════════════════════════════════════════════════════════════════════════
# FRAGMENT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def find_fragments_with_info(key_positions, crib_indices, min_len=2):
    """Find contiguous runs of key positions with their crib data.

    Returns list of fragments, each is a list of (key_pos, crib_index) tuples.
    """
    if not key_positions:
        return []

    pairs = sorted(zip(key_positions, crib_indices), key=lambda x: x[0])

    fragments = []
    current = [pairs[0]]
    for i in range(1, len(pairs)):
        if pairs[i][0] == current[-1][0] + 1:
            current.append(pairs[i])
        else:
            if len(current) >= min_len:
                fragments.append(current)
            current = [pairs[i]]
    if len(current) >= min_len:
        fragments.append(current)

    return fragments


def fragment_to_key_expr(fragment):
    """Convert a fragment to a list of (M_index, PT_offset) tuples.

    Key value at each position: K = (M[ct_idx] + pt_offset) mod 26
    """
    exprs = []
    for key_pos, crib_idx in fragment:
        ct_idx, pt_num = CRIB_INFO[crib_idx]
        exprs.append((ct_idx, pt_num))
    return exprs


def evaluate_fragment(exprs, M_values):
    """Compute fragment text given M values.

    Returns string of key letters.
    """
    chars = []
    for ct_idx, pt_offset in exprs:
        val = (M_values[ct_idx] + pt_offset) % MOD
        chars.append(ALPH[val])
    return "".join(chars)


# ═══════════════════════════════════════════════════════════════════════════
# MONO-INVARIANT CONSTRAINTS (Phase A)
# ═══════════════════════════════════════════════════════════════════════════

def extract_forced_constraints(fragment):
    """Extract mono-invariant forced-difference constraints.

    For pairs in the fragment sharing the same CT letter index, the
    key difference is (PT_j - PT_i) mod 26, independent of Mono.

    Returns list of (pos_i_in_frag, pos_j_in_frag, forced_diff, distance_in_key).
    """
    exprs = fragment_to_key_expr(fragment)
    constraints = []
    for i in range(len(exprs)):
        for j in range(i + 1, len(exprs)):
            if exprs[i][0] == exprs[j][0]:  # same CT letter
                forced_diff = (exprs[j][1] - exprs[i][1]) % MOD
                key_dist = fragment[j][0] - fragment[i][0]
                constraints.append((i, j, forced_diff, key_dist))
    return constraints


# ═══════════════════════════════════════════════════════════════════════════
# HILL CLIMBER (Phase B)
# ═══════════════════════════════════════════════════════════════════════════

def hill_climb_fragment(exprs, scorer, n_restarts=20, max_iters=50):
    """Hill-climb M values to maximize quadgram score of fragment.

    Returns (best_score_per_char, best_M, best_text).
    """
    frag_len = len(exprs)
    if frag_len < 4:
        return -999, None, None

    # Identify which M indices are used
    used_m = sorted(set(ct_idx for ct_idx, _ in exprs))
    m_positions = {m: i for i, m in enumerate(used_m)}

    best_global = (-999, None, None)

    for restart in range(n_restarts):
        # Random initial M values (only for used indices)
        M = [random.randint(0, 25) for _ in range(N_M)]

        for iteration in range(max_iters):
            improved = False
            for m_idx in used_m:
                best_val = M[m_idx]
                best_score = -999
                for v in range(26):
                    M[m_idx] = v
                    text = evaluate_fragment(exprs, M)
                    sc = scorer.score_per_char(text)
                    if sc > best_score:
                        best_score = sc
                        best_val = v
                M[m_idx] = best_val
                if best_score > best_global[0]:
                    improved = True

            text = evaluate_fragment(exprs, M)
            sc = scorer.score_per_char(text)
            if sc > best_global[0]:
                best_global = (sc, list(M), text)

            if not improved:
                break

    return best_global


# ═══════════════════════════════════════════════════════════════════════════
# NULL DISTRIBUTION (random permutations)
# ═══════════════════════════════════════════════════════════════════════════

def null_score_distribution(frag_len, n_m_used, scorer, n_samples=200):
    """Generate null distribution by hill-climbing random fragment structures.

    Creates random (ct_idx, pt_offset) expressions of the same length and
    number of M variables, then hill-climbs.
    """
    scores = []
    for _ in range(n_samples):
        # Random expressions with same structure
        random_exprs = [
            (random.randint(0, n_m_used - 1), random.randint(0, 25))
            for _ in range(frag_len)
        ]
        sc, _, _ = hill_climb_fragment(random_exprs, scorer, n_restarts=5, max_iters=30)
        scores.append(sc)
    return scores


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("MONO-INVARIANT RUNNING-KEY DISCRIMINATOR")
    print("Model: CT73 = Mono(Trans(Beaufort(PT73, K_english)))")
    print("=" * 78)
    print()

    scorer = get_default_scorer()
    print(f"Quadgram scorer loaded (floor={scorer._floor:.3f})")
    print(f"Distinct CT letters at cribs: {N_M}")
    print(f"Crib CT letters: {''.join(CRIB_CT_LETTERS)}")
    print(f"Crib PT letters: {''.join(CRIB_PT_LETTERS)}")
    print()

    triples = generate_triples()
    print(f"Valid (a1,a2,a3) triples: {len(triples)}")

    # ── Phase A: Structural survey — which configs produce long fragments? ──
    print()
    print("=" * 78)
    print("PHASE A: FRAGMENT STRUCTURE SURVEY")
    print("=" * 78)

    WIDTHS = list(range(2, 11))
    t0 = time.time()
    all_configs = []

    for a1, a2, a3 in triples:
        shifted = shifted_cribs_for_triple(a1, a2, a3)

        for w in WIDTHS:
            # Generate orderings
            if w <= 7:
                orderings = list(iterperms(range(w)))
            else:
                orderings = [tuple(range(w))]
                for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW",
                           "DEFECTOR", "KOMPASS"]:
                    order = keyword_to_order(kw, w)
                    if order and order not in orderings:
                        orderings.append(order)

            for oi, ordering in enumerate(orderings):
                perm = columnar_perm(w, ordering, length=73)
                key_positions = [perm[s] for s in shifted]
                crib_indices = list(range(24))

                fragments = find_fragments_with_info(key_positions, crib_indices, min_len=6)
                if not fragments:
                    continue

                max_frag = max(fragments, key=len)
                exprs = fragment_to_key_expr(max_frag)
                n_m_used = len(set(ct_idx for ct_idx, _ in exprs))
                forced = extract_forced_constraints(max_frag)

                all_configs.append({
                    'triple': (a1, a2, a3),
                    'width': w,
                    'ordering_idx': oi,
                    'ordering': ordering,
                    'frag_len': len(max_frag),
                    'n_m_used': n_m_used,
                    'n_forced': len(forced),
                    'fragment': max_frag,
                    'exprs': exprs,
                    'forced_constraints': forced,
                    'all_fragments': fragments,
                })

    print(f"Configs with fragment ≥6: {len(all_configs)}")
    print(f"Survey took {time.time()-t0:.1f}s")

    if not all_configs:
        print("\nNo configurations produce fragments of length ≥6.")
        print("VERDICT: Mono+Trans+Running key cannot be tested with fragment")
        print("analysis at these widths. The model remains underdetermined.")
        return

    # Distribution of fragment lengths
    frag_len_dist = defaultdict(int)
    for c in all_configs:
        frag_len_dist[c['frag_len']] += 1
    print(f"\nFragment length distribution:")
    for fl in sorted(frag_len_dist):
        print(f"  Length {fl:2d}: {frag_len_dist[fl]} configs")

    # Show top configs by fragment length
    all_configs.sort(key=lambda x: (-x['frag_len'], -x['n_forced']))
    print(f"\nTop 10 configs by fragment length:")
    print(f"{'Triple':>12} {'Width':>5} {'Ord#':>5} {'FragLen':>8} "
          f"{'#M_used':>8} {'#Forced':>8}")
    print("-" * 55)
    for c in all_configs[:10]:
        print(f"{str(c['triple']):>12} {c['width']:5d} {c['ordering_idx']:5d} "
              f"{c['frag_len']:8d} {c['n_m_used']:8d} {c['n_forced']:8d}")

    # ── Phase A.2: Mono-invariant forced constraints ──
    print()
    print("=" * 78)
    print("PHASE A.2: MONO-INVARIANT FORCED CONSTRAINTS")
    print("=" * 78)

    best_config = all_configs[0]
    print(f"\nBest config: triple={best_config['triple']}, "
          f"width={best_config['width']}, frag_len={best_config['frag_len']}")
    print(f"M variables used: {best_config['n_m_used']}/{N_M}")
    print(f"Forced constraints: {best_config['n_forced']}")
    print(f"\nForced same-CT-letter constraints (mono-invariant):")
    for pi, pj, diff, dist in best_config['forced_constraints']:
        ci = CRIB_INFO[best_config['fragment'][pi][1]]
        cj = CRIB_INFO[best_config['fragment'][pj][1]]
        ct_letter = DISTINCT_CT[ci[0]]
        pt_i = ALPH[ci[1]]
        pt_j = ALPH[cj[1]]
        print(f"  frag[{pi}]↔frag[{pj}]: CT={ct_letter}, "
              f"PT={pt_i}→{pt_j}, forced K_diff={diff}, key_distance={dist}")

    # ── Phase B: Hill-climb optimization ──
    print()
    print("=" * 78)
    print("PHASE B: HILL-CLIMB QUADGRAM OPTIMIZATION")
    print("=" * 78)

    # Process top configs (those with longest fragments)
    MAX_CONFIGS_TO_CLIMB = min(200, len(all_configs))
    climb_results = []
    t1 = time.time()

    for ci, config in enumerate(all_configs[:MAX_CONFIGS_TO_CLIMB]):
        if ci % 50 == 0:
            print(f"  Hill-climbing config {ci}/{MAX_CONFIGS_TO_CLIMB}...")

        sc, M_best, text_best = hill_climb_fragment(
            config['exprs'], scorer, n_restarts=30, max_iters=60
        )
        config['best_score'] = sc
        config['best_text'] = text_best
        config['best_M'] = M_best
        climb_results.append(config)

    climb_results.sort(key=lambda x: -x['best_score'])
    print(f"\nHill-climbing took {time.time()-t1:.1f}s for {MAX_CONFIGS_TO_CLIMB} configs")

    print(f"\nTop 15 hill-climbed results:")
    print(f"{'Rank':>5} {'Score':>8} {'FragLen':>8} {'Triple':>12} "
          f"{'Width':>5} {'Text':<30}")
    print("-" * 75)
    for i, c in enumerate(climb_results[:15]):
        text = c['best_text'] or ""
        if len(text) > 28:
            text = text[:25] + "..."
        print(f"{i+1:5d} {c['best_score']:8.4f} {c['frag_len']:8d} "
              f"{str(c['triple']):>12} {c['width']:5d} {text:<30}")

    # ── Phase C: Null distribution comparison ──
    print()
    print("=" * 78)
    print("PHASE C: NULL DISTRIBUTION — Is the best score significant?")
    print("=" * 78)

    top_config = climb_results[0]
    frag_len = top_config['frag_len']
    n_m_used = top_config['n_m_used']
    observed_score = top_config['best_score']

    print(f"\nObserved best: score={observed_score:.4f}, frag_len={frag_len}, "
          f"n_M_used={n_m_used}")
    print(f"Generating null distribution (random fragment structures, same length/DOF)...")

    null_scores = null_score_distribution(frag_len, n_m_used, scorer, n_samples=500)
    null_scores.sort()
    null_mean = sum(null_scores) / len(null_scores)
    null_std = (sum((s - null_mean)**2 for s in null_scores) / len(null_scores)) ** 0.5
    null_max = max(null_scores)
    pct = sum(1 for s in null_scores if s <= observed_score) / len(null_scores) * 100

    print(f"Null distribution (N={len(null_scores)}):")
    print(f"  Mean: {null_mean:.4f}")
    print(f"  Std:  {null_std:.4f}")
    print(f"  Max:  {null_max:.4f}")
    print(f"  Observed percentile: {pct:.1f}%")
    if null_std > 0:
        z = (observed_score - null_mean) / null_std
        print(f"  Z-score: {z:.2f}")
    else:
        z = 0

    # ── Phase D: Cross-fragment consistency ──
    print()
    print("=" * 78)
    print("PHASE D: CROSS-FRAGMENT CONSISTENCY")
    print("=" * 78)

    # For configs with multiple long fragments, check if the best M from
    # the longest fragment also scores well on shorter fragments
    multi_frag_configs = [c for c in climb_results if len(c['all_fragments']) > 1
                          and c['best_M'] is not None]

    if multi_frag_configs:
        print(f"\n{len(multi_frag_configs)} configs have multiple fragments. "
              f"Testing cross-fragment consistency...")

        for c in multi_frag_configs[:10]:
            M = c['best_M']
            scores = []
            texts = []
            for frag in c['all_fragments']:
                exprs = fragment_to_key_expr(frag)
                text = evaluate_fragment(exprs, M)
                sc = scorer.score_per_char(text) if len(text) >= 4 else -999
                scores.append(sc)
                texts.append(text)

            c['cross_scores'] = scores
            c['cross_texts'] = texts
            print(f"  Triple={c['triple']} w={c['width']}: "
                  f"scores={[round(s,3) for s in scores]}, "
                  f"texts={texts}")
    else:
        print("No configs with multiple long fragments found.")

    # ── Phase E: Variant comparison ──
    # Beaufort is the default (CLAUDE.md), but test Vigenère too
    print()
    print("=" * 78)
    print("PHASE E: VARIANT COMPARISON (Beaufort vs Vigenère)")
    print("=" * 78)

    # Recompute CRIB_INFO for Vigenère: K = (CT - PT) mod 26
    # With mono: K[perm[s_i]] = (Mono_inv(CT_i) - PT_i) mod 26 [Vig]
    # But Mono_inv just shifts, so the structure is the same with different offsets
    # For Vigenère: K = (M_{CT_letter} - PT_num) mod 26
    # vs Beaufort: K = (M_{CT_letter} + PT_num) mod 26
    # The sign change means different forced constraints

    CRIB_INFO_VIG = []
    for i in range(24):
        ct_idx = CT_LETTER_IDX[CRIB_CT_LETTERS[i]]
        pt_num = CRIB_PT_NUMS[i]
        CRIB_INFO_VIG.append((ct_idx, (MOD - pt_num) % MOD))  # negate PT for Vig

    # Redo hill-climb for top Beaufort configs under Vigenère
    print(f"Re-climbing top 20 configs under Vigenère...")
    vig_results = []
    for c in climb_results[:20]:
        frag = c['fragment']
        vig_exprs = []
        for key_pos, crib_idx in frag:
            ct_idx, neg_pt = CRIB_INFO_VIG[crib_idx]
            vig_exprs.append((ct_idx, neg_pt))
        sc, M_best, text_best = hill_climb_fragment(
            vig_exprs, scorer, n_restarts=30, max_iters=60
        )
        vig_results.append((c['triple'], c['width'], sc, text_best))

    print(f"\n{'Triple':>12} {'Width':>5} {'Beau_score':>11} {'Vig_score':>11} "
          f"{'Beau_text':<25} {'Vig_text':<25}")
    print("-" * 95)
    for i, (c, vr) in enumerate(zip(climb_results[:20], vig_results)):
        bt = (c.get('best_text') or "")[:23]
        vt = (vr[3] or "")[:23]
        print(f"{str(c['triple']):>12} {c['width']:5d} {c['best_score']:11.4f} "
              f"{vr[2]:11.4f} {bt:<25} {vt:<25}")

    # ── VERDICT ──
    print()
    print("=" * 78)
    print("VERDICT")
    print("=" * 78)

    if observed_score > -3.5 and pct > 97:
        print(f"\n*** SIGNAL: Best score {observed_score:.4f} exceeds 97th percentile")
        print(f"    of null distribution. INVESTIGATE this configuration.")
    elif pct > 90:
        print(f"\nMARGINAL: Best score {observed_score:.4f} at {pct:.1f}th percentile.")
        print(f"Worth noting but not significant after search multiplicity.")
    else:
        print(f"\nNO SIGNAL: Best score {observed_score:.4f} at {pct:.1f}th percentile.")
        print(f"The hill-climbed fragments are NOT distinguishable from random")
        print(f"constraint systems with the same structure.")
        print(f"\nThis means the mono layer's {N_M} DOF are sufficient to produce")
        print(f"English-like fragments from ANY underlying model, confirming")
        print(f"E-FRAC-54's underdetermination finding.")

    print(f"\nKey structural facts:")
    print(f"  - Max fragment length achievable: {all_configs[0]['frag_len']}")
    print(f"  - M variables used in longest fragment: {all_configs[0]['n_m_used']}/{N_M}")
    print(f"  - Forced mono-invariant constraints: {all_configs[0]['n_forced']}")
    print(f"  - Overconstrained positions: {all_configs[0]['frag_len'] - all_configs[0]['n_m_used']}")

    # Save results
    result_path = os.path.join(_ROOT, "results", "mono_runkey_discriminator_01.json")
    save_data = {
        'experiment': 'e_mono_runkey_discriminator_01',
        'n_triples': len(triples),
        'n_configs_with_long_frags': len(all_configs),
        'max_frag_len': all_configs[0]['frag_len'] if all_configs else 0,
        'best_score': round(observed_score, 4),
        'best_text': top_config.get('best_text'),
        'best_triple': top_config['triple'],
        'best_width': top_config['width'],
        'null_mean': round(null_mean, 4),
        'null_std': round(null_std, 4),
        'null_max': round(null_max, 4),
        'observed_percentile': round(pct, 1),
        'z_score': round(z, 2),
        'n_forced_constraints': top_config['n_forced'],
        'frag_len_distribution': dict(frag_len_dist),
    }
    with open(result_path, 'w') as f:
        json.dump(save_data, f, indent=2)
    print(f"\nResults saved to {result_path}")


if __name__ == "__main__":
    main()
