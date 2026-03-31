#!/usr/bin/env python3
"""
Cipher: running key discriminator
Family: statistical
Status: active
Keyspace: ~58K transpositions (identity + columnar w6/8/9)
Last run:
Best score:
"""
"""E-KEYSTREAM-ENGLISH-01: Keystream English-Likelihood Under Transposition.

Statistical attack: under the running-key hypothesis (without mono layer),
the Beaufort keystream at crib positions IS the source text at corresponding
positions. We test whether any transposition produces keystream fragments
that score as plausible English.

For each Bean-compatible columnar ordering at widths 6, 8, 9 (plus identity):
1. Compute the inverse permutation (CT pos -> PT pos)
2. Map crib PT positions through the permutation to get source-text positions
3. Sort keystream values by source-text position order
4. Score the resulting fragments for English bigram/quadgram plausibility
5. Compare against null distribution (random 26-letter strings)

Also tests Candidate 2: cross-crib block merging. If a transposition maps
the ENE and BCL blocks to adjacent source positions, the merged fragment
has higher statistical power.

Output: JSON results with per-ordering scores, null distribution, and verdict.
"""
import itertools
import json
import os
import random
import sys
import time
from collections import defaultdict
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, BEAN_EQ, BEAN_INEQ,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
)
from kryptos.kernel.scoring.ngram import NgramScorer

# ── Constants ─────────────────────────────────────────────────────────────

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Crib blocks
ENE_START, ENE_WORD = CRIB_WORDS[0]  # (21, "EASTNORTHEAST")
BCL_START, BCL_WORD = CRIB_WORDS[1]  # (63, "BERLINCLOCK")
ENE_POSITIONS = list(range(ENE_START, ENE_START + len(ENE_WORD)))
BCL_POSITIONS = list(range(BCL_START, BCL_START + len(BCL_WORD)))
ALL_CRIB_POSITIONS = sorted(ENE_POSITIONS + BCL_POSITIONS)

# Beaufort keystream letters at each crib position (model-independent)
KEYSTREAM_AT = {}
for i, pos in enumerate(sorted(CRIB_DICT.keys())):
    KEYSTREAM_AT[pos] = BEAUFORT_KEYSTREAM_AT_CRIBS[i]

# All three variant keystreams at crib positions
VARIANT_KEYSTREAMS = {}
for pos in sorted(CRIB_DICT.keys()):
    ct_val = ALPH_IDX[CT[pos]]
    pt_val = CRIB_PT_NUM[pos]
    VARIANT_KEYSTREAMS[pos] = {
        "beaufort": (ct_val + pt_val) % MOD,
        "vigenere": (ct_val - pt_val) % MOD,
        "variant_beaufort": (pt_val - ct_val) % MOD,
    }

# ── Columnar permutation infrastructure ──────────────────────────────────


def build_col_heights(width):
    n_rows = CT_LEN // width
    remainder = CT_LEN % width
    return [n_rows + 1 if j < remainder else n_rows for j in range(width)]


def build_columnar_inv_perm(order, width, col_heights):
    """Build inverse permutation: inv_perm[pt_pos] = ct_pos.

    Columnar encryption: write PT row-by-row into grid of given width,
    read columns in order. So CT position is determined by column read order.
    inv_perm tells us: for a given PT position, which CT position was it sent to.
    """
    # Forward perm: perm[ct_pos] = pt_pos
    perm = []
    for rank in range(width):
        col = list(order).index(rank)
        height = col_heights[col]
        for row in range(height):
            perm.append(row * width + col)

    # Invert: inv[pt_pos] = ct_pos
    inv = [0] * CT_LEN
    for ct_pos, pt_pos in enumerate(perm):
        if pt_pos < CT_LEN:
            inv[pt_pos] = ct_pos
    return inv


def check_bean_eq_only(inv_perm):
    """Check Bean equality: CT at mapped positions must match."""
    for eq_a, eq_b in BEAN_EQ:
        if CT_NUM[inv_perm[eq_a]] != CT_NUM[inv_perm[eq_b]]:
            return False
    return True


def check_bean_full(inv_perm, variant="beaufort"):
    """Check Bean equality + all 242 inequalities."""
    def key_at(pt_pos):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            return (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            return (ct_val + pt_val) % MOD
        else:  # variant_beaufort
            return (pt_val - ct_val) % MOD

    for eq_a, eq_b in BEAN_EQ:
        if key_at(eq_a) != key_at(eq_b):
            return False
    for ineq_a, ineq_b in BEAN_INEQ:
        if key_at(ineq_a) == key_at(ineq_b):
            return False
    return True


# ── Fragment scoring ─────────────────────────────────────────────────────


def load_quadgram_scorer():
    """Load quadgram scorer from standard location."""
    paths = [
        os.path.join(_ROOT, "data", "english_quadgrams.json"),
        os.path.join(_ROOT, "results", "anneal_step7_start8", "english_quadgrams.json"),
    ]
    for p in paths:
        if os.path.exists(p):
            return NgramScorer.from_file(p)
    raise FileNotFoundError(f"No quadgram file found at: {paths}")


def build_bigram_scorer():
    """Build bigram log-probabilities from quadgram data (marginalize).

    Since we only have quadgrams, we compute bigram frequencies by summing
    over all quadgrams that contain each bigram as a prefix.
    """
    scorer = load_quadgram_scorer()
    # Estimate bigram logprobs from quadgram data
    bigram_counts = defaultdict(float)
    for gram, logp in scorer.log_probs.items():
        # Each quadgram ABCD contributes to bigrams AB, BC, CD
        prob = 10 ** logp  # Convert from log10
        for i in range(3):
            bigram_counts[gram[i:i+2]] += prob

    total = sum(bigram_counts.values())
    if total == 0:
        return {}

    import math
    bigram_logp = {}
    for bg, count in bigram_counts.items():
        bigram_logp[bg] = math.log10(count / total)

    return bigram_logp


def score_fragment_bigram(fragment, bigram_logp):
    """Score a text fragment using bigram log-probabilities."""
    if len(fragment) < 2:
        return -10.0
    total = 0.0
    floor = min(bigram_logp.values()) if bigram_logp else -10.0
    n = 0
    for i in range(len(fragment) - 1):
        bg = fragment[i:i+2]
        total += bigram_logp.get(bg, floor)
        n += 1
    return total / n if n > 0 else floor


def score_fragment_quadgram(fragment, scorer):
    """Score using quadgrams (requires length >= 4)."""
    if len(fragment) < 4:
        return -10.0
    return scorer.score_per_char(fragment)


# ── Core analysis: map crib positions through transposition ──────────────


def analyze_transposition(inv_perm, variant="beaufort"):
    """For a given inverse permutation, compute the source-text positions
    of crib characters and extract the keystream fragment in source order.

    Under running-key: key[i] = source_text[i], so the keystream at
    crib position p equals source_text[inv_perm[p]] (the source char
    at the CT position that maps to this PT position).

    Actually, under running key with transposition:
    - PT is written into grid, columns read off as CT
    - key[ct_pos] = source_text[ct_pos] (key aligns with CT positions)
    - Decryption: PT[pt_pos] = decrypt(CT[ct_pos], key[ct_pos])
      where ct_pos = inv_perm[pt_pos]
    - So key at crib position p is key[inv_perm[p]] = source[inv_perm[p]]
    - The keystream value we observe at p is indeed k = f(CT[inv_perm[p]], PT[p])

    We want to know: do the source-text characters at positions
    {inv_perm[p] for p in crib_positions} form English when read in order?
    """
    # Map each crib PT position to its CT position (= source-text position)
    ene_source_positions = [(inv_perm[p], p) for p in ENE_POSITIONS]
    bcl_source_positions = [(inv_perm[p], p) for p in BCL_POSITIONS]

    # Get keystream values at each crib position under specified variant
    def get_key_letter(pt_pos):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        else:
            k = (pt_val - ct_val) % MOD
        return ALPH[k]

    # Sort each block by source position to get the fragment in source order
    ene_sorted = sorted(ene_source_positions, key=lambda x: x[0])
    bcl_sorted = sorted(bcl_source_positions, key=lambda x: x[0])

    ene_fragment = "".join(get_key_letter(pt_pos) for _, pt_pos in ene_sorted)
    bcl_fragment = "".join(get_key_letter(pt_pos) for _, pt_pos in bcl_sorted)

    # Check block adjacency: how close are the two blocks in source space?
    ene_src_positions = [s for s, _ in ene_sorted]
    bcl_src_positions = [s for s, _ in bcl_sorted]

    ene_max = max(ene_src_positions)
    ene_min = min(ene_src_positions)
    bcl_max = max(bcl_src_positions)
    bcl_min = min(bcl_src_positions)

    # Gap between blocks in source space
    if ene_max < bcl_min:
        gap = bcl_min - ene_max - 1
        merged_order = "ENE_BCL"
    elif bcl_max < ene_min:
        gap = ene_min - bcl_max - 1
        merged_order = "BCL_ENE"
    else:
        gap = -1  # Overlapping/interleaved
        merged_order = "INTERLEAVED"

    # Build merged fragment (all 24 keystream chars sorted by source position)
    all_source = ene_source_positions + bcl_source_positions
    all_sorted = sorted(all_source, key=lambda x: x[0])
    merged_fragment = "".join(get_key_letter(pt_pos) for _, pt_pos in all_sorted)

    # Contiguity: are source positions consecutive within each block?
    ene_contiguous = all(
        ene_src_positions[i+1] - ene_src_positions[i] == 1
        for i in range(len(ene_src_positions) - 1)
    )
    bcl_contiguous = all(
        bcl_src_positions[i+1] - bcl_src_positions[i] == 1
        for i in range(len(bcl_src_positions) - 1)
    )

    return {
        "ene_fragment": ene_fragment,
        "bcl_fragment": bcl_fragment,
        "merged_fragment": merged_fragment,
        "ene_source_positions": ene_src_positions,
        "bcl_source_positions": bcl_src_positions,
        "block_gap": gap,
        "merged_order": merged_order,
        "ene_contiguous": ene_contiguous,
        "bcl_contiguous": bcl_contiguous,
    }


# ── Null distribution ────────────────────────────────────────────────────


def generate_null_distribution(bigram_logp, scorer, n_samples=1_000_000, seed=42):
    """Generate null distribution of fragment scores under random keystream."""
    rng = random.Random(seed)

    ene_bigram_scores = []
    bcl_bigram_scores = []
    merged_bigram_scores = []
    ene_quad_scores = []
    bcl_quad_scores = []
    merged_quad_scores = []

    for _ in range(n_samples):
        # Random 13-char fragment (ENE length)
        ene_frag = "".join(ALPH[rng.randint(0, 25)] for _ in range(13))
        # Random 11-char fragment (BCL length)
        bcl_frag = "".join(ALPH[rng.randint(0, 25)] for _ in range(11))
        # Random 24-char merged fragment
        merged_frag = "".join(ALPH[rng.randint(0, 25)] for _ in range(24))

        ene_bigram_scores.append(score_fragment_bigram(ene_frag, bigram_logp))
        bcl_bigram_scores.append(score_fragment_bigram(bcl_frag, bigram_logp))
        merged_bigram_scores.append(score_fragment_bigram(merged_frag, bigram_logp))
        ene_quad_scores.append(score_fragment_quadgram(ene_frag, scorer))
        bcl_quad_scores.append(score_fragment_quadgram(bcl_frag, scorer))
        merged_quad_scores.append(score_fragment_quadgram(merged_frag, scorer))

    return {
        "n_samples": n_samples,
        "seed": seed,
        "ene_bigram": sorted(ene_bigram_scores),
        "bcl_bigram": sorted(bcl_bigram_scores),
        "merged_bigram": sorted(merged_bigram_scores),
        "ene_quad": sorted(ene_quad_scores),
        "bcl_quad": sorted(bcl_quad_scores),
        "merged_quad": sorted(merged_quad_scores),
    }


def percentile_rank(sorted_dist, value):
    """What fraction of the null distribution is <= value."""
    import bisect
    idx = bisect.bisect_right(sorted_dist, value)
    return idx / len(sorted_dist)


# ── Worker for parallel columnar enumeration ─────────────────────────────


def evaluate_ordering(args):
    """Evaluate a single columnar ordering. Returns dict or None."""
    width, order, bigram_logp_items, quad_path = args

    # Reconstruct bigram logp dict (can't pickle lambda/closure)
    bigram_logp = dict(bigram_logp_items)
    scorer = NgramScorer.from_file(quad_path)

    col_heights = build_col_heights(width)
    inv_perm = build_columnar_inv_perm(order, width, col_heights)

    # Quick Bean equality check
    if not check_bean_eq_only(inv_perm):
        return None

    results = {}
    for variant in ("beaufort", "vigenere", "variant_beaufort"):
        if not check_bean_full(inv_perm, variant):
            continue

        analysis = analyze_transposition(inv_perm, variant)

        ene_bg = score_fragment_bigram(analysis["ene_fragment"], bigram_logp)
        bcl_bg = score_fragment_bigram(analysis["bcl_fragment"], bigram_logp)
        merged_bg = score_fragment_bigram(analysis["merged_fragment"], bigram_logp)
        ene_qg = score_fragment_quadgram(analysis["ene_fragment"], scorer)
        bcl_qg = score_fragment_quadgram(analysis["bcl_fragment"], scorer)
        merged_qg = score_fragment_quadgram(analysis["merged_fragment"], scorer)

        key = f"w{width}_{''.join(map(str, order))}_{variant}"
        results[key] = {
            "width": width,
            "order": list(order),
            "variant": variant,
            "ene_fragment": analysis["ene_fragment"],
            "bcl_fragment": analysis["bcl_fragment"],
            "merged_fragment": analysis["merged_fragment"],
            "ene_bigram_score": ene_bg,
            "bcl_bigram_score": bcl_bg,
            "merged_bigram_score": merged_bg,
            "ene_quad_score": ene_qg,
            "bcl_quad_score": bcl_qg,
            "merged_quad_score": merged_qg,
            "block_gap": analysis["block_gap"],
            "merged_order": analysis["merged_order"],
            "ene_contiguous": analysis["ene_contiguous"],
            "bcl_contiguous": analysis["bcl_contiguous"],
            "ene_source_positions": analysis["ene_source_positions"],
            "bcl_source_positions": analysis["bcl_source_positions"],
        }

    return results if results else None


# ── Main ─────────────────────────────────────────────────────────────────


def main():
    print("=" * 72)
    print("E-KEYSTREAM-ENGLISH-01: Keystream English-Likelihood Under Transposition")
    print("=" * 72)
    t0 = time.time()

    # Load scoring infrastructure
    print("\n[1] Loading quadgram scorer and building bigram table...")
    scorer = load_quadgram_scorer()
    bigram_logp = build_bigram_scorer()
    print(f"    Quadgrams: {len(scorer.log_probs):,} entries")
    print(f"    Bigrams: {len(bigram_logp):,} entries")

    # Find quadgram file path for workers
    quad_path = None
    for p in [
        os.path.join(_ROOT, "data", "english_quadgrams.json"),
        os.path.join(_ROOT, "results", "anneal_step7_start8", "english_quadgrams.json"),
    ]:
        if os.path.exists(p):
            quad_path = p
            break

    # ── Identity transposition (no transposition) ────────────────────────
    print("\n[2] Evaluating identity transposition (no transposition)...")

    identity_inv = list(range(CT_LEN))
    identity_results = {}
    for variant in ("beaufort", "vigenere", "variant_beaufort"):
        analysis = analyze_transposition(identity_inv, variant)
        ene_bg = score_fragment_bigram(analysis["ene_fragment"], bigram_logp)
        bcl_bg = score_fragment_bigram(analysis["bcl_fragment"], bigram_logp)
        merged_bg = score_fragment_bigram(analysis["merged_fragment"], bigram_logp)
        ene_qg = score_fragment_quadgram(analysis["ene_fragment"], scorer)
        bcl_qg = score_fragment_quadgram(analysis["bcl_fragment"], scorer)
        merged_qg = score_fragment_quadgram(analysis["merged_fragment"], scorer)

        key = f"identity_{variant}"
        identity_results[key] = {
            "width": "identity",
            "order": "identity",
            "variant": variant,
            "ene_fragment": analysis["ene_fragment"],
            "bcl_fragment": analysis["bcl_fragment"],
            "merged_fragment": analysis["merged_fragment"],
            "ene_bigram_score": ene_bg,
            "bcl_bigram_score": bcl_bg,
            "merged_bigram_score": merged_bg,
            "ene_quad_score": ene_qg,
            "bcl_quad_score": bcl_qg,
            "merged_quad_score": merged_qg,
            "block_gap": analysis["block_gap"],
            "merged_order": analysis["merged_order"],
            "ene_contiguous": analysis["ene_contiguous"],
            "bcl_contiguous": analysis["bcl_contiguous"],
        }
        print(f"    {variant}:")
        print(f"      ENE fragment: {analysis['ene_fragment']}  bigram={ene_bg:.3f}  quad={ene_qg:.3f}")
        print(f"      BCL fragment: {analysis['bcl_fragment']}  bigram={bcl_bg:.3f}  quad={bcl_qg:.3f}")
        print(f"      Merged:       {analysis['merged_fragment']}  bigram={merged_bg:.3f}  quad={merged_qg:.3f}")
        print(f"      Block gap in source space: {analysis['block_gap']}")

    # ── Null distribution ────────────────────────────────────────────────
    print("\n[3] Generating null distribution (1M random fragments)...")
    null_dist = generate_null_distribution(bigram_logp, scorer, n_samples=1_000_000)
    print(f"    Done. Null medians:")
    print(f"      ENE bigram:  {null_dist['ene_bigram'][500000]:.3f}")
    print(f"      BCL bigram:  {null_dist['bcl_bigram'][500000]:.3f}")
    print(f"      Merged bigram: {null_dist['merged_bigram'][500000]:.3f}")
    print(f"      ENE quad:    {null_dist['ene_quad'][500000]:.3f}")
    print(f"      BCL quad:    {null_dist['bcl_quad'][500000]:.3f}")
    print(f"      Merged quad: {null_dist['merged_quad'][500000]:.3f}")

    # Percentile the identity results
    print("\n    Identity transposition percentiles vs null:")
    for key, res in identity_results.items():
        ene_pct = percentile_rank(null_dist["ene_bigram"], res["ene_bigram_score"])
        bcl_pct = percentile_rank(null_dist["bcl_bigram"], res["bcl_bigram_score"])
        merged_pct = percentile_rank(null_dist["merged_bigram"], res["merged_bigram_score"])
        ene_qpct = percentile_rank(null_dist["ene_quad"], res["ene_quad_score"])
        bcl_qpct = percentile_rank(null_dist["bcl_quad"], res["bcl_quad_score"])
        merged_qpct = percentile_rank(null_dist["merged_quad"], res["merged_quad_score"])
        print(f"    {key}:")
        print(f"      Bigram pctile: ENE={ene_pct:.4f}  BCL={bcl_pct:.4f}  merged={merged_pct:.4f}")
        print(f"      Quad pctile:   ENE={ene_qpct:.4f}  BCL={bcl_qpct:.4f}  merged={merged_qpct:.4f}")

    # ── Columnar transpositions ──────────────────────────────────────────
    print("\n[4] Enumerating Bean-compatible columnar orderings (widths 6, 8, 9)...")

    # Build work items
    work_items = []
    bigram_items = list(bigram_logp.items())

    for width in (6, 8, 9):
        col_heights = build_col_heights(width)
        n_orderings = 0
        bean_eq_pass = 0

        for order in itertools.permutations(range(width)):
            n_orderings += 1
            inv_perm = build_columnar_inv_perm(order, width, col_heights)
            if check_bean_eq_only(inv_perm):
                bean_eq_pass += 1
                work_items.append((width, order, bigram_items, quad_path))

        print(f"    Width {width}: {n_orderings:,} orderings, {bean_eq_pass} pass Bean-eq")

    print(f"    Total work items: {len(work_items):,}")

    # Parallel evaluation
    n_workers = max(1, cpu_count() - 2)
    print(f"\n[5] Evaluating {len(work_items):,} orderings on {n_workers} workers...")

    all_results = {}
    all_results.update(identity_results)

    with Pool(n_workers) as pool:
        chunk_size = max(1, len(work_items) // (n_workers * 4))
        done = 0
        for result in pool.imap_unordered(evaluate_ordering, work_items, chunksize=chunk_size):
            done += 1
            if done % 5000 == 0:
                print(f"    {done}/{len(work_items)} evaluated...")
            if result is not None:
                all_results.update(result)

    n_bean_full_pass = len(all_results) - len(identity_results)
    print(f"    Done. {n_bean_full_pass} orderings pass full Bean (across all variants)")

    # ── Rank results ─────────────────────────────────────────────────────
    print("\n[6] Ranking results...")

    # Score each result against null distribution
    ranked = []
    for key, res in all_results.items():
        ene_pct = percentile_rank(null_dist["ene_bigram"], res["ene_bigram_score"])
        bcl_pct = percentile_rank(null_dist["bcl_bigram"], res["bcl_bigram_score"])
        merged_pct = percentile_rank(null_dist["merged_bigram"], res["merged_bigram_score"])
        ene_qpct = percentile_rank(null_dist["ene_quad"], res["ene_quad_score"])
        bcl_qpct = percentile_rank(null_dist["bcl_quad"], res["bcl_quad_score"])
        merged_qpct = percentile_rank(null_dist["merged_quad"], res["merged_quad_score"])

        # Combined score: max percentile across all metrics
        best_pct = max(ene_pct, bcl_pct, merged_pct, ene_qpct, bcl_qpct, merged_qpct)

        ranked.append({
            "key": key,
            "best_percentile": best_pct,
            "ene_bigram_pct": ene_pct,
            "bcl_bigram_pct": bcl_pct,
            "merged_bigram_pct": merged_pct,
            "ene_quad_pct": ene_qpct,
            "bcl_quad_pct": bcl_qpct,
            "merged_quad_pct": merged_qpct,
            **res,
        })

    ranked.sort(key=lambda x: x["best_percentile"], reverse=True)

    # ── Report ───────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("RESULTS")
    print("=" * 72)

    print(f"\nTotal transpositions evaluated: {len(all_results)}")
    print(f"  Identity: 3 (one per variant)")
    print(f"  Columnar (Bean-passing): {n_bean_full_pass}")

    # Top 20
    print(f"\n── TOP 20 BY BEST PERCENTILE ────────────────────────────")
    for i, r in enumerate(ranked[:20]):
        print(f"\n  #{i+1}: {r['key']}")
        print(f"    ENE: {r['ene_fragment']}  bigram_pct={r['ene_bigram_pct']:.4f}  quad_pct={r['ene_quad_pct']:.4f}")
        print(f"    BCL: {r['bcl_fragment']}  bigram_pct={r['bcl_bigram_pct']:.4f}  quad_pct={r['bcl_quad_pct']:.4f}")
        print(f"    Merged: {r['merged_fragment']}  bigram_pct={r['merged_bigram_pct']:.4f}  quad_pct={r['merged_quad_pct']:.4f}")
        print(f"    Block gap: {r.get('block_gap', '?')}  Order: {r.get('merged_order', '?')}")
        print(f"    BEST PERCENTILE: {r['best_percentile']:.6f}")

    # Block merging analysis (Candidate 2)
    print(f"\n── BLOCK MERGING ANALYSIS ───────────────────────────────")
    close_blocks = [r for r in ranked if isinstance(r.get("block_gap"), int) and 0 <= r["block_gap"] <= 5]
    close_blocks.sort(key=lambda x: x["block_gap"])
    if close_blocks:
        print(f"  {len(close_blocks)} transpositions bring crib blocks within 5 positions:")
        for r in close_blocks[:10]:
            print(f"    {r['key']}: gap={r['block_gap']}  merged_bgpct={r['merged_bigram_pct']:.4f}  merged_qpct={r['merged_quad_pct']:.4f}")
    else:
        print("  No transpositions bring crib blocks within 5 positions.")

    # Statistical summary
    print(f"\n── STATISTICAL SUMMARY ─────────────────────────────────")
    if ranked:
        best = ranked[0]
        n_above_99 = sum(1 for r in ranked if r["best_percentile"] > 0.99)
        n_above_999 = sum(1 for r in ranked if r["best_percentile"] > 0.999)
        n_total = len(ranked)

        # Bonferroni-corrected threshold
        alpha = 0.001
        bonferroni_threshold = 1.0 - alpha / n_total
        n_above_bonferroni = sum(1 for r in ranked if r["best_percentile"] > bonferroni_threshold)

        print(f"  Best overall percentile: {best['best_percentile']:.6f} ({best['key']})")
        print(f"  Total transpositions tested: {n_total}")
        print(f"  Above 99th percentile: {n_above_99}")
        print(f"  Above 99.9th percentile: {n_above_999}")
        print(f"  Bonferroni threshold (alpha={alpha}, n={n_total}): {bonferroni_threshold:.6f}")
        print(f"  Above Bonferroni threshold: {n_above_bonferroni}")

        # Expected counts under null
        expected_99 = n_total * 0.01 * 6  # 6 metrics tested
        expected_999 = n_total * 0.001 * 6
        print(f"\n  Expected >99th pctile under null (6 metrics × {n_total} tests): ~{expected_99:.0f}")
        print(f"  Expected >99.9th pctile under null: ~{expected_999:.1f}")
        print(f"  Observed >99th: {n_above_99}")
        print(f"  Observed >99.9th: {n_above_999}")

        if n_above_bonferroni > 0:
            print(f"\n  *** {n_above_bonferroni} results survive Bonferroni correction ***")
            print(f"  VERDICT: SIGNAL — investigate further")
        elif n_above_999 > expected_999 * 3:
            print(f"\n  Observed >>99.9th count ({n_above_999}) exceeds 3x expected ({expected_999:.1f})")
            print(f"  VERDICT: SUGGESTIVE — mild enrichment above chance")
        else:
            print(f"\n  VERDICT: NOT SUPPORTED — no transposition produces English-like keystream")
            print(f"  Running key without mono is NOT supported for tested transpositions.")

    # ── Save results ─────────────────────────────────────────────────────
    elapsed = time.time() - t0
    output = {
        "experiment": "E-KEYSTREAM-ENGLISH-01",
        "description": "Keystream English-likelihood under transposition",
        "elapsed_seconds": elapsed,
        "n_transpositions": len(all_results),
        "n_above_99th": n_above_99,
        "n_above_999th": n_above_999,
        "bonferroni_threshold": bonferroni_threshold,
        "n_above_bonferroni": n_above_bonferroni,
        "null_distribution_samples": null_dist["n_samples"],
        "null_seed": null_dist["seed"],
        "top_20": ranked[:20],
        "block_merging_close": [r for r in close_blocks[:10]] if close_blocks else [],
    }

    results_path = os.path.join(_ROOT, "results", "keystream_english_likelihood.json")
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {results_path}")
    print(f"  Elapsed: {elapsed:.1f}s")
    print("=" * 72)

    return ranked


def attack(ciphertext=CT, **params):
    """Standard attack contract."""
    ranked = main()
    results = []
    for r in ranked[:10]:
        score = r["best_percentile"] * 24  # Scale to 0-24 range for compatibility
        results.append((
            score,
            f"ENE={r['ene_fragment']} BCL={r['bcl_fragment']}",
            f"Running key {r['variant']} under {r['key']}, best_pctile={r['best_percentile']:.4f}"
        ))
    return results


if __name__ == "__main__":
    main()
