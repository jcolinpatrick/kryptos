#!/usr/bin/env python3
"""
Keyword-decoupled palette analysis.

QUESTION: Is the null-palette signal ({B,G,I,K,O,W,Z}) specific to
the keyword KRYPTOS, or does it appear under other keywords too?

DESIGN: Run the FULL consensus-building SA protocol (200 restarts ×
300K steps, threshold ≥12/24) under the KA autokey Vigenère model,
but replace the keyword KRYPTOS with 20 alternative keywords.

For each keyword:
  - Build the keyword-mixed alphabet (keyword_mixed_alphabet)
  - Run 200 SA restarts of the autokey Vigenère null-mask search
  - Build consensus top-17 (>50% frequency among ≥threshold masks)
  - Report palette, position overlap, structural properties

INTERPRETATION:
  - If similar palettes recur → KA-structural artifact or model-family effect
  - If palette sharply degrades → KRYPTOS-specific dependence is real

# METADATA
# id: e_keyword_decoupled_palette_01
# family: statistical
# status: active
# has_results: Y
# registered: N
# best_score: n/a
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, random, math, time, json
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CRIB_POSITIONS, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    ALPH, KRYPTOS_ALPHABET,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet

# ── Constants ────────────────────────────────────────────────────────────
N = 97
N_NULLS = 24
N_PT = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]
NC_SET = frozenset(NON_CRIB)

N_WORKERS = max(1, cpu_count() - 2)
N_RESTARTS = 200
N_STEPS = 300_000
SCORE_THRESHOLD = 12
T0 = 0.5
TF = 0.01

REFERENCE_PALETTE = frozenset(NULL_PALETTE)
REFERENCE_POSITIONS = frozenset(CONSENSUS_NULL_POSITIONS)

# ── Keyword panel ────────────────────────────────────────────────────────
# 1. The original (for baseline comparison)
# 2. 10 thematic keywords (relevant to Kryptos but NOT "KRYPTOS")
# 3. 10 random 7-letter English words (no Kryptos connection)
# 4. 2 control keywords (nonsense strings)

KEYWORDS = [
    # Original
    ("KRYPTOS", "original"),
    # Thematic
    ("SANBORN", "thematic"),
    ("SCHEIDT", "thematic"),
    ("LANGLEY", "thematic"),
    ("ABSCISSA", "thematic"),
    ("BERLINCLOCK", "thematic"),
    ("SHADOW", "thematic"),
    ("DEFECTOR", "thematic"),
    ("COMPASS", "thematic"),
    ("PALIMPSEST", "thematic"),
    ("COLOPHON", "thematic"),
    # Random 7-letter English words
    ("PREMISE", "random"),
    ("CAPELLA", "random"),
    ("LABARUM", "random"),
    ("CASTRAL", "random"),
    ("JUNKIER", "random"),
    ("GENERAL", "random"),
    ("FIREARM", "random"),
    ("PROBLEM", "random"),
    ("CLIMATE", "random"),
    ("KINGDOM", "random"),
    # Controls (nonsense)
    ("AAAAAAA", "control"),
    ("QZXJVBW", "control"),
]


# ── Decryption ───────────────────────────────────────────────────────────
def make_autokey_scorer(keyword):
    """Return a scoring function for the given keyword + its mixed alphabet."""
    alpha = keyword_mixed_alphabet(keyword)
    alpha_idx = {c: i for i, c in enumerate(alpha)}

    def score_mask(null_set_frozen):
        ct_reduced = ''.join(CT[i] for i in range(N) if i not in null_set_frozen)
        if len(ct_reduced) != N_PT:
            return 0.0

        n_before_ene = sum(1 for p in null_set_frozen if p < ENE_START)
        n_before_bcl = sum(1 for p in null_set_frozen if p < BCL_START)
        ene_s = ENE_START - n_before_ene
        bcl_s = BCL_START - n_before_bcl

        # Autokey Vigenère decrypt with keyword-mixed alphabet
        kw_idx = [alpha_idx[c] for c in keyword if c in alpha_idx]
        klen = len(kw_idx)
        pt_indices = []
        pt_chars = []
        for i, c in enumerate(ct_reduced):
            ci = alpha_idx[c]
            ki = kw_idx[i] if i < klen else pt_indices[i - klen]
            pi = (ci - ki) % 26
            pt_indices.append(pi)
            pt_chars.append(alpha[pi])

        pt = ''.join(pt_chars)

        e = sum(1 for j, ch in enumerate(ENE_WORD)
                if ene_s + j < len(pt) and pt[ene_s + j] == ch)
        b = sum(1 for j, ch in enumerate(BCL_WORD)
                if bcl_s + j < len(pt) and pt[bcl_s + j] == ch)
        return float(e + b)

    return score_mask


# ── SA engine ────────────────────────────────────────────────────────────
def sa_run(scorer, seed, steps=N_STEPS):
    rng = random.Random(seed)
    pool_positions = list(NC_SET)
    null_set = set(rng.sample(pool_positions, N_NULLS))
    non_null = set(pool_positions) - null_set

    score = scorer(frozenset(null_set))
    best_sc = score
    best_null = frozenset(null_set)

    for step in range(steps):
        T = T0 * (TF / T0) ** (step / steps)
        cands = list(null_set)
        nn_list = list(non_null)
        if not cands or not nn_list:
            break
        out = rng.choice(cands)
        into = rng.choice(nn_list)
        null_set.discard(out)
        null_set.add(into)
        non_null.discard(into)
        non_null.add(out)

        new_sc = scorer(frozenset(null_set))
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-10)):
            score = new_sc
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)
        else:
            null_set.discard(into)
            null_set.add(out)
            non_null.discard(out)
            non_null.add(into)

    return best_sc, sorted(best_null)


# ── Worker wrapper (must be top-level for pickle) ────────────────────────
# Global state set per-keyword batch
_GLOBAL_SCORER = None

def _init_worker(keyword):
    global _GLOBAL_SCORER
    _GLOBAL_SCORER = make_autokey_scorer(keyword)

def _worker(seed):
    return sa_run(_GLOBAL_SCORER, seed)


def build_consensus(keyword, n_restarts):
    """Run n_restarts SA, build consensus from masks scoring ≥ threshold."""
    seeds = [i * 53 + hash(keyword) % 10000 for i in range(n_restarts)]

    with Pool(N_WORKERS, initializer=_init_worker, initargs=(keyword,)) as pool:
        results = pool.map(_worker, seeds)

    freq = Counter()
    scores = []
    n_qualifying = 0
    for sc, mask in results:
        scores.append(sc)
        if sc >= SCORE_THRESHOLD:
            n_qualifying += 1
            for p in mask:
                freq[p] += 1

    # Fallback: if too few qualify, use best-2 threshold
    if n_qualifying < 10 and scores:
        freq = Counter()
        n_qualifying = 0
        fallback_threshold = max(scores) - 2
        for sc, mask in results:
            if sc >= fallback_threshold:
                n_qualifying += 1
                for p in mask:
                    freq[p] += 1

    # Top 17 by frequency
    top17 = frozenset(p for p, _ in freq.most_common(17))
    top24 = frozenset(p for p, _ in freq.most_common(24))

    return top17, top24, freq, scores, n_qualifying


# ── Structural analysis helpers ──────────────────────────────────────────
def ka_column_analysis(letters, keyword):
    """Check if letters concentrate in specific columns of the keyword-mixed Polybius grid."""
    alpha = keyword_mixed_alphabet(keyword)
    cols = {}
    for i, ch in enumerate(alpha):
        cols[ch] = i % 6  # 5×6 grid (last cell may wrap)
    col_dist = Counter(cols.get(ch, -1) for ch in letters)
    n_cols_used = len([c for c in col_dist if c >= 0])
    return col_dist, n_cols_used


def mod5_analysis(positions):
    """Check mod-5 residue distribution of positions."""
    residues = Counter(p % 5 for p in positions)
    return dict(sorted(residues.items()))


# ── Main ─────────────────────────────────────────────────────────────────
def main():
    print("=" * 72)
    print("E-KEYWORD-DECOUPLED-PALETTE-01")
    print("Keyword-Decoupled Palette Analysis")
    print("=" * 72)
    print(f"Model: autokey Vigenère with keyword-mixed alphabet")
    print(f"Protocol: {N_RESTARTS} SA restarts × {N_STEPS:,} steps per keyword")
    print(f"Keywords: {len(KEYWORDS)}")
    print(f"Workers: {N_WORKERS}")
    print(f"Score threshold: ≥{SCORE_THRESHOLD}/24")
    print(f"Reference palette: {sorted(REFERENCE_PALETTE)}")
    print(f"Reference positions: {sorted(REFERENCE_POSITIONS)}")
    print()

    t_start = time.time()
    all_results = {}

    for kw, category in KEYWORDS:
        alpha = keyword_mixed_alphabet(kw)
        print(f"\n{'─' * 72}")
        print(f"Keyword: {kw} ({category})  Alphabet: {alpha}")
        print(f"{'─' * 72}")
        t0 = time.time()

        top17, top24, freq, scores, n_qual = build_consensus(kw, N_RESTARTS)

        # Analyze consensus
        letters_17 = set(CT[p] for p in top17)
        letters_24 = set(CT[p] for p in top24)
        n_distinct_17 = len(letters_17)
        n_distinct_24 = len(letters_24)

        # Palette overlaps
        pal_jaccard = (
            len(letters_17 & REFERENCE_PALETTE) /
            len(letters_17 | REFERENCE_PALETTE)
        ) if letters_17 else 0
        pal_overlap = len(letters_17 & REFERENCE_PALETTE)
        pal_recall = pal_overlap / len(REFERENCE_PALETTE) if REFERENCE_PALETTE else 0
        pal_precision = pal_overlap / n_distinct_17 if n_distinct_17 else 0

        # Position overlaps
        pos_jaccard = (
            len(top17 & REFERENCE_POSITIONS) /
            len(top17 | REFERENCE_POSITIONS)
        ) if top17 else 0
        pos_overlap = len(top17 & REFERENCE_POSITIONS)

        # Structural analysis
        kw_col_dist, kw_n_cols = ka_column_analysis(letters_17, kw)
        ref_col_dist, ref_n_cols = ka_column_analysis(letters_17, "KRYPTOS")
        mod5 = mod5_analysis(top17)

        elapsed = time.time() - t0
        best_score = max(scores) if scores else 0
        mean_score = round(sum(scores) / len(scores), 2) if scores else 0

        result = {
            'keyword': kw,
            'category': category,
            'alphabet': alpha,
            'n_qualifying': n_qual,
            'best_score': best_score,
            'mean_score': mean_score,
            'top17_positions': sorted(top17),
            'top24_positions': sorted(top24),
            'letters_at_top17': ''.join(CT[p] for p in sorted(top17)),
            'n_distinct_top17': n_distinct_17,
            'palette_top17': sorted(letters_17),
            'n_distinct_top24': n_distinct_24,
            'palette_jaccard': round(pal_jaccard, 3),
            'palette_overlap': pal_overlap,
            'palette_recall': round(pal_recall, 3),
            'palette_precision': round(pal_precision, 3),
            'position_jaccard': round(pos_jaccard, 3),
            'position_overlap': pos_overlap,
            'kw_col_distribution': {str(k): v for k, v in kw_col_dist.items()},
            'kw_n_cols_used': kw_n_cols,
            'mod5_residues': mod5,
            'elapsed_s': round(elapsed, 1),
        }
        all_results[kw] = result

        print(f"  Qualifying: {n_qual}/{N_RESTARTS}  Best: {best_score:.0f}/24  Mean: {mean_score}")
        print(f"  Top-17 positions: {sorted(top17)}")
        print(f"  Letters: {''.join(CT[p] for p in sorted(top17))}")
        print(f"  Distinct: {n_distinct_17}  Palette: {sorted(letters_17)}")
        print(f"  Palette overlap: {pal_overlap}/7  Jaccard: {pal_jaccard:.3f}")
        print(f"  Position overlap: {pos_overlap}/17  Jaccard: {pos_jaccard:.3f}")
        print(f"  [{elapsed:.0f}s]")
        sys.stdout.flush()

    # ── Summary table ────────────────────────────────────────────────────
    total_elapsed = time.time() - t_start
    print(f"\n{'=' * 72}")
    print("SUMMARY")
    print(f"{'=' * 72}")
    print()
    print(f"  {'Keyword':<15s} {'Cat':<10s} {'Qual':>4s} {'Best':>4s} {'Dist':>4s} "
          f"{'PalOvlp':>7s} {'PalJac':>7s} {'PosOvlp':>7s} {'PosJac':>7s} {'Palette'}")
    print(f"  {'-'*15} {'-'*10} {'-'*4} {'-'*4} {'-'*4} "
          f"{'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*20}")

    for kw, _ in KEYWORDS:
        r = all_results[kw]
        pal_str = ''.join(r['palette_top17'])
        marker = " <<<" if kw == "KRYPTOS" else ""
        print(f"  {kw:<15s} {r['category']:<10s} {r['n_qualifying']:>4d} "
              f"{r['best_score']:>4.0f} {r['n_distinct_top17']:>4d} "
              f"{r['palette_overlap']:>4d}/7 {r['palette_jaccard']:>7.3f} "
              f"{r['position_overlap']:>4d}/17 {r['position_jaccard']:>7.3f} "
              f"{pal_str}{marker}")

    # ── Distribution analysis ────────────────────────────────────────────
    print(f"\n## Distribution of palette properties across keywords:")

    distincts = [r['n_distinct_top17'] for r in all_results.values()]
    pal_jaccards = [r['palette_jaccard'] for r in all_results.values()]
    pos_jaccards = [r['position_jaccard'] for r in all_results.values()]
    pal_overlaps = [r['palette_overlap'] for r in all_results.values()]

    kryptos_r = all_results["KRYPTOS"]
    non_kryptos = {k: v for k, v in all_results.items() if k != "KRYPTOS"}

    nk_distincts = [r['n_distinct_top17'] for r in non_kryptos.values()]
    nk_pal_jac = [r['palette_jaccard'] for r in non_kryptos.values()]
    nk_pos_jac = [r['position_jaccard'] for r in non_kryptos.values()]

    print(f"\n  Distinct letters at top-17:")
    print(f"    KRYPTOS:     {kryptos_r['n_distinct_top17']}")
    print(f"    Others mean: {sum(nk_distincts)/len(nk_distincts):.1f}")
    print(f"    Others min:  {min(nk_distincts)}")
    print(f"    Others max:  {max(nk_distincts)}")

    print(f"\n  Palette Jaccard (vs BGIKOWZ):")
    print(f"    KRYPTOS:     {kryptos_r['palette_jaccard']:.3f}")
    print(f"    Others mean: {sum(nk_pal_jac)/len(nk_pal_jac):.3f}")
    print(f"    Others min:  {min(nk_pal_jac):.3f}")
    print(f"    Others max:  {max(nk_pal_jac):.3f}")

    print(f"\n  Position Jaccard (vs consensus 17):")
    print(f"    KRYPTOS:     {kryptos_r['position_jaccard']:.3f}")
    print(f"    Others mean: {sum(nk_pos_jac)/len(nk_pos_jac):.3f}")
    print(f"    Others min:  {min(nk_pos_jac):.3f}")
    print(f"    Others max:  {max(nk_pos_jac):.3f}")

    # How many non-KRYPTOS keywords produce ≤7 distinct?
    n_low = sum(1 for d in nk_distincts if d <= 7)
    # How many produce ≥5/7 palette overlap?
    n_high_overlap = sum(1 for r in non_kryptos.values() if r['palette_overlap'] >= 5)

    print(f"\n  Non-KRYPTOS keywords with ≤7 distinct: {n_low}/{len(non_kryptos)}")
    print(f"  Non-KRYPTOS keywords with ≥5/7 overlap: {n_high_overlap}/{len(non_kryptos)}")

    # ── Adjudication ─────────────────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("ADJUDICATION")
    print(f"{'=' * 72}")

    kryptos_distinct = kryptos_r['n_distinct_top17']
    kryptos_pal_jac = kryptos_r['palette_jaccard']

    # Is KRYPTOS special among the keywords?
    rank_distinct = sum(1 for d in nk_distincts if d <= kryptos_distinct) + 1
    rank_pal_jac = sum(1 for j in nk_pal_jac if j >= kryptos_pal_jac) + 1

    print(f"\n  KRYPTOS distinct rank: {rank_distinct}/{len(KEYWORDS)} "
          f"({'best' if rank_distinct == 1 else 'not best'} among all keywords)")
    print(f"  KRYPTOS palette-Jaccard rank: {rank_pal_jac}/{len(KEYWORDS)} "
          f"({'best' if rank_pal_jac == 1 else 'not best'} among all keywords)")

    # Check if palette is broadly similar across keywords (model artifact)
    # or specific to KRYPTOS
    mean_nk_jac = sum(nk_pal_jac) / len(nk_pal_jac)

    if n_low >= len(non_kryptos) * 0.3:
        verdict = "MODEL-FAMILY ARTIFACT"
        detail = (f"{n_low}/{len(non_kryptos)} non-KRYPTOS keywords also produce ≤7 distinct. "
                  f"The low diversity is a property of the SA+autokey model, not the keyword.")
    elif n_high_overlap >= len(non_kryptos) * 0.3:
        verdict = "KA-STRUCTURAL ARTIFACT"
        detail = (f"{n_high_overlap}/{len(non_kryptos)} non-KRYPTOS keywords recover ≥5/7 "
                  f"of the palette. The specific letters are a KA-alphabet structure effect.")
    elif kryptos_distinct <= 9 and mean_nk_jac < 0.2:
        verdict = "KRYPTOS-SPECIFIC SIGNAL"
        detail = (f"KRYPTOS produces {kryptos_distinct} distinct with Jaccard={kryptos_pal_jac:.3f}, "
                  f"while non-KRYPTOS mean Jaccard={mean_nk_jac:.3f}. "
                  f"The palette is meaningfully tied to the KRYPTOS keyword.")
    else:
        verdict = "INCONCLUSIVE"
        detail = (f"Mixed results. KRYPTOS distinct={kryptos_distinct}, "
                  f"mean non-KRYPTOS Jaccard={mean_nk_jac:.3f}. "
                  f"Cannot clearly attribute the palette to keyword vs model vs data.")

    print(f"\n  VERDICT: {verdict}")
    print(f"  {detail}")

    print(f"\n## What this means for the null-palette hypothesis:")
    if verdict == "KRYPTOS-SPECIFIC SIGNAL":
        print(f"  UPGRADED: The palette signal is keyword-dependent, supporting the idea")
        print(f"  that KRYPTOS as a keyword plays a generative role in null selection.")
    elif verdict in ("MODEL-FAMILY ARTIFACT", "KA-STRUCTURAL ARTIFACT"):
        print(f"  DOWNGRADED: The palette is NOT specific to KRYPTOS. It is an artifact")
        print(f"  of the cipher model or alphabet structure. The palette's significance")
        print(f"  at null positions is partially or fully explained by the optimization")
        print(f"  landscape, not by a true stego-cipher coupling.")
    else:
        print(f"  NEUTRAL: Cannot discriminate. More targeted testing needed.")

    print(f"\n## Recommended next step:")
    if verdict == "KRYPTOS-SPECIFIC SIGNAL":
        print(f"  Test the KA grid column concentration: does KRYPTOS specifically route")
        print(f"  the palette letters to adjacent columns?")
    else:
        print(f"  Accept that the palette is a model-family property and redirect")
        print(f"  research to placement rules (mod-7, mod-5) rather than letter identity.")

    print(f"\n  Total elapsed: {total_elapsed:.0f}s ({total_elapsed / 60:.1f} min)")

    # ── Save results ─────────────────────────────────────────────────────
    output = {
        'experiment': 'E-KEYWORD-DECOUPLED-PALETTE-01',
        'protocol': {
            'model': 'autokey_vigenere_keyword_mixed',
            'n_restarts': N_RESTARTS,
            'n_steps': N_STEPS,
            'score_threshold': SCORE_THRESHOLD,
            'n_keywords': len(KEYWORDS),
        },
        'reference_palette': sorted(REFERENCE_PALETTE),
        'reference_positions': sorted(REFERENCE_POSITIONS),
        'results': all_results,
        'summary': {
            'verdict': verdict,
            'kryptos_distinct': kryptos_distinct,
            'kryptos_palette_jaccard': kryptos_pal_jac,
            'non_kryptos_mean_distinct': round(sum(nk_distincts) / len(nk_distincts), 1),
            'non_kryptos_mean_palette_jaccard': round(mean_nk_jac, 3),
            'n_non_kryptos_low_distinct': n_low,
            'n_non_kryptos_high_overlap': n_high_overlap,
        },
        'total_elapsed_s': round(total_elapsed, 1),
        'workers': N_WORKERS,
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    out_path = os.path.join(_ROOT, 'results', 'keyword_decoupled_palette_01.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results: {out_path}")


if __name__ == '__main__':
    main()
