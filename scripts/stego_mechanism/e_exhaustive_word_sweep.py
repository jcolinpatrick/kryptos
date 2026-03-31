#!/usr/bin/env python3
"""
Phase B2: Exhaustive Word Sweep — All 26^5 five-letter strings × 4 variants.

Finds all words achieving 23/23 pure-cell classification.
Groups by partition equivalence class.
Identifies English dictionary words.
Determines whether CHART's partition is common or rare.

Output: results/stego_mechanism/exhaustive_word_sweep.json
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import sys, os, json
from collections import defaultdict, Counter
from datetime import datetime, timezone
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
KRYPTOS_WORD = "KRYPTOS"
KW_AZ = [ALPH_IDX[c] for c in KRYPTOS_WORD]
KW_KA = [KA_IDX[c] for c in KRYPTOS_WORD]

# ── Build target table ──────────────────────────────────────────────
PALETTE_POSITIONS = sorted(p for p in range(CT_LEN) if CT[p] in NULL_PALETTE)

cell_data = defaultdict(list)
for p in PALETTE_POSITIONS:
    cell_data[(p % 7, p % 5)].append((p, p in CONSENSUS_NULL_POSITIONS))

occupied_pure = {}
for r in range(7):
    for c in range(5):
        entries = cell_data.get((r, c), [])
        if not entries:
            continue
        nulls = [e for e in entries if e[1]]
        reals = [e for e in entries if not e[1]]
        if nulls and not reals:
            occupied_pure[(r, c)] = True
        elif reals and not nulls:
            occupied_pure[(r, c)] = False
        # mixed cells excluded

N_PURE = len(occupied_pure)  # 23
PURE_CELLS = sorted(occupied_pure.keys())
PURE_LABELS = [occupied_pure[rc] for rc in PURE_CELLS]

# Pre-compute which pure cells are null vs real
NULL_CELL_INDICES = [i for i, lab in enumerate(PURE_LABELS) if lab]
REAL_CELL_INDICES = [i for i, lab in enumerate(PURE_LABELS) if not lab]

# ── Load English dictionary ─────────────────────────────────────────
DICT_PATH = os.path.join(_ROOT, "wordlists", "english.txt")
ENGLISH_5 = set()
if os.path.exists(DICT_PATH):
    with open(DICT_PATH) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) == 5 and w.isalpha():
                ENGLISH_5.add(w)
print(f"Loaded {len(ENGLISH_5)} five-letter English words")


def sweep_variant(variant_name):
    """Sweep all 26^5 words for one cipher variant. Returns (variant, results_dict).

    NOTE on KA variants: word indices are enumerated in AZ space (0-25 = A-Z)
    for all variants. For KA variants, we use KA indices for KRYPTOS row values
    but AZ indices for word columns. This is a mixed-space operation. The sweep
    is still exhaustive (all 26^5 vectors tested), so perfect-word COUNTS are
    correct, but word LABELS and partition VALUES for KA variants are in mixed
    space. The primary finding (vigenere_az) is unaffected.
    """
    # Determine index space and operation
    is_ka = "ka" in variant_name
    alph_for_decode = KA if is_ka else ALPH
    if "beaufort" in variant_name:
        kw = KW_KA if is_ka else KW_AZ
        op = lambda a, b: (a - b) % MOD
    else:  # vigenere
        kw = KW_KA if is_ka else KW_AZ
        op = lambda a, b: (a + b) % MOD

    # Pre-compute KRYPTOS row values for each pure cell
    cell_row_vals = [kw[rc[0]] for rc in PURE_CELLS]
    cell_cols = [rc[1] for rc in PURE_CELLS]

    perfect_words = []  # (word_str, null_value_set_tuple)
    near_perfect = []   # score 22
    score_hist = Counter()

    total = MOD ** 5
    for word_num in range(total):
        # Decode word number to 5 letter indices
        w = word_num
        word_indices = [0] * 5
        for i in range(4, -1, -1):
            word_indices[i] = w % MOD
            w //= MOD

        # Compute cipher output at each pure cell
        outputs = [op(cell_row_vals[i], word_indices[cell_cols[i]])
                   for i in range(N_PURE)]

        # Induce null-value set from null cells
        null_values = set(outputs[i] for i in NULL_CELL_INDICES)

        # Score
        correct = sum(1 for i in NULL_CELL_INDICES if outputs[i] in null_values)
        correct += sum(1 for i in REAL_CELL_INDICES if outputs[i] not in null_values)

        score_hist[correct] += 1

        if correct == N_PURE:
            word_str = "".join(alph_for_decode[wi] for wi in word_indices)
            perfect_words.append((word_str, tuple(sorted(null_values))))
        elif correct == N_PURE - 1:
            word_str = "".join(alph_for_decode[wi] for wi in word_indices)
            near_perfect.append(word_str)

        if word_num % 2_000_000 == 0 and word_num > 0:
            print(f"  {variant_name}: {word_num:,}/{total:,} "
                  f"({len(perfect_words)} perfect so far)")

    # Group by partition
    partition_groups = defaultdict(list)
    for word, part in perfect_words:
        partition_groups[part].append(word)

    # English words among perfect
    english_perfect = [w for w, _ in perfect_words if w in ENGLISH_5]

    return variant_name, {
        "total_tested": total,
        "perfect_count": len(perfect_words),
        "near_perfect_count": len(near_perfect),
        "score_histogram": {str(k): v for k, v in sorted(score_hist.items())},
        "distinct_partitions": len(partition_groups),
        "partition_sizes": {
            str(k): len(v) for k, v in sorted(
                partition_groups.items(), key=lambda x: -len(x[1])
            )[:20]  # top 20 partitions by frequency
        },
        "english_perfect_count": len(english_perfect),
        "english_perfect_words": sorted(english_perfect)[:200],  # cap output
        "chart_partition": str(tuple(sorted([3, 8, 12, 15, 16, 19, 20, 24]))),
        "chart_partition_count": len(
            partition_groups.get(tuple(sorted([3, 8, 12, 15, 16, 19, 20, 24])), [])
        ),
    }


def run_b2():
    results = {
        "experiment": "e_exhaustive_word_sweep",
        "date": datetime.now(timezone.utc).isoformat(),
        "spec": "docs/superpowers/specs/2026-03-23-stego-mechanism-formalization-design.md",
    }

    print("=" * 80)
    print("PHASE B2: EXHAUSTIVE WORD SWEEP (26^5 × 4 variants)")
    print(f"Total evaluations: {4 * 26**5:,}")
    print("=" * 80)

    variants = ["beaufort_az", "vigenere_az", "beaufort_ka", "vigenere_ka"]

    # Run variants in parallel (4 processes)
    n_workers = min(4, cpu_count())
    print(f"Using {n_workers} parallel workers\n")

    with Pool(n_workers) as pool:
        variant_results = dict(pool.map(sweep_variant, variants))

    results["variants"] = variant_results

    # Summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    for vname, vdata in variant_results.items():
        print(f"\n{vname}:")
        print(f"  Perfect (23/23): {vdata['perfect_count']:,}")
        print(f"  Distinct partitions: {vdata['distinct_partitions']}")
        print(f"  English perfect words: {vdata['english_perfect_count']}")
        print(f"  CHART partition count: {vdata['chart_partition_count']}")
        if vdata['english_perfect_words']:
            sample = vdata['english_perfect_words'][:20]
            print(f"  Sample English words: {', '.join(sample)}")

    # Key question: is the partition unique per variant?
    for vname, vdata in variant_results.items():
        if vdata["distinct_partitions"] == 1:
            results.setdefault("key_findings", []).append(
                f"{vname}: ALL perfect words produce the SAME partition — "
                f"word is irrelevant, only partition matters"
            )

    out_path = os.path.join(_ROOT, "results", "stego_mechanism",
                            "exhaustive_word_sweep.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


if __name__ == "__main__":
    run_b2()
