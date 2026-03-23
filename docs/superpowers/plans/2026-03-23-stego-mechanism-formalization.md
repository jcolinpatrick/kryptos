# Stego Mechanism Formalization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Formalize the K4 stego layer as a testable generative specification, then propagate constraints to the cipher layer.

**Architecture:** Six experiment scripts in `scripts/stego_mechanism/`, each corresponding to one phase of the spec (B1–B5, C). Each is a standalone Python script using `PYTHONPATH=src`, importing from `kryptos.kernel.constants`, and writing structured JSON to `results/stego_mechanism/`. No new kernel modules needed. Scripts run sequentially with dependency gating: B1 determines whether B2 is needed; B3 is the critical gate; C runs regardless.

**Tech Stack:** Python 3.12, stdlib only (+ `multiprocessing` for B2 parallelism), `PYTHONPATH=src`

**Spec:** `docs/superpowers/specs/2026-03-23-stego-mechanism-formalization-design.md`

---

## File Structure

```
scripts/stego_mechanism/
  e_simplicity_tests.py          — B1: SEVEN-only, single-shift, 2-letter keys
  e_exhaustive_word_sweep.py     — B2: All 26^5 words × 4 variants, partition clustering
  e_partition_analysis.py        — B3: Structural analysis of null-value sets
  e_mixed_cell_varying.py        — B4: Tiebreaker, false-positive model, secondary filter
  e_full_spec_test.py            — B5: Independent reconstruction from spec alone
  e_constraint_propagation.py    — C:  Push stego constraints into cipher search space

results/stego_mechanism/
  simplicity_tests.json          — B1 output
  exhaustive_word_sweep.json     — B2 output
  partition_analysis.json        — B3 output
  mixed_cell_varying.json        — B4 output
  full_spec_test.json            — B5 output
  constraint_propagation.json    — C output
```

Each script is self-contained with the standard 2-level bootstrap:
```python
import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
```

**Shared setup in every script** (the "table preamble"):
- Build palette positions: `[p for p in range(97) if CT[p] in NULL_PALETTE]` → 35 positions
- Build cell data: `defaultdict(list)` mapping `(p%7, p%5)` → `[(pos, is_null), ...]`
- Build target table: 10 pure-null cells, 13 pure-real cells, 3 mixed cells
- Build `occupied_pure`: dict of `(r,c) → True/False` for the 23 non-mixed cells
- Define cipher functions: `beaufort_az(a,b)=(a-b)%26`, `vigenere_az(a,b)=(a+b)%26`, etc.

---

## Task 1: Create Directory Structure and Shared Constants

**Files:**
- Create: `scripts/stego_mechanism/` (directory)
- Create: `results/stego_mechanism/` (directory)

- [ ] **Step 1: Create directories**

```bash
mkdir -p scripts/stego_mechanism results/stego_mechanism
```

- [ ] **Step 2: Verify directories exist**

```bash
ls -d scripts/stego_mechanism results/stego_mechanism
```

Expected: both paths listed.

- [ ] **Step 3: Commit**

```bash
git add scripts/stego_mechanism results/stego_mechanism
git commit --allow-empty -m "chore: create stego_mechanism script and results directories"
```

---

## Task 2: Phase B1 — Simplicity Tests

**Files:**
- Create: `scripts/stego_mechanism/e_simplicity_tests.py`
- Output: `results/stego_mechanism/simplicity_tests.json`

**Purpose:** Prove that a 3-keyword system (KRYPTOS + SEVEN + CHART) is necessary by showing simpler alternatives (SEVEN alone, single shift, 2-letter keys) fail to achieve 23/23 with a structured partition.

- [ ] **Step 1: Write the script**

Create `scripts/stego_mechanism/e_simplicity_tests.py` with:

```python
#!/usr/bin/env python3
"""
Phase B1: Simplicity Tests — Can a simpler system generate the 7×5 table?

Tests whether SEVEN alone, a single shift, or a 2-letter cycling key
achieves 23/23 pure-cell classification WITH a structured partition
(threshold, modular rule, or Polybius region).

If any simpler system works, CHART is unnecessary.

Output: results/stego_mechanism/simplicity_tests.json
"""
import sys, os, json
from collections import defaultdict
from datetime import datetime, timezone
from itertools import product

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
KRYPTOS_WORD = "KRYPTOS"

# ── Build target table ──────────────────────────────────────────────
PALETTE_POSITIONS = sorted(p for p in range(CT_LEN) if CT[p] in NULL_PALETTE)

cell_data = defaultdict(list)
for p in PALETTE_POSITIONS:
    cell_data[(p % 7, p % 5)].append((p, p in CONSENSUS_NULL_POSITIONS))

target = {}
for r in range(7):
    for c in range(5):
        entries = cell_data.get((r, c), [])
        if not entries:
            target[(r, c)] = None
        else:
            nulls = [e for e in entries if e[1]]
            reals = [e for e in entries if not e[1]]
            if nulls and not reals:
                target[(r, c)] = True
            elif reals and not nulls:
                target[(r, c)] = False
            else:
                target[(r, c)] = "mixed"

occupied_pure = {(r, c): v for (r, c), v in target.items() if v in (True, False)}
N_PURE = len(occupied_pure)  # 23

# ── Cipher functions ────────────────────────────────────────────────
CIPHER_FNS = {
    "beaufort_az": lambda a, b: (ALPH_IDX[a] - ALPH_IDX[b]) % MOD,
    "vigenere_az": lambda a, b: (ALPH_IDX[a] + ALPH_IDX[b]) % MOD,
    "beaufort_ka": lambda a, b: (KA_IDX[a] - KA_IDX[b]) % MOD,
    "vigenere_ka": lambda a, b: (KA_IDX[a] + KA_IDX[b]) % MOD,
}


def score_word(col_key, cipher_fn):
    """Compute cell outputs and find best data-fit partition score on 23 pure cells."""
    cell_outputs = {}
    for r in range(7):
        for c in range(5):
            cell_outputs[(r, c)] = cipher_fn(KRYPTOS_WORD[r], col_key[c % len(col_key)])

    # Induce null-value set from pure-null cells
    null_values = set()
    for (r, c), is_null in occupied_pure.items():
        if is_null:
            null_values.add(cell_outputs[(r, c)])

    # Score: how many pure cells are correctly classified?
    correct = 0
    for (r, c), is_null in occupied_pure.items():
        predicted_null = cell_outputs[(r, c)] in null_values
        if predicted_null == is_null:
            correct += 1

    return correct, null_values, cell_outputs


def test_structured_partitions(cell_outputs):
    """Test threshold and modular partition rules. Return best structured score."""
    best = {"type": None, "score": 0, "params": {}}

    # Threshold rules: null iff output < T
    for t in range(1, MOD):
        correct = 0
        for (r, c), is_null in occupied_pure.items():
            predicted = cell_outputs[(r, c)] < t
            if predicted == is_null:
                correct += 1
        if correct > best["score"]:
            best = {"type": "threshold", "score": correct, "params": {"T": t}}

    # Modular rules: null iff output % M in S, for M=2..6
    for m in range(2, 7):
        residues = set(range(m))
        # Try all non-empty subsets of residues
        for r_size in range(1, m):
            for subset in _combinations(list(residues), r_size):
                s = set(subset)
                correct = 0
                for (r, c), is_null in occupied_pure.items():
                    predicted = (cell_outputs[(r, c)] % m) in s
                    if predicted == is_null:
                        correct += 1
                if correct > best["score"]:
                    best = {"type": f"mod_{m}", "score": correct,
                            "params": {"M": m, "S": sorted(s)}}

    return best


def _combinations(lst, r):
    """Simple combinations generator (avoid importing itertools.combinations twice)."""
    from itertools import combinations
    return combinations(lst, r)


def run_b1():
    results = {
        "experiment": "e_simplicity_tests",
        "date": datetime.now(timezone.utc).isoformat(),
        "spec": "docs/superpowers/specs/2026-03-23-stego-mechanism-formalization-design.md",
    }

    print("=" * 80)
    print("PHASE B1: SIMPLICITY TESTS")
    print("=" * 80)

    # ── B1.1: SEVEN direct ──────────────────────────────────────────
    print("\n── B1.1: SEVEN as column keyword ──")
    b1_1 = {}
    for cname, cfn in CIPHER_FNS.items():
        score, null_vals, cell_outs = score_word("SEVEN", cfn)
        structured = test_structured_partitions(cell_outs)
        b1_1[cname] = {
            "data_fit_score": score,
            "null_values": sorted(null_vals),
            "null_letters": sorted(ALPH[v] for v in null_vals),
            "best_structured": structured,
        }
        print(f"  {cname}: data-fit={score}/{N_PURE}, "
              f"best structured={structured['score']}/{N_PURE} ({structured['type']})")

    results["B1_1_seven"] = b1_1
    seven_kills = any(v["best_structured"]["score"] == N_PURE for v in b1_1.values())
    results["B1_1_kills_chart"] = seven_kills
    print(f"  → SEVEN kills CHART? {seven_kills}")

    # ── B1.2: Single shift ──────────────────────────────────────────
    print("\n── B1.2: Single constant shift (0-25) ──")
    b1_2 = {"best_per_variant": {}}
    for cname, cfn in CIPHER_FNS.items():
        best_shift = {"shift": -1, "data_fit": 0, "structured": 0}
        for s in range(MOD):
            # Use ALPH[s] as the constant column "letter"
            col_letter = ALPH[s]
            cell_outputs = {}
            for r in range(7):
                for c in range(5):
                    cell_outputs[(r, c)] = cfn(KRYPTOS_WORD[r], col_letter)

            # Induce partition
            null_values = set()
            for (rc), is_null in occupied_pure.items():
                if is_null:
                    null_values.add(cell_outputs[rc])
            correct = sum(
                1 for rc, is_null in occupied_pure.items()
                if (cell_outputs[rc] in null_values) == is_null
            )
            if correct > best_shift["data_fit"]:
                best_shift = {"shift": s, "letter": col_letter,
                              "data_fit": correct, "structured": 0}

        # Test structured partitions for the best shift
        col_letter = ALPH[best_shift["shift"]]
        cell_outputs = {}
        for r in range(7):
            for c in range(5):
                cell_outputs[(r, c)] = cfn(KRYPTOS_WORD[r], col_letter)
        structured = test_structured_partitions(cell_outputs)
        best_shift["structured"] = structured["score"]
        best_shift["structured_type"] = structured["type"]

        b1_2["best_per_variant"][cname] = best_shift
        print(f"  {cname}: best shift={best_shift['shift']} ({best_shift['letter']}), "
              f"data-fit={best_shift['data_fit']}/{N_PURE}, "
              f"structured={best_shift['structured']}/{N_PURE}")

    results["B1_2_single_shift"] = b1_2
    shift_kills = any(
        v["data_fit"] == N_PURE
        for v in b1_2["best_per_variant"].values()
    )
    results["B1_2_kills_chart"] = shift_kills
    print(f"  → Single shift kills CHART? {shift_kills}")

    # ── B1.3: 2-letter cycling key ─────────────────────────────────
    print("\n── B1.3: 2-letter cycling keys (676 × 4 variants) ──")
    b1_3 = {"best_per_variant": {}, "perfect_keys": []}
    for cname, cfn in CIPHER_FNS.items():
        best_key = {"key": "", "data_fit": 0}
        for a in range(MOD):
            for b in range(MOD):
                key_str = ALPH[a] + ALPH[b]
                score, null_vals, _ = score_word(key_str, cfn)
                if score > best_key["data_fit"]:
                    best_key = {"key": key_str, "data_fit": score,
                                "null_values": sorted(null_vals)}
                if score == N_PURE:
                    b1_3["perfect_keys"].append({
                        "key": key_str, "cipher": cname, "score": score
                    })

        b1_3["best_per_variant"][cname] = best_key
        print(f"  {cname}: best key={best_key['key']}, "
              f"data-fit={best_key['data_fit']}/{N_PURE}")

    results["B1_3_two_letter"] = b1_3
    two_letter_kills = len(b1_3["perfect_keys"]) > 0
    results["B1_3_kills_chart"] = two_letter_kills
    print(f"  → 2-letter key kills CHART? {two_letter_kills} "
          f"({len(b1_3['perfect_keys'])} perfect keys)")

    # ── Summary ─────────────────────────────────────────────────────
    any_kill = seven_kills or shift_kills or two_letter_kills
    results["any_simplicity_kill"] = any_kill
    results["verdict"] = "CHART_UNNECESSARY" if any_kill else "CHART_SURVIVES"

    print(f"\n{'=' * 80}")
    print(f"VERDICT: {results['verdict']}")
    print(f"{'=' * 80}")

    # Write results
    os.makedirs(os.path.join(_ROOT, "results", "stego_mechanism"), exist_ok=True)
    out_path = os.path.join(_ROOT, "results", "stego_mechanism", "simplicity_tests.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


if __name__ == "__main__":
    run_b1()
```

- [ ] **Step 2: Run the script**

```bash
PYTHONPATH=src python3 -u scripts/stego_mechanism/e_simplicity_tests.py
```

Expected: Each test shows score/23 per variant. VERDICT is likely `CHART_SURVIVES` (simpler systems don't work with structured partitions). If `CHART_UNNECESSARY`, stop and report — the plan changes.

- [ ] **Step 3: Review results**

```bash
cat results/stego_mechanism/simplicity_tests.json | python3 -m json.tool | head -40
```

Check: `any_simplicity_kill` should be `false`. If `true`, read the details — which simpler system worked and with what partition?

- [ ] **Step 4: Commit**

```bash
git add scripts/stego_mechanism/e_simplicity_tests.py results/stego_mechanism/simplicity_tests.json
git commit -m "feat(stego): B1 simplicity tests — prove CHART necessity"
```

---

## Task 3: Phase B2 — Exhaustive Word Sweep

**Files:**
- Create: `scripts/stego_mechanism/e_exhaustive_word_sweep.py`
- Output: `results/stego_mechanism/exhaustive_word_sweep.json`

**Purpose:** Sweep all 11.88M five-letter strings × 4 cipher variants. Find all 23/23 words. Group by partition equivalence class. Identify English dictionary words among them. Determine whether CHART's partition is common or rare.

**Gate:** Only run if B1 verdict is `CHART_SURVIVES`.

- [ ] **Step 1: Write the script**

Create `scripts/stego_mechanism/e_exhaustive_word_sweep.py` with:

```python
#!/usr/bin/env python3
"""
Phase B2: Exhaustive Word Sweep — All 26^5 five-letter strings × 4 variants.

Finds all words achieving 23/23 pure-cell classification.
Groups by partition equivalence class.
Identifies English dictionary words.
Determines whether CHART's partition is common or rare.

Output: results/stego_mechanism/exhaustive_word_sweep.json
"""
import sys, os, json
from collections import defaultdict, Counter
from datetime import datetime, timezone
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
    """Sweep all 26^5 words for one cipher variant. Returns (variant, results_dict)."""
    if "beaufort" in variant_name and "az" in variant_name:
        kw = KW_AZ
        op = lambda a, b: (a - b) % MOD
    elif "vigenere" in variant_name and "az" in variant_name:
        kw = KW_AZ
        op = lambda a, b: (a + b) % MOD
    elif "beaufort" in variant_name and "ka" in variant_name:
        kw = KW_KA
        op = lambda a, b: (a - b) % MOD
    else:  # vigenere_ka
        kw = KW_KA
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
            word_str = "".join(ALPH[wi] for wi in word_indices)
            perfect_words.append((word_str, tuple(sorted(null_values))))
        elif correct == N_PURE - 1:
            word_str = "".join(ALPH[wi] for wi in word_indices)
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
```

- [ ] **Step 2: Run the script**

```bash
PYTHONPATH=src python3 -u scripts/stego_mechanism/e_exhaustive_word_sweep.py
```

Expected runtime: 5–20 minutes on 28 cores. Watch for progress lines. Key outputs: perfect count, distinct partition count, English word list, CHART partition count.

- [ ] **Step 3: Review results — focus on partition uniqueness**

```bash
python3 -c "
import json
d = json.load(open('results/stego_mechanism/exhaustive_word_sweep.json'))
for v, r in d['variants'].items():
    print(f'{v}: {r[\"perfect_count\"]:,} perfect, {r[\"distinct_partitions\"]} partitions, '
          f'{r[\"english_perfect_count\"]} English, CHART partition={r[\"chart_partition_count\"]}')"
```

**Critical check:** If `distinct_partitions == 1` for vigenere_az → the partition is uniquely determined by the table + variant. CHART is just one of many words that produce this unique partition. The WORD doesn't matter — proceed to B3 to analyze the PARTITION.

If multiple partitions exist → CHART's specific partition matters. Check if it's rare or common.

- [ ] **Step 4: Commit**

```bash
git add scripts/stego_mechanism/e_exhaustive_word_sweep.py results/stego_mechanism/exhaustive_word_sweep.json
git commit -m "feat(stego): B2 exhaustive word sweep — partition equivalence classes"
```

---

## Task 4: Phase B3 — Partition Analysis

**Files:**
- Create: `scripts/stego_mechanism/e_partition_analysis.py`
- Output: `results/stego_mechanism/partition_analysis.json`

**Purpose:** Determine whether the null-value set (from B2, likely {D,I,M,P,Q,T,U,Y} = {3,8,12,15,16,19,20,24} for vigenere_az) has algebraic structure. This is the CRITICAL GATE — if no structure, report descriptive finding and stop.

- [ ] **Step 1: Write the script**

Create `scripts/stego_mechanism/e_partition_analysis.py` with:

```python
#!/usr/bin/env python3
"""
Phase B3: Partition Rule Analysis — CRITICAL GATE

Determines whether the null-value set has algebraic structure
(Polybius region, keyword complement, threshold, modular rule).

Reads the canonical partition from B2 results. If B2 hasn't run,
uses CHART:vigenere_az partition {3,8,12,15,16,19,20,24}.

Output: results/stego_mechanism/partition_analysis.json
"""
import sys, os, json
from collections import Counter
from datetime import datetime, timezone
from itertools import combinations

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    NULL_PALETTE, BEAUFORT_KEYSTREAM_AT_CRIBS,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── Load canonical partition from B2, or use default ────────────────
B2_PATH = os.path.join(_ROOT, "results", "stego_mechanism", "exhaustive_word_sweep.json")
DEFAULT_NULL_SET = frozenset([3, 8, 12, 15, 16, 19, 20, 24])  # CHART:vigenere_az
DEFAULT_VARIANT = "vigenere_az"

if os.path.exists(B2_PATH):
    with open(B2_PATH) as f:
        b2 = json.load(f)
    # Use the vigenere_az canonical partition (or whichever has fewest distinct partitions)
    vig_data = b2["variants"].get("vigenere_az", {})
    if vig_data.get("distinct_partitions", 0) == 1:
        # Unique partition — extract it
        part_str = list(vig_data.get("partition_sizes", {}).keys())[0]
        null_set = frozenset(json.loads(part_str))
        print(f"Loaded UNIQUE partition from B2 vigenere_az: {sorted(null_set)}")
    else:
        null_set = DEFAULT_NULL_SET
        print(f"B2 has multiple partitions; using CHART default: {sorted(null_set)}")
else:
    null_set = DEFAULT_NULL_SET
    print(f"No B2 results; using CHART default: {sorted(null_set)}")

null_letters = frozenset(ALPH[v] for v in null_set)
real_set = frozenset(range(MOD)) - null_set
real_letters = frozenset(ALPH[v] for v in real_set)


def run_b3():
    results = {
        "experiment": "e_partition_analysis",
        "date": datetime.now(timezone.utc).isoformat(),
        "null_set_az_indices": sorted(null_set),
        "null_set_letters": sorted(null_letters),
        "null_set_size": len(null_set),
        "real_set_letters": sorted(real_letters),
    }

    print("=" * 80)
    print("PHASE B3: PARTITION RULE ANALYSIS — CRITICAL GATE")
    print(f"Null set ({len(null_set)} letters): {sorted(null_letters)}")
    print(f"Real set ({len(real_set)} letters): {sorted(real_letters)}")
    print("=" * 80)

    # ── B3.1: Polybius Grid Mapping ─────────────────────────────────
    print("\n── B3.1: Polybius Grid Mapping ──")

    # AZ grid (5-wide)
    az_positions = {}
    for v in null_set:
        r, c = divmod(v, 5)
        az_positions[ALPH[v]] = (r, c)
    results["B3_1_az_grid"] = {letter: list(pos) for letter, pos in az_positions.items()}

    print("  AZ 5-wide positions of null-set letters:")
    for letter, (r, c) in sorted(az_positions.items()):
        print(f"    {letter} (AZ={ALPH_IDX[letter]:2d}) → row={r}, col={c}")

    az_rows = Counter(pos[0] for pos in az_positions.values())
    az_cols = Counter(pos[1] for pos in az_positions.values())
    print(f"  AZ row distribution: {dict(az_rows)}")
    print(f"  AZ col distribution: {dict(az_cols)}")

    # KA grid (5-wide)
    ka_positions = {}
    for letter in null_letters:
        ki = KA_IDX[letter]
        r, c = divmod(ki, 5)
        ka_positions[letter] = (r, c)
    results["B3_1_ka_grid"] = {letter: list(pos) for letter, pos in ka_positions.items()}

    print("\n  KA 5-wide positions of null-set letters:")
    for letter, (r, c) in sorted(ka_positions.items()):
        print(f"    {letter} (KA={KA_IDX[letter]:2d}) → row={r}, col={c}")

    ka_rows = Counter(pos[0] for pos in ka_positions.values())
    ka_cols = Counter(pos[1] for pos in ka_positions.values())
    print(f"  KA row distribution: {dict(ka_rows)}")
    print(f"  KA col distribution: {dict(ka_cols)}")

    # Check for contiguous regions
    results["B3_1_az_row_set"] = sorted(az_rows.keys())
    results["B3_1_ka_row_set"] = sorted(ka_rows.keys())
    results["B3_1_az_col_set"] = sorted(az_cols.keys())
    results["B3_1_ka_col_set"] = sorted(ka_cols.keys())

    # ── B3.2: Set-Theoretic Relationships ───────────────────────────
    print("\n── B3.2: Set-Theoretic Relationships ──")

    palette_set = frozenset(NULL_PALETTE)
    kryptos_set = frozenset("KRYPTOS")
    seven_set = frozenset("SEVEN")
    chart_set = frozenset("CHART")

    intersections = {
        "palette": sorted(null_letters & palette_set),
        "kryptos": sorted(null_letters & kryptos_set),
        "seven": sorted(null_letters & seven_set),
        "chart": sorted(null_letters & chart_set),
    }
    results["B3_2_intersections"] = intersections

    for name, inter in intersections.items():
        print(f"  Null set ∩ {name:>8s} = {inter} ({len(inter)} letters)")

    # Complement analysis
    print(f"\n  Complement (real set, 18 letters): {sorted(real_letters)}")
    # Check if complement contains recognizable words
    # (Just report — manual review needed)

    # ── B3.3: Numerical Structure ───────────────────────────────────
    print("\n── B3.3: Numerical Structure ──")
    null_list = sorted(null_set)
    diffs = [null_list[i+1] - null_list[i] for i in range(len(null_list)-1)]
    total_sum = sum(null_list)

    print(f"  Values (AZ): {null_list}")
    print(f"  Consecutive diffs: {diffs}")
    print(f"  Sum: {total_sum} = {_factorize(total_sum)}")

    numerical = {"values": null_list, "diffs": diffs, "sum": total_sum}

    for m in range(2, 14):
        residues = sorted(set(v % m for v in null_list))
        coverage = len(residues) / m
        numerical[f"mod_{m}_residues"] = residues
        if coverage < 0.6:  # concentrated in fewer than 60% of residue classes
            print(f"  mod-{m}: residues {residues} ({len(residues)}/{m} = {coverage:.0%}) ← CONCENTRATED")
        else:
            print(f"  mod-{m}: residues {residues} ({len(residues)}/{m} = {coverage:.0%})")

    results["B3_3_numerical"] = numerical

    # Bit pattern analysis
    print(f"\n  5-bit patterns:")
    for v in null_list:
        print(f"    {ALPH[v]} = {v:2d} = {v:05b}")
    # Check if any single bit position selects the null set
    for bit in range(5):
        selected = {v for v in range(MOD) if (v >> bit) & 1}
        overlap = null_set & selected
        print(f"  Bit {bit} set → {len(overlap)}/{len(null_set)} null members "
              f"({len(selected)}/26 total)")

    # KA indexing
    null_ka_indices = sorted(KA_IDX[ALPH[v]] for v in null_set)
    print(f"\n  Values (KA): {null_ka_indices}")
    ka_diffs = [null_ka_indices[i+1] - null_ka_indices[i]
                for i in range(len(null_ka_indices)-1)]
    print(f"  KA consecutive diffs: {ka_diffs}")

    results["B3_3_ka_indices"] = null_ka_indices

    # ── B3.4: Generative Tests ──────────────────────────────────────
    print("\n── B3.4: Generative Tests ──")

    # Test: is null_set = Cipher(single_letter, each_null_letter)?
    generative = {}
    for key_letter_idx in range(MOD):
        # Beaufort AZ: key_letter - input mod 26
        beau_outputs = frozenset((key_letter_idx - v) % MOD for v in range(MOD)
                                  if (key_letter_idx - v) % MOD in null_set)
        if len(beau_outputs) == len(null_set):
            # This key maps some set of inputs to exactly the null set
            preimage = frozenset(v for v in range(MOD)
                                 if (key_letter_idx - v) % MOD in null_set)
            generative[f"beaufort_key_{ALPH[key_letter_idx]}"] = {
                "preimage": sorted(preimage),
                "preimage_letters": sorted(ALPH[v] for v in preimage),
            }

    results["B3_4_generative"] = generative
    if generative:
        print(f"  Found {len(generative)} generative key mappings:")
        for name, data in generative.items():
            print(f"    {name}: preimage = {data['preimage_letters']}")
    else:
        print("  No single-key generative mapping found.")

    # ── B3.5: Cross-Layer Test ──────────────────────────────────────
    print("\n── B3.5: Cross-Layer Test ──")
    ks_nums = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]

    ks_in_null = [v for v in ks_nums if v in null_set]
    ks_in_real = [v for v in ks_nums if v in real_set]

    cross_layer = {
        "keystream_values": ks_nums,
        "ks_in_null_set": len(ks_in_null),
        "ks_in_real_set": len(ks_in_real),
        "ks_null_fraction": len(ks_in_null) / len(ks_nums),
        "expected_null_fraction": len(null_set) / MOD,
    }

    # Additive inverses
    null_inverses = frozenset((MOD - v) % MOD for v in null_set)
    ks_set = frozenset(ks_nums)
    cross_layer["inverse_overlap_with_ks"] = len(null_inverses & ks_set)

    results["B3_5_cross_layer"] = cross_layer
    print(f"  Keystream values in null set: {len(ks_in_null)}/24 "
          f"(expected: {len(null_set)/MOD*24:.1f})")
    print(f"  Keystream values in real set: {len(ks_in_real)}/24")
    print(f"  Null set additive inverses ∩ keystream: "
          f"{cross_layer['inverse_overlap_with_ks']}")

    # ── Verdict ─────────────────────────────────────────────────────
    print(f"\n{'=' * 80}")

    structured_signals = []
    # Check for row/col concentration in either grid
    for grid_name, rows, cols in [("AZ", az_rows, az_cols), ("KA", ka_rows, ka_cols)]:
        if len(rows) <= 3:
            structured_signals.append(f"{grid_name} grid: null set in {len(rows)} rows")
        if len(cols) <= 2:
            structured_signals.append(f"{grid_name} grid: null set in {len(cols)} columns")
    # Check for modular concentration
    for m in range(2, 8):
        residues = set(v % m for v in null_list)
        if len(residues) <= m // 2:
            structured_signals.append(f"mod-{m}: only {len(residues)}/{m} residues")
    # Check for generative mapping
    if generative:
        structured_signals.append(f"{len(generative)} generative key mappings found")

    results["structured_signals"] = structured_signals

    if structured_signals:
        results["verdict"] = "STRUCTURED"
        print("VERDICT: STRUCTURED — partition has algebraic structure")
        for sig in structured_signals:
            print(f"  ✓ {sig}")
    else:
        results["verdict"] = "ARBITRARY"
        print("VERDICT: ARBITRARY — no structural interpretation found")
        print("  → CRITICAL GATE FAILED. Classification is descriptive, not generative.")
        print("  → Phase C still runs on weaker (existing) constraints.")

    print(f"{'=' * 80}")

    out_path = os.path.join(_ROOT, "results", "stego_mechanism", "partition_analysis.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


def _factorize(n):
    """Simple factorization for display."""
    if n <= 1:
        return str(n)
    factors = []
    d = 2
    temp = n
    while d * d <= temp:
        while temp % d == 0:
            factors.append(d)
            temp //= d
        d += 1
    if temp > 1:
        factors.append(temp)
    return " × ".join(str(f) for f in factors) if len(factors) > 1 else str(n)


if __name__ == "__main__":
    run_b3()
```

- [ ] **Step 2: Run the script**

```bash
PYTHONPATH=src python3 -u scripts/stego_mechanism/e_partition_analysis.py
```

Expected: <1 minute. Key output: the VERDICT line (STRUCTURED or ARBITRARY).

- [ ] **Step 3: Review results — this is the critical gate**

If `STRUCTURED`: the partition has algebraic meaning. Proceed to B4.
If `ARBITRARY`: the classification is descriptive. Skip B4/B5. Phase C still runs on existing constraints. Report the descriptive finding and update MEMORY.md.

- [ ] **Step 4: Commit**

```bash
git add scripts/stego_mechanism/e_partition_analysis.py results/stego_mechanism/partition_analysis.json
git commit -m "feat(stego): B3 partition analysis — critical gate"
```

---

## Task 5: Phase B4 — Mixed Cells and Varying Nulls

**Files:**
- Create: `scripts/stego_mechanism/e_mixed_cell_varying.py`
- Output: `results/stego_mechanism/mixed_cell_varying.json`

**Purpose:** Formalize the mixed-cell tiebreaker. Test the false-positive model for varying nulls. Identify secondary filter candidates.

**Gate:** Only run if B3 verdict is `STRUCTURED`.

- [ ] **Step 1: Write the script**

Create `scripts/stego_mechanism/e_mixed_cell_varying.py` with:

```python
#!/usr/bin/env python3
"""
Phase B4: Mixed Cells and Varying Null Resolution

B4.1: Formalize the "first occurrence = null" tiebreaker for 3 mixed cells.
B4.2: False-positive model — which non-palette positions fall in null cells?
B4.3: Position-only rule produces ~39 nulls; identify secondary filter.
B4.4: Validate predicted varying nulls against Bean constraints.

Output: results/stego_mechanism/mixed_cell_varying.json
"""
import sys, os, json
from collections import defaultdict
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ,
)

KA = KRYPTOS_ALPHABET

# ── Build table structures ──────────────────────────────────────────
PALETTE_POSITIONS = sorted(p for p in range(CT_LEN) if CT[p] in NULL_PALETTE)
ALL_POSITIONS = list(range(CT_LEN))

cell_data = defaultdict(list)
for p in PALETTE_POSITIONS:
    cell_data[(p % 7, p % 5)].append((p, p in CONSENSUS_NULL_POSITIONS))

# Full table classification
table = {}
for r in range(7):
    for c in range(5):
        entries = cell_data.get((r, c), [])
        if not entries:
            table[(r, c)] = {"type": "empty", "positions": []}
        else:
            nulls = [e for e in entries if e[1]]
            reals = [e for e in entries if not e[1]]
            if nulls and not reals:
                table[(r, c)] = {"type": "null", "positions": entries}
            elif reals and not nulls:
                table[(r, c)] = {"type": "real", "positions": entries}
            else:
                table[(r, c)] = {"type": "mixed", "positions": entries}

# Identify null cells (pure null + mixed)
null_cells = {rc for rc, v in table.items() if v["type"] in ("null", "mixed")}


def run_b4():
    results = {
        "experiment": "e_mixed_cell_varying",
        "date": datetime.now(timezone.utc).isoformat(),
    }

    print("=" * 80)
    print("PHASE B4: MIXED CELLS AND VARYING NULLS")
    print("=" * 80)

    # ── B4.1: Tiebreaker formalization ──────────────────────────────
    print("\n── B4.1: Mixed Cell Tiebreaker ──")
    mixed_cells = {rc: v for rc, v in table.items() if v["type"] == "mixed"}
    b4_1 = {"mixed_cells": {}}

    for rc, data in sorted(mixed_cells.items()):
        positions = data["positions"]
        null_pos = [p for p, is_null in positions if is_null]
        real_pos = [p for p, is_null in positions if not is_null]
        first_is_null = min(null_pos) < min(real_pos)

        cell_info = {
            "cell": list(rc),
            "null_positions": null_pos,
            "real_positions": real_pos,
            "null_chars": [CT[p] for p in null_pos],
            "real_chars": [CT[p] for p in real_pos],
            "first_is_null": first_is_null,
        }
        b4_1["mixed_cells"][str(rc)] = cell_info

        print(f"  Cell {rc}: null@{null_pos}({[CT[p] for p in null_pos]}) "
              f"vs real@{real_pos}({[CT[p] for p in real_pos]}) "
              f"→ first_is_null={first_is_null}")

    all_first_null = all(v["first_is_null"] for v in b4_1["mixed_cells"].values())
    b4_1["tiebreaker_rule"] = "first_occurrence_is_null" if all_first_null else "INCONSISTENT"
    results["B4_1_tiebreaker"] = b4_1
    print(f"  → Rule: {b4_1['tiebreaker_rule']}")

    # Test alternative: if BOTH positions in mixed cells are null
    both_null_count = 17 + sum(len(v["real_positions"]) for v in b4_1["mixed_cells"].values())
    print(f"  If both-null in mixed cells: {both_null_count} consensus nulls "
          f"(need {24 - both_null_count} varying)")

    # ── B4.2: False-positive model ──────────────────────────────────
    print("\n── B4.2: False-Positive Model ──")

    # Find ALL positions (palette and non-palette) in null cells
    positions_in_null_cells = []
    for p in range(CT_LEN):
        cell = (p % 7, p % 5)
        if cell in null_cells:
            positions_in_null_cells.append(p)

    # Split by palette membership
    palette_in_null = [p for p in positions_in_null_cells if CT[p] in NULL_PALETTE]
    non_palette_in_null = [p for p in positions_in_null_cells if CT[p] not in NULL_PALETTE]

    b4_2 = {
        "total_positions_in_null_cells": len(positions_in_null_cells),
        "palette_in_null_cells": len(palette_in_null),
        "non_palette_in_null_cells": len(non_palette_in_null),
        "non_palette_positions": non_palette_in_null,
        "non_palette_chars": [CT[p] for p in non_palette_in_null],
    }

    print(f"  Positions in null cells: {len(positions_in_null_cells)}")
    print(f"  Palette positions in null cells: {len(palette_in_null)} "
          f"(these include the 17 consensus nulls)")
    print(f"  Non-palette positions in null cells: {len(non_palette_in_null)}")
    print(f"    Positions: {non_palette_in_null}")
    print(f"    Characters: {[CT[p] for p in non_palette_in_null]}")

    # Which of these are in crib ranges?
    in_crib = [p for p in non_palette_in_null if p in CRIB_POSITIONS]
    not_in_crib = [p for p in non_palette_in_null if p not in CRIB_POSITIONS]

    b4_2["in_crib_ranges"] = in_crib
    b4_2["outside_crib_ranges"] = not_in_crib
    print(f"  In crib ranges: {in_crib} (cannot be nulls)")
    print(f"  Outside crib ranges: {not_in_crib} (varying null candidates)")

    # Compare to prior VP-1 candidates
    prior_vp1_candidates = {39, 40, 43, 55, 87, 94}
    overlap = set(not_in_crib) & prior_vp1_candidates
    b4_2["vp1_overlap"] = sorted(overlap)
    b4_2["vp1_overlap_fraction"] = f"{len(overlap)}/{len(prior_vp1_candidates)}"
    print(f"  VP-1 overlap: {sorted(overlap)} ({len(overlap)}/{len(prior_vp1_candidates)})")

    results["B4_2_false_positive"] = b4_2

    # ── B4.3: Secondary filter ──────────────────────────────────────
    print("\n── B4.3: Secondary Filter Candidates ──")

    # We need exactly 7 varying nulls from the non-crib, non-palette null-cell positions
    candidates = not_in_crib
    need = 7
    b4_3 = {
        "candidate_count": len(candidates),
        "need": need,
        "candidates": candidates,
    }

    if len(candidates) == need:
        print(f"  EXACTLY {need} candidates — no secondary filter needed!")
        b4_3["filter_needed"] = False
        b4_3["predicted_varying_nulls"] = candidates
    elif len(candidates) > need:
        print(f"  {len(candidates)} candidates for {need} slots — secondary filter needed")
        b4_3["filter_needed"] = True
        # Test: first N by position order
        first_n = sorted(candidates)[:need]
        b4_3["first_n_by_position"] = first_n
        print(f"    First {need} by position: {first_n}")

        # Test: character-based grouping
        char_groups = defaultdict(list)
        for p in candidates:
            char_groups[CT[p]].append(p)
        b4_3["char_groups"] = {k: v for k, v in sorted(char_groups.items())}
        print(f"    Character groups: {dict(char_groups)}")
    else:
        print(f"  Only {len(candidates)} candidates for {need} slots — model incomplete")
        b4_3["filter_needed"] = True
        b4_3["deficit"] = need - len(candidates)

    results["B4_3_secondary_filter"] = b4_3

    # ── B4.4: Validation ────────────────────────────────────────────
    print("\n── B4.4: Validation ──")

    # If we have a predicted mask, validate it
    predicted_nulls = set(CONSENSUS_NULL_POSITIONS)
    if not b4_3.get("filter_needed", True) and "predicted_varying_nulls" in b4_3:
        predicted_nulls |= set(b4_3["predicted_varying_nulls"])
    elif "first_n_by_position" in b4_3:
        predicted_nulls |= set(b4_3["first_n_by_position"])

    b4_4 = {"predicted_null_count": len(predicted_nulls)}

    if len(predicted_nulls) == 24:
        predicted_real = sorted(set(range(CT_LEN)) - predicted_nulls)
        real_text = "".join(CT[p] for p in predicted_real)
        b4_4["real_positions"] = predicted_real
        b4_4["real_text_length"] = len(real_text)

        # Bean EQ check
        eq_pos_a, eq_pos_b = BEAN_EQ
        if eq_pos_a in predicted_nulls or eq_pos_b in predicted_nulls:
            b4_4["bean_eq"] = "N/A (one of EQ positions is null)"
        else:
            # Both are real — check if they're at the same keystream index
            b4_4["bean_eq"] = "POSITIONS_REAL"

        # Check crib coverage
        crib_in_real = sum(1 for p in CRIB_POSITIONS if p not in predicted_nulls)
        b4_4["crib_coverage"] = f"{crib_in_real}/{len(CRIB_POSITIONS)}"

        print(f"  Predicted mask: {len(predicted_nulls)} nulls")
        print(f"  Real text length: {len(real_text)}")
        print(f"  Crib coverage: {b4_4['crib_coverage']}")
    else:
        print(f"  Predicted mask has {len(predicted_nulls)} nulls (target: 24)")

    results["B4_4_validation"] = b4_4

    # ── Verdict ─────────────────────────────────────────────────────
    print(f"\n{'=' * 80}")
    if not b4_3.get("filter_needed", True):
        results["verdict"] = "COMPLETE_MASK_PREDICTED"
        print("VERDICT: COMPLETE — mechanism predicts all 24 null positions")
    elif len(candidates) >= need:
        results["verdict"] = "PARTIAL_NEEDS_FILTER"
        print(f"VERDICT: PARTIAL — {len(candidates)} candidates for {need} slots, "
              f"secondary filter needed")
    else:
        results["verdict"] = "INCOMPLETE"
        print(f"VERDICT: INCOMPLETE — only {len(candidates)} candidates for {need} slots")
    print(f"{'=' * 80}")

    out_path = os.path.join(_ROOT, "results", "stego_mechanism", "mixed_cell_varying.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


if __name__ == "__main__":
    run_b4()
```

- [ ] **Step 2: Run the script**

```bash
PYTHONPATH=src python3 -u scripts/stego_mechanism/e_mixed_cell_varying.py
```

Expected: <1 minute. Key outputs: tiebreaker rule confirmation, candidate count for varying nulls, whether a secondary filter is needed.

- [ ] **Step 3: Commit**

```bash
git add scripts/stego_mechanism/e_mixed_cell_varying.py results/stego_mechanism/mixed_cell_varying.json
git commit -m "feat(stego): B4 mixed cells and varying null resolution"
```

---

## Task 6: Phase B5 — Full Generative Specification Test

**Files:**
- Create: `scripts/stego_mechanism/e_full_spec_test.py`
- Output: `results/stego_mechanism/full_spec_test.json`

**Purpose:** Write the stego mechanism as a clean, self-contained specification. Test it by reconstructing the null positions from ONLY the keywords and rules — NO access to the null position data during computation. Compare predicted positions to known consensus nulls.

- [ ] **Step 1: Write the script**

Create `scripts/stego_mechanism/e_full_spec_test.py` with:

```python
#!/usr/bin/env python3
"""
Phase B5: Full Generative Specification Test

Implements the complete stego mechanism from keywords + rules ONLY.
Does NOT read CONSENSUS_NULL_POSITIONS during mask generation.
Compares predicted mask to known consensus after generation.

This is the "independent reconstruction" test: can the spec alone
reproduce the consensus null positions?

Output: results/stego_mechanism/full_spec_test.json
"""
import sys, os, json
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
# NOTE: We deliberately do NOT import CONSENSUS_NULL_POSITIONS here.
# We will load it ONLY for validation at the end.

# ══════════════════════════════════════════════════════════════════════
# SPECIFICATION — derived from B1-B4 results
# Fill these in after running B1-B4. Placeholders use CHART:vigenere_az.
# ══════════════════════════════════════════════════════════════════════

# Keyword 1: KRYPTOS (row keyword, 7 letters)
KW_ROW = "KRYPTOS"

# Keyword 2: SEVEN (column keyword / palette generator, 5 letters)
KW_COL_PALETTE = "SEVEN"

# Keyword 3: CHART (table generator, 5 letters) — or updated from B1/B2
KW_COL_TABLE = "CHART"

# Cipher operation for table generation
TABLE_CIPHER = "vigenere_az"  # or updated from B1/B2

# Null output set — MUST be updated from B3 results
# Default: CHART:vigenere_az partition
NULL_OUTPUT_SET = frozenset([3, 8, 12, 15, 16, 19, 20, 24])

# Palette: generated by KRYPTOS × SEVEN on KA grid (prior validated finding)
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
PALETTE = frozenset()  # Will be computed below


def generate_palette():
    """Generate palette from KRYPTOS × SEVEN on 5-wide KA grid."""
    grid = []
    for i in range(0, len(KA), 5):
        grid.append(KA[i:i+5])
    # Row 5 may have only 1 letter

    kryptos_set = frozenset(KW_ROW)
    seven_set = frozenset(KW_COL_PALETTE)
    palette = set()

    for r, row in enumerate(grid):
        kryptos_trigger = any(row[c] in kryptos_set for c in range(min(3, len(row))))
        seven_trigger = any(row[c] in seven_set for c in range(min(3, len(row))))

        if kryptos_trigger:
            palette.add(row[0])  # col 0
        if seven_trigger and len(row) > 3:
            palette.add(row[3])  # col 3
        if not kryptos_trigger and not seven_trigger:
            palette.add(row[0])  # default col 0

    return frozenset(palette)


def classify_position(pos, ct_char):
    """Classify a single position as null or real using the spec."""
    r = pos % len(KW_ROW)   # 7
    c = pos % len(KW_COL_TABLE)  # 5

    # Compute table cipher output
    row_letter = KW_ROW[r]
    col_letter = KW_COL_TABLE[c]

    row_val = ALPH_IDX[row_letter]
    col_val = ALPH_IDX[col_letter]

    if TABLE_CIPHER == "vigenere_az":
        output = (row_val + col_val) % MOD
    elif TABLE_CIPHER == "beaufort_az":
        output = (row_val - col_val) % MOD
    else:
        raise ValueError(f"Unknown cipher: {TABLE_CIPHER}")

    cell_is_null = output in NULL_OUTPUT_SET
    char_in_palette = ct_char in PALETTE

    return cell_is_null, char_in_palette


def generate_mask():
    """Generate the complete null mask from the specification."""
    # Phase 1: classify all positions
    classifications = []
    for p in range(CT_LEN):
        cell_null, in_palette = classify_position(p, CT[p])
        classifications.append({
            "pos": p,
            "ct_char": CT[p],
            "cell_is_null": cell_null,
            "in_palette": in_palette,
        })

    # Phase 2: assign null status
    # Consensus null: palette letter in null cell
    consensus_nulls = set()
    # Track mixed cells (multiple palette letters in same null cell)
    cell_palette_positions = {}  # (r,c) -> list of palette positions in null cells
    for cl in classifications:
        if cl["cell_is_null"] and cl["in_palette"]:
            cell = (cl["pos"] % len(KW_ROW), cl["pos"] % len(KW_COL_TABLE))
            cell_palette_positions.setdefault(cell, []).append(cl["pos"])

    # Apply tiebreaker: first occurrence in each cell is null
    for cell, positions in cell_palette_positions.items():
        if len(positions) == 1:
            consensus_nulls.add(positions[0])
        else:
            # Mixed cell: first position is null, rest are real
            consensus_nulls.add(min(positions))

    # Varying nulls: non-palette positions in null cells, outside crib ranges
    # (Load crib positions for this check)
    from kryptos.kernel.constants import CRIB_POSITIONS
    varying_candidates = []
    for cl in classifications:
        if cl["cell_is_null"] and not cl["in_palette"]:
            if cl["pos"] not in CRIB_POSITIONS:
                varying_candidates.append(cl["pos"])

    return consensus_nulls, varying_candidates, classifications


def run_b5():
    global PALETTE

    results = {
        "experiment": "e_full_spec_test",
        "date": datetime.now(timezone.utc).isoformat(),
        "spec_params": {
            "kw_row": KW_ROW,
            "kw_col_palette": KW_COL_PALETTE,
            "kw_col_table": KW_COL_TABLE,
            "table_cipher": TABLE_CIPHER,
            "null_output_set": sorted(NULL_OUTPUT_SET),
        },
    }

    print("=" * 80)
    print("PHASE B5: FULL GENERATIVE SPECIFICATION TEST")
    print("=" * 80)

    # Generate palette
    PALETTE = generate_palette()
    print(f"Generated palette: {sorted(PALETTE)}")
    results["generated_palette"] = sorted(PALETTE)

    # Check against known palette
    from kryptos.kernel.constants import NULL_PALETTE
    palette_match = PALETTE == frozenset(NULL_PALETTE)
    results["palette_matches_known"] = palette_match
    print(f"Palette matches known {sorted(NULL_PALETTE)}? {palette_match}")

    if not palette_match:
        print("WARNING: Generated palette doesn't match. Spec may be wrong.")

    # Generate mask
    consensus_nulls, varying_candidates, classifications = generate_mask()

    print(f"\nPredicted consensus nulls ({len(consensus_nulls)}): {sorted(consensus_nulls)}")
    print(f"Varying null candidates ({len(varying_candidates)}): {varying_candidates}")

    results["predicted_consensus_nulls"] = sorted(consensus_nulls)
    results["varying_null_candidates"] = varying_candidates
    results["predicted_consensus_count"] = len(consensus_nulls)

    # ── Validate against known consensus ────────────────────────────
    from kryptos.kernel.constants import CONSENSUS_NULL_POSITIONS
    known = frozenset(CONSENSUS_NULL_POSITIONS)

    match_count = len(consensus_nulls & known)
    false_positives = consensus_nulls - known
    false_negatives = known - consensus_nulls

    results["validation"] = {
        "known_consensus_count": len(known),
        "predicted_count": len(consensus_nulls),
        "match_count": match_count,
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
        "accuracy": match_count / len(known) if known else 0,
    }

    print(f"\n── Validation ──")
    print(f"  Known consensus nulls: {len(known)}")
    print(f"  Predicted: {len(consensus_nulls)}")
    print(f"  Matches: {match_count}/{len(known)}")
    if false_positives:
        print(f"  False positives: {sorted(false_positives)}")
    if false_negatives:
        print(f"  False negatives: {sorted(false_negatives)}")

    if match_count == len(known) and len(consensus_nulls) == len(known):
        results["verdict"] = "PERFECT_RECONSTRUCTION"
        print(f"\nVERDICT: PERFECT — spec reconstructs all {len(known)} consensus nulls")
    elif match_count == len(known):
        results["verdict"] = "SUPERSET"
        print(f"\nVERDICT: SUPERSET — all known nulls found, plus {len(false_positives)} extras")
    else:
        results["verdict"] = f"PARTIAL_{match_count}_OF_{len(known)}"
        print(f"\nVERDICT: PARTIAL — {match_count}/{len(known)} consensus nulls reconstructed")

    out_path = os.path.join(_ROOT, "results", "stego_mechanism", "full_spec_test.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


if __name__ == "__main__":
    run_b5()
```

- [ ] **Step 2: Run the script**

```bash
PYTHONPATH=src python3 -u scripts/stego_mechanism/e_full_spec_test.py
```

Expected: PERFECT_RECONSTRUCTION if the spec correctly predicts all 17 consensus nulls. If not, check which positions are wrong — these indicate spec errors.

- [ ] **Step 3: Update spec parameters if B1-B4 changed the defaults**

If B1 killed CHART (a simpler system works), update `KW_COL_TABLE`, `TABLE_CIPHER`, and `NULL_OUTPUT_SET` in the script. Re-run.

- [ ] **Step 4: Commit**

```bash
git add scripts/stego_mechanism/e_full_spec_test.py results/stego_mechanism/full_spec_test.json
git commit -m "feat(stego): B5 full generative spec — independent reconstruction test"
```

---

## Task 7: Phase C — Constraint Propagation to Cipher

**Files:**
- Create: `scripts/stego_mechanism/e_constraint_propagation.py`
- Output: `results/stego_mechanism/constraint_propagation.json`

**Purpose:** Push every confirmed stego property into the cipher layer as a hard constraint. Test mod-6 substitutions on the row-key sequence. Check partition-cipher interaction. Compare mechanism-predicted mask to consensus mask.

- [ ] **Step 1: Write the script**

Create `scripts/stego_mechanism/e_constraint_propagation.py` with:

```python
#!/usr/bin/env python3
"""
Phase C: Constraint Propagation — Stego → Cipher

C1: Palette-enriched keystream as hard constraint
C2: AP {G,K,O} structural requirement
C3: Row-key mod-6 substitution search (720 permutations × 4 input sources)
C4: Partition-cipher interaction
C5: Mask-conditioned cipher re-test (compare mechanism mask vs consensus)

Output: results/stego_mechanism/constraint_propagation.json
"""
import sys, os, json
from collections import Counter
from datetime import datetime, timezone
from itertools import permutations

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAUFORT_KEYSTREAM_AT_CRIBS,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# Known row key (Beaufort, from split-coordinate model)
ROW_KEY = [4, 4, 1, 4, 1, 5, 0, 0, 5, 4, 1, 2, 1, 4, 2, 0, 1, 3, 3, 4, 2, 3, 1, 0]
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)


def run_c():
    results = {
        "experiment": "e_constraint_propagation",
        "date": datetime.now(timezone.utc).isoformat(),
    }

    print("=" * 80)
    print("PHASE C: CONSTRAINT PROPAGATION (Stego → Cipher)")
    print("=" * 80)

    # Load B3 partition if available
    b3_path = os.path.join(_ROOT, "results", "stego_mechanism", "partition_analysis.json")
    if os.path.exists(b3_path):
        with open(b3_path) as f:
            b3 = json.load(f)
        null_set = frozenset(b3["null_set_az_indices"])
    else:
        null_set = frozenset([3, 8, 12, 15, 16, 19, 20, 24])

    null_letters = frozenset(ALPH[v] for v in null_set)
    palette_nums = frozenset(ALPH_IDX[c] for c in NULL_PALETTE)

    # ── C1: Palette-enriched keystream ──────────────────────────────
    print("\n── C1: Palette-Enriched Keystream ──")
    ks_nums = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]

    ks_in_palette = sum(1 for v in ks_nums if v in palette_nums)
    expected = len(ks_nums) * len(palette_nums) / MOD

    c1 = {
        "observed": ks_in_palette,
        "expected_random": round(expected, 2),
        "total": len(ks_nums),
        "constraint": f"Any cipher must produce >= {max(1, int(expected * 1.5))}/24 "
                      f"palette membership (2σ filter: reject if < {max(1, int(expected + 2 * (expected * (1 - len(palette_nums)/MOD))**0.5))})",
    }
    results["C1_palette_enrichment"] = c1
    print(f"  Keystream palette membership: {ks_in_palette}/24 "
          f"(expected random: {expected:.1f})")

    # ── C2: AP {G,K,O} structural requirement ──────────────────────
    print("\n── C2: AP {G,K,O} Structural Requirement ──")
    ap_set = {ALPH_IDX[c] for c in "GKO"}
    ks_in_ap = sum(1 for v in ks_nums if v in ap_set)

    # Map to KA rows
    ap_ka_rows = {KA_IDX[c] // 5 for c in "GKO"}

    c2 = {
        "ap_values_az": sorted(ap_set),
        "ap_ka_rows": sorted(ap_ka_rows),
        "ks_in_ap": ks_in_ap,
        "total": len(ks_nums),
        "constraint": f"Cipher key at {ks_in_ap}/24 positions must produce "
                      f"Polybius rows {sorted(ap_ka_rows)}",
    }
    results["C2_ap_requirement"] = c2
    print(f"  AP {{G,K,O}} at {ks_in_ap}/24 keystream positions")
    print(f"  KA row mapping: G→row{KA_IDX['G']//5}, K→row{KA_IDX['K']//5}, "
          f"O→row{KA_IDX['O']//5}")

    # ── C3: Row-key mod-6 substitution search ──────────────────────
    print("\n── C3: Row-Key Mod-6 Substitution Search ──")

    # Input sources for substitution
    input_sources = {}

    # (a) Sequential position index mod 6
    input_sources["pos_mod6"] = [p % 6 for p in CRIB_POS_SORTED]

    # (b) CT letter at crib position mod 6
    input_sources["ct_mod6"] = [ALPH_IDX[CT[p]] % 6 for p in CRIB_POS_SORTED]

    # (c) PT letter at crib position mod 6
    crib_pts = []
    for p in CRIB_POS_SORTED:
        crib_pts.append(ALPH_IDX[CRIB_DICT[p]])
    input_sources["pt_mod6"] = [v % 6 for v in crib_pts]

    # (d) Column key mod 5 (with 0-pad for 6th value)
    col_keys_beaufort = []
    for p in CRIB_POS_SORTED:
        ct_val = ALPH_IDX[CT[p]]
        pt_val = ALPH_IDX[CRIB_DICT[p]]
        col_keys_beaufort.append((ct_val + pt_val) % MOD % 5)
    input_sources["col_key_mod5"] = col_keys_beaufort

    c3 = {"input_sources": {}, "best_overall": {"score": 0}}

    for src_name, src_vals in input_sources.items():
        best_perm = None
        best_score = 0

        # Test all 720 permutations of {0,1,2,3,4,5}
        for perm in permutations(range(6)):
            mapped = [perm[v] for v in src_vals]
            score = sum(1 for a, b in zip(mapped, ROW_KEY) if a == b)
            if score > best_score:
                best_score = score
                best_perm = perm

        c3["input_sources"][src_name] = {
            "input_values": src_vals,
            "best_perm": list(best_perm) if best_perm else None,
            "best_score": best_score,
            "total": len(ROW_KEY),
        }

        if best_score > c3["best_overall"]["score"]:
            c3["best_overall"] = {
                "source": src_name, "score": best_score,
                "perm": list(best_perm) if best_perm else None,
            }

        print(f"  {src_name}: best perm score = {best_score}/24")

    # Expected by chance: for each position, P(match) = 1/6. Expected = 24/6 = 4.
    c3["expected_random"] = 4.0
    c3["constraint"] = (
        f"Best mod-6 substitution: {c3['best_overall']['score']}/24 "
        f"from {c3['best_overall']['source']} (expected random: 4.0)"
    )
    results["C3_mod6_substitution"] = c3
    print(f"  → Best overall: {c3['best_overall']['source']} at "
          f"{c3['best_overall']['score']}/24 (random baseline: 4.0)")

    # ── C4: Partition-cipher interaction ────────────────────────────
    print("\n── C4: Partition-Cipher Interaction ──")

    ks_in_null_part = sum(1 for v in ks_nums if v in null_set)
    expected_null = len(ks_nums) * len(null_set) / MOD

    c4 = {
        "ks_in_null_partition": ks_in_null_part,
        "expected_random": round(expected_null, 2),
        "total": len(ks_nums),
        "avoidance_or_preference": (
            "AVOIDANCE" if ks_in_null_part < expected_null * 0.5
            else "PREFERENCE" if ks_in_null_part > expected_null * 1.5
            else "NEUTRAL"
        ),
    }
    results["C4_partition_interaction"] = c4
    print(f"  Keystream values in null output partition: {ks_in_null_part}/24 "
          f"(expected: {expected_null:.1f})")
    print(f"  → {c4['avoidance_or_preference']}")

    # ── C5: Constraint Summary ──────────────────────────────────────
    print(f"\n── C5: Constraint Summary ──")
    constraints = []

    constraints.append(f"C1: Cipher must produce ≥{ks_in_palette}/24 palette keystream "
                       f"(vs {expected:.1f} random)")
    constraints.append(f"C2: {ks_in_ap}/24 positions must map to AP rows "
                       f"{sorted(ap_ka_rows)} in KA grid")
    constraints.append(f"C3: Row key is NOT a simple mod-6 substitution of "
                       f"position/CT/PT/colkey (best: {c3['best_overall']['score']}/24)")
    constraints.append(f"C4: Keystream-partition interaction: {c4['avoidance_or_preference']}")
    constraints.append("C5: Row key is non-periodic, non-autokey, non-NDYAHR, "
                       "non-Berlin-Clock-routed (prior eliminations)")

    results["constraints_summary"] = constraints
    for con in constraints:
        print(f"  {con}")

    # New constraints (beyond existing CxS-1..4)
    new_constraints = []
    if c3["best_overall"]["score"] <= 6:  # not much better than random
        new_constraints.append(
            "Row key is NOT a substitution cipher of any tested input source at mod-6 level"
        )
    if c4["avoidance_or_preference"] != "NEUTRAL":
        new_constraints.append(
            f"Keystream {c4['avoidance_or_preference'].lower()}s the null output partition "
            f"({ks_in_null_part}/24 vs {expected_null:.1f} expected)"
        )

    results["new_constraints"] = new_constraints
    results["verdict"] = (
        "NEW_CONSTRAINTS_FOUND" if new_constraints else "NO_NEW_CONSTRAINTS"
    )

    print(f"\n{'=' * 80}")
    if new_constraints:
        print(f"VERDICT: {len(new_constraints)} NEW CONSTRAINT(S) FOUND")
        for nc in new_constraints:
            print(f"  → {nc}")
    else:
        print("VERDICT: No new constraints beyond existing CxS-1..4")
    print(f"{'=' * 80}")

    out_path = os.path.join(_ROOT, "results", "stego_mechanism",
                            "constraint_propagation.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {out_path}")

    return results


if __name__ == "__main__":
    run_c()
```

- [ ] **Step 2: Run the script**

```bash
PYTHONPATH=src python3 -u scripts/stego_mechanism/e_constraint_propagation.py
```

Expected: <1 minute. Key output: which new constraints (if any) were discovered.

- [ ] **Step 3: Review and commit**

```bash
git add scripts/stego_mechanism/e_constraint_propagation.py results/stego_mechanism/constraint_propagation.json
git commit -m "feat(stego): Phase C constraint propagation — stego to cipher"
```

---

## Task 8: Update Memory and Commit Final Results

**Files:**
- Update: `memory/stego_mechanism_formalization.md` (create if needed)
- Update: MEMORY.md (if findings change the paradigm)

- [ ] **Step 1: Write memory file summarizing all results**

Create/update `memory/stego_mechanism_formalization.md` with:
- B1 verdict (did simpler systems work?)
- B2 partition uniqueness (is the partition determined by the table, or by the word?)
- B3 verdict (STRUCTURED or ARBITRARY — the critical gate)
- B4 varying null predictions
- B5 reconstruction accuracy
- C new constraints

- [ ] **Step 2: Update MEMORY.md if the paradigm changed**

If B3 found structure → update "GROUND TRUTH" and "OPEN ATTACK SURFACE" sections.
If B3 found arbitrary → update "CONFIRMED REAL" to note the descriptive finding.
If C found new constraints → update "OPEN ATTACK SURFACE" with new filters.

- [ ] **Step 3: Final commit**

```bash
git add -A memory/ results/stego_mechanism/
git commit -m "docs: stego mechanism formalization — full results and memory update"
```
