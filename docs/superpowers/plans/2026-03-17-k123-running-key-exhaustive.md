# K1-K3 Running Key Exhaustive Transformation Search — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Exhaustively test K1-K3 plaintext as a running key through ~60 transformations (offsets, transpositions, decimation, interleaving, cross-encryption) under 6 cipher variants and 2 models, then fall back to 500-text Gutenberg scan if no signal.

**Architecture:** Single self-contained script (`scripts/campaigns/f_k123_running_key_exhaustive_v1.py`) handles Phases 1-3. A separate script (`scripts/campaigns/f_gutenberg_running_key_scan_v1.py`) handles Phase 4. Both use the existing `kryptos.kernel.constants` for CT/cribs and the proven crib-drag pattern from `scripts/two_system/e_running_key_crib_drag.py`.

**Tech Stack:** Python 3.11+ stdlib only. `multiprocessing.Pool` for parallelism. `json` for output. No external dependencies.

**Spec:** `docs/superpowers/specs/2026-03-17-k123-running-key-exhaustive-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `scripts/campaigns/f_k123_running_key_exhaustive_v1.py` | Phases 1-3: text generation, crib-drag, signal classification |
| `scripts/campaigns/f_gutenberg_running_key_scan_v1.py` | Phase 4: download + scan 500 Gutenberg texts |
| `results/k123_running_key_exhaustive/summary.json` | Phase 1-3 output |
| `results/k123_running_key_exhaustive/phase4_gutenberg/scan_results.json` | Phase 4 output |

No test file needed — this is a one-shot experiment script, not library code. Validation is by crib-match count (the scoring IS the test).

---

### Task 1: Core Crib-Drag Engine

**Files:**
- Create: `scripts/campaigns/f_k123_running_key_exhaustive_v1.py`

This task builds the foundational functions: required-key derivation for all 6 variants, crib-drag with Bean EQ check, and the parallel dispatch harness.

- [ ] **Step 1: Create script with metadata header, imports, and constants**

```python
#!/usr/bin/env python3
"""
Cipher: running_key
Family: campaigns
Status: active
Keyspace: ~750K configs (K1-K3 x 60 transforms x 6 variants x 2 models)
Last run:
Best score:
"""
"""
K1-K3 Running Key Exhaustive Transformation Search

Sanborn: "I have left instructions in the earlier text that refer to later text."
K1-K3 plaintext tested as direct running key: max 7/24 = noise.
This script tests K1-K3 through ~60 transformations (columnar transposition,
decimation, rail fence, interleaving, cross-encryption, reversal) under
6 cipher variants (Beaufort/Vigenere/VarBeaufort x AZ/KA) and 2 models
(Model B raw CT97, Model A consensus-null CT73).

Output: results/k123_running_key_exhaustive/summary.json
"""
import json
import sys
import os
import time
import math
from itertools import permutations
from multiprocessing import Pool, cpu_count
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, MOD, BEAN_EQ

# ── K1-K3 Plaintexts ──────────────────────────────────────────────────────
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
K3_PT = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
         "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEA"
         "TINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLE"
         "ALITTLEINSERTEDACANDLEANDPEEREDIN")

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Consensus null positions (17 fixed + 7 varying = 24 total)
CONSENSUS_NULLS = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]

# Model A: extract CT73 by removing null positions
CT73 = "".join(CT[i] for i in range(CT_LEN) if i not in CONSENSUS_NULLS)
# Model A crib positions: map original positions to CT73 positions
CT73_CRIB_DICT = {}
orig_to_ct73 = {}
ct73_idx = 0
for i in range(CT_LEN):
    if i not in CONSENSUS_NULLS:
        orig_to_ct73[i] = ct73_idx
        if i in CRIB_DICT:
            CT73_CRIB_DICT[ct73_idx] = CRIB_DICT[i]
        ct73_idx += 1

RESULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results', 'k123_running_key_exhaustive')
```

- [ ] **Step 2: Add derive_required_key for all 6 variants**

```python
def derive_required_key(ct_text, crib_dict, variant, alphabet):
    """Derive required running-key character at each crib position.

    Returns {position: required_key_value} for each crib position.
    """
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    required = {}
    for pos, pt_ch in crib_dict.items():
        c = alph_idx[ct_text[pos]]
        p = alph_idx[pt_ch]
        if variant == "vigenere":
            k = (c - p) % 26
        elif variant == "beaufort":
            k = (c + p) % 26
        elif variant == "var_beaufort":
            k = (p - c) % 26
        else:
            raise ValueError(f"Unknown variant: {variant}")
        required[pos] = k
    return required


def crib_drag(text_alpha, required_key, window_len):
    """Slide window across text, count crib matches at each offset.

    Returns list of (offset, match_count) for matches >= 8.
    """
    n = len(text_alpha)
    if n < window_len:
        return []
    positions = sorted(required_key.keys())
    results = []
    for offset in range(n - window_len + 1):
        matches = sum(1 for pos in positions
                      if (ord(text_alpha[offset + pos]) - 65) == required_key[pos])
        if matches >= 8:
            results.append((offset, matches))
    return results


def check_bean_eq(text_alpha, offset, ct_text, variant, alphabet):
    """Check Bean equality k[27]=k[65] for a candidate running key offset."""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    keys = []
    for pos in (27, 65):
        c = alph_idx[ct_text[pos]]
        k_val = ord(text_alpha[offset + pos]) - 65
        keys.append(k_val)
    return keys[0] == keys[1]
```

- [ ] **Step 3: Verify crib-drag produces same results as existing script on K1K2K3 direct**

Run: `PYTHONPATH=src python3 -u -c "
import sys; sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, MOD
# Quick sanity: direct K1K2K3 as running key, Beaufort AZ
K1K2K3 = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSIONITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDSLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEINSERTEDACANDLEANDPEEREDIN'
required = {}
for pos, pt_ch in CRIB_DICT.items():
    c = ord(CT[pos]) - 65
    p = ord(pt_ch) - 65
    required[pos] = (c + p) % 26
best = 0
for off in range(len(K1K2K3) - 97 + 1):
    m = sum(1 for pos in required if ord(K1K2K3[off+pos])-65 == required[pos])
    best = max(best, m)
print(f'Direct K1K2K3 Beaufort AZ best: {best}/24')
"`

Expected: A number <=7 (confirming prior result, baseline).

- [ ] **Step 4: Commit**

```bash
git add scripts/campaigns/f_k123_running_key_exhaustive_v1.py
git commit -m "feat: add K1-K3 running key exhaustive search - core engine"
```

---

### Task 2: Phase 1 — Text Generation

**Files:**
- Modify: `scripts/campaigns/f_k123_running_key_exhaustive_v1.py`

Add all transformation functions and the text generation phase.

- [ ] **Step 1: Add transformation functions**

```python
def columnar_read(text, width, col_order):
    """Read text off a width-W grid by columns in given order.

    text is written row-by-row into grid, then read column-by-column
    in the order specified by col_order.
    """
    rows = math.ceil(len(text) / width)
    # Pad text to fill grid
    padded = text + "A" * (rows * width - len(text))
    result = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        for row in range(rows):
            idx = row * width + col_idx
            if idx < len(text):  # Don't include padding
                result.append(padded[idx])
    return "".join(result)


def keyword_to_order(keyword, width):
    """Convert keyword to column ordering (ascending rank of letters)."""
    kw = keyword[:width].upper()
    if len(kw) < width:
        return None
    indexed = sorted(range(len(kw)), key=lambda i: (kw[i], i))
    order = [0] * len(kw)
    for rank, pos in enumerate(indexed):
        order[pos] = rank
    return order


def decimation(text, step):
    """Read every step-th letter from text (wrapping)."""
    n = len(text)
    if math.gcd(step, n) != 1:
        # Non-coprime: just take every step-th without wrap
        return text[::step]
    result = []
    idx = 0
    for _ in range(n):
        result.append(text[idx % n])
        idx += step
    return "".join(result)


def rail_fence_read(text, rails):
    """Encode text as rail fence, read off by rail."""
    n = len(text)
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return "".join("".join(r) for r in fence)


def interleave(texts):
    """Interleave multiple texts: t1[0]t2[0]t3[0]t1[1]t2[1]..."""
    result = []
    max_len = max(len(t) for t in texts)
    for i in range(max_len):
        for t in texts:
            if i < len(t):
                result.append(t[i])
    return "".join(result)


def cross_encrypt(text_a, text_b, variant):
    """Encrypt text_a using text_b as running key under given variant."""
    min_len = min(len(text_a), len(text_b))
    result = []
    for i in range(min_len):
        a = ord(text_a[i]) - 65
        b = ord(text_b[i]) - 65
        if variant == "beaufort":
            c = (a + b) % 26
        else:  # vigenere
            c = (a - b) % 26
        result.append(chr(c + 65))
    return "".join(result)
```

- [ ] **Step 2: Add generate_derived_texts function**

```python
def generate_derived_texts():
    """Generate all ~60 derived running-key candidate texts from K1-K3 PT.

    Returns list of (name, text) tuples.
    """
    sources = {
        "K1": K1_PT,
        "K2": K2_PT,
        "K3": K3_PT,
        "K1K2K3": K1_PT + K2_PT + K3_PT,
    }

    texts = []

    # 1. Identity
    for name, src in sources.items():
        texts.append((f"{name}_identity", src))

    # 2. Reversed
    for name, src in sources.items():
        texts.append((f"{name}_reversed", src[::-1]))

    # 3. All 6 concatenation orders
    sections = [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]
    from itertools import permutations as iterperms
    for perm in iterperms(sections):
        order_name = "".join(p[0] for p in perm)
        concat = "".join(p[1] for p in perm)
        if order_name != "K1K2K3":  # Already in identity
            texts.append((f"concat_{order_name}", concat))

    # 4. Decimation (every 2nd, 3rd, 5th, 7th, 13th)
    for name, src in sources.items():
        for step in [2, 3, 5, 7, 13]:
            texts.append((f"{name}_decimate_{step}", decimation(src, step)))

    # 5. Rail fence (2-5 rails)
    for name, src in sources.items():
        for rails in [2, 3, 4, 5]:
            texts.append((f"{name}_railfence_{rails}", rail_fence_read(src, rails)))

    # 6. Interleaving (3 orders)
    for order in [(K1_PT, K2_PT, K3_PT), (K1_PT, K3_PT, K2_PT), (K2_PT, K1_PT, K3_PT)]:
        order_names = []
        for t in order:
            if t is K1_PT: order_names.append("K1")
            elif t is K2_PT: order_names.append("K2")
            else: order_names.append("K3")
        texts.append((f"interleave_{'_'.join(order_names)}", interleave(list(order))))

    # 7. Columnar transposition (widths x keyword orderings)
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "BERLINCLOCK"]
    widths = [7, 8, 9, 10, 14, 24, 31]
    for name, src in sources.items():
        for w in widths:
            # Ascending order
            asc_order = list(range(w))
            texts.append((f"{name}_col{w}_asc", columnar_read(src, w, asc_order)))
            # Keyword orders
            for kw in keywords:
                order = keyword_to_order(kw, w)
                if order is not None:
                    texts.append((f"{name}_col{w}_{kw}", columnar_read(src, w, order)))

    # 8. Cross-section encryption (6 ordered pairs x 2 variants)
    section_pairs = [
        ("K1", K1_PT, "K2", K2_PT), ("K1", K1_PT, "K3", K3_PT),
        ("K2", K2_PT, "K1", K1_PT), ("K2", K2_PT, "K3", K3_PT),
        ("K3", K3_PT, "K1", K1_PT), ("K3", K3_PT, "K2", K2_PT),
    ]
    for n1, t1, n2, t2 in section_pairs:
        for enc_var in ["beaufort", "vigenere"]:
            texts.append((f"xenc_{n1}by{n2}_{enc_var}", cross_encrypt(t1, t2, enc_var)))

    return texts
```

- [ ] **Step 3: Verify text generation produces expected count**

Run: `PYTHONPATH=src python3 -u scripts/campaigns/f_k123_running_key_exhaustive_v1.py --phase1-only`

(Add a `--phase1-only` flag that just generates and counts texts, then exits.)

Expected: ~60+ derived texts printed with names and lengths.

- [ ] **Step 4: Commit**

```bash
git add scripts/campaigns/f_k123_running_key_exhaustive_v1.py
git commit -m "feat: add Phase 1 text generation (60+ K1-K3 transformations)"
```

---

### Task 3: Phase 2 — Core Search + W=7 Exhaustive

**Files:**
- Modify: `scripts/campaigns/f_k123_running_key_exhaustive_v1.py`

Add the main search loop, parallel dispatch, and W=7 exhaustive permutation search.

- [ ] **Step 1: Add search worker function**

```python
def search_worker(args):
    """Worker for parallel crib-drag search.

    args: (text_name, text_alpha, variant, alphabet, model, ct_text, crib_dict, window_len)
    Returns: list of (text_name, variant, alphabet_name, model, offset, matches, bean_eq)
    """
    text_name, text_alpha, variant, alphabet, model, ct_text, crib_dict, window_len = args
    alph_name = "AZ" if alphabet == AZ else "KA"
    required = derive_required_key(ct_text, crib_dict, variant, alphabet)
    hits = crib_drag(text_alpha, required, window_len)

    results = []
    for offset, matches in hits:
        bean = check_bean_eq(text_alpha, offset, ct_text, variant, alphabet) if matches >= 10 else None
        results.append({
            "text": text_name,
            "variant": variant,
            "alphabet": alph_name,
            "model": model,
            "offset": offset,
            "matches": matches,
            "bean_eq": bean,
        })
    return results


def search_w7_worker(args):
    """Worker for W=7 exhaustive permutation search.

    args: (perm_tuple, source_name, source_text, variant, alphabet, model, ct_text, crib_dict, window_len)
    """
    perm_tuple, source_name, source_text, variant, alphabet, model, ct_text, crib_dict, window_len = args
    alph_name = "AZ" if alphabet == AZ else "KA"
    col_order = list(perm_tuple)
    transformed = columnar_read(source_text, 7, col_order)
    required = derive_required_key(ct_text, crib_dict, variant, alphabet)
    hits = crib_drag(transformed, required, window_len)

    results = []
    for offset, matches in hits:
        bean = check_bean_eq(transformed, offset, ct_text, variant, alphabet) if matches >= 10 else None
        results.append({
            "text": f"{source_name}_col7_perm{''.join(str(x) for x in col_order)}",
            "variant": variant,
            "alphabet": alph_name,
            "model": model,
            "offset": offset,
            "matches": matches,
            "bean_eq": bean,
        })
    return results
```

- [ ] **Step 2: Add run_phase2 function**

```python
def run_phase2(derived_texts):
    """Run Phase 2: crib-drag all derived texts under all variants/models."""
    variants = ["beaufort", "vigenere", "var_beaufort"]
    alphabets = [(AZ, "AZ"), (KA, "KA")]
    models = [
        ("B", CT, CRIB_DICT, CT_LEN),
        ("A", CT73, CT73_CRIB_DICT, len(CT73)),
    ]

    # Build work items for non-transposed texts
    work_items = []
    for text_name, text_alpha in derived_texts:
        for variant in variants:
            for alphabet, alph_name in alphabets:
                for model_name, ct_text, crib_dict, window_len in models:
                    work_items.append((
                        text_name, text_alpha, variant, alphabet,
                        model_name, ct_text, crib_dict, window_len
                    ))

    print(f"Phase 2a: {len(work_items)} non-transposed configs", flush=True)

    all_results = []
    with Pool(min(cpu_count(), 28)) as pool:
        for batch_results in pool.imap_unordered(search_worker, work_items, chunksize=50):
            all_results.extend(batch_results)

    # W=7 exhaustive: all 5040 permutations x 4 source texts x 6 variants x 2 models
    sources = {"K1": K1_PT, "K2": K2_PT, "K3": K3_PT, "K1K2K3": K1_PT + K2_PT + K3_PT}
    w7_items = []
    for perm in permutations(range(7)):
        for src_name, src_text in sources.items():
            for variant in variants:
                for alphabet, alph_name in alphabets:
                    for model_name, ct_text, crib_dict, window_len in models:
                        w7_items.append((
                            perm, src_name, src_text, variant, alphabet,
                            model_name, ct_text, crib_dict, window_len
                        ))

    print(f"Phase 2b: {len(w7_items)} W=7 exhaustive configs", flush=True)

    with Pool(min(cpu_count(), 28)) as pool:
        for batch_results in pool.imap_unordered(search_w7_worker, w7_items, chunksize=500):
            all_results.extend(batch_results)

    return all_results
```

- [ ] **Step 3: Add Phase 2b extended transposition search**

```python
def run_phase2b():
    """Phase 2b: extended transpositions on K1K2K3 combined."""
    combined = K1_PT + K2_PT + K3_PT
    variants = ["beaufort", "vigenere", "var_beaufort"]
    alphabets = [(AZ, "AZ"), (KA, "KA")]
    models = [
        ("B", CT, CRIB_DICT, CT_LEN),
        ("A", CT73, CT73_CRIB_DICT, len(CT73)),
    ]
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "BERLINCLOCK"]

    work_items = []

    # All widths 2-31 for combined text
    for w in range(2, 32):
        asc_order = list(range(w))
        transformed = columnar_read(combined, w, asc_order)
        for variant in variants:
            for alphabet, _ in alphabets:
                for model_name, ct_text, crib_dict, window_len in models:
                    work_items.append((
                        f"K1K2K3_col{w}_asc", transformed, variant, alphabet,
                        model_name, ct_text, crib_dict, window_len
                    ))
        for kw in keywords:
            order = keyword_to_order(kw, w)
            if order:
                transformed = columnar_read(combined, w, order)
                for variant in variants:
                    for alphabet, _ in alphabets:
                        for model_name, ct_text, crib_dict, window_len in models:
                            work_items.append((
                                f"K1K2K3_col{w}_{kw}", transformed, variant, alphabet,
                                model_name, ct_text, crib_dict, window_len
                            ))

    # Double transposition: width-W then width-V
    for w1 in [7, 8, 9, 10, 14]:
        for w2 in [7, 8, 9, 10, 14]:
            if w1 == w2:
                continue
            t1 = columnar_read(combined, w1, list(range(w1)))
            t2 = columnar_read(t1, w2, list(range(w2)))
            for variant in variants:
                for alphabet, _ in alphabets:
                    for model_name, ct_text, crib_dict, window_len in models:
                        work_items.append((
                            f"K1K2K3_dbl_col{w1}_col{w2}", t2, variant, alphabet,
                            model_name, ct_text, crib_dict, window_len
                        ))

    # Boustrophedon reading of K1K2K3 on 28x31 grid
    grid_width = 31
    rows = math.ceil(len(combined) / grid_width)
    boustro = []
    for r in range(rows):
        row_start = r * grid_width
        row_end = min(row_start + grid_width, len(combined))
        row_text = combined[row_start:row_end]
        if r % 2 == 1:
            row_text = row_text[::-1]
        boustro.append(row_text)
    boustro_text = "".join(boustro)
    for variant in variants:
        for alphabet, _ in alphabets:
            for model_name, ct_text, crib_dict, window_len in models:
                work_items.append((
                    "K1K2K3_boustrophedon_31", boustro_text, variant, alphabet,
                    model_name, ct_text, crib_dict, window_len
                ))

    # Column-first reading of K1K2K3 on 28x31 grid
    col_first = []
    padded = combined + "A" * (rows * grid_width - len(combined))
    for c in range(grid_width):
        for r in range(rows):
            idx = r * grid_width + c
            if idx < len(combined):
                col_first.append(padded[idx])
    col_first_text = "".join(col_first)
    for variant in variants:
        for alphabet, _ in alphabets:
            for model_name, ct_text, crib_dict, window_len in models:
                work_items.append((
                    "K1K2K3_colfirst_31", col_first_text, variant, alphabet,
                    model_name, ct_text, crib_dict, window_len
                ))

    print(f"Phase 2b: {len(work_items)} extended transposition configs", flush=True)

    all_results = []
    with Pool(min(cpu_count(), 28)) as pool:
        for batch_results in pool.imap_unordered(search_worker, work_items, chunksize=50):
            all_results.extend(batch_results)

    return all_results
```

- [ ] **Step 4: Commit**

```bash
git add scripts/campaigns/f_k123_running_key_exhaustive_v1.py
git commit -m "feat: add Phase 2 search + W=7 exhaustive + extended transpositions"
```

---

### Task 4: Phase 3 — Signal Classification and Main Entry Point

**Files:**
- Modify: `scripts/campaigns/f_k123_running_key_exhaustive_v1.py`

Add signal classification, JSON output, and the `main()` function that ties everything together.

- [ ] **Step 1: Add classify_and_report function**

```python
def classify_and_report(all_results, elapsed):
    """Classify results and write output."""
    os.makedirs(RESULT_DIR, exist_ok=True)

    # Sort by match count descending
    all_results.sort(key=lambda x: x["matches"], reverse=True)

    # Classify
    signals = [r for r in all_results if r["matches"] >= 18]
    interesting = [r for r in all_results if 12 <= r["matches"] < 18]
    noise_best = all_results[0] if all_results else None

    summary = {
        "experiment": "K1-K3 Running Key Exhaustive Transformation Search",
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_configs": len(all_results),
        "elapsed_seconds": round(elapsed, 1),
        "best_score": noise_best["matches"] if noise_best else 0,
        "best_detail": noise_best if noise_best else None,
        "signal_count": len(signals),
        "interesting_count": len(interesting),
        "signals": signals,
        "interesting": interesting,
        "top_20": all_results[:20],
        "classification": (
            "BREAKTHROUGH" if any(r["matches"] >= 24 and r.get("bean_eq") for r in signals)
            else "SIGNAL" if signals
            else "INTERESTING" if interesting
            else "NOISE"
        ),
    }

    out_path = os.path.join(RESULT_DIR, "summary.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

    return summary
```

- [ ] **Step 2: Add main function**

```python
def main():
    t0 = time.monotonic()

    print("=" * 70, flush=True)
    print("  K1-K3 RUNNING KEY EXHAUSTIVE TRANSFORMATION SEARCH", flush=True)
    print("=" * 70, flush=True)
    print(f"  CT97: {CT}", flush=True)
    print(f"  CT73: {CT73} (len={len(CT73)})", flush=True)
    print(f"  Cribs: {len(CRIB_DICT)} positions (Model B), {len(CT73_CRIB_DICT)} positions (Model A)", flush=True)
    print(f"  CPUs: {cpu_count()}", flush=True)
    print(flush=True)

    # Phase 1: Generate derived texts
    print("Phase 1: Generating derived texts...", flush=True)
    derived_texts = generate_derived_texts()
    print(f"  Generated {len(derived_texts)} texts", flush=True)
    for name, text in derived_texts[:5]:
        print(f"    {name}: {len(text)} chars, preview: {text[:40]}...", flush=True)
    print(f"    ... and {len(derived_texts) - 5} more", flush=True)

    if "--phase1-only" in sys.argv:
        for name, text in derived_texts:
            print(f"  {name}: {len(text)} chars", flush=True)
        print(f"\nTotal: {len(derived_texts)} derived texts", flush=True)
        return

    # Phase 2: Core search
    print("\nPhase 2: Core search (non-transposed + W=7 exhaustive)...", flush=True)
    results_p2 = run_phase2(derived_texts)
    print(f"  Phase 2 hits (>=8): {len(results_p2)}", flush=True)
    if results_p2:
        best = max(results_p2, key=lambda x: x["matches"])
        print(f"  Phase 2 best: {best['matches']}/24 ({best['text']}, {best['variant']}, {best['alphabet']}, model {best['model']})", flush=True)

    # Phase 2b: Extended transpositions
    print("\nPhase 2b: Extended transpositions...", flush=True)
    results_p2b = run_phase2b()
    print(f"  Phase 2b hits (>=8): {len(results_p2b)}", flush=True)
    if results_p2b:
        best = max(results_p2b, key=lambda x: x["matches"])
        print(f"  Phase 2b best: {best['matches']}/24 ({best['text']}, {best['variant']}, {best['alphabet']}, model {best['model']})", flush=True)

    # Phase 3: Classify
    all_results = results_p2 + results_p2b
    elapsed = time.monotonic() - t0

    print(f"\nPhase 3: Classification ({len(all_results)} total hits)...", flush=True)
    summary = classify_and_report(all_results, elapsed)

    print(f"\n{'=' * 70}", flush=True)
    print(f"  RESULT: {summary['classification']}", flush=True)
    print(f"  Best score: {summary['best_score']}/24", flush=True)
    if summary['best_detail']:
        d = summary['best_detail']
        print(f"  Best: {d['text']} / {d['variant']} / {d['alphabet']} / model {d['model']} / offset {d['offset']}", flush=True)
    print(f"  Signals (>=18): {summary['signal_count']}", flush=True)
    print(f"  Interesting (>=12): {summary['interesting_count']}", flush=True)
    print(f"  Elapsed: {elapsed:.1f}s", flush=True)
    print(f"  Output: {RESULT_DIR}/summary.json", flush=True)
    print(f"{'=' * 70}", flush=True)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run the full Phase 1-3 search**

Run: `PYTHONPATH=src python3 -u scripts/campaigns/f_k123_running_key_exhaustive_v1.py`

Expected: Completes in <5 minutes. Best score likely <=9/24 (noise). Classification: NOISE or INTERESTING.

- [ ] **Step 4: Commit with results**

```bash
git add scripts/campaigns/f_k123_running_key_exhaustive_v1.py
git commit -m "feat: complete K1-K3 running key exhaustive search (Phases 1-3)"
```

---

### Task 5: Phase 4 — Gutenberg Scan Script (Background)

**Files:**
- Create: `scripts/campaigns/f_gutenberg_running_key_scan_v1.py`

Only run this if Phase 1-3 produces no signal >=12/24.

- [ ] **Step 1: Create Gutenberg download + scan script**

The script should:
1. Use `urllib.request` (stdlib) to download Gutenberg plain text files by ID
2. Cache downloads in `results/k123_running_key_exhaustive/phase4_gutenberg/downloads/`
3. For each downloaded text, run the same `crib_drag` function under all 6 variants and 2 models
4. Use `multiprocessing.Pool` for parallel scanning
5. Write results to `results/k123_running_key_exhaustive/phase4_gutenberg/scan_results.json`

Key design: include a curated list of ~500 Gutenberg IDs organized by category (Cold War, cryptography, Berlin, Egyptian archaeology, spy fiction, etc.). The list can be hardcoded — Gutenberg IDs are stable.

- [ ] **Step 2: Test with 5 Gutenberg texts to verify pipeline**

Run: `PYTHONPATH=src python3 -u scripts/campaigns/f_gutenberg_running_key_scan_v1.py --limit 5`

Expected: Downloads 5 texts, scans each, reports best scores (likely <=7/24).

- [ ] **Step 3: Launch full 500-text scan in background**

Run: `PYTHONPATH=src python3 -u scripts/campaigns/f_gutenberg_running_key_scan_v1.py > results/k123_running_key_exhaustive/phase4_gutenberg/scan.log 2>&1 &`

Expected: Runs 2-6 hours. Monitor with `tail -f results/k123_running_key_exhaustive/phase4_gutenberg/scan.log`.

- [ ] **Step 4: Commit**

```bash
git add scripts/campaigns/f_gutenberg_running_key_scan_v1.py
git commit -m "feat: add Phase 4 Gutenberg running-key scan (500 texts)"
```

---

### Task 6: Record Results in MEMORY.md

**Files:**
- Modify: `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/MEMORY.md`
- Modify: `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/elimination_ledger.md`

- [ ] **Step 1: After Phase 1-3 completes, add result to elimination ledger**

If result is NOISE (<=11/24):
- Add entry to elimination_ledger.md Section 9 (Key Derivation):
  `K1-K3 PT as running key through 60+ transformations (2026-03-17): ~750K configs, best X/24 = NOISE`

If result is SIGNAL (>=12/24):
- Add entry to MEMORY.md CONFIRMED REAL section with full details

- [ ] **Step 2: After Phase 4 completes (if run), add result to elimination ledger**

Add entry:
  `Running key from 500 Gutenberg texts (2026-03-17): ~1.2B evals, best X/24 = NOISE/SIGNAL`

- [ ] **Step 3: Update OPEN ATTACK SURFACE in MEMORY.md**

If both phases are noise: mark "Running key from untested sources" as PARTIALLY TESTED, note remaining gap (non-English texts, classified documents, non-Gutenberg sources).
