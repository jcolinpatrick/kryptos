# Operation Gutenberg Sweep — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Test every English-language text on Project Gutenberg (~40K books, ~10B alpha characters) as a running key for K4 under Model A (CT97) and Model B (CT73 with stego-aware null masks), formally eliminating "running key from any publicly available English text" as a possibility.

**Architecture:** Single script with four phases — catalog acquisition, Model A scan (CT97 × 3 variants), Model B scan (CT73 × 3 layouts × 3 variants, optimized from 55 masks), results aggregation. Uses `multiprocessing.Pool` with 28 workers. Checkpoint/resume via manifest file for crash resilience.

**Tech Stack:** Python 3.12 stdlib only (`urllib`, `multiprocessing`, `json`, `csv`, `itertools`). Imports from `kryptos.kernel.constants`. No venv packages needed.

**Critical optimization — 55 masks collapse to 3 layouts:** The 55 candidate null masks differ only in which 7 positions (from 16 candidates) are null. No varying null falls within or between crib groups (21–33 and 63–73). Only the *count* of varying nulls before position 63 matters for crib scoring, taking values 15, 16, or 17. This gives 3 distinct Group 2 position layouts (6, 28, and 21 masks respectively). Model B scan checks Group 1 (13 cribs, mask-invariant) once, then Group 2 (11 cribs) at only 3 offsets instead of 55.

---

## File Structure

| File | Purpose |
|------|---------|
| `scripts/running_key/e_gutenberg_sweep_01.py` | Main sweep script (all phases) |
| `tests/test_gutenberg_sweep.py` | Unit + integration tests |
| `results/e_gutenberg_sweep_01/` | Output directory (created at runtime) |

---

## Constants Reference

```python
# Consensus nulls (17 fixed positions)
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}

# Varying null positions — 7 chosen from 16 candidates
CORE_5 = {38, 39, 45, 87, 93}          # Always null (in all 55 masks)
REMAINING_11 = [40, 41, 42, 43, 44, 55, 56, 88, 94, 95, 96]  # Pick 2

# 55 masks = C(11, 2) combinations
# But for crib scoring: only 3 distinct layouts

# Crib groups (CT97 positions)
GROUP_1 = list(range(21, 34))   # EASTNORTHEAST, 13 positions
GROUP_2 = list(range(63, 74))   # BERLINCLOCK, 11 positions

# Nulls before Group 1 (always 8 consensus, 0 varying) → Group 1 CT73 positions: 13–25
# Nulls before Group 2 (12 consensus + 3–5 varying) → 3 layouts:
#   Layout A: 15 nulls before 63 → G2 CT73 start = 48 (6 masks)
#   Layout B: 16 nulls before 63 → G2 CT73 start = 47 (28 masks)
#   Layout C: 17 nulls before 63 → G2 CT73 start = 46 (21 masks)
```

---

## Task 1: Computational Kernel — Tests

**Files:**
- Create: `tests/test_gutenberg_sweep.py`

- [ ] **Step 1: Write mask generation and layout tests**

```python
"""Tests for e_gutenberg_sweep_01 computational kernel."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from kryptos.kernel.constants import CT, CRIB_DICT, ALPH_IDX, BEAN_EQ, BEAN_INEQ

# Import will work after Task 2 implements the module
# For now, define expected values for verification

CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
CORE_5 = {38, 39, 45, 87, 93}
REMAINING_11 = [40, 41, 42, 43, 44, 55, 56, 88, 94, 95, 96]


class TestMaskGeneration:
    def test_mask_count(self):
        from itertools import combinations
        masks = []
        for extra in combinations(REMAINING_11, 2):
            masks.append(sorted(CONSENSUS_NULLS | CORE_5 | set(extra)))
        assert len(masks) == 55

    def test_each_mask_has_24_positions(self):
        from itertools import combinations
        for extra in combinations(REMAINING_11, 2):
            mask = CONSENSUS_NULLS | CORE_5 | set(extra)
            assert len(mask) == 24

    def test_no_crib_in_any_mask(self):
        """No crib position should ever be a null."""
        from itertools import combinations
        crib_positions = set(CRIB_DICT.keys())
        for extra in combinations(REMAINING_11, 2):
            mask = CONSENSUS_NULLS | CORE_5 | set(extra)
            assert mask.isdisjoint(crib_positions)


class TestLayoutCollapse:
    """Verify that 55 masks collapse to 3 crib-scoring layouts."""

    def test_group1_invariant(self):
        """Group 1 CT73 positions must be identical across all 55 masks."""
        from itertools import combinations
        g1_positions_seen = set()
        for extra in combinations(REMAINING_11, 2):
            mask = sorted(CONSENSUS_NULLS | CORE_5 | set(extra))
            # Map CT97 pos 21-33 to CT73 positions
            nulls_before = [sum(1 for n in mask if n < p) for p in range(21, 34)]
            ct73_pos = tuple(p - nb for p, nb in zip(range(21, 34), nulls_before))
            g1_positions_seen.add(ct73_pos)
        assert len(g1_positions_seen) == 1, f"Expected 1 layout, got {len(g1_positions_seen)}"

    def test_group2_has_3_layouts(self):
        """Group 2 CT73 positions must have exactly 3 distinct layouts."""
        from itertools import combinations
        g2_layouts = set()
        for extra in combinations(REMAINING_11, 2):
            mask = sorted(CONSENSUS_NULLS | CORE_5 | set(extra))
            nulls_before = [sum(1 for n in mask if n < p) for p in range(63, 74)]
            ct73_pos = tuple(p - nb for p, nb in zip(range(63, 74), nulls_before))
            g2_layouts.add(ct73_pos)
        assert len(g2_layouts) == 3

    def test_layout_counts(self):
        """Verify the distribution: 6, 28, 21 masks per layout."""
        from itertools import combinations
        from collections import Counter
        layout_counter = Counter()
        for extra in combinations(REMAINING_11, 2):
            mask = sorted(CONSENSUS_NULLS | CORE_5 | set(extra))
            nulls_before_63 = sum(1 for n in mask if n < 63)
            layout_counter[nulls_before_63] += 1
        assert sorted(layout_counter.values()) == [6, 21, 28]


class TestExpectedKeyValues:
    """Verify pre-computed expected text values at crib positions."""

    def test_beaufort_keystream_matches_known(self):
        """Beaufort keystream at cribs must match JLJODEGKUKKKLOCGGBGOKTRU."""
        known = "JLJODEGKUKKKLOCGGBGOKTRU"
        ct_num = [ALPH_IDX[c] for c in CT]
        idx = 0
        for pos in sorted(CRIB_DICT.keys()):
            pt_num = ALPH_IDX[CRIB_DICT[pos]]
            beau_key = (ct_num[pos] + pt_num) % 26
            assert beau_key == ALPH_IDX[known[idx]], (
                f"pos {pos}: expected {known[idx]}={ALPH_IDX[known[idx]]}, got {beau_key}"
            )
            idx += 1

    def test_vigenere_key_at_pos21(self):
        ct_num = ALPH_IDX[CT[21]]  # F=5
        pt_num = ALPH_IDX['E']      # E=4
        assert (ct_num - pt_num) % 26 == 1  # B

    def test_beaufort_key_at_pos21(self):
        ct_num = ALPH_IDX[CT[21]]  # F=5
        pt_num = ALPH_IDX['E']      # E=4
        assert (ct_num + pt_num) % 26 == 9  # J


class TestScoring:
    """Verify crib scoring on crafted text."""

    def test_perfect_score_crafted_text(self):
        """A text crafted to match all 24 crib positions should score 24."""
        ct_num = [ALPH_IDX[c] for c in CT]
        # Build a 97-char text where text[pos] = beaufort_key at each position
        text_chars = [0] * 97
        for pos, ch in CRIB_DICT.items():
            pt_num = ALPH_IDX[ch]
            text_chars[pos] = (ct_num[pos] + pt_num) % 26  # Beaufort key
        # Score at offset=0
        score = 0
        for pos in sorted(CRIB_DICT.keys()):
            expected = (ct_num[pos] + ALPH_IDX[CRIB_DICT[pos]]) % 26
            if text_chars[pos] == expected:
                score += 1
        assert score == 24

    def test_random_text_low_score(self):
        """Random text should score near 0-1 on average."""
        import random
        random.seed(42)
        text_num = [random.randint(0, 25) for _ in range(200)]
        ct_num = [ALPH_IDX[c] for c in CT]
        scores = []
        for offset in range(200 - 97 + 1):
            score = 0
            for pos in sorted(CRIB_DICT.keys()):
                expected = (ct_num[pos] + ALPH_IDX[CRIB_DICT[pos]]) % 26
                if text_num[offset + pos] == expected:
                    score += 1
            scores.append(score)
        avg = sum(scores) / len(scores)
        assert avg < 3, f"Average score {avg} too high for random"
```

- [ ] **Step 2: Run tests to verify they fail** (kernel not yet implemented)

```bash
PYTHONPATH=src pytest tests/test_gutenberg_sweep.py -v
```

Expected: Most tests PASS (they use inline logic, not imports from the script). The `TestMaskGeneration`, `TestLayoutCollapse`, `TestExpectedKeyValues`, and `TestScoring` tests should all pass since they compute independently.

- [ ] **Step 3: Commit test file**

```bash
git add tests/test_gutenberg_sweep.py
git commit -m "test: add computational kernel tests for Gutenberg sweep"
```

---

## Task 2: Script Skeleton + Computational Kernel

**Files:**
- Create: `scripts/running_key/e_gutenberg_sweep_01.py`

- [ ] **Step 1: Write metadata header, imports, and all constants/precomputation**

```python
#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: ~40K texts × ~200K offsets × 3 variants × (Model A + Model B 3 layouts)
Last run:
Best score:
"""
"""
Operation Gutenberg Sweep — test every English-language Gutenberg text as a
running key for K4 under Model A (CT97) and Model B (CT73, stego-aware).

Usage:
    PYTHONPATH=src python3 -u scripts/running_key/e_gutenberg_sweep_01.py [--cached-only] [--model-a-only]
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from itertools import combinations
from multiprocessing import Pool
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ, N_CRIBS,
)

# ── Configuration ────────────────────────────────────────────────────
NUM_WORKERS = 28
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_ROOT / "results" / "e_gutenberg_sweep_01"
CACHE_DIR = Path("/data/tmp/gutenberg_cache")
CATALOG_PATH = CACHE_DIR / "pg_catalog.csv"
MANIFEST_PATH = RESULTS_DIR / "manifest.json"
CHECKPOINT_PATH = RESULTS_DIR / "checkpoint.json"

REPORT_THRESHOLD_A = 12   # Model A: report ≥12/24
REPORT_THRESHOLD_B = 12   # Model B: report ≥12/24
SIGNAL_THRESHOLD = 18
BREAKTHROUGH = 24
G1_MIN_FOR_SIGNAL = 7     # Minimum Group 1 score to possibly reach 18/24

# ── Pre-compute CT numerics ──────────────────────────────────────────
CT_NUM = tuple(ALPH_IDX[c] for c in CT)

# ── Crib groups (CT97 positions) ─────────────────────────────────────
GROUP_1_POS = list(range(21, 34))   # 13 positions: EASTNORTHEAST
GROUP_2_POS = list(range(63, 74))   # 11 positions: BERLINCLOCK

# ── Pre-compute expected text values per variant ─────────────────────
# For running key: text[offset + pos] must equal these values
# Vigenere: key = (CT - PT) % 26    (text IS the key)
# Beaufort: key = (CT + PT) % 26
# Var Beaufort: key = (PT - CT) % 26

def _compute_expected(positions):
    """Compute expected running-key text values at crib positions."""
    vig, beau, vbeau = [], [], []
    for pos in positions:
        ct = CT_NUM[pos]
        pt = ALPH_IDX[CRIB_DICT[pos]]
        vig.append((ct - pt) % MOD)
        beau.append((ct + pt) % MOD)
        vbeau.append((pt - ct) % MOD)
    return vig, beau, vbeau

G1_VIG, G1_BEAU, G1_VBEAU = _compute_expected(GROUP_1_POS)
G2_VIG, G2_BEAU, G2_VBEAU = _compute_expected(GROUP_2_POS)

VARIANTS = [
    ("vigenere", G1_VIG, G2_VIG),
    ("beaufort", G1_BEAU, G2_BEAU),
    ("variant_beaufort", G1_VBEAU, G2_VBEAU),
]

# ── Null mask layouts ────────────────────────────────────────────────
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
CORE_5 = {38, 39, 45, 87, 93}
REMAINING_11 = [40, 41, 42, 43, 44, 55, 56, 88, 94, 95, 96]

def _compute_layouts():
    """Compute the 3 distinct Group 2 CT73 position layouts.

    Returns list of (g2_ct73_positions, mask_count, bean_eq_ct73, bean_ineq_ct73).
    """
    from collections import Counter

    # Group all 55 masks by nulls-before-63 count
    layout_groups = {}  # nulls_before_63 -> count
    for extra in combinations(REMAINING_11, 2):
        mask = CONSENSUS_NULLS | CORE_5 | set(extra)
        nb63 = sum(1 for n in mask if n < 63)
        layout_groups[nb63] = layout_groups.get(nb63, 0) + 1

    # Group 1 CT73 positions (invariant): 8 nulls before pos 21
    g1_ct73 = tuple(p - 8 for p in GROUP_1_POS)  # (13, 14, ..., 25)

    layouts = []
    for nb63, count in sorted(layout_groups.items()):
        g2_ct73 = tuple(p - nb63 for p in GROUP_2_POS)

        # Bean EQ: CT97 positions (27, 65) → CT73 positions
        bean_eq_ct73 = (27 - 8, 65 - nb63)  # (19, 65-nb63)

        # Bean INEQ: all pairs involve crib positions only
        # Map each to CT73 space
        bean_ineq_ct73 = []
        for a, b in BEAN_INEQ:
            # Map a and b to CT73
            if a in range(21, 34):
                a_ct73 = a - 8
            elif a in range(63, 74):
                a_ct73 = a - nb63
            else:
                continue  # Non-crib position, skip
            if b in range(21, 34):
                b_ct73 = b - 8
            elif b in range(63, 74):
                b_ct73 = b - nb63
            else:
                continue
            bean_ineq_ct73.append((a_ct73, b_ct73))

        layouts.append({
            "g2_ct73": g2_ct73,
            "mask_count": count,
            "nb63": nb63,
            "bean_eq_ct73": bean_eq_ct73,
            "bean_ineq_ct73": bean_ineq_ct73,
        })

    return g1_ct73, layouts

G1_CT73, LAYOUTS = _compute_layouts()
# LAYOUTS has 3 entries with mask_count summing to 55
```

- [ ] **Step 2: Run tests to verify kernel computations**

```bash
PYTHONPATH=src pytest tests/test_gutenberg_sweep.py -v
```

Expected: All tests PASS.

- [ ] **Step 3: Commit skeleton**

```bash
git add scripts/running_key/e_gutenberg_sweep_01.py
git commit -m "feat: Gutenberg sweep script skeleton with computational kernel"
```

---

## Task 3: Catalog Download & Text Acquisition

**Files:**
- Modify: `scripts/running_key/e_gutenberg_sweep_01.py`

- [ ] **Step 1: Implement catalog download and parsing**

```python
def download_catalog() -> List[Tuple[int, str]]:
    """Download Gutenberg catalog CSV, return list of (id, title) for English texts."""
    CATALOG_URL = "https://www.gutenberg.org/cache/epub/feeds/pg_catalog.csv"

    if CATALOG_PATH.exists():
        raw = CATALOG_PATH.read_text(encoding="utf-8", errors="replace")
    else:
        print(f"Downloading catalog from {CATALOG_URL}...")
        req = urllib.request.Request(CATALOG_URL, headers={"User-Agent": "KryptosResearch/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        CATALOG_PATH.write_text(raw, encoding="utf-8")

    # Parse CSV: columns are Text#, Type, Issued, Title, Language, Authors, Subjects, LoCC, Bookshelves
    reader = csv.DictReader(io.StringIO(raw))
    english_texts = []
    for row in reader:
        lang = row.get("Language", "")
        if "en" not in lang.lower().split(";")[0]:
            continue
        text_type = row.get("Type", "")
        if "Text" not in text_type:
            continue
        try:
            gid = int(row["Text#"])
        except (ValueError, KeyError):
            continue
        title = row.get("Title", f"PG{gid}")[:120]
        english_texts.append((gid, title))

    return english_texts
```

- [ ] **Step 2: Implement single-text download with caching**

```python
def download_text(gid: int) -> Optional[str]:
    """Download a Gutenberg text, cache raw file. Returns uppercase A-Z only."""
    cache_path = CACHE_DIR / f"pg{gid}.txt"

    if cache_path.exists():
        raw = cache_path.read_text(encoding="utf-8", errors="replace")
    else:
        urls = [
            f"https://www.gutenberg.org/cache/epub/{gid}/pg{gid}.txt",
            f"https://www.gutenberg.org/files/{gid}/{gid}-0.txt",
            f"https://www.gutenberg.org/files/{gid}/{gid}.txt",
        ]
        raw = None
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "KryptosResearch/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                break
            except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
                continue
        if raw is None:
            return None
        try:
            cache_path.write_text(raw, encoding="utf-8")
        except OSError:
            pass  # Cache write failure is non-fatal

    cleaned = re.sub(r'[^A-Za-z]', '', raw).upper()
    return cleaned if len(cleaned) >= 73 else None  # Min length for Model B
```

- [ ] **Step 3: Implement parallel download with progress**

```python
def download_all(text_list: List[Tuple[int, str]]) -> List[Tuple[int, str, str]]:
    """Download all texts with parallel workers. Returns (id, title, alpha_text) triples."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Check cache first
    cached = 0
    to_download = []
    for gid, title in text_list:
        if (CACHE_DIR / f"pg{gid}.txt").exists():
            cached += 1
        to_download.append((gid, title))

    print(f"Texts in catalog: {len(text_list)}")
    print(f"Already cached: {cached}")
    print(f"Need to download: {len(text_list) - cached}")

    results = []
    failed = 0
    too_short = 0

    def _download_one(args):
        gid, title = args
        text = download_text(gid)
        return gid, title, text

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_download_one, (gid, title)): (gid, title)
                   for gid, title in to_download}
        for i, future in enumerate(as_completed(futures)):
            gid, title, text = future.result()
            if text is None:
                failed += 1
            elif len(text) < 73:
                too_short += 1
            else:
                results.append((gid, title, text))

            if (i + 1) % 1000 == 0:
                print(f"  Download progress: {i+1}/{len(to_download)} "
                      f"(OK: {len(results)}, fail: {failed}, short: {too_short})")
                sys.stdout.flush()

    print(f"Download complete: {len(results)} usable texts, "
          f"{failed} failed, {too_short} too short")
    return results
```

- [ ] **Step 4: Test catalog download manually**

```bash
PYTHONPATH=src python3 -c "
import sys; sys.path.insert(0, 'scripts/running_key')
# Quick test: download catalog, count English texts
from e_gutenberg_sweep_01 import download_catalog
texts = download_catalog()
print(f'English texts in catalog: {len(texts)}')
print(f'First 5: {texts[:5]}')
"
```

Expected: ~35,000–42,000 English texts.

- [ ] **Step 5: Commit**

```bash
git add scripts/running_key/e_gutenberg_sweep_01.py
git commit -m "feat: Gutenberg catalog download and text acquisition"
```

---

## Task 4: Model A Scanner

**Files:**
- Modify: `scripts/running_key/e_gutenberg_sweep_01.py`

- [ ] **Step 1: Implement Model A scan worker**

```python
def scan_model_a(args: Tuple) -> Dict:
    """Scan one text as running key against CT97 (Model A).

    For each variant, check all offsets. The running key text IS the key.
    Match condition: text_num[offset + pos] == expected_val[pos].
    """
    text_id, title, text_alpha = args
    text_len = len(text_alpha)
    n_offsets = text_len - CT_LEN + 1  # CT_LEN = 97

    if n_offsets <= 0:
        return {"text_id": text_id, "title": title, "text_len": text_len,
                "offsets_tested": 0, "best_score": 0, "best_variant": "",
                "best_offset": -1, "hits": []}

    text_num = bytearray(ALPH_IDX[c] for c in text_alpha)
    ct = CT_NUM

    # Pre-compute expected text values for all 24 crib positions per variant
    crib_checks = []
    for variant_name, g1_exp, g2_exp in VARIANTS:
        checks = []
        for i, pos in enumerate(GROUP_1_POS):
            checks.append((pos, g1_exp[i]))
        for i, pos in enumerate(GROUP_2_POS):
            checks.append((pos, g2_exp[i]))
        crib_checks.append((variant_name, checks))

    best_score = 0
    best_variant = ""
    best_offset = -1
    hits = []

    for variant_name, checks in crib_checks:
        for offset in range(n_offsets):
            score = 0
            for pos, expected in checks:
                if text_num[offset + pos] == expected:
                    score += 1

            if score > best_score:
                best_score = score
                best_variant = variant_name
                best_offset = offset

            if score >= REPORT_THRESHOLD_A:
                hit = _make_hit(text_num, offset, score, variant_name,
                                CT_LEN, ct, checks, title)
                hits.append(hit)

                if score >= BREAKTHROUGH:
                    print(f"\n!!! BREAKTHROUGH (Model A): {title} | "
                          f"{variant_name} | offset={offset} | score={score}/24 !!!")
                    sys.stdout.flush()

    return {"text_id": text_id, "title": title, "text_len": text_len,
            "model": "A", "offsets_tested": n_offsets * 3,
            "best_score": best_score, "best_variant": best_variant,
            "best_offset": best_offset, "hits": hits}


def _make_hit(text_num, offset, score, variant_name, ct_len, ct, checks, title):
    """Build a hit record (shared by Model A and B)."""
    # Derive plaintext snippet at crib positions
    pt_at_cribs = {}
    for pos, _ in checks:
        tv = text_num[offset + pos]
        if "vigenere" == variant_name:
            pt_val = (ct[pos] - tv) % 26
        elif "beaufort" == variant_name:
            pt_val = (tv - ct[pos]) % 26
        else:
            pt_val = (ct[pos] + tv) % 26
        pt_at_cribs[pos] = chr(pt_val + 65)

    return {"score": score, "variant": variant_name, "offset": offset, "title": title}
```

- [ ] **Step 2: Add integration test against cached King James Bible**

Add to `tests/test_gutenberg_sweep.py`:

```python
class TestModelAIntegration:
    """Integration test using cached Gutenberg text."""

    @pytest.mark.skipif(
        not Path("/data/tmp/gutenberg_cache/pg10.txt").exists(),
        reason="King James Bible not cached"
    )
    def test_kjb_best_score(self):
        """Prior scan showed KJB best = 8/24. Verify consistency."""
        # Load and strip text
        raw = Path("/data/tmp/gutenberg_cache/pg10.txt").read_text(errors="replace")
        alpha = re.sub(r'[^A-Za-z]', '', raw).upper()
        assert len(alpha) > CT_LEN

        # Import scanner
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "running_key"))
        from e_gutenberg_sweep_01 import scan_model_a
        result = scan_model_a(("PG10", "King James Bible", alpha))
        # Prior result: best = 8/24 (vigenere, offset=546245)
        assert result["best_score"] >= 7, "Score dropped below expected"
        assert result["best_score"] <= 12, "Unexpectedly high score"
```

- [ ] **Step 3: Run tests**

```bash
PYTHONPATH=src pytest tests/test_gutenberg_sweep.py -v -x
```

- [ ] **Step 4: Commit**

```bash
git add scripts/running_key/e_gutenberg_sweep_01.py tests/test_gutenberg_sweep.py
git commit -m "feat: Model A scanner for Gutenberg sweep"
```

---

## Task 5: Model B Scanner with Split-Crib Optimization

**Files:**
- Modify: `scripts/running_key/e_gutenberg_sweep_01.py`

- [ ] **Step 1: Implement Model B scan worker**

This is the core novel code. The optimization: check Group 1 (13 cribs, mask-invariant) first. Only if G1 score >= 7 do we check Group 2 under the 3 layouts.

```python
def scan_model_b(args: Tuple) -> Dict:
    """Scan one text as running key against CT73 (Model B, 3 layouts).

    Split-crib optimization:
    1. Check Group 1 (13 cribs at CT73 positions 13-25) — same for all masks
    2. If G1 score >= 7: check Group 2 (11 cribs) at 3 layout offsets
    3. Best total = max(G1 + G2) across layouts
    """
    text_id, title, text_alpha = args
    text_len = len(text_alpha)
    n_offsets = text_len - 73 + 1  # CT73 is 73 chars

    if n_offsets <= 0:
        return {"text_id": text_id, "title": title, "text_len": text_len,
                "model": "B", "offsets_tested": 0, "best_score": 0,
                "best_variant": "", "best_offset": -1, "best_layout": -1,
                "hits": []}

    text_num = bytearray(ALPH_IDX[c] for c in text_alpha)

    best_score = 0
    best_variant = ""
    best_offset = -1
    best_layout = -1
    hits = []
    offsets_tested = 0

    for variant_name, g1_expected, g2_expected in VARIANTS:
        # Group 1 checks: (ct73_pos, expected_val) — mask-invariant
        g1_checks = list(zip(G1_CT73, g1_expected))

        # Group 2 checks per layout: (ct73_pos, expected_val)
        g2_checks_per_layout = []
        for layout in LAYOUTS:
            g2_checks_per_layout.append(list(zip(layout["g2_ct73"], g2_expected)))

        for offset in range(n_offsets):
            offsets_tested += 1

            # Phase 1: Check Group 1 (13 cribs)
            g1_score = 0
            for ct73_pos, expected in g1_checks:
                if text_num[offset + ct73_pos] == expected:
                    g1_score += 1

            if g1_score < G1_MIN_FOR_SIGNAL:
                # Track best even below threshold
                if g1_score > best_score:
                    best_score = g1_score
                    best_variant = variant_name
                    best_offset = offset
                continue

            # Phase 2: Check Group 2 under each layout
            for layout_idx, g2_checks in enumerate(g2_checks_per_layout):
                g2_score = 0
                for ct73_pos, expected in g2_checks:
                    if offset + ct73_pos < text_len:
                        if text_num[offset + ct73_pos] == expected:
                            g2_score += 1

                total = g1_score + g2_score
                if total > best_score:
                    best_score = total
                    best_variant = variant_name
                    best_offset = offset
                    best_layout = layout_idx

                if total >= REPORT_THRESHOLD_B:
                    hits.append({
                        "score": total, "g1_score": g1_score,
                        "g2_score": g2_score, "variant": variant_name,
                        "offset": offset, "layout": layout_idx,
                        "title": title,
                    })

                    if total >= BREAKTHROUGH:
                        print(f"\n!!! BREAKTHROUGH (Model B): {title} | "
                              f"{variant_name} | layout={layout_idx} | "
                              f"offset={offset} | score={total}/24 !!!")
                        sys.stdout.flush()

    return {"text_id": text_id, "title": title, "text_len": text_len,
            "model": "B", "offsets_tested": offsets_tested,
            "best_score": best_score, "best_variant": best_variant,
            "best_offset": best_offset, "best_layout": best_layout,
            "hits": hits}
```

- [ ] **Step 2: Add test — split-crib matches naive approach**

Add to `tests/test_gutenberg_sweep.py`:

```python
class TestModelBCorrectness:
    """Verify split-crib optimization produces correct results."""

    def test_split_crib_matches_naive(self):
        """On a small text, verify optimized scan matches brute-force."""
        import random
        random.seed(123)
        text_num = bytearray(random.randint(0, 25) for _ in range(500))
        text_alpha = ''.join(chr(b + 65) for b in text_num)

        # Import scanner
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "running_key"))
        from e_gutenberg_sweep_01 import (
            scan_model_b, LAYOUTS, G1_CT73, VARIANTS
        )

        # Run optimized scanner
        result = scan_model_b(("test", "test", text_alpha))
        opt_best = result["best_score"]

        # Run naive: for each variant × layout × offset, check all 24 cribs
        naive_best = 0
        for variant_name, g1_exp, g2_exp in VARIANTS:
            for layout in LAYOUTS:
                checks = list(zip(G1_CT73, g1_exp)) + list(zip(layout["g2_ct73"], g2_exp))
                for offset in range(500 - 73 + 1):
                    score = sum(1 for pos, exp in checks
                                if offset + pos < 500 and text_num[offset + pos] == exp)
                    if score > naive_best:
                        naive_best = score

        assert opt_best == naive_best, f"Optimized {opt_best} != naive {naive_best}"
```

- [ ] **Step 3: Run tests**

```bash
PYTHONPATH=src pytest tests/test_gutenberg_sweep.py::TestModelBCorrectness -v
```

- [ ] **Step 4: Commit**

```bash
git add scripts/running_key/e_gutenberg_sweep_01.py tests/test_gutenberg_sweep.py
git commit -m "feat: Model B scanner with split-crib 3-layout optimization"
```

---

## Task 6: Main Orchestrator with Checkpoint/Resume

**Files:**
- Modify: `scripts/running_key/e_gutenberg_sweep_01.py`

- [ ] **Step 1: Implement checkpoint save/load**

```python
def save_checkpoint(scanned_ids: set, results_a: list, results_b: list):
    """Save progress to checkpoint file."""
    checkpoint = {
        "scanned_ids": sorted(scanned_ids),
        "results_a_count": len(results_a),
        "results_b_count": len(results_b),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    tmp = CHECKPOINT_PATH.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(checkpoint, f)
    tmp.rename(CHECKPOINT_PATH)


def load_checkpoint() -> set:
    """Load set of already-scanned text IDs from checkpoint."""
    if not CHECKPOINT_PATH.exists():
        return set()
    with open(CHECKPOINT_PATH) as f:
        data = json.load(f)
    return set(data.get("scanned_ids", []))
```

- [ ] **Step 2: Implement main orchestrator**

```python
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Gutenberg Running-Key Sweep")
    parser.add_argument("--cached-only", action="store_true",
                        help="Only scan already-cached texts (no downloads)")
    parser.add_argument("--model-a-only", action="store_true",
                        help="Skip Model B scan")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of texts to scan (0 = all)")
    args = parser.parse_args()

    print("=" * 80)
    print("OPERATION GUTENBERG SWEEP — Running-Key Exhaustive Search")
    print("=" * 80)
    print(f"CT: {CT}")
    print(f"Workers: {NUM_WORKERS}")
    print(f"Model A threshold: {REPORT_THRESHOLD_A}/24")
    print(f"Model B threshold: {REPORT_THRESHOLD_B}/24")
    print(f"Layouts: {len(LAYOUTS)} (collapsed from 55 masks)")
    for i, layout in enumerate(LAYOUTS):
        print(f"  Layout {i}: G2 start={layout['g2_ct73'][0]}, "
              f"masks={layout['mask_count']}, nb63={layout['nb63']}")
    print()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Phase 0: Acquire texts
    if args.cached_only:
        # Scan only cached files
        texts = []
        for f in sorted(CACHE_DIR.glob("pg*.txt")):
            gid = int(f.stem[2:])
            text = download_text(gid)
            if text and len(text) >= 73:
                texts.append((gid, f"PG{gid}", text))
        print(f"Cached texts loaded: {len(texts)}")
    else:
        catalog = download_catalog()
        print(f"Catalog: {len(catalog)} English texts")
        raw_texts = download_all(catalog)
        texts = [(gid, title, text) for gid, title, text in raw_texts]
        print(f"Usable texts: {len(texts)}")

    if args.limit > 0:
        texts = texts[:args.limit]
        print(f"Limited to {len(texts)} texts")

    # Load checkpoint (skip already-scanned)
    already_done = load_checkpoint()
    texts = [(gid, title, text) for gid, title, text in texts
             if gid not in already_done]
    print(f"After checkpoint filter: {len(texts)} texts to scan")
    print()

    total_alpha = sum(len(t[2]) for t in texts)
    print(f"Total alpha characters: {total_alpha:,}")

    # Phase 1: Model A scan
    print("\n" + "=" * 80)
    print("PHASE 1: MODEL A SCAN (CT97)")
    print("=" * 80)
    sys.stdout.flush()

    t0 = time.time()
    results_a = []
    all_hits_a = []
    scan_args_a = [(f"PG{gid}", title, text) for gid, title, text in texts]

    with Pool(processes=NUM_WORKERS) as pool:
        for i, result in enumerate(pool.imap_unordered(scan_model_a, scan_args_a)):
            results_a.append(result)
            if result["hits"]:
                all_hits_a.extend(result["hits"])
            if (i + 1) % 500 == 0:
                elapsed = time.time() - t0
                print(f"  Model A: {i+1}/{len(texts)} texts | "
                      f"best so far: {max(r['best_score'] for r in results_a)}/24 | "
                      f"{elapsed:.0f}s")
                sys.stdout.flush()

    t_a = time.time() - t0
    best_a = max((r["best_score"] for r in results_a), default=0)
    print(f"Model A complete: {len(results_a)} texts, {t_a:.1f}s, best={best_a}/24")
    print(f"Model A hits >= {REPORT_THRESHOLD_A}: {len(all_hits_a)}")

    # Phase 2: Model B scan
    results_b = []
    all_hits_b = []

    if not args.model_a_only:
        print("\n" + "=" * 80)
        print("PHASE 2: MODEL B SCAN (CT73, 3 LAYOUTS)")
        print("=" * 80)
        sys.stdout.flush()

        t1 = time.time()
        scan_args_b = [(f"PG{gid}", title, text) for gid, title, text in texts]

        with Pool(processes=NUM_WORKERS) as pool:
            for i, result in enumerate(pool.imap_unordered(scan_model_b, scan_args_b)):
                results_b.append(result)
                if result["hits"]:
                    all_hits_b.extend(result["hits"])
                if (i + 1) % 500 == 0:
                    elapsed = time.time() - t1
                    print(f"  Model B: {i+1}/{len(texts)} texts | "
                          f"best so far: {max(r['best_score'] for r in results_b)}/24 | "
                          f"{elapsed:.0f}s")
                    sys.stdout.flush()

        t_b = time.time() - t1
        best_b = max((r["best_score"] for r in results_b), default=0)
        print(f"Model B complete: {len(results_b)} texts, {t_b:.1f}s, best={best_b}/24")
        print(f"Model B hits >= {REPORT_THRESHOLD_B}: {len(all_hits_b)}")

    # Save checkpoint
    scanned_ids = {gid for gid, _, _ in texts}
    save_checkpoint(scanned_ids, results_a, results_b)

    # Phase 3: Results
    write_results(results_a, results_b, all_hits_a, all_hits_b, texts, args)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Test with `--cached-only --limit 5`**

```bash
PYTHONPATH=src python3 -u scripts/running_key/e_gutenberg_sweep_01.py --cached-only --limit 5
```

Expected: Scans 5 cached texts quickly, reports scores, no crashes.

- [ ] **Step 4: Commit**

```bash
git add scripts/running_key/e_gutenberg_sweep_01.py
git commit -m "feat: main orchestrator with checkpoint/resume for Gutenberg sweep"
```

---

## Task 7: Results Aggregation & Elimination Artifact

**Files:**
- Modify: `scripts/running_key/e_gutenberg_sweep_01.py`

- [ ] **Step 1: Implement results writer**

```python
def write_results(results_a, results_b, hits_a, hits_b, texts, args):
    """Write comprehensive results and elimination artifact."""
    total_offsets_a = sum(r["offsets_tested"] for r in results_a)
    total_offsets_b = sum(r["offsets_tested"] for r in results_b)

    # Sort by best score descending
    results_a.sort(key=lambda r: r["best_score"], reverse=True)
    results_b.sort(key=lambda r: r["best_score"], reverse=True)
    hits_a.sort(key=lambda h: h["score"], reverse=True)
    hits_b.sort(key=lambda h: h["score"], reverse=True)

    # Score distributions
    from collections import Counter
    dist_a = Counter(r["best_score"] for r in results_a)
    dist_b = Counter(r["best_score"] for r in results_b)

    summary = {
        "experiment": "e_gutenberg_sweep_01",
        "description": "Exhaustive running-key scan of all English Gutenberg texts",
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "texts_scanned": len(results_a),
        "total_alpha_chars": sum(len(t[2]) for t in texts),
        "model_a": {
            "total_offsets": total_offsets_a,
            "best_score": results_a[0]["best_score"] if results_a else 0,
            "best_text": results_a[0]["title"] if results_a else "",
            "best_variant": results_a[0]["best_variant"] if results_a else "",
            "hits_above_threshold": len(hits_a),
            "score_distribution": dict(sorted(dist_a.items())),
            "top_20": [{"score": r["best_score"], "title": r["title"],
                        "variant": r["best_variant"], "offset": r["best_offset"]}
                       for r in results_a[:20]],
        },
        "model_b": {
            "total_offsets": total_offsets_b,
            "layouts": len(LAYOUTS),
            "masks_represented": sum(l["mask_count"] for l in LAYOUTS),
            "best_score": results_b[0]["best_score"] if results_b else 0,
            "best_text": results_b[0]["title"] if results_b else "",
            "best_variant": results_b[0]["best_variant"] if results_b else "",
            "hits_above_threshold": len(hits_b),
            "score_distribution": dict(sorted(dist_b.items())),
            "top_20": [{"score": r["best_score"], "title": r["title"],
                        "variant": r["best_variant"], "offset": r["best_offset"],
                        "layout": r.get("best_layout")}
                       for r in results_b[:20]],
        },
        "breakthroughs": [h for h in hits_a + hits_b if h["score"] >= BREAKTHROUGH],
        "signals": [h for h in hits_a + hits_b if SIGNAL_THRESHOLD <= h["score"] < BREAKTHROUGH],
    }

    # Write JSON results
    with open(RESULTS_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Write elimination entry
    best_overall = max(
        summary["model_a"]["best_score"],
        summary["model_b"]["best_score"],
    )
    elimination = {
        "id": "e_gutenberg_sweep_01",
        "family": "running_key",
        "cipher": "running key (Vig/Beau/VBeau)",
        "status": "eliminated" if best_overall < SIGNAL_THRESHOLD else "SIGNAL",
        "best_score": best_overall,
        "configs_tested": f"{total_offsets_a + total_offsets_b:,} offset-checks",
        "texts_tested": len(results_a),
        "description": (
            f"All English Gutenberg texts (~{len(results_a):,}) as running key. "
            f"Model A (CT97): {total_offsets_a:,} offsets, best {summary['model_a']['best_score']}/24. "
            f"Model B (CT73, 3 stego layouts from 55 masks): {total_offsets_b:,} offsets, "
            f"best {summary['model_b']['best_score']}/24. "
            f"All 3 cipher variants tested."
        ),
    }
    with open(RESULTS_DIR / "elimination_entry.json", "w") as f:
        json.dump(elimination, f, indent=2)

    # Print summary
    print("\n" + "=" * 80)
    print("RESULTS SUMMARY")
    print("=" * 80)
    print(f"Texts scanned: {len(results_a):,}")
    print(f"Model A offsets: {total_offsets_a:,} | best: {summary['model_a']['best_score']}/24")
    print(f"Model B offsets: {total_offsets_b:,} | best: {summary['model_b']['best_score']}/24")
    print(f"\nModel A top 10:")
    for r in results_a[:10]:
        print(f"  {r['best_score']:2d}/24 | {r['best_variant']:18s} | {r['title'][:60]}")
    if results_b:
        print(f"\nModel B top 10:")
        for r in results_b[:10]:
            print(f"  {r['best_score']:2d}/24 | {r['best_variant']:18s} | L{r.get('best_layout','-')} | {r['title'][:55]}")

    print(f"\nBreakthroughs: {len(summary['breakthroughs'])}")
    print(f"Signals (≥18): {len(summary['signals'])}")
    print(f"\nResults: {RESULTS_DIR}")
```

- [ ] **Step 2: Test with `--cached-only`**

```bash
PYTHONPATH=src python3 -u scripts/running_key/e_gutenberg_sweep_01.py --cached-only
```

Expected: Scans ~101 cached texts, produces `results/e_gutenberg_sweep_01/summary.json`, best Model A ≈ 9/24.

- [ ] **Step 3: Commit**

```bash
git add scripts/running_key/e_gutenberg_sweep_01.py
git commit -m "feat: results aggregation and elimination artifact for Gutenberg sweep"
```

---

## Task 8: Integration Test — Verify Against Prior Results

**Files:**
- No new files

- [ ] **Step 1: Run full cached-only scan and compare**

```bash
PYTHONPATH=src python3 -u scripts/running_key/e_gutenberg_sweep_01.py --cached-only 2>&1 | tee /tmp/gutenberg_sweep_integration.log
```

**Verify:**
- Model A best score matches prior: 9/24 (PG27573, The Man in the Iron Mask, vigenere)
- Model B best score is ≤ 12/24 (no false signals)
- No breakthroughs or signals
- Runtime < 2 minutes for 101 texts
- Results files written correctly

- [ ] **Step 2: Verify results JSON**

```bash
python3 -c "
import json
with open('results/e_gutenberg_sweep_01/summary.json') as f:
    s = json.load(f)
print(f'Texts: {s[\"texts_scanned\"]}')
print(f'Model A best: {s[\"model_a\"][\"best_score\"]}/24 ({s[\"model_a\"][\"best_text\"]})')
print(f'Model B best: {s[\"model_b\"][\"best_score\"]}/24 ({s[\"model_b\"][\"best_text\"]})')
print(f'Breakthroughs: {len(s[\"breakthroughs\"])}')
print(f'Signals: {len(s[\"signals\"])}')
"
```

- [ ] **Step 3: Fix any discrepancies, commit if changes needed**

---

## Task 9: Full Sweep Launch

**Files:**
- No new files

- [ ] **Step 1: Launch full Gutenberg sweep**

```bash
PYTHONPATH=src python3 -u scripts/running_key/e_gutenberg_sweep_01.py 2>&1 | tee results/e_gutenberg_sweep_01/sweep.log &
```

**Expected timeline:**
- Phase 0 (download): ~20–40 minutes for ~40K texts
- Phase 1 (Model A): ~50 minutes on 28 cores
- Phase 2 (Model B): ~2–3 hours on 28 cores
- Total: ~4–5 hours

- [ ] **Step 2: Monitor progress**

```bash
tail -f results/e_gutenberg_sweep_01/sweep.log
```

- [ ] **Step 3: Collect results and update MEMORY.md**

After completion:
1. Read `results/e_gutenberg_sweep_01/summary.json`
2. Add entry to root `exhaustion_log.json`
3. Update `MEMORY.md` PROVEN IMPOSSIBLE section with new elimination
4. Commit all artifacts

---

## Risk Mitigation

- **Download failures:** Individual text failures are logged and skipped. Checkpoint/resume handles crashes.
- **Rate limiting:** 20 concurrent connections is well within Gutenberg's tolerance. If blocked, reduce to 5 and retry.
- **Memory:** Each worker processes one text at a time. Even a 10MB text (stripped to A-Z) fits easily in memory. No shared state between workers.
- **False positives at scale:** With ~42B Model A offsets, we expect ~5 hits at ≥12/24 by binomial chance. With ~100B effective Model B offsets, we expect ~15 at ≥12/24. These are noise — only ≥18 is signal. The report threshold of 12 captures these for statistical validation.
- **Correctness:** Split-crib optimization is verified against naive brute-force in `TestModelBCorrectness`. Integration test validates against prior 101-text scan results.
