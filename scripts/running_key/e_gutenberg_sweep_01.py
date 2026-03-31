#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: ~40K texts x ~200K offsets x 3 variants x (Model A + Model B 3 layouts)
Last run:
Best score:

Operation Gutenberg Sweep — test every English-language Gutenberg text as a
running key for K4 under Model A (CT97) and Model B (CT73, stego-aware).

Phase 0: Download Gutenberg catalog + texts (parallel, cached)
Phase 1: Model A scan — CT97 x 3 cipher variants, all offsets
Phase 2: Model B scan — CT73 x 3 layouts (collapsed from 55 null masks) x 3 variants
Phase 3: Results aggregation + elimination artifact

Critical optimization: 55 null masks collapse to 3 distinct crib-scoring layouts
because no varying null falls within or between crib groups (21-33, 63-73).

Usage:
    PYTHONPATH=src python3 -u scripts/running_key/e_gutenberg_sweep_01.py
    PYTHONPATH=src python3 -u scripts/running_key/e_gutenberg_sweep_01.py --cached-only
    PYTHONPATH=src python3 -u scripts/running_key/e_gutenberg_sweep_01.py --model-a-only --limit 100
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
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
CHECKPOINT_PATH = RESULTS_DIR / "checkpoint.json"

# Scoring thresholds
# Model A: report >= 12 for statistical distribution analysis
# Model B: report >= 18 only (SIGNAL), enabling the G1>=7 pre-filter (99.7% pruning)
REPORT_THRESHOLD_A = 12
REPORT_THRESHOLD_B = 18    # Must be >= G1_MIN + 11 for correctness
SIGNAL_THRESHOLD = 18
BREAKTHROUGH = 24
G1_MIN_FOR_SIGNAL = 7      # Min Group 1 score to possibly reach 18/24 (18-11=7)

CT73_LEN = 73              # CT_LEN minus 24 nulls

# ── Pre-compute CT numerics ──────────────────────────────────────────
CT_NUM = tuple(ALPH_IDX[c] for c in CT)

# ── Crib groups (CT97 positions) ─────────────────────────────────────
GROUP_1_POS = list(range(21, 34))   # 13 positions: EASTNORTHEAST
GROUP_2_POS = list(range(63, 74))   # 11 positions: BERLINCLOCK

# ── Pre-compute expected text values per variant ─────────────────────
# For running key: text_num[offset + pos] must equal these values
# Vigenere:       key = (CT - PT) mod 26  (text IS the key)
# Beaufort:       key = (CT + PT) mod 26
# Var Beaufort:   key = (PT - CT) mod 26


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
    ("vigenere",         G1_VIG,   G2_VIG),
    ("beaufort",         G1_BEAU,  G2_BEAU),
    ("variant_beaufort", G1_VBEAU, G2_VBEAU),
]

# ── Model A: combined crib checks (CT97 positions) ──────────────────
MODEL_A_CHECKS = []
for _vname, g1_exp, g2_exp in VARIANTS:
    checks = list(zip(GROUP_1_POS, g1_exp)) + list(zip(GROUP_2_POS, g2_exp))
    MODEL_A_CHECKS.append((_vname, checks))

# ── Null mask layouts ────────────────────────────────────────────────
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
CORE_5 = {38, 39, 45, 87, 93}
REMAINING_11 = [40, 41, 42, 43, 44, 55, 56, 88, 94, 95, 96]


def _compute_layouts():
    """Compute the 3 distinct Group 2 CT73 position layouts.

    55 masks collapse to 3 layouts because varying nulls don't fall
    within or between crib groups. Only the count of varying nulls
    before position 63 matters (takes values 15, 16, or 17).

    Returns (g1_ct73, layouts) where:
      g1_ct73 = tuple of 13 CT73 positions for Group 1 (mask-invariant)
      layouts = list of dicts with g2_ct73, mask_count, nb63
    """
    layout_groups = {}
    for extra in combinations(REMAINING_11, 2):
        mask = CONSENSUS_NULLS | CORE_5 | set(extra)
        nb63 = sum(1 for n in mask if n < 63)
        layout_groups[nb63] = layout_groups.get(nb63, 0) + 1

    # Group 1: always 8 nulls before pos 21
    g1_ct73 = tuple(p - 8 for p in GROUP_1_POS)  # (13, 14, ..., 25)

    layouts = []
    for nb63, count in sorted(layout_groups.items()):
        g2_ct73 = tuple(p - nb63 for p in GROUP_2_POS)
        layouts.append({
            "g2_ct73": g2_ct73,
            "mask_count": count,
            "nb63": nb63,
        })

    return g1_ct73, layouts


G1_CT73, LAYOUTS = _compute_layouts()
# Verify: 3 layouts summing to 55
assert len(LAYOUTS) == 3
assert sum(l["mask_count"] for l in LAYOUTS) == 55


# ═════════════════════════════════════════════════════════════════════
# PHASE 0: CATALOG & TEXT ACQUISITION
# ═════════════════════════════════════════════════════════════════════

def download_catalog() -> List[Tuple[int, str]]:
    """Download Gutenberg catalog CSV, return (id, title) for English texts."""
    CATALOG_URL = "https://www.gutenberg.org/cache/epub/feeds/pg_catalog.csv"

    if CATALOG_PATH.exists():
        raw = CATALOG_PATH.read_text(encoding="utf-8", errors="replace")
    else:
        print(f"Downloading catalog from {CATALOG_URL}...")
        req = urllib.request.Request(CATALOG_URL,
                                     headers={"User-Agent": "KryptosResearch/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        CATALOG_PATH.write_text(raw, encoding="utf-8")
        print(f"Catalog saved: {len(raw):,} bytes")

    reader = csv.DictReader(io.StringIO(raw))
    english_texts = []
    for row in reader:
        lang = row.get("Language", "").strip().split(";")[0].strip().lower()
        if lang != "en":
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
                req = urllib.request.Request(
                    url, headers={"User-Agent": "KryptosResearch/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                break
            except (urllib.error.URLError, urllib.error.HTTPError,
                    OSError, TimeoutError):
                continue
        if raw is None:
            return None
        try:
            cache_path.write_text(raw, encoding="utf-8")
        except OSError:
            pass  # Cache write failure is non-fatal

    cleaned = re.sub(r'[^A-Za-z]', '', raw).upper()
    return cleaned if len(cleaned) >= CT73_LEN else None


def download_all(text_list: List[Tuple[int, str]]) -> List[Tuple[int, str, str]]:
    """Download all texts with parallel workers. Returns (id, title, alpha) triples."""
    cached = sum(1 for gid, _ in text_list
                 if (CACHE_DIR / f"pg{gid}.txt").exists())
    print(f"Catalog entries: {len(text_list):,}")
    print(f"Already cached: {cached:,}")
    print(f"Need to download: {len(text_list) - cached:,}")
    sys.stdout.flush()

    results = []
    failed = 0
    too_short = 0

    def _download_one(args):
        gid, title = args
        text = download_text(gid)
        return gid, title, text

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_download_one, item): item
                   for item in text_list}
        for i, future in enumerate(as_completed(futures)):
            try:
                gid, title, text = future.result()
            except Exception:
                failed += 1
                continue

            if text is None:
                failed += 1
            elif len(text) < CT73_LEN:
                too_short += 1
            else:
                results.append((gid, title, text))

            if (i + 1) % 2000 == 0:
                print(f"  Download: {i+1:,}/{len(text_list):,} "
                      f"(OK: {len(results):,}, fail: {failed}, short: {too_short})")
                sys.stdout.flush()

    print(f"Download complete: {len(results):,} usable, "
          f"{failed} failed, {too_short} too short")
    return results


# ═════════════════════════════════════════════════════════════════════
# PHASE 1: MODEL A SCAN (CT97)
# ═════════════════════════════════════════════════════════════════════

def scan_model_a(args: Tuple) -> Dict:
    """Scan one text as running key against CT97 (Model A).

    For each variant, check all offsets. Match: text_num[offset+pos] == expected.
    """
    text_id, title, text_alpha = args
    text_len = len(text_alpha)
    n_offsets = text_len - CT_LEN + 1

    if n_offsets <= 0:
        return {"text_id": text_id, "title": title, "text_len": text_len,
                "model": "A", "offsets_tested": 0, "best_score": 0,
                "best_variant": "", "best_offset": -1, "hits": []}

    text_num = bytearray(ALPH_IDX[c] for c in text_alpha)

    best_score = 0
    best_variant = ""
    best_offset = -1
    hits = []

    for variant_name, checks in MODEL_A_CHECKS:
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
                hits.append({
                    "score": score, "variant": variant_name,
                    "offset": offset, "title": title, "model": "A",
                })

            if score >= BREAKTHROUGH:
                print(f"\n!!! BREAKTHROUGH (A): {title} | "
                      f"{variant_name} | off={offset} | {score}/24 !!!")
                sys.stdout.flush()

    return {"text_id": text_id, "title": title, "text_len": text_len,
            "model": "A", "offsets_tested": n_offsets * 3,
            "best_score": best_score, "best_variant": best_variant,
            "best_offset": best_offset, "hits": hits}


# ═════════════════════════════════════════════════════════════════════
# PHASE 2: MODEL B SCAN (CT73, 3 LAYOUTS)
# ═════════════════════════════════════════════════════════════════════

def scan_model_b(args: Tuple) -> Dict:
    """Scan one text as running key against CT73 (Model B, 3 layouts).

    Split-crib optimization:
    1. Check Group 1 (13 cribs at CT73 pos 13-25) — same for all masks
    2. If G1 score >= 7: check Group 2 (11 cribs) at 3 layout offsets
    3. Best total = max(G1 + G2) across layouts

    REPORT_THRESHOLD_B = 18 ensures G1_MIN_FOR_SIGNAL = 7 is valid:
    even if all 11 G2 cribs match (max), G1 must be >= 7 to reach 18.
    """
    text_id, title, text_alpha = args
    text_len = len(text_alpha)
    n_offsets = text_len - CT73_LEN + 1

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
        # Group 1: (ct73_pos, expected_val) — mask-invariant
        g1_checks = list(zip(G1_CT73, g1_expected))

        # Group 2: per layout
        g2_per_layout = [list(zip(lay["g2_ct73"], g2_expected))
                         for lay in LAYOUTS]

        for offset in range(n_offsets):
            offsets_tested += 1

            # Phase 1: Group 1 (13 cribs)
            g1_score = 0
            for ct73_pos, expected in g1_checks:
                if text_num[offset + ct73_pos] == expected:
                    g1_score += 1

            # Track best G1 even below threshold
            if g1_score > best_score:
                best_score = g1_score
                best_variant = variant_name
                best_offset = offset
                best_layout = -1

            if g1_score < G1_MIN_FOR_SIGNAL:
                continue

            # Phase 2: Group 2 under each layout
            for layout_idx, g2_checks in enumerate(g2_per_layout):
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
                        "score": total, "g1": g1_score, "g2": g2_score,
                        "variant": variant_name, "offset": offset,
                        "layout": layout_idx, "title": title, "model": "B",
                    })

                if total >= BREAKTHROUGH:
                    print(f"\n!!! BREAKTHROUGH (B): {title} | "
                          f"{variant_name} | L{layout_idx} | "
                          f"off={offset} | {total}/24 !!!")
                    sys.stdout.flush()

    return {"text_id": text_id, "title": title, "text_len": text_len,
            "model": "B", "offsets_tested": offsets_tested,
            "best_score": best_score, "best_variant": best_variant,
            "best_offset": best_offset, "best_layout": best_layout,
            "hits": hits}


# ═════════════════════════════════════════════════════════════════════
# CHECKPOINT / RESUME
# ═════════════════════════════════════════════════════════════════════

def save_checkpoint(scanned_ids: set, phase: str):
    """Save progress — accumulates with prior checkpoint."""
    prior = load_checkpoint()
    merged = prior | scanned_ids
    data = {
        "scanned_ids": sorted(merged),
        "count": len(merged),
        "phase": phase,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    tmp = CHECKPOINT_PATH.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f)
    tmp.rename(CHECKPOINT_PATH)


def load_checkpoint() -> set:
    """Load set of already-scanned text IDs."""
    if not CHECKPOINT_PATH.exists():
        return set()
    try:
        with open(CHECKPOINT_PATH) as f:
            data = json.load(f)
        return set(data.get("scanned_ids", []))
    except (json.JSONDecodeError, OSError):
        return set()


# ═════════════════════════════════════════════════════════════════════
# PHASE 3: RESULTS
# ═════════════════════════════════════════════════════════════════════

def write_results(results_a, results_b, hits_a, hits_b, n_texts, total_alpha):
    """Write comprehensive results and elimination artifact."""
    total_offsets_a = sum(r["offsets_tested"] for r in results_a)
    total_offsets_b = sum(r["offsets_tested"] for r in results_b)

    results_a.sort(key=lambda r: r["best_score"], reverse=True)
    results_b.sort(key=lambda r: r["best_score"], reverse=True)
    hits_a.sort(key=lambda h: h["score"], reverse=True)
    hits_b.sort(key=lambda h: h["score"], reverse=True)

    dist_a = Counter(r["best_score"] for r in results_a)
    dist_b = Counter(r["best_score"] for r in results_b)

    best_a = results_a[0]["best_score"] if results_a else 0
    best_b = results_b[0]["best_score"] if results_b else 0

    summary = {
        "experiment": "e_gutenberg_sweep_01",
        "description": "Exhaustive running-key scan of all English Gutenberg texts",
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "texts_scanned": n_texts,
        "total_alpha_chars": total_alpha,
        "model_a": {
            "total_offsets": total_offsets_a,
            "best_score": best_a,
            "best_text": results_a[0]["title"] if results_a else "",
            "best_variant": results_a[0]["best_variant"] if results_a else "",
            "best_offset": results_a[0]["best_offset"] if results_a else -1,
            "hits_above_threshold": len(hits_a),
            "report_threshold": REPORT_THRESHOLD_A,
            "score_distribution": {str(k): v for k, v in sorted(dist_a.items())},
            "top_20": [{"score": r["best_score"], "title": r["title"],
                        "variant": r["best_variant"], "offset": r["best_offset"]}
                       for r in results_a[:20]],
        },
        "model_b": {
            "total_offsets": total_offsets_b,
            "layouts": len(LAYOUTS),
            "masks_represented": sum(l["mask_count"] for l in LAYOUTS),
            "best_score": best_b,
            "best_text": results_b[0]["title"] if results_b else "",
            "best_variant": results_b[0]["best_variant"] if results_b else "",
            "best_offset": results_b[0]["best_offset"] if results_b else -1,
            "hits_above_threshold": len(hits_b),
            "report_threshold": REPORT_THRESHOLD_B,
            "score_distribution": {str(k): v for k, v in sorted(dist_b.items())},
            "top_20": [{"score": r["best_score"], "title": r["title"],
                        "variant": r["best_variant"], "offset": r["best_offset"],
                        "layout": r.get("best_layout")}
                       for r in results_b[:20]],
        },
        "breakthroughs": [h for h in hits_a + hits_b if h["score"] >= BREAKTHROUGH],
        "signals": [h for h in hits_a + hits_b
                    if SIGNAL_THRESHOLD <= h["score"] < BREAKTHROUGH],
    }

    with open(RESULTS_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Elimination entry
    best_overall = max(best_a, best_b)
    elimination = {
        "id": "e_gutenberg_sweep_01",
        "family": "running_key",
        "cipher": "running key (Vigenere/Beaufort/Variant Beaufort)",
        "status": "eliminated" if best_overall < SIGNAL_THRESHOLD else "SIGNAL",
        "best_score": best_overall,
        "configs_tested": f"{total_offsets_a + total_offsets_b:,} offset-checks",
        "texts_tested": n_texts,
        "description": (
            f"All English Gutenberg texts (~{n_texts:,}) as running key. "
            f"Model A (CT97): {total_offsets_a:,} offsets, best {best_a}/24. "
            f"Model B (CT73, 3 stego layouts from 55 masks): "
            f"{total_offsets_b:,} offsets, best {best_b}/24. "
            f"3 cipher variants. Total alpha chars: {total_alpha:,}."
        ),
    }
    with open(RESULTS_DIR / "elimination_entry.json", "w") as f:
        json.dump(elimination, f, indent=2)

    # Console summary
    print("\n" + "=" * 80)
    print("RESULTS SUMMARY")
    print("=" * 80)
    print(f"Texts scanned: {n_texts:,}")
    print(f"Total alpha characters: {total_alpha:,}")
    print(f"Model A: {total_offsets_a:,} offsets | best {best_a}/24")
    print(f"Model B: {total_offsets_b:,} offsets | best {best_b}/24")

    print(f"\nModel A score distribution:")
    for score in sorted(dist_a.keys(), reverse=True)[:10]:
        print(f"  {score:2d}/24: {dist_a[score]:,} texts")

    print(f"\nModel A top 10:")
    for r in results_a[:10]:
        print(f"  {r['best_score']:2d}/24 | {r['best_variant']:18s} | "
              f"off={r['best_offset']:>8d} | {r['title'][:55]}")

    if results_b:
        print(f"\nModel B score distribution:")
        for score in sorted(dist_b.keys(), reverse=True)[:10]:
            print(f"  {score:2d}/24: {dist_b[score]:,} texts")

        print(f"\nModel B top 10:")
        for r in results_b[:10]:
            print(f"  {r['best_score']:2d}/24 | {r['best_variant']:18s} | "
                  f"L{r.get('best_layout', '-')} | {r['title'][:50]}")

    print(f"\nBreakthroughs: {len(summary['breakthroughs'])}")
    print(f"Signals (>={SIGNAL_THRESHOLD}): {len(summary['signals'])}")
    print(f"\nResults saved: {RESULTS_DIR}")

    return summary


# ═════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Operation Gutenberg Sweep — Running-Key Exhaustive Search")
    parser.add_argument("--cached-only", action="store_true",
                        help="Only scan already-cached texts (no downloads)")
    parser.add_argument("--model-a-only", action="store_true",
                        help="Skip Model B scan")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of texts (0 = all)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from checkpoint (skip already-scanned)")
    args = parser.parse_args()

    print("=" * 80)
    print("OPERATION GUTENBERG SWEEP")
    print("Running-Key Exhaustive Search for Kryptos K4")
    print("=" * 80)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN} | CT73 length: {CT73_LEN}")
    print(f"Cribs: {N_CRIBS} (Group 1: {len(GROUP_1_POS)}, Group 2: {len(GROUP_2_POS)})")
    print(f"Workers: {NUM_WORKERS}")
    print(f"Model A report threshold: {REPORT_THRESHOLD_A}/24")
    print(f"Model B report threshold: {REPORT_THRESHOLD_B}/24 (G1 min: {G1_MIN_FOR_SIGNAL})")
    print(f"Layouts: {len(LAYOUTS)} (collapsed from 55 masks)")
    for i, lay in enumerate(LAYOUTS):
        print(f"  Layout {i}: G2 CT73 start={lay['g2_ct73'][0]}, "
              f"masks={lay['mask_count']}, nulls_before_63={lay['nb63']}")
    print()
    sys.stdout.flush()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Phase 0: Acquire texts ───────────────────────────────────────
    print("PHASE 0: TEXT ACQUISITION")
    print("-" * 40)

    if args.cached_only:
        texts = []
        for f in sorted(CACHE_DIR.glob("pg*.txt")):
            try:
                gid = int(f.stem[2:])
            except ValueError:
                continue
            text = download_text(gid)
            if text and len(text) >= CT73_LEN:
                texts.append((gid, f"PG{gid}", text))
        print(f"Cached texts loaded: {len(texts)}")
    else:
        catalog = download_catalog()
        print(f"Catalog: {len(catalog):,} English texts")
        sys.stdout.flush()
        raw_texts = download_all(catalog)
        texts = [(gid, title, text) for gid, title, text in raw_texts]

    if args.limit > 0:
        texts = texts[:args.limit]
        print(f"Limited to {len(texts)} texts")

    if args.resume:
        already_done = load_checkpoint()
        before = len(texts)
        texts = [(gid, t, txt) for gid, t, txt in texts if gid not in already_done]
        print(f"Checkpoint: skipping {before - len(texts)} already-scanned texts")

    n_texts = len(texts)
    total_alpha = sum(len(t[2]) for t in texts)
    print(f"\nTexts to scan: {n_texts:,}")
    print(f"Total alpha characters: {total_alpha:,}")
    est_offsets_a = sum(max(0, len(t[2]) - CT_LEN + 1) for t in texts) * 3
    est_offsets_b = sum(max(0, len(t[2]) - CT73_LEN + 1) for t in texts)
    print(f"Estimated Model A offsets: {est_offsets_a:,}")
    print(f"Estimated Model B offsets: {est_offsets_b:,} (before G1 filter)")
    print()
    sys.stdout.flush()

    if n_texts == 0:
        print("No texts to scan. Exiting.")
        return

    # ── Phase 1: Model A ─────────────────────────────────────────────
    print("=" * 80)
    print("PHASE 1: MODEL A SCAN (CT97)")
    print("=" * 80)
    sys.stdout.flush()

    t0 = time.time()
    results_a = []
    all_hits_a = []
    scan_args = [(f"PG{gid}", title, text) for gid, title, text in texts]

    with Pool(processes=NUM_WORKERS) as pool:
        for i, result in enumerate(pool.imap_unordered(scan_model_a, scan_args)):
            results_a.append(result)
            if result["hits"]:
                all_hits_a.extend(result["hits"])
            if (i + 1) % 500 == 0 or (i + 1) == n_texts:
                elapsed = time.time() - t0
                cur_best = max(r["best_score"] for r in results_a)
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                eta = (n_texts - i - 1) / rate if rate > 0 else 0
                print(f"  A: {i+1:,}/{n_texts:,} | best={cur_best}/24 | "
                      f"{elapsed:.0f}s | ~{eta:.0f}s remaining")
                sys.stdout.flush()

    t_a = time.time() - t0
    best_a = max((r["best_score"] for r in results_a), default=0)
    offsets_a = sum(r["offsets_tested"] for r in results_a)
    print(f"\nModel A done: {n_texts:,} texts, {offsets_a:,} offsets, "
          f"{t_a:.1f}s, best={best_a}/24")
    print(f"Hits >= {REPORT_THRESHOLD_A}: {len(all_hits_a)}")
    sys.stdout.flush()

    # Checkpoint after Model A
    save_checkpoint({gid for gid, _, _ in texts}, "model_a_complete")

    # ── Phase 2: Model B ─────────────────────────────────────────────
    results_b = []
    all_hits_b = []

    if not args.model_a_only:
        print("\n" + "=" * 80)
        print("PHASE 2: MODEL B SCAN (CT73, 3 LAYOUTS)")
        print("=" * 80)
        sys.stdout.flush()

        t1 = time.time()

        with Pool(processes=NUM_WORKERS) as pool:
            for i, result in enumerate(pool.imap_unordered(scan_model_b, scan_args)):
                results_b.append(result)
                if result["hits"]:
                    all_hits_b.extend(result["hits"])
                if (i + 1) % 500 == 0 or (i + 1) == n_texts:
                    elapsed = time.time() - t1
                    cur_best = max(r["best_score"] for r in results_b)
                    rate = (i + 1) / elapsed if elapsed > 0 else 0
                    eta = (n_texts - i - 1) / rate if rate > 0 else 0
                    print(f"  B: {i+1:,}/{n_texts:,} | best={cur_best}/24 | "
                          f"{elapsed:.0f}s | ~{eta:.0f}s remaining")
                    sys.stdout.flush()

        t_b = time.time() - t1
        best_b = max((r["best_score"] for r in results_b), default=0)
        offsets_b = sum(r["offsets_tested"] for r in results_b)
        print(f"\nModel B done: {n_texts:,} texts, {offsets_b:,} offsets, "
              f"{t_b:.1f}s, best={best_b}/24")
        print(f"Hits >= {REPORT_THRESHOLD_B}: {len(all_hits_b)}")
        sys.stdout.flush()

        save_checkpoint({gid for gid, _, _ in texts}, "model_b_complete")

    # ── Phase 3: Results ─────────────────────────────────────────────
    write_results(results_a, results_b, all_hits_a, all_hits_b,
                  n_texts, total_alpha)

    total_time = time.time() - t0
    print(f"\nTotal elapsed: {total_time:.1f}s ({total_time/3600:.2f}h)")


if __name__ == "__main__":
    main()
