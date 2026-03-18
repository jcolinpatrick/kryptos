#!/usr/bin/env python3 -u
"""
=================================================================
TKAS v2 — Transposition-Keystream Running Key Search
=================================================================
Cipher:     Two-system model (substitution + stego/transposition)
Family:     campaigns
Status:     active
Keyspace:   ~4.5M transpositions x 3 variants x ~300K text offsets
Last run:   never
Best score: --

HYPOTHESIS
----------
TKAS v1 eliminated periodic keys behind all standard transpositions.
This variant tests RUNNING KEYS: for each transposition S2, the 24
known keystream values get remapped to positions in {0..72}. If the
key is a running key from a source text, then:
  source_text[S2(crib_ct73_idx) + offset] == keystream_value
for all 24 cribs, at some offset.

For random English text, expected matches ~0.92/24 per offset.
A score of 8+ is highly unusual. A score of 12+ is a breakthrough.

TEXTS TESTED
------------
Phase A (full 4.2M transpositions): K1/K2/K3 PT, concatenated, reversed
Phase B (sampled transpositions): Carter texts, reference docs
=================================================================
"""

import sys
import os
import re
import json
import time
import itertools
import random
from collections import Counter
from multiprocessing import Pool, cpu_count

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_ENTRIES, N_CRIBS, CRIB_DICT,
)

# ── Constants (reused from TKAS v1) ───────────────────────────────────

CONSENSUS_NULLS = frozenset(
    {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
)
CRIB_POS_CT97 = sorted(CRIB_DICT.keys())

# Keystreams for 3 variants
def _build_ks(variant):
    keys = []
    for pos in CRIB_POS_CT97:
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[CRIB_DICT[pos]]
        if variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "variant_beaufort":
            k = (pt_val - ct_val) % MOD
        keys.append(k)
    return keys

KEYSTREAMS = {
    "beaufort": _build_ks("beaufort"),
    "vigenere": _build_ks("vigenere"),
    "variant_beaufort": _build_ks("variant_beaufort"),
}

# CT73 crib indices (mask-independent, proven in TKAS v1)
_REF_VARYING = [38, 39, 40, 55, 87, 93, 94]
_REF_NULLS = CONSENSUS_NULLS | set(_REF_VARYING)
_REF_NONNULL = sorted(set(range(CT_LEN)) - _REF_NULLS)
CRIB_CT73_IDX = [_REF_NONNULL.index(pos) for pos in CRIB_POS_CT97]

REPORT_THRESHOLD = 6
SIGNAL_THRESHOLD = 10

# ── K1-K3 Plaintexts ──────────────────────────────────────────────────

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETIC"
         "FIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUN"
         "KNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTT"
         "HERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMES"
         "SAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNOR"
         "THSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS")
K3_PT = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
         "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY"
         "BREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE"
         "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
         "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
         "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ")

# ── Text sanitization ─────────────────────────────────────────────────

def sanitize(text):
    """Strip to uppercase alpha only."""
    return re.sub(r"[^A-Z]", "", text.upper())

def text_to_arr(text):
    """Convert sanitized text to numpy int8 array (A=0, Z=25)."""
    if HAS_NUMPY:
        return np.array([ord(c) - 65 for c in text], dtype=np.int8)
    return [ord(c) - 65 for c in text]

# ── Source text loading ───────────────────────────────────────────────

def load_source_texts():
    """Load all available source texts for running key matching."""
    texts = {}

    # K1-K3 plaintexts and derived
    texts["K1_PT"] = K1_PT
    texts["K2_PT"] = K2_PT
    texts["K3_PT"] = K3_PT
    texts["K1K2K3"] = K1_PT + K2_PT + K3_PT
    texts["K3K2K1"] = K3_PT + K2_PT + K1_PT
    texts["K1_rev"] = K1_PT[::-1]
    texts["K2_rev"] = K2_PT[::-1]
    texts["K3_rev"] = K3_PT[::-1]
    texts["K1K2K3_rev"] = (K1_PT + K2_PT + K3_PT)[::-1]

    # CT itself as potential running key
    texts["CT97"] = CT
    texts["CT97_rev"] = CT[::-1]

    # Reference text files
    ref_dir = os.path.join(_ROOT, "reference")
    if os.path.isdir(ref_dir):
        for fname in sorted(os.listdir(ref_dir)):
            fpath = os.path.join(ref_dir, fname)
            if os.path.isfile(fpath) and fname.endswith((".txt", ".md")):
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        raw = f.read()
                    clean = sanitize(raw)
                    if len(clean) >= 73:
                        texts[f"ref:{fname}"] = clean
                except Exception:
                    pass

    # Thematic keywords repeated to length 200
    for kw in ["KRYPTOS", "PALIMPSEST", "DEFECTOR", "ABSCISSA", "BERLINCLOCK",
               "EASTNORTHEAST", "SEVEN", "KOMPASS", "HOROLOGE"]:
        rep = (kw * 30)[:200]
        texts[f"kw:{kw}"] = rep

    return texts

# ── Transposition generators (same as TKAS v1, streamlined) ──────────

def get_factor_pairs(n, min_dim=2):
    pairs = []
    for r in range(min_dim, n + 1):
        if n % r == 0 and n // r >= min_dim:
            pairs.append((r, n // r))
    return pairs

def double_rotation_perm(n, r1, c1, r2, c2):
    inter = [0] * n
    for i in range(n):
        row, col = divmod(i, c1)
        j = col * r1 + (r1 - 1 - row)
        if j < n:
            inter[j] = i
    perm = [0] * n
    for j in range(n):
        row, col = divmod(j, c2)
        k = col * r2 + (r2 - 1 - row)
        if k < n:
            perm[k] = inter[j]
    return perm

def single_rotation_perm(n, rows, cols):
    perm = [0] * n
    for i in range(n):
        row, col = divmod(i, cols)
        j = col * rows + (rows - 1 - row)
        if j < n:
            perm[j] = i
    return perm

def columnar_perm_fast(width, col_order, length):
    full_rows, remainder = divmod(length, width)
    rank_to_col = [0] * width
    for col_idx, rank in enumerate(col_order):
        rank_to_col[rank] = col_idx
    perm = []
    for rank in range(width):
        col_idx = rank_to_col[rank]
        col_len = full_rows + (1 if col_idx < remainder else 0)
        for r in range(col_len):
            perm.append(r * width + col_idx)
    return perm

# ── Scoring engine ────────────────────────────────────────────────────

def match_running_key_numpy(text_arr, positions, key_values):
    """Slide 24-position sparse pattern across text, return (best_score, best_offset).
    Uses numpy for speed."""
    max_pos = max(positions)
    n_offsets = len(text_arr) - max_pos
    if n_offsets <= 0:
        return 0, -1

    matches = np.zeros(n_offsets, dtype=np.int8)
    for p, kv in zip(positions, key_values):
        matches += (text_arr[p:p + n_offsets] == kv)

    best_idx = int(np.argmax(matches))
    return int(matches[best_idx]), best_idx


def match_running_key_python(text_ints, positions, key_values):
    """Pure Python fallback."""
    max_pos = max(positions)
    n_offsets = len(text_ints) - max_pos
    if n_offsets <= 0:
        return 0, -1

    best_score = 0
    best_offset = -1
    for offset in range(n_offsets):
        s = sum(1 for p, kv in zip(positions, key_values) if text_ints[p + offset] == kv)
        if s > best_score:
            best_score = s
            best_offset = offset
    return best_score, best_offset


match_running_key = match_running_key_numpy if HAS_NUMPY else match_running_key_python

# ── Worker for columnar batch ─────────────────────────────────────────

def _search_col_batch(args):
    """Worker: score a batch of columnar orderings against all texts."""
    width, orderings, n, text_data = args
    # text_data: list of (name, text_arr)
    hits = []

    for col_order in orderings:
        perm = columnar_perm_fast(width, col_order, n)
        if len(perm) != n:
            continue
        positions = [perm[idx] for idx in CRIB_CT73_IDX if idx < n]
        if len(positions) != 24:
            continue

        for variant, kv in KEYSTREAMS.items():
            kv_arr = kv  # list of 24 ints
            for text_name, text_arr in text_data:
                score, offset = match_running_key(text_arr, positions, kv_arr)
                if score >= REPORT_THRESHOLD:
                    hits.append({
                        "family": f"columnar_w{width}",
                        "col_order": list(col_order),
                        "variant": variant,
                        "text": text_name,
                        "offset": offset,
                        "score": score,
                    })
    return hits

# ── Phase runners ─────────────────────────────────────────────────────

def run_phase_rotation(texts_arr, n=72):
    """Test double + single rotation on 72-char against all texts."""
    results = []
    crib_idx = CRIB_CT73_IDX
    fps = get_factor_pairs(n)
    seen = set()
    count = 0

    # Double rotation
    for r1, c1 in fps:
        for r2, c2 in fps:
            perm = double_rotation_perm(n, r1, c1, r2, c2)
            pk = tuple(perm)
            if pk in seen:
                continue
            seen.add(pk)
            count += 1
            positions = [perm[idx] for idx in crib_idx if idx < n]
            if len(positions) != 24:
                continue
            for variant, kv in KEYSTREAMS.items():
                for text_name, text_arr in texts_arr:
                    score, offset = match_running_key(text_arr, positions, kv)
                    if score >= REPORT_THRESHOLD:
                        results.append({
                            "family": "double_rotation",
                            "desc": f"drot_n{n}",
                            "variant": variant,
                            "text": text_name,
                            "offset": offset,
                            "score": score,
                        })

    # Single rotation
    for r, c in fps:
        perm = single_rotation_perm(n, r, c)
        pk = tuple(perm)
        if pk in seen:
            continue
        seen.add(pk)
        count += 1
        positions = [perm[idx] for idx in crib_idx if idx < n]
        if len(positions) != 24:
            continue
        for variant, kv in KEYSTREAMS.items():
            for text_name, text_arr in texts_arr:
                score, offset = match_running_key(text_arr, positions, kv)
                if score >= REPORT_THRESHOLD:
                    results.append({
                        "family": "single_rotation",
                        "desc": f"srot_n{n}",
                        "variant": variant,
                        "text": text_name,
                        "offset": offset,
                        "score": score,
                    })

    print(f"  {count} rotation perms x {len(texts_arr)} texts x 3 variants")
    return results


def run_phase_identity(texts_arr, n=73):
    """Test identity transposition (Model B baseline) against all texts."""
    results = []
    perm = list(range(n))
    positions = [perm[idx] for idx in CRIB_CT73_IDX if idx < n]
    for variant, kv in KEYSTREAMS.items():
        for text_name, text_arr in texts_arr:
            score, offset = match_running_key(text_arr, positions, kv)
            if score >= REPORT_THRESHOLD:
                results.append({
                    "family": "identity",
                    "desc": "no_transposition",
                    "variant": variant,
                    "text": text_name,
                    "offset": offset,
                    "score": score,
                })
    print(f"  Identity (baseline) x {len(texts_arr)} texts x 3 variants")
    return results


def run_phase_columnar(texts_arr, n=73, exhaustive_max=10, sa_samples=10000,
                       n_workers=None):
    """Columnar transpositions w2-31 against all texts."""
    if n_workers is None:
        n_workers = min(cpu_count(), 28)
    results = []
    total_orderings = 0

    for w in range(2, min(32, n)):
        t0 = time.time()
        if w <= exhaustive_max:
            all_orderings = list(itertools.permutations(range(w)))
        else:
            seen_o = set()
            all_orderings = []
            for _ in range(sa_samples):
                o = list(range(w))
                random.shuffle(o)
                ot = tuple(o)
                if ot not in seen_o:
                    seen_o.add(ot)
                    all_orderings.append(ot)

        n_ord = len(all_orderings)
        total_orderings += n_ord

        batch_size = max(1, n_ord // (n_workers * 4))
        batches = []
        for i in range(0, n_ord, batch_size):
            batches.append((w, all_orderings[i:i + batch_size], n, texts_arr))

        if n_ord > 500 and n_workers > 1:
            with Pool(n_workers) as pool:
                for br in pool.map(_search_col_batch, batches):
                    results.extend(br)
        else:
            for batch in batches:
                results.extend(_search_col_batch(batch))

        elapsed = time.time() - t0
        n_hits = sum(1 for r in results if r["family"] == f"columnar_w{w}")
        print(f"  w={w}: {n_ord:,} orderings [{elapsed:.1f}s] hits={n_hits}")

    print(f"  Total columnar: {total_orderings:,}")
    return results


# ── Reporting ──────────────────────────────────────────────────────────

def report_results(all_results, output_path=None):
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)

    if not all_results:
        print(f"  NO configs scored >= {REPORT_THRESHOLD}")
        return

    # Sort by score descending
    all_results.sort(key=lambda x: -x["score"])

    max_score = all_results[0]["score"]
    print(f"\n  Total hits >= {REPORT_THRESHOLD}: {len(all_results)}")
    print(f"\n  {'Score':>5}  {'Variant':>16}  {'Family':>18}  {'Text':>20}  {'Offset':>7}")
    print(f"  {'─'*5}  {'─'*16}  {'─'*18}  {'─'*20}  {'─'*7}")
    for r in all_results[:50]:
        print(
            f"  {r['score']:>5}  {r['variant']:>16}  {r['family']:>18}  "
            f"{r['text']:>20}  {r.get('offset', ''):>7}"
        )

    # Baselines
    print(f"\n  Expected random baseline: ~0.92/24 per offset")
    print(f"  Report threshold: {REPORT_THRESHOLD}/24")
    print(f"  Signal threshold: {SIGNAL_THRESHOLD}/24")

    if max_score >= 12:
        print(f"\n  *** BREAKTHROUGH: {max_score}/24 running-key match found! ***")
    elif max_score >= SIGNAL_THRESHOLD:
        print(f"\n  *** STRONG SIGNAL: {max_score}/24 match found ***")
    elif max_score >= 8:
        print(f"\n  ** MODERATE SIGNAL: {max_score}/24 match **")
    else:
        print(f"\n  Best score: {max_score}/24 — consistent with noise")

    if output_path is None:
        output_path = os.path.join(_ROOT, "results", "f_tkas_running_key_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "experiment": "TKAS_running_key_v1",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "report_threshold": REPORT_THRESHOLD,
            "signal_threshold": SIGNAL_THRESHOLD,
            "n_hits": len(all_results),
            "max_score": max_score,
            "hits": all_results[:200],
        }, f, indent=2)
    print(f"\n  Results written to: {output_path}")


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    random.seed(20260318)

    print("=" * 70)
    print("TKAS v2 — Transposition-Keystream Running Key Search")
    print("=" * 70)
    print(f"Numpy: {'YES' if HAS_NUMPY else 'NO (will be slow)'}")
    print(f"Workers: {min(cpu_count(), 28)}")
    print(f"Beaufort keystream: {''.join(ALPH[k] for k in KEYSTREAMS['beaufort'])}")
    print(f"Report threshold: {REPORT_THRESHOLD}/24, Signal: {SIGNAL_THRESHOLD}/24")

    # Load source texts
    print(f"\n{'─'*70}")
    print("Loading source texts...")
    print(f"{'─'*70}")
    raw_texts = load_source_texts()
    print(f"  Loaded {len(raw_texts)} source texts:")
    total_chars = 0
    for name, text in sorted(raw_texts.items()):
        clean = sanitize(text)
        total_chars += len(clean)
        if len(clean) > 200:
            print(f"    {name}: {len(clean):,} chars")
    print(f"  Total: {total_chars:,} chars across {len(raw_texts)} texts")

    # Prepare text arrays
    short_texts = []  # for full transposition search
    long_texts = []   # for sampled transposition search
    for name, text in raw_texts.items():
        clean = sanitize(text)
        if len(clean) < 73:
            continue
        arr = text_to_arr(clean)
        if len(clean) <= 2000:
            short_texts.append((name, arr))
        else:
            long_texts.append((name, arr))
    all_texts = short_texts + long_texts

    print(f"  Short texts (<= 2000 chars): {len(short_texts)}")
    print(f"  Long texts (> 2000 chars): {len(long_texts)}")

    # Phase 0: Identity baseline
    print(f"\n{'─'*70}")
    print("Phase 0: Identity transposition (Model B baseline)")
    print(f"{'─'*70}")
    results_0 = run_phase_identity(all_texts, n=73)

    # Phase 1: K3 double + single rotation (72 chars, all texts)
    print(f"\n{'─'*70}")
    print("Phase 1: K3 double + single rotation (72 chars)")
    print(f"{'─'*70}")
    results_1 = run_phase_rotation(all_texts, n=72)

    # Phase 2: Columnar (SHORT texts only for exhaustive widths)
    print(f"\n{'─'*70}")
    print("Phase 2A: Columnar w2-10 exhaustive (short texts)")
    print(f"{'─'*70}")
    results_2a = run_phase_columnar(short_texts, n=73, exhaustive_max=10,
                                     sa_samples=10000)

    # Phase 2B: Columnar w2-8 exhaustive + w9-31 sampled (long texts)
    print(f"\n{'─'*70}")
    print("Phase 2B: Columnar w2-8 exhaustive + w9-31 sampled (long texts)")
    print(f"{'─'*70}")
    results_2b = run_phase_columnar(long_texts, n=73, exhaustive_max=8,
                                     sa_samples=5000)

    # Compile
    all_results = results_0 + results_1 + results_2a + results_2b
    report_results(all_results)

    elapsed = time.time() - t_start
    print(f"\n  Total elapsed: {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print("=" * 70)


if __name__ == "__main__":
    main()
