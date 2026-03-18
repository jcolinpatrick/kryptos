#!/usr/bin/env python3
"""
Cipher:   running_key
Family:   campaigns
Status:   active
Keyspace: ~750K configs
Last run:
Best score:

Exhaustive running-key crib-drag search using K1-K3 plaintext through ~60
transformations. Tests whether any transformed version of K1/K2/K3 plaintext
serves as the running key for K4 under Beaufort/Vigenere/VarBeaufort variants
on either the raw 97-char ciphertext or the 73-char null-extracted ciphertext.

Phase 1: Generate ~60+ derived texts from K1, K2, K3 and K1K2K3 combined
Phase 2: Crib-drag each derived text against the required key at crib positions
Phase 2b: Extended transpositions on K1K2K3 combined (widths 2-31, double-trans)
"""

import sys
import os
import json
import time
import math
import argparse
import multiprocessing
from itertools import permutations, product
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET, BEAN_EQ,
)

# ── Plaintext constants ──────────────────────────────────────────────────────

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
    "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEA"
    "TINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLE"
    "ALITTLEINSERTEDACANDLEANDPEEREDIN"
)
K1K2K3 = K1_PT + K2_PT + K3_PT

# ── Alphabet lookups ─────────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

ALPHABETS = {
    "AZ": (AZ, AZ_IDX),
    "KA": (KA, KA_IDX),
}

VARIANTS = ["beaufort", "vigenere", "varbeaufort"]

# ── Consensus null mask ───────────────────────────────────────────────────────

MASK_24 = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
MASK_SET = set(MASK_24)

CT73_POSITIONS = [i for i in range(CT_LEN) if i not in MASK_SET]
CT73 = ''.join(CT[i] for i in CT73_POSITIONS)

# Map CT97 crib positions → CT73 positions
_pos97_to_73 = {}
_idx = 0
for _p in range(CT_LEN):
    if _p not in MASK_SET:
        _pos97_to_73[_p] = _idx
        _idx += 1

CT73_CRIB_DICT = {}
for pos97, ch in CRIB_DICT.items():
    if pos97 in _pos97_to_73:
        CT73_CRIB_DICT[_pos97_to_73[pos97]] = ch

# ── Keyword list for columnar transpositions ──────────────────────────────────

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "BERLINCLOCK"]


# ── Core cipher utilities ─────────────────────────────────────────────────────

def derive_required_key(ct_text, crib_dict, variant, alph_str, alph_idx):
    """Compute the required key value at each crib position.
    Returns dict: position → required key integer (0-25).
    """
    required = {}
    for pos, pt_ch in crib_dict.items():
        if pos >= len(ct_text):
            continue
        ct_ch = ct_text[pos]
        if ct_ch not in alph_idx or pt_ch not in alph_idx:
            continue
        c = alph_idx[ct_ch]
        p = alph_idx[pt_ch]
        if variant == "vigenere":
            k = (c - p) % MOD
        elif variant == "beaufort":
            k = (c + p) % MOD
        else:  # varbeaufort
            k = (p - c) % MOD
        required[pos] = k
    return required


def crib_drag(text_alpha, required_key, ct_text, crib_dict, alph_idx):
    """Slide running-key text across the ciphertext and count matching key values.

    text_alpha: list of integer values (0-25) for the running-key text
    required_key: dict of pos → required key int
    ct_text: the ciphertext string being attacked
    Returns (best_score, best_offset, matches_at_best_offset)
    """
    n_ct = len(ct_text)
    n_key = len(text_alpha)
    if n_key < n_ct:
        max_offset = n_key - 1  # key shorter than CT — slide key
    else:
        max_offset = n_key - n_ct  # key longer than CT — slide CT

    best_score = 0
    best_offset = 0
    best_matches = []

    for offset in range(max(1, max_offset + 1) if max_offset >= 0 else 1):
        score = 0
        matches = []
        for pos, req_k in required_key.items():
            if n_key >= n_ct:
                # key is at least as long as CT — use key[pos+offset]
                key_idx = pos + offset
                if key_idx >= n_key:
                    continue
            else:
                # key is shorter than CT — use key[(pos - offset) % n_key] or sliding
                key_idx = pos - offset
                if key_idx < 0 or key_idx >= n_key:
                    continue
            if text_alpha[key_idx] == req_k:
                score += 1
                matches.append(pos)
        if score > best_score:
            best_score = score
            best_offset = offset
            best_matches = matches

    return best_score, best_offset, best_matches


def crib_drag_fast(key_ints, required_key, n_ct):
    """Fast crib-drag: slide key_ints over positions 0..n_ct-1.
    Returns best (score, offset).
    """
    n_key = len(key_ints)
    crib_positions = list(required_key.keys())
    crib_values = [required_key[p] for p in crib_positions]
    n_cribs = len(crib_positions)

    best_score = 0
    best_offset = 0

    if n_key >= n_ct:
        # slide key over CT: at offset d, key char at pos p is key_ints[p + d]
        max_d = n_key - n_ct
        for d in range(max_d + 1):
            score = 0
            for i in range(n_cribs):
                ki = crib_positions[i] + d
                if ki < n_key and key_ints[ki] == crib_values[i]:
                    score += 1
            if score > best_score:
                best_score = score
                best_offset = d
    else:
        # slide key under CT: at offset d, key char for CT pos p is key_ints[p - d]
        max_d = n_ct - n_key
        for d in range(max_d + 1):
            score = 0
            for i in range(n_cribs):
                ki = crib_positions[i] - d
                if 0 <= ki < n_key and key_ints[ki] == crib_values[i]:
                    score += 1
            if score > best_score:
                best_score = score
                best_offset = -d
    return best_score, best_offset


def check_bean_eq(key_ints, offset, n_ct):
    """Check Bean equality: key at CT pos 27 == key at CT pos 65."""
    n_key = len(key_ints)
    if n_key >= n_ct:
        i27 = 27 + offset
        i65 = 65 + offset
        if i27 < n_key and i65 < n_key:
            return key_ints[i27] == key_ints[i65]
    else:
        i27 = 27 - offset
        i65 = 65 - offset
        if 0 <= i27 < n_key and 0 <= i65 < n_key:
            return key_ints[i27] == key_ints[i65]
    return None


# ── Transposition utilities ───────────────────────────────────────────────────

def keyword_to_order(keyword, width):
    """Convert a keyword to a column read order for columnar transposition.
    Returns a permutation list of length width: order[i] = which column to read i-th.
    """
    kw = (keyword + ALPH)[:width]
    indexed = sorted(range(width), key=lambda i: (kw[i], i))
    order = [0] * width
    for rank, col in enumerate(indexed):
        order[rank] = col
    return order


def columnar_read(text, width, col_order):
    """Read text in columnar transposition order.
    col_order: list of column indices indicating read order.
    Returns the rearranged string.
    """
    if not text:
        return text
    n = len(text)
    n_rows = math.ceil(n / width)
    # Pad with placeholder if needed
    padded = text + '?' * (n_rows * width - n)
    # Build grid: grid[row][col]
    grid = []
    for r in range(n_rows):
        grid.append(list(padded[r * width:(r + 1) * width]))
    # Read columns in order
    result = []
    for col in col_order:
        for r in range(n_rows):
            ch = grid[r][col]
            if ch != '?':
                result.append(ch)
    return ''.join(result)


def decimation(text, step):
    """Read every step-th character."""
    return text[::step]


def rail_fence_read(text, rails):
    """Rail fence cipher read (encode direction — zigzag assignment)."""
    n = len(text)
    if rails <= 1 or rails >= n:
        return text
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for i, ch in enumerate(text):
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return ''.join(''.join(r) for r in fence)


def interleave_texts(texts):
    """Interleave characters from multiple texts (round-robin)."""
    result = []
    max_len = max(len(t) for t in texts)
    for i in range(max_len):
        for t in texts:
            if i < len(t):
                result.append(t[i])
    return ''.join(result)


def cross_encrypt(text_a, text_b, variant, alph_str, alph_idx):
    """Encrypt text_a using text_b as a running key (modular, repeating)."""
    n = len(text_a)
    result = []
    b_len = len(text_b)
    for i in range(n):
        ca = alph_idx.get(text_a[i], 0)
        cb = alph_idx.get(text_b[i % b_len], 0)
        if variant == "vigenere":
            r = (ca + cb) % MOD
        elif variant == "beaufort":
            r = (cb - ca) % MOD
        else:  # varbeaufort
            r = (ca - cb) % MOD
        result.append(alph_str[r])
    return ''.join(result)


def text_to_ints(text, alph_idx):
    """Convert text to integer list using alphabet index."""
    return [alph_idx.get(ch, 0) for ch in text]


# ── Derived text generation ───────────────────────────────────────────────────

def generate_derived_texts():
    """Generate all derived texts from K1, K2, K3, and K1K2K3.
    Returns list of (label, text_str).
    """
    sources = [
        ("K1", K1_PT),
        ("K2", K2_PT),
        ("K3", K3_PT),
        ("K1K2K3", K1K2K3),
    ]

    derived = []

    for src_name, src_text in sources:
        # 1. Identity
        derived.append((f"{src_name}_identity", src_text))

        # 2. Reversed
        derived.append((f"{src_name}_reversed", src_text[::-1]))

        # 3. Columnar transpositions — ascending order
        for w in [7, 8, 9, 10, 14, 24, 31]:
            col_order = list(range(w))  # ascending
            t = columnar_read(src_text, w, col_order)
            derived.append((f"{src_name}_col{w}_asc", t))

        # 4. Columnar transpositions — keyword orders
        for kw in KEYWORDS:
            for w in [7, 8, 9, 10, 14, 24, 31]:
                col_order = keyword_to_order(kw, w)
                t = columnar_read(src_text, w, col_order)
                derived.append((f"{src_name}_col{w}_{kw}", t))

        # 5. Decimation
        for step in [2, 3, 5, 7, 13]:
            t = decimation(src_text, step)
            if t:
                derived.append((f"{src_name}_dec{step}", t))

        # 6. Rail fence
        for rails in [2, 3, 4, 5]:
            t = rail_fence_read(src_text, rails)
            derived.append((f"{src_name}_rail{rails}", t))

    # 7. K-section interleaving — 3 orders
    sections = [K1_PT, K2_PT, K3_PT]
    interleave_orders = [
        [0, 1, 2],
        [0, 2, 1],
        [2, 1, 0],
    ]
    for order in interleave_orders:
        texts_in_order = [sections[i] for i in order]
        t = interleave_texts(texts_in_order)
        label = f"interleave_{'_'.join(str(i+1) for i in order)}"
        derived.append((label, t))

    # 8. All 6 concatenation orders of K1, K2, K3
    for perm in permutations([0, 1, 2]):
        parts = [sections[i] for i in perm]
        t = ''.join(parts)
        label = f"concat_{''.join(str(i+1) for i in perm)}"
        derived.append((label, t))

    # 9. Cross-section encryption (12 additional)
    section_pairs = [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)]
    pair_names = ["K1K2", "K1K3", "K2K1", "K2K3", "K3K1", "K3K2"]
    alph_str, alph_idx = AZ, AZ_IDX
    for (i, j), name in zip(section_pairs, pair_names):
        for var in ["beaufort", "vigenere"]:
            t = cross_encrypt(sections[i], sections[j], var, alph_str, alph_idx)
            derived.append((f"cross_{name}_{var}", t))

    return derived


# ── W=7 exhaustive permutations ───────────────────────────────────────────────

def generate_w7_args(required_keys_by_model_variant_alpha):
    """Generate all args for W=7 exhaustive search across all perms of 7 columns."""
    sources = [
        ("K1", K1_PT),
        ("K2", K2_PT),
        ("K3", K3_PT),
        ("K1K2K3", K1K2K3),
    ]
    all_args = []
    all_perms = list(permutations(range(7)))  # 5040

    for perm in all_perms:
        for src_name, src_text in sources:
            text = columnar_read(src_text, 7, list(perm))
            for model_key, (ct_text, crib_dict) in [
                ("B", (CT, CRIB_DICT)),
                ("A", (CT73, CT73_CRIB_DICT)),
            ]:
                for variant in VARIANTS:
                    for alph_name in ["AZ", "KA"]:
                        alph_str, alph_idx = ALPHABETS[alph_name]
                        rkey_key = (model_key, variant, alph_name)
                        req_key = required_keys_by_model_variant_alpha[rkey_key]
                        key_ints = text_to_ints(text, alph_idx)
                        n_ct = len(ct_text)
                        label = f"{src_name}_col7_perm{''.join(map(str, perm))}"
                        all_args.append((
                            label, key_ints, req_key, n_ct,
                            variant, alph_name, model_key, text
                        ))
    return all_args


# ── Worker functions ──────────────────────────────────────────────────────────

def search_worker(args):
    """Worker for phase 2 search."""
    label, text, all_required_keys = args
    results = []
    for model_key, (ct_text, crib_dict) in [
        ("B", (CT, CRIB_DICT)),
        ("A", (CT73, CT73_CRIB_DICT)),
    ]:
        for variant in VARIANTS:
            for alph_name in ["AZ", "KA"]:
                alph_str, alph_idx = ALPHABETS[alph_name]
                rkey_key = (model_key, variant, alph_name)
                req_key = all_required_keys[rkey_key]
                key_ints = text_to_ints(text, alph_idx)
                n_ct = len(ct_text)
                score, offset = crib_drag_fast(key_ints, req_key, n_ct)
                if score >= 8:
                    bean = check_bean_eq(key_ints, abs(offset), n_ct)
                    results.append({
                        "text": label,
                        "variant": variant,
                        "alphabet": alph_name,
                        "model": model_key,
                        "offset": offset,
                        "matches": score,
                        "bean_eq": bean,
                    })
    return results


def search_w7_worker(args):
    """Worker for W=7 exhaustive search."""
    label, key_ints, req_key, n_ct, variant, alph_name, model_key, text = args
    score, offset = crib_drag_fast(key_ints, req_key, n_ct)
    if score >= 8:
        bean = check_bean_eq(key_ints, abs(offset), n_ct)
        return {
            "text": label,
            "variant": variant,
            "alphabet": alph_name,
            "model": model_key,
            "offset": offset,
            "matches": score,
            "bean_eq": bean,
        }
    return None


# ── Extended transpositions (Phase 2b) ───────────────────────────────────────

def generate_phase2b_args(all_required_keys):
    """Generate args for Phase 2b: extended transpositions on K1K2K3."""
    args_list = []
    src_text = K1K2K3
    src_name = "K1K2K3"

    # Widths 2-31 with ascending column order
    for w in range(2, 32):
        col_order = list(range(w))
        text = columnar_read(src_text, w, col_order)
        label = f"{src_name}_col{w}_asc"
        for model_key, (ct_text, crib_dict) in [
            ("B", (CT, CRIB_DICT)),
            ("A", (CT73, CT73_CRIB_DICT)),
        ]:
            for variant in VARIANTS:
                for alph_name in ["AZ", "KA"]:
                    alph_str, alph_idx = ALPHABETS[alph_name]
                    rkey_key = (model_key, variant, alph_name)
                    req_key = all_required_keys[rkey_key]
                    key_ints = text_to_ints(text, alph_idx)
                    n_ct = len(ct_text)
                    args_list.append((label, key_ints, req_key, n_ct, variant, alph_name, model_key, text))

    # Widths 2-31 with each keyword ordering
    for kw in KEYWORDS:
        for w in range(2, 32):
            col_order = keyword_to_order(kw, w)
            text = columnar_read(src_text, w, col_order)
            label = f"{src_name}_col{w}_{kw}"
            for model_key, (ct_text, crib_dict) in [
                ("B", (CT, CRIB_DICT)),
                ("A", (CT73, CT73_CRIB_DICT)),
            ]:
                for variant in VARIANTS:
                    for alph_name in ["AZ", "KA"]:
                        alph_str, alph_idx = ALPHABETS[alph_name]
                        rkey_key = (model_key, variant, alph_name)
                        req_key = all_required_keys[rkey_key]
                        key_ints = text_to_ints(text, alph_idx)
                        n_ct = len(ct_text)
                        args_list.append((label, key_ints, req_key, n_ct, variant, alph_name, model_key, text))

    # Double transposition: width-W then width-V
    double_widths = [7, 8, 9, 10, 14]
    for w1 in double_widths:
        for w2 in double_widths:
            col_order1 = list(range(w1))
            text_tmp = columnar_read(src_text, w1, col_order1)
            col_order2 = list(range(w2))
            text = columnar_read(text_tmp, w2, col_order2)
            label = f"{src_name}_col{w1}then{w2}_asc"
            for model_key, (ct_text, crib_dict) in [
                ("B", (CT, CRIB_DICT)),
                ("A", (CT73, CT73_CRIB_DICT)),
            ]:
                for variant in VARIANTS:
                    for alph_name in ["AZ", "KA"]:
                        alph_str, alph_idx = ALPHABETS[alph_name]
                        rkey_key = (model_key, variant, alph_name)
                        req_key = all_required_keys[rkey_key]
                        key_ints = text_to_ints(text, alph_idx)
                        n_ct = len(ct_text)
                        args_list.append((label, key_ints, req_key, n_ct, variant, alph_name, model_key, text))

    # Boustrophedon reading on 28×31 grid (alternating row directions)
    grid_text = src_text.ljust(28 * 31, 'X')[:28 * 31]
    boustro = []
    for row in range(28):
        row_chars = grid_text[row * 31:(row + 1) * 31]
        if row % 2 == 0:
            boustro.extend(row_chars)
        else:
            boustro.extend(reversed(row_chars))
    text = ''.join(boustro)
    label = f"{src_name}_boustrophedon_28x31"
    for model_key, (ct_text, crib_dict) in [
        ("B", (CT, CRIB_DICT)),
        ("A", (CT73, CT73_CRIB_DICT)),
    ]:
        for variant in VARIANTS:
            for alph_name in ["AZ", "KA"]:
                alph_str, alph_idx = ALPHABETS[alph_name]
                rkey_key = (model_key, variant, alph_name)
                req_key = all_required_keys[rkey_key]
                key_ints = text_to_ints(text, alph_idx)
                n_ct = len(ct_text)
                args_list.append((label, key_ints, req_key, n_ct, variant, alph_name, model_key, text))

    # Column-first reading on 28×31 grid
    col_first = []
    for col in range(31):
        for row in range(28):
            idx = row * 31 + col
            if idx < len(src_text):
                col_first.append(src_text[idx])
    text = ''.join(col_first)
    label = f"{src_name}_colfirst_28x31"
    for model_key, (ct_text, crib_dict) in [
        ("B", (CT, CRIB_DICT)),
        ("A", (CT73, CT73_CRIB_DICT)),
    ]:
        for variant in VARIANTS:
            for alph_name in ["AZ", "KA"]:
                alph_str, alph_idx = ALPHABETS[alph_name]
                rkey_key = (model_key, variant, alph_name)
                req_key = all_required_keys[rkey_key]
                key_ints = text_to_ints(text, alph_idx)
                n_ct = len(ct_text)
                args_list.append((label, key_ints, req_key, n_ct, variant, alph_name, model_key, text))

    return args_list


# ── Reporting ─────────────────────────────────────────────────────────────────

def classify_and_report(all_results, elapsed, total_configs):
    """Classify results and produce final report."""
    signals = [r for r in all_results if r["matches"] >= 18]
    interesting = [r for r in all_results if 12 <= r["matches"] < 18]
    noise = [r for r in all_results if r["matches"] < 12]

    all_sorted = sorted(all_results, key=lambda r: r["matches"], reverse=True)
    top_20 = all_sorted[:20]
    best = top_20[0] if top_20 else None

    classification = "NOISE"
    if signals:
        classification = "SIGNAL"
    elif interesting:
        classification = "INTERESTING"

    summary = {
        "experiment": "K1-K3 Running Key Exhaustive Transformation Search",
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_configs": total_configs,
        "elapsed_seconds": round(elapsed, 2),
        "best_score": best["matches"] if best else 0,
        "best_detail": best,
        "signal_count": len(signals),
        "interesting_count": len(interesting),
        "signals": signals,
        "interesting": interesting,
        "top_20": top_20,
        "classification": classification,
    }

    print(f"\n{'='*60}", flush=True)
    print(f"RESULTS — {classification}", flush=True)
    print(f"Total configs tested: {total_configs}", flush=True)
    print(f"Elapsed: {elapsed:.1f}s", flush=True)
    print(f"Best score: {best['matches'] if best else 0}/24", flush=True)
    print(f"Signals (>=18): {len(signals)}", flush=True)
    print(f"Interesting (>=12): {len(interesting)}", flush=True)
    if top_20:
        print("\nTop 20 results:", flush=True)
        for r in top_20[:20]:
            bean_str = f" bean={r['bean_eq']}" if r.get("bean_eq") is not None else ""
            print(f"  {r['matches']:2d}/24 | {r['text'][:45]:45s} | {r['variant']:12s} | {r['alphabet']} | M={r['model']} | off={r['offset']}{bean_str}", flush=True)

    return summary


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="K1-K3 Running Key Exhaustive Search")
    parser.add_argument("--phase1-only", action="store_true",
                        help="Only generate derived texts, do not search")
    parser.add_argument("--workers", type=int, default=min(multiprocessing.cpu_count(), 28),
                        help="Number of worker processes")
    args = parser.parse_args()

    t0 = time.time()

    print("=" * 60, flush=True)
    print("K1-K3 Running Key Exhaustive Search", flush=True)
    print(f"CT length: {CT_LEN}, Crib positions: {N_CRIBS}", flush=True)
    print(f"K1: {len(K1_PT)} chars, K2: {len(K2_PT)} chars, K3: {len(K3_PT)} chars", flush=True)
    print(f"K1K2K3: {len(K1K2K3)} chars", flush=True)

    # Phase 1: generate derived texts
    print("\nPhase 1: Generating derived texts...", flush=True)
    derived_texts = generate_derived_texts()
    print(f"Generated {len(derived_texts)} derived texts", flush=True)

    # Print summary of text types
    label_prefixes = defaultdict(int)
    for label, text in derived_texts:
        prefix = label.split("_")[0]
        label_prefixes[prefix] += 1
    for prefix, cnt in sorted(label_prefixes.items()):
        print(f"  {prefix}: {cnt} texts", flush=True)

    if args.phase1_only:
        print("\nPhase 1 only — done.", flush=True)
        for label, text in derived_texts[:10]:
            print(f"  {label}: len={len(text)}, sample={text[:20]}", flush=True)
        print(f"  ... and {len(derived_texts)-10} more", flush=True)
        return

    # Pre-compute required keys for all model/variant/alphabet combos
    print("\nPre-computing required keys...", flush=True)
    all_required_keys = {}
    for model_key, (ct_text, crib_dict) in [
        ("B", (CT, CRIB_DICT)),
        ("A", (CT73, CT73_CRIB_DICT)),
    ]:
        for variant in VARIANTS:
            for alph_name in ["AZ", "KA"]:
                alph_str, alph_idx = ALPHABETS[alph_name]
                req = derive_required_key(ct_text, crib_dict, variant, alph_str, alph_idx)
                all_required_keys[(model_key, variant, alph_name)] = req
    print(f"Required key maps: {len(all_required_keys)} combinations", flush=True)

    n_workers = args.workers
    print(f"Using {n_workers} worker processes", flush=True)

    all_results = []
    total_configs = 0

    # Phase 2: crib-drag search on derived texts
    print("\nPhase 2: Crib-drag search on derived texts...", flush=True)
    phase2_args = [(label, text, all_required_keys) for label, text in derived_texts]
    total_configs += len(phase2_args) * len(VARIANTS) * len(ALPHABETS) * 2  # × models

    with multiprocessing.Pool(n_workers) as pool:
        for i, res_list in enumerate(pool.imap_unordered(search_worker, phase2_args)):
            all_results.extend(res_list)
            if (i + 1) % 50 == 0 or (i + 1) == len(phase2_args):
                print(f"  Phase 2: {i+1}/{len(phase2_args)} texts done, hits so far: {len(all_results)}", flush=True)

    t_phase2 = time.time() - t0
    print(f"Phase 2 done in {t_phase2:.1f}s", flush=True)

    # Phase 2b: extended transpositions on K1K2K3
    print("\nPhase 2b: Extended transpositions on K1K2K3...", flush=True)
    phase2b_args = generate_phase2b_args(all_required_keys)
    total_configs += len(phase2b_args)
    print(f"  {len(phase2b_args)} configs in phase 2b", flush=True)

    with multiprocessing.Pool(n_workers) as pool:
        hits_2b = 0
        for i, result in enumerate(pool.imap_unordered(search_w7_worker, phase2b_args, chunksize=500)):
            if result is not None:
                all_results.append(result)
                hits_2b += 1
            if (i + 1) % 10000 == 0:
                print(f"  Phase 2b: {i+1}/{len(phase2b_args)} done, hits: {hits_2b}", flush=True)
    print(f"  Phase 2b done, hits: {hits_2b}", flush=True)

    t_phase2b = time.time() - t0
    print(f"Phase 2b done in {t_phase2b:.1f}s total", flush=True)

    # W=7 exhaustive: ALL 5040 permutations
    print("\nPhase 2c: W=7 exhaustive (5040 perms × 4 sources × 6 variants × 2 models)...", flush=True)
    w7_configs = list(permutations(range(7)))
    sources_4 = [
        ("K1", K1_PT),
        ("K2", K2_PT),
        ("K3", K3_PT),
        ("K1K2K3", K1K2K3),
    ]

    w7_args = []
    for perm in w7_configs:
        for src_name, src_text in sources_4:
            text = columnar_read(src_text, 7, list(perm))
            for model_key, (ct_text, crib_dict) in [
                ("B", (CT, CRIB_DICT)),
                ("A", (CT73, CT73_CRIB_DICT)),
            ]:
                for variant in VARIANTS:
                    for alph_name in ["AZ", "KA"]:
                        alph_str, alph_idx = ALPHABETS[alph_name]
                        rkey_key = (model_key, variant, alph_name)
                        req_key = all_required_keys[rkey_key]
                        key_ints = text_to_ints(text, alph_idx)
                        n_ct = len(ct_text)
                        label = f"{src_name}_col7_perm{''.join(map(str, perm))}"
                        w7_args.append((
                            label, key_ints, req_key, n_ct,
                            variant, alph_name, model_key, text
                        ))

    total_configs += len(w7_args)
    print(f"  {len(w7_args)} W=7 configs to test", flush=True)

    with multiprocessing.Pool(n_workers) as pool:
        hits_w7 = 0
        for i, result in enumerate(pool.imap_unordered(search_w7_worker, w7_args, chunksize=500)):
            if result is not None:
                all_results.append(result)
                hits_w7 += 1
            if (i + 1) % 100000 == 0:
                print(f"  W=7: {i+1}/{len(w7_args)} done, hits: {hits_w7}", flush=True)

    print(f"  W=7 done, hits: {hits_w7}", flush=True)

    elapsed = time.time() - t0
    print(f"\nTotal elapsed: {elapsed:.1f}s", flush=True)
    print(f"Total configs: {total_configs}", flush=True)

    # Classify and report
    summary = classify_and_report(all_results, elapsed, total_configs)

    # Write results
    out_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results', 'k123_running_key_exhaustive'
    )
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "summary.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults written to {out_path}", flush=True)


if __name__ == "__main__":
    main()
