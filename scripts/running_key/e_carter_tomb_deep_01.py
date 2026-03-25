#!/usr/bin/env python3
"""
Cipher: running_key
Family: running_key
Status: active
Keyspace: ~900K offsets x 3 texts x 3 variants + CT73 + key fragment English detection
Last run:
Best score:
"""
"""
E-CARTER-TOMB-DEEP-01: Comprehensive Carter Running Key Analysis

Six-phase analysis of Howard Carter's "The Tomb of Tut-Ankh-Amen" Vol 1
as a running-key source for K4.

Phase 1: Text preparation and character counts
Phase 2: Direct running key (all offsets, all 3 variants)
Phase 3: Bean constraint filter on Phase 2 hits
Phase 4: Key fragment English detection (quadgram scoring of key at crib positions)
Phase 5: K3 source passage focus (near "SLOWLY DESPERATELY SLOWLY")
Phase 6: 73-char null-extracted CT analysis

Output: results/e_carter_tomb_deep_01.json
Repro: PYTHONPATH=src python3 -u scripts/running_key/e_carter_tomb_deep_01.py
"""

import json
import sys
import os
import re
import time
import math

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD, BEAN_EQ, BEAN_INEQ
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.constraints.bean import verify_bean_simple

# ── Constants ──
CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN  # 97
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

ENE_RANGE = list(range(21, 34))  # 13 positions
BC_RANGE = list(range(63, 74))   # 11 positions

# Null positions (0-indexed) from consensus mask
NULL_POS = sorted({2, 6, 9, 13, 17, 20, 34, 38, 42, 46, 50, 52, 53, 56, 60, 74, 77})

# ── Load quadgrams ──
QUADGRAM_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
QUADGRAMS = {}
if os.path.exists(QUADGRAM_PATH):
    with open(QUADGRAM_PATH) as f:
        QUADGRAMS = json.load(f)
    # Find floor value
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0
    print(f"Loaded {len(QUADGRAMS)} quadgrams (floor={QG_FLOOR:.3f})")
else:
    QG_FLOOR = -10.0
    print("WARNING: No quadgrams file found")


def quadgram_score(text):
    """Score a text string using log quadgram probabilities. Returns score per char."""
    if len(text) < 4:
        return QG_FLOOR
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
        count += 1
    return total / count if count > 0 else QG_FLOOR


def nums_to_text(nums):
    return ''.join(chr(n + ord('A')) for n in nums)


def sanitize_text(raw):
    """Strip everything non-alpha, uppercase."""
    # Remove soft hyphens, bullets, etc.
    cleaned = raw.replace('\u00ac', '').replace('\u2022', '').replace('\xad', '')
    return re.sub(r'[^A-Za-z]', '', cleaned).upper()


def load_text_file(path):
    with open(path) as f:
        raw = f.read()
    clean = sanitize_text(raw)
    return clean, [ALPH_IDX[c] for c in clean]


def extract_gutenberg_body(raw):
    """Extract body between Gutenberg header/footer markers."""
    start_markers = ["*** START OF", "***START OF"]
    end_markers = ["*** END OF", "***END OF"]
    start = 0
    for m in start_markers:
        idx = raw.find(m)
        if idx >= 0:
            start = raw.index('\n', idx) + 1
            break
    end = len(raw)
    for m in end_markers:
        idx = raw.find(m)
        if idx >= 0:
            end = idx
            break
    return raw[start:end]


def compute_key_values(ct_nums, pt_dict, variant):
    """Compute key values at crib positions for a given variant."""
    keys = {}
    for pos, pt_val in pt_dict.items():
        ct_val = ct_nums[pos]
        if variant == "vigenere":
            keys[pos] = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            keys[pos] = (ct_val + pt_val) % MOD
        elif variant == "var_beaufort":
            keys[pos] = (pt_val - ct_val) % MOD
    return keys


def decrypt_full(ct_nums, key_nums, variant):
    """Decrypt full ciphertext with running key."""
    pt = []
    for i in range(len(ct_nums)):
        c = ct_nums[i]
        k = key_nums[i] if i < len(key_nums) else 0
        if variant == "vigenere":
            pt.append((c - k) % MOD)
        elif variant == "beaufort":
            pt.append((k - c) % MOD)
        elif variant == "var_beaufort":
            pt.append((c + k) % MOD)  # PT = CT + K for var_beaufort decrypt
    return pt


def check_bean_keystream(keystream_97):
    """Check Bean equality and all 242 inequalities on a 97-length keystream."""
    # Equality: k[27] == k[65]
    eq_pass = keystream_97[27] == keystream_97[65]

    # Inequalities
    ineq_fail = 0
    for (a, b) in BEAN_INEQ:
        if a < len(keystream_97) and b < len(keystream_97):
            if keystream_97[a] == keystream_97[b]:
                ineq_fail += 1

    return eq_pass, ineq_fail


def score_crib_match(ct_nums, text_nums, offset, variant):
    """Count how many crib positions match when using text at offset as running key."""
    ene_match = 0
    bc_match = 0
    key_required = compute_key_values(ct_nums, CRIB_PT, variant)

    for pos in ENE_RANGE:
        text_pos = pos + offset
        if text_pos < len(text_nums) and text_nums[text_pos] == key_required[pos]:
            ene_match += 1

    for pos in BC_RANGE:
        text_pos = pos + offset
        if text_pos < len(text_nums) and text_nums[text_pos] == key_required[pos]:
            bc_match += 1

    return ene_match, bc_match, ene_match + bc_match


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Prepare texts
# ══════════════════════════════════════════════════════════════════════════
def phase1():
    print("\n" + "=" * 70)
    print("PHASE 1: TEXT PREPARATION")
    print("=" * 70)

    texts = {}

    # Carter Tomb OCR (448K)
    path1 = os.path.join(_ROOT, "reference", "Carter_Tomb.txt")
    if os.path.exists(path1):
        clean1, nums1 = load_text_file(path1)
        texts["Carter_Tomb"] = (clean1, nums1)
        print(f"  Carter_Tomb.txt: {len(clean1)} alpha chars (from {os.path.getsize(path1)} bytes)")
    else:
        print(f"  WARNING: {path1} not found")

    # carter_vol1 OCR (437K)
    path2 = os.path.join(_ROOT, "reference", "carter_vol1.txt")
    if os.path.exists(path2):
        clean2, nums2 = load_text_file(path2)
        texts["carter_vol1"] = (clean2, nums2)
        print(f"  carter_vol1.txt: {len(clean2)} alpha chars (from {os.path.getsize(path2)} bytes)")
    else:
        print(f"  WARNING: {path2} not found")

    # Gutenberg (G. Elliot Smith - different book, but thematically related)
    path3 = os.path.join(_ROOT, "reference", "carter_gutenberg.txt")
    if os.path.exists(path3):
        with open(path3) as f:
            raw3 = f.read()
        body3 = extract_gutenberg_body(raw3)
        clean3_full = sanitize_text(raw3)
        clean3_body = sanitize_text(body3)
        nums3_full = [ALPH_IDX[c] for c in clean3_full]
        nums3_body = [ALPH_IDX[c] for c in clean3_body]
        texts["carter_gutenberg_full"] = (clean3_full, nums3_full)
        texts["carter_gutenberg_body"] = (clean3_body, nums3_body)
        print(f"  carter_gutenberg.txt (full): {len(clean3_full)} alpha chars")
        print(f"  carter_gutenberg.txt (body only): {len(clean3_body)} alpha chars")
    else:
        print(f"  WARNING: {path3} not found")

    return texts


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Direct running key (all offsets, all variants)
# ══════════════════════════════════════════════════════════════════════════
def phase2(texts):
    print("\n" + "=" * 70)
    print("PHASE 2: DIRECT RUNNING KEY — ALL OFFSETS, ALL VARIANTS")
    print("=" * 70)

    VARIANTS = ["vigenere", "beaufort", "var_beaufort"]
    THRESHOLD = 8
    all_hits = []

    for text_name, (clean, nums) in texts.items():
        max_offset = len(nums) - N
        if max_offset <= 0:
            print(f"  {text_name}: too short ({len(nums)} chars), skipping")
            continue

        print(f"\n  Scanning {text_name} ({len(nums)} chars, {max_offset} offsets)...", flush=True)

        for variant in VARIANTS:
            key_required = compute_key_values(CT_NUM, CRIB_PT, variant)
            hits_this = 0

            for offset in range(max_offset):
                ene_match = 0
                bc_match = 0

                # Check ENE block (positions 21-33)
                for pos in ENE_RANGE:
                    tp = pos + offset
                    if nums[tp] == key_required[pos]:
                        ene_match += 1

                # Early exit: if ENE < 4, skip BC check
                if ene_match < 4:
                    continue

                # Check BC block (positions 63-73)
                for pos in BC_RANGE:
                    tp = pos + offset
                    if nums[tp] == key_required[pos]:
                        bc_match += 1

                total = ene_match + bc_match
                if total >= THRESHOLD:
                    # Decrypt full text
                    key_slice = nums[offset:offset + N]
                    pt_nums = decrypt_full(CT_NUM, key_slice, variant)
                    pt_str = nums_to_text(pt_nums)

                    # Key fragment text at crib positions
                    ene_key_text = clean[21 + offset:34 + offset]
                    bc_key_text = clean[63 + offset:74 + offset]

                    # Score with official scorer
                    sb = score_candidate(pt_str)

                    hit = {
                        "text": text_name,
                        "variant": variant,
                        "offset": offset,
                        "ene_match": ene_match,
                        "bc_match": bc_match,
                        "total_match": total,
                        "plaintext": pt_str,
                        "ene_key_fragment": ene_key_text,
                        "bc_key_fragment": bc_key_text,
                        "crib_score": sb.crib_score,
                        "crib_classification": sb.crib_classification,
                    }
                    all_hits.append(hit)
                    hits_this += 1

            print(f"    {variant}: {hits_this} hits >= {THRESHOLD}", flush=True)

    # Sort by total match
    all_hits.sort(key=lambda h: -h["total_match"])

    print(f"\n  PHASE 2 TOTAL: {len(all_hits)} hits >= {THRESHOLD}")
    if all_hits:
        print(f"  Best match: {all_hits[0]['total_match']}/24 "
              f"({all_hits[0]['text']}, {all_hits[0]['variant']}, offset={all_hits[0]['offset']})")
        print(f"  Top 10:")
        for h in all_hits[:10]:
            print(f"    {h['total_match']}/24 ENE={h['ene_match']} BC={h['bc_match']} "
                  f"{h['text']} {h['variant']} off={h['offset']}")
            print(f"      ENE key: '{h['ene_key_fragment']}'  BC key: '{h['bc_key_fragment']}'")
            print(f"      PT: {h['plaintext'][:60]}...")

    return all_hits


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Bean constraint filter
# ══════════════════════════════════════════════════════════════════════════
def phase3(hits, texts):
    print("\n" + "=" * 70)
    print("PHASE 3: BEAN CONSTRAINT FILTER")
    print("=" * 70)

    bean_results = []
    for h in hits:
        text_name = h["text"]
        if text_name not in texts:
            continue
        _, nums = texts[text_name]
        offset = h["offset"]
        variant = h["variant"]

        # Compute full keystream
        key_slice = nums[offset:offset + N]
        if len(key_slice) < N:
            continue

        eq_pass, ineq_fail = check_bean_keystream(key_slice)

        bean_results.append({
            **h,
            "bean_eq_pass": eq_pass,
            "bean_ineq_failures": ineq_fail,
            "bean_full_pass": eq_pass and ineq_fail == 0,
        })

    bean_pass = [b for b in bean_results if b["bean_full_pass"]]
    bean_eq_only = [b for b in bean_results if b["bean_eq_pass"]]
    print(f"  Total hits checked: {len(bean_results)}")
    print(f"  Bean equality pass (k[27]==k[65]): {len(bean_eq_only)}")
    print(f"  Bean FULL pass (eq + 242 ineq): {len(bean_pass)}")

    if bean_pass:
        print(f"\n  Bean FULL PASS hits:")
        for b in bean_pass[:20]:
            print(f"    {b['total_match']}/24 {b['text']} {b['variant']} off={b['offset']}")
            print(f"      PT: {b['plaintext'][:60]}...")

    if bean_eq_only and not bean_pass:
        print(f"\n  Bean equality-only pass hits (top 10):")
        for b in sorted(bean_eq_only, key=lambda x: -x["total_match"])[:10]:
            print(f"    {b['total_match']}/24 {b['text']} {b['variant']} off={b['offset']} "
                  f"ineq_fail={b['bean_ineq_failures']}")

    return bean_results


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Key fragment English detection
# ══════════════════════════════════════════════════════════════════════════
def phase4(texts):
    print("\n" + "=" * 70)
    print("PHASE 4: KEY FRAGMENT ENGLISH DETECTION")
    print("=" * 70)
    print("  At crib positions, the running key IS the Carter text.")
    print("  Scoring key fragments for English-ness via quadgrams.")

    VARIANTS = ["vigenere", "beaufort", "var_beaufort"]
    results_by_variant = {}

    for variant in VARIANTS:
        key_required = compute_key_values(CT_NUM, CRIB_PT, variant)

        # Required key letters at ENE positions (13 chars) and BC positions (11 chars)
        ene_required = [key_required[p] for p in ENE_RANGE]
        bc_required = [key_required[p] for p in BC_RANGE]

        ene_str = nums_to_text(ene_required)
        bc_str = nums_to_text(bc_required)

        print(f"\n  Variant: {variant}")
        print(f"    Required ENE key (pos 21-33): {ene_str}")
        print(f"    Required BC  key (pos 63-73): {bc_str}")
        print(f"    ENE quadgram score: {quadgram_score(ene_str):.3f}")
        print(f"    BC  quadgram score: {quadgram_score(bc_str):.3f}")

        # Now for each text, slide and find where the text best matches
        # these required key fragments
        variant_results = []
        for text_name, (clean, nums) in texts.items():
            max_offset = len(nums) - N
            if max_offset <= 0:
                continue

            for offset in range(max_offset):
                # Extract what the text gives as key at crib positions
                ene_actual = [nums[p + offset] for p in ENE_RANGE]
                bc_actual = [nums[p + offset] for p in BC_RANGE]

                ene_match = sum(1 for a, b in zip(ene_actual, ene_required) if a == b)
                bc_match = sum(1 for a, b in zip(bc_actual, bc_required) if a == b)

                # Only report offsets with some match
                if ene_match + bc_match >= 5:
                    # The key fragment from the text at these positions
                    ene_text = clean[21 + offset:34 + offset]
                    bc_text = clean[63 + offset:74 + offset]

                    # Overall key fragment (full 97 chars from text)
                    full_key_text = clean[offset:offset + N]

                    # Quadgram of the key fragments
                    ene_qg = quadgram_score(ene_text)
                    bc_qg = quadgram_score(bc_text)

                    variant_results.append({
                        "text": text_name,
                        "offset": offset,
                        "ene_match": ene_match,
                        "bc_match": bc_match,
                        "total_match": ene_match + bc_match,
                        "ene_text": ene_text,
                        "bc_text": bc_text,
                        "ene_qg": ene_qg,
                        "bc_qg": bc_qg,
                        "full_key_97": full_key_text,
                    })

        # Sort by total match, then by quadgram quality
        variant_results.sort(key=lambda x: (-x["total_match"], -(x["ene_qg"] + x["bc_qg"])))

        print(f"    Offsets with >= 5 crib matches: {len(variant_results)}")
        print(f"    Top 20 by crib match count:")
        for r in variant_results[:20]:
            print(f"      {r['total_match']}/24 (ENE={r['ene_match']} BC={r['bc_match']}) "
                  f"{r['text']} off={r['offset']}")
            print(f"        ENE key: '{r['ene_text']}' (qg={r['ene_qg']:.3f})")
            print(f"        BC  key: '{r['bc_text']}' (qg={r['bc_qg']:.3f})")

        results_by_variant[variant] = variant_results

    # Also: Find the most English-looking key fragments regardless of match count
    print(f"\n  KEY FRAGMENT ENGLISH QUALITY (top by quadgram, any match count):")
    for variant in VARIANTS:
        key_required = compute_key_values(CT_NUM, CRIB_PT, variant)
        ene_str = nums_to_text([key_required[p] for p in ENE_RANGE])
        bc_str = nums_to_text([key_required[p] for p in BC_RANGE])

        print(f"\n  {variant}:")
        print(f"    Required ENE: {ene_str}  Required BC: {bc_str}")

        # Score just the REQUIRED key fragments themselves
        ene_qg = quadgram_score(ene_str)
        bc_qg = quadgram_score(bc_str)
        print(f"    ENE quadgram: {ene_qg:.3f}  BC quadgram: {bc_qg:.3f}")
        print(f"    Combined: {(ene_qg + bc_qg) / 2:.3f}")
        print(f"    (English text typically scores -4.0 to -3.5 per char)")

    return results_by_variant


# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: K3 source passage focus
# ══════════════════════════════════════════════════════════════════════════
def phase5(texts):
    print("\n" + "=" * 70)
    print("PHASE 5: K3 SOURCE PASSAGE FOCUS")
    print("=" * 70)

    # K3 plaintext fragments (from the Carter book passage)
    k3_fragments = [
        "SLOWLYDESPERATELYSLOWLY",
        "THEREMAINSOFPASSAGE",
        "CANYOUSEEANYTHING",
        "YESWONDERFULTHINGS",
    ]

    VARIANTS = ["vigenere", "beaufort", "var_beaufort"]
    SEARCH_RADIUS = 500

    passage_hits = []

    for text_name, (clean, nums) in texts.items():
        print(f"\n  Searching {text_name} for K3 passage fragments...")

        for frag in k3_fragments:
            idx = clean.find(frag)
            if idx >= 0:
                print(f"    Found '{frag}' at alpha position {idx}")

                # Test offsets in range [idx - SEARCH_RADIUS, idx + SEARCH_RADIUS]
                for variant in VARIANTS:
                    key_required = compute_key_values(CT_NUM, CRIB_PT, variant)
                    best_in_range = None

                    for offset in range(max(0, idx - SEARCH_RADIUS),
                                       min(len(nums) - N, idx + SEARCH_RADIUS)):
                        ene_match = sum(1 for p in ENE_RANGE
                                       if nums[p + offset] == key_required[p])
                        bc_match = sum(1 for p in BC_RANGE
                                      if nums[p + offset] == key_required[p])
                        total = ene_match + bc_match

                        if total >= 5:
                            ene_text = clean[21 + offset:34 + offset]
                            bc_text = clean[63 + offset:74 + offset]
                            key_slice = nums[offset:offset + N]
                            pt_nums = decrypt_full(CT_NUM, key_slice, variant)
                            pt_str = nums_to_text(pt_nums)
                            sb = score_candidate(pt_str)

                            hit = {
                                "text": text_name,
                                "variant": variant,
                                "offset": offset,
                                "near_fragment": frag,
                                "distance_from_fragment": offset - idx,
                                "ene_match": ene_match,
                                "bc_match": bc_match,
                                "total_match": total,
                                "ene_key": ene_text,
                                "bc_key": bc_text,
                                "plaintext": pt_str,
                                "crib_score": sb.crib_score,
                            }
                            passage_hits.append(hit)
                            if best_in_range is None or total > best_in_range["total_match"]:
                                best_in_range = hit

                    if best_in_range:
                        print(f"      {variant}: best={best_in_range['total_match']}/24 "
                              f"at offset {best_in_range['offset']} "
                              f"(dist={best_in_range['distance_from_fragment']:+d})")
            else:
                print(f"    '{frag}' NOT found in {text_name}")

    passage_hits.sort(key=lambda h: -h["total_match"])
    if passage_hits:
        print(f"\n  Top 10 passage-area hits:")
        for h in passage_hits[:10]:
            print(f"    {h['total_match']}/24 {h['text']} {h['variant']} "
                  f"off={h['offset']} near '{h['near_fragment']}' "
                  f"dist={h['distance_from_fragment']:+d}")
            print(f"      ENE key: '{h['ene_key']}'  BC key: '{h['bc_key']}'")
    else:
        print(f"\n  No passage-area hits >= 5")

    return passage_hits


# ══════════════════════════════════════════════════════════════════════════
# PHASE 6: 73-char null-extracted CT
# ══════════════════════════════════════════════════════════════════════════
def phase6(texts):
    print("\n" + "=" * 70)
    print("PHASE 6: 73-CHAR NULL-EXTRACTED CT ANALYSIS")
    print("=" * 70)

    # Build CT73 by removing null positions
    ct73 = ""
    ct73_from_positions = []
    for i in range(N):
        if i not in NULL_POS:
            ct73 += CT[i]
            ct73_from_positions.append(i)

    ct73_nums = [ALPH_IDX[c] for c in ct73]
    n73 = len(ct73)
    print(f"  CT73 ({n73} chars): {ct73}")
    print(f"  Null positions removed: {NULL_POS}")
    print(f"  Remaining positions: {ct73_from_positions[:20]}...")

    # Map crib positions to CT73 indices
    ct73_crib = {}
    for orig_pos, ch in CRIB_DICT.items():
        if orig_pos not in NULL_POS:
            new_idx = ct73_from_positions.index(orig_pos)
            ct73_crib[new_idx] = ch

    print(f"  Cribs mapped to CT73 positions: {ct73_crib}")
    print(f"  ({len(ct73_crib)} crib positions survive null removal)")

    VARIANTS = ["vigenere", "beaufort", "var_beaufort"]
    THRESHOLD = 6  # Lower threshold since fewer cribs
    all_hits = []

    for text_name, (clean, nums) in texts.items():
        max_offset = len(nums) - n73
        if max_offset <= 0:
            continue

        print(f"\n  Scanning {text_name} against CT73 ({max_offset} offsets)...", flush=True)

        for variant in VARIANTS:
            # Compute required key values at CT73 crib positions
            key_required = {}
            for ct73_idx, pt_ch in ct73_crib.items():
                ct_val = ct73_nums[ct73_idx]
                pt_val = ALPH_IDX[pt_ch]
                if variant == "vigenere":
                    key_required[ct73_idx] = (ct_val - pt_val) % MOD
                elif variant == "beaufort":
                    key_required[ct73_idx] = (ct_val + pt_val) % MOD
                elif variant == "var_beaufort":
                    key_required[ct73_idx] = (pt_val - ct_val) % MOD

            hits_this = 0
            for offset in range(max_offset):
                match_count = 0
                for ct73_idx, req_val in key_required.items():
                    tp = ct73_idx + offset
                    if tp < len(nums) and nums[tp] == req_val:
                        match_count += 1

                if match_count >= THRESHOLD:
                    key_slice = nums[offset:offset + n73]
                    if len(key_slice) < n73:
                        continue
                    pt_nums = decrypt_full(ct73_nums, key_slice, variant)
                    pt_str = nums_to_text(pt_nums)

                    fsb = score_candidate_free(pt_str)

                    all_hits.append({
                        "text": text_name,
                        "variant": variant,
                        "offset": offset,
                        "match_count": match_count,
                        "max_possible": len(ct73_crib),
                        "plaintext": pt_str,
                        "crib_score_free": fsb.crib_score,
                        "ngram_per_char": fsb.ngram_per_char,
                    })
                    hits_this += 1

            print(f"    {variant}: {hits_this} hits >= {THRESHOLD}", flush=True)

    all_hits.sort(key=lambda h: -h["match_count"])
    print(f"\n  PHASE 6 TOTAL: {len(all_hits)} hits >= {THRESHOLD}")
    if all_hits:
        print(f"  Best: {all_hits[0]['match_count']}/{all_hits[0]['max_possible']} "
              f"({all_hits[0]['text']}, {all_hits[0]['variant']}, off={all_hits[0]['offset']})")
        for h in all_hits[:10]:
            print(f"    {h['match_count']}/{h['max_possible']} {h['text']} {h['variant']} "
                  f"off={h['offset']} PT={h['plaintext'][:50]}...")

    return all_hits


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
def main():
    t0 = time.time()

    print("=" * 70)
    print("E-CARTER-TOMB-DEEP-01: Comprehensive Carter Running Key Analysis")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT_LEN: {N}")
    print(f"Cribs: ENE at 21-33 (13 chars), BC at 63-73 (11 chars)")
    print(f"Null positions: {NULL_POS} ({len(NULL_POS)} positions)")

    # Phase 1
    texts = phase1()

    # Phase 2
    p2_hits = phase2(texts)

    # Phase 3
    p3_results = phase3(p2_hits, texts)

    # Phase 4
    p4_results = phase4(texts)

    # Phase 5
    p5_hits = phase5(texts)

    # Phase 6
    p6_hits = phase6(texts)

    elapsed = time.time() - t0

    # ── Summary ──
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"  Elapsed: {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"  Phase 2 hits (>= 8/24): {len(p2_hits)}")
    if p2_hits:
        print(f"    Best: {p2_hits[0]['total_match']}/24")
    print(f"  Phase 3 Bean full pass: {sum(1 for b in p3_results if b.get('bean_full_pass'))}")
    print(f"  Phase 3 Bean eq pass: {sum(1 for b in p3_results if b.get('bean_eq_pass'))}")
    print(f"  Phase 5 passage hits (>= 5): {len(p5_hits)}")
    print(f"  Phase 6 CT73 hits (>= 6): {len(p6_hits)}")

    # Determine verdict
    max_score = 0
    if p2_hits:
        max_score = max(h["total_match"] for h in p2_hits)
    if p6_hits:
        max_score = max(max_score, max(h["match_count"] for h in p6_hits))

    if max_score >= 18:
        verdict = "SIGNAL"
    elif max_score >= 12:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\n  MAX CRIB MATCH: {max_score}/24")
    print(f"  VERDICT: {verdict}")

    # Key fragment analysis summary
    print(f"\n  KEY FRAGMENT ENGLISH QUALITY:")
    for variant in ["vigenere", "beaufort", "var_beaufort"]:
        key_required = compute_key_values(CT_NUM, CRIB_PT, variant)
        ene_str = nums_to_text([key_required[p] for p in ENE_RANGE])
        bc_str = nums_to_text([key_required[p] for p in BC_RANGE])
        ene_qg = quadgram_score(ene_str)
        bc_qg = quadgram_score(bc_str)
        print(f"    {variant}: ENE='{ene_str}' ({ene_qg:.3f})  "
              f"BC='{bc_str}' ({bc_qg:.3f})  avg={(ene_qg+bc_qg)/2:.3f}")

    # ── Save artifact ──
    os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
    artifact = {
        "experiment": "E-CARTER-TOMB-DEEP-01",
        "description": "Comprehensive Carter running key analysis (6 phases)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ciphertext": CT,
        "texts_analyzed": {name: len(clean) for name, (clean, _) in texts.items()},
        "phase2": {
            "threshold": 8,
            "total_hits": len(p2_hits),
            "best_match": p2_hits[0] if p2_hits else None,
            "top_10": p2_hits[:10],
        },
        "phase3": {
            "bean_full_pass": sum(1 for b in p3_results if b.get("bean_full_pass")),
            "bean_eq_pass": sum(1 for b in p3_results if b.get("bean_eq_pass")),
            "bean_pass_hits": [b for b in p3_results if b.get("bean_full_pass")][:20],
        },
        "phase4_key_fragments": {
            variant: {
                "required_ene": nums_to_text([compute_key_values(CT_NUM, CRIB_PT, variant)[p] for p in ENE_RANGE]),
                "required_bc": nums_to_text([compute_key_values(CT_NUM, CRIB_PT, variant)[p] for p in BC_RANGE]),
            }
            for variant in ["vigenere", "beaufort", "var_beaufort"]
        },
        "phase5": {
            "passage_hits": len(p5_hits),
            "top_5": p5_hits[:5],
        },
        "phase6": {
            "ct73": "".join(CT[i] for i in range(N) if i not in NULL_POS),
            "threshold": 6,
            "total_hits": len(p6_hits),
            "top_10": p6_hits[:10],
        },
        "max_crib_match": max_score,
        "verdict": verdict,
        "elapsed_seconds": round(elapsed, 1),
    }

    outpath = os.path.join(_ROOT, "results", "e_carter_tomb_deep_01.json")
    with open(outpath, "w") as f:
        json.dump(artifact, f, indent=2, default=str)

    print(f"\n  Artifact saved: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/running_key/e_carter_tomb_deep_01.py")


if __name__ == "__main__":
    main()
