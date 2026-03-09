#!/usr/bin/env python3
"""
Cipher:   Multi-layer (Vigenère / Beaufort + null removal + transposition)
Family:   team
Status:   active
Keyspace: ~15,000 configs
Last run: 2026-03-09
Best score: TBD

Test K2/K3 X-delimiter segment widths as K4 parameters.
K2 plaintext X positions yield segment widths [67,69,60,51,110,8].
K4 X positions [6,79] create segments [6,72,17].
38576 mod 97 = 67 (matches first K2 segment width).

Tests:
  A) K2 segment widths as Vigenère key (mod 26 → PRIZGI)
  B) K2 widths as null positions (accumulated mod 97)
  C) K4 between-X as real CT (positions 7-78 = 72 chars)
  D) X marks the dig — chars outside [6,79] are nulls
  E) K2 widths mod 97 as stepping intervals
  F) Segment widths as columnar transposition period
  G) Proportional null distribution across K4 X-segments

Scoring: crib substring check + quadgrams. Report qg/char > -9.5 or crib hit.
"""
from __future__ import annotations

import json
import math
import sys
import os
from collections import Counter
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD

# ── Constants ────────────────────────────────────────────────────────────────

K2_X_WIDTHS = [67, 69, 60, 51, 110, 8]
K4_X_POSITIONS = [6, 79]
K4_SEGMENTS = [6, 72, 17]  # chars before first X, between Xs, after last X

CT_NUMS = [ALPH_IDX[c] for c in CT]

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "DEFECTOR",
    "PARALLAX", "COLOPHON", "SHADOW",
]

CRIBS = [
    "EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "BERLIN",
    "CLOCK", "NORTHEAST", "SLOWLY", "INVISIBLE",
]

# ── Quadgram scorer ─────────────────────────────────────────────────────────

QUADGRAMS: Dict[str, float] = {}
QG_FLOOR: float = -12.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qg_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "english_quadgrams.json")
    qg_path = os.path.normpath(qg_path)
    with open(qg_path) as f:
        QUADGRAMS.update(json.load(f))
    if QUADGRAMS:
        QG_FLOOR = min(QUADGRAMS.values()) - 1.0

def quadgram_score(text: str) -> float:
    if len(text) < 4:
        return QG_FLOOR * max(len(text), 1)
    total = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
    return total / (len(text) - 3)

# ── Cipher operations ────────────────────────────────────────────────────────

def vig_decrypt(ct_nums: List[int], key_nums: List[int]) -> str:
    """Standard Vigenère: PT[i] = (CT[i] - KEY[i%len]) % 26"""
    klen = len(key_nums)
    return "".join(ALPH[(ct_nums[i] - key_nums[i % klen]) % MOD] for i in range(len(ct_nums)))

def beau_decrypt(ct_nums: List[int], key_nums: List[int]) -> str:
    """Beaufort: PT[i] = (KEY[i%len] - CT[i]) % 26"""
    klen = len(key_nums)
    return "".join(ALPH[(key_nums[i % klen] - ct_nums[i]) % MOD] for i in range(len(ct_nums)))

def varbeau_decrypt(ct_nums: List[int], key_nums: List[int]) -> str:
    """Variant Beaufort: PT[i] = (CT[i] + KEY[i%len]) % 26"""
    klen = len(key_nums)
    return "".join(ALPH[(ct_nums[i] + key_nums[i % klen]) % MOD] for i in range(len(ct_nums)))

def keyword_to_nums(kw: str) -> List[int]:
    return [ALPH_IDX[c] for c in kw.upper()]

def text_to_nums(text: str) -> List[int]:
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]

# ── Scoring ──────────────────────────────────────────────────────────────────

def check_cribs(pt: str) -> List[str]:
    """Return list of cribs found as substrings in pt."""
    found = []
    for crib in CRIBS:
        if crib in pt:
            found.append(crib)
    return found

def score_result(pt: str) -> Tuple[float, List[str]]:
    """Return (quadgram_per_char, list_of_cribs_found)."""
    cribs = check_cribs(pt)
    qg = quadgram_score(pt) if len(pt) >= 4 else -15.0
    return qg, cribs

REPORT_THRESHOLD = -9.5  # quadgram/char threshold for reporting

# ── Result tracking ──────────────────────────────────────────────────────────

results: List[Dict] = []
configs_tested = 0

def record(test_name: str, method: str, pt: str, detail: str = ""):
    global configs_tested
    configs_tested += 1
    qg, cribs = score_result(pt)
    if cribs or qg > REPORT_THRESHOLD:
        entry = {
            "test": test_name,
            "method": method,
            "plaintext": pt,
            "qg_per_char": round(qg, 4),
            "cribs_found": cribs,
            "detail": detail,
            "pt_len": len(pt),
        }
        results.append(entry)
        crib_str = f" CRIBS: {cribs}" if cribs else ""
        print(f"  *** HIT: {test_name} | {method} | qg={qg:.4f}{crib_str}")
        print(f"      PT: {pt[:80]}{'...' if len(pt)>80 else ''}")
        if detail:
            print(f"      Detail: {detail}")

# ═══════════════════════════════════════════════════════════════════════════
# TEST A: K2 segment widths as Vigenère key
# ═══════════════════════════════════════════════════════════════════════════

def test_a_widths_as_key():
    """K2 segment widths [67,69,60,51,110,8] mod 26 = [15,17,8,25,6,8] = PRIZGI."""
    print("\n=== TEST A: K2 widths mod 26 as direct cipher key ===")
    key_raw = [w % MOD for w in K2_X_WIDTHS]
    key_str = "".join(ALPH[k] for k in key_raw)
    print(f"  Key values: {key_raw} = {key_str}")

    count = 0
    # Direct application on full K4
    for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", varbeau_decrypt)]:
        pt = fn(CT_NUMS, key_raw)
        record("A-direct", f"{name}(key={key_str})", pt)
        count += 1

    # Different mod bases
    for mod_base in [97, 52, 13]:
        key_mod = [w % mod_base % MOD for w in K2_X_WIDTHS]
        key_s = "".join(ALPH[k] for k in key_mod)
        for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", varbeau_decrypt)]:
            pt = fn(CT_NUMS, key_mod)
            record("A-mod", f"{name}(key={key_s},mod{mod_base})", pt)
            count += 1

    # Reversed widths
    key_rev = [w % MOD for w in reversed(K2_X_WIDTHS)]
    key_rs = "".join(ALPH[k] for k in key_rev)
    for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", varbeau_decrypt)]:
        pt = fn(CT_NUMS, key_rev)
        record("A-rev", f"{name}(key={key_rs})", pt)
        count += 1

    # Differences between consecutive widths
    diffs = [(K2_X_WIDTHS[i+1] - K2_X_WIDTHS[i]) % MOD for i in range(len(K2_X_WIDTHS)-1)]
    diff_s = "".join(ALPH[d] for d in diffs)
    for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", varbeau_decrypt)]:
        pt = fn(CT_NUMS, diffs)
        record("A-diff", f"{name}(key={diff_s})", pt)
        count += 1

    # Cumulative widths mod 26
    cum = []
    s = 0
    for w in K2_X_WIDTHS:
        s += w
        cum.append(s % MOD)
    cum_s = "".join(ALPH[c] for c in cum)
    for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", varbeau_decrypt)]:
        pt = fn(CT_NUMS, cum)
        record("A-cum", f"{name}(key={cum_s})", pt)
        count += 1

    # Try PRIZGI combined with each keyword (width key XOR'd / added to keyword)
    for kw in KEYWORDS:
        kw_nums = keyword_to_nums(kw)
        # Repeat width key to keyword length, add mod 26
        combined = [(kw_nums[i] + key_raw[i % len(key_raw)]) % MOD for i in range(len(kw_nums))]
        comb_s = "".join(ALPH[c] for c in combined)
        for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
            pt = fn(CT_NUMS, combined)
            record("A-combined", f"{name}(key={key_str}+{kw}={comb_s})", pt)
            count += 1

    print(f"  Test A: {count} configs tested")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# TEST B: K2 widths as null positions
# ═══════════════════════════════════════════════════════════════════════════

def test_b_widths_as_null_positions():
    """Accumulated widths mod 97 as null position indices. Remove, decrypt remainder."""
    print("\n=== TEST B: K2 accumulated widths mod 97 as null positions ===")
    count = 0

    null_sets = []

    # Method 1: Simple accumulation mod 97
    acc = []
    s = 0
    for w in K2_X_WIDTHS:
        s += w
        acc.append(s % CT_LEN)
    null_sets.append(("accum-6", sorted(set(acc))))

    # Method 2: Each width mod 97 as a position
    raw_pos = sorted(set(w % CT_LEN for w in K2_X_WIDTHS))
    null_sets.append(("raw-direct", raw_pos))

    # Method 3: Step from 0 by each individual width until 24 positions
    for start_w in K2_X_WIDTHS:
        step_pos = []
        seen = set()
        pos = 0
        while len(step_pos) < 30 and pos not in seen:
            seen.add(pos)
            step_pos.append(pos)
            pos = (pos + start_w) % CT_LEN
        # Take first 24
        if len(step_pos) >= 24:
            null_sets.append((f"step-{start_w}-24", step_pos[:24]))
        if len(step_pos) >= 20:
            null_sets.append((f"step-{start_w}-all({len(step_pos)})", step_pos))

    # Method 4: Accumulate cyclically for 24 steps
    acc_cycle = []
    s = 0
    for i in range(24):
        s += K2_X_WIDTHS[i % len(K2_X_WIDTHS)]
        acc_cycle.append(s % CT_LEN)
    null_sets.append(("acc-cycle-24", sorted(set(acc_cycle))))

    # Method 5: Use accumulated widths, extend with width differences
    acc_ext = list(set(acc))
    # Fill remaining with stepping by gcd of widths
    from math import gcd
    from functools import reduce
    g = reduce(gcd, K2_X_WIDTHS)
    if g > 1:
        pos = 0
        while len(acc_ext) < 24:
            pos = (pos + g) % CT_LEN
            if pos not in set(acc_ext):
                acc_ext.append(pos)
    null_sets.append(("acc-ext-gcd", sorted(set(acc_ext[:24]))))

    for ns_name, null_pos in null_sets:
        null_set = set(null_pos)
        if len(null_set) < 2 or len(null_set) > 50:
            continue
        reduced = [CT_NUMS[i] for i in range(CT_LEN) if i not in null_set]
        if len(reduced) < 20:
            continue

        for kw in KEYWORDS:
            key = keyword_to_nums(kw)
            for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                pt = fn(reduced, key)
                record("B-null", f"{name}({kw}),nulls={ns_name}({len(null_set)})", pt,
                       f"nulls={sorted(null_set)[:15]}...")
                count += 1

    print(f"  Test B: {count} configs tested")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# TEST C: K4 between-X as real CT
# ═══════════════════════════════════════════════════════════════════════════

def test_c_between_x():
    """K4[7:79] = 72 chars between X at 6 and X at 79. Test as 73-char CT (off by 1)."""
    print("\n=== TEST C: Between-X extraction (72-74 chars) ===")
    count = 0

    extractions = [
        ("7-79", CT[7:79]),   # between X positions (exclusive both) — 72 chars
        ("6-80", CT[6:80]),   # inclusive both X positions — 74 chars
        ("6-79", CT[6:79]),   # inclusive start, exclusive end — 73 chars
        ("7-80", CT[7:80]),   # exclusive start, inclusive end — 73 chars
    ]

    for ex_name, extracted in extractions:
        ext_nums = text_to_nums(extracted)
        print(f"  Extraction [{ex_name}]: {len(extracted)} chars = {extracted[:50]}...")

        for kw in KEYWORDS:
            key = keyword_to_nums(kw)
            for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", varbeau_decrypt)]:
                pt = fn(ext_nums, key)
                record("C-betweenX", f"{name}({kw}),extract={ex_name}({len(extracted)}ch)", pt,
                       f"extracted={extracted[:40]}...")
                count += 1

    print(f"  Test C: {count} configs tested")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# TEST D: X marks the dig — boundary chars are nulls
# ═══════════════════════════════════════════════════════════════════════════

def test_d_boundary_nulls():
    """Positions 0-5 + 80-96 = 23 chars (close to 24). Remove outer, decrypt inner."""
    print("\n=== TEST D: X marks boundary — outside chars are nulls ===")
    count = 0

    boundaries = [
        ("0-5+80-96", list(range(0, 6)) + list(range(80, 97))),     # 23 nulls
        ("0-5+79-96", list(range(0, 6)) + list(range(79, 97))),     # 24 nulls
        ("0-6+80-96", list(range(0, 7)) + list(range(80, 97))),     # 24 nulls
        ("0-6+79-96", list(range(0, 7)) + list(range(79, 97))),     # 25 nulls
        ("0-5+81-96", list(range(0, 6)) + list(range(81, 97))),     # 22 nulls
        ("0-4+80-96", list(range(0, 5)) + list(range(80, 97))),     # 22 nulls
    ]

    for bname, null_pos in boundaries:
        null_set = set(null_pos)
        reduced = [CT_NUMS[i] for i in range(CT_LEN) if i not in null_set]
        rlen = len(reduced)
        reduced_text = "".join(ALPH[n] for n in reduced)
        print(f"  Boundary [{bname}]: {len(null_pos)} nulls removed, {rlen} chars remain")

        for kw in KEYWORDS:
            key = keyword_to_nums(kw)
            for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", varbeau_decrypt)]:
                pt = fn(reduced, key)
                record("D-boundary", f"{name}({kw}),boundary={bname}({rlen}ch)", pt,
                       f"{rlen} chars, nulls at {bname}")
                count += 1

    print(f"  Test D: {count} configs tested")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# TEST E: K2 widths mod 97 as stepping
# ═══════════════════════════════════════════════════════════════════════════

def test_e_stepping():
    """Step through K4 by each width mod 97. Visited = nulls OR reading order."""
    print("\n=== TEST E: K2 widths as stepping intervals ===")
    count = 0

    for step_val in K2_X_WIDTHS:
        step = step_val % CT_LEN
        if step == 0:
            continue

        # Generate positions visited by stepping
        visited = []
        pos = 0
        seen = set()
        while pos not in seen:
            seen.add(pos)
            visited.append(pos)
            pos = (pos + step) % CT_LEN

        print(f"  Step={step_val} (mod97={step}): visits {len(visited)} positions")

        # Interpretation 1: visited = reading order of real CT
        reading_order_ct = "".join(CT[p] for p in visited)
        ro_nums = text_to_nums(reading_order_ct)

        for kw in KEYWORDS:
            key = keyword_to_nums(kw)
            for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                pt = fn(ro_nums, key)
                record("E-step-read", f"{name}({kw}),step={step_val}mod97={step}", pt,
                       f"visited {len(visited)} pos, first 10: {visited[:10]}")
                count += 1

        # Interpretation 2: visited = nulls (if partial cycle)
        if len(visited) < CT_LEN:
            remainder_pos = [i for i in range(CT_LEN) if i not in seen]
            remainder = [CT_NUMS[i] for i in remainder_pos]
            if 20 <= len(remainder) <= 80:
                print(f"    Partial cycle: {len(visited)} visited, {len(remainder)} remain")
                for kw in KEYWORDS:
                    key = keyword_to_nums(kw)
                    for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                        pt = fn(remainder, key)
                        record("E-step-null", f"{name}({kw}),step={step_val},rem={len(remainder)}", pt)
                        count += 1

    # Combined stepping: alternate between two width values
    for i in range(len(K2_X_WIDTHS)):
        for j in range(i + 1, len(K2_X_WIDTHS)):
            w1, w2 = K2_X_WIDTHS[i], K2_X_WIDTHS[j]
            visited = []
            pos = 0
            seen = set()
            toggle = True
            while len(visited) < CT_LEN:
                if pos in seen:
                    # Find next unvisited
                    found = False
                    for p in range(CT_LEN):
                        if p not in seen:
                            pos = p
                            found = True
                            break
                    if not found:
                        break
                seen.add(pos)
                visited.append(pos)
                step = (w1 if toggle else w2) % CT_LEN
                toggle = not toggle
                pos = (pos + step) % CT_LEN

            if len(visited) == CT_LEN:
                reordered = "".join(CT[p] for p in visited)
                ro_nums = text_to_nums(reordered)
                for kw in KEYWORDS[:4]:  # Limit to keep runtime manageable
                    key = keyword_to_nums(kw)
                    for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                        pt = fn(ro_nums, key)
                        record("E-alt-step", f"{name}({kw}),alt={w1}/{w2}", pt)
                        count += 1

    print(f"  Test E: {count} configs tested")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# TEST F: Segment widths as columnar transposition period
# ═══════════════════════════════════════════════════════════════════════════

def test_f_columnar():
    """Columnar transposition with period = each width value, then decrypt."""
    print("\n=== TEST F: Segment widths as columnar transposition period ===")
    count = 0

    periods = sorted(set([8, 51, 60, 67, 69] +       # K2 widths (110 > 97, skip)
                         [6, 17, 72] +                  # K4 segment lengths
                         [24, 73]))                     # 24 nulls, 73-char hypothesis

    for period in periods:
        if period < 2 or period > 96:
            continue

        # --- Fill by rows, read by columns ---
        ncols = period
        nrows = math.ceil(CT_LEN / ncols)
        # Pad with sentinel
        padded = list(CT) + ['?'] * (nrows * ncols - CT_LEN)

        grid = []
        for r in range(nrows):
            grid.append(padded[r * ncols:(r + 1) * ncols])

        col_read = ""
        for c in range(ncols):
            for r in range(nrows):
                ch = grid[r][c]
                if ch != '?':
                    col_read += ch

        col_nums = text_to_nums(col_read)

        for kw in KEYWORDS:
            key = keyword_to_nums(kw)
            for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                pt = fn(col_nums, key)
                record("F-colTrans", f"{name}({kw}),period={period}", pt,
                       f"fill rows read cols, {nrows}x{ncols}")
                count += 1

        # --- Fill by columns, read by rows ---
        nrows2 = period
        ncols2 = math.ceil(CT_LEN / nrows2)
        grid2 = [['?'] * ncols2 for _ in range(nrows2)]
        idx = 0
        for c in range(ncols2):
            for r in range(nrows2):
                if idx < CT_LEN:
                    grid2[r][c] = CT[idx]
                    idx += 1

        row_read = ""
        for r in range(nrows2):
            for c in range(ncols2):
                ch = grid2[r][c]
                if ch != '?':
                    row_read += ch

        row_nums = text_to_nums(row_read)

        for kw in KEYWORDS:
            key = keyword_to_nums(kw)
            for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                pt = fn(row_nums, key)
                record("F-colTrans-rev", f"{name}({kw}),period={period},rev", pt,
                       f"fill cols read rows, {nrows2}x{ncols2}")
                count += 1

    print(f"  Test F: {count} configs tested")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# TEST G: K4 segments + K2 widths for proportional null removal
# ═══════════════════════════════════════════════════════════════════════════

def test_g_proportional_nulls():
    """K4 has 3 segments [6,72,17]. Distribute 24 nulls proportionally or by K2 widths."""
    print("\n=== TEST G: Proportional null removal per segment ===")
    count = 0

    seg_bounds = [
        (0, 6),     # before first X (6 chars)
        (7, 79),    # between Xs exclusive (72 chars)
        (80, 97),   # after last X (17 chars)
    ]

    null_distributions = []

    # Proportional to segment length
    total = sum(K4_SEGMENTS)
    prop = [round(24 * s / total) for s in K4_SEGMENTS]
    while sum(prop) > 24:
        prop[prop.index(max(prop))] -= 1
    while sum(prop) < 24:
        prop[prop.index(min(prop))] += 1
    null_distributions.append(("proportional", prop))

    # Various fixed distributions
    null_distributions.extend([
        ("even-8each", [8, 8, 8]),
        ("all-inner", [0, 24, 0]),
        ("all-outer", [6, 11, 7]),       # 6+7 outer = 13, 11 inner
        ("6-12-6", [6, 12, 6]),
        ("0-17-7", [0, 17, 7]),
        ("6-17-1", [6, 17, 1]),
        ("6-1-17", [6, 1, 17]),          # outer = all null
        ("1-18-5", [1, 18, 5]),          # 73-char: keep 5+54+14
        ("3-18-3", [3, 18, 3]),
        ("6-0-17", [6, 0, 17]),          # outer = all null, inner intact
        ("0-7-17", [0, 7, 17]),          # only inner+right nulls
        ("5-14-5", [5, 14, 5]),
        ("2-20-2", [2, 20, 2]),
        ("4-16-4", [4, 16, 4]),
    ])

    for dist_name, null_per_seg in null_distributions:
        if sum(null_per_seg) != 24:
            continue
        valid = True
        for i, (start, end) in enumerate(seg_bounds):
            seg_len = end - start
            if null_per_seg[i] < 0 or null_per_seg[i] > seg_len:
                valid = False
                break
        if not valid:
            continue

        for removal_strategy in ["first", "last", "even"]:
            null_positions = set()
            for i, (start, end) in enumerate(seg_bounds):
                seg_len = end - start
                n_remove = null_per_seg[i]
                seg_indices = list(range(start, end))

                if removal_strategy == "first":
                    for j in range(min(n_remove, len(seg_indices))):
                        null_positions.add(seg_indices[j])
                elif removal_strategy == "last":
                    for j in range(min(n_remove, len(seg_indices))):
                        null_positions.add(seg_indices[-(j + 1)])
                elif removal_strategy == "even":
                    if n_remove > 0 and seg_len > 0:
                        step = seg_len / n_remove
                        for j in range(n_remove):
                            idx = int(j * step) + start
                            if idx < end:
                                null_positions.add(idx)

            reduced = [CT_NUMS[i] for i in range(CT_LEN) if i not in null_positions]
            rlen = len(reduced)

            for kw in KEYWORDS:
                key = keyword_to_nums(kw)
                for cname, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                    pt = fn(reduced, key)
                    record("G-propNull",
                           f"{cname}({kw}),dist={dist_name},rm={removal_strategy}",
                           pt, f"{rlen} chars, dist={null_per_seg}")
                    count += 1

    print(f"  Test G: {count} configs tested")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# TEST H (bonus): 38576 mod 97 = 67 coincidence
# ═══════════════════════════════════════════════════════════════════════════

def test_h_coordinate_key():
    """Test 38576 mod 97 = 67 and coordinate-derived keys."""
    print("\n=== TEST H: 38576 mod 97 = 67 + coordinate-derived keys ===")
    count = 0

    coord_values = [
        ("38576", [3, 8, 5, 7, 6]),
        ("38576mod97=67", [67 % MOD]),
        ("38-57-6.5", [38 % MOD, 57 % MOD, 6, 5]),
        ("77-8-44", [77 % MOD, 8, 44 % MOD]),
        ("K2coords-7", [38 % MOD, 57 % MOD, 6 % MOD, 5 % MOD, 77 % MOD, 8 % MOD, 44 % MOD]),
        ("K2diff-3", [(77-38) % MOD, (57-8) % MOD, (44-6) % MOD]),
        ("67split", [6, 7]),
    ]

    for vname, key_vals in coord_values:
        if not key_vals:
            continue
        for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", varbeau_decrypt)]:
            pt = fn(CT_NUMS, key_vals)
            record("H-coord", f"{name}(key={vname})", pt)
            count += 1

    # 38576 mod 97 = 67 → step by 67 (since gcd(67,97)=1, full cycle)
    step = 67
    visited = []
    pos = 0
    seen = set()
    while pos not in seen:
        seen.add(pos)
        visited.append(pos)
        pos = (pos + step) % CT_LEN

    reordered = "".join(CT[p] for p in visited)
    ro_nums = text_to_nums(reordered)
    print(f"  Step=67: visits {len(visited)} positions (full cycle since gcd(67,97)=1)")
    print(f"  Reordered CT: {reordered[:50]}...")

    for kw in KEYWORDS:
        key = keyword_to_nums(kw)
        for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
            pt = fn(ro_nums, key)
            record("H-step67", f"{name}({kw}),step=67", pt)
            count += 1

    # Also: step by 30 (97-67=30)
    step2 = 30
    visited2 = []
    pos = 0
    seen2 = set()
    while pos not in seen2:
        seen2.add(pos)
        visited2.append(pos)
        pos = (pos + step2) % CT_LEN

    reordered2 = "".join(CT[p] for p in visited2)
    ro_nums2 = text_to_nums(reordered2)
    for kw in KEYWORDS:
        key = keyword_to_nums(kw)
        for name, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
            pt = fn(ro_nums2, key)
            record("H-step30", f"{name}({kw}),step=30(97-67)", pt)
            count += 1

    print(f"  Test H: {count} configs tested")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 72)
    print("E-X-DELIMITER-WIDTHS: K2/K3 X-delimiter widths as K4 parameters")
    print("=" * 72)
    print(f"K4 CT ({CT_LEN} chars): {CT}")
    print(f"K2 X-segment widths: {K2_X_WIDTHS}")
    print(f"K4 X positions: {K4_X_POSITIONS}")
    print(f"K4 segments: {K4_SEGMENTS}")
    print(f"Keywords: {KEYWORDS}")
    print(f"38576 mod 97 = {38576 % 97}")

    load_quadgrams()
    print(f"Loaded {len(QUADGRAMS)} quadgrams (floor={QG_FLOOR:.2f})")

    total = 0
    total += test_a_widths_as_key()
    total += test_b_widths_as_null_positions()
    total += test_c_between_x()
    total += test_d_boundary_nulls()
    total += test_e_stepping()
    total += test_f_columnar()
    total += test_g_proportional_nulls()
    total += test_h_coordinate_key()

    print("\n" + "=" * 72)
    print(f"TOTAL: {total} configs tested, {len(results)} results above threshold")
    print("=" * 72)

    if results:
        print("\n--- ALL RESULTS (sorted by qg/char descending) ---")
        results.sort(key=lambda r: r["qg_per_char"], reverse=True)
        for i, r in enumerate(results):
            crib_str = f" | CRIBS: {r['cribs_found']}" if r["cribs_found"] else ""
            print(f"  [{i+1:3d}] qg={r['qg_per_char']:.4f} | {r['test']} | {r['method']}{crib_str}")
            print(f"        PT({r['pt_len']}): {r['plaintext'][:90]}")
            if r.get("detail"):
                print(f"        {r['detail']}")
    else:
        print("\nNo results above threshold (qg > -9.5 or crib found)")

    # Save results
    out_dir = os.path.join(os.path.dirname(__file__), "..", "..", "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "e_x_delimiter_widths.json")
    with open(out_path, "w") as f:
        json.dump({
            "total_configs": total,
            "hits": len(results),
            "threshold": REPORT_THRESHOLD,
            "results": results,
        }, f, indent=2)
    print(f"\nResults saved to {out_path}")

if __name__ == "__main__":
    main()
