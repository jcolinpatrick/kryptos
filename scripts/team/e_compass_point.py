#!/usr/bin/env python3
"""
Cipher: Compass point / W-delimiter / ENE bearing / directional grid reading
Family: team
Status: active
Keyspace: ~15000 configs
Last run: 2026-03-09
Best score:
"""
"""E-COMPASS-POINT: Test the compass-point interpretation of POINT from K2 plaintext.

The lodestone on Kryptos points ENE (East-Northeast) = EASTNORTHEAST crib.
K2 plaintext contains "POINT" — could be a compass direction reference.
73-char hypothesis: 24 of 97 chars are nulls, leaving 73 real CT chars.
W positions in K4: [20, 36, 48, 58, 74] — may be compass/period markers.

Tests:
  A) W-as-compass-point: W positions as directional markers. Remove W's,
     decrypt with keywords via Vigenere/Beaufort.
  B) ENE bearing as key: Use compass bearing 67.5 deg (ENE) to derive null
     positions via modular arithmetic.
  C) Directional grid reading: Arrange K4 in grid widths 7-14, read in 8
     compass directions (N-S, S-N, E-W, W-E, NE-SW, NW-SE, SE-NW, SW-NE).
     Decrypt each reading with top keywords.
  D) Combined model: W positions (5 nulls) + 19 more from ENE-derived
     positions to get 24 total nulls. Decrypt remaining 73 chars.
"""
import sys
import os
import json
import math
from pathlib import Path
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, N_CRIBS,
)

# ── Quadgram scorer ──────────────────────────────────────────────────────

QG_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "english_quadgrams.json"


def load_quadgrams():
    with open(QG_PATH) as f:
        data = json.load(f)
    if isinstance(data, dict) and "logp" in data:
        data = data["logp"]
    floor = min(data.values())
    return data, floor


QUADGRAMS, QG_FLOOR = load_quadgrams()


def qg_score(text):
    """Quadgram log-probability score per character."""
    text = text.upper()
    n = len(text)
    if n < 4:
        return QG_FLOOR
    total = sum(QUADGRAMS.get(text[i:i + 4], QG_FLOOR) for i in range(n - 3))
    return total / (n - 3)


# ── Cipher operations ────────────────────────────────────────────────────

def vig_dec(ct_text, key_nums):
    """Vigenere decrypt: PT[i] = (CT[i] - KEY[i%len]) mod 26."""
    klen = len(key_nums)
    return "".join(
        chr(((ord(c) - 65) - key_nums[i % klen]) % 26 + 65)
        for i, c in enumerate(ct_text)
    )


def beau_dec(ct_text, key_nums):
    """Beaufort decrypt: PT[i] = (KEY[i%len] - CT[i]) mod 26."""
    klen = len(key_nums)
    return "".join(
        chr((key_nums[i % klen] - (ord(c) - 65)) % 26 + 65)
        for i, c in enumerate(ct_text)
    )


def text_to_key(word):
    """Convert text to numeric key (A=0 .. Z=25)."""
    return [ord(c) - 65 for c in word.upper()]


def ic(text):
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text.upper())
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


# ── Helpers ──────────────────────────────────────────────────────────────

W_POSITIONS = [i for i, c in enumerate(CT) if c == "W"]
# Expected: [20, 36, 48, 58, 74]

CT_NO_W = "".join(c for c in CT if c != "W")
# 92 chars with W removed

# Segment lengths between W's
SEGMENT_BOUNDARIES = []
prev = 0
for wp in W_POSITIONS:
    SEGMENT_BOUNDARIES.append((prev, wp))
    prev = wp + 1
SEGMENT_BOUNDARIES.append((prev, CT_LEN))
SEGMENT_LENGTHS = [b - a for a, b in SEGMENT_BOUNDARIES]

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "DEFECTOR",
    "PARALLAX", "COLOPHON", "SHADOW", "ENE", "EASTNORTHEAST",
    "NORTH", "EAST", "SOUTH", "WEST",
]

CRIB_FRAGMENTS = ["EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH",
                   "BERLIN", "CLOCK", "THE"]


def check_cribs(pt):
    """Check for crib substrings in plaintext. Returns list of hits."""
    hits = []
    for crib in CRIB_FRAGMENTS:
        idx = pt.find(crib)
        if idx >= 0:
            hits.append(f"{crib}@{idx}")
    return hits


# ── Results collection ───────────────────────────────────────────────────

results = []  # (qg_per_char, method, plaintext, ic_val, crib_hits)
configs_tested = 0
QG_NOISE_THRESHOLD = -9.5


def record(method, pt):
    global configs_tested
    configs_tested += 1
    if len(pt) < 4:
        return
    qg = qg_score(pt)
    ic_val = ic(pt)
    cribs = check_cribs(pt)
    # Always record if crib hit or above noise threshold
    if cribs or qg > QG_NOISE_THRESHOLD:
        results.append((qg, method, pt, ic_val, cribs))
        if cribs:
            print(f"  *** CRIB HIT: {method} | {', '.join(cribs)} | "
                  f"QG={qg:.4f} | {pt[:60]}", flush=True)


def decrypt_both(ct_text, key_nums, method_prefix):
    """Decrypt with both Vigenere and Beaufort, record results."""
    record(f"{method_prefix}|Vig", vig_dec(ct_text, key_nums))
    record(f"{method_prefix}|Beau", beau_dec(ct_text, key_nums))


# ══════════════════════════════════════════════════════════════════════════
# TEST A: W-as-compass-point
# ══════════════════════════════════════════════════════════════════════════

def test_a():
    print("=" * 78)
    print("TEST A: W-as-compass-point — treat W positions as directional markers")
    print("=" * 78)
    print(f"W positions in K4: {W_POSITIONS}")
    print(f"Segment lengths (between W's): {SEGMENT_LENGTHS}")
    print(f"CT without W's ({len(CT_NO_W)} chars): {CT_NO_W}")
    print(flush=True)

    start_count = configs_tested

    # A1: Remove W's, decrypt remaining 92 chars with each keyword
    print("A1) Remove W's (5 nulls), decrypt 92 chars with keywords")
    for kw in KEYWORDS:
        key = text_to_key(kw)
        decrypt_both(CT_NO_W, key, f"A1-noW-{kw}")

    # A2: Decrypt full 97-char CT with keywords (baseline comparison)
    print("A2) Full CT decrypt with keywords (baseline)")
    for kw in KEYWORDS:
        key = text_to_key(kw)
        decrypt_both(CT, key, f"A2-full-{kw}")

    # A3: Segment lengths as key
    seg_key = SEGMENT_LENGTHS  # [20, 15, 11, 9, 15, 22]
    seg_key_txt = "".join(chr(s % 26 + 65) for s in seg_key)
    print(f"A3) Segment lengths as key: {SEGMENT_LENGTHS} -> {seg_key_txt}")
    decrypt_both(CT, seg_key, "A3-seglen-full")
    decrypt_both(CT_NO_W, seg_key, "A3-seglen-noW")

    # A4: W-delimited telegram — decrypt each segment independently with key reset
    print("A4) W-delimited telegram: decrypt each segment independently")
    segments = [CT[a:b] for a, b in SEGMENT_BOUNDARIES]
    for kw in KEYWORDS:
        key = text_to_key(kw)
        decoded_segs = []
        for seg in segments:
            if seg:
                decoded_segs.append(vig_dec(seg, key))
        full_pt = "W".join(decoded_segs)
        record(f"A4-telegram-Vig-{kw}", full_pt)
        decoded_segs_b = []
        for seg in segments:
            if seg:
                decoded_segs_b.append(beau_dec(seg, key))
        full_pt_b = "W".join(decoded_segs_b)
        record(f"A4-telegram-Beau-{kw}", full_pt_b)

    # A5: W positions mod 26 as key
    wpos_key = [p % 26 for p in W_POSITIONS]
    wpos_txt = "".join(chr(k + 65) for k in wpos_key)
    print(f"A5) W positions as key: {W_POSITIONS} -> {wpos_txt}")
    decrypt_both(CT, wpos_key, "A5-wposkey-full")
    decrypt_both(CT_NO_W, wpos_key, "A5-wposkey-noW")

    # A6: W-to-W diffs as key
    w_diffs = [W_POSITIONS[i + 1] - W_POSITIONS[i] for i in range(len(W_POSITIONS) - 1)]
    diff_txt = "".join(chr(d % 26 + 65) for d in w_diffs)
    print(f"A6) W-to-W diffs as key: {w_diffs} -> {diff_txt}")
    decrypt_both(CT, w_diffs, "A6-wdiffs-full")
    decrypt_both(CT_NO_W, w_diffs, "A6-wdiffs-noW")

    print(f"  Test A complete: {configs_tested - start_count} configs\n", flush=True)


# ══════════════════════════════════════════════════════════════════════════
# TEST B: ENE bearing as key
# ══════════════════════════════════════════════════════════════════════════

def test_b():
    print("=" * 78)
    print("TEST B: ENE bearing (67.5 deg) as key to derive null positions")
    print("=" * 78, flush=True)

    start_count = configs_tested

    # B1: Every ceil(67.5/n)-th position is null
    print("B1) Periodic null removal: every ceil(67.5/n)-th position")
    for n in range(1, 20):
        period = math.ceil(67.5 / n)
        if period < 2 or period > 50:
            continue
        for offset in range(min(period, 5)):
            null_pos = [i for i in range(CT_LEN) if (i - offset) % period == 0]
            n_nulls = len(null_pos)
            if n_nulls < 3 or n_nulls > 40:
                continue
            remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(null_pos))
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "DEFECTOR"]:
                key = text_to_key(kw)
                decrypt_both(remaining, key,
                             f"B1-p{period}o{offset}-n{n_nulls}-{kw}")

    # B2: Positions where (i*67 + offset) % 97 < 24 are nulls (gets exactly 24)
    print("B2) (i*67+offset) mod 97 < 24 -> null positions")
    for offset in range(97):
        null_pos = [i for i in range(CT_LEN) if (i * 67 + offset) % 97 < 24]
        # Since gcd(67,97)=1, this always gives exactly 24 nulls
        if len(null_pos) != 24:
            continue
        remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(null_pos))
        assert len(remaining) == 73
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "DEFECTOR",
                    "PARALLAX", "COLOPHON"]:
            key = text_to_key(kw)
            decrypt_both(remaining, key,
                         f"B2-67x+{offset}mod97-{kw}")

    # B3: Positions where (i*68 + offset) % 97 < 24 (68 = round(67.5))
    print("B3) (i*68+offset) mod 97 < 24 -> null positions")
    for offset in range(97):
        null_pos = [i for i in range(CT_LEN) if (i * 68 + offset) % 97 < 24]
        if len(null_pos) != 24:
            continue
        remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(null_pos))
        if len(remaining) != 73:
            continue
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "DEFECTOR",
                    "PARALLAX", "COLOPHON"]:
            key = text_to_key(kw)
            decrypt_both(remaining, key,
                         f"B3-68x+{offset}mod97-{kw}")

    # B4: ENE bearing digits as key: 6, 7, 5 or 67, 5
    print("B4) ENE bearing digits as key")
    bearing_keys = {
        "675": [6, 7, 5],
        "67-5": [67 % 26, 5],  # 67%26=15=P, 5=F -> PF
        "ENE": text_to_key("ENE"),
        "EASTNORTHEAST": text_to_key("EASTNORTHEAST"),
        "POINT": text_to_key("POINT"),
        "compass-3": [3],       # ENE = point 3 on 16-pt compass
        "compass-5": [5],       # ENE = point 5 on 32-pt compass
        "compass-6": [6],       # ENE = point 6 on 32-pt (some systems)
        "bearing-P": [15],      # 67%26=15=P
    }
    for bname, bkey in bearing_keys.items():
        decrypt_both(CT, bkey, f"B4-{bname}-full")
        decrypt_both(CT_NO_W, bkey, f"B4-{bname}-noW")

    # B5: Double decrypt: bearing key then keyword
    print("B5) Double decrypt: bearing key then keyword")
    for bname in ["ENE", "POINT", "675"]:
        bkey = bearing_keys[bname]
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX"]:
            kw_key = text_to_key(kw)
            # bearing first, then keyword
            pt1 = vig_dec(CT, bkey)
            record(f"B5-{bname}+{kw}|Vig+Vig", vig_dec(pt1, kw_key))
            record(f"B5-{bname}+{kw}|Vig+Beau", beau_dec(pt1, kw_key))
            pt1b = beau_dec(CT, bkey)
            record(f"B5-{bname}+{kw}|Beau+Vig", vig_dec(pt1b, kw_key))
            record(f"B5-{bname}+{kw}|Beau+Beau", beau_dec(pt1b, kw_key))
            # keyword first, then bearing
            pt2 = vig_dec(CT, kw_key)
            record(f"B5-{kw}+{bname}|Vig+Vig", vig_dec(pt2, bkey))
            record(f"B5-{kw}+{bname}|Vig+Beau", beau_dec(pt2, bkey))

    print(f"  Test B complete: {configs_tested - start_count} configs\n", flush=True)


# ══════════════════════════════════════════════════════════════════════════
# TEST C: Directional grid reading
# ══════════════════════════════════════════════════════════════════════════

def test_c():
    print("=" * 78)
    print("TEST C: Directional grid reading — arrange K4 in grids, read in 8 directions")
    print("=" * 78, flush=True)

    start_count = configs_tested

    TOP_KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "DEFECTOR",
                    "PARALLAX", "COLOPHON", "SHADOW"]

    for width in range(7, 15):  # grid widths 7..14
        height = math.ceil(CT_LEN / width)
        # Build grid: row-major, pad with None
        grid = []
        for r in range(height):
            row = []
            for c in range(width):
                pos = r * width + c
                if pos < CT_LEN:
                    row.append(CT[pos])
                else:
                    row.append(None)
            grid.append(row)

        readings = {}

        # E->W (normal row reading = original CT, skip)
        # W->E: each row reversed
        we = ""
        for r in range(height):
            for c in range(width - 1, -1, -1):
                if grid[r][c] is not None:
                    we += grid[r][c]
        readings[f"W{width}-WE"] = we

        # N->S: columns top to bottom
        ns = ""
        for c in range(width):
            for r in range(height):
                if grid[r][c] is not None:
                    ns += grid[r][c]
        readings[f"W{width}-NS"] = ns

        # S->N: columns bottom to top
        sn = ""
        for c in range(width):
            for r in range(height - 1, -1, -1):
                if grid[r][c] is not None:
                    sn += grid[r][c]
        readings[f"W{width}-SN"] = sn

        # NE->SW: upper-left to lower-right diagonals
        ne_sw = ""
        for diag in range(height + width - 1):
            for r in range(height):
                c = diag - r
                if 0 <= c < width and grid[r][c] is not None:
                    ne_sw += grid[r][c]
        readings[f"W{width}-NESW"] = ne_sw

        # NW->SE: upper-right to lower-left diagonals
        nw_se = ""
        for diag in range(-(height - 1), width):
            for r in range(height):
                c = r + diag
                if 0 <= c < width and grid[r][c] is not None:
                    nw_se += grid[r][c]
        readings[f"W{width}-NWSE"] = nw_se

        # SE->NW: reverse of NW->SE
        readings[f"W{width}-SENW"] = nw_se[::-1]

        # SW->NE: reverse of NE->SW
        readings[f"W{width}-SWNE"] = ne_sw[::-1]

        # Serpentine (boustrophedon)
        serp = ""
        for r in range(height):
            if r % 2 == 0:
                for c in range(width):
                    if grid[r][c] is not None:
                        serp += grid[r][c]
            else:
                for c in range(width - 1, -1, -1):
                    if grid[r][c] is not None:
                        serp += grid[r][c]
        readings[f"W{width}-serp"] = serp

        # Column serpentine
        col_serp = ""
        for c in range(width):
            if c % 2 == 0:
                for r in range(height):
                    if grid[r][c] is not None:
                        col_serp += grid[r][c]
            else:
                for r in range(height - 1, -1, -1):
                    if grid[r][c] is not None:
                        col_serp += grid[r][c]
        readings[f"W{width}-colserp"] = col_serp

        # Decrypt each reading with top keywords
        for rname, rtext in readings.items():
            if rtext == CT:  # skip if identical to original
                continue
            if len(rtext) < 10:
                continue
            for kw in TOP_KEYWORDS:
                key = text_to_key(kw)
                decrypt_both(rtext, key, f"C-{rname}-{kw}")

    # Also test the 28x31 grid specific to Kryptos (K4 rows 24-27)
    print("C-special: 28x31 Kryptos grid, K4 rows only")
    K4_GRID = {}
    # Row 24: 4 chars at cols 27-30
    for i in range(4):
        K4_GRID[(24, 27 + i)] = CT[i]
    # Rows 25-27: full rows
    for r in range(25, 28):
        for c in range(31):
            pos = 4 + (r - 25) * 31 + c
            if pos < CT_LEN:
                K4_GRID[(r, c)] = CT[pos]

    # Column reading TB
    col_tb = ""
    for c in range(31):
        for r in [24, 25, 26, 27]:
            if (r, c) in K4_GRID:
                col_tb += K4_GRID[(r, c)]
    # Column reading BT
    col_bt = ""
    for c in range(31):
        for r in [27, 26, 25, 24]:
            if (r, c) in K4_GRID:
                col_bt += K4_GRID[(r, c)]

    for reading, label in [(col_tb, "28x31-colTB"), (col_bt, "28x31-colBT")]:
        for kw in TOP_KEYWORDS:
            key = text_to_key(kw)
            decrypt_both(reading, key, f"C-{label}-{kw}")

    # Reversed CT
    ct_rev = CT[::-1]
    for kw in TOP_KEYWORDS:
        key = text_to_key(kw)
        decrypt_both(ct_rev, key, f"C-reversed-{kw}")

    print(f"  Test C complete: {configs_tested - start_count} configs\n", flush=True)


# ══════════════════════════════════════════════════════════════════════════
# TEST D: Combined model — W nulls + ENE-derived nulls = 24 total
# ══════════════════════════════════════════════════════════════════════════

def test_d():
    print("=" * 78)
    print("TEST D: Combined model — W positions (5 nulls) + 19 ENE-derived = 24 total")
    print("=" * 78, flush=True)

    start_count = configs_tested
    w_set = set(W_POSITIONS)
    non_w_positions = [i for i in range(CT_LEN) if i not in w_set]

    TOP_KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "DEFECTOR",
                    "PARALLAX", "COLOPHON"]

    # D1: (i*67 + offset) % 97 selects 19 additional nulls from non-W positions
    print("D1) W nulls + (i*67+off)%97 derived additional 19 nulls")
    for multiplier in [67, 68]:
        for offset in range(97):
            # Positions where mapping falls below threshold
            ene_null_candidates = []
            for i in non_w_positions:
                val = (i * multiplier + offset) % 97
                if val < 24:
                    ene_null_candidates.append(i)
            # We need exactly 19 more to reach 24 total
            if len(ene_null_candidates) != 19:
                continue
            all_nulls = sorted(w_set | set(ene_null_candidates))
            assert len(all_nulls) == 24
            remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(all_nulls))
            assert len(remaining) == 73
            for kw in TOP_KEYWORDS:
                key = text_to_key(kw)
                decrypt_both(remaining, key,
                             f"D1-{multiplier}x+{offset}-{kw}")

    # D2: Every n-th non-W position is null (to get 19 more)
    print("D2) W nulls + periodic selection of 19 from non-W positions")
    # 92 non-W positions, need 19 nulls -> period ~4.8
    for period in range(3, 10):
        for offset in range(period):
            extra = [non_w_positions[j] for j in range(offset, len(non_w_positions), period)]
            if len(extra) < 15 or len(extra) > 25:
                continue
            # Trim or extend to exactly 19
            if len(extra) >= 19:
                extra = extra[:19]
            else:
                continue
            all_nulls = sorted(w_set | set(extra))
            if len(all_nulls) != 24:
                continue
            remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(all_nulls))
            if len(remaining) != 73:
                continue
            for kw in TOP_KEYWORDS:
                key = text_to_key(kw)
                decrypt_both(remaining, key,
                             f"D2-p{period}o{offset}-{kw}")

    # D3: Compass bearing 67.5 -> take positions where i % 5 == k for each k
    # (5 W's suggests mod-5 structure)
    print("D3) W nulls + mod-based selection from non-W")
    for modulus in [3, 4, 5, 6, 7, 8]:
        for residue in range(modulus):
            extra = [p for p in non_w_positions if p % modulus == residue]
            if abs(len(extra) - 19) > 3:
                continue
            extra = extra[:19]
            if len(extra) < 19:
                continue
            all_nulls = sorted(w_set | set(extra))
            if len(all_nulls) != 24:
                continue
            remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(all_nulls))
            if len(remaining) != 73:
                continue
            for kw in TOP_KEYWORDS:
                key = text_to_key(kw)
                decrypt_both(remaining, key,
                             f"D3-mod{modulus}r{residue}-{kw}")

    # D4: Letter-frequency based null selection
    # Positions with rare letters in CT more likely to be nulls
    print("D4) W nulls + rare-letter positions as additional nulls")
    # English letter frequencies (approx), rarest last
    eng_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
        'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
        'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
        'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
        'Q': 0.10, 'Z': 0.07,
    }
    # Score each non-W position by letter rarity (lower freq = more likely null)
    scored_positions = [(eng_freq.get(CT[i], 0.1), i) for i in non_w_positions]
    scored_positions.sort()  # rarest first

    # Take the 19 rarest-letter positions as nulls
    extra_19_rare = [p for _, p in scored_positions[:19]]
    all_nulls = sorted(w_set | set(extra_19_rare))
    if len(all_nulls) == 24:
        remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(all_nulls))
        print(f"  D4 rare-letter nulls: positions {sorted(extra_19_rare)}")
        print(f"  Remaining ({len(remaining)} chars): {remaining[:50]}...")
        for kw in TOP_KEYWORDS:
            key = text_to_key(kw)
            decrypt_both(remaining, key, f"D4-rareletters-{kw}")

    # D5: Positions where CT letter matches ENE-key-derived expectation = NOT null
    # (positions that don't match = null)
    print("D5) ENE key match/mismatch based null selection")
    ene_key = text_to_key("EASTNORTHEAST")  # 13-char key
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        kw_key = text_to_key(kw)
        # Compute expected CT if kw encrypts to CT via Vig
        # Expected PT[i] = Vig_dec(CT[i], kw_key)
        # If PT matches ENE pattern at crib positions, position is "real"
        # Here we use a simpler heuristic: positions where
        # Vig_dec(CT[i], kw_key[i%klen]) produces a high-frequency letter = real
        pt_full = vig_dec(CT, kw_key)
        # Score each non-W position
        scored = [(eng_freq.get(pt_full[i], 0.1), i) for i in non_w_positions]
        scored.sort()  # rarest first = most likely null
        extra = [p for _, p in scored[:19]]
        all_nulls_d5 = sorted(w_set | set(extra))
        if len(all_nulls_d5) == 24:
            rem = "".join(CT[i] for i in range(CT_LEN) if i not in set(all_nulls_d5))
            if len(rem) == 73:
                for kw2 in TOP_KEYWORDS:
                    key2 = text_to_key(kw2)
                    decrypt_both(rem, key2, f"D5-{kw}-rare19-{kw2}")

    # D6: Weltzeituhr-inspired: 24 positions at regular intervals (24 facets of clock)
    print("D6) Weltzeituhr 24-facet: 24 evenly-spaced null positions")
    # 97/24 ~ 4.04, so roughly every 4th position
    for offset in range(4):
        null_pos = []
        for f in range(24):
            pos = int(round(offset + f * (97.0 / 24.0))) % 97
            null_pos.append(pos)
        null_pos = sorted(set(null_pos))
        if len(null_pos) != 24:
            continue
        remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(null_pos))
        if len(remaining) != 73:
            continue
        for kw in TOP_KEYWORDS:
            key = text_to_key(kw)
            decrypt_both(remaining, key, f"D6-weltz-off{offset}-{kw}")

    # D7: Combined W-nulls check: do W's plus first/last n positions yield 24?
    print("D7) W nulls + boundary positions")
    # Try adding positions from start and end
    for n_start in range(0, 20):
        for n_end in range(0, 20):
            if n_start + n_end != 19:
                continue
            extra = list(range(n_start)) + list(range(CT_LEN - n_end, CT_LEN))
            # Remove any that overlap with W positions
            extra = [p for p in extra if p not in w_set]
            if len(extra) != 19:
                continue
            all_nulls = sorted(w_set | set(extra))
            if len(all_nulls) != 24:
                continue
            remaining = "".join(CT[i] for i in range(CT_LEN) if i not in set(all_nulls))
            if len(remaining) != 73:
                continue
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT"]:
                key = text_to_key(kw)
                decrypt_both(remaining, key,
                             f"D7-start{n_start}end{n_end}-{kw}")

    print(f"  Test D complete: {configs_tested - start_count} configs\n", flush=True)


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("KRYPTOS K4 — Compass Point Interpretation of POINT from K2")
    print(f"CT ({CT_LEN} chars): {CT}")
    print(f"W positions: {W_POSITIONS}")
    print(f"Segments: {SEGMENT_LENGTHS}")
    print(f"CT without W ({len(CT_NO_W)} chars): {CT_NO_W}")
    print()

    test_a()
    test_b()
    test_c()
    test_d()

    # ── Final Report ─────────────────────────────────────────────────────

    print("=" * 78)
    print(f"FINAL REPORT — {configs_tested} total configurations tested")
    print("=" * 78)

    # Reference scores
    ct_qg = qg_score(CT)
    ct_ic = ic(CT)
    print(f"\nReference: CT QG/char = {ct_qg:.4f}, IC = {ct_ic:.4f}")
    print(f"English QG/char: -4.2 to -3.5 | Random: -5.0 to -4.5")
    print(f"Noise threshold: QG/char > {QG_NOISE_THRESHOLD}")

    # Separate crib hits
    crib_results = [r for r in results if r[4]]
    non_crib_results = [r for r in results if not r[4]]

    print(f"\n--- CRIB MATCHES: {len(crib_results)} ---")
    if crib_results:
        crib_results.sort(key=lambda x: x[0], reverse=True)
        for qg, method, pt, ic_val, cribs in crib_results:
            print(f"  QG={qg:.4f} IC={ic_val:.4f} | {method}")
            print(f"  PT: {pt[:70]}")
            print(f"  Cribs: {', '.join(cribs)}")
            print()
    else:
        print("  No crib matches found in any configuration.")

    # Sort all by QG score
    results.sort(key=lambda x: x[0], reverse=True)

    print(f"\n--- TOP 30 BY QUADGRAM SCORE (from {len(results)} stored) ---")
    print(f"{'Rank':>4} {'QG/ch':>8} {'IC':>7} {'Method':<55} {'Cribs'}")
    print("-" * 110)
    for rank, (qg, method, pt, ic_val, cribs) in enumerate(results[:30], 1):
        crib_str = ", ".join(cribs) if cribs else "-"
        print(f"{rank:>4} {qg:>8.4f} {ic_val:>7.4f} {method:<55} {crib_str}")
        if rank <= 10:
            pt_disp = pt[:75] + ("..." if len(pt) > 75 else "")
            print(f"     PT: {pt_disp}")

    # IC distribution
    if results:
        top_ics = [r[3] for r in results[:100]]
        print(f"\n--- IC DISTRIBUTION (top 100) ---")
        print(f"  Mean: {sum(top_ics) / len(top_ics):.4f}")
        print(f"  Max:  {max(top_ics):.4f}")
        print(f"  Min:  {min(top_ics):.4f}")

    # Summary by test
    print(f"\n--- SUMMARY BY TEST ---")
    test_counts = Counter()
    for _, method, _, _, _ in results:
        test_letter = method.split("-")[0] if "-" in method else method[0]
        test_counts[test_letter] += 1
    for test, count in sorted(test_counts.items()):
        print(f"  {test}: {count} results stored")

    print(f"\nTotal configurations tested: {configs_tested}")
    print("Done.", flush=True)


if __name__ == "__main__":
    main()
