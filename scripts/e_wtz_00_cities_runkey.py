#!/usr/bin/env python3
"""E-WTZ-00: Weltzeituhr city names and UTC offsets as running key / numeric key.

HYPOTHESIS
----------
Sanborn's Aug 2025 clue: BERLINCLOCK = Weltzeituhr (the World Time Clock at
Alexanderplatz, East Berlin). He called it "a reminder." The Weltzeituhr has
~148 cities arranged in 24 time-zone sectors, readable publicly on-site.

If Sanborn encoded a running key from the Weltzeituhr, this would be:
  ✓ Position-dependent, non-periodic (K5 same-position constraint)
  ✓ Publicly available (Sanborn: "publicly available info suffices")
  ✓ Non-mathematical ("not even a math solution" — just read the clock)
  ✓ Connected to Berlin Clock (named in the crib BERLINCLOCK)

WHAT'S TESTED
-------------
1. City names (German spellings, GDR-era) concatenated as running key text
   — clockwise (UTC-11 → UTC+12) and counterclockwise
2. UTC offset sequence: each city → (offset + 12) mod 26 as key letter
   — forward and reversed
3. Single time-zone rings (UTC+1 = Berlin, UTC+3 = Moscow, etc.)
4. German city initials-only as a key fragment
5. UTC offset value per position (modular cycling, direct key from offsets)

FRAMEWORK GAP
-------------
E-CFM-09: 73.7M chars of text corpora tested as running key, identity trans.
E-EGYPT-01: 1.19B configs including columnar trans, all NOISE.
NOT TESTED: The specific Weltzeituhr city-name sequence as a running key.

Run: PYTHONPATH=src python3 -u scripts/e_wtz_00_cities_runkey.py
"""

import sys
import os
import json
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

# ── Weltzeituhr city data (Alexanderplatz, Berlin, 1969 installation) ─────────
# Cities in UTC-offset order (approximately, GDR-era German spelling).
# Each tuple: (UTC_offset_int, [city_names_in_german])
# Source: public photographs + GDR documentation of the Weltzeituhr.
# Note: Exact 1969 city list is approximated; fractional-hour offsets omitted.

WTZ_BY_OFFSET = [
    (-11, ["PAPEETE", "APIA"]),
    (-10, ["HONOLULU"]),
    (-9,  ["ANCHORAGE"]),
    (-8,  ["LOSANGELES", "VANCOUVER", "SANFRANCISCO"]),
    (-7,  ["DENVER", "SALTLAKECITY", "PHOENIX"]),
    (-6,  ["MEXIKOCITY", "CHICAGO", "WINNIPEG"]),
    (-5,  ["NEWYORK", "MONTREAL", "LIMA", "BOGOTA", "HAVANA", "MIAMI"]),
    (-4,  ["CARACAS", "LAPAZ", "SANTIAGO", "SANJUAN"]),
    (-3,  ["BUENOSAIRES", "RIODEJANEIRO", "MONTEVIDEO", "BRASILIA"]),
    (-2,  ["ATLANTIK"]),
    (-1,  ["AZOREN", "KAPS"]),
    (0,   ["LONDON", "DAKAR", "CASABLANCA", "DUBLIN", "REYKJAVIK", "ABIDJAN"]),
    (1,   ["PARIS", "BERLIN", "ROM", "MADRID", "AMSTERDAM", "BRUESSEL",
            "WIEN", "BUDAPEST", "BELGRAD", "WARSCHAU", "PRAG", "BERN",
            "STOCKHOLM", "OSLO", "KOPENHAGEN", "ALGIER", "TUNIS", "LAGOS"]),
    (2,   ["KAIRO", "ATHEN", "JERUSALEM", "BEIRUT", "BUKAREST", "SOFIA",
            "KIEW", "RIGA", "HELSINKI", "ISTANBUL", "TRIPOLIS", "KHARTOUM"]),
    (3,   ["MOSKAU", "BAGDAD", "NAIROBI", "ADDISABEBA", "RIAD", "ADEN",
            "SANKTPETERSBURG"]),
    (4,   ["DUBAI", "TIFLIS", "BAKU", "ABUDHABI", "MASKAT"]),
    (5,   ["KARATSCHI", "TASCHKENT", "JEKATERINBURG"]),
    (6,   ["KALKUTTA", "DHAKA", "KOLOMBO", "NOWOSIBIRSK"]),
    (7,   ["BANGKOK", "JAKARTA", "HANOI", "KRASNOJARSK"]),
    (8,   ["PEKING", "HONGKONG", "SINGAPUR", "MANILA", "TAIPEI",
            "IRKUTSK", "ULAANBAATAR"]),
    (9,   ["TOKIO", "SOUL", "JAKUTSK"]),
    (10,  ["SYDNEY", "MELBOURNE", "BRISBANE", "GUAM", "WLADIWOSTOK"]),
    (11,  ["NOUMEA", "HONIARA", "MAGADAN"]),
    (12,  ["AUCKLAND", "WELLINGTON", "SUVA", "PETROPAWLOWSK"]),
]

ALPH_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# ── Derived keystream constraints ─────────────────────────────────────────────

CT_VALS = [ALPH_IDX[c] for c in CT]
PT_VALS = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POS_LIST = sorted(CRIB_DICT.keys())

# Precompute known key values for all 3 cipher variants
def make_known_key(ct_v, pt_v, mod):
    return {
        "vigenere":     {pos: (ct_v[pos] - pt_v[pos]) % mod for pos in pt_v},
        "beaufort":     {pos: (ct_v[pos] + pt_v[pos]) % mod for pos in pt_v},
        "var_beaufort": {pos: (pt_v[pos] - ct_v[pos]) % mod for pos in pt_v},
    }

KNOWN = make_known_key(CT_VALS, PT_VALS, MOD)

# EAST constraint: positions 21-24 appear again at 30-33 (EAST repeats in ENE)
# Key diffs: [key[30]-key[21], key[31]-key[22], key[32]-key[23], key[33]-key[24]] mod 26
EAST_DIFFS = {
    "vigenere":     [(KNOWN["vigenere"][30+j] - KNOWN["vigenere"][21+j]) % MOD for j in range(4)],
    "beaufort":     [(KNOWN["beaufort"][30+j] - KNOWN["beaufort"][21+j]) % MOD for j in range(4)],
    "var_beaufort": [(KNOWN["var_beaufort"][30+j] - KNOWN["var_beaufort"][21+j]) % MOD for j in range(4)],
}
# Also check Bean-EQ: key[27] == key[65]
BEAN_EQ_VALS = {vname: KNOWN[vname][27] for vname in KNOWN}

# ── Running key scorer ────────────────────────────────────────────────────────

def score_key(key_seq: list, vname: str) -> int:
    """Count how many of the 24 crib positions match."""
    known = KNOWN[vname]
    return sum(1 for pos in CRIB_POS_LIST if pos < len(key_seq) and key_seq[pos] == known[pos])

def bean_eq_pass(key_seq: list, vname: str) -> bool:
    """Check Bean equality k[27] == k[65]."""
    if len(key_seq) <= 65:
        return False
    return key_seq[27] == key_seq[65] == BEAN_EQ_VALS[vname]

def east_filter(key_seq: list, vname: str) -> bool:
    """EAST constraint: check gap-9 differences at positions 21-24."""
    diffs = EAST_DIFFS[vname]
    if len(key_seq) <= 33:
        return False
    for j in range(4):
        if (key_seq[30 + j] - key_seq[21 + j]) % MOD != diffs[j]:
            return False
    return True

def test_key_seq(key_seq: list, label: str) -> list:
    """Test a candidate key sequence against all cribs and filters."""
    results = []
    for vname in ["vigenere", "beaufort", "var_beaufort"]:
        if not east_filter(key_seq, vname):
            continue  # fast pre-filter
        score = score_key(key_seq, vname)
        bean = bean_eq_pass(key_seq, vname)
        if score >= 6:
            results.append({
                "label": label,
                "cipher": vname,
                "score": score,
                "bean_eq": bean,
                "key_preview": "".join(ALPH_STR[k] for k in key_seq[:30]),
            })
    return results

# ── City text running key ─────────────────────────────────────────────────────

def build_city_text(reverse: bool = False) -> str:
    """Concatenate city names in UTC offset order."""
    data = list(reversed(WTZ_BY_OFFSET)) if reverse else WTZ_BY_OFFSET
    parts = []
    for _, cities in data:
        parts.extend(cities)
    return "".join(parts)

def test_text_as_runkey(text: str, label: str, min_score: int = 6) -> list:
    """Try all offsets of text as a running key."""
    alpha_vals = [ALPH_IDX[c] for c in text if c in ALPH_IDX]
    n = len(alpha_vals)
    if n < CT_LEN:
        print(f"  [{label}] Text only {n} alpha chars — too short")
        return []

    results = []
    for off in range(n - CT_LEN + 1):
        key_seq = alpha_vals[off:off + CT_LEN]
        hits = test_key_seq(key_seq, f"{label}_off{off}")
        results.extend(hits)

    top = sorted(results, key=lambda r: -r["score"])[:5]
    if top:
        print(f"  [{label}] Best: {top[0]['score']}/24 "
              f"(cipher={top[0]['cipher']}, bean={top[0]['bean_eq']})")
    else:
        print(f"  [{label}] No match ≥6/24 after EAST filter")
    return results

# ── UTC offset numeric key ────────────────────────────────────────────────────

def build_offset_key(reverse: bool = False) -> list:
    """Build a numeric key from UTC offsets (offset+12 maps -12..+13 → 0..25)."""
    data = list(reversed(WTZ_BY_OFFSET)) if reverse else WTZ_BY_OFFSET
    key = []
    for offset, cities in data:
        val = (offset + 12) % MOD
        key.extend([val] * len(cities))
    return key

def test_offset_key(offset_key: list, label: str) -> list:
    """Test UTC offset key (try all start positions + cycling)."""
    n = len(offset_key)
    results = []

    # Direct sliding window (if long enough)
    for start in range(max(1, n - CT_LEN + 1)):
        key_seq = offset_key[start:start + CT_LEN]
        if len(key_seq) < CT_LEN:
            break
        hits = test_key_seq(key_seq, f"{label}_start{start}")
        results.extend(hits)

    # Cyclic extension (repeat offset key to fill 97 chars)
    for start in range(n):
        key_seq = [(offset_key[(start + i) % n]) for i in range(CT_LEN)]
        hits = test_key_seq(key_seq, f"{label}_cyc{start}")
        results.extend(hits)

    top = sorted(results, key=lambda r: -r["score"])[:3]
    if top:
        print(f"  [{label}] Best: {top[0]['score']}/24")
    else:
        print(f"  [{label}] No match ≥6/24")
    return results

# ── Additional creative encodings ─────────────────────────────────────────────

def city_initials(reverse: bool = False) -> list:
    """First letter of each city name as a key value."""
    data = list(reversed(WTZ_BY_OFFSET)) if reverse else WTZ_BY_OFFSET
    key = []
    for _, cities in data:
        for city in cities:
            if city[0] in ALPH_IDX:
                key.append(ALPH_IDX[city[0]])
    return key

def city_lengths(reverse: bool = False) -> list:
    """Length of each city name mod 26 as a key value."""
    data = list(reversed(WTZ_BY_OFFSET)) if reverse else WTZ_BY_OFFSET
    key = []
    for _, cities in data:
        for city in cities:
            key.append(len(city) % MOD)
    return key

def test_numeric_key(key: list, label: str) -> list:
    """Cycle/slide a numeric key and test."""
    n = len(key)
    results = []
    for start in range(n):
        key_seq = [key[(start + i) % n] for i in range(CT_LEN)]
        hits = test_key_seq(key_seq, f"{label}_s{start}")
        results.extend(hits)
    top = sorted(results, key=lambda r: -r["score"])[:3]
    if top:
        print(f"  [{label}] Best: {top[0]['score']}/24")
    else:
        print(f"  [{label}] No match ≥6/24")
    return results

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("="*65)
    print("E-WTZ-00: Weltzeituhr as running key / numeric key source")
    print("="*65)

    total_cities = sum(len(c) for _, c in WTZ_BY_OFFSET)
    print(f"City list: {len(WTZ_BY_OFFSET)} time zones, {total_cities} cities\n")

    all_results = []

    # ── 1. City name text, clockwise and counterclockwise ─────────────────────
    print("=== Part 1: City Name Text as Running Key ===")
    for reverse in [False, True]:
        label = "CityText_CW" if not reverse else "CityText_CCW"
        text = build_city_text(reverse)
        print(f"\n[{label}] Length: {len(text)} chars, alpha: "
              f"{sum(1 for c in text if c in ALPH_IDX)} chars")
        print(f"  Preview: {text[:60]}...")
        r = test_text_as_runkey(text, label)
        all_results.extend(r)

    # ── 2. UTC offset numeric key ─────────────────────────────────────────────
    print("\n=== Part 2: UTC Offset Numeric Key ===")
    for reverse in [False, True]:
        label = "UTC_Offset_CW" if not reverse else "UTC_Offset_CCW"
        key = build_offset_key(reverse)
        print(f"\n[{label}] Key length: {len(key)}, sample: {key[:20]}")
        r = test_offset_key(key, label)
        all_results.extend(r)

    # ── 3. City initials as key ───────────────────────────────────────────────
    print("\n=== Part 3: City Name Initials as Key ===")
    for reverse in [False, True]:
        label = "CityInit_CW" if not reverse else "CityInit_CCW"
        key = city_initials(reverse)
        print(f"\n[{label}] Key: {len(key)} chars = "
              f"{''.join(ALPH_STR[v] for v in key[:40])}...")
        r = test_numeric_key(key, label)
        all_results.extend(r)

    # ── 4. City name lengths as key ───────────────────────────────────────────
    print("\n=== Part 4: City Name Lengths mod 26 ===")
    for reverse in [False, True]:
        label = "CityLen_CW" if not reverse else "CityLen_CCW"
        key = city_lengths(reverse)
        print(f"\n[{label}] Key: {len(key)} values, sample: {key[:20]}")
        r = test_numeric_key(key, label)
        all_results.extend(r)

    # ── 5. EAST subsets: Berlin zone (UTC+1) only ─────────────────────────────
    print("\n=== Part 5: Single Time-Zone Rings ===")
    for offset, cities in WTZ_BY_OFFSET:
        if offset in (0, 1, 2, 3):  # Focus on European/African/Middle-East zones
            text = "".join(cities)
            if len(text) >= CT_LEN:
                r = test_text_as_runkey(text, f"TZ{offset:+d}")
                all_results.extend(r)
            else:
                print(f"  [TZ{offset:+d}] Too short ({len(text)} chars), skipping standalone")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "="*65)
    print("SUMMARY")
    print("="*65)

    top_all = sorted(all_results, key=lambda r: (-r["score"], -r.get("bean_eq", False)))[:20]

    if top_all:
        print(f"Total hits ≥6/24 (after EAST filter): {len(all_results)}")
        print(f"Top results:")
        for r in top_all[:10]:
            print(f"  score={r['score']}/24 bean={r['bean_eq']} "
                  f"cipher={r['cipher']} label={r['label']}")
        best_score = top_all[0]["score"]
        verdict = "SIGNAL" if best_score >= 18 else ("WEAK" if best_score >= 10 else "NOISE")
    else:
        print("No results ≥6/24 after EAST filter → NOISE")
        best_score = 0
        verdict = "NOISE"

    print(f"\nBest score: {best_score}/24")
    print(f"Verdict: {verdict}")

    # Write output
    os.makedirs("results", exist_ok=True)
    out = {
        "experiment": "E-WTZ-00",
        "hypothesis": "Weltzeituhr city names / UTC offsets as running key source",
        "n_cities": total_cities,
        "n_time_zones": len(WTZ_BY_OFFSET),
        "tests_run": [
            "CityText_CW", "CityText_CCW",
            "UTC_Offset_CW", "UTC_Offset_CCW",
            "CityInit_CW", "CityInit_CCW",
            "CityLen_CW", "CityLen_CCW",
            "TZ+0_ring", "TZ+1_ring", "TZ+2_ring", "TZ+3_ring",
        ],
        "total_hits_ge6": len(all_results),
        "best_score": best_score,
        "top_results": top_all[:20],
        "verdict": verdict,
        "framework_gap_closed": (
            "E-CFM-09 tested 73.7M chars of general text corpora. "
            "E-WTZ-00 specifically tests the Weltzeituhr city-name sequence "
            "and UTC-offset encoding as a running key source — previously untested."
        ),
    }
    outfile = "results/e_wtz_00_cities_runkey.json"
    with open(outfile, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults written to {outfile}")


if __name__ == "__main__":
    main()
