#!/usr/bin/env python3
"""
Cipher: Berlin clock
Family: thematic/berlin_clock
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-03: Berlin Clock sweep for K4.

Sanborn confirmed "BERLINCLOCK" refers to the Urania Weltzeituhr (World Time
Clock) at Alexanderplatz, Berlin. This is a 24-facet rotating column showing
world cities and their time offsets from Berlin time (CET/CEST).

Also tests the Mengenlehreuhr (Berlin "set theory" clock) which encodes
time in a unique binary scheme using 5 rows.

URANIA WELTZEITUHR:
- 24 city/timezone facets arranged around a rotating pillar
- Each facet shows a city name and time offset from Berlin
- The pillar rotates once per hour
- Key parameters: facet number (0-23), offset from Berlin, city name ordinals

MENGENLEHREUHR:
- Row 1: 4 blocks × 5 hours each (0-4 lit)
- Row 2: 4 blocks × 1 hour each (0-4 lit)
- Row 3: 11 blocks × 5 minutes each (0-11 lit)
- Row 4: 4 blocks × 1 minute each (0-4 lit)
- For time h:m → [h//5, h%5, m//5, m%5]

Tests all combinations × compass bearing variants × cipher variants.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]


def num_to_char(n):
    return chr(ord('A') + (n % 26))


def vig_decrypt(ct_nums, key_nums):
    period = len(key_nums)
    return [(ct_nums[i] - key_nums[i % period]) % MOD for i in range(len(ct_nums))]


def beaufort_decrypt(ct_nums, key_nums):
    period = len(key_nums)
    return [(key_nums[i % period] - ct_nums[i]) % MOD for i in range(len(ct_nums))]


def score_cribs(pt_nums):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == ALPH_IDX[ch]:
            matches += 1
    return matches


def check_bean(pt_nums):
    key = [(CT_NUM[i] - pt_nums[i]) % MOD for i in range(len(pt_nums))]
    for a, b in BEAN_EQ:
        if key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if key[a] == key[b]:
            return False
    return True


def berlin_clock_rows(hour, minute):
    """Return Mengenlehreuhr row values for a given time."""
    return [hour // 5, hour % 5, minute // 5, minute % 5]


def berlin_clock_binary(hour, minute):
    """Return Mengenlehreuhr binary representation (23 bits)."""
    r1, r2, r3, r4 = hour // 5, hour % 5, minute // 5, minute % 5
    bits = []
    for i in range(4):
        bits.append(1 if i < r1 else 0)
    for i in range(4):
        bits.append(1 if i < r2 else 0)
    for i in range(11):
        bits.append(1 if i < r3 else 0)
    for i in range(4):
        bits.append(1 if i < r4 else 0)
    return bits


# ── URANIA WELTZEITUHR DATA ─────────────────────────────────────────────────
# 24 facets with city names and UTC offsets (in hours from UTC)
# Arranged alphabetically on the actual clock; the physical ordering
# around the column starts from a reference point.

WELTZEITUHR_CITIES = [
    # (city_name, UTC_offset_hours, facet_number_on_clock)
    # Facet ordering from known documentation/photos (clockwise from reference)
    ("ANCHORAGE", -9, 0),
    ("BUENOS AIRES", -3, 1),
    ("CARACAS", -4, 2),
    ("CHICAGO", -6, 3),
    ("DACCA", 6, 4),        # now Dhaka
    ("DELHI", 5, 5),         # +5:30 rounded
    ("HAVANA", -5, 6),
    ("HELSINKI", 2, 7),
    ("KABUL", 4, 8),         # +4:30 rounded
    ("KAIRO", 2, 9),         # Cairo in German
    ("LONDON", 0, 10),
    ("MEXICO", -6, 11),      # Mexico City
    ("MOSKAU", 3, 12),       # Moscow in German
    ("NOWOSIBIRSK", 7, 13),  # Novosibirsk in German
    ("PJOENGJANG", 9, 14),   # Pyongyang in German
    ("PEKING", 8, 15),       # Beijing in German
    ("REYKJAVIK", 0, 16),
    ("SANTIAGO", -4, 17),
    ("SOFIA", 2, 18),
    ("TASCHKENT", 5, 19),    # Tashkent in German
    ("TOKIO", 9, 20),        # Tokyo in German
    ("WLADIWOSTOK", 10, 21), # Vladivostok in German
    ("WELLINGTON", 12, 22),
    ("WINDHOEK", 2, 23),     # +2 (historically)
]

# The Weltzeituhr also displays Berlin time (CET = UTC+1)
BERLIN_OFFSET = 1  # CET


def city_name_to_nums(name):
    """Convert city name to numeric values (A=0..Z=25)."""
    return [ALPH_IDX.get(c, 0) for c in name.upper() if c in ALPH_IDX]


def main():
    print("=" * 80)
    print("E-03: Berlin Clock Sweep for K4")
    print("  Testing both Urania Weltzeituhr and Mengenlehreuhr")
    print("=" * 80)

    results = []

    # ═══════════════════════════════════════════════════════════════════════════
    # PART A: URANIA WELTZEITUHR (the clock Sanborn confirmed)
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 60)
    print("PART A: URANIA WELTZEITUHR")
    print("=" * 60)

    # ── A1: City names as Vigenère keys ──────────────────────────────────────

    print("\n── A1: City names as direct Vigenère/Beaufort keys ──")

    for city, utc_off, facet in WELTZEITUHR_CITIES:
        key_nums = city_name_to_nums(city)
        if not key_nums:
            continue
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, key_nums)
            score = score_cribs(pt)
            if score >= 5:
                bean = check_bean(pt)
                pt_text = ''.join(num_to_char(n) for n in pt)
                print(f"  {city} ({variant}): score={score}/{N_CRIBS} "
                      f"{'BEAN✓' if bean else 'bean✗'} PT={pt_text[:40]}...")
                results.append((score, f"city_{city}_{variant}", key_nums, bean))

    # Also test BERLIN, KRYPTOS, PALIMPSEST, ABSCISSA as keys
    for keyword in ["BERLIN", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
                     "WELTZEITUHR", "URANIA", "ALEXANDERPLATZ",
                     "EASTNORTHEAST", "BERLINCLOCK"]:
        key_nums = city_name_to_nums(keyword)
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, key_nums)
            score = score_cribs(pt)
            if score >= 5:
                bean = check_bean(pt)
                pt_text = ''.join(num_to_char(n) for n in pt)
                print(f"  {keyword} ({variant}): score={score}/{N_CRIBS} "
                      f"{'BEAN✓' if bean else 'bean✗'}")
                results.append((score, f"keyword_{keyword}_{variant}", key_nums, bean))

    # ── A2: Facet numbers as key sequence ────────────────────────────────────

    print("\n── A2: Facet-derived key sequences ──")

    # UTC offsets as key
    utc_offsets = [off % 26 for _, off, _ in WELTZEITUHR_CITIES]
    # Offsets relative to Berlin (CET = UTC+1)
    berlin_offsets = [(off - BERLIN_OFFSET) % 26 for _, off, _ in WELTZEITUHR_CITIES]
    # Facet numbers directly
    facet_nums = [f % 26 for _, _, f in WELTZEITUHR_CITIES]
    # City name first letters
    first_letters = [ALPH_IDX[city[0]] for city, _, _ in WELTZEITUHR_CITIES]

    for name, seq in [
        ("utc_offsets", utc_offsets),
        ("berlin_offsets", berlin_offsets),
        ("facet_numbers", facet_nums),
        ("first_letters", first_letters),
    ]:
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, seq)
            score = score_cribs(pt)
            if score >= 5:
                bean = check_bean(pt)
                print(f"  {name} ({variant}): score={score}/{N_CRIBS} "
                      f"{'BEAN✓' if bean else 'bean✗'}")
                results.append((score, f"facet_{name}_{variant}", seq, bean))

    # ── A3: Progressive Weltzeituhr rotation ─────────────────────────────────

    print("\n── A3: Progressive rotation (facet + position offset) ──")

    for start_facet in range(24):
        for step in range(1, 25):
            # Key[i] = (start_facet + i * step) mod 24, reduced mod 26
            key = [(start_facet + i * step) % 24 for i in range(CT_LEN)]
            for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                pt = dfn(CT_NUM, key)
                score = score_cribs(pt)
                if score >= 8:
                    bean = check_bean(pt)
                    tag = f"progressive facet={start_facet} step={step} {variant}"
                    print(f"  {tag}: score={score}/{N_CRIBS} "
                          f"{'BEAN✓' if bean else 'bean✗'}")
                    results.append((score, tag, key[:10], bean))

    # ── A4: Facet as starting position on Weltzeituhr, read city names ───────

    print("\n── A4: Concatenated city names from facet orderings ──")

    # Starting from each facet, read city names around the clock
    for start in range(24):
        all_letters = []
        for i in range(24):
            facet_idx = (start + i) % 24
            city_name = WELTZEITUHR_CITIES[facet_idx][0]
            all_letters.extend(city_name_to_nums(city_name))
        # Use as running key
        key = all_letters[:CT_LEN]
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, key)
            score = score_cribs(pt)
            if score >= 6:
                bean = check_bean(pt)
                print(f"  city_concat start={start} ({variant}): score={score}/{N_CRIBS}")
                results.append((score, f"city_concat_{start}_{variant}", [], bean))

    # ── A5: Compass bearing (67.5° ENE) as Weltzeituhr facet ─────────────────

    print("\n── A5: ENE bearing → Weltzeituhr facet mapping ──")

    # 67.5° maps to which facet? The Weltzeituhr has 24 facets × 15° each = 360°
    # 67.5° / 15° = 4.5 → facet 4 or 5
    ene_facets = [4, 5]  # DACCA or DELHI
    for ene_facet in ene_facets:
        city_name = WELTZEITUHR_CITIES[ene_facet][0]
        print(f"  ENE → facet {ene_facet} = {city_name}")

        # Use this city as key
        key = city_name_to_nums(city_name)
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, key)
            score = score_cribs(pt)
            bean = check_bean(pt)
            pt_text = ''.join(num_to_char(n) for n in pt)
            print(f"    {city_name} ({variant}): score={score}/{N_CRIBS} "
                  f"{'BEAN✓' if bean else 'bean✗'} PT={pt_text[:40]}...")

    # T=19 → facet 19 = TASCHKENT
    t_facet = 19
    city_name = WELTZEITUHR_CITIES[t_facet][0]
    print(f"  T IS YOUR POSITION → facet {t_facet} = {city_name}")
    key = city_name_to_nums(city_name)
    for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
        pt = dfn(CT_NUM, key)
        score = score_cribs(pt)
        bean = check_bean(pt)
        pt_text = ''.join(num_to_char(n) for n in pt)
        print(f"    {city_name} ({variant}): score={score}/{N_CRIBS} "
              f"{'BEAN✓' if bean else 'bean✗'}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PART B: MENGENLEHREUHR (set theory clock)
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 60)
    print("PART B: MENGENLEHREUHR")
    print("=" * 60)

    # ── B1: Clock row values as key ──────────────────────────────────────────

    print("\n── B1: Clock rows [h//5, h%5, m//5, m%5] as key ──")

    mengenlehr_hits = 0
    for hour in range(24):
        for minute in range(60):
            rows = berlin_clock_rows(hour, minute)

            # Method 1: raw rows as cyclic key
            for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                pt = dfn(CT_NUM, rows)
                score = score_cribs(pt)
                if score >= 8:
                    bean = check_bean(pt)
                    tag = f"ML {hour:02d}:{minute:02d} rows {variant}"
                    results.append((score, tag, rows[:], bean))
                    mengenlehr_hits += 1
                    if score >= 10:
                        print(f"  ** {tag}: score={score}/{N_CRIBS}")

            # Method 2: rows with hour and minute appended
            extended = rows + [hour % 26, minute % 26]
            for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                pt = dfn(CT_NUM, extended)
                score = score_cribs(pt)
                if score >= 8:
                    bean = check_bean(pt)
                    tag = f"ML {hour:02d}:{minute:02d} rows+hm {variant}"
                    results.append((score, tag, extended[:], bean))
                    mengenlehr_hits += 1
                    if score >= 10:
                        print(f"  ** {tag}: score={score}/{N_CRIBS}")

            # Method 3: direct h,m as 2-element key
            hm = [hour % 26, minute % 26]
            for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                pt = dfn(CT_NUM, hm)
                score = score_cribs(pt)
                if score >= 8:
                    bean = check_bean(pt)
                    tag = f"ML {hour:02d}:{minute:02d} hm {variant}"
                    results.append((score, tag, hm[:], bean))
                    mengenlehr_hits += 1
                    if score >= 10:
                        print(f"  ** {tag}: score={score}/{N_CRIBS}")

    print(f"  B1 complete. Hits ≥8: {mengenlehr_hits}")

    # ── B2: Binary representation as key ─────────────────────────────────────

    print("\n── B2: Mengenlehreuhr binary (23-bit) as key ──")

    binary_hits = 0
    for hour in range(24):
        for minute in range(60):
            bits = berlin_clock_binary(hour, minute)
            for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                pt = dfn(CT_NUM, bits)
                score = score_cribs(pt)
                if score >= 8:
                    binary_hits += 1
                    if score >= 10:
                        tag = f"ML binary {hour:02d}:{minute:02d} {variant}"
                        print(f"  ** {tag}: score={score}/{N_CRIBS}")
                        results.append((score, tag, bits[:], False))

    print(f"  B2 complete. Hits ≥8: {binary_hits}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PART C: COMBINED — Weltzeituhr + Mengenlehreuhr + bearing + T-position
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 60)
    print("PART C: COMBINED TESTS")
    print("=" * 60)

    # ── C1: Significant times and dates ──────────────────────────────────────

    print("\n── C1: Historically significant date/time sequences ──")

    date_seqs = {
        "1989_11_09_digits": [1, 9, 8, 9, 1, 1, 0, 9],
        "1986_digits": [1, 9, 8, 6],
        "1990_11_03_digits": [1, 9, 9, 0, 1, 1, 0, 3],
        "berlin_wall_hhmm_2300": [23, 0],
        "berlin_wall_hhmm_0000": [0, 0],
        "coordinates_38_57_77_8": [3, 8, 5, 7, 7, 7, 8],
        "coord_mod26": [38 % 26, 57 % 26, 77 % 26, 8],
        "67_bearing": [6, 7],
        "675_bearing": [6, 7, 5],
        "year_89": [8, 9],
        "year_86": [8, 6],
        "year_90": [9, 0],
        "YAR": [24, 0, 17],
        "DYARO": [3, 24, 0, 17, 14],
        "T_pos_19": [19],
        "T_pos_20": [20],
    }

    for name, key in date_seqs.items():
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, key)
            score = score_cribs(pt)
            if score >= 5:
                bean = check_bean(pt)
                print(f"  {name} ({variant}): score={score}/{N_CRIBS} "
                      f"{'BEAN✓' if bean else 'bean✗'}")
                results.append((score, f"date_{name}_{variant}", key, bean))

    # ── C2: Weltzeituhr city + Mengenlehreuhr time ───────────────────────────

    print("\n── C2: Weltzeituhr city key + Mengenlehreuhr offset ──")

    c2_hits = 0
    # For each Weltzeituhr city, add its UTC offset as a constant shift
    for city, utc_off, facet in WELTZEITUHR_CITIES:
        city_key = city_name_to_nums(city)
        # Apply UTC offset as additional shift
        shifted_key = [(k + utc_off) % MOD for k in city_key]
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, shifted_key)
            score = score_cribs(pt)
            if score >= 6:
                bean = check_bean(pt)
                print(f"  {city}+UTC({utc_off}) ({variant}): score={score}/{N_CRIBS}")
                results.append((score, f"city+utc_{city}_{variant}", shifted_key, bean))
                c2_hits += 1

    print(f"  C2 complete. Hits ≥6: {c2_hits}")

    # ── C3: Progressive key from Weltzeituhr rotation + position ─────────────

    print("\n── C3: Weltzeituhr position-progressive key ──")

    # Key idea: the clock rotates. K4's key = position on clock face at each
    # character position, rotating at some rate.
    # k[i] = (start_facet + i * rotation_rate) mod 24
    # Combined with city UTC offset at that facet

    c3_hits = 0
    for start in range(24):
        for rate_num in range(1, 24):
            for rate_den in [1, 2, 3, 4, 5, 6]:
                # Key at position i = UTC offset of facet (start + i*rate_num/rate_den) mod 24
                key = []
                for i in range(CT_LEN):
                    facet_idx = (start + (i * rate_num) // rate_den) % 24
                    offset_val = WELTZEITUHR_CITIES[facet_idx][1]
                    key.append(offset_val % MOD)

                for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                    pt = dfn(CT_NUM, key)
                    score = score_cribs(pt)
                    if score >= 10:
                        bean = check_bean(pt)
                        tag = (f"progressive start={start} rate={rate_num}/{rate_den} "
                               f"{variant}")
                        print(f"  ** {tag}: score={score}/{N_CRIBS}")
                        results.append((score, tag, key[:10], bean))
                        c3_hits += 1

    print(f"  C3 complete. Hits ≥10: {c3_hits}")

    # ── C4: City name ordinals as position-dependent key ─────────────────────

    print("\n── C4: City name character cycling as running key ──")

    # For each starting city and direction of reading:
    # The key at position i is drawn from the concatenated city names
    for start in range(24):
        for direction in [1, -1]:
            running_key = []
            for facet_step in range(24):
                facet_idx = (start + facet_step * direction) % 24
                name_nums = city_name_to_nums(WELTZEITUHR_CITIES[facet_idx][0])
                running_key.extend(name_nums)
                if len(running_key) >= CT_LEN:
                    break
            running_key = running_key[:CT_LEN]
            if len(running_key) < CT_LEN:
                running_key.extend([0] * (CT_LEN - len(running_key)))

            for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                pt = dfn(CT_NUM, running_key)
                score = score_cribs(pt)
                if score >= 6:
                    bean = check_bean(pt)
                    d_name = "CW" if direction == 1 else "CCW"
                    tag = f"running_city start={start} {d_name} {variant}"
                    print(f"  {tag}: score={score}/{N_CRIBS}")
                    results.append((score, tag, [], bean))

    # ═══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 80)
    print("SUMMARY: Top results across all tests")
    print("=" * 80)

    results.sort(key=lambda x: (-x[0], -x[3]))
    seen = set()
    count = 0
    for score, tag, key, bean in results:
        if count >= 25:
            break
        if tag in seen:
            continue
        seen.add(tag)
        bean_str = "BEAN✓" if bean else "bean✗"
        key_str = str(key[:8]) + "..." if len(key) > 8 else str(key)
        print(f"  {score}/{N_CRIBS} {bean_str} | {tag} | key={key_str}")
        count += 1

    best = results[0] if results else (0, "none", [], False)
    print(f"\nBest overall: {best[0]}/{N_CRIBS} | {best[1]}")

    if best[0] >= 17:
        print("SUCCESS: Berlin Clock hypothesis shows strong signal")
    elif best[0] >= 10:
        print("INTERESTING: Above noise, investigate further")
    else:
        print("FAILURE: Berlin Clock states as direct key material → at/near noise floor")

    print("\n[E-03 COMPLETE]")
    return best[0]


if __name__ == "__main__":
    main()
