#!/usr/bin/env python3
"""E-S-128: Weltzeituhr city-name-derived keys for K4.

Sanborn: "You'd better delve into that particular clock"
         "There's a lot of fodder there"

The "fodder" = 146 city/region names engraved on 24 timezone faces.
City names extracted from 7 photographs of the Urania Weltzeituhr.
All names in GERMAN as engraved on the clock (DDR-era + 1997 additions).

KEY DISCOVERY: The Washington DC face (UTC-5) has EXACTLY 7 cities:
  MONTREAL, WASHINGTON, NEW YORK, PANAMA, BOGOTA, QUITO, LIMA
This connects directly to the width-7 hypothesis!

Tests:
  (a) DC-face 7 cities as period-7 key (first letters, alphabetical order, etc.)
  (b) Berlin-face city initials as key
  (c) All city initials in clockwise order as running key
  (d) City count per face as numeric key (24 elements)
  (e) DC-face cities + w7 columnar orderings
  (f) Berlin-face cities as keyword alphabets
  (g) City names concatenated as running key + w7 columnar
  (h) Face-pair derived keys (Berlin face + DC face combined)

Stage 4 of Progressive Solve Plan (corrected) — city data phase.
"""
import json
import os
import sys
import time as time_mod
import random
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic


def make_key(text):
    """Convert text to numeric key (A=0, B=1, ..., Z=25)."""
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


# ═══════════════════════════════════════════════════════════════════════════
# WELTZEITUHR CITY DATA — extracted from 7 photographs
# German spellings as engraved on the clock
# Organized by UTC timezone face (24 faces total)
# Upper = cities above the hour-number strip
# Lower = cities below the hour-number strip
# ═══════════════════════════════════════════════════════════════════════════

# Each face is a list of city names in reading order (upper L→R, then lower L→R)
# Face index: 0=UTC-12 (Date Line) through 23=UTC+11

WELTZEITUHR_FACES = {
    # UTC-12 to UTC-9: Far Pacific/Alaska (sparse, not clearly visible in photos)
    0: ["DATUMSGRENZE"],           # UTC-12: International Date Line
    1: [],                          # UTC-11: Midway/Samoa (not visible)
    2: [],                          # UTC-10: Hawaii (not visible)
    3: [],                          # UTC-9: Alaska (not visible)

    # UTC-8: Pacific
    4: ["VANCOUVER", "SAN FRANCISCO", "LOS ANGELES"],

    # UTC-7: Mountain
    5: ["EDMONTON", "DENVER"],

    # UTC-6: Central Americas
    6: ["NEW ORLEANS", "MEXIKO-STADT", "HAVANNA",
        "GUATEMALA-STADT", "MANAGUA", "GALAPAGOS-INSELN"],

    # UTC-5: Eastern US — THE DC FACE (*** 7 cities! ***)
    7: ["MONTREAL", "WASHINGTON", "NEW YORK",
        "PANAMA", "BOGOTA", "QUITO", "LIMA"],

    # UTC-4: Atlantic
    8: ["HALIFAX",
        "CARACAS", "LA PAZ", "ASUNCION", "SANTIAGO DE CHILE"],

    # UTC-3: East South America
    9: ["WESTGROENLAND",
        "BRASILIA", "RIO DE JANEIRO", "SAO PAULO", "MONTEVIDEO", "BUENOS AIRES"],

    # UTC-2: Mid-Atlantic
    10: ["KAP VERDE"],

    # UTC-1: Azores / East Greenland
    11: ["OSTGROENLAND", "AZOREN"],

    # UTC+0: Greenwich
    12: ["REYKJAVIK", "DUBLIN", "LONDON", "LISSABON", "MADEIRA", "BISSAU",
         "CASABLANCA", "CONAKRY", "DAKAR", "BAMAKO", "ACCRA"],

    # UTC+1: Central European Time — THE BERLIN FACE (18 cities)
    13: ["AMSTERDAM", "BERLIN", "BRUESSEL", "BUDAPEST", "MADRID",
         "PARIS", "PRAG", "STOCKHOLM", "WARSCHAU",
         "OSLO", "KOPENHAGEN", "WIEN", "BERN", "PRESSBURG",
         "BELGRAD", "ROM", "TUNIS", "KINSHASA"],

    # UTC+2: Eastern European
    14: ["HELSINKI", "RIGA", "TALLINN", "WILNA", "MINSK",
         "KIEW", "BUKAREST", "SOFIA", "NIKOSIA",
         "ANKARA", "ISTANBUL", "ATHEN", "TEL AVIV", "JERUSALEM",
         "BEIRUT", "DAMASKUS", "KAIRO", "KAPSTADT"],

    # UTC+3: Moscow / East Africa
    15: ["MURMANSK", "ST PETERSBURG", "MOSKAU",
         "BAGDAD", "ADEN", "SANAA", "ADDIS ABEBA",
         "MOGADISCHU", "DARESSALAM", "ANTANANARIVO", "KUWAIT"],
    # Note: TEHERAN is +3:30, shown on this panel with "+30'" annotation

    # UTC+4: Gulf / Caucasus
    16: ["NISCHNIJ NOWGOROD", "WOLGOGRAD", "BAKU", "TIFLIS", "ERIWAN",
         "MAURITIUS"],
    # Note: KABUL is +4:30, shown on this panel with "+30'" annotation

    # UTC+5: Central Asia
    17: ["JEKATERINBURG", "ASCHGABAT", "BISCHKEK", "DUSCHANBE",
         "KARACHI"],
    # Note: NEW DELHI +5:30, COLOMBO +5:30 shown on this panel

    # UTC+6: Central/South Asia
    18: ["OMSK", "ALMATY", "TASCHKENT", "NOWOSIBIRSK",
         "DHAKA"],
    # Note: RANGUN (Yangon) is +6:30, shown with "+30'" annotation

    # UTC+7: Southeast Asia
    19: ["KRASNOJARSK", "HANOI", "BANGKOK", "PHNOM PENH", "JAKARTA"],

    # UTC+8: East Asia (partially visible in photos)
    20: ["PEKING", "SHANGHAI", "MANILA", "PERTH", "SINGAPUR", "KUALA LUMPUR"],

    # UTC+9: Japan/Korea (partially visible)
    21: ["JAKUTSK", "TOKIO", "SEOUL"],

    # UTC+10: Eastern Australia (partially visible)
    22: ["WLADIWOSTOK", "SYDNEY", "MELBOURNE"],

    # UTC+11: Pacific (sparse, not clearly visible)
    23: [],
}

# Half-hour timezone cities (shown on adjacent full-hour panels with "+30'" mark)
HALF_HOUR_CITIES = {
    "TEHERAN": 15,      # UTC+3:30, shown on UTC+3 panel
    "KABUL": 16,         # UTC+4:30, shown on UTC+4 panel
    "NEW DELHI": 17,     # UTC+5:30, shown on UTC+5 panel
    "COLOMBO": 17,       # UTC+5:30, shown on UTC+5 panel
    "RANGUN": 18,        # UTC+6:30, shown on UTC+6 panel
}


# ═══════════════════════════════════════════════════════════════════════════
# DERIVED KEY MATERIAL
# ═══════════════════════════════════════════════════════════════════════════

def get_all_cities_ordered():
    """All cities in clockwise order starting from UTC-12."""
    cities = []
    for face in range(24):
        cities.extend(WELTZEITUHR_FACES[face])
    # Add half-hour cities at their panel positions
    for city, panel in sorted(HALF_HOUR_CITIES.items(), key=lambda x: x[1]):
        # Insert after the full-hour cities of that panel
        pass  # Already implicitly ordered
    return cities


def get_city_initials(city_list):
    """First letter of each city name."""
    return "".join(c[0] for c in city_list if c and c[0] in ALPH_IDX)


def get_city_counts():
    """Number of cities on each face (24 elements)."""
    return [len(WELTZEITUHR_FACES[f]) for f in range(24)]


def city_names_concat(city_list):
    """Concatenate city names into one string (alpha only)."""
    return "".join(c for city in city_list for c in city.upper() if c in ALPH_IDX)


def alphabetical_order(city_list):
    """Return permutation that sorts cities alphabetically."""
    indexed = list(enumerate(city_list))
    indexed.sort(key=lambda x: x[1])
    return [i for i, _ in indexed]


def main():
    t0 = time_mod.time()
    random.seed(128)
    print("=" * 70)
    print("E-S-128: Weltzeituhr City-Name-Derived Keys")
    print("=" * 70)

    # ── Verify city data ──────────────────────────────────────────────────
    all_cities = get_all_cities_ordered()
    city_counts = get_city_counts()
    total_cities = sum(city_counts)
    print(f"Total cities extracted: {total_cities} (expected ~146)")
    print(f"Cities per face: {city_counts}")
    print(f"City count sum: {total_cities}")

    # The DC face (face 7, UTC-5)
    dc_face = WELTZEITUHR_FACES[7]
    berlin_face = WELTZEITUHR_FACES[13]
    print(f"\n*** DC face (UTC-5): {len(dc_face)} cities = {dc_face}")
    print(f"*** Berlin face (UTC+1): {len(berlin_face)} cities")
    print(f"*** DC face has {len(dc_face)} cities — {'MATCHES' if len(dc_face) == 7 else 'DOES NOT MATCH'} width 7!")

    results = []
    best_overall = 0
    total_tested = 0

    # ── Phase 1: DC-face 7 cities as period-7 key ─────────────────────────
    print("\n--- Phase 1: DC-face 7 cities as period-7 key ---")
    phase1_best = 0

    dc_initials = get_city_initials(dc_face)  # "MWNPBQL"
    print(f"  DC face initials: {dc_initials}")
    dc_initials_key = make_key(dc_initials)
    print(f"  DC initials numeric: {dc_initials_key}")

    # Alphabetical ordering of DC cities
    dc_alpha_order = alphabetical_order(dc_face)
    print(f"  DC alphabetical order: {dc_alpha_order} = {[dc_face[i] for i in dc_alpha_order]}")

    # Multiple key derivations from DC face cities
    dc_keys = {
        "dc_initials": dc_initials_key,                           # M,W,N,P,B,Q,L
        "dc_initials_reversed": dc_initials_key[::-1],            # L,Q,B,P,N,W,M
        "dc_alpha_order": dc_alpha_order,                          # Alphabetical permutation
        "dc_alpha_initials": [make_key(dc_face[i])[0] for i in dc_alpha_order],  # Initials in alpha order
        "dc_name_lengths": [len(c.replace(" ", "")) for c in dc_face],  # Name lengths
        "dc_name_lengths_mod26": [len(c.replace(" ", "")) % 26 for c in dc_face],
        "dc_full_name": make_key("".join(dc_face)),                # All names concatenated
        "dc_second_letters": [make_key(c)[1] if len(make_key(c)) > 1 else 0 for c in dc_face],
        "dc_last_letters": [make_key(c)[-1] for c in dc_face],    # Last letters
    }

    # Also test permutations: DC alpha order as w7 columnar ordering
    dc_alpha_perm_key = dc_alpha_order  # This IS a permutation of 0-6
    if len(set(dc_alpha_perm_key)) == 7 and max(dc_alpha_perm_key) == 6:
        dc_keys["dc_alpha_as_w7_perm"] = dc_alpha_perm_key

    # Test DC-derived keys directly (no transposition)
    for key_name, key in dc_keys.items():
        if not key or max(key) >= 26 or min(key) < 0:
            # Fix: ensure key values are in range
            key = [k % 26 for k in key]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase1_best:
                phase1_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "dc_key_direct",
                    "key_name": key_name,
                    "variant": variant.value,
                    "score": sc,
                })
        # Print each key's best
        best_for_key = max(
            score_cribs(decrypt_text(CT, [k % 26 for k in key], v))
            for v in CipherVariant
        )
        if best_for_key > 3:
            print(f"  {key_name}: {[k % 26 for k in key]} → best {best_for_key}/24")

    if phase1_best > best_overall:
        best_overall = phase1_best
    print(f"  Phase 1 best: {phase1_best}/24")

    # ── Phase 2: DC-face keys + w7 columnar ───────────────────────────────
    print("\n--- Phase 2: DC-face keys + w7 columnar (5040 orderings) ---")
    phase2_best = 0

    # Test ALL w7 orderings with DC-derived keys
    all_w7 = list(itertools.permutations(range(7)))
    print(f"  Testing {len(all_w7)} w7 orderings × {len(dc_keys)} DC keys × 3 variants")

    for col_order in all_w7:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for key_name, key in dc_keys.items():
            key_mod = [k % 26 for k in key]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(ct_untrans, key_mod, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase2_best:
                    phase2_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "phase": "dc_key_w7",
                        "key_name": key_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

        # Also Model A (sub then trans)
        for key_name in ["dc_initials", "dc_full_name", "dc_alpha_initials"]:
            key_mod = [k % 26 for k in dc_keys[key_name]]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt_sub = decrypt_text(CT, key_mod, variant)
                pt = apply_perm(pt_sub, inv)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase2_best:
                    phase2_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "phase": "dc_key_w7_modelA",
                        "key_name": key_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase2_best > best_overall:
        best_overall = phase2_best
    print(f"  Phase 2 best: {phase2_best}/24")

    # ── Phase 3: DC alpha order as the w7 transposition ───────────────────
    print("\n--- Phase 3: DC alphabetical order AS the w7 transposition ---")
    phase3_best = 0

    # The alphabetical ordering of the 7 DC cities IS a permutation of {0..6}
    # Use this as the columnar transposition key
    dc_w7_perm = columnar_perm(7, dc_alpha_order, CT_LEN)
    dc_w7_inv = invert_perm(dc_w7_perm)
    ct_dc_untrans = apply_perm(CT, dc_w7_inv)

    # Test with many substitution keys
    sub_keys_phase3 = {
        "KRYPTOS": make_key("KRYPTOS"),
        "PALIMPCEST": make_key("PALIMPCEST"),
        "ABSCISSA": make_key("ABSCISSA"),
        "BERLINCLOCK": make_key("BERLINCLOCK"),
        "WELTZEITUHR": make_key("WELTZEITUHR"),
        "URANIA": make_key("URANIA"),
        "COORD_MOD26": [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]],
        "dc_initials": dc_initials_key,
        "berlin_initials": make_key(get_city_initials(berlin_face)),
        "identity": [0],
    }

    # Also test Berlin-face city initials as substitution keys
    berlin_initials = get_city_initials(berlin_face)
    print(f"  Berlin face initials: {berlin_initials}")
    sub_keys_phase3["berlin_initials_full"] = make_key(berlin_initials)

    for key_name, key in sub_keys_phase3.items():
        for variant in CipherVariant:
            # Model B
            pt = decrypt_text(ct_dc_untrans, key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase3_best:
                phase3_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "dc_alpha_w7_trans",
                    "key": key_name,
                    "variant": variant.value,
                    "score": sc,
                    "model": "B",
                })

            # Model A
            pt_sub = decrypt_text(CT, key, variant)
            pt = apply_perm(pt_sub, dc_w7_inv)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase3_best:
                phase3_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "dc_alpha_w7_trans",
                    "key": key_name,
                    "variant": variant.value,
                    "score": sc,
                    "model": "A",
                })

    if phase3_best > best_overall:
        best_overall = phase3_best
    print(f"  DC-alpha as w7 trans + various sub keys: {phase3_best}/24")

    # ── Phase 4: City counts per face as numeric key ──────────────────────
    print("\n--- Phase 4: City counts per face as numeric key ---")
    phase4_best = 0

    count_key = city_counts  # 24-element key
    count_key_mod26 = [c % 26 for c in count_key]
    print(f"  City counts: {count_key}")

    # Also: nonzero counts only, or cumulative counts
    nonzero_counts = [c for c in count_key if c > 0]
    cumulative_counts = []
    cum = 0
    for c in count_key:
        cum += c
        cumulative_counts.append(cum % 26)

    count_keys = {
        "counts_24": count_key_mod26,
        "counts_nonzero": [c % 26 for c in nonzero_counts],
        "counts_cumulative": cumulative_counts,
        "counts_reversed": count_key_mod26[::-1],
        # Count difference between adjacent faces
        "counts_diff": [(count_key[(i+1)%24] - count_key[i]) % 26 for i in range(24)],
    }

    for key_name, key in count_keys.items():
        for variant in CipherVariant:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase4_best:
                phase4_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "city_counts",
                    "key_name": key_name,
                    "variant": variant.value,
                    "score": sc,
                })

    # Count keys + w7 columnar (sampled)
    w7_sample = [tuple(random.sample(range(7), 7)) for _ in range(500)]
    w7_sample.append(tuple(range(7)))

    for col_order in w7_sample:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for key_name in ["counts_24", "counts_nonzero", "counts_cumulative"]:
            key = count_keys[key_name]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase4_best:
                    phase4_best = sc

    if phase4_best > best_overall:
        best_overall = phase4_best
    print(f"  Phase 4 best: {phase4_best}/24")

    # ── Phase 5: All city initials as running key ─────────────────────────
    print("\n--- Phase 5: City initials / names as running key ---")
    phase5_best = 0

    all_cities = get_all_cities_ordered()
    all_initials = get_city_initials(all_cities)
    all_names = city_names_concat(all_cities)
    print(f"  All initials ({len(all_initials)} chars): {all_initials[:50]}...")
    print(f"  All names concatenated: {len(all_names)} chars")

    # Also: initials starting from Berlin face, DC face, GMT face
    def rotated_initials(start_face):
        cities = []
        for i in range(24):
            f = (start_face + i) % 24
            cities.extend(WELTZEITUHR_FACES[f])
        return get_city_initials(cities)

    rk_sources = {
        "initials_from_utc-12": all_initials,
        "initials_from_berlin": rotated_initials(13),
        "initials_from_dc": rotated_initials(7),
        "initials_from_gmt": rotated_initials(12),
        "names_from_utc-12": all_names,
        "names_from_berlin": city_names_concat(
            [c for i in range(24) for c in WELTZEITUHR_FACES[(13+i)%24]]
        ),
        "names_from_dc": city_names_concat(
            [c for i in range(24) for c in WELTZEITUHR_FACES[(7+i)%24]]
        ),
        # Berlin face names only (18 cities, cycled)
        "berlin_face_names": city_names_concat(berlin_face),
        # DC face names only (7 cities, cycled = period 7!)
        "dc_face_names": city_names_concat(dc_face),
    }

    for rk_name, rk_text in rk_sources.items():
        if len(rk_text) < 7:
            continue
        rk_key = make_key(rk_text)
        # Cycle to CT length
        if len(rk_key) < CT_LEN:
            rk_key = (rk_key * ((CT_LEN // len(rk_key)) + 1))[:CT_LEN]
        else:
            rk_key = rk_key[:CT_LEN]

        for variant in CipherVariant:
            pt = decrypt_text(CT, rk_key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase5_best:
                phase5_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "running_key",
                    "source": rk_name,
                    "variant": variant.value,
                    "score": sc,
                })

    # Running keys + w7 columnar
    for col_order in w7_sample[:300]:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for rk_name in ["initials_from_berlin", "dc_face_names", "names_from_dc"]:
            rk_text = rk_sources[rk_name]
            rk_key = make_key(rk_text)
            if len(rk_key) < CT_LEN:
                rk_key = (rk_key * ((CT_LEN // len(rk_key)) + 1))[:CT_LEN]
            else:
                rk_key = rk_key[:CT_LEN]

            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, rk_key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase5_best:
                    phase5_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "phase": "running_key_w7",
                        "source": rk_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase5_best > best_overall:
        best_overall = phase5_best
    print(f"  Phase 5 best: {phase5_best}/24")

    # ── Phase 6: Berlin+DC face pair derived keys ─────────────────────────
    print("\n--- Phase 6: Berlin-DC face pair derived keys ---")
    phase6_best = 0

    # Interleave Berlin and DC face initials
    b_init = get_city_initials(berlin_face)
    d_init = get_city_initials(dc_face)
    print(f"  Berlin initials: {b_init} ({len(b_init)} chars)")
    print(f"  DC initials: {d_init} ({len(d_init)} chars)")

    # XOR / add / subtract Berlin and DC initials
    b_key = make_key(b_init)
    d_key = make_key(d_init)

    pair_keys = {}
    # Use shorter key (DC=7) cycling against longer (Berlin=18)
    for i in range(7):
        pass  # Keys generated below

    # DC initials XOR Berlin initials (mod 26)
    pair_keys["dc_xor_berlin"] = [(d_key[i % 7] + b_key[i % 18]) % 26 for i in range(97)]
    pair_keys["berlin_xor_dc"] = [(b_key[i % 18] + d_key[i % 7]) % 26 for i in range(97)]
    pair_keys["dc_sub_berlin"] = [(d_key[i % 7] - b_key[i % 18]) % 26 for i in range(97)]
    pair_keys["berlin_sub_dc"] = [(b_key[i % 18] - d_key[i % 7]) % 26 for i in range(97)]

    # Interleaved: D B D B D B D B D B...
    interleaved = []
    for i in range(max(len(b_key), len(d_key))):
        if i < len(d_key):
            interleaved.append(d_key[i])
        if i < len(b_key):
            interleaved.append(b_key[i])
    pair_keys["interleaved_db"] = interleaved

    # Berlin face names as period-18 key
    pair_keys["berlin_names_p18"] = make_key(city_names_concat(berlin_face))

    for key_name, key in pair_keys.items():
        if len(key) < CT_LEN:
            key = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
        else:
            key = key[:CT_LEN]

        for variant in CipherVariant:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase6_best:
                phase6_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "pair_key",
                    "key_name": key_name,
                    "variant": variant.value,
                    "score": sc,
                })

    # Pair keys + w7 columnar
    for col_order in w7_sample[:300]:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for key_name in ["dc_xor_berlin", "berlin_sub_dc", "interleaved_db"]:
            key = pair_keys[key_name]
            if len(key) < CT_LEN:
                key = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
            else:
                key = key[:CT_LEN]

            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase6_best:
                    phase6_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "phase": "pair_key_w7",
                        "key_name": key_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase6_best > best_overall:
        best_overall = phase6_best
    print(f"  Phase 6 best: {phase6_best}/24")

    # ── Phase 7: DC face city names as keyword alphabet ───────────────────
    print("\n--- Phase 7: City names as keyword-mixed alphabets ---")
    phase7_best = 0

    def keyword_alphabet(keyword):
        """Generate keyword-mixed alphabet from keyword."""
        seen = set()
        result = []
        for c in keyword.upper():
            if c in ALPH_IDX and c not in seen:
                seen.add(c)
                result.append(c)
        for c in ALPH:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return "".join(result)

    def decrypt_with_mixed_alpha(ct, key, mixed_alpha):
        """Decrypt using a mixed alphabet for substitution."""
        # Create mapping: mixed_alpha[i] represents the letter at position i
        # To decrypt: convert CT through mixed alpha, then apply key
        alpha_map = {mixed_alpha[i]: i for i in range(26)}
        result = []
        for i, c in enumerate(ct):
            c_idx = alpha_map.get(c, ALPH_IDX.get(c, 0))
            k = key[i % len(key)]
            p_idx = (c_idx - k) % 26
            result.append(ALPH[p_idx])
        return "".join(result)

    # Keyword alphabets from city names
    keyword_alphas = {
        "dc_names": keyword_alphabet("".join(dc_face)),
        "berlin_names": keyword_alphabet("".join(berlin_face)),
        "kryptos": keyword_alphabet("KRYPTOS"),
        "berlinclock": keyword_alphabet("BERLINCLOCK"),
        "weltzeituhr": keyword_alphabet("WELTZEITUHR"),
        "washington": keyword_alphabet("WASHINGTON"),
    }

    for alpha_name, mixed_alpha in keyword_alphas.items():
        for key_name in ["dc_initials", "dc_alpha_initials", "dc_name_lengths"]:
            key = dc_keys[key_name]
            key_mod = [k % 26 for k in key]
            pt = decrypt_with_mixed_alpha(CT, key_mod, mixed_alpha)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase7_best:
                phase7_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "phase": "mixed_alpha",
                    "alphabet": alpha_name,
                    "key": key_name,
                    "score": sc,
                })

    # Mixed alphabets + w7 columnar (sampled)
    for col_order in w7_sample[:200]:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for alpha_name, mixed_alpha in keyword_alphas.items():
            for key_name in ["dc_initials", "dc_full_name"]:
                key = dc_keys[key_name]
                key_mod = [k % 26 for k in key]
                pt = decrypt_with_mixed_alpha(ct_untrans, key_mod, mixed_alpha)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase7_best:
                    phase7_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "phase": "mixed_alpha_w7",
                        "alphabet": alpha_name,
                        "key": key_name,
                        "col_order": list(col_order),
                        "score": sc,
                    })

    if phase7_best > best_overall:
        best_overall = phase7_best
    print(f"  Phase 7 best: {phase7_best}/24")

    # ── Phase 8: Time-specific number-to-face mapping ─────────────────────
    print("\n--- Phase 8: Specific time mappings ---")
    phase8_best = 0

    # Key times (Berlin local time):
    # - Berlin Wall opening: 23:30 on Nov 9, 1989 → hour 23 or 24
    # - K4 installation: 1990 → various times
    # - Sanborn's Egypt trip: 1986
    # For each time, the rotating hour ring maps numbers to faces differently.
    # At time H (Berlin), number H appears at the Berlin face (face 13).
    # So number N appears at face (13 + N - H) % 24.

    key_times = {
        "wall_2330": 23,   # Berlin Wall opening 23:30
        "wall_midnight": 24,  # = 0
        "noon": 12,
        "1am": 1,          # UTC+1 = 1:00 at Berlin
        "7pm_dc_noon": 19, # When it's noon in DC, it's 19:00 (7 PM) in Berlin
        # At time H in Berlin, the number at the DC face (face 7) is:
        # (H + 7 - 13) % 24 = (H - 6) % 24
    }

    for time_name, berlin_hour in key_times.items():
        # At this time, the number-to-face mapping is:
        # Number N is at face (13 + N - berlin_hour) % 24
        # Or equivalently: face F has number (berlin_hour + F - 13) % 24
        face_numbers = [(berlin_hour + f - 13) % 24 for f in range(24)]
        # This gives us a permutation of {0..23}
        if face_numbers[0] == 0:
            face_numbers = [(n if n != 0 else 24) for n in face_numbers]
        # Normalize to 0-23
        face_numbers_norm = [n % 24 for n in face_numbers]

        # Use face numbers as reading order
        if len(set(face_numbers_norm)) == 24:
            reading_order = sorted(range(24), key=lambda f: face_numbers_norm[f])
            perm = columnar_perm(24, reading_order, CT_LEN)
            if len(perm) == CT_LEN and len(set(perm)) == CT_LEN:
                inv = invert_perm(perm)
                ct_untrans = apply_perm(CT, inv)

                for key_name in ["dc_initials", "dc_full_name"]:
                    key = [k % 26 for k in dc_keys[key_name]]
                    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                        pt = decrypt_text(ct_untrans, key, variant)
                        sc = score_cribs(pt)
                        total_tested += 1
                        if sc > phase8_best:
                            phase8_best = sc

    if phase8_best > best_overall:
        best_overall = phase8_best
    print(f"  Phase 8 best: {phase8_best}/24")

    # ── Phase 9: Comprehensive DC+Berlin combined with exhaustive w7 ──────
    print("\n--- Phase 9: Top DC-derived keys × ALL 5040 w7 orderings (decisive) ---")
    phase9_best = 0
    phase9_best_config = None

    # The most promising DC-derived keys
    top_dc_keys = {
        "dc_initials": dc_initials_key,  # [12,22,13,15,1,16,11] = MWNPBQL
        "dc_last_letters": dc_keys["dc_last_letters"],
        "dc_name_lengths": dc_keys["dc_name_lengths"],
        "dc_second_letters": dc_keys["dc_second_letters"],
    }

    # Also: variations on DC initials
    # Rotate the 7 initials
    for rot in range(1, 7):
        rotated = dc_initials_key[rot:] + dc_initials_key[:rot]
        top_dc_keys[f"dc_initials_rot{rot}"] = rotated

    for col_order in all_w7:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for key_name, key in top_dc_keys.items():
            key_mod = [k % 26 for k in key]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(ct_untrans, key_mod, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase9_best:
                    phase9_best = sc
                    phase9_best_config = {
                        "key": key_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                        "key_values": key_mod,
                    }
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "phase": "dc_exhaustive_w7",
                        "key_name": key_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase9_best > best_overall:
        best_overall = phase9_best
    print(f"  Phase 9 best: {phase9_best}/24")
    if phase9_best_config:
        print(f"  Best config: {phase9_best_config}")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time_mod.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Results above noise: {len([r for r in results if r['score'] > NOISE_FLOOR])}")
    print(f"Results above store: {len([r for r in results if r['score'] >= STORE_THRESHOLD])}")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["score"])[:20]:
            print(f"  score={r['score']}/24 {r.get('phase','')} key={r.get('key_name',r.get('key',''))} "
                  f"var={r.get('variant','')} order={r.get('col_order','')}")

    # Note on noise thresholds
    print(f"\n  Period-7 noise threshold: ~8.2/24")
    print(f"  Only scores >10/24 are noteworthy at period 7")

    verdict = "SIGNAL" if best_overall >= 18 else ("STORE" if best_overall > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    if best_overall <= 8:
        print("DC-face-derived keys produce NO signal above noise at period 7.")
        print("The 7-city coincidence is likely just that — a coincidence.")
    elif best_overall <= STORE_THRESHOLD:
        print("Marginal results — log for investigation but likely noise.")
    else:
        print("*** SIGNAL DETECTED — investigate immediately! ***")

    artifact = {
        "experiment_id": "e_s_128",
        "stage": 4,
        "hypothesis": "Weltzeituhr city names (esp. DC face = 7 cities) provide K4 key material",
        "parameters_source": "Photographs of Urania Weltzeituhr, 7 images",
        "clock": "Urania Weltzeituhr, Alexanderplatz, Berlin",
        "sanborn_quotes": [
            "You'd better delve into that particular clock",
            "There's a lot of fodder there",
        ],
        "dc_face_cities": dc_face,
        "dc_face_count": len(dc_face),
        "berlin_face_cities": berlin_face,
        "berlin_face_count": len(berlin_face),
        "total_cities_extracted": total_cities,
        "total_tested": total_tested,
        "best_score": best_overall,
        "best_config": phase9_best_config,
        "above_noise": [r for r in results if r["score"] > NOISE_FLOOR][:50],
        "above_store": [r for r in results if r["score"] >= STORE_THRESHOLD][:50],
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "photo_sources": [f"reference/Pictures/Urania_{i}.jpg" for i in range(1, 8)],
        "note": (
            "DC face (UTC-5) has exactly 7 cities: MONTREAL, WASHINGTON, NEW YORK, "
            "PANAMA, BOGOTA, QUITO, LIMA. This connects to the width-7 hypothesis. "
            "However, ~8 cities visible on photos that may be missing from far-east panels."
        ),
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_128_weltzeituhr_cities.py",
    }

    out_path = "artifacts/progressive_solve/stage4/weltzeituhr_cities_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
