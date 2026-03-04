#!/usr/bin/env python3
"""
Cipher: Berlin clock
Family: thematic/berlin_clock
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-134: DDR-era (1989/1990) Weltzeituhr city list as K4 key material.

Sanborn visited Berlin around 1989. The Urania Weltzeituhr was DIFFERENT then:
- 1997 overhaul added ~20 cities omitted "for political reasons" (DDR)
- City names were DDR-era German forms (Leningrad, Alma-Ata)
- Kiew was under Moscow time (UTC+3), not UTC+2

This experiment reconstructs the 1989 city list and tests it as key material,
then compares against the modern (post-1997) list. This is the formal A/B test
from the H0/H1/H2 Weltzeituhr hypothesis framework:
  U-model = DDR-era list (what Sanborn actually saw)
  G-model = modern list (post-1997 updates)

If U-model outperforms G-model, that supports H2 (Weltzeituhr-specific mechanism).
If both produce noise, stop rule S2 fires (downgrade to H0).

Tests (mirroring e_s_128):
  (a) Face initials as keys (all faces, Berlin, DC, various starting faces)
  (b) City names concatenated as running keys
  (c) City counts per face as numeric keys
  (d) DC-face cities as period-N key (N = number of cities on DC face)
  (e) Berlin-face cities as keyword alphabets
  (f) All keys × w7 columnar transposition (5040 orderings)
  (g) Face-pair derived keys (Berlin + DC cross-products)
  (h) DDR-specific: Leningrad, Alma-Ata, Pjoengjang face initials

Output: results/e_s_134_weltzeituhr_ddr.json
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


# ═══════════════════════════════════════════════════════════════════════════════
# MODERN (POST-1997) CITY LIST — from Hungarian Wikipedia, comprehensive
# Organized by face (0-23), face 0 = UTC-12 (Date Line)
# ═══════════════════════════════════════════════════════════════════════════════

MODERN_FACES = {
    0: ["DATUMSGRENZE"],
    1: ["KAP DESCHNEW", "APIA"],
    2: ["HONOLULU", "MARQUESAS INSELN"],
    3: ["NOME", "FAIRBANKS", "ANCHORAGE"],
    4: ["VANCOUVER", "DAWSON", "SAN FRANCISCO", "LOS ANGELES"],
    5: ["EDMONTON", "DENVER"],
    6: ["NEW ORLEANS", "MEXIKO STADT", "GUATEMALA STADT", "MANAGUA",
        "GALAPAGOS INSELN"],
    7: ["MONTREAL", "WASHINGTON", "NEW YORK", "HAVANNA",
        "PANAMA", "SANTAFE DE BOGOTA", "QUITO", "LIMA"],
    8: ["HALIFAX", "CARACAS", "LA PAZ", "ASUNCION", "SANTIAGO DE CHILE"],
    9: ["WESTGROENLAND", "BRASILIA", "RIO DE JANEIRO",
        "SAO PAULO", "MONTEVIDEO", "BUENOS AIRES"],
    10: ["OSTGROENLAND"],
    11: ["AZOREN", "KAP VERDE"],
    12: ["REYKJAVIK", "DUBLIN", "LONDON", "LISSABON", "MADEIRA",
         "BISSAU", "CASABLANCA", "CONAKRY", "DAKAR", "BAMAKO", "ACCRA"],
    13: ["AMSTERDAM", "BERLIN", "BRUESSEL", "BUDAPEST", "MADRID",
         "PARIS", "PRAG", "STOCKHOLM", "WARSCHAU",
         "OSLO", "KOPENHAGEN", "WIEN", "BERN", "PRESSBURG",
         "BELGRAD", "ROM", "TUNIS", "KINSHASA"],
    14: ["HELSINKI", "RIGA", "TALLINN", "WILNA", "MINSK",
         "KIEW", "BUKAREST", "SOFIA", "NIKOSIA",
         "ANKARA", "ISTANBUL", "ATHEN", "TEL AVIV", "JERUSALEM",
         "BEIRUT", "DAMASKUS", "KAIRO", "KAPSTADT"],
    15: ["MURMANSK", "ST PETERSBURG", "MOSKAU",
         "TEHERAN", "BAGDAD", "ADEN", "SANAA", "ADDIS ABEBA",
         "MOGADISCHU", "DARESSALAM", "ANTANANARIVO", "KUWAIT"],
    16: ["NISCHNIJ NOWGOROD", "WOLGOGRAD", "BAKU", "TIFLIS", "ERIWAN",
         "KABUL", "MAURITIUS"],
    17: ["JEKATERINBURG", "ASCHGABAT", "BISCHKEK", "DUSCHANBE",
         "NEW DELHI", "KARACHI", "COLOMBO"],
    18: ["OMSK", "ALMATY", "TASCHKENT", "NOWOSIBIRSK",
         "RANGUN", "DHAKA"],
    19: ["KRASNOJARSK", "HANOI", "BANGKOK", "PHNOM PENH", "JAKARTA"],
    20: ["IRKUTSK", "ULAN BATOR", "PEKING", "SHANGHAI", "MANILA",
         "PERTH", "HONGKONG", "KUALA LUMPUR", "SINGAPUR"],
    21: ["JAKUTSK", "PJOENGJANG", "TOKIO", "SEOUL",
         "CHABAROWSK", "WLADIWOSTOK", "SYDNEY", "CANBERRA", "MELBOURNE"],
    22: ["MAGADAN", "SACHALIN"],
    23: ["KAMTSCHATKA", "WELLINGTON"],
}


# ═══════════════════════════════════════════════════════════════════════════════
# DDR-ERA (1989/1990) RECONSTRUCTION
#
# Documented 1997 changes (sources: German Wikipedia, Deutschlandfunk):
# 1. Leningrad → St. Petersburg
# 2. Alma-Ata → Almaty
# 3. ~20 cities ADDED that were "omitted for political reasons"
#    Confirmed additions: Tel Aviv, Jerusalem, Kapstadt, Seoul
#    Probable additions (DDR didn't recognize / had hostile relations):
#      - Havanna stays (Cuba was DDR ally)
#      - Pjoengjang stays (DPRK was DDR ally)
#      - Seoul removed (South Korea not recognized by DDR)
#      - Tel Aviv/Jerusalem removed (Israel not recognized by DDR)
#      - Kapstadt removed (apartheid South Africa)
#      - Santafe de Bogota: possibly missing (renamed from Bogota in 1991)
#    Less certain removals (testing both with/without):
#      - Taipei was never on the clock
#      - West German cities: none on clock (Berlin was East Berlin)
# 4. Kiew moved from UTC+3 (Moscow time) to UTC+2
# 5. Nischnij Nowgorod was Gorki until 1990
# ═══════════════════════════════════════════════════════════════════════════════

# Cities CONFIRMED or highly likely added in 1997 (not present in DDR era)
CITIES_ADDED_1997 = {
    "TEL AVIV", "JERUSALEM", "KAPSTADT", "SEOUL",
    # Probable: these reflect post-Cold-War geopolitics
    "CANBERRA",        # Australia - not hostile but possibly omitted
    "WELLINGTON",      # NZ - same logic
    "SANTAFE DE BOGOTA",  # Was just "Bogota" pre-1991, may have been present as BOGOTA
}

# Conservative set: only the 4 confirmed removals
CITIES_ADDED_1997_CONFIRMED = {
    "TEL AVIV", "JERUSALEM", "KAPSTADT", "SEOUL",
}

# DDR-era name replacements (modern → DDR)
DDR_NAME_MAP = {
    "ST PETERSBURG": "LENINGRAD",
    "ALMATY": "ALMA ATA",
    "NISCHNIJ NOWGOROD": "GORKI",
    "SANTAFE DE BOGOTA": "BOGOTA",
}


def build_ddr_faces(removal_set):
    """Build DDR-era face list by reverting 1997 changes."""
    ddr = {}
    for face_idx, cities in MODERN_FACES.items():
        ddr_cities = []
        for city in cities:
            if city in removal_set:
                continue
            # Apply name reversions
            ddr_name = DDR_NAME_MAP.get(city, city)
            ddr_cities.append(ddr_name)
        ddr[face_idx] = ddr_cities

    # Move Kiew from UTC+2 (face 14) to UTC+3 (face 15) — Moscow time
    if "KIEW" in ddr[14]:
        ddr[14].remove("KIEW")
        # Insert after Moskau
        moskau_idx = next((i for i, c in enumerate(ddr[15]) if c == "MOSKAU"), len(ddr[15]))
        ddr[15].insert(moskau_idx + 1, "KIEW")

    return ddr


# Build two DDR variants: conservative (4 removals) and expanded (~7 removals)
DDR_FACES_CONSERVATIVE = build_ddr_faces(CITIES_ADDED_1997_CONFIRMED)
DDR_FACES_EXPANDED = build_ddr_faces(CITIES_ADDED_1997)


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def make_key(text):
    """Convert text to numeric key (A=0..Z=25)."""
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


def get_all_cities(faces):
    """All cities clockwise from face 0."""
    cities = []
    for f in range(24):
        cities.extend(faces.get(f, []))
    return cities


def get_city_initials(city_list):
    """First letter of each city."""
    return "".join(c[0] for c in city_list if c and c[0] in ALPH_IDX)


def get_city_counts(faces):
    """Number of cities on each face."""
    return [len(faces.get(f, [])) for f in range(24)]


def city_names_concat(city_list):
    """Concatenate city names, alpha only."""
    return "".join(c for city in city_list for c in city.upper() if c in ALPH_IDX)


def keyword_alphabet(keyword):
    """Generate keyword-mixed alphabet."""
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


def rotated_initials(faces, start_face):
    """City initials starting from a given face, wrapping around."""
    cities = []
    for i in range(24):
        f = (start_face + i) % 24
        cities.extend(faces.get(f, []))
    return get_city_initials(cities)


def decrypt_with_mixed_alpha(ct, key, mixed_alpha):
    """Decrypt using a mixed alphabet for substitution."""
    alpha_map = {mixed_alpha[i]: i for i in range(26)}
    result = []
    for i, c in enumerate(ct):
        c_idx = alpha_map.get(c, ALPH_IDX.get(c, 0))
        k = key[i % len(key)]
        p_idx = (c_idx - k) % 26
        result.append(ALPH[p_idx])
    return "".join(result)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST BATTERY — runs the same tests for a given face model
# ═══════════════════════════════════════════════════════════════════════════════

def run_test_battery(faces, model_name, all_w7, w7_sample):
    """Run full test battery for a city face model. Returns (best_score, results, total_tested)."""
    results = []
    best_overall = 0
    total_tested = 0

    all_cities = get_all_cities(faces)
    city_counts = get_city_counts(faces)
    total_cities = sum(city_counts)

    # Identify key faces
    dc_face = faces.get(7, [])       # UTC-5
    berlin_face = faces.get(13, [])  # UTC+1
    moscow_face = faces.get(15, [])  # UTC+3

    print(f"\n  [{model_name}] Total cities: {total_cities}")
    print(f"  [{model_name}] DC face ({len(dc_face)}): {dc_face}")
    print(f"  [{model_name}] Berlin face ({len(berlin_face)}): {berlin_face[:5]}...")
    print(f"  [{model_name}] Moscow face ({len(moscow_face)}): {moscow_face[:5]}...")

    # ── Phase 1: Face initials as keys ────────────────────────────────────
    phase_best = 0
    dc_initials = get_city_initials(dc_face)
    berlin_initials = get_city_initials(berlin_face)
    moscow_initials = get_city_initials(moscow_face)

    print(f"  [{model_name}] DC initials: {dc_initials}")
    print(f"  [{model_name}] Berlin initials: {berlin_initials}")
    print(f"  [{model_name}] Moscow initials: {moscow_initials}")

    # Build key derivations from DC face
    dc_keys = {}
    if dc_face:
        dc_init_key = make_key(dc_initials)
        dc_keys["dc_initials"] = dc_init_key
        dc_keys["dc_initials_rev"] = dc_init_key[::-1]
        dc_keys["dc_full_name"] = make_key("".join(dc_face))
        dc_keys["dc_name_lengths"] = [len(c.replace(" ", "")) % 26 for c in dc_face]
        dc_keys["dc_last_letters"] = [make_key(c)[-1] for c in dc_face if make_key(c)]
        dc_keys["dc_second_letters"] = [make_key(c)[1] if len(make_key(c)) > 1 else 0 for c in dc_face]

    # Berlin face keys
    berlin_keys = {}
    if berlin_face:
        b_init_key = make_key(berlin_initials)
        berlin_keys["berlin_initials"] = b_init_key
        berlin_keys["berlin_full_name"] = make_key("".join(berlin_face))

    # Moscow face keys (DDR-specific: includes Leningrad/Kiew)
    moscow_keys = {}
    if moscow_face:
        m_init_key = make_key(moscow_initials)
        moscow_keys["moscow_initials"] = m_init_key
        moscow_keys["moscow_full_name"] = make_key("".join(moscow_face))

    # All keys to test directly (no transposition)
    all_face_keys = {}
    all_face_keys.update(dc_keys)
    all_face_keys.update(berlin_keys)
    all_face_keys.update(moscow_keys)

    # Running keys from various starting faces
    rk_keys = {}
    for start_name, start_face_idx in [("utc0", 0), ("berlin", 13), ("dc", 7),
                                         ("gmt", 12), ("moscow", 15)]:
        initials = rotated_initials(faces, start_face_idx)
        if initials:
            rk_keys[f"initials_from_{start_name}"] = make_key(initials)
        names = city_names_concat(
            [c for i in range(24) for c in faces.get((start_face_idx + i) % 24, [])]
        )
        if names:
            rk_keys[f"names_from_{start_name}"] = make_key(names)

    # City counts as keys
    count_keys = {
        "counts_24": [c % 26 for c in city_counts],
        "counts_nonzero": [c % 26 for c in city_counts if c > 0],
        "counts_cumulative": [],
    }
    cum = 0
    for c in city_counts:
        cum += c
        count_keys["counts_cumulative"].append(cum % 26)
    count_keys["counts_diff"] = [
        (city_counts[(i + 1) % 24] - city_counts[i]) % 26 for i in range(24)
    ]

    # ── Test all keys directly ────────────────────────────────────────────
    all_test_keys = {}
    all_test_keys.update(all_face_keys)
    all_test_keys.update(count_keys)

    for key_name, key in all_test_keys.items():
        if not key:
            continue
        key_mod = [k % 26 for k in key]
        for variant in CipherVariant:
            # Cycle key if shorter than CT
            full_key = (key_mod * ((CT_LEN // len(key_mod)) + 1))[:CT_LEN]
            pt = decrypt_text(CT, full_key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase_best:
                phase_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "model": model_name, "phase": "direct",
                    "key_name": key_name, "variant": variant.value,
                    "score": sc,
                })

    # Running keys direct
    for rk_name, rk_key in rk_keys.items():
        if not rk_key or len(rk_key) < 7:
            continue
        full_key = (rk_key * ((CT_LEN // len(rk_key)) + 1))[:CT_LEN] if len(rk_key) < CT_LEN else rk_key[:CT_LEN]
        for variant in CipherVariant:
            pt = decrypt_text(CT, full_key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase_best:
                phase_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "model": model_name, "phase": "running_key_direct",
                    "key_name": rk_name, "variant": variant.value,
                    "score": sc,
                })

    if phase_best > best_overall:
        best_overall = phase_best
    print(f"  [{model_name}] Direct keys best: {phase_best}/24")

    # ── Phase 2: Keys + w7 columnar (exhaustive for top keys) ─────────────
    phase_best = 0

    # Select top key candidates for exhaustive w7 search
    top_keys = {}
    if dc_keys:
        for k in ["dc_initials", "dc_full_name", "dc_last_letters"]:
            if k in dc_keys:
                top_keys[k] = dc_keys[k]
    if berlin_keys:
        top_keys["berlin_initials"] = berlin_keys["berlin_initials"]
    if moscow_keys:
        top_keys["moscow_initials"] = moscow_keys["moscow_initials"]

    # Also add rotations of DC initials if DC has 7 or 8 cities
    if "dc_initials" in dc_keys:
        base = dc_keys["dc_initials"]
        for rot in range(1, len(base)):
            top_keys[f"dc_initials_rot{rot}"] = base[rot:] + base[:rot]

    for col_order in all_w7:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for key_name, key in top_keys.items():
            key_mod = [k % 26 for k in key]
            full_key = (key_mod * ((CT_LEN // len(key_mod)) + 1))[:CT_LEN]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                # Model B: undo trans then sub
                pt = decrypt_text(ct_untrans, full_key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase_best:
                    phase_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "model": model_name, "phase": "w7_modelB",
                        "key_name": key_name, "col_order": list(col_order),
                        "variant": variant.value, "score": sc,
                    })

        # Model A (sub then trans) for select keys
        for key_name in list(top_keys.keys())[:3]:
            key = top_keys[key_name]
            key_mod = [k % 26 for k in key]
            full_key = (key_mod * ((CT_LEN // len(key_mod)) + 1))[:CT_LEN]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt_sub = decrypt_text(CT, full_key, variant)
                pt = apply_perm(pt_sub, inv)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase_best:
                    phase_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "model": model_name, "phase": "w7_modelA",
                        "key_name": key_name, "col_order": list(col_order),
                        "variant": variant.value, "score": sc,
                    })

    if phase_best > best_overall:
        best_overall = phase_best
    print(f"  [{model_name}] W7 columnar best: {phase_best}/24")

    # ── Phase 3: Running keys + w7 columnar (sampled) ─────────────────────
    phase_best = 0
    for col_order in w7_sample:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for rk_name in list(rk_keys.keys())[:4]:
            rk_key = rk_keys[rk_name]
            if not rk_key or len(rk_key) < 7:
                continue
            full_key = (rk_key * ((CT_LEN // len(rk_key)) + 1))[:CT_LEN] if len(rk_key) < CT_LEN else rk_key[:CT_LEN]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, full_key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase_best:
                    phase_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "model": model_name, "phase": "rk_w7",
                        "key_name": rk_name, "col_order": list(col_order),
                        "variant": variant.value, "score": sc,
                    })

    if phase_best > best_overall:
        best_overall = phase_best
    print(f"  [{model_name}] Running key + w7 best: {phase_best}/24")

    # ── Phase 4: Keyword alphabets from city names ────────────────────────
    phase_best = 0
    kw_alphas = {}
    if dc_face:
        kw_alphas["dc_names"] = keyword_alphabet("".join(dc_face))
    if berlin_face:
        kw_alphas["berlin_names"] = keyword_alphabet("".join(berlin_face))
    if moscow_face:
        kw_alphas["moscow_names"] = keyword_alphabet("".join(moscow_face))
    kw_alphas["kryptos"] = keyword_alphabet("KRYPTOS")
    kw_alphas["weltzeituhr"] = keyword_alphabet("WELTZEITUHR")

    for alpha_name, mixed_alpha in kw_alphas.items():
        for key_name in list(all_face_keys.keys())[:6]:
            key = all_face_keys[key_name]
            if not key:
                continue
            key_mod = [k % 26 for k in key]
            full_key = (key_mod * ((CT_LEN // len(key_mod)) + 1))[:CT_LEN]
            pt = decrypt_with_mixed_alpha(CT, full_key, mixed_alpha)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > phase_best:
                phase_best = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "model": model_name, "phase": "mixed_alpha",
                    "alphabet": alpha_name, "key": key_name,
                    "score": sc,
                })

    # Mixed alpha + w7 (sampled)
    for col_order in w7_sample[:200]:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)
        for alpha_name in list(kw_alphas.keys())[:3]:
            mixed_alpha = kw_alphas[alpha_name]
            for key_name in list(dc_keys.keys())[:2]:
                key = dc_keys[key_name]
                if not key:
                    continue
                key_mod = [k % 26 for k in key]
                full_key = (key_mod * ((CT_LEN // len(key_mod)) + 1))[:CT_LEN]
                pt = decrypt_with_mixed_alpha(ct_untrans, full_key, mixed_alpha)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase_best:
                    phase_best = sc

    if phase_best > best_overall:
        best_overall = phase_best
    print(f"  [{model_name}] Mixed alphabet best: {phase_best}/24")

    # ── Phase 5: Face-pair derived keys ───────────────────────────────────
    phase_best = 0
    if dc_keys and berlin_keys:
        d_key = dc_keys.get("dc_initials", [])
        b_key = berlin_keys.get("berlin_initials", [])
        if d_key and b_key:
            pair_keys = {
                "dc_add_berlin": [(d_key[i % len(d_key)] + b_key[i % len(b_key)]) % 26
                                  for i in range(97)],
                "dc_sub_berlin": [(d_key[i % len(d_key)] - b_key[i % len(b_key)]) % 26
                                  for i in range(97)],
                "berlin_sub_dc": [(b_key[i % len(b_key)] - d_key[i % len(d_key)]) % 26
                                  for i in range(97)],
            }
            # Interleaved
            interleaved = []
            for i in range(max(len(b_key), len(d_key))):
                if i < len(d_key):
                    interleaved.append(d_key[i])
                if i < len(b_key):
                    interleaved.append(b_key[i])
            pair_keys["interleaved_db"] = interleaved

            for key_name, key in pair_keys.items():
                full_key = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN] if len(key) < CT_LEN else key[:CT_LEN]
                for variant in CipherVariant:
                    pt = decrypt_text(CT, full_key, variant)
                    sc = score_cribs(pt)
                    total_tested += 1
                    if sc > phase_best:
                        phase_best = sc
                    if sc > NOISE_FLOOR:
                        results.append({
                            "model": model_name, "phase": "pair_key",
                            "key_name": key_name, "variant": variant.value,
                            "score": sc,
                        })

    if phase_best > best_overall:
        best_overall = phase_best
    print(f"  [{model_name}] Face-pair keys best: {phase_best}/24")

    # ── Phase 6: Time-offset transpositions ───────────────────────────────
    phase_best = 0
    key_times = {
        "wall_2330": 23,
        "wall_midnight": 0,
        "noon": 12,
        "berlin_1am": 1,
        "dc_noon_berlin_6pm": 18,
    }
    for time_name, berlin_hour in key_times.items():
        face_numbers = [(berlin_hour + f - 13) % 24 for f in range(24)]
        if len(set(face_numbers)) == 24:
            reading_order = sorted(range(24), key=lambda f: face_numbers[f])
            perm = columnar_perm(24, reading_order, CT_LEN)
            if len(perm) == CT_LEN and len(set(perm)) == CT_LEN:
                inv = invert_perm(perm)
                ct_untrans = apply_perm(CT, inv)
                for key_name in list(all_face_keys.keys())[:4]:
                    key = all_face_keys[key_name]
                    if not key:
                        continue
                    key_mod = [k % 26 for k in key]
                    full_key = (key_mod * ((CT_LEN // len(key_mod)) + 1))[:CT_LEN]
                    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                        pt = decrypt_text(ct_untrans, full_key, variant)
                        sc = score_cribs(pt)
                        total_tested += 1
                        if sc > phase_best:
                            phase_best = sc

    if phase_best > best_overall:
        best_overall = phase_best
    print(f"  [{model_name}] Time-offset trans best: {phase_best}/24")

    return best_overall, results, total_tested


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    t0 = time_mod.time()
    random.seed(134)

    print("=" * 70)
    print("E-S-134: DDR-era Weltzeituhr City List — Falsification Test")
    print("=" * 70)
    print()
    print("H0: Berlin clock is thematic only (no operational role)")
    print("H1: Clock provides weak constraint (direction, indexing)")
    print("H2: Urania Weltzeituhr specifically required for method")
    print()
    print("Test: Compare DDR-era (1989) list vs modern (post-1997) list")
    print("Stop rule S2: If U-model ≈ G-model, downgrade to H0")
    print()

    # Print DDR-era changes
    print("--- DDR-era reconstruction ---")
    print("Name reversions: St Petersburg→Leningrad, Almaty→Alma-Ata, "
          "Nischnij Nowgorod→Gorki, Santafe de Bogota→Bogota")
    print("Cities removed (confirmed 1997 additions): Tel Aviv, Jerusalem, Kapstadt, Seoul")
    print("Timezone change: Kiew moved from UTC+2 → UTC+3 (Moscow time)")
    print()

    # Precompute w7 orderings
    all_w7 = list(itertools.permutations(range(7)))
    w7_sample = [tuple(random.sample(range(7), 7)) for _ in range(500)]
    w7_sample.append(tuple(range(7)))

    # ── Run test battery for each model ───────────────────────────────────

    models = {
        "DDR_conservative": DDR_FACES_CONSERVATIVE,  # U-model (4 confirmed removals)
        "DDR_expanded": DDR_FACES_EXPANDED,           # U-model (7 removals)
        "Modern": MODERN_FACES,                       # G-model (post-1997)
    }

    model_results = {}
    grand_total = 0

    for model_name, faces in models.items():
        print(f"\n{'='*60}")
        print(f"  MODEL: {model_name}")
        print(f"{'='*60}")
        best, results, tested = run_test_battery(faces, model_name, all_w7, w7_sample)
        model_results[model_name] = {
            "best_score": best,
            "results_above_noise": [r for r in results if r["score"] > NOISE_FLOOR],
            "results_above_store": [r for r in results if r["score"] >= STORE_THRESHOLD],
            "total_tested": tested,
        }
        grand_total += tested
        print(f"\n  [{model_name}] OVERALL BEST: {best}/24  ({tested:,} configs tested)")

    # ── Comparison & Verdict ──────────────────────────────────────────────
    elapsed = time_mod.time() - t0

    print(f"\n{'='*70}")
    print("COMPARISON: DDR-era vs Modern")
    print(f"{'='*70}")

    for name, data in model_results.items():
        print(f"  {name:25s}: best={data['best_score']}/24  "
              f"above_noise={len(data['results_above_noise'])}  "
              f"above_store={len(data['results_above_store'])}  "
              f"tested={data['total_tested']:,}")

    ddr_best = max(model_results["DDR_conservative"]["best_score"],
                   model_results["DDR_expanded"]["best_score"])
    modern_best = model_results["Modern"]["best_score"]

    print(f"\n  DDR-era best:  {ddr_best}/24")
    print(f"  Modern best:   {modern_best}/24")
    print(f"  Difference:    {ddr_best - modern_best}")
    print(f"  Noise floor:   {NOISE_FLOOR}/24 (period-7 expected random: ~8.2)")

    # Stop rule evaluation
    print(f"\n--- Stop Rule Evaluation ---")

    s2_fired = abs(ddr_best - modern_best) <= 2 and max(ddr_best, modern_best) <= NOISE_FLOOR + 4
    print(f"  S2 (Model interchangeability): {'FIRED' if s2_fired else 'NOT FIRED'}")
    if s2_fired:
        print("     → DDR and Modern models perform similarly. No Weltzeituhr-specificity.")

    s1_fired = max(ddr_best, modern_best) <= NOISE_FLOOR + 2
    print(f"  S1 (No operational dependency): {'FIRED' if s1_fired else 'NOT FIRED'}")
    if s1_fired:
        print("     → No candidate requires clock data beyond 'Berlin + time'.")

    if s1_fired and s2_fired:
        verdict = "H0 SUPPORTED"
        print(f"\n  VERDICT: {verdict}")
        print("  The Weltzeituhr (DDR-era or modern) provides NO operational signal.")
        print("  'Berlin Clock' in the plaintext is thematic content, not mechanism.")
        print("  Sanborn's 'A reminder' is consistent with memorial/atmospheric meaning.")
    elif ddr_best > modern_best + 3 and ddr_best > NOISE_FLOOR + 3:
        verdict = "H2 POSSIBLE"
        print(f"\n  VERDICT: {verdict}")
        print("  DDR-era list shows differential signal — investigate further!")
    elif max(ddr_best, modern_best) > NOISE_FLOOR + 3:
        verdict = "H1 POSSIBLE"
        print(f"\n  VERDICT: {verdict}")
        print("  Some signal above noise — clock may provide weak constraint.")
    else:
        verdict = "H0 SUPPORTED"
        print(f"\n  VERDICT: {verdict}")
        print("  All results within noise. Clock is thematic only.")

    print(f"\nTotal configs tested: {grand_total:,}")
    print(f"Runtime: {elapsed:.1f}s")

    # ── Save artifact ─────────────────────────────────────────────────────
    artifact = {
        "experiment_id": "e_s_134",
        "hypothesis": "DDR-era (1989) Weltzeituhr city list as K4 key material",
        "framework": "H0/H1/H2 Weltzeituhr falsification (formal A/B test)",
        "models_tested": {
            name: {
                "best_score": data["best_score"],
                "above_noise": len(data["results_above_noise"]),
                "above_store": len(data["results_above_store"]),
                "total_tested": data["total_tested"],
                "top_results": sorted(
                    data["results_above_noise"],
                    key=lambda r: -r["score"]
                )[:10],
            }
            for name, data in model_results.items()
        },
        "ddr_reconstruction": {
            "name_reversions": dict(DDR_NAME_MAP),
            "cities_removed_confirmed": list(CITIES_ADDED_1997_CONFIRMED),
            "cities_removed_expanded": list(CITIES_ADDED_1997),
            "timezone_changes": {"KIEW": "UTC+2 → UTC+3 (Moscow time)"},
        },
        "stop_rules": {
            "S1_no_operational_dependency": s1_fired,
            "S2_model_interchangeability": s2_fired,
        },
        "verdict": verdict,
        "total_tested": grand_total,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_134_weltzeituhr_ddr_era.py",
    }

    os.makedirs("results", exist_ok=True)
    out_path = "results/e_s_134_weltzeituhr_ddr.json"
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifact written to {out_path}")


if __name__ == "__main__":
    main()
