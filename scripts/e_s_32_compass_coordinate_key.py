#!/usr/bin/env python3
"""
E-S-32: Compass Bearing & Coordinate Key Derivation

"What's the point?" — Sanborn's 2025 embedded clue

EASTNORTHEAST is a compass bearing (67.5°). BERLINCLOCK is the Urania
Weltzeituhr at Alexanderplatz, Berlin. K2's plaintext contains coordinates
(38°57'6.5"N, 77°8'44"W = Kryptos location).

Hypothesis: the key is derived from compass bearings, coordinates, or
distances between geographic points related to the clues.

Tests:
1. Compass bearing from Kryptos to Berlin Clock as key seed
2. Coordinates of key locations as key values
3. Distance/bearing calculations between clue locations
4. ENE bearing (67.5°) applied to coordinates
5. Date arithmetic (1986, 1989) as key derivation
6. Combined: coordinates + dates + bearings as procedural key

All tested with identity transposition AND with K3-like columnar (width 7).

Output: results/e_s_32_compass_coordinate_key.json
"""

import json
import math
import sys
import os
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Key locations
KRYPTOS_LAT = 38 + 57/60 + 6.5/3600  # 38.9518°N
KRYPTOS_LON = -(77 + 8/60 + 44/3600)  # -77.1456°W

# Berlin Urania Weltzeituhr (Alexanderplatz)
BERLIN_CLOCK_LAT = 52 + 31/60 + 18/3600  # 52.5217°N
BERLIN_CLOCK_LON = 13 + 24/60 + 48/3600  # 13.4133°E

# Giza Pyramids (1986 Egypt trip)
GIZA_LAT = 29 + 58/60 + 45/3600  # 29.9792°N
GIZA_LON = 31 + 8/60 + 3/3600    # 31.1342°E

# Valley of the Kings (Tutankhamun's tomb)
VALLEY_KINGS_LAT = 25 + 44/60 + 24/3600  # 25.7400°N
VALLEY_KINGS_LON = 32 + 36/60 + 6/3600   # 32.6017°E

# Berlin Wall (1989)
BERLIN_WALL_LAT = 52 + 30/60 + 32/3600  # Brandenburg Gate area
BERLIN_WALL_LON = 13 + 22/60 + 42/3600

ENE_BEARING = 67.5  # East-Northeast compass bearing


def haversine_bearing(lat1, lon1, lat2, lon2):
    """Compute initial bearing from point 1 to point 2."""
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlon = lon2 - lon1
    x = math.sin(dlon) * math.cos(lat2)
    y = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(lat2) * math.cos(dlon)
    bearing = math.atan2(x, y)
    return (math.degrees(bearing) + 360) % 360


def haversine_distance(lat1, lon1, lat2, lon2):
    """Distance in km."""
    R = 6371
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    return R * 2 * math.asin(math.sqrt(a))


def coord_to_nums(lat, lon, method):
    """Convert coordinates to number sequences using various methods."""
    if method == "degrees_int":
        return [int(abs(lat)) % 26, int(abs(lon)) % 26]
    elif method == "dms_digits":
        # Degrees, minutes, seconds as individual digits
        lat_d = int(abs(lat))
        lat_m = int((abs(lat) - lat_d) * 60)
        lat_s = int(((abs(lat) - lat_d) * 60 - lat_m) * 60)
        lon_d = int(abs(lon))
        lon_m = int((abs(lon) - lon_d) * 60)
        lon_s = int(((abs(lon) - lon_d) * 60 - lon_m) * 60)
        digits = []
        for n in [lat_d, lat_m, lat_s, lon_d, lon_m, lon_s]:
            for d in str(n):
                digits.append(int(d))
        return digits
    elif method == "dms_values":
        lat_d = int(abs(lat))
        lat_m = int((abs(lat) - lat_d) * 60)
        lat_s = round(((abs(lat) - lat_d) * 60 - lat_m) * 60, 1)
        lon_d = int(abs(lon))
        lon_m = int((abs(lon) - lon_d) * 60)
        lon_s = round(((abs(lon) - lon_d) * 60 - lon_m) * 60, 1)
        return [int(x) % 26 for x in [lat_d, lat_m, lat_s, lon_d, lon_m, lon_s]]
    return []


def check_period_consistency(intermediate, periods):
    """Check crib consistency at given periods."""
    best = 0
    best_p = 0
    for p in periods:
        residue_keys = defaultdict(set)
        for pos in CRIB_POS:
            if pos < len(intermediate):
                k = (intermediate[pos] - CRIB_PT[pos]) % MOD
                residue_keys[pos % p].add(k)
        n_consistent = sum(1 for ks in residue_keys.values() if len(ks) == 1)
        if n_consistent > best:
            best = n_consistent
            best_p = p
    return best, best_p


def generate_key_sequences():
    """Generate all candidate key sequences from coordinates, bearings, dates."""
    keys = {}

    # 1. Compass bearings between locations
    locations = {
        "kryptos": (KRYPTOS_LAT, KRYPTOS_LON),
        "berlin_clock": (BERLIN_CLOCK_LAT, BERLIN_CLOCK_LON),
        "giza": (GIZA_LAT, GIZA_LON),
        "valley_kings": (VALLEY_KINGS_LAT, VALLEY_KINGS_LON),
        "berlin_wall": (BERLIN_WALL_LAT, BERLIN_WALL_LON),
    }

    print("\nGeographic bearings and distances:")
    for name1, (lat1, lon1) in locations.items():
        for name2, (lat2, lon2) in locations.items():
            if name1 >= name2:
                continue
            bearing = haversine_bearing(lat1, lon1, lat2, lon2)
            dist = haversine_distance(lat1, lon1, lat2, lon2)
            print(f"  {name1} → {name2}: bearing={bearing:.1f}° dist={dist:.0f}km")

            # Use bearing digits as key
            b_int = int(round(bearing))
            digits = [int(d) for d in str(b_int)]
            keys[f"bearing_{name1}_to_{name2}"] = digits

            # Distance digits
            d_int = int(round(dist))
            digits = [int(d) for d in str(d_int)]
            keys[f"dist_{name1}_to_{name2}"] = digits

    # 2. Coordinate values as key sequences
    for name, (lat, lon) in locations.items():
        for method in ["dms_digits", "dms_values"]:
            nums = coord_to_nums(lat, lon, method)
            keys[f"coord_{name}_{method}"] = nums

    # 3. Date-based keys
    keys["date_1986"] = [1, 9, 8, 6]
    keys["date_1989"] = [1, 9, 8, 9]
    keys["date_both"] = [1, 9, 8, 6, 1, 9, 8, 9]
    keys["date_reversed"] = [9, 8, 9, 1, 6, 8, 9, 1]
    keys["year_diff"] = [3]  # 1989-1986
    keys["date_sum"] = [1+1, 9+9, 8+8, 6+9]  # = [2, 18, 16, 15]

    # 4. ENE bearing as key
    keys["ene_675"] = [6, 7, 5]
    keys["ene_bearing_int"] = [int(ENE_BEARING) % 26]

    # 5. Combined: Kryptos coords + dates
    kryptos_dms = coord_to_nums(KRYPTOS_LAT, abs(KRYPTOS_LON), "dms_digits")
    keys["kryptos_dms_dates"] = kryptos_dms + [1, 9, 8, 6, 1, 9, 8, 9]

    # 6. Special: "WHATS THE POINT" → compass point ENE = 67.5
    # Could mean: derive key from the ENE bearing applied to coordinates
    bearing_k2b = haversine_bearing(KRYPTOS_LAT, KRYPTOS_LON, BERLIN_CLOCK_LAT, BERLIN_CLOCK_LON)
    keys["bearing_k_to_bc"] = [int(d) for d in str(int(round(bearing_k2b)))]

    # 7. K3 transposition key as part of K4 key
    keys["k3_key_4152637"] = [4, 1, 5, 2, 6, 3, 7]
    keys["k3_key_0indexed"] = [3, 0, 4, 1, 5, 2, 6]

    # 8. Combined K3 + coordinates
    keys["k3_key_kryptos_coord"] = [4,1,5,2,6,3,7] + kryptos_dms

    return keys


def main():
    print("=" * 60)
    print("E-S-32: Compass Bearing & Coordinate Key Derivation")
    print("=" * 60)
    print(f'"What\'s the point?" — compass point, coordinate point, or both?')

    key_seqs = generate_key_sequences()
    print(f"\nTotal key sequences: {len(key_seqs)}")

    periods = list(range(2, 25))
    results = []
    best_overall = 0

    for key_name, key_raw in key_seqs.items():
        if not key_raw:
            continue

        # Pad to at least length N by repeating
        key_padded = (key_raw * ((N // len(key_raw)) + 1))[:N]

        for direction, dir_name in [(1, "add"), (-1, "sub")]:
            # Apply key to CT
            modified = [(CT_NUM[i] + direction * key_padded[i]) % MOD for i in range(N)]

            score, best_p = check_period_consistency(modified, periods)

            if score > best_overall:
                best_overall = score
                print(f"  NEW BEST: {key_name} {dir_name}: {score}/24 at p={best_p}")

            if score >= 12:
                results.append({
                    "key_name": key_name,
                    "direction": dir_name,
                    "score": score,
                    "period": best_p,
                    "key_values": key_raw[:20],
                })

    # Also test with width-7 columnar transposition (K3's method)
    print(f"\nWith width-7 columnar transposition:")
    k3_order = [3, 0, 4, 1, 5, 2, 6]  # K3's key order (0-indexed)

    # Test a few promising columnar orderings
    test_orders = [
        k3_order,
        [0, 1, 2, 3, 4, 5, 6],  # identity
        [6, 5, 4, 3, 2, 1, 0],  # reverse
        [3, 1, 4, 1, 5, 2, 6],  # K3 but 1 appears twice? No, invalid. Skip.
    ]

    # Build columnar decrypt for each ordering
    for order in test_orders:
        if len(set(order)) != 7:
            continue

        for key_name, key_raw in key_seqs.items():
            if not key_raw:
                continue

            key_padded = (key_raw * ((N // len(key_raw)) + 1))[:N]

            for direction, dir_name in [(1, "add"), (-1, "sub")]:
                modified = [(CT_NUM[i] + direction * key_padded[i]) % MOD for i in range(N)]

                # Undo columnar transposition
                n_rows = (N + 6) // 7
                n_long = N % 7 if N % 7 != 0 else 7

                cols = [[] for _ in range(7)]
                pos = 0
                for ci in order:
                    col_len = n_rows if ci < n_long else n_rows - 1
                    cols[ci] = modified[pos:pos + col_len]
                    pos += col_len

                untransposed = []
                for row in range(n_rows):
                    for col in range(7):
                        if row < len(cols[col]):
                            untransposed.append(cols[col][row])

                score, best_p = check_period_consistency(untransposed, periods)

                if score >= 12:
                    print(f"  {key_name} {dir_name} order={order}: {score}/24 at p={best_p}")
                    results.append({
                        "key_name": key_name,
                        "direction": dir_name,
                        "order": order,
                        "score": score,
                        "period": best_p,
                        "key_values": key_raw[:20],
                        "model": "mask+columnar",
                    })

    # Summary
    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Best score: {best_overall}/24")
    print(f"  Results ≥ 12: {len(results)}")

    if results:
        results.sort(key=lambda r: -r['score'])
        for r in results[:10]:
            print(f"    {r['key_name']} {r['direction']}: {r['score']}/24 at p={r['period']}")

    verdict = "NOISE" if best_overall < 18 else "SIGNAL"
    print(f"  Verdict: {verdict}")

    # Save
    os.makedirs("results", exist_ok=True)
    with open("results/e_s_32_compass_coordinate.json", "w") as f:
        json.dump({
            "experiment": "E-S-32",
            "total_keys": len(key_seqs),
            "best_score": best_overall,
            "verdict": verdict,
            "results": results[:20],
        }, f, indent=2)

    print(f"\n  Artifact: results/e_s_32_compass_coordinate.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_32_compass_coordinate_key.py")


if __name__ == "__main__":
    main()
