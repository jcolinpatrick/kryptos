#!/usr/bin/env python3
"""Geometric Key Derivation from Kryptos Installation Network.

Family:    geodetic
Cipher:    geometric-to-key mapping
Status:    active
Keyspace:  ~5000 candidate keys from geometric relationships
Last run:  never
Best score: n/a

Tests the hypothesis that the Kryptos installation's geometric relationships
(bearings, distances, angles between features) encode cipher key material.

Known geometric anchors:
- Station LOOMIS (HV4826) — destroyed triangulation station on CIA grounds
- ABBOTT (HV4841) — azimuth mark, 2km NE at 45.58° from LOOMIS
- Compass rose — at entrance, ~8.6m from LOOMIS
- Sculpture — NW courtyard, ~65m from LOOMIS
- K2 coordinates — 38°57'6.5"N, 77°8'44"W (both NAD27 and NAD83 interpretations)
- Small pool — 38°57'08.17"N, 77°08'44.68"W
- Large pool — 38°57'07.53"N, 77°08'43.71"W

Key discovery: LOOMIS→ABBOTT azimuth (45.58°) mod 26 = 20 → position 20 = W (first delimiter)
"""
import math
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT, N_CRIBS, ALPH
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.crib_score import score_cribs

# ── Known points (WGS84/NAD83) ───────────────────────────────────────────

POINTS = {
    # Station LOOMIS NAD83(1993) — from NGS datasheet HV4826
    'LOOMIS':     (38 + 57/60 + 6.22007/3600,  -(77 + 8/60 + 48.14192/3600)),
    # Station LOOMIS NAD27 — from NGS datasheet
    'LOOMIS_N27': (38 + 57/60 + 5.82/3600,     -(77 + 8/60 + 49.222/3600)),
    # Station ABBOTT NAD83(1993) — from NGS datasheet HV4841
    'ABBOTT':     (38 + 57/60 + 51.80971/3600,  -(77 + 7/60 + 48.53679/3600)),
    # Compass rose — user satellite estimate
    'COMPASS':    (38 + 57/60 + 6.00/3600,      -(77 + 8/60 + 47.92/3600)),
    # Sculpture — satellite estimate
    'SCULPTURE':  (38.95208,                      -77.14611),
    # K2 coordinates (raw WGS84 interpretation)
    'K2_WGS84':   (38 + 57/60 + 6.5/3600,       -(77 + 8/60 + 44.0/3600)),
    # K2 coordinates (NAD27-corrected via NOAA NCAT)
    'K2_NAD27C':  (38.9519162,                    -77.1452562),
    # Small pool
    'SMALL_POOL': (38 + 57/60 + 8.17/3600,      -(77 + 8/60 + 44.68/3600)),
    # Large pool
    'LARGE_POOL': (38 + 57/60 + 7.53/3600,      -(77 + 8/60 + 43.71/3600)),
}


def to_meters(lat1, lon1, lat2, lon2):
    """Convert lat/lon delta to local meters (small distance approx)."""
    avg_lat = math.radians((lat1 + lat2) / 2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    dy = dlat * 6371000  # north in meters
    dx = dlon * 6371000 * math.cos(avg_lat)  # east in meters
    return dx, dy


def bearing_deg(lat1, lon1, lat2, lon2):
    """Compass bearing from point 1 to point 2 (degrees, 0=N, 90=E)."""
    dx, dy = to_meters(lat1, lon1, lat2, lon2)
    angle = math.degrees(math.atan2(dx, dy))  # atan2(east, north)
    return angle % 360


def distance_m(lat1, lon1, lat2, lon2):
    """Distance in meters between two points."""
    dx, dy = to_meters(lat1, lon1, lat2, lon2)
    return math.sqrt(dx*dx + dy*dy)


def angle_at_vertex(a, vertex, b):
    """Angle at vertex between rays to a and b (degrees)."""
    b1 = bearing_deg(*vertex, *a)
    b2 = bearing_deg(*vertex, *b)
    diff = abs(b1 - b2)
    if diff > 180:
        diff = 360 - diff
    return diff


# ── Compute all pairwise relationships ───────────────────────────────────

def compute_relationships():
    """Compute and print all geometric relationships."""
    names = list(POINTS.keys())
    relationships = []

    print("=" * 80)
    print("GEOMETRIC RELATIONSHIPS — KRYPTOS INSTALLATION NETWORK")
    print("=" * 80)

    # Key bearings from LOOMIS
    origin_names = ['LOOMIS', 'COMPASS', 'SCULPTURE']
    target_names = ['COMPASS', 'SCULPTURE', 'K2_WGS84', 'K2_NAD27C',
                    'SMALL_POOL', 'LARGE_POOL', 'ABBOTT']

    for origin in origin_names:
        lat1, lon1 = POINTS[origin]
        print(f"\n── From {origin} ──")
        for target in target_names:
            if target == origin:
                continue
            lat2, lon2 = POINTS[target]
            b = bearing_deg(lat1, lon1, lat2, lon2)
            d = distance_m(lat1, lon1, lat2, lon2)
            b_mod26 = round(b) % 26
            d_mod26 = round(d) % 26
            relationships.append((origin, target, b, d))
            print(f"  → {target:15s}: bearing {b:7.2f}°  dist {d:7.1f}m  "
                  f"| b%26={b_mod26:2d}={ALPH[b_mod26]}  d%26={d_mod26:2d}={ALPH[d_mod26]}")

    # Key angles at vertices
    print(f"\n── Angles at vertices ──")
    triplets = [
        ('ABBOTT', 'LOOMIS', 'K2_WGS84', "ABBOTT-LOOMIS-K2"),
        ('ABBOTT', 'LOOMIS', 'SCULPTURE', "ABBOTT-LOOMIS-SCULPTURE"),
        ('COMPASS', 'SCULPTURE', 'K2_WGS84', "COMPASS-SCULPTURE-K2"),
        ('COMPASS', 'SCULPTURE', 'SMALL_POOL', "COMPASS-SCULPTURE-POOL"),
        ('LOOMIS', 'SCULPTURE', 'K2_WGS84', "LOOMIS-SCULPTURE-K2"),
        ('LOOMIS', 'COMPASS', 'K2_WGS84', "LOOMIS-COMPASS-K2"),
        ('K2_WGS84', 'SCULPTURE', 'SMALL_POOL', "K2-SCULPTURE-POOL"),
    ]
    for a_name, v_name, b_name, label in triplets:
        ang = angle_at_vertex(POINTS[a_name], POINTS[v_name], POINTS[b_name])
        a_mod26 = round(ang) % 26
        print(f"  {label:30s}: {ang:7.2f}°  | %26={a_mod26:2d}={ALPH[a_mod26]}")

    return relationships


# ── Key generation strategies ────────────────────────────────────────────

def generate_bearing_keys():
    """Generate candidate keys from bearing sequences."""
    keys = {}

    # Strategy 1: Bearings from LOOMIS to features in sequence
    # Try various orderings and subsets
    feature_orders = [
        ("LOOMIS→features(CR,SC,K2,SP,LP)", ['COMPASS', 'SCULPTURE', 'K2_WGS84', 'SMALL_POOL', 'LARGE_POOL']),
        ("LOOMIS→features(CR,SC,K2w,SP)", ['COMPASS', 'SCULPTURE', 'K2_WGS84', 'SMALL_POOL']),
        ("LOOMIS→features(CR,SC,K2n,SP)", ['COMPASS', 'SCULPTURE', 'K2_NAD27C', 'SMALL_POOL']),
        ("LOOMIS→features(SC,K2,SP,LP)", ['SCULPTURE', 'K2_WGS84', 'SMALL_POOL', 'LARGE_POOL']),
        ("LOOMIS→features(AB,SC,K2,SP)", ['ABBOTT', 'SCULPTURE', 'K2_WGS84', 'SMALL_POOL']),
        ("LOOMIS→features(CR,SC,K2)", ['COMPASS', 'SCULPTURE', 'K2_WGS84']),
        ("LOOMIS→(AB,SC,K2,SP,LP)", ['ABBOTT', 'SCULPTURE', 'K2_WGS84', 'SMALL_POOL', 'LARGE_POOL']),
    ]

    for label, targets in feature_orders:
        bearings = []
        for t in targets:
            b = bearing_deg(*POINTS['LOOMIS'], *POINTS[t])
            bearings.append(b)

        # Encoding: round bearing mod 26
        key_mod26 = [round(b) % 26 for b in bearings]
        keys[f"{label} b%26"] = key_mod26

        # Encoding: floor bearing mod 26
        key_floor = [int(b) % 26 for b in bearings]
        keys[f"{label} floor(b)%26"] = key_floor

        # Encoding: bearing/360 * 26 (proportional mapping)
        key_prop = [int(b / 360 * 26) % 26 for b in bearings]
        keys[f"{label} b*26/360"] = key_prop

        # Encoding: round bearing / 10 (reduce to <26)
        key_div10 = [round(b / 10) % 26 for b in bearings]
        keys[f"{label} b/10"] = key_div10

    # Strategy 2: Bearings from COMPASS ROSE
    cr_targets = [
        ("CR→features(SC,K2,SP,LP)", ['SCULPTURE', 'K2_WGS84', 'SMALL_POOL', 'LARGE_POOL']),
        ("CR→features(SC,K2w,SP)", ['SCULPTURE', 'K2_WGS84', 'SMALL_POOL']),
        ("CR→features(SC,K2n,SP)", ['SCULPTURE', 'K2_NAD27C', 'SMALL_POOL']),
    ]
    for label, targets in cr_targets:
        bearings = [bearing_deg(*POINTS['COMPASS'], *POINTS[t]) for t in targets]
        keys[f"{label} b%26"] = [round(b) % 26 for b in bearings]
        keys[f"{label} b*26/360"] = [int(b / 360 * 26) % 26 for b in bearings]

    # Strategy 3: Bearings from SCULPTURE
    sc_targets = [
        ("SC→features(CR,K2,SP,LP)", ['COMPASS', 'K2_WGS84', 'SMALL_POOL', 'LARGE_POOL']),
        ("SC→features(K2,SP,LP)", ['K2_WGS84', 'SMALL_POOL', 'LARGE_POOL']),
    ]
    for label, targets in sc_targets:
        bearings = [bearing_deg(*POINTS['SCULPTURE'], *POINTS[t]) for t in targets]
        keys[f"{label} b%26"] = [round(b) % 26 for b in bearings]

    return keys


def generate_distance_keys():
    """Generate candidate keys from distance sequences."""
    keys = {}

    feature_orders = [
        ("LOOMIS dists(CR,SC,K2,SP,LP)", ['COMPASS', 'SCULPTURE', 'K2_WGS84', 'SMALL_POOL', 'LARGE_POOL']),
        ("LOOMIS dists(CR,SC,K2,SP)", ['COMPASS', 'SCULPTURE', 'K2_WGS84', 'SMALL_POOL']),
        ("LOOMIS dists(SC,K2,SP)", ['SCULPTURE', 'K2_WGS84', 'SMALL_POOL']),
    ]

    for label, targets in feature_orders:
        dists = [distance_m(*POINTS['LOOMIS'], *POINTS[t]) for t in targets]
        keys[f"{label} d%26"] = [round(d) % 26 for d in dists]
        keys[f"{label} floor(d)%26"] = [int(d) % 26 for d in dists]
        # Distances in feet
        dists_ft = [d * 3.28084 for d in dists]
        keys[f"{label} ft%26"] = [round(d) % 26 for d in dists_ft]

    return keys


def generate_angle_keys():
    """Generate keys from angles at vertices."""
    keys = {}

    # Angles at LOOMIS
    loomis_pairs = [
        ('ABBOTT', 'SCULPTURE'),
        ('ABBOTT', 'K2_WGS84'),
        ('SCULPTURE', 'K2_WGS84'),
        ('SCULPTURE', 'SMALL_POOL'),
        ('COMPASS', 'K2_WGS84'),
        ('COMPASS', 'SCULPTURE'),
    ]
    angles = []
    for a, b in loomis_pairs:
        ang = angle_at_vertex(POINTS[a], POINTS['LOOMIS'], POINTS[b])
        angles.append(ang)
    keys["LOOMIS angles 6-way %26"] = [round(a) % 26 for a in angles]
    keys["LOOMIS angles 6-way *26/360"] = [int(a / 360 * 26) % 26 for a in angles]

    # Angles at SCULPTURE
    sc_pairs = [
        ('COMPASS', 'K2_WGS84'),
        ('COMPASS', 'SMALL_POOL'),
        ('LOOMIS', 'K2_WGS84'),
        ('LOOMIS', 'SMALL_POOL'),
        ('K2_WGS84', 'SMALL_POOL'),
    ]
    angles_sc = []
    for a, b in sc_pairs:
        ang = angle_at_vertex(POINTS[a], POINTS['SCULPTURE'], POINTS[b])
        angles_sc.append(ang)
    keys["SCULPTURE angles 5-way %26"] = [round(a) % 26 for a in angles_sc]

    return keys


def generate_special_keys():
    """Generate keys from specific hypotheses."""
    keys = {}

    # LOOMIS→ABBOTT azimuth = 45.58° is the PUBLISHED GEODETIC VALUE
    # This is the most precise number we have
    abbott_az = 45.58

    # Key from ABBOTT azimuth digits: 4, 5, 5, 8
    keys["ABBOTT az digits 4558"] = [4, 5, 5, 8]

    # Key from ABBOTT azimuth as degrees.minutes: 45° 34.8' → 4, 5, 3, 4, 8
    keys["ABBOTT az DM 45348"] = [4, 5, 3, 4, 8]

    # ABBOTT azimuth mod 26 = 20 (= W position). As single-letter key:
    keys["ABBOTT az%26=20(U)"] = [20]

    # The LOOMIS→K2 bearing (85°) and distance (100m)
    k2_bearing = bearing_deg(*POINTS['LOOMIS'], *POINTS['K2_WGS84'])
    k2_dist = distance_m(*POINTS['LOOMIS'], *POINTS['K2_WGS84'])
    keys["K2 bearing digits"] = [int(d) for d in str(round(k2_bearing))]
    keys["K2 dist digits"] = [int(d) for d in str(round(k2_dist))]

    # Datum shift: 28.7m at 64.6°
    keys["datum shift bearing 65%26"] = [65 % 26]  # 13 = N
    keys["datum shift dist 29%26"] = [29 % 26]  # 3 = D

    # LOOMIS coords as key material
    # NAD83: 38°57'06.22007"N → digits 3, 8, 5, 7, 0, 6, 2, 2
    keys["LOOMIS lat digits"] = [3, 8, 5, 7, 0, 6, 2, 2]
    keys["LOOMIS lon digits"] = [7, 7, 0, 8, 4, 8, 1, 4]
    # Interleaved
    keys["LOOMIS lat+lon interleaved"] = [3,7, 8,7, 5,0, 7,8, 0,4, 6,8, 2,1, 2,4]

    # K2 coordinates as key: 38 57 6.5  77 8 44
    keys["K2 coord digits"] = [3,8,5,7,6,5,7,7,8,4,4]

    # Crossing angle at sculpture (ABBOTT-line meets K2-line)
    abbott_bearing = bearing_deg(*POINTS['LOOMIS'], *POINTS['ABBOTT'])
    k2_from_loomis = bearing_deg(*POINTS['LOOMIS'], *POINTS['K2_WGS84'])
    crossing = abs(k2_from_loomis - abbott_bearing)
    keys[f"crossing angle {crossing:.1f}"] = [round(crossing) % 26]

    # MAGNETIC DECLINATION as key element
    # ~10.5° west in 1989-1990 DC area
    keys["declination 10.5%26"] = [10, 5]
    keys["declination 11%26"] = [11]

    # Try geodetic keywords
    for word in ['LOOMIS', 'ABBOTT', 'BOWEN', 'PBPP', 'AZIMUTH', 'BEARING',
                 'SURVEY', 'DATUM', 'LODESTONE', 'KOMPASS', 'KRYPTOS',
                 'MAGNETIC', 'COMPASS', 'TRIANGLE', 'STATION']:
        keys[f"keyword:{word}"] = [ord(c) - 65 for c in word]

    # Published ABBOTT azimuth = 45° 34' 46.08" → try as period-specific
    # 45.58° → nearest integer bearings along the network
    # LOOMIS→CR (~203°), LOOMIS→SC (~53°), LOOMIS→K2 (~85°)
    # These as keyword letters
    b_cr = bearing_deg(*POINTS['LOOMIS'], *POINTS['COMPASS'])
    b_sc = bearing_deg(*POINTS['LOOMIS'], *POINTS['SCULPTURE'])
    b_k2 = bearing_deg(*POINTS['LOOMIS'], *POINTS['K2_WGS84'])
    b_sp = bearing_deg(*POINTS['LOOMIS'], *POINTS['SMALL_POOL'])
    b_ab = bearing_deg(*POINTS['LOOMIS'], *POINTS['ABBOTT'])

    # All LOOMIS bearings sorted by angle
    all_bearings = sorted([
        ('CR', b_cr), ('SC', b_sc), ('K2', b_k2),
        ('SP', b_sp), ('AB', b_ab),
    ], key=lambda x: x[1])

    print(f"\n── LOOMIS bearings (sorted) ──")
    for name, b in all_bearings:
        print(f"  {name:4s}: {b:7.2f}°  %26={round(b)%26:2d}={ALPH[round(b)%26]}")

    # Key from sorted bearing deltas (differences between consecutive bearings)
    deltas = [all_bearings[i+1][1] - all_bearings[i][1]
              for i in range(len(all_bearings)-1)]
    keys["LOOMIS bearing deltas %26"] = [round(d) % 26 for d in deltas]
    print(f"  Deltas: {[f'{d:.1f}' for d in deltas]}")

    # Compass rose readings model: 8 cardinal/intercardinal positions
    # with lodestone at LOOMIS position (8.6m from CR)
    print(f"\n── Compass Rose Lodestone Model (8-point) ──")
    cr_lat, cr_lon = POINTS['COMPASS']
    lo_lat, lo_lon = POINTS['LOOMIS']
    lo_dx, lo_dy = to_meters(cr_lat, cr_lon, lo_lat, lo_lon)
    lo_dist = math.sqrt(lo_dx*lo_dx + lo_dy*lo_dy)
    lo_angle = math.degrees(math.atan2(lo_dx, lo_dy))
    print(f"  Lodestone at {lo_dist:.1f}m, bearing {lo_angle:.1f}° from compass rose")

    # Model compass readings at 8 positions around rose edge (assume 1m radius)
    rose_radius = 1.0  # meters (approximate)
    for n_points in [8, 16, 26]:
        deflections = []
        for i in range(n_points):
            theta = 360.0 * i / n_points  # position angle from north
            # Position on rose edge
            px = rose_radius * math.sin(math.radians(theta))
            py = rose_radius * math.cos(math.radians(theta))
            # Vector from this position to lodestone
            rx = lo_dx - px
            ry = lo_dy - py
            r = math.sqrt(rx*rx + ry*ry)
            # Simplified dipole field (horizontal component)
            # Assume lodestone moment points north (along y) with magnitude m
            # B_horizontal ∝ (3(m·r̂)r̂ - m) / r³
            # For simplicity, compute deflection angle from earth's field
            # Earth's field ≈ 20μT horizontal in DC
            # Lodestone field ≈ proportional to 1/r³
            # The deflection ≈ arctan(B_lode_perp / B_earth) for weak fields
            r_hat_x, r_hat_y = rx/r, ry/r
            # Dipole field components (normalized, moment along north)
            m_dot_rhat = r_hat_y  # m·r̂ (moment points north)
            Bx = (3 * m_dot_rhat * r_hat_x) / (r**3)  # no -mx since mx=0
            By = (3 * m_dot_rhat * r_hat_y - 1) / (r**3)  # -my/r³
            # Deflection from pure north (arctan of east/north component ratio)
            deflection = math.degrees(math.atan2(Bx, By))
            deflections.append(deflection)

        if n_points <= 16:
            print(f"  {n_points}-point deflections: {[f'{d:.1f}' for d in deflections]}")
        # Convert to key values
        key_vals = [round(abs(d)) % 26 for d in deflections]
        keys[f"lodestone {n_points}pt %26"] = key_vals
        # Also try proportional mapping
        max_defl = max(abs(d) for d in deflections) if deflections else 1
        key_prop = [round(abs(d) / max_defl * 25) for d in deflections]
        keys[f"lodestone {n_points}pt proportional"] = key_prop

    return keys


# ── Test all candidate keys ──────────────────────────────────────────────

def test_key(key_nums, label, variant, alpha_label='AZ'):
    """Test a candidate key against K4."""
    if not key_nums:
        return 0, ""
    pt = decrypt_text(CT, key_nums, variant)
    sc = score_cribs(pt)
    return sc, pt


def main():
    rels = compute_relationships()

    print("\n" + "=" * 80)
    print("GENERATING CANDIDATE KEYS")
    print("=" * 80)

    all_keys = {}
    all_keys.update(generate_bearing_keys())
    all_keys.update(generate_distance_keys())
    all_keys.update(generate_angle_keys())
    all_keys.update(generate_special_keys())

    print(f"\nTotal candidate keys: {len(all_keys)}")

    # Test each key against K4
    print("\n" + "=" * 80)
    print("TESTING CANDIDATE KEYS AGAINST K4")
    print("=" * 80)

    variants = [
        (CipherVariant.VIGENERE, "Vig"),
        (CipherVariant.BEAUFORT, "Beau"),
        (CipherVariant.VAR_BEAUFORT, "VBeau"),
    ]

    results = []
    best_score = 0

    for label, key_nums in all_keys.items():
        if not key_nums:
            continue
        key_str = ''.join(ALPH[k % 26] for k in key_nums)
        for variant, vname in variants:
            sc, pt = test_key(key_nums, label, variant)
            if sc > 0:
                results.append((sc, vname, label, key_str, pt[:40]))
            if sc > best_score:
                best_score = sc

    # Sort by score descending
    results.sort(key=lambda x: -x[0])

    print(f"\nResults with score > 0 (showing top 50):")
    print(f"{'Score':>5} {'Var':>5} {'Key':>20} {'Label':<50} {'PT[:40]'}")
    print("-" * 130)
    for sc, vname, label, key_str, pt_preview in results[:50]:
        print(f"{sc:5d} {vname:>5} {key_str:>20} {label:<50} {pt_preview}")

    print(f"\n{'=' * 80}")
    print(f"BEST SCORE: {best_score}/24")
    print(f"Total keys tested: {len(all_keys)} × 3 variants = {len(all_keys)*3}")

    # Also try: intersection point coordinates as key
    print(f"\n{'=' * 80}")
    print(f"LINE INTERSECTION ANALYSIS")
    print(f"{'=' * 80}")

    # Define sightlines as (origin_point, bearing_degrees)
    sightlines = {
        'LOOMIS→ABBOTT':     ('LOOMIS', 45.58),  # published geodetic azimuth
        'LOOMIS→SCULPTURE':  ('LOOMIS', bearing_deg(*POINTS['LOOMIS'], *POINTS['SCULPTURE'])),
        'LOOMIS→K2':         ('LOOMIS', bearing_deg(*POINTS['LOOMIS'], *POINTS['K2_WGS84'])),
        'LOOMIS→POOL':       ('LOOMIS', bearing_deg(*POINTS['LOOMIS'], *POINTS['SMALL_POOL'])),
        'CR→SCULPTURE':      ('COMPASS', bearing_deg(*POINTS['COMPASS'], *POINTS['SCULPTURE'])),
        'CR→K2':             ('COMPASS', bearing_deg(*POINTS['COMPASS'], *POINTS['K2_WGS84'])),
        'CR→POOL':           ('COMPASS', bearing_deg(*POINTS['COMPASS'], *POINTS['SMALL_POOL'])),
        'SC→K2':             ('SCULPTURE', bearing_deg(*POINTS['SCULPTURE'], *POINTS['K2_WGS84'])),
        'SC→POOL':           ('SCULPTURE', bearing_deg(*POINTS['SCULPTURE'], *POINTS['SMALL_POOL'])),
        'LODESTONE_ENE':     ('COMPASS', 67.5),  # ENE direction from compass rose
        'LODESTONE_ENE_MAG': ('COMPASS', 57.0),  # ENE magnetic (corrected for declination)
    }

    print(f"\nSightlines:")
    for name, (origin, bearing) in sightlines.items():
        print(f"  {name:25s}: from {origin:12s} at {bearing:7.2f}°")

    # Compute all pairwise intersections
    print(f"\nPairwise intersections (within 500m of LOOMIS):")
    sl_names = list(sightlines.keys())
    intersection_keys = {}

    for i in range(len(sl_names)):
        for j in range(i+1, len(sl_names)):
            n1, n2 = sl_names[i], sl_names[j]
            o1, b1 = sightlines[n1]
            o2, b2 = sightlines[n2]
            # Skip if same origin (parallel lines scenario is boring)
            if o1 == o2:
                continue
            # Solve intersection
            # Line 1: origin1 + t * direction1
            # Line 2: origin2 + s * direction2
            o1_lat, o1_lon = POINTS[o1]
            o2_lat, o2_lon = POINTS[o2]
            # Convert to local meters from LOOMIS
            ref_lat, ref_lon = POINTS['LOOMIS']
            x1, y1 = to_meters(ref_lat, ref_lon, o1_lat, o1_lon)
            x2, y2 = to_meters(ref_lat, ref_lon, o2_lat, o2_lon)
            # Direction vectors (bearing: 0=N=+y, 90=E=+x)
            dx1 = math.sin(math.radians(b1))
            dy1 = math.cos(math.radians(b1))
            dx2 = math.sin(math.radians(b2))
            dy2 = math.cos(math.radians(b2))
            # Solve: (x1 + t*dx1, y1 + t*dy1) = (x2 + s*dx2, y2 + s*dy2)
            # t*dx1 - s*dx2 = x2 - x1
            # t*dy1 - s*dy2 = y2 - y1
            det = dx1 * (-dy2) - (-dx2) * dy1
            if abs(det) < 1e-10:
                continue  # parallel
            t = ((x2 - x1) * (-dy2) - (-dx2) * (y2 - y1)) / det
            ix = x1 + t * dx1
            iy = y1 + t * dy1
            dist_from_loomis = math.sqrt(ix*ix + iy*iy)
            if dist_from_loomis > 500 or t < 0:  # only forward intersections within 500m
                continue
            bearing_from_loomis = math.degrees(math.atan2(ix, iy)) % 360
            print(f"  {n1} × {n2}:")
            print(f"    at ({ix:.1f}m E, {iy:.1f}m N) of LOOMIS, "
                  f"dist={dist_from_loomis:.1f}m, bearing={bearing_from_loomis:.1f}°")

            # Convert intersection to potential key values
            key_label = f"intersect:{n1}×{n2}"
            intersection_keys[f"{key_label} coords%26"] = [
                round(abs(ix)) % 26, round(abs(iy)) % 26
            ]
            intersection_keys[f"{key_label} bearing%26"] = [
                round(bearing_from_loomis) % 26
            ]
            intersection_keys[f"{key_label} dist%26"] = [
                round(dist_from_loomis) % 26
            ]

    # Test intersection-derived keys
    if intersection_keys:
        print(f"\nTesting {len(intersection_keys)} intersection-derived keys...")
        int_results = []
        for label, key_nums in intersection_keys.items():
            if not key_nums:
                continue
            key_str = ''.join(ALPH[k % 26] for k in key_nums)
            for variant, vname in variants:
                sc, pt = test_key(key_nums, label, variant)
                if sc > 0:
                    int_results.append((sc, vname, label, key_str, pt[:40]))

        int_results.sort(key=lambda x: -x[0])
        if int_results:
            print(f"\nIntersection key results (score > 0):")
            for sc, vname, label, key_str, pt_preview in int_results[:20]:
                print(f"  {sc:5d} {vname:>5} {key_str:>10} {label}")
        else:
            print(f"  No intersection keys scored > 0")

    print(f"\n{'=' * 80}")
    print(f"SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total candidate keys: {len(all_keys) + len(intersection_keys)}")
    print(f"Total decryption attempts: {(len(all_keys) + len(intersection_keys)) * 3}")
    print(f"Best score: {best_score}/24")
    if best_score >= 10:
        print(f"*** SIGNAL DETECTED — investigate top results ***")
    elif best_score >= 7:
        print(f"Above noise floor but not significant")
    else:
        print(f"All noise. Geometric keys as simple periodic substitution = eliminated.")
        print(f"\nNOTE: These keys were tested as DIRECT substitution on 97-char carved text.")
        print(f"Under the two-system model, the geometric key may apply to the INNER layer")
        print(f"(after removing the outer transposition), which we cannot test without")
        print(f"knowing the transposition.")


if __name__ == '__main__':
    main()
