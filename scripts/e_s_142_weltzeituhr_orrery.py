#!/usr/bin/env python3
"""E-S-142: Weltzeituhr solar system model (orrery) as K4 key material.

The Urania Weltzeituhr has a rotating model of the solar system on top.
In 1989 (when Sanborn visited Berlin), this showed 9 planets.

Key observation: 9 planets → width 9, and 97/9 = 10.78 ≈ Sanborn's "10.8 rows"

This experiment tests the orrery as key source:
  (a) Planet initials as substitution key (MVEMJSUNP, period 9)
  (b) German planet names (Merkur, Venus, Erde, Mars, Jupiter, Saturn, Uranus, Neptun, Pluto)
  (c) Planet-name-derived columnar orderings (width 9)
  (d) Orbital data as numeric keys (radii, periods, planet numbers)
  (e) Combined: planet substitution key + width-9 columnar transposition
  (f) Reverse/shuffle orderings (inner-to-outer, outer-to-inner, alphabetical)
  (g) Planetary positions on key dates (Nov 9 1989, Nov 3 1990) as key offsets

Previously tested on Weltzeituhr: cities (E-S-127/128/134), timezone faces, reading orders.
The orrery itself was NEVER tested.

Output: results/e_s_142_weltzeituhr_orrery.json
"""

import json
import os
import sys
import time as time_mod
import itertools
import math

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

SEED = 142
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
VARIANT_NAMES = {
    CipherVariant.VIGENERE: "Vig",
    CipherVariant.BEAUFORT: "Beau",
    CipherVariant.VAR_BEAUFORT: "VB",
}

# ═══════════════════════════════════════════════════════════════════════════════
# SOLAR SYSTEM DATA (as of 1989 — 9 planets including Pluto)
# ═══════════════════════════════════════════════════════════════════════════════

# Order from Sun outward
PLANETS_EN = ["MERCURY", "VENUS", "EARTH", "MARS", "JUPITER", "SATURN", "URANUS", "NEPTUNE", "PLUTO"]
PLANETS_DE = ["MERKUR", "VENUS", "ERDE", "MARS", "JUPITER", "SATURN", "URANUS", "NEPTUN", "PLUTO"]

# Planet initials (same in English and German!)
PLANET_INITIALS = "MVEMJSUNP"

# Mean orbital radii (AU) — for numeric key derivation
ORBITAL_RADII_AU = [0.387, 0.723, 1.000, 1.524, 5.203, 9.537, 19.191, 30.069, 39.482]

# Orbital periods (Earth years)
ORBITAL_PERIODS_YR = [0.241, 0.615, 1.000, 1.881, 11.862, 29.457, 84.011, 164.79, 247.92]

# Planet numbers (traditional ordering, 1-indexed from Sun)
PLANET_NUMBERS = [1, 2, 3, 4, 5, 6, 7, 8, 9]

# Approximate ecliptic longitudes on key dates (degrees, J2000 epoch)
# Computed from mean orbital elements — approximate but deterministic
def mean_longitude(planet_idx, jd):
    """Approximate mean ecliptic longitude for a planet at Julian Date.

    Uses simplified mean orbital elements (adequate for key-derivation testing).
    Returns degrees [0, 360).
    """
    # Mean longitudes at J2000.0 (JD 2451545.0) in degrees
    L0 = [252.251, 181.980, 100.464, 355.453, 34.351, 49.944, 313.232, 304.880, 238.929]
    # Mean daily motions (degrees/day)
    N = [4.09233445, 1.60213034, 0.98560028, 0.52402068, 0.08308529,
         0.03344414, 0.01172834, 0.00598103, 0.00396012]

    dt = jd - 2451545.0  # days from J2000.0
    lon = (L0[planet_idx] + N[planet_idx] * dt) % 360.0
    return lon

# Key dates as Julian Dates
JD_BERLIN_WALL = 2447836.5    # Nov 9, 1989
JD_KRYPTOS_DED = 2448195.5    # Nov 3, 1990
JD_EGYPT_1986 = 2446432.5     # ~Jan 1, 1986 (approximate)


def make_key(text):
    """Convert text to numeric key (A=0, B=1, ..., Z=25)."""
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


def keyword_to_col_order(keyword):
    """Derive columnar transposition column order from keyword.

    Letters sorted alphabetically; ties broken left-to-right.
    Returns list of column indices in read-off order.
    """
    indexed = [(ch, i) for i, ch in enumerate(keyword.upper())]
    indexed.sort(key=lambda x: (x[0], x[1]))
    order = [0] * len(keyword)
    for rank, (ch, orig_idx) in enumerate(indexed):
        order[orig_idx] = rank
    # order[i] = which rank column i gets
    # We want read-off order: which original column to read at each rank
    read_order = [0] * len(keyword)
    for orig_idx, rank in enumerate(order):
        read_order[rank] = orig_idx
    return read_order


def apply_columnar(ct_text, width, col_order):
    """Apply columnar transposition decryption.

    ct_text written into grid row-by-row, read off in col_order.
    Returns the permutation (gather convention).
    """
    n = len(ct_text)
    nrows = math.ceil(n / width)
    # Build column lengths (last row may be short)
    full_cols = n % width if n % width != 0 else width
    col_lengths = []
    for c in range(width):
        if c < (n % width) or n % width == 0:
            col_lengths.append(nrows)
        else:
            col_lengths.append(nrows - 1)

    # CT was written column-by-column in col_order
    # To decrypt: assign CT chars to columns in read order, then read row-by-row
    perm = [0] * n
    ct_pos = 0
    col_contents = [[] for _ in range(width)]
    for rank in range(width):
        col_idx = col_order[rank]
        clen = col_lengths[col_idx]
        for row in range(clen):
            col_contents[col_idx].append(ct_pos)
            ct_pos += 1

    # Now read row-by-row
    result_perm = []
    for row in range(nrows):
        for col in range(width):
            if row < len(col_contents[col]):
                result_perm.append(col_contents[col][row])

    return result_perm


def test_substitution_key(key_name, key_nums, results):
    """Test a numeric substitution key against all variants."""
    for variant in VARIANTS:
        pt = decrypt_text(CT, key_nums, variant)
        sc = score_cribs(pt)
        ic_val = ic(pt)
        vname = VARIANT_NAMES[variant]

        if sc > NOISE_FLOOR:
            results.append({
                "test": f"sub_{key_name}_{vname}",
                "key_name": key_name,
                "variant": vname,
                "score": sc,
                "ic": round(ic_val, 4),
                "pt_snippet": pt[:40],
                "key": key_nums[:20],
            })
            print(f"  [STORE] {key_name}/{vname}: score={sc}, ic={ic_val:.4f}, pt={pt[:30]}...")

        if sc >= STORE_THRESHOLD:
            print(f"  *** HIGH SCORE: {key_name}/{vname}: score={sc}, ic={ic_val:.4f}")
            print(f"      PT: {pt}")


def test_transposition_only(perm_name, perm, results):
    """Test a transposition-only permutation."""
    # Apply inverse perm to CT (decryption = inverse of encryption perm)
    inv = invert_perm(perm)
    pt = apply_perm(CT, inv)
    sc = score_cribs(pt)
    ic_val = ic(pt)

    if sc > NOISE_FLOOR:
        results.append({
            "test": f"trans_{perm_name}",
            "perm_name": perm_name,
            "score": sc,
            "ic": round(ic_val, 4),
            "pt_snippet": pt[:40],
        })
        print(f"  [STORE] trans_{perm_name}: score={sc}, ic={ic_val:.4f}")


def test_combined(key_name, key_nums, perm_name, perm, results):
    """Test substitution + transposition combination."""
    inv = invert_perm(perm)

    for variant in VARIANTS:
        # Try both orders: sub then trans, trans then sub
        for order_name, ops in [("sub_trans", "st"), ("trans_sub", "ts")]:
            if ops == "st":
                # Decrypt substitution first, then undo transposition
                pt_sub = decrypt_text(CT, key_nums, variant)
                pt = apply_perm(pt_sub, inv)
            else:
                # Undo transposition first, then decrypt substitution
                ct_untrans = apply_perm(CT, inv)
                pt = decrypt_text(ct_untrans, key_nums, variant)

            sc = score_cribs(pt)
            ic_val = ic(pt)
            vname = VARIANT_NAMES[variant]
            label = f"{order_name}_{key_name}_{perm_name}_{vname}"

            if sc > NOISE_FLOOR:
                results.append({
                    "test": label,
                    "key_name": key_name,
                    "perm_name": perm_name,
                    "variant": vname,
                    "order": order_name,
                    "score": sc,
                    "ic": round(ic_val, 4),
                    "pt_snippet": pt[:40],
                })
                print(f"  [STORE] {label}: score={sc}, ic={ic_val:.4f}")

            if sc >= STORE_THRESHOLD:
                print(f"  *** HIGH: {label}: score={sc}")
                print(f"      PT: {pt}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    t0 = time_mod.time()
    results = []
    best_score = 0
    total_tests = 0

    print("=" * 72)
    print("E-S-142: Weltzeituhr Orrery (Solar System Model) — K4 Key Tests")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Planet initials: {PLANET_INITIALS} (period 9)")
    print(f"97 / 9 = {97/9:.4f} ≈ Sanborn's '10.8 rows'")
    print()

    # ──────────────────────────────────────────────────────────────────────
    # PHASE A: Planet initials as substitution key
    # ──────────────────────────────────────────────────────────────────────
    print("─" * 72)
    print("PHASE A: Planet initials as substitution key (period 9)")
    print("─" * 72)

    # A1: MVEMJSUNP (orbital order, Sun outward)
    key_a1 = make_key(PLANET_INITIALS)
    print(f"\nA1: MVEMJSUNP = {key_a1}")
    test_substitution_key("MVEMJSUNP", key_a1, results)
    total_tests += 3

    # A2: Reverse (Pluto inward)
    key_a2 = list(reversed(key_a1))
    print(f"\nA2: PNUSJMEV M = {key_a2}")
    test_substitution_key("PNUSJMEVM_rev", key_a2, results)
    total_tests += 3

    # A3: Alphabetical by planet name (English)
    alpha_en = sorted(range(9), key=lambda i: PLANETS_EN[i])
    key_a3 = [make_key(PLANETS_EN[i][0])[0] for i in alpha_en]
    alpha_str = "".join(PLANETS_EN[i][0] for i in alpha_en)
    print(f"\nA3: Alphabetical (EN): {alpha_str} = {key_a3}")
    test_substitution_key(f"alpha_en_{alpha_str}", key_a3, results)
    total_tests += 3

    # A4: Alphabetical by planet name (German)
    alpha_de = sorted(range(9), key=lambda i: PLANETS_DE[i])
    key_a4 = [make_key(PLANETS_DE[i][0])[0] for i in alpha_de]
    alpha_str_de = "".join(PLANETS_DE[i][0] for i in alpha_de)
    print(f"\nA4: Alphabetical (DE): {alpha_str_de} = {key_a4}")
    test_substitution_key(f"alpha_de_{alpha_str_de}", key_a4, results)
    total_tests += 3

    # A5: Full planet names concatenated as running key
    for lang, names in [("EN", PLANETS_EN), ("DE", PLANETS_DE)]:
        concat = "".join(names)
        key_a5 = make_key(concat)[:CT_LEN]
        print(f"\nA5-{lang}: {concat[:30]}... ({len(key_a5)} chars)")
        test_substitution_key(f"concat_{lang}", key_a5, results)
        total_tests += 3

    # A6: Each planet name as a repeating key
    for lang, names in [("EN", PLANETS_EN), ("DE", PLANETS_DE)]:
        for name in names:
            key_a6 = make_key(name)
            if len(key_a6) > 0:
                # Repeat to CT length
                full_key = (key_a6 * (CT_LEN // len(key_a6) + 1))[:CT_LEN]
                test_substitution_key(f"planet_{lang}_{name}", full_key, results)
                total_tests += 3

    # ──────────────────────────────────────────────────────────────────────
    # PHASE B: Orbital data as numeric keys
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE B: Orbital data as numeric keys")
    print("─" * 72)

    # B1: Orbital radii → mod 26
    radii_key = [round(r * 10) % 26 for r in ORBITAL_RADII_AU]
    print(f"\nB1: Radii*10 mod 26 = {radii_key}")
    full_key = (radii_key * (CT_LEN // 9 + 1))[:CT_LEN]
    test_substitution_key("radii_mod26", full_key, results)
    total_tests += 3

    # B2: Orbital periods → mod 26
    periods_key = [round(p * 10) % 26 for p in ORBITAL_PERIODS_YR]
    print(f"\nB2: Periods*10 mod 26 = {periods_key}")
    full_key = (periods_key * (CT_LEN // 9 + 1))[:CT_LEN]
    test_substitution_key("periods_mod26", full_key, results)
    total_tests += 3

    # B3: Planet numbers (1-9) as key
    pnum_key = [(n - 1) % 26 for n in PLANET_NUMBERS]  # 0-indexed: 0-8
    print(f"\nB3: Planet numbers (0-indexed) = {pnum_key}")
    full_key = (pnum_key * (CT_LEN // 9 + 1))[:CT_LEN]
    test_substitution_key("planet_numbers", full_key, results)
    total_tests += 3

    # B4: Radii ratios (relative to Earth) rounded
    radii_ratio = [round(r / 1.0 * 26) % 26 for r in ORBITAL_RADII_AU]
    print(f"\nB4: Radii ratios * 26 mod 26 = {radii_ratio}")
    full_key = (radii_ratio * (CT_LEN // 9 + 1))[:CT_LEN]
    test_substitution_key("radii_ratio", full_key, results)
    total_tests += 3

    # ──────────────────────────────────────────────────────────────────────
    # PHASE C: Planet-derived columnar transpositions (width 9)
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE C: Width-9 columnar transposition from planet orderings")
    print("─" * 72)

    col_orders = {}

    # C1: MVEMJSUNP keyword → column order
    co1 = keyword_to_col_order(PLANET_INITIALS)
    col_orders["MVEMJSUNP"] = co1
    print(f"\nC1: MVEMJSUNP → col order {co1}")

    # C2: Reverse (PNUSJMEVM)
    co2 = keyword_to_col_order(PLANET_INITIALS[::-1])
    col_orders["PNUSJMEVM"] = co2
    print(f"C2: PNUSJMEVM → col order {co2}")

    # C3: Alphabetical English planet names → order by sorted rank
    co3 = [alpha_en.index(i) for i in range(9)]  # rank of each planet
    col_orders["alpha_en"] = co3
    print(f"C3: Alpha EN order → {co3}")

    # C4: Alphabetical German planet names → order by sorted rank
    co4 = [alpha_de.index(i) for i in range(9)]
    col_orders["alpha_de"] = co4
    print(f"C4: Alpha DE order → {co4}")

    # C5: By orbital radius (already natural order 0-8, but let's also try reverse)
    co5_fwd = list(range(9))  # trivial (identity)
    co5_rev = list(range(8, -1, -1))  # reverse
    col_orders["radius_out"] = co5_fwd
    col_orders["radius_in"] = co5_rev
    print(f"C5: Radius outward → {co5_fwd} (identity)")
    print(f"    Radius inward  → {co5_rev}")

    # C6: By orbital period (same as radius order for planets, but let's be explicit)
    period_order = sorted(range(9), key=lambda i: ORBITAL_PERIODS_YR[i])
    co6 = [period_order.index(i) for i in range(9)]
    col_orders["period_rank"] = co6
    print(f"C6: Period rank → {co6}")

    # C7: German full planet names as keyword
    for name in PLANETS_DE:
        if len(name) == 9:  # only if it happens to be 9 chars
            co = keyword_to_col_order(name)
            col_orders[f"kw_{name}"] = co
            print(f"C7: Keyword '{name}' → {co}")

    # Test each column order as transposition-only
    for pname, co in col_orders.items():
        perm = apply_columnar(CT, 9, co)
        if perm and len(perm) == CT_LEN:
            test_transposition_only(f"w9_{pname}", perm, results)
            total_tests += 1

    # ──────────────────────────────────────────────────────────────────────
    # PHASE D: Planetary positions on key dates → numeric key
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE D: Planetary ecliptic longitudes on key dates")
    print("─" * 72)

    dates = {
        "berlin_wall_1989_11_09": JD_BERLIN_WALL,
        "kryptos_ded_1990_11_03": JD_KRYPTOS_DED,
        "egypt_1986_01_01": JD_EGYPT_1986,
    }

    for date_name, jd in dates.items():
        lons = [mean_longitude(i, jd) for i in range(9)]
        print(f"\n{date_name}:")
        for i, (name, lon) in enumerate(zip(PLANETS_EN, lons)):
            print(f"  {name:10s}: {lon:7.2f}°")

        # D1: Longitude degrees mod 26
        key_d1 = [round(lon) % 26 for lon in lons]
        print(f"  → mod 26 key: {key_d1}")
        full_key = (key_d1 * (CT_LEN // 9 + 1))[:CT_LEN]
        test_substitution_key(f"lon_mod26_{date_name}", full_key, results)
        total_tests += 3

        # D2: Longitude / 360 * 26 (map full circle to alphabet)
        key_d2 = [round(lon / 360.0 * 26) % 26 for lon in lons]
        print(f"  → scaled key:  {key_d2}")
        full_key = (key_d2 * (CT_LEN // 9 + 1))[:CT_LEN]
        test_substitution_key(f"lon_scaled_{date_name}", full_key, results)
        total_tests += 3

        # D3: Longitude differences from Earth (offset from our perspective)
        earth_lon = lons[2]
        key_d3 = [round(((lon - earth_lon) % 360)) % 26 for lon in lons]
        print(f"  → Earth-rel:   {key_d3}")
        full_key = (key_d3 * (CT_LEN // 9 + 1))[:CT_LEN]
        test_substitution_key(f"lon_earthrel_{date_name}", full_key, results)
        total_tests += 3

        # D4: Planet order sorted by longitude on that date → columnar key
        lon_order = sorted(range(9), key=lambda i: lons[i])
        col_key = [lon_order.index(i) for i in range(9)]
        print(f"  → longitude-sorted col order: {col_key}")
        perm = apply_columnar(CT, 9, col_key)
        if perm and len(perm) == CT_LEN:
            test_transposition_only(f"w9_lon_{date_name}", perm, results)
            total_tests += 1

    # ──────────────────────────────────────────────────────────────────────
    # PHASE E: Combined substitution + transposition
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE E: Combined planet substitution + width-9 transposition")
    print("─" * 72)

    # Test key substitution keys × key transposition orderings
    sub_keys = {
        "MVEMJSUNP": make_key(PLANET_INITIALS),
        "concat_EN": make_key("".join(PLANETS_EN))[:CT_LEN],
        "concat_DE": make_key("".join(PLANETS_DE))[:CT_LEN],
    }

    # Add date-based keys
    for date_name, jd in dates.items():
        lons = [mean_longitude(i, jd) for i in range(9)]
        key = [round(lon) % 26 for lon in lons]
        sub_keys[f"lon_{date_name}"] = (key * (CT_LEN // 9 + 1))[:CT_LEN]

    # Select most interesting column orders
    interesting_cols = {k: v for k, v in col_orders.items()
                        if k not in ("radius_out",)}  # skip identity

    # Add date-based column orders
    for date_name, jd in dates.items():
        lons = [mean_longitude(i, jd) for i in range(9)]
        lon_order = sorted(range(9), key=lambda i: lons[i])
        col_key = [lon_order.index(i) for i in range(9)]
        interesting_cols[f"lon_{date_name}"] = col_key

    combo_count = 0
    for sk_name, sk_vals in sub_keys.items():
        for co_name, co_vals in interesting_cols.items():
            perm = apply_columnar(CT, 9, co_vals)
            if perm and len(perm) == CT_LEN:
                test_combined(sk_name, sk_vals, f"w9_{co_name}", perm, results)
                combo_count += 1
                total_tests += 6  # 3 variants × 2 orders

    print(f"\n  Tested {combo_count} sub×trans combinations ({combo_count * 6} configs)")

    # ──────────────────────────────────────────────────────────────────────
    # PHASE F: All 9! = 362880 width-9 orderings × planet initials key
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE F: MVEMJSUNP key × ALL 362,880 width-9 columnar orderings")
    print("─" * 72)

    key_mvem = make_key(PLANET_INITIALS)
    phase_f_best = 0
    phase_f_count = 0
    phase_f_checked = 0

    for perm_tuple in itertools.permutations(range(9)):
        col_order = list(perm_tuple)
        perm = apply_columnar(CT, 9, col_order)
        if not perm or len(perm) != CT_LEN:
            continue

        inv = invert_perm(perm)

        for variant in VARIANTS:
            # sub then trans
            pt_sub = decrypt_text(CT, key_mvem, variant)
            pt = apply_perm(pt_sub, inv)
            sc = score_cribs(pt)

            if sc > phase_f_best:
                phase_f_best = sc
                vname = VARIANT_NAMES[variant]
                print(f"  New best: score={sc} order={col_order} {vname} (sub→trans) pt={pt[:30]}...")

            if sc > NOISE_FLOOR:
                results.append({
                    "test": f"F_MVEMJSUNP_w9perm_{vname}_st",
                    "score": sc,
                    "col_order": col_order,
                    "variant": VARIANT_NAMES[variant],
                    "order": "sub_trans",
                    "pt_snippet": pt[:40],
                })

            # trans then sub
            ct_untrans = apply_perm(CT, inv)
            pt2 = decrypt_text(ct_untrans, key_mvem, variant)
            sc2 = score_cribs(pt2)

            if sc2 > phase_f_best:
                phase_f_best = sc2
                vname = VARIANT_NAMES[variant]
                print(f"  New best: score={sc2} order={col_order} {vname} (trans→sub) pt={pt2[:30]}...")

            if sc2 > NOISE_FLOOR:
                results.append({
                    "test": f"F_MVEMJSUNP_w9perm_{vname}_ts",
                    "score": sc2,
                    "col_order": col_order,
                    "variant": VARIANT_NAMES[variant],
                    "order": "trans_sub",
                    "pt_snippet": pt2[:40],
                })

            phase_f_checked += 2

        phase_f_count += 1
        if phase_f_count % 50000 == 0:
            elapsed = time_mod.time() - t0
            print(f"  ... {phase_f_count}/362880 orderings, {phase_f_checked} configs, "
                  f"best={phase_f_best}, {elapsed:.1f}s")

    total_tests += phase_f_checked
    print(f"\n  Phase F complete: {phase_f_checked} configs, best score = {phase_f_best}")

    # ──────────────────────────────────────────────────────────────────────
    # PHASE G: Concatenated planet names as running key × all w9 orderings
    # (Sampled — too many to exhaust)
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE G: Planet name running keys × sampled w9 orderings (10K sample)")
    print("─" * 72)

    import random as rng
    rng.seed(SEED)

    running_keys = {
        "concat_EN": make_key("".join(PLANETS_EN))[:CT_LEN],
        "concat_DE": make_key("".join(PLANETS_DE))[:CT_LEN],
        "concat_EN_rev": make_key("".join(reversed(PLANETS_EN)))[:CT_LEN],
        "concat_DE_rev": make_key("".join(reversed(PLANETS_DE)))[:CT_LEN],
        # Double-concatenated (longer coverage)
        "double_EN": make_key("".join(PLANETS_EN * 2))[:CT_LEN],
        "double_DE": make_key("".join(PLANETS_DE * 2))[:CT_LEN],
    }

    phase_g_best = 0
    phase_g_checked = 0
    sample_perms = [list(p) for p in rng.sample(
        list(itertools.permutations(range(9))), min(10000, 362880)
    )]

    for rk_name, rk_vals in running_keys.items():
        for col_order in sample_perms:
            perm = apply_columnar(CT, 9, col_order)
            if not perm or len(perm) != CT_LEN:
                continue
            inv = invert_perm(perm)

            for variant in VARIANTS:
                pt_sub = decrypt_text(CT, rk_vals, variant)
                pt = apply_perm(pt_sub, inv)
                sc = score_cribs(pt)

                if sc > phase_g_best:
                    phase_g_best = sc
                    vname = VARIANT_NAMES[variant]
                    print(f"  New best: score={sc} key={rk_name} order={col_order} "
                          f"{vname} pt={pt[:30]}...")

                if sc > NOISE_FLOOR:
                    results.append({
                        "test": f"G_{rk_name}_w9_{VARIANT_NAMES[variant]}",
                        "score": sc,
                        "col_order": col_order,
                        "variant": VARIANT_NAMES[variant],
                        "pt_snippet": pt[:40],
                    })

                phase_g_checked += 1

        print(f"  {rk_name}: {len(sample_perms) * 3} configs checked, best={phase_g_best}")

    total_tests += phase_g_checked

    # ──────────────────────────────────────────────────────────────────────
    # SUMMARY
    # ──────────────────────────────────────────────────────────────────────
    elapsed = time_mod.time() - t0

    above_noise = [r for r in results if r["score"] > NOISE_FLOOR]
    above_store = [r for r in results if r["score"] >= STORE_THRESHOLD]

    if results:
        best = max(results, key=lambda r: r["score"])
    else:
        best = {"score": 0, "test": "none"}

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configurations tested: {total_tests}")
    print(f"Above NOISE ({NOISE_FLOOR}): {len(above_noise)}")
    print(f"Above STORE ({STORE_THRESHOLD}): {len(above_store)}")
    print(f"Best score: {best['score']} ({best.get('test', 'N/A')})")
    print(f"Elapsed: {elapsed:.1f}s")

    if above_store:
        print(f"\n  STORE-level results:")
        for r in sorted(above_store, key=lambda x: -x["score"])[:10]:
            print(f"    score={r['score']} test={r['test']}")

    print(f"\nConclusion: ", end="")
    if best["score"] >= STORE_THRESHOLD:
        print(f"SIGNAL DETECTED — best score {best['score']} warrants investigation")
    elif best["score"] > NOISE_FLOOR:
        print(f"Marginal results (best={best['score']}), likely noise but logged")
    else:
        print(f"No signal. Solar system model does not appear to be K4 key source.")

    # Save results
    os.makedirs("results", exist_ok=True)
    output = {
        "experiment": "E-S-142",
        "description": "Weltzeituhr orrery (solar system model) as K4 key material",
        "total_tests": total_tests,
        "best_score": best["score"],
        "best_test": best.get("test"),
        "above_noise": len(above_noise),
        "above_store": len(above_store),
        "elapsed_s": round(elapsed, 1),
        "results": sorted(results, key=lambda r: -r["score"])[:50],
    }

    outpath = "results/e_s_142_weltzeituhr_orrery.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")


if __name__ == "__main__":
    main()
