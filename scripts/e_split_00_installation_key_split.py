#!/usr/bin/env python3
"""E-SPLIT-00: Installation Key Split Combiner

Tests the hypothesis that K4's encryption key is composed from multiple
independent "splits" derived from different Kryptos installation elements,
combined following Ed Scheidt's CKM key-split-combiner principle.

Background:
  Scheidt held 36 patents on Constructive Key Management (CKM), where
  encryption keys are split across independent generators and reconstituted
  at decrypt time. Gillogly stated K4 uses "an invention by Ed Scheidt that
  has never appeared in cryptographic literature." The key DERIVATION process
  (combining installation elements) is the novel invention, not the cipher
  primitive itself.

Station LOOMIS (HV4826):
  NGS geodetic marker at 38°57'06.22"N, 077°08'48.14"W, Fairfax County VA.
  Located on what became CIA grounds. Destroyed, replaced by BOWEN (AJ3427).
  Sanborn confirmed a bronze USGS marker was buried near Kryptos and
  "remains important to solving K4."

Phases:
  1. Alphabetic key-split pairs (mod-26 add/sub/concat/interleave) × 3 variants
  2. Alphabetic + numeric (LOOMIS datasheet values) × 3 variants
  3. Keyword transposition + keyword Vigenere from different sources
  4. Triple splits (three key sources combined)

Scoring: crib match (24 positions), Bean constraints, quadgram analysis.
"""
import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, DECRYPT_FN,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
)
from kryptos.kernel.constraints.bean import verify_bean
from kryptos.kernel.alphabet import KA

# ── Constants ─────────────────────────────────────────────────────────────

CT_NUM = [ALPH_IDX[c] for c in CT]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
VARIANT_NAMES = {CipherVariant.VIGENERE: "Vig", CipherVariant.BEAUFORT: "Beau",
                 CipherVariant.VAR_BEAUFORT: "VarBeau"}

# ── Key Sources ───────────────────────────────────────────────────────────

# Alphabetic sources: words from the Kryptos installation
ALPHA_SOURCES = {
    # Core installation elements
    "KRYPTOS":      [ALPH_IDX[c] for c in "KRYPTOS"],
    "LOOMIS":       [ALPH_IDX[c] for c in "LOOMIS"],
    "BOWEN":        [ALPH_IDX[c] for c in "BOWEN"],
    "ABBOTT":       [ALPH_IDX[c] for c in "ABBOTT"],
    # K1-K3 keywords
    "PALIMPSEST":   [ALPH_IDX[c] for c in "PALIMPSEST"],
    "ABSCISSA":     [ALPH_IDX[c] for c in "ABSCISSA"],
    # K2/K4 content
    "BERLINCLOCK":  [ALPH_IDX[c] for c in "BERLINCLOCK"],
    "WEBSTER":      [ALPH_IDX[c] for c in "WEBSTER"],
    # People
    "SANBORN":      [ALPH_IDX[c] for c in "SANBORN"],
    "SCHEIDT":      [ALPH_IDX[c] for c in "SCHEIDT"],
    # Location
    "LANGLEY":      [ALPH_IDX[c] for c in "LANGLEY"],
    "FALLSCHURCH":  [ALPH_IDX[c] for c in "FALLSCHURCH"],
    # K1/K2 plaintext words
    "SHADOW":       [ALPH_IDX[c] for c in "SHADOW"],
    "IQLUSION":     [ALPH_IDX[c] for c in "IQLUSION"],
    "LAYERTWO":     [ALPH_IDX[c] for c in "LAYERTWO"],
    "IDBYROWS":     [ALPH_IDX[c] for c in "IDBYROWS"],
    # Thematic
    "CLOCK":        [ALPH_IDX[c] for c in "CLOCK"],
    "BERLIN":       [ALPH_IDX[c] for c in "BERLIN"],
    "WELTZEITUHR":  [ALPH_IDX[c] for c in "WELTZEITUHR"],
    "DRUSILLA":     [ALPH_IDX[c] for c in "DRUSILLA"],
    # BOWEN extended context
    "PBOWEN":       [ALPH_IDX[c] for c in "PBOWEN"],        # P. Bowen (who the station is named after)
    "OLDGEORGETOWN":[ALPH_IDX[c] for c in "OLDGEORGETOWN"], # 6300 Old Georgetown Pike
    "MCLEAN":       [ALPH_IDX[c] for c in "MCLEAN"],        # McLean, Virginia
    "TURNERFAIRBANK":[ALPH_IDX[c] for c in "TURNERFAIRBANK"],# Turner-Fairbank Highway Research Center
}

# Numeric sources: from LOOMIS datasheet and K2
NUMERIC_SOURCES = {
    "K2_lat_dms":       [3,8,5,7,6,5],         # 38°57'6.5"
    "K2_lon_dms":       [7,7,8,4,4],            # 77°8'44"
    "K2_coords_full":   [3,8,5,7,6,5,7,7,8,4,4],  # all K2 coord digits
    "LOOMIS_elev_m":    [7,9],                   # 79 meters
    "LOOMIS_elev_ft":   [2,5,9],                 # 259 feet
    "LOOMIS_PID":       [7,21,4,8,2,6],          # HV4826 as alpha values
    "LOOMIS_PID_digits":[4,8,2,6],               # 4826
    "LOOMIS_year":      [1,9,3,0],               # 1930
    "LOOMIS_geoid":     [3,1,8,2],               # 31.82 (geoid height)
    "LOOMIS_az_ABBOTT": [4,5,3,5,0,5],           # azimuth 45°35'05.5"
    "LOOMIS_lat_sec":   [0,6,2,2,0,0,7],         # 06.22007"
    "LOOMIS_lon_sec":   [4,8,1,4,1,9,2],         # 48.14192"
    "LOOMIS_UTM_N":     [4,3,1,3,6,1,1],         # UTM northing 4313611
    "LOOMIS_UTM_E":     [3,1,3,9,7,7],           # UTM easting 313977
    "BOWEN_PID":        [0,9,3,4,2,7],            # AJ3427 as alpha values
    "BOWEN_PID_digits": [3,4,2,7],               # 3427
    "coord_diff_lon":   [4,1,4],                  # ~4.14" lon difference K2 vs LOOMIS
    "eight_lines_73":   [8,7,3],                  # Sanborn's yellow pad note
    "elevation_79":     [0,7,9],                  # 079 zero-padded
    # BOWEN datasheet values (AJ3427, replacement for LOOMIS, established 1984)
    "BOWEN_year":       [1,9,8,4],               # 1984
    "BOWEN_lat_sec":    [1,8],                    # ~18" lat
    "BOWEN_lon_sec":    [5,5],                    # ~55" lon
    "BOWEN_grid":       [1,3,8,1,3,9],            # USNG grid 18SUJ 138 139
    "LOOMIS_BOWEN_yrs": [1,9,3,0,1,9,8,4],       # both years concatenated
    "PBOWEN_alpha":     [15,1,14,22,4,13],        # PBOWEN as A-Z values
}


# ── Crib checking ─────────────────────────────────────────────────────────

def check_cribs(pt_nums: list[int]) -> int:
    """Count how many of the 24 known plaintext positions match."""
    matches = 0
    for pos, expected_char in CRIB_DICT.items():
        if pos < len(pt_nums):
            expected_num = ALPH_IDX[expected_char]
            if pt_nums[pos] == expected_num:
                matches += 1
    return matches


def check_bean(pt_nums: list[int], ct_nums: list[int]) -> tuple[bool, bool]:
    """Check Bean equality and inequality constraints.
    Returns (eq_pass, ineq_pass).
    Uses Vigenere key recovery: k = (c - p) mod 26.
    Bean constraints are variant-independent for the equality check
    since CT[27]=CT[65] and PT[27]=PT[65]."""
    # Bean equality: k[27] = k[65]
    k27 = (ct_nums[27] - pt_nums[27]) % MOD
    k65 = (ct_nums[65] - pt_nums[65]) % MOD
    eq_pass = (k27 == k65)

    # Bean inequality: all 21 pairs must differ
    ineq_pass = True
    for p1, p2 in BEAN_INEQ:
        if p1 < len(pt_nums) and p2 < len(pt_nums):
            k1 = (ct_nums[p1] - pt_nums[p1]) % MOD
            k2 = (ct_nums[p2] - pt_nums[p2]) % MOD
            if k1 == k2:
                ineq_pass = False
                break

    return eq_pass, ineq_pass


def nums_to_text(nums: list[int]) -> str:
    return "".join(ALPH[n % MOD] for n in nums)


# ── Key combination methods ───────────────────────────────────────────────

def combine_add(a: list[int], b: list[int], length: int = CT_LEN) -> list[int]:
    """Mod-26 addition: K[i] = (A[i%la] + B[i%lb]) mod 26."""
    return [(a[i % len(a)] + b[i % len(b)]) % MOD for i in range(length)]

def combine_sub(a: list[int], b: list[int], length: int = CT_LEN) -> list[int]:
    """Mod-26 subtraction: K[i] = (A[i%la] - B[i%lb]) mod 26."""
    return [(a[i % len(a)] - b[i % len(b)]) % MOD for i in range(length)]

def combine_concat(a: list[int], b: list[int], length: int = CT_LEN) -> list[int]:
    """Concatenation: A||B repeated to fill length."""
    ab = a + b
    return [ab[i % len(ab)] for i in range(length)]

def combine_interleave(a: list[int], b: list[int], length: int = CT_LEN) -> list[int]:
    """Interleave: A₁B₁A₂B₂... repeated to fill length."""
    inter = []
    max_pairs = max(len(a), len(b))
    for i in range(max_pairs):
        inter.append(a[i % len(a)])
        inter.append(b[i % len(b)])
    return [inter[i % len(inter)] for i in range(length)]

COMBINE_METHODS = {
    "add": combine_add,
    "sub_AB": combine_sub,
    "sub_BA": lambda a, b, n=CT_LEN: combine_sub(b, a, n),
    "concat_AB": combine_concat,
    "concat_BA": lambda a, b, n=CT_LEN: combine_concat(b, a, n),
    "interleave": combine_interleave,
}


# ── Decrypt with full key ─────────────────────────────────────────────────

def decrypt_with_key(ct_nums: list[int], key: list[int],
                     variant: CipherVariant) -> list[int]:
    """Decrypt CT with a full-length key using specified variant."""
    dec_fn = DECRYPT_FN[variant]
    return [dec_fn(ct_nums[i], key[i]) for i in range(len(ct_nums))]


# ── Quadgram scoring (lightweight) ────────────────────────────────────────

QUADGRAMS = None

def load_quadgrams():
    global QUADGRAMS
    qg_path = os.path.join(os.path.dirname(__file__), "..", "data",
                           "english_quadgrams.json")
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            QUADGRAMS = json.load(f)
    else:
        QUADGRAMS = {}


def quadgram_score(text: str) -> float:
    """Log-probability per character using quadgram model."""
    if not QUADGRAMS:
        return -10.0
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, -10.0)
        count += 1
    return total / max(count, 1)


# ── Word detection ────────────────────────────────────────────────────────

WORDSET = None

def load_wordlist():
    global WORDSET
    wl_path = os.path.join(os.path.dirname(__file__), "..", "wordlists",
                           "english.txt")
    if os.path.exists(wl_path):
        with open(wl_path) as f:
            WORDSET = set(w.strip().upper() for w in f if len(w.strip()) >= 4)
    else:
        WORDSET = set()


def count_words(text: str, min_len: int = 5) -> list[str]:
    """Find English words of length >= min_len in text."""
    found = []
    for wlen in range(min(12, len(text)), min_len - 1, -1):
        for i in range(len(text) - wlen + 1):
            word = text[i:i+wlen]
            if word in WORDSET:
                found.append(word)
    return found


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    load_quadgrams()
    load_wordlist()

    results = []
    best_score = 0
    total_tests = 0
    above_noise = 0  # score > 6

    def test_candidate(key: list[int], variant: CipherVariant,
                       desc: str, category: str):
        nonlocal best_score, total_tests, above_noise
        total_tests += 1

        pt_nums = decrypt_with_key(CT_NUM, key, variant)
        crib_matches = check_cribs(pt_nums)

        if crib_matches > best_score:
            best_score = crib_matches

        if crib_matches > 6:  # above noise floor
            above_noise += 1
            pt_text = nums_to_text(pt_nums)
            eq_pass, ineq_pass = check_bean(pt_nums, CT_NUM)
            qg = quadgram_score(pt_text)
            words = count_words(pt_text) if WORDSET else []

            result = {
                "desc": desc,
                "category": category,
                "variant": VARIANT_NAMES[variant],
                "crib_matches": crib_matches,
                "bean_eq": eq_pass,
                "bean_ineq": ineq_pass,
                "quadgram": round(qg, 3),
                "words_found": words[:10],
                "pt_preview": pt_text[:40],
                "key_preview": nums_to_text(key[:20]),
                "key_period": len(set(
                    tuple(key[i::p] for i in range(p))
                    for p in range(1, min(30, len(key)+1))
                )),
            }
            results.append(result)

        if crib_matches >= 18:  # signal threshold
            pt_text = nums_to_text(pt_nums)
            print(f"\n*** SIGNAL ({crib_matches}/24) ***")
            print(f"  Desc: {desc}")
            print(f"  Variant: {VARIANT_NAMES[variant]}")
            print(f"  PT: {pt_text}")
            print(f"  Key: {nums_to_text(key[:30])}")

        if crib_matches == 24:
            pt_text = nums_to_text(pt_nums)
            eq_pass, ineq_pass = check_bean(pt_nums, CT_NUM)
            print(f"\n{'='*70}")
            print(f"!!! BREAKTHROUGH — 24/24 CRIB MATCH !!!")
            print(f"  Desc: {desc}")
            print(f"  Variant: {VARIANT_NAMES[variant]}")
            print(f"  Bean EQ: {eq_pass}, Bean INEQ: {ineq_pass}")
            print(f"  PT: {pt_text}")
            print(f"  Key: {nums_to_text(key)}")
            print(f"{'='*70}")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 1: Alphabetic key-split pairs
    # ══════════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PHASE 1: Alphabetic Key-Split Pairs")
    print("=" * 70)

    alpha_names = list(ALPHA_SOURCES.keys())
    p1_count = 0

    for i, name_a in enumerate(alpha_names):
        key_a = ALPHA_SOURCES[name_a]
        for j, name_b in enumerate(alpha_names):
            if i == j:
                continue  # skip self-pairs for add/sub (trivial)
            key_b = ALPHA_SOURCES[name_b]

            for comb_name, comb_fn in COMBINE_METHODS.items():
                combined = comb_fn(key_a, key_b, CT_LEN)
                desc = f"{name_a}+{name_b}({comb_name})"

                for variant in VARIANTS:
                    test_candidate(combined, variant, desc, "alpha_pair")
                    p1_count += 1

    print(f"  Phase 1 complete: {p1_count} tests, "
          f"best={best_score}/24, above_noise={above_noise}")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 2: Alphabetic + Numeric combined keys
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 2: Alphabetic + Numeric Key Splits")
    print("=" * 70)

    p2_count = 0

    for alpha_name, alpha_key in ALPHA_SOURCES.items():
        for num_name, num_key in NUMERIC_SOURCES.items():
            # Add numeric to alphabetic
            combined_add = combine_add(alpha_key, num_key, CT_LEN)
            combined_sub = combine_sub(alpha_key, num_key, CT_LEN)
            combined_rsub = combine_sub(num_key, alpha_key, CT_LEN)

            for combined, cname in [(combined_add, "add"),
                                     (combined_sub, "sub"),
                                     (combined_rsub, "rsub")]:
                desc = f"{alpha_name}+{num_name}({cname})"
                for variant in VARIANTS:
                    test_candidate(combined, variant, desc, "alpha_num")
                    p2_count += 1

    print(f"  Phase 2 complete: {p2_count} tests, "
          f"best={best_score}/24, above_noise={above_noise}")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 3: Transposition (one source) + Substitution (another source)
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 3: Keyword Transposition + Keyword Substitution")
    print("=" * 70)

    p3_count = 0

    # Use keywords that produce reasonable column widths for transposition
    trans_keywords = {}
    for name, key in ALPHA_SOURCES.items():
        width = len(key)
        if 4 <= width <= 12:
            order = keyword_to_order(name, width)
            if order is not None:
                perm = columnar_perm(width, order, CT_LEN)
                inv = invert_perm(perm)
                trans_keywords[name] = {"perm": perm, "inv": inv,
                                        "width": width, "order": order}

    for trans_name, trans_data in trans_keywords.items():
        # Direction 1: Undo transposition first, then decrypt substitution
        untransposed = apply_perm(CT, trans_data["inv"])
        ut_nums = [ALPH_IDX[c] for c in untransposed]

        for sub_name, sub_key in ALPHA_SOURCES.items():
            if sub_name == trans_name:
                continue  # different sources for split knowledge

            sub_full = [sub_key[i % len(sub_key)] for i in range(CT_LEN)]

            for variant in VARIANTS:
                pt_nums = decrypt_with_key(ut_nums, sub_full, variant)
                desc = f"trans({trans_name}w{trans_data['width']})+sub({sub_name},{VARIANT_NAMES[variant]})"

                # Inline scoring for transposition phase
                crib_matches = check_cribs(pt_nums)
                total_tests += 1
                p3_count += 1

                if crib_matches > 6:
                    above_noise += 1
                    pt_text = nums_to_text(pt_nums)
                    eq_pass, ineq_pass = check_bean(pt_nums, CT_NUM)
                    results.append({
                        "desc": desc, "category": "trans_sub",
                        "variant": VARIANT_NAMES[variant],
                        "crib_matches": crib_matches,
                        "bean_eq": eq_pass, "bean_ineq": ineq_pass,
                        "quadgram": round(quadgram_score(pt_text), 3),
                        "words_found": count_words(pt_text)[:10] if WORDSET else [],
                        "pt_preview": pt_text[:40],
                        "key_preview": f"trans={trans_name},sub={sub_name}",
                    })
                    if crib_matches > best_score:
                        best_score = crib_matches
                if crib_matches >= 18:
                    pt_text = nums_to_text(pt_nums)
                    print(f"\n*** SIGNAL ({crib_matches}/24) trans+sub ***")
                    print(f"  {desc}")
                    print(f"  PT: {pt_text}")

        # Direction 2: Decrypt substitution first, then undo transposition
        for sub_name, sub_key in ALPHA_SOURCES.items():
            if sub_name == trans_name:
                continue

            sub_full = [sub_key[i % len(sub_key)] for i in range(CT_LEN)]

            for variant in VARIANTS:
                pt_nums_sub = decrypt_with_key(CT_NUM, sub_full, variant)
                pt_sub_text = nums_to_text(pt_nums_sub)
                pt_text = apply_perm(pt_sub_text, trans_data["inv"])
                pt_nums = [ALPH_IDX[c] for c in pt_text]
                desc = f"sub({sub_name},{VARIANT_NAMES[variant]})+trans({trans_name}w{trans_data['width']})"

                crib_matches = check_cribs(pt_nums)
                total_tests += 1
                p3_count += 1

                if crib_matches > 6:
                    above_noise += 1
                    eq_pass, ineq_pass = check_bean(pt_nums, CT_NUM)
                    results.append({
                        "desc": desc, "category": "sub_trans",
                        "variant": VARIANT_NAMES[variant],
                        "crib_matches": crib_matches,
                        "bean_eq": eq_pass, "bean_ineq": ineq_pass,
                        "quadgram": round(quadgram_score(pt_text), 3),
                        "words_found": count_words(pt_text)[:10] if WORDSET else [],
                        "pt_preview": pt_text[:40],
                        "key_preview": f"sub={sub_name},trans={trans_name}",
                    })
                    if crib_matches > best_score:
                        best_score = crib_matches
                if crib_matches >= 18:
                    print(f"\n*** SIGNAL ({crib_matches}/24) sub+trans ***")
                    print(f"  {desc}")
                    print(f"  PT: {pt_text}")

    print(f"  Phase 3 complete: {p3_count} tests, "
          f"best={best_score}/24, above_noise={above_noise}")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 4: Triple Splits (three sources combined)
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 4: Triple Key Splits (A + B + C)")
    print("=" * 70)

    p4_count = 0

    # Priority triples: always include KRYPTOS or LOOMIS as anchor
    anchor_keys = ["KRYPTOS", "LOOMIS", "BOWEN", "PALIMPSEST", "ABSCISSA"]

    for anchor in anchor_keys:
        key_anchor = ALPHA_SOURCES[anchor]
        # Combine with every pair of other alphabetic sources
        other_names = [n for n in alpha_names if n != anchor]

        for i, name_b in enumerate(other_names):
            key_b = ALPHA_SOURCES[name_b]
            for name_c in other_names[i+1:]:
                key_c = ALPHA_SOURCES[name_c]

                # Triple addition: A + B + C
                triple = [(key_anchor[k % len(key_anchor)]
                          + key_b[k % len(key_b)]
                          + key_c[k % len(key_c)]) % MOD
                         for k in range(CT_LEN)]
                desc = f"{anchor}+{name_b}+{name_c}(add3)"

                for variant in VARIANTS:
                    test_candidate(triple, variant, desc, "triple")
                    p4_count += 1

        # Triple with numeric sources
        for num_name, num_key in NUMERIC_SOURCES.items():
            for name_b in alpha_names:
                if name_b == anchor:
                    continue
                key_b = ALPHA_SOURCES[name_b]
                triple = [(key_anchor[k % len(key_anchor)]
                          + key_b[k % len(key_b)]
                          + num_key[k % len(num_key)]) % MOD
                         for k in range(CT_LEN)]
                desc = f"{anchor}+{name_b}+{num_name}(add3)"
                for variant in VARIANTS:
                    test_candidate(triple, variant, desc, "triple_num")
                    p4_count += 1

    print(f"  Phase 4 complete: {p4_count} tests, "
          f"best={best_score}/24, above_noise={above_noise}")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 5: LOOMIS/BOWEN-specific deep tests
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 5: LOOMIS/BOWEN Deep Investigation")
    print("=" * 70)

    p5_count = 0

    # Test station names as direct keys (simple Vigenere)
    for station in ["LOOMIS", "BOWEN", "ABBOTT"]:
        key = ALPHA_SOURCES[station]
        full_key = [key[i % len(key)] for i in range(CT_LEN)]
        for variant in VARIANTS:
            test_candidate(full_key, variant, f"direct({station})", "station_direct")
            p5_count += 1

    # LOOMIS full designation as key
    loomis_full = [ALPH_IDX[c] for c in "LOOMISPBANDPP"]
    full_key = [loomis_full[i % len(loomis_full)] for i in range(CT_LEN)]
    for variant in VARIANTS:
        test_candidate(full_key, variant, "direct(LOOMISPBANDPP)", "station_direct")
        p5_count += 1

    # LOOMIS combined with coordinate data from its own datasheet
    for num_name in ["LOOMIS_PID", "LOOMIS_PID_digits", "LOOMIS_year",
                     "LOOMIS_elev_m", "LOOMIS_elev_ft", "LOOMIS_az_ABBOTT",
                     "LOOMIS_lat_sec", "LOOMIS_lon_sec", "LOOMIS_geoid",
                     "LOOMIS_UTM_N", "LOOMIS_UTM_E"]:
        num_key = NUMERIC_SOURCES[num_name]
        # KRYPTOS + LOOMIS_data
        combo = combine_add(ALPHA_SOURCES["KRYPTOS"], num_key, CT_LEN)
        for variant in VARIANTS:
            test_candidate(combo, variant,
                          f"KRYPTOS+{num_name}(add)", "loomis_deep")
            p5_count += 1

        # LOOMIS + LOOMIS_data
        combo2 = combine_add(ALPHA_SOURCES["LOOMIS"], num_key, CT_LEN)
        for variant in VARIANTS:
            test_candidate(combo2, variant,
                          f"LOOMIS+{num_name}(add)", "loomis_deep")
            p5_count += 1

    # LOOMIS as transposition + KRYPTOS as substitution (and vice versa)
    # with elevation/coordinate augmented keys
    for aug_name in ["LOOMIS_elev_m", "LOOMIS_PID_digits", "K2_coords_full",
                     "LOOMIS_az_ABBOTT", "eight_lines_73"]:
        aug = NUMERIC_SOURCES[aug_name]

        # KRYPTOS + augmentation as substitution key
        sub_key = combine_add(ALPHA_SOURCES["KRYPTOS"], aug, CT_LEN)

        # LOOMIS as transposition
        if "LOOMIS" in trans_keywords:
            td = trans_keywords["LOOMIS"]
            untransposed = apply_perm(CT, td["inv"])
            ut_nums = [ALPH_IDX[c] for c in untransposed]
            for variant in VARIANTS:
                pt_nums = decrypt_with_key(ut_nums, sub_key, variant)
                desc = f"trans(LOOMIS)+sub(KRYPTOS+{aug_name},{VARIANT_NAMES[variant]})"
                crib_matches = check_cribs(pt_nums)
                total_tests += 1
                p5_count += 1
                if crib_matches > 6:
                    above_noise += 1
                    pt_text = nums_to_text(pt_nums)
                    eq_pass, ineq_pass = check_bean(pt_nums, CT_NUM)
                    results.append({
                        "desc": desc, "category": "loomis_deep",
                        "variant": VARIANT_NAMES[variant],
                        "crib_matches": crib_matches,
                        "bean_eq": eq_pass, "bean_ineq": ineq_pass,
                        "quadgram": round(quadgram_score(pt_text), 3),
                        "words_found": count_words(pt_text)[:10] if WORDSET else [],
                        "pt_preview": pt_text[:40],
                        "key_preview": f"trans=LOOMIS,sub=KRYPTOS+{aug_name}",
                    })
                    if crib_matches > best_score:
                        best_score = crib_matches
                if crib_matches >= 18:
                    pt_text = nums_to_text(pt_nums)
                    print(f"\n*** SIGNAL ({crib_matches}/24) ***")
                    print(f"  {desc}")
                    print(f"  PT: {pt_text}")

    print(f"  Phase 5 complete: {p5_count} tests, "
          f"best={best_score}/24, above_noise={above_noise}")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 6: KA-Space (Quagmire III) variants
    # K1/K2 use Quagmire III with the KA alphabet (KRYPTOSABCDEFGHIJLMNQUVWXZ).
    # In KA-space: K=0, R=1, Y=2, P=3, T=4, O=5, S=6, A=7, B=8, ...
    # Critically: KRYPTOS = [0,1,2,3,4,5,6] in KA (the identity!)
    #   vs [10,17,24,15,19,14,18] in standard A-Z.
    # Every combined key produces fundamentally different results.
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 6: KA-Space (Quagmire III) Key-Split Combinations")
    print("=" * 70)

    p6_count = 0

    # Encode CT in KA-space
    CT_KA = KA.encode(CT)

    # Encode all alphabetic sources in KA-space
    ALPHA_KA = {}
    for name in ALPHA_SOURCES:
        ALPHA_KA[name] = KA.encode(name)

    def test_candidate_ka(key_ka: list[int], variant: CipherVariant,
                          desc: str, category: str):
        """Test a candidate in KA-space: decrypt CT_KA with key_ka, decode via KA."""
        nonlocal best_score, total_tests, above_noise
        total_tests += 1

        dec_fn = DECRYPT_FN[variant]
        pt_ka = [dec_fn(CT_KA[i], key_ka[i]) for i in range(CT_LEN)]
        pt_text = KA.decode(pt_ka)
        pt_nums = [ALPH_IDX[c] for c in pt_text]

        crib_matches = check_cribs(pt_nums)

        if crib_matches > best_score:
            best_score = crib_matches

        if crib_matches > 6:
            above_noise += 1
            eq_pass, ineq_pass = check_bean(pt_nums, CT_NUM)
            qg = quadgram_score(pt_text)
            words = count_words(pt_text) if WORDSET else []
            results.append({
                "desc": desc, "category": category,
                "variant": VARIANT_NAMES[variant],
                "crib_matches": crib_matches,
                "bean_eq": eq_pass, "bean_ineq": ineq_pass,
                "quadgram": round(qg, 3),
                "words_found": words[:10],
                "pt_preview": pt_text[:40],
                "key_preview": KA.decode(key_ka[:20]),
            })

        if crib_matches >= 18:
            print(f"\n*** SIGNAL ({crib_matches}/24) KA-space ***")
            print(f"  Desc: {desc}")
            print(f"  Variant: {VARIANT_NAMES[variant]}")
            print(f"  PT: {pt_text}")
            print(f"  Key: {KA.decode(key_ka[:30])}")

        if crib_matches == 24:
            eq_pass, ineq_pass = check_bean(pt_nums, CT_NUM)
            print(f"\n{'='*70}")
            print(f"!!! BREAKTHROUGH — 24/24 CRIB MATCH (KA-SPACE) !!!")
            print(f"  Desc: {desc}")
            print(f"  Variant: {VARIANT_NAMES[variant]}")
            print(f"  Bean EQ: {eq_pass}, Bean INEQ: {ineq_pass}")
            print(f"  PT: {pt_text}")
            print(f"  Key: {KA.decode(key_ka)}")
            print(f"{'='*70}")

    # Phase 6a: All alphabetic pairs in KA-space
    for i, name_a in enumerate(alpha_names):
        key_a = ALPHA_KA[name_a]
        for j, name_b in enumerate(alpha_names):
            if i == j:
                continue
            key_b = ALPHA_KA[name_b]

            for comb_name, comb_fn in COMBINE_METHODS.items():
                combined = comb_fn(key_a, key_b, CT_LEN)
                desc = f"KA:{name_a}+{name_b}({comb_name})"

                for variant in VARIANTS:
                    test_candidate_ka(combined, variant, desc, "ka_pair")
                    p6_count += 1

    print(f"  Phase 6a (KA alpha pairs): {p6_count} tests")

    # Phase 6b: Alphabetic + Numeric in KA-space
    p6b_start = p6_count
    for alpha_name in ALPHA_KA:
        alpha_key = ALPHA_KA[alpha_name]
        for num_name, num_key in NUMERIC_SOURCES.items():
            combined_add = combine_add(alpha_key, num_key, CT_LEN)
            combined_sub = combine_sub(alpha_key, num_key, CT_LEN)
            combined_rsub = combine_sub(num_key, alpha_key, CT_LEN)

            for combined, cname in [(combined_add, "add"),
                                     (combined_sub, "sub"),
                                     (combined_rsub, "rsub")]:
                desc = f"KA:{alpha_name}+{num_name}({cname})"
                for variant in VARIANTS:
                    test_candidate_ka(combined, variant, desc, "ka_alpha_num")
                    p6_count += 1

    print(f"  Phase 6b (KA alpha+numeric): {p6_count - p6b_start} tests")

    # Phase 6c: Triple splits in KA-space (anchored)
    p6c_start = p6_count
    for anchor in anchor_keys:
        if anchor not in ALPHA_KA:
            continue
        key_anchor = ALPHA_KA[anchor]
        other_names = [n for n in alpha_names if n != anchor]

        for i_b, name_b in enumerate(other_names):
            key_b = ALPHA_KA[name_b]
            for name_c in other_names[i_b+1:]:
                key_c = ALPHA_KA[name_c]

                triple = [(key_anchor[k % len(key_anchor)]
                          + key_b[k % len(key_b)]
                          + key_c[k % len(key_c)]) % MOD
                         for k in range(CT_LEN)]
                desc = f"KA:{anchor}+{name_b}+{name_c}(add3)"

                for variant in VARIANTS:
                    test_candidate_ka(triple, variant, desc, "ka_triple")
                    p6_count += 1

    print(f"  Phase 6c (KA triples): {p6_count - p6c_start} tests")

    # Phase 6d: KA-space transposition + KA-space substitution
    p6d_start = p6_count
    for trans_name, trans_data in trans_keywords.items():
        untransposed = apply_perm(CT, trans_data["inv"])
        ut_ka = KA.encode(untransposed)

        for sub_name in ALPHA_KA:
            if sub_name == trans_name:
                continue
            sub_key_ka = ALPHA_KA[sub_name]
            sub_full_ka = [sub_key_ka[k % len(sub_key_ka)] for k in range(CT_LEN)]

            for variant in VARIANTS:
                dec_fn = DECRYPT_FN[variant]
                pt_ka = [dec_fn(ut_ka[k], sub_full_ka[k]) for k in range(CT_LEN)]
                pt_text = KA.decode(pt_ka)
                pt_nums = [ALPH_IDX[c] for c in pt_text]

                crib_matches = check_cribs(pt_nums)
                total_tests += 1
                p6_count += 1

                if crib_matches > best_score:
                    best_score = crib_matches
                if crib_matches > 6:
                    above_noise += 1
                    eq_pass, ineq_pass = check_bean(pt_nums, CT_NUM)
                    results.append({
                        "desc": f"KA:trans({trans_name})+sub({sub_name},{VARIANT_NAMES[variant]})",
                        "category": "ka_trans_sub",
                        "variant": VARIANT_NAMES[variant],
                        "crib_matches": crib_matches,
                        "bean_eq": eq_pass, "bean_ineq": ineq_pass,
                        "quadgram": round(quadgram_score(pt_text), 3),
                        "words_found": count_words(pt_text)[:10] if WORDSET else [],
                        "pt_preview": pt_text[:40],
                        "key_preview": f"KA:trans={trans_name},sub={sub_name}",
                    })
                if crib_matches >= 18:
                    print(f"\n*** SIGNAL ({crib_matches}/24) KA trans+sub ***")
                    print(f"  KA:trans({trans_name})+sub({sub_name},{VARIANT_NAMES[variant]})")
                    print(f"  PT: {pt_text}")

    print(f"  Phase 6d (KA trans+sub): {p6_count - p6d_start} tests")
    print(f"  Phase 6 total: {p6_count} tests, "
          f"best={best_score}/24, above_noise={above_noise}")

    # ══════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total tests:    {total_tests:,}")
    print(f"  Above noise(>6): {above_noise}")
    print(f"  Best score:      {best_score}/24")
    print(f"  Elapsed:         {elapsed:.1f}s")

    # Sort results by score descending
    results.sort(key=lambda r: (-r["crib_matches"],
                                 -r.get("quadgram", -10),
                                 not r.get("bean_eq", False)))

    print(f"\n  Top 20 results:")
    print(f"  {'Score':>5} {'Bean':>6} {'QG':>7} {'Category':<15} {'Description'}")
    print(f"  {'-'*5} {'-'*6} {'-'*7} {'-'*15} {'-'*40}")
    for r in results[:20]:
        bean = ("EQ" if r["bean_eq"] else "--") + ("+" if r.get("bean_ineq") else "-")
        words = ",".join(r.get("words_found", [])[:3])
        print(f"  {r['crib_matches']:>5} {bean:>6} {r.get('quadgram', -10):>7.2f} "
              f"{r['category']:<15} {r['desc'][:50]}")
        if words:
            print(f"        Words: {words}")
        if r["crib_matches"] >= 10:
            print(f"        PT: {r['pt_preview']}")

    # Save results
    outpath = os.path.join(os.path.dirname(__file__), "..", "results",
                           "e_split_00_installation_key_split.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-SPLIT-00",
            "description": "Installation Key Split Combiner",
            "total_tests": total_tests,
            "above_noise": above_noise,
            "best_score": best_score,
            "elapsed_s": round(elapsed, 1),
            "alpha_sources": list(ALPHA_SOURCES.keys()),
            "numeric_sources": list(NUMERIC_SOURCES.keys()),
            "top_results": results[:50],
        }, f, indent=2)

    print(f"\n  Results saved to {outpath}")

    if best_score >= 18:
        print(f"\n  *** SIGNAL DETECTED — investigate top results ***")
    elif best_score >= 10:
        print(f"\n  Above storage threshold — worth logging but likely underdetermined")
    else:
        print(f"\n  All noise (best {best_score}/24). Key-split hypothesis not confirmed")
        print(f"  with these specific installation element combinations.")

    return best_score


if __name__ == "__main__":
    score = main()
    sys.exit(0 if score < 18 else 1)
