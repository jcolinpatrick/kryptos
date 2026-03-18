#!/usr/bin/env python3
"""
Cipher:   Operation Gold / Berlin Tunnel thematic sweep
Family:   campaigns
Status:   active
Keyspace: ~50 keywords × 12 periodic configs + ~30 numeric keys × 6 + col7 SA + running keys
Last run: 2026-03-16
Best score: TBD

Tests Operation Gold (Berlin Tunnel) keywords, numeric parameters, and date-derived
keys as cipher keys. This extends prior E-OPGOLD-01/03 which only tested 1500/800
configs at best 5/24.

NEW elements not covered by prior sweeps:
  - Operation Gold specific numeric keys (tunnel length, cost, cable depth, etc.)
  - Combined structural numbers [7,11,21,6,5] etc.
  - New keywords: LUNN, PETERLUNN, ROWLETT, FRANKROWLETT, WILLIAMKINGHARVEY, etc.
  - Book titles: BETRAYALINBERLIN, THEINNOCENT, etc.
  - All the above on CT73+col7 model (not just raw CT97)
  - Date-derived keys for tunnel-specific dates

NOTE: Gronsfeld on raw CT97 is PROVEN IMPOSSIBLE (keystream values exceed 0-9 at cribs).
We test numeric keys here as GENERAL periodic Vigenere/Beaufort (not restricted to 0-9),
and also on CT73+col7 where the raw-97 elimination does NOT apply.
"""

import sys, os, json, time, math, random
import multiprocessing as mp
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
)

# ---- Constants ----
CT97 = CT
N = 97
N_NULLS = 24
N_PT = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
NON_CRIB = sorted([i for i in range(N) if i not in CRIB_POSITIONS])
NC_SET = frozenset(NON_CRIB)

# Alphabets
AZ = ALPH
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ_IDX_MAP = {c: i for i, c in enumerate(AZ)}
KA_IDX_MAP = {c: i for i, c in enumerate(KA_STR)}

# Crib positions for fast scoring
CRIB_LIST = sorted(CRIB_DICT.items())

# User-specified consensus null mask
CONSENSUS_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])

# ---- Quadgram loading ----
QUADGRAMS = {}
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'english_quadgrams.json')
    p = os.path.normpath(p)
    if os.path.exists(p):
        with open(p) as f:
            QUADGRAMS.update(json.load(f))
        QG_FLOOR = min(QUADGRAMS.values()) - 1.0

def qg_score(text):
    if len(text) < 4:
        return -99.0
    total = 0.0
    for i in range(len(text) - 3):
        total += QUADGRAMS.get(text[i:i+4], QG_FLOOR)
    return total / len(text)

# ---- Cipher operations ----
def vig_dec(ct, key_nums, alpha_str, idx_map):
    """Vigenere: P = (C - K) mod 26"""
    klen = len(key_nums)
    out = []
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = key_nums[i % klen]
        out.append(alpha_str[(ci - ki) % 26])
    return ''.join(out)

def beau_dec(ct, key_nums, alpha_str, idx_map):
    """Beaufort: P = (K - C) mod 26"""
    klen = len(key_nums)
    out = []
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = key_nums[i % klen]
        out.append(alpha_str[(ki - ci) % 26])
    return ''.join(out)

def vbeau_dec(ct, key_nums, alpha_str, idx_map):
    """Variant Beaufort: P = (C + K) mod 26"""
    klen = len(key_nums)
    out = []
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = key_nums[i % klen]
        out.append(alpha_str[(ci + ki) % 26])
    return ''.join(out)

def autokey_pt_vig(ct, primer_nums, alpha_str, idx_map):
    out = []; L = len(primer_nums)
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = primer_nums[i] if i < L else idx_map[out[i - L]]
        out.append(alpha_str[(ci - ki) % 26])
    return ''.join(out)

def autokey_ct_vig(ct, primer_nums, alpha_str, idx_map):
    out = []; L = len(primer_nums)
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = primer_nums[i] if i < L else idx_map[ct[i - L]]
        out.append(alpha_str[(ci - ki) % 26])
    return ''.join(out)

def autokey_pt_beau(ct, primer_nums, alpha_str, idx_map):
    out = []; L = len(primer_nums)
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = primer_nums[i] if i < L else idx_map[out[i - L]]
        out.append(alpha_str[(ki - ci) % 26])
    return ''.join(out)

def autokey_ct_beau(ct, primer_nums, alpha_str, idx_map):
    out = []; L = len(primer_nums)
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = primer_nums[i] if i < L else idx_map[ct[i - L]]
        out.append(alpha_str[(ki - ci) % 26])
    return ''.join(out)

# ---- Scoring ----
def count_crib_hits_97(text):
    hits = 0
    for pos, ch in CRIB_LIST:
        if pos < len(text) and text[pos] == ch:
            hits += 1
    return hits

def count_crib_hits_73(pt, null_set):
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s + j < len(pt) and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s + j < len(pt) and pt[bcl_s + j] == c)
    return e + b, e, b

# ---- Col7 permutation ----
def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))

# ---- Autokey fast for CT73+col7 ----
def autokey_decrypt_az_fast(ct_list, kw_nums, beau=False):
    pt = []; L = len(kw_nums)
    for i, ci in enumerate(ct_list):
        ki = kw_nums[i] if i < L else (ord(pt[i - L]) - 65)
        pt.append(chr(((ki - ci) if beau else (ci - ki)) % 26 + 65))
    return ''.join(pt)

def periodic_decrypt_73(ct_list, key_nums, beau=False):
    """Periodic decrypt on numeric CT list."""
    klen = len(key_nums)
    out = []
    for i, ci in enumerate(ct_list):
        ki = key_nums[i % klen]
        if beau:
            out.append(chr((ki - ci) % 26 + 65))
        else:
            out.append(chr((ci - ki) % 26 + 65))
    return ''.join(out)

def eval_mask_col7_autokey(null_set, kw_nums, beau=True):
    """CT73+col7+autokey"""
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    ct73_t = [ct73_az[PERM_COL7[i]] for i in range(N_PT)]
    pt = autokey_decrypt_az_fast(ct73_t, kw_nums, beau)
    total, e, b = count_crib_hits_73(pt, null_set)
    return total, e, b, pt

def eval_mask_col7_periodic(null_set, key_nums, beau=True):
    """CT73+col7+periodic"""
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    ct73_t = [ct73_az[PERM_COL7[i]] for i in range(N_PT)]
    pt = periodic_decrypt_73(ct73_t, key_nums, beau)
    total, e, b = count_crib_hits_73(pt, null_set)
    return total, e, b, pt

def eval_mask_nocol7_periodic(null_set, key_nums, beau=True):
    """CT73 (no col7)+periodic"""
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    pt = periodic_decrypt_73(ct73_az, key_nums, beau)
    total, e, b = count_crib_hits_73(pt, null_set)
    return total, e, b, pt

def eval_mask_nocol7_autokey(null_set, kw_nums, beau=True):
    """CT73 (no col7)+autokey"""
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    pt = autokey_decrypt_az_fast(ct73_az, kw_nums, beau)
    total, e, b = count_crib_hits_73(pt, null_set)
    return total, e, b, pt

# ========================================================================
# KEYWORD LISTS
# ========================================================================

# Operation Gold keywords (user-specified + new ones)
OPGOLD_KEYWORDS = [
    # Main op names
    "GOLD", "OPERATIONGOLD", "STOPWATCH", "OPERATIONSTOPWATCH",
    # People involved
    "HARVEY", "WILLIAMHARVEY", "WILLIAMKINGHARVEY", "BILLHARVEY",
    "BLAKE", "GEORGEBLAKE",
    "LUNN", "PETERLUNN",
    "ROWLETT", "FRANKROWLETT",
    "STAFFD", "WILLIAMSON",
    # Locations
    "ALTGLIENICKE", "RUDOW", "NEUKOLLN", "TREPTOW",
    "SCHONEFELDER", "ZOSSEN",
    # Book/film titles
    "BETRAYALINBERLIN", "INNOCENT", "THEINNOCENT",
    # Tunnel-related terms
    "BERLINTUNNEL", "TUNNEL", "WIRETAP", "CABLE",
    "INTERCEPTOR", "SIGINT", "COMINT",
    # Combined forms
    "GOLDTUNNEL", "STOPWATCHGOLD", "HARVEYLUNN",
    "BLAKEBETRAY", "TUNNELOPERATION",
]

# Filter alpha only, dedup
OPGOLD_KEYWORDS = list(dict.fromkeys(kw for kw in OPGOLD_KEYWORDS if kw.isalpha()))

# ---- Numeric keys from Operation Gold ----
NUMERIC_KEYS = {
    # Direct Op Gold numbers
    "cost_65": [6, 5],  # $6.5M cycling
    "date_4211956": [4, 2, 1, 1, 9, 5, 6],  # April 21, 1956 digits
    "tunnel_450m": [4, 5, 0],  # 450 metres
    "tunnel_1476ft": [1, 4, 7, 6],  # 1476 feet
    "comms_90000": [9, 0, 0, 0, 0],  # 90,000 communications
    "hours_67000": [6, 7, 0, 0, 0],  # 67,000 hours
    "linguists_317": [3, 1, 7],  # 317 linguists
    "cost_6500000": [6, 5, 0, 0, 0, 0, 0],  # $6.5M full
    "depth_7m": [7],  # 7m basement depth (single digit = period 1)
    "cable_47cm": [4, 7],  # 47cm cable depth
    "months_11": [1, 1],  # 11 months
    "months_days_1111": [1, 1, 1, 1],  # 11 months 11 days
    "cables_3": [3],  # 3 cables tapped
    # Date-derived keys
    "disc_date_apr21": [4, 21],  # April 21 = [4,21]
    "disc_date_apr21_mod26": [4, 21],  # Same but mod 26 applied in cipher
    "dig_sep2_1954": [9, 2, 1, 9, 5, 4],  # Digging began
    "shaft_feb25_1955": [2, 25, 1, 9, 5, 5],  # Shaft completed
    # Combined structural numbers (mod 26)
    "struct_7_11_47_6_5_mod26": [7, 11, 21, 6, 5],  # [7,11,47,6,5] mod 26
    "struct_7_11_21_47_mod26": [7, 11, 21, 21],  # [7,11,21,47] mod 26
    "struct_21_7_11_47_mod26": [21, 7, 11, 21],  # [21,7,11,47] mod 26
    "struct_7_11_21_6_5": [7, 11, 21, 6, 5],  # raw structural
    "struct_21_11_7_47_mod26": [21, 11, 7, 21],  # reversed
    "struct_6_5_cycling": [6, 5],  # K2 "6.5 seconds" cycling
    "struct_13_11_cycling": [13, 11],  # crib lengths cycling
    "struct_73_24": [73 % 26, 24],  # = [21, 24]
    "struct_24_13_11": [24, 13, 11],  # triple-24 components
    # More mod-arithmetic derived
    "1476_mod_97_eq_21": [1, 4, 7, 6],  # tunnel length, 1476%97=21
    "650_mod_26": [650 % 26],  # = [0] ... trivial
    "struct_47_21_7_11": [21, 21, 7, 11],  # 47%26=21, then structural
    "struct_7_13_11_24": [7, 13, 11, 24],  # depth, crib lens, nulls
    "struct_21_13_11_7": [21, 13, 11, 7],  # ENE start, crib lens, depth
    "struct_21_47_7_11_mod26": [21, 21, 7, 11],  # positions mod 26
    # Key digits from K2 coordinate encoding
    "k2_38_57_65": [3, 8, 5, 7, 6, 5],  # K2 degrees, minutes, seconds
    "k2_385765": [3, 8, 5, 7, 6, 5],  # same sequential
    "k2_38577844": [3, 8, 5, 7, 7, 8, 4, 4],  # full lat/long digits
}

# ---- Running key texts ----
RUNNING_KEYS = {
    "betrayal_title": "BETRAYALINBERLINTHETRUE"
                      "STORYOFTHECOLDWARSMOSTAUDACIOUSESPIONAGEOPERATION",
    "innocent_title": "THEINNOCENTANOVEL",
    "betrayal_full":  "BETRAYALINBERLIN",
    "gold_desc":      "OPERATIONGOLDWASAJOINTOPERATIONBETWEENTHE"
                      "CENTRALINTELLIGENCEAGENCYANDTHESECRETINTELLIGENCESERVICE",
    "tunnel_desc":    "BERLINTUNNELASUBTERRANEANPASSAGEINTERCEPTINGSOVIET"
                      "COMMUNICATIONSINEASTBERLIN",
    "blake_desc":     "GEORGEBLAKEWASADOUBLEAGENTWHOBETRAYEDTHETUNNELPROJECT",
}

# ========================================================================
# PHASE 1: All keywords periodic + autokey on raw CT97
# ========================================================================

def phase1_periodic_raw97():
    """Test all Op Gold keywords with periodic + autokey on raw CT97."""
    results = []
    for kw in OPGOLD_KEYWORDS:
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
            try:
                key_nums = [idx_map[c] for c in kw]
            except KeyError:
                continue

            # Periodic: Vig, Beau, VBeau
            for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec), ("vbeau", vbeau_dec)]:
                pt = decrypt_fn(CT97, key_nums, alpha_str, idx_map)
                anchored = count_crib_hits_97(pt)
                qg = qg_score(pt) if QUADGRAMS else -99.0
                results.append({
                    'phase': 'periodic_raw97',
                    'keyword': kw,
                    'cipher': cipher_name,
                    'alphabet': alpha_name,
                    'key_type': 'alpha',
                    'crib_hits': anchored,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })

            # Autokey: PT-vig, CT-vig, PT-beau, CT-beau
            for ak_name, ak_fn in [("ak_pt_vig", autokey_pt_vig), ("ak_ct_vig", autokey_ct_vig),
                                    ("ak_pt_beau", autokey_pt_beau), ("ak_ct_beau", autokey_ct_beau)]:
                try:
                    key_nums = [idx_map[c] for c in kw]
                except KeyError:
                    continue
                pt = ak_fn(CT97, key_nums, alpha_str, idx_map)
                anchored = count_crib_hits_97(pt)
                qg = qg_score(pt) if QUADGRAMS else -99.0
                results.append({
                    'phase': 'autokey_raw97',
                    'keyword': kw,
                    'cipher': ak_name,
                    'alphabet': alpha_name,
                    'key_type': 'alpha',
                    'crib_hits': anchored,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })
    return results

# ========================================================================
# PHASE 2: All numeric keys on raw CT97 (periodic only)
# ========================================================================

def phase2_numeric_raw97():
    """Test numeric keys as periodic Vig/Beau/VBeau on raw CT97 with AZ and KA."""
    results = []
    for key_name, key_digits in NUMERIC_KEYS.items():
        if len(key_digits) == 0:
            continue
        # Apply mod 26 to any values > 25
        key_mod = [d % 26 for d in key_digits]

        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
            for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec), ("vbeau", vbeau_dec)]:
                pt = decrypt_fn(CT97, key_mod, alpha_str, idx_map)
                anchored = count_crib_hits_97(pt)
                qg = qg_score(pt) if QUADGRAMS else -99.0
                results.append({
                    'phase': 'numeric_raw97',
                    'keyword': key_name,
                    'cipher': cipher_name,
                    'alphabet': alpha_name,
                    'key_type': 'numeric',
                    'key_digits': key_mod,
                    'crib_hits': anchored,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })
    return results

# ========================================================================
# PHASE 3: CT73 + col7 with consensus mask (periodic + autokey)
# ========================================================================

def phase3_ct73_col7():
    """Test all keywords and numeric keys on CT73+col7 with consensus null mask."""
    results = []

    # Alpha keywords
    for kw in OPGOLD_KEYWORDS:
        kw_nums_az = [ord(c) - 65 for c in kw]

        # Autokey Beaufort (DEFECTOR model)
        for beau in [True, False]:
            cipher = "beau" if beau else "vig"
            total, e, b, pt = eval_mask_col7_autokey(CONSENSUS_MASK, kw_nums_az, beau)
            results.append({
                'phase': 'ct73_col7_autokey',
                'keyword': kw,
                'cipher': cipher,
                'alphabet': 'AZ',
                'key_type': 'alpha',
                'crib_hits': total,
                'ene': e,
                'bcl': b,
                'qg': round(qg_score(pt), 4) if QUADGRAMS else -99.0,
                'pt': pt[:80],
            })

        # Periodic on CT73+col7
        for beau in [True, False]:
            cipher = "beau" if beau else "vig"
            total, e, b, pt = eval_mask_col7_periodic(CONSENSUS_MASK, kw_nums_az, beau)
            results.append({
                'phase': 'ct73_col7_periodic',
                'keyword': kw,
                'cipher': cipher,
                'alphabet': 'AZ',
                'key_type': 'alpha',
                'crib_hits': total,
                'ene': e,
                'bcl': b,
                'qg': round(qg_score(pt), 4) if QUADGRAMS else -99.0,
                'pt': pt[:80],
            })

        # Also try without col7 (just null mask removal + periodic/autokey)
        for beau in [True, False]:
            cipher = "beau" if beau else "vig"
            total, e, b, pt = eval_mask_nocol7_periodic(CONSENSUS_MASK, kw_nums_az, beau)
            results.append({
                'phase': 'ct73_nocol7_periodic',
                'keyword': kw,
                'cipher': cipher,
                'alphabet': 'AZ',
                'key_type': 'alpha',
                'crib_hits': total,
                'ene': e,
                'bcl': b,
                'qg': round(qg_score(pt), 4) if QUADGRAMS else -99.0,
                'pt': pt[:80],
            })

    # Numeric keys on CT73+col7
    for key_name, key_digits in NUMERIC_KEYS.items():
        if len(key_digits) == 0:
            continue
        key_mod = [d % 26 for d in key_digits]

        for beau in [True, False]:
            cipher = "beau" if beau else "vig"
            # With col7
            total, e, b, pt = eval_mask_col7_periodic(CONSENSUS_MASK, key_mod, beau)
            results.append({
                'phase': 'ct73_col7_numeric',
                'keyword': key_name,
                'cipher': cipher,
                'alphabet': 'AZ',
                'key_type': 'numeric',
                'key_digits': key_mod,
                'crib_hits': total,
                'ene': e,
                'bcl': b,
                'qg': round(qg_score(pt), 4) if QUADGRAMS else -99.0,
                'pt': pt[:80],
            })
            # Without col7
            total, e, b, pt = eval_mask_nocol7_periodic(CONSENSUS_MASK, key_mod, beau)
            results.append({
                'phase': 'ct73_nocol7_numeric',
                'keyword': key_name,
                'cipher': cipher,
                'alphabet': 'AZ',
                'key_type': 'numeric',
                'key_digits': key_mod,
                'crib_hits': total,
                'ene': e,
                'bcl': b,
                'qg': round(qg_score(pt), 4) if QUADGRAMS else -99.0,
                'pt': pt[:80],
            })

    return results

# ========================================================================
# PHASE 4: Running keys
# ========================================================================

def phase4_running_keys():
    """Test long phrases as running keys on raw CT97."""
    results = []
    for rk_name, rk_text in RUNNING_KEYS.items():
        rk_clean = ''.join(c for c in rk_text.upper() if c.isalpha())
        if len(rk_clean) < 20:
            continue

        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
            try:
                rk_nums = [idx_map[c] for c in rk_clean]
            except KeyError:
                continue

            # Test at all valid offsets within the running key
            max_off = max(0, len(rk_nums) - N) + 1
            for off in range(max_off):
                key_segment = rk_nums[off:off + N]
                if len(key_segment) < N:
                    # Pad by repeating
                    key_segment = key_segment * ((N // len(key_segment)) + 2)
                    key_segment = key_segment[:N]

                for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec)]:
                    pt = decrypt_fn(CT97, key_segment, alpha_str, idx_map)
                    anchored = count_crib_hits_97(pt)
                    qg = qg_score(pt) if QUADGRAMS else -99.0
                    results.append({
                        'phase': 'running_key',
                        'keyword': f"{rk_name}[off={off}]",
                        'cipher': cipher_name,
                        'alphabet': alpha_name,
                        'key_type': 'running',
                        'crib_hits': anchored,
                        'qg': round(qg, 4),
                        'pt': pt[:80],
                    })

    return results

# ========================================================================
# PHASE 5: Col7 + null-mask SA for top Op Gold keywords
# ========================================================================

def sa_col7_worker(args):
    """SA for one keyword with col7 null-mask model (autokey Beaufort)."""
    keyword, seed, beau = args
    rng = random.Random(seed)

    kw_nums = [ord(c) - 65 for c in keyword]
    pool = list(NON_CRIB)
    extra = set(rng.sample(pool, N_NULLS))
    null_set = extra
    non_null = NC_SET - null_set

    total, _, _, _ = eval_mask_col7_autokey(frozenset(null_set), kw_nums, beau)
    score = float(total)
    best_sc = score
    best_null = frozenset(null_set)

    steps = 80_000
    T0, Tf = 0.5, 0.01
    for step in range(steps):
        T = T0 * (Tf / T0) ** (step / steps)
        cands = list(null_set)
        nn_list = list(non_null)
        if not cands or not nn_list:
            break
        out = rng.choice(cands)
        into = rng.choice(nn_list)
        null_set = (null_set - {out}) | {into}
        non_null = (non_null - {into}) | {out}
        total, _, _, _ = eval_mask_col7_autokey(frozenset(null_set), kw_nums, beau)
        new_sc = float(total)
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / max(T, 0.001)):
            score = new_sc
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)
        else:
            null_set = (null_set - {into}) | {out}
            non_null = (non_null - {out}) | {into}

    total, e, b, pt = eval_mask_col7_autokey(best_null, kw_nums, beau)
    return {
        'phase': 'col7_null_sa',
        'keyword': keyword,
        'cipher': 'beau' if beau else 'vig',
        'alphabet': 'AZ',
        'key_type': 'alpha_sa',
        'crib_hits': total,
        'ene': e,
        'bcl': b,
        'pt': pt[:80],
        'mask': sorted(best_null),
        'seed': seed,
    }

# ========================================================================
# PHASE 6: Mod arithmetic analysis (informational)
# ========================================================================

def phase6_mod_analysis():
    """Compute and report the user's mod-arithmetic observations."""
    results = []

    # 1476 mod 97
    v = 1476 % 97
    results.append(f"1476 mod 97 = {v} (ENE starts at position 21: {'MATCH' if v == 21 else 'NO MATCH'})")

    # 6500000 mod 97
    v = 6500000 % 97
    results.append(f"6500000 mod 97 = {v} (position {v} is inside ENE crib 21-33: {21 <= v <= 33})")

    # 450 factorization
    results.append(f"450 = {450} = 2 * 225 = 2 * 15^2. 450/97 = {450/97:.4f}")

    # Other mod checks
    for val, desc in [(1476, "tunnel_ft"), (450, "tunnel_m"), (6500000, "cost"),
                       (90000, "comms"), (67000, "hours"), (317, "linguists")]:
        m97 = val % 97
        m26 = val % 26
        m73 = val % 73
        m24 = val % 24
        results.append(f"{desc}={val}: mod97={m97} mod26={m26} mod73={m73} mod24={m24}")

    return results


# ========================================================================
# MAIN
# ========================================================================

def main():
    t0 = time.time()
    load_quadgrams()
    n_workers = min(os.cpu_count() or 4, 4)

    print("=" * 78)
    print("E-OPGOLD-BERLIN-TUNNEL-V2: Operation Gold / Berlin Tunnel Sweep")
    print("=" * 78)
    print(f"Op Gold keywords: {len(OPGOLD_KEYWORDS)}")
    print(f"Numeric key sets: {len(NUMERIC_KEYS)}")
    print(f"Running key phrases: {len(RUNNING_KEYS)}")
    print(f"Quadgrams loaded: {len(QUADGRAMS)}")
    print(f"Workers: {n_workers}")
    print()
    sys.stdout.flush()

    all_results = []
    best_global = 0

    # ---- Phase 1: Periodic + autokey on raw CT97 ----
    print("=" * 78)
    print(f"PHASE 1: Periodic + Autokey on raw CT97 ({len(OPGOLD_KEYWORDS)} keywords)")
    print("=" * 78)
    sys.stdout.flush()

    p1 = phase1_periodic_raw97()
    all_results.extend(p1)
    p1_best = max((r['crib_hits'] for r in p1), default=0)
    p1_above = [r for r in p1 if r['crib_hits'] >= 8]
    for r in p1_above:
        print(f"  [>=8] {r['keyword']:25s} | {r['cipher']:12s}/{r['alphabet']} | "
              f"crib={r['crib_hits']:2d} qg={r['qg']:7.3f}")
    print(f"\n  Phase 1: {len(p1)} configs, best {p1_best}/24, {len(p1_above)} >= 8")
    if p1_best > best_global:
        best_global = p1_best
    sys.stdout.flush()

    # ---- Phase 2: Numeric keys on raw CT97 ----
    print()
    print("=" * 78)
    print(f"PHASE 2: Numeric keys on raw CT97 ({len(NUMERIC_KEYS)} key sets)")
    print("=" * 78)
    sys.stdout.flush()

    p2 = phase2_numeric_raw97()
    all_results.extend(p2)
    p2_best = max((r['crib_hits'] for r in p2), default=0)
    p2_above = [r for r in p2 if r['crib_hits'] >= 8]
    for r in p2_above:
        print(f"  [>=8] {r['keyword']:30s} | {r['cipher']:5s}/{r['alphabet']} | "
              f"crib={r['crib_hits']:2d} key={r['key_digits']}")
    print(f"\n  Phase 2: {len(p2)} configs, best {p2_best}/24, {len(p2_above)} >= 8")
    if p2_best > best_global:
        best_global = p2_best
    sys.stdout.flush()

    # ---- Phase 3: CT73 + col7 with consensus mask ----
    print()
    print("=" * 78)
    print(f"PHASE 3: CT73 + consensus mask (keywords + numeric keys)")
    print("=" * 78)
    sys.stdout.flush()

    p3 = phase3_ct73_col7()
    all_results.extend(p3)
    p3_best = max((r['crib_hits'] for r in p3), default=0)
    p3_above = [r for r in p3 if r['crib_hits'] >= 8]
    for r in p3_above:
        print(f"  [>=8] {r['phase']:25s} | {r['keyword']:25s} | {r['cipher']:5s} | "
              f"crib={r['crib_hits']:2d} (e={r.get('ene','?')},b={r.get('bcl','?')})")
    print(f"\n  Phase 3: {len(p3)} configs, best {p3_best}/24, {len(p3_above)} >= 8")
    if p3_best > best_global:
        best_global = p3_best
    sys.stdout.flush()

    # ---- Phase 4: Running keys ----
    print()
    print("=" * 78)
    print(f"PHASE 4: Running keys ({len(RUNNING_KEYS)} phrases)")
    print("=" * 78)
    sys.stdout.flush()

    p4 = phase4_running_keys()
    all_results.extend(p4)
    p4_best = max((r['crib_hits'] for r in p4), default=0)
    p4_above = [r for r in p4 if r['crib_hits'] >= 8]
    for r in p4_above:
        print(f"  [>=8] {r['keyword']:40s} | {r['cipher']:5s}/{r['alphabet']} | "
              f"crib={r['crib_hits']:2d} qg={r['qg']:7.3f}")
    print(f"\n  Phase 4: {len(p4)} configs, best {p4_best}/24, {len(p4_above)} >= 8")
    if p4_best > best_global:
        best_global = p4_best
    sys.stdout.flush()

    # ---- Phase 5: SA for top Op Gold keywords ----
    print()
    print("=" * 78)
    print("PHASE 5: Col7 + Null-mask SA for Op Gold keywords")
    print("=" * 78)
    sys.stdout.flush()

    sa_tasks = []
    for kw in OPGOLD_KEYWORDS[:25]:  # top 25 keywords
        for seed_base in range(5):  # 5 restarts each
            seed = hash(("opgold_v2", kw, seed_base)) & 0xFFFFFFFF
            sa_tasks.append((kw, seed, True))   # Beaufort
            sa_tasks.append((kw, seed, False))  # Vigenere

    print(f"  {len(sa_tasks)} SA tasks ({min(25, len(OPGOLD_KEYWORDS))} keywords x 5 seeds x 2 ciphers)")
    sys.stdout.flush()

    sa_results = []
    done = 0
    with mp.Pool(n_workers) as pool:
        for r in pool.imap_unordered(sa_col7_worker, sa_tasks, chunksize=2):
            done += 1
            if r['crib_hits'] >= 8:
                sa_results.append(r)
                print(f"  [SA >=8] {r['keyword']:25s} | {r['cipher']} | "
                      f"crib={r['crib_hits']:2d} (ene={r['ene']}, bcl={r['bcl']})")
                sys.stdout.flush()
            if done % 50 == 0:
                elapsed = time.time() - t0
                print(f"  SA progress: {done}/{len(sa_tasks)} ({elapsed:.0f}s)")
                sys.stdout.flush()

    all_results.extend(sa_results)
    if sa_results:
        p5_best = max(r['crib_hits'] for r in sa_results)
    else:
        p5_best = 0
    print(f"\n  Phase 5: {len(sa_tasks)} SA runs, {len(sa_results)} hits >= 8, best {p5_best}/24")
    if p5_best > best_global:
        best_global = p5_best
    sys.stdout.flush()

    # ---- Phase 6: Mod analysis ----
    print()
    print("=" * 78)
    print("PHASE 6: Modular arithmetic analysis")
    print("=" * 78)
    mod_results = phase6_mod_analysis()
    for line in mod_results:
        print(f"  {line}")
    sys.stdout.flush()

    # ---- Final Summary ----
    elapsed = time.time() - t0
    print()
    print("=" * 78)
    print("FINAL SUMMARY")
    print("=" * 78)

    all_results.sort(key=lambda r: (-r['crib_hits'], -r.get('qg', -99)))

    total_configs = len(p1) + len(p2) + len(p3) + len(p4) + len(sa_tasks)
    print(f"Total configurations tested: {total_configs}")
    print(f"Results collected: {len(all_results)}")
    print(f"Best crib score: {best_global}/24")
    print(f"Elapsed: {elapsed:.1f}s")
    print()

    # Report anything >= 8
    hits_8plus = [r for r in all_results if r['crib_hits'] >= 8]
    if hits_8plus:
        print(f"ALL RESULTS >= 8/24 ({len(hits_8plus)} total):")
        print()
        for i, r in enumerate(hits_8plus[:80]):
            extra = ""
            if 'ene' in r:
                extra = f" (e={r['ene']},b={r['bcl']})"
            if 'key_digits' in r:
                extra += f" key={r['key_digits']}"
            print(f"  {i+1:3d}. crib={r['crib_hits']:2d} | {r['phase']:25s} | "
                  f"{r['keyword']:30s} | {r['cipher']:12s}/{r.get('alphabet','AZ')} | "
                  f"qg={r.get('qg',-99):7.3f}{extra}")
    else:
        print("NO results >= 8/24 crib hits")

    # Top 30 overall
    print()
    print("TOP 30 OVERALL:")
    for i, r in enumerate(all_results[:30]):
        extra = ""
        if 'ene' in r:
            extra = f" (e={r['ene']},b={r['bcl']})"
        if 'key_digits' in r:
            extra += f" key={r['key_digits']}"
        print(f"  {i+1:3d}. crib={r['crib_hits']:2d} | {r['phase']:25s} | "
              f"{r['keyword']:30s} | {r['cipher']:12s}/{r.get('alphabet','AZ')} | "
              f"qg={r.get('qg',-99):7.3f}{extra}")
        if i < 10:
            print(f"       PT: {r['pt'][:70]}")

    # Signal check
    print()
    if any(r['crib_hits'] >= 18 for r in all_results):
        print("*** SIGNAL DETECTED (>=18/24) --- INVESTIGATE IMMEDIATELY ***")
    elif any(r['crib_hits'] >= 10 for r in all_results):
        print("** INTERESTING (>=10/24) --- Worth further analysis **")
    else:
        print(f"VERDICT: NOISE --- best crib score {best_global}/24")

    # ---- Save results ----
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'e_opgold_berlin_tunnel_v2.json')

    # Strip masks for size
    save_results = []
    for r in all_results[:200]:
        sr = {k: v for k, v in r.items() if k != 'mask'}
        save_results.append(sr)

    output = {
        'experiment': 'e_opgold_berlin_tunnel_v2',
        'description': 'Operation Gold / Berlin Tunnel comprehensive keyword + numeric key sweep',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'n_keywords': len(OPGOLD_KEYWORDS),
        'n_numeric_keys': len(NUMERIC_KEYS),
        'n_running_keys': len(RUNNING_KEYS),
        'n_sa_tasks': len(sa_tasks),
        'elapsed_seconds': round(elapsed, 1),
        'best_crib_score': best_global,
        'verdict': 'SIGNAL' if best_global >= 18 else ('INTERESTING' if best_global >= 10 else 'NOISE'),
        'mod_analysis': mod_results,
        'top_results': save_results,
        'keywords_tested': OPGOLD_KEYWORDS,
        'numeric_keys_tested': {k: v for k, v in NUMERIC_KEYS.items()},
    }

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")
    sys.stdout.flush()


if __name__ == '__main__':
    main()
