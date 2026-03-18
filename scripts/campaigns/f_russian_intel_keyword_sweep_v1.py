#!/usr/bin/env python3
"""Russian intelligence terminology keyword sweep for K4.

Cipher:   Periodic Vig/Beau/VBeau + Autokey + Col7+null-mask SA
Family:   campaigns
Status:   active
Keyspace: ~70 keywords x 12 cipher modes + col7 SA + pairs = ~5K+ configs
Last run: never
Best score: N/A

Sanborn has deep engagement with Russian themes (Cyrillic Projector used
keyword SHADOW on Russian text). The Kryptos Alphabet starts with K. The
dominant keystream value is K(10) at 5/24 occurrences.

Tests Russian intelligence K-words, spy tradecraft terms, operation names,
and Cyrillic Projector connection keywords across:
  1. Periodic Vig/Beau/VBeau on raw CT97 (AZ + KA) -- anchored + free crib
  2. Autokey (PT + CT, Vig + Beau) on raw CT97 (AZ + KA)
  3. Col7 + null-mask SA (DEFECTOR-model) for all keywords
  4. 73-char null-extracted periodic (4 variants x col7)
  5. Keyword pairs with K-word combinations
  6. Model B (direct Beaufort on all 97)

Thresholds: report >= 8/24 crib OR qg > -5.5
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

# Crib positions for fast scoring on raw 97
CRIB_LIST = sorted(CRIB_DICT.items())

# Null mask (consensus from 15/24 masks)
USER_MASK = sorted([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
MASK_SET = frozenset(USER_MASK)
KEPT = [i for i in range(97) if i not in MASK_SET]
CT73 = ''.join(CT97[i] for i in KEPT)
CT73_NUMS = [ord(c) - 65 for c in CT73]

# KA lookup tables
_KA_IDX_ARRAY = [KA_IDX_MAP[chr(i+65)] for i in range(26)]
_KA_CHAR_ARRAY = [ord(KA_STR[i]) - 65 for i in range(26)]

# Col7 undo on 73-char
def col7_undo(text):
    n = len(text)
    ncols = 7
    nrows_full = n // ncols
    extra = n % ncols
    col_lens = [nrows_full + (1 if c < extra else 0) for c in range(ncols)]
    idx = 0; cols = []
    for c in range(ncols):
        cols.append(text[idx:idx+col_lens[c]])
        idx += col_lens[c]
    out = []
    for r in range(nrows_full + (1 if extra > 0 else 0)):
        for c in range(ncols):
            if r < col_lens[c]:
                out.append(cols[c][r])
    return ''.join(out)

CT73_COL7 = col7_undo(CT73)
CT73_COL7_NUMS = [ord(c) - 65 for c in CT73_COL7]

# Shifted crib positions (Model A)
def compute_shifted_pos(pos97):
    return pos97 - sum(1 for m in USER_MASK if m < pos97)

ENE_S = compute_shifted_pos(21)
BCL_S = compute_shifted_pos(63)
ENE_TARGETS = [(ENE_S + j, ord(c) - 65) for j, c in enumerate(ENE_WORD)]
BCL_TARGETS = [(BCL_S + j, ord(c) - 65) for j, c in enumerate(BCL_WORD)]


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

def ic(text):
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


# ---- Cipher operations ----
def vig_dec(ct, key_nums, alpha_str, idx_map):
    klen = len(key_nums)
    out = []
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = key_nums[i % klen]
        out.append(alpha_str[(ci - ki) % 26])
    return ''.join(out)

def beau_dec(ct, key_nums, alpha_str, idx_map):
    klen = len(key_nums)
    out = []
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = key_nums[i % klen]
        out.append(alpha_str[(ki - ci) % 26])
    return ''.join(out)

def vbeau_dec(ct, key_nums, alpha_str, idx_map):
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

def count_crib_hits_free(text):
    score = 0
    if ENE_WORD in text:
        score += 13
    else:
        for flen in range(len(ENE_WORD) - 1, 4, -1):
            for start in range(len(ENE_WORD) - flen + 1):
                if ENE_WORD[start:start+flen] in text:
                    score += flen
                    break
            if score > 0:
                break
    if BCL_WORD in text:
        score += 11
    else:
        for flen in range(len(BCL_WORD) - 1, 4, -1):
            for start in range(len(BCL_WORD) - flen + 1):
                if BCL_WORD[start:start+flen] in text:
                    score += flen
                    break
            if score > 0:
                break
    return score

def count_crib_hits_73(pt, ene_s, bcl_s):
    """Crib scoring on 73-char output with pre-computed shifted positions."""
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


# ---- Score periodic on 73-char ----
def score_periodic_73(ct_nums, key_nums, variant):
    """Decrypt 73-char text with periodic key and score against shifted cribs."""
    klen = len(key_nums)
    n = len(ct_nums)

    if variant == 0:  # AZ vig
        pt = [(ct_nums[i] - key_nums[i % klen]) % 26 for i in range(n)]
    elif variant == 1:  # AZ beau
        pt = [(key_nums[i % klen] - ct_nums[i]) % 26 for i in range(n)]
    elif variant == 2:  # KA vig
        pt = [_KA_CHAR_ARRAY[(_KA_IDX_ARRAY[ct_nums[i]] - _KA_IDX_ARRAY[key_nums[i%klen]]) % 26] for i in range(n)]
    else:  # KA beau
        pt = [_KA_CHAR_ARRAY[(_KA_IDX_ARRAY[key_nums[i%klen]] - _KA_IDX_ARRAY[ct_nums[i]]) % 26] for i in range(n)]

    e = sum(1 for pos, target in ENE_TARGETS if 0 <= pos < n and pt[pos] == target)
    b = sum(1 for pos, target in BCL_TARGETS if 0 <= pos < n and pt[pos] == target)
    return e + b, e, b, ''.join(chr(x+65) for x in pt)


# ========================================================================
# KEYWORD LISTS
# ========================================================================

KEYWORDS_RUSSIAN = [
    # Russian Intelligence K-words
    "KONSPIRATSIYA", "KOMBINATSIYA", "KOMPROMAT", "KREMLIN", "KROT",
    "KURYER", "KANAL", "KOLOKOL", "KONTROL", "KOMMUNIST", "KAMERA",
    "KAPITAN", "KOMISSAR", "KOMSOMOL", "KVARTIRA", "KODEKS", "KULAK",
    "KARATEL", "KONFIDENTSIALNY",
    # Russian Intelligence Terms (non-K)
    "SPETSNAZ", "REZIDENT", "REZIDENTURA", "APPARATCHIK", "NOMENKLATURA",
    "GLASNOST", "PERESTROIKA", "TOVARISHCH", "POLITBURO", "GULAG",
    "SMERSH", "CHEKA", "OKHRANA", "LUBYANKA", "ZASLON", "ILLEGALS",
    "AKTIVKA",
    # Operation Names with Russian Connection
    "VENONA", "ENORMOZ", "BOREAS", "DUBOK", "RYAN", "AQUARIUM",
    "DIRECTORATE",
    # Sanborn's Cyrillic Projector Connection
    "SHADOW", "CYRILLIC", "PROJECTOR", "CYRILLICPROJECTOR",
    "TENI", "SVET", "SVETITENI",
    # Combined K-word pairs
    "KRYPTOSKREMLIN", "KRYPTOSKROT", "KGBKRYPTOS", "KOMPROMATKRYPTOS",
    "KONSPIRATSIYAKRYPTOS", "KRYPTOSKOMPROMAT", "KREMLINKRYPTOS",
    "KROTKRYPTOS",
    # Double-K words
    "KGBKRYPTOS", "KREMLINKRYPTOS", "KOMBINATSIYAKRYPTOS",
]

# Deduplicate and filter to alpha only
KEYWORDS_RUSSIAN = list(dict.fromkeys(
    kw for kw in KEYWORDS_RUSSIAN if kw.isalpha() and kw.isascii()
))


# ========================================================================
# PHASE 1 WORKER (module-level for pickling)
# ========================================================================

def phase1_all_worker(keyword):
    """Test one keyword across all periodic + autokey modes. Returns (hits, all_scores)."""
    results_hit = []
    results_all = []

    for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
        try:
            key_nums = [idx_map[c] for c in keyword]
        except KeyError:
            continue

        for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec), ("vbeau", vbeau_dec)]:
            pt = decrypt_fn(CT97, key_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            free = count_crib_hits_free(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0

            results_all.append({'keyword': keyword, 'cipher': cipher_name, 'alphabet': alpha_name,
                               'crib_hits': anchored, 'qg': round(qg, 4)})

            if anchored >= 8 or free >= 10 or qg > -5.5:
                results_hit.append({
                    'phase': 'periodic_97',
                    'keyword': keyword,
                    'cipher': cipher_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
                    'free_score': free,
                    'qg': round(qg, 4),
                    'ic': round(ic(pt), 5),
                    'pt': pt[:80],
                })

        for ak_name, ak_fn in [("ak_pt_vig", autokey_pt_vig), ("ak_ct_vig", autokey_ct_vig),
                                ("ak_pt_beau", autokey_pt_beau), ("ak_ct_beau", autokey_ct_beau)]:
            try:
                key_nums = [idx_map[c] for c in keyword]
            except KeyError:
                continue
            pt = ak_fn(CT97, key_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            free = count_crib_hits_free(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0

            results_all.append({'keyword': keyword, 'cipher': ak_name, 'alphabet': alpha_name,
                               'crib_hits': anchored, 'qg': round(qg, 4)})

            if anchored >= 8 or free >= 10 or qg > -5.5:
                results_hit.append({
                    'phase': 'autokey_97',
                    'keyword': keyword,
                    'cipher': ak_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
                    'free_score': free,
                    'qg': round(qg, 4),
                    'ic': round(ic(pt), 5),
                    'pt': pt[:80],
                })

    return results_hit, results_all


# ========================================================================
# PHASE 2: Col7 + null-mask SA
# ========================================================================

def autokey_decrypt_az_fast(ct_list, kw_nums, beau=False):
    pt = []; L = len(kw_nums)
    for i, ci in enumerate(ct_list):
        ki = kw_nums[i] if i < L else (ord(pt[i - L]) - 65)
        pt.append(chr(((ki - ci) if beau else (ci - ki)) % 26 + 65))
    return ''.join(pt)

def eval_mask_col7(null_set, kw_nums, beau=True):
    kept = [i for i in range(N) if i not in null_set]
    ct73_raw = ''.join(CT97[i] for i in kept)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    perm = reverse_perm(columnar_perm(len(ct73_az), 7))
    ct73_t = [ct73_az[perm[i]] for i in range(len(ct73_az))]
    pt = autokey_decrypt_az_fast(ct73_t, kw_nums, beau)
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    total, e, b = count_crib_hits_73(pt, ene_s, bcl_s)
    return total, e, b, pt

def sa_col7_worker(args):
    keyword, seed, beau = args
    rng = random.Random(seed)

    kw_nums = [ord(c) - 65 for c in keyword]
    pool = list(NON_CRIB)
    extra = set(rng.sample(pool, N_NULLS))
    null_set = extra
    non_null = NC_SET - null_set

    total, _, _, _ = eval_mask_col7(frozenset(null_set), kw_nums, beau)
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
        out_pos = rng.choice(cands)
        into_pos = rng.choice(nn_list)
        null_set = (null_set - {out_pos}) | {into_pos}
        non_null = (non_null - {into_pos}) | {out_pos}
        total, _, _, _ = eval_mask_col7(frozenset(null_set), kw_nums, beau)
        new_sc = float(total)
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / max(T, 0.001)):
            score = new_sc
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)
        else:
            null_set = (null_set - {into_pos}) | {out_pos}
            non_null = (non_null - {out_pos}) | {into_pos}

    total, e, b, pt = eval_mask_col7(best_null, kw_nums, beau)
    return {
        'phase': 'col7_null_sa',
        'keyword': keyword,
        'cipher': 'beau' if beau else 'vig',
        'alphabet': 'AZ',
        'crib_hits': total,
        'ene': e,
        'bcl': b,
        'pt': pt[:80],
        'mask': sorted(best_null),
        'seed': seed,
    }


# ========================================================================
# PHASE 3: Periodic on 73-char null-extracted (4 variants x col7)
# ========================================================================

def phase3_worker(keyword):
    """Periodic sub on 73-char text (with and without col7), 4 variants."""
    results = []
    try:
        key_nums = [ord(c) - 65 for c in keyword]
    except Exception:
        return results

    for use_col7 in (False, True):
        ct_nums = CT73_COL7_NUMS if use_col7 else CT73_NUMS
        for variant in range(4):
            total, e, b, pt_str = score_periodic_73(ct_nums, key_nums, variant)
            variant_name = ['AZ_vig', 'AZ_beau', 'KA_vig', 'KA_beau'][variant]
            qg = qg_score(pt_str) if QUADGRAMS else -99.0

            if total >= 8 or qg > -5.5:
                results.append({
                    'phase': 'periodic_73',
                    'keyword': keyword,
                    'cipher': variant_name,
                    'col7': use_col7,
                    'crib_hits': total,
                    'ene': e,
                    'bcl': b,
                    'qg': round(qg, 4),
                    'period': len(keyword),
                    'pt': pt_str[:80],
                })

    return results


# ========================================================================
# PHASE 4: Combined keyword pairs
# ========================================================================

KEYWORD_PAIRS = [
    "KRYPTOSKREMLIN", "KRYPTOSKROT", "KGBKRYPTOS", "KOMPROMATKRYPTOS",
    "KONSPIRATSIYAKRYPTOS", "KRYPTOSKOMPROMAT", "KREMLINKRYPTOS",
    "KROTKRYPTOS", "KGBKRYPTOS", "KREMLINKRYPTOS", "KOMBINATSIYAKRYPTOS",
    # Cross with known survivors
    "DEFECTORKREMLIN", "KREMLINDELDEFECTOR", "KRYPTOSVENONA",
    "VENONAKRYPTOS", "SHADOWKRYPTOS", "KRYPTOSSHADOW",
    "DEFECTORKOMPROMAT", "KOMPROMATSHADOW",
    "KONSPIRATSIYAPALIMPSEST", "PALIMPSESTKREMLIN",
    "DEFECTORSPETSNAZ", "SPETSNAZDEFECTOR",
    "ABSCISSAKREMLIN", "KOMPASSVENONA",
    "KOLOPHONKREMLIN", "PARALLAXVENONA",
    "DEFECTORREZIDENT", "REZIDENTKRYPTOS",
    "SMERSHSHADOW", "SHADOWSMERSH",
    "CHECKAKRYPTOS", "KRYPTOSLUBYANKA",
]
KEYWORD_PAIRS = list(dict.fromkeys(kw for kw in KEYWORD_PAIRS if kw.isalpha()))

def phase4_worker(combined):
    results = []
    for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
        try:
            key_nums = [idx_map[c] for c in combined]
        except KeyError:
            continue
        for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = decrypt_fn(CT97, key_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            free = count_crib_hits_free(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0
            if anchored >= 8 or free >= 10 or qg > -5.5:
                results.append({
                    'phase': 'keyword_pair',
                    'keyword': combined[:50],
                    'cipher': cipher_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
                    'free_score': free,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })
    return results


# ========================================================================
# PHASE 5: Model B (direct periodic on all 97, no null, no trans)
# ========================================================================

def phase5_model_b():
    results = []
    for kw in KEYWORDS_RUSSIAN:
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
            try:
                key_nums = [idx_map[c] for c in kw]
            except KeyError:
                continue
            for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec), ("vbeau", vbeau_dec)]:
                pt = decrypt_fn(CT97, key_nums, alpha_str, idx_map)
                anchored = count_crib_hits_97(pt)
                free = count_crib_hits_free(pt)
                qg = qg_score(pt) if QUADGRAMS else -99.0
                if anchored >= 8 or free >= 10 or qg > -5.5:
                    results.append({
                        'phase': 'model_b',
                        'keyword': kw,
                        'cipher': cipher_name,
                        'alphabet': alpha_name,
                        'crib_hits': anchored,
                        'free_score': free,
                        'qg': round(qg, 4),
                        'pt': pt[:80],
                    })
    return results


# ========================================================================
# MAIN
# ========================================================================

def main():
    t0 = time.time()
    load_quadgrams()
    n_workers = min(os.cpu_count() or 4, 4)  # limit to 4 as per rules

    print("=" * 78)
    print("RUSSIAN INTELLIGENCE KEYWORD SWEEP -- K4 Decipherment")
    print("=" * 78)
    print(f"Russian keywords: {len(KEYWORDS_RUSSIAN)}")
    print(f"Keyword pairs: {len(KEYWORD_PAIRS)}")
    print(f"Quadgrams loaded: {len(QUADGRAMS)}")
    print(f"Workers: {n_workers}")
    print(f"CT73 = {CT73}")
    print(f"CT73_COL7 = {CT73_COL7}")
    print(f"ENE_S={ENE_S}, BCL_S={BCL_S}")
    print()
    print("Keywords:")
    for kw in KEYWORDS_RUSSIAN:
        print(f"  {kw} (len={len(kw)})")
    print()
    sys.stdout.flush()

    all_results = []

    # ---- Phase 1: Periodic + autokey on raw CT97 ----
    print("=" * 78)
    print("PHASE 1: Periodic Vig/Beau/VBeau + Autokey on raw CT97")
    print(f"  {len(KEYWORDS_RUSSIAN)} keywords x 14 modes (6 periodic + 8 autokey) x 2 alphabets")
    print("=" * 78)
    sys.stdout.flush()

    all_phase1_scores = []

    with mp.Pool(n_workers) as pool:
        for hits, all_scores in pool.imap_unordered(phase1_all_worker, KEYWORDS_RUSSIAN, chunksize=4):
            all_phase1_scores.extend(all_scores)
            for r in hits:
                all_results.append(r)
                print(f"  [HIT] {r['phase']} | {r['keyword']:20s} | {r['cipher']:12s} | "
                      f"{r.get('alphabet', 'AZ')} | crib={r['crib_hits']:2d} free={r.get('free_score', 0):2d} "
                      f"qg={r['qg']:7.3f} | {r['pt'][:50]}")
                sys.stdout.flush()

    p1_crib_dist = Counter(s['crib_hits'] for s in all_phase1_scores)
    p1_best = max(s['crib_hits'] for s in all_phase1_scores) if all_phase1_scores else 0
    print(f"\n  Phase 1 complete: {len(all_phase1_scores)} total configs, "
          f"{len([r for r in all_results if r['phase'] in ('periodic_97', 'autokey_97')])} above threshold")
    print(f"  Crib distribution: {dict(sorted(p1_crib_dist.items(), reverse=True))}")
    print(f"  Best crib score (Phase 1): {p1_best}/24")
    sys.stdout.flush()

    # ---- Phase 2: Col7 + null-mask SA ----
    print()
    print("=" * 78)
    print("PHASE 2: Col7 + Null-mask SA (DEFECTOR-model) for ALL Russian keywords")
    print("=" * 78)
    sys.stdout.flush()

    sa_tasks = []
    for kw in KEYWORDS_RUSSIAN:
        for seed_base in range(5):
            seed = hash((kw, seed_base)) & 0xFFFFFFFF
            sa_tasks.append((kw, seed, True))   # beau
            sa_tasks.append((kw, seed, False))  # vig

    print(f"  {len(sa_tasks)} SA tasks ({len(KEYWORDS_RUSSIAN)} keywords x 5 seeds x 2 ciphers)")
    sys.stdout.flush()

    sa_results = []
    sa_all_scores = []
    done = 0
    with mp.Pool(n_workers) as pool:
        for r in pool.imap_unordered(sa_col7_worker, sa_tasks, chunksize=2):
            done += 1
            sa_all_scores.append(r['crib_hits'])
            if r['crib_hits'] >= 8:
                sa_results.append(r)
                all_results.append(r)
                print(f"  [SA] {r['keyword']:20s} | {r['cipher']} | "
                      f"crib={r['crib_hits']:2d} (ene={r['ene']}, bcl={r['bcl']}) | "
                      f"seed={r['seed']} | {r['pt'][:50]}")
                sys.stdout.flush()
            if done % 40 == 0:
                elapsed = time.time() - t0
                print(f"  SA progress: {done}/{len(sa_tasks)} ({elapsed:.0f}s)")
                sys.stdout.flush()

    sa_crib_dist = Counter(sa_all_scores)
    sa_best = max(sa_all_scores) if sa_all_scores else 0
    print(f"\n  Phase 2 complete: {len(sa_results)} SA results >= 8/24")
    print(f"  SA crib distribution: {dict(sorted(sa_crib_dist.items(), reverse=True))}")
    print(f"  Best SA score: {sa_best}/24")
    sys.stdout.flush()

    # ---- Phase 3: Periodic on 73-char ----
    print()
    print("=" * 78)
    print("PHASE 3: Periodic sub on 73-char null-extracted text (4 variants x col7)")
    print(f"  {len(KEYWORDS_RUSSIAN)} keywords x 4 variants x 2 (col7/direct) = {len(KEYWORDS_RUSSIAN)*8} configs")
    print("=" * 78)
    sys.stdout.flush()

    p3_all_scores = []
    with mp.Pool(n_workers) as pool:
        for hits in pool.imap_unordered(phase3_worker, KEYWORDS_RUSSIAN, chunksize=4):
            for r in hits:
                p3_all_scores.append(r['crib_hits'])
                all_results.append(r)
                print(f"  [73] {r['keyword']:20s} | {r['cipher']:8s} | col7={r['col7']} | "
                      f"crib={r['crib_hits']:2d} (ene={r.get('ene',0)}, bcl={r.get('bcl',0)}) "
                      f"qg={r['qg']:7.3f} | {r['pt'][:50]}")
                sys.stdout.flush()

    p3_best = max(p3_all_scores) if p3_all_scores else 0
    print(f"\n  Phase 3 complete: {len(p3_all_scores)} results >= 8/24, best = {p3_best}/24")
    sys.stdout.flush()

    # ---- Phase 4: Keyword pairs ----
    print()
    print("=" * 78)
    print("PHASE 4: Combined keyword pairs as running keys on raw CT97")
    print(f"  {len(KEYWORD_PAIRS)} pairs x 4 (Vig/Beau x AZ/KA)")
    print("=" * 78)
    sys.stdout.flush()

    p4_count = 0
    with mp.Pool(n_workers) as pool:
        for hits in pool.imap_unordered(phase4_worker, KEYWORD_PAIRS, chunksize=4):
            for r in hits:
                all_results.append(r)
                p4_count += 1
                print(f"  [PAIR] {r['keyword']:40s} | {r['cipher']}/{r['alphabet']} | "
                      f"crib={r['crib_hits']:2d} free={r.get('free_score', 0):2d}")
                sys.stdout.flush()

    print(f"\n  Phase 4 complete: {p4_count} pair results above threshold")
    sys.stdout.flush()

    # ---- Phase 5: Model B ----
    print()
    print("=" * 78)
    print("PHASE 5: Model B (direct periodic on all 97, no null/trans)")
    print(f"  {len(KEYWORDS_RUSSIAN)} keywords x 3 ciphers x 2 alphabets = {len(KEYWORDS_RUSSIAN)*6} configs")
    print("=" * 78)
    sys.stdout.flush()

    mb_results = phase5_model_b()
    for r in mb_results:
        all_results.append(r)
        print(f"  [MB] {r['keyword']:20s} | {r['cipher']}/{r['alphabet']} | "
              f"crib={r['crib_hits']:2d} free={r.get('free_score',0):2d} qg={r['qg']:7.3f}")
    sys.stdout.flush()

    # ========================================================================
    # FINAL SUMMARY
    # ========================================================================
    elapsed = time.time() - t0
    print()
    print("=" * 78)
    print("FINAL SUMMARY -- RUSSIAN INTELLIGENCE KEYWORD SWEEP")
    print("=" * 78)

    total_configs = (len(all_phase1_scores)
                     + len(sa_tasks)
                     + len(KEYWORDS_RUSSIAN) * 8
                     + len(KEYWORD_PAIRS) * 4
                     + len(KEYWORDS_RUSSIAN) * 6)

    print(f"Total configurations tested: ~{total_configs}")
    print(f"Total results above threshold: {len(all_results)}")
    print(f"Elapsed: {elapsed:.1f}s")
    print()

    # Sort all results
    all_results.sort(key=lambda r: (-r['crib_hits'], -r.get('qg', -99)))

    best_crib = max((r['crib_hits'] for r in all_results), default=0)
    print(f"BEST CRIB SCORE: {best_crib}/24")
    print()

    if all_results:
        print("TOP 50 RESULTS (by crib hits):")
        for i, r in enumerate(all_results[:50]):
            print(f"  {i+1:3d}. crib={r['crib_hits']:2d} | {r['phase']:15s} | "
                  f"{r['keyword']:25s} | {r.get('cipher','?'):12s}/{r.get('alphabet','AZ')} | "
                  f"qg={r.get('qg', -99):7.3f} | {r.get('pt', '')[:55]}")
    else:
        print("NO results above threshold in any phase.")

    # Best by quadgram
    qg_sorted = sorted(all_results, key=lambda r: -r.get('qg', -99))
    print()
    print("TOP 20 BY QUADGRAM:")
    for i, r in enumerate(qg_sorted[:20]):
        print(f"  {i+1:3d}. qg={r.get('qg', -99):7.3f} | crib={r['crib_hits']:2d} | "
              f"{r['phase']:15s} | {r['keyword']:25s}")

    # Signal check
    print()
    if any(r['crib_hits'] >= 18 for r in all_results):
        print("*** SIGNAL DETECTED (>=18/24) -- INVESTIGATE IMMEDIATELY ***")
    elif any(r['crib_hits'] >= 10 for r in all_results):
        print("** INTERESTING (>=10/24) -- Worth further analysis **")
    else:
        print(f"VERDICT: NOISE -- best crib score {best_crib}/24 (below 10/24 threshold)")
        print("Russian intelligence keywords produce no crib-consistent decryptions.")

    # ---- Save results ----
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'f_russian_intel_keyword_sweep_v1.json')

    output = {
        'experiment': 'f_russian_intel_keyword_sweep_v1',
        'description': 'Russian intelligence terminology keyword sweep for K4',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'n_keywords': len(KEYWORDS_RUSSIAN),
        'n_pairs': len(KEYWORD_PAIRS),
        'elapsed_seconds': round(elapsed, 1),
        'best_crib_score': best_crib,
        'best_qg': max((r.get('qg', -99) for r in all_results), default=-99),
        'phases': {
            'phase1_periodic_autokey_97': {
                'configs': len(all_phase1_scores),
                'best': p1_best,
                'distribution': dict(sorted(p1_crib_dist.items(), reverse=True)),
            },
            'phase2_col7_null_sa': {
                'tasks': len(sa_tasks),
                'best': sa_best,
                'distribution': dict(sorted(sa_crib_dist.items(), reverse=True)),
            },
            'phase3_periodic_73': {
                'configs': len(KEYWORDS_RUSSIAN) * 8,
                'hits_ge8': len(p3_all_scores),
                'best': p3_best,
            },
            'phase4_pairs': {
                'configs': len(KEYWORD_PAIRS) * 4,
                'hits': p4_count,
            },
            'phase5_model_b': {
                'configs': len(KEYWORDS_RUSSIAN) * 6,
                'hits': len(mb_results),
            },
        },
        'top_results': all_results[:100],
        'keywords_tested': KEYWORDS_RUSSIAN,
        'keyword_pairs_tested': KEYWORD_PAIRS,
    }

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")
    sys.stdout.flush()


if __name__ == '__main__':
    main()
