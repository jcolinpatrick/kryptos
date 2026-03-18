#!/usr/bin/env python3
"""
Cipher:   Narrative / spy / Cold War keyword sweep
Family:   campaigns
Status:   active
Keyspace: ~100 keywords × 12 periodic variants + col7 null-mask SA + keyword pairs + Gronsfeld dates
Last run: 2026-03-16
Best score: TBD

Comprehensive test of spy/Cold War/Berlin narrative keywords as cipher keys.
Tests:
  1. Periodic decryption on raw CT97 (Vig/Beau/VBeau × AZ/KA) — anchored + free crib
  2. Col7 + null-mask SA (DEFECTOR:AZ_beau model) for top keywords
  3. Keyword pairs as running keys
  4. Date-derived Gronsfeld keys
  5. Autokey (PT + CT) for all keywords
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
AZ_TO_KA = [KA_IDX_MAP[c] for c in AZ]

# Crib positions for fast scoring on raw 97
CRIB_LIST = sorted(CRIB_DICT.items())

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
    """PT-autokey Vigenere"""
    out = []; L = len(primer_nums)
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = primer_nums[i] if i < L else idx_map[out[i - L]]
        out.append(alpha_str[(ci - ki) % 26])
    return ''.join(out)

def autokey_ct_vig(ct, primer_nums, alpha_str, idx_map):
    """CT-autokey Vigenere"""
    out = []; L = len(primer_nums)
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = primer_nums[i] if i < L else idx_map[ct[i - L]]
        out.append(alpha_str[(ci - ki) % 26])
    return ''.join(out)

def autokey_pt_beau(ct, primer_nums, alpha_str, idx_map):
    """PT-autokey Beaufort"""
    out = []; L = len(primer_nums)
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = primer_nums[i] if i < L else idx_map[out[i - L]]
        out.append(alpha_str[(ki - ci) % 26])
    return ''.join(out)

def autokey_ct_beau(ct, primer_nums, alpha_str, idx_map):
    """CT-autokey Beaufort"""
    out = []; L = len(primer_nums)
    for i, c in enumerate(ct):
        ci = idx_map[c]
        ki = primer_nums[i] if i < L else idx_map[ct[i - L]]
        out.append(alpha_str[(ki - ci) % 26])
    return ''.join(out)

# ---- Scoring ----
def count_crib_hits_97(text):
    """Anchored crib scoring on raw 97-char output."""
    hits = 0
    for pos, ch in CRIB_LIST:
        if pos < len(text) and text[pos] == ch:
            hits += 1
    return hits

def count_crib_hits_free(text):
    """Free crib: search for ENE and BCL as substrings anywhere."""
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

def count_crib_hits_73(pt, null_set):
    """Crib scoring on 73-char output (adjusted for null removal)."""
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

# ---- Keyword list ----
KEYWORDS_NARRATIVE = [
    # People
    "WEBSTER", "WILLIAMWEBSTER", "SANBORN", "SCHEIDT", "EDSCHEIDT",
    "GILLOGLY", "STEIN", "DAVIDSTEIN", "CARTER", "HOWARDCARTER",
    "CARNARVON", "SHAW", "EDSHAW",
    # Spy terms
    "DEFECTOR", "EXFILTRATE", "EXFILTRATION", "MOLE", "DOUBLEAGENT",
    "DEADFALL", "DEADDROP", "SAFEHOUSE", "HANDLER", "ASSET", "OPERATIVE",
    "SLEEPER", "TURNCOAT", "TRADECRAFT", "CLANDESTINE", "COVERT",
    "CLASSIFIED", "TOPSECRET", "EYESONLY", "ONLYWW", "LASTMESSAGE",
    "HISLASTMESSAGE",
    # Berlin/Cold War
    "BERLINWALL", "CHECKPOINT", "CHARLIE", "CHECKPOINTCHARLIE",
    "ALEXANDERPLATZ", "WELTZEITUHR", "BRANDENBURGGATE", "EASTBERLIN",
    "WESTBERLIN", "FRIEDRICHSTRASSE", "STASI", "NOVEMBER",
    "NOVEMBER1989", "FALLOFTHEWALL", "REUNIFICATION", "COLDWAR",
    "IRONCURTAIN",
    # Kryptos-specific
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "KOMPASS", "COLOPHON",
    "PARALLAX", "SHADOW", "MEDUSA", "ENIGMA", "LODESTONE", "COMPASS",
    "IQLUSION", "DESPARATLY", "LAYERTWO", "IDBYROWS", "XLAYERTWO",
    "DIGATAL", "UNDERGRUUND", "LUCIDMEMORY",
    # Operational
    "LANGLEY", "VIRGINIA", "CENTRALINTELLIGENCE", "AGENCY",
    "HEADQUARTERS", "NEWHEADQUARTERS", "CRYPTOGRAPHY", "ENCIPHERMENT",
    "MASKING", "STEGANOGRAPHY", "INVISIBLE", "MAGNETIC",
    # Dates as words
    "NINETEENEIGHTYNINE", "NINETEENNINETY", "NOVEMBERNINTH",
    "NINTHNOVEMBER",
    # Egyptian
    "TUTANKHAMUN", "PHARAOH", "VALLEYOFKINGS", "WONDERFULTHINGS",
    "YESINDEED", "CANYOUSEEANYTHING",
    # Combined narrative phrases
    "ONLYWWKNOWS", "BURIEDOUTTHERE", "THEEXACTLOCATION",
    "TOTALLYINVISIBLE", "SUBTLESHADING", "ABSENCEOFLIGHT",
    "NUANCEOFILQUSION",
]

# Remove any with non-alpha chars or duplicates
KEYWORDS_NARRATIVE = list(dict.fromkeys(
    kw for kw in KEYWORDS_NARRATIVE if kw.isalpha()
))

# ---- Running key pairs (top 20 narrative keywords) ----
TOP20 = [
    "DEFECTOR", "BERLINWALL", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
    "CHECKPOINT", "COLDWAR", "WEBSTER", "SCHEIDT", "EXFILTRATE",
    "ALEXANDERPLATZ", "STASI", "SAFEHOUSE", "HANDLER", "TRADECRAFT",
    "ENIGMA", "LANGLEY", "TURNCOAT", "IRONCURTAIN", "WELTZEITUHR",
]

KEYWORD_PAIRS = []
for i, k1 in enumerate(TOP20):
    for j, k2 in enumerate(TOP20):
        if i != j:
            combined = k1 + k2
            KEYWORD_PAIRS.append(combined)
# Keep only first 100 to limit runtime
KEYWORD_PAIRS = KEYWORD_PAIRS[:100]

# ---- Date Gronsfeld keys ----
GRONSFELD_KEYS = {
    "19891109": [1, 9, 8, 9, 1, 1, 0, 9],   # Nov 9, 1989 (Wall fell)
    "11091989": [1, 1, 0, 9, 1, 9, 8, 9],   # US date format
    "19901103": [1, 9, 9, 0, 1, 1, 0, 3],   # Nov 3, 1990 (dedication)
    "11031990": [1, 1, 0, 3, 1, 9, 9, 0],   # US date format
    "19901119": [1, 9, 9, 0, 1, 1, 1, 9],   # Nov 19, 1990 (close date)
    "19890101": [1, 9, 8, 9, 0, 1, 0, 1],   # Jan 1, 1989
    "38576577844": [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],  # K2 coords concatenated
}

# ========================================================================
# PHASE 1: Periodic decryption on raw CT97 for all narrative keywords
# ========================================================================

def phase1_worker(args):
    """Test one keyword across 6 cipher variants (3 ciphers × 2 alphabets).
    Returns list of results with crib_hits >= threshold."""
    keyword = args
    results = []

    for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
        # Encode keyword
        try:
            key_nums = [idx_map[c] for c in keyword]
        except KeyError:
            continue  # skip if keyword has chars not in alphabet

        for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec), ("vbeau", vbeau_dec)]:
            pt = decrypt_fn(CT97, key_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            free = count_crib_hits_free(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0

            if anchored >= 8 or free >= 10 or qg > -5.0:
                results.append({
                    'phase': 'periodic',
                    'keyword': keyword,
                    'cipher': cipher_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
                    'free_score': free,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })

        # Also test autokey (PT and CT) for Vig and Beau
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

            if anchored >= 8 or free >= 10 or qg > -5.0:
                results.append({
                    'phase': 'autokey',
                    'keyword': keyword,
                    'cipher': ak_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
                    'free_score': free,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })

    return results

# ========================================================================
# PHASE 2: Col7 + null-mask SA for top narrative keywords
# ========================================================================

def autokey_decrypt_az_fast(ct_list, kw_nums, beau=False):
    pt = []; L = len(kw_nums)
    for i, ci in enumerate(ct_list):
        ki = kw_nums[i] if i < L else (ord(pt[i - L]) - 65)
        pt.append(chr(((ki - ci) if beau else (ci - ki)) % 26 + 65))
    return ''.join(pt)

def eval_mask_col7(null_set, kw_nums, beau=True):
    """Evaluate a null mask with col7 transposition and AZ Beaufort autokey."""
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    ct73_t = [ct73_az[PERM_COL7[i]] for i in range(N_PT)]
    pt = autokey_decrypt_az_fast(ct73_t, kw_nums, beau)
    total, e, b = count_crib_hits_73(pt, null_set)
    return total, e, b, pt

def sa_col7_worker(args):
    """SA for one keyword with col7 null-mask model."""
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
    best_pt = ""

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
        total, _, _, _ = eval_mask_col7(frozenset(null_set), kw_nums, beau)
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

    # Get best PT
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
# PHASE 3: Keyword pairs as running keys
# ========================================================================

def phase3_worker(args):
    """Test a keyword pair as running key."""
    combined = args
    results = []

    for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP)]:
        try:
            key_nums = [idx_map[c] for c in combined]
        except KeyError:
            continue

        for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = decrypt_fn(CT97, key_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            free = count_crib_hits_free(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0

            if anchored >= 8 or free >= 10 or qg > -5.0:
                results.append({
                    'phase': 'running_key_pair',
                    'keyword': combined[:40] + ('...' if len(combined) > 40 else ''),
                    'cipher': cipher_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
                    'free_score': free,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })

    return results

# ========================================================================
# PHASE 4: Gronsfeld date keys
# ========================================================================

def phase4_gronsfeld():
    """Test date-derived Gronsfeld keys."""
    results = []
    for date_name, key_digits in GRONSFELD_KEYS.items():
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
            for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec), ("vbeau", vbeau_dec)]:
                pt = decrypt_fn(CT97, key_digits, alpha_str, idx_map)
                anchored = count_crib_hits_97(pt)
                free = count_crib_hits_free(pt)
                qg = qg_score(pt) if QUADGRAMS else -99.0

                results.append({
                    'phase': 'gronsfeld',
                    'keyword': date_name,
                    'cipher': cipher_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
                    'free_score': free,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })
    return results

# ========================================================================
# PHASE 5: Model B — direct Beaufort on raw 97 (no null, no trans)
# ========================================================================

def phase5_model_b():
    """Test each keyword as direct periodic Beaufort on raw 97
    (no transposition, no null mask) — 'Model B' where cipher
    on all 97 and 24 PT chars are garbage."""
    results = []
    for kw in KEYWORDS_NARRATIVE:
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
            try:
                key_nums = [idx_map[c] for c in kw]
            except KeyError:
                continue
            pt = beau_dec(CT97, key_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            free = count_crib_hits_free(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0

            # Lower threshold for Model B since we expect some hits
            if anchored >= 6 or free >= 8 or qg > -5.5:
                results.append({
                    'phase': 'model_b_beau',
                    'keyword': kw,
                    'cipher': 'beau',
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
    print("NARRATIVE KEYWORD SWEEP — Comprehensive Spy/Cold War/Berlin Terms")
    print("=" * 78)
    print(f"Narrative keywords: {len(KEYWORDS_NARRATIVE)}")
    print(f"Keyword pairs: {len(KEYWORD_PAIRS)}")
    print(f"Gronsfeld date keys: {len(GRONSFELD_KEYS)}")
    print(f"Quadgrams loaded: {len(QUADGRAMS)}")
    print(f"Workers: {n_workers}")
    print()
    sys.stdout.flush()

    all_results = []

    # ---- Phase 1: Periodic + autokey on raw 97 ----
    print("=" * 78)
    print("PHASE 1: Periodic + Autokey on raw CT97 for ALL narrative keywords")
    print(f"  {len(KEYWORDS_NARRATIVE)} keywords × 10 cipher modes × 2 alphabets = {len(KEYWORDS_NARRATIVE) * 20} configs")
    print("=" * 78)
    sys.stdout.flush()

    with mp.Pool(n_workers) as pool:
        for batch in pool.imap_unordered(phase1_worker, KEYWORDS_NARRATIVE, chunksize=4):
            for r in batch:
                all_results.append(r)
                print(f"  [HIT] {r['phase']} | {r['keyword']:20s} | {r['cipher']:12s} | "
                      f"{r['alphabet']} | crib={r['crib_hits']:2d} free={r.get('free_score', 0):2d} "
                      f"qg={r['qg']:7.3f} | {r['pt'][:50]}")
                sys.stdout.flush()

    p1_count = len(all_results)
    print(f"\n  Phase 1 complete: {p1_count} results above threshold")
    sys.stdout.flush()

    # ---- Phase 2: Col7 null-mask SA for top 30 narrative keywords ----
    print()
    print("=" * 78)
    print("PHASE 2: Col7 + Null-mask SA (DEFECTOR-model) for top narrative keywords")
    print("=" * 78)
    sys.stdout.flush()

    # Select keywords for SA: top performers from phase 1 + all spy terms
    SA_KEYWORDS = list(dict.fromkeys(
        [r['keyword'] for r in sorted(all_results, key=lambda x: -x['crib_hits'])[:20]] +
        [
            "DEFECTOR", "EXFILTRATE", "BERLINWALL", "CHECKPOINT", "CHARLIE",
            "CHECKPOINTCHARLIE", "ALEXANDERPLATZ", "WELTZEITUHR", "STASI",
            "COLDWAR", "IRONCURTAIN", "SAFEHOUSE", "HANDLER", "TURNCOAT",
            "TRADECRAFT", "CLANDESTINE", "OPERATIVE", "SLEEPER", "DEADDROP",
            "WEBSTER", "SCHEIDT", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
            "KOMPASS", "COLOPHON", "PARALLAX", "ENIGMA", "LANGLEY",
            "SANBORN", "SHAW", "EDSHAW",
        ]
    ))

    sa_tasks = []
    for kw in SA_KEYWORDS[:40]:  # limit to 40 keywords
        for seed_base in range(5):  # 5 restarts each
            seed = hash((kw, seed_base)) & 0xFFFFFFFF
            sa_tasks.append((kw, seed, True))   # beau
            sa_tasks.append((kw, seed, False))  # vig

    print(f"  {len(sa_tasks)} SA tasks ({len(SA_KEYWORDS[:40])} keywords × 5 seeds × 2 ciphers)")
    sys.stdout.flush()

    sa_results = []
    done = 0
    with mp.Pool(n_workers) as pool:
        for r in pool.imap_unordered(sa_col7_worker, sa_tasks, chunksize=2):
            done += 1
            if r['crib_hits'] >= 10:
                sa_results.append(r)
                print(f"  [SA HIT] {r['keyword']:20s} | {r['cipher']} | "
                      f"crib={r['crib_hits']:2d} (ene={r['ene']}, bcl={r['bcl']}) | "
                      f"seed={r['seed']} | {r['pt'][:50]}")
                sys.stdout.flush()
            if done % 50 == 0:
                elapsed = time.time() - t0
                print(f"  SA progress: {done}/{len(sa_tasks)} ({elapsed:.0f}s)")
                sys.stdout.flush()

    all_results.extend(sa_results)
    print(f"\n  Phase 2 complete: {len(sa_results)} SA results >= 10/24")
    sys.stdout.flush()

    # ---- Phase 3: Keyword pairs as running keys ----
    print()
    print("=" * 78)
    print("PHASE 3: Keyword pairs as running keys")
    print(f"  {len(KEYWORD_PAIRS)} pairs × 2 ciphers × 1 alphabet = {len(KEYWORD_PAIRS) * 2} configs")
    print("=" * 78)
    sys.stdout.flush()

    p3_count = 0
    with mp.Pool(n_workers) as pool:
        for batch in pool.imap_unordered(phase3_worker, KEYWORD_PAIRS, chunksize=4):
            for r in batch:
                all_results.append(r)
                p3_count += 1
                print(f"  [PAIR HIT] {r['keyword']:40s} | {r['cipher']} | "
                      f"crib={r['crib_hits']:2d} free={r.get('free_score', 0):2d} "
                      f"qg={r['qg']:7.3f}")
                sys.stdout.flush()

    print(f"\n  Phase 3 complete: {p3_count} pair results above threshold")
    sys.stdout.flush()

    # ---- Phase 4: Gronsfeld date keys ----
    print()
    print("=" * 78)
    print("PHASE 4: Gronsfeld date keys")
    print("=" * 78)
    sys.stdout.flush()

    grons_results = phase4_gronsfeld()
    for r in grons_results:
        all_results.append(r)
        print(f"  [{r['keyword']:14s}] {r['cipher']:5s}/{r['alphabet']} | "
              f"crib={r['crib_hits']:2d} free={r.get('free_score', 0):2d} qg={r['qg']:7.3f} "
              f"| {r['pt'][:50]}")
    sys.stdout.flush()

    # ---- Phase 5: Model B ----
    print()
    print("=" * 78)
    print("PHASE 5: Model B (direct Beaufort, no trans/null, all 97)")
    print("=" * 78)
    sys.stdout.flush()

    mb_results = phase5_model_b()
    for r in mb_results:
        all_results.append(r)
        print(f"  [MODEL B] {r['keyword']:20s} | {r['alphabet']} | "
              f"crib={r['crib_hits']:2d} free={r.get('free_score', 0):2d} qg={r['qg']:7.3f}")
    sys.stdout.flush()

    # ---- Final Summary ----
    elapsed = time.time() - t0
    print()
    print("=" * 78)
    print("FINAL SUMMARY")
    print("=" * 78)

    # Sort all results by crib_hits descending, then qg descending
    all_results.sort(key=lambda r: (-r['crib_hits'], -r.get('qg', -99)))

    total_configs = len(KEYWORDS_NARRATIVE) * 20 + len(sa_tasks) + len(KEYWORD_PAIRS) * 2 + len(grons_results) + len(KEYWORDS_NARRATIVE) * 2
    print(f"Total configurations tested: ~{total_configs}")
    print(f"Total results above threshold: {len(all_results)}")
    print(f"Elapsed: {elapsed:.1f}s")
    print()

    # Best by crib hits
    if all_results:
        best_crib = all_results[0]['crib_hits']
        print(f"BEST CRIB SCORE: {best_crib}/24")
        print()
        print("TOP 40 RESULTS (by crib hits):")
        for i, r in enumerate(all_results[:40]):
            print(f"  {i+1:3d}. crib={r['crib_hits']:2d} | {r['phase']:18s} | "
                  f"{r['keyword']:25s} | {r['cipher']:12s}/{r.get('alphabet', 'AZ')} | "
                  f"qg={r.get('qg', -99):7.3f} | {r['pt'][:55]}")
    else:
        print("NO results above threshold in any phase.")

    # Best by quadgram
    qg_sorted = sorted(all_results, key=lambda r: -r.get('qg', -99))
    print()
    print("TOP 20 BY QUADGRAM:")
    for i, r in enumerate(qg_sorted[:20]):
        print(f"  {i+1:3d}. qg={r.get('qg', -99):7.3f} | crib={r['crib_hits']:2d} | "
              f"{r['phase']:18s} | {r['keyword']:25s} | {r['cipher']:12s}")

    # Signal check
    print()
    if any(r['crib_hits'] >= 18 for r in all_results):
        print("*** SIGNAL DETECTED (>=18/24) — INVESTIGATE IMMEDIATELY ***")
    elif any(r['crib_hits'] >= 10 for r in all_results):
        print("** INTERESTING (>=10/24) — Worth further analysis **")
    else:
        best = max((r['crib_hits'] for r in all_results), default=0)
        print(f"VERDICT: NOISE — best crib score {best}/24 (below 10/24 threshold)")

    # ---- Save results ----
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'f_narrative_keyword_sweep_v1.json')

    output = {
        'experiment': 'f_narrative_keyword_sweep_v1',
        'description': 'Comprehensive spy/Cold War/Berlin narrative keyword sweep',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'n_keywords': len(KEYWORDS_NARRATIVE),
        'n_pairs': len(KEYWORD_PAIRS),
        'n_gronsfeld': len(GRONSFELD_KEYS),
        'n_sa_tasks': len(sa_tasks),
        'elapsed_seconds': round(elapsed, 1),
        'best_crib_score': max((r['crib_hits'] for r in all_results), default=0),
        'best_qg': max((r.get('qg', -99) for r in all_results), default=-99),
        'top_results': all_results[:100],
        'keywords_tested': KEYWORDS_NARRATIVE,
    }

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")
    sys.stdout.flush()


if __name__ == '__main__':
    main()
