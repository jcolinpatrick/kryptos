#!/usr/bin/env python3
"""
Cipher:   Cold War operation/spy keyword sweep
Family:   campaigns
Status:   active
Keyspace: ~120 keywords x 6 periodic configs + col7 null-mask SA + running keys + autokey
Last run: 2026-03-16
Best score: TBD

Tests declassified CIA Cold War operation names and spy terminology as cipher keys.
Focus areas: Berlin Tunnel (Operation Gold), Penkovsky, Bridge of Spies,
Soviet intel terms, other CIA ops, George Blake, Berlin-specific, CIA Directors,
generic spy craft. Special focus on KOMPROMAT.

Test configurations:
  1. Periodic on raw CT97: Beau/Vig x AZ/KA (4 configs per keyword)
  2. Col7 + null-mask SA (DEFECTOR:AZ_beau model) for all keywords
  3. Running key for keywords > 20 chars: Beaufort at all offsets
  4. KOMPROMAT special: autokey, concatenated keys
  5. Autokey (PT/CT) for all keywords
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

# ---- The Cold War keyword list (user specified) ----
KEYWORDS_RAW = [
    # Operation Gold / Berlin Tunnel
    "GOLD", "STOPWATCH", "BERLINTUNNEL", "TUNNEL", "OPERATIONGOLD",
    "OPERATIONSTOPWATCH", "HARVEY", "WILLIAMHARVEY", "BILLHARVEY",
    "ALTGLIENICKE", "RUDOW", "SCHONEFELDERCHAUSSEE",
    # Penkovsky (Soviet defector who spied for CIA)
    "PENKOVSKY", "OLEGPENKOVSKY", "IRONBARK", "OPERATIONIRONBARK",
    "CHICKADEE", "HERO", "WYNNE", "GREVILLEWYNNE",
    # Bridge of Spies / Spy Exchanges
    "GLIENICKE", "BRIDGEOFSPIES", "RUDOLABEL", "ABELHAUSEN",
    "GARYOPOWERS", "EXCHANGE",
    # Soviet/Russian Intelligence Terms
    "KOMPROMAT", "KOMPROMITTIROVAT", "DISINFORMATION",
    "DEZINFORMATSIYA", "MASKIROVKA", "AKTIVNYEMEROPRIYATIYA",
    "SPETSNAZ", "REZIDENT", "REZIDENTURA", "ILLEGALS",
    # Other CIA Cold War Ops
    "CORONA", "DISCOVERER", "MONGOOSE", "ZAPATA", "PBSUCCESS",
    "AJAX", "TPAJAX", "MKULTRA", "ARTICHOKE", "BLUEBIRD",
    "MOCKINGBIRD", "PAPERCLIP", "GLADIO", "CHAOS", "HTLINGUAL",
    "VENONA",
    # George Blake (mole who betrayed the tunnel)
    "BLAKE", "GEORGEBLAKE", "MOLE", "BETRAYAL", "DOUBLEAGENT",
    "TREACHERY",
    # Berlin-specific
    "CHECKPOINT", "CHARLIE", "CHECKPOINTCHARLIE",
    "FRIEDRICHSTRASSE", "BORNHOLMERSTRASSE", "ALEXANDERPLATZ",
    "WELTZEITUHR", "BERLINERMAUER", "TODESSTREIFEN",
    "GRENZGAENGER", "MAUERFALL", "WENDE",
    # CIA Directors (Webster era)
    "WEBSTER", "WILLIAMWEBSTER", "CASEY", "WILLIAMCASEY",
    "TURNER", "STANSFIELDTURNER", "COLBY", "WILLIAMCOLBY",
    "DULLES", "ALLENDULLES",
    # Generic spy craft
    "TRADECRAFT", "CLANDESTINE", "COVERT", "EXFILTRATE",
    "INFILTRATE", "DEBRIEF", "HANDLER", "CUTOUT", "SAFEHOUSE",
    "DEADLETTER", "DEADDROP", "BRUSH", "SIGNALSITE",
    "ACCOMMODATION", "LEGEND", "BACKSTOP", "BURNED", "BLOWN",
    "TERMINATED",
]

# Filter: alpha only, dedup
KEYWORDS = list(dict.fromkeys(kw for kw in KEYWORDS_RAW if kw.isalpha()))

# Special KOMPROMAT combinations
KOMPROMAT_SPECIALS = [
    "KOMPROMATDEFECTOR", "DEFECTORKOMPROMAT",
    "KOMPROMATKRYPTOS", "KRYPTOSKOMPROMAT",
    "KOMPROMATBERLIN", "BERLINKOMPROMAT",
    "KOMPROMATGOLD", "GOLDKOMPROMAT",
    "KOMPROMATCHECKPOINT", "CHECKPOINTKOMPROMAT",
]

# ========================================================================
# PHASE 1: Periodic decryption on raw CT97 (Beau/Vig x AZ/KA)
# ========================================================================

def phase1_periodic_worker(keyword):
    """Test one keyword across 4 periodic configs + 4 autokey configs x 2 alphabets."""
    results = []

    for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
        try:
            key_nums = [idx_map[c] for c in keyword]
        except KeyError:
            continue

        for cipher_name, decrypt_fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = decrypt_fn(CT97, key_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0

            results.append({
                'phase': 'periodic',
                'keyword': keyword,
                'cipher': cipher_name,
                'alphabet': alpha_name,
                'crib_hits': anchored,
                'qg': round(qg, 4),
                'pt': pt[:80],
            })

        # Autokey (PT and CT) for Vig and Beau
        for ak_name, ak_fn in [
            ("ak_pt_vig", autokey_pt_vig), ("ak_ct_vig", autokey_ct_vig),
            ("ak_pt_beau", autokey_pt_beau), ("ak_ct_beau", autokey_ct_beau),
        ]:
            try:
                key_nums = [idx_map[c] for c in keyword]
            except KeyError:
                continue
            pt = ak_fn(CT97, key_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0

            results.append({
                'phase': 'autokey',
                'keyword': keyword,
                'cipher': ak_name,
                'alphabet': alpha_name,
                'crib_hits': anchored,
                'qg': round(qg, 4),
                'pt': pt[:80],
            })

    return results


# ========================================================================
# PHASE 2: Col7 + null-mask SA for all keywords
# ========================================================================

def autokey_decrypt_az_fast(ct_list, kw_nums, beau=False):
    pt = []; L = len(kw_nums)
    for i, ci in enumerate(ct_list):
        ki = kw_nums[i] if i < L else (ord(pt[i - L]) - 65)
        pt.append(chr(((ki - ci) if beau else (ci - ki)) % 26 + 65))
    return ''.join(pt)

def eval_mask_col7(null_set, kw_nums, beau=True):
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    ct73_t = [ct73_az[PERM_COL7[i]] for i in range(N_PT)]
    pt = autokey_decrypt_az_fast(ct73_t, kw_nums, beau)
    total, e, b = count_crib_hits_73(pt, null_set)
    return total, e, b, pt

def sa_col7_worker(args):
    keyword, seed, beau = args
    rng = random.Random(seed)

    kw_nums = [ord(c) - 65 for c in keyword]
    pool_choices = list(NON_CRIB)
    extra = set(rng.sample(pool_choices, N_NULLS))
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
# PHASE 3: Running key for keywords > 20 chars (Beaufort at all offsets)
# ========================================================================

def phase3_running_key():
    """For keywords >= len(CT97), use as running key (no cycling).
    For shorter keywords, test at all start positions within keyword."""
    results = []
    long_keywords = [kw for kw in KEYWORDS if len(kw) > 20]

    for kw in long_keywords:
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP)]:
            try:
                kw_nums = [idx_map[c] for c in kw]
            except KeyError:
                continue

            # If keyword is longer than N, test all start offsets
            if len(kw) >= N:
                offsets = range(len(kw) - N + 1)
            else:
                offsets = [0]  # for shorter, just use beginning

            for off in offsets:
                key_segment = kw_nums[off:off + N]
                if len(key_segment) < N:
                    # Pad by repeating
                    key_segment = key_segment * ((N // len(key_segment)) + 2)
                    key_segment = key_segment[:N]

                for cipher_name, decrypt_fn in [("beau", beau_dec), ("vig", vig_dec)]:
                    pt = decrypt_fn(CT97, key_segment, alpha_str, idx_map)
                    anchored = count_crib_hits_97(pt)
                    qg = qg_score(pt) if QUADGRAMS else -99.0

                    if anchored >= 6 or qg > -5.5:
                        results.append({
                            'phase': 'running_key',
                            'keyword': kw[:40],
                            'cipher': cipher_name,
                            'alphabet': alpha_name,
                            'offset': off,
                            'crib_hits': anchored,
                            'qg': round(qg, 4),
                            'pt': pt[:80],
                        })
    return results


# ========================================================================
# PHASE 4: KOMPROMAT special tests
# ========================================================================

def phase4_kompromat_special():
    """Special tests for KOMPROMAT:
    - Autokey primer on CT73+col7
    - Concatenated keys (KOMPROMAT+KRYPTOS, etc.)
    """
    results = []

    kw = "KOMPROMAT"

    # Test KOMPROMAT autokey on CT73+col7
    for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
        try:
            kw_nums = [idx_map[c] for c in kw]
        except KeyError:
            continue

        # Autokey on raw CT97
        for ak_name, ak_fn in [
            ("ak_pt_vig", autokey_pt_vig), ("ak_ct_vig", autokey_ct_vig),
            ("ak_pt_beau", autokey_pt_beau), ("ak_ct_beau", autokey_ct_beau),
        ]:
            pt = ak_fn(CT97, kw_nums, alpha_str, idx_map)
            anchored = count_crib_hits_97(pt)
            qg = qg_score(pt) if QUADGRAMS else -99.0
            results.append({
                'phase': 'kompromat_autokey_raw97',
                'keyword': kw,
                'cipher': ak_name,
                'alphabet': alpha_name,
                'crib_hits': anchored,
                'qg': round(qg, 4),
                'pt': pt[:80],
            })

    # KOMPROMAT autokey on CT73+col7 (use consensus mask)
    CONSENSUS_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in CONSENSUS_MASK)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    ct73_t = [ct73_az[PERM_COL7[i]] for i in range(N_PT)]
    ct73_t_str = ''.join(chr(v + 65) for v in ct73_t)

    for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP), ("KA", KA_STR, KA_IDX_MAP)]:
        try:
            kw_nums = [idx_map[c] for c in kw]
        except KeyError:
            continue

        for ak_name, ak_fn in [
            ("ak_pt_vig", autokey_pt_vig), ("ak_ct_vig", autokey_ct_vig),
            ("ak_pt_beau", autokey_pt_beau), ("ak_ct_beau", autokey_ct_beau),
        ]:
            pt = ak_fn(ct73_t_str, kw_nums, alpha_str, idx_map)
            total, e, b = count_crib_hits_73(pt, CONSENSUS_MASK)
            qg = qg_score(pt) if QUADGRAMS else -99.0
            results.append({
                'phase': 'kompromat_autokey_73col7',
                'keyword': kw,
                'cipher': ak_name,
                'alphabet': alpha_name,
                'crib_hits': total,
                'ene': e,
                'bcl': b,
                'qg': round(qg, 4),
                'pt': pt[:80],
            })

    # KOMPROMAT concatenated keys on raw CT97
    for combo_kw in KOMPROMAT_SPECIALS:
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP)]:
            try:
                kw_nums = [idx_map[c] for c in combo_kw]
            except KeyError:
                continue
            for cipher_name, decrypt_fn in [("beau", beau_dec), ("vig", vig_dec)]:
                pt = decrypt_fn(CT97, kw_nums, alpha_str, idx_map)
                anchored = count_crib_hits_97(pt)
                qg = qg_score(pt) if QUADGRAMS else -99.0
                results.append({
                    'phase': 'kompromat_combo',
                    'keyword': combo_kw,
                    'cipher': cipher_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
                    'qg': round(qg, 4),
                    'pt': pt[:80],
                })

    # KOMPROMAT concatenated keys autokey
    for combo_kw in KOMPROMAT_SPECIALS:
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX_MAP)]:
            try:
                kw_nums = [idx_map[c] for c in combo_kw]
            except KeyError:
                continue
            for ak_name, ak_fn in [
                ("ak_pt_beau", autokey_pt_beau), ("ak_ct_beau", autokey_ct_beau),
            ]:
                pt = ak_fn(CT97, kw_nums, alpha_str, idx_map)
                anchored = count_crib_hits_97(pt)
                qg = qg_score(pt) if QUADGRAMS else -99.0
                results.append({
                    'phase': 'kompromat_combo_autokey',
                    'keyword': combo_kw,
                    'cipher': ak_name,
                    'alphabet': alpha_name,
                    'crib_hits': anchored,
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
    n_workers = min(os.cpu_count() or 4, 4)

    print("=" * 78)
    print("COLD WAR OPS KEYWORD SWEEP")
    print("CIA Operations, Spy Terminology, Berlin Focus")
    print("=" * 78)
    print(f"Keywords: {len(KEYWORDS)}")
    print(f"KOMPROMAT special combos: {len(KOMPROMAT_SPECIALS)}")
    print(f"Quadgrams loaded: {len(QUADGRAMS)}")
    print(f"Workers: {n_workers}")
    print()
    sys.stdout.flush()

    all_results = []

    # ---- Phase 1: Periodic + autokey on raw 97 ----
    print("=" * 78)
    print(f"PHASE 1: Periodic + Autokey on raw CT97 ({len(KEYWORDS)} keywords)")
    print(f"  {len(KEYWORDS)} keywords x 12 cipher modes = ~{len(KEYWORDS) * 12} configs")
    print("=" * 78)
    sys.stdout.flush()

    with mp.Pool(n_workers) as pool:
        for batch in pool.imap_unordered(phase1_periodic_worker, KEYWORDS, chunksize=4):
            for r in batch:
                all_results.append(r)
                if r['crib_hits'] >= 8 or r['qg'] > -5.5:
                    print(f"  [HIT] {r['phase']:10s} | {r['keyword']:25s} | "
                          f"{r['cipher']:12s}/{r['alphabet']} | crib={r['crib_hits']:2d} "
                          f"qg={r['qg']:7.3f} | {r['pt'][:50]}")
                    sys.stdout.flush()

    p1_hits = sum(1 for r in all_results if r['crib_hits'] >= 8 or r.get('qg', -99) > -5.5)
    p1_total = len(all_results)
    print(f"\n  Phase 1 complete: {p1_total} total configs, {p1_hits} hits (>=8/24 or qg>-5.5)")
    sys.stdout.flush()

    # ---- Phase 2: Col7 null-mask SA for all keywords ----
    print()
    print("=" * 78)
    print(f"PHASE 2: Col7 + Null-mask SA for ALL keywords")
    print("=" * 78)
    sys.stdout.flush()

    sa_tasks = []
    for kw in KEYWORDS:
        for seed_base in range(3):  # 3 restarts each
            seed = hash((kw, seed_base)) & 0xFFFFFFFF
            sa_tasks.append((kw, seed, True))   # AZ Beaufort (best model)
            sa_tasks.append((kw, seed, False))  # AZ Vigenere

    print(f"  {len(sa_tasks)} SA tasks ({len(KEYWORDS)} keywords x 3 seeds x 2 ciphers)")
    sys.stdout.flush()

    sa_results = []
    done = 0
    with mp.Pool(n_workers) as pool:
        for r in pool.imap_unordered(sa_col7_worker, sa_tasks, chunksize=2):
            done += 1
            sa_results.append(r)
            if r['crib_hits'] >= 8:
                print(f"  [SA] {r['keyword']:25s} | {r['cipher']} | "
                      f"crib={r['crib_hits']:2d} (ene={r['ene']}, bcl={r['bcl']}) | "
                      f"seed={r['seed']}")
                sys.stdout.flush()
            if done % 100 == 0:
                elapsed = time.time() - t0
                print(f"  SA progress: {done}/{len(sa_tasks)} ({elapsed:.0f}s)")
                sys.stdout.flush()

    all_results.extend(sa_results)
    p2_hits = sum(1 for r in sa_results if r['crib_hits'] >= 8)
    print(f"\n  Phase 2 complete: {len(sa_results)} SA runs, {p2_hits} hits >= 8/24")
    sys.stdout.flush()

    # ---- Phase 3: Running key for long keywords ----
    print()
    print("=" * 78)
    print("PHASE 3: Running key for keywords > 20 chars")
    print("=" * 78)
    sys.stdout.flush()

    rk_results = phase3_running_key()
    all_results.extend(rk_results)
    for r in rk_results:
        if r['crib_hits'] >= 6 or r.get('qg', -99) > -5.5:
            print(f"  [RK] {r['keyword']:35s} | {r['cipher']}/{r['alphabet']} off={r.get('offset', 0)} | "
                  f"crib={r['crib_hits']:2d} qg={r['qg']:7.3f}")
    print(f"\n  Phase 3 complete: {len(rk_results)} results above threshold")
    sys.stdout.flush()

    # ---- Phase 4: KOMPROMAT special ----
    print()
    print("=" * 78)
    print("PHASE 4: KOMPROMAT special tests")
    print("=" * 78)
    sys.stdout.flush()

    kp_results = phase4_kompromat_special()
    all_results.extend(kp_results)
    for r in kp_results:
        tag = r['phase'].replace('kompromat_', '')
        print(f"  [{tag:20s}] {r['keyword']:25s} | {r['cipher']:12s}/{r['alphabet']} | "
              f"crib={r['crib_hits']:2d} qg={r['qg']:7.3f}")
    print(f"\n  Phase 4 complete: {len(kp_results)} configs")
    sys.stdout.flush()

    # ---- Final Summary ----
    elapsed = time.time() - t0
    print()
    print("=" * 78)
    print("FINAL SUMMARY")
    print("=" * 78)

    all_results.sort(key=lambda r: (-r['crib_hits'], -r.get('qg', -99)))

    total_configs = p1_total + len(sa_tasks) + len(rk_results) + len(kp_results)
    print(f"Total configurations tested: {total_configs}")
    print(f"Total results collected: {len(all_results)}")
    print(f"Elapsed: {elapsed:.1f}s")
    print()

    # Report ANYTHING >= 8/24 or qg > -5.5
    hits_8plus = [r for r in all_results if r['crib_hits'] >= 8]
    hits_qg = [r for r in all_results if r.get('qg', -99) > -5.5 and r['crib_hits'] < 8]

    if hits_8plus:
        print(f"RESULTS >= 8/24 CRIB HITS ({len(hits_8plus)} total):")
        print()
        for i, r in enumerate(hits_8plus[:60]):
            print(f"  {i+1:3d}. crib={r['crib_hits']:2d} | {r['phase']:22s} | "
                  f"{r['keyword']:25s} | {r['cipher']:12s}/{r.get('alphabet', 'AZ')} | "
                  f"qg={r.get('qg', -99):7.3f} | {r['pt'][:55]}")
    else:
        print("NO results >= 8/24 crib hits")

    if hits_qg:
        print(f"\nRESULTS with qg > -5.5 (below 8 cribs) ({len(hits_qg)} total):")
        for i, r in enumerate(hits_qg[:20]):
            print(f"  {i+1:3d}. qg={r.get('qg', -99):7.3f} | crib={r['crib_hits']:2d} | "
                  f"{r['phase']:22s} | {r['keyword']:25s} | {r['cipher']:12s}")

    # Best overall
    best_crib = all_results[0]['crib_hits'] if all_results else 0
    best_qg_r = max(all_results, key=lambda r: r.get('qg', -99)) if all_results else None
    print()
    print(f"BEST CRIB: {best_crib}/24")
    if best_qg_r:
        print(f"BEST QG:   {best_qg_r.get('qg', -99):.4f} ({best_qg_r['keyword']}/{best_qg_r['cipher']})")

    # SA phase best per keyword
    print()
    print("SA PHASE BEST PER KEYWORD (top 30):")
    sa_by_kw = {}
    for r in sa_results:
        kw = r['keyword']
        if kw not in sa_by_kw or r['crib_hits'] > sa_by_kw[kw]['crib_hits']:
            sa_by_kw[kw] = r
    sa_sorted = sorted(sa_by_kw.values(), key=lambda r: -r['crib_hits'])
    for i, r in enumerate(sa_sorted[:30]):
        print(f"  {i+1:3d}. {r['keyword']:25s} | {r['cipher']} | crib={r['crib_hits']:2d} "
              f"(ene={r.get('ene', '?')}, bcl={r.get('bcl', '?')})")

    # Signal check
    print()
    if any(r['crib_hits'] >= 18 for r in all_results):
        print("*** SIGNAL DETECTED (>=18/24) --- INVESTIGATE IMMEDIATELY ***")
    elif any(r['crib_hits'] >= 10 for r in all_results):
        print("** INTERESTING (>=10/24) --- Worth further analysis **")
    else:
        print(f"VERDICT: NOISE --- best crib score {best_crib}/24 (below 10/24 threshold)")

    # ---- Save results ----
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'e_cold_war_ops_keyword_sweep.json')

    output = {
        'experiment': 'e_cold_war_ops_keyword_sweep',
        'description': 'Cold War CIA ops + spy terminology keyword sweep',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'n_keywords': len(KEYWORDS),
        'elapsed_seconds': round(elapsed, 1),
        'best_crib_score': best_crib,
        'best_qg': best_qg_r.get('qg', -99) if best_qg_r else -99,
        'hits_8plus_count': len(hits_8plus),
        'hits_qg_count': len(hits_qg),
        'top_results': [r for r in all_results[:100] if 'mask' not in r or len(str(r.get('mask', []))) < 200],
        'sa_best_per_keyword': [{k: v for k, v in r.items() if k != 'mask'} for r in sa_sorted[:50]],
        'keywords_tested': KEYWORDS,
    }

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")
    sys.stdout.flush()


if __name__ == '__main__':
    main()
