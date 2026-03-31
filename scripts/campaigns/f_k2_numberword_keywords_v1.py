#!/usr/bin/env python3
"""
# Cipher: K2 number-word keywords as cipher keys
# Family: campaigns
# Status: active
# Keyspace: ~40 keywords x 10 ciphers x 5 transpositions = ~2,000 configs
# Last run: 2026-03-15
# Best score: TBD

Systematic test of K2 plaintext number-words as cipher keywords for K4.

K2 plaintext: "THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE
SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS
WEST X LAYER TWO"

Sanborn: "I have left instructions in the earlier text that refer to later text"
=> K2 words may BE the cipher keyword for K4.

SEVEN is especially promising: palette generation via KRYPTOS+SEVEN on
KA 5-wide Polybius grid (P=1/1672), Beaufort KA key=N maps SEVEN->palette.

Keywords tested:
  PRIMARY: FIVE, SEVEN, EIGHT, NORTH, WEST, THIRTY, FIFTY, FORTY, SIX,
           POINT, DEGREES, MINUTES, SECONDS, LAYER, TWO
  COMPOUND: THIRTYEIGHT, FIFTYSEVEN, SEVENTYSEVEN, FORTYFOUR,
            NORTHWEST, WESTNORTH, LAYERTWO, SEVENTY, SIXPOINT,
            POINTFIVE, SIXPOINTFIVE
  NUMERIC: digit-derived key vectors from K2 coordinates
  COMPARISON: DEFECTOR, KRYPTOS, PALIMPSEST, ABSCISSA, KOMPASS, COLOPHON

Cipher configs: Beaufort/Vigenere autokey on AZ/KA (4), periodic on AZ/KA (4),
                Quagmire II autokey/periodic (2) = 10 total.

Transposition: col7 ascending, col5, col8, no trans, col7 KRYPTOS-ordered.

Model: CT97 -> remove 24 nulls -> 73 CT -> inv_trans -> autokey/periodic decrypt
Scoring: cribs at shifted positions (Model A).
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import sys, time, json
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97 = CT
N = 97; N_PT = 73; N_NULLS = 24

ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

ENE_NUMS = tuple(AZ_IDX[c] for c in ENE_WORD)
BCL_NUMS = tuple(AZ_IDX[c] for c in BCL_WORD)

# ── Consensus null mask ────────────────────────────────────────────────
# 17 consensus + 7 varying (mask 0)
MASK_24 = sorted([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
MASK_SET = frozenset(MASK_24)

# Pre-count nulls before crib positions
N_BEFORE_21 = sum(1 for p in MASK_24 if p < 21)  # 8
N_BEFORE_63 = sum(1 for p in MASK_24 if p < 63)  # 16
ENE_S = 21 - N_BEFORE_21  # = 13
BCL_S = 63 - N_BEFORE_63  # = 47

CT97_AZ = tuple(AZ_IDX[c] for c in CT97)

# ── Columnar transposition ─────────────────────────────────────────────

def columnar_perm(n, width):
    """Standard ascending columnar transposition permutation."""
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def columnar_perm_ordered(n, width, col_order):
    """Columnar transposition with given column reading order."""
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in col_order:
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def keyword_to_order(kw, width):
    """Keyword to column order: alphabetize keyword letters."""
    kw = kw[:width]
    indexed = sorted(range(len(kw)), key=lambda i: (kw[i], i))
    order = [0] * len(kw)
    for rank, orig in enumerate(indexed):
        order[orig] = rank
    return tuple(order)

# Pre-compute transposition inverse permutations
TRANS_CONFIGS = {}

# Col7 ascending
p7 = columnar_perm(N_PT, 7)
TRANS_CONFIGS["col7_asc"] = tuple(reverse_perm(p7))

# Col5 ascending
p5 = columnar_perm(N_PT, 5)
TRANS_CONFIGS["col5_asc"] = tuple(reverse_perm(p5))

# Col8 ascending
p8 = columnar_perm(N_PT, 8)
TRANS_CONFIGS["col8_asc"] = tuple(reverse_perm(p8))

# No transposition = identity
TRANS_CONFIGS["none"] = tuple(range(N_PT))

# Col7 KRYPTOS-ordered: KRYPTOS = K(0),R(1),Y(2),P(3),T(4),O(5),S(6)
# Alphabetical order: K(0)->0, O(5)->1, P(3)->2, R(1)->3, S(6)->4, T(4)->5, Y(2)->6
# Column reading order: [0, 5, 3, 1, 6, 4, 2]
kryptos_order = keyword_to_order("KRYPTOS", 7)
p7k = columnar_perm_ordered(N_PT, 7, kryptos_order)
TRANS_CONFIGS["col7_kryptos"] = tuple(reverse_perm(p7k))

# ── Extract 73 chars from mask ─────────────────────────────────────────

CT73_AZ = tuple(CT97_AZ[i] for i in range(N) if i not in MASK_SET)
assert len(CT73_AZ) == N_PT

# ── Cipher implementations ─────────────────────────────────────────────

def autokey_decrypt_az(ct73, kw_nums, beaufort=True):
    """Autokey decrypt on AZ. Beaufort: P=(K-C)%26. Vigenere: P=(C-K)%26."""
    L = len(kw_nums)
    pt = [0] * len(ct73)
    for i in range(len(ct73)):
        ki = kw_nums[i] if i < L else pt[i - L]
        if beaufort:
            pt[i] = (ki - ct73[i]) % 26
        else:
            pt[i] = (ct73[i] - ki) % 26
    return pt

def autokey_decrypt_ka(ct73_az, kw_str, beaufort=True):
    """Autokey decrypt on KA alphabet."""
    ct73_ka = [KA_IDX[AZ[c]] for c in ct73_az]
    kw_ka = [KA_IDX[c] for c in kw_str]
    L = len(kw_ka)
    pt_ka = [0] * len(ct73_az)
    for i in range(len(ct73_az)):
        ki = kw_ka[i] if i < L else pt_ka[i - L]
        if beaufort:
            pt_ka[i] = (ki - ct73_ka[i]) % 26
        else:
            pt_ka[i] = (ct73_ka[i] - ki) % 26
    # Convert back to AZ for crib comparison
    return [AZ_IDX[KA[p]] for p in pt_ka]

def periodic_decrypt_az(ct73, kw_nums, beaufort=True):
    """Periodic (repeating key) decrypt on AZ."""
    L = len(kw_nums)
    pt = [0] * len(ct73)
    for i in range(len(ct73)):
        ki = kw_nums[i % L]
        if beaufort:
            pt[i] = (ki - ct73[i]) % 26
        else:
            pt[i] = (ct73[i] - ki) % 26
    return pt

def periodic_decrypt_ka(ct73_az, kw_str, beaufort=True):
    """Periodic decrypt on KA alphabet."""
    ct73_ka = [KA_IDX[AZ[c]] for c in ct73_az]
    kw_ka = [KA_IDX[c] for c in kw_str]
    L = len(kw_ka)
    pt_ka = [0] * len(ct73_az)
    for i in range(len(ct73_az)):
        ki = kw_ka[i % L]
        if beaufort:
            pt_ka[i] = (ki - ct73_ka[i]) % 26
        else:
            pt_ka[i] = (ct73_ka[i] - ki) % 26
    return [AZ_IDX[KA[p]] for p in pt_ka]

def q2_autokey(ct73_az, kw_str):
    """Quagmire II autokey: CT via KA body, key via AZ column, indicator K."""
    # Q2: Look up CT letter in KA to find column, then use AZ key letter
    # to find PT from that column.
    # Decrypt: find ct in KA row of key letter. PT = KA column header.
    # Actually: Q2 uses tableau where row headers are AZ (key), column headers are
    # standard position, body = shifted KA alphabet.
    # For Q2 with indicator K: row for key letter k is KA shifted by (AZ_IDX[k]-AZ_IDX['K'])
    # Decrypt: P = KA[(KA_IDX[C] - AZ_IDX[key[i]]) % 26]
    # With autokey: key[i] = kw[i] for i < L, else PT[i-L]
    kw_az = [AZ_IDX[c] for c in kw_str]
    L = len(kw_az)
    pt = [0] * len(ct73_az)
    for i in range(len(ct73_az)):
        ci_ka = KA_IDX[AZ[ct73_az[i]]]
        ki = kw_az[i] if i < L else pt[i - L]
        pt_ka_idx = (ci_ka - ki) % 26
        pt[i] = AZ_IDX[KA[pt_ka_idx]]
    return pt

def q2_periodic(ct73_az, kw_str):
    """Quagmire II periodic."""
    kw_az = [AZ_IDX[c] for c in kw_str]
    L = len(kw_az)
    pt = [0] * len(ct73_az)
    for i in range(len(ct73_az)):
        ci_ka = KA_IDX[AZ[ct73_az[i]]]
        ki = kw_az[i % L]
        pt_ka_idx = (ci_ka - ki) % 26
        pt[i] = AZ_IDX[KA[pt_ka_idx]]
    return pt

# ── Scoring ────────────────────────────────────────────────────────────

def score_pt(pt_nums, ene_s, bcl_s):
    """Score plaintext against shifted cribs."""
    e = sum(1 for j in range(13) if ene_s + j < len(pt_nums) and pt_nums[ene_s + j] == ENE_NUMS[j])
    b = sum(1 for j in range(11) if bcl_s + j < len(pt_nums) and pt_nums[bcl_s + j] == BCL_NUMS[j])
    return e + b, e, b

# ── Keywords ───────────────────────────────────────────────────────────

# Primary K2 number-words
K2_PRIMARY = [
    "FIVE", "SEVEN", "EIGHT", "NORTH", "WEST", "THIRTY", "FIFTY",
    "FORTY", "SIX", "POINT", "DEGREES", "MINUTES", "SECONDS",
    "LAYER", "TWO",
]

# Compound K2 words
K2_COMPOUND = [
    "THIRTYEIGHT", "FIFTYSEVEN", "SEVENTYSEVEN", "FORTYFOUR",
    "SEVENTY", "NORTHWEST", "WESTNORTH", "LAYERTWO",
    "SIXPOINT", "POINTFIVE", "SIXPOINTFIVE",
    "FIVESEVEN", "SEVENFIVE", "EIGHTFIVE", "EIGHTSEVEN",
    "FIVEEIGHT", "SEVENEIGHT",
    "THIRTYSEVEN", "FIFTYFIVE", "FIFTYEIGHT",
]

# Known comparison keywords
COMPARISON = [
    "DEFECTOR", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "KOMPASS", "COLOPHON",
]

ALL_KEYWORDS = K2_PRIMARY + K2_COMPOUND + COMPARISON

# Numeric key vectors from K2 coordinates
# 38 57 6.5 -> digits [3,8,5,7,6,5]
# 77 8 44 -> digits [7,7,8,4,4]
# All digits: [3,8,5,7,6,5,7,7,8,4,4]
# Coordinate numbers mod 26: [38,57,6,5] mod 26 = [12,5,6,5], [77,8,44] mod 26 = [25,8,18]
NUMERIC_KEYS = {
    "DIGITS_LAT": [3, 8, 5, 7, 6, 5],           # 38°57'6.5"
    "DIGITS_LON": [7, 7, 8, 4, 4],               # 77°8'44"
    "DIGITS_ALL": [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],
    "MOD26_LAT": [12, 5, 6, 5],                   # [38,57,6,5] mod 26
    "MOD26_LON": [25, 8, 18],                      # [77,8,44] mod 26
    "MOD26_ALL": [12, 5, 6, 5, 25, 8, 18],        # combined
    "DIGITS_A0": [3, 8, 5, 7, 6, 5],             # same as DIGITS_LAT (A=0 encoding: D,I,F,H,G,F)
    "RAW_NUMS": [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],  # all raw digits
}

# ── Cipher config list ─────────────────────────────────────────────────

CIPHER_CONFIGS = [
    ("AZ_beau_autokey",  "az", "beaufort", "autokey"),
    ("AZ_vig_autokey",   "az", "vigenere", "autokey"),
    ("KA_beau_autokey",  "ka", "beaufort", "autokey"),
    ("KA_vig_autokey",   "ka", "vigenere", "autokey"),
    ("AZ_beau_periodic", "az", "beaufort", "periodic"),
    ("AZ_vig_periodic",  "az", "vigenere", "periodic"),
    ("KA_beau_periodic", "ka", "beaufort", "periodic"),
    ("KA_vig_periodic",  "ka", "vigenere", "periodic"),
    ("Q2_autokey",       "q2", "beaufort", "autokey"),
    ("Q2_periodic",      "q2", "beaufort", "periodic"),
]

# ── Main sweep ─────────────────────────────────────────────────────────

def decrypt_config(ct73_trans, kw_str, cipher_name, alph, variant, mode):
    """Decrypt using the given cipher configuration. Returns PT as AZ nums."""
    kw_az = [AZ_IDX[c] for c in kw_str]

    if cipher_name.startswith("Q2"):
        if mode == "autokey":
            return q2_autokey(ct73_trans, kw_str)
        else:
            return q2_periodic(ct73_trans, kw_str)
    elif alph == "az":
        beaufort = (variant == "beaufort")
        if mode == "autokey":
            return autokey_decrypt_az(ct73_trans, kw_az, beaufort)
        else:
            return periodic_decrypt_az(ct73_trans, kw_az, beaufort)
    else:  # KA
        beaufort = (variant == "beaufort")
        if mode == "autokey":
            return autokey_decrypt_ka(ct73_trans, kw_str, beaufort)
        else:
            return periodic_decrypt_ka(ct73_trans, kw_str, beaufort)

def decrypt_numeric(ct73_trans, key_nums, beaufort=True, mode="autokey"):
    """Decrypt with numeric key vector on AZ."""
    L = len(key_nums)
    pt = [0] * len(ct73_trans)
    if mode == "autokey":
        for i in range(len(ct73_trans)):
            ki = key_nums[i] if i < L else pt[i - L]
            if beaufort:
                pt[i] = (ki - ct73_trans[i]) % 26
            else:
                pt[i] = (ct73_trans[i] - ki) % 26
    else:  # periodic
        for i in range(len(ct73_trans)):
            ki = key_nums[i % L]
            if beaufort:
                pt[i] = (ki - ct73_trans[i]) % 26
            else:
                pt[i] = (ct73_trans[i] - ki) % 26
    return pt

# ── Run the sweep ──────────────────────────────────────────────────────

print("=" * 70)
print("K2 NUMBER-WORD KEYWORD SWEEP")
print("=" * 70)
print(f"CT: {CT97}")
print(f"Mask: {MASK_24}")
print(f"Shifted crib positions: ENE@{ENE_S}, BCL@{BCL_S}")
print(f"Keywords: {len(ALL_KEYWORDS)} word + {len(NUMERIC_KEYS)} numeric = {len(ALL_KEYWORDS) + len(NUMERIC_KEYS)} total")
print(f"Ciphers: {len(CIPHER_CONFIGS)}")
print(f"Transpositions: {len(TRANS_CONFIGS)}")
print()

# Verify with DEFECTOR:AZ_beau:col7 first
ct73_col7 = tuple(CT73_AZ[TRANS_CONFIGS["col7_asc"][i]] for i in range(N_PT))
defector_az = [AZ_IDX[c] for c in "DEFECTOR"]
pt_verify = autokey_decrypt_az(ct73_col7, defector_az, beaufort=True)
sc_v, e_v, b_v = score_pt(pt_verify, ENE_S, BCL_S)
print(f"VERIFICATION: DEFECTOR:AZ_beau:col7 = {sc_v}/24 (ene={e_v}/13, bcl={b_v}/11)")
assert sc_v == 15, f"Verification failed! Expected 15, got {sc_v}"
print("  VERIFIED OK\n")

t_start = time.time()
total_configs = 0
score_dist = {}
results_13plus = []
results_16plus = []
best_score = 0
best_config = None

# Part 1: Word keywords
print("-" * 70)
print("PART 1: WORD KEYWORDS")
print("-" * 70)

for kw_str in ALL_KEYWORDS:
    kw_best = 0
    for trans_name, inv_perm in TRANS_CONFIGS.items():
        # Apply inverse transposition to CT73
        ct73_trans = tuple(CT73_AZ[inv_perm[i]] for i in range(N_PT))

        for cipher_name, alph, variant, mode in CIPHER_CONFIGS:
            pt = decrypt_config(ct73_trans, kw_str, cipher_name, alph, variant, mode)
            sc, e, b = score_pt(pt, ENE_S, BCL_S)
            total_configs += 1

            score_dist[sc] = score_dist.get(sc, 0) + 1

            if sc > best_score:
                best_score = sc
                best_config = (kw_str, cipher_name, trans_name)

            if sc > kw_best:
                kw_best = sc

            if sc >= 13:
                pt_str = ''.join(AZ[p] for p in pt)
                entry = {
                    "keyword": kw_str,
                    "cipher": cipher_name,
                    "trans": trans_name,
                    "score": sc,
                    "ene": e,
                    "bcl": b,
                    "pt_first60": pt_str[:60],
                }
                results_13plus.append(entry)

                marker = ""
                if sc >= 16:
                    marker = " *** EXCEEDS CEILING ***"
                    results_16plus.append(entry)
                if sc >= 18:
                    marker = " *** SIGNAL ***"
                if sc == 24:
                    marker = " *** BREAKTHROUGH ***"

                print(f"  {kw_str:25s} {cipher_name:20s} {trans_name:15s} = {sc}/24 (e={e}, b={b}){marker}")
                print(f"    PT: {pt_str[:60]}")

    if kw_best >= 10:
        print(f"  [{kw_str}: best={kw_best}/24]")

# Part 2: Numeric keys
print()
print("-" * 70)
print("PART 2: NUMERIC KEY VECTORS")
print("-" * 70)

for num_name, key_nums in NUMERIC_KEYS.items():
    num_best = 0
    for trans_name, inv_perm in TRANS_CONFIGS.items():
        ct73_trans = tuple(CT73_AZ[inv_perm[i]] for i in range(N_PT))

        for beau in [True, False]:
            for mode in ["autokey", "periodic"]:
                pt = decrypt_numeric(ct73_trans, key_nums, beaufort=beau, mode=mode)
                sc, e, b = score_pt(pt, ENE_S, BCL_S)
                total_configs += 1

                cipher_tag = f"{'beau' if beau else 'vig'}_{mode}"
                score_dist[sc] = score_dist.get(sc, 0) + 1

                if sc > best_score:
                    best_score = sc
                    best_config = (num_name, cipher_tag, trans_name)

                if sc > num_best:
                    num_best = sc

                if sc >= 13:
                    pt_str = ''.join(AZ[p] for p in pt)
                    entry = {
                        "keyword": num_name,
                        "cipher": cipher_tag,
                        "trans": trans_name,
                        "score": sc,
                        "ene": e,
                        "bcl": b,
                        "pt_first60": pt_str[:60],
                    }
                    results_13plus.append(entry)

                    marker = ""
                    if sc >= 16:
                        marker = " *** EXCEEDS CEILING ***"
                        results_16plus.append(entry)
                    if sc >= 18:
                        marker = " *** SIGNAL ***"
                    if sc == 24:
                        marker = " *** BREAKTHROUGH ***"

                    print(f"  {num_name:25s} {cipher_tag:20s} {trans_name:15s} = {sc}/24 (e={e}, b={b}){marker}")
                    print(f"    PT: {pt_str[:60]}")

    if num_best >= 10:
        print(f"  [{num_name}: best={num_best}/24]")

# Part 3: Also test with ALL 6 known 15/24 masks
print()
print("-" * 70)
print("PART 3: MULTI-MASK TEST (6 known 15/24 masks)")
print("-" * 70)
print("Testing top keywords with all 6 known masks...")

MASKS_6 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],
    [0,1,2,5,8,12,14,20,36,39,41,42,52,55,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,95],
    [0,1,2,5,8,12,14,20,36,41,42,44,52,55,58,59,74,75,78,84,85,88,93,96],
]

# Top keywords to test across all masks
TOP_KEYWORDS = ["SEVEN", "FIVE", "EIGHT", "NORTH", "NORTHWEST", "LAYERTWO",
                "THIRTYEIGHT", "FIFTYSEVEN", "SEVENTYSEVEN", "DEGREES",
                "POINT", "SECONDS", "DEFECTOR"]

multi_mask_best = 0

for mask_idx, mask in enumerate(MASKS_6):
    ms = frozenset(mask)
    ct73_m = tuple(AZ_IDX[CT97[i]] for i in range(N) if i not in ms)
    assert len(ct73_m) == N_PT

    n_b21 = sum(1 for p in mask if p < 21)
    n_b63 = sum(1 for p in mask if p < 63)
    ene_s_m = 21 - n_b21
    bcl_s_m = 63 - n_b63

    for kw_str in TOP_KEYWORDS:
        for trans_name, inv_perm in TRANS_CONFIGS.items():
            ct73_trans = tuple(ct73_m[inv_perm[i]] for i in range(N_PT))

            for cipher_name, alph, variant, mode in CIPHER_CONFIGS:
                pt = decrypt_config(ct73_trans, kw_str, cipher_name, alph, variant, mode)
                sc, e, b = score_pt(pt, ene_s_m, bcl_s_m)
                total_configs += 1

                if sc > multi_mask_best:
                    multi_mask_best = sc

                if sc >= 13:
                    pt_str = ''.join(AZ[p] for p in pt)
                    marker = ""
                    if sc >= 16:
                        marker = " *** EXCEEDS CEILING ***"
                    if sc >= 18:
                        marker = " *** SIGNAL ***"
                    if sc == 24:
                        marker = " *** BREAKTHROUGH ***"
                    print(f"  mask{mask_idx} {kw_str:20s} {cipher_name:20s} {trans_name:15s} = {sc}/24 (e={e}, b={b}){marker}")

elapsed = time.time() - t_start

# ── Summary ────────────────────────────────────────────────────────────

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total configs tested: {total_configs:,}")
print(f"Elapsed: {elapsed:.1f}s")
print(f"Best score: {best_score}/24 from {best_config}")
print(f"Multi-mask best: {multi_mask_best}/24")
print()

print("Score distribution:")
for sc in sorted(score_dist.keys(), reverse=True):
    pct = 100.0 * score_dist[sc] / total_configs
    print(f"  {sc:3d}/24: {score_dist[sc]:>6,} configs ({pct:.2f}%)")

print()
if results_13plus:
    print(f"\nResults >= 13/24 ({len(results_13plus)} hits):")
    for r in sorted(results_13plus, key=lambda x: -x["score"]):
        marker = ""
        if r["score"] >= 16:
            marker = " *** EXCEEDS CEILING ***"
        if r["score"] >= 18:
            marker = " *** SIGNAL ***"
        if r["score"] == 24:
            marker = " *** BREAKTHROUGH ***"
        print(f"  {r['score']}/24 {r['keyword']:25s} {r['cipher']:20s} {r['trans']:15s} e={r['ene']} b={r['bcl']}{marker}")
else:
    print("No results >= 13/24.")

if results_16plus:
    print(f"\n*** {len(results_16plus)} RESULTS EXCEED 15/24 CEILING: ***")
    for r in results_16plus:
        print(f"  {r['score']}/24 {r['keyword']} {r['cipher']} {r['trans']}")
        print(f"    PT: {r['pt_first60']}")

# ── Save results ──────────────────────────────────────────────────────

output = {
    "experiment": "k2_numberword_keywords",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "total_configs": total_configs,
    "elapsed_s": round(elapsed, 1),
    "best_score": best_score,
    "best_config": str(best_config),
    "multi_mask_best": multi_mask_best,
    "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
    "results_13plus": results_13plus,
    "results_16plus": results_16plus,
    "conclusion": "SIGNAL" if best_score >= 18 else ("EXCEEDS_CEILING" if best_score >= 16 else ("INTERESTING" if best_score >= 13 else "NOISE")),
}

outpath = "/home/cpatrick/kryptos/results/k2_numberword_keywords.json"
with open(outpath, "w") as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to {outpath}")
