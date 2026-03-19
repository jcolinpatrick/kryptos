#!/usr/bin/env python3
"""
Cipher: chaocipher / counter-directional-strips
Family: two_system
Status: active
Keyspace: ~60K configs
Last run:
Best score:
"""
"""Counter-Directional Cipher Models for K4

Motivated by the two arrows on Sanborn's coding chart (one pointing right →,
one pointing left ←) and the Chaocipher parallel noted by Dr. Bean.

Sanborn (NPR 2010): "I think once the Krypto-philes study it in a FORENSIC
manner, there might be REVELATIONS in there."

Tests:
1. True Chaocipher algorithm (Rubin 2010) with KA/AZ/keyword initial states
2. Counter-sliding strips with dynamic (character-dependent) advance
3. Boustrophedon cipher (alternating Vigenère/Beaufort by grid row)

Applied to CT97 (raw carved text) with cribs at standard positions.
"""

import sys
import os
import json
import time

# Bootstrap path
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT

# ============================================================
# Constants
# ============================================================

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
MOD = 26

AZ_INV = {c: i for i, c in enumerate(AZ)}
KA_INV = {c: i for i, c in enumerate(KA)}

CT_NUMS = [AZ_INV[c] for c in CT]

# Crib data
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_NUMS = [AZ_INV[CRIB_DICT[p]] for p in CRIB_POS]

# Thematic keywords
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "BERLIN",
    "CLOCK", "ENIGMA", "SEVEN", "SHADOW", "KOMPASS",
    "COLOPHON", "MAGNETIC", "INVISIBLE", "BURIED",
]

RESULTS_DIR = os.path.join(_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


def keyword_mixed(keyword, base=AZ):
    """Generate a keyword-mixed alphabet."""
    seen = set()
    result = []
    for c in keyword.upper() + base:
        if c.isalpha() and c not in seen:
            seen.add(c)
            result.append(c)
    return "".join(result)


def score_cribs(pt_nums):
    """Score plaintext against known cribs. Returns matching count (0-24)."""
    s = 0
    for pos, exp in zip(CRIB_POS, CRIB_NUMS):
        if pos < len(pt_nums) and pt_nums[pos] == exp:
            s += 1
    return s


# ============================================================
# PHASE 1: TRUE CHAOCIPHER (Rubin 2010)
# ============================================================

def chaocipher_encrypt(pt_list, left_init, right_init):
    """Encrypt using true Chaocipher. All args are lists of ints (0-25)."""
    left = list(left_init)
    right = list(right_init)
    ct = []
    for pv in pt_list:
        pi = right.index(pv)
        cv = left[pi]
        ct.append(cv)
        # Permute left: rotate CT to zenith, extract idx 1, shift 2-13, insert at 13
        left = left[pi:] + left[:pi]
        e = left[1]
        left = [left[0]] + left[2:14] + [e] + left[14:]
        # Permute right: rotate PT to zenith, advance 1, extract idx 2, shift 3-13, insert at 13
        right = right[pi:] + right[:pi]
        right = right[1:] + right[:1]
        e = right[2]
        right = right[:2] + right[3:14] + [e] + right[14:]
    return ct


def chaocipher_decrypt(ct_list, left_init, right_init):
    """Decrypt using true Chaocipher. All args are lists of ints (0-25)."""
    left = list(left_init)
    right = list(right_init)
    pt = []
    for cv in ct_list:
        ci = left.index(cv)
        pv = right[ci]
        pt.append(pv)
        # Permute left (identical to encrypt)
        left = left[ci:] + left[:ci]
        e = left[1]
        left = [left[0]] + left[2:14] + [e] + left[14:]
        # Permute right (identical to encrypt)
        right = right[ci:] + right[:ci]
        right = right[1:] + right[:1]
        e = right[2]
        right = right[:2] + right[3:14] + [e] + right[14:]
    return pt


def verify_chaocipher():
    """Verify against Byrne Exhibit 1 test vector."""
    L = [AZ_INV[c] for c in "HXUCZVAMDSLKPEFJRIGTWOBNYQ"]
    R = [AZ_INV[c] for c in "PTLNBQDEOYSFAVZKGJRIHWXUMC"]
    pt = [AZ_INV[c] for c in "WELLDONEISBETTERTHANWELLSAID"]
    expected = "OAHQHCNYNXTSZJRRHJBYHQKSOUJY"

    ct = chaocipher_encrypt(pt, L, R)
    ct_str = "".join(AZ[v] for v in ct)
    assert ct_str == expected, f"Encrypt failed: {ct_str} != {expected}"

    pt_dec = chaocipher_decrypt(ct, L, R)
    pt_str = "".join(AZ[v] for v in pt_dec)
    assert pt_str == "WELLDONEISBETTERTHANWELLSAID", f"Decrypt failed: {pt_str}"

    print("[PASS] Chaocipher verified against Byrne Exhibit 1")


def run_chaocipher():
    """Test true Chaocipher on CT97 with various initial alphabets."""
    print("\n" + "=" * 60)
    print("PHASE 1: TRUE CHAOCIPHER (Rubin 2010)")
    print("=" * 60)

    # Build alphabet pool: KA rotations + AZ rotations + keyword-mixed
    pool = []
    for i in range(26):
        pool.append((f"KA_r{i}", [AZ_INV[c] for c in (KA[i:] + KA[:i])]))
    for i in range(26):
        pool.append((f"AZ_r{i}", [AZ_INV[c] for c in (AZ[i:] + AZ[:i])]))
    for kw in KEYWORDS:
        m = keyword_mixed(kw)
        pool.append((kw, [AZ_INV[c] for c in m]))
        for r in [7, 13]:
            pool.append((f"{kw}_r{r}", [AZ_INV[c] for c in (m[r:] + m[:r])]))

    n = len(pool)
    print(f"  {n} alphabets → {n*n} pairs")

    best = 0
    best_cfgs = []
    total = 0
    t0 = time.time()

    for ln, li in pool:
        for rn, ri in pool:
            pt = chaocipher_decrypt(CT_NUMS, li, ri)
            sc = score_cribs(pt)
            total += 1
            if sc > best:
                best = sc
                txt = "".join(AZ[v] for v in pt)
                best_cfgs = [(sc, f"L={ln} R={rn}", txt)]
                print(f"  NEW BEST: {sc}/24 — L={ln}, R={rn}")
                if sc >= 6:
                    print(f"    PT: {txt[:60]}...")
            elif sc == best and sc > 0 and len(best_cfgs) < 20:
                txt = "".join(AZ[v] for v in pt)
                best_cfgs.append((sc, f"L={ln} R={rn}", txt))

    elapsed = time.time() - t0
    print(f"  {total} configs in {elapsed:.1f}s, best={best}/24")
    return best, best_cfgs, total


# ============================================================
# PHASE 2: COUNTER-SLIDING STRIPS (dynamic advance)
# ============================================================

def counter_slide_decrypt(ct_nums, a_inv, b_arr, oa, ob, adv_fn):
    """Decrypt with counter-sliding strips using numeric arrays.

    a_inv[letter_num] = position in strip A
    b_arr[position] = letter_num in strip B
    oa, ob = initial offsets
    adv_fn(ct_val, pt_val, pos) -> advance amount
    """
    pt = []
    ca, cb = oa, ob
    for i, cv in enumerate(ct_nums):
        pos = (a_inv[cv] - ca) % MOD
        pv = b_arr[(pos + cb) % MOD]
        pt.append(pv)
        adv = adv_fn(cv, pv, i) % MOD
        ca = (ca + adv) % MOD   # strip A slides right →
        cb = (cb - adv) % MOD   # strip B slides left  ←
    return pt


def build_inv(alpha_str):
    """Build inverse lookup array for an alphabet string."""
    inv = [0] * 26
    for i, c in enumerate(alpha_str):
        inv[AZ_INV[c]] = i
    return inv


def build_arr(alpha_str):
    """Build forward lookup array for an alphabet string."""
    return [AZ_INV[c] for c in alpha_str]


def run_counter_slide():
    """Test counter-sliding strips with dynamic advance on CT97."""
    print("\n" + "=" * 60)
    print("PHASE 2: COUNTER-SLIDING STRIPS (dynamic advance)")
    print("=" * 60)

    # Pre-build KA inverse lookup for advance functions
    ka_inv_map = [0] * 26
    for i, c in enumerate(KA):
        ka_inv_map[AZ_INV[c]] = i

    # Advance functions: (ct_val, pt_val, position) -> advance amount
    # These produce DYNAMIC (non-periodic) substitution
    adv_fns = {
        "ct_az":       lambda cv, pv, i: cv,
        "pt_az":       lambda cv, pv, i: pv,
        "ct_az+1":     lambda cv, pv, i: cv + 1,
        "pt_az+1":     lambda cv, pv, i: pv + 1,
        "ct_ka":       lambda cv, pv, i: ka_inv_map[cv],
        "pt_ka":       lambda cv, pv, i: ka_inv_map[pv],
        "ct_ka+1":     lambda cv, pv, i: ka_inv_map[cv] + 1,
        "pt_ka+1":     lambda cv, pv, i: ka_inv_map[pv] + 1,
        "ct+pt":       lambda cv, pv, i: cv + pv,
        "ct-pt":       lambda cv, pv, i: cv - pv,
        "ct*pt_mod26": lambda cv, pv, i: (cv * pv) % MOD,
        "pos+1":       lambda cv, pv, i: i + 1,
    }

    # Fibonacci advance sequence
    fib = [1, 1]
    for _ in range(100):
        fib.append((fib[-1] + fib[-2]) % 26)
    adv_fns["fibonacci"] = lambda cv, pv, i: fib[min(i, 99)]

    # Strip alphabet pairs
    strips = [
        ("KA", build_inv(KA), build_arr(KA)),
        ("AZ", build_inv(AZ), build_arr(AZ)),
    ]
    for kw in ["PALIMPSEST", "ABSCISSA", "DEFECTOR", "BERLIN", "SEVEN"]:
        m = keyword_mixed(kw)
        strips.append((kw, build_inv(m), build_arr(m)))

    # Test all strip pairs × advance fns × offsets
    pairs = []
    for an, ai, aa in strips:
        for bn, bi, ba in strips:
            pairs.append((f"{an}x{bn}", ai, ba))

    n_total = len(pairs) * len(adv_fns) * 676
    print(f"  {len(pairs)} pairs × {len(adv_fns)} fns × 676 offsets = {n_total} configs")

    best = 0
    best_cfgs = []
    total = 0
    t0 = time.time()

    for pair_name, a_inv, b_arr in pairs:
        for fn_name, fn in adv_fns.items():
            for oa in range(26):
                for ob in range(26):
                    pt = counter_slide_decrypt(CT_NUMS, a_inv, b_arr, oa, ob, fn)
                    sc = score_cribs(pt)
                    total += 1
                    if sc > best:
                        best = sc
                        txt = "".join(AZ[v] for v in pt)
                        cfg = f"{pair_name} fn={fn_name} oa={oa} ob={ob}"
                        best_cfgs = [(sc, cfg, txt)]
                        print(f"  NEW BEST: {sc}/24 — {cfg}")
                        if sc >= 6:
                            print(f"    PT: {txt[:60]}...")
                    elif sc == best and sc > 0 and len(best_cfgs) < 20:
                        txt = "".join(AZ[v] for v in pt)
                        cfg = f"{pair_name} fn={fn_name} oa={oa} ob={ob}"
                        best_cfgs.append((sc, cfg, txt))

    elapsed = time.time() - t0
    print(f"  {total} configs in {elapsed:.1f}s, best={best}/24")
    return best, best_cfgs, total


# ============================================================
# PHASE 3: BOUSTROPHEDON CIPHER (alternating Vig/Beau by row)
# ============================================================

def boustrophedon_decrypt(ct_nums, key_nums, width, mode="vig_beau"):
    """Decrypt with alternating Vigenère/Beaufort by grid row.

    mode:
      "vig_beau" = odd rows Vigenère, even rows Beaufort (→ then ←)
      "beau_vig" = odd rows Beaufort, even rows Vigenère (← then →)
    """
    pt = []
    key_len = len(key_nums)
    for i, cv in enumerate(ct_nums):
        row = i // width
        col = i % width
        ki = key_nums[col % key_len]  # key from column position

        if mode == "vig_beau":
            if row % 2 == 0:  # → Vigenère
                pv = (cv - ki) % MOD
            else:             # ← Beaufort
                pv = (ki - cv) % MOD
        else:  # beau_vig
            if row % 2 == 0:  # ← Beaufort
                pv = (ki - cv) % MOD
            else:             # → Vigenère
                pv = (cv - ki) % MOD
        pt.append(pv)
    return pt


def boustrophedon_decrypt_reversed_key(ct_nums, key_nums, width, mode="vig_beau"):
    """Same but key reads backwards on alternating rows."""
    pt = []
    key_len = len(key_nums)
    for i, cv in enumerate(ct_nums):
        row = i // width
        col = i % width

        if row % 2 == 0:
            ki = key_nums[col % key_len]
        else:
            ki = key_nums[(key_len - 1 - (col % key_len)) % key_len]

        if mode == "vig_beau":
            if row % 2 == 0:
                pv = (cv - ki) % MOD
            else:
                pv = (ki - cv) % MOD
        else:
            if row % 2 == 0:
                pv = (ki - cv) % MOD
            else:
                pv = (cv - ki) % MOD
        pt.append(pv)
    return pt


def run_boustrophedon():
    """Test boustrophedon cipher (coding chart arrow hypothesis)."""
    print("\n" + "=" * 60)
    print("PHASE 3: BOUSTROPHEDON CIPHER (alternating Vig/Beau)")
    print("=" * 60)
    print("  Hypothesis: → arrow = Vigenère, ← arrow = Beaufort")
    print("  Alternating cipher operation by grid row")

    # Generate keyword key sequences
    key_seqs = {}
    for kw in KEYWORDS:
        # Key in AZ
        key_seqs[f"{kw}_AZ"] = [AZ_INV[c] for c in kw]
        # Key in KA
        key_seqs[f"{kw}_KA"] = [KA_INV[c] for c in kw]

    # Grid widths to test (sculpture-relevant)
    widths = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 21, 23, 31]

    modes = ["vig_beau", "beau_vig"]
    variants = ["standard", "reversed_key"]

    n_total = len(key_seqs) * len(widths) * len(modes) * len(variants)
    print(f"  {len(key_seqs)} keys × {len(widths)} widths × {len(modes)} modes × {len(variants)} variants = {n_total}")

    best = 0
    best_cfgs = []
    total = 0
    t0 = time.time()

    for kn, knums in key_seqs.items():
        for w in widths:
            for mode in modes:
                for var in variants:
                    if var == "standard":
                        pt = boustrophedon_decrypt(CT_NUMS, knums, w, mode)
                    else:
                        pt = boustrophedon_decrypt_reversed_key(CT_NUMS, knums, w, mode)
                    sc = score_cribs(pt)
                    total += 1
                    if sc > best:
                        best = sc
                        txt = "".join(AZ[v] for v in pt)
                        cfg = f"key={kn} w={w} mode={mode} var={var}"
                        best_cfgs = [(sc, cfg, txt)]
                        print(f"  NEW BEST: {sc}/24 — {cfg}")
                        if sc >= 6:
                            print(f"    PT: {txt[:60]}...")
                    elif sc == best and sc > 0 and len(best_cfgs) < 10:
                        txt = "".join(AZ[v] for v in pt)
                        cfg = f"key={kn} w={w} mode={mode} var={var}"
                        best_cfgs.append((sc, cfg, txt))

    elapsed = time.time() - t0
    print(f"  {total} configs in {elapsed:.1f}s, best={best}/24")
    return best, best_cfgs, total


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("Counter-Directional Cipher Models for K4")
    print("Hypothesis: coding chart arrows (→ ←) indicate cipher mechanism")
    print(f"CT: {CT}")
    print(f"Cribs: {len(CRIB_POS)} positions ({CRIB_POS[0]}-{CRIB_POS[-1]})")
    print()

    # Verify Chaocipher implementation
    verify_chaocipher()

    # Run all phases
    results = {}

    ch_best, ch_cfgs, ch_n = run_chaocipher()
    results["chaocipher"] = {
        "configs": ch_n, "best_score": ch_best,
        "best": [(s, c, t[:60]) for s, c, t in ch_cfgs[:10]],
    }

    cs_best, cs_cfgs, cs_n = run_counter_slide()
    results["counter_slide"] = {
        "configs": cs_n, "best_score": cs_best,
        "best": [(s, c, t[:60]) for s, c, t in cs_cfgs[:10]],
    }

    bo_best, bo_cfgs, bo_n = run_boustrophedon()
    results["boustrophedon"] = {
        "configs": bo_n, "best_score": bo_best,
        "best": [(s, c, t[:60]) for s, c, t in bo_cfgs[:10]],
    }

    # Summary
    overall = max(ch_best, cs_best, bo_best)
    total = ch_n + cs_n + bo_n

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Chaocipher:     {ch_best}/24 ({ch_n:,} configs)")
    print(f"  Counter-slide:  {cs_best}/24 ({cs_n:,} configs)")
    print(f"  Boustrophedon:  {bo_best}/24 ({bo_n:,} configs)")
    print(f"  Overall best:   {overall}/24 ({total:,} total configs)")

    if overall >= 6:
        print("\n*** ABOVE NOISE — investigate further ***")
    elif overall <= 3:
        print("\n  All models at noise level on CT97.")
        print("  Next steps: test on CT73 (after null extraction),")
        print("  or expand initial alphabet search space.")

    results["overall_best"] = overall
    results["total_configs"] = total
    results["conclusion"] = (
        "SIGNAL" if overall >= 18 else
        "INTERESTING" if overall >= 10 else
        "NOISE"
    )

    outfile = os.path.join(RESULTS_DIR, "e_ts_counter_directional.json")
    with open(outfile, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults → {outfile}")
