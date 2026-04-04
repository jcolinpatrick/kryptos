#!/usr/bin/env python3
"""
Cipher: multi-model
Family: analysis
Status: active
Keyspace: ~2M configs
Last run: 2026-04-04
Best score: TBD

WSW COMPASS ATTACK: The red (north-seeking) needle points TOWARD the
lodestone = WSW (247.5°). Community focused on ENE (opposite end) because
it matches the crib. But Sanborn explicitly says "LODESTONE = MISDIRECTION"
and titled a piece "All Ships Sailed in Circles" — misdirection by magnetism.

HYPOTHESIS: WSW is the operative compass signal, not ENE.
ENE matches the crib (narrative), WSW encodes the method (procedural).

WSW-derived parameters:
  - WSW as letters: W=22, S=18, W=22
  - 247.5° → 247 mod 26 = 13 → N → ROT13 (self-reciprocal!)
  - 247 mod 10 = 7 → period 7, width 7 (known K4 feature!)
  - 247 = 13 × 19 → factors: 13 and 19 (T=19, "T IS YOUR POSITION")
  - 248 (rounded) = 8 × 31 → "3 Lines 93" could be 3 × 31
  - WSW opposite = ENE = 67.5° → 67 mod 26 = 15 (P)
  - WSW+ENE: shifts [22,18,22,4,13,4] or similar interleaving
  - 247.5 / 360 × 26 = 17.875 → ~18 = S (or 17 = R, same as YAR!)

The 247 = 13 × 19 factoring is remarkable:
  - 13 = ROT13 = the classic self-reciprocal shift
  - 19 = T in A=0 = "T IS YOUR POSITION"
  - 13 + 19 = 32, and position 32 is where CT[32]=S and PT[32]=S (self-encrypting!)

Usage: PYTHONPATH=src python3 -u scripts/analysis/e_wsw_compass_attack.py
"""

import sys
import os
import json
import time
import itertools
from multiprocessing import Pool, cpu_count
from typing import List, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_decrypt, beau_decrypt, varbeau_decrypt,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
CT_NUMS = [ALPH_IDX[c] for c in CT]
CT_KA = [KA_IDX[c] for c in CT]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
DFNS = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}

best_score = 0
results = []


def log_hit(attack, score, pt, method):
    global best_score
    results.append({"attack": attack, "score": score, "pt": pt[:60], "method": method})
    if score > best_score:
        best_score = score
        print(f"  *** NEW BEST: {score}/{N_CRIBS} | {attack} | {method}")
        print(f"      PT: {pt[:70]}")


def decrypt_score(ct_nums, key_nums, variant):
    dfn = DFNS[variant]
    pt = "".join(ALPH[dfn(ct_nums[i], key_nums[i])] for i in range(len(ct_nums)))
    return pt, score_cribs(pt)


# ══════════════════════════════════════════════════════════════════════════════
# W1: WSW as keyword (repeating)
# ══════════════════════════════════════════════════════════════════════════════

def attack_W1():
    """WSW and related compass keywords."""
    print("\n[W1] WSW-derived keywords...")
    count = 0

    keywords = [
        "WSW",                      # direct
        "WESTSOUTHWEST",            # full name
        "WESTSOUTHWESTERLY",        # extended
        "WSWENE",                   # both bearings
        "ENEWSW",                   # reversed
        "SWWSW",                    # stuttered
        "WEST",                     # component
        "SOUTHWEST",                # component
        "SOUTH",                    # component
        # Numeric-derived
        "NR",                       # 13,17 (247 mod 26 = 13 = N, YAR R=17)
        "NT",                       # 13,19 (factors of 247)
        "PN",                       # 15,13 (ENE mod 26 = 15, WSW mod 26 = 13)
        "NTSRP",                    # 13,19,18,17,15 (WSW-derived values)
        # WSW as A=0 → shift values
        "KRYPTOSWSW",              # keyword + compass
        "WSWKRYPTOS",
        "POINTWSW",
        "WSWPOINT",
        "SHADOWWSW",
        "WSWSECRET",
        "WSWSEVEN",
        # 247 factoring: 13 × 19
        "NT",                       # N=13, T=19
        "TN",                       # reversed
    ]

    for kw in keywords:
        key = [ALPH_IDX[c] for c in kw]
        key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
        for variant in VARIANTS:
            pt, sc = decrypt_score(CT_NUMS, key_ext, variant)
            if sc >= NOISE_FLOOR:
                log_hit("W1", sc, pt, f"keyword_{kw}_{variant.value}")
            count += 1

        # Also with KA indexing
        ka_key = [KA_IDX[c] for c in kw if c in KA_IDX]
        if ka_key:
            ka_ext = (ka_key * ((CT_LEN // len(ka_key)) + 1))[:CT_LEN]
            for variant in VARIANTS:
                dfn = DFNS[variant]
                pt = "".join(KA[dfn(CT_KA[i], ka_ext[i]) % 26] for i in range(CT_LEN))
                sc = score_cribs(pt)
                if sc >= NOISE_FLOOR:
                    log_hit("W1", sc, pt, f"KA_keyword_{kw}_{variant.value}")
                count += 1

    print(f"  W1 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# W2: ROT13 connection (247 mod 26 = 13)
# ══════════════════════════════════════════════════════════════════════════════

def attack_W2():
    """247 mod 26 = 13 = ROT13. Test ROT13 as a layer."""
    print("\n[W2] ROT13 as cipher layer...")
    count = 0

    # ROT13 the CT first, then try keywords
    ct_rot13 = "".join(ALPH[(ALPH_IDX[c] + 13) % 26] for c in CT)
    ct_rot13_nums = [ALPH_IDX[c] for c in ct_rot13]

    # Score ROT13 directly
    sc = score_cribs(ct_rot13)
    print(f"  ROT13(CT) direct score: {sc}/{N_CRIBS}")
    if sc >= NOISE_FLOOR:
        log_hit("W2", sc, ct_rot13, "rot13_direct")
    count += 1

    # ROT13 then keyword decrypt
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "SECRET",
               "WSW", "SEVEN", "BERLIN", "SHADOW", "COMPASS"]:
        key = [ALPH_IDX[c] for c in kw]
        key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
        for variant in VARIANTS:
            pt, sc = decrypt_score(ct_rot13_nums, key_ext, variant)
            if sc >= NOISE_FLOOR:
                log_hit("W2", sc, pt, f"rot13_then_{kw}_{variant.value}")
            count += 1

    # Keyword decrypt then ROT13
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "SECRET",
               "WSW", "SEVEN"]:
        key = [ALPH_IDX[c] for c in kw]
        key_ext = (key * ((CT_LEN // len(key)) + 1))[:CT_LEN]
        for variant in VARIANTS:
            pt, sc_raw = decrypt_score(CT_NUMS, key_ext, variant)
            pt_rot13 = "".join(ALPH[(ALPH_IDX[c] + 13) % 26] for c in pt)
            sc = score_cribs(pt_rot13)
            if sc >= NOISE_FLOOR:
                log_hit("W2", sc, pt_rot13, f"{kw}_then_rot13_{variant.value}")
            count += 1

    # Alternating ROT13: apply ROT13 to every other position
    for phase in [0, 1]:
        ct_alt = ""
        for i, c in enumerate(CT):
            if i % 2 == phase:
                ct_alt += ALPH[(ALPH_IDX[c] + 13) % 26]
            else:
                ct_alt += c
        sc = score_cribs(ct_alt)
        if sc >= NOISE_FLOOR:
            log_hit("W2", sc, ct_alt, f"alt_rot13_phase{phase}")
        count += 1

    print(f"  W2 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# W3: 247 = 13 × 19 — factor-derived period/shift
# ══════════════════════════════════════════════════════════════════════════════

def attack_W3():
    """247 = 13 × 19. Test period 13 with shift 19, period 19 with shift 13, etc."""
    print("\n[W3] Factor 247=13×19 exploitation...")
    count = 0

    # Period 13, shifts derived from 19
    for period in [13, 19, 7]:  # 7 because 247 mod 10 = 7
        for base_shift in [13, 19, 7, 22, 18]:  # N, T, G/7, W, S
            # Progressive key: shift increases by base_shift each period
            key_nums = [(base_shift * (i // period) + (i % period)) % 26
                        for i in range(CT_LEN)]
            for variant in VARIANTS:
                pt, sc = decrypt_score(CT_NUMS, key_nums, variant)
                if sc >= NOISE_FLOOR:
                    log_hit("W3", sc, pt,
                            f"p{period}_shift{base_shift}_prog_{variant.value}")
                count += 1

            # Multiplicative key
            key_nums = [(base_shift * (i % period)) % 26 for i in range(CT_LEN)]
            for variant in VARIANTS:
                pt, sc = decrypt_score(CT_NUMS, key_nums, variant)
                if sc >= NOISE_FLOOR:
                    log_hit("W3", sc, pt,
                            f"p{period}_shift{base_shift}_mult_{variant.value}")
                count += 1

    # Special: period 13 with two-phase key [13, 19, 13, 19, ...]
    key_cycle = [13, 19]
    key_nums = [key_cycle[i % 2] for i in range(CT_LEN)]
    for variant in VARIANTS:
        pt, sc = decrypt_score(CT_NUMS, key_nums, variant)
        if sc >= NOISE_FLOOR:
            log_hit("W3", sc, pt, f"cycle_13_19_{variant.value}")
        count += 1

    # Period 13 exhaustive (26^1 × some combos)
    for shift_a in range(26):
        for shift_b in range(26):
            key_nums = [shift_a if i % 13 < 7 else shift_b for i in range(CT_LEN)]
            pt, sc = decrypt_score(CT_NUMS, key_nums, CipherVariant.BEAUFORT)
            if sc >= NOISE_FLOOR:
                log_hit("W3", sc, pt, f"p13_split_a{shift_a}_b{shift_b}_beau")
            count += 1

    print(f"  W3 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# W4: WSW+YAR combined parameters
# ══════════════════════════════════════════════════════════════════════════════

def attack_W4():
    """WSW bearing (247.5°) combined with YAR (24,0,17) as cipher parameters."""
    print("\n[W4] WSW + YAR combined parameters...")
    count = 0

    # 247.5 / 360 × 26 = 17.875 → R=17 matches YAR's R!
    # This is a striking convergence: compass bearing → same value as YAR's R.

    # Key: [W, S, W, Y, A, R] = [22, 18, 22, 24, 0, 17]
    wsw_yar = [22, 18, 22, 24, 0, 17]  # period 6
    wsw_yar_key = (wsw_yar * ((CT_LEN // 6) + 1))[:CT_LEN]
    for variant in VARIANTS:
        pt, sc = decrypt_score(CT_NUMS, wsw_yar_key, variant)
        if sc >= NOISE_FLOOR:
            log_hit("W4", sc, pt, f"WSWYAR_p6_{variant.value}")
        count += 1

    # DRYAD-style: use WSW values [22,18,22] to select 3 tableau rows,
    # then use YAR [24,0,17] to select starting column within each row
    tab = []
    for r in range(26):
        tab.append([KA[(r + c) % 26] for c in range(26)])

    for wsw_rows in [[22, 18, 22], [18, 22, 18]]:
        for yar_start in [[24, 0, 17], [17, 0, 24]]:
            key_text = ""
            for cycle in range(CT_LEN // 3 + 1):
                for i in range(3):
                    r = wsw_rows[i % len(wsw_rows)]
                    c = (yar_start[i % len(yar_start)] + cycle) % 26
                    key_text += tab[r][c]
            key_nums = [ALPH_IDX[c] for c in key_text[:CT_LEN]]
            for variant in VARIANTS:
                pt, sc = decrypt_score(CT_NUMS, key_nums, variant)
                if sc >= NOISE_FLOOR:
                    log_hit("W4", sc, pt,
                            f"tab_WSW{''.join(str(r) for r in wsw_rows)}_YAR{''.join(str(y) for y in yar_start)}_{variant.value}")
                count += 1

    # Fibonacci from WSW values: seed [22, 18, 22], Fibonacci mod 26
    seeds_list = [
        [22, 18, 22],          # WSW
        [22, 18, 22, 24, 0, 17],  # WSW+YAR
        [13, 19],              # N, T (247 factors)
        [17, 0, 24],           # RAY (reversed YAR)
        [22, 18],              # WS
        [13, 7],               # N=247%26, G=247%10
    ]

    for seed in seeds_list:
        ks = list(seed)
        while len(ks) < CT_LEN:
            ks.append((ks[-len(seed)] + ks[-len(seed)+1]) % 26)
        for variant in VARIANTS:
            pt, sc = decrypt_score(CT_NUMS, ks[:CT_LEN], variant)
            if sc >= NOISE_FLOOR:
                log_hit("W4", sc, pt,
                        f"fib_seed{'_'.join(str(s) for s in seed)}_{variant.value}")
            count += 1

        # Also Fibonacci mod 10
        ks10 = list(seed)
        while len(ks10) < CT_LEN:
            ks10.append((ks10[-len(seed)] + ks10[-len(seed)+1]) % 10)
        for variant in VARIANTS:
            pt, sc = decrypt_score(CT_NUMS, ks10[:CT_LEN], variant)
            if sc >= NOISE_FLOOR:
                log_hit("W4", sc, pt,
                        f"fib10_seed{'_'.join(str(s) for s in seed)}_{variant.value}")
            count += 1

    print(f"  W4 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# W5: Columnar width 7 (247 mod 10 = 7) + WSW-derived column order
# ══════════════════════════════════════════════════════════════════════════════

def attack_W5():
    """Width-7 columnar with WSW-derived column orders, then substitution."""
    print("\n[W5] Width-7 columnar + WSW parameters...")
    count = 0

    def columnar_unread(text, width, col_order):
        """Undo columnar transposition with given column order."""
        n = len(text)
        nrows = (n + width - 1) // width
        full_cols = n % width if n % width != 0 else width

        # How many chars in each column (in output order)
        col_lens = []
        for c in range(width):
            if c < full_cols:
                col_lens.append(nrows)
            else:
                col_lens.append(nrows - 1)

        # Read columns in the order specified
        cols = {}
        pos = 0
        for out_idx in range(width):
            orig_col = col_order[out_idx]
            clen = col_lens[orig_col]
            cols[orig_col] = text[pos:pos + clen]
            pos += clen

        # Read row by row
        result = []
        for r in range(nrows):
            for c in range(width):
                if r < len(cols.get(c, "")):
                    result.append(cols[c][r])
        return "".join(result)

    # All 5040 permutations of 7 columns
    for perm in itertools.permutations(range(7)):
        deperm = columnar_unread(CT, 7, list(perm))
        sc = score_cribs(deperm)
        if sc >= NOISE_FLOOR:
            log_hit("W5", sc, deperm, f"col7_order{''.join(str(p) for p in perm)}")
        count += 1

        # Also: decipher then Beaufort with WSW key
        dep_nums = [ALPH_IDX[c] for c in deperm]
        wsw_key = [22, 18, 22] * ((CT_LEN // 3) + 1)
        pt, sc2 = decrypt_score(dep_nums, wsw_key[:CT_LEN], CipherVariant.BEAUFORT)
        if sc2 >= NOISE_FLOOR:
            log_hit("W5", sc2, pt,
                    f"col7_{''.join(str(p) for p in perm)}_then_WSW_beau")
        count += 1

        if count % 1000 == 0 and count > 0:
            print(f"    W5 progress: {count:,}...")

    print(f"  W5 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# W6: WSW as Beaufort key for width-7 sub-columns
# ══════════════════════════════════════════════════════════════════════════════

def attack_W6():
    """Interleave WSW (3 values) and ENE (3 values) as period-6 key, exhaustive."""
    print("\n[W6] WSW/ENE interleaved period-6 exhaustive Beaufort...")
    count = 0

    # WSW = [22, 18, 22], ENE = [4, 13, 4]
    # Try all 720 permutations of these 6 values
    base_values = [22, 18, 22, 4, 13, 4]

    seen = set()
    for perm in itertools.permutations(base_values):
        if perm in seen:
            continue
        seen.add(perm)
        key = list(perm) * ((CT_LEN // 6) + 1)
        key = key[:CT_LEN]
        for variant in VARIANTS:
            pt, sc = decrypt_score(CT_NUMS, key, variant)
            if sc >= NOISE_FLOOR:
                log_hit("W6", sc, pt,
                        f"wsw_ene_perm{''.join(str(v) for v in perm)}_{variant.value}")
            count += 1

    # Also: [W,S,W,E,N,E] as letter indices with KA
    base_ka = [KA_IDX[c] for c in "WSWENE"]
    for perm in itertools.permutations(range(6)):
        perm_key = [base_ka[perm[i % 6]] for i in range(CT_LEN)]
        # Only test Beaufort (most promising)
        pt_nums = [beau_decrypt(CT_KA[i], perm_key[i]) for i in range(CT_LEN)]
        pt = "".join(KA[n % 26] for n in pt_nums)
        sc = score_cribs(pt)
        if sc >= NOISE_FLOOR:
            log_hit("W6", sc, pt,
                    f"KA_wsw_ene_perm{''.join(str(p) for p in perm)}_beau")
        count += 1

    print(f"  W6 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# W7: Position 32 self-encrypting connection: 13 + 19 = 32
# ══════════════════════════════════════════════════════════════════════════════

def attack_W7():
    """247 = 13 × 19, and 13 + 19 = 32. CT[32]=PT[32]=S (self-encrypting).
    Test: start keystream at position 32 offset, or use position 32 as pivot."""
    print("\n[W7] Position 32 self-encrypting pivot...")
    count = 0

    # Split K4 at position 32 (the self-encrypting S) and treat halves differently
    # Half 1: positions 0-31 (32 chars), Half 2: positions 32-96 (65 chars)

    for shift1 in range(26):
        for shift2 in range(26):
            key = [shift1] * 32 + [shift2] * 65
            for variant in VARIANTS:
                pt, sc = decrypt_score(CT_NUMS, key, variant)
                if sc >= NOISE_FLOOR:
                    log_hit("W7", sc, pt,
                            f"split32_s1_{shift1}_s2_{shift2}_{variant.value}")
                count += 1

    # Position 73 also self-encrypts (CT[73]=PT[73]=K)
    # Split at both: [0-31] [32-72] [73-96]
    for s1 in range(26):
        for s2 in range(26):
            for s3 in range(26):
                key = [s1]*32 + [s2]*41 + [s3]*24
                # Only Beaufort
                pt, sc = decrypt_score(CT_NUMS, key, CipherVariant.BEAUFORT)
                if sc >= NOISE_FLOOR:
                    log_hit("W7", sc, pt,
                            f"split32_73_s{s1}_{s2}_{s3}_beau")
                count += 1
                if count % 100000 == 0:
                    print(f"    W7 progress: {count:,}...")

    print(f"  W7 complete: {count:,} configs")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    start = time.time()
    print("=" * 80)
    print("WSW COMPASS ATTACK — The red needle points toward the lodestone")
    print("=" * 80)
    print(f"\nKey numeric values:")
    print(f"  WSW = 247.5° → 247 mod 26 = 13 (N) = ROT13")
    print(f"  247 = 13 × 19 → N=13, T=19 ('T IS YOUR POSITION')")
    print(f"  247 mod 10 = 7 → width-7 (known K4 feature)")
    print(f"  13 + 19 = 32 → position of self-encrypting S")
    print(f"  247.5/360 × 26 = 17.875 → ~R=17 (matches YAR)")

    attacks = [
        attack_W1,   # WSW keywords
        attack_W2,   # ROT13 layer
        attack_W3,   # 247=13×19 period/shift
        attack_W4,   # WSW+YAR combined
        attack_W5,   # Width-7 columnar + WSW order
        attack_W6,   # WSW/ENE interleaved
        attack_W7,   # Position 32 self-encrypting pivot
    ]

    for fn in attacks:
        try:
            fn()
        except Exception as e:
            print(f"  ERROR in {fn.__name__}: {e}")
            import traceback
            traceback.print_exc()

    elapsed = time.time() - start

    print("\n" + "=" * 80)
    print(f"WSW COMPASS ATTACK COMPLETE — {elapsed:.1f}s")
    print(f"Results above noise ({NOISE_FLOOR}): {len(results)}")
    print(f"Best score: {best_score}/{N_CRIBS}")
    print("=" * 80)

    if results:
        for r in sorted(results, key=lambda x: -x['score'])[:20]:
            print(f"  Score {r['score']:2d} | {r['attack']} | {r['method']}")
            print(f"           PT: {r['pt']}")

    out_path = os.path.join(_ROOT, "results", "wsw_compass_attack.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed": elapsed,
            "best_score": best_score,
            "total_hits": len(results),
            "results": results,
        }, f, indent=2)
    print(f"\nResults: {out_path}")


if __name__ == "__main__":
    main()
