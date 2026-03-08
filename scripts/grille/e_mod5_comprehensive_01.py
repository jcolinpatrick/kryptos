#!/usr/bin/env python3
"""
# Cipher: Mod-5 Pattern Analysis (Bean E0d)
# Family: grille
# Status: active
# Keyspace: ~50M (interleave perms * keywords * variants + period-5 enums)
# Last run: never
# Best score: n/a
#
# Bean 2021 (E0d): mod-5 pattern in K4 with p~1/1470, NEVER explored.
# Connections: Berlin Clock (base-5), FIVE at cylinder seam, 5 W's, 5 DYARO chars.
#
# This script performs six analyses:
#  1. IC and frequency of mod-5 residue classes
#  2. Mod-5 interleaved reads with keyword decryption (120 orderings x 8 keywords x 3 variants)
#  3. Period-5 key consistency analysis from cribs
#  4. Berlin Clock: brute-force all 26^5 period-5 keys (optimized numeric)
#  5. Mod-5 transposition (5 streams reinterleaved, 120 perms)
#  6. Summary report with mod-5 keystream patterns
"""
from __future__ import annotations

import itertools
import sys
import os
import time
from collections import Counter
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
    BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.ic import ic, ic_by_position
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.free_crib import score_free_fast
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.constraints.bean import verify_bean_simple

PERIOD = 5
KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
            "COLOPHON", "SHADOW", "FIVE"]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
VARIANT_NAMES = {
    CipherVariant.VIGENERE: "Vigenere",
    CipherVariant.BEAUFORT: "Beaufort",
    CipherVariant.VAR_BEAUFORT: "VarBeau",
}

KEY_RECOVER_FN = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}

# Pre-compute numeric CT
CT_NUMS = [ord(c) - 65 for c in CT]

# Pre-compute crib positions and expected values as numeric
CRIB_NUMS = {pos: ord(ch) - 65 for pos, ch in CRIB_DICT.items()}

# ── Fast numeric decrypt & score ───────────────────────────────────────────

def fast_decrypt_period5(ct_nums, key5, variant):
    """Decrypt with period-5 key using numeric arrays. Returns list of ints."""
    result = [0] * len(ct_nums)
    if variant == CipherVariant.VIGENERE:
        for i, c in enumerate(ct_nums):
            result[i] = (c - key5[i % 5]) % 26
    elif variant == CipherVariant.BEAUFORT:
        for i, c in enumerate(ct_nums):
            result[i] = (key5[i % 5] - c) % 26
    else:  # VAR_BEAUFORT
        for i, c in enumerate(ct_nums):
            result[i] = (c + key5[i % 5]) % 26
    return result


def fast_crib_score(pt_nums):
    """Count matching crib positions from numeric plaintext."""
    score = 0
    for pos, expected in CRIB_NUMS.items():
        if pt_nums[pos] == expected:
            score += 1
    return score


def fast_free_crib_score(pt_nums):
    """Fast check for EASTNORTHEAST and BERLINCLOCK as substrings."""
    pt_str = "".join(chr(n + 65) for n in pt_nums)
    score = 0
    if "EASTNORTHEAST" in pt_str:
        score += 13
    if "BERLINCLOCK" in pt_str:
        score += 11
    return score


def fast_bean_check(key5):
    """Check Bean constraints for a period-5 key."""
    full_ks = [key5[i % 5] for i in range(CT_LEN)]
    return verify_bean_simple(full_ks)


def keyword_to_key(keyword):
    return [ALPH_IDX[c] for c in keyword.upper()]


def decrypt_with_keyword(ct, keyword, variant):
    key = keyword_to_key(keyword)
    return decrypt_text(ct, key, variant)


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS 1: Mod-5 Residue Class Statistics
# ═══════════════════════════════════════════════════════════════════════════════

def analysis_1():
    print("=" * 80)
    print("ANALYSIS 1: Mod-5 Residue Class Statistics")
    print("=" * 80)
    print()

    classes = [""] * PERIOD
    for i, ch in enumerate(CT):
        classes[i % PERIOD] += ch

    overall_ic = ic(CT)
    print(f"Overall K4 IC: {overall_ic:.4f} (random: {1/26:.4f}, English: 0.0667)")
    print()

    position_ics = ic_by_position(CT, PERIOD)

    for r in range(PERIOD):
        group = classes[r]
        group_ic = position_ics[r]
        freq = Counter(group)
        n = len(group)

        print(f"Class {r} (positions mod 5 = {r}): {n} chars, IC = {group_ic:.4f}")
        print(f"  Text: {group}")
        sorted_freq = sorted(freq.items(), key=lambda x: -x[1])
        freq_str = ", ".join(f"{c}:{cnt}" for c, cnt in sorted_freq[:10])
        print(f"  Top freqs: {freq_str}")
        expected = n / 26.0
        chi2 = sum((freq.get(c, 0) - expected) ** 2 / expected for c in ALPH)
        print(f"  Chi-squared (uniform): {chi2:.2f}  (critical p=0.05 df=25: 37.65)")
        print(f"  Distinct letters: {len(freq)}/26")
        print()

    print("IC by residue for various periods (for comparison):")
    for p in [3, 4, 5, 6, 7, 8, 10, 13]:
        ics = ic_by_position(CT, p)
        avg_ic = sum(ics) / len(ics)
        print(f"  Period {p:2d}: avg={avg_ic:.4f}, max={max(ics):.4f}, "
              f"min={min(ics):.4f}, values=[{', '.join(f'{v:.4f}' for v in ics)}]")
    print()

    print("Crib positions by mod-5 residue:")
    for r in range(PERIOD):
        crib_in_class = sorted((pos, ch) for pos, ch in CRIB_DICT.items() if pos % PERIOD == r)
        entries = ", ".join(f"{pos}={ch}" for pos, ch in crib_in_class) if crib_in_class else "(none)"
        print(f"  Class {r}: {len(crib_in_class)} cribs: {entries}")
    print()

    print("Bean equality constraint positions by mod-5 residue:")
    for a, b in BEAN_EQ:
        print(f"  k[{a}] == k[{b}]  -->  residues {a%5} and {b%5}")
    print()

    print("Bean inequality constraints by residue pair:")
    residue_ineq = Counter()
    for a, b in BEAN_INEQ:
        residue_ineq[(a%5, b%5)] += 1
    for (ra, rb), cnt in sorted(residue_ineq.items()):
        print(f"  ({ra}, {rb}): {cnt} constraints")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS 2: Mod-5 Interleaved Reads + Keyword Decryption
# ═══════════════════════════════════════════════════════════════════════════════

def analysis_2():
    print("=" * 80)
    print("ANALYSIS 2: Mod-5 Interleaved Reads + Keyword Decryption")
    print("=" * 80)
    print()

    classes = [""] * PERIOD
    for i, ch in enumerate(CT):
        classes[i % PERIOD] += ch
    print(f"Class sizes: {[len(c) for c in classes]}")
    print()

    best_results = []
    total = 0

    for perm in itertools.permutations(range(PERIOD)):
        reordered = "".join(classes[p] for p in perm)
        for keyword in KEYWORDS:
            for variant in VARIANTS:
                pt = decrypt_with_keyword(reordered, keyword, variant)
                anch = score_cribs(pt)
                free = score_free_fast(pt)
                best_sc = max(anch, free)
                total += 1
                if best_sc > NOISE_FLOOR:
                    method = f"interleave({perm})+{keyword}+{VARIANT_NAMES[variant]}"
                    best_results.append((best_sc, pt[:50], method, f"a={anch},f={free}"))

    best_results.sort(key=lambda x: -x[0])
    print(f"Tested: {total}, Hits above noise ({NOISE_FLOOR}): {len(best_results)}")
    if best_results:
        print("\nTop 20:")
        for i, (sc, pt, method, det) in enumerate(best_results[:20]):
            print(f"  {i+1:3d}. score={sc:2d} {det}  {method}")
            print(f"       PT: {pt}...")
    else:
        print("  None above noise floor.")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS 3: Period-5 Key Consistency from Cribs
# ═══════════════════════════════════════════════════════════════════════════════

def analysis_3():
    print("=" * 80)
    print("ANALYSIS 3: Period-5 Key Consistency from Cribs")
    print("=" * 80)
    print()

    KA = KRYPTOS_ALPHABET
    KA_IDX = {c: i for i, c in enumerate(KA)}

    for label, alpha_idx in [("Standard AZ", ALPH_IDX), ("KA", KA_IDX)]:
        print(f"--- {label} ---")
        for variant in VARIANTS:
            vname = VARIANT_NAMES[variant]
            recover = KEY_RECOVER_FN[variant]

            key_by_res = {r: [] for r in range(PERIOD)}
            for pos, pt_ch in sorted(CRIB_DICT.items()):
                ct_ch = CT[pos]
                c = alpha_idx[ct_ch]
                p = alpha_idx[pt_ch]
                k = recover(c, p)
                key_by_res[pos % PERIOD].append((pos, k, ct_ch, pt_ch))

            all_consistent = True
            for r in range(PERIOD):
                entries = key_by_res[r]
                if not entries:
                    continue
                k_vals = set(e[1] for e in entries)
                if len(k_vals) > 1:
                    all_consistent = False

            if all_consistent:
                key_str_parts = []
                for r in range(PERIOD):
                    entries = key_by_res[r]
                    if entries:
                        kv = entries[0][1]
                        if label == "KA":
                            key_str_parts.append(KA[kv])
                        else:
                            key_str_parts.append(ALPH[kv])
                    else:
                        key_str_parts.append("?")
                print(f"  {vname} + {label}: CONSISTENT! Key = {''.join(key_str_parts)}")
            else:
                # Count how many residues are consistent
                n_con = 0
                n_incon = 0
                for r in range(PERIOD):
                    entries = key_by_res[r]
                    if entries:
                        k_vals = set(e[1] for e in entries)
                        if len(k_vals) == 1:
                            n_con += 1
                        else:
                            n_incon += 1
                print(f"  {vname} + {label}: INCONSISTENT ({n_con} consistent, {n_incon} inconsistent)")

                # Show detail for AZ only
                if label == "Standard AZ":
                    for r in range(PERIOD):
                        entries = key_by_res[r]
                        k_vals = sorted(set(e[1] for e in entries))
                        letters = ",".join(ALPH[k] for k in k_vals)
                        status = "OK" if len(k_vals) == 1 else "CLASH"
                        print(f"    r={r}: {status} vals={k_vals} ({letters})")
                        for pos, k, ct_ch, pt_ch in entries:
                            print(f"      pos={pos:2d}: CT={ct_ch} PT={pt_ch} k={k:2d} ({ALPH[k]})")
        print()


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS 4: Brute-Force Period-5 Keys (Optimized)
# ═══════════════════════════════════════════════════════════════════════════════

def analysis_4():
    print("=" * 80)
    print("ANALYSIS 4: Brute-Force All 26^5 Period-5 Keys (Optimized)")
    print("=" * 80)
    print()

    total_keys = 26**5
    print(f"Total keys to test per variant: {total_keys:,}")
    print()

    for variant in VARIANTS:
        vname = VARIANT_NAMES[variant]
        t0 = time.time()
        hits = []
        tested = 0

        for k0 in range(26):
            for k1 in range(26):
                for k2 in range(26):
                    for k3 in range(26):
                        for k4 in range(26):
                            key5 = [k0, k1, k2, k3, k4]
                            pt_nums = fast_decrypt_period5(CT_NUMS, key5, variant)
                            anch = fast_crib_score(pt_nums)

                            if anch > NOISE_FLOOR:
                                free = fast_free_crib_score(pt_nums)
                                best_sc = max(anch, free)
                                key_word = "".join(ALPH[k] for k in key5)
                                pt_str = "".join(chr(n+65) for n in pt_nums)
                                bean = fast_bean_check(key5)
                                ic_val = ic(pt_str)
                                hits.append((best_sc, pt_str, key_word, anch, free, bean, ic_val))
                            else:
                                free = fast_free_crib_score(pt_nums)
                                if free > NOISE_FLOOR:
                                    best_sc = free
                                    key_word = "".join(ALPH[k] for k in key5)
                                    pt_str = "".join(chr(n+65) for n in pt_nums)
                                    bean = fast_bean_check(key5)
                                    ic_val = ic(pt_str)
                                    hits.append((best_sc, pt_str, key_word, anch, free, bean, ic_val))

                            tested += 1

            # Progress update every 26^4 keys
            if (k0 + 1) % 5 == 0:
                elapsed = time.time() - t0
                pct = (k0+1) / 26 * 100
                print(f"  {vname}: {pct:.0f}% done ({tested:,} tested, "
                      f"{len(hits)} hits, {elapsed:.1f}s)")

        elapsed = time.time() - t0
        hits.sort(key=lambda x: -x[0])

        print(f"\n  {vname}: DONE in {elapsed:.1f}s")
        print(f"  Total hits above noise: {len(hits)}")

        # Separate by Bean pass/fail
        bean_pass = [h for h in hits if h[5]]
        bean_fail = [h for h in hits if not h[5]]
        print(f"  Bean PASS: {len(bean_pass)}, Bean FAIL: {len(bean_fail)}")

        if bean_pass:
            print(f"\n  Bean-PASSING hits (top 20):")
            for i, (sc, pt, kw, anch, free, bean, ic_val) in enumerate(bean_pass[:20]):
                print(f"    {i+1:3d}. score={sc:2d} (a={anch},f={free}) key={kw} "
                      f"IC={ic_val:.4f} Bean=PASS")
                print(f"         PT: {pt[:65]}...")

        print(f"\n  All hits (top 20, regardless of Bean):")
        for i, (sc, pt, kw, anch, free, bean, ic_val) in enumerate(hits[:20]):
            print(f"    {i+1:3d}. score={sc:2d} (a={anch},f={free}) key={kw} "
                  f"IC={ic_val:.4f} Bean={'PASS' if bean else 'FAIL'}")
            print(f"         PT: {pt[:65]}...")

        # Score distribution
        score_dist = Counter(h[0] for h in hits)
        print(f"\n  Score distribution: {dict(sorted(score_dist.items(), reverse=True))}")
        print()


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS 5: Mod-5 Transposition (Stream Reinterleaving)
# ═══════════════════════════════════════════════════════════════════════════════

def analysis_5():
    print("=" * 80)
    print("ANALYSIS 5: Mod-5 Transposition (Stream Reinterleaving)")
    print("=" * 80)
    print()

    # Extract 5 streams from CT
    streams = [[] for _ in range(PERIOD)]
    for i, ch in enumerate(CT):
        streams[i % PERIOD].append(ch)

    print(f"Stream lengths: {[len(s) for s in streams]}")
    # 97/5 = 19 remainder 2, so classes 0,1 have 20 chars, classes 2,3,4 have 19

    best_results = []
    total = 0

    for perm in itertools.permutations(range(PERIOD)):
        # Reinterleave: position i gets from stream perm[i%5], in order
        # Build stream iterators
        iters = [iter(streams[p]) for p in perm]
        reinterleaved = []
        for i in range(CT_LEN):
            r = i % PERIOD
            try:
                ch = next(iters[r])
                reinterleaved.append(ch)
            except StopIteration:
                reinterleaved.append('X')
        ri_text = "".join(reinterleaved)

        # Raw check
        anch = score_cribs(ri_text)
        free = score_free_fast(ri_text)
        best_sc = max(anch, free)
        total += 1
        if best_sc > NOISE_FLOOR:
            best_results.append((best_sc, ri_text[:60], f"reinterleave({perm})+raw", f"a={anch},f={free}"))

        # Decrypt with each keyword/variant
        for keyword in KEYWORDS:
            for variant in VARIANTS:
                pt = decrypt_with_keyword(ri_text, keyword, variant)
                anch = score_cribs(pt)
                free = score_free_fast(pt)
                best_sc = max(anch, free)
                total += 1
                if best_sc > NOISE_FLOOR:
                    method = f"reinterleave({perm})+{keyword}+{VARIANT_NAMES[variant]}"
                    best_results.append((best_sc, pt[:60], method, f"a={anch},f={free}"))

    best_results.sort(key=lambda x: -x[0])
    print(f"\nTested: {total}, Hits above noise: {len(best_results)}")
    if best_results:
        print("\nTop 20:")
        for i, (sc, pt, method, det) in enumerate(best_results[:20]):
            print(f"  {i+1:3d}. score={sc:2d} {det}  {method}")
            print(f"       PT: {pt}...")
    else:
        print("  None above noise floor.")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS 6: Mod-5 Keystream Pattern Report (Bean E0d Core)
# ═══════════════════════════════════════════════════════════════════════════════

def analysis_6():
    print("=" * 80)
    print("ANALYSIS 6: Mod-5 Keystream Pattern Report (Bean E0d Core)")
    print("=" * 80)
    print()

    # ── 6A: Keystream values at crib positions, grouped by pos mod 5 ────────

    print("6A: Vigenere keystream at crib positions, grouped by pos mod 5:")
    vig_ks = {}
    for i, kv in enumerate(VIGENERE_KEY_ENE):
        vig_ks[21 + i] = kv
    for i, kv in enumerate(VIGENERE_KEY_BC):
        vig_ks[63 + i] = kv

    for r in range(5):
        entries = [(pos, kv) for pos, kv in sorted(vig_ks.items()) if pos % 5 == r]
        k_vals = [kv for _, kv in entries]
        k_mod5 = [kv % 5 for kv in k_vals]
        k_letters = [ALPH[kv] for kv in k_vals]
        print(f"  r={r}: k_vals={k_vals}, k_mod5={k_mod5}, letters={k_letters}")
        if len(set(k_mod5)) == 1 and len(k_mod5) > 1:
            print(f"    *** ALL k mod 5 = {k_mod5[0]} for this residue class! ***")

    print()

    print("6B: Beaufort keystream at crib positions, grouped by pos mod 5:")
    beau_ks = {}
    for i, kv in enumerate(BEAUFORT_KEY_ENE):
        beau_ks[21 + i] = kv
    for i, kv in enumerate(BEAUFORT_KEY_BC):
        beau_ks[63 + i] = kv

    for r in range(5):
        entries = [(pos, kv) for pos, kv in sorted(beau_ks.items()) if pos % 5 == r]
        k_vals = [kv for _, kv in entries]
        k_mod5 = [kv % 5 for kv in k_vals]
        k_letters = [ALPH[kv] for kv in k_vals]
        print(f"  r={r}: k_vals={k_vals}, k_mod5={k_mod5}, letters={k_letters}")
        if len(set(k_mod5)) == 1 and len(k_mod5) > 1:
            print(f"    *** ALL k mod 5 = {k_mod5[0]} for this residue class! ***")

    print()

    # ── 6C: Check ALL mod-d patterns for d=2..13 ────────────────────────────
    print("6C: Keystream mod-d consistency check (Vig) for d=2..13:")
    print("     For each d, group crib positions by pos%d. Within each group,")
    print("     check if k%d is constant. Count consistent groups.")
    print()

    for d in range(2, 14):
        groups = {r: [] for r in range(d)}
        for pos, kv in sorted(vig_ks.items()):
            groups[pos % d].append(kv % d)

        n_consistent = 0
        n_total = 0
        for r in range(d):
            vals = groups[r]
            if len(vals) > 1:
                n_total += 1
                if len(set(vals)) == 1:
                    n_consistent += 1

        print(f"  d={d:2d}: {n_consistent}/{n_total} groups have constant k%d")

        # Expected by chance
        if n_total > 0:
            # Probability that n random values are all equal mod d = (1/d)^(n-1) per group
            # But this is a rough estimate
            pass

    print()

    # ── 6D: W positions ─────────────────────────────────────────────────────
    print("6D: W positions in K4:")
    w_pos = [i for i, c in enumerate(CT) if c == 'W']
    w_res = [i % 5 for i in w_pos]
    print(f"  Positions: {w_pos}")
    print(f"  Residues mod 5: {w_res}")
    print(f"  All different residues: {len(set(w_res)) == 5}")
    print()

    # ── 6E: DYARO letter positions ──────────────────────────────────────────
    print("6E: DYARO raised letter positions:")
    for letter in "DYARO":
        positions = [i for i, c in enumerate(CT) if c == letter]
        residues = [i % 5 for i in positions]
        print(f"  {letter}: positions={positions}, residues_mod5={residues}")
    print()

    # ── 6F: Difference patterns in keystream ─────────────────────────────────
    print("6F: Consecutive differences in Vigenere keystream (sorted by pos):")
    sorted_ks = sorted(vig_ks.items())
    diffs = []
    for i in range(len(sorted_ks) - 1):
        pos1, k1 = sorted_ks[i]
        pos2, k2 = sorted_ks[i+1]
        d = (k2 - k1) % 26
        diffs.append(d)
        print(f"  pos {pos1:2d}->pos {pos2:2d} (gap={pos2-pos1}): "
              f"k={k1:2d}->{k2:2d}, diff={d:2d} (mod26), diff%5={d%5}")

    diff_mod5 = [d % 5 for d in diffs]
    print(f"\n  Differences mod 5: {diff_mod5}")
    print(f"  Counter: {dict(Counter(diff_mod5))}")
    print()

    # ── 6G: Stehle's delta-4 observation ─────────────────────────────────────
    print("6G: Stehle's delta-4 = 5 observation:")
    print("  Computing 4th finite differences of Vigenere keystream at crib positions...")
    ks_vals = [k for _, k in sorted_ks]
    # 1st differences
    d1 = [(ks_vals[i+1] - ks_vals[i]) % 26 for i in range(len(ks_vals)-1)]
    d2 = [(d1[i+1] - d1[i]) % 26 for i in range(len(d1)-1)]
    d3 = [(d2[i+1] - d2[i]) % 26 for i in range(len(d2)-1)]
    d4 = [(d3[i+1] - d3[i]) % 26 for i in range(len(d3)-1)]

    print(f"  k values (sorted by pos): {ks_vals}")
    print(f"  d1: {d1}")
    print(f"  d2: {d2}")
    print(f"  d3: {d3}")
    print(f"  d4: {d4}")

    d4_mod5 = [d % 5 for d in d4]
    print(f"  d4 mod 5: {d4_mod5}")
    n_fives = sum(1 for d in d4 if d == 5)
    n_div5 = sum(1 for d in d4 if d % 5 == 0)
    print(f"  Count d4==5: {n_fives}/{len(d4)}")
    print(f"  Count d4 divisible by 5: {n_div5}/{len(d4)}")
    print()

    # ── 6H: Berlin Clock time encoding connection ──────────────────────────
    print("6H: Berlin Clock connection:")
    print("  The Berlin Clock (Mengenlehreuhr) encodes time in base 5:")
    print("    Row 1: 5-hour blocks")
    print("    Row 2: 1-hour blocks")
    print("    Row 3: 5-minute blocks")
    print("    Row 4: 1-minute blocks")
    print()
    print("  If key values represent time in Berlin Clock format,")
    print("  then k values should decompose into 5*a + b form:")
    print()
    for pos, kv in sorted(vig_ks.items()):
        a, b = divmod(kv, 5)
        print(f"    pos={pos:2d}: k={kv:2d} = 5*{a} + {b}  ({ALPH[kv]})")
    print()

    # Check if the (5*a, b) pattern repeats with period 5
    print("  Grouping (a, b) = (k//5, k%5) by position mod 5:")
    for r in range(5):
        entries = [(pos, kv) for pos, kv in sorted(vig_ks.items()) if pos % 5 == r]
        a_vals = [kv // 5 for _, kv in entries]
        b_vals = [kv % 5 for _, kv in entries]
        print(f"    r={r}: a={a_vals}, b={b_vals}")
        if len(set(b_vals)) == 1 and len(b_vals) > 1:
            print(f"      *** b is constant = {b_vals[0]} ***")
        if len(set(a_vals)) == 1 and len(a_vals) > 1:
            print(f"      *** a is constant = {a_vals[0]} ***")
    print()

    # ── 6I: Comprehensive mod-d pattern probability ─────────────────────────
    print("6I: Pattern rarity analysis:")
    print("  For each modulus d, compute # of within-group collisions in k%d")
    print("  and compare to random expectation.")
    print()

    for cipher_name, ks_data in [("Vigenere", vig_ks), ("Beaufort", beau_ks)]:
        print(f"  --- {cipher_name} ---")
        for d in [2, 3, 4, 5, 6, 7, 8, 10, 13]:
            groups = {r: [] for r in range(d)}
            for pos, kv in sorted(ks_data.items()):
                groups[pos % d].append(kv % d)

            # Count total pairs that match within groups
            total_pairs = 0
            matching_pairs = 0
            for r in range(d):
                vals = groups[r]
                n = len(vals)
                for i in range(n):
                    for j in range(i+1, n):
                        total_pairs += 1
                        if vals[i] == vals[j]:
                            matching_pairs += 1

            if total_pairs > 0:
                observed = matching_pairs / total_pairs
                expected = 1.0 / d
                ratio = observed / expected if expected > 0 else 0
                print(f"    d={d:2d}: {matching_pairs}/{total_pairs} pairs match "
                      f"({observed:.3f}, expected {expected:.3f}, ratio={ratio:.2f})")
        print()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80)
    print("COMPREHENSIVE MOD-5 PATTERN ANALYSIS -- Bean E0d Exploration")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print("=" * 80)
    print()

    t_start = time.time()

    analysis_1()
    analysis_2()
    analysis_3()
    analysis_4()
    analysis_5()
    analysis_6()

    elapsed = time.time() - t_start
    print("=" * 80)
    print(f"MOD-5 ANALYSIS COMPLETE. Total time: {elapsed:.1f}s")
    print("=" * 80)


if __name__ == "__main__":
    main()
