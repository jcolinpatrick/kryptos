#!/usr/bin/env python3
"""
Cipher: running key
Family: tableau
Status: exhausted
Keyspace: see implementation
Last run:
Best score:
"""
"""E-AUDIT-07: Exhaustive K3-as-running-key test for K4 decryption.

Motivation: Antipodes sculpture orders K3->K4, suggesting K3's output
may feed into K4 as a running key.

Tests:
  1. Vigenere: PT = (CT - KEY) mod 26
  2. Beaufort: PT = (KEY - CT) mod 26
  3. Variant Beaufort: PT = (CT + KEY) mod 26
  4. All offsets within each key source (with wrapping)
  5. K3 plaintext reversed as key
  6. K3 ciphertext as key (forward + reversed)
  7. Both AZ and KA alphabets

Scoring: count crib position matches (24 = breakthrough).

Usage: PYTHONPATH=src python3 -u scripts/e_audit_07_k3_running_key.py
"""
import time
from collections import defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)

# ── K3 Plaintext (canonical, from Howard Carter / Kryptos sculpture) ──
# Includes Sanborn's deliberate misspelling "DESPARATLY" and extra "I" in IINSERTED
K3_PT_RAW = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBRIS"
    "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVED"
    "WITHTREMB LINGHANDSIMADETINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENW IDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHIN EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)

# Note: some versions have "OFPASSAGEDEBRIS" vs "OFJPASSAGEDEBRIS"
# The 'J' appears in some K3 decryptions. Let's also try without J.
K3_PT_ALT_RAW = K3_PT_RAW.replace("OFJPASSAGEDEBRIS", "OFPASSAGEDEBRIS")

# ── K3 Ciphertext (canonical, 336 characters from Kryptos sculpture) ──
K3_CT_RAW = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# Also have an alternate K3 CT transcription (shorter, from dragnet_v3)
K3_CT_ALT_RAW = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETP"
    "EOCASDAHSATLHCTICEUEAAHTDSTTHLNHASEEHPIEAHTTSHNEDRNMIAHTTDGKTA"
    "EWJRVIKNLERAHSEJKDWKNLCGLPRHNSIEKNLTEPKAEORNDSITKNDDPNKAHNTQK"
)


def clean(s):
    """Uppercase, letters only."""
    return ''.join(c for c in s.upper() if c.isalpha())


def make_idx(alphabet):
    return {c: i for i, c in enumerate(alphabet)}


# ── Cleaned key sources ──
K3_PT = clean(K3_PT_RAW)
K3_PT_ALT = clean(K3_PT_ALT_RAW)
K3_CT_FULL = clean(K3_CT_RAW)
K3_CT_ALT = clean(K3_CT_ALT_RAW)

KEY_SOURCES = {
    "K3_PT": K3_PT,
    "K3_PT_rev": K3_PT[::-1],
    "K3_PT_alt": K3_PT_ALT,
    "K3_PT_alt_rev": K3_PT_ALT[::-1],
    "K3_CT": K3_CT_FULL,
    "K3_CT_rev": K3_CT_FULL[::-1],
    "K3_CT_alt": K3_CT_ALT,
    "K3_CT_alt_rev": K3_CT_ALT[::-1],
}

# ── Cipher variant functions ──
# All operate on numeric arrays (0-25)

def vig_decrypt(ct_num, key_num):
    """Vigenere: PT = (CT - KEY) mod 26"""
    return [(c - k) % MOD for c, k in zip(ct_num, key_num)]


def beau_decrypt(ct_num, key_num):
    """Beaufort: PT = (KEY - CT) mod 26"""
    return [(k - c) % MOD for c, k in zip(ct_num, key_num)]


def vbeau_decrypt(ct_num, key_num):
    """Variant Beaufort: PT = (CT + KEY) mod 26"""
    return [(c + k) % MOD for c, k in zip(ct_num, key_num)]


VARIANTS = {
    "Vigenere": vig_decrypt,
    "Beaufort": beau_decrypt,
    "VarBeaufort": vbeau_decrypt,
}

ALPHABETS = {
    "AZ": (ALPH, make_idx(ALPH)),
    "KA": (KRYPTOS_ALPHABET, make_idx(KRYPTOS_ALPHABET)),
}

# ── Scoring ──

def score_cribs(pt_num, alph_idx):
    """Count matching crib positions."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        expected = alph_idx[ch]
        if pos < len(pt_num) and pt_num[pos] == expected:
            matches += 1
    return matches


def check_bean(pt_num, ct_num, alph_idx, variant_fn_name):
    """Check Bean constraints. Returns (eq_pass, ineq_pass, ineq_count)."""
    # Compute keystream at all positions
    # We need to derive k[i] consistently with the variant
    key_vals = {}
    for pos in range(len(pt_num)):
        c = ct_num[pos]
        p = pt_num[pos]
        if variant_fn_name == "Vigenere":
            # PT = (CT - K) => K = (CT - PT)
            key_vals[pos] = (c - p) % MOD
        elif variant_fn_name == "Beaufort":
            # PT = (K - CT) => K = (PT + CT)
            key_vals[pos] = (p + c) % MOD
        elif variant_fn_name == "VarBeaufort":
            # PT = (CT + K) => K = (PT - CT)
            key_vals[pos] = (p - c) % MOD

    # Check equality
    eq_pass = True
    for a, b in BEAN_EQ:
        if a in key_vals and b in key_vals:
            if key_vals[a] != key_vals[b]:
                eq_pass = False
                break

    # Check inequalities
    ineq_pass = 0
    ineq_total = 0
    for a, b in BEAN_INEQ:
        if a in key_vals and b in key_vals:
            ineq_total += 1
            if key_vals[a] != key_vals[b]:
                ineq_pass += 1

    return eq_pass, ineq_pass, ineq_total


def get_wrapped_key(src_num, offset, length):
    """Extract key of given length from src starting at offset, wrapping if needed."""
    src_len = len(src_num)
    result = []
    for i in range(length):
        result.append(src_num[(offset + i) % src_len])
    return result


# ── Attack ──

def attack(ciphertext, **params):
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    ct_len = len(ciphertext)
    all_results = []

    for alph_name, (alphabet, aidx) in ALPHABETS.items():
        ct_num = [aidx[c] for c in ciphertext]

        for src_name, src_text in KEY_SOURCES.items():
            try:
                src_num = [aidx[c] for c in src_text]
            except KeyError:
                continue

            src_len = len(src_num)

            for variant_name, decrypt_fn in VARIANTS.items():
                for offset in range(src_len):
                    key_num = get_wrapped_key(src_num, offset, ct_len)
                    pt_num = decrypt_fn(ct_num, key_num)
                    score = score_cribs(pt_num, aidx)

                    if score >= 3:
                        pt_text = ''.join(alphabet[x] for x in pt_num)
                        eq_pass, ineq_pass, ineq_total = check_bean(
                            pt_num, ct_num, aidx, variant_name
                        )
                        method = (f"{alph_name}/{src_name}/{variant_name} "
                                  f"offset={offset} "
                                  f"bean_eq={'PASS' if eq_pass else 'FAIL'} "
                                  f"bean_ineq={ineq_pass}/{ineq_total}")
                        all_results.append((float(score), pt_text, method))

    # Sort by score descending
    all_results.sort(key=lambda r: r[0], reverse=True)
    return all_results


# ── Main ──

def main():
    print("=" * 78)
    print("E-AUDIT-07: K3 as Running Key for K4 — Exhaustive Test")
    print("=" * 78)
    print()
    print(f"K4 CT: {CT} ({CT_LEN} chars)")
    print(f"Cribs: {N_CRIBS} positions (21-33=EASTNORTHEAST, 63-73=BERLINCLOCK)")
    print()
    print("Key sources:")
    for name, src in KEY_SOURCES.items():
        print(f"  {name}: {len(src)} chars")
    print()
    print(f"Variants: {list(VARIANTS.keys())}")
    print(f"Alphabets: {list(ALPHABETS.keys())}")
    print()

    t0 = time.time()

    results = attack(CT)

    elapsed = time.time() - t0

    # Count total tests for reporting
    total_tests = 0
    for alph_name, (alphabet, aidx) in ALPHABETS.items():
        for src_name, src_text in KEY_SOURCES.items():
            try:
                [aidx[c] for c in src_text]
            except KeyError:
                continue
            total_tests += len(src_text) * len(VARIANTS)

    # ── Top 10 ──
    top_n = results[:10]

    print()
    print("=" * 78)
    print(f"TOP 10 RESULTS (out of {total_tests:,} tested, {elapsed:.2f}s)")
    print("=" * 78)

    for rank, (score, pt, method) in enumerate(top_n, 1):
        print(f"\n  #{rank}: Score {score:.0f}/{N_CRIBS}")
        print(f"    {method}")
        print(f"    PT: {pt}")
        print(f"    PT[21:34]: {pt[21:34]}  (want: EASTNORTHEAST)")
        print(f"    PT[63:74]: {pt[63:74]}  (want: BERLINCLOCK)")

    # ── Score distribution ──
    print()
    print("-" * 78)
    print("SCORE DISTRIBUTION:")
    score_counts = defaultdict(int)
    for s, _, _ in results:
        score_counts[int(s)] += 1
    zero_count = total_tests - sum(score_counts.values())
    print(f"  Score 0-2: {zero_count:,} (not individually stored)")
    for s in sorted(score_counts.keys()):
        label = ""
        if s >= BREAKTHROUGH_THRESHOLD:
            label = " *** BREAKTHROUGH ***"
        elif s >= SIGNAL_THRESHOLD:
            label = " ** SIGNAL **"
        elif s >= STORE_THRESHOLD:
            label = " * STORE *"
        elif s > NOISE_FLOOR:
            label = " (above noise)"
        print(f"  Score {s}: {score_counts[s]:,}{label}")

    # ── Final verdict ──
    best_score = top_n[0][0] if top_n else 0
    print()
    print("=" * 78)
    print("VERDICT")
    print("=" * 78)
    print(f"  Total configurations: {total_tests:,}")
    print(f"  Best score: {best_score:.0f}/{N_CRIBS}")

    if best_score >= BREAKTHROUGH_THRESHOLD:
        print("  *** BREAKTHROUGH — K3 running key SOLVES K4! ***")
    elif best_score >= SIGNAL_THRESHOLD:
        print("  ** SIGNAL — warrants investigation with transposition layer **")
    elif best_score > NOISE_FLOOR:
        print(f"  Above noise ({NOISE_FLOOR}) but below signal ({SIGNAL_THRESHOLD}).")
        print("  May warrant investigation with additional transformations.")
    else:
        print(f"  NOISE. Best score {best_score:.0f} <= noise floor {NOISE_FLOOR}.")
        print("  K3 plaintext/ciphertext as direct running key: ELIMINATED.")
        print("  (Does not rule out K3 as running key WITH transposition layer.)")

    print(f"\n  Repro: PYTHONPATH=src python3 -u scripts/e_audit_07_k3_running_key.py")
    print()


if __name__ == "__main__":
    main()
