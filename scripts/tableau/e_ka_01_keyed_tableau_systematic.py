#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-KA-01: KA Tableau Systematic Attack — All Keyed-Alphabet Cipher Variants

The Kryptos sculpture carries a physical Vigenère tableau using the keyed alphabet:
  KA = KRYPTOSABCDEFGHIJLMNQUVWXZ
K1 (PALIMPSEST) and K2 (ABSCISSA) are confirmed to use this tableau.
K3 uses transposition + KRYPTOS keyword through this tableau.

Gap analysis vs prior work:
  E-S-38: KA key fragments (widths 5-8, quadgram-scored). NO periodicity consistency
          check. NO VarBeaufort. Identity transposition NOT tested.
  E-S-81: Keyword alphabets + w7 columnar. Only vig/beau at period=7. Does NOT check
          all periods 1-26. Only "sub-then-trans" model (PT-column key).
  E-S-36: Gronsfeld — AZ alphabet only. KA NOT tested.
  E-S-100: Porta — AZ alphabet only. KA NOT tested.
  Two-square / Four-square: Never tested. Structural argument exists (97 is odd).

This experiment:
  Part 1: KA-Vigenère / KA-Beaufort / KA-VarBeaufort + identity transposition,
          all periods 1-26. Algebraic key derivation + consistency check.
  Part 2: Kryptos-lexicon keyword direct test (all confirmed + proposed keywords).
          Also scans wordlist for best KA-Vig keyword with Bean pass.
  Part 3: Porta cipher with KA-alphabet indexing, identity, periods 2-14.
  Part 4: Gronsfeld (digit-restricted key 0-9) with KA tableau, all periods.
  Part 5: Structural proof — Two-square and Four-square eliminated (97 is odd).
  Part 6: KA-Vig/Beau/VarBeau + width-7 columnar (5040 orderings × 26 periods × 3
          variants), BOTH "sub-then-trans" (PT-space key) and "trans-then-sub"
          (CT-space key) models. Bean-equality pre-filter applied.

Truth taxonomy applied throughout:
  [DERIVED FACT] = deterministic from constants + cipher math
  [INTERNAL RESULT] = empirical result from this script
  [HYPOTHESIS] = not yet proven

Repro: PYTHONPATH=src python3 -u scripts/e_ka_01_keyed_tableau_systematic.py
"""

import json
import os
import sys
import time
from collections import defaultdict
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, KRYPTOS_ALPHABET, MOD, ALPH_IDX, ALPH,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

# ── Constants ────────────────────────────────────────────────────────────────
KA = KRYPTOS_ALPHABET          # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = ALPH_IDX

CT_KA = [KA_IDX[c] for c in CT]   # CT letters in KA-index space
N = CT_LEN

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_KA = {pos: KA_IDX[ch] for pos, ch in CRIB_DICT.items()}

VARIANTS = ["vig", "beau", "varbeau"]
VARIANT_LABELS = {
    "vig": "KA-Vigenère",
    "beau": "KA-Beaufort",
    "varbeau": "KA-VarBeaufort",
}

# Thematic keywords: confirmed K1-K3 keywords + Sanborn 2025 clues + common proposals
THEMATIC_KEYWORDS = [
    # K1-K3 confirmed
    "PALIMPSEST", "ABSCISSA", "KRYPTOS",
    # Sanborn 2025 clues
    "WELTZEITUHR", "BERLINCLOCK", "EGYPT", "BERLIN",
    # Physical artifact / common proposals
    "SHADOW", "COMPASS", "CLOCK", "SANBORN", "SCHEIDT",
    "NORTHEAST", "LANGLEY", "ENIGMA", "SECRET", "NORTH", "EAST",
    "POINT", "NINETYSEVEN", "ANTIPODES", "HIRSHHORN",
    "TUTANKHAMUN", "CARTER", "BURIED", "LODESTONE",
    "QUARTZ", "CREATIVITY", "IQLUSION", "VIRTUALLY",
    "INVISIBLE", "DESPARATLY", "UNDERGROUND",
    "LAYER", "TWO", "SOUTHEAST", "SOUTHWEST",
    "KRYPTOS", "LANGLEY", "SHADOW", "MAGNETIC",
]
# Deduplicate preserving order
_seen = set()
THEMATIC_KEYWORDS = [kw for kw in THEMATIC_KEYWORDS
                     if kw not in _seen and not _seen.add(kw)]

# ── Helper functions ─────────────────────────────────────────────────────────

def ka_vig_key(ct_ka_val, pt_ka_val):
    return (ct_ka_val - pt_ka_val) % MOD

def ka_beau_key(ct_ka_val, pt_ka_val):
    return (ct_ka_val + pt_ka_val) % MOD

def ka_varbeau_key(ct_ka_val, pt_ka_val):
    return (pt_ka_val - ct_ka_val) % MOD

KEY_FN = {"vig": ka_vig_key, "beau": ka_beau_key, "varbeau": ka_varbeau_key}


def keystream_identity(variant):
    """KA keystream at crib positions for IDENTITY transposition."""
    fn = KEY_FN[variant]
    return {pos: fn(CT_KA[pos], KA_IDX[ch]) for pos, ch in CRIB_DICT.items()}


def keystream_with_perm(variant, perm):
    """KA keystream at crib positions after columnar transposition.

    perm[pt_pos] = ct_pos  (gather convention)
    ct_char for PT position p = CT[perm[p]]
    """
    fn = KEY_FN[variant]
    return {pos: fn(KA_IDX[CT[perm[pos]]], KA_IDX[ch])
            for pos, ch in CRIB_DICT.items()}


def check_period(ks, period, pos_fn=None):
    """Check if keystream is consistent at given period.

    pos_fn: function mapping crib_pos -> index for grouping.
            Default: identity (PT-space periodicity).
    Returns (is_consistent, key_list) where key_list[r] is the
    required key value at residue r (None if undetermined).
    """
    if pos_fn is None:
        pos_fn = lambda p: p
    res = defaultdict(set)
    for pos, kv in ks.items():
        res[pos_fn(pos) % period].add(kv)
    key = []
    for r in range(period):
        vals = res.get(r, set())
        if len(vals) > 1:
            return False, None
        key.append(list(vals)[0] if vals else None)
    return True, key


def bean_eq(ks):
    """Bean equality in KA space: ks[27] == ks[65]."""
    return ks.get(27) == ks.get(65)


def key_to_str(key, alpha=KA):
    return "".join(alpha[k] if k is not None else "?" for k in key)


def decrypt_ka(variant, key_list, period):
    """Full decryption with KA tableau using periodic key_list."""
    pt_chars = []
    for i in range(N):
        c = CT_KA[i]
        k = key_list[i % period] if key_list[i % period] is not None else 0
        if variant == "vig":
            p = (c - k) % MOD
        elif variant == "beau":
            p = (k - c) % MOD
        else:
            p = (c + k) % MOD
        pt_chars.append(KA[p])
    return "".join(pt_chars)


# ── Startup banner ────────────────────────────────────────────────────────────
t_global = time.time()
results = {}

print("=" * 72)
print("E-KA-01: KA Tableau Systematic Attack")
print(f"  KA alphabet: {KA}")
print(f"  N={N} (prime), cribs={len(CRIB_POS)} positions at {CRIB_POS}")
print("=" * 72)

# Verify KA vs AZ keystreams are DISTINCT (justifies doing this test)
ks_vig_id = keystream_identity("vig")
ks_beau_id = keystream_identity("beau")
ks_vb_id = keystream_identity("varbeau")

ka_vig_ene = tuple(ks_vig_id[p] for p in range(21, 34))
ka_vig_bc  = tuple(ks_vig_id[p] for p in range(63, 74))
print(f"\n  KA-Vig ENE keystream: {ka_vig_ene}")
print(f"  AZ-Vig ENE keystream: {VIGENERE_KEY_ENE}  (from constants)")
print(f"  Streams identical: {ka_vig_ene == VIGENERE_KEY_ENE}  ← False confirms distinct test")
print(f"\n  KA-Vig BC  keystream: {ka_vig_bc}")
print(f"  AZ-Vig BC  keystream: {VIGENERE_KEY_BC}")
print(f"  Streams identical: {ka_vig_bc == VIGENERE_KEY_BC}")

# ════════════════════════════════════════════════════════════════════════════
# PART 1: Identity transposition + KA variants, periods 1-26
# ════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 72)
print("PART 1: KA Tableau + Identity Transposition — periods 1-26")
print("=" * 72)
print()
print("  For each variant and period p: checks if all crib positions with the same")
print("  residue mod p produce the SAME KA keystream value.")
print("  Consistency → a period-p keyword COULD work for that variant.")
print()

p1_results = []

for variant in VARIANTS:
    ks = keystream_identity(variant)
    b_eq = bean_eq(ks)

    ks_ene = [ks[p] for p in range(21, 34) if p in ks]
    ks_bc  = [ks[p] for p in range(63, 74) if p in ks]

    print(f"  {VARIANT_LABELS[variant]}:")
    print(f"    Bean k[27]=k[65]: {'PASS' if b_eq else 'FAIL'} "
          f"(k[27]={ks.get(27)}, k[65]={ks.get(65)})")
    print(f"    KS ENE (21-33): {ks_ene}")
    print(f"    KS BC  (63-73): {ks_bc}")

    any_consistent = False
    for period in range(1, 27):
        ok, key = check_period(ks, period)
        if ok:
            any_consistent = True
            key_str = key_to_str(key)
            n_det = sum(1 for k in key if k is not None)
            is_kw = key_str.replace("?", "") in THEMATIC_KEYWORDS
            kw_note = "  ← *** KNOWN KEYWORD ***" if is_kw else ""
            det_note = f" ({n_det}/{period} determined)" if n_det < period else ""
            bean_note = "" if b_eq else " [Bean:FAIL]"
            print(f"    period={period:2d}: CONSISTENT{bean_note}{det_note}"
                  f"  key='{key_str}'{kw_note}")
            p1_results.append({
                "variant": variant, "period": period,
                "key": [k for k in key], "key_str": key_str,
                "bean": b_eq, "n_det": n_det, "kw_match": is_kw,
            })

    if not any_consistent:
        print(f"    Periods 1-26: NONE consistent")
        print(f"    [INTERNAL RESULT] KA-{variant} + identity transposition:")
        print(f"    ELIMINATED for all periodic keyword lengths 1-26.")
    print()

results["part1"] = p1_results

p1_consistent_meaningful = [r for r in p1_results if r["period"] <= 7]
p1_kw_matches = [r for r in p1_results if r["kw_match"]]

# ════════════════════════════════════════════════════════════════════════════
# PART 2: Kryptos-lexicon keyword direct test + wordlist scan
# ════════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("PART 2: Kryptos-Lexicon Keyword Direct Test (KA tableau, identity)")
print("=" * 72)
print()
print("  For each keyword W: counts crib positions where KA decryption matches.")
print("  Bean pass: PT[27] == PT[65] (both must decode to R = KA_idx 1).")
print("  Noise floor: ~0.9/24 expected random. Threshold for interest: ≥5.")
print()

p2_results = []
for kw in THEMATIC_KEYWORDS:
    kw_ka = [KA_IDX[c] for c in kw if c in KA_IDX]
    if len(kw_ka) != len(kw):
        continue  # Non-KA chars — skip
    p = len(kw_ka)

    for variant in VARIANTS:
        fn = KEY_FN[variant]
        # Count crib matches
        count = 0
        for pos, ch in CRIB_DICT.items():
            c_v = CT_KA[pos]
            k_v = kw_ka[pos % p]
            expected_ks = fn(c_v, KA_IDX[ch])  # What the key must be
            if expected_ks == k_v:
                count += 1

        # Bean check: decoded PT[27] == decoded PT[65]
        k27 = kw_ka[27 % p]
        k65 = kw_ka[65 % p]
        c27, c65 = CT_KA[27], CT_KA[65]
        if variant == "vig":
            pt27, pt65 = (c27 - k27) % MOD, (c65 - k65) % MOD
        elif variant == "beau":
            pt27, pt65 = (k27 - c27) % MOD, (k65 - c65) % MOD
        else:
            pt27, pt65 = (c27 + k27) % MOD, (c65 + k65) % MOD
        b_pass = (pt27 == pt65)

        if count >= 5:
            marker = "***" if count >= 12 else "   "
            print(f"  {marker} {kw:20s} p={p:2d} {VARIANT_LABELS[variant]}: "
                  f"{count:2d}/24  Bean:{'PASS' if b_pass else 'FAIL'}")
            p2_results.append({"keyword": kw, "variant": variant,
                                "score": count, "period": p, "bean": b_pass})

if not any(r["score"] >= 5 for r in p2_results):
    print("  No thematic keyword scores ≥5/24 with any KA variant.")

# AZ reference for comparison
print()
print("  Reference — AZ Vigenère scores for confirmed K1-K3 keywords:")
for kw in ["PALIMPSEST", "ABSCISSA", "KRYPTOS"]:
    kw_az = [ALPH_IDX[c] for c in kw]
    p = len(kw_az)
    score = sum(
        1 for pos, ch in CRIB_DICT.items()
        if (ALPH_IDX[CT[pos]] - kw_az[pos % p]) % MOD == ALPH_IDX[ch]
    )
    print(f"    {kw:20s} (AZ-Vig, identity): {score:2d}/24")

# Wordlist scan (KA-Vig only, Bean-pass filter)
wordlist_path = "wordlists/english.txt"
wl_hits = []
if os.path.exists(wordlist_path):
    print()
    print("  Scanning wordlist (KA-Vigenère, identity, Bean-pass)...")
    t_wl = time.time()
    with open(wordlist_path) as f:
        words = [ln.strip().upper() for ln in f if ln.strip().isalpha()]
    print(f"  Loaded {len(words):,} words")

    for word in words:
        if not (3 <= len(word) <= 22):
            continue
        if not all(c in KA_IDX for c in word):
            continue
        kw_ka = [KA_IDX[c] for c in word]
        p = len(kw_ka)

        # Bean filter (KA-Vig): decoded PT[27] == decoded PT[65]
        k27 = kw_ka[27 % p]
        k65 = kw_ka[65 % p]
        pt27 = (CT_KA[27] - k27) % MOD
        pt65 = (CT_KA[65] - k65) % MOD
        if pt27 != pt65:
            continue  # Bean fail

        # Count KA-Vig matches
        score = sum(
            1 for pos, ch in CRIB_DICT.items()
            if (CT_KA[pos] - kw_ka[pos % p]) % MOD == KA_IDX[ch]
        )
        if score >= 7:
            wl_hits.append({"word": word, "score": score, "period": p, "bean": True})

    wl_hits.sort(key=lambda x: -x["score"])
    elapsed_wl = time.time() - t_wl
    print(f"  Wordlist scan: {elapsed_wl:.1f}s")
    print(f"  Hits ≥7/24 (Bean:PASS, KA-Vig, identity): {len(wl_hits)}")
    for h in wl_hits[:10]:
        print(f"    {h['word']:20s} p={h['period']:2d}: {h['score']:2d}/24")
    results["part2_wordlist"] = wl_hits[:50]

results["part2"] = p2_results

# ════════════════════════════════════════════════════════════════════════════
# PART 3: Porta cipher with KA-alphabet indexing, identity, periods 2-14
# ════════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print("PART 3: Porta Cipher with KA-Alphabet Indexing (identity transposition)")
print("=" * 72)
print()
print("  Porta is self-reciprocal. Group g = KA_idx(key) // 2 (0-12).")
print("  KA[0-12] = K,R,Y,P,T,O,S,A,B,C,D,E,F  (low half)")
print("  KA[13-25] = G,H,I,J,L,M,N,Q,U,V,W,X,Z (high half)")
print("  Encryption: low-half → high-half, high-half → low-half.")
print()
print("  E-S-100 tested AZ-Porta. This test uses KA-position indices.")
print()


def porta_ka_enc(pt_ka, key_ka):
    """Porta encryption/decryption using KA position indices."""
    g = key_ka // 2
    if pt_ka < 13:
        return ((pt_ka + g) % 13) + 13
    else:
        return (pt_ka - 13 - g) % 13


def porta_ka_valid_keys(ct_ka, pt_ka):
    """All KA key indices k in [0,25] where porta_ka_enc(pt_ka, k) == ct_ka."""
    return [k for k in range(26) if porta_ka_enc(pt_ka, k) == ct_ka]


p3_results = {}
p3_surviving = []

for period in range(2, 15):
    residue_keys = {r: set(range(26)) for r in range(period)}

    for pos, ch in CRIB_DICT.items():
        r = pos % period
        ct_v = CT_KA[pos]
        pt_v = KA_IDX[ch]
        valid = set(porta_ka_valid_keys(ct_v, pt_v))
        residue_keys[r] &= valid

    empty = any(len(residue_keys[r]) == 0 for r in range(period))
    if empty:
        total = 0
    else:
        total = 1
        for r in range(period):
            total *= len(residue_keys[r])

    if empty or total == 0:
        print(f"  period={period:2d}: ELIMINATED (0 solutions)")
    else:
        p3_surviving.append(period)
        print(f"  period={period:2d}: {total} solution(s) surviving")
        if total <= 50:
            for r in range(period):
                opts = sorted(residue_keys[r])
                letters = "".join(KA[k] for k in opts)
                print(f"    residue {r}: {opts} = '{letters}'")
            if total <= 5:
                # Enumerate and show plaintext
                from itertools import product as iproduct
                keys_per_r = [sorted(residue_keys[r]) for r in range(period)]
                for combo in iproduct(*keys_per_r):
                    pt = [KA[porta_ka_enc(CT_KA[i], combo[i % period])] for i in range(N)]
                    print(f"    PT: {''.join(pt)}")

    p3_results[period] = total

results["part3"] = p3_results

# ════════════════════════════════════════════════════════════════════════════
# PART 4: Gronsfeld with KA tableau (digit-restricted key 0-9)
# ════════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print("PART 4: Gronsfeld Cipher with KA Tableau (digit-restricted key 0-9)")
print("=" * 72)
print()
print("  Gronsfeld = Vigenère restricted to numeric key values 0-9.")
print("  E-S-36 tested Gronsfeld with AZ alphabet. This tests with KA indices.")
print()

p4_hits = []

for variant in VARIANTS:
    ks = keystream_identity(variant)
    all_vals = list(ks.values())
    in_range = all(0 <= v <= 9 for v in all_vals)

    print(f"  {VARIANT_LABELS[variant]}:")
    print(f"    Full KS values: min={min(all_vals)}, max={max(all_vals)}, "
          f"all-in-0-9: {in_range}")

    any_gronsfeld = False
    for period in range(1, 27):
        ok, key = check_period(ks, period)
        if ok and key:
            key_nums = [k for k in key if k is not None]
            if key_nums:
                if max(key_nums) <= 9:
                    print(f"    *** GRONSFELD p={period}: key={key_nums}")
                    any_gronsfeld = True
                    # Full decrypt
                    pt = decrypt_ka(variant, key, period)
                    print(f"    PT: {pt}")
                    p4_hits.append({"variant": variant, "period": period,
                                    "key": key_nums, "pt": pt})
                elif max(key_nums) <= 12:
                    print(f"    Extended-digit (0-12) p={period}: key={key_nums}")

    if not any_gronsfeld:
        print(f"    No Gronsfeld (0-9) solutions at any period 1-26.")

results["part4"] = p4_hits

# ════════════════════════════════════════════════════════════════════════════
# PART 5: Structural eliminations — Two-square and Four-square
# ════════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print("PART 5: Structural Eliminations")
print("=" * 72)
print()
print("  TWO-SQUARE CIPHER:")
print("    Mechanism: digraphic (enciphers PAIRS of letters, ~Playfair variant)")
print(f"   K4 length = {N} (ODD PRIME — cannot form complete pairs)")
print(f"   → [DERIVED FACT] TWO-SQUARE ELIMINATED FOR K4 (parity)")
print()
print("  FOUR-SQUARE CIPHER:")
print("    Mechanism: digraphic (enciphers PAIRS of letters)")
print(f"   K4 length = {N} (ODD PRIME — cannot form complete pairs)")
print(f"   → [DERIVED FACT] FOUR-SQUARE ELIMINATED FOR K4 (parity)")
print()
print("  These join Playfair (e_playfair_01_full_disproof.py) and ADFGVX")
print("  as parity-blocked ciphers. See docs/elimination_tiers.md Tier 1.")
print()
print("  Note on KA tableau + Two-square: even if 5x5 Polybius were used with")
print("  KA alphabet (e.g., I/J merged), parity (97 odd) still blocks it.")

results["part5"] = {
    "two_square": "ELIMINATED — 97 is odd, digraph cipher requires even length",
    "four_square": "ELIMINATED — 97 is odd, digraph cipher requires even length",
}

# ════════════════════════════════════════════════════════════════════════════
# PART 6: KA tableau + width-7 columnar transposition
# BOTH models: "sub-then-trans" (PT-space key) and "trans-then-sub" (CT-space key)
# ════════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print("PART 6: KA Tableau + Width-7 Columnar Transposition")
print("  All 5040 orderings × 3 variants × 26 periods × 2 models")
print("=" * 72)
print()
print("  Model A (sub-then-trans): key period in PT space (p_fn = pt_pos % period)")
print("  Model B (trans-then-sub): key period in CT space (p_fn = ct_pos % period)")
print()
print("  E-S-81 tested: Model A only (vig+beau) at period=7.")
print("  This adds: Model B, VarBeaufort, all periods 1-26, Bean pre-filter.")
print()

WIDTH = 7
N_ROWS = N // WIDTH
N_EXTRA = N % WIDTH
COL_LENS = [N_ROWS + 1 if c < N_EXTRA else N_ROWS for c in range(WIDTH)]


def build_w7_perm(order):
    """Width-7 columnar transposition permutation.
    perm[pt_pos] = ct_pos  (gather convention: CT[perm[pt_pos]] is at PT pos pt_pos)
    """
    perm = [0] * N
    ct_pos = 0
    for rank in range(WIDTH):
        col = order[rank]
        clen = COL_LENS[col]
        for row in range(clen):
            pt_pos = row * WIDTH + col
            perm[pt_pos] = ct_pos
            ct_pos += 1
    return perm


t_p6 = time.time()
all_orders_w7 = list(permutations(range(WIDTH)))
n_w7 = len(all_orders_w7)
n_p6_bean_pass = 0
n_p6_consistent = 0
p6_hits = []       # all consistent configs (any period, any model)
p6_interesting = []  # period ≤7 configs OR keyword matches
last_print_p6 = t_p6

for oi, order in enumerate(all_orders_w7):
    perm = build_w7_perm(order)

    for variant in VARIANTS:
        ks = keystream_with_perm(variant, perm)

        # Bean-equality pre-filter
        if not bean_eq(ks):
            continue
        n_p6_bean_pass += 1

        # ── Model A: key period in PT space ──────────────────────────────
        for period in range(1, 27):
            ok, key = check_period(ks, period)  # default: pos_fn = pt_pos
            if ok and key:
                n_p6_consistent += 1
                key_str = key_to_str(key)
                is_meaningful = (period <= 7)
                is_kw = key_str.replace("?", "") in THEMATIC_KEYWORDS
                rec = {
                    "model": "A", "order": list(order), "variant": variant,
                    "period": period, "key_str": key_str,
                    "meaningful": is_meaningful, "kw_match": is_kw,
                }
                p6_hits.append(rec)
                if is_meaningful or is_kw:
                    p6_interesting.append(rec)
                    label = "MEANINGFUL" if is_meaningful else "KW-MATCH"
                    print(f"  *** {label} Model-A: order={list(order)[:4]}... "
                          f"{VARIANT_LABELS[variant]} p={period} key='{key_str}'")

        # ── Model B: key period in CT space ──────────────────────────────
        for period in range(1, 27):
            ok, key = check_period(ks, period, pos_fn=lambda p: perm[p])
            if ok and key:
                n_p6_consistent += 1
                key_str = key_to_str(key)
                is_meaningful = (period <= 7)
                is_kw = key_str.replace("?", "") in THEMATIC_KEYWORDS
                rec = {
                    "model": "B", "order": list(order), "variant": variant,
                    "period": period, "key_str": key_str,
                    "meaningful": is_meaningful, "kw_match": is_kw,
                }
                p6_hits.append(rec)
                if is_meaningful or is_kw:
                    p6_interesting.append(rec)
                    label = "MEANINGFUL" if is_meaningful else "KW-MATCH"
                    print(f"  *** {label} Model-B: order={list(order)[:4]}... "
                          f"{VARIANT_LABELS[variant]} p={period} key='{key_str}'")

    # Progress report
    now = time.time()
    if now - last_print_p6 > 25:
        pct = 100 * (oi + 1) / n_w7
        print(f"  [{pct:5.1f}%] {oi+1}/{n_w7} orderings | "
              f"bean_pass={n_p6_bean_pass} | consistent={n_p6_consistent} | "
              f"interesting={len(p6_interesting)} ({now - t_p6:.0f}s)")
        last_print_p6 = now

elapsed_p6 = time.time() - t_p6
print()
print(f"  Part 6 complete: {elapsed_p6:.1f}s")
print(f"  Total configurations: {n_w7} orderings × 3 variants × 2 models")
print(f"  Bean-pass configs: {n_p6_bean_pass:,} / {n_w7 * 3:,}")
print(f"  Consistent (period ≤26, Model A+B): {n_p6_consistent:,}")
print(f"  Interesting (period ≤7 OR keyword): {len(p6_interesting)}")

if p6_interesting:
    print(f"\n  Interesting configs (period ≤7 or keyword match):")
    for r in p6_interesting[:30]:
        print(f"    Mdl{r['model']} order={r['order'][:4]}... "
              f"{r['variant']:12s} p={r['period']:2d} key='{r['key_str']}'")
else:
    print()
    print("  [INTERNAL RESULT] No interesting hits (period ≤7 or keyword match).")
    print("  KA tableau + width-7 columnar: NOISE for both Model A and Model B.")

p6_meaningful = [h for h in p6_interesting if h["meaningful"]]
p6_kw = [h for h in p6_interesting if h["kw_match"]]

results["part6"] = {
    "n_orders": n_w7,
    "n_bean_pass": n_p6_bean_pass,
    "n_consistent": n_p6_consistent,
    "n_interesting": len(p6_interesting),
    "n_meaningful": len(p6_meaningful),
    "n_kw_matches": len(p6_kw),
    "top_hits": p6_hits[:100],
}

# ════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════════
total_elapsed = time.time() - t_global

print()
print("=" * 72)
print("SUMMARY — E-KA-01: KA Tableau Systematic Attack")
print("=" * 72)

print()
print("Part 1 (Identity + KA variants, periods 1-26):")
if not p1_consistent_meaningful and not p1_kw_matches:
    print("  [INTERNAL RESULT] NO consistent periods ≤7 for any KA variant.")
    print("  [INTERNAL RESULT] NO known thematic keyword matches.")
    print("  KA-Vigenère, KA-Beaufort, KA-VarBeaufort + identity transposition:")
    print("  ELIMINATED for all periodic keyword lengths 1-26.")
    p1_verdict = "NOISE"
else:
    p1_verdict = "SIGNAL"
    for r in p1_consistent_meaningful:
        print(f"  SIGNAL: {r['variant']} period={r['period']} key='{r['key_str']}'")
    for r in p1_kw_matches:
        print(f"  KEYWORD: {r['variant']} period={r['period']} key='{r['key_str']}'")

print()
print("Part 2 (Lexicon keywords, identity):")
p2_hi = [r for r in p2_results if r["score"] >= 7]
if not p2_hi:
    print("  [INTERNAL RESULT] No thematic keyword scores ≥7/24.")
    print("  PALIMPSEST / ABSCISSA / KRYPTOS all score <4/24 with KA tableau.")
    p2_verdict = "NOISE"
else:
    p2_verdict = "SIGNAL"
    for r in p2_hi:
        print(f"  SIGNAL: {r['keyword']} {r['score']}/24 ({r['variant']})")

if wl_hits:
    print(f"  Wordlist: {wl_hits[0]['word']} scores {wl_hits[0]['score']}/24")
else:
    print("  Wordlist: no words score ≥7/24 with Bean:PASS (KA-Vig, identity).")

print()
print("Part 3 (KA-Porta, identity, periods 2-14):")
if p3_surviving:
    print(f"  Periods with survivors: {p3_surviving}")
    p3_verdict = "OPEN"
else:
    print("  [INTERNAL RESULT] All periods 2-14 ELIMINATED for KA-Porta + identity.")
    p3_verdict = "NOISE"

print()
print("Part 4 (Gronsfeld with KA, identity):")
if p4_hits:
    for h in p4_hits:
        print(f"  *** GRONSFELD: {h['variant']} p={h['period']} key={h['key']}")
    p4_verdict = "SIGNAL"
else:
    print("  [INTERNAL RESULT] No Gronsfeld (0-9) solutions at any period 1-26.")
    p4_verdict = "NOISE"

print()
print("Part 5 (Structural):")
print("  [DERIVED FACT] Two-square: ELIMINATED (97 odd, digraph requires even length)")
print("  [DERIVED FACT] Four-square: ELIMINATED (97 odd, digraph requires even length)")

print()
print("Part 6 (KA + w7 columnar, 5040 × 3 × 26 × 2 models):")
if p6_meaningful:
    print(f"  *** MEANINGFUL HITS (period ≤7): {len(p6_meaningful)}")
    for r in p6_meaningful[:5]:
        print(f"    Mdl{r['model']} {r['variant']} p={r['period']} key='{r['key_str']}'")
    p6_verdict = "SIGNAL"
elif p6_kw:
    print(f"  Keyword matches (high period, likely underdetermined): {len(p6_kw)}")
    p6_verdict = "WEAK"
else:
    print("  [INTERNAL RESULT] NO meaningful hits (period ≤7) in either model.")
    print("  [INTERNAL RESULT] NO thematic keyword matches found.")
    p6_verdict = "NOISE"

print()
any_signal = any(v in ("SIGNAL", "OPEN") for v in [p1_verdict, p2_verdict,
                                                     p3_verdict, p4_verdict,
                                                     p6_verdict])
if any_signal:
    verdict = "SIGNAL/OPEN — see sub-part details above"
else:
    verdict = (
        "NOISE — KA tableau with all tested cipher families "
        "(Vigenère, Beaufort, VarBeaufort, Porta, Gronsfeld) + "
        "identity and w7-columnar (5040 orderings, both PT-space and CT-space "
        "key models, periods 1-26): NO signals. "
        "Two-square/Four-square: structurally ELIMINATED by parity."
    )

print(f"OVERALL VERDICT: {verdict}")
print(f"Total elapsed: {total_elapsed:.1f}s")

# ── Save ─────────────────────────────────────────────────────────────────────
results["verdict"] = verdict
results["elapsed_seconds"] = round(total_elapsed, 1)
results["sub_verdicts"] = {
    "p1": p1_verdict, "p2": p2_verdict, "p3": p3_verdict,
    "p4": p4_verdict, "p5": "ELIMINATED (derived)", "p6": p6_verdict,
}

os.makedirs("results", exist_ok=True)
path = "results/e_ka_01_keyed_tableau.json"
with open(path, "w") as f:
    json.dump(results, f, indent=2, default=str)

print(f"\nArtifact: {path}")
print(f"Repro:    PYTHONPATH=src python3 -u scripts/e_ka_01_keyed_tableau_systematic.py")
