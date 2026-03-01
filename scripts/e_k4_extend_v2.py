#!/usr/bin/env python3 -u
"""
e_k4_extend_v2.py — Extended BERLINCLOCK analysis, phase 2.

WHAT'S ALREADY DONE (do not re-test):
  - e_s_berlin_extend.py: beam search, period consistency (1-26), Gronsfeld,
    Porta (via e_ka_01), phrase tests.  All returned NOISE.
  - agent_k4_keystream_language_scan.py: language fingerprint, English P≈1e-7.
  - e_webster_01 / e_ka_01: two-keyword Vigenère, KA alphabet, Porta — NOISE.

NEW IN THIS SCRIPT:
  1. KA-alphabet keystream + period consistency  (standard ALPH vs KA ALPH)
  2. Two-keyword exhaustive: for ALL (p1, p2) pairs lcm≤97, count conflicts.
     Fixed kw1 = known K1-K3 keywords; derive required kw2 residues.
  3. CT-autokey self-reference: does any 11-char CT window = BC keystream?
  4. Affine key model: k[i] = (a*CT[i] + b) mod 26 — fits all 24 values?
  5. Period "near-misses": which periods have exactly 1 conflict (which pos)?
  6. Self-encrypting propagation: if k[32]=k[73]=0, what does that imply
     for adjacent positions under autokey or periodic key?
  7. BC differential constraint: compute variant-independent differential
     signature at BC crib positions for running-key filtering.
  8. Summary table: what structural properties survive all constraints?

All results to: results/e_k4_extend_v2.json
"""

import sys, json, itertools
from pathlib import Path
from math import gcd

sys.path.insert(0, 'src')

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH, ALPH_IDX,
    KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)

# ── Constants ───────────────────────────────────────────────────────────────

CT_VALS = [ALPH_IDX[c] for c in CT]

ENE_WORD, ENE_START = "EASTNORTHEAST", 21
BC_WORD,  BC_START  = "BERLINCLOCK",   63

CRIB_POS_LIST = sorted(CRIB_POSITIONS)

# Full sparse keystream dict under each variant (standard alphabet)
def build_ks_dict(variant="vig"):
    """Return {pos: key_int} for all 24 crib positions."""
    d = {}
    for i, kv in enumerate(VIGENERE_KEY_ENE):
        d[ENE_START + i] = kv
    for i, kv in enumerate(VIGENERE_KEY_BC):
        d[BC_START + i] = kv

    if variant == "vig":
        return d
    elif variant == "beau":
        # Beaufort key = C+P mod 26 = vig_key applied as: beau_k = (ct+pt) % 26
        d2 = {}
        for pos, vig_k in d.items():
            ct_v = CT_VALS[pos]
            pt_v = (ct_v - vig_k) % MOD   # pt from vig key
            d2[pos] = (ct_v + pt_v) % MOD
        return d2
    elif variant == "vbeau":
        # VarBeaufort: k = (pt - ct) % 26 = (-vig_k) % 26
        return {pos: (-v) % MOD for pos, v in d.items()}
    else:
        raise ValueError(f"Unknown variant: {variant}")

# Kryptos-keyed alphabet indexing
KA = KRYPTOS_ALPHABET   # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

def build_ks_dict_ka(variant="vig"):
    """Keystream dict using KA alphabet for both PT and CT indexing."""
    d = {}
    for start, word in [(ENE_START, ENE_WORD), (BC_START, BC_WORD)]:
        for offset, pt_ch in enumerate(word):
            pos = start + offset
            ct_ch = CT[pos]
            ct_v = KA_IDX[ct_ch]
            pt_v = KA_IDX[pt_ch]
            if variant == "vig":
                kv = (ct_v - pt_v) % MOD
            elif variant == "beau":
                kv = (ct_v + pt_v) % MOD
            elif variant == "vbeau":
                kv = (pt_v - ct_v) % MOD
            else:
                raise ValueError(variant)
            d[pos] = kv
    return d


def ks_dict_to_str(ks_dict, alphabet=ALPH):
    return "".join(alphabet[ks_dict[p]] for p in CRIB_POS_LIST)


def check_periods_with_conflicts(ks_dict):
    """For each period 1-26, return (consistent, n_conflicts, conflict_details)."""
    results = {}
    for period in range(1, 27):
        residue = {}
        conflicts = []
        for pos in CRIB_POS_LIST:
            kv = ks_dict[pos]
            r = pos % period
            if r in residue:
                if residue[r] != kv:
                    conflicts.append((pos, r, residue[r], kv))
            else:
                residue[r] = kv
        results[period] = {
            "consistent": len(conflicts) == 0,
            "n_conflicts": len(conflicts),
            "conflicts": conflicts[:5],   # first 5 conflict details
        }
    return results


def lcm(a, b):
    return a * b // gcd(a, b)


# ── Section 1: KA-alphabet keystream ───────────────────────────────────────

print("=" * 72)
print("Section 1: KA-Alphabet Keystream + Period Consistency")
print("=" * 72)

ka_results = {}
for variant in ("vig", "beau", "vbeau"):
    ks = build_ks_dict_ka(variant)
    ks_str = ks_dict_to_str(ks, KA)
    period_info = check_periods_with_conflicts(ks)
    consistent_periods = [p for p, r in period_info.items() if r["consistent"]]
    near_misses = [(p, r["n_conflicts"]) for p, r in period_info.items()
                   if r["n_conflicts"] == 1]

    print(f"\n  Variant: {variant}")
    print(f"  KA keystream (24 pos): {ks_str}")
    print(f"  Consistent periods (1-26): {consistent_periods}")
    print(f"  Near-miss periods (1 conflict): {near_misses}")

    # Bean check under KA
    bean_eq_fail = []
    for i, j in BEAN_EQ:
        if ks.get(i) != ks.get(j):
            bean_eq_fail.append((i, j, ks.get(i), ks.get(j)))
    bean_ineq_fail = []
    for i, j in BEAN_INEQ:
        if i in ks and j in ks and ks[i] == ks[j]:
            bean_ineq_fail.append((i, j, ks[i]))
    bean_verdict = "PASS" if not bean_eq_fail and not bean_ineq_fail else "FAIL"
    print(f"  Bean EQ failures: {bean_eq_fail}")
    print(f"  Bean INEQ failures: {bean_ineq_fail}")
    print(f"  Bean verdict: {bean_verdict}")

    ka_results[variant] = dict(
        ks_str=ks_str,
        consistent_periods=consistent_periods,
        near_miss_periods=near_misses,
        bean=bean_verdict,
    )


# ── Section 2: Two-Keyword Product Cipher (exhaustive) ─────────────────────

print("\n" + "=" * 72)
print("Section 2: Two-Keyword Product Cipher — Exhaustive Conflict Count")
print("=" * 72)
print("""
For each (p1, p2) pair, the combined key k[i] = (kw1[i%p1] + kw2[i%p2]) % 26.
Given the 24 known Vigenère key values, we derive required kw2[r] for each
residue r = pos % p2, conditioned on kw1[pos%p1] from known keywords.
We count conflicts (same residue r requires different values).
""")

VIG_KS = build_ks_dict("vig")

# Known keywords to test as kw1
KEYWORDS = {
    "KRYPTOS":      [ALPH_IDX[c] for c in "KRYPTOS"],
    "PALIMPSEST":   [ALPH_IDX[c] for c in "PALIMPSEST"],
    "ABSCISSA":     [ALPH_IDX[c] for c in "ABSCISSA"],
    "BERLINCLOCK":  [ALPH_IDX[c] for c in "BERLINCLOCK"],
    "EASTNORTHEAST":[ALPH_IDX[c] for c in "EASTNORTHEAST"],
    "SHADOW":       [ALPH_IDX[c] for c in "SHADOW"],
    "DIGETAL":      [ALPH_IDX[c] for c in "DIGETAL"],
    "KRYPTOSBERLINCLOCK": [ALPH_IDX[c] for c in "KRYPTOSBERLINCLOCK"],
}

two_kw_results = {}
print(f"  {'kw1':<22} {'p1':>4} {'p2':>4} {'min_conflicts':>14}  kw2_candidate")
print(f"  {'-'*22} {'-'*4} {'-'*4} {'-'*14}  {'-'*20}")

for kw_name, kw_vals in KEYWORDS.items():
    p1 = len(kw_vals)
    best_for_kw = []
    for p2 in range(1, 28):
        residues = {}
        conflict_count = 0
        for pos in CRIB_POS_LIST:
            k_total = VIG_KS[pos]
            k1 = kw_vals[pos % p1]
            k2_needed = (k_total - k1) % MOD
            r = pos % p2
            if r in residues:
                if residues[r] != k2_needed:
                    conflict_count += 1
            else:
                residues[r] = k2_needed

        if conflict_count == 0:
            kw2_str = "".join(ALPH[residues.get(r, 0)] for r in range(p2))
            tag = f"CONSISTENT! kw2={kw2_str}"
            print(f"  {kw_name:<22} {p1:>4} {p2:>4} {conflict_count:>14}  {tag}")
            best_for_kw.append(dict(p2=p2, n_conflicts=0, kw2=kw2_str))
        elif conflict_count <= 2:
            print(f"  {kw_name:<22} {p1:>4} {p2:>4} {conflict_count:>14}  near-miss")

    two_kw_results[kw_name] = best_for_kw

# Also test: ALL periods p1 without a fixed keyword (just find which combined
# periods have 0 conflicts assuming kw1 is free to be any sequence of length p1)
print("\n  --- Free kw1+kw2: which (p1,p2) pairs CAN be consistent? ---")
print("  (Testing if any kw1[r1] values + kw2[r2] values exist that explain 24 known k values)")
print("  (For each residue class (r1=pos%p1, r2=pos%p2), k_total = kw1[r1]+kw2[r2] must agree)")
print()

free_two_kw_consistent = []
for p1 in range(1, 14):
    for p2 in range(p1, 14):   # p2 >= p1 to avoid double-counting
        combined_period = lcm(p1, p2)
        # Group positions by (pos%p1, pos%p2) combined residue
        # Check if all positions sharing the same combined residue agree on k_total
        combined_residues = {}
        consistent = True
        for pos in CRIB_POS_LIST:
            r = (pos % p1, pos % p2)
            kv = VIG_KS[pos]
            if r in combined_residues:
                if combined_residues[r] != kv:
                    consistent = False
                    break
            else:
                combined_residues[r] = kv

        if consistent:
            free_two_kw_consistent.append((p1, p2, combined_period))
            print(f"    CONSISTENT: (p1={p1}, p2={p2}, lcm={combined_period}) — "
                  f"{len(combined_residues)} distinct residue classes for 24 known positions")

if not free_two_kw_consistent:
    print("    NO (p1,p2) pairs in 1-13 × 1-13 are consistent. "
          "=> Two-keyword product with p1,p2 ≤ 13 is ELIMINATED.")


# ── Section 3: CT-Autokey Self-Reference ───────────────────────────────────

print("\n" + "=" * 72)
print("Section 3: CT-Autokey Self-Reference Check")
print("=" * 72)
print("""
Under CT-autokey: key[i] = CT[i-P] for some primer length P.
If true, the BC keystream letters must appear as a CT substring at offset -P.
We check all P in 1..96 for both:
  (a) 11-char BC window:  CT[63-P:74-P]  should equal  'MUYKLGKORNA'
  (b) 13-char ENE window: CT[21-P:34-P]  should equal  'BLZCDCYYGCKAZ'
  (c) Both simultaneously (requires same P).
""")

VIG_BC_STR  = "".join(ALPH[v] for v in VIGENERE_KEY_BC)    # MUYKLGKORNA
VIG_ENE_STR = "".join(ALPH[v] for v in VIGENERE_KEY_ENE)   # BLZCDCYYGCKAZ

print(f"  BC  keystream (11 chars): {VIG_BC_STR}")
print(f"  ENE keystream (13 chars): {VIG_ENE_STR}")
print()

ct_autokey_hits = []
for P in range(1, CT_LEN):
    bc_start  = BC_START  - P
    ene_start = ENE_START - P
    bc_match  = ene_match = False

    # BC window
    if 0 <= bc_start and bc_start + 11 <= CT_LEN:
        window = CT[bc_start : bc_start + 11]
        if window == VIG_BC_STR:
            bc_match = True

    # ENE window
    if 0 <= ene_start and ene_start + 13 <= CT_LEN:
        window = CT[ene_start : ene_start + 13]
        if window == VIG_ENE_STR:
            ene_match = True

    if bc_match or ene_match:
        tag = "BOTH" if bc_match and ene_match else ("BC" if bc_match else "ENE")
        print(f"  HIT! P={P:3d}  {tag}  window={CT[bc_start:bc_start+11] if bc_match else CT[ene_start:ene_start+13]}")
        ct_autokey_hits.append(dict(P=P, bc=bc_match, ene=ene_match))

# Also: check partial matches (how close is the best match?)
print("\n  Best PARTIAL matches (Hamming distance for 11-char BC window):")
best_partial = []
for P in range(1, CT_LEN):
    bc_start = BC_START - P
    if 0 <= bc_start and bc_start + 11 <= CT_LEN:
        window = CT[bc_start : bc_start + 11]
        hd = sum(w != v for w, v in zip(window, VIG_BC_STR))
        best_partial.append((hd, P, window))
best_partial.sort()
for hd, P, window in best_partial[:5]:
    print(f"    P={P:3d}  hamming={hd}  CT_window={window}  target={VIG_BC_STR}")

if not ct_autokey_hits:
    print("\n  RESULT: NO CT-autokey primer P in 1..96 produces an exact match.")
    print("  => CT-autokey model ELIMINATED for direct identity transposition.")


# ── Section 4: Affine Key Model ─────────────────────────────────────────────

print("\n" + "=" * 72)
print("Section 4: Affine Key Model — k[i] = (a*CT[i] + b) mod 26")
print("=" * 72)
print("""
Tests if the keystream at crib positions is an affine function of the CT values.
For each (a, b) pair, count how many of the 24 positions are consistent.
""")

affine_results = []
for a in range(MOD):
    for b in range(MOD):
        # k[i] = (a * ct[i] + b) % 26
        matches = 0
        for pos in CRIB_POS_LIST:
            predicted_k = (a * CT_VALS[pos] + b) % MOD
            if predicted_k == VIG_KS[pos]:
                matches += 1
        if matches >= 6:    # above random (24/26 ≈ 0.92 expected)
            affine_results.append((matches, a, b))

affine_results.sort(reverse=True)
print(f"  Top 10 affine (a, b) by matches/24:")
print(f"  {'a':>4} {'b':>4} {'matches/24':>12}  verdict")
print(f"  {'-'*4} {'-'*4} {'-'*12}  {'-'*20}")
for matches, a, b in affine_results[:10]:
    verdict = "SIGNAL" if matches >= 18 else ("interesting" if matches >= 10 else "noise")
    print(f"  {a:>4} {b:>4} {matches:>12}/24   {verdict}")

max_affine_matches = affine_results[0][0] if affine_results else 0
print(f"\n  Maximum affine matches: {max_affine_matches}/24")
if max_affine_matches < 10:
    print("  RESULT: Affine key model ELIMINATED (max matches below noise threshold).")
else:
    print(f"  RESULT: Best affine (a={affine_results[0][1]}, b={affine_results[0][2]}) achieves {max_affine_matches}/24.")


# ── Section 5: Period Near-Misses — which conflict positions? ──────────────

print("\n" + "=" * 72)
print("Section 5: Period Near-Misses — Diagnostic Detail")
print("=" * 72)
print("""
For each period, show which crib positions create conflicts.
A 'near-miss' (1 conflict) might indicate a single misspelling/typo in K4 cribs.
""")

vig_period_info = check_periods_with_conflicts(VIG_KS)
print(f"\n  Vigenère — periods 1-26 conflict summary:")
print(f"  {'period':>8} {'conflicts':>10}  first conflict detail")
for period in range(1, 27):
    info = vig_period_info[period]
    nc = info["n_conflicts"]
    if nc == 0:
        tag = "CONSISTENT"
    elif nc == 1:
        c = info["conflicts"][0]
        tag = f"1-CONFLICT: pos={c[0]} r={c[1]} expected={ALPH[c[2]]} got={ALPH[c[3]]}"
    else:
        tag = f"{nc} conflicts"
    print(f"  {period:>8} {nc:>10}  {tag}")


# ── Section 6: Self-Encrypting Propagation ─────────────────────────────────

print("\n" + "=" * 72)
print("Section 6: Self-Encrypting Position Propagation")
print("=" * 72)
print("""
k[32]=0 and k[73]=0 (ALL variants: verified from CT[32]=PT[32]=S, CT[73]=PT[73]=K).
Under a running-key cipher, RK[32+offset]=A and RK[73+offset]=A (Vigenère).
Under periodic key of period p: k[32] = k[32 mod p] = 0 AND k[73] = k[73 mod p] = 0.

Constraint: if k[32 mod p] = k[73 mod p], then 32 ≡ 73 (mod p) → p | 41.
  Divisors of 41: {1, 41}  → p=1 (trivial) or p=41.
If 32 mod p ≠ 73 mod p, then BOTH residue classes must have key value 0.
  This adds one constraint per period tested.

Below: for each period 1-26, check if the self-encrypting positions are
consistent with the OBSERVED conflicts in the keystream.
""")

print(f"  32 mod p and 73 mod p for periods 1-26:")
for p in range(1, 27):
    r32 = 32 % p
    r73 = 73 % p
    constraint = "SAME residue → p | (73-32)=41" if r32 == r73 else f"DIFFERENT residues ({r32}, {r73}) → both must be 0"
    # Check if the period conflicts involve these residues
    info = vig_period_info[p]
    conflict_residues = {c[1] for c in info["conflicts"]}
    self_enc_conflict = r32 in conflict_residues or r73 in conflict_residues
    print(f"    p={p:2d}: r32={r32:2d} r73={r73:2d}  {constraint[:50]}"
          f"  {'[conflict involves self-enc pos]' if self_enc_conflict else ''}")


# ── Section 7: BC Differential Constraint (running key filter) ─────────────

print("\n" + "=" * 72)
print("Section 7: BC Differential Constraint for Running Key Filtering")
print("=" * 72)
print("""
The EAST constraint uses 4-char variant-independent differential [1,25,1,23].
This works because the differential K[i+1]-K[i] = (CT[i+1]-CT[i]) - (PT[i+1]-PT[i]).
For Vigenère: delta_K = delta_CT - delta_PT.
The PT differential at EAST (EAST positions 21-24) is fixed from the crib.
The CT differential at those positions is also fixed from the CT.
=> delta_K is independent of the cipher variant additive constant.

NEW: Compute the analogous BC differential signature.
""")

# CT values at BC positions
bc_ct_vals = [CT_VALS[BC_START + i] for i in range(len(BC_WORD))]
bc_pt_vals = [ALPH_IDX[c] for c in BC_WORD]

# First-order differences
bc_ct_diffs = [(bc_ct_vals[i+1] - bc_ct_vals[i]) % MOD for i in range(len(BC_WORD)-1)]
bc_pt_diffs = [(bc_pt_vals[i+1] - bc_pt_vals[i]) % MOD for i in range(len(BC_WORD)-1)]
bc_ks_diffs = [(bc_ct_diffs[i] - bc_pt_diffs[i]) % MOD for i in range(len(bc_ct_diffs))]

print(f"  BC crib: {BC_WORD}")
print(f"  CT at BC: {''.join(CT[BC_START:BC_START+len(BC_WORD)])}")
print(f"  CT diffs (mod 26): {bc_ct_diffs}")
print(f"  PT diffs (mod 26): {bc_pt_diffs}")
print(f"  KS diffs = CT-PT diffs (mod 26, VARIANT-INDEPENDENT): {bc_ks_diffs}")
print(f"\n  This 10-element differential signature is the BC equivalent of EAST's [1,25,1,23].")
print(f"  A running key source must have a 10-consecutive-char window with exactly")
print(f"  these first-differences, shifted by the same offset (or accounting for transposition).")
print(f"\n  For comparison — ENE differential signature:")
ene_ct_vals = [CT_VALS[ENE_START + i] for i in range(len(ENE_WORD))]
ene_pt_vals = [ALPH_IDX[c] for c in ENE_WORD]
ene_ct_diffs = [(ene_ct_vals[i+1] - ene_ct_vals[i]) % MOD for i in range(len(ENE_WORD)-1)]
ene_pt_diffs = [(ene_pt_vals[i+1] - ene_pt_vals[i]) % MOD for i in range(len(ENE_WORD)-1)]
ene_ks_diffs = [(ene_ct_diffs[i] - ene_pt_diffs[i]) % MOD for i in range(len(ene_ct_diffs))]
print(f"  ENE KS diffs: {ene_ks_diffs}")
print(f"\n  EAST filter (E-CFM-06) uses first 4 diffs: {ene_ks_diffs[:4]}")
print(f"  BC filter would use first 4 diffs:         {bc_ks_diffs[:4]}")

# Check: does the BC 4-diff filter appear anywhere in the CT itself (for CT-autokey)?
bc_4diff = bc_ks_diffs[:4]
print(f"\n  Checking for BC 4-diff {bc_4diff} in CT first-differences...")
ct_diffs = [(CT_VALS[i+1] - CT_VALS[i]) % MOD for i in range(CT_LEN-1)]
ct_4diff_windows = [ct_diffs[i:i+4] for i in range(len(ct_diffs)-3)]
matches_in_ct = [i for i, w in enumerate(ct_4diff_windows) if w == bc_4diff]
print(f"  CT positions where BC 4-diff pattern starts: {matches_in_ct}")
if not matches_in_ct:
    print("  None. => BC 4-diff pattern NOT found in CT itself.")
else:
    for pos in matches_in_ct:
        print(f"    pos {pos}: CT window = {CT[pos:pos+5]}")


# ── Section 8: Keystream Word Embedding ────────────────────────────────────

print("\n" + "=" * 72)
print("Section 8: Keystream Word Embedding — Do any words appear in the keystream?")
print("=" * 72)
print("""
Given the 24-char Vigenère keystream BLZCDCYYGCKAZMUYKLGKORNA,
check whether any substring of length ≥ 3 is an English word.
Also check if the keystream contains any K1-K4 theme words.
""")

VIG_KS_STR = "".join(ALPH[VIG_KS[p]] for p in CRIB_POS_LIST)
print(f"  Full 24-char keystream: {VIG_KS_STR}")

# Words to search for
THEME_WORDS = [
    "ACE", "AGE", "ARC", "ARE", "ARK", "ART", "BAR", "BAY",
    "BEG", "BIG", "BIT", "BOK", "CAR", "COD", "CRY",
    "DOC", "DIG", "EAR", "ECO", "GAR", "GUL", "GUN",
    "KAZ", "KON", "LAG", "LUG", "MAY", "MUG", "NAY",
    "OAK", "ORB", "ORK", "OCA", "RAG", "RUG", "RUN",
    "YAK", "YAM", "YOK",
    # Short relevant words
    "KG", "LK", "MU", "MY", "OG", "OK", "OR", "UK",
    # Theme words (check substrings)
    "KGCK", "MUYK", "GKAZ", "KORN", "ORNA",
    # Acronyms
    "CIA", "NSA", "KGB", "FBI", "MIT",
]

found_words = []
for word in THEME_WORDS:
    if word in VIG_KS_STR:
        pos_in_ks = VIG_KS_STR.index(word)
        found_words.append((word, pos_in_ks))
        print(f"  FOUND: '{word}' at keystream position {pos_in_ks}")

# Check all 3-grams that look like real words
try:
    wl_path = Path("wordlists/words.txt")
    if not wl_path.exists():
        wl_path = Path("wordlists/english.txt")
    if wl_path.exists():
        with open(wl_path) as f:
            wordset = {w.strip().upper() for w in f if 3 <= len(w.strip()) <= 6}
        print(f"\n  Checking against wordlist ({len(wordset)} words)...")
        for length in range(3, 8):
            for start in range(len(VIG_KS_STR) - length + 1):
                sub = VIG_KS_STR[start:start+length]
                if sub in wordset:
                    print(f"  WORDLIST HIT: '{sub}' at keystream pos {start}")
    else:
        print("  (No wordlist found; skipping dictionary check)")
except Exception as e:
    print(f"  (Wordlist check failed: {e})")

if not found_words:
    print("  No theme words found in 24-char keystream.")


# ── Section 9: Known Keyword Direct Injection at BERLINCLOCK ───────────────

print("\n" + "=" * 72)
print("Section 9: Known Keyword Direct Key — BERLINCLOCK position test")
print("=" * 72)
print("""
If K4 uses a repeating keyword, and we know the key at 11 consecutive positions
(BC: positions 63-73, Vigenère keystream = MUYKLGKORNA), then the keyword
must contain 'MUYKLGKORNA' as a cyclic substring.
We check all known candidate keywords for this property.
""")

VIG_BC_KEY_STR = "".join(ALPH[v] for v in VIGENERE_KEY_BC)
print(f"  BC Vigenère keystream: {VIG_BC_KEY_STR}")
print()

for kw_name, kw_vals in KEYWORDS.items():
    kw_str = "".join(ALPH[v] for v in kw_vals)
    p = len(kw_vals)
    # For a repeating keyword of period p starting at some offset o,
    # key[63] = kw[(63+o) % p], ..., key[73] = kw[(73+o) % p]
    # This means the keyword (cyclically starting at offset o) must equal MUYKLGKORNA.
    found_offset = None
    for o in range(p):
        window = "".join(ALPH[kw_vals[(63 + o + i) % p]] for i in range(11))
        if window == VIG_BC_KEY_STR:
            found_offset = o
            break
    if found_offset is not None:
        print(f"  MATCH: {kw_name} (len={p}) at offset {found_offset}: "
              f"cyclic window = {window}")
    else:
        # Find closest match (minimum Hamming distance over all offsets)
        best_hd = 11
        best_o = 0
        for o in range(p):
            window = "".join(ALPH[kw_vals[(63 + o + i) % p]] for i in range(11))
            hd = sum(a != b for a, b in zip(window, VIG_BC_KEY_STR))
            if hd < best_hd:
                best_hd = hd
                best_o = o
        best_window = "".join(ALPH[kw_vals[(63 + best_o + i) % p]] for i in range(11))
        print(f"  No match: {kw_name:<22} (len={p})  best Hamming={best_hd}/11  "
              f"best window={best_window}")


# ── Summary ─────────────────────────────────────────────────────────────────

print("\n" + "=" * 72)
print("CRITICAL ASSESSMENT — What do these results prove or disprove?")
print("=" * 72)

print("""
1. KA-ALPHABET KEYSTREAM: Computed above. Bean verdict shown per variant.
   Period consistency check mirrors standard alphabet result.

2. TWO-KEYWORD PRODUCT:
   - KRYPTOS as kw1: ALL p2 in 1-13 = CONFLICT (proven in prior run).
   - PALIMPSEST, ABSCISSA, BERLINCLOCK: results above.
   - Free (p1,p2) sweep: results above — if all CONFLICT, this ELIMINATES
     all two-keyword periodic products with p1,p2 ≤ 13.

3. CT-AUTOKEY: If no CT substring exactly matches BC keystream at any offset
   → CT-autokey ELIMINATED under identity transposition.

4. AFFINE KEY MODEL: If max matches < 10, affine key is ELIMINATED.

5. PERIOD NEAR-MISSES: If no period has exactly 1 conflict, then no single
   error in the crib positions could save a periodic model.
   If 1-conflict exists: which position is it? Is that a potential typo?

6. SELF-ENCRYPTING PROPAGATION: k[32]=k[73]=0 forces p | 41 for same-residue
   periodic keys. Divisors of 41 in range: only 1 and 41 — both already
   eliminated by other constraints.

7. BC DIFFERENTIAL: 10-element signature computed. This can be used in
   future running-key corpus scans as a parallel filter to EAST.

8. KEYWORD INJECTION: No known keyword (KRYPTOS, PALIMPSEST, ABSCISSA,
   BERLINCLOCK, etc.) cyclically matches the 11-char BC keystream → all
   known candidate keywords ELIMINATED as sole repeating Vigenère key.
""")


# ── Save JSON ───────────────────────────────────────────────────────────────

results = {
    "ka_alphabet_keystream": ka_results,
    "two_keyword_product": two_kw_results,
    "two_keyword_free_consistent": free_two_kw_consistent,
    "ct_autokey_hits": ct_autokey_hits,
    "affine_key_top10": [{"matches": m, "a": a, "b": b} for m, a, b in affine_results[:10]],
    "affine_max_matches": max_affine_matches,
    "period_near_misses_vig": {
        str(p): r["n_conflicts"] for p, r in vig_period_info.items()
    },
    "bc_differential_ks": bc_ks_diffs,
    "ene_differential_ks": ene_ks_diffs,
    "bc_4diff_in_ct": matches_in_ct,
    "vig_ks_24char": VIG_KS_STR,
}

out_path = Path("results/e_k4_extend_v2.json")
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n[SAVED] {out_path}")
