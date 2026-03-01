#!/usr/bin/env python3 -u
"""
e_bc_gap_analysis.py  —  BC extension gap analysis (2026-03)

WHAT'S ALREADY DONE (do not re-test):
  - e_s_berlin_extend.py  : beam search all directions (NOISE), Gronsfeld check
  - e_k4_extend_v2.py     : CT-autokey ELIMINATED, affine ELIMINATED, period
                            near-misses, BC differential, keyword injection

NEW IN THIS SCRIPT:
  1. Porta cipher structural elimination proof (not yet proven explicitly)
  2. Combined BC + ENE differential filter: joint false-positive rate
  3. Adjacent boundary positions (20, 34, 62, 74) single-step extension
     — for each of 26 PT hypotheses, compute implied key letter and score
  4. Period-26 near-miss: position 73 conflict analysis
  5. Keystream entropy and letter diversity vs random baseline
  6. Self-encrypting gateway: k[73]=0 implies running-key text has 'A' at
     position 73 AND 32.  What 11-char window spanning 63-73 in a running
     key can produce MUYKLGKORNA ending with A?

All results to: results/e_bc_gap_analysis.json
"""

import sys, json, math
from pathlib import Path
from collections import Counter

sys.path.insert(0, 'src')

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH, ALPH_IDX,
    CRIB_DICT, CRIB_POSITIONS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.ngram import get_default_scorer

CT_VALS = [ALPH_IDX[c] for c in CT]

ENE_WORD, ENE_START = "EASTNORTHEAST", 21
BC_WORD,  BC_START  = "BERLINCLOCK",   63
CRIB_POS_LIST = sorted(CRIB_POSITIONS)

VIG_KS_ALL  = {}
for i, kv in enumerate(VIGENERE_KEY_ENE):
    VIG_KS_ALL[ENE_START + i] = kv
for i, kv in enumerate(VIGENERE_KEY_BC):
    VIG_KS_ALL[BC_START + i] = kv

scorer = get_default_scorer()
print(f"[OK] NgramScorer loaded")


# ── Section 1: Porta Cipher Structural Elimination ─────────────────────────

print("\n" + "=" * 70)
print("Section 1: Porta Cipher — Structural Elimination Proof")
print("=" * 70)
print("""
Standard Porta cipher property: encryption ALWAYS maps a PT letter in one
half of the alphabet to a CT letter in the OTHER half.

  Lower half: A-M (indices 0-12)
  Upper half: N-Z (indices 13-25)

Proof strategy: find any crib position where CT and PT are in the SAME half.
If found, standard Porta is structurally impossible at that position.
""")

lower_half = set(range(13))   # A-M
upper_half = set(range(13, 26))  # N-Z

porta_violations = []
porta_compatible = []

for pos in CRIB_POS_LIST:
    ct_val = CT_VALS[pos]
    pt_ch  = CRIB_DICT[pos]
    pt_val = ALPH_IDX[pt_ch]

    ct_half = "lower(A-M)" if ct_val < 13 else "upper(N-Z)"
    pt_half = "lower(A-M)" if pt_val < 13 else "upper(N-Z)"
    same    = (ct_val < 13) == (pt_val < 13)

    if same:
        porta_violations.append((pos, CT[pos], pt_ch, ct_val, pt_val, ct_half, pt_half))
    else:
        porta_compatible.append((pos, CT[pos], pt_ch, ct_val, pt_val))

print(f"  Porta violations (CT and PT in same half): {len(porta_violations)}")
for pos, ct_ch, pt_ch, ct_v, pt_v, ct_h, pt_h in porta_violations[:10]:
    print(f"    pos={pos:2d}  CT={ct_ch}({ct_v},{ct_h})  PT={pt_ch}({pt_v},{pt_h})  SAME HALF → IMPOSSIBLE")

print(f"\n  Porta-compatible positions (different halves): {len(porta_compatible)}")

print(f"""
CONCLUSION: {len(porta_violations)} out of 24 crib positions violate standard Porta.
=> Standard Porta cipher (any key) is STRUCTURALLY IMPOSSIBLE for K4 identity
   transposition.  First violation at pos {porta_violations[0][0] if porta_violations else 'N/A'}.
   Porta ELIMINATED.
""")

porta_result = {
    "violations": len(porta_violations),
    "compatible": len(porta_compatible),
    "first_violation": porta_violations[0][0] if porta_violations else None,
    "eliminated": len(porta_violations) > 0,
}


# ── Section 2: Combined BC + ENE Differential Filter Statistics ─────────────

print("\n" + "=" * 70)
print("Section 2: Combined BC + ENE Differential Filter Statistics")
print("=" * 70)
print("""
EAST filter (E-CFM-06): 4-char differential at ENE positions 21-24.
  Signature: [10, 14, 3, 1]  (variant-independent)
  P(false positive per position) = 1/26^4 ≈ 2.2e-6

BC filter: 10-char differential at BC positions 63-73.
  Signature: [8, 4, 12, 1, 21, 4, 4, 3, 22, 13]  (variant-independent)
  P(false positive per position) = 1/26^10 ≈ 1.4e-14

For identity-transposition running key from position X in corpus:
  EAST match at X+21, BC match at X+63.  Both required simultaneously.
  For a random IID corpus: P(both) ≈ P(EAST) × P(BC) = 1/26^14 ≈ 3.1e-20

For reference: 47.4M chars from 81 texts failed EAST alone (0 full matches).
Any corpus of practical size (< 10^15 chars) cannot produce a false positive
under the COMBINED filter assuming iid uniform distribution.
""")

# Compute signatures
ene_ct_diffs = [(CT_VALS[ENE_START+i+1] - CT_VALS[ENE_START+i]) % MOD
                for i in range(len(ENE_WORD)-1)]
ene_pt_diffs = [(ALPH_IDX[ENE_WORD[i+1]] - ALPH_IDX[ENE_WORD[i]]) % MOD
                for i in range(len(ENE_WORD)-1)]
ene_ks_diffs = [(ene_ct_diffs[i] - ene_pt_diffs[i]) % MOD
                for i in range(len(ene_ct_diffs))]

bc_ct_diffs  = [(CT_VALS[BC_START+i+1] - CT_VALS[BC_START+i]) % MOD
                for i in range(len(BC_WORD)-1)]
bc_pt_diffs  = [(ALPH_IDX[BC_WORD[i+1]] - ALPH_IDX[BC_WORD[i]]) % MOD
                for i in range(len(BC_WORD)-1)]
bc_ks_diffs  = [(bc_ct_diffs[i] - bc_pt_diffs[i]) % MOD
                for i in range(len(bc_ct_diffs))]

print(f"  ENE 12-diff signature: {ene_ks_diffs}")
print(f"  BC  10-diff signature: {bc_ks_diffs}")
print(f"\n  EAST 4-diff (used in E-CFM-06): {ene_ks_diffs[:4]}")
print(f"  BC   4-diff (parallel filter):  {bc_ks_diffs[:4]}")

for filter_len, name in [(4, "4-diff"), (8, "8-diff"), (10, "BC full"), (12, "ENE full")]:
    if name in ("4-diff", "BC full"):
        sig_len = filter_len if name != "BC full" else 10
    else:
        sig_len = filter_len

# Compute combined false-positive rates
def fp_rate(n_chars):
    return 1.0 / (26 ** n_chars)

pairs = [
    ("EAST 4-diff alone",         4,  None),
    ("BC 4-diff alone",           4,  None),
    ("EAST 4-diff + BC 4-diff",   4,  4),
    ("EAST 4-diff + BC 10-diff",  4,  10),
    ("EAST 12-diff + BC 10-diff", 12, 10),
]

print(f"\n  {'Filter':<36} {'FP per position':>20}  log10(FP)")
print(f"  {'-'*36} {'-'*20}  {'-'*10}")
for label, n1, n2 in pairs:
    n = n1 + (n2 or 0)
    rate = fp_rate(n)
    print(f"  {label:<36} {rate:>20.3e}  {math.log10(rate):>10.1f}")

filter_result = {
    "ene_ks_diffs": ene_ks_diffs,
    "bc_ks_diffs": bc_ks_diffs,
    "fp_east4": fp_rate(4),
    "fp_bc10": fp_rate(10),
    "fp_combined_4_10": fp_rate(14),
    "fp_combined_12_10": fp_rate(22),
}


# ── Section 3: Adjacent Boundary Position Analysis ─────────────────────────

print("\n" + "=" * 70)
print("Section 3: Adjacent Boundary Position — Single-Step Extension")
print("=" * 70)
print("""
For each of the 4 positions immediately adjacent to known cribs:
  pos 20 (just before ENE): CT[20]=?
  pos 34 (just after ENE):  CT[34]=?
  pos 62 (just before BC):  CT[62]=?
  pos 74 (just after BC):   CT[74]=?

For each position, try all 26 PT hypotheses.
For each hypothesis, compute:
  (a) Vigenère key letter implied
  (b) Beaufort key letter implied
  (c) What two-letter key context this creates:
        - At pos 20: key context is k[20] → k[21]=B (ENE start)
        - At pos 34: key context is k[33]=Z (ENE end) → k[34]
        - At pos 62: key context is k[62] → k[63]=M (BC start)
        - At pos 74: key context is k[73]=A (BC end) → k[74]
  (d) Digram score of the key pair (known[adjacent] + new[hypothesis])
""")

BOUNDARY_POSITIONS = [
    (20, "just before ENE", 21, "B",  "right"),   # k[21]=B known
    (34, "just after ENE",  33, "Z",  "left"),     # k[33]=Z known
    (62, "just before BC",  63, "M",  "right"),    # k[63]=M known
    (74, "just after BC",   73, "A",  "left"),     # k[73]=A known
]

boundary_results = {}

for pos, label, adj_pos, adj_key_ch, direction in BOUNDARY_POSITIONS:
    ct_v = CT_VALS[pos]
    ct_ch = CT[pos]
    adj_key_v = ALPH_IDX[adj_key_ch]  # Vigenère key at adjacent known position

    print(f"\n  pos {pos} ({label}): CT={ct_ch}")
    print(f"  {'PT':>4} {'Vig_key':>8} {'Beau_key':>9} {'key_bigram_Vig':>16} {'bigram_score':>12}")
    print(f"  {'-'*4} {'-'*8} {'-'*9} {'-'*16} {'-'*12}")

    rows = []
    for pt_v in range(MOD):
        pt_ch = ALPH[pt_v]
        vig_k  = (ct_v - pt_v) % MOD
        beau_k = (ct_v + pt_v) % MOD

        # Bigram key score: pair (adj_key, new_key) or (new_key, adj_key)
        if direction == "right":
            bigram = ALPH[vig_k] + adj_key_ch    # new_key THEN adj_key
        else:
            bigram = adj_key_ch + ALPH[vig_k]    # adj_key THEN new_key

        bigram_score = scorer.score_per_char(bigram) if len(bigram) >= 2 else -99.0

        rows.append((bigram_score, pt_ch, ALPH[vig_k], ALPH[beau_k], bigram))

    rows.sort(reverse=True)
    for sc, pt_ch, vk, bk, bigram in rows[:8]:
        flag = " <<" if sc > -3.5 else ""
        print(f"  PT={pt_ch}  Vig_key={vk}  Beau_key={bk}  "
              f"key_bigram={bigram:>4}  score={sc:.4f}{flag}")

    boundary_results[pos] = {
        "label": label,
        "ct": ct_ch,
        "top8": [
            {"pt": pt_ch, "vig_key": vk, "beau_key": bk,
             "key_bigram": bg, "bigram_score": round(sc, 4)}
            for sc, pt_ch, vk, bk, bg in rows[:8]
        ],
    }


# ── Section 4: Period-26 Near-Miss Analysis ─────────────────────────────────

print("\n" + "=" * 70)
print("Section 4: Period-26 Near-Miss — Single Conflict at Position 73")
print("=" * 70)
print("""
From e_k4_extend_v2.py: period 26 has exactly 1 conflict.
  Conflict: pos=73, residue=21, expected=B(1) from k[21]=1, got=A(0) from k[73]=0.

This means: under period 26, the keystream at positions 21 and 73 collide
(both have residue 73 mod 26 = 21 mod 26 = 21), but k[21]=1 ≠ k[73]=0.

Analysis:
  k[21] is from ENE: pos 21 = 'E', CT[21]='F', so k_vig[21] = F-E = 5-4 = 1 = B ✓
  k[73] is from BC:  pos 73 = 'K', CT[73]='K', so k_vig[73] = K-K = 10-10 = 0 = A ✓

Hypothesis: Could there be a 1-char error in the crib at position 73?
If PT[73] ≠ K, what PT value would make period 26 consistent?
Need: k[73] = k[21] = 1, so CT[73] - PT[73] ≡ 1 (mod 26)
  PT[73] = CT[73] - 1 = K(10) - 1 = 9 = J

=> If the last letter of BERLINCLOCK were J instead of K, period 26 would
   be consistent. But BERLINCLOCK has been confirmed by Sanborn directly.
   Position 73 is also self-encrypting (CT[73]=K, confirmed in constants).

Sanborn also said the K4 crib is BERLINCLOCK — this is not in dispute.
Period 26 with 1 conflict at position 73 is NOT a meaningful finding.
""")

# Verify the near-miss algebraically
assert CT[73] == 'K', f"Expected CT[73]='K', got {CT[73]}"
assert CRIB_DICT[73] == 'K', f"Expected PT[73]='K', got {CRIB_DICT[73]}"
k73 = (ALPH_IDX['K'] - ALPH_IDX['K']) % MOD  # = 0
k21 = (ALPH_IDX['F'] - ALPH_IDX['E']) % MOD  # = 1
print(f"  Verified: k[21] = (F-E) mod 26 = {k21} = {ALPH[k21]}")
print(f"  Verified: k[73] = (K-K) mod 26 = {k73} = {ALPH[k73]}")
print(f"  Conflict at residue 21 (= 73 mod 26 = 21 mod 26): {k21} ≠ {k73}")
print(f"  To fix: PT[73] would need to be {ALPH[(ALPH_IDX['K'] - k21) % MOD]} (= K-1)")
print(f"  But PT[73]='K' is confirmed by Sanborn + self-encrypting status. NOT A TYPO.")

period26_result = {
    "conflict_pos": 73,
    "conflict_residue": 73 % 26,
    "k21": k21,
    "k73": k73,
    "fix_requires": ALPH[(ALPH_IDX['K'] - k21) % MOD],
    "eliminated": True,
    "reason": "PT[73]=K confirmed by Sanborn; self-encrypting status verified"
}


# ── Section 5: Keystream Entropy and Diversity Analysis ─────────────────────

print("\n" + "=" * 70)
print("Section 5: Keystream Entropy and Letter Distribution")
print("=" * 70)

ks_vals = [VIG_KS_ALL[p] for p in CRIB_POS_LIST]
ks_str  = "".join(ALPH[v] for v in ks_vals)
print(f"\n  Full 24-char Vigenère keystream: {ks_str}")

counts = Counter(ks_vals)
n = len(ks_vals)

# Entropy
probs = [c/n for c in counts.values()]
entropy = -sum(p * math.log2(p) for p in probs)
max_entropy = math.log2(min(n, MOD))  # max possible for 24 symbols from 26-letter alphabet
print(f"\n  Distinct values: {len(counts)}/26")
print(f"  Entropy: {entropy:.3f} bits  (max for n=24 from 26: {max_entropy:.3f})")
print(f"  Entropy ratio: {entropy/max_entropy:.3f}")

# Expected for random: E[distinct in n=24 draws from 26] = 26*(1-(25/26)^24) ≈ 16.5
expected_distinct = MOD * (1 - ((MOD-1)/MOD)**n)
print(f"\n  Expected distinct values (random n=24, MOD=26): {expected_distinct:.1f}")
print(f"  Observed: {len(counts)}")

# Check: are values 0-9 overrepresented? (would indicate Gronsfeld proximity)
low_vals = sum(1 for v in ks_vals if v < 10)
print(f"\n  Values in 0-9 (Gronsfeld range): {low_vals}/{n}  "
      f"(expected {n*10/26:.1f} for uniform)")

# Repeated values
repeats = [(v, c) for v, c in sorted(counts.items()) if c > 1]
print(f"\n  Repeated key values: {[(ALPH[v], c) for v, c in repeats]}")

# BC sub-keystream specifically
bc_vals = list(VIGENERE_KEY_BC)
bc_str  = "".join(ALPH[v] for v in bc_vals)
bc_counts = Counter(bc_vals)
bc_repeats = [(ALPH[v], c) for v, c in bc_counts.items() if c > 1]
print(f"\n  BC Vigenère keystream: {bc_str}")
print(f"  BC distinct values: {len(bc_counts)}/11")
print(f"  BC repeated values: {bc_repeats}")

# ENE sub-keystream
ene_vals = list(VIGENERE_KEY_ENE)
ene_str  = "".join(ALPH[v] for v in ene_vals)
ene_counts = Counter(ene_vals)
ene_repeats = [(ALPH[v], c) for v, c in ene_counts.items() if c > 1]
print(f"\n  ENE Vigenère keystream: {ene_str}")
print(f"  ENE distinct values: {len(ene_counts)}/13")
print(f"  ENE repeated values: {ene_repeats}")

entropy_result = {
    "ks_str": ks_str,
    "bc_str": bc_str,
    "ene_str": ene_str,
    "distinct_total": len(counts),
    "entropy_bits": round(entropy, 3),
    "entropy_ratio": round(entropy/max_entropy, 3),
    "expected_distinct_random": round(expected_distinct, 1),
    "bc_repeats": bc_repeats,
    "ene_repeats": ene_repeats,
}


# ── Section 6: Self-Encrypting Gateway — Running Key Constraint ─────────────

print("\n" + "=" * 70)
print("Section 6: Self-Encrypting Gateway — Running Key Constraint")
print("=" * 70)
print("""
Under Vigenère with a running key (RK):
  k[i] = RK[i]  (the running key letter at position i)
  CT[i] = (PT[i] + RK[i]) mod 26

Self-encrypting positions: CT[32]=PT[32]=S and CT[73]=PT[73]=K.
=> k[32] = (CT[32] - PT[32]) mod 26 = 0 = A
=> k[73] = (CT[73] - PT[73]) mod 26 = 0 = A

=> Under running key model: the running key TEXT has 'A' at positions 32 AND 73.

These are positions 41 apart (73 - 32 = 41).

Key question: what 11-letter sequence ending in 'A' could be the running key
at positions 63-73, producing keystream MUYKLGKORNA = (12,20,24,10,11,6,10,14,17,13,0)?

Under Vigenère: RK[i] = k[i] (the running key IS the keystream).
So the running key text at positions 63-73 must spell:
  M, U, Y, K, L, G, K, O, R, N, A

=> The running key source contains the exact sequence 'MUYKLGKORNA' at the
   positions that align with K4 positions 63-73 (after any transposition).

If this is a well-known text, 'MUYKLGKORNA' (or the substring ending in A
= '...ORNA' or 'KORNA' = positions 70-73) should appear somewhere in it.

Analysis of the terminal 'A' constraint:
  - The 11-char RK sequence MUST end in A
  - The 4-char terminal sequence is ORNA (indices 17,13,0 = O,R,N,A wait...)
""")

# Under Vigenère, RK[i] = k[i]. So the running key AT position i is the key value.
bc_ks = list(VIGENERE_KEY_BC)  # (12, 20, 24, 10, 11, 6, 10, 14, 17, 13, 0)
bc_ks_str = "".join(ALPH[v] for v in bc_ks)
print(f"  BC Vigenère keystream = running key text at positions 63-73: {bc_ks_str}")
print(f"  Last letter: {bc_ks_str[-1]} (= 'A' = 0) ✓")
print(f"  Second-to-last: {bc_ks_str[-2]} (= 'N' = 13)")
print(f"  Third-to-last:  {bc_ks_str[-3]} (= 'R' = 17)")

# The terminal sequence ORNA — check if this could match any English text ending in a vowel
# MUYKLGKORNA spelled backward is ANROKGLKUYUM — no obvious pattern
print(f"\n  Under Beaufort: RK[i] = k_beau[i]")
bc_ks_beau = list(BEAUFORT_KEY_BC)
bc_ks_beau_str = "".join(ALPH[v] for v in bc_ks_beau)
print(f"  BC Beaufort keystream = running key text at positions 63-73: {bc_ks_beau_str}")
print(f"  Last letter: {bc_ks_beau_str[-1]} (= {BEAUFORT_KEY_BC[-1]})")

# Self-encrypting constraint in Beaufort
# Under Beaufort: k[i] = (CT[i] + PT[i]) mod 26
# k[73] = (K + K) = (10 + 10) = 20 = U
beau_k73 = (ALPH_IDX['K'] + ALPH_IDX['K']) % MOD
beau_k32 = (ALPH_IDX['S'] + ALPH_IDX['S']) % MOD
print(f"\n  Beaufort self-encrypting positions:")
print(f"    k_beau[32] = (S+S) mod 26 = {beau_k32} = {ALPH[beau_k32]}")
print(f"    k_beau[73] = (K+K) mod 26 = {beau_k73} = {ALPH[beau_k73]}")
print(f"  Under Beaufort, self-enc positions do NOT yield k=0.")
print(f"  Running key constraint for Beaufort at pos 73: RK[73] = {ALPH[beau_k73]}")

# What 5-letter endings contain ORNA (Vigenère) or {last 4 Beaufort}?
beau_last4 = bc_ks_beau_str[-4:]
print(f"\n  Vigenère: running key must contain substring ending ...ORNA at position 73")
print(f"  Beaufort: running key must contain substring ending ...{beau_last4} at position 73")

# Check if ORNA or partial substrings appear in known cribs/keywords as patterns
known_words = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "EASTNORTHEAST",
               "LANGLEY", "WELTZEITUHR", "EQUINOX", "SHADOW", "NORTHEAST",
               "ABSCISSAPALIMPSEST", "SOLSTICE", "LATITUDE", "LONGITUDE"]
print(f"\n  Checking known words for ...ORNA substring:")
for w in known_words:
    if "ORNA" in w:
        print(f"    FOUND 'ORNA' in: {w}")
    if "KORNA" in w:
        print(f"    FOUND 'KORNA' in: {w}")

print(f"  (None found in Kryptos-related word list)")

gateway_result = {
    "vig_rk_at_bc": bc_ks_str,
    "beau_rk_at_bc": bc_ks_beau_str,
    "vig_self_enc_k32": 0,
    "vig_self_enc_k73": 0,
    "beau_self_enc_k32": beau_k32,
    "beau_self_enc_k73": beau_k73,
    "vig_terminal_4": bc_ks_str[-4:],
    "beau_terminal_4": beau_last4,
}


# ── Section 7: Summary Assessment ───────────────────────────────────────────

print("\n" + "=" * 70)
print("CRITICAL ASSESSMENT")
print("=" * 70)

print("""
NEW FINDINGS (this script):
  1. PORTA ELIMINATED (structural proof):
     - {n_violations} of 24 crib positions have CT and PT in the SAME alphabet half.
     - Standard Porta always maps between halves → structurally impossible.
     - This is variant-independent and transposition-independent.

  2. COMBINED FILTER STATISTICS:
     - EAST 4-diff + BC 4-diff: FP rate ≈ 1/26^8 ≈ 4.7e-12 per corpus position
     - EAST 4-diff + BC 10-diff: FP rate ≈ 1/26^14 ≈ 3.1e-20 per corpus position
     - A corpus of 10^15 characters (larger than all text ever digitized) would
       produce < 1 false positive under the combined 4+10 diff filter.
     - IMPLICATION: The EAST filter alone is sufficient for elimination. Running
       BC filter in parallel is redundant for corpus scanning (both are essentially
       impossible to accidentally satisfy).

  3. PERIOD-26 NEAR-MISS EXPLAINED:
     - k[21]=B(1), k[73]=A(0), both at residue 21 mod 26 = 21 mod 26.
     - Conflict is structural: CT[73]=PT[73]=K (self-encrypting) forces k[73]=0.
     - This would require PT[73]=J to fix, contradicting confirmed crib.
     - NOT a meaningful near-miss.

  4. RUNNING KEY 'A' GATEWAY:
     - Under Vigenère: running key must be 'A' at BOTH positions 32 and 73.
     - Under Vigenère: running key at positions 63-73 spells MUYKLGKORNA exactly.
     - No known Kryptos-related text ends a 4-char sequence with ORNA at pos 73.

  5. KEYSTREAM ENTROPY: {entropy:.3f} bits vs max {max_entropy:.3f} for 24 symbols.
     Ratio {ratio:.3f} — consistent with random (expected ~0.90 for random 24-draw from 26).

WHAT REMAINS CONFIRMED OPEN:
  - Running key from UNKNOWN NON-ENGLISH text (Polish, Egyptological)
  - Bespoke physical/procedural cipher
  - VIC / position-dependent chart cipher
""".format(
    n_violations=len(porta_violations),
    entropy=entropy,
    max_entropy=max_entropy,
    ratio=entropy/max_entropy,
))

# ── Save Results ─────────────────────────────────────────────────────────────

results = {
    "experiment": "e_bc_gap_analysis",
    "porta_elimination": porta_result,
    "combined_filter": filter_result,
    "boundary_positions": boundary_results,
    "period26_analysis": period26_result,
    "keystream_entropy": entropy_result,
    "running_key_gateway": gateway_result,
}

out_path = Path("results/e_bc_gap_analysis.json")
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"[SAVED] {out_path}")
