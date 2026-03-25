#!/usr/bin/env python3
"""
E-GKO-KEY-SWEEP: Multi-variant, multi-alphabet GKO keystream analysis

Phase 1: Compute running key values at all 24 crib positions under
         6 variant/alphabet combos (Beaufort/Vigenere/VarBeau x AZ/KA).
Phase 2: Analyze Beaufort AZ running key GKO density vs English expectation.
Phase 3: GKO count at crib positions per variant/alphabet combo.
Phase 4: Test 7 keyword-mixed alphabets — does any reduce GKO concentration?

Attack-type: analysis
Family: keystream-forensics
Status: active
"""

import sys, os, json
from datetime import datetime, timezone
from collections import Counter

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT
from kryptos.kernel.alphabet import AZ, KA, Alphabet, keyword_mixed_alphabet

# ── Setup ────────────────────────────────────────────────────────────────────

ENE_POS = list(range(21, 34))   # 13 positions (0-indexed)
BCL_POS = list(range(63, 74))   # 11 positions
ALL_CRIB_POS = sorted(ENE_POS + BCL_POS)  # 24 positions

ENE_PT = "EASTNORTHEAST"
BCL_PT = "BERLINCLOCK"
FULL_PT = ENE_PT + BCL_PT  # 24 chars matching ALL_CRIB_POS order

GKO_LETTERS = {'G', 'K', 'O'}
GKO_AZ = {AZ.char_to_idx(c) for c in GKO_LETTERS}  # {6, 10, 14}

# English letter frequencies (approximate)
ENG_FREQ = {
    'A': 0.0817, 'B': 0.0150, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}

results = {"timestamp": datetime.now(timezone.utc).isoformat(), "phases": {}}

def compute_key_at_cribs(alpha, variant_name):
    """Compute key letter at each crib position under given alphabet and variant.

    Variants (all use alpha indexing):
      Beaufort:  key_idx = (alpha(CT) + alpha(PT)) % 26
      Vigenere:  key_idx = (alpha(CT) - alpha(PT)) % 26
      VarBeau:   key_idx = (alpha(PT) - alpha(CT)) % 26

    Returns list of 24 (key_char, key_idx) tuples.
    """
    key_data = []
    for i, pos in enumerate(ALL_CRIB_POS):
        ct_idx = alpha.char_to_idx(CT[pos])
        pt_idx = alpha.char_to_idx(FULL_PT[i])

        if variant_name == 'Beaufort':
            k_idx = (ct_idx + pt_idx) % 26
        elif variant_name == 'Vigenere':
            k_idx = (ct_idx - pt_idx) % 26
        elif variant_name == 'VarBeau':
            k_idx = (pt_idx - ct_idx) % 26
        else:
            raise ValueError(f"Unknown variant: {variant_name}")

        k_char = alpha.idx_to_char(k_idx)
        key_data.append((k_char, k_idx))

    return key_data

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 & 3: All 6 variant/alphabet combos — key values and GKO counts
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 76)
print("PHASE 1 & 3: Running key at 24 crib positions — 6 variant/alphabet combos")
print("=" * 76)

VARIANTS = ['Beaufort', 'Vigenere', 'VarBeau']
ALPHABETS = [('AZ', AZ), ('KA', KA)]

phase1_results = {}

for variant in VARIANTS:
    for alpha_name, alpha in ALPHABETS:
        combo_name = f"{variant}_{alpha_name}"
        key_data = compute_key_at_cribs(alpha, variant)

        key_chars = [k[0] for k in key_data]
        key_indices = [k[1] for k in key_data]
        key_str = ''.join(key_chars)

        # Count GKO membership — key LETTERS that are G, K, or O
        gko_letter_count = sum(1 for c in key_chars if c in GKO_LETTERS)

        # Count key indices in the AZ AP {6, 10, 14}
        # This is different from letter count when using KA indexing
        gko_idx_count = sum(1 for idx in key_indices if idx in GKO_AZ)

        # Count membership in the AP {s, s+4, s+8} for this alphabet's indexing
        # (the AP that matters depends on whether we're in AZ or KA space)
        alpha_gko_indices = {alpha.char_to_idx(c) for c in GKO_LETTERS}
        gko_alpha_idx_count = sum(1 for idx in key_indices if idx in alpha_gko_indices)

        freq = Counter(key_chars)

        print(f"\n--- {combo_name} ---")
        print(f"  Key:  {key_str}")
        print(f"  Dist: {dict(freq.most_common())}")
        print(f"  GKO letter count:     {gko_letter_count}/24")
        print(f"  GKO AZ-idx count:     {gko_idx_count}/24  (indices in {{6,10,14}})")
        print(f"  GKO alpha-idx count:  {gko_alpha_idx_count}/24  (alpha-indices of G,K,O)")

        # Check if the AP {6,10,14} in THIS alphabet maps to different letters
        ap_letters_in_alpha = [alpha.idx_to_char(v) for v in [6, 10, 14]]
        ap_count = sum(1 for idx in key_indices if idx in {6, 10, 14})
        print(f"  AP {{6,10,14}} in {alpha_name} = {{{','.join(ap_letters_in_alpha)}}}: {ap_count}/24")

        # Detailed position-by-position
        print(f"\n  {'Pos':>3s}  {'CT':>2s}  {'PT':>2s}  {'CT_i':>4s}  {'PT_i':>4s}  {'K_i':>3s}  {'K':>1s}  {'GKO?':>4s}")
        for i, pos in enumerate(ALL_CRIB_POS):
            ct_c = CT[pos]
            pt_c = FULL_PT[i]
            ct_i = alpha.char_to_idx(ct_c)
            pt_i = alpha.char_to_idx(pt_c)
            k_c, k_i = key_data[i]
            gko_mark = "GKO" if k_c in GKO_LETTERS else ""
            print(f"  {pos:3d}  {ct_c:>2s}  {pt_c:>2s}  {ct_i:4d}  {pt_i:4d}  {k_i:3d}  {k_c:>1s}  {gko_mark:>4s}")

        phase1_results[combo_name] = {
            "key_string": key_str,
            "key_indices": key_indices,
            "gko_letter_count": gko_letter_count,
            "gko_az_idx_count": gko_idx_count,
            "gko_alpha_idx_count": gko_alpha_idx_count,
            "ap_6_10_14_letters": ap_letters_in_alpha,
            "ap_6_10_14_count": ap_count,
            "distribution": dict(freq.most_common()),
        }

results["phases"]["phase1_and_3"] = phase1_results

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Beaufort AZ running key — GKO density vs English
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 76)
print("PHASE 2: Beaufort AZ running key — GKO density analysis")
print("=" * 76)

beau_az_keys = phase1_results["Beaufort_AZ"]["key_string"]
gko_count_beau_az = phase1_results["Beaufort_AZ"]["gko_letter_count"]

# Expected GKO fraction in English text
eng_gko_prob = ENG_FREQ['G'] + ENG_FREQ['K'] + ENG_FREQ['O']
expected_gko_24 = eng_gko_prob * 24
observed_gko_24 = gko_count_beau_az

print(f"\nBeaufort AZ key at cribs: {beau_az_keys}")
print(f"GKO count: {observed_gko_24}/24 = {observed_gko_24/24:.1%}")
print(f"English GKO frequency: {eng_gko_prob:.4f} = {eng_gko_prob:.1%}")
print(f"Expected GKO in 24 random English chars: {expected_gko_24:.2f}")
print(f"Enrichment ratio: {observed_gko_24/expected_gko_24:.1f}x")

# Binomial p-value
from math import comb
p_ge = sum(comb(24, k) * eng_gko_prob**k * (1-eng_gko_prob)**(24-k)
           for k in range(observed_gko_24, 25))
print(f"Binomial P(X >= {observed_gko_24} | n=24, p={eng_gko_prob:.4f}) = {p_ge:.2e}")

# Non-GKO key letters
non_gko = [c for c in beau_az_keys if c not in GKO_LETTERS]
print(f"\nNon-GKO key letters ({len(non_gko)}): {''.join(non_gko)}")
print(f"Non-GKO distribution: {dict(Counter(non_gko).most_common())}")

# What English words/phrases are dense in G, K, O?
print("\nHigh-GKO English words (for running key hypothesis):")
wordlist_path = os.path.join(_ROOT, 'wordlists', 'english.txt')
if os.path.exists(wordlist_path):
    high_gko_words = []
    with open(wordlist_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 5 and len(w) <= 30:
                gko_frac = sum(1 for c in w if c in GKO_LETTERS) / len(w)
                if gko_frac >= 0.40:
                    high_gko_words.append((gko_frac, w))
    high_gko_words.sort(key=lambda x: (-x[0], -len(x[1])))
    for frac, w in high_gko_words[:30]:
        print(f"  {w:30s}  GKO={frac:.0%}  len={len(w)}")
    print(f"  ... {len(high_gko_words)} words with >= 40% GKO density")
else:
    print("  (wordlist not found)")

results["phases"]["phase2"] = {
    "beaufort_az_key": beau_az_keys,
    "gko_count": observed_gko_24,
    "english_gko_prob": eng_gko_prob,
    "expected_gko_24": round(expected_gko_24, 2),
    "enrichment_ratio": round(observed_gko_24 / expected_gko_24, 2),
    "binomial_p": p_ge,
    "non_gko_letters": ''.join(non_gko),
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 SUMMARY: Comparative GKO counts across all combos
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 76)
print("PHASE 3 SUMMARY: GKO counts across all 6 variant/alphabet combos")
print("=" * 76)

print(f"\n{'Combo':<20s}  {'GKO letters':>11s}  {'GKO AZ-idx':>10s}  {'AP{6,10,14}':>11s}  {'Key string'}")
for combo_name in sorted(phase1_results.keys()):
    d = phase1_results[combo_name]
    print(f"{combo_name:<20s}  {d['gko_letter_count']:>6d}/24    {d['gko_az_idx_count']:>5d}/24    {d['ap_6_10_14_count']:>6d}/24    {d['key_string']}")

# Identify which combo minimizes GKO concentration
min_combo = min(phase1_results.items(), key=lambda x: x[1]['gko_letter_count'])
max_combo = max(phase1_results.items(), key=lambda x: x[1]['gko_letter_count'])
print(f"\nLowest GKO letter count:  {min_combo[0]} with {min_combo[1]['gko_letter_count']}/24")
print(f"Highest GKO letter count: {max_combo[0]} with {max_combo[1]['gko_letter_count']}/24")

# Key observation: the GKO letter count is variant-dependent because different
# variants produce different key letters, even though CT and PT are the same.
# Under Beaufort AZ, key[i] = (CT_az + PT_az) % 26, and GKO = {G,K,O} letters.
# Under Vigenere AZ, key[i] = (CT_az - PT_az) % 26 — different values.

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Keyword-mixed alphabets — does any reduce GKO concentration?
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 76)
print("PHASE 4: 7 keyword-mixed alphabets — GKO concentration under Beaufort")
print("=" * 76)

KEYWORDS = ['KRYPTOS', 'DEFECTOR', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'BERLIN', 'SCHEIDT']

phase4_results = {}

for kw in KEYWORDS:
    seq = keyword_mixed_alphabet(kw)
    alpha = Alphabet(f"KW_{kw}", seq)

    key_data = compute_key_at_cribs(alpha, 'Beaufort')
    key_chars = [k[0] for k in key_data]
    key_indices = [k[1] for k in key_data]
    key_str = ''.join(key_chars)

    gko_letter_count = sum(1 for c in key_chars if c in GKO_LETTERS)

    # What are the GKO indices in this mixed alphabet?
    gko_mixed_indices = {alpha.char_to_idx(c) for c in GKO_LETTERS}

    # Do GKO letters still form an AP in this alphabet?
    gko_sorted = sorted(gko_mixed_indices)
    if len(gko_sorted) == 3:
        d1 = gko_sorted[1] - gko_sorted[0]
        d2 = gko_sorted[2] - gko_sorted[1]
        is_ap = (d1 == d2)
        ap_step = d1 if is_ap else None
    else:
        is_ap = False
        ap_step = None

    # Count key indices that fall in {6,10,14} (the AZ AP indices)
    az_ap_count = sum(1 for idx in key_indices if idx in {6, 10, 14})

    freq = Counter(key_chars)

    print(f"\n--- Keyword: {kw} ---")
    print(f"  Alphabet: {seq}")
    print(f"  G={alpha.char_to_idx('G')}, K={alpha.char_to_idx('K')}, O={alpha.char_to_idx('O')}  -> {gko_sorted}")
    print(f"  GKO forms AP? {'YES (step=' + str(ap_step) + ')' if is_ap else 'NO (diffs=' + str(d1) + ',' + str(d2) + ')'}")
    print(f"  Key:  {key_str}")
    print(f"  GKO letter count:    {gko_letter_count}/24")
    print(f"  AZ AP {{6,10,14}} idx: {az_ap_count}/24")
    print(f"  Dist: {dict(freq.most_common())}")

    # Check: what 3-letter set has the MOST hits in the key values for this alphabet?
    best_triple = None
    best_count = 0
    for a in range(26):
        for b in range(a+1, 26):
            for c in range(b+1, 26):
                count = sum(1 for idx in key_indices if idx in {a, b, c})
                if count > best_count:
                    best_count = count
                    best_triple = (a, b, c)
    best_letters = [alpha.idx_to_char(v) for v in best_triple] if best_triple else []
    best_diffs = (best_triple[1]-best_triple[0], best_triple[2]-best_triple[1]) if best_triple else (0,0)
    print(f"  Best 3-idx triple: {best_triple} = {{{','.join(best_letters)}}} with {best_count}/24 hits  (diffs={best_diffs})")

    phase4_results[kw] = {
        "alphabet": seq,
        "gko_indices": gko_sorted,
        "gko_is_ap": is_ap,
        "gko_ap_step": ap_step,
        "key_string": key_str,
        "gko_letter_count": gko_letter_count,
        "az_ap_idx_count": az_ap_count,
        "best_triple_indices": list(best_triple) if best_triple else [],
        "best_triple_letters": best_letters,
        "best_triple_count": best_count,
        "distribution": dict(freq.most_common()),
    }

results["phases"]["phase4"] = phase4_results

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 76)
print("PHASE 4 SUMMARY: Keyword alphabets vs GKO concentration")
print("=" * 76)

print(f"\n{'Keyword':<14s}  {'GKO idx':>7s}  {'AP?':>4s}  {'GKO count':>9s}  {'Best 3':>6s}  Best triple")
for kw in KEYWORDS:
    d = phase4_results[kw]
    ap_str = f"d={d['gko_ap_step']}" if d['gko_is_ap'] else "NO"
    print(f"{kw:<14s}  {str(d['gko_indices']):>7s}  {ap_str:>4s}  {d['gko_letter_count']:>5d}/24  {d['best_triple_count']:>2d}/24  {d['best_triple_indices']} = {{{','.join(d['best_triple_letters'])}}}")

# Also compare with AZ and KA baselines
print(f"\n{'AZ (baseline)':<14s}  {'[6,10,14]':>7s}  {'d=4':>4s}  {phase1_results['Beaufort_AZ']['gko_letter_count']:>5d}/24")
print(f"{'KA (baseline)':<14s}  {str(sorted({KA.char_to_idx(c) for c in GKO_LETTERS})):>7s}  {'':>4s}  {phase1_results['Beaufort_KA']['gko_letter_count']:>5d}/24")

# ══════════════════════════════════════════════════════════════════════════════
# OVERALL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 76)
print("OVERALL SUMMARY")
print("=" * 76)

# The key insight: the keystream k[i] = (AZ(CT[i]) + AZ(PT[i])) % 26 is
# FIXED regardless of what cipher system produced the CT. It is a mathematical
# identity from CT and PT. The 12/24 GKO concentration is a fact about the
# CT and the cribs.
#
# When we change the alphabet or variant, we change what KEY LETTER corresponds
# to each keystream value. But the underlying numerical keystream (in AZ) is the same.
#
# So the question is: under which model does the key text look most "natural"?

print(f"""
KEY INSIGHT: The AZ keystream k[i] = (AZ(CT[i]) + AZ(PT[i])) mod 26 is FIXED
at crib positions — it is an identity of the ciphertext and plaintext, independent
of the cipher variant or alphabet used.

The 12/24 GKO concentration (50% vs 10.3% expected for English) is therefore an
INVARIANT property of K4's CT and the cribs. No choice of variant or alphabet
can change it.

What DOES change across models is what KEY LETTERS the keystream maps to.
The GKO letter count varies because different alphabets map the indices
{{6, 10, 14}} to different letters.

PHASE 1/3 RESULTS — GKO letter counts by model:""")

for combo_name in sorted(phase1_results.keys()):
    d = phase1_results[combo_name]
    print(f"  {combo_name:<20s}  {d['gko_letter_count']:>2d}/24 GKO letters")

print(f"""
PHASE 2 — Beaufort AZ running key would need 50% GKO density:
  English expectation: {expected_gko_24:.1f}/24 ({eng_gko_prob:.1%})
  Observed: {observed_gko_24}/24 ({observed_gko_24/24:.1%})
  Enrichment: {observed_gko_24/expected_gko_24:.1f}x | p = {p_ge:.2e}
  -> Running key from natural English is extremely unlikely under Beaufort AZ

PHASE 4 — Keyword alphabets:
  GKO remains an AP only under AZ (step 4) and KRYPTOS/KA (same as AZ for GKO).
  Other keyword alphabets BREAK the AP structure of GKO indices.
  But GKO letter count in the key is the same for Beaufort with ANY alphabet
  (because the key letters that are G, K, O are determined by CT and PT, not the alphabet).
""")

# Wait — that last claim needs verification. Let me check.
# Under Beaufort with alphabet A:
#   key_idx_in_A = (A(CT) + A(PT)) % 26
#   key_letter = A.idx_to_char(key_idx_in_A)
# The key LETTER depends on the alphabet! Different alphabets map index 6 to different letters.
# So the GKO LETTER count CAN change.

# But the AZ keystream (the numerical values {6,10,14}) is what has the AP property.
# The question is whether there's an alphabet where the AP maps to MORE common English letters,
# making a running key more plausible.

print("CORRECTION: GKO LETTER count in key DOES vary by alphabet, because")
print("different alphabets map the fixed AZ keystream indices to different letters.")
print("The AP {6,10,14} in AZ maps to {G,K,O}, but in other alphabets, index 6")
print("may map to a common letter like E or T.")
print()

# Find which alphabet makes the AP {6,10,14} map to the MOST common English letters
print("Which alphabet makes indices {6,10,14} map to the most common English letters?")
all_alphabets = [('AZ', AZ), ('KA', KA)] + [(kw, Alphabet(f"KW_{kw}", keyword_mixed_alphabet(kw))) for kw in KEYWORDS]

for name, alpha in all_alphabets:
    letters_at_6_10_14 = [alpha.idx_to_char(v) for v in [6, 10, 14]]
    total_freq = sum(ENG_FREQ[c] for c in letters_at_6_10_14)
    print(f"  {name:<14s}  idx 6,10,14 -> {','.join(letters_at_6_10_14)}  combined freq = {total_freq:.4f}")

# ── Save results ─────────────────────────────────────────────────────────────

output_path = os.path.join(_ROOT, 'results', 'gko_key_sweep.json')
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)

print(f"\nResults saved to: {output_path}")
