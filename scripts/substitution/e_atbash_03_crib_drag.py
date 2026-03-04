#!/usr/bin/env python3
"""
Cipher: monoalphabetic substitution
Family: substitution
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-ATBASH-03: Exhaustive crib-dragging on Atbash(K4) hypothesis.

Hypothesis: The carved K4 text was Atbash-encoded, so the REAL ciphertext
is Atbash(carved_text). We crib-drag EASTNORTHEAST and BERLINCLOCK across
the Atbash CT under Vigenere and Beaufort key models, looking for:
  - Periodic key fragments matching KRYPTOS (period 7) or PALIMPSEST (period 10)
  - Consistent key when BOTH cribs are placed simultaneously
  - Bean constraint satisfaction
  - Key at original crib positions (21-33, 63-73) in the Atbash CT

Usage:
    PYTHONPATH=src python3 -u scripts/e_atbash_03_crib_drag.py
"""
from __future__ import annotations

import itertools
import string
from collections import defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_WORDS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

# ── Atbash transform ──────────────────────────────────────────────────────

def atbash(text: str) -> str:
    """Atbash: A<->Z, B<->Y, ..., M<->N."""
    return "".join(chr(ord("Z") - (ord(c) - ord("A"))) for c in text)

# ── Key extraction helpers ─────────────────────────────────────────────────

def vig_key_letter(ct_char: str, pt_char: str) -> int:
    """Vigenere: key = (CT - PT) mod 26."""
    return (ALPH_IDX[ct_char] - ALPH_IDX[pt_char]) % MOD

def beau_key_letter(ct_char: str, pt_char: str) -> int:
    """Beaufort: key = (CT + PT) mod 26 ... actually key = (PT - CT) mod 26.
    Standard Beaufort: CT = (K - PT) mod 26, so K = (CT + PT) mod 26.
    Wait -- let's be precise per CLAUDE.md:
      Vigenere: K = (CT - PT) mod 26
      Beaufort: K = (CT + PT) mod 26
      Variant Beaufort: K = (PT - CT) mod 26
    """
    return (ALPH_IDX[ct_char] + ALPH_IDX[pt_char]) % MOD

def varbeau_key_letter(ct_char: str, pt_char: str) -> int:
    """Variant Beaufort: key = (PT - CT) mod 26."""
    return (ALPH_IDX[pt_char] - ALPH_IDX[ct_char]) % MOD

def idx_to_letter(i: int) -> str:
    return ALPH[i % MOD]

# ── Known keywords ─────────────────────────────────────────────────────────

KEYWORDS = {
    "KRYPTOS":    [ALPH_IDX[c] for c in "KRYPTOS"],
    "PALIMPSEST": [ALPH_IDX[c] for c in "PALIMPSEST"],
    "ABSCISSA":   [ALPH_IDX[c] for c in "ABSCISSA"],
}

def check_keyword_match(key_fragment: list[int], start_pos: int, keyword: str, period: int) -> bool:
    """Check if key_fragment is consistent with keyword repeated at given period,
    starting from position start_pos in the full CT."""
    kw = KEYWORDS[keyword]
    for i, k in enumerate(key_fragment):
        expected = kw[(start_pos + i) % period]
        if k != expected:
            return False
    return True

def best_keyword_match(key_fragment: list[int], start_pos: int, keyword: str, period: int) -> int:
    """Count how many positions match keyword at given period."""
    kw = KEYWORDS[keyword]
    matches = 0
    for i, k in enumerate(key_fragment):
        expected = kw[(start_pos + i) % period]
        if k == expected:
            matches += 1
    return matches


# ── Build Atbash CT ────────────────────────────────────────────────────────

ATBASH_CT = atbash(CT)
print("=" * 80)
print("E-ATBASH-03: Crib-Dragging on Atbash(K4)")
print("=" * 80)
print()
print(f"Original CT:  {CT}")
print(f"Atbash CT:    {ATBASH_CT}")
print(f"Length: {len(ATBASH_CT)}")
print()

# Verify Atbash
assert len(ATBASH_CT) == CT_LEN
assert atbash(ATBASH_CT) == CT  # Atbash is its own inverse
print("[OK] Atbash is involutory (verified)")
print()

# ── Section 5: Bean constraint check ───────────────────────────────────────

print("=" * 80)
print("SECTION 5: Bean Constraint Under Atbash")
print("=" * 80)
print()
print(f"Original CT[27] = {CT[27]}, CT[65] = {CT[65]}  (both = P)")
print(f"Atbash  CT[27] = {ATBASH_CT[27]}, CT[65] = {ATBASH_CT[65]}")
print()
print(f"Original: PT[27] = R, PT[65] = R  (both decrypt to R)")
print(f"Bean EQ requires k[27] = k[65]")
print()

# Under Atbash CT, if PT[27]=R and PT[65]=R still:
for variant_name, key_fn in [("Vigenere", vig_key_letter), ("Beaufort", beau_key_letter), ("Var.Beaufort", varbeau_key_letter)]:
    k27 = key_fn(ATBASH_CT[27], "R")
    k65 = key_fn(ATBASH_CT[65], "R")
    print(f"  {variant_name}: k[27]={k27}({idx_to_letter(k27)}), k[65]={k65}({idx_to_letter(k65)})  "
          f"{'EQUAL (Bean PASS)' if k27 == k65 else 'NOT EQUAL (Bean FAIL)'}")

# Also check: what if the cribs DON'T apply at original positions?
# The PT letters at 27 and 65 might not be R anymore under scrambling.
# But under the Atbash hypothesis (no scrambling, just Atbash layer),
# the crib positions are fixed, so PT[27]=R, PT[65]=R still hold.
print()
print("NOTE: Under pure Atbash hypothesis (no transposition), crib positions")
print("are unchanged, so PT[27]=R and PT[65]=R still hold.")
print()

# ── Section 4: Key at original crib positions ─────────────────────────────

print("=" * 80)
print("SECTION 4: Key at Original Crib Positions (21-33, 63-73) in Atbash CT")
print("=" * 80)
print()

for crib_start, crib_word in CRIB_WORDS:
    print(f"Crib: {crib_word} at position {crib_start}")
    ct_slice = ATBASH_CT[crib_start:crib_start + len(crib_word)]
    print(f"  Atbash CT slice: {ct_slice}")
    print(f"  Plaintext:       {crib_word}")

    for variant_name, key_fn in [("Vigenere", vig_key_letter), ("Beaufort", beau_key_letter), ("Var.Beaufort", varbeau_key_letter)]:
        keys = [key_fn(ct_slice[i], crib_word[i]) for i in range(len(crib_word))]
        key_letters = "".join(idx_to_letter(k) for k in keys)
        print(f"  {variant_name:14s} key: {key_letters}  ({keys})")

        # Check against known keywords
        for kw_name, kw_period in [("KRYPTOS", 7), ("PALIMPSEST", 10), ("ABSCISSA", 8)]:
            matches = best_keyword_match(keys, crib_start, kw_name, kw_period)
            if matches >= 3:
                print(f"    -> {kw_name} (period {kw_period}): {matches}/{len(keys)} positions match")
    print()

# ── Section 1 & 2: Crib dragging each crib independently ──────────────────

print("=" * 80)
print("SECTIONS 1 & 2: Independent Crib Dragging")
print("=" * 80)
print()

def analyze_key_periodicity(keys: list[int], label: str = "") -> list[str]:
    """Look for internal periodicity in a key fragment."""
    findings = []
    n = len(keys)
    for period in range(1, n):
        matches = 0
        comparisons = 0
        for i in range(n):
            for j in range(i + 1, n):
                if (j - i) % period == 0:
                    comparisons += 1
                    if keys[i] == keys[j]:
                        matches += 1
        if comparisons > 0 and matches == comparisons:
            findings.append(f"period-{period} (all {comparisons} pairs agree)")
    return findings

# Store all single-crib placements for later cross-checking
single_crib_results = {}  # (crib_idx, pos, variant) -> key_fragment

for crib_idx, (_, crib_word) in enumerate(CRIB_WORDS):
    print(f"--- Crib: {crib_word} (len={len(crib_word)}) ---")
    print()

    best_kw_score = 0
    best_kw_info = ""

    for pos in range(CT_LEN - len(crib_word) + 1):
        ct_slice = ATBASH_CT[pos:pos + len(crib_word)]

        for variant_name, key_fn in [("Vig", vig_key_letter), ("Beau", beau_key_letter), ("VarBeau", varbeau_key_letter)]:
            keys = [key_fn(ct_slice[i], crib_word[i]) for i in range(len(crib_word))]
            single_crib_results[(crib_idx, pos, variant_name)] = keys

            # Check keyword matches
            for kw_name, kw_period in [("KRYPTOS", 7), ("PALIMPSEST", 10), ("ABSCISSA", 8)]:
                matches = best_keyword_match(keys, pos, kw_name, kw_period)
                threshold = max(4, len(crib_word) // 2)
                if matches >= threshold:
                    key_letters = "".join(idx_to_letter(k) for k in keys)
                    info = (f"  pos={pos:2d} {variant_name:8s} key={key_letters} "
                            f"kw={kw_name} period={kw_period} matches={matches}/{len(crib_word)}")
                    if matches > best_kw_score:
                        best_kw_score = matches
                        best_kw_info = info
                    if matches >= threshold + 1:
                        print(info)

            # Check internal periodicity
            periodicities = analyze_key_periodicity(keys)
            if periodicities:
                key_letters = "".join(idx_to_letter(k) for k in keys)
                for p in periodicities:
                    if not p.startswith("period-1 "):  # Skip trivial all-same
                        pass  # Too many, only print really interesting ones

                # Only print if ALL key letters are the same (Caesar shift)
                if len(set(keys)) == 1:
                    print(f"  pos={pos:2d} {variant_name:8s} key={key_letters} -> CAESAR (all same key letter)")

    if best_kw_score >= 4:
        print(f"\n  Best keyword match: {best_kw_info}")
    print()

# ── Section 3: Dual crib placement with keyword consistency ────────────────

print("=" * 80)
print("SECTION 3: Dual Crib Placement — Keyword Consistency Check")
print("=" * 80)
print()

crib_ene = CRIB_WORDS[0][1]  # EASTNORTHEAST
crib_bc = CRIB_WORDS[1][1]   # BERLINCLOCK
len_ene = len(crib_ene)      # 13
len_bc = len(crib_bc)        # 11

def ranges_overlap(s1: int, l1: int, s2: int, l2: int) -> bool:
    """Check if [s1, s1+l1) and [s2, s2+l2) overlap."""
    return s1 < s2 + l2 and s2 < s1 + l1

# For each keyword and variant, try all valid position pairs
print("Testing all valid (pos_ENE, pos_BC) pairs for keyword consistency...")
print(f"  ENE positions: 0..{CT_LEN - len_ene}")
print(f"  BC  positions: 0..{CT_LEN - len_bc}")
print()

best_results = []  # (score, description)

for variant_name, key_fn in [("Vig", vig_key_letter), ("Beau", beau_key_letter), ("VarBeau", varbeau_key_letter)]:
    for kw_name, kw_period in [("KRYPTOS", 7), ("PALIMPSEST", 10), ("ABSCISSA", 8)]:
        kw = KEYWORDS[kw_name]

        local_best_score = 0
        local_best_info = ""

        for pos_ene in range(CT_LEN - len_ene + 1):
            # Pre-compute ENE key
            ene_keys = single_crib_results.get((0, pos_ene, variant_name))
            if ene_keys is None:
                continue

            # Count ENE matches with keyword
            ene_matches = 0
            for i, k in enumerate(ene_keys):
                if k == kw[(pos_ene + i) % kw_period]:
                    ene_matches += 1

            # Skip if ENE alone has too few matches
            if ene_matches < 3:
                continue

            for pos_bc in range(CT_LEN - len_bc + 1):
                # Skip overlapping placements
                if ranges_overlap(pos_ene, len_ene, pos_bc, len_bc):
                    continue

                bc_keys = single_crib_results.get((1, pos_bc, variant_name))
                if bc_keys is None:
                    continue

                # Count BC matches
                bc_matches = 0
                for i, k in enumerate(bc_keys):
                    if k == kw[(pos_bc + i) % kw_period]:
                        bc_matches += 1

                total = ene_matches + bc_matches
                if total > local_best_score:
                    local_best_score = total

                    # Build combined key picture
                    full_key = [None] * CT_LEN
                    for i, k in enumerate(ene_keys):
                        full_key[pos_ene + i] = k
                    for i, k in enumerate(bc_keys):
                        full_key[pos_bc + i] = k

                    key_str = ""
                    for fk in full_key:
                        key_str += idx_to_letter(fk) if fk is not None else "."

                    local_best_info = (
                        f"{variant_name:8s} kw={kw_name:10s} period={kw_period:2d}  "
                        f"ENE@{pos_ene:2d}({ene_matches}/{len_ene}) "
                        f"BC@{pos_bc:2d}({bc_matches}/{len_bc}) "
                        f"total={total}/24"
                    )

        if local_best_score >= 10:
            best_results.append((local_best_score, local_best_info))
            print(f"  {local_best_info}")

if not best_results:
    print("  No dual placement achieved >= 10/24 keyword matches.")

# Sort and show top results
best_results.sort(key=lambda x: -x[0])
if best_results:
    print(f"\n  Top 10 dual placements:")
    for score, info in best_results[:10]:
        print(f"    {info}")
print()

# ── Section 3b: Check ALL keyword matches exhaustively (lower threshold) ──

print("=" * 80)
print("SECTION 3b: Top Dual Placements by Total Key Matches (any keyword)")
print("=" * 80)
print()

# Collect the absolute best for each variant x keyword
all_dual = []

for variant_name, key_fn in [("Vig", vig_key_letter), ("Beau", beau_key_letter), ("VarBeau", varbeau_key_letter)]:
    for kw_name, kw_period in [("KRYPTOS", 7), ("PALIMPSEST", 10), ("ABSCISSA", 8)]:
        kw = KEYWORDS[kw_name]

        best_score = 0
        best_positions = (0, 0)
        best_ene_m = 0
        best_bc_m = 0

        for pos_ene in range(CT_LEN - len_ene + 1):
            ene_keys = single_crib_results.get((0, pos_ene, variant_name))
            if ene_keys is None:
                continue
            ene_matches = sum(1 for i, k in enumerate(ene_keys) if k == kw[(pos_ene + i) % kw_period])

            for pos_bc in range(CT_LEN - len_bc + 1):
                if ranges_overlap(pos_ene, len_ene, pos_bc, len_bc):
                    continue
                bc_keys = single_crib_results.get((1, pos_bc, variant_name))
                if bc_keys is None:
                    continue
                bc_matches = sum(1 for i, k in enumerate(bc_keys) if k == kw[(pos_bc + i) % kw_period])

                total = ene_matches + bc_matches
                if total > best_score:
                    best_score = total
                    best_positions = (pos_ene, pos_bc)
                    best_ene_m = ene_matches
                    best_bc_m = bc_matches

        pos_ene, pos_bc = best_positions
        all_dual.append((best_score, variant_name, kw_name, kw_period, pos_ene, pos_bc, best_ene_m, best_bc_m))

all_dual.sort(key=lambda x: -x[0])
print(f"{'Score':>5s}  {'Variant':8s}  {'Keyword':10s}  {'Per':>3s}  {'ENE@':>5s}  {'BC@':>5s}  {'ENE':>4s}  {'BC':>4s}")
print("-" * 60)
for score, variant, kw, period, pe, pb, em, bm in all_dual:
    print(f"{score:5d}  {variant:8s}  {kw:10s}  {period:3d}  {pe:5d}  {pb:5d}  {em:3d}/{len_ene}  {bm:3d}/{len_bc}")
print()

# ── Section 3c: Overlap agreement check ───────────────────────────────────

print("=" * 80)
print("SECTION 3c: Key Overlap Agreement (positions where both cribs define key)")
print("=" * 80)
print()

# This can only happen if cribs overlap, which we excluded above.
# Instead, check: for the top placements, does the key at overlapping
# KEYWORD PERIOD positions agree?

for score, variant, kw, period, pe, pb, em, bm in all_dual[:5]:
    ene_keys = single_crib_results[(0, pe, variant)]
    bc_keys = single_crib_results[(1, pb, variant)]

    # Build position -> key mapping
    key_map = {}
    conflicts = 0
    for i, k in enumerate(ene_keys):
        pos = pe + i
        key_map[pos] = k
    for i, k in enumerate(bc_keys):
        pos = pb + i
        if pos in key_map:
            if key_map[pos] != k:
                conflicts += 1
            # This means cribs overlap (shouldn't happen given our filter)
        key_map[pos] = k

    # Check period-consistency: for positions in same residue class, do keys agree?
    residue_keys = defaultdict(list)
    for pos, k in sorted(key_map.items()):
        residue_keys[pos % period].append((pos, k))

    period_conflicts = 0
    period_agreements = 0
    for residue, entries in residue_keys.items():
        if len(entries) > 1:
            vals = [e[1] for e in entries]
            for i in range(len(vals)):
                for j in range(i + 1, len(vals)):
                    if vals[i] == vals[j]:
                        period_agreements += 1
                    else:
                        period_conflicts += 1

    key_letters = "".join(idx_to_letter(k) for _, k in sorted(key_map.items()))
    print(f"  {variant} kw={kw} p={period} ENE@{pe} BC@{pb}: "
          f"period-agreements={period_agreements}, period-conflicts={period_conflicts}")
    if period_agreements > 0 and period_conflicts == 0:
        print(f"    *** PERFECT period consistency! ***")

    # Show the actual key at each residue class
    if period <= 10:
        for r in range(period):
            entries = residue_keys.get(r, [])
            if entries:
                vals = [idx_to_letter(e[1]) for e in entries]
                positions = [e[0] for e in entries]
                unique = set(vals)
                marker = " <-- ALL AGREE" if len(unique) == 1 and len(vals) > 1 else ""
                print(f"    residue {r}: positions {positions} -> keys {vals}{marker}")
    print()

# ── Section 6: Self-encrypting position check ─────────────────────────────

print("=" * 80)
print("SECTION 6: Self-Encrypting Position Check Under Atbash")
print("=" * 80)
print()

print("Under original CT: CT[32]=S, PT[32]=S and CT[73]=K, PT[73]=K")
print(f"Under Atbash CT:   CT[32]={ATBASH_CT[32]}, CT[73]={ATBASH_CT[73]}")
print()
print("For self-encryption to hold in Atbash CT, we'd need:")
print(f"  CT[32]={ATBASH_CT[32]} == PT[32]=S?  {'YES' if ATBASH_CT[32] == 'S' else 'NO'}")
print(f"  CT[73]={ATBASH_CT[73]} == PT[73]=K?  {'YES' if ATBASH_CT[73] == 'K' else 'NO'}")
print()
print("Self-encrypting positions under Vigenere (key=0=A) or Beaufort:")
for i in range(CT_LEN):
    if ATBASH_CT[i] == CT[i]:
        print(f"  Position {i}: Atbash CT = Original CT = {CT[i]}  (Atbash fixpoint)")
# Atbash fixpoint is only N (13th letter, maps to N under A<->Z = 0<->25, 13<->12...
# actually A(0)<->Z(25), B(1)<->Y(24)... M(12)<->N(13). NO fixpoint.)
print("  (Atbash has no fixpoints: no letter maps to itself)")
print()

# ── Section 7: Frequency analysis of Atbash CT ────────────────────────────

print("=" * 80)
print("SECTION 7: Frequency Analysis of Atbash CT")
print("=" * 80)
print()

from collections import Counter
freq = Counter(ATBASH_CT)
for ch, count in sorted(freq.items(), key=lambda x: -x[1]):
    bar = "#" * count
    print(f"  {ch}: {count:2d}  {bar}")
print()

# IC of Atbash CT (should be same as original since Atbash is a substitution)
n = CT_LEN
ic = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
print(f"  IC of Atbash CT: {ic:.4f}  (same as original: {0.0361:.4f})")
print()

# ── Section 8: What if key is also Atbash-related? ─────────────────────────

print("=" * 80)
print("SECTION 8: Special Key Patterns Under Atbash CT")
print("=" * 80)
print()
print("Check: if the key is 'KRYPTOS' Atbash'd = ", atbash("KRYPTOS"))
print("Check: if the key is 'PALIMPSEST' Atbash'd = ", atbash("PALIMPSEST"))
print("Check: if the key is 'ABSCISSA' Atbash'd = ", atbash("ABSCISSA"))
print()

# Add these Atbash'd keywords to our keyword list and recheck at original positions
extra_keywords = {
    "PIBYGLH": [ALPH_IDX[c] for c in atbash("KRYPTOS")],     # Atbash(KRYPTOS)
    "KZORNKHVG": [ALPH_IDX[c] for c in atbash("PALIMPSEST")], # Atbash(PALIMPSEST)
    "ZYHHRHhz": None  # skip if not valid
}

# Actually compute properly
for kw_orig in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    kw_atbash = atbash(kw_orig)
    kw_vals = [ALPH_IDX[c] for c in kw_atbash]
    period = len(kw_orig)

    print(f"Keyword: Atbash({kw_orig}) = {kw_atbash}, period={period}")

    # Check at original crib positions
    for crib_start, crib_word in CRIB_WORDS:
        ct_slice = ATBASH_CT[crib_start:crib_start + len(crib_word)]

        for variant_name, key_fn in [("Vig", vig_key_letter), ("Beau", beau_key_letter)]:
            keys = [key_fn(ct_slice[i], crib_word[i]) for i in range(len(crib_word))]
            matches = 0
            for i, k in enumerate(keys):
                expected = kw_vals[(crib_start + i) % period]
                if k == expected:
                    matches += 1
            if matches >= 3:
                key_letters = "".join(idx_to_letter(k) for k in keys)
                print(f"  {crib_word}@{crib_start} {variant_name}: key={key_letters}, matches={matches}/{len(crib_word)}")
    print()

# ── Section 9: Try with KA alphabet for key derivation ─────────────────────

print("=" * 80)
print("SECTION 9: KA-Alphabet Key Derivation at Original Positions")
print("=" * 80)
print()

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

def vig_key_ka(ct_char: str, pt_char: str) -> int:
    """Vigenere key in KA alphabet: key = (CT_ka - PT_ka) mod 26."""
    return (KA_IDX[ct_char] - KA_IDX[pt_char]) % MOD

def beau_key_ka(ct_char: str, pt_char: str) -> int:
    """Beaufort key in KA alphabet: key = (CT_ka + PT_ka) mod 26."""
    return (KA_IDX[ct_char] + KA_IDX[pt_char]) % MOD

for crib_start, crib_word in CRIB_WORDS:
    ct_slice = ATBASH_CT[crib_start:crib_start + len(crib_word)]
    print(f"Crib: {crib_word} @ pos {crib_start}")
    print(f"  Atbash CT: {ct_slice}")

    for variant_name, key_fn in [("Vig/KA", vig_key_ka), ("Beau/KA", beau_key_ka)]:
        keys = [key_fn(ct_slice[i], crib_word[i]) for i in range(len(crib_word))]
        key_letters_ka = "".join(KRYPTOS_ALPHABET[k] for k in keys)
        key_letters_az = "".join(idx_to_letter(k) for k in keys)
        print(f"  {variant_name:10s} indices: {keys}")
        print(f"  {variant_name:10s} KA-key:  {key_letters_ka}")
        print(f"  {variant_name:10s} AZ-key:  {key_letters_az}")

        # Check keyword matches
        for kw_name, kw_period in [("KRYPTOS", 7), ("PALIMPSEST", 10), ("ABSCISSA", 8)]:
            kw_ka = [KA_IDX[c] for c in kw_name]
            matches = sum(1 for i, k in enumerate(keys) if k == kw_ka[(crib_start + i) % kw_period])
            if matches >= 3:
                print(f"    {kw_name} (KA, period {kw_period}): {matches}/{len(crib_word)} match")
    print()

# ── Section 10: Full decryption attempt with best keyword candidates ───────

print("=" * 80)
print("SECTION 10: Full Decryption Attempts")
print("=" * 80)
print()

def decrypt_vig(ct: str, key: str) -> str:
    """Decrypt ct with repeating Vigenere key. PT = (CT - K) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        k = ALPH_IDX[key[i % len(key)]]
        p = (ALPH_IDX[c] - k) % MOD
        pt.append(ALPH[p])
    return "".join(pt)

def decrypt_beau(ct: str, key: str) -> str:
    """Decrypt ct with repeating Beaufort key. PT = (K - CT) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        k = ALPH_IDX[key[i % len(key)]]
        p = (k - ALPH_IDX[c]) % MOD
        pt.append(ALPH[p])
    return "".join(pt)

def decrypt_varbeau(ct: str, key: str) -> str:
    """Decrypt ct with repeating Variant Beaufort. PT = (CT + K) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        k = ALPH_IDX[key[i % len(key)]]
        p = (ALPH_IDX[c] + k) % MOD
        pt.append(ALPH[p])
    return "".join(pt)

# Try various keywords on Atbash CT
test_keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA",
                  atbash("KRYPTOS"), atbash("PALIMPSEST"), atbash("ABSCISSA")]

for kw in test_keywords:
    for dec_name, dec_fn in [("Vig", decrypt_vig), ("Beau", decrypt_beau), ("VarBeau", decrypt_varbeau)]:
        pt = dec_fn(ATBASH_CT, kw)

        # Check for cribs
        ene_count = 0
        bc_count = 0
        for pos in range(len(pt) - 12):
            if pt[pos:pos+13] == "EASTNORTHEAST":
                ene_count += 1
            if pos < len(pt) - 10:
                if pt[pos:pos+11] == "BERLINCLOCK":
                    bc_count += 1

        # Check at original positions
        ene_at_orig = pt[21:34] == "EASTNORTHEAST"
        bc_at_orig = pt[63:74] == "BERLINCLOCK"

        # Count individual crib letter matches at original positions
        ene_chars = sum(1 for i, ch in enumerate("EASTNORTHEAST") if pt[21+i] == ch)
        bc_chars = sum(1 for i, ch in enumerate("BERLINCLOCK") if pt[63+i] == ch)
        total = ene_chars + bc_chars

        if total >= 5:
            print(f"  kw={kw:12s} {dec_name:8s}: ENE@21={ene_chars}/13, BC@63={bc_chars}/11, total={total}/24")
            print(f"    PT: {pt}")
            print()

# ── Section 11: Brute force short keywords (1-4 letters) on Atbash CT ─────

print("=" * 80)
print("SECTION 11: Brute-Force Short Keywords (len 1-4) on Atbash CT")
print("=" * 80)
print()

best_brute = []
for key_len in range(1, 5):
    for combo in itertools.product(range(26), repeat=key_len):
        key = "".join(ALPH[c] for c in combo)

        for dec_name, dec_fn in [("Vig", decrypt_vig), ("Beau", decrypt_beau)]:
            pt = dec_fn(ATBASH_CT, key)

            # Score against cribs at ALL positions
            best_total = 0
            best_pos = (-1, -1)

            # Only check original positions for speed in brute force
            ene_chars = sum(1 for i, ch in enumerate("EASTNORTHEAST") if pt[21+i] == ch)
            bc_chars = sum(1 for i, ch in enumerate("BERLINCLOCK") if pt[63+i] == ch)
            total = ene_chars + bc_chars

            if total >= 8:
                best_brute.append((total, key, dec_name, ene_chars, bc_chars, pt))

best_brute.sort(key=lambda x: -x[0])
if best_brute:
    print(f"Top results (score >= 8/24):")
    for total, key, dec, ene, bc, pt in best_brute[:20]:
        print(f"  key={key:4s} {dec:5s}: ENE={ene}/13 BC={bc}/11 total={total}/24")
        print(f"    PT: {pt[:50]}...")
else:
    print("  No short keywords scored >= 8/24 at original crib positions.")
print()

# ── Final Summary ──────────────────────────────────────────────────────────

print("=" * 80)
print("FINAL SUMMARY")
print("=" * 80)
print()
print(f"Atbash CT: {ATBASH_CT}")
print()
print("Bean EQ under Atbash (positions 27, 65):")
for variant_name, key_fn in [("Vig", vig_key_letter), ("Beau", beau_key_letter), ("VarBeau", varbeau_key_letter)]:
    k27 = key_fn(ATBASH_CT[27], "R")
    k65 = key_fn(ATBASH_CT[65], "R")
    status = "PASS" if k27 == k65 else "FAIL"
    print(f"  {variant_name:10s}: k[27]={idx_to_letter(k27)} k[65]={idx_to_letter(k65)} -> Bean {status}")
print()

# Check if any dual placement hit >= 12/24
threshold_hits = [x for x in all_dual if x[0] >= 12]
if threshold_hits:
    print(f"Dual placements with >= 12/24 keyword matches: {len(threshold_hits)}")
    for score, variant, kw, period, pe, pb, em, bm in threshold_hits:
        print(f"  {score}/24: {variant} kw={kw} p={period} ENE@{pe} BC@{pb}")
else:
    print("No dual placement achieved >= 12/24 keyword matches.")
    print(f"Best dual placement: {all_dual[0][0]}/24 ({all_dual[0][1]} kw={all_dual[0][2]})")

print()
print("CONCLUSION: See above for detailed analysis. If no section shows")
print("BREAKTHROUGH-level matches (24/24 with Bean PASS), the Atbash")
print("hypothesis does not directly yield K4's plaintext with tested keywords.")
print()
print("[E-ATBASH-03 COMPLETE]")
