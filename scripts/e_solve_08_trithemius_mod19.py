#!/usr/bin/env python3
"""
E-SOLVE-08: Trithemius Slope + Mod-19 Component Hypotheses

Tests the two strongest findings from deep keystream analysis:

H24: Trithemius-like progressive cipher (CT = PT + c*i + R) mod 26
     At slope c=5, Vigenère residual at ENE contains "ICTORI" (6 consecutive
     English chars). Unique among 78 slope/convention tests.

H25: Period-19 key component
     Both Bean EQ (k[27]=k[65]) and k[31]=k[69]=10 are explained by
     positions ≡ mod 19. Test period-19 + secondary component.

H26: Combined c*i + period-p component
     CT[i] = PT[i] + c*i + periodic_key[i%p] (mod 26)

H27: Beaufort + period-19 component (Beaufort more structured, 1200x)
     Test K(i) = base[i%19] + slope*i (mod 26) under Beaufort convention.
"""

import sys
sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

CT_VALS = [ALPH_IDX[c] for c in CT]

# Known keystream at crib positions
VIG_KEY = {}
for i, v in enumerate(VIGENERE_KEY_ENE):
    VIG_KEY[21 + i] = v
for i, v in enumerate(VIGENERE_KEY_BC):
    VIG_KEY[63 + i] = v

BEAU_KEY = {}
for i, v in enumerate(BEAUFORT_KEY_ENE):
    BEAU_KEY[21 + i] = v
for i, v in enumerate(BEAUFORT_KEY_BC):
    BEAU_KEY[63 + i] = v


def check_bean(key_vals):
    """Check Bean EQ and INEQ on a full 97-length key array."""
    for a, b in BEAN_EQ:
        if key_vals[a] != key_vals[b]:
            return False
    for a, b in BEAN_INEQ:
        if key_vals[a] == key_vals[b]:
            return False
    return True


def crib_score(key_vals, mode="vig"):
    """Score key_vals against known crib keystream values."""
    ref = VIG_KEY if mode == "vig" else BEAU_KEY
    matches = 0
    for pos, expected in ref.items():
        if key_vals[pos] == expected:
            matches += 1
    return matches


def decrypt_vig(key_vals):
    """Decrypt CT with Vigenère key: PT = (CT - K) mod 26"""
    return "".join(ALPH[(CT_VALS[i] - key_vals[i]) % MOD] for i in range(CT_LEN))


def decrypt_beau(key_vals):
    """Decrypt CT with Beaufort key: PT = (K - CT) mod 26"""
    return "".join(ALPH[(key_vals[i] - CT_VALS[i]) % MOD] for i in range(CT_LEN))


def english_words_in(text, min_len=4):
    """Quick check for English word fragments."""
    words = []
    known_words = {
        "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "CAN",
        "HER", "WAS", "ONE", "OUR", "OUT", "HIS", "HAS", "HAD", "HOW",
        "WHO", "OIL", "DID", "GET", "HIM", "WITH", "THAT", "THIS",
        "HAVE", "FROM", "THEY", "BEEN", "SAID", "EACH", "WILL",
        "THEIR", "THERE", "ABOUT", "WOULD", "COULD", "WHICH",
        "NORTH", "SOUTH", "EAST", "WEST", "CLOCK", "LIGHT", "DARK",
        "BERLIN", "SHADOW", "UNDER", "GROUND", "SLOWLY", "LAYER",
        "POINT", "LOCATION", "ENTRANCE", "BETWEEN", "SUBTLE",
        "SHADING", "ABSENCE", "DEGREES", "VISIBLE", "BURIED",
        "VICTORIA", "VICTORY", "PICTORIAL", "HISTORY", "FACTORY",
        "ICTORI",  # the key fragment we found
        "SECRET", "HIDDEN", "CIPHER", "CODE", "KRYPTOS",
        "WATER", "STONE", "COPPER", "TIME", "TOMB", "DOOR",
        "OPEN", "CLOSE", "NEAR", "TURN", "STEP", "LOOK", "FIND",
    }
    text_upper = text.upper()
    for w in known_words:
        if len(w) >= min_len and w in text_upper:
            words.append(w)
    return words


def ic(text):
    """Index of coincidence."""
    from collections import Counter
    n = len(text)
    if n < 2:
        return 0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def vowel_pct(text):
    return sum(1 for c in text if c in "AEIOU") / len(text) * 100


# ======================================================================
print("E-SOLVE-08: Trithemius Slope + Mod-19 Component Hypotheses")
print(f"CT: {CT[:50]}...")
print()

total_tested = 0
above_noise = 0
best_score = 0
best_config = ""
best_pt = ""

# ======================================================================
# H24: Trithemius-like key: k[i] = c*i + offset (mod 26)
# Test all slopes c=0..25, offsets o=0..25
# Also test: k[i] = c*i + periodic_component[i%p]
# ======================================================================
print("=" * 70)
print("TEST 1: Pure Trithemius — k[i] = c*i + offset (mod 26)")
print("=" * 70)

t1_count = 0
t1_above = 0

for c in range(26):
    for offset in range(26):
        key = [(c * i + offset) % MOD for i in range(CT_LEN)]

        for mode, decrypt in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
            score = crib_score(key, mode)
            t1_count += 1

            if score > 6:
                t1_above += 1
                pt = decrypt(key)
                bean = check_bean(key)
                print(f"  c={c} offset={offset} ({mode}): score={score}/24, Bean={'PASS' if bean else 'FAIL'}")
                print(f"    PT: {pt[:50]}...")

                if score > best_score:
                    best_score = score
                    best_config = f"H24: c={c} offset={offset} ({mode})"
                    best_pt = pt

total_tested += t1_count
above_noise += t1_above
print(f"\n  Pure Trithemius: {t1_count} tested, {t1_above} above noise\n")

# ======================================================================
# H25: Period-19 key component
# k[i] = base_key[i % 19] (mod 26), test all 26^constraint positions
# We have constraints at specific i%19 residues from the cribs
# ======================================================================
print("=" * 70)
print("TEST 2: Period-19 Key (informed by mod-19 pattern)")
print("=" * 70)

# Map crib positions to their mod-19 residue
residue_constraints_vig = {}  # residue -> set of required values
residue_constraints_beau = {}

for pos in sorted(VIG_KEY.keys()):
    r = pos % 19
    residue_constraints_vig.setdefault(r, []).append((pos, VIG_KEY[pos]))

for pos in sorted(BEAU_KEY.keys()):
    r = pos % 19
    residue_constraints_beau.setdefault(r, []).append((pos, BEAU_KEY[pos]))

print("  Vigenère residue constraints (mod 19):")
consistent_vig = True
for r in sorted(residue_constraints_vig.keys()):
    entries = residue_constraints_vig[r]
    vals = set(v for _, v in entries)
    status = "CONSISTENT" if len(vals) == 1 else "INCONSISTENT"
    if len(vals) > 1:
        consistent_vig = False
    print(f"    Residue {r:2d}: {entries} -> {status}")

print(f"\n  Period-19 Vigenère: {'ALL CONSISTENT' if consistent_vig else 'INCONSISTENT — period 19 not pure periodic under Vigenère'}")

print("\n  Beaufort residue constraints (mod 19):")
consistent_beau = True
for r in sorted(residue_constraints_beau.keys()):
    entries = residue_constraints_beau[r]
    vals = set(v for _, v in entries)
    status = "CONSISTENT" if len(vals) == 1 else "INCONSISTENT"
    if len(vals) > 1:
        consistent_beau = False
    print(f"    Residue {r:2d}: {entries} -> {status}")

print(f"\n  Period-19 Beaufort: {'ALL CONSISTENT' if consistent_beau else 'INCONSISTENT — period 19 not pure periodic under Beaufort'}")

# Even if inconsistent, check how many residues ARE consistent
for mode_name, constraints in [("vig", residue_constraints_vig), ("beau", residue_constraints_beau)]:
    consistent_residues = 0
    inconsistent_residues = 0
    for r, entries in constraints.items():
        vals = set(v for _, v in entries)
        if len(vals) == 1:
            consistent_residues += 1
        else:
            inconsistent_residues += 1
    print(f"  {mode_name}: {consistent_residues} consistent residues, {inconsistent_residues} inconsistent")


# ======================================================================
# H26: Combined c*i + period-p key
# k[i] = c*i + base[i%p] (mod 26)
# Test slopes c=1..25, periods p=2..26
# ======================================================================
print("\n" + "=" * 70)
print("TEST 3: Trithemius + Periodic — k[i] = c*i + base[i%p] (mod 26)")
print("=" * 70)

t3_count = 0
t3_above = 0
t3_consistent = []

for c in range(1, 26):  # skip c=0 (pure periodic, already tested extensively)
    for p in [8, 13, 16, 19, 20, 23, 24, 26]:  # Bean-compatible periods
        # Compute residual: r[i] = known_key[i] - c*i (mod 26)
        # Check if residuals are consistent with period p

        for mode_name, known_key in [("vig", VIG_KEY), ("beau", BEAU_KEY)]:
            residuals = {}  # residue -> set of values
            all_consistent = True

            for pos, kval in known_key.items():
                r = pos % p
                residual = (kval - c * pos) % MOD
                residuals.setdefault(r, set()).add(residual)

            # Check consistency
            for r, vals in residuals.items():
                if len(vals) > 1:
                    all_consistent = False
                    break

            t3_count += 1

            if all_consistent:
                # Build the full period-p base key from residuals
                base = [0] * p
                for r, vals in residuals.items():
                    base[r] = list(vals)[0]

                # Free residues get value 0 (we'll sweep them)
                constrained_residues = set(residuals.keys())
                free_residues = [r for r in range(p) if r not in constrained_residues]

                # For small number of free residues, sweep all 26^n
                n_free = len(free_residues)

                # Build full key with this base
                key = [(c * i + base[i % p]) % MOD for i in range(CT_LEN)]

                # Score against cribs
                score_v = crib_score(key, mode_name)

                if score_v >= 24:
                    pt = decrypt_vig(key) if mode_name == "vig" else decrypt_beau(key)
                    bean = check_bean(key)
                    words = english_words_in(pt)
                    pt_ic = ic(pt)
                    vp = vowel_pct(pt)

                    t3_consistent.append({
                        "c": c, "p": p, "mode": mode_name,
                        "score": score_v, "bean": bean,
                        "n_free": n_free, "base": base[:],
                        "pt": pt, "words": words, "ic": pt_ic, "vp": vp,
                    })

                    if score_v > best_score:
                        best_score = score_v
                        best_config = f"H26: c={c} p={p} ({mode_name})"
                        best_pt = pt

                    t3_above += 1

                    # Only print if Bean passes or has good secondary metrics
                    if bean or pt_ic > 0.05 or len(words) > 0:
                        print(f"  *** c={c} p={p} ({mode_name}): {score_v}/24, "
                              f"Bean={'PASS' if bean else 'FAIL'}, IC={pt_ic:.4f}, "
                              f"vowels={vp:.0f}%, free={n_free}")
                        if words:
                            print(f"      Words: {words}")
                        print(f"      PT: {pt}")
                        key_text = "".join(ALPH[k] for k in key)
                        print(f"      Key: {key_text}")

                elif score_v > 6:
                    t3_above += 1

total_tested += t3_count
above_noise += t3_above

print(f"\n  Trithemius+Periodic: {t3_count} tested, {t3_above} above noise, "
      f"{len(t3_consistent)} at 24/24")

# For 24/24 hits, check if any are NOT due to underdetermination
if t3_consistent:
    print("\n  Checking 24/24 hits for underdetermination...")
    for hit in t3_consistent[:20]:  # limit output
        n_free_ratio = hit["n_free"] / hit["p"]
        determined = "UNDERDETERMINED" if n_free_ratio > 0.4 else "CONSTRAINED"
        print(f"    c={hit['c']} p={hit['p']} ({hit['mode']}): {determined} "
              f"(free={hit['n_free']}/{hit['p']}={n_free_ratio:.1%}), "
              f"Bean={'PASS' if hit['bean'] else 'FAIL'}, IC={hit['ic']:.4f}")


# ======================================================================
# H24b: Deep dive on slope c=5 — the "ICTORI" finding
# Compute full residual R[i] = k_vig[i] - 5*i (mod 26) at crib positions
# Then try to find running key text that matches
# ======================================================================
print("\n" + "=" * 70)
print("TEST 4: Slope c=5 Deep Dive — ICTORI Residual Analysis")
print("=" * 70)

# Compute residuals at all crib positions
residual_5 = {}
for pos, kval in VIG_KEY.items():
    r = (kval - 5 * pos) % MOD
    residual_5[pos] = r

# Print the residual "key" at crib positions
ene_residuals = [residual_5[21 + i] for i in range(13)]
bc_residuals = [residual_5[63 + i] for i in range(11)]

ene_text = "".join(ALPH[v] for v in ene_residuals)
bc_text = "".join(ALPH[v] for v in bc_residuals)

print(f"  ENE residual (pos 21-33): {ene_residuals}")
print(f"  ENE as text:              {ene_text}")
print(f"  BC residual (pos 63-73):  {bc_residuals}")
print(f"  BC as text:               {bc_text}")

# Check: what if the residual R is derived from a keyword?
# R[i] = keyword[i % keyword_len]
# Test keyword lengths 1-24

print(f"\n  Testing if residual is periodic (keyword-based):")
for kw_len in range(1, 25):
    residue_vals = {}
    consistent = True
    for pos, val in residual_5.items():
        r = pos % kw_len
        if r in residue_vals:
            if residue_vals[r] != val:
                consistent = False
                break
        else:
            residue_vals[r] = val

    if consistent:
        # Build keyword
        kw = [0] * kw_len
        for r, v in residue_vals.items():
            kw[r] = v
        kw_text = "".join(ALPH[v] for v in kw)
        constrained = len(residue_vals)
        free = kw_len - constrained

        # Build full key and decrypt
        full_key = [(5 * i + kw[i % kw_len]) % MOD for i in range(CT_LEN)]
        pt = decrypt_vig(full_key)
        pt_ic = ic(pt)
        vp = vowel_pct(pt)
        words = english_words_in(pt, 3)
        bean = check_bean(full_key)

        print(f"    kw_len={kw_len:2d}: keyword={kw_text} "
              f"(constrained={constrained}, free={free}), "
              f"Bean={'PASS' if bean else 'FAIL'}, IC={pt_ic:.4f}, "
              f"vowels={vp:.0f}%")
        if words:
            print(f"      Words in PT: {words}")
        if pt_ic > 0.05 or len(words) >= 2 or bean:
            print(f"      PT: {pt}")

# Now try slope 5 with different conventions
print(f"\n  Testing slope c=5 under all conventions:")
for c in [5]:
    for mode_name, known_key, decrypt in [
        ("vig", VIG_KEY, decrypt_vig),
        ("beau", BEAU_KEY, decrypt_beau),
    ]:
        residual = {}
        for pos, kval in known_key.items():
            r = (kval - c * pos) % MOD
            residual[pos] = r

        ene_text = "".join(ALPH[(residual[21+i]) % MOD] for i in range(13))
        bc_text = "".join(ALPH[(residual[63+i]) % MOD] for i in range(11))

        print(f"\n  c={c} ({mode_name}):")
        print(f"    ENE residual text: {ene_text}")
        print(f"    BC residual text:  {bc_text}")

        # Check for English fragments
        for text, label in [(ene_text, "ENE"), (bc_text, "BC")]:
            words = english_words_in(text, 3)
            if words:
                print(f"    {label} words found: {words}")


# ======================================================================
# H24c: All slopes, all conventions — systematic fragment search
# ======================================================================
print("\n" + "=" * 70)
print("TEST 5: All Slopes — Systematic English Fragment Search")
print("=" * 70)

# Load wordlist for more thorough search
import os
wordlist_path = "wordlists/english.txt"
long_words = set()
if os.path.exists(wordlist_path):
    with open(wordlist_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 5:
                long_words.add(w)
    print(f"  Loaded {len(long_words)} words (5+ chars) from wordlist")
else:
    print("  No wordlist available, using built-in set")

def find_word_fragments(text, min_len=5):
    """Find all word fragments in text from wordlist."""
    found = []
    text = text.upper()
    for length in range(min(len(text), 13), min_len - 1, -1):
        for start in range(len(text) - length + 1):
            fragment = text[start:start+length]
            if fragment in long_words:
                found.append(fragment)
    return found

best_fragments = []

for c in range(26):
    for mode_name, known_key in [("vig", VIG_KEY), ("beau", BEAU_KEY)]:
        residuals_ene = []
        residuals_bc = []

        for i in range(13):
            pos = 21 + i
            r = (known_key[pos] - c * pos) % MOD
            residuals_ene.append(ALPH[r])

        for i in range(11):
            pos = 63 + i
            r = (known_key[pos] - c * pos) % MOD
            residuals_bc.append(ALPH[r])

        ene_text = "".join(residuals_ene)
        bc_text = "".join(residuals_bc)

        ene_words = find_word_fragments(ene_text) if long_words else english_words_in(ene_text, 5)
        bc_words = find_word_fragments(bc_text) if long_words else english_words_in(bc_text, 5)

        if ene_words or bc_words:
            total_len = sum(len(w) for w in ene_words) + sum(len(w) for w in bc_words)
            best_fragments.append({
                "c": c, "mode": mode_name,
                "ene_text": ene_text, "bc_text": bc_text,
                "ene_words": ene_words, "bc_words": bc_words,
                "total_chars": total_len,
            })

best_fragments.sort(key=lambda x: x["total_chars"], reverse=True)

print(f"\n  Slopes producing 5+ letter word fragments in residual:")
for f in best_fragments[:15]:
    print(f"    c={f['c']:2d} ({f['mode']}): ENE={f['ene_text']} BC={f['bc_text']}")
    if f['ene_words']:
        print(f"      ENE words: {f['ene_words']}")
    if f['bc_words']:
        print(f"      BC words: {f['bc_words']}")

if not best_fragments:
    print("  No 5+ letter words found in any slope residual.")


# ======================================================================
# H27: Beaufort + mod-19 partial periodicity
# Test: K_beau[i] = A[i%19] + B[i%p2] (mod 26) for various p2
# ======================================================================
print("\n" + "=" * 70)
print("TEST 6: Beaufort Two-Component Key (mod-19 + secondary period)")
print("=" * 70)

t6_count = 0
t6_above = 0

for p2 in [2, 3, 4, 5, 7, 8, 13]:
    # For each (r19, r_p2) pair, check if Beaufort key values are consistent
    pair_vals = {}  # (r19, r_p2) -> set of key values

    for pos, kval in BEAU_KEY.items():
        pair = (pos % 19, pos % p2)
        pair_vals.setdefault(pair, set()).add(kval)

    consistent = all(len(v) == 1 for v in pair_vals.values())
    n_pairs = len(pair_vals)
    n_consistent = sum(1 for v in pair_vals.values() if len(v) == 1)
    n_conflicting = sum(1 for v in pair_vals.values() if len(v) > 1)

    print(f"  p2={p2}: {n_pairs} (r19,r{p2}) pairs, "
          f"{n_consistent} consistent, {n_conflicting} conflicting "
          f"-> {'CONSISTENT' if consistent else 'INCONSISTENT'}")

    t6_count += 1

    if consistent:
        # Build base values from constraints
        # A[r19] + B[r_p2] = kval for each constrained pair
        # This is a system of linear equations mod 26
        # With n_pairs equations and 19+p2 unknowns
        print(f"    -> Would need to solve {n_pairs} eqns in {19+p2} unknowns")

        # Simple approach: fix A[0]=0, solve for rest
        # First, enumerate all A,B combinations that satisfy constraints
        # For small p2, this is feasible

        if p2 <= 5:
            found_any = False
            for a0 in range(26):
                # Try to derive other values
                A = [None] * 19
                B = [None] * p2
                A[0] = a0

                conflict = False
                changed = True
                while changed and not conflict:
                    changed = False
                    for pos, kval in BEAU_KEY.items():
                        r19 = pos % 19
                        rp2 = pos % p2

                        if A[r19] is not None and B[rp2] is not None:
                            if (A[r19] + B[rp2]) % MOD != kval:
                                conflict = True
                                break
                        elif A[r19] is not None:
                            b_val = (kval - A[r19]) % MOD
                            if B[rp2] is not None and B[rp2] != b_val:
                                conflict = True
                                break
                            B[rp2] = b_val
                            changed = True
                        elif B[rp2] is not None:
                            a_val = (kval - B[rp2]) % MOD
                            if A[r19] is not None and A[r19] != a_val:
                                conflict = True
                                break
                            A[r19] = a_val
                            changed = True

                if not conflict:
                    # Check if all constraints are satisfied
                    all_ok = True
                    for pos, kval in BEAU_KEY.items():
                        r19 = pos % 19
                        rp2 = pos % p2
                        if A[r19] is not None and B[rp2] is not None:
                            if (A[r19] + B[rp2]) % MOD != kval:
                                all_ok = False
                                break

                    if all_ok:
                        # Fill free positions with 0
                        for i in range(19):
                            if A[i] is None:
                                A[i] = 0
                        for i in range(p2):
                            if B[i] is None:
                                B[i] = 0

                        # Build full key and decrypt
                        key = [(A[i % 19] + B[i % p2]) % MOD for i in range(CT_LEN)]
                        score = crib_score(key, "beau")

                        if score >= 20:
                            pt = decrypt_beau(key)
                            bean = check_bean(key)
                            pt_ic = ic(pt)
                            vp = vowel_pct(pt)
                            words = english_words_in(pt)

                            if not found_any:
                                found_any = True

                            t6_count += 1
                            if score > 6:
                                t6_above += 1

                            if score >= 24 and (bean or pt_ic > 0.05):
                                print(f"    a0={a0}: score={score}/24, "
                                      f"Bean={'PASS' if bean else 'FAIL'}, "
                                      f"IC={pt_ic:.4f}, vowels={vp:.0f}%")
                                print(f"      A={A}")
                                print(f"      B={B}")
                                print(f"      PT: {pt}")
                                if words:
                                    print(f"      Words: {words}")

                                if score > best_score:
                                    best_score = score
                                    best_config = f"H27: p1=19 p2={p2} a0={a0} (beau)"
                                    best_pt = pt

total_tested += t6_count
above_noise += t6_above


# ======================================================================
# H24d: Slope 5 + running key from known sources
# If CT = PT + 5*i + R[i], then R[i] is the running key.
# Test R against: KRYPTOS repeated, KA alphabet, CT itself, reversed CT
# ======================================================================
print("\n" + "=" * 70)
print("TEST 7: Slope 5 + Known Running Key Sources")
print("=" * 70)

t7_count = 0
t7_above = 0

# Running key sources to test
running_key_sources = {
    "KRYPTOS_repeat": (KRYPTOS_ALPHABET * 4)[:CT_LEN],
    "KA_cyclic": (KRYPTOS_ALPHABET * 4)[:CT_LEN],
    "ALPH_repeat": (ALPH * 4)[:CT_LEN],
    "CT_itself": CT,
    "CT_reversed": CT[::-1],
    "KRYPTOS_7": ("KRYPTOS" * 14)[:CT_LEN],
    "PALIMPSEST_repeat": ("PALIMPSEST" * 10)[:CT_LEN],
    "ABSCISSA_repeat": ("ABSCISSA" * 13)[:CT_LEN],
    "DESPARATLY_repeat": ("DESPARATLY" * 10)[:CT_LEN],  # Sanborn's misspelling
    "SHADOW_repeat": ("SHADOW" * 17)[:CT_LEN],
    "EQUINOX_repeat": ("EQUINOX" * 14)[:CT_LEN],
    "VICTORIA_repeat": ("VICTORIA" * 13)[:CT_LEN],
    "KRYPTOSABCDEFGHIJLMNQUVWXZ": KRYPTOS_ALPHABET + (KRYPTOS_ALPHABET * 3)[:CT_LEN - 26],
}

for source_name, running_key in running_key_sources.items():
    running_vals = [ALPH_IDX[c] for c in running_key[:CT_LEN]]

    for slope in [5, 21]:  # 21 = -5 mod 26
        for mode in ["vig", "beau"]:
            # Build key: k[i] = slope*i + running_val[i]
            key = [(slope * i + running_vals[i]) % MOD for i in range(CT_LEN)]
            score = crib_score(key, mode)
            t7_count += 1

            if score > 6:
                t7_above += 1
                pt = decrypt_vig(key) if mode == "vig" else decrypt_beau(key)
                bean = check_bean(key)
                pt_ic = ic(pt)

                print(f"  {source_name} c={slope} ({mode}): {score}/24, "
                      f"Bean={'PASS' if bean else 'FAIL'}, IC={pt_ic:.4f}")
                if score >= 10:
                    print(f"    PT: {pt}")

                if score > best_score:
                    best_score = score
                    best_config = f"H24d: {source_name} c={slope} ({mode})"
                    best_pt = pt

total_tested += t7_count
above_noise += t7_above
print(f"\n  Running key + slope: {t7_count} tested, {t7_above} above noise\n")


# ======================================================================
# H28: Beaufort with KA-alphabet slope
# In KA space: k_ka[i] = c*i (mod 26), then map through KA alphabet
# ======================================================================
print("=" * 70)
print("TEST 8: KA-Space Trithemius (key generated in KA ordering)")
print("=" * 70)

t8_count = 0
t8_above = 0

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

for c in range(1, 26):
    for offset in range(26):
        # Key in KA space: ka_pos = c*i + offset
        # Map to standard: key_val = ALPH_IDX[KA[ka_pos % 26]]
        key = [ALPH_IDX[KRYPTOS_ALPHABET[(c * i + offset) % MOD]] for i in range(CT_LEN)]

        for mode in ["vig", "beau"]:
            score = crib_score(key, mode)
            t8_count += 1

            if score > 6:
                t8_above += 1
                pt = decrypt_vig(key) if mode == "vig" else decrypt_beau(key)
                bean = check_bean(key)

                print(f"  KA c={c} offset={offset} ({mode}): {score}/24, "
                      f"Bean={'PASS' if bean else 'FAIL'}")
                if score >= 10:
                    print(f"    PT: {pt[:60]}...")

                if score > best_score:
                    best_score = score
                    best_config = f"H28: KA c={c} offset={offset} ({mode})"
                    best_pt = pt

total_tested += t8_count
above_noise += t8_above
print(f"\n  KA-space Trithemius: {t8_count} tested, {t8_above} above noise\n")


# ======================================================================
# H29: Position-dependent variant switching
# What if some positions use Vig and others use Beaufort?
# Test: even positions Vig, odd positions Beaufort (and vice versa)
# Also: positions < 48 use one, >= 48 use other
# ======================================================================
print("=" * 70)
print("TEST 9: Variant Switching (Vig/Beau by position)")
print("=" * 70)

t9_count = 0
t9_above = 0

# For each slope, check if mixing Vig and Beau keystreams is periodic
for c in range(26):
    for split_rule in ["even_odd", "odd_even", "half_half", "half_half_rev",
                       "mod3_0", "mod3_1", "mod3_2"]:

        # Compute mixed residual
        mixed_residual = {}
        for pos in sorted(VIG_KEY.keys()):
            if split_rule == "even_odd":
                kval = VIG_KEY[pos] if pos % 2 == 0 else BEAU_KEY[pos]
            elif split_rule == "odd_even":
                kval = BEAU_KEY[pos] if pos % 2 == 0 else VIG_KEY[pos]
            elif split_rule == "half_half":
                kval = VIG_KEY[pos] if pos < 48 else BEAU_KEY[pos]
            elif split_rule == "half_half_rev":
                kval = BEAU_KEY[pos] if pos < 48 else VIG_KEY[pos]
            elif split_rule == "mod3_0":
                kval = VIG_KEY[pos] if pos % 3 == 0 else BEAU_KEY[pos]
            elif split_rule == "mod3_1":
                kval = VIG_KEY[pos] if pos % 3 == 1 else BEAU_KEY[pos]
            else:  # mod3_2
                kval = VIG_KEY[pos] if pos % 3 == 2 else BEAU_KEY[pos]

            r = (kval - c * pos) % MOD
            mixed_residual[pos] = r

        # Check periodicity of residual
        for p in [7, 8, 13, 19]:
            residue_check = {}
            consistent = True
            for pos, val in mixed_residual.items():
                r = pos % p
                if r in residue_check:
                    if residue_check[r] != val:
                        consistent = False
                        break
                else:
                    residue_check[r] = val

            t9_count += 1

            if consistent:
                t9_above += 1
                print(f"  *** c={c} split={split_rule} period={p}: CONSISTENT!")

                # Build key and decrypt
                base = [0] * p
                for r, v in residue_check.items():
                    base[r] = v

                # Need to know which convention to use at each position
                # This is complex... just decrypt and check
                key_vals = [(c * i + base[i % p]) % MOD for i in range(CT_LEN)]

                # Decrypt with Vig (the mixed residual already accounts for convention)
                pt_chars = []
                for i in range(CT_LEN):
                    if split_rule == "even_odd":
                        if i % 2 == 0:
                            pt_chars.append(ALPH[(CT_VALS[i] - key_vals[i]) % MOD])
                        else:
                            pt_chars.append(ALPH[(key_vals[i] - CT_VALS[i]) % MOD])
                    elif split_rule == "odd_even":
                        if i % 2 == 0:
                            pt_chars.append(ALPH[(key_vals[i] - CT_VALS[i]) % MOD])
                        else:
                            pt_chars.append(ALPH[(CT_VALS[i] - key_vals[i]) % MOD])
                    elif split_rule == "half_half":
                        if i < 48:
                            pt_chars.append(ALPH[(CT_VALS[i] - key_vals[i]) % MOD])
                        else:
                            pt_chars.append(ALPH[(key_vals[i] - CT_VALS[i]) % MOD])
                    elif split_rule == "half_half_rev":
                        if i < 48:
                            pt_chars.append(ALPH[(key_vals[i] - CT_VALS[i]) % MOD])
                        else:
                            pt_chars.append(ALPH[(CT_VALS[i] - key_vals[i]) % MOD])
                    else:
                        # mod3 variants - use Vig as default
                        pt_chars.append(ALPH[(CT_VALS[i] - key_vals[i]) % MOD])

                pt = "".join(pt_chars)
                words = english_words_in(pt)
                pt_ic = ic(pt)

                print(f"    PT: {pt}")
                print(f"    IC={pt_ic:.4f}, words={words}")

                if 24 > best_score:
                    best_score = 24
                    best_config = f"H29: c={c} split={split_rule} p={p}"
                    best_pt = pt

total_tested += t9_count
above_noise += t9_above
print(f"\n  Variant switching: {t9_count} tested, {t9_above} above noise\n")


# ======================================================================
# SUMMARY
# ======================================================================
print("\n" + "=" * 70)
print(f"E-SOLVE-08 COMPLETE")
print("=" * 70)
print(f"  Total configs tested: {total_tested}")
print(f"  Above noise (>6/24): {above_noise}")
print(f"  Best score: {best_score}/24")
print(f"  Best config: {best_config}")
if best_pt:
    print(f"  Best PT: {best_pt[:60]}...")
print()
