#!/usr/bin/env python3
"""
Morse Reflection Pool Theory — Supplement (K0 padding to 97, deeper combos)

Cipher: substitution + reflection
Family: grille
Status: active
Keyspace: ~400 configs
Last run: 2026-03-08
Best score: TBD

Extends e_morse_reflection_01 with:
  - K0 padding variants to reach exactly 97 chars
  - K0 reflection applied as Polybius/bifid-style operation
  - Reflection involution as cipher step in multi-layer model
  - Period analysis of reflection key
  - Systematic period testing (periods 2-26) using reflected K0 fragments
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, NOISE_FLOOR,
    ALPH, ALPH_IDX, KRYPTOS_ALPHABET, MOD,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.free_crib import score_free

# ── Morse Reflection Substitution (same as part 1) ────────────────────────

REFLECTION_PAIRS = {
    'A': 'N', 'N': 'A', 'B': 'V', 'V': 'B',
    'D': 'U', 'U': 'D', 'F': 'L', 'L': 'F',
    'G': 'W', 'W': 'G', 'Q': 'Y', 'Y': 'Q',
}
SELF_MIRROR = set('EHIKMOPRSTX')
INVALID_REFLECT = set('CJZ')

def reflect_letter(ch):
    ch = ch.upper()
    if ch in REFLECTION_PAIRS:
        return REFLECTION_PAIRS[ch]
    elif ch in SELF_MIRROR:
        return ch
    return None  # C, J, Z

def reflect_text(text, skip_invalid=True):
    result = []
    for ch in text.upper():
        if not ch.isalpha():
            continue
        r = reflect_letter(ch)
        if r is not None:
            result.append(r)
        elif not skip_invalid:
            result.append(ch)
    return ''.join(result)

def reflect_and_reverse(text, skip_invalid=True):
    return reflect_text(text, skip_invalid)[::-1]

# ── Cipher operations ──────────────────────────────────────────────────────

def make_idx(alph):
    return {ch: i for i, ch in enumerate(alph)}

def vig_dec(ct, key, alph=ALPH):
    idx = make_idx(alph)
    m = len(alph)
    return ''.join(alph[(idx[ct[i]] - idx[key[i % len(key)]]) % m] for i in range(len(ct)))

def beau_dec(ct, key, alph=ALPH):
    idx = make_idx(alph)
    m = len(alph)
    return ''.join(alph[(idx[key[i % len(key)]] - idx[ct[i]]) % m] for i in range(len(ct)))

def vbeau_dec(ct, key, alph=ALPH):
    idx = make_idx(alph)
    m = len(alph)
    return ''.join(alph[(idx[ct[i]] + idx[key[i % len(key)]]) % m] for i in range(len(ct)))

CIPHERS = {'Vig': vig_dec, 'Beau': beau_dec, 'VBeau': vbeau_dec}
ALPHS = {'AZ': ALPH, 'KA': KRYPTOS_ALPHABET}

# ── Scoring ────────────────────────────────────────────────────────────────

def score(pt):
    if len(pt) < CT_LEN:
        return 0, 0, 0
    d = score_cribs_detailed(pt)
    return d['score'], d['ene_score'], d['bc_score']

def score_free_check(pt):
    fcr = score_free(pt.upper())
    return fcr.score, fcr.ene_found, fcr.bc_found

# ── K0 text variants ──────────────────────────────────────────────────────

# The raw K0 words
K0_WORDS = [
    'VIRTUALLY', 'INVISIBLE', 'DIGETAL', 'INTERPRETATIU',
    'SHADOW', 'FORCES', 'LUCID', 'MEMORY',
    'T', 'IS', 'YOUR', 'POSITION', 'SOS', 'RQ',
]

K0_STRIPPED = ''.join(K0_WORDS)  # 81 chars

# Build multiple K0 variants with different E-padding strategies to target 97 chars
def build_k0_variants():
    variants = {}

    # No padding
    variants['raw81'] = K0_STRIPPED  # 81 chars

    # Single E between every word
    variants['e_every_word'] = 'E'.join(K0_WORDS)  # 94 chars
    variants['e_every_word_trail'] = 'E'.join(K0_WORDS) + 'E'  # 95 chars

    # E between words, EE between "lines" (6 lines in original)
    lines = [
        'VIRTUALLYEINVISIBLE',     # line 1
        'DIGETALEINTERPRETATIU',   # line 2
        'SHADOWEFORCES',           # line 3
        'LUCIDEMEMORY',            # line 4
        'TEISEYOUREPOSITION',      # line 5
        'SOSERQ',                  # line 6 (SOS and RQ on same "line"?)
    ]
    variants['e_lines_v1'] = 'EE'.join(lines)  # varies

    # Different line groupings
    lines2 = [
        'VIRTUALLYEINVISIBLE',
        'DIGETALEINTERPRETATIU',
        'SHADOWEFORCES',
        'LUCIDEMEMORY',
        'TEISEYOUREPOSITION',
        'SOS',
        'RQ',
    ]
    variants['e_lines_v2'] = 'EE'.join(lines2)

    # Pad to exactly 97 with trailing E's
    for base_name in list(variants.keys()):
        base = variants[base_name]
        if len(base) < 97:
            padded = base + 'E' * (97 - len(base))
            variants[f'{base_name}_pad97'] = padded
        elif len(base) > 97:
            truncated = base[:97]
            variants[f'{base_name}_trunc97'] = truncated

    # Also: E at start (some Morse decodings start with E for initial spacing)
    variants['e_lead_raw'] = 'E' * (97 - 81) + K0_STRIPPED  # 97 chars
    variants['e_centered'] = 'E' * 8 + K0_STRIPPED + 'E' * 8  # 97 chars

    # Repeat K0 to fill 97
    repeated = (K0_STRIPPED * 2)[:97]
    variants['repeated_97'] = repeated

    return variants

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    config_count = 0
    best_score = 0
    best_config = ""
    best_pt = ""
    above_noise = []

    def test(desc, pt, free_too=True):
        nonlocal config_count, best_score, best_config, best_pt
        config_count += 1
        s, ene, bc = score(pt)
        effective = s

        if free_too:
            fs, fe, fb = score_free_check(pt)
            effective = max(s, fs)

        if effective > best_score:
            best_score = effective
            best_config = desc
            best_pt = pt

        if s > NOISE_FLOOR:
            above_noise.append((s, 'anchored', desc, pt[:80]))
            print(f"  *** ABOVE NOISE (anchored {s}/24): {desc}")
            print(f"      ENE={ene}/13 BC={bc}/11  PT: {pt[:80]}")
        if free_too:
            fs, fe, fb = score_free_check(pt)
            if fs > NOISE_FLOOR and s <= NOISE_FLOOR:
                above_noise.append((fs, 'free', desc, pt[:80]))
                print(f"  *** ABOVE NOISE (free {fs}/24): {desc}")
                print(f"      ENE={'Y' if fe else 'n'} BC={'Y' if fb else 'n'}  PT: {pt[:80]}")

    print("=" * 80)
    print("MORSE REFLECTION — SUPPLEMENT (padding, periods, deep combos)")
    print("=" * 80)

    # ── 1. K0 padding variants as keys ─────────────────────────────────────
    print("\n── PART 1: K0 PADDING VARIANTS AS KEYS ──")
    variants = build_k0_variants()
    print(f"  {len(variants)} K0 variants built")
    for vname, vtext in sorted(variants.items()):
        print(f"    {vname}: {len(vtext)} chars")

    # Reflect each variant, use as key
    for vname, vtext in variants.items():
        for refl_mode in ['sub', 'rev', 'keep', 'rev_keep']:
            if refl_mode == 'sub':
                key = reflect_text(vtext, skip_invalid=True)
            elif refl_mode == 'rev':
                key = reflect_and_reverse(vtext, skip_invalid=True)
            elif refl_mode == 'keep':
                key = reflect_text(vtext, skip_invalid=False)
            elif refl_mode == 'rev_keep':
                key = reflect_and_reverse(vtext, skip_invalid=False)

            if not key:
                continue

            for cn, cf in CIPHERS.items():
                for an, al in ALPHS.items():
                    pt = cf(CT, key, al)
                    test(f"Pad:{vname}|{refl_mode}|{cn}|{an}", pt, free_too=False)

    print(f"  Part 1 configs: {config_count}")

    # ── 2. Period-based fragments of reflected K0 ──────────────────────────
    print("\n── PART 2: PERIOD-BASED EXTRACTION FROM REFLECTED K0 ──")
    # Extract every Nth letter from reflected K0 as a keyword
    base_reflected = reflect_text(K0_STRIPPED, skip_invalid=False)  # 81 chars

    for period in range(2, 27):
        for offset in range(min(period, 5)):  # First 5 offsets per period
            fragment = base_reflected[offset::period]
            if len(fragment) < 2:
                continue
            for cn, cf in CIPHERS.items():
                for an, al in ALPHS.items():
                    pt = cf(CT, fragment, al)
                    test(f"Period({period},off={offset})|{cn}|{an}", pt, free_too=False)

    print(f"  Part 2 configs: {config_count}")

    # ── 3. Reflection as part of multi-layer: reflect then Vig ─────────────
    print("\n── PART 3: MULTI-LAYER: REFLECT CT → DECRYPT ──")

    # Build reflected alphabet as substitution
    REFL_ALPH = ''
    for ch in ALPH:
        r = reflect_letter(ch)
        REFL_ALPH += r if r else ch
    # REFL_ALPH: NVCUELWHIJKFMAOPYRSTDBGXQZ

    # Apply reflection substitution to CT
    ct_refl = ''.join(REFL_ALPH[ALPH.index(c)] for c in CT)

    # Then try every standard keyword with Vig/Beau/VBeau on AZ/KA
    # (already done in part 1 script, but let's also try with the padded K0 keys)
    # Plus: apply reflection to KNOWN KEYSTREAM values and see what they map to

    print(f"  Reflected alphabet: {REFL_ALPH}")
    print(f"  CT reflected: {ct_refl}")

    # Check: does reflecting known Vigenere keystream values produce anything meaningful?
    print("\n  Known Vigenere keystream at ENE positions: ", VIGENERE_KEY_ENE)
    vig_key_letters = ''.join(ALPH[k] for k in VIGENERE_KEY_ENE)
    print(f"  As letters: {vig_key_letters}")
    refl_vig_key = reflect_text(vig_key_letters, skip_invalid=False)
    print(f"  Reflected:  {refl_vig_key}")

    print("\n  Known Vigenere keystream at BC positions: ", VIGENERE_KEY_BC)
    vig_key_bc = ''.join(ALPH[k] for k in VIGENERE_KEY_BC)
    print(f"  As letters: {vig_key_bc}")
    refl_vig_bc = reflect_text(vig_key_bc, skip_invalid=False)
    print(f"  Reflected:  {refl_vig_bc}")

    print("\n  Known Beaufort keystream at ENE positions: ", BEAUFORT_KEY_ENE)
    beau_key_letters = ''.join(ALPH[k] for k in BEAUFORT_KEY_ENE)
    print(f"  As letters: {beau_key_letters}")
    refl_beau_key = reflect_text(beau_key_letters, skip_invalid=False)
    print(f"  Reflected:  {refl_beau_key}")

    print("\n  Known Beaufort keystream at BC positions: ", BEAUFORT_KEY_BC)
    beau_key_bc = ''.join(ALPH[k] for k in BEAUFORT_KEY_BC)
    print(f"  As letters: {beau_key_bc}")
    refl_beau_bc = reflect_text(beau_key_bc, skip_invalid=False)
    print(f"  Reflected:  {refl_beau_bc}")

    # Do reflected keystream values suggest a periodic keyword?
    # ENE Vig keystream reflected:
    refl_ene_nums = [ALPH.index(c) for c in refl_vig_key]
    refl_bc_nums = [ALPH.index(c) for c in refl_vig_bc]
    print(f"\n  Reflected Vig ENE keystream nums: {refl_ene_nums}")
    print(f"  Reflected Vig BC keystream nums:  {refl_bc_nums}")

    # Check if reflected keystream has period compatibility
    for period in range(1, 14):
        consistent = True
        for i in range(len(refl_ene_nums)):
            for j in range(i + 1, len(refl_ene_nums)):
                if (21 + i) % period == (21 + j) % period:
                    if refl_ene_nums[i] != refl_ene_nums[j]:
                        consistent = False
                        break
            if not consistent:
                break
        if consistent:
            # Also check BC
            bc_consistent = True
            for i in range(len(refl_bc_nums)):
                for j in range(i + 1, len(refl_bc_nums)):
                    if (63 + i) % period == (63 + j) % period:
                        if refl_bc_nums[i] != refl_bc_nums[j]:
                            bc_consistent = False
                            break
                if not bc_consistent:
                    break

            # Cross-check ENE vs BC
            cross_ok = True
            for i in range(len(refl_ene_nums)):
                for j in range(len(refl_bc_nums)):
                    if (21 + i) % period == (63 + j) % period:
                        if refl_ene_nums[i] != refl_bc_nums[j]:
                            cross_ok = False
                            break
                if not cross_ok:
                    break

            if consistent and bc_consistent and cross_ok:
                print(f"  *** Reflected Vig keystream CONSISTENT at period {period}")

    # ── 4. Reflection involution applied at different stages ───────────────
    print("\n── PART 4: REFLECTION AT DIFFERENT STAGES ──")

    # Model: PT → reflect → Vig encrypt → CT
    # Decrypt: CT → Vig decrypt → reflect → PT
    # Since reflect is involution, reflect(reflect(x)) = x
    keywords_top = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'DEFECTOR',
                     'PARALLAX', 'COLOPHON', 'FIVE', 'POINT', 'VIRTUALLY',
                     'INVISIBLE', 'MEMORY', 'POSITION', 'FORCES', 'LUCID',
                     'NORTHEAST', 'BERLINCLOCK', 'EASTNORTHEAST']

    for kw in keywords_top:
        for cn, cf in CIPHERS.items():
            for an, al in ALPHS.items():
                # Stage 1: Decrypt first, then reflect
                pt_step1 = cf(CT, kw, al)
                pt = reflect_text(pt_step1, skip_invalid=False)
                if len(pt) >= CT_LEN:
                    test(f"DecThenRefl|{kw}|{cn}|{an}", pt)

                # Stage 2: Reflect first, then decrypt
                ct_r = reflect_text(CT, skip_invalid=False)
                pt2 = cf(ct_r, kw, al)
                test(f"ReflThenDec|{kw}|{cn}|{an}", pt2)

                # Stage 3: Reflect key, decrypt
                rkw = reflect_text(kw, skip_invalid=False)
                pt3 = cf(CT, rkw, al)
                test(f"ReflKey|{kw}→{rkw}|{cn}|{an}", pt3)

                # Stage 4: Reflect everything
                pt4 = cf(ct_r, rkw, al)
                test(f"ReflAll|{kw}|{cn}|{an}", pt4)

    print(f"  Part 4 configs: {config_count}")

    # ── 5. Test: reflection pairs as positional swaps in K4 ────────────────
    print("\n── PART 5: REFLECTION PAIRS AS POSITIONAL SWAPS ──")

    # What if the reflection doesn't transform letters, but tells us which
    # positions in K4 to SWAP?
    # Wherever K0 has a swappable letter pair (e.g., A at position i and N at
    # position j), swap K4[i] and K4[j]

    # Build position groups based on K0 letter identity
    from collections import defaultdict
    k0 = K0_STRIPPED

    # For each reflection pair, find positions in K0
    pair_groups = defaultdict(list)
    for i, ch in enumerate(k0):
        if ch in REFLECTION_PAIRS:
            # Group by the pair (unordered)
            pair = tuple(sorted([ch, REFLECTION_PAIRS[ch]]))
            pair_groups[pair].append(i)

    print(f"  Reflection pair positions in K0:")
    for pair, positions in sorted(pair_groups.items()):
        if all(p < CT_LEN for p in positions):
            ct_at = ''.join(CT[p] for p in positions)
            print(f"    {pair[0]}↔{pair[1]}: positions {positions} → CT chars: {ct_at}")

    # Try swapping K4 characters at paired positions
    ct_list = list(CT)
    for pair, positions in pair_groups.items():
        if len(positions) >= 2:
            # Swap positions pairwise
            for i in range(0, len(positions) - 1, 2):
                p1, p2 = positions[i], positions[i + 1]
                if p1 < CT_LEN and p2 < CT_LEN:
                    ct_list[p1], ct_list[p2] = ct_list[p2], ct_list[p1]

    ct_swapped = ''.join(ct_list)
    print(f"\n  CT after pair-swaps: {ct_swapped}")

    for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'DEFECTOR']:
        for cn, cf in CIPHERS.items():
            for an, al in ALPHS.items():
                pt = cf(ct_swapped, kw, al)
                test(f"PairSwap+{kw}|{cn}|{an}", pt)

    # ── 6. Numeric value of reflection mapping ─────────────────────────────
    print("\n── PART 6: REFLECTION AS NUMERIC KEY ──")

    # The reflection defines a specific numeric shift for each letter
    # A→N = shift +13, B→V = shift +20, D→U = shift +17, etc.
    reflection_shifts = {}
    for ch in ALPH:
        r = reflect_letter(ch)
        if r:
            shift = (ALPH.index(r) - ALPH.index(ch)) % 26
            reflection_shifts[ch] = shift
        else:
            reflection_shifts[ch] = 0  # C, J, Z: no shift

    print(f"  Per-letter shifts: ", end="")
    for ch in ALPH:
        print(f"{ch}:{reflection_shifts[ch]:+d} ", end="")
    print()

    # Apply these shifts to K4 positionally based on K0 letter at each position
    padded_k0 = K0_STRIPPED + 'E' * (97 - len(K0_STRIPPED))  # Pad with E (shift=0)
    shifted_ct = ''
    for i in range(CT_LEN):
        k0_ch = padded_k0[i]
        shift = reflection_shifts.get(k0_ch, 0)
        c_idx = ALPH.index(CT[i])
        shifted_ct += ALPH[(c_idx - shift) % 26]

    print(f"  K4 shifted by K0 reflection values: {shifted_ct}")

    for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'A']:  # 'A' = identity
        for cn, cf in CIPHERS.items():
            pt = cf(shifted_ct, kw, ALPH)
            test(f"ReflShift+{kw}|{cn}|AZ", pt)

    # Also: use the shifts as a key stream directly
    shift_key = ''.join(ALPH[reflection_shifts.get(padded_k0[i], 0)] for i in range(CT_LEN))
    print(f"  Shift key as letters: {shift_key[:50]}...")

    for cn, cf in CIPHERS.items():
        for an, al in ALPHS.items():
            pt = cf(CT, shift_key, al)
            test(f"ShiftKey|{cn}|{an}", pt)

    # ── 7. K0 reflection → check if it could BE the K4 plaintext ──────────
    print("\n── PART 7: IS REFLECTED K0 THE K4 PLAINTEXT? ──")

    # What if the K4 plaintext IS the reflected K0 text (padded)?
    # Check: does any simple cipher turn K4 into reflected K0?
    for vname, vtext in [('raw81_pad', K0_STRIPPED + 'E' * 16),
                          ('refl81_pad', reflect_text(K0_STRIPPED, skip_invalid=False) + 'E' * 16)]:
        target = vtext[:97].upper()
        print(f"\n  Testing if {vname} is K4 plaintext...")
        print(f"    Target: {target[:60]}...")

        # What key would be needed for Vigenere?
        vig_key_needed = ''
        for i in range(CT_LEN):
            k = (ALPH.index(CT[i]) - ALPH.index(target[i])) % 26
            vig_key_needed += ALPH[k]
        print(f"    Vig key needed: {vig_key_needed[:60]}...")

        # Check if this key is periodic
        for period in range(1, 30):
            periodic = True
            for i in range(CT_LEN):
                if vig_key_needed[i] != vig_key_needed[i % period]:
                    periodic = False
                    break
            if periodic:
                keyword = vig_key_needed[:period]
                print(f"    *** PERIODIC KEY FOUND at period {period}: {keyword}")

        # What key for Beaufort?
        beau_key_needed = ''
        for i in range(CT_LEN):
            k = (ALPH.index(CT[i]) + ALPH.index(target[i])) % 26
            beau_key_needed += ALPH[k]
        print(f"    Beau key needed: {beau_key_needed[:60]}...")

        for period in range(1, 30):
            periodic = True
            for i in range(CT_LEN):
                if beau_key_needed[i] != beau_key_needed[i % period]:
                    periodic = False
                    break
            if periodic:
                keyword = beau_key_needed[:period]
                print(f"    *** PERIODIC BEAU KEY FOUND at period {period}: {keyword}")

    # ── 8. The 11 self-mirror letters as a reduced alphabet ────────────────
    print("\n── PART 8: SELF-MIRROR AS REDUCED ALPHABET ──")

    # What if self-mirror letters (EHIKMOPRSTX) form a reduced cipher?
    # Map: E=0, H=1, I=2, K=3, M=4, O=5, P=6, R=7, S=8, T=9, X=10
    mirror_alph = 'EHIKMOPRSTX'  # 11 letters
    mirror_idx = {ch: i for i, ch in enumerate(mirror_alph)}

    # Count how many K4 letters are in the mirror set
    k4_mirror = sum(1 for ch in CT if ch in SELF_MIRROR)
    k4_swap = sum(1 for ch in CT if ch in REFLECTION_PAIRS)
    k4_invalid = sum(1 for ch in CT if ch in INVALID_REFLECT)
    print(f"  K4 letter distribution:")
    print(f"    Self-mirror: {k4_mirror}/97 ({k4_mirror/97:.1%})")
    print(f"    Swappable:   {k4_swap}/97 ({k4_swap/97:.1%})")
    print(f"    Invalid:     {k4_invalid}/97 ({k4_invalid/97:.1%})")
    print(f"    Expected (mirror=11/26): {11/26:.1%}")
    print(f"    Expected (swap=12/26):   {12/26:.1%}")
    print(f"    Expected (invalid=3/26): {3/26:.1%}")

    # Chi-squared test for distribution
    expected_mirror = 97 * 11 / 26
    expected_swap = 97 * 12 / 26
    expected_invalid = 97 * 3 / 26
    chi2 = ((k4_mirror - expected_mirror)**2 / expected_mirror +
            (k4_swap - expected_swap)**2 / expected_swap +
            (k4_invalid - expected_invalid)**2 / expected_invalid)
    print(f"    Chi-squared (vs uniform): {chi2:.2f} (df=2, p<0.05 if >5.99)")

    # ── 9. Test if REFLECTION maps cribs to each other ─────────────────────
    print("\n── PART 9: CRIB REFLECTION ANALYSIS ──")
    ene = 'EASTNORTHEAST'
    bc = 'BERLINCLOCK'
    ene_refl = reflect_text(ene, skip_invalid=False)
    bc_refl = reflect_text(bc, skip_invalid=False)
    print(f"  EASTNORTHEAST → {ene_refl}")
    print(f"  BERLINCLOCK   → {bc_refl}")

    # Are there any shared patterns between reflected and original cribs?
    # Check if reflected ENE contains BC or vice versa
    if bc in ene_refl or bc_refl in ene:
        print(f"  *** OVERLAP FOUND between reflected cribs!")
    else:
        print(f"  No direct overlap between reflected cribs")

    # Check if reflected crib chars match CT at crib positions
    ene_ct = CT[21:34]
    bc_ct = CT[63:74]
    print(f"\n  CT at ENE positions: {ene_ct}")
    print(f"  CT at BC positions:  {bc_ct}")
    print(f"  Reflected ENE crib:  {ene_refl}")
    print(f"  Reflected BC crib:   {bc_refl}")

    # How many chars match between reflected crib and CT at those positions?
    ene_match = sum(1 for a, b in zip(ene_refl, ene_ct) if a == b)
    bc_match = sum(1 for a, b in zip(bc_refl, bc_ct) if a == b)
    print(f"  Reflected ENE vs CT at ENE positions: {ene_match}/{len(ene_refl)} matches")
    print(f"  Reflected BC vs CT at BC positions:   {bc_match}/{len(bc_refl)} matches")

    # What if reflect(PT) = CT? (reflection IS the cipher)
    # Then reflect(crib) should equal CT at those positions
    # Already checked above

    # ═══════════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"  Total configurations tested: {config_count}")
    print(f"  Best score: {best_score}/24")
    if best_config:
        print(f"  Best config: {best_config}")
    if best_pt:
        print(f"  Best PT: {best_pt[:97]}")

    if above_noise:
        print(f"\n  ABOVE NOISE (>{NOISE_FLOOR}):")
        above_noise.sort(key=lambda x: -x[0])
        for s, mode, desc, pt in above_noise:
            print(f"    [{mode}] Score {s}/24: {desc}")
    else:
        print(f"\n  No results above noise floor (>{NOISE_FLOOR})")

    return config_count, best_score, above_noise


if __name__ == '__main__':
    main()
