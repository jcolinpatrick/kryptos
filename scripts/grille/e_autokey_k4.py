#!/usr/bin/env python3
"""
Cipher: autokey
Family: grille
Status: active
Keyspace: ~2.5M configs (5 types x 2 alphabets x all primers 1-3 + thematic)
Last run: 2026-03-06
Best score: TBD
"""
"""
E-AUTOKEY-K4: Comprehensive Autokey Cipher Attack on K4

Tests ALL autokey variants systematically, including the critical
KNOWN-PLAINTEXT BACKWARD PROPAGATION attack that can directly recover
the primer from the two known cribs.

Autokey types:
  1. Plaintext autokey (Vigenere): k[i] = PT[i-L] for i >= L
  2. Ciphertext autokey (Vigenere): k[i] = CT[i-L] for i >= L
  3. Plaintext autokey (Beaufort): CT[i] = (k[i] - PT[i]) mod 26
  4. Ciphertext autokey (Beaufort): CT[i] = (k[i] - PT[i]) mod 26
  5. Mixed/alternating autokey: PT feedback on even, CT on odd (and vice versa)

Each tested with both AZ and KA alphabets.

KEY INNOVATION: Known-plaintext propagation attack.
  - Cribs at positions 21-33 and 63-73 let us RECOVER key values
  - Propagate backward through the autokey chain to deduce the primer
  - Check if both cribs yield a consistent primer
  - This is O(1) per (type, alphabet) — no brute force needed!

Also: Exhaustive primer search for lengths 1-3 (all 26 + 676 + 17576)
and thematic keywords.
"""

import sys
import os
import time
import json
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, CRIB_WORDS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.constraints.bean import verify_bean, verify_bean_simple

# ── Alphabet setup ────────────────────────────────────────────────────────

ALPHABETS = {
    'AZ': (ALPH, {c: i for i, c in enumerate(ALPH)}),
    'KA': (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}


def to_nums(text, idx_map):
    return [idx_map[c] for c in text]


def to_text(nums, alpha_str):
    return ''.join(alpha_str[n % MOD] for n in nums)


# ── Autokey decrypt functions ─────────────────────────────────────────────
# Each returns (plaintext_nums, keystream) given (ct_nums, primer_nums, alpha_name)

def decrypt_pt_autokey_vig(ct_nums, primer_nums, alpha_name='AZ'):
    """Plaintext autokey, Vigenere: CT[i] = (PT[i] + k[i]) mod 26
    k[i] = primer[i] for i < L, PT[i-L] for i >= L
    PT[i] = (CT[i] - k[i]) mod 26
    """
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    ks = [0] * n

    for i in range(n):
        if i < L:
            ks[i] = primer_nums[i]
        else:
            ks[i] = pt[i - L]
        pt[i] = (ct_nums[i] - ks[i]) % MOD
    return pt, ks


def decrypt_ct_autokey_vig(ct_nums, primer_nums, alpha_name='AZ'):
    """Ciphertext autokey, Vigenere: CT[i] = (PT[i] + k[i]) mod 26
    k[i] = primer[i] for i < L, CT[i-L] for i >= L
    PT[i] = (CT[i] - k[i]) mod 26
    """
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    ks = [0] * n

    for i in range(n):
        if i < L:
            ks[i] = primer_nums[i]
        else:
            ks[i] = ct_nums[i - L]
        pt[i] = (ct_nums[i] - ks[i]) % MOD
    return pt, ks


def decrypt_pt_autokey_beau(ct_nums, primer_nums, alpha_name='AZ'):
    """Plaintext autokey, Beaufort: CT[i] = (k[i] - PT[i]) mod 26
    k[i] = primer[i] for i < L, PT[i-L] for i >= L
    PT[i] = (k[i] - CT[i]) mod 26
    """
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    ks = [0] * n

    for i in range(n):
        if i < L:
            ks[i] = primer_nums[i]
        else:
            ks[i] = pt[i - L]
        pt[i] = (ks[i] - ct_nums[i]) % MOD
    return pt, ks


def decrypt_ct_autokey_beau(ct_nums, primer_nums, alpha_name='AZ'):
    """Ciphertext autokey, Beaufort: CT[i] = (k[i] - PT[i]) mod 26
    k[i] = primer[i] for i < L, CT[i-L] for i >= L
    PT[i] = (k[i] - CT[i]) mod 26
    """
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    ks = [0] * n

    for i in range(n):
        if i < L:
            ks[i] = primer_nums[i]
        else:
            ks[i] = ct_nums[i - L]
        pt[i] = (ks[i] - ct_nums[i]) % MOD
    return pt, ks


def decrypt_pt_autokey_varbeau(ct_nums, primer_nums, alpha_name='AZ'):
    """Plaintext autokey, Variant Beaufort: CT[i] = (PT[i] - k[i]) mod 26
    k[i] = primer[i] for i < L, PT[i-L] for i >= L
    PT[i] = (CT[i] + k[i]) mod 26
    """
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    ks = [0] * n

    for i in range(n):
        if i < L:
            ks[i] = primer_nums[i]
        else:
            ks[i] = pt[i - L]
        pt[i] = (ct_nums[i] + ks[i]) % MOD
    return pt, ks


def decrypt_ct_autokey_varbeau(ct_nums, primer_nums, alpha_name='AZ'):
    """Ciphertext autokey, Variant Beaufort: CT[i] = (PT[i] - k[i]) mod 26
    k[i] = primer[i] for i < L, CT[i-L] for i >= L
    PT[i] = (CT[i] + k[i]) mod 26
    """
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    ks = [0] * n

    for i in range(n):
        if i < L:
            ks[i] = primer_nums[i]
        else:
            ks[i] = ct_nums[i - L]
        pt[i] = (ct_nums[i] + ks[i]) % MOD
    return pt, ks


def decrypt_mixed_autokey_vig(ct_nums, primer_nums, alpha_name='AZ'):
    """Mixed autokey, Vigenere: even positions use PT feedback, odd use CT.
    CT[i] = (PT[i] + k[i]) mod 26
    k[i] = primer[i] for i < L
    k[i] = PT[i-L] for i >= L and (i-L) even
    k[i] = CT[i-L] for i >= L and (i-L) odd
    """
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    ks = [0] * n

    for i in range(n):
        if i < L:
            ks[i] = primer_nums[i]
        else:
            src_pos = i - L
            if src_pos % 2 == 0:
                ks[i] = pt[src_pos]
            else:
                ks[i] = ct_nums[src_pos]
        pt[i] = (ct_nums[i] - ks[i]) % MOD
    return pt, ks


def decrypt_mixed_autokey_beau(ct_nums, primer_nums, alpha_name='AZ'):
    """Mixed autokey, Beaufort: even positions use PT feedback, odd use CT."""
    L = len(primer_nums)
    n = len(ct_nums)
    pt = [0] * n
    ks = [0] * n

    for i in range(n):
        if i < L:
            ks[i] = primer_nums[i]
        else:
            src_pos = i - L
            if src_pos % 2 == 0:
                ks[i] = pt[src_pos]
            else:
                ks[i] = ct_nums[src_pos]
        pt[i] = (ks[i] - ct_nums[i]) % MOD
    return pt, ks


# All decrypt functions to test
DECRYPT_FUNCTIONS = {
    'PT-Vig':      decrypt_pt_autokey_vig,
    'CT-Vig':      decrypt_ct_autokey_vig,
    'PT-Beau':     decrypt_pt_autokey_beau,
    'CT-Beau':     decrypt_ct_autokey_beau,
    'PT-VarBeau':  decrypt_pt_autokey_varbeau,
    'CT-VarBeau':  decrypt_ct_autokey_varbeau,
    'Mixed-Vig':   decrypt_mixed_autokey_vig,
    'Mixed-Beau':  decrypt_mixed_autokey_beau,
}

# ── Known-plaintext propagation attack ────────────────────────────────────

def recover_keystream_at_cribs(ct_nums, idx_map, variant):
    """Recover the keystream values at crib positions from known PT.

    For Vigenere: k[i] = (CT[i] - PT[i]) mod 26
    For Beaufort: k[i] = (CT[i] + PT[i]) mod 26
    For VarBeau: k[i] = (PT[i] - CT[i]) mod 26

    Returns dict {position: key_value}
    """
    crib_pt = {}
    for pos, ch in CRIB_DICT.items():
        crib_pt[pos] = idx_map[ch]

    ks_at_cribs = {}
    for pos, pt_val in crib_pt.items():
        ct_val = ct_nums[pos]
        if 'Vig' in variant:
            ks_at_cribs[pos] = (ct_val - pt_val) % MOD
        elif 'Beau' in variant and 'Var' not in variant:
            ks_at_cribs[pos] = (ct_val + pt_val) % MOD
        elif 'VarBeau' in variant:
            ks_at_cribs[pos] = (pt_val - ct_val) % MOD
    return ks_at_cribs


def kpa_pt_autokey(ct_nums, idx_map, alpha_str, variant, max_primer_len=96):
    """Known-plaintext attack on plaintext autokey.

    For PT-autokey with primer length L:
      k[i] = PT[i-L] for i >= L
      k[i] = primer[i] for i < L

    So at crib position i (where we know PT[i] and thus k[i]):
      if i >= L: k[i] = PT[i-L], so PT[i-L] = k[i]
      if i < L: primer[i] = k[i]

    We can propagate: knowing PT[i-L] lets us compute k[i-L+L] = k[i] = PT[i-L],
    and if we know k at position j, PT[j] = decrypt(CT[j], k[j]).
    Then PT[j] becomes key for position j+L, etc.

    Returns list of (primer_len, primer_text, pt_text, crib_score, bean_pass, ks)
    for all consistent primer lengths.
    """
    results = []

    # Recover keystream at crib positions
    ks_at_cribs = recover_keystream_at_cribs(ct_nums, idx_map, variant)

    for L in range(1, max_primer_len + 1):
        # For PT-autokey with primer length L:
        # At crib position i (i >= L): k[i] = PT[i-L]
        # So we know PT[i-L] = k[i] = ks_at_cribs[i]
        # This gives us PT values at positions {crib_pos - L} for crib_pos >= L

        # Also at crib position i (i < L): primer[i] = ks_at_cribs[i]

        known_pt = {}
        primer_constraints = {}

        for pos, ch in CRIB_DICT.items():
            known_pt[pos] = idx_map[ch]

        for pos, k_val in ks_at_cribs.items():
            if pos < L:
                primer_constraints[pos] = k_val
            else:
                # PT[pos - L] = k_val
                derived_pos = pos - L
                if derived_pos in known_pt:
                    # Check consistency
                    if known_pt[derived_pos] != k_val:
                        break  # contradiction
                else:
                    known_pt[derived_pos] = k_val
        else:
            # No contradiction from initial assignment
            # Now propagate: for each known PT[j], k[j+L] = PT[j]
            # Then PT[j+L] = decrypt(CT[j+L], PT[j])
            changed = True
            contradiction = False
            iterations = 0
            while changed and not contradiction and iterations < 200:
                changed = False
                iterations += 1

                # Forward: PT[j] known => k[j+L] = PT[j] => PT[j+L] = decrypt(CT[j+L], k[j+L])
                new_pt = {}
                for j, pt_val in known_pt.items():
                    target = j + L
                    if target < CT_LEN:
                        if 'Vig' in variant:
                            derived_pt = (ct_nums[target] - pt_val) % MOD
                        elif 'Beau' in variant and 'Var' not in variant:
                            derived_pt = (pt_val - ct_nums[target]) % MOD
                        elif 'VarBeau' in variant:
                            derived_pt = (ct_nums[target] + pt_val) % MOD

                        if target in known_pt:
                            if known_pt[target] != derived_pt:
                                contradiction = True
                                break
                        elif target not in new_pt:
                            new_pt[target] = derived_pt
                            changed = True

                if contradiction:
                    break

                known_pt.update(new_pt)

                # Backward: PT[j] known and j >= L => k[j] = PT[j-L]
                # So PT[j-L] = k[j]. But k[j] = (relationship with CT[j] and PT[j])
                # Actually for PT autokey: k[j] = PT[j-L] for j >= L
                # And we can compute k[j] from CT[j] and PT[j]:
                #   Vig: k[j] = (CT[j] - PT[j]) mod 26
                #   Beau: k[j] = (CT[j] + PT[j]) mod 26
                #   VarBeau: k[j] = (PT[j] - CT[j]) mod 26
                new_pt2 = {}
                for j, pt_val in known_pt.items():
                    if j >= L:
                        if 'Vig' in variant:
                            k_val = (ct_nums[j] - pt_val) % MOD
                        elif 'Beau' in variant and 'Var' not in variant:
                            k_val = (ct_nums[j] + pt_val) % MOD
                        elif 'VarBeau' in variant:
                            k_val = (pt_val - ct_nums[j]) % MOD

                        src = j - L
                        if src in known_pt:
                            if known_pt[src] != k_val:
                                contradiction = True
                                break
                        elif src not in new_pt2:
                            new_pt2[src] = k_val
                            changed = True

                        # Also: if src < L, this constrains the primer
                        if src < L:
                            if src in primer_constraints:
                                if primer_constraints[src] != k_val:
                                    contradiction = True
                                    break
                            else:
                                primer_constraints[src] = k_val

                if contradiction:
                    break

                known_pt.update(new_pt2)

            if contradiction:
                continue

            # Build full plaintext and keystream
            n_determined = len(known_pt)
            if n_determined < 24:
                continue  # Not enough determined to score

            # For undetermined positions, fill with 0 (won't affect crib scoring)
            pt_full = [known_pt.get(i, 0) for i in range(CT_LEN)]
            pt_text = ''.join(alpha_str[v] for v in pt_full)

            # Mark undetermined positions
            det_mask = [i in known_pt for i in range(CT_LEN)]

            # Score using anchored cribs (these are at fixed positions)
            sb = score_candidate(pt_text)

            # Also score with free cribs
            fb = score_candidate_free(pt_text)

            # Compute keystream for Bean check
            ks_full = [0] * CT_LEN
            for i in range(CT_LEN):
                if i < L:
                    ks_full[i] = primer_constraints.get(i, 0)
                else:
                    ks_full[i] = pt_full[i - L]

            bean = verify_bean_simple(ks_full) if n_determined > 80 else False

            # Build primer text
            primer_text = ''.join(alpha_str[primer_constraints[i]] if i in primer_constraints else '?' for i in range(L))

            if sb.crib_score > NOISE_FLOOR or fb.crib_score > 0 or n_determined >= 80:
                results.append({
                    'primer_len': L,
                    'primer': primer_text,
                    'pt': pt_text,
                    'n_determined': n_determined,
                    'anchored_score': sb.crib_score,
                    'free_score': fb.crib_score,
                    'free_ene': fb.ene_found,
                    'free_bc': fb.bc_found,
                    'bean': bean,
                    'ic': sb.ic_value,
                    'classification': sb.crib_classification,
                    'ks': ks_full,
                })

    return results


def kpa_ct_autokey(ct_nums, idx_map, alpha_str, variant, max_primer_len=96):
    """Known-plaintext attack on ciphertext autokey.

    For CT-autokey with primer length L:
      k[i] = CT[i-L] for i >= L (FULLY DETERMINED from CT alone!)
      k[i] = primer[i] for i < L

    The key for positions >= L is known. We just need to find the primer.
    At crib positions i < L: primer[i] is determined by the crib.
    At crib positions i >= L: we can verify k[i] = CT[i-L] produces correct PT.
    """
    results = []

    ks_at_cribs = recover_keystream_at_cribs(ct_nums, idx_map, variant)

    for L in range(1, max_primer_len + 1):
        # Check consistency at crib positions >= L
        consistent = True
        primer_constraints = {}

        for pos, k_val in ks_at_cribs.items():
            if pos >= L:
                # Key should be CT[pos-L]
                expected_k = ct_nums[pos - L]
                if expected_k != k_val:
                    consistent = False
                    break
            else:
                # This constrains the primer
                primer_constraints[pos] = k_val

        if not consistent:
            continue

        # Build full keystream
        ks = [0] * CT_LEN
        for i in range(CT_LEN):
            if i < L:
                ks[i] = primer_constraints.get(i, 0)
            else:
                ks[i] = ct_nums[i - L]

        # Decrypt
        pt_nums = [0] * CT_LEN
        for i in range(CT_LEN):
            if 'Vig' in variant:
                pt_nums[i] = (ct_nums[i] - ks[i]) % MOD
            elif 'Beau' in variant and 'Var' not in variant:
                pt_nums[i] = (ks[i] - ct_nums[i]) % MOD
            elif 'VarBeau' in variant:
                pt_nums[i] = (ct_nums[i] + ks[i]) % MOD

        pt_text = to_text(pt_nums, alpha_str)

        # Score
        sb = score_candidate(pt_text)
        fb = score_candidate_free(pt_text)

        # Bean
        bean = verify_bean_simple(ks)

        # Primer text
        primer_text = ''.join(alpha_str[primer_constraints[i]] if i in primer_constraints else '?' for i in range(L))

        # We have score = 24 at crib positions >= L by construction.
        # The question is whether primer positions are also correct.
        # For L > 33, ALL crib positions are >= L so we always get 24/24 -- trivial.
        # For L <= 33, some cribs constrain the primer.

        if sb.crib_score > NOISE_FLOOR or fb.crib_score > 0:
            results.append({
                'primer_len': L,
                'primer': primer_text,
                'pt': pt_text,
                'n_determined': CT_LEN,
                'anchored_score': sb.crib_score,
                'free_score': fb.crib_score,
                'free_ene': fb.ene_found,
                'free_bc': fb.bc_found,
                'bean': bean,
                'ic': sb.ic_value,
                'classification': sb.crib_classification,
                'ks': ks,
            })

    return results


# ── Brute-force primer search ─────────────────────────────────────────────

def brute_force_primers(ct_nums, idx_map, alpha_str, alpha_name,
                        decrypt_fn, variant_name, max_primer_len=3,
                        thematic_primers=None):
    """Exhaustive primer search for short primers + thematic keywords.

    Returns list of results above noise floor.
    """
    results = []
    n_tested = 0
    best_anchored = 0
    best_free = 0

    def test_primer(primer_nums, primer_text):
        nonlocal n_tested, best_anchored, best_free
        n_tested += 1

        pt_nums, ks = decrypt_fn(ct_nums, primer_nums, alpha_name)
        pt_text = to_text(pt_nums, alpha_str)

        # Quick crib check first (fast path)
        anchored = 0
        for pos, ch in CRIB_DICT.items():
            if pt_text[pos] == ch:
                anchored += 1

        if anchored > best_anchored:
            best_anchored = anchored

        # Free crib check (substring search)
        free = 0
        if 'EASTNORTHEAST' in pt_text:
            free += 13
        if 'BERLINCLOCK' in pt_text:
            free += 11

        if free > best_free:
            best_free = free

        if anchored > NOISE_FLOOR or free > 0:
            # Full scoring
            sb = score_candidate(pt_text)
            fb = score_candidate_free(pt_text)
            bean = verify_bean_simple(ks)

            results.append({
                'primer_len': len(primer_nums),
                'primer': primer_text,
                'pt': pt_text,
                'anchored_score': sb.crib_score,
                'free_score': fb.crib_score,
                'free_ene': fb.ene_found,
                'free_bc': fb.bc_found,
                'bean': bean,
                'ic': sb.ic_value,
                'classification': sb.crib_classification,
            })

    # Exhaustive search for primers of length 1 to max_primer_len
    for plen in range(1, max_primer_len + 1):
        for combo in product(range(MOD), repeat=plen):
            primer_nums = list(combo)
            primer_text = to_text(primer_nums, alpha_str)
            test_primer(primer_nums, primer_text)

    # Thematic keyword primers
    if thematic_primers:
        for kw in thematic_primers:
            kw_upper = kw.upper()
            # Filter to only letters in the alphabet
            kw_filtered = ''.join(c for c in kw_upper if c in idx_map)
            if not kw_filtered or len(kw_filtered) > CT_LEN - 1:
                continue
            primer_nums = [idx_map[c] for c in kw_filtered]
            test_primer(primer_nums, kw_filtered)

    return results, n_tested, best_anchored, best_free


# ── Bean constraint check on autokey keystream ────────────────────────────

def check_bean_autokey_keystream(ks):
    """Check Bean constraints directly on the autokey-derived keystream.

    Bean EQ: k[27] = k[65]
    Bean INEQ: 21 pairs that must differ
    """
    return verify_bean_simple(ks)


# ── IC and English scoring ────────────────────────────────────────────────

def ic(text):
    n = len(text)
    if n < 2:
        return 0.0
    counts = [0] * 26
    for c in text:
        counts[ALPH_IDX.get(c, 0)] += 1
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def english_bigram_score(text):
    """Quick English-likeness via common bigrams."""
    common = {'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND',
              'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR',
              'ST', 'TO', 'NT', 'NG', 'SE', 'HA', 'OU', 'IO', 'LE', 'VE'}
    score = 0
    for i in range(len(text) - 1):
        if text[i:i+2] in common:
            score += 1
    return score


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    t_start = time.time()

    print("=" * 80)
    print("E-AUTOKEY-K4: Comprehensive Autokey Cipher Attack on K4")
    print("=" * 80)
    print(f"  CT: {CT}")
    print(f"  CT length: {CT_LEN}")
    print(f"  Cribs: pos 21-33 = EASTNORTHEAST, pos 63-73 = BERLINCLOCK")
    print(f"  Bean EQ: k[27]=k[65], 21 inequalities")
    print()
    sys.stdout.flush()

    # Thematic primers to test
    THEMATIC_PRIMERS = [
        'HOROLOGE', 'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'DEFECTOR',
        'PARALLAX', 'COLOPHON', 'URANIA', 'BERLIN', 'CLOCK',
        'BERLINCLOCK', 'EASTNORTHEAST', 'SANBORN', 'SCHEIDT',
        'SHADOW', 'ENIGMA', 'SPHINX', 'PHARAOH', 'CARTER',
        'TUTANKHAMUN', 'ALEXANDERPLATZ', 'COMPASS', 'QUARTZ',
        'LODESTONE', 'MORSE', 'VIGENERE', 'BEAUFORT', 'TABLEAU',
        'VERDIGRIS', 'BETWEEN', 'SLOWLY', 'DESPARATLY',
        # KA-derived primers
        'KRYPTOSAB', 'KRYPTOSA', 'KRYPTO', 'KR', 'KRY', 'KRYP',
        # Short thematic
        'CIA', 'NSA', 'SOS', 'KEY', 'TIME', 'EAST', 'NORTH',
    ]

    all_results = []
    phase_summaries = {}

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1: KNOWN-PLAINTEXT PROPAGATION ATTACK
    # ══════════════════════════════════════════════════════════════════════

    print("=" * 80)
    print("PHASE 1: KNOWN-PLAINTEXT PROPAGATION ATTACK")
    print("  Using cribs to directly recover primer — O(1) per config")
    print("=" * 80)
    sys.stdout.flush()

    phase1_results = []

    for alpha_name, (alpha_str, idx_map) in ALPHABETS.items():
        ct_nums = to_nums(CT, idx_map)

        # PT-autokey variants
        for variant in ['Vig', 'Beau', 'VarBeau']:
            tag = f"KPA-PT-{variant}-{alpha_name}"
            print(f"\n  --- {tag} ---")
            sys.stdout.flush()

            res = kpa_pt_autokey(ct_nums, idx_map, alpha_str, variant)

            if res:
                # Sort by anchored score desc, then free score desc
                res.sort(key=lambda r: (-r['anchored_score'], -r['free_score']))
                top = res[0]
                print(f"  Found {len(res)} consistent primer lengths")
                print(f"  Best: L={top['primer_len']} primer='{top['primer']}' "
                      f"anchored={top['anchored_score']}/{N_CRIBS} "
                      f"free={top['free_score']}/24 "
                      f"bean={'PASS' if top['bean'] else 'FAIL'} "
                      f"IC={top['ic']:.4f} det={top['n_determined']}/{CT_LEN}")

                # Show top 5
                for r in res[:5]:
                    bean_str = "BEAN-PASS" if r['bean'] else "bean-fail"
                    ene_str = "ENE" if r.get('free_ene') else ""
                    bc_str = "BC" if r.get('free_bc') else ""
                    print(f"    L={r['primer_len']:2d} primer='{r['primer'][:20]}' "
                          f"anch={r['anchored_score']:2d} free={r['free_score']:2d} "
                          f"{bean_str} IC={r['ic']:.4f} "
                          f"det={r['n_determined']} {ene_str} {bc_str}")

                # Show any with score > STORE_THRESHOLD
                for r in res:
                    if r['anchored_score'] >= STORE_THRESHOLD or r['free_score'] >= 11:
                        print(f"  *** INTERESTING: L={r['primer_len']} primer='{r['primer']}' "
                              f"anch={r['anchored_score']} free={r['free_score']} "
                              f"{'BEAN-PASS' if r['bean'] else 'bean-fail'}")
                        print(f"      PT: {r['pt'][:80]}...")

                for r in res:
                    r['tag'] = tag
                phase1_results.extend(res)
            else:
                print(f"  No consistent primer lengths found (all contradicted)")

        # CT-autokey variants
        for variant in ['Vig', 'Beau', 'VarBeau']:
            tag = f"KPA-CT-{variant}-{alpha_name}"
            print(f"\n  --- {tag} ---")
            sys.stdout.flush()

            res = kpa_ct_autokey(ct_nums, idx_map, alpha_str, variant)

            if res:
                res.sort(key=lambda r: (-r['anchored_score'], -r['free_score']))
                top = res[0]
                print(f"  Found {len(res)} consistent primer lengths")
                print(f"  Best: L={top['primer_len']} primer='{top['primer']}' "
                      f"anchored={top['anchored_score']}/{N_CRIBS} "
                      f"free={top['free_score']}/24 "
                      f"bean={'PASS' if top['bean'] else 'FAIL'} "
                      f"IC={top['ic']:.4f}")

                for r in res[:5]:
                    bean_str = "BEAN-PASS" if r['bean'] else "bean-fail"
                    ene_str = "ENE" if r.get('free_ene') else ""
                    bc_str = "BC" if r.get('free_bc') else ""
                    print(f"    L={r['primer_len']:2d} primer='{r['primer'][:20]}' "
                          f"anch={r['anchored_score']:2d} free={r['free_score']:2d} "
                          f"{bean_str} IC={r['ic']:.4f} {ene_str} {bc_str}")

                for r in res:
                    if r['anchored_score'] >= STORE_THRESHOLD or r['free_score'] >= 11:
                        print(f"  *** INTERESTING: L={r['primer_len']} primer='{r['primer']}' "
                              f"anch={r['anchored_score']} free={r['free_score']} "
                              f"{'BEAN-PASS' if r['bean'] else 'bean-fail'}")
                        print(f"      PT: {r['pt'][:80]}...")

                for r in res:
                    r['tag'] = tag
                phase1_results.extend(res)
            else:
                print(f"  No consistent primer lengths found (all contradicted)")

    sys.stdout.flush()

    # Phase 1 summary
    if phase1_results:
        phase1_results.sort(key=lambda r: (-r['anchored_score'], -r['free_score']))
        best_p1 = phase1_results[0]
        phase_summaries['phase1'] = {
            'n_configs': len(phase1_results),
            'best_anchored': best_p1['anchored_score'],
            'best_free': best_p1['free_score'],
            'best_tag': best_p1.get('tag', ''),
            'best_primer': best_p1['primer'],
        }
        print(f"\n  Phase 1 overall best: anchored={best_p1['anchored_score']}/{N_CRIBS} "
              f"free={best_p1['free_score']}/24 "
              f"tag={best_p1.get('tag', '')} primer='{best_p1['primer']}'")

        # Check for Bean-passing results
        bean_pass_results = [r for r in phase1_results if r['bean']]
        if bean_pass_results:
            print(f"  Bean-passing results: {len(bean_pass_results)}")
            for r in bean_pass_results[:10]:
                print(f"    {r.get('tag', '')} L={r['primer_len']} primer='{r['primer']}' "
                      f"anch={r['anchored_score']} free={r['free_score']}")
    else:
        phase_summaries['phase1'] = {'n_configs': 0, 'best_anchored': 0, 'best_free': 0}
        print(f"\n  Phase 1: ALL autokey types contradicted by cribs")

    all_results.extend(phase1_results)
    sys.stdout.flush()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2: EXHAUSTIVE PRIMER SEARCH (lengths 1-3 + thematic)
    # ══════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 80)
    print("PHASE 2: EXHAUSTIVE PRIMER SEARCH")
    print("  All primers length 1-3 (26 + 676 + 17576 = 18278 per variant)")
    print("  Plus thematic keyword primers")
    print("=" * 80)
    sys.stdout.flush()

    phase2_results = []
    phase2_total = 0

    for alpha_name, (alpha_str, idx_map) in ALPHABETS.items():
        ct_nums = to_nums(CT, idx_map)

        for variant_name, decrypt_fn in DECRYPT_FUNCTIONS.items():
            tag = f"BF-{variant_name}-{alpha_name}"
            t0 = time.time()

            res, n_tested, best_anch, best_free = brute_force_primers(
                ct_nums, idx_map, alpha_str, alpha_name,
                decrypt_fn, variant_name,
                max_primer_len=3,
                thematic_primers=THEMATIC_PRIMERS,
            )

            elapsed = time.time() - t0
            phase2_total += n_tested

            print(f"  {tag}: {n_tested:,} tested in {elapsed:.1f}s | "
                  f"best_anchored={best_anch} best_free={best_free} "
                  f"above_noise={len(res)}")

            for r in res:
                r['tag'] = tag

            if res:
                res.sort(key=lambda r: (-r['anchored_score'], -r['free_score']))
                for r in res[:3]:
                    bean_str = "BEAN-PASS" if r['bean'] else "bean-fail"
                    print(f"    primer='{r['primer']}' anch={r['anchored_score']} "
                          f"free={r['free_score']} {bean_str} IC={r['ic']:.4f}")
                    if r['anchored_score'] >= STORE_THRESHOLD or r['free_score'] >= 11:
                        print(f"      PT: {r['pt'][:80]}...")

            phase2_results.extend(res)
            sys.stdout.flush()

    # Phase 2 summary
    if phase2_results:
        phase2_results.sort(key=lambda r: (-r['anchored_score'], -r['free_score']))
        best_p2 = phase2_results[0]
        phase_summaries['phase2'] = {
            'total_tested': phase2_total,
            'above_noise': len(phase2_results),
            'best_anchored': best_p2['anchored_score'],
            'best_free': best_p2['free_score'],
            'best_tag': best_p2.get('tag', ''),
            'best_primer': best_p2['primer'],
        }
        print(f"\n  Phase 2 overall: {phase2_total:,} configs tested, "
              f"{len(phase2_results)} above noise")
        print(f"  Best: anchored={best_p2['anchored_score']}/{N_CRIBS} "
              f"free={best_p2['free_score']}/24 "
              f"tag={best_p2.get('tag', '')} primer='{best_p2['primer']}'")
    else:
        phase_summaries['phase2'] = {
            'total_tested': phase2_total,
            'above_noise': 0,
            'best_anchored': 0,
            'best_free': 0,
        }
        print(f"\n  Phase 2: {phase2_total:,} configs tested, NONE above noise")

    all_results.extend(phase2_results)
    sys.stdout.flush()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3: BEAN CONSTRAINT ANALYSIS
    # ══════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 80)
    print("PHASE 3: BEAN CONSTRAINT ANALYSIS ON AUTOKEY KEYSTREAMS")
    print("  For each autokey type, which primer lengths can satisfy k[27]=k[65]?")
    print("=" * 80)
    sys.stdout.flush()

    for alpha_name, (alpha_str, idx_map) in ALPHABETS.items():
        ct_nums = to_nums(CT, idx_map)

        print(f"\n  === {alpha_name} alphabet ===")

        # For CT-autokey: k[i] = CT[i-L] for i >= L
        # Bean EQ: k[27] = k[65] => CT[27-L] = CT[65-L] for L <= 27
        # For L > 27: k[27] = primer[27], k[65] = CT[65-L]
        # For L > 65: k[27] = primer[27], k[65] = primer[65]

        print(f"\n  CT-autokey Bean analysis (k[27]=k[65]):")
        for variant in ['Vig', 'Beau', 'VarBeau']:
            bean_compatible_L = []
            for L in range(1, CT_LEN):
                # Compute k[27] and k[65]
                if 27 < L:
                    k27 = None  # primer position, unconstrained
                else:
                    k27 = ct_nums[27 - L]
                if 65 < L:
                    k65 = None  # primer position, unconstrained
                else:
                    k65 = ct_nums[65 - L]

                if k27 is None or k65 is None:
                    # At least one is a free primer position — can always satisfy
                    bean_compatible_L.append(L)
                elif k27 == k65:
                    bean_compatible_L.append(L)

            print(f"    CT-{variant}: {len(bean_compatible_L)} Bean-compatible L values "
                  f"(out of {CT_LEN - 1})")
            if len(bean_compatible_L) <= 30:
                print(f"      L = {bean_compatible_L}")

        # For PT-autokey: k[i] = PT[i-L] for i >= L
        # Bean EQ: k[27] = k[65] => PT[27-L] = PT[65-L]
        # If both 27-L and 65-L are crib positions, we can check
        print(f"\n  PT-autokey Bean analysis (k[27]=k[65]):")
        for variant in ['Vig', 'Beau', 'VarBeau']:
            for L in range(1, min(28, CT_LEN)):
                pos_a = 27 - L
                pos_b = 65 - L
                # k[27] = PT[pos_a], k[65] = PT[pos_b]
                # If both are crib positions, check if CRIB[pos_a] == CRIB[pos_b]
                if pos_a >= 0 and pos_b >= 0:
                    if pos_a in CRIB_DICT and pos_b in CRIB_DICT:
                        eq = CRIB_DICT[pos_a] == CRIB_DICT[pos_b]
                        if eq:
                            print(f"    PT-{variant} L={L}: k[27]=PT[{pos_a}]='{CRIB_DICT[pos_a]}' "
                                  f"k[65]=PT[{pos_b}]='{CRIB_DICT[pos_b]}' -> BEAN EQ PASS")
                        else:
                            print(f"    PT-{variant} L={L}: k[27]=PT[{pos_a}]='{CRIB_DICT[pos_a]}' "
                                  f"k[65]=PT[{pos_b}]='{CRIB_DICT[pos_b]}' -> BEAN EQ FAIL (eliminated)")

    sys.stdout.flush()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4: DEEP ANALYSIS OF BEST CANDIDATES
    # ══════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 80)
    print("PHASE 4: DEEP ANALYSIS OF BEST CANDIDATES")
    print("=" * 80)
    sys.stdout.flush()

    # Collect all results, sort by score
    all_results.sort(key=lambda r: (-r.get('anchored_score', 0), -r.get('free_score', 0)))

    # Show top 20
    print(f"\n  Top 20 results across all phases:")
    for i, r in enumerate(all_results[:20]):
        bean_str = "BEAN-PASS" if r.get('bean') else "bean-fail"
        ene_str = "ENE" if r.get('free_ene') else ""
        bc_str = "BC" if r.get('free_bc') else ""
        tag = r.get('tag', '?')
        print(f"  {i+1:2d}. {tag} primer='{r.get('primer', '?')[:20]}' "
              f"anch={r.get('anchored_score', 0):2d}/{N_CRIBS} "
              f"free={r.get('free_score', 0):2d}/24 "
              f"{bean_str} IC={r.get('ic', 0):.4f} "
              f"{ene_str} {bc_str}")

    # Show any breakthrough or signal
    signals = [r for r in all_results
               if r.get('anchored_score', 0) >= SIGNAL_THRESHOLD
               or r.get('free_score', 0) >= 13]
    if signals:
        print(f"\n  *** SIGNAL-LEVEL RESULTS: {len(signals)} ***")
        for r in signals:
            print(f"  Tag: {r.get('tag', '')}")
            print(f"  Primer: '{r.get('primer', '')}'")
            print(f"  Anchored: {r.get('anchored_score', 0)}/{N_CRIBS}")
            print(f"  Free: {r.get('free_score', 0)}/24")
            print(f"  Bean: {'PASS' if r.get('bean') else 'FAIL'}")
            print(f"  PT: {r.get('pt', '')}")
            print()
    else:
        print(f"\n  No signal-level results found.")

    # Show Bean-passing results
    bean_pass = [r for r in all_results if r.get('bean')]
    print(f"\n  Bean-passing results: {len(bean_pass)}")
    for r in bean_pass[:10]:
        print(f"    {r.get('tag', '')} primer='{r.get('primer', '')[:20]}' "
              f"anch={r.get('anchored_score', 0)} free={r.get('free_score', 0)}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 5: CT-AUTOKEY INTERMEDIATE TEXT ANALYSIS
    # For CT-autokey, the intermediate text I[j] = (CT[j] - CT[j-L]) mod 26
    # is FULLY DETERMINED (no key needed). Check if this intermediate text
    # contains crib substrings for any L.
    # ══════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 80)
    print("PHASE 5: CT-AUTOKEY INTERMEDIATE TEXT (no primer needed)")
    print("  For CT-autokey Vig: I[j] = (CT[j] - CT[j-L]) mod 26")
    print("  Check if I contains EASTNORTHEAST or BERLINCLOCK for any L")
    print("=" * 80)
    sys.stdout.flush()

    for alpha_name, (alpha_str, idx_map) in ALPHABETS.items():
        ct_nums = to_nums(CT, idx_map)

        for variant, op in [
            ('Vig', lambda a, b: (a - b) % MOD),
            ('Beau', lambda a, b: (b - a) % MOD),
            ('VarBeau', lambda a, b: (a + b) % MOD),
        ]:
            best_free_L = (0, 0)  # (score, L)
            for L in range(1, CT_LEN):
                # Compute intermediate text for positions L..96
                inter = []
                for j in range(L, CT_LEN):
                    inter.append(op(ct_nums[j], ct_nums[j - L]))
                inter_text = to_text(inter, alpha_str)

                # Check for cribs as substrings
                score = 0
                if 'EASTNORTHEAST' in inter_text:
                    score += 13
                if 'BERLINCLOCK' in inter_text:
                    score += 11

                if score > best_free_L[0]:
                    best_free_L = (score, L)

                if score > 0:
                    print(f"  *** CT-{variant}-{alpha_name} L={L}: "
                          f"free_score={score} intermediate contains crib!")
                    print(f"      I: {inter_text[:80]}...")

                # Also check anchored positions (shifted by L)
                # At position j in the intermediate, the PT position is j
                # (if no transposition). Crib at PT pos 21 => I[21] should match...
                # But I starts at position L, so I[0] = position L in CT.
                # For anchored check: crib at pos p => I[p-L] should match
                anchored = 0
                for pos, ch in CRIB_DICT.items():
                    idx_in_inter = pos - L
                    if 0 <= idx_in_inter < len(inter_text):
                        if inter_text[idx_in_inter] == ch:
                            anchored += 1
                if anchored > NOISE_FLOOR:
                    print(f"  CT-{variant}-{alpha_name} L={L}: "
                          f"anchored={anchored}/{N_CRIBS} (shifted)")

            print(f"  CT-{variant}-{alpha_name}: best free score = {best_free_L[0]} at L={best_free_L[1]}")

    sys.stdout.flush()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 6: BIDIRECTIONAL PROPAGATION DEEP ANALYSIS
    # For the KPA results, analyze the determined positions and look for
    # English-like patterns in the plaintext.
    # ══════════════════════════════════════════════════════════════════════

    print("\n" + "=" * 80)
    print("PHASE 6: ENGLISH QUALITY ANALYSIS OF BEST CANDIDATES")
    print("=" * 80)
    sys.stdout.flush()

    # Take top 30 by anchored score and analyze
    top_candidates = sorted(all_results,
                            key=lambda r: (-r.get('anchored_score', 0), -r.get('free_score', 0)))[:30]

    for i, r in enumerate(top_candidates[:10]):
        pt = r.get('pt', '')
        if not pt:
            continue
        eng = english_bigram_score(pt)
        ic_val = ic(pt)
        tag = r.get('tag', '?')
        print(f"  {i+1}. {tag} L={r.get('primer_len', '?')} primer='{r.get('primer', '?')[:15]}' "
              f"anch={r.get('anchored_score', 0)} "
              f"eng_bigrams={eng} IC={ic_val:.4f}")
        print(f"     PT: {pt[:97]}")
        # Check for any English words
        words_found = []
        for w in ['THE', 'AND', 'WAS', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU',
                   'ALL', 'CAN', 'HER', 'ONE', 'OUR', 'OUT', 'HAD', 'HAS',
                   'HIS', 'HOW', 'ITS', 'MAY', 'NEW', 'NOW', 'OLD', 'SEE',
                   'WAY', 'WHO', 'DID', 'GET', 'SAY', 'SHE', 'TOO', 'USE',
                   'EAST', 'NORTH', 'BERLIN', 'CLOCK', 'TIME', 'WALL',
                   'BETWEEN', 'SLOWLY', 'BURIED', 'SHADOW', 'UNDER',
                   'GROUND', 'LAYER', 'SECRET', 'HIDDEN', 'CLUE']:
            if w in pt:
                words_found.append(w)
        if words_found:
            print(f"     English words: {', '.join(words_found)}")

    sys.stdout.flush()

    # ══════════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════════════════════

    total_time = time.time() - t_start

    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)

    print(f"\n  Total time: {total_time:.1f}s")
    print(f"  Total results above noise: {len(all_results)}")

    if all_results:
        best = all_results[0]
        print(f"\n  Overall best anchored: {best.get('anchored_score', 0)}/{N_CRIBS} "
              f"({best.get('tag', '')}, primer='{best.get('primer', '')}')")

        best_free = max(all_results, key=lambda r: r.get('free_score', 0))
        print(f"  Overall best free: {best_free.get('free_score', 0)}/24 "
              f"({best_free.get('tag', '')}, primer='{best_free.get('primer', '')}')")

        bean_results = [r for r in all_results if r.get('bean')]
        print(f"  Bean-passing: {len(bean_results)} results")

    # Verdict
    max_anchored = max((r.get('anchored_score', 0) for r in all_results), default=0)
    max_free = max((r.get('free_score', 0) for r in all_results), default=0)

    if max_anchored >= 24 or max_free >= 24:
        verdict = "BREAKTHROUGH"
    elif max_anchored >= SIGNAL_THRESHOLD or max_free >= 13:
        verdict = "SIGNAL — investigate further"
    elif max_anchored >= STORE_THRESHOLD or max_free >= 11:
        verdict = "INTERESTING — above noise but likely not autokey"
    elif max_anchored > NOISE_FLOOR:
        verdict = "MARGINAL — slightly above noise floor"
    else:
        verdict = "NO SIGNAL — autokey eliminated for direct correspondence"

    print(f"\n  VERDICT: {verdict}")

    # Per-phase summary
    for phase, summary in phase_summaries.items():
        print(f"\n  {phase}: {summary}")

    # Save artifact
    artifact = {
        'experiment': 'e_autokey_k4',
        'description': 'Comprehensive autokey cipher attack on K4',
        'total_time': total_time,
        'total_above_noise': len(all_results),
        'max_anchored': max_anchored,
        'max_free': max_free,
        'verdict': verdict,
        'phase_summaries': phase_summaries,
        'top_10': [{k: v for k, v in r.items() if k != 'ks'}
                   for r in all_results[:10]],
    }

    os.makedirs("results", exist_ok=True)
    artifact_path = "results/e_autokey_k4.json"
    with open(artifact_path, 'w') as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\n  Artifact: {artifact_path}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/grille/e_autokey_k4.py")

    print("\n[E-AUTOKEY-K4 COMPLETE]")
    return max_anchored


if __name__ == '__main__':
    main()
