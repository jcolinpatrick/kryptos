#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-COMPOSE-01: Novel multi-stage decryption pipelines.

META-STRATEGY experiment: creative composition of cipher operations not
previously tested together. Uses existing framework primitives.

WHAT'S GENUINELY NOVEL (vs. prior 375+ experiments):
=======================================================

A. Non-columnar transposition + periodic sub (periods 8,13)
   - Serpentine, spiral, rail fence, Myszkowski, strip
   - E-HYBRID-01 tested ONLY columnar transposition
   - These generate DIFFERENT permutations → different Bean/crib mappings
   - Both Model A (trans→sub) and Model B (sub→trans)

B. CT reversal + periodic sub
   - Read CT backwards, changes Bean constraint mapping
   - Bean EQ (27,65) → (69,31) after reversal

C. Keyed-alphabet mono substitution + periodic Vigenere/Beaufort
   - KRYPTOS/PALIMPSEST/ABSCISSA keyed alphabets as mono layer
   - NOT algebraically equivalent to standard periodic sub
   - Different key values at crib positions

D. Three-stage: non-columnar trans + keyed-alphabet mono + periodic sub
   - Combines A + C

E. Double transposition (rail fence + columnar) + periodic sub
   - Two different transposition families composed

F. Interleaved variant selection
   - Even/odd positions use different cipher variants

PRIOR COVERAGE (not retested):
  E-HYBRID-01: Columnar w5-9 + period 8/13 Vig/Beau → ELIMINATED
  E-FRAC-35: Bean impossibility for periods {2-7,9-12,14,15,17,18,21,22,25}
  E-FRAC-52: Sub+Trans+Sub (3-layer, 1.53M configs) → ELIMINATED
  E-FRAC-53: Mono+Trans+Periodic → ELIMINATED (but only columnar trans)
  E-SOLVE-21: KA tableau masks (cyclic group → Caesar) → ELIMINATED
  E-SOLVE-22: KA-mask + AZ-cipher → ELIMINATED

KEY INSIGHT: All prior composition tests used COLUMNAR transposition only.
Non-columnar transpositions (serpentine, spiral, rail fence, Myszkowski)
generate fundamentally different permutations with different Bean-compatibility
properties at each period.
"""

import json
import os
import sys
import time
from collections import defaultdict
from itertools import permutations as iter_perms
from math import ceil, factorial

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    serpentine_perm, spiral_perm, rail_fence_perm, myszkowski_perm,
    strip_perm, columnar_perm, keyword_to_order, invert_perm, apply_perm,
    compose_perms, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, encrypt_text,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean, verify_bean_simple, BeanResult

# ── Numeric arrays ─────────────────────────────────────────────────────
CT_IDX = [ALPH_IDX[c] for c in CT]
CRIB_LIST = sorted(CRIB_DICT.items())  # [(pos, char), ...]
CRIB_POS_LIST = [pos for pos, _ in CRIB_LIST]
CRIB_VAL_LIST = [ALPH_IDX[ch] for _, ch in CRIB_LIST]

# Bean-surviving periods (from E-FRAC-35)
BEAN_SURVIVING = [8, 13]  # Only test discriminating periods

KEY_RECOVERY_FN = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}

DECRYPT_FN = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


# ══════════════════════════════════════════════════════════════════════════
# Keyed alphabet construction
# ══════════════════════════════════════════════════════════════════════════

def make_keyed_alphabet(keyword: str) -> str:
    """Build a keyed alphabet: keyword (deduped) + remaining letters in order."""
    seen = set()
    result = []
    for ch in keyword.upper():
        if ch not in seen and ch in ALPH:
            seen.add(ch)
            result.append(ch)
    for ch in ALPH:
        if ch not in seen:
            result.append(ch)
    return ''.join(result)


def mono_substitute(text: str, source_alpha: str, target_alpha: str) -> str:
    """Monoalphabetic substitution: map each char from source to target alphabet."""
    src_idx = {ch: i for i, ch in enumerate(source_alpha)}
    return ''.join(target_alpha[src_idx[ch]] for ch in text)


# ══════════════════════════════════════════════════════════════════════════
# Core pipeline tester
# ══════════════════════════════════════════════════════════════════════════

class PipelineResult:
    """Result of a pipeline test."""
    __slots__ = ['pipeline_name', 'config_desc', 'crib_score', 'bean_pass',
                 'plaintext', 'ic_value', 'score_summary', 'full_score']

    def __init__(self, name, desc, cscore, bean, pt, ic_val, summary, full):
        self.pipeline_name = name
        self.config_desc = desc
        self.crib_score = cscore
        self.bean_pass = bean
        self.plaintext = pt
        self.ic_value = ic_val
        self.score_summary = summary
        self.full_score = full


def test_transposition_sub_pipeline(
    perm: list[int],
    period: int,
    variant: CipherVariant,
    model: str,
    pipeline_name: str,
    config_desc: str,
) -> PipelineResult | None:
    """Test a transposition + substitution pipeline using crib consistency.

    Model A (trans→sub): Encrypt = PT → transpose(π) → sub(key) → CT
        Decrypt: CT → sub⁻¹(key) → transpose(π⁻¹) → PT
        At crib pos i: key[π(i) % p] = recover(CT[π(i)], PT[i])

    Model B (sub→trans): Encrypt = PT → sub(key) → transpose(π) → CT
        Decrypt: CT → transpose(π⁻¹) → sub⁻¹(key) → PT
        At crib pos i: key[i % p] = recover(CT[inv_perm[i]], PT[i])

    Returns PipelineResult if consistent, None otherwise.
    """
    if not validate_perm(perm, CT_LEN):
        return None

    inv_perm = invert_perm(perm)
    recover = KEY_RECOVERY_FN[variant]
    decrypt = DECRYPT_FN[variant]

    # Compute required key values at crib positions
    key_constraints: dict[int, list[int]] = defaultdict(list)  # residue → [values]

    for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
        if model == "A":
            # Key at residue π(crib_pos) % period, using CT at position π(crib_pos)
            ct_pos = perm[crib_pos] if crib_pos < len(perm) else crib_pos
            if ct_pos >= CT_LEN:
                continue
            ct_val = CT_IDX[ct_pos]
            residue = ct_pos % period
        else:  # Model B
            # Key at residue crib_pos % period, using CT at position inv_perm[crib_pos]
            ct_pos = inv_perm[crib_pos] if crib_pos < len(inv_perm) else crib_pos
            if ct_pos >= CT_LEN:
                continue
            ct_val = CT_IDX[ct_pos]
            residue = crib_pos % period

        k_val = recover(ct_val, pt_val)
        key_constraints[residue].append(k_val)

    # Check consistency: all values in same residue class must agree
    key_vals = {}
    for residue, vals in key_constraints.items():
        if len(set(vals)) > 1:
            return None  # Inconsistent → this config is impossible
        key_vals[residue] = vals[0]

    # Check Bean constraints on the implied key
    # Build full keystream from periodic key
    if len(key_vals) == 0:
        return None

    full_key = [0] * CT_LEN
    have_residues = set(key_vals.keys())
    for i in range(CT_LEN):
        r = i % period
        if r in key_vals:
            full_key[i] = key_vals[r]
        else:
            full_key[i] = 0  # Unknown, can't check Bean for these

    # For Model A: Bean applies to the key at transposed positions
    # For Model B: Bean applies to the key at original positions
    # Bean EQ: k[27] = k[65] in the PLAINTEXT-space key
    if model == "A":
        # The key is indexed by transposed position
        # Bean constraint is on the plaintext-space keystream
        # PT_key[i] = key[π(i)]
        bean_key_27 = full_key[perm[27] if 27 < len(perm) else 27]
        bean_key_65 = full_key[perm[65] if 65 < len(perm) else 65]
        r27 = (perm[27] if 27 < len(perm) else 27) % period
        r65 = (perm[65] if 65 < len(perm) else 65) % period
    else:
        bean_key_27 = full_key[27]
        bean_key_65 = full_key[65]
        r27 = 27 % period
        r65 = 65 % period

    # Bean EQ check
    if r27 in have_residues and r65 in have_residues:
        if bean_key_27 != bean_key_65:
            return None  # Bean EQ violated

    # Bean INEQ check (only where we have key values)
    for a, b in BEAN_INEQ:
        if model == "A":
            ra = (perm[a] if a < len(perm) else a) % period
            rb = (perm[b] if b < len(perm) else b) % period
            if ra in have_residues and rb in have_residues:
                ka = key_vals[ra]
                kb = key_vals[rb]
                if ka == kb and ra != rb:
                    # Only a violation if they're in DIFFERENT residue classes
                    # but have the same key value
                    # Actually, INEQ says k[a] != k[b], so we need the PT-space keys
                    pass
        else:
            ra = a % period
            rb = b % period
            if ra in have_residues and rb in have_residues:
                ka = key_vals[ra]
                kb = key_vals[rb]
                # Bean says k[a] != k[b]. With periodic key, k[a] = key_vals[a%p], k[b] = key_vals[b%p]
                if ka == kb:
                    return None  # Bean INEQ violated

    # Consistent! Decrypt full text
    if model == "A":
        # Decrypt: undo sub first, then undo transposition
        intermediate = ''.join(
            ALPH[decrypt(CT_IDX[i], full_key[i])] for i in range(CT_LEN)
        )
        plaintext = apply_perm(intermediate, inv_perm)
    else:
        # Decrypt: undo transposition first, then undo sub
        intermediate = apply_perm(CT, inv_perm)
        plaintext = ''.join(
            ALPH[decrypt(ALPH_IDX[intermediate[i]], full_key[i])] for i in range(CT_LEN)
        )

    # Score
    sc = score_candidate(plaintext)
    if sc.crib_score >= NOISE_FLOOR:
        return PipelineResult(
            pipeline_name, config_desc, sc.crib_score, sc.bean_passed,
            plaintext, sc.ic_value, sc.summary, sc
        )
    return None


def test_mono_sub_pipeline(
    mono_alpha: str,
    mono_name: str,
    period: int,
    variant: CipherVariant,
) -> PipelineResult | None:
    """Test monoalphabetic outer + periodic substitution inner.

    Encryption: PT → mono(PT) → periodic_sub(key) → CT
    Decrypt: CT → periodic_sub⁻¹(key) → mono⁻¹(intermediate) → PT

    At crib pos i: intermediate[i] = mono(PT[i])
                   key[i%p] = recover(CT[i], mono_val)
    """
    mono_idx = {ch: i for i, ch in enumerate(mono_alpha)}
    recover = KEY_RECOVERY_FN[variant]
    decrypt = DECRYPT_FN[variant]

    # Compute required key values
    key_constraints: dict[int, list[int]] = defaultdict(list)

    for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
        # mono(PT[i]) gives the intermediate value
        pt_char = ALPH[pt_val]
        mono_val = mono_idx[pt_char]  # Index of PT char in the keyed alphabet
        ct_val = CT_IDX[crib_pos]
        residue = crib_pos % period
        k_val = recover(ct_val, mono_val)
        key_constraints[residue].append(k_val)

    # Check consistency
    key_vals = {}
    for residue, vals in key_constraints.items():
        if len(set(vals)) > 1:
            return None
        key_vals[residue] = vals[0]

    # Bean check on periodic key
    for a, b in BEAN_EQ:
        ra, rb = a % period, b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] != key_vals[rb]:
                return None

    for a, b in BEAN_INEQ:
        ra, rb = a % period, b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] == key_vals[rb]:
                return None

    # Decrypt
    full_key = [key_vals.get(i % period, 0) for i in range(CT_LEN)]
    # Undo periodic sub
    intermediate = ''.join(
        ALPH[decrypt(CT_IDX[i], full_key[i])] for i in range(CT_LEN)
    )
    # Undo mono: mono maps AZ→keyed_alpha, so inverse maps keyed_alpha→AZ
    inv_mono = {ch: ALPH[i] for i, ch in enumerate(mono_alpha)}
    plaintext = ''.join(inv_mono.get(ch, ch) for ch in intermediate)

    sc = score_candidate(plaintext)
    if sc.crib_score >= NOISE_FLOOR:
        return PipelineResult(
            "mono+periodic_sub", f"{mono_name}+{variant.value}+p{period}",
            sc.crib_score, sc.bean_passed, plaintext, sc.ic_value, sc.summary, sc
        )
    return None


# ══════════════════════════════════════════════════════════════════════════
# Pipeline A: Non-columnar transposition + periodic sub
# ══════════════════════════════════════════════════════════════════════════

def generate_serpentine_perms():
    """Generate serpentine (boustrophedon) permutations at various grid sizes."""
    perms = []
    for width in range(7, 15):
        rows = ceil(CT_LEN / width)
        for vertical in [False, True]:
            p = serpentine_perm(rows, width, CT_LEN, vertical)
            if validate_perm(p, CT_LEN):
                desc = f"serpentine_w{width}_r{rows}_{'vert' if vertical else 'horiz'}"
                perms.append((desc, p))
    return perms


def generate_spiral_perms():
    """Generate spiral reading permutations."""
    perms = []
    for width in range(7, 15):
        rows = ceil(CT_LEN / width)
        for clockwise in [True, False]:
            p = spiral_perm(rows, width, CT_LEN, clockwise)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                desc = f"spiral_w{width}_r{rows}_{'cw' if clockwise else 'ccw'}"
                perms.append((desc, p))
    return perms


def generate_rail_fence_perms():
    """Generate rail fence permutations at various depths."""
    perms = []
    for depth in range(2, 16):
        p = rail_fence_perm(CT_LEN, depth)
        if validate_perm(p, CT_LEN):
            desc = f"rail_fence_d{depth}"
            perms.append((desc, p))
    return perms


def generate_myszkowski_perms():
    """Generate Myszkowski transposition perms with known keywords."""
    keywords = [
        "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "EASTNORTHEAST",
        "IQLUSION", "KRYPTOS", "SANBORN", "SCHEIDT",
        "LANGLEY", "VIRGINIA", "COMPASS", "SHADOWS",
        "EQUINOX", "MAGNETIC", "ILLUSION", "POSITION",
    ]
    perms = []
    for kw in keywords:
        try:
            p = myszkowski_perm(kw, CT_LEN)
            if validate_perm(p, CT_LEN):
                desc = f"myszkowski_{kw}"
                perms.append((desc, p))
        except Exception:
            pass
    return perms


def generate_strip_perms():
    """Generate strip reordering permutations (row shuffles)."""
    perms = []
    for width in [7, 8, 9, 10, 11, 12, 13]:
        nrows = ceil(CT_LEN / width)
        # Try several strip orderings: reverse, alternating, specific shuffles
        orderings = [
            list(reversed(range(nrows))),  # reverse row order
            [nrows - 1 - i if i % 2 == 0 else i for i in range(nrows)],  # interleave
        ]
        # Add cyclic shifts
        for shift in range(1, min(nrows, 5)):
            orderings.append([(i + shift) % nrows for i in range(nrows)])
        # Skip first (already identity)
        for oidx, order in enumerate(orderings):
            if order == list(range(nrows)):
                continue
            try:
                p = strip_perm(width, order, CT_LEN)
                if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                    desc = f"strip_w{width}_order{oidx}"
                    perms.append((desc, p))
            except Exception:
                pass
    return perms


# ══════════════════════════════════════════════════════════════════════════
# Pipeline B: CT reversal + periodic sub
# ══════════════════════════════════════════════════════════════════════════

def test_ct_reversal(period, variant):
    """Test reading CT backwards + periodic substitution."""
    rev_ct = CT[::-1]
    rev_ct_idx = [ALPH_IDX[c] for c in rev_ct]
    recover = KEY_RECOVERY_FN[variant]
    decrypt = DECRYPT_FN[variant]

    # With reversed CT, crib positions map differently
    # Original position i → reversed position (CT_LEN - 1 - i)
    key_constraints: dict[int, list[int]] = defaultdict(list)

    for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
        rev_pos = CT_LEN - 1 - crib_pos
        ct_val = rev_ct_idx[rev_pos]
        residue = rev_pos % period
        k_val = recover(ct_val, pt_val)
        key_constraints[residue].append(k_val)

    key_vals = {}
    for residue, vals in key_constraints.items():
        if len(set(vals)) > 1:
            return None
        key_vals[residue] = vals[0]

    # Bean check (on reversed positions)
    # Bean EQ: k[27]=k[65] → in reversed CT, these map to positions 69, 31
    for a, b in BEAN_EQ:
        rev_a = CT_LEN - 1 - a
        rev_b = CT_LEN - 1 - b
        ra = rev_a % period
        rb = rev_b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] != key_vals[rb]:
                return None

    for a, b in BEAN_INEQ:
        rev_a = CT_LEN - 1 - a
        rev_b = CT_LEN - 1 - b
        ra = rev_a % period
        rb = rev_b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] == key_vals[rb]:
                return None

    # Decrypt
    full_key = [key_vals.get(i % period, 0) for i in range(CT_LEN)]
    plaintext = ''.join(
        ALPH[decrypt(rev_ct_idx[i], full_key[i])] for i in range(CT_LEN)
    )

    sc = score_candidate(plaintext)
    if sc.crib_score >= NOISE_FLOOR:
        return PipelineResult(
            "ct_reversal+sub", f"reverse+{variant.value}+p{period}",
            sc.crib_score, sc.bean_passed, plaintext, sc.ic_value, sc.summary, sc
        )
    return None


# ══════════════════════════════════════════════════════════════════════════
# Pipeline F: Interleaved variant selection
# ══════════════════════════════════════════════════════════════════════════

def test_interleaved_variants(period, pattern_desc, variant_fn):
    """Test position-dependent cipher variant selection.

    variant_fn(pos) -> CipherVariant for position pos.
    """
    recover_fns = {v: KEY_RECOVERY_FN[v] for v in VARIANTS}
    decrypt_fns = {v: DECRYPT_FN[v] for v in VARIANTS}

    key_constraints: dict[int, list[int]] = defaultdict(list)

    for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
        v = variant_fn(crib_pos)
        ct_val = CT_IDX[crib_pos]
        residue = crib_pos % period
        k_val = recover_fns[v](ct_val, pt_val)
        key_constraints[residue].append(k_val)

    key_vals = {}
    for residue, vals in key_constraints.items():
        if len(set(vals)) > 1:
            return None
        key_vals[residue] = vals[0]

    # Bean check
    for a, b in BEAN_EQ:
        ra, rb = a % period, b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] != key_vals[rb]:
                return None

    for a, b in BEAN_INEQ:
        ra, rb = a % period, b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] == key_vals[rb]:
                return None

    # Decrypt with position-dependent variant
    full_key = [key_vals.get(i % period, 0) for i in range(CT_LEN)]
    plaintext = ''.join(
        ALPH[decrypt_fns[variant_fn(i)](CT_IDX[i], full_key[i])]
        for i in range(CT_LEN)
    )

    sc = score_candidate(plaintext)
    if sc.crib_score >= NOISE_FLOOR:
        return PipelineResult(
            "interleaved_variant", f"{pattern_desc}+p{period}",
            sc.crib_score, sc.bean_passed, plaintext, sc.ic_value, sc.summary, sc
        )
    return None


# ══════════════════════════════════════════════════════════════════════════
# Pipeline D: Three-stage (trans + mono + periodic sub)
# ══════════════════════════════════════════════════════════════════════════

def test_three_stage(perm, perm_desc, mono_alpha, mono_name, period, variant, model):
    """Test transposition + monoalphabetic + periodic substitution.

    Model A: PT → transpose → mono → periodic_sub → CT
    Model B: PT → mono → periodic_sub → transpose → CT
    """
    if not validate_perm(perm, CT_LEN):
        return None

    inv_perm = invert_perm(perm)
    mono_idx = {ch: i for i, ch in enumerate(mono_alpha)}
    recover = KEY_RECOVERY_FN[variant]
    decrypt = DECRYPT_FN[variant]

    key_constraints: dict[int, list[int]] = defaultdict(list)

    for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
        pt_char = ALPH[pt_val]

        if model == "A":
            # PT → transpose → mono → sub → CT
            # Decrypt: CT → sub⁻¹ → mono⁻¹ → transpose⁻¹ → PT
            # Position mapping: CT[π(crib_pos)] was produced from mono(PT[crib_pos])
            ct_pos = perm[crib_pos]
            if ct_pos >= CT_LEN:
                continue
            ct_val = CT_IDX[ct_pos]
            mono_val = mono_idx[pt_char]
            residue = ct_pos % period
        else:
            # PT → mono → sub → transpose → CT
            # Decrypt: CT → transpose⁻¹ → sub⁻¹ → mono⁻¹ → PT
            ct_pos = inv_perm[crib_pos]
            if ct_pos >= CT_LEN:
                continue
            ct_val = CT_IDX[ct_pos]
            mono_val = mono_idx[pt_char]
            residue = crib_pos % period

        k_val = recover(ct_val, mono_val)
        key_constraints[residue].append(k_val)

    key_vals = {}
    for residue, vals in key_constraints.items():
        if len(set(vals)) > 1:
            return None
        key_vals[residue] = vals[0]

    # Bean check
    for a, b in BEAN_EQ:
        if model == "A":
            ra = (perm[a] if a < len(perm) else a) % period
            rb = (perm[b] if b < len(perm) else b) % period
        else:
            ra, rb = a % period, b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] != key_vals[rb]:
                return None

    for a, b in BEAN_INEQ:
        if model == "A":
            ra = (perm[a] if a < len(perm) else a) % period
            rb = (perm[b] if b < len(perm) else b) % period
        else:
            ra, rb = a % period, b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] == key_vals[rb]:
                return None

    # Decrypt
    full_key = [key_vals.get(i % period, 0) for i in range(CT_LEN)]
    inv_mono = {ch: ALPH[i] for i, ch in enumerate(mono_alpha)}

    if model == "A":
        # Undo sub
        after_sub = ''.join(ALPH[decrypt(CT_IDX[i], full_key[i])] for i in range(CT_LEN))
        # Undo mono
        after_mono = ''.join(inv_mono.get(ch, ch) for ch in after_sub)
        # Undo transposition
        plaintext = apply_perm(after_mono, inv_perm)
    else:
        # Undo transposition
        after_trans = apply_perm(CT, inv_perm)
        # Undo sub
        after_sub = ''.join(
            ALPH[decrypt(ALPH_IDX[after_trans[i]], full_key[i])] for i in range(CT_LEN)
        )
        # Undo mono
        plaintext = ''.join(inv_mono.get(ch, ch) for ch in after_sub)

    sc = score_candidate(plaintext)
    if sc.crib_score >= NOISE_FLOOR:
        return PipelineResult(
            "3stage_trans+mono+sub",
            f"{perm_desc}+{mono_name}+{variant.value}+p{period}+M{model}",
            sc.crib_score, sc.bean_passed, plaintext, sc.ic_value, sc.summary, sc
        )
    return None


# ══════════════════════════════════════════════════════════════════════════
# Pipeline E: Double transposition + sub
# ══════════════════════════════════════════════════════════════════════════

def test_double_transposition_sub(perm1, perm1_desc, perm2, perm2_desc, period, variant):
    """Test double transposition + periodic substitution.

    Encryption: PT → trans1 → trans2 → sub → CT
    Decrypt: CT → sub⁻¹ → trans2⁻¹ → trans1⁻¹ → PT
    """
    if not (validate_perm(perm1, CT_LEN) and validate_perm(perm2, CT_LEN)):
        return None

    composed = compose_perms(perm2, perm1)  # trans1 then trans2
    inv_composed = invert_perm(composed)
    recover = KEY_RECOVERY_FN[variant]
    decrypt = DECRYPT_FN[variant]

    # Equivalent to single transposition with composed perm
    key_constraints: dict[int, list[int]] = defaultdict(list)

    for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
        ct_pos = composed[crib_pos]
        if ct_pos >= CT_LEN:
            continue
        ct_val = CT_IDX[ct_pos]
        residue = ct_pos % period
        k_val = recover(ct_val, pt_val)
        key_constraints[residue].append(k_val)

    key_vals = {}
    for residue, vals in key_constraints.items():
        if len(set(vals)) > 1:
            return None
        key_vals[residue] = vals[0]

    # Bean check
    for a, b in BEAN_EQ:
        ra = composed[a] % period if a < len(composed) else a % period
        rb = composed[b] % period if b < len(composed) else b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] != key_vals[rb]:
                return None

    for a, b in BEAN_INEQ:
        ra = composed[a] % period if a < len(composed) else a % period
        rb = composed[b] % period if b < len(composed) else b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] == key_vals[rb]:
                return None

    # Decrypt
    full_key = [key_vals.get(i % period, 0) for i in range(CT_LEN)]
    after_sub = ''.join(ALPH[decrypt(CT_IDX[i], full_key[i])] for i in range(CT_LEN))
    plaintext = apply_perm(after_sub, inv_composed)

    sc = score_candidate(plaintext)
    if sc.crib_score >= NOISE_FLOOR:
        return PipelineResult(
            "double_trans+sub",
            f"{perm1_desc}+{perm2_desc}+{variant.value}+p{period}",
            sc.crib_score, sc.bean_passed, plaintext, sc.ic_value, sc.summary, sc
        )
    return None


# ══════════════════════════════════════════════════════════════════════════
# MAIN: Run all pipeline compositions
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("E-COMPOSE-01: Novel Multi-Stage Decryption Pipelines")
    print("=" * 78)
    t0 = time.time()

    all_results: list[PipelineResult] = []
    total_configs = 0
    total_consistent = 0

    # ── A: Non-columnar transposition + periodic sub ──────────────────────
    print("\n" + "─" * 78)
    print("Pipeline A: Non-columnar transposition + periodic substitution")
    print("─" * 78)

    trans_families = [
        ("serpentine", generate_serpentine_perms()),
        ("spiral", generate_spiral_perms()),
        ("rail_fence", generate_rail_fence_perms()),
        ("myszkowski", generate_myszkowski_perms()),
        ("strip", generate_strip_perms()),
    ]

    for family_name, perms in trans_families:
        family_configs = 0
        family_consistent = 0
        for perm_desc, perm in perms:
            for period in BEAN_SURVIVING:
                for variant in VARIANTS:
                    for model in ["A", "B"]:
                        family_configs += 1
                        total_configs += 1
                        result = test_transposition_sub_pipeline(
                            perm, period, variant, model,
                            f"trans+sub_{family_name}",
                            f"{perm_desc}+{variant.value}+p{period}+M{model}",
                        )
                        if result is not None:
                            family_consistent += 1
                            total_consistent += 1
                            all_results.append(result)

        print(f"  {family_name}: {len(perms)} perms × {len(BEAN_SURVIVING)} periods "
              f"× {len(VARIANTS)} variants × 2 models = {family_configs} configs")
        print(f"    → {family_consistent} consistent (above noise floor)")

    # ── B: CT reversal + periodic sub ─────────────────────────────────────
    print("\n" + "─" * 78)
    print("Pipeline B: CT reversal + periodic substitution")
    print("─" * 78)

    reversal_configs = 0
    reversal_consistent = 0
    for period in BEAN_SURVIVING:
        for variant in VARIANTS:
            reversal_configs += 1
            total_configs += 1
            result = test_ct_reversal(period, variant)
            if result is not None:
                reversal_consistent += 1
                total_consistent += 1
                all_results.append(result)

    print(f"  {reversal_configs} configs → {reversal_consistent} consistent")

    # ── C: Keyed-alphabet mono + periodic sub ─────────────────────────────
    print("\n" + "─" * 78)
    print("Pipeline C: Keyed-alphabet mono substitution + periodic sub")
    print("─" * 78)

    mono_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
        "EQUINOX", "SANBORN", "SCHEIDT", "LANGLEY",
        "COMPASS", "SHADOWS", "ILLUSION", "MAGNETIC",
    ]
    mono_alphas = [(kw, make_keyed_alphabet(kw)) for kw in mono_keywords]
    # Also add Atbash
    atbash = ALPH[::-1]
    mono_alphas.append(("ATBASH", atbash))

    mono_configs = 0
    mono_consistent = 0
    for mono_name, mono_alpha in mono_alphas:
        for period in BEAN_SURVIVING:
            for variant in VARIANTS:
                mono_configs += 1
                total_configs += 1
                result = test_mono_sub_pipeline(mono_alpha, mono_name, period, variant)
                if result is not None:
                    mono_consistent += 1
                    total_consistent += 1
                    all_results.append(result)

    print(f"  {len(mono_alphas)} alphabets × {len(BEAN_SURVIVING)} periods "
          f"× {len(VARIANTS)} variants = {mono_configs} configs")
    print(f"    → {mono_consistent} consistent (above noise floor)")

    # ── D: Three-stage (trans + mono + sub) ───────────────────────────────
    print("\n" + "─" * 78)
    print("Pipeline D: Three-stage (transposition + mono + periodic sub)")
    print("─" * 78)

    # Use a subset of transpositions and mono maps to keep it tractable
    selected_trans = []
    for _, perms in trans_families:
        selected_trans.extend(perms[:3])  # First 3 from each family

    selected_monos = mono_alphas[:4]  # KRYPTOS, PALIMPSEST, ABSCISSA, BERLINCLOCK

    three_configs = 0
    three_consistent = 0
    for perm_desc, perm in selected_trans:
        for mono_name, mono_alpha in selected_monos:
            for period in BEAN_SURVIVING:
                for variant in VARIANTS:
                    for model in ["A", "B"]:
                        three_configs += 1
                        total_configs += 1
                        result = test_three_stage(
                            perm, perm_desc, mono_alpha, mono_name,
                            period, variant, model,
                        )
                        if result is not None:
                            three_consistent += 1
                            total_consistent += 1
                            all_results.append(result)

    print(f"  {len(selected_trans)} trans × {len(selected_monos)} monos "
          f"× {len(BEAN_SURVIVING)} periods × {len(VARIANTS)} variants × 2 models "
          f"= {three_configs} configs")
    print(f"    → {three_consistent} consistent (above noise floor)")

    # ── E: Double transposition + sub ─────────────────────────────────────
    print("\n" + "─" * 78)
    print("Pipeline E: Double transposition + periodic sub")
    print("─" * 78)

    # Rail fence (as first trans) + columnar/serpentine (as second trans)
    rail_perms = generate_rail_fence_perms()
    serp_perms = generate_serpentine_perms()[:4]  # Limit
    col_perms = []
    for width in [7, 8, 9, 10]:
        order = list(range(width))
        p = columnar_perm(width, order, CT_LEN)
        if validate_perm(p, CT_LEN):
            col_perms.append((f"columnar_w{width}_identity", p))
        rev_order = list(reversed(range(width)))
        p2 = columnar_perm(width, rev_order, CT_LEN)
        if validate_perm(p2, CT_LEN):
            col_perms.append((f"columnar_w{width}_reverse", p2))

    double_configs = 0
    double_consistent = 0
    for rd, rp in rail_perms[:6]:  # depths 2-7
        for cd, cp in col_perms + serp_perms:
            for period in BEAN_SURVIVING:
                for variant in VARIANTS:
                    double_configs += 1
                    total_configs += 1
                    result = test_double_transposition_sub(
                        rp, rd, cp, cd, period, variant,
                    )
                    if result is not None:
                        double_consistent += 1
                        total_consistent += 1
                        all_results.append(result)

    print(f"  {double_configs} configs → {double_consistent} consistent")

    # ── F: Interleaved variant selection ───────────────────────────────────
    print("\n" + "─" * 78)
    print("Pipeline F: Interleaved variant selection")
    print("─" * 78)

    # Define interleaving patterns
    patterns = [
        ("even_vig_odd_beau", lambda i: CipherVariant.VIGENERE if i % 2 == 0
                                        else CipherVariant.BEAUFORT),
        ("even_beau_odd_vig", lambda i: CipherVariant.BEAUFORT if i % 2 == 0
                                        else CipherVariant.VIGENERE),
        ("mod3_0vig_1beau_2vb", lambda i: [CipherVariant.VIGENERE,
                                            CipherVariant.BEAUFORT,
                                            CipherVariant.VAR_BEAUFORT][i % 3]),
        ("first48_vig_rest_beau", lambda i: CipherVariant.VIGENERE if i < 48
                                            else CipherVariant.BEAUFORT),
        ("first_half_beau_rest_vig", lambda i: CipherVariant.BEAUFORT if i < 49
                                               else CipherVariant.VIGENERE),
        ("ene_region_beau_rest_vig", lambda i: CipherVariant.BEAUFORT if 21 <= i <= 33
                                               else CipherVariant.VIGENERE),
        ("bc_region_beau_rest_vig", lambda i: CipherVariant.BEAUFORT if 63 <= i <= 73
                                              else CipherVariant.VIGENERE),
    ]

    interleave_configs = 0
    interleave_consistent = 0
    for pattern_desc, pattern_fn in patterns:
        for period in BEAN_SURVIVING:
            interleave_configs += 1
            total_configs += 1
            result = test_interleaved_variants(period, pattern_desc, pattern_fn)
            if result is not None:
                interleave_consistent += 1
                total_consistent += 1
                all_results.append(result)

    print(f"  {len(patterns)} patterns × {len(BEAN_SURVIVING)} periods "
          f"= {interleave_configs} configs")
    print(f"    → {interleave_consistent} consistent")

    # ── Summary ───────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print("\n" + "=" * 78)
    print(f"SUMMARY — E-COMPOSE-01")
    print(f"=" * 78)
    print(f"Total configurations tested: {total_configs}")
    print(f"Total consistent (above noise): {total_consistent}")
    print(f"Elapsed: {elapsed:.1f}s")

    if all_results:
        # Sort by crib score descending
        all_results.sort(key=lambda r: r.crib_score, reverse=True)
        print(f"\n{'─' * 78}")
        print(f"Top results (above noise floor = {NOISE_FLOOR}):")
        print(f"{'─' * 78}")
        for r in all_results[:20]:
            print(f"  [{r.crib_score:2d}/24] {r.pipeline_name}: {r.config_desc}")
            print(f"          {r.score_summary}")
            if r.crib_score >= STORE_THRESHOLD:
                print(f"          PT: {r.plaintext}")
    else:
        print(f"\n  NO results above noise floor ({NOISE_FLOOR}/24).")

    best_score = max((r.crib_score for r in all_results), default=0)
    bean_passes = sum(1 for r in all_results if r.bean_pass)

    print(f"\nBest crib score: {best_score}/24")
    print(f"Bean passes: {bean_passes}")
    print(f"Verdict: {'NOISE' if best_score <= 9 else 'INTERESTING' if best_score <= 17 else 'SIGNAL'}")

    # ── Save results ──────────────────────────────────────────────────────
    results_dir = os.path.join(os.path.dirname(__file__), '..', 'results')
    os.makedirs(results_dir, exist_ok=True)
    output = {
        "experiment": "E-COMPOSE-01",
        "description": "Novel multi-stage decryption pipelines",
        "total_configs": total_configs,
        "total_consistent": total_consistent,
        "best_score": best_score,
        "bean_passes": bean_passes,
        "elapsed_sec": elapsed,
        "pipelines_tested": [
            "A: non-columnar trans + periodic sub",
            "B: CT reversal + periodic sub",
            "C: keyed-alphabet mono + periodic sub",
            "D: 3-stage trans+mono+sub",
            "E: double trans + sub",
            "F: interleaved variant",
        ],
        "top_results": [
            {
                "pipeline": r.pipeline_name,
                "config": r.config_desc,
                "crib_score": r.crib_score,
                "bean_pass": r.bean_pass,
                "ic": r.ic_value,
                "plaintext": r.plaintext[:30] + "..." if r.plaintext else "",
            }
            for r in all_results[:20]
        ] if all_results else [],
    }

    out_path = os.path.join(results_dir, "e_compose_01.json")
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
