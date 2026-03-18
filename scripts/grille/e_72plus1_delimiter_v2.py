#!/usr/bin/env python3
"""
72+1 Delimiter Hypothesis v2 — Comprehensive.

Remove 1 char from ct73 -> 72 = 6x12.
Also: remove 25 from CT97 -> 72 directly.
Also: test other periods that divide 72 (1,2,3,4,6,8,9,12,18,24,36).
Also: test col6 + arbitrary period sub.
Also: full autokey sweep with keyword col6 + multiple primers.

Reports ALL scores and complete distributions.

Cipher: grille/e_72plus1_delimiter_v2
Family: grille
Status: active
Keyspace: ~49 delim x 720 col6 x factors(72) x 6 variants x keywords
Last run: never
Best score: N/A
"""
import sys
import os
import json
import time
import itertools
import math
from collections import defaultdict
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.autokey import autokey_decrypt

# ── Constants ──────────────────────────────────────────────────────────────

MASK_24 = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
MASK_SET = set(MASK_24)

ct73 = ''.join(CT[i] for i in range(CT_LEN) if i not in MASK_SET)
assert len(ct73) == 73

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"

# ct73 crib positions
ENE_START_73 = 13
BCL_START_73 = 47

CRIB_POSITIONS_73 = set(range(13, 26)) | set(range(47, 58))

VARIANTS = ['vigenere', 'beaufort', 'var_beaufort']
FACTORS_72 = [1, 2, 3, 4, 6, 8, 9, 12, 18, 24, 36]

PALETTE = set('BGIKOW')  # Fixed: no space in Z
PALETTE_WITH_Z = set('BGIKOW' + 'Z')

THEMATIC_KEYWORDS = [
    "KRYPTOS", "DEFECTOR", "PALIMPSEST", "ABSCISSA", "SHADOW",
    "SANBORN", "COMPASS", "ENIGMA", "COLOPHON", "KOMPASS",
    "SEVEN", "CLOCK", "BERLIN", "TWELVE", "CIPHER",
    "NEEDLE", "COPPER", "MASTER", "LODESTONE", "ALETHEIA",
]

KEYWORDS_6_CHAR = [kw[:6] for kw in THEMATIC_KEYWORDS if len(kw) >= 6]


def key_recover(c, p, variant):
    if variant == 'vigenere':
        return (c - p) % MOD
    elif variant == 'beaufort':
        return (c + p) % MOD
    elif variant == 'var_beaufort':
        return (p - c) % MOD

def decrypt_char(c, k, variant):
    if variant == 'vigenere':
        return (c - k) % MOD
    elif variant == 'beaufort':
        return (k - c) % MOD
    elif variant == 'var_beaufort':
        return (c + k) % MOD

def keyword_to_col_order(kw, width):
    kw = kw[:width].upper()
    if len(kw) < width:
        return None
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return tuple(order)

def columnar_perm(width, col_order, length):
    cols = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        perm.extend(cols[col_idx])
    return perm

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)


def crib_score(pt, ene_s, bcl_s):
    """Score plaintext against cribs. Returns (total, ene_score, bcl_score)."""
    ene = 0
    for i, ch in enumerate(ENE_WORD):
        pos = ene_s + i
        if pos < len(pt) and pt[pos] == ch:
            ene += 1
    bcl = 0
    for i, ch in enumerate(BCL_WORD):
        pos = bcl_s + i
        if pos < len(pt) and pt[pos] == ch:
            bcl += 1
    return ene + bcl, ene, bcl


def period_crib_consistency(text, period, variant, ene_s, bcl_s, alph='AZ'):
    """Check periodic substitution crib consistency on text.
    Returns (score, conflicts, key_if_zero_conflict)."""
    idx_fn = (lambda c: ord(c) - 65) if alph == 'AZ' else (lambda c: KA_IDX[c])

    crib_at = {}
    for i, ch in enumerate(ENE_WORD):
        crib_at[ene_s + i] = ch
    for i, ch in enumerate(BCL_WORD):
        crib_at[bcl_s + i] = ch

    residue_keys = defaultdict(set)
    for pos, pt_ch in crib_at.items():
        if pos >= len(text):
            continue
        c = idx_fn(text[pos])
        p = idx_fn(pt_ch)
        k = key_recover(c, p, variant)
        residue_keys[pos % period].add(k)

    conflicts = sum(1 for r in residue_keys.values() if len(r) > 1)

    # Score = number of crib positions whose residue is conflict-free
    score = 0
    for pos in crib_at:
        if pos >= len(text):
            continue
        r = pos % period
        if len(residue_keys[r]) == 1:
            score += 1

    key = None
    if conflicts == 0:
        key = [0] * period
        for r, ks in residue_keys.items():
            if ks:
                key[r] = list(ks)[0]

    return score, conflicts, key


def decrypt_periodic(text, key, variant, alph='AZ'):
    """Decrypt with periodic key."""
    idx_fn = (lambda c: ord(c) - 65) if alph == 'AZ' else (lambda c: KA_IDX[c])
    chr_fn = (lambda v: chr(v + 65)) if alph == 'AZ' else (lambda v: KA[v])
    period = len(key)
    return ''.join(chr_fn(decrypt_char(idx_fn(c), key[i % period], variant))
                   for i, c in enumerate(text))


# ══════════════════════════════════════════════════════════════════════════
# Worker: Process one delimiter position
# ══════════════════════════════════════════════════════════════════════════

def process_delimiter_v2(args):
    d, ct73_str = args
    ct72 = ct73_str[:d] + ct73_str[d+1:]
    removed_char = ct73_str[d]

    ene_s = 13 - (1 if d < 13 else 0)
    bcl_s = 47 - (1 if d < 47 else 0)

    results = []
    best_score = 0
    best_detail = None

    # ── Test A: Period-p direct (all factors of 72, both alphabets) ──────
    for period in FACTORS_72:
        if period > 24:  # Underdetermined above 24
            continue
        for alph in ['AZ', 'KA']:
            for variant in VARIANTS:
                score, conflicts, key = period_crib_consistency(
                    ct72, period, variant, ene_s, bcl_s, alph)

                if score > best_score:
                    best_score = score
                    best_detail = {
                        'type': 'period_direct',
                        'period': period,
                        'variant': variant,
                        'alph': alph,
                        'score': score,
                        'conflicts': conflicts,
                    }

                if conflicts == 0 and key is not None:
                    pt = decrypt_periodic(ct72, key, variant, alph)
                    key_str = ''.join(chr(k + 65) for k in key)
                    results.append({
                        'type': 'period_direct_zero_conflict',
                        'delimiter_pos': d,
                        'removed_char': removed_char,
                        'period': period,
                        'variant': variant,
                        'alph': alph,
                        'score': score,
                        'key': key_str,
                        'pt': pt,
                    })

                if score >= 10:
                    results.append({
                        'type': 'period_direct_high',
                        'delimiter_pos': d,
                        'removed_char': removed_char,
                        'period': period,
                        'variant': variant,
                        'alph': alph,
                        'score': score,
                        'conflicts': conflicts,
                    })

    # ── Test B: Width-6 col trans + period-6 cipher (all 720 orderings) ──
    for perm_tuple in itertools.permutations(range(6)):
        col_order = list(perm_tuple)
        perm = columnar_perm(6, col_order, 72)
        inv = invert_perm(perm)
        intermediate = apply_perm(ct72, perm)

        for variant in VARIANTS:
            for alph in ['AZ']:  # AZ only for col6 exhaustive
                score, conflicts, key = period_crib_consistency(
                    intermediate, 6, variant,
                    # Map crib positions through inverse
                    ene_s, bcl_s, alph)

                # Wait - need to be more careful. The crib positions in the
                # transposed space are inv[ene_s+i], inv[bcl_s+i], not ene_s, bcl_s.
                # Let me compute correctly:
                crib_inter = {}
                for i, ch in enumerate(ENE_WORD):
                    orig_pos = ene_s + i
                    if orig_pos < 72:
                        inter_pos = inv[orig_pos]
                        crib_inter[inter_pos] = ch
                for i, ch in enumerate(BCL_WORD):
                    orig_pos = bcl_s + i
                    if orig_pos < 72:
                        inter_pos = inv[orig_pos]
                        crib_inter[inter_pos] = ch

                idx_fn = lambda c: ord(c) - 65

                residue_keys = defaultdict(set)
                for pos, pt_ch in crib_inter.items():
                    c = idx_fn(intermediate[pos])
                    p = idx_fn(pt_ch)
                    k = key_recover(c, p, variant)
                    residue_keys[pos % 6].add(k)

                conflicts = sum(1 for r in residue_keys.values() if len(r) > 1)
                s = 0
                for pos in crib_inter:
                    r = pos % 6
                    if len(residue_keys[r]) == 1:
                        s += 1

                if s > best_score:
                    best_score = s
                    best_detail = {
                        'type': 'col6_p6',
                        'col_order': col_order,
                        'variant': variant,
                        'score': s,
                        'conflicts': conflicts,
                    }

                if conflicts == 0:
                    key6 = [0] * 6
                    for r, ks in residue_keys.items():
                        if ks:
                            key6[r] = list(ks)[0]
                    pt_inter = decrypt_periodic(intermediate, key6, variant)
                    key_str = ''.join(chr(k + 65) for k in key6)
                    results.append({
                        'type': 'col6_p6_zero_conflict',
                        'delimiter_pos': d,
                        'removed_char': removed_char,
                        'col_order': col_order,
                        'variant': variant,
                        'score': s,
                        'key': key_str,
                        'pt': pt_inter,
                    })

                if s >= 14:
                    results.append({
                        'type': 'col6_p6_high',
                        'delimiter_pos': d,
                        'removed_char': removed_char,
                        'col_order': col_order,
                        'variant': variant,
                        'score': s,
                        'conflicts': conflicts,
                    })

    # ── Test C: Keyword col6 + autokey ──────────────────────────────────
    for kw in KEYWORDS_6_CHAR[:10]:
        col_order = keyword_to_col_order(kw, 6)
        if col_order is None:
            continue
        perm = columnar_perm(6, list(col_order), 72)
        intermediate = apply_perm(ct72, perm)

        # Map crib positions through inverse
        inv = invert_perm(perm)
        # Adjusted crib positions in ct72 space
        crib_ct72_ene = ene_s
        crib_ct72_bcl = bcl_s

        for primer_kw in THEMATIC_KEYWORDS[:10]:
            for variant in VARIANTS:
                try:
                    pt = autokey_decrypt(intermediate, primer_kw, variant)
                except:
                    continue

                # Score in ct72 (output) space
                # But autokey operates on intermediate, so we need to
                # apply transposition to get back to ct72 space
                # Actually, intermediate = undo_col(ct72), decrypt(intermediate) -> pt_inter
                # To score, we need to map crib positions from ct72 space to intermediate space
                # Score against crib in intermediate space
                s = 0
                for i, ch in enumerate(ENE_WORD):
                    orig_pos = ene_s + i
                    if orig_pos < 72:
                        ipos = inv[orig_pos]
                        if ipos < len(pt) and pt[ipos] == ch:
                            s += 1
                for i, ch in enumerate(BCL_WORD):
                    orig_pos = bcl_s + i
                    if orig_pos < 72:
                        ipos = inv[orig_pos]
                        if ipos < len(pt) and pt[ipos] == ch:
                            s += 1

                if s > best_score:
                    best_score = s
                    best_detail = {
                        'type': 'col6_autokey',
                        'col_kw': kw,
                        'primer': primer_kw,
                        'variant': variant,
                        'score': s,
                    }

                if s >= 6:
                    results.append({
                        'type': 'col6_autokey',
                        'delimiter_pos': d,
                        'removed_char': removed_char,
                        'col_kw': kw,
                        'primer': primer_kw,
                        'variant': variant,
                        'score': s,
                        'pt_fragment': pt[:40],
                    })

    # ── Test D: Direct autokey (no transposition) ───────────────────────
    for primer_kw in THEMATIC_KEYWORDS[:10]:
        for variant in VARIANTS:
            try:
                pt = autokey_decrypt(ct72, primer_kw, variant)
            except:
                continue
            s, ene, bcl = crib_score(pt, ene_s, bcl_s)

            if s > best_score:
                best_score = s
                best_detail = {
                    'type': 'direct_autokey',
                    'primer': primer_kw,
                    'variant': variant,
                    'score': s,
                }

            if s >= 6:
                results.append({
                    'type': 'direct_autokey',
                    'delimiter_pos': d,
                    'removed_char': removed_char,
                    'primer': primer_kw,
                    'variant': variant,
                    'score': s,
                    'ene': ene,
                    'bcl': bcl,
                    'pt_fragment': pt[:40],
                })

    return d, best_score, best_detail, results


# ══════════════════════════════════════════════════════════════════════════
# Worker: 25-null mask
# ══════════════════════════════════════════════════════════════════════════

def process_25null_v2(args):
    extra_pos, = args
    mask_25 = sorted(MASK_24 + [extra_pos])
    mask_set_25 = set(mask_25)

    # Check no crib position removed
    for pos in range(21, 34):
        if pos in mask_set_25:
            return extra_pos, 0, None, []
    for pos in range(63, 74):
        if pos in mask_set_25:
            return extra_pos, 0, None, []

    ct72 = ''.join(CT[i] for i in range(CT_LEN) if i not in mask_set_25)
    if len(ct72) != 72:
        return extra_pos, 0, None, []

    ene_s = 21 - sum(1 for n in mask_25 if n < 21)
    bcl_s = 63 - sum(1 for n in mask_25 if n < 63)

    results = []
    best_score = 0
    best_detail = None

    for period in FACTORS_72:
        if period > 24:
            continue
        for alph in ['AZ', 'KA']:
            for variant in VARIANTS:
                score, conflicts, key = period_crib_consistency(
                    ct72, period, variant, ene_s, bcl_s, alph)

                if score > best_score:
                    best_score = score
                    best_detail = {
                        'type': '25null_period',
                        'extra_pos': extra_pos,
                        'period': period,
                        'variant': variant,
                        'alph': alph,
                        'score': score,
                        'conflicts': conflicts,
                    }

                if conflicts == 0 and key is not None:
                    pt = decrypt_periodic(ct72, key, variant, alph)
                    key_str = ''.join(chr(k + 65) for k in key)
                    results.append({
                        'type': '25null_zero_conflict',
                        'extra_pos': extra_pos,
                        'extra_char': CT[extra_pos],
                        'period': period,
                        'variant': variant,
                        'alph': alph,
                        'score': score,
                        'key': key_str,
                        'pt': pt,
                    })

                if score >= 10:
                    results.append({
                        'type': '25null_high',
                        'extra_pos': extra_pos,
                        'extra_char': CT[extra_pos],
                        'period': period,
                        'variant': variant,
                        'alph': alph,
                        'score': score,
                        'conflicts': conflicts,
                    })

    # Also test col6 with keyword orderings
    for kw in KEYWORDS_6_CHAR[:6]:
        col_order = keyword_to_col_order(kw, 6)
        if col_order is None:
            continue
        perm = columnar_perm(6, list(col_order), 72)
        inv = invert_perm(perm)
        intermediate = apply_perm(ct72, perm)

        crib_inter = {}
        for i, ch in enumerate(ENE_WORD):
            orig_pos = ene_s + i
            if orig_pos < 72:
                crib_inter[inv[orig_pos]] = ch
        for i, ch in enumerate(BCL_WORD):
            orig_pos = bcl_s + i
            if orig_pos < 72:
                crib_inter[inv[orig_pos]] = ch

        for variant in VARIANTS:
            residue_keys = defaultdict(set)
            for pos, pt_ch in crib_inter.items():
                c = ord(intermediate[pos]) - 65
                p = ord(pt_ch) - 65
                k = key_recover(c, p, variant)
                residue_keys[pos % 6].add(k)

            conflicts = sum(1 for r in residue_keys.values() if len(r) > 1)
            s = sum(1 for pos in crib_inter
                    if len(residue_keys[pos % 6]) == 1)

            if s > best_score:
                best_score = s
                best_detail = {
                    'type': '25null_col6_p6',
                    'extra_pos': extra_pos,
                    'col_kw': kw,
                    'variant': variant,
                    'score': s,
                    'conflicts': conflicts,
                }

            if conflicts == 0:
                key6 = [0] * 6
                for r, ks in residue_keys.items():
                    if ks:
                        key6[r] = list(ks)[0]
                pt_inter = decrypt_periodic(intermediate, key6, variant)
                key_str = ''.join(chr(k + 65) for k in key6)
                results.append({
                    'type': '25null_col6_zero',
                    'extra_pos': extra_pos,
                    'extra_char': CT[extra_pos],
                    'col_kw': kw,
                    'variant': variant,
                    'score': s,
                    'key': key_str,
                    'pt': pt_inter,
                })

            if s >= 14:
                results.append({
                    'type': '25null_col6_high',
                    'extra_pos': extra_pos,
                    'extra_char': CT[extra_pos],
                    'col_kw': kw,
                    'variant': variant,
                    'score': s,
                    'conflicts': conflicts,
                })

    return extra_pos, best_score, best_detail, results


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()

    print("=" * 70)
    print("72+1 DELIMITER HYPOTHESIS v2 — Comprehensive")
    print("=" * 70)
    print(f"CT97: {CT}")
    print(f"ct73: {ct73}")
    print()

    # W, Q, X positions in ct73
    special_positions = {
        'W': [i for i, c in enumerate(ct73) if c == 'W'],
        'Q': [i for i, c in enumerate(ct73) if c == 'Q'],
        'X': [i for i, c in enumerate(ct73) if c == 'X'],
    }
    for ch, positions in special_positions.items():
        non_crib = [p for p in positions if p not in CRIB_POSITIONS_73]
        print(f"{ch} in ct73: {positions} (non-crib: {non_crib})")
    print()

    valid_delimiters = sorted(set(range(73)) - CRIB_POSITIONS_73)
    print(f"Valid delimiter positions: {len(valid_delimiters)}")
    print()

    # ── Phase 1: All delimiter positions ──────────────────────────────────

    print("PHASE 1: Delimiter removal from ct73 -> ct72")
    print("-" * 70)

    n_workers = min(cpu_count(), 12)
    tasks1 = [(d, ct73) for d in valid_delimiters]

    all_results_1 = []
    best_per_delim = {}
    score_dist_1 = defaultdict(int)
    zero_conflicts_1 = []
    high_scores_1 = []
    autokey_hits_1 = []

    with Pool(n_workers) as pool:
        for d, best_s, best_d, results in pool.imap_unordered(process_delimiter_v2, tasks1):
            best_per_delim[d] = (best_s, best_d)
            score_dist_1[best_s] += 1
            for r in results:
                all_results_1.append(r)
                if 'zero_conflict' in r['type']:
                    zero_conflicts_1.append(r)
                if r.get('score', 0) >= 10:
                    high_scores_1.append(r)
                if 'autokey' in r['type'] and r.get('score', 0) >= 6:
                    autokey_hits_1.append(r)

    print(f"\nPhase 1 complete:")
    print(f"  Delimiter positions tested: {len(valid_delimiters)}")
    print(f"  Total significant results: {len(all_results_1)}")
    print(f"  Zero-conflict configs: {len(zero_conflicts_1)}")
    print(f"  High scores (>=10): {len(high_scores_1)}")
    print(f"  Autokey hits (>=6): {len(autokey_hits_1)}")

    print(f"\nBest score per delimiter position:")
    for d in sorted(best_per_delim.keys()):
        s, det = best_per_delim[d]
        if s >= 8:
            print(f"  d={d:2d} ({ct73[d]}): best={s}/24 — {det}")
    print(f"\n  Score distribution (best per delimiter):")
    for s in sorted(score_dist_1.keys(), reverse=True):
        if score_dist_1[s] > 0:
            print(f"    {s}/24: {score_dist_1[s]} delimiters")

    # ── Phase 2: 25-null model ────────────────────────────────────────────

    print("\n" + "=" * 70)
    print("PHASE 2: 25-null model (remove 25 from CT97 -> 72)")
    print("-" * 70)

    # Candidate 25th null positions
    crib_97 = set(range(21, 34)) | set(range(63, 74))
    candidates_25 = [i for i in range(CT_LEN)
                     if i not in MASK_SET and i not in crib_97]

    print(f"Candidate positions for 25th null: {len(candidates_25)}")

    palette_cands = [i for i in candidates_25 if CT[i] in PALETTE_WITH_Z]
    print(f"  Palette candidates: {len(palette_cands)} -> {[(i, CT[i]) for i in palette_cands]}")

    tasks2 = [(extra_pos,) for extra_pos in candidates_25]

    all_results_2 = []
    best_per_extra = {}
    score_dist_2 = defaultdict(int)
    zero_conflicts_2 = []

    with Pool(n_workers) as pool:
        for ep, best_s, best_d, results in pool.imap_unordered(process_25null_v2, tasks2):
            best_per_extra[ep] = (best_s, best_d)
            score_dist_2[best_s] += 1
            for r in results:
                all_results_2.append(r)
                if 'zero' in r['type']:
                    zero_conflicts_2.append(r)

    print(f"\nPhase 2 complete:")
    print(f"  25-null masks tested: {len(candidates_25)}")
    print(f"  Total significant results: {len(all_results_2)}")
    print(f"  Zero-conflict configs: {len(zero_conflicts_2)}")

    print(f"\nBest score per extra-null position:")
    for ep in sorted(best_per_extra.keys()):
        s, det = best_per_extra[ep]
        if s >= 8:
            print(f"  pos={ep:2d} ({CT[ep]}): best={s}/24 — {det}")
    print(f"\n  Score distribution (best per extra null):")
    for s in sorted(score_dist_2.keys(), reverse=True):
        if score_dist_2[s] > 0:
            print(f"    {s}/24: {score_dist_2[s]} positions")

    # ── Phase 3: Exhaustive col6 on top delimiter positions ──────────────

    print("\n" + "=" * 70)
    print("PHASE 3: Exhaustive col6 (720 perms) + all factor periods on top delimiters")
    print("-" * 70)

    # Take top 10 delimiter positions by score
    top_delims = sorted(best_per_delim.items(), key=lambda x: -x[1][0])[:10]
    print(f"Top 10 delimiters: {[(d, s) for d, (s, _) in top_delims]}")

    phase3_results = []

    for d, (_, _) in top_delims:
        ct72 = ct73[:d] + ct73[d+1:]
        ene_s = 13 - (1 if d < 13 else 0)
        bcl_s = 47 - (1 if d < 47 else 0)

        local_best = 0

        # Test all 720 col6 orderings x multiple periods
        for perm_tuple in itertools.permutations(range(6)):
            col_order = list(perm_tuple)
            perm = columnar_perm(6, col_order, 72)
            inv = invert_perm(perm)
            intermediate = apply_perm(ct72, perm)

            # Map cribs through inverse
            crib_inter = {}
            for i, ch in enumerate(ENE_WORD):
                orig_pos = ene_s + i
                if orig_pos < 72:
                    crib_inter[inv[orig_pos]] = ch
            for i, ch in enumerate(BCL_WORD):
                orig_pos = bcl_s + i
                if orig_pos < 72:
                    crib_inter[inv[orig_pos]] = ch

            # Test multiple periods on intermediate
            for period in [1, 2, 3, 4, 6, 8, 9, 12]:
                for variant in VARIANTS:
                    idx_fn = lambda c: ord(c) - 65

                    residue_keys = defaultdict(set)
                    for pos, pt_ch in crib_inter.items():
                        c = idx_fn(intermediate[pos])
                        p = idx_fn(pt_ch)
                        k = key_recover(c, p, variant)
                        residue_keys[pos % period].add(k)

                    conflicts = sum(1 for r in residue_keys.values() if len(r) > 1)
                    s = sum(1 for pos in crib_inter
                            if len(residue_keys[pos % period]) == 1)

                    if s > local_best:
                        local_best = s

                    if conflicts == 0:
                        key_p = [0] * period
                        for r, ks in residue_keys.items():
                            if ks:
                                key_p[r] = list(ks)[0]
                        pt = decrypt_periodic(intermediate, key_p, variant)
                        key_str = ''.join(chr(k + 65) for k in key_p)
                        phase3_results.append({
                            'type': 'col6_multiperiod_zero',
                            'delimiter_pos': d,
                            'removed_char': ct73[d],
                            'col_order': col_order,
                            'period': period,
                            'variant': variant,
                            'score': s,
                            'key': key_str,
                            'pt': pt[:60],
                        })
                        if s >= 10:
                            print(f"  *** ZERO CONFLICT + HIGH SCORE: d={d} "
                                  f"col={col_order} p={period} v={variant} "
                                  f"score={s} key={key_str}")

                    if s >= 14:
                        phase3_results.append({
                            'type': 'col6_multiperiod_high',
                            'delimiter_pos': d,
                            'removed_char': ct73[d],
                            'col_order': col_order,
                            'period': period,
                            'variant': variant,
                            'score': s,
                            'conflicts': conflicts,
                        })

        print(f"  d={d:2d} ({ct73[d]}): local best = {local_best}/24")

    print(f"\nPhase 3 results: {len(phase3_results)}")

    # ── Summary ───────────────────────────────────────────────────────────

    elapsed = time.time() - t0

    all_zero = zero_conflicts_1 + zero_conflicts_2 + \
               [r for r in phase3_results if 'zero' in r['type']]
    all_high = high_scores_1 + \
               [r for r in all_results_2 if r.get('score', 0) >= 10] + \
               [r for r in phase3_results if r.get('score', 0) >= 10]

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Phase 1 (delim removal): {len(all_results_1)} significant results")
    print(f"Phase 2 (25-null): {len(all_results_2)} significant results")
    print(f"Phase 3 (exhaustive col6xperiod): {len(phase3_results)} results")
    print(f"\nTotal zero-conflict configs: {len(all_zero)}")
    print(f"Total high-score (>=10): {len(all_high)}")
    print(f"Total autokey hits (>=6): {len(autokey_hits_1)}")

    if all_zero:
        print(f"\n*** ZERO-CONFLICT RESULTS ***")
        for r in all_zero[:20]:
            print(f"  {r}")

    if all_high:
        print(f"\n*** HIGH-SCORE RESULTS (>=10/24) ***")
        for r in sorted(all_high, key=lambda x: -x.get('score', 0))[:20]:
            print(f"  {r}")

    if autokey_hits_1:
        print(f"\n*** AUTOKEY HITS (>=6/24) ***")
        for r in sorted(autokey_hits_1, key=lambda x: -x.get('score', 0))[:20]:
            print(f"  {r}")

    # Save
    output = {
        'experiment': '72+1 delimiter hypothesis v2',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'elapsed_s': elapsed,
        'ct73': ct73,
        'null_mask_24': MASK_24,
        'phase1': {
            'delimiters_tested': len(valid_delimiters),
            'total_results': len(all_results_1),
            'zero_conflicts': len(zero_conflicts_1),
            'high_scores': len(high_scores_1),
            'autokey_hits': len(autokey_hits_1),
            'best_per_delim': {str(d): (s, det) for d, (s, det) in best_per_delim.items()},
            'score_distribution': {str(k): v for k, v in sorted(score_dist_1.items())},
        },
        'phase2': {
            'masks_tested': len(candidates_25),
            'total_results': len(all_results_2),
            'zero_conflicts': len(zero_conflicts_2),
            'best_per_extra': {str(ep): (s, det) for ep, (s, det) in best_per_extra.items()},
            'score_distribution': {str(k): v for k, v in sorted(score_dist_2.items())},
        },
        'phase3': {
            'total_results': len(phase3_results),
        },
        'zero_conflict_details': all_zero[:100],
        'high_score_details': sorted(all_high, key=lambda x: -x.get('score', 0))[:100],
        'autokey_details': sorted(autokey_hits_1, key=lambda x: -x.get('score', 0))[:50],
    }

    outpath = os.path.abspath(os.path.join(
        os.path.dirname(__file__), '..', '..', 'results', 'e_72plus1_delimiter_v2.json'))
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")


if __name__ == '__main__':
    main()
