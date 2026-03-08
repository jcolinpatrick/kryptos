#!/usr/bin/env python3
"""Search for POINT as a floating crib in K4 decryptions.

Cipher: Vigenere/Beaufort/VarBeaufort
Family: grille
Status: active
Keyspace: ~340 keywords × 3 variants + exhaustive position analysis
Last run: never
Best score: n/a

Motivation: Sanborn's Aug 2025 open letter contains "(CLUE) what's the point?"
If POINT is a new plaintext crib (matching his pattern of giving cribs as
plaintext words: BERLIN, CLOCK, EAST, NORTHEAST), we should be able to
find it in candidate decryptions.

Three-phase approach:
  Phase 1: Decrypt K4 with 340 thematic keywords × 3 variants, search for POINT
  Phase 2: For each of the 93 possible positions of POINT in 97-char text,
           derive required key values and check for periodic consistency
  Phase 3: Check co-occurrence of POINT with known cribs EASTNORTHEAST/BERLINCLOCK
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.kernel.scoring.free_crib import score_free, CRIB_ENE, CRIB_BC

POINT = "POINT"
POINT_LEN = len(POINT)

# All positions where POINT could start in a 97-char text
MAX_START = CT_LEN - POINT_LEN  # 92


def load_keywords(path: str) -> list[str]:
    """Load keywords from file, one per line, skip comments/blanks."""
    words = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                words.append(line.upper())
    return words


def keyword_to_nums(kw: str) -> list[int]:
    return [ALPH_IDX[c] for c in kw]


def check_periodic_consistency(key_vals: dict[int, int], period: int) -> tuple[bool, int]:
    """Check if key values are consistent with a periodic key of given period.

    Returns (is_consistent, n_constraints_checked).
    """
    residue_vals: dict[int, int] = {}
    checked = 0
    for pos, kval in key_vals.items():
        r = pos % period
        if r in residue_vals:
            checked += 1
            if residue_vals[r] != kval:
                return False, checked
        else:
            residue_vals[r] = kval
    return True, checked


# ── Phase 1: Keyword sweep ──────────────────────────────────────────────

def phase1_keyword_sweep():
    """Decrypt K4 with thematic keywords, search for POINT."""
    print("=" * 70)
    print("PHASE 1: Keyword sweep — searching for POINT in decryptions")
    print("=" * 70)

    kw_path = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords.txt')
    keywords = load_keywords(kw_path)

    # Add POINT itself and related words
    extras = [
        "POINT", "POINTER", "COMPASS", "LODESTONE", "MAGNETIC",
        "HOROLOGE", "DEFECTOR", "PARALLAX", "COLOPHON",
        "URANIA", "QUARTZ", "CRYSTAL",
    ]
    for w in extras:
        if w not in keywords:
            keywords.append(w)

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
    hits = []
    total = 0

    for kw in keywords:
        key_nums = keyword_to_nums(kw)
        for variant in variants:
            pt = decrypt_text(CT, key_nums, variant)
            total += 1

            # Search for POINT
            pos = pt.find(POINT)
            if pos != -1:
                # Also check for known cribs
                fcr = score_free(pt, find_fragments_flag=False)
                hits.append({
                    'keyword': kw,
                    'variant': variant.value,
                    'point_pos': pos,
                    'plaintext': pt,
                    'ene_found': fcr.ene_found,
                    'bc_found': fcr.bc_found,
                    'crib_score': fcr.score,
                })

    print(f"\nSearched {total} configurations ({len(keywords)} keywords × 3 variants)")
    print(f"POINT found in {len(hits)} decryptions\n")

    if hits:
        # Sort by crib score desc, then by keyword
        hits.sort(key=lambda h: (-h['crib_score'], h['keyword']))
        for h in hits:
            print(f"  {h['keyword']:20s} {h['variant']:15s} POINT@{h['point_pos']:2d}"
                  f"  cribs={h['crib_score']}/24"
                  f"  ENE={'Y' if h['ene_found'] else 'n'}"
                  f"  BC={'Y' if h['bc_found'] else 'n'}")
            # Show context around POINT
            pt = h['plaintext']
            p = h['point_pos']
            start = max(0, p - 5)
            end = min(len(pt), p + POINT_LEN + 5)
            context = pt[start:p] + "[" + pt[p:p+POINT_LEN] + "]" + pt[p+POINT_LEN:end]
            print(f"    context: ...{context}...")
            print(f"    full PT: {pt}")
            print()
    else:
        print("  No hits.")

    return hits


# ── Phase 2: Position analysis ──────────────────────────────────────────

def phase2_position_analysis():
    """For each position where POINT could appear, derive key constraints
    and check for periodic consistency with known crib key values."""
    print("\n" + "=" * 70)
    print("PHASE 2: If POINT is at position P, what key values are needed?")
    print("         Check consistency with known crib-derived keys.")
    print("=" * 70)

    # Known crib positions and their plaintext chars
    crib_pt = CRIB_DICT  # {pos: char}

    recover_fns = {
        'vigenere': vig_recover_key,
        'beaufort': beau_recover_key,
        'var_beaufort': varbeau_recover_key,
    }

    ct_nums = [ALPH_IDX[c] for c in CT]
    point_nums = [ALPH_IDX[c] for c in POINT]

    best_results = []

    for variant_name, recover_fn in recover_fns.items():
        # Get key values at known crib positions
        crib_keys = {}
        for pos, pt_ch in crib_pt.items():
            crib_keys[pos] = recover_fn(ct_nums[pos], ALPH_IDX[pt_ch])

        for start_pos in range(MAX_START + 1):
            # Derive key values if POINT is at start_pos
            point_keys = {}
            for i, pt_num in enumerate(point_nums):
                pos = start_pos + i
                point_keys[pos] = recover_fn(ct_nums[pos], pt_num)

            # Combine with crib keys
            all_keys = {**crib_keys, **point_keys}

            # Check for conflicts between POINT keys and crib keys at overlapping positions
            overlap_conflict = False
            for pos in point_keys:
                if pos in crib_keys and point_keys[pos] != crib_keys[pos]:
                    overlap_conflict = True
                    break

            if overlap_conflict:
                continue  # POINT at this position contradicts known cribs

            # Check periodic consistency for various periods
            for period in range(1, 27):
                consistent, n_checks = check_periodic_consistency(all_keys, period)
                if consistent and n_checks >= 3:
                    best_results.append({
                        'variant': variant_name,
                        'point_pos': start_pos,
                        'period': period,
                        'n_constraints': n_checks,
                        'key_residues': {},
                    })
                    # Build residue map
                    residues: dict[int, int] = {}
                    for pos, kval in all_keys.items():
                        r = pos % period
                        residues[r] = kval
                    best_results[-1]['key_residues'] = residues

    # Filter: only keep results with highest constraint count per (variant, point_pos, period)
    print(f"\nFound {len(best_results)} period-consistent placements\n")

    if best_results:
        # Sort by constraints desc, period asc
        best_results.sort(key=lambda r: (-r['n_constraints'], r['period']))

        # Show top results, focusing on short periods (meaningful discrimination)
        shown = 0
        for r in best_results:
            if r['period'] > 13:
                continue  # Skip high periods (underdetermined)
            if shown >= 30:
                break
            period = r['period']
            residues = r['key_residues']
            # Try to reconstruct keyword from residues
            kw_chars = []
            for i in range(period):
                if i in residues:
                    kw_chars.append(ALPH[residues[i]])
                else:
                    kw_chars.append('?')
            kw_str = ''.join(kw_chars)

            print(f"  {r['variant']:15s} POINT@{r['point_pos']:2d}"
                  f"  period={period:2d}  constraints={r['n_constraints']:2d}"
                  f"  key={kw_str}")
            shown += 1

        if shown == 0:
            print("  No results with period ≤ 13 and ≥ 3 constraints.")

    return best_results


# ── Phase 3: Co-occurrence with cribs ──────────────────────────────────

def phase3_cooccurrence():
    """Check if POINT can co-occur with EASTNORTHEAST and BERLINCLOCK
    in a 97-char text without overlap."""
    print("\n" + "=" * 70)
    print("PHASE 3: Can POINT fit in a 97-char text alongside known cribs?")
    print("=" * 70)

    ene_start, ene_end = 21, 34  # EASTNORTHEAST occupies 21-33
    bc_start, bc_end = 63, 74    # BERLINCLOCK occupies 63-73

    valid_positions = []
    for p in range(MAX_START + 1):
        p_end = p + POINT_LEN
        # Check no overlap with ENE or BC
        overlaps_ene = p < ene_end and p_end > ene_start
        overlaps_bc = p < bc_end and p_end > bc_start
        if not overlaps_ene and not overlaps_bc:
            valid_positions.append(p)

    print(f"\nPOINT (5 chars) can fit at {len(valid_positions)} non-overlapping positions:")
    print(f"  Positions: {valid_positions}")

    # Especially interesting: adjacent to cribs
    adjacent = []
    for p in valid_positions:
        p_end = p + POINT_LEN
        if p_end == ene_start:  # POINT immediately before ENE
            adjacent.append((p, "immediately before EASTNORTHEAST"))
        if p == ene_end:  # POINT immediately after ENE
            adjacent.append((p, "immediately after EASTNORTHEAST"))
        if p_end == bc_start:  # POINT immediately before BC
            adjacent.append((p, "immediately before BERLINCLOCK"))
        if p == bc_end:  # POINT immediately after BC
            adjacent.append((p, "immediately after BERLINCLOCK"))

    if adjacent:
        print(f"\nAdjacent placements:")
        for pos, desc in adjacent:
            print(f"  POINT@{pos}: {desc}")
            # What would the full text look like?
            template = list('?' * CT_LEN)
            for i, ch in enumerate(POINT):
                template[pos + i] = ch
            for cpos, ch in CRIB_DICT.items():
                template[cpos] = ch
            segment_start = max(0, pos - 3)
            segment_end = min(CT_LEN, max(pos + POINT_LEN, bc_end) + 3)
            print(f"    ...{''.join(template[segment_start:segment_end])}...")

    # Special check: "WHATS THE POINT" or "THE POINT" as longer phrase
    longer_phrases = [
        "WHATSTHEPOINT",
        "THEPOINT",
        "POINTOF",
        "POINTIS",
        "FOCALPOINT",
        "COMPASSPOINT",
        "VANTAGEPOINT",
        "COUNTERPOINT",
        "PINPOINT",
        "GUNPOINT",
        "CHECKPOINT",
        "STANDPOINT",
        "VIEWPOINT",
        "STARTINGPOINT",
        "TURNINGPOINT",
    ]
    print(f"\nAlso checking {len(longer_phrases)} POINT-containing phrases as cribs...")

    return valid_positions


# ── Phase 4: Exhaustive direct search ──────────────────────────────────

def phase4_exhaustive():
    """Try ALL 26-letter keywords of length 1-8 that would place POINT
    at each valid position (i.e., derive partial key from POINT + known cribs,
    check if the full decryption with that periodic key produces English-like text)."""
    print("\n" + "=" * 70)
    print("PHASE 4: For promising (position, period) combos, decrypt full text")
    print("         and search for POINT + known cribs together")
    print("=" * 70)

    ct_nums = [ALPH_IDX[c] for c in CT]

    recover_fns = {
        'vigenere': vig_recover_key,
        'beaufort': beau_recover_key,
        'var_beaufort': varbeau_recover_key,
    }

    # For each variant, for each POINT position, for each period,
    # derive full key from POINT + cribs and decrypt
    results = []

    for variant_name, recover_fn in recover_fns.items():
        # Crib keys
        crib_keys = {}
        for pos, pt_ch in CRIB_DICT.items():
            crib_keys[pos] = recover_fn(ct_nums[pos], ALPH_IDX[pt_ch])

        point_nums = [ALPH_IDX[c] for c in POINT]

        for start_pos in range(MAX_START + 1):
            # POINT keys
            point_keys = {}
            for i, pt_num in enumerate(point_nums):
                pos = start_pos + i
                point_keys[pos] = recover_fn(ct_nums[pos], pt_num)

            # Check overlap conflicts
            conflict = False
            for pos in point_keys:
                if pos in crib_keys and point_keys[pos] != crib_keys[pos]:
                    conflict = True
                    break
            if conflict:
                continue

            all_keys = {**crib_keys, **point_keys}

            # Try periods that are consistent
            for period in [5, 6, 7, 8, 9, 10]:
                consistent, n_checks = check_periodic_consistency(all_keys, period)
                if not consistent:
                    continue

                # Build full key from known residues
                residues: dict[int, int] = {}
                for pos, kval in all_keys.items():
                    r = pos % period
                    if r in residues:
                        assert residues[r] == kval
                    else:
                        residues[r] = kval

                n_known = len(residues)
                if n_known < period:
                    # Some residues unknown - try all 26^n_unknown combos if small enough
                    unknown = [i for i in range(period) if i not in residues]
                    n_unknown = len(unknown)
                    if n_unknown > 3:
                        continue  # Too many unknowns

                    # Enumerate unknown residue values
                    from itertools import product
                    for combo in product(range(26), repeat=n_unknown):
                        full_key = list(residues.get(i, 0) for i in range(period))
                        for idx, val in zip(unknown, combo):
                            full_key[idx] = val

                        # Decrypt
                        decrypt_fn_map = {
                            'vigenere': lambda c, k: (c - k) % MOD,
                            'beaufort': lambda c, k: (k - c) % MOD,
                            'var_beaufort': lambda c, k: (c + k) % MOD,
                        }
                        dfn = decrypt_fn_map[variant_name]
                        pt_chars = []
                        for i, c in enumerate(ct_nums):
                            pt_chars.append(ALPH[dfn(c, full_key[i % period])])
                        pt = ''.join(pt_chars)

                        # Check for POINT AND a known crib
                        has_point = POINT in pt
                        has_ene = CRIB_ENE in pt
                        has_bc = CRIB_BC in pt

                        if has_point and (has_ene or has_bc):
                            kw_str = ''.join(ALPH[v] for v in full_key)
                            results.append({
                                'variant': variant_name,
                                'point_pos': start_pos,
                                'period': period,
                                'keyword': kw_str,
                                'plaintext': pt,
                                'has_ene': has_ene,
                                'has_bc': has_bc,
                            })
                else:
                    # All residues known, decrypt directly
                    full_key = [residues[i] for i in range(period)]
                    decrypt_fn_map = {
                        'vigenere': lambda c, k: (c - k) % MOD,
                        'beaufort': lambda c, k: (k - c) % MOD,
                        'var_beaufort': lambda c, k: (c + k) % MOD,
                    }
                    dfn = decrypt_fn_map[variant_name]
                    pt_chars = []
                    for i, c in enumerate(ct_nums):
                        pt_chars.append(ALPH[dfn(c, full_key[i % period])])
                    pt = ''.join(pt_chars)

                    has_point = POINT in pt
                    has_ene = CRIB_ENE in pt
                    has_bc = CRIB_BC in pt

                    if has_point and (has_ene or has_bc):
                        kw_str = ''.join(ALPH[v] for v in full_key)
                        results.append({
                            'variant': variant_name,
                            'point_pos': start_pos,
                            'period': period,
                            'keyword': kw_str,
                            'plaintext': pt,
                            'has_ene': has_ene,
                            'has_bc': has_bc,
                        })

    print(f"\nSearched POINT positions × periods 5-10 × 3 variants")
    print(f"Configs with POINT + at least one known crib: {len(results)}")

    if results:
        for r in results:
            print(f"\n  *** HIT ***")
            print(f"  {r['variant']} period={r['period']} key={r['keyword']}")
            print(f"  POINT@{r['point_pos']} ENE={'Y' if r['has_ene'] else 'n'} BC={'Y' if r['has_bc'] else 'n'}")
            print(f"  PT: {r['plaintext']}")
    else:
        print("  No configs produce POINT + known crib simultaneously.")

    return results


def main():
    print("POINT-as-crib investigation")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Searching for: '{POINT}' (5 chars)")
    print()

    phase1_keyword_sweep()
    phase2_position_analysis()
    phase3_cooccurrence()
    phase4_exhaustive()

    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()
