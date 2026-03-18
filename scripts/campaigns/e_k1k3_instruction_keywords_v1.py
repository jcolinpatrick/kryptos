#!/usr/bin/env python3
"""
Cipher:   K1-K3 instruction-derived keyword tests
Family:   campaigns
Status:   active
Keyspace: ~900 configs (misspelling keywords + row-based null masks + autokey)
Last run: 2026-03-17
Best score: TBD

Tests three untested K1-K3 instruction hypotheses:
  1. IQLUSION and variants as cipher keywords (~100 configs)
  2. DESPARATLY, UNDERGRUUND and variants (~300 configs)
  3. Row-based null mask from "ID BY ROWS" (~500 configs)
"""

import sys, os, json, time, math
from collections import Counter
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, DECRYPT_FN,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm, keyword_to_order,
)
from kryptos.kernel.scoring.crib_score import score_cribs

# ---- Constants ----
CT97 = CT
N = 97
KA_STR = KRYPTOS_ALPHABET
AZ = ALPH
AZ_IDX = ALPH_IDX
KA_IDX = {c: i for i, c in enumerate(KA_STR)}

# Consensus null mask (24 positions)
MASK_24 = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
MASK_SET = set(MASK_24)

# CT73 from consensus mask
CT73_POSITIONS = [i for i in range(N) if i not in MASK_SET]
CT73 = ''.join(CT97[i] for i in CT73_POSITIONS)

# Crib positions in CT97
ENE_POS = list(range(21, 34))  # 13 chars
BCL_POS = list(range(63, 74))  # 11 chars
ENE_TEXT = "EASTNORTHEAST"
BCL_TEXT = "BERLINCLOCK"
CRIB_POS_SET = frozenset(range(21, 34)) | frozenset(range(63, 74))

# Col7 transposition (undo) for CT97
def undo_col7(text):
    """Undo col7 columnar transposition (width=7, ascending order)."""
    order = list(range(7))  # ascending = 0,1,2,3,4,5,6
    perm = columnar_perm(7, order, len(text))
    inv = invert_perm(perm)
    return apply_perm(text, inv)

# Precompute col7-undone CT97
CT97_COL7UNDONE = undo_col7(CT97)

# ---- Cipher helpers ----
def kw_to_nums(kw, idx_map):
    """Convert keyword string to numeric key values."""
    return [idx_map[c] for c in kw.upper()]

def keyword_mixed_alphabet(kw):
    """Build keyword-mixed alphabet from keyword."""
    seen = set()
    alpha = []
    for c in kw.upper():
        if c not in seen and c in AZ_IDX:
            seen.add(c)
            alpha.append(c)
    for c in AZ:
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    return ''.join(alpha)

def decrypt_with_alphabet(ct, alpha_str, key_nums, variant):
    """Decrypt using a custom alphabet for substitution."""
    alpha_idx = {c: i for i, c in enumerate(alpha_str)}
    fn = DECRYPT_FN[variant]
    klen = len(key_nums)
    out = []
    for i, c in enumerate(ct):
        ci = alpha_idx.get(c, ord(c) - 65)
        pi = fn(ci, key_nums[i % klen]) % 26
        out.append(alpha_str[pi])
    return ''.join(out)

def autokey_decrypt(ct, primer_nums, variant, mode='pt'):
    """Autokey decryption. mode='pt' for PT-autokey, 'ct' for CT-autokey."""
    fn = DECRYPT_FN[variant]
    key = list(primer_nums)
    out = []
    for i, c in enumerate(ct):
        ci = ord(c) - 65
        ki = key[i] if i < len(key) else key[-1]  # extend later
        pi = fn(ci, ki) % 26
        out.append(chr(pi + 65))
        if mode == 'pt':
            key.append(pi)
        else:  # ct
            key.append(ci)
    return ''.join(out)

def score_ct73_cribs(pt73):
    """Score cribs in a 73-char plaintext that was extracted from CT97 via mask.

    The 73-char positions map back to CT97 positions. We need to check if
    crib positions survived the mask and score accordingly.
    """
    # Map CT73 position -> CT97 position
    score = 0
    for i73, i97 in enumerate(CT73_POSITIONS):
        if i97 in CRIB_DICT:
            if i73 < len(pt73) and pt73[i73] == CRIB_DICT[i97]:
                score += 1
    return score

# ---- Scoring ----
def score_with_detail(pt, label, ct_type='ct97'):
    """Score and return dict with details."""
    if ct_type == 'ct97':
        sc = score_cribs(pt)
    elif ct_type == 'ct73':
        sc = score_ct73_cribs(pt)
    else:
        sc = score_cribs(pt)
    return {
        'label': label,
        'score': sc,
        'ct_type': ct_type,
        'pt_snippet': pt[:50] if pt else '',
    }

# ======================================================================
# TEST 1: IQLUSION and variants as keywords
# ======================================================================
def test1_iqlusion():
    print("=" * 70)
    print("TEST 1: IQLUSION and variants as cipher keywords")
    print("=" * 70)

    keywords = [
        "IQLUSION",       # 8 chars - Sanborn coinage from K1
        "IQLUSIO",        # 7 chars
        "IQLUSI",         # 6 chars
        "NUANCE",         # 6 chars - from "the NUANCE of IQLUSION"
        "NUANCEOFIQLUSION",  # 16 chars
    ]

    results = []
    best = 0
    total = 0

    for kw in keywords:
        # --- A) Periodic on raw CT97 (AZ and KA) ---
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX), ("KA", KA_STR, KA_IDX)]:
            key = kw_to_nums(kw, idx_map)
            for variant in CipherVariant:
                pt = decrypt_text(CT97, key, variant)
                sc = score_cribs(pt)
                total += 1
                if sc > best: best = sc
                lbl = f"{kw}:{alpha_name}_{variant.value}:raw97"
                if sc >= 6:
                    print(f"  ** {lbl}: {sc}/24")
                    results.append(score_with_detail(pt, lbl))
                elif sc >= 1:
                    pass  # silent

        # --- B) Periodic on CT73 (consensus null-extracted) ---
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX), ("KA", KA_STR, KA_IDX)]:
            key = kw_to_nums(kw, idx_map)
            for variant in CipherVariant:
                pt73 = decrypt_text(CT73, key, variant)
                sc = score_ct73_cribs(pt73)
                total += 1
                if sc > best: best = sc
                lbl = f"{kw}:{alpha_name}_{variant.value}:ct73"
                if sc >= 6:
                    print(f"  ** {lbl}: {sc}/24")
                    results.append(score_with_detail(pt73, lbl, 'ct73'))

        # --- C) Periodic on CT97 with col7 undone first ---
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX), ("KA", KA_STR, KA_IDX)]:
            key = kw_to_nums(kw, idx_map)
            for variant in CipherVariant:
                pt = decrypt_text(CT97_COL7UNDONE, key, variant)
                sc = score_cribs(pt)
                total += 1
                if sc > best: best = sc
                lbl = f"{kw}:{alpha_name}_{variant.value}:col7undo"
                if sc >= 6:
                    print(f"  ** {lbl}: {sc}/24")
                    results.append(score_with_detail(pt, lbl))

        # --- D) Autokey with keyword as primer ---
        for alpha_name, idx_map in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
            key = kw_to_nums(kw, idx_map)
            for variant in CipherVariant:
                for mode in ['pt', 'ct']:
                    pt = autokey_decrypt(CT97, key, variant, mode)
                    sc = score_cribs(pt)
                    total += 1
                    if sc > best: best = sc
                    lbl = f"{kw}:{alpha_name}_{variant.value}:autokey_{mode}:raw97"
                    if sc >= 6:
                        print(f"  ** {lbl}: {sc}/24")
                        results.append(score_with_detail(pt, lbl))

        # --- E) Keyword-mixed alphabet as mono substitution ---
        mixed = keyword_mixed_alphabet(kw)
        mixed_idx = {c: i for i, c in enumerate(mixed)}
        # Simple mono sub: PT[i] = mixed[AZ_IDX[CT[i]]]  (identity key = [0,1,...,25])
        pt_mono = ''.join(mixed[AZ_IDX[c]] for c in CT97)
        sc = score_cribs(pt_mono)
        total += 1
        if sc > best: best = sc
        lbl = f"{kw}:mixed_alpha_mono:raw97"
        if sc >= 6:
            print(f"  ** {lbl}: {sc}/24")
            results.append(score_with_detail(pt_mono, lbl))

        # Reverse: PT[i] = AZ[mixed_idx[CT[i]]]
        pt_mono_rev = ''.join(AZ[mixed_idx[c]] for c in CT97)
        sc = score_cribs(pt_mono_rev)
        total += 1
        if sc > best: best = sc
        lbl = f"{kw}:mixed_alpha_mono_rev:raw97"
        if sc >= 6:
            print(f"  ** {lbl}: {sc}/24")
            results.append(score_with_detail(pt_mono_rev, lbl))

    print(f"\nTest 1 summary: {total} configs tested, best = {best}/24")
    return results, total, best

# ======================================================================
# TEST 2: DESPARATLY, UNDERGRUUND and variants
# ======================================================================
def test2_misspellings():
    print("\n" + "=" * 70)
    print("TEST 2: DESPARATLY, UNDERGRUUND, and variants as cipher keywords")
    print("=" * 70)

    keywords = [
        "DESPARATLY",       # 10 chars - K3 misspelling
        "UNDERGRUUND",      # 11 chars - K2 misspelling
        "DESPARATLYSLOWLY", # 16 chars - K3 phrase
        "PALIMPCEST",       # 10 chars - K1 misspelling (also test original form)
        "DIGETAL",          # 7 chars - another K1 misspelling
        "SLOWLY",           # 6 chars - from K3 phrase
    ]

    results = []
    best = 0
    total = 0

    for kw in keywords:
        # --- A) Periodic on raw CT97 ---
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX), ("KA", KA_STR, KA_IDX)]:
            key = kw_to_nums(kw, idx_map)
            for variant in CipherVariant:
                pt = decrypt_text(CT97, key, variant)
                sc = score_cribs(pt)
                total += 1
                if sc > best: best = sc
                lbl = f"{kw}:{alpha_name}_{variant.value}:raw97"
                if sc >= 6:
                    print(f"  ** {lbl}: {sc}/24")
                    results.append(score_with_detail(pt, lbl))

        # --- B) Periodic on CT73 ---
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX), ("KA", KA_STR, KA_IDX)]:
            key = kw_to_nums(kw, idx_map)
            for variant in CipherVariant:
                pt73 = decrypt_text(CT73, key, variant)
                sc = score_ct73_cribs(pt73)
                total += 1
                if sc > best: best = sc
                lbl = f"{kw}:{alpha_name}_{variant.value}:ct73"
                if sc >= 6:
                    print(f"  ** {lbl}: {sc}/24")
                    results.append(score_with_detail(pt73, lbl, 'ct73'))

        # --- C) Periodic on CT97 with col7 undone ---
        for alpha_name, alpha_str, idx_map in [("AZ", AZ, AZ_IDX), ("KA", KA_STR, KA_IDX)]:
            key = kw_to_nums(kw, idx_map)
            for variant in CipherVariant:
                pt = decrypt_text(CT97_COL7UNDONE, key, variant)
                sc = score_cribs(pt)
                total += 1
                if sc > best: best = sc
                lbl = f"{kw}:{alpha_name}_{variant.value}:col7undo"
                if sc >= 6:
                    print(f"  ** {lbl}: {sc}/24")
                    results.append(score_with_detail(pt, lbl))

        # --- D) Autokey with keyword as primer ---
        for alpha_name, idx_map in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
            key = kw_to_nums(kw, idx_map)
            for variant in CipherVariant:
                for mode in ['pt', 'ct']:
                    pt = autokey_decrypt(CT97, key, variant, mode)
                    sc = score_cribs(pt)
                    total += 1
                    if sc > best: best = sc
                    lbl = f"{kw}:{alpha_name}_{variant.value}:autokey_{mode}:raw97"
                    if sc >= 6:
                        print(f"  ** {lbl}: {sc}/24")
                        results.append(score_with_detail(pt, lbl))

        # --- E) Mixed alphabet ---
        mixed = keyword_mixed_alphabet(kw)
        mixed_idx = {c: i for i, c in enumerate(mixed)}
        pt_mono = ''.join(mixed[AZ_IDX[c]] for c in CT97)
        sc = score_cribs(pt_mono)
        total += 1
        if sc > best: best = sc
        lbl = f"{kw}:mixed_alpha_mono:raw97"
        if sc >= 6:
            print(f"  ** {lbl}: {sc}/24")
            results.append(score_with_detail(pt_mono, lbl))

        pt_mono_rev = ''.join(AZ[mixed_idx[c]] for c in CT97)
        sc = score_cribs(pt_mono_rev)
        total += 1
        if sc > best: best = sc
        lbl = f"{kw}:mixed_alpha_mono_rev:raw97"
        if sc >= 6:
            print(f"  ** {lbl}: {sc}/24")
            results.append(score_with_detail(pt_mono_rev, lbl))

    print(f"\nTest 2 summary: {total} configs tested, best = {best}/24")
    return results, total, best

# ======================================================================
# TEST 3: Row-based null mask from "ID BY ROWS"
# ======================================================================
def test3_row_based_null_mask():
    print("\n" + "=" * 70)
    print("TEST 3: Row-based null mask from 'ID BY ROWS'")
    print("=" * 70)

    CIPHER_KEYWORDS = [
        ("KRYPTOS", "KA"),
        ("PALIMPSEST", "AZ"),
        ("ABSCISSA", "AZ"),
        ("DEFECTOR", "AZ"),
        ("IQLUSION", "AZ"),
        ("IQLUSION", "KA"),
    ]
    VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]

    results = []
    best = 0
    total = 0
    total_masks_tested = 0
    total_masks_crib_survive = 0

    # For each width where rows * width can give exactly 24 nulls
    # Width W: nrows = ceil(97/W), need k full rows = 24/W chars as nulls
    # Full row has W chars (except possibly last row which is shorter)

    print("\nPhase 1: Exact row-based null masks (k rows * W = 24)")
    print("-" * 60)

    for W in range(3, 25):
        nrows = math.ceil(N / W)
        last_row_len = N - (nrows - 1) * W  # length of last (potentially partial) row

        # Possible null row counts: need exactly 24 null positions
        # Each full row contributes W positions, last row contributes last_row_len

        # Strategy: try all combinations of rows that sum to exactly 24 positions
        row_sizes = [W] * (nrows - 1) + [last_row_len] if last_row_len > 0 else [W] * nrows
        actual_nrows = len(row_sizes)

        # Find combinations of rows that give exactly 24 positions
        valid_combos = []
        for k in range(1, actual_nrows + 1):
            if k > actual_nrows:
                break
            for combo in combinations(range(actual_nrows), k):
                total_null = sum(row_sizes[r] for r in combo)
                if total_null == 24:
                    valid_combos.append(combo)

        if not valid_combos:
            continue

        print(f"\n  Width {W}: {actual_nrows} rows (last row = {last_row_len} chars), "
              f"{len(valid_combos)} valid row combinations for 24 nulls")

        for combo in valid_combos:
            total_masks_tested += 1

            # Determine null positions
            null_positions = set()
            for r in combo:
                start = r * W
                end = min(start + W, N)
                for pos in range(start, end):
                    null_positions.add(pos)

            # Check: do both ENE and BCL crib positions survive?
            ene_survive = all(p not in null_positions for p in ENE_POS)
            bcl_survive = all(p not in null_positions for p in BCL_POS)

            if not (ene_survive and bcl_survive):
                continue

            total_masks_crib_survive += 1

            # Extract CT73 from non-null positions
            real_positions = sorted(set(range(N)) - null_positions)
            ct73_local = ''.join(CT97[i] for i in real_positions)

            # Map CT97 crib positions to CT73 positions
            pos_map = {p97: i73 for i73, p97 in enumerate(real_positions)}

            # Score: check if crib chars appear at mapped positions
            def score_local_cribs(pt73_local):
                sc = 0
                for p97, ch in CRIB_DICT.items():
                    if p97 in pos_map:
                        i73 = pos_map[p97]
                        if i73 < len(pt73_local) and pt73_local[i73] == ch:
                            sc += 1
                return sc

            # Test cipher keywords
            for kw, alpha_name in CIPHER_KEYWORDS:
                idx_map = AZ_IDX if alpha_name == "AZ" else KA_IDX
                alpha_str = AZ if alpha_name == "AZ" else KA_STR
                key = kw_to_nums(kw, idx_map)

                for variant in VARIANTS:
                    pt73_local = decrypt_text(ct73_local, key, variant)
                    sc = score_local_cribs(pt73_local)
                    total += 1
                    if sc > best: best = sc

                    if sc >= 6:
                        lbl = f"W{W}:rows{combo}:{kw}:{alpha_name}_{variant.value}"
                        print(f"  ** {lbl}: {sc}/24")
                        results.append({
                            'label': lbl,
                            'score': sc,
                            'width': W,
                            'null_rows': combo,
                            'null_positions': sorted(null_positions),
                            'pt_snippet': pt73_local[:50],
                        })

    print(f"\n  Phase 1 total masks: {total_masks_tested}, crib-surviving: {total_masks_crib_survive}")

    # Phase 2: Width 8 specifically (from "8 Lines")
    # 3 rows of 8 = 24 exactly. 97/8 = 12.125, so 12 full rows of 8 + 1 partial row of 1
    # Actually nrows = ceil(97/8) = 13, last row has 1 char
    # Already covered in Phase 1 for W=8, but let's report specifics

    print("\n\nPhase 2: Additional widths with partial-row masks")
    print("-" * 60)
    print("  (Partial rows: select some positions from a row, not all)")

    # For widths that DON'T divide into 24 exactly, try partial row selections
    # This is more complex. Focus on key widths: 7, 8, 12, 31
    KEY_WIDTHS = [7, 8, 12, 31]

    for W in KEY_WIDTHS:
        nrows = math.ceil(N / W)
        row_sizes = []
        for r in range(nrows):
            start = r * W
            end = min(start + W, N)
            row_sizes.append(end - start)

        # Try: select some full rows, supplement with partial from another row
        # to reach exactly 24 nulls
        # Only do this if no exact solution exists for this width

        # Check if exact solutions exist
        has_exact = False
        for k in range(1, nrows + 1):
            for combo in combinations(range(nrows), k):
                if sum(row_sizes[r] for r in combo) == 24:
                    has_exact = True
                    break
            if has_exact:
                break

        if has_exact:
            continue  # Already handled in Phase 1

        # Try full rows + partial from one more row
        for k_full in range(0, nrows):
            for full_combo in combinations(range(nrows), k_full):
                full_total = sum(row_sizes[r] for r in full_combo)
                remaining = 24 - full_total
                if remaining <= 0 or remaining > W:
                    continue

                # Pick one more row to take 'remaining' positions from
                available_rows = [r for r in range(nrows) if r not in full_combo]
                for extra_row in available_rows:
                    if row_sizes[extra_row] < remaining:
                        continue

                    # Build null positions: all of full rows + first 'remaining' positions of extra row
                    null_positions = set()
                    for r in full_combo:
                        start = r * W
                        end = min(start + W, N)
                        for pos in range(start, end):
                            null_positions.add(pos)

                    extra_start = extra_row * W
                    for j in range(remaining):
                        null_positions.add(extra_start + j)

                    if len(null_positions) != 24:
                        continue

                    total_masks_tested += 1

                    # Check crib survival
                    ene_survive = all(p not in null_positions for p in ENE_POS)
                    bcl_survive = all(p not in null_positions for p in BCL_POS)
                    if not (ene_survive and bcl_survive):
                        continue

                    total_masks_crib_survive += 1

                    real_positions = sorted(set(range(N)) - null_positions)
                    ct73_local = ''.join(CT97[i] for i in real_positions)
                    pos_map = {p97: i73 for i73, p97 in enumerate(real_positions)}

                    def score_local_cribs2(pt73_local):
                        sc = 0
                        for p97, ch in CRIB_DICT.items():
                            if p97 in pos_map:
                                i73 = pos_map[p97]
                                if i73 < len(pt73_local) and pt73_local[i73] == ch:
                                    sc += 1
                        return sc

                    for kw, alpha_name in CIPHER_KEYWORDS:
                        idx_map = AZ_IDX if alpha_name == "AZ" else KA_IDX
                        key = kw_to_nums(kw, idx_map)

                        for variant in VARIANTS:
                            pt73_local = decrypt_text(ct73_local, key, variant)
                            sc = score_local_cribs2(pt73_local)
                            total += 1
                            if sc > best: best = sc

                            if sc >= 6:
                                lbl = f"partial:W{W}:full{full_combo}+extra_r{extra_row}:{kw}:{alpha_name}_{variant.value}"
                                print(f"  ** {lbl}: {sc}/24")
                                results.append({
                                    'label': lbl,
                                    'score': sc,
                                    'width': W,
                                    'null_positions': sorted(null_positions),
                                    'pt_snippet': pt73_local[:50],
                                })

        # Limit combinatorial explosion
        if total > 100000:
            print(f"  Stopping W={W} early (total={total})")
            break

    print(f"\nTest 3 summary: {total} cipher configs tested, "
          f"{total_masks_tested} masks tested, {total_masks_crib_survive} survived crib filter, "
          f"best = {best}/24")
    return results, total, best

# ======================================================================
# MAIN
# ======================================================================
def main():
    t0 = time.time()

    print("=" * 70)
    print("K1-K3 INSTRUCTION KEYWORD HYPOTHESIS TESTS")
    print(f"CT97: {CT97}")
    print(f"CT73 (consensus mask): {CT73} (len={len(CT73)})")
    print(f"Consensus null positions: {MASK_24}")
    print("=" * 70)

    all_results = []
    total_configs = 0
    global_best = 0
    flagged = []

    # Test 1
    r1, n1, b1 = test1_iqlusion()
    all_results.extend(r1)
    total_configs += n1
    if b1 > global_best: global_best = b1

    # Test 2
    r2, n2, b2 = test2_misspellings()
    all_results.extend(r2)
    total_configs += n2
    if b2 > global_best: global_best = b2

    # Test 3
    r3, n3, b3 = test3_row_based_null_mask()
    all_results.extend(r3)
    total_configs += n3
    if b3 > global_best: global_best = b3

    # Flag anything >= 10
    flagged = [r for r in all_results if r.get('score', 0) >= 10]

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total configurations tested: {total_configs}")
    print(f"Global best score: {global_best}/24")
    print(f"Time: {elapsed:.1f}s")

    if flagged:
        print(f"\n*** FLAGGED RESULTS (score >= 10/24): {len(flagged)} ***")
        for r in sorted(flagged, key=lambda x: -x.get('score', 0)):
            print(f"  {r.get('score', '?')}/24 : {r.get('label', '?')}")
            if 'pt_snippet' in r:
                print(f"    PT: {r['pt_snippet']}")
    else:
        print("\nNo results >= 10/24. All NOISE.")

    above_6 = [r for r in all_results if r.get('score', 0) >= 6]
    if above_6:
        print(f"\nResults >= 6/24 (above noise floor): {len(above_6)}")
        for r in sorted(above_6, key=lambda x: -x.get('score', 0)):
            print(f"  {r.get('score', '?')}/24 : {r.get('label', '?')}")
    else:
        print("\nNo results >= 6/24.")

    # Save results
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'test': 'K1-K3 instruction keyword hypothesis tests',
        'total_configs': total_configs,
        'global_best': global_best,
        'elapsed_seconds': elapsed,
        'test1_iqlusion': {'configs': n1, 'best': b1},
        'test2_misspellings': {'configs': n2, 'best': b2},
        'test3_row_null_mask': {'configs': n3, 'best': b3},
        'flagged_results': flagged,
        'above_noise_results': above_6,
        'conclusion': 'NOISE' if global_best < 10 else ('INTERESTING' if global_best < 18 else 'SIGNAL'),
    }

    outpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results',
                           'k1k3_instruction_keywords_v1.json')
    outpath = os.path.normpath(outpath)
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {outpath}")

if __name__ == '__main__':
    main()
