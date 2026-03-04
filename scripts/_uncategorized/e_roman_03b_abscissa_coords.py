#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-ROMAN-03b: ABSCISSA/PALIMPSEST/KRYPTOS coordinate-based triple transposition.

Supplementary to E-ROMAN-03. Key insight: ABSCISSA literally means "x-coordinate."
The three K1-K3 answer words may each define a "threading string":
  1. ABSCISSA -> x-coordinate (column addressing)
  2. PALIMPSEST -> y-coordinate (row addressing / depth layer)
  3. KRYPTOS -> substitution alphabet or z-coordinate

Tests:
  Phase 1: Letter values as orderings — all 6 permutations of which keyword
           controls which transposition layer.
  Phase 2: Letter values mod width as column-read orders for each width.
  Phase 3: Exhaustive width combos with the 3 keyword-derived orderings,
           combined with all substitution variants.
  Phase 4: All 6 layer orderings + running key from Carter Chapter X.
  Phase 5: ABSCISSA values as direct position permutation (not columnar).
"""
import json
import itertools
import os
import time

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX
from kryptos.kernel.scoring.aggregate import score_candidate


# ── Cipher functions ──

def vig_decrypt(ct, key_vals):
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        pt.append(ALPH[(ALPH_IDX[c] - key_vals[i % klen]) % 26])
    return ''.join(pt)


def beau_decrypt(ct, key_vals):
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        pt.append(ALPH[(key_vals[i % klen] - ALPH_IDX[c]) % 26])
    return ''.join(pt)


def varbeau_decrypt(ct, key_vals):
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        pt.append(ALPH[(ALPH_IDX[c] + key_vals[i % klen]) % 26])
    return ''.join(pt)


VFUNCS = [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]


def columnar_decrypt(ct, width, order):
    """Standard columnar transposition decrypt."""
    n = len(ct)
    nrows = (n + width - 1) // width
    n_long = n % width if n % width != 0 else width
    col_lens = [nrows if col < n_long else nrows - 1 for col in range(width)]
    cols = {}
    pos = 0
    for rank in range(width):
        col_idx = order[rank]
        length = col_lens[col_idx]
        cols[col_idx] = ct[pos:pos + length]
        pos += length
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(cols.get(col, '')):
                result.append(cols[col][row])
    return ''.join(result)


def keyword_to_order(kw, width):
    """Convert keyword to columnar transposition order for given width."""
    seen = []
    for c in kw.upper():
        if c not in seen:
            seen.append(c)
        if len(seen) == width:
            break
    while len(seen) < width:
        for c in ALPH:
            if c not in seen:
                seen.append(c)
            if len(seen) == width:
                break
    indexed = sorted(range(width), key=lambda i: seen[i])
    col_rank = [0] * width
    for rank, col in enumerate(indexed):
        col_rank[col] = rank
    return [col_rank.index(r) for r in range(width)]


def letter_values_to_order(letter_vals, width):
    """Convert letter value sequence to a valid columnar order for given width.
    Takes the first `width` values (mod width) and derives a ranking.
    If duplicate values exist, break ties by position (left-to-right).
    """
    vals = [v % width for v in letter_vals[:width]]
    # If we don't have enough values, extend cyclically
    while len(vals) < width:
        vals.append(letter_vals[len(vals) % len(letter_vals)] % width)
    # Rank by value, ties broken by position
    indexed = sorted(range(width), key=lambda i: (vals[i], i))
    order = [0] * width
    for rank, col in enumerate(indexed):
        order[col] = rank
    return [order.index(r) for r in range(width)]


def load_carter_running_key():
    """Load running key text from Carter Vol 1."""
    carter_path = '/home/cpatrick/kryptos/reference/carter_vol1.txt'
    with open(carter_path, 'r') as f:
        raw = f.read()
    return ''.join(c.upper() for c in raw if c.isalpha())


# ── Key constants ──

ABSCISSA_VALS = [ALPH_IDX[c] for c in 'ABSCISSA']    # [0,1,18,2,8,18,18,0]
PALIMPSEST_VALS = [ALPH_IDX[c] for c in 'PALIMPSEST'] # [15,0,11,8,12,15,18,4,18,19]
KRYPTOS_VALS = [ALPH_IDX[c] for c in 'KRYPTOS']       # [10,17,24,15,19,14,18]

# The three "coordinate" keywords and their natural widths
COORD_KEYWORDS = {
    'ABSCISSA': (ABSCISSA_VALS, 8),     # 8 letters
    'PALIMPSEST': (PALIMPSEST_VALS, 10), # 10 letters
    'KRYPTOS': (KRYPTOS_VALS, 7),        # 7 letters
}

# All 6 permutations of assigning keywords to layers
LAYER_PERMS = list(itertools.permutations(['ABSCISSA', 'PALIMPSEST', 'KRYPTOS']))

# Substitution variants
SUB_KEYS = {
    'identity': None,
    'vig_KRYPTOS': ('vig', KRYPTOS_VALS),
    'vig_PALIMPSEST': ('vig', PALIMPSEST_VALS),
    'vig_ABSCISSA': ('vig', ABSCISSA_VALS),
    'beau_KRYPTOS': ('beau', KRYPTOS_VALS),
    'beau_PALIMPSEST': ('beau', PALIMPSEST_VALS),
    'beau_ABSCISSA': ('beau', ABSCISSA_VALS),
    'varbeau_KRYPTOS': ('varbeau', KRYPTOS_VALS),
    'varbeau_PALIMPSEST': ('varbeau', PALIMPSEST_VALS),
    'varbeau_ABSCISSA': ('varbeau', ABSCISSA_VALS),
}

# Additional widths to try for each keyword
EXTRA_WIDTHS = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]


def apply_sub(text, sub_spec):
    if sub_spec is None:
        return text
    variant, key_vals = sub_spec
    if variant == 'vig':
        return vig_decrypt(text, key_vals)
    elif variant == 'beau':
        return beau_decrypt(text, key_vals)
    elif variant == 'varbeau':
        return varbeau_decrypt(text, key_vals)
    return text


# ── Main ──

def main():
    t0 = time.time()
    total = 0
    best_score = 0
    best_config = None
    best_pt = None
    results_above_noise = []

    def check(pt, config_str):
        nonlocal total, best_score, best_config, best_pt
        sc = score_candidate(pt)
        total += 1
        if sc.crib_score > best_score:
            best_score = sc.crib_score
            best_config = config_str
            best_pt = pt
            print(f"  NEW BEST: {sc.crib_score}/24 -- {config_str}")
            if sc.crib_score >= 10:
                print(f"    PT: {pt}")
        if sc.crib_score >= 7:
            results_above_noise.append({
                'config': config_str,
                'score': sc.crib_score,
                'pt_snippet': pt[:60],
            })
        return sc.crib_score

    print("=" * 70)
    print("E-ROMAN-03b: ABSCISSA/PALIMPSEST/KRYPTOS Coordinate Triple Transposition")
    print("=" * 70)

    print(f"\n  ABSCISSA letter values:   {ABSCISSA_VALS}")
    print(f"  PALIMPSEST letter values: {PALIMPSEST_VALS}")
    print(f"  KRYPTOS letter values:    {KRYPTOS_VALS}")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: Natural widths — keyword-derived orderings, all 6 layer perms
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 1: Natural widths + keyword orderings, all 6 layer perms ---")
    p1_count = 0

    for perm in LAYER_PERMS:
        kw1, kw2, kw3 = perm
        vals1, w1 = COORD_KEYWORDS[kw1]
        vals2, w2 = COORD_KEYWORDS[kw2]
        vals3, w3 = COORD_KEYWORDS[kw3]

        # Method A: keyword_to_order (standard keyword columnar ordering)
        o1 = keyword_to_order(kw1, w1)
        o2 = keyword_to_order(kw2, w2)
        o3 = keyword_to_order(kw3, w3)

        t1 = columnar_decrypt(CT, w1, o1)
        t2 = columnar_decrypt(t1, w2, o2)
        t3 = columnar_decrypt(t2, w3, o3)

        for sub_name, sub_spec in SUB_KEYS.items():
            pt = apply_sub(t3, sub_spec)
            check(pt, f"p1-kw/{kw1}(w{w1})/{kw2}(w{w2})/{kw3}(w{w3})/{sub_name}")
            p1_count += 1

        # Method B: letter_values_to_order (rank by letter values mod width)
        o1b = letter_values_to_order(vals1, w1)
        o2b = letter_values_to_order(vals2, w2)
        o3b = letter_values_to_order(vals3, w3)

        t1b = columnar_decrypt(CT, w1, o1b)
        t2b = columnar_decrypt(t1b, w2, o2b)
        t3b = columnar_decrypt(t2b, w3, o3b)

        for sub_name, sub_spec in SUB_KEYS.items():
            pt = apply_sub(t3b, sub_spec)
            check(pt, f"p1-lv/{kw1}(w{w1})/{kw2}(w{w2})/{kw3}(w{w3})/{sub_name}")
            p1_count += 1

        # Method C: direct letter values as order (take unique sorted positions)
        # For width w, use first w values, sort to get read order
        def vals_to_direct_order(vals, w):
            v = vals[:w]
            # Create (val, original_position) pairs, sort by val
            pairs = sorted(range(len(v)), key=lambda i: (v[i], i))
            order = [0] * w
            for rank, col in enumerate(pairs):
                order[col] = rank
            return [order.index(r) for r in range(w)]

        o1c = vals_to_direct_order(vals1, w1)
        o2c = vals_to_direct_order(vals2, w2)
        o3c = vals_to_direct_order(vals3, w3)

        t1c = columnar_decrypt(CT, w1, o1c)
        t2c = columnar_decrypt(t1c, w2, o2c)
        t3c = columnar_decrypt(t2c, w3, o3c)

        for sub_name, sub_spec in SUB_KEYS.items():
            pt = apply_sub(t3c, sub_spec)
            check(pt, f"p1-direct/{kw1}(w{w1})/{kw2}(w{w2})/{kw3}(w{w3})/{sub_name}")
            p1_count += 1

    print(f"  Phase 1: {p1_count} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: Cross-width — try all width combos from EXTRA_WIDTHS for
    #          each keyword, all 6 layer perms
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 2: Cross-width sweep (all 6 layer perms x widths 3-13) ---")
    p2_count = 0

    for perm in LAYER_PERMS:
        kw1, kw2, kw3 = perm
        vals1, _ = COORD_KEYWORDS[kw1]
        vals2, _ = COORD_KEYWORDS[kw2]
        vals3, _ = COORD_KEYWORDS[kw3]

        for w1 in EXTRA_WIDTHS:
            o1 = keyword_to_order(kw1, w1)
            t1 = columnar_decrypt(CT, w1, o1)
            for w2 in EXTRA_WIDTHS:
                o2 = keyword_to_order(kw2, w2)
                t2 = columnar_decrypt(t1, w2, o2)
                for w3 in EXTRA_WIDTHS:
                    o3 = keyword_to_order(kw3, w3)
                    t3 = columnar_decrypt(t2, w3, o3)

                    for sub_name, sub_spec in SUB_KEYS.items():
                        pt = apply_sub(t3, sub_spec)
                        check(pt, f"p2-xw/{kw1}(w{w1})/{kw2}(w{w2})/{kw3}(w{w3})/{sub_name}")
                        p2_count += 1

                    if total % 50000 == 0:
                        elapsed = time.time() - t0
                        rate = total / elapsed if elapsed > 0 else 0
                        print(f"    ... {total} configs, {rate:.0f}/s, best {best_score}/24")

    print(f"  Phase 2: {p2_count} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3: Letter-values-mod-width as column-read orders, cross-width
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 3: Letter values mod width as orderings ---")
    p3_count = 0

    for perm in LAYER_PERMS:
        kw1, kw2, kw3 = perm
        vals1, _ = COORD_KEYWORDS[kw1]
        vals2, _ = COORD_KEYWORDS[kw2]
        vals3, _ = COORD_KEYWORDS[kw3]

        for w1 in EXTRA_WIDTHS:
            o1 = letter_values_to_order(vals1, w1)
            t1 = columnar_decrypt(CT, w1, o1)
            for w2 in EXTRA_WIDTHS:
                o2 = letter_values_to_order(vals2, w2)
                t2 = columnar_decrypt(t1, w2, o2)
                for w3 in EXTRA_WIDTHS:
                    o3 = letter_values_to_order(vals3, w3)
                    t3 = columnar_decrypt(t2, w3, o3)

                    for sub_name, sub_spec in SUB_KEYS.items():
                        pt = apply_sub(t3, sub_spec)
                        check(pt, f"p3-lvmod/{kw1}(w{w1})/{kw2}(w{w2})/{kw3}(w{w3})/{sub_name}")
                        p3_count += 1

                    if total % 50000 == 0:
                        elapsed = time.time() - t0
                        rate = total / elapsed if elapsed > 0 else 0
                        print(f"    ... {total} configs, {rate:.0f}/s, best {best_score}/24")

    print(f"  Phase 3: {p3_count} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4: All 6 layer orderings + Carter running key
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 4: Coordinate triple trans + Carter running key ---")
    p4_count = 0

    carter_alpha = load_carter_running_key()
    # Sweep offsets around 7692 +/- 200
    rk_start = max(0, 7692 - 200)
    rk_end = min(len(carter_alpha), 7692 + 200 + CT_LEN)
    print(f"  Carter text: {len(carter_alpha)} alpha chars total")
    print(f"  RK sweep: offsets {rk_start} to {rk_end - CT_LEN}")

    for perm in LAYER_PERMS:
        kw1, kw2, kw3 = perm
        vals1, w1 = COORD_KEYWORDS[kw1]
        vals2, w2 = COORD_KEYWORDS[kw2]
        vals3, w3 = COORD_KEYWORDS[kw3]

        # Test both keyword_to_order and letter_values_to_order
        for order_method, om_name in [
            (lambda kw, w: keyword_to_order(kw, w), 'kw'),
            (lambda kw, w: letter_values_to_order(COORD_KEYWORDS[kw][0], w), 'lv'),
        ]:
            o1 = order_method(kw1, w1)
            o2 = order_method(kw2, w2)
            o3 = order_method(kw3, w3)

            t1 = columnar_decrypt(CT, w1, o1)
            t2 = columnar_decrypt(t1, w2, o2)
            t3 = columnar_decrypt(t2, w3, o3)

            for rk_off in range(rk_start, rk_end - CT_LEN + 1):
                rk_text = carter_alpha[rk_off:rk_off + CT_LEN]
                if len(rk_text) < CT_LEN:
                    continue
                rk_vals = [ALPH_IDX[c] for c in rk_text]

                for vname, vfunc in VFUNCS:
                    pt = vfunc(t3, rk_vals)
                    check(pt, f"p4-rk/{om_name}/{kw1}(w{w1})/{kw2}(w{w2})/{kw3}(w{w3})/{vname}/off={rk_off}")
                    p4_count += 1

            if p4_count % 50000 == 0 and p4_count > 0:
                elapsed = time.time() - t0
                rate = total / elapsed if elapsed > 0 else 0
                print(f"    ... {total} configs ({p4_count} RK), {rate:.0f}/s, best {best_score}/24")

    # Also test with all extra widths for top 2 perms
    for perm in LAYER_PERMS[:2]:
        kw1, kw2, kw3 = perm
        for w1 in [7, 8, 10]:
            for w2 in [7, 8, 10]:
                for w3 in [7, 8, 10]:
                    o1 = keyword_to_order(kw1, w1)
                    o2 = keyword_to_order(kw2, w2)
                    o3 = keyword_to_order(kw3, w3)
                    t1 = columnar_decrypt(CT, w1, o1)
                    t2 = columnar_decrypt(t1, w2, o2)
                    t3 = columnar_decrypt(t2, w3, o3)
                    for rk_off in range(rk_start, rk_end - CT_LEN + 1, 5):  # Step 5 to reduce
                        rk_text = carter_alpha[rk_off:rk_off + CT_LEN]
                        if len(rk_text) < CT_LEN:
                            continue
                        rk_vals = [ALPH_IDX[c] for c in rk_text]
                        for vname, vfunc in VFUNCS:
                            pt = vfunc(t3, rk_vals)
                            check(pt, f"p4-rkxw/{kw1}(w{w1})/{kw2}(w{w2})/{kw3}(w{w3})/{vname}/off={rk_off}")
                            p4_count += 1

    print(f"  Phase 4: {p4_count} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 5: ABSCISSA values as direct position permutation
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 5: ABSCISSA values as position-based permutation ---")
    p5_count = 0

    # Use ABSCISSA values [0,1,18,2,8,18,18,0] to define a position-based
    # rearrangement: for each block of 8 chars, rearrange according to ABSCISSA ranking
    def permute_by_values(text, vals):
        """Rearrange text in blocks according to value ranking."""
        blen = len(vals)
        # Create ranking (stable sort by value)
        ranked = sorted(range(blen), key=lambda i: (vals[i], i))
        inv_rank = [0] * blen
        for r, pos in enumerate(ranked):
            inv_rank[pos] = r

        result = list(text)
        nblocks = (len(text) + blen - 1) // blen
        for b in range(nblocks):
            start = b * blen
            end = min(start + blen, len(text))
            block = text[start:end]
            if len(block) < blen:
                # Last incomplete block — leave as is or partial permute
                continue
            for i in range(blen):
                result[start + i] = block[inv_rank[i]]
        return ''.join(result)

    # Apply ABSCISSA permutation, then PALIMPSEST, then KRYPTOS
    for perm in LAYER_PERMS:
        kw1, kw2, kw3 = perm
        vals1, _ = COORD_KEYWORDS[kw1]
        vals2, _ = COORD_KEYWORDS[kw2]
        vals3, _ = COORD_KEYWORDS[kw3]

        t1 = permute_by_values(CT, vals1)
        t2 = permute_by_values(t1, vals2)
        t3 = permute_by_values(t2, vals3)

        for sub_name, sub_spec in SUB_KEYS.items():
            pt = apply_sub(t3, sub_spec)
            check(pt, f"p5-blockperm/{kw1}/{kw2}/{kw3}/{sub_name}")
            p5_count += 1

    # Also try: single permutation pass then substitution
    for kw_name, (vals, _) in COORD_KEYWORDS.items():
        t1 = permute_by_values(CT, vals)
        for sub_name, sub_spec in SUB_KEYS.items():
            pt = apply_sub(t1, sub_spec)
            check(pt, f"p5-single/{kw_name}/{sub_name}")
            p5_count += 1

    # Two-layer block permutation
    for kw1, kw2 in itertools.permutations(COORD_KEYWORDS.keys(), 2):
        vals1, _ = COORD_KEYWORDS[kw1]
        vals2, _ = COORD_KEYWORDS[kw2]
        t1 = permute_by_values(CT, vals1)
        t2 = permute_by_values(t1, vals2)
        for sub_name, sub_spec in SUB_KEYS.items():
            pt = apply_sub(t2, sub_spec)
            check(pt, f"p5-double/{kw1}/{kw2}/{sub_name}")
            p5_count += 1

    print(f"  Phase 5: {p5_count} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 6: Mixed — one layer columnar, one layer block permutation,
    #          one layer substitution
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 6: Mixed columnar + block permutation ---")
    p6_count = 0

    for perm in LAYER_PERMS:
        kw_col, kw_block, kw_sub = perm
        vals_col, w_col = COORD_KEYWORDS[kw_col]
        vals_block, _ = COORD_KEYWORDS[kw_block]
        vals_sub, _ = COORD_KEYWORDS[kw_sub]

        # Columnar first, then block perm, then sub
        for w in EXTRA_WIDTHS:
            o = keyword_to_order(kw_col, w)
            t1 = columnar_decrypt(CT, w, o)
            t2 = permute_by_values(t1, vals_block)
            for vname, vfunc in VFUNCS:
                pt = vfunc(t2, vals_sub)
                check(pt, f"p6-col+block/{kw_col}(w{w})/{kw_block}/{vname}_{kw_sub}")
                p6_count += 1

        # Block perm first, then columnar, then sub
        for w in EXTRA_WIDTHS:
            t1 = permute_by_values(CT, vals_block)
            o = keyword_to_order(kw_col, w)
            t2 = columnar_decrypt(t1, w, o)
            for vname, vfunc in VFUNCS:
                pt = vfunc(t2, vals_sub)
                check(pt, f"p6-block+col/{kw_block}/{kw_col}(w{w})/{vname}_{kw_sub}")
                p6_count += 1

    print(f"  Phase 6: {p6_count} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 7: Keyword values as PERIODIC substitution key after
    #          coordinate-based transposition
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 7: Coordinate trans + periodic key from other keywords ---")
    p7_count = 0

    # For each pair of transposition keywords, use the third as periodic sub key
    for kw_t1, kw_t2, kw_sub in LAYER_PERMS:
        vals_t1, w_t1 = COORD_KEYWORDS[kw_t1]
        vals_t2, w_t2 = COORD_KEYWORDS[kw_t2]
        vals_sub, _ = COORD_KEYWORDS[kw_sub]

        # Two transpositions at natural widths
        o1 = keyword_to_order(kw_t1, w_t1)
        o2 = keyword_to_order(kw_t2, w_t2)
        t1 = columnar_decrypt(CT, w_t1, o1)
        t2 = columnar_decrypt(t1, w_t2, o2)

        # Sub with third keyword's values
        for vname, vfunc in VFUNCS:
            pt = vfunc(t2, vals_sub)
            check(pt, f"p7-2trans+sub/{kw_t1}(w{w_t1})/{kw_t2}(w{w_t2})/{vname}_{kw_sub}")
            p7_count += 1

        # Also try extra widths
        for w1 in [7, 8, 10]:
            for w2 in [7, 8, 10]:
                o1 = keyword_to_order(kw_t1, w1)
                o2 = keyword_to_order(kw_t2, w2)
                t1 = columnar_decrypt(CT, w1, o1)
                t2 = columnar_decrypt(t1, w2, o2)
                for vname, vfunc in VFUNCS:
                    pt = vfunc(t2, vals_sub)
                    check(pt, f"p7-2trans+sub/{kw_t1}(w{w1})/{kw_t2}(w{w2})/{vname}_{kw_sub}")
                    p7_count += 1

    print(f"  Phase 7: {p7_count} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # Summary
    # ═══════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print(f"TOTAL: {total} configurations tested in {elapsed:.1f}s")
    print(f"GLOBAL BEST: {best_score}/24")
    if best_config:
        print(f"BEST CONFIG: {best_config}")
    if best_pt:
        print(f"BEST PT: {best_pt[:60]}...")
    print(f"Results above noise (>=7): {len(results_above_noise)}")

    if best_score <= 6:
        classification = "NOISE"
    elif best_score <= 17:
        classification = "STORE"
    elif best_score <= 23:
        classification = "SIGNAL -- INVESTIGATE!"
    else:
        classification = "BREAKTHROUGH"
    print(f"CLASSIFICATION: {classification}")
    print("=" * 70)

    # Save results
    os.makedirs('results', exist_ok=True)
    output = {
        'experiment': 'E-ROMAN-03b',
        'description': 'ABSCISSA/PALIMPSEST/KRYPTOS coordinate-based triple transposition',
        'hypothesis': 'K1-K3 answers as coordinate system: ABSCISSA=x, PALIMPSEST=y, KRYPTOS=z',
        'total_configs': total,
        'best_score': best_score,
        'best_config': best_config,
        'best_pt_snippet': best_pt[:60] if best_pt else None,
        'classification': classification,
        'elapsed_seconds': round(elapsed, 1),
        'keyword_values': {
            'ABSCISSA': ABSCISSA_VALS,
            'PALIMPSEST': PALIMPSEST_VALS,
            'KRYPTOS': KRYPTOS_VALS,
        },
        'above_noise': results_above_noise[:100],
    }
    with open('results/e_roman_03b_abscissa_coords.json', 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nArtifact: results/e_roman_03b_abscissa_coords.json")


if __name__ == '__main__':
    main()
