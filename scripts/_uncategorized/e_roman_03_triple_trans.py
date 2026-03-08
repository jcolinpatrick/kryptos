#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-ROMAN-03: Triple sequential columnar transposition experiment.

Hypothesis: Howard Carter's "Tomb of Tut-Ankh-Amen" Chapter X describes beadwork
restoration: "it may be necessary to have three independent threading strings to
every bead, if the rows are to lie smoothly in place." This suggests K4 uses
THREE transposition layers.

Model: CT -> columnar_decrypt(w1, order1) -> columnar_decrypt(w2, order2)
       -> columnar_decrypt(w3, order3) -> substitution -> candidate PT

Search space:
  1. Keyword-derived orderings from 25 thematic keywords
  2. Width triples: homogeneous (5-10) + 9 mixed triples
  3. Substitution: identity + Vig/Beau with KRYPTOS/PALIMPSEST/ABSCISSA
  4. Running key from Carter Chapter X (+/- 200 chars around offset 7692)
"""
import json
import os
import sys
import time

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX
from kryptos.kernel.scoring.aggregate import score_candidate


# ── Cipher functions ──

def vig_decrypt(ct, key_vals):
    """Vigenere: PT = (CT - KEY) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        pt.append(ALPH[(ALPH_IDX[c] - key_vals[i % klen]) % 26])
    return ''.join(pt)


def beau_decrypt(ct, key_vals):
    """Beaufort: PT = (KEY - CT) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        pt.append(ALPH[(key_vals[i % klen] - ALPH_IDX[c]) % 26])
    return ''.join(pt)


def columnar_decrypt(ct, width, order):
    """Standard columnar transposition decrypt.
    order[rank] = col_idx: rank-th column read corresponds to col_idx position.
    """
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
    """Convert keyword to columnar transposition order for given width.
    Returns list where order[rank] = col_idx (reading order).
    """
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
    # Rank by alphabetical order of keyword chars
    indexed = sorted(range(width), key=lambda i: seen[i])
    col_rank = [0] * width
    for rank, col in enumerate(indexed):
        col_rank[col] = rank
    return [col_rank.index(r) for r in range(width)]


def load_carter_running_key(offset, length):
    """Load running key text from Carter Vol 1, returning alpha-only uppercase."""
    carter_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                               'reference', 'carter_vol1.txt')
    if not os.path.exists(carter_path):
        carter_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                   'reference', 'carter_vol1.txt')
    with open(carter_path, 'r') as f:
        raw = f.read()
    # Extract alpha chars starting from approximate byte offset
    alpha = ''.join(c.upper() for c in raw if c.isalpha())
    start = max(0, offset)
    end = min(len(alpha), start + length)
    return alpha[start:end]


# ── Keywords and orderings ──

KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'CARTER', 'HERBERT',
    'TUTANKHAMUN', 'ANTECHAMBER', 'BERLINCLOCK', 'LABORATORY', 'DISCOVERY',
    'EXCAVATION', 'WONDERFUL', 'CANDLE', 'CARNARVON', 'SANBORN',
    'CHECKPOINT', 'CHARLIE', 'GOLDGLINT', 'DESPARATLY', 'LAYERTWO',
    'TREASURE', 'SARCOPHAGUS', 'CHAPTER', 'PATTERN', 'THREADING',
]

# Width triples to test
HOMOGENEOUS_WIDTHS = [5, 6, 7, 8, 9, 10]
MIXED_TRIPLES = [
    (7, 10, 5), (7, 5, 3), (5, 10, 7), (8, 7, 5), (9, 7, 5),
    (10, 7, 3), (5, 7, 10), (6, 8, 10), (7, 9, 5),
]

# Substitution keys
SUB_KEYS = {
    'identity': None,
    'vig_KRYPTOS': ('vig', [ALPH_IDX[c] for c in 'KRYPTOS']),
    'vig_PALIMPSEST': ('vig', [ALPH_IDX[c] for c in 'PALIMPSEST']),
    'vig_ABSCISSA': ('vig', [ALPH_IDX[c] for c in 'ABSCISSA']),
    'beau_KRYPTOS': ('beau', [ALPH_IDX[c] for c in 'KRYPTOS']),
    'beau_PALIMPSEST': ('beau', [ALPH_IDX[c] for c in 'PALIMPSEST']),
    'beau_ABSCISSA': ('beau', [ALPH_IDX[c] for c in 'ABSCISSA']),
}


def apply_substitution(text, sub_spec):
    """Apply substitution layer. sub_spec is None (identity) or (variant, key_vals)."""
    if sub_spec is None:
        return text
    variant, key_vals = sub_spec
    if variant == 'vig':
        return vig_decrypt(text, key_vals)
    elif variant == 'beau':
        return beau_decrypt(text, key_vals)
    return text


def apply_running_key(text, rk_text, variant):
    """Apply running key substitution."""
    key_vals = [ALPH_IDX[c] for c in rk_text[:len(text)]]
    if variant == 'vig':
        return vig_decrypt(text, key_vals)
    else:
        return beau_decrypt(text, key_vals)


# ── Precompute unique orderings per width ──

def build_orderings_for_width(width):
    """Build deduplicated keyword-derived orderings for a given width."""
    seen = set()
    orderings = []
    for kw in KEYWORDS:
        order = tuple(keyword_to_order(kw, width))
        if order not in seen:
            seen.add(order)
            orderings.append((kw, list(order)))
    # Also add identity and reverse
    ident = tuple(range(width))
    if ident not in seen:
        seen.add(ident)
        orderings.append(('identity', list(ident)))
    rev = tuple(range(width - 1, -1, -1))
    if rev not in seen:
        seen.add(rev)
        orderings.append(('reverse', list(rev)))
    return orderings


# ── Main ──

def main():
    t0 = time.time()
    total = 0
    best_score = 0
    best_config = None
    best_pt = None
    results_above_noise = []

    print("=" * 70)
    print("E-ROMAN-03: Triple Sequential Columnar Transposition")
    print("=" * 70)

    # Precompute orderings for all needed widths
    all_widths = set(HOMOGENEOUS_WIDTHS)
    for w1, w2, w3 in MIXED_TRIPLES:
        all_widths.update([w1, w2, w3])
    all_widths = sorted(all_widths)

    orderings_by_width = {}
    for w in all_widths:
        orderings_by_width[w] = build_orderings_for_width(w)
        print(f"  Width {w}: {len(orderings_by_width[w])} unique orderings")

    # Build width triples list
    width_triples = [(w, w, w) for w in HOMOGENEOUS_WIDTHS] + list(MIXED_TRIPLES)
    print(f"\n  Width triples to test: {len(width_triples)}")

    # Count total combos for estimation
    total_combos = 0
    for w1, w2, w3 in width_triples:
        n1 = len(orderings_by_width[w1])
        n2 = len(orderings_by_width[w2])
        n3 = len(orderings_by_width[w3])
        total_combos += n1 * n2 * n3
    total_sub = len(SUB_KEYS)
    print(f"  Triple combos: {total_combos}")
    print(f"  Substitution variants: {total_sub}")
    print(f"  Estimated configs (phase 1): {total_combos * total_sub}")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: Triple transposition + substitution
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 1: Triple transposition + substitution ---")
    p1_start = time.time()

    for widx, (w1, w2, w3) in enumerate(width_triples):
        orders1 = orderings_by_width[w1]
        orders2 = orderings_by_width[w2]
        orders3 = orderings_by_width[w3]
        triple_label = f"({w1},{w2},{w3})"
        combo_count = len(orders1) * len(orders2) * len(orders3)
        print(f"  Width triple {triple_label}: {combo_count} ordering combos x {total_sub} subs = {combo_count * total_sub}")

        for kw1, o1 in orders1:
            # Apply first transposition
            t1 = columnar_decrypt(CT, w1, o1)
            for kw2, o2 in orders2:
                # Apply second transposition
                t2 = columnar_decrypt(t1, w2, o2)
                for kw3, o3 in orders3:
                    # Apply third transposition
                    t3 = columnar_decrypt(t2, w3, o3)

                    # Apply each substitution variant
                    for sub_name, sub_spec in SUB_KEYS.items():
                        pt = apply_substitution(t3, sub_spec)
                        sc = score_candidate(pt)
                        total += 1

                        if sc.crib_score > best_score:
                            best_score = sc.crib_score
                            best_config = f"{triple_label}/{kw1}/{kw2}/{kw3}/{sub_name}"
                            best_pt = pt
                            print(f"  NEW BEST: {sc.crib_score}/24 -- {best_config}")
                            if sc.crib_score >= 10:
                                print(f"    PT: {pt}")

                        if sc.crib_score >= 7:
                            results_above_noise.append({
                                'config': f"{triple_label}/{kw1}/{kw2}/{kw3}/{sub_name}",
                                'score': sc.crib_score,
                                'pt_snippet': pt[:60],
                            })

                    if total % 50000 == 0:
                        elapsed = time.time() - t0
                        rate = total / elapsed if elapsed > 0 else 0
                        print(f"    ... {total} configs, {rate:.0f}/s, best {best_score}/24")

        p1_elapsed = time.time() - p1_start
        print(f"  {triple_label} done. Total so far: {total}, {p1_elapsed:.1f}s, best {best_score}/24")

    p1_total = total
    p1_elapsed = time.time() - p1_start
    print(f"\n  Phase 1 complete: {p1_total} configs in {p1_elapsed:.1f}s, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: Triple transposition + running key from Carter Chapter X
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n--- Phase 2: Triple transposition + Carter running key ---")
    p2_start = time.time()
    p2_count = 0

    # Load Carter text around offset 7692 (alpha chars), +/- 200
    # We need at least 97 chars from each starting position
    carter_start = max(0, 7692 - 200)
    carter_end = 7692 + 200 + CT_LEN
    carter_text = load_carter_running_key(carter_start, carter_end - carter_start)
    print(f"  Carter text loaded: {len(carter_text)} alpha chars from offset {carter_start}")
    if len(carter_text) < CT_LEN:
        print(f"  WARNING: Carter text too short ({len(carter_text)} < {CT_LEN})")

    # For running key phase, use only identity transposition ordering combinations
    # that scored best in phase 1, plus a representative sample
    # To keep runtime reasonable, test top keyword per width + identity
    rk_orderings = {}
    for w in all_widths:
        # Take first 5 unique orderings per width (most thematic)
        rk_orderings[w] = orderings_by_width[w][:5]

    # Narrower set of width triples for running key phase
    rk_triples = [(w, w, w) for w in [7, 8, 9, 10]] + [
        (7, 10, 5), (8, 7, 5), (9, 7, 5), (5, 7, 10),
    ]

    rk_offsets = range(0, min(400, len(carter_text) - CT_LEN + 1))

    for w1, w2, w3 in rk_triples:
        o1_list = rk_orderings.get(w1, orderings_by_width[w1][:3])
        o2_list = rk_orderings.get(w2, orderings_by_width[w2][:3])
        o3_list = rk_orderings.get(w3, orderings_by_width[w3][:3])
        triple_label = f"({w1},{w2},{w3})"

        for kw1, o1 in o1_list:
            t1 = columnar_decrypt(CT, w1, o1)
            for kw2, o2 in o2_list:
                t2 = columnar_decrypt(t1, w2, o2)
                for kw3, o3 in o3_list:
                    t3 = columnar_decrypt(t2, w3, o3)

                    # Sweep running key offsets
                    for rk_off in rk_offsets:
                        rk_segment = carter_text[rk_off:rk_off + CT_LEN]
                        if len(rk_segment) < CT_LEN:
                            continue

                        for variant in ['vig', 'beau']:
                            pt = apply_running_key(t3, rk_segment, variant)
                            sc = score_candidate(pt)
                            total += 1
                            p2_count += 1

                            if sc.crib_score > best_score:
                                best_score = sc.crib_score
                                best_config = f"rk/{triple_label}/{kw1}/{kw2}/{kw3}/{variant}/off={carter_start + rk_off}"
                                best_pt = pt
                                print(f"  NEW BEST: {sc.crib_score}/24 -- {best_config}")
                                if sc.crib_score >= 10:
                                    print(f"    PT: {pt}")

                            if sc.crib_score >= 7:
                                results_above_noise.append({
                                    'config': f"rk/{triple_label}/{kw1}/{kw2}/{kw3}/{variant}/off={carter_start + rk_off}",
                                    'score': sc.crib_score,
                                    'pt_snippet': pt[:60],
                                })

                        if p2_count % 50000 == 0:
                            elapsed = time.time() - t0
                            rate = total / elapsed if elapsed > 0 else 0
                            print(f"    ... {total} configs ({p2_count} RK), {rate:.0f}/s, best {best_score}/24")

    p2_elapsed = time.time() - p2_start
    print(f"\n  Phase 2 complete: {p2_count} configs in {p2_elapsed:.1f}s, best {best_score}/24")

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
        'experiment': 'E-ROMAN-03',
        'description': 'Triple sequential columnar transposition + substitution/running key',
        'hypothesis': 'Carter Ch X beadwork "three independent threading strings" -> 3 transposition layers',
        'total_configs': total,
        'best_score': best_score,
        'best_config': best_config,
        'best_pt_snippet': best_pt[:60] if best_pt else None,
        'classification': classification,
        'phase1_configs': p1_total,
        'phase2_configs': p2_count,
        'elapsed_seconds': round(elapsed, 1),
        'width_triples_tested': [list(t) for t in width_triples],
        'keywords_used': KEYWORDS,
        'above_noise': results_above_noise[:100],  # Cap at 100 entries
    }
    result_path = 'results/e_roman_03_triple_trans.json'
    with open(result_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nArtifact: {result_path}")


if __name__ == '__main__':
    main()
