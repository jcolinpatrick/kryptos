#!/usr/bin/env python3
"""E-CHART-06: Test HERBERT and Carter-related primers.

Jim Sanborn's real first name is Herbert. Lady Evelyn Herbert was
Lord Carnarvon's daughter, one of the first into Tutankhamun's tomb
(the K3 source material). Test HERBERT as autokey primer, keyword,
and in combinations.
"""
import json, itertools, os, sys

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, CRIB_DICT

from kryptos.kernel.scoring.aggregate import score_candidate

# KA alphabet index
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

def vig_decrypt(ct, key, alph_idx):
    """Vigenere: PT = (CT - KEY) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)] if isinstance(key, str) else key[i]
        ci = alph_idx[c]
        ki = alph_idx[k] if isinstance(k, str) else k
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)

def beau_decrypt(ct, key, alph_idx):
    """Beaufort: PT = (KEY - CT) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)] if isinstance(key, str) else key[i]
        ci = alph_idx[c]
        ki = alph_idx[k] if isinstance(k, str) else k
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)

def varbeau_decrypt(ct, key, alph_idx):
    """Variant Beaufort: PT = (CT + KEY) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)] if isinstance(key, str) else key[i]
        ci = alph_idx[c]
        ki = alph_idx[k] if isinstance(k, str) else k
        pt.append(ALPH[(ci + ki) % 26])
    return ''.join(pt)

def autokey_pt_decrypt(ct, primer, variant='vig', alph_idx=ALPH_IDX):
    """Plaintext-autokey: key = primer + PT[0], PT[1], ..."""
    pt = []
    key_vals = [alph_idx[c] for c in primer]
    for i, c in enumerate(ct):
        ci = alph_idx[c]
        ki = key_vals[i]
        if variant == 'vig':
            p = (ci - ki) % 26
        elif variant == 'beau':
            p = (ki - ci) % 26
        else:  # varbeau
            p = (ci + ki) % 26
        pt.append(ALPH[p])
        key_vals.append(p)  # feed back plaintext
    return ''.join(pt)

def autokey_ct_decrypt(ct, primer, variant='vig', alph_idx=ALPH_IDX):
    """Ciphertext-autokey: key = primer + CT[0], CT[1], ..."""
    pt = []
    key_vals = [alph_idx[c] for c in primer]
    ct_vals = [alph_idx[c] for c in ct]
    for i in range(len(ct_vals)):
        ci = ct_vals[i]
        ki = key_vals[i]
        if variant == 'vig':
            p = (ci - ki) % 26
        elif variant == 'beau':
            p = (ki - ci) % 26
        else:  # varbeau
            p = (ci + ki) % 26
        pt.append(ALPH[p])
        key_vals.append(ci)  # feed back ciphertext
    return ''.join(pt)

def apply_columnar_trans(ct, width, order):
    """Un-transpose: given CT arranged in columns by order, recover original."""
    n = len(ct)
    nrows = (n + width - 1) // width
    full_cols = n % width if n % width != 0 else width

    # Figure out column lengths
    col_lens = []
    for col in range(width):
        if full_cols == width or col < full_cols:
            col_lens.append(nrows)
        else:
            col_lens.append(nrows - 1)

    # Split CT into columns in order
    cols = {}
    pos = 0
    for rank in range(width):
        col_idx = order[rank]
        length = col_lens[col_idx]
        cols[col_idx] = ct[pos:pos+length]
        pos += length

    # Read off row by row
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(cols[col]):
                result.append(cols[col][row])
    return ''.join(result)

# ── Primers to test ──
HERBERT_PRIMERS = [
    'HERBERT', 'EVELYN', 'EVELYNHERBERT', 'HERBERTEVELYN',
    'CARNARVON', 'LORDCARNARVON', 'CARTER', 'HOWARDCARTER',
    'TUTANKHAMUN', 'TUTANKHAMEN', 'TOMB', 'PHARAOH',
    'SANBORN', 'HERBERTSANBORN', 'HERBERTJAMES',
    'JIMHERBERT', 'HERBERTJIM',
    # Combine HERBERT with YAR
    'HERBERTYAR', 'YARHERBERT', 'HERBERTDYAR', 'DYARHERBERT',
    # HERBERT + sculpture elements
    'HERBERTKRYPTOS', 'KRYPTOSHERBERT',
    'HERBERTPALIMPSEST', 'PALIMPSESTHERBERT',
    'HERBERTABSCISSA', 'ABSCISSAHERBERT',
    'HERBERTGOLD', 'GOLDHERBERT',
    'HERBERTSTOPWATCH', 'STOPWATCHHERBERT',
    'HERBERTHILL', 'HILLHERBERT',
    'HERBERTISLE', 'ISLEHERBERT',
    'HERBERTLIES', 'LIESHERBERT',
    # Just the name as a keyword
    'HERBERT',
]
# Deduplicate
HERBERT_PRIMERS = list(dict.fromkeys(HERBERT_PRIMERS))

results = []
best_score = 0
best_config = None
total = 0

print("=" * 70)
print("E-CHART-06: HERBERT & Carter-Related Primers")
print("=" * 70)

# ── Phase 1: Direct keyword substitution ──
print("\n--- Phase 1: HERBERT as repeating keyword ---")
for primer in HERBERT_PRIMERS:
    for variant_name, func in [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]:
        for alph_name, aidx in [('AZ', ALPH_IDX), ('KA', KA_IDX)]:
            pt = func(CT, primer, aidx)
            sc = score_candidate(pt)
            total += 1
            if sc.crib_score > best_score:
                best_score = sc.crib_score
                best_config = f"keyword={primer}/{variant_name}/{alph_name}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {best_config}")
                print(f"    PT snippet: {pt[:40]}...")
            if sc.crib_score >= 6:
                results.append({
                    'phase': 'keyword',
                    'primer': primer,
                    'variant': variant_name,
                    'alphabet': alph_name,
                    'score': sc.crib_score,
                    'pt_snippet': pt[:50],
                })

print(f"  Phase 1: {total} configs, best {best_score}/24")

# ── Phase 2: Autokey with HERBERT primers ──
print("\n--- Phase 2: Autokey with HERBERT-related primers ---")
phase2_best = 0
for primer in HERBERT_PRIMERS:
    for variant in ['vig', 'beau', 'varbeau']:
        for feedback in ['pt', 'ct']:
            for alph_name, aidx in [('AZ', ALPH_IDX), ('KA', KA_IDX)]:
                if feedback == 'pt':
                    pt = autokey_pt_decrypt(CT, primer, variant, aidx)
                else:
                    pt = autokey_ct_decrypt(CT, primer, variant, aidx)
                sc = score_candidate(pt)
                total += 1
                if sc.crib_score > phase2_best:
                    phase2_best = sc.crib_score
                    cfg = f"autokey-{feedback}/{primer}/{variant}/{alph_name}"
                    print(f"  NEW BEST: {sc.crib_score}/24 — {cfg}")
                    print(f"    PT snippet: {pt[:40]}...")
                if sc.crib_score >= 6:
                    results.append({
                        'phase': 'autokey',
                        'primer': primer,
                        'variant': variant,
                        'feedback': feedback,
                        'alphabet': alph_name,
                        'score': sc.crib_score,
                        'pt_snippet': pt[:50],
                    })

if phase2_best > best_score:
    best_score = phase2_best
print(f"  Phase 2: {total} configs total, autokey best {phase2_best}/24")

# ── Phase 3: HERBERT + width-8 columnar transposition ──
print("\n--- Phase 3: HERBERT autokey + width-8 columnar ---")
# Test HERBERT specifically with all 40,320 w8 orderings
phase3_best = 0
p3_count = 0
for order in itertools.permutations(range(8)):
    untrans = apply_columnar_trans(CT, 8, list(order))
    for variant in ['vig', 'beau', 'varbeau']:
        for feedback in ['pt', 'ct']:
            if feedback == 'pt':
                pt = autokey_pt_decrypt(untrans, 'HERBERT', variant, ALPH_IDX)
            else:
                pt = autokey_ct_decrypt(untrans, 'HERBERT', variant, ALPH_IDX)
            sc = score_candidate(pt)
            p3_count += 1
            total += 1
            if sc.crib_score > phase3_best:
                phase3_best = sc.crib_score
                cfg = f"w8-autokey-{feedback}/HERBERT/{variant}/order={list(order)}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {cfg}")
                if sc.crib_score >= 10:
                    print(f"    PT: {pt}")
            if sc.crib_score >= 8:
                results.append({
                    'phase': 'w8_autokey',
                    'primer': 'HERBERT',
                    'variant': variant,
                    'feedback': feedback,
                    'order': list(order),
                    'score': sc.crib_score,
                    'pt_snippet': pt[:50],
                })

if phase3_best > best_score:
    best_score = phase3_best
print(f"  Phase 3: {p3_count} configs, w8+autokey best {phase3_best}/24")

# ── Phase 4: HERBERT as keyword + width-8 columnar ──
print("\n--- Phase 4: HERBERT keyword + width-8 columnar ---")
phase4_best = 0
p4_count = 0
for order in itertools.permutations(range(8)):
    untrans = apply_columnar_trans(CT, 8, list(order))
    for variant_name, func in [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]:
        pt = func(untrans, 'HERBERT', ALPH_IDX)
        sc = score_candidate(pt)
        p4_count += 1
        total += 1
        if sc.crib_score > phase4_best:
            phase4_best = sc.crib_score
            cfg = f"w8-keyword/HERBERT/{variant_name}/order={list(order)}"
            print(f"  NEW BEST: {sc.crib_score}/24 — {cfg}")
            if sc.crib_score >= 10:
                print(f"    PT: {pt}")
        if sc.crib_score >= 8:
            results.append({
                'phase': 'w8_keyword',
                'primer': 'HERBERT',
                'variant': variant_name,
                'order': list(order),
                'score': sc.crib_score,
                'pt_snippet': pt[:50],
            })

if phase4_best > best_score:
    best_score = phase4_best
print(f"  Phase 4: {p4_count} configs, w8+keyword best {phase4_best}/24")

# ── Phase 5: EVELYN, CARNARVON, CARTER + width-8 columnar ──
print("\n--- Phase 5: Other Carter-related keywords + width-8 columnar ---")
phase5_best = 0
p5_count = 0
CARTER_KEYS = ['EVELYN', 'CARNARVON', 'CARTER', 'TUTANKHAMUN', 'HERBERTEVELYN']
for keyword in CARTER_KEYS:
    for order in itertools.permutations(range(8)):
        untrans = apply_columnar_trans(CT, 8, list(order))
        for variant_name, func in [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]:
            pt = func(untrans, keyword, ALPH_IDX)
            sc = score_candidate(pt)
            p5_count += 1
            total += 1
            if sc.crib_score > phase5_best:
                phase5_best = sc.crib_score
                cfg = f"w8-keyword/{keyword}/{variant_name}/order={list(order)}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {cfg}")
                if sc.crib_score >= 10:
                    print(f"    PT: {pt}")
            if sc.crib_score >= 8:
                results.append({
                    'phase': 'w8_carter_keyword',
                    'primer': keyword,
                    'variant': variant_name,
                    'order': list(order),
                    'score': sc.crib_score,
                    'pt_snippet': pt[:50],
                })
    print(f"    {keyword}: best so far {phase5_best}/24 ({p5_count} configs)")

if phase5_best > best_score:
    best_score = phase5_best
print(f"  Phase 5: {p5_count} configs, best {phase5_best}/24")

# ── Summary ──
print("\n" + "=" * 70)
print(f"TOTAL: {total} configurations tested")
print(f"GLOBAL BEST: {best_score}/24")
print(f"Results above noise: {len(results)}")
if best_score <= 9:
    print("CLASSIFICATION: NOISE")
elif best_score <= 17:
    print("CLASSIFICATION: STORE (worth logging but likely noise at w8)")
else:
    print("CLASSIFICATION: SIGNAL — INVESTIGATE!")
print("=" * 70)

# Save results
os.makedirs('results', exist_ok=True)
with open('results/e_chart_06_herbert.json', 'w') as f:
    json.dump({
        'experiment': 'E-CHART-06',
        'description': 'HERBERT and Carter-related primers',
        'total_configs': total,
        'best_score': best_score,
        'classification': 'NOISE' if best_score <= 9 else 'STORE' if best_score <= 17 else 'SIGNAL',
        'above_noise': results,
    }, f, indent=2)
print(f"\nArtifact: results/e_chart_06_herbert.json")
