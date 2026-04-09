#!/usr/bin/env python3
"""
Cipher: quagmire_indicator
Family: archive_evidence
Status: exhausted
Keyspace: ~5000 configs
Last run:
Best score:
"""
"""E-AAA-INDICATOR-SWEEP-07: Quagmire III/IV with indicator letter sweep.

SOURCE: Archives of American Art — extends E-AAA-TABLEAU-STRUCT-06.

The Quagmire III indicator letter determines which position in the mixed alphabet
aligns with 'A' (or the first letter of the PT alphabet). K1-K3 used indicator 'K'
(the first letter of KRYPTOS). If K4 uses a different indicator, ALL key values
change, potentially producing signal where indicator='A' or indicator='K' did not.

This script sweeps all 26 indicator letters for the archive-supported tableau
alphabets, using the repo's quagmire module directly.

Also tests: ABSCISSA as indicator keyword (first letter 'A' = indicator A),
and explores whether "ABSCISSA" = the indicator letter IS 'A' (the abscissa
of the chart = column A = indicator A).
"""
import sys, os, time

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CONSENSUS_NULL_POSITIONS, ALPH
from kryptos.kernel.alphabet import keyword_mixed_alphabet
from kryptos.kernel.transforms.quagmire import quagmire_decrypt
from kryptos.kernel.scoring.aggregate import score_candidate_free

t0 = time.time()

CT73 = ''.join(c for i, c in enumerate(CT) if i not in CONSENSUS_NULL_POSITIONS)

# Tableau keywords (CT alphabet construction)
CT_KEYWORDS = ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST', 'ECLIPSE', 'NORMANDY', '']
# '' = standard AZ alphabet

# Period keywords
PERIOD_KEYWORDS = ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST', 'ECLIPSE', 'NORMANDY',
                   'KUBARK', 'SHADOW', 'COMPASS', 'ENIGMA', 'SANBORN']

best_score = 0
best_result = None
total = 0
hits = []

print("=" * 80)
print("E-AAA-INDICATOR-SWEEP-07: Quagmire III with indicator sweep")
print("=" * 80)
print(f"CT73: {CT73} ({len(CT73)} chars)")

# For each CT alphabet keyword x period keyword x indicator letter
for ct_kw in CT_KEYWORDS:
    ct_label = ct_kw if ct_kw else 'AZ'
    for period_kw in PERIOD_KEYWORDS:
        for indicator in ALPH:
            pt = quagmire_decrypt(
                CT73,
                period_keyword=period_kw,
                indicator=indicator,
                ct_alphabet_keyword=ct_kw,
                pt_alphabet_keyword='',  # PT uses standard AZ
            )
            total += 1
            sc = score_candidate_free(pt)
            if sc.crib_score > best_score:
                best_score = sc.crib_score
                best_result = (ct_label, period_kw, indicator, pt, sc)
            if sc.crib_score >= 10:
                hits.append((sc.crib_score, ct_label, period_kw, indicator, pt[:40]))

            # Also test with PT alphabet = same as CT alphabet (Quagmire III proper)
            if ct_kw:
                pt2 = quagmire_decrypt(
                    CT73,
                    period_keyword=period_kw,
                    indicator=indicator,
                    ct_alphabet_keyword=ct_kw,
                    pt_alphabet_keyword=ct_kw,
                )
                total += 1
                sc2 = score_candidate_free(pt2)
                if sc2.crib_score > best_score:
                    best_score = sc2.crib_score
                    best_result = (f'{ct_label}(Q3)', period_kw, indicator, pt2, sc2)
                if sc2.crib_score >= 10:
                    hits.append((sc2.crib_score, f'{ct_label}(Q3)', period_kw, indicator, pt2[:40]))

elapsed = time.time() - t0
print(f"\nTotal configurations: {total}")
print(f"Elapsed: {elapsed:.1f}s")
print(f"Best score: {best_score}/24")

if best_result:
    label, pkw, ind, pt, sc = best_result
    print(f"\nBest: ct_alpha={label} period_key={pkw} indicator={ind}")
    print(f"  PT: {pt[:70]}")
    print(f"  Score: {sc}")

if hits:
    print(f"\nHits >= 10:")
    for h in sorted(hits, reverse=True):
        print(f"  score={h[0]} ct={h[1]} key={h[2]} ind={h[3]} pt={h[4]}")
else:
    print("\nNo hits >= 10 (all noise)")

print(f"\n{'='*80}")
