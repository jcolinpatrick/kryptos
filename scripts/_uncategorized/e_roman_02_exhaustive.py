#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-ROMAN-02: Exhaustive transposition sweeps with Roman numeral keys.

Follow-up to E-ROMAN-01 (all NOISE at 66K configs). This test runs the
computationally heavier exhaustive columnar transposition sweeps combined
with the most promising Roman-numeral-derived key sequences.

Key hypotheses:
  1. K3 used w7(KRYPTOS) + p10(PALIMPSEST). K4 uses w10(X=10) + keyword.
  2. Excavation dates beyond Nov 26 + transposition (never tested before).
  3. Width-6 (Chapter VI, page 97) + date/chapter keys, exhaustive.
  4. Width-10 exhaustive (3.6M orderings) with PALIMPSEST as key.
  5. Width-8 (Bean-compatible) + ALL excavation date keys.
"""
import json, itertools, os, sys, time

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Cipher functions ──

def vig_d(ct, key_vals):
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        pt.append(ALPH[(ALPH_IDX[c] - key_vals[i % klen]) % 26])
    return ''.join(pt)

def beau_d(ct, key_vals):
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        pt.append(ALPH[(key_vals[i % klen] - ALPH_IDX[c]) % 26])
    return ''.join(pt)

def varbeau_d(ct, key_vals):
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        pt.append(ALPH[(ALPH_IDX[c] + key_vals[i % klen]) % 26])
    return ''.join(pt)

VFUNCS = [('vig', vig_d), ('beau', beau_d), ('varbeau', varbeau_d)]

def columnar_decrypt(ct, width, order):
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
    order = [0] * width
    for rank, col in enumerate(indexed):
        order[col] = rank
    return [order.index(r) for r in range(width)]

# ── Key sequences from Roman numeral / date hypotheses ──

# Excavation dates as key sequences (comprehensive)
DATE_KEYS = {
    # Nov 4, 1922 — discovery of first step
    'nov4_digits':    [1, 1, 0, 4, 1, 9, 2, 2],
    'nov4_comp':      [11, 4, 19, 22],
    'nov4_md':        [11, 4],
    'nov4_day':       [4],
    # Nov 5, 1922 — staircase cleared
    'nov5_md':        [11, 5],
    'nov5_day':       [5],
    # Nov 25, 1922 — second sealed door
    'nov25_md':       [11, 25],
    'nov25_day':      [25],
    # Nov 26, 1922 — "Can you see anything?" (previously tested alone)
    'nov26_md':       [11, 26 % 26],  # 26%26=0
    'nov26_day':      [26 % 26],
    # Nov 27, 1922 — Antechamber explored
    'nov27_md':       [11, 1],  # 27%26=1
    # Feb 16, 1923 — Burial chamber OFFICIALLY opened
    'feb16_digits':   [0, 2, 1, 6, 1, 9, 2, 3],
    'feb16_comp':     [2, 16, 19, 23],
    'feb16_md':       [2, 16],
    'feb16_day':      [16],
    # Feb 17, 1923 — First entry to burial chamber
    'feb17_md':       [2, 17],
    'feb17_day':      [17],
    # Apr 5, 1923 — Carnarvon dies
    'apr5_md':        [4, 5],
    'apr5_day':       [5],
    # Combined: sequence of all discovery days
    'all_nov_days':   [4, 5, 23, 25, 26, 27, 28, 29],
    # Key moments days
    'key3_days':      [4, 26, 16],  # discovery, breach, burial opening
    'key3_mod':       [4, 0, 16],   # mod 26
    # Gap between events
    'gap_nov26_feb16': [84 % 26],   # = 6 (!!!)
    # Roman chapter numbers
    'roman_V':        [5],
    'roman_VI':       [6],
    'roman_X':        [10],
    'roman_V_VI':     [5, 6],
    'roman_V_X':      [5, 10],
    'roman_VI_X':     [6, 10],
    'roman_V_to_XI':  [5, 6, 7, 8, 9, 10, 11],
    # PALIMPSEST as numeric (same as K3's key)
    'PALIMPSEST': [ALPH_IDX[c] for c in 'PALIMPSEST'],
    # ABSCISSA as numeric
    'ABSCISSA': [ALPH_IDX[c] for c in 'ABSCISSA'],
    # KRYPTOS as numeric
    'KRYPTOS': [ALPH_IDX[c] for c in 'KRYPTOS'],
    # Chapter titles as keys
    'PRELIMINARY': [ALPH_IDX[c] for c in 'PRELIMINARY'],
    'INVESTIGATION': [ALPH_IDX[c] for c in 'INVESTIGATION'],
    'FINDING': [ALPH_IDX[c] for c in 'FINDING'],
    'SURVEY': [ALPH_IDX[c] for c in 'SURVEY'],
    'LABORATORY': [ALPH_IDX[c] for c in 'LABORATORY'],
}

results = []
best_score = 0
best_config = None
total = 0
t0 = time.time()

print("=" * 70)
print("E-ROMAN-02: Exhaustive Transposition + Roman Numeral Keys")
print("=" * 70)

# ══════════════════════════════════════════════════════════════════════
# SWEEP 1: Width-8 exhaustive (40,320 orderings) × top date keys
# ══════════════════════════════════════════════════════════════════════
print("\n--- Sweep 1: Width-8 exhaustive × date/Roman keys ---")
s1_count = 0
s1_best = 0

# Select most promising keys (short + medium length)
sweep1_keys = {k: v for k, v in DATE_KEYS.items()
               if len(v) <= 8 and k not in ['PALIMPSEST', 'ABSCISSA', 'KRYPTOS',
                                              'PRELIMINARY', 'INVESTIGATION',
                                              'FINDING', 'SURVEY', 'LABORATORY']}

for order in itertools.permutations(range(8)):
    untrans = columnar_decrypt(CT, 8, list(order))
    for kname, kvals in sweep1_keys.items():
        for vname, vfunc in VFUNCS:
            pt = vfunc(untrans, kvals)
            sc = score_candidate(pt)
            s1_count += 1
            total += 1
            if sc.crib_score > s1_best:
                s1_best = sc.crib_score
                cfg = f"w8/{kname}/{vname}/order={list(order)}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {cfg}")
                if sc.crib_score > best_score:
                    best_score = sc.crib_score
                    best_config = cfg
                if sc.crib_score >= 10:
                    print(f"    PT: {pt}")
            if sc.crib_score >= 8:
                results.append({
                    'sweep': 'w8_dates', 'config': f"{kname}/{vname}",
                    'order': list(order), 'score': sc.crib_score,
                    'pt_snippet': pt[:60],
                })

elapsed = time.time() - t0
print(f"  Sweep 1: {s1_count} configs in {elapsed:.1f}s, best {s1_best}/24")

# ══════════════════════════════════════════════════════════════════════
# SWEEP 2: Width-8 × keyword keys (PALIMPSEST, ABSCISSA, chapter titles)
# ══════════════════════════════════════════════════════════════════════
print("\n--- Sweep 2: Width-8 × keyword keys ---")
s2_count = 0
s2_best = 0

sweep2_keys = {k: v for k, v in DATE_KEYS.items()
               if k in ['PALIMPSEST', 'ABSCISSA', 'KRYPTOS', 'PRELIMINARY',
                         'INVESTIGATION', 'FINDING', 'SURVEY', 'LABORATORY']}

for order in itertools.permutations(range(8)):
    untrans = columnar_decrypt(CT, 8, list(order))
    for kname, kvals in sweep2_keys.items():
        for vname, vfunc in VFUNCS:
            pt = vfunc(untrans, kvals)
            sc = score_candidate(pt)
            s2_count += 1
            total += 1
            if sc.crib_score > s2_best:
                s2_best = sc.crib_score
                cfg = f"w8/{kname}/{vname}"
                print(f"  NEW BEST: {sc.crib_score}/24 — {cfg}")
                if sc.crib_score > best_score:
                    best_score = sc.crib_score
                    best_config = cfg
            if sc.crib_score >= 8:
                results.append({
                    'sweep': 'w8_keywords', 'config': f"{kname}/{vname}",
                    'order': list(order), 'score': sc.crib_score,
                    'pt_snippet': pt[:60],
                })

elapsed = time.time() - t0
print(f"  Sweep 2: {s2_count} configs in {elapsed:.1f}s, best {s2_best}/24")

# ══════════════════════════════════════════════════════════════════════
# SWEEP 3: Width-6 exhaustive (720 orderings) × ALL keys
# ══════════════════════════════════════════════════════════════════════
print("\n--- Sweep 3: Width-6 exhaustive × ALL keys ---")
s3_count = 0
s3_best = 0

for order in itertools.permutations(range(6)):
    untrans = columnar_decrypt(CT, 6, list(order))
    for kname, kvals in DATE_KEYS.items():
        for vname, vfunc in VFUNCS:
            pt = vfunc(untrans, kvals)
            sc = score_candidate(pt)
            s3_count += 1
            total += 1
            if sc.crib_score > s3_best:
                s3_best = sc.crib_score
                cfg = f"w6/{kname}/{vname}"
                if s3_best > best_score:
                    best_score = s3_best
                    best_config = cfg
                print(f"  NEW BEST: {sc.crib_score}/24 — {cfg}")
            if sc.crib_score >= 8:
                results.append({
                    'sweep': 'w6_all', 'config': f"{kname}/{vname}",
                    'order': list(order), 'score': sc.crib_score,
                    'pt_snippet': pt[:60],
                })

elapsed = time.time() - t0
print(f"  Sweep 3: {s3_count} configs in {elapsed:.1f}s, best {s3_best}/24")

# ══════════════════════════════════════════════════════════════════════
# SWEEP 4: Width-10 keyword orderings × PALIMPSEST + dates
# ══════════════════════════════════════════════════════════════════════
print("\n--- Sweep 4: Width-10 keyword orderings × all keys ---")
s4_count = 0
s4_best = 0

# For width-10, exhaustive is 3.6M orderings — too slow with all keys.
# Use 40 keyword-derived orderings + random sample.
w10_kw_orders = []
kw_list_10 = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'BERLINCLOCK', 'EASTNORTHEAS',
    'TUTANKHAMUN', 'CARTER', 'HERBERT', 'ANTECHAMBER', 'GOLDGLINT',
    'WONDERFUL', 'TOMBOFTUT', 'DISCOVERY', 'EXCAVATION', 'PRELIMINARY',
    'CARNARVON', 'EVELYN', 'CANDLE', 'DESPARATLY', 'SANBORN',
    'CHECKPOINT', 'CHARLIE', 'STOPWATCH', 'HOWARDCARTER', 'LAYERTWO',
    'INVESTIGATION', 'LABORATORY', 'FINDING', 'SURVEY', 'CLEARANCE',
    'CHAPTER', 'VOLUME', 'APPENDIX', 'TREASURE', 'SARCOPHAGUS',
    'PHOTOGRAPH', 'PLATE', 'ROMAN', 'NUMERAL', 'HIEROGLYPH',
]

seen_orders = set()
for kw in kw_list_10:
    try:
        o = tuple(keyword_to_order(kw, 10))
        if o not in seen_orders:
            seen_orders.add(o)
            w10_kw_orders.append((kw, list(o)))
    except Exception:
        pass

# Also add identity and reverse
for extra_name, extra_order in [('identity', list(range(10))),
                                 ('reverse', list(range(9, -1, -1)))]:
    o = tuple(extra_order)
    if o not in seen_orders:
        seen_orders.add(o)
        w10_kw_orders.append((extra_name, extra_order))

print(f"  {len(w10_kw_orders)} unique width-10 orderings from keywords")

for oname, order in w10_kw_orders:
    untrans = columnar_decrypt(CT, 10, order)
    for kname, kvals in DATE_KEYS.items():
        for vname, vfunc in VFUNCS:
            pt = vfunc(untrans, kvals)
            sc = score_candidate(pt)
            s4_count += 1
            total += 1
            if sc.crib_score > s4_best:
                s4_best = sc.crib_score
                cfg = f"w10/{oname}/{kname}/{vname}"
                if s4_best > best_score:
                    best_score = s4_best
                    best_config = cfg
                print(f"  NEW BEST: {sc.crib_score}/24 — {cfg}")
            if sc.crib_score >= 8:
                results.append({
                    'sweep': 'w10_kw', 'config': cfg,
                    'order': order, 'score': sc.crib_score,
                    'pt_snippet': pt[:60],
                })

elapsed = time.time() - t0
print(f"  Sweep 4: {s4_count} configs in {elapsed:.1f}s, best {s4_best}/24")

# ══════════════════════════════════════════════════════════════════════
# SWEEP 5: Width-10 exhaustive × PALIMPSEST only (the K3 method variant)
# ══════════════════════════════════════════════════════════════════════
print("\n--- Sweep 5: Width-10 exhaustive × PALIMPSEST (K3-variant) ---")
s5_count = 0
s5_best = 0

palimpsest_key = [ALPH_IDX[c] for c in 'PALIMPSEST']  # [15,0,11,8,12,15,18,4,18,19]

for order in itertools.permutations(range(10)):
    untrans = columnar_decrypt(CT, 10, list(order))
    for vname, vfunc in VFUNCS:
        pt = vfunc(untrans, palimpsest_key)
        sc = score_candidate(pt)
        s5_count += 1
        total += 1
        if sc.crib_score > s5_best:
            s5_best = sc.crib_score
            cfg = f"w10-exhaustive/PALIMPSEST/{vname}/order={list(order)}"
            if s5_best > best_score:
                best_score = s5_best
                best_config = cfg
            print(f"  NEW BEST: {sc.crib_score}/24 [{s5_count}/{3628800*3}] — {cfg}")
            if sc.crib_score >= 10:
                print(f"    PT: {pt}")
        if sc.crib_score >= 8:
            results.append({
                'sweep': 'w10_palimpsest', 'config': f"PALIMPSEST/{vname}",
                'order': list(order), 'score': sc.crib_score,
                'pt_snippet': pt[:60],
            })
    # Progress every 500K orderings
    if (s5_count % 1500000) == 0:
        elapsed = time.time() - t0
        rate = s5_count / elapsed if elapsed > 0 else 0
        print(f"  ... {s5_count}/{3628800*3} ({100*s5_count/(3628800*3):.1f}%), {rate:.0f}/s, best {s5_best}/24")

elapsed = time.time() - t0
print(f"  Sweep 5: {s5_count} configs in {elapsed:.1f}s, best {s5_best}/24")

# ══════════════════════════════════════════════════════════════════════
# SWEEP 6: Width-10 exhaustive × ABSCISSA (another K3 keyword)
# ══════════════════════════════════════════════════════════════════════
print("\n--- Sweep 6: Width-10 exhaustive × ABSCISSA ---")
s6_count = 0
s6_best = 0

abscissa_key = [ALPH_IDX[c] for c in 'ABSCISSA']

for order in itertools.permutations(range(10)):
    untrans = columnar_decrypt(CT, 10, list(order))
    for vname, vfunc in VFUNCS:
        pt = vfunc(untrans, abscissa_key)
        sc = score_candidate(pt)
        s6_count += 1
        total += 1
        if sc.crib_score > s6_best:
            s6_best = sc.crib_score
            cfg = f"w10-exhaustive/ABSCISSA/{vname}/order={list(order)}"
            if s6_best > best_score:
                best_score = s6_best
                best_config = cfg
            print(f"  NEW BEST: {sc.crib_score}/24 [{s6_count}/{3628800*3}] — {cfg}")
            if sc.crib_score >= 10:
                print(f"    PT: {pt}")
    if (s6_count % 1500000) == 0:
        elapsed = time.time() - t0
        rate = total / elapsed if elapsed > 0 else 0
        print(f"  ... {s6_count}/{3628800*3} ({100*s6_count/(3628800*3):.1f}%), best {s6_best}/24")

elapsed = time.time() - t0
print(f"  Sweep 6: {s6_count} configs in {elapsed:.1f}s, best {s6_best}/24")

# ══════════════════════════════════════════════════════════════════════
# SWEEP 7: Width-10 exhaustive × KRYPTOS key
# ══════════════════════════════════════════════════════════════════════
print("\n--- Sweep 7: Width-10 exhaustive × KRYPTOS ---")
s7_count = 0
s7_best = 0

kryptos_key = [ALPH_IDX[c] for c in 'KRYPTOS']

for order in itertools.permutations(range(10)):
    untrans = columnar_decrypt(CT, 10, list(order))
    for vname, vfunc in VFUNCS:
        pt = vfunc(untrans, kryptos_key)
        sc = score_candidate(pt)
        s7_count += 1
        total += 1
        if sc.crib_score > s7_best:
            s7_best = sc.crib_score
            cfg = f"w10-exhaustive/KRYPTOS/{vname}/order={list(order)}"
            if s7_best > best_score:
                best_score = s7_best
                best_config = cfg
            print(f"  NEW BEST: {sc.crib_score}/24 [{s7_count}/{3628800*3}] — {cfg}")
            if sc.crib_score >= 10:
                print(f"    PT: {pt}")
    if (s7_count % 1500000) == 0:
        elapsed = time.time() - t0
        rate = total / elapsed if elapsed > 0 else 0
        print(f"  ... {s7_count}/{3628800*3} ({100*s7_count/(3628800*3):.1f}%), best {s7_best}/24")

elapsed = time.time() - t0
print(f"  Sweep 7: {s7_count} configs in {elapsed:.1f}s, best {s7_best}/24")

# ══════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print(f"TOTAL: {total} configurations tested in {time.time()-t0:.1f}s")
print(f"GLOBAL BEST: {best_score}/24")
if best_config:
    print(f"BEST CONFIG: {best_config}")
print(f"Results above noise: {len(results)}")
if best_score <= 9:
    print("CLASSIFICATION: NOISE")
elif best_score <= 17:
    print("CLASSIFICATION: STORE")
else:
    print("CLASSIFICATION: SIGNAL — INVESTIGATE!")
print("=" * 70)

os.makedirs('results', exist_ok=True)
with open('results/e_roman_02_exhaustive.json', 'w') as f:
    json.dump({
        'experiment': 'E-ROMAN-02',
        'description': 'Exhaustive transposition + Roman numeral keys',
        'total_configs': total,
        'best_score': best_score,
        'best_config': best_config,
        'classification': 'NOISE' if best_score <= 9 else 'STORE' if best_score <= 17 else 'SIGNAL',
        'above_noise': results,
        'sweep_bests': {
            'w8_dates': s1_best, 'w8_keywords': s2_best,
            'w6_all': s3_best, 'w10_keywords': s4_best,
            'w10_palimpsest': s5_best, 'w10_abscissa': s6_best,
            'w10_kryptos': s7_best,
        },
    }, f, indent=2)
print(f"\nArtifact: results/e_roman_02_exhaustive.json")
