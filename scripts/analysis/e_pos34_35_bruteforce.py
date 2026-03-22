#!/usr/bin/env python3
"""Brute-force PT[34]-PT[35]: score 676 extended keystreams.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   676 (26 × 26)
Last run:   2026-03-21
Best score: TBD

For each of 26×26 possible plaintext values at CT97 positions 34 and 35,
compute the Beaufort A=0 keystream extension and score against confirmed
properties: row clustering, AP enrichment, column-0 (Bean mod-5),
keystream IC, and English language priors.
"""
import sys, os, statistics, json
from collections import Counter
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ── Helpers ──────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {ch: i for i, ch in enumerate(KA)}

def az(ch):
    """Letter → AZ index (A=0)."""
    return ALPH_IDX[ch]

def az_chr(v):
    """AZ index → letter."""
    return ALPH[v % 26]

def ka(ch):
    """Letter → KA index."""
    return KA_IDX[ch]

def ka_row(ch):
    return ka(ch) // 5

def ka_col(ch):
    return ka(ch) % 5

def beaufort_key(ct_ch, pt_ch):
    """Beaufort A=0: K = (C + P) mod 26."""
    return (az(ct_ch) + az(pt_ch)) % 26

def ic(values):
    """Index of coincidence for a list of integer values."""
    n = len(values)
    if n < 2:
        return 0.0
    counts = Counter(values)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))

# ── Known keystreams ─────────────────────────────────────────────────────

ENE_PT = "EASTNORTHEAST"
ENE_CT = CT[21:34]
ENE_KS = [beaufort_key(c, p) for c, p in zip(ENE_CT, ENE_PT)]  # 13 values

BCL_PT = "BERLINCLOCK"
BCL_CT = CT[63:74]
BCL_KS = [beaufort_key(c, p) for c, p in zip(BCL_CT, BCL_PT)]  # 11 values

FULL_KS = ENE_KS + BCL_KS  # 24 values

# Null palette in AZ values
NULL_PALETTE_AZ = {az(ch) for ch in "BGIKOWZ"}

# AP set (G=6, K=10, O=14 in AZ)
AP_AZ = {az('G'), az('K'), az('O')}

# ── Baseline statistics ──────────────────────────────────────────────────

def ks_stats(values):
    """Comprehensive keystream statistics."""
    n = len(values)
    letters = [az_chr(v) for v in values]
    rows = [ka_row(ch) for ch in letters]
    cols = [ka_col(ch) for ch in letters]
    ka_vals = [ka(ch) for ch in letters]

    row_pairs = sum(1 for i in range(n - 1) if rows[i] == rows[i + 1])
    col_pairs = sum(1 for i in range(n - 1) if cols[i] == cols[i + 1])
    ap_count = sum(1 for v in values if v in AP_AZ)
    col0_count = sum(1 for c in cols if c == 0)
    distinct = len(set(values))
    ic_val = ic(values)
    # Values in null palette
    null_pal_count = sum(1 for v in values if v in NULL_PALETTE_AZ)

    return {
        'row_pairs': row_pairs,
        'max_pairs': n - 1,
        'col_pairs': col_pairs,
        'ap_count': ap_count,
        'col0_count': col0_count,
        'distinct': distinct,
        'ic': ic_val,
        'null_pal': null_pal_count,
        'rows': rows,
        'cols': cols,
        'ka_vals': ka_vals,
    }


# ── Display baselines ───────────────────────────────────────────────────

print("=" * 78)
print("K4 Position 34-35 Brute Force: 676 Keystream Extensions")
print("=" * 78)

ene_str = ''.join(az_chr(v) for v in ENE_KS)
bcl_str = ''.join(az_chr(v) for v in BCL_KS)
full_str = ''.join(az_chr(v) for v in FULL_KS)

print(f"\nENE keystream (13): {ene_str}")
print(f"BCL keystream (11): {bcl_str}")
print(f"Full keystream (24): {full_str}")

base13 = ks_stats(ENE_KS)
base24 = ks_stats(FULL_KS)

print(f"\n── Baseline: ENE (13 values) ──")
print(f"  Row-same pairs: {base13['row_pairs']}/{base13['max_pairs']}"
      f" ({base13['row_pairs']/base13['max_pairs']:.0%})")
print(f"  AP count:  {base13['ap_count']}/13 ({base13['ap_count']/13:.0%})")
print(f"  Col-0:     {base13['col0_count']}/13 ({base13['col0_count']/13:.0%})")
print(f"  IC:        {base13['ic']:.4f}")
print(f"  Distinct:  {base13['distinct']}")
print(f"  Rows:      {base13['rows']}")

print(f"\n── Baseline: Full 24 values ──")
print(f"  Row-same pairs: {base24['row_pairs']}/{base24['max_pairs']}"
      f" ({base24['row_pairs']/base24['max_pairs']:.0%})")
print(f"  AP count:  {base24['ap_count']}/24 ({base24['ap_count']/24:.0%})")
print(f"  Col-0:     {base24['col0_count']}/24 ({base24['col0_count']/24:.0%})")
print(f"  IC:        {base24['ic']:.4f}")
print(f"  Distinct:  {base24['distinct']}")

# ── English trigram priors (T + PT34 + PT35) ─────────────────────────────
# Top English trigrams starting with T (from quadgram data / frequency tables)
# Ranked by frequency in English text
T_TRIGRAMS = {
    "THE": 10, "THA": 8, "TIO": 7, "TIN": 6, "TER": 6,
    "TED": 5, "TIS": 5, "TAT": 4, "TON": 4, "TEN": 4,
    "TAN": 4, "TOR": 4, "TIC": 3, "TIV": 3, "TOO": 3,
    "TWO": 3, "TIM": 3, "TRE": 3, "TRA": 3, "TRI": 3,
    "TUR": 3, "TES": 3, "TLE": 3, "TRO": 2, "TRU": 2,
}

# ── Brute force ──────────────────────────────────────────────────────────

CT34_val = az(CT[34])  # O = 14
CT35_val = az(CT[35])  # T = 19

print(f"\nCT[34] = {CT[34]} (AZ={CT34_val})")
print(f"CT[35] = {CT[35]} (AZ={CT35_val})")
print(f"\nScoring 676 (PT34, PT35) combinations...\n")

results = []

for pt34 in range(26):
    for pt35 in range(26):
        k34 = (CT34_val + pt34) % 26
        k35 = (CT35_val + pt35) % 26

        # Extended ENE keystream (15 values)
        ks15 = ENE_KS + [k34, k35]

        # Full extended keystream (26 values: 15 ENE + 11 BCL)
        ks26 = ks15 + BCL_KS

        s15 = ks_stats(ks15)
        s26 = ks_stats(ks26)

        # ── Scoring criteria ──

        # 1. Row clustering in 15-value window (baseline: 6/12 = 50%)
        row_score = s15['row_pairs']

        # 2. AP enrichment in 15 (baseline: 5/13 = 38%, full 24: 12/24 = 50%)
        ap_score = s15['ap_count']

        # 3. Column-0 (Bean mod-5) in 15 (baseline: 6/13 = 46%, full: ~54%)
        col0_score = s15['col0_count']

        # 4. IC of full 26-value keystream (baseline 24: 0.0797)
        ic_26 = s26['ic']

        # 5. Distinct values in 26-value keystream (baseline 24: 12 distinct)
        distinct_26 = s26['distinct']

        # 6. New values already present in the 24-value set?
        k34_in_full = k34 in FULL_KS
        k35_in_full = k35 in FULL_KS
        reuse_score = (1 if k34_in_full else 0) + (1 if k35_in_full else 0)

        # 7. Cross-crib: new values match BCL keystream values?
        bcl_set = set(BCL_KS)
        bcl_match = (1 if k34 in bcl_set else 0) + (1 if k35 in bcl_set else 0)

        # 8. English trigram prior (T + pt34 + pt35)
        trigram = "T" + az_chr(pt34) + az_chr(pt35)
        lang_score = T_TRIGRAMS.get(trigram, 0)

        # 9. Row continuation from last ENE value (L = row 3)
        last_row = ka_row(az_chr(ENE_KS[-1]))  # L → row 3
        cont_r = (1 if ka_row(az_chr(k34)) == last_row else 0)

        # 10. New pair clusters (same row as each other)
        pair_cluster = 1 if ka_row(az_chr(k34)) == ka_row(az_chr(k35)) else 0

        # ── Composite score ──
        # Weight by confidence in each property
        composite = (
            row_score * 4.0 +        # row clustering: strongest confirmed signal
            ap_score * 2.5 +          # AP enrichment: confirmed
            col0_score * 2.5 +        # Bean mod-5: confirmed
            ic_26 * 50.0 +            # IC: want high (baseline 0.08 → ~4 pts)
            (26 - distinct_26) * 1.0 + # fewer distinct: consistent with structure
            reuse_score * 2.0 +       # value reuse: consistent with low distinct
            bcl_match * 1.5 +         # cross-crib key reuse
            lang_score * 0.5 +        # English prior (weak weight)
            cont_r * 2.0 +            # continues last row cluster
            pair_cluster * 1.0        # new pair clusters together
        )

        # K2 digit check: do the KA values of k34, k35 relate to K2 numbers?
        ka_k34 = ka(az_chr(k34))
        ka_k35 = ka(az_chr(k35))
        k2_note = ""
        k2_pairs = [(3, 8), (5, 7), (7, 7), (8, 4), (4, 4)]
        for a, b in k2_pairs:
            if ka_k34 % 10 == a and ka_k35 % 10 == b:
                k2_note = f"K2({a}{b})"
            elif ka_k34 == a and ka_k35 == b:
                k2_note = f"K2={a},{b}"

        results.append({
            'pt34': az_chr(pt34), 'pt35': az_chr(pt35),
            'k34': az_chr(k34), 'k35': az_chr(k35),
            'k34v': k34, 'k35v': k35,
            'ks15': ''.join(az_chr(v) for v in ks15),
            'ks26': ''.join(az_chr(v) for v in ks26),
            'row_pairs': row_score, 'ap': ap_score, 'col0': col0_score,
            'ic26': ic_26, 'distinct26': distinct_26,
            'reuse': reuse_score, 'bcl_match': bcl_match,
            'lang': lang_score, 'trigram': trigram,
            'cont_r': cont_r, 'pair_cl': pair_cluster,
            'composite': composite, 'k2_note': k2_note,
            'rows15': s15['rows'], 'ka_vals': s15['ka_vals'],
        })

# ── Sort and display ─────────────────────────────────────────────────────

results.sort(key=lambda r: r['composite'], reverse=True)

print(f"{'Rk':>3} {'PT':>3} {'Key':>4} {'Extended KS (15)':>17} "
      f"{'RowP':>4} {'AP':>3} {'C0':>3} {'IC26':>6} {'Dst':>3} "
      f"{'Reu':>3} {'BCL':>3} {'TXX':>4} {'Lng':>3} {'CR':>3} {'PC':>3} "
      f"{'Score':>6} {'Note':>8}")
print("-" * 105)

for i, r in enumerate(results[:40]):
    print(f"{i+1:3d} {r['pt34']}{r['pt35']:>2} {r['k34']}{r['k35']:>3} "
          f"{r['ks15']:>17} "
          f"{r['row_pairs']:4d} {r['ap']:3d} {r['col0']:3d} {r['ic26']:6.4f} "
          f"{r['distinct26']:3d} {r['reuse']:3d} {r['bcl_match']:3d} "
          f"{r['trigram']:>4} {r['lang']:3d} {r['cont_r']:3d} {r['pair_cl']:3d} "
          f"{r['composite']:6.1f} {r['k2_note']:>8}")

# ── Statistical summary ─────────────────────────────────────────────────

print(f"\n{'='*78}")
print("STATISTICAL SUMMARY")
print(f"{'='*78}")

scores = [r['composite'] for r in results]
print(f"\nComposite: min={min(scores):.1f}, max={max(scores):.1f}, "
      f"mean={statistics.mean(scores):.1f}, stdev={statistics.stdev(scores):.1f}")

# Separation analysis: how far is #1 from the pack?
gap = scores[0] - scores[1]  # already sorted descending
print(f"Gap between #1 and #2: {gap:.1f}")
print(f"Gap between #1 and mean: {scores[0] - statistics.mean(scores):.1f} "
      f"({(scores[0] - statistics.mean(scores))/statistics.stdev(scores):.1f}σ)")

# Distribution of key criteria
high_row = sum(1 for r in results if r['row_pairs'] >= 7)
high_ap = sum(1 for r in results if r['ap'] >= 8)
high_col0 = sum(1 for r in results if r['col0'] >= 8)
high_ic = sum(1 for r in results if r['ic26'] >= 0.08)

print(f"\nCriteria distributions (out of 676):")
print(f"  Row pairs ≥ 7/14:    {high_row:3d} ({high_row/676:.1%})")
print(f"  AP ≥ 8/15 (53%):     {high_ap:3d} ({high_ap/676:.1%})")
print(f"  Col-0 ≥ 8/15 (53%):  {high_col0:3d} ({high_col0/676:.1%})")
print(f"  IC(26) ≥ 0.08:       {high_ic:3d} ({high_ic/676:.1%})")

# Elite candidates: high on ALL criteria
elite = [r for r in results
         if r['row_pairs'] >= 7 and r['ap'] >= 7 and r['col0'] >= 7
         and r['ic26'] >= 0.07]

print(f"\nELITE (row≥7 AND AP≥7 AND col0≥7 AND IC≥0.07): {len(elite)}/676")
for r in elite:
    print(f"  PT={r['pt34']}{r['pt35']} → K={r['k34']}{r['k35']} "
          f"KS={r['ks15']} row={r['row_pairs']} AP={r['ap']} "
          f"col0={r['col0']} IC={r['ic26']:.4f}")

# ── Deep analysis of top 10 ─────────────────────────────────────────────

print(f"\n{'='*78}")
print("DEEP ANALYSIS — TOP 10 CANDIDATES")
print(f"{'='*78}")

for i, r in enumerate(results[:10]):
    print(f"\n── #{i+1}: PT[34]={r['pt34']} PT[35]={r['pt35']} "
          f"→ Key[34]={r['k34']} Key[35]={r['k35']} ──")
    print(f"  Keystream (15): {r['ks15']}")
    print(f"  Keystream (26): {r['ks26']}")
    print(f"  KA values:      {r['ka_vals']}")
    print(f"  Polybius rows:  {r['rows15']}")

    # Plaintext context
    msg = f"EASTNORTHEAST{r['pt34']}{r['pt35']}"
    print(f"  Plaintext:      ...{msg}...[null]...")

    # Check for patterns in KA values
    ka_v = r['ka_vals']
    diffs = [ka_v[j + 1] - ka_v[j] for j in range(len(ka_v) - 1)]
    print(f"  KA diffs:       {diffs}")

    # Check for row periodicity
    row_seq = ''.join(str(x) for x in r['rows15'])
    for p in range(2, 8):
        chunk = row_seq[:p]
        reps = sum(1 for j in range(0, len(row_seq), p)
                   if row_seq[j:j + p] == chunk)
        if reps >= 3:
            print(f"  Row period-{p}: '{chunk}' × {reps}")

    # English context after EASTNORTHEAST
    if r['trigram'] in T_TRIGRAMS:
        print(f"  English trigram: {r['trigram']} (score {T_TRIGRAMS[r['trigram']]})")

    # Check if key values match any pattern with BCL keystream
    ks26_vals = [az(ch) for ch in r['ks26']]
    # Look for the new key values appearing at specific intervals
    for bpos, bval in enumerate(BCL_KS):
        if r['k34v'] == bval:
            ct73_offset = bpos + 15  # rough position in CT73
            print(f"  Key[34]={r['k34']} matches BCL position {bpos} "
                  f"(~CT73 offset {ct73_offset})")
        if r['k35v'] == bval:
            ct73_offset = bpos + 15
            print(f"  Key[35]={r['k35']} matches BCL position {bpos} "
                  f"(~CT73 offset {ct73_offset})")

# ── K2 coordinate analysis ──────────────────────────────────────────────

print(f"\n{'='*78}")
print("K2 COORDINATE ENCODING CHECK")
print(f"{'='*78}")

# The K2 progressive solve: K2 encodes 38→24, 77→14, 8→8
# K2 coordinate digits: 3,8,5,7,6,5 (latitude), 7,7,8,4,4 (longitude)
# Check if any candidate's KA values at positions 14-15 encode K2 digits

k2_lat = [3, 8, 5, 7, 6, 5]  # 38°57'6.5"
k2_lon = [7, 7, 8, 4, 4]     # 77°8'44"

k2_hits = []
for r in results:
    ka_k34 = ka(r['k34'])
    ka_k35 = ka(r['k35'])
    # Direct: KA values are K2 digits
    for label, digits in [("lat", k2_lat), ("lon", k2_lon)]:
        for offset in range(len(digits) - 1):
            if ka_k34 == digits[offset] and ka_k35 == digits[offset + 1]:
                k2_hits.append((r['pt34'], r['pt35'], r['k34'], r['k35'],
                                f"KA=K2_{label}[{offset}:{offset+2}]",
                                r['composite']))
    # Mod 10
    for label, digits in [("lat", k2_lat), ("lon", k2_lon)]:
        for offset in range(len(digits) - 1):
            if ka_k34 % 10 == digits[offset] and ka_k35 % 10 == digits[offset + 1]:
                if ka_k34 != digits[offset]:  # skip if already caught above
                    k2_hits.append((r['pt34'], r['pt35'], r['k34'], r['k35'],
                                    f"KA%10=K2_{label}[{offset}:{offset+2}]",
                                    r['composite']))

if k2_hits:
    print(f"\n{len(k2_hits)} candidates match K2 digit sequences:")
    for pt34, pt35, k34, k35, note, score in sorted(k2_hits, key=lambda x: -x[5]):
        print(f"  PT={pt34}{pt35} K={k34}{k35} {note} (composite={score:.1f})")
else:
    print("\nNo candidates match K2 digit sequences.")

# ── Value-reuse analysis ─────────────────────────────────────────────────

print(f"\n{'='*78}")
print("VALUE REUSE ANALYSIS")
print(f"{'='*78}")

print(f"\nFull 24-value keystream letter counts:")
full_counts = Counter(full_str)
for ch, cnt in sorted(full_counts.items(), key=lambda x: -x[1]):
    row = ka_row(ch)
    col = ka_col(ch)
    print(f"  {ch}: {cnt}× (KA row={row}, col={col})")

print(f"\nCandidates where BOTH new values already appear in the 24-value set:")
both_reuse = [r for r in results if r['reuse'] == 2]
both_reuse.sort(key=lambda r: -r['composite'])
for r in both_reuse[:20]:
    f24_count_k34 = full_counts.get(r['k34'], 0)
    f24_count_k35 = full_counts.get(r['k35'], 0)
    print(f"  PT={r['pt34']}{r['pt35']} → K={r['k34']}{r['k35']} "
          f"({r['k34']}:{f24_count_k34}×, {r['k35']}:{f24_count_k35}×) "
          f"composite={r['composite']:.1f}")

# ── Save results ─────────────────────────────────────────────────────────

outfile = os.path.join(_ROOT, "results", "e_pos34_35_bruteforce.json")
os.makedirs(os.path.dirname(outfile), exist_ok=True)

output = {
    "experiment": "e_pos34_35_bruteforce",
    "timestamp": datetime.now().isoformat(),
    "description": "Brute-force PT[34]-PT[35] under Beaufort A=0, "
                   "scoring extended keystream against confirmed properties",
    "ct_positions": [34, 35],
    "ct_values": [CT[34], CT[35]],
    "combinations": 676,
    "top_20": [
        {
            "rank": i + 1,
            "pt34": r['pt34'], "pt35": r['pt35'],
            "key34": r['k34'], "key35": r['k35'],
            "ks15": r['ks15'], "ks26": r['ks26'],
            "row_pairs": r['row_pairs'], "ap": r['ap'],
            "col0": r['col0'], "ic26": r['ic26'],
            "distinct26": r['distinct26'],
            "composite": r['composite'],
            "trigram": r['trigram'],
        }
        for i, r in enumerate(results[:20])
    ],
    "elite_count": len(elite),
    "elite": [
        {"pt": r['pt34'] + r['pt35'], "key": r['k34'] + r['k35'],
         "composite": r['composite']}
        for r in elite
    ],
    "score_stats": {
        "min": min(scores), "max": max(scores),
        "mean": statistics.mean(scores), "stdev": statistics.stdev(scores),
    },
}

with open(outfile, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to {outfile}")
