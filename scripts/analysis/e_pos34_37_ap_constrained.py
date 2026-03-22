#!/usr/bin/env python3
"""AP-Constrained Position 34-37 Extension: extend keystream with filters.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   ~234 (9 AP-constrained × 26) + restricted alphabet filter
Last run:   2026-03-21
Best score: TBD

Extends the pos34_35 brute force to position 37 (position 36 is a consensus
null). Uses AP enrichment (≥8/15) to filter pos34_35 candidates, then
extends to position 37 with scoring against:
- Restricted alphabet (must use only the 12 observed values)
- Row clustering continuation
- AP maintenance
- IC of extended keystream
- English quadgram scoring for plaintext extension
"""
import sys, os, json, statistics
from collections import Counter
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

KA = KRYPTOS_ALPHABET
KA_IDX = {ch: i for i, ch in enumerate(KA)}

def az(ch): return ALPH_IDX[ch]
def az_chr(v): return ALPH[v % 26]
def ka_row(ch): return KA_IDX[ch] // 5
def ka_col(ch): return KA_IDX[ch] % 5

def beaufort_key(ct_ch, pt_ch):
    return (az(ct_ch) + az(pt_ch)) % 26

def beaufort_decrypt(ct_ch, key_val):
    """Decrypt: PT = (K - C) mod 26."""
    return (key_val - az(ct_ch)) % 26

def ic(values):
    n = len(values)
    if n < 2: return 0.0
    counts = Counter(values)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))

# ── Known keystream ─────────────────────────────────────────────────────
ENE_KS = [beaufort_key(c, p) for c, p in zip(CT[21:34], "EASTNORTHEAST")]
BCL_KS = [beaufort_key(c, p) for c, p in zip(CT[63:74], "BERLINCLOCK")]
FULL_KS = ENE_KS + BCL_KS  # 24 values

# Restricted alphabet: the 12 AZ values that appear in the known keystream
RESTRICTED_AZ = set(FULL_KS)  # {1,2,3,4,6,9,10,11,14,17,19,20}

# AP set
AP_AZ = {6, 10, 14}  # G, K, O

# Consensus nulls (position 36 is null, 37 is cipher)
CONSENSUS_NULLS = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}

# ── Load quadgram data ──────────────────────────────────────────────────
quadgram_file = os.path.join(_ROOT, "data", "english_quadgrams.json")
QUADGRAMS = {}
if os.path.exists(quadgram_file):
    with open(quadgram_file) as f:
        QUADGRAMS = json.load(f)
    print(f"Loaded {len(QUADGRAMS):,} quadgrams")
else:
    print("WARNING: No quadgram data found")

def quadgram_score(text):
    """Score text using quadgram log-probabilities."""
    if not QUADGRAMS or len(text) < 4:
        return -10.0
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, -10.0)
        count += 1
    return total / count if count > 0 else -10.0

# ── Phase 1: Find AP-constrained candidates for positions 34-35 ─────────

print("=" * 78)
print("PHASE 1: AP-Constrained Position 34-35 Candidates")
print("=" * 78)

CT34_val = az(CT[34])
CT35_val = az(CT[35])
CT37_val = az(CT[37])

print(f"CT[34] = {CT[34]} (AZ={CT34_val})")
print(f"CT[35] = {CT[35]} (AZ={CT35_val})")
print(f"CT[36] = {CT[36]} (NULL — consensus)")
print(f"CT[37] = {CT[37]} (AZ={CT37_val})")

ap_candidates = []

for pt34 in range(26):
    for pt35 in range(26):
        k34 = (CT34_val + pt34) % 26
        k35 = (CT35_val + pt35) % 26
        ks15 = ENE_KS + [k34, k35]

        # Count AP in 15-value keystream
        ap_count = sum(1 for v in ks15 if v in AP_AZ)
        if ap_count >= 8:
            # Also check row clustering
            letters = [az_chr(v) for v in ks15]
            rows = [ka_row(ch) for ch in letters]
            row_pairs = sum(1 for i in range(14) if rows[i] == rows[i+1])

            # Check restricted alphabet compliance
            restricted_ok = k34 in RESTRICTED_AZ and k35 in RESTRICTED_AZ

            ap_candidates.append({
                'pt34': az_chr(pt34), 'pt35': az_chr(pt35),
                'k34': k34, 'k35': k35,
                'k34_ch': az_chr(k34), 'k35_ch': az_chr(k35),
                'ap': ap_count,
                'row_pairs': row_pairs,
                'restricted_ok': restricted_ok,
                'ks15': ks15,
            })

print(f"\nAP ≥ 8/15 candidates: {len(ap_candidates)}/676")

# Sort by AP then row_pairs
ap_candidates.sort(key=lambda x: (-x['ap'], -x['row_pairs']))

for c in ap_candidates:
    ks_str = ''.join(az_chr(v) for v in c['ks15'])
    restr = "✓" if c['restricted_ok'] else "✗"
    print(f"  PT={c['pt34']}{c['pt35']} K={c['k34_ch']}{c['k35_ch']} "
          f"AP={c['ap']}/15 RowP={c['row_pairs']}/14 "
          f"Restricted={restr} KS={ks_str}")

# ── Phase 2: Extend to position 37 ─────────────────────────────────────

print(f"\n{'='*78}")
print("PHASE 2: Extend to Position 37 (pos 36 = null, skipped)")
print("=" * 78)

results = []

for cand in ap_candidates:
    for pt37 in range(26):
        k37 = (CT37_val + pt37) % 26

        # Extended keystream: ENE(13) + k34 + k35 + k37 = 16 values
        # (pos 36 is null, no key value)
        ks16 = cand['ks15'] + [k37]

        # Full extended: 16 + BCL(11) = 27 values
        ks27 = ks16 + BCL_KS

        letters16 = [az_chr(v) for v in ks16]
        rows16 = [ka_row(ch) for ch in letters16]
        cols16 = [ka_col(ch) for ch in letters16]

        # ── Scoring ──

        # 1. Restricted alphabet: k37 must be in the 12-value set
        k37_restricted = k37 in RESTRICTED_AZ
        all_restricted = cand['restricted_ok'] and k37_restricted

        # 2. Row clustering in 16-value window
        row_pairs = sum(1 for i in range(15) if rows16[i] == rows16[i+1])

        # 3. AP count in 16
        ap16 = sum(1 for v in ks16 if v in AP_AZ)

        # 4. IC of full 27
        ic27 = ic(ks27)

        # 5. Distinct values in 27
        distinct27 = len(set(ks27))

        # 6. Column-0 (Bean mod-5) count
        col0_16 = sum(1 for c in cols16 if c == 0)

        # 7. Row continuation from k35 to k37
        # (k35 row → k37 row: same row = continuation)
        k35_row = ka_row(az_chr(cand['k35']))
        k37_row = ka_row(az_chr(k37))
        cont_r = 1 if k35_row == k37_row else 0

        # 8. Quadgram score for plaintext extension
        # After EASTNORTHEAST (pos 21-33), pos 34-35-[36=null]-37
        pt_extension = f"EASTNORTHEAST{cand['pt34']}{cand['pt35']}{az_chr(pt37)}"
        qg_score = quadgram_score(pt_extension)

        # 9. Value reuse (k37 already in the 24-value set)
        k37_reuse = 1 if k37 in set(FULL_KS) else 0

        # ── Composite ──
        composite = (
            row_pairs * 4.0 +
            ap16 * 2.5 +
            col0_16 * 2.0 +
            ic27 * 50.0 +
            (26 - distinct27) * 1.0 +
            (3.0 if all_restricted else 0.0) +
            k37_reuse * 2.0 +
            cont_r * 1.5 +
            qg_score * -1.0 +  # More negative = worse English → subtract
            (2.0 if k37_restricted else 0.0)
        )

        results.append({
            'pt34': cand['pt34'], 'pt35': cand['pt35'], 'pt37': az_chr(pt37),
            'k34': cand['k34_ch'], 'k35': cand['k35_ch'], 'k37': az_chr(k37),
            'k34v': cand['k34'], 'k35v': cand['k35'], 'k37v': k37,
            'ap16': ap16, 'row_pairs': row_pairs, 'col0': col0_16,
            'ic27': ic27, 'distinct27': distinct27,
            'all_restricted': all_restricted, 'k37_restricted': k37_restricted,
            'cont_r': cont_r, 'k37_reuse': k37_reuse,
            'qg_score': qg_score, 'composite': composite,
            'ks16': ''.join(az_chr(v) for v in ks16),
            'ks27': ''.join(az_chr(v) for v in ks27),
            'pt_ext': f"{cand['pt34']}{cand['pt35']}_{az_chr(pt37)}",
        })

results.sort(key=lambda r: -r['composite'])

print(f"\nTotal combinations: {len(results)}")
print(f"Restricted alphabet compliant: {sum(1 for r in results if r['all_restricted'])}")

# ── Display top results ─────────────────────────────────────────────────

print(f"\n{'='*78}")
print("TOP 40 CANDIDATES")
print("=" * 78)

print(f"{'Rk':>3} {'PT':>5} {'Key':>5} {'KS16':>18} "
      f"{'RowP':>4} {'AP':>3} {'C0':>3} {'IC27':>6} {'Dst':>3} "
      f"{'Rst':>3} {'QG':>6} {'Score':>7}")
print("-" * 90)

for i, r in enumerate(results[:40]):
    rst = "✓" if r['all_restricted'] else "✗"
    print(f"{i+1:3d} {r['pt34']}{r['pt35']}{r['pt37']:>3} "
          f"{r['k34']}{r['k35']}{r['k37']:>3} "
          f"{r['ks16']:>18} "
          f"{r['row_pairs']:4d} {r['ap16']:3d} {r['col0']:3d} "
          f"{r['ic27']:6.4f} {r['distinct27']:3d} "
          f"{rst:>3} {r['qg_score']:6.2f} {r['composite']:7.1f}")

# ── Restricted alphabet analysis ────────────────────────────────────────

print(f"\n{'='*78}")
print("RESTRICTED ALPHABET COMPLIANT — TOP 20")
print("=" * 78)

restricted_results = [r for r in results if r['all_restricted']]
restricted_results.sort(key=lambda r: -r['composite'])

print(f"Total compliant: {len(restricted_results)}/{len(results)}")
print(f"Expected by chance: {len(ap_candidates)} × (12/26) = {len(ap_candidates)*12/26:.0f}")
print()

for i, r in enumerate(restricted_results[:20]):
    print(f"  {i+1:3d} PT={r['pt34']}{r['pt35']}_{r['pt37']} "
          f"K={r['k34']}{r['k35']}{r['k37']} "
          f"KS={r['ks16']} "
          f"AP={r['ap16']} RowP={r['row_pairs']} IC={r['ic27']:.4f} "
          f"QG={r['qg_score']:.2f} Score={r['composite']:.1f}")

# ── English plaintext analysis ──────────────────────────────────────────

print(f"\n{'='*78}")
print("ENGLISH PLAINTEXT ANALYSIS — BEST QUADGRAM SCORES")
print("=" * 78)

# Best quadgram scores overall
qg_sorted = sorted(results, key=lambda r: r['qg_score'], reverse=True)
print("\nTop 20 by English quadgram score:")
for i, r in enumerate(qg_sorted[:20]):
    rst = "✓" if r['all_restricted'] else " "
    # Construct full context
    pt_context = f"...EASTNORTHEAST{r['pt34']}{r['pt35']}?{r['pt37']}..."
    print(f"  {i+1:3d} {pt_context:40s} {rst} QG={r['qg_score']:.3f} "
          f"K={r['k34']}{r['k35']}{r['k37']} Score={r['composite']:.1f}")

# ── Deep analysis of top 10 ────────────────────────────────────────────

print(f"\n{'='*78}")
print("DEEP ANALYSIS — TOP 10")
print("=" * 78)

for i, r in enumerate(results[:10]):
    print(f"\n── #{i+1}: PT=...T{r['pt34']}{r['pt35']}[null]{r['pt37']}... "
          f"→ Key={r['k34']}{r['k35']}[skip]{r['k37']} ──")
    print(f"  Keystream (16): {r['ks16']}")
    print(f"  Keystream (27): {r['ks27']}")
    print(f"  AP: {r['ap16']}/16 ({r['ap16']/16:.0%})")
    print(f"  Row pairs: {r['row_pairs']}/15 ({r['row_pairs']/15:.0%})")
    print(f"  Col-0: {r['col0']}/16 ({r['col0']/16:.0%})")
    print(f"  IC(27): {r['ic27']:.4f}")
    print(f"  Distinct(27): {r['distinct27']}")
    print(f"  Restricted: {'ALL ✓' if r['all_restricted'] else '✗ (k37 new)' if not r['k37_restricted'] else '✗ (k34/35 new)'}")
    print(f"  Quadgram: {r['qg_score']:.3f}")

    # Check row pattern
    letters = [az_chr(v) for v in [r['k34v'], r['k35v'], r['k37v']]]
    rows = [ka_row(ch) for ch in letters]
    cols = [ka_col(ch) for ch in letters]
    print(f"  New key positions: {letters} → rows {rows}, cols {cols}")

# ── Save results ────────────────────────────────────────────────────────
outfile = os.path.join(_ROOT, "results", "e_pos34_37_ap_constrained.json")
os.makedirs(os.path.dirname(outfile), exist_ok=True)

output = {
    "experiment": "e_pos34_37_ap_constrained",
    "timestamp": datetime.now().isoformat(),
    "description": "AP-constrained pos 34-37 extension (pos 36 = null)",
    "ap_candidates_34_35": len(ap_candidates),
    "total_combinations": len(results),
    "restricted_compliant": len(restricted_results),
    "top_20": [
        {
            "rank": i + 1,
            "pt": f"{r['pt34']}{r['pt35']}_{r['pt37']}",
            "key": f"{r['k34']}{r['k35']}{r['k37']}",
            "ks16": r['ks16'], "ks27": r['ks27'],
            "ap16": r['ap16'], "row_pairs": r['row_pairs'],
            "ic27": r['ic27'], "distinct27": r['distinct27'],
            "all_restricted": r['all_restricted'],
            "qg_score": r['qg_score'], "composite": r['composite'],
        }
        for i, r in enumerate(results[:20])
    ],
    "restricted_top_10": [
        {
            "pt": f"{r['pt34']}{r['pt35']}_{r['pt37']}",
            "key": f"{r['k34']}{r['k35']}{r['k37']}",
            "composite": r['composite'],
        }
        for r in restricted_results[:10]
    ],
}

with open(outfile, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to {outfile}")
