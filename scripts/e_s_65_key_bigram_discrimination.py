#!/usr/bin/env python3
"""
E-S-65: Key Bigram Discrimination for Width-7 Model B

NOVEL APPROACH: Under Model B (trans→sub) with width-7 columnar transposition
and a running key, consecutive rows within the same grid column map to
consecutive CT positions. The key values at these positions form BIGRAMS
from the running key text.

From the 24 crib characters, we can derive 10 key bigrams:
- ENE crib (rows 3-4): 6 bigrams (columns 0-5, each with rows 3&4)
- BC crib (rows 9-10): 4 bigrams (columns 0-3, each with rows 9&10)

If the key is from an English running text, these bigrams should score high
on English bigram frequencies. Wrong orderings produce pseudo-random bigrams.

This gives ~70 bits of discrimination across 5040 orderings — far more than
needed to identify the correct ordering IF the key is English.

Also tests:
- Gromark filter (all 24 key values must be digits 0-9)
- Unigram frequency scoring
- Both Vigenère and Beaufort variants
"""

import json
import math
import os
import sys
import time
from itertools import permutations

# ── Constants ──────────────────────────────────────────────────────────────
CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)  # 97

# Known plaintext (0-indexed)
CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

WIDTH = 7
NROWS = (N + WIDTH - 1) // WIDTH  # 14
# Column lengths: columns 0..(N%WIDTH-1) have NROWS chars, rest have NROWS-1
# 97 = 13*7 + 6, so columns 0-5 have 14 chars, column 6 has 13
COL_LENS = [NROWS if c < (N % WIDTH) else NROWS - 1 for c in range(WIDTH)]
# Verify: sum = 97
assert sum(COL_LENS) == N, f"Column lengths sum to {sum(COL_LENS)}, expected {N}"

print("=" * 70)
print("E-S-65: Key Bigram Discrimination for Width-7 Model B")
print("=" * 70)
print(f"CT length: {N}, Width: {WIDTH}, Rows: {NROWS}")
print(f"Column lengths: {COL_LENS}")

# ── Derive bigram log-probabilities from quadgram data ─────────────────────
print("\nLoading quadgram data and deriving bigram log-probs...")
with open("data/english_quadgrams.json") as f:
    qg_data = json.load(f)
if isinstance(qg_data, dict) and "logp" in qg_data:
    qg_data = qg_data["logp"]

# Build bigram log-probs by marginalizing quadgrams
# P(a,b) = sum_{c,d} P(a,b,c,d)
# In log space: log P(a,b) = logsumexp over all quadgrams starting with (a,b)
bigram_logp = {}
for qg, logp in qg_data.items():
    if len(qg) == 4:
        bg = qg[:2]
        if bg not in bigram_logp:
            bigram_logp[bg] = []
        bigram_logp[bg].append(logp)

# Compute logsumexp for each bigram
bg_scores = {}
for bg, logps in bigram_logp.items():
    max_lp = max(logps)
    lse = max_lp + math.log(sum(math.exp(lp - max_lp) for lp in logps))
    bg_scores[bg] = lse

# Normalize: find max for reference
all_bg_vals = list(bg_scores.values())
max_bg = max(all_bg_vals)
min_bg = min(all_bg_vals)
print(f"Bigram log-probs: {len(bg_scores)} bigrams, range [{min_bg:.3f}, {max_bg:.3f}]")

# Default for missing bigrams (floor)
BG_FLOOR = min_bg - 2.0

# English letter frequencies (log-prob)
ENG_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074,
}
ENG_LOG_FREQ = {c: math.log(f) for c, f in ENG_FREQ.items()}
UNIFORM_LOG = math.log(1/26)

# ── Identify crib positions in the grid ────────────────────────────────────
# PT position p → grid (row, col) = (p // WIDTH, p % WIDTH)
crib_grid = {}  # (row, col) → PT letter
for p, letter in CRIB_DICT.items():
    row, col = divmod(p, WIDTH)
    crib_grid[(row, col)] = letter

# Identify bigram pairs: consecutive rows in same column, both with crib values
bigram_pairs = []  # list of ((row1, col), (row2, col))
for col in range(WIDTH):
    rows_with_cribs = sorted(r for (r, c) in crib_grid if c == col)
    for i in range(len(rows_with_cribs) - 1):
        if rows_with_cribs[i+1] == rows_with_cribs[i] + 1:
            bigram_pairs.append(((rows_with_cribs[i], col), (rows_with_cribs[i+1], col)))

print(f"\nKey bigram pairs from cribs ({len(bigram_pairs)} bigrams):")
for (r1, c), (r2, _) in bigram_pairs:
    pt1 = crib_grid[(r1, c)]
    pt2 = crib_grid[(r2, c)]
    print(f"  Grid col {c}, rows {r1}-{r2}: PT=({pt1},{pt2})")

# Identify all crib positions for unigram scoring
crib_positions = []  # (row, col, pt_letter)
for (r, c), letter in sorted(crib_grid.items()):
    crib_positions.append((r, c, letter))
print(f"Total crib positions for unigram scoring: {len(crib_positions)}")

# ── Scoring function ──────────────────────────────────────────────────────
def score_ordering(order, variant='vig'):
    """
    For a given column ordering, compute:
    - Key bigram score (sum of English bigram log-probs)
    - Key unigram score (sum of English letter log-probs)
    - Gromark feasibility (all key values 0-9)
    - The 24 key values

    Model B: trans→sub
    CT[j] = sub(intermediate[j], key[j])
    intermediate[j] = PT[row*7 + grid_col] where j is in the block for grid_col

    For Vigenère: key[j] = (CT[j] - intermediate[j]) % 26
    For Beaufort: key[j] = (CT[j] + intermediate[j]) % 26
    """
    # Compute column start positions in CT
    starts = {}
    pos = 0
    for grid_col in order:
        starts[grid_col] = pos
        pos += COL_LENS[grid_col]

    # Compute key values at crib positions
    key_vals = {}  # (row, col) → key_value (0-25)
    key_chars = {}  # (row, col) → key_letter
    for row, col, pt_letter in crib_positions:
        ct_pos = starts[col] + row
        ct_val = CT_IDX[ct_pos]
        pt_val = IDX[pt_letter]
        if variant == 'vig':
            k = (ct_val - pt_val) % 26
        elif variant == 'beau':
            k = (ct_val + pt_val) % 26
        else:  # variant beaufort: K = (PT - CT)
            k = (pt_val - ct_val) % 26
        key_vals[(row, col)] = k
        key_chars[(row, col)] = AZ[k]

    # Bigram score
    bg_score = 0.0
    for (r1, c), (r2, _) in bigram_pairs:
        k1 = key_chars[(r1, c)]
        k2 = key_chars[(r2, c)]
        bg = k1 + k2
        bg_score += bg_scores.get(bg, BG_FLOOR)

    # Unigram score
    ug_score = 0.0
    for row, col, _ in crib_positions:
        kc = key_chars[(row, col)]
        ug_score += ENG_LOG_FREQ[kc]

    # Gromark check: all key values ≤ 9
    gromark_ok = all(v <= 9 for v in key_vals.values())

    # Extract key string at crib positions (sorted by CT position)
    key_at_cribs = []
    for row, col, _ in crib_positions:
        ct_pos = starts[col] + row
        key_at_cribs.append((ct_pos, key_chars[(row, col)]))
    key_at_cribs.sort()
    key_str = ''.join(c for _, c in key_at_cribs)

    return bg_score, ug_score, gromark_ok, key_str


# ── Main sweep ─────────────────────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 1: Sweep all 5040 orderings × 3 variants")
print("-" * 50)

results = []
gromark_candidates = []
t0 = time.time()

for order in permutations(range(WIDTH)):
    for variant in ('vig', 'beau', 'vbeau'):
        bg_score, ug_score, gromark_ok, key_str = score_ordering(order, variant)
        results.append({
            'order': list(order),
            'variant': variant,
            'bg_score': bg_score,
            'ug_score': ug_score,
            'gromark_ok': gromark_ok,
            'key_str': key_str,
            'combined': bg_score + ug_score,
        })
        if gromark_ok:
            gromark_candidates.append(results[-1])

elapsed = time.time() - t0
print(f"  Tested {len(results)} configs in {elapsed:.1f}s")
print(f"  Gromark candidates: {len(gromark_candidates)}")

# ── Sort and report ────────────────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 2: Top results by bigram score")
print("-" * 50)

results.sort(key=lambda x: x['bg_score'], reverse=True)

print("\nTop 30 by bigram score:")
print(f"{'Rank':>4} {'Order':>25} {'Var':>5} {'BG_Score':>10} {'UG_Score':>10} {'Combined':>10} {'Key@Cribs':>26}")
for i, r in enumerate(results[:30]):
    print(f"{i+1:4d} {str(r['order']):>25} {r['variant']:>5} {r['bg_score']:10.3f} {r['ug_score']:10.3f} {r['combined']:10.3f} {r['key_str']:>26}")

# Distribution statistics
all_bg = [r['bg_score'] for r in results]
mean_bg = sum(all_bg) / len(all_bg)
std_bg = (sum((x - mean_bg)**2 for x in all_bg) / len(all_bg)) ** 0.5
print(f"\nBigram score stats: mean={mean_bg:.3f}, std={std_bg:.3f}")
print(f"Top score: {all_bg[0]:.3f} (z={(all_bg[0] - mean_bg) / std_bg:.2f})")

# ── Check for separation ──────────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 3: Score separation analysis")
print("-" * 50)

# Check gap between #1 and #2, and between top group and rest
for n_top in [1, 5, 10, 20]:
    top_avg = sum(all_bg[:n_top]) / n_top
    rest_avg = sum(all_bg[n_top:]) / len(all_bg[n_top:])
    gap = top_avg - rest_avg
    print(f"  Top-{n_top} avg={top_avg:.3f}, rest avg={rest_avg:.3f}, gap={gap:.3f}")

# Per-variant analysis
print("\nBest per variant:")
for v in ('vig', 'beau', 'vbeau'):
    v_results = [r for r in results if r['variant'] == v]
    v_results.sort(key=lambda x: x['bg_score'], reverse=True)
    best = v_results[0]
    v_bg = [r['bg_score'] for r in v_results]
    v_mean = sum(v_bg) / len(v_bg)
    v_std = (sum((x - v_mean)**2 for x in v_bg) / len(v_bg)) ** 0.5
    z = (best['bg_score'] - v_mean) / v_std if v_std > 0 else 0
    print(f"  {v:>5}: best={best['bg_score']:.3f} order={best['order']} key={best['key_str']} z={z:.2f}")

# ── Unigram analysis ──────────────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 4: Top results by unigram score")
print("-" * 50)

results.sort(key=lambda x: x['ug_score'], reverse=True)
print("\nTop 15 by unigram score:")
print(f"{'Rank':>4} {'Order':>25} {'Var':>5} {'UG_Score':>10} {'BG_Score':>10} {'Key@Cribs':>26}")
for i, r in enumerate(results[:15]):
    print(f"{i+1:4d} {str(r['order']):>25} {r['variant']:>5} {r['ug_score']:10.3f} {r['bg_score']:10.3f} {r['key_str']:>26}")

# ── Combined score ────────────────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 5: Top results by combined (BG + UG) score")
print("-" * 50)

results.sort(key=lambda x: x['combined'], reverse=True)
print("\nTop 15 by combined score:")
print(f"{'Rank':>4} {'Order':>25} {'Var':>5} {'Combined':>10} {'BG_Score':>10} {'UG_Score':>10} {'Key@Cribs':>26}")
for i, r in enumerate(results[:15]):
    print(f"{i+1:4d} {str(r['order']):>25} {r['variant']:>5} {r['combined']:10.3f} {r['bg_score']:10.3f} {r['ug_score']:10.3f} {r['key_str']:>26}")

# ── Gromark analysis ──────────────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 6: Gromark (digit-only key) candidates")
print("-" * 50)
if gromark_candidates:
    print(f"  {len(gromark_candidates)} candidates found!")
    for gc in gromark_candidates[:20]:
        print(f"  order={gc['order']} var={gc['variant']} key={gc['key_str']}")
else:
    print("  No candidates — Gromark eliminated for all orderings")
    # Compute expected: P(all 24 ≤ 9) = (10/26)^24
    p_gromark = (10/26)**24
    print(f"  Expected: {p_gromark:.2e} × {len(results)} = {p_gromark * len(results):.4f} candidates")

# ── Phase 7: Running key test on top orderings ────────────────────────────
print("\n" + "-" * 50)
print("Phase 7: Running key test on top bigram orderings")
print("-" * 50)

# Load running key texts
rk_texts = {}
rk_dir = "reference/running_key_texts"
for fname in os.listdir(rk_dir):
    if fname.endswith('.txt'):
        with open(os.path.join(rk_dir, fname)) as f:
            text = ''.join(c.upper() for c in f.read() if c.upper() in AZ)
        rk_texts[fname] = text

# Also add Carter
with open("reference/carter_vol1_extract.txt") as f:
    carter = ''.join(c.upper() for c in f.read() if c.upper() in AZ)
rk_texts['carter_extract.txt'] = carter[:50000]  # Limit size

print(f"Running key texts: {len(rk_texts)}")
for name, text in rk_texts.items():
    print(f"  {name}: {len(text)} chars")

# Get top 50 orderings by bigram score (across all variants)
results.sort(key=lambda x: x['bg_score'], reverse=True)
top_orderings = []
seen = set()
for r in results:
    key = tuple(r['order'])
    if key not in seen:
        seen.add(key)
        top_orderings.append(r['order'])
    if len(top_orderings) >= 50:
        break

# For each top ordering × variant × text × offset: check crib matches
best_rk = {'cribs': 0}
configs_tested = 0

for order in top_orderings:
    # Build the transposition: CT_pos → PT_pos
    perm = [0] * N  # perm[ct_pos] = pt_pos
    pos = 0
    for grid_col in order:
        for row in range(COL_LENS[grid_col]):
            ct_pos = pos
            pt_pos = row * WIDTH + grid_col
            perm[ct_pos] = pt_pos
            pos += 1

    for variant in ('vig', 'beau'):
        for name, text in rk_texts.items():
            max_offset = len(text) - N
            if max_offset < 0:
                continue
            # Sample offsets (every 1 for short texts, every 10 for long)
            step = max(1, max_offset // 5000)
            for offset in range(0, max_offset, step):
                key_slice = text[offset:offset + N]
                # Apply cipher: CT[j] = sub(PT[perm[j]], key[j])
                # Check cribs: PT[p] should match CRIB_DICT[p]
                # Under Model B: intermediate[j] = PT[perm[j]]
                # CT[j] = (intermediate[j] + key_val[j]) % 26 for vig
                # So: PT[perm[j]] = (CT[j] - key_val[j]) % 26 for vig
                # And PT[perm[j]] = (key_val[j] - CT[j]) % 26 for beau

                cribs = 0
                for p, expected in CRIB_DICT.items():
                    # Find ct_pos j such that perm[j] = p
                    # Precompute inv_perm
                    pass  # We'll use inv_perm below

                break  # Placeholder — we need inv_perm

            break
        break
    break

# Rewrite with inv_perm for efficiency
print("\n  Testing running keys against top 50 orderings...")
t1 = time.time()
best_rk = {'cribs': 0, 'order': None, 'variant': None, 'text': None, 'offset': None}

for oi, order in enumerate(top_orderings):
    # Build inv_perm: pt_pos → ct_pos
    inv_perm = [0] * N
    pos = 0
    for grid_col in order:
        for row in range(COL_LENS[grid_col]):
            pt_pos = row * WIDTH + grid_col
            inv_perm[pt_pos] = pos
            pos += 1

    for variant in ('vig', 'beau'):
        for name, text in rk_texts.items():
            max_offset = len(text) - N
            if max_offset < 0:
                continue
            step = max(1, max_offset // 5000)
            for offset in range(0, max_offset, step):
                # key_vals[j] = IDX[text[offset + j]]
                cribs = 0
                for p, expected in CRIB_DICT.items():
                    j = inv_perm[p]
                    kv = IDX[text[offset + j]]
                    ct_v = CT_IDX[j]
                    if variant == 'vig':
                        pt_v = (ct_v - kv) % 26
                    else:
                        pt_v = (kv - ct_v) % 26
                    if AZ[pt_v] == expected:
                        cribs += 1
                configs_tested += 1

                if cribs > best_rk['cribs']:
                    best_rk = {
                        'cribs': cribs,
                        'order': list(order),
                        'variant': variant,
                        'text': name,
                        'offset': offset,
                    }
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 order={list(order)} {variant} {name} offset={offset}")

t2 = time.time()
print(f"  Tested {configs_tested:,} configs in {t2-t1:.1f}s")
print(f"  Best: {best_rk['cribs']}/24 — {best_rk}")

# ── Phase 8: Extended running key test — ALL orderings × top texts ────────
print("\n" + "-" * 50)
print("Phase 8: Extended running key — ALL 5040 orderings × all texts")
print("-" * 50)

# For each text, precompute key arrays for speed
best_extended = {'cribs': 0}
configs_ext = 0
t3 = time.time()

for name, text in rk_texts.items():
    max_offset = len(text) - N
    if max_offset < 0:
        continue
    text_idx = [IDX[c] for c in text]

    for order in permutations(range(WIDTH)):
        # Build inv_perm
        inv_perm = [0] * N
        pos = 0
        for grid_col in order:
            for row in range(COL_LENS[grid_col]):
                pt_pos = row * WIDTH + grid_col
                inv_perm[pt_pos] = pos
                pos += 1

        # Precompute crib CT positions
        crib_ct_positions = [(p, inv_perm[p], expected) for p, expected in CRIB_DICT.items()]

        step = max(1, max_offset // 2000)
        for offset in range(0, max_offset, step):
            for variant_sign in (1, -1):  # 1=vig, -1=beau
                cribs = 0
                for p, j, expected in crib_ct_positions:
                    kv = text_idx[offset + j]
                    ct_v = CT_IDX[j]
                    pt_v = (ct_v - variant_sign * kv) % 26
                    if AZ[pt_v] == expected:
                        cribs += 1
                configs_ext += 1

                if cribs > best_extended['cribs']:
                    vname = 'vig' if variant_sign == 1 else 'beau'
                    best_extended = {
                        'cribs': cribs,
                        'order': list(order),
                        'variant': vname,
                        'text': name,
                        'offset': offset,
                    }
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 order={list(order)} {vname} {name} offset={offset}")

t4 = time.time()
print(f"  Tested {configs_ext:,} configs in {t4-t3:.1f}s")
print(f"  Best: {best_extended['cribs']}/24 — {best_extended}")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

results.sort(key=lambda x: x['bg_score'], reverse=True)
best = results[0]
all_bg = [r['bg_score'] for r in results]
mean_bg = sum(all_bg) / len(all_bg)
std_bg = (sum((x - mean_bg)**2 for x in all_bg) / len(all_bg)) ** 0.5

print(f"\n  Key bigram discrimination:")
print(f"    Best ordering: {best['order']} ({best['variant']})")
print(f"    Bigram score: {best['bg_score']:.3f} (z={(best['bg_score'] - mean_bg) / std_bg:.2f})")
print(f"    Key at cribs: {best['key_str']}")

# Assess signal quality
z_top = (best['bg_score'] - mean_bg) / std_bg
if z_top > 4.0:
    verdict = "STRONG SIGNAL — ordering discriminated"
elif z_top > 3.0:
    verdict = "MODERATE SIGNAL — worth investigating"
elif z_top > 2.0:
    verdict = "WEAK SIGNAL — borderline"
else:
    verdict = "NO SIGNAL — underdetermined or key not English"

print(f"\n  Gromark: {'CANDIDATES FOUND' if gromark_candidates else 'ELIMINATED (all orderings)'}")
print(f"  Running key (top 50 orderings): best {best_rk['cribs']}/24")
print(f"  Running key (all orderings): best {best_extended['cribs']}/24")
print(f"\n  Verdict: {verdict}")

# Save results
output = {
    'experiment': 'E-S-65',
    'description': 'Key bigram discrimination for width-7 Model B',
    'top_20_bg': [{
        'order': r['order'],
        'variant': r['variant'],
        'bg_score': r['bg_score'],
        'ug_score': r['ug_score'],
        'combined': r['combined'],
        'key_str': r['key_str'],
    } for r in results[:20]],
    'stats': {
        'mean_bg': mean_bg,
        'std_bg': std_bg,
        'z_top': z_top,
    },
    'gromark_candidates': len(gromark_candidates),
    'running_key_best': best_rk,
    'running_key_extended_best': best_extended,
    'verdict': verdict,
}

os.makedirs("results", exist_ok=True)
with open("results/e_s_65_key_bigram.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_65_key_bigram.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_65_key_bigram_discrimination.py")
