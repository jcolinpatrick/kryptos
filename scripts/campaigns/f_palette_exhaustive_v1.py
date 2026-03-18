#!/usr/bin/env python3
"""EXHAUSTIVE palette-constrained null-mask search.

DISCOVERY: All 17 consensus null chars use ONLY 7 letters {B,G,I,K,O,W,Z}.
There are 35 positions in CT97 where CT[p] is in this palette.
17 are consensus nulls. 4 are crib positions (must NOT be nulls).
That leaves 14 candidates for the remaining 7 null slots.

C(14,7) = 3,432 possible 24-null masks. EXHAUSTIVELY SEARCHABLE.

For each mask, test:
  - DEFECTOR:AZ_beau + col7 (known 15/24 model)
  - DEFECTOR:AZ_beau direct (no transposition)
  - DEFECTOR:AZ_vig + col7
  - DEFECTOR:AZ_vig direct
  - KRYPTOS:KA_vig + col7
  - KRYPTOS:KA_vig direct
  - KRYPTOS:KA_beau + col7
  - KRYPTOS:KA_beau direct

Then for top-5 scoring masks, test all 6 keywords x all variants.

Cipher: autokey (keyword primes, then PT feedback)
Family: campaigns
Status: active
Keyspace: 3,432 masks x 8 cipher configs = 27,456 primary; top-5 x 72 = 360 secondary
Last run: never
Best score: TBD
"""

import sys, time, json
from itertools import combinations
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS, KRYPTOS_ALPHABET

CT97 = CT
N = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[chr(i+65)] for i in range(26)]

# ── Palette definition ──────────────────────────────────────────────────
PALETTE = frozenset('BGIKOWZ')

# Consensus null positions (17 positions, 100% agreement across all 6 known 15/24 masks)
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})

# All positions where CT[p] is in the palette
ALL_PALETTE_POS = frozenset(i for i in range(N) if CT97[i] in PALETTE)

# Crib positions that are also in palette (cannot be nulls)
CRIB_PALETTE = ALL_PALETTE_POS & CRIB_POSITIONS

# Candidate positions: palette, not consensus, not crib
CANDIDATES = sorted(ALL_PALETTE_POS - CONSENSUS_NULLS - CRIB_POSITIONS)

assert len(CONSENSUS_NULLS) == 17
assert len(ALL_PALETTE_POS) == 35
assert len(CRIB_PALETTE) == 4  # positions 30,31,70,73
assert len(CANDIDATES) == 14

# ── Transposition ─────────────────────────────────────────────────────
def columnar_perm(n, width):
    """Columnar transposition: write row-by-row, read col-by-col.
    Returns perm where transposed[i] = original[perm[i]]."""
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

COL7_INV = reverse_perm(columnar_perm(N_PT, 7))

def apply_col7(ct73_list):
    return [ct73_list[COL7_INV[i]] for i in range(N_PT)]

# ── Autokey decryption ─────────────────────────────────────────────────
def autokey_decrypt_az(ct73_az, kw_str, beau=False):
    """AZ autokey decrypt. ct73_az = list of ints 0-25."""
    kw_az = [ord(c) - 65 for c in kw_str.upper()]
    L = len(kw_az)
    pt = []
    for i, c in enumerate(ct73_az):
        k = kw_az[i] if i < L else pt[i - L]
        p = (k - c) % 26 if beau else (c - k) % 26
        pt.append(p)
    return pt

def autokey_decrypt_ka(ct73_az, kw_str, beau=False):
    """KA autokey decrypt. ct73_az = list of ints 0-25 (AZ-indexed)."""
    ct73_ka = [AZ_TO_KA[c] for c in ct73_az]
    kw_ka = [KA_IDX[c] for c in kw_str.upper()]
    L = len(kw_ka)
    pt_ka = []
    for i, c in enumerate(ct73_ka):
        k = kw_ka[i] if i < L else pt_ka[i - L]
        p = (k - c) % 26 if beau else (c - k) % 26
        pt_ka.append(p)
    return pt_ka  # KA indices

def pt_to_text_az(pt_indices):
    return ''.join(chr(p + 65) for p in pt_indices)

def pt_to_text_ka(pt_ka_indices):
    return ''.join(KA_STR[p] for p in pt_ka_indices)

# ── Crib scoring ───────────────────────────────────────────────────────
def count_crib_hits_az(pt_indices, ene_s, bcl_s):
    """Score cribs against AZ-indexed plaintext."""
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < N_PT and pt_indices[ene_s + j] == ord(c) - 65)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < N_PT and pt_indices[bcl_s + j] == ord(c) - 65)
    return e + b, e, b

def count_crib_hits_ka(pt_ka_indices, ene_s, bcl_s):
    """Score cribs against KA-indexed plaintext."""
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < N_PT and pt_ka_indices[ene_s + j] == KA_IDX[c])
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < N_PT and pt_ka_indices[bcl_s + j] == KA_IDX[c])
    return e + b, e, b

# ── Evaluate one mask + one cipher config ──────────────────────────────
def evaluate(null_set, kw_str, beau, ka, use_col7):
    """Returns (total_score, ene_score, bcl_score, plaintext_string)."""
    # Extract 73 chars
    ct73_raw = [CT97[i] for i in range(N) if i not in null_set]
    ct73_az = [ord(c) - 65 for c in ct73_raw]

    # Compute shifted crib positions
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    # Apply transposition if requested
    if use_col7:
        ct73_work = apply_col7(ct73_az)
    else:
        ct73_work = list(ct73_az)

    # Decrypt and score
    if ka:
        pt = autokey_decrypt_ka(ct73_work, kw_str, beau)
        total, e, b = count_crib_hits_ka(pt, ene_s, bcl_s)
        pt_text = pt_to_text_ka(pt)
    else:
        pt = autokey_decrypt_az(ct73_work, kw_str, beau)
        total, e, b = count_crib_hits_az(pt, ene_s, bcl_s)
        pt_text = pt_to_text_az(pt)

    return total, e, b, pt_text

# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════
t0 = time.time()

print("=" * 72)
print("PALETTE-CONSTRAINED EXHAUSTIVE NULL-MASK SEARCH")
print("=" * 72)
print(f"CT97 = {CT97}")
print(f"Palette letters: {sorted(PALETTE)}")
print(f"Consensus nulls ({len(CONSENSUS_NULLS)}): {sorted(CONSENSUS_NULLS)}")
print(f"  Letters: {''.join(CT97[i] for i in sorted(CONSENSUS_NULLS))}")
print(f"Palette positions in CT ({len(ALL_PALETTE_POS)}): {sorted(ALL_PALETTE_POS)}")
print(f"Crib positions in palette ({len(CRIB_PALETTE)}): {sorted(CRIB_PALETTE)}")
print(f"  Letters: {', '.join(f'{p}={CT97[p]}' for p in sorted(CRIB_PALETTE))}")
print(f"Candidates ({len(CANDIDATES)}): {CANDIDATES}")
print(f"  Letters: {', '.join(f'{p}={CT97[p]}' for p in CANDIDATES)}")
print(f"Total masks to test: C({len(CANDIDATES)},7) = {len(list(combinations(CANDIDATES, 7)))}")
print()

# Verify existing 15/24 seed mask
SEED_15 = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
v_total, v_e, v_b, v_pt = evaluate(SEED_15, 'DEFECTOR', True, False, True)
print(f"Verification of known 15/24 mask: {v_total}/24 (ene={v_e}/13, bcl={v_b}/11)")
print(f"  PT = {v_pt}")
# Check which positions in that mask are NOT in palette
non_palette_in_seed = [p for p in sorted(SEED_15) if CT97[p] not in PALETTE]
print(f"  Non-palette positions in this mask: {non_palette_in_seed}")
print(f"  Letters: {', '.join(f'{p}={CT97[p]}' for p in non_palette_in_seed)}")
print()

# ── Phase 1: Primary cipher configs ─────────────────────────────────
PRIMARY_CONFIGS = [
    ('DEFECTOR', True,  False, True,  'DEFECTOR:AZ_beau+col7'),
    ('DEFECTOR', True,  False, False, 'DEFECTOR:AZ_beau:direct'),
    ('DEFECTOR', False, False, True,  'DEFECTOR:AZ_vig+col7'),
    ('DEFECTOR', False, False, False, 'DEFECTOR:AZ_vig:direct'),
    ('KRYPTOS',  False, True,  True,  'KRYPTOS:KA_vig+col7'),
    ('KRYPTOS',  False, True,  False, 'KRYPTOS:KA_vig:direct'),
    ('KRYPTOS',  True,  True,  True,  'KRYPTOS:KA_beau+col7'),
    ('KRYPTOS',  True,  True,  False, 'KRYPTOS:KA_beau:direct'),
]

# Generate all 3432 mask combos
all_combos = list(combinations(CANDIDATES, 7))
n_combos = len(all_combos)
print(f"Phase 1: {n_combos} masks x {len(PRIMARY_CONFIGS)} configs = {n_combos * len(PRIMARY_CONFIGS)} evaluations")
print()

# Store all results >= 12
high_results = []
# Track global best per config
config_bests = {label: (0, None, None, None, None) for _, _, _, _, label in PRIMARY_CONFIGS}
# Track all scores for histogram
score_hist = {}

n_evals = 0
for ci, combo in enumerate(all_combos):
    null_set = frozenset(CONSENSUS_NULLS | set(combo))
    assert len(null_set) == 24

    for kw, beau, ka, use_col7, label in PRIMARY_CONFIGS:
        total, e, b, pt = evaluate(null_set, kw, beau, ka, use_col7)
        n_evals += 1

        key = f"{label}:{total}"
        score_hist[key] = score_hist.get(key, 0) + 1

        if total >= 12:
            result = {
                'score': total, 'ene': e, 'bcl': b, 'pt': pt,
                'label': label, 'mask': sorted(null_set),
                'extra_nulls': sorted(combo)
            }
            high_results.append(result)

        if total > config_bests[label][0]:
            config_bests[label] = (total, e, b, pt, sorted(null_set))

    # Progress
    if (ci + 1) % 500 == 0 or ci == n_combos - 1:
        elapsed = time.time() - t0
        rate = n_evals / elapsed if elapsed > 0 else 0
        n_high = len(high_results)
        print(f"  [{ci+1}/{n_combos}] {n_evals} evals, {rate:.0f}/s, {n_high} hits >= 12/24  [{elapsed:.1f}s]")

print()
print("=" * 72)
print("PHASE 1 RESULTS — Best per config")
print("=" * 72)
for kw, beau, ka, use_col7, label in PRIMARY_CONFIGS:
    best = config_bests[label]
    print(f"  {label}: {best[0]}/24 (ene={best[1]}/13, bcl={best[2]}/11)")
    if best[3]:
        print(f"    PT   = {best[3]}")
        print(f"    mask = {best[4]}")
    print()

# Sort high results
high_results.sort(key=lambda x: (-x['score'], x['label']))

print("=" * 72)
print(f"ALL RESULTS >= 12/24 ({len(high_results)} total)")
print("=" * 72)
for r in high_results:
    print(f"  {r['score']}/24 ene={r['ene']}/13 bcl={r['bcl']}/11 | {r['label']}")
    print(f"    PT    = {r['pt']}")
    print(f"    extra = {r['extra_nulls']}")
    print()

# ── Phase 2: Top-5 masks with all keywords ─────────────────────────
print("=" * 72)
print("PHASE 2: TOP MASKS x ALL KEYWORDS x ALL VARIANTS")
print("=" * 72)

# Get unique top masks by score
seen_masks = set()
top_masks = []
for r in high_results:
    mask_key = tuple(r['mask'])
    if mask_key not in seen_masks:
        seen_masks.add(mask_key)
        top_masks.append(r)
    if len(top_masks) >= 5:
        break

ALL_KEYWORDS = ['DEFECTOR', 'KRYPTOS', 'KOMPASS', 'ABSCISSA', 'COLOPHON', 'PARALLAX']
ALL_VARIANTS = [
    (True,  False, True,  'AZ_beau+col7'),
    (True,  False, False, 'AZ_beau:direct'),
    (False, False, True,  'AZ_vig+col7'),
    (False, False, False, 'AZ_vig:direct'),
    (True,  True,  True,  'KA_beau+col7'),
    (True,  True,  False, 'KA_beau:direct'),
    (False, True,  True,  'KA_vig+col7'),
    (False, True,  False, 'KA_vig:direct'),
    # Also var_beaufort AZ
    # We'll add var_beaufort manually below
]

phase2_results = []
for mi, top_r in enumerate(top_masks):
    null_set = frozenset(top_r['mask'])
    print(f"\nMask {mi+1}: {top_r['mask']} (Phase 1 best: {top_r['score']}/24 via {top_r['label']})")

    for kw in ALL_KEYWORDS:
        for beau, ka, use_col7, var_label in ALL_VARIANTS:
            total, e, b, pt = evaluate(null_set, kw, beau, ka, use_col7)
            label = f"{kw}:{var_label}"
            if total >= 10:
                phase2_results.append({
                    'score': total, 'ene': e, 'bcl': b, 'pt': pt,
                    'label': label, 'mask': sorted(null_set),
                })
                if total >= 12:
                    print(f"  ** {label}: {total}/24 (ene={e}/13, bcl={b}/11)")
                    print(f"     PT = {pt}")

        # Also test var_beaufort (AZ only) with and without col7
        for use_col7, trans_label in [(True, '+col7'), (False, ':direct')]:
            # Var Beaufort: P = (C + K) mod 26 => K-C = -(P), so P = C + K
            # We implement directly
            ct73_raw = [CT97[i] for i in range(N) if i not in null_set]
            ct73_az = [ord(c) - 65 for c in ct73_raw]
            n1 = sum(1 for p in null_set if p < ENE_START)
            n2 = sum(1 for p in null_set if p < BCL_START)
            ene_s = ENE_START - n1; bcl_s = BCL_START - n2

            if use_col7:
                ct73_work = apply_col7(ct73_az)
            else:
                ct73_work = list(ct73_az)

            # Var Beaufort autokey: P = (C + K) mod 26 (from autokey.py)
            kw_az = [ord(c) - 65 for c in kw.upper()]
            L = len(kw_az)
            pt_indices = []
            for i, c in enumerate(ct73_work):
                k = kw_az[i] if i < L else pt_indices[i - L]
                p = (c + k) % 26
                pt_indices.append(p)

            total, e, b = count_crib_hits_az(pt_indices, ene_s, bcl_s)
            label = f"{kw}:AZ_vbeau{trans_label}"
            if total >= 10:
                pt_text = ''.join(chr(p + 65) for p in pt_indices)
                phase2_results.append({
                    'score': total, 'ene': e, 'bcl': b, 'pt': pt_text,
                    'label': label, 'mask': sorted(null_set),
                })
                if total >= 12:
                    print(f"  ** {label}: {total}/24 (ene={e}/13, bcl={b}/11)")
                    print(f"     PT = {pt_text}")

phase2_results.sort(key=lambda x: (-x['score'], x['label']))
print()
print("=" * 72)
print(f"PHASE 2 RESULTS >= 10/24 ({len(phase2_results)} total)")
print("=" * 72)
for r in phase2_results:
    print(f"  {r['score']}/24 ene={r['ene']}/13 bcl={r['bcl']}/11 | {r['label']}")
    print(f"    PT   = {r['pt']}")
    print(f"    mask = {r['mask']}")
    print()

# ── Score distribution histogram ─────────────────────────────────────
print("=" * 72)
print("SCORE DISTRIBUTION (Phase 1)")
print("=" * 72)
for label_name in [l for _, _, _, _, l in PRIMARY_CONFIGS]:
    scores = {}
    for key, count in score_hist.items():
        parts = key.rsplit(':', 1)
        if parts[0] == label_name:
            sc = int(parts[1])
            scores[sc] = count
    total_count = sum(scores.values())
    print(f"  {label_name} (n={total_count}):")
    for sc in sorted(scores.keys(), reverse=True):
        if scores[sc] > 0:
            pct = 100.0 * scores[sc] / total_count
            bar = '#' * min(50, scores[sc] // max(1, total_count // 200))
            print(f"    {sc:2d}/24: {scores[sc]:5d} ({pct:5.1f}%) {bar}")
    print()

# ── Summary ──────────────────────────────────────────────────────────
elapsed = time.time() - t0
global_best = high_results[0] if high_results else None
print("=" * 72)
print(f"EXHAUSTIVE SEARCH COMPLETE: {n_evals} evaluations in {elapsed:.1f}s")
print("=" * 72)
if global_best:
    print(f"GLOBAL BEST: {global_best['score']}/24 (ene={global_best['ene']}/13, bcl={global_best['bcl']}/11)")
    print(f"  Config: {global_best['label']}")
    print(f"  PT    : {global_best['pt']}")
    print(f"  Mask  : {global_best['mask']}")
    print(f"  Extra nulls (from candidates): {global_best['extra_nulls']}")

    # Check if any score >= 18 (SIGNAL)
    signals = [r for r in high_results if r['score'] >= 18]
    if signals:
        print(f"\n  *** {len(signals)} SIGNAL-LEVEL RESULTS (>= 18/24) ***")
        for s in signals:
            print(f"    {s['score']}/24 | {s['label']} | PT={s['pt']}")

    # Check for breakthrough
    breakthroughs = [r for r in high_results if r['score'] >= 24]
    if breakthroughs:
        print(f"\n  *** BREAKTHROUGH: {len(breakthroughs)} PERFECT SCORE(S) ***")
        for b in breakthroughs:
            print(f"    {b['score']}/24 | {b['label']} | PT={b['pt']}")
            print(f"    mask = {b['mask']}")
else:
    print("NO results >= 12/24")

# ── Save results ─────────────────────────────────────────────────────
output = {
    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
    'task': 'palette_exhaustive_null_mask',
    'n_masks': n_combos,
    'n_configs': len(PRIMARY_CONFIGS),
    'n_evals': n_evals,
    'elapsed_s': round(elapsed, 1),
    'palette': sorted(PALETTE),
    'consensus_nulls': sorted(CONSENSUS_NULLS),
    'candidates': CANDIDATES,
    'global_best': global_best,
    'all_high_results': high_results[:50],  # Top 50
    'phase2_results': phase2_results[:30],  # Top 30
    'config_bests': {k: {'score': v[0], 'ene': v[1], 'bcl': v[2], 'pt': v[3], 'mask': v[4]}
                     for k, v in config_bests.items()},
    'verdict': 'BREAKTHROUGH' if any(r['score'] >= 24 for r in high_results)
               else 'SIGNAL' if any(r['score'] >= 18 for r in high_results)
               else 'PROMISING' if any(r['score'] >= 15 for r in high_results)
               else 'NOISE'
}

with open('results/palette_exhaustive_null_mask.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"\nResults saved to results/palette_exhaustive_null_mask.json")
print(f"\nverdict: {json.dumps({'verdict': output['verdict'], 'global_best': global_best['score'] if global_best else 0, 'n_evals': n_evals})}")
