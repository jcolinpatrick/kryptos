#!/usr/bin/env python3
"""E-S-85: CT-Autokey Full Decryption + Quadgram Scoring

Key insight: For ciphertext-autokey, the intermediate text is FULLY DETERMINED
from CT alone (no key needed). We compute candidate plaintexts for all
(variant, primer_length, ordering) combinations and score with quadgrams.

For each autokey variant and primer length m:
  Vigenère CT-autokey:  Intermediate[j] = (CT[j] - CT[j-m]) % 26
  Beaufort CT-autokey:  Intermediate[j] = (CT[j-m] - CT[j]) % 26
  VarBeau CT-autokey:   Intermediate[j] = (CT[j] + CT[j-m]) % 26

Then for each width-7 ordering:
  PT = inverse_transposition(Intermediate)

Score with quadgrams + crib check.

Also investigates the E-S-83 finding: vig, order=[2,6,3,0,1,4,5], m=3, offset=19
giving 10/24 crib matches.

Phase 1: CT-autokey (offset=0), all 5040 orderings × 14 primers × 3 variants
Phase 2: CT-autokey with offset, focused on top configs
Phase 3: Intermediate-text autokey with short primers (m=1-3)
Phase 4: Direct correspondence (no transposition)
"""

import json
import os
import sys
import time
from itertools import permutations

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
CT_NUM = [AZ_IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
PT_NUM = {pos: AZ_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POS = sorted(CRIB_DICT.keys())

WIDTH = 7
NROWS_FULL = N // WIDTH
NROWS_EXTRA = N % WIDTH
COL_LENGTHS = [NROWS_FULL + 1 if c < NROWS_EXTRA else NROWS_FULL
               for c in range(WIDTH)]

# Load quadgram data
qg_path = "data/english_quadgrams.json"
QUADGRAMS = {}
if os.path.exists(qg_path):
    with open(qg_path) as f:
        raw = json.load(f)
    # Data format: top-level dict with keys like "THAN"
    if isinstance(raw, dict):
        if "logp" in raw:
            QUADGRAMS = raw["logp"]
        else:
            QUADGRAMS = raw

QG_FLOOR = -15.0  # Floor for missing quadgrams


def qg_score(text):
    """Quadgram log-probability score."""
    if not QUADGRAMS:
        return 0.0
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, QG_FLOOR)
    return score


def build_columnar_perm(order):
    """perm[ct_pos] = pt_pos (gather)."""
    perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        col = order[rank]
        clen = COL_LENGTHS[col]
        for row in range(clen):
            pt_pos = row * WIDTH + col
            perm[j] = pt_pos
            j += 1
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def compute_intermediate_ct_autokey(variant, m, offset=0):
    """Compute intermediate text for CT-autokey.

    For positions j >= m:
      vig:      Inter[j] = (CT[j] - CT[j-m] - offset) % 26
      beau:     Inter[j] = (CT[j-m] - CT[j] + offset) % 26
      var_beau: Inter[j] = (CT[j] + CT[j-m] + offset) % 26

    Returns list of (position, value) pairs for j >= m.
    """
    inter = {}
    for j in range(m, N):
        if variant == 'vig':
            inter[j] = (CT_NUM[j] - CT_NUM[j - m] - offset) % 26
        elif variant == 'beau':
            inter[j] = (CT_NUM[j - m] - CT_NUM[j] + offset) % 26
        else:  # var_beau
            inter[j] = (CT_NUM[j] + CT_NUM[j - m] + offset) % 26
    return inter


def apply_transposition(inter, perm):
    """Apply transposition to get plaintext.

    Under Model B: perm[j] = pt_pos for each ct_pos j.
    So PT[perm[j]] = Intermediate[j].
    Returns PT as string (with '?' for positions from primer).
    """
    pt = ['?'] * N
    for j, val in inter.items():
        pt_pos = perm[j]
        pt[pt_pos] = AZ[val]
    return ''.join(pt)


def count_crib_matches(inter, perm):
    """Count how many crib positions match."""
    matches = 0
    total = 0
    for j in range(N):
        if j not in inter:
            continue
        pt_pos = perm[j]
        if pt_pos in PT_NUM:
            total += 1
            if inter[j] == PT_NUM[pt_pos]:
                matches += 1
    return matches, total


print("=" * 70)
print("E-S-85: CT-Autokey Full Decryption + Quadgram Scoring")
print("=" * 70)
print(f"  Quadgrams loaded: {len(QUADGRAMS):,}")

# ── Phase 1: CT-autokey (no offset) × all orderings × quadgrams ─────────

print("\n" + "-" * 50)
print("Phase 1: CT-autokey (offset=0) × 5040 orderings × 3 variants × 14 primers")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
VARIANTS = ['vig', 'beau', 'var_beau']
PRIMER_RANGE = range(1, 15)

t0 = time.time()

# Track best by quadgram score AND by crib matches
best_qg = {'score': -999.0, 'config': None, 'pt': ''}
best_crib = {'matches': 0, 'total': 0, 'config': None, 'pt': ''}
best_combined = {'score': -999.0, 'config': None, 'pt': ''}  # qg score among configs with ≥1 crib match

n_tested = 0

for variant in VARIANTS:
    for m in PRIMER_RANGE:
        inter = compute_intermediate_ct_autokey(variant, m)

        for order in all_orders:
            order = list(order)
            perm = build_columnar_perm(order)

            # Count crib matches
            cm, ct = count_crib_matches(inter, perm)

            # Compute plaintext and quadgram score
            pt = apply_transposition(inter, perm)
            # Score only the non-'?' portion
            pt_clean = pt.replace('?', '')
            qgs = qg_score(pt_clean) / max(len(pt_clean) - 3, 1) if len(pt_clean) > 3 else -15.0

            if qgs > best_qg['score']:
                best_qg = {
                    'score': qgs, 'config': (variant, m, order),
                    'pt': pt, 'cribs': cm
                }

            if cm > best_crib['matches']:
                best_crib = {
                    'matches': cm, 'total': ct,
                    'config': (variant, m, order), 'pt': pt, 'qg': qgs
                }

            if cm >= 5 and qgs > best_combined['score']:
                best_combined = {
                    'score': qgs, 'config': (variant, m, order),
                    'pt': pt, 'cribs': cm
                }

            n_tested += 1

        if n_tested % 50000 == 0:
            elapsed = time.time() - t0
            print(f"  [{n_tested:,}] {elapsed:.1f}s | "
                  f"best qg: {best_qg['score']:.3f} ({best_qg['cribs']} cribs), "
                  f"best crib: {best_crib['matches']}")

elapsed_p1 = time.time() - t0
print(f"\n  Phase 1 done: {n_tested:,} configs in {elapsed_p1:.1f}s")
print(f"  Best QG: {best_qg['score']:.3f} (cribs={best_qg['cribs']}) "
      f"config={best_qg['config']}")
print(f"    PT: {best_qg['pt'][:60]}...")
print(f"  Best cribs: {best_crib['matches']}/{best_crib['total']} "
      f"(qg={best_crib.get('qg', 0):.3f}) config={best_crib['config']}")
if best_combined['config']:
    print(f"  Best combined (cribs≥5): qg={best_combined['score']:.3f} "
          f"(cribs={best_combined['cribs']}) config={best_combined['config']}")
    print(f"    PT: {best_combined['pt'][:60]}...")


# ── Phase 2: Investigate E-S-83 finding ──────────────────────────────────

print("\n" + "-" * 50)
print("Phase 2: Investigate E-S-83 CT-feedback+offset finding")
print("-" * 50)

# The finding: vig, order=[2,6,3,0,1,4,5], m=3, offset=19, 10/24 cribs
# Decrypt the full text under this configuration
hit_order = [2, 6, 3, 0, 1, 4, 5]
hit_perm = build_columnar_perm(hit_order)
hit_inter = compute_intermediate_ct_autokey('vig', 3, offset=19)
hit_pt = apply_transposition(hit_inter, hit_perm)
hit_cribs, hit_total = count_crib_matches(hit_inter, hit_perm)
hit_qg = qg_score(hit_pt.replace('?', '')) / max(len(hit_pt.replace('?', '')) - 3, 1)

print(f"  Config: vig, order={hit_order}, m=3, offset=19")
print(f"  Cribs: {hit_cribs}/{hit_total}")
print(f"  QG score per char: {hit_qg:.3f}")
print(f"  Full PT: {hit_pt}")

# Check which cribs match and which don't
print(f"  Crib detail:")
for j in range(N):
    if j not in hit_inter:
        continue
    pt_pos = hit_perm[j]
    if pt_pos in PT_NUM:
        expected = AZ[PT_NUM[pt_pos]]
        got = AZ[hit_inter[j]]
        match = "OK" if hit_inter[j] == PT_NUM[pt_pos] else "FAIL"
        print(f"    CT[{j}]→PT[{pt_pos}]: expected {expected}, got {got} [{match}]")

# Test significance: how many orderings achieve ≥10 with this (variant, m, offset)?
count_ge10 = 0
for order in all_orders:
    order = list(order)
    perm = build_columnar_perm(order)
    cm, _ = count_crib_matches(hit_inter, perm)
    if cm >= 10:
        count_ge10 += 1

print(f"\n  Orderings with ≥10 cribs for (vig, m=3, offset=19): {count_ge10}/5040")

# Test across all offsets for this ordering
print(f"  All offsets for order={hit_order}, vig, m=3:")
for offset in range(26):
    inter = compute_intermediate_ct_autokey('vig', 3, offset=offset)
    cm, ct = count_crib_matches(inter, hit_perm)
    if cm >= 5:
        print(f"    offset={offset}: {cm}/{ct} cribs")


# ── Phase 3: CT-autokey with offset (top 25 offsets) ─────────────────────

print("\n" + "-" * 50)
print("Phase 3: CT-autokey + offset sweep (m=1-7, offset=0-25)")
print("-" * 50)

t2 = time.time()

best_offset_qg = {'score': -999.0, 'config': None, 'pt': ''}
best_offset_crib = {'matches': 0, 'config': None}

for variant in VARIANTS:
    for m in range(1, 8):
        for offset in range(26):
            inter = compute_intermediate_ct_autokey(variant, m, offset)

            for order in all_orders:
                order = list(order)
                perm = build_columnar_perm(order)
                cm, ct = count_crib_matches(inter, perm)

                if cm >= 10:
                    pt = apply_transposition(inter, perm)
                    pt_clean = pt.replace('?', '')
                    qgs = qg_score(pt_clean) / max(len(pt_clean) - 3, 1) if len(pt_clean) > 3 else -15.0

                    if cm > best_offset_crib['matches']:
                        best_offset_crib = {
                            'matches': cm, 'total': ct,
                            'config': (variant, m, offset, order),
                            'qg': qgs, 'pt': pt
                        }

                    if qgs > best_offset_qg['score']:
                        best_offset_qg = {
                            'score': qgs, 'config': (variant, m, offset, order),
                            'pt': pt, 'cribs': cm
                        }

        if (time.time() - t2) > 2:
            print(f"  {variant} m={m}: best cribs={best_offset_crib['matches']}, "
                  f"best qg={best_offset_qg['score']:.3f}")

elapsed_p3 = time.time() - t2
print(f"\n  Phase 3 done in {elapsed_p3:.1f}s")
print(f"  Best offset cribs: {best_offset_crib['matches']} "
      f"config={best_offset_crib.get('config', 'none')}")
if best_offset_crib.get('pt'):
    print(f"    PT: {best_offset_crib['pt'][:60]}...")
print(f"  Best offset QG: {best_offset_qg['score']:.3f} "
      f"config={best_offset_qg.get('config', 'none')}")


# ── Phase 4: Direct correspondence (no transposition) ────────────────────

print("\n" + "-" * 50)
print("Phase 4: Direct correspondence (no transposition)")
print("-" * 50)

identity = list(range(N))

best_direct = {'score': -999.0, 'config': None, 'pt': '', 'cribs': 0}

for variant in VARIANTS:
    for m in PRIMER_RANGE:
        for offset in range(26):
            inter = compute_intermediate_ct_autokey(variant, m, offset)

            # Direct: perm = identity
            cm = 0
            ct = 0
            for j in inter:
                if j in PT_NUM:
                    ct += 1
                    if inter[j] == PT_NUM[j]:
                        cm += 1

            pt_chars = ''.join(AZ[inter[j]] if j in inter else '?' for j in range(N))
            pt_clean = pt_chars.replace('?', '')
            qgs = qg_score(pt_clean) / max(len(pt_clean) - 3, 1) if len(pt_clean) > 3 else -15.0

            if qgs > best_direct['score']:
                best_direct = {
                    'score': qgs, 'config': (variant, m, offset),
                    'pt': pt_chars, 'cribs': cm
                }

            if cm >= 5:
                print(f"  Direct: {cm} cribs, qg={qgs:.3f}, "
                      f"config=({variant}, m={m}, offset={offset})")

print(f"  Best direct QG: {best_direct['score']:.3f} "
      f"(cribs={best_direct['cribs']}) config={best_direct['config']}")
print(f"    PT: {best_direct['pt'][:60]}...")


# ── Summary ──────────────────────────────────────────────────────────────

total_elapsed = time.time() - t0
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (no offset): best QG={best_qg['score']:.3f} "
      f"(cribs={best_qg['cribs']}), best cribs={best_crib['matches']}")
print(f"  Phase 2 (hit investigation): {hit_cribs}/{hit_total} cribs, "
      f"QG={hit_qg:.3f}")
print(f"  Phase 3 (with offset): best cribs={best_offset_crib['matches']}, "
      f"best QG={best_offset_qg['score']:.3f}")
print(f"  Phase 4 (direct): best QG={best_direct['score']:.3f} "
      f"(cribs={best_direct['cribs']})")
print(f"  Total time: {total_elapsed:.1f}s")

# Verdict
max_cribs = max(best_crib['matches'],
                best_offset_crib.get('matches', 0),
                hit_cribs)

if max_cribs >= 20:
    verdict = f"BREAKTHROUGH — {max_cribs} cribs match!"
elif max_cribs >= 15:
    verdict = f"STRONG SIGNAL — {max_cribs} cribs, investigate"
elif max_cribs >= 10:
    verdict = f"INTERESTING — {max_cribs} cribs, check significance"
else:
    verdict = f"NO SIGNAL — best {max_cribs} cribs at noise level"

print(f"\n  Verdict: {verdict}")

# English QG reference: well-encrypted text ~-4.3/char, English ~-2.4/char
# Noise floor ~-6.0/char
best_overall_qg = max(best_qg['score'], best_offset_qg['score'],
                      best_direct['score'])
if best_overall_qg > -3.5:
    print(f"  QG NOTE: best {best_overall_qg:.3f}/char approaching English range")

output = {
    'experiment': 'E-S-85',
    'description': 'CT-autokey full decryption + quadgram scoring',
    'phase1_best_qg': {'score': best_qg['score'],
                       'config': str(best_qg['config']),
                       'cribs': best_qg['cribs']},
    'phase1_best_crib': {'matches': best_crib['matches'],
                         'config': str(best_crib['config'])},
    'phase2_hit': {'cribs': hit_cribs, 'qg': hit_qg, 'pt': hit_pt},
    'phase3_best_crib': {'matches': best_offset_crib.get('matches', 0),
                         'config': str(best_offset_crib.get('config', ''))},
    'phase4_direct': {'qg': best_direct['score'],
                      'cribs': best_direct['cribs']},
    'total_elapsed': total_elapsed,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_85_autokey_decrypt.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_85_autokey_decrypt.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_85_autokey_decrypt.py")
