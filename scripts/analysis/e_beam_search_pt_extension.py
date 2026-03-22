#!/usr/bin/env python3
"""Beam Search PT Extension: extend plaintext from cribs using keystream constraints.

Cipher:     Beaufort A=0 (two-system model)
Family:     analysis
Status:     active
Keyspace:   beam search (width 500, 12 restricted values per step)
Last run:   2026-03-21
Best score: TBD

Extends plaintext from ENE crib rightward (positions 34→62) and from BCL
crib leftward (positions 62→34), skipping consensus nulls. Uses beam search
with scoring by: quadgram English, restricted alphabet compliance, row
clustering, AP enrichment.
"""
import sys, os, json
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
def beaufort_key(ct_ch, pt_ch): return (az(ct_ch) + az(pt_ch)) % 26

# ── Known data ──────────────────────────────────────────────────────────
ENE_KS = [beaufort_key(c, p) for c, p in zip(CT[21:34], "EASTNORTHEAST")]
BCL_KS = [beaufort_key(c, p) for c, p in zip(CT[63:74], "BERLINCLOCK")]
FULL_KS = ENE_KS + BCL_KS

RESTRICTED_AZ = set(FULL_KS)  # 12 values: {1,2,3,4,6,9,10,11,14,17,19,20}
AP_AZ = {6, 10, 14}

# Consensus nulls
CONSENSUS_NULLS = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}

# Load quadgrams
quadgram_file = os.path.join(_ROOT, "data", "english_quadgrams.json")
QUADGRAMS = {}
if os.path.exists(quadgram_file):
    with open(quadgram_file) as f:
        QUADGRAMS = json.load(f)
    print(f"Loaded {len(QUADGRAMS):,} quadgrams")

FLOOR = -10.0

def qg_score(text):
    if len(text) < 4 or not QUADGRAMS:
        return FLOOR
    total = sum(QUADGRAMS.get(text[i:i+4], FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)

# ── Cipher positions between cribs ──────────────────────────────────────
# Positions 34-62 excluding consensus nulls
# Position 36 is consensus null, 52 is consensus null, 58-59 are consensus nulls
# Varying nulls: 2 from {38-45}, 1 from {55-56}
# For beam search, try the most likely null configuration: no varying nulls in 34-62
# except at positions 38 and 55 (most conservative guess)

# Case 1: Assume nulls at 36, 38, 52, 55, 58, 59 (maximizing cipher positions)
# Case 2: Assume nulls at 36, 44, 52, 56, 58, 59 (alternative)
# We'll try both

NULL_CONFIGS = {
    "config_A": {36, 38, 45, 52, 55, 58, 59},  # varying nulls at 38,45,55
    "config_B": {36, 39, 44, 52, 56, 58, 59},  # varying nulls at 39,44,56
    "config_C": {36, 40, 43, 52, 55, 58, 59},  # varying nulls at 40,43,55
    "minimal":  {36, 52, 58, 59},               # only consensus nulls
}

BEAM_WIDTH = 500
RESTRICTED_VALUES = sorted(RESTRICTED_AZ)

print("=" * 78)
print("BEAM SEARCH PLAINTEXT EXTENSION")
print("=" * 78)
print(f"Beam width: {BEAM_WIDTH}")
print(f"Restricted values: {[az_chr(v) for v in RESTRICTED_VALUES]}")
print(f"CT positions 34-62: {CT[34:63]}")

# ── Direction 1: ENE rightward (pos 34 → 62) ───────────────────────────

for config_name, null_set in NULL_CONFIGS.items():
    print(f"\n{'='*78}")
    print(f"NULL CONFIG: {config_name} — nulls in [34,62]: {sorted(p for p in null_set if 34<=p<=62)}")
    print("=" * 78)

    # Cipher positions from 34 to 62 (excluding nulls)
    cipher_positions = [p for p in range(34, 63) if p not in null_set]
    print(f"Cipher positions: {cipher_positions}")
    print(f"Count: {len(cipher_positions)}")

    # Initialize beam with ENE keystream ending state
    # Each beam entry: (keystream_so_far, plaintext_so_far, score)
    # Start with the known ENE keystream
    ene_pt = "EASTNORTHEAST"
    ene_ks = list(ENE_KS)

    beam = [(ene_ks[:], ene_pt, 0.0)]

    for step, pos in enumerate(cipher_positions):
        ct_val = az(CT[pos])
        new_beam = []

        for ks_so_far, pt_so_far, prev_score in beam:
            for key_val in RESTRICTED_VALUES:
                # Decrypt: PT = (K - C) mod 26
                pt_val = (key_val - ct_val) % 26
                pt_ch = az_chr(pt_val)

                # New keystream and plaintext
                new_ks = ks_so_far + [key_val]
                new_pt = pt_so_far + pt_ch

                # Score components
                # 1. Quadgram score (only score last 4+ chars for efficiency)
                qg = QUADGRAMS.get(new_pt[-4:], FLOOR) if len(new_pt) >= 4 else 0.0

                # 2. Row clustering with previous key
                prev_row = ka_row(az_chr(new_ks[-2]))
                curr_row = ka_row(az_chr(key_val))
                row_bonus = 1.5 if prev_row == curr_row else 0.0

                # 3. AP bonus
                ap_bonus = 0.5 if key_val in AP_AZ else 0.0

                # Cumulative score
                new_score = prev_score + qg + row_bonus + ap_bonus

                new_beam.append((new_ks, new_pt, new_score))

        # Keep top BEAM_WIDTH
        new_beam.sort(key=lambda x: -x[2])
        beam = new_beam[:BEAM_WIDTH]

        if (step + 1) % 5 == 0 or step == len(cipher_positions) - 1:
            best_ks, best_pt, best_score = beam[0]
            pt_display = best_pt[13:]  # skip EASTNORTHEAST
            print(f"  Step {step+1:2d} (pos {pos:2d}): "
                  f"top PT='...{pt_display[-20:]}' score={best_score:.1f}")

    # Final results
    print(f"\n  TOP 20 PLAINTEXT EXTENSIONS ({config_name}):")
    seen_pts = set()
    rank = 0
    for ks, pt, score in beam:
        pt_ext = pt[13:]  # after EASTNORTHEAST
        if pt_ext in seen_pts:
            continue
        seen_pts.add(pt_ext)
        rank += 1
        if rank > 20:
            break
        ks_ext = ''.join(az_chr(v) for v in ks[13:])
        print(f"    {rank:3d}. PT='EASTNORTHEAST{pt_ext}' "
              f"KS='{ks_ext}' score={score:.1f}")

# ── Direction 2: BCL leftward (pos 62 → 34) ────────────────────────────

print(f"\n{'='*78}")
print("REVERSE DIRECTION: BCL LEFTWARD (pos 62 → 34)")
print("=" * 78)

# Use minimal null config for reverse
null_set = NULL_CONFIGS["minimal"]
cipher_positions = [p for p in range(62, 33, -1) if p not in null_set]
print(f"Cipher positions (reverse): {cipher_positions}")

bcl_pt = "BERLINCLOCK"
bcl_ks = list(BCL_KS)

beam = [(bcl_ks[:], bcl_pt, 0.0)]

for step, pos in enumerate(cipher_positions):
    ct_val = az(CT[pos])
    new_beam = []

    for ks_so_far, pt_so_far, prev_score in beam:
        for key_val in RESTRICTED_VALUES:
            pt_val = (key_val - ct_val) % 26
            pt_ch = az_chr(pt_val)

            new_ks = [key_val] + ks_so_far
            new_pt = pt_ch + pt_so_far

            # Score: quadgram on first 4 chars (reversed direction)
            qg = QUADGRAMS.get(new_pt[:4], FLOOR) if len(new_pt) >= 4 else 0.0

            prev_row = ka_row(az_chr(new_ks[1]))
            curr_row = ka_row(az_chr(key_val))
            row_bonus = 1.5 if prev_row == curr_row else 0.0
            ap_bonus = 0.5 if key_val in AP_AZ else 0.0

            new_score = prev_score + qg + row_bonus + ap_bonus
            new_beam.append((new_ks, new_pt, new_score))

    new_beam.sort(key=lambda x: -x[2])
    beam = new_beam[:BEAM_WIDTH]

    if (step + 1) % 5 == 0 or step == len(cipher_positions) - 1:
        best_ks, best_pt, best_score = beam[0]
        pt_display = best_pt[:20]
        print(f"  Step {step+1:2d} (pos {pos:2d}): "
              f"top PT='{pt_display}...' score={best_score:.1f}")

# Final reverse results
print(f"\n  TOP 20 PLAINTEXT EXTENSIONS (BCL leftward):")
seen_pts = set()
rank = 0
for ks, pt, score in beam:
    pt_ext = pt[:-11]  # before BERLINCLOCK
    if pt_ext in seen_pts:
        continue
    seen_pts.add(pt_ext)
    rank += 1
    if rank > 20:
        break
    ks_ext = ''.join(az_chr(v) for v in ks[:-11])
    print(f"    {rank:3d}. PT='{pt_ext}BERLINCLOCK' "
          f"KS='{ks_ext}' score={score:.1f}")

# ── Convergence test: do forward and reverse agree? ─────────────────────

print(f"\n{'='*78}")
print("CONVERGENCE: DO FORWARD AND REVERSE MEET?")
print("=" * 78)

# This would require running both directions and checking overlap
# For now, just report the overlapping position ranges
print("Forward covers: positions 34-62 (after ENE)")
print("Reverse covers: positions 62-34 (before BCL)")
print("If both directions converge on the same plaintext in the overlap zone,")
print("that's strong evidence for the correct decryption.")

# ── Save results ────────────────────────────────────────────────────────
outfile = os.path.join(_ROOT, "results", "e_beam_search_pt_extension.json")
os.makedirs(os.path.dirname(outfile), exist_ok=True)

output = {
    "experiment": "e_beam_search_pt_extension",
    "timestamp": datetime.now().isoformat(),
    "description": "Beam search plaintext extension from ENE rightward and BCL leftward",
    "beam_width": BEAM_WIDTH,
    "restricted_values": RESTRICTED_VALUES,
}

with open(outfile, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to {outfile}")
