#!/usr/bin/env python3
"""Exhaustive brute-force of period-27 (and 28, 29) Beaufort keys.

CRITICAL DISCOVERY: The existing proof covers periods 1-26 only.
For period 27, ALL 24 crib positions have DISTINCT residues mod 27,
so there is NO crib-based contradiction. This period has NEVER been tested.

Period 27: 24/27 slots filled from cribs, 3 FREE SLOTS.
  Brute force: 26^3 = 17,576 completions — done in <1 second.

Period 28: 4 free slots = 26^4 = 456,976 combos — ~1 sec.
Period 29: 5 free slots = 26^5 ≈ 11.9M combos — ~15 sec.

Scoring: quadgrams on full 97-char decryption. Cribs are always correct
since the 24 fixed key slots are derived directly from cribs.
Report any combo with score > -3.8/char (well above noise floor of -4.2).
"""
import sys, itertools, math
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_WORDS

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Quadgram scorer
import json
from pathlib import Path
qg_file = Path("data/english_quadgrams.json")
with open(qg_file) as f:
    QG = json.load(f)
# QG values are already log probabilities (negative floats)
QG_FLOOR = min(QG.values()) - 2.0  # below worst known quadgram

def score_text(text):
    """Sum log-prob of all quadgrams. QG values are already log-probs."""
    text = text.upper()
    n = len(text) - 3
    if n <= 0:
        return QG_FLOOR
    s = sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(n))
    return s / n

HAVE_QG = True
print(f"Quadgrams: {len(QG)} entries, floor={QG_FLOOR:.3f}")
# Verify: 'EASTNORTHEAST' should score better than random
test_good = score_text('EASTNORTHEAST')
test_bad = score_text('XKQWZJFVBMHYP')
print(f"Score test: EASTNORTHEAST={test_good:.3f}, random={test_bad:.3f}")

# Build crib key values
crib_key = {}
for (start, word) in CRIB_WORDS:
    for j, ch in enumerate(word):
        pos = start + j
        ct_ch = CT[pos]
        key_val = (AZ.index(ch) + AZ.index(ct_ch)) % 26
        crib_key[pos] = key_val

def decrypt_beaufort(ct_str, key_cycle):
    """Beaufort A=0: PT[i] = (key[i] - CT[i]) mod 26."""
    return ''.join(AZ[(k - AZ.index(c)) % 26] for c, k in zip(ct_str, key_cycle))

def test_period(period, verbose=True):
    """Test all period-P completions."""
    # Fill known key slots from crib positions
    key_slots = {}
    for pos, kval in crib_key.items():
        slot = pos % period
        if slot in key_slots and key_slots[slot] != kval:
            print(f"  Period {period}: CONTRADICTION at slot {slot}!")
            return
        key_slots[slot] = kval

    free_slots = [s for s in range(period) if s not in key_slots]
    n_free = len(free_slots)
    n_combos = 26 ** n_free

    if verbose:
        print(f"\nPeriod {period}: {len(key_slots)}/{period} slots known, {n_free} free")
        print(f"  Known: {' '.join(AZ[key_slots[s]] if s in key_slots else '?' for s in range(period))}")
        print(f"  Free slots: {free_slots}")
        print(f"  Testing {n_combos:,} completions...")

    best_score = -999
    best_key = None
    best_pt = None
    top_results = []

    for vals in itertools.product(range(26), repeat=n_free):
        # Build full key cycle
        full_key = dict(key_slots)
        for slot, val in zip(free_slots, vals):
            full_key[slot] = val

        # Apply to full CT97
        key_cycle = [full_key[i % period] for i in range(len(CT))]
        pt = decrypt_beaufort(CT, key_cycle)

        # Score
        sc = score_text(pt)
        if sc > best_score:
            best_score = sc
            best_key = ''.join(AZ[full_key[s]] for s in range(period))
            best_pt = pt

        # Track all above threshold
        if sc > -3.8:
            top_results.append((sc, ''.join(AZ[full_key[s]] for s in range(period)), pt))

    if verbose or top_results:
        print(f"  Best score: {best_score:.4f}/char")
        print(f"  Best key: {best_key}")
        print(f"  Best PT (first 60): {best_pt[:60]}")
        if best_pt:
            # Verify cribs
            for start, word in CRIB_WORDS:
                print(f"  Crib '{word}' at {start}: '{best_pt[start:start+len(word)]}' {'✓' if best_pt[start:start+len(word)]==word else '✗'}")

    if top_results:
        print(f"\n  *** {len(top_results)} RESULTS ABOVE THRESHOLD (-3.8) ***")
        for sc, key, pt in sorted(top_results, reverse=True)[:10]:
            print(f"  score={sc:.4f} key={key} PT={pt[:80]}")
    else:
        noise = -4.2 if HAVE_QG else -0.5
        print(f"  No results above threshold -3.8 (noise floor ≈ {noise}). Period {period} appears NOISE.")

    return best_score, best_key, top_results

# Run tests
print("=== Exhaustive Period 27/28/29 Brute-Force (Never Previously Tested) ===\n")
print(f"Quadgram scorer: {'ACTIVE' if HAVE_QG else 'FALLBACK'}")

r27 = test_period(27)
print()

# Only run 28 if 27 shows nothing
print("--- Period 28 ---")
r28 = test_period(28, verbose=True)
print()

# Period 29 is 11.9M combos - run if 27/28 show nothing
print("--- Period 29 (11.9M combos, ~15s) ---")
r29 = test_period(29, verbose=True)
print()

# Summary
print("=== Summary ===")
for p, r in [(27, r27), (28, r28), (29, r29)]:
    if r:
        best_sc, best_key, hits = r
        print(f"Period {p}: best={best_sc:.4f}, signals={len(hits)}")
        if hits:
            print(f"  *** POSSIBLE SIGNAL at period {p}! ***")
