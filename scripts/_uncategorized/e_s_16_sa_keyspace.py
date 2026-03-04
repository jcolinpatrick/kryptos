#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-16: SA directly over key space (no transposition).

Model: K4 = Vigenère(PT, key) where key is an arbitrary 97-letter sequence.
This is the simplest possible model. SA optimizes the key to maximize
quadgram fitness of the decrypted text.

Unlike E-S-08 (which searches over transposition permutations + short periodic key),
this searches directly over the 97 key values, constrained by:
1. The 24 known key values at crib positions (fixed, not optimized)
2. Bean equality: key[27] = key[65] (enforced)

This tests the hypothesis that K4 is simple Vigenère with a 97-letter
non-repeating key (running key from unknown source).

If SA finds a key producing English plaintext, we can then try to identify
the running key source.

Also tests Beaufort variant.
"""

import json
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_ENTRIES, MOD

# ═══ Setup ════════════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = set(p for p, _ in _sorted)
CRIB_DICT = {p: c for p, c in _sorted}
PT_INT = {p: ord(c) - 65 for p, c in _sorted}

# Known key values (Vigenère)
VIG_KEY_KNOWN = {}
for p in CRIB_POS:
    VIG_KEY_KNOWN[p] = (CT_INT[p] - PT_INT[p]) % 26

# Known key values (Beaufort)
BEAU_KEY_KNOWN = {}
for p in CRIB_POS:
    BEAU_KEY_KNOWN[p] = (CT_INT[p] + PT_INT[p]) % 26

# Free positions (not constrained by cribs)
FREE_POS = [i for i in range(CT_LEN) if i not in CRIB_POS]

# Bean constraint positions
BEAN_POS = (27, 65)

# Load quadgrams
qg_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(qg_path) as f:
    qg_data = json.load(f)

QG = qg_data['logp'] if 'logp' in qg_data else qg_data
QG_FLOOR = min(QG.values())
QG_BEST = max(QG.values())

print(f"Quadgram scorer: {len(QG)} entries, floor={QG_FLOOR:.3f}, best={QG_BEST:.3f}")

# Pre-compute: for each quadgram starting position, which positions are free?
# This helps us do incremental scoring when changing one key position.


def decrypt_vig(key):
    return ''.join(chr((CT_INT[i] - key[i]) % 26 + 65) for i in range(CT_LEN))


def decrypt_beau(key):
    return ''.join(chr((key[i] - CT_INT[i]) % 26 + 65) for i in range(CT_LEN))


def qg_score(text):
    score = 0.0
    for i in range(len(text) - 3):
        score += QG.get(text[i:i+4], QG_FLOOR)
    return score


def sa_search(variant, n_restarts, n_steps, seed=42):
    """SA over free key positions to maximize quadgram fitness."""
    rng = random.Random(seed)

    known_key = VIG_KEY_KNOWN if variant == 'vigenere' else BEAU_KEY_KNOWN
    decrypt_fn = decrypt_vig if variant == 'vigenere' else decrypt_beau

    best_global_score = -1e18
    best_global_key = None
    best_global_pt = None

    for restart in range(n_restarts):
        # Initialize key: known values at crib positions, random elsewhere
        key = [0] * CT_LEN
        for p, v in known_key.items():
            key[p] = v

        # Bean constraint: key[27] = key[65] (already set from cribs if both are crib positions)
        # Both 27 and 65 are crib positions, so they're already fixed

        for p in FREE_POS:
            key[p] = rng.randint(0, 25)

        # Decrypt and score
        pt = decrypt_fn(key)
        current_score = qg_score(pt)

        best_score = current_score
        best_key = list(key)
        best_pt = pt

        # SA parameters
        T_start = 2.0
        T_end = 0.01

        for step in range(n_steps):
            T = T_start * (T_end / T_start) ** (step / n_steps)

            # Pick a random free position and change its key value
            pos = rng.choice(FREE_POS)
            old_val = key[pos]
            new_val = rng.randint(0, 25)
            if new_val == old_val:
                new_val = (old_val + rng.randint(1, 25)) % 26

            key[pos] = new_val

            # Recompute affected quadgrams (positions pos-3 to pos)
            # For efficiency, just recompute full score
            # (incremental would be better but this is simpler)
            pt_list = list(pt)
            if variant == 'vigenere':
                pt_list[pos] = chr((CT_INT[pos] - new_val) % 26 + 65)
            else:
                pt_list[pos] = chr((new_val - CT_INT[pos]) % 26 + 65)

            # Compute score delta for affected quadgrams
            old_qg = 0.0
            new_qg = 0.0
            for start in range(max(0, pos - 3), min(CT_LEN - 3, pos + 1)):
                old_qg += QG.get(pt[start:start+4], QG_FLOOR)
                new_qg += QG.get(''.join(pt_list[start:start+4]), QG_FLOOR)

            delta = new_qg - old_qg
            new_score = current_score + delta

            if delta > 0 or rng.random() < math.exp(delta / T):
                pt = ''.join(pt_list)
                current_score = new_score
                if current_score > best_score:
                    best_score = current_score
                    best_key = list(key)
                    best_pt = pt
            else:
                key[pos] = old_val

        if best_score > best_global_score:
            best_global_score = best_score
            best_global_key = list(best_key)
            best_global_pt = best_pt

        if (restart + 1) % 10 == 0 or restart == 0:
            qgc = best_global_score / max(CT_LEN - 3, 1)
            print(f"  [{restart+1:>4}/{n_restarts}] qg/c={qgc:.3f}  "
                  f"PT={best_global_pt[:40]}...")
            sys.stdout.flush()

    return best_global_score, best_global_key, best_global_pt


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-16: SA over Key Space (No Transposition)")
    print("=" * 60)
    print(f"CT length: {CT_LEN}")
    print(f"Fixed positions (cribs): {len(CRIB_POS)}")
    print(f"Free positions: {len(FREE_POS)}")
    print(f"Model: CT[i] = variant(PT[i], key[i])")
    print()

    all_results = {}

    for variant in ['vigenere', 'beaufort']:
        print(f"\n{'=' * 60}")
        print(f"  {variant.upper()} — 50 restarts × 500K steps")
        print(f"{'=' * 60}")

        score, key, pt = sa_search(
            variant=variant,
            n_restarts=50,
            n_steps=500_000,
            seed=12345,
        )

        qgc = score / max(CT_LEN - 3, 1)

        # Check crib matches (should be 24/24 by construction)
        crib_ok = sum(1 for p in CRIB_POS
                      if pt[p] == CRIB_DICT[p])

        # Check Bean
        bean_ok = (key[27] == key[65])

        # IC of plaintext
        freq = [0] * 26
        for c in pt:
            freq[ord(c) - 65] += 1
        ic = sum(f * (f - 1) for f in freq) / (CT_LEN * (CT_LEN - 1))

        print(f"\n  Best: qg/c={qgc:.3f}  cribs={crib_ok}/24  bean={bean_ok}  IC={ic:.4f}")
        print(f"  PT: {pt}")
        print(f"  Key: {' '.join(chr(k+65) for k in key)}")

        # Check if key matches any known text
        key_str = ''.join(chr(k+65) for k in key)

        all_results[variant] = {
            "score": round(score, 3),
            "qg_per_char": round(qgc, 3),
            "crib_matches": crib_ok,
            "bean_pass": bean_ok,
            "ic": round(ic, 4),
            "plaintext": pt,
            "key_str": key_str,
        }

    # ═══ Summary ═══════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Time: {elapsed:.0f}s ({elapsed/60:.1f} min)")

    for var, res in all_results.items():
        print(f"\n  {var}:")
        print(f"    qg/c: {res['qg_per_char']:.3f} (English≈-4.29, Random≈-7.49)")
        print(f"    IC: {res['ic']:.4f} (English≈0.0667)")
        print(f"    PT: {res['plaintext'][:60]}...")

    # English-likeness assessment
    best_var = max(all_results, key=lambda v: all_results[v]["qg_per_char"])
    best_qgc = all_results[best_var]["qg_per_char"]
    best_ic = all_results[best_var]["ic"]

    if best_qgc > -4.0 and best_ic > 0.060:
        verdict = "ENGLISH-LIKE — investigate key source"
    elif best_qgc > -4.5:
        verdict = "PARTIAL ENGLISH — fragments but not coherent"
    elif best_qgc > -5.5:
        verdict = "MIXED — some English patterns"
    else:
        verdict = "NO SIGNAL"

    print(f"\n  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_16_sa_keyspace.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-16",
            "hypothesis": "K4 is simple Vigenere/Beaufort with non-repeating key",
            "total_time_s": round(elapsed, 1),
            "verdict": verdict,
            "results": all_results,
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_16_sa_keyspace.py")
    print(f"\nRESULT: best_qgc={best_qgc:.3f} verdict={verdict}")


if __name__ == "__main__":
    main()
