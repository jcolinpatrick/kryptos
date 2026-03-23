#!/usr/bin/env python3
"""
Null Palette as Gromark Primer on CT97
=======================================
Cipher:   Gromark (lagged Fibonacci polyalphabetic)
Family:   grille
Status:   active
Keyspace: 5040 perms × 25 bases × 3 variants × 2 alphabets = 756,000
Last run: never
Best score: n/a

Tests null palette letters {B,G,I,K,O,W,Z} = {1,6,8,10,14,22,25} (A=0)
as a 7-digit Gromark primer on raw CT97 in all 5040 permutations.

Bean (2021) argued Gromark is the most likely K4 cipher.
Prior Gromark exhaustive sweep on CT97 only covered plen 2-6 (3.2B configs).
This test specifically checks plen=7 with the palette values.

NOTE: For bases < 26, primer digits must be < base. Configs where any
palette value >= base are automatically skipped (invalid Gromark primer).
This means most bases < 26 will have 0 valid configs.

Usage:
    PYTHONPATH=src python3 -u scripts/grille/e_palette_gromark_primer.py
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from itertools import permutations

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, ALPH, KRYPTOS_ALPHABET, MOD, CRIB_DICT, N_CRIBS, CRIB_ENTRIES
from kryptos.kernel.scoring.crib_score import score_cribs

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CT_LEN = len(CT)
assert CT_LEN == 97

AZ = ALPH
KA = KRYPTOS_ALPHABET

# Null palette: B=1, G=6, I=8, K=10, O=14, W=22, Z=25 (A=0 indexing)
PALETTE_LETTERS = "BGIKOWZ"
PALETTE_VALS = tuple(AZ.index(ch) for ch in PALETTE_LETTERS)
assert PALETTE_VALS == (1, 6, 8, 10, 14, 22, 25), f"Got {PALETTE_VALS}"

# Build sorted crib entries for early termination
_crib_entries = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POSITIONS = [e[0] for e in _crib_entries]
CRIB_CHARS = [e[1] for e in _crib_entries]

VARIANTS = ["beaufort", "vigenere", "variant_beaufort"]
ALPHABETS = [("AZ", AZ), ("KA", KA)]


# ---------------------------------------------------------------------------
# Gromark core
# ---------------------------------------------------------------------------

def gromark_expand(primer, length, base):
    """Expand primer via Fibonacci-like recurrence mod base."""
    L = len(primer)
    key = list(primer)
    while len(key) < length:
        key.append((key[-L] + key[-(L - 1)]) % base)
    return key


def compute_required_keys(alphabet, variant):
    """Compute required keystream values at each crib position."""
    required = []
    for pos, pt_ch in _crib_entries:
        ct_ch = CT[pos]
        cn = alphabet.index(ct_ch)
        pn = alphabet.index(pt_ch)
        if variant == "vigenere":
            k = (cn - pn) % 26
        elif variant == "beaufort":
            k = (cn + pn) % 26
        elif variant == "variant_beaufort":
            k = (pn - cn) % 26
        else:
            raise ValueError(f"Unknown variant: {variant}")
        required.append(k)
    return required


def decrypt_gromark(ct, key, variant, alphabet):
    """Decrypt ciphertext using expanded Gromark key."""
    pt = []
    for i, ch in enumerate(ct):
        cn = alphabet.index(ch)
        kv = key[i]
        if variant == "vigenere":
            pn = (cn - kv) % 26
        elif variant == "beaufort":
            pn = (kv - cn) % 26
        elif variant == "variant_beaufort":
            pn = (cn + kv) % 26
        else:
            raise ValueError(variant)
        pt.append(alphabet[pn])
    return "".join(pt)


# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------

def main():
    t_start = time.time()
    out_dir = os.path.join(_ROOT, "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "e_palette_gromark_primer.json")

    all_perms = list(permutations(PALETTE_VALS))
    n_perms = len(all_perms)
    assert n_perms == 5040, f"Expected 5040 permutations, got {n_perms}"

    min_base = 2
    max_base = 26

    total_tested = 0
    total_skipped = 0
    total_crib_pass = 0
    best_score = 0
    best_results = []  # top 20 results
    per_base_best = {}

    print(f"Palette Gromark Primer Sweep on CT97")
    print(f"  Palette: {PALETTE_LETTERS} = {PALETTE_VALS}")
    print(f"  Permutations: {n_perms}")
    print(f"  Bases: {min_base}-{max_base}")
    print(f"  Variants: {len(VARIANTS)}")
    print(f"  Alphabets: {len(ALPHABETS)}")
    print(f"  Max configs: {n_perms * (max_base - min_base + 1) * len(VARIANTS) * len(ALPHABETS):,}")
    print()

    for base in range(min_base, max_base + 1):
        # Check if any palette value >= base (invalid for this base)
        max_val = max(PALETTE_VALS)
        if max_val >= base:
            n_skip = n_perms * len(VARIANTS) * len(ALPHABETS)
            total_skipped += n_skip
            continue

        base_best_score = 0
        base_tested = 0

        for alpha_label, alphabet in ALPHABETS:
            # Precompute CT as numbers in this alphabet
            ct_nums = [alphabet.index(ch) for ch in CT]

            for variant in VARIANTS:
                # Compute required keys at crib positions
                required = compute_required_keys(alphabet, variant)

                for primer in all_perms:
                    # Expand primer
                    key = gromark_expand(primer, CT_LEN, base)

                    # Early crib check: verify key matches at all crib positions
                    match = True
                    crib_hits = 0
                    for idx in range(len(CRIB_POSITIONS)):
                        pos = CRIB_POSITIONS[idx]
                        if key[pos] == required[idx]:
                            crib_hits += 1
                        else:
                            match = False
                            # Don't break yet -- count hits for scoring

                    total_tested += 1
                    base_tested += 1

                    if crib_hits > base_best_score:
                        base_best_score = crib_hits

                    if crib_hits >= 6:  # report threshold
                        # Full decrypt and score
                        pt = decrypt_gromark(CT, key, variant, alphabet)
                        score = score_cribs(pt)

                        result = {
                            "score": score,
                            "crib_hits": crib_hits,
                            "base": base,
                            "variant": variant,
                            "alphabet": alpha_label,
                            "primer": list(primer),
                            "primer_str": ",".join(str(d) for d in primer),
                            "plaintext_snippet": pt[:40],
                            "method": f"gromark/b{base}/p7/{variant}/{alpha_label}/palette"
                        }

                        best_results.append(result)
                        best_results.sort(key=lambda x: -x["score"])
                        best_results = best_results[:20]

                        if score > best_score:
                            best_score = score
                            print(f"  NEW BEST: {score}/24 | base={base} {variant} {alpha_label} | primer={list(primer)}")

                    if match:
                        total_crib_pass += 1
                        pt = decrypt_gromark(CT, key, variant, alphabet)
                        score = score_cribs(pt)
                        print(f"  CRIB PASS! {score}/24 | base={base} {variant} {alpha_label} | primer={list(primer)}")
                        print(f"    PT: {pt}")

        per_base_best[base] = {
            "tested": base_tested,
            "best_crib_hits": base_best_score,
        }

        if base_tested > 0:
            print(f"  Base {base:2d}: {base_tested:,} tested, best crib hits={base_best_score}/24")

    elapsed = time.time() - t_start

    # Summary
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Total tested:  {total_tested:,}")
    print(f"  Total skipped: {total_skipped:,} (palette values >= base)")
    print(f"  Crib passes:   {total_crib_pass}")
    print(f"  Best score:    {best_score}/24")
    print(f"  Elapsed:       {elapsed:.1f}s")
    print(f"  Rate:          {total_tested / max(elapsed, 0.001):,.0f}/s")

    if best_results:
        print(f"\n  Top results (>= 6/24 crib hits):")
        for r in best_results[:10]:
            print(f"    {r['score']}/24 | base={r['base']} {r['variant']} {r['alphabet']} | primer={r['primer_str']}")

    # Save results
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "experiment": "palette_gromark_primer",
        "description": "Null palette {B,G,I,K,O,W,Z} as 7-digit Gromark primer on raw CT97",
        "palette": {
            "letters": PALETTE_LETTERS,
            "values_A0": list(PALETTE_VALS),
        },
        "params": {
            "min_base": min_base,
            "max_base": max_base,
            "primer_length": 7,
            "n_permutations": n_perms,
            "variants": VARIANTS,
            "alphabets": [a[0] for a in ALPHABETS],
            "max_configs": n_perms * (max_base - min_base + 1) * len(VARIANTS) * len(ALPHABETS),
        },
        "results": {
            "total_tested": total_tested,
            "total_skipped": total_skipped,
            "total_crib_pass": total_crib_pass,
            "best_score": best_score,
            "elapsed_seconds": round(elapsed, 2),
            "per_base": per_base_best,
            "top_results": best_results[:20],
        },
        "verdict": "ELIMINATED" if best_score < 10 else "INVESTIGATE",
        "note": (
            f"Only base 26 is valid (all palette values < 26). "
            f"Bases 2-25 require digits < base, but max palette value = 25."
        ),
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
