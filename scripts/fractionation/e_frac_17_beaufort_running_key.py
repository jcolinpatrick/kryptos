#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-17: Beaufort Running Key Search Against Reference Texts

E-FRAC-16 found that the Beaufort key at crib positions has significantly
concentrated values (entropy at 0.3rd percentile). This experiment tests
whether the Beaufort key could be derived from a known text (running key).

For each reference text:
1. Slide a window of length 97 across the text
2. At each offset, check how many of the 24 known Beaufort key values match
3. Report any offsets with matches above random expectation

Also tests Vigenere running key for completeness.

Under direct correspondence (no transposition):
- Beaufort running key: K4_CT[i] = (keytext[i] - PT[i]) mod 26
  → keytext[i] = (K4_CT[i] + PT[i]) mod 26 at known positions
- Vigenere running key: K4_CT[i] = (PT[i] + keytext[i]) mod 26
  → keytext[i] = (K4_CT[i] - PT[i]) mod 26 at known positions
"""

import json
import os
import re
import time
from pathlib import Path

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)


def clean_text(text: str) -> str:
    """Extract only uppercase alphabetic characters from text."""
    return re.sub(r'[^A-Z]', '', text.upper())


def load_text(path: str) -> str:
    """Load and clean a reference text."""
    with open(path) as f:
        return clean_text(f.read())


def build_key_targets() -> dict:
    """Build the target key values at each crib position for Beaufort and Vigenere."""
    targets = {}
    for variant_name, ene_key, bc_key in [
        ('beaufort', BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC),
        ('vigenere', VIGENERE_KEY_ENE, VIGENERE_KEY_BC),
    ]:
        key_map = {}
        for i, pos in enumerate(range(21, 34)):
            key_map[pos] = ene_key[i]
        for i, pos in enumerate(range(63, 74)):
            key_map[pos] = bc_key[i]
        targets[variant_name] = key_map
    return targets


def search_running_key(clean_text: str, targets: dict, variant: str) -> list:
    """Search for running key matches in the text.

    For each starting offset in the text, check how many of the 24 target
    key values match the text character at the corresponding position.

    Returns list of (offset, n_matches, matched_positions) for matches >= threshold.
    """
    text_len = len(clean_text)
    if text_len < CT_LEN:
        return []

    key_targets = targets[variant]
    results = []
    best_match = 0
    best_offset = -1

    for offset in range(text_len - CT_LEN + 1):
        n_match = 0
        matched = []
        for pos, target_val in key_targets.items():
            text_val = ALPH_IDX[clean_text[offset + pos]]
            if text_val == target_val:
                n_match += 1
                matched.append(pos)
        if n_match > best_match:
            best_match = n_match
            best_offset = offset
        if n_match >= 3:  # Store anything above trivial
            results.append((offset, n_match, matched))

    return results, best_match, best_offset


def main():
    start_time = time.time()
    results = {}

    print("=" * 70)
    print("E-FRAC-17: Beaufort Running Key Search")
    print("=" * 70)

    targets = build_key_targets()

    # Print target key values for reference
    print("\n  Target key values (what the running key text must have at each position):")
    for variant in ['beaufort', 'vigenere']:
        key_map = targets[variant]
        print(f"\n  {variant.upper()}:")
        for start, end, name in [(21, 34, "ENE"), (63, 74, "BC")]:
            vals = [key_map[p] for p in range(start, end)]
            letters = ''.join(ALPH[v] for v in vals)
            print(f"    {name} (pos {start}-{end-1}): {letters}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Expected matches under random
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Each position has a 1/26 chance of matching
    # Expected matches = 24/26 ≈ 0.923
    # P(X >= k) for X ~ Binomial(24, 1/26)
    import math
    print(f"\n  Random expectation: 24 × (1/26) = {24/26:.3f} matches per offset")
    print(f"  P(X>=3) = {sum(math.comb(24,k) * (1/26)**k * (25/26)**(24-k) for k in range(3,25)):.4f}")
    print(f"  P(X>=4) = {sum(math.comb(24,k) * (1/26)**k * (25/26)**(24-k) for k in range(4,25)):.4f}")
    print(f"  P(X>=5) = {sum(math.comb(24,k) * (1/26)**k * (25/26)**(24-k) for k in range(5,25)):.6f}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Search all reference texts
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ref_dir = Path("reference")
    text_files = [
        ("carter_gutenberg", ref_dir / "carter_gutenberg.txt"),
        ("carter_vol1_extract", ref_dir / "carter_vol1_extract.txt"),
        ("cia_charter", ref_dir / "running_key_texts/cia_charter.txt"),
        ("jfk_berlin", ref_dir / "running_key_texts/jfk_berlin.txt"),
        ("nsa_act_1947", ref_dir / "running_key_texts/nsa_act_1947.txt"),
        ("reagan_berlin", ref_dir / "running_key_texts/reagan_berlin.txt"),
        ("udhr", ref_dir / "running_key_texts/udhr.txt"),
    ]

    # Also construct combined K1-K3 plaintext as a candidate key
    # K1 plaintext (publicly known)
    k1_pt = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABORDSECRETOFILLUSIONIMAGESWERETHEFORMOFFICTION"
    # K2 plaintext (publicly known)
    k2_pt = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESTHLANABORDSECURIYORDERSTILLEXISTXWHOKNOWSWHOKNOWSWHOKNOWSLAYERTWO"
    # K3 plaintext (publicly known)
    k3_pt = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORDSRISTHATHADORDSBEENHIDDENFORHUNDREDSOFYEARSWOULDBEBROUGHTTOLIGHT"

    # Clean them
    k123_combined = clean_text(k1_pt + k2_pt + k3_pt)

    text_search_results = {}

    for variant in ['beaufort', 'vigenere']:
        print(f"\n{'='*50}")
        print(f"  Variant: {variant.upper()}")
        print(f"{'='*50}")

        variant_results = {}

        for text_name, text_path in text_files:
            if not text_path.exists():
                continue
            text = load_text(str(text_path))
            hits, best_n, best_off = search_running_key(text, targets, variant)

            n_offsets = len(text) - CT_LEN + 1
            n_ge3 = sum(1 for _, n, _ in hits if n >= 3)
            n_ge4 = sum(1 for _, n, _ in hits if n >= 4)

            print(f"\n  {text_name} ({len(text)} chars, {n_offsets} offsets):")
            print(f"    Best: {best_n}/24 matches at offset {best_off}")
            print(f"    Offsets with ≥3 matches: {n_ge3} ({n_ge3/max(n_offsets,1)*100:.2f}%)")
            print(f"    Offsets with ≥4 matches: {n_ge4}")

            if best_n >= 3:
                # Show top matches
                top_hits = sorted(hits, key=lambda x: -x[1])[:5]
                for off, n, matched in top_hits:
                    key_excerpt = text[off:off+CT_LEN] if off + CT_LEN <= len(text) else text[off:]
                    print(f"    Offset {off}: {n} matches at positions {matched}")
                    print(f"      Key text: {key_excerpt[:40]}...")

            variant_results[text_name] = {
                'text_length': len(text),
                'n_offsets': n_offsets,
                'best_matches': best_n,
                'best_offset': best_off,
                'n_ge3': n_ge3,
                'n_ge4': n_ge4,
            }

        # Also search K1-K3 combined plaintext
        text = k123_combined
        hits, best_n, best_off = search_running_key(text, targets, variant)
        n_offsets = max(len(text) - CT_LEN + 1, 0)
        n_ge3 = sum(1 for _, n, _ in hits if n >= 3) if hits else 0

        print(f"\n  K1-K3 combined plaintext ({len(text)} chars, {n_offsets} offsets):")
        print(f"    Best: {best_n}/24 matches at offset {best_off}")
        print(f"    Offsets with ≥3 matches: {n_ge3}")

        if best_n >= 3 and hits:
            top_hits = sorted(hits, key=lambda x: -x[1])[:3]
            for off, n, matched in top_hits:
                key_excerpt = text[off:off+CT_LEN] if off + CT_LEN <= len(text) else text[off:]
                print(f"    Offset {off}: {n} matches at positions {matched}")
                print(f"      Key text: {key_excerpt[:40]}...")

        variant_results['k123_combined'] = {
            'text_length': len(text),
            'n_offsets': n_offsets,
            'best_matches': best_n,
            'best_offset': best_off,
            'n_ge3': n_ge3,
        }

        text_search_results[variant] = variant_results

    results['search_results'] = text_search_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # What expected max matches for these text lengths?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    import random
    print(f"\n{'='*50}")
    print(f"  Monte Carlo: expected best match for random text")
    print(f"{'='*50}")
    random.seed(42)

    for n_offsets_test in [1000, 10000, 100000, 300000]:
        mc_bests = []
        for _ in range(1000):
            best = 0
            for _ in range(n_offsets_test):
                m = sum(1 for _ in range(24) if random.randint(0, 25) == random.randint(0, 25))
                if m > best:
                    best = m
            mc_bests.append(best)
        mc_mean = sum(mc_bests) / len(mc_bests)
        mc_max = max(mc_bests)
        print(f"  {n_offsets_test:>7d} offsets: expected best = {mc_mean:.1f}/24, max observed = {mc_max}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Summary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    runtime = time.time() - start_time

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    all_bests = {}
    for variant in ['beaufort', 'vigenere']:
        for text_name, info in text_search_results[variant].items():
            key = f"{variant}/{text_name}"
            all_bests[key] = info['best_matches']

    best_overall = max(all_bests.items(), key=lambda x: x[1])
    print(f"\n  Best overall: {best_overall[0]} — {best_overall[1]}/24 matches")
    print(f"\n  All results:")
    for key, n in sorted(all_bests.items(), key=lambda x: -x[1]):
        if n >= 2:
            print(f"    {key:45s}: {n}/24")

    any_signal = best_overall[1] >= 5
    if any_signal:
        print(f"\n  *** POTENTIAL SIGNAL: {best_overall[1]}/24 matches at {best_overall[0]} ***")
    else:
        print(f"\n  No running key source found above random expectation")
        print(f"  The key is NOT derived from any of the tested reference texts")

    print(f"\nRuntime: {runtime:.1f}s")

    verdict = "SIGNAL" if any_signal else "NOISE"
    print(f"RESULT: best={best_overall[1]}/24 verdict={verdict}")

    results['summary'] = {
        'best_match': best_overall[1],
        'best_source': best_overall[0],
        'verdict': verdict,
        'runtime': runtime,
    }

    # Save
    out_dir = Path("results/frac")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "e_frac_17_beaufort_running_key.json"
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
