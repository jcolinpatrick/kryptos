#!/usr/bin/env python3
"""
e_berlin_clock_route.py — Berlin Clock as routing permutation for K4 row key.

HYPOTHESIS: The 24 row-key values (from the split-coordinate Polybius model)
are routed through a Berlin clock structure. Undoing the routing reveals a
simpler underlying key.

PHASE 1: World Clock (Urania Weltzeituhr) — circular 24-node permutations
  - 24 rotations × 2 directions = 48
  - Step-k walks (k=1..23) × 2 directions = 46
  - Boustrophedon variants = ~24
  - Total: ~120 walks

PHASE 2: Mengenlehreuhr — banded 1+4+4+11+4 permutations
  - Band-order permutations: 5! = 120
  - Within-band direction: 2^5 = 32
  - Circular 11-band: 11 start positions
  - Combined (pruned): ~1000 walks

For each walk, check the permuted sequence for:
  - Periodicity (period ≤ 12)
  - Keyword row-value match
  - IC above random (> 0.20)
  - Palindrome / symmetry
  - Full-keystream letter permutation → readable fragment
"""

import sys
import os
import json
import time
import math
from collections import Counter
from itertools import permutations, product

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CRIB_DICT, KRYPTOS_ALPHABET, ALPH, ALPH_IDX,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
)

GRID_COLS = 5
GRID_ROWS = 6
KA_IDX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}
CRIB_POSITIONS = sorted(CRIB_DICT.keys())


def ka_row(ch):
    return KA_IDX[ch] // GRID_COLS


# ── Derive row keys ─────────────────────────────────────────────────────

ROW_KEY_BEAU = []
ROW_KEY_VIG = []
for pos in CRIB_POSITIONS:
    ct_r = ka_row(CT[pos])
    pt_r = ka_row(CRIB_DICT[pos])
    ROW_KEY_BEAU.append((ct_r + pt_r) % GRID_ROWS)
    ROW_KEY_VIG.append((ct_r - pt_r) % GRID_ROWS)

FULL_KS = list(BEAUFORT_KEYSTREAM_AT_CRIBS)  # 24 letters


# ── Keywords to test against ─────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "SEVEN", "CHART",
    "DEFECTOR", "SHADOW", "ENIGMA", "ORDINATE", "EASTNORTHEAST", "CIPHER",
    "SECRET", "TOWER", "LAYER", "KOMPASS", "BERLIN", "CLOCK", "WELTZEIT",
    "ALEXANDERPLATZ", "MENGENLEHREUHR", "URANIA", "WINDROSE", "NORTHEAST",
    "INVISIBLE", "FORCES", "LUCID", "MEMORY", "UNDERGROUND", "BURIED",
    "IQLUSION", "DESPARATLY", "UNDERGRUUND", "VIRTUALLY", "DIGETAL",
    "PALIMPCEST", "SANBORN", "SCHEIDT", "WEBSTER", "CARTER", "HOWARD",
    "TUTANKHAMUN", "PHARAOH", "TOMB", "HIEROGLYPH", "ROSETTA",
    "POLYBIUS", "BEAUFORT", "VIGENERE", "AUTOKEY", "TABLEAU",
]


def keyword_row_pattern(keyword):
    """Get the cycling row-value pattern for a keyword on the KA grid."""
    return [ka_row(ch) for ch in keyword.upper() if ch.isalpha()]


KEYWORD_ROW_PATTERNS = {}
for kw in KEYWORDS:
    clean = "".join(ch for ch in kw.upper() if ch.isalpha())
    if clean:
        KEYWORD_ROW_PATTERNS[kw] = keyword_row_pattern(clean)


# ── Scoring functions ────────────────────────────────────────────────────

def check_periodicity(seq, max_period=12):
    """Check if sequence is periodic. Return best period and match count."""
    n = len(seq)
    best_period = 0
    best_matches = 0
    for p in range(1, min(max_period + 1, n)):
        matches = sum(1 for i in range(n) if seq[i] == seq[i % p])
        if matches > best_matches:
            best_matches = matches
            best_period = p
    return best_period, best_matches


def check_keyword_match(seq, patterns):
    """Check if sequence matches any keyword's cycling row pattern."""
    n = len(seq)
    best_kw = None
    best_score = 0
    for kw, pat in patterns.items():
        if len(pat) == 0:
            continue
        matches = sum(1 for i in range(n) if seq[i] == pat[i % len(pat)])
        if matches > best_score:
            best_score = matches
            best_kw = kw
    return best_kw, best_score


def compute_ic(seq):
    """Index of coincidence for a mod-6 sequence."""
    n = len(seq)
    if n <= 1:
        return 0.0
    counts = Counter(seq)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def is_palindrome(seq):
    return seq == seq[::-1]


def check_letters_readable(letters):
    """Check if a permuted letter sequence contains common English fragments."""
    s = "".join(letters)
    fragments = [
        "THE", "AND", "ING", "ION", "ENT", "FOR", "TER", "EST", "HER",
        "EAS", "NOR", "BER", "LIN", "CLO", "CK", "KEY", "SEC", "RET",
        "HID", "DEN", "COD", "WAR", "SPY", "CIA", "NSA", "KRY", "PTO",
    ]
    found = [f for f in fragments if f in s]
    return found, s


# ── Phase 1: World Clock (circular 24-node) ─────────────────────────────

def generate_circular_walks():
    """Generate all circular permutations of 24 positions."""
    walks = []
    n = 24

    # 1. Simple rotations (CW and CCW)
    for start in range(n):
        # Clockwise
        perm = [(start + i) % n for i in range(n)]
        walks.append((f"rotate_cw_{start}", perm))
        # Counter-clockwise
        perm = [(start - i) % n for i in range(n)]
        walks.append((f"rotate_ccw_{start}", perm))

    # 2. Step-k walks (visit every k-th position)
    for k in range(2, n):
        if math.gcd(k, n) == n:
            continue  # Would visit only 1 position
        # CW step-k
        perm = [(i * k) % n for i in range(n)]
        if len(set(perm)) == n:  # Must visit all 24
            walks.append((f"step_{k}_cw", perm))
        # CCW step-k
        perm = [((n - i) * k) % n for i in range(n)]
        if len(set(perm)) == n:
            walks.append((f"step_{k}_ccw", perm))

    # 3. Boustrophedon (half CW, half CCW from different starts)
    for start in range(n):
        half = n // 2
        first_half = [(start + i) % n for i in range(half)]
        second_half = [(start + half - 1 - i) % n for i in range(half)]
        # Avoid duplicates in second half
        remaining = [x for x in second_half if x not in first_half]
        if len(first_half) + len(remaining) == n:
            walks.append((f"boust_cw_start{start}", first_half + remaining))
        elif len(set(first_half + second_half)) == n:
            walks.append((f"boust_cw_start{start}", first_half + second_half))

    # 4. Reflection (reverse)
    walks.append(("reverse", list(range(n - 1, -1, -1))))

    # 5. Half-and-interleave (odd/even split)
    walks.append(("even_odd", [i for i in range(0, n, 2)] + [i for i in range(1, n, 2)]))
    walks.append(("odd_even", [i for i in range(1, n, 2)] + [i for i in range(0, n, 2)]))

    # 6. ENE-anchored rotations (if ENE = facet 4.5 ≈ position 4 or 5 on 24-hr clock
    # E-NE is ~67.5°, on a 24-position circle each position = 15°, so 67.5/15 = 4.5
    for ene_pos in [4, 5]:
        perm = [(ene_pos + i) % n for i in range(n)]
        walks.append((f"ene_anchor_{ene_pos}_cw", perm))
        perm = [(ene_pos - i) % n for i in range(n)]
        walks.append((f"ene_anchor_{ene_pos}_ccw", perm))

    # Deduplicate
    seen = set()
    unique_walks = []
    for name, perm in walks:
        key = tuple(perm)
        if key not in seen and len(set(perm)) == n:
            seen.add(key)
            unique_walks.append((name, perm))

    return unique_walks


# ── Phase 2: Mengenlehreuhr (banded 1+4+4+11+4) ────────────────────────

def generate_banded_walks():
    """Generate banded permutations for the Mengenlehreuhr structure."""
    bands = [1, 4, 4, 11, 4]  # 1+4+4+11+4 = 24
    band_starts = [0]
    for b in bands[:-1]:
        band_starts.append(band_starts[-1] + b)
    # band_starts = [0, 1, 5, 9, 20]

    walks = []

    # 1. Band-order permutations (5! = 120) × within-band direction (2^5 = 32)
    # Full combo is 3840 — sample the most interesting ones
    band_indices = list(range(5))

    for band_order in permutations(band_indices):
        # Default direction (L→R all bands)
        perm = []
        for b in band_order:
            start = band_starts[b]
            size = bands[b]
            perm.extend(range(start, start + size))
        name = f"order_{''.join(map(str, band_order))}_lr"
        walks.append((name, perm))

        # All reversed within bands
        perm_rev = []
        for b in band_order:
            start = band_starts[b]
            size = bands[b]
            perm_rev.extend(range(start + size - 1, start - 1, -1))
        name_rev = f"order_{''.join(map(str, band_order))}_rl"
        walks.append((name_rev, perm_rev))

        # Serpentine (alternating direction)
        perm_serp = []
        for idx, b in enumerate(band_order):
            start = band_starts[b]
            size = bands[b]
            if idx % 2 == 0:
                perm_serp.extend(range(start, start + size))
            else:
                perm_serp.extend(range(start + size - 1, start - 1, -1))
        name_serp = f"order_{''.join(map(str, band_order))}_serp"
        walks.append((name_serp, perm_serp))

    # 2. Circular starts for the 11-lamp band (Band 3, positions 9-19)
    for circ_start in range(11):
        perm = list(range(0, 9))  # Bands 0-2 normal
        band3 = [(9 + (circ_start + i) % 11) for i in range(11)]
        perm.extend(band3)
        perm.extend(range(20, 24))  # Band 4 normal
        walks.append((f"circ11_start{circ_start}", perm))

        # Also reversed
        perm_rev = list(range(0, 9))
        band3_rev = [(9 + (circ_start - i) % 11) for i in range(11)]
        perm_rev.extend(band3_rev)
        perm_rev.extend(range(20, 24))
        walks.append((f"circ11_start{circ_start}_rev", perm_rev))

    # Deduplicate
    seen = set()
    unique_walks = []
    for name, perm in walks:
        key = tuple(perm)
        if key not in seen and len(perm) == 24 and len(set(perm)) == 24:
            seen.add(key)
            unique_walks.append((name, perm))

    return unique_walks


# ── Test a single permutation ────────────────────────────────────────────

def test_permutation(name, perm, targets, ks_letters, kw_patterns):
    """Test one permutation against all targets. Return results if interesting."""
    results = []

    for target_name, target_seq in targets:
        permuted = [target_seq[perm[i]] for i in range(24)]

        # Periodicity
        best_period, period_matches = check_periodicity(permuted)
        period_score = period_matches / 24.0

        # Keyword match
        best_kw, kw_matches = check_keyword_match(permuted, kw_patterns)

        # IC
        ic = compute_ic(permuted)

        # Palindrome
        is_pal = is_palindrome(permuted)

        # Is it interesting?
        interesting = (
            period_matches >= 20 or  # Strong periodicity
            kw_matches >= 18 or      # Strong keyword match
            ic >= 0.22 or            # High IC (random = 0.167 for mod-6)
            is_pal                   # Perfect palindrome
        )

        if interesting:
            results.append({
                "walk": name,
                "target": target_name,
                "permuted_seq": permuted,
                "best_period": best_period,
                "period_matches": period_matches,
                "best_keyword": best_kw,
                "keyword_matches": kw_matches,
                "ic": round(ic, 4),
                "is_palindrome": is_pal,
            })

    # Full keystream letter permutation
    ks_permuted = [ks_letters[perm[i]] for i in range(24)]
    fragments, ks_str = check_letters_readable(ks_permuted)
    if fragments:
        results.append({
            "walk": name,
            "target": "keystream_letters",
            "permuted_str": ks_str,
            "fragments_found": fragments,
        })

    return results


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("EXPERIMENT: Berlin Clock Route/Permutation")
    print("=" * 70)

    targets = [
        ("beaufort_rows", ROW_KEY_BEAU),
        ("vigenere_rows", ROW_KEY_VIG),
    ]

    print(f"\nBeaufort row key: {ROW_KEY_BEAU}")
    print(f"Vigenère row key: {ROW_KEY_VIG}")
    print(f"Keystream letters: {''.join(FULL_KS)}")
    print(f"Keywords to test: {len(KEYWORD_ROW_PATTERNS)}")

    # Baseline (identity permutation)
    identity = list(range(24))
    for tname, tseq in targets:
        bp, bm = check_periodicity(tseq)
        bkw, bkm = check_keyword_match(tseq, KEYWORD_ROW_PATTERNS)
        ic = compute_ic(tseq)
        print(f"\n  Baseline {tname}: period={bp}({bm}/24), "
              f"kw={bkw}({bkm}/24), IC={ic:.4f}, palindrome={is_palindrome(tseq)}")

    all_results = []
    t0 = time.time()

    # ── Phase 1: World Clock ────────────────────────────────────────
    print("\n" + "=" * 70)
    print("PHASE 1: World Clock (circular 24-node)")
    print("=" * 70)

    circular_walks = generate_circular_walks()
    print(f"  Circular walks to test: {len(circular_walks)}")

    phase1_results = []
    best_p1 = {"period_matches": 0, "keyword_matches": 0}

    for name, perm in circular_walks:
        hits = test_permutation(name, perm, targets, FULL_KS, KEYWORD_ROW_PATTERNS)
        phase1_results.extend(hits)

        for h in hits:
            if h.get("period_matches", 0) > best_p1.get("period_matches", 0):
                best_p1 = h
            if h.get("keyword_matches", 0) > best_p1.get("keyword_matches", 0):
                best_p1 = h

    print(f"  Interesting results: {len(phase1_results)}")
    if phase1_results:
        # Show top results
        scored = [r for r in phase1_results if "period_matches" in r]
        scored.sort(key=lambda r: max(r.get("period_matches", 0), r.get("keyword_matches", 0)),
                    reverse=True)
        for r in scored[:10]:
            print(f"    {r['walk']} ({r['target']}): period={r['best_period']}({r['period_matches']}/24), "
                  f"kw={r['best_keyword']}({r['keyword_matches']}/24), IC={r['ic']}")

        # Show keystream fragment hits
        ks_hits = [r for r in phase1_results if "fragments_found" in r]
        for r in ks_hits[:5]:
            print(f"    {r['walk']}: KS='{r['permuted_str']}' fragments={r['fragments_found']}")

    # ── Phase 2: Mengenlehreuhr ─────────────────────────────────────
    print("\n" + "=" * 70)
    print("PHASE 2: Mengenlehreuhr (banded 1+4+4+11+4)")
    print("=" * 70)

    banded_walks = generate_banded_walks()
    print(f"  Banded walks to test: {len(banded_walks)}")

    phase2_results = []
    best_p2 = {"period_matches": 0, "keyword_matches": 0}

    for name, perm in banded_walks:
        hits = test_permutation(name, perm, targets, FULL_KS, KEYWORD_ROW_PATTERNS)
        phase2_results.extend(hits)

        for h in hits:
            if h.get("period_matches", 0) > best_p2.get("period_matches", 0):
                best_p2 = h
            if h.get("keyword_matches", 0) > best_p2.get("keyword_matches", 0):
                best_p2 = h

    print(f"  Interesting results: {len(phase2_results)}")
    if phase2_results:
        scored = [r for r in phase2_results if "period_matches" in r]
        scored.sort(key=lambda r: max(r.get("period_matches", 0), r.get("keyword_matches", 0)),
                    reverse=True)
        for r in scored[:10]:
            print(f"    {r['walk']} ({r['target']}): period={r['best_period']}({r['period_matches']}/24), "
                  f"kw={r['best_keyword']}({r['keyword_matches']}/24), IC={r['ic']}")

        ks_hits = [r for r in phase2_results if "fragments_found" in r]
        for r in ks_hits[:5]:
            print(f"    {r['walk']}: KS='{r['permuted_str']}' fragments={r['fragments_found']}")

    elapsed = time.time() - t0

    # ── Summary ──────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Phase 1 walks: {len(circular_walks)}, interesting: {len(phase1_results)}")
    print(f"  Phase 2 walks: {len(banded_walks)}, interesting: {len(phase2_results)}")
    print(f"  Elapsed: {elapsed:.1f}s")

    total_interesting = len(phase1_results) + len(phase2_results)
    all_results = phase1_results + phase2_results

    if all_results:
        # Find overall best by keyword match
        kw_scored = [r for r in all_results if "keyword_matches" in r]
        if kw_scored:
            best_kw = max(kw_scored, key=lambda r: r["keyword_matches"])
            print(f"\n  Best keyword match: {best_kw['best_keyword']} "
                  f"({best_kw['keyword_matches']}/24) via {best_kw['walk']}")

        # Find overall best by periodicity
        per_scored = [r for r in all_results if "period_matches" in r]
        if per_scored:
            best_per = max(per_scored, key=lambda r: r["period_matches"])
            print(f"  Best periodicity: period={best_per['best_period']} "
                  f"({best_per['period_matches']}/24) via {best_per['walk']}")

    verdict = "SIGNAL" if any(
        r.get("period_matches", 0) >= 20 or r.get("keyword_matches", 0) >= 20
        for r in all_results
    ) else "INTERESTING" if total_interesting > 0 else "NOISE"

    print(f"\n  Verdict: {verdict}")

    output = {
        "experiment": "e_berlin_clock_route",
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "phase1_walks": len(circular_walks),
        "phase2_walks": len(banded_walks),
        "phase1_interesting": len(phase1_results),
        "phase2_interesting": len(phase2_results),
        "elapsed_seconds": round(elapsed, 1),
        "all_results": all_results[:100],  # Cap output size
        "verdict": verdict,
    }

    out_path = os.path.join(_ROOT, "results", "e_berlin_clock_route.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results: {out_path}")


if __name__ == "__main__":
    main()
