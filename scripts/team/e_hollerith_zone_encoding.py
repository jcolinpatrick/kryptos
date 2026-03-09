#!/usr/bin/env python3
"""
# Cipher: IBM Hollerith punch card zone encoding null identification
# Family: team
# Status: active
# Keyspace: 7 structural tests × 8 keywords × 3 cipher variants
# Last run: never
# Best score: 0

Test whether IBM 80-column punch card CHARACTER ENCODING properties
can identify the 24 null positions in Kryptos K4.

Hypothesis: K4 has 73 real CT chars + 24 nulls. The nulls might be
identifiable by some property of their IBM punch card encoding.

IBM Card Encoding:
  Group 12 (zone 12): A-I  (digit 1-9)
  Group 11 (zone 11): J-R  (digit 1-9)
  Group 0  (zone 0):  S-Z  (digit 2-9)
"""

import json
import sys
import os
from pathlib import Path
from itertools import combinations
from collections import Counter

# ── Constants ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_WORDS
from kryptos.kernel.scoring.ngram import NgramScorer

QUADGRAM_PATH = Path(__file__).parent.parent.parent / "data" / "english_quadgrams.json"

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
            "PARALLAX", "COLOPHON", "HOROLOGE", "SHADOW"]

# ── IBM Punch Card Encoding Tables ────────────────────────────────────

def get_zone(ch: str) -> int:
    """Return the zone punch for a letter: 12, 11, or 0."""
    if 'A' <= ch <= 'I':
        return 12
    elif 'J' <= ch <= 'R':
        return 11
    elif 'S' <= ch <= 'Z':
        return 0
    raise ValueError(f"Not an uppercase letter: {ch}")

def get_digit(ch: str) -> int:
    """Return the digit punch for a letter (1-9)."""
    if 'A' <= ch <= 'I':
        return ord(ch) - ord('A') + 1
    elif 'J' <= ch <= 'R':
        return ord(ch) - ord('J') + 1
    elif 'S' <= ch <= 'Z':
        return ord(ch) - ord('S') + 2
    raise ValueError(f"Not an uppercase letter: {ch}")

def get_punch_sum(ch: str) -> int:
    """Return zone + digit as a numeric sum."""
    return get_zone(ch) + get_digit(ch)

# ── Crypto helpers ────────────────────────────────────────────────────

def vig_decrypt(ct: str, key: str) -> str:
    out = []
    klen = len(key)
    for i, c in enumerate(ct):
        shift = ord(key[i % klen]) - ord('A')
        out.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
    return ''.join(out)

def beau_decrypt(ct: str, key: str) -> str:
    out = []
    klen = len(key)
    for i, c in enumerate(ct):
        shift = ord(key[i % klen]) - ord('A')
        out.append(chr((shift - (ord(c) - ord('A'))) % 26 + ord('A')))
    return ''.join(out)

def vbeau_decrypt(ct: str, key: str) -> str:
    """Variant Beaufort: PT = CT - K mod 26 (same as Vig encrypt direction)."""
    out = []
    klen = len(key)
    for i, c in enumerate(ct):
        shift = ord(key[i % klen]) - ord('A')
        out.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
    return ''.join(out)

DECRYPTORS = {
    'Vigenere': vig_decrypt,
    'Beaufort': beau_decrypt,
    'VarBeau': vbeau_decrypt,
}

# ── Scoring ───────────────────────────────────────────────────────────

def load_scorer():
    """Load quadgram scorer."""
    print(f"Loading quadgrams from {QUADGRAM_PATH}...")
    return NgramScorer.from_file(QUADGRAM_PATH)

def check_cribs(text: str) -> list:
    """Check if any crib words appear anywhere in text."""
    found = []
    for _, word in CRIB_WORDS:
        idx = text.find(word)
        if idx >= 0:
            found.append((word, idx))
    return found

def try_decryptions(remaining_ct: str, scorer, label: str, top_results: list):
    """Try all keyword/cipher combos on remaining_ct, report results."""
    results = []
    for kw in KEYWORDS:
        for cipher_name, decrypt_fn in DECRYPTORS.items():
            pt = decrypt_fn(remaining_ct, kw)
            sc = scorer.score_per_char(pt)
            cribs = check_cribs(pt)
            results.append((sc, cipher_name, kw, pt, cribs))

    results.sort(reverse=True)

    print(f"\n  Top 5 decryptions for [{label}] (remaining {len(remaining_ct)} chars):")
    for i, (sc, cipher, kw, pt, cribs) in enumerate(results[:5]):
        crib_str = f" *** CRIB FOUND: {cribs} ***" if cribs else ""
        print(f"    {i+1}. {sc:+.4f}/char  {cipher:10s} key={kw:12s}  {pt[:50]}...{crib_str}")

    # Add to global top results
    for sc, cipher, kw, pt, cribs in results[:3]:
        top_results.append((sc, cipher, kw, pt, cribs, label))

    # Check for any crib hits at all
    for sc, cipher, kw, pt, cribs in results:
        if cribs:
            print(f"\n  *** CRIB HIT: {cipher} key={kw} → {cribs}")
            print(f"      Plaintext: {pt}")
            print(f"      Score: {sc:+.4f}/char")


def extract_remaining(ct: str, null_positions: set) -> str:
    """Remove null positions, return remaining CT."""
    return ''.join(c for i, c in enumerate(ct) if i not in null_positions)


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80)
    print("IBM HOLLERITH PUNCH CARD ENCODING — NULL IDENTIFICATION IN K4")
    print("=" * 80)
    print(f"\nK4 ciphertext ({CT_LEN} chars): {CT}")
    print(f"Target: identify 24 null positions using punch card properties\n")

    scorer = load_scorer()
    top_results = []

    # Pre-compute properties for each K4 character
    zones = [get_zone(c) for c in CT]
    digits = [get_digit(c) for c in CT]
    punch_sums = [get_punch_sum(c) for c in CT]

    # ── TEST 1: Zone-based null identification ─────────────────────────
    print("\n" + "─" * 80)
    print("TEST 1: Zone-based null identification")
    print("─" * 80)

    zone_groups = {12: [], 11: [], 0: []}
    for i, z in enumerate(zones):
        zone_groups[z].append(i)

    for zone_id in [12, 11, 0]:
        letters_in_zone = {12: "A-I", 11: "J-R", 0: "S-Z"}[zone_id]
        count = len(zone_groups[zone_id])
        match_str = " *** MATCH (= 24)! ***" if count == 24 else ""
        print(f"  Zone {zone_id:2d} ({letters_in_zone}): {count} positions{match_str}")
        chars_at = ''.join(CT[i] for i in zone_groups[zone_id])
        print(f"    Characters: {chars_at}")
        print(f"    Positions: {zone_groups[zone_id]}")

        if count == 24:
            null_pos = set(zone_groups[zone_id])
            remaining = extract_remaining(CT, null_pos)
            print(f"    Remaining CT ({len(remaining)} chars): {remaining}")
            try_decryptions(remaining, scorer, f"Zone-{zone_id}-as-nulls", top_results)

    # Also check if any TWO zones combined = 24
    print("\n  Combined zone checks (two zones = nulls):")
    for z1, z2 in [(12, 11), (12, 0), (11, 0)]:
        combined = len(zone_groups[z1]) + len(zone_groups[z2])
        real_zone = [z for z in [12, 11, 0] if z != z1 and z != z2][0]
        print(f"    Zones {z1}+{z2} = {combined} nulls, Zone {real_zone} = {len(zone_groups[real_zone])} real")
        if combined == 24:
            print(f"    *** MATCH! Only Zone-{real_zone} letters are real CT ***")
            null_pos = set(zone_groups[z1]) | set(zone_groups[z2])
            remaining = extract_remaining(CT, null_pos)
            try_decryptions(remaining, scorer, f"Only-Zone-{real_zone}-real", top_results)

    # ── TEST 2: Digit-based null identification ─────────────────────────
    print("\n" + "─" * 80)
    print("TEST 2: Digit-based null identification")
    print("─" * 80)

    digit_groups = {d: [] for d in range(1, 10)}
    for i, d in enumerate(digits):
        digit_groups[d].append(i)

    # Letters mapping for reference
    digit_letters = {
        1: "A, J",
        2: "B, K, S",
        3: "C, L, T",
        4: "D, M, U",
        5: "E, N, V",
        6: "F, O, W",
        7: "G, P, X",
        8: "H, Q, Y",
        9: "I, R, Z",
    }

    for d in range(1, 10):
        count = len(digit_groups[d])
        match_str = " *** MATCH (= 24)! ***" if count == 24 else ""
        print(f"  Digit {d} ({digit_letters[d]:>12s}): {count:2d} positions{match_str}")
        if count == 24:
            null_pos = set(digit_groups[d])
            remaining = extract_remaining(CT, null_pos)
            chars_removed = ''.join(CT[i] for i in sorted(null_pos))
            print(f"    Removed: {chars_removed}")
            print(f"    Remaining CT ({len(remaining)} chars): {remaining}")
            try_decryptions(remaining, scorer, f"Digit-{d}-as-nulls", top_results)

    # Check combinations of digits that sum to 24
    print("\n  Digit combinations summing to 24 positions:")
    for n_combo in range(2, 5):
        for combo in combinations(range(1, 10), n_combo):
            total = sum(len(digit_groups[d]) for d in combo)
            if total == 24:
                combo_str = '+'.join(str(d) for d in combo)
                letters = ', '.join(digit_letters[d] for d in combo)
                print(f"    Digits {combo_str} = 24 positions  (letters: {letters})")
                null_pos = set()
                for d in combo:
                    null_pos.update(digit_groups[d])
                remaining = extract_remaining(CT, null_pos)
                try_decryptions(remaining, scorer, f"Digits-{combo_str}-as-nulls", top_results)

    # ── TEST 3: Punch sum thresholds ───────────────────────────────────
    print("\n" + "─" * 80)
    print("TEST 3: Punch sum (zone + digit) thresholds")
    print("─" * 80)

    # Show distribution
    sum_counter = Counter(punch_sums)
    print("\n  Punch sum distribution:")
    for s in sorted(sum_counter.keys()):
        chars = ''.join(CT[i] for i, ps in enumerate(punch_sums) if ps == s)
        print(f"    Sum {s:2d}: {sum_counter[s]:2d} positions  chars={chars}")

    # Check thresholds
    print("\n  Threshold checks (positions with sum <= threshold):")
    for threshold in range(1, 25):
        count = sum(1 for ps in punch_sums if ps <= threshold)
        if count == 24:
            null_pos = set(i for i, ps in enumerate(punch_sums) if ps <= threshold)
            remaining = extract_remaining(CT, null_pos)
            print(f"    Sum <= {threshold}: {count} positions *** MATCH! ***")
            try_decryptions(remaining, scorer, f"PunchSum-le-{threshold}-nulls", top_results)

    print("\n  Threshold checks (positions with sum >= threshold):")
    for threshold in range(1, 25):
        count = sum(1 for ps in punch_sums if ps >= threshold)
        if count == 24:
            null_pos = set(i for i, ps in enumerate(punch_sums) if ps >= threshold)
            remaining = extract_remaining(CT, null_pos)
            print(f"    Sum >= {threshold}: {count} positions *** MATCH! ***")
            try_decryptions(remaining, scorer, f"PunchSum-ge-{threshold}-nulls", top_results)

    # Check exact sum values
    print("\n  Exact sum value checks:")
    for s in sorted(sum_counter.keys()):
        if sum_counter[s] == 24:
            null_pos = set(i for i, ps in enumerate(punch_sums) if ps == s)
            remaining = extract_remaining(CT, null_pos)
            print(f"    Sum == {s}: {sum_counter[s]} positions *** MATCH! ***")
            try_decryptions(remaining, scorer, f"PunchSum-eq-{s}-nulls", top_results)

    # Combinations of sums totaling 24
    print("\n  Sum value combinations totaling 24 positions:")
    all_sums = sorted(sum_counter.keys())
    for n_combo in range(2, 5):
        for combo in combinations(all_sums, n_combo):
            total = sum(sum_counter[s] for s in combo)
            if total == 24:
                combo_str = '+'.join(str(s) for s in combo)
                print(f"    Sums {combo_str} = 24 positions")
                null_pos = set(i for i, ps in enumerate(punch_sums) if ps in combo)
                remaining = extract_remaining(CT, null_pos)
                try_decryptions(remaining, scorer, f"PunchSums-{combo_str}-nulls", top_results)

    # ── TEST 4: Zone as two-system indicator ───────────────────────────
    print("\n" + "─" * 80)
    print("TEST 4: Zone as two-system indicator")
    print("─" * 80)
    print("  Sanborn said 'TWO SYSTEMS'. Test each zone as null set.")

    for null_zone in [12, 11, 0]:
        null_pos = set(zone_groups[null_zone])
        remaining = extract_remaining(CT, null_pos)
        n_null = len(null_pos)
        n_real = len(remaining)
        print(f"\n  Zone {null_zone} as nulls: {n_null} nulls, {n_real} real CT chars")
        print(f"    Null chars: {''.join(CT[i] for i in sorted(null_pos))}")
        print(f"    Real CT:    {remaining}")

        # Even if not exactly 73, try decryption for any interesting count
        if n_real >= 20:
            try_decryptions(remaining, scorer, f"Zone-{null_zone}-null-system", top_results)

    # ── TEST 5: Hollerith digit row analysis ───────────────────────────
    print("\n" + "─" * 80)
    print("TEST 5: Hollerith digit row analysis")
    print("─" * 80)

    # Row 0 is special: it's both a zone row (for S-Z) and digit row 0
    # S-Z use zone 0. Letters in zone 0 have a "row 0 punch"
    zone0_count = len(zone_groups[0])
    print(f"\n  Zone-0 letters (S-Z, have 'row 0 punch'): {zone0_count} positions")
    print(f"    Chars: {''.join(CT[i] for i in zone_groups[0])}")

    # Digit row groups are same as Test 2 digit groups
    # Check: positions where digit row is a multiple of something
    print("\n  Digit row modular patterns:")
    for mod in [2, 3, 4]:
        for remainder in range(mod):
            pos_list = [i for i, d in enumerate(digits) if d % mod == remainder]
            if len(pos_list) == 24:
                print(f"    digit % {mod} == {remainder}: 24 positions *** MATCH! ***")
                null_pos = set(pos_list)
                remaining = extract_remaining(CT, null_pos)
                try_decryptions(remaining, scorer, f"Digit-mod{mod}-eq{remainder}-nulls", top_results)
            else:
                print(f"    digit % {mod} == {remainder}: {len(pos_list)} positions")

    # ── TEST 6: Even vs odd digit ──────────────────────────────────────
    print("\n" + "─" * 80)
    print("TEST 6: Even vs odd digit parity")
    print("─" * 80)

    odd_positions = [i for i, d in enumerate(digits) if d % 2 == 1]
    even_positions = [i for i, d in enumerate(digits) if d % 2 == 0]

    odd_letters = "A,C,E,G,I,J,L,N,P,R"  # digits 1,3,5,7,9
    even_letters = "B,D,F,H,K,M,O,Q,S,T,U,V,W,X,Y,Z"  # digits 2,4,6,8

    print(f"  Odd digit (1,3,5,7,9) [{odd_letters}]: {len(odd_positions)} positions")
    if len(odd_positions) == 24:
        print(f"    *** MATCH! ***")
        null_pos = set(odd_positions)
        remaining = extract_remaining(CT, null_pos)
        try_decryptions(remaining, scorer, "Odd-digit-as-nulls", top_results)

    print(f"  Even digit (2,4,6,8) [{even_letters}]: {len(even_positions)} positions")
    if len(even_positions) == 24:
        print(f"    *** MATCH! ***")
        null_pos = set(even_positions)
        remaining = extract_remaining(CT, null_pos)
        try_decryptions(remaining, scorer, "Even-digit-as-nulls", top_results)

    # ── TEST 7: Two-punch row parity ───────────────────────────────────
    print("\n" + "─" * 80)
    print("TEST 7: Two-punch row parity (zone row + digit row)")
    print("─" * 80)

    both_even = []  # zone even AND digit even
    both_odd = []   # zone odd AND digit odd
    mixed = []      # one even, one odd

    for i in range(CT_LEN):
        z = zones[i]
        d = digits[i]
        z_even = (z % 2 == 0)
        d_even = (d % 2 == 0)
        if z_even and d_even:
            both_even.append(i)
        elif not z_even and not d_even:
            both_odd.append(i)
        else:
            mixed.append(i)

    print(f"  Both even (zone even + digit even): {len(both_even)} positions")
    print(f"    Chars: {''.join(CT[i] for i in both_even)}")
    if len(both_even) == 24:
        print(f"    *** MATCH! ***")
        try_decryptions(extract_remaining(CT, set(both_even)), scorer, "BothEven-nulls", top_results)

    print(f"  Both odd (zone odd + digit odd):   {len(both_odd)} positions")
    print(f"    Chars: {''.join(CT[i] for i in both_odd)}")
    if len(both_odd) == 24:
        print(f"    *** MATCH! ***")
        try_decryptions(extract_remaining(CT, set(both_odd)), scorer, "BothOdd-nulls", top_results)

    print(f"  Mixed (one even, one odd):          {len(mixed)} positions")
    print(f"    Chars: {''.join(CT[i] for i in mixed)}")
    if len(mixed) == 24:
        print(f"    *** MATCH! ***")
        try_decryptions(extract_remaining(CT, set(mixed)), scorer, "Mixed-parity-nulls", top_results)

    # ── TEST 7b: Zone parity alone ─────────────────────────────────────
    print("\n  Zone parity alone:")
    z_even = [i for i in range(CT_LEN) if zones[i] % 2 == 0]
    z_odd = [i for i in range(CT_LEN) if zones[i] % 2 == 1]
    print(f"    Zone even (0, 12): {len(z_even)} positions")
    print(f"    Zone odd (11):     {len(z_odd)} positions")
    if len(z_even) == 24:
        print(f"    Zone-even = 24 *** MATCH! ***")
        try_decryptions(extract_remaining(CT, set(z_even)), scorer, "ZoneEven-nulls", top_results)
    if len(z_odd) == 24:
        print(f"    Zone-odd = 24 *** MATCH! ***")
        try_decryptions(extract_remaining(CT, set(z_odd)), scorer, "ZoneOdd-nulls", top_results)

    # ── BONUS TEST 8: Punch card COLUMN position mod analysis ──────────
    print("\n" + "─" * 80)
    print("TEST 8 (BONUS): Letter ordinal properties")
    print("─" * 80)
    print("  Check if letters at certain ordinal positions (A=0..Z=25) mod N give 24")

    for mod in [2, 3, 4, 5, 6, 7, 8, 9, 10, 13]:
        for rem in range(mod):
            pos_list = [i for i, c in enumerate(CT) if (ord(c) - ord('A')) % mod == rem]
            if len(pos_list) == 24:
                chars = ''.join(CT[p] for p in pos_list)
                print(f"  ord%{mod}=={rem}: 24 positions *** MATCH! ***  chars={chars}")
                null_pos = set(pos_list)
                remaining = extract_remaining(CT, null_pos)
                try_decryptions(remaining, scorer, f"Ord-mod{mod}-eq{rem}-nulls", top_results)

    # ── BONUS TEST 9: KA alphabet index zone grouping ──────────────────
    print("\n" + "─" * 80)
    print("TEST 9 (BONUS): KA-alphabet index groups of 8/9")
    print("─" * 80)

    KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    ka_idx = {c: i for i, c in enumerate(KA)}

    # Split KA into 3 groups like IBM zones but based on KA ordering
    ka_group1 = set(KA[0:9])    # K,R,Y,P,T,O,S,A,B
    ka_group2 = set(KA[9:18])   # C,D,E,F,G,H,I,J,L
    ka_group3 = set(KA[18:26])  # M,N,Q,U,V,W,X,Z

    groups = {'KA-first9': ka_group1, 'KA-mid9': ka_group2, 'KA-last8': ka_group3}
    for gname, gset in groups.items():
        pos_list = [i for i, c in enumerate(CT) if c in gset]
        print(f"  {gname} {sorted(gset)}: {len(pos_list)} positions")
        if len(pos_list) == 24:
            print(f"    *** MATCH! ***")
            remaining = extract_remaining(CT, set(pos_list))
            try_decryptions(remaining, scorer, f"{gname}-nulls", top_results)

    # Also check KA index mod values
    print("\n  KA-index mod checks:")
    for mod in [3, 4, 8, 9, 13]:
        for rem in range(mod):
            pos_list = [i for i, c in enumerate(CT) if ka_idx[c] % mod == rem]
            if len(pos_list) == 24:
                chars = ''.join(CT[p] for p in pos_list)
                print(f"    KA_idx%{mod}=={rem}: 24 positions *** MATCH! ***  chars={chars}")
                remaining = extract_remaining(CT, set(pos_list))
                try_decryptions(remaining, scorer, f"KAidx-mod{mod}-eq{rem}-nulls", top_results)

    # ── SUMMARY ────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("SUMMARY: Exact-24 matches found")
    print("=" * 80)

    # Collect all 24-matches we found
    matches_24 = []

    # Zone checks
    for zone_id in [12, 11, 0]:
        if len(zone_groups[zone_id]) == 24:
            matches_24.append(f"Zone {zone_id}: {len(zone_groups[zone_id])} positions")

    # Digit checks
    for d in range(1, 10):
        if len(digit_groups[d]) == 24:
            matches_24.append(f"Digit {d}: {len(digit_groups[d])} positions")

    if not matches_24:
        print("  No single IBM property gives exactly 24 positions.")
    else:
        for m in matches_24:
            print(f"  {m}")

    # ── TOP RESULTS ────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("TOP 20 DECRYPTION RESULTS (by quadgram score/char)")
    print("=" * 80)

    top_results.sort(reverse=True, key=lambda x: x[0])
    for i, (sc, cipher, kw, pt, cribs, label) in enumerate(top_results[:20]):
        crib_str = f" *** CRIB: {cribs} ***" if cribs else ""
        print(f"  {i+1:2d}. {sc:+.4f}/char  {cipher:10s} key={kw:12s}  [{label}]")
        print(f"      PT: {pt[:60]}{'...' if len(pt) > 60 else ''}{crib_str}")

    # ── CRIB HITS ──────────────────────────────────────────────────────
    crib_hits = [r for r in top_results if r[4]]
    if crib_hits:
        print("\n" + "=" * 80)
        print("!!! CRIB MATCHES FOUND !!!")
        print("=" * 80)
        for sc, cipher, kw, pt, cribs, label in crib_hits:
            print(f"  {cipher} key={kw} [{label}]: {cribs}")
            print(f"  PT: {pt}")
    else:
        print("\n  No crib matches found in any decryption attempt.")

    # ── FULL CHARACTER ANALYSIS TABLE ──────────────────────────────────
    print("\n" + "=" * 80)
    print("APPENDIX: Full K4 character IBM encoding table")
    print("=" * 80)
    print(f"  {'Pos':>3s}  {'Ch':>2s}  {'Zone':>4s}  {'Digit':>5s}  {'Sum':>3s}  {'ZPar':>4s}  {'DPar':>4s}")
    print(f"  {'---':>3s}  {'--':>2s}  {'----':>4s}  {'-----':>5s}  {'---':>3s}  {'----':>4s}  {'----':>4s}")
    for i, c in enumerate(CT):
        z = zones[i]
        d = digits[i]
        ps = punch_sums[i]
        zp = 'even' if z % 2 == 0 else 'odd'
        dp = 'even' if d % 2 == 0 else 'odd'
        print(f"  {i:3d}  {c:>2s}  {z:4d}  {d:5d}  {ps:3d}  {zp:>4s}  {dp:>4s}")

    print("\n" + "=" * 80)
    print("DONE. Total decryption attempts scored:", len(top_results))
    print("=" * 80)


if __name__ == "__main__":
    main()
