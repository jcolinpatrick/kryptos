#!/usr/bin/env python3
"""
Two-Keyword Vigenere Punch Card Model for Kryptos K4.

Cipher: Two-keyword Vigenere punch card
Family: team
Status: active
Keyspace: ~50 W1 x 6 rules x 8 W2 x 2 ciphers x 2 alphabets
Last run: never
Best score: 0

MODEL:
  System 1 (Null Mask): keyword W1 applied through Vigenere/Beaufort tableau
  generates derived value D[i] at each position. A rule on D[i] picks 24 nulls.

  System 2 (Decryption): After removing nulls, keyword W2 decrypts 73 chars
  via Vigenere or Beaufort.

  Also tests KA alphabet ordering (KRYPTOSABCDEFGHIJLMNQUVWXZ).
"""
from __future__ import annotations

import json
import sys
import time
from itertools import combinations
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Constants ────────────────────────────────────────────────────────────────

CT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWAT"
    "JKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
assert len(CT) == 97

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(ALPH)}

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

CRIBS = ["EASTNORTHEAST", "BERLINCLOCK"]

# ── Quadgram scorer ──────────────────────────────────────────────────────────

QUADGRAM_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "english_quadgrams.json"


class QGScorer:
    def __init__(self, path: Path) -> None:
        with open(path) as f:
            data = json.load(f)
        if "logp" in data:
            data = data["logp"]
        self.logp: Dict[str, float] = data
        self.floor = min(self.logp.values())

    def score(self, text: str) -> float:
        text = text.upper()
        total = 0.0
        for i in range(len(text) - 3):
            total += self.logp.get(text[i : i + 4], self.floor)
        return total

    def score_per_char(self, text: str) -> float:
        text = text.upper()
        n = len(text) - 3
        if n <= 0:
            return self.floor
        return self.score(text) / n


def compute_ic(text: str) -> float:
    """Index of coincidence."""
    text = text.upper()
    n = len(text)
    if n < 2:
        return 0.0
    counts = [0] * 26
    for c in text:
        if "A" <= c <= "Z":
            counts[ord(c) - 65] += 1
    total = sum(c * (c - 1) for c in counts)
    return total / (n * (n - 1))


# ── Cipher operations ────────────────────────────────────────────────────────

def derive_key_vig(ct_char: str, key_char: str, idx: Dict[str, int]) -> int:
    """D[i] = (CT[i] - Key[i]) mod 26 — Vigenere convention."""
    return (idx[ct_char] - idx[key_char]) % 26


def derive_key_beau(ct_char: str, key_char: str, idx: Dict[str, int]) -> int:
    """D[i] = (CT[i] + Key[i]) mod 26 — Beaufort convention."""
    return (idx[ct_char] + idx[key_char]) % 26


def decrypt_vig(ct73: str, key: str, idx: Dict[str, int]) -> str:
    """PT[i] = (CT[i] - Key[i]) mod 26"""
    inv = {v: k for k, v in idx.items()}
    out = []
    klen = len(key)
    for i, c in enumerate(ct73):
        val = (idx[c] - idx[key[i % klen]]) % 26
        out.append(inv[val])
    return "".join(out)


def decrypt_beau(ct73: str, key: str, idx: Dict[str, int]) -> str:
    """PT[i] = (Key[i] - CT[i]) mod 26"""
    inv = {v: k for k, v in idx.items()}
    out = []
    klen = len(key)
    for i, c in enumerate(ct73):
        val = (idx[key[i % klen]] - idx[c]) % 26
        out.append(inv[val])
    return "".join(out)


# ── Null mask generation ─────────────────────────────────────────────────────

def compute_derived(ct: str, w1: str, mode: str, idx: Dict[str, int]) -> List[int]:
    """Compute derived values D[i] for all positions."""
    klen = len(w1)
    derive_fn = derive_key_vig if mode == "vig" else derive_key_beau
    return [derive_fn(ct[i], w1[i % klen], idx) for i in range(len(ct))]


def find_null_masks(derived: List[int]) -> List[Tuple[str, str, Set[int]]]:
    """Apply all punch rules, return list of (rule_name, param, null_positions)
    where |null_positions| == 24."""
    results = []
    n = len(derived)

    # Rule 1 & 2: Modular residue
    for mod in [2, 3, 4, 6, 8, 13]:
        for r in range(mod):
            nulls = {i for i in range(n) if derived[i] % mod == r}
            if len(nulls) == 24:
                results.append((f"mod{mod}", f"r={r}", nulls))

    # Rule 3: Range threshold
    for t in range(1, 26):
        nulls = {i for i in range(n) if derived[i] < t}
        if len(nulls) == 24:
            results.append(("range_lt", f"T={t}", nulls))

    # Also test D[i] >= T
    for t in range(1, 26):
        nulls = {i for i in range(n) if derived[i] >= t}
        if len(nulls) == 24:
            results.append(("range_ge", f"T={t}", nulls))

    # Rule 4: Specific value
    for v in range(26):
        nulls = {i for i in range(n) if derived[i] == v}
        if len(nulls) == 24:
            results.append(("exact", f"v={v}", nulls))

    # Rule 5: Top/bottom quartile (always gives 24 if we handle ties)
    sorted_pairs = sorted(enumerate(derived), key=lambda x: x[1])
    # Bottom 24
    val_at_24 = sorted_pairs[23][1]  # value of 24th smallest
    val_at_25 = sorted_pairs[24][1] if len(sorted_pairs) > 24 else val_at_24 + 1
    if val_at_24 != val_at_25:
        # Clean split — no tie ambiguity
        nulls = {sorted_pairs[i][0] for i in range(24)}
        results.append(("bottom24", "smallest", nulls))
    else:
        # Tie at boundary — enumerate all ways to break tie
        # Positions with value < val_at_24 are definitely in
        definite = [p for p in sorted_pairs if p[1] < val_at_24]
        tied = [p for p in sorted_pairs if p[1] == val_at_24]
        need = 24 - len(definite)
        if 0 < need <= len(tied) and need <= 10:  # cap combinatorics
            for combo in combinations(range(len(tied)), need):
                nulls = {p[0] for p in definite}
                for ci in combo:
                    nulls.add(tied[ci][0])
                results.append(("bottom24_tie", f"smallest+tiebreak", nulls))
        elif need <= 0:
            # More than 24 are strictly less — shouldn't happen, but handle
            pass

    # Top 24
    sorted_desc = sorted(enumerate(derived), key=lambda x: -x[1])
    val_at_24d = sorted_desc[23][1]
    val_at_25d = sorted_desc[24][1] if len(sorted_desc) > 24 else val_at_24d - 1
    if val_at_24d != val_at_25d:
        nulls = {sorted_desc[i][0] for i in range(24)}
        results.append(("top24", "largest", nulls))
    else:
        definite = [p for p in sorted_desc if p[1] > val_at_24d]
        tied = [p for p in sorted_desc if p[1] == val_at_24d]
        need = 24 - len(definite)
        if 0 < need <= len(tied) and need <= 10:
            for combo in combinations(range(len(tied)), need):
                nulls = {p[0] for p in definite}
                for ci in combo:
                    nulls.add(tied[ci][0])
                results.append(("top24_tie", f"largest+tiebreak", nulls))

    # Rule 6: Even/odd (already covered by mod2, but explicit for clarity)
    # Already included in mod2 above.

    return results


# ── Main attack ──────────────────────────────────────────────────────────────

def attack():
    print("=" * 80)
    print("TWO-KEYWORD VIGENERE PUNCH CARD MODEL — K4")
    print("=" * 80)
    print()

    # Load quadgram scorer
    print(f"Loading quadgrams from {QUADGRAM_PATH}...")
    scorer = QGScorer(QUADGRAM_PATH)
    print(f"  Loaded {len(scorer.logp)} quadgrams, floor={scorer.floor:.4f}")
    print()

    W1_KEYWORDS = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
        "COLOPHON", "HOROLOGE", "SHADOW", "ENIGMA", "BERLINCLOCK",
        "EASTNORTHEAST", "CLOCK", "BERLIN", "FIVE", "SANBORN",
        "SCHEIDT", "WEBSTER", "CIA", "LANGLEY", "LUCID",
        "MATRIX", "LAYER", "TWO", "INFERNO", "PALIMPCEST",
        "IQLUSION", "DESPARATLY", "DIGETAL", "INTERPRETATIU",
        "WHATSTHEPOINT", "POINTW", "POINT", "WORLDCLOCK",
        "WELTZEITUHR", "CARTER", "HOWARD", "CANDLE", "ANTECHAMBER",
        "TOMB", "PETRIFIED", "CYPHER", "CIPHER", "LOOM",
        "JACQUARD", "PUNCHCARD", "HOLLERITH", "BINARY", "CARDAN", "GRILLE",
    ]

    W2_KEYWORDS = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
        "PARALLAX", "COLOPHON", "HOROLOGE", "SHADOW",
    ]

    ALPHABETS = [
        ("AZ", ALPH, AZ_IDX),
        ("KA", KA, KA_IDX),
    ]

    DERIVE_MODES = [("vig", "Vigenere"), ("beau", "Beaufort")]
    DECRYPT_MODES = [("vig", decrypt_vig), ("beau", decrypt_beau)]

    # Phase 1: Find all valid null masks
    print("PHASE 1: Scanning for valid null masks (exactly 24 nulls)")
    print("-" * 80)

    valid_masks: List[Tuple[str, str, str, str, str, Set[int]]] = []
    # (w1, derive_mode_name, alph_name, rule_name, param, null_set)

    mask_count = 0
    for alph_name, alph_str, alph_idx in ALPHABETS:
        for w1 in W1_KEYWORDS:
            for dm_key, dm_name in DERIVE_MODES:
                derived = compute_derived(CT, w1, dm_key, alph_idx)
                masks = find_null_masks(derived)
                for rule_name, param, nulls in masks:
                    valid_masks.append((w1, dm_name, alph_name, rule_name, param, nulls))
                    mask_count += 1

    print(f"  Found {mask_count} valid null masks")
    print()

    # Print summary of masks
    if mask_count > 0 and mask_count <= 500:
        print("Valid mask summary:")
        print(f"  {'W1':<18} {'Derive':<10} {'Alph':<4} {'Rule':<16} {'Param':<20}")
        print(f"  {'-'*18} {'-'*10} {'-'*4} {'-'*16} {'-'*20}")
        for w1, dm, al, rule, param, nulls in valid_masks:
            print(f"  {w1:<18} {dm:<10} {al:<4} {rule:<16} {param:<20}")
        print()
    elif mask_count > 500:
        # Group by (w1, derive, alph)
        from collections import Counter
        group_counts: Dict[Tuple[str, str, str], int] = Counter()
        for w1, dm, al, rule, param, nulls in valid_masks:
            group_counts[(w1, dm, al)] += 1
        print(f"  Too many masks to list individually ({mask_count}). Summary by (W1, derive, alph):")
        for (w1, dm, al), cnt in sorted(group_counts.items()):
            print(f"    {w1:<18} {dm:<10} {al:<4} → {cnt} masks")
        print()

    # Phase 2: Decrypt and score
    print("PHASE 2: Decrypting with W2 keywords and scoring")
    print("-" * 80)

    ResultTuple = Tuple[float, float, str, str, str, str, str, str, str, str, List[str]]
    # (qg_per_char, ic, plaintext, w1, derive, alph, rule, param, w2, decrypt_mode, crib_hits)

    all_results: List[ResultTuple] = []
    crib_hits: List[ResultTuple] = []
    total_decryptions = 0
    t0 = time.time()

    for mask_idx, (w1, dm_name, alph_name, rule_name, param, nulls) in enumerate(valid_masks):
        # Build 73-char ciphertext by removing nulls
        ct73 = "".join(CT[i] for i in range(97) if i not in nulls)
        assert len(ct73) == 73, f"Expected 73, got {len(ct73)}"

        # Get the right alphabet index for decryption
        _, _, alph_idx = next(
            (a, s, idx) for a, s, idx in ALPHABETS if a == alph_name
        )

        for w2 in W2_KEYWORDS:
            for dec_key, dec_fn in DECRYPT_MODES:
                pt = dec_fn(ct73, w2, alph_idx)
                total_decryptions += 1

                # Check for cribs
                hits = []
                for crib in CRIBS:
                    if crib in pt:
                        hits.append(crib)

                qg = scorer.score_per_char(pt)
                ic = compute_ic(pt)

                result = (qg, ic, pt, w1, dm_name, alph_name, rule_name, param, w2, dec_key, hits)

                if hits:
                    crib_hits.append(result)
                    print(f"\n  *** CRIB HIT! ***")
                    print(f"  W1={w1}, derive={dm_name}, alph={alph_name}")
                    print(f"  Rule={rule_name}, param={param}")
                    print(f"  W2={w2}, decrypt={dec_key}")
                    print(f"  PT: {pt}")
                    print(f"  Cribs found: {hits}")
                    print(f"  QG/char={qg:.4f}, IC={ic:.4f}")
                    print()

                all_results.append(result)

        # Progress
        if (mask_idx + 1) % 100 == 0:
            elapsed = time.time() - t0
            print(f"  Processed {mask_idx + 1}/{len(valid_masks)} masks, "
                  f"{total_decryptions} decryptions, {elapsed:.1f}s elapsed")

    elapsed = time.time() - t0
    print(f"\n  Total: {total_decryptions} decryptions in {elapsed:.1f}s")
    print()

    # Also test W1 == W2 for keywords that appear in both lists
    # (This is already covered since W2_KEYWORDS is a subset of W1_KEYWORDS)

    # Phase 3: Results
    print("=" * 80)
    print("RESULTS")
    print("=" * 80)
    print()

    if crib_hits:
        print(f"*** {len(crib_hits)} CRIB HITS FOUND ***")
        for r in crib_hits:
            qg, ic, pt, w1, dm, al, rule, param, w2, dec, hits = r
            print(f"  W1={w1} derive={dm} alph={al} rule={rule} param={param}")
            print(f"  W2={w2} decrypt={dec}")
            print(f"  PT: {pt}")
            print(f"  Cribs: {hits}, QG/char={qg:.4f}, IC={ic:.4f}")
            print()
    else:
        print("No crib hits found.")
        print()

    # Top 30 by quadgram score
    all_results.sort(key=lambda x: -x[0])  # sort by QG/char descending
    top_n = min(30, len(all_results))

    print(f"TOP {top_n} RESULTS BY QUADGRAM SCORE")
    print("-" * 120)
    print(f"{'#':>3} {'QG/chr':>8} {'IC':>7} {'W1':<15} {'Deriv':<6} {'Alph':<3} "
          f"{'Rule':<14} {'Param':<18} {'W2':<12} {'Dec':<5} {'Plaintext'}")
    print("-" * 120)

    for rank, r in enumerate(all_results[:top_n], 1):
        qg, ic, pt, w1, dm, al, rule, param, w2, dec, hits = r
        marker = " <<<" if hits else ("" if qg <= -5.5 else " **")
        # Truncate PT for display
        pt_display = pt[:60] + "..." if len(pt) > 60 else pt
        print(f"{rank:>3} {qg:>8.4f} {ic:>7.4f} {w1:<15} {dm:<6} {al:<3} "
              f"{rule:<14} {param:<18} {w2:<12} {dec:<5} {pt_display}{marker}")

    print()

    # Highlight any result with QG/char > -5.5
    good_results = [r for r in all_results if r[0] > -5.5]
    if good_results:
        print(f"RESULTS WITH QG/char > -5.5: {len(good_results)}")
        for r in good_results[:50]:
            qg, ic, pt, w1, dm, al, rule, param, w2, dec, hits = r
            print(f"  QG={qg:.4f} IC={ic:.4f} W1={w1} {dm} {al} {rule}({param}) "
                  f"W2={w2} {dec}")
            print(f"    PT: {pt}")
        print()
    else:
        print("No results with QG/char > -5.5")
        print()

    # Statistics
    print("STATISTICS")
    print("-" * 40)
    if all_results:
        qgs = [r[0] for r in all_results]
        print(f"  Total decryptions: {total_decryptions}")
        print(f"  Valid masks tested: {len(valid_masks)}")
        print(f"  Best QG/char:  {max(qgs):.4f}")
        print(f"  Worst QG/char: {min(qgs):.4f}")
        print(f"  Mean QG/char:  {sum(qgs)/len(qgs):.4f}")
        print(f"  Crib hits: {len(crib_hits)}")
    else:
        print("  No results generated (no valid masks found)")

    print()
    print("Done.")


if __name__ == "__main__":
    attack()
