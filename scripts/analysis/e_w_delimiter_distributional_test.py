#!/usr/bin/env python3
"""
Cipher: W-delimiter distributional null test
Family: analysis
Status: active
Keyspace: ~1000 grammatical pairs + ~5000 wordlist pairs + ~50000 random null
Last run:
Best score:

PURPOSE
-------
Convert the W-delimiter crib extension test from "find pretty hits" into a
distributional null test. The question is NOT:

  "Can we find some (slot1, slot2) pair that creates a third k=0 position?"

It is:

  "Within a fair population of plausible (slot1, slot2) pairs, is the
  AT+NEAR pair UNUSUALLY good or merely typical?"

If most plausible pairs also create a third k=0 position, then the AT+NEAR
result is baseline behavior of the test, not signal. If only a small
fraction do, AT+NEAR is in the tail and worth investigating further.

THE THREE POPULATIONS
---------------------
1. RANDOM null: ~50,000 uniform random (slot1=2 letters, slot2=4 letters).
   This tells us the rate of structural coincidences with NO English filter.

2. WORDLIST baseline: every valid 2-letter English word x every valid 4-letter
   English word from the project wordlist. Tells us the rate among real words.

3. GRAMMATICAL-FIT subset: hand-curated lists from the prior script (words
   that grammatically fit the slot positions). Tells us the rate among words
   that pass a soft grammatical filter.

For each population we measure:
- Distribution of NEW k=0 positions added (0, 1, 2, ...)
- Distribution of NEW positions where k matches an existing crib k value
- Distribution of common-ngram counts in the augmented keystream

Then we locate AT+NEAR within each distribution and report its percentile.

WHAT WOULD COUNT AS SIGNAL
--------------------------
If AT+NEAR's structural stats are above the 99th percentile of the wordlist
baseline, that's modest signal. If they're above the 99.9th percentile of
the random null, that's stronger signal. If they're at or below the median
of any population, the AT+NEAR result is wishful thinking.

WHAT THIS TEST DOES NOT DO
--------------------------
- It does not assume W IS a delimiter. It only asks: under that assumption,
  how distinctive is the specific AT+NEAR pair?
- It does not extend the keystream to unconstrained positions.
- It does not test non-additive ciphers.
- It treats the augmented Bean compatibility as a sanity gate, not a filter.
"""
from __future__ import annotations

import os
import sys
import random
import string
from collections import Counter
from itertools import product
from pathlib import Path

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT,
)

# ── Slot definitions ─────────────────────────────────────────────────

SLOT1_POSITIONS = [34, 35]
SLOT1_LENGTH = 2
SLOT2_POSITIONS = [59, 60, 61, 62]
SLOT2_LENGTH = 4

# CT at the slot positions
SLOT1_CT = "".join(CT[p] for p in SLOT1_POSITIONS)  # "OT"
SLOT2_CT = "".join(CT[p] for p in SLOT2_POSITIONS)  # "INFB"

# ── Structural feature computation ───────────────────────────────────

def compute_features(slot1: str, slot2: str, variant: str) -> dict:
    """Compute the structural features of an augmented keystream.

    Returns a dict with:
      new_zero_count: number of NEW positions where k=0 (under variant)
      bean_eq_holds: bool — whether k[27]==k[65] is preserved
      slot1_keys: the 2 keystream values added in slot 1
      slot2_keys: the 4 keystream values added in slot 2
    """
    # Build augmented PT
    augmented = dict(CRIB_DICT)
    for i, ch in enumerate(slot1):
        augmented[SLOT1_POSITIONS[i]] = ch
    for i, ch in enumerate(slot2):
        augmented[SLOT2_POSITIONS[i]] = ch

    # Compute keystream
    ks = {}
    for pos, pt in augmented.items():
        c = ALPH_IDX[CT[pos]]
        p = ALPH_IDX[pt]
        if variant == "vig":
            k = (c - p) % MOD
        elif variant == "beau":
            k = (c + p) % MOD
        elif variant == "vbeau":
            k = (p - c) % MOD
        ks[pos] = k

    # Count new k=0 positions (positions added in slot1 or slot2)
    new_positions = SLOT1_POSITIONS + SLOT2_POSITIONS
    new_zero_count = sum(1 for p in new_positions if ks[p] == 0)

    # Bean equality
    bean_eq_holds = ks[27] == ks[65]

    # Slot keys
    slot1_keys = "".join(ALPH[ks[p]] for p in SLOT1_POSITIONS)
    slot2_keys = "".join(ALPH[ks[p]] for p in SLOT2_POSITIONS)

    return {
        "new_zero_count": new_zero_count,
        "bean_eq_holds": bean_eq_holds,
        "slot1_keys": slot1_keys,
        "slot2_keys": slot2_keys,
    }


# ── Population 1: random null ────────────────────────────────────────

def random_population(n_samples: int, seed: int = 42) -> list[tuple[str, str]]:
    """Uniform random 2-letter and 4-letter strings (no English filter)."""
    random.seed(seed)
    pairs = []
    for _ in range(n_samples):
        s1 = "".join(random.choice(string.ascii_uppercase) for _ in range(2))
        s2 = "".join(random.choice(string.ascii_uppercase) for _ in range(4))
        pairs.append((s1, s2))
    return pairs


# ── Population 2: wordlist baseline ──────────────────────────────────

def load_wordlist() -> tuple[list[str], list[str]]:
    """Load every valid ASCII 2-letter and 4-letter English word from the wordlist."""
    wl_path = Path(_ROOT) / "wordlists" / "english.txt"
    if not wl_path.exists():
        return [], []
    ascii_upper = set(string.ascii_uppercase)
    twos = []
    fours = []
    with wl_path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip().upper()
            if not w:
                continue
            # Strict ASCII A-Z only
            if not all(c in ascii_upper for c in w):
                continue
            if len(w) == 2:
                twos.append(w)
            elif len(w) == 4:
                fours.append(w)
    return twos, fours


def wordlist_population(max_pairs: int = 200_000, seed: int = 42) -> list[tuple[str, str]]:
    """Cartesian of every 2-letter x 4-letter word, capped to max_pairs.

    The full cartesian is ~9M pairs which is too slow for an interactive
    test. We sample uniformly without replacement instead.
    """
    twos, fours = load_wordlist()
    if not twos or not fours:
        return []
    full_size = len(twos) * len(fours)
    if full_size <= max_pairs:
        return [(t, f) for t in twos for f in fours]
    # Uniform random sample of (twos, fours) pairs
    rng = random.Random(seed)
    pairs = set()
    while len(pairs) < max_pairs:
        t = rng.choice(twos)
        f = rng.choice(fours)
        pairs.add((t, f))
    return sorted(pairs)


# ── Population 3: grammatical-fit subset ─────────────────────────────

GRAMMATICAL_SLOT1 = [
    "TO", "AT", "IN", "ON", "OF", "BY", "UP", "IS", "AS", "AN", "OR",
    "IT", "HE", "WE", "US", "ME", "MY", "IF", "SO", "NO", "DO", "BE", "GO",
]
GRAMMATICAL_SLOT2 = [
    "NEAR", "ATOP", "UPON", "OVER", "ONTO", "INTO", "PAST", "FROM",
    "HERE", "BACK", "AWAY", "DOWN", "THIS", "THAT", "SOME", "EACH",
    "TIME", "HOUR", "ZONE", "WHEN", "ONCE", "NOON",
    "FIND", "SEEK", "READ", "LOOK", "KEEP", "HOLD", "SHOW", "MEET", "TELL",
    "VIEW", "TRUE", "REAL", "MAIN",
    "EDGE", "SIDE", "AREA", "FACE", "PART", "WALL", "GATE", "DOOR",
    "WEST", "EAST",
]

def grammatical_population() -> list[tuple[str, str]]:
    return [(s1, s2) for s1 in GRAMMATICAL_SLOT1 for s2 in GRAMMATICAL_SLOT2]


# ── Distribution analysis ────────────────────────────────────────────

def analyze_population(name: str, pairs: list[tuple[str, str]], variant: str) -> dict:
    """Compute the distribution of new_zero_count across a population."""
    if not pairs:
        return {"name": name, "variant": variant, "n": 0, "distribution": {}}

    new_zeros = Counter()
    bean_pass = 0
    for s1, s2 in pairs:
        feats = compute_features(s1, s2, variant)
        new_zeros[feats["new_zero_count"]] += 1
        if feats["bean_eq_holds"]:
            bean_pass += 1

    return {
        "name": name,
        "variant": variant,
        "n": len(pairs),
        "distribution": dict(new_zeros),
        "bean_eq_pass_rate": bean_pass / len(pairs),
    }


def percentile_of_value(distribution: dict, value: int) -> float:
    """What fraction of the distribution has a STRICTLY HIGHER new_zero_count?

    Returns a value in [0, 100]. Lower = more anomalous (rarer).
    A value of 0 means nothing in the population beat it.
    A value of 50 means half the population is at least as good.
    """
    total = sum(distribution.values())
    if total == 0:
        return 100.0
    higher = sum(count for k, count in distribution.items() if k > value)
    return 100.0 * higher / total


def fraction_at_or_above(distribution: dict, value: int) -> float:
    """Fraction of population with new_zero_count >= value."""
    total = sum(distribution.values())
    if total == 0:
        return 1.0
    at_or_above = sum(count for k, count in distribution.items() if k >= value)
    return at_or_above / total


# ── Main ─────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("W-Delimiter Distributional Null Test")
    print("=" * 72)
    print()
    print(f"Slot 1 CT: {SLOT1_CT}  positions {SLOT1_POSITIONS}")
    print(f"Slot 2 CT: {SLOT2_CT}  positions {SLOT2_POSITIONS}")
    print()
    print("Question: within a fair population of plausible (slot1, slot2)")
    print("candidate pairs, is the AT+NEAR pair UNUSUAL or merely typical?")
    print()

    # Compute the AT+NEAR baseline for each variant
    print("=" * 72)
    print("AT+NEAR baseline (the candidate under test)")
    print("=" * 72)
    at_near_features = {}
    for variant in ["vig", "beau", "vbeau"]:
        feats = compute_features("AT", "NEAR", variant)
        at_near_features[variant] = feats
        print(f"  {variant:5s}: new_zero_count={feats['new_zero_count']}  "
              f"slot1_keys={feats['slot1_keys']}  slot2_keys={feats['slot2_keys']}  "
              f"bean_eq={'pass' if feats['bean_eq_holds'] else 'fail'}")
    print()

    # Build populations
    print("Building populations...")
    pop_random = random_population(50000, seed=42)
    pop_wordlist = wordlist_population()
    pop_grammatical = grammatical_population()

    print(f"  Random (uniform A-Z):     {len(pop_random):>6,} pairs")
    print(f"  Wordlist (real words):    {len(pop_wordlist):>6,} pairs")
    print(f"  Grammatical (curated):    {len(pop_grammatical):>6,} pairs")
    print()

    # Analyze each population under each variant
    populations = [
        ("Random null", pop_random),
        ("Wordlist", pop_wordlist),
        ("Grammatical", pop_grammatical),
    ]

    for name, pairs in populations:
        if not pairs:
            print(f"=== {name}: SKIPPED (population empty) ===")
            continue
        print("=" * 72)
        print(f"=== {name} ({len(pairs):,} pairs) ===")
        print("=" * 72)
        for variant in ["vig", "beau", "vbeau"]:
            result = analyze_population(name, pairs, variant)
            dist = result["distribution"]
            total = sum(dist.values())
            at_near_zero = at_near_features[variant]["new_zero_count"]

            print(f"\n  Variant: {variant}")
            print(f"    Distribution of new_zero_count (positions added with k=0):")
            for zc in sorted(dist.keys()):
                count = dist[zc]
                pct = 100.0 * count / total
                bar = "#" * int(pct / 2)
                marker = "  <-- AT+NEAR" if zc == at_near_zero else ""
                print(f"      {zc} new zeros: {count:>6,} ({pct:5.2f}%) {bar}{marker}")

            # Where does AT+NEAR rank?
            at_or_above = fraction_at_or_above(dist, at_near_zero)
            print(f"    Bean equality preserved: "
                  f"{result['bean_eq_pass_rate']*100:5.1f}% of population")
            print(f"    AT+NEAR new_zero_count = {at_near_zero}")
            print(f"    Population fraction with new_zero_count >= {at_near_zero}: "
                  f"{at_or_above*100:.2f}%")

            # Verdict
            if at_or_above >= 0.5:
                verdict = "TYPICAL — at or above the median is common"
            elif at_or_above >= 0.10:
                verdict = "MILD — in the top 10-50%"
            elif at_or_above >= 0.01:
                verdict = "MODEST — in the top 1-10%"
            elif at_or_above >= 0.001:
                verdict = "TAIL — in the top 0.1-1%"
            else:
                verdict = "EXTREME — top 0.1% or rarer"
            print(f"    Verdict: {verdict}")

    # ── Side analysis: WHY does new_zero_count happen at all? ────────
    print()
    print("=" * 72)
    print("Why does new_zero_count > 0 happen?")
    print("=" * 72)
    print()
    print("Under Vig and VBeau, a NEW k=0 at slot position p requires PT[p]==CT[p].")
    print("So the rate of new_zero_count > 0 is determined entirely by how often")
    print("a candidate happens to have a letter that matches the CT at that slot.")
    print()
    print(f"Slot 1 CT: {SLOT1_CT[0]} at pos {SLOT1_POSITIONS[0]}, "
          f"{SLOT1_CT[1]} at pos {SLOT1_POSITIONS[1]}")
    print(f"  Any 2-letter PT with PT[0]={SLOT1_CT[0]} or PT[1]={SLOT1_CT[1]} "
          f"adds a self-encrypting position.")
    print()
    print(f"Slot 2 CT: {SLOT2_CT[0]} at pos {SLOT2_POSITIONS[0]}, "
          f"{SLOT2_CT[1]} at pos {SLOT2_POSITIONS[1]}, "
          f"{SLOT2_CT[2]} at pos {SLOT2_POSITIONS[2]}, "
          f"{SLOT2_CT[3]} at pos {SLOT2_POSITIONS[3]}")
    print(f"  Any 4-letter PT matching any of those letters at the corresponding")
    print(f"  position adds a self-encrypting.")
    print()
    print(f"Random null expectation under uniform letters:")
    print(f"  P(slot1 has >=1 letter match) = 1 - (25/26)^2 = "
          f"{1 - (25/26)**2:.4f} ({(1 - (25/26)**2)*100:.1f}%)")
    print(f"  P(slot2 has >=1 letter match) = 1 - (25/26)^4 = "
          f"{1 - (25/26)**4:.4f} ({(1 - (25/26)**4)*100:.1f}%)")
    print(f"  P(pair adds >=1 self-encrypting) = "
          f"1 - (25/26)^6 = {1 - (25/26)**6:.4f} "
          f"({(1 - (25/26)**6)*100:.1f}%)")
    print(f"  Expected new_zero_count for random pair: 6 * (1/26) = {6/26:.4f}")
    print()

    # ── Show which grammatical candidates produce extra zeros ────────
    print("=" * 72)
    print("Grammatical candidates that produce >= 1 new k=0 (under Vig/VBeau)")
    print("=" * 72)
    extra_zero_hits = []
    for s1, s2 in pop_grammatical:
        feats = compute_features(s1, s2, "vig")
        if feats["new_zero_count"] >= 1:
            extra_zero_hits.append((s1, s2, feats["new_zero_count"], feats["slot1_keys"], feats["slot2_keys"]))

    extra_zero_hits.sort(key=lambda x: -x[2])
    print(f"\n  {len(extra_zero_hits)} of {len(pop_grammatical)} grammatical pairs "
          f"({100*len(extra_zero_hits)/len(pop_grammatical):.1f}%) produce >= 1 new k=0")
    print()
    for s1, s2, zc, k1, k2 in extra_zero_hits[:30]:
        marker = " <-- AT+NEAR" if (s1, s2) == ("AT", "NEAR") else ""
        print(f"    {s1:4s} {s2:5s}  new_zeros={zc}  slot1_k={k1}  slot2_k={k2}{marker}")
    if len(extra_zero_hits) > 30:
        print(f"    ... and {len(extra_zero_hits) - 30} more")

    return 0


if __name__ == "__main__":
    sys.exit(main())
