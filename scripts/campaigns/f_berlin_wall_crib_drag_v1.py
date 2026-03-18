#!/usr/bin/env python3 -u
"""
=================================================================
BERLIN WALL CABLE VOCABULARY CRIB DRAG v1
=================================================================
Cipher:     Model B Beaufort on raw CT97
Family:     campaigns
Status:     active
Keyspace:   ~120 candidate words x ~90 positions each
Last run:   never
Best score: --

HYPOTHESIS
----------
K4 plaintext is a CIA cable from Berlin Station reporting on the
Alexanderplatz demonstration (Nov 4, 1989) at the Urania Weltzeituhr.
BERLINCLOCK = location (the Weltzeituhr), EASTNORTHEAST = bearing/sector.

If the plaintext contains Berlin Wall vocabulary, placing those words
at CT97 positions produces Beaufort key values that should show:
  1. Consistency with known crib key values (no conflicts)
  2. AP {G,K,O} enrichment (if the 50% rate extends beyond cribs)
  3. IC consistent with 0.0797 (the crib-derived IC)
  4. Key fragment readability (if key is running text)

This is NOT a decryption attempt -- it's a CONSTRAINT SEARCH that
tests whether Berlin Wall vocabulary is compatible with the K4 keystream.
=================================================================
"""

import sys
import os
import json
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

# ── Known keystream ────────────────────────────────────────────────────

CRIB_POS = sorted(CRIB_DICT.keys())  # 24 positions
KNOWN_KEY = {}
for pos in CRIB_POS:
    KNOWN_KEY[pos] = (ALPH_IDX[CT[pos]] + ALPH_IDX[CRIB_DICT[pos]]) % MOD

AP_VALUES = frozenset({6, 10, 14})  # G, K, O
KNOWN_AP_COUNT = sum(1 for v in KNOWN_KEY.values() if v in AP_VALUES)
KNOWN_AP_RATE = KNOWN_AP_COUNT / len(KNOWN_KEY)

print(f"Known keystream: {''.join(ALPH[KNOWN_KEY[p]] for p in CRIB_POS)}")
print(f"Known AP rate: {KNOWN_AP_COUNT}/{len(KNOWN_KEY)} = {KNOWN_AP_RATE:.1%}")
print(f"AP values: G({6}), K({10}), O({14})")

# ── Candidate vocabulary ───────────────────────────────────────────────

VOCAB = {
    # Berlin Wall narrative
    "WALL": "wall",
    "BERLINWALL": "berlin-wall",
    "THEWALL": "the-wall",
    "FALLOFTHEWALL": "fall-narrative",
    "PROTEST": "protest",
    "PROTESTS": "protest",
    "DEMONSTRATION": "protest",
    "MASSIVE": "scale",
    "CROWD": "crowd",
    "CROWDS": "crowd",
    "THOUSANDS": "scale",
    "HUNDREDTHOUSAND": "scale",
    "FIVEHUNDREDTHOUSAND": "scale",
    "ONEMILLION": "scale",
    "GATHERING": "crowd",
    "BORDER": "border",
    "BREACH": "breach",
    "BREACHED": "breach",
    "OPENING": "breach",
    "OPENED": "breach",
    "COLLAPSE": "regime",
    "COLLAPSED": "regime",
    "REGIME": "regime",
    "UNSTABLE": "regime",
    "CRITICAL": "regime",
    "IMMINENT": "urgency",
    "IMMEDIATE": "urgency",
    "URGENT": "urgency",
    "FREEDOM": "freedom",
    "REVOLUTION": "revolution",
    "SECTOR": "location",
    "CHECKPOINT": "location",
    "NOVEMBER": "date",
    "FOURTH": "date",
    "NINETEENEIGHTYNINE": "date",
    "EMBASSY": "cia",
    "STATION": "cia",
    "REPORT": "cable",
    "REPORTED": "cable",
    "REPORTING": "cable",
    "ADVISE": "cable",
    "ADVISED": "cable",

    # German words
    "MAUER": "german",
    "GRENZE": "german",
    "PLATZ": "german",
    "ALEXANDERPLATZ": "german",
    "STRASSE": "german",
    "VOLK": "german",
    "FREIHEIT": "german",
    "BRANDENBURGERTOR": "german",
    "BORNHOLMER": "german",
    "FRIEDRICHSTRASSE": "german",
    "WELTZEITUHR": "german",
    "WORLDTIMECLOCK": "german",

    # CIA cable terminology
    "FLASH": "cable-priority",
    "PRIORITY": "cable-priority",
    "NOFORN": "cable-class",
    "SECRET": "cable-class",
    "CLASSIFIED": "cable-class",
    "LANGLEY": "cia",
    "HEADQUARTERS": "cia",
    "OPERATIONS": "cia",
    "BERLINSTATION": "cia",

    # Directions and locations
    "NORTH": "direction",
    "SOUTH": "direction",
    "EAST": "direction",
    "WEST": "direction",
    "NORTHEAST": "direction",
    "NORTHWEST": "direction",
    "SOUTHEAST": "direction",
    "SOUTHWEST": "direction",
    "EASTBERLIN": "location",
    "WESTBERLIN": "location",
    "EASTGERMANY": "location",

    # Phrases matching cable format
    "ATBERLINCLOCK": "phrase",
    "ATLOCATION": "phrase",
    "ATPLATZ": "phrase",
    "REPORTFROM": "phrase",
    "CROWDATPLATZ": "phrase",
    "WALLBREACH": "phrase",
    "WALLMAYFALL": "phrase",
    "WALLISOPEN": "phrase",
    "WALLISDOWN": "phrase",
    "GATEISOPEN": "phrase",
    "BORDERISOPEN": "phrase",
    "REGIMECOLLAPSE": "phrase",
    "MASSIVEDEMO": "phrase",
    "MASSIVEPROTEST": "phrase",
    "HUNDREDSOFTHOUSANDS": "phrase",
}

# ── Crib drag engine ──────────────────────────────────────────────────

def try_placement(word, pos):
    """Try placing word at CT97 position pos.

    Returns dict with key values, AP stats, and consistency info,
    or None if placement conflicts with known cribs.
    """
    word_len = len(word)
    if pos + word_len > CT_LEN:
        return None

    new_keys = {}
    for j, ch in enumerate(word):
        p = pos + j
        kv = (ALPH_IDX[CT[p]] + ALPH_IDX[ch]) % MOD

        # Check conflict with known crib key values
        if p in KNOWN_KEY:
            if KNOWN_KEY[p] != kv:
                return None  # conflict — this placement is impossible
            # else: consistent, don't add to new_keys (already known)
        else:
            new_keys[p] = kv

    if not new_keys:
        return None  # word fully overlaps with existing cribs, nothing new

    # Merge with known keys
    merged = dict(KNOWN_KEY)
    merged.update(new_keys)

    # Check Bean inequalities on merged set
    bean_violations = 0
    for a, b in BEAN_INEQ:
        if a in merged and b in merged:
            if merged[a] == merged[b]:
                bean_violations += 1

    # Check Bean equality
    bean_eq_ok = True
    for a, b in BEAN_EQ:
        if a in merged and b in merged:
            if merged[a] != merged[b]:
                bean_eq_ok = False

    # AP statistics on new key values only
    new_vals = list(new_keys.values())
    new_ap = sum(1 for v in new_vals if v in AP_VALUES)
    new_ap_rate = new_ap / len(new_vals) if new_vals else 0

    # AP statistics on merged set
    merged_vals = list(merged.values())
    merged_ap = sum(1 for v in merged_vals if v in AP_VALUES)
    merged_ap_rate = merged_ap / len(merged_vals)

    # IC of merged key values
    n = len(merged_vals)
    freq = Counter(merged_vals)
    merged_ic = sum(f * (f-1) for f in freq.values()) / (n * (n-1)) if n > 1 else 0

    # Key letters at new positions
    new_key_str = "".join(ALPH[new_keys[p]] for p in sorted(new_keys))

    return {
        "word": word,
        "pos": pos,
        "new_key_str": new_key_str,
        "new_key_values": {str(p): v for p, v in sorted(new_keys.items())},
        "new_ap_count": new_ap,
        "new_ap_rate": new_ap_rate,
        "new_len": len(new_vals),
        "merged_ap_count": merged_ap,
        "merged_ap_rate": merged_ap_rate,
        "merged_ic": merged_ic,
        "merged_size": len(merged_vals),
        "bean_violations": bean_violations,
        "bean_eq_ok": bean_eq_ok,
    }


def score_placement(result):
    """Score a valid placement. Higher = more interesting."""
    if result is None:
        return -999

    score = 0

    # Bean violations are fatal
    if result["bean_violations"] > 0:
        score -= 100 * result["bean_violations"]
    if not result["bean_eq_ok"]:
        score -= 500

    # AP enrichment: reward new key values in {G,K,O}
    # Baseline: 3/26 = 11.5%. Crib rate: 50%.
    # Score by how much new AP rate exceeds baseline
    expected_ap = result["new_len"] * 3 / 26
    score += (result["new_ap_count"] - expected_ap) * 10

    # IC bonus: reward IC close to known 0.0797
    ic_diff = abs(result["merged_ic"] - 0.0797)
    score += max(0, 5 - ic_diff * 100)

    return score


# ── Main search ────────────────────────────────────────────────────────

def main():
    t_start = time.time()

    print("\n" + "=" * 70)
    print("Berlin Wall Cable Vocabulary Crib Drag v1")
    print("=" * 70)
    print(f"Vocabulary: {len(VOCAB)} candidate words")
    print(f"CT: {CT}")

    all_results = []
    word_summary = {}

    for word, category in sorted(VOCAB.items(), key=lambda x: (-len(x[0]), x[0])):
        valid_placements = 0
        best_for_word = None
        best_score_for_word = -999

        for pos in range(CT_LEN - len(word) + 1):
            result = try_placement(word, pos)
            if result is None:
                continue

            result["category"] = category
            s = score_placement(result)
            result["composite_score"] = s
            valid_placements += 1

            if s > best_score_for_word:
                best_score_for_word = s
                best_for_word = result

            if result["bean_violations"] == 0 and result["bean_eq_ok"]:
                all_results.append(result)

        if best_for_word:
            word_summary[word] = {
                "valid_placements": valid_placements,
                "best_score": best_score_for_word,
                "best_pos": best_for_word["pos"],
                "best_new_ap_rate": best_for_word["new_ap_rate"],
                "best_new_key": best_for_word["new_key_str"],
                "category": category,
            }

    # Sort by composite score
    all_results.sort(key=lambda x: -x["composite_score"])

    # Report
    print(f"\n{'─'*70}")
    print(f"RESULTS: {len(all_results)} valid Bean-consistent placements")
    print(f"{'─'*70}")

    # Top placements by AP enrichment
    print(f"\n  TOP 30 BY COMPOSITE SCORE (AP enrichment + IC match):")
    print(f"  {'Score':>6} {'Word':<20} {'Pos':>4} {'NewAP':>6} {'MrgAP':>6} {'MrgIC':>7} {'NewKey'}")
    print(f"  {'─'*6} {'─'*20} {'─'*4} {'─'*6} {'─'*6} {'─'*7} {'─'*30}")
    for r in all_results[:30]:
        print(
            f"  {r['composite_score']:>6.1f} {r['word']:<20} {r['pos']:>4} "
            f"{r['new_ap_rate']:>5.0%} {r['merged_ap_rate']:>5.0%} "
            f"{r['merged_ic']:>7.4f} {r['new_key_str'][:30]}"
        )

    # Summary by category
    print(f"\n  BEST PLACEMENT PER WORD (sorted by AP enrichment):")
    sorted_words = sorted(
        word_summary.items(),
        key=lambda x: -x[1]["best_new_ap_rate"]
    )
    print(f"  {'Word':<20} {'Cat':<15} {'#Valid':>6} {'BestPos':>7} {'AP%':>5} {'Key fragment'}")
    print(f"  {'─'*20} {'─'*15} {'─'*6} {'─'*7} {'─'*5} {'─'*30}")
    for word, info in sorted_words[:50]:
        print(
            f"  {word:<20} {info['category']:<15} {info['valid_placements']:>6} "
            f"{info['best_pos']:>7} {info['best_new_ap_rate']:>4.0%} "
            f"{info['best_new_key'][:30]}"
        )

    # Statistical summary
    print(f"\n  STATISTICAL SUMMARY:")
    all_new_ap_rates = [r["new_ap_rate"] for r in all_results]
    print(f"  Mean new AP rate across all placements: {sum(all_new_ap_rates)/len(all_new_ap_rates):.1%}")
    print(f"  Baseline (random): {3/26:.1%}")
    print(f"  Known crib AP rate: {KNOWN_AP_RATE:.1%}")

    # How many placements have new AP rate >= 40%?
    high_ap = [r for r in all_results if r["new_ap_rate"] >= 0.4]
    print(f"  Placements with new AP >= 40%: {len(high_ap)}/{len(all_results)} = {len(high_ap)/max(1,len(all_results)):.1%}")

    # Bean violations
    print(f"  Bean-violating placements (excluded): counted but not stored")

    # Words with ZERO valid placements (completely impossible)
    impossible = [w for w in VOCAB if w not in word_summary]
    if impossible:
        print(f"\n  IMPOSSIBLE WORDS (conflict with cribs at every position):")
        for w in sorted(impossible, key=lambda x: -len(x)):
            print(f"    {w}")

    # Specific interesting checks
    print(f"\n  KEY OBSERVATIONS:")

    # Check: does ALEXANDERPLATZ fit anywhere?
    if "ALEXANDERPLATZ" in word_summary:
        info = word_summary["ALEXANDERPLATZ"]
        print(f"  ALEXANDERPLATZ: {info['valid_placements']} valid positions, "
              f"best AP={info['best_new_ap_rate']:.0%} at pos {info['best_pos']}")
    else:
        print(f"  ALEXANDERPLATZ: IMPOSSIBLE (conflicts at all positions)")

    # Check: does MAUER fit?
    if "MAUER" in word_summary:
        info = word_summary["MAUER"]
        print(f"  MAUER: {info['valid_placements']} valid positions, "
              f"best AP={info['best_new_ap_rate']:.0%} at pos {info['best_pos']}")

    # Check: does WALL fit?
    if "WALL" in word_summary:
        info = word_summary["WALL"]
        print(f"  WALL: {info['valid_placements']} valid positions, "
              f"best AP={info['best_new_ap_rate']:.0%} at pos {info['best_pos']}")

    # Check: does PROTEST fit?
    if "PROTEST" in word_summary:
        info = word_summary["PROTEST"]
        print(f"  PROTEST: {info['valid_placements']} valid positions, "
              f"best AP={info['best_new_ap_rate']:.0%} at pos {info['best_pos']}")

    # Save results
    output_path = os.path.join(_ROOT, "results", "f_berlin_wall_crib_drag_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "experiment": "berlin_wall_crib_drag_v1",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "n_words": len(VOCAB),
            "n_valid_placements": len(all_results),
            "known_ap_rate": KNOWN_AP_RATE,
            "top50": all_results[:50],
            "word_summary": word_summary,
            "impossible_words": impossible,
        }, f, indent=2)
    print(f"\n  Results: {output_path}")

    elapsed = time.time() - t_start
    print(f"  Elapsed: {elapsed:.1f}s")
    print("=" * 70)


if __name__ == "__main__":
    main()
