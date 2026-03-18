#!/usr/bin/env python3 -u
"""
=================================================================
BERLIN CABLE TEMPLATE ANALYSIS v1
=================================================================
Cipher:     Model B Beaufort on raw CT97
Family:     campaigns
Status:     active

Tests FULL 97-char plaintext templates for the Berlin Wall cable
hypothesis. W's at {20,36,48,58,74} are treated as delimiters.

Each template fills the 6 segments between W-delimiters:
  Seg 1 (0-19):  20 chars
  Seg 2 (21-35): 15 chars (contains EASTNORTHEAST + 2 chars)
  Seg 3 (37-47): 11 chars
  Seg 4 (49-57):  9 chars
  Seg 5 (59-73): 15 chars (contains BERLINCLOCK + 4 chars)
  Seg 6 (75-96): 22 chars

For each template, computes the full Beaufort keystream and checks:
  - AP {G,K,O} rate across all 97 positions
  - IC of the key
  - Key readability (quadgram score)
  - Bean constraint satisfaction
  - Whether key fragments match known texts
=================================================================
"""

import sys
import os
import json
import time
import re
import itertools
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

# ── Quadgrams ──────────────────────────────────────────────────────────

QG_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
with open(QG_PATH) as f:
    _qg_raw = json.load(f)
QG_FLOOR = min(_qg_raw.values()) - 1.0
QG_TABLE = [QG_FLOOR] * (26 ** 4)
for gram, logp in _qg_raw.items():
    if len(gram) == 4:
        a, b, c, d = [ord(ch) - 65 for ch in gram]
        QG_TABLE[a * 17576 + b * 676 + c * 26 + d] = logp
del _qg_raw


def qg_score_arr(arr):
    n = len(arr)
    if n < 4:
        return QG_FLOOR
    total = sum(QG_TABLE[arr[i]*17576 + arr[i+1]*676 + arr[i+2]*26 + arr[i+3]]
                for i in range(n - 3))
    return total / (n - 3)

# ── Constants ──────────────────────────────────────────────────────────

CT_ARR = [ALPH_IDX[c] for c in CT]
AP_VALUES = frozenset({6, 10, 14})
W_POSITIONS = [20, 36, 48, 58, 74]

# Segment boundaries (between W-delimiters)
SEGMENTS = [
    (0, 19, 20),    # seg 1: 20 chars
    (21, 35, 15),   # seg 2: 15 chars (ENE + 2)
    (37, 47, 11),   # seg 3: 11 chars
    (49, 57, 9),    # seg 4: 9 chars
    (59, 73, 15),   # seg 5: 15 chars (BCL + 4)
    (75, 96, 22),   # seg 6: 22 chars
]

# ── Key computation ────────────────────────────────────────────────────

def compute_full_key(plaintext_97):
    """Compute Beaufort key for a 97-char plaintext."""
    assert len(plaintext_97) == 97, f"Need 97 chars, got {len(plaintext_97)}"
    pt_arr = [ALPH_IDX[c] for c in plaintext_97.upper()]
    key_arr = [(CT_ARR[i] + pt_arr[i]) % MOD for i in range(97)]
    return key_arr


def check_cribs(plaintext_97):
    """Check if plaintext matches known cribs."""
    for pos, ch in CRIB_DICT.items():
        if plaintext_97[pos] != ch:
            return False, pos
    return True, -1


def check_bean(key_arr):
    """Check Bean constraints."""
    # Equality
    for a, b in BEAN_EQ:
        if key_arr[a] != key_arr[b]:
            return False, f"EQ violation: k[{a}]={key_arr[a]} != k[{b}]={key_arr[b]}"
    # Inequalities
    violations = 0
    for a, b in BEAN_INEQ:
        if key_arr[a] == key_arr[b]:
            violations += 1
    return violations == 0, f"{violations} inequality violations"


def analyze_key(key_arr):
    """Compute key statistics."""
    n = len(key_arr)
    ap_count = sum(1 for v in key_arr if v in AP_VALUES)
    freq = Counter(key_arr)
    ic = sum(f*(f-1) for f in freq.values()) / (n * (n-1)) if n > 1 else 0
    distinct = len(freq)
    key_str = "".join(ALPH[v] for v in key_arr)
    key_qg = qg_score_arr(key_arr)

    return {
        "key_str": key_str,
        "ap_count": ap_count,
        "ap_rate": ap_count / n,
        "ic": ic,
        "distinct": distinct,
        "key_qg": key_qg,
    }


# ── Segment fillers ───────────────────────────────────────────────────

# Seg 2 suffixes (2 chars after EASTNORTHEAST, positions 34-35)
SEG2_SUFFIXES = ["OF", "AT", "TO", "IS", "BY", "IN", "ON"]

# Seg 5 prefixes (4 chars before BERLINCLOCK, positions 59-62)
SEG5_PREFIXES = ["NEAR", "FROM", "PAST", "OVER", "ATTH", "BYTH", "OFTH"]

# Seg 3 options (11 chars, positions 37-47)
SEG3_OPTIONS = [
    "OVERTHEWALL",     # Over the Wall
    "BREACHWALL",      # Breach + Wall (10 chars, need padding?)
    "THEBERLINWA",     # The Berlin Wa[ll] — truncated
    "THROUGHWALL",     # Through wall
    "THELODESTON",     # The Lodeston (telegram model guess)
    "PASTTHEWALL",     # Past the wall
    "ATTHEGATEAT",     # At the gate at
    "CROSSEDWALL",     # Crossed wall
    "BORDERATWAL",     # Border at Wal[l]
    "THEFALLOFTH",     # The fall of th[e wall]
    "ACROSSTHEBL",     # Across the bl[ock]
    "PROTESTSATW",     # Protests at W[eltzeituhr]
]

# Seg 4 options (9 chars, positions 49-57)
SEG4_OPTIONS = [
    "THOUSANDS",       # Thousands (crowd estimate)
    "FIVEPACES",       # Five paces (telegram model)
    "HUNDREDSOF",      # Hundreds of — 10 chars, too long
    "MASSIVECRO",      # Massive cro[wd] — truncated
    "CROWDSGATH",      # Crowds gath[ered] — truncated
    "ISBREACHED",      # Is breached
    "ISOPENREPO",      # Is open repo[rt]
    "WALLISOPEN",      # Wall is open — 10 chars too long
    "ATTHEGATE",       # At the gate
    "REGIMEFALL",      # Regime fall — 10 chars too long
    "IMMEDIATE",       # Cable priority
    "FLASHREPOR",      # Flash repor[t] — truncated
    "AEDYNAMIC",       # CIA cryptonym (Soviet ops)
    "BGFIENDOP",       # CIA cryptonym (Communist bloc)
]

# Seg 1 options (20 chars, positions 0-19)
SEG1_OPTIONS = [
    "REPORTFROMEASTBERLIN",  # Report from East Berlin
    "FLASHREPORTFROMBERLI",  # Flash report from Berli[n]
    "ITISLOCATEDEXACTLYAT",  # Telegram model guess
    "PRIORITYFROMEASTBERL",  # Priority from East Berl[in]
    "SECRETFROMBERLINSTAT",  # Secret from Berlin stat[ion]
    "URGENTREPORTFROMEAST",  # Urgent report from east
    "TOLANGLEYFROMEASTBER",  # To Langley from East Ber[lin]
    "STATIONTOLANGLEYWALL",  # Station to Langley wall
    "SUBJECTPROTESTATALEX",  # Subject protest at Alex[anderplatz]
    "FROMAGENTATBERLINEAS",  # From agent at Berlin eas[t]
    "BORDERINCIDENTREPORT",  # Border incident report
    "AEDYNAMICOPSBERLINES",  # AE DYNAMIC ops Berlin es[t]
    "SITUATIONREPORTBERLI",  # Situation report Berli[n]
]

# Seg 6 options (22 chars, positions 75-96)
SEG6_OPTIONS = [
    "ALEXANDERPLATZPROTESTS",  # Alexanderplatz protests
    "LANGLEYDOESNOTKNOWTHIS",  # Telegram model guess
    "REGIMECOLLAPSEPOSSIBLE",  # Regime collapse possible
    "THOUSANDSATTHEWORLDCLO",  # Thousands at the world clo[ck]
    "ALEXANDERPLATZDEMOCRAC",  # Alexanderplatz democrac[y]
    "WALLBREACHIMMINENTRECO",  # Wall breach imminent reco[mmend]
    "WALLBREACHIMMINENTADVI",  # Wall breach imminent advi[se]
    "REQUESTIMMEDIATEINTELR",  # Request immediate intel r[eport]
    "BORDERISOPENCROWDSFLOW",  # Border is open crowds flow
    "MASSIVEDEMONSTRATIONAT",  # Massive demonstration at
    "CROWDESTIMATEOVERMILLI",  # Crowd estimate over milli[on]
    "BERLINWALLHASBEENOPENE",  # Berlin Wall has been opene[d]
    "EASTSECTORUNSTABLEADVI",  # East sector unstable advi[se]
    "ENDOFANERAADVISELANGLE",  # End of an era advise Langle[y]
]

# ── Template assembly ──────────────────────────────────────────────────

def assemble_template(seg1, seg2_suffix, seg3, seg4, seg5_prefix, seg6):
    """Assemble a 97-char plaintext from segment fillers."""
    seg2 = "EASTNORTHEAST" + seg2_suffix
    seg5 = seg5_prefix + "BERLINCLOCK"

    # Validate lengths
    parts = [seg1, seg2, seg3, seg4, seg5, seg6]
    expected = [20, 15, 11, 9, 15, 22]
    for p, e, name in zip(parts, expected, ["seg1","seg2","seg3","seg4","seg5","seg6"]):
        if len(p) != e:
            return None  # wrong length

    # Assemble with W delimiters
    pt = seg1 + "W" + seg2 + "W" + seg3 + "W" + seg4 + "W" + seg5 + "W" + seg6
    assert len(pt) == 97, f"Template length {len(pt)} != 97"
    return pt


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t_start = time.time()

    print("=" * 70)
    print("Berlin Cable Template Analysis v1")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"W-delimiters at: {W_POSITIONS}")
    print(f"Segments: {[(s,e,l) for s,e,l in SEGMENTS]}")

    # Filter to correct-length options
    seg1_valid = [s for s in SEG1_OPTIONS if len(s) == 20]
    seg3_valid = [s for s in SEG3_OPTIONS if len(s) == 11]
    seg4_valid = [s for s in SEG4_OPTIONS if len(s) == 9]
    seg6_valid = [s for s in SEG6_OPTIONS if len(s) == 22]

    print(f"\nValid options: seg1={len(seg1_valid)}, seg2_sfx={len(SEG2_SUFFIXES)}, "
          f"seg3={len(seg3_valid)}, seg4={len(seg4_valid)}, "
          f"seg5_pfx={len(SEG5_PREFIXES)}, seg6={len(seg6_valid)}")

    total = (len(seg1_valid) * len(SEG2_SUFFIXES) * len(seg3_valid) *
             len(seg4_valid) * len(SEG5_PREFIXES) * len(seg6_valid))
    print(f"Total templates: {total:,}")

    results = []
    crib_ok_count = 0
    bean_ok_count = 0
    tested = 0

    for seg1 in seg1_valid:
        for seg2_sfx in SEG2_SUFFIXES:
            for seg3 in seg3_valid:
                for seg4 in seg4_valid:
                    for seg5_pfx in SEG5_PREFIXES:
                        for seg6 in seg6_valid:
                            pt = assemble_template(
                                seg1, seg2_sfx, seg3, seg4, seg5_pfx, seg6
                            )
                            if pt is None:
                                continue
                            tested += 1

                            # Check cribs
                            crib_ok, fail_pos = check_cribs(pt)
                            if not crib_ok:
                                continue
                            crib_ok_count += 1

                            # Compute key
                            key_arr = compute_full_key(pt)

                            # Check Bean
                            bean_ok, bean_msg = check_bean(key_arr)
                            if not bean_ok:
                                continue
                            bean_ok_count += 1

                            # Analyze
                            stats = analyze_key(key_arr)
                            stats["plaintext"] = pt
                            stats["seg1"] = seg1
                            stats["seg2_sfx"] = seg2_sfx
                            stats["seg3"] = seg3
                            stats["seg4"] = seg4
                            stats["seg5_pfx"] = seg5_pfx
                            stats["seg6"] = seg6

                            results.append(stats)

    print(f"\nTested: {tested:,}")
    print(f"Crib-consistent: {crib_ok_count:,}")
    print(f"Bean-consistent: {bean_ok_count:,}")

    if not results:
        print("\n  NO templates pass both crib and Bean checks.")
        return

    # Sort by AP rate descending, then by key IC proximity to 0.08
    results.sort(key=lambda x: (-x["ap_rate"], -abs(x["ic"] - 0.0797)))

    print(f"\n{'='*70}")
    print(f"TOP 20 TEMPLATES BY AP RATE")
    print(f"{'='*70}")
    print(f"  {'AP%':>5} {'IC':>7} {'KeyQG':>7} {'Dist':>4}  Plaintext summary")
    print(f"  {'─'*5} {'─'*7} {'─'*7} {'─'*4}  {'─'*50}")

    for r in results[:20]:
        summary = f"{r['seg1'][:10]}..{r['seg3']}..{r['seg4']}..{r['seg6'][:10]}"
        print(
            f"  {r['ap_rate']:>4.0%} {r['ic']:>7.4f} {r['key_qg']:>7.3f} "
            f"{r['distinct']:>4}  {summary}"
        )
        print(f"        KEY: {r['key_str']}")
        print(f"         PT: {r['plaintext'][:50]}...")

    # Best by key quadgram (most English-like key)
    results_by_kqg = sorted(results, key=lambda x: -x["key_qg"])
    print(f"\n{'='*70}")
    print(f"TOP 10 BY KEY READABILITY (quadgram)")
    print(f"{'='*70}")
    for r in results_by_kqg[:10]:
        print(f"  KeyQG={r['key_qg']:.3f} AP={r['ap_rate']:.0%} IC={r['ic']:.4f}")
        print(f"    KEY: {r['key_str']}")
        print(f"     PT: {r['plaintext']}")

    # Statistical summary
    all_ap = [r["ap_rate"] for r in results]
    all_ic = [r["ic"] for r in results]
    print(f"\n{'='*70}")
    print(f"STATISTICS ACROSS {len(results)} VALID TEMPLATES")
    print(f"{'='*70}")
    print(f"  AP rate:  mean={sum(all_ap)/len(all_ap):.1%}, "
          f"max={max(all_ap):.1%}, min={min(all_ap):.1%}")
    print(f"  Key IC:   mean={sum(all_ic)/len(all_ic):.4f}, "
          f"max={max(all_ic):.4f}, min={min(all_ic):.4f}")
    print(f"  Known crib AP rate: 50%")
    print(f"  Random AP baseline: 11.5%")

    # Save
    output_path = os.path.join(_ROOT, "results", "f_berlin_cable_templates_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "experiment": "berlin_cable_templates_v1",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "tested": tested,
            "crib_ok": crib_ok_count,
            "bean_ok": bean_ok_count,
            "top20_by_ap": results[:20],
            "top10_by_kqg": results_by_kqg[:10],
        }, f, indent=2)
    print(f"\n  Results: {output_path}")

    elapsed = time.time() - t_start
    print(f"  Elapsed: {elapsed:.1f}s")
    print("=" * 70)


if __name__ == "__main__":
    main()
