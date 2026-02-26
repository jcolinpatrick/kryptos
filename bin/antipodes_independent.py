#!/usr/bin/env python3
"""ANT-001: Antipodes as Independent Cipher

Tests the hypothesis that the Antipodes sculpture constitutes an independent
encipherment with different plaintext, different section boundaries (defined
by the SPACE delimiter), and possibly different keys — despite the ciphertext
being 99.5% identical to Kryptos.

Key structural observations:
  - Antipodes starts with K3 (not K1), reads K3→K4→[SPACE]→K1→K2
  - ONE SPACE between K4 and K1 (pass 1 only) — the only delimiter
  - K3 and K4 flow continuously with NO delimiter (merged block: 433 chars)
  - Tableau is 33 cols wide (vs 30 on Kryptos), with NO anomalies
  - UNDERGROUND spelling corrected (one CT char change: R→E)

Phase 1: Transcription audit (diff Antipodes vs Kryptos, delta file)
Phase 2: Baseline null test (apply Kryptos keys K1/K2 — do they still work?)
Phase 3: Statistical analysis of Antipodes segments (IC, Kasiski, frequency)
Phase 4: Merged K3+K4 block analysis (cross-boundary continuity)
Phase 5: Delta analysis (what does the one character difference tell us?)

Usage:
    PYTHONPATH=src python3 -u bin/antipodes_independent.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter, defaultdict
from math import gcd, log
from functools import reduce
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD,
    CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET,
    NOISE_FLOOR,
)
from kryptos.kernel.scoring.ic import ic, ic_by_position
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, DECRYPT_FN, KEY_RECOVERY,
)

# ── Paths ────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results" / "ant_001"
SUMMARY_FILE = ROOT / "reports" / "ant_001.summary.json"

# ── Alphabets ────────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KA)}
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX: Dict[str, int] = {c: i for i, c in enumerate(AZ)}

# ── Antipodes Grid (47 rows, letters only) ───────────────────────────────────

ANTIPODES_ROWS = [
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACH",
    "TNREYULDSLLSLLNOHSNOSMRWXMNETPRNG",
    "ATIHNRARPESLNNELEBLPIIACAEWMTWNDITE",
    "ENRAHCTENEUDRETNHAEOETFOLSEDTIWENH",
    "AEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWE",
    "NATAMATEGYEERLBTEEFOASFIOTUETUAEOT",
    "OARMAEERTNRTIBSEDDNIAAHTTMSTEWPIER",
    "OAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDD",
    "RYDLORITRKLMLEHAGTDHARDPNEOHMGFMF",
    "EUHEECDMRIPFEIMEHNLSSTTRTVDOHWOBK",
    "RUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTW",
    "TQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZF",
    "PKWGDKZXTJCDIGKUHUAUEKCAREMUFPHZL",
    "RFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQV",
    "YUVLLTREVJYQTMKYRDMFDVFPJUDEEHZWE",
    "TZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQ",
    "ZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDA",
    "GDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJL",
    "BQCETBJDFHRRYIZETKZEMVDUFKSJHKFWHK",
    "UWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYC",
    "UQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLA",
    "VIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF",
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZ",
    "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFM",
    "PNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBE",
    "DMHDAFMJGZNUPLGEWJLLAETGENDYAHROH",
    "NLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSL",
    "LSLLNOHSNOSMRWXMNETPRNGATIHNRARPE",
    "SLNNELEBLPIIACAEWMTWNDITEENRAHCTEN",
    "EUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQ",
    "HEENCTAYCREIFTBRSPAMHHEWENATAMATEG",
    "YEERLBTEEFOASFIOTUETUAEOTOARMAEERT",
    "NRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKL",
    "MLEHAGTDHARDPNEOHMGFMFEUHEECDMRIP",
    "FEIMEHNLSSTTRTVDOHWOBKRUOXOGHULBS",
    "OLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZ",
    "WATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJ",
    "CDIGKUHUAUEKCAREMUFPHZLRFAXYUSDJKZ",
    "LDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJY",
    "QTMKYRDMFDVFPJUDEEHZWETZYVGWHKKQ",
    "ETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPF",
    "XHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNG",
    "EUNAQZGZLECGYUXUEENJTBJLBQCETBJDFH",
    "RRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIH",
    "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLD",
    "KFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ",
]

FLAT = "".join(ANTIPODES_ROWS)

# ── Kryptos section ciphertexts (for diffing) ───────────────────────────────

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

# Kryptos K2 CT — has BQCRT (UNDERGRUUND)
K2_CT_KRYPTOS = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

K4_CT = CT  # from constants

# Known plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT_KRYPTOS = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION"
    "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWS"
    "THEEXACTLOCATIONONLYWWTHISISHISTLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
    "FORTYFOURSECONDSWESTXLAYERTWO"
)
K2_PT_ANTIPODES = K2_PT_KRYPTOS.replace("UNDERGRUUND", "UNDERGROUND")

K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
    "OTHEEARLIESTTASKWASENTALANTSANDHOWTESIDWALLSITTWASFORCED"
    "HEWALLSLOWLYWERECAVINGINTHEYWEREONLYABLETONOTREADITVERYC"
    "LEARLYWASTHEREACHAROOMBEYONDTHECHAMBERQCANYOUSEEANYTHINGQ"
)

# ── Antipodes segment boundaries ────────────────────────────────────────────
# Based on verified reconstruction (human inspection, 2026-02-25)
# Sequence: K3 → K4 → [SPACE] → K1 → K2 → K3 → K4 → K1 → K2 (truncated)
# The SPACE is the ONLY physical delimiter.

# Find K4 in flat text to establish boundaries
K4_START = FLAT.find(K4_CT)
assert K4_START >= 0, "K4 not found in Antipodes flat text"

# Section boundaries (pass 1)
K3_START = 0
K3_END = K4_START                    # K3: [0, K4_START)
K4_END = K4_START + CT_LEN           # K4: [K4_START, K4_END)
K1_START = K4_END                    # K1 starts right after K4 (SPACE is physical, not in text data)
K1_END = K1_START + len(K1_CT)       # K1: [K1_START, K1_END)
K2_START = K1_END                    # K2: [K2_START, ...)
# Pass 1 ends where pass 2 K3 starts
K4_START_P2 = FLAT.find(K4_CT, K4_START + 1)
PASS1_LEN = K4_START_P2 - len(K3_CT)  # approximate
K2_END = K4_START_P2 - len(K3_CT)     # end of K2 in pass 1

# Extract sections
AP_K3 = FLAT[K3_START:K3_END]
AP_K4 = FLAT[K4_START:K4_END]
AP_K1 = FLAT[K1_START:K1_END]
AP_K2 = FLAT[K2_START:K2_START + len(K2_CT_KRYPTOS)]

# Delimiter-defined segments
STREAM_ALPHA = FLAT[K3_START:K4_END]     # K3+K4 before SPACE (433 chars)
STREAM_BETA = FLAT[K1_START:K2_START + len(K2_CT_KRYPTOS)]  # K1+K2 after SPACE

# Merged K3+K4 block
MERGED = AP_K3 + AP_K4

print(f"Antipodes flat text: {len(FLAT)} chars")
print(f"K3 section: pos [{K3_START}, {K3_END}) = {len(AP_K3)} chars")
print(f"K4 section: pos [{K4_START}, {K4_END}) = {len(AP_K4)} chars")
print(f"  [SPACE delimiter between K4 and K1 — physical only]")
print(f"K1 section: pos [{K1_START}, {K1_END}) = {len(AP_K1)} chars")
print(f"K2 section: pos [{K2_START}, {K2_START + len(AP_K2)}) = {len(AP_K2)} chars")
print(f"Stream Alpha (K3+K4): {len(STREAM_ALPHA)} chars")
print(f"Stream Beta  (K1+K2): {len(STREAM_BETA)} chars")
print(f"Merged K3+K4: {len(MERGED)} chars")


# ── Helper functions ─────────────────────────────────────────────────────────


def decrypt_ka_vigenere(ct: str, keyword: str) -> str:
    """Decrypt ciphertext using KA Vigenere with keyword."""
    fn = DECRYPT_FN[CipherVariant.VIGENERE]
    kw_len = len(keyword)
    key = [KA_IDX[keyword[i % kw_len]] for i in range(len(ct))]
    return "".join(KA[fn(KA_IDX[ct[i]], key[i])] for i in range(len(ct)))


def frequency_analysis(text: str) -> Dict[str, float]:
    """Letter frequency as percentages."""
    counts = Counter(text)
    total = sum(counts.values())
    return {c: counts.get(c, 0) / total * 100 for c in AZ}


def kasiski_analysis(text: str, min_n: int = 3, max_n: int = 5) -> Dict[str, Any]:
    """Find repeated n-grams and estimate period from spacing GCDs."""
    spacings: List[int] = []
    repeated_grams: Dict[str, List[int]] = {}

    for n in range(min_n, max_n + 1):
        positions: Dict[str, List[int]] = defaultdict(list)
        for i in range(len(text) - n + 1):
            gram = text[i:i + n]
            positions[gram].append(i)

        for gram, pos_list in positions.items():
            if len(pos_list) >= 2:
                if len(pos_list) <= 5:
                    repeated_grams[gram] = pos_list
                for i in range(len(pos_list)):
                    for j in range(i + 1, len(pos_list)):
                        spacings.append(pos_list[j] - pos_list[i])

    if not spacings:
        return {"spacings": [], "factor_counts": {}, "top_periods": [],
                "repeated_grams": len(repeated_grams)}

    # Count factor occurrences
    factor_counts: Dict[int, int] = defaultdict(int)
    for s in spacings:
        for f in range(2, min(s + 1, 40)):
            if s % f == 0:
                factor_counts[f] += 1

    top = sorted(factor_counts.items(), key=lambda x: -x[1])[:10]
    return {
        "n_spacings": len(spacings),
        "factor_counts": dict(top),
        "top_periods": [p for p, _ in top[:5]],
        "repeated_grams": len(repeated_grams),
    }


def friedman_estimate(text: str) -> Optional[float]:
    """Estimate key period using Friedman test (IC-based)."""
    ic_val = ic(text)
    n = len(text)
    kp = 0.0667  # English IC
    kr = 1.0 / 26  # Random IC
    if ic_val <= kr:
        return None
    return (kp - kr) * n / ((n - 1) * ic_val - n * kr + kp)


def ic_period_scan(text: str, max_period: int = 30) -> List[Tuple[int, float]]:
    """Compute average IC at each period. High values suggest the correct period."""
    results = []
    for p in range(1, min(max_period + 1, len(text) // 3)):
        ics = ic_by_position(text, p)
        avg_ic = sum(ics) / len(ics) if ics else 0
        results.append((p, avg_ic))
    return results


def chi_squared_english(text: str) -> float:
    """Chi-squared statistic against English letter frequencies."""
    english_freq = {
        'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
        'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
        'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
        'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
        'U': 2.758, 'V': 0.978, 'W': 2.361, 'X': 0.150, 'Y': 1.974,
        'Z': 0.074,
    }
    n = len(text)
    counts = Counter(text)
    chi2 = 0.0
    for c in AZ:
        observed = counts.get(c, 0)
        expected = english_freq[c] / 100 * n
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Transcription Audit
# ══════════════════════════════════════════════════════════════════════════════


def phase1_transcription_audit() -> Dict[str, Any]:
    """Diff Antipodes against Kryptos character-by-character."""
    print("\n" + "=" * 70)
    print("PHASE 1: Transcription Audit")
    print("=" * 70)

    # Build Kryptos full CT in Kryptos order: K1+K2+K3+K4
    kryptos_full = K1_CT + K2_CT_KRYPTOS + K3_CT + K4_CT
    # Antipodes order (pass 1): K3+K4+K1+K2
    antipodes_pass1 = K3_CT + K4_CT + K1_CT + K2_CT_KRYPTOS

    # Diff Antipodes flat text against expected Antipodes order
    # The Antipodes should match K3+K4+K1+K2(corrected) repeated
    expected_ap = AP_K3 + AP_K4 + AP_K1  # first 3 sections from flat text

    deltas: List[Dict[str, Any]] = []

    # Diff K3 section
    for i in range(len(AP_K3)):
        if i < len(K3_CT) and AP_K3[i] != K3_CT[i]:
            deltas.append({
                "section": "K3", "pos_in_section": i,
                "pos_in_flat": K3_START + i,
                "kryptos": K3_CT[i], "antipodes": AP_K3[i],
            })

    # Diff K4 section
    for i in range(len(AP_K4)):
        if AP_K4[i] != K4_CT[i]:
            deltas.append({
                "section": "K4", "pos_in_section": i,
                "pos_in_flat": K4_START + i,
                "kryptos": K4_CT[i], "antipodes": AP_K4[i],
            })

    # Diff K1 section
    for i in range(min(len(AP_K1), len(K1_CT))):
        if AP_K1[i] != K1_CT[i]:
            deltas.append({
                "section": "K1", "pos_in_section": i,
                "pos_in_flat": K1_START + i,
                "kryptos": K1_CT[i], "antipodes": AP_K1[i],
            })

    # Diff K2 section
    for i in range(min(len(AP_K2), len(K2_CT_KRYPTOS))):
        if AP_K2[i] != K2_CT_KRYPTOS[i]:
            deltas.append({
                "section": "K2", "pos_in_section": i,
                "pos_in_flat": K2_START + i,
                "kryptos": K2_CT_KRYPTOS[i], "antipodes": AP_K2[i],
            })

    print(f"\n  Character differences found: {len(deltas)}")
    for d in deltas:
        print(f"    {d['section']}[{d['pos_in_section']}] (flat[{d['pos_in_flat']}]): "
              f"Kryptos='{d['kryptos']}' -> Antipodes='{d['antipodes']}'")

    # Verify UNDERGROUND correction
    underground_found = any(
        d["section"] == "K2" and d["kryptos"] == "R" and d["antipodes"] == "E"
        for d in deltas
    )
    print(f"\n  UNDERGROUND correction (R->E): {'FOUND' if underground_found else 'NOT FOUND'}")

    if len(deltas) == 1 and underground_found:
        print("  Result: EXACTLY ONE difference — the UNDERGROUND correction only.")
        print("  Implication: Ciphertext is character-identical except for one spelling fix.")
    elif len(deltas) == 0:
        print("  Result: ZERO differences — ciphertext is IDENTICAL.")
    else:
        print(f"  Result: {len(deltas)} differences found — investigate!")

    # Section boundary summary
    print(f"\n  Antipodes reading order (pass 1):")
    print(f"    K3 ({len(AP_K3)} chars) -> K4 ({len(AP_K4)} chars) -> "
          f"[SPACE] -> K1 ({len(AP_K1)} chars) -> K2 ({len(AP_K2)} chars)")
    print(f"    Total pass 1: {len(AP_K3) + len(AP_K4) + len(AP_K1) + len(AP_K2)} chars")

    return {"deltas": deltas, "underground_found": underground_found}


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Baseline Null Test
# ══════════════════════════════════════════════════════════════════════════════


def phase2_baseline_null_test() -> Dict[str, Any]:
    """Apply known Kryptos keys to Antipodes sections."""
    print("\n" + "=" * 70)
    print("PHASE 2: Baseline Null Test")
    print("  Question: Do the Kryptos keys (PALIMPSEST, ABSCISSA) decrypt")
    print("  the Antipodes sections to the same plaintexts?")
    print("=" * 70)

    results = {}

    # Test K1: PALIMPSEST
    print("\n  --- K1 section: keyword PALIMPSEST ---")
    ap_k1_pt = decrypt_ka_vigenere(AP_K1, "PALIMPSEST")
    k1_match = ap_k1_pt == K1_PT
    print(f"  Antipodes K1 decrypted: {ap_k1_pt[:40]}...")
    print(f"  Expected K1 plaintext:  {K1_PT[:40]}...")
    print(f"  Match: {'YES — same plaintext' if k1_match else 'NO — DIFFERENT plaintext!'}")
    results["k1_match"] = k1_match
    results["k1_pt"] = ap_k1_pt

    # Test K2: ABSCISSA
    print("\n  --- K2 section: keyword ABSCISSA ---")
    ap_k2_pt = decrypt_ka_vigenere(AP_K2, "ABSCISSA")
    k2_match_kryptos = ap_k2_pt == K2_PT_KRYPTOS
    k2_match_corrected = ap_k2_pt == K2_PT_ANTIPODES
    print(f"  Antipodes K2 decrypted: ...{ap_k2_pt[100:140]}...")
    print(f"  Expected (corrected):   ...{K2_PT_ANTIPODES[100:140]}...")
    print(f"  Match (Kryptos PT):     {'YES' if k2_match_kryptos else 'NO'}")
    print(f"  Match (corrected PT):   {'YES' if k2_match_corrected else 'NO'}")

    if k2_match_corrected and not k2_match_kryptos:
        print("  Result: K2 decrypts to SAME plaintext but with UNDERGROUND fixed!")
        print("  This PROVES K2 uses the same key (ABSCISSA) on both sculptures.")
    results["k2_match_corrected"] = k2_match_corrected
    results["k2_pt"] = ap_k2_pt

    # Summary
    print("\n  === Baseline Summary ===")
    if k1_match and k2_match_corrected:
        print("  K1: SAME key, SAME plaintext")
        print("  K2: SAME key, SAME plaintext (with spelling correction)")
        print("  K3: [transposition — not tested here, but K3 CT is IDENTICAL]")
        print("  K4: [unsolved — CT is IDENTICAL to Kryptos K4]")
        print()
        print("  CONCLUSION: The Kryptos keys decrypt the Antipodes sections")
        print("  to the same plaintexts. At the FIRST LAYER, Antipodes is NOT")
        print("  an independent cipher — it uses the same keys.")
        print()
        print("  HOWEVER: This does not rule out a SECOND LAYER using the")
        print("  Antipodes tableau (33 cols, no anomalies) with a different key.")
        print("  The SPACE delimiter and different section ordering may indicate")
        print("  a different reading/interpretation of the same ciphertext.")
    else:
        print("  UNEXPECTED: Key mismatch detected — investigate!")

    results["conclusion"] = "same_keys" if (k1_match and k2_match_corrected) else "different_keys"
    return results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Statistical Analysis of Antipodes Segments
# ══════════════════════════════════════════════════════════════════════════════


def phase3_statistical_analysis() -> Dict[str, Any]:
    """IC, Kasiski, and frequency analysis of each segment."""
    print("\n" + "=" * 70)
    print("PHASE 3: Statistical Analysis")
    print("  Analyzing each Antipodes segment as if it were an unknown cipher.")
    print("=" * 70)

    results = {}

    segments = {
        "K3_CT": AP_K3,
        "K4_CT": AP_K4,
        "K1_CT": AP_K1,
        "K2_CT": AP_K2,
        "Stream_Alpha (K3+K4)": STREAM_ALPHA,
        "Stream_Beta (K1+K2)": STREAM_BETA,
        "Merged_K3K4": MERGED,
    }

    for name, text in segments.items():
        print(f"\n  --- {name} ({len(text)} chars) ---")
        seg_results: Dict[str, Any] = {"length": len(text)}

        # IC
        ic_val = ic(text)
        seg_results["ic"] = round(ic_val, 5)
        ic_interp = (
            "ENGLISH-LIKE" if ic_val > 0.055 else
            "ELEVATED" if ic_val > 0.045 else
            "NEAR-RANDOM" if ic_val > 0.035 else
            "BELOW-RANDOM"
        )
        print(f"    IC = {ic_val:.5f} ({ic_interp}; English=0.0667, random=0.0385)")

        # Chi-squared
        chi2 = chi_squared_english(text)
        seg_results["chi_squared"] = round(chi2, 1)
        print(f"    Chi-squared vs English = {chi2:.1f} (lower=more English-like)")

        # Friedman period estimate
        if len(text) >= 50:
            fp = friedman_estimate(text)
            seg_results["friedman_period"] = round(fp, 1) if fp else None
            if fp:
                print(f"    Friedman period estimate = {fp:.1f}")
            else:
                print(f"    Friedman period estimate = N/A (IC too low)")

        # Kasiski (only for longer texts)
        if len(text) >= 100:
            kas = kasiski_analysis(text)
            seg_results["kasiski_top_periods"] = kas.get("top_periods", [])
            seg_results["kasiski_n_spacings"] = kas.get("n_spacings", 0)
            if kas["top_periods"]:
                print(f"    Kasiski top periods: {kas['top_periods']} "
                      f"({kas['n_spacings']} spacings from {kas['repeated_grams']} repeated grams)")

        # IC period scan (look for the period that maximizes average IC)
        if len(text) >= 60:
            scan = ic_period_scan(text, max_period=min(26, len(text) // 4))
            best_periods = sorted(scan, key=lambda x: -x[1])[:5]
            seg_results["ic_scan_best"] = [(p, round(v, 5)) for p, v in best_periods]
            print(f"    IC-scan best periods: {[(p, f'{v:.5f}') for p, v in best_periods[:3]]}")

        # Letter frequency top 5
        freq = frequency_analysis(text)
        top5 = sorted(freq.items(), key=lambda x: -x[1])[:5]
        print(f"    Top 5 letters: {', '.join(f'{c}={v:.1f}%' for c, v in top5)}")

        results[name] = seg_results

    return results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Merged Block Analysis
# ══════════════════════════════════════════════════════════════════════════════


def phase4_merged_block() -> Dict[str, Any]:
    """Analyze the merged K3+K4 block for cross-boundary cipher continuity."""
    print("\n" + "=" * 70)
    print("PHASE 4: Merged K3+K4 Block Analysis")
    print("  The K3+K4 boundary on Antipodes has NO delimiter.")
    print("  If K3 and K4 were encrypted as ONE block, the merged IC")
    print("  should differ from the arithmetic mean of individual ICs.")
    print("=" * 70)

    results = {}

    # Individual ICs
    ic_k3 = ic(AP_K3)
    ic_k4 = ic(AP_K4)
    ic_merged = ic(MERGED)
    ic_mean = (ic_k3 * len(AP_K3) + ic_k4 * len(AP_K4)) / (len(AP_K3) + len(AP_K4))

    print(f"\n  K3 IC:     {ic_k3:.5f} ({len(AP_K3)} chars)")
    print(f"  K4 IC:     {ic_k4:.5f} ({len(AP_K4)} chars)")
    print(f"  Merged IC: {ic_merged:.5f} ({len(MERGED)} chars)")
    print(f"  Weighted mean: {ic_mean:.5f}")
    print(f"  Deviation: {ic_merged - ic_mean:+.5f}")

    results["ic_k3"] = round(ic_k3, 5)
    results["ic_k4"] = round(ic_k4, 5)
    results["ic_merged"] = round(ic_merged, 5)
    results["ic_weighted_mean"] = round(ic_mean, 5)
    results["ic_deviation"] = round(ic_merged - ic_mean, 5)

    # Interpretation
    dev = abs(ic_merged - ic_mean)
    if dev < 0.002:
        print(f"  Interpretation: Merged IC matches weighted mean within noise.")
        print(f"  No evidence of cross-boundary cipher continuity.")
        results["cross_boundary"] = "no_evidence"
    elif ic_merged > ic_mean + 0.005:
        print(f"  Interpretation: Merged IC is HIGHER than expected!")
        print(f"  This suggests the two blocks share cipher structure.")
        results["cross_boundary"] = "elevated"
    else:
        print(f"  Interpretation: Small deviation, inconclusive.")
        results["cross_boundary"] = "inconclusive"

    # Remap K4 cribs to merged block positions
    print(f"\n  --- Crib position remapping ---")
    print(f"  K4 starts at position {len(AP_K3)} in the merged block")
    print(f"  K4 crib EASTNORTHEAST (K4 pos 21-33) -> merged pos {len(AP_K3)+21}-{len(AP_K3)+33}")
    print(f"  K4 crib BERLINCLOCK   (K4 pos 63-73) -> merged pos {len(AP_K3)+63}-{len(AP_K3)+73}")

    k4_offset = len(AP_K3)
    results["k4_offset_in_merged"] = k4_offset
    results["ene_merged_pos"] = (k4_offset + 21, k4_offset + 33)
    results["bc_merged_pos"] = (k4_offset + 63, k4_offset + 73)

    # Test: does the K3 transposition pattern extend into K4?
    print(f"\n  --- Cross-boundary pattern test ---")
    # K3 was solved as a transposition cipher. If the same transposition
    # extends into K4, the K3 plaintext pattern should continue.
    # We can check: does K3 PT + K4 CT (treated as continuing transposition)
    # produce any readable extension?
    print(f"  K3 plaintext ends with: ...{K3_PT[-20:]}")
    print(f"  K4 ciphertext starts with: {K4_CT[:20]}...")
    print(f"  If K3's transposition continued, K4 CT would need to be")
    print(f"  de-transposed using K3's route, starting at position {len(K3_PT)}.")
    print(f"  (This requires K3's specific route cipher parameters —")
    print(f"   not tested here, flagged for manual investigation.)")

    # IC comparison: K3 PT vs K4 CT
    ic_k3_pt = ic(K3_PT)
    print(f"\n  K3 plaintext IC: {ic_k3_pt:.5f} (expected ~0.065 for English)")
    results["ic_k3_pt"] = round(ic_k3_pt, 5)

    # Kasiski on merged block
    print(f"\n  --- Kasiski on merged block ({len(MERGED)} chars) ---")
    kas = kasiski_analysis(MERGED)
    if kas["top_periods"]:
        print(f"  Top periods: {kas['top_periods']}")
        print(f"  ({kas['n_spacings']} spacings from {kas['repeated_grams']} repeated grams)")
    results["kasiski_merged"] = kas.get("top_periods", [])

    # IC period scan on merged block
    scan = ic_period_scan(MERGED, max_period=30)
    best = sorted(scan, key=lambda x: -x[1])[:5]
    print(f"  IC-scan best periods: {[(p, f'{v:.5f}') for p, v in best[:3]]}")
    results["ic_scan_merged"] = [(p, round(v, 5)) for p, v in best]

    return results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Delta Analysis
# ══════════════════════════════════════════════════════════════════════════════


def phase5_delta_analysis(deltas: List[Dict]) -> Dict[str, Any]:
    """Analyze the differences between Antipodes and Kryptos."""
    print("\n" + "=" * 70)
    print("PHASE 5: Delta Analysis")
    print("  The differences between Antipodes and Kryptos ciphertext.")
    print("=" * 70)

    results: Dict[str, Any] = {"n_deltas": len(deltas)}

    if len(deltas) == 0:
        print("\n  No deltas to analyze — ciphertexts are identical.")
        return results

    if len(deltas) == 1:
        d = deltas[0]
        print(f"\n  Only ONE delta: {d['section']}[{d['pos_in_section']}]")
        print(f"    Kryptos: '{d['kryptos']}' -> Antipodes: '{d['antipodes']}'")
        print(f"    Position in flat text: {d['pos_in_flat']}")

        # Compute the key implication
        k_char = d["kryptos"]
        a_char = d["antipodes"]
        diff_az = (ord(a_char) - ord(k_char)) % 26
        diff_ka = (KA_IDX[a_char] - KA_IDX[k_char]) % 26
        print(f"    AZ difference: ({a_char}-{k_char}) mod 26 = {diff_az}")
        print(f"    KA difference: ({a_char}-{k_char}) mod 26 = {diff_ka}")

        # What this tells us about the cipher
        print(f"\n  Analysis:")
        print(f"    With ABSCISSA key at K2 pos {d['pos_in_section']}:")
        print(f"    Kryptos:   CT='{k_char}' -> PT='U' (UNDERGRUUND)")
        print(f"    Antipodes: CT='{a_char}' -> PT='O' (UNDERGROUND)")
        print(f"    The ciphertext change is consistent with a plaintext change")
        print(f"    under the SAME key. This is a spelling correction, not a")
        print(f"    different cipher.")

        results["analysis"] = "spelling_correction"
        results["delta_detail"] = d
        return results

    # Multiple deltas — unexpected, analyze further
    print(f"\n  {len(deltas)} deltas found:")
    for d in deltas:
        print(f"    {d['section']}[{d['pos_in_section']}]: "
              f"'{d['kryptos']}' -> '{d['antipodes']}'")

    # Check periodicity
    positions = [d["pos_in_flat"] for d in deltas]
    if len(positions) >= 2:
        spacings = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]
        print(f"  Positions: {positions}")
        print(f"  Spacings: {spacings}")
        if len(set(spacings)) == 1:
            print(f"  PERIODIC with period {spacings[0]}!")
            results["periodic"] = True
            results["period"] = spacings[0]
        else:
            g = reduce(gcd, spacings)
            print(f"  GCD of spacings: {g}")
            results["periodic"] = False
            results["gcd"] = g

    # Read delta chars as message
    delta_chars = "".join(d["antipodes"] for d in deltas)
    kryptos_chars = "".join(d["kryptos"] for d in deltas)
    print(f"  Delta chars (Antipodes): {delta_chars}")
    print(f"  Delta chars (Kryptos):   {kryptos_chars}")
    results["delta_chars_antipodes"] = delta_chars
    results["delta_chars_kryptos"] = kryptos_chars

    return results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3b: Vigenere Period Attack
# ══════════════════════════════════════════════════════════════════════════════


def phase3b_vigenere_attack() -> Dict[str, Any]:
    """Try to solve each segment as an independent Vigenere cipher."""
    print("\n" + "=" * 70)
    print("PHASE 3b: Independent Vigenere Attack")
    print("  For each segment, try to recover the key assuming a new Vigenere")
    print("  cipher with the Antipodes KA tableau.")
    print("=" * 70)

    results = {}
    targets = [
        ("Stream_Alpha (K3+K4)", STREAM_ALPHA),
        ("Stream_Beta (K1+K2)", STREAM_BETA),
        ("K4 alone", AP_K4),
    ]

    for name, text in targets:
        print(f"\n  --- {name} ({len(text)} chars) ---")

        # Find the period that maximizes average IC of residue classes
        scan = ic_period_scan(text, max_period=min(30, len(text) // 4))
        best = sorted(scan, key=lambda x: -x[1])[:5]
        print(f"    Best periods by IC: {[(p, f'{v:.5f}') for p, v in best[:5]]}")

        # For each good period, try frequency-based key recovery (KA alphabet)
        for period, avg_ic in best[:3]:
            if avg_ic < 0.045:
                continue
            print(f"\n    Trying period {period} (avg IC = {avg_ic:.5f}):")

            # Split into residue classes
            key_guess = []
            for r in range(period):
                residue = text[r::period]
                # For each possible key value, compute chi-squared of decrypted residue
                best_k = 0
                best_chi = float('inf')
                for k in range(26):
                    fn = DECRYPT_FN[CipherVariant.VIGENERE]
                    decrypted = "".join(KA[fn(KA_IDX[c], k)] for c in residue)
                    chi = chi_squared_english(decrypted)
                    if chi < best_chi:
                        best_chi = chi
                        best_k = k
                key_guess.append(best_k)

            # Decrypt with guessed key
            fn = DECRYPT_FN[CipherVariant.VIGENERE]
            pt = "".join(
                KA[fn(KA_IDX[text[i]], key_guess[i % period])]
                for i in range(len(text))
            )
            ic_pt = ic(pt)
            chi_pt = chi_squared_english(pt)
            key_letters = "".join(KA[k] for k in key_guess)
            print(f"      Key (KA): {key_letters}")
            print(f"      PT IC: {ic_pt:.5f}, Chi-sq: {chi_pt:.1f}")
            print(f"      PT: {pt[:60]}...")

            seg_key = f"{name}_p{period}"
            results[seg_key] = {
                "period": period, "avg_ic": round(avg_ic, 5),
                "key_ka": key_letters, "pt_ic": round(ic_pt, 5),
                "chi_squared": round(chi_pt, 1),
                "plaintext_preview": pt[:100],
            }

            # Check if this is the known solution (PALIMPSEST or ABSCISSA)
            if name == "Stream_Beta (K1+K2)":
                if period == 10 and key_letters.startswith("PALIMPSEST"[:period]):
                    print(f"      ** This is the known PALIMPSEST key! **")
                if period == 8 and key_letters.startswith("ABSCISSA"[:period]):
                    print(f"      ** This is the known ABSCISSA key! **")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════


def main() -> None:
    t0 = time.time()
    print("=" * 70)
    print("ANT-001: Antipodes as Independent Cipher")
    print("=" * 70)
    print()
    print("Hypothesis: The Antipodes ciphertext, despite being 99.5% identical")
    print("to Kryptos, enciphers a DIFFERENT plaintext using different keys,")
    print("with section boundaries defined by physical delimiters (the SPACE).")
    print()
    print("The merged K3+K4 block (433 chars, continuous, no delimiter) is")
    print("potentially a single encipherment — far more tractable than")
    print("K4 alone (97 chars).")

    # Setup
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Run all phases
    p1 = phase1_transcription_audit()
    p2 = phase2_baseline_null_test()
    p3 = phase3_statistical_analysis()
    p3b = phase3b_vigenere_attack()
    p4 = phase4_merged_block()
    p5 = phase5_delta_analysis(p1["deltas"])

    # Overall summary
    elapsed = round(time.time() - t0, 1)

    print("\n" + "=" * 70)
    print("ANT-001 OVERALL SUMMARY")
    print("=" * 70)

    print(f"\n  Phase 1 (Transcription): {len(p1['deltas'])} differences found")
    print(f"  Phase 2 (Baseline): K1={'SAME' if p2.get('k1_match') else 'DIFF'} key, "
          f"K2={'SAME' if p2.get('k2_match_corrected') else 'DIFF'} key")
    print(f"  Phase 3 (Statistics): See detailed output above")
    print(f"  Phase 4 (Merged): IC deviation = {p4.get('ic_deviation', 'N/A')}")
    print(f"  Phase 5 (Delta): {p5.get('analysis', 'multiple deltas')}")

    print(f"\n  Key findings:")
    if p2.get("conclusion") == "same_keys":
        print(f"    1. K1 and K2 use the SAME keys as Kryptos (PALIMPSEST, ABSCISSA)")
        print(f"    2. The UNDERGROUND correction is a spelling fix, not a different cipher")
        print(f"    3. At the FIRST LAYER, Antipodes sections are NOT independently encrypted")
        print(f"    4. The Antipodes tableau (33 cols, zero anomalies) may serve a")
        print(f"       SECOND-LAYER purpose: decrypt the Kryptos first-layer output")
        print(f"       with a new key to reveal a different message")

    print(f"\n  Merged K3+K4 block ({len(MERGED)} chars):")
    print(f"    IC = {p4.get('ic_merged', 'N/A')} (cross-boundary: {p4.get('cross_boundary', 'N/A')})")

    print(f"\n  Open questions:")
    print(f"    1. What key decrypts the FIRST-LAYER K4 plaintext through the")
    print(f"       Antipodes tableau to produce a SECOND plaintext?")
    print(f"    2. Does the SPACE delimiter indicate where to START reading")
    print(f"       a second-layer decipherment?")
    print(f"    3. Does the K3 transposition extend continuously into K4")
    print(f"       when treated as one 433-char block?")

    print(f"\n  Elapsed: {elapsed}s")

    # Write summary
    summary = {
        "experiment": "ANT-001",
        "hypothesis": "Antipodes as independent cipher",
        "phase1_deltas": len(p1["deltas"]),
        "phase2_conclusion": p2.get("conclusion"),
        "phase3_stats": {k: v for k, v in p3.items() if isinstance(v, dict)},
        "phase4_merged_ic": p4.get("ic_merged"),
        "phase4_cross_boundary": p4.get("cross_boundary"),
        "phase5_analysis": p5.get("analysis"),
        "elapsed_s": elapsed,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\n  Summary: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
