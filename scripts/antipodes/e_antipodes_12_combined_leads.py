#!/usr/bin/env python3
"""
Cipher: polyalphabetic/insertion
Family: antipodes
Status: exhausted
Keyspace: ~500,000 configs
Last run:
Best score:

E-ANTIPODES-12: Combined Antipodes Leads — Keywords, Insertion, Seeding

Tests four leads from the 2026-04-01 Antipodes investigation:

LEAD 1: ANTIPODES as keyword (Jefferson precedent — he used it as a Vigenère
        keyword example for Lewis & Clark)
LEAD 2: Thematic keywords from light/shadow duality:
        SHADOW (COF-Small keyword), LIGHT, CANDLE, SVET, DECEIT (COF-Large),
        ANTIPODES, COVERTBALANCE, SEVEN, PENETRATED
LEAD 3: Character insertion/removal at positions in K4 (COF precedent —
        dots mark where chars were removed, inserting them restores key
        alignment). Test removing 1-3 chars and inserting 1-3 chars.
LEAD 4: Extra L as seed — archive says "Extra L at end of line, Bottom
        chart seeding." Test L (AZ=11, KA=12) as key offset.
LEAD 5: LAYERTWO insertion — community noted 8 chars = LAYERTWO, matching
        the COF's 8-char insertion requirement.

All tested under Vigenere, Beaufort, and Variant Beaufort.
"""

import sys
import os
import time
import itertools
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, ALPH, ALPH_IDX, MOD,
    CRIB_POSITIONS, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

CT97 = CT
CT_LEN = len(CT97)

# ── Keywords to test ───────────────────────────────────────────────────────

KEYWORDS_STR = [
    "ANTIPODES", "SHADOW", "LIGHT", "CANDLE", "SVET", "DECEIT",
    "COVERTBALANCE", "SEVEN", "PENETRATED", "KRYPTOS", "PALIMPSEST",
    "ABSCISSA", "BERLINCLOCK", "ARTICHOKE",  # Jefferson's agreed keyword
    "UNDERGROUND", "MEET", "LAYERTWO",
    # Combinations
    "KRYPTOSSHADOW", "KRYPTOSLIGHT", "KRYPTOSCANDLE",
    "KRYPTOSANTIPODES", "KRYPTOSDECEIT", "KRYPTOSSVET",
    "SHADOWLIGHT", "CANDLELIGHT", "ANTIPODESLIGHT",
    # Reversed
    "SEDOPITNA", "WODAHS", "THGIL",
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


def str_to_key(s):
    """Convert string keyword to numeric key list."""
    return [ALPH_IDX[c] for c in s.upper()]


def score_both(text, desc):
    """Score with both anchored and free cribs, return best."""
    sa = score_candidate(text)
    sf = score_candidate_free(text)
    best = max(sa.crib_score, sf.crib_score)
    mode = "anch" if sa.crib_score >= sf.crib_score else "free"
    return (best, text, f"{desc} [{mode}]", sa.bean_passed if sa.crib_score >= sf.crib_score else False)


# ── LEAD 1 & 2: Keyword tests ─────────────────────────────────────────────

def test_keyword(args):
    """Test a single keyword + variant + optional L-offset."""
    kw_str, variant, l_offset = args
    results = []
    key = str_to_key(kw_str)

    if l_offset != 0:
        key = [(k + l_offset) % MOD for k in key]

    pt = decrypt_text(CT97, key, variant)
    offset_label = f"+L{l_offset}" if l_offset else ""
    desc = f"KW={kw_str}{offset_label} {variant.value}"
    score, text, full_desc, bean = score_both(pt, desc)
    if score >= 4:  # Lower threshold to capture near-misses
        results.append((score, text, full_desc, bean))

    return results


# ── LEAD 3: Insertion/removal tests ───────────────────────────────────────

def test_removal(args):
    """Remove 1 char at position pos, then decrypt with keyword."""
    pos, kw_str, variant = args
    results = []

    # Remove char at pos
    modified_ct = CT97[:pos] + CT97[pos+1:]
    assert len(modified_ct) == 96

    key = str_to_key(kw_str)
    pt = decrypt_text(modified_ct, key, variant)
    desc = f"REMOVE@{pos} KW={kw_str} {variant.value}"
    score, text, full_desc, bean = score_both(pt, desc)
    if score >= 5:
        results.append((score, text, full_desc, bean))

    return results


def test_removal_2(args):
    """Remove 2 chars at positions p1,p2, then decrypt."""
    p1, p2, kw_str, variant = args
    results = []

    modified_ct = "".join(c for i, c in enumerate(CT97) if i not in (p1, p2))
    assert len(modified_ct) == 95

    key = str_to_key(kw_str)
    pt = decrypt_text(modified_ct, key, variant)
    desc = f"REMOVE@{p1},{p2} KW={kw_str} {variant.value}"
    score, text, full_desc, bean = score_both(pt, desc)
    if score >= 5:
        results.append((score, text, full_desc, bean))

    return results


def test_insertion(args):
    """Insert 1 char at position pos, then decrypt."""
    pos, insert_char, kw_str, variant = args
    results = []

    modified_ct = CT97[:pos] + insert_char + CT97[pos:]
    assert len(modified_ct) == 98

    key = str_to_key(kw_str)
    pt = decrypt_text(modified_ct, key, variant)
    desc = f"INSERT={insert_char}@{pos} KW={kw_str} {variant.value}"
    score, text, full_desc, bean = score_both(pt, desc)
    if score >= 5:
        results.append((score, text, full_desc, bean))

    return results


def test_layertwo_insertion(args):
    """Insert LAYERTWO (8 chars) at a position, then decrypt."""
    pos, kw_str, variant = args
    results = []
    insert_text = "LAYERTWO"

    modified_ct = CT97[:pos] + insert_text + CT97[pos:]
    assert len(modified_ct) == 105

    key = str_to_key(kw_str)
    pt = decrypt_text(modified_ct, key, variant)
    desc = f"INSERT=LAYERTWO@{pos} KW={kw_str} {variant.value}"
    score, text, full_desc, bean = score_both(pt, desc)
    if score >= 5:
        results.append((score, text, full_desc, bean))

    return results


# ── Main ───────────────────────────────────────────────────────────────────

def attack(ciphertext=CT97, **params):
    t0 = time.time()
    all_results = []
    n_workers = max(1, cpu_count() - 2)

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: Pure keyword tests (including L-offset)
    # ═══════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PHASE 1: Keyword tests")
    configs = []
    for kw in KEYWORDS_STR:
        for variant in VARIANTS:
            for l_offset in [0, 11, 12, 15]:  # 0=none, 11=L(AZ), 12=L(KA), 15=?
                configs.append((kw, variant, l_offset))

    print(f"  {len(configs)} configs ({len(KEYWORDS_STR)} keywords × "
          f"{len(VARIANTS)} variants × 4 offsets)")

    with Pool(n_workers) as pool:
        batch_results = pool.map(test_keyword, configs)
    for rlist in batch_results:
        all_results.extend(rlist)

    phase1_best = max((r[0] for r in all_results), default=0)
    print(f"  Phase 1 best: {phase1_best}/24 ({len(all_results)} results ≥4)")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: Single-char removal + keyword
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 2: Single-character removal + keyword")

    # Use top keywords only for removal (otherwise too many configs)
    TOP_KW = ["ANTIPODES", "SHADOW", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
              "LIGHT", "CANDLE", "DECEIT", "SEVEN", "ARTICHOKE", "LAYERTWO",
              "KRYPTOSSHADOW", "KRYPTOSLIGHT", "KRYPTOSANTIPODES"]
    configs = []
    for pos in range(CT_LEN):
        for kw in TOP_KW:
            for variant in VARIANTS:
                configs.append((pos, kw, variant))

    print(f"  {len(configs)} configs ({CT_LEN} positions × "
          f"{len(TOP_KW)} keywords × {len(VARIANTS)} variants)")

    with Pool(n_workers) as pool:
        batch_results = pool.map(test_removal, configs)
    for rlist in batch_results:
        all_results.extend(rlist)

    phase2_best = max((r[0] for r in all_results if "REMOVE" in r[2]), default=0)
    print(f"  Phase 2 best: {phase2_best}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3: Single-char insertion + keyword
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 3: Single-character insertion + keyword")

    # Test inserting each of 26 letters at each of 98 positions
    configs = []
    INSERT_KW = ["ANTIPODES", "SHADOW", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
                 "LIGHT", "CANDLE", "DECEIT", "ARTICHOKE", "KRYPTOSSHADOW",
                 "KRYPTOSANTIPODES"]
    for pos in range(CT_LEN + 1):
        for ch in ALPH:
            for kw in INSERT_KW:
                for variant in VARIANTS:
                    configs.append((pos, ch, kw, variant))

    print(f"  {len(configs)} configs ({CT_LEN+1} positions × 26 chars × "
          f"{len(INSERT_KW)} keywords × {len(VARIANTS)} variants)")

    # Process in batches for memory
    batch_size = 5000
    phase3_best = 0
    for i in range(0, len(configs), batch_size):
        batch = configs[i:i + batch_size]
        with Pool(n_workers) as pool:
            batch_results = pool.map(test_insertion, batch)
        for rlist in batch_results:
            for r in rlist:
                all_results.append(r)
                if r[0] > phase3_best:
                    phase3_best = r[0]
                    print(f"  NEW BEST INSERT: {r[0]}/24 — {r[2]}")
                    if r[0] >= 8:
                        print(f"    TEXT: {r[1][:60]}...")

        done = min(i + batch_size, len(configs))
        if done % 50000 < batch_size:
            elapsed = time.time() - t0
            print(f"  [{done}/{len(configs)}] ({elapsed:.0f}s) best_insert={phase3_best}/24")

    print(f"  Phase 3 best: {phase3_best}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4: LAYERTWO (8-char) insertion
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 4: LAYERTWO insertion")

    configs = []
    for pos in range(CT_LEN + 1):
        for kw in TOP_KW:
            for variant in VARIANTS:
                configs.append((pos, kw, variant))

    print(f"  {len(configs)} configs ({CT_LEN+1} positions × "
          f"{len(TOP_KW)} keywords × {len(VARIANTS)} variants)")

    with Pool(n_workers) as pool:
        batch_results = pool.map(test_layertwo_insertion, configs)
    for rlist in batch_results:
        all_results.extend(rlist)

    phase4_best = max((r[0] for r in all_results if "LAYERTWO@" in r[2]), default=0)
    print(f"  Phase 4 best: {phase4_best}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 5: Double removal (pairs of positions)
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 5: Double-character removal + keyword")

    SLIM_KW = ["ANTIPODES", "SHADOW", "KRYPTOS", "PALIMPSEST", "LIGHT",
               "CANDLE", "ARTICHOKE"]
    configs = []
    # Sample pairs: focus on positions near known features
    # X positions: 6, 79. Y position: 64. ? boundary positions.
    FOCUS_POS = list(range(CT_LEN))
    for p1, p2 in itertools.combinations(FOCUS_POS, 2):
        if abs(p1 - p2) > 30:
            continue  # Skip widely separated pairs to keep manageable
        for kw in SLIM_KW:
            for variant in [CipherVariant.BEAUFORT]:  # Most likely variant
                configs.append((p1, p2, kw, variant))

    print(f"  {len(configs)} configs (nearby pairs × "
          f"{len(SLIM_KW)} keywords × Beaufort)")

    with Pool(n_workers) as pool:
        batch_results = pool.map(test_removal_2, configs)
    for rlist in batch_results:
        all_results.extend(rlist)

    phase5_best = max((r[0] for r in all_results if "REMOVE@" in r[2] and "," in r[2]), default=0)
    print(f"  Phase 5 best: {phase5_best}/24")

    # ═══════════════════════════════════════════════════════════════════
    # Final report
    # ═══════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0
    all_results.sort(key=lambda x: -x[0])

    print(f"\n{'=' * 70}")
    print(f"COMBINED ANTIPODES LEADS — FINAL REPORT")
    print(f"  Total time: {elapsed:.1f}s")
    print(f"  Total results ≥ threshold: {len(all_results)}")
    overall_best = all_results[0][0] if all_results else 0
    print(f"  Overall best: {overall_best}/24")

    if all_results:
        print(f"\nTop 30 results:")
        for score, text, desc, bean in all_results[:30]:
            bean_str = "BEAN✓" if bean else ""
            print(f"  {score:2d}/24 {bean_str:6s} {desc}")
            if score >= 8:
                print(f"         {text[:70]}")

    # Phase breakdown
    print(f"\nPhase breakdown:")
    print(f"  Phase 1 (keywords):      best={phase1_best}/24")
    print(f"  Phase 2 (removal):       best={phase2_best}/24")
    print(f"  Phase 3 (insertion):     best={phase3_best}/24")
    print(f"  Phase 4 (LAYERTWO ins):  best={phase4_best}/24")
    print(f"  Phase 5 (double remove): best={phase5_best}/24")

    return [(s, t, d) for s, t, d, b in all_results[:50]]


if __name__ == "__main__":
    results = attack()
