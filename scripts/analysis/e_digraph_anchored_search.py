#!/usr/bin/env python3
"""Digraph-anchored cipher search: find cipher configs where CIA digraphs
appear immediately before EASTNORTHEAST and/or BERLINCLOCK cribs in PT73.

Cipher:  Periodic Beaufort/Vigenere (all keywords x periods 1-26) + optional col6/col7
Family:  analysis
Status:  active
Keyspace: ~40M+ (keywords * periods * variants * masks * transpositions)
Last run: never
Best score: n/a

MODEL: CT97 -> remove 24 nulls -> CT73 -> (optional col6/col7 inverse) -> periodic decrypt -> PT73

For each null mask, the crib start positions in PT73 shift:
  ENE_start_73 = 21 - (nulls before 21)
  BCL_start_73 = 63 - (nulls before 63)

The positions IMMEDIATELY before ENE (pt73[ENE-2:ENE]) and before BCL (pt73[BCL-2:BCL])
should contain CIA cryptonym digraphs if K4 is a CIA cable.

Valid Berlin/Cold War CIA digraphs:
  AE (Soviet), DT (East Germany), CA (West Germany), BG (Bulgaria), GT (Guatemala),
  CK (CIA internal), KU (Ukraine), HT (Cuba), OD (Near East), ZR (counterintelligence),
  LC (Latin America), QR (unidentified), PB (Latin America), MK (mind control), AM (Cuba)

PHASES:
  1. Consensus null mask (17 fixed + 7 varying from 18 palette-real positions): C(18,7)=31,824
     For each mask: compute crib positions in PT73, check digraphs, check full cribs.
  2. For top masks with digraphs: try ALL keywords x periods x variants x col6/col7.
  3. Extended: check positions 9-12 (4 chars before ENE) and 49-50 (before BCL).
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, json, time, math
from itertools import combinations
from multiprocessing import Pool, cpu_count
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CRIB_POSITIONS

# ── Constants ──────────────────────────────────────────────────────────────

CT97 = CT
CT97_NUM = tuple(ord(c) - 65 for c in CT97)
N = 97
N_NULLS = 24
N_PT = 73

ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_NUMS = tuple(ord(c) - 65 for c in ENE_WORD)
BCL_NUMS = tuple(ord(c) - 65 for c in BCL_WORD)
ENE_START_97 = 21
BCL_START_97 = 63

# CIA cryptonym digraphs (Berlin/Cold War relevant)
CIA_DIGRAPHS = frozenset([
    "AE", "DT", "CA", "BG", "GT", "CK", "KU", "HT", "OD", "ZR",
    "LC", "QR", "PB", "MK", "AM"
])
CIA_DIGRAPH_NUMS = frozenset(
    (ord(d[0]) - 65, ord(d[1]) - 65) for d in CIA_DIGRAPHS
)

# Consensus null positions (17 fixed)
CONSENSUS_17 = frozenset({0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85})

# Palette-but-real positions (18 positions that are palette letters but NOT consensus nulls)
PALETTE_REAL = sorted({7, 16, 18, 19, 30, 31, 34, 45, 46, 47, 48, 56, 62, 70, 73, 77, 86, 93})

# All non-crib, non-consensus positions that could be the 7 varying nulls
# Actually the user says: 17 consensus + 7 from the 18 palette-real positions
# But palette-constrained mask was DISPROVED. Let me use the proper varying pool.
# The varying pool = all 97 positions minus 17 consensus minus 24 crib positions = 56 positions
# But C(56,7) = 231.9M -- too many. User specified C(18,7) from palette-real.
# HOWEVER, palette-constrained was DISPROVED (varying nulls contain non-palette letters).
# The user explicitly requests C(18,7) = 31,824 as a tractable subset.

VARYING_POOL = PALETTE_REAL  # 18 palette-real positions
assert len(VARYING_POOL) == 18

# ── Transposition helpers ──────────────────────────────────────────────────

def columnar_perm(n, width):
    """Build columnar transposition permutation (gather convention)."""
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def inverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

# Pre-compute transposition permutations
PERM_COL7 = inverse_perm(columnar_perm(N_PT, 7))
PERM_COL6 = inverse_perm(columnar_perm(N_PT, 6))

# ── Keywords ───────────────────────────────────────────────────────────────

HARDCODED_KEYWORDS = [
    "DEFECTOR", "KRYPTOS", "ABSCISSA", "KOMPASS", "PALIMPSEST",
    "BERLINCLOCK", "GOLD", "ABEL", "FISHER", "MARK", "POWERS",
    "BRIDGE", "TUNNEL", "VECTOR", "SHADOW", "TOWER", "CHART",
    "LAYER", "SEVEN", "NORTH", "COLOPHON", "PARALLAX", "MEDUSA",
    "SANBORN", "SCHEIDT", "LANGLEY", "ANTIPODES", "ENIGMA",
    "WELLZEITUHR", "WELTZEITUHR", "CIPHER", "CRYPTANALYSIS",
    "ESPIONAGE", "STEGANOGRAPHY", "BERLIN", "CHECKPOINT", "COLDWAR",
    "STASI", "ALEXANDERPLATZ", "EAST", "WEST", "PASSAGE", "CHAMBER",
    "INVISIBLE", "ILLUSION", "NUANCE", "OCCLUSION", "ABSENCE",
    "SUBTLE", "CLANDESTINE", "COVERT", "DISPATCH", "COURIER",
    "AZIMUTH", "MERIDIAN", "POLARIS", "SEXTANT", "LODESTONE",
    "PETRIFIED", "PROJECTION", "SERPENTINE", "WONDERFULTHINGS",
]

def load_thematic_keywords():
    """Load keywords from thematic_keywords.txt, filter to 7-8 letter words."""
    kw_path = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords.txt')
    extra = []
    if os.path.exists(kw_path):
        with open(kw_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                w = line.upper()
                if w.isalpha() and 7 <= len(w) <= 8:
                    extra.append(w)
    # Also add all hardcoded keywords regardless of length
    all_kw = list(set(HARDCODED_KEYWORDS + extra))
    all_kw.sort()
    return all_kw

ALL_KEYWORDS = load_thematic_keywords()

# ── Cipher functions ───────────────────────────────────────────────────────

def periodic_decrypt_beau(ct_nums, key_nums, period):
    """Beaufort: PT[i] = (KEY[i%period] - CT[i]) mod 26"""
    return tuple((key_nums[i % period] - ct_nums[i]) % 26 for i in range(len(ct_nums)))

def periodic_decrypt_vig(ct_nums, key_nums, period):
    """Vigenere: PT[i] = (CT[i] - KEY[i%period]) mod 26"""
    return tuple((ct_nums[i] - key_nums[i % period]) % 26 for i in range(len(ct_nums)))

# ── Mask evaluation ────────────────────────────────────────────────────────

def null_mask_to_ct73(null_set):
    """Extract 73-char CT from 97-char CT by removing null positions."""
    return tuple(CT97_NUM[i] for i in range(N) if i not in null_set)

def compute_crib_positions(null_set):
    """Compute where ENE and BCL start in the 73-char PT."""
    n_before_ene = sum(1 for p in null_set if p < ENE_START_97)
    n_before_bcl = sum(1 for p in null_set if p < BCL_START_97)
    ene_start = ENE_START_97 - n_before_ene
    bcl_start = BCL_START_97 - n_before_bcl
    return ene_start, bcl_start

def count_crib_matches(pt_nums, ene_start, bcl_start):
    """Count how many crib positions match."""
    ene_hits = 0
    for j, c in enumerate(ENE_NUMS):
        pos = ene_start + j
        if 0 <= pos < len(pt_nums) and pt_nums[pos] == c:
            ene_hits += 1
    bcl_hits = 0
    for j, c in enumerate(BCL_NUMS):
        pos = bcl_start + j
        if 0 <= pos < len(pt_nums) and pt_nums[pos] == c:
            bcl_hits += 1
    return ene_hits + bcl_hits, ene_hits, bcl_hits

def check_digraph_at(pt_nums, pos):
    """Check if pt_nums[pos:pos+2] is a CIA digraph."""
    if pos < 0 or pos + 1 >= len(pt_nums):
        return None
    pair = (pt_nums[pos], pt_nums[pos + 1])
    if pair in CIA_DIGRAPH_NUMS:
        return chr(pair[0] + 65) + chr(pair[1] + 65)
    return None

# ── Phase 1: Null mask enumeration with direct crib check ─────────────────

def evaluate_mask_basic(varying_7):
    """For a given set of 7 varying null positions, check if any cipher config
    produces both crib matches AND digraphs at expected positions.

    Returns list of hits: (mask, ene_start, bcl_start, digraph_positions)
    """
    null_set = CONSENSUS_17 | frozenset(varying_7)
    assert len(null_set) == N_NULLS

    ct73 = null_mask_to_ct73(null_set)
    ene_start, bcl_start = compute_crib_positions(null_set)

    # Check positions for digraphs (in raw CT73 -- before any cipher)
    # After cipher, the plaintext at these positions depends on the key.
    # So we need to check what KEY VALUES would be required at these positions
    # for the plaintext to contain a digraph.

    # Digraph check positions (in PT73 space):
    # Before ENE: positions ene_start-2, ene_start-1
    # Before BCL: positions bcl_start-2, bcl_start-1
    # Extended: ene_start-4 to ene_start-1, bcl_start-4 to bcl_start-1

    digraph_before_ene = ene_start - 2  # 2 chars = last 2 of preceding word
    digraph_before_bcl = bcl_start - 2

    return (tuple(sorted(null_set)), ene_start, bcl_start, digraph_before_ene, digraph_before_bcl, tuple(ct73))

def phase1_enumerate_masks():
    """Enumerate C(18,7)=31,824 masks and compute crib positions + CT73 for each."""
    print("=" * 70)
    print("PHASE 1: Enumerate C(18,7) = 31,824 null masks")
    print("  Consensus 17:", sorted(CONSENSUS_17))
    print("  Varying pool (18 palette-real):", VARYING_POOL)
    print("=" * 70)

    t0 = time.time()
    masks_data = []
    for varying in combinations(VARYING_POOL, 7):
        result = evaluate_mask_basic(varying)
        masks_data.append(result)

    elapsed = time.time() - t0
    print(f"  Enumerated {len(masks_data)} masks in {elapsed:.1f}s")

    # Statistics on crib start positions
    ene_positions = defaultdict(int)
    bcl_positions = defaultdict(int)
    for _, ene_s, bcl_s, _, _, _ in masks_data:
        ene_positions[ene_s] += 1
        bcl_positions[bcl_s] += 1

    print(f"\n  ENE start position distribution in PT73:")
    for pos in sorted(ene_positions.keys()):
        print(f"    pos={pos}: {ene_positions[pos]} masks")
    print(f"\n  BCL start position distribution in PT73:")
    for pos in sorted(bcl_positions.keys()):
        print(f"    pos={pos}: {bcl_positions[pos]} masks")

    return masks_data

# ── Phase 2: For each mask, try all keywords x periods x variants ──────────

def evaluate_mask_cipher(args):
    """Worker function for multiprocessing.
    For a single mask, try all keywords x periods x variants x transpositions.
    Return any hits where crib >= 12 AND digraph found before ENE or BCL.
    """
    mask_tuple, ene_start, bcl_start, dg_before_ene, dg_before_bcl, ct73_tuple = args

    ct73 = list(ct73_tuple)
    hits = []

    # Transposition options: none, col7, col6
    trans_options = [
        ("none", list(range(N_PT))),
        ("col7", PERM_COL7),
        ("col6", PERM_COL6),
    ]

    for trans_name, perm in trans_options:
        # Apply transposition
        ct73_t = [ct73[perm[i]] for i in range(N_PT)]
        ct73_t_nums = tuple(ct73_t)

        for kw_str in ALL_KEYWORDS:
            kw_nums = tuple(ord(c) - 65 for c in kw_str)
            kw_len = len(kw_nums)

            # Test periods 1 through min(26, kw_len)
            # For periodic cipher, the key repeats every `period` chars
            # Period = keyword length for simple Vigenere/Beaufort
            for period in range(1, min(27, kw_len + 1)):
                key_nums = kw_nums[:period]

                for variant_name, decrypt_fn in [("beau", periodic_decrypt_beau), ("vig", periodic_decrypt_vig)]:
                    pt_nums = decrypt_fn(ct73_t_nums, key_nums, period)

                    # Count crib matches
                    total, ene_hits, bcl_hits = count_crib_matches(pt_nums, ene_start, bcl_start)

                    # Check digraphs at positions before ENE and BCL
                    dg_ene = None
                    dg_bcl = None
                    dg_ene_ext = []
                    dg_bcl_ext = []

                    # Immediate 2-char before ENE
                    if dg_before_ene >= 0:
                        dg_ene = check_digraph_at(pt_nums, dg_before_ene)

                    # Immediate 2-char before BCL
                    if dg_before_bcl >= 0:
                        dg_bcl = check_digraph_at(pt_nums, dg_before_bcl)

                    # Extended: check positions 4 chars before ENE (pairs at -4,-3 and -3,-2)
                    for offset in range(-4, 0):
                        check_pos = ene_start + offset
                        d = check_digraph_at(pt_nums, check_pos)
                        if d:
                            dg_ene_ext.append((d, check_pos))

                    for offset in range(-4, 0):
                        check_pos = bcl_start + offset
                        d = check_digraph_at(pt_nums, check_pos)
                        if d:
                            dg_bcl_ext.append((d, check_pos))

                    has_digraph = dg_ene is not None or dg_bcl is not None or len(dg_ene_ext) > 0 or len(dg_bcl_ext) > 0

                    # Report hits at various thresholds
                    # Tier A: crib >= 15 (regardless of digraph)
                    # Tier B: crib >= 12 AND digraph immediately before ENE or BCL
                    # Tier C: crib >= 10 AND digraph at extended positions
                    # Tier D: crib >= 8 AND digraph immediately before both ENE and BCL

                    report = False
                    tier = None

                    if total >= 15:
                        report = True
                        tier = "A"
                    elif total >= 12 and (dg_ene is not None or dg_bcl is not None):
                        report = True
                        tier = "B"
                    elif total >= 10 and has_digraph:
                        report = True
                        tier = "C"
                    elif total >= 8 and dg_ene is not None and dg_bcl is not None:
                        report = True
                        tier = "D"

                    if report:
                        pt_str = ''.join(chr(c + 65) for c in pt_nums)
                        hits.append({
                            "tier": tier,
                            "mask": list(mask_tuple),
                            "keyword": kw_str,
                            "period": period,
                            "variant": variant_name,
                            "trans": trans_name,
                            "crib_total": total,
                            "ene_hits": ene_hits,
                            "bcl_hits": bcl_hits,
                            "ene_start": ene_start,
                            "bcl_start": bcl_start,
                            "dg_before_ene": dg_ene,
                            "dg_before_bcl": dg_bcl,
                            "dg_ene_extended": [(d, p) for d, p in dg_ene_ext],
                            "dg_bcl_extended": [(d, p) for d, p in dg_bcl_ext],
                            "plaintext": pt_str,
                        })

    return hits

# ── Phase 3: Full search with all possible null masks ──────────────────────
# Instead of C(18,7) only from palette-real, also try the full varying pool.
# But C(56,7) = 231.9M is too large. We'll focus on masks where:
# - ENE and BCL cribs are at positions allowing digraphs
# - Use the consensus-17 base

def phase2_cipher_search(masks_data, n_workers=24):
    """For each mask, try all keywords x periods x variants x transpositions."""
    print("\n" + "=" * 70)
    n_kw = len(ALL_KEYWORDS)
    n_masks = len(masks_data)
    # Estimate: per mask, ~n_kw keywords * ~avg 8 periods * 2 variants * 3 trans
    est_per_mask = n_kw * 8 * 2 * 3  # rough estimate
    est_total = n_masks * est_per_mask
    print(f"PHASE 2: Cipher search across {n_masks} masks x {n_kw} keywords x periods x variants x trans")
    print(f"  Estimated configs: ~{est_total:,.0f}")
    print(f"  Workers: {n_workers}")
    print("=" * 70)

    t0 = time.time()
    all_hits = []

    with Pool(n_workers) as pool:
        batch_size = 500
        n_batches = (n_masks + batch_size - 1) // batch_size
        processed = 0

        for batch_idx in range(n_batches):
            start = batch_idx * batch_size
            end = min(start + batch_size, n_masks)
            batch = masks_data[start:end]

            results = pool.map(evaluate_mask_cipher, batch)

            for hit_list in results:
                all_hits.extend(hit_list)

            processed += len(batch)
            elapsed = time.time() - t0
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (n_masks - processed) / rate if rate > 0 else 0

            n_tierA = sum(1 for h in all_hits if h['tier'] == 'A')
            n_tierB = sum(1 for h in all_hits if h['tier'] == 'B')
            n_tierC = sum(1 for h in all_hits if h['tier'] == 'C')
            n_tierD = sum(1 for h in all_hits if h['tier'] == 'D')

            print(f"  [{processed}/{n_masks}] {elapsed:.0f}s, {rate:.1f} masks/s, "
                  f"ETA {eta:.0f}s | Hits: A={n_tierA} B={n_tierB} C={n_tierC} D={n_tierD}")

    total_time = time.time() - t0
    print(f"\n  Phase 2 complete: {total_time:.1f}s, {len(all_hits)} total hits")
    return all_hits

# ── Phase 3: Extended search with broader mask pool ────────────────────────

def phase3_broad_mask_search(n_random=5000, n_workers=24):
    """Sample random masks from the full C(56,7) space and test them.
    This covers masks where the varying nulls are NOT from the palette-real set.
    """
    print("\n" + "=" * 70)
    print(f"PHASE 3: Random mask sampling ({n_random} masks from C(56,7) space)")
    print("=" * 70)

    # Full varying pool: all non-crib non-consensus positions
    all_positions = set(range(N))
    crib_set = set(CRIB_POSITIONS)
    full_varying_pool = sorted(all_positions - CONSENSUS_17 - crib_set)

    import random as rng
    rng.seed(42)

    masks_data = []
    seen = set()
    attempts = 0
    while len(masks_data) < n_random and attempts < n_random * 10:
        attempts += 1
        varying = tuple(sorted(rng.sample(full_varying_pool, 7)))
        if varying in seen:
            continue
        seen.add(varying)
        result = evaluate_mask_basic(varying)
        masks_data.append(result)

    print(f"  Generated {len(masks_data)} unique random masks")

    t0 = time.time()
    all_hits = []

    with Pool(n_workers) as pool:
        batch_size = 500
        n_batches = (len(masks_data) + batch_size - 1) // batch_size
        processed = 0

        for batch_idx in range(n_batches):
            start = batch_idx * batch_size
            end = min(start + batch_size, len(masks_data))
            batch = masks_data[start:end]

            results = pool.map(evaluate_mask_cipher, batch)
            for hit_list in results:
                all_hits.extend(hit_list)

            processed += len(batch)
            elapsed = time.time() - t0
            rate = processed / elapsed if elapsed > 0 else 0

            n_tierA = sum(1 for h in all_hits if h['tier'] == 'A')
            n_tierB = sum(1 for h in all_hits if h['tier'] == 'B')

            print(f"  [{processed}/{len(masks_data)}] {elapsed:.0f}s | "
                  f"Hits: A={n_tierA} B={n_tierB}")

    total_time = time.time() - t0
    print(f"  Phase 3 complete: {total_time:.1f}s, {len(all_hits)} total hits")
    return all_hits

# ── Analysis and output ────────────────────────────────────────────────────

def analyze_hits(all_hits, phase_name):
    """Analyze and summarize hits from a phase."""
    print(f"\n{'=' * 70}")
    print(f"ANALYSIS: {phase_name}")
    print(f"{'=' * 70}")

    if not all_hits:
        print("  NO HITS FOUND")
        return {}

    # Sort by tier then crib score
    tier_order = {"A": 0, "B": 1, "C": 2, "D": 3}
    all_hits.sort(key=lambda h: (tier_order.get(h['tier'], 99), -h['crib_total']))

    # Count by tier
    tier_counts = defaultdict(int)
    for h in all_hits:
        tier_counts[h['tier']] += 1

    print(f"  Total hits: {len(all_hits)}")
    for tier in ["A", "B", "C", "D"]:
        print(f"    Tier {tier}: {tier_counts[tier]}")

    # Keyword frequency in hits
    kw_freq = defaultdict(int)
    for h in all_hits:
        kw_freq[h['keyword']] += 1

    print(f"\n  Top keywords in hits:")
    for kw, cnt in sorted(kw_freq.items(), key=lambda x: -x[1])[:20]:
        print(f"    {kw}: {cnt}")

    # Digraph frequency
    dg_freq = defaultdict(int)
    for h in all_hits:
        if h['dg_before_ene']:
            dg_freq[h['dg_before_ene']] += 1
        if h['dg_before_bcl']:
            dg_freq[h['dg_before_bcl']] += 1
        for d, p in h.get('dg_ene_extended', []):
            dg_freq[d] += 1
        for d, p in h.get('dg_bcl_extended', []):
            dg_freq[d] += 1

    print(f"\n  Digraph frequency in hits:")
    for dg, cnt in sorted(dg_freq.items(), key=lambda x: -x[1]):
        print(f"    {dg}: {cnt}")

    # Show top 20 hits
    print(f"\n  TOP 20 HITS:")
    for i, h in enumerate(all_hits[:20]):
        dg_str_parts = []
        if h['dg_before_ene']:
            dg_str_parts.append(f"ENE-2={h['dg_before_ene']}")
        if h['dg_before_bcl']:
            dg_str_parts.append(f"BCL-2={h['dg_before_bcl']}")
        for d, p in h.get('dg_ene_extended', []):
            dg_str_parts.append(f"ENE@{p}={d}")
        for d, p in h.get('dg_bcl_extended', []):
            dg_str_parts.append(f"BCL@{p}={d}")
        dg_str = ", ".join(dg_str_parts) if dg_str_parts else "none"

        pt_preview = h['plaintext'][:30] + "..." if len(h['plaintext']) > 30 else h['plaintext']
        print(f"    [{h['tier']}] crib={h['crib_total']}/24 (e={h['ene_hits']}/13 b={h['bcl_hits']}/11) "
              f"{h['keyword']}:{h['variant']}:p{h['period']}+{h['trans']} "
              f"dg=[{dg_str}]")
        print(f"         PT: ...{h['plaintext'][max(0,h['ene_start']-4):h['ene_start']+15]}... "
              f"...{h['plaintext'][max(0,h['bcl_start']-4):h['bcl_start']+13]}...")

    # Check for any hits with digraphs before BOTH ENE and BCL
    dual_dg = [h for h in all_hits if h['dg_before_ene'] and h['dg_before_bcl']]
    print(f"\n  Hits with digraphs before BOTH ENE and BCL: {len(dual_dg)}")
    for h in dual_dg[:10]:
        print(f"    crib={h['crib_total']}/24 {h['keyword']}:{h['variant']}:p{h['period']}+{h['trans']} "
              f"ENE-2={h['dg_before_ene']} BCL-2={h['dg_before_bcl']}")

    # Statistical significance check
    # Expected random rate for a digraph at position X:
    # P(specific pair is CIA digraph) = 15/676 = 0.0222 per pair
    # For 2 positions (before ENE and BCL): P(at least one) = 1-(1-0.0222)^2 = 0.0439
    # So ~4.4% of random configs should have a digraph
    n_with_any_dg = sum(1 for h in all_hits if h['dg_before_ene'] or h['dg_before_bcl'])
    print(f"\n  Hits with any immediate digraph (before ENE or BCL): {n_with_any_dg}/{len(all_hits)}")
    print(f"    Rate: {n_with_any_dg/len(all_hits)*100:.1f}% (random expected: ~4.4%)")

    summary = {
        "total_hits": len(all_hits),
        "tier_counts": dict(tier_counts),
        "top_keywords": dict(sorted(kw_freq.items(), key=lambda x: -x[1])[:20]),
        "digraph_freq": dict(dg_freq),
        "dual_digraph_count": len(dual_dg),
        "digraph_rate": n_with_any_dg / max(1, len(all_hits)),
    }
    return summary

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    print("DIGRAPH-ANCHORED CIPHER SEARCH FOR K4")
    print("=" * 70)
    print(f"CT97: {CT97}")
    print(f"Keywords: {len(ALL_KEYWORDS)}")
    print(f"CIA digraphs: {sorted(CIA_DIGRAPHS)}")
    print(f"Consensus nulls: {sorted(CONSENSUS_17)}")
    print(f"Palette-real varying pool: {VARYING_POOL}")
    print()

    # Phase 1: Enumerate masks
    masks_data = phase1_enumerate_masks()

    # Phase 2: Full cipher search on C(18,7) masks
    n_workers = min(24, cpu_count())
    hits_p2 = phase2_cipher_search(masks_data, n_workers=n_workers)
    summary_p2 = analyze_hits(hits_p2, "Phase 2: Palette-real masks")

    # Phase 3: Broader random masks
    hits_p3 = phase3_broad_mask_search(n_random=5000, n_workers=n_workers)
    summary_p3 = analyze_hits(hits_p3, "Phase 3: Random broad masks")

    # Combine all hits
    all_hits = hits_p2 + hits_p3
    summary_all = analyze_hits(all_hits, "COMBINED ALL PHASES")

    total_time = time.time() - t_start

    # Determine verdict
    tier_a_hits = [h for h in all_hits if h['tier'] == 'A']
    tier_b_hits = [h for h in all_hits if h['tier'] == 'B']
    dual_dg = [h for h in all_hits if h['dg_before_ene'] and h['dg_before_bcl']]

    max_crib = max((h['crib_total'] for h in all_hits), default=0) if all_hits else 0
    max_crib_with_dg = max(
        (h['crib_total'] for h in all_hits if h['dg_before_ene'] or h['dg_before_bcl']),
        default=0
    ) if all_hits else 0

    # Check if digraph rate is significantly above random
    n_with_dg = sum(1 for h in all_hits if h['dg_before_ene'] or h['dg_before_bcl'])
    dg_rate = n_with_dg / max(1, len(all_hits))
    is_enriched = dg_rate > 0.08  # 2x random rate of 4.4%

    if max_crib >= 18 and max_crib_with_dg >= 15:
        verdict = "SIGNAL"
    elif max_crib >= 15 and len(dual_dg) > 0 and dual_dg[0]['crib_total'] >= 12:
        verdict = "INTERESTING"
    elif max_crib_with_dg >= 12 and is_enriched:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\n{'=' * 70}")
    print(f"FINAL VERDICT: {verdict}")
    print(f"  Max crib score (any): {max_crib}/24")
    print(f"  Max crib score (with digraph): {max_crib_with_dg}/24")
    print(f"  Digraph rate: {dg_rate*100:.1f}% (random baseline: ~4.4%)")
    print(f"  Dual digraph hits: {len(dual_dg)}")
    print(f"  Total time: {total_time:.1f}s")
    print(f"{'=' * 70}")

    # Save results
    output = {
        "experiment": "digraph_anchored_search",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": "periodic Beau/Vig + optional col6/col7 + 24-null mask",
        "n_keywords": len(ALL_KEYWORDS),
        "keywords_list": ALL_KEYWORDS,
        "n_masks_palette": len(masks_data),
        "n_masks_random": 5000,
        "digraphs": sorted(CIA_DIGRAPHS),
        "total_configs_est": summary_all.get("total_hits", 0),
        "total_time_s": round(total_time, 1),
        "verdict": verdict,
        "max_crib_any": max_crib,
        "max_crib_with_digraph": max_crib_with_dg,
        "digraph_rate": round(dg_rate, 4),
        "dual_digraph_count": len(dual_dg),
        "phase2_summary": summary_p2,
        "phase3_summary": summary_p3,
        "combined_summary": summary_all,
        "top_20_hits": all_hits[:20] if all_hits else [],
        "tier_b_hits": [h for h in all_hits if h['tier'] == 'B'][:50],
        "dual_digraph_hits": dual_dg[:20],
    }

    results_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'digraph_anchored_search.json')
    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {results_path}")


if __name__ == "__main__":
    main()
