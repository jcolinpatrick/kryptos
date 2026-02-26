#!/usr/bin/env python3
"""E-BESPOKE-07: Systematic 1-indexed parameter variants for YAR, RQ, EQUAL, DYAR.

AUDIT GAP: All 60+ prior experiments used 0-indexed values for sculpture
annotations (Y=24, A=0, R=17). But Sanborn is an artist, not a programmer —
he would naturally use 1-indexed (A=1, B=2, ... Z=26 mod 26 = 0 → Y=25, A=1, R=18).

This experiment systematically tests ALL 1-indexed parameter variants across
7 phases, covering substitution keys, transposition parameters, combined
parameters, and a head-to-head comparison with 0-indexed equivalents.

Phases:
  1. YAR [25,1,18] as periodic/autokey material (Vig/Beau/VarBeau)
  2. YAR [25,1,18] as transposition parameters (columnar, rotation, decimation, grid)
  3. Combined 1-indexed parameters (YAR+T, YAR+RQ, EQUAL, misspelling combos)
  4. YAR as keyword for columnar transposition (width comparison)
  5. DYAR and DYARO 1-indexed as periodic keys
  6. Period-7 comprehensive (YAR+shifts, KRYPTOS combinations)
  7. Head-to-head: top 5 1-indexed vs 0-indexed equivalents
"""
from __future__ import annotations

import math
import sys
import time
from collections import defaultdict
from itertools import permutations, product
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    CT,
    CT_LEN,
    CRIB_DICT,
    CRIB_WORDS,
    MOD,
    N_CRIBS,
    NOISE_FLOOR,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.transforms.transposition import (
    apply_perm,
    invert_perm,
    columnar_perm,
)
from kryptos.kernel.constraints.bean import verify_bean


# ── Helpers ──────────────────────────────────────────────────────────────────

def c2n(c: str) -> int:
    return ord(c) - 65

def n2c(n: int) -> str:
    return chr((n % 26) + 65)

def decrypt_with_key(ct: str, key: List[int], variant: str) -> str:
    """Decrypt ct with numeric key (mod 26), returning plaintext string."""
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        cv = c2n(c)
        kv = key[i % klen] % MOD  # ensure mod 26
        if variant == "vig":
            pt = (cv - kv) % MOD
        elif variant == "beau":
            pt = (kv - cv) % MOD
        elif variant == "varbeau":
            pt = (cv + kv) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        result.append(n2c(pt))
    return "".join(result)

def decrypt_autokey_pt(ct: str, seed: List[int], variant: str) -> str:
    """Autokey decryption where key[i] = PT[i-len(seed)] for i >= len(seed)."""
    slen = len(seed)
    pt = []
    for i, c in enumerate(ct):
        cv = c2n(c)
        if i < slen:
            kv = seed[i] % MOD
        else:
            kv = c2n(pt[i - slen])
        if variant == "vig":
            pv = (cv - kv) % MOD
        elif variant == "beau":
            pv = (kv - cv) % MOD
        elif variant == "varbeau":
            pv = (cv + kv) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        pt.append(n2c(pv))
    return "".join(pt)

def decrypt_autokey_ct(ct: str, seed: List[int], variant: str) -> str:
    """Autokey decryption where key[i] = CT[i-len(seed)] for i >= len(seed)."""
    slen = len(seed)
    pt = []
    for i, c in enumerate(ct):
        cv = c2n(c)
        if i < slen:
            kv = seed[i] % MOD
        else:
            kv = c2n(ct[i - slen])
        if variant == "vig":
            pv = (cv - kv) % MOD
        elif variant == "beau":
            pv = (kv - cv) % MOD
        elif variant == "varbeau":
            pv = (cv + kv) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        pt.append(n2c(pv))
    return "".join(pt)

def keyword_to_numeric(kw: str) -> List[int]:
    """Convert keyword string to numeric key values (A=0, B=1, ..., Z=25)."""
    return [ALPH_IDX[c] for c in kw.upper()]


VARIANT_NAMES = {"vig": "Vigenere", "beau": "Beaufort", "varbeau": "VarBeau"}
VARIANTS = ["vig", "beau", "varbeau"]


# ── Global best tracker ──────────────────────────────────────────────────────

class BestTracker:
    """Track top N results across all phases."""
    def __init__(self, max_entries: int = 50):
        self.results: List[Tuple[int, str, str, str]] = []  # (score, label, phase, pt_snippet)
        self.max_entries = max_entries
        self.total_configs = 0

    def record(self, score: int, label: str, phase: str, pt: str):
        self.total_configs += 1
        if score > NOISE_FLOOR or len(self.results) < self.max_entries:
            self.results.append((score, label, phase, pt[:60]))
            self.results.sort(key=lambda x: -x[0])
            if len(self.results) > self.max_entries:
                self.results = self.results[:self.max_entries]

    @property
    def best_score(self) -> int:
        return self.results[0][0] if self.results else 0

    def top_n(self, n: int = 5) -> List[Tuple[int, str, str, str]]:
        return self.results[:n]

    def print_top(self, n: int = 10):
        print(f"\n  TOP {n} RESULTS (out of {self.total_configs} configs tested):")
        for i, (sc, label, phase, pt_snip) in enumerate(self.results[:n]):
            print(f"  {i+1:3d}. {sc:2d}/24  [{phase}]  {label}")
            print(f"       PT: {pt_snip}")


tracker = BestTracker(max_entries=50)


# ── Key definitions ─────────────────────────────────────────────────────────

# 1-indexed: A=1, B=2, ..., Z=26 (mod 26 → Z=0)
YAR_1 = [25, 1, 18]       # Y=25, A=1, R=18
YAR_0 = [24, 0, 17]       # Y=24, A=0, R=17

YART_1 = [25, 1, 18, 20]  # YART 1-indexed (T=20)
YARL_1 = [25, 1, 18, 12]  # YARL 1-indexed (L=12)
TRAY_1 = [20, 18, 1, 25]  # TRAY 1-indexed
RAY_1 = [18, 1, 25]       # RAY 1-indexed

YART_0 = [24, 0, 17, 19]  # YART 0-indexed
YARL_0 = [24, 0, 17, 11]  # YARL 0-indexed
TRAY_0 = [19, 17, 0, 24]  # TRAY 0-indexed
RAY_0 = [17, 0, 24]       # RAY 0-indexed

RQ_1 = [18, 17]           # R=18, Q=17 (1-indexed)
RQ_0 = [17, 16]           # R=17, Q=16 (0-indexed)

# EQUAL letters: E, R, V, B, M (self-encrypting positions in one analysis)
EQUAL_1 = [5, 18, 22, 2, 13]  # 1-indexed
EQUAL_0 = [4, 17, 21, 1, 12]  # 0-indexed

# Misspelling shifts: DIGETAL→DIGITAL(4), IQLUSION→ILLUSION(5), DESPARATLY→DESPERATELY(4), PALIMPCEST→PALIMPSEST(16)
MISSP_SHIFTS = [4, 5, 4, 16]

# KRYPTOS keyword
KRYPTOS_KEY = keyword_to_numeric("KRYPTOS")  # [10, 17, 24, 15, 19, 14, 18]
KRYPTOS_1 = [11, 18, 25, 16, 20, 15, 19]    # 1-indexed

# DYAR and DYARO
DYAR_1 = [4, 25, 1, 18]        # 1-indexed (D=4)
DYAR_0 = [3, 24, 0, 17]        # 0-indexed (D=3)
DYARO_1 = [4, 25, 1, 18, 15]   # 1-indexed (O=15)
DYARO_0 = [3, 24, 0, 17, 14]   # 0-indexed (O=14)


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: YAR [25, 1, 18] as key material
# ══════════════════════════════════════════════════════════════════════════════

def phase1_yar_key_material():
    """Test YAR 1-indexed as periodic and autokey material."""
    print("\n" + "=" * 78)
    print("  PHASE 1: YAR [25, 1, 18] AS KEY MATERIAL")
    print("=" * 78)

    configs = 0

    # ── Phase 1a: YAR period 3, all 6 permutations, 3 variants ──
    print(f"\n  --- Phase 1a: YAR permutations (6 perms x 3 variants = 18 configs) ---")
    seen_perms = set()
    for perm in permutations(YAR_1):
        key = list(perm)
        key_t = tuple(key)
        if key_t in seen_perms:
            continue
        seen_perms.add(key_t)
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"YAR1_perm{list(key)}_{variant}"
            tracker.record(sc, label, "P1a", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    print(f"  Phase 1a: {configs} configs, best so far: {tracker.best_score}/24")

    # ── Phase 1b: Extended keywords — YART, YARL, TRAY, RAY (all perms) ──
    print(f"\n  --- Phase 1b: Extended YAR keywords (YART/YARL/TRAY/RAY) ---")
    extended_keys = {
        "YART_1": YART_1,
        "YARL_1": YARL_1,
        "TRAY_1": TRAY_1,
        "RAY_1":  RAY_1,
    }

    for name, base_key in extended_keys.items():
        seen_perms = set()
        tested_this = 0
        for perm in permutations(base_key):
            key = list(perm)
            key_t = tuple(key)
            if key_t in seen_perms:
                continue
            seen_perms.add(key_t)
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, key, variant)
                sc = score_cribs(pt)
                label = f"{name}_perm{list(key)}_{variant}"
                tracker.record(sc, label, "P1b", pt)
                configs += 1
                tested_this += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     PT: {pt[:50]}")
        print(f"  {name}: {tested_this} configs tested")

    print(f"  Phase 1b: {configs} configs total, best so far: {tracker.best_score}/24")

    # ── Phase 1c: Autokey modes ──
    print(f"\n  --- Phase 1c: Autokey with YAR [25,1,18] seed ---")
    for seed_name, seed in [("YAR_1", YAR_1), ("YAR_0", YAR_0)]:
        for variant in VARIANTS:
            # PT autokey
            pt = decrypt_autokey_pt(CT, seed, variant)
            sc = score_cribs(pt)
            label = f"autokey_PT_{seed_name}_{variant}"
            tracker.record(sc, label, "P1c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

            # CT autokey
            pt = decrypt_autokey_ct(CT, seed, variant)
            sc = score_cribs(pt)
            label = f"autokey_CT_{seed_name}_{variant}"
            tracker.record(sc, label, "P1c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # Also test extended seeds as autokey primers
    for seed_name, seed in [("YART_1", YART_1), ("DYAR_1", DYAR_1), ("DYARO_1", DYARO_1)]:
        for variant in VARIANTS:
            pt = decrypt_autokey_pt(CT, seed, variant)
            sc = score_cribs(pt)
            label = f"autokey_PT_{seed_name}_{variant}"
            tracker.record(sc, label, "P1c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

            pt = decrypt_autokey_ct(CT, seed, variant)
            sc = score_cribs(pt)
            label = f"autokey_CT_{seed_name}_{variant}"
            tracker.record(sc, label, "P1c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    print(f"\n  Phase 1 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2: YAR [25, 1, 18] as transposition parameters
# ══════════════════════════════════════════════════════════════════════════════

def phase2_yar_transposition():
    """Test YAR as transposition parameters: width, rotation, decimation, grid."""
    print("\n" + "=" * 78)
    print("  PHASE 2: YAR [25, 1, 18] AS TRANSPOSITION PARAMETERS")
    print("=" * 78)

    configs = 0

    # ── Phase 2a: Columnar transposition width 3 ──
    print(f"\n  --- Phase 2a: Columnar width 3, ordering from [25,1,18] ---")
    # Sorted rank: 1<18<25 → ranks [2, 0, 1]
    col_order_1 = [2, 0, 1]  # from sorted rank of [25, 1, 18]
    # Also from 0-indexed [24, 0, 17] → same relative order → same rank [2, 0, 1]
    col_order_0 = [2, 0, 1]  # same!
    print(f"  1-indexed sort of [25,1,18] -> col order {col_order_1}")
    print(f"  0-indexed sort of [24,0,17] -> col order {col_order_0}")
    print(f"  NOTE: Relative order is preserved — col ordering is IDENTICAL")

    perm = columnar_perm(3, col_order_1, CT_LEN)
    inv = invert_perm(perm)

    # Gather (encryption direction)
    ct_gathered = apply_perm(CT, perm)
    sc = score_cribs(ct_gathered)
    label = "col_w3_order[2,0,1]_gather"
    tracker.record(sc, label, "P2a", ct_gathered)
    configs += 1
    if sc > NOISE_FLOOR:
        print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # Scatter (decryption direction)
    ct_scattered = apply_perm(CT, inv)
    sc = score_cribs(ct_scattered)
    label = "col_w3_order[2,0,1]_scatter"
    tracker.record(sc, label, "P2a", ct_scattered)
    configs += 1
    if sc > NOISE_FLOOR:
        print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # With substitution on scattered result
    for variant in VARIANTS:
        for kw_name, kw_key in [("KRYPTOS", KRYPTOS_KEY), ("YAR1", YAR_1)]:
            pt = decrypt_with_key(ct_scattered, kw_key, variant)
            sc = score_cribs(pt)
            label = f"col_w3_scatter+{kw_name}_{variant}"
            tracker.record(sc, label, "P2a", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # All 6 orderings of 3 columns
    print(f"\n  --- Phase 2a-ext: All 6 column orderings for width 3 ---")
    for col_perm in permutations(range(3)):
        col_order = list(col_perm)
        perm = columnar_perm(3, col_order, CT_LEN)
        inv = invert_perm(perm)
        ct_dec = apply_perm(CT, inv)
        sc = score_cribs(ct_dec)
        label = f"col_w3_order{col_order}_scatter"
        tracker.record(sc, label, "P2a", ct_dec)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

        for variant in VARIANTS:
            pt = decrypt_with_key(ct_dec, KRYPTOS_KEY, variant)
            sc = score_cribs(pt)
            label = f"col_w3_order{col_order}+KRYPTOS_{variant}"
            tracker.record(sc, label, "P2a", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # ── Phase 2b: CT rotation by 25, 1, 18 ──
    print(f"\n  --- Phase 2b: CT rotation by 25, 1, 18 ---")
    for rot_val in [25, 1, 18, 24, 0, 17]:
        rotated = CT[rot_val:] + CT[:rot_val]
        shifted_cribs = {(pos - rot_val) % CT_LEN: ch for pos, ch in CRIB_DICT.items()}

        # Raw score
        sc = sum(1 for pos, ch in shifted_cribs.items() if 0 <= pos < len(rotated) and rotated[pos] == ch)
        label = f"rot{rot_val}_raw"
        tracker.record(sc, label, "P2b", rotated)
        configs += 1

        # With substitution
        for variant in VARIANTS:
            for kw_name, kw_key in [("KRYPTOS", KRYPTOS_KEY), ("YAR1", YAR_1)]:
                pt = decrypt_with_key(rotated, kw_key, variant)
                sc = sum(1 for pos, ch in shifted_cribs.items() if 0 <= pos < len(pt) and pt[pos] == ch)
                label = f"rot{rot_val}+{kw_name}_{variant}"
                tracker.record(sc, label, "P2b", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # ── Phase 2c: Skip decimation by 25, 1, 18 ──
    print(f"\n  --- Phase 2c: Skip decimation by 25, 1, 18 ---")
    for skip in [25, 1, 18, 24, 17]:
        if math.gcd(skip, CT_LEN) != 1:
            print(f"  SKIP {skip}: gcd({skip}, {CT_LEN}) != 1, not a valid permutation")
            continue
        for start in range(CT_LEN):
            decimated = ""
            pos = start
            for _ in range(CT_LEN):
                decimated += CT[pos]
                pos = (pos + skip) % CT_LEN
            sc = score_cribs(decimated)
            label = f"decimate{skip}_start{start}"
            tracker.record(sc, label, "P2c", decimated)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

            # With KRYPTOS substitution on best start positions
            if start < 5:  # limit to avoid explosion
                for variant in ["vig", "beau"]:
                    pt = decrypt_with_key(decimated, KRYPTOS_KEY, variant)
                    sc2 = score_cribs(pt)
                    label2 = f"decimate{skip}_s{start}+KRYPTOS_{variant}"
                    tracker.record(sc2, label2, "P2c", pt)
                    configs += 1
                    if sc2 > NOISE_FLOOR:
                        print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")

    # ── Phase 2d: Grid widths 25 and 18 ──
    print(f"\n  --- Phase 2d: Grid widths 25 and 18 (1-indexed YAR values) ---")
    for w in [25, 18, 24, 17]:
        h = math.ceil(CT_LEN / w)
        print(f"  Width {w}: {h} rows ({CT_LEN} chars)")

        # Column-first read
        col_read = []
        for c in range(w):
            for r in range(h):
                idx = r * w + c
                if idx < CT_LEN:
                    col_read.append(CT[idx])
        col_text = "".join(col_read)

        sc = score_cribs(col_text)
        label = f"grid_w{w}_col_read"
        tracker.record(sc, label, "P2d", col_text)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

        # Also try inverse (write by columns, read by rows)
        inv_read = [''] * CT_LEN
        idx = 0
        for c in range(w):
            for r in range(h):
                pos = r * w + c
                if pos < CT_LEN and idx < CT_LEN:
                    inv_read[pos] = CT[idx]
                    idx += 1
        inv_text = "".join(inv_read)
        if len(inv_text) == CT_LEN:
            sc = score_cribs(inv_text)
            label = f"grid_w{w}_inv_read"
            tracker.record(sc, label, "P2d", inv_text)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

        # With KRYPTOS substitution
        for text, text_name in [(col_text, "col"), (inv_text, "inv")]:
            if len(text) != CT_LEN:
                continue
            for variant in ["vig", "beau"]:
                pt = decrypt_with_key(text, KRYPTOS_KEY, variant)
                sc = score_cribs(pt)
                label = f"grid_w{w}_{text_name}+KRYPTOS_{variant}"
                tracker.record(sc, label, "P2d", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    print(f"\n  Phase 2 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3: Combined 1-indexed parameters
# ══════════════════════════════════════════════════════════════════════════════

def phase3_combined():
    """Test combinations of 1-indexed parameters."""
    print("\n" + "=" * 78)
    print("  PHASE 3: COMBINED 1-INDEXED PARAMETERS")
    print("=" * 78)

    configs = 0

    # ── Phase 3a: YAR + T=20 (period 4) ──
    print(f"\n  --- Phase 3a: YAR+T key combinations ---")
    combo_keys = {
        "YAR1+T20 [25,1,18,20]": [25, 1, 18, 20],
        "T20+YAR1 [20,25,1,18]": [20, 25, 1, 18],
        "YAR0+T19 [24,0,17,19]": [24, 0, 17, 19],
        "T19+YAR0 [19,24,0,17]": [19, 24, 0, 17],
    }
    for name, key in combo_keys.items():
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"{name}_{variant}"
            tracker.record(sc, label, "P3a", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # ── Phase 3b: YAR + RQ (period 5) ──
    print(f"\n  --- Phase 3b: YAR+RQ key combinations ---")
    combo_keys_rq = {
        "YAR1+RQ1 [25,1,18,18,17]": [25, 1, 18, 18, 17],
        "RQ1+YAR1 [18,17,25,1,18]": [18, 17, 25, 1, 18],
        "YAR0+RQ0 [24,0,17,17,16]": [24, 0, 17, 17, 16],
        "RQ0+YAR0 [17,16,24,0,17]": [17, 16, 24, 0, 17],
        "YAR1+RQ1_alt [25,1,18,17,18]": [25, 1, 18, 17, 18],  # RQ reversed
    }
    for name, key in combo_keys_rq.items():
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"{name}_{variant}"
            tracker.record(sc, label, "P3b", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # ── Phase 3c: EQUAL 1-indexed [5,18,22,2,13] as period 5 key ──
    print(f"\n  --- Phase 3c: EQUAL 1-indexed [5,18,22,2,13] (period 5) ---")
    # Note: the user specified [5,17,21,1,12] but let me verify.
    # E=5, R=18, V=22, B=2, M=13 in 1-indexed. But user wrote [5,17,21,1,12].
    # User's 0-indexed: [4,16,20,0,11] → E=4, Q=16, U=20, A=0, L=11
    # Hmm, these don't match E,R,V,B,M. Let me use the user's exact values.
    EQUAL_1_user = [5, 17, 21, 1, 12]   # as specified by user
    EQUAL_0_user = [4, 16, 20, 0, 11]   # as specified by user

    for name, key in [("EQUAL_1", EQUAL_1_user), ("EQUAL_0", EQUAL_0_user)]:
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"{name}_{variant}"
            tracker.record(sc, label, "P3c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # All 120 permutations of EQUAL_1 x 3 variants = 360 configs
    print(f"  Testing all 120 permutations of EQUAL_1 x 3 variants = 360 configs...")
    seen_eq = set()
    eq_above_noise = 0
    for perm in permutations(EQUAL_1_user):
        key = list(perm)
        key_t = tuple(key)
        if key_t in seen_eq:
            continue
        seen_eq.add(key_t)
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"EQUAL1_perm{list(key)}_{variant}"
            tracker.record(sc, label, "P3c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                eq_above_noise += 1
                if eq_above_noise <= 5:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
    if eq_above_noise > 5:
        print(f"  ... {eq_above_noise} total above noise floor")

    # ── Phase 3d: YAR + misspelling shifts = period 7 ──
    print(f"\n  --- Phase 3d: YAR [25,1,18] + misspelling shifts [4,5,4,16] = period 7 ---")
    p7_key = [25, 1, 18, 4, 5, 4, 16]
    print(f"  Key: {p7_key} (period 7 — matches KRYPTOS keyword length!)")

    # All 7 rotations x 3 variants = 21 configs
    for rot in range(7):
        rotated_key = p7_key[rot:] + p7_key[:rot]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, rotated_key, variant)
            sc = score_cribs(pt)
            label = f"YAR1+missp_rot{rot}{rotated_key}_{variant}"
            tracker.record(sc, label, "P3d", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # Also try 0-indexed version
    p7_key_0 = [24, 0, 17, 4, 5, 4, 16]
    print(f"  0-indexed equivalent: {p7_key_0}")
    for rot in range(7):
        rotated_key = p7_key_0[rot:] + p7_key_0[:rot]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, rotated_key, variant)
            sc = score_cribs(pt)
            label = f"YAR0+missp_rot{rot}{rotated_key}_{variant}"
            tracker.record(sc, label, "P3d", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # Also reversed misspelling order
    p7_key_rev = [25, 1, 18, 16, 4, 5, 4]
    for rot in range(7):
        rotated_key = p7_key_rev[rot:] + p7_key_rev[:rot]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, rotated_key, variant)
            sc = score_cribs(pt)
            label = f"YAR1+missp_rev_rot{rot}_{variant}"
            tracker.record(sc, label, "P3d", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # Misspelling shifts + YAR (reversed concatenation order)
    p7_key_alt = [4, 5, 4, 16, 25, 1, 18]
    for rot in range(7):
        rotated_key = p7_key_alt[rot:] + p7_key_alt[:rot]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, rotated_key, variant)
            sc = score_cribs(pt)
            label = f"missp+YAR1_rot{rot}_{variant}"
            tracker.record(sc, label, "P3d", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    print(f"\n  Phase 3 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 4: YAR as keyword for columnar transposition
# ══════════════════════════════════════════════════════════════════════════════

def phase4_yar_columnar():
    """Test YAR as column keyword and width parameter."""
    print("\n" + "=" * 78)
    print("  PHASE 4: YAR AS KEYWORD FOR COLUMNAR TRANSPOSITION")
    print("=" * 78)

    configs = 0

    # ── Phase 4a: Sort-derived column order ──
    print(f"\n  --- Phase 4a: Column order from YAR sort ---")
    # [25, 1, 18] -> sorted positions: 1 is smallest (idx 1), 18 next (idx 2), 25 last (idx 0)
    # ranks: [2, 0, 1]
    # This is the SAME for both 0-indexed and 1-indexed because relative order is preserved
    print(f"  1-indexed [25,1,18] -> col order [2, 0, 1] (SAME as 0-indexed)")
    print(f"  0-indexed [24,0,17] -> col order [2, 0, 1] (IDENTICAL)")
    print(f"  YAR as column ORDER is indexing-invariant. Testing anyway.")

    for col_order in [[2, 0, 1], [1, 2, 0], [0, 1, 2]]:
        perm = columnar_perm(3, col_order, CT_LEN)
        inv = invert_perm(perm)
        ct_dec = apply_perm(CT, inv)
        sc = score_cribs(ct_dec)
        label = f"col_w3_{col_order}_scatter"
        tracker.record(sc, label, "P4a", ct_dec)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

        # With substitution
        for variant in VARIANTS:
            for kw_name, kw_key in [("KRYPTOS", KRYPTOS_KEY), ("YAR1", YAR_1)]:
                pt = decrypt_with_key(ct_dec, kw_key, variant)
                sc2 = score_cribs(pt)
                label2 = f"col_w3_{col_order}+{kw_name}_{variant}"
                tracker.record(sc2, label2, "P4a", pt)
                configs += 1
                if sc2 > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")

    # ── Phase 4b: Width comparison 25 vs 24 ──
    print(f"\n  --- Phase 4b: Width 25 vs Width 24 (YAR as WIDTH differs by indexing) ---")
    for w in [25, 24]:
        h = math.ceil(CT_LEN / w)
        print(f"  Width {w}: {h} rows, {w*h - CT_LEN} padding")

        # Identity column order
        col_order = list(range(w))
        try:
            perm = columnar_perm(w, col_order, CT_LEN)
            inv = invert_perm(perm)
            ct_dec = apply_perm(CT, inv)
            sc = score_cribs(ct_dec)
            label = f"col_w{w}_identity_scatter"
            tracker.record(sc, label, "P4b", ct_dec)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

            # Reverse order
            rev_order = list(range(w - 1, -1, -1))
            perm_r = columnar_perm(w, rev_order, CT_LEN)
            inv_r = invert_perm(perm_r)
            ct_dec_r = apply_perm(CT, inv_r)
            sc_r = score_cribs(ct_dec_r)
            label_r = f"col_w{w}_reverse_scatter"
            tracker.record(sc_r, label_r, "P4b", ct_dec_r)
            configs += 1
            if sc_r > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label_r} -> {sc_r}/24")

            # With substitution
            for text, t_name in [(ct_dec, "id"), (ct_dec_r, "rev")]:
                for variant in ["vig", "beau"]:
                    pt = decrypt_with_key(text, KRYPTOS_KEY, variant)
                    sc2 = score_cribs(pt)
                    label2 = f"col_w{w}_{t_name}+KRYPTOS_{variant}"
                    tracker.record(sc2, label2, "P4b", pt)
                    configs += 1
                    if sc2 > NOISE_FLOOR:
                        print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")

        except Exception as e:
            print(f"  Error at width {w}: {e}")

    # ── Phase 4c: Width 18 vs 17 (R value) ──
    print(f"\n  --- Phase 4c: Width 18 vs Width 17 (R=18 vs R=17) ---")
    for w in [18, 17]:
        h = math.ceil(CT_LEN / w)
        col_order = list(range(w))
        try:
            perm = columnar_perm(w, col_order, CT_LEN)
            inv = invert_perm(perm)
            ct_dec = apply_perm(CT, inv)
            sc = score_cribs(ct_dec)
            label = f"col_w{w}_identity_scatter"
            tracker.record(sc, label, "P4c", ct_dec)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

            for variant in ["vig", "beau"]:
                pt = decrypt_with_key(ct_dec, KRYPTOS_KEY, variant)
                sc2 = score_cribs(pt)
                label2 = f"col_w{w}+KRYPTOS_{variant}"
                tracker.record(sc2, label2, "P4c", pt)
                configs += 1
                if sc2 > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")

        except Exception as e:
            print(f"  Error at width {w}: {e}")

    print(f"\n  Phase 4 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 5: DYAR and DYARO 1-indexed
# ══════════════════════════════════════════════════════════════════════════════

def phase5_dyar():
    """Test DYAR and DYARO in 1-indexed form as periodic keys."""
    print("\n" + "=" * 78)
    print("  PHASE 5: DYAR AND DYARO 1-INDEXED")
    print("=" * 78)

    configs = 0

    # ── Phase 5a: DYAR [4,25,1,18] period 4 ──
    print(f"\n  --- Phase 5a: DYAR 1-indexed [4,25,1,18] (period 4) ---")
    print(f"  Compare: 0-indexed DYAR = [3,24,0,17]")

    for name, key in [("DYAR_1", DYAR_1), ("DYAR_0", DYAR_0)]:
        # All rotations
        for rot in range(len(key)):
            rotated_key = key[rot:] + key[:rot]
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, rotated_key, variant)
                sc = score_cribs(pt)
                label = f"{name}_rot{rot}{rotated_key}_{variant}"
                tracker.record(sc, label, "P5a", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     PT: {pt[:50]}")

    # All 24 permutations of DYAR_1
    print(f"  Testing all 24 permutations of DYAR_1 x 3 variants = 72 configs...")
    seen_dy = set()
    for perm in permutations(DYAR_1):
        key = list(perm)
        key_t = tuple(key)
        if key_t in seen_dy:
            continue
        seen_dy.add(key_t)
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"DYAR1_perm{list(key)}_{variant}"
            tracker.record(sc, label, "P5a", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # ── Phase 5b: DYARO [4,25,1,18,15] period 5 ──
    print(f"\n  --- Phase 5b: DYARO 1-indexed [4,25,1,18,15] (period 5) ---")
    print(f"  Compare: 0-indexed DYARO = [3,24,0,17,14]")

    for name, key in [("DYARO_1", DYARO_1), ("DYARO_0", DYARO_0)]:
        # All rotations
        for rot in range(len(key)):
            rotated_key = key[rot:] + key[:rot]
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, rotated_key, variant)
                sc = score_cribs(pt)
                label = f"{name}_rot{rot}_{variant}"
                tracker.record(sc, label, "P5b", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     PT: {pt[:50]}")

    # All 120 permutations of DYARO_1
    print(f"  Testing all permutations of DYARO_1 x 3 variants...")
    seen_dyo = set()
    dyo_above = 0
    for perm in permutations(DYARO_1):
        key = list(perm)
        key_t = tuple(key)
        if key_t in seen_dyo:
            continue
        seen_dyo.add(key_t)
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"DYARO1_perm_{variant}"
            tracker.record(sc, label, "P5b", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                dyo_above += 1
                if dyo_above <= 5:
                    print(f"  ** ABOVE NOISE: DYARO1 perm {list(key)} {variant} -> {sc}/24")
    if dyo_above > 5:
        print(f"  ... {dyo_above} total above noise")

    # ── Phase 5c: DYAR/DYARO as autokey seeds ──
    print(f"\n  --- Phase 5c: DYAR/DYARO as autokey seeds ---")
    for name, seed in [("DYAR_1", DYAR_1), ("DYAR_0", DYAR_0),
                        ("DYARO_1", DYARO_1), ("DYARO_0", DYARO_0)]:
        for variant in VARIANTS:
            pt = decrypt_autokey_pt(CT, seed, variant)
            sc = score_cribs(pt)
            label = f"autokey_PT_{name}_{variant}"
            tracker.record(sc, label, "P5c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

            pt = decrypt_autokey_ct(CT, seed, variant)
            sc = score_cribs(pt)
            label = f"autokey_CT_{name}_{variant}"
            tracker.record(sc, label, "P5c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    print(f"\n  Phase 5 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 6: Period-7 comprehensive
# ══════════════════════════════════════════════════════════════════════════════

def phase6_period7():
    """Comprehensive period-7 testing with 1-indexed combinations."""
    print("\n" + "=" * 78)
    print("  PHASE 6: PERIOD-7 COMPREHENSIVE (1-INDEXED)")
    print("=" * 78)

    configs = 0

    # KRYPTOS 0-indexed: [10, 17, 24, 15, 19, 14, 18]
    # KRYPTOS 1-indexed: [11, 18, 25, 16, 20, 15, 19]
    yar_missp_1 = [25, 1, 18, 4, 5, 4, 16]
    yar_missp_0 = [24, 0, 17, 4, 5, 4, 16]

    # ── Phase 6a: Element-wise SUM of KRYPTOS + [25,1,18,4,5,4,16] mod 26 ──
    print(f"\n  --- Phase 6a: KRYPTOS (op) YAR+missp combinations ---")
    for kryp_name, kryp_key in [("KRYPTOS_0", KRYPTOS_KEY), ("KRYPTOS_1", KRYPTOS_1)]:
        for ym_name, ym_key in [("YM_1", yar_missp_1), ("YM_0", yar_missp_0)]:
            # Element-wise SUM
            key_sum = [(a + b) % MOD for a, b in zip(kryp_key, ym_key)]
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, key_sum, variant)
                sc = score_cribs(pt)
                label = f"{kryp_name}+{ym_name}_SUM{key_sum}_{variant}"
                tracker.record(sc, label, "P6a", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     PT: {pt[:50]}")

            # Element-wise DIFFERENCE (kryp - ym)
            key_diff = [(a - b) % MOD for a, b in zip(kryp_key, ym_key)]
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, key_diff, variant)
                sc = score_cribs(pt)
                label = f"{kryp_name}-{ym_name}_DIFF{key_diff}_{variant}"
                tracker.record(sc, label, "P6a", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     PT: {pt[:50]}")

            # Element-wise DIFFERENCE (ym - kryp)
            key_diff2 = [(b - a) % MOD for a, b in zip(kryp_key, ym_key)]
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, key_diff2, variant)
                sc = score_cribs(pt)
                label = f"{ym_name}-{kryp_name}_DIFF{key_diff2}_{variant}"
                tracker.record(sc, label, "P6a", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     PT: {pt[:50]}")

            # XOR-like: (a ^ b) mod 26 — bitwise XOR then mod 26
            key_xor = [(a ^ b) % MOD for a, b in zip(kryp_key, ym_key)]
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, key_xor, variant)
                sc = score_cribs(pt)
                label = f"{kryp_name}^{ym_name}_XOR{key_xor}_{variant}"
                tracker.record(sc, label, "P6a", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     PT: {pt[:50]}")

    # ── Phase 6b: Interleaving YAR and shifts to make period 7 ──
    print(f"\n  --- Phase 6b: Interleaved period-7 keys ---")
    # YAR = [25, 1, 18], shifts = [4, 5, 4, 16]
    # Various interleavings:
    interleaves = {
        "Y_s_A_s_R_s_s": [25, 4, 1, 5, 18, 4, 16],      # alternating
        "s_Y_s_A_s_R_s": [4, 25, 5, 1, 4, 18, 16],
        "s_s_Y_s_s_A_R": [4, 5, 25, 4, 16, 1, 18],
        "YAR_sss_s":     [25, 1, 18, 4, 5, 4, 16],       # concatenated (already tested in P3d)
        "sss_s_YAR":     [4, 5, 4, 16, 25, 1, 18],       # reversed concat
        "s_Y_s_A_R_s_s": [4, 25, 5, 1, 18, 4, 16],
        "YR_ssss_A":     [25, 18, 4, 5, 4, 16, 1],
        "mirror_Y_ss_R_ss_A": [25, 4, 5, 18, 4, 16, 1],  # Y...R...A mirror
    }
    for name, key in interleaves.items():
        assert len(key) == 7, f"Key {name} has length {len(key)}, expected 7"
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            label = f"interleave_{name}_{variant}"
            tracker.record(sc, label, "P6b", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # ── Phase 6c: Period-7 keys derived from 1-indexed KRYPTOS ──
    print(f"\n  --- Phase 6c: KRYPTOS 1-indexed [11,18,25,16,20,15,19] as key ---")
    for variant in VARIANTS:
        pt = decrypt_with_key(CT, KRYPTOS_1, variant)
        sc = score_cribs(pt)
        label = f"KRYPTOS_1idx_{variant}"
        tracker.record(sc, label, "P6c", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
            print(f"     PT: {pt[:50]}")

    # Difference between KRYPTOS 0-indexed and 1-indexed
    key_k_diff = [(a - b) % MOD for a, b in zip(KRYPTOS_KEY, KRYPTOS_1)]
    print(f"  KRYPTOS_0 - KRYPTOS_1 = {key_k_diff}")
    # This should be [-1, -1, -1, -1, -1, -1, -1] mod 26 = [25,25,25,25,25,25,25]
    # Which is just a Caesar shift of -1!

    # ── Phase 6d: Transposition + substitution with period 7 keys ──
    print(f"\n  --- Phase 6d: Width-7 columnar + period-7 1-indexed keys ---")
    # Test width 7 with various column orders, followed by period-7 substitution
    width7_orders = list(permutations(range(7)))
    print(f"  Testing {len(width7_orders)} col orderings x selected keys x 3 variants...")

    p7_keys_to_test = {
        "YAR1+missp": yar_missp_1,
        "KRYPTOS_1": KRYPTOS_1,
        "KRYPTOS_0": KRYPTOS_KEY,
    }

    # Sample: test all 5040 column orderings but only with the most promising keys
    best_p6d = 0
    for col_order in width7_orders:
        col_list = list(col_order)
        try:
            perm = columnar_perm(7, col_list, CT_LEN)
            inv = invert_perm(perm)
            ct_dec = apply_perm(CT, inv)
        except Exception:
            continue

        # Quick raw check
        sc_raw = score_cribs(ct_dec)
        configs += 1
        if sc_raw > NOISE_FLOOR:
            tracker.record(sc_raw, f"col_w7_{col_list}_raw", "P6d", ct_dec)
            print(f"  ** RAW ABOVE NOISE: col_w7 {col_list} -> {sc_raw}/24")

        # With each period-7 key
        for kn, kk in p7_keys_to_test.items():
            for variant in ["vig", "beau"]:
                pt = decrypt_with_key(ct_dec, kk, variant)
                sc = score_cribs(pt)
                tracker.record(sc, f"col_w7_{col_list}+{kn}_{variant}", "P6d", pt)
                configs += 1
                if sc > best_p6d:
                    best_p6d = sc
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: col_w7 {col_list}+{kn}_{variant} -> {sc}/24")

    print(f"  Phase 6d: best = {best_p6d}/24")

    # ── Phase 6e: YAR+missp with columnar transposition (period 7 key + width 7 transposition) ──
    print(f"\n  --- Phase 6e: Other period-7 key attempts ---")
    # RQ + EQUAL_1 truncated to 7 = [18, 17, 5, 17, 21, 1, 12]
    rq_eq_7 = [18, 17, 5, 17, 21, 1, 12]
    for variant in VARIANTS:
        pt = decrypt_with_key(CT, rq_eq_7, variant)
        sc = score_cribs(pt)
        label = f"RQ1+EQUAL1_trunc7_{variant}"
        tracker.record(sc, label, "P6e", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # T + YAR + missp shifts = [20, 25, 1, 18, 4, 5, 4] — period 7
    t_yar_missp = [20, 25, 1, 18, 4, 5, 4]
    for rot in range(7):
        rotated_key = t_yar_missp[rot:] + t_yar_missp[:rot]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, rotated_key, variant)
            sc = score_cribs(pt)
            label = f"T+YAR1+missp3_rot{rot}_{variant}"
            tracker.record(sc, label, "P6e", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # DYAR + missp3 = [4, 25, 1, 18, 4, 5, 4] — period 7 with duplicate 4s
    dyar_missp = [4, 25, 1, 18, 4, 5, 4]
    for rot in range(7):
        rotated_key = dyar_missp[rot:] + dyar_missp[:rot]
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, rotated_key, variant)
            sc = score_cribs(pt)
            label = f"DYAR1+missp3_rot{rot}_{variant}"
            tracker.record(sc, label, "P6e", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    print(f"\n  Phase 6 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 7: Head-to-head comparison
# ══════════════════════════════════════════════════════════════════════════════

def phase7_head_to_head():
    """Compare top 1-indexed results with their 0-indexed equivalents."""
    print("\n" + "=" * 78)
    print("  PHASE 7: HEAD-TO-HEAD 1-INDEXED vs 0-INDEXED COMPARISON")
    print("=" * 78)

    configs = 0

    # Define paired comparisons: (name, 1-indexed key, 0-indexed key)
    paired = [
        ("YAR",            YAR_1,    YAR_0),
        ("YART",           YART_1,   YART_0),
        ("RAY",            RAY_1,    RAY_0),
        ("TRAY",           TRAY_1,   TRAY_0),
        ("DYAR",           DYAR_1,   DYAR_0),
        ("DYARO",          DYARO_1,  DYARO_0),
        ("RQ",             RQ_1,     RQ_0),
        ("EQUAL",          [5, 17, 21, 1, 12], [4, 16, 20, 0, 11]),
        ("YAR+missp_p7",   [25, 1, 18, 4, 5, 4, 16], [24, 0, 17, 4, 5, 4, 16]),
        ("KRYPTOS",        KRYPTOS_1, KRYPTOS_KEY),
    ]

    results_1idx = {}
    results_0idx = {}

    print(f"\n  {'Name':<20s} {'Variant':<10s} {'1-idx Score':>11s} {'0-idx Score':>11s} {'Winner':>8s}")
    print(f"  {'-'*20} {'-'*10} {'-'*11} {'-'*11} {'-'*8}")

    for name, key1, key0 in paired:
        for variant in VARIANTS:
            pt1 = decrypt_with_key(CT, key1, variant)
            sc1 = score_cribs(pt1)
            tracker.record(sc1, f"h2h_{name}_1idx_{variant}", "P7", pt1)
            configs += 1

            pt0 = decrypt_with_key(CT, key0, variant)
            sc0 = score_cribs(pt0)
            tracker.record(sc0, f"h2h_{name}_0idx_{variant}", "P7", pt0)
            configs += 1

            k = f"{name}_{variant}"
            results_1idx[k] = sc1
            results_0idx[k] = sc0

            if sc1 == sc0:
                winner = "TIE"
            elif sc1 > sc0:
                winner = "1-IDX"
            else:
                winner = "0-IDX"

            if sc1 > NOISE_FLOOR or sc0 > NOISE_FLOOR:
                print(f"  {name:<20s} {variant:<10s} {sc1:>5d}/24    {sc0:>5d}/24    {winner:>8s} **")
            else:
                print(f"  {name:<20s} {variant:<10s} {sc1:>5d}/24    {sc0:>5d}/24    {winner:>8s}")

    # Summary statistics
    n_1_wins = sum(1 for k in results_1idx if results_1idx[k] > results_0idx[k])
    n_0_wins = sum(1 for k in results_1idx if results_0idx[k] > results_1idx[k])
    n_ties = sum(1 for k in results_1idx if results_1idx[k] == results_0idx[k])

    avg_1 = sum(results_1idx.values()) / len(results_1idx) if results_1idx else 0
    avg_0 = sum(results_0idx.values()) / len(results_0idx) if results_0idx else 0

    print(f"\n  SUMMARY:")
    print(f"  1-indexed wins: {n_1_wins}")
    print(f"  0-indexed wins: {n_0_wins}")
    print(f"  Ties:           {n_ties}")
    print(f"  Average 1-idx:  {avg_1:.2f}/24")
    print(f"  Average 0-idx:  {avg_0:.2f}/24")

    if avg_1 > avg_0 + 0.5:
        print(f"  VERDICT: 1-indexed scores BETTER on average (+{avg_1 - avg_0:.2f})")
    elif avg_0 > avg_1 + 0.5:
        print(f"  VERDICT: 0-indexed scores BETTER on average (+{avg_0 - avg_1:.2f})")
    else:
        print(f"  VERDICT: No meaningful difference between indexing conventions")

    # Also test autokey head-to-head
    print(f"\n  --- Autokey head-to-head ---")
    for name, seed1, seed0 in [("YAR", YAR_1, YAR_0), ("DYAR", DYAR_1, DYAR_0)]:
        for variant in VARIANTS:
            for mode, func in [("PT", decrypt_autokey_pt), ("CT", decrypt_autokey_ct)]:
                pt1 = func(CT, seed1, variant)
                sc1 = score_cribs(pt1)
                pt0 = func(CT, seed0, variant)
                sc0 = score_cribs(pt0)
                configs += 2

                winner = "TIE" if sc1 == sc0 else ("1-IDX" if sc1 > sc0 else "0-IDX")
                if sc1 > NOISE_FLOOR or sc0 > NOISE_FLOOR:
                    print(f"  autokey_{mode}_{name}  {variant:<10s}  1-idx:{sc1}/24  0-idx:{sc0}/24  {winner} **")
                else:
                    print(f"  autokey_{mode}_{name}  {variant:<10s}  1-idx:{sc1}/24  0-idx:{sc0}/24  {winner}")

    # Top 5 overall + their 0-indexed equivalents
    print(f"\n  --- Top 5 overall results ---")
    top5 = tracker.top_n(5)
    for i, (sc, label, phase, pt_snip) in enumerate(top5):
        print(f"  {i+1}. {sc}/24 [{phase}] {label}")
        print(f"     PT: {pt_snip}")

    print(f"\n  Phase 7 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()

    print("=" * 78)
    print("  E-BESPOKE-07: SYSTEMATIC 1-INDEXED PARAMETER VARIANTS")
    print("  Closing audit gap: YAR/RQ/EQUAL/DYAR never tested in 1-indexed form")
    print("=" * 78)
    print(f"  CT: {CT}")
    print(f"  CT length: {CT_LEN}")
    print(f"  Cribs (0-indexed): {CRIB_WORDS}")
    print(f"\n  Parameter comparison:")
    print(f"    YAR  0-idx: {YAR_0}  vs  1-idx: {YAR_1}")
    print(f"    YART 0-idx: {YART_0}  vs  1-idx: {YART_1}")
    print(f"    RAY  0-idx: {RAY_0}  vs  1-idx: {RAY_1}")
    print(f"    TRAY 0-idx: {TRAY_0}  vs  1-idx: {TRAY_1}")
    print(f"    DYAR 0-idx: {DYAR_0}  vs  1-idx: {DYAR_1}")
    print(f"    DYARO 0-idx: {DYARO_0} vs  1-idx: {DYARO_1}")
    print(f"    RQ   0-idx: {RQ_0}  vs  1-idx: {RQ_1}")
    print(f"    KRYPTOS 0-idx: {KRYPTOS_KEY}  vs  1-idx: {KRYPTOS_1}")
    print(f"    EQUAL 0-idx: {[4,16,20,0,11]}  vs  1-idx: {[5,17,21,1,12]}")
    print(f"    Misspelling shifts: {MISSP_SHIFTS} (indexing-independent)")

    c1 = phase1_yar_key_material()
    c2 = phase2_yar_transposition()
    c3 = phase3_combined()
    c4 = phase4_yar_columnar()
    c5 = phase5_dyar()
    c6 = phase6_period7()
    c7 = phase7_head_to_head()

    # ── Final Summary ──
    elapsed = time.time() - t0

    print("\n" + "#" * 78)
    print("  FINAL SUMMARY — E-BESPOKE-07: 1-INDEXED PARAMETER VARIANTS")
    print("#" * 78)

    tracker.print_top(15)

    total = tracker.total_configs
    print(f"\n  Phase breakdown:")
    print(f"    Phase 1 (YAR key material):       {c1:>8d} configs")
    print(f"    Phase 2 (YAR transposition):      {c2:>8d} configs")
    print(f"    Phase 3 (Combined parameters):     {c3:>8d} configs")
    print(f"    Phase 4 (YAR columnar keyword):    {c4:>8d} configs")
    print(f"    Phase 5 (DYAR/DYARO):              {c5:>8d} configs")
    print(f"    Phase 6 (Period-7 comprehensive):  {c6:>8d} configs")
    print(f"    Phase 7 (Head-to-head):            {c7:>8d} configs")
    print(f"    TOTAL:                             {total:>8d} configs")

    print(f"\n  Elapsed time: {elapsed:.1f}s")

    best = tracker.best_score
    if best <= NOISE_FLOOR:
        print(f"\n  VERDICT: ALL RESULTS AT OR BELOW NOISE FLOOR ({NOISE_FLOOR}/24).")
        print(f"  1-indexed parameter interpretation does NOT produce meaningful results.")
        print(f"  The 0-indexed vs 1-indexed distinction is NOT the systematic error we suspected.")
        print(f"  AUDIT GAP CLOSED: both indexing conventions produce equivalent noise.")
    elif best < 10:
        print(f"\n  VERDICT: Best score {best}/24 — borderline, likely noise.")
        print(f"  1-indexed does not meaningfully improve over 0-indexed.")
    elif best < 18:
        print(f"\n  VERDICT: Best score {best}/24 — check period for false positive risk.")
        print(f"  At period <= 7, expected random is ~8.2/24.")
    else:
        print(f"\n  VERDICT: Best score {best}/24 — INVESTIGATE IMMEDIATELY.")
        print(f"  Check period, run Bean constraints, verify manually.")

    print(f"\n  Done.")


if __name__ == "__main__":
    main()
