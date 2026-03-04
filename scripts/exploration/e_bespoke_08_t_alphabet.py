#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-BESPOKE-08: T-first alphabet hypothesis — "T IS YOUR POSITION" = T=position 1.

Tests the hypothesis that the sculpture clue "T IS YOUR POSITION" literally
means the cipher alphabet starts at T instead of A:

  Standard: ABCDEFGHIJKLMNOPQRSTUVWXYZ  (A=0)
  T-first:  TUVWXYZABCDEFGHIJKLMNOPQRS  (T=0)

This is a rotation by 19: letter_value = (ord(c) - ord('T')) % 26.
Under T-alphabet, KRYPTOS = [17,24,5,22,0,21,25] instead of [10,17,24,15,19,14,18].

Six phases:
  1. T-alphabet Vigenere tableau (substitution with T-indexed key values)
  2. T-alphabet grid coordinates (columnar transposition with T-indexed column ordering)
  3. T-alphabet position-dependent key (CT self-referencing running key)
  4. T-alphabet + grid widths (columnar 5-14 + T-alphabet keyword orderings + Vig/Beau)
  5. T-alphabet + misspelling shifts (T-values of misspelled letters as key)
  6. Rotated KA alphabet (KRYPTOS alphabet starting from T)
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
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.transforms.transposition import (
    apply_perm,
    invert_perm,
    columnar_perm,
)
from kryptos.kernel.constraints.bean import verify_bean


# ── T-alphabet utilities ─────────────────────────────────────────────────────

T_ALPH = "TUVWXYZABCDEFGHIJKLMNOPQRS"  # T=0, U=1, ..., S=25
T_IDX = {c: i for i, c in enumerate(T_ALPH)}  # letter -> T-position (0-based)

def c2n(c: str) -> int:
    """Standard: A=0, B=1, ..., Z=25."""
    return ord(c) - 65

def n2c(n: int) -> str:
    return chr((n % 26) + 65)

def t_val(c: str) -> int:
    """T-alphabet position: T=0, U=1, ..., A=7, ..., S=25."""
    return T_IDX[c]

def keyword_t_vals(kw: str) -> List[int]:
    """Convert keyword to T-alphabet values (0-indexed)."""
    return [T_IDX[c] for c in kw.upper()]

def keyword_std_vals(kw: str) -> List[int]:
    """Convert keyword to standard alphabet values (0-indexed)."""
    return [ALPH_IDX[c] for c in kw.upper()]

def keyword_to_col_order(kw: str, alphabet_idx: Dict[str, int]) -> List[int]:
    """Convert keyword to column order using given alphabet index.

    Returns ranking: the column that should be read first gets rank 0, etc.
    """
    indexed = [(alphabet_idx[c], i) for i, c in enumerate(kw.upper())]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * len(kw)
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


# ── Decryption helpers ────────────────────────────────────────────────────────

VARIANTS = ["vig", "beau", "varbeau"]
VARIANT_NAMES = {"vig": "Vigenere", "beau": "Beaufort", "varbeau": "VarBeau"}

def decrypt_with_key(ct: str, key: List[int], variant: str) -> str:
    """Decrypt ct with numeric key (mod 26), returning plaintext string."""
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        cv = c2n(c)
        kv = key[i % klen] % MOD
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

def decrypt_with_alphabet(ct: str, key: List[int], variant: str,
                          enc_alph: str, dec_alph: str = ALPH) -> str:
    """Decrypt using a custom cipher alphabet for key lookup.

    Key values index into enc_alph instead of standard ALPH.
    Plaintext is read from dec_alph.
    """
    enc_idx = {c: i for i, c in enumerate(enc_alph)}
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        cv = enc_idx.get(c, c2n(c))
        kv = key[i % klen] % MOD
        if variant == "vig":
            pt_val = (cv - kv) % MOD
        elif variant == "beau":
            pt_val = (kv - cv) % MOD
        elif variant == "varbeau":
            pt_val = (cv + kv) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        result.append(dec_alph[pt_val])
    return "".join(result)


# ── Global best tracker ───────────────────────────────────────────────────────

class BestTracker:
    """Track top N results across all phases."""
    def __init__(self, max_entries: int = 50):
        self.results: List[Tuple[int, str, str, str]] = []
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


# ── Keywords to test ──────────────────────────────────────────────────────────

KEYWORDS = {
    "KRYPTOS":       "KRYPTOS",
    "PALIMPSEST":    "PALIMPSEST",
    "ABSCISSA":      "ABSCISSA",
    "BERLINCLOCK":   "BERLINCLOCK",
    "EASTNORTHEAST": "EASTNORTHEAST",
    "CHECKPOINT":    "CHECKPOINT",
    "CHARLIE":       "CHARLIE",
}


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: T-alphabet as Vigenere tableau
# ══════════════════════════════════════════════════════════════════════════════

def phase1_t_tableau():
    """T-alphabet Vigenere tableau: key values derived from T-first ordering."""
    print("\n" + "=" * 78)
    print("  PHASE 1: T-ALPHABET AS VIGENERE TABLEAU")
    print("=" * 78)

    configs = 0

    # Show key derivation for KRYPTOS
    print(f"\n  T-alphabet: {T_ALPH}")
    print(f"  Standard:   {ALPH}")
    print(f"\n  Key derivation comparison for KRYPTOS:")
    for c in "KRYPTOS":
        print(f"    {c}: standard={ALPH_IDX[c]:2d}  T-alph={T_IDX[c]:2d}")

    kryptos_std = keyword_std_vals("KRYPTOS")
    kryptos_t = keyword_t_vals("KRYPTOS")
    print(f"\n  KRYPTOS standard key: {kryptos_std}")
    print(f"  KRYPTOS T-alph key:  {kryptos_t}")
    print(f"  Difference (T - std) mod 26: {[(t - s) % 26 for s, t in zip(kryptos_std, kryptos_t)]}")

    # Phase 1a: All keywords x 3 variants, using T-alphabet key values
    print(f"\n  --- Phase 1a: Keywords with T-alphabet key values ---")
    for kw_name, kw_str in KEYWORDS.items():
        key_t = keyword_t_vals(kw_str)
        key_s = keyword_std_vals(kw_str)
        for variant in VARIANTS:
            # T-alphabet key
            pt = decrypt_with_key(CT, key_t, variant)
            sc = score_cribs(pt)
            label = f"T-key_{kw_name}_{variant}"
            tracker.record(sc, label, "P1a", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

            # Standard key for comparison
            pt_s = decrypt_with_key(CT, key_s, variant)
            sc_s = score_cribs(pt_s)
            label_s = f"Std-key_{kw_name}_{variant}"
            tracker.record(sc_s, label_s, "P1a", pt_s)
            configs += 1
            if sc_s > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label_s} -> {sc_s}/24")
                print(f"     PT: {pt_s[:50]}")

    # Phase 1b: T-alphabet tableau where CT and PT also use T-positions
    print(f"\n  --- Phase 1b: Full T-alphabet tableau (CT indexed by T, PT indexed by T) ---")
    for kw_name, kw_str in KEYWORDS.items():
        key_t = keyword_t_vals(kw_str)
        for variant in VARIANTS:
            # Encrypt using T-alphabet for everything:
            # CT val = T_IDX[ct_char], key val = T_IDX[key_char]
            # PT_val = decrypt(CT_val, key_val), PT = T_ALPH[PT_val]
            pt = decrypt_with_alphabet(CT, key_t, variant, T_ALPH, T_ALPH)
            sc = score_cribs(pt)
            label = f"T-full_{kw_name}_{variant}"
            tracker.record(sc, label, "P1b", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # Phase 1c: Mixed tableau — CT in T-alphabet, PT in standard
    print(f"\n  --- Phase 1c: Mixed tableau (CT T-indexed, PT standard) ---")
    for kw_name, kw_str in KEYWORDS.items():
        key_t = keyword_t_vals(kw_str)
        for variant in VARIANTS:
            pt = decrypt_with_alphabet(CT, key_t, variant, T_ALPH, ALPH)
            sc = score_cribs(pt)
            label = f"T-mixed_{kw_name}_{variant}"
            tracker.record(sc, label, "P1c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

    # Phase 1d: All rotations of each keyword (period alignment search)
    print(f"\n  --- Phase 1d: Keyword rotations with T-alphabet keys ---")
    for kw_name, kw_str in KEYWORDS.items():
        key_t = keyword_t_vals(kw_str)
        klen = len(key_t)
        for rot in range(klen):
            rotated_key = key_t[rot:] + key_t[:rot]
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, rotated_key, variant)
                sc = score_cribs(pt)
                label = f"T-rot{rot}_{kw_name}_{variant}"
                tracker.record(sc, label, "P1d", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     Key: {rotated_key}")
                    print(f"     PT: {pt[:50]}")

    print(f"\n  Phase 1 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2: T-alphabet for grid coordinates
# ══════════════════════════════════════════════════════════════════════════════

def phase2_t_grid():
    """T-alphabet column ordering for columnar transposition."""
    print("\n" + "=" * 78)
    print("  PHASE 2: T-ALPHABET FOR GRID COORDINATES")
    print("=" * 78)

    configs = 0

    # Show column ordering comparison for KRYPTOS (width 7)
    print(f"\n  Column ordering comparison for KRYPTOS (width 7):")
    kw = "KRYPTOS"

    order_std = keyword_to_col_order(kw, ALPH_IDX)
    order_t = keyword_to_col_order(kw, T_IDX)

    print(f"    Letter:       {'  '.join(kw)}")
    print(f"    Std values:   {'  '.join(f'{ALPH_IDX[c]:2d}' for c in kw)}")
    print(f"    T-values:     {'  '.join(f'{T_IDX[c]:2d}' for c in kw)}")
    print(f"    Std col order: {order_std}")
    print(f"    T col order:   {order_t}")
    print(f"    Are they different? {order_std != order_t}")

    if order_std != order_t:
        print(f"    *** DIFFERENT ORDERINGS! This could matter. ***")

    # Phase 2a: Width-7 columnar KRYPTOS with both orderings + Vig/Beau/VarBeau
    print(f"\n  --- Phase 2a: Width-7 KRYPTOS columnar (T-order vs Std-order) ---")
    for order_name, col_order in [("T-order", order_t), ("Std-order", order_std)]:
        try:
            perm = columnar_perm(7, col_order, CT_LEN)
            inv = invert_perm(perm)

            # Gather direction (undo encryption)
            ct_dec = apply_perm(CT, inv)
            sc = score_cribs(ct_dec)
            label = f"col_w7_{order_name}_scatter"
            tracker.record(sc, label, "P2a", ct_dec)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {ct_dec[:50]}")

            # Also gather direction
            ct_gath = apply_perm(CT, perm)
            sc_g = score_cribs(ct_gath)
            label_g = f"col_w7_{order_name}_gather"
            tracker.record(sc_g, label_g, "P2a", ct_gath)
            configs += 1
            if sc_g > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label_g} -> {sc_g}/24")

            # Combined with substitution
            for sub_text, sub_name in [(ct_dec, "scatter"), (ct_gath, "gather")]:
                for kw_name, kw_str in KEYWORDS.items():
                    key_t = keyword_t_vals(kw_str)
                    key_s = keyword_std_vals(kw_str)
                    for key_label, key_vals in [("Tkey", key_t), ("Skey", key_s)]:
                        for variant in VARIANTS:
                            pt = decrypt_with_key(sub_text, key_vals, variant)
                            sc2 = score_cribs(pt)
                            label2 = f"col_w7_{order_name}_{sub_name}+{kw_name}_{key_label}_{variant}"
                            tracker.record(sc2, label2, "P2a", pt)
                            configs += 1
                            if sc2 > NOISE_FLOOR:
                                print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")
                                print(f"     PT: {pt[:50]}")
        except Exception as e:
            print(f"  Error: {e}")

    # Phase 2b: Test all keywords as columnar keywords, comparing T vs standard ordering
    print(f"\n  --- Phase 2b: Multiple keywords as columnar keywords ---")
    for kw_name, kw_str in KEYWORDS.items():
        w = len(kw_str)
        if w < 3 or w > 15:
            continue

        order_std_kw = keyword_to_col_order(kw_str, ALPH_IDX)
        order_t_kw = keyword_to_col_order(kw_str, T_IDX)

        if order_std_kw == order_t_kw:
            print(f"  {kw_name} (width {w}): T-order == Std-order, skipping duplicate")
            # Still test one version
            try:
                perm = columnar_perm(w, order_t_kw, CT_LEN)
                inv = invert_perm(perm)
                ct_dec = apply_perm(CT, inv)
                sc = score_cribs(ct_dec)
                label = f"col_w{w}_{kw_name}_scatter"
                tracker.record(sc, label, "P2b", ct_dec)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
            except Exception:
                pass
            continue

        print(f"  {kw_name} (width {w}): T-order={order_t_kw} vs Std-order={order_std_kw} ***DIFFERENT***")

        for order_name, col_order in [("T-order", order_t_kw), ("Std-order", order_std_kw)]:
            try:
                perm = columnar_perm(w, col_order, CT_LEN)
                inv = invert_perm(perm)
                ct_dec = apply_perm(CT, inv)
                sc = score_cribs(ct_dec)
                label = f"col_w{w}_{kw_name}_{order_name}_scatter"
                tracker.record(sc, label, "P2b", ct_dec)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

                ct_gath = apply_perm(CT, perm)
                sc_g = score_cribs(ct_gath)
                label_g = f"col_w{w}_{kw_name}_{order_name}_gather"
                tracker.record(sc_g, label_g, "P2b", ct_gath)
                configs += 1
                if sc_g > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label_g} -> {sc_g}/24")

                # With KRYPTOS T-key substitution
                key_t = keyword_t_vals("KRYPTOS")
                for variant in ["vig", "beau"]:
                    pt = decrypt_with_key(ct_dec, key_t, variant)
                    sc2 = score_cribs(pt)
                    label2 = f"col_w{w}_{kw_name}_{order_name}+KRYPTOS_T_{variant}"
                    tracker.record(sc2, label2, "P2b", pt)
                    configs += 1
                    if sc2 > NOISE_FLOOR:
                        print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")
            except Exception as e:
                print(f"  Error with {kw_name} {order_name}: {e}")

    print(f"\n  Phase 2 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3: T-alphabet position-dependent key
# ══════════════════════════════════════════════════════════════════════════════

def phase3_t_position_key():
    """Use T-position values of CT characters as a running key."""
    print("\n" + "=" * 78)
    print("  PHASE 3: T-ALPHABET POSITION-DEPENDENT KEY")
    print("=" * 78)

    configs = 0

    # Phase 3a: key[i] = T_pos(CT[i]) — CT self-referencing
    print(f"\n  --- Phase 3a: key[i] = T_pos(CT[i]) ---")
    t_key_from_ct = [T_IDX[c] for c in CT]
    print(f"  First 20 CT chars:    {CT[:20]}")
    print(f"  T-positions:          {t_key_from_ct[:20]}")

    for variant in VARIANTS:
        pt = decrypt_with_key(CT, t_key_from_ct, variant)
        sc = score_cribs(pt)
        label = f"T-pos_CT_self_{variant}"
        tracker.record(sc, label, "P3a", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
            print(f"     PT: {pt[:60]}")
        else:
            print(f"  {label}: {sc}/24")

    # Phase 3b: key[i] = T_pos(ALPH[i mod 26]) — cycling T-alphabet
    print(f"\n  --- Phase 3b: key[i] = T_pos(ALPH[i mod 26]) = cycling 0..25 shifted ---")
    cycling_key = [T_IDX[ALPH[i % 26]] for i in range(CT_LEN)]
    print(f"  First 30 key values: {cycling_key[:30]}")
    # This is just [(i * 7) % 26 ... hmm no. T_IDX['A']=7, T_IDX['B']=8, ..., T_IDX['Z']=6
    # So cycling_key = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 1, 2, 3, 4, 5, 6, 7, 8, ...]
    # = [(i + 7) % 26 for i in range(CT_LEN)]

    for variant in VARIANTS:
        pt = decrypt_with_key(CT, cycling_key, variant)
        sc = score_cribs(pt)
        label = f"T-pos_cycling_ALPH_{variant}"
        tracker.record(sc, label, "P3b", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
            print(f"     PT: {pt[:60]}")
        else:
            print(f"  {label}: {sc}/24")

    # Phase 3c: key[i] = T_pos(T_ALPH[i mod 26]) — cycling from T perspective
    print(f"\n  --- Phase 3c: key[i] = T_pos(T_ALPH[i mod 26]) = [0,1,2,...25,0,1,...] ---")
    cycling_key_t = [i % 26 for i in range(CT_LEN)]
    # This is just identity — 0,1,2,...,25,0,1,...
    for variant in VARIANTS:
        pt = decrypt_with_key(CT, cycling_key_t, variant)
        sc = score_cribs(pt)
        label = f"T-pos_cycling_TALPH_{variant}"
        tracker.record(sc, label, "P3c", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
        else:
            print(f"  {label}: {sc}/24")

    # Phase 3d: key[i] = standard_pos(CT[i]) for comparison
    print(f"\n  --- Phase 3d: key[i] = Std_pos(CT[i]) (comparison baseline) ---")
    std_key_from_ct = [ALPH_IDX[c] for c in CT]
    for variant in VARIANTS:
        pt = decrypt_with_key(CT, std_key_from_ct, variant)
        sc = score_cribs(pt)
        label = f"Std-pos_CT_self_{variant}"
        tracker.record(sc, label, "P3d", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
        else:
            print(f"  {label}: {sc}/24")

    # Phase 3e: 1-indexed T-alphabet: T=1, U=2, ..., S=26
    # key[i] = (T_IDX[CT[i]] + 1) — so T=1 not T=0
    print(f"\n  --- Phase 3e: 1-indexed T-pos: T=1, U=2, ..., S=26 (mod 26) ---")
    t_key_1idx = [(T_IDX[c] + 1) % 26 for c in CT]
    print(f"  First 20 values: {t_key_1idx[:20]}")
    for variant in VARIANTS:
        pt = decrypt_with_key(CT, t_key_1idx, variant)
        sc = score_cribs(pt)
        label = f"T-pos1idx_CT_self_{variant}"
        tracker.record(sc, label, "P3e", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
        else:
            print(f"  {label}: {sc}/24")

    # Phase 3f: Autokey with T-alphabet seed from KRYPTOS
    print(f"\n  --- Phase 3f: Autokey (PT-feedback) with T-alphabet KRYPTOS seed ---")
    kryptos_t = keyword_t_vals("KRYPTOS")
    for variant in VARIANTS:
        # PT-feedback autokey
        slen = len(kryptos_t)
        pt_chars = []
        for i, c in enumerate(CT):
            cv = c2n(c)
            if i < slen:
                kv = kryptos_t[i] % MOD
            else:
                kv = c2n(pt_chars[i - slen])
            if variant == "vig":
                pv = (cv - kv) % MOD
            elif variant == "beau":
                pv = (kv - cv) % MOD
            else:  # varbeau
                pv = (cv + kv) % MOD
            pt_chars.append(n2c(pv))
        pt = "".join(pt_chars)
        sc = score_cribs(pt)
        label = f"autokey_PT_KRYPTOS_T_{variant}"
        tracker.record(sc, label, "P3f", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
            print(f"     PT: {pt[:60]}")

        # CT-feedback autokey
        pt_chars2 = []
        for i, c in enumerate(CT):
            cv = c2n(c)
            if i < slen:
                kv = kryptos_t[i] % MOD
            else:
                kv = c2n(CT[i - slen])
            if variant == "vig":
                pv = (cv - kv) % MOD
            elif variant == "beau":
                pv = (kv - cv) % MOD
            else:
                pv = (cv + kv) % MOD
            pt_chars2.append(n2c(pv))
        pt2 = "".join(pt_chars2)
        sc2 = score_cribs(pt2)
        label2 = f"autokey_CT_KRYPTOS_T_{variant}"
        tracker.record(sc2, label2, "P3f", pt2)
        configs += 1
        if sc2 > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")

    print(f"\n  Phase 3 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 4: T-alphabet + grid widths
# ══════════════════════════════════════════════════════════════════════════════

def phase4_t_grid_widths():
    """Columnar transposition at widths 5-14 with T-alphabet keyword orderings."""
    print("\n" + "=" * 78)
    print("  PHASE 4: T-ALPHABET + GRID WIDTHS (5-14)")
    print("=" * 78)

    configs = 0

    col_keywords = {
        "KRYPTOS":    "KRYPTOS",      # w=7
        "PALIMPSEST": "PALIMPSEST",   # w=10
        "ABSCISSA":   "ABSCISSA",     # w=8
    }

    for width in range(5, 15):
        above_noise_this_width = 0
        print(f"\n  --- Width {width} ---")

        for kw_name, kw_str in col_keywords.items():
            if len(kw_str) != width:
                # Truncate or skip
                if len(kw_str) < width:
                    continue
                kw_use = kw_str[:width]
                kw_label = f"{kw_name}[:{width}]"
            else:
                kw_use = kw_str
                kw_label = kw_name

            order_std = keyword_to_col_order(kw_use, ALPH_IDX)
            order_t = keyword_to_col_order(kw_use, T_IDX)

            orders_to_test = [("T-order", order_t)]
            if order_std != order_t:
                orders_to_test.append(("Std-order", order_std))

            for order_name, col_order in orders_to_test:
                try:
                    perm = columnar_perm(width, col_order, CT_LEN)
                    inv = invert_perm(perm)
                    ct_dec = apply_perm(CT, inv)

                    # Raw transposition score
                    sc = score_cribs(ct_dec)
                    label = f"col_w{width}_{kw_label}_{order_name}_raw"
                    tracker.record(sc, label, "P4", ct_dec)
                    configs += 1
                    if sc > NOISE_FLOOR:
                        above_noise_this_width += 1
                        print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

                    # With Vig/Beau decryption using various keys
                    for sub_kw_name, sub_kw_str in [("KRYPTOS", "KRYPTOS")]:
                        key_t = keyword_t_vals(sub_kw_str)
                        key_s = keyword_std_vals(sub_kw_str)

                        for key_label, key_vals in [("Tkey", key_t), ("Skey", key_s)]:
                            for variant in ["vig", "beau"]:
                                pt = decrypt_with_key(ct_dec, key_vals, variant)
                                sc2 = score_cribs(pt)
                                label2 = f"col_w{width}_{kw_label}_{order_name}+{sub_kw_name}_{key_label}_{variant}"
                                tracker.record(sc2, label2, "P4", pt)
                                configs += 1
                                if sc2 > NOISE_FLOOR:
                                    above_noise_this_width += 1
                                    print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")

                    # Also try gather direction
                    ct_gath = apply_perm(CT, perm)
                    sc_g = score_cribs(ct_gath)
                    tracker.record(sc_g, f"col_w{width}_{kw_label}_{order_name}_gather_raw", "P4", ct_gath)
                    configs += 1
                    if sc_g > NOISE_FLOOR:
                        above_noise_this_width += 1

                    for variant in ["vig", "beau"]:
                        key_t = keyword_t_vals("KRYPTOS")
                        pt = decrypt_with_key(ct_gath, key_t, variant)
                        sc3 = score_cribs(pt)
                        tracker.record(sc3, f"col_w{width}_{kw_label}_{order_name}_gather+KRYPTOS_T_{variant}", "P4", pt)
                        configs += 1
                        if sc3 > NOISE_FLOOR:
                            above_noise_this_width += 1

                except Exception:
                    pass

        # Also test identity and reverse column orders for each width
        for order_name, col_order in [("identity", list(range(width))),
                                       ("reverse", list(range(width - 1, -1, -1)))]:
            try:
                perm = columnar_perm(width, col_order, CT_LEN)
                inv = invert_perm(perm)
                ct_dec = apply_perm(CT, inv)
                for key_label, key_vals in [("KRYPTOS_T", keyword_t_vals("KRYPTOS"))]:
                    for variant in ["vig", "beau"]:
                        pt = decrypt_with_key(ct_dec, key_vals, variant)
                        sc = score_cribs(pt)
                        tracker.record(sc, f"col_w{width}_{order_name}+{key_label}_{variant}", "P4", pt)
                        configs += 1
                        if sc > NOISE_FLOOR:
                            above_noise_this_width += 1
                            print(f"  ** ABOVE NOISE: col_w{width}_{order_name}+{key_label}_{variant} -> {sc}/24")
            except Exception:
                pass

        if above_noise_this_width == 0:
            print(f"  Width {width}: all noise")

    print(f"\n  Phase 4 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 5: T-alphabet + misspelling shifts
# ══════════════════════════════════════════════════════════════════════════════

def phase5_t_misspelling():
    """T-alphabet values of misspelling letters as cipher key."""
    print("\n" + "=" * 78)
    print("  PHASE 5: T-ALPHABET + MISSPELLING SHIFTS")
    print("=" * 78)

    configs = 0

    # Misspelling pairs from sculpture:
    # S->C (PALIMPCEST), L->Q (IQLUSION), E->A (DESPARATLY), I->E (DIGETAL)
    # Note: UNDERGRUUND may not be deliberate (corrected on Antipodes)
    misspelling_letters = {
        "wrong":   "SQAI",   # wrong letters as they appear
        "correct": "SLEA",   # correct letters they should be (wait: S->C means S is wrong?)
    }
    # Actually: PALIMPSEST->PALIMPCEST: S replaced by C (wrong=C, correct=S)
    # ILLUSION->IQLUSION: L replaced by Q (wrong=Q, correct=L)
    # DESPERATELY->DESPARATLY: E replaced by A (wrong=A, correct=E)
    # DIGITAL->DIGETAL: I replaced by E (wrong=E, correct=I)
    wrong_letters = "CQAE"    # C, Q, A, E
    correct_letters = "SLEI"  # S, L, E, I

    print(f"\n  Misspelling analysis:")
    print(f"    Wrong letters:   {wrong_letters}")
    print(f"    Correct letters: {correct_letters}")
    print()

    # Standard values
    wrong_std = [ALPH_IDX[c] for c in wrong_letters]
    correct_std = [ALPH_IDX[c] for c in correct_letters]
    print(f"    Wrong std values:   {wrong_std}  ({list(wrong_letters)})")
    print(f"    Correct std values: {correct_std}  ({list(correct_letters)})")
    print(f"    Std shifts (W-C):   {[(w - c) % 26 for w, c in zip(wrong_std, correct_std)]}")

    # T-alphabet values
    wrong_t = [T_IDX[c] for c in wrong_letters]
    correct_t = [T_IDX[c] for c in correct_letters]
    print(f"\n    Wrong T values:     {wrong_t}  ({list(wrong_letters)})")
    print(f"    Correct T values:   {correct_t}  ({list(correct_letters)})")
    print(f"    T shifts (W-C):     {[(w - c) % 26 for w, c in zip(wrong_t, correct_t)]}")
    print(f"    NOTE: Shifts are the same (differences are rotation-invariant)")

    # Phase 5a: Use T-values of wrong letters as period-4 key
    print(f"\n  --- Phase 5a: T-values of wrong letters [{wrong_t}] as period-4 key ---")
    for key_label, key_vals in [("wrong_T", wrong_t), ("correct_T", correct_t),
                                 ("wrong_std", wrong_std), ("correct_std", correct_std)]:
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key_vals, variant)
            sc = score_cribs(pt)
            label = f"missp_{key_label}_{variant}"
            tracker.record(sc, label, "P5a", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     Key: {key_vals}, PT: {pt[:50]}")

    # Phase 5b: All permutations of misspelling T-values
    print(f"\n  --- Phase 5b: All permutations of wrong_T and correct_T ---")
    for base_name, base_key in [("wrong_T", wrong_t), ("correct_T", correct_t)]:
        seen = set()
        above = 0
        for perm in permutations(base_key):
            key = list(perm)
            kt = tuple(key)
            if kt in seen:
                continue
            seen.add(kt)
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, key, variant)
                sc = score_cribs(pt)
                label = f"missp_{base_name}_perm_{variant}"
                tracker.record(sc, label, "P5b", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    above += 1
                    if above <= 3:
                        print(f"  ** ABOVE NOISE: {base_name} perm {key} {variant} -> {sc}/24")
        if above > 3:
            print(f"  ... {above} total above noise for {base_name}")

    # Phase 5c: Combined misspelling T-values as extended keys
    print(f"\n  --- Phase 5c: Combined misspelling key sets ---")
    # All 8 values combined: [wrong_T + correct_T] = period 8
    combined_8 = wrong_t + correct_t
    print(f"  Combined 8 values: {combined_8}")
    for variant in VARIANTS:
        pt = decrypt_with_key(CT, combined_8, variant)
        sc = score_cribs(pt)
        label = f"missp_combined8_{variant}"
        tracker.record(sc, label, "P5c", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # Reversed
    combined_8r = correct_t + wrong_t
    for variant in VARIANTS:
        pt = decrypt_with_key(CT, combined_8r, variant)
        sc = score_cribs(pt)
        label = f"missp_combined8r_{variant}"
        tracker.record(sc, label, "P5c", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # Phase 5d: Misspelling T-values + KRYPTOS T-key combined
    print(f"\n  --- Phase 5d: Misspelling + KRYPTOS combined keys ---")
    kryptos_t = keyword_t_vals("KRYPTOS")
    # Interleave: K, wrong[0], R, wrong[1], Y, wrong[2], P, wrong[3], T, O, S
    # Or concatenate: KRYPTOS + wrong_T = period 11
    concat_11 = kryptos_t + wrong_t
    print(f"  KRYPTOS_T + wrong_T = {concat_11} (period 11)")
    for variant in VARIANTS:
        pt = decrypt_with_key(CT, concat_11, variant)
        sc = score_cribs(pt)
        label = f"missp_KRYPTOS_T+wrong_T_{variant}"
        tracker.record(sc, label, "P5d", pt)
        configs += 1
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

    # Element-wise operations with KRYPTOS (need same length = 7)
    # Pad misspelling to 7: wrong_T + wrong_T[:3] = [9, 24, 8, 12, 9, 24, 8]
    wrong_t_7 = (wrong_t * 3)[:7]
    correct_t_7 = (correct_t * 3)[:7]
    for missp_name, missp_key in [("wrong_T_7", wrong_t_7), ("correct_T_7", correct_t_7)]:
        key_sum = [(a + b) % MOD for a, b in zip(kryptos_t, missp_key)]
        key_diff = [(a - b) % MOD for a, b in zip(kryptos_t, missp_key)]
        key_diff2 = [(b - a) % MOD for a, b in zip(kryptos_t, missp_key)]
        for op_name, op_key in [("SUM", key_sum), ("DIFF", key_diff), ("DIFF2", key_diff2)]:
            for variant in VARIANTS:
                pt = decrypt_with_key(CT, op_key, variant)
                sc = score_cribs(pt)
                label = f"KRYPTOS_T_{op_name}_{missp_name}_{variant}"
                tracker.record(sc, label, "P5d", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     Key: {op_key}")

    # Phase 5e: The user's specific suggestion — E,Q,U,A,L T-values as key
    print(f"\n  --- Phase 5e: EQUAL letters T-values as key ---")
    equal_letters_t = [T_IDX[c] for c in "EQUAL"]   # E=12, Q=24, U=2, A=8, L=19
    equal_letters_s = [ALPH_IDX[c] for c in "EQUAL"]  # E=4, Q=16, U=20, A=0, L=11
    print(f"  EQUAL T-values: {equal_letters_t}")
    print(f"  EQUAL std values: {equal_letters_s}")

    for key_label, key_vals in [("EQUAL_T", equal_letters_t), ("EQUAL_std", equal_letters_s)]:
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key_vals, variant)
            sc = score_cribs(pt)
            label = f"{key_label}_{variant}"
            tracker.record(sc, label, "P5e", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     Key: {key_vals}, PT: {pt[:50]}")

    # All permutations of EQUAL_T
    seen_eq = set()
    eq_above = 0
    for perm in permutations(equal_letters_t):
        key = list(perm)
        kt = tuple(key)
        if kt in seen_eq:
            continue
        seen_eq.add(kt)
        for variant in VARIANTS:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            tracker.record(sc, f"EQUAL_T_perm_{variant}", "P5e", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                eq_above += 1
                if eq_above <= 3:
                    print(f"  ** ABOVE NOISE: EQUAL_T perm {key} {variant} -> {sc}/24")
    if eq_above > 3:
        print(f"  ... {eq_above} total above noise for EQUAL_T perms")

    print(f"\n  Phase 5 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 6: Rotated KA alphabet
# ══════════════════════════════════════════════════════════════════════════════

def phase6_rotated_ka():
    """KRYPTOS alphabet (KA) rotated to start at T."""
    print("\n" + "=" * 78)
    print("  PHASE 6: ROTATED KA ALPHABET (START AT T)")
    print("=" * 78)

    configs = 0

    # Find T in KA
    ka = KRYPTOS_ALPHABET
    t_pos_in_ka = ka.index('T')
    print(f"\n  KA alphabet:    {ka}")
    print(f"  T is at position {t_pos_in_ka} (0-indexed) in KA")

    # Rotate KA to start at T
    ka_from_t = ka[t_pos_in_ka:] + ka[:t_pos_in_ka]
    print(f"  KA from T:      {ka_from_t}")
    print(f"  Standard ALPH:  {ALPH}")

    # Build index for rotated KA
    ka_t_idx = {c: i for i, c in enumerate(ka_from_t)}

    # Phase 6a: Use rotated KA as substitution alphabet with various keywords
    print(f"\n  --- Phase 6a: Rotated KA as cipher alphabet ---")
    for kw_name, kw_str in KEYWORDS.items():
        # Key values from KA-from-T
        key_ka_t = [ka_t_idx[c] for c in kw_str]
        key_ka = [ka.index(c) for c in kw_str]  # original KA positions
        key_std = keyword_std_vals(kw_str)

        for key_label, key_vals in [("KA-T", key_ka_t), ("KA", key_ka), ("Std", key_std)]:
            for variant in VARIANTS:
                # Standard decrypt with the given key
                pt = decrypt_with_key(CT, key_vals, variant)
                sc = score_cribs(pt)
                label = f"KA-T_sub_{kw_name}_{key_label}_{variant}"
                tracker.record(sc, label, "P6a", pt)
                configs += 1
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                    print(f"     Key: {key_vals[:10]}..., PT: {pt[:50]}")

    # Phase 6b: Use rotated KA for both CT lookup and PT output
    print(f"\n  --- Phase 6b: Full rotated-KA tableau ---")
    for kw_name, kw_str in KEYWORDS.items():
        key_ka_t = [ka_t_idx[c] for c in kw_str]
        for variant in VARIANTS:
            # CT indexed by KA-from-T, PT output via KA-from-T
            pt = decrypt_with_alphabet(CT, key_ka_t, variant, ka_from_t, ka_from_t)
            sc = score_cribs(pt)
            label = f"KA-T_full_{kw_name}_{variant}"
            tracker.record(sc, label, "P6b", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     PT: {pt[:50]}")

            # CT indexed by original KA, PT output via original KA
            key_ka = [ka.index(c) for c in kw_str]
            pt2 = decrypt_with_alphabet(CT, key_ka, variant, ka, ka)
            sc2 = score_cribs(pt2)
            label2 = f"KA_full_{kw_name}_{variant}"
            tracker.record(sc2, label2, "P6b", pt2)
            configs += 1
            if sc2 > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")
                print(f"     PT: {pt2[:50]}")

    # Phase 6c: Mixed KA modes
    print(f"\n  --- Phase 6c: Mixed KA modes (CT=KA-T, PT=std or CT=std, PT=KA-T) ---")
    for kw_name in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        kw_str = KEYWORDS[kw_name]
        key_ka_t = [ka_t_idx[c] for c in kw_str]
        key_std = keyword_std_vals(kw_str)

        for variant in VARIANTS:
            # CT in KA-T space, PT in standard
            pt = decrypt_with_alphabet(CT, key_ka_t, variant, ka_from_t, ALPH)
            sc = score_cribs(pt)
            label = f"KA-T_ct_std_pt_{kw_name}_{variant}"
            tracker.record(sc, label, "P6c", pt)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

            # CT in standard, PT in KA-T space
            pt2 = decrypt_with_alphabet(CT, key_ka_t, variant, ALPH, ka_from_t)
            sc2 = score_cribs(pt2)
            label2 = f"std_ct_KA-T_pt_{kw_name}_{variant}"
            tracker.record(sc2, label2, "P6c", pt2)
            configs += 1
            if sc2 > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")

            # CT in original KA, PT in standard
            key_ka = [ka.index(c) for c in kw_str]
            pt3 = decrypt_with_alphabet(CT, key_ka, variant, ka, ALPH)
            sc3 = score_cribs(pt3)
            label3 = f"KA_ct_std_pt_{kw_name}_{variant}"
            tracker.record(sc3, label3, "P6c", pt3)
            configs += 1
            if sc3 > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label3} -> {sc3}/24")

    # Phase 6d: Rotated KA + columnar transposition
    print(f"\n  --- Phase 6d: Rotated KA column ordering + substitution ---")
    kw = "KRYPTOS"
    order_ka_t = keyword_to_col_order(kw, ka_t_idx)
    order_ka = keyword_to_col_order(kw, {c: i for i, c in enumerate(ka)})
    order_std = keyword_to_col_order(kw, ALPH_IDX)

    print(f"  KRYPTOS column orders:")
    print(f"    KA-T order: {order_ka_t}")
    print(f"    KA order:   {order_ka}")
    print(f"    Std order:  {order_std}")

    unique_orders = set()
    for order_name, col_order in [("KA-T", order_ka_t), ("KA", order_ka), ("Std", order_std)]:
        order_t = tuple(col_order)
        if order_t in unique_orders:
            print(f"  {order_name}: duplicate of earlier order, skipping")
            continue
        unique_orders.add(order_t)

        try:
            perm = columnar_perm(7, col_order, CT_LEN)
            inv = invert_perm(perm)
            ct_dec = apply_perm(CT, inv)

            sc = score_cribs(ct_dec)
            label = f"col_w7_{order_name}_KA_raw"
            tracker.record(sc, label, "P6d", ct_dec)
            configs += 1
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")

            # With substitution
            for key_label, key_vals in [("KRYPTOS_T", keyword_t_vals("KRYPTOS")),
                                         ("KRYPTOS_KA-T", [ka_t_idx[c] for c in "KRYPTOS"]),
                                         ("KRYPTOS_std", keyword_std_vals("KRYPTOS"))]:
                for variant in ["vig", "beau", "varbeau"]:
                    pt = decrypt_with_key(ct_dec, key_vals, variant)
                    sc2 = score_cribs(pt)
                    label2 = f"col_w7_{order_name}+{key_label}_{variant}"
                    tracker.record(sc2, label2, "P6d", pt)
                    configs += 1
                    if sc2 > NOISE_FLOOR:
                        print(f"  ** ABOVE NOISE: {label2} -> {sc2}/24")
                        print(f"     PT: {pt[:50]}")
        except Exception as e:
            print(f"  Error: {e}")

    # Phase 6e: All rotations of KA (not just from T)
    print(f"\n  --- Phase 6e: All 26 rotations of KA as cipher alphabet ---")
    best_rot_score = 0
    for rot_offset in range(26):
        ka_rot = ka[rot_offset:] + ka[:rot_offset]
        ka_rot_idx = {c: i for i, c in enumerate(ka_rot)}
        key_kr = [ka_rot_idx[c] for c in "KRYPTOS"]

        for variant in ["vig", "beau"]:
            pt = decrypt_with_key(CT, key_kr, variant)
            sc = score_cribs(pt)
            label = f"KA_rot{rot_offset}({ka_rot[0]})_KRYPTOS_{variant}"
            tracker.record(sc, label, "P6e", pt)
            configs += 1
            if sc > best_rot_score:
                best_rot_score = sc
            if sc > NOISE_FLOOR:
                print(f"  ** ABOVE NOISE: {label} -> {sc}/24")
                print(f"     KA starts with: {ka_rot[:10]}...")

    print(f"  Best across all 26 KA rotations: {best_rot_score}/24")

    print(f"\n  Phase 6 total: {configs} configs, best: {tracker.best_score}/24")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()

    print("=" * 78)
    print("  E-BESPOKE-08: T-FIRST ALPHABET HYPOTHESIS")
    print("  'T IS YOUR POSITION' = cipher alphabet starts at T, not A")
    print("=" * 78)
    print(f"  CT: {CT}")
    print(f"  CT length: {CT_LEN}")
    print(f"  Cribs (0-indexed): {CRIB_WORDS}")
    print(f"\n  T-alphabet:  {T_ALPH}")
    print(f"  Standard:    {ALPH}")
    print(f"\n  Key derivation comparison:")
    print(f"  {'Letter':>8s}  {'Std':>4s}  {'T-alph':>6s}")
    print(f"  {'------':>8s}  {'---':>4s}  {'------':>6s}")
    for c in "KRYPTOSPALIMPSESTABSCISSA":
        if c not in "KRYPTOS" and c not in "PALIMPSEST" and c not in "ABSCISSA":
            continue
        print(f"  {c:>8s}  {ALPH_IDX[c]:>4d}  {T_IDX[c]:>6d}")

    print(f"\n  KRYPTOS key comparison:")
    print(f"    Standard: {keyword_std_vals('KRYPTOS')}")
    print(f"    T-alph:   {keyword_t_vals('KRYPTOS')}")

    print(f"\n  Column ordering comparison for KRYPTOS:")
    std_order = keyword_to_col_order("KRYPTOS", ALPH_IDX)
    t_order = keyword_to_col_order("KRYPTOS", T_IDX)
    print(f"    Standard order: {std_order}")
    print(f"    T-alph order:   {t_order}")
    print(f"    Different? {std_order != t_order}")

    c1 = phase1_t_tableau()
    c2 = phase2_t_grid()
    c3 = phase3_t_position_key()
    c4 = phase4_t_grid_widths()
    c5 = phase5_t_misspelling()
    c6 = phase6_rotated_ka()

    # ── Final Summary ──
    elapsed = time.time() - t0

    print("\n" + "#" * 78)
    print("  FINAL SUMMARY -- E-BESPOKE-08: T-FIRST ALPHABET HYPOTHESIS")
    print("#" * 78)

    tracker.print_top(15)

    total = tracker.total_configs
    print(f"\n  Phase breakdown:")
    print(f"    Phase 1 (T-alphabet tableau):         {c1:>8d} configs")
    print(f"    Phase 2 (T-alphabet grid coords):     {c2:>8d} configs")
    print(f"    Phase 3 (T-alphabet position key):    {c3:>8d} configs")
    print(f"    Phase 4 (T-alphabet + grid widths):   {c4:>8d} configs")
    print(f"    Phase 5 (T-alphabet + misspellings):  {c5:>8d} configs")
    print(f"    Phase 6 (Rotated KA alphabet):        {c6:>8d} configs")
    print(f"    TOTAL:                                {total:>8d} configs")

    print(f"\n  Elapsed time: {elapsed:.1f}s")

    best = tracker.best_score
    if best <= NOISE_FLOOR:
        print(f"\n  VERDICT: ALL RESULTS AT OR BELOW NOISE FLOOR ({NOISE_FLOOR}/24).")
        print(f"  The T-first alphabet hypothesis does NOT produce meaningful crib matches.")
        print(f"  'T IS YOUR POSITION' does not appear to mean T=position 1 for key derivation.")
    elif best < 10:
        print(f"\n  VERDICT: Best score {best}/24 -- borderline, likely noise.")
    elif best < 18:
        print(f"\n  VERDICT: Best score {best}/24 -- check period for false positive risk.")
        print(f"  At period <= 7, expected random is ~8.2/24.")
    else:
        print(f"\n  VERDICT: Best score {best}/24 -- INVESTIGATE IMMEDIATELY.")
        print(f"  Check period, run Bean constraints, verify manually.")

    print(f"\n  Done.")


if __name__ == "__main__":
    main()
