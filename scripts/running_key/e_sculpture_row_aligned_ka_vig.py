#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: ~400K row pairings × 3 variants × 2 alphabets
Last run:
Best score:

E-SCULPTURE-ROW-ALIGNED: Row-aligned sculpture-as-key using KA Vigenère

HYPOTHESIS: Each row of K4 is decrypted using a physically corresponding row
from the cipher panel as the key, under KA Vigenère. Community member Kimmo
observed that OBKR (K4 row 0, 4 chars) decrypted with QRLG (end of panel
row 3) under KA Vigenère produces EACH — a real English word. This only works
with KA, not standard AZ.

WHAT'S NEW vs E-ANTIPODES-04: That test used sequential offsets with AZ
alphabet. This test uses:
  (a) KA Vigenère (essential — OBKR→EACH only works under KA)
  (b) Physical row alignment (each K4 row paired with a panel row)
  (c) All possible row pairings, not just sequential

K4 physical layout (width 31):
  Row 24: ...OBKR          (4 chars, cols 27-30)
  Row 25: UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO (31 chars)
  Row 26: TWTQSJQSSEKZZWATJKLUDIAWINFBNYP (31 chars)
  Row 27: VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR (31 chars)
"""

import json
import os
import sys
import time
from itertools import product

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT
from kryptos.kernel.scoring.crib_score import score_cribs

# Corpus policy declaration — this script uses the engraved K1-K4
# ciphertext panel (in physical row layout) as the running-key source
# for K4 decryption under KA Vigenere. Allowlisted as clue-surface under
# source_id `panel_ciphertext` (added 2026-04-08 as part of C7 review).
# See src/kryptos/admissibility/corpus_policy.py::DEFAULT_ALLOWLIST.
SOURCE_ID = "panel_ciphertext"

# ── Panel rows (from cylinder_viewer.js, ? marks removed) ──────────────

PANEL_ROWS_RAW = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # 0   K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",   # 1   K1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",   # 2   K1/K2
    "EGGWHKKDQMCPFQZDQMMIAGPFXHQRLG",    # 3   K2
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",    # 4   K2
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHR",    # 5   K2
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",    # 6   K2
    "IHHDDDUVHDWKBFUFPWNTDFIYCUQZER",     # 7   K2
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",    # 8   K2
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",    # 9   K2
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",    # 10  K2
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",    # 11  K2
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",    # 12  K2
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",    # 13  K2
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",    # 14  K3
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",    # 15  K3
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",     # 16  K3
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",     # 17  K3
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",    # 18  K3
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",     # 19  K3
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",     # 20  K3
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",    # 21  K3
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",     # 22  K3
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",    # 23  K3
    "ECDMRIPFEIMEHNLSSTTRTVDOHWOBKR",     # 24  K3/K4
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",    # 25  K4
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",    # 26  K4
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",   # 27  K4
]

# Alpha-only panel rows (remove any ? marks)
PANEL_ROWS = ["".join(c for c in row if c.isalpha()) for row in PANEL_ROWS_RAW]
N_ROWS = len(PANEL_ROWS)

# K4 rows as physically carved
K4_ROWS = [
    CT[0:4],    # OBKR (4 chars, end of row 24)
    CT[4:35],   # 31 chars (row 25)
    CT[35:66],  # 31 chars (row 26)
    CT[66:97],  # 31 chars (row 27)
]

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Pre-compute index tables
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(AZ)}


def decrypt_row(ct_row, key_text, idx_table, alph_str, variant):
    """Decrypt ct_row char-by-char using key_text (wraps if needed)."""
    pt = []
    klen = len(key_text)
    for i, c in enumerate(ct_row):
        ci = idx_table[c]
        ki = idx_table[key_text[i % klen]]
        if variant == 0:    # Vigenère
            pi = (ci - ki) % 26
        elif variant == 1:  # Beaufort
            pi = (ki - ci) % 26
        else:               # Variant Beaufort
            pi = (ci + ki) % 26
        pt.append(alph_str[pi])
    return "".join(pt)


def test_alignment(k4_keys, idx_table, alph_str, variant):
    """Decrypt full K4 and score."""
    parts = []
    for ct_row, key_text in zip(K4_ROWS, k4_keys):
        parts.append(decrypt_row(ct_row, key_text, idx_table, alph_str, variant))
    pt = "".join(parts)
    return pt, score_cribs(pt)


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-SCULPTURE-ROW-ALIGNED: Row-aligned sculpture key")
    print("=" * 70)

    # Verify Kimmo's claim
    print("\n--- Verify: OBKR + QRLG (KA Vig) = EACH ---")
    pt_check = decrypt_row("OBKR", "QRLG", KA_IDX, KA, 0)
    print(f"  Result: {pt_check}  (expected: EACH, match: {pt_check == 'EACH'})")

    best_score = 0
    best_result = None
    total_configs = 0
    above_noise = []
    VARIANT_NAMES = ["Vigenère", "Beaufort", "Var_Beaufort"]

    def record(sc, pt, alph_name, var_idx, strategy, key_rows, key_align="end"):
        nonlocal best_score, best_result, total_configs
        total_configs += 1
        if sc > best_score:
            best_score = sc
            best_result = {
                "alphabet": alph_name,
                "variant": VARIANT_NAMES[var_idx],
                "strategy": strategy,
                "key_rows": key_rows,
                "key_align": key_align,
                "crib_score": sc,
                "plaintext": pt,
            }
            if sc >= 6:
                print(f"  NEW BEST: {sc}/24 | {alph_name} {VARIANT_NAMES[var_idx]} | "
                      f"{strategy} rows={key_rows}")
                if sc >= 10:
                    print(f"    PT: {pt}")
        if sc >= 6:
            above_noise.append({
                "alphabet": alph_name, "variant": VARIANT_NAMES[var_idx],
                "strategy": strategy, "key_rows": key_rows, "score": sc,
            })

    configs_per_alph_var = {
        "KA": (KA_IDX, KA),
        "AZ": (AZ_IDX, AZ),
    }

    # ── Strategy 1: Sequential row pairing ─────────────────────────────
    print("\n--- Strategy 1: Sequential (K4 row i ↔ panel row start+i) ---")
    for alph_name, (idx_t, alph_s) in configs_per_alph_var.items():
        for v in range(3):
            for start in range(N_ROWS):
                keys = []
                for i in range(4):
                    r = (start + i) % N_ROWS
                    if i == 0:
                        keys.append(PANEL_ROWS[r][-4:])  # End-aligned for short row
                    else:
                        keys.append(PANEL_ROWS[r])
                pt, sc = test_alignment(keys, idx_t, alph_s, v)
                rows = [(start + i) % N_ROWS for i in range(4)]
                record(sc, pt, alph_name, v, "sequential", rows)

    # ── Strategy 2: Reverse sequential ──────────────────────────────────
    print("\n--- Strategy 2: Reverse sequential ---")
    for alph_name, (idx_t, alph_s) in configs_per_alph_var.items():
        for v in range(3):
            for start in range(N_ROWS):
                keys = []
                for i in range(4):
                    r = (start - i) % N_ROWS
                    if i == 0:
                        keys.append(PANEL_ROWS[r][-4:])
                    else:
                        keys.append(PANEL_ROWS[r])
                pt, sc = test_alignment(keys, idx_t, alph_s, v)
                rows = [(start - i) % N_ROWS for i in range(4)]
                record(sc, pt, alph_name, v, "reverse", rows)

    # ── Strategy 3: Mirror (K4 row i ↔ panel row N-1-i) ────────────────
    print("\n--- Strategy 3: Mirror pairing ---")
    for alph_name, (idx_t, alph_s) in configs_per_alph_var.items():
        for v in range(3):
            for offset in range(N_ROWS):
                keys = []
                for i in range(4):
                    r = (N_ROWS - 1 - i + offset) % N_ROWS
                    if i == 0:
                        keys.append(PANEL_ROWS[r][-4:])
                    else:
                        keys.append(PANEL_ROWS[r])
                pt, sc = test_alignment(keys, idx_t, alph_s, v)
                rows = [(N_ROWS - 1 - i + offset) % N_ROWS for i in range(4)]
                record(sc, pt, alph_name, v, "mirror", rows)

    # ── Strategy 4: Kimmo's QRLG for row 0, exhaustive for rows 1-3 ────
    # 28^3 × 3 × 2 = 131,712 configs
    print("\n--- Strategy 4: Kimmo (row 3 end for OBKR) + exhaustive rows 1-3 ---")
    key_row0 = PANEL_ROWS[3][-4:]  # QRLG
    for alph_name, (idx_t, alph_s) in configs_per_alph_var.items():
        for v in range(3):
            for r1, r2, r3 in product(range(N_ROWS), repeat=3):
                keys = [key_row0, PANEL_ROWS[r1], PANEL_ROWS[r2], PANEL_ROWS[r3]]
                pt, sc = test_alignment(keys, idx_t, alph_s, v)
                record(sc, pt, alph_name, v, "kimmo_row3", [3, r1, r2, r3])

    # ── Strategy 5: ALL panel rows for row 0 (end-aligned), exhaustive rows 1-3 ──
    # 28^4 × 3 × 2 = ~3.7M — but each test is fast (string ops only)
    print("\n--- Strategy 5: Full exhaustive (all row 0 sources × all rows 1-3) ---")
    checkpoint = time.time()
    for alph_name, (idx_t, alph_s) in configs_per_alph_var.items():
        for v in range(3):
            for r0 in range(N_ROWS):
                key_r0 = PANEL_ROWS[r0][-4:]
                for r1, r2, r3 in product(range(N_ROWS), repeat=3):
                    keys = [key_r0, PANEL_ROWS[r1], PANEL_ROWS[r2], PANEL_ROWS[r3]]
                    pt, sc = test_alignment(keys, idx_t, alph_s, v)
                    record(sc, pt, alph_name, v, "exhaustive", [r0, r1, r2, r3])

                if time.time() - checkpoint > 30:
                    print(f"  Progress: {alph_name} {VARIANT_NAMES[v]} r0={r0}/{N_ROWS} | "
                          f"configs={total_configs:,} | best={best_score}/24")
                    checkpoint = time.time()

    # ── Strategy 6: Start-aligned row 0 (first 4 chars instead of last 4) ──
    print("\n--- Strategy 6: Start-aligned row 0 + exhaustive ---")
    for alph_name, (idx_t, alph_s) in configs_per_alph_var.items():
        for v in range(3):
            for r0 in range(N_ROWS):
                key_r0 = PANEL_ROWS[r0][:4]  # FIRST 4 chars
                for r1, r2, r3 in product(range(N_ROWS), repeat=3):
                    keys = [key_r0, PANEL_ROWS[r1], PANEL_ROWS[r2], PANEL_ROWS[r3]]
                    pt, sc = test_alignment(keys, idx_t, alph_s, v)
                    record(sc, pt, alph_name, v, "start_aligned", [r0, r1, r2, r3])

    elapsed = time.time() - t0

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Best crib score: {best_score}/24")
    if best_result:
        for k, v in best_result.items():
            if k not in ("plaintext",):
                print(f"  {k}: {v}")
        if best_score >= 10:
            print(f"  Plaintext: {best_result['plaintext']}")
    print(f"Above-noise results (≥6): {len(above_noise)}")
    print(f"Elapsed: {elapsed:.1f}s")

    # Write results
    outdir = os.path.join(_ROOT, 'results', 'e_sculpture_row_aligned')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-SCULPTURE-ROW-ALIGNED",
        "hypothesis": "Row-aligned sculpture text as key under KA Vigenère (Kimmo hypothesis)",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_result": {k: v for k, v in best_result.items() if k != "plaintext"} if best_result else None,
        "above_noise_count": len(above_noise),
        "above_noise_top10": sorted(above_noise, key=lambda x: x["score"], reverse=True)[:10],
        "elapsed_seconds": elapsed,
        "verified_claim": f"OBKR + QRLG (KA Vig) = {pt_check}",
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)

    if best_score <= 6:
        print("\nCONCLUSION: NOISE — Row-aligned sculpture key hypothesis not supported.")
    elif best_score <= 9:
        print(f"\nCONCLUSION: NOISE ({best_score}/24) — above random floor but not significant.")
    else:
        print(f"\nCONCLUSION: Score {best_score}/24 — investigate further.")


if __name__ == "__main__":
    main()
