#!/usr/bin/env python3 -u
"""
Cipher: K-panel-as-running-key XOR (Cryptosclue / German Guesser replication)
Family: novel
Status: active
Keyspace: 2 encodings * 676 panel start positions * 2 OBKR-handling modes
Last run:
Best score:

Replicates the Cryptosclue ("German Guesser") hypothesis that K4 is decrypted by
XOR-ing the ciphertext against the KRYPTOS alphabet panel read as a long running
key, with the highest IoC occurring at "row M" of the panel.

Cryptosclue claims IoC ~= 0.06077 (with extra L), or ~= 0.04558 (without extra L)
on the 93-char post-OBKR remainder, starting at row M. Against an English IoC of
~0.0667 and random IoC of ~0.0385, the headline number is suggestive but the
selection (drop OBKR, pick row M, pick encoding) was made post-hoc.

This script:
  1) Reproduces the Cryptosclue arithmetic for ALL 676 panel starting positions,
     two encodings (A=0 standard, ITA-2 Baudot), and both OBKR-handling modes.
  2) Builds a proper null distribution by shuffling the K-panel rotations 1000
     times and re-running the same 676-position sweep.
  3) Reports the peak IoC, the peak starting position, the null mean/std/95/99,
     and the p-value of the peak vs the multiplicity-corrected null.

Predicted outcomes (locked here, NOT post-hoc):
  - The 0.06077 / 0.04558 numbers should be reproducible at SOME starting
    position with SOME encoding/OBKR-mode combination (arithmetic check).
  - Peak IoC across 676 positions will exceed the per-position null mean
    (max-of-N order statistic). This is expected and is NOT evidence.
  - After comparing the peak against the MAX-IoC null distribution from
    K-panel-shuffles, the predicted outcome is: peak falls within the null
    distribution and the Cryptosclue claim collapses to selection bias.
  - A surprise outcome (peak meaningfully outside the null) would warrant
    a proper red-team and statistical-auditor pass before any propagation.

All positions 0-indexed. Output: results/cryptosclue_replication_YYYYMMDD.json
"""

import sys
import os
import json
import datetime
import random
import statistics

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET

# ============================================================================
# CONSTANTS / ENCODINGS
# ============================================================================

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"

assert KA == "KRYPTOSABCDEFGHIJLMNQUVWXZ", f"KA changed: {KA!r}"
assert len(KA) == 26 and len(set(KA)) == 26

# Cryptosclue uses 5-bit ASCII. We support two encodings:
#   AZ:    A=0, B=1, ..., Z=25  (standard alphabet ordinal, 5-bit value)
#   ITA2:  Baudot/teletype 5-bit codes
AZ_ENC = {c: i for i, c in enumerate(ALPH)}
AZ_DEC = {v: c for c, v in AZ_ENC.items()}

ITA2_ENC = {
    'A': 0b00011, 'B': 0b11001, 'C': 0b01110, 'D': 0b01001,
    'E': 0b00001, 'F': 0b01101, 'G': 0b11010, 'H': 0b10100,
    'I': 0b00110, 'J': 0b01011, 'K': 0b01111, 'L': 0b10010,
    'M': 0b11100, 'N': 0b01100, 'O': 0b11000, 'P': 0b10110,
    'Q': 0b10111, 'R': 0b01010, 'S': 0b00101, 'T': 0b10000,
    'U': 0b00111, 'V': 0b11110, 'W': 0b10011, 'X': 0b11101,
    'Y': 0b10101, 'Z': 0b10001,
}
# ITA2 decode is partial (only values appearing in the table). For null-handling
# we substitute the key letter when XOR result is unreachable, matching
# Cryptosclue's "Rockex discriminator" note.
ITA2_DEC = {v: k for k, v in ITA2_ENC.items()}


def build_kpanel_flat():
    """K-panel as a flat 676-char string: 26 rows, each a left-rotation of KA.

    Row r starts at KA[r] and reads to the end then wraps. This matches the
    K1 / K2 Quagmire III convention used elsewhere in the kernel.
    """
    rows = []
    for r in range(26):
        rows.append(KA[r:] + KA[:r])
    return "".join(rows)


KPANEL_FLAT = build_kpanel_flat()
assert len(KPANEL_FLAT) == 676


# ============================================================================
# XOR DECRYPT
# ============================================================================

def xor_decrypt(ct, key, encoding):
    """5-bit XOR of CT and KEY using the given encoding.

    For each position i:
      v = enc[ct[i]] XOR enc[key[i]]
      if v in decode table -> emit decoded letter
      else -> emit key letter (Cryptosclue's discriminator rule)
    """
    enc, dec = encoding
    out = []
    for c, k in zip(ct, key):
        if c not in enc or k not in enc:
            out.append(k)
            continue
        v = enc[c] ^ enc[k]
        if v in dec:
            out.append(dec[v])
        else:
            out.append(k)
    return "".join(out)


def ioc(text):
    """Index of coincidence on alphabetic chars in text."""
    counts = {}
    for c in text:
        if c.isalpha():
            counts[c] = counts.get(c, 0) + 1
    n = sum(counts.values())
    if n < 2:
        return 0.0
    num = sum(v * (v - 1) for v in counts.values())
    den = n * (n - 1)
    return num / den


# ============================================================================
# SWEEP
# ============================================================================

def sweep_one_panel(panel_flat, ct, encodings, obkr_modes):
    """Sweep all 676 panel start positions x encodings x obkr modes.

    Returns list of dicts: {enc_name, obkr_mode, start_pos, ioc, pt_head}.
    """
    results = []
    for enc_name, enc_pair in encodings.items():
        for obkr_mode in obkr_modes:
            ct_use = ct if obkr_mode == "with_obkr" else ct[4:]
            n = len(ct_use)
            for start in range(len(panel_flat)):
                # Build key by reading panel from `start` with wraparound.
                if start + n <= len(panel_flat):
                    key = panel_flat[start:start + n]
                else:
                    key = (panel_flat[start:] + panel_flat[:(start + n) % len(panel_flat)])[:n]
                pt = xor_decrypt(ct_use, key, enc_pair)
                results.append({
                    "enc": enc_name,
                    "obkr_mode": obkr_mode,
                    "start_pos": start,
                    "ioc": ioc(pt),
                    "pt_head": pt[:20],
                })
    return results


def shuffled_panel(seed):
    """K-panel with the 26 rows randomly permuted."""
    rng = random.Random(seed)
    rows = [KA[r:] + KA[:r] for r in range(26)]
    rng.shuffle(rows)
    return "".join(rows)


# ============================================================================
# MAIN
# ============================================================================

def main():
    encodings = {"AZ": (AZ_ENC, AZ_DEC), "ITA2": (ITA2_ENC, ITA2_DEC)}
    obkr_modes = ["with_obkr", "without_obkr"]

    print("=" * 70)
    print("Cryptosclue K-panel XOR replication")
    print(f"CT len: {len(CT)}; KA: {KA}")
    print(f"Panel flat len: {len(KPANEL_FLAT)} (26 rows x 26 chars)")
    print("=" * 70)

    # ----- Tier 1: replicate Cryptosclue on the real K-panel -----
    print("\n[Tier 1] Real K-panel sweep across 676 start positions x 2 encodings x 2 OBKR modes")
    real_results = sweep_one_panel(KPANEL_FLAT, CT, encodings, obkr_modes)
    real_results.sort(key=lambda r: r["ioc"], reverse=True)

    top10 = real_results[:10]
    print("\nTop 10 (encoding, obkr_mode, start_pos, IoC, PT[:20]):")
    for r in top10:
        print(f"  {r['enc']:5s} {r['obkr_mode']:14s} start={r['start_pos']:3d}  ioc={r['ioc']:.5f}  {r['pt_head']}")

    peak = real_results[0]
    peak_per_combo = {}
    for r in real_results:
        key = (r["enc"], r["obkr_mode"])
        if key not in peak_per_combo or r["ioc"] > peak_per_combo[key]["ioc"]:
            peak_per_combo[key] = r

    print("\nPeak IoC per (encoding, obkr_mode):")
    for k, r in peak_per_combo.items():
        print(f"  {k[0]:5s} {k[1]:14s} start={r['start_pos']:3d}  ioc={r['ioc']:.5f}  {r['pt_head']}")

    # Sanity: did we reproduce Cryptosclue's ~0.06077 / ~0.04558?
    target_with = 0.06077  # claimed with extra L
    target_without = 0.04558  # claimed without extra L
    near_target = [r for r in real_results if abs(r["ioc"] - target_with) < 0.005 or abs(r["ioc"] - target_without) < 0.005]
    print(f"\nRows within +/-0.005 of Cryptosclue targets (0.06077 or 0.04558): {len(near_target)}")
    if near_target[:5]:
        for r in near_target[:5]:
            print(f"  {r['enc']:5s} {r['obkr_mode']:14s} start={r['start_pos']:3d}  ioc={r['ioc']:.5f}  {r['pt_head']}")

    # ----- Tier 2: null distribution via K-panel row shuffles -----
    print("\n[Tier 2] Null model: 1000 K-panel row-shuffles, max-IoC over each sweep")
    n_null = 1000
    null_max_iocs = []
    for trial in range(n_null):
        panel = shuffled_panel(seed=trial)
        trial_results = sweep_one_panel(panel, CT, encodings, obkr_modes)
        null_max_iocs.append(max(r["ioc"] for r in trial_results))
        if (trial + 1) % 100 == 0:
            print(f"  trial {trial + 1}/{n_null}  current max sample = {null_max_iocs[-1]:.5f}")

    null_max_iocs.sort()
    null_mean = statistics.mean(null_max_iocs)
    null_stdev = statistics.stdev(null_max_iocs)
    null_p95 = null_max_iocs[int(0.95 * n_null)]
    null_p99 = null_max_iocs[int(0.99 * n_null)]
    null_max = null_max_iocs[-1]

    real_peak = peak["ioc"]
    # p-value: fraction of null trials whose max-IoC >= real peak.
    p_value = sum(1 for v in null_max_iocs if v >= real_peak) / n_null

    print("\n[Null distribution of max-IoC across 676-position sweep]")
    print(f"  mean  = {null_mean:.5f}")
    print(f"  stdev = {null_stdev:.5f}")
    print(f"  p95   = {null_p95:.5f}")
    print(f"  p99   = {null_p99:.5f}")
    print(f"  max   = {null_max:.5f}")

    print(f"\n[Comparison]")
    print(f"  Real K-panel peak IoC:         {real_peak:.5f}  (at {peak['enc']} / {peak['obkr_mode']} / start={peak['start_pos']})")
    print(f"  Null max-IoC distribution p95: {null_p95:.5f}")
    print(f"  Null max-IoC distribution p99: {null_p99:.5f}")
    print(f"  p-value of real peak vs null:  {p_value:.4f}")

    if p_value < 0.01:
        verdict = "PEAK_OUTSIDE_NULL (p < 0.01) -- warrants red-team + statistical-auditor"
    elif p_value < 0.05:
        verdict = "PEAK_MARGINAL (0.01 <= p < 0.05) -- not actionable, document"
    else:
        verdict = "PEAK_WITHIN_NULL (p >= 0.05) -- Cryptosclue claim collapses to selection bias"
    print(f"\nVERDICT: {verdict}")

    # ----- Persist -----
    out = {
        "run_at": datetime.datetime.utcnow().isoformat() + "Z",
        "script": "scripts/novel/e_kpanel_xor_cryptosclue_replication.py",
        "ct": CT,
        "ct_len": len(CT),
        "ka": KA,
        "panel_flat_len": len(KPANEL_FLAT),
        "n_panel_starts": len(KPANEL_FLAT),
        "encodings": list(encodings.keys()),
        "obkr_modes": obkr_modes,
        "top10": top10,
        "peak_per_combo": {f"{k[0]}/{k[1]}": v for k, v in peak_per_combo.items()},
        "near_cryptosclue_targets": near_target[:20],
        "null": {
            "n_trials": n_null,
            "mean": null_mean,
            "stdev": null_stdev,
            "p95": null_p95,
            "p99": null_p99,
            "max": null_max,
        },
        "real_peak_ioc": real_peak,
        "p_value": p_value,
        "verdict": verdict,
    }
    today = datetime.datetime.utcnow().strftime("%Y%m%d")
    out_path = os.path.join(_ROOT, "results", f"cryptosclue_replication_{today}.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults written: {out_path}")


if __name__ == "__main__":
    main()
