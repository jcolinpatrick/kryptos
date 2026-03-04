#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: grille
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRILLE-04: Period-targeted Vigenere/Beaufort attacks on YAR grille CT.

Statistical analysis found weak periodic signals at periods 5 and 7.
This script uses IC-based key recovery for those periods, plus exhaustive
per-stream shift optimization using quadgram scoring.

Attacks:
  1. IC-based key recovery: split CT into p streams, find optimal shift per stream
  2. Quadgram hill-climbing: optimize each stream position for best quadgram score
  3. Beaufort variant of both approaches
  4. Variant Beaufort of both approaches
  5. Specific contextual keys for periods 5 and 7
  6. All of the above in KA-space
  7. Extended periods: 2, 3, 4, 5, 6, 7, 8, 10, 13, 53 (factor pair of 106)

Run: PYTHONPATH=src python3 -u scripts/e_grille_04_period_attacks.py
"""

import json
import math
import itertools
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

YAR_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
YAR_LEN = len(YAR_CT)  # 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

# English letter frequencies (for IC-based scoring)
ENGLISH_FREQ = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
]

# Specific contextual keys to try
CONTEXT_KEYS_5 = [
    "CLOCK", "LIGHT", "SHADE", "NORTH", "MASKT", "YARCT", "CARDS",
    "CODES", "LAYER", "SPLIT", "CYANO", "CRYPT", "SOLVE", "GLEAM",
    "DEATH", "EARTH", "CAIRN", "VAULT", "GHOST", "WHEAT",
]
CONTEXT_KEYS_7 = [
    "KRYPTOS", "SANBORN", "SCHEIDT", "GRILLES", "MASKING", "BERLINS",
    "PALIMPS", "CARDANS", "SHADOWS", "SECRETS", "ANCIENT", "DECODER",
    "MISSING", "PYRAMID", "PHARAOH", "BENEATH", "THROUGH", "PASSAGE",
    "HISTORY", "ECTURE",
]

# ── Quadgram Loader ──────────────────────────────────────────────────────────

QUADGRAMS = {}
QUADGRAM_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QUADGRAM_FLOOR
    qpath = Path(__file__).resolve().parent.parent / "data" / "english_quadgrams.json"
    if not qpath.exists():
        print(f"[WARN] Quadgram file not found: {qpath}")
        return False
    with open(qpath) as f:
        raw = json.load(f)
    sample_val = next(iter(raw.values()))
    if sample_val < 0:
        QUADGRAMS.update(raw)
        QUADGRAM_FLOOR = min(raw.values()) - 1.0
    else:
        total = sum(raw.values())
        for k, v in raw.items():
            QUADGRAMS[k] = math.log10(v / total)
        QUADGRAM_FLOOR = math.log10(0.5 / total)
    print(f"[INFO] Loaded {len(QUADGRAMS)} quadgrams, floor={QUADGRAM_FLOOR:.4f}")
    return True

def quadgram_score(text: str) -> float:
    """Return total log10 probability (sum, not average)."""
    text = text.upper()
    if len(text) < 4:
        return QUADGRAM_FLOOR * max(1, len(text) - 3)
    total = 0.0
    for i in range(len(text) - 3):
        total += QUADGRAMS.get(text[i:i+4], QUADGRAM_FLOOR)
    return total

def quadgram_score_avg(text: str) -> float:
    """Return average log10 probability per quadgram."""
    text = text.upper()
    n = len(text) - 3
    if n <= 0:
        return QUADGRAM_FLOOR
    return quadgram_score(text) / n

# ── Cipher operations ────────────────────────────────────────────────────────

def decrypt_char_vig(ct_char, key_char, alpha, alpha_idx):
    """Vigenere: PT = (CT - KEY) mod 26"""
    return alpha[(alpha_idx[ct_char] - alpha_idx[key_char]) % 26]

def decrypt_char_beau(ct_char, key_char, alpha, alpha_idx):
    """Beaufort: PT = (KEY - CT) mod 26"""
    return alpha[(alpha_idx[key_char] - alpha_idx[ct_char]) % 26]

def decrypt_char_varbeau(ct_char, key_char, alpha, alpha_idx):
    """Variant Beaufort: PT = (CT + KEY) mod 26"""
    return alpha[(alpha_idx[ct_char] + alpha_idx[key_char]) % 26]

def decrypt_with_key(ct, key, variant, alpha, alpha_idx):
    """Decrypt ct with periodic key using given variant."""
    klen = len(key)
    if variant == "vig":
        return "".join(decrypt_char_vig(ct[i], key[i % klen], alpha, alpha_idx) for i in range(len(ct)))
    elif variant == "beau":
        return "".join(decrypt_char_beau(ct[i], key[i % klen], alpha, alpha_idx) for i in range(len(ct)))
    elif variant == "varbeau":
        return "".join(decrypt_char_varbeau(ct[i], key[i % klen], alpha, alpha_idx) for i in range(len(ct)))

def decrypt_with_shifts(ct, shifts, variant, alpha, alpha_idx):
    """Decrypt using numeric shift array (periodic)."""
    period = len(shifts)
    key = "".join(alpha[s % 26] for s in shifts)
    return decrypt_with_key(ct, key, variant, alpha, alpha_idx)

# ── Stream extraction ────────────────────────────────────────────────────────

def extract_streams(ct, period):
    """Split ct into `period` streams (every period-th character)."""
    streams = [[] for _ in range(period)]
    for i, c in enumerate(ct):
        streams[i % period].append(c)
    return streams

# ── IC-based shift recovery ──────────────────────────────────────────────────

def chi_squared_score(stream, shift, alpha, alpha_idx):
    """Chi-squared statistic for a stream decrypted with given shift.
    Lower = more English-like."""
    n = len(stream)
    if n == 0:
        return float('inf')
    counts = [0] * 26
    for c in stream:
        pt_idx = (alpha_idx[c] - shift) % 26
        counts[pt_idx] += 1
    chi2 = 0.0
    for i in range(26):
        expected = n * ENGLISH_FREQ[i]
        if expected > 0:
            chi2 += (counts[i] - expected) ** 2 / expected
    return chi2

def best_shift_chi2(stream, alpha, alpha_idx):
    """Find the shift that minimizes chi-squared for this stream."""
    best_shift = 0
    best_chi2 = float('inf')
    all_scores = []
    for shift in range(26):
        chi2 = chi_squared_score(stream, shift, alpha, alpha_idx)
        all_scores.append((chi2, shift))
        if chi2 < best_chi2:
            best_chi2 = chi2
            best_shift = shift
    all_scores.sort()
    return best_shift, best_chi2, all_scores[:5]  # Return top 5

# ── Quadgram-based key optimization ──────────────────────────────────────────

def optimize_key_quadgram(ct, period, variant, alpha, alpha_idx):
    """
    For each key position, try all 26 shifts and pick the one that
    maximizes the quadgram score of the resulting plaintext.
    Iterates until convergence (greedy hill-climbing).
    """
    # Start from IC-based best guess
    streams = extract_streams(ct, period)
    if variant == "vig":
        shifts = [best_shift_chi2(s, alpha, alpha_idx)[0] for s in streams]
    elif variant == "beau":
        # For Beaufort, PT = KEY - CT, so shift finding is different
        # Try all and pick best chi2 on decrypted stream
        shifts = []
        for s in streams:
            best_sh, _, _ = best_shift_beau_chi2(s, alpha, alpha_idx)
            shifts.append(best_sh)
    else:  # varbeau
        shifts = []
        for s in streams:
            best_sh, _, _ = best_shift_varbeau_chi2(s, alpha, alpha_idx)
            shifts.append(best_sh)

    best_score = quadgram_score(decrypt_with_shifts(ct, shifts, variant, alpha, alpha_idx))

    # Hill-climb: iterate over each position, try all 26 shifts
    improved = True
    iterations = 0
    while improved and iterations < 50:
        improved = False
        iterations += 1
        for pos in range(period):
            original_shift = shifts[pos]
            for s in range(26):
                if s == original_shift:
                    continue
                shifts[pos] = s
                pt = decrypt_with_shifts(ct, shifts, variant, alpha, alpha_idx)
                sc = quadgram_score(pt)
                if sc > best_score:
                    best_score = sc
                    improved = True
                    original_shift = s  # Keep this shift
                else:
                    shifts[pos] = original_shift

    pt = decrypt_with_shifts(ct, shifts, variant, alpha, alpha_idx)
    key_str = "".join(alpha[s % 26] for s in shifts)
    return shifts, key_str, pt, best_score, iterations

def best_shift_beau_chi2(stream, alpha, alpha_idx):
    """Find best Beaufort shift for a stream using chi-squared."""
    best_shift = 0
    best_chi2 = float('inf')
    all_scores = []
    for shift in range(26):
        n = len(stream)
        counts = [0] * 26
        for c in stream:
            pt_idx = (shift - alpha_idx[c]) % 26
            counts[pt_idx] += 1
        chi2 = 0.0
        for i in range(26):
            expected = n * ENGLISH_FREQ[i]
            if expected > 0:
                chi2 += (counts[i] - expected) ** 2 / expected
        all_scores.append((chi2, shift))
        if chi2 < best_chi2:
            best_chi2 = chi2
            best_shift = shift
    all_scores.sort()
    return best_shift, best_chi2, all_scores[:5]

def best_shift_varbeau_chi2(stream, alpha, alpha_idx):
    """Find best Variant Beaufort shift for a stream using chi-squared."""
    best_shift = 0
    best_chi2 = float('inf')
    all_scores = []
    for shift in range(26):
        n = len(stream)
        counts = [0] * 26
        for c in stream:
            pt_idx = (alpha_idx[c] + shift) % 26
            counts[pt_idx] += 1
        chi2 = 0.0
        for i in range(26):
            expected = n * ENGLISH_FREQ[i]
            if expected > 0:
                chi2 += (counts[i] - expected) ** 2 / expected
        all_scores.append((chi2, shift))
        if chi2 < best_chi2:
            best_chi2 = chi2
            best_shift = shift
    all_scores.sort()
    return best_shift, best_chi2, all_scores[:5]

# ── Exhaustive small-period search ───────────────────────────────────────────

def exhaustive_search(ct, period, variant, alpha, alpha_idx, top_n=5):
    """For small periods (2-4), try all 26^period keys exhaustively."""
    total = 26 ** period
    best = []
    for combo in itertools.product(range(26), repeat=period):
        shifts = list(combo)
        pt = decrypt_with_shifts(ct, shifts, variant, alpha, alpha_idx)
        sc = quadgram_score(pt)
        if len(best) < top_n:
            best.append((sc, shifts[:], pt))
            best.sort(reverse=True)
        elif sc > best[-1][0]:
            best[-1] = (sc, shifts[:], pt)
            best.sort(reverse=True)
    return best, total

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("E-GRILLE-04: Period-Targeted Vigenere/Beaufort Attacks on YAR Grille CT")
    print("=" * 80)
    print(f"\nCT ({YAR_LEN} chars): {YAR_CT}\n")

    if not load_quadgrams():
        print("[FATAL] Cannot proceed without quadgram data")
        return

    # Collect ALL results globally: (qg_avg, label, key, pt)
    all_results = []

    def record(label, key_str, pt):
        avg = quadgram_score_avg(pt)
        all_results.append((avg, label, key_str, pt))

    # ── SECTION A: Exhaustive search for periods 2, 3, 4 ────────────────
    print("\n" + "=" * 70)
    print("SECTION A: EXHAUSTIVE SEARCH (periods 2-4)")
    print("=" * 70)

    for period in [2, 3, 4]:
        for variant in ["vig", "beau", "varbeau"]:
            for alpha, alpha_idx, alpha_name in [(AZ, AZ_IDX, "AZ"), (KA, KA_IDX, "KA")]:
                results, total = exhaustive_search(YAR_CT, period, variant, alpha, alpha_idx, top_n=3)
                label_base = f"Exhaustive p={period} {variant} {alpha_name}"
                print(f"\n  {label_base} ({total} keys):")
                for sc, shifts, pt in results:
                    key_str = "".join(alpha[s] for s in shifts)
                    avg = sc / max(1, YAR_LEN - 3)
                    record(label_base, key_str, pt)
                    print(f"    key={key_str:8s}  qg={avg:.3f}/char  PT: {pt[:55]}...")

    # ── SECTION B: IC-based + quadgram hill-climbing for periods 5-8,10,13 ─
    print("\n" + "=" * 70)
    print("SECTION B: IC-BASED + QUADGRAM HILL-CLIMBING (periods 5-8, 10, 13, 53)")
    print("=" * 70)

    target_periods = [5, 6, 7, 8, 10, 13, 53]

    for period in target_periods:
        print(f"\n  --- Period {period} ---")

        for variant in ["vig", "beau", "varbeau"]:
            for alpha, alpha_idx, alpha_name in [(AZ, AZ_IDX, "AZ"), (KA, KA_IDX, "KA")]:
                shifts, key_str, pt, sc, iters = optimize_key_quadgram(
                    YAR_CT, period, variant, alpha, alpha_idx
                )
                avg = sc / max(1, YAR_LEN - 3)
                label = f"HillClimb p={period} {variant} {alpha_name}"
                record(label, key_str, pt)
                marker = " <<<" if avg > -5.5 else ""
                print(f"    {variant:8s} {alpha_name}: key={key_str:15s}  qg={avg:.3f}/char  iters={iters}{marker}")
                print(f"              PT: {pt[:65]}...")

    # ── SECTION C: Specific contextual keys (period 5 and 7) ────────────
    print("\n" + "=" * 70)
    print("SECTION C: SPECIFIC CONTEXTUAL KEYS")
    print("=" * 70)

    print("\n  --- Period-5 contextual keys ---")
    for key in CONTEXT_KEYS_5:
        for variant in ["vig", "beau", "varbeau"]:
            for alpha, alpha_idx, alpha_name in [(AZ, AZ_IDX, "AZ"), (KA, KA_IDX, "KA")]:
                pt = decrypt_with_key(YAR_CT, key, variant, alpha, alpha_idx)
                avg = quadgram_score_avg(pt)
                label = f"Context p=5 {variant} {alpha_name} key={key}"
                record(label, key, pt)
                if avg > -6.5:
                    print(f"    {variant:8s} {alpha_name} key={key:12s}  qg={avg:.3f}/char  PT: {pt[:50]}...")

    print("\n  --- Period-7 contextual keys ---")
    for key in CONTEXT_KEYS_7:
        for variant in ["vig", "beau", "varbeau"]:
            for alpha, alpha_idx, alpha_name in [(AZ, AZ_IDX, "AZ"), (KA, KA_IDX, "KA")]:
                pt = decrypt_with_key(YAR_CT, key, variant, alpha, alpha_idx)
                avg = quadgram_score_avg(pt)
                label = f"Context p=7 {variant} {alpha_name} key={key}"
                record(label, key, pt)
                if avg > -6.5:
                    print(f"    {variant:8s} {alpha_name} key={key:12s}  qg={avg:.3f}/char  PT: {pt[:50]}...")

    # ── SECTION D: Multi-start hill-climbing with random restarts ────────
    print("\n" + "=" * 70)
    print("SECTION D: MULTI-START HILL-CLIMBING (periods 5 and 7, 100 restarts)")
    print("=" * 70)

    import random
    random.seed(42)

    for period in [5, 7]:
        print(f"\n  --- Period {period}, 100 random restarts ---")
        for variant in ["vig", "beau", "varbeau"]:
            for alpha, alpha_idx, alpha_name in [(AZ, AZ_IDX, "AZ"), (KA, KA_IDX, "KA")]:
                global_best_score = -float('inf')
                global_best_shifts = None
                global_best_pt = None

                for restart in range(100):
                    # Random starting key
                    shifts = [random.randint(0, 25) for _ in range(period)]

                    # Hill-climb from this starting point
                    pt = decrypt_with_shifts(YAR_CT, shifts, variant, alpha, alpha_idx)
                    best_score = quadgram_score(pt)

                    improved = True
                    while improved:
                        improved = False
                        for pos in range(period):
                            orig = shifts[pos]
                            for s in range(26):
                                if s == orig:
                                    continue
                                shifts[pos] = s
                                pt = decrypt_with_shifts(YAR_CT, shifts, variant, alpha, alpha_idx)
                                sc = quadgram_score(pt)
                                if sc > best_score:
                                    best_score = sc
                                    improved = True
                                    orig = s
                                else:
                                    shifts[pos] = orig

                    if best_score > global_best_score:
                        global_best_score = best_score
                        global_best_shifts = shifts[:]
                        global_best_pt = decrypt_with_shifts(YAR_CT, shifts, variant, alpha, alpha_idx)

                key_str = "".join(alpha[s] for s in global_best_shifts)
                avg = global_best_score / max(1, YAR_LEN - 3)
                label = f"MultiStart p={period} {variant} {alpha_name}"
                record(label, key_str, global_best_pt)
                marker = " <<<" if avg > -5.5 else ""
                print(f"    {variant:8s} {alpha_name}: key={key_str:10s}  qg={avg:.3f}/char{marker}")
                print(f"              PT: {global_best_pt[:65]}...")

    # ── SECTION E: IC stream analysis detail for periods 5 and 7 ─────────
    print("\n" + "=" * 70)
    print("SECTION E: IC STREAM ANALYSIS DETAIL (periods 5 and 7)")
    print("=" * 70)

    for period in [5, 7]:
        print(f"\n  --- Period {period} stream analysis ---")
        streams = extract_streams(YAR_CT, period)
        for si, stream in enumerate(streams):
            stream_str = "".join(stream)
            n = len(stream)
            # Compute IC of this stream
            counts = [0] * 26
            for c in stream:
                counts[AZ_IDX[c]] += 1
            ic = sum(c * (c - 1) for c in counts) / (n * (n - 1)) if n > 1 else 0

            # Best shifts
            best_sh, best_chi2, top5 = best_shift_chi2(stream, AZ, AZ_IDX)
            print(f"    Stream {si}: len={n}, IC={ic:.4f}, best_shift={best_sh} (chi2={best_chi2:.1f})")
            print(f"      chars: {stream_str}")
            print(f"      top-5 shifts: {[(s, f'{c:.1f}') for c, s in top5]}")

    # ── SECTION F: Exhaustive period-5 in AZ (26^5 = 11.8M) ─────────────
    print("\n" + "=" * 70)
    print("SECTION F: EXHAUSTIVE PERIOD-5 KEY SEARCH (26^5 = 11,881,376 keys)")
    print("=" * 70)
    print("  Running Vigenere, Beaufort, Variant Beaufort in AZ-space...")

    for variant in ["vig", "beau", "varbeau"]:
        best_5 = []
        count = 0
        for combo in itertools.product(range(26), repeat=5):
            shifts = list(combo)
            pt = decrypt_with_shifts(YAR_CT, shifts, variant, AZ, AZ_IDX)
            sc = quadgram_score(pt)
            count += 1
            if len(best_5) < 5:
                best_5.append((sc, shifts[:], pt))
                best_5.sort(reverse=True)
            elif sc > best_5[-1][0]:
                best_5[-1] = (sc, shifts[:], pt)
                best_5.sort(reverse=True)
            if count % 2_000_000 == 0:
                avg_best = best_5[0][0] / max(1, YAR_LEN - 3) if best_5 else -99
                print(f"    {variant}: {count:,} / 11,881,376 ... best so far: {avg_best:.3f}/char", flush=True)

        print(f"\n  {variant.upper()} period-5 exhaustive — top 5:")
        for sc, shifts, pt in best_5:
            key_str = "".join(AZ[s] for s in shifts)
            avg = sc / max(1, YAR_LEN - 3)
            label = f"Exhaust-p5 {variant} AZ"
            record(label, key_str, pt)
            print(f"    key={key_str}  qg={avg:.3f}/char  PT: {pt[:60]}...")

    # ── FINAL RESULTS ────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("FINAL RESULTS: TOP 20 MOST ENGLISH-LIKE OUTPUTS (by quadgram avg)")
    print("=" * 80)

    all_results.sort(key=lambda x: x[0], reverse=True)

    for rank, (avg, label, key_str, pt) in enumerate(all_results[:20], 1):
        print(f"\n  #{rank:2d}  qg={avg:.3f}/char")
        print(f"       method: {label}")
        print(f"       key: {key_str}")
        print(f"       PT: {pt}")

    # Reference thresholds
    print(f"\n  Reference: English text ~= -2.3 to -2.8/char, random ~= -4.5/char")
    print(f"  Total outputs tested: {len(all_results)}")

    best_avg = all_results[0][0] if all_results else -99
    print(f"  Best quadgram avg: {best_avg:.3f}/char")

    if best_avg > -3.5:
        print("\n  *** SIGNAL DETECTED — manual review recommended ***")
    elif best_avg > -4.0:
        print("\n  ** Weak signal — possible partial decryption **")
    else:
        print("\n  All results at noise level. No classical periodic cipher decrypts this CT.")

    print(f"\n{'=' * 80}")
    print("E-GRILLE-04 COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
