#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
EXP-LECARRE-RK-001: Running-Key Vigenère/Beaufort from Novel Texts

Hypothesis: K4 was produced using a running-key cipher keyed from consecutive
text in a novel (originally targeting le Carré's "The Russia House" and
"A Perfect Spy", but works with any text file).

Procedure:
  1. Slide a 97-char window across the source text (stride=1)
  2. At each position, compute Vigenère: P = (C - K) mod 26
     and Beaufort: P = (K - C) mod 26
  3. Score each window against 24 known plaintext chars
  4. Flag any window scoring ≥18/24

Usage:
  PYTHONPATH=src python3 -u scripts/exp_lecarre_rk_001.py [text_file ...]

If no files given, scans all .txt files in reference/running_key_texts/.
"""

import os
import sys
import glob
import json
import time

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)

# ── Precompute CT as integers ───────────────────────────────────────────────
CT_INT = [ALPH_IDX[c] for c in CT]
CRIB_POSITIONS = sorted(CRIB_DICT.keys())
CRIB_PT_INT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POSITIONS}


def load_text(filepath: str) -> str:
    """Load a text file, strip to uppercase alpha only."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return "".join(c for c in raw.upper() if c in ALPH)


def score_window_vig(key_ints: list[int]) -> int:
    """Score a 97-char key window under Vigenère: P = (C - K) mod 26."""
    score = 0
    for pos in CRIB_POSITIONS:
        pt = (CT_INT[pos] - key_ints[pos]) % MOD
        if pt == CRIB_PT_INT[pos]:
            score += 1
    return score


def score_window_beau(key_ints: list[int]) -> int:
    """Score a 97-char key window under Beaufort: P = (K - C) mod 26."""
    score = 0
    for pos in CRIB_POSITIONS:
        pt = (key_ints[pos] - CT_INT[pos]) % MOD
        if pt == CRIB_PT_INT[pos]:
            score += 1
    return score


def check_bean(key_ints: list[int], variant: str) -> bool:
    """Check Bean constraints for a given key window."""
    # Bean EQ: k[27] == k[65]
    if key_ints[27] != key_ints[65]:
        return False
    # Bean INEQ: k[a] != k[b] for all 21 pairs
    for a, b in BEAN_INEQ:
        if a in CRIB_PT_INT and b in CRIB_PT_INT:
            # Both are crib positions — derive key values
            if variant == "vig":
                ka = (CT_INT[a] - CRIB_PT_INT[a]) % MOD
                kb = (CT_INT[b] - CRIB_PT_INT[b]) % MOD
            else:
                ka = (CRIB_PT_INT[a] + CT_INT[a]) % MOD
                kb = (CRIB_PT_INT[b] + CT_INT[b]) % MOD
            if ka == kb:
                return False
    return True


def decrypt_full(key_ints: list[int], variant: str) -> str:
    """Decrypt full CT with given key."""
    pt = []
    for i in range(CT_LEN):
        if variant == "vig":
            p = (CT_INT[i] - key_ints[i]) % MOD
        else:
            p = (key_ints[i] - CT_INT[i]) % MOD
        pt.append(ALPH[p])
    return "".join(pt)


def has_english_words(text: str, min_len: int = 5, min_count: int = 2) -> bool:
    """Quick check if text contains recognizable English words."""
    wordlist_path = "wordlists/english.txt"
    if not os.path.exists(wordlist_path):
        return False
    with open(wordlist_path) as f:
        words = set(w.strip().upper() for w in f if len(w.strip()) >= min_len)
    count = 0
    for wlen in range(min_len, min(12, len(text))):
        for i in range(len(text) - wlen + 1):
            if text[i:i+wlen] in words:
                count += 1
                if count >= min_count:
                    return True
    return count >= min_count


def scan_file(filepath: str, results: list):
    """Scan a single text file with sliding window."""
    basename = os.path.basename(filepath)
    text = load_text(filepath)
    n = len(text)

    if n < CT_LEN:
        print(f"  {basename}: {n} chars — TOO SHORT (need {CT_LEN})")
        return

    text_ints = [ALPH_IDX[c] for c in text]
    n_windows = n - CT_LEN + 1

    best_vig = 0
    best_beau = 0
    best_vig_pos = -1
    best_beau_pos = -1
    hits_vig = []
    hits_beau = []

    for start in range(n_windows):
        key_window = text_ints[start:start + CT_LEN]

        # Vigenère
        sv = score_window_vig(key_window)
        if sv > best_vig:
            best_vig = sv
            best_vig_pos = start
        if sv >= SIGNAL_THRESHOLD:
            pt = decrypt_full(key_window, "vig")
            hits_vig.append({
                "pos": start, "score": sv, "variant": "vig",
                "key_fragment": text[start:start+20],
                "plaintext": pt,
                "bean": check_bean(key_window, "vig"),
            })

        # Beaufort
        sb = score_window_beau(key_window)
        if sb > best_beau:
            best_beau = sb
            best_beau_pos = start
        if sb >= SIGNAL_THRESHOLD:
            pt = decrypt_full(key_window, "beau")
            hits_beau.append({
                "pos": start, "score": sb, "variant": "beau",
                "key_fragment": text[start:start+20],
                "plaintext": pt,
                "bean": check_bean(key_window, "beau"),
            })

    # Compute expected random score for this window count
    # Each crib position has 1/26 chance of matching → E[score] = 24/26 ≈ 0.923
    expected = 24.0 / 26.0

    print(f"  {basename}: {n:,} chars, {n_windows:,} windows")
    print(f"    Best Vigenère:  {best_vig}/24 at pos {best_vig_pos}")
    print(f"    Best Beaufort:  {best_beau}/24 at pos {best_beau_pos}")
    print(f"    Hits ≥{SIGNAL_THRESHOLD}: Vig={len(hits_vig)}, Beau={len(hits_beau)}")
    print(f"    Expected random: {expected:.1f}/24")

    if hits_vig or hits_beau:
        print(f"    *** SIGNAL DETECTED ***")
        for h in (hits_vig + hits_beau)[:10]:
            print(f"      {h['variant'].upper()} pos={h['pos']} score={h['score']}/24 "
                  f"bean={'PASS' if h['bean'] else 'FAIL'}")
            print(f"        key: ...{h['key_fragment']}...")
            print(f"        PT:  {h['plaintext']}")

    # Also report anything above noise floor
    above_noise_vig = 0
    above_noise_beau = 0
    for start in range(n_windows):
        key_window = text_ints[start:start + CT_LEN]
        if score_window_vig(key_window) > NOISE_FLOOR:
            above_noise_vig += 1
        if score_window_beau(key_window) > NOISE_FLOOR:
            above_noise_beau += 1

    print(f"    Above noise (>{NOISE_FLOOR}): Vig={above_noise_vig}, Beau={above_noise_beau}")

    results.append({
        "file": basename,
        "chars": n,
        "windows": n_windows,
        "best_vig": best_vig,
        "best_vig_pos": best_vig_pos,
        "best_beau": best_beau,
        "best_beau_pos": best_beau_pos,
        "hits_vig": hits_vig,
        "hits_beau": hits_beau,
        "above_noise_vig": above_noise_vig,
        "above_noise_beau": above_noise_beau,
    })


def main():
    print("EXP-LECARRE-RK-001: Running-Key Sliding Window Test")
    print("=" * 70)
    print()
    print(f"Ciphertext: {CT}")
    print(f"Length: {CT_LEN}")
    print(f"Known positions: {len(CRIB_POSITIONS)} (ENE: 21-33, BC: 63-73)")
    print(f"Signal threshold: ≥{SIGNAL_THRESHOLD}/24")
    print()

    # Determine text files to scan
    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        # Default: scan all available running key texts
        files = sorted(glob.glob("reference/running_key_texts/*.txt"))
        # Also include Carter texts
        for carter in ["reference/carter_gutenberg.txt", "reference/carter_vol1.txt"]:
            if os.path.exists(carter):
                files.append(carter)

    if not files:
        print("ERROR: No text files found. Provide paths as arguments.")
        print("Usage: PYTHONPATH=src python3 -u scripts/exp_lecarre_rk_001.py <file1.txt> [file2.txt ...]")
        sys.exit(1)

    print(f"Scanning {len(files)} text file(s)...")
    print("-" * 70)

    results = []
    t0 = time.time()

    for filepath in files:
        if not os.path.exists(filepath):
            print(f"  WARNING: {filepath} not found, skipping")
            continue
        scan_file(filepath, results)
        print()

    elapsed = time.time() - t0

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()

    total_windows = sum(r["windows"] for r in results)
    total_hits = sum(len(r["hits_vig"]) + len(r["hits_beau"]) for r in results)
    max_vig = max((r["best_vig"] for r in results), default=0)
    max_beau = max((r["best_beau"] for r in results), default=0)
    max_overall = max(max_vig, max_beau)

    print(f"Files scanned: {len(results)}")
    print(f"Total windows: {total_windows:,}")
    print(f"Best Vigenère:  {max_vig}/24")
    print(f"Best Beaufort:  {max_beau}/24")
    print(f"Hits ≥{SIGNAL_THRESHOLD}: {total_hits}")
    print(f"Elapsed: {elapsed:.1f}s")
    print()

    if total_hits > 0:
        print("*** HITS FOUND — INVESTIGATE ***")
        for r in results:
            for h in r["hits_vig"] + r["hits_beau"]:
                print(f"  {r['file']} {h['variant'].upper()} pos={h['pos']} "
                      f"score={h['score']}/24 bean={'PASS' if h['bean'] else 'FAIL'}")
    elif max_overall <= NOISE_FLOOR:
        print(f"ALL NOISE (max {max_overall}/24 ≤ noise floor {NOISE_FLOOR})")
    elif max_overall < SIGNAL_THRESHOLD:
        print(f"NO SIGNAL (max {max_overall}/24 < threshold {SIGNAL_THRESHOLD})")
        print("Consistent with single-layer running-key ceiling of 14-17/24.")
    else:
        print(f"UNEXPECTED: max={max_overall} but no hits captured")

    print()
    print("NOTE: le Carré novels ('The Russia House', 'A Perfect Spy') are NOT")
    print("available in the repository. Provide digitized .txt files to test them.")
    print("These results are a baseline using available running-key texts.")

    # Save results
    os.makedirs("results", exist_ok=True)
    out_path = "results/exp_lecarre_rk_001.json"
    with open(out_path, "w") as f:
        json.dump({
            "experiment": "EXP-LECARRE-RK-001",
            "hypothesis": "Running-key Vigenère/Beaufort from novel/speech text",
            "files_scanned": [r["file"] for r in results],
            "total_windows": total_windows,
            "max_vig": max_vig,
            "max_beau": max_beau,
            "signal_threshold": SIGNAL_THRESHOLD,
            "hits": total_hits,
            "results": results,
            "elapsed_s": elapsed,
            "le_carre_available": False,
        }, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
