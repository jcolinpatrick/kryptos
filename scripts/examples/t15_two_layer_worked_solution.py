#!/usr/bin/env python3
"""
KRYPTOSBOT TRAINING: Worked Solution for Two-Layer Cipher Decomposition
=========================================================================

This is a TEACHING DOCUMENT. It walks through the complete diagnostic and
solving process for a ciphertext that was encrypted with TWO layers:
  Layer 1 (inner): Vigenere substitution
  Layer 2 (outer): Columnar transposition

The key insight: when two layers are present, standard single-layer
diagnostics give MISLEADING results. The bot must learn to recognize
the COMBINED SIGNATURE of two layers and systematically decompose them.

Challenge used: T15-VIG-PLUS-TRANS
  CT: VIWFUVDUJWVVTCVDWYAQCNRXEEIHSEVPUSIXNRWKHHLAIPHSEXZOEMUCRIHT
      HTIEPIEXHLIIIACHMVIXHKZLWXDFDJRFVGVZLRLWGDFULNVILRTYHKPUYHYX
  PT: THECOORDINATESINDICATEDASITETWELVEKILOMETERSNORTHEASTOFTHEOLD
      GARRISONWHERESUPPLIESHADBEENCACHEDDURINGTHEPREVIOUSWINTER
  Sub keyword:   CADASTRE (period 8)
  Trans keyword: GNOMON (width 6)
  Layer order:   substitution first, then transposition

Author: Colin Patrick / Claude (K4 Project)
Date:   2026-03-05
"""

from collections import Counter
import math

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# ─────────────────────────────────────────────────────────────
# The ciphertext under analysis
# ─────────────────────────────────────────────────────────────

CT = "VIWFUVDUJWVVTCVDWYAQCNRXEEIHSEVPUSIXNRWKHHLAIPHSEXZOEMUCRIHTHTIEPIEXHLIIIACHMVIXHKZLWXDFDJRFVGVZLRLWGDFULNVILRTYHKPUYHYX"

print("=" * 72)
print("STEP 1: INITIAL DIAGNOSTICS")
print("=" * 72)
print(f"\nCiphertext length: {len(CT)}")
print(f"Ciphertext: {CT}")

# ─────────────────────────────────────────────────────────────
# STEP 1A: Index of Coincidence
# ─────────────────────────────────────────────────────────────

def ic(text: str) -> float:
    """Calculate Index of Coincidence."""
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    total = sum(f * (f - 1) for f in freq.values())
    return total / (n * (n - 1))

ic_val = ic(CT)
print(f"\nIndex of Coincidence: {ic_val:.4f}")
print(f"  English text:   ~0.0667")
print(f"  Random/uniform: ~0.0385")
print(f"  Observed:        {ic_val:.4f}")

if ic_val > 0.060:
    print("  --> DIAGNOSIS: IC near English. Suggests TRANSPOSITION ONLY.")
    print("      (Transposition preserves letter frequencies.)")
elif ic_val > 0.050:
    print("  --> DIAGNOSIS: IC moderately depressed. Could be:")
    print("      - Weak polyalphabetic substitution (short key)")
    print("      - OR: substitution + transposition combined")
    print("      This is the AMBIGUOUS ZONE where two-layer ciphers live.")
elif ic_val > 0.042:
    print("  --> DIAGNOSIS: IC significantly depressed. Suggests:")
    print("      - Polyalphabetic substitution (period 5-12)")
    print("      - OR: two-layer system")
    print("      *** THIS IS THE TWO-LAYER DANGER ZONE ***")
else:
    print("  --> DIAGNOSIS: IC near random. Suggests:")
    print("      - Long-period polyalphabetic or running key")
    print("      - OR: fractionation (Bifid, ADFGX)")
    print("      - OR: heavily layered system")

# ─────────────────────────────────────────────────────────────
# STEP 1B: Frequency distribution
# ─────────────────────────────────────────────────────────────

print(f"\n{'─' * 72}")
print("STEP 1B: Frequency Distribution")
freq = Counter(CT)
total_chars = len(CT)
sorted_freq = sorted(freq.items(), key=lambda x: -x[1])

print(f"\n  Letter  Count  Freq%   English%")
english_freq = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
    'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
    'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
    'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
    'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1, 'Z': 0.1
}
for letter, count in sorted_freq[:10]:
    pct = 100.0 * count / total_chars
    eng_pct = english_freq.get(letter, 0.0)
    marker = " <-- unusual" if abs(pct - eng_pct) > 4.0 else ""
    print(f"  {letter}       {count:3d}    {pct:5.1f}%   {eng_pct:5.1f}%{marker}")

# Check if frequencies MATCH English (transposition) or are FLAT (substitution)
top5_pct = sum(100.0 * freq.get(c, 0) / total_chars for c in "ETAOI")
print(f"\n  Top-5 English letters (ETAOI) account for: {top5_pct:.1f}% of CT")
print(f"  In English text, they should be ~43.5%")
if top5_pct > 38:
    print("  --> Frequencies roughly preserved. TRANSPOSITION likely present.")
elif top5_pct > 28:
    print("  --> Frequencies partially flattened. SUBSTITUTION likely present.")
    print("      But not fully flat -- could be short-key polyalphabetic")
    print("      OR substitution layer partially masked by transposition.")
else:
    print("  --> Frequencies heavily flattened. Strong substitution or fractionation.")

# ─────────────────────────────────────────────────────────────
# STEP 1C: Kasiski examination
# ─────────────────────────────────────────────────────────────

print(f"\n{'─' * 72}")
print("STEP 1C: Kasiski Examination (repeated n-gram spacing)")

def kasiski(text: str, min_len: int = 3, max_len: int = 5) -> dict:
    """Find repeated n-grams and their spacings."""
    results = {}
    for ngram_len in range(min_len, max_len + 1):
        for i in range(len(text) - ngram_len):
            ngram = text[i:i+ngram_len]
            for j in range(i + 1, len(text) - ngram_len + 1):
                if text[j:j+ngram_len] == ngram:
                    spacing = j - i
                    if ngram not in results:
                        results[ngram] = []
                    results[ngram].append(spacing)
    return results

kas = kasiski(CT)
if kas:
    print(f"\n  Found {len(kas)} repeated n-grams. Top spacings:")
    all_spacings = []
    for ngram, spacings in sorted(kas.items(), key=lambda x: -len(x[0]))[:10]:
        print(f"    '{ngram}' at spacings: {spacings}")
        all_spacings.extend(spacings)

    # GCD analysis on spacings
    from math import gcd
    from functools import reduce
    if len(all_spacings) >= 2:
        overall_gcd = reduce(gcd, all_spacings)
        print(f"\n  GCD of all spacings: {overall_gcd}")
        if overall_gcd > 1:
            print(f"  --> Possible Vigenere period: {overall_gcd}")
            print(f"      BUT: if transposition is present, Kasiski results are UNRELIABLE.")
            print(f"      Transposition BREAKS the periodic spacing that Kasiski depends on.")
        else:
            print(f"  --> GCD = 1. No clean period detected.")
            print(f"      This is EXPECTED for two-layer ciphers:")
            print(f"      the transposition layer scrambles the periodic structure.")
else:
    print("  No significant repeated n-grams found.")
    print("  This is CONSISTENT WITH two-layer encryption.")


print(f"\n{'=' * 72}")
print("STEP 2: TWO-LAYER HYPOTHESIS TEST")
print("=" * 72)

print("""
The diagnostics above show MIXED SIGNALS:
  - IC is in the ambiguous zone (not English, not fully random)
  - Frequencies are partially but not fully flattened
  - Kasiski gives no clean period (or an unreliable one)

*** THIS COMBINATION IS THE SIGNATURE OF A TWO-LAYER CIPHER ***

Single-layer ciphers give CLEAN signals:
  - Pure transposition: IC = English, frequencies = English, Kasiski = N/A
  - Pure Vigenere:      IC = depressed, frequencies = flat, Kasiski = clean period
  - Pure mono sub:      IC = English, frequencies = shifted, Kasiski = N/A

Two-layer ciphers give MUDDY signals:
  - IC: between English and random (transposition partially preserves, sub partially flattens)
  - Frequencies: partially flattened (sub flattens, trans shuffles the flattened distribution)
  - Kasiski: broken or unreliable (trans disrupts periodic spacing)

DECISION: Proceed with two-layer decomposition.
""")


print(f"\n{'=' * 72}")
print("STEP 3: SYSTEMATIC DECOMPOSITION")
print("=" * 72)

print("""
Strategy: The OUTER layer (applied last during encryption) must be
removed FIRST during decryption.

Two possible orders:
  A) Encryption: Sub then Trans --> Decryption: undo Trans, then undo Sub
  B) Encryption: Trans then Sub --> Decryption: undo Sub, then undo Vigenere

We try BOTH. For each candidate outer layer removal, we check whether
the intermediate result shows clean single-layer diagnostic signatures.
""")

# ─────────────────────────────────────────────────────────────
# STEP 3A: Try TRANSPOSITION as outer layer
# ─────────────────────────────────────────────────────────────

print(f"{'─' * 72}")
print("STEP 3A: Hypothesis -- Transposition is the OUTER layer")
print("         (Encryption was: Sub first, then Trans)")
print("         (We undo Trans first, then check residual for Sub)")

def columnar_transpose_decrypt(ct: str, key_order: list[int]) -> str:
    width = len(key_order)
    nrows = len(ct) // width
    remainder = len(ct) % width
    # Handle uneven columns
    col_lengths = [nrows] * width
    # Columns that get an extra character (the first 'remainder' columns in read order)
    for i in range(remainder):
        col_lengths[key_order[i]] += 1
    cols = [""] * width
    pos = 0
    for col in key_order:
        cols[col] = ct[pos:pos+col_lengths[col]]
        pos += col_lengths[col]
    # Read off row by row
    pt = []
    for r in range(nrows + (1 if remainder else 0)):
        for c in range(width):
            if r < len(cols[c]):
                pt.append(cols[c][r])
    return "".join(pt)

def keyword_to_column_order(keyword: str) -> list[int]:
    indexed = sorted(enumerate(keyword.upper()), key=lambda x: (x[1], x[0]))
    return [orig for _, (orig, _) in enumerate(indexed)]

def try_columnar_widths(ct: str, min_w: int = 4, max_w: int = 15):
    """Try all columnar transposition widths. For each, check if
    the result looks like clean single-layer polyalphabetic."""
    results = []
    for width in range(min_w, max_w + 1):
        if len(ct) % width != 0:
            # Skip widths that don't divide evenly (simplification)
            # In practice you'd handle padding, but this catches most cases
            continue

        # Generate all possible column orderings for this width
        # (Too many for brute force -- instead, try the IDENTITY ordering
        # and check IC of the result. If IC improves toward English,
        # transposition at this width is promising.)
        from itertools import permutations

        # Quick heuristic: try identity permutation first
        nrows = len(ct) // width
        # Read columns directly (identity permutation = undo a specific transposition)
        # Try reading the CT as columns and reconstructing rows
        inter = ""
        for r in range(nrows):
            for c in range(width):
                inter += ct[c * nrows + r]

        inter_ic = ic(inter)

        # Also check: does the intermediate text show periodic structure?
        # Test IC of every nth character for candidate periods
        best_period_ic = 0
        best_period = 0
        for period in range(3, 13):
            period_ics = []
            for offset in range(period):
                column = inter[offset::period]
                if len(column) > 5:
                    period_ics.append(ic(column))
            if period_ics:
                avg_ic = sum(period_ics) / len(period_ics)
                if avg_ic > best_period_ic:
                    best_period_ic = avg_ic
                    best_period = period

        results.append({
            "width": width,
            "ic_after": inter_ic,
            "best_period": best_period,
            "best_period_ic": best_period_ic,
            "intermediate": inter[:40] + "..."
        })

    return sorted(results, key=lambda x: -x["best_period_ic"])

print("\nTrying columnar widths 4-15, checking if residual shows periodic structure:\n")
width_results = try_columnar_widths(CT)
print(f"  {'Width':>5}  {'IC after':>8}  {'Best period':>11}  {'Period IC':>9}")
print(f"  {'─'*5}  {'─'*8}  {'─'*11}  {'─'*9}")
for r in width_results[:8]:
    marker = " <-- PROMISING" if r["best_period_ic"] > 0.060 else ""
    print(f"  {r['width']:>5}  {r['ic_after']:>8.4f}  {r['best_period']:>11}  {r['best_period_ic']:>9.4f}{marker}")

print("""
INTERPRETATION:
  If any width produces a residual where single-column IC rises toward
  ~0.067 (English), that width is likely correct and the residual is a
  polyalphabetic substitution cipher that can be attacked normally.

  The 'Best period IC' column is key: it shows the average IC when the
  intermediate text is split into columns at the best candidate period.
  Values above 0.060 strongly suggest a Vigenere-family cipher underneath.
""")


# ─────────────────────────────────────────────────────────────
# STEP 3B: Demonstrate the CORRECT decomposition
# ─────────────────────────────────────────────────────────────

print(f"\n{'=' * 72}")
print("STEP 4: CORRECT DECOMPOSITION (using known answer)")
print("=" * 72)
print("\nFor this training example, we know the answer:")
print("  Outer layer: Columnar transposition, keyword GNOMON (width 6)")
print("  Inner layer: Vigenere, keyword CADASTRE (period 8)")
print("\nLet's verify the decomposition step by step.\n")

# Step 4a: Undo the columnar transposition
trans_key = "GNOMON"
col_order = keyword_to_column_order(trans_key)
print(f"Transposition keyword: {trans_key}")
print(f"Column read order: {col_order}")
print(f"  (G=0, N=3, O=4, M=2, O=5, N=1 -> alphabetical rank: G<M<N<N<O<O)")
print(f"  Columns were read in order: {col_order}")

intermediate = columnar_transpose_decrypt(CT, col_order)
print(f"\nAfter undoing transposition:")
print(f"  {intermediate[:60]}...")
print(f"  IC of intermediate: {ic(intermediate):.4f}")

# Check periodic structure of intermediate
print(f"\nPeriodic IC analysis of intermediate:")
for period in range(3, 13):
    col_ics = []
    for offset in range(period):
        col = intermediate[offset::period]
        if len(col) > 3:
            col_ics.append(ic(col))
    avg = sum(col_ics) / len(col_ics) if col_ics else 0
    marker = " <-- STRONG SIGNAL" if avg > 0.060 else ""
    print(f"  Period {period:2d}: avg column IC = {avg:.4f}{marker}")

# Step 4b: Undo the Vigenere
print(f"\n{'─' * 72}")
print("Vigenere decryption of intermediate with keyword CADASTRE:\n")

def vigenere_decrypt(ct: str, key: str, alphabet: str = ALPHA) -> str:
    n = len(alphabet)
    return "".join(alphabet[(alphabet.index(c) - alphabet.index(key[i % len(key)])) % n]
                   for i, c in enumerate(ct))

plaintext = vigenere_decrypt(intermediate, "CADASTRE")
print(f"  Recovered plaintext:")
print(f"  {plaintext[:60]}")
print(f"  {plaintext[60:]}")

# Verify
EXPECTED = "THECOORDINATESINDICATEDASITETWELVEKILOMETERSNORTHEASTOFTHEOLDGARRISONWHERESUPPLIESHADBEENCACHEDDURINGTHEPREVIOUSWINTER"
match = plaintext.rstrip("X") == EXPECTED or plaintext[:len(EXPECTED)] == EXPECTED
print(f"\n  Matches expected plaintext: {'YES' if match else 'NO'}")
print(f"  IC of plaintext: {ic(plaintext):.4f} (should be ~0.067)")


print(f"\n{'=' * 72}")
print("STEP 5: SUMMARY -- THE TWO-LAYER DECISION TREE")
print("=" * 72)

print("""
When you encounter a ciphertext, follow this diagnostic sequence:

1. COMPUTE IC
   - IC > 0.060       --> likely TRANSPOSITION ONLY (or mono substitution)
   - IC = 0.042-0.055 --> likely POLYALPHABETIC (Vigenere family)
   - IC = 0.035-0.042 --> likely RUNNING KEY, FRACTIONATION, or TWO-LAYER
   - IC < 0.035       --> likely heavily encrypted or very long key

2. CHECK FREQUENCY DISTRIBUTION
   - Matches English       --> TRANSPOSITION (frequencies preserved)
   - Partially flattened   --> SHORT-KEY polyalphabetic or TWO-LAYER
   - Fully flat            --> LONG-KEY polyalphabetic or fractionation

3. RUN KASISKI
   - Clean period found    --> single-layer PERIODIC polyalphabetic
   - No clean period       --> AUTOKEY, RUNNING KEY, or TWO-LAYER
   - Contradictory results --> TWO-LAYER (transposition broke the periodicity)

4. THE TWO-LAYER TEST (if signals are MIXED or CONTRADICTORY)
   >>> IC is ambiguous AND frequencies are partially flat AND Kasiski fails
   >>> This triple-mismatch is the TWO-LAYER SIGNATURE

5. DECOMPOSITION PROCEDURE
   a) Assume TRANSPOSITION is outer layer (most common in historical practice)
   b) Try columnar transposition at widths 4-15
   c) For each width, undo transposition and check if residual shows:
      - Higher IC than the original CT
      - Clean periodic structure (column ICs > 0.060 at some period)
   d) When a promising width is found, try all column permutations at that width
      (or use keyword dictionary)
   e) For each candidate transposition undo, attack the residual as Vigenere:
      - Use Kasiski/IC to find period
      - Solve each column as Caesar
   f) If no transposition-first decomposition works, try SUBSTITUTION as outer layer
      (undo Vigenere first, then look for transposition in residual)

6. VALIDATION
   - Recovered plaintext should have IC ~0.067
   - Recovered plaintext should be readable English
   - Both keys should be memorable words (for Sanborn-style ciphers)

CRITICAL INSIGHT:
  The COMBINATION of ambiguous IC + partially flat frequencies + failed Kasiski
  is not a failure of your analysis tools. It is DIAGNOSTIC INFORMATION.
  It tells you that two layers are present and that single-layer attacks will
  fail. Switch to the decomposition procedure immediately.
""")


print(f"\n{'=' * 72}")
print("STEP 6: WHAT WENT WRONG WITH SINGLE-LAYER ATTACKS")
print("=" * 72)

print("""
If you tried to solve this ciphertext as a SINGLE-LAYER cipher, here is
why every approach failed:

AS VIGENERE:
  - IC suggests polyalphabetic, so this seems reasonable
  - But Kasiski gives no clean period (transposition broke it)
  - Even if you guess period 8, the columns don't decrypt to English
    because the transposition shuffled which characters are in which columns
  - Result: gibberish at every period

AS TRANSPOSITION:
  - IC is too low for pure transposition (~0.045 vs expected ~0.067)
  - Even if you find the right columnar undo, the result looks random
    because the Vigenere layer is still present
  - Result: undoing transposition gives you Vigenere ciphertext,
    which LOOKS like a failed transposition attempt

AS MONOALPHABETIC:
  - IC is far too low for monoalphabetic (~0.045 vs expected ~0.067)
  - Should be eliminated immediately

AS PLAYFAIR/BIFID:
  - IC range might seem compatible
  - But frequency patterns don't match fractionation signature
  - Result: wrong family entirely

THE TRAP: each single-layer test gives a PLAUSIBLE but WRONG partial
diagnosis. The bot must learn to recognize when NO single-layer
diagnosis fits cleanly, and switch to two-layer decomposition.
""")

print("=" * 72)
print("END OF WORKED SOLUTION")
print("=" * 72)
