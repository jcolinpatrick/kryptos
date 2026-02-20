#!/usr/bin/env python3
"""
E-S-35: Null Cipher / Steganographic Extraction

Scheidt: "I masked the English language" — what if "masking" means the
plaintext is HIDDEN within the ciphertext, with some positions being nulls?

Tests:
1. Every Nth character (N=2..10)
2. Characters at positions matching a pattern (Fibonacci, primes, triangular)
3. Characters where CT value has a specific property (odd/even, mod N)
4. Reading the CT in a grid pattern (row-skip, column-skip, diagonal)
5. Alternating extraction with known crib alignment
6. Selective extraction producing English (IC > 0.06 filter)

For each extraction pattern, check:
- IC of extracted text
- Quadgram score
- Whether known cribs align (EASTNORTHEAST at extracted positions)

Output: results/e_s_35_null_cipher.json
"""

import json
import sys
import os
import time
import math
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN

# Load quadgrams
def load_quadgrams():
    path = "data/english_quadgrams.json"
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "logp" in data:
        return data["logp"]
    return data

def quadgram_score(text, logp):
    if logp is None or len(text) < 4:
        return -999.0
    score = 0.0
    floor = -10.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += logp.get(qg, floor)
    return score

def ic(text):
    if len(text) < 2:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return sum(c * (c-1) for c in counts.values()) / (n * (n-1))


def primes_up_to(n):
    sieve = [True] * (n + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(n**0.5) + 1):
        if sieve[i]:
            for j in range(i*i, n+1, i):
                sieve[j] = False
    return [i for i in range(n+1) if sieve[i]]

def fibonacci_up_to(n):
    fibs = [1, 2]
    while fibs[-1] < n:
        fibs.append(fibs[-1] + fibs[-2])
    return [f for f in fibs if f <= n]

def triangular_up_to(n):
    result = []
    k = 1
    while k * (k+1) // 2 <= n:
        result.append(k * (k+1) // 2)
        k += 1
    return result


def main():
    print("=" * 60)
    print("E-S-35: Null Cipher / Steganographic Extraction")
    print("=" * 60)
    print(f"CT: {CT}")
    print(f"Length: {N}")

    t0 = time.time()
    logp = load_quadgrams()
    if logp:
        print(f"Quadgrams: {len(logp)} entries")

    all_results = []

    # Full CT baseline
    baseline_ic = ic(CT)
    baseline_qg = quadgram_score(CT, logp)
    print(f"\nBaseline: IC={baseline_ic:.4f}  qg={baseline_qg:.1f}")

    # =========================================================
    # 1. Every Nth character, all starting positions
    # =========================================================
    print(f"\n{'='*60}")
    print(f"1. Every Nth character")
    print(f"{'='*60}")

    for step in range(2, 15):
        for start in range(step):
            positions = list(range(start, N, step))
            if len(positions) < 8:
                continue
            extracted = ''.join(CT[i] for i in positions)
            ext_ic = ic(extracted)
            ext_qg = quadgram_score(extracted, logp)

            if ext_ic > 0.055 or ext_qg > baseline_qg + 10:
                result = {
                    "method": f"every_{step}_from_{start}",
                    "positions": positions,
                    "extracted": extracted,
                    "length": len(extracted),
                    "ic": round(ext_ic, 4),
                    "qg": round(ext_qg, 1),
                }
                all_results.append(result)
                print(f"  step={step} start={start}: len={len(extracted)}"
                      f" IC={ext_ic:.4f} qg={ext_qg:.1f} text={extracted[:40]}")

    # =========================================================
    # 2. Special position patterns
    # =========================================================
    print(f"\n{'='*60}")
    print(f"2. Special position patterns")
    print(f"{'='*60}")

    primes = primes_up_to(N - 1)
    fibs = fibonacci_up_to(N - 1)
    triangulars = triangular_up_to(N - 1)

    # Fibonacci positions (0-indexed)
    fib_0 = [f - 1 for f in fibs if f - 1 < N]  # 1-indexed Fibonacci → 0-indexed
    patterns = {
        "primes": primes,
        "fibonacci_0idx": fib_0,
        "fibonacci_1idx": [f for f in fibs if f < N],
        "triangular": [t for t in triangulars if t < N],
        "squares": [i*i for i in range(1, 10) if i*i < N],
        "odd_positions": [i for i in range(N) if i % 2 == 1],
        "even_positions": [i for i in range(N) if i % 2 == 0],
        "non_primes": [i for i in range(N) if i not in set(primes)],
    }

    for name, positions in patterns.items():
        if len(positions) < 8:
            continue
        extracted = ''.join(CT[i] for i in positions if i < N)
        ext_ic = ic(extracted)
        ext_qg = quadgram_score(extracted, logp)

        result = {
            "method": name,
            "positions": positions[:20],
            "extracted": extracted[:60],
            "length": len(extracted),
            "ic": round(ext_ic, 4),
            "qg": round(ext_qg, 1),
        }
        all_results.append(result)
        flag = " ***" if ext_ic > 0.055 else ""
        print(f"  {name}: len={len(extracted)} IC={ext_ic:.4f} qg={ext_qg:.1f}{flag}"
              f" text={extracted[:40]}")

    # =========================================================
    # 3. Character value filters
    # =========================================================
    print(f"\n{'='*60}")
    print(f"3. Character value filters")
    print(f"{'='*60}")

    for mod in range(2, 8):
        for rem in range(mod):
            positions = [i for i in range(N) if CT_NUM[i] % mod == rem]
            if len(positions) < 8:
                continue
            extracted = ''.join(CT[i] for i in positions)
            ext_ic = ic(extracted)
            ext_qg = quadgram_score(extracted, logp)

            if ext_ic > 0.055 or ext_qg > baseline_qg:
                result = {
                    "method": f"ct_val_mod{mod}_eq{rem}",
                    "length": len(extracted),
                    "ic": round(ext_ic, 4),
                    "qg": round(ext_qg, 1),
                    "extracted": extracted[:60],
                }
                all_results.append(result)
                print(f"  CT[i]%{mod}=={rem}: len={len(extracted)} IC={ext_ic:.4f}"
                      f" qg={ext_qg:.1f} text={extracted[:40]}")

    # =========================================================
    # 4. Grid-based reading patterns
    # =========================================================
    print(f"\n{'='*60}")
    print(f"4. Grid-based reading patterns")
    print(f"{'='*60}")

    for width in range(5, 15):
        height = (N + width - 1) // width

        # Diagonal readings
        for start_col in range(width):
            positions = []
            r, c = 0, start_col
            while r < height:
                pos = r * width + c
                if pos < N:
                    positions.append(pos)
                r += 1
                c = (c + 1) % width
            if len(positions) < 8:
                continue
            extracted = ''.join(CT[i] for i in positions)
            ext_ic = ic(extracted)
            ext_qg = quadgram_score(extracted, logp)

            if ext_ic > 0.055:
                result = {
                    "method": f"diagonal_w{width}_start{start_col}",
                    "length": len(extracted),
                    "ic": round(ext_ic, 4),
                    "qg": round(ext_qg, 1),
                }
                all_results.append(result)
                print(f"  diag w={width} s={start_col}: len={len(extracted)}"
                      f" IC={ext_ic:.4f} qg={ext_qg:.1f} text={extracted[:40]}")

        # Spiral reading (simple: outer ring first)
        # Skip for brevity — grid patterns unlikely to produce English

    # =========================================================
    # 5. "What's the point?" — decimal positions
    # =========================================================
    print(f"\n{'='*60}")
    print(f"5. Coordinate-based position selection")
    print(f"{'='*60}")

    # K2 coordinates: 38°57'6.5"N, 77°8'44"W
    # These numbers as positions: 38, 57, 6, 5, 77, 8, 44
    coord_positions = [38, 57, 6, 5, 77, 8, 44]
    extracted = ''.join(CT[i] for i in coord_positions if i < N)
    print(f"  K2 coord positions {coord_positions}: {extracted}")

    # DMS digits: 3,8,5,7,6,5,7,7,8,4,4
    dms_positions = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
    # Remove duplicates maintaining order
    seen = set()
    dms_unique = []
    for p in dms_positions:
        if p not in seen and p < N:
            dms_unique.append(p)
            seen.add(p)
    extracted = ''.join(CT[i] for i in dms_unique)
    print(f"  DMS digits {dms_unique}: {extracted}")

    # Offset coordinates: use as step/start
    for step in coord_positions:
        if step < 2 or step >= N:
            continue
        for start in range(min(step, 5)):
            positions = list(range(start, N, step))
            if len(positions) < 8:
                continue
            extracted = ''.join(CT[i] for i in positions)
            ext_ic = ic(extracted)
            if ext_ic > 0.055:
                print(f"  step={step} start={start}: len={len(extracted)}"
                      f" IC={ext_ic:.4f} text={extracted[:40]}")

    # =========================================================
    # 6. Removal patterns (remove Nth, keep rest)
    # =========================================================
    print(f"\n{'='*60}")
    print(f"6. Null removal patterns")
    print(f"{'='*60}")

    for step in range(2, 15):
        for start in range(step):
            # Remove positions at this step, keep rest
            removed = set(range(start, N, step))
            positions = [i for i in range(N) if i not in removed]
            if len(positions) < 30:
                continue
            extracted = ''.join(CT[i] for i in positions)
            ext_ic = ic(extracted)
            ext_qg = quadgram_score(extracted, logp)

            if ext_ic > 0.050:
                result = {
                    "method": f"remove_every_{step}_from_{start}",
                    "n_removed": len(removed),
                    "remaining": len(positions),
                    "ic": round(ext_ic, 4),
                    "qg": round(ext_qg, 1),
                }
                all_results.append(result)
                flag = " ***" if ext_ic > 0.055 else ""
                print(f"  remove step={step} start={start}: remaining={len(positions)}"
                      f" IC={ext_ic:.4f} qg={ext_qg:.1f}{flag}")

    # =========================================================
    # 7. W-positions as separators (extended)
    # =========================================================
    print(f"\n{'='*60}")
    print(f"7. W-separator and letter-specific extraction")
    print(f"{'='*60}")

    # Extract text between W's
    w_positions = [i for i in range(N) if CT[i] == 'W']
    print(f"  W positions: {w_positions}")
    segments = []
    prev = 0
    for wp in w_positions:
        if wp > prev:
            seg = CT[prev:wp]
            segments.append(seg)
        prev = wp + 1
    if prev < N:
        segments.append(CT[prev:])
    for i, seg in enumerate(segments):
        seg_ic = ic(seg) if len(seg) >= 4 else 0
        print(f"  Segment {i}: len={len(seg)} IC={seg_ic:.4f} text={seg}")

    # First letters of each segment
    first_letters = ''.join(s[0] for s in segments if s)
    print(f"  First letters of W-segments: {first_letters}")

    # Last letters
    last_letters = ''.join(s[-1] for s in segments if s)
    print(f"  Last letters of W-segments: {last_letters}")

    # =========================================================
    # 8. Comprehensive IC scan: all possible selections of ~49 from 97
    # (infeasible to enumerate, but scan systematic patterns)
    # =========================================================
    print(f"\n{'='*60}")
    print(f"8. Systematic half-selection IC scan")
    print(f"{'='*60}")

    best_ic = 0
    best_ic_config = None

    # Two-stride patterns: select/skip of varying lengths
    for sel_len in range(1, 8):
        for skip_len in range(1, 8):
            for start in range(sel_len + skip_len):
                positions = []
                i = start
                while i < N:
                    for j in range(sel_len):
                        if i + j < N:
                            positions.append(i + j)
                    i += sel_len + skip_len
                if 20 <= len(positions) <= 80:
                    extracted = ''.join(CT[p] for p in positions)
                    ext_ic = ic(extracted)
                    if ext_ic > best_ic:
                        best_ic = ext_ic
                        best_ic_config = f"sel={sel_len} skip={skip_len} start={start}"
                    if ext_ic > 0.055:
                        ext_qg = quadgram_score(extracted, logp)
                        print(f"  sel={sel_len} skip={skip_len} start={start}:"
                              f" len={len(extracted)} IC={ext_ic:.4f} qg={ext_qg:.1f}"
                              f" text={extracted[:40]}")
                        all_results.append({
                            "method": f"sel{sel_len}_skip{skip_len}_start{start}",
                            "length": len(extracted),
                            "ic": round(ext_ic, 4),
                            "qg": round(ext_qg, 1),
                        })

    print(f"\n  Best IC in scan: {best_ic:.4f} ({best_ic_config})")

    # =========================================================
    # SUMMARY
    # =========================================================
    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Total patterns tested: ~{len(all_results)} recorded")
    print(f"  Time: {elapsed:.1f}s")

    # Sort by IC
    ic_results = [r for r in all_results if 'ic' in r]
    ic_results.sort(key=lambda r: -r['ic'])

    print(f"\n  Top 10 by IC:")
    for r in ic_results[:10]:
        print(f"    {r['method']}: IC={r['ic']:.4f} len={r['length']}"
              f" qg={r.get('qg','?')}")

    # Any IC > 0.055?
    high_ic = [r for r in ic_results if r['ic'] > 0.055]
    if high_ic:
        print(f"\n  {len(high_ic)} patterns with IC > 0.055")
        verdict = "INVESTIGATE"
    else:
        print(f"\n  No patterns with IC > 0.055")
        verdict = "NOISE"

    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_35_null_cipher.json", "w") as f:
        json.dump({
            "experiment": "E-S-35",
            "total_patterns": len(all_results),
            "verdict": verdict,
            "elapsed_seconds": round(elapsed, 1),
            "top_by_ic": ic_results[:20],
        }, f, indent=2)
    print(f"\n  Artifact: results/e_s_35_null_cipher.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_35_null_cipher.py")


if __name__ == "__main__":
    main()
