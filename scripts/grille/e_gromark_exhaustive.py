#!/usr/bin/env python3
"""
Exhaustive Gromark/Vimark Sweep
================================
Cipher:   Gromark (lagged Fibonacci polyalphabetic)
Family:   grille
Status:   active
Keyspace: bases 2-26 × primer lengths 2-7 × keyword alphabets
Last run: never
Best score: n/a

Exhaustively tests all Gromark variants:
  1. For each (keyword_alphabet, cipher_variant), compute required keystream
     at 24 crib positions → determine minimum viable base
  2. For each viable (alphabet, variant, base, primer_length), sweep all B^P
     primers with early crib termination during keystream expansion
  3. Decrypt and score survivors with quadgrams

Key insight: exact crib matching is far stronger than Bean constraints alone.
Most primers are eliminated at the first crib position (pos 21).

Usage:
    PYTHONPATH=src python3 -u scripts/grille/e_gromark_exhaustive.py
    PYTHONPATH=src python3 -u scripts/grille/e_gromark_exhaustive.py --max-base 26 --max-plen 7
    PYTHONPATH=src python3 -u scripts/grille/e_gromark_exhaustive.py --alphabets keyword  # use Bean keyword alphabets
    PYTHONPATH=src python3 -u scripts/grille/e_gromark_exhaustive.py --alphabets full      # use full wordlist

Output:
    results/gromark_exhaustive/summary.json
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
CT_LEN = 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

# Build sorted crib entries: (position, pt_char, ct_char)
_CRIB_ENTRIES = []
for _s, _t in CRIBS:
    for _j, _c in enumerate(_t):
        _CRIB_ENTRIES.append((_s + _j, _c, CT[_s + _j]))
_CRIB_ENTRIES.sort()
CRIB_POSITIONS = [e[0] for e in _CRIB_ENTRIES]
CRIB_PT = [e[1] for e in _CRIB_ENTRIES]
CRIB_CT = [e[2] for e in _CRIB_ENTRIES]
N_CRIBS = len(CRIB_POSITIONS)

# ---------------------------------------------------------------------------
# Alphabet construction
# ---------------------------------------------------------------------------

def keyword_alphabet(kw):
    seen = set()
    alpha = []
    for ch in kw.upper():
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            alpha.append(ch)
    for ch in AZ:
        if ch not in seen:
            seen.add(ch)
            alpha.append(ch)
    return "".join(alpha)


def compute_required_keys(alphabet, variant):
    """Required keystream values at each sorted crib position."""
    required = []
    for i in range(N_CRIBS):
        cn = alphabet.index(CRIB_CT[i])
        pn = alphabet.index(CRIB_PT[i])
        if variant == "vig":
            k = (cn - pn) % 26
        elif variant == "beau":
            k = (cn + pn) % 26
        elif variant == "varbeau":
            k = (pn - cn) % 26
        else:
            raise ValueError(variant)
        required.append(k)
    return required


# ---------------------------------------------------------------------------
# Quadgram scoring (loaded per worker)
# ---------------------------------------------------------------------------
_QG = None
_QG_FLOOR = -10.0


def _ensure_qg():
    global _QG, _QG_FLOOR
    if _QG is not None:
        return
    qg_path = Path(__file__).resolve().parent.parent / "data" / "english_quadgrams.json"
    if not qg_path.exists():
        qg_path = Path(__file__).resolve().parent.parent.parent / "data" / "english_quadgrams.json"
    with open(qg_path) as f:
        _QG = json.load(f)
    _QG_FLOOR = min(_QG.values()) - 1.0


def qg_score(text):
    _ensure_qg()
    s = 0.0
    n = len(text) - 3
    for i in range(n):
        s += _QG.get(text[i:i + 4], _QG_FLOOR)
    return s / max(1, n) if n > 0 else _QG_FLOOR


# ---------------------------------------------------------------------------
# Worker: sweep primers for one (alphabet, variant, base, plen) combo
# ---------------------------------------------------------------------------

def worker_sweep(args):
    """Sweep a chunk of primers. Returns dict with stats and top results."""
    (base, plen, start_int, end_int,
     crib_positions, required_keys,
     ct_nums, alphabet, variant, alpha_label) = args

    _ensure_qg()

    n_tested = 0
    n_crib_pass = 0
    top_results = []
    TOP_K = 5
    ENGLISH_THRESHOLD = -5.5  # reasonable English

    for primer_int in range(start_int, end_int):
        # Decode primer integer to base-B digits
        primer = [0] * plen
        n = primer_int
        for d in range(plen - 1, -1, -1):
            primer[d] = n % base
            n //= base

        # Expand keystream with early crib termination
        k = list(primer)
        crib_idx = 0
        failed = False

        # Check any crib positions within the primer (plen > 21 only)
        while crib_idx < N_CRIBS and crib_positions[crib_idx] < plen:
            if k[crib_positions[crib_idx]] != required_keys[crib_idx]:
                failed = True
                break
            crib_idx += 1

        if not failed:
            # Expand keystream position by position
            while len(k) < CT_LEN:
                k.append((k[-plen] + k[-(plen - 1)]) % base)
                pos = len(k) - 1

                # Check crib(s) at this position
                while crib_idx < N_CRIBS and crib_positions[crib_idx] == pos:
                    if k[pos] != required_keys[crib_idx]:
                        failed = True
                        break
                    crib_idx += 1
                if failed:
                    break

        n_tested += 1

        if not failed and len(k) >= CT_LEN:
            n_crib_pass += 1
            # Decrypt
            pt_chars = []
            for i in range(CT_LEN):
                c = ct_nums[i]
                kv = k[i]
                if variant == "vig":
                    p = (c - kv) % 26
                elif variant == "beau":
                    p = (kv - c) % 26
                else:  # varbeau
                    p = (c + kv) % 26
                pt_chars.append(alphabet[p])
            pt_text = "".join(pt_chars)
            score = qg_score(pt_text)

            primer_str = "".join(str(d) for d in primer)
            method = f"gromark/b{base}/p{plen}/{variant}/{alpha_label}/{primer_str}"

            top_results.append((score, pt_text, primer_str, method))
            top_results.sort(key=lambda x: -x[0])
            top_results = top_results[:TOP_K]

    return {
        "base": base,
        "plen": plen,
        "variant": variant,
        "alpha": alpha_label,
        "start": start_int,
        "end": end_int,
        "n_tested": n_tested,
        "n_crib_pass": n_crib_pass,
        "top": top_results,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Exhaustive Gromark sweep")
    parser.add_argument("--min-base", type=int, default=2)
    parser.add_argument("--max-base", type=int, default=26)
    parser.add_argument("--min-plen", type=int, default=2)
    parser.add_argument("--max-plen", type=int, default=7)
    parser.add_argument("--workers", type=int, default=0, help="0 = all CPUs")
    parser.add_argument("--chunk-size", type=int, default=500_000,
                        help="Primers per worker chunk")
    parser.add_argument("--alphabets", choices=["standard", "keyword", "full"],
                        default="standard",
                        help="standard=AZ+KA, keyword=+Bean keywords, full=+entire wordlist")
    args = parser.parse_args()

    num_workers = args.workers or cpu_count()
    out_dir = Path(__file__).resolve().parent.parent.parent / "results" / "gromark_exhaustive"
    os.makedirs(out_dir, exist_ok=True)

    # Build alphabet list
    alphabets = [("AZ", AZ), ("KA", KA)]
    if args.alphabets in ("keyword", "full"):
        wl_path = (Path(__file__).resolve().parent.parent.parent /
                   "results" / "bean_keywords" / "bean_keywords_wordlist.txt")
        if wl_path.exists():
            seen_alphas = {AZ, KA}
            with open(wl_path) as f:
                for line in f:
                    kw = line.strip()
                    if kw:
                        alpha = keyword_alphabet(kw)
                        if alpha not in seen_alphas:
                            seen_alphas.add(alpha)
                            alphabets.append((kw, alpha))
            print(f"Loaded {len(alphabets)} distinct alphabets (AZ + KA + {len(alphabets)-2} keyword)")
    if args.alphabets == "full":
        wl_path = Path(__file__).resolve().parent.parent.parent / "wordlists" / "english.txt"
        if wl_path.exists():
            seen_alphas = {a for _, a in alphabets}
            added = 0
            with open(wl_path) as f:
                for line in f:
                    kw = line.strip().upper()
                    if kw and kw.isalpha() and len(kw) >= 3:
                        alpha = keyword_alphabet(kw)
                        if alpha not in seen_alphas:
                            seen_alphas.add(alpha)
                            alphabets.append((kw, alpha))
                            added += 1
            print(f"Added {added} more alphabets from full wordlist (total: {len(alphabets)})")

    VARIANTS = ["vig", "beau", "varbeau"]

    # Phase 1: Precompute all combos and check viability
    print(f"\nGromark Exhaustive Sweep")
    print(f"  Bases: {args.min_base}-{args.max_base}")
    print(f"  Primer lengths: {args.min_plen}-{args.max_plen}")
    print(f"  Alphabets: {len(alphabets)}")
    print(f"  Workers: {num_workers}")
    print()

    combos = []  # (alpha_label, alpha, variant, base, plen, required_keys, min_base)
    combo_stats = defaultdict(int)

    for alpha_label, alpha in alphabets:
        ct_nums = [alpha.index(ch) for ch in CT]
        for variant in VARIANTS:
            required = compute_required_keys(alpha, variant)
            min_base = max(required) + 1

            for base in range(max(args.min_base, min_base), args.max_base + 1):
                for plen in range(args.min_plen, args.max_plen + 1):
                    total_primers = base ** plen
                    combos.append({
                        "alpha_label": alpha_label,
                        "alpha": alpha,
                        "variant": variant,
                        "base": base,
                        "plen": plen,
                        "required": required,
                        "ct_nums": ct_nums,
                        "total_primers": total_primers,
                    })
                    combo_stats[(base, plen)] += 1

    total_primers = sum(c["total_primers"] for c in combos)
    print(f"  Viable combos: {len(combos)}")
    print(f"  Total primers to test: {total_primers:,}")
    print()

    # Show combo distribution
    print(f"  {'Base':>5} {'PLen':>5} {'#Combos':>8} {'Primers/combo':>14} {'Total':>14}")
    print("  " + "-" * 50)
    for base in range(args.min_base, args.max_base + 1):
        for plen in range(args.min_plen, args.max_plen + 1):
            nc = combo_stats.get((base, plen), 0)
            if nc > 0:
                per = base ** plen
                print(f"  {base:5d} {plen:5d} {nc:8d} {per:14,d} {nc * per:14,d}")
    print()

    # Phase 2: Build work items (chunk large combos)
    work_items = []
    for combo in combos:
        total = combo["total_primers"]
        alpha_label = combo["alpha_label"]
        alpha = combo["alpha"]
        ct_nums = combo["ct_nums"]
        variant = combo["variant"]
        base = combo["base"]
        plen = combo["plen"]
        required = combo["required"]

        if total <= args.chunk_size:
            work_items.append((
                base, plen, 0, total,
                CRIB_POSITIONS, required,
                ct_nums, alpha, variant, alpha_label
            ))
        else:
            for start in range(0, total, args.chunk_size):
                end = min(start + args.chunk_size, total)
                work_items.append((
                    base, plen, start, end,
                    CRIB_POSITIONS, required,
                    ct_nums, alpha, variant, alpha_label
                ))

    print(f"  Work items: {len(work_items)} (chunk size: {args.chunk_size:,})")
    print()

    # Phase 3: Execute
    t0 = time.time()
    all_results = []
    total_tested = 0
    total_crib_pass = 0
    global_top = []

    print("Sweeping...", flush=True)
    with Pool(num_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(worker_sweep, work_items)):
            total_tested += result["n_tested"]
            total_crib_pass += result["n_crib_pass"]

            for entry in result["top"]:
                global_top.append(entry)
                global_top.sort(key=lambda x: -x[0])
                global_top = global_top[:20]

            if result["n_crib_pass"] > 0:
                print(f"  CRIB MATCH: b{result['base']}/p{result['plen']}/{result['variant']}/{result['alpha']} "
                      f"— {result['n_crib_pass']} primers passed all 24 crib positions!", flush=True)
                for score, pt, primer, method in result["top"]:
                    print(f"    score={score:.2f} primer={primer} PT={pt[:40]}...", flush=True)

            if (i + 1) % 100 == 0 or (i + 1) == len(work_items):
                elapsed = time.time() - t0
                rate = total_tested / max(0.001, elapsed)
                pct = 100.0 * (i + 1) / len(work_items)
                print(f"  [{pct:5.1f}%] {total_tested:,} tested, {total_crib_pass} crib-pass, "
                      f"{rate:,.0f} primers/sec, {elapsed:.1f}s elapsed", flush=True)

    elapsed = time.time() - t0
    rate = total_tested / max(0.001, elapsed)

    # Phase 4: Report
    print(f"\n{'=' * 60}")
    print(f"GROMARK EXHAUSTIVE SWEEP — COMPLETE")
    print(f"{'=' * 60}")
    print(f"  Primers tested:  {total_tested:,}")
    print(f"  Crib-pass:       {total_crib_pass}")
    print(f"  Elapsed:         {elapsed:.1f}s")
    print(f"  Rate:            {rate:,.0f} primers/sec")
    print()

    if total_crib_pass == 0:
        print("  RESULT: NO Gromark primer produces correct cribs at any tested")
        print("  (alphabet, variant, base, primer_length) combination.")
        print("  Gromark is ELIMINATED for the tested parameter space.")
    else:
        print(f"  RESULT: {total_crib_pass} primer(s) produce correct cribs!")
        print("  Top results by quadgram score:")
        for score, pt, primer, method in global_top[:20]:
            print(f"    {score:+.2f}  {method}")
            print(f"           PT={pt}")

    # Save summary
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "params": {
            "min_base": args.min_base,
            "max_base": args.max_base,
            "min_plen": args.min_plen,
            "max_plen": args.max_plen,
            "alphabets": args.alphabets,
            "n_alphabets": len(alphabets),
            "n_combos": len(combos),
            "chunk_size": args.chunk_size,
            "workers": num_workers,
        },
        "results": {
            "total_tested": total_tested,
            "total_crib_pass": total_crib_pass,
            "elapsed_seconds": round(elapsed, 2),
            "rate_per_sec": round(rate),
            "top": [
                {"score": s, "plaintext": p, "primer": pr, "method": m}
                for s, p, pr, m in global_top
            ],
        },
    }
    summary_path = out_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Summary: {summary_path}")


if __name__ == "__main__":
    main()
