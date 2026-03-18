#!/usr/bin/env python3
"""
Gromark/Vimark on 73-char null-extracted K4
=============================================
Cipher:   Gromark (lagged Fibonacci polyalphabetic)
Family:   grille
Status:   active
Keyspace: bases 2-26 x primer lengths 2-8 x 6 (alpha,variant) combos x +/- col7
Last run: never
Best score: n/a

Tests Gromark on the 73-char null-extracted CT rather than raw 97.
Bean tested Gromark only on raw 97 (3.2B primers, 0 survivors).
The two-system model means the cipher operates AFTER null extraction,
so the 73-char text is the correct input.

Uses the consensus null mask from the 15/24 DEFECTOR:AZ_beau model:
  MASK = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]

Shifted cribs in 73-char text:
  ENE: positions 13-25  (EASTNORTHEAST)
  BCL: positions 47-57  (BERLINCLOCK)

Tests:
  1. Standard scan: bases 2-26, primer lengths 2-7, AZ+KA, vig/beau/varbeau
  2. With col7 undo applied first (73-char -> undo col7 -> Gromark decrypt)
  3. Named primers: DYAHR, SEVEN, FIVE, KRYPTOS, DEFECTOR, etc.
  4. Various bases: 3,4,5,6,7,8,10,12,13,24,26

Usage:
    PYTHONPATH=src python3 -u scripts/grille/e_gromark_73char.py
    PYTHONPATH=src python3 -u scripts/grille/e_gromark_73char.py --max-base 26 --max-plen 8
    PYTHONPATH=src python3 -u scripts/grille/e_gromark_73char.py --col7-only
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
CT97 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
MASK = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59, 74, 75, 78, 84, 85, 88, 94, 96]
MASK_SET = set(MASK)

# Extract 73-char CT
CT73 = "".join(CT97[i] for i in range(97) if i not in MASK_SET)
CT73_LEN = len(CT73)  # 73
assert CT73_LEN == 73, f"Expected 73, got {CT73_LEN}"

# Map raw positions to 73-char positions
RAW_TO_73 = {}
j = 0
for i in range(97):
    if i not in MASK_SET:
        RAW_TO_73[i] = j
        j += 1

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Build shifted crib entries: (position_in_73, pt_char, ct_char)
_CRIB_ENTRIES = []
for start, text in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
    for k, ch in enumerate(text):
        raw_pos = start + k
        if raw_pos not in MASK_SET:
            pos73 = RAW_TO_73[raw_pos]
            _CRIB_ENTRIES.append((pos73, ch, CT73[pos73]))
_CRIB_ENTRIES.sort()
CRIB_POSITIONS = [e[0] for e in _CRIB_ENTRIES]
CRIB_PT = [e[1] for e in _CRIB_ENTRIES]
CRIB_CT = [e[2] for e in _CRIB_ENTRIES]
N_CRIBS = len(_CRIB_ENTRIES)
assert N_CRIBS == 24, f"Expected 24 cribs, got {N_CRIBS}"

# Col7 transposition on 73-char text
def col7_perm(n):
    """Column-reading permutation for width 7 on n chars."""
    ncols = 7
    nrows_full = n // ncols
    extra = n % ncols
    perm = []
    for col in range(ncols):
        rows = nrows_full + (1 if col < extra else 0)
        for row in range(rows):
            perm.append(row * ncols + col)
    return perm

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def apply_perm(text, perm):
    return "".join(text[perm[i]] for i in range(len(perm)))


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


def compute_required_keys(alphabet, variant, ct_text, crib_positions, crib_pt, crib_ct):
    """Required keystream values at each sorted crib position."""
    required = []
    for i in range(len(crib_positions)):
        cn = alphabet.index(crib_ct[i])
        pn = alphabet.index(crib_pt[i])
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
    qg_path = Path(__file__).resolve().parent.parent.parent / "data" / "english_quadgrams.json"
    if not qg_path.exists():
        qg_path = Path(__file__).resolve().parent.parent / "data" / "english_quadgrams.json"
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
     ct_nums, alphabet, variant, alpha_label,
     text_len) = args

    _ensure_qg()

    n_tested = 0
    n_crib_pass = 0
    top_results = []
    TOP_K = 5

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

        # Check any crib positions within the primer
        while crib_idx < len(crib_positions) and crib_positions[crib_idx] < plen:
            if k[crib_positions[crib_idx]] != required_keys[crib_idx]:
                failed = True
                break
            crib_idx += 1

        if not failed:
            # Expand keystream position by position
            while len(k) < text_len:
                k.append((k[-plen] + k[-(plen - 1)]) % base)
                pos = len(k) - 1

                # Check crib(s) at this position
                while crib_idx < len(crib_positions) and crib_positions[crib_idx] == pos:
                    if k[pos] != required_keys[crib_idx]:
                        failed = True
                        break
                    crib_idx += 1
                if failed:
                    break

        n_tested += 1

        if not failed and len(k) >= text_len:
            n_crib_pass += 1
            # Decrypt
            pt_chars = []
            for i in range(text_len):
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

            primer_str = ",".join(str(d) for d in primer)
            method = f"gromark73/b{base}/p{plen}/{variant}/{alpha_label}/[{primer_str}]"

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
# Named primer tests
# ---------------------------------------------------------------------------

def test_named_primers(ct_text, crib_positions, crib_pt, crib_ct, alphabets, col7_label=""):
    """Test specific named primers across all alphabets and variants."""
    text_len = len(ct_text)

    named_primers = {
        # Name -> list of (base, primer_digits)
        "DYAHR_b26": (26, [3, 24, 0, 7, 17]),
        "SEVEN_b26": (26, [18, 4, 21, 4, 13]),
        "FIVE_b26": (26, [5, 8, 21, 4]),
        "KRYPTOS_b26": (26, [10, 17, 24, 15, 19, 14, 18]),
        "DEFECTOR_b26": (26, [3, 4, 5, 4, 2, 19, 14, 17]),
        "CLOCK_b26": (26, [2, 11, 14, 2, 10]),
        "BERLIN_b26": (26, [1, 4, 17, 11, 8, 13]),
        "PALIMPSEST_b26": (26, [15, 0, 11, 8, 12, 15, 18, 4, 18, 19]),
        "ABSCISSA_b26": (26, [0, 1, 18, 2, 8, 18, 18, 0]),
        "KOMPASS_b26": (26, [10, 14, 12, 15, 0, 18, 18]),
        "SHADOW_b26": (26, [18, 7, 0, 3, 14, 22]),
        "CARTER_b26": (26, [2, 0, 17, 19, 4, 17]),
        # Base 5
        "12345_b5": (5, [1, 2, 3, 4, 0]),
        "11111_b5": (5, [1, 1, 1, 1, 1]),
        "01234_b5": (5, [0, 1, 2, 3, 4]),
        # Base 10
        "31415_b10": (10, [3, 1, 4, 1, 5]),
        "27182_b10": (10, [2, 7, 1, 8, 2]),
        "73241_b10": (10, [7, 3, 2, 4, 1]),
        "24731_b10": (10, [2, 4, 7, 3, 1]),
        # DYAHR in KA order
        "DYAHR_KA_b26": (26, [KA.index(c) for c in "DYAHR"]),
    }

    results = []
    variants = ["vig", "beau", "varbeau"]

    for primer_name, (base, primer) in named_primers.items():
        for alpha_label, alpha in alphabets:
            required = compute_required_keys(alpha, "vig", ct_text, crib_positions, crib_pt, crib_ct)
            min_base = max(required) + 1

            for variant in variants:
                req = compute_required_keys(alpha, variant, ct_text, crib_positions, crib_pt, crib_ct)
                mb = max(req) + 1
                if base < mb:
                    continue  # Base too small for this variant

                # Expand keystream
                k = list(primer)
                plen = len(primer)
                while len(k) < text_len:
                    k.append((k[-plen] + k[-(plen - 1)]) % base)

                # Check cribs
                matches = 0
                for i in range(len(crib_positions)):
                    if k[crib_positions[i]] == req[i]:
                        matches += 1

                ct_nums = [alpha.index(ch) for ch in ct_text]
                # Decrypt
                pt_chars = []
                for i in range(text_len):
                    c = ct_nums[i]
                    kv = k[i]
                    if variant == "vig":
                        p = (c - kv) % 26
                    elif variant == "beau":
                        p = (kv - c) % 26
                    else:
                        p = (c + kv) % 26
                    pt_chars.append(alpha[p])
                pt_text = "".join(pt_chars)

                if matches >= 6:
                    results.append({
                        "name": primer_name,
                        "alpha": alpha_label,
                        "variant": variant,
                        "crib_matches": matches,
                        "plaintext": pt_text[:40],
                        "col7": col7_label,
                    })
                    print(f"  Named primer {primer_name} {alpha_label}:{variant}{col7_label}: "
                          f"{matches}/24 cribs, PT={pt_text[:30]}...")

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Gromark on 73-char null-extracted K4")
    parser.add_argument("--min-base", type=int, default=2)
    parser.add_argument("--max-base", type=int, default=26)
    parser.add_argument("--min-plen", type=int, default=2)
    parser.add_argument("--max-plen", type=int, default=7)
    parser.add_argument("--workers", type=int, default=0, help="0 = all CPUs")
    parser.add_argument("--chunk-size", type=int, default=500_000)
    parser.add_argument("--col7-only", action="store_true", help="Only test with col7 undo")
    parser.add_argument("--named-only", action="store_true", help="Only test named primers")
    parser.add_argument("--max-total", type=int, default=0,
                        help="Max total primers to test (0=unlimited, for time-boxing)")
    args = parser.parse_args()

    num_workers = args.workers or min(cpu_count(), 8)  # Cap at 8 to leave cores
    out_dir = Path(__file__).resolve().parent.parent.parent / "results" / "gromark_73char"
    os.makedirs(out_dir, exist_ok=True)

    # Build alphabet list
    alphabets = [("AZ", AZ), ("KA", KA)]
    VARIANTS = ["vig", "beau", "varbeau"]

    # Prepare two text variants: direct 73-char and col7-undone 73-char
    perm7 = col7_perm(73)
    inv_perm7 = invert_perm(perm7)
    ct73_col7 = apply_perm(CT73, inv_perm7)  # Undo col7

    text_variants = []
    if not args.col7_only:
        text_variants.append(("direct", CT73))
    text_variants.append(("col7undo", ct73_col7))
    if not args.col7_only:
        # Also try col7 in the other direction
        ct73_col7_fwd = apply_perm(CT73, perm7)
        text_variants.append(("col7fwd", ct73_col7_fwd))

    print("=" * 70)
    print("GROMARK ON 73-CHAR NULL-EXTRACTED K4")
    print("=" * 70)
    print(f"  CT73 (direct): {CT73}")
    print(f"  CT73 (col7 undo): {ct73_col7}")
    print(f"  Crib positions (73-char): {CRIB_POSITIONS}")
    print(f"  Number of cribs: {N_CRIBS}")
    print()

    # Phase 0: Named primers
    print("--- Phase 0: Named Primer Tests ---")
    all_named_results = []
    for text_label, text in text_variants:
        if text_label == "direct":
            cpos, cpt, cct = CRIB_POSITIONS, CRIB_PT, CRIB_CT
        else:
            # For transposed text, crib positions shift
            # We need to find where each crib char ends up after transposition
            if text_label == "col7undo":
                # After undoing col7, position i in undone text = text at inv_perm7[i]
                # So crib at pos p in direct text -> same pos p in direct text
                # But the TEXT changed, not the positions. The cribs are properties of the plaintext.
                # The cipher operates on the pre-transposition text.
                # Actually: if model is null_extract -> col7 -> gromark_encrypt -> ct73
                # then decrypt is: ct73 -> gromark_decrypt -> undo_col7 -> plaintext
                # So cribs should appear in the FINAL plaintext, not at any intermediate step.
                # For our purposes: we test if gromark(ct73_col7_undone) produces cribs at positions.
                # But the crib positions in the gromark-decrypted text should be the col7-permuted crib positions.
                # This is getting complex. Let me think...

                # Model: PT73 -> col7_encrypt -> intermediate -> gromark_encrypt -> CT73
                # Decrypt: CT73 -> gromark_decrypt(key) -> intermediate -> col7_decrypt -> PT73
                # Cribs are in PT73 at positions 13-25, 47-57.
                # In intermediate (after col7_encrypt), they are at perm7[13], perm7[14], etc.
                # The gromark operates on intermediate, so the "crib positions" for gromark
                # are the col7-permuted positions.

                mapped_crib_entries = []
                for pos73, pt_ch, _ in _CRIB_ENTRIES:
                    new_pos = perm7[pos73]  # Where this position ends up after col7
                    new_ct = CT73[new_pos]  # CT character at that position
                    mapped_crib_entries.append((new_pos, pt_ch, new_ct))
                mapped_crib_entries.sort()
                cpos = [e[0] for e in mapped_crib_entries]
                cpt = [e[1] for e in mapped_crib_entries]
                cct = [e[2] for e in mapped_crib_entries]
            elif text_label == "col7fwd":
                mapped_crib_entries = []
                for pos73, pt_ch, _ in _CRIB_ENTRIES:
                    new_pos = inv_perm7[pos73]
                    new_ct = CT73[new_pos] if new_pos < len(CT73) else '?'
                    mapped_crib_entries.append((new_pos, pt_ch, new_ct))
                mapped_crib_entries.sort()
                cpos = [e[0] for e in mapped_crib_entries]
                cpt = [e[1] for e in mapped_crib_entries]
                cct = [e[2] for e in mapped_crib_entries]
            else:
                cpos, cpt, cct = CRIB_POSITIONS, CRIB_PT, CRIB_CT

        print(f"\n  Text variant: {text_label}")
        named = test_named_primers(text, cpos, cpt, cct, alphabets, f"({text_label})")
        all_named_results.extend(named)

    if args.named_only:
        print("\n  Named-only mode, skipping exhaustive sweep.")
        summary = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "mode": "named_only",
            "named_results": all_named_results,
        }
        with open(out_dir / "named_primers.json", "w") as f:
            json.dump(summary, f, indent=2)
        return

    # Phase 1: Exhaustive sweep
    t0 = time.time()

    all_summary = {}

    for text_label, ct_text in text_variants:
        if text_label == "direct":
            cpos, cpt, cct = CRIB_POSITIONS, CRIB_PT, CRIB_CT
        elif text_label == "col7undo":
            mapped_crib_entries = []
            for pos73, pt_ch, _ in _CRIB_ENTRIES:
                new_pos = perm7[pos73]
                new_ct = CT73[new_pos]
                mapped_crib_entries.append((new_pos, pt_ch, new_ct))
            mapped_crib_entries.sort()
            cpos = [e[0] for e in mapped_crib_entries]
            cpt = [e[1] for e in mapped_crib_entries]
            cct = [e[2] for e in mapped_crib_entries]
        elif text_label == "col7fwd":
            mapped_crib_entries = []
            for pos73, pt_ch, _ in _CRIB_ENTRIES:
                new_pos = inv_perm7[pos73]
                new_ct = CT73[new_pos] if new_pos < len(CT73) else '?'
                mapped_crib_entries.append((new_pos, pt_ch, new_ct))
            mapped_crib_entries.sort()
            cpos = [e[0] for e in mapped_crib_entries]
            cpt = [e[1] for e in mapped_crib_entries]
            cct = [e[2] for e in mapped_crib_entries]

        print(f"\n{'='*70}")
        print(f"EXHAUSTIVE SWEEP: {text_label}")
        print(f"{'='*70}")
        print(f"  Text: {ct_text[:40]}...")
        print(f"  Crib positions: {cpos}")

        combos = []
        combo_stats = defaultdict(int)

        for alpha_label, alpha in alphabets:
            ct_nums = [alpha.index(ch) for ch in ct_text]
            for variant in VARIANTS:
                required = compute_required_keys(alpha, variant, ct_text, cpos, cpt, cct)
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

        # Apply max-total cap
        if args.max_total > 0 and total_primers > args.max_total:
            # Filter to smaller combos only
            combos_filtered = []
            running = 0
            for c in sorted(combos, key=lambda x: x["total_primers"]):
                if running + c["total_primers"] <= args.max_total:
                    combos_filtered.append(c)
                    running += c["total_primers"]
            combos = combos_filtered
            total_primers = sum(c["total_primers"] for c in combos)
            print(f"  (Capped to {total_primers:,} primers, {len(combos)} combos)")

        print(f"  Viable combos: {len(combos)}")
        print(f"  Total primers to test: {total_primers:,}")

        # Show combo distribution
        print(f"\n  {'Base':>5} {'PLen':>5} {'#Combos':>8} {'Primers/combo':>14} {'Total':>14}")
        print("  " + "-" * 50)
        for base in range(args.min_base, args.max_base + 1):
            for plen in range(args.min_plen, args.max_plen + 1):
                nc = combo_stats.get((base, plen), 0)
                if nc > 0:
                    per = base ** plen
                    print(f"  {base:5d} {plen:5d} {nc:8d} {per:14,d} {nc * per:14,d}")

        # Build work items
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

            chunk = args.chunk_size
            if total <= chunk:
                work_items.append((
                    base, plen, 0, total,
                    cpos, required,
                    ct_nums, alpha, variant, alpha_label,
                    CT73_LEN
                ))
            else:
                for start in range(0, total, chunk):
                    end = min(start + chunk, total)
                    work_items.append((
                        base, plen, start, end,
                        cpos, required,
                        ct_nums, alpha, variant, alpha_label,
                        CT73_LEN
                    ))

        print(f"\n  Work items: {len(work_items)} (chunk size: {args.chunk_size:,})")
        print()

        # Execute
        sweep_t0 = time.time()
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
                    print(f"  *** CRIB MATCH: b{result['base']}/p{result['plen']}/{result['variant']}/{result['alpha']} "
                          f"-- {result['n_crib_pass']} primers passed ALL 24 crib positions!", flush=True)
                    for score, pt, primer, method in result["top"]:
                        print(f"      score={score:.2f} primer=[{primer}] PT={pt[:50]}...", flush=True)

                if (i + 1) % 200 == 0 or (i + 1) == len(work_items):
                    elapsed = time.time() - sweep_t0
                    rate = total_tested / max(0.001, elapsed)
                    pct = 100.0 * (i + 1) / len(work_items)
                    print(f"  [{pct:5.1f}%] {total_tested:,} tested, {total_crib_pass} crib-pass, "
                          f"{rate:,.0f} primers/sec, {elapsed:.1f}s elapsed", flush=True)

        elapsed = time.time() - sweep_t0
        rate = total_tested / max(0.001, elapsed)

        print(f"\n  {text_label} COMPLETE: {total_tested:,} tested, {total_crib_pass} crib-pass, {elapsed:.1f}s")

        if total_crib_pass > 0:
            print(f"\n  *** SURVIVORS FOUND: {total_crib_pass} ***")
            for score, pt, primer, method in global_top[:10]:
                print(f"    {score:+.3f}  {method}")
                print(f"           PT={pt}")
        else:
            print(f"  RESULT: ZERO crib-pass. Gromark ELIMINATED for {text_label} on 73-char text.")

        all_summary[text_label] = {
            "total_tested": total_tested,
            "total_crib_pass": total_crib_pass,
            "elapsed_seconds": round(elapsed, 2),
            "rate_per_sec": round(rate),
            "top": [
                {"score": s, "plaintext": p, "primer": pr, "method": m}
                for s, p, pr, m in global_top
            ],
        }

    total_elapsed = time.time() - t0

    # Final summary
    print(f"\n{'='*70}")
    print("FINAL SUMMARY")
    print(f"{'='*70}")

    grand_total_tested = sum(v["total_tested"] for v in all_summary.values())
    grand_total_crib_pass = sum(v["total_crib_pass"] for v in all_summary.values())

    for label, data in all_summary.items():
        print(f"  {label}: {data['total_tested']:,} tested, {data['total_crib_pass']} crib-pass")

    print(f"\n  Grand total: {grand_total_tested:,} tested, {grand_total_crib_pass} crib-pass")
    print(f"  Total elapsed: {total_elapsed:.1f}s")

    if grand_total_crib_pass == 0:
        print("\n  CONCLUSION: Gromark on 73-char null-extracted K4 is ELIMINATED")
        print("  for all tested (base, primer_length, alphabet, variant) combinations.")
    else:
        print(f"\n  CONCLUSION: {grand_total_crib_pass} survivor(s) found! Investigate.")

    # Save
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "experiment": "gromark_73char",
        "description": "Gromark/Vimark on 73-char null-extracted K4 (two-system model)",
        "null_mask": MASK,
        "ct73": CT73,
        "crib_positions_73": CRIB_POSITIONS,
        "params": {
            "min_base": args.min_base,
            "max_base": args.max_base,
            "min_plen": args.min_plen,
            "max_plen": args.max_plen,
            "n_alphabets": len(alphabets),
            "workers": num_workers,
        },
        "text_variants": list(all_summary.keys()),
        "results": all_summary,
        "grand_total_tested": grand_total_tested,
        "grand_total_crib_pass": grand_total_crib_pass,
        "total_elapsed_seconds": round(total_elapsed, 2),
        "named_primer_results": all_named_results,
    }
    summary_path = out_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Summary: {summary_path}")


if __name__ == "__main__":
    main()
