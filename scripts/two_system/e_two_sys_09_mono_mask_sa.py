#!/usr/bin/env python3
# Cipher:     Two-system Model A (monoalphabetic substitution + null mask SA)
# Family:     two_system
# Status:     active
# Keyspace:   704 keywords × 2 bases × 8 restarts × 100K SA iters
# Last run:
# Best score:
#
# E-TWO-SYS-09: Monoalphabetic substitution + null mask SA.
#
# HYPOTHESIS: Sanborn said "I did NOT use that table" (Vigenère tableau).
# K4's substitution layer might be MONOALPHABETIC — a simple keyword-mixed
# alphabet used as a direct letter-for-letter substitution. Combined with
# a null mask (the Cardan grille / "second system"), this is:
#   - Hand-executable (just a substitution table)
#   - "Much more difficult" when combined with transposition/nulls
#   - Consistent with "two systems of encipherment"
#   - Consistent with Scheidt's 10-year solvability estimate
#
# For each keyword, we build a keyword-mixed alphabet and use it as a
# monoalphabetic cipher: PT[i] = alphabet[CT[i]'s position in standard AZ]
# (or the reverse mapping). SA searches for the null mask.
#
# Also tests: Porta cipher, Atbash, affine, and Caesar shifts.
from __future__ import annotations

import bisect
import math
import os
import random
import sys
import time
import multiprocessing as mp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet

# ── Constants ─────────────────────────────────────────────────────────────

N_NULLS = 24
CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"
CRIB_LIST = sorted(CRIB_DICT.items())

SA_ITERATIONS = 100_000
SA_RESTARTS = 8
SA_T_INIT = 2.0
SA_T_MIN = 0.01
SA_COOLING = 0.99997

REPORT_THRESHOLD = 8
N_WORKERS = min(28, os.cpu_count() or 4)


# ── Build substitution tables ────────────────────────────────────────────

def build_mono_tables(keyword, base=ALPH):
    """Build monoalphabetic substitution tables from a keyword-mixed alphabet.

    Returns list of (name, decrypt_table) where decrypt_table[i] gives
    the plaintext letter index for ciphertext letter index i.

    We test multiple interpretations:
      1. Forward: CT position in base → mixed alphabet letter (mixed[base_idx(CT)])
      2. Reverse: CT position in mixed → base alphabet letter (base[mixed_idx(CT)])
      3. Atbash-mixed: reversed mixed alphabet
    """
    mixed = keyword_mixed_alphabet(keyword, base)
    base_label = "KA" if base == KRYPTOS_ALPHABET else "AZ"

    # Index lookups
    base_idx = [0] * 26
    for i, c in enumerate(base):
        base_idx[ord(c) - 65] = i

    mixed_idx = [0] * 26
    for i, c in enumerate(mixed):
        mixed_idx[ord(c) - 65] = i

    tables = []

    # Forward: plaintext = mixed[base_index(ciphertext)]
    # i.e., find CT's position in base alphabet, read mixed alphabet at that position
    fwd = [0] * 26
    for ct_ord in range(26):
        ct_char = chr(ct_ord + 65)
        pos = base_idx[ct_ord]
        pt_char = mixed[pos]
        fwd[ct_ord] = ord(pt_char) - 65
    tables.append((f"fwd_{base_label}", fwd))

    # Reverse: plaintext = base[mixed_index(ciphertext)]
    # i.e., find CT's position in mixed alphabet, read base alphabet at that position
    rev = [0] * 26
    for ct_ord in range(26):
        ct_char = chr(ct_ord + 65)
        pos = mixed_idx[ct_ord]
        pt_char = base[pos]
        rev[ct_ord] = ord(pt_char) - 65
    tables.append((f"rev_{base_label}", rev))

    # Atbash on mixed: reverse the mixed alphabet, then forward
    rev_mixed = mixed[::-1]
    atb = [0] * 26
    for ct_ord in range(26):
        pos = base_idx[ct_ord]
        pt_char = rev_mixed[pos]
        atb[ct_ord] = ord(pt_char) - 65
    tables.append((f"atb_{base_label}", atb))

    return tables


def build_special_tables():
    """Build non-keyword-based substitution tables."""
    tables = []

    # Atbash (reverse alphabet)
    atbash = [25 - i for i in range(26)]
    tables.append(("Atbash", atbash))

    # Caesar shifts (1-25)
    for shift in range(1, 26):
        caesar = [(i + shift) % 26 for i in range(26)]
        tables.append((f"Caesar_{shift}", caesar))

    # Affine: PT = (a * CT + b) mod 26, for coprime a
    coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in coprimes:
        for b in range(26):
            if a == 1 and b == 0:
                continue  # identity
            affine = [(a * i + b) % 26 for i in range(26)]
            # Only keep if it's a valid permutation (all affine with coprime a are)
            tables.append((f"Affine_{a}_{b}", affine))

    # KA as direct substitution: position in AZ → KA char
    ka_idx = [0] * 26
    for i, c in enumerate(KRYPTOS_ALPHABET):
        ka_idx[ord(c) - 65] = i
    # Forward: AZ position → KA letter
    ka_fwd = [ord(KRYPTOS_ALPHABET[i]) - 65 for i in range(26)]
    tables.append(("KA_direct", ka_fwd))
    # Reverse: KA position → AZ letter
    ka_rev = [ord(ALPH[ka_idx[i]]) - 65 for i in range(26)]
    tables.append(("KA_reverse", ka_rev))

    # Porta cipher (reciprocal, 13 key groups)
    # For simplicity, test all 13 Porta "rows"
    for key_val in range(13):
        porta = list(range(26))
        for i in range(13):
            j = (i + key_val) % 13 + 13
            porta[i] = j
            porta[j] = i
        tables.append((f"Porta_{key_val}", porta))

    return tables


# ── Fast SA scoring for monoalphabetic ───────────────────────────────────

def score_mono_fast(null_sorted, ct_ords, decrypt_table, crib_entries):
    """Score a null mask with monoalphabetic substitution.

    For mono, decryption is just: PT[i] = decrypt_table[CT[i]]
    No key period involved — every position uses the same table.
    """
    hits = 0
    null_set_len = len(null_sorted)
    for orig_pos, expected_char in crib_entries:
        # Binary search: is orig_pos a null?
        lo, hi = 0, null_set_len
        is_null = False
        while lo < hi:
            mid = (lo + hi) // 2
            if null_sorted[mid] < orig_pos:
                lo = mid + 1
            elif null_sorted[mid] == orig_pos:
                is_null = True
                break
            else:
                hi = mid
        if is_null:
            continue
        # Mono decrypt: position-independent
        pt_ord = decrypt_table[ct_ords[orig_pos]]
        if chr(pt_ord + 65) == expected_char:
            hits += 1
    return hits


# ── SA search ────────────────────────────────────────────────────────────

def sa_search_mono(args):
    """SA search for null mask with monoalphabetic substitution."""
    table_name = args["table_name"]
    decrypt_table = args["decrypt_table"]
    rng_seed = args["rng_seed"]

    ct_ords = [ord(c) - 65 for c in CT]
    crib_entries = CRIB_LIST
    available = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)

    rng = random.Random(rng_seed)

    best_overall_score = -1
    best_overall_nulls = None

    _bisect_left = bisect.bisect_left
    _insort = bisect.insort

    for restart in range(SA_RESTARTS):
        free_nulls = rng.sample(available, N_NULLS)
        non_null_list = [p for p in available if p not in set(free_nulls)]

        null_sorted = sorted(free_nulls)
        current_score = score_mono_fast(null_sorted, ct_ords, decrypt_table, crib_entries)

        best_score = current_score
        best_nulls = list(free_nulls)

        temp = SA_T_INIT
        _randrange = rng.randrange
        _random = rng.random
        _exp = math.exp

        for _ in range(SA_ITERATIONS):
            ri = _randrange(N_NULLS)
            ai = _randrange(len(non_null_list))
            remove_pos = free_nulls[ri]
            add_pos = non_null_list[ai]

            free_nulls[ri] = add_pos
            non_null_list[ai] = remove_pos

            rm_idx = _bisect_left(null_sorted, remove_pos)
            del null_sorted[rm_idx]
            _insort(null_sorted, add_pos)

            new_score = score_mono_fast(null_sorted, ct_ords, decrypt_table, crib_entries)

            delta = new_score - current_score
            if delta > 0 or (delta == 0 and _random() < 0.5):
                current_score = new_score
                if current_score > best_score:
                    best_score = current_score
                    best_nulls = list(free_nulls)
            elif temp > SA_T_MIN and _random() < _exp(delta / temp):
                current_score = new_score
            else:
                free_nulls[ri] = remove_pos
                non_null_list[ai] = add_pos
                rv_idx = _bisect_left(null_sorted, add_pos)
                del null_sorted[rv_idx]
                _insort(null_sorted, remove_pos)

            temp *= SA_COOLING

        if best_score > best_overall_score:
            best_overall_score = best_score
            best_overall_nulls = sorted(best_nulls)

    # Free crib check on best
    free_score = 0
    pt = ""
    if best_overall_score >= REPORT_THRESHOLD - 2:
        null_set = set(best_overall_nulls)
        pt_chars = []
        for i in range(CT_LEN):
            if i not in null_set:
                pt_chars.append(chr(decrypt_table[ord(CT[i]) - 65] + 65))
        pt = "".join(pt_chars)
        if CRIB_ENE in pt:
            free_score += 13
        if CRIB_BC in pt:
            free_score += 11

    return {
        "table_name": table_name,
        "mapped_score": best_overall_score,
        "free_score": free_score,
        "null_positions": best_overall_nulls,
        "plaintext": pt,
    }


# ── Load keywords ────────────────────────────────────────────────────────

def load_keywords():
    wordlist_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords_v2.txt'
    )
    words = set()
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                w = line.upper()
                if 3 <= len(w) <= 13 and w.isalpha():
                    words.add(w)
    for w in ["KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
              "SHADOW", "CIPHER", "SECRET", "BERLIN", "CLOCK",
              "PALIMPSEST", "COMPASS", "LODESTONE", "ENIGMA", "SANBORN", "SCHEIDT"]:
        words.add(w)
    return sorted(words)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 78)
    print("E-TWO-SYS-09: Monoalphabetic substitution + null mask SA")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")

    keywords = load_keywords()
    print(f"Keywords loaded: {len(keywords)}")

    # Build all substitution tables
    print(f"\nBuilding substitution tables...")
    all_tables = []

    # Keyword-based mono tables (3 variants × 2 bases per keyword)
    for keyword in keywords:
        for base in [ALPH, KRYPTOS_ALPHABET]:
            tables = build_mono_tables(keyword, base)
            all_tables.extend(tables)

    # Special tables (Atbash, Caesar, Affine, Porta, KA direct)
    special = build_special_tables()
    all_tables.extend(special)

    # Deduplicate by actual table content
    seen = set()
    unique_tables = []
    for name, table in all_tables:
        key = tuple(table)
        if key not in seen:
            seen.add(key)
            unique_tables.append((name, table))

    print(f"Total tables (before dedup): {len(all_tables)}")
    print(f"Unique substitution tables: {len(unique_tables)}")
    print(f"  Keyword-based: {len(all_tables) - len(special)}")
    print(f"  Special (Atbash/Caesar/Affine/Porta/KA): {len(special)}")
    print(f"\nSA: {SA_ITERATIONS:,} iters × {SA_RESTARTS} restarts per table")
    print(f"Report threshold: {REPORT_THRESHOLD}")
    print(f"Workers: {N_WORKERS}")

    total_sa = len(unique_tables) * SA_RESTARTS * SA_ITERATIONS
    print(f"Total SA evaluations: {total_sa:,}")
    print()
    sys.stdout.flush()

    # Build work items
    tasks = []
    for name, table in unique_tables:
        seed = hash(name) & 0xFFFFFFFF
        tasks.append({
            "table_name": name,
            "decrypt_table": table,
            "rng_seed": seed,
        })

    all_results = []
    completed = 0
    n_hits = 0
    REPORT_EVERY = 200

    with mp.Pool(N_WORKERS) as pool:
        for result in pool.imap_unordered(sa_search_mono, tasks, chunksize=1):
            completed += 1
            all_results.append(result)

            if result["mapped_score"] >= REPORT_THRESHOLD or result["free_score"] >= 11:
                n_hits += 1
                print(f"    *** HIT: {result['table_name']} "
                      f"mapped={result['mapped_score']} free={result['free_score']}")
                if result["plaintext"]:
                    print(f"        PT: {result['plaintext'][:60]}...")
                sys.stdout.flush()

            if completed % REPORT_EVERY == 0 or completed == len(tasks):
                elapsed = time.time() - t0
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (len(tasks) - completed) / rate if rate > 0 else 0
                best_so_far = max(r["mapped_score"] for r in all_results)
                print(f"  [{completed:,}/{len(tasks):,}] {elapsed:.0f}s "
                      f"({rate:.1f}/s, ETA {eta:.0f}s) | "
                      f"best_mapped={best_so_far} | hits={n_hits}")
                sys.stdout.flush()

    elapsed = time.time() - t0

    # ── Results ──────────────────────────────────────────────────────────
    print(f"\n{'=' * 78}")
    print(f"RESULTS")
    print(f"{'=' * 78}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/60:.1f}m)")
    print(f"Unique tables tested: {len(unique_tables)}")

    all_results.sort(key=lambda r: -max(r["mapped_score"], r["free_score"]))

    best = all_results[0] if all_results else None
    if best:
        print(f"\nBest: mapped={best['mapped_score']} free={best['free_score']}")
        print(f"  Table: {best['table_name']}")
        print(f"  Nulls: {best['null_positions']}")
        if best["plaintext"]:
            print(f"  PT: {best['plaintext'][:70]}...")

    reportable = [r for r in all_results
                  if r["mapped_score"] >= REPORT_THRESHOLD or r["free_score"] >= 11]

    print(f"\nResults above threshold: {len(reportable)}")
    if reportable:
        for i, r in enumerate(reportable[:50]):
            print(f"  #{i+1}: mapped={r['mapped_score']} free={r['free_score']} | "
                  f"{r['table_name']}")
            if r["plaintext"]:
                print(f"       PT: {r['plaintext'][:70]}...")
    else:
        print("  (none)")

    best_score = max(max(r["mapped_score"], r["free_score"]) for r in all_results) if all_results else 0
    print(f"\n{'=' * 78}")
    if best_score >= 18:
        print(f"*** SIGNAL (best={best_score}) — investigate ***")
    elif best_score >= REPORT_THRESHOLD:
        print(f"Above noise (best={best_score})")
    else:
        print(f"NOISE — Monoalphabetic + null mask: no signal (best={best_score})")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
