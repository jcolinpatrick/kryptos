#!/usr/bin/env python3
"""
VIC cipher narrative-driven parameter sweep for K4.

Cipher:  VIC cipher (full key generation + straddling checkerboard + double transposition)
Family:  campaigns
Status:  active
Keyspace: ~60M configs (100K keygroups × phrases × dates × top-rows × mappings × prefix-pairs)
Last run: never
Best score: N/A

NARRATIVE HYPOTHESIS (user-driven, 2026-03-17):
  Fixed with high confidence:
    - Date: Berlin Wall fall (Nov 9, 1989) → 091189 (DDMMYY) or 110989 (MMDDYY)
    - Personal number: 5 (FIVE at cylinder seam)
    - Top-row letters: {A,D,E,H,N,O,R,Y} — the 8 unique letters from NDYAHR region,
      which is EXACTLY the VIC top-row count of 8. Appears in TOP ROW of K3 grid.
      Test forward (ENDRYAHR) and reversed (RHAYDNE) — reversed is how they read
      from the BACK of the Kryptos sculpture.
  Variable:
    - Keygroup: Brute-force all 100,000 (5-digit) keygroups
    - Phrase: ~30 candidates from K1-K3 plaintext, thematic words, Sanborn quotes
    - Letter-to-digit mapping: 5 schemes (checkerboard, AZ/KA × 0/1-indexed)
    - Prefix column pairs: top 6 most likely positions

Uses the verified VIC pipeline from e_full_vic_pipeline_k4.py.
Parallelized across 28 CPU cores.
"""
import sys
import os
import json
import time
import math
from pathlib import Path
from multiprocessing import Pool, cpu_count
from itertools import product

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# Import VIC functions from the existing verified pipeline
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analysis"))
from e_full_vic_pipeline_k4 import (
    generate_vic_keys, complete_vic_keys, build_checkerboard,
    cb_decode, vic_decrypt, vic_decrypt_single,
    rank10, rank_n, columnar_decrypt, disrupted_decrypt,
    verify_pipeline,
)

# ========================================================================
# CT → DIGIT MAPPINGS (5 schemes)
# ========================================================================
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

def ct_to_digits_az0(ct):
    """A=0, B=1, ..., Z=25, each mod 10"""
    return ''.join(str(ALPH_IDX[c] % 10) for c in ct)

def ct_to_digits_az1(ct):
    """A=1, B=2, ..., Z=26, each mod 10 (so Z=6)"""
    return ''.join(str((ALPH_IDX[c] + 1) % 10) for c in ct)

def ct_to_digits_ka0(ct):
    """KA alphabet 0-indexed mod 10"""
    return ''.join(str(KA_IDX[c] % 10) for c in ct)

def ct_to_digits_ka1(ct):
    """KA alphabet 1-indexed mod 10"""
    return ''.join(str((KA_IDX[c] + 1) % 10) for c in ct)

DIGIT_MAPS = [
    ("AZ0", ct_to_digits_az0),
    ("AZ1", ct_to_digits_az1),
    ("KA0", ct_to_digits_ka0),
    ("KA1", ct_to_digits_ka1),
]

# Pre-compute digit streams
CT_DIGITS = {name: fn(CT) for name, fn in DIGIT_MAPS}

# ========================================================================
# PARAMETER SPACE
# ========================================================================

# Date: Berlin Wall fall — high confidence
DATES = [
    ("BerlinDDMMYY", [0, 9, 1, 1, 8, 9]),
    ("BerlinMMDDYY", [1, 1, 0, 9, 8, 9]),
]

# Personal number: 5 (FIVE) — high confidence
PERSONAL_NUMBER = 5

# Top-row letters: 8 unique from NDYAHR = {A,D,E,H,N,O,R,Y}
# Order matters for checkerboard layout
TOP_ROWS = [
    ("ENDRYAHR_fwd", "ENDRYAHR"),    # As read from front of sculpture
    ("RHAYDNE_rev", "RHAYDNE"),      # As read from BACK of sculpture
    ("ADEHONRY_alph", "ADEHONRY"),   # Alphabetical
    ("NDYAHROE_raised", "NDYAHROE"), # Raised chars first, then remaining
    ("EORNDYAH_freq", "EORNDYAH"),   # By English frequency (E,O,R,N,D,Y,A,H)
    ("RHONDAYE_name", "RHONDAYE"),   # Anagram: RHONDA + YE
]

# Prefix column pairs: which 2 of 10 columns are blank in top row
# With 8 letters in 10 columns, blanks are at positions 8,9 (default)
# but could be at other positions depending on layout
PREFIX_PAIRS = [
    (8, 9),  # Default: last two columns blank
    (0, 1),  # First two blank
    (0, 9),  # First and last blank
    (4, 5),  # Middle blanks
    (2, 7),  # Spread blanks
    (3, 6),  # Quarter positions
]

# Phrases: 20+ letters, ordered by narrative plausibility
PHRASES = [
    # K1-K3 plaintext openings
    ("K1_PT", "BETWEENSUBTLESHADING"),
    ("K2_PT", "ITWASTOTALLYINVISIBL"),
    ("K3_PT", "SLOWLYDESPARATLYSLOW"),
    # K1-K3 deeper fragments
    ("K1_LUCID", "LUCIDITYOFAPALIMPSES"),
    ("K2_MAGNET", "THEYUSEDTHEEARTHSMAG"),
    ("K2_BURIED", "ITSBURIEDOUTTHERESOME"),
    ("K3_TREMBL", "WITHTREMBLINGHANDSIM"),
    ("K3_BREACH", "IMADEATINYBREACHINTH"),
    # Keywords and combinations
    ("KA_20", "KRYPTOSABCDEFGHIJLMN"),
    ("PAL_ABS", "PALIMPSESTABSCISSAKR"),
    ("ABS_PAL", "ABSCISSAPALIMPSESTKR"),
    ("DEF_KRY", "DEFECTORKRYPTOSABCDE"),
    ("KRY_PAL", "KRYPTOSPALIMPSESTAB"),
    ("KRY_DEF", "KRYPTOSDEFECTORABSC"),
    # Thematic — spy/Cold War
    ("CRIBS20", "EASTNORTHEASTBERLINC"),
    ("META20", "THEANSWERISTWOSYSTEM"),
    ("SHADOW", "BETWEENSUBTLESHADOWA"),
    ("BERLIN", "BERLINWALLNOVEMBERNI"),
    ("WHATPT", "WHATSTHEPOINTWHATIST"),
    # Sanborn quotes / concepts
    ("TWOSYS", "TWOSYSTEMSOFENCIPHER"),
    ("UNVEIL", "DESIGNEDTOUNVEILITSE"),
    ("INSTRC", "IHAVELEFTINSTRUCTION"),
    ("OBVKEY", "THEMOSTOBVIOUSKEYTO"),
    # Physical sculpture references
    ("NDYAHR_PAD", "NDYAHRENDRYAHRONEND"),
    ("CODERM", "THECODEROOM CYLINDER"),
    ("LODEST", "THELODESTONEPOINTSTO"),
    # Number words from K2 coordinates
    ("NUMWRD", "THIRTYEIGHTFIFTYSEVE"),
    ("FIVESV", "FIVESEVENTHIRTYEIGHT"),
]

# ========================================================================
# SCORING (crib-only, fast)
# ========================================================================

ENE = "EASTNORTHEAST"  # positions 21-33
BC = "BERLINCLOCK"     # positions 63-73

def fast_score(pt):
    """Fast crib scoring. Returns (fixed_score, ene, bc, pt_len)."""
    ene_score = 0
    bc_score = 0
    if len(pt) >= 34:
        for i in range(13):
            if 21 + i < len(pt) and pt[21 + i] == ENE[i]:
                ene_score += 1
    if len(pt) >= 74:
        for i in range(11):
            if 63 + i < len(pt) and pt[63 + i] == BC[i]:
                bc_score += 1
    return ene_score + bc_score, ene_score, bc_score, len(pt)


# ========================================================================
# WORKER FUNCTION (one keygroup batch)
# ========================================================================

def worker(args):
    """Process a batch of keygroups for one (phrase, date) combo.
    Returns list of results with score >= threshold."""
    phrase_name, phrase, date_name, date_digits, kg_start, kg_end = args

    base = generate_vic_keys(phrase, date_digits, PERSONAL_NUMBER)
    if base is None:
        return [], kg_end - kg_start, 0

    results = []
    configs = 0
    keys_ok = 0

    for kg_int in range(kg_start, kg_end):
        kg = [(kg_int // (10**i)) % 10 for i in range(4, -1, -1)]

        keys = complete_vic_keys(base, kg)
        if keys is None:
            continue
        keys_ok += 1

        for tr_name, top_row in TOP_ROWS:
            for pp in PREFIX_PAIRS:
                enc, dec, pf = build_checkerboard(keys['line_s'], top_row, pp)
                if enc is None:
                    continue

                for dm_name, ct_digits in CT_DIGITS.items():
                    configs += 1

                    # Full VIC decrypt (double transposition)
                    try:
                        pt = vic_decrypt(ct_digits, keys['trans1_key'],
                                        keys['trans2_key'], dec, pf)
                    except Exception:
                        continue

                    total, ene, bc, pt_len = fast_score(pt)
                    if total >= 6:
                        results.append({
                            'score': total, 'ene': ene, 'bc': bc,
                            'phrase': phrase_name, 'date': date_name,
                            'kg': ''.join(map(str, kg)),
                            'top_row': tr_name, 'prefix': pp,
                            'dm': dm_name,
                            'a': keys['a'], 'b': keys['b'],
                            'pt': pt[:80], 'pt_len': pt_len,
                            'mode': 'full_vic',
                        })

                    # Also try checkerboard-only (skip transpositions)
                    try:
                        pt_cb = cb_decode(ct_digits, dec, pf)
                    except Exception:
                        continue
                    configs += 1

                    total2, ene2, bc2, pt_len2 = fast_score(pt_cb)
                    if total2 >= 6:
                        results.append({
                            'score': total2, 'ene': ene2, 'bc': bc2,
                            'phrase': phrase_name, 'date': date_name,
                            'kg': ''.join(map(str, kg)),
                            'top_row': tr_name, 'prefix': pp,
                            'dm': dm_name,
                            'pt': pt_cb[:80], 'pt_len': pt_len2,
                            'mode': 'cb_only',
                        })

    return results, configs, keys_ok


# ========================================================================
# MAIN
# ========================================================================

def run():
    t0 = time.time()
    ncores = min(cpu_count(), 28)

    print("=" * 72)
    print("VIC CIPHER NARRATIVE-DRIVEN PARAMETER SWEEP")
    print("=" * 72)
    print(f"CT: {CT} ({CT_LEN} chars)")
    print(f"Cores: {ncores}")
    print(f"Personal number: {PERSONAL_NUMBER} (FIVE)")
    print(f"Dates: {len(DATES)}")
    print(f"Phrases: {len(PHRASES)}")
    print(f"Top-rows: {len(TOP_ROWS)} ({', '.join(t[0] for t in TOP_ROWS)})")
    print(f"Prefix pairs: {len(PREFIX_PAIRS)}")
    print(f"Digit mappings: {len(CT_DIGITS)}")
    print(f"Keygroups: 100,000 (brute-force 00000-99999)")
    print(f"Configs per keygroup: ~{len(TOP_ROWS) * len(PREFIX_PAIRS) * len(CT_DIGITS) * 2}")
    est_total = len(PHRASES) * len(DATES) * 100_000 * len(TOP_ROWS) * len(PREFIX_PAIRS) * len(CT_DIGITS) * 2
    print(f"Estimated total configs: ~{est_total:,}")
    print(flush=True)

    # Verify pipeline first
    print("Verifying pipeline...")
    verify_pipeline()

    # Build work items: one per (phrase, date, keygroup_batch)
    BATCH_SIZE = 1000  # keygroups per batch
    work_items = []
    for phrase_name, phrase in PHRASES:
        for date_name, date_digits in DATES:
            for kg_start in range(0, 100_000, BATCH_SIZE):
                kg_end = min(kg_start + BATCH_SIZE, 100_000)
                work_items.append((phrase_name, phrase, date_name, date_digits, kg_start, kg_end))

    print(f"Work items: {len(work_items)} batches")
    print(f"Starting sweep...", flush=True)

    all_results = []
    total_configs = 0
    total_keys = 0
    batches_done = 0

    with Pool(ncores) as pool:
        for batch_results, batch_configs, batch_keys in pool.imap_unordered(worker, work_items, chunksize=4):
            all_results.extend(batch_results)
            total_configs += batch_configs
            total_keys += batch_keys
            batches_done += 1

            if batches_done % 200 == 0:
                elapsed = time.time() - t0
                pct = 100 * batches_done / len(work_items)
                best = max((r['score'] for r in all_results), default=0)
                print(f"  [{pct:5.1f}%] {batches_done}/{len(work_items)} batches | "
                      f"{total_configs:,} configs | {total_keys:,} keys | "
                      f"{len(all_results)} hits | best={best}/24 | "
                      f"{elapsed:.0f}s", flush=True)

    elapsed = time.time() - t0

    # Sort results
    all_results.sort(key=lambda r: r['score'], reverse=True)

    # Summary
    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Valid key derivations: {total_keys:,}")
    print(f"Results with score >= 6: {len(all_results)}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/60:.1f}m)")

    best_score = all_results[0]['score'] if all_results else 0
    print(f"\nBest score: {best_score}/24")

    if all_results:
        print(f"\nTop 30 results:")
        for i, r in enumerate(all_results[:30]):
            print(f"  {i+1:3d}. {r['score']:2d}/24 (ENE={r['ene']}, BC={r['bc']}) | "
                  f"{r['mode']} | {r['phrase']} {r['date']} kg={r['kg']} "
                  f"tr={r.get('top_row','')} dm={r['dm']} | "
                  f"PT({r['pt_len']}): {r['pt'][:50]}")

    # Verdict
    if best_score >= 18:
        verdict = "SIGNAL"
    elif best_score >= 10:
        verdict = "INTERESTING"
    elif best_score >= 6:
        verdict = "WEAK"
    else:
        verdict = "NOISE"
    print(f"\nVERDICT: {verdict}")

    # Save
    out_path = Path(__file__).resolve().parents[2] / "results" / "f_vic_narrative_sweep_v1.json"
    os.makedirs(out_path.parent, exist_ok=True)
    output = {
        'experiment': 'f_vic_narrative_sweep_v1',
        'description': 'VIC cipher narrative-driven sweep: Berlin Wall date + FIVE + NDYAHR top-row + 100K keygroups',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'valid_keys': total_keys,
        'elapsed_seconds': round(elapsed, 1),
        'parameters': {
            'dates': [d[0] for d in DATES],
            'personal_number': PERSONAL_NUMBER,
            'phrases': [p[0] for p in PHRASES],
            'top_rows': [t[0] for t in TOP_ROWS],
            'prefix_pairs': PREFIX_PAIRS,
            'digit_mappings': list(CT_DIGITS.keys()),
            'keygroup_range': '00000-99999',
        },
        'best_score': best_score,
        'verdict': verdict,
        'results_above_6': len(all_results),
        'top_50': all_results[:50],
    }
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    run()
