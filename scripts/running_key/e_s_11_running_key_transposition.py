#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-11: Running key + columnar transposition.

Tests whether K4 = transpose(vig(PT, running_key)) [Model A]
   or  K4 = vig(transpose(PT), running_key)         [Model B]

For each columnar transposition (widths 5-10) and each running key text,
checks if the crib-derived key values match any offset in the text.

Model A: T[p + offset] = (CT[sigma(p)] - PT[p]) mod 26
  Running key positions are at crib positions (contiguous blocks).
  Different transpositions change the REQUIRED values.

Model B: T[sigma_inv(p) + offset] = (CT[sigma_inv(p)] - PT[p]) mod 26
  Running key positions are at transposed crib positions (scattered).
  Different transpositions change which positions in T are sampled.

Also tests Beaufort variant for both models.
"""

import json
import os
import sys
import time
from collections import defaultdict
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_ENTRIES, MOD

# ═══ Setup ════════════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
PT_INT = {p: ord(c) - 65 for p, c in _sorted}
N_CRIBS = len(CRIB_POS)

# ═══ Known texts ═════════════════════════════════════════════════════════

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETIC"
         "FIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOAN"
         "UNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHIS"
         "THEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
         "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
         "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
         "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO")
K3_PT = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
         "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSI"
         "MADEATINYBREACHINTHEUPPER"
         "LEFTHANDCORNERANDTHENWIDENINTHEHOLEALITTLEIINSERTEDTHECANDLE"
         "ANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
         "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOM"
         "WITHINEMERGEFROMTHEMISTXCANYOUSEEANYTHINGQ")


def load_text_file(path):
    """Load a text file and strip to uppercase alpha only."""
    with open(path) as f:
        raw = f.read().upper()
    return ''.join(c for c in raw if c.isalpha())


def load_running_key_texts():
    """Load all running key candidate texts."""
    texts = {}
    texts["K1_PT"] = K1_PT
    texts["K2_PT"] = K2_PT
    texts["K3_PT"] = K3_PT
    texts["K123_PT"] = K1_PT + K2_PT + K3_PT

    rkt_dir = "reference/running_key_texts"
    if os.path.isdir(rkt_dir):
        for fn in sorted(os.listdir(rkt_dir)):
            if fn.endswith('.txt'):
                path = os.path.join(rkt_dir, fn)
                name = fn.replace('.txt', '')
                texts[name] = load_text_file(path)

    # Carter book extract if available
    carter_path = "reference/carter_vol1_extract.txt"
    if os.path.isfile(carter_path):
        texts["carter_vol1"] = load_text_file(carter_path)

    return texts


# ═══ Columnar transposition ══════════════════════════════════════════════

def columnar_perm(width, col_order, length):
    """Build columnar transposition permutation (gather convention).
    output[i] = input[perm[i]]
    """
    n_rows = (length + width - 1) // width
    perm = []
    for col in col_order:
        for row in range(n_rows):
            pos = row * width + col
            if pos < length:
                perm.append(pos)
    return perm


def invert_perm(perm):
    """Compute inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ═══ Scoring ═════════════════════════════════════════════════════════════

def check_model_a(sigma, text_int, text_len):
    """Model A: CT = transpose(vig(PT, running_key))
    T[p + offset] = (CT[sigma[p]] - PT[p]) mod 26

    Returns (best_matches, best_offset).
    """
    # For each crib position, compute the required T value
    # given this transposition sigma
    # required[i] = (CT[sigma[crib_pos[i]]] - PT_crib[i]) mod 26
    required = []
    for p in CRIB_POS:
        ct_val = CT_INT[sigma[p]]
        pt_val = PT_INT[p]
        required.append((ct_val - pt_val) % 26)

    # Crib positions are: 21-33 and 63-73
    # For offset o, check T[21+o], T[22+o], ..., T[33+o], T[63+o], ..., T[73+o]
    best_matches = 0
    best_offset = -1

    max_offset = text_len - max(CRIB_POS) - 1
    if max_offset < 0:
        return 0, -1

    for o in range(max_offset + 1):
        matches = 0
        for i, p in enumerate(CRIB_POS):
            t_pos = p + o
            if t_pos < text_len and text_int[t_pos] == required[i]:
                matches += 1
        if matches > best_matches:
            best_matches = matches
            best_offset = o

    return best_matches, best_offset


def check_model_a_beaufort(sigma, text_int, text_len):
    """Model A Beaufort: CT = transpose(beaufort(PT, running_key))
    T[p + offset] = (CT[sigma[p]] + PT[p]) mod 26
    """
    required = []
    for p in CRIB_POS:
        ct_val = CT_INT[sigma[p]]
        pt_val = PT_INT[p]
        required.append((ct_val + pt_val) % 26)

    best_matches = 0
    best_offset = -1
    max_offset = text_len - max(CRIB_POS) - 1
    if max_offset < 0:
        return 0, -1

    for o in range(max_offset + 1):
        matches = 0
        for i, p in enumerate(CRIB_POS):
            t_pos = p + o
            if t_pos < text_len and text_int[t_pos] == required[i]:
                matches += 1
        if matches > best_matches:
            best_matches = matches
            best_offset = o

    return best_matches, best_offset


def check_model_b(sigma_inv, text_int, text_len):
    """Model B: CT = vig(transpose(PT), running_key)
    T[sigma_inv[p] + offset] = (CT[sigma_inv[p]] - PT[p]) mod 26

    Returns (best_matches, best_offset).
    """
    # For each crib position p, the key is sampled at sigma_inv[p]
    q_vals = []  # (q_position, required_value)
    for p in CRIB_POS:
        q = sigma_inv[p]
        v = (CT_INT[q] - PT_INT[p]) % 26
        q_vals.append((q, v))

    best_matches = 0
    best_offset = -1
    max_q = max(q for q, _ in q_vals)
    max_offset = text_len - max_q - 1
    if max_offset < 0:
        return 0, -1

    for o in range(max_offset + 1):
        matches = 0
        for q, v in q_vals:
            t_pos = q + o
            if t_pos < text_len and text_int[t_pos] == v:
                matches += 1
        if matches > best_matches:
            best_matches = matches
            best_offset = o

    return best_matches, best_offset


def check_model_b_beaufort(sigma_inv, text_int, text_len):
    """Model B Beaufort: CT = beaufort(transpose(PT), running_key)"""
    q_vals = []
    for p in CRIB_POS:
        q = sigma_inv[p]
        v = (CT_INT[q] + PT_INT[p]) % 26
        q_vals.append((q, v))

    best_matches = 0
    best_offset = -1
    max_q = max(q for q, _ in q_vals)
    max_offset = text_len - max_q - 1
    if max_offset < 0:
        return 0, -1

    for o in range(max_offset + 1):
        matches = 0
        for q, v in q_vals:
            t_pos = q + o
            if t_pos < text_len and text_int[t_pos] == v:
                matches += 1
        if matches > best_matches:
            best_matches = matches
            best_offset = o

    return best_matches, best_offset


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-11: Running Key + Columnar Transposition")
    print("=" * 60)
    print("Model A: CT = transpose(vig(PT, running_key))")
    print("Model B: CT = vig(transpose(PT), running_key)")
    print("Both Vigenère and Beaufort variants")
    print()

    # Load running key texts
    texts = load_running_key_texts()
    print(f"Running key texts loaded: {len(texts)}")
    for name, text in sorted(texts.items()):
        print(f"  {name}: {len(text)} chars")
    print()

    # Convert to integer arrays
    texts_int = {name: [ord(c) - 65 for c in text] for name, text in texts.items()}

    all_results = {}
    global_best = {"matches": 0}

    # Test each width
    for width in range(5, 11):
        n_orders = 1
        for i in range(2, width + 1):
            n_orders *= i

        print(f"\n{'=' * 60}")
        print(f"  Width {width}: {n_orders} orderings × {len(texts)} texts × 4 models")
        print(f"{'=' * 60}")
        sys.stdout.flush()

        width_best = {"matches": 0}
        n_checked = 0
        t_width = time.time()

        for col_order in permutations(range(width)):
            sigma = columnar_perm(width, col_order, CT_LEN)
            sigma_inv = invert_perm(sigma)

            for text_name, text_int in texts_int.items():
                text_len = len(text_int)

                # Model A Vigenère
                m, o = check_model_a(sigma, text_int, text_len)
                if m > width_best["matches"]:
                    width_best = {"matches": m, "model": "A_vig", "width": width,
                                  "col_order": list(col_order), "text": text_name,
                                  "offset": o}
                if m > global_best["matches"]:
                    global_best = dict(width_best)

                # Model A Beaufort
                m, o = check_model_a_beaufort(sigma, text_int, text_len)
                if m > width_best["matches"]:
                    width_best = {"matches": m, "model": "A_beau", "width": width,
                                  "col_order": list(col_order), "text": text_name,
                                  "offset": o}
                if m > global_best["matches"]:
                    global_best = dict(width_best)

                # Model B Vigenère
                m, o = check_model_b(sigma_inv, text_int, text_len)
                if m > width_best["matches"]:
                    width_best = {"matches": m, "model": "B_vig", "width": width,
                                  "col_order": list(col_order), "text": text_name,
                                  "offset": o}
                if m > global_best["matches"]:
                    global_best = dict(width_best)

                # Model B Beaufort
                m, o = check_model_b_beaufort(sigma_inv, text_int, text_len)
                if m > width_best["matches"]:
                    width_best = {"matches": m, "model": "B_beau", "width": width,
                                  "col_order": list(col_order), "text": text_name,
                                  "offset": o}
                if m > global_best["matches"]:
                    global_best = dict(width_best)

                n_checked += 4

            # Progress
            idx = 0
            for i, c in enumerate(col_order):
                if c != i:
                    idx = sum(1 for _ in permutations(range(width)))
                    break
            if n_checked % (n_orders * len(texts) * 4 // 10 + 1) < len(texts) * 4:
                elapsed = time.time() - t_width
                print(f"  [{n_checked:>10,}] best={width_best['matches']}/24  "
                      f"({elapsed:.0f}s)", end='\r')
                sys.stdout.flush()

        elapsed = time.time() - t_width
        print(f"  Width {width}: best={width_best['matches']}/24  "
              f"model={width_best.get('model', '?')}  "
              f"text={width_best.get('text', '?')}  "
              f"({elapsed:.1f}s)")

        key = f"width_{width}"
        all_results[key] = {
            "width": width,
            "n_orderings": n_orders,
            "best_matches": width_best["matches"],
            "best_config": width_best,
            "elapsed_s": round(elapsed, 1),
        }

    # ═══ Summary ═════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total time: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print()

    for key, r in sorted(all_results.items()):
        cfg = r["best_config"]
        print(f"  {key}: best={r['best_matches']}/24  "
              f"model={cfg.get('model', '?')}  "
              f"text={cfg.get('text', '?')}  "
              f"offset={cfg.get('offset', '?')}")

    print(f"\n  Global best: {global_best['matches']}/24")
    if global_best['matches'] > 0:
        print(f"    Model: {global_best.get('model', '?')}")
        print(f"    Width: {global_best.get('width', '?')}")
        print(f"    Col order: {global_best.get('col_order', '?')}")
        print(f"    Text: {global_best.get('text', '?')}")
        print(f"    Offset: {global_best.get('offset', '?')}")

    # Expected random: ~24/26 ≈ 0.92 per (σ, text, offset) check
    # With many offsets, expected max per (σ, text) pair: depends on text length
    # Rough: for text of length L, expected max matches ≈ 24/26 + sqrt(2*ln(L)*24/26*(1-1/26)) ≈ 2-4
    noise_floor = 5  # conservative noise floor for this test

    if global_best["matches"] >= 10:
        verdict = "SIGNAL"
    elif global_best["matches"] >= noise_floor:
        verdict = "INVESTIGATE"
    else:
        verdict = "NOISE"

    print(f"\n  Noise floor: ~{noise_floor}/24 (conservative)")
    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_11_running_key_transposition.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-11",
            "hypothesis": "Running key from known texts + columnar transposition",
            "total_time_s": round(elapsed, 1),
            "verdict": verdict,
            "global_best": global_best,
            "results_by_width": all_results,
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_11_running_key_transposition.py")
    print(f"\nRESULT: best={global_best['matches']}/24 verdict={verdict}")


if __name__ == "__main__":
    main()
