#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-EXPLORER-04: Non-standard cipher structures.

Four hypotheses tested, each addressing the "not a math solution" clue
and the "two separate systems" / "coding charts" clues:

H1: Polybius-variant lookup tables (coding charts as non-standard grids)
    - 5x5, 6x5, 5x6, 6x6 grids with KRYPTOS-keyed and standard alphabets
    - Checkerboard encoding: convert CT to coordinate pairs, re-read
    - Tests whether the "coding charts" are lookup grids, not a Vigenere tableau

H2: Position-dependent alphabet switching
    - K5 shares coded words at same positions => position-dependent cipher
    - Test: select one of N alphabets based on position (mod N, or based on
      a rule derived from the sculpture's physical features)
    - Alphabets derived from: KRYPTOS keyword rotations, misspelling substitutions

H3: Interleave/deinterleave + substitution
    - Sanborn: "two separate systems for the bottom text"
    - Test: split CT into two interleaved streams, each encrypted with a
      different simple cipher (Vigenere/Beaufort/Caesar with different keys)
    - If the "two systems" are literally two interlocked ciphers

H4: Modified autokey with K1-K3 plaintext seeding
    - Scheidt: "change in methodology from K3 to K4"
    - Test: autokey cipher seeded with K1/K2/K3 plaintext fragments
    - The seed provides the non-periodic key that evades Bean impossibility
    - Different from standard autokey (already eliminated) because the seed
      comes from solved sections, not a short keyword

All constants from kryptos.kernel.constants. Scoring via score_candidate().
"""
from __future__ import annotations

import json
import itertools
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean_simple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)

CT_NUMS = [ALPH_IDX[c] for c in CT]


# ============================================================================
# HYPOTHESIS 1: Polybius-variant lookup tables (coding charts)
# ============================================================================

def make_polybius_grid(alphabet: str, rows: int, cols: int) -> Dict[str, Tuple[int, int]]:
    """Create a Polybius grid mapping char -> (row, col)."""
    grid = {}
    for i, ch in enumerate(alphabet[:rows * cols]):
        r, c = divmod(i, cols)
        grid[ch] = (r, c)
    return grid


def polybius_encode(text: str, grid: Dict[str, Tuple[int, int]]) -> List[int]:
    """Encode text as stream of coordinate values."""
    result = []
    for ch in text:
        if ch in grid:
            r, c = grid[ch]
            result.append(r)
            result.append(c)
    return result


def polybius_decode(coords: List[int], grid: Dict[str, Tuple[int, int]], cols: int) -> str:
    """Decode coordinate stream back to text using inverse grid."""
    inv_grid = {}
    for ch, (r, c) in grid.items():
        inv_grid[(r, c)] = ch
    result = []
    for i in range(0, len(coords) - 1, 2):
        r, c = coords[i], coords[i + 1]
        if (r, c) in inv_grid:
            result.append(inv_grid[(r, c)])
        else:
            result.append("?")
    return "".join(result)


def test_h1_polybius_charts():
    """Test if CT encodes Polybius coordinate pairs under various grids.

    The idea: Sanborn's "coding charts" are lookup tables. The CT letters
    represent coordinate pairs in these charts. Each pair of CT letters
    encodes one plaintext letter.

    If CT has 97 chars, pairs would give 48 PT chars (with 1 leftover).
    We check if the crib positions align with any pair interpretation.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 1: Polybius-variant lookup tables (coding charts)")
    print("=" * 70)

    # Grid alphabets to test
    alphabets = {
        "standard": ALPH,
        "kryptos": KRYPTOS_ALPHABET,
        "reversed": ALPH[::-1],
        "kryptos_rev": KRYPTOS_ALPHABET[::-1],
    }

    # Grid dimensions (rows x cols) where rows*cols >= 26
    grid_dims = [(5, 6), (6, 5), (6, 6), (5, 5)]  # 5x5 needs IJ merge

    results = []
    best_score = 0

    for alph_name, alph in alphabets.items():
        for rows, cols in grid_dims:
            if rows * cols < 26 and rows * cols < len(alph):
                # Need IJ merge for 5x5
                merged = alph.replace("J", "")[:25]
                grid = make_polybius_grid(merged, rows, cols)
            else:
                grid = make_polybius_grid(alph, rows, cols)

            # Method A: Convert CT letters to row indices, treat pairs as (row,col)
            # Each CT letter maps to its position in the alphabet
            ct_positions = []
            for c in CT:
                if c in grid:
                    r, col_val = grid[c]
                    ct_positions.extend([r, col_val])

            # Method B: Use ordinal positions mod rows/cols as coordinates
            # Pair consecutive CT letters: (CT[0] mod rows, CT[1] mod cols) -> PT[0]
            inv_grid = {(r, c): ch for ch, (r, c) in grid.items()}

            for pair_offset in range(2):  # Start pairing at 0 or 1
                pt_chars = []
                for i in range(pair_offset, CT_LEN - 1, 2):
                    r_val = CT_NUMS[i] % rows
                    c_val = CT_NUMS[i + 1] % cols
                    if (r_val, c_val) in inv_grid:
                        pt_chars.append(inv_grid[(r_val, c_val)])
                    else:
                        pt_chars.append("X")  # placeholder
                pt = "".join(pt_chars)

                # Check cribs - but positions are halved since pairs encode one char
                # Crib positions 21-33 in CT would map to PT positions ~10-16
                # This is a fundamentally different structure
                score = 0
                for pos, expected in CRIB_DICT.items():
                    # PT position = (pos - pair_offset) // 2 if pos >= pair_offset
                    pt_pos = (pos - pair_offset) // 2
                    if 0 <= pt_pos < len(pt) and pt[pt_pos] == expected:
                        score += 1

                if score > best_score:
                    best_score = score
                    results.append({
                        "method": "ordinal_mod_pair",
                        "alphabet": alph_name,
                        "grid": f"{rows}x{cols}",
                        "pair_offset": pair_offset,
                        "score": score,
                        "pt_preview": pt[:30],
                    })

            # Method C: Direct positional decoding
            # Treat CT[i] as encoding PT directly through the grid mapping
            # Grid row = key, grid col = plaintext (or vice versa)
            # This is equivalent to a substitution through the grid
            for direction in ["row_key", "col_key"]:
                for key_period in range(1, 7):  # Test small key periods
                    pt_chars = []
                    for i in range(CT_LEN):
                        key_val = i % key_period
                        ct_idx = CT_NUMS[i]
                        if direction == "row_key":
                            # Row = key, column = position in row -> PT
                            r = key_val % rows
                            c = ct_idx % cols
                        else:
                            r = ct_idx % rows
                            c = key_val % cols
                        if (r, c) in inv_grid:
                            pt_chars.append(inv_grid[(r, c)])
                        else:
                            pt_chars.append("X")
                    pt = "".join(pt_chars)

                    score = sum(1 for pos, ch in CRIB_DICT.items()
                                if pos < len(pt) and pt[pos] == ch)

                    if score >= 4:  # Log anything moderately interesting
                        results.append({
                            "method": f"grid_{direction}_p{key_period}",
                            "alphabet": alph_name,
                            "grid": f"{rows}x{cols}",
                            "score": score,
                            "pt_preview": pt[:30],
                        })
                    if score > best_score:
                        best_score = score

    print(f"Total configs tested: {len(alphabets) * len(grid_dims) * (2 + 2*6)}")
    print(f"Best crib score: {best_score}/24")
    print(f"Results with score >= 4: {len([r for r in results if r['score'] >= 4])}")

    if results:
        for r in sorted(results, key=lambda x: -x["score"])[:5]:
            print(f"  {r['method']} {r['alphabet']} {r['grid']}: {r['score']}/24")
            print(f"    PT: {r['pt_preview']}...")

    return {"best_score": best_score, "results": results}


# ============================================================================
# HYPOTHESIS 2: Position-dependent alphabet switching
# ============================================================================

def rotate_alphabet(alph: str, n: int) -> str:
    """Rotate alphabet by n positions."""
    n = n % len(alph)
    return alph[n:] + alph[:n]


def test_h2_position_dependent_alphabets():
    """Test position-dependent alphabet switching.

    K5 sharing coded words at same positions as K4 implies the cipher
    is position-dependent (same position -> same transformation regardless
    of plaintext content). This is consistent with multiple alphabets
    selected by position.

    We test:
    - N alphabets (N=2..7), each a rotation of KRYPTOS alphabet
    - Position determines which alphabet to use: pos % N
    - Each alphabet applies a simple substitution (shift by alphabet offset)
    - Also test: alphabets derived from K1-K3 keywords (PALIMPSEST, ABSCISSA, KRYPTOS)
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 2: Position-dependent alphabet switching")
    print("=" * 70)

    # Generate alphabet sets
    base_alphabets = {
        "standard": ALPH,
        "kryptos": KRYPTOS_ALPHABET,
    }

    # Keyword-derived alphabets
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "KRYPTOSPALIMPSEST",
                "BERLIN", "CLOCK", "EASTNORTHEAST", "LAYER"]

    results = []
    best_score = 0
    configs_tested = 0

    # Test 1: Position mod N selects one of N Caesar-shifted alphabets
    for n_alphs in range(2, 8):
        for base_name, base_alph in base_alphabets.items():
            # Generate N alphabets by rotating base
            for rotation_step in range(1, 14):  # rotation increment per alphabet
                alphs = [rotate_alphabet(base_alph, i * rotation_step)
                         for i in range(n_alphs)]

                # Decrypt: for each position, use alphabet[pos % n_alphs]
                # Substitution: CT char position in the selected alphabet = PT char position in standard alphabet
                pt_chars = []
                for i in range(CT_LEN):
                    alph = alphs[i % n_alphs]
                    ct_pos_in_alph = alph.find(CT[i])
                    if ct_pos_in_alph >= 0:
                        pt_chars.append(ALPH[ct_pos_in_alph])
                    else:
                        pt_chars.append("?")
                pt = "".join(pt_chars)

                score = sum(1 for pos, ch in CRIB_DICT.items()
                            if pos < len(pt) and pt[pos] == ch)
                configs_tested += 1

                if score > best_score:
                    best_score = score

                if score >= 5:
                    results.append({
                        "method": f"caesar_mod{n_alphs}_step{rotation_step}",
                        "base": base_name,
                        "score": score,
                        "pt_preview": pt[:30],
                    })

    # Test 2: Keyword-derived position-dependent alphabets
    # Each letter of the keyword defines a shift for that position (cycling)
    for keyword in keywords:
        kw_shifts = [ALPH_IDX[c] for c in keyword.upper() if c in ALPH_IDX]
        kw_len = len(kw_shifts)
        if kw_len == 0:
            continue

        for base_name, base_alph in base_alphabets.items():
            # Method: at position i, shift the base alphabet by keyword[i % kw_len]
            # This is essentially Vigenere, which we know is eliminated for periodic keys.
            # BUT: test with the KRYPTOS alphabet (non-standard ordering) as base.
            # Standard Vigenere uses ALPH ordering; using KRYPTOS ordering is different.

            pt_chars = []
            for i in range(CT_LEN):
                shift = kw_shifts[i % kw_len]
                alph = rotate_alphabet(base_alph, shift)
                ct_pos = alph.find(CT[i])
                if ct_pos >= 0:
                    pt_chars.append(ALPH[ct_pos])
                else:
                    pt_chars.append("?")
            pt = "".join(pt_chars)

            score = sum(1 for pos, ch in CRIB_DICT.items()
                        if pos < len(pt) and pt[pos] == ch)
            configs_tested += 1

            if score > best_score:
                best_score = score

            if score >= 5:
                results.append({
                    "method": f"kw_shift_{keyword}",
                    "base": base_name,
                    "score": score,
                    "pt_preview": pt[:30],
                })

    # Test 3: Quagmire-style position-dependent alphabets
    # Each position uses a DIFFERENT keyword-mixed alphabet
    # The keyword rotates: position i uses keyword starting at letter i % len(keyword)
    for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]:
        kw_len = len(keyword)
        for indicator_kw in ["KRYPTOS", "ABSCISSA"]:
            ind_shifts = [ALPH_IDX[c] for c in indicator_kw if c in ALPH_IDX]
            ind_len = len(ind_shifts)

            # Build keyword-mixed alphabet
            seen = set()
            mixed = []
            for c in keyword.upper():
                if c not in seen and c in ALPH_IDX:
                    mixed.append(c)
                    seen.add(c)
            for c in ALPH:
                if c not in seen:
                    mixed.append(c)
                    seen.add(c)
            mixed_alph = "".join(mixed)

            # Decrypt with indicator-driven rotation of mixed alphabet
            pt_chars = []
            for i in range(CT_LEN):
                shift = ind_shifts[i % ind_len]
                alph = rotate_alphabet(mixed_alph, shift)
                ct_pos = alph.find(CT[i])
                if ct_pos >= 0:
                    pt_chars.append(ALPH[ct_pos])
                else:
                    pt_chars.append("?")
            pt = "".join(pt_chars)

            score = sum(1 for pos, ch in CRIB_DICT.items()
                        if pos < len(pt) and pt[pos] == ch)
            configs_tested += 1

            if score > best_score:
                best_score = score

            if score >= 5:
                results.append({
                    "method": f"quagmire_{keyword}_{indicator_kw}",
                    "base": "mixed",
                    "score": score,
                    "pt_preview": pt[:30],
                })

    print(f"Configs tested: {configs_tested}")
    print(f"Best crib score: {best_score}/24")
    print(f"Results with score >= 5: {len([r for r in results if r['score'] >= 5])}")

    if results:
        for r in sorted(results, key=lambda x: -x["score"])[:5]:
            print(f"  {r['method']} ({r['base']}): {r['score']}/24")
            print(f"    PT: {r['pt_preview']}...")

    return {"best_score": best_score, "configs_tested": configs_tested, "results": results}


# ============================================================================
# HYPOTHESIS 3: Interleave/deinterleave + dual substitution
# ============================================================================

def deinterleave(text: str, n: int, start: int = 0) -> List[str]:
    """Split text into n interleaved streams.

    stream[k] = text[start+k], text[start+k+n], text[start+k+2n], ...
    """
    streams = ["" for _ in range(n)]
    for i, ch in enumerate(text):
        streams[i % n] += ch
    return streams


def interleave(streams: List[str]) -> str:
    """Recombine interleaved streams."""
    result = []
    max_len = max(len(s) for s in streams)
    for i in range(max_len):
        for s in streams:
            if i < len(s):
                result.append(s[i])
    return "".join(result)


def test_h3_dual_system():
    """Test Sanborn's "two separate systems" as literal dual encryption.

    If the CT was produced by interleaving two separately encrypted streams:
    - Even positions encrypted with system A (e.g., Vigenere with key1)
    - Odd positions encrypted with system B (e.g., Beaufort with key2)

    For each split, we check if the known cribs constrain the key enough
    to be useful.

    Also test: N-way interleave (N=3,4,5) and different starting phases.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 3: Dual/multi-system interleave")
    print("=" * 70)

    results = []
    best_score = 0
    configs_tested = 0

    # All cipher variant combinations for 2 systems
    variants = ["vigenere", "beaufort", "var_beaufort"]

    decrypt_fns = {
        "vigenere": lambda c, k: (c - k) % MOD,
        "beaufort": lambda c, k: (k - c) % MOD,
        "var_beaufort": lambda c, k: (c + k) % MOD,
    }

    recover_fns = {
        "vigenere": lambda c, p: (c - p) % MOD,
        "beaufort": lambda c, p: (c + p) % MOD,
        "var_beaufort": lambda c, p: (p - c) % MOD,
    }

    # Test N-way interleave with N=2,3,4,5
    for n_streams in range(2, 6):
        # Split cribs into their respective streams
        stream_cribs: Dict[int, Dict[int, str]] = {s: {} for s in range(n_streams)}
        for pos, ch in CRIB_DICT.items():
            stream_idx = pos % n_streams
            stream_pos = pos // n_streams
            stream_cribs[stream_idx][stream_pos] = ch

        # For each stream, test all variants with small periodic keys
        for periods in itertools.product(range(1, 8), repeat=n_streams):
            for var_combo in itertools.product(variants, repeat=n_streams):
                # For each stream, recover key at crib positions
                # and check if the key is consistent with the given period
                all_consistent = True
                total_score = 0

                for s in range(n_streams):
                    variant = var_combo[s]
                    period = periods[s]
                    recover_fn = recover_fns[variant]

                    # Stream s contains CT chars at positions s, s+n_streams, s+2*n_streams, ...
                    stream_ct = [CT_NUMS[j] for j in range(s, CT_LEN, n_streams)]

                    # Recover key at crib positions within this stream
                    key_residues: Dict[int, int] = {}  # residue -> key value
                    consistent = True

                    for stream_pos, pt_ch in stream_cribs[s].items():
                        if stream_pos >= len(stream_ct):
                            continue
                        c = stream_ct[stream_pos]
                        p = ALPH_IDX[pt_ch]
                        k = recover_fn(c, p)
                        residue = stream_pos % period

                        if residue in key_residues:
                            if key_residues[residue] != k:
                                consistent = False
                                break
                        else:
                            key_residues[residue] = k

                    if consistent:
                        total_score += len(stream_cribs[s])
                    else:
                        all_consistent = False
                        break

                configs_tested += 1

                if all_consistent and total_score > best_score:
                    best_score = total_score

                if all_consistent and total_score >= 10:
                    results.append({
                        "n_streams": n_streams,
                        "variants": list(var_combo),
                        "periods": list(periods),
                        "score": total_score,
                    })

                # Early termination for large search spaces
                if configs_tested > 500000:
                    break
            if configs_tested > 500000:
                break
        if configs_tested > 500000:
            print(f"  (terminated early at {configs_tested} configs)")
            break

    print(f"Configs tested: {configs_tested}")
    print(f"Best crib score: {best_score}/24")
    print(f"Fully consistent configs with score >= 10: {len(results)}")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["score"])[:10]:
            print(f"  n={r['n_streams']} vars={r['variants']} periods={r['periods']}: {r['score']}/24")

    return {"best_score": best_score, "configs_tested": configs_tested, "results": results}


# ============================================================================
# HYPOTHESIS 4: Modified autokey with K1-K3 seeding
# ============================================================================

def test_h4_k123_autokey():
    """Test autokey cipher seeded with K1/K2/K3 plaintext.

    Standard autokey was eliminated because it's stateful (contradicts K5
    position-dependent constraint). BUT if the "key" is literally the
    plaintext of earlier sections, then each position has a fixed key
    value (= the corresponding K1/K2/K3 plaintext letter at that offset).

    This makes it a running key cipher where the key text is the
    prior solutions. Since K3 is 337 chars, it alone can cover K4's 97.

    The twist: test with different offsets into K1/K2/K3, and test
    all three variants.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 4: K1-K3 plaintext as running key (extended autokey)")
    print("=" * 70)

    # K1-K3 plaintext (public knowledge)
    K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABORTIQLUSION"
    K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOLONITAWASSLOWLYDESPERATLYNEEDINGAQUALIFIEDOPERATORWHOISITWHOWASREADYTOGOOUTWITHTHEEXTRATIMETHEYHADNOTHINGWHATSOEVERTOWORKWITHXITWOULDTAKEANEXPERTINREADINGTHESIGNATURESTOASCERTAINTHETRUEMEANINGOFTHEDOCUMENTIONSSUBMITTEDTOTHEMONTHEIRREADINGSOFANYARTICULATEUSEFULNESS"
    # Note: K2 contains the famous misspellings (UNDERGRUUND, etc.)

    K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDABORIESWERERECOVEREDGENTLYATFIRSTBUTIINTHELASTANDWITHGROWINGEXCITEMENTASERIESOFFASCINATINGDISCOVERIESWEREBEINGMADETHEREARAPPEAREDTOBEATINYCROSSNEARTHEOPENINGINWHICHHADBEENUSEDTOPENETRATETHISCHAMBERANDSEALEDWITHPLASTEROFPARISONDTHEFLOORBENEATHTHEDOORWAYWASASMALLPOTTERYJARINTHISANDSOMEOTHERSWEREFOUNDSEALEDROBBERYHADOBVIOUSLYBEENPRACTISEDONDAPREMIUMSCALEIHADEXPECTEDTOFINDCONSIDERABLEREMAINSOFTHEORIGINALFURNITURETHEREWERENONEBOTHCORRIDORSHADBEENEMPTIED"
    # Note: This is an approximation - the exact K3 plaintext varies slightly by source

    # Source texts to test
    sources = {
        "K1": K1_PT,
        "K2": K2_PT,
        "K3": K3_PT,
        "K1K2": K1_PT + K2_PT,
        "K2K3": K2_PT + K3_PT,
        "K1K2K3": K1_PT + K2_PT + K3_PT,
        "K3_reversed": K3_PT[::-1],
        "K2_reversed": K2_PT[::-1],
    }

    decrypt_fns = {
        "vigenere": lambda c, k: (c - k) % MOD,
        "beaufort": lambda c, k: (k - c) % MOD,
        "var_beaufort": lambda c, k: (c + k) % MOD,
    }

    results = []
    best_score = 0
    configs_tested = 0

    for src_name, src_text in sources.items():
        src_text = "".join(c for c in src_text.upper() if c in ALPH_IDX)
        max_offset = len(src_text) - CT_LEN
        if max_offset <= 0:
            print(f"  {src_name}: too short ({len(src_text)} chars), skipping")
            continue

        for variant_name, decrypt_fn in decrypt_fns.items():
            src_best = 0
            src_best_offset = 0

            for offset in range(max_offset):
                score = 0
                for pos, expected_ch in CRIB_DICT.items():
                    key_pos = offset + pos
                    if key_pos >= len(src_text):
                        break
                    k = ALPH_IDX[src_text[key_pos]]
                    p = decrypt_fn(CT_NUMS[pos], k)
                    if ALPH[p] == expected_ch:
                        score += 1

                configs_tested += 1

                if score > src_best:
                    src_best = score
                    src_best_offset = offset

                if score > best_score:
                    best_score = score

                if score >= 7:
                    # Decrypt full text
                    pt_chars = []
                    for i in range(CT_LEN):
                        kp = offset + i
                        if kp >= len(src_text):
                            break
                        k = ALPH_IDX[src_text[kp]]
                        p = decrypt_fn(CT_NUMS[i], k)
                        pt_chars.append(ALPH[p])
                    pt = "".join(pt_chars)

                    results.append({
                        "source": src_name,
                        "variant": variant_name,
                        "offset": offset,
                        "score": score,
                        "pt_preview": pt[:40],
                        "key_preview": src_text[offset:offset+20],
                    })

            print(f"  {src_name} + {variant_name}: best={src_best}/24 at offset={src_best_offset}")

    print(f"\nConfigs tested: {configs_tested}")
    print(f"Best crib score: {best_score}/24")
    print(f"Results with score >= 7: {len([r for r in results if r['score'] >= 7])}")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["score"])[:5]:
            print(f"  {r['source']} + {r['variant']} offset={r['offset']}: {r['score']}/24")
            print(f"    PT: {r['pt_preview']}...")
            print(f"    Key: {r['key_preview']}...")

    return {"best_score": best_score, "configs_tested": configs_tested, "results": results}


# ============================================================================
# BONUS: Test keystream as positions in K1-K3 plaintext
# ============================================================================

def test_bonus_keystream_in_k123():
    """Check if the known Vigenere/Beaufort keystream values at crib positions
    correspond to positions of letters in K1/K2/K3 plaintext.

    If the key IS the K3 plaintext at specific offsets, the keystream values
    should be the alphabetic indices of K3 letters. We already test this
    as running key above. But here we check a different angle: do the
    keystream VALUES (not letters) index into some structure?
    """
    print("\n" + "=" * 70)
    print("BONUS: Keystream structure analysis")
    print("=" * 70)

    # Known keystream (Vigenere convention)
    vig_key_positions = {}
    for i, (pos, _) in enumerate(sorted(CRIB_DICT.items())):
        if pos <= 33:
            vig_key_positions[pos] = VIGENERE_KEY_ENE[pos - 21]
        else:
            vig_key_positions[pos] = VIGENERE_KEY_BC[pos - 63]

    print("Known Vigenere keystream at crib positions:")
    for pos in sorted(vig_key_positions.keys()):
        k = vig_key_positions[pos]
        print(f"  pos {pos:2d}: k={k:2d} ({ALPH[k]})")

    # Check: are the key values at crib positions the same as CT or PT
    # at some offset? (Self-referential key)
    print("\nSelf-reference check:")
    for offset in range(-50, 51):
        matches = 0
        for pos, k in vig_key_positions.items():
            ref_pos = pos + offset
            if 0 <= ref_pos < CT_LEN:
                if CT_NUMS[ref_pos] == k:
                    matches += 1
        if matches >= 4:
            print(f"  Offset {offset:+3d}: {matches}/24 keystream values match CT")

    # Check: differences between consecutive key values
    sorted_positions = sorted(vig_key_positions.keys())
    diffs = []
    for i in range(len(sorted_positions) - 1):
        p1, p2 = sorted_positions[i], sorted_positions[i + 1]
        k1, k2 = vig_key_positions[p1], vig_key_positions[p2]
        diff = (k2 - k1) % 26
        diffs.append(diff)
    print(f"\nKey value differences (mod 26): {diffs}")

    # Check: are key values a simple function of position?
    print("\nKey vs position analysis:")
    for a in range(26):
        for b in range(26):
            matches = sum(1 for pos, k in vig_key_positions.items()
                          if (a * pos + b) % 26 == k)
            if matches >= 8:
                print(f"  k = ({a}*pos + {b}) mod 26: {matches}/24 matches")

    return {"keystream": vig_key_positions}


# ============================================================================
# Main
# ============================================================================

def main():
    print("E-EXPLORER-04: Non-Standard Cipher Structures")
    print(f"CT: {CT[:20]}...{CT[-10:]}")
    print(f"CT length: {CT_LEN}")
    print(f"Cribs: {N_CRIBS} positions")

    t0 = time.time()
    all_results = {}

    # H1: Polybius-variant lookup tables
    h1 = test_h1_polybius_charts()
    all_results["h1_polybius"] = h1

    # H2: Position-dependent alphabet switching
    h2 = test_h2_position_dependent_alphabets()
    all_results["h2_position_dependent"] = h2

    # H3: Dual/multi-system interleave
    h3 = test_h3_dual_system()
    all_results["h3_dual_system"] = h3

    # H4: K1-K3 plaintext as running key
    h4 = test_h4_k123_autokey()
    all_results["h4_k123_autokey"] = h4

    # Bonus: Keystream structure
    bonus = test_bonus_keystream_in_k123()
    all_results["bonus_keystream"] = bonus

    elapsed = time.time() - t0

    # Final Summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total time: {elapsed:.1f}s")
    print(f"H1 (Polybius charts):          best={h1['best_score']}/24")
    print(f"H2 (Position-dep. alphabets):  best={h2['best_score']}/24")
    print(f"H3 (Dual-system interleave):   best={h3['best_score']}/24")
    print(f"H4 (K1-K3 running key):        best={h4['best_score']}/24")

    print("\n--- INTERPRETATION ---")
    noise_floor = 6
    for label, score in [
        ("H1", h1['best_score']),
        ("H2", h2['best_score']),
        ("H3", h3['best_score']),
        ("H4", h4['best_score']),
    ]:
        if score >= 18:
            print(f"{label}: SIGNAL ({score}/24) — investigate further")
        elif score >= 10:
            print(f"{label}: INTERESTING ({score}/24) — above noise, worth logging")
        elif score >= 7:
            print(f"{label}: MARGINAL ({score}/24) — near noise ceiling")
        else:
            print(f"{label}: NOISE ({score}/24) — within random expectation")

    # H3 special note: fully consistent interleave configs
    if h3['results']:
        print(f"\nH3 NOTE: {len(h3['results'])} fully consistent multi-system configs found.")
        print("  These are consistent with cribs but likely underdetermined.")
        print("  Need English language scoring to distinguish real from noise.")

    # Save
    out_path = ARTIFACTS_DIR / "explorer_04_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
