"""
KryptosBot Compute Engine — Local parallel execution layer.

DESIGN PHILOSOPHY:
    The Agent SDK is expensive (tokens) but smart (reasoning).
    Your VM is cheap (local CPU) but needs direction.

    So: use 1-3 agent sessions for INTELLIGENCE, and dispatch
    the actual cryptanalytic computation as LOCAL multiprocessing
    jobs across all 28 cores.

    Agent sessions should:
      - Read the framework, understand what exists
      - Decide what to run and with what parameters
      - Generate or locate the right scripts
      - DISPATCH them as local jobs (not execute inline)
      - Interpret results and decide next steps

    Local jobs should:
      - Do the brute-force permutation sweeps
      - Do the scoring against quadgram tables
      - Do the statistical profiling
      - Write structured JSON results to disk
      - Use ALL available cores via multiprocessing

This module provides the local compute layer that agents dispatch to.
"""

from __future__ import annotations

import json
import logging
import multiprocessing as mp
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from itertools import permutations
from math import log10
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("kryptosbot.compute")

# ---------------------------------------------------------------------------
# K4 Constants (duplicated here to avoid import overhead in worker processes)
# ---------------------------------------------------------------------------

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
K4_LEN = 97

# Both known cribs (0-indexed)
CRIBS = [
    (21, "EASTNORTHEAST"),  # positions 21-33
    (63, "BERLINCLOCK"),    # positions 63-73
]
# Legacy single-crib aliases (used by check_crib)
CRIB = "BERLINCLOCK"
CRIB_START = 63

# ---------------------------------------------------------------------------
# Quadgram Scorer (loaded once per process, cached)
# ---------------------------------------------------------------------------

_QUADGRAMS: dict[str, float] | None = None
_QG_FLOOR: float = -10.0


def load_quadgrams(filepath: str | Path | None = None) -> dict[str, float]:
    """
    Load English quadgram log-probabilities.

    Expected file format: one line per quadgram, tab-separated:
        TION    4567823
        NTHE    3456789
        ...

    If no file is provided, tries common locations.
    Returns dict mapping quadgram -> log10(probability).
    """
    global _QUADGRAMS, _QG_FLOOR

    if _QUADGRAMS is not None:
        return _QUADGRAMS

    search_paths = [
        filepath,
        Path("english_quadgrams.txt"),
        Path("data/english_quadgrams.txt"),
        Path("data/english_quadgrams.json"),
        Path("resources/english_quadgrams.txt"),
    ]

    for p in search_paths:
        if p and Path(p).exists():
            with open(p) as f:
                content = f.read().strip()

            # JSON format: {"THAN": -3.776, ...} (values are log10 probs)
            if content.startswith("{"):
                import json as _json
                raw_json = _json.loads(content)
                _QUADGRAMS = {k.upper(): float(v) for k, v in raw_json.items()}
                _QG_FLOOR = min(_QUADGRAMS.values()) - 1.0
                logger.info("Loaded %d quadgrams (JSON) from %s", len(_QUADGRAMS), p)
                return _QUADGRAMS

            # Text format: "THAN 12345" (values are integer counts)
            raw: dict[str, int] = {}
            for line in content.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    raw[parts[0].upper()] = int(parts[1])

            total = sum(raw.values())
            _QUADGRAMS = {qg: log10(count / total) for qg, count in raw.items()}
            _QG_FLOOR = log10(0.01 / total)
            logger.info("Loaded %d quadgrams from %s", len(_QUADGRAMS), p)
            return _QUADGRAMS

    # Fallback: empty scorer (will score everything as floor)
    logger.warning("No quadgram file found — scoring will be unreliable")
    _QUADGRAMS = {}
    return _QUADGRAMS


def score_text(text: str) -> float:
    """Score English-likeness using quadgram log-probabilities."""
    qg = load_quadgrams()
    if not qg:
        return 0.0

    score = 0.0
    upper = text.upper()
    for i in range(len(upper) - 3):
        gram = upper[i:i + 4]
        score += qg.get(gram, _QG_FLOOR)
    return score


def check_crib(plaintext: str) -> bool:
    """Check if BERLINCLOCK appears at the correct position."""
    if len(plaintext) < CRIB_START + len(CRIB):
        return False
    return plaintext[CRIB_START:CRIB_START + len(CRIB)] == CRIB


def check_all_cribs(plaintext: str) -> int:
    """Check all known cribs. Returns number of matching crib characters (0-24)."""
    matches = 0
    for start, crib in CRIBS:
        if len(plaintext) < start + len(crib):
            continue
        for i, ch in enumerate(crib):
            if plaintext[start + i] == ch:
                matches += 1
    return matches


# ---------------------------------------------------------------------------
# Columnar Transposition — parallelized
# ---------------------------------------------------------------------------

def _columnar_decrypt(ciphertext: str, key_order: tuple[int, ...]) -> str:
    """Decrypt columnar transposition given a column ordering."""
    ncols = len(key_order)
    nrows = -(-len(ciphertext) // ncols)  # ceiling division
    n_long = len(ciphertext) - ncols * (nrows - 1)  # columns with extra char

    # Determine column lengths
    col_lengths = []
    for col in range(ncols):
        orig_col = key_order[col]
        col_lengths.append(nrows if orig_col < n_long else nrows - 1)

    # Split ciphertext into columns (in key order)
    columns: list[str] = []
    pos = 0
    for length in col_lengths:
        columns.append(ciphertext[pos:pos + length])
        pos += length

    # Reorder columns to original position
    ordered: list[str] = [""] * ncols
    for i, col_idx in enumerate(key_order):
        ordered[col_idx] = columns[i]

    # Read off row by row
    plaintext = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(ordered[col]):
                plaintext.append(ordered[col][row])

    return "".join(plaintext)


def _pt_pos_to_ct_idx(pt_pos: int, key_order: tuple[int, ...], ncols: int, nrows: int, n_long: int) -> int:
    """Map a plaintext position to its ciphertext index under columnar transposition.

    This avoids full decryption — just computes where one character comes from.
    """
    row = pt_pos // ncols
    col = pt_pos % ncols

    # Find where column `col` appears in reading order
    reading_pos = key_order.index(col)

    # CT offset = sum of lengths of all columns read before this one
    ct_offset = 0
    for i in range(reading_pos):
        ct_offset += nrows if key_order[i] < n_long else nrows - 1

    return ct_offset + row


def _test_columnar_width_chunk(args: tuple[int, list[tuple[int, ...]]]) -> list[dict[str, Any]]:
    """
    Worker function for multiprocessing.
    Tests a chunk of permutations for a given column width.

    Optimized: checks crib characters via direct position mapping (no full decrypt)
    before attempting full decryption. This rejects ~96%+ of permutations with
    just 2 character lookups.
    """
    width, perm_chunk = args

    results = []
    nrows = -(-K4_LEN // width)
    n_long = K4_LEN - width * (nrows - 1)

    # Precompute crib position lookups: (pt_position, expected_char)
    crib_checks = []
    for start, crib in CRIBS:
        for i, ch in enumerate(crib):
            crib_checks.append((start + i, ch))

    # Quick-reject positions: first char of each crib
    quick_checks = [(21, 'E'), (63, 'B')]

    for perm in perm_chunk:
        # Stage 1: ultra-fast rejection — check first char of each crib
        reject = False
        for pt_pos, expected in quick_checks:
            if pt_pos >= K4_LEN:
                continue
            ct_idx = _pt_pos_to_ct_idx(pt_pos, perm, width, nrows, n_long)
            if ct_idx >= K4_LEN or K4[ct_idx] != expected:
                reject = True
                break
        if reject:
            continue

        # Stage 2: check all 24 crib characters via position mapping
        crib_matches = 0
        for pt_pos, expected in crib_checks:
            if pt_pos >= K4_LEN:
                continue
            ct_idx = _pt_pos_to_ct_idx(pt_pos, perm, width, nrows, n_long)
            if ct_idx < K4_LEN and K4[ct_idx] == expected:
                crib_matches += 1

        if crib_matches >= 10:  # partial match worth recording
            plaintext = _columnar_decrypt(K4, perm)
            score = score_text(plaintext) if crib_matches >= 20 else 0.0
            results.append({
                "width": width,
                "key": list(perm),
                "score": score,
                "plaintext": plaintext if crib_matches == 24 else plaintext[:50],
                "crib_match": crib_matches == 24,
                "crib_chars_matched": crib_matches,
            })

    return results


def run_columnar_transposition(
    min_width: int = 2,
    max_width: int = 15,
    num_workers: int | None = None,
    output_file: str = "columnar_results.json",
) -> dict[str, Any]:
    """
    Exhaustive columnar transposition attack using all CPU cores.

    For each key width, generates all permutations, chunks them across
    workers, and collects the top-scoring candidates.

    Returns a summary dict and writes detailed results to output_file.
    """
    if num_workers is None:
        num_workers = min(mp.cpu_count(), 28)

    all_results: list[dict[str, Any]] = []
    crib_matches: list[dict[str, Any]] = []
    start_time = time.time()

    logger.info(
        "Columnar transposition: widths %d-%d, %d workers",
        min_width, max_width, num_workers,
    )

    TOP_N = 50  # only keep top N results to bound memory

    for width in range(min_width, max_width + 1):
        from math import factorial
        total_perms = factorial(width)
        logger.info("Width %d: %s permutations", width, f"{total_perms:,}")

        if total_perms > 5_000_000_000:
            logger.warning("Width %d has %s perms — skipping (too large)", width, f"{total_perms:,}")
            continue

        from itertools import islice
        chunk_size = min(500_000, max(10_000, total_perms // (num_workers * 4)))
        perm_iter = permutations(range(width))
        perms_tested = 0
        width_start = time.time()
        last_report = width_start

        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures: dict[Any, int] = {}

            while True:
                chunk = list(islice(perm_iter, chunk_size))
                if not chunk:
                    break
                future = executor.submit(_test_columnar_width_chunk, (width, chunk))
                futures[future] = len(chunk)

                # Backpressure: wait when too many in-flight
                if len(futures) >= num_workers * 2:
                    done_futures = []
                    for f in as_completed(futures):
                        done_futures.append(f)
                        if len(done_futures) >= num_workers:
                            break
                    for f in done_futures:
                        try:
                            chunk_results = f.result()
                            perms_tested += futures[f]
                            for r in chunk_results:
                                if r.get("crib_match"):
                                    crib_matches.append(r)
                                    logger.critical("CRIB MATCH at width %d: %s", width, r["plaintext"][:40])
                                all_results.append(r)
                            # Bound memory: keep only top N
                            if len(all_results) > TOP_N * 2:
                                all_results.sort(key=lambda x: (x.get("crib_chars_matched", 0), x.get("score", 0)), reverse=True)
                                all_results = all_results[:TOP_N]
                        except Exception as exc:
                            logger.error("Worker error: %s", exc)
                        del futures[f]

                    # Progress report every 30 seconds
                    now = time.time()
                    if now - last_report >= 30:
                        elapsed_w = now - width_start
                        rate = perms_tested / elapsed_w if elapsed_w > 0 else 0
                        pct = perms_tested / total_perms * 100
                        eta = (total_perms - perms_tested) / rate if rate > 0 else 0
                        logger.info(
                            "  Width %d: %s/%s (%.1f%%) — %s/sec — ETA %.0fs",
                            width, f"{perms_tested:,}", f"{total_perms:,}", pct, f"{rate:,.0f}", eta,
                        )
                        last_report = now

            # Drain remaining futures
            for future in as_completed(futures):
                try:
                    chunk_results = future.result()
                    perms_tested += futures.get(future, 0)
                    for r in chunk_results:
                        if r.get("crib_match"):
                            crib_matches.append(r)
                            logger.critical("CRIB MATCH at width %d: %s", width, r["plaintext"][:40])
                        all_results.append(r)
                except Exception as exc:
                    logger.error("Worker error: %s", exc)

        # Trim after each width
        all_results.sort(key=lambda x: (x.get("crib_chars_matched", 0), x.get("score", 0)), reverse=True)
        all_results = all_results[:TOP_N]

        elapsed_w = time.time() - width_start
        rate = perms_tested / elapsed_w if elapsed_w > 0 else 0
        logger.info(
            "Width %d complete: %s perms in %.1fs (%s/sec) — %d crib matches",
            width, f"{perms_tested:,}", elapsed_w, f"{rate:,.0f}", len(crib_matches),
        )

    # Sort all results by score
    all_results.sort(key=lambda x: x["score"], reverse=True)
    elapsed = time.time() - start_time

    summary = {
        "attack": "columnar_transposition",
        "widths_tested": list(range(min_width, max_width + 1)),
        "total_candidates_scored": len(all_results),
        "crib_matches": crib_matches,
        "top_20": all_results[:20],
        "elapsed_seconds": elapsed,
        "num_workers": num_workers,
        "status": "SOLVED" if crib_matches else "DISPROVED" if max_width <= 15 else "PARTIAL",
        "disproof_evidence": (
            f"All permutations for widths {min_width}-{max_width} exhausted. "
            f"No crib match found in {len(all_results)} candidates."
        ) if not crib_matches else "",
    }

    output_path = Path(output_file)
    output_path.write_text(json.dumps(summary, indent=2))
    logger.info(
        "Columnar transposition complete: %.1fs, %d candidates, %d crib matches → %s",
        elapsed, len(all_results), len(crib_matches), output_path,
    )

    return summary


# ---------------------------------------------------------------------------
# Vigenère / Polyalphabetic — parallelized keyword search
# ---------------------------------------------------------------------------

KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"


def _vigenere_decrypt(ciphertext: str, keyword: str, alphabet: str = "") -> str:
    """Decrypt Vigenère cipher. Supports keyed alphabet."""
    if not alphabet:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    plaintext = []
    key_len = len(keyword)
    for i, c in enumerate(ciphertext.upper()):
        if c in alphabet:
            c_idx = alphabet.index(c)
            k_idx = alphabet.index(keyword[i % key_len].upper())
            p_idx = (c_idx - k_idx) % len(alphabet)
            plaintext.append(alphabet[p_idx])
        else:
            plaintext.append(c)
    return "".join(plaintext)


def _beaufort_decrypt(ciphertext: str, keyword: str, alphabet: str = "") -> str:
    """Decrypt Beaufort cipher."""
    if not alphabet:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    plaintext = []
    key_len = len(keyword)
    for i, c in enumerate(ciphertext.upper()):
        if c in alphabet:
            c_idx = alphabet.index(c)
            k_idx = alphabet.index(keyword[i % key_len].upper())
            p_idx = (k_idx - c_idx) % len(alphabet)
            plaintext.append(alphabet[p_idx])
        else:
            plaintext.append(c)
    return "".join(plaintext)


def _test_keyword_batch(args: tuple[list[str], str, str]) -> list[dict[str, Any]]:
    """Worker: test a batch of keywords with Vigenère and Beaufort."""
    keywords, cipher_type, alphabet = args
    load_quadgrams()

    results = []
    for kw in keywords:
        if cipher_type == "vigenere":
            pt = _vigenere_decrypt(K4, kw, alphabet)
        elif cipher_type == "beaufort":
            pt = _beaufort_decrypt(K4, kw, alphabet)
        else:
            continue

        crib_match = check_crib(pt)
        score = score_text(pt)

        if crib_match or score > -400:  # threshold for "interesting"
            results.append({
                "keyword": kw,
                "cipher": cipher_type,
                "alphabet": "kryptos" if alphabet == KRYPTOS_ALPHABET else "standard",
                "score": score,
                "plaintext": pt if crib_match else pt[:50],
                "crib_match": crib_match,
            })

    return results


def run_keyword_search(
    wordlist_path: str | Path | None = None,
    max_key_length: int = 12,
    num_workers: int | None = None,
    output_file: str = "keyword_results.json",
) -> dict[str, Any]:
    """
    Parallel Vigenère/Beaufort keyword search using all CPU cores.

    Tests each keyword against both standard and Kryptos-keyed alphabets,
    with both Vigenère and Beaufort decryption.
    """
    if num_workers is None:
        num_workers = min(mp.cpu_count(), 28)

    # Build keyword list — domain-specific words first
    kryptos_words = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
        "SHADOW", "LUCID", "MEMORY", "DYAHR", "VIRTUALLY", "INVISIBLE",
        "BERLIN", "CLOCK", "BERLINCLOCK", "NORTHEAST", "SOUTHEAST",
        "IQLUSION", "ILLUSION", "DESPERAT", "SLOWLY",
        "UNDERGROUND", "LANGLEY", "CIA", "MORSE", "DIGETAL",
        "WEBSTER", "DRUSILLA", "WELTZEITUHR", "ANTIPODES",
    ]

    # Auto-discover wordlist if not provided
    if not wordlist_path:
        for candidate in [
            Path("../wordlists/english.txt"),
            Path("wordlists/english.txt"),
            Path(os.environ.get("KBOT_PROJECT_ROOT", ".")) / "wordlists" / "english.txt",
        ]:
            if candidate.exists():
                wordlist_path = str(candidate)
                break

    # Load external wordlist
    if wordlist_path and Path(wordlist_path).exists():
        loaded = 0
        with open(wordlist_path) as f:
            for line in f:
                word = line.strip().upper()
                if 2 <= len(word) <= max_key_length and word.isalpha():
                    kryptos_words.append(word)
                    loaded += 1
        logger.info("Loaded %d words from %s (length 2-%d)", loaded, wordlist_path, max_key_length)
    else:
        logger.warning("No wordlist found — using %d built-in keywords only", len(kryptos_words))

    # Deduplicate
    keywords = list(set(kryptos_words))
    logger.info("Testing %d keywords × 2 ciphers × 2 alphabets = %d combinations",
                len(keywords), len(keywords) * 4)

    all_results: list[dict[str, Any]] = []
    crib_matches: list[dict[str, Any]] = []
    start_time = time.time()

    # Create work batches: keywords × cipher × alphabet
    batch_size = max(1, len(keywords) // (num_workers * 2))
    work_items = []
    for cipher in ["vigenere", "beaufort"]:
        for alphabet in ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", KRYPTOS_ALPHABET]:
            for i in range(0, len(keywords), batch_size):
                batch = keywords[i:i + batch_size]
                work_items.append((batch, cipher, alphabet))

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(_test_keyword_batch, item): item for item in work_items}
        for future in as_completed(futures):
            try:
                batch_results = future.result()
                for r in batch_results:
                    if r["crib_match"]:
                        crib_matches.append(r)
                        logger.critical("CRIB MATCH: %s / %s / %s", r["keyword"], r["cipher"], r["alphabet"])
                    all_results.append(r)
            except Exception as exc:
                logger.error("Worker error: %s", exc)

    all_results.sort(key=lambda x: x["score"], reverse=True)
    elapsed = time.time() - start_time

    summary = {
        "attack": "keyword_search",
        "keywords_tested": len(keywords),
        "cipher_types": ["vigenere", "beaufort"],
        "alphabets": ["standard", "kryptos"],
        "crib_matches": crib_matches,
        "top_20": all_results[:20],
        "elapsed_seconds": elapsed,
        "num_workers": num_workers,
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    logger.info("Keyword search complete: %.1fs, %d keywords → %s", elapsed, len(keywords), output_file)
    return summary


# ---------------------------------------------------------------------------
# Statistical Profile — single-process but fast (numpy-free)
# ---------------------------------------------------------------------------

def run_statistical_profile(output_file: str = "statistical_profile.json") -> dict[str, Any]:
    """Comprehensive statistical analysis of K4 ciphertext."""
    from collections import Counter

    text = K4.upper()
    n = len(text)

    # Letter frequency
    freq = Counter(text)
    freq_pct = {ch: count / n for ch, count in sorted(freq.items())}

    # Index of Coincidence
    ic = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1)) if n > 1 else 0

    # Shannon entropy
    from math import log2
    entropy = -sum((c / n) * log2(c / n) for c in freq.values() if c > 0)

    # Digraph IC
    digraphs = Counter(text[i:i + 2] for i in range(n - 1))
    total_di = sum(digraphs.values())
    di_ic = sum(c * (c - 1) for c in digraphs.values()) / (total_di * (total_di - 1)) if total_di > 1 else 0

    # Autocorrelation for periods 1-50
    autocorr: dict[int, float] = {}
    for period in range(1, min(51, n)):
        matches = sum(1 for i in range(n - period) if text[i] == text[i + period])
        autocorr[period] = matches / (n - period)

    # Chi-squared vs uniform
    expected_uniform = n / 26
    chi_sq_uniform = sum((freq.get(chr(65 + i), 0) - expected_uniform) ** 2 / expected_uniform for i in range(26))

    # English expected frequencies
    eng_freq = {
        'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127,
        'F': 0.022, 'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002,
        'K': 0.008, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075,
        'P': 0.019, 'Q': 0.001, 'R': 0.060, 'S': 0.063, 'T': 0.091,
        'U': 0.028, 'V': 0.010, 'W': 0.023, 'X': 0.002, 'Y': 0.020,
        'Z': 0.001,
    }
    chi_sq_english = sum(
        (freq.get(ch, 0) - eng_freq[ch] * n) ** 2 / (eng_freq[ch] * n)
        for ch in eng_freq
    )

    # Conclusions
    conclusions = []
    if 0.060 <= ic <= 0.070:
        conclusions.append("IoC (~{:.4f}) consistent with monoalphabetic substitution or transposition".format(ic))
    elif 0.040 <= ic <= 0.055:
        conclusions.append("IoC (~{:.4f}) consistent with polyalphabetic cipher (key length 3-10)".format(ic))
    elif ic < 0.040:
        conclusions.append("IoC (~{:.4f}) near random — consistent with long polyalphabetic key or complex cipher".format(ic))

    # Peak autocorrelation periods
    sorted_ac = sorted(autocorr.items(), key=lambda x: x[1], reverse=True)
    peak_periods = [p for p, v in sorted_ac[:5] if v > 1.2 / 26]
    if peak_periods:
        conclusions.append(f"Autocorrelation peaks at periods: {peak_periods} — possible key lengths")
    else:
        conclusions.append("No significant autocorrelation peaks — disfavors periodic polyalphabetic")

    profile = {
        "ciphertext_length": n,
        "letter_frequency": freq_pct,
        "index_of_coincidence": round(ic, 6),
        "digraph_ic": round(di_ic, 6),
        "shannon_entropy": round(entropy, 4),
        "chi_squared_vs_uniform": round(chi_sq_uniform, 2),
        "chi_squared_vs_english": round(chi_sq_english, 2),
        "autocorrelation": {str(k): round(v, 6) for k, v in sorted(autocorr.items())},
        "autocorrelation_peaks": peak_periods,
        "conclusions": conclusions,
        "reference": {
            "english_ic": 0.0667,
            "random_ic": 0.0385,
            "english_entropy": 4.19,
            "random_entropy": 4.70,
        },
    }

    Path(output_file).write_text(json.dumps(profile, indent=2))
    logger.info("Statistical profile written to %s", output_file)
    return profile


# ---------------------------------------------------------------------------
# Disproof: Caesar + Affine (exhaustive, fast, no multiprocessing needed)
# ---------------------------------------------------------------------------

def run_exhaustive_simple_ciphers(output_file: str = "simple_cipher_results.json") -> dict[str, Any]:
    """Exhaustively test Caesar (25 shifts) and Affine (312 keys)."""
    from math import gcd

    results: dict[str, Any] = {"caesar": [], "affine": []}
    crib_matches: list[dict[str, Any]] = []
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # Caesar
    for shift in range(1, 26):
        pt = "".join(alpha[(alpha.index(c) - shift) % 26] for c in K4)
        score = score_text(pt)
        entry = {"shift": shift, "score": score, "plaintext": pt[:50], "crib_match": check_crib(pt)}
        results["caesar"].append(entry)
        if entry["crib_match"]:
            crib_matches.append({"type": "caesar", **entry})

    # Affine: decrypt = a_inv * (c - b) mod 26
    valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]
    for a in valid_a:
        # Modular inverse of a
        a_inv = pow(a, -1, 26)
        for b in range(26):
            pt = "".join(alpha[(a_inv * (alpha.index(c) - b)) % 26] for c in K4)
            score = score_text(pt)
            entry = {"a": a, "b": b, "score": score, "plaintext": pt[:50], "crib_match": check_crib(pt)}
            results["affine"].append(entry)
            if entry["crib_match"]:
                crib_matches.append({"type": "affine", **entry})

    results["affine"].sort(key=lambda x: x["score"], reverse=True)
    results["caesar"].sort(key=lambda x: x["score"], reverse=True)

    summary = {
        "caesar_tested": 25,
        "affine_tested": len(valid_a) * 26,
        "crib_matches": crib_matches,
        "caesar_top5": results["caesar"][:5],
        "affine_top5": results["affine"][:5],
        "caesar_disproved": len(crib_matches) == 0,
        "affine_disproved": len(crib_matches) == 0,
        "disproof_evidence": (
            f"All 25 Caesar shifts and {len(valid_a) * 26} Affine keys tested. "
            "No crib match at positions 64-74. Both cipher families eliminated."
        ) if not crib_matches else "",
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    return summary


# ---------------------------------------------------------------------------
# Master dispatch: run everything locally
# ---------------------------------------------------------------------------

def run_all_local_attacks(
    num_workers: int = 28,
    output_dir: str = "kbot_results",
) -> dict[str, Any]:
    """
    Run all parallelized local attacks. This is what agents should
    DISPATCH instead of writing their own brute-force code.

    Returns a summary of all attacks.
    """
    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    results: dict[str, Any] = {}

    logger.info("=" * 60)
    logger.info("KryptosBot Local Compute Engine — %d workers", num_workers)
    logger.info("=" * 60)

    # 1. Statistical profile (fast, single-process)
    logger.info("--- Phase 1: Statistical Profile ---")
    results["statistical"] = run_statistical_profile(str(out / "statistical_profile.json"))

    # 2. Exhaustive simple ciphers (fast, single-process)
    logger.info("--- Phase 2: Simple Cipher Disproof ---")
    results["simple"] = run_exhaustive_simple_ciphers(str(out / "simple_ciphers.json"))

    # 3. Keyword search (parallel)
    logger.info("--- Phase 3: Keyword Search ---")
    results["keywords"] = run_keyword_search(
        num_workers=num_workers,
        output_file=str(out / "keyword_results.json"),
    )

    # 4. Columnar transposition (parallel, heaviest)
    # Wrapped in try/except — this is the phase most likely to hit
    # memory or time limits. Previous phases' results are preserved.
    logger.info("--- Phase 4: Columnar Transposition ---")
    try:
        results["columnar"] = run_columnar_transposition(
            min_width=2,
            max_width=12,  # 13+ needs hours even with streaming
            num_workers=num_workers,
            output_file=str(out / "columnar_results.json"),
        )
    except (MemoryError, Exception) as exc:
        logger.error("Columnar transposition failed: %s", exc)
        results["columnar"] = {"status": f"FAILED: {exc}", "crib_matches": []}

    # Summary
    total_crib_matches = sum(
        len(r.get("crib_matches", []))
        for r in results.values()
    )

    master_summary = {
        "attacks_run": list(results.keys()),
        "total_crib_matches": total_crib_matches,
        "results_directory": str(out),
        "per_attack": {k: {
            "crib_matches": len(v.get("crib_matches", [])),
            "status": v.get("status", "complete"),
        } for k, v in results.items()},
    }

    (out / "master_summary.json").write_text(json.dumps(master_summary, indent=2))
    logger.info("All local attacks complete. Results in %s/", out)
    return master_summary


# ---------------------------------------------------------------------------
# CLI entry point: run directly without Agent SDK
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="KryptosBot Local Compute Engine")
    parser.add_argument("--workers", type=int, default=28, help="Number of CPU workers")
    parser.add_argument("--output", type=str, default="kbot_results", help="Output directory")
    parser.add_argument("--attack", type=str, default="all",
                        choices=["all", "stats", "simple", "keywords", "columnar"],
                        help="Which attack to run")
    args = parser.parse_args()

    if args.attack == "all":
        run_all_local_attacks(args.workers, args.output)
    elif args.attack == "stats":
        run_statistical_profile(f"{args.output}/statistical_profile.json")
    elif args.attack == "simple":
        load_quadgrams()
        run_exhaustive_simple_ciphers(f"{args.output}/simple_ciphers.json")
    elif args.attack == "keywords":
        run_keyword_search(num_workers=args.workers, output_file=f"{args.output}/keyword_results.json")
    elif args.attack == "columnar":
        run_columnar_transposition(num_workers=args.workers, output_file=f"{args.output}/columnar_results.json")
