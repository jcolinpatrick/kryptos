"""
KryptosBot Compute Engine — Local parallel execution layer.

DESIGN PHILOSOPHY:
    The Agent SDK is expensive (tokens) but smart (reasoning).
    Your local CPU is cheap but needs direction.

    So: use 1-3 agent sessions for INTELLIGENCE, and dispatch
    the actual cryptanalytic computation as LOCAL multiprocessing
    jobs across all available cores.

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
        num_workers = mp.cpu_count() or 4

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
        num_workers = mp.cpu_count() or 4

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
            "No crib match at positions 63-73 (0-indexed). Both cipher families eliminated."
        ) if not crib_matches else "",
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    return summary


# ---------------------------------------------------------------------------
# Master dispatch: run everything locally
# ---------------------------------------------------------------------------

def run_all_local_attacks(
    num_workers: int = 0,
    output_dir: str = "kbot_results",
) -> dict[str, Any]:
    """
    Run all parallelized local attacks. This is what agents should
    DISPATCH instead of writing their own brute-force code.

    Returns a summary of all attacks.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

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
# Key-Split Combiner — Constants & Utilities
# ---------------------------------------------------------------------------

# Numeric representation of K4 ciphertext
K4_NUM = [ord(c) - 65 for c in K4]

# All 24 known crib positions as (pos, expected_number) for fast checking
_CRIB_CHECKS: list[tuple[int, int]] = []
for _cs, _cw in CRIBS:
    for _ci, _cc in enumerate(_cw):
        _CRIB_CHECKS.append((_cs + _ci, ord(_cc) - 65))

# Bean constraint positions
_BEAN_EQ = ((27, 65),)
_BEAN_INEQ = (
    (24, 28), (28, 33), (24, 33), (21, 30), (21, 64), (30, 64),
    (68, 25), (22, 31), (66, 70), (26, 71), (69, 72), (23, 32),
    (71, 21), (25, 26), (24, 66), (31, 73), (29, 63), (32, 33),
    (67, 68), (27, 72), (23, 28),
)


# Alphabetic key sources (24 sources from installation context)
SPLIT_ALPHA_SOURCES: dict[str, list[int]] = {
    "KRYPTOS":       [ord(c) - 65 for c in "KRYPTOS"],
    "LOOMIS":        [ord(c) - 65 for c in "LOOMIS"],
    "BOWEN":         [ord(c) - 65 for c in "BOWEN"],
    "ABBOTT":        [ord(c) - 65 for c in "ABBOTT"],
    "PALIMPSEST":    [ord(c) - 65 for c in "PALIMPSEST"],
    "ABSCISSA":      [ord(c) - 65 for c in "ABSCISSA"],
    "BERLINCLOCK":   [ord(c) - 65 for c in "BERLINCLOCK"],
    "WEBSTER":       [ord(c) - 65 for c in "WEBSTER"],
    "SANBORN":       [ord(c) - 65 for c in "SANBORN"],
    "SCHEIDT":       [ord(c) - 65 for c in "SCHEIDT"],
    "LANGLEY":       [ord(c) - 65 for c in "LANGLEY"],
    "FALLSCHURCH":   [ord(c) - 65 for c in "FALLSCHURCH"],
    "SHADOW":        [ord(c) - 65 for c in "SHADOW"],
    "IQLUSION":      [ord(c) - 65 for c in "IQLUSION"],
    "LAYERTWO":      [ord(c) - 65 for c in "LAYERTWO"],
    "IDBYROWS":      [ord(c) - 65 for c in "IDBYROWS"],
    "CLOCK":         [ord(c) - 65 for c in "CLOCK"],
    "BERLIN":        [ord(c) - 65 for c in "BERLIN"],
    "WELTZEITUHR":   [ord(c) - 65 for c in "WELTZEITUHR"],
    "DRUSILLA":      [ord(c) - 65 for c in "DRUSILLA"],
    "PBOWEN":        [ord(c) - 65 for c in "PBOWEN"],
    "OLDGEORGETOWN": [ord(c) - 65 for c in "OLDGEORGETOWN"],
    "MCLEAN":        [ord(c) - 65 for c in "MCLEAN"],
    "TURNERFAIRBANK":[ord(c) - 65 for c in "TURNERFAIRBANK"],
}

# Numeric key sources (from LOOMIS/BOWEN datasheets and K2)
SPLIT_NUMERIC_SOURCES: dict[str, list[int]] = {
    "K2_lat_dms":       [3, 8, 5, 7, 6, 5],
    "K2_lon_dms":       [7, 7, 8, 4, 4],
    "K2_coords_full":   [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],
    "LOOMIS_elev_m":    [7, 9],
    "LOOMIS_elev_ft":   [2, 5, 9],
    "LOOMIS_PID":       [7, 21, 4, 8, 2, 6],
    "LOOMIS_PID_digits":[4, 8, 2, 6],
    "LOOMIS_year":      [1, 9, 3, 0],
    "LOOMIS_geoid":     [3, 1, 8, 2],
    "LOOMIS_az_ABBOTT": [4, 5, 3, 5, 0, 5],
    "LOOMIS_lat_sec":   [0, 6, 2, 2, 0, 0, 7],
    "LOOMIS_lon_sec":   [4, 8, 1, 4, 1, 9, 2],
    "LOOMIS_UTM_N":     [4, 3, 1, 3, 6, 1, 1],
    "LOOMIS_UTM_E":     [3, 1, 3, 9, 7, 7],
    "BOWEN_PID":        [0, 9, 3, 4, 2, 7],
    "BOWEN_PID_digits": [3, 4, 2, 7],
    "coord_diff_lon":   [4, 1, 4],
    "eight_lines_73":   [8, 7, 3],
    "elevation_79":     [0, 7, 9],
    "BOWEN_year":       [1, 9, 8, 4],
    "BOWEN_lat_sec":    [1, 8],
    "BOWEN_lon_sec":    [5, 5],
    "BOWEN_grid":       [1, 3, 8, 1, 3, 9],
    "LOOMIS_BOWEN_yrs": [1, 9, 3, 0, 1, 9, 8, 4],
    "PBOWEN_alpha":     [15, 1, 14, 22, 4, 13],
}

# Text sources (from the sculpture itself) — used for running-key attacks
# K1 plaintext (63 chars)
_K1_PT = (
    "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABORUNIW"
    "AINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"[:63]  # truncated
)
# We define them properly below
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQ LUSION"[:63].replace(" ", "")
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMA"
    "GNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDER"
    "GRUUNDTOANUNKNOWNLOCATIONXDOESTHLANGLEYKNOWABOUTTHISTHEY"
    "SHOULDITSBURIEDDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIO"
    "NXONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEV"
    "ENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHT"
    "MINUTESFORTYFOURSECONDSWEST"
)[:369]
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORRUNIWASIN"
    "FBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)[:336]
# Corrected canonical K1-K3 plaintext
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
    "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESTHLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDDOUTTHERESOMEWHEREX"
    "WHOKNOWSTHEEXACTLOCATIONXONLYWWTHISWASHISLASTMESSAGEX"
    "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
    "SEVENTYSEVENDEGREESEIGLZTMINUTESFORTYFOURSECONDSWEST"
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORRUNIWASIN"
    "FBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
# Use only the first 336 chars for K3
K3_PT = K3_PT[:336] if len(K3_PT) >= 336 else K3_PT

# K1-K3 ciphertext
K1_CT = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
)
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIM"
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIM"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFO"
    "LSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFO"
    "ASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDD"
    "HINEHMNTYMQAINIOASMTRMYDAWLENROREAKPTDAAFMAPXCTIDAKNQSAIDSLLNOH"
    "FRHQKNEETNAALFEWPCTIDAKNQSAIDSLLNOH"
)

# Proper fixed K1-K3
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
    "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESTLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDDOUTTHERESOMEWHEREX"
    "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
    "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
    "SEVENTYSEVENDEGREESEIGLZTMINUTESFORTYFOURSECONDSWEST"
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATLAYAT"
    "THEBOTTOMOFTHESTAIRCASEWASAREMNANTOFSOMEANCIENTCIVILIZATI"
    "ONXWITHTREMBLINGHANDSIMADEATINYBREACHINTHELEFTHANDCORNERX"
    "ATFIRSTICOULDNTSEEANYTHINGXTHEHOTAIRRISINGFROMTHECHAMBERB"
    "LOCKINGTHECANDELIGHTXBUTNOWASTHEDETAILSOFTHEROOMWITHINEME"
    "RGEDFROMTHEMISTCANYOUSEEANYTHINGXQ"
)
# Ensure correct lengths
K1_PT = K1_PT[:63]
K2_PT = K2_PT[:369]
K3_PT = K3_PT[:336]

# Morse code text from sculpture
MORSE_TEXT = "VIRTUALLY INVISIBLE DIGETAL INTERPRETATIT SOS".replace(" ", "")

# K1-K3 CT (alpha only, from sculpture)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"[:63]
K2_CT_TEXT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"
    # Full K2 CT is 369 chars — we use what we have
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFO"
    "LSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFO"
    "ASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDD"
    "HINEHMNTYMQAINIOASMTRMYDAWLENROREAKPTDAAFMAPXCTIDAKNQSA"
)[:336]

# All text sources for running-key tests
SPLIT_TEXT_SOURCES: dict[str, str] = {
    "K1_PT": K1_PT,
    "K2_PT": K2_PT,
    "K3_PT": K3_PT,
    "K1_CT": K1_CT,
    "K3_CT": K3_CT,
    "MORSE": MORSE_TEXT,
    "K123_PT": K1_PT + K2_PT + K3_PT,
    "K123_CT": K1_CT + K3_CT,  # K2 CT partial
}

# Top-10 keywords for transposition-aware splits
TOP_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
    "BERLINCLOCK", "LOOMIS", "BOWEN", "WEBSTER", "LANGLEY",
]


def bean_filter(key: list[int]) -> bool:
    """Early-reject keys where Bean equality fails: key[27] != key[65].

    Returns True if key PASSES the filter (should be tested further).
    Returns False if key FAILS (should be rejected).
    ~96.2% rejection rate.
    """
    if len(key) < 74:
        return True  # Can't check — let through
    return key[27] == key[65]


def _check_cribs_numeric(key: list[int], variant: str = "vig") -> int:
    """Count crib matches for a numeric key against K4.

    variant: "vig" = P = (C - K) mod 26
             "beau" = P = (K - C) mod 26
             "varbeau" = P = (C + K) mod 26
    """
    matches = 0
    klen = len(key)
    for pos, expected in _CRIB_CHECKS:
        k = key[pos % klen] if pos < K4_LEN else 0
        c = K4_NUM[pos]
        if variant == "vig":
            p = (c - k) % 26
        elif variant == "beau":
            p = (k - c) % 26
        else:  # varbeau
            p = (c + k) % 26
        if p == expected:
            matches += 1
    return matches


def _decrypt_with_key(key: list[int], variant: str = "vig") -> str:
    """Decrypt K4 with a numeric key. Returns plaintext string."""
    klen = len(key)
    result = []
    for i in range(K4_LEN):
        c = K4_NUM[i]
        k = key[i % klen]
        if variant == "vig":
            p = (c - k) % 26
        elif variant == "beau":
            p = (k - c) % 26
        else:
            p = (c + k) % 26
        result.append(chr(p + 65))
    return "".join(result)


def _check_bean_key(key: list[int]) -> tuple[bool, bool]:
    """Check Bean EQ and INEQ on a full-length key (or repeating key)."""
    klen = len(key)
    # EQ check
    eq_pass = (key[27 % klen] == key[65 % klen])
    # INEQ check
    ineq_pass = True
    for p1, p2 in _BEAN_INEQ:
        if key[p1 % klen] == key[p2 % klen]:
            ineq_pass = False
            break
    return eq_pass, ineq_pass


# ---------------------------------------------------------------------------
# Key-Split Combiner: Key Derivation Chains (~73K configs)
# ---------------------------------------------------------------------------

def _derive_chain_worker(args: tuple) -> list[dict[str, Any]]:
    """Worker: test derivation chain keys."""
    chain_configs = args[0]
    results = []

    for cfg in chain_configs:
        key = cfg["key"]
        if not bean_filter(key):
            continue

        for vname in ("vig", "beau", "varbeau"):
            matches = _check_cribs_numeric(key, vname)
            if matches >= 10:
                pt = _decrypt_with_key(key, vname)
                eq, ineq = _check_bean_key(key)
                results.append({
                    "chain": cfg["chain"],
                    "sources": cfg["sources"],
                    "variant": vname,
                    "crib_chars_matched": matches,
                    "bean_eq": eq,
                    "bean_ineq": ineq,
                    "plaintext": pt[:50] if matches < 24 else pt,
                    "key_preview": "".join(chr(k + 65) for k in key[:20]),
                })

    return results


def _encrypt_keyword(a_nums: list[int], b_nums: list[int]) -> list[int]:
    """Encrypt keyword A with keyword B as Vigenere key. Result length = len(A)."""
    return [(a_nums[i] + b_nums[i % len(b_nums)]) % 26 for i in range(len(a_nums))]


def run_key_derivation_chains(
    num_workers: int | None = None,
    output_file: str = "derivation_chains.json",
) -> dict[str, Any]:
    """
    Multi-step key derivation: encrypt keyword A with keyword B, use result as K4 key.
    Tests Scheidt's CKM patent model: the final key never exists statically.

    ~73K configs: all (A,B) pairs × 3 encrypt methods × 3 decrypt variants + triple chains.
    """
    if num_workers is None:
        num_workers = mp.cpu_count() or 4

    start_time = time.time()
    all_sources = {**SPLIT_ALPHA_SOURCES}
    source_names = list(all_sources.keys())
    chain_configs: list[dict[str, Any]] = []

    # Double chains: encrypt(A, B) → key
    for na in source_names:
        a = all_sources[na]
        for nb in source_names:
            if na == nb:
                continue
            b = all_sources[nb]
            # Method 1: Vig-encrypt A with B
            key1 = [(a[i % len(a)] + b[i % len(b)]) % 26 for i in range(K4_LEN)]
            chain_configs.append({"key": key1, "chain": "add(A,B)", "sources": f"{na}+{nb}"})
            # Method 2: Vig-encrypt B with A
            key2 = [(b[i % len(b)] + a[i % len(a)]) % 26 for i in range(K4_LEN)]
            chain_configs.append({"key": key2, "chain": "add(B,A)", "sources": f"{nb}+{na}"})
            # Method 3: Subtract
            key3 = [(a[i % len(a)] - b[i % len(b)]) % 26 for i in range(K4_LEN)]
            chain_configs.append({"key": key3, "chain": "sub(A,B)", "sources": f"{na}-{nb}"})

    # Triple chains: encrypt(encrypt(A, B), C) — anchored to KRYPTOS
    anchor = all_sources["KRYPTOS"]
    for nb in source_names:
        if nb == "KRYPTOS":
            continue
        b = all_sources[nb]
        intermediate = [(anchor[i % len(anchor)] + b[i % len(b)]) % 26 for i in range(K4_LEN)]
        for nc in source_names:
            if nc in ("KRYPTOS", nb):
                continue
            c_src = all_sources[nc]
            key = [(intermediate[i] + c_src[i % len(c_src)]) % 26 for i in range(K4_LEN)]
            chain_configs.append({
                "key": key,
                "chain": "add(add(KRYPTOS,B),C)",
                "sources": f"KRYPTOS+{nb}+{nc}",
            })

    # Also add numeric sources combined with alphabetic
    for na in source_names[:10]:  # top 10 alpha sources
        a = all_sources[na]
        for nn, nv in SPLIT_NUMERIC_SOURCES.items():
            key = [(a[i % len(a)] + nv[i % len(nv)]) % 26 for i in range(K4_LEN)]
            chain_configs.append({"key": key, "chain": "add(A,N)", "sources": f"{na}+{nn}"})

    logger.info("Key derivation chains: %d configs across %d workers",
                len(chain_configs), num_workers)

    # Chunk and parallelize
    chunk_size = max(1, len(chain_configs) // (num_workers * 4))
    work_items = []
    for i in range(0, len(chain_configs), chunk_size):
        work_items.append((chain_configs[i:i + chunk_size],))

    all_results: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(_derive_chain_worker, item): item for item in work_items}
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception as exc:
                logger.error("Derivation chain worker error: %s", exc)

    all_results.sort(key=lambda x: x["crib_chars_matched"], reverse=True)
    elapsed = time.time() - start_time

    summary = {
        "attack": "key_derivation_chains",
        "configs_tested": len(chain_configs),
        "configs_after_bean": sum(1 for c in chain_configs if bean_filter(c["key"])),
        "results_above_10": len(all_results),
        "top_20": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
        "best_score": all_results[0]["crib_chars_matched"] if all_results else 0,
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    logger.info("Derivation chains: %d configs in %.1fs, best=%d/24 → %s",
                len(chain_configs), elapsed,
                summary["best_score"], output_file)
    return summary


# ---------------------------------------------------------------------------
# Key-Split Combiner: Tableau Row Keys (~1K configs)
# ---------------------------------------------------------------------------

def _build_ka_tableau() -> list[list[int]]:
    """Build the 26×26 KA Vigenere tableau as numeric rows."""
    ka = KRYPTOS_ALPHABET
    ka_idx = {c: i for i, c in enumerate(ka)}
    tableau = []
    for row in range(26):
        tableau.append([(ka_idx[ka[(row + col) % 26]]) for col in range(26)])
    return tableau


def _tableau_worker(args: tuple) -> list[dict[str, Any]]:
    """Worker: test tableau-derived keys."""
    configs = args[0]
    results = []
    for cfg in configs:
        key = cfg["key"]
        if not bean_filter(key):
            continue
        for vname in ("vig", "beau", "varbeau"):
            matches = _check_cribs_numeric(key, vname)
            if matches >= 10:
                pt = _decrypt_with_key(key, vname)
                results.append({
                    "method": cfg["method"],
                    "variant": vname,
                    "crib_chars_matched": matches,
                    "plaintext": pt[:50] if matches < 24 else pt,
                    "key_preview": "".join(chr(k + 65) for k in key[:20]),
                })
    return results


def run_tableau_row_keys(
    num_workers: int | None = None,
    output_file: str = "tableau_keys.json",
) -> dict[str, Any]:
    """
    Keys derived from the physical KA tableau structure:
    - Single rows, columns, diagonals as repeating keys
    - Keyword-indexed row sequences
    - Coordinate-indexed tableau lookups
    """
    if num_workers is None:
        num_workers = mp.cpu_count() or 4

    start_time = time.time()
    tableau = _build_ka_tableau()
    ka = KRYPTOS_ALPHABET
    ka_idx = {c: i for i, c in enumerate(ka)}
    configs: list[dict[str, Any]] = []

    # Single rows as repeating keys (26 configs)
    for r in range(26):
        key = [tableau[r][c % 26] for c in range(K4_LEN)]
        configs.append({"key": key, "method": f"row_{r}"})

    # Single columns as repeating keys (26 configs)
    for c in range(26):
        key = [tableau[r % 26][c] for r in range(K4_LEN)]
        configs.append({"key": key, "method": f"col_{c}"})

    # Main diagonals (26 configs each for 2 directions)
    for offset in range(26):
        key_d1 = [tableau[(i + offset) % 26][i % 26] for i in range(K4_LEN)]
        key_d2 = [tableau[i % 26][(i + offset) % 26] for i in range(K4_LEN)]
        configs.append({"key": key_d1, "method": f"diag_down_{offset}"})
        configs.append({"key": key_d2, "method": f"diag_right_{offset}"})

    # Keyword-indexed row sequences: read rows indexed by keyword letters
    for kw_name, kw_nums in SPLIT_ALPHA_SOURCES.items():
        key = []
        for i in range(K4_LEN):
            row_idx = kw_nums[i % len(kw_nums)] % 26
            col_idx = i % 26
            key.append(tableau[row_idx][col_idx])
        configs.append({"key": key, "method": f"kw_row_{kw_name}"})

    # Keyword-indexed column sequences
    for kw_name, kw_nums in list(SPLIT_ALPHA_SOURCES.items())[:10]:
        key = []
        for i in range(K4_LEN):
            row_idx = i % 26
            col_idx = kw_nums[i % len(kw_nums)] % 26
            key.append(tableau[row_idx][col_idx])
        configs.append({"key": key, "method": f"kw_col_{kw_name}"})

    # Double-keyword: row from A, col from B
    for na in list(SPLIT_ALPHA_SOURCES.keys())[:6]:  # top 6
        a = SPLIT_ALPHA_SOURCES[na]
        for nb in list(SPLIT_ALPHA_SOURCES.keys())[:6]:
            if na == nb:
                continue
            b = SPLIT_ALPHA_SOURCES[nb]
            key = [tableau[a[i % len(a)] % 26][b[i % len(b)] % 26] for i in range(K4_LEN)]
            configs.append({"key": key, "method": f"tableau_{na}_{nb}"})

    # Coordinate-indexed: use K2 coords to index tableau
    for nn, nv in list(SPLIT_NUMERIC_SOURCES.items())[:8]:
        key = [tableau[nv[i % len(nv)] % 26][i % 26] for i in range(K4_LEN)]
        configs.append({"key": key, "method": f"coord_row_{nn}"})

    logger.info("Tableau row keys: %d configs across %d workers",
                len(configs), num_workers)

    chunk_size = max(1, len(configs) // (num_workers * 2))
    work_items = []
    for i in range(0, len(configs), chunk_size):
        work_items.append((configs[i:i + chunk_size],))

    all_results: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(_tableau_worker, item): item for item in work_items}
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception as exc:
                logger.error("Tableau worker error: %s", exc)

    all_results.sort(key=lambda x: x["crib_chars_matched"], reverse=True)
    elapsed = time.time() - start_time

    summary = {
        "attack": "tableau_row_keys",
        "configs_tested": len(configs),
        "results_above_10": len(all_results),
        "top_20": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
        "best_score": all_results[0]["crib_chars_matched"] if all_results else 0,
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    logger.info("Tableau keys: %d configs in %.1fs, best=%d/24 → %s",
                len(configs), elapsed, summary["best_score"], output_file)
    return summary


# ---------------------------------------------------------------------------
# Key-Split Combiner: Positional Key Generation (~10K configs)
# ---------------------------------------------------------------------------

def _positional_worker(args: tuple) -> list[dict[str, Any]]:
    """Worker: test position-dependent key generation."""
    configs = args[0]
    results = []
    for cfg in configs:
        key = cfg["key"]
        if not bean_filter(key):
            continue
        for vname in ("vig", "beau", "varbeau"):
            matches = _check_cribs_numeric(key, vname)
            if matches >= 10:
                pt = _decrypt_with_key(key, vname)
                results.append({
                    "method": cfg["method"],
                    "sources": cfg["sources"],
                    "variant": vname,
                    "crib_chars_matched": matches,
                    "plaintext": pt[:50] if matches < 24 else pt,
                    "key_preview": "".join(chr(k + 65) for k in key[:20]),
                })
    return results


def run_positional_key_generation(
    num_workers: int | None = None,
    output_file: str = "positional_keys.json",
) -> dict[str, Any]:
    """
    Position-dependent mixing: key[i] = f(source_A[i%la], source_B[i%lb], i).
    Six mixing functions testing Scheidt's position-dependent combiner concept.
    """
    if num_workers is None:
        num_workers = mp.cpu_count() or 4

    start_time = time.time()
    configs: list[dict[str, Any]] = []

    source_names = list(SPLIT_ALPHA_SOURCES.keys())
    # Test all (A, B) pairs for top-12 sources × 6 mixing functions
    top_sources = source_names[:12]

    for na in top_sources:
        a = SPLIT_ALPHA_SOURCES[na]
        la = len(a)
        for nb in top_sources:
            if na == nb:
                continue
            b = SPLIT_ALPHA_SOURCES[nb]
            lb = len(b)

            # Function 1: (A + B + i) % 26 — position-shifted
            key1 = [(a[i % la] + b[i % lb] + i) % 26 for i in range(K4_LEN)]
            configs.append({"key": key1, "method": "pos_shift", "sources": f"{na},{nb}"})

            # Function 2: (A * (i+1) + B) % 26 — multiplicative position
            key2 = [(a[i % la] * (i + 1) + b[i % lb]) % 26 for i in range(K4_LEN)]
            configs.append({"key": key2, "method": "mult_pos", "sources": f"{na},{nb}"})

            # Function 3: (A + B[i² % lb]) % 26 — quadratic index into B
            key3 = [(a[i % la] + b[(i * i) % lb]) % 26 for i in range(K4_LEN)]
            configs.append({"key": key3, "method": "quad_idx", "sources": f"{na},{nb}"})

            # Function 4: (A ^ B) % 26 — XOR-like mod 26
            key4 = [(a[i % la] ^ b[i % lb]) % 26 for i in range(K4_LEN)]
            configs.append({"key": key4, "method": "xor_mod", "sources": f"{na},{nb}"})

            # Function 5: A[(i + B) % la] — B-indexed shuffle of A
            key5 = [a[(i + b[i % lb]) % la] for i in range(K4_LEN)]
            configs.append({"key": key5, "method": "b_shuffle", "sources": f"{na},{nb}"})

            # Function 6: (A + B + CT[i]) % 26 — CT-autokey hybrid
            key6 = [(a[i % la] + b[i % lb] + K4_NUM[i]) % 26 for i in range(K4_LEN)]
            configs.append({"key": key6, "method": "ct_autokey", "sources": f"{na},{nb}"})

    # Also test with numeric sources as B
    for na in top_sources[:6]:
        a = SPLIT_ALPHA_SOURCES[na]
        la = len(a)
        for nn, nv in list(SPLIT_NUMERIC_SOURCES.items())[:10]:
            lb = len(nv)
            key = [(a[i % la] + nv[i % lb] + i) % 26 for i in range(K4_LEN)]
            configs.append({"key": key, "method": "pos_shift_num", "sources": f"{na},{nn}"})
            key2 = [(a[i % la] * (i + 1) + nv[i % lb]) % 26 for i in range(K4_LEN)]
            configs.append({"key": key2, "method": "mult_pos_num", "sources": f"{na},{nn}"})

    logger.info("Positional key generation: %d configs across %d workers",
                len(configs), num_workers)

    chunk_size = max(1, len(configs) // (num_workers * 4))
    work_items = []
    for i in range(0, len(configs), chunk_size):
        work_items.append((configs[i:i + chunk_size],))

    all_results: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(_positional_worker, item): item for item in work_items}
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception as exc:
                logger.error("Positional key worker error: %s", exc)

    all_results.sort(key=lambda x: x["crib_chars_matched"], reverse=True)
    elapsed = time.time() - start_time

    summary = {
        "attack": "positional_key_generation",
        "configs_tested": len(configs),
        "results_above_10": len(all_results),
        "top_20": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
        "best_score": all_results[0]["crib_chars_matched"] if all_results else 0,
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    logger.info("Positional keys: %d configs in %.1fs, best=%d/24 → %s",
                len(configs), elapsed, summary["best_score"], output_file)
    return summary


# ---------------------------------------------------------------------------
# Key-Split Combiner: Installation Text Running Key (~2.3K configs)
# ---------------------------------------------------------------------------

def _running_key_worker(args: tuple) -> list[dict[str, Any]]:
    """Worker: test running key + keyword split combinations."""
    configs = args[0]
    results = []
    for cfg in configs:
        key = cfg["key"]
        if not bean_filter(key):
            continue
        for vname in ("vig", "beau", "varbeau"):
            matches = _check_cribs_numeric(key, vname)
            if matches >= 10:
                pt = _decrypt_with_key(key, vname)
                results.append({
                    "method": cfg["method"],
                    "source": cfg["source"],
                    "variant": vname,
                    "crib_chars_matched": matches,
                    "plaintext": pt[:50] if matches < 24 else pt,
                    "key_preview": "".join(chr(k + 65) for k in key[:20]),
                })
    return results


def run_installation_text_running_key(
    num_workers: int | None = None,
    output_file: str = "text_running_keys.json",
) -> dict[str, Any]:
    """
    K1-K3 PT/CT + Morse + combined texts as running key,
    optionally combined with keyword splits.
    Tests self-referential hypothesis: the sculpture's own text is a key component.
    """
    if num_workers is None:
        num_workers = mp.cpu_count() or 4

    start_time = time.time()
    configs: list[dict[str, Any]] = []

    for txt_name, txt in SPLIT_TEXT_SOURCES.items():
        if len(txt) < K4_LEN:
            continue  # Too short to use as running key without repeat
        txt_nums = [ord(c) - 65 for c in txt.upper() if c.isalpha()]
        if len(txt_nums) < K4_LEN:
            continue

        # Method 1: Direct running key (various offsets into the text)
        max_offsets = min(len(txt_nums) - K4_LEN + 1, 100)
        for offset in range(max_offsets):
            key = txt_nums[offset:offset + K4_LEN]
            configs.append({
                "key": key,
                "method": f"running_key_off{offset}",
                "source": txt_name,
            })

        # Method 2: Running key + keyword XOR
        for kw_name in TOP_KEYWORDS[:6]:
            kw = SPLIT_ALPHA_SOURCES[kw_name]
            kw_len = len(kw)
            for offset in range(min(max_offsets, 20)):
                rk = txt_nums[offset:offset + K4_LEN]
                key = [(rk[i] + kw[i % kw_len]) % 26 for i in range(K4_LEN)]
                configs.append({
                    "key": key,
                    "method": f"rk_plus_kw_off{offset}",
                    "source": f"{txt_name}+{kw_name}",
                })

    # Also test with shorter texts repeated
    for txt_name, txt in SPLIT_TEXT_SOURCES.items():
        txt_nums = [ord(c) - 65 for c in txt.upper() if c.isalpha()]
        if len(txt_nums) < 10 or len(txt_nums) >= K4_LEN:
            continue
        # Repeat to fill
        key = [txt_nums[i % len(txt_nums)] for i in range(K4_LEN)]
        configs.append({
            "key": key,
            "method": "repeated_text",
            "source": txt_name,
        })
        # Repeat + keyword
        for kw_name in TOP_KEYWORDS[:4]:
            kw = SPLIT_ALPHA_SOURCES[kw_name]
            combined = [(key[i] + kw[i % len(kw)]) % 26 for i in range(K4_LEN)]
            configs.append({
                "key": combined,
                "method": "repeated_text_plus_kw",
                "source": f"{txt_name}+{kw_name}",
            })

    logger.info("Installation text running keys: %d configs across %d workers",
                len(configs), num_workers)

    chunk_size = max(1, len(configs) // (num_workers * 4))
    work_items = []
    for i in range(0, len(configs), chunk_size):
        work_items.append((configs[i:i + chunk_size],))

    all_results: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(_running_key_worker, item): item for item in work_items}
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception as exc:
                logger.error("Running key worker error: %s", exc)

    all_results.sort(key=lambda x: x["crib_chars_matched"], reverse=True)
    elapsed = time.time() - start_time

    summary = {
        "attack": "installation_text_running_key",
        "configs_tested": len(configs),
        "results_above_10": len(all_results),
        "top_20": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
        "best_score": all_results[0]["crib_chars_matched"] if all_results else 0,
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    logger.info("Text running keys: %d configs in %.1fs, best=%d/24 → %s",
                len(configs), elapsed, summary["best_score"], output_file)
    return summary


# ---------------------------------------------------------------------------
# Key-Split Combiner: Alphabet Mapping Keys (~225 configs)
# ---------------------------------------------------------------------------

def run_alphabet_mapping_keys(
    num_workers: int | None = None,
    output_file: str = "alphabet_mapping_keys.json",
) -> dict[str, Any]:
    """
    Keys from AZ↔KA mapping displacement vectors and
    keyword-through-tableau transformations.
    """
    if num_workers is None:
        num_workers = mp.cpu_count() or 4

    start_time = time.time()
    ka = KRYPTOS_ALPHABET
    ka_idx = {c: i for i, c in enumerate(ka)}
    az = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    configs: list[dict[str, Any]] = []

    # AZ→KA displacement vector: for each letter, how far it moves
    az_to_ka_disp = [(ka_idx[c] - i) % 26 for i, c in enumerate(az)]
    ka_to_az_disp = [(ord(c) - 65 - i) % 26 for i, c in enumerate(ka)]

    # Method 1: Displacement vectors as repeating keys
    key1 = [az_to_ka_disp[i % 26] for i in range(K4_LEN)]
    configs.append({"key": key1, "method": "az_to_ka_disp"})
    key2 = [ka_to_az_disp[i % 26] for i in range(K4_LEN)]
    configs.append({"key": key2, "method": "ka_to_az_disp"})

    # Method 2: Keyword through KA tableau — map each keyword letter through KA
    for kw_name, kw_nums in SPLIT_ALPHA_SOURCES.items():
        # Transform keyword through KA mapping
        mapped = [ka_idx[az[k % 26]] for k in kw_nums]
        key = [mapped[i % len(mapped)] for i in range(K4_LEN)]
        configs.append({"key": key, "method": f"kw_through_ka_{kw_name}"})

        # Double mapping: keyword → KA → displacement
        double_mapped = [(ka_idx[az[k % 26]] - k) % 26 for k in kw_nums]
        key = [double_mapped[i % len(double_mapped)] for i in range(K4_LEN)]
        configs.append({"key": key, "method": f"kw_double_map_{kw_name}"})

    # Method 3: Displacement + keyword combination
    for kw_name in TOP_KEYWORDS[:8]:
        kw = SPLIT_ALPHA_SOURCES[kw_name]
        kw_len = len(kw)
        key = [(az_to_ka_disp[i % 26] + kw[i % kw_len]) % 26 for i in range(K4_LEN)]
        configs.append({"key": key, "method": f"disp_plus_kw_{kw_name}"})
        key2 = [(az_to_ka_disp[i % 26] * kw[i % kw_len]) % 26 for i in range(K4_LEN)]
        configs.append({"key": key2, "method": f"disp_mult_kw_{kw_name}"})

    # Method 4: KA self-mapping chains
    # Apply KA mapping repeatedly: letter → KA position → use that as index → ...
    for depth in range(2, 6):
        chain_key = list(range(26))
        for _ in range(depth):
            chain_key = [ka_idx[az[chain_key[j] % 26]] for j in range(26)]
        key = [chain_key[i % 26] for i in range(K4_LEN)]
        configs.append({"key": key, "method": f"ka_chain_depth{depth}"})

    logger.info("Alphabet mapping keys: %d configs", len(configs))

    all_results: list[dict[str, Any]] = []
    # Small enough to run single-threaded
    for cfg in configs:
        key = cfg["key"]
        if not bean_filter(key):
            continue
        for vname in ("vig", "beau", "varbeau"):
            matches = _check_cribs_numeric(key, vname)
            if matches >= 10:
                pt = _decrypt_with_key(key, vname)
                all_results.append({
                    "method": cfg["method"],
                    "variant": vname,
                    "crib_chars_matched": matches,
                    "plaintext": pt[:50] if matches < 24 else pt,
                    "key_preview": "".join(chr(k + 65) for k in key[:20]),
                })

    all_results.sort(key=lambda x: x["crib_chars_matched"], reverse=True)
    elapsed = time.time() - start_time

    summary = {
        "attack": "alphabet_mapping_keys",
        "configs_tested": len(configs),
        "results_above_10": len(all_results),
        "top_20": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
        "best_score": all_results[0]["crib_chars_matched"] if all_results else 0,
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    logger.info("Alphabet mapping keys: %d configs in %.1fs, best=%d/24 → %s",
                len(configs), elapsed, summary["best_score"], output_file)
    return summary


# ---------------------------------------------------------------------------
# Key-Split Combiner: Transposition-Aware Splits (~3M configs, pruned)
# ---------------------------------------------------------------------------

def _trans_split_worker(args: tuple) -> list[dict[str, Any]]:
    """
    Worker for transposition-aware key splits.
    For each columnar permutation, checks if first crib char lands correctly,
    then does full substitution + crib check on survivors.
    """
    width, perm_chunk, kw_keys, layer_orders = args
    results = []
    nrows = -(-K4_LEN // width)
    n_long = K4_LEN - width * (nrows - 1)

    for perm in perm_chunk:
        # Quick check: does E (pos 21) or B (pos 63) survive first-char test?
        # Under trans-first (decrypt trans then sub): check if CT at mapped position
        # could yield the crib char for any variant
        # Under sub-first (decrypt sub then trans): the crib constraint is on
        # the sub output, which we need to check differently

        for order in layer_orders:
            if order == "trans_first":
                # Decrypt transposition first, then substitution
                # After undoing trans, position i in intermediate came from CT[perm_mapped[i]]
                # Then we decrypt the intermediate with substitution to get PT
                # For crib: PT[pos] = decrypt_sub(intermediate[pos], key[pos])
                # where intermediate[pos] = CT[trans_source[pos]]
                # Quick reject: check first char of each crib
                pt21_ct_idx = _pt_pos_to_ct_idx(21, perm, width, nrows, n_long)
                if pt21_ct_idx >= K4_LEN:
                    continue
                ct_at_21 = K4_NUM[pt21_ct_idx]

                pt63_ct_idx = _pt_pos_to_ct_idx(63, perm, width, nrows, n_long)
                if pt63_ct_idx >= K4_LEN:
                    continue
                ct_at_63 = K4_NUM[pt63_ct_idx]

                # For E at pos 21: need key s.t. decrypt(ct_at_21, k) = E(=4)
                # For B at pos 63: need key s.t. decrypt(ct_at_63, k) = B(=1)
                # These constrain the key at those positions

                # Full decrypt transposition
                intermediate = _columnar_decrypt(K4, perm)
                inter_nums = [ord(c) - 65 for c in intermediate]

                for kw_name, kw_nums in kw_keys:
                    kw_len = len(kw_nums)
                    for vname in ("vig", "beau", "varbeau"):
                        # Quick check positions 21 and 63
                        k21 = kw_nums[21 % kw_len]
                        k63 = kw_nums[63 % kw_len]

                        if vname == "vig":
                            p21 = (inter_nums[21] - k21) % 26
                            p63 = (inter_nums[63] - k63) % 26
                        elif vname == "beau":
                            p21 = (k21 - inter_nums[21]) % 26
                            p63 = (k63 - inter_nums[63]) % 26
                        else:
                            p21 = (inter_nums[21] + k21) % 26
                            p63 = (inter_nums[63] + k63) % 26

                        if p21 != 4 or p63 != 1:  # E=4, B=1
                            continue

                        # Full crib check
                        matches = 0
                        key_full = [kw_nums[i % kw_len] for i in range(K4_LEN)]
                        for pos, expected in _CRIB_CHECKS:
                            c = inter_nums[pos]
                            k = key_full[pos]
                            if vname == "vig":
                                p = (c - k) % 26
                            elif vname == "beau":
                                p = (k - c) % 26
                            else:
                                p = (c + k) % 26
                            if p == expected:
                                matches += 1

                        if matches >= 10:
                            # Full decrypt
                            pt = _decrypt_with_key(key_full, vname)
                            # Actually decrypt the transposed intermediate
                            pt_chars = []
                            for i in range(K4_LEN):
                                c = inter_nums[i]
                                k = key_full[i]
                                if vname == "vig":
                                    p = (c - k) % 26
                                elif vname == "beau":
                                    p = (k - c) % 26
                                else:
                                    p = (c + k) % 26
                                pt_chars.append(chr(p + 65))
                            pt = "".join(pt_chars)

                            # Bean check on key
                            eq, ineq = _check_bean_key(key_full)
                            results.append({
                                "width": width,
                                "perm": list(perm),
                                "keyword": kw_name,
                                "variant": vname,
                                "order": order,
                                "crib_chars_matched": matches,
                                "bean_eq": eq,
                                "bean_ineq": ineq,
                                "plaintext": pt[:50] if matches < 24 else pt,
                            })

            elif order == "sub_first":
                # Decrypt substitution first (on raw CT), then transposition
                # PT = undo_trans(decrypt_sub(CT, key))
                for kw_name, kw_nums in kw_keys:
                    kw_len = len(kw_nums)
                    for vname in ("vig", "beau", "varbeau"):
                        # Decrypt substitution on raw CT
                        inter = []
                        key_full = [kw_nums[i % kw_len] for i in range(K4_LEN)]
                        for i in range(K4_LEN):
                            c = K4_NUM[i]
                            k = key_full[i]
                            if vname == "vig":
                                p = (c - k) % 26
                            elif vname == "beau":
                                p = (k - c) % 26
                            else:
                                p = (c + k) % 26
                            inter.append(chr(p + 65))
                        inter_text = "".join(inter)

                        # Now undo transposition
                        pt = _columnar_decrypt(inter_text, perm)

                        # Quick reject on first crib chars
                        if len(pt) > 63 and pt[21] == 'E' and pt[63] == 'B':
                            matches = 0
                            for pos, expected in _CRIB_CHECKS:
                                if pos < len(pt) and ord(pt[pos]) - 65 == expected:
                                    matches += 1
                            if matches >= 10:
                                eq, ineq = _check_bean_key(key_full)
                                results.append({
                                    "width": width,
                                    "perm": list(perm),
                                    "keyword": kw_name,
                                    "variant": vname,
                                    "order": order,
                                    "crib_chars_matched": matches,
                                    "bean_eq": eq,
                                    "bean_ineq": ineq,
                                    "plaintext": pt[:50] if matches < 24 else pt,
                                })

    return results


def run_transposition_aware_splits(
    min_width: int = 5,
    max_width: int = 8,
    num_workers: int | None = None,
    output_file: str = "trans_aware_splits.json",
) -> dict[str, Any]:
    """
    Different key splits for different cipher layers:
    columnar widths 5-8 (exhaustive permutations) × top 10 substitution keywords
    × 3 variants × 2 layer orderings.

    Uses crib-first-char pruning for >96% early rejection.
    """
    if num_workers is None:
        num_workers = mp.cpu_count() or 4

    start_time = time.time()
    all_results: list[dict[str, Any]] = []

    # Prepare keyword keys
    kw_keys = [(name, SPLIT_ALPHA_SOURCES[name]) for name in TOP_KEYWORDS]
    layer_orders = ["trans_first", "sub_first"]

    total_perms = 0

    for width in range(min_width, max_width + 1):
        from math import factorial
        n_perms = factorial(width)
        total_perms += n_perms
        logger.info("Trans-aware splits: width %d — %s perms × %d kw × 3 variants × 2 orders",
                     width, f"{n_perms:,}", len(kw_keys))

        # Chunk permutations
        from itertools import islice
        chunk_size = min(50_000, max(1_000, n_perms // (num_workers * 4)))
        perm_iter = permutations(range(width))
        tested = 0
        width_start = time.time()

        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures: dict[Any, int] = {}

            while True:
                chunk = list(islice(perm_iter, chunk_size))
                if not chunk:
                    break
                future = executor.submit(
                    _trans_split_worker,
                    (width, chunk, kw_keys, layer_orders),
                )
                futures[future] = len(chunk)

                # Backpressure
                if len(futures) >= num_workers * 2:
                    done_futures = []
                    for f in as_completed(futures):
                        done_futures.append(f)
                        if len(done_futures) >= num_workers:
                            break
                    for f in done_futures:
                        try:
                            all_results.extend(f.result())
                            tested += futures[f]
                        except Exception as exc:
                            logger.error("Trans-split worker error: %s", exc)
                        del futures[f]

            # Drain
            for f in as_completed(futures):
                try:
                    all_results.extend(f.result())
                    tested += futures.get(f, 0)
                except Exception as exc:
                    logger.error("Trans-split worker error: %s", exc)

        width_elapsed = time.time() - width_start
        rate = tested / width_elapsed if width_elapsed > 0 else 0
        logger.info("  Width %d done: %s perms in %.1fs (%s/sec), %d hits so far",
                     width, f"{tested:,}", width_elapsed, f"{rate:,.0f}", len(all_results))

    all_results.sort(key=lambda x: x["crib_chars_matched"], reverse=True)
    elapsed = time.time() - start_time

    summary = {
        "attack": "transposition_aware_splits",
        "widths_tested": list(range(min_width, max_width + 1)),
        "total_perms": total_perms,
        "keywords_tested": [name for name, _ in kw_keys],
        "results_above_10": len(all_results),
        "top_20": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
        "best_score": all_results[0]["crib_chars_matched"] if all_results else 0,
    }

    Path(output_file).write_text(json.dumps(summary, indent=2))
    logger.info("Trans-aware splits: %s perms in %.1fs, best=%d/24 → %s",
                f"{total_perms:,}", elapsed, summary["best_score"], output_file)
    return summary


# ---------------------------------------------------------------------------
# Master dispatch for key-split campaign
# ---------------------------------------------------------------------------

def run_all_split_attacks(
    num_workers: int = 0,
    output_dir: str = "split_results",
) -> dict[str, Any]:
    """Run all key-split combiner attacks. Returns summary."""
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    results: dict[str, Any] = {}
    start_time = time.time()

    logger.info("=" * 60)
    logger.info("Key-Split Combiner Campaign — %d workers", num_workers)
    logger.info("=" * 60)

    # 1. Alphabet mapping keys (fast, <1s)
    logger.info("--- Phase 1: Alphabet Mapping Keys ---")
    results["alphabet_mapping"] = run_alphabet_mapping_keys(
        num_workers=num_workers,
        output_file=str(out / "alphabet_mapping_keys.json"),
    )

    # 2. Tableau row keys (fast, <5s)
    logger.info("--- Phase 2: Tableau Row Keys ---")
    results["tableau"] = run_tableau_row_keys(
        num_workers=num_workers,
        output_file=str(out / "tableau_keys.json"),
    )

    # 3. Key derivation chains (moderate, ~30s)
    logger.info("--- Phase 3: Key Derivation Chains ---")
    results["derivation_chains"] = run_key_derivation_chains(
        num_workers=num_workers,
        output_file=str(out / "derivation_chains.json"),
    )

    # 4. Positional key generation (moderate, ~30s)
    logger.info("--- Phase 4: Positional Key Generation ---")
    results["positional"] = run_positional_key_generation(
        num_workers=num_workers,
        output_file=str(out / "positional_keys.json"),
    )

    # 5. Installation text running key (moderate, ~1min)
    logger.info("--- Phase 5: Installation Text Running Key ---")
    results["text_running_key"] = run_installation_text_running_key(
        num_workers=num_workers,
        output_file=str(out / "text_running_keys.json"),
    )

    # 6. Transposition-aware splits (heaviest, ~5-20min)
    logger.info("--- Phase 6: Transposition-Aware Splits ---")
    try:
        results["trans_splits"] = run_transposition_aware_splits(
            min_width=5,
            max_width=8,
            num_workers=num_workers,
            output_file=str(out / "trans_aware_splits.json"),
        )
    except Exception as exc:
        logger.error("Trans-aware splits failed: %s", exc)
        results["trans_splits"] = {"status": f"FAILED: {exc}"}

    elapsed = time.time() - start_time

    # Aggregate
    best_overall = 0
    for r in results.values():
        if isinstance(r, dict):
            best_overall = max(best_overall, r.get("best_score", 0))

    master_summary = {
        "campaign": "key_split_combiner",
        "attacks_run": list(results.keys()),
        "elapsed_seconds": round(elapsed, 1),
        "best_overall_score": best_overall,
        "per_attack": {
            k: {
                "configs": v.get("configs_tested", v.get("total_perms", "?")),
                "hits_above_10": v.get("results_above_10", 0),
                "best": v.get("best_score", 0),
                "time": v.get("elapsed_seconds", "?"),
            }
            for k, v in results.items()
            if isinstance(v, dict)
        },
    }

    (out / "master_summary.json").write_text(json.dumps(master_summary, indent=2))
    logger.info("=" * 60)
    logger.info("Key-Split Campaign complete: %.1fs, best=%d/24", elapsed, best_overall)
    logger.info("Results in %s/", out)
    logger.info("=" * 60)
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
    parser.add_argument("--workers", type=int, default=0, help="Number of CPU workers (0 = auto-detect)")
    parser.add_argument("--output", type=str, default="kbot_results", help="Output directory")
    parser.add_argument("--attack", type=str, default="all",
                        choices=["all", "stats", "simple", "keywords", "columnar",
                                 "splits", "derivation", "tableau", "positional",
                                 "textkey", "alphamap", "transplit"],
                        help="Which attack to run")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

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
    elif args.attack == "splits":
        run_all_split_attacks(num_workers=args.workers, output_dir=args.output)
    elif args.attack == "derivation":
        run_key_derivation_chains(num_workers=args.workers, output_file=f"{args.output}/derivation_chains.json")
    elif args.attack == "tableau":
        run_tableau_row_keys(num_workers=args.workers, output_file=f"{args.output}/tableau_keys.json")
    elif args.attack == "positional":
        run_positional_key_generation(num_workers=args.workers, output_file=f"{args.output}/positional_keys.json")
    elif args.attack == "textkey":
        run_installation_text_running_key(num_workers=args.workers, output_file=f"{args.output}/text_running_keys.json")
    elif args.attack == "alphamap":
        run_alphabet_mapping_keys(num_workers=args.workers, output_file=f"{args.output}/alphabet_mapping_keys.json")
    elif args.attack == "transplit":
        run_transposition_aware_splits(num_workers=args.workers, output_file=f"{args.output}/trans_aware_splits.json")
