#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-TEAM-BOOK-CIPHER: Book cipher extraction from known texts.

Extracts keys from reference texts using non-sequential methods
(every-Nth word/char, sentence acrostics, prime/Fibonacci positions,
grid diagonals) and tests them against K4 under all three cipher variants.

Also tests K1-K3 known plaintexts as key sources.
"""
import sys
import os
import json
import re
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Configuration ──────────────────────────────────────────────────────

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_book_cipher.json")

# Source text files
SOURCE_FILES = [
    ("carter_gutenberg", "reference/carter_gutenberg.txt"),
    ("carter_vol1", "reference/carter_vol1.txt"),
    ("cia_charter", "reference/running_key_texts/cia_charter.txt"),
    ("jfk_berlin", "reference/running_key_texts/jfk_berlin.txt"),
    ("nsa_act_1947", "reference/running_key_texts/nsa_act_1947.txt"),
    ("reagan_berlin", "reference/running_key_texts/reagan_berlin.txt"),
    ("udhr", "reference/running_key_texts/udhr.txt"),
]

# K1-K3 known plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"

# EAST constraint: gap-9 diffs for Vigenere/Beaufort
EAST_DIFFS_VIG = [1, 25, 1, 23]  # positions 21-24 vs 30-33
EAST_DIFFS_VARBEAU = [25, 1, 25, 3]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

# ── Helper functions ───────────────────────────────────────────────────

def strip_alpha(text):
    """Extract only A-Z characters."""
    return "".join(c for c in text.upper() if c in ALPH)


def sieve_primes(max_n):
    """Simple sieve of Eratosthenes."""
    if max_n < 2:
        return []
    is_prime = [True] * (max_n + 1)
    is_prime[0] = is_prime[1] = False
    for i in range(2, int(max_n**0.5) + 1):
        if is_prime[i]:
            for j in range(i*i, max_n + 1, i):
                is_prime[j] = False
    return [i for i in range(2, max_n + 1) if is_prime[i]]


# ── Extraction methods ─────────────────────────────────────────────────

def extract_nth_word_first(text, n):
    """Every-Nth word, take first letter."""
    words = re.findall(r'[A-Za-z]+', text)
    return "".join(w[0].upper() for i, w in enumerate(words) if i % n == 0 and w)


def extract_nth_char(text, n):
    """Every-Nth character from alpha-only text."""
    alpha = strip_alpha(text)
    return alpha[::n]


def extract_sentence_acrostics(text):
    """First letter of each sentence."""
    sentences = re.split(r'[.!?]+', text)
    result = []
    for s in sentences:
        s = s.strip()
        if s:
            for c in s:
                if c.isalpha():
                    result.append(c.upper())
                    break
    return "".join(result)


def extract_primes(text, max_n=None):
    """Characters at prime-indexed positions."""
    alpha = strip_alpha(text)
    if max_n is None:
        max_n = len(alpha)
    primes = sieve_primes(max_n)
    return "".join(alpha[p] for p in primes if p < len(alpha))


def extract_fibonacci(text):
    """Characters at Fibonacci-indexed positions."""
    alpha = strip_alpha(text)
    fibs = [1, 1]
    while fibs[-1] < len(alpha):
        fibs.append(fibs[-1] + fibs[-2])
    return "".join(alpha[f] for f in fibs if f < len(alpha))


def extract_diagonal(text, width):
    """Diagonal of text laid out in a grid of given width."""
    alpha = strip_alpha(text)
    result = []
    for i in range(len(alpha)):
        row, col = divmod(i, width)
        if row == col:
            result.append(alpha[i])
    return "".join(result)


def extract_antidiagonal(text, width):
    """Anti-diagonal of text laid out in a grid of given width."""
    alpha = strip_alpha(text)
    result = []
    for i in range(len(alpha)):
        row, col = divmod(i, width)
        if row + col == width - 1:
            result.append(alpha[i])
    return "".join(result)


def extract_paragraph_acrostics(text):
    """First letter of each paragraph."""
    paragraphs = text.split('\n\n')
    result = []
    for p in paragraphs:
        p = p.strip()
        if p:
            for c in p:
                if c.isalpha():
                    result.append(c.upper())
                    break
    return "".join(result)


def extract_word_length_mod(text, mod_val):
    """Take first letter of words whose length mod mod_val == 0."""
    words = re.findall(r'[A-Za-z]+', text)
    return "".join(w[0].upper() for w in words if len(w) % mod_val == 0 and len(w) > 0)


def extract_nth_word_last(text, n):
    """Every-Nth word, take last letter."""
    words = re.findall(r'[A-Za-z]+', text)
    return "".join(w[-1].upper() for i, w in enumerate(words) if i % n == 0 and w)


# ── EAST constraint check ─────────────────────────────────────────────

def check_east_constraint(key_list):
    """Check if key satisfies EAST gap-9 diffs.

    EAST appears at positions 21-24 and 30-33 in cribs.
    Under running key, the key diffs at these positions must match.
    """
    if len(key_list) < 34:
        return False, False

    diffs = [(key_list[30+i] - key_list[21+i]) % MOD for i in range(4)]
    vig_match = (diffs == EAST_DIFFS_VIG)
    varbeau_match = (diffs == EAST_DIFFS_VARBEAU)
    return vig_match, varbeau_match


# ── Main evaluation loop ──────────────────────────────────────────────

def evaluate_extraction(extracted_text, source_name, method_name, params_str=""):
    """Test an extracted text as a key against K4."""
    if len(extracted_text) < CT_LEN:
        return None

    # Use first 97 characters as key
    key_str = extracted_text[:CT_LEN]
    key_list = [ALPH_IDX[c] for c in key_str]

    best_result = None
    best_score = -1

    # Check EAST constraint
    east_vig, east_varbeau = check_east_constraint(key_list)

    # Check Bean constraint on the key itself
    bean_result = verify_bean(key_list)

    for variant in VARIANTS:
        pt = decrypt_text(CT, key_list, variant)
        sc = score_candidate(pt, bean_result)

        score = sc.crib_score
        if score > best_score:
            best_score = score
            best_result = {
                "source": source_name,
                "method": method_name,
                "params": params_str,
                "variant": variant.value,
                "crib_score": sc.crib_score,
                "bean_passed": sc.bean_passed,
                "ic": sc.ic_value,
                "classification": sc.crib_classification,
                "east_vig_match": east_vig,
                "east_varbeau_match": east_varbeau,
                "key_snippet": key_str[:30],
                "pt_snippet": pt[:40],
                "summary": sc.summary,
                "extracted_len": len(extracted_text),
            }

    return best_result


def evaluate_with_offsets(extracted_text, source_name, method_name, params_str=""):
    """Test extracted text at multiple offsets as running key."""
    results = []
    if len(extracted_text) < CT_LEN:
        return results

    max_offset = min(len(extracted_text) - CT_LEN, 500)  # Cap at 500 offsets

    for offset in range(max_offset + 1):
        key_str = extracted_text[offset:offset + CT_LEN]
        if len(key_str) < CT_LEN:
            break

        key_list = [ALPH_IDX[c] for c in key_str]

        # Quick EAST check first as filter
        east_vig, east_varbeau = check_east_constraint(key_list)

        bean_result = verify_bean(key_list)

        for variant in VARIANTS:
            pt = decrypt_text(CT, key_list, variant)
            sc = score_candidate(pt, bean_result)

            if sc.crib_score >= 4 or east_vig or east_varbeau:  # Only record interesting results
                results.append({
                    "source": source_name,
                    "method": method_name,
                    "params": f"{params_str} offset={offset}",
                    "variant": variant.value,
                    "crib_score": sc.crib_score,
                    "bean_passed": sc.bean_passed,
                    "ic": sc.ic_value,
                    "classification": sc.crib_classification,
                    "east_vig_match": east_vig,
                    "east_varbeau_match": east_varbeau,
                    "key_snippet": key_str[:30],
                    "pt_snippet": pt[:40],
                    "summary": sc.summary,
                    "offset": offset,
                })

    return results


def main():
    t0 = time.time()
    base_dir = os.path.join(os.path.dirname(__file__), "..")

    # Load source texts
    sources = {}
    for name, rel_path in SOURCE_FILES:
        full_path = os.path.join(base_dir, rel_path)
        if os.path.exists(full_path):
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            sources[name] = raw
            print(f"  Loaded {name}: {len(raw)} chars, {len(strip_alpha(raw))} alpha")
        else:
            print(f"  WARNING: {full_path} not found, skipping")

    # Add K1-K3 plaintexts as sources
    sources["K1_plaintext"] = K1_PT
    sources["K2_plaintext"] = K2_PT
    sources["K3_plaintext"] = K3_PT
    # Combined K1+K2+K3
    sources["K123_combined"] = K1_PT + K2_PT + K3_PT
    # K3+K4 CT as potential key
    sources["K3K4_ct_combined"] = K3_PT + CT

    print(f"\nLoaded {len(sources)} sources total")
    print("=" * 70)

    all_results = []
    total_tested = 0
    best_overall = {"crib_score": -1}
    east_matches = []

    # ── Method 1: Every-Nth word first letter ──────────────────────────
    print("\n[1] Every-Nth word first letter (N=1..20)")
    for source_name, raw_text in sources.items():
        for n in range(1, 21):
            extracted = extract_nth_word_first(raw_text, n)
            if len(extracted) >= CT_LEN:
                result = evaluate_extraction(extracted, source_name, "nth_word_first", f"N={n}")
                total_tested += 1
                if result:
                    all_results.append(result)
                    if result["crib_score"] > best_overall.get("crib_score", -1):
                        best_overall = result
                    if result["east_vig_match"] or result["east_varbeau_match"]:
                        east_matches.append(result)
    print(f"  Tested {total_tested} configurations so far")

    # ── Method 2: Every-Nth character ──────────────────────────────────
    print("\n[2] Every-Nth character (N=1..30)")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        alpha = strip_alpha(raw_text)
        for n in range(1, 31):
            extracted = extract_nth_char(raw_text, n)
            if len(extracted) >= CT_LEN:
                result = evaluate_extraction(extracted, source_name, "nth_char", f"N={n}")
                total_tested += 1
                if result:
                    all_results.append(result)
                    if result["crib_score"] > best_overall.get("crib_score", -1):
                        best_overall = result
                    if result["east_vig_match"] or result["east_varbeau_match"]:
                        east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 3: Sentence acrostics ───────────────────────────────────
    print("\n[3] Sentence acrostics")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        extracted = extract_sentence_acrostics(raw_text)
        if len(extracted) >= CT_LEN:
            result = evaluate_extraction(extracted, source_name, "sentence_acrostics", "")
            total_tested += 1
            if result:
                all_results.append(result)
                if result["crib_score"] > best_overall.get("crib_score", -1):
                    best_overall = result
                if result["east_vig_match"] or result["east_varbeau_match"]:
                    east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 4: Prime-indexed positions ──────────────────────────────
    print("\n[4] Prime-indexed positions")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        extracted = extract_primes(raw_text)
        if len(extracted) >= CT_LEN:
            result = evaluate_extraction(extracted, source_name, "prime_positions", "")
            total_tested += 1
            if result:
                all_results.append(result)
                if result["crib_score"] > best_overall.get("crib_score", -1):
                    best_overall = result
                if result["east_vig_match"] or result["east_varbeau_match"]:
                    east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 5: Fibonacci positions ──────────────────────────────────
    print("\n[5] Fibonacci positions")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        extracted = extract_fibonacci(raw_text)
        if len(extracted) >= CT_LEN:
            result = evaluate_extraction(extracted, source_name, "fibonacci_positions", "")
            total_tested += 1
            if result:
                all_results.append(result)
                if result["crib_score"] > best_overall.get("crib_score", -1):
                    best_overall = result
                if result["east_vig_match"] or result["east_varbeau_match"]:
                    east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 6: Grid diagonals ───────────────────────────────────────
    print("\n[6] Grid diagonals (width 5-30)")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        for width in range(5, 31):
            extracted = extract_diagonal(raw_text, width)
            if len(extracted) >= CT_LEN:
                result = evaluate_extraction(extracted, source_name, "diagonal", f"width={width}")
                total_tested += 1
                if result:
                    all_results.append(result)
                    if result["crib_score"] > best_overall.get("crib_score", -1):
                        best_overall = result
                    if result["east_vig_match"] or result["east_varbeau_match"]:
                        east_matches.append(result)

            # Also anti-diagonal
            extracted = extract_antidiagonal(raw_text, width)
            if len(extracted) >= CT_LEN:
                result = evaluate_extraction(extracted, source_name, "antidiagonal", f"width={width}")
                total_tested += 1
                if result:
                    all_results.append(result)
                    if result["crib_score"] > best_overall.get("crib_score", -1):
                        best_overall = result
                    if result["east_vig_match"] or result["east_varbeau_match"]:
                        east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 7: Paragraph acrostics ──────────────────────────────────
    print("\n[7] Paragraph acrostics")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        extracted = extract_paragraph_acrostics(raw_text)
        if len(extracted) >= CT_LEN:
            result = evaluate_extraction(extracted, source_name, "paragraph_acrostics", "")
            total_tested += 1
            if result:
                all_results.append(result)
                if result["crib_score"] > best_overall.get("crib_score", -1):
                    best_overall = result
                if result["east_vig_match"] or result["east_varbeau_match"]:
                    east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 8: Word length mod ──────────────────────────────────────
    print("\n[8] Word length mod (mod 2-10)")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        for mod_val in range(2, 11):
            extracted = extract_word_length_mod(raw_text, mod_val)
            if len(extracted) >= CT_LEN:
                result = evaluate_extraction(extracted, source_name, "word_length_mod", f"mod={mod_val}")
                total_tested += 1
                if result:
                    all_results.append(result)
                    if result["crib_score"] > best_overall.get("crib_score", -1):
                        best_overall = result
                    if result["east_vig_match"] or result["east_varbeau_match"]:
                        east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 9: Every-Nth word last letter ───────────────────────────
    print("\n[9] Every-Nth word last letter (N=1..20)")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        for n in range(1, 21):
            extracted = extract_nth_word_last(raw_text, n)
            if len(extracted) >= CT_LEN:
                result = evaluate_extraction(extracted, source_name, "nth_word_last", f"N={n}")
                total_tested += 1
                if result:
                    all_results.append(result)
                    if result["crib_score"] > best_overall.get("crib_score", -1):
                        best_overall = result
                    if result["east_vig_match"] or result["east_varbeau_match"]:
                        east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 10: Full text as running key with offsets ────────────────
    print("\n[10] Full alpha text as running key (sliding window, up to 500 offsets)")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        alpha = strip_alpha(raw_text)
        if len(alpha) < CT_LEN:
            continue

        offset_results = evaluate_with_offsets(alpha, source_name, "running_key_offset", "")
        total_tested += min(len(alpha) - CT_LEN + 1, 501)
        for r in offset_results:
            all_results.append(r)
            if r["crib_score"] > best_overall.get("crib_score", -1):
                best_overall = r
            if r["east_vig_match"] or r["east_varbeau_match"]:
                east_matches.append(r)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 11: Reversed text as key ────────────────────────────────
    print("\n[11] Reversed alpha text as running key")
    count_before = total_tested
    for source_name, raw_text in sources.items():
        alpha = strip_alpha(raw_text)
        reversed_alpha = alpha[::-1]
        if len(reversed_alpha) >= CT_LEN:
            result = evaluate_extraction(reversed_alpha, source_name, "reversed", "")
            total_tested += 1
            if result:
                all_results.append(result)
                if result["crib_score"] > best_overall.get("crib_score", -1):
                    best_overall = result
                if result["east_vig_match"] or result["east_varbeau_match"]:
                    east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Method 12: Alternating characters from pairs of sources ────────
    print("\n[12] Interleaved pairs of sources")
    count_before = total_tested
    source_names = list(sources.keys())
    for i in range(len(source_names)):
        for j in range(i+1, len(source_names)):
            a = strip_alpha(sources[source_names[i]])
            b = strip_alpha(sources[source_names[j]])
            interleaved = ""
            for k in range(max(len(a), len(b))):
                if k < len(a):
                    interleaved += a[k]
                if k < len(b):
                    interleaved += b[k]
                if len(interleaved) >= CT_LEN + 50:
                    break
            if len(interleaved) >= CT_LEN:
                result = evaluate_extraction(interleaved, f"{source_names[i]}+{source_names[j]}", "interleaved", "")
                total_tested += 1
                if result:
                    all_results.append(result)
                    if result["crib_score"] > best_overall.get("crib_score", -1):
                        best_overall = result
                    if result["east_vig_match"] or result["east_varbeau_match"]:
                        east_matches.append(result)
    print(f"  Tested {total_tested - count_before} new ({total_tested} total)")

    # ── Summary ────────────────────────────────────────────────────────
    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print(f"FINAL SUMMARY — E-TEAM-BOOK-CIPHER")
    print(f"=" * 70)
    print(f"Total extractions tested: {total_tested}")
    print(f"Total results recorded:   {len(all_results)}")
    print(f"EAST constraint matches:  {len(east_matches)}")
    print(f"Elapsed time:             {elapsed:.1f}s")

    if best_overall.get("crib_score", -1) >= 0:
        print(f"\nBest score: {best_overall['crib_score']}/{N_CRIBS}")
        print(f"  Source:   {best_overall.get('source', '?')}")
        print(f"  Method:   {best_overall.get('method', '?')}")
        print(f"  Params:   {best_overall.get('params', '?')}")
        print(f"  Variant:  {best_overall.get('variant', '?')}")
        print(f"  Bean:     {best_overall.get('bean_passed', '?')}")
        print(f"  Key:      {best_overall.get('key_snippet', '?')}...")
        print(f"  PT:       {best_overall.get('pt_snippet', '?')}...")

    if east_matches:
        print(f"\nEAST constraint matches ({len(east_matches)}):")
        for em in east_matches[:10]:
            print(f"  {em['source']}/{em['method']}/{em['params']} "
                  f"score={em['crib_score']} bean={em['bean_passed']} "
                  f"vig={em['east_vig_match']} varbeau={em['east_varbeau_match']}")

    # Score distribution
    score_dist = {}
    for r in all_results:
        s = r["crib_score"]
        score_dist[s] = score_dist.get(s, 0) + 1
    print(f"\nScore distribution: {dict(sorted(score_dist.items()))}")

    # Determine verdict
    max_score = best_overall.get("crib_score", 0)
    if max_score >= 18:
        verdict = "SIGNAL"
    elif max_score >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")

    # ── Write results ──────────────────────────────────────────────────
    output = {
        "experiment": "E-TEAM-BOOK-CIPHER",
        "description": "Book cipher extraction from known texts using non-sequential methods",
        "total_tested": total_tested,
        "total_recorded": len(all_results),
        "east_matches_count": len(east_matches),
        "elapsed_seconds": round(elapsed, 1),
        "verdict": verdict,
        "best_result": best_overall if best_overall.get("crib_score", -1) >= 0 else None,
        "east_matches": east_matches[:20],
        "score_distribution": dict(sorted(score_dist.items())),
        "top_results": sorted(all_results, key=lambda x: x["crib_score"], reverse=True)[:50],
        "methods_tested": [
            "nth_word_first (N=1..20)",
            "nth_char (N=1..30)",
            "sentence_acrostics",
            "prime_positions",
            "fibonacci_positions",
            "diagonal (width=5..30)",
            "antidiagonal (width=5..30)",
            "paragraph_acrostics",
            "word_length_mod (mod=2..10)",
            "nth_word_last (N=1..20)",
            "running_key_offset (0..500)",
            "reversed",
            "interleaved_pairs",
        ],
        "sources_tested": list(sources.keys()),
    }

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
