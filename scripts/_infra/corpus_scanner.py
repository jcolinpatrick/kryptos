#!/usr/bin/env python3
"""
Cipher: running key
Family: _infra
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Gutenberg Corpus Running-Key Scanner for Kryptos K4.

Downloads 60+ texts from Project Gutenberg and tests every offset as a
running-key start position under Vigenere, Beaufort, and Variant Beaufort.

Usage:
    PYTHONPATH=src python3 -u scripts/corpus_scanner.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import List, Tuple, Dict, Optional

# ── Import canonical constants ───────────────────────────────────────────
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ, N_CRIBS,
)

# ── Configuration ────────────────────────────────────────────────────────
NUM_WORKERS = 14
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_ROOT / "results" / "corpus_scan"
CACHE_DIR = Path("/data/tmp/gutenberg_cache")
MIN_REPORT_SCORE = 18  # Report anything at SIGNAL level or above
BREAKTHROUGH = 24

# Pre-compute CT as numeric array (once, globally)
CT_NUM = tuple(ALPH_IDX[c] for c in CT)

# Pre-compute crib constraints: list of (position, expected_vigenere_key_value)
# For Vigenere: key[i] = (CT[i] - PT[i]) mod 26
# For Beaufort: key[i] = (CT[i] + PT[i]) mod 26
# For Variant Beaufort: key[i] = (PT[i] - CT[i]) mod 26
CRIB_POS_PT = []  # (position, pt_numeric)
for pos, ch in sorted(CRIB_DICT.items()):
    CRIB_POS_PT.append((pos, ALPH_IDX[ch]))

CRIB_VIG_KEYS = []   # (position, expected_key_value) for Vigenere
CRIB_BEAU_KEYS = []  # for Beaufort
CRIB_VBEAU_KEYS = [] # for Variant Beaufort

for pos, pt_num in CRIB_POS_PT:
    ct_num = CT_NUM[pos]
    CRIB_VIG_KEYS.append((pos, (ct_num - pt_num) % MOD))
    CRIB_BEAU_KEYS.append((pos, (ct_num + pt_num) % MOD))
    CRIB_VBEAU_KEYS.append((pos, (pt_num - ct_num) % MOD))

# Bean constraint positions
BEAN_EQ_POS = BEAN_EQ[0]  # (27, 65)
BEAN_INEQ_PAIRS = list(BEAN_INEQ)

# ── Gutenberg text list ──────────────────────────────────────────────────
# (gutenberg_id, title, thematic_relevance)
GUTENBERG_TEXTS = [
    # Bible & religious
    (10, "King James Bible", "religious"),
    (8001, "Bible - Douay-Rheims", "religious"),

    # Shakespeare
    (1524, "Hamlet", "shakespeare"),
    (1533, "Macbeth", "shakespeare"),
    (1513, "Romeo and Juliet", "shakespeare"),
    (1519, "The Merchant of Venice", "shakespeare"),
    (1521, "The Tempest", "shakespeare"),
    (1532, "King Lear", "shakespeare"),
    (1041, "Shakespeare Sonnets", "shakespeare"),
    (1531, "Julius Caesar", "shakespeare"),
    (1526, "Othello", "shakespeare"),

    # Edgar Allan Poe (cryptography connections)
    (2147, "The Gold-Bug and Other Tales (Poe)", "crypto_literary"),
    (1064, "The Masque of the Red Death (Poe)", "crypto_literary"),
    (2148, "The Fall of the House of Usher (Poe)", "literary"),
    (932, "The Fall of the House of Usher (alt) (Poe)", "literary"),
    (2149, "The Murders in the Rue Morgue (Poe)", "literary"),
    (10031, "Complete Works of Poe Vol 1", "crypto_literary"),

    # Conan Doyle (Dancing Men cipher story)
    (1661, "Adventures of Sherlock Holmes", "crypto_literary"),
    (2852, "The Hound of the Baskervilles", "crypto_literary"),
    (108, "The Return of Sherlock Holmes", "crypto_literary"),
    (2097, "The Sign of the Four", "literary"),
    (244, "A Study in Scarlet", "literary"),

    # Egypt / archaeology (Howard Carter, Tutankhamun)
    (13726, "The Tomb of Tutankhamen - Carter Vol 1", "egypt"),
    (17325, "The Tomb of Tutankhamen - Carter Vol 2", "egypt"),
    (14400, "The Book of the Dead", "egypt"),
    (4363, "Cleopatra by H Rider Haggard", "egypt"),

    # Cold War / espionage / intelligence
    (219, "Heart of Darkness (Conrad)", "literary"),
    (7370, "The Secret Agent (Conrad)", "intelligence"),
    (974, "The Secret Garden", "literary"),
    (35897, "The CIA and the Cult of Intelligence", "intelligence"),

    # Founding documents / American history
    (1, "Declaration of Independence", "american"),
    (5, "US Constitution", "american"),
    (18, "Bill of Rights", "american"),

    # Famous speeches
    # (These are short; we include them but expect less coverage)

    # Classic literature broadly
    (1342, "Pride and Prejudice", "classic"),
    (2701, "Moby Dick", "classic"),
    (84, "Frankenstein", "classic"),
    (1232, "The Prince (Machiavelli)", "classic"),
    (76, "Adventures of Tom Sawyer", "classic"),
    (2600, "War and Peace", "classic"),
    (5200, "Metamorphosis (Kafka)", "classic"),
    (1080, "A Modest Proposal (Swift)", "classic"),
    (46, "A Christmas Carol", "classic"),
    (345, "Dracula", "classic"),
    (1952, "The Yellow Wallpaper", "classic"),
    (1497, "Republic (Plato)", "classic"),
    (4300, "Ulysses (Joyce)", "classic"),
    (996, "Don Quixote", "classic"),
    (30254, "The Art of War (Sun Tzu)", "classic"),
    (16, "Peter Pan", "classic"),
    (11, "Alice in Wonderland", "classic"),
    (98, "A Tale of Two Cities", "classic"),
    (1260, "Jane Eyre", "classic"),
    (174, "Picture of Dorian Gray", "classic"),
    (161, "Sense and Sensibility", "classic"),
    (514, "Little Women", "classic"),
    (43, "The Strange Case of Dr Jekyll and Mr Hyde", "classic"),
    (768, "Wuthering Heights", "classic"),
    (1400, "Great Expectations", "classic"),
    (2591, "Grimms Fairy Tales", "classic"),
    (1184, "Count of Monte Cristo", "classic"),

    # Cryptography-related
    (29331, "Cryptography (Smith)", "crypto"),
    (18145, "Manual of Cryptography (Hitt)", "crypto"),

    # More Poe
    (17192, "Complete Poetical Works of Poe", "crypto_literary"),

    # More adventure / mystery
    (5230, "The Thirty-Nine Steps", "adventure"),
    (2500, "Siddhartha (Hesse)", "literary"),
    (164, "Twenty Thousand Leagues Under the Sea", "adventure"),
    (36, "The War of the Worlds", "classic"),
]

# ── Text download & caching ─────────────────────────────────────────────

def download_gutenberg(gid: int, title: str) -> Optional[str]:
    """Download a Gutenberg text, caching locally. Returns uppercase A-Z only."""
    cache_path = CACHE_DIR / f"pg{gid}.txt"

    if cache_path.exists():
        raw = cache_path.read_text(encoding="utf-8", errors="replace")
    else:
        urls = [
            f"https://www.gutenberg.org/cache/epub/{gid}/pg{gid}.txt",
            f"https://www.gutenberg.org/files/{gid}/{gid}-0.txt",
            f"https://www.gutenberg.org/files/{gid}/{gid}.txt",
        ]
        raw = None
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "KryptosResearch/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                break
            except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
                continue

        if raw is None:
            return None

        cache_path.write_text(raw, encoding="utf-8")

    # Strip to uppercase A-Z only
    cleaned = re.sub(r'[^A-Za-z]', '', raw).upper()
    return cleaned if len(cleaned) >= CT_LEN else None


def load_local_text(path: str) -> Optional[str]:
    """Load a local reference text, return uppercase A-Z only."""
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
        cleaned = re.sub(r'[^A-Za-z]', '', raw).upper()
        return cleaned if len(cleaned) >= CT_LEN else None
    except FileNotFoundError:
        return None


# ── Core scanning logic ─────────────────────────────────────────────────

def scan_text_worker(args: Tuple) -> Dict:
    """
    Scan a single text against K4 CT using all three cipher variants.
    Returns dict with best scores and any high-scoring hits.

    This runs in a worker process.
    """
    text_id, title, text_alpha = args
    text_len = len(text_alpha)
    n_offsets = text_len - CT_LEN + 1

    if n_offsets <= 0:
        return {
            "text_id": text_id, "title": title, "text_len": text_len,
            "offsets_tested": 0, "best_score": 0, "best_variant": "",
            "best_offset": -1, "hits": []
        }

    # Convert text to numeric array (fast lookup)
    # Use a bytearray for speed - each byte is 0-25
    text_num = bytearray(ALPH_IDX[c] for c in text_alpha)

    # Pre-build crib check arrays for each variant
    # Each is a list of (position, expected_key_value)
    crib_checks = {
        "vigenere": [(p, k) for p, k in CRIB_VIG_KEYS],
        "beaufort": [(p, k) for p, k in CRIB_BEAU_KEYS],
        "variant_beaufort": [(p, k) for p, k in CRIB_VBEAU_KEYS],
    }

    best_score = 0
    best_variant = ""
    best_offset = -1
    hits = []  # High-scoring hits

    ct = CT_NUM  # local ref for speed

    for variant_name, crib_expected in crib_checks.items():
        for offset in range(n_offsets):
            score = 0

            # For each crib position, compute key and check against expected
            for pos, expected_k in crib_expected:
                text_val = text_num[offset + pos]

                if variant_name == "vigenere":
                    k = (ct[pos] - text_val) % 26
                elif variant_name == "beaufort":
                    k = (ct[pos] + text_val) % 26
                else:  # variant_beaufort
                    k = (text_val - ct[pos]) % 26

                if k == expected_k:
                    score += 1

            if score > best_score:
                best_score = score
                best_variant = variant_name
                best_offset = offset

            if score >= MIN_REPORT_SCORE:
                # Check Bean constraint for high scorers
                bean_pass = False
                if score >= 20:
                    # Compute full key at Bean positions
                    def compute_key_at(p):
                        tv = text_num[offset + p]
                        if variant_name == "vigenere":
                            return (ct[p] - tv) % 26
                        elif variant_name == "beaufort":
                            return (ct[p] + tv) % 26
                        else:
                            return (tv - ct[p]) % 26

                    k27 = compute_key_at(BEAN_EQ_POS[0])
                    k65 = compute_key_at(BEAN_EQ_POS[1])
                    bean_eq_ok = (k27 == k65)

                    bean_ineq_ok = True
                    for a, b in BEAN_INEQ_PAIRS:
                        ka = compute_key_at(a)
                        kb = compute_key_at(b)
                        if ka == kb:
                            bean_ineq_ok = False
                            break

                    bean_pass = bean_eq_ok and bean_ineq_ok

                # Derive plaintext for context
                pt_chars = []
                for i in range(CT_LEN):
                    tv = text_num[offset + i]
                    if variant_name == "vigenere":
                        pt_val = (ct[i] - (ct[i] - tv) % 26) % 26  # = tv actually for running key vigenere: PT = (CT - K) mod 26 where K = running_key_char
                        # Wait - for running key Vigenere: CT = (PT + K) mod 26, so PT = (CT - K) mod 26
                        # Here K IS the running key text character
                        pt_val = (ct[i] - tv) % 26
                    elif variant_name == "beaufort":
                        # Beaufort: CT = (K - PT) mod 26, so PT = (K - CT) mod 26
                        pt_val = (tv - ct[i]) % 26
                    else:
                        # Variant Beaufort: CT = (PT - K) mod 26, so PT = (CT + K) mod 26
                        pt_val = (ct[i] + tv) % 26
                    pt_chars.append(chr(pt_val + 65))

                pt_str = "".join(pt_chars)

                # Get the running key text snippet
                key_snippet = text_alpha[offset:offset + CT_LEN]

                hit = {
                    "score": score,
                    "variant": variant_name,
                    "offset": offset,
                    "bean_pass": bean_pass if score >= 20 else None,
                    "plaintext": pt_str,
                    "key_snippet": key_snippet,
                }
                hits.append(hit)

                if score >= BREAKTHROUGH:
                    # EMERGENCY: Print immediately
                    print(f"\n!!! BREAKTHROUGH: {title} | {variant_name} | offset={offset} | score={score}/24 !!!")
                    print(f"    PT: {pt_str}")
                    print(f"    Key: {key_snippet}")
                    sys.stdout.flush()

    return {
        "text_id": text_id,
        "title": title,
        "text_len": text_len,
        "offsets_tested": n_offsets * 3,  # 3 variants
        "best_score": best_score,
        "best_variant": best_variant,
        "best_offset": best_offset,
        "hits": hits,
    }


def scan_text_worker_optimized(args: Tuple) -> Dict:
    """
    Optimized scanner - avoids recomputing key values per variant.
    Uses direct numeric comparison.
    """
    text_id, title, text_alpha = args
    text_len = len(text_alpha)
    n_offsets = text_len - CT_LEN + 1

    if n_offsets <= 0:
        return {
            "text_id": text_id, "title": title, "text_len": text_len,
            "offsets_tested": 0, "best_score": 0, "best_variant": "",
            "best_offset": -1, "hits": []
        }

    # Convert text to numeric list for fast indexing
    _idx = ALPH_IDX
    text_num = [_idx[c] for c in text_alpha]

    ct = CT_NUM

    # For each variant, pre-compute what the text character must be at each
    # crib position for a match.
    # Vigenere: key[i] = (CT[i] - PT[i]) mod 26. Running-key text IS the key.
    #   So match when text_num[offset+pos] == (CT[pos] - PT[pos]) mod 26
    # Beaufort: key[i] = (CT[i] + PT[i]) mod 26
    #   So match when text_num[offset+pos] == (CT[pos] + PT[pos]) mod 26
    # Variant Beaufort: key[i] = (PT[i] - CT[i]) mod 26
    #   So match when text_num[offset+pos] == (PT[pos] - CT[pos]) mod 26

    crib_positions = []
    vig_expected = []
    beau_expected = []
    vbeau_expected = []

    for pos, pt_ch in sorted(CRIB_DICT.items()):
        pt_num = _idx[pt_ch]
        crib_positions.append(pos)
        vig_expected.append((ct[pos] - pt_num) % 26)
        beau_expected.append((ct[pos] + pt_num) % 26)
        vbeau_expected.append((pt_num - ct[pos]) % 26)

    n_cribs = len(crib_positions)

    best_score = 0
    best_variant = ""
    best_offset = -1
    hits = []

    # Scan all offsets for each variant
    for variant_idx, (variant_name, expected) in enumerate([
        ("vigenere", vig_expected),
        ("beaufort", beau_expected),
        ("variant_beaufort", vbeau_expected),
    ]):
        for offset in range(n_offsets):
            score = 0
            for ci in range(n_cribs):
                if text_num[offset + crib_positions[ci]] == expected[ci]:
                    score += 1

            if score > best_score:
                best_score = score
                best_variant = variant_name
                best_offset = offset

            if score >= MIN_REPORT_SCORE:
                bean_pass = None
                if score >= 20:
                    # Compute key at Bean positions
                    def key_at(p):
                        tv = text_num[offset + p]
                        if variant_idx == 0:
                            return (ct[p] - tv) % 26  # running key IS the key for vig
                        elif variant_idx == 1:
                            return (ct[p] + tv) % 26
                        else:
                            return (tv - ct[p]) % 26

                    # Wait - re-think. For running key cipher:
                    # The "key" at position i is the text character at offset+i.
                    # But for Bean constraints, we need the KEYSTREAM value k[i].
                    # Vigenere: CT[i] = (PT[i] + K[i]) mod 26, so K[i] = (CT[i] - PT[i]) mod 26
                    # Here K[i] is derived from both PT and CT, not directly the running text.
                    # Actually in running-key Vigenere, the running text IS K[i].
                    # So K[i] = text_num[offset+i], and PT[i] = (CT[i] - K[i]) mod 26.
                    # The Bean constraint is on the derived keystream: k[i] = text_num[offset+i]
                    # For Vigenere running key.

                    # For Beaufort: CT[i] = (K[i] - PT[i]) mod 26
                    # K[i] = text_num[offset+i] (running text)
                    # Bean constraint checks k[i] values... but wait, the Bean constraints
                    # are formulated on keystream derived as K[i] = (CT[i] - PT[i]) mod 26
                    # regardless of variant. Let me re-derive.
                    #
                    # Bean says: the keystream value at pos 27 equals keystream at pos 65.
                    # Keystream = how CT maps to PT. For Vigenere: k[i] = (CT[i] - PT[i]) mod 26
                    # For Beaufort: k[i] = (CT[i] + PT[i]) mod 26 ... no wait.
                    #
                    # From constants.py, BEAN is variant-independent because
                    # CT[27]=CT[65]='P' and PT[27]=PT[65]='R' regardless of variant.
                    # So k[27]=k[65] always holds for crib positions.
                    #
                    # For non-crib positions, the keystream depends on the cipher model.
                    # In a running-key cipher, the keystream IS the running text.
                    # So for Vigenere: k[i] = text_num[offset+i]
                    # Bean eq: text_num[offset+27] == text_num[offset+65]
                    # Bean ineq: text_num[offset+a] != text_num[offset+b] for each (a,b)

                    # Actually this is wrong too. The Bean constraints are on the
                    # "key function" k[i] = f(CT[i], PT[i]). For running-key Vigenere,
                    # the running text char IS the key, so k[i] = text_num[offset+i].
                    # For Beaufort, CT[i] = (K[i] - PT[i]) mod 26, so
                    # K[i] = (CT[i] + PT[i]) mod 26 but K[i] IS also text_num[offset+i].
                    # The Bean constraint is formulated variant-independently in constants.py
                    # as just k[27]=k[65]. Since for running key, the text IS the key,
                    # we just check text_num[offset+27] == text_num[offset+65].

                    # But wait - that's only correct if Bean is about the running key
                    # character itself. Let me check: CLAUDE.md says Bean EQ is
                    # "variant-independent: CT[27]=CT[65]=P, PT[27]=PT[65]=R"
                    # This means for ANY cipher, k[27]=k[65] because the CT and PT
                    # values are the same at both positions. So the constraint is:
                    # whatever function maps (CT,PT)->key, it gives same value at 27 and 65.
                    # For running key: key IS the text char, so text[27+off] must equal text[65+off].

                    k27 = text_num[offset + 27]
                    k65 = text_num[offset + 65]
                    bean_eq_ok = (k27 == k65)

                    bean_ineq_ok = True
                    for a, b in BEAN_INEQ_PAIRS:
                        if text_num[offset + a] == text_num[offset + b]:
                            bean_ineq_ok = False
                            break

                    bean_pass = bean_eq_ok and bean_ineq_ok

                # Derive plaintext
                pt_chars = []
                for i in range(CT_LEN):
                    tv = text_num[offset + i]
                    if variant_idx == 0:  # Vigenere: PT = (CT - K) mod 26
                        pt_val = (ct[i] - tv) % 26
                    elif variant_idx == 1:  # Beaufort: PT = (K - CT) mod 26
                        pt_val = (tv - ct[i]) % 26
                    else:  # Variant Beaufort: PT = (CT + K) mod 26
                        pt_val = (ct[i] + tv) % 26
                    pt_chars.append(chr(pt_val + 65))
                pt_str = "".join(pt_chars)

                key_snippet = text_alpha[offset:offset + CT_LEN]

                hit = {
                    "score": score,
                    "variant": variant_name,
                    "offset": offset,
                    "bean_pass": bean_pass,
                    "plaintext": pt_str,
                    "key_snippet": key_snippet,
                }
                hits.append(hit)

                if score >= BREAKTHROUGH:
                    print(f"\n!!! BREAKTHROUGH: {title} | {variant_name} | offset={offset} | score={score}/24 !!!")
                    print(f"    PT: {pt_str}")
                    print(f"    Key: {key_snippet}")
                    sys.stdout.flush()

    return {
        "text_id": text_id,
        "title": title,
        "text_len": text_len,
        "offsets_tested": n_offsets * 3,
        "best_score": best_score,
        "best_variant": best_variant,
        "best_offset": best_offset,
        "hits": hits,
    }


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("KRYPTOS K4 — GUTENBERG CORPUS RUNNING-KEY SCANNER")
    print("=" * 80)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Crib positions: {sorted(CRIB_DICT.keys())}")
    print(f"Workers: {NUM_WORKERS}")
    print(f"Min report score: {MIN_REPORT_SCORE}/24")
    print()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Phase 1: Download all Gutenberg texts
    print("Phase 1: Downloading Gutenberg texts...")
    texts_to_scan = []  # (id_str, title, text_alpha)

    for gid, title, _theme in GUTENBERG_TEXTS:
        text = download_gutenberg(gid, title)
        if text:
            print(f"  [OK] PG{gid}: {title} ({len(text):,} chars)")
            texts_to_scan.append((f"PG{gid}", title, text))
        else:
            print(f"  [FAIL] PG{gid}: {title}")
        sys.stdout.flush()

    # Phase 2: Load local reference texts
    print("\nPhase 2: Loading local reference texts...")
    base = str(PROJECT_ROOT)
    local_texts = [
        (f"{base}/reference/carter_gutenberg.txt", "Carter Gutenberg (local)"),
        (f"{base}/reference/carter_vol1.txt", "Carter Vol 1 (local)"),
        (f"{base}/reference/carter_vol1_extract.txt", "Carter Vol 1 Extract (local)"),
        (f"{base}/reference/carter_text_cache.txt", "Carter Text Cache (local)"),
        (f"{base}/reference/running_key_texts/reagan_berlin.txt", "Reagan Berlin Wall Speech"),
        (f"{base}/reference/running_key_texts/jfk_berlin.txt", "JFK Ich bin ein Berliner"),
        (f"{base}/reference/running_key_texts/udhr.txt", "Universal Declaration of Human Rights"),
        (f"{base}/reference/running_key_texts/nsa_act_1947.txt", "National Security Act 1947"),
        (f"{base}/reference/running_key_texts/cia_charter.txt", "CIA Charter"),
    ]

    for path, title in local_texts:
        text = load_local_text(path)
        if text:
            print(f"  [OK] {title} ({len(text):,} chars)")
            texts_to_scan.append((f"LOCAL:{Path(path).stem}", title, text))
        else:
            print(f"  [SKIP] {title} (not found or too short)")
        sys.stdout.flush()

    print(f"\nTotal texts to scan: {len(texts_to_scan)}")
    total_offsets = sum((len(t[2]) - CT_LEN + 1) * 3 for t in texts_to_scan if len(t[2]) >= CT_LEN)
    print(f"Total offsets to test (x3 variants): {total_offsets:,}")
    print()

    # Phase 3: Parallel scanning
    print("Phase 3: Scanning (this may take a while)...")
    print("-" * 80)
    sys.stdout.flush()

    start_time = time.time()
    all_results = []
    all_hits = []

    with Pool(processes=NUM_WORKERS) as pool:
        for i, result in enumerate(pool.imap_unordered(scan_text_worker_optimized, texts_to_scan)):
            elapsed = time.time() - start_time
            all_results.append(result)

            status = f"  [{i+1}/{len(texts_to_scan)}] {result['title']}: "
            status += f"best={result['best_score']}/24 ({result['best_variant']}) "
            status += f"| {result['offsets_tested']:,} offsets | {elapsed:.1f}s"
            print(status)

            if result['hits']:
                all_hits.extend(result['hits'])
                for h in result['hits']:
                    marker = "***" if h['score'] >= 20 else "  >"
                    print(f"    {marker} score={h['score']}/24 variant={h['variant']} offset={h['offset']} bean={h.get('bean_pass')}")
                    if h['score'] >= 20:
                        print(f"        PT: {h['plaintext']}")

            sys.stdout.flush()

    total_time = time.time() - start_time

    # Phase 4: Summary
    print()
    print("=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)
    print(f"Total time: {total_time:.1f}s")
    print(f"Texts scanned: {len(all_results)}")
    print(f"Total offsets tested: {sum(r['offsets_tested'] for r in all_results):,}")

    # Sort results by best score
    all_results.sort(key=lambda r: r['best_score'], reverse=True)

    print(f"\nTop 20 texts by best score:")
    for r in all_results[:20]:
        print(f"  {r['best_score']:2d}/24 | {r['best_variant']:18s} | offset={r['best_offset']:>8d} | {r['title']}")

    # Sort all hits by score
    all_hits.sort(key=lambda h: h['score'], reverse=True)

    if all_hits:
        print(f"\nAll hits >= {MIN_REPORT_SCORE}/24: {len(all_hits)}")
        for h in all_hits[:50]:
            print(f"  {h['score']:2d}/24 | {h['variant']:18s} | bean={str(h.get('bean_pass')):>5s} | {h['plaintext'][:40]}...")
    else:
        print(f"\nNo hits >= {MIN_REPORT_SCORE}/24 found.")

    # Check for breakthroughs
    breakthroughs = [h for h in all_hits if h['score'] >= BREAKTHROUGH]
    if breakthroughs:
        print(f"\n{'!'*80}")
        print(f"BREAKTHROUGHS FOUND: {len(breakthroughs)}")
        print(f"{'!'*80}")
        for h in breakthroughs:
            print(f"  Score: {h['score']}/24")
            print(f"  Variant: {h['variant']}")
            print(f"  PT: {h['plaintext']}")
            print(f"  Key: {h['key_snippet']}")
            print()

    # Save results
    output = {
        "scan_time": total_time,
        "texts_scanned": len(all_results),
        "total_offsets": sum(r['offsets_tested'] for r in all_results),
        "min_report_score": MIN_REPORT_SCORE,
        "top_results": all_results[:20],
        "all_hits": all_hits[:200],  # Cap at 200 hits
        "breakthroughs": breakthroughs,
    }

    output_path = RESULTS_DIR / "corpus_scan_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {output_path}")

    # Also save a summary text file
    summary_path = RESULTS_DIR / "corpus_scan_summary.txt"
    with open(summary_path, "w") as f:
        f.write(f"Kryptos K4 Gutenberg Corpus Running-Key Scan\n")
        f.write(f"{'='*60}\n")
        f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Texts scanned: {len(all_results)}\n")
        f.write(f"Total offsets: {sum(r['offsets_tested'] for r in all_results):,}\n")
        f.write(f"Time: {total_time:.1f}s\n\n")
        f.write(f"Top results:\n")
        for r in all_results[:20]:
            f.write(f"  {r['best_score']:2d}/24 | {r['title']}\n")
        f.write(f"\nHits >= {MIN_REPORT_SCORE}:\n")
        for h in all_hits[:100]:
            f.write(f"  {h['score']:2d}/24 | {h['variant']} | PT: {h['plaintext']}\n")
        if breakthroughs:
            f.write(f"\nBREAKTHROUGHS:\n")
            for h in breakthroughs:
                f.write(f"  {h['score']}/24 | {h['variant']} | PT: {h['plaintext']}\n")
    print(f"Summary saved to: {summary_path}")


if __name__ == "__main__":
    main()
