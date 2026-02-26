#!/usr/bin/env python3
"""
Gutenberg Corpus Running-Key Scanner — Wave 2 (Expanded).

Downloads ~120 additional texts from Project Gutenberg, focusing on:
- More spy/intelligence/espionage fiction
- More archaeology/Egypt
- More Washington DC / American history
- Encyclopedias and reference works
- Philosophy, science, occult
- Additional classic literature
- Texts about codes, ciphers, secret writing

Usage:
    PYTHONPATH=src python3 -u scripts/corpus_scanner_wave2.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from multiprocessing import Pool
from pathlib import Path
from typing import List, Tuple, Dict, Optional

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ, N_CRIBS,
)

NUM_WORKERS = 14
RESULTS_DIR = Path("/home/cpatrick/kryptos/results/corpus_scan")
CACHE_DIR = Path("/data/tmp/gutenberg_cache")
MIN_REPORT_SCORE = 16  # Lower threshold for wave 2
BREAKTHROUGH = 24

CT_NUM = tuple(ALPH_IDX[c] for c in CT)

CRIB_POS_PT = sorted((pos, ALPH_IDX[ch]) for pos, ch in CRIB_DICT.items())
BEAN_EQ_POS = BEAN_EQ[0]
BEAN_INEQ_PAIRS = list(BEAN_INEQ)

# Pre-compute expected text values at crib positions for each variant
CRIB_POSITIONS = [p for p, _ in CRIB_POS_PT]
VIG_EXPECTED = [(CT_NUM[p] - pt) % 26 for p, pt in CRIB_POS_PT]
BEAU_EXPECTED = [(CT_NUM[p] + pt) % 26 for p, pt in CRIB_POS_PT]
VBEAU_EXPECTED = [(pt - CT_NUM[p]) % 26 for p, pt in CRIB_POS_PT]

# ── Expanded Gutenberg text list ─────────────────────────────────────────
GUTENBERG_TEXTS_WAVE2 = [
    # Spy / intelligence / espionage fiction
    (2852, "Hound of the Baskervilles", "spy"),  # already in wave1, will skip via cache
    (35688, "The Riddle of the Sands (Childers)", "spy"),
    (1539, "Measure for Measure (Shakespeare)", "shakespeare"),
    (1120, "The Scarlet Pimpernel", "spy"),
    (4099, "Greenmantle (Buchan)", "spy"),
    (2003, "Mr Standfast (Buchan)", "spy"),

    # More archaeology / Egypt / ancient world
    (14400, "Book of the Dead", "egypt"),  # cached
    (10897, "A History of Egypt (Breasted) Vol 1", "egypt"),
    (17866, "Egyptian Ideas of the Future Life (Budge)", "egypt"),
    (15892, "The Mummy (Loudon)", "egypt"),

    # Philosophy / occult / mysticism
    (1497, "Republic (Plato)", "philosophy"),  # cached
    (1656, "Apology (Plato)", "philosophy"),
    (1580, "Symposium (Plato)", "philosophy"),
    (10616, "Meditations (Marcus Aurelius)", "philosophy"),
    (55201, "The Kybalion", "occult"),
    (14209, "The Secret Doctrine Vol 1 (Blavatsky)", "occult"),
    (3760, "The Problems of Philosophy (Russell)", "philosophy"),
    (815, "Democracy in America Vol 1", "american"),
    (816, "Democracy in America Vol 2", "american"),

    # Cryptography / mathematics / codes
    (852, "The Decameron (Boccaccio)", "literary"),
    (27518, "Military Cryptanalysis Part 1 (Friedman)", "crypto"),
    (39948, "On the Writing of the Insane", "literary"),
    (28520, "The Cipher of Roger Bacon", "crypto"),
    (29321, "Secret Writing", "crypto"),

    # American history / founding / DC
    (16960, "The Federalist Papers", "american"),
    (3, "John F Kennedy Inaugural Address", "american"),
    (815, "Democracy in America Vol 1 (Tocqueville)", "american"),
    (1, "Declaration of Independence", "american"),  # cached
    (5, "US Constitution", "american"),  # cached
    (3, "JFK Inaugural Address", "american"),
    (4657, "Lincoln Speeches and Addresses", "american"),
    (4362, "Lincoln Gettysburg Address", "american"),
    (51, "Autobiography of Benjamin Franklin", "american"),

    # More classic/famous literature
    (2554, "Crime and Punishment", "classic"),
    (600, "Notes from Underground (Dostoevsky)", "classic"),
    (28054, "The Brothers Karamazov", "classic"),
    (805, "This Side of Paradise (Fitzgerald)", "classic"),
    (64317, "The Great Gatsby", "classic"),
    (55, "The Wonderful Wizard of Oz", "classic"),
    (120, "Treasure Island", "classic"),
    (244, "A Study in Scarlet", "classic"),  # cached
    (74, "Adventures of Tom Sawyer", "classic"),
    (730, "Oliver Twist", "classic"),
    (1023, "Bleak House", "classic"),
    (1399, "Anna Karenina", "classic"),
    (7178, "The Invisible Man", "classic"),
    (35, "The Time Machine", "classic"),
    (209, "The Turn of the Screw", "classic"),
    (215, "The Call of the Wild", "classic"),
    (205, "Walden", "classic"),
    (62, "A Princess of Mars", "classic"),
    (2148, "Fall of House of Usher", "classic"),  # cached
    (236, "The Jungle Book", "classic"),
    (110, "Tess of the D'Urbervilles", "classic"),
    (526, "Heart of a Dog", "classic"),

    # More Shakespeare
    (1515, "A Midsummer Night's Dream", "shakespeare"),
    (1534, "Twelfth Night", "shakespeare"),
    (1522, "The Winter's Tale", "shakespeare"),
    (1523, "Much Ado About Nothing", "shakespeare"),
    (1528, "As You Like It", "shakespeare"),
    (1120, "Richard III", "shakespeare"),
    (1500, "All's Well That Ends Well", "shakespeare"),
    (1793, "Complete Works of Shakespeare", "shakespeare"),

    # Science / technology
    (28233, "The Origin of Species (Darwin)", "science"),
    (4217, "A Brief History of Time Concept", "science"),  # may not exist
    (14725, "The Interpretation of Dreams (Freud)", "science"),
    (36, "War of the Worlds", "science"),  # cached

    # Cold War / Berlin
    (62838, "Berlin Stories (Isherwood)", "berlin"),  # may not exist
    (8164, "Armageddon 2419 AD", "scifi"),
    (27573, "The Man in the Iron Mask", "classic"),

    # Religious / mystical texts
    (10, "King James Bible", "religious"),  # cached
    (2680, "Meditations (Descartes)", "philosophy"),
    (7849, "The Analects of Confucius", "religious"),
    (2500, "Siddhartha", "religious"),  # cached
    (7999, "Bhagavad Gita", "religious"),
    (2944, "Tao Te Ching", "religious"),
    (2346, "The Imitation of Christ", "religious"),

    # More Poe (complete works)
    (10031, "Complete Works of Poe Vol 1", "poe"),  # cached
    (10032, "Complete Works of Poe Vol 2", "poe"),
    (10033, "Complete Works of Poe Vol 3", "poe"),
    (10034, "Complete Works of Poe Vol 4", "poe"),
    (10035, "Complete Works of Poe Vol 5", "poe"),

    # Adventure / exploration
    (2083, "The Travels of Marco Polo", "adventure"),
    (3207, "Leviathan (Hobbes)", "philosophy"),
    (996, "Don Quixote", "adventure"),  # cached
    (4705, "A Journey to the Centre of the Earth", "adventure"),
    (103, "Around the World in 80 Days", "adventure"),

    # Espionage non-fiction / intelligence
    (10007, "Kama Sutra", "classic"),
    (132, "The Art of War", "strategy"),
    (1946, "On Liberty (Mill)", "philosophy"),

    # H.P. Lovecraft
    (68283, "The Call of Cthulhu", "horror"),
    (70912, "At the Mountains of Madness", "horror"),
    (73233, "The Shadow over Innsmouth", "horror"),
    (68236, "The Dunwich Horror", "horror"),

    # More Conan Doyle
    (2343, "The Valley of Fear", "detective"),
    (3289, "The Lost World", "detective"),
    (834, "The Adventures of Sherlock Holmes (alt)", "detective"),

    # Reference / encyclopedia
    (4283, "The Elements of Style", "reference"),
    (5827, "The Problems of Philosophy", "reference"),

    # Specific texts mentioned in Kryptos community research
    (159, "The Same Old Story (Chekhov)", "literary"),
    (480, "The Rime of the Ancient Mariner", "literary"),
    (4085, "The Interesting Narrative of Olaudah Equiano", "literary"),
    (408, "The Souls of Black Folk (Du Bois)", "american"),
    (8800, "The Divine Comedy (Dante)", "literary"),
    (2000, "The Virginian (Wister)", "american"),
]

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
    cleaned = re.sub(r'[^A-Za-z]', '', raw).upper()
    return cleaned if len(cleaned) >= CT_LEN else None


def scan_text_worker(args: Tuple) -> Dict:
    """Scan a single text against K4 CT using all three cipher variants."""
    text_id, title, text_alpha = args
    text_len = len(text_alpha)
    n_offsets = text_len - CT_LEN + 1

    if n_offsets <= 0:
        return {
            "text_id": text_id, "title": title, "text_len": text_len,
            "offsets_tested": 0, "best_score": 0, "best_variant": "",
            "best_offset": -1, "hits": []
        }

    _idx = ALPH_IDX
    text_num = [_idx[c] for c in text_alpha]
    ct = CT_NUM

    crib_positions = CRIB_POSITIONS
    n_cribs = len(crib_positions)

    best_score = 0
    best_variant = ""
    best_offset = -1
    hits = []

    for variant_name, expected in [
        ("vigenere", VIG_EXPECTED),
        ("beaufort", BEAU_EXPECTED),
        ("variant_beaufort", VBEAU_EXPECTED),
    ]:
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
                vi = variant_name
                for i in range(CT_LEN):
                    tv = text_num[offset + i]
                    if vi == "vigenere":
                        pt_val = (ct[i] - tv) % 26
                    elif vi == "beaufort":
                        pt_val = (tv - ct[i]) % 26
                    else:
                        pt_val = (ct[i] + tv) % 26
                    pt_chars.append(chr(pt_val + 65))
                pt_str = "".join(pt_chars)
                key_snippet = text_alpha[offset:offset + CT_LEN]

                hit = {
                    "text_id": text_id, "title": title,
                    "score": score, "variant": variant_name,
                    "offset": offset, "bean_pass": bean_pass,
                    "plaintext": pt_str, "key_snippet": key_snippet,
                }
                hits.append(hit)

                if score >= BREAKTHROUGH:
                    print(f"\n!!! BREAKTHROUGH: {title} | {variant_name} | offset={offset} | score={score}/24 !!!")
                    print(f"    PT: {pt_str}")
                    sys.stdout.flush()

    return {
        "text_id": text_id, "title": title, "text_len": text_len,
        "offsets_tested": n_offsets * 3,
        "best_score": best_score, "best_variant": best_variant,
        "best_offset": best_offset, "hits": hits,
    }


def main():
    print("=" * 80)
    print("KRYPTOS K4 — GUTENBERG CORPUS RUNNING-KEY SCANNER (WAVE 2)")
    print("=" * 80)
    print(f"CT: {CT}")
    print(f"Workers: {NUM_WORKERS}, Min report: {MIN_REPORT_SCORE}/24")
    print()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # De-duplicate by Gutenberg ID
    seen_ids = set()
    unique_texts = []
    for gid, title, theme in GUTENBERG_TEXTS_WAVE2:
        if gid not in seen_ids:
            seen_ids.add(gid)
            unique_texts.append((gid, title, theme))

    print(f"Downloading {len(unique_texts)} unique texts...")
    texts_to_scan = []

    for gid, title, _theme in unique_texts:
        text = download_gutenberg(gid, title)
        if text:
            print(f"  [OK] PG{gid}: {title} ({len(text):,} chars)")
            texts_to_scan.append((f"PG{gid}", title, text))
        else:
            print(f"  [FAIL] PG{gid}: {title}")
        sys.stdout.flush()

    print(f"\nTotal texts: {len(texts_to_scan)}")
    total_offsets = sum((len(t[2]) - CT_LEN + 1) * 3 for t in texts_to_scan)
    print(f"Total offsets (x3 variants): {total_offsets:,}")
    print()

    print("Scanning...")
    print("-" * 80)
    sys.stdout.flush()

    start_time = time.time()
    all_results = []
    all_hits = []

    with Pool(processes=NUM_WORKERS) as pool:
        for i, result in enumerate(pool.imap_unordered(scan_text_worker, texts_to_scan)):
            elapsed = time.time() - start_time
            all_results.append(result)
            print(f"  [{i+1}/{len(texts_to_scan)}] {result['title']}: best={result['best_score']}/24 ({result['best_variant']}) | {result['offsets_tested']:,} offsets | {elapsed:.1f}s")
            if result['hits']:
                all_hits.extend(result['hits'])
                for h in result['hits']:
                    marker = "***" if h['score'] >= 20 else ">>>" if h['score'] >= 18 else "  >"
                    print(f"    {marker} score={h['score']}/24 variant={h['variant']} offset={h['offset']}")
                    if h['score'] >= 18:
                        print(f"        PT: {h['plaintext']}")
            sys.stdout.flush()

    total_time = time.time() - start_time

    print()
    print("=" * 80)
    print(f"WAVE 2 SCAN COMPLETE — {total_time:.1f}s")
    print("=" * 80)
    print(f"Texts: {len(all_results)}, Offsets: {sum(r['offsets_tested'] for r in all_results):,}")

    all_results.sort(key=lambda r: r['best_score'], reverse=True)
    print(f"\nTop 20:")
    for r in all_results[:20]:
        print(f"  {r['best_score']:2d}/24 | {r['best_variant']:18s} | {r['title']}")

    all_hits.sort(key=lambda h: h['score'], reverse=True)
    if all_hits:
        print(f"\nAll hits >= {MIN_REPORT_SCORE}/24: {len(all_hits)}")
        for h in all_hits[:30]:
            print(f"  {h['score']:2d}/24 | {h['variant']:18s} | {h['title']} | PT: {h['plaintext'][:40]}...")
    else:
        print(f"\nNo hits >= {MIN_REPORT_SCORE}/24.")

    breakthroughs = [h for h in all_hits if h['score'] >= BREAKTHROUGH]
    if breakthroughs:
        print(f"\n{'!'*80}")
        print(f"BREAKTHROUGHS: {len(breakthroughs)}")
        for h in breakthroughs:
            print(f"  {h['score']}/24 | {h['variant']} | {h['title']} | PT: {h['plaintext']}")

    output = {
        "scan_time": total_time,
        "texts_scanned": len(all_results),
        "total_offsets": sum(r['offsets_tested'] for r in all_results),
        "top_results": [
            {k: v for k, v in r.items() if k != 'hits'}
            for r in all_results[:30]
        ],
        "all_hits": all_hits[:200],
        "breakthroughs": breakthroughs,
    }

    output_path = RESULTS_DIR / "corpus_scan_wave2_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()
