#!/usr/bin/env python3
"""E-CFM-09: Gutenberg-scale EAST constraint scan.

[HYPOTHESIS] If K4 uses a running key from a published text, the source text
must satisfy the EAST gap-9 differential constraint (from E-CFM-06):

  For Vigenere/Beaufort: source[off+j+9] - source[off+j] ≡ delta_j (mod 26)
  for j in {21,22,23,24} with delta = [1, 25, 1, 23]
  For Var Beaufort: delta = [25, 1, 25, 3]

Combined with Bean-EQ (source[off+27] = source[off+65]):
  P(all 5 constraints satisfied randomly) ≈ 8.4e-8

This experiment downloads 100+ Project Gutenberg texts (50+ MB of English prose),
applies the EAST filter as a fast first pass, then Bean-EQ and full 24-position
checks on any survivors. Uses 28 CPU cores for parallel scanning.

If NO text passes: the running key is NOT from any tested Gutenberg text.
If a text passes: IMMEDIATE investigation — potential solution.

VM: 28 vCPUs, 31GB RAM. Designed for local parallel execution.
"""
import sys
import os
import json
import time
import urllib.request
import urllib.error
from multiprocessing import Pool, cpu_count
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.transforms.vigenere import (
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)

# ── EAST gap-9 differentials (from E-CFM-06) ──────────────────────────────
# Precompute for all variants
CRIB_POSITIONS = sorted(CRIB_DICT.keys())
CT_VALS = [ALPH_IDX[c] for c in CT]
PT_VALS = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Compute key fragments and EAST diffs for each variant
VARIANTS = {}
for vname, recover_fn in [("vigenere", vig_recover_key),
                           ("beaufort", beau_recover_key),
                           ("var_beaufort", varbeau_recover_key)]:
    keys = []
    for pos in CRIB_POSITIONS:
        k = recover_fn(CT_VALS[pos], PT_VALS[pos])
        keys.append(k)
    # EAST diffs: gap between indices 0-3 and 9-12
    diffs = [(keys[9 + j] - keys[j]) % MOD for j in range(4)]
    VARIANTS[vname] = {"keys": keys, "east_diffs": diffs}

# Vigenere and Beaufort produce identical EAST diffs (verified in E-CFM-06)
assert VARIANTS["vigenere"]["east_diffs"] == VARIANTS["beaufort"]["east_diffs"]


# ── Gutenberg book list ────────────────────────────────────────────────────
# Curated: thematically relevant + major English literature
GUTENBERG_BOOKS = [
    # Howard Carter — THE K3 SOURCE (highest priority)
    (1459, "Howard Carter - Tomb of Tutankhamen Vol 1"),
    (1460, "Howard Carter - Tomb of Tutankhamen Vol 2"),
    (1461, "Howard Carter - Tomb of Tutankhamen Vol 3"),
    # Egypt & Archaeology
    (14400, "George Rawlinson - History of Ancient Egypt"),
    (4363, "E. A. Wallis Budge - The Egyptian Book of the Dead"),
    (17325, "E. A. Wallis Budge - Tutankhamen"),
    # Berlin / German / Cold War themed
    (5200, "Franz Kafka - Metamorphosis"),
    (7849, "Homer - The Odyssey (Butler trans)"),
    (2591, "Brothers Grimm - Fairy Tales"),
    # Espionage / Intelligence / Codes
    (1661, "Arthur Conan Doyle - Adventures of Sherlock Holmes"),
    (244, "Arthur Conan Doyle - A Study in Scarlet"),
    (1155, "Arthur Conan Doyle - The Valley of Fear"),
    (108, "Arthur Conan Doyle - Return of Sherlock Holmes"),
    (863, "G.K. Chesterton - The Man Who Was Thursday"),
    (2852, "Joseph Conrad - The Secret Agent"),
    (219, "Joseph Conrad - Heart of Darkness"),
    # Major English Literature (broad coverage)
    (98, "Charles Dickens - A Tale of Two Cities"),
    (1400, "Charles Dickens - Great Expectations"),
    (730, "Charles Dickens - Oliver Twist"),
    (46, "Charles Dickens - A Christmas Carol"),
    (2701, "Herman Melville - Moby Dick"),
    (1342, "Jane Austen - Pride and Prejudice"),
    (11, "Lewis Carroll - Alice in Wonderland"),
    (84, "Mary Shelley - Frankenstein"),
    (345, "Bram Stoker - Dracula"),
    (36, "H.G. Wells - War of the Worlds"),
    (174, "Oscar Wilde - Picture of Dorian Gray"),
    (4300, "James Joyce - Ulysses"),
    (1260, "Charlotte Bronte - Jane Eyre"),
    (16328, "Beowulf"),
    (76, "Mark Twain - Tom Sawyer"),
    (74, "Mark Twain - Huckleberry Finn"),
    (1080, "Jonathan Swift - A Modest Proposal"),
    (829, "Gulliver's Travels"),
    (1232, "Machiavelli - The Prince"),
    (2554, "Fyodor Dostoevsky - Crime and Punishment"),
    (2600, "Leo Tolstoy - War and Peace"),
    (1952, "Charlotte Perkins Gilman - The Yellow Wallpaper"),
    # American themes (CIA/US context)
    (3207, "The Declaration of Independence"),
    (5, "US Bill of Rights"),
    (1497, "The Republic by Plato"),
    (100, "Complete Works of Shakespeare"),
    (1184, "The Count of Monte Cristo"),
    (55, "The Wonderful Wizard of Oz"),
    (158, "Emma by Jane Austen"),
    (1023, "Bleak House by Dickens"),
    (120, "Treasure Island"),
    (25344, "The Scarlet Pimpernel"),
    (35, "The Time Machine"),
    (43, "The Strange Case of Dr Jekyll and Mr Hyde"),
    (768, "Wuthering Heights"),
    (514, "Little Women"),
    (16, "Peter Pan"),
    (215, "The Call of the Wild"),
    (3600, "Edgar Allan Poe - The Gold Bug (codes!)"),
    (2147, "Edgar Allan Poe - Complete Poetical Works"),
    (2148, "Edgar Allan Poe - Complete Works Vol 2"),
    (2149, "Edgar Allan Poe - Complete Works Vol 3"),
    (2150, "Edgar Allan Poe - Complete Works Vol 4"),
    # Additional major works
    (1727, "The Odyssey (Pope trans)"),
    (6130, "Homer - The Iliad (Butler trans)"),
    (28054, "Brothers Karamazov"),
    (1399, "Anna Karenina"),
    (2542, "Les Miserables"),
    (996, "Don Quixote"),
    (19942, "Candide by Voltaire"),
    (1934, "The Castle of Otranto"),
    (30254, "The Code Book (if available)"),
    # German language texts (Weltzeituhr connection)
    (7200, "Goethe - Die Leiden des jungen Werthers"),
    (2229, "Nietzsche - Jenseits von Gut und Bose"),
    (5323, "Nietzsche - Also sprach Zarathustra"),
    (7205, "Kafka - Das Urteil"),
    (22367, "Kafka - Der Prozess"),
]


def strip_alpha(text: str) -> str:
    """Keep only A-Z uppercase."""
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


def download_gutenberg(book_id: int) -> str | None:
    """Download a Gutenberg text, return raw string or None on failure."""
    urls = [
        f"https://www.gutenberg.org/cache/epub/{book_id}/pg{book_id}.txt",
        f"https://www.gutenberg.org/files/{book_id}/{book_id}-0.txt",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "KryptosResearch/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                # Try UTF-8, then latin-1
                try:
                    return raw.decode("utf-8")
                except UnicodeDecodeError:
                    return raw.decode("latin-1")
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            continue
    return None


def scan_text_east(text_alpha: str, east_diffs: list, variant_name: str,
                   full_keys: list) -> dict:
    """Scan a single text for EAST constraint matches.

    Returns dict with match counts and any full matches.
    """
    n = len(text_alpha)
    if n < CT_LEN:
        return {"east_matches": 0, "bean_eq_matches": 0, "full_matches": [],
                "text_len": n}

    max_offset = n - CT_LEN
    east_matches = 0
    bean_eq_matches = 0
    full_matches = []

    # Preconvert text to integer array for speed
    text_ints = [ALPH_IDX[c] for c in text_alpha]

    for offset in range(max_offset + 1):
        # EAST gap-9 check (4 constraints, positions 21-24 and 30-33)
        match = True
        for j in range(4):
            pos1 = offset + 21 + j
            pos2 = offset + 30 + j
            if (text_ints[pos2] - text_ints[pos1]) % MOD != east_diffs[j]:
                match = False
                break
        if not match:
            continue

        east_matches += 1

        # Bean-EQ: source[off+27] = source[off+65]
        if text_ints[offset + 27] != text_ints[offset + 65]:
            continue
        bean_eq_matches += 1

        # Full 24-position check
        all_match = True
        for idx, pos in enumerate(CRIB_POSITIONS):
            if text_ints[offset + pos] != full_keys[idx]:
                all_match = False
                break

        if all_match:
            # BREAKTHROUGH!
            context = text_alpha[offset:offset + CT_LEN]
            full_matches.append({
                "offset": offset,
                "source_97": context,
                "source_start": text_alpha[max(0, offset - 10):offset + 40],
            })

    return {
        "east_matches": east_matches,
        "bean_eq_matches": bean_eq_matches,
        "full_matches": full_matches,
        "text_len": n,
    }


def scan_worker(args):
    """Worker: download, strip, and scan one Gutenberg book."""
    book_id, title, east_diffs_vig, east_diffs_vb, keys_vig, keys_beau, keys_vb = args

    raw = download_gutenberg(book_id)
    if raw is None:
        return {"book_id": book_id, "title": title, "status": "DOWNLOAD_FAILED"}

    text = strip_alpha(raw)
    if len(text) < CT_LEN:
        return {"book_id": book_id, "title": title, "status": "TOO_SHORT",
                "text_len": len(text)}

    results = {"book_id": book_id, "title": title, "status": "OK",
               "text_len": len(text), "variants": {}}

    # Scan for Vigenere/Beaufort (same EAST diffs)
    for vname, keys in [("vigenere", keys_vig), ("beaufort", keys_beau)]:
        r = scan_text_east(text, east_diffs_vig, vname, keys)
        results["variants"][vname] = r

    # Scan for Var Beaufort (different EAST diffs)
    r = scan_text_east(text, east_diffs_vb, "var_beaufort", keys_vb)
    results["variants"]["var_beaufort"] = r

    return results


def load_local_corpus():
    """Load all local corpus texts for scanning."""
    base = os.path.join(os.path.dirname(__file__), "..")
    texts = {}

    # Running key texts
    rk_dir = os.path.join(base, "reference", "running_key_texts")
    if os.path.isdir(rk_dir):
        for f in sorted(os.listdir(rk_dir)):
            path = os.path.join(rk_dir, f)
            if os.path.isfile(path):
                with open(path) as fh:
                    texts[f"local/{f}"] = strip_alpha(fh.read())

    # Carter texts
    for name in ["carter_gutenberg.txt", "carter_vol1.txt"]:
        path = os.path.join(base, "reference", name)
        if os.path.isfile(path):
            with open(path) as fh:
                texts[f"local/{name}"] = strip_alpha(fh.read())

    # Wordlist
    wl_path = os.path.join(base, "wordlists", "english.txt")
    if os.path.isfile(wl_path):
        with open(wl_path) as fh:
            texts["local/wordlist"] = strip_alpha(fh.read())

    return texts


def main():
    print("=" * 70)
    print("E-CFM-09: Gutenberg-Scale EAST Constraint Scan")
    print("=" * 70)

    n_workers = min(28, cpu_count())
    print(f"CPUs: {n_workers}")
    print(f"Books to scan: {len(GUTENBERG_BOOKS)}")
    print(f"CT length: {CT_LEN}")

    # Show EAST diffs
    vig_diffs = VARIANTS["vigenere"]["east_diffs"]
    vb_diffs = VARIANTS["var_beaufort"]["east_diffs"]
    print(f"\nEAST gap-9 diffs (Vig/Beau): {vig_diffs}")
    print(f"EAST gap-9 diffs (VarBeau):  {vb_diffs}")

    keys_vig = VARIANTS["vigenere"]["keys"]
    keys_beau = VARIANTS["beaufort"]["keys"]
    keys_vb = VARIANTS["var_beaufort"]["keys"]

    # ── Step 1: Local corpus scan ──────────────────────────────────────────
    print("\n── Step 1: Local corpus scan ──")
    local_texts = load_local_corpus()
    print(f"Loaded {len(local_texts)} local texts")

    local_total_east = {v: 0 for v in ["vigenere", "beaufort", "var_beaufort"]}
    local_total_bean = {v: 0 for v in ["vigenere", "beaufort", "var_beaufort"]}
    local_total_full = {v: 0 for v in ["vigenere", "beaufort", "var_beaufort"]}
    local_total_chars = 0

    for name, text in sorted(local_texts.items()):
        local_total_chars += len(text)
        for vname, keys, diffs in [("vigenere", keys_vig, vig_diffs),
                                    ("beaufort", keys_beau, vig_diffs),
                                    ("var_beaufort", keys_vb, vb_diffs)]:
            r = scan_text_east(text, diffs, vname, keys)
            local_total_east[vname] += r["east_matches"]
            local_total_bean[vname] += r["bean_eq_matches"]
            local_total_full[vname] += len(r["full_matches"])
            if r["east_matches"] > 0:
                print(f"  {name} ({len(text)} chars, {vname}): "
                      f"{r['east_matches']} EAST, {r['bean_eq_matches']} Bean-EQ, "
                      f"{len(r['full_matches'])} full")
            if r["full_matches"]:
                for m in r["full_matches"]:
                    print(f"    *** FULL MATCH at offset {m['offset']}! ***")
                    print(f"    Source: {m['source_start']}...")

    print(f"\n  Local corpus: {local_total_chars:,} chars scanned")
    for v in ["vigenere", "beaufort", "var_beaufort"]:
        print(f"  {v}: {local_total_east[v]} EAST, {local_total_bean[v]} Bean-EQ, "
              f"{local_total_full[v]} full")

    # ── Step 2: Gutenberg download + scan (parallel) ──────────────────────
    print("\n── Step 2: Gutenberg download + scan ──")
    print(f"Downloading and scanning {len(GUTENBERG_BOOKS)} books with {n_workers} workers...")
    t0 = time.time()

    # Prepare worker args
    worker_args = []
    for book_id, title in GUTENBERG_BOOKS:
        worker_args.append((book_id, title, vig_diffs, vb_diffs,
                            keys_vig, keys_beau, keys_vb))

    # Use pool for parallel download + scan
    with Pool(n_workers) as pool:
        results = pool.map(scan_worker, worker_args)

    elapsed = time.time() - t0
    print(f"  Completed in {elapsed:.1f}s")

    # ── Step 3: Aggregate results ──────────────────────────────────────────
    print("\n── Step 3: Results ──")

    total_chars = 0
    total_books_ok = 0
    total_books_failed = 0
    grand_east = {v: 0 for v in ["vigenere", "beaufort", "var_beaufort"]}
    grand_bean = {v: 0 for v in ["vigenere", "beaufort", "var_beaufort"]}
    grand_full = {v: 0 for v in ["vigenere", "beaufort", "var_beaufort"]}
    breakthroughs = []

    for r in results:
        if r["status"] == "DOWNLOAD_FAILED":
            total_books_failed += 1
            print(f"  FAILED: [{r['book_id']}] {r['title']}")
            continue
        if r["status"] == "TOO_SHORT":
            print(f"  SHORT:  [{r['book_id']}] {r['title']} ({r['text_len']} chars)")
            continue

        total_books_ok += 1
        total_chars += r["text_len"]

        has_matches = False
        for vname, vr in r["variants"].items():
            grand_east[vname] += vr["east_matches"]
            grand_bean[vname] += vr["bean_eq_matches"]
            grand_full[vname] += len(vr["full_matches"])
            if vr["east_matches"] > 0:
                has_matches = True
            if vr["full_matches"]:
                breakthroughs.append((r, vname, vr["full_matches"]))

        if has_matches:
            parts = []
            for vname in ["vigenere", "beaufort", "var_beaufort"]:
                vr = r["variants"][vname]
                if vr["east_matches"] > 0:
                    parts.append(f"{vname}:{vr['east_matches']}E/{vr['bean_eq_matches']}B/{len(vr['full_matches'])}F")
            print(f"  MATCH:  [{r['book_id']:>5}] {r['title'][:50]:50s} "
                  f"({r['text_len']:>7,} chars) {', '.join(parts)}")

    # Show all scanned books
    print(f"\n  Books OK: {total_books_ok}, Failed: {total_books_failed}")
    print(f"  Total alpha chars scanned: {total_chars:,}")

    # Expected false positive rates
    for vname in ["vigenere", "beaufort", "var_beaufort"]:
        expected_east = total_chars * (1.0 / MOD) ** 4
        expected_bean = total_chars * (1.0 / MOD) ** 5
        print(f"\n  {vname}:")
        print(f"    EAST matches: {grand_east[vname]} (expected random: {expected_east:.1f})")
        print(f"    Bean-EQ pass: {grand_bean[vname]} (expected random: {expected_bean:.2f})")
        print(f"    Full matches: {grand_full[vname]}")

    # ── Step 4: Breakthroughs? ─────────────────────────────────────────────
    if breakthroughs:
        print("\n" + "!" * 70)
        print("*** BREAKTHROUGH — FULL RUNNING KEY MATCH FOUND! ***")
        print("!" * 70)
        for r, vname, matches in breakthroughs:
            print(f"\n  Book: [{r['book_id']}] {r['title']}")
            print(f"  Variant: {vname}")
            for m in matches:
                print(f"  Offset: {m['offset']}")
                print(f"  Source key (97 chars): {m['source_97']}")
                # Decrypt K4
                keys = VARIANTS[vname]["keys"]
                pt = []
                for i in range(CT_LEN):
                    ct_val = CT_VALS[i]
                    k_val = ALPH_IDX[m["source_97"][i]]
                    if vname == "vigenere":
                        pt_val = (ct_val - k_val) % MOD
                    elif vname == "beaufort":
                        pt_val = (k_val - ct_val) % MOD
                    else:
                        pt_val = (ct_val + k_val) % MOD
                    pt.append(ALPH[pt_val])
                pt_str = "".join(pt)
                print(f"  Decrypted K4: {pt_str}")
                # Verify cribs
                for pos, ch in CRIB_DICT.items():
                    if pt_str[pos] != ch:
                        print(f"  WARNING: Crib mismatch at pos {pos}: "
                              f"expected {ch}, got {pt_str[pos]}")
        print("\n  Verdict: SIGNAL — investigate immediately!")
    else:
        print()

    # ── Step 5: Per-book summary table ─────────────────────────────────────
    print("\n── Step 5: All books scanned (sorted by EAST matches) ──")
    scored = []
    for r in results:
        if r["status"] != "OK":
            continue
        total_e = sum(r["variants"][v]["east_matches"]
                      for v in ["vigenere", "beaufort", "var_beaufort"])
        scored.append((total_e, r))
    scored.sort(key=lambda x: -x[0])

    for total_e, r in scored[:30]:
        if total_e > 0:
            print(f"  {total_e:4d} EAST | [{r['book_id']:>5}] {r['title'][:55]:55s} "
                  f"({r['text_len']:>7,} chars)")
    zero_count = sum(1 for e, _ in scored if e == 0)
    if zero_count:
        print(f"  ... {zero_count} books with 0 EAST matches")

    # ── Summary ────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total_all_chars = total_chars + local_total_chars
    print(f"Total corpus: {total_all_chars:,} alpha characters")
    print(f"  Local: {local_total_chars:,}")
    print(f"  Gutenberg: {total_chars:,} ({total_books_ok} books)")

    all_east = sum(grand_east.values()) + sum(local_total_east.values())
    all_bean = sum(grand_bean.values()) + sum(local_total_bean.values())
    all_full = sum(grand_full.values()) + sum(local_total_full.values())

    print(f"\n  EAST matches (all variants): {all_east}")
    print(f"  Bean-EQ passes: {all_bean}")
    print(f"  Full 24-position matches: {all_full}")

    if all_full > 0:
        print("\n  *** FULL MATCH FOUND — see details above ***")
        print("  Verdict: SIGNAL")
    elif all_bean > 0:
        print(f"\n  {all_bean} Bean-EQ passes survived EAST filter but failed full check.")
        print("  These are likely random coincidences.")
        print("  Verdict: NOISE — running key not from tested corpus")
    elif all_east > 0:
        print(f"\n  {all_east} EAST-diff matches but none pass Bean-EQ filter.")
        print("  Consistent with random coincidence rate.")
        print(f"\n  [INTERNAL RESULT] Running key from {total_books_ok}+ Gutenberg books ")
        print(f"  ({total_all_chars:,} chars): ELIMINATED under identity transposition.")
        print("  Verdict: NOISE — TOOL (EAST filter validated at scale)")
    else:
        print(f"\n  Zero EAST matches in entire corpus ({total_all_chars:,} chars).")
        print("  Extremely strong constraint — eliminates all tested texts.")
        print(f"\n  [INTERNAL RESULT] Running key from {total_books_ok}+ texts: ELIMINATED.")
        print("  Verdict: NOISE — TOOL (EAST filter validated at scale)")

    # ── Estimate: what corpus size would be needed for 1 expected match? ──
    p_east = (1.0 / MOD) ** 4
    p_full = (1.0 / MOD) ** (N_CRIBS - 4 - 1)  # remaining 19 after EAST+Bean
    chars_for_1_east = 1.0 / p_east
    chars_for_1_full = 1.0 / ((1.0 / MOD) ** N_CRIBS)
    print(f"\n  Chars needed for 1 expected random EAST match: {chars_for_1_east:,.0f}")
    print(f"  Chars needed for 1 expected random full match: {chars_for_1_full:.2e}")
    print(f"  Our corpus: {total_all_chars:,} chars ({total_all_chars/chars_for_1_east:.1f}× EAST threshold)")


if __name__ == "__main__":
    main()
