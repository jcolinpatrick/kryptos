#!/usr/bin/env python3
"""
Cipher: team-sourced attack
Family: team
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-TEAM-FRENCH-SCAN: French, Latin, and Egyptian-themed Gutenberg texts + EAST filter.

Downloads French literature, Latin classics, and Egypt-themed English texts
from Project Gutenberg. Scans each with EAST gap-9 differential + Bean-EQ
filter to test whether any passage could serve as a running key for K4.

Rationale: Sanborn's 2025 clue mentions Egypt trip 1986. Champollion
(French Egyptologist) deciphered hieroglyphics. K3 references Howard Carter
and Tutankhamun. French/Latin texts are plausible key sources.
"""
import sys
import os
import json
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAN_EQ,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Configuration ──────────────────────────────────────────────────────

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
CACHE_DIR = os.path.join(BASE_DIR, "tmp", "gutenberg_french")
RESULTS_PATH = os.path.join(BASE_DIR, "results", "e_team_french_scan.json")

# EAST gap-9 diffs
EAST_DIFFS_VIG = [1, 25, 1, 23]      # Vig and Beau identical
EAST_DIFFS_VARBEAU = [25, 1, 25, 3]

# Precompute key fragments for each variant at crib positions
CRIB_POSITIONS_SORTED = sorted(CRIB_DICT.keys())
VARIANTS_RECOVER = {
    "vigenere": vig_recover_key,
    "beaufort": beau_recover_key,
    "var_beaufort": varbeau_recover_key,
}
KEY_FRAGMENTS = {}
for vname, recover_fn in VARIANTS_RECOVER.items():
    keys = []
    for pos in CRIB_POSITIONS_SORTED:
        pt_val = ALPH_IDX[CRIB_DICT[pos]]
        ct_val = ALPH_IDX[CT[pos]]
        keys.append(recover_fn(ct_val, pt_val))
    KEY_FRAGMENTS[vname] = dict(zip(CRIB_POSITIONS_SORTED, keys))

# ── Gutenberg text catalog ─────────────────────────────────────────────

GUTENBERG_TEXTS = [
    # French Literature
    (4650,  "candide", "Voltaire", "Candide", "french"),
    (17489, "miserables_1", "Hugo", "Les Misérables Tome I", "french"),
    (17490, "miserables_2", "Hugo", "Les Misérables Tome II", "french"),
    (17491, "miserables_3", "Hugo", "Les Misérables Tome III", "french"),
    (17492, "miserables_4", "Hugo", "Les Misérables Tome IV", "french"),
    (17493, "miserables_5", "Hugo", "Les Misérables Tome V", "french"),
    (19657, "notre_dame", "Hugo", "Notre-Dame de Paris", "french"),
    (17989, "monte_cristo_1", "Dumas", "Le Comte de Monte-Cristo T1", "french"),
    (17990, "monte_cristo_2", "Dumas", "Le Comte de Monte-Cristo T2", "french"),
    (1954,  "pere_goriot", "Balzac", "Le Père Goriot", "french"),
    (14287, "trois_mousquetaires", "Dumas", "Les Trois Mousquetaires", "french"),
    (13846, "fleurs_du_mal", "Baudelaire", "Les Fleurs du Mal", "french"),
    (5782,  "le_petit_prince", "Saint-Exupéry", "Le Petit Prince", "french"),

    # French Egypt-related
    (14005, "champollion_precis", "Champollion", "Précis du système hiéroglyphique", "french_egypt"),
    (10962, "description_egypte", "Various", "Description de l'Égypte (extract)", "french_egypt"),

    # Latin Classics
    (10657, "de_bello_gallico", "Caesar", "De Bello Gallico", "latin"),
    (2707,  "aeneid", "Virgil", "Aeneid", "latin"),
    (2412,  "metamorphoses", "Ovid", "Metamorphoses", "latin"),
    (18710, "cicero_catilinam", "Cicero", "In Catilinam", "latin"),
    (46236, "de_rerum_natura", "Lucretius", "De Rerum Natura", "latin"),

    # English Egypt-themed (not in E-CFM-09 Gutenberg batch)
    (36483, "egypt_exploration", "Edwards", "A Thousand Miles Up the Nile", "english_egypt"),
    (14400, "egyptian_tales", "Petrie", "Egyptian Tales", "english_egypt"),
    (16363, "book_of_dead", "Budge", "The Book of the Dead", "english_egypt"),
    (30344, "egypt_pharaohs", "Rawlinson", "History of Ancient Egypt", "english_egypt"),
    (10897, "herodotus_2", "Herodotus", "Histories Book II (Egypt)", "english_egypt"),
]

# French accent/diacritic mappings (strip to base letter)
FRENCH_ACCENTS = {
    'à': 'A', 'â': 'A', 'ä': 'A', 'æ': 'AE',
    'ç': 'C',
    'è': 'E', 'é': 'E', 'ê': 'E', 'ë': 'E',
    'î': 'I', 'ï': 'I',
    'ô': 'O', 'ö': 'O', 'œ': 'OE',
    'ù': 'U', 'û': 'U', 'ü': 'U',
    'ÿ': 'Y',
    'À': 'A', 'Â': 'A', 'Ä': 'A', 'Æ': 'AE',
    'Ç': 'C',
    'È': 'E', 'É': 'E', 'Ê': 'E', 'Ë': 'E',
    'Î': 'I', 'Ï': 'I',
    'Ô': 'O', 'Ö': 'O', 'Œ': 'OE',
    'Ù': 'U', 'Û': 'U', 'Ü': 'U',
    'Ÿ': 'Y',
    # German (for any mixed texts)
    'ß': 'SS',
}


def text_to_alpha(text):
    """Convert text to uppercase alpha-only, expanding accents/diacritics."""
    result = []
    for c in text:
        if c in FRENCH_ACCENTS:
            result.append(FRENCH_ACCENTS[c])
        elif c.upper() in ALPH:
            result.append(c.upper())
    return "".join(result)


def download_gutenberg(gid, name):
    """Download a Gutenberg text with caching."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR, f"pg{gid}_{name}.txt")

    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    urls = [
        f"https://www.gutenberg.org/cache/epub/{gid}/pg{gid}.txt",
        f"https://www.gutenberg.org/files/{gid}/{gid}-0.txt",
        f"https://www.gutenberg.org/files/{gid}/{gid}.txt",
    ]

    for url in urls:
        try:
            print(f"    Trying {url}...")
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (K4 Research) kryptos-project/1.0"
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("latin-1")

            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(text)
            return text

        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            print(f"      Failed: {e}")
            continue

    print(f"    ERROR: Could not download PG#{gid}")
    return None


def strip_gutenberg_header_footer(text):
    """Remove Project Gutenberg header/footer boilerplate."""
    start_markers = [
        "*** START OF THIS PROJECT GUTENBERG",
        "*** START OF THE PROJECT GUTENBERG",
        "***START OF THIS PROJECT GUTENBERG",
        "***START OF THE PROJECT GUTENBERG",
    ]
    end_markers = [
        "*** END OF THIS PROJECT GUTENBERG",
        "*** END OF THE PROJECT GUTENBERG",
        "***END OF THIS PROJECT GUTENBERG",
        "***END OF THE PROJECT GUTENBERG",
        "End of the Project Gutenberg",
        "End of Project Gutenberg",
    ]

    start_idx = 0
    for marker in start_markers:
        idx = text.find(marker)
        if idx >= 0:
            nl = text.find("\n", idx)
            if nl >= 0:
                start_idx = nl + 1
            break

    end_idx = len(text)
    for marker in end_markers:
        idx = text.find(marker)
        if idx >= 0:
            end_idx = idx
            break

    return text[start_idx:end_idx]


def scan_east_constraint(alpha_text, diffs, variant_name):
    """Scan text for EAST gap-9 differential + Bean-EQ matches."""
    if len(alpha_text) < CT_LEN:
        return [], 0, 0, 0

    max_offset = len(alpha_text) - CT_LEN
    east_matches = 0
    bean_eq_matches = 0
    full_matches = []

    text_num = [ALPH_IDX.get(c, -1) for c in alpha_text]

    for offset in range(max_offset + 1):
        # EAST gap-9 diffs at positions 21-24 vs 30-33
        match = True
        for j in range(4):
            p1 = offset + 21 + j
            p2 = offset + 30 + j
            if text_num[p1] < 0 or text_num[p2] < 0:
                match = False
                break
            if (text_num[p2] - text_num[p1]) % MOD != diffs[j]:
                match = False
                break

        if not match:
            continue

        east_matches += 1

        # Bean-EQ: source[off+27] = source[off+65]
        if alpha_text[offset + 27] != alpha_text[offset + 65]:
            continue

        bean_eq_matches += 1

        # Full 24-position key consistency check
        key_frags = KEY_FRAGMENTS[variant_name]
        key_list = [text_num[offset + i] for i in range(CT_LEN)]

        crib_match = 0
        for pos, expected_key in key_frags.items():
            if key_list[pos] == expected_key:
                crib_match += 1

        if crib_match >= 5:
            entry = {
                "offset": offset,
                "crib_match": crib_match,
                "snippet": alpha_text[offset:offset+50],
                "variant": variant_name,
            }
            # Full decrypt for significant matches
            if crib_match >= 10:
                for cv in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                    pt = decrypt_text(CT, key_list, cv)
                    bean = verify_bean(key_list)
                    sc = score_candidate(pt, bean)
                    entry[f"decrypt_{cv.value}"] = {
                        "crib_score": sc.crib_score,
                        "bean_passed": sc.bean_passed,
                        "pt_snippet": pt[:50],
                    }
            full_matches.append(entry)

    return full_matches, east_matches, bean_eq_matches, max_offset + 1


def main():
    t0 = time.time()

    print("=" * 70)
    print("E-TEAM-FRENCH-SCAN: French/Latin/Egyptian Gutenberg + EAST Filter")
    print("=" * 70)

    # Download and process texts
    texts = {}
    download_stats = {"success": 0, "failed": 0, "failed_ids": []}

    print("\n── Downloading texts ──")
    for gid, name, author, title, category in GUTENBERG_TEXTS:
        print(f"  [{gid}] {author}: {title} ({category})")
        raw = download_gutenberg(gid, name)
        if raw is None:
            download_stats["failed"] += 1
            download_stats["failed_ids"].append(gid)
            continue

        download_stats["success"] += 1
        stripped = strip_gutenberg_header_footer(raw)
        alpha = text_to_alpha(stripped)
        print(f"    Raw: {len(raw):,} → Stripped: {len(stripped):,} → Alpha: {len(alpha):,}")

        if len(alpha) >= CT_LEN:
            texts[f"{author}_{name}"] = {
                "alpha": alpha,
                "gid": gid,
                "title": title,
                "author": author,
                "category": category,
                "alpha_len": len(alpha),
            }

    total_alpha = sum(t["alpha_len"] for t in texts.values())
    print(f"\n  Downloads: {download_stats['success']} success, {download_stats['failed']} failed")
    if download_stats["failed_ids"]:
        print(f"  Failed IDs: {download_stats['failed_ids']}")
    print(f"  Texts loaded: {len(texts)}")
    print(f"  Total alpha chars: {total_alpha:,}")

    # Scan
    print("\n── Scanning with EAST + Bean-EQ filter ──")

    all_results = {}
    grand_east = 0
    grand_bean = 0
    grand_full = []
    grand_offsets = 0

    scan_configs = [
        ("vigenere", EAST_DIFFS_VIG),
        ("var_beaufort", EAST_DIFFS_VARBEAU),
    ]

    for text_name, text_info in sorted(texts.items()):
        alpha = text_info["alpha"]
        text_results = {"east": 0, "bean_eq": 0, "full_matches": [], "offsets_scanned": 0}

        for variant_name, diffs in scan_configs:
            full_matches, east_count, bean_count, n_offsets = scan_east_constraint(
                alpha, diffs, variant_name
            )
            text_results["east"] += east_count
            text_results["bean_eq"] += bean_count
            text_results["offsets_scanned"] += n_offsets

            for fm in full_matches:
                fm["text"] = text_name
                text_results["full_matches"].append(fm)

        grand_east += text_results["east"]
        grand_bean += text_results["bean_eq"]
        grand_full.extend(text_results["full_matches"])
        grand_offsets += text_results["offsets_scanned"]

        status = "CLEAN" if text_results["bean_eq"] == 0 else f"BEAN-EQ={text_results['bean_eq']}"
        full_flag = f" FULL={len(text_results['full_matches'])}" if text_results["full_matches"] else ""
        cat = text_info["category"]
        print(f"  {text_name:40s} [{cat:13s}] {text_info['alpha_len']:>8,} | "
              f"EAST={text_results['east']:>4} BEQ={text_results['bean_eq']:>2}"
              f"{full_flag} [{status}]")

        all_results[text_name] = {
            "gid": text_info["gid"],
            "title": text_info["title"],
            "author": text_info["author"],
            "category": text_info["category"],
            "alpha_len": text_info["alpha_len"],
            "east_matches": text_results["east"],
            "bean_eq_matches": text_results["bean_eq"],
            "full_match_count": len(text_results["full_matches"]),
            "full_matches": text_results["full_matches"],
        }

    elapsed = time.time() - t0

    # ── Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("FINAL SUMMARY — E-TEAM-FRENCH-SCAN")
    print("=" * 70)
    print(f"Texts scanned:       {len(texts)}")
    print(f"Total alpha chars:   {total_alpha:,}")
    print(f"Total offsets:       {grand_offsets:,}")
    print(f"EAST matches:        {grand_east}")
    print(f"Bean-EQ passes:      {grand_bean}")
    print(f"Full matches (>=5):  {len(grand_full)}")
    print(f"Elapsed:             {elapsed:.1f}s")

    # Category breakdown
    cat_stats = {}
    for text_name, text_info in texts.items():
        cat = text_info["category"]
        if cat not in cat_stats:
            cat_stats[cat] = {"chars": 0, "count": 0}
        cat_stats[cat]["chars"] += text_info["alpha_len"]
        cat_stats[cat]["count"] += 1
    print("\nBy category:")
    for cat, stats in sorted(cat_stats.items()):
        print(f"  {cat:15s}: {stats['count']:2d} texts, {stats['chars']:>10,} chars")

    # Expected false positives
    exp_east = grand_offsets * (1.0/26)**4
    exp_bean = grand_east * (1.0/26)
    print(f"\nExpected EAST (random):  {exp_east:.1f}")
    print(f"Expected BEQ|EAST:       {exp_bean:.2f}")
    if grand_offsets > 0 and grand_east > 0:
        print(f"Observed EAST ratio:     {grand_east/exp_east:.2f}x random")

    # Significant matches
    significant = [fm for fm in grand_full if fm.get("crib_match", 0) >= 10]
    if significant:
        print(f"\n*** SIGNIFICANT MATCHES (crib >= 10) ***")
        for fm in significant:
            print(f"  {fm['text']} offset={fm['offset']} crib={fm['crib_match']} "
                  f"snippet={fm.get('snippet','')[:40]}")
    else:
        print(f"\nNo significant (>=10) matches found.")

    near = [fm for fm in grand_full if 5 <= fm.get("crib_match", 0) < 10]
    if near:
        print(f"\nNear misses (crib 5-9): {len(near)}")
        for fm in near[:10]:
            print(f"  {fm['text']} offset={fm['offset']} crib={fm['crib_match']} "
                  f"variant={fm.get('variant','')} snippet={fm.get('snippet','')[:40]}")

    max_crib = max((fm.get("crib_match", 0) for fm in grand_full), default=0)
    if max_crib >= 18:
        verdict = "SIGNAL"
    elif max_crib >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")

    # ── Write results ──────────────────────────────────────────────────
    output = {
        "experiment": "E-TEAM-FRENCH-SCAN",
        "description": "French/Latin/Egyptian Gutenberg texts scanned with EAST+Bean-EQ filter",
        "texts_scanned": len(texts),
        "texts_attempted": len(GUTENBERG_TEXTS),
        "total_alpha_chars": total_alpha,
        "total_offsets_scanned": grand_offsets,
        "east_matches": grand_east,
        "bean_eq_matches": grand_bean,
        "full_match_count": len(grand_full),
        "significant_count": len(significant),
        "elapsed_seconds": round(elapsed, 1),
        "verdict": verdict,
        "category_breakdown": cat_stats,
        "download_stats": download_stats,
        "per_text_results": all_results,
        "full_matches_detail": grand_full[:50],
        "texts_catalog": [
            {"gid": gid, "name": name, "author": author, "title": title, "category": cat}
            for gid, name, author, title, cat in GUTENBERG_TEXTS
        ],
    }

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
