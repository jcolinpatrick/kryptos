#!/usr/bin/env python3
"""E-TEAM-ITALIAN-SPANISH-SCAN: Italian + Spanish Gutenberg texts + EAST filter.

Extends corpus scanning to Italian and Spanish literature. Previous scans:
- English: 47.4M chars (E-CFM-09) — ELIMINATED
- German: 4.5M chars (E-TEAM German) — ELIMINATED
- French/Latin/Egyptian: 10.2M chars (E-TEAM French) — ELIMINATED

Also scans K1-K3 plaintext concatenation as running key source.
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
CACHE_DIR = os.path.join(BASE_DIR, "tmp", "gutenberg_it_es")
RESULTS_PATH = os.path.join(BASE_DIR, "results", "e_team_italian_spanish_scan.json")

# EAST gap-9 diffs
EAST_DIFFS_VIG = [1, 25, 1, 23]
EAST_DIFFS_VARBEAU = [25, 1, 25, 3]

# Precompute key fragments
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

# K1-K3 plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"

# ── Gutenberg text catalog ─────────────────────────────────────────────

GUTENBERG_TEXTS = [
    # Italian Literature
    (1012,  "divina_commedia", "Dante", "La Divina Commedia", "italian"),
    (1013,  "inferno", "Dante", "Inferno", "italian"),
    (1014,  "purgatorio", "Dante", "Purgatorio", "italian"),
    (1015,  "paradiso", "Dante", "Paradiso", "italian"),
    (1232,  "principe", "Machiavelli", "Il Principe", "italian"),
    (3726,  "decameron", "Boccaccio", "Decameron", "italian"),
    (23700, "promessi_sposi", "Manzoni", "I Promessi Sposi", "italian"),
    (18155, "pirandello_fu_mattia", "Pirandello", "Il Fu Mattia Pascal", "italian"),
    (38145, "leopardi_canti", "Leopardi", "Canti", "italian"),
    (30601, "leopardi_operette", "Leopardi", "Operette Morali", "italian"),
    (19480, "svevo_coscienza", "Svevo", "La Coscienza di Zeno", "italian"),
    (24249, "verga_malavoglia", "Verga", "I Malavoglia", "italian"),
    (29737, "collodi_pinocchio", "Collodi", "Le Avventure di Pinocchio", "italian"),
    (6130,  "casanova", "Casanova", "Mémoires (Italian)", "italian"),
    (22382, "goldoni_locandiera", "Goldoni", "La Locandiera", "italian"),

    # Spanish Literature
    (2000,  "quijote_1", "Cervantes", "Don Quijote Parte I", "spanish"),
    (2001,  "quijote_2", "Cervantes", "Don Quijote Parte II", "spanish"),
    (15532, "lazarillo", "Anonymous", "Lazarillo de Tormes", "spanish"),
    (49836, "celestina", "Rojas", "La Celestina", "spanish"),
    (17073, "garcia_lorca_romancero", "García Lorca", "Romancero Gitano", "spanish"),
    (56223, "borges_ficciones", "Borges", "Ficciones", "spanish"),
    (50751, "neruda_veinte", "Neruda", "Veinte Poemas de Amor", "spanish"),
    (14765, "becquer_rimas", "Bécquer", "Rimas y Leyendas", "spanish"),
    (24536, "sor_juana", "Sor Juana", "Poemas", "spanish"),
    (15725, "galdos_fortunata", "Pérez Galdós", "Fortunata y Jacinta", "spanish"),
    (49010, "unamuno_niebla", "Unamuno", "Niebla", "spanish"),
    (54829, "machado_campos", "Machado", "Campos de Castilla", "spanish"),
]

# Accent/diacritic mappings for Italian/Spanish
ACCENT_MAP = {
    # Italian
    'à': 'A', 'è': 'E', 'é': 'E', 'ì': 'I', 'ò': 'O', 'ù': 'U',
    'À': 'A', 'È': 'E', 'É': 'E', 'Ì': 'I', 'Ò': 'O', 'Ù': 'U',
    # Spanish
    'á': 'A', 'í': 'I', 'ó': 'O', 'ú': 'U', 'ñ': 'N',
    'Á': 'A', 'Í': 'I', 'Ó': 'O', 'Ú': 'U', 'Ñ': 'N',
    'ü': 'U', 'Ü': 'U',
    # French (may appear in Italian texts)
    'â': 'A', 'ê': 'E', 'î': 'I', 'ô': 'O', 'û': 'U',
    'ç': 'C', 'Ç': 'C',
    'ë': 'E', 'ï': 'I', 'ÿ': 'Y',
    'æ': 'AE', 'œ': 'OE', 'Æ': 'AE', 'Œ': 'OE',
    'ß': 'SS',
    'Â': 'A', 'Ê': 'E', 'Î': 'I', 'Ô': 'O', 'Û': 'U',
    'Ë': 'E', 'Ï': 'I', 'Ÿ': 'Y',
    'ä': 'A', 'ö': 'O',
    'Ä': 'A', 'Ö': 'O',
}


def text_to_alpha(text):
    """Convert text to uppercase alpha-only, expanding accents."""
    result = []
    for c in text:
        if c in ACCENT_MAP:
            result.append(ACCENT_MAP[c])
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
    """Remove Project Gutenberg header/footer."""
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
    """Scan text for EAST gap-9 + Bean-EQ matches."""
    if len(alpha_text) < CT_LEN:
        return [], 0, 0, 0

    max_offset = len(alpha_text) - CT_LEN
    east_matches = 0
    bean_eq_matches = 0
    full_matches = []

    text_num = [ALPH_IDX.get(c, -1) for c in alpha_text]

    for offset in range(max_offset + 1):
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

        if alpha_text[offset + 27] != alpha_text[offset + 65]:
            continue

        bean_eq_matches += 1

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
    print("E-TEAM-ITALIAN-SPANISH-SCAN: Italian + Spanish Gutenberg + EAST Filter")
    print("=" * 70)

    texts = {}
    download_stats = {"success": 0, "failed": 0, "failed_ids": []}

    # Download Gutenberg texts
    print("\n-- Downloading texts --")
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
        print(f"    Raw: {len(raw):,} -> Alpha: {len(alpha):,}")

        if len(alpha) >= CT_LEN:
            texts[f"{author}_{name}"] = {
                "alpha": alpha,
                "gid": gid,
                "title": title,
                "author": author,
                "category": category,
                "alpha_len": len(alpha),
            }

    # Add K1-K3 plaintext concatenation
    k123 = K1_PT + K2_PT + K3_PT
    texts["K123_plaintext"] = {
        "alpha": k123,
        "gid": None,
        "title": "K1+K2+K3 plaintext concatenation",
        "author": "Kryptos",
        "category": "kryptos_internal",
        "alpha_len": len(k123),
    }
    # Also K3+K4CT+K1+K2 (Antipodes order)
    antipodes_order = K3_PT + CT + K1_PT + K2_PT
    texts["Antipodes_order"] = {
        "alpha": antipodes_order,
        "gid": None,
        "title": "K3+K4CT+K1+K2 (Antipodes order)",
        "author": "Kryptos",
        "category": "kryptos_internal",
        "alpha_len": len(antipodes_order),
    }

    total_alpha = sum(t["alpha_len"] for t in texts.values())
    print(f"\n  Downloads: {download_stats['success']} success, {download_stats['failed']} failed")
    if download_stats["failed_ids"]:
        print(f"  Failed IDs: {download_stats['failed_ids']}")
    print(f"  Texts loaded: {len(texts)}")
    print(f"  Total alpha chars: {total_alpha:,}")

    # Scan
    print("\n-- Scanning with EAST + Bean-EQ filter --")

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
        print(f"  {text_name:40s} [{cat:16s}] {text_info['alpha_len']:>8,} | "
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
    print("FINAL SUMMARY -- E-TEAM-ITALIAN-SPANISH-SCAN")
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
        print(f"  {cat:18s}: {stats['count']:2d} texts, {stats['chars']:>10,} chars")

    exp_east = grand_offsets * (1.0/26)**4
    exp_bean = grand_east * (1.0/26)
    print(f"\nExpected EAST (random):  {exp_east:.1f}")
    print(f"Expected BEQ|EAST:       {exp_bean:.2f}")
    if grand_offsets > 0 and exp_east > 0:
        print(f"Observed EAST ratio:     {grand_east/exp_east:.2f}x random")

    significant = [fm for fm in grand_full if fm.get("crib_match", 0) >= 10]
    if significant:
        print(f"\n*** SIGNIFICANT MATCHES (crib >= 10) ***")
        for fm in significant:
            print(f"  {fm['text']} offset={fm['offset']} crib={fm['crib_match']}")
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

    # Cumulative totals across all corpus scans
    print(f"\n-- CUMULATIVE CORPUS TOTALS (all scans) --")
    print(f"  English (E-CFM-09):        47,400,000 chars")
    print(f"  German (E-TEAM):            4,511,293 chars")
    print(f"  French/Latin/Egypt (E-TEAM):10,207,584 chars")
    print(f"  Italian/Spanish (this):    {total_alpha:>10,} chars")
    cumulative = 47_400_000 + 4_511_293 + 10_207_584 + total_alpha
    print(f"  GRAND TOTAL:               {cumulative:>10,} chars")
    print(f"  Full 24-pos matches:       0 across ALL corpora")

    # ── Write results ──────────────────────────────────────────────────
    output = {
        "experiment": "E-TEAM-ITALIAN-SPANISH-SCAN",
        "description": "Italian + Spanish Gutenberg texts + K1-K3 plaintext scanned with EAST+Bean-EQ filter",
        "texts_scanned": len(texts),
        "texts_attempted": len(GUTENBERG_TEXTS) + 2,
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
        "cumulative_all_scans": {
            "english_chars": 47_400_000,
            "german_chars": 4_511_293,
            "french_latin_egypt_chars": 10_207_584,
            "italian_spanish_chars": total_alpha,
            "grand_total": cumulative,
            "full_matches": 0,
        },
        "per_text_results": all_results,
        "full_matches_detail": grand_full[:50],
    }

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
