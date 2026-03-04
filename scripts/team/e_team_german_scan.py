#!/usr/bin/env python3
"""
Cipher: team-sourced attack
Family: team
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-TEAM-GERMAN-SCAN: Download and scan German Gutenberg texts with EAST filter.

Downloads German literature from Project Gutenberg and scans each text
with the EAST gap-9 differential constraint + Bean-EQ filter to test
whether any passage could serve as a running key for K4.

EAST constraint: Under running key, the source text must satisfy:
  source[off+30+j] - source[off+21+j] ≡ delta_j (mod 26) for j=0..3
  where delta = [1,25,1,23] (Vig/Beau) or [25,1,25,3] (VarBeau)

Bean-EQ: source[off+27] = source[off+65] (same character, gap-38)

Combined P(false positive) ≈ 8.4e-8 per offset position.
For 10M chars: ~0.84 expected false positives.
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
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Configuration ──────────────────────────────────────────────────────

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
CACHE_DIR = os.path.join(BASE_DIR, "tmp", "gutenberg_german")
RESULTS_PATH = os.path.join(BASE_DIR, "results", "e_team_german_scan.json")

# Project Gutenberg German texts
GUTENBERG_TEXTS = [
    # (ID, short_name, author, title)
    (22367, "verwandlung", "Kafka", "Die Verwandlung"),
    (7849,  "prozess", "Kafka", "Der Prozess"),
    (2229,  "faust", "Goethe", "Faust"),
    (2407,  "werther", "Goethe", "Die Leiden des jungen Werther"),
    (2404,  "wahlverwandtschaften", "Goethe", "Die Wahlverwandtschaften"),
    (6498,  "raeuber", "Schiller", "Die Räuber"),
    (7205,  "zarathustra", "Nietzsche", "Also sprach Zarathustra"),
    (7204,  "jenseits", "Nietzsche", "Jenseits von Gut und Böse"),
    (2591,  "grimm", "Grimm", "Kinder- und Hausmärchen"),
    # Additional German texts of historical/political relevance
    (5323,  "emilia_galotti", "Lessing", "Emilia Galotti"),
    (6499,  "kabale_liebe", "Schiller", "Kabale und Liebe"),
    (2636,  "prinz_homburg", "Kleist", "Prinz Friedrich von Homburg"),
    (7882,  "effi_briest", "Fontane", "Effi Briest"),
    (9318,  "buddenbrooks", "Mann", "Buddenbrooks"),
    (29153, "steppenwolf", "Hesse", "Der Steppenwolf"),
    (46525, "siddhartha", "Hesse", "Siddhartha"),
]

# EAST gap-9 diffs (derived from cribs, variant-independent for Vig/Beau)
EAST_DIFFS_VIG = [1, 25, 1, 23]   # Vig and Beau identical
EAST_DIFFS_VARBEAU = [25, 1, 25, 3]  # Negated

# Known key fragments at crib positions (for full 24-position check)
CRIB_POSITIONS_SORTED = sorted(CRIB_DICT.keys())
VARIANTS_RECOVER = {
    "vigenere": vig_recover_key,
    "beaufort": beau_recover_key,
    "var_beaufort": varbeau_recover_key,
}

# Precompute key fragments for each variant
KEY_FRAGMENTS = {}
for vname, recover_fn in VARIANTS_RECOVER.items():
    keys = []
    for pos in CRIB_POSITIONS_SORTED:
        pt_val = ALPH_IDX[CRIB_DICT[pos]]
        ct_val = ALPH_IDX[CT[pos]]
        keys.append(recover_fn(ct_val, pt_val))
    KEY_FRAGMENTS[vname] = dict(zip(CRIB_POSITIONS_SORTED, keys))

# German umlaut/eszett mappings
GERMAN_MAP = {
    'Ä': 'AE', 'ä': 'AE',
    'Ö': 'OE', 'ö': 'OE',
    'Ü': 'UE', 'ü': 'UE',
    'ß': 'SS',
}


# ── Helper functions ───────────────────────────────────────────────────

def german_to_alpha(text):
    """Convert German text to uppercase alpha-only, expanding umlauts."""
    result = []
    for c in text:
        if c in GERMAN_MAP:
            result.append(GERMAN_MAP[c])
        elif c.upper() in ALPH:
            result.append(c.upper())
    return "".join(result)


def download_gutenberg(gid, name):
    """Download a Gutenberg text, with caching."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR, f"pg{gid}_{name}.txt")

    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    # Try multiple URL patterns
    urls = [
        f"https://www.gutenberg.org/cache/epub/{gid}/pg{gid}.txt",
        f"https://www.gutenberg.org/files/{gid}/{gid}-0.txt",
        f"https://www.gutenberg.org/files/{gid}/{gid}.txt",
    ]

    for url in urls:
        try:
            print(f"    Downloading {url}...")
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (K4 Research) kryptos-project/1.0"
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                # Try UTF-8 first, fall back to latin-1
                raw = resp.read()
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("latin-1")

            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(text)
            return text

        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            print(f"    Failed ({e}), trying next URL...")
            continue

    print(f"    ERROR: Could not download PG#{gid}")
    return None


def strip_gutenberg_header_footer(text):
    """Remove Project Gutenberg header and footer boilerplate."""
    # Find start of actual text
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
            # Find next newline after marker
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
    """Scan text for EAST gap-9 differential matches.

    Returns list of (offset, east_match, bean_eq_match, full_24_score) tuples.
    """
    if len(alpha_text) < CT_LEN:
        return [], 0, 0, 0

    max_offset = len(alpha_text) - CT_LEN
    east_matches = 0
    bean_eq_matches = 0
    full_matches = []

    # Pre-convert to numeric for speed
    text_num = [ALPH_IDX.get(c, -1) for c in alpha_text]

    for offset in range(max_offset + 1):
        # Check EAST gap-9 diffs at positions 21-24 vs 30-33
        match = True
        for j in range(4):
            p1 = offset + 21 + j
            p2 = offset + 30 + j
            if text_num[p1] < 0 or text_num[p2] < 0:
                match = False
                break
            char_diff = (text_num[p2] - text_num[p1]) % MOD
            if char_diff != diffs[j]:
                match = False
                break

        if not match:
            continue

        east_matches += 1

        # Check Bean-EQ: source[off+27] = source[off+65]
        if alpha_text[offset + 27] != alpha_text[offset + 65]:
            continue

        bean_eq_matches += 1

        # Full 24-position key consistency check
        key_frags = KEY_FRAGMENTS[variant_name]
        key_list = [text_num[offset + i] for i in range(CT_LEN)]

        # Check all 24 crib positions
        crib_match = 0
        for pos, expected_key in key_frags.items():
            if key_list[pos] == expected_key:
                crib_match += 1

        if crib_match >= 10:  # Only record significant matches
            full_matches.append({
                "offset": offset,
                "crib_match": crib_match,
                "snippet": alpha_text[offset:offset+40],
                "key_snippet": "".join(ALPH[k] for k in key_list[:30]),
            })
        elif crib_match >= 5:  # Track near-misses too
            full_matches.append({
                "offset": offset,
                "crib_match": crib_match,
                "snippet": alpha_text[offset:offset+40],
            })

    return full_matches, east_matches, bean_eq_matches, max_offset + 1


def full_decrypt_and_score(alpha_text, offset, variant):
    """Decrypt K4 using text at offset as running key and score."""
    key_str = alpha_text[offset:offset + CT_LEN]
    if len(key_str) < CT_LEN:
        return None

    key_list = [ALPH_IDX[c] for c in key_str]
    pt = decrypt_text(CT, key_list, variant)
    bean_result = verify_bean(key_list)
    sc = score_candidate(pt, bean_result)

    return {
        "crib_score": sc.crib_score,
        "bean_passed": sc.bean_passed,
        "ic": sc.ic_value,
        "classification": sc.crib_classification,
        "pt_snippet": pt[:50],
        "summary": sc.summary,
    }


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 70)
    print("E-TEAM-GERMAN-SCAN: German Gutenberg Texts + EAST Filter")
    print("=" * 70)

    # Variant -> diffs mapping
    variant_diffs = {
        "vigenere": EAST_DIFFS_VIG,
        "beaufort": EAST_DIFFS_VIG,        # Same as Vig (derived fact)
        "var_beaufort": EAST_DIFFS_VARBEAU,
    }

    # Download and process all texts
    texts = {}
    print("\n── Downloading texts ──")
    for gid, name, author, title in GUTENBERG_TEXTS:
        print(f"  [{gid}] {author}: {title}")
        raw = download_gutenberg(gid, name)
        if raw is None:
            continue
        stripped = strip_gutenberg_header_footer(raw)
        alpha = german_to_alpha(stripped)
        print(f"    Raw: {len(raw)} chars → Stripped: {len(stripped)} → Alpha: {len(alpha)}")
        if len(alpha) >= CT_LEN:
            texts[f"{author}_{name}"] = {
                "alpha": alpha,
                "gid": gid,
                "title": title,
                "author": author,
                "alpha_len": len(alpha),
            }

    # Also load local reference texts that weren't scanned in E-CFM-09
    local_files = [
        ("reference/carter_gutenberg.txt", "Carter_gutenberg"),
        ("reference/carter_vol1.txt", "Carter_vol1"),
    ]
    for rel_path, name in local_files:
        full_path = os.path.join(BASE_DIR, rel_path)
        if os.path.exists(full_path):
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            alpha = german_to_alpha(raw)  # Works for English too (no umlauts)
            if len(alpha) >= CT_LEN:
                texts[name] = {
                    "alpha": alpha,
                    "gid": None,
                    "title": name,
                    "author": "Reference",
                    "alpha_len": len(alpha),
                }

    total_alpha = sum(t["alpha_len"] for t in texts.values())
    print(f"\n  Total texts: {len(texts)}")
    print(f"  Total alpha chars: {total_alpha:,}")

    # Scan each text
    print("\n── Scanning with EAST + Bean-EQ filter ──")

    all_results = {}
    grand_east = 0
    grand_bean = 0
    grand_full = []
    grand_offsets = 0

    # Only need to scan with Vig diffs (same as Beau) + VarBeau diffs
    scan_configs = [
        ("vigenere", EAST_DIFFS_VIG),       # covers both Vig and Beau
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
                fm["variant"] = variant_name
                fm["text"] = text_name
                text_results["full_matches"].append(fm)

                # If significant, do full decrypt
                if fm.get("crib_match", 0) >= 10:
                    # Map variant name to CipherVariant
                    cv = {
                        "vigenere": CipherVariant.VIGENERE,
                        "beaufort": CipherVariant.BEAUFORT,
                        "var_beaufort": CipherVariant.VAR_BEAUFORT,
                    }
                    # Try both Vig and Beau since they share diffs
                    for try_variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT] if variant_name != "var_beaufort" else [CipherVariant.VAR_BEAUFORT]:
                        decrypt_result = full_decrypt_and_score(alpha, fm["offset"], try_variant)
                        if decrypt_result:
                            fm[f"decrypt_{try_variant.value}"] = decrypt_result

        grand_east += text_results["east"]
        grand_bean += text_results["bean_eq"]
        grand_full.extend(text_results["full_matches"])
        grand_offsets += text_results["offsets_scanned"]

        status = "CLEAN" if text_results["bean_eq"] == 0 else f"BEAN-EQ={text_results['bean_eq']}"
        full_flag = f" FULL={len(text_results['full_matches'])}" if text_results["full_matches"] else ""
        print(f"  {text_name:40s} {text_info['alpha_len']:>8,} chars | "
              f"EAST={text_results['east']:>4} BEAN-EQ={text_results['bean_eq']:>2} "
              f"{full_flag} [{status}]")

        all_results[text_name] = {
            "gid": text_info["gid"],
            "title": text_info["title"],
            "author": text_info["author"],
            "alpha_len": text_info["alpha_len"],
            "east_matches": text_results["east"],
            "bean_eq_matches": text_results["bean_eq"],
            "full_match_count": len(text_results["full_matches"]),
            "full_matches": text_results["full_matches"],
        }

    elapsed = time.time() - t0

    # ── Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("FINAL SUMMARY — E-TEAM-GERMAN-SCAN")
    print("=" * 70)
    print(f"Texts scanned:       {len(texts)}")
    print(f"Total alpha chars:   {total_alpha:,}")
    print(f"Total offsets:       {grand_offsets:,}")
    print(f"EAST matches:        {grand_east}")
    print(f"Bean-EQ passes:      {grand_bean}")
    print(f"Full matches (>=5):  {len(grand_full)}")
    print(f"Elapsed:             {elapsed:.1f}s")

    # Expected false positives
    exp_east = grand_offsets * (1.0/26)**4
    exp_bean = grand_east * (1.0/26)
    print(f"\nExpected EAST (random): {exp_east:.1f}")
    print(f"Expected Bean-EQ|EAST:  {exp_bean:.2f}")
    print(f"Observed EAST ratio:    {grand_east/max(grand_offsets,1)*26**4:.2f}x random" if grand_offsets > 0 else "")

    # Any significant full matches?
    significant = [fm for fm in grand_full if fm.get("crib_match", 0) >= 10]
    if significant:
        print(f"\n*** SIGNIFICANT MATCHES (crib >= 10) ***")
        for fm in significant:
            print(f"  {fm['text']} offset={fm['offset']} crib={fm['crib_match']} "
                  f"snippet={fm.get('snippet','')[:40]}")
    else:
        print(f"\nNo full 24-position matches found.")

    # Near misses
    near = [fm for fm in grand_full if 5 <= fm.get("crib_match", 0) < 10]
    if near:
        print(f"\nNear misses (crib 5-9): {len(near)}")
        for fm in near[:10]:
            print(f"  {fm['text']} offset={fm['offset']} crib={fm['crib_match']} "
                  f"variant={fm.get('variant','')} snippet={fm.get('snippet','')[:40]}")

    # Verdict
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
        "experiment": "E-TEAM-GERMAN-SCAN",
        "description": "German Gutenberg texts scanned with EAST gap-9 + Bean-EQ filter",
        "texts_scanned": len(texts),
        "total_alpha_chars": total_alpha,
        "total_offsets_scanned": grand_offsets,
        "east_matches": grand_east,
        "bean_eq_matches": grand_bean,
        "full_match_count": len(grand_full),
        "significant_count": len(significant) if significant else 0,
        "elapsed_seconds": round(elapsed, 1),
        "verdict": verdict,
        "expected_east_random": round(exp_east, 1),
        "per_text_results": all_results,
        "full_matches_detail": grand_full[:50],
        "texts_attempted": [
            {"gid": gid, "name": name, "author": author, "title": title}
            for gid, name, author, title in GUTENBERG_TEXTS
        ],
    }

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
