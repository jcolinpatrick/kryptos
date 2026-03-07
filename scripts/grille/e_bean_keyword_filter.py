#!/usr/bin/env python3
"""
Bean-Satisfying Keyword Extractor
==================================
Cipher:   polyalphabetic (Gromark / Vigenère / Beaufort)
Family:   grille
Status:   active
Keyspace: ~1.45M dictionary entries → Bean-viable lengths → constraint filter → thematic rank
Last run: never
Best score: n/a

Reads the Kaikki English dictionary JSONL and extracts all words satisfying
Bean's equality + inequality constraints for periodic keys. Then ranks by
thematic relevance (architecture, art, science, history, cryptography — the
categories Sanborn favors for keywords).

Usage:
    PYTHONPATH=src python3 -u scripts/grille/e_bean_keyword_filter.py [--min-len 8] [--max-len 20] [--workers 8]

Output:
    results/bean_keywords/  — TSV files by length, plus ranked summary
"""

import json
import os
import re
import sys
from collections import defaultdict
from multiprocessing import Pool, cpu_count

# ---------------------------------------------------------------------------
# Bean constraints (duplicated here for standalone worker-process use)
# ---------------------------------------------------------------------------
BEAN_EQ = (27, 65)
BEAN_INEQ = [
    (24, 28), (28, 33), (24, 33), (21, 30), (21, 64), (30, 64),
    (68, 25), (22, 31), (66, 70), (26, 71), (69, 72), (23, 32),
    (71, 21), (25, 26), (24, 66), (31, 73), (29, 63), (32, 33),
    (67, 68), (27, 72), (23, 28),
]

# Lengths that are impossible (some inequality pair collapses to same position)
IMPOSSIBLE_LENGTHS = set()
for _L in range(1, 100):
    for _i, _j in BEAN_INEQ:
        if _i % _L == _j % _L:
            IMPOSSIBLE_LENGTHS.add(_L)
            break

# ---------------------------------------------------------------------------
# Thematic scoring — words Sanborn would plausibly use as keywords
# ---------------------------------------------------------------------------
# Known Kryptos-series keywords for reference:
# KRYPTOS, PALIMPSEST, ABSCISSA, OUBLIETTE, CENOTAPH, REVETEMENT, FILIGREE,
# PARALLAX, GNOMON, ESCUTCHEON, VERDIGRIS, TRIPTYCH, COLOPHON, ARMATURE, OCULUS, DOLMEN

# High-value categories (from Kaikki category tags and glosses)
THEME_HIGH = re.compile(
    r"(?i)\b("
    r"architect|sculpt|art\b|arts\b|artistic|cipher|crypt|code\b|codes\b|"
    r"fortif|military|espionage|intelligen|ancient|greek|latin|roman\b|"
    r"egypt|archaeolog|antiquit|monument|tomb|burial|funerar|"
    r"optic|astronomy|astro|navig|compass|sundial|gnomon|"
    r"masonry|stone|marble|bronze|copper|metal|patina|verdigris|"
    r"heraldry|herald|emblem|insignia|"
    r"printing|typograph|book\b|manuscript|calligraph|"
    r"geometr|mathematic|algebra|"
    r"ruin|temple|column|pillar|vault|arch\b|arches|dome|"
    r"alchemy|occult|esoteric|mystical|symbol|"
    r"ornament|decorat|motif|relief|engrav|inscript|carv|"
    r"cartograph|map\b|maps\b|"
    r"museum|gallery|artifact|relic|"
    r"philo|classi|renaissan|medieval|gothic|baroque|"
    r"botany|botanical|garden|"
    r"geology|mineral|fossil|crystal|"
    r"nautical|maritime|naval"
    r")\b"
)

# Medium-value: general science, history, rare/obscure English
THEME_MED = re.compile(
    r"(?i)\b("
    r"science|physics|chemistr|biolog|engineer|"
    r"histor|war\b|battle|siege|weapon|"
    r"literature|poetry|prose|myth|legend|"
    r"music|instrument|"
    r"geograph|terrain|landscape|"
    r"philosophy|logic|"
    r"anatomy|physiolog|"
    r"law\b|legal|jurispruden|"
    r"religion|theolog|church|cathedral|"
    r"language|linguist|grammar|"
    r"zoolog|entomolog|ornitholog"
    r")\b"
)

# Negative categories — obviously unrelated to Sanborn's aesthetic
THEME_NEG = re.compile(
    r"(?i)\b("
    r"slang|vulgar|offensive|derogatory|pejorative|"
    r"internet|computing|software|programming|"
    r"sports|baseball|football|basketball|soccer|cricket|tennis|golf|hockey|"
    r"cooking|culinary|cuisine|recipe|"
    r"medical|medicine|disease|symptom|diagnosis|clinical|surgical|"
    r"obstetric|gynecolog|pediatric|dental|"
    r"fashion|clothing|garment|textile|"
    r"automotive|vehicle|"
    r"brand|trademark|"
    r"informal|colloquial|dialectal"
    r")\b"
)

# POS preference: nouns strongly preferred (all known keywords are nouns)
POS_SCORE = {
    "noun": 3,
    "adj": 1,
    "name": 0,  # proper nouns less likely
    "verb": -1,
    "adv": -2,
    "prep": -3,
    "conj": -3,
    "det": -3,
    "pron": -3,
    "intj": -3,
    "num": -3,
    "particle": -3,
    "affix": -5,
    "prefix": -5,
    "suffix": -5,
    "infix": -5,
}


def score_thematic(word, pos, categories, glosses):
    """Score a word's thematic relevance to Kryptos. Higher = more plausible."""
    score = 0

    # POS
    score += POS_SCORE.get(pos, 0)

    # Length bonus: Sanborn's keywords are 5-11 chars, sweet spot 7-9
    wlen = len(word)
    if 7 <= wlen <= 9:
        score += 2
    elif 5 <= wlen <= 11:
        score += 1
    elif wlen > 15:
        score -= 1

    # Search categories and glosses for thematic matches
    text = " ".join(categories) + " " + " ".join(glosses)

    high_matches = THEME_HIGH.findall(text)
    med_matches = THEME_MED.findall(text)
    neg_matches = THEME_NEG.findall(text)

    score += min(len(high_matches) * 2, 8)  # cap at +8
    score += min(len(med_matches), 3)        # cap at +3
    score -= min(len(neg_matches) * 2, 6)    # cap at -6

    # Bonus for rare/obscure words (fewer senses = more obscure)
    # We'll use gloss count as a proxy - common words have many senses

    # Bonus if word itself looks "architectural/artistic" (heuristic)
    if re.search(r"(?i)(tion|ment|ture|ence|ance|ium|oid|esque|ette|rix|sis|polis)$", word):
        score += 1

    return score


def check_bean_constraints(word):
    """Check if a word (as periodic key) satisfies all Bean constraints."""
    L = len(word)
    if L in IMPOSSIBLE_LENGTHS:
        return False

    w = word.upper()

    # Equality: w[27 % L] == w[65 % L]
    if w[27 % L] != w[65 % L]:
        return False

    # All 21 inequalities
    for i, j in BEAN_INEQ:
        if w[i % L] == w[j % L]:
            return False

    return True


def process_chunk(chunk):
    """Process a chunk of JSONL lines, return Bean-passing words with metadata."""
    results = []
    for line in chunk:
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        word = d.get("word", "")
        if not word or not word.isalpha() or not word.isascii():
            continue

        w_upper = word.upper()
        L = len(w_upper)
        if L < 3 or L > 30:
            continue
        if L in IMPOSSIBLE_LENGTHS:
            continue

        if not check_bean_constraints(w_upper):
            continue

        # Extract metadata
        pos = d.get("pos", "")
        categories = []
        glosses = []
        for s in d.get("senses", []):
            for c in s.get("categories", []):
                if isinstance(c, dict):
                    categories.append(c.get("name", ""))
                else:
                    categories.append(str(c))
            for g in s.get("glosses", []):
                glosses.append(g)

        theme_score = score_thematic(w_upper, pos, categories, glosses)

        results.append({
            "word": w_upper,
            "original": word,
            "length": L,
            "pos": pos,
            "theme_score": theme_score,
            "categories": categories[:5],  # keep top 5
            "gloss": glosses[0][:120] if glosses else "",
            "eq_pos": f"{27 % L}->{65 % L}",
        })

    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract Bean-satisfying keywords from Kaikki dictionary")
    parser.add_argument("--min-len", type=int, default=3, help="Minimum word length (default: 3)")
    parser.add_argument("--max-len", type=int, default=30, help="Maximum word length (default: 30)")
    parser.add_argument("--workers", type=int, default=0, help="Number of workers (default: all CPUs)")
    parser.add_argument("--min-theme", type=int, default=-999, help="Minimum theme score to include (default: all)")
    args = parser.parse_args()

    jsonl_path = os.path.join(os.path.dirname(__file__), "..", "..", "kaikki.org-dictionary-English-words.jsonl")
    jsonl_path = os.path.abspath(jsonl_path)
    if not os.path.exists(jsonl_path):
        print(f"ERROR: {jsonl_path} not found", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.join(os.path.dirname(__file__), "..", "..", "results", "bean_keywords")
    os.makedirs(out_dir, exist_ok=True)

    num_workers = args.workers or cpu_count()
    print(f"Bean Keyword Filter")
    print(f"  Dictionary: {jsonl_path}")
    print(f"  Length range: {args.min_len}-{args.max_len}")
    print(f"  Workers: {num_workers}")
    print(f"  Impossible lengths: {sorted(IMPOSSIBLE_LENGTHS & set(range(args.min_len, args.max_len + 1)))}")
    viable = sorted(set(range(args.min_len, args.max_len + 1)) - IMPOSSIBLE_LENGTHS)
    print(f"  Viable lengths: {viable}")
    print()

    # Read and chunk the file
    print("Reading dictionary...", flush=True)
    chunk_size = 50000
    chunks = []
    current_chunk = []
    total_lines = 0

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            current_chunk.append(line)
            total_lines += 1
            if len(current_chunk) >= chunk_size:
                chunks.append(current_chunk)
                current_chunk = []
        if current_chunk:
            chunks.append(current_chunk)

    print(f"  {total_lines:,} entries in {len(chunks)} chunks", flush=True)

    # Process in parallel
    print("Filtering by Bean constraints...", flush=True)
    all_results = []
    with Pool(num_workers) as pool:
        for i, chunk_results in enumerate(pool.imap_unordered(process_chunk, chunks)):
            all_results.extend(chunk_results)
            if (i + 1) % 5 == 0:
                print(f"  Processed {(i+1)*chunk_size:,}/{total_lines:,} — {len(all_results):,} Bean-passing so far", flush=True)

    print(f"\n  Total Bean-passing entries: {len(all_results):,}", flush=True)

    # Deduplicate by uppercase word (keep highest theme score per word)
    by_word = {}
    for r in all_results:
        w = r["word"]
        if w not in by_word or r["theme_score"] > by_word[w]["theme_score"]:
            by_word[w] = r

    unique_results = sorted(by_word.values(), key=lambda x: (-x["theme_score"], x["word"]))
    print(f"  Unique words: {len(unique_results):,}", flush=True)

    # Apply length filter
    unique_results = [r for r in unique_results if args.min_len <= r["length"] <= args.max_len]
    print(f"  After length filter ({args.min_len}-{args.max_len}): {len(unique_results):,}", flush=True)

    # Apply theme filter
    if args.min_theme > -999:
        unique_results = [r for r in unique_results if r["theme_score"] >= args.min_theme]
        print(f"  After theme filter (>={args.min_theme}): {len(unique_results):,}", flush=True)

    # Stats by length
    by_len = defaultdict(list)
    for r in unique_results:
        by_len[r["length"]].append(r)

    print(f"\n{'Len':>4} {'Count':>7} {'Bean eq positions':>20} {'Top-scored example'}")
    print("-" * 80)
    for L in sorted(by_len.keys()):
        words = by_len[L]
        eq_str = f"word[{27%L}]==word[{65%L}]" if 27 % L != 65 % L else f"trivial (pos {27%L})"
        top = words[0] if words else None
        top_str = f"{top['word']} (theme={top['theme_score']}, {top['pos']})" if top else ""
        print(f"{L:4d} {len(words):7d} {eq_str:>20s} {top_str}")

    # Write output files
    # 1. Full ranked list
    full_path = os.path.join(out_dir, "bean_keywords_ranked.tsv")
    with open(full_path, "w") as f:
        f.write("word\tlength\tpos\ttheme_score\teq_positions\tgloss\tcategories\n")
        for r in unique_results:
            cats = "; ".join(r["categories"][:3])
            f.write(f"{r['word']}\t{r['length']}\t{r['pos']}\t{r['theme_score']}\t{r['eq_pos']}\t{r['gloss']}\t{cats}\n")
    print(f"\nWrote full ranked list: {full_path}")

    # 2. Per-length files
    for L in sorted(by_len.keys()):
        path = os.path.join(out_dir, f"bean_keywords_len{L:02d}.tsv")
        words = sorted(by_len[L], key=lambda x: (-x["theme_score"], x["word"]))
        with open(path, "w") as f:
            f.write("word\tpos\ttheme_score\tgloss\tcategories\n")
            for r in words:
                cats = "; ".join(r["categories"][:3])
                f.write(f"{r['word']}\t{r['pos']}\t{r['theme_score']}\t{r['gloss']}\t{cats}\n")

    # 3. Top candidates (theme_score >= 3, nouns only)
    top_path = os.path.join(out_dir, "bean_keywords_top_candidates.tsv")
    top_candidates = [r for r in unique_results if r["theme_score"] >= 3 and r["pos"] == "noun"]
    with open(top_path, "w") as f:
        f.write("word\tlength\ttheme_score\tgloss\tcategories\n")
        for r in sorted(top_candidates, key=lambda x: (-x["theme_score"], x["word"])):
            cats = "; ".join(r["categories"][:3])
            f.write(f"{r['word']}\t{r['length']}\t{r['theme_score']}\t{r['gloss']}\t{cats}\n")
    print(f"Wrote top candidates (noun, theme>=3): {top_path} ({len(top_candidates):,} words)")

    # 4. Priority-8 file (length 8, Sanborn's sweet spot)
    len8 = by_len.get(8, [])
    if len8:
        path8 = os.path.join(out_dir, "bean_keywords_len08_priority.tsv")
        with open(path8, "w") as f:
            f.write("word\tpos\ttheme_score\tgloss\tcategories\n")
            for r in sorted(len8, key=lambda x: (-x["theme_score"], x["word"])):
                cats = "; ".join(r["categories"][:3])
                f.write(f"{r['word']}\t{r['pos']}\t{r['theme_score']}\t{r['gloss']}\t{cats}\n")
        print(f"Wrote length-8 priority list: {path8} ({len(len8):,} words)")

    # 5. Plain word list for campaign consumption
    wordlist_path = os.path.join(out_dir, "bean_keywords_wordlist.txt")
    with open(wordlist_path, "w") as f:
        for r in unique_results:
            f.write(r["word"] + "\n")
    print(f"Wrote plain wordlist: {wordlist_path} ({len(unique_results):,} words)")

    # Summary
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Total dictionary entries:  {total_lines:,}")
    print(f"  Bean-passing unique words: {len(unique_results):,}")
    print(f"  Top candidates (noun+theme>=3): {len(top_candidates):,}")
    print(f"  Length-8 words: {len(len8):,}")
    print(f"\n  Top 20 by theme score:")
    for r in unique_results[:20]:
        print(f"    {r['word']:20s} len={r['length']:2d} pos={r['pos']:5s} theme={r['theme_score']:+3d}  {r['gloss'][:60]}")

    # Known keywords check
    known = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "VERDIGRIS", "CENOTAPH",
             "FILIGREE", "PARALLAX", "GNOMON", "ESCUTCHEON", "TRIPTYCH",
             "COLOPHON", "ARMATURE", "OCULUS", "DOLMEN", "OUBLIETTE", "REVETEMENT"]
    print(f"\n  Known keyword Bean-check:")
    for kw in known:
        L = len(kw)
        if L in IMPOSSIBLE_LENGTHS:
            status = f"IMPOSSIBLE (len {L})"
        elif check_bean_constraints(kw):
            status = "PASS"
        else:
            eq_ok = kw[27 % L] == kw[65 % L]
            status = f"FAIL (eq={eq_ok}, need [{27%L}]==[{65%L}]: {kw[27%L]} vs {kw[65%L]})"
        print(f"    {kw:15s} len={L:2d}  {status}")


if __name__ == "__main__":
    main()
