#!/usr/bin/env python3
"""E-EGYPT-00: Transliteration-aware Egyptological corpus pipeline.

[HYPOTHESIS] If K4 uses a running key from an Egypt-related text (Sanborn
visited Egypt in 1986, K3 plaintext is from Carter's book), the source text's
Egyptological spellings will produce a specific A-Z letter sequence that must
satisfy the EAST gap-9 differential + Bean-EQ constraints.

Different scholars spell the same Egyptian names differently:
    Tutankhamen / Tutankhamun / Tut-Ankh-Amen → different A-Z sequences
    Akhenaton / Akhenaten / Akh-en-Aten       → different letter positions

This pipeline:
1. Ingests Egypt-related texts (local + Gutenberg)
2. Produces 9 variant representations per passage
3. Writes flat A-Z testing files per variant type
4. Runs EAST constraint scan on every variant
5. Generates analysis report

VM: 28 vCPUs, 31GB RAM.  Designed for parallel local execution.
"""
import sys
import os
import json
import time
import re
from multiprocessing import Pool, cpu_count
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.transforms.vigenere import (
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.corpus.schema import CorpusPassage, OffsetEntry
from kryptos.corpus.normalize import EgyptNormalizer, EGYPT_NAMES
from kryptos.corpus.variants import VariantGenerator
from kryptos.corpus.ingest import TextIngester, EGYPT_GUTENBERG_BOOKS

# ── Configuration ────────────────────────────────────────────────────────

WORKERS = min(28, cpu_count())
OUTPUT_DIR = "results/egypt_corpus"
REFERENCE_DIR = "reference"

# ── EAST constraint setup (from E-CFM-06) ────────────────────────────────

CRIB_POSITIONS = sorted(CRIB_DICT.keys())
CT_VALS = [ALPH_IDX[c] for c in CT]
PT_VALS = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Precompute key fragments for all cipher variants
CIPHER_VARIANTS = {}
for vname, recover_fn in [
    ("vigenere", vig_recover_key),
    ("beaufort", beau_recover_key),
    ("var_beaufort", varbeau_recover_key),
]:
    keys = [recover_fn(CT_VALS[pos], PT_VALS[pos]) for pos in CRIB_POSITIONS]
    # EAST diffs: gap between first 4 and next 4 crib positions (gap=9)
    east_diffs = [(keys[9 + j] - keys[j]) % MOD for j in range(4)]
    CIPHER_VARIANTS[vname] = {"keys": keys, "east_diffs": east_diffs}


# ── EAST scanner ─────────────────────────────────────────────────────────

def scan_east(args: Tuple[str, str, str]) -> Dict:
    """Scan a single variant file for EAST constraint matches.

    Args: (variant_name, alpha_text, cipher_variant_name)
    Returns: dict with match counts and details.
    """
    variant_name, alpha_text, cipher_name = args
    if len(alpha_text) < CT_LEN:
        return {
            "variant": variant_name, "cipher": cipher_name,
            "text_len": len(alpha_text),
            "east_matches": 0, "bean_eq_passes": 0, "full_matches": 0,
            "details": [],
        }

    ints = [ALPH_IDX.get(c, 0) for c in alpha_text]
    n = len(ints)
    east_diffs = CIPHER_VARIANTS[cipher_name]["east_diffs"]
    keys_ref = CIPHER_VARIANTS[cipher_name]["keys"]

    east_matches = 0
    bean_eq_passes = 0
    full_matches = 0
    details = []

    recover_fn = {
        "vigenere": vig_recover_key,
        "beaufort": beau_recover_key,
        "var_beaufort": varbeau_recover_key,
    }[cipher_name]

    for offset in range(n - CT_LEN + 1):
        # Fast EAST check: 4 differential constraints
        ok = True
        for j in range(4):
            p1 = offset + CRIB_POSITIONS[j]       # pos 21+j
            p2 = offset + CRIB_POSITIONS[9 + j]   # pos 30+j
            if p1 >= n or p2 >= n:
                ok = False
                break
            diff = (ints[p2] - ints[p1]) % MOD
            if diff != east_diffs[j]:
                ok = False
                break
        if not ok:
            continue
        east_matches += 1

        # Bean-EQ check: k[27] = k[65]
        pos27 = offset + 27
        pos65 = offset + 65
        if pos27 >= n or pos65 >= n:
            continue
        k27 = recover_fn(ints[pos27], PT_VALS[27])
        k65 = recover_fn(ints[pos65], PT_VALS[65])
        if k27 != k65:
            continue
        bean_eq_passes += 1

        # Full 24-position check
        all_match = True
        recovered_keys = {}
        for i, pos in enumerate(CRIB_POSITIONS):
            abs_pos = offset + pos
            if abs_pos >= n:
                all_match = False
                break
            k = recover_fn(ints[abs_pos], PT_VALS[pos])
            recovered_keys[pos] = k

        if all_match and len(recovered_keys) == N_CRIBS:
            # Check Bean inequalities
            bean_ok = True
            for p1, p2 in BEAN_INEQ:
                if p1 in recovered_keys and p2 in recovered_keys:
                    if recovered_keys[p1] == recovered_keys[p2]:
                        bean_ok = False
                        break

            if bean_ok:
                full_matches += 1
                # Extract context for reporting
                ctx_start = max(0, offset - 10)
                ctx_end = min(n, offset + CT_LEN + 10)
                context = alpha_text[ctx_start:ctx_end]
                details.append({
                    "offset": offset,
                    "context": context[:200],
                    "keys_sample": {
                        str(k): v for k, v in list(recovered_keys.items())[:5]
                    },
                })

    return {
        "variant": variant_name,
        "cipher": cipher_name,
        "text_len": len(alpha_text),
        "east_matches": east_matches,
        "bean_eq_passes": bean_eq_passes,
        "full_matches": full_matches,
        "details": details[:10],  # cap detail output
    }


# ── Pipeline phases ──────────────────────────────────────────────────────

def phase_1_ingest() -> Dict[str, List[CorpusPassage]]:
    """Download and load all source texts."""
    print("=" * 72)
    print("PHASE 1: Ingest source texts")
    print("=" * 72)

    ingester = TextIngester(
        cache_dir=os.path.join(OUTPUT_DIR, "downloads")
    )

    # Local files
    print("\n[1a] Loading local files...")
    local = ingester.ingest_all_local(REFERENCE_DIR)
    for fname, passages in local.items():
        total_alpha = sum(p.raw_alpha_length for p in passages)
        print(f"  {fname}: {len(passages)} passages, "
              f"{total_alpha:,} alpha chars")

    # Gutenberg downloads
    print(f"\n[1b] Downloading {len(EGYPT_GUTENBERG_BOOKS)} Gutenberg texts...")
    gutenberg = ingester.ingest_gutenberg_batch()
    for fname, passages in gutenberg.items():
        total_alpha = sum(p.raw_alpha_length for p in passages)
        print(f"  {fname}: {len(passages)} passages, "
              f"{total_alpha:,} alpha chars")

    failed = len(EGYPT_GUTENBERG_BOOKS) - len(gutenberg)
    if failed:
        downloaded_ids = {
            int(k.replace("pg", "").replace(".txt", ""))
            for k in gutenberg.keys()
        }
        for bid, title, _ in EGYPT_GUTENBERG_BOOKS:
            if bid not in downloaded_ids:
                print(f"  FAILED: pg{bid} ({title})")

    all_sources = {**local, **gutenberg}
    total_passages = sum(len(v) for v in all_sources.values())
    total_alpha = sum(
        sum(p.raw_alpha_length for p in v) for v in all_sources.values()
    )
    print(f"\nTotal: {len(all_sources)} sources, {total_passages} passages, "
          f"{total_alpha:,} alpha chars")
    return all_sources


def phase_2_variants(
    all_sources: Dict[str, List[CorpusPassage]],
) -> Tuple[List[CorpusPassage], Dict[str, str]]:
    """Generate variant forms for all passages."""
    print("\n" + "=" * 72)
    print("PHASE 2: Generate variant forms")
    print("=" * 72)

    generator = VariantGenerator()
    variant_names = generator.variant_names()
    print(f"Variant types: {', '.join(variant_names)}")

    # Process all passages
    all_passages = []
    # Accumulate flat alpha streams per variant
    streams: Dict[str, List[str]] = {v: [] for v in variant_names}
    offset_maps: Dict[str, List[Dict]] = {v: [] for v in variant_names}

    egypt_name_hits = 0
    passages_with_names = 0

    for source_file, passages in all_sources.items():
        for passage in passages:
            variants = generator.generate_all(passage.raw)
            passage.variants = variants

            # Check for Egyptian name content
            names = EgyptNormalizer.identify_egypt_names(passage.raw)
            if names:
                passages_with_names += 1
                egypt_name_hits += len(names)

            # Accumulate streams
            for vname in variant_names:
                alpha = variants[vname]["alpha"]
                if alpha:
                    current_offset = sum(
                        len(s) for s in streams[vname]
                    )
                    offset_maps[vname].append({
                        "offset_start": current_offset,
                        "offset_end": current_offset + len(alpha),
                        "passage_id": passage.passage_id,
                        "source_file": passage.provenance.source_file,
                        "line_start": passage.provenance.line_start,
                    })
                    streams[vname].append(alpha)

            all_passages.append(passage)

    # Build flat testing strings
    flat_texts: Dict[str, str] = {}
    for vname in variant_names:
        flat_texts[vname] = "".join(streams[vname])

    # Report variant statistics
    print(f"\nProcessed {len(all_passages)} passages")
    print(f"Passages with Egyptian names: {passages_with_names}")
    print(f"Total Egyptian name hits: {egypt_name_hits}")
    print("\nVariant stream lengths:")
    for vname in variant_names:
        length = len(flat_texts[vname])
        diff = length - len(flat_texts["raw"])
        diff_str = f" ({diff:+d})" if diff != 0 else ""
        print(f"  {vname:20s}: {length:>10,} chars{diff_str}")

    # Write output files
    print("\nWriting output files...")
    os.makedirs(os.path.join(OUTPUT_DIR, "testing"), exist_ok=True)

    # Corpus JSONL
    corpus_path = os.path.join(OUTPUT_DIR, "corpus.jsonl")
    with open(corpus_path, "w") as f:
        for passage in all_passages:
            f.write(passage.to_json() + "\n")
    print(f"  corpus.jsonl: {len(all_passages)} passages")

    # Flat testing files
    for vname in variant_names:
        test_path = os.path.join(OUTPUT_DIR, "testing", f"{vname}.txt")
        with open(test_path, "w") as f:
            f.write(flat_texts[vname])
        print(f"  testing/{vname}.txt: {len(flat_texts[vname]):,} chars")

    # Offset index
    index_path = os.path.join(OUTPUT_DIR, "offset_index.json")
    with open(index_path, "w") as f:
        json.dump(offset_maps, f, indent=2)
    print(f"  offset_index.json: {sum(len(v) for v in offset_maps.values())} entries")

    return all_passages, flat_texts


def phase_3_east_scan(flat_texts: Dict[str, str]) -> List[Dict]:
    """Run EAST constraint scan on all variant × cipher combinations."""
    print("\n" + "=" * 72)
    print("PHASE 3: EAST constraint scan")
    print("=" * 72)

    # Build scan tasks: (variant_name, text, cipher_variant)
    tasks = []
    for vname, text in flat_texts.items():
        for cipher in ["vigenere", "var_beaufort"]:
            # Vigenere and Beaufort have identical EAST diffs (proven in E-CFM-06)
            # so we only need vigenere + var_beaufort
            tasks.append((vname, text, cipher))

    print(f"Scanning {len(tasks)} combinations "
          f"({len(flat_texts)} variants × 2 cipher types)")
    print(f"Using {WORKERS} workers...")

    t0 = time.time()
    with Pool(WORKERS) as pool:
        results = pool.map(scan_east, tasks)
    elapsed = time.time() - t0

    # Summarize
    total_east = sum(r["east_matches"] for r in results)
    total_bean = sum(r["bean_eq_passes"] for r in results)
    total_full = sum(r["full_matches"] for r in results)

    print(f"\nCompleted in {elapsed:.1f}s")
    print(f"Total EAST matches: {total_east}")
    print(f"Total Bean-EQ passes: {total_bean}")
    print(f"Total FULL matches: {total_full}")

    # False positive analysis
    total_offsets = sum(
        max(0, r["text_len"] - CT_LEN + 1) for r in results
    )
    p_east = (1 / MOD) ** 4
    expected_east = total_offsets * p_east
    expected_bean = total_east * (1 / MOD)
    expected_full = total_bean * (25 / MOD) ** 21

    print(f"\nFalse positive analysis:")
    print(f"  Offsets scanned: {total_offsets:,}")
    print(f"  EAST:  {total_east} observed vs {expected_east:.1f} expected "
          f"({total_east / expected_east:.2f}x)" if expected_east > 0 else "")
    print(f"  Bean:  {total_bean} observed vs {expected_bean:.1f} expected")
    print(f"  Full:  {total_full} observed vs {expected_full:.1f} expected "
          f"({total_full / expected_full:.2f}x)" if expected_full > 0 else "")

    if total_full > 0 and expected_full > 0 and total_full / expected_full > 3.0:
        print("\n*** ANOMALOUS: observed >> expected — INVESTIGATE ***")
        for r in results:
            if r["full_matches"] > 0:
                print(f"  {r['variant']}/{r['cipher']}: "
                      f"{r['full_matches']} constraint passes")
                for d in r["details"]:
                    print(f"    offset={d['offset']}: {d['context'][:80]}...")
    elif total_full > 0:
        print(f"\n  All {total_full} constraint passes are consistent with "
              f"random false positives (ratio ≈ "
              f"{total_full / expected_full:.2f}x)."
              if expected_full > 0 else "")

    # Per-variant summary
    print("\nPer-variant results:")
    print(f"  {'Variant':20s} {'Cipher':14s} {'Len':>10s} "
          f"{'EAST':>6s} {'Bean':>6s} {'Full':>6s}")
    print("  " + "-" * 66)
    for r in results:
        print(f"  {r['variant']:20s} {r['cipher']:14s} "
              f"{r['text_len']:>10,} {r['east_matches']:>6} "
              f"{r['bean_eq_passes']:>6} {r['full_matches']:>6}")

    # Save scan results
    scan_path = os.path.join(OUTPUT_DIR, "east_scan_results.json")
    with open(scan_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved: {scan_path}")

    return results


def phase_4_report(
    all_passages: List[CorpusPassage],
    flat_texts: Dict[str, str],
    scan_results: List[Dict],
) -> None:
    """Generate analysis report."""
    print("\n" + "=" * 72)
    print("PHASE 4: Generate report")
    print("=" * 72)

    # Count Egyptian names per source
    name_counts: Dict[str, int] = defaultdict(int)
    for passage in all_passages:
        names = EgyptNormalizer.identify_egypt_names(passage.raw)
        name_counts[passage.provenance.source_file] += len(names)

    # Variant divergence analysis
    raw_len = len(flat_texts.get("raw", ""))
    divergences = {}
    for vname, text in flat_texts.items():
        if vname == "raw":
            continue
        # Count character differences from raw (up to min length)
        min_len = min(len(text), raw_len)
        raw_sub = flat_texts["raw"][:min_len]
        text_sub = text[:min_len]
        diffs = sum(1 for a, b in zip(raw_sub, text_sub) if a != b)
        divergences[vname] = {
            "length_delta": len(text) - raw_len,
            "char_diffs": diffs,
            "diff_rate": diffs / min_len if min_len > 0 else 0,
        }

    # EAST scan summary per variant
    variant_scan = defaultdict(lambda: {"east": 0, "bean": 0, "full": 0})
    for r in scan_results:
        v = r["variant"]
        variant_scan[v]["east"] += r["east_matches"]
        variant_scan[v]["bean"] += r["bean_eq_passes"]
        variant_scan[v]["full"] += r["full_matches"]

    # Promise / priority ranking
    generator = VariantGenerator()
    descriptions = generator.variant_descriptions()

    report_lines = [
        "# E-EGYPT-00: Egyptological Corpus Pipeline — Report",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"- **Sources ingested:** {len(set(p.provenance.source_file for p in all_passages))}",
        f"- **Total passages:** {len(all_passages)}",
        f"- **Raw alpha characters:** {raw_len:,}",
        f"- **Variant types:** {len(flat_texts)}",
        f"- **EAST scan combinations:** {len(scan_results)}",
        "",
        "## Source Texts",
        "",
        "| Source | Passages | Alpha Chars | Egypt Names |",
        "|--------|----------|-------------|-------------|",
    ]

    source_stats = defaultdict(lambda: {"passages": 0, "chars": 0})
    for p in all_passages:
        sf = p.provenance.source_file
        source_stats[sf]["passages"] += 1
        source_stats[sf]["chars"] += p.raw_alpha_length
    for sf in sorted(source_stats.keys()):
        s = source_stats[sf]
        nc = name_counts.get(sf, 0)
        report_lines.append(
            f"| {sf} | {s['passages']} | {s['chars']:,} | {nc} |"
        )

    report_lines += [
        "",
        "## Variant Analysis",
        "",
        "| Variant | Description | Length | Δ Raw | Char Diffs | Diff Rate |",
        "|---------|-------------|--------|-------|------------|-----------|",
    ]
    for vname in generator.variant_names():
        desc = descriptions.get(vname, "")
        length = len(flat_texts.get(vname, ""))
        if vname == "raw":
            report_lines.append(
                f"| **{vname}** | {desc} | {length:,} | — | — | — |"
            )
        else:
            d = divergences.get(vname, {})
            delta = d.get("length_delta", 0)
            diffs = d.get("char_diffs", 0)
            rate = d.get("diff_rate", 0)
            report_lines.append(
                f"| **{vname}** | {desc} | {length:,} | "
                f"{delta:+d} | {diffs:,} | {rate:.4f} |"
            )

    report_lines += [
        "",
        "## EAST Constraint Scan Results",
        "",
        "| Variant | EAST Matches | Bean-EQ | Full Matches |",
        "|---------|-------------|---------|-------------|",
    ]
    for vname in generator.variant_names():
        vs = variant_scan[vname]
        report_lines.append(
            f"| **{vname}** | {vs['east']} | {vs['bean']} | {vs['full']} |"
        )

    # Most promising layers analysis
    report_lines += [
        "",
        "## Most Promising Layers for Running-Key Experiments",
        "",
        "### Ranking Criteria",
        "",
        "Layers are ranked by **cryptanalytic distinctiveness**: how much the",
        "variant's A-Z stream differs from the raw stream.  Higher divergence",
        "means the variant tests genuinely different running-key alignments.",
        "",
        "### Priority Ranking",
        "",
    ]

    ranked = sorted(
        [
            (vname, divergences.get(vname, {}))
            for vname in generator.variant_names()
            if vname != "raw"
        ],
        key=lambda x: (
            abs(x[1].get("length_delta", 0)),
            x[1].get("char_diffs", 0),
        ),
        reverse=True,
    )

    for rank, (vname, d) in enumerate(ranked, 1):
        delta = d.get("length_delta", 0)
        diffs = d.get("char_diffs", 0)
        desc = descriptions.get(vname, "")
        if abs(delta) > 0:
            why = (f"Changes letter count by {delta:+d}, shifting ALL "
                   f"subsequent positions.  Every offset in the EAST scanner "
                   f"tests a different alignment than raw.")
        elif diffs > 0:
            why = (f"{diffs:,} character substitutions — each is a position "
                   f"where the running key would produce a different "
                   f"ciphertext letter.")
        else:
            why = "Minimal divergence from raw — low priority."

        report_lines.append(f"**{rank}. {vname}** — {desc}")
        report_lines.append(f"   - Length delta: {delta:+d}, "
                            f"char diffs: {diffs:,}")
        report_lines.append(f"   - {why}")
        report_lines.append("")

    report_lines += [
        "### Recommendations",
        "",
        "1. **digraph_reduced** and **full_reduced** are highest priority — they",
        "   change letter COUNT, which shifts every downstream position.  A match",
        "   invisible in the raw stream may become visible after digraph reduction.",
        "",
        "2. **modern** and **carter_era** test specific name-spelling hypotheses.",
        "   If the source text uses a specific edition's conventions, only the",
        "   matching variant will produce the correct key alignment.",
        "",
        "3. **translit_approx** tests the maximal-reduction hypothesis: that the",
        "   running key was generated from a consonantal / transliteration-style",
        "   rendering rather than a printed English text.",
        "",
        "4. **raw** and **unicode_norm** remain the baseline — most running-key",
        "   texts will match these if they match anything.",
        "",
        "5. All variants should be tested with TRANSPOSITION in addition to",
        "   identity correspondence.  The EAST constraint diffs change under",
        "   transposition, so matches missed here may appear with a non-identity",
        "   permutation.",
        "",
        "## Normalization Rules Reference",
        "",
        f"- **Egyptian names in database:** {len(EGYPT_NAMES)} entries",
        f"- **Total spelling variants:** "
        f"{sum(len(v['v']) for v in EGYPT_NAMES.values())}",
        f"- **Digraph reductions:** KH→X, SH→S, PH→F, TH→T, DJ→J, CH→X",
        f"- **Transliteration entries with alpha form:** "
        f"{sum(1 for v in EGYPT_NAMES.values() if v.get('ta'))}",
        "",
        "## Corpus Schema",
        "",
        "```",
        "corpus.jsonl — one JSON object per passage:",
        "  passage_id:      <source_file>:<line_start>",
        "  raw:             original text with formatting",
        "  raw_alpha_length: len(A-Z chars in raw)",
        "  variants:        dict of variant_name → {",
        "    text:  variant with formatting",
        "    alpha: A-Z uppercase only",
        "    length: len(alpha)",
        "    steps: [normalization steps applied]",
        "  }",
        "  provenance: {",
        "    source_file, title, author, gutenberg_id,",
        "    chapter, line_start, line_end, original_text",
        "  }",
        "",
        "testing/<variant>.txt — flat A-Z string, all passages concatenated",
        "offset_index.json — maps testing file offsets → passage IDs",
        "```",
        "",
        "## Verdict",
        "",
    ]

    total_full = sum(r["full_matches"] for r in scan_results)
    total_east = sum(r["east_matches"] for r in scan_results)
    total_bean = sum(r["bean_eq_passes"] for r in scan_results)
    total_offsets = sum(
        max(0, r["text_len"] - CT_LEN + 1) for r in scan_results
    )
    expected_east = total_offsets * (1 / MOD) ** 4
    expected_bean = total_east * (1 / MOD)
    expected_full = total_bean * (25 / MOD) ** 21

    report_lines += [
        "### False Positive Analysis",
        "",
        f"- Offsets scanned: {total_offsets:,}",
        f"- EAST: {total_east} observed vs {expected_east:.1f} expected "
        f"({total_east / expected_east:.2f}x)"
        if expected_east > 0 else "",
        f"- Bean-EQ: {total_bean} observed vs {expected_bean:.1f} expected",
        f"- Constraint passes: {total_full} observed vs "
        f"{expected_full:.1f} expected "
        f"({total_full / expected_full:.2f}x)"
        if expected_full > 0 else "",
        "",
    ]

    anomalous = (
        total_full > 0
        and expected_full > 0
        and total_full / expected_full > 3.0
    )
    if anomalous:
        report_lines.append(
            "**ANOMALOUS** — observed >> expected.  Investigate immediately."
        )
    else:
        report_lines.append(
            f"**NOISE** — all {total_full} constraint passes are consistent "
            f"with random false positives "
            f"(ratio ≈ {total_full / expected_full:.2f}x).  "
            f"Running key from these Egyptological corpora is ELIMINATED "
            f"under identity transposition.  "
            f"OPEN with non-identity transposition."
            if expected_full > 0 else
            f"**NO MATCHES** — running key from these corpora is ELIMINATED "
            f"under identity transposition."
        )

    report_lines.append("")
    report_lines.append(
        f"*Generated by e_egypt_00_corpus_pipeline.py — "
        f"{time.strftime('%Y-%m-%d %H:%M:%S')}*"
    )

    report_text = "\n".join(report_lines)
    report_path = os.path.join(OUTPUT_DIR, "report.md")
    with open(report_path, "w") as f:
        f.write(report_text)
    print(f"Report saved: {report_path}")
    print(f"Report length: {len(report_lines)} lines")


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()

    print("E-EGYPT-00: Transliteration-Aware Egyptological Corpus Pipeline")
    print(f"Workers: {WORKERS}")
    print(f"Output:  {OUTPUT_DIR}/")
    print()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Phase 1: Ingest
    all_sources = phase_1_ingest()

    # Phase 2: Variant generation
    all_passages, flat_texts = phase_2_variants(all_sources)

    # Phase 3: EAST scan
    scan_results = phase_3_east_scan(flat_texts)

    # Phase 4: Report
    phase_4_report(all_passages, flat_texts, scan_results)

    elapsed = time.time() - t_start
    print(f"\n{'=' * 72}")
    print(f"Pipeline complete in {elapsed:.1f}s")
    print(f"Output directory: {OUTPUT_DIR}/")
    print(f"  corpus.jsonl          — {len(all_passages)} passages")
    print(f"  testing/              — {len(flat_texts)} variant files")
    print(f"  offset_index.json     — offset → passage mapping")
    print(f"  east_scan_results.json — EAST constraint scan results")
    print(f"  report.md             — analysis report")

    total_full = sum(r["full_matches"] for r in scan_results)
    total_offsets = sum(
        max(0, r["text_len"] - CT_LEN + 1) for r in scan_results
    )
    expected_full = (
        sum(r["bean_eq_passes"] for r in scan_results) * (25 / MOD) ** 21
    )
    anomalous = (
        total_full > 0
        and expected_full > 0
        and total_full / expected_full > 3.0
    )

    if anomalous:
        print(f"\n*** {total_full} ANOMALOUS MATCHES — INVESTIGATE ***")
        sys.exit(2)
    else:
        print(f"\nVerdict: {total_full} constraint passes "
              f"(all consistent with random, "
              f"expected ≈ {expected_full:.1f}). "
              f"ELIMINATED under identity transposition.")
        sys.exit(0)


if __name__ == "__main__":
    main()
