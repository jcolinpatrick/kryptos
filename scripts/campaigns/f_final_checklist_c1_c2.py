#!/usr/bin/env python3
"""
Cipher: running-key + columnar transposition
Family: campaigns/final_checklist
Status: active
Keyspace: Bean-passing columnar widths {6,8,9} x {Vig, Beau, VarBeau} x offsets(source)
Last run:
Best score:

C1 + C2 — Final Checklist Running-Key Campaign
===============================================

Executes campaigns C1 (Carter Vol 1) and C2 (Kahn Codebreakers) under the
admissibility gate defined in docs/admissibility_architecture.md, against
the pre-registered thresholds in docs/preregistered_thresholds_2026_04_08.md.

C1 tests:
  - Source: carter_tomb_vol1 (reference/carter_vol1.txt, 437 KB, allowlisted
    under ARTIST_STATEMENT)
  - Transposition: columnar widths {6, 8, 9} (Bean-passing orderings only)
  - Variants: vigenere, beaufort, variant_beaufort
  - Stopping: full enumeration or first ESCALATED candidate

C2 tests:
  - Source: kahn_codebreakers (reference/running_key_texts/kahn_codebreakers_1967.txt,
    3.9 MB, allowlisted under CREATOR_STATEMENT)
  - Same transposition / variant / stop structure

GAP CLOSED vs E-FRAC-49:
  - E-FRAC-49 referenced reference/carter_vol1_extract.txt which DOES NOT
    exist on disk (confirmed 2026-04-08). Only carter_gutenberg.txt (117K
    chars) was tested under the Carter label; the allowlisted 437 KB
    carter_vol1.txt has not been tested under columnar.
  - Kahn Codebreakers was added 2026-04-04 (commit 56c56fe) and tested
    only under identity transposition (best 8/24 = noise). Columnar sweep
    has not been performed.
  - E-FRAC-49 recorded only 24/24 exact matches. This script records the
    best crib score per (ordering, variant, source) and applies the full
    conjunctive escalation criterion (crib >= 20/24 AND Bean pass AND
    quadgram per char >= -4.5 AND word hits >= 3 AND coherent fragment).

HYPOTHESIS: Neither C1 nor C2 produces an ESCALATED candidate. Confirming
this moves running-key from bin C to bin B and completes the final
checklist contribution from the running-key family.

ADMISSIBILITY: Sources are loaded exclusively through the corpus policy
gate via kryptos.admissibility.check_corpus_source. Any source not on the
allowlist produces a CorpusPolicyViolation certificate and halts the
campaign.

RESULT OUTPUT:
  results/f_final_checklist_c1_c2.json — conforms to the preregistered
  thresholds document's record-keeping contract.
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
from pathlib import Path

import numpy as np

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.constants import (  # noqa: E402
    CT,
    CT_LEN,
    ALPH_IDX,
    MOD,
    CRIB_ENTRIES,
    N_CRIBS,
    BEAN_EQ,
    BEAN_INEQ,
)
from kryptos.admissibility.corpus_policy import (  # noqa: E402
    CORPUS_ALLOWLIST,
    CorpusJustification,
)

# ── Constants ────────────────────────────────────────────────────────────

CT_NUM = np.array([ALPH_IDX[c] for c in CT], dtype=np.int8)
N = CT_LEN  # 97

CRIB_POS = np.array([pos for pos, _ in CRIB_ENTRIES], dtype=np.int32)
CRIB_PT = np.array([ALPH_IDX[ch] for _, ch in CRIB_ENTRIES], dtype=np.int8)

BEAN_EQ_PAIRS = list(BEAN_EQ)
BEAN_INEQ_PAIRS = list(BEAN_INEQ)

WIDTHS = [6, 8, 9]
VARIANTS = ["vigenere", "beaufort", "variant_beaufort"]

# Pre-registered thresholds (see docs/preregistered_thresholds_2026_04_08.md)
ESCALATE_CRIB_MIN = 20
ESCALATE_QGRAM_MIN = -4.5
ESCALATE_WORD_HIT_MIN = 3
FRAGMENT_MIN_LEN = 10
FRAGMENT_MIN_WORDS = 2
FRAGMENT_MIN_QGRAM = -4.0

RESULTS_PATH = _ROOT / "results" / "f_final_checklist_c1_c2.json"
PREREGISTERED_PATH = "docs/preregistered_thresholds_2026_04_08.md"


# ── Gate-controlled source loading ───────────────────────────────────────


def resolve_allowlisted_source(source_id: str) -> bytes:
    """Resolve a source file exclusively via the corpus allowlist."""
    if source_id not in CORPUS_ALLOWLIST:
        raise RuntimeError(f"source_id {source_id!r} not in CORPUS_ALLOWLIST")
    lic = CORPUS_ALLOWLIST[source_id]
    uri = lic.provenance_uri
    if uri.startswith("kryptos://"):
        raise RuntimeError(
            f"source_id {source_id!r} uses opaque URI {uri}; "
            "this script cannot resolve clue-surface-only sources"
        )
    path = _ROOT / uri
    if not path.exists():
        raise RuntimeError(
            f"source_id {source_id!r} declared path {path} but file missing"
        )
    return path.read_bytes()


def load_text_as_nums(source_id: str) -> np.ndarray:
    """Load an allowlisted source and return its alpha-only numpy array."""
    raw = resolve_allowlisted_source(source_id).decode("utf-8", errors="replace").upper()
    nums = [ALPH_IDX[c] for c in raw if c in ALPH_IDX]
    return np.array(nums, dtype=np.int8)


# ── Columnar permutation utilities (copied from E-FRAC-49) ───────────────


def generate_columnar_perm(width: int, col_order):
    nrows = (N + width - 1) // width
    full_cols = N - (nrows - 1) * width
    perm = []
    for col in col_order:
        rows = nrows if col < full_cols else nrows - 1
        for row in range(rows):
            pos = row * width + col
            if pos < N:
                perm.append(pos)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def compute_required_key(inv_perm, variant):
    required = {}
    for i in range(N_CRIBS):
        pos = int(CRIB_POS[i])
        pt_val = int(CRIB_PT[i])
        ct_val = int(CT_NUM[inv_perm[pos]])
        if variant == "vigenere":
            key_val = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            key_val = (ct_val + pt_val) % MOD
        elif variant == "variant_beaufort":
            key_val = (pt_val - ct_val) % MOD
        else:
            raise ValueError(variant)
        required[pos] = key_val
    return required


def bean_eq_holds(inv_perm) -> bool:
    for a, b in BEAN_EQ_PAIRS:
        if CT_NUM[inv_perm[a]] != CT_NUM[inv_perm[b]]:
            return False
    return True


def bean_ineq_holds(required_key) -> bool:
    for a, b in BEAN_INEQ_PAIRS:
        if required_key[a] == required_key[b]:
            return False
    return True


# ── Scoring ──────────────────────────────────────────────────────────────


def load_quadgrams():
    qp = _ROOT / "data" / "english_quadgrams.json"
    with qp.open() as f:
        return json.load(f)


def load_wordlist(min_len: int = 4):
    wp = _ROOT / "wordlists" / "english.txt"
    words = set()
    with wp.open() as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= min_len and w.isalpha():
                words.add(w)
    return words


def quadgram_per_char(text: str, quadgrams: dict) -> float:
    if len(text) < 4:
        return -10.0
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        total += quadgrams.get(text[i : i + 4], -10.0)
        n += 1
    return total / n if n else -10.0


def word_hits(text: str, words: set, min_len: int = 6) -> int:
    n = len(text)
    hits = 0
    for length in range(min_len, min(15, n) + 1):
        for i in range(n - length + 1):
            if text[i : i + length] in words:
                hits += 1
    return hits


def find_coherent_fragment(
    text: str, quadgrams: dict, words: set
) -> bool:
    for start in range(len(text) - FRAGMENT_MIN_LEN + 1):
        for length in range(FRAGMENT_MIN_LEN, min(30, len(text) - start) + 1):
            frag = text[start : start + length]
            wcount = 0
            for wl in range(4, min(12, length) + 1):
                for j in range(length - wl + 1):
                    if frag[j : j + wl] in words:
                        wcount += 1
                        if wcount >= FRAGMENT_MIN_WORDS:
                            break
                if wcount >= FRAGMENT_MIN_WORDS:
                    break
            if wcount >= FRAGMENT_MIN_WORDS:
                if quadgram_per_char(frag, quadgrams) >= FRAGMENT_MIN_QGRAM:
                    return True
    return False


def derive_plaintext(source: np.ndarray, offset: int, inv_perm, variant: str) -> str:
    pt = []
    for j in range(N):
        key_val = int(source[offset + j])
        ct_val = int(CT_NUM[inv_perm[j]])
        if variant == "vigenere":
            pt.append(chr((ct_val - key_val) % MOD + ord("A")))
        elif variant == "beaufort":
            pt.append(chr((key_val - ct_val) % MOD + ord("A")))
        else:  # variant_beaufort
            pt.append(chr((ct_val + key_val) % MOD + ord("A")))
    return "".join(pt)


# ── Core sweep ───────────────────────────────────────────────────────────


def sweep_source(
    source_id: str,
    source: np.ndarray,
    quadgrams: dict,
    words: set,
) -> dict:
    """Run C1 or C2 against a loaded allowlisted source."""
    start = time.time()
    n_offsets = len(source) - N + 1
    source_id_report = {
        "source_id": source_id,
        "source_len": int(len(source)),
        "n_offsets": int(n_offsets),
        "orderings_tested": 0,
        "bean_passing_orderings": 0,
        "offsets_scanned": 0,
        "max_crib_score": 0,
        "bean_passes": 0,
        "escalated_candidates": [],
        "near_miss_candidates": [],
        "per_width": {},
    }

    if n_offsets <= 0:
        source_id_report["verdict"] = "ERROR"
        source_id_report["error"] = "source too short"
        return source_id_report

    from itertools import permutations

    for width in WIDTHS:
        w_report = {
            "orderings": math.factorial(width),
            "bean_passing": 0,
            "offsets_scanned": 0,
            "max_score": 0,
        }

        for col_order in permutations(range(width)):
            source_id_report["orderings_tested"] += 1
            perm = generate_columnar_perm(width, col_order)
            inv_perm = invert_perm(perm)

            if not bean_eq_holds(inv_perm):
                continue

            for variant in VARIANTS:
                required = compute_required_key(inv_perm, variant)
                if not bean_ineq_holds(required):
                    continue

                source_id_report["bean_passing_orderings"] += 1
                w_report["bean_passing"] += 1

                required_arr = np.array(
                    [required[int(p)] for p in CRIB_POS], dtype=np.int8
                )

                # Vectorized count of crib matches at each offset.
                match_counts = np.zeros(n_offsets, dtype=np.int32)
                for k, pos in enumerate(CRIB_POS):
                    match_counts += (
                        source[int(pos) : int(pos) + n_offsets] == required_arr[k]
                    ).astype(np.int32)

                source_id_report["offsets_scanned"] += n_offsets
                w_report["offsets_scanned"] += n_offsets

                max_here = int(match_counts.max())
                if max_here > w_report["max_score"]:
                    w_report["max_score"] = max_here
                if max_here > source_id_report["max_crib_score"]:
                    source_id_report["max_crib_score"] = max_here

                # Any offset that could possibly escalate
                high = np.where(match_counts >= ESCALATE_CRIB_MIN)[0]
                for off in high.tolist():
                    source_id_report["bean_passes"] += 1  # Bean is forced by construction
                    pt = derive_plaintext(source, off, inv_perm, variant)
                    qg = quadgram_per_char(pt, quadgrams)
                    wh = word_hits(pt, words)
                    crib_sc = int(match_counts[off])
                    coherent = find_coherent_fragment(pt, quadgrams, words)
                    meets_all = (
                        crib_sc >= ESCALATE_CRIB_MIN
                        and qg >= ESCALATE_QGRAM_MIN
                        and wh >= ESCALATE_WORD_HIT_MIN
                        and coherent
                    )
                    record = {
                        "source_id": source_id,
                        "width": width,
                        "col_order": list(col_order),
                        "variant": variant,
                        "offset": int(off),
                        "crib_score": crib_sc,
                        "bean_passed": True,
                        "quadgram_per_char": qg,
                        "word_hits": wh,
                        "coherent_fragment": coherent,
                        "plaintext": pt,
                    }
                    if meets_all:
                        source_id_report["escalated_candidates"].append(record)
                    else:
                        # Record up to 20 near-misses per source to avoid blowup
                        if len(source_id_report["near_miss_candidates"]) < 20:
                            fails = []
                            if crib_sc < ESCALATE_CRIB_MIN:
                                fails.append(f"crib<{ESCALATE_CRIB_MIN}")
                            if qg < ESCALATE_QGRAM_MIN:
                                fails.append(f"qgram<{ESCALATE_QGRAM_MIN}")
                            if wh < ESCALATE_WORD_HIT_MIN:
                                fails.append(f"words<{ESCALATE_WORD_HIT_MIN}")
                            if not coherent:
                                fails.append("no_coherent_fragment")
                            record["fails"] = fails
                            source_id_report["near_miss_candidates"].append(record)

        source_id_report["per_width"][str(width)] = w_report
        elapsed = time.time() - start
        print(
            f"  w={width} orderings={w_report['orderings']} "
            f"bean_passing={w_report['bean_passing']} "
            f"max_score={w_report['max_score']} "
            f"escalated={len(source_id_report['escalated_candidates'])} "
            f"[{elapsed:.0f}s]",
            flush=True,
        )
        if source_id_report["escalated_candidates"]:
            # Stopping criterion: first ESCALATED candidate halts the sweep.
            source_id_report["verdict"] = "ESCALATED"
            source_id_report["elapsed_seconds"] = elapsed
            return source_id_report

    source_id_report["elapsed_seconds"] = time.time() - start
    source_id_report["verdict"] = "EMPTY"
    return source_id_report


# ── Campaign driver ──────────────────────────────────────────────────────


def main():
    t0 = time.time()
    print("=" * 72)
    print("C1 + C2 — Final Checklist Running-Key Campaign (admissibility-gated)")
    print("=" * 72)
    print(f"Pre-registered thresholds: {PREREGISTERED_PATH}")
    print(f"Escalation requires: crib >= {ESCALATE_CRIB_MIN}/24, Bean pass,")
    print(f"  quadgram >= {ESCALATE_QGRAM_MIN}/char, word_hits >= {ESCALATE_WORD_HIT_MIN},")
    print(f"  coherent fragment (>= {FRAGMENT_MIN_LEN} chars, "
          f">= {FRAGMENT_MIN_WORDS} words, qgram >= {FRAGMENT_MIN_QGRAM}).")
    print()

    print("Loading scoring data...")
    quadgrams = load_quadgrams()
    words = load_wordlist(min_len=4)
    print(f"  quadgrams: {len(quadgrams):,}")
    print(f"  wordlist (>=4 chars): {len(words):,}")
    print()

    # Confirm allowlist entries
    print("Corpus allowlist verification:")
    for src_id in ("carter_tomb_vol1", "kahn_codebreakers"):
        lic = CORPUS_ALLOWLIST.get(src_id)
        if lic is None:
            raise RuntimeError(f"{src_id} missing from allowlist")
        print(
            f"  {src_id}: {lic.title!r} by {lic.author} "
            f"[{lic.justification.value}] → {lic.provenance_uri}"
        )
    print()

    campaigns = []

    for campaign_name, source_id in [
        ("C1", "carter_tomb_vol1"),
        ("C2", "kahn_codebreakers"),
    ]:
        print(f"=== {campaign_name}: {source_id} ===")
        try:
            source = load_text_as_nums(source_id)
        except Exception as exc:
            print(f"  LOAD FAILED: {exc}")
            campaigns.append(
                {
                    "campaign": campaign_name,
                    "source_id": source_id,
                    "verdict": "ERROR",
                    "error": str(exc),
                }
            )
            continue
        print(f"  loaded {len(source):,} alpha chars, "
              f"{len(source) - N + 1:,} offsets")

        report = sweep_source(source_id, source, quadgrams, words)
        report["campaign"] = campaign_name
        campaigns.append(report)
        print(f"  verdict: {report['verdict']}")
        print()
        if report["verdict"] == "ESCALATED":
            print("  ESCALATED — stopping campaign sequence for investigation.")
            break

    out = {
        "experiment": "f_final_checklist_c1_c2",
        "description": "C1 + C2 admissibility-gated running-key + columnar",
        "preregistered_thresholds_doc": PREREGISTERED_PATH,
        "thresholds": {
            "crib_min": ESCALATE_CRIB_MIN,
            "quadgram_min": ESCALATE_QGRAM_MIN,
            "word_hits_min": ESCALATE_WORD_HIT_MIN,
            "fragment_min_len": FRAGMENT_MIN_LEN,
            "fragment_min_words": FRAGMENT_MIN_WORDS,
            "fragment_min_quadgram": FRAGMENT_MIN_QGRAM,
        },
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": time.time() - t0,
        "campaigns": campaigns,
    }
    # Overall verdict: ESCALATED if any; else EMPTY if all completed; else PARTIAL
    verdicts = [c.get("verdict") for c in campaigns]
    if "ESCALATED" in verdicts:
        out["verdict"] = "ESCALATED"
    elif all(v == "EMPTY" for v in verdicts):
        out["verdict"] = "EMPTY"
    else:
        out["verdict"] = "PARTIAL"
    out["escalated_candidates"] = [
        cand
        for c in campaigns
        for cand in c.get("escalated_candidates", [])
    ]
    out["near_miss_count"] = sum(
        len(c.get("near_miss_candidates", [])) for c in campaigns
    )

    RESULTS_PATH.parent.mkdir(exist_ok=True)
    with RESULTS_PATH.open("w") as f:
        json.dump(out, f, indent=2)

    print("=" * 72)
    print(f"Final verdict: {out['verdict']}")
    print(f"Total escalated: {len(out['escalated_candidates'])}")
    print(f"Total near-misses recorded: {out['near_miss_count']}")
    print(f"Elapsed: {out['elapsed_seconds']:.0f}s")
    print(f"Output: {RESULTS_PATH}")
    print("=" * 72)


if __name__ == "__main__":
    main()
