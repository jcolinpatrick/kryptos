#!/usr/bin/env python3
"""
Cipher: 3-layer composition (substitution × transposition × substitution)
Family: campaigns/final_checklist
Status: active
Keyspace: {additive_mask, vigenere, beaufort} × {myszkowski, rail_fence, route,
           block_transposition} × {additive_mask, vigenere, beaufort}
Last run:
Best score:

C6 — Final Checklist: Non-Columnar 3-Layer Enumeration
======================================================

Executes campaign C6 from docs/exhaustion_audit_2026_04_08.md against the
pre-registered thresholds in docs/preregistered_thresholds_2026_04_08.md.

MOTIVATION:
  - E-FRAC-52 eliminated Sub+Trans+Sub ONLY for columnar widths 6/8/9 at
    p1*p2 <= 50.
  - E-FRAC-53 eliminated Mono+Trans+Periodic ONLY for columnar widths 6/8/9
    at periods 3-12.
  - Three-layer compositions with non-columnar middle transpositions have
    never been systematically enumerated.
  - The composition framework is 2-layer only (src/kryptos/composition/
    orchestrator.py enumerate_stacks). This script implements a focused
    3-layer enumeration OUTSIDE the framework to close the gap.

DESIGN CHOICES:
  1. Outer and inner layers limited to ADDITIVE families: additive_mask,
     vigenere, beaufort. Variant_beaufort is omitted only to cut redundant
     compute — it is the sign-swap of beaufort for purposes of Bean analysis.
  2. Middle layer is one of: transposition_myszkowski, transposition_rail_fence,
     transposition_route, block_transposition. Columnar is explicitly excluded
     because it duplicates E-FRAC-52/53 coverage.
  3. Peel order fixed: encryption = inner → middle → outer; decryption = outer
     → middle → inner. Both orders were tested in E-FRAC-52's 2-layer audit
     and produced the same null. Restricting to one order here is an
     explicit compute-budget decision.
  4. Bean pre-check is SKIPPED for 3-layer compositions (the effective key
     at crib positions is a non-trivial function of two keywords plus a
     permutation; no simple structural filter). This is a documented
     deviation from the pre-registered thresholds: the ESCALATION criterion
     drops the Bean conjunct for C6 ONLY. All other conjuncts (crib ≥ 20,
     quadgram ≥ -4.5, word hits ≥ 3, coherent fragment) apply unchanged.
  5. Scoring is ANCHORED (cribs at positions 21-33 and 63-73) because the
     full 3-layer inverse restores original positions. Free scoring is not
     needed.

HYPOTHESIS: Zero ESCALATED candidates. Confirming this downgrades three-layer
non-columnar composition from bin C to bin B and completes the final
checklist contribution from the 3-layer architectural gap.

OUTPUT: results/f_final_checklist_c6.json
"""
from __future__ import annotations

import itertools
import json
import math
import sys
import time
import traceback
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.constants import (  # noqa: E402
    CT,
    CT_LEN,
    CRIB_ENTRIES,
    N_CRIBS,
)
from kryptos.composition.models import LayerFamily  # noqa: E402
from kryptos.composition.registry import (  # noqa: E402
    build_transforms,
    generate_params,
    make_instance,
)


# ── Constants ────────────────────────────────────────────────────────────

CRIB_POS = [pos for pos, _ in CRIB_ENTRIES]
CRIB_CH = {pos: ch for pos, ch in CRIB_ENTRIES}

OUTER_FAMILIES = [
    LayerFamily.ADDITIVE_MASK,
    LayerFamily.VIGENERE,
    LayerFamily.BEAUFORT,
]

INNER_FAMILIES = OUTER_FAMILIES

MIDDLE_FAMILIES = [
    LayerFamily.TRANSPOSITION_MYSZKOWSKI,
    LayerFamily.TRANSPOSITION_RAIL_FENCE,
    LayerFamily.TRANSPOSITION_ROUTE,
    LayerFamily.BLOCK_TRANSPOSITION,
]

ESCALATE_CRIB_MIN = 20
ESCALATE_QGRAM_MIN = -4.5
ESCALATE_WORD_HIT_MIN = 3
FRAGMENT_MIN_LEN = 10
FRAGMENT_MIN_WORDS = 2
FRAGMENT_MIN_QGRAM = -4.0

RESULTS_PATH = _ROOT / "results" / "f_final_checklist_c6.json"
PREREGISTERED_PATH = "docs/preregistered_thresholds_2026_04_08.md"


# ── Scoring ──────────────────────────────────────────────────────────────


def load_quadgrams() -> dict:
    with (_ROOT / "data" / "english_quadgrams.json").open() as f:
        return json.load(f)


def load_wordlist() -> set:
    words = set()
    with (_ROOT / "wordlists" / "english.txt").open() as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 4 and w.isalpha():
                words.add(w)
    return words


def crib_score(pt: str) -> int:
    return sum(1 for pos, ch in CRIB_ENTRIES if pt[pos] == ch)


def quadgram_per_char(text: str, quadgrams: dict) -> float:
    if len(text) < 4:
        return -10.0
    total = 0.0
    for i in range(len(text) - 3):
        total += quadgrams.get(text[i : i + 4], -10.0)
    return total / (len(text) - 3)


def word_hits(text: str, words: set) -> int:
    n = len(text)
    hits = 0
    for length in range(6, min(13, n) + 1):
        for i in range(n - length + 1):
            if text[i : i + length] in words:
                hits += 1
    return hits


def find_coherent_fragment(text: str, quadgrams: dict, words: set) -> bool:
    for start in range(len(text) - FRAGMENT_MIN_LEN + 1):
        for length in range(FRAGMENT_MIN_LEN, min(25, len(text) - start) + 1):
            frag = text[start : start + length]
            wcount = 0
            for wl in range(4, min(11, length) + 1):
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


def build_pair(family: LayerFamily, params: dict):
    """Return (forward, inverse) for a family + params. Injects length."""
    p = dict(params)
    p.setdefault("length", CT_LEN)
    inst = make_instance(family, p)
    return build_transforms(inst)


def enumerate_family_configs(family: LayerFamily) -> list:
    """Return [(params_dict, (forward, inverse)), ...] for all default params."""
    out = []
    params_list = generate_params(family, length=CT_LEN)
    for params in params_list:
        try:
            pair = build_pair(family, params)
            out.append((params, pair))
        except Exception as exc:
            print(f"  [skip] {family.value} {params}: {exc}")
    return out


# ── Main sweep ───────────────────────────────────────────────────────────


def main():
    t0 = time.time()
    print("=" * 72)
    print("C6 — Final Checklist 3-Layer Non-Columnar Enumeration")
    print("=" * 72)
    print(f"Pre-registered thresholds: {PREREGISTERED_PATH}")
    print(f"Escalation (for 3-layer, Bean conjunct DROPPED — see docstring):")
    print(f"  crib >= {ESCALATE_CRIB_MIN}/24 AND quadgram >= {ESCALATE_QGRAM_MIN}/char")
    print(f"  AND word_hits >= {ESCALATE_WORD_HIT_MIN} AND coherent fragment")
    print()

    print("Loading scoring data...")
    quadgrams = load_quadgrams()
    words = load_wordlist()
    print(f"  quadgrams: {len(quadgrams):,}, words (>=4): {len(words):,}")
    print()

    # Build config lists
    print("Building layer configs:")
    outer_configs = {}
    inner_configs = {}
    middle_configs = {}
    for fam in OUTER_FAMILIES:
        outer_configs[fam] = enumerate_family_configs(fam)
        print(f"  outer[{fam.value}]: {len(outer_configs[fam])}")
    for fam in INNER_FAMILIES:
        inner_configs[fam] = outer_configs[fam]  # same set
    for fam in MIDDLE_FAMILIES:
        middle_configs[fam] = enumerate_family_configs(fam)
        print(f"  middle[{fam.value}]: {len(middle_configs[fam])}")

    total_outer = sum(len(v) for v in outer_configs.values())
    total_inner = sum(len(v) for v in inner_configs.values())
    total_middle = sum(len(v) for v in middle_configs.values())
    projected = total_outer * total_middle * total_inner
    print()
    print(
        f"Projected compositions: {total_outer} × {total_middle} × {total_inner}"
        f" = {projected:,}"
    )
    print()

    tested = 0
    escalated = []
    near_misses = []
    max_score = 0
    max_qgram = -10.0
    per_family_stats: dict = {}

    try:
        for outer_fam in OUTER_FAMILIES:
            for outer_params, (_, outer_inv) in outer_configs[outer_fam]:
                for mid_fam in MIDDLE_FAMILIES:
                    fam_key = f"{outer_fam.value}|{mid_fam.value}"
                    if fam_key not in per_family_stats:
                        per_family_stats[fam_key] = {
                            "tested": 0,
                            "max_score": 0,
                            "max_qgram": -10.0,
                        }
                    stats = per_family_stats[fam_key]
                    for mid_params, (_, mid_inv) in middle_configs[mid_fam]:
                        for inner_fam in INNER_FAMILIES:
                            for inner_params, (_, inner_inv) in inner_configs[inner_fam]:
                                # Decrypt: CT → outer_inv → mid_inv → inner_inv
                                try:
                                    step1 = outer_inv(CT)
                                    step2 = mid_inv(step1)
                                    pt = inner_inv(step2)
                                except Exception:
                                    continue
                                tested += 1
                                stats["tested"] += 1

                                sc = crib_score(pt)
                                if sc > stats["max_score"]:
                                    stats["max_score"] = sc
                                if sc > max_score:
                                    max_score = sc

                                if sc >= ESCALATE_CRIB_MIN:
                                    qg = quadgram_per_char(pt, quadgrams)
                                    wh = word_hits(pt, words)
                                    coh = find_coherent_fragment(pt, quadgrams, words)
                                    if qg > stats["max_qgram"]:
                                        stats["max_qgram"] = qg
                                    if qg > max_qgram:
                                        max_qgram = qg
                                    record = {
                                        "outer": {"family": outer_fam.value, "params": outer_params},
                                        "middle": {"family": mid_fam.value, "params": mid_params},
                                        "inner": {"family": inner_fam.value, "params": inner_params},
                                        "crib_score": sc,
                                        "quadgram_per_char": qg,
                                        "word_hits": wh,
                                        "coherent_fragment": coh,
                                        "plaintext": pt,
                                    }
                                    meets_all = (
                                        sc >= ESCALATE_CRIB_MIN
                                        and qg >= ESCALATE_QGRAM_MIN
                                        and wh >= ESCALATE_WORD_HIT_MIN
                                        and coh
                                    )
                                    if meets_all:
                                        escalated.append(record)
                                        raise StopIteration("escalated — stopping")
                                    else:
                                        fails = []
                                        if qg < ESCALATE_QGRAM_MIN:
                                            fails.append(f"qgram<{ESCALATE_QGRAM_MIN}")
                                        if wh < ESCALATE_WORD_HIT_MIN:
                                            fails.append(f"words<{ESCALATE_WORD_HIT_MIN}")
                                        if not coh:
                                            fails.append("no_coherent_fragment")
                                        record["fails"] = fails
                                        if len(near_misses) < 30:
                                            near_misses.append(record)

                                if tested % 25000 == 0:
                                    el = time.time() - t0
                                    rate = tested / el if el > 0 else 0
                                    eta = (projected - tested) / rate if rate > 0 else -1
                                    print(
                                        f"  [{tested:>7,}/{projected:,}] "
                                        f"max={max_score} qg={max_qgram:.2f} "
                                        f"rate={rate:.0f}/s ETA={eta:.0f}s",
                                        flush=True,
                                    )
    except StopIteration as exc:
        print(f"  STOP: {exc}")
    except Exception:
        traceback.print_exc()

    elapsed = time.time() - t0
    print()
    print("=" * 72)
    print(f"Total compositions tested: {tested:,}")
    print(f"Max crib score: {max_score}/24")
    print(f"Max quadgram/char: {max_qgram:.3f}")
    print(f"Escalated candidates: {len(escalated)}")
    print(f"Near-miss records: {len(near_misses)}")
    print(f"Elapsed: {elapsed:.0f}s")

    verdict = "ESCALATED" if escalated else ("EMPTY" if tested >= projected * 0.99 else "PARTIAL")
    print(f"Verdict: {verdict}")
    print("=" * 72)

    out = {
        "experiment": "f_final_checklist_c6",
        "description": "C6 — 3-layer non-columnar composition enumeration",
        "preregistered_thresholds_doc": PREREGISTERED_PATH,
        "thresholds": {
            "crib_min": ESCALATE_CRIB_MIN,
            "quadgram_min": ESCALATE_QGRAM_MIN,
            "word_hits_min": ESCALATE_WORD_HIT_MIN,
            "fragment_min_len": FRAGMENT_MIN_LEN,
            "fragment_min_words": FRAGMENT_MIN_WORDS,
            "fragment_min_quadgram": FRAGMENT_MIN_QGRAM,
            "bean_conjunct_dropped": True,
            "bean_deviation_rationale": (
                "3-layer effective key at crib positions depends on both "
                "keywords + middle permutation; no simple structural filter "
                "analogous to the 2-layer Bean check. Conjunctive criterion "
                "retains all other checks."
            ),
        },
        "outer_families": [f.value for f in OUTER_FAMILIES],
        "middle_families": [f.value for f in MIDDLE_FAMILIES],
        "inner_families": [f.value for f in INNER_FAMILIES],
        "projected_compositions": projected,
        "total_tested": tested,
        "max_crib_score": max_score,
        "max_quadgram": max_qgram,
        "verdict": verdict,
        "escalated_candidates": escalated,
        "near_miss_count": len(near_misses),
        "near_misses_sample": near_misses[:10],
        "per_family_stats": per_family_stats,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": elapsed,
    }

    RESULTS_PATH.parent.mkdir(exist_ok=True)
    with RESULTS_PATH.open("w") as f:
        json.dump(out, f, indent=2)
    print(f"Output: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
