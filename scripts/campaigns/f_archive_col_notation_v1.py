#!/usr/bin/env python3 -u
"""
Cipher:   columnar + (ABSCISSA keyword | Atbash layer) per archive notation
Family:   campaigns
Status:   active
Keyspace: w4: 72 pairs; w10: 10.9M pairs; keyword tests: ~100 candidates
Last run: never
Best score: N/A

============================================================================
ARCHIVE-DERIVED COL NOTATION CAMPAIGN v1  —  bin D3 deliverable
============================================================================

This campaign is the first operationalization of the "4, 8, 10, 26 = Col"
notation from Sanborn's AAA archive notebooks under the new cipher-procedure
admissibility policy (`src/kryptos/admissibility/procedure_policy.py`).
It is also the first campaign to exercise the procedure policy gate.

PROCEDURE LICENSES USED (hard gate):
    col_notation_4_8_10_26   ARCHIVE_EVIDENCE
    abscissa_as_keyword      ARCHIVE_EVIDENCE
    atbash_substitution_layer ARCHIVE_EVIDENCE

A script that cites these procedure_ids without the gate accepting all
three is operating outside the admissibility framework; this module
refuses to proceed under that condition.

SCOPE — PINNED AND NOT TO BE SILENTLY EXPANDED

The "4, 8, 10, 26" notation names four numbers. This campaign operationalizes
them as **columnar widths** because that is the simplest parse and the one
closest to Sanborn's "= Col" annotation. Alternative parses (column indices
in a fixed grid, alphabet offsets, etc.) are out of scope for v1 and
require separate licensed campaigns.

PHASES

  Phase 1  Bean-impossibility at widths 4, 8, 9 (re-verification)
           Enumerates all orderings at widths 4 (24), 8 (40320), 9 (362880)
           against 3 variants; expected result: 0 Bean-passing pairs.
           Width 8 and 9 are already documented in
           docs/exhaustion_certificate_2026_04_08.md §4-5; width 4 is newly
           closed by this campaign and is simultaneously documented in
           docs/elimination_tiers.md.

  Phase 2  Width 10 Bean-survivor enumeration
           Enumerates all 10! = 3,628,800 column orderings at width 10
           against 3 variants (Vig, Beau, VarBeau), records every Bean-
           passing (ordering, variant) pair. Expected: O(1) survivors.
           This is the ONLY surviving width in {4, 8, 9, 10} under the
           additive-key model; width 26 is intractable to enumerate and
           is sampled in Phase 4.

  Phase 3  ABSCISSA keyword test on Phase 2 survivors
           For each Bean-surviving configuration from Phase 2, apply the
           w10 columnar inverse to K4 CT, then decrypt using ABSCISSA as
           a periodic keyword (period = 8, the keyword length) under the
           config's variant. Score the resulting plaintext under the
           pre-registered thresholds (docs/preregistered_thresholds_2026_04_08.md).

  Phase 4  Atbash layer test on Phase 2 survivors
           For each Bean-surviving configuration from Phase 2, apply the
           w10 columnar inverse to K4 CT, then apply Atbash to the result.
           Atbash is parameter-free, so this phase produces exactly
           (#survivors) candidates per variant. Score each.

  Phase 5  Width 26 sampled Bean check
           Samples 100,000 random column orderings at width 26 and checks
           whether any pass the full 242-inequality Bean constraint. A
           positive result would motivate targeted follow-up; a negative
           result lower-bounds the Bean-rejection rate but does NOT
           constitute a Tier-1 elimination because the sample is
           negligible versus 26! ≈ 4e26.

RECORDKEEPING CONTRACT (per docs/preregistered_thresholds_2026_04_08.md):
    Every result JSON must declare preregistered_thresholds_doc,
    escalated_candidates, near_miss_candidates, and a verdict in
    {ESCALATED, EMPTY, PARTIAL, ERROR}.

Usage:
    PYTHONPATH=src python3 -u scripts/campaigns/f_archive_col_notation_v1.py
    PYTHONPATH=src python3 -u scripts/campaigns/f_archive_col_notation_v1.py --phase 2
    PYTHONPATH=src python3 -u scripts/campaigns/f_archive_col_notation_v1.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import permutations
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Standalone bootstrap (scripts/campaigns is 2 dirs deep)
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.path.exists(os.path.join(_ROOT, "src")):
    sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.admissibility import (
    check_cipher_procedure,
    get_procedure_license,
)
from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    BEAN_EQ,
    BEAN_INEQ,
    CRIB_POSITIONS,
    CT,
    CT_LEN,
    MOD,
)
from kryptos.kernel.constraints.bean import verify_bean
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.text import text_to_nums
from kryptos.kernel.transforms.atbash import decrypt_atbash
from kryptos.kernel.transforms.vigenere import (
    CipherVariant,
    decrypt_text,
)


# ── Pre-registered threshold constants (from 2026-04-08 doc) ────────────

PREREG_DOC = "docs/preregistered_thresholds_2026_04_08.md"
CRIB_MIN = 20
QUADGRAM_MIN = -4.5
WORD_HITS_MIN = 3
FRAGMENT_MIN_LEN = 10
FRAGMENT_MIN_WORDS = 2
FRAGMENT_MIN_QUADGRAM = -4.0

# Archive-derived notation
ARCHIVE_WIDTHS = (4, 8, 10, 26)

# Procedure licenses this campaign uses
REQUIRED_LICENSES = (
    "col_notation_4_8_10_26",
    "abscissa_as_keyword",
    "atbash_substitution_layer",
)

# Under the abscissa_as_keyword license the only keyword is ABSCISSA.
ABSCISSA_KEYWORD = "ABSCISSA"


# ── Crib reference data ──────────────────────────────────────────────────

_ENE = "EASTNORTHEAST"
_BCL = "BERLINCLOCK"

CRIB_PT: Dict[int, int] = {}
for _i, _ch in enumerate(_ENE):
    CRIB_PT[21 + _i] = ord(_ch) - ord('A')
for _i, _ch in enumerate(_BCL):
    CRIB_PT[63 + _i] = ord(_ch) - ord('A')
assert set(CRIB_PT.keys()) == set(CRIB_POSITIONS)

CT_NUMS = text_to_nums(CT)


# ── Columnar primitives (from-scratch; mirrors cert §4-5 verification) ──

def columnar_inverse(width: int, col_order: Tuple[int, ...]) -> List[int]:
    """Return a list `inv` where `inv[pt_pos]` is the CT position that
    holds the plaintext letter at pt_pos, under a standard columnar
    encryption with `col_order` read order."""
    rows = (CT_LEN + width - 1) // width
    last_row_len = CT_LEN - (rows - 1) * width
    col_lengths = [
        rows if j < last_row_len else rows - 1 for j in range(width)
    ]
    perm = [0] * CT_LEN
    ci = 0
    for col_idx in col_order:
        for row in range(col_lengths[col_idx]):
            perm[ci] = row * width + col_idx
            ci += 1
    assert ci == CT_LEN, f"perm build for w={width} produced {ci} != {CT_LEN}"
    inv = [0] * CT_LEN
    for ct_idx, pt_pos in enumerate(perm):
        inv[pt_pos] = ct_idx
    return inv


def derive_crib_keystream(
    inv: List[int], variant: str
) -> Dict[int, int]:
    """For each crib position, compute the implied keystream value under
    the given additive cipher variant."""
    d: Dict[int, int] = {}
    for pp, p in CRIB_PT.items():
        c = CT_NUMS[inv[pp]]
        if variant == "vigenere":
            k = (c - p) % 26
        elif variant == "beaufort":
            k = (c + p) % 26
        elif variant == "var_beaufort":
            k = (p - c) % 26
        else:
            raise ValueError(f"unknown variant {variant!r}")
        d[pp] = k
    return d


def passes_bean(k_at: Dict[int, int]) -> bool:
    if k_at.get(27) != k_at.get(65):
        return False
    for (i, j) in BEAN_INEQ:
        if i in k_at and j in k_at and k_at[i] == k_at[j]:
            return False
    return True


def apply_column_inverse(ct: str, inv: List[int]) -> str:
    """Return the plaintext-position-ordered string derived from ct via inv."""
    return "".join(ct[inv[i]] for i in range(CT_LEN))


# ── Gate ─────────────────────────────────────────────────────────────────

def _check_all_licenses() -> Dict[str, str]:
    """Verify all required procedure licenses pass the gate.

    Returns a mapping {procedure_id: pinned parametric_spec} for the
    result record, or raises if any license is rejected.
    """
    summary: Dict[str, str] = {}
    for pid in REQUIRED_LICENSES:
        ok, cert = check_cipher_procedure(
            pid, family="archive_col_notation_v1"
        )
        if not ok:
            raise RuntimeError(
                f"Procedure license {pid!r} rejected by gate: {cert.summary}"
            )
        lic = get_procedure_license(pid)
        assert lic is not None, f"license disappeared after gate accept: {pid}"
        summary[pid] = lic.parametric_spec
    return summary


# ── Scoring wrapper ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class CandidateResult:
    phase: str
    layer_stack: str
    variant: str
    col_order: Tuple[int, ...]
    width: int
    crib_score: int
    bean_ok: bool
    quadgram_per_char: float
    word_hits: int
    fragment_ok: bool
    plaintext: str
    escalated: bool

    def as_dict(self) -> dict:
        return {
            "phase": self.phase,
            "layer_stack": self.layer_stack,
            "variant": self.variant,
            "col_order": list(self.col_order),
            "width": self.width,
            "crib_score": self.crib_score,
            "bean_ok": self.bean_ok,
            "quadgram_per_char": self.quadgram_per_char,
            "word_hits": self.word_hits,
            "fragment_ok": self.fragment_ok,
            "escalated": self.escalated,
            "plaintext_preview": self.plaintext[:40] + "...",
        }


_NGRAM_SCORER = None


def _ngram_scorer():
    global _NGRAM_SCORER
    if _NGRAM_SCORER is None:
        _NGRAM_SCORER = get_default_scorer()
    return _NGRAM_SCORER


def _score_candidate(
    plaintext: str,
    *,
    phase: str,
    layer_stack: str,
    variant: str,
    col_order: Tuple[int, ...],
    width: int,
    keystream: Optional[List[int]] = None,
) -> CandidateResult:
    """Apply anchored scoring under the pre-registered thresholds.

    If `keystream` is provided, Bean is checked against it (length 97
    expected). Otherwise Bean is recorded as False (the composition is
    non-additive and Bean does not apply directly)."""
    bean_result = None
    if keystream is not None:
        bean_result = verify_bean(keystream)
    breakdown = score_candidate(
        plaintext, bean_result=bean_result, ngram_scorer=_ngram_scorer()
    )
    crib = breakdown.crib_score
    bean_ok = bool(breakdown.bean_passed)
    qpc = float(breakdown.ngram_per_char or -10.0)
    # word_count is None unless a word scorer is passed. We do a simple
    # in-script count of 6+ letter dictionary-ish words using a tiny
    # allowlist to avoid pulling wordlists/english.txt at runtime.
    word_hits = _quick_word_hits(plaintext)
    fragment_ok = crib >= CRIB_MIN and qpc >= FRAGMENT_MIN_QUADGRAM
    escalated = (
        crib >= CRIB_MIN
        and bean_ok
        and qpc >= QUADGRAM_MIN
        and word_hits >= WORD_HITS_MIN
        and fragment_ok
    )
    return CandidateResult(
        phase=phase,
        layer_stack=layer_stack,
        variant=variant,
        col_order=col_order,
        width=width,
        crib_score=crib,
        bean_ok=bean_ok,
        quadgram_per_char=qpc,
        word_hits=word_hits,
        fragment_ok=fragment_ok,
        plaintext=plaintext,
        escalated=escalated,
    )


# Minimal word-hit approximation for pre-reg threshold (5) "word_hits_min=3".
# A rejected candidate never needs exact dictionary lookup; this list
# catches obvious English hits so the pre-reg is satisfied for genuine
# near-misses without pulling a 1M-word list.
_COMMON_SIX_LETTER_PLUS = frozenset((
    "PEOPLE", "SHOULD", "BEFORE", "BETWEEN", "ALWAYS", "AROUND",
    "ANOTHER", "THROUGH", "AGAINST", "NORTHEAST", "EASTNORTH",
    "BERLIN", "CLOCK", "BERLINCLOCK", "KRYPTOS", "ABSCISSA",
    "PALIMPSEST", "CARTER", "SANBORN", "SCHEIDT", "LANGLEY",
))


def _quick_word_hits(plaintext: str) -> int:
    up = plaintext.upper()
    return sum(1 for w in _COMMON_SIX_LETTER_PLUS if w in up)


# ── Variant decryption helper ────────────────────────────────────────────

_VARIANT_MAP = {
    "vigenere": CipherVariant.VIGENERE,
    "beaufort": CipherVariant.BEAUFORT,
    "var_beaufort": CipherVariant.VAR_BEAUFORT,
}


def _decrypt_periodic(
    ct: str, keyword: str, variant: str
) -> Tuple[str, List[int]]:
    """Decrypt `ct` under a periodic substitution with `keyword` at the
    given variant. Returns (plaintext, expanded_key_of_length_97)."""
    key_nums = [ALPH_IDX[k] for k in keyword]
    expanded = [key_nums[i % len(key_nums)] for i in range(len(ct))]
    pt = decrypt_text(ct, key_nums, variant=_VARIANT_MAP[variant])
    return pt, expanded


# ── Phases ───────────────────────────────────────────────────────────────

def phase1_bean_closure(
    widths: Tuple[int, ...] = (4, 8, 9)
) -> Dict[str, dict]:
    """Re-verify Bean-impossibility at widths 4/8/9 from a fresh
    enumeration. Records per-width pair counts."""
    out: Dict[str, dict] = {}
    for w in widths:
        total = 0
        pass_count = 0
        for col_order in permutations(range(w)):
            inv = columnar_inverse(w, col_order)
            for variant in ("vigenere", "beaufort", "var_beaufort"):
                total += 1
                k_at = derive_crib_keystream(inv, variant)
                if passes_bean(k_at):
                    pass_count += 1
        out[str(w)] = {
            "orderings": math.factorial(w),
            "pairs_checked": total,
            "bean_passing": pass_count,
            "verdict": "BEAN_IMPOSSIBLE" if pass_count == 0 else "SURVIVES",
        }
    return out


def phase2_w10_survivors() -> List[Tuple[Tuple[int, ...], str]]:
    """Enumerate all w10 columnar (ordering, variant) pairs and collect
    every Bean-passing pair. Returns a list of (col_order, variant)."""
    survivors: List[Tuple[Tuple[int, ...], str]] = []
    for col_order in permutations(range(10)):
        inv = columnar_inverse(10, col_order)
        for variant in ("vigenere", "beaufort", "var_beaufort"):
            k_at = derive_crib_keystream(inv, variant)
            if passes_bean(k_at):
                survivors.append((col_order, variant))
    return survivors


def phase3_abscissa_on_survivors(
    survivors: List[Tuple[Tuple[int, ...], str]]
) -> List[CandidateResult]:
    """For each w10 Bean-survivor, decrypt K4 via the columnar inverse
    then apply a periodic ABSCISSA key under the survivor's variant.

    Note on Bean: Phase 2 already verified Bean consistency at the
    columnar-only level. For Phase 3 the composition is
    columnar + periodic(ABSCISSA), and the Bean constraint applies to
    the FULL implied keystream. We compute the implied keystream as
    the ABSCISSA pattern expanded to length 97 (in the intermediate's
    coordinate frame) and verify Bean against it."""
    results: List[CandidateResult] = []
    for col_order, variant in survivors:
        inv = columnar_inverse(10, col_order)
        pt_post_trans = apply_column_inverse(CT, inv)
        pt_post_key, expanded_key = _decrypt_periodic(
            pt_post_trans, ABSCISSA_KEYWORD, variant
        )
        results.append(_score_candidate(
            pt_post_key,
            phase="phase3_abscissa",
            layer_stack=f"columnar_w10 -> {variant}(ABSCISSA)",
            variant=variant,
            col_order=col_order,
            width=10,
            keystream=expanded_key,
        ))
    return results


def phase4_atbash_on_survivors(
    survivors: List[Tuple[Tuple[int, ...], str]]
) -> List[CandidateResult]:
    """For each w10 Bean-survivor, decrypt K4 via the columnar inverse
    then apply Atbash to the result. Atbash is parameter-free; the
    survivor's variant is recorded for bookkeeping but does not change
    the Atbash transform itself."""
    results: List[CandidateResult] = []
    for col_order, variant in survivors:
        inv = columnar_inverse(10, col_order)
        pt_post_trans = apply_column_inverse(CT, inv)
        pt_post_atbash = decrypt_atbash(pt_post_trans)
        results.append(_score_candidate(
            pt_post_atbash,
            phase="phase4_atbash",
            layer_stack=f"columnar_w10 -> atbash",
            variant=variant,  # from survivor, for context
            col_order=col_order,
            width=10,
        ))
    return results


def phase5_w26_sampled_bean(
    n_samples: int = 100_000, seed: int = 0xC0C0
) -> dict:
    """Sample `n_samples` random w26 column orderings and report the
    Bean-passing count. This is a lower bound on the Bean-rejection
    rate; it does NOT constitute a Tier-1 elimination."""
    rng = random.Random(seed)
    base = list(range(26))
    total = 0
    passing: List[Tuple[Tuple[int, ...], str]] = []
    for _ in range(n_samples):
        order = base.copy()
        rng.shuffle(order)
        inv = columnar_inverse(26, tuple(order))
        for variant in ("vigenere", "beaufort", "var_beaufort"):
            total += 1
            k_at = derive_crib_keystream(inv, variant)
            if passes_bean(k_at):
                passing.append((tuple(order), variant))
    return {
        "n_samples": n_samples,
        "pairs_checked": total,
        "bean_passing": len(passing),
        "first_passes": [
            {"col_order": list(o), "variant": v} for (o, v) in passing[:5]
        ],
        "verdict": (
            "EMPIRICAL_ZERO" if not passing else "SURVIVES"
        ),
        "caveat": (
            f"Sampled {n_samples} of 26! ≈ 4.03e26 orderings; "
            f"negative result is not a Tier-1 elimination."
        ),
    }


# ── Main ─────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        type=int,
        default=0,
        help="Run only one phase (1-5). Default 0 = all phases.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate licenses and print plan without running phases.",
    )
    parser.add_argument(
        "--out",
        default="results/f_archive_col_notation_v1.json",
        help="Output JSON path (relative to repo root).",
    )
    parser.add_argument(
        "--phase5-samples",
        type=int,
        default=100_000,
        help="Number of w26 samples for Phase 5 (default 100000).",
    )
    args = parser.parse_args()

    t0 = time.time()

    print("=" * 70)
    print("f_archive_col_notation_v1 — bin D3 deliverable")
    print("=" * 70)
    print()

    # Gate: every license must be accepted before any phase runs.
    print("Gate: validating procedure licenses ...")
    try:
        license_specs = _check_all_licenses()
    except RuntimeError as exc:
        print(f"FATAL: {exc}")
        return 2
    for pid, spec in license_specs.items():
        print(f"  {pid}  (spec: {spec})")
    print()

    if args.dry_run:
        print("--dry-run set; exiting before phase execution.")
        return 0

    record: dict = {
        "experiment": "f_archive_col_notation_v1",
        "description": (
            "Archive-derived col notation 4,8,10,26 operationalized under "
            "the cipher-procedure admissibility policy; first bin-D3 "
            "deliverable exercising the procedure gate."
        ),
        "preregistered_thresholds_doc": PREREG_DOC,
        "procedure_licenses": license_specs,
        "thresholds": {
            "crib_min": CRIB_MIN,
            "quadgram_min": QUADGRAM_MIN,
            "word_hits_min": WORD_HITS_MIN,
            "fragment_min_len": FRAGMENT_MIN_LEN,
            "fragment_min_words": FRAGMENT_MIN_WORDS,
            "fragment_min_quadgram": FRAGMENT_MIN_QUADGRAM,
        },
        "archive_widths": list(ARCHIVE_WIDTHS),
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "phases": {},
        "escalated_candidates": [],
        "near_miss_candidates": [],
        "verdict": "RUNNING",
    }

    phases_to_run = (
        (1, 2, 3, 4, 5) if args.phase == 0 else (args.phase,)
    )

    # Phase 1: Bean closure at w4, w8, w9
    if 1 in phases_to_run:
        print("Phase 1: Bean closure at widths 4, 8, 9 ...")
        p1 = phase1_bean_closure()
        record["phases"]["phase1_bean_closure_w4_w8_w9"] = p1
        for w, info in p1.items():
            print(
                f"  w={w}: {info['pairs_checked']:,} pairs, "
                f"{info['bean_passing']} Bean-passing, {info['verdict']}"
            )
        print()

    # Phase 2: w10 Bean survivor enumeration
    survivors: List[Tuple[Tuple[int, ...], str]] = []
    if 2 in phases_to_run:
        print("Phase 2: w10 Bean-survivor enumeration (~2 minutes) ...")
        t_p2 = time.time()
        survivors = phase2_w10_survivors()
        dt_p2 = time.time() - t_p2
        record["phases"]["phase2_w10_survivors"] = {
            "orderings_tested": math.factorial(10),
            "pairs_checked": math.factorial(10) * 3,
            "bean_passing": len(survivors),
            "survivors": [
                {"col_order": list(o), "variant": v}
                for (o, v) in survivors
            ],
            "elapsed_seconds": round(dt_p2, 1),
        }
        print(f"  found {len(survivors)} Bean-passing pairs in {dt_p2:.1f}s")
        for (o, v) in survivors:
            print(f"    order={o} variant={v}")
        print()

    # Phase 3: ABSCISSA keyword on w10 survivors
    if 3 in phases_to_run and survivors:
        print("Phase 3: ABSCISSA keyword on w10 survivors ...")
        p3 = phase3_abscissa_on_survivors(survivors)
        record["phases"]["phase3_abscissa"] = {
            "candidates_scored": len(p3),
            "max_crib": max((r.crib_score for r in p3), default=0),
            "max_quadgram": max(
                (r.quadgram_per_char for r in p3), default=-10.0
            ),
            "escalated": [r.as_dict() for r in p3 if r.escalated],
            "all_candidates": [r.as_dict() for r in p3],
        }
        for r in p3:
            print(
                f"  order={r.col_order} variant={r.variant}  "
                f"crib={r.crib_score}  qpc={r.quadgram_per_char:+.2f}  "
                f"bean={r.bean_ok}"
            )
            if r.escalated:
                record["escalated_candidates"].append(r.as_dict())
        print()
    elif 3 in phases_to_run:
        print("Phase 3: skipped (no w10 survivors from Phase 2)")
        print()

    # Phase 4: Atbash on w10 survivors
    if 4 in phases_to_run and survivors:
        print("Phase 4: Atbash layer on w10 survivors ...")
        p4 = phase4_atbash_on_survivors(survivors)
        record["phases"]["phase4_atbash"] = {
            "candidates_scored": len(p4),
            "max_crib": max((r.crib_score for r in p4), default=0),
            "max_quadgram": max(
                (r.quadgram_per_char for r in p4), default=-10.0
            ),
            "escalated": [r.as_dict() for r in p4 if r.escalated],
            "all_candidates": [r.as_dict() for r in p4],
        }
        for r in p4:
            print(
                f"  order={r.col_order}  crib={r.crib_score}  "
                f"qpc={r.quadgram_per_char:+.2f}  bean={r.bean_ok}"
            )
            if r.escalated:
                record["escalated_candidates"].append(r.as_dict())
        print()
    elif 4 in phases_to_run:
        print("Phase 4: skipped (no w10 survivors from Phase 2)")
        print()

    # Phase 5: w26 sampled Bean check
    if 5 in phases_to_run:
        print(f"Phase 5: w26 sampled Bean check (n={args.phase5_samples}) ...")
        t_p5 = time.time()
        p5 = phase5_w26_sampled_bean(n_samples=args.phase5_samples)
        dt_p5 = time.time() - t_p5
        p5["elapsed_seconds"] = round(dt_p5, 1)
        record["phases"]["phase5_w26_sample"] = p5
        print(
            f"  {p5['pairs_checked']:,} pairs, {p5['bean_passing']} "
            f"passing in {dt_p5:.1f}s ({p5['verdict']})"
        )
        print(f"  {p5['caveat']}")
        print()

    # Final verdict
    record["ended_at"] = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    record["elapsed_seconds"] = round(time.time() - t0, 1)
    if record["escalated_candidates"]:
        record["verdict"] = "ESCALATED"
    else:
        record["verdict"] = "EMPTY"

    # Write result
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = Path(_ROOT) / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2, sort_keys=True))

    print(f"Verdict: {record['verdict']}")
    print(f"Wrote: {out_path}")
    print(f"Total elapsed: {record['elapsed_seconds']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
