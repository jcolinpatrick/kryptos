#!/usr/bin/env python3 -u
"""
Cipher:   columnar_w10 + Quagmire III (KRYPTOS alphabet, ABSCISSA keyword)
Family:   campaigns
Status:   exhausted
Keyspace: 2 candidates (the 2 canonical w10 Bean-survivors from
          f_archive_col_notation_v1; the 4 raw entries in v1 collapse to
          2 distinct orderings under the Vig/VarBeau Bean symmetry)
Last run: 2026-04-21
Best score: 1  (verdict EMPTY; see results/f_w10_quagmire_iii_v1.json)

============================================================================
W10 + QUAGMIRE III (K2 CONTINUITY) CAMPAIGN v1
============================================================================

Follow-on to f_archive_col_notation_v1. That campaign tested ABSCISSA as a
periodic Vigenere/Beaufort/VarBeaufort keyword and Atbash as an inner
layer on the 4 w10 Bean-surviving configurations, with verdict EMPTY.
This campaign tests Quagmire III (the K2-canonical construction) on the
same 4 survivors.

Rationale (clue-surface continuity): K2 was solved as Quagmire III with:
    - period keyword            =  ABSCISSA
    - CT alphabet keyword       =  KRYPTOS (giving the mixed alphabet
                                   KRYPTOSABCDEFGHIJLMNQUVWXZ)
    - PT alphabet keyword       =  KRYPTOS (same mixed alphabet as CT;
                                   canonical Q III uses ONE mixed alphabet
                                   on both sides)
    - indicator                 =  K      (first letter of the mixed
                                   alphabet = zero-shift row)

If K4 also uses Quagmire III as an inner substitution layer composed
with a columnar transposition layer, and the column width is 10, then
the construction for each w10 Bean-surviving (ordering, variant) pair
is:
    CT  =  columnar_w10(kappa, Quagmire3_K2(PT))
    PT  =  Quagmire3_K2^-1(columnar_w10^-1(CT, kappa))

The variant of the w10 survivor (Vig or VarBeau) is an artifact of the
Bean check at the columnar-only level; it does NOT carry into the
Quagmire composition, which uses the fixed Quagmire III tableau. We
therefore test each of the 2 distinct w10 orderings once (not 4 times,
since the two variants are structurally coupled per the Vig/VarBeau
Bean symmetry noted in the v1 campaign output).

Procedure licenses used (all must pass the gate):
    col_notation_4_8_10_26   ARCHIVE_EVIDENCE
    quagmire_iii_family      CLUE_SURFACE       (K1/K2 continuity)
    abscissa_as_keyword      ARCHIVE_EVIDENCE   (also K2 keyword, clue-surface)

Verdict criteria: pre-registered in docs/preregistered_thresholds_2026_04_08.md
(crib >= 20/24 AND Bean AND quadgram/char >= -4.5 AND word_hits >= 3 AND
one coherent English fragment).

Usage:
    PYTHONPATH=src python3 -u scripts/campaigns/f_w10_quagmire_iii_v1.py
    PYTHONPATH=src python3 -u scripts/campaigns/f_w10_quagmire_iii_v1.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Standalone bootstrap
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.path.exists(os.path.join(_ROOT, "src")):
    sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.admissibility import (
    check_cipher_procedure,
    get_procedure_license,
)
from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.quagmire import quagmire_decrypt


# ── Pre-registered thresholds ────────────────────────────────────────────

PREREG_DOC = "docs/preregistered_thresholds_2026_04_08.md"
CRIB_MIN = 20
QUADGRAM_MIN = -4.5
WORD_HITS_MIN = 3
FRAGMENT_MIN_LEN = 10
FRAGMENT_MIN_WORDS = 2
FRAGMENT_MIN_QUADGRAM = -4.0

REQUIRED_LICENSES = (
    "col_notation_4_8_10_26",
    "quagmire_iii_family",
    "abscissa_as_keyword",
)

# Cached w10 Bean-surviving column orders from f_archive_col_notation_v1.
# These are the ONLY w10 orderings that admit a Bean-consistent keystream
# under the 242-inequality constraint. Each appears under both Vig and
# VarBeau (Vig/VarBeau are structurally coupled under negation symmetry
# of the Bean predicate); Beaufort does not survive either.
W10_SURVIVORS: Tuple[Tuple[int, ...], ...] = (
    (7, 9, 1, 4, 6, 8, 3, 5, 2, 0),
    (8, 7, 9, 6, 1, 5, 2, 0, 3, 4),
)

QUAGMIRE_PERIOD_KEYWORD = "ABSCISSA"
QUAGMIRE_CT_ALPHABET_KEYWORD = "KRYPTOS"
QUAGMIRE_PT_ALPHABET_KEYWORD = "KRYPTOS"  # canonical Q III: same mixed
#                                           alphabet on both sides
QUAGMIRE_INDICATOR = "K"  # K2 canonical: first letter of KRYPTOS-mixed
#                           alphabet = zero-shift reference row. Pinned
#                           by tests/test_transforms.py::TestQuagmire
#                           ::test_k2_groundtruth (landed 2026-04-21).
#
# History: prior to 2026-04-21 this file carried
# QUAGMIRE_INDICATOR = "A" and omitted QUAGMIRE_PT_ALPHABET_KEYWORD.
# That configuration does NOT reproduce K2's plaintext under
# kernel.transforms.quagmire (verified 2026-04-21). Fixed to the
# K2-canonical convention before the first real run.


# ── Columnar inverse (duplicated from v1 for self-contained reproduction) ──

def columnar_inverse(width: int, col_order: Tuple[int, ...]) -> List[int]:
    """Return `inv[pt_pos] = ct_idx` for a standard columnar transposition."""
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
    inv = [0] * CT_LEN
    for ct_idx, pt_pos in enumerate(perm):
        inv[pt_pos] = ct_idx
    return inv


def apply_column_inverse(ct: str, inv: List[int]) -> str:
    return "".join(ct[inv[i]] for i in range(CT_LEN))


# ── Gate ─────────────────────────────────────────────────────────────────

def _check_all_licenses() -> Dict[str, str]:
    summary: Dict[str, str] = {}
    for pid in REQUIRED_LICENSES:
        ok, cert = check_cipher_procedure(pid, family="w10_quagmire_iii_v1")
        if not ok:
            raise RuntimeError(
                f"License {pid!r} rejected: {cert.summary}"
            )
        lic = get_procedure_license(pid)
        assert lic is not None
        summary[pid] = lic.parametric_spec
    return summary


# ── Scoring ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Candidate:
    col_order: Tuple[int, ...]
    plaintext: str
    crib_score: int
    quadgram_per_char: float
    word_hits: int
    escalated: bool

    def as_dict(self) -> dict:
        return {
            "col_order": list(self.col_order),
            "crib_score": self.crib_score,
            "quadgram_per_char": self.quadgram_per_char,
            "word_hits": self.word_hits,
            "escalated": self.escalated,
            "plaintext_preview": self.plaintext[:40] + "...",
        }


_COMMON_6PLUS = frozenset((
    "PEOPLE", "SHOULD", "BEFORE", "BETWEEN", "ALWAYS", "AROUND",
    "ANOTHER", "THROUGH", "AGAINST", "NORTHEAST", "EASTNORTH",
    "BERLIN", "CLOCK", "BERLINCLOCK", "KRYPTOS", "ABSCISSA",
    "PALIMPSEST", "CARTER", "SANBORN", "SCHEIDT", "LANGLEY",
    "SECRET", "MESSAGE", "HIDDEN", "WITHIN",
))


def _quick_word_hits(plaintext: str) -> int:
    up = plaintext.upper()
    return sum(1 for w in _COMMON_6PLUS if w in up)


def _score(plaintext: str, col_order: Tuple[int, ...]) -> Candidate:
    breakdown = score_candidate(
        plaintext, bean_result=None, ngram_scorer=get_default_scorer()
    )
    crib = breakdown.crib_score
    qpc = float(breakdown.ngram_per_char or -10.0)
    word_hits = _quick_word_hits(plaintext)
    fragment_ok = crib >= CRIB_MIN and qpc >= FRAGMENT_MIN_QUADGRAM
    escalated = (
        crib >= CRIB_MIN
        and qpc >= QUADGRAM_MIN
        and word_hits >= WORD_HITS_MIN
        and fragment_ok
    )
    return Candidate(
        col_order=col_order,
        plaintext=plaintext,
        crib_score=crib,
        quadgram_per_char=qpc,
        word_hits=word_hits,
        escalated=escalated,
    )


# ── Main ─────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--out",
        default="results/f_w10_quagmire_iii_v1.json",
    )
    args = parser.parse_args()

    t0 = time.time()
    print("=" * 70)
    print("f_w10_quagmire_iii_v1 — bin D3 follow-on")
    print("=" * 70)
    print()

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
        print("--dry-run set; exiting.")
        return 0

    record: dict = {
        "experiment": "f_w10_quagmire_iii_v1",
        "description": (
            "Quagmire III (K2 canonical: ABSCISSA + KRYPTOS alphabet) on "
            "the 4 w10 Bean-surviving column orders from "
            "f_archive_col_notation_v1; bin D3 follow-on."
        ),
        "preregistered_thresholds_doc": PREREG_DOC,
        "procedure_licenses": license_specs,
        "quagmire_config": {
            "period_keyword": QUAGMIRE_PERIOD_KEYWORD,
            "ct_alphabet_keyword": QUAGMIRE_CT_ALPHABET_KEYWORD,
            "pt_alphabet_keyword": QUAGMIRE_PT_ALPHABET_KEYWORD,
            "indicator": QUAGMIRE_INDICATOR,
        },
        "w10_survivors_tested": [list(c) for c in W10_SURVIVORS],
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "candidates": [],
        "escalated_candidates": [],
        "near_miss_candidates": [],
        "verdict": "RUNNING",
    }

    print("Decrypting w10 Bean-survivors through Quagmire III ...")
    for col_order in W10_SURVIVORS:
        inv = columnar_inverse(10, col_order)
        intermediate = apply_column_inverse(CT, inv)
        plaintext = quagmire_decrypt(
            intermediate,
            QUAGMIRE_PERIOD_KEYWORD,
            indicator=QUAGMIRE_INDICATOR,
            ct_alphabet_keyword=QUAGMIRE_CT_ALPHABET_KEYWORD,
            pt_alphabet_keyword=QUAGMIRE_PT_ALPHABET_KEYWORD,
        )
        cand = _score(plaintext, col_order)
        record["candidates"].append(cand.as_dict())
        print(
            f"  order={col_order}  crib={cand.crib_score}  "
            f"qpc={cand.quadgram_per_char:+.2f}  words={cand.word_hits}"
        )
        print(f"    PT: {plaintext}")
        if cand.escalated:
            record["escalated_candidates"].append(cand.as_dict())
    print()

    record["ended_at"] = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    record["elapsed_seconds"] = round(time.time() - t0, 2)
    record["verdict"] = (
        "ESCALATED" if record["escalated_candidates"] else "EMPTY"
    )

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
