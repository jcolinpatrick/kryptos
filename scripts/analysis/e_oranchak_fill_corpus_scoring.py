#!/usr/bin/env python3
"""
Cipher: n/a (candidate-fill corpus scoring)
Family: analysis
Status: ready
Keyspace: n/a
Last run: never
Best score: n/a
"""
# ^^^ STANDARD HEADER
#
# Score the 19,185-row candidate-fill corpus that was copied from the
# doranchak/kryptos repo into data/k4_candidate_fills_oranchak.csv.
#
# Corpus schema (two columns, comma-separated, 97 letters each after space
# removal):
#
#   col 1 = a real English passage of exactly 97 letters (no spaces)
#   col 2 = the same passage with letters at positions 21-33 replaced by
#           EASTNORTHEAST and at positions 63-73 replaced by BERLINCLOCK
#
# Every col-2 string therefore satisfies the K4 anchored-crib contract at
# positions 21-33 and 63-73 by construction — so `score_candidate()` will
# report crib_score=24 for all 19,185 rows. The interesting signal here
# is the NON-CRIB quality of col 2: quadgram per-char score over the
# 97 chars minus the crib positions.
#
# Provenance: originally at doranchak/kryptos/ciphers/test-ciphers/
#   k4-length-97-plaintexts.txt. Mirrored 2026-04-21.
#
# This script is ready to run but has not been run as a campaign. It is
# intended for one-shot exploratory use; wire it into a real sweep only
# after preregistering a threshold per feedback_preregister_thresholds.md.

import csv
import os
import sys
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import get_default_scorer


CORPUS_PATH = Path(_ROOT) / "data" / "k4_candidate_fills_oranchak.csv"


def iter_corpus(path: Path):
    """Yield (row_idx, original_97, with_cribs_97) tuples.

    Spaces are stripped; result length is asserted to be 97 per field.
    """
    with path.open("r", encoding="utf-8", errors="strict") as f:
        reader = csv.reader(f)
        for idx, row in enumerate(reader):
            if len(row) != 2:
                raise ValueError(f"row {idx}: expected 2 cols, got {len(row)}")
            original = row[0].replace(" ", "").upper()
            withcribs = row[1].replace(" ", "").upper()
            if len(original) != 97 or len(withcribs) != 97:
                raise ValueError(
                    f"row {idx}: expected 97 letters each, "
                    f"got {len(original)}/{len(withcribs)}"
                )
            yield idx, original, withcribs


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack contract wrapper.

    Note: this attack does not use the ciphertext argument — the corpus
    is a set of *candidate plaintexts*. We score each candidate against
    the K4 anchored-crib + quadgram contract and return top-N sorted.
    The ciphertext is accepted for contract compatibility only.
    """
    del ciphertext  # unused
    limit = int(params.get("limit", 0))  # 0 = no limit
    top_n = int(params.get("top_n", 50))

    scorer = get_default_scorer()
    results: list[tuple[float, str, str]] = []
    for idx, _original, withcribs in iter_corpus(CORPUS_PATH):
        if limit and idx >= limit:
            break
        sb = score_candidate(withcribs, ngram_scorer=scorer)
        # Score is quadgram-per-char; every row has crib_score=24 by
        # construction, so that dimension is uninformative.
        sort_key = sb.ngram_per_char if sb.ngram_per_char is not None else -1e9
        results.append((
            float(sort_key),
            withcribs,
            f"oranchak_row={idx} crib={sb.crib_score} qpc={sort_key:+.3f}",
        ))
    results.sort(key=lambda x: -x[0])
    return results[:top_n]


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Only score the first N rows (0 = all 19,185)",
    )
    parser.add_argument(
        "--top-n", type=int, default=50,
        help="How many top-scored rows to print (by quadgram per char)",
    )
    args = parser.parse_args()

    if not CORPUS_PATH.exists():
        print(f"ERROR: corpus not found at {CORPUS_PATH}", file=sys.stderr)
        return 2

    print(f"Scoring corpus: {CORPUS_PATH}")
    print(f"Limit: {args.limit or 'all 19,185'} rows")
    print(f"Top N: {args.top_n}\n")

    top = attack("", limit=args.limit, top_n=args.top_n)
    print(f"Top {len(top)} candidates by quadgram per-char:\n")
    for sort_key, pt, desc in top:
        print(f"  {sort_key:+.3f}  {desc}")
        print(f"         {pt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
