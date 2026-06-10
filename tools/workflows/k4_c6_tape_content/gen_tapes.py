"""Deterministic generator: public K-section text -> length-97 numeric tapes.

Workflow: k4-c6-tape-content-sweep (ts 20260528T232903Z)
Cell:     C6 (NON-H1) — outer boustrophedon permutes CT, then inner additive
          key_tape. Bean does NOT apply by construction.

PROVENANCE (LOAD-BEARING):
  Every tape is derived PROGRAMMATICALLY from PUBLIC repo-sourced strings only:
    - solved K1 / K2 / K3 plaintexts (Gillogly/Stein 1999; Elonka Dunin page)
    - public K1 / K2 / K3 ciphertexts (same public sources)
    - K1+K2+K3 plaintext concatenation
    - the public KRYPTOS Vigenere tableau (rows = KRYPTOS-keyed alphabet
      shifted, read row-major)
  Source strings are imported from kryptosbot/panel_cribs.py, which labels them
  PUBLIC FACTS. NEVER any leaked / auction / sealed K4 plaintext. NEVER a short
  keyword cycled to length (that is PERIODIC and out of scope).

TAPE CONSTRUCTION:
  Two alphabet mappings:
    AZ : letter -> standard A=0 index in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    KA : letter -> index in 'KRYPTOSABCDEFGHIJLMNQUVWXZ' (KRYPTOS-keyed)
  Each source string is mapped letterwise to ints, then fit to length 97:
    - length > 97 : TRUNCATE to first 97 (declared rule TRUNC97)
    - length < 97 : CYCLE the natural-language string to 97 (declared rule
      CYCLE97). Only applied to NATURAL-LANGUAGE sources whose intrinsic length
      is > 26, so the result is NOT a short-keyword-period tape. K1_PT / K1_CT
      have length 63 (period 63, well outside the eliminated <=26 periodic
      regime and outside the short-keyword definition). The 26-letter tableau
      ROW is NOT used standalone; instead the full 676-char row-major tableau
      read is used and TRUNCATED to 97.

OUTPUT:
  results/workflows/k4_c6_tape_content/20260528T232903Z/tapes.json
  A list of records: {tape_id, source, alphabet, fit_rule, src_len, values[97]}
  Deterministic: no randomness, stable ordering.
"""

from __future__ import annotations

import json
import os
import sys

# repo-root namespace import for kryptosbot
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "src"))

from kryptosbot.panel_cribs import (  # noqa: E402  PUBLIC FACTS
    _K1_PT, _K1_CT, _K2_PT, _K2_CT, _K3_PT, _K3_CT,
)
from kryptos.kernel.constants import CT_LEN  # noqa: E402  == 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"  # public KRYPTOS-keyed alphabet (matches KA singleton)
_AZ_IDX = {c: i for i, c in enumerate(AZ)}
_KA_IDX = {c: i for i, c in enumerate(KA)}


def _build_tableau_rowmajor() -> str:
    """Public KRYPTOS Vigenere tableau, read row-major.

    Row r (0..25) is the KRYPTOS-keyed alphabet rotated left by r. This is the
    standard tabula-recta construction on the KRYPTOS alphabet — the public
    tableau carved/published with Kryptos. 26x26 = 676 letters.
    """
    rows = []
    for r in range(26):
        rows.append(KA[r:] + KA[:r])
    return "".join(rows)


_TABLEAU = _build_tableau_rowmajor()
assert len(_TABLEAU) == 676


def _fit97(values: list[int], src_len: int) -> tuple[list[int], str]:
    """Fit an int list to exactly 97 via a declared rule."""
    if len(values) >= CT_LEN:
        return values[:CT_LEN], "TRUNC97"
    # cycle (only reached for natural-language src_len in {63}; >26 by design)
    out = [values[i % len(values)] for i in range(CT_LEN)]
    return out, "CYCLE97"


def _map_string(s: str, alphabet: str) -> list[int]:
    idx = _AZ_IDX if alphabet == "AZ" else _KA_IDX
    return [idx[c] for c in s if c in idx]


# Public corpus: (logical source name, raw string). NO short keywords. NO K4.
_SOURCES: list[tuple[str, str]] = [
    ("K1_PT", _K1_PT),                       # 63 (CYCLE97; period 63)
    ("K2_PT", _K2_PT),                       # 369 (TRUNC97)
    ("K3_PT", _K3_PT),                       # 336 (TRUNC97)
    ("K1_CT", _K1_CT),                       # 63 (CYCLE97; period 63)
    ("K2_CT", _K2_CT),                       # 369 (TRUNC97)
    ("K3_CT", _K3_CT),                       # 336 (TRUNC97)
    ("K1K2K3_PT", _K1_PT + _K2_PT + _K3_PT), # 768 (TRUNC97)
    ("KRYPTOS_TABLEAU_ROWMAJOR", _TABLEAU),  # 676 (TRUNC97)
]


def generate() -> list[dict]:
    records: list[dict] = []
    for source, raw in _SOURCES:
        for alphabet in ("AZ", "KA"):
            mapped = _map_string(raw, alphabet)
            values, fit_rule = _fit97(mapped, len(raw))
            assert len(values) == CT_LEN, (source, alphabet, len(values))
            assert all(0 <= v <= 25 for v in values)
            records.append({
                "tape_id": f"{source}__{alphabet}",
                "source": source,
                "alphabet": alphabet,
                "fit_rule": fit_rule,
                "src_len": len(raw),
                "values": values,
            })
    return records


def main() -> None:
    out_dir = os.path.join(
        _REPO, "results", "workflows", "k4_c6_tape_content", "20260528T232903Z"
    )
    os.makedirs(out_dir, exist_ok=True)
    records = generate()
    out_path = os.path.join(out_dir, "tapes.json")
    with open(out_path, "w") as fh:
        json.dump(records, fh, indent=2)
    print(f"wrote {len(records)} tapes -> {out_path}")
    for r in records:
        print(f"  {r['tape_id']:34s} fit={r['fit_rule']:8s} src_len={r['src_len']:4d} "
              f"head={r['values'][:8]}")


if __name__ == "__main__":
    main()
