#!/usr/bin/env python3
"""Static guard: embedded K1-K3 texts must match the verified transcriptions.

ID:     audit_kryptos_text_integrity
Family: audit
Origin: 2026-09-29 clean-room audit (see docs/audits/kryptos_text_integrity_audit_2026_09_29.md)

THE DEFECT

Many experiment scripts embed their own copy of the K1, K2 or K3 plaintext or
ciphertext instead of importing it. A large share of those copies were written
from memory rather than transcribed, and they diverge from the real texts
partway through (typically after 20-60 letters), continuing with invented text
such as "...LIESTHENUABORDSECRETOFILLUSION...". Any running-key, crib-drag or
keystream result computed from such a copy did not test the real text.

REFERENCE

The reference texts are ``kryptosbot/panel_cribs.py`` (_K1_PT/_K1_CT,
_K2_PT/_K2_CT, _K3_PT/_K3_CT) plus ``kryptos.kernel.constants.CT`` for K4.
This script re-verifies them before use:
  * K1 CT decrypts to K1 PT under Quagmire III (KA alphabet, key PALIMPSEST);
  * K2 CT decrypts to K2 PT under Quagmire III (KA alphabet, key ABSCISSA);
  * K3 CT is the unkeyed double rotation of K3 PT (8x42 then 24x14 turn),
    equivalently PT[i] = CT[(191 + 192*i) mod 337].

ACCEPTED VARIANTS

A literal that uses the standard-English or corrected form of a carved anomaly
is not a defect: ILLUSION for IQLUSION (K1), UNDERGROUND for UNDERGRUUND (K2,
a carving error), the corrected K2 ending XLAYERTWO for IDBYROWS (an error
Sanborn acknowledged), and DESPERATELY for DESPARATLY (K3).

OUTPUT

Every uppercase string literal of 40+ letters in scripts/ and src/ (excluding
scripts/archive/) whose first 20 letters occur in a reference text is checked.
Literals that diverge are listed with the divergence offset. Exit status is 1 if
any divergent literal is found, so the guard can be used in CI.

Usage:
    PYTHONPATH=src python3 scripts/audit/audit_kryptos_text_integrity.py [--json OUT]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "kryptosbot"))

import panel_cribs as pc  # noqa: E402  (data only)
from kryptos.kernel.constants import CT as K4_CT  # noqa: E402

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"


def _q3_decrypt(ct: str, key: str) -> str:
    return "".join(KA[(KA.index(c) - KA.index(key[i % len(key)])) % 26] for i, c in enumerate(ct))


def _turn(s: str, width: int) -> str:
    rows = [s[i:i + width] for i in range(0, len(s), width)]
    return "".join(rows[r][c] for c in range(width) for r in range(len(rows) - 1, -1, -1) if c < len(rows[r]))


def verified_references() -> dict[str, str]:
    """Return reference texts after checking each against its known method."""
    assert _q3_decrypt(pc._K1_CT, "PALIMPSEST") == pc._K1_PT, "K1 reference fails Quagmire III check"
    assert _q3_decrypt(pc._K2_CT, "ABSCISSA") == pc._K2_PT, "K2 reference fails Quagmire III check"
    assert _turn(_turn(pc._K3_PT, 42), 14) == pc._K3_CT, "K3 reference fails double-rotation check"
    refs = {
        "K1PT": pc._K1_PT, "K1CT": pc._K1_CT,
        "K2PT": pc._K2_PT, "K2CT": pc._K2_CT,
        "K3PT": pc._K3_PT, "K3CT": pc._K3_CT,
        "K4CT": K4_CT,
    }
    refs["K123PT"] = refs["K1PT"] + refs["K2PT"] + refs["K3PT"]
    refs["K123CT"] = refs["K1CT"] + refs["K2CT"] + refs["K3CT"]
    return refs


def accepted_variants(refs: dict[str, str]) -> list[str]:
    """Plaintexts with the standard or corrected forms of the carved anomalies."""
    k1 = refs["K1PT"].replace("IQLUSION", "ILLUSION")
    k2 = refs["K2PT"].replace("UNDERGRUUND", "UNDERGROUND")
    k2x = k2.replace("IDBYROWS", "XLAYERTWO")
    k2x_only = refs["K2PT"].replace("IDBYROWS", "XLAYERTWO")
    k3 = refs["K3PT"].replace("DESPARATLY", "DESPERATELY")
    return [k1, k2, k2x, k2x_only, k3, k1 + k2x + k3, k1 + k2 + k3]


def best_match(s: str, refs: dict[str, str]) -> tuple[int, str, int] | None:
    best = None
    for name, r in refs.items():
        i = r.find(s[:20])
        if i < 0:
            continue
        n = 0
        while n < len(s) and i + n < len(r) and s[n] == r[i + n]:
            n += 1
        cand = (n, name, i)
        if best is None or cand > best:
            best = cand
    return best


def scan(root: str) -> list[dict]:
    refs = verified_references()
    variants = accepted_variants(refs)
    files = glob.glob(os.path.join(root, "scripts", "**", "*.py"), recursive=True)
    files += glob.glob(os.path.join(root, "src", "**", "*.py"), recursive=True)
    rows = []
    for path in sorted(files):
        rel = os.path.relpath(path, root)
        if rel.startswith(os.path.join("scripts", "archive")) or rel == os.path.join("scripts", "audit", "audit_kryptos_text_integrity.py"):
            continue
        text = open(path, errors="ignore").read()
        for m in re.finditer(r"['\"]([A-Z]{40,})['\"]", text):
            lit = m.group(1)
            hit = best_match(lit, refs)
            if hit is None:
                continue
            n, name, off = hit
            if n == len(lit):
                status = "exact"
            elif any(lit in v for v in variants):
                status = "accepted_variant"
            else:
                status = "divergent"
            rows.append({
                "file": rel, "line": text[:m.start()].count("\n") + 1, "length": len(lit),
                "reference": name, "ref_offset": off, "matched_prefix": n, "status": status,
                "context": lit[max(0, n - 8):n + 16] if status == "divergent" else "",
            })
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", help="write full results to this path")
    args = ap.parse_args()
    rows = scan(_ROOT)
    bad = [r for r in rows if r["status"] == "divergent"]
    ok = sum(r["status"] == "exact" for r in rows)
    var = sum(r["status"] == "accepted_variant" for r in rows)
    print(f"literals matched to a Kryptos text: {len(rows)}  exact: {ok}  accepted variants: {var}  divergent: {len(bad)}")
    print(f"files with divergent literals: {len({r['file'] for r in bad})}")
    for r in bad:
        print(f"  {r['file']}:{r['line']}  len={r['length']}  {r['reference']}@{r['ref_offset']}  diverges at {r['matched_prefix']}  ...{r['context']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rows, fh, indent=1)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
