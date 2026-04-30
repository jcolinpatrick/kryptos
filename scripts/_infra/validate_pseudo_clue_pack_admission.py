"""Real-K4 pseudo-clue pack admission validator (read-only).

Checks future packs against the mechanical items in
``docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md``. This script does NOT
mutate any pack file, does NOT run the bridge audit, and does NOT
load the kernel — it is a pure-Python admission gate.

Usage:
  PYTHONPATH=src python3 scripts/_infra/validate_pseudo_clue_pack_admission.py <pack.json | dir/>

Exit codes:
  0 — every pack admissible (no mechanical FAILs; HUMAN_REVIEW items
      reported but do not block).
  1 — at least one pack failed at least one mechanical check.
  2 — invocation error (missing path, unreadable file, schema reject).

Checks (numbered to match the admission standard document):
  R1  — provenance specificity: at least one provenance item names a
        URL_OR_REGISTRY_KEY, OR has source_type in
        {crib, anomaly, registry}.
  R2  — every keyword and numeric_role role_hint != "unknown".
  R3a — bounds.allow_project_safe_defaults == False (or pack explicitly
        justifies the deviation in caveats).
  R3b — bounds.allow_default_widths == False (or pack justifies in
        caveats).
  R3c — every numeric_role has at least one source_ids entry that
        matches a provenance source_id in the same pack.
  R4  — bounds.allowed_keywords is set non-empty AND every keyword's
        token appears in allowed_keywords (case-insensitive); OR the
        pack states a justification in caveats containing the phrase
        "no allowed_keywords".
  R5  — pack does NOT name a running-key / book-cipher hypothesis
        without a citation. (Heuristic: if hypothesis_summary contains
        any of {"running key", "running-key", "book cipher", "book-cipher"}
        the pack must also cite a public_comment or human_note
        provenance with url_or_registry_key set.)
  R6  — if allow_project_safe_defaults=True, caveats MUST contain a
        per-default justification phrase (substring "default" plus
        substring "justif" or substring "rationale").
  R7  — caveats or hypothesis_summary mention at least one of:
        bean, ngram, anomaly, null mask, route geometry, position
        consistency. (Substring match, case-insensitive.)
  R8  — caveats contains exactly one of the four campaign_001_coverage
        markers:
          campaign_001_coverage: not_covered
          campaign_001_coverage: tightened
          campaign_001_coverage: new_provenance
          campaign_001_coverage: covered    (rejected with FAIL)
  R9  — bounds.max_specs <= 500. If > 500, caveats must contain
        substring "cost justification" AND R7 must list bean OR anomaly
        (the strongest corroboration types).
  R10 — caveats contains a predeclared success criterion of the form
        "pack passes if" OR "success: crib_score" OR
        "success_criterion".

Items that require author judgment (mechanism mapping in rule 2,
side-effect prediction strength beyond keyword presence, soundness of
provenance) are reported as HUMAN_REVIEW and do NOT cause exit code 1.

This script is intentionally tolerant: false positives are worse than
false negatives because the validator is a gate, not a substitute for
review. Each FAIL has a clear remediation hint.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


COVERAGE_MARKERS = (
    "campaign_001_coverage: not_covered",
    "campaign_001_coverage: tightened",
    "campaign_001_coverage: new_provenance",
    "campaign_001_coverage: covered",
)
SIDE_EFFECT_MARKERS = (
    "bean", "ngram", "anomaly",
    "null mask", "null-mask",
    "route geometry", "route_geometry",
    "position consistency", "position_consistency",
    "side-effect", "side effect",
)
SUCCESS_MARKERS = (
    "pack passes if", "success: crib_score", "success_criterion",
    "success criterion", "predeclared success",
)
RUNKEY_MARKERS = (
    "running key", "running-key", "book cipher", "book-cipher",
)
SPECIFIC_PROVENANCE_TYPES = frozenset({"crib", "anomaly", "registry"})
DEFAULT_JUSTIFICATION_HINTS = ("justif", "rationale")


@dataclass
class CheckResult:
    rule: str
    severity: str   # "FAIL" | "HUMAN_REVIEW" | "OK"
    message: str

    def is_fail(self) -> bool:
        return self.severity == "FAIL"


@dataclass
class PackReport:
    path: str
    pack_id: str
    results: list[CheckResult] = field(default_factory=list)

    def fails(self) -> list[CheckResult]:
        return [r for r in self.results if r.is_fail()]

    def human_reviews(self) -> list[CheckResult]:
        return [r for r in self.results if r.severity == "HUMAN_REVIEW"]


def _caveats_text(pack: dict) -> str:
    parts: list[str] = list(pack.get("caveats", []) or [])
    parts.append(pack.get("hypothesis_summary", "") or "")
    parts.extend(list(pack.get("constraints", []) or []))
    return "\n".join(parts).lower()


def _has_substring(haystack: str, needles: Iterable[str]) -> bool:
    h = haystack.lower()
    return any(n.lower() in h for n in needles)


def _check_r1(pack: dict) -> CheckResult:
    prov = pack.get("provenance_items", []) or []
    if not prov:
        return CheckResult("R1", "FAIL", "no provenance_items declared")
    for p in prov:
        st = p.get("source_type", "")
        if st in SPECIFIC_PROVENANCE_TYPES:
            return CheckResult("R1", "OK", "")
        if p.get("url_or_registry_key"):
            return CheckResult("R1", "OK", "")
    return CheckResult(
        "R1", "FAIL",
        "no provenance item names a URL_OR_REGISTRY_KEY and no entry has "
        "source_type in {crib, anomaly, registry}; bare public_comment / "
        "human_note provenance must carry url_or_registry_key",
    )


def _check_r2(pack: dict) -> CheckResult:
    bad: list[str] = []
    for kw in pack.get("keywords", []) or []:
        if kw.get("role_hint", "unknown") == "unknown":
            bad.append(f"keyword:{kw.get('token','')}")
    for n in pack.get("numeric_roles", []) or []:
        if n.get("role_hint", "unknown") == "unknown":
            bad.append(f"numeric:{n.get('value', '?')}")
    if bad:
        return CheckResult(
            "R2", "FAIL",
            f"role_hint='unknown' on: {', '.join(bad[:5])}"
            + (f" (+{len(bad)-5} more)" if len(bad) > 5 else ""),
        )
    return CheckResult("R2", "OK", "")


def _check_r3(pack: dict) -> list[CheckResult]:
    out: list[CheckResult] = []
    bounds = pack.get("bounds", {}) or {}
    caveats = _caveats_text(pack)
    if bounds.get("allow_project_safe_defaults", True):
        if "allow_project_safe_defaults" in caveats and any(
            h in caveats for h in DEFAULT_JUSTIFICATION_HINTS
        ):
            out.append(CheckResult(
                "R3a", "OK",
                "allow_project_safe_defaults=True with stated justification",
            ))
        else:
            out.append(CheckResult(
                "R3a", "FAIL",
                "bounds.allow_project_safe_defaults=True without explicit "
                "justification in caveats",
            ))
    else:
        out.append(CheckResult("R3a", "OK", ""))
    if bounds.get("allow_default_widths", True):
        if "allow_default_widths" in caveats and any(
            h in caveats for h in DEFAULT_JUSTIFICATION_HINTS
        ):
            out.append(CheckResult(
                "R3b", "OK",
                "allow_default_widths=True with stated justification",
            ))
        else:
            out.append(CheckResult(
                "R3b", "FAIL",
                "bounds.allow_default_widths=True without explicit "
                "justification in caveats",
            ))
    else:
        out.append(CheckResult("R3b", "OK", ""))
    prov_ids = {
        p.get("source_id", "")
        for p in (pack.get("provenance_items", []) or [])
    }
    bad_nums: list[str] = []
    for n in pack.get("numeric_roles", []) or []:
        sids = list(n.get("source_ids", []) or [])
        if not sids or not any(s in prov_ids for s in sids):
            bad_nums.append(str(n.get("value", "?")))
    if bad_nums:
        out.append(CheckResult(
            "R3c", "FAIL",
            f"numeric_roles with no provenance link: {', '.join(bad_nums[:5])}",
        ))
    else:
        out.append(CheckResult("R3c", "OK", ""))
    return out


def _check_r4(pack: dict) -> CheckResult:
    bounds = pack.get("bounds", {}) or {}
    allowed = [str(k).upper().strip() for k in (bounds.get("allowed_keywords", []) or [])]
    keywords = [str(k.get("token", "")).upper().strip() for k in (pack.get("keywords", []) or [])]
    caveats = _caveats_text(pack)
    if not keywords:
        return CheckResult("R4", "OK", "no keyword hints")
    if allowed:
        missing = [k for k in keywords if k and k not in allowed]
        if missing:
            return CheckResult(
                "R4", "FAIL",
                f"keyword tokens missing from bounds.allowed_keywords: "
                f"{', '.join(missing[:5])}",
            )
        return CheckResult("R4", "OK", "")
    if "no allowed_keywords" in caveats:
        return CheckResult(
            "R4", "HUMAN_REVIEW",
            "no allowed_keywords; pack states a justification — verify "
            "manually",
        )
    return CheckResult(
        "R4", "FAIL",
        "bounds.allowed_keywords is empty and pack does not justify "
        "open keyword pool in caveats (substring 'no allowed_keywords' "
        "missing)",
    )


def _check_r5(pack: dict) -> CheckResult:
    summ = (pack.get("hypothesis_summary", "") or "").lower()
    if not _has_substring(summ, RUNKEY_MARKERS):
        return CheckResult("R5", "OK", "")
    for p in pack.get("provenance_items", []) or []:
        if p.get("source_type") in {"public_comment", "human_note"} \
                and p.get("url_or_registry_key"):
            return CheckResult("R5", "OK", "")
    return CheckResult(
        "R5", "FAIL",
        "running-key/book-cipher hypothesis without specific source-text "
        "citation (public_comment or human_note provenance with "
        "url_or_registry_key)",
    )


def _check_r6(pack: dict) -> CheckResult:
    bounds = pack.get("bounds", {}) or {}
    if not bounds.get("allow_project_safe_defaults", False):
        return CheckResult("R6", "OK", "")
    caveats = _caveats_text(pack)
    if "default" in caveats and any(h in caveats for h in DEFAULT_JUSTIFICATION_HINTS):
        return CheckResult(
            "R6", "HUMAN_REVIEW",
            "allow_project_safe_defaults=True with default justification "
            "phrase present — verify manually",
        )
    return CheckResult(
        "R6", "FAIL",
        "allow_project_safe_defaults=True but caveats lack a per-default "
        "justification (need substring 'default' + 'justif' or 'rationale')",
    )


def _check_r7(pack: dict) -> CheckResult:
    blob = _caveats_text(pack)
    if _has_substring(blob, SIDE_EFFECT_MARKERS):
        return CheckResult(
            "R7", "HUMAN_REVIEW",
            "side-effect marker present — verify the prediction is "
            "concrete and falsifiable, not just a keyword mention",
        )
    return CheckResult(
        "R7", "FAIL",
        "no predicted side-effect found in caveats / hypothesis_summary "
        "(need at least one of: bean, ngram, anomaly, null mask, "
        "route geometry, position consistency, side-effect)",
    )


def _check_r8(pack: dict) -> CheckResult:
    blob = _caveats_text(pack)
    matches = [m for m in COVERAGE_MARKERS if m in blob]
    if not matches:
        return CheckResult(
            "R8", "FAIL",
            "no campaign_001_coverage statement; required substring is "
            "one of: campaign_001_coverage: {not_covered, tightened, "
            "new_provenance, covered}",
        )
    if len(matches) > 1:
        return CheckResult(
            "R8", "FAIL",
            f"multiple campaign_001_coverage markers present: {matches}",
        )
    if matches[0] == "campaign_001_coverage: covered":
        return CheckResult(
            "R8", "FAIL",
            "campaign_001_coverage: covered — overlapping packs are "
            "rejected at admission (the family is already on the "
            "closed-null list)",
        )
    return CheckResult("R8", "OK", f"coverage = {matches[0]}")


def _check_r9(pack: dict) -> CheckResult:
    bounds = pack.get("bounds", {}) or {}
    max_specs = int(bounds.get("max_specs", 200))
    if max_specs <= 500:
        return CheckResult("R9", "OK", "")
    caveats = _caveats_text(pack)
    if "cost justification" not in caveats:
        return CheckResult(
            "R9", "FAIL",
            f"max_specs={max_specs} > 500 without 'cost justification' "
            "phrase in caveats",
        )
    if not _has_substring(caveats, ("bean", "anomaly")):
        return CheckResult(
            "R9", "FAIL",
            f"max_specs={max_specs} > 500 with cost justification but "
            "no bean / anomaly side-effect prediction",
        )
    return CheckResult("R9", "HUMAN_REVIEW", "max_specs > 500 — verify justification soundness")


def _check_r10(pack: dict) -> CheckResult:
    blob = _caveats_text(pack)
    if _has_substring(blob, SUCCESS_MARKERS):
        return CheckResult(
            "R10", "HUMAN_REVIEW",
            "success criterion phrase present — verify it is concrete and "
            "predeclared, not post-hoc",
        )
    return CheckResult(
        "R10", "FAIL",
        "no predeclared success criterion in caveats (need substring "
        "'pack passes if' OR 'success: crib_score' OR 'success_criterion')",
    )


def validate_pack(pack: dict, path: str) -> PackReport:
    report = PackReport(path=path, pack_id=str(pack.get("pack_id", "")))
    report.results.append(_check_r1(pack))
    report.results.append(_check_r2(pack))
    report.results.extend(_check_r3(pack))
    report.results.append(_check_r4(pack))
    report.results.append(_check_r5(pack))
    report.results.append(_check_r6(pack))
    report.results.append(_check_r7(pack))
    report.results.append(_check_r8(pack))
    report.results.append(_check_r9(pack))
    report.results.append(_check_r10(pack))
    return report


def _collect_paths(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(target.glob("*.json"))
    print(f"ERROR: {target} is not a file or directory", file=sys.stderr)
    sys.exit(2)


def _print_report(r: PackReport) -> None:
    print(f"=== {r.pack_id or '<no pack_id>'}  ({r.path})")
    for chk in r.results:
        if chk.severity == "OK":
            continue
        print(f"  [{chk.severity}] {chk.rule}: {chk.message}")
    if not r.fails() and not r.human_reviews():
        print("  [OK] all mechanical checks pass")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="pack JSON file or directory of packs")
    ap.add_argument(
        "--quiet", action="store_true",
        help="only print summary line and FAILs (suppresses HUMAN_REVIEW)",
    )
    args = ap.parse_args()
    target = Path(args.path)
    paths = _collect_paths(target)
    if not paths:
        print(f"ERROR: no JSON files at {target}", file=sys.stderr)
        return 2
    reports: list[PackReport] = []
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                pack = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: {p}: {exc}", file=sys.stderr)
            return 2
        reports.append(validate_pack(pack, str(p)))
    n_fail = sum(1 for r in reports if r.fails())
    n_review = sum(1 for r in reports if r.human_reviews())
    n_ok = len(reports) - n_fail
    for r in reports:
        if args.quiet and not r.fails():
            continue
        _print_report(r)
    print(f"SUMMARY: {len(reports)} packs checked; {n_ok} pass mechanical "
          f"checks, {n_fail} FAIL, {n_review} have HUMAN_REVIEW items")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
