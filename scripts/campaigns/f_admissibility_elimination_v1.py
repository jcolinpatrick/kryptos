"""f_admissibility_elimination_v1 — first admissibility-first campaign.

Cipher: periodic_additive (vigenere | beaufort | var_beaufort)
Family: admissibility
Status: active
Keyspace: 3 variants x 26 periods = 78 (variant, period) pairs
Last run:
Best score: N/A — this campaign produces certificates, not scores

Purpose
=======

Runs the new `kryptos.admissibility.periodic_admissibility` CP-SAT-backed
checker over every (variant, period) pair for periods 1..26 and produces
structured elimination / admissibility certificates.  Cross-verifies the
pure-Python and CP-SAT backends wherever OR-Tools is available.

In addition, sweeps the existing `scripts/running_key/` directory and
evaluates each script against the new corpus policy, emitting a
`CORPUS_POLICY_VIOLATION` certificate for any source that is not on the
allowlist.  These certificates are the formal record that the running-key
search space has been restricted to the justified allowlist.

Output
======

Two JSON files under results/:

    results/admissibility_elimination_v1/periodic_additive.json
    results/admissibility_elimination_v1/running_key_policy.json

Each entry is a self-describing certificate (see
`kryptos.admissibility.certificate`).  Human-readable summary is printed
to stdout.

Compute
=======

Single-process, <2 seconds total.  Does NOT compete with background
campaigns for CPU.  Do not parallelise — the CSP is microsecond-scale.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path


# Standalone bootstrap
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
    if _ROOT == "/":
        raise RuntimeError("Cannot locate repo root")
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.admissibility import (  # noqa: E402
    AdmissibilityCertificate,
    EliminationCertificate,
    EliminationReason,
    check_corpus_source,
    check_periodic_additive,
    sweep_periodic_additive,
    certificate_to_json,
)
from kryptos.admissibility.periodic_admissibility import HAS_CP_SAT  # noqa: E402


RESULTS_DIR = Path(_ROOT) / "results" / "admissibility_elimination_v1"
RUNNING_KEY_DIR = Path(_ROOT) / "scripts" / "running_key"


def _cert_to_plain(cert) -> dict:
    """Serialise a certificate into a plain dict for JSON output."""
    return cert.as_dict()


def run_periodic_campaign() -> dict:
    """Sweep the full periodic-additive family with cross-verification."""
    print("\n=== Periodic additive sweep ===")
    cross_verify = HAS_CP_SAT
    if cross_verify:
        print("  CP-SAT available — cross-verifying pure-Python vs CP-SAT")
    else:
        print("  CP-SAT unavailable — pure-Python path only")

    certs = sweep_periodic_additive(
        periods=tuple(range(1, 27)),
        variants=("vigenere", "beaufort", "var_beaufort"),
        cross_verify=cross_verify,
    )

    n_total = len(certs)
    n_elim = sum(1 for c in certs if isinstance(c, EliminationCertificate))
    n_adm = sum(1 for c in certs if isinstance(c, AdmissibilityCertificate))

    print(f"  Checked {n_total} (variant, period) pairs")
    print(f"  Eliminated (formal UNSAT): {n_elim}")
    print(f"  Admissible (survived):     {n_adm}")

    # Per-variant breakdown with the smallest admissible period — this
    # is the key diagnostic: periods >= p_min are where the CSP first
    # acquires enough DOF to satisfy Bean + cribs.
    for variant in ("vigenere", "beaufort", "var_beaufort"):
        variant_certs = [c for c in certs if f"/{variant}/" in c.family]
        admissible_periods = [
            int(c.family.split("/p")[-1])
            for c in variant_certs
            if isinstance(c, AdmissibilityCertificate)
        ]
        eliminated_periods = [
            int(c.family.split("/p")[-1])
            for c in variant_certs
            if isinstance(c, EliminationCertificate)
        ]
        if admissible_periods:
            p_min = min(admissible_periods)
            print(
                f"  {variant:13s}: eliminated p in {sorted(eliminated_periods)}, "
                f"smallest admissible p = {p_min}"
            )
        else:
            print(
                f"  {variant:13s}: ALL periods 1..26 eliminated "
                f"(formal UNSAT)"
            )

    # Reason breakdown
    reason_counts: dict = {}
    for c in certs:
        if isinstance(c, EliminationCertificate):
            reason_counts[c.reason.value] = reason_counts.get(c.reason.value, 0) + 1
    if reason_counts:
        print("  Elimination reason breakdown:")
        for r, n in sorted(reason_counts.items()):
            print(f"    {r}: {n}")

    return {
        "n_total": n_total,
        "n_elim": n_elim,
        "n_adm": n_adm,
        "reason_counts": reason_counts,
        "certificates": [_cert_to_plain(c) for c in certs],
    }


def run_running_key_policy_campaign() -> dict:
    """Walk scripts/running_key/ and check each against corpus policy."""
    print("\n=== Running-key corpus policy sweep ===")
    if not RUNNING_KEY_DIR.exists():
        print(f"  {RUNNING_KEY_DIR} not found — skipping")
        return {"n_scripts": 0, "certificates": []}

    script_paths = sorted(RUNNING_KEY_DIR.glob("e_*.py"))
    print(f"  Found {len(script_paths)} running-key scripts")

    # Scanner patterns.  The goal is NOT to be clever about dynamic code;
    # it is to identify scripts whose source selection is statically
    # auditable.  A script that passes no pattern is recorded as
    # ASSUMPTION_UNMET — manual verification required before running.
    source_re = re.compile(
        r"""(?ix)
        (?:source_path|source_file|corpus_path|running_key_path|
           KEY_FILE|SOURCE|SOURCE_PATH|BOOK_PATH|KEY_TEXT_PATH|
           source_text|key_text|book_path|text_path|PATH)
        \s* = \s*
        (?:r|b)? ['"]([^'"]+)['"]
        """,
    )
    # Inline literal source references inside function calls
    open_re = re.compile(
        r"""(?x)
        (?:open|Path|read_text|load_text|load_source|load_corpus)
        \s*\(\s*
        (?:r|b)? ['"]([^'"]+\.txt)['"]
        """,
    )
    # Known token hints — if a script mentions a non-allowlisted author
    # or title by name, that is a strong signal of an unlicensed source.
    hint_re = re.compile(
        r"(?i)\b(gutenberg|schliemann|troy|lecarre|tinker|tailor|"
        r"berlin_wall|great_big_story|wtz_00_cities|"
        r"book_cipher|isbn_hunt|thematic_running|foreign_running|"
        r"digraph_running)\b"
    )
    # Explicit direct-id declaration: `SOURCE_ID = "k1_plaintext"` bypasses
    # the path heuristic and goes straight to check_corpus_source() with
    # is_source_id=True.  Use this when the script consumes an allowlisted
    # source that cannot be expressed as a file literal (e.g. inline K1/K2/K3
    # plaintext, `os.path.join`-built paths).  Authors of amended scripts MUST
    # ensure the declared id matches what the code actually loads.
    source_id_re = re.compile(
        r"""(?x)
        ^ \s* (?:SOURCE_ID | source_id | CORPUS_SOURCE_ID)
        \s* = \s*
        (?:r|b)? ['"]([^'"]+)['"]
        """,
        re.MULTILINE,
    )
    # Opt-out marker for scripts whose hypothesis does NOT involve consuming
    # an external text as a running key — e.g. SA that optimizes a key
    # directly for English-quadgram quality (E-FRAC-54 architecture), or
    # analysis-only DOF scripts.  These scripts legitimately have no
    # corpus source, and the policy should not flag them as UNCLEAR.
    no_corpus_re = re.compile(
        r"""(?x)
        ^ \s* (?:NO_CORPUS_SOURCE | no_corpus_source)
        \s* = \s*
        True \b
        """,
        re.MULTILINE,
    )

    certificates = []
    rejected = 0
    accepted = 0
    unclear = 0

    for script in script_paths:
        try:
            src = script.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # ── Fast-path 1: explicit NO_CORPUS_SOURCE opt-out ───────────────
        # Scripts whose hypothesis does not involve an external text
        # (quadgram-guided SA, DOF analysis, etc.) declare themselves
        # exempt from the corpus policy.  We emit an AdmissibilityCertificate
        # so the status is visible, not a silent pass.
        if no_corpus_re.search(src):
            accepted += 1
            certificates.append(AdmissibilityCertificate(
                family=f"running_key/{script.name}",
                summary=(
                    f"Script {script.name} declares NO_CORPUS_SOURCE — "
                    f"hypothesis does not consume an external text."
                ),
                assumptions=[
                    "Script-declared exemption: the running-key hypothesis "
                    "is key-space search (e.g. quadgram-guided SA), not "
                    "source-text guessing",
                ],
                evidence={
                    "script": script.name,
                    "declaration": "NO_CORPUS_SOURCE = True",
                },
                solver="manual",
            ))
            print(f"  ACCEPT  {script.name}  (NO_CORPUS_SOURCE opt-out)")
            continue

        # ── Fast-path 2: explicit SOURCE_ID declaration ──────────────────
        # Bypasses the path heuristic and goes directly to the allowlist.
        source_id_matches = source_id_re.findall(src)
        if source_id_matches:
            any_accepted = False
            script_rejections = []
            for sid in source_id_matches:
                ok, cert = check_corpus_source(
                    sid, family=f"running_key/{script.name}",
                    is_source_id=True,
                )
                if ok:
                    any_accepted = True
                    break
                script_rejections.append(cert)
            if any_accepted:
                accepted += 1
                certificates.append(AdmissibilityCertificate(
                    family=f"running_key/{script.name}",
                    summary=(
                        f"Script {script.name} declares SOURCE_ID"
                        f"={source_id_matches[0]!r} which is on the "
                        f"corpus allowlist."
                    ),
                    assumptions=[
                        "Script-declared source_id matches an allowlisted "
                        "CorpusLicense entry",
                    ],
                    evidence={
                        "script": script.name,
                        "source_ids": source_id_matches,
                    },
                    solver="manual",
                ))
                print(f"  ACCEPT  {script.name}  (SOURCE_ID={source_id_matches[0]!r})")
                continue
            # If all declared SOURCE_IDs are rejected, fall through to
            # rejection path below.
            rejected += 1
            certificates.extend(script_rejections)
            print(f"  REJECT  {script.name}  (SOURCE_ID {source_id_matches!r} not on allowlist)")
            continue

        # Collect plausible source-path literals from the script body.
        candidates = set()
        for regex in (source_re, open_re):
            for m in regex.finditer(src):
                path = m.group(1)
                # Skip obvious non-source paths
                if any(skip in path.lower() for skip in (
                    "results/", ".sqlite", ".db", ".json", "__pycache__",
                    "exhaustion", "manifest", "ledger",
                )):
                    continue
                if path.endswith((".py", ".toml", ".yml", ".yaml")):
                    continue
                candidates.add(path)

        # Scripts with unknown-author hints are implicitly unlicensed.
        hint_matches = sorted(set(m.group(1).lower()
                                  for m in hint_re.finditer(src)))

        if not candidates and not hint_matches:
            # Source cannot be statically identified AND no suggestive
            # hints.  Record as ASSUMPTION_UNMET — the script needs
            # manual provenance review before it is admissible.
            unclear += 1
            certificates.append(EliminationCertificate(
                family=f"running_key/{script.name}",
                reason=EliminationReason.ASSUMPTION_UNMET,
                summary=(
                    f"Script {script.name} does not declare a statically "
                    f"identifiable source — manual provenance review "
                    f"required before running under corpus policy."
                ),
                assumptions=[
                    "Running-key scripts must expose source_path/source_id "
                    "as a statically scannable literal or an allowlisted "
                    "source_id parameter",
                ],
                evidence={
                    "script": script.name,
                    "static_scan": "no source literal found",
                },
                solver="manual",
                is_exact=False,
            ))
            print(f"  UNCLEAR {script.name}  (no static source)")
            continue

        if not candidates and hint_matches:
            # Hints only.  Reject as unlicensed (more strict than
            # "unclear") because the hints themselves imply unlicensed
            # authors or themes.
            rejected += 1
            certificates.append(EliminationCertificate(
                family=f"running_key/{script.name}",
                reason=EliminationReason.CORPUS_POLICY_VIOLATION,
                summary=(
                    f"Script {script.name} references unlicensed themes "
                    f"or authors {hint_matches} and declares no "
                    f"allowlisted source."
                ),
                assumptions=[
                    "Running-key sources must be publicly justified",
                    "Thematic hints are not substitutes for a licensed source",
                ],
                evidence={
                    "script": script.name,
                    "hint_matches": hint_matches,
                },
                solver="manual",
                is_exact=False,
            ))
            print(f"  REJECT  {script.name}  (hints only: {hint_matches})")
            continue

        # For each candidate path, run the corpus policy check.  A script
        # is admissible iff at least one of its source candidates maps
        # to a licensed entry.
        any_accepted = False
        script_rejections = []
        for cand in sorted(candidates):
            ok, cert = check_corpus_source(
                cand, family=f"running_key/{script.name}",
            )
            if ok:
                any_accepted = True
                break
            else:
                script_rejections.append(cert)

        if any_accepted:
            accepted += 1
            print(f"  ACCEPT  {script.name}  (licensed source found)")
        else:
            rejected += 1
            # Emit one certificate per script naming all candidates.
            merged = EliminationCertificate(
                family=f"running_key/{script.name}",
                reason=EliminationReason.CORPUS_POLICY_VIOLATION,
                summary=(
                    f"Script {script.name} references source(s) "
                    f"{sorted(candidates)} none of which are on the "
                    f"corpus allowlist."
                ),
                assumptions=[
                    "Running-key sources must be publicly justified",
                    "Arbitrary 'guess a book' search is not admissible",
                ],
                evidence={
                    "script": script.name,
                    "candidates": sorted(candidates),
                    "individual_rejection_summaries": [
                        c.summary for c in script_rejections
                    ],
                },
                solver="manual",
                is_exact=False,
            )
            certificates.append(merged)
            print(f"  REJECT  {script.name}  ({len(candidates)} candidate(s))")

    print(
        f"  {accepted} accepted, {rejected} rejected, "
        f"{unclear} without identifiable source literals"
    )

    return {
        "n_scripts": len(script_paths),
        "accepted": accepted,
        "rejected": rejected,
        "unclear": unclear,
        "certificates": [_cert_to_plain(c) for c in certificates],
    }


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    periodic = run_periodic_campaign()
    (RESULTS_DIR / "periodic_additive.json").write_text(
        json.dumps(periodic, indent=2, sort_keys=True), encoding="utf-8",
    )

    running_key = run_running_key_policy_campaign()
    (RESULTS_DIR / "running_key_policy.json").write_text(
        json.dumps(running_key, indent=2, sort_keys=True), encoding="utf-8",
    )

    print("\n=== Summary ===")
    print(
        f"  Periodic additive: {periodic['n_elim']}/{periodic['n_total']} "
        f"(variant, period) pairs eliminated with formal UNSAT"
    )
    print(
        f"  Running-key scripts: {running_key.get('rejected', 0)}/"
        f"{running_key.get('n_scripts', 0)} rejected by corpus policy"
    )
    print(f"\n  Output: {RESULTS_DIR}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
