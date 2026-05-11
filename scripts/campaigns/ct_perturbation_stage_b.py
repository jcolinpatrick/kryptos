#!/usr/bin/env python3
"""CT-Perturbation Stage B — campaign runner stub + synthetic-recovery test.

Status: STUB v0.2 (2026-05-06). The full Stage B sweep runner is still
deferred per ``docs/campaigns/ct_perturbation_stage_b_prereg.md``; this
revision adds the prereg's mandatory pre-launch synthetic-recovery
test (§7) without yet building the H2 × keyword × family × alphabet
sweep loop. The full v1 sweep runner is its own brainstorm/plan/build
cycle (Stage A's runner is 1836 lines; Stage B v1 will be similar).

What this module does:
    - Validates the ``--ambiguous-positions PATH`` JSON manifest using
      the framework's ``load_ambiguous_positions`` schema validator.
    - Computes the Stage B universe size for the supplied ``A``.
    - Runs the prereg §7 synthetic-recovery test:
        §7.1 Selective — plant H2 corruption at two crib positions,
              verify the H2-constrained sweep over ``A* = {p1, p2}``
              recovers the original encryption (alert fires for the
              planted (p1, old, new), (p2, old, new) tuple).
        §7.2 Structural — plant H2 corruption at non-crib positions,
              verify no false alert fires AND Bean state is unchanged
              from canonical (Bean is invariant under non-crib edits).
      Each case runs against BOTH cipher fixtures the prereg requires:
      Vigenère + AZ + ``PALIMPSEST`` and Beaufort + KA + ``KRYPTOS``.
    - Refuses ``--execute-full`` until the v1 sweep runner lands, with
      an instructive message.

What this module does NOT do:
    - Enumerate the full Stage B universe and execute it. That is the
      v1 sweep loop and is deferred.
    - Use the parallel worker pool, JSONL writer, or checkpointing
      infrastructure from Stage A. The recovery test is single-process
      and runs the H2 enumeration directly via the helpers in
      ``kryptosbot.ct_perturbation``.

Exit codes:
    0  manifest validated; recovery test passed (if requested);
       dry-run summary printed.
    2  configuration error (missing arg, schema invalid, k>20 without
       override, etc.).
    3  ``--execute-full`` requested but full runner not yet implemented.
    4  ``--synthetic-recovery-test`` requested and one or both probes
       failed.

Usage:
    PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \\
        --ambiguous-positions PATH/TO/A.json \\
        [--allow-large-ambiguous-set] \\
        [--synthetic-recovery-test [--recovery-artifact-dir DIR]] \\
        [--dry-run]

The full runner v1 must be specified separately (brainstorm + writing-plans
+ subagent-driven build) before ``--execute-full`` is supported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Standalone bootstrap (script lives 2 levels deep under repo root).
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


from kryptos.kernel.alphabet import AZ as _AZ, KA as _KA  # noqa: E402
from kryptos.kernel.constants import CRIB_DICT, CT  # noqa: E402
from kryptos.kernel.transforms.vigenere import (  # noqa: E402
    CipherVariant,
    encrypt_text,
)
from kryptosbot.ct_perturbation import (  # noqa: E402
    AlertPolicy,
    AmbiguousPositionsManifest,
    CANONICAL_CRIB_DICT,
    CTVariantH2,
    ScorerContext,
    SUPPORTED_ALPHABET_KINDS,
    SUPPORTED_FAMILIES,
    TopNHeap,
    derive_bean_constraints,
    enumerate_hamming2_variants_constrained,
    load_ambiguous_positions,
    score_candidate_ct_parametric,
    stage_b_universe_size,
)
from scripts.campaigns.ct_perturbation_stage_a import (  # noqa: E402
    KeywordSource,
    atomic_write_json,
    load_keywords,
    _git_commit,
    _module_sha,
)


_K_MAX_DEFAULT = 20  # prereg §3.3
_PREREG_PATH = "docs/campaigns/ct_perturbation_stage_b_prereg.md"
_RECOVERY_ARTIFACT_DEFAULT = (
    _ROOT / "results" / "ct_perturbation_stage_b" / "_synthetic_recovery"
)

# Fixed cipher fixtures the prereg §7 requires. Both must be tested in
# the selective probe.
_RECOVERY_FIXTURES: tuple[dict[str, Any], ...] = (
    {
        "label": "vigenere_AZ_PALIMPSEST",
        "family": CipherVariant.VIGENERE,
        "alphabet_kind": "AZ",
        "alphabet": _AZ,
        "keyword": "PALIMPSEST",
    },
    {
        "label": "beaufort_KA_KRYPTOS",
        "family": CipherVariant.BEAUFORT,
        "alphabet_kind": "KA",
        "alphabet": _KA,
        "keyword": "KRYPTOS",
    },
)

# Crib positions used to plant the §7.1 selective probe. Both must be
# in the canonical crib set; we use the EAST/BERLIN boundary positions
# so the planted correction overlaps both crib regions.
_SELECTIVE_PROBE_POSITIONS: tuple[int, int] = (21, 63)

# Non-crib positions used for the §7.2 structural probe. Chosen from
# regions outside the cribs (positions 0-20, 34-62, 74-96).
_STRUCTURAL_PROBE_POSITIONS: tuple[int, int] = (10, 80)


# ─── sweep config ────────────────────────────────────────────────────────


@dataclass
class SweepConfig:
    """Internal config bundle for the Stage B H2 sweep driver.

    Mirrors Stage A's SweepConfig but typed against ``AmbiguousPositionsManifest``
    and uses ``max_h2_variants`` rather than the H1 ``max_ct_variants`` cap.
    """
    ct: str
    keywords: list[str]
    manifest: AmbiguousPositionsManifest | None
    families: tuple[CipherVariant, ...] = SUPPORTED_FAMILIES
    alphabet_kinds: tuple[str, ...] = SUPPORTED_ALPHABET_KINDS
    universe_size: int = 1
    policy: AlertPolicy = field(default_factory=AlertPolicy)
    include_h0: bool = False
    max_h2_variants: int | None = None
    max_configs: int | None = None
    keyword_limit: int | None = None
    crib_dict: dict[int, str] = field(default_factory=lambda: dict(CANONICAL_CRIB_DICT))
    run_id_for_logging: str = ""


# ─── sweep state accumulators ────────────────────────────────────────────


@dataclass
class SweepResults:
    """Accumulator for H2 sweep state."""
    candidates_evaluated: int = 0
    alerts: list[dict[str, Any]] = field(default_factory=list)
    watchlist: list[dict[str, Any]] = field(default_factory=list)
    top_n: TopNHeap = field(default_factory=lambda: TopNHeap(capacity=100))
    bean_pass_count: int = 0
    by_family_alert_count: dict[str, int] = field(default_factory=dict)
    by_alphabet_alert_count: dict[str, int] = field(default_factory=dict)
    rejection_reason_counts: dict[str, int] = field(default_factory=dict)
    variants_completed: int = 0
    last_completed_variant_id: str | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class VariantEvalResult:
    """Per-H2-variant result emitted by evaluate_one_h2_variant."""
    variant_id: str
    n_evaluated: int
    alerts: list[dict[str, Any]]
    watchlist: list[dict[str, Any]]
    top_candidates: list[tuple[float, dict[str, Any]]]
    bean_pass_count: int
    rejection_reason_counts: dict[str, int]
    trace_rows: list[dict[str, Any]]


# ─── synthetic recovery test ─────────────────────────────────────────────


def _build_synthetic_pt() -> str:
    """Build a 97-char synthetic plaintext that places the canonical 24
    cribs at canonical positions and fills non-crib slots with neutral
    filler. The filler matters only insofar as it determines the
    encrypted-CT bytes outside cribs; the recovery test does not score
    on filler content.
    """
    pt_chars = ["X"] * len(CT)
    for pos, ch in CRIB_DICT.items():
        pt_chars[pos] = ch
    return "".join(pt_chars)


def _swap_to_non_canonical(ct_char: str) -> str:
    """Return a letter that is alphabetic, uppercase, and != ct_char."""
    return "A" if ct_char != "A" else "B"


def _build_h2_corrupt_ct(
    true_ct: str, pos1: int, pos2: int
) -> tuple[str, dict[int, tuple[str, str]]]:
    """Apply Hamming-2 corruption at positions pos1 < pos2.

    Returns (corrupt_ct, {pos: (true_char, corrupt_char)}). The
    corruption is deterministic: each affected position receives 'A'
    unless that equals the true character, in which case 'B'.
    """
    if pos1 >= pos2:
        raise ValueError(f"pos1 must be less than pos2, got {pos1} >= {pos2}")
    new1 = _swap_to_non_canonical(true_ct[pos1])
    new2 = _swap_to_non_canonical(true_ct[pos2])
    corrupt = (
        true_ct[:pos1]
        + new1
        + true_ct[pos1 + 1 : pos2]
        + new2
        + true_ct[pos2 + 1 :]
    )
    return corrupt, {pos1: (true_ct[pos1], new1), pos2: (true_ct[pos2], new2)}


def _ambiguous_manifest_from_positions(
    positions: Iterable[int], rationale_per_position: dict[str, str],
) -> AmbiguousPositionsManifest:
    """Build an AmbiguousPositionsManifest in-memory for the recovery test.

    The recovery test does not load from disk; it constructs a manifest
    matching the operator-supplied schema directly. The schema's
    `archive_provenance` requirement is satisfied with a synthetic-test
    sentinel that disqualifies this manifest from real-K4 use.
    """
    sorted_positions = sorted(set(int(p) for p in positions))
    return AmbiguousPositionsManifest(
        schema_version="ct_perturbation_stage_b.ambiguous_positions.v1",
        archive_provenance={
            "primary_source": "SYNTHETIC_RECOVERY_TEST_NOT_FOR_REAL_K4",
            "image_hashes": [],
            "evaluator": "synthetic_recovery_test",
            "evaluation_date": time.strftime("%Y-%m-%d"),
            "method": "in-memory test fixture, not archive evidence",
        },
        positions=tuple(sorted_positions),
        rationale_per_position=dict(rationale_per_position),
        checksum_sha256=hashlib.sha256(
            ",".join(str(p) for p in sorted_positions).encode("utf-8")
        ).hexdigest(),
    )


def _selective_probe_for_fixture(
    fixture: dict[str, Any],
    pos_pair: tuple[int, int] = _SELECTIVE_PROBE_POSITIONS,
) -> dict[str, Any]:
    """Run the §7.1 selective recovery probe for one cipher fixture."""
    pos1, pos2 = sorted(pos_pair)
    family: CipherVariant = fixture["family"]
    alphabet = fixture["alphabet"]
    alphabet_kind: str = fixture["alphabet_kind"]
    keyword: str = fixture["keyword"]

    synthetic_pt = _build_synthetic_pt()
    key = alphabet.encode(keyword)
    true_ct = encrypt_text(synthetic_pt, key, variant=family, alphabet=alphabet)

    # The "carved" CT is true_ct corrupted at pos1, pos2.
    corrupt_ct, corruption_map = _build_h2_corrupt_ct(true_ct, pos1, pos2)

    # Ambiguous-position set planted to match the corruption.
    manifest = _ambiguous_manifest_from_positions(
        positions=[pos1, pos2],
        rationale_per_position={
            str(pos1): f"selective probe, pos1={pos1} (in EAST crib region)",
            str(pos2): f"selective probe, pos2={pos2} (in BERLIN crib region)",
        },
    )

    # Universe size for Bonferroni in the recovery test. With a 1-element
    # keyword pool and one (family, alphabet) combination, the universe
    # is exactly the H2 variant count over A.
    h2_variants = list(enumerate_hamming2_variants_constrained(corrupt_ct, manifest))
    universe_size = len(h2_variants) * 1 * 1 * 1

    policy = AlertPolicy(
        h1_require_full_cribs=True,
        h1_require_bean_pass=True,
        h1_require_ngram_floor=False,  # no ngram null in recovery test
        h1_p_adjusted_threshold=1.0,   # bypass null-cache requirement
        require_null_for_alert=False,
    )

    candidates_evaluated = 0
    matching_alert: dict[str, Any] | None = None
    alerts_total = 0

    for variant in h2_variants:
        ctx = ScorerContext.build(
            variant=variant,
            crib_dict=dict(CRIB_DICT),
            ngram_dist=None,
            alphabet_kind=alphabet_kind,
        )
        score, _pt = score_candidate_ct_parametric(
            ctx,
            keyword=keyword,
            family=family,
            alphabet_kind=alphabet_kind,
            universe_size=universe_size,
            policy=policy,
            ngram_scorer=None,
        )
        candidates_evaluated += 1
        if score.alert_class == "alert":
            alerts_total += 1
            # Match against the planted correction signature.
            matches_planted = (
                variant.pos1 == pos1
                and variant.pos2 == pos2
                and variant.new1 == true_ct[pos1]
                and variant.new2 == true_ct[pos2]
            )
            if matches_planted and matching_alert is None:
                matching_alert = {
                    "variant_id": variant.variant_id,
                    "pos1": variant.pos1,
                    "old1": variant.old1,
                    "new1": variant.new1,
                    "pos2": variant.pos2,
                    "old2": variant.old2,
                    "new2": variant.new2,
                    "crib_score": score.crib_score,
                    "crib_total": score.crib_total,
                    "bean_passed": score.bean_passed,
                }

    return {
        "fixture": fixture["label"],
        "pos1": pos1,
        "pos2": pos2,
        "expected_correction_pos1": (true_ct[pos1], corruption_map[pos1][1]),
        "expected_correction_pos2": (true_ct[pos2], corruption_map[pos2][1]),
        "h2_variants_enumerated": len(h2_variants),
        "candidates_evaluated": candidates_evaluated,
        "alerts_total": alerts_total,
        "matching_alert": matching_alert,
        "passed": matching_alert is not None,
        "true_ct_sha256": hashlib.sha256(true_ct.encode("utf-8")).hexdigest(),
        "corrupt_ct_sha256": hashlib.sha256(corrupt_ct.encode("utf-8")).hexdigest(),
    }


def _structural_probe_for_fixture(
    fixture: dict[str, Any],
    pos_pair: tuple[int, int] = _STRUCTURAL_PROBE_POSITIONS,
) -> dict[str, Any]:
    """Run the §7.2 structural recovery probe for one cipher fixture.

    The structural probe operates on the REAL K4 ciphertext (not a
    synthetic encryption) because the prereg's structural argument is
    about ensuring the Stage B sweep does not false-flag random
    non-crib perturbations of the real CT. With the synthetic
    encryption used by the selective probe, decrypting any H2 variant
    at non-crib positions trivially yields canonical cribs at canonical
    positions (Vigenère/Beaufort is position-local), which is a
    structural artifact of the synthetic fixture rather than a
    cryptographic property worth testing.

    Verifies:
      (a) no alert fires for the H2-constrained sweep over A* = {q1, q2}
          when the underlying CT is real K4 (random keyword decryption
          rarely produces full crib match);
      (b) Bean constraint set is unchanged when only non-crib positions
          are edited (a structural property of Bean we spot-check by
          comparing canonical-CT and corrupt-CT derivations).
    """
    pos1, pos2 = sorted(pos_pair)
    crib_positions = set(CRIB_DICT.keys())
    if pos1 in crib_positions or pos2 in crib_positions:
        raise ValueError(
            f"structural probe positions ({pos1}, {pos2}) must be non-crib"
        )

    family: CipherVariant = fixture["family"]
    alphabet = fixture["alphabet"]
    alphabet_kind: str = fixture["alphabet_kind"]
    keyword: str = fixture["keyword"]

    # Use REAL K4 CT for the structural probe.
    true_ct = CT
    corrupt_ct, _ = _build_h2_corrupt_ct(true_ct, pos1, pos2)

    manifest = _ambiguous_manifest_from_positions(
        positions=[pos1, pos2],
        rationale_per_position={
            str(pos1): f"structural probe, pos1={pos1} (non-crib)",
            str(pos2): f"structural probe, pos2={pos2} (non-crib)",
        },
    )

    h2_variants = list(enumerate_hamming2_variants_constrained(corrupt_ct, manifest))
    universe_size = max(1, len(h2_variants))

    policy = AlertPolicy(
        h1_require_full_cribs=True,
        h1_require_bean_pass=True,
        h1_require_ngram_floor=False,
        h1_p_adjusted_threshold=1.0,
        require_null_for_alert=False,
    )

    bean_pass_count = 0
    alert_count = 0
    candidates_evaluated = 0

    for variant in h2_variants:
        ctx = ScorerContext.build(
            variant=variant,
            crib_dict=dict(CRIB_DICT),
            ngram_dist=None,
            alphabet_kind=alphabet_kind,
        )
        score, _pt = score_candidate_ct_parametric(
            ctx,
            keyword=keyword,
            family=family,
            alphabet_kind=alphabet_kind,
            universe_size=universe_size,
            policy=policy,
            ngram_scorer=None,
        )
        candidates_evaluated += 1
        if score.bean_passed:
            bean_pass_count += 1
        if score.alert_class == "alert":
            alert_count += 1

    # Bean invariance spot-check: derive Bean constraints over canonical
    # CT and over the corrupt CT (both H2 outside cribs); compare. The
    # design memo's argument is that non-crib edits do not change Bean
    # state at the crib positions.
    canonical_eq, canonical_ineq, canonical_linear = derive_bean_constraints(
        CT, dict(CRIB_DICT), alphabet=alphabet,
    )
    corrupt_eq, corrupt_ineq, corrupt_linear = derive_bean_constraints(
        corrupt_ct, dict(CRIB_DICT), alphabet=alphabet,
    )
    bean_invariance_holds = (
        canonical_eq == corrupt_eq
        and canonical_ineq == corrupt_ineq
        and canonical_linear == corrupt_linear
    )

    return {
        "fixture": fixture["label"],
        "pos1": pos1,
        "pos2": pos2,
        "h2_variants_enumerated": len(h2_variants),
        "candidates_evaluated": candidates_evaluated,
        "bean_pass_count": bean_pass_count,
        "alerts_total": alert_count,
        "bean_invariance_holds": bean_invariance_holds,
        "passed": (alert_count == 0) and bean_invariance_holds,
        "true_ct_sha256": hashlib.sha256(true_ct.encode("utf-8")).hexdigest(),
        "corrupt_ct_sha256": hashlib.sha256(corrupt_ct.encode("utf-8")).hexdigest(),
    }


def synthetic_recovery_test(
    *,
    artifact_dir: Path | None = None,
) -> dict[str, Any]:
    """Run the prereg §7 synthetic-recovery test.

    Both probes run against both cipher fixtures (Vigenère + AZ +
    PALIMPSEST and Beaufort + KA + KRYPTOS). Writes
    ``recovery_test_report.json`` to ``artifact_dir`` (default
    ``results/ct_perturbation_stage_b/_synthetic_recovery/``).

    Returns a report dict. ``passed`` is True iff both probes pass for
    both fixtures.
    """
    if artifact_dir is None:
        artifact_dir = _RECOVERY_ARTIFACT_DEFAULT
    artifact_dir.mkdir(parents=True, exist_ok=True)

    selective_results = [
        _selective_probe_for_fixture(fixture)
        for fixture in _RECOVERY_FIXTURES
    ]
    structural_results = [
        _structural_probe_for_fixture(fixture)
        for fixture in _RECOVERY_FIXTURES
    ]

    selective_passed = all(r["passed"] for r in selective_results)
    structural_passed = all(r["passed"] for r in structural_results)
    overall_passed = selective_passed and structural_passed

    report = {
        "schema_version": "ct_perturbation_stage_b.recovery_test_report.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "campaign_id": "ct_perturbation_stage_b",
        "prereg_section": "§7",
        "passed": overall_passed,
        "selective_passed": selective_passed,
        "structural_passed": structural_passed,
        "selective_probes": selective_results,
        "structural_probes": structural_results,
        "explanation": (
            "§7.1 selective: plant H2 corruption at two crib positions, "
            "verify the H2-constrained sweep over A* = {p1, p2} recovers "
            "the original encryption. §7.2 structural: plant H2 outside "
            "cribs, verify no false alert AND Bean state invariant."
        ),
    }

    out_path = artifact_dir / "recovery_test_report.json"
    out_path.write_text(json.dumps(report, indent=2))
    return report


# ─── stub CLI ────────────────────────────────────────────────────────────


def _build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "CT-Perturbation Stage B — STUB v0.2. Manifest validation + "
            "synthetic-recovery test. Full sweep runner deferred. See "
            f"{_PREREG_PATH}."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--ambiguous-positions",
        type=Path,
        required=False,
        help=(
            "Path to operator-predeclared ambiguous-position JSON. "
            "Required for manifest validation; not required for "
            "--synthetic-recovery-test (which constructs its own A "
            "in-memory). Schema: ct_perturbation_stage_b.ambiguous_positions.v1. "
            "See prereg §3.2."
        ),
    )
    ap.add_argument(
        "--allow-large-ambiguous-set",
        action="store_true",
        help=f"Permit |A| > {_K_MAX_DEFAULT} (default refuses).",
    )
    ap.add_argument(
        "--keyword-count",
        type=int,
        default=719,
        help="Keyword pool size for universe-size estimation (default 719).",
    )
    ap.add_argument(
        "--synthetic-recovery-test",
        action="store_true",
        help=(
            "Run the prereg §7 synthetic-recovery test (selective + "
            "structural probes against both cipher fixtures). Writes "
            "recovery_test_report.json to --recovery-artifact-dir."
        ),
    )
    ap.add_argument(
        "--recovery-artifact-dir",
        type=Path,
        default=None,
        help=(
            "Output directory for the recovery test report (default: "
            "results/ct_perturbation_stage_b/_synthetic_recovery/)."
        ),
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate manifest and print summary; do not attempt execution.",
    )
    ap.add_argument(
        "--execute-full",
        action="store_true",
        help=(
            "Reserved for v1 runner; in this stub, exits with code 3 and "
            "instructions for the v1 build."
        ),
    )
    return ap


def _print_summary(manifest: AmbiguousPositionsManifest, n_keywords: int) -> None:
    universe = stage_b_universe_size(manifest, n_keywords=n_keywords)
    k = len(manifest.positions)
    print()
    print("=" * 72)
    print("  CT-Perturbation Stage B — manifest validated")
    print("=" * 72)
    print(f"  schema_version:      {manifest.schema_version}")
    print(
        f"  primary_source:      "
        f"{manifest.archive_provenance.get('primary_source', '(unset)')}"
    )
    print(
        f"  evaluator:           "
        f"{manifest.archive_provenance.get('evaluator', '(unset)')}"
    )
    print(
        f"  evaluation_date:     "
        f"{manifest.archive_provenance.get('evaluation_date', '(unset)')}"
    )
    print(f"  k = |A|:             {k}")
    print(f"  positions:           {sorted(manifest.positions)}")
    print()
    print("  Universe sizing (per prereg §3.3):")
    for key, value in universe.items():
        if isinstance(value, int):
            print(f"    {key:30s} {value:>15,}")
        else:
            print(f"    {key:30s} {value}")
    print()
    print("=" * 72)
    print("  Status: STUB v0.2 — synthetic-recovery test wired; full")
    print("  sweep runner not yet built.")
    print(f"  See {_PREREG_PATH} for full campaign spec.")
    print("=" * 72)
    print()


def _print_recovery_report(report: dict[str, Any]) -> None:
    print()
    print("=" * 72)
    print("  Synthetic recovery test (prereg §7)")
    print("=" * 72)
    print(f"  overall passed:         {report['passed']}")
    print(f"  selective probes pass:  {report['selective_passed']}")
    print(f"  structural probes pass: {report['structural_passed']}")
    print()
    print("  Selective (§7.1):")
    for probe in report["selective_probes"]:
        ok = "PASS" if probe["passed"] else "FAIL"
        print(
            f"    [{ok}] {probe['fixture']:32s} "
            f"variants={probe['h2_variants_enumerated']:5d}  "
            f"alerts={probe['alerts_total']}  "
            f"matched_planted={probe['matching_alert'] is not None}"
        )
    print()
    print("  Structural (§7.2):")
    for probe in report["structural_probes"]:
        ok = "PASS" if probe["passed"] else "FAIL"
        print(
            f"    [{ok}] {probe['fixture']:32s} "
            f"variants={probe['h2_variants_enumerated']:5d}  "
            f"alerts={probe['alerts_total']}  "
            f"bean_invariant={probe['bean_invariance_holds']}"
        )
    print()


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)

    # If --synthetic-recovery-test is requested, run it FIRST. The recovery
    # test does not require an operator-supplied --ambiguous-positions
    # because it constructs its own ambiguous-position set in-memory.
    if args.synthetic_recovery_test:
        report = synthetic_recovery_test(
            artifact_dir=args.recovery_artifact_dir,
        )
        _print_recovery_report(report)
        if not report["passed"]:
            print(
                "\nERROR: synthetic-recovery test failed. The Stage B "
                "harness must pass §7 before --execute-full is "
                "authorized.",
                file=sys.stderr,
            )
            return 4
        # If only --synthetic-recovery-test was requested (no manifest
        # validation), exit successfully here.
        if args.ambiguous_positions is None:
            return 0

    # Manifest validation path (requires --ambiguous-positions).
    if args.ambiguous_positions is None:
        if not args.synthetic_recovery_test:
            print(
                "ERROR: --ambiguous-positions is required unless "
                "running --synthetic-recovery-test alone.",
                file=sys.stderr,
            )
            print(f"\nSee {_PREREG_PATH} §3 for the schema.", file=sys.stderr)
            return 2
        return 0  # recovery-test-only path already handled

    if not args.ambiguous_positions.exists():
        print(
            f"ERROR: --ambiguous-positions path does not exist: "
            f"{args.ambiguous_positions}",
            file=sys.stderr,
        )
        print(
            f"\nStage B requires an operator-predeclared ambiguous-position "
            f"set per prereg §3.\nSee {_PREREG_PATH} for the schema.",
            file=sys.stderr,
        )
        return 2

    try:
        manifest = load_ambiguous_positions(
            args.ambiguous_positions,
            allow_large=args.allow_large_ambiguous_set,
        )
    except (ValueError, json.JSONDecodeError) as e:
        print(
            f"ERROR: --ambiguous-positions failed schema validation: {e}",
            file=sys.stderr,
        )
        print(
            f"\nSee {_PREREG_PATH} §3.2 for the v1 schema and §3.1 for the "
            f"operator-decision contract.",
            file=sys.stderr,
        )
        return 2

    k = len(manifest.positions)
    if k > _K_MAX_DEFAULT and not args.allow_large_ambiguous_set:
        print(
            f"ERROR: |A| = {k} exceeds k_max_default = {_K_MAX_DEFAULT}; "
            f"pass --allow-large-ambiguous-set to override.",
            file=sys.stderr,
        )
        print(
            f"\nLarger archive evidence sets monotonically increase the "
            f"search universe; see prereg §3.3 cardinality table.",
            file=sys.stderr,
        )
        return 2

    _print_summary(manifest, n_keywords=args.keyword_count)

    if args.execute_full:
        print(
            "\nERROR: --execute-full is not supported in this stub (v0.2).",
            file=sys.stderr,
        )
        print(
            "\nThe full Stage B sweep runner is a separate project requiring "
            "its own brainstorm/plan/build cycle (Stage A's runner is 1836 "
            f"lines; Stage B will be similar). See {_PREREG_PATH} §9 for "
            "the binding CLI spec.",
            file=sys.stderr,
        )
        print(
            "\nUntil then, this stub validates manifests, computes universe "
            "sizes, and runs the prereg §7 synthetic-recovery test.",
            file=sys.stderr,
        )
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
