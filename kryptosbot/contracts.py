"""
Centralized contract validation for all controller boundaries.

Every structured payload entering the controller — worker results,
theorist proposals, tool-mediated updates — passes through validators
here. The controller never acts on raw text; it acts on ParseResult.value
only when ParseResult.is_valid is True.

POLICY: Fail closed. If a payload cannot be validated into the expected
typed contract, the result is an explicit error. No heuristic inference
from prose. No silent fallback to default enum values. Raw text is
preserved in ParseResult.raw for audit/debugging only.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Generic, Optional, TYPE_CHECKING, TypeVar

from .models import (
    TheoryRecord,
    WorkerContract, WorkerStatus,
)

if TYPE_CHECKING:
    from .problem_context import ProblemContext

logger = logging.getLogger("kryptosbot.contracts")


# ---------------------------------------------------------------------------
# Independent verification — kernel always overrules worker self-report
# ---------------------------------------------------------------------------
#
# WHY: Workers are LLMs writing JSON. They can (and do) fabricate
# crib_score=24, bean_passed=True without actually running the kernel.
# Day-4 verification surfaced a worker that emitted a CT73-space plaintext
# with cribs textually pasted in, claimed crib_score=24 and bean_passed=True,
# and triggered a BREAKTHROUGH alert despite score=0.0 on the same line.
#
# POLICY: Never trust worker self-reported crib_score / bean_passed / score.
# After parsing the worker JSON, recompute these fields from best_plaintext
# against the kernel. If the worker's plaintext is the wrong length, mark the
# contract unverifiable and zero the score fields so no alert can fire.

# Additive cipher variants tried during Bean verification, in the order
# they are tested. The first variant that yields a Bean-PASS keystream
# wins and its name is recorded on the contract's bean_variant field.
# Order is fixed so test assertions (and audit logs) can rely on it.
_BEAN_VARIANTS: tuple[tuple[str, Any], ...] = (
    ("vigenere",         lambda c, p: (c - p) % 26),  # K = CT - PT
    ("beaufort",         lambda c, p: (c + p) % 26),  # K = CT + PT
    ("variant_beaufort", lambda c, p: (p - c) % 26),  # K = PT - CT
)


def _safe_int(val: Any) -> int:
    """Best-effort coercion of a worker-supplied value to int.

    WorkerContract is sometimes constructed outside validate_worker_contract
    (e.g. by tests, by direct from_dict, by older stored data). A field
    that holds a non-numeric string would cause int(val or 0) to crash
    unhandled, taking the whole verifier with it. This helper fails closed
    to 0 on any TypeError/ValueError, which is consistent with the
    verifier's "refuse to trust garbage" posture.
    """
    try:
        return int(val or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(val: Any) -> float:
    """Best-effort coercion of a worker-supplied value to float. See _safe_int."""
    try:
        return float(val or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _verify_against_kernel(contract: WorkerContract) -> None:
    """Recompute crib_score, bean_passed, and score from best_plaintext.

    Mutates the contract in place. If the worker self-reported values
    disagree with the kernel, saves them to worker_self_report and sets
    fields_overwritten=True. If verification cannot run (wrong length,
    import failure), sets verification_error and zeroes the score fields.

    Also populates ``bean_variant`` with one of "vigenere" / "beaufort" /
    "variant_beaufort" when Bean passes, or None otherwise. The variant
    recorded is the FIRST one that satisfies Bean in the fixed order
    declared by ``_BEAN_VARIANTS``.

    Always overrules the worker — this is the project's epistemic posture.
    """
    pt = (contract.best_plaintext or "").strip().upper()

    # Snapshot worker's claims before any mutation, so we can compare and
    # preserve them even when verification cannot run. Uses _safe_* helpers
    # so a pathological non-numeric value cannot crash the verifier.
    worker_claim = {
        "crib_score": _safe_int(contract.crib_score),
        "bean_passed": bool(contract.bean_passed),
        "score": _safe_float(contract.score),
    }

    # Default to None; any branch that successfully identifies a passing
    # variant will overwrite this below.
    contract.bean_variant = None

    # Empty plaintext is a legitimate "I have no candidate" — accept worker
    # claim of zero/false; flag any non-zero claim as a hallucination.
    if not pt:
        if (worker_claim["crib_score"] != 0
                or worker_claim["bean_passed"]
                or worker_claim["score"] != 0.0):
            contract.fields_overwritten = True
            contract.worker_self_report = worker_claim
            contract.verification_error = (
                "Worker reported non-zero score fields with empty best_plaintext"
            )
            contract.crib_score = 0
            contract.bean_passed = False
            contract.score = 0.0
        return

    # Kernel scoring operates on CT97 space. Anything else cannot be verified
    # against fixed crib positions — refuse to trust the worker's numbers.
    if len(pt) != 97:
        contract.fields_overwritten = True
        contract.worker_self_report = worker_claim
        contract.verification_error = (
            f"best_plaintext length {len(pt)} != 97 (CT97 space required for "
            f"verification); worker self-reported scores discarded"
        )
        contract.crib_score = 0
        contract.bean_passed = False
        contract.score = 0.0
        return

    # Non-A-Z characters (typically '?' placeholders for unknown positions)
    # bypass the length check above but silently fail downstream: text_to_nums
    # drops them, the resulting num list is shorter than 97, and the kernel's
    # verify_bean_simple raises a ValueError that leaks into verification_error
    # as if the verifier itself were broken. Reject these explicitly so the
    # error message describes what actually happened.
    if not pt.isalpha() or not pt.isascii():
        contract.fields_overwritten = True
        contract.worker_self_report = worker_claim
        contract.verification_error = (
            f"best_plaintext contains non-A-Z characters; CT97 space requires "
            f"uppercase A-Z only (got {len(pt) - sum(1 for c in pt if 'A' <= c <= 'Z')} "
            f"non-alphabetic char(s)); worker self-reported scores discarded"
        )
        contract.crib_score = 0
        contract.bean_passed = False
        contract.score = 0.0
        return

    # Plaintext is CT97-shaped. Recompute crib_score and bean_passed from
    # the kernel directly. We deliberately do NOT call score_candidate here
    # because (a) alerts.classify_outcome only gates on crib_score and
    # bean_passed, and (b) score_candidate's full ScoreBreakdown requires
    # constructing a complete BeanResult, which adds coupling for no benefit.
    try:
        from kryptos.kernel.constants import CT
        from kryptos.kernel.text import text_to_nums
        from kryptos.kernel.scoring.crib_score import score_cribs
        from kryptos.kernel.constraints.bean import verify_bean_simple

        verified_crib = int(score_cribs(pt))

        # Bean check: derive the keystream under each of the three classical
        # variants (Vigenere, Beaufort, Variant Beaufort) and accept Bean
        # PASS if any of them satisfies the constraints. The worker doesn't
        # tell us which variant they used, so we charitably try all three.
        # Order is fixed by _BEAN_VARIANTS — the first passing variant wins
        # and its name is recorded on contract.bean_variant.
        ct_nums = text_to_nums(CT)
        pt_nums = text_to_nums(pt)
        verified_bean = False
        verified_variant: Optional[str] = None
        for variant_name, derive in _BEAN_VARIANTS:
            keystream = [derive(c, p) for c, p in zip(ct_nums, pt_nums)]
            if verify_bean_simple(keystream):
                verified_bean = True
                verified_variant = variant_name
                break

        # Mirror crib_score into the score field. The display surfaces it,
        # but no control flow depends on it being a kernel aggregate score.
        verified_score = float(verified_crib)

    except Exception as exc:
        # Kernel verification crashed — refuse to trust worker, mark error.
        contract.fields_overwritten = True
        contract.worker_self_report = worker_claim
        contract.verification_error = f"Kernel verification raised: {exc}"
        contract.crib_score = 0
        contract.bean_passed = False
        contract.score = 0.0
        return

    # Compare worker claims to kernel truth. If anything disagrees, record
    # the worker's self-report and overwrite with kernel values.
    disagreement = (
        verified_crib != worker_claim["crib_score"]
        or verified_bean != worker_claim["bean_passed"]
    )
    if disagreement:
        contract.fields_overwritten = True
        contract.worker_self_report = worker_claim

    contract.crib_score = verified_crib
    contract.bean_passed = verified_bean
    contract.score = verified_score
    contract.bean_variant = verified_variant

T = TypeVar("T")


# ---------------------------------------------------------------------------
# ParseResult — the single return type for all boundary parsing
# ---------------------------------------------------------------------------

@dataclass
class ParseResult(Generic[T]):
    """
    Result of a boundary parse operation.

    Either is_valid=True and value is populated,
    or is_valid=False and errors describe what went wrong.

    raw is always preserved for audit regardless of validity.
    """
    is_valid: bool = False
    value: Optional[T] = None
    errors: list[str] = field(default_factory=list)
    raw: str = ""

    @classmethod
    def ok(cls, value: T, raw: str = "") -> ParseResult[T]:
        return cls(is_valid=True, value=value, raw=raw)

    @classmethod
    def fail(cls, errors: list[str], raw: str = "") -> ParseResult[T]:
        return cls(is_valid=False, errors=errors, raw=raw)


# ---------------------------------------------------------------------------
# JSON extraction — deterministic, no heuristic repair
# ---------------------------------------------------------------------------

def extract_json_block(raw: str) -> Optional[str]:
    """
    Extract the last fenced JSON block from raw text.

    Looks for ```json ... ``` blocks. Returns the content of the last
    one found (workers are instructed to put the result block last).
    Returns None if no fenced block found.

    Does NOT attempt to find bare JSON objects in prose — that path
    leads to false positives from example JSON in narrative text.
    """
    blocks = re.findall(r"```(?:json)?\s*\n(.*?)\n```", raw, re.DOTALL)
    if blocks:
        return blocks[-1].strip()
    return None


# ---------------------------------------------------------------------------
# Worker contract validation
# ---------------------------------------------------------------------------

# Fields that must be present for a worker contract to be actionable.
# "status" is the absolute minimum — without it the controller cannot
# determine what happened.
_WORKER_REQUIRED_FIELDS = {"status"}

# Valid values for the status enum.
_VALID_WORKER_STATUSES = frozenset(s.value for s in WorkerStatus)


def validate_worker_contract(
    raw: str,
    hypothesis_id: str,
) -> ParseResult[WorkerContract]:
    """
    Parse and validate a WorkerContract from raw worker output.

    Steps:
    1. Extract the last fenced JSON block.
    2. Parse as JSON dict.
    3. Validate required fields and enum values.
    4. Construct WorkerContract with strict field checking.

    If ANY step fails, returns ParseResult.fail with explicit errors.
    The raw output is always preserved for audit.
    """
    # Step 1: Extract JSON block
    json_str = extract_json_block(raw)
    if json_str is None:
        return ParseResult.fail(
            errors=["No fenced JSON block (```json ... ```) found in worker output"],
            raw=raw,
        )

    # Step 2: Parse JSON
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        return ParseResult.fail(
            errors=[f"JSON parse error: {exc}"],
            raw=raw,
        )

    if not isinstance(data, dict):
        return ParseResult.fail(
            errors=[f"Expected JSON object, got {type(data).__name__}"],
            raw=raw,
        )

    # Step 3: Validate required fields
    errors: list[str] = []
    for req in _WORKER_REQUIRED_FIELDS:
        if req not in data:
            errors.append(f"Missing required field: '{req}'")

    # Validate status enum
    status_val = data.get("status")
    if status_val is not None and status_val not in _VALID_WORKER_STATUSES:
        errors.append(
            f"Invalid status '{status_val}'; "
            f"valid values: {sorted(_VALID_WORKER_STATUSES)}"
        )

    # Validate score type if present
    score_val = data.get("score")
    if score_val is not None and not isinstance(score_val, (int, float)):
        errors.append(f"Field 'score' must be numeric, got {type(score_val).__name__}")

    # Validate crib_score type if present
    crib_val = data.get("crib_score")
    if crib_val is not None and not isinstance(crib_val, (int, float)):
        errors.append(f"Field 'crib_score' must be numeric, got {type(crib_val).__name__}")

    # Validate bean_passed type if present
    bean_val = data.get("bean_passed")
    if bean_val is not None and not isinstance(bean_val, bool):
        errors.append(f"Field 'bean_passed' must be boolean, got {type(bean_val).__name__}")

    # Validate list-of-strings fields
    for list_field in ("disproof_evidence", "supporting_evidence"):
        lv = data.get(list_field)
        if lv is not None:
            if not isinstance(lv, list):
                errors.append(f"Field '{list_field}' must be a list, got {type(lv).__name__}")
            elif not all(isinstance(item, str) for item in lv):
                errors.append(f"Field '{list_field}' must be a list of strings")

    # Validate raw_artifacts is a dict if present
    ra = data.get("raw_artifacts")
    if ra is not None and not isinstance(ra, dict):
        errors.append(f"Field 'raw_artifacts' must be an object, got {type(ra).__name__}")

    if errors:
        return ParseResult.fail(errors=errors, raw=raw)

    # Step 4: Construct validated contract
    # Override hypothesis_id to ensure it matches the dispatched theory
    data["hypothesis_id"] = hypothesis_id

    try:
        status = WorkerStatus(data["status"])
    except (ValueError, KeyError):
        # Should not reach here due to validation above, but defensive
        return ParseResult.fail(
            errors=[f"Status enum construction failed for '{data.get('status')}'"],
            raw=raw,
        )

    contract = WorkerContract(
        hypothesis_id=hypothesis_id,
        status=status,
        score=float(data.get("score", 0.0)),
        crib_score=int(data.get("crib_score", 0)),
        bean_passed=bool(data.get("bean_passed", False)),
        best_plaintext=str(data.get("best_plaintext", "")),
        disproof_evidence=data.get("disproof_evidence", []),
        supporting_evidence=data.get("supporting_evidence", []),
        next_action=str(data.get("next_action", "")),
        family_generalization=str(data.get("family_generalization", "")),
        narrative_summary=str(data.get("narrative_summary", "")),
        raw_artifacts=data.get("raw_artifacts", {}),
    )

    # Independent verification: kernel always overrules worker self-report.
    # See _verify_against_kernel docstring for the policy rationale.
    _verify_against_kernel(contract)

    return ParseResult.ok(value=contract, raw=raw)


# ---------------------------------------------------------------------------
# Theory proposal validation
# ---------------------------------------------------------------------------

# Fields a theory proposal must have to be worth evaluating
_THEORY_REQUIRED_FIELDS = {"core_claim", "mechanism", "family"}


def _known_anomaly_ids(problem: Optional["ProblemContext"] = None) -> set[str]:
    """Return the canonical anomaly IDs recognized by the controller.

    Reads through ProblemContext (when supplied) so theory-proposal
    validation only consults the real-K4 KNOWN_ANOMALIES registry in
    real-K4 mode. In K4Bench mode the accessor returns an empty set,
    which makes ANY anomaly reference in a parsed bench theory invalid
    — bench challenges define no anomaly registry, so a non-empty
    ``anomalies_exploited`` field IS a contamination signal.

    For backwards compatibility, callers that have not yet been
    migrated to thread a ProblemContext fall back to the live registry
    (preserves existing real-K4 behavior). New call sites should
    always supply ``problem``.
    """
    if problem is not None:
        return problem.known_anomaly_ids()

    from .registries import KNOWN_ANOMALIES

    return {
        str(item.get("anomaly_id", "")).strip()
        for item in KNOWN_ANOMALIES
        if str(item.get("anomaly_id", "")).strip()
    }


@dataclass
class TheoryParseReport:
    """Report from parsing a batch of theory proposals."""
    valid: list[TheoryRecord] = field(default_factory=list)
    invalid: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _normalize_anomaly_id(raw: str) -> str:
    """Extract the canonical anomaly_id prefix from a theorist-supplied string.

    Post-K4-cycle-1 hygiene (2026-04-21, commit 2). The 2026-04-21 run
    surfaced that the theorist frequently writes anomaly references as
    "<canonical_id> <free-form commentary>" or
    "<canonical_id> (<parenthetical>)", e.g.

      "aaa_compass_cipher (tie to physical sculpture geometry specifically)"
      "k3_continuity as under-explored source material"
      "mirror_ka is listed as underexplored (0 tested)"

    The pre-fix validator did exact-match on the whole string and
    rejected 4 of 5 cycle-1 theories for this cosmetic issue. The R3
    validator was structurally correct ("canonical ids only") but too
    strict about form.

    This normalizer takes everything up to the first whitespace or '('
    character and strips trailing punctuation. It does NOT prefix-match
    against the canonical set — the downstream exact-match check still
    enforces canonicality. This is purely a trailing-commentary
    stripper.

    Examples:
        "aaa_compass_cipher (tie to ...)" → "aaa_compass_cipher"
        "k3_continuity as under-explored" → "k3_continuity"
        "mirror_ka is listed..."          → "mirror_ka"
        "archive-attested K3 misspellings" → "archive-attested"
          (and if 'archive-attested' is not canonical, the exact-match
          check downstream rejects it — appropriate)

    Empty/whitespace-only input returns "" (downstream rejects empty).
    """
    s = (raw or "").strip()
    if not s:
        return ""
    # Cut at first whitespace or '('. Any trailing punctuation (commas,
    # semicolons, trailing underscores) is stripped — but NOT hyphens or
    # underscores within the id itself, which are valid characters.
    end = len(s)
    for i, ch in enumerate(s):
        if ch.isspace() or ch == "(":
            end = i
            break
    head = s[:end].rstrip(",.;:")
    return head


def validate_theory_proposals(
    raw: str,
    *,
    problem: Optional["ProblemContext"] = None,
) -> TheoryParseReport:
    """
    Parse and validate theory proposals from theorist output.

    Steps:
    1. Extract JSON array from raw output.
    2. Validate each item has required fields.
    3. Validate field types deterministically.
    4. Return valid theories + explicit rejection records for invalid ones.

    No semantic guessing. Items without required fields are rejected,
    not repaired.

    ``problem`` is the ProblemContext that gates real-K4 registry
    access. When supplied (the controller always supplies it), bench
    runs validate against an empty anomaly registry, which makes any
    ``anomalies_exploited`` reference an invalid contamination signal.
    When omitted (legacy / test paths), falls back to the live
    KNOWN_ANOMALIES registry — preserves prior real-K4 behavior.
    """
    report = TheoryParseReport()
    known_anomaly_ids = _known_anomaly_ids(problem=problem)

    # Step 1: Extract JSON array.
    # The raw output may contain Python repr strings like [ThinkingBlock(...)]
    # and [TextBlock(...)]. We need to find the actual JSON array, which
    # starts with [{ (array of objects). Try fenced blocks first, then
    # look for [{ patterns.
    json_str = None

    # First: check for fenced ```json blocks (same as worker contract)
    fenced = extract_json_block(raw)
    if fenced and fenced.strip().startswith("["):
        json_str = fenced

    # Second: find [ that starts a JSON array of objects.
    # Use bracket-depth matching to find the corresponding ], not rfind.
    # This prevents cross-pairing when multiple arrays appear in the output.
    if json_str is None:
        for i, ch in enumerate(raw):
            if ch == "[":
                # Skip Python repr patterns: [ThinkingBlock, [TextBlock
                if i + 1 < len(raw) and raw[i + 1].isalpha():
                    continue
                # Find matching ] via bracket-depth counting
                depth = 0
                in_string = False
                escape_next = False
                end = -1
                for j in range(i, len(raw)):
                    c = raw[j]
                    if escape_next:
                        escape_next = False
                        continue
                    if c == "\\" and in_string:
                        escape_next = True
                        continue
                    if c == '"' and not escape_next:
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if c == "[":
                        depth += 1
                    elif c == "]":
                        depth -= 1
                        if depth == 0:
                            end = j
                            break
                if end < 0:
                    continue
                candidate = raw[i:end + 1]
                try:
                    parsed = json.loads(candidate)
                    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                        json_str = candidate
                        break
                except json.JSONDecodeError:
                    continue

    if json_str is None:
        report.errors.append("No JSON array found in theorist output")
        return report

    # Step 2: Parse JSON
    try:
        items = json.loads(json_str)
    except json.JSONDecodeError as exc:
        report.errors.append(f"JSON parse error: {exc}")
        return report

    if not isinstance(items, list):
        report.errors.append(f"Expected JSON array, got {type(items).__name__}")
        return report

    # Step 3: Validate each item
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            report.invalid.append({
                "index": i, "raw": str(item)[:500],
                "error": f"Expected object, got {type(item).__name__}",
            })
            continue

        # Check required fields
        missing = _THEORY_REQUIRED_FIELDS - set(item.keys())
        if missing:
            report.invalid.append({
                "index": i, "raw": json.dumps(item)[:500],
                "error": f"Missing required fields: {sorted(missing)}",
            })
            continue

        # Check required fields are non-empty strings
        empty_required = [
            f for f in _THEORY_REQUIRED_FIELDS
            if not isinstance(item.get(f), str) or not item[f].strip()
        ]
        if empty_required:
            report.invalid.append({
                "index": i, "raw": json.dumps(item)[:500],
                "error": f"Empty or non-string required fields: {sorted(empty_required)}",
            })
            continue

        # Type-check optional list fields
        type_errors = []
        for list_field in ("tags", "clue_anchors_used", "anomalies_exploited", "kill_criteria"):
            val = item.get(list_field)
            if val is not None and not isinstance(val, list):
                type_errors.append(f"'{list_field}' must be a list")
        anomalies = item.get("anomalies_exploited")
        if isinstance(anomalies, list):
            invalid_anomaly_entries = []
            for value in anomalies:
                if not isinstance(value, str) or not value.strip():
                    invalid_anomaly_entries.append(repr(value))
                    continue
                # Post-K4-cycle-1 hygiene (2026-04-21, commit 2): strip
                # trailing free-form commentary before exact-match. The
                # normalizer takes the first whitespace/paren-split token;
                # see _normalize_anomaly_id. This recovers theories
                # where the theorist wrote e.g. "aaa_compass_cipher (tie
                # to physical sculpture)" instead of the bare id. The
                # canonical-exact-match check still enforces that the
                # normalized head is a known anomaly.
                normalized = _normalize_anomaly_id(value)
                if not normalized or normalized not in known_anomaly_ids:
                    invalid_anomaly_entries.append(
                        normalized or value.strip()
                    )
            if invalid_anomaly_entries:
                type_errors.append(
                    "'anomalies_exploited' must contain only canonical anomaly_ids; "
                    f"invalid entries: {invalid_anomaly_entries[:3]}"
                )
        if item.get("minimal_test_spec") is not None and not isinstance(item["minimal_test_spec"], dict):
            type_errors.append("'minimal_test_spec' must be an object")
        # Day 5 optional numeric field — accept int, float, or omit. Not
        # an error to skip; theorist may not always know the cost upfront.
        ecm = item.get("estimated_compute_minutes")
        if ecm is not None and not isinstance(ecm, (int, float)):
            type_errors.append("'estimated_compute_minutes' must be numeric")

        # R3-2 (2026-04-21): dsl_spec must be either a dict or explicit
        # null. A dict is further validated structurally below so that
        # syntactic errors surface as "invalid" rather than silently
        # parsing to an un-dispatchable spec. The critic enforces
        # Category-A spec requirements (DSL_CUTOVER_CONTRACT §6.5); the
        # boundary parser only checks shape.
        dsl_spec_raw = item.get("dsl_spec")
        if dsl_spec_raw is not None and not isinstance(dsl_spec_raw, dict):
            type_errors.append(
                "'dsl_spec' must be a HypothesisSpec object or null"
            )

        if type_errors:
            report.invalid.append({
                "index": i, "raw": json.dumps(item)[:500],
                "error": "; ".join(type_errors),
            })
            continue

        # R3-2: store the dsl_spec verbatim at boundary time; structural
        # validation runs in the critic's Category-A/C check where it
        # can produce the canonical "dsl_untranslatable" rejection
        # reason. Rejecting at boundary-parse time for minor schema
        # variance (e.g., a theorist-placeholder hypothesis_id the
        # controller would have filled in later) would drop otherwise-
        # fixable theories.
        #
        # The null/dict type check above is preserved: a theorist
        # emitting a string or array where a dict is expected is a
        # structural error worth rejecting at boundary time.
        dsl_spec_dict: dict[str, Any] = {}
        if isinstance(dsl_spec_raw, dict):
            dsl_spec_dict = dsl_spec_raw

        # Step 4: Construct validated TheoryRecord
        theory = TheoryRecord(
            title=str(item.get("title", "")),
            core_claim=item["core_claim"],
            mechanism=item["mechanism"],
            family=item["family"],
            subfamily=str(item.get("subfamily", "")),
            tags=item.get("tags", []),
            clue_anchors_used=item.get("clue_anchors_used", []),
            anomalies_exploited=item.get("anomalies_exploited", []),
            novelty_basis=str(item.get("novelty_basis", "")),
            kill_criteria=item.get("kill_criteria", []),
            expected_signal=str(item.get("expected_signal", "")),
            compute_cost_estimate=str(item.get("compute_cost_estimate", "")),
            estimated_compute_minutes=int(item.get("estimated_compute_minutes") or 0),
            minimal_test_spec=item.get("minimal_test_spec", {}),
            dsl_spec=dsl_spec_dict,
        )
        report.valid.append(theory)

    return report
