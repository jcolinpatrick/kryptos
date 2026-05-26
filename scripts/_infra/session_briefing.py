#!/usr/bin/env python3
"""Session briefing generator — a renderer + validator for K4 research state.

Run at the start of every Claude Code session:
    PYTHONPATH=src python3 scripts/_infra/session_briefing.py

DESIGN CONTRACT
---------------
This script is a *renderer + validator*. The structured source files are the
source of truth; the script's job is to surface them concisely and to FAIL
LOUDLY (not silently) when a canonical source is missing or malformed. It
must never broaden a claim beyond its source-supported scope, and it must
never present a sampled or empirical negative as a mathematical proof.

REQUIRED sources (missing/malformed => briefing is DEGRADED; --strict exits 1):
  - kryptos.kernel.constants            (CT, cribs, Bean constants) — hard requirement
  - exhaustion_log.json                 (family/status landscape)
  - docs/session_briefing_claims.json   (externalized doctrine; embedded fallback if absent)
  - docs/claims_registry.json           (canonical disputed/retired/superseded claims)

OPTIONAL sources (missing => warn, continue):
  - results/*.json, results/*/summary.json, results/*/result.json (campaign verdicts)
  - bin-C artifact JSON/markdown files
  - docs/elimination_tiers.md (referenced for humans; NOT parsed by this script)

EVIDENCE-CLASS SEMANTICS
------------------------
Only `mathematical_proof` / `structural_proof` claims may render with
permanent / never language. `exhaustive_search`, `sampled_search`,
`empirical_negative`, and `admissibility` claims are rendered with
scope-limited language ("within declared scope", "sampled — not proof",
"blocked pending source"). This is enforced by EVIDENCE_CLASS_LANGUAGE.

SCALE NOTE
----------
results/ contains >140k JSON files (mostly per-job outputs under
results/dsl_jobs/). Parsing all of them at session start would hang the
tool, so file *counts* are computed by walking filenames only (fast), while
*verdict parsing* is scoped to campaign-level artifacts: top-level
results/*.json plus one level of nested summary.json / result.json. Deep
per-job files are counted but not parsed; the footer says so.

CLI flags (all optional; bare invocation is the normal startup path):
  --strict   exit nonzero if any required source is missing/malformed
  --debug    include parse-error detail in the SOURCE HEALTH section
  --json     emit machine-readable diagnostics/state instead of the briefing
  --self-test  run built-in assertions on the pure helpers and exit
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

# Kernel constants are a HARD requirement: without them the script cannot
# describe K4 at all. Failure here is fatal regardless of --strict.
try:
    from kryptos.kernel.constants import (  # noqa: E402
        CT, CT_LEN, N_CRIBS,
        BEAN_EQ, BEAN_INEQ, BEAN_LINEAR, CRIB_WORDS,
        SELF_ENCRYPTING, IC_RANDOM, IC_ENGLISH,
    )
    from kryptos.kernel.scoring.ic import ic as _kernel_ic  # noqa: E402
    _KERNEL_OK = True
    _KERNEL_ERR = None
except Exception as exc:  # pragma: no cover - exercised only on broken install
    _KERNEL_OK = False
    _KERNEL_ERR = repr(exc)

from kryptos.alignment_models import ALIGNMENT_MODELS, ALIGNMENT_MODEL_KEYS as _ALIGNMENT_MODEL_KEYS  # noqa: E402


# ── Diagnostics ───────────────────────────────────────────────────────────────

@dataclass
class Diagnostics:
    """Collects warnings/errors so source failures are visible, not silent."""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    debug: bool = False

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    @property
    def degraded(self) -> bool:
        return bool(self.errors)


# ── Pure helpers ──────────────────────────────────────────────────────────────

def first_present(d: dict[str, Any], keys: Iterable[str]) -> Any:
    """Return the first key whose value is not None.

    Preserves valid falsy values (0, "", []), unlike `a or b`, which would
    discard a legitimate best_score of 0.
    """
    if not isinstance(d, dict):
        return None
    for key in keys:
        if key in d and d[key] is not None:
            return d[key]
    return None


def load_json(path: str, diag: Diagnostics, required: bool = False) -> Optional[Any]:
    """Load a JSON file. On failure: error (required) or warn (optional)."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        msg = f"missing: {os.path.relpath(path, _ROOT)}"
        (diag.error if required else diag.warn)(msg)
        return None
    except (json.JSONDecodeError, OSError) as exc:
        detail = f" ({exc})" if diag.debug else ""
        msg = f"malformed: {os.path.relpath(path, _ROOT)}{detail}"
        (diag.error if required else diag.warn)(msg)
        return None


class VerdictClass(Enum):
    CLOSED = "closed"      # eliminated / disproved / exhausted / certified
    NOISE = "noise"        # ran, indistinguishable from random
    RETIRED = "retired"    # withdrawn / superseded claim
    OPEN = "open"          # interesting / signal / needs attention
    BLOCKED = "blocked"    # cannot run under current assumptions
    UNKNOWN = "unknown"    # unrecognized / ambiguous / absent


# A verdict is "terminal" (safe to treat as closed for bin-C purposes) only
# for these classes. OPEN/BLOCKED/UNKNOWN must never read as closed.
_TERMINAL_CLASSES = {VerdictClass.CLOSED, VerdictClass.NOISE, VerdictClass.RETIRED}


def is_terminal(vc: VerdictClass) -> bool:
    return vc in _TERMINAL_CLASSES


def _coerce_verdict_str(value: Any) -> Optional[str]:
    """Extract the underlying verdict string (handles dict-shaped verdicts)."""
    if value is None:
        return None
    if isinstance(value, dict):
        value = first_present(value, ("summary", "status", "verdict", "conclusion"))
        if value is None:
            return None
    s = str(value).strip()
    return s or None


def normalize_verdict(value: Any) -> Optional[str]:
    """Normalize a verdict value to an UPPER_SNAKE token string, or None.

    Accepts strings or dicts (extracts a summary/status/verdict field).
    Collapses spaces, hyphens, em dashes, and punctuation to underscores so
    downstream matching is stable.
    """
    s = _coerce_verdict_str(value)
    if s is None:
        return None
    text = s.upper()
    out: list[str] = []
    for ch in text:
        out.append(ch if ch.isalnum() else "_")
    norm = "_".join(tok for tok in "".join(out).split("_") if tok)
    return norm or None


def _verdict_head(s: str) -> str:
    """The leading verdict token: text before the first ':' or '('.

    Project verdicts are prose like "ELIMINATED (audit ...): ... NO SIGNAL".
    The semantic verdict is the head; the tail is human explanation that
    must NOT drive classification (it routinely mentions SIGNAL, INVESTIGATE,
    DO NOT TEST, etc. inside an ELIMINATED verdict).
    """
    for sep in (":", "("):
        idx = s.find(sep)
        if idx != -1:
            s = s[:idx]
    return s


# Ordered (substring, class) rules. ORDER MATTERS: open/negation guards are
# checked before closed substrings so "FAILED_TO_ELIMINATE" and
# "NOT_ELIMINATED" never read as ELIMINATED.
_VERDICT_RULES: tuple[tuple[str, VerdictClass], ...] = (
    # Negation / open guards FIRST.
    ("NOT_ELIMINAT", VerdictClass.OPEN),
    ("FAILED_TO_ELIMINAT", VerdictClass.UNKNOWN),
    ("CANNOT_ELIMINAT", VerdictClass.OPEN),
    ("NO_SIGNIFICANT", VerdictClass.NOISE),
    ("NOT_SIGNIFICANT", VerdictClass.NOISE),
    ("NO_SIGNAL", VerdictClass.NOISE),
    ("BELOW_SIGNAL", VerdictClass.NOISE),
    ("ZERO_SIGNAL", VerdictClass.NOISE),
    # Noise family (ran, indistinguishable from random).
    ("NOISE", VerdictClass.NOISE),
    ("PEAK_WITHIN_NULL", VerdictClass.NOISE),
    ("LOW_DIVERSITY", VerdictClass.NOISE),
    # Retired / superseded.
    ("RETIRED", VerdictClass.RETIRED),
    ("SUPERSEDED", VerdictClass.RETIRED),
    ("WITHDRAWN", VerdictClass.RETIRED),
    # Open / needs attention.
    ("INTEREST", VerdictClass.OPEN),
    ("SIGNAL", VerdictClass.OPEN),
    ("PROMISING", VerdictClass.OPEN),
    ("ELEVATED", VerdictClass.OPEN),
    ("ESCALATE", VerdictClass.OPEN),
    ("INVESTIGATE", VerdictClass.OPEN),
    ("NEAR_MISS", VerdictClass.OPEN),
    ("LIKELY_OPEN", VerdictClass.OPEN),
    ("SUCCESS", VerdictClass.OPEN),
    # Blocked / cannot run.
    ("ASSUMPTION_UNMET", VerdictClass.BLOCKED),
    ("BLOCKED", VerdictClass.BLOCKED),
    ("LOW_INFORMATION", VerdictClass.BLOCKED),
    ("NEEDS_SOURCE", VerdictClass.BLOCKED),
    # Ambiguous / incomplete -> UNKNOWN (never closed).
    ("UNCLEAR", VerdictClass.UNKNOWN),
    ("INCONCLUSIVE", VerdictClass.UNKNOWN),
    ("INCOMPLETE", VerdictClass.UNKNOWN),
    ("UNDERDETERMINED", VerdictClass.UNKNOWN),
    ("MARGINAL", VerdictClass.UNKNOWN),
    ("WEAK", VerdictClass.UNKNOWN),
    ("TBD", VerdictClass.UNKNOWN),
    ("TODO", VerdictClass.UNKNOWN),
    # Closed (terminal). Checked AFTER negation guards above.
    ("STRUCTURALLY", VerdictClass.CLOSED),
    ("MATHEMATICALLY", VerdictClass.CLOSED),
    ("ELIMINAT", VerdictClass.CLOSED),
    ("DISPROV", VerdictClass.CLOSED),
    ("EXHAUST", VerdictClass.CLOSED),
    ("CERTIFIED", VerdictClass.CLOSED),
    ("ADMISSIBILITY_REJECT", VerdictClass.CLOSED),
    ("INVALID", VerdictClass.CLOSED),
    ("EMPTY", VerdictClass.CLOSED),
    ("NO_PERIODIC_CIPHER", VerdictClass.CLOSED),
)


def classify_verdict(value: Any) -> VerdictClass:
    """Classify a raw verdict value conservatively.

    Strategy: classify the verdict HEAD (leading token before ':' or '(')
    first, since that carries the semantic verdict; only if the head is
    unrecognized do we scan the full string. This prevents prose in the tail
    of an ELIMINATED verdict (e.g. "... NO SIGNAL", "... INVESTIGATE later")
    from flipping the classification. Negation phrases are checked before
    closed substrings, and unrecognized/absent verdicts are UNKNOWN, never
    CLOSED.
    """
    s = _coerce_verdict_str(value)
    if s is None:
        return VerdictClass.UNKNOWN
    full = normalize_verdict(s)
    if not full:
        return VerdictClass.UNKNOWN
    head = normalize_verdict(_verdict_head(s)) or full
    for needle, vclass in _VERDICT_RULES:
        if needle in head:
            return vclass
    for needle, vclass in _VERDICT_RULES:
        if needle in full:
            return vclass
    return VerdictClass.UNKNOWN


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Best-effort timestamp parse. Returns None when unparseable."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # Try ISO-8601 first (handles trailing Z and offsets on 3.11+).
    # Return tz-naive so dated entries are mutually comparable when sorting.
    iso = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(iso).replace(tzinfo=None)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(text[: len(fmt) + 6], fmt)
        except ValueError:
            continue
    return None


def compute_ic(text: str) -> float:
    """Index of coincidence. Uses the kernel implementation when available."""
    if _KERNEL_OK:
        return float(_kernel_ic(text))
    counts: dict[str, int] = {}
    letters = [c for c in text.upper() if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    for c in letters:
        counts[c] = counts.get(c, 0) + 1
    num = sum(v * (v - 1) for v in counts.values())
    return num / (n * (n - 1))


def self_encrypting_positions() -> dict[int, str]:
    """Positions where CT[i] == PT[i], sourced from kernel SELF_ENCRYPTING."""
    if _KERNEL_OK:
        return dict(SELF_ENCRYPTING)
    return {}


# ── Result data model + scanning ──────────────────────────────────────────────

@dataclass
class ResultEntry:
    name: str
    path: str
    verdict: Optional[str]
    verdict_class: VerdictClass
    best_score: Any = None
    timestamp: Optional[str] = None
    timestamp_dt: Optional[datetime] = None
    configs: Any = None


_VERDICT_KEYS = ("verdict", "verdict_status", "conclusion", "status")
_SCORE_KEYS = ("best_score", "best_crib_score", "max_crib_score", "max_score")
_TS_KEYS = ("timestamp", "date", "produced_at", "started_at", "completed_at")
_CONFIG_KEYS = ("total_configs", "configs_tested", "keyspace_tested", "orderings_tested")


def _entry_from_dict(name: str, path: str, d: dict[str, Any]) -> ResultEntry:
    raw_verdict = first_present(d, _VERDICT_KEYS)
    norm = normalize_verdict(raw_verdict)
    ts_raw = first_present(d, _TS_KEYS)
    return ResultEntry(
        name=name,
        path=os.path.relpath(path, _ROOT),
        verdict=norm,
        verdict_class=classify_verdict(raw_verdict),
        best_score=first_present(d, _SCORE_KEYS),
        timestamp=str(ts_raw) if ts_raw is not None else None,
        timestamp_dt=parse_timestamp(ts_raw),
        configs=first_present(d, _CONFIG_KEYS),
    )


def scan_result_files(diag: Diagnostics) -> list[ResultEntry]:
    """Parse campaign-level result artifacts only (scoped, fast).

    Scope: results/*.json + results/*/summary.json + results/*/result.json.
    Deep per-job files (results/dsl_jobs/**, etc.) are intentionally NOT
    parsed here — they are counted in count_result_files(). Dedupe is by
    logical campaign (top-level filename, or the immediate parent dir for
    nested artifacts) so a dir with both summary.json and result.json counts
    once (summary wins).
    """
    import glob

    results_dir = os.path.join(_ROOT, "results")
    entries: list[ResultEntry] = []
    seen_dirs: set[str] = set()

    def _load(path: str, name: str) -> Optional[dict]:
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            detail = f" ({exc})" if diag.debug else ""
            diag.warn(f"unparseable result: {os.path.relpath(path, _ROOT)}{detail}")
            return None
        return data if isinstance(data, dict) else None

    # Top-level campaign files.
    for rf in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        data = _load(rf, os.path.basename(rf))
        if data is not None:
            name = os.path.basename(rf)[: -len(".json")]
            entries.append(_entry_from_dict(name, rf, data))

    # One level of nested campaign artifacts: summary.json preferred.
    for sd in sorted(glob.glob(os.path.join(results_dir, "*", "summary.json"))):
        seen_dirs.add(os.path.dirname(sd))
        data = _load(sd, os.path.basename(os.path.dirname(sd)))
        if data is not None:
            entries.append(_entry_from_dict(os.path.basename(os.path.dirname(sd)), sd, data))
    for rd in sorted(glob.glob(os.path.join(results_dir, "*", "result.json"))):
        parent = os.path.dirname(rd)
        if parent in seen_dirs:
            continue  # summary.json already covered this campaign
        seen_dirs.add(parent)
        data = _load(rd, os.path.basename(parent))
        if data is not None:
            entries.append(_entry_from_dict(os.path.basename(parent), rd, data))

    return entries


def count_result_files() -> dict[str, int]:
    """Count result JSON files recursively by walking filenames only (fast).

    Does NOT parse contents (there are >140k files). Parse stats belong to
    the scoped scan in scan_result_files().
    """
    results_dir = os.path.join(_ROOT, "results")
    total = top_level = nested = result_json = summary_json = 0
    subdirs = 0
    for root, dirs, files in os.walk(results_dir):
        if root == results_dir:
            subdirs = len(dirs)
        is_top = (root == results_dir)
        for fn in files:
            if not fn.endswith(".json"):
                continue
            total += 1
            if is_top:
                top_level += 1
            else:
                nested += 1
            if fn == "result.json":
                result_json += 1
            elif fn == "summary.json":
                summary_json += 1
    return {
        "total": total,
        "top_level": top_level,
        "nested": nested,
        "result_json": result_json,
        "summary_json": summary_json,
        "subdirs": subdirs,
    }


def count_scripts() -> int:
    import glob
    patterns = ("e_*.py", "f_*.py", "blitz_*.py")
    total = 0
    for pat in patterns:
        total += len(glob.glob(os.path.join(_ROOT, "scripts", "**", pat), recursive=True))
    return total


# ── Exhaustion-log status buckets ─────────────────────────────────────────────

_EXHAUSTED_STATUSES = {"exhausted"}
_ACTIVE_STATUSES = {"active", "testable", "running", "queued", "promising",
                    "in_progress", "open"}
_BLOCKED_STATUSES = {"blocked", "assumption_unmet", "needs_source", "deferred"}
_RETIRED_STATUSES = {"retired", "superseded", "invalid", "archived", "deprecated"}


def _bucket_status(status: str) -> str:
    s = (status or "").lower()
    if s in _EXHAUSTED_STATUSES:
        return "exhausted"
    if s in _ACTIVE_STATUSES:
        return "active"
    if s in _BLOCKED_STATUSES:
        return "blocked"
    if s in _RETIRED_STATUSES:
        return "retired"
    return "unknown"


# ── Section-claims registry (externalized doctrine) ───────────────────────────

# Embedded fallback used ONLY when docs/session_briefing_claims.json is
# missing/malformed. Kept compact; the canonical, fully-sourced version lives
# in the JSON registry. Use of this fallback is announced in SOURCE HEALTH.
_FALLBACK_SECTION_CLAIMS: dict[str, list[dict]] = {
    "proofs": [
        {"evidence_class": "mathematical_proof",
         "statement": "Pure transposition impossible (CT has 2 E's, PT needs 3).",
         "scope": "pure transposition, direct correspondence"},
        {"evidence_class": "mathematical_proof",
         "statement": "ALL periodic polyalphabetic (periods 1-26) eliminated via full 242 Bean set.",
         "scope": "direct correspondence"},
        {"evidence_class": "structural_proof",
         "statement": "ALL autokey variants + arbitrary transposition (PT-max 16/24, CT-max 21/24).",
         "scope": "autokey family"},
        {"evidence_class": "sampled_search",
         "statement": "Columnar w10-15 SAMPLED 100K each, max 14/24 (not exhaustive).",
         "scope": "columnar w10-15, sampled"},
    ],
    "do_not_test": [
        {"evidence_class": "structural_proof",
         "statement": "Any autokey variant (structural).", "scope": "autokey"},
        {"evidence_class": "exhaustive_search",
         "statement": "DEFECTOR/PALIMPSEST keywords (15/24 ceiling).", "scope": "those keywords"},
        {"evidence_class": "mathematical_proof",
         "statement": "Periodic substitution on null-extracted CT73, periods 1-23 (algebraic).",
         "scope": "CT73 periodic"},
    ],
    "surviving_anomaly": [
        {"evidence_class": "empirical_negative",
         "statement": "Width-21 bigram on CT97 (p=1.6e-4) — STEGO artifact, not actionable.",
         "scope": "CT97"},
    ],
    "retired_anomaly": [
        {"evidence_class": "methodological_audit", "status": "retired",
         "statement": "Null palette {B,G,I,K,O,W,Z} — score-conditioned, retired April 2026.",
         "scope": "palette"},
    ],
    "bin_d": [
        {"evidence_class": "operational_prerequisite", "status": "blocked",
         "statement": "Mono+Trans+Running-key — needs a new detector, not more sweeps.",
         "scope": "E-FRAC-54"},
    ],
    "bin_e": [
        {"evidence_class": "operational_prerequisite", "status": "blocked",
         "statement": "Bespoke chart-based cipher — needs public chart or procedure license.",
         "scope": "chart cipher"},
    ],
    "pitfall": [
        {"statement": "ALL positions 0-indexed (cribs at 21-33, 63-73)."},
        {"statement": "Every command needs PYTHONPATH=src."},
        {"statement": "Import constants from kryptos.kernel.constants — NEVER hardcode."},
        {"statement": "Vigenere K=(CT-PT)%26 | Beaufort K=(CT+PT)%26 | VarBeau K=(PT-CT)%26."},
        {"statement": "High scores at large periods are ALWAYS false positives."},
        {"statement": "Root exhaustion_log.json is authoritative (NOT scripts/EXHAUSTION.json)."},
    ],
}


def load_section_claims(diag: Diagnostics) -> tuple[dict[str, list[dict]], bool]:
    """Load docs/session_briefing_claims.json grouped by section.

    Returns (sections, used_fallback). Required source: a missing/malformed
    registry is an ERROR (degrades the briefing) and triggers the embedded
    fallback with a visible warning.
    """
    path = os.path.join(_ROOT, "docs", "session_briefing_claims.json")
    data = load_json(path, diag, required=True)
    if not isinstance(data, dict) or "claims" not in data:
        diag.warn("using embedded fallback for doctrine sections "
                  "(docs/session_briefing_claims.json unavailable/invalid)")
        return _FALLBACK_SECTION_CLAIMS, True

    sections: dict[str, list[dict]] = {}
    required_fields = ("section", "status", "evidence_class", "statement")
    for c in data["claims"]:
        if not isinstance(c, dict):
            diag.warn("claims_registry section entry is not an object; skipped")
            continue
        missing = [f for f in required_fields if not c.get(f)]
        if missing:
            cid = c.get("claim_id", "?")
            diag.warn(f"section claim {cid} missing fields {missing}")
        sec = c.get("section", "unknown")
        sections.setdefault(sec, []).append(c)
    return sections, False


# ── Evidence-class presentation ───────────────────────────────────────────────

# Maps evidence_class -> (heading, marker, scope-limited?) for the proofs
# section. Only proof classes may use permanent/never framing.
_EVIDENCE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("MATHEMATICALLY IMPOSSIBLE (permanent)", ("mathematical_proof",)),
    ("STRUCTURALLY IMPOSSIBLE (permanent)", ("structural_proof",)),
    ("EXHAUSTIVELY ELIMINATED WITHIN DECLARED SCOPE", ("exhaustive_search",)),
    ("SAMPLED NEGATIVE — LOW PRIOR, NOT PROOF", ("sampled_search",)),
    ("EMPIRICALLY NEGATIVE / LOW PRIOR", ("empirical_negative",)),
    ("ADMISSIBILITY-REJECTED / PROVENANCE-BLOCKED", ("admissibility",)),
)


# ── Assumption boundaries (alignment / plaintext-length models) ───────────────
#
# Every elimination is proven under SOME assumption about how the 97 carved
# ciphertext characters map to plaintext positions. The vast majority assume a
# DIRECT positional mapping CT[i] -> PT[i] with fixed CT_LEN=97 and fixed public
# crib positions. Such a proof closes ONLY its own alignment model; it does NOT
# close null-bearing, variable-PT-length, non-direct-alignment, or joint
# mask x mechanism inference models. The briefing must make this explicit so a
# direct-mapping closure is never silently read as a global elimination.
#
# Ordered narrowest (most assumptions) -> broadest (fewest assumptions). A proof
# under a narrow model says nothing about a broader one below it.
# Mandated acceptance statement: the briefing must always assert that current
# exhaustion is scoped to the models that actually have a proving artifact.
SCOPED_EXHAUSTION_STATEMENT = (
    "Current exhaustion is SCOPED. Direct-mapping, public-crib-compiled "
    "classical hand-cipher space may be exhausted. Null-bearing / "
    "variable-length / non-direct-mapping space is only closed where a "
    "specific artifact proves THAT model; otherwise it remains outside the "
    "closure certificate."
)

# Cautionary line printed when an assumption-boundary source cannot be located.
_ASSUMPTION_BOUNDARY_WARNING = (
    "WARNING: assumption-boundary source unavailable; do not treat "
    "direct-mapping eliminations as global eliminations."
)

# Sources that back the assumption-boundary discipline. Doc sources are
# repo-relative (any candidate path present satisfies the row). Memory sources
# are research notes that may live in repo memory/ or in Claude Code's
# auto-memory dir; they are searched across candidate directories.
_ASSUMPTION_BOUNDARY_DOC_SOURCES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("docs/REAL_K4_CURRENT_POSITION.md", ("docs/REAL_K4_CURRENT_POSITION.md",)),
    ("AUDIT-1 (docs/methodological_audits.md)",
     ("docs/methodological_audits.md", "docs/methodological_audits")),
)
_ASSUMPTION_BOUNDARY_MEM_SOURCES: tuple[tuple[str, str], ...] = (
    ("feedback_pt_length_open_question.md", "feedback_pt_length_open_question.md"),
    ("project_stego_mechanism_family_cleanup_2026_05_15.md",
     "project_stego_mechanism_family_cleanup_2026_05_15.md"),
)


# ── Assumption-boundary helpers ───────────────────────────────────────────────

def _auto_memory_dir(root: str) -> str:
    """Derive Claude Code's auto-memory dir for this repo from its path.

    /home/cpatrick/kryptos -> ~/.claude/projects/-home-cpatrick-kryptos/memory
    """
    slug = "-" + root.strip("/").replace("/", "-")
    return os.path.expanduser(os.path.join("~", ".claude", "projects", slug, "memory"))


def resolve_assumption_boundary_sources(
    root: str, mem_dirs: Optional[list[str]] = None
) -> list[tuple[str, bool]]:
    """Resolve each assumption-boundary source to (label, found).

    Doc sources are checked relative to `root`. Memory sources are searched
    across `mem_dirs` (defaults to repo memory/, memory/retired/, and the
    derived auto-memory dir). A source is `found` if any candidate exists.
    """
    if mem_dirs is None:
        mem_dirs = [
            os.path.join(root, "memory"),
            os.path.join(root, "memory", "retired"),
            _auto_memory_dir(root),
        ]
    resolved: list[tuple[str, bool]] = []
    for label, candidates in _ASSUMPTION_BOUNDARY_DOC_SOURCES:
        found = any(os.path.exists(os.path.join(root, c)) for c in candidates)
        resolved.append((label, found))
    for label, filename in _ASSUMPTION_BOUNDARY_MEM_SOURCES:
        found = any(os.path.exists(os.path.join(d, filename)) for d in mem_dirs)
        resolved.append((label, found))
    return resolved


def check_assumption_boundary_sources(diag: Diagnostics,
                                      root: Optional[str] = None) -> list[str]:
    """Warn for each missing assumption-boundary source; return missing labels."""
    resolved = resolve_assumption_boundary_sources(root if root is not None else _ROOT)
    missing = [label for label, found in resolved if not found]
    for label in missing:
        diag.warn(f"assumption-boundary source unavailable: {label}")
    return missing


def claims_missing_alignment_model(sections: dict[str, list[dict]]) -> list[str]:
    """Elimination claims (proofs / do_not_test) lacking a valid alignment model.

    Enforces the rule that every elimination must declare which alignment /
    plaintext-length model it assumes. Returns claim_ids (or statement
    prefixes) of offenders.
    """
    offenders: list[str] = []
    for sec in ("proofs", "do_not_test"):
        for c in sections.get(sec, []):
            if c.get("alignment_model") not in _ALIGNMENT_MODEL_KEYS:
                offenders.append(c.get("claim_id") or (c.get("statement", "")[:40]))
    return offenders


def assumption_boundary_summary(sections: dict[str, list[dict]]) -> list[dict]:
    """Group elimination claims by their declared alignment model.

    Returns one row per model (in taxonomy order):
      {key, description, closure_claims: [claim...], has_closure: bool}

    `has_closure` means "at least one elimination is scoped to this model" —
    NOT that the model is globally closed. A claim tagged to a narrow model
    never appears under a broader one, so a direct-mapping proof can never make
    the null-bearing / non-direct / joint models read as closed.
    """
    elim_claims = list(sections.get("proofs", [])) + list(sections.get("do_not_test", []))
    by_model: dict[str, list[dict]] = {k: [] for k, _ in ALIGNMENT_MODELS}
    for c in elim_claims:
        model = c.get("alignment_model")
        if model in by_model:
            by_model[model].append(c)
    rows: list[dict] = []
    for key, desc in ALIGNMENT_MODELS:
        claims = by_model[key]
        rows.append({"key": key, "description": desc,
                     "closure_claims": claims, "has_closure": bool(claims)})
    return rows


# ── Briefing sections ─────────────────────────────────────────────────────────

def section_header() -> None:
    print("=" * 72)
    print("K4 SESSION BRIEFING")
    bean = (f"Bean: {len(BEAN_EQ)} eq + {len(BEAN_INEQ)} ineq + "
            f"{len(BEAN_LINEAR)} linear") if _KERNEL_OK else "Bean: <kernel unavailable>"
    ct_info = f"CT: {CT_LEN} chars  |  Cribs: {N_CRIBS} positions" if _KERNEL_OK \
        else "CT: <kernel unavailable>"
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  {ct_info}  |  {bean}")
    print("=" * 72)


def section_operating_contract() -> None:
    print()
    print("── SESSION OPERATING CONTRACT ─────────────────────────────────────")
    print()
    print("  1. Do not launch compute unless the family is TESTABLE NOW.")
    print("  2. Mathematical/structural proofs are permanent; empirical and")
    print("     sampled negatives are scope-limited (reopenable with new assumptions).")
    print("  3. Retired/disputed/superseded claims are NOT live evidence.")
    print("  4. If a required source is missing/malformed, the briefing is DEGRADED.")
    print("  5. Any new test requires: hypothesis, scope delta, source artifact,")
    print("     pre-registered threshold, and a retest justification.")
    print()


def section_critical_constants(diag: Diagnostics) -> None:
    print("── CRITICAL CONSTANTS ─────────────────────────────────────────────")
    print()
    if not _KERNEL_OK:
        print("  ⚠ kernel constants unavailable — cannot render CT/cribs/Bean.")
        print()
        return
    print(f"  CT: {CT}")
    for start, word in CRIB_WORDS:
        print(f"  Crib: positions {start}-{start + len(word) - 1}: {word}")
    print(f"  Bean equality: k[{BEAN_EQ[0][0]}] = k[{BEAN_EQ[0][1]}]  "
          f"({len(BEAN_INEQ)} inequalities + {len(BEAN_LINEAR)} linear constraints)")
    print("  [DERIVED FACT] These admit exactly 624 valid keystreams at the 24 "
          "crib positions (see memory/bean_linear_constraints_624.md).")
    # Self-encrypting positions sourced from kernel constant, not hardcoded text.
    se = self_encrypting_positions()
    se_str = ", ".join(f"CT[{p}]=PT[{p}]={c}" for p, c in sorted(se.items())) or "none"
    print(f"  Self-encrypting (kernel SELF_ENCRYPTING): {se_str}")
    # IC computed live from CT, compared to the kernel's random baseline.
    ic_val = compute_ic(CT)
    rel = "below" if ic_val < IC_RANDOM else "above"
    print(f"  IC (computed from CT): {ic_val:.4f} — {rel} random baseline "
          f"{IC_RANDOM:.4f} (English {IC_ENGLISH:.4f}).")
    print("    Significance: NOT significant for n=97 (sourced: docs/elimination_tiers.md "
          "E-FRAC-13; this script does not recompute the test).")
    print()
    # Null-palette / consensus-null-positions intentionally NOT printed
    # (retired claim C-PALETTE-01 / SBR-001). Do not re-add.


def section_source_health(diag: Diagnostics, used_fallback: bool,
                          counts: dict[str, int], n_elog: int) -> None:
    print("── SOURCE HEALTH ──────────────────────────────────────────────────")
    print()
    if _KERNEL_OK:
        print("  ✓ kernel constants loaded from kryptos.kernel.constants")
    else:
        print(f"  ✗ kernel constants FAILED to import: {_KERNEL_ERR}")
    print(f"  {'✓' if n_elog else '✗'} exhaustion_log.json: {n_elog} entries")
    print(f"  ✓ result JSON files counted: {counts['total']} "
          f"({counts['top_level']} top-level, {counts['nested']} nested)")
    if used_fallback:
        print("  ⚠ doctrine sections: EMBEDDED FALLBACK in use "
              "(docs/session_briefing_claims.json unavailable)")
    else:
        print("  ✓ doctrine sections loaded from docs/session_briefing_claims.json")
    for w in diag.warnings:
        print(f"  ⚠ {w}")
    for e in diag.errors:
        print(f"  ✗ {e}")
    if diag.degraded:
        print()
        print("  ‼ BRIEFING DEGRADED — a required source is missing/malformed.")
        print("     Treat the state below as incomplete. Re-run with --debug for detail,")
        print("     or --strict to fail the session-start gate.")
    print()


def section_registry_flags(registry_data: Any) -> None:
    """Surface disputed/retired/superseded claims from the canonical registry."""
    claims = registry_data.get("claims", []) if isinstance(registry_data, dict) else []
    if not claims:
        return
    buckets = (
        ("DISPUTED", [c for c in claims if c.get("status") == "disputed"]),
        ("RETIRED", [c for c in claims if c.get("status") == "retired"]),
        ("SUPERSEDED", [c for c in claims if c.get("status") == "superseded"]),
    )
    if not any(b for _, b in buckets):
        return
    print("── CLAIM REGISTRY — DISPUTED / RETIRED / SUPERSEDED ───────────────")
    print()
    print("  From docs/claims_registry.json. Do NOT cite as live evidence")
    print("  without first checking docs/methodological_audits.md.")
    print()
    for name, bucket in buckets:
        if not bucket:
            continue
        print(f"  {name}:")
        for c in bucket:
            cid = c.get("claim_id", "?")
            stmt = c.get("statement", "")
            short = (stmt[:118] + "…") if len(stmt) > 118 else stmt
            print(f"    • {cid}: {short}")
        print()


def section_exhaustion_summary(elog: dict, diag: Diagnostics) -> None:
    from collections import defaultdict
    print("── ELIMINATION LANDSCAPE ──────────────────────────────────────────")
    print()
    if not elog:
        print("  ⚠ exhaustion_log.json unavailable — landscape cannot be rendered.")
        print()
        return

    families: dict[str, dict[str, int]] = defaultdict(
        lambda: {"exhausted": 0, "active": 0, "blocked": 0, "retired": 0,
                 "unknown": 0, "total": 0, "certified": 0})
    for v in elog.values():
        fam = v.get("family", "_unknown")
        bucket = _bucket_status(v.get("status", "unknown"))
        families[fam][bucket] += 1
        families[fam]["total"] += 1
        if v.get("phase2_certificate") or v.get("coverage_certificate"):
            families[fam]["certified"] += 1

    total = sum(f["total"] for f in families.values())
    tot_exh = sum(f["exhausted"] for f in families.values())
    tot_act = sum(f["active"] for f in families.values())
    tot_other = total - tot_exh - tot_act
    print(f"  Scripts tracked: {total}  |  Exhausted: {tot_exh}  |  "
          f"Active: {tot_act}  |  Blocked/retired/unknown: {tot_other}")
    print()
    print(f"  {'Family':<28s} {'Exh':>4s} {'Act':>4s} {'Tot':>4s}  Status")
    print(f"  {'-'*28} {'-'*4} {'-'*4} {'-'*4}  {'-'*30}")

    sorted_fams = sorted(families.items(),
                         key=lambda x: (-x[1]["exhausted"], -x[1]["total"]))
    shown = 0
    max_rows = 20
    hidden = 0
    for fam, c in sorted_fams:
        if c["total"] < 2 and c["exhausted"] == 0:
            continue
        if shown >= max_rows:
            hidden += 1
            continue
        shown += 1
        if c["exhausted"] == c["total"] and c["total"] > 0:
            if c["certified"] > 0:
                status = "COVERAGE-CERTIFIED ELIMINATED"
            else:
                status = "ALL TRACKED SCRIPTS EXHAUSTED"
        elif c["exhausted"] > 0:
            pct = c["exhausted"] / c["total"] * 100
            status = f"PARTIALLY EXHAUSTED ({pct:.0f}%)"
        elif c["blocked"] > 0 and c["active"] == 0:
            status = "BLOCKED"
        elif c["retired"] > 0 and c["active"] == 0 and c["exhausted"] == 0:
            status = "RETIRED"
        elif c["active"] > 0:
            status = "ACTIVE / TESTABLE"
        else:
            status = "UNKNOWN STATUS"
        print(f"  {fam[:28]:<28s} {c['exhausted']:>4d} {c['active']:>4d} "
              f"{c['total']:>4d}  {status}")
    if hidden:
        print(f"  ... and {hidden} more families with fewer exhausted scripts "
              f"(see exhaustion_log.json)")
    print()
    print("  Note: 'ALL TRACKED SCRIPTS EXHAUSTED' means every tracked script in")
    print("  that family is marked exhausted — NOT a coverage-certified proof of")
    print("  family-wide impossibility unless tagged COVERAGE-CERTIFIED.")
    print()


def _align_tag(c: dict) -> str:
    """Inline alignment-model tag for an elimination claim, or '' if absent."""
    model = c.get("alignment_model")
    return f"  [align: {model}]" if model in _ALIGNMENT_MODEL_KEYS else ""


def _render_claim_lines(claims: list[dict], marker: str, scope_limited: bool) -> None:
    for c in claims:
        stmt = c.get("statement", "")
        scope = c.get("scope")
        align = _align_tag(c)
        if scope_limited and scope:
            print(f"  {marker} {stmt}  [scope: {scope}]{align}")
        else:
            print(f"  {marker} {stmt}{align}")


def section_proofs(sections: dict[str, list[dict]]) -> None:
    proofs = sections.get("proofs", [])
    print("── PROVEN / CERTIFIED CLOSURES (by evidence class) ────────────────")
    print()
    if not proofs:
        print("  ⚠ no proof claims available.")
        print()
        return
    by_class: dict[str, list[dict]] = {}
    for c in proofs:
        by_class.setdefault(c.get("evidence_class", "unknown"), []).append(c)
    for heading, classes in _EVIDENCE_GROUPS:
        group = [c for cl in classes for c in by_class.get(cl, [])]
        if not group:
            continue
        permanent = any(cl in ("mathematical_proof", "structural_proof") for cl in classes)
        marker = "✗" if permanent else "·"
        scope_limited = not permanent
        print(f"  {heading}")
        _render_claim_lines(group, marker, scope_limited)
        print()


def section_do_not_test(sections: dict[str, list[dict]]) -> None:
    items = sections.get("do_not_test", [])
    print("── DO NOT TEST (without a materially new assumption) ──────────────")
    print()
    if not items:
        print("  ⚠ no do-not-test claims available.")
        print()
        return
    for c in items:
        ec = c.get("evidence_class", "unknown")
        permanent = ec in ("mathematical_proof", "structural_proof")
        marker = "✗" if permanent else "·"
        stmt = c.get("statement", "")
        tag = "" if permanent else f"  [{ec}]"
        print(f"  {marker} {stmt}{tag}{_align_tag(c)}")
    print()


def section_assumption_boundaries(sections: dict[str, list[dict]],
                                  diag: Diagnostics) -> None:
    """Render the alignment / plaintext-length model boundary for eliminations.

    Makes explicit which alignment model each closure assumes, and refuses to
    let a direct-mapping closure read as closing null-bearing / variable-length
    / non-direct space. Always ends with the mandated scoped-exhaustion
    statement.
    """
    print("── ASSUMPTION BOUNDARIES (alignment / plaintext-length models) ────")
    print()
    print("  Every elimination below assumes a specific mapping from the 97")
    print("  carved CT chars to plaintext positions. A proof under a NARROW")
    print("  model does NOT close a BROADER model. Models are ordered narrowest")
    print("  (most assumptions) to broadest (fewest):")
    print()
    summary = assumption_boundary_summary(sections)
    for row in summary:
        key, desc = row["key"], row["description"]
        claims = row["closure_claims"]
        if claims:
            print(f"  • {key}")
            print(f"      {desc}")
            print(f"      SCOPED CLOSURES ({len(claims)}) — apply only within this model:")
            for c in claims:
                stmt = c.get("statement", "")
                scope = c.get("scope")
                scope_str = f"  [scope: {scope}]" if scope else ""
                print(f"        - {stmt}{scope_str}")
        else:
            print(f"  • {key} — NOT CLOSED")
            print(f"      {desc}")
            print("      No artifact proves any closure under this model; it remains")
            print("      outside the closure certificate.")
    print()

    # Flag any elimination claim that failed to declare its alignment model.
    missing = claims_missing_alignment_model(sections)
    if missing:
        diag.warn(f"{len(missing)} elimination claim(s) lack a declared "
                  f"alignment_model: {', '.join(missing[:6])}"
                  + (" ..." if len(missing) > 6 else ""))
        print(f"  ⚠ {len(missing)} elimination claim(s) do NOT declare an alignment")
        print("    model. Treat them as direct-mapping-scoped only — they do NOT")
        print("    close null-bearing, variable-length, or non-direct space.")
        print()

    # Surface assumption-boundary source availability and, if any is missing,
    # the mandated cautionary line.
    sources = resolve_assumption_boundary_sources(_ROOT)
    missing_sources = [label for label, found in sources if not found]
    if missing_sources:
        print("  Assumption-boundary sources:")
        for label, found in sources:
            print(f"    {'✓' if found else '✗'} {label}")
        print(f"  ‼ {_ASSUMPTION_BOUNDARY_WARNING}")
        print()

    print("  " + _scoped_statement_block())
    print()


def _scoped_statement_block() -> str:
    """The mandated scoped-exhaustion statement, wrapped for the briefing."""
    import textwrap
    wrapped = textwrap.fill(SCOPED_EXHAUSTION_STATEMENT, width=68,
                            subsequent_indent="  ")
    return wrapped


def section_anomalies(sections: dict[str, list[dict]]) -> None:
    surviving = sections.get("surviving_anomaly", [])
    retired = sections.get("retired_anomaly", [])
    print("── SURVIVING ANOMALIES (real but not exploitable) ─────────────────")
    print()
    if surviving:
        for c in surviving:
            print(f"  • {c.get('statement', '')}")
    else:
        print("  (none recorded)")
    print()
    print("── RETIRED ANOMALIES (do NOT revive as live evidence) ─────────────")
    print()
    if retired:
        for c in retired:
            print(f"  ✗ {c.get('statement', '')}")
    else:
        print("  (none recorded)")
    print()


def section_results_verdicts(results: list[ResultEntry]) -> None:
    print("── RESULTS WITH VERDICTS ──────────────────────────────────────────")
    print()
    from collections import Counter
    by_class = Counter(r.verdict_class for r in results if r.verdict is not None)
    closed = by_class[VerdictClass.CLOSED]
    noise = by_class[VerdictClass.NOISE]
    retired = by_class[VerdictClass.RETIRED]
    openc = by_class[VerdictClass.OPEN]
    blocked = by_class[VerdictClass.BLOCKED]
    unknown = by_class[VerdictClass.UNKNOWN]
    print(f"  Closed: {closed}  |  Noise: {noise}  |  Retired: {retired}  |  "
          f"Open: {openc}  |  Blocked: {blocked}  |  Unknown: {unknown}")
    print(f"  (scoped scan: {len(results)} campaign-level artifacts parsed; "
          f"deep per-job files not parsed)")
    print()

    # OPEN / signal results need attention — show all.
    open_results = [r for r in results if r.verdict_class == VerdictClass.OPEN]
    if open_results:
        print(f"  OPEN / NEEDS ATTENTION ({len(open_results)}):")
        for r in open_results:
            score = f" best={r.best_score}" if r.best_score is not None else ""
            ts = f" ({r.timestamp[:10]})" if r.timestamp else ""
            print(f"    {r.name[:44]:<44s} {(r.verdict or '')[:22]}{score}{ts}")
        print()

    # Recently-closed results, timestamp-sorted (undated last).
    closed_results = [r for r in results
                      if r.verdict_class in (VerdictClass.CLOSED, VerdictClass.NOISE)]
    closed_results.sort(
        key=lambda r: (r.timestamp_dt is not None, r.timestamp_dt or datetime.min),
        reverse=True)
    dated = [r for r in closed_results if r.timestamp_dt is not None]
    if dated:
        print(f"  MOST RECENT CLOSED/NOISE (by timestamp, {len(dated)} dated):")
        for r in dated[:10]:
            score = f" best={r.best_score}" if r.best_score is not None else ""
            print(f"    {r.timestamp[:10]}  {r.name[:40]:<40s} {(r.verdict or '')[:18]}{score}")
        if len(closed_results) > len(dated):
            print(f"    ... plus {len(closed_results) - len(dated)} undated closed/noise results")
        print()

    # Only flag results that HAD a verdict string we could not classify — not
    # results that simply lack a verdict field (those are merely uncategorized).
    unknown_results = [r for r in results
                       if r.verdict_class == VerdictClass.UNKNOWN and r.verdict is not None]
    if unknown_results:
        print(f"  ⚠ {len(unknown_results)} result(s) have unrecognized verdict strings "
              f"(classified UNKNOWN, NOT closed):")
        for r in unknown_results[:6]:
            print(f"    {r.name[:44]:<44s} {(r.verdict or '')[:24]}")
        if len(unknown_results) > 6:
            print(f"    ... and {len(unknown_results) - 6} more")
        print()


def _md_has_closure_language(path: str) -> bool:
    try:
        with open(path) as f:
            text = f.read().lower()
    except OSError:
        return False
    needles = ("certificate", "formally closes", "exhaustion complete",
               "final checklist complete", "no candidates escalated", "closed the bin")
    return any(n in text for n in needles)


def _bin_c_status(campaign_id: str, diag: Diagnostics) -> dict[str, Any]:
    """Resolve the real closure state of a bin-C campaign from artifacts.

    Returns {status, verdict, artifact, warnings}. status is one of
    CLOSED / TESTABLE / DEFERRED / OPEN / UNKNOWN / DEGRADED.

    Closure requires an EXPLICIT terminal classified verdict, a structured
    completion signal (campaign ran with zero escalated candidates), or
    content-verified closure language — never the mere existence of a file
    or a JSON entry.
    """
    warnings: list[str] = []
    artifact_map = {
        "C7": [
            (os.path.join("results", "admissibility_elimination_v1",
                          "running_key_policy.json"), None),
            (os.path.join("docs", "exhaustion_certificate_2026_04_08.md"), None),
        ],
        "C1": [(os.path.join("results", "f_final_checklist_c1_c2.json"), "carter_tomb_vol1")],
        "C2": [(os.path.join("results", "f_final_checklist_c1_c2.json"), "kahn_codebreakers")],
        "C6": [(os.path.join("results", "f_final_checklist_c6.json"), None)],
    }
    deferred = {"C3", "C4", "C5", "C8"}
    if campaign_id in deferred:
        return {"status": "DEFERRED", "verdict": None, "artifact": None, "warnings": []}

    for rel_path, inner_key in artifact_map.get(campaign_id, []):
        full = os.path.join(_ROOT, rel_path)
        if not os.path.exists(full):
            continue

        # Markdown fallback: closure ONLY if content has closure language.
        if full.endswith(".md"):
            if _md_has_closure_language(full):
                return {"status": "CLOSED", "verdict": "CERTIFIED (content-verified)",
                        "artifact": rel_path, "warnings": warnings}
            warnings.append(f"{rel_path} present but no closure language found")
            continue

        try:
            with open(full) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            detail = f" ({exc})" if diag.debug else ""
            warnings.append(f"malformed artifact {rel_path}{detail}")
            continue
        if not isinstance(data, dict):
            warnings.append(f"artifact {rel_path} is not an object")
            continue

        # C7-style structured policy signal: unclear == 0 means certified.
        if "unclear" in data and "n_scripts" in data:
            if data.get("unclear") == 0:
                acc, rej = data.get("accepted", "?"), data.get("rejected", "?")
                return {"status": "CLOSED",
                        "verdict": f"CERTIFIED (unclear=0, accepted={acc}, rejected={rej})",
                        "artifact": rel_path, "warnings": warnings}
            warnings.append(f"{rel_path} has {data.get('unclear')} UNCLEAR entries — not closed")
            return {"status": "OPEN", "verdict": "UNCLEAR entries remain",
                    "artifact": rel_path, "warnings": warnings}

        # Combined multi-campaign JSON: find the named campaign entry.
        if inner_key and "campaigns" in data:
            for entry in data["campaigns"]:
                if not isinstance(entry, dict) or entry.get("source_id") != inner_key:
                    continue
                raw_verdict = first_present(entry, _VERDICT_KEYS)
                if raw_verdict is not None:
                    vc = classify_verdict(raw_verdict)
                    if is_terminal(vc):
                        return {"status": "CLOSED", "verdict": normalize_verdict(raw_verdict),
                                "artifact": rel_path, "warnings": warnings}
                    return {"status": "OPEN", "verdict": normalize_verdict(raw_verdict),
                            "artifact": rel_path, "warnings": warnings}
                # No verdict string: derive from structured completion metrics.
                escalated = entry.get("escalated_candidates")
                max_score = first_present(entry, ("max_crib_score", "max_score"))
                ran = first_present(entry, ("orderings_tested", "offsets_scanned",
                                            "bean_passing_orderings"))
                if isinstance(escalated, list) and len(escalated) > 0:
                    return {"status": "OPEN",
                            "verdict": f"{len(escalated)} escalated candidate(s)",
                            "artifact": rel_path, "warnings": warnings}
                if isinstance(escalated, list) and ran is not None:
                    return {"status": "CLOSED",
                            "verdict": f"NO_ESCALATION (max_crib_score={max_score})",
                            "artifact": rel_path, "warnings": warnings}
                warnings.append(f"{rel_path} campaign {inner_key} has neither verdict "
                                f"nor completion metrics")
                return {"status": "UNKNOWN", "verdict": None,
                        "artifact": rel_path, "warnings": warnings}
            warnings.append(f"{rel_path} has no campaign entry for {inner_key}")
            continue

        # Flat single-campaign JSON: require a terminal classified verdict.
        raw_verdict = first_present(data, _VERDICT_KEYS)
        if raw_verdict is not None:
            vc = classify_verdict(raw_verdict)
            status = "CLOSED" if is_terminal(vc) else "OPEN"
            return {"status": status, "verdict": normalize_verdict(raw_verdict),
                    "artifact": rel_path, "warnings": warnings}
        # C6-style: outer/middle/inner enumeration with escalation list.
        escalated = first_present(data, ("escalated_candidates", "candidates"))
        ran = first_present(data, ("total_configs", "configs_tested", "combos_tested"))
        if isinstance(escalated, list) and len(escalated) > 0:
            return {"status": "OPEN", "verdict": f"{len(escalated)} escalated",
                    "artifact": rel_path, "warnings": warnings}
        if isinstance(escalated, list) and ran is not None:
            return {"status": "CLOSED", "verdict": "NO_ESCALATION",
                    "artifact": rel_path, "warnings": warnings}
        warnings.append(f"{rel_path} has no verdict and no recognizable completion signal")
        return {"status": "UNKNOWN", "verdict": None,
                "artifact": rel_path, "warnings": warnings}

    return {"status": "TESTABLE", "verdict": None, "artifact": None, "warnings": warnings}


_BIN_C_DESCRIPTIONS = [
    ("C7", "Admissibility backlog (running-key provenance review)"),
    ("C1", "Carter Vol 1 + columnar w6/8/9 x 3 variants (admissibility-gated)"),
    ("C2", "Kahn Codebreakers + columnar w6/8/9 x 3 variants (admissibility-gated)"),
    ("C6", "Non-columnar 3-layer enumeration"),
    ("C3", "Bifid as composition OUTER"),
    ("C4", "Four-square as composition OUTER"),
    ("C5", "Homophonic as composition OUTER"),
    ("C8", "Stateful seed-space expansion"),
]


def section_open_attack_surface(sections: dict[str, list[dict]],
                                bin_c_status: dict[str, dict]) -> None:
    print("── FINAL CHECKLIST — BIN C (execution state) ──────────────────────")
    print()
    n_closed = n_testable = n_deferred = n_other = 0
    for cid, name in _BIN_C_DESCRIPTIONS:
        st = bin_c_status[cid]
        status, verdict, artifact = st["status"], st["verdict"], st["artifact"]
        if status == "CLOSED":
            n_closed += 1; marker = "✓"; tag = f"CLOSED ({verdict})" if verdict else "CLOSED"
        elif status == "DEFERRED":
            n_deferred += 1; marker = "⊘"; tag = "DEFERRED (run only if upstream escalates)"
        elif status == "TESTABLE":
            n_testable += 1; marker = "→"; tag = "TESTABLE NOW"
        elif status == "OPEN":
            n_other += 1; marker = "!"; tag = f"OPEN ({verdict})" if verdict else "OPEN"
        else:
            n_other += 1; marker = "?"; tag = f"{status}"
        print(f"  {marker} {cid:<3s} {name} — {tag}")
        if artifact:
            print(f"      artifact: {artifact}")
    print()
    print(f"  Summary: {n_closed} closed, {n_testable} testable, "
          f"{n_deferred} deferred, {n_other} open/unknown")
    print()

    print("── BIN D — weakly testable (engineering, not compute) ─────────────")
    print()
    bin_d = sections.get("bin_d", [])
    if bin_d:
        for c in bin_d:
            print(f"  → {c.get('statement', '')}")
    else:
        print("  ⚠ no bin-D claims available.")
    print()
    print("── BIN E — untestable under current clues (waiting list) ──────────")
    print()
    bin_e = sections.get("bin_e", [])
    if bin_e:
        for c in bin_e:
            print(f"  ⊘ {c.get('statement', '')}")
    else:
        print("  ⚠ no bin-E claims available.")
    print()
    print("  Bin D/E are prerequisites for new testable hypotheses, not open families.")
    print()


def section_pitfalls(sections: dict[str, list[dict]]) -> None:
    print("── PITFALLS ───────────────────────────────────────────────────────")
    print()
    for c in sections.get("pitfall", []):
        print(f"  ⚠ {c.get('statement', '')}")
    print()


def section_footer(counts: dict[str, int], n_elog: int, n_scripts: int,
                   diag: Diagnostics) -> None:
    print("=" * 72)
    print(f"Data sources: exhaustion_log.json ({n_elog} entries) | "
          f"results/ ({counts['total']} JSON: {counts['top_level']} top-level, "
          f"{counts['nested']} nested, {counts['result_json']} result.json, "
          f"{counts['summary_json']} summary.json across {counts['subdirs']} subdirs) | "
          f"{n_scripts} scripts")
    if diag.degraded:
        print("STATUS: ‼ DEGRADED — see SOURCE HEALTH above.")
    else:
        print(f"STATUS: ok ({len(diag.warnings)} warning(s))")
    print("Detailed proofs: docs/elimination_tiers.md | "
          "Doctrine registry: docs/session_briefing_claims.json")
    print("Search experiments: PYTHONPATH=src python3 run_attack.py --list --verbose | grep KEYWORD")
    print("=" * 72)


# ── Orchestration ─────────────────────────────────────────────────────────────

def build_state(diag: Diagnostics) -> dict[str, Any]:
    """Load and resolve ALL sources up front so SOURCE HEALTH (rendered near
    the top) reflects every warning — including those from bin-C artifact
    resolution and the claims registry. Render is a pure consumer of state."""
    elog = load_json(os.path.join(_ROOT, "exhaustion_log.json"), diag, required=True)
    if not isinstance(elog, dict):
        elog = {}
    sections, used_fallback = load_section_claims(diag)
    registry = load_json(os.path.join(_ROOT, "docs", "claims_registry.json"),
                         diag, required=True)
    # Assumption-boundary sources are warn-level (not degrade): a missing one
    # triggers the cautionary line in the ASSUMPTION BOUNDARIES section.
    check_assumption_boundary_sources(diag)
    results = scan_result_files(diag)
    counts = count_result_files()
    bin_c_status: dict[str, dict] = {}
    for cid, _name in _BIN_C_DESCRIPTIONS:
        st = _bin_c_status(cid, diag)
        for w in st["warnings"]:
            diag.warn(f"bin-{cid}: {w}")
        bin_c_status[cid] = st
    return {
        "elog": elog,
        "sections": sections,
        "used_fallback": used_fallback,
        "registry": registry,
        "results": results,
        "counts": counts,
        "n_scripts": count_scripts(),
        "bin_c_status": bin_c_status,
    }


def render(state: dict[str, Any], diag: Diagnostics) -> None:
    section_header()
    section_critical_constants(diag)
    section_operating_contract()
    # SOURCE HEALTH near the top: all diagnostics were already collected in
    # build_state(), so this panel is complete.
    section_source_health(diag, state["used_fallback"], state["counts"], len(state["elog"]))
    section_registry_flags(state["registry"])
    section_exhaustion_summary(state["elog"], diag)
    section_proofs(state["sections"])
    section_do_not_test(state["sections"])
    section_assumption_boundaries(state["sections"], diag)
    section_anomalies(state["sections"])
    section_results_verdicts(state["results"])
    section_open_attack_surface(state["sections"], state["bin_c_status"])
    section_pitfalls(state["sections"])
    section_footer(state["counts"], len(state["elog"]), state["n_scripts"], diag)


def emit_json(state: dict[str, Any], diag: Diagnostics) -> None:
    payload = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "degraded": diag.degraded,
        "kernel_ok": _KERNEL_OK,
        "counts": state["counts"],
        "n_elog": len(state["elog"]),
        "n_scripts": state["n_scripts"],
        "used_fallback_doctrine": state["used_fallback"],
        "results_by_class": {},
        "bin_c": {},
        "warnings": diag.warnings,
        "errors": diag.errors,
    }
    from collections import Counter
    by_class = Counter(r.verdict_class.value for r in state["results"] if r.verdict)
    payload["results_by_class"] = dict(by_class)
    for cid, st in state["bin_c_status"].items():
        payload["bin_c"][cid] = {"status": st["status"], "verdict": st["verdict"]}
    print(json.dumps(payload, indent=2))


# ── Self-test (lightweight; full suite in tests/test_session_briefing.py) ──────

def run_self_test() -> int:
    checks = []

    def ok(cond, label):
        checks.append((bool(cond), label))

    ok(classify_verdict("ELIMINATED") == VerdictClass.CLOSED, "ELIMINATED->CLOSED")
    ok(classify_verdict("CERTIFIED") == VerdictClass.CLOSED, "CERTIFIED->CLOSED")
    ok(classify_verdict("INTERESTING") == VerdictClass.OPEN, "INTERESTING->OPEN")
    ok(classify_verdict("SIGNAL") == VerdictClass.OPEN, "SIGNAL->OPEN")
    ok(classify_verdict("FAILED_TO_ELIMINATE") != VerdictClass.CLOSED,
       "FAILED_TO_ELIMINATE not CLOSED")
    ok(classify_verdict("NOT ELIMINATED") != VerdictClass.CLOSED, "NOT ELIMINATED not CLOSED")
    ok(classify_verdict("UNCLEAR") in (VerdictClass.UNKNOWN, VerdictClass.OPEN),
       "UNCLEAR open/unknown")
    ok(classify_verdict("") == VerdictClass.UNKNOWN, "empty->UNKNOWN")
    ok(classify_verdict(None) == VerdictClass.UNKNOWN, "None->UNKNOWN")
    ok(classify_verdict("NOISE -- 6/24") == VerdictClass.NOISE, "NOISE phrase->NOISE")
    ok(classify_verdict("MARGINAL -- LIKELY NOISE") == VerdictClass.NOISE,
       "MARGINAL+NOISE->NOISE")
    ok(first_present({"a": 0, "b": 5}, ("a", "b")) == 0, "first_present preserves 0")
    ok(first_present({"a": None, "b": 5}, ("a", "b")) == 5, "first_present skips None")
    ok(parse_timestamp("2026-04-08T14:18:44") is not None, "iso timestamp parses")
    ok(parse_timestamp("garbage") is None, "garbage timestamp -> None")
    if _KERNEL_OK:
        ok(abs(compute_ic(CT) - 0.0361) < 0.001, "IC(CT) stable ~0.0361")
        ok(set(self_encrypting_positions()) == {32, 73}, "self-encrypting {32,73}")
    ok(compute_ic("AAAA") == 1.0, "IC all-same == 1.0")

    failed = [label for cond, label in checks if not cond]
    for cond, label in checks:
        print(f"  {'PASS' if cond else 'FAIL'}  {label}")
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="K4 session briefing (renderer + validator)")
    parser.add_argument("--strict", action="store_true",
                        help="exit nonzero if a required source is missing/malformed")
    parser.add_argument("--debug", action="store_true",
                        help="include parse-error detail in SOURCE HEALTH")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable diagnostics/state and exit")
    parser.add_argument("--self-test", action="store_true",
                        help="run built-in helper assertions and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if not _KERNEL_OK:
        print(f"FATAL: kernel constants unavailable ({_KERNEL_ERR}). "
              f"Run with PYTHONPATH=src.", file=sys.stderr)
        return 2

    diag = Diagnostics(debug=args.debug)
    state = build_state(diag)

    if args.json:
        emit_json(state, diag)
    else:
        render(state, diag)

    if args.strict and diag.degraded:
        print("\n--strict: exiting nonzero due to degraded required source(s).",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
