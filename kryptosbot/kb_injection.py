"""KB query, signature generation, and novelty join for Phase 2 yield-feedback.

Stdlib + sqlite3. Reads ``db/cipher_discovery.sqlite`` (or an injected
path for tests). Produces ``CipherDiscoverySuggestion`` records for the
critic to attach to ``REJECT_EMPIRICALLY_DEAD`` rejections.

See docs/specs/2026-05-16-yield-feedback-phase2-design.md §4.2.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable, Literal, Optional


KB_SIGNATURE_SCHEMA_VERSION = "kb_mechanism_sig_v1"

_WHITESPACE_RE = re.compile(r"\s+")
_WORD_RE = re.compile(r"[a-z0-9]+")


def _normalize(s: Optional[str]) -> str:
    """Lowercase, collapse internal whitespace, strip. None → ''."""
    if not s or not isinstance(s, str):
        return ""
    return _WHITESPACE_RE.sub(" ", s).strip().lower()


def _content_tokens(*fields: Optional[str]) -> tuple[str, ...]:
    """Extract a sorted, deduplicated tuple of word tokens from prose fields.

    Used for signature payload — order-independent, case-folded, no
    punctuation. Empty fields contribute nothing.
    """
    joined = " ".join(_normalize(f) for f in fields if f)
    tokens = set(_WORD_RE.findall(joined))
    return tuple(sorted(tokens))


def kb_mechanism_signature(record) -> str:
    """Deterministic 16-char hash of normalized KB fields.

    The signature describes the KB mechanism itself. The ledger-family
    mapping (``kb_family_map.KB_TO_LEDGER_FAMILY``) is deliberately
    EXCLUDED — mixing it in would let a mapping-table edit silently
    invalidate every prior signature.

    Accepts any record with the CipherRecord-compatible attribute set
    (canonical_name, cipher_family, cipher_type, taxonomy, operational_mechanics,
    description). Taxonomy may be an enum-like with ``.value`` or a string.
    """
    cipher_type_val = getattr(record, "cipher_type", "")
    if hasattr(cipher_type_val, "value"):
        cipher_type_val = cipher_type_val.value
    taxonomy_val = getattr(record, "taxonomy", "")
    if hasattr(taxonomy_val, "value"):
        taxonomy_val = taxonomy_val.value

    payload = {
        "schema": KB_SIGNATURE_SCHEMA_VERSION,
        "canonical_name": _normalize(getattr(record, "canonical_name", "")),
        "cipher_family": _normalize(getattr(record, "cipher_family", "")),
        "cipher_type": _normalize(str(cipher_type_val or "")),
        "taxonomy": _normalize(str(taxonomy_val or "")),
        "mechanics_tokens": list(_content_tokens(
            getattr(record, "canonical_name", ""),
            getattr(record, "cipher_family", ""),
            str(cipher_type_val or ""),
            getattr(record, "operational_mechanics", ""),
            getattr(record, "description", ""),
        )),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def dispatcher_testable(record) -> bool:
    """True iff the record's cipher_family maps to a dispatcher-supported kind.

    Two-step: KB cipher_family → KB_TO_DSL_KIND → kind → _SUPPORTED_KINDS.
    The second step is re-evaluated at every call so dispatcher changes
    take effect immediately.
    """
    from kryptosbot.kb_family_map import KB_TO_DSL_KIND, normalize_kb_family
    from kryptosbot.job_dispatcher import _SUPPORTED_KINDS

    key = normalize_kb_family(getattr(record, "cipher_family", ""))
    kind = KB_TO_DSL_KIND.get(key)
    return bool(kind and kind in _SUPPORTED_KINDS)


NoveltyVerdictKind = Literal["allow", "reject", "defer_needs_mapping"]


@dataclass(frozen=True)
class KBCandidateNoveltyVerdict:
    """Per-row novelty join result. Constructed once per candidate row.

    ``verdict`` is the actionable output:
    - "allow"              — candidate survives all filters; emit suggestion.
    - "reject"             — failed one or more eligibility / novelty checks.
    - "defer_needs_mapping" — KB cipher_family is not in KB_TO_LEDGER_FAMILY.
                             Operator review path; never silently rendered.
    """
    kb_record_id: str
    kb_cipher_family: str
    mapped_ledger_families: tuple[str, ...]
    tested_status_ok: bool
    family_blocked: bool
    static_exhaustion_blocked: bool
    mechanism_signature: str
    signature_seen: bool
    dispatcher_testable: bool
    verdict: NoveltyVerdictKind
    reasons: tuple[str, ...]


SketchClass = Literal["dsl_testable", "category_b", "unknown"]


@dataclass(frozen=True)
class CipherDiscoverySuggestion:
    """Single rendered suggestion attached to an EmpiricalDeathRejectionPayload.

    Carries enough structure for the critic to ledger and the controller
    to aggregate and render, but never enough to auto-dispatch.
    Suggestions are prompt context only — the theorist must still draft
    a HypothesisSpec and the critic must still admit it.
    """
    kb_record_id: str
    canonical_name: str
    kb_cipher_family: str
    mapped_ledger_families: tuple[str, ...]
    mechanism_signature: str
    signature_schema_version: str
    dispatcher_testable: bool
    k4_relevance_score: float
    sketch_class: SketchClass
    one_line_sketch: str
    bounded_kill_criterion: str
    source_verdict: Literal["allow"]

    def to_dict(self) -> dict:
        return {
            "kb_record_id": self.kb_record_id,
            "canonical_name": self.canonical_name,
            "kb_cipher_family": self.kb_cipher_family,
            "mapped_ledger_families": list(self.mapped_ledger_families),
            "mechanism_signature": self.mechanism_signature,
            "signature_schema_version": self.signature_schema_version,
            "dispatcher_testable": bool(self.dispatcher_testable),
            "k4_relevance_score": float(self.k4_relevance_score),
            "sketch_class": self.sketch_class,
            "one_line_sketch": self.one_line_sketch,
            "bounded_kill_criterion": self.bounded_kill_criterion,
            "source_verdict": self.source_verdict,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CipherDiscoverySuggestion":
        return cls(
            kb_record_id=str(d.get("kb_record_id", "")),
            canonical_name=str(d.get("canonical_name", "")),
            kb_cipher_family=str(d.get("kb_cipher_family", "")),
            mapped_ledger_families=tuple(d.get("mapped_ledger_families") or ()),
            mechanism_signature=str(d.get("mechanism_signature", "")),
            signature_schema_version=str(
                d.get("signature_schema_version", KB_SIGNATURE_SCHEMA_VERSION)
            ),
            dispatcher_testable=bool(d.get("dispatcher_testable", False)),
            k4_relevance_score=float(d.get("k4_relevance_score", 0.0)),
            sketch_class=d.get("sketch_class", "unknown"),
            one_line_sketch=str(d.get("one_line_sketch", "")),
            bounded_kill_criterion=str(d.get("bounded_kill_criterion", "")),
            source_verdict="allow",
        )


import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


# Columns we strictly require from the cipher_records table. Other columns
# are read opportunistically; missing values fall back to dataclass defaults.
_CORE_COLUMNS = (
    "record_id",
    "canonical_name",
    "cipher_family",
    "cipher_type",
    "taxonomy",
    "description",
    "operational_mechanics",
    "k4_relevance_score",
    "tested_in_project",
    "exhaustion_status",
)


def iter_kb_records(db_path: str):
    """Yield CipherRecord-compatible objects from ``db_path``.

    Missing DB → empty iterator (no exception). Corrupt rows → skipped
    with WARNING. Schema-version drift on the cipher_records table is
    tolerated as long as the columns in _CORE_COLUMNS are present.
    """
    from kryptos.cipher_discovery.schema import CipherRecord

    if not Path(db_path).exists():
        return

    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        # Introspect which of the core columns are actually present so
        # we tolerate schema drift / minimal fixtures gracefully.
        try:
            info = conn.execute("PRAGMA table_info(cipher_records)").fetchall()
        except sqlite3.Error as exc:
            logger.warning("kb_injection: table_info failed: %s", exc)
            return
        present = {r["name"] for r in info}
        if not present:
            logger.warning("kb_injection: cipher_records table missing or empty schema")
            return
        select_cols = [c for c in _CORE_COLUMNS if c in present]
        if "record_id" not in select_cols or "canonical_name" not in select_cols:
            logger.warning(
                "kb_injection: cipher_records missing required columns; have %r",
                sorted(present),
            )
            return
        try:
            cursor = conn.execute(
                f"SELECT {','.join(select_cols)} FROM cipher_records"
            )
        except sqlite3.Error as exc:
            logger.warning("kb_injection: cipher_records query failed: %s", exc)
            return
        for row in cursor:
            try:
                keys = set(row.keys())
                rec = CipherRecord(
                    record_id=(row["record_id"] if "record_id" in keys else "") or "",
                    canonical_name=(row["canonical_name"] if "canonical_name" in keys else "") or "",
                    cipher_family=(row["cipher_family"] if "cipher_family" in keys else "") or "",
                    description=(row["description"] if "description" in keys else "") or "",
                    operational_mechanics=(row["operational_mechanics"] if "operational_mechanics" in keys else "") or "",
                )
                # Patch the bare-string enum-typed columns onto the
                # CipherRecord via direct attribute assignment so we
                # don't have to construct the actual enums (and so
                # taxonomy/cipher_type drift doesn't crash the loader).
                if "cipher_type" in keys:
                    try:
                        rec.cipher_type = row["cipher_type"] or ""
                    except Exception:
                        pass
                if "taxonomy" in keys:
                    try:
                        rec.taxonomy = row["taxonomy"] or ""
                    except Exception:
                        pass
                if "k4_relevance_score" in keys:
                    rec.k4_relevance_score = float(row["k4_relevance_score"] or 0.0)
                if "tested_in_project" in keys:
                    rec.tested_in_project = bool(row["tested_in_project"])
                if "exhaustion_status" in keys:
                    rec.exhaustion_status = row["exhaustion_status"] or ""
                yield rec
            except Exception as exc:
                rid = row["record_id"] if "record_id" in row.keys() else "?"
                logger.warning(
                    "kb_injection: skipping corrupt row %r: %s", rid, exc
                )
                continue
    except sqlite3.Error as exc:
        logger.warning("kb_injection: sqlite open failed: %s", exc)
    finally:
        if conn is not None:
            conn.close()


_EXHAUSTED_STATUSES = frozenset({"exhausted"})


def classify_kb_candidate(
    record,
    *,
    prior_signatures: dict,
    blocked_families_in_cycle: frozenset,
    static_exhaustion_blocklist: frozenset,
) -> KBCandidateNoveltyVerdict:
    """Per-row novelty join. Pure: no I/O, no SQL.

    Determines verdict by sequentially checking:
    1. KB cipher_family mapping — None → defer_needs_mapping.
    2. tested_in_project / exhaustion_status — exhausted → reject.
    3. mapped_ledger_families ∩ blocked_families_in_cycle — overlap → reject.
    4. mapped_ledger_families ∩ static_exhaustion_blocklist — overlap → reject.
    5. mechanism_signature ∈ prior_signatures[family] for any mapped family — reject.
    Otherwise → allow.
    """
    from kryptosbot.kb_family_map import map_kb_family_to_ledger_families

    reasons: list[str] = []
    kb_record_id = getattr(record, "record_id", "") or ""
    kb_cipher_family = getattr(record, "cipher_family", "") or ""

    mapped = map_kb_family_to_ledger_families(kb_cipher_family)
    if mapped is None:
        return KBCandidateNoveltyVerdict(
            kb_record_id=kb_record_id,
            kb_cipher_family=kb_cipher_family,
            mapped_ledger_families=(),
            tested_status_ok=False,
            family_blocked=False,
            static_exhaustion_blocked=False,
            mechanism_signature=kb_mechanism_signature(record),
            signature_seen=False,
            dispatcher_testable=False,
            verdict="defer_needs_mapping",
            reasons=(f"unmapped KB cipher_family: {kb_cipher_family!r}",),
        )

    mapped_tuple = tuple(sorted(mapped))
    exhaustion_status = (getattr(record, "exhaustion_status", "") or "").lower()
    tested = bool(getattr(record, "tested_in_project", False))
    tested_status_ok = (not tested) or (exhaustion_status not in _EXHAUSTED_STATUSES)
    if not tested_status_ok:
        reasons.append(
            f"exhausted: tested_in_project={tested} exhaustion_status={exhaustion_status!r}"
        )

    family_blocked = bool(mapped & blocked_families_in_cycle)
    if family_blocked:
        overlap = sorted(mapped & blocked_families_in_cycle)
        reasons.append(f"mapped families overlap blocked cycle families: {overlap}")

    static_exhaustion_blocked = bool(mapped & static_exhaustion_blocklist)
    if static_exhaustion_blocked:
        overlap = sorted(mapped & static_exhaustion_blocklist)
        reasons.append(f"mapped families overlap static exhaustion list: {overlap}")

    signature = kb_mechanism_signature(record)
    signature_seen = any(
        signature in (prior_signatures.get(fam) or frozenset())
        for fam in mapped
    )
    if signature_seen:
        reasons.append(f"mechanism_signature {signature!r} already seen in a mapped family")

    dispatcher_supported = dispatcher_testable(record)

    if tested_status_ok and not family_blocked and not static_exhaustion_blocked and not signature_seen:
        verdict: NoveltyVerdictKind = "allow"
        if not reasons:
            reasons.append("ok")
    else:
        verdict = "reject"

    return KBCandidateNoveltyVerdict(
        kb_record_id=kb_record_id,
        kb_cipher_family=kb_cipher_family,
        mapped_ledger_families=mapped_tuple,
        tested_status_ok=tested_status_ok,
        family_blocked=family_blocked,
        static_exhaustion_blocked=static_exhaustion_blocked,
        mechanism_signature=signature,
        signature_seen=signature_seen,
        dispatcher_testable=dispatcher_supported,
        verdict=verdict,
        reasons=tuple(reasons),
    )


def _one_line_sketch(record) -> str:
    """Return a short prose sketch for the suggestion render.

    Prefers operational_mechanics, falls back to description, then
    canonical_name. Truncated to 160 chars."""
    for attr in ("operational_mechanics", "description"):
        val = getattr(record, attr, "") or ""
        val = _WHITESPACE_RE.sub(" ", val).strip()
        if val:
            return val[:160]
    return _normalize(getattr(record, "canonical_name", ""))[:160] or ""


def _bounded_kill_criterion(record) -> str:
    """One-line guidance the theorist can adapt into a kill criterion."""
    from kryptosbot.kb_family_map import KB_TO_DSL_KIND, normalize_kb_family

    key = normalize_kb_family(getattr(record, "cipher_family", ""))
    kind = KB_TO_DSL_KIND.get(key)
    if kind:
        return (
            f"If the {kind} translator yields zero crib_score >= 18 across "
            f"its bounded parameter space, treat the mechanism as inert."
        )
    return (
        "Specify a bounded, hand-executable test method and a per-trial "
        "crib_score / Bean-pass criterion before dispatch."
    )


def _sketch_class(record) -> SketchClass:
    if dispatcher_testable(record):
        return "dsl_testable"
    from kryptosbot.kb_family_map import map_kb_family_to_ledger_families
    mapped = map_kb_family_to_ledger_families(getattr(record, "cipher_family", ""))
    if mapped:
        return "category_b"
    return "unknown"


def query_suggestions(
    *,
    blocked_family: str,
    blocked_signature: str,
    prior_signatures: dict,
    blocked_families_in_cycle: frozenset,
    static_exhaustion_blocklist: frozenset,
    db_path: str = "db/cipher_discovery.sqlite",
    max_per_call: int = 12,
) -> tuple[CipherDiscoverySuggestion, ...]:
    """Return ranked allow-list of suggestions for one blocked rejection.

    Failure modes:
      Missing DB → ().
      Corrupt row → skipped via iter_kb_records.
    Ranking key: (not dispatcher_testable, -k4_relevance_score, canonical_name).
    """
    allow_pairs: list[tuple[KBCandidateNoveltyVerdict, object]] = []
    for record in iter_kb_records(db_path):
        verdict = classify_kb_candidate(
            record,
            prior_signatures=prior_signatures,
            blocked_families_in_cycle=blocked_families_in_cycle,
            static_exhaustion_blocklist=static_exhaustion_blocklist,
        )
        if verdict.verdict == "allow":
            allow_pairs.append((verdict, record))
        elif verdict.verdict == "defer_needs_mapping":
            logger.warning(
                "kb_injection: defer_needs_mapping kb_record_id=%r kb_cipher_family=%r",
                verdict.kb_record_id, verdict.kb_cipher_family,
            )

    def _rank(pair: tuple[KBCandidateNoveltyVerdict, object]) -> tuple:
        v, r = pair
        return (
            not v.dispatcher_testable,
            -float(getattr(r, "k4_relevance_score", 0.0) or 0.0),
            (getattr(r, "canonical_name", "") or "").lower(),
        )

    allow_pairs.sort(key=_rank)
    out: list[CipherDiscoverySuggestion] = []
    for verdict, record in allow_pairs[:max_per_call]:
        out.append(CipherDiscoverySuggestion(
            kb_record_id=verdict.kb_record_id,
            canonical_name=getattr(record, "canonical_name", "") or "",
            kb_cipher_family=verdict.kb_cipher_family,
            mapped_ledger_families=verdict.mapped_ledger_families,
            mechanism_signature=verdict.mechanism_signature,
            signature_schema_version=KB_SIGNATURE_SCHEMA_VERSION,
            dispatcher_testable=verdict.dispatcher_testable,
            k4_relevance_score=float(getattr(record, "k4_relevance_score", 0.0) or 0.0),
            sketch_class=_sketch_class(record),
            one_line_sketch=_one_line_sketch(record),
            bounded_kill_criterion=_bounded_kill_criterion(record),
            source_verdict="allow",
        ))
    return tuple(out)
