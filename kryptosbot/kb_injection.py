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
