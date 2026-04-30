"""Real-K4 LLM↔HCC bridge: theorist prompt + JSON parser.

The LLM theorist prompt is a string template + structured JSON
output specification. The theorist's job is to propose
*pseudo-clue packs* — structured role hypotheses with provenance —
NOT plaintext, NOT DSL specs, NOT solution claims.

This module:
  * Provides the prompt string-builder (parametrised by the active
    evidence registry summary and the lesson registry summary).
  * Provides a strict JSON parser that validates the LLM output
    against the PseudoCluePack schema and rejects packs missing
    provenance.
  * Provides a small ``LLMConfig`` dataclass for prompt knobs (cap
    on packs, evidence tier preference, etc.).

The LLM is NEVER asked to:
  * propose plaintext,
  * emit DSL,
  * make solve claims,
  * cite K4Bench challenges or sealed-answer text.

The prompt explicitly lists forbidden behaviours and requires
provenance per role.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from kryptosbot.real_k4_pseudo_clue_pack import (
    PseudoCluePack, OPERATION_KINDS, KEYWORD_ROLE_HINTS,
    NUMERIC_ROLE_HINTS, EVIDENCE_TIERS,
)


@dataclass
class LLMConfig:
    """Knobs for the bridge theorist prompt."""
    max_packs: int = 5
    max_keywords_per_pack: int = 6
    max_numeric_roles_per_pack: int = 4
    max_operation_hints_per_pack: int = 5
    max_composition_templates_per_pack: int = 4
    max_specs_per_pack: int = 200
    min_evidence_tier: str = "tier_4_inference"
    forbid_speculation_only_packs: bool = True


_FORBIDDEN_BEHAVIOURS = """
You MUST NOT do any of the following:
  - Propose K4 plaintext, candidate decryptions, or partial PT.
  - Emit DSL specs, layer pipelines, or transform sequences.
  - Claim a solve, a "high confidence" decoding, or convergence.
  - Cite K4Bench challenge IDs (K4B-*), bench sealed answers, or
    bench-only tokens.
  - Cite a source you did not pull from the supplied evidence
    registry — every role MUST cite a real source_id.
  - Bypass the schema by emitting free text instead of structured
    pack JSON.
""".strip()


_PACK_SCHEMA_TEMPLATE = """
A pseudo-clue pack is a structured role hypothesis. JSON shape:

{
  "pack_id": "string (unique within run)",
  "title": "short human-readable title",
  "hypothesis_summary": "one paragraph, no plaintext, no DSL",
  "provenance_items": [
    {
      "source_id": "registry key, anomaly id, or crib span id",
      "source_type": "<one of: %(SOURCE_TYPES)s>",
      "quote_or_summary": "≤1 sentence excerpt or paraphrase",
      "confidence": 0.0,
      "url_or_registry_key": "optional"
    }, ...
  ],
  "evidence_tier": "<one of: %(EVIDENCE_TIERS)s>",
  "keywords": [
    {
      "token": "A-Z, length >= 2",
      "role_hint": "<one of: %(KEYWORD_ROLE_HINTS)s>",
      "source_ids": ["existing provenance source_id, ..."],
      "confidence": 0.0
    }, ...
  ],
  "numeric_roles": [
    {
      "value": 3,
      "token": "three",
      "role_hint": "<one of: %(NUMERIC_ROLE_HINTS)s>",
      "source_ids": ["..."],
      "confidence": 0.0
    }, ...
  ],
  "operation_hints": [
    {
      "operation": "<one of: %(OPERATION_KINDS)s>",
      "role": "required | optional | speculative",
      "source_ids": ["..."],
      "confidence": 0.0
    }, ...
  ],
  "composition_templates": [
    {
      "layer_kinds": ["caesar", "columnar", "rail_fence"],
      "ordered": true,
      "rationale": "why this composition fits the evidence",
      "confidence": 0.0,
      "max_layers": 3
    }, ...
  ],
  "bounds": {
    "max_specs": 200,
    "allowed_widths": [...],
    "allowed_depths": [...],
    "allowed_shifts": [...],
    "allowed_keywords": [...],
    "allow_project_safe_defaults": true,
    "allow_default_widths": true
  },
  "constraints": ["short string statements"],
  "caveats": ["short caveat statements"],
  "excluded_reasons": ["why some interpretation was deliberately left out"]
}
""".strip()


_OUTPUT_FORMAT = """
Respond with a single JSON object of the form:

{
  "packs": [<PseudoCluePack JSON>, ...]
}

If you cannot form ANY justified pack from the supplied evidence,
return {"packs": []} with an explanatory ``packs_excluded_reason``
field. Do not invent provenance.
""".strip()


def render_bridge_prompt(
    *,
    evidence_registry_summary: str,
    lesson_registry_summary: str,
    config: LLMConfig = LLMConfig(),
) -> str:
    """Build the bridge theorist prompt string.

    The two summary fields are short paragraphs the caller has
    pre-built from ``real_k4_clue_registry`` and
    ``solver_capabilities`` respectively. The theorist sees the
    evidence inventory + the available solver capabilities, and
    proposes structured role hypotheses linking the two.
    """
    sub_format = {
        "SOURCE_TYPES": ", ".join(sorted(_safe_set_str_set("crib anomaly sculpture public_comment registry human_note".split()))),
        "EVIDENCE_TIERS": ", ".join(sorted(EVIDENCE_TIERS)),
        "KEYWORD_ROLE_HINTS": ", ".join(sorted(KEYWORD_ROLE_HINTS)),
        "NUMERIC_ROLE_HINTS": ", ".join(sorted(NUMERIC_ROLE_HINTS)),
        "OPERATION_KINDS": ", ".join(sorted(OPERATION_KINDS)),
    }
    schema_block = _PACK_SCHEMA_TEMPLATE % sub_format
    knobs = (
        f"You may propose AT MOST {config.max_packs} packs. Each pack:\n"
        f"  - at most {config.max_keywords_per_pack} keywords,\n"
        f"  - at most {config.max_numeric_roles_per_pack} numeric roles,\n"
        f"  - at most {config.max_operation_hints_per_pack} operation hints,\n"
        f"  - at most {config.max_composition_templates_per_pack} "
        f"composition templates,\n"
        f"  - bounds.max_specs ≤ {config.max_specs_per_pack}.\n"
        f"  - evidence_tier no weaker than {config.min_evidence_tier}."
    )
    return (
        "You are the real-K4 interpretive theorist. Your task is to\n"
        "translate the evidence registry into structured PSEUDO-CLUE\n"
        "PACKS that a deterministic compiler can use to enumerate\n"
        "candidate cipher pipelines for testing against the public\n"
        "K4 cribs. You are NOT a solver. You are NOT producing\n"
        "plaintext. You are producing structured ROLE HYPOTHESES.\n\n"
        f"EVIDENCE REGISTRY (real-K4 only):\n{evidence_registry_summary}\n\n"
        f"AVAILABLE SOLVER CAPABILITIES (lesson taxonomy):\n"
        f"{lesson_registry_summary}\n\n"
        f"FORBIDDEN BEHAVIOURS:\n{_FORBIDDEN_BEHAVIOURS}\n\n"
        f"PER-RUN KNOBS:\n{knobs}\n\n"
        f"PACK SCHEMA:\n{schema_block}\n\n"
        f"OUTPUT FORMAT:\n{_OUTPUT_FORMAT}\n"
    )


def _safe_set_str_set(items: Sequence[str]) -> set[str]:
    return {str(x) for x in items}


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------


class BridgePromptParseError(ValueError):
    """Raised when the LLM response cannot be parsed into pack JSON."""


def parse_packs_response(
    response_text: str,
) -> tuple[list[PseudoCluePack], list[dict[str, Any]]]:
    """Parse the LLM's JSON response into a list of PseudoCluePack
    plus a list of per-pack rejection reasons (one entry per
    rejected pack).

    Tolerant of leading/trailing prose: extracts the FIRST JSON
    object from the text. Strict on schema: any pack failing
    ``PseudoCluePack.validate()`` is rejected with its error list.

    Returns (accepted_packs, rejection_records).
    """
    if not isinstance(response_text, str) or not response_text.strip():
        raise BridgePromptParseError(
            "empty or non-string response_text"
        )
    obj = _extract_first_json_object(response_text)
    if obj is None:
        raise BridgePromptParseError(
            "no JSON object found in response_text"
        )
    if not isinstance(obj, dict) or "packs" not in obj:
        raise BridgePromptParseError(
            "response missing top-level 'packs' field"
        )
    packs_raw = obj.get("packs", [])
    if not isinstance(packs_raw, list):
        raise BridgePromptParseError(
            "'packs' must be a JSON array"
        )
    accepted: list[PseudoCluePack] = []
    rejected: list[dict[str, Any]] = []
    for i, p in enumerate(packs_raw):
        if not isinstance(p, dict):
            rejected.append({
                "index": i, "errors": ["entry is not a JSON object"],
            })
            continue
        try:
            pack = PseudoCluePack.from_dict(p)
        except (KeyError, TypeError, ValueError) as e:
            rejected.append({
                "index": i, "pack_id": p.get("pack_id"),
                "errors": [f"from_dict failed: {e}"],
            })
            continue
        errs = pack.validate()
        if errs:
            rejected.append({
                "index": i, "pack_id": pack.pack_id,
                "errors": errs,
            })
            continue
        accepted.append(pack)
    return accepted, rejected


def _extract_first_json_object(text: str) -> Optional[Any]:
    """Scan for the first balanced '{...}' or '[...]' block and parse it."""
    s = text
    start = -1
    for i, ch in enumerate(s):
        if ch in "{[":
            start = i
            break
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for j in range(start, len(s)):
        ch = s[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start: j + 1])
                except json.JSONDecodeError:
                    return None
    return None


__all__ = [
    "LLMConfig",
    "BridgePromptParseError",
    "render_bridge_prompt",
    "parse_packs_response",
]
