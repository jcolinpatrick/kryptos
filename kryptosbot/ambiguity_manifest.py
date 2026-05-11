"""Evidence-anchored ambiguity manifest (v2) for CT perturbation Stage B.

This module implements the v2 manifest schema mandated by the
ct_perturbation_stage_b prereg (archive-anchored, evidence-first,
preregistered ambiguous-position selection). Distinct from the v1
schema at kryptosbot.ct_perturbation.AmbiguousPositionsManifest, which
is the legacy positions-only format retained for synthetic-recovery
and dry-run paths.

Design contract:
  - v2 is the only schema accepted by Stage B `--execute-full`.
  - v2 manifests are FROZEN: once written, they may not be edited
    after launch. The manifest_hash detects post-launch tampering.
  - Every selected position carries an evidence tier, a per-position
    rationale, source ids, and a candidate-substitution list. There is
    no "all 25 letters" default; the operator must enumerate what the
    evidence supports.
  - excluded_positions is a hard requirement (prevents researcher
    degrees of freedom via retroactive set widening). A test-only
    override exists but is forbidden for --execute-full.
  - manifest_hash is computed over a canonical JSON serialization of
    every field except manifest_hash itself.

References:
  - docs/campaigns/ct_perturbation_stage_b_prereg.md (binding)
  - docs/campaigns/ct_perturbation_stage_b_archive_review_checklist.md
  - feedback_two_tier_preregistration.md (no laundering breadth)
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

# ─── Schema and policy constants ────────────────────────────────────────

SCHEMA_VERSION = "ct_perturbation_stage_b.ambiguous_positions.v2_evidence_anchored"

# Conservative tier ladder. Stronger tiers (lower index in the list)
# carry more weight; the validator's policy threshold determines which
# tiers may carry allowed_in_main_campaign=True.
TIER_ORDER: tuple[str, ...] = (
    "tier_1_direct_transcription_conflict",
    "tier_2_visible_physical_ambiguity",
    "tier_3_archive_or_photo_ambiguity",
    "tier_4_weak_contextual_only",
)
_TIER_INDEX: dict[str, int] = {t: i for i, t in enumerate(TIER_ORDER)}

EXCLUSION_TIER = "excluded"

# Evidence types are open-ended descriptors. The validator does not
# enforce a closed enum here because new sources (e.g. a future high-
# resolution scan) should not require a code change. The operator must
# supply a non-empty string.
DEFAULT_POLICY_MIN_TIER = "tier_2_visible_physical_ambiguity"
DEFAULT_MAX_K = 20
HARD_K_CEILING = 20

# Canonical CT length. Imported lazily to avoid a top-level dependency
# on kryptos.kernel.constants in case downstream tooling needs to load
# manifests without the kernel installed.
def _ct_len() -> int:
    from kryptos.kernel.constants import CT_LEN
    return int(CT_LEN)


def _canonical_ct() -> str:
    from kryptos.kernel.constants import CT
    return CT


# ─── Dataclasses ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class EvidenceSource:
    """Provenance record for one piece of supporting evidence.

    The id is referenced by selected/excluded position records via
    source_ids. The validator enforces that every referenced id resolves
    to an EvidenceSource entry.
    """
    id: str
    type: str
    description: str
    uri: str = ""
    path: str = ""
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "description": self.description,
            "uri": self.uri,
            "path": self.path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class SelectedPosition:
    """A position selected for the Stage B perturbation universe.

    candidate_substitutions is the exact list of alternative letters
    the operator believes the position could have carried. Do not
    default to all 25 letters: the prereg requires evidence-supported
    candidates only.

    allowed_in_main_campaign gates whether this position contributes to
    the --execute-full universe. Operators may include lower-tier
    positions as exploratory entries while marking them False; only
    True entries are enumerated for the main campaign.
    """
    pos0: int
    carved_char: str
    candidate_substitutions: tuple[str, ...]
    evidence_tier: str
    evidence_type: str
    rationale: str
    source_ids: tuple[str, ...]
    reviewer_notes: str = ""
    allowed_in_main_campaign: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "pos0": self.pos0,
            "carved_char": self.carved_char,
            "candidate_substitutions": list(self.candidate_substitutions),
            "evidence_tier": self.evidence_tier,
            "evidence_type": self.evidence_type,
            "rationale": self.rationale,
            "source_ids": list(self.source_ids),
            "reviewer_notes": self.reviewer_notes,
            "allowed_in_main_campaign": self.allowed_in_main_campaign,
        }


@dataclass(frozen=True)
class ExcludedPosition:
    """A position considered but excluded from the perturbation universe.

    Recording exclusions is a hard preregistration requirement. It
    prevents retroactive set widening: a future operator faced with a
    Stage B null result cannot quietly add positions and rerun, because
    the original manifest documents what was considered.
    """
    pos0: int
    carved_char: str
    reason_excluded: str
    evidence_type_if_any: str = ""
    source_ids: tuple[str, ...] = ()
    reviewer_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pos0": self.pos0,
            "carved_char": self.carved_char,
            "reason_excluded": self.reason_excluded,
            "evidence_type_if_any": self.evidence_type_if_any,
            "source_ids": list(self.source_ids),
            "reviewer_notes": self.reviewer_notes,
        }


@dataclass(frozen=True)
class SelectionPolicy:
    """Per-manifest selection policy.

    min_tier_for_main_campaign sets the floor for the tier of any
    SelectedPosition with allowed_in_main_campaign=True. Tiers
    weaker than this threshold may exist in the manifest as evidence
    of the operator's thinking but cannot drive the main campaign.

    max_k constrains the total count of allowed positions. The
    validator additionally enforces a hard ceiling of HARD_K_CEILING.
    """
    min_tier_for_main_campaign: str = DEFAULT_POLICY_MIN_TIER
    max_k: int = DEFAULT_MAX_K

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_tier_for_main_campaign": self.min_tier_for_main_campaign,
            "max_k": self.max_k,
        }


@dataclass(frozen=True)
class AmbiguityManifestV2:
    """Evidence-anchored ambiguity manifest (v2).

    Frozen and hash-pinned. Stage B's --execute-full path requires this
    schema; v1 manifests are accepted only for --dry-run and
    --synthetic-recovery-test.
    """
    schema_version: str
    campaign_id: str
    created_at_utc: str
    kernel_commit: str
    ct_source: str
    ct_length: int
    selected_positions: tuple[SelectedPosition, ...]
    excluded_positions: tuple[ExcludedPosition, ...]
    evidence_sources: tuple[EvidenceSource, ...]
    selection_policy: SelectionPolicy
    max_k: int
    frozen: bool
    manifest_hash: str = ""

    # Cached at load time; populated by load_v2 for inspection only.
    # Marked non-comparing/non-hash so dataclass identity is unaffected.
    _allowed_positions: tuple[int, ...] = field(
        default=(), repr=False, compare=False,
    )

    def to_dict(self, include_hash: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "created_at_utc": self.created_at_utc,
            "kernel_commit": self.kernel_commit,
            "ct_source": self.ct_source,
            "ct_length": self.ct_length,
            "selected_positions": [p.to_dict() for p in self.selected_positions],
            "excluded_positions": [p.to_dict() for p in self.excluded_positions],
            "evidence_sources": [s.to_dict() for s in self.evidence_sources],
            "selection_policy": self.selection_policy.to_dict(),
            "max_k": self.max_k,
            "frozen": self.frozen,
        }
        if include_hash:
            payload["manifest_hash"] = self.manifest_hash
        return payload

    def allowed_positions(self) -> tuple[int, ...]:
        """Positions where allowed_in_main_campaign=True, sorted."""
        return tuple(
            sorted(
                p.pos0 for p in self.selected_positions if p.allowed_in_main_campaign
            )
        )

    def allowed_selections(self) -> tuple[SelectedPosition, ...]:
        """SelectedPosition records with allowed_in_main_campaign=True.

        Sorted by pos0 for determinism.
        """
        return tuple(
            sorted(
                (p for p in self.selected_positions if p.allowed_in_main_campaign),
                key=lambda s: s.pos0,
            )
        )

    def k(self) -> int:
        """Count of allowed selected positions (the main-campaign k)."""
        return len(self.allowed_positions())


# ─── Hash computation ───────────────────────────────────────────────────


def compute_manifest_hash(payload: dict[str, Any]) -> str:
    """Compute the deterministic SHA-256 hash of a v2 manifest payload.

    The hash is computed over a canonical JSON serialization with
    sorted keys, no whitespace, and the manifest_hash field stripped
    (so the hash describes the rest of the manifest, not itself).
    """
    pruned = {k: v for k, v in payload.items() if k != "manifest_hash"}
    canonical = json.dumps(pruned, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_universe_hash(
    allowed: tuple[SelectedPosition, ...],
    families: tuple[str, ...],
    alphabet_kinds: tuple[str, ...],
    keywords_sha256: str,
    keyword_count: int,
) -> str:
    """Compute a deterministic hash describing the actual H2 universe.

    Captures the configuration that determines which (variant,
    family, alphabet, keyword) cells will be evaluated. Changes to any
    of these inputs invalidate the hash.
    """
    parts: dict[str, Any] = {
        "allowed_positions": [p.pos0 for p in allowed],
        "candidate_substitutions": [
            {"pos0": p.pos0, "substitutions": sorted(p.candidate_substitutions)}
            for p in allowed
        ],
        "families": list(families),
        "alphabet_kinds": list(alphabet_kinds),
        "keywords_sha256": keywords_sha256,
        "keyword_count": keyword_count,
    }
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ─── Validator ──────────────────────────────────────────────────────────


class ManifestValidationError(ValueError):
    """Raised on any v2 manifest validation failure.

    The error message lists every check that failed (not just the
    first) so the operator can fix the manifest in one pass.
    """


def _is_upper_letter(ch: str) -> bool:
    return isinstance(ch, str) and len(ch) == 1 and "A" <= ch <= "Z"


_SHA256_HEX = re.compile(r"^[0-9a-f]{40,}$")


def _coerce_selection_policy(raw: Any) -> SelectionPolicy:
    if raw is None:
        return SelectionPolicy()
    if not isinstance(raw, dict):
        raise ManifestValidationError(
            "selection_policy must be an object or omitted"
        )
    return SelectionPolicy(
        min_tier_for_main_campaign=str(raw.get(
            "min_tier_for_main_campaign", DEFAULT_POLICY_MIN_TIER,
        )),
        max_k=int(raw.get("max_k", DEFAULT_MAX_K)),
    )


def _coerce_evidence_source(raw: Any, errors: list[str]) -> EvidenceSource | None:
    if not isinstance(raw, dict):
        errors.append(f"evidence_sources entry must be an object: {raw!r}")
        return None
    src_id = raw.get("id")
    if not isinstance(src_id, str) or not src_id.strip():
        errors.append(f"evidence_sources entry missing non-empty 'id': {raw!r}")
        return None
    src_type = raw.get("type")
    if not isinstance(src_type, str) or not src_type.strip():
        errors.append(f"evidence_sources[{src_id}] missing non-empty 'type'")
        return None
    description = raw.get("description", "")
    if not isinstance(description, str):
        errors.append(f"evidence_sources[{src_id}] description must be a string")
        description = ""
    return EvidenceSource(
        id=src_id.strip(),
        type=src_type.strip(),
        description=description.strip(),
        uri=str(raw.get("uri", "")).strip(),
        path=str(raw.get("path", "")).strip(),
        sha256=str(raw.get("sha256", "")).strip(),
    )


def _coerce_selected_position(
    raw: Any, errors: list[str], idx: int,
) -> SelectedPosition | None:
    if not isinstance(raw, dict):
        errors.append(f"selected_positions[{idx}] must be an object")
        return None
    pos0 = raw.get("pos0")
    carved_char = raw.get("carved_char", "")
    if not isinstance(pos0, int) or isinstance(pos0, bool):
        errors.append(
            f"selected_positions[{idx}] pos0 must be an int; got {pos0!r}"
        )
        return None
    candidates_raw = raw.get("candidate_substitutions", [])
    if not isinstance(candidates_raw, list):
        errors.append(
            f"selected_positions[{idx}] candidate_substitutions must be a list"
        )
        candidates_raw = []
    candidates: list[str] = []
    for c in candidates_raw:
        if not isinstance(c, str) or len(c) != 1:
            errors.append(
                f"selected_positions[{idx}] candidate {c!r} must be a single char"
            )
            continue
        upper = c.upper()
        if not _is_upper_letter(upper):
            errors.append(
                f"selected_positions[{idx}] candidate {c!r} must be A-Z"
            )
            continue
        candidates.append(upper)
    source_ids_raw = raw.get("source_ids", [])
    if not isinstance(source_ids_raw, list):
        errors.append(
            f"selected_positions[{idx}] source_ids must be a list"
        )
        source_ids_raw = []
    source_ids = tuple(str(s) for s in source_ids_raw)
    return SelectedPosition(
        pos0=pos0,
        carved_char=str(carved_char).upper(),
        candidate_substitutions=tuple(candidates),
        evidence_tier=str(raw.get("evidence_tier", "")).strip(),
        evidence_type=str(raw.get("evidence_type", "")).strip(),
        rationale=str(raw.get("rationale", "")).strip(),
        source_ids=source_ids,
        reviewer_notes=str(raw.get("reviewer_notes", "")),
        allowed_in_main_campaign=bool(raw.get("allowed_in_main_campaign", True)),
    )


def _coerce_excluded_position(
    raw: Any, errors: list[str], idx: int,
) -> ExcludedPosition | None:
    if not isinstance(raw, dict):
        errors.append(f"excluded_positions[{idx}] must be an object")
        return None
    pos0 = raw.get("pos0")
    if not isinstance(pos0, int) or isinstance(pos0, bool):
        errors.append(
            f"excluded_positions[{idx}] pos0 must be an int; got {pos0!r}"
        )
        return None
    source_ids_raw = raw.get("source_ids", [])
    source_ids = tuple(
        str(s) for s in (source_ids_raw if isinstance(source_ids_raw, list) else [])
    )
    return ExcludedPosition(
        pos0=pos0,
        carved_char=str(raw.get("carved_char", "")).upper(),
        reason_excluded=str(raw.get("reason_excluded", "")).strip(),
        evidence_type_if_any=str(raw.get("evidence_type_if_any", "")).strip(),
        source_ids=source_ids,
        reviewer_notes=str(raw.get("reviewer_notes", "")),
    )


def _validate_payload(
    payload: dict[str, Any],
    *,
    for_main_campaign: bool,
    allow_empty_excluded_for_test_only: bool,
    current_kernel_commit: str | None,
    require_fresh_kernel_commit: bool,
) -> tuple[AmbiguityManifestV2, list[str]]:
    """Core validator. Returns (manifest, errors); manifest is partially
    constructed even if errors is non-empty so callers can inspect."""
    errors: list[str] = []

    schema = payload.get("schema_version")
    if schema != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION!r}; got {schema!r}"
        )

    campaign_id = str(payload.get("campaign_id", "")).strip()
    if not campaign_id:
        errors.append("campaign_id must be a non-empty string")

    created_at = str(payload.get("created_at_utc", "")).strip()
    if not created_at:
        errors.append("created_at_utc must be a non-empty ISO-8601 UTC string")

    kernel_commit = str(payload.get("kernel_commit", "")).strip()
    if not kernel_commit:
        errors.append("kernel_commit must be set (use the commit at manifest authoring time)")
    elif require_fresh_kernel_commit and current_kernel_commit and current_kernel_commit != "unknown":
        if kernel_commit != current_kernel_commit:
            errors.append(
                f"stale_manifest_kernel_commit: manifest kernel_commit={kernel_commit!r} "
                f"does not match current={current_kernel_commit!r}. "
                "Re-author the manifest against the current kernel or re-evaluate evidence."
            )

    ct_source = str(payload.get("ct_source", "")).strip()
    if not ct_source:
        errors.append("ct_source must be a non-empty string (e.g. 'carved_panel_v2026')")

    ct_length_raw = payload.get("ct_length")
    if not isinstance(ct_length_raw, int) or isinstance(ct_length_raw, bool):
        errors.append("ct_length must be an int")
        ct_length_raw = _ct_len()
    elif ct_length_raw != _ct_len():
        errors.append(
            f"ct_length={ct_length_raw} does not match canonical CT length {_ct_len()}"
        )

    selection_policy = _coerce_selection_policy(payload.get("selection_policy"))
    if selection_policy.min_tier_for_main_campaign not in _TIER_INDEX:
        errors.append(
            f"selection_policy.min_tier_for_main_campaign {selection_policy.min_tier_for_main_campaign!r} "
            f"not in {list(TIER_ORDER)}"
        )

    max_k_raw = payload.get("max_k", selection_policy.max_k)
    if not isinstance(max_k_raw, int) or isinstance(max_k_raw, bool):
        errors.append(f"max_k must be an int; got {max_k_raw!r}")
        max_k_raw = HARD_K_CEILING
    if max_k_raw > HARD_K_CEILING:
        errors.append(
            f"max_k={max_k_raw} exceeds HARD_K_CEILING={HARD_K_CEILING}. "
            "Author a separate Stage B' preregistration for larger k."
        )

    frozen = bool(payload.get("frozen", False))

    # Evidence sources
    evidence_sources_raw = payload.get("evidence_sources", [])
    if not isinstance(evidence_sources_raw, list):
        errors.append("evidence_sources must be a list")
        evidence_sources_raw = []
    evidence_sources: list[EvidenceSource] = []
    source_ids_seen: set[str] = set()
    for entry in evidence_sources_raw:
        coerced = _coerce_evidence_source(entry, errors)
        if coerced is None:
            continue
        if coerced.id in source_ids_seen:
            errors.append(f"duplicate evidence source id: {coerced.id!r}")
            continue
        source_ids_seen.add(coerced.id)
        evidence_sources.append(coerced)

    # Selected positions
    selected_raw = payload.get("selected_positions", [])
    if not isinstance(selected_raw, list):
        errors.append("selected_positions must be a list")
        selected_raw = []
    selected: list[SelectedPosition] = []
    positions_seen: set[int] = set()
    ct = _canonical_ct() if ct_source == "carved_panel_v2026_canonical" or ct_source.startswith("carved_panel") else None
    # Note: for non-canonical CT sources (synthetic fixtures), we skip
    # carved_char-vs-canonical CT cross-checks. This is allowed and
    # documented; v1 synthetic-recovery uses this path.

    for idx, entry in enumerate(selected_raw):
        coerced = _coerce_selected_position(entry, errors, idx)
        if coerced is None:
            continue
        # Range
        if coerced.pos0 < 0 or coerced.pos0 >= _ct_len():
            errors.append(
                f"selected_positions[{idx}] pos0={coerced.pos0} out of range "
                f"[0, {_ct_len()})"
            )
            continue
        # Duplicates
        if coerced.pos0 in positions_seen:
            errors.append(
                f"duplicate selected position pos0={coerced.pos0}"
            )
            continue
        positions_seen.add(coerced.pos0)
        # Carved-char vs canonical (only when ct_source is canonical)
        if ct is not None:
            actual = ct[coerced.pos0]
            if coerced.carved_char != actual:
                errors.append(
                    f"selected_positions[{idx}] carved_char={coerced.carved_char!r} "
                    f"does not match canonical CT[{coerced.pos0}]={actual!r}"
                )
        # Candidates
        if not coerced.candidate_substitutions:
            errors.append(
                f"selected_positions[{idx}] (pos0={coerced.pos0}) must have at "
                f"least one candidate substitution"
            )
        for c in coerced.candidate_substitutions:
            if c == coerced.carved_char:
                errors.append(
                    f"selected_positions[{idx}] (pos0={coerced.pos0}) candidate "
                    f"{c!r} equals carved_char; substitutions must differ"
                )
        # Evidence tier
        if not coerced.evidence_tier:
            errors.append(
                f"selected_positions[{idx}] (pos0={coerced.pos0}) missing evidence_tier"
            )
        elif coerced.evidence_tier not in _TIER_INDEX:
            errors.append(
                f"selected_positions[{idx}] (pos0={coerced.pos0}) evidence_tier "
                f"{coerced.evidence_tier!r} not in {list(TIER_ORDER)}"
            )
        # Rationale
        if not coerced.rationale:
            errors.append(
                f"selected_positions[{idx}] (pos0={coerced.pos0}) missing rationale"
            )
        # Source ids: every referenced id must resolve
        if not coerced.source_ids:
            errors.append(
                f"selected_positions[{idx}] (pos0={coerced.pos0}) source_ids must "
                f"be non-empty"
            )
        for sid in coerced.source_ids:
            if sid not in source_ids_seen:
                errors.append(
                    f"selected_positions[{idx}] (pos0={coerced.pos0}) cites "
                    f"unknown source_id {sid!r}"
                )
        # Tier-policy threshold for main-campaign membership
        if coerced.allowed_in_main_campaign and coerced.evidence_tier in _TIER_INDEX:
            tier_idx = _TIER_INDEX[coerced.evidence_tier]
            policy_idx = _TIER_INDEX.get(
                selection_policy.min_tier_for_main_campaign, len(TIER_ORDER),
            )
            if tier_idx > policy_idx:
                errors.append(
                    f"selected_positions[{idx}] (pos0={coerced.pos0}) "
                    f"allowed_in_main_campaign=True but tier "
                    f"{coerced.evidence_tier!r} is weaker than "
                    f"policy.min_tier={selection_policy.min_tier_for_main_campaign!r}"
                )
        selected.append(coerced)

    # max_k check (allowed positions only)
    allowed_count = sum(1 for p in selected if p.allowed_in_main_campaign)
    if allowed_count > max_k_raw:
        errors.append(
            f"allowed selected positions ({allowed_count}) exceed max_k={max_k_raw}"
        )

    # Excluded positions
    excluded_raw = payload.get("excluded_positions", [])
    if not isinstance(excluded_raw, list):
        errors.append("excluded_positions must be a list")
        excluded_raw = []
    excluded: list[ExcludedPosition] = []
    excluded_seen: set[int] = set()
    for idx, entry in enumerate(excluded_raw):
        coerced_x = _coerce_excluded_position(entry, errors, idx)
        if coerced_x is None:
            continue
        if coerced_x.pos0 < 0 or coerced_x.pos0 >= _ct_len():
            errors.append(
                f"excluded_positions[{idx}] pos0={coerced_x.pos0} out of range "
                f"[0, {_ct_len()})"
            )
            continue
        if coerced_x.pos0 in excluded_seen:
            errors.append(
                f"duplicate excluded position pos0={coerced_x.pos0}"
            )
            continue
        if coerced_x.pos0 in positions_seen:
            errors.append(
                f"position pos0={coerced_x.pos0} appears in both selected and excluded"
            )
            continue
        excluded_seen.add(coerced_x.pos0)
        if not coerced_x.reason_excluded:
            errors.append(
                f"excluded_positions[{idx}] (pos0={coerced_x.pos0}) missing reason_excluded"
            )
        excluded.append(coerced_x)

    if for_main_campaign:
        if not excluded and not allow_empty_excluded_for_test_only:
            errors.append(
                "excluded_positions is empty; main campaign requires a non-empty "
                "considered-and-excluded list (prereg §13.2 discipline). "
                "Use --allow-empty-excluded-for-test-only for testing fixtures only."
            )
        if not frozen:
            errors.append(
                "frozen=False; main campaign requires frozen=True. "
                "Freeze the manifest after authoring; do not edit after freezing."
            )

    # Manifest hash
    stored_hash = str(payload.get("manifest_hash", "")).strip()
    computed_hash = compute_manifest_hash(payload)
    if stored_hash and stored_hash != computed_hash:
        errors.append(
            f"manifest_hash mismatch: stored={stored_hash!r}, computed={computed_hash!r}. "
            "Recompute and rewrite, or restore the prior content."
        )

    manifest = AmbiguityManifestV2(
        schema_version=str(schema) if isinstance(schema, str) else SCHEMA_VERSION,
        campaign_id=campaign_id or "ct_perturbation_stage_b",
        created_at_utc=created_at,
        kernel_commit=kernel_commit,
        ct_source=ct_source,
        ct_length=ct_length_raw if isinstance(ct_length_raw, int) else _ct_len(),
        selected_positions=tuple(selected),
        excluded_positions=tuple(excluded),
        evidence_sources=tuple(evidence_sources),
        selection_policy=selection_policy,
        max_k=max_k_raw if isinstance(max_k_raw, int) else HARD_K_CEILING,
        frozen=frozen,
        manifest_hash=computed_hash,
    )
    return manifest, errors


def load_v2(
    path: str | Path,
    *,
    for_main_campaign: bool = True,
    allow_empty_excluded_for_test_only: bool = False,
    current_kernel_commit: str | None = None,
    require_fresh_kernel_commit: bool = False,
) -> AmbiguityManifestV2:
    """Load and validate a v2 ambiguity manifest.

    Args:
      path: filesystem path to the manifest JSON file.
      for_main_campaign: when True, enforce the launch-gate rules
        (frozen, non-empty excluded, max_k). When False (--dry-run,
        validation-only), those rules are relaxed.
      allow_empty_excluded_for_test_only: emergency override; not
        permitted on --execute-full. Stage B passes this only when
        --allow-empty-excluded-for-test-only is on the command line
        AND --execute-full is absent.
      current_kernel_commit: the current kernel SHA. Compared against
        the manifest's kernel_commit when require_fresh_kernel_commit
        is True.
      require_fresh_kernel_commit: when True, refuse manifests whose
        kernel_commit does not match current_kernel_commit. Use this
        for --execute-full; defaults to False elsewhere.

    Raises ManifestValidationError on any validation failure.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, dict):
        raise ManifestValidationError("manifest must be a JSON object")
    manifest, errors = _validate_payload(
        raw,
        for_main_campaign=for_main_campaign,
        allow_empty_excluded_for_test_only=allow_empty_excluded_for_test_only,
        current_kernel_commit=current_kernel_commit,
        require_fresh_kernel_commit=require_fresh_kernel_commit,
    )
    if errors:
        raise ManifestValidationError(
            "v2 manifest validation failed with "
            f"{len(errors)} error(s):\n  - " + "\n  - ".join(errors)
        )
    return manifest


def validate_dict(
    payload: dict[str, Any],
    *,
    for_main_campaign: bool = True,
    allow_empty_excluded_for_test_only: bool = False,
    current_kernel_commit: str | None = None,
    require_fresh_kernel_commit: bool = False,
) -> AmbiguityManifestV2:
    """Validate a dict payload directly. Same semantics as load_v2.

    Useful for in-memory manifests built by tests or future authoring
    tools.
    """
    manifest, errors = _validate_payload(
        payload,
        for_main_campaign=for_main_campaign,
        allow_empty_excluded_for_test_only=allow_empty_excluded_for_test_only,
        current_kernel_commit=current_kernel_commit,
        require_fresh_kernel_commit=require_fresh_kernel_commit,
    )
    if errors:
        raise ManifestValidationError(
            "v2 manifest validation failed with "
            f"{len(errors)} error(s):\n  - " + "\n  - ".join(errors)
        )
    return manifest


# ─── Universe enumeration ───────────────────────────────────────────────


def iter_h2_variants(
    ct: str,
    manifest: AmbiguityManifestV2,
) -> Iterator[tuple[int, str, str, int, str, str]]:
    """Yield (pos1, old1, new1, pos2, old2, new2) tuples for the v2 universe.

    Uses ONLY the candidate_substitutions specified per allowed position.
    Does NOT default to all 25 letters; that is the point of v2.
    """
    allowed = manifest.allowed_selections()
    for i_idx in range(len(allowed)):
        for j_idx in range(i_idx + 1, len(allowed)):
            sel_i = allowed[i_idx]
            sel_j = allowed[j_idx]
            pos1, pos2 = sel_i.pos0, sel_j.pos0
            old1, old2 = ct[pos1], ct[pos2]
            # candidate_substitutions for each position; iterate in
            # sorted order for determinism.
            for new1 in sorted(sel_i.candidate_substitutions):
                if new1 == old1:
                    continue
                for new2 in sorted(sel_j.candidate_substitutions):
                    if new2 == old2:
                        continue
                    yield (pos1, old1, new1, pos2, old2, new2)


def h2_universe_size(manifest: AmbiguityManifestV2) -> int:
    """Total H2 variants in the v2 universe.

    Sum over (i, j) pairs of (|cands_i| - cancel_i) * (|cands_j| - cancel_j),
    where cancel is 1 if carved_char appears in the candidate set (no-op
    substitution skipped).
    """
    allowed = manifest.allowed_selections()
    from kryptos.kernel.constants import CT
    total = 0
    for i_idx in range(len(allowed)):
        for j_idx in range(i_idx + 1, len(allowed)):
            sel_i = allowed[i_idx]
            sel_j = allowed[j_idx]
            n_i = sum(
                1 for c in sel_i.candidate_substitutions
                if c != CT[sel_i.pos0]
            )
            n_j = sum(
                1 for c in sel_j.candidate_substitutions
                if c != CT[sel_j.pos0]
            )
            total += n_i * n_j
    return total


# ─── Authoring helper ───────────────────────────────────────────────────


def build_payload(
    *,
    campaign_id: str,
    kernel_commit: str,
    ct_source: str,
    selected_positions: list[SelectedPosition],
    excluded_positions: list[ExcludedPosition],
    evidence_sources: list[EvidenceSource],
    selection_policy: SelectionPolicy | None = None,
    max_k: int = DEFAULT_MAX_K,
    frozen: bool = False,
    created_at_utc: str | None = None,
) -> dict[str, Any]:
    """Build a v2 manifest payload (with computed manifest_hash) for writing.

    The returned dict is ready to be `json.dump`ed to disk. Note: this
    helper does NOT validate; pass through validate_dict if you want
    pre-write validation.
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "created_at_utc": (
            created_at_utc
            if created_at_utc is not None
            else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
        "kernel_commit": kernel_commit,
        "ct_source": ct_source,
        "ct_length": _ct_len(),
        "selected_positions": [p.to_dict() for p in selected_positions],
        "excluded_positions": [p.to_dict() for p in excluded_positions],
        "evidence_sources": [s.to_dict() for s in evidence_sources],
        "selection_policy": (
            selection_policy or SelectionPolicy()
        ).to_dict(),
        "max_k": max_k,
        "frozen": frozen,
    }
    payload["manifest_hash"] = compute_manifest_hash(payload)
    return payload


__all__ = [
    "AmbiguityManifestV2",
    "DEFAULT_MAX_K",
    "DEFAULT_POLICY_MIN_TIER",
    "EvidenceSource",
    "EXCLUSION_TIER",
    "ExcludedPosition",
    "HARD_K_CEILING",
    "ManifestValidationError",
    "SCHEMA_VERSION",
    "SelectionPolicy",
    "SelectedPosition",
    "TIER_ORDER",
    "build_payload",
    "compute_manifest_hash",
    "compute_universe_hash",
    "h2_universe_size",
    "iter_h2_variants",
    "load_v2",
    "validate_dict",
]
