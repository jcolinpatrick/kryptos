"""Campaign result manifest schema and writer.

PURPOSE
-------
When a campaign produces a notable result (elimination, narrow residual, or
unexpected hit), it writes a small machine-readable manifest to
results/campaign_manifests/<campaign_id>.json. The internalcontroller
reads these manifests at bootstrap and updates its family registry
automatically.

This is the structural bridge between external campaign work and the
controller's view of the elimination landscape. Without it, the controller
keeps proposing theories for families that have already been thoroughly
tested elsewhere — wasting tokens.

DESIGN PRINCIPLES
-----------------
- Manifests are plain JSON. Campaigns do not need to import internal.
- The schema is versioned. Future versions can add fields without breaking
  older readers.
- Manifests are idempotent. Re-running the same campaign overwrites the
  same manifest file (one manifest per campaign_id).
- The controller treats manifests as authoritative for family metadata
  (tier, evidence, status) but never clobbers live stats (total_theories,
  best_score, eliminated_theories) maintained by the controller's own ledger.
- Manifests are scope-bounded. They include explicit caveats so the
  controller (or a human reading them later) cannot misread a narrow
  result as covering more than it does.

NOT a replacement for:
- The frozen null report system (results/null_reports/) — those are the
  immutable publication-grade artifacts. Manifests are the lightweight
  controller-feeding layer that summarizes the frozen artifact's key
  facts in a small structured form.
- The exhaustion log — that tracks individual scripts. Manifests track
  campaign-level results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


MANIFEST_SCHEMA_VERSION = "1.0"


class CampaignVerdict(str, Enum):
    """The five verdicts a campaign manifest can carry.

    STRONG_ELIMINATION: The campaign exhausted its hypothesis class with
        zero positive results. The family is eliminated within stated scope.

    NARROW_RESIDUAL: The campaign found candidates that survive a weak
        criterion but none clear a strict multi-feature multiplicity bar.
        The family is not strictly eliminated but produces no positive
        evidence within the tested scope.

    BOUNDED_NULL: The campaign enumerated a bounded parameterized space
        and found no joint anomaly success. Bounded negative within the
        explicit search space; not a global elimination.

    UNEXPECTED_HIT: The campaign produced a candidate that clears a
        strict multi-feature multiplicity threshold. Requires independent
        verification before any further claim.

    OPEN: The campaign tested but the result is structurally limited
        (e.g., underdetermined by the scoring path). Family remains open.
    """
    STRONG_ELIMINATION = "strong_elimination"
    NARROW_RESIDUAL = "narrow_residual"
    BOUNDED_NULL = "bounded_null"
    UNEXPECTED_HIT = "unexpected_hit"
    OPEN = "open"


@dataclass
class CampaignManifest:
    """A small structured summary of a campaign result.

    Written by the campaign at end of run. Read by the controller at
    bootstrap to update its family registry. Stays in sync with the
    underlying frozen artifact (which the manifest references via
    evidence_pointer).
    """

    # Schema versioning
    manifest_version: str = MANIFEST_SCHEMA_VERSION

    # Identity
    campaign_id: str = ""              # e.g., "f_two_layer_stego_cipher_v1"
    campaign_name: str = ""            # human-readable name
    completed_at: str = ""             # ISO timestamp
    git_commit: str = ""               # short commit hash if available

    # Verdict
    verdict: str = CampaignVerdict.OPEN.value
    verdict_summary: str = ""          # one paragraph, citation-grade
    evidence_pointer: str = ""         # path to the frozen artifact, if any

    # Family registry update payload
    # Each entry maps a family_id to the new tier (if changed) and the
    # evidence text the controller should record. The controller is
    # responsible for ONLY updating tier upward (more eliminated) and
    # for appending evidence rather than overwriting it.
    family_updates: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Scope discipline
    scope_caveats: list[str] = field(default_factory=list)
    scope_does_not_cover: list[str] = field(default_factory=list)

    # Quantitative summary
    total_profiles_evaluated: int = 0
    joint_anomaly_successes: int = 0
    populations_tested: list[str] = field(default_factory=list)
    variants_tested: list[str] = field(default_factory=list)

    # Free-form notes (not parsed by controller)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CampaignManifest:
        d = dict(d)
        # Ignore unknown fields for forward-compatibility
        valid_fields = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in valid_fields})

    def validate(self) -> list[str]:
        """Return a list of validation errors, empty if valid."""
        errors = []
        if not self.campaign_id:
            errors.append("campaign_id is required")
        if not self.completed_at:
            errors.append("completed_at is required")
        if self.verdict not in {v.value for v in CampaignVerdict}:
            errors.append(f"invalid verdict: {self.verdict}")
        if self.family_updates:
            for fid, update in self.family_updates.items():
                if "tier" in update:
                    if not isinstance(update["tier"], int) or not 1 <= update["tier"] <= 4:
                        errors.append(f"family_updates[{fid}].tier must be int 1-4")
                if "evidence" in update and not isinstance(update["evidence"], str):
                    errors.append(f"family_updates[{fid}].evidence must be str")
        return errors


# ── Path conventions ─────────────────────────────────────────────────

def manifest_dir(project_root: Path) -> Path:
    """Canonical path for the campaign manifests directory."""
    return project_root / "results" / "campaign_manifests"


def manifest_path_for(project_root: Path, campaign_id: str) -> Path:
    """Canonical filename for a campaign manifest."""
    return manifest_dir(project_root) / f"{campaign_id}.json"


# ── Writer ───────────────────────────────────────────────────────────

def write_manifest(
    manifest: CampaignManifest,
    project_root: Path,
) -> Path:
    """Write a manifest to its canonical location.

    Validates before writing. Raises ValueError if validation fails.
    Creates the parent directory if needed. Idempotent: re-running the
    same campaign overwrites the same manifest file.

    Returns the path written.
    """
    errors = manifest.validate()
    if errors:
        raise ValueError(f"Manifest validation failed: {'; '.join(errors)}")

    if not manifest.completed_at:
        manifest.completed_at = datetime.now(timezone.utc).isoformat()

    target = manifest_path_for(project_root, manifest.campaign_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest.to_dict(), indent=2))
    return target


# ── Reader ───────────────────────────────────────────────────────────

def load_manifest(path: Path) -> CampaignManifest:
    """Load a single manifest from disk."""
    data = json.loads(path.read_text())
    return CampaignManifest.from_dict(data)


def load_all_manifests(project_root: Path) -> list[CampaignManifest]:
    """Load every manifest from results/campaign_manifests/.

    Returns an empty list if the directory doesn't exist. Skips files
    that fail validation, logging the error to stderr.
    """
    import sys
    target = manifest_dir(project_root)
    if not target.exists():
        return []
    manifests = []
    for path in sorted(target.glob("*.json")):
        try:
            m = load_manifest(path)
            errors = m.validate()
            if errors:
                print(f"[manifest] WARNING: {path.name} failed validation: "
                      f"{'; '.join(errors)}", file=sys.stderr)
                continue
            manifests.append(m)
        except Exception as exc:
            print(f"[manifest] WARNING: failed to load {path.name}: {exc}",
                  file=sys.stderr)
    return manifests


# ── Helper for campaigns ─────────────────────────────────────────────

def quick_manifest(
    *,
    campaign_id: str,
    campaign_name: str,
    verdict: CampaignVerdict,
    verdict_summary: str,
    family_updates: dict[str, dict[str, Any]],
    scope_caveats: list[str] = None,
    scope_does_not_cover: list[str] = None,
    evidence_pointer: str = "",
    total_profiles_evaluated: int = 0,
    joint_anomaly_successes: int = 0,
    populations_tested: list[str] = None,
    variants_tested: list[str] = None,
    git_commit: str = "",
    notes: str = "",
) -> CampaignManifest:
    """Convenience constructor for the common case."""
    return CampaignManifest(
        campaign_id=campaign_id,
        campaign_name=campaign_name,
        completed_at=datetime.now(timezone.utc).isoformat(),
        git_commit=git_commit,
        verdict=verdict.value,
        verdict_summary=verdict_summary,
        evidence_pointer=evidence_pointer,
        family_updates=family_updates,
        scope_caveats=scope_caveats or [],
        scope_does_not_cover=scope_does_not_cover or [],
        total_profiles_evaluated=total_profiles_evaluated,
        joint_anomaly_successes=joint_anomaly_successes,
        populations_tested=populations_tested or [],
        variants_tested=variants_tested or [],
        notes=notes,
    )
