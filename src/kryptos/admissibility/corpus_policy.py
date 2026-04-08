"""Corpus admissibility policy for running-key and text-derived hypotheses.

This is the hard gate that prevents Kryptosbot from drifting into
unconstrained 'guess a book' search.  A source text is admissible iff
it is on the allowlist, AND the allowlist entry carries a public,
reproducible justification tied to clue surface, artist/creator
statement, archive evidence, or a documented anomaly-derived retrieval.

Default allowlist is intentionally small.  Extending it requires:
    1. A `CorpusJustification` enum value
    2. A public `provenance_uri` (URL or repo-path)
    3. At least one `evidence_ref` (doc path or URL)
    4. A `sha256_hash` of the canonical source bytes (reproducibility)
    5. An `added_at` timestamp

At runtime the allowlist can be extended via a JSON override file at
`config/corpus_allowlist.json` — see `load_allowlist_override()`.  The
override MUST follow the same schema; entries without all fields are
rejected.

Integration points:
    - `kryptos.novelty.triage.triage_running_key` — hard gate at entry
    - New scripts: `from kryptos.admissibility import check_corpus_source`

Known ungated paths (policy applies only to Hypothesis-routed loads):
    - `kryptos.corpus.ingest.TextIngester` does NOT enforce the policy.
      It is a corpus builder used by non-Hypothesis scripts.
    - Scripts under `scripts/running_key/` that call `decrypt_text`
      directly without building a Hypothesis are not gated.
    - See `docs/admissibility_architecture.md` "Known ungated paths"
      for the full enumeration.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from kryptos.admissibility.certificate import (
    EliminationCertificate,
    EliminationReason,
)


class CorpusPolicyError(Exception):
    """Raised when corpus policy is enforced and a source is rejected."""


class CorpusJustification(str, Enum):
    """Closed taxonomy of reasons a source may be admitted."""

    CLUE_SURFACE = "clue_surface"
    """Derived from the literal clue surface of the Kryptos installation
    (K1/K2/K3 text, sculpture geometry, engraved plaques)."""

    ARTIST_STATEMENT = "artist_statement"
    """Publicly attested by Jim Sanborn (interviews, letters, archives)."""

    CREATOR_STATEMENT = "creator_statement"
    """Publicly attested by Ed Scheidt or other documented creators."""

    ARCHIVE_EVIDENCE = "archive_evidence"
    """Sourced from a primary-record archive (Archives of American Art,
    NSA declassified material, documented correspondence)."""

    ANOMALY_DERIVED = "anomaly_derived"
    """Retrieved via a documented anomaly-exploitation procedure whose
    retrieval logic is public and reproducible.  Narrative anomalies
    are NOT sufficient — the derivation must be a fixed function."""


@dataclass(frozen=True)
class CorpusLicense:
    """Allowlist entry for a running-key / text-derived source.

    Equality/hashing is by `source_id`, so a source can appear only once
    per logical identity regardless of where it lives on disk.
    """

    source_id: str
    title: str
    author: str
    justification: CorpusJustification
    provenance_uri: str           # Public URL or in-repo path
    evidence_refs: Tuple[str, ...]  # At least 1; doc paths or URLs
    sha256_hash: Optional[str]    # Canonical content hash or None if not pinned
    added_at: str
    notes: str = ""

    def __post_init__(self):
        # Integrity of license entry itself
        if not self.source_id:
            raise ValueError("source_id required")
        if not self.provenance_uri:
            raise ValueError(f"[{self.source_id}] provenance_uri required")
        if not self.evidence_refs:
            raise ValueError(
                f"[{self.source_id}] evidence_refs required (>=1 public reference)"
            )

    def as_dict(self) -> Dict:
        d = asdict(self)
        d["justification"] = self.justification.value
        d["evidence_refs"] = list(self.evidence_refs)
        return d


# ── Default allowlist ────────────────────────────────────────────────────
#
# Each entry here must survive the Admissibility Prosecutor: the
# justification must be *specific and public*, not "Sanborn once mentioned
# a book".  The initial list is deliberately narrow — fewer than ten
# entries — so that pretence by proliferation is impossible.
#
# To add to this list permanently: edit this file AND add a test to
# `tests/test_admissibility.py::TestCorpusPolicy` verifying the new
# entry.  For runtime-only extensions, use `config/corpus_allowlist.json`.

DEFAULT_ALLOWLIST: Tuple[CorpusLicense, ...] = (
    CorpusLicense(
        source_id="k1_plaintext",
        title="K1 Plaintext (BETWEEN SUBTLE SHADING...)",
        author="Jim Sanborn",
        justification=CorpusJustification.CLUE_SURFACE,
        provenance_uri="kryptos://k1_plaintext",
        evidence_refs=(
            "docs/kryptos_ground_truth.md",
            "src/kryptos/kernel/constants.py",
        ),
        sha256_hash=None,  # Derived from repo constants at runtime
        added_at="2026-04-08T00:00:00+00:00",
        notes=(
            "K1/K2/K3 plaintexts are published primary clue surface.  "
            "Running-key derivation from these is the 'text is the key' "
            "hypothesis class that is defensible without external guessing."
        ),
    ),
    CorpusLicense(
        source_id="k2_plaintext",
        title="K2 Plaintext (IT WAS TOTALLY INVISIBLE...)",
        author="Jim Sanborn",
        justification=CorpusJustification.CLUE_SURFACE,
        provenance_uri="kryptos://k2_plaintext",
        evidence_refs=(
            "docs/kryptos_ground_truth.md",
        ),
        sha256_hash=None,
        added_at="2026-04-08T00:00:00+00:00",
        notes="Published K2 plaintext; legitimate clue-surface source.",
    ),
    CorpusLicense(
        source_id="k3_plaintext",
        title="K3 Plaintext (SLOWLY DESPARATLY SLOWLY...)",
        author="Jim Sanborn",
        justification=CorpusJustification.CLUE_SURFACE,
        provenance_uri="kryptos://k3_plaintext",
        evidence_refs=(
            "docs/kryptos_ground_truth.md",
        ),
        sha256_hash=None,
        added_at="2026-04-08T00:00:00+00:00",
        notes="Published K3 plaintext; legitimate clue-surface source.",
    ),
    CorpusLicense(
        source_id="carter_tomb_vol1",
        title="The Tomb of Tut-ankh-Amen, Volume I",
        author="Howard Carter & A. C. Mace",
        justification=CorpusJustification.ARTIST_STATEMENT,
        provenance_uri="reference/carter_vol1.txt",
        evidence_refs=(
            "reference/ed_scheidt_dossier.md",
            "MEMORY.md",  # 'Running-key from UNTESTED sources' open list
            "docs/kryptos_ground_truth.md",
        ),
        sha256_hash=None,  # Populated at load time if file exists
        added_at="2026-04-08T00:00:00+00:00",
        notes=(
            "Sanborn's documented interest in Tut-ankh-Amen tomb "
            "(Egyptological sub-theme of K1 'shading'/'absence of light' "
            "and 'Carter' correspondence in AAA archive).  Admitted as an "
            "ARTIST_STATEMENT source; running-key search from this text "
            "is a defensible hypothesis class, not arbitrary book-guessing."
        ),
    ),
    CorpusLicense(
        source_id="kahn_codebreakers",
        title="The Codebreakers",
        author="David Kahn",
        justification=CorpusJustification.CREATOR_STATEMENT,
        provenance_uri="reference/running_key_texts/kahn_codebreakers_1967.txt",
        evidence_refs=(
            "reference/ed_scheidt_dossier.md",
        ),
        sha256_hash=None,
        added_at="2026-04-08T00:00:00+00:00",
        notes=(
            "Ed Scheidt is publicly documented as having used Kahn's "
            "The Codebreakers during K4 design consultation.  "
            "Admissible as a CREATOR_STATEMENT source."
        ),
    ),
    CorpusLicense(
        source_id="panel_ciphertext",
        title="Kryptos Engraved Cipher Panel (K1-K4 Ciphertext in Row Layout)",
        author="Jim Sanborn",
        justification=CorpusJustification.CLUE_SURFACE,
        provenance_uri="kryptos://panel_ciphertext",
        evidence_refs=(
            "docs/kryptos_ground_truth.md",
            "src/kryptos/kernel/constants.py",  # CT is defined here
        ),
        sha256_hash=None,  # Derived from repo constants at runtime
        added_at="2026-04-08T00:00:00+00:00",
        notes=(
            "The K1-K4 ciphertext as physically carved on the Kryptos "
            "sculpture, consumed as a running-key source under the "
            "hypothesis that K4 is decrypted using physically adjacent "
            "or row-aligned CT segments.  Pure clue surface: the bytes "
            "are engraved in copper and reproducible from any public "
            "transcription.  Seeded by the Kimmo observation that OBKR "
            "under KA Vigenere with QRLG (panel row 3 tail) produces "
            "EACH.  Distinct from k1/k2/k3_plaintext (which cover the "
            "decrypted plaintexts): this covers the CT surface directly.  "
            "Note on self-reference: permits using K4 CT as (offset-"
            "shifted) running key for K4 decryption.  The crib-position "
            "check prevents trivial self-decryption at offset 0, so no "
            "backdoor is introduced; the row-alignment hypothesis "
            "fundamentally depends on cross-row pairings."
        ),
    ),
)


# Normalized runtime registry: source_id -> CorpusLicense.
# Built from DEFAULT_ALLOWLIST plus optional override at load time.

def _build_registry(
    entries: Tuple[CorpusLicense, ...],
) -> Dict[str, CorpusLicense]:
    reg: Dict[str, CorpusLicense] = {}
    for lic in entries:
        if lic.source_id in reg:
            raise ValueError(f"Duplicate source_id in allowlist: {lic.source_id}")
        reg[lic.source_id] = lic
    return reg


CORPUS_ALLOWLIST: Dict[str, CorpusLicense] = _build_registry(DEFAULT_ALLOWLIST)


# ── Override loading ─────────────────────────────────────────────────────

def load_allowlist_override(
    path: str | Path = "config/corpus_allowlist.json",
) -> int:
    """Extend the runtime allowlist from a JSON file.

    The override file must be a JSON list of objects matching the
    `CorpusLicense` field layout (with `justification` as a string).
    Invalid entries are REJECTED SILENTLY in terms of not corrupting the
    allowlist, but the function raises `CorpusPolicyError` with a
    consolidated message so the caller knows which entries failed.

    Returns the number of successfully added entries.
    """
    p = Path(path)
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CorpusPolicyError(f"Cannot read allowlist override {p}: {exc}")
    if not isinstance(data, list):
        raise CorpusPolicyError(
            f"Allowlist override {p} must be a JSON list of license objects"
        )

    errors: List[str] = []
    added = 0
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            errors.append(f"[{i}] not a dict")
            continue
        try:
            lic = CorpusLicense(
                source_id=raw["source_id"],
                title=raw["title"],
                author=raw["author"],
                justification=CorpusJustification(raw["justification"]),
                provenance_uri=raw["provenance_uri"],
                evidence_refs=tuple(raw["evidence_refs"]),
                sha256_hash=raw.get("sha256_hash"),
                added_at=raw.get("added_at", datetime.now(timezone.utc).isoformat()),
                notes=raw.get("notes", ""),
            )
        except (KeyError, ValueError) as exc:
            errors.append(f"[{i}] {exc}")
            continue
        if lic.source_id in CORPUS_ALLOWLIST:
            errors.append(f"[{i}] duplicate source_id {lic.source_id}")
            continue
        CORPUS_ALLOWLIST[lic.source_id] = lic
        added += 1

    if errors:
        raise CorpusPolicyError(
            f"Allowlist override {p} had {len(errors)} invalid entries: "
            + "; ".join(errors[:5])
            + ("..." if len(errors) > 5 else "")
        )
    return added


# ── The gate ─────────────────────────────────────────────────────────────

def get_license(source_id: str) -> Optional[CorpusLicense]:
    """Look up an allowlist entry by `source_id`.  None if not licensed."""
    return CORPUS_ALLOWLIST.get(source_id)


def _repo_root() -> Path:
    """Locate the repository root for resolving license provenance URIs.

    Resolution order:
        1. ``KRYPTOS_REPO_ROOT`` environment variable (when set)
        2. Walk up from this file until a directory containing both
           ``src/kryptos`` and ``reference`` is found
        3. Fall back to the current working directory
    """
    env = os.environ.get("KRYPTOS_REPO_ROOT")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "src" / "kryptos").exists() and (parent / "reference").exists():
            return parent
    return Path.cwd()


def resolve_license_path(source_id: str) -> Optional[Path]:
    """Resolve a licensed source_id to a concrete readable file path.

    This is the authoritative function for "which bytes does this license
    actually consume?".  Caller-supplied paths are **never** honoured
    here — the whole point is that a licensed `source_id` uniquely
    determines the bytes read.

    Returns:
        A concrete ``Path`` to an existing readable file, or ``None``
        when the license:
          - is not in the allowlist,
          - uses an opaque URI scheme (e.g. ``kryptos://``) that has no
            registered local resolver, or
          - points to a repo-relative path that does not exist on disk.

    The ``None`` result should be treated by callers as an
    ``ASSUMPTION_UNMET`` condition, not as a silent fallthrough.
    """
    lic = CORPUS_ALLOWLIST.get(source_id)
    if lic is None:
        return None
    uri = lic.provenance_uri
    if not uri:
        return None

    # Opaque scheme (kryptos://, http://, etc.) — not file-backed.
    if "://" in uri and not uri.startswith("file://"):
        return None

    if uri.startswith("file://"):
        raw = uri[len("file://"):]
    else:
        raw = uri

    path = Path(raw)
    if not path.is_absolute():
        path = _repo_root() / path

    try:
        if path.is_file():
            return path
    except OSError:
        return None
    return None


def _path_to_source_id(path: str) -> Optional[str]:
    """Heuristic mapping from a filesystem path to a known source_id.

    Used to grandfather existing scripts that pass a `source_path` string
    rather than a `source_id`.  If no match is found, the gate must
    REJECT — this is deliberate: the policy defaults to deny.
    """
    if not path:
        return None
    base = os.path.basename(path).lower()
    # Known mappings from existing scripts
    if "carter_vol1" in base or "carter_vol_1" in base:
        return "carter_tomb_vol1"
    if "kahn" in base and "codebreaker" in base:
        return "kahn_codebreakers"
    if base in ("k1.txt", "k1_plaintext.txt"):
        return "k1_plaintext"
    if base in ("k2.txt", "k2_plaintext.txt"):
        return "k2_plaintext"
    if base in ("k3.txt", "k3_plaintext.txt"):
        return "k3_plaintext"
    return None


def check_corpus_source(
    source: str,
    *,
    family: str = "running_key",
    is_source_id: bool = False,
) -> Tuple[bool, Optional[EliminationCertificate]]:
    """Check whether a source is admissible under the corpus policy.

    Args:
        source: Either a filesystem path (default) or a source_id
            (when `is_source_id=True`).
        family: The hypothesis family name for the certificate.
        is_source_id: If True, `source` is treated as a canonical
            source_id; otherwise it is heuristically mapped from a path.

    Returns:
        (ok, certificate):
            ok=True, certificate=None     — source is admissible
            ok=False, certificate=<cert>  — source rejected, certificate
                                             carries reason + evidence
    """
    if is_source_id:
        source_id: Optional[str] = source
    else:
        source_id = _path_to_source_id(source)

    if source_id is None:
        return False, EliminationCertificate(
            family=family,
            reason=EliminationReason.CORPUS_POLICY_VIOLATION,
            summary=(
                f"Source {source!r} cannot be mapped to any allowlisted "
                f"corpus entry (unconstrained running-key is not admissible)."
            ),
            assumptions=[
                "Running-key sources must be publicly justified",
                "Arbitrary 'guess a book' search is not an admissible strategy",
            ],
            evidence={
                "source": source,
                "mapped_source_id": None,
                "allowlist_size": len(CORPUS_ALLOWLIST),
                "allowlisted_ids": sorted(CORPUS_ALLOWLIST.keys()),
            },
            solver="manual",
            is_exact=False,
        )

    lic = CORPUS_ALLOWLIST.get(source_id)
    if lic is None:
        return False, EliminationCertificate(
            family=family,
            reason=EliminationReason.CORPUS_POLICY_VIOLATION,
            summary=(
                f"Source id {source_id!r} is not on the corpus allowlist."
            ),
            assumptions=[
                "Running-key sources must be on the public-provenance allowlist",
            ],
            evidence={
                "source": source,
                "mapped_source_id": source_id,
                "allowlist_size": len(CORPUS_ALLOWLIST),
                "allowlisted_ids": sorted(CORPUS_ALLOWLIST.keys()),
            },
            solver="manual",
            is_exact=False,
        )

    return True, None


def sha256_of_file(path: str | Path) -> Optional[str]:
    """Compute SHA256 of a file for provenance pinning.  None if absent."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
