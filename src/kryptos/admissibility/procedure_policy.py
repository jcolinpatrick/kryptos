"""Cipher-procedure admissibility policy for bespoke-cipher hypotheses.

This is the hard gate that prevents Kryptosbot from drifting into
unconstrained 'guess a procedure' search. It is the companion of the
corpus policy (`corpus_policy.py`): corpus policy gates *bytes* (running-
key and other text-derived hypotheses), procedure policy gates *cipher
constructions* (bespoke cipher families claimed to be K4-relevant).

A cipher procedure is admissible iff it is on the allowlist, AND the
allowlist entry carries a public, reproducible justification tied to
clue surface, artist/creator statement, archive evidence, or a documented
anomaly-derived retrieval, AND the allowlist entry names a concrete
parametric spec that the attack code must conform to.

Default allowlist is intentionally small. Extending it requires:
    1. A `ProcedureJustification` enum value
    2. A public `provenance_uri` (URL or repo path to the evidence)
    3. At least one `evidence_ref` (doc path or URL documenting the claim)
    4. A `parametric_spec` pointer (repo path to a docs/code file that
       formally defines the attack's parameter space and semantics)
    5. An `added_at` timestamp

At runtime the allowlist can be extended via a JSON override file at
`config/procedure_allowlist.json`; see `load_procedure_allowlist_override()`.

Integration points:
    - Bespoke-cipher campaign scripts: `from kryptos.admissibility import
      check_cipher_procedure`
    - Novelty hypothesis classes that claim archive/anomaly provenance

Scope — what this gate does NOT cover:
    - Standard kernel ciphers (Vigenere, Beaufort, columnar, etc.) do
      not need a procedure license. They are generic cryptographic
      primitives, not Kryptos-specific procedure claims. The gate is for
      attacks that operationalize a claim like "Sanborn's archive
      suggests cipher procedure X" or "this procedure is derived from
      sculpture anomaly Y".
    - The gate does not validate the parametric spec itself; it only
      checks that the license names one. Validating the spec is the job
      of the code that implements the attack.

Derivation-pointer requirement (shared with corpus_policy):
    A solver working only from Kryptos itself and its public record must
    be able to derive a pointer to this procedure as a plausible K4
    construction. A creator statement about cipher MECHANICS ("I read
    Kahn during design") is NOT a procedure license (that is about
    mechanics consultation, not about the cipher construction actually
    used). A creator statement about the cipher construction itself
    ("I used a Beaufort layer") IS a procedure license, provided the
    statement is publicly attested and reproducible.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from kryptos.admissibility.certificate import (
    EliminationCertificate,
    EliminationReason,
)


class ProcedurePolicyError(Exception):
    """Raised when procedure policy is enforced and a procedure is rejected."""


class ProcedureJustification(str, Enum):
    """Closed taxonomy of reasons a cipher procedure may be admitted.

    This taxonomy mirrors `CorpusJustification` but applies to cipher
    CONSTRUCTIONS rather than to text bytes. The derivation-pointer
    requirement applies identically: a solver working only from Kryptos
    itself must be able to reach this procedure via a public derivation
    path, not via the creator's extra-Kryptos reading list.
    """

    CLUE_SURFACE = "clue_surface"
    """Derived from the literal clue surface of the Kryptos installation:
    the sculpture's physical features, engraved text, Vigenere tableau
    on the back panel, published K1/K2/K3 cipher techniques, or similar
    publicly-readable material. A solver can reach the procedure without
    extra-Kryptos knowledge.

    Example: K1 and K2 are solved as Quagmire III (a keyed Vigenere
    variant with a mixed-CT alphabet). K4 being tested as Quagmire III
    is a CLUE_SURFACE procedure claim because the construction is
    directly attested by solved sections of the same sculpture."""

    ARTIST_STATEMENT = "artist_statement"
    """Publicly attested by Jim Sanborn as a cipher construction used
    in K4. A statement about artist intent ("I wrote the plaintext to
    be enigmatic") is NOT sufficient; the statement must name the
    cipher construction and be publicly reproducible.

    Sanborn statements carry Tier-3 epistemic weight per
    `feedback_sanborn_epistemic_weight.md`: treat them as community
    hearsay unless independently corroborated by the sculpture itself
    or by archive evidence. An ARTIST_STATEMENT procedure license is
    acceptable only when the statement is unambiguous about the cipher
    construction, not about artist intent or puzzle philosophy."""

    CREATOR_STATEMENT = "creator_statement"
    """Publicly attested by Ed Scheidt or another documented creator
    as a cipher construction used in K4. Subject to the same
    mechanics-vs-construction distinction as the corpus policy:
    "I read Kahn while designing the cipher" is a mechanics statement
    (not a valid procedure license), but "K4 uses a Beaufort layer"
    is a construction statement (valid if publicly attested).

    This tier is deliberately narrower than ARTIST_STATEMENT because
    Scheidt was the technical consultant on how K4 works. His
    statements about mechanics are plentiful; his statements about
    the specific K4 construction are rare and tightly scoped."""

    ARCHIVE_EVIDENCE = "archive_evidence"
    """Sourced from a primary-record archive (Archives of American Art,
    NSA declassified material, documented correspondence) where the
    archive record names a cipher construction in a way a solver can
    discover through public archival research.

    Example: Sanborn's AAA notebooks (circa 1988-1990) include the
    notation `4, 8, 10, 26 = Col` on a working page. A solver who
    obtains the archive can derive "try columnar widths 4, 8, 10, 26"
    as a procedure. The archive record is the derivation pointer."""

    ANOMALY_DERIVED = "anomaly_derived"
    """Retrieved via a documented anomaly-exploitation procedure whose
    retrieval logic is public and reproducible. Narrative anomalies
    ("the sculpture has a lodestone pointing at the pool") are NOT
    sufficient; the derivation must be a fixed function operating on
    Kryptos-internal state, producing a concrete cipher construction
    as output.

    Example: if a documented rule says "the circled-letter positions
    encode a transposition permutation," and the circled letters are
    publicly photographed, the resulting permutation is an
    ANOMALY_DERIVED procedure claim. The derivation must be pinned;
    "try something clever with the anomaly" does not qualify."""


@dataclass(frozen=True)
class ProcedureLicense:
    """Allowlist entry for a bespoke cipher procedure.

    Equality/hashing is by `procedure_id`, so a procedure can appear
    only once per logical identity regardless of how it is described.

    Attributes
    ----------
    procedure_id : str
        Canonical snake_case identifier. Must be unique within the
        allowlist.
    name : str
        Human-readable name (e.g., "ABSCISSA as Vigenere keyword").
    family : str
        Cipher family label: "substitution", "transposition", "compound",
        "grille", "hybrid", or similar. This is advisory; it does not
        constrain the spec.
    justification : ProcedureJustification
        The taxonomy value describing why this procedure is admissible.
    provenance_uri : str
        Public URL or in-repo path pointing at the PRIMARY evidence for
        the procedure (archive page, Sanborn letter, Scheidt dossier
        entry, anomaly documentation). This is evidence of the claim,
        not a file of bytes to consume.
    evidence_refs : tuple[str, ...]
        At least one additional public reference (doc paths or URLs)
        that corroborates or contextualises the claim.
    parametric_spec : str
        Repo path or URI to a document or code module that formally
        defines the attack's parameter space and semantics. Pinning
        this prevents procedure-license drift: two scripts that both
        claim "ABSCISSA" must operationalize it according to the same
        named spec, not in ad-hoc ways.
    added_at : str
        ISO-8601 timestamp, UTC.
    notes : str
        Free-text explanation of why the procedure is admissible and
        any caveats. Kept optional but strongly encouraged.
    """

    procedure_id: str
    name: str
    family: str
    justification: ProcedureJustification
    provenance_uri: str
    evidence_refs: Tuple[str, ...]
    parametric_spec: str
    added_at: str
    notes: str = ""

    def __post_init__(self):
        if not self.procedure_id:
            raise ValueError("procedure_id required")
        if not self.provenance_uri:
            raise ValueError(
                f"[{self.procedure_id}] provenance_uri required"
            )
        if not self.evidence_refs:
            raise ValueError(
                f"[{self.procedure_id}] evidence_refs required "
                f"(>=1 public reference)"
            )
        if not self.parametric_spec:
            raise ValueError(
                f"[{self.procedure_id}] parametric_spec required "
                f"(pin the formal attack specification)"
            )

    def as_dict(self) -> Dict:
        d = asdict(self)
        d["justification"] = self.justification.value
        d["evidence_refs"] = list(self.evidence_refs)
        return d


# ── Default allowlist ────────────────────────────────────────────────────
#
# Initial entries are deliberately scoped to procedures that have a
# documented derivation pointer in Kryptos' public record. Expanding
# this list permanently requires editing this file AND adding a test
# in tests/test_procedure_policy.py asserting the new entry's shape.
#
# For runtime-only extensions, use `config/procedure_allowlist.json`.

DEFAULT_PROCEDURE_ALLOWLIST: Tuple[ProcedureLicense, ...] = (
    ProcedureLicense(
        procedure_id="quagmire_iii_family",
        name="Quagmire III (solved-section continuity)",
        family="substitution",
        justification=ProcedureJustification.CLUE_SURFACE,
        provenance_uri="kryptos://k1_k2_cipher_type",
        evidence_refs=(
            "docs/kryptos_ground_truth.md",
            "docs/invariants.md",
        ),
        parametric_spec="src/kryptos/kernel/transforms/vigenere.py",
        added_at="2026-04-09T00:00:00+00:00",
        notes=(
            "K1 and K2 are solved as Quagmire III (keyed Vigenere with "
            "mixed CT alphabet, KRYPTOS as the keyed alphabet). K4 "
            "being tested under Quagmire III as one layer of a "
            "composition is a CLUE_SURFACE procedure claim because the "
            "construction is directly attested by solved sections of "
            "the same sculpture. This does not imply K4 IS Quagmire "
            "III; it licenses tests that treat it as a candidate layer."
        ),
    ),
    ProcedureLicense(
        procedure_id="k3_columnar_transposition",
        name="K3-style columnar transposition (solved-section continuity)",
        family="transposition",
        justification=ProcedureJustification.CLUE_SURFACE,
        provenance_uri="kryptos://k3_cipher_type",
        evidence_refs=(
            "docs/kryptos_ground_truth.md",
            "docs/invariants.md",
        ),
        parametric_spec="src/kryptos/kernel/transforms/transposition.py",
        added_at="2026-04-09T00:00:00+00:00",
        notes=(
            "K3 is solved as a double columnar transposition. K4 being "
            "tested with a columnar transposition layer (any width in "
            "the kernel's supported range) is a CLUE_SURFACE procedure "
            "claim by solved-section continuity. This license does NOT "
            "override the Tier 1 elimination of columnar widths 6/8/9 "
            "under additive keys (see elimination_tiers.md); it "
            "licenses the construction as a candidate, not its success."
        ),
    ),
    ProcedureLicense(
        procedure_id="abscissa_as_keyword",
        name="ABSCISSA as Vigenere/Beaufort/Quagmire keyword",
        family="substitution",
        justification=ProcedureJustification.ARCHIVE_EVIDENCE,
        provenance_uri="reference/Notes/Archives Visit.txt",
        evidence_refs=(
            "MEMORY.md",  # cites AAA archive findings
            "docs/anomaly_registry.md",
        ),
        parametric_spec="src/kryptos/kernel/transforms/vigenere.py",
        added_at="2026-04-09T00:00:00+00:00",
        notes=(
            "ABSCISSA appears as a research term in Sanborn's AAA "
            "archive notebooks (circa 1988-1990). A solver with access "
            "to the public archive can derive ABSCISSA as a candidate "
            "keyword. The license covers using ABSCISSA as the key for "
            "any standard polyalphabetic substitution (Vigenere, "
            "Beaufort, Variant Beaufort, Quagmire III). It does NOT "
            "cover ad-hoc bespoke constructions that merely cite "
            "ABSCISSA as inspiration."
        ),
    ),
    ProcedureLicense(
        procedure_id="atbash_substitution_layer",
        name="Atbash substitution as a composition layer",
        family="substitution",
        justification=ProcedureJustification.ARCHIVE_EVIDENCE,
        provenance_uri="reference/Notes/Archives Visit.txt",
        evidence_refs=(
            "MEMORY.md",  # AAA findings: ATBASH on same page as ABSCISSA
            "docs/anomaly_registry.md",
        ),
        parametric_spec="src/kryptos/kernel/transforms/atbash.py",
        added_at="2026-04-09T00:00:00+00:00",
        notes=(
            "ATBASH appears in Sanborn's AAA archive notebooks on the "
            "same working page as ABSCISSA. The license covers Atbash "
            "as a substitution layer in a composition (Atbash is "
            "parameter-free: it is the fixed involution A<->Z, B<->Y, "
            "...). Pinned to `atbash.py` in the kernel; if that module "
            "does not exist the gate still accepts the license but "
            "scripts using it are responsible for providing an "
            "equivalent fixed-alphabet-reversal implementation."
        ),
    ),
    ProcedureLicense(
        procedure_id="col_notation_4_8_10_26",
        name="Columnar widths {4, 8, 10, 26} per Sanborn archive notation",
        family="transposition",
        justification=ProcedureJustification.ARCHIVE_EVIDENCE,
        provenance_uri="reference/Notes/Archives Visit.txt",
        evidence_refs=(
            "MEMORY.md",  # cites the notation 4,8,10,26=Col
        ),
        parametric_spec="src/kryptos/kernel/transforms/transposition.py",
        added_at="2026-04-09T00:00:00+00:00",
        notes=(
            "Sanborn's AAA notebook contains the notation "
            "'4, 8, 10, 26 = Col' on a working page. The license "
            "covers columnar transposition tests at these four specific "
            "widths (not all widths). Widths 4 and 26 have not been "
            "exhaustively tested under the current 242-ineq Bean "
            "constraint; widths 8 and 10 are covered by the "
            "source-independent Tier 1 elimination in "
            "elimination_tiers.md only for columnar combined with "
            "ADDITIVE keys, not for columnar combined with mono inner "
            "layers, so the license remains meaningful for "
            "multi-layer compositions."
        ),
    ),
    ProcedureLicense(
        procedure_id="beaufort_layer_archive",
        name="Beaufort cipher as a composition layer (Sanborn handwritten list)",
        family="substitution",
        justification=ProcedureJustification.ARCHIVE_EVIDENCE,
        provenance_uri="reference/Notes/Archives Visit.txt",
        evidence_refs=(
            "MEMORY.md",  # cites Sanborn's handwritten cipher list
        ),
        parametric_spec="src/kryptos/kernel/transforms/vigenere.py",
        added_at="2026-04-09T00:00:00+00:00",
        notes=(
            "Sanborn's AAA archive contains a handwritten list of "
            "cipher names that includes 'Beaufort Cipher'. The list "
            "does not specify K4 uses Beaufort, only that Sanborn "
            "considered it. Under the derivation-pointer rule this is "
            "sufficient: a solver reading the archive can derive "
            "Beaufort as a candidate. The kernel's Beaufort "
            "implementation is the pinned spec. A=0 indexing is the "
            "confirmed default per MEMORY.md pitfalls."
        ),
    ),
)


# Normalized runtime registry: procedure_id -> ProcedureLicense.
def _build_registry(
    entries: Tuple[ProcedureLicense, ...],
) -> Dict[str, ProcedureLicense]:
    reg: Dict[str, ProcedureLicense] = {}
    for lic in entries:
        if lic.procedure_id in reg:
            raise ValueError(
                f"Duplicate procedure_id in allowlist: {lic.procedure_id}"
            )
        reg[lic.procedure_id] = lic
    return reg


PROCEDURE_ALLOWLIST: Dict[str, ProcedureLicense] = _build_registry(
    DEFAULT_PROCEDURE_ALLOWLIST
)


# ── Override loading ─────────────────────────────────────────────────────

def load_procedure_allowlist_override(
    path: str | Path = "config/procedure_allowlist.json",
) -> int:
    """Extend the runtime procedure allowlist from a JSON file.

    The override file must be a JSON list of objects matching the
    `ProcedureLicense` field layout (with `justification` as a string
    and `evidence_refs` as a list). Invalid entries are rejected with a
    consolidated `ProcedurePolicyError`.

    Returns the number of successfully added entries. Returns 0 without
    error if the override file does not exist.
    """
    p = Path(path)
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ProcedurePolicyError(
            f"Cannot read procedure allowlist override {p}: {exc}"
        )
    if not isinstance(data, list):
        raise ProcedurePolicyError(
            f"Procedure allowlist override {p} must be a JSON list"
        )

    errors: List[str] = []
    added = 0
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            errors.append(f"[{i}] not a dict")
            continue
        try:
            lic = ProcedureLicense(
                procedure_id=raw["procedure_id"],
                name=raw["name"],
                family=raw["family"],
                justification=ProcedureJustification(raw["justification"]),
                provenance_uri=raw["provenance_uri"],
                evidence_refs=tuple(raw["evidence_refs"]),
                parametric_spec=raw["parametric_spec"],
                added_at=raw.get(
                    "added_at",
                    datetime.now(timezone.utc).isoformat(),
                ),
                notes=raw.get("notes", ""),
            )
        except (KeyError, ValueError) as exc:
            errors.append(f"[{i}] {exc}")
            continue
        if lic.procedure_id in PROCEDURE_ALLOWLIST:
            errors.append(
                f"[{i}] duplicate procedure_id {lic.procedure_id}"
            )
            continue
        PROCEDURE_ALLOWLIST[lic.procedure_id] = lic
        added += 1

    if errors:
        raise ProcedurePolicyError(
            f"Procedure allowlist override {p} had {len(errors)} "
            f"invalid entries: "
            + "; ".join(errors[:5])
            + ("..." if len(errors) > 5 else "")
        )
    return added


# ── The gate ─────────────────────────────────────────────────────────────

def get_procedure_license(procedure_id: str) -> Optional[ProcedureLicense]:
    """Look up a procedure allowlist entry. Returns None if not licensed."""
    return PROCEDURE_ALLOWLIST.get(procedure_id)


def check_cipher_procedure(
    procedure_id: str,
    *,
    family: str = "cipher_procedure",
) -> Tuple[bool, Optional[EliminationCertificate]]:
    """Check whether a cipher procedure is admissible under the policy.

    This is the hard gate for bespoke-cipher hypothesis scripts. A
    script proposing to operationalize a claim like "Sanborn's archive
    suggests procedure X" must pass this check before running; scripts
    testing standard kernel ciphers (Vigenere, Beaufort, columnar)
    without a Kryptos-specific provenance claim do NOT need to call
    this gate.

    Args:
        procedure_id: Canonical procedure identifier (must match a
            `ProcedureLicense.procedure_id`).
        family: The hypothesis family label for the certificate.
            Defaults to "cipher_procedure".

    Returns:
        (ok, certificate):
            ok=True, certificate=None   — procedure is admissible
            ok=False, certificate=<c>   — procedure rejected; certificate
                                           carries reason, assumptions,
                                           and allowlist evidence.
    """
    if not procedure_id:
        return False, EliminationCertificate(
            family=family,
            reason=EliminationReason.PROCEDURE_POLICY_VIOLATION,
            summary=(
                "Empty procedure_id; cipher-procedure attacks must "
                "declare a canonical procedure_id on the allowlist."
            ),
            assumptions=[
                "Bespoke cipher procedures must be publicly justified",
                "Ad-hoc 'guess a procedure' search is not admissible",
            ],
            evidence={
                "procedure_id": procedure_id,
                "allowlist_size": len(PROCEDURE_ALLOWLIST),
                "allowlisted_ids": sorted(PROCEDURE_ALLOWLIST.keys()),
            },
            solver="manual",
            is_exact=False,
        )

    lic = PROCEDURE_ALLOWLIST.get(procedure_id)
    if lic is None:
        return False, EliminationCertificate(
            family=family,
            reason=EliminationReason.PROCEDURE_POLICY_VIOLATION,
            summary=(
                f"Procedure id {procedure_id!r} is not on the procedure "
                f"allowlist. Bespoke cipher procedures require a public "
                f"derivation pointer plus a pinned parametric spec."
            ),
            assumptions=[
                "Cipher procedures must satisfy the derivation-pointer rule",
                "Procedures must name a pinned parametric spec",
            ],
            evidence={
                "procedure_id": procedure_id,
                "allowlist_size": len(PROCEDURE_ALLOWLIST),
                "allowlisted_ids": sorted(PROCEDURE_ALLOWLIST.keys()),
            },
            solver="manual",
            is_exact=False,
        )

    return True, None
