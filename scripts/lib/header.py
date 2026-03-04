"""Parse, validate, and generate metadata headers for attack scripts.

The standard header is a docstring at the top of each script:

    \"\"\"
    Cipher: Vigenere
    Family: polyalphabetic
    Status: exhausted
    Keyspace: 26^1 through 26^12
    Last run: 2026-03-04
    Best score: 847.3 (quadgram)
    \"\"\"

All parsing is text-based — scripts are never imported.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

VALID_STATUSES = frozenset({"exhausted", "active", "promising"})
REQUIRED_FIELDS = ("Cipher", "Family", "Status", "Keyspace", "Last run", "Best score")

# Known families (from EXHAUSTION.json taxonomy).  Extensible.
KNOWN_FAMILIES = frozenset({
    "antipodes", "blitz", "campaigns", "cfm", "crib_analysis",
    "encoding", "exploration", "fractionation", "grille",
    "k3_continuity", "polyalphabetic", "running_key", "statistical",
    "substitution", "tableau", "team",
    "thematic/berlin_clock", "thematic/sculpture_physical",
    "transposition/columnar", "transposition/other",
    "yar", "_infra", "_uncategorized",
})


@dataclass
class ScriptHeader:
    """Parsed metadata header from an attack script."""
    cipher: str
    family: str
    status: str
    keyspace: str = ""
    last_run: str = ""
    best_score: str = ""
    path: Optional[str] = None

    def validate(self) -> list[str]:
        """Return list of validation errors (empty = valid)."""
        errors = []
        if self.status not in VALID_STATUSES:
            errors.append(
                f"Invalid status '{self.status}'; "
                f"must be one of {sorted(VALID_STATUSES)}"
            )
        if not self.cipher:
            errors.append("Cipher field is empty")
        if not self.family:
            errors.append("Family field is empty")
        return errors

    def to_docstring(self) -> str:
        """Render as a triple-quoted docstring block."""
        return (
            '"""\n'
            f"Cipher: {self.cipher}\n"
            f"Family: {self.family}\n"
            f"Status: {self.status}\n"
            f"Keyspace: {self.keyspace}\n"
            f"Last run: {self.last_run}\n"
            f"Best score: {self.best_score}\n"
            '"""\n'
        )

    def to_dict(self) -> dict:
        """Serialize to dict for JSON output."""
        return {
            "cipher": self.cipher,
            "family": self.family,
            "status": self.status,
            "keyspace": self.keyspace,
            "last_run": self.last_run,
            "best_score": self.best_score,
        }


def parse_header(filepath: str) -> Optional[ScriptHeader]:
    """Parse metadata header from a script file without importing it.

    Reads raw text and extracts fields from the first docstring.
    Returns None if the file lacks a conforming header (needs at least
    Cipher, Family, and Status fields).
    """
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return None

    # Find the first triple-quoted docstring (double or single quotes)
    match = re.search(r'"""(.*?)"""', text[:3000], re.DOTALL)
    if not match:
        match = re.search(r"'''(.*?)'''", text[:3000], re.DOTALL)
    if not match:
        return None

    docstring = match.group(1)

    # Extract key: value fields
    fields = {}
    for field_name in REQUIRED_FIELDS:
        pattern = rf"^{re.escape(field_name)}:\s*(.+)$"
        field_match = re.search(pattern, docstring, re.MULTILINE)
        if field_match:
            fields[field_name] = field_match.group(1).strip()

    # Must have at least the three critical fields
    if not all(k in fields for k in ("Cipher", "Family", "Status")):
        return None

    return ScriptHeader(
        cipher=fields.get("Cipher", ""),
        family=fields.get("Family", ""),
        status=fields.get("Status", ""),
        keyspace=fields.get("Keyspace", ""),
        last_run=fields.get("Last run", ""),
        best_score=fields.get("Best score", ""),
        path=filepath,
    )


def has_standard_header(filepath: str) -> bool:
    """Check whether a script has a parseable standard header."""
    return parse_header(filepath) is not None


def has_attack_function(filepath: str) -> bool:
    """Check whether a script defines an attack() function (text scan, no import)."""
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return False
    return bool(re.search(r"^def attack\s*\(", text, re.MULTILINE))


def extract_legacy_description(filepath: str) -> str:
    """Extract the first line of the existing docstring for legacy scripts."""
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return ""

    match = re.search(r'"""(.*?)"""', text[:5000], re.DOTALL)
    if not match:
        match = re.search(r"'''(.*?)'''", text[:5000], re.DOTALL)
    if not match:
        return ""

    first_line = match.group(1).strip().split("\n")[0].strip()
    return first_line
