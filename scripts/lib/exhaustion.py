"""Exhaustion log — the authoritative source of truth for attack state.

The exhaustion log (exhaustion_log.json at project root) tracks:
- Attack status: exhausted | active | promising
- Keyspace description
- Best historical score
- Last run date
- Family classification

If script headers and the exhaustion log conflict, the log is authoritative.
"""

import json
from datetime import date
from pathlib import Path
from typing import Optional

# Default location
DEFAULT_LOG_PATH = Path(__file__).resolve().parents[2] / "exhaustion_log.json"

VALID_STATUSES = frozenset({"exhausted", "active", "promising"})


def load(path: Optional[str] = None) -> dict:
    """Load the exhaustion log. Returns empty dict if file doesn't exist."""
    p = Path(path) if path else DEFAULT_LOG_PATH
    if not p.exists():
        return {}
    with open(p, "r") as f:
        return json.load(f)


def save(data: dict, path: Optional[str] = None) -> None:
    """Write the exhaustion log atomically (write-then-rename)."""
    p = Path(path) if path else DEFAULT_LOG_PATH
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    tmp.rename(p)


def get(attack_id: str, path: Optional[str] = None) -> Optional[dict]:
    """Get a single entry from the log."""
    data = load(path)
    return data.get(attack_id)


def update(
    attack_id: str,
    *,
    status: Optional[str] = None,
    keyspace: Optional[str] = None,
    best: Optional[float] = None,
    family: Optional[str] = None,
    last_run: Optional[str] = None,
    description: Optional[str] = None,
    path: Optional[str] = None,
) -> dict:
    """Update or create an entry in the exhaustion log.

    Only provided fields are updated; existing fields are preserved.
    Returns the updated entry.
    """
    data = load(path)
    entry = data.get(attack_id, {})

    if status is not None:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'; must be one of {sorted(VALID_STATUSES)}")
        entry["status"] = status
    if keyspace is not None:
        entry["keyspace"] = keyspace
    if best is not None:
        entry["best"] = best
    if family is not None:
        entry["family"] = family
    if last_run is not None:
        entry["last_run"] = last_run
    if description is not None:
        entry["description"] = description

    data[attack_id] = entry
    save(data, path)
    return entry


def record_run(
    attack_id: str,
    score: float,
    *,
    status: Optional[str] = None,
    path: Optional[str] = None,
) -> dict:
    """Record a completed run: update best score and last_run date.

    Only updates best if the new score exceeds the existing best.
    """
    data = load(path)
    entry = data.get(attack_id, {})

    existing_best = entry.get("best")
    if existing_best is None or score > existing_best:
        entry["best"] = score

    entry["last_run"] = date.today().isoformat()

    if status is not None:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'")
        entry["status"] = status

    data[attack_id] = entry
    save(data, path)
    return entry


def reconcile(header_data: dict, log_data: dict) -> list[str]:
    """Compare header metadata against exhaustion log entries.

    Returns list of mismatch descriptions. The log is authoritative;
    mismatches indicate the script header is stale.
    """
    mismatches = []
    for attack_id, header in header_data.items():
        log_entry = log_data.get(attack_id)
        if log_entry is None:
            mismatches.append(f"{attack_id}: in headers but missing from exhaustion log")
            continue

        h_status = header.get("status", "")
        l_status = log_entry.get("status", "")
        if h_status and l_status and h_status != l_status:
            mismatches.append(
                f"{attack_id}: status mismatch — "
                f"header='{h_status}' vs log='{l_status}' (log is authoritative)"
            )

        h_family = header.get("family", "")
        l_family = log_entry.get("family", "")
        if h_family and l_family and h_family != l_family:
            mismatches.append(
                f"{attack_id}: family mismatch — "
                f"header='{h_family}' vs log='{l_family}'"
            )

    for attack_id in log_data:
        if attack_id not in header_data:
            mismatches.append(f"{attack_id}: in exhaustion log but no script header found")

    return mismatches
