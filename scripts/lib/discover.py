"""Script discovery and manifest generation.

Discovers attack scripts in scripts/, parses their headers, and builds
manifests without importing any script modules.
"""

import json
from pathlib import Path
from typing import Optional

from .header import (
    ScriptHeader,
    has_attack_function,
    has_standard_header,
    parse_header,
    extract_legacy_description,
)

SCRIPTS_DIR = Path(__file__).resolve().parents[1]  # scripts/


def discover_scripts(scripts_dir: Optional[str] = None) -> list[Path]:
    """Find all Python scripts in the scripts directory (recursive).

    Excludes __pycache__, lib/, examples/, and non-.py files.
    """
    d = Path(scripts_dir) if scripts_dir else SCRIPTS_DIR
    exclude_dirs = {"lib", "examples", "__pycache__"}
    scripts = []
    for p in sorted(d.rglob("*.py")):
        if p.name.startswith("__"):
            continue
        # Skip scripts inside excluded subdirectories
        try:
            rel = p.relative_to(d)
        except ValueError:
            continue
        if any(part in exclude_dirs for part in rel.parts[:-1]):
            continue
        scripts.append(p)
    return scripts


def build_manifest(
    scripts_dir: Optional[str] = None,
    exhaustion_log: Optional[dict] = None,
) -> list[dict]:
    """Build a manifest of all scripts with parsed metadata.

    For scripts with standard headers, uses those fields.
    For legacy scripts, pulls from exhaustion_log if available,
    otherwise marks as 'unknown'.

    Each manifest entry has:
        script_id, path, cipher, family, status, keyspace,
        last_run, best_score, has_header, has_attack_fn, description
    """
    d = Path(scripts_dir) if scripts_dir else SCRIPTS_DIR
    scripts = discover_scripts(scripts_dir)
    if exhaustion_log is None:
        exhaustion_log = {}

    manifest = []
    for script_path in scripts:
        script_id = script_path.stem  # filename without .py
        # Relative path: use the scripts dir's parent if possible, else filename
        try:
            rel_path = str(script_path.relative_to(d.parent))
        except ValueError:
            rel_path = script_path.name

        header = parse_header(str(script_path))
        log_entry = exhaustion_log.get(script_id, {})
        has_attack = has_attack_function(str(script_path))

        if header:
            # Standard header — use it, but note if log disagrees
            entry = {
                "script_id": script_id,
                "path": rel_path,
                "cipher": header.cipher,
                "family": log_entry.get("family", header.family),
                "status": log_entry.get("status", header.status),
                "keyspace": header.keyspace,
                "last_run": log_entry.get("last_run", header.last_run),
                "best_score": log_entry.get("best", header.best_score),
                "has_header": True,
                "has_attack_fn": has_attack,
                "description": extract_legacy_description(str(script_path)),
            }
        else:
            # Legacy script — pull from exhaustion log
            entry = {
                "script_id": script_id,
                "path": rel_path,
                "cipher": "",
                "family": log_entry.get("family", "_uncategorized"),
                "status": log_entry.get("status", "active"),
                "keyspace": log_entry.get("keyspace", ""),
                "last_run": log_entry.get("last_run", ""),
                "best_score": log_entry.get("best", ""),
                "has_header": False,
                "has_attack_fn": has_attack,
                "description": log_entry.get(
                    "description",
                    extract_legacy_description(str(script_path)),
                ),
            }

        manifest.append(entry)

    return manifest


def filter_manifest(
    manifest: list[dict],
    *,
    family: Optional[str] = None,
    status: Optional[str] = None,
    min_score: Optional[float] = None,
    has_attack_fn: Optional[bool] = None,
    has_header: Optional[bool] = None,
) -> list[dict]:
    """Filter manifest entries by criteria.

    family: exact match or substring match (e.g. 'transposition' matches
            'transposition/columnar' and 'transposition/other')
    """
    results = manifest
    if family is not None:
        results = [
            e for e in results
            if family.lower() in e.get("family", "").lower()
        ]
    if status is not None:
        results = [
            e for e in results
            if e.get("status", "") == status
        ]
    if min_score is not None:
        def _score_val(e):
            bs = e.get("best_score", "")
            if isinstance(bs, (int, float)):
                return bs
            if isinstance(bs, str):
                # Extract leading number from strings like "847.3 (quadgram)"
                import re
                m = re.match(r"[-+]?\d*\.?\d+", bs)
                return float(m.group()) if m else None
            return None

        results = [
            e for e in results
            if (s := _score_val(e)) is not None and s >= min_score
        ]
    if has_attack_fn is not None:
        results = [
            e for e in results
            if e.get("has_attack_fn") == has_attack_fn
        ]
    if has_header is not None:
        results = [
            e for e in results
            if e.get("has_header") == has_header
        ]
    return results


def print_manifest_table(manifest: list[dict], verbose: bool = False) -> None:
    """Pretty-print a manifest as a table."""
    if not manifest:
        print("No scripts found.")
        return

    # Compact table
    print(f"{'ID':<45} {'Family':<25} {'Status':<12} {'Hdr':>3} {'Atk':>3} {'Best':>10}")
    print("-" * 105)
    for e in manifest:
        best = e.get("best_score", "")
        if isinstance(best, float):
            best = f"{best:.1f}"
        best = str(best)[:10]
        print(
            f"{e['script_id']:<45} "
            f"{e.get('family', ''):<25} "
            f"{e.get('status', ''):<12} "
            f"{'Y' if e.get('has_header') else 'N':>3} "
            f"{'Y' if e.get('has_attack_fn') else 'N':>3} "
            f"{best:>10}"
        )

    print(f"\nTotal: {len(manifest)} scripts")

    if verbose:
        # Summary stats
        families = {}
        statuses = {}
        n_headers = 0
        n_attack = 0
        for e in manifest:
            fam = e.get("family", "_uncategorized")
            families[fam] = families.get(fam, 0) + 1
            st = e.get("status", "unknown")
            statuses[st] = statuses.get(st, 0) + 1
            if e.get("has_header"):
                n_headers += 1
            if e.get("has_attack_fn"):
                n_attack += 1

        print(f"\nBy family:")
        for fam, count in sorted(families.items(), key=lambda x: -x[1]):
            print(f"  {fam}: {count}")
        print(f"\nBy status:")
        for st, count in sorted(statuses.items(), key=lambda x: -x[1]):
            print(f"  {st}: {count}")
        print(f"\nStandard headers: {n_headers}/{len(manifest)}")
        print(f"attack() function: {n_attack}/{len(manifest)}")
