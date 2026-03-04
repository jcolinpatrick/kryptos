#!/usr/bin/env python3
"""Migrate legacy scripts to the standard header + attack() contract.

Usage:
    # Preview what would change (dry run)
    python scripts/lib/migrate.py --dry-run scripts/e_frac_05_mixed_alphabets.py

    # Add standard header to a script
    python scripts/lib/migrate.py scripts/e_solve_13_grid_routes.py

    # Batch: add headers to all scripts in a family
    python scripts/lib/migrate.py --family transposition/columnar

    # Show migration status
    python scripts/lib/migrate.py --status

The migration process:
1. Reads the existing docstring to infer Cipher and description
2. Looks up the script in exhaustion_log.json for family/status
3. Prepends the standard header block above the existing docstring
4. Does NOT modify the script body or add attack() — that's manual work

Scripts that already have a standard header are skipped.
"""

import argparse
import re
import sys
from datetime import date
from pathlib import Path

# Add project root for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.lib.header import (
    ScriptHeader,
    has_standard_header,
    parse_header,
    extract_legacy_description,
    KNOWN_FAMILIES,
)
from scripts.lib.exhaustion import load as load_exhaustion

SCRIPTS_DIR = Path(__file__).resolve().parents[1]

# Map family slugs to likely cipher types (best-effort inference)
FAMILY_TO_CIPHER = {
    "polyalphabetic": "Vigenere/Beaufort",
    "substitution": "monoalphabetic substitution",
    "transposition/columnar": "columnar transposition",
    "transposition/other": "non-columnar transposition",
    "grille": "Cardan grille",
    "fractionation": "fractionation analysis",
    "running_key": "running key",
    "tableau": "tableau analysis",
    "yar": "YAR grille",
    "k3_continuity": "K3-method extension",
    "crib_analysis": "crib-based constraint",
    "thematic/berlin_clock": "Berlin clock",
    "thematic/sculpture_physical": "physical/coordinate",
    "antipodes": "Antipodes analysis",
    "encoding": "encoding/extraction",
    "statistical": "statistical analysis",
    "blitz": "multi-method blitz",
    "campaigns": "multi-vector campaign",
    "cfm": "cipher family model",
    "team": "team-sourced attack",
    "exploration": "exploratory/bespoke",
    "_infra": "infrastructure",
    "_uncategorized": "uncategorized",
}


def infer_header(script_path: Path, exhaustion_log: dict) -> ScriptHeader:
    """Infer a standard header from a legacy script + exhaustion log."""
    script_id = script_path.stem
    log_entry = exhaustion_log.get(script_id, {})

    family = log_entry.get("family", "_uncategorized")
    cipher = FAMILY_TO_CIPHER.get(family, "unknown")
    description = extract_legacy_description(str(script_path))

    # Try to infer cipher from description keywords
    desc_lower = (description or "").lower()
    if "vigenere" in desc_lower or "beaufort" in desc_lower:
        cipher = "Vigenere/Beaufort"
    elif "autokey" in desc_lower:
        cipher = "autokey"
    elif "hill" in desc_lower:
        cipher = "Hill cipher"
    elif "columnar" in desc_lower:
        cipher = "columnar transposition"
    elif "grille" in desc_lower or "cardan" in desc_lower:
        cipher = "Cardan grille"
    elif "playfair" in desc_lower:
        cipher = "Playfair"
    elif "bifid" in desc_lower:
        cipher = "Bifid"
    elif "running key" in desc_lower or "running-key" in desc_lower:
        cipher = "running key"

    return ScriptHeader(
        cipher=cipher,
        family=family,
        status=log_entry.get("status", "active"),
        keyspace=log_entry.get("keyspace", "see implementation"),
        last_run=log_entry.get("last_run", ""),
        best_score=str(log_entry.get("best", "")) if log_entry.get("best") else "",
        path=str(script_path),
    )


def add_header_to_script(script_path: Path, header: ScriptHeader, dry_run: bool = False) -> bool:
    """Prepend a standard metadata header to a script.

    Inserts the header block as a NEW docstring before the existing one.
    The existing docstring (description) is preserved below.

    Returns True if the file was modified (or would be in dry run).
    """
    text = script_path.read_text(encoding="utf-8")

    # Find where to insert: after shebang (if present), before everything else
    lines = text.split("\n")
    insert_idx = 0

    # Skip shebang
    if lines and lines[0].startswith("#!"):
        insert_idx = 1

    # Build the header block
    header_block = header.to_docstring()

    # Insert before the existing content
    new_lines = lines[:insert_idx] + header_block.rstrip("\n").split("\n") + lines[insert_idx:]
    new_text = "\n".join(new_lines)

    if dry_run:
        print(f"  Would add header to {script_path.name}:")
        for line in header_block.strip().split("\n"):
            print(f"    {line}")
        return True

    script_path.write_text(new_text, encoding="utf-8")
    return True


def migrate_script(script_path: Path, exhaustion_log: dict, dry_run: bool = False) -> bool:
    """Migrate a single script. Returns True if modified."""
    if has_standard_header(str(script_path)):
        print(f"  SKIP {script_path.name} — already has standard header")
        return False

    header = infer_header(script_path, exhaustion_log)
    errors = header.validate()
    if errors:
        print(f"  WARN {script_path.name} — header validation: {errors}")

    return add_header_to_script(script_path, header, dry_run=dry_run)


def main():
    parser = argparse.ArgumentParser(description="Migrate scripts to standard header format")
    parser.add_argument("scripts", nargs="*", help="Script files to migrate")
    parser.add_argument("--all", action="store_true", help="Migrate ALL scripts")
    parser.add_argument("--family", help="Migrate all scripts in this family")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--status", action="store_true", help="Show migration status")
    parser.add_argument("--exhaustion-log", default=None, help="Path to exhaustion_log.json")
    args = parser.parse_args()

    exhaustion_log = load_exhaustion(args.exhaustion_log)

    if args.status:
        from scripts.lib.discover import discover_scripts
        scripts = discover_scripts()
        n_total = len(scripts)
        n_header = sum(1 for s in scripts if has_standard_header(str(s)))
        print(f"Migration status: {n_header}/{n_total} scripts have standard headers")
        print(f"  Remaining: {n_total - n_header}")
        return

    targets = []

    if args.scripts:
        targets = [Path(s) for s in args.scripts]
    elif getattr(args, 'all', False):
        from scripts.lib.discover import discover_scripts
        targets = discover_scripts()
    elif args.family:
        from scripts.lib.discover import discover_scripts
        for script_path in discover_scripts():
            script_id = script_path.stem
            entry = exhaustion_log.get(script_id, {})
            if args.family.lower() in entry.get("family", "").lower():
                targets.append(script_path)
    else:
        parser.print_help()
        return

    modified = 0
    for target in targets:
        if not target.exists():
            print(f"  NOT FOUND: {target}")
            continue
        if migrate_script(target, exhaustion_log, dry_run=args.dry_run):
            modified += 1

    action = "Would modify" if args.dry_run else "Modified"
    print(f"\n{action} {modified}/{len(targets)} scripts")


if __name__ == "__main__":
    main()
