#!/usr/bin/env python3
"""
KryptosBot Script Organizer
============================
Categorizes ~520 flat scripts into a structured hierarchy,
generates a machine-readable manifest, and optionally moves files.

Usage:
    # DRY RUN (default) - shows what would happen, writes manifest
    python kryptos_organize.py /path/to/scripts

    # EXECUTE - actually moves files into subdirectories
    python kryptos_organize.py /path/to/scripts --execute

    # MANIFEST ONLY - just build the manifest from current layout
    python kryptos_organize.py /path/to/scripts --manifest-only

Outputs:
    MANIFEST.tsv    - machine-readable index (path|family|status|description)
    EXHAUSTION.json - tracks which attack vectors have been tested
    migration.log   - what moved where (only in --execute mode)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime


# ── Category definitions ─────────────────────────────────────────────────────
# Each rule: (family_dir, description, filename_patterns)
# Order matters — first match wins.

CATEGORIES: list[tuple[str, str, list[str]]] = [
    # Fractionation family (huge — 55+ scripts)
    ("fractionation", "Fractionation & bean-period analysis", [
        r"e_frac_\d+",
    ]),

    # Grille / turning grille / Cardan
    ("grille", "Grille, turning grille, and Cardan aperture attacks", [
        r"e_grille_\d+", r"blitz_grille_", r"blitz_k3_grille",
        r"blitz_csp_grille", r"grille_", r"e_unscramble_",
        r"e_mengen_grille", r"e_s_70_turning", r"e_s_72_grille",
        r"e_s_104_turning", r"e_audit_04_cardan",
        r"e_tableau_reflow_grille",
    ]),

    # Columnar transposition
    ("transposition/columnar", "Columnar transposition attacks", [
        r"e_grid31_", r"e_k4_keyed_columnar", r"e_k4_keyword_double",
        r"e_k4_simple_columnar", r"e_col_pure", r"e_columnar_gap",
        r"e_s_06_double_columnar", r"e_s_19_double_columnar",
        r"e_s_33_double_columnar", r"e_s_33b_mixed_double",
        r"e_s_53_keyword_columnar", r"e_s_101_statistical_trans",
        r"e_s_108_column_stat", r"e_s_109_top_ordering",
        r"e_s_133_width9", r"e_s_133b_width9",
        r"e_rerun_03_columnar", r"e_egypt_01_columnar",
        r"e_k4_double_columnar", r"agent_k4_columnar",
        r"e_w9_poly_01_columnar", r"e_w9_poly_01b",
        r"e_s_81_ka_tableau_columnar", r"e_s_83_autokey_columnar",
        r"e_s_84_polynomial_key_columnar", r"e_s_93_autokey_columnar",
        r"e_frac_46_double_columnar",  # cross-listed
    ]),

    # Other transposition (route, strip, rail, scytale, etc.)
    ("transposition/other", "Non-columnar transposition attacks", [
        r"e_s_02_stride", r"e_s_07_sa_perm", r"e_s_12_reading",
        r"e_s_22_amsco", r"e_s_39_myszkowski", r"e_s_55_grid_route",
        r"e_s_88_redefence", r"e_route_definitive",
        r"e_novel_01_route", r"blitz_strip_", r"e_audit_02_strip",
        r"e_audit_05_scytale", r"e_ref_02_strip",
        r"e_solve_13_grid_routes", r"k4_reading_orders",
        r"e_s_03_missing_char_routes", r"e_s_04_missing_char_struct",
        r"e_frac_25_transposition_entropy",
        r"e_frac_32_simple_transposition", r"e_frac_47_myszkowski",
        r"e_frac_48_amsco", r"e_team_physical_trans",
        r"e_solve_05_key_trans", r"e_solve_12_keystream_trans",
        r"e_solve_16_encrypt_trans",
    ]),

    # Polyalphabetic / Vigenère / Beaufort / autokey
    ("polyalphabetic", "Vigenère, Beaufort, autokey, and polyalphabetic", [
        r"e_poly_\d+", r"e06_autokey", r"e_autokey_",
        r"e_s_64_autokey", r"e_s_69_pt_autokey",
        r"e_s_69b_autokey", r"e_s_85_autokey",
        r"e_s_89_progressive", r"e_s_96_multiwidth_autokey",
        r"e_solve_07_beaufort", r"e_solve_14_beaufort",
        r"e_solve_20_autokey", r"e_solve_21_mixed_variant",
        r"e_extend_xor_autokey", r"e_hybrid_03_complete_columnar_vig",
        r"e_frac_17_beaufort", r"e_frac_23_beaufort",
        r"e_chart_02_autokey", r"e_s_56_affine_poly",
        r"e_s_100_porta", r"e_kasiski_",
    ]),

    # Running key
    ("running_key", "Running key and book cipher attacks", [
        r"e_runkey_", r"e_s_11_running_key", r"e_s_31_carter_running",
        r"e_s_51_dual_running", r"e_s_52_carter_columnar_running",
        r"e_s_66_themed_running", r"e_s_98_k123_running",
        r"e_s_103_thematic_running", r"e_s_135_berlin_wall_running",
        r"e_s_136_great_big_story", r"e_frac_24_running_key",
        r"e_frac_39_running_key", r"e_frac_49_running_key",
        r"e_frac_50_running_key", r"e_frac_51_english_key",
        r"e_frac_54_mono_running", r"e_chart_01_running",
        r"e_cfm_01_running_key", r"e_cfm_02_mono_running",
        r"e_novel_02_book", r"e_team_book_cipher",
        r"e_antipodes_04_sculpture_running",
        r"e_wtz_00_cities_runkey", r"exp_lecarre_rk",
        r"k4_running_key",
    ]),

    # Substitution (mono, affine, atbash, hill, bifid, trifid)
    ("substitution", "Monoalphabetic, affine, Hill, bifid, trifid", [
        r"e_affine_mono", r"e_atbash_", r"e04_hill",
        r"e_s_09_bifid", r"e_s_37_mixed_alpha",
        r"e_s_41_hill_trans", r"e_s_42_bifid", r"e_s_42b_trifid",
        r"e_s_44_trifid", r"e_s_73_mixed_alphabet",
        r"e_s_77_hill_anomaly", r"e_s_80_latin_square",
        r"e_s_99_mono_constraint", r"e_s_107_shifted_mixed",
        r"e_mono_sa_sub", r"e_audit_05_hill",
        r"e_s_151_hill_w9", r"e_team_mono_trans",
        r"e_team_homo_contradiction", r"e_team_homophonic_trans",
        r"e_team_targeted_homo", r"e_cfm_04_homophonic",
        r"e_freq_homophonic", r"e_frac_53_mono_inner",
        r"e_solve_17_2d_matrix", r"hill_cipher_analysis",
        r"e_antipodes_01_hill",
    ]),

    # Tableau / KA (Kryptos Alphabet)
    ("tableau", "Tableau, KA alphabet, and keyword analysis", [
        r"e_tableau_", r"e_ka_\d+", r"e_s_38_ka_tableau",
        r"e_s_76_keyword_alpha", r"e_webster_",
        r"blitz_tableau_", r"e_audit_05_tableau",
        r"e_audit_06_k3_method", r"e_audit_07_k3_running",
        r"e_bespoke_11_tableau", r"e_grille_08_tableau",
        r"e_grille_11_tableau", r"e_grille_19_tableau",
        r"e_chart_03_misspelling_tableau", r"e_chart_03b_reduced",
        r"e_antipodes_06_tableau",
    ]),

    # YAR (Yet Another Reconstruction)
    ("yar", "YAR family — grille reconstruction and variants", [
        r"yar_", r"e_yar_", r"e_audit_05_yar",
        r"e_antipodes_07_yar", r"e_s_87_kryptos_key_arbtrans",
    ]),

    # Blitz campaign (general brute-force sweeps)
    ("blitz", "Blitz campaign — fast brute-force sweeps", [
        r"blitz_",
    ]),

    # Berlin / Weltzeituhr / clock themed
    ("thematic/berlin_clock", "Berlin clock, Weltzeituhr, and DDR-era keys", [
        r"e03_berlin", r"e_novel_04_berlin", r"e_s_122_berlin",
        r"e_s_127_weltzeituhr", r"e_s_128_weltzeituhr",
        r"e_s_134_weltzeituhr", r"e_s_139_berlin",
        r"e_s_142_weltzeituhr", r"e_s_153_berlin",
        r"e_audit_03_weltzeituhr", r"e_team_weltzeituhr",
    ]),

    # Sculpture / physical / installation
    ("thematic/sculpture_physical", "Physical sculpture, installation, and coordinate keys", [
        r"e_s_74_sculpture", r"e_s_110_k5_position",
        r"e_s_117_coordinate", r"e_s_32_compass",
        r"e_s_60_coordinate", r"e_s_123_compass",
        r"e_explorer_06_physical", r"e_grille_12_installation",
        r"e_split_00_installation", r"e_antipodes_10_coordinate",
        r"e_solve_19_2d_keyword",
    ]),

    # Crib / plaintext analysis
    ("crib_analysis", "Crib dragging, plaintext reconstruction, constraint solving", [
        r"e_s_14_crib", r"e_s_75_extended_cribs",
        r"e_s_91_plaintext_ext", r"e_s_125_positional",
        r"e_s_130_checkpoint", r"e_s_131_point_crib",
        r"e_s_137_point_crib", r"e_s_138_point_sa",
        r"e_s_140_secret_reminder", r"e_s_141_point_end",
        r"e_s_20_constraint", r"e_s_121_constraint",
        r"e_s_149_anomaly_concept", r"e_atbash_03_crib",
        r"e_solve_06_crib", r"e_audit_01_crib",
        r"e_frac_18_crib", r"e_frac_29_w6w8_crib",
        r"e_frac_30_w10_w15_crib",
        r"blitz_constraint_solver", r"blitz_variable_cribs",
        r"blitz_plaintext_arch", r"k4_plaintext_",
        r"k4_whats_the_point", r"e_team_whats_the_point",
    ]),

    # Solve / novel / marathon (general attack campaigns)
    ("campaigns", "Multi-vector campaign scripts and novel attack ideas", [
        r"e_solve_\d+", r"e_novel_\d+", r"e_marathon_",
        r"e_review_model", r"e_rerun_\d+",
        r"k4_novel_attacks", r"k4_deep_structure",
        r"k4_dual_sa", r"k4_two_layer",
        r"e_s_86_three_layer", r"e_s_143_progressive",
        r"e_s_154_progressive",
    ]),

    # Statistical / frequency / information-theoretic
    ("statistical", "Statistical analysis, frequency, IC, entropy", [
        r"e_stat_\d+", r"e_freq_equiv", r"e_frac_13_ic",
        r"e_frac_14_autocorrelation", r"e_frac_44_information",
        r"e_s_25_ct_structural", r"e_s_132_regression",
        r"e_chart_08_noise", r"card_cipher_stats",
    ]),

    # K3 method / K1-K3 continuity
    ("k3_continuity", "K1-K3 method applied to K4, cross-section analysis", [
        r"e_s_58_k3_variant", r"e_s_63_k3_variants",
        r"e_s_106_k3_outer", r"e_s_119_k3_grid",
        r"e_s_78_reverse_eng", r"e_s_79_same_ct",
        r"e_s_105_self_key", r"e_hybrid_04_reverse_k3",
        r"e_antipodes_03_k3k4", r"e_cfm_07_k3_rotational",
        r"k3_ct_pt_audit", r"solve_k1_from_k0",
    ]),

    # CFM (cipher family modeling)
    ("cfm", "Cipher family modeling and constraint-based elimination", [
        r"e_cfm_\d+",
    ]),

    # Antipodes
    ("antipodes", "Antipodes series — paired/complementary attacks", [
        r"e_antipodes_\d+",
    ]),

    # Chart / bespoke / exploration
    ("exploration", "Exploratory analysis, bespoke methods, chart series", [
        r"e_chart_\d+", r"e_bespoke_\d+", r"e_explorer_\d+",
        r"e_compose_\d+",
    ]),

    # Team collaboration scripts
    ("team", "Team-sourced attack ideas and collaborative scripts", [
        r"e_team_",
    ]),

    # Morse / encoding transforms
    ("encoding", "Morse code, encoding transforms, extraction patterns", [
        r"e01_morse", r"e02_misspelling", r"e_s_112_morse",
        r"e_s_144_morse", r"e_s_17_extraction",
        r"e_chart_04_morse", r"e_misspelling_ct",
        r"e_audit_08_delimiter",
    ]),

    # Infrastructure / utilities / harness
    ("_infra", "Infrastructure, harnesses, validators, corpus tools", [
        r"kbot_harness", r"corpus_scanner", r"build_experiment_ledger",
        r"e_validator_\d+", r"e_ledger_\d+", r"vm_capability_report",
        r"dragnet_v4", r"e_sa_assault", r"e_sa_constrained",
        r"k4_sa_plaintext", r"k4_word_search", r"k4_algebraic",
        r"k4_clock_cipher", r"k4_reverse_engine",
    ]),
]

# Catch-all for anything that doesn't match
UNCATEGORIZED_DIR = "_uncategorized"


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class ScriptEntry:
    filename: str
    family: str
    subfolder: str
    description: str
    status: str = "unknown"  # unknown | active | exhausted | promising | superseded
    line_count: int = 0
    has_docstring: bool = False


# ── Categorization engine ────────────────────────────────────────────────────

def categorize(filename: str) -> tuple[str, str]:
    """Return (subfolder, family_description) for a filename."""
    stem = Path(filename).stem
    for subfolder, description, patterns in CATEGORIES:
        for pat in patterns:
            if re.match(pat, stem):
                return subfolder, description
    return UNCATEGORIZED_DIR, "Uncategorized — needs manual review"


def extract_header_info(filepath: Path) -> tuple[str, str]:
    """
    Pull description and status from a script's docstring or header comments.
    Returns (description, status).
    """
    description = ""
    status = "unknown"
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                lines.append(line)
                if i > 30:  # Only scan first 30 lines
                    break

        text = "".join(lines)

        # Try triple-quote docstring
        match = re.search(r'"""(.+?)"""', text, re.DOTALL)
        if not match:
            match = re.search(r"'''(.+?)'''", text, re.DOTALL)
        if match:
            doc = match.group(1).strip()
            # First line of docstring as description
            description = doc.split("\n")[0].strip()

        # Fallback: first comment line
        if not description:
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("#") and not stripped.startswith("#!"):
                    description = stripped.lstrip("# ").strip()
                    if len(description) > 10:
                        break

        # Look for status markers
        status_match = re.search(
            r"Status:\s*(exhausted|active|promising|superseded|unknown)",
            text, re.IGNORECASE
        )
        if status_match:
            status = status_match.group(1).lower()

    except (OSError, UnicodeDecodeError):
        pass

    return description[:200], status  # Truncate long descriptions


def count_lines(filepath: Path) -> int:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


# ── Main logic ───────────────────────────────────────────────────────────────

def scan_scripts(script_dir: Path) -> list[ScriptEntry]:
    """Scan all .py files and categorize them."""
    entries = []
    for f in sorted(script_dir.glob("*.py")):
        subfolder, family_desc = categorize(f.name)
        desc, status = extract_header_info(f)
        lc = count_lines(f)
        entries.append(ScriptEntry(
            filename=f.name,
            family=family_desc,
            subfolder=subfolder,
            description=desc or "(no description)",
            status=status,
            line_count=lc,
            has_docstring=bool(desc and desc != "(no description)"),
        ))
    return entries


def write_manifest(entries: list[ScriptEntry], output_dir: Path) -> None:
    """Write MANIFEST.tsv — the machine-readable index for Claude Code."""
    manifest_path = output_dir / "MANIFEST.tsv"
    with open(manifest_path, "w") as f:
        f.write("path\tfamily\tstatus\tlines\tdescription\n")
        for e in entries:
            rel_path = f"{e.subfolder}/{e.filename}" if e.subfolder != "." else e.filename
            f.write(f"{rel_path}\t{e.family}\t{e.status}\t{e.line_count}\t{e.description}\n")
    print(f"  Written: {manifest_path} ({len(entries)} entries)")


def write_exhaustion_log(entries: list[ScriptEntry], output_dir: Path) -> None:
    """Write EXHAUSTION.json — tracks attack vector status."""
    log: dict[str, dict] = {}
    for e in entries:
        key = Path(e.filename).stem
        log[key] = {
            "family": e.subfolder,
            "status": e.status,
            "lines": e.line_count,
            "description": e.description,
        }
    path = output_dir / "EXHAUSTION.json"
    with open(path, "w") as f:
        json.dump(log, f, indent=2)
    print(f"  Written: {path}")


def write_summary(entries: list[ScriptEntry]) -> None:
    """Print a human-readable summary."""
    from collections import Counter
    folder_counts = Counter(e.subfolder for e in entries)
    status_counts = Counter(e.status for e in entries)
    undocumented = sum(1 for e in entries if not e.has_docstring)

    print("\n" + "=" * 60)
    print("  CATEGORIZATION SUMMARY")
    print("=" * 60)

    print(f"\n  Total scripts: {len(entries)}")
    print(f"  Undocumented:  {undocumented} ({undocumented*100//len(entries)}%)")

    print("\n  By family:")
    for folder, count in folder_counts.most_common():
        print(f"    {folder:40s}  {count:4d}")

    print("\n  By status:")
    for status, count in status_counts.most_common():
        print(f"    {status:15s}  {count:4d}")


def dry_run(entries: list[ScriptEntry], script_dir: Path) -> None:
    """Show what would happen without moving anything."""
    print("\n  DRY RUN — proposed moves:")
    print("  (use --execute to actually move files)\n")

    from collections import defaultdict
    by_folder: dict[str, list[str]] = defaultdict(list)
    for e in entries:
        by_folder[e.subfolder].append(e.filename)

    for folder in sorted(by_folder.keys()):
        files = by_folder[folder]
        print(f"  {folder}/ ({len(files)} scripts)")
        for fn in files[:3]:
            print(f"    {fn}")
        if len(files) > 3:
            print(f"    ... and {len(files) - 3} more")
        print()


def execute_move(entries: list[ScriptEntry], script_dir: Path) -> None:
    """Actually move files into subdirectories."""
    log_lines = []
    timestamp = datetime.now().isoformat()

    for e in entries:
        src = script_dir / e.filename
        dest_dir = script_dir / e.subfolder
        dest = dest_dir / e.filename

        if not src.exists():
            continue

        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        log_lines.append(f"{timestamp}  {e.filename}  ->  {e.subfolder}/{e.filename}")

    log_path = script_dir / "migration.log"
    with open(log_path, "w") as f:
        f.write("\n".join(log_lines))
    print(f"\n  Moved {len(log_lines)} files. Log: {log_path}")


def write_claude_md_snippet(entries: list[ScriptEntry], output_dir: Path) -> None:
    """Generate a CLAUDE.md snippet for the scripts directory."""
    from collections import Counter
    folder_counts = Counter(e.subfolder for e in entries)

    snippet = """## Scripts Directory Structure

### How to navigate
- Read `MANIFEST.tsv` before exploring individual scripts
- Check `EXHAUSTION.json` before running any attack to avoid duplicating work
- Each subdirectory has a specific cipher family focus

### Directory layout
"""
    for folder, count in folder_counts.most_common():
        # Find the family description
        desc = next((e.family for e in entries if e.subfolder == folder), "")
        snippet += f"- `{folder}/` ({count} scripts) — {desc}\n"

    snippet += """
### Script contract
Every attack script should return `list[tuple[float, str, str]]`:
- float: fitness score (quadgram default)
- str: candidate plaintext
- str: method description

### Before adding a new script
1. Check MANIFEST.tsv for existing coverage of the cipher family
2. Check EXHAUSTION.json for parameter ranges already tested
3. Place in the correct subdirectory by family
4. Add a docstring header with: Cipher, Family, Status, Keyspace
"""
    path = output_dir / "CLAUDE_SCRIPTS_SNIPPET.md"
    with open(path, "w") as f:
        f.write(snippet)
    print(f"  Written: {path}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Organize KryptosBot scripts")
    parser.add_argument("script_dir", type=Path, help="Path to scripts directory")
    parser.add_argument("--execute", action="store_true",
                        help="Actually move files (default is dry run)")
    parser.add_argument("--manifest-only", action="store_true",
                        help="Only generate manifest, don't propose moves")
    args = parser.parse_args()

    script_dir = args.script_dir.resolve()
    if not script_dir.is_dir():
        print(f"Error: {script_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {script_dir} ...")
    entries = scan_scripts(script_dir)

    if not entries:
        print("No .py files found.")
        sys.exit(0)

    write_summary(entries)
    write_manifest(entries, script_dir)
    write_exhaustion_log(entries, script_dir)
    write_claude_md_snippet(entries, script_dir)

    if args.manifest_only:
        print("\n  Manifest-only mode — no file moves proposed.")
    elif args.execute:
        confirm = input("\n  This will move files. Type 'yes' to confirm: ")
        if confirm.strip().lower() == "yes":
            execute_move(entries, script_dir)
        else:
            print("  Aborted.")
    else:
        dry_run(entries, script_dir)


if __name__ == "__main__":
    main()
