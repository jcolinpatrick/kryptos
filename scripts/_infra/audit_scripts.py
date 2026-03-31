#!/usr/bin/env python3
"""
Script corpus audit tool for the KryptosBot project.

Classifies every script in scripts/ into tiers A-E based on structural
compliance, research value, and comment quality. Produces human-readable
and machine-readable reports.

Usage:
    PYTHONPATH=src python3 scripts/_infra/audit_scripts.py --summary
    PYTHONPATH=src python3 scripts/_infra/audit_scripts.py --report
    PYTHONPATH=src python3 scripts/_infra/audit_scripts.py --report --json
    PYTHONPATH=src python3 scripts/_infra/audit_scripts.py --fix --tier C --dry-run
    PYTHONPATH=src python3 scripts/_infra/audit_scripts.py --fix --tier C --apply
    PYTHONPATH=src python3 scripts/_infra/audit_scripts.py --reclassify

See docs/SCRIPT_RIGOR_STANDARD.md for tier definitions.
"""
import argparse
import csv
import io
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import date
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from header import parse_header, has_standard_header, has_attack_function

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPTS_DIR = os.path.join(_ROOT, "scripts")
RESULTS_DIR = os.path.join(_ROOT, "results")
EXHAUSTION_LOG = os.path.join(_ROOT, "exhaustion_log.json")

# Directories with special classification rules
INFRA_DIRS = {"_infra", "lib"}
TEMPLATE_DIRS = {"examples"}
CAMPAIGN_DIRS = {"campaigns"}

# Overclaim patterns — scanned in docstrings and comments only
OVERCLAIM_PATTERNS = [
    (r"\bstrong evidence\b", "strong evidence"),
    (r"\bindependently confirms\b", "independently confirms"),
    (r"\bhidden signature\b", "hidden signature"),
    (r"\balmost certainly\b", "almost certainly"),
    (r"\bwe believe\b", "we believe"),
    (r"\bremarkable\b", "remarkable"),
    (r"\bstriking\b", "striking"),
    (r"\belegant\b", "elegant"),
]

# These patterns are only overclaims if NOT in an elimination context
CONTEXT_SENSITIVE_PATTERNS = [
    (r"\bconfirms\b", "confirms", r"(impossible|eliminated|disproved|structurally|Ed Scheidt|Sanborn)"),
    (r"\bproves\b", "proves", r"(impossible|eliminated|cannot|structurally)"),
]

# Reclassification keywords for _uncategorized scripts
FAMILY_KEYWORDS = {
    "substitution": r"vigen[eè]re|beaufort|substitut|caesar|rot[\-\s]?\d|monoalpha|hill\s+cipher|affine\s+cipher",
    "transposition": r"columnar|transposi|permut|rail\s*fence|route\s+cipher|myszkowski|amsco",
    "grille": r"grille|cardan|turning|overlay|mask\s+(position|extract)",
    "running_key": r"running.key|book.cipher|running_key",
    "fractionation": r"bifid|trifid|playfair|four.square|two.square|adfg[vx]|polybius",
    "novel": r"\bvic\b|rs44|wheatstone|chaocipher|enigma|gromark",
    "encoding": r"morse|binary|encod|bacon|ascii",
    "stego_mechanism": r"\bnull\b|stego|palette|filler",
    "statistical": r"statist|monte.carlo|significance|p[\-_]value|permutation.test",
    "polyalphabetic": r"kasiski|period\s+detect|autokey|progressive.key",
    "analysis": r"analys[ie]s|forensic|audit|review|meta[\-_]analys",
}

DEPRECATION_BANNER = """\
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md
"""

WARNING_BANNER = """\
# WARNING: This script's comments or methodology may overclaim.
# Results require independent validation before use.
# See docs/SCRIPT_RIGOR_STANDARD.md
"""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ScriptAudit:
    path: str
    rel_path: str = ""
    tier: str = ""
    score: int = 0
    category: str = "research"  # research | infrastructure | template
    has_standard_header: bool = False
    imports_constants: bool = False
    has_attack_fn: bool = False
    has_result_file: bool = False
    exhaustion_status: str = ""
    overclaim_words: list = field(default_factory=list)
    hardcodes_ct: bool = False
    hardcodes_nulls: bool = False
    line_count: int = 0
    code_lines: int = 0
    in_uncategorized: bool = False
    in_root: bool = False
    has_docstring: bool = False
    connected_to_rq: bool = False
    family: str = ""
    recommended_action: str = "none"
    rationale: str = ""

    def to_dict(self):
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_exhaustion_log() -> dict:
    """Load exhaustion_log.json, return dict keyed by script ID."""
    if not os.path.exists(EXHAUSTION_LOG):
        return {}
    with open(EXHAUSTION_LOG) as f:
        return json.load(f)


def load_result_ids() -> set:
    """Scan results/*.json and return set of experiment IDs."""
    ids = set()
    if not os.path.isdir(RESULTS_DIR):
        return ids
    for entry in os.listdir(RESULTS_DIR):
        path = os.path.join(RESULTS_DIR, entry)
        if os.path.isfile(path) and entry.endswith(".json"):
            # ID from filename
            ids.add(entry.replace(".json", "").lower().replace("-", "_"))
            # Also try to read experiment field
            try:
                with open(path) as f:
                    data = json.load(f)
                exp = data.get("experiment", data.get("experiment_id", ""))
                if exp:
                    ids.add(exp.lower().replace("-", "_"))
            except Exception:
                pass
        elif os.path.isdir(path):
            sub = os.path.join(path, "results.json")
            if os.path.isfile(sub):
                ids.add(entry.lower().replace("-", "_"))
    return ids


def find_all_scripts() -> list:
    """Find all .py files under scripts/."""
    scripts = []
    for dirpath, _, filenames in os.walk(SCRIPTS_DIR):
        for fname in sorted(filenames):
            if fname.endswith(".py") and not fname.startswith("__"):
                scripts.append(os.path.join(dirpath, fname))
    return scripts


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def extract_comments_and_docstrings(text: str) -> str:
    """Extract docstrings and comment lines for overclaim scanning."""
    parts = []
    # Docstrings
    for m in re.finditer(r'"""(.*?)"""', text, re.DOTALL):
        parts.append(m.group(1))
    for m in re.finditer(r"'''(.*?)'''", text, re.DOTALL):
        parts.append(m.group(1))
    # Comment lines
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):
            parts.append(stripped)
    return "\n".join(parts)


def detect_overclaims(text: str) -> list:
    """Detect overclaim language in docstrings/comments. Returns list of matched words."""
    comment_text = extract_comments_and_docstrings(text)
    lower = comment_text.lower()
    found = []

    for pattern, label in OVERCLAIM_PATTERNS:
        if re.search(pattern, lower):
            found.append(label)

    for pattern, label, negation in CONTEXT_SENSITIVE_PATTERNS:
        matches = list(re.finditer(pattern, lower))
        for m in matches:
            # Check 60 chars around the match for negation context
            start = max(0, m.start() - 60)
            end = min(len(lower), m.end() + 60)
            context = lower[start:end]
            if not re.search(negation, context, re.IGNORECASE):
                found.append(label)
                break  # Count once per pattern

    return found


def check_imports_constants(text: str) -> bool:
    """Check if script imports from kryptos.kernel.constants."""
    return bool(re.search(r"from\s+kryptos\.kernel\.constants\s+import", text))


def check_hardcodes_ct(text: str) -> bool:
    """Check if script hardcodes the K4 ciphertext."""
    # Look for the CT string outside of comments/docstrings
    # Simple heuristic: OBKRUOX appears as a string literal in code
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "OBKRUOX" in stripped and ("=" in stripped or "'" in stripped or '"' in stripped):
            return True
    return False


def check_hardcodes_nulls(text: str) -> bool:
    """Check if script hardcodes null positions instead of importing."""
    # Look for list literals containing typical null position values
    # that aren't importing CONSENSUS_NULL_POSITIONS
    if "CONSENSUS_NULL_POSITIONS" in text:
        return False
    # Heuristic: a list literal with numbers like [4, 7, 13, ...] near "null"
    if re.search(r"null.*positions?\s*=\s*\[[\d,\s]+\]", text, re.IGNORECASE):
        return True
    if re.search(r"NULL.*=\s*\[[\d,\s]{20,}\]", text):
        return True
    return False


def check_connected_to_rq(text: str) -> bool:
    """Check if script references a research question."""
    return bool(re.search(r"RQ-\d+", text))


def count_code_lines(text: str) -> int:
    """Count non-blank, non-comment lines."""
    count = 0
    in_docstring = False
    for line in text.split("\n"):
        stripped = line.strip()
        if '"""' in stripped or "'''" in stripped:
            in_docstring = not in_docstring
            continue
        if in_docstring:
            continue
        if stripped and not stripped.startswith("#"):
            count += 1
    return count


def script_id_from_path(path: str) -> str:
    """Derive a script ID from its file path for matching against exhaustion log."""
    fname = os.path.basename(path).replace(".py", "")
    return fname.lower().replace("-", "_")


def get_subdir(path: str) -> str:
    """Get the immediate subdirectory under scripts/."""
    rel = os.path.relpath(path, SCRIPTS_DIR)
    parts = rel.split(os.sep)
    if len(parts) > 1:
        return parts[0]
    return ""  # Root level


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_script(audit: ScriptAudit) -> int:
    """Compute a 0-100 score for a script based on the rubric."""
    score = 0

    # --- Structure & Compliance (35 pts) ---
    if audit.has_standard_header:
        score += 15
    elif audit.has_docstring:
        score += 5

    if audit.imports_constants:
        score += 10

    if audit.has_attack_fn:
        score += 10

    if audit.hardcodes_ct:
        score -= 10

    # --- Research Value (35 pts) ---
    if audit.has_result_file:
        score += 15

    if audit.exhaustion_status == "exhausted":
        score += 10
    elif audit.exhaustion_status == "active":
        score += 5

    if audit.connected_to_rq:
        score += 5

    if audit.in_uncategorized:
        score -= 5

    # --- Comment Quality (20 pts) ---
    if audit.has_docstring:
        score += 10

    # Mechanical comments bonus (heuristic: has # comments explaining code)
    score += 5  # Give benefit of the doubt

    if not audit.overclaim_words:
        score += 5
    else:
        penalty = min(len(audit.overclaim_words) * 5, 15)
        score -= penalty

    # --- Additional penalties ---
    if audit.code_lines < 20:
        score -= 10

    if audit.hardcodes_nulls:
        score -= 5

    if audit.in_root:
        score -= 5

    return max(0, min(100, score))


def assign_tier(score: int) -> str:
    if score >= 75:
        return "A"
    elif score >= 55:
        return "B"
    elif score >= 35:
        return "C"
    elif score >= 15:
        return "D"
    else:
        return "E"


def determine_action(audit: ScriptAudit) -> str:
    if audit.category != "research":
        return "none"
    if audit.tier == "A":
        return "none"
    if audit.tier == "B":
        if not audit.has_standard_header:
            return "fix-header"
        return "none"
    if audit.tier == "C":
        return "add-deprecation"
    if audit.tier == "D":
        return "add-warning"
    if audit.tier == "E":
        return "review-for-deletion"
    return "none"


def build_rationale(audit: ScriptAudit) -> str:
    parts = []
    if audit.category == "infrastructure":
        return "Infrastructure script (not tiered for research value)"
    if audit.category == "template":
        return "Template/example script"

    if audit.has_standard_header:
        parts.append("standard header")
    else:
        parts.append("legacy/missing header")

    if audit.has_result_file:
        parts.append("has results")
    if audit.exhaustion_status:
        parts.append(f"status:{audit.exhaustion_status}")
    if audit.overclaim_words:
        parts.append(f"overclaims:{','.join(audit.overclaim_words[:3])}")
    if audit.hardcodes_ct:
        parts.append("hardcodes CT")
    if audit.code_lines < 20:
        parts.append("stub")
    if audit.in_uncategorized:
        parts.append("uncategorized")

    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Main audit
# ---------------------------------------------------------------------------

def audit_corpus() -> list:
    """Run the full audit on all scripts. Returns list of ScriptAudit objects."""
    exhaustion = load_exhaustion_log()
    result_ids = load_result_ids()
    scripts = find_all_scripts()

    # Build exhaustion lookup by normalized ID
    exh_lookup = {}
    for key, val in exhaustion.items():
        norm = key.lower().replace("-", "_")
        exh_lookup[norm] = val

    audits = []

    for path in scripts:
        rel = os.path.relpath(path, _ROOT)
        subdir = get_subdir(path)
        sid = script_id_from_path(path)

        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        audit = ScriptAudit(path=path, rel_path=rel)
        audit.line_count = len(text.split("\n"))
        audit.code_lines = count_code_lines(text)

        # Classify special directories
        if subdir in INFRA_DIRS:
            audit.category = "infrastructure"
        elif subdir in TEMPLATE_DIRS:
            audit.category = "template"

        # Structural checks
        audit.has_standard_header = has_standard_header(path)
        audit.has_attack_fn = has_attack_function(path)
        audit.imports_constants = check_imports_constants(text)
        audit.hardcodes_ct = check_hardcodes_ct(text)
        audit.hardcodes_nulls = check_hardcodes_nulls(text)
        audit.has_docstring = bool(re.search(r'"""', text[:3000]))
        audit.connected_to_rq = check_connected_to_rq(text)

        # Location signals
        audit.in_uncategorized = subdir == "_uncategorized"
        audit.in_root = subdir == ""

        # Exhaustion log
        exh = exh_lookup.get(sid)
        if exh:
            audit.exhaustion_status = exh.get("status", "")
            audit.family = exh.get("family", "")

        # Result file
        audit.has_result_file = sid in result_ids

        # Overclaim detection
        audit.overclaim_words = detect_overclaims(text)

        # Score and tier
        if audit.category == "infrastructure":
            audit.tier = "infra"
            audit.score = -1
        elif audit.category == "template":
            audit.tier = "A"
            audit.score = 100
        else:
            # Campaign scripts don't need attack()
            if subdir in CAMPAIGN_DIRS:
                # Temporarily pretend they have attack() for scoring
                saved = audit.has_attack_fn
                audit.has_attack_fn = True
                audit.score = score_script(audit)
                audit.has_attack_fn = saved
            else:
                audit.score = score_script(audit)
            audit.tier = assign_tier(audit.score)

        audit.recommended_action = determine_action(audit)
        audit.rationale = build_rationale(audit)
        audits.append(audit)

    return audits


# ---------------------------------------------------------------------------
# Reclassification
# ---------------------------------------------------------------------------

def propose_reclassification(audits: list) -> list:
    """For _uncategorized scripts, propose family assignments."""
    proposals = []
    for audit in audits:
        if not audit.in_uncategorized:
            continue
        try:
            text = Path(audit.path).read_text(encoding="utf-8", errors="replace")[:5000].lower()
        except Exception:
            continue

        best_family = None
        best_count = 0
        for family, pattern in FAMILY_KEYWORDS.items():
            matches = len(re.findall(pattern, text, re.IGNORECASE))
            if matches > best_count:
                best_count = matches
                best_family = family

        if best_family and best_count >= 2:
            proposals.append({
                "source": audit.rel_path,
                "proposed_family": best_family,
                "confidence": "high" if best_count >= 4 else "medium",
                "match_count": best_count,
            })
        elif best_family:
            proposals.append({
                "source": audit.rel_path,
                "proposed_family": best_family,
                "confidence": "low",
                "match_count": best_count,
            })
        else:
            proposals.append({
                "source": audit.rel_path,
                "proposed_family": "unknown",
                "confidence": "none",
                "match_count": 0,
            })

    return proposals


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_summary(audits: list):
    """Print aggregate statistics to stdout."""
    tier_counts = {}
    infra_count = 0
    template_count = 0
    hardcoded_ct = 0
    uncategorized = 0
    overclaim_scripts = 0
    legacy_headers = 0

    for a in audits:
        if a.category == "infrastructure":
            infra_count += 1
        elif a.category == "template":
            template_count += 1
        else:
            tier_counts[a.tier] = tier_counts.get(a.tier, 0) + 1

        if a.hardcodes_ct:
            hardcoded_ct += 1
        if a.in_uncategorized:
            uncategorized += 1
        if a.overclaim_words:
            overclaim_scripts += 1
        if not a.has_standard_header and a.category == "research":
            legacy_headers += 1

    total = len(audits)
    research = total - infra_count - template_count

    print(f"\nScript Corpus Audit — {date.today()}")
    print("=" * 50)
    print(f"Total scripts: {total}")
    print(f"  Infrastructure: {infra_count} (not tiered)")
    print(f"  Templates: {template_count} (Tier A by definition)")
    print(f"  Research scripts: {research}")
    print()
    for tier in ["A", "B", "C", "D", "E"]:
        count = tier_counts.get(tier, 0)
        pct = count / research * 100 if research else 0
        labels = {"A": "production", "B": "exploratory", "C": "historical",
                  "D": "needs work", "E": "delete candidates"}
        print(f"  Tier {tier} ({labels[tier]}): {count:>5} ({pct:.1f}%)")

    print(f"\nTop issues:")
    print(f"  {hardcoded_ct} scripts hardcode CT (should import from constants)")
    print(f"  {uncategorized} scripts in _uncategorized/ (need proper family)")
    print(f"  {overclaim_scripts} scripts contain overclaim language")
    print(f"  {legacy_headers} research scripts have legacy (non-parseable) headers")

    # Recommended actions
    actions = {}
    for a in audits:
        if a.recommended_action != "none":
            actions[a.recommended_action] = actions.get(a.recommended_action, 0) + 1

    if actions:
        print(f"\nRecommended actions:")
        action_labels = {
            "fix-header": "Fix headers",
            "add-deprecation": "Add deprecation warning (Tier C)",
            "add-warning": "Add overclaim warning (Tier D)",
            "review-for-deletion": "Review for deletion (Tier E)",
        }
        for action, count in sorted(actions.items(), key=lambda x: -x[1]):
            label = action_labels.get(action, action)
            print(f"  {label}: {count} scripts")
    print()


def write_json_report(audits: list, output: str):
    """Write the full audit report as JSON."""
    tier_counts = {}
    for a in audits:
        key = f"tier_{a.tier}" if a.tier != "infra" else "infrastructure"
        tier_counts[key] = tier_counts.get(key, 0) + 1

    report = {
        "metadata": {
            "date": str(date.today()),
            "total_scripts": len(audits),
            "tool_version": "1.0",
        },
        "summary": tier_counts,
        "scripts": [a.to_dict() for a in audits],
    }

    with open(output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"JSON report written to: {output}")


def write_tsv_report(audits: list, output: str):
    """Write the audit report as TSV."""
    with open(output, "w", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow([
            "Path", "Tier", "Score", "Category", "Header", "Constants",
            "Attack", "Result", "ExhStatus", "Overclaims", "Lines",
            "CodeLines", "Action", "Rationale",
        ])
        for a in audits:
            writer.writerow([
                a.rel_path, a.tier, a.score, a.category,
                "standard" if a.has_standard_header else "legacy",
                "imports" if a.imports_constants else ("hardcoded" if a.hardcodes_ct else "none"),
                "yes" if a.has_attack_fn else "no",
                "yes" if a.has_result_file else "no",
                a.exhaustion_status or "n/a",
                len(a.overclaim_words),
                a.line_count, a.code_lines,
                a.recommended_action, a.rationale,
            ])
    print(f"TSV report written to: {output}")


# ---------------------------------------------------------------------------
# Fix mode
# ---------------------------------------------------------------------------

BANNERS = {
    "C": DEPRECATION_BANNER,
    "D": WARNING_BANNER,
}


def already_has_banner(text: str) -> bool:
    """Check if a file already has a deprecation or warning banner."""
    return ("DEPRECATED:" in text and "SCRIPT_RIGOR_STANDARD" in text) or \
           ("WARNING:" in text and "SCRIPT_RIGOR_STANDARD" in text)


def apply_fix(audits: list, tiers: list, dry_run: bool):
    """Apply fix operations to scripts in the specified tiers."""
    fixed = 0
    skipped = 0

    for a in audits:
        if a.tier not in tiers:
            continue
        if a.category != "research":
            continue

        banner = BANNERS.get(a.tier)
        if not banner:
            continue

        try:
            text = Path(a.path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        if already_has_banner(text):
            skipped += 1
            continue

        # Insert banner after the shebang line and first docstring
        lines = text.split("\n")
        insert_idx = 0

        # Skip shebang
        if lines and lines[0].startswith("#!"):
            insert_idx = 1

        # Skip first docstring block
        in_docstring = False
        for i in range(insert_idx, min(len(lines), 50)):
            line = lines[i].strip()
            if '"""' in line or "'''" in line:
                if in_docstring:
                    insert_idx = i + 1
                    break
                else:
                    # Check for single-line docstring
                    count = line.count('"""') + line.count("'''")
                    if count >= 2:
                        insert_idx = i + 1
                        break
                    in_docstring = True
            elif not in_docstring and line and not line.startswith("#"):
                # Hit code before finding docstring — insert after comments
                insert_idx = i
                break

        # Also skip comment-only header blocks
        while insert_idx < len(lines) and lines[insert_idx].strip().startswith("#"):
            insert_idx += 1

        new_lines = lines[:insert_idx] + [banner] + lines[insert_idx:]
        new_text = "\n".join(new_lines)

        if dry_run:
            print(f"  [DRY-RUN] Would add {a.tier} banner to: {a.rel_path}")
        else:
            with open(a.path, "w") as f:
                f.write(new_text)
            print(f"  [FIXED] Added {a.tier} banner to: {a.rel_path}")
        fixed += 1

    mode = "DRY-RUN" if dry_run else "APPLIED"
    print(f"\n{mode}: {fixed} scripts modified, {skipped} already had banners")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Script corpus audit tool")
    parser.add_argument("--summary", action="store_true", help="Print aggregate stats")
    parser.add_argument("--report", action="store_true", help="Generate full report")
    parser.add_argument("--json", action="store_true", help="Output JSON report (with --report)")
    parser.add_argument("--tsv", action="store_true", help="Output TSV report (with --report)")
    parser.add_argument("--fix", action="store_true", help="Apply fixes")
    parser.add_argument("--tier", type=str, help="Comma-separated tiers to fix (e.g., C,D)")
    parser.add_argument("--dry-run", action="store_true", help="Show what --fix would do")
    parser.add_argument("--apply", action="store_true", help="Actually apply --fix changes")
    parser.add_argument("--reclassify", action="store_true", help="Propose reclassification for _uncategorized")
    parser.add_argument("--output-dir", type=str, default=_ROOT, help="Output directory for reports")

    args = parser.parse_args()

    if not any([args.summary, args.report, args.fix, args.reclassify]):
        args.summary = True  # Default to summary

    print("Auditing script corpus...")
    audits = audit_corpus()
    print(f"  Scanned {len(audits)} scripts")

    if args.summary or args.report:
        print_summary(audits)

    if args.report:
        out_dir = args.output_dir
        if args.json or (not args.tsv):
            write_json_report(audits, os.path.join(out_dir, "audit_report.json"))
        if args.tsv or (not args.json):
            write_tsv_report(audits, os.path.join(out_dir, "audit_report.tsv"))

    if args.fix:
        if not args.tier:
            print("ERROR: --fix requires --tier (e.g., --tier C,D)")
            sys.exit(1)
        tiers = [t.strip().upper() for t in args.tier.split(",")]
        if "E" in tiers:
            print("ERROR: --fix --tier E is not supported. Deletion is manual only.")
            sys.exit(1)
        if not args.apply and not args.dry_run:
            args.dry_run = True  # Default to dry-run
            print("(Defaulting to --dry-run. Use --apply to write changes.)")
        apply_fix(audits, tiers, dry_run=not args.apply)

    if args.reclassify:
        proposals = propose_reclassification(audits)
        print(f"\nReclassification proposals for {len(proposals)} _uncategorized scripts:")
        print("-" * 70)
        by_confidence = {"high": [], "medium": [], "low": [], "none": []}
        for p in proposals:
            by_confidence[p["confidence"]].append(p)

        for conf in ["high", "medium", "low", "none"]:
            items = by_confidence[conf]
            if items:
                print(f"\n  [{conf.upper()} confidence] ({len(items)} scripts)")
                for p in items:
                    src = os.path.basename(p["source"])
                    print(f"    {src:50s} → {p['proposed_family']} ({p['match_count']} matches)")


if __name__ == "__main__":
    main()
