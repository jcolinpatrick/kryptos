#!/usr/bin/env bash
# scan_content.sh — Scan files for forbidden-content patterns.
#
# Reads patterns from $PATTERNS_FILE (default: ./forbidden_content.txt next
# to this script). Each pattern is a TSV line: <regex>\t<reason>.
# Lines starting with `#` are comments.
#
# Usage:
#   scan_content.sh <file1> [<file2> ...]
#                       Scan the listed files (paths relative or absolute).
#   scan_content.sh --tree <git-tree-ish>
#                       Scan every blob reachable from <git-tree-ish>.
#   scan_content.sh --commits <range>
#                       Scan files touched by commits in the range
#                       (e.g. origin/main..HEAD). Only ADDED/MODIFIED files
#                       in their post-state are scanned; deletions skipped.
#
# Exit codes:
#   0  No matches.
#   1  At least one match found (details printed to stderr).
#   2  Usage / configuration error.
#
# Examples:
#   ops/publish/scan_content.sh CLAUDE.md docs/operations.md
#   ops/publish/scan_content.sh --tree HEAD
#   ops/publish/scan_content.sh --commits origin/main..HEAD

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERNS_FILE="${PATTERNS_FILE:-$SCRIPT_DIR/forbidden_content.txt}"

if [ ! -f "$PATTERNS_FILE" ]; then
  echo "scan_content: ERROR — patterns file not found: $PATTERNS_FILE" >&2
  exit 2
fi

mode="files"
case "${1:-}" in
  --tree)
    mode="tree"
    treeish="${2:-HEAD}"
    shift 2 || true
    ;;
  --commits)
    mode="commits"
    range="${2:-}"
    if [ -z "$range" ]; then
      echo "scan_content: ERROR — --commits requires a range argument" >&2
      exit 2
    fi
    shift 2 || true
    ;;
  --help|-h|"")
    if [ "${1:-}" = "" ]; then
      echo "scan_content: ERROR — no files specified (try --help)" >&2
      exit 2
    fi
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
    exit 0
    ;;
esac

# Files exempt from content scanning. The privacy machinery itself
# necessarily contains the patterns it blocks (the pattern file lists
# them; the scanner and publish script reference them by name in
# comments). Self-exempt these three files to prevent the scanner
# from blocking its own publication.
SCAN_EXEMPT=(
  "ops/publish/forbidden_content.txt"
  "ops/publish/scan_content.sh"
  "ops/publish/publish_to_github.sh"
)

is_scan_exempt() {
  local p="$1"
  for exempt in "${SCAN_EXEMPT[@]}"; do
    if [ "$p" = "$exempt" ]; then
      return 0
    fi
  done
  return 1
}

# Load patterns: one regex per line, with the reason kept for reporting.
patterns=()
reasons=()
while IFS=$'\t' read -r pat reason || [ -n "$pat" ]; do
  case "$pat" in
    \#*|"") continue ;;
  esac
  patterns+=("$pat")
  reasons+=("${reason:-no reason given}")
done < "$PATTERNS_FILE"

if [ "${#patterns[@]}" -eq 0 ]; then
  echo "scan_content: WARNING — no active patterns in $PATTERNS_FILE" >&2
  exit 0
fi

# Resolve which files to scan.
files_to_scan=()
case "$mode" in
  files)
    for f in "$@"; do
      [ -f "$f" ] && files_to_scan+=("$f")
    done
    ;;
  tree)
    while IFS= read -r path; do
      files_to_scan+=("$path")
    done < <(git ls-tree -r --name-only "$treeish")
    # We'll scan blob content directly via git show; track by path-only.
    ;;
  commits)
    while IFS= read -r line; do
      # name-status output: "A\tpath" / "M\tpath" / "D\tpath" / "R100\told\tnew"
      op="$(echo "$line" | cut -f1)"
      case "$op" in
        D*) continue ;;
        R*|C*) path="$(echo "$line" | cut -f3)" ;;
        *)    path="$(echo "$line" | cut -f2)" ;;
      esac
      [ -n "$path" ] && files_to_scan+=("$path")
    done < <(git log --name-status --pretty=format: "$range" 2>/dev/null \
             | sort -u | grep -v '^$' || true)
    ;;
esac

if [ "${#files_to_scan[@]}" -eq 0 ]; then
  exit 0
fi

# Scan. For tree/commits modes, read content from the git index/tree;
# for files mode, read from disk. We accumulate hits and report at the end.
violations=0
hits_summary=""

read_blob() {
  local path="$1"
  case "$mode" in
    tree)    git show "$treeish:$path" 2>/dev/null || true ;;
    commits) git show "HEAD:$path" 2>/dev/null \
              || git show "$path" 2>/dev/null \
              || cat "$path" 2>/dev/null \
              || true ;;
    files)   cat "$path" 2>/dev/null || true ;;
  esac
}

# Build a single combined regex (pat1|pat2|...|patN) for the bulk pre-check.
# This collapses N grep calls per file into 1 — critical for tree/commits
# modes which can scan 1000+ files. We only fall back to per-pattern grep
# when the bulk check fires, to attribute the hit to its reason.
combined=""
for p in "${patterns[@]}"; do
  if [ -n "$combined" ]; then
    combined="$combined|$p"
  else
    combined="$p"
  fi
done

for path in "${files_to_scan[@]}"; do
  # Self-exempt the privacy-machinery files (they necessarily contain
  # the patterns they block).
  if is_scan_exempt "$path"; then
    continue
  fi
  # Bulk pre-check: one grep call, exit-status-only (-q), with -m 1 so we
  # stop on the first match. Skip non-matching files cheaply.
  if [ "$mode" = "files" ]; then
    if ! grep -q -I -E -m 1 -- "$combined" "$path" 2>/dev/null; then
      continue
    fi
  else
    blob="$(read_blob "$path")"
    [ -z "$blob" ] && continue
    if ! printf '%s' "$blob" | grep -q -a -E -m 1 -- "$combined" 2>/dev/null; then
      continue
    fi
  fi

  # Bulk check fired. Now identify which pattern(s) matched, with line
  # numbers, so the report points at the actual proprietary terminology.
  for i in "${!patterns[@]}"; do
    pat="${patterns[$i]}"
    reason="${reasons[$i]}"
    if [ "$mode" = "files" ]; then
      matches="$(grep -m 3 -n -I -E -- "$pat" "$path" 2>/dev/null || true)"
    else
      matches="$(printf '%s' "$blob" | grep -m 3 -n -a -E -- "$pat" 2>/dev/null || true)"
    fi
    if [ -n "$matches" ]; then
      violations=$((violations + 1))
      hits_summary+="$path: $reason"$'\n'
      while IFS= read -r line; do
        hits_summary+="    L${line}"$'\n'
      done <<< "$matches"
    fi
  done
done

if [ "$violations" -gt 0 ]; then
  {
    echo ""
    echo "scan_content: BLOCKED — $violations forbidden-content match(es):"
    echo ""
    printf '%s' "$hits_summary"
    echo ""
    echo "Patterns are defined in: $PATTERNS_FILE"
    echo "To intentionally publish a flagged term, edit the file in question"
    echo "before pushing, or remove the pattern from forbidden_content.txt"
    echo "(only the operator should do this; document the change in the commit)."
    echo ""
  } >&2
  exit 1
fi

exit 0
