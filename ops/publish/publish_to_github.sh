#!/usr/bin/env bash
# publish_to_github.sh — publish public-safe local commits to origin (GitHub).
#
# Filters out proprietary paths (<internal>/, cross-import scripts, brain-
# construction docs) commit-by-commit, preserving research-narrative history
# while excluding IP. Builds a temporary branch '_publish' on top of
# origin/main and pushes it forward-only — no force-push, no history
# rewrite of public history.
#
# Usage:
#   ops/publish/publish_to_github.sh             # interactive: dry-run, then prompt
#   ops/publish/publish_to_github.sh --dry-run   # build _publish, do not push
#   ops/publish/publish_to_github.sh --push      # build and push without prompt
#
# Companion: .githooks/pre-push enforces the same boundary at push time so
# any direct `git push origin main` is blocked. core.hooksPath must be set
# to '.githooks' for the hook to fire.

set -euo pipefail

MODE=interactive
case "${1:-}" in
  --dry-run) MODE=dry_run ;;
  --push)    MODE=push ;;
  "")        MODE=interactive ;;
  *)         echo "Unknown arg: $1" >&2; exit 2 ;;
esac

# ── Forbidden paths (private — never reaches GitHub) ─────────────────────
# Negative pathspecs for `git diff -- ${PUBLIC_PATHSPECS[@]}`.
PUBLIC_PATHSPECS=(
  '.'
  ':!<internal>/'
  ':!scripts/_infra/calibrate_null_baselines.py'
  ':!scripts/_infra/calibrate_null_baselines_r2_4.py'
  ':!tests/test_polybius_scorer.py'
  ':!tests/test_internal_oracle_hardening.py'
  ':!tests/test_historical_eliminations.py'
  ':!<internal>phase_*'
  ':!<internal>'
  ':!<internal>/'
  ':!<internal>/phase_R3*'
  ':!<internal>/CLAUDE_CODE_BRIEF_*'
  ':!<internal>/CURRENT_WORKER_PATH.md'
  ':!<internal>/DSL_CUTOVER_CONTRACT.md'
  ':!<internal>/SUMMARY.md'
)

FORBIDDEN_REGEX='^(<internal>/|scripts/_infra/calibrate_null_baselines|tests/test_polybius_scorer\.py$|tests/test_internal_oracle_hardening\.py$|tests/test_historical_eliminations\.py$|<internal>phase_|<internal>/|<internal>/phase_R3|<internal>/CLAUDE_CODE_BRIEF|<internal>/CURRENT_WORKER_PATH|<internal>/DSL_CUTOVER_CONTRACT|<internal>/SUMMARY\.md$|<internal>SUMMARY\.md$)'

cd "$(git rev-parse --show-toplevel)"

current_branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$current_branch" != "main" ]; then
  echo "ERROR: must run from main branch (current: $current_branch)" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: working tree has uncommitted changes; commit or stash first." >&2
  exit 1
fi

echo "Fetching origin..."
git fetch origin

unpushed=$(git rev-list --count origin/main..main)
if [ "$unpushed" = "0" ]; then
  echo "Nothing to publish — main is at origin/main."
  exit 0
fi

echo "Found $unpushed unpushed commit(s) on main."
echo ""

# Build the temporary publish branch from origin/main
git branch -D _publish 2>/dev/null || true
git checkout -B _publish origin/main >/dev/null 2>&1

commits=$(git rev-list --reverse origin/main..main)
total=$(echo "$commits" | wc -l)
applied=0
skipped_empty=0
skipped_failed=0

echo "Applying commits to _publish (oldest first)..."
echo ""

for c in $commits; do
  short=$(git log -1 --format='%h' "$c")
  subject=$(git log -1 --format='%s' "$c" | head -c 76)

  # Build the public-only diff for this commit
  diff_file=$(mktemp)
  if ! git diff --binary "$c^" "$c" -- "${PUBLIC_PATHSPECS[@]}" > "$diff_file" 2>/dev/null; then
    echo "  ! $short (diff failed) — skipping: $subject" >&2
    skipped_failed=$((skipped_failed + 1))
    rm -f "$diff_file"
    continue
  fi

  if [ ! -s "$diff_file" ]; then
    # No public changes in this commit
    echo "  ⊘ $short (no public changes)  $subject"
    skipped_empty=$((skipped_empty + 1))
    rm -f "$diff_file"
    continue
  fi

  # Apply the filtered diff
  if ! git apply --index --reject --whitespace=nowarn "$diff_file" 2>/dev/null; then
    echo "  ! $short (apply failed) — skipping: $subject" >&2
    git reset --hard >/dev/null 2>&1
    skipped_failed=$((skipped_failed + 1))
    rm -f "$diff_file"
    continue
  fi
  rm -f "$diff_file"

  if git diff --cached --quiet; then
    # Apply was a no-op after filtering
    echo "  ⊘ $short (filtered to no-op)  $subject"
    skipped_empty=$((skipped_empty + 1))
    continue
  fi

  # Commit using the original commit's metadata (author, message, date)
  git commit -C "$c" --no-verify --quiet
  applied=$((applied + 1))
  echo "  ✓ $short  $subject"
done

echo ""
echo "Summary: $applied applied, $skipped_empty skipped (no public changes), $skipped_failed skipped (apply failures)"
echo ""

# Verify _publish has no forbidden paths
violations=$(git diff origin/main.._publish --name-only 2>/dev/null | grep -E "$FORBIDDEN_REGEX" || true)
if [ -n "$violations" ]; then
  echo "ERROR: _publish branch contains forbidden paths:" >&2
  echo "$violations" | sed 's/^/  /' >&2
  echo "Aborting." >&2
  git checkout main >/dev/null 2>&1
  exit 1
fi

echo "Diff vs origin/main:"
git diff origin/main.._publish --stat | tail -20
echo ""

if [ "$MODE" = "dry_run" ]; then
  echo "DRY RUN — _publish branch is built locally; not pushing."
  echo "  Review:  git log origin/main.._publish --oneline"
  echo "  Diff:    git diff origin/main.._publish"
  echo "  Push:    ops/publish/publish_to_github.sh --push"
  echo ""
  echo "Returning to main branch."
  git checkout main >/dev/null 2>&1
  exit 0
fi

if [ "$MODE" = "interactive" ]; then
  echo "Push _publish to origin/main? [y/N]"
  read -r answer
  if [ "${answer:-N}" != "y" ] && [ "${answer:-N}" != "Y" ]; then
    echo "Cancelled. _publish branch retained for inspection."
    git checkout main >/dev/null 2>&1
    exit 0
  fi
fi

# The push: pre-push hook will re-verify the boundary
echo "Pushing _publish to origin/main..."
git push origin _publish:main

# Verify origin/main has no <internal>/
echo ""
echo "Verifying origin/main..."
git fetch origin
post_violations=$(git ls-tree -r origin/main --name-only 2>/dev/null | grep -E "$FORBIDDEN_REGEX" || true)
if [ -n "$post_violations" ]; then
  echo "POST-PUSH ERROR: origin/main contains forbidden paths:" >&2
  echo "$post_violations" | head -20 | sed 's/^/  /' >&2
  exit 1
fi
echo "✓ origin/main contains 0 forbidden paths."

echo ""
echo "Restoring main branch."
git checkout main >/dev/null 2>&1

echo ""
echo "Publish complete. _publish branch retained — run 'git branch -D _publish' to clean up."
