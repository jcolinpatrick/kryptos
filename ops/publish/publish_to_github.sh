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

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

current_branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$current_branch" != "main" ]; then
  echo "ERROR: must run from main branch (current: $current_branch)" >&2
  exit 1
fi

# Refuse if the index has STAGED changes (those would taint the cherry-picks).
# Unstaged worktree dirt (e.g., pre-existing modifications to <internal>/) is
# fine — we run the publish in an isolated git worktree.
if ! git diff --cached --quiet; then
  echo "ERROR: index has staged changes; commit or unstage before publishing." >&2
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

# Build the temporary publish in an isolated worktree so we don't touch
# the operator's working tree (which may legitimately carry uncommitted
# private-side modifications).
WORKTREE_DIR="$(mktemp -d -t kryptos-publish-XXXXXX)"
trap 'cd "$REPO_ROOT"; git worktree remove --force "$WORKTREE_DIR" 2>/dev/null || true; rm -rf "$WORKTREE_DIR"' EXIT

git branch -D _publish 2>/dev/null || true
git worktree add -B _publish "$WORKTREE_DIR" origin/main >/dev/null 2>&1
cd "$WORKTREE_DIR"

# ── Step 0: actively remove any pre-leaked forbidden paths inherited from origin/main ──
# (Past pushes may have leaked some files before this hook + script existed.)
preleak=$(git ls-tree -r HEAD --name-only 2>/dev/null | grep -E "$FORBIDDEN_REGEX" || true)
if [ -n "$preleak" ]; then
  echo "Removing pre-leaked forbidden paths from _publish base:"
  echo "$preleak" | while read -r path; do
    [ -z "$path" ] && continue
    git rm -f -- "$path" >/dev/null 2>&1 || true
    echo "  - $path"
  done
  if ! git diff --cached --quiet; then
    git commit --no-verify --quiet -m "publish: remove pre-leaked proprietary paths

Files leaked in prior pushes are removed from public history.
Filter list is enforced by ops/publish/publish_to_github.sh and
.githooks/pre-push going forward."
  fi
  echo ""
fi

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

  # Apply the filtered diff. Try 3-way merge first (resilient against
  # context drift), fall back to plain apply, then to cherry-pick.
  applied_ok=0
  if git apply --index --3way --whitespace=nowarn "$diff_file" 2>/dev/null; then
    applied_ok=1
  elif git apply --index --whitespace=nowarn "$diff_file" 2>/dev/null; then
    applied_ok=1
  fi
  if [ "$applied_ok" = "0" ]; then
    rm -f "$diff_file"
    # Final fallback: git cherry-pick (3-way merge from the original commit) + active filter
    if git cherry-pick --no-commit "$c" 2>/dev/null; then
      # Remove any forbidden paths the cherry-pick may have introduced
      forbidden_in_stage=$(git diff --cached --name-only | grep -E "$FORBIDDEN_REGEX" || true)
      for path in $forbidden_in_stage; do
        git rm -f -- "$path" >/dev/null 2>&1 || git checkout HEAD -- "$path" 2>/dev/null || true
      done
      # Also check working-tree changes
      forbidden_in_wt=$(git diff --name-only | grep -E "$FORBIDDEN_REGEX" || true)
      for path in $forbidden_in_wt; do
        git checkout HEAD -- "$path" 2>/dev/null || true
      done
      git add -A 2>/dev/null || true
      if git diff --cached --quiet; then
        git reset --hard >/dev/null 2>&1
        echo "  ⊘ $short (cherry-pick filtered to no-op)  $subject"
        skipped_empty=$((skipped_empty + 1))
        continue
      fi
      git commit -C "$c" --no-verify --quiet
      applied=$((applied + 1))
      echo "  ✓ $short (via cherry-pick fallback)  $subject"
      continue
    fi
    git reset --hard >/dev/null 2>&1
    git cherry-pick --abort 2>/dev/null || true
    echo "  ! $short (3-way + plain apply + cherry-pick all failed) — skipping: $subject" >&2
    skipped_failed=$((skipped_failed + 1))
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

# Verify _publish has no forbidden paths in its CURRENT TREE (not in the
# diff — diffing includes intentional deletions, which would false-positive).
violations=$(git ls-tree -r _publish --name-only 2>/dev/null | grep -E "$FORBIDDEN_REGEX" || true)
if [ -n "$violations" ]; then
  echo "ERROR: _publish branch tree contains forbidden paths:" >&2
  echo "$violations" | sed 's/^/  /' >&2
  echo "Aborting." >&2
  exit 1
fi

echo "Diff vs origin/main:"
git diff origin/main.._publish --stat | tail -20
echo ""

if [ "$MODE" = "dry_run" ]; then
  echo "DRY RUN — _publish branch built in isolated worktree; not pushing."
  echo "  Review:    git log origin/main.._publish --oneline"
  echo "  Full diff: git diff origin/main.._publish"
  echo "  Push:      ops/publish/publish_to_github.sh --push"
  echo ""
  echo "(The temporary worktree at $WORKTREE_DIR is auto-cleaned on script exit;"
  echo " the _publish branch ref is retained in the main repo for inspection.)"
  exit 0
fi

if [ "$MODE" = "interactive" ]; then
  echo "Push _publish to origin/main? [y/N]"
  read -r answer
  if [ "${answer:-N}" != "y" ] && [ "${answer:-N}" != "Y" ]; then
    echo "Cancelled. _publish branch retained for inspection in the main repo."
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
echo "Publish complete. _publish branch retained in the main repo."
echo "Worktree auto-cleans on script exit."
