#!/usr/bin/env bash
# publish_to_github.sh — RETIRED 2026-06-11.
#
# The filtered-mirror publish workflow is obsolete under the transparency
# doctrine: this repo (including kryptosbot/) is pushed directly to GitHub.
# Only four classes stay private, enforced by .githooks/pre-push and
# .gitignore:
#   1. .claude/ and any SKILL.md  (agent/skill construction)
#   2. .env files                 (secrets)
#   3. reference/, archive/, analysis_runs/ (local-only material)
#   4. copy/                      (retired snapshot)
#
# To publish: git push origin main
# Companion content scan still runs from the pre-push hook
# (ops/publish/scan_content.sh).

echo "RETIRED: the filtered publish workflow was replaced on 2026-06-11." >&2
echo "Push directly: git push origin main  (.githooks/pre-push guards the" >&2
echo "private classes: .claude/, SKILL.md, .env, reference/, archive/," >&2
echo "analysis_runs/, copy/)." >&2
exit 1
