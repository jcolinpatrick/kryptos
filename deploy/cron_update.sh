#!/usr/bin/env bash
#
# cron_update.sh — Automated rebuild & maintenance for kryptosbot.com
#
# Crontab entry (every 30 min, with flock to prevent overlap):
#   */30 * * * * /usr/bin/flock -n /tmp/kryptosbot-cron.lock /home/cpatrick/kryptos/deploy/cron_update.sh
#
# Flags:
#   --force    Rebuild even if no input changes detected
#   --dry-run  Run pytest + rebuild but skip git commit
#
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
REPO_DIR="/home/cpatrick/kryptos"
LOG_FILE="${REPO_DIR}/logs/cron_update.log"
CHECKSUM_FILE="${REPO_DIR}/logs/.last_build_inputs_checksum"
MAX_LOG_SIZE=$((5 * 1024 * 1024))  # 5 MB

# Safe paths for auto-commit (tracked modifications only)
SAFE_PATHS=(
    "reports/"
    "docs/"
    "site_builder/"
    "memory/"
    "wordlists/"
    "CLAUDE.md"
    "anomaly_registry.md"
)

# ── Parse flags ──────────────────────────────────────────────────────────────
FORCE=false
DRY_RUN=false
for arg in "$@"; do
    case "$arg" in
        --force)   FORCE=true ;;
        --dry-run) DRY_RUN=true ;;
        *)         echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────
ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() { echo "[$(ts)] $*"; }

log_section() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "[$(ts)] $*"
    echo "════════════════════════════════════════════════════════════════"
}

rotate_log() {
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(stat --format=%s "$LOG_FILE" 2>/dev/null || echo 0)
        if (( size > MAX_LOG_SIZE )); then
            mv "$LOG_FILE" "${LOG_FILE}.1"
            log "Log rotated (was ${size} bytes)"
        fi
    fi
}

# ── Setup ────────────────────────────────────────────────────────────────────
cd "$REPO_DIR"
mkdir -p logs

# Rotate log if needed, then redirect all output
rotate_log
exec >> "$LOG_FILE" 2>&1

log_section "cron_update.sh starting (force=$FORCE, dry_run=$DRY_RUN)"

# ── Step 1: Run pytest (gate) ────────────────────────────────────────────────
log_section "Step 1: Running pytest"

if PYTHONPATH=src venv/bin/pytest tests/ -q --tb=short; then
    log "Pytest PASSED"
else
    log "ERROR: Pytest FAILED — aborting (site not rebuilt)"
    exit 1
fi

# ── Step 2: Check if rebuild is needed ───────────────────────────────────────
log_section "Step 2: Checking for input changes"

compute_inputs_checksum() {
    # Collect mtimes of all build inputs into a deterministic fingerprint.
    # We hash mtimes (not contents) for speed — any touch triggers rebuild.
    {
        # Database mtimes
        find db/ -name '*.sqlite' -printf '%T@ %p\n' 2>/dev/null | sort

        # Results JSON mtimes
        find results/ -name '*.json' -printf '%T@ %p\n' 2>/dev/null | sort

        # Docs content (small enough to hash directly)
        find docs/ -name '*.md' -exec md5sum {} + 2>/dev/null | sort

        # Site builder code/templates/static
        find site_builder/ -type f -exec md5sum {} + 2>/dev/null | sort

        # Reports content
        find reports/ -name '*.md' -exec md5sum {} + 2>/dev/null | sort
        find reports/ -name '*.json' -exec md5sum {} + 2>/dev/null | sort
    } | md5sum | awk '{print $1}'
}

CURRENT_CHECKSUM=$(compute_inputs_checksum)
LAST_CHECKSUM=""
if [[ -f "$CHECKSUM_FILE" ]]; then
    LAST_CHECKSUM=$(cat "$CHECKSUM_FILE")
fi

if [[ "$FORCE" == "false" && "$CURRENT_CHECKSUM" == "$LAST_CHECKSUM" ]]; then
    log "No input changes detected (checksum: $CURRENT_CHECKSUM). Skipping rebuild."
    log_section "Done (no rebuild needed)"
    exit 0
fi

log "Input changes detected (was: ${LAST_CHECKSUM:-<none>}, now: $CURRENT_CHECKSUM)"

# ── Step 3: Rebuild static site ──────────────────────────────────────────────
log_section "Step 3: Rebuilding static site"

if PYTHONPATH=src venv/bin/python3 site_builder/build.py; then
    log "Site build completed"
else
    log "ERROR: Site build FAILED — not saving checksum (next run will retry)"
    exit 1
fi

# Post-build sanity checks
SANITY_OK=true

if [[ ! -f "site/index.html" ]]; then
    log "SANITY FAIL: site/index.html missing"
    SANITY_OK=false
fi

if [[ ! -f "site/static/style.css" ]]; then
    log "SANITY FAIL: site/static/style.css missing"
    SANITY_OK=false
fi

# Check for elimination pages (expect 10+)
ELIM_COUNT=0
if [[ -d "site/elimination" ]]; then
    ELIM_COUNT=$(find site/elimination/ -name 'index.html' 2>/dev/null | wc -l)
fi
if (( ELIM_COUNT < 10 )); then
    log "SANITY FAIL: Only $ELIM_COUNT elimination pages (expected 10+)"
    SANITY_OK=false
fi

# Validate search index JSON
if [[ -f "site/search-index.json" ]]; then
    if ! python3 -c "import json; json.load(open('site/search-index.json'))" 2>/dev/null; then
        log "SANITY FAIL: search-index.json is not valid JSON"
        SANITY_OK=false
    fi
else
    log "SANITY WARN: search-index.json not found (non-fatal)"
fi

if [[ "$SANITY_OK" == "false" ]]; then
    log "ERROR: Sanity checks FAILED — not saving checksum (next run will retry)"
    exit 1
fi

log "Sanity checks PASSED ($ELIM_COUNT elimination pages)"

# Save checksum on success
echo "$CURRENT_CHECKSUM" > "$CHECKSUM_FILE"
log "Checksum saved: $CURRENT_CHECKSUM"

# ── Step 4: Auto-commit tracked changes ──────────────────────────────────────
log_section "Step 4: Auto-commit check"

if [[ "$DRY_RUN" == "true" ]]; then
    log "Dry run — skipping git commit"
else
    # Stage only modifications to already-tracked files in safe paths
    STAGED_COUNT=0
    STAGED_SUMMARY=()

    for safe_path in "${SAFE_PATHS[@]}"; do
        if [[ -e "$safe_path" ]]; then
            # git add -u only stages modifications/deletions to tracked files
            git add -u -- "$safe_path" 2>/dev/null || true
        fi
    done

    # Check if anything was staged
    STAGED_FILES=$(git diff --cached --name-only 2>/dev/null || true)

    if [[ -z "$STAGED_FILES" ]]; then
        log "No tracked file changes to commit"
    else
        # Build commit message with category counts
        REPORT_COUNT=$(echo "$STAGED_FILES" | grep -c '^reports/' || true)
        DOC_COUNT=$(echo "$STAGED_FILES" | grep -c '^docs/' || true)
        BUILDER_COUNT=$(echo "$STAGED_FILES" | grep -c '^site_builder/' || true)
        MEMORY_COUNT=$(echo "$STAGED_FILES" | grep -c '^memory/' || true)
        OTHER_COUNT=$(echo "$STAGED_FILES" | grep -cv '^reports/\|^docs/\|^site_builder/\|^memory/' || true)

        # Build summary parts
        PARTS=()
        (( REPORT_COUNT > 0 )) && PARTS+=("${REPORT_COUNT} report(s)")
        (( DOC_COUNT > 0 )) && PARTS+=("${DOC_COUNT} doc(s)")
        (( BUILDER_COUNT > 0 )) && PARTS+=("${BUILDER_COUNT} builder file(s)")
        (( MEMORY_COUNT > 0 )) && PARTS+=("${MEMORY_COUNT} memory file(s)")
        (( OTHER_COUNT > 0 )) && PARTS+=("${OTHER_COUNT} other file(s)")

        SUMMARY=$(IFS=', '; echo "${PARTS[*]}")
        FILE_COUNT=$(echo "$STAGED_FILES" | wc -l)

        COMMIT_MSG="[auto] Update ${SUMMARY}

Auto-committed by cron_update.sh

Files changed (${FILE_COUNT}):
$(echo "$STAGED_FILES" | sed 's/^/  /')"

        if git commit -m "$COMMIT_MSG"; then
            log "Committed $FILE_COUNT file(s): $SUMMARY"
            log "Files:"
            echo "$STAGED_FILES" | while read -r f; do log "  $f"; done
        else
            log "WARN: git commit failed (maybe pre-commit hook?)"
            git reset HEAD -- . 2>/dev/null || true
        fi
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────
log_section "Done (success)"
