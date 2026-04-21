#!/usr/bin/env bash
# Poll GitHub traffic API and append to a persistent log.
# GitHub only retains 14 days of traffic data, so this must run
# at least every 13 days to avoid gaps. Daily is ideal.
#
# Usage: ops/tools/poll_github_traffic.sh
# Cron:  0 6 * * * /home/cpatrick/kryptos/ops/tools/poll_github_traffic.sh

set -euo pipefail

REPO="jcolinpatrick/kryptos"
LOG_DIR="/home/cpatrick/kryptos/logs/github_traffic"
mkdir -p "$LOG_DIR"

CLONES_LOG="$LOG_DIR/clones.jsonl"
VIEWS_LOG="$LOG_DIR/views.jsonl"
SUMMARY_LOG="$LOG_DIR/daily_summary.tsv"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DATE_TODAY=$(date -u +"%Y-%m-%d")

# Fetch traffic data
CLONES_JSON=$(gh api "repos/$REPO/traffic/clones" 2>/dev/null) || {
    echo "[$TIMESTAMP] ERROR: Failed to fetch clone data" >> "$LOG_DIR/errors.log"
    exit 1
}
VIEWS_JSON=$(gh api "repos/$REPO/traffic/views" 2>/dev/null) || {
    echo "[$TIMESTAMP] ERROR: Failed to fetch view data" >> "$LOG_DIR/errors.log"
    exit 1
}

# Append raw API responses with poll timestamp
echo "{\"polled_at\":\"$TIMESTAMP\",\"data\":$CLONES_JSON}" >> "$CLONES_LOG"
echo "{\"polled_at\":\"$TIMESTAMP\",\"data\":$VIEWS_JSON}" >> "$VIEWS_LOG"

# Extract per-day records and deduplicate into the summary TSV
# Header if file doesn't exist
if [ ! -f "$SUMMARY_LOG" ]; then
    printf "date\tclones\tunique_cloners\tviews\tunique_viewers\tpolled_at\n" > "$SUMMARY_LOG"
fi

# Parse each day's data from the API response, only append dates not already logged
python3 -c "
import json, sys

clones = json.loads('''$CLONES_JSON''')
views = json.loads('''$VIEWS_JSON''')

# Build lookup from views
view_map = {}
for v in views.get('clones', views.get('views', [])):
    # Handle both endpoints having same structure
    pass
view_map = {v['timestamp'][:10]: v for v in views.get('views', [])}

# Read existing dates
existing = set()
try:
    with open('$SUMMARY_LOG') as f:
        for line in f:
            if line.startswith('date') or not line.strip():
                continue
            existing.add(line.split('\t')[0])
except FileNotFoundError:
    pass

# Append new dates
with open('$SUMMARY_LOG', 'a') as f:
    for c in clones.get('clones', []):
        day = c['timestamp'][:10]
        if day in existing:
            continue
        v = view_map.get(day, {'count': 0, 'uniques': 0})
        f.write(f\"{day}\t{c['count']}\t{c['uniques']}\t{v['count']}\t{v['uniques']}\t$TIMESTAMP\n\")
        existing.add(day)
"

# Print the current rolling-14-day API totals to stdout.
# These are NOT per-day counts; GitHub's traffic endpoints return a moving
# 14-day window. Keep the wording explicit so cron logs are not misread as
# daily deltas.
TOTAL_CLONES=$(echo "$CLONES_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])")
UNIQUE_CLONES=$(echo "$CLONES_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['uniques'])")
TOTAL_VIEWS=$(echo "$VIEWS_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])")
UNIQUE_VIEWS=$(echo "$VIEWS_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['uniques'])")

echo "[$DATE_TODAY] Rolling 14d clones: $TOTAL_CLONES ($UNIQUE_CLONES unique) | Rolling 14d views: $TOTAL_VIEWS ($UNIQUE_VIEWS unique)"
