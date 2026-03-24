#!/usr/bin/env bash
#
# analyze_traffic.sh — Traffic quality analysis for internal.com
#
# Usage: ./tools/analyze_traffic.sh [/var/log/nginx/access.log]
#
set -euo pipefail

LOG="${1:-/var/log/nginx/access.log}"

if [[ ! -f "$LOG" ]]; then
    echo "ERROR: Log file not found: $LOG" >&2
    exit 1
fi

TOTAL=$(wc -l < "$LOG")
FIRST=$(head -1 "$LOG" | grep -oP '\[\K[^]]+' || echo "?")
LAST=$(tail -1 "$LOG" | grep -oP '\[\K[^]]+' || echo "?")

echo "═══════════════════════════════════════════════════════════"
echo "  internal.com Traffic Analysis"
echo "  Log: $LOG ($TOTAL requests)"
echo "  Period: $FIRST → $LAST"
echo "═══════════════════════════════════════════════════════════"

echo ""
echo "── 1. STATUS CODE DISTRIBUTION ──────────────────────────"
awk '{print $9}' "$LOG" | sort | uniq -c | sort -rn | head -10

echo ""
echo "── 2. TRAFFIC CLASSIFICATION ────────────────────────────"

# Known bot user agents (case-insensitive match in UA field)
BOT_PATTERN='bot|crawl|spider|semrush|ahrefs|mj12|amazonbot|gptbot|googleother|bingbot|yandex|baidu|applebot|duckduck|facebook|twitter|linkedin|slack|curl|wget|python|java|go-http|libred|scanner|masscan|zgrab|censys|shodan|nmap|nikto'

BOTS=$(awk -F'"' -v pat="$BOT_PATTERN" 'tolower($6) ~ pat || $6 == "-" {c++} END {print c+0}' "$LOG")
HUMANS=$(( TOTAL - BOTS ))
BOT_PCT=$(( BOTS * 100 / TOTAL ))
HUMAN_PCT=$(( HUMANS * 100 / TOTAL ))

echo "  Total requests:   $TOTAL"
echo "  Likely bot:       $BOTS ($BOT_PCT%)"
echo "  Likely human:     $HUMANS ($HUMAN_PCT%)"

echo ""
echo "── 3. TOP 404 PATHS ─────────────────────────────────────"
TOTAL_404=$(awk '$9 == 404' "$LOG" | wc -l)

# Classify 404s
PROBE_404=$(awk '$9 == 404 {print $7}' "$LOG" | grep -ciE '\.(php|asp|aspx|env|git|bak|sql|zip|tar|rar|gz|cgi)|wp-|/admin|/cgi-bin|/config|/login|/manager|/phpmyadmin|/shell|/setup|/install|/actuator|/containers|\.aws|\.well-known|Dr0v|hello\.world' || true)
INFRA_404=$(awk '$9 == 404 {print $7}' "$LOG" | grep -ciE 'robots\.txt|favicon\.ico|sitemap\.xml|fonts\.css|apple-touch|manifest\.json' || true)
OTHER_404=$(( TOTAL_404 - PROBE_404 - INFRA_404 ))

echo "  Total 404s:       $TOTAL_404 ($(( TOTAL_404 * 100 / TOTAL ))% of traffic)"
echo "  ├─ Bot probes:    $PROBE_404 ($(( PROBE_404 * 100 / (TOTAL_404 > 0 ? TOTAL_404 : 1) ))%)"
echo "  ├─ Missing infra: $INFRA_404 ($(( INFRA_404 * 100 / (TOTAL_404 > 0 ? TOTAL_404 : 1) ))%)"
echo "  └─ Other:         $OTHER_404"
echo ""
echo "  Top 20 (excluding known bot probes):"
awk '$9 == 404 {print $7}' "$LOG" | \
    grep -viE '\.(php|asp|aspx|env|git|bak|sql|zip|tar|rar|gz|cgi)|wp-|/admin|/cgi-bin|/config|/login|/manager|/phpmyadmin|/shell|/setup|/install|/actuator|/containers|\.aws|Dr0v|hello\.world' | \
    sort | uniq -c | sort -rn | head -20

echo ""
echo "── 4. REFERRER ANALYSIS ─────────────────────────────────"
NO_REF=$(awk -F'"' '$4 == "-"' "$LOG" | wc -l)
WITH_REF=$(( TOTAL - NO_REF ))
echo "  No referrer:      $NO_REF ($(( NO_REF * 100 / TOTAL ))%)"
echo "  Has referrer:     $WITH_REF ($(( WITH_REF * 100 / TOTAL ))%)"
echo ""
echo "  Top external referrers:"
awk -F'"' '{print $4}' "$LOG" | \
    grep -v '^-$' | \
    grep -viE 'internal\.com|192\.168\.|100\.18\.|127\.0\.0' | \
    sort | uniq -c | sort -rn | head -15

echo ""
echo "── 5. LIKELY HUMAN TRAFFIC ──────────────────────────────"
echo "  Top pages viewed by likely-human visitors (200 status, browser UA, no bot):"
awk -F'"' -v pat="$BOT_PATTERN" '
    tolower($6) !~ pat && $6 != "-" {
        split($2, req, " ");
        n = split($0, parts, "\" ");
        # Status is between 2nd and 3rd quote blocks
        status_part = parts[2];
        split(status_part, sp, " ");
        status = sp[1];
        if (status == "200") print req[2]
    }' "$LOG" | \
    grep -v '\.\(css\|js\|png\|jpg\|woff2\|ico\|json\)' | \
    sort | uniq -c | sort -rn | head -20

echo ""
echo "── 6. TOP USER AGENTS ───────────────────────────────────"
awk -F'"' '{print $6}' "$LOG" | sort | uniq -c | sort -rn | head -15

echo ""
echo "── 7. ATTACK SIGNATURES ─────────────────────────────────"
echo "  Non-GET/HEAD/POST methods:"
awk -F'"' '{split($2,a," "); if (a[1] !~ /^(GET|HEAD|POST)$/) print a[1]}' "$LOG" | \
    sort | uniq -c | sort -rn | head -10

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Analysis complete."
echo "═══════════════════════════════════════════════════════════"
