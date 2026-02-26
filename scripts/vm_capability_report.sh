#!/bin/bash
# VM Capability Report for Kryptos K4 Project
# Run this after VM changes to inform Claude sessions of available resources.
# Usage: bash scripts/vm_capability_report.sh
# Output: results/vm_capability.txt (paste into Claude session)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$PROJECT_DIR/results"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/vm_capability.txt"

{
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           KRYPTOS VM CAPABILITY REPORT                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

echo "── OS ─────────────────────────────────────────────────────────"
echo "Distro:  $(grep '^PRETTY_NAME' /etc/os-release | cut -d= -f2 | tr -d '"')"
echo "Kernel:  $(uname -r)"
echo "Arch:    $(uname -m)"
echo ""

echo "── CPU ────────────────────────────────────────────────────────"
echo "Model:   $(grep 'Model name' /proc/cpuinfo | head -1 | sed 's/.*: //')"
echo "vCPUs:   $(nproc)"
echo "Sockets: $(lscpu | grep '^Socket' | awk '{print $NF}')"
echo "Cores/s: $(lscpu | grep '^Core' | awk '{print $NF}')"
echo "Threads: $(lscpu | grep '^Thread' | awk '{print $NF}')"
echo "Hyper:   $(lscpu | grep 'Hypervisor' | awk '{print $NF}') ($(cat /sys/class/dmi/id/product_name 2>/dev/null || echo 'unknown'))"
FREQ=$(lscpu | grep 'CPU max MHz' | awk '{printf "%.1f GHz", $NF/1000}' 2>/dev/null || lscpu | grep 'Model name' | grep -oE '[0-9]+\.[0-9]+GHz' || echo "unknown")
echo "Freq:    $FREQ"
FLAGS=$(grep -o -E '(aes|avx|avx2|avx512[a-z]*|sse4_[12]|sha_ni|popcnt)' /proc/cpuinfo 2>/dev/null | sort -u | tr '\n' ' ')
echo "Flags:   ${FLAGS:-none detected}"
echo ""

echo "── MEMORY ─────────────────────────────────────────────────────"
echo "Total:   $(free -h | awk '/^Mem:/{print $2}')"
echo "Used:    $(free -h | awk '/^Mem:/{print $3}')"
echo "Free:    $(free -h | awk '/^Mem:/{print $4}')"
echo "Avail:   $(free -h | awk '/^Mem:/{print $7}')"
SWAP=$(swapon --show 2>/dev/null | tail -1)
echo "Swap:    ${SWAP:-none}"
echo ""

echo "── STORAGE ──────────────────────────────────────────────────"
df -h / | awk 'NR==2{printf "Root:    %s total, %s used, %s free (%s)\n", $2, $3, $4, $5}'
echo "I/O:     $(dd if=/dev/zero of=/tmp/.vm_bench bs=1M count=128 oflag=dsync 2>&1 | grep -oE '[0-9.]+ [MG]B/s')"
rm -f /tmp/.vm_bench
echo ""

echo "── NETWORK ──────────────────────────────────────────────────"
IP=$(ip -4 addr show | grep -v 127.0.0.1 | grep 'inet ' | awk '{print $2}' | head -1)
echo "IP:      ${IP:-no external IP}"
INET=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" https://www.google.com 2>/dev/null || echo "fail")
if [ "$INET" = "200" ] || [ "$INET" = "301" ] || [ "$INET" = "302" ]; then
    echo "Internet: YES (HTTP $INET)"
    GUT=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" https://www.gutenberg.org/ 2>/dev/null || echo "fail")
    echo "Gutenberg: $([ "$GUT" = "200" ] && echo "reachable" || echo "blocked/unreachable ($GUT)")"
else
    echo "Internet: NO ($INET)"
fi
echo ""

echo "── PYTHON ───────────────────────────────────────────────────"
echo "Version: $(python3 --version 2>&1)"
python3 -c "
import multiprocessing, sqlite3, sys, os
print(f'Arch:    {\"64-bit\" if sys.maxsize > 2**32 else \"32-bit\"}')
print(f'Workers: {multiprocessing.cpu_count()} (multiprocessing.cpu_count)')
print(f'SQLite:  {sqlite3.sqlite_version}')
try:
    import tomllib; print('tomllib: available')
except: print('tomllib: NOT available')
try:
    import numpy; print(f'numpy:   {numpy.__version__} (system)')
except: print('numpy:   not in system python')
"
# Check venv
if [ -f "$PROJECT_DIR/venv/bin/python3" ]; then
    echo "Venv:    present at $PROJECT_DIR/venv/"
    "$PROJECT_DIR/venv/bin/python3" -c "
try:
    import numpy; print(f'  numpy: {numpy.__version__}')
except: print('  numpy: not installed')
try:
    import pymupdf; print(f'  pymupdf: available')
except: print('  pymupdf: not installed')
" 2>/dev/null
else
    echo "Venv:    not found"
fi
echo ""

echo "── TOOLS ────────────────────────────────────────────────────"
for cmd in tmux screen git curl wget gcc make jq sqlite3 bc; do
    path=$(which "$cmd" 2>/dev/null || true)
    if [ -n "$path" ]; then
        echo "  $cmd: YES ($path)"
    else
        echo "  $cmd: NOT INSTALLED"
    fi
done
echo ""

echo "── COMPUTE BENCHMARK ────────────────────────────────────────"
python3 -c "
import time, multiprocessing

def bench(n):
    s = 0
    for i in range(n):
        s = (s * 7 + 13) % 26
    return s

N = 5_000_000
cores = multiprocessing.cpu_count()

t0 = time.time()
bench(N)
single_rate = N / (time.time() - t0)

t0 = time.time()
with multiprocessing.Pool(cores) as pool:
    pool.map(bench, [N]*cores)
multi_rate = (N * cores) / (time.time() - t0)

eff = multi_rate / (single_rate * cores) * 100
print(f'Single-core:  {single_rate/1e6:.1f}M ops/sec')
print(f'All {cores} cores: {multi_rate/1e6:.1f}M ops/sec')
print(f'Efficiency:   {eff:.0f}%')
print(f'Est DRAGNET:  ~{multi_rate/200/1e3:.0f}K candidates/sec (Phase 1)')
"
echo ""

echo "── ACTIVE BACKGROUND JOBS ───────────────────────────────────"
# Check for running experiment scripts
ps aux | grep -E "python3.*scripts/" | grep -v grep | awk '{printf "  PID %-8s CPU %-5s MEM %-5s %s\n", $2, $3, $4, $11" "$12" "$13}' || echo "  none"
echo ""

echo "── RECOMMENDATIONS ──────────────────────────────────────────"
VCPUS=$(nproc)
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
DISK_FREE=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')

if [ "$VCPUS" -lt 32 ]; then
    echo "  [CPU]  Consider increasing to 32 vCPUs (ESXi 8.0 supports 768/VM)"
fi
if [ "$RAM_GB" -lt 16 ]; then
    echo "  [RAM]  Consider increasing to 24-32 GB for large corpus sweeps"
fi
if [ "$DISK_FREE" -lt 20 ]; then
    echo "  [DISK] Only ${DISK_FREE}GB free — expand LV or add disk for corpus storage"
else
    echo "  [DISK] ${DISK_FREE}GB free — sufficient for corpus + results"
fi
SWAP_SIZE=$(free -m | awk '/^Swap:/{print $2}')
if [ "$SWAP_SIZE" -eq 0 ]; then
    echo "  [SWAP] No swap configured — consider adding 4-8GB swap as safety net"
fi
if ! which screen >/dev/null 2>&1; then
    echo "  [TOOL] Install screen: sudo apt install screen (for persistent sessions)"
fi
echo ""
echo "══════════════════════════════════════════════════════════════"

} | tee "$OUT"

echo ""
echo "Report saved to: $OUT"
echo "Paste contents into a Claude session to inform it of VM capabilities."
