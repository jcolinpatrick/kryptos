#!/usr/bin/env bash
# Tier-1 local rerun batch for preserved Kryptos controller eliminations.
#
# Purpose:
#   Run the highest-value local reruns that do not require Claude tokens.
#
# Usage:
#   bash scripts/rerun_keep_batch.sh --list
#   bash scripts/rerun_keep_batch.sh --all
#   bash scripts/rerun_keep_batch.sh one_lie
#   bash scripts/rerun_keep_batch.sh coordinates
#
# Behavior:
#   - Runs only bounded local scripts.
#   - Streams output to the terminal and also saves per-target logs under
#     results/reruns/<timestamp>/.
#   - Stops on first failure so a bad rerun does not silently contaminate
#     the batch summary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

export PYTHONPATH="$PROJECT_ROOT/src"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$PROJECT_ROOT/results/reruns/$STAMP"
mkdir -p "$OUT_DIR"
MANIFEST_JSONL="$OUT_DIR/rerun_manifest.jsonl"

TARGETS=(
  one_lie
  crib_perturb
  archive_beaufort_trans
  polybius_walk
  coordinates
)

list_targets() {
  cat <<'EOF'
Available rerun targets:
  one_lie
    scripts/archive_evidence/e_aaa_one_lie_09.py
    Historical tie-in: transcription/one-lie perturbation family

  crib_perturb
    scripts/crib_analysis/e_s_14_crib_perturbation.py
    Historical tie-in: crib perturbation / CT correction family

  archive_beaufort_trans
    scripts/archive_evidence/e_aaa_beaufort_trans_01.py
    Historical tie-in: archive-evidence columnar + substitution family

  polybius_walk
    scripts/exploration/e_polybius_walk.py
    Historical tie-in: geometry / grid-walk family

  coordinates
    scripts/archive_evidence/e_aaa_he_lied_04.py
    scripts/thematic/sculpture_physical/e_s_117_coordinate_keys.py
    Historical tie-in: k2_coords preserved reruns
EOF
}

run_logged() {
  local label="$1"
  shift
  local logfile="$OUT_DIR/${label}.log"
  echo ""
  echo "== $label =="
  echo "log: $logfile"
  "$@" 2>&1 | tee "$logfile"
}

summary_json() {
  local logfile="$1"
  python3 - "$logfile" <<'PY'
import json
import re
import sys
from pathlib import Path

log = Path(sys.argv[1])
pat = re.compile(r"^(VERDICT:|RESULT:|Best score:|No hits|Hits \(|Configurations tested:)")
keep = [line.strip() for line in log.read_text(encoding="utf-8", errors="replace").splitlines() if pat.search(line)]
if not keep:
    keep = log.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
print(json.dumps(keep[-12:], ensure_ascii=True))
PY
}

append_manifest() {
  local target="$1"
  local theory_ids_json="$2"
  local scripts_json="$3"
  local logs_json="$4"
  local summary_json_payload="$5"
  python3 - "$MANIFEST_JSONL" "$OUT_DIR" "$target" "$theory_ids_json" "$scripts_json" "$logs_json" "$summary_json_payload" <<'PY'
import json
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
payload = {
    "run_dir": sys.argv[2],
    "target": sys.argv[3],
    "theory_ids": json.loads(sys.argv[4]),
    "script_paths": json.loads(sys.argv[5]),
    "log_files": json.loads(sys.argv[6]),
    "summary_lines": json.loads(sys.argv[7]),
    "result_class": "elimination_rerun",
}
with manifest.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(payload, ensure_ascii=True) + "\n")
PY
}

run_target() {
  local target="$1"
  case "$target" in
    one_lie)
      run_logged "$target" python3 -u scripts/archive_evidence/e_aaa_one_lie_09.py
      append_manifest \
        "$target" \
        '["1e7d16753a83"]' \
        '["scripts/archive_evidence/e_aaa_one_lie_09.py"]' \
        "[\"$OUT_DIR/${target}.log\"]" \
        "$(summary_json "$OUT_DIR/${target}.log")"
      ;;
    crib_perturb)
      run_logged "$target" python3 -u scripts/crib_analysis/e_s_14_crib_perturbation.py
      append_manifest \
        "$target" \
        '["846379a97774"]' \
        '["scripts/crib_analysis/e_s_14_crib_perturbation.py"]' \
        "[\"$OUT_DIR/${target}.log\"]" \
        "$(summary_json "$OUT_DIR/${target}.log")"
      ;;
    archive_beaufort_trans)
      run_logged "$target" python3 -u scripts/archive_evidence/e_aaa_beaufort_trans_01.py
      append_manifest \
        "$target" \
        '["d38c9de74196"]' \
        '["scripts/archive_evidence/e_aaa_beaufort_trans_01.py"]' \
        "[\"$OUT_DIR/${target}.log\"]" \
        "$(summary_json "$OUT_DIR/${target}.log")"
      ;;
    polybius_walk)
      run_logged "$target" python3 -u scripts/exploration/e_polybius_walk.py
      append_manifest \
        "$target" \
        '["7cb543d6946b"]' \
        '["scripts/exploration/e_polybius_walk.py"]' \
        "[\"$OUT_DIR/${target}.log\"]" \
        "$(summary_json "$OUT_DIR/${target}.log")"
      ;;
    coordinates)
      run_logged "${target}_he_lied" python3 -u scripts/archive_evidence/e_aaa_he_lied_04.py
      run_logged "${target}_k2" python3 -u scripts/thematic/sculpture_physical/e_s_117_coordinate_keys.py
      append_manifest \
        "$target" \
        '["a2d882aae635","b767faec6315","d32b533d4d8a"]' \
        '["scripts/archive_evidence/e_aaa_he_lied_04.py","scripts/thematic/sculpture_physical/e_s_117_coordinate_keys.py"]' \
        "[\"$OUT_DIR/${target}_he_lied.log\",\"$OUT_DIR/${target}_k2.log\"]" \
        "$(python3 - <<PY
import json
from pathlib import Path
import re
logs = [
    Path("$OUT_DIR/${target}_he_lied.log"),
    Path("$OUT_DIR/${target}_k2.log"),
]
pat = re.compile(r"^(VERDICT:|RESULT:|Best score:|No hits|Hits \(|Configurations tested:)")
keep = []
for log in logs:
    lines = log.read_text(encoding='utf-8', errors='replace').splitlines()
    matched = [f"{log.name}: {line.strip()}" for line in lines if pat.search(line)]
    keep.extend(matched or [f"{log.name}: {line}" for line in lines[-6:]])
print(json.dumps(keep[-12:], ensure_ascii=True))
PY
)"
      ;;
    *)
      echo "Unknown target: $target" >&2
      echo "Run with --list to see valid targets." >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  cat > "$OUT_DIR/manifest.txt" <<EOF
Tier-1 local rerun batch
Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Project root: $PROJECT_ROOT
Targets: ${TARGETS[*]}
EOF
}

main() {
  if [[ $# -eq 0 || "${1:-}" == "--list" ]]; then
    list_targets
    echo ""
    echo "Logs will be written under: $OUT_DIR"
    exit 0
  fi

  write_manifest

  if [[ "${1:-}" == "--all" ]]; then
    shift
    for target in "${TARGETS[@]}"; do
      run_target "$target"
    done
  else
    for target in "$@"; do
      run_target "$target"
    done
  fi

  echo ""
  echo "Completed. Logs saved under: $OUT_DIR"
}

main "$@"
