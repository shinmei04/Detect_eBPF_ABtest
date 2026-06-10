#!/usr/bin/env bash
# Created: 2026-06-10
# Purpose: 25 ms detector window comparison experiment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ORIGINAL_ARGS=("$@")

MODE="focused"
SYNTHETIC_TEST=0
BOTTLENECK_MBPS="15"
PERIOD_MS="1000"
DURATION_SEC="60"
ATTACK_START_SEC="20"
BUCKET_MS="25"
MAX_CASES=""
CAPTURE_INGRESS_IFACE=""
CAPTURE_EGRESS_IFACE=""
TCP_INFO_INTERVAL_MS="50"
COLLECT_TCP_INFO=1
RTO_CAUSAL_WINDOW_MS="500"
DISABLE_OFFLOADS=0
OUTPUT_DIR=""
EXISTING_REPO_DIR="${REPO_ROOT}/Detect_eBPF_ABtest_mininet"
PAYLOAD_SIZE="750"
NUM_ATTACK_FLOWS="8"
SEED_VALUES=(1 2 3)
PEAK_MULTIPLIER_VALUES=()
DUTY_RATIO_VALUES=()
FAILED_CASES=()

usage() {
  cat <<'USAGE'
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Usage:
  sudo ./run_ldos_bandwidth_grid_20260610.sh --smoke
  sudo ./run_ldos_bandwidth_grid_20260610.sh --focused
  ./run_ldos_bandwidth_grid_20260610.sh --smoke --synthetic-test

Options:
  --smoke                         Run 1 seed, 1 condition, all scenarios, short duration.
  --focused                       Run focused 5-condition grid, seeds 1 2 3.
  --dry-run | --synthetic-test     Generate deterministic smoke artifacts without Mininet.
  --bottleneck-mbps N             Bottleneck capacity C in Mbps. Default: 15.
  --period-ms N                   LDoS period T in ms. Default: 1000.
  --peak-multiplier-values ...    Override peak multipliers R/C.
  --duty-ratio-values ...         Override duty ratios L/T.
  --max-cases N                   Limit the number of conditions.
  --seed-values ...               Override seeds.
  --duration-sec N                Experiment duration. Default: 60.
  --attack-start-sec N            Attack start time. Default: 20.
  --capture-ingress-iface IFACE   Override Capture A interface.
  --capture-egress-iface IFACE    Override Capture B interface.
  --tcp-info-interval-ms N        ss/TCP_INFO sampling interval. Default: 50.
  --disable-tcp-info              Disable ss/TCP_INFO collection.
  --rto-causal-window-ms N        Pulse-end to RTO causal window. Default: 500.
  --disable-offloads              Disable TSO/GSO/GRO on capture interfaces.
  --existing-repo-dir DIR         Existing repo with Mininet implementation.
  --output-dir DIR                Result directory.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --smoke)
      MODE="smoke"
      SEED_VALUES=(1)
      DURATION_SEC="12"
      ATTACK_START_SEC="3"
      MAX_CASES="${MAX_CASES:-1}"
      shift
      ;;
    --focused)
      MODE="focused"
      shift
      ;;
    --dry-run|--synthetic-test)
      SYNTHETIC_TEST=1
      shift
      ;;
    --bottleneck-mbps)
      BOTTLENECK_MBPS="$2"
      shift 2
      ;;
    --period-ms)
      PERIOD_MS="$2"
      shift 2
      ;;
    --max-cases)
      MAX_CASES="$2"
      shift 2
      ;;
    --duration-sec)
      DURATION_SEC="$2"
      shift 2
      ;;
    --attack-start-sec)
      ATTACK_START_SEC="$2"
      shift 2
      ;;
    --bucket-ms)
      BUCKET_MS="$2"
      shift 2
      ;;
    --payload-size)
      PAYLOAD_SIZE="$2"
      shift 2
      ;;
    --num-attack-flows)
      NUM_ATTACK_FLOWS="$2"
      shift 2
      ;;
    --capture-ingress-iface)
      CAPTURE_INGRESS_IFACE="$2"
      shift 2
      ;;
    --capture-egress-iface)
      CAPTURE_EGRESS_IFACE="$2"
      shift 2
      ;;
    --tcp-info-interval-ms)
      TCP_INFO_INTERVAL_MS="$2"
      shift 2
      ;;
    --disable-tcp-info)
      COLLECT_TCP_INFO=0
      shift
      ;;
    --rto-causal-window-ms)
      RTO_CAUSAL_WINDOW_MS="$2"
      shift 2
      ;;
    --disable-offloads)
      DISABLE_OFFLOADS=1
      shift
      ;;
    --existing-repo-dir)
      EXISTING_REPO_DIR="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --seed-values)
      shift
      SEED_VALUES=()
      while [[ $# -gt 0 && "$1" != --* ]]; do
        SEED_VALUES+=("$1")
        shift
      done
      ;;
    --peak-multiplier-values)
      shift
      PEAK_MULTIPLIER_VALUES=()
      while [[ $# -gt 0 && "$1" != --* ]]; do
        PEAK_MULTIPLIER_VALUES+=("$1")
        shift
      done
      ;;
    --duty-ratio-values)
      shift
      DUTY_RATIO_VALUES=()
      while [[ $# -gt 0 && "$1" != --* ]]; do
        DUTY_RATIO_VALUES+=("$1")
        shift
      done
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${#SEED_VALUES[@]} -eq 0 ]]; then
  echo "--seed-values must include at least one seed" >&2
  exit 2
fi

if [[ -z "${OUTPUT_DIR}" ]]; then
  OUTPUT_DIR="${REPO_ROOT}/results_bandwidth_20260610_$(date +%Y%m%d_%H%M%S)"
fi

if [[ -x "${EXISTING_REPO_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${EXISTING_REPO_DIR}/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi
export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH:-}"

mkdir -p "${OUTPUT_DIR}/"{raw,cases,csv,figures,logs}

cleanup() {
  if [[ "${SYNTHETIC_TEST}" -eq 0 ]]; then
    if command -v mn >/dev/null 2>&1; then
      mn -c >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT INT TERM

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

require_command "${PYTHON_BIN}"
if [[ "${SYNTHETIC_TEST}" -eq 0 ]]; then
  for cmd in tcpdump iperf3 tc ip mn ovs-vsctl; do
    require_command "${cmd}"
  done
  if [[ "${COLLECT_TCP_INFO}" -eq 1 ]]; then
    require_command ss
  fi
  if [[ "${DISABLE_OFFLOADS}" -eq 1 ]]; then
    require_command ethtool
  fi
  if [[ "$(id -u)" != "0" ]]; then
    echo "Real Mininet execution requires sudo/root. Re-run with sudo, or use --synthetic-test." >&2
    exit 2
  fi
  ovs-vsctl show >/dev/null
  mn -c >/dev/null 2>&1 || true
fi

echo "LDoS bandwidth pipeline started: $(date '+%Y-%m-%dT%H:%M:%S%z')"
echo "mode=${MODE} synthetic=${SYNTHETIC_TEST}"
echo "output_dir=${OUTPUT_DIR}"
printf '%q ' "$0" "${ORIGINAL_ARGS[@]}" > "${OUTPUT_DIR}/command_20260610.txt"
printf '\n' >> "${OUTPUT_DIR}/command_20260610.txt"
git -C "${REPO_ROOT}" rev-parse HEAD > "${OUTPUT_DIR}/git_commit_20260610.txt" 2>/dev/null || true
"${PYTHON_BIN}" -m pip freeze > "${OUTPUT_DIR}/pip_freeze_20260610.txt" 2>/dev/null || true

"${PYTHON_BIN}" - "${OUTPUT_DIR}" "${BOTTLENECK_MBPS}" "${PERIOD_MS}" "${MAX_CASES}" "${PEAK_MULTIPLIER_VALUES[*]-}" "${DUTY_RATIO_VALUES[*]-}" <<'PY'
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bandwidth_metrics_20260610 import average_attack_rate_mbps, configured_average_attack_pct, focused_conditions

out_dir = Path(sys.argv[1])
bottleneck = float(sys.argv[2])
period_ms = float(sys.argv[3])
max_cases = int(sys.argv[4]) if sys.argv[4] else None
peak_values = [float(x) for x in sys.argv[5].split()] if sys.argv[5].strip() else []
duty_values = [float(x) for x in sys.argv[6].split()] if len(sys.argv) > 6 and sys.argv[6].strip() else []
if peak_values or duty_values:
    if not peak_values or not duty_values:
        raise SystemExit("--peak-multiplier-values and --duty-ratio-values must be supplied together")
    rows = []
    for peak in peak_values:
        for duty in duty_values:
            peak_rate = bottleneck * peak
            burst_ms = period_ms * duty
            avg = average_attack_rate_mbps(peak_rate, burst_ms, period_ms)
            avg_pct = configured_average_attack_pct(avg, bottleneck)
            if avg_pct <= 33.0 + 1e-9:
                rows.append({
                    "condition_id": f"avg{round(avg_pct):02d}_peak{str(peak).replace('.', '_')}",
                    "peak_multiplier": peak,
                    "duty_ratio": duty,
                    "peak_rate_mbps": peak_rate,
                    "burst_ms": burst_ms,
                    "period_ms": period_ms,
                    "configured_average_attack_mbps": avg,
                    "configured_average_attack_pct": avg_pct,
                })
else:
    rows = focused_conditions(bottleneck, period_ms)
if max_cases is not None:
    rows = rows[:max_cases]
path = out_dir / "condition_grid_20260610.csv"
with path.open("w", newline="") as f:
    fields = [
        "condition_id",
        "peak_multiplier",
        "duty_ratio",
        "peak_rate_mbps",
        "burst_ms",
        "period_ms",
        "configured_average_attack_mbps",
        "configured_average_attack_pct",
    ]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
print(path)
PY

cat > "${OUTPUT_DIR}/metadata_20260610.json" <<META
{
  "created_date": "2026-06-10",
  "purpose": "25 ms detector window comparison experiment",
  "pipeline_name": "ldos_bandwidth_20260610",
  "mode": "${MODE}",
  "synthetic_test": ${SYNTHETIC_TEST},
  "bottleneck_mbps": ${BOTTLENECK_MBPS},
  "period_ms": ${PERIOD_MS},
  "duration_sec": ${DURATION_SEC},
  "attack_start_sec": ${ATTACK_START_SEC},
  "bucket_ms": ${BUCKET_MS},
  "tcp_info_interval_ms": ${TCP_INFO_INTERVAL_MS},
  "collect_tcp_info": ${COLLECT_TCP_INFO},
  "rto_causal_window_ms": ${RTO_CAUSAL_WINDOW_MS},
  "disable_offloads": ${DISABLE_OFFLOADS}
}
META

CONDITION_LINES=()
while IFS= read -r line; do
  CONDITION_LINES+=("${line}")
done < <(tail -n +2 "${OUTPUT_DIR}/condition_grid_20260610.csv")
SCENARIOS=(constant_udp random_microburst periodic_ldos stat_matched_ldos)

run_case() {
  local scenario="$1"
  local condition_id="$2"
  local seed="$3"
  local peak_rate="$4"
  local burst_ms="$5"
  local period_ms="$6"
  local duty_ratio="$7"
  local avg_attack="$8"
  local case_id="${condition_id}_${scenario}_seed${seed}_20260610"
  local args=(
    "${PYTHON_BIN}" "${SCRIPT_DIR}/run_ldos_bandwidth_experiment_20260610.py"
    --output-dir "${OUTPUT_DIR}"
    --case-id "${case_id}"
    --scenario "${scenario}"
    --condition-id "${condition_id}"
    --seed "${seed}"
    --bottleneck-mbps "${BOTTLENECK_MBPS}"
    --peak-rate-mbps "${peak_rate}"
    --burst-ms "${burst_ms}"
    --period-ms "${period_ms}"
    --duty-ratio "${duty_ratio}"
    --configured-average-attack-mbps "${avg_attack}"
    --duration-sec "${DURATION_SEC}"
    --attack-start-sec "${ATTACK_START_SEC}"
    --bucket-ms "${BUCKET_MS}"
    --tcp-info-interval-ms "${TCP_INFO_INTERVAL_MS}"
    --payload-size "${PAYLOAD_SIZE}"
    --num-attack-flows "${NUM_ATTACK_FLOWS}"
    --existing-repo-dir "${EXISTING_REPO_DIR}"
  )
  if [[ -n "${CAPTURE_INGRESS_IFACE}" ]]; then
    args+=(--capture-ingress-iface "${CAPTURE_INGRESS_IFACE}")
  fi
  if [[ -n "${CAPTURE_EGRESS_IFACE}" ]]; then
    args+=(--capture-egress-iface "${CAPTURE_EGRESS_IFACE}")
  fi
  if [[ "${SYNTHETIC_TEST}" -eq 1 ]]; then
    args+=(--synthetic-test)
  fi
  if [[ "${COLLECT_TCP_INFO}" -eq 0 ]]; then
    args+=(--disable-tcp-info)
  fi
  if [[ "${DISABLE_OFFLOADS}" -eq 1 ]]; then
    args+=(--disable-offloads)
  fi
  echo "Running case: ${case_id}"
  if ! "${args[@]}" > "${OUTPUT_DIR}/logs/${case_id}.log" 2>&1; then
    echo "FAILED: ${case_id}" >&2
    FAILED_CASES+=("${case_id}")
  fi
}

for seed in "${SEED_VALUES[@]}"; do
  run_case "no_attack" "baseline" "${seed}" "${BOTTLENECK_MBPS}" "100" "${PERIOD_MS}" "0.1" "0"
done

for line in "${CONDITION_LINES[@]}"; do
  IFS=',' read -r condition_id peak_multiplier duty_ratio peak_rate burst_ms period_ms avg_attack avg_pct <<<"${line}"
  for seed in "${SEED_VALUES[@]}"; do
    for scenario in "${SCENARIOS[@]}"; do
      run_case "${scenario}" "${condition_id}" "${seed}" "${peak_rate}" "${burst_ms}" "${period_ms}" "${duty_ratio}" "${avg_attack}"
    done
  done
done

"${PYTHON_BIN}" "${SCRIPT_DIR}/analyze_bandwidth_utilization_20260610.py" \
  --results-dir "${OUTPUT_DIR}" \
  --bucket-ms "${BUCKET_MS}" \
  --bottleneck-mbps "${BOTTLENECK_MBPS}"

"${PYTHON_BIN}" "${SCRIPT_DIR}/analyze_tcp_rto_20260610.py" \
  --results-dir "${OUTPUT_DIR}" \
  --rto-causal-window-ms "${RTO_CAUSAL_WINDOW_MS}" \
  --period-ms "${PERIOD_MS}"

"${PYTHON_BIN}" "${SCRIPT_DIR}/plot_bandwidth_utilization_20260610.py" \
  --input-dir "${OUTPUT_DIR}/csv" \
  --output-dir "${OUTPUT_DIR}/figures" \
  --results-dir "${OUTPUT_DIR}" \
  --bottleneck-mbps "${BOTTLENECK_MBPS}" \
  --attack-start-sec "${ATTACK_START_SEC}"

"${PYTHON_BIN}" "${SCRIPT_DIR}/plot_tcp_rto_20260610.py" \
  --input-dir "${OUTPUT_DIR}/csv" \
  --output-dir "${OUTPUT_DIR}/figures" \
  --bottleneck-mbps "${BOTTLENECK_MBPS}"

"${PYTHON_BIN}" - "${OUTPUT_DIR}" <<'PY'
import csv
import math
import sys
from pathlib import Path

out = Path(sys.argv[1])
case_path = out / "csv" / "case_metrics_20260610.csv"
rows = []
if case_path.exists():
    with case_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
summary = [
    "# LDoS Bandwidth Experiment Summary",
    "",
    "Created: 2026-06-10",
    "Purpose: 25 ms detector window comparison experiment.",
    "",
    f"- cases: {len(rows)}",
    f"- csv_dir: {out / 'csv'}",
    f"- figures_dir: {out / 'figures'}",
    "",
    "## Best Synthetic/Measured Rows",
    "",
    "| condition | scenario | seed | TCP Mbps | TCP degradation % | attack % | idle % | FNR % |",
    "|---|---|---:|---:|---:|---:|---:|---:|",
]
for row in rows[:20]:
    def val(name, scale=1.0):
        try:
            return float(row.get(name, "")) * scale
        except ValueError:
            return math.nan
    summary.append(
        f"| {row.get('condition_id','')} | {row.get('scenario','')} | {row.get('seed','')} | "
        f"{val('tcp_mbps'):.2f} | {val('tcp_degradation_pct'):.2f} | "
        f"{val('attack_share_pct'):.2f} | {val('idle_share_pct'):.2f} | {val('FNR', 100.0):.2f} |"
    )
(out / "summary_20260610.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
PY

cat > "${OUTPUT_DIR}/README_20260610.txt" <<README
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Pipeline: ldos_bandwidth_20260610
Output directory: ${OUTPUT_DIR}

CSV outputs are in csv/.
Figures are in figures/.
Case raw data and metadata are in cases/<case_id>/.
README

if [[ ${#FAILED_CASES[@]} -gt 0 ]]; then
  printf '%s\n' "${FAILED_CASES[@]}" > "${OUTPUT_DIR}/failed_cases_20260610.txt"
  echo "Pipeline finished with failed cases:"
  printf '  %s\n' "${FAILED_CASES[@]}"
  exit 1
fi

echo "LDoS bandwidth pipeline finished: $(date '+%Y-%m-%dT%H:%M:%S%z')"
echo "Output directory: ${OUTPUT_DIR}"
