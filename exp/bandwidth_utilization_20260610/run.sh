#!/usr/bin/env bash
# Created: 2026-06-10
# Purpose: 25 ms detector window comparison experiment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ORIGINAL_ARGS=("$@")

MODE="focused"
OUTPUT_TAG="20260610"
TCP5_ATTACK5_MODE=0
RTO_CALIBRATION_MODE=0
SYNTHETIC_TEST=0
BOTTLENECK_MBPS="15"
PERIOD_MS="1000"
DURATION_SEC="60"
ATTACK_START_SEC="20"
EVALUATION_START_SEC=""
EVALUATION_END_SEC=""
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
TCP_TARGET_MBPS=""
TCP_PACING_TIMER_US=""
QUEUE_LIMIT_PACKETS=""
RTO_PEAK_VALUES=()
RTO_QUEUE_VALUES=()
SEED_VALUES=(1 2 3)
PEAK_MULTIPLIER_VALUES=()
DUTY_RATIO_VALUES=()
FAILED_CASES=()

usage() {
  cat <<'USAGE'
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Usage:
  sudo ./run.sh --smoke
  sudo ./run.sh --focused
  ./run.sh --smoke --synthetic-test

Options:
  --smoke                         Run 1 seed, 1 condition, all scenarios, short duration.
  --focused                       Run focused 5-condition grid, seeds 1 2 3.
  --tcp5-attack5-smoke            Run TCP=5 Mbps, avg attack=5 Mbps smoke (seed 1).
  --tcp5-attack5-focused          Run TCP=5 Mbps, avg attack=5 Mbps focused grid (seeds 1..5).
  --rto-calibration-smoke         Run RTO calibration smoke, peak 30 Mbps and queue 100 packets.
  --rto-calibration-grid          Run RTO calibration grid, peak 15/30/45/60 and queue 50/100/200.
  --dry-run | --synthetic-test     Generate deterministic smoke artifacts without Mininet.
  --bottleneck-mbps N             Bottleneck capacity C in Mbps. Default: 15.
  --period-ms N                   LDoS period T in ms. Default: 1000.
  --peak-multiplier-values ...    Override peak multipliers R/C.
  --duty-ratio-values ...         Override duty ratios L/T.
  --max-cases N                   Limit the number of conditions.
  --seed-values ...               Override seeds.
  --duration-sec N                Experiment duration. Default: 60.
  --attack-start-sec N            Attack start time. Default: 20.
  --evaluation-start-sec N        Evaluation window start.
  --evaluation-end-sec N          Evaluation window end.
  --capture-ingress-iface IFACE   Override Capture A interface.
  --capture-egress-iface IFACE    Override Capture B interface.
  --tcp-info-interval-ms N        ss/TCP_INFO sampling interval. Default: 50.
  --tcp-target-mbps N             iperf3 TCP bitrate target, e.g. 5.
  --tcp-pacing-timer-us N         Optional iperf3 --pacing-timer value.
  --queue-limit-packets N         Bottleneck netem queue limit in packets.
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
    --tcp5-attack5-smoke)
      MODE="tcp5_attack5_smoke"
      OUTPUT_TAG="20260611"
      TCP5_ATTACK5_MODE=1
      SEED_VALUES=(1)
      DURATION_SEC="20"
      ATTACK_START_SEC="5"
      EVALUATION_START_SEC="7"
      EVALUATION_END_SEC="18"
      BOTTLENECK_MBPS="15"
      PERIOD_MS="1000"
      BUCKET_MS="25"
      TCP_INFO_INTERVAL_MS="50"
      TCP_TARGET_MBPS="5"
      shift
      ;;
    --tcp5-attack5-focused)
      MODE="tcp5_attack5_focused"
      OUTPUT_TAG="20260611"
      TCP5_ATTACK5_MODE=1
      SEED_VALUES=(1 2 3 4 5)
      DURATION_SEC="60"
      ATTACK_START_SEC="20"
      EVALUATION_START_SEC="25"
      EVALUATION_END_SEC="55"
      BOTTLENECK_MBPS="15"
      PERIOD_MS="1000"
      BUCKET_MS="25"
      TCP_INFO_INTERVAL_MS="50"
      TCP_TARGET_MBPS="5"
      shift
      ;;
    --rto-calibration-smoke)
      MODE="rto_calibration_smoke"
      OUTPUT_TAG="20260611"
      TCP5_ATTACK5_MODE=1
      RTO_CALIBRATION_MODE=1
      SEED_VALUES=(1)
      DURATION_SEC="20"
      ATTACK_START_SEC="5"
      EVALUATION_START_SEC="7"
      EVALUATION_END_SEC="18"
      BOTTLENECK_MBPS="15"
      PERIOD_MS="1000"
      BUCKET_MS="25"
      TCP_INFO_INTERVAL_MS="50"
      TCP_TARGET_MBPS="5"
      RTO_PEAK_VALUES=(30)
      RTO_QUEUE_VALUES=(100)
      shift
      ;;
    --rto-calibration-grid)
      MODE="rto_calibration_grid"
      OUTPUT_TAG="20260611"
      TCP5_ATTACK5_MODE=1
      RTO_CALIBRATION_MODE=1
      SEED_VALUES=(1)
      DURATION_SEC="20"
      ATTACK_START_SEC="5"
      EVALUATION_START_SEC="7"
      EVALUATION_END_SEC="18"
      BOTTLENECK_MBPS="15"
      PERIOD_MS="1000"
      BUCKET_MS="25"
      TCP_INFO_INTERVAL_MS="50"
      TCP_TARGET_MBPS="5"
      RTO_PEAK_VALUES=(15 30 45 60)
      RTO_QUEUE_VALUES=(50 100 200)
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
    --evaluation-start-sec)
      EVALUATION_START_SEC="$2"
      shift 2
      ;;
    --evaluation-end-sec)
      EVALUATION_END_SEC="$2"
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
    --tcp-target-mbps)
      TCP_TARGET_MBPS="$2"
      shift 2
      ;;
    --tcp-pacing-timer-us)
      TCP_PACING_TIMER_US="$2"
      shift 2
      ;;
    --queue-limit-packets)
      QUEUE_LIMIT_PACKETS="$2"
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
  OUTPUT_DIR="${SCRIPT_DIR}/out/$(date +%Y%m%d_%H%M%S)"
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
printf '%q ' "$0" "${ORIGINAL_ARGS[@]}" > "${OUTPUT_DIR}/command_${OUTPUT_TAG}.txt"
printf '\n' >> "${OUTPUT_DIR}/command_${OUTPUT_TAG}.txt"
git -C "${REPO_ROOT}" rev-parse HEAD > "${OUTPUT_DIR}/git_commit_${OUTPUT_TAG}.txt" 2>/dev/null || true
"${PYTHON_BIN}" -m pip freeze > "${OUTPUT_DIR}/pip_freeze_${OUTPUT_TAG}.txt" 2>/dev/null || true

"${PYTHON_BIN}" - "${OUTPUT_DIR}" "${BOTTLENECK_MBPS}" "${PERIOD_MS}" "${MAX_CASES}" "${PEAK_MULTIPLIER_VALUES[*]-}" "${DUTY_RATIO_VALUES[*]-}" "${TCP5_ATTACK5_MODE}" "${OUTPUT_TAG}" "${RTO_CALIBRATION_MODE}" "${RTO_PEAK_VALUES[*]-}" "${RTO_QUEUE_VALUES[*]-}" <<'PY'
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
from metrics import average_attack_rate_mbps, configured_average_attack_pct, focused_conditions

out_dir = Path(sys.argv[1])
bottleneck = float(sys.argv[2])
period_ms = float(sys.argv[3])
max_cases = int(sys.argv[4]) if sys.argv[4] else None
peak_values = [float(x) for x in sys.argv[5].split()] if sys.argv[5].strip() else []
duty_values = [float(x) for x in sys.argv[6].split()] if len(sys.argv) > 6 and sys.argv[6].strip() else []
tcp5_attack5 = int(sys.argv[7]) == 1
output_tag = sys.argv[8]
rto_calibration = int(sys.argv[9]) == 1
rto_peaks = [float(x) for x in sys.argv[10].split()] if len(sys.argv) > 10 and sys.argv[10].strip() else []
rto_queues = [int(float(x)) for x in sys.argv[11].split()] if len(sys.argv) > 11 and sys.argv[11].strip() else []
if rto_calibration:
    rows = []
    for peak_rate in rto_peaks:
        burst_ms = 1000.0 * 5.0 / peak_rate
        for queue in rto_queues:
            rows.append({
                "condition_id": f"rto_peak{int(peak_rate)}_queue{queue}",
                "peak_multiplier": peak_rate / bottleneck,
                "duty_ratio": burst_ms / period_ms,
                "peak_rate_mbps": peak_rate,
                "burst_ms": burst_ms,
                "period_ms": period_ms,
                "configured_average_attack_mbps": 5.0,
                "configured_average_attack_pct": configured_average_attack_pct(5.0, bottleneck),
                "configured_queue_packets": queue,
            })
elif tcp5_attack5:
    peak_rate = 15.0
    burst_ms = 1000.0 / 3.0
    avg = average_attack_rate_mbps(peak_rate, burst_ms, period_ms)
    rows = [{
        "condition_id": "tcp5_attack5",
        "peak_multiplier": peak_rate / bottleneck,
        "duty_ratio": burst_ms / period_ms,
        "peak_rate_mbps": peak_rate,
        "burst_ms": burst_ms,
        "period_ms": period_ms,
        "configured_average_attack_mbps": avg,
        "configured_average_attack_pct": configured_average_attack_pct(avg, bottleneck),
        "configured_queue_packets": "",
    }]
elif peak_values or duty_values:
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
                    "configured_queue_packets": "",
                })
else:
    rows = focused_conditions(bottleneck, period_ms)
    for row in rows:
        row["configured_queue_packets"] = ""
if max_cases is not None:
    rows = rows[:max_cases]
path = out_dir / f"condition_grid_{output_tag}.csv"
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
        "configured_queue_packets",
    ]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
print(path)
PY

cat > "${OUTPUT_DIR}/metadata_${OUTPUT_TAG}.json" <<META
{
  "created_date": "${OUTPUT_TAG:0:4}-${OUTPUT_TAG:4:2}-${OUTPUT_TAG:6:2}",
  "purpose": "25 ms detector window comparison experiment",
  "pipeline_name": "ldos_bandwidth_${OUTPUT_TAG}",
  "mode": "${MODE}",
  "tcp5_attack5_mode": ${TCP5_ATTACK5_MODE},
  "rto_calibration_mode": ${RTO_CALIBRATION_MODE},
  "synthetic_test": ${SYNTHETIC_TEST},
  "bottleneck_mbps": ${BOTTLENECK_MBPS},
  "period_ms": ${PERIOD_MS},
  "duration_sec": ${DURATION_SEC},
  "attack_start_sec": ${ATTACK_START_SEC},
  "evaluation_start_sec": ${EVALUATION_START_SEC:-null},
  "evaluation_end_sec": ${EVALUATION_END_SEC:-null},
  "bucket_ms": ${BUCKET_MS},
  "tcp_target_mbps": ${TCP_TARGET_MBPS:-null},
  "tcp_info_interval_ms": ${TCP_INFO_INTERVAL_MS},
  "collect_tcp_info": ${COLLECT_TCP_INFO},
  "rto_causal_window_ms": ${RTO_CAUSAL_WINDOW_MS},
  "disable_offloads": ${DISABLE_OFFLOADS}
}
META

CONDITION_LINES=()
while IFS= read -r line; do
  CONDITION_LINES+=("${line}")
done < <(tail -n +2 "${OUTPUT_DIR}/condition_grid_${OUTPUT_TAG}.csv")
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
  local queue_packets="${9:-}"
  local case_id="${condition_id}_${scenario}_seed${seed}_${OUTPUT_TAG}"
  local args=(
    "${PYTHON_BIN}" "${SCRIPT_DIR}/run.py"
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
    --output-tag "${OUTPUT_TAG}"
    --existing-repo-dir "${EXISTING_REPO_DIR}"
  )
  if [[ -n "${EVALUATION_START_SEC}" ]]; then
    args+=(--evaluation-start-sec "${EVALUATION_START_SEC}")
  fi
  if [[ -n "${EVALUATION_END_SEC}" ]]; then
    args+=(--evaluation-end-sec "${EVALUATION_END_SEC}")
  fi
  if [[ -n "${TCP_TARGET_MBPS}" ]]; then
    args+=(--tcp-target-mbps "${TCP_TARGET_MBPS}")
  fi
  if [[ -n "${TCP_PACING_TIMER_US}" ]]; then
    args+=(--tcp-pacing-timer-us "${TCP_PACING_TIMER_US}")
  fi
  if [[ -n "${queue_packets}" ]]; then
    args+=(--queue-limit-packets "${queue_packets}")
  elif [[ -n "${QUEUE_LIMIT_PACKETS}" ]]; then
    args+=(--queue-limit-packets "${QUEUE_LIMIT_PACKETS}")
  fi
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
    return 1
  fi
  return 0
}

validate_tcp5_no_attack_seed() {
  local seed="$1"
  local case_id="${2:-baseline_no_attack_seed${seed}_${OUTPUT_TAG}}"
  local iperf_json="${OUTPUT_DIR}/cases/${case_id}/raw/iperf/iperf_client_${OUTPUT_TAG}.json"
  "${PYTHON_BIN}" - "${iperf_json}" "${OUTPUT_DIR}/csv/tcp_rate_validation_precheck_${OUTPUT_TAG}.csv" "${case_id}" "${seed}" "${TCP_TARGET_MBPS}" <<'PY'
import csv
import json
import math
import sys
from pathlib import Path

iperf_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
case_id = sys.argv[3]
seed = sys.argv[4]
target = float(sys.argv[5])
measured = math.nan
if iperf_path.exists():
    try:
        data = json.loads(iperf_path.read_text())
        end = data.get("end", {})
        candidates = [
            end.get("sum_received", {}).get("bits_per_second"),
            end.get("sum", {}).get("bits_per_second"),
            end.get("streams", [{}])[0].get("receiver", {}).get("bits_per_second") if end.get("streams") else None,
        ]
        for value in candidates:
            if value is not None:
                measured = float(value) / 1_000_000.0
                break
    except Exception:
        measured = math.nan
error_pct = 100.0 * (measured - target) / target if target > 0 and not math.isnan(measured) else math.nan
abs_error = abs(error_pct) if not math.isnan(error_pct) else math.inf
status = "failed"
if abs_error <= 5.0:
    status = "matched"
elif abs_error <= 10.0:
    status = "warning"
out_path.parent.mkdir(parents=True, exist_ok=True)
new_file = not out_path.exists()
with out_path.open("a", newline="") as handle:
    fields = ["case_id", "seed", "target_tcp_mbps", "measured_tcp_receiver_mbps", "tcp_rate_error_pct", "tcp_rate_match_status"]
    writer = csv.DictWriter(handle, fieldnames=fields)
    if new_file:
        writer.writeheader()
    writer.writerow({
        "case_id": case_id,
        "seed": seed,
        "target_tcp_mbps": f"{target:.9g}",
        "measured_tcp_receiver_mbps": "" if math.isnan(measured) else f"{measured:.9g}",
        "tcp_rate_error_pct": "" if math.isnan(error_pct) else f"{error_pct:.9g}",
        "tcp_rate_match_status": status,
    })
print(status)
PY
}

if [[ "${RTO_CALIBRATION_MODE}" -eq 1 ]]; then
  for line in "${CONDITION_LINES[@]}"; do
    line="${line%$'\r'}"
    IFS=',' read -r condition_id peak_multiplier duty_ratio peak_rate burst_ms period_ms avg_attack avg_pct queue_packets <<<"${line}"
    for seed in "${SEED_VALUES[@]}"; do
      baseline_case_id="${condition_id}_no_attack_seed${seed}_${OUTPUT_TAG}"
      if run_case "no_attack" "${condition_id}" "${seed}" "${peak_rate}" "${burst_ms}" "${period_ms}" "${duty_ratio}" "0" "${queue_packets}"; then
        status="$(validate_tcp5_no_attack_seed "${seed}" "${baseline_case_id}")"
        echo "TCP baseline validation condition=${condition_id} seed=${seed}: ${status}"
        if [[ "${status}" == "failed" ]]; then
          echo "Skipping periodic case for ${condition_id} seed=${seed}: no_attack TCP is outside ±10% of ${TCP_TARGET_MBPS} Mbps" >&2
          FAILED_CASES+=("${condition_id}_seed${seed}_tcp_baseline_validation_failed")
        else
          run_case "periodic_ldos" "${condition_id}" "${seed}" "${peak_rate}" "${burst_ms}" "${period_ms}" "${duty_ratio}" "${avg_attack}" "${queue_packets}"
        fi
      fi
    done
  done
else
  VALID_SEEDS=()
  for seed in "${SEED_VALUES[@]}"; do
    if run_case "no_attack" "baseline" "${seed}" "${BOTTLENECK_MBPS}" "100" "${PERIOD_MS}" "0.1" "0"; then
      if [[ "${TCP5_ATTACK5_MODE}" -eq 1 ]]; then
        status="$(validate_tcp5_no_attack_seed "${seed}")"
        echo "TCP baseline validation seed=${seed}: ${status}"
        if [[ "${status}" == "failed" ]]; then
          echo "Skipping attack cases for seed=${seed}: no_attack TCP is outside ±10% of ${TCP_TARGET_MBPS} Mbps" >&2
          FAILED_CASES+=("seed${seed}_tcp_baseline_validation_failed")
        else
          VALID_SEEDS+=("${seed}")
        fi
      else
        VALID_SEEDS+=("${seed}")
      fi
    fi
  done

  for line in "${CONDITION_LINES[@]}"; do
    line="${line%$'\r'}"
    IFS=',' read -r condition_id peak_multiplier duty_ratio peak_rate burst_ms period_ms avg_attack avg_pct queue_packets <<<"${line}"
    for seed in "${VALID_SEEDS[@]}"; do
      for scenario in "${SCENARIOS[@]}"; do
        run_case "${scenario}" "${condition_id}" "${seed}" "${peak_rate}" "${burst_ms}" "${period_ms}" "${duty_ratio}" "${avg_attack}" "${queue_packets}"
      done
    done
  done
fi

: > "${OUTPUT_DIR}/failed_cases_${OUTPUT_TAG}.txt"
if [[ ${#FAILED_CASES[@]} -gt 0 ]]; then
  printf '%s\n' "${FAILED_CASES[@]}" > "${OUTPUT_DIR}/failed_cases_${OUTPUT_TAG}.txt"
fi

if [[ "${RTO_CALIBRATION_MODE}" -eq 1 ]]; then
  "${PYTHON_BIN}" "${SCRIPT_DIR}/analyze_rto_calibration.py" \
    --results-dir "${OUTPUT_DIR}" \
    --bucket-ms "${BUCKET_MS}" \
    --bottleneck-mbps "${BOTTLENECK_MBPS}" \
    --evaluation-start-sec "${EVALUATION_START_SEC}" \
    --evaluation-end-sec "${EVALUATION_END_SEC}" \
    --tcp-target-mbps "${TCP_TARGET_MBPS}" \
    --attack-target-mbps "5" \
    --output-tag "${OUTPUT_TAG}" \
    --mode "${MODE}"
elif [[ "${TCP5_ATTACK5_MODE}" -eq 1 ]]; then
  "${PYTHON_BIN}" "${SCRIPT_DIR}/analyze_tcp5_attack5.py" \
    --results-dir "${OUTPUT_DIR}" \
    --bucket-ms "${BUCKET_MS}" \
    --bottleneck-mbps "${BOTTLENECK_MBPS}" \
    --evaluation-start-sec "${EVALUATION_START_SEC}" \
    --evaluation-end-sec "${EVALUATION_END_SEC}" \
    --tcp-target-mbps "${TCP_TARGET_MBPS}" \
    --attack-target-mbps "5" \
    --output-tag "${OUTPUT_TAG}" \
    --mode "${MODE}"
else
  "${PYTHON_BIN}" "${SCRIPT_DIR}/analyze.py" \
    --results-dir "${OUTPUT_DIR}" \
    --bucket-ms "${BUCKET_MS}" \
    --bottleneck-mbps "${BOTTLENECK_MBPS}"

  "${PYTHON_BIN}" "${SCRIPT_DIR}/analyze_tcp_rto.py" \
    --results-dir "${OUTPUT_DIR}" \
    --rto-causal-window-ms "${RTO_CAUSAL_WINDOW_MS}" \
    --period-ms "${PERIOD_MS}"

  "${PYTHON_BIN}" "${SCRIPT_DIR}/plot_bandwidth.py" \
    --input-dir "${OUTPUT_DIR}/csv" \
    --output-dir "${OUTPUT_DIR}/figures" \
    --results-dir "${OUTPUT_DIR}" \
    --bottleneck-mbps "${BOTTLENECK_MBPS}" \
    --attack-start-sec "${ATTACK_START_SEC}"

  "${PYTHON_BIN}" "${SCRIPT_DIR}/plot_tcp_rto.py" \
    --input-dir "${OUTPUT_DIR}/csv" \
    --output-dir "${OUTPUT_DIR}/figures" \
    --bottleneck-mbps "${BOTTLENECK_MBPS}"
fi

"${PYTHON_BIN}" - "${OUTPUT_DIR}" "${OUTPUT_TAG}" "${TCP5_ATTACK5_MODE}" <<'PY'
import csv
import math
import sys
from pathlib import Path

out = Path(sys.argv[1])
tag = sys.argv[2]
tcp5 = int(sys.argv[3]) == 1
case_path = out / "csv" / f"case_metrics_{tag}.csv"
rows = []
if case_path.exists():
    with case_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
summary = [
    "# LDoS Bandwidth Experiment Summary",
    "",
    f"Created: {tag[:4]}-{tag[4:6]}-{tag[6:8]}",
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
if not tcp5:
    (out / f"summary_{tag}.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
PY

cat > "${OUTPUT_DIR}/README_${OUTPUT_TAG}.txt" <<README
Created: ${OUTPUT_TAG:0:4}-${OUTPUT_TAG:4:2}-${OUTPUT_TAG:6:2}
Purpose: 25 ms detector window comparison experiment.

Pipeline: ldos_bandwidth_${OUTPUT_TAG}
Output directory: ${OUTPUT_DIR}

CSV outputs are in csv/.
Figures are in figures/.
Case raw data and metadata are in cases/<case_id>/.
README

if [[ ${#FAILED_CASES[@]} -gt 0 ]]; then
  printf '%s\n' "${FAILED_CASES[@]}" > "${OUTPUT_DIR}/failed_cases_${OUTPUT_TAG}.txt"
  echo "Pipeline finished with failed cases:"
  printf '  %s\n' "${FAILED_CASES[@]}"
  exit 1
fi

echo "LDoS bandwidth pipeline finished: $(date '+%Y-%m-%dT%H:%M:%S%z')"
echo "Output directory: ${OUTPUT_DIR}"
if [[ "${MODE}" == "tcp5_attack5_smoke" ]]; then
  echo "Smoke completed. Focused command:"
  echo "sudo ./exp/bandwidth_utilization_20260610/run.sh --tcp5-attack5-focused --existing-repo-dir \"${EXISTING_REPO_DIR}\""
fi
