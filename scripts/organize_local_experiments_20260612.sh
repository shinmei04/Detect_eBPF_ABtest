#!/usr/bin/env bash
# Organize local-only experiment artifacts.  This intentionally moves ignored
# result directories out of the repository root without deleting them.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="${ROOT_DIR}/local_experiment_workspace"

mkdir -p \
  "${WORKSPACE}/00_ab_throughput_tradeoff" \
  "${WORKSPACE}/01_phaseaware_ldos" \
  "${WORKSPACE}/02_bandwidth_20260610" \
  "${WORKSPACE}/03_tcp5_rto_20260611" \
  "${WORKSPACE}/archive_legacy_code" \
  "${WORKSPACE}/logs"

move_if_exists() {
  local src="$1"
  local dst="$2"
  local src_path="${ROOT_DIR}/${src}"
  local dst_path="${WORKSPACE}/${dst}"
  if [[ -e "${src_path}" || -L "${src_path}" ]]; then
    if [[ -e "${dst_path}/$(basename "${src}")" || -L "${dst_path}/$(basename "${src}")" ]]; then
      echo "skip existing: ${dst}/$(basename "${src}")"
    else
      echo "move: ${src} -> local_experiment_workspace/${dst}/"
      mv "${src_path}" "${dst_path}/"
    fi
  fi
}

move_if_exists "results_mininet_ab" "00_ab_throughput_tradeoff"
move_if_exists "results_throughput" "00_ab_throughput_tradeoff"
move_if_exists "results_throughput_sweep" "00_ab_throughput_tradeoff"
move_if_exists "results_tradeoff" "00_ab_throughput_tradeoff"

move_if_exists "results_flddos_phaseaware_onecase" "01_phaseaware_ldos"
move_if_exists "results_phaseaware_grid_54_20260604_155650" "01_phaseaware_ldos"
move_if_exists "results_phaseaware_grid_63_20260604_155530" "01_phaseaware_ldos"

move_if_exists "results_bandwidth_20260610_20260610_142104" "02_bandwidth_20260610"
move_if_exists "results_bandwidth_20260610_20260610_142643" "02_bandwidth_20260610"
move_if_exists "results_bandwidth_20260610_iprerun" "02_bandwidth_20260610"
move_if_exists "experiment_archive_20260610" "02_bandwidth_20260610"
move_if_exists "experiment_archive_20260610_iprerun" "02_bandwidth_20260610"

move_if_exists "results_tcp5_attack5_20260611_20260611_153019" "03_tcp5_rto_20260611"
move_if_exists "results_rto_calibration_20260611_20260611_165912" "03_tcp5_rto_20260611"
move_if_exists "results_rto_calibration_20260611_20260611_170800" "03_tcp5_rto_20260611"

move_if_exists "run_phaseaware_grid_54.sh" "archive_legacy_code"
move_if_exists "run_phaseaware_grid_63.sh" "archive_legacy_code"

move_if_exists "focused_20260610_20260610_142643.log" "logs"
move_if_exists "results_phaseaware_grid_54_20260604_155650.log" "logs"
move_if_exists "results_phaseaware_grid_63_20260604_155530.log" "logs"
move_if_exists "rto_calibration_grid_20260611_165912.log" "logs"
move_if_exists "rto_calibration_grid_20260611_170800.log" "logs"

cat > "${WORKSPACE}/README.md" <<'README'
# Local Experiment Workspace

This directory is intentionally ignored by Git.  It keeps large local
experiment artifacts out of the repository root while preserving them on disk.

## Layout

- `00_ab_throughput_tradeoff/`: AB test, throughput, sweep, and tradeoff runs.
- `01_phaseaware_ldos/`: phase-aware and F-LDDoS exploratory runs.
- `02_bandwidth_20260610/`: 20260610 bandwidth runs and pcap reanalysis archives.
- `03_tcp5_rto_20260611/`: TCP=5 Mbps / attack=5 Mbps and RTO calibration runs.
- `archive_legacy_code/`: older one-off launcher scripts that are not part of
  the current pipeline.
- `logs/`: top-level run logs moved out of the repository root.

Current maintained experiment code lives in:

- `bandwidth_20260610_exp/`
- `mininet_experiment/`
- `src/`
- `scripts/`
README

if compgen -G "${WORKSPACE}/archive_legacy_code/*.sh" > /dev/null; then
  find "${WORKSPACE}/archive_legacy_code" -maxdepth 1 -type f -name "*.sh" -printf "%f\0" \
    | tar --null -czf "${WORKSPACE}/archive_legacy_code/legacy_experiment_code_20260612.tar.gz" \
      -C "${WORKSPACE}/archive_legacy_code" \
      -T -
fi

echo
echo "Organized local experiment artifacts under: ${WORKSPACE}"
find "${WORKSPACE}" -maxdepth 2 -mindepth 1 -type d | sort
