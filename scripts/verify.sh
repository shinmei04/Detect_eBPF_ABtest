#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
python_bin="${PYTHON_BIN:-$repo_root/.venv/bin/python}"
if [[ ! -x "$python_bin" && -z "${PYTHON_BIN:-}" ]]; then python_bin=python3; fi
export PYTHONDONTWRITEBYTECODE=1
export MPLBACKEND=Agg
printf 'VERIFY Python: %s\n' "$python_bin"
# Required repository check, also covering non-exp entry points below.
python3 -m compileall -q exp src
"$python_bin" -m compileall -q scripts tests mininet_experiment experiments/main_ldos_tcp6m/scripts
"$python_bin" -m compileall -q experiments/dpsws_additional_eval_20260709 experiments/dpsws_random_and_sack_check_20260709 main.py
mapfile -d '' shell_files < <(find scripts exp mininet_experiment experiments -type f -name '*.sh' -print0)
for file in "${shell_files[@]}"; do bash -n "$file"; done
printf 'PASS Shell syntax: %s files\n' "${#shell_files[@]}"
# Separate processes avoid collisions between experiment-local analyze/run modules.
mapfile -t test_dirs < <(find tests exp mininet_experiment experiments -type f -name 'test_*.py' ! -path '*/out/*' ! -path '*/archive_unused/*' -printf '%h\n' | sort -u)
if [[ ${#test_dirs[@]} -eq 0 ]]; then echo 'No tests discovered' >&2; exit 1; fi
for directory in "${test_dirs[@]}"; do
  printf 'TEST %s\n' "$directory"
  "$python_bin" -m unittest discover -s "$directory" -p 'test_*.py' -v
done
# CLI/config validation only; does not launch experiments or write results.
for profile in smoke paper_reproduction frequency_comparison; do
  bash scripts/run_evaluation.sh --profile "$profile" --dry-run
done
printf 'PASS verify (no Mininet run; no pcap evaluation)\n'
