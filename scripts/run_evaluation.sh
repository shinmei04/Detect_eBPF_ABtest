#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
python_bin="${PYTHON_BIN:-$repo_root/.venv/bin/python}"
if [[ ! -x "$python_bin" && -z "${PYTHON_BIN:-}" ]]; then python_bin=python3; fi
export PYTHONDONTWRITEBYTECODE=1
export MPLBACKEND=Agg
exec "$python_bin" "$repo_root/exp/evaluation_harness_20260906/run.py" "$@"
