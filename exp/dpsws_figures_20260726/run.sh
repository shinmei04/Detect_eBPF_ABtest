#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date +%Y%m%d_%H%M%S)"
output_dir="${repo_root}/exp/dpsws_figures_20260726/out/${timestamp}"

cd "${repo_root}"
exec .venv/bin/python exp/dpsws_figures_20260726/run.py --output-dir "${output_dir}" "$@"

