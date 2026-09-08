#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date +%Y%m%d_%H%M%S)"
output_root="${repo_root}/exp/microburst_interval_20260726/out/${timestamp}"

cd "${repo_root}"
.venv/bin/python exp/microburst_interval_20260726/run.py --output-dir "${output_root}/runs/wide_interval_trial_1"
.venv/bin/python exp/microburst_interval_20260726/analyze.py "${output_root}"

