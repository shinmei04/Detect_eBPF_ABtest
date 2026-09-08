#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date +%Y%m%d_%H%M%S)"
output_root="${repo_root}/exp/dpsws_microburst_20260726/out/${timestamp}"

cd "${repo_root}"
mkdir -p "${output_root}/runs"
for trial in $(seq 1 10); do
  .venv/bin/python exp/dpsws_microburst_20260726/run.py \
    --trial "${trial}" \
    --output-dir "${output_root}/runs/microburst_trial_${trial}"
done
.venv/bin/python exp/dpsws_microburst_20260726/analyze.py "${output_root}"

