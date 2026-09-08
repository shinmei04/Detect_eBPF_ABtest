#!/usr/bin/env python3
"""Reanalyze only the three saved TCP-unlimited LDoS pcaps at 25 ms."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ANALYZER = SCRIPT_DIR / "analyze.py"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("dpsws_integrated_analyzer", ANALYZER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ANALYZER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    output = args.output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    selected, _ = module.discover_trials(output)
    direct = module.load_module("dpsws_verified_25ms_existing", module.DIRECT_ANALYZER)
    trained, _, info = module.train_direct_detector(direct)
    train_hash = module.sha256(Path(info["pcap"]))
    if train_hash != module.EXPECTED_TRAIN_SHA256:
        raise AssertionError("training pcap hash mismatch")
    rows = [module.detector_row(selected[("ldos", trial)], trial, output, direct, trained) for trial in range(1, 4)]
    module.write_csv(output / "existing_3_detector_results_25ms.csv", rows, module.DETECTOR_FIELDS)
    module.copy_legacy(output, selected)
    module.write_detector_investigation(output / "detector_investigation.md", direct, train_hash)
    for row in rows:
        if row["attack_windows"] != 1600 or row["missing_timestamps"] or row["duplicate_timestamps"]:
            raise AssertionError(f"trial {row['trial']} failed 25 ms validation")
    print(f"EXISTING_RESULTS={output / 'existing_3_detector_results_25ms.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
