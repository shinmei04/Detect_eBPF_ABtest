#!/usr/bin/env python3
"""Run one avg10 benign microburst with a wider, equal-mean interval range."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = REPO_ROOT / "experiments/main_ldos_tcp6m/scripts"
SOURCE_RUNNER = SOURCE_DIR / "run_experiment.py"
SENDER_BINARY = SOURCE_DIR / "udp_pulse_sender_binary"
RANDOM_SEED_ARGUMENT = 20260718
INTERVAL_MIN_MS = 50.0
INTERVAL_MAX_MS = 300.0


def load_runner():
    spec = importlib.util.spec_from_file_location("dpsws_main_run_experiment", SOURCE_RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SOURCE_RUNNER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runner = load_runner()
    if not SENDER_BINARY.is_file():
        raise SystemExit(f"missing existing UDP sender binary: {SENDER_BINARY}")
    runner.SENDER_BIN = SENDER_BINARY
    original_build_cases = runner.build_cases

    def build_wide_interval_case(source_args):
        cases = original_build_cases(source_args)
        source_args.tcp_target_mbps = None
        selected = [case for case in cases if case.case_id == "train_random_avg10"]
        if len(selected) != 1:
            raise RuntimeError(f"expected one train_random_avg10 case, got {len(selected)}")
        case = selected[0]
        case.tcp_target_mbps = None
        case.random_interval_min_ms = INTERVAL_MIN_MS
        case.random_interval_max_ms = INTERVAL_MAX_MS
        case.case_id = "random_benign_avg10_tcp_unlimited_i50_300_trial_1"
        case.condition_key = "c15_tcp_unlimited_random_avg10_r15_b5_30_i50_300"
        return selected

    runner.build_cases = build_wide_interval_case
    source_argv = [
        str(SOURCE_RUNNER), "--preset", "c15_train_candidates",
        "--random-seed", str(RANDOM_SEED_ARGUMENT),
        "--output-dir", str(args.output_dir.resolve()), "--fast", "--no-plots",
    ]
    old_argv = sys.argv
    try:
        sys.argv = source_argv
        return int(runner.main())
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    raise SystemExit(main())

