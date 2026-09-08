#!/usr/bin/env python3
"""Run one adopted benign avg10 microburst trial with unlimited TCP."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = REPO_ROOT / "experiments/main_ldos_tcp6m/scripts"
SOURCE_RUNNER = SOURCE_DIR / "run_experiment.py"
SENDER_BINARY = SOURCE_DIR / "udp_pulse_sender_binary"
BASE_RANDOM_SEED = 20260707


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
    parser.add_argument("--trial", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.trial <= 10:
        raise SystemExit("--trial must be in 1..10")
    runner = load_runner()
    if not SENDER_BINARY.is_file():
        raise SystemExit(f"missing existing UDP sender binary: {SENDER_BINARY}")
    runner.SENDER_BIN = SENDER_BINARY
    original_build_cases = runner.build_cases

    def build_tcp_unlimited_benign_case(source_args):
        cases = original_build_cases(source_args)
        source_args.tcp_target_mbps = None
        selected = [case for case in cases if case.case_id == "train_random_avg10"]
        if len(selected) != 1:
            raise RuntimeError(f"expected one train_random_avg10 case, got {len(selected)}")
        case = selected[0]
        case.tcp_target_mbps = None
        case.case_id = f"random_benign_avg10_tcp_unlimited_trial_{args.trial}"
        case.condition_key = "c15_tcp_unlimited_random_avg10_r15_b5_30_i140_210"
        return selected

    runner.build_cases = build_tcp_unlimited_benign_case
    source_argv = [
        str(SOURCE_RUNNER),
        "--preset", "c15_train_candidates",
        "--random-seed", str(BASE_RANDOM_SEED + args.trial),
        "--output-dir", str(args.output_dir.resolve()),
        "--fast", "--no-plots",
    ]
    old_argv = sys.argv
    try:
        sys.argv = source_argv
        return int(runner.main())
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    raise SystemExit(main())
