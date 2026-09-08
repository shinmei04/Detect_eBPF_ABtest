#!/usr/bin/env python3
"""Run one DPSWS TCP-unlimited trial using the adopted main experiment."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = REPO_ROOT / "experiments" / "main_ldos_tcp6m" / "scripts"
SOURCE_RUNNER = SOURCE_DIR / "run_experiment.py"
SENDER_BINARY = SOURCE_DIR / "udp_pulse_sender_binary"


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
    parser.add_argument("--condition", choices=["baseline", "ldos"], required=True)
    parser.add_argument("--trial", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.trial < 1:
        raise SystemExit("--trial must be positive")
    runner = load_runner()
    if not SENDER_BINARY.is_file():
        raise SystemExit(f"missing existing UDP sender binary: {SENDER_BINARY}")
    runner.SENDER_BIN = SENDER_BINARY
    original_build_cases = runner.build_cases

    def build_tcp_unlimited_case(source_args):
        cases = original_build_cases(source_args)
        source_args.tcp_target_mbps = None
        wanted_type = "base" if args.condition == "baseline" else "periodic_ldos"
        selected = [case for case in cases if case.case_type == wanted_type]
        if len(selected) != 1:
            raise RuntimeError(f"expected one {wanted_type} case, got {len(selected)}")
        case = selected[0]
        case.tcp_target_mbps = None
        if args.condition == "baseline":
            case.case_id = f"baseline_tcp_unlimited_trial_{args.trial}"
            case.condition_key = "c15_tcp_unlimited"
        else:
            case.case_id = f"periodic_ldos_tcp_unlimited_r15_l300_t1000_trial_{args.trial}"
            case.condition_key = "c15_tcp_unlimited_r15_l300_t1000"
        return selected

    runner.build_cases = build_tcp_unlimited_case
    source_argv = [
        str(SOURCE_RUNNER),
        "--preset",
        "c15_tcp6m_avg30",
        "--output-dir",
        str(args.output_dir.resolve()),
        "--fast",
        "--no-plots",
    ]
    old_argv = sys.argv
    try:
        sys.argv = source_argv
        return int(runner.main())
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    raise SystemExit(main())
