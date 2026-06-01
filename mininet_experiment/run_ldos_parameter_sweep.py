"""Sweep LDoS burst/payload parameters for TCP throughput degradation."""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path
from typing import Any

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MININET_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(MININET_ROOT) not in sys.path:
    sys.path.insert(0, str(MININET_ROOT))

from run_throughput_impact_experiment import (
    assert_mininet_environment,
    run_one_scenario,
    synthetic_throughput,
    synthetic_windows,
    validate_args,
    write_aggregate_outputs,
)
from src.throughput_impact import (
    build_confusion_matrices,
    build_detector_metrics,
    build_missed_harmful_windows,
    build_throughput_metrics,
)
from src.throughput_sweep import scenario_summary_row, write_sweep_outputs
from src.utils import ensure_dir


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Sweep original_like LDoS parameters for TCP degradation.")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--attack-start-sec", type=float, default=20.0)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--period-ms", type=int, default=1000)
    parser.add_argument("--burst-ms", type=int, default=200)
    parser.add_argument("--burst-pkts-per-bucket-values", type=int, nargs="+", default=[10, 20, 30, 40])
    parser.add_argument("--payload-size-values", type=int, nargs="+", default=[80, 200, 400, 800])
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--warmup-windows", type=int, default=20)
    parser.add_argument("--score-threshold", type=int, default=2)
    parser.add_argument("--min-packets-for-detection", type=int, default=10)
    parser.add_argument(
        "--detector-profile",
        choices=["current", "phase3"],
        default="current",
        help="Use current throughput-impact evaluation or Phase3-compatible UDP baseline/labeling.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("results_throughput_sweep"))
    parser.add_argument(
        "--synthetic-test",
        action="store_true",
        help="Generate deterministic synthetic sweep outputs without Mininet; for local smoke tests only.",
    )
    return parser.parse_args()


def main() -> None:
    """Run the parameter sweep."""
    args = parse_args()
    validate_sweep_args(args)
    output_dir = ensure_dir(args.output_dir)
    if args.synthetic_test:
        run_synthetic_sweep(args, output_dir)
    else:
        run_mininet_sweep(args, output_dir)


def validate_sweep_args(args: argparse.Namespace) -> None:
    """Validate sweep-specific arguments."""
    base = copy.copy(args)
    base.payload_size = max(args.payload_size_values)
    base.burst_pkts_per_bucket = max(args.burst_pkts_per_bucket_values)
    validate_args(base)
    if any(value <= 0 for value in args.burst_pkts_per_bucket_values):
        raise SystemExit("--burst-pkts-per-bucket-values must be positive")
    if any(value <= 0 for value in args.payload_size_values):
        raise SystemExit("--payload-size-values must be positive")


def run_mininet_sweep(args: argparse.Namespace, output_dir: Path) -> None:
    """Run the sweep in a WSL2/Ubuntu Mininet environment."""
    assert_mininet_environment()
    from mininet.clean import cleanup
    from mininet.link import TCLink
    from mininet.net import Mininet

    from minimal_topo import MinimalABTopo

    cleanup()
    network: Mininet | None = None
    rows: list[dict[str, Any]] = []
    try:
        network = Mininet(topo=MinimalABTopo(), link=TCLink, autoSetMacs=True, autoStaticArp=True)
        network.start()
        baseline_args = make_run_args(args, burst_pkts_per_bucket=0, payload_size=0)
        no_attack_ts, no_attack_windows = run_one_scenario(
            network,
            "no_attack",
            baseline_args,
            ensure_dir(output_dir / "no_attack"),
        )
        baseline_tables = build_tables([no_attack_ts], [no_attack_windows], args.attack_start_sec)
        rows.append(
            scenario_summary_row(
                "no_attack",
                0,
                0,
                baseline_tables["throughput_metrics"],
                baseline_tables["detector_metrics"],
                baseline_tables["missed_harmful"],
            )
        )

        best: dict[str, Any] | None = None
        for burst in args.burst_pkts_per_bucket_values:
            for payload in args.payload_size_values:
                run_args = make_run_args(args, burst, payload)
                scenario_dir = ensure_dir(output_dir / f"original_like_burst_{burst}_payload_{payload}")
                timeseries, windows = run_one_scenario(network, "original_like_ldos", run_args, scenario_dir)
                tables = build_tables([no_attack_ts, timeseries], [no_attack_windows, windows], args.attack_start_sec)
                write_aggregate_outputs(
                    scenario_dir,
                    [no_attack_ts, timeseries],
                    [no_attack_windows, windows],
                    notes=[
                        f"detector_profile: {args.detector_profile}",
                        f"parameter sweep original_like_ldos burst={burst}, payload={payload}",
                    ],
                    attack_start_sec=args.attack_start_sec,
                )
                row = scenario_summary_row(
                    "original_like_ldos",
                    burst,
                    payload,
                    tables["throughput_metrics"],
                    tables["detector_metrics"],
                    tables["missed_harmful"],
                )
                rows.append(row)
                if best is None or row.get("throughput_degradation", -1.0) > best.get("throughput_degradation", -1.0):
                    best = row

        if best is not None:
            burst = int(best["burst_pkts_per_bucket"])
            payload = int(best["payload_size"])
            stat_args = make_run_args(args, burst, payload)
            scenario_dir = ensure_dir(output_dir / f"stat_matched_best_burst_{burst}_payload_{payload}")
            timeseries, windows = run_one_scenario(network, "stat_matched_ldos", stat_args, scenario_dir)
            tables = build_tables([no_attack_ts, timeseries], [no_attack_windows, windows], args.attack_start_sec)
            write_aggregate_outputs(
                scenario_dir,
                [no_attack_ts, timeseries],
                [no_attack_windows, windows],
                notes=[
                    f"detector_profile: {args.detector_profile}",
                    f"stat_matched_ldos using best original_like params burst={burst}, payload={payload}",
                ],
                attack_start_sec=args.attack_start_sec,
            )
            rows.append(
                scenario_summary_row(
                    "stat_matched_ldos",
                    burst,
                    payload,
                    tables["throughput_metrics"],
                    tables["detector_metrics"],
                    tables["missed_harmful"],
                    selected_best=True,
                )
            )
    finally:
        if network is not None:
            network.stop()
        cleanup()

    write_sweep_outputs(pd.DataFrame(rows), output_dir)


def run_synthetic_sweep(args: argparse.Namespace, output_dir: Path) -> None:
    """Generate deterministic synthetic sweep outputs without Mininet."""
    rows: list[dict[str, Any]] = []
    no_attack_args = make_run_args(args, 0, 0)
    no_attack_ts = synthetic_throughput("no_attack", args.duration_sec, args.attack_start_sec, 90.0)
    no_attack_windows = synthetic_windows("no_attack", no_attack_args, no_attack_ts)
    baseline_tables = build_tables([no_attack_ts], [no_attack_windows], args.attack_start_sec)
    rows.append(
        scenario_summary_row(
            "no_attack",
            0,
            0,
            baseline_tables["throughput_metrics"],
            baseline_tables["detector_metrics"],
            baseline_tables["missed_harmful"],
        )
    )

    best: dict[str, Any] | None = None
    for burst in args.burst_pkts_per_bucket_values:
        for payload in args.payload_size_values:
            run_args = make_run_args(args, burst, payload)
            attack_mbps = synthetic_attack_mbps(burst, payload, base_mbps=90.0, stat_matched=False)
            timeseries = synthetic_throughput("original_like_ldos", args.duration_sec, args.attack_start_sec, attack_mbps)
            windows = synthetic_windows("original_like_ldos", run_args, timeseries)
            tables = build_tables([no_attack_ts, timeseries], [no_attack_windows, windows], args.attack_start_sec)
            row = scenario_summary_row(
                "original_like_ldos",
                burst,
                payload,
                tables["throughput_metrics"],
                tables["detector_metrics"],
                tables["missed_harmful"],
            )
            rows.append(row)
            if best is None or row.get("throughput_degradation", -1.0) > best.get("throughput_degradation", -1.0):
                best = row

    if best is not None:
        burst = int(best["burst_pkts_per_bucket"])
        payload = int(best["payload_size"])
        stat_args = make_run_args(args, burst, payload)
        attack_mbps = synthetic_attack_mbps(burst, payload, base_mbps=90.0, stat_matched=True)
        timeseries = synthetic_throughput("stat_matched_ldos", args.duration_sec, args.attack_start_sec, attack_mbps)
        windows = synthetic_windows("stat_matched_ldos", stat_args, timeseries)
        tables = build_tables([no_attack_ts, timeseries], [no_attack_windows, windows], args.attack_start_sec)
        rows.append(
            scenario_summary_row(
                "stat_matched_ldos",
                burst,
                payload,
                tables["throughput_metrics"],
                tables["detector_metrics"],
                tables["missed_harmful"],
                selected_best=True,
            )
        )
    write_sweep_outputs(pd.DataFrame(rows), output_dir)


def synthetic_attack_mbps(burst: int, payload: int, base_mbps: float, stat_matched: bool) -> float:
    """Return synthetic attack-period Mbps for smoke testing the sweep path."""
    relative_load = (burst * payload) / (10 * 80)
    degradation = min(0.8, 0.015 + 0.055 * relative_load)
    if stat_matched:
        degradation *= 0.85
    return max(1.0, base_mbps * (1.0 - degradation))


def make_run_args(args: argparse.Namespace, burst_pkts_per_bucket: int, payload_size: int) -> argparse.Namespace:
    """Clone CLI args and install one burst/payload setting."""
    run_args = copy.copy(args)
    run_args.burst_pkts_per_bucket = int(burst_pkts_per_bucket)
    run_args.payload_size = int(payload_size)
    run_args.scenarios = []
    return run_args


def build_tables(
    timeseries_frames: list[pd.DataFrame],
    window_frames: list[pd.DataFrame],
    attack_start_sec: float,
) -> dict[str, pd.DataFrame]:
    """Build metric tables from one baseline plus one scenario."""
    timeseries = pd.concat(timeseries_frames, ignore_index=True)
    window_log = pd.concat(window_frames, ignore_index=True)
    throughput_metrics = build_throughput_metrics(timeseries, attack_start_sec)
    detector_metrics = build_detector_metrics(window_log, attack_start_sec)
    confusion_matrices = build_confusion_matrices(detector_metrics)
    missed_harmful = build_missed_harmful_windows(window_log)
    return {
        "timeseries": timeseries,
        "window_log": window_log,
        "throughput_metrics": throughput_metrics,
        "detector_metrics": detector_metrics,
        "confusion_matrices": confusion_matrices,
        "missed_harmful": missed_harmful,
    }


if __name__ == "__main__":
    main()
