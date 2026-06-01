"""Run R/L/T/payload tradeoff experiments for stat-matched LDoS."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MININET_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(MININET_ROOT) not in sys.path:
    sys.path.insert(0, str(MININET_ROOT))

from pcap_to_features import build_features_from_pcap
from run_throughput_impact_experiment import (
    IPERF_PORT,
    UDP_PORT,
    assert_mininet_environment,
    build_no_attack_windows,
    parse_iperf_json,
    start_background,
    start_tcpdump,
    stop_background,
    synthetic_throughput,
    synthetic_windows,
    validate_args,
    wait_for_process,
)
from src.paper_reproduction_detector import PaperDetectorConfig, run_paper_detector_by_seed
from src.throughput_impact import (
    build_confusion_matrices,
    build_detector_metrics,
    build_missed_harmful_windows,
    build_throughput_metrics,
    enrich_window_predictions,
    write_throughput_outputs,
)
from src.tradeoff_analysis import (
    TradeoffCondition,
    build_tradeoff_conditions,
    compute_stat_match_metrics,
    condition_tradeoff_row,
    packets_from_csv,
    write_tradeoff_outputs,
)
from src.utils import ensure_dir


TRADEOFF_SCENARIOS = ["no_attack", "random_microburst_only", "original_like_ldos", "stat_matched_ldos"]


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Run stat-matching/TCP degradation/FNR tradeoff experiment.")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--attack-start-sec", type=float, default=20.0)
    parser.add_argument("--detector-profile", choices=["phase3", "current"], default="phase3")
    parser.add_argument("--grid-search", action="store_true")
    parser.add_argument("--attack-rate-mbps-values", type=float, nargs="+", default=[30, 60, 90, 120, 150])
    parser.add_argument("--burst-ms-values", type=int, nargs="+", default=[100, 150, 200, 250, 300, 400])
    parser.add_argument("--period-ms-values", type=int, nargs="+", default=[800, 1000, 1200, 1500])
    parser.add_argument("--payload-size-values", type=int, nargs="+", default=[80, 750, 1000, 1200, 1472])
    parser.add_argument("--attack-preset", choices=["none", "all_rto", "rto_2", "rto_3", "rto_4"], default="none")
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--warmup-windows", type=int, default=20)
    parser.add_argument("--score-threshold", type=int, default=2)
    parser.add_argument("--min-packets-for-detection", type=int, default=10)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--max-cases", type=int)
    parser.add_argument("--output-dir", type=Path, default=Path("results_tradeoff"))
    parser.add_argument("--synthetic-test", action="store_true", help="Generate deterministic outputs without Mininet.")
    return parser.parse_args()


def main() -> None:
    """Run the tradeoff experiment and aggregate results."""
    args = parse_args()
    validate_tradeoff_args(args)
    output_dir = ensure_dir(args.output_dir)
    conditions = build_tradeoff_conditions(
        attack_rates=args.attack_rate_mbps_values,
        burst_values=args.burst_ms_values,
        period_values=args.period_ms_values,
        payload_values=args.payload_size_values,
        include_grid=args.grid_search,
        attack_preset=args.attack_preset,
    )
    if args.max_cases is not None:
        conditions = conditions[: args.max_cases]
    if not conditions:
        raise SystemExit("No conditions selected. Use --grid-search or --attack-preset all_rto.")

    rows: list[pd.DataFrame] = []
    if args.synthetic_test:
        for condition in conditions:
            maybe = run_or_load_condition_synthetic(condition, args, output_dir)
            if maybe is not None:
                rows.append(maybe)
    else:
        rows.extend(run_mininet_conditions(conditions, args, output_dir))

    existing = sorted(output_dir.glob("*/tradeoff_condition_metrics.csv"))
    for path in existing:
        row = pd.read_csv(path)
        if not row.empty and row["condition_id"].iloc[0] not in {r["condition_id"].iloc[0] for r in rows}:
            rows.append(row)
    aggregate = pd.concat(rows, ignore_index=True) if rows else pd.DataFrame()
    if not aggregate.empty:
        aggregate = aggregate.drop_duplicates(subset=["condition_id"], keep="last")
    write_tradeoff_outputs(aggregate, output_dir)


def validate_tradeoff_args(args: argparse.Namespace) -> None:
    """Validate CLI args using throughput experiment validation shape."""
    args.burst_pkts_per_bucket = 1
    args.payload_size = max(args.payload_size_values) if args.payload_size_values else 80
    validate_args(args)
    if args.bucket_ms <= 0:
        raise SystemExit("--bucket-ms must be positive")
    if args.max_cases is not None and args.max_cases <= 0:
        raise SystemExit("--max-cases must be positive")


def run_mininet_conditions(
    conditions: list[TradeoffCondition],
    args: argparse.Namespace,
    output_dir: Path,
) -> list[pd.DataFrame]:
    """Run tradeoff conditions on Mininet."""
    assert_mininet_environment()
    from mininet.clean import cleanup
    from mininet.link import TCLink
    from mininet.net import Mininet

    from minimal_topo import MinimalABTopo

    cleanup()
    network: Mininet | None = None
    rows: list[pd.DataFrame] = []
    try:
        network = Mininet(topo=MinimalABTopo(), link=TCLink, autoSetMacs=True, autoStaticArp=True)
        network.start()
        for condition in conditions:
            condition_dir = ensure_dir(output_dir / condition.condition_id)
            row_path = condition_dir / "tradeoff_condition_metrics.csv"
            if args.resume and row_path.exists():
                rows.append(pd.read_csv(row_path))
                continue
            row = run_condition_mininet(network, condition, args, condition_dir)
            row_frame = pd.DataFrame([row])
            row_frame.to_csv(row_path, index=False)
            rows.append(row_frame)
    finally:
        if network is not None:
            network.stop()
        cleanup()
    return rows


def run_condition_mininet(
    network: Any,
    condition: TradeoffCondition,
    args: argparse.Namespace,
    condition_dir: Path,
) -> dict[str, Any]:
    """Run all scenarios for one condition and return aggregate tradeoff row."""
    metadata = {
        "condition_id": condition.condition_id,
        "attack_rate_mbps": condition.attack_rate_mbps,
        "burst_ms": condition.burst_ms,
        "period_ms": condition.period_ms,
        "payload_size": condition.payload_size,
        "preset": condition.preset,
        "detector_profile": args.detector_profile,
    }
    (condition_dir / "condition_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    timeseries_frames: list[pd.DataFrame] = []
    window_frames: list[pd.DataFrame] = []
    udp_summaries: list[dict[str, Any]] = []
    for scenario in TRADEOFF_SCENARIOS:
        scenario_dir = ensure_dir(condition_dir / scenario)
        timeseries, windows, summary = run_rate_scenario(network, scenario, condition, args, scenario_dir)
        timeseries_frames.append(timeseries)
        window_frames.append(windows)
        if summary:
            udp_summaries.append(summary)

    timeseries = pd.concat(timeseries_frames, ignore_index=True)
    window_log = pd.concat(window_frames, ignore_index=True)
    throughput_metrics = build_throughput_metrics(timeseries, args.attack_start_sec)
    detector_metrics = build_detector_metrics(window_log, args.attack_start_sec)
    confusion_matrices = build_confusion_matrices(detector_metrics)
    missed_harmful = build_missed_harmful_windows(window_log)
    write_throughput_outputs(
        output_dir=condition_dir,
        timeseries=timeseries,
        window_log=window_log,
        throughput_metrics=throughput_metrics,
        detector_metrics=detector_metrics,
        confusion_matrices=confusion_matrices,
        missed_harmful=missed_harmful,
        attack_start_sec=args.attack_start_sec,
        notes=[f"condition_id: {condition.condition_id}", "detector_profile: phase3-compatible" if args.detector_profile == "phase3" else "detector_profile: current"],
    )
    stat_windows = window_log[window_log["scenario"] == "stat_matched_ldos"].copy()
    stat_packets = packets_from_csv(condition_dir / "stat_matched_ldos" / "udp_packets_from_pcap.csv")
    stat_metrics = compute_stat_match_metrics(
        stat_windows,
        stat_packets,
        bucket_ms=args.bucket_ms,
        attack_start_sec=args.attack_start_sec,
        duration_sec=args.duration_sec,
        period_ms=condition.period_ms,
    )
    udp_metrics = aggregate_udp_metrics(udp_summaries)
    return condition_tradeoff_row(condition, throughput_metrics, detector_metrics, stat_metrics, udp_metrics)


def run_rate_scenario(
    network: Any,
    scenario: str,
    condition: TradeoffCondition,
    args: argparse.Namespace,
    scenario_dir: Path,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any] | None]:
    """Run one rate-based scenario in Mininet."""
    h1, h2, h3, h4 = [network.get(name) for name in ("h1", "h2", "h3", "h4")]
    send_log_dir = ensure_dir(scenario_dir / "send_logs")
    pcap_path = scenario_dir / f"{scenario}.pcap"
    iperf_json = scenario_dir / "iperf_client.json"
    sink_log = scenario_dir / "sink_log.csv"
    has_udp = scenario != "no_attack"
    iperf_server_pid = ""
    iperf_client_pid = ""
    tcpdump_pid = ""
    sink_pid = ""
    experiment_start_wall = 0.0
    attack_summary: dict[str, Any] | None = None
    try:
        iperf_server_pid = start_background(h2, ["iperf3", "-s", "-p", str(IPERF_PORT)], scenario_dir / "iperf_server.log")
        time.sleep(0.5)
        if has_udp:
            sink_pid = start_background(
                h2,
                [
                    py(),
                    str(MININET_ROOT / "traffic_generators" / "udp_sink.py"),
                    "--bind-ip",
                    "0.0.0.0",
                    "--port",
                    str(UDP_PORT),
                    "--duration-sec",
                    str(args.duration_sec + 5.0),
                    "--log",
                    str(sink_log),
                ],
                scenario_dir / "udp_sink.log",
            )
            tcpdump_pid = start_tcpdump(h2, pcap_path, scenario_dir / "tcpdump.log")
            time.sleep(0.5)
        iperf_client_pid = start_background(
            h1,
            ["iperf3", "-c", "10.0.0.2", "-p", str(IPERF_PORT), "-t", str(int(args.duration_sec)), "-i", "1", "-J"],
            iperf_json,
        )
        experiment_start_wall = time.time()
        attack_summary = run_udp_sequence(h3, h4, scenario, condition, args, send_log_dir, scenario_dir)
        wait_for_process(h1, iperf_client_pid)
        time.sleep(0.5)
    finally:
        stop_background(h1, iperf_client_pid)
        stop_background(h2, tcpdump_pid)
        stop_background(h2, sink_pid)
        stop_background(h2, iperf_server_pid)

    throughput = parse_iperf_json(iperf_json, scenario)
    throughput.to_csv(scenario_dir / "tcp_throughput_timeseries.csv", index=False)
    windows = build_windows_for_rate_scenario(scenario, condition, args, pcap_path, throughput, scenario_dir, experiment_start_wall)
    windows.to_csv(scenario_dir / "window_detailed_log.csv", index=False)
    return throughput, windows, attack_summary


def run_udp_sequence(
    h3: Any,
    h4: Any,
    scenario: str,
    condition: TradeoffCondition,
    args: argparse.Namespace,
    send_log_dir: Path,
    scenario_dir: Path,
) -> dict[str, Any] | None:
    """Run UDP sequence for a tradeoff scenario."""
    attack_duration = max(0.0, args.duration_sec - args.attack_start_sec)
    if scenario == "no_attack":
        return None
    if scenario == "random_microburst_only":
        time.sleep(args.attack_start_sec)
        return run_rate_generator(
            h4,
            "send_rate_random_microburst.py",
            condition,
            args,
            send_log_dir / "random_microburst_send_log.csv",
            scenario_dir / "random_microburst.summary.json",
            src_port=40004,
            duration_sec=attack_duration,
        )
    if scenario == "original_like_ldos":
        if args.detector_profile == "phase3":
            run_normal_benign(h4, args, send_log_dir / "normal_benign_baseline_send_log.csv", scenario_dir / "normal_benign_stdout.log", duration_sec=args.attack_start_sec)
        else:
            time.sleep(args.attack_start_sec)
        return run_rate_generator(
            h3,
            "send_rate_periodic_ldos.py",
            condition,
            args,
            send_log_dir / "periodic_ldos_attack_send_log.csv",
            scenario_dir / "periodic_ldos_attack.summary.json",
            src_port=40003,
            duration_sec=attack_duration,
        )
    if scenario == "stat_matched_ldos":
        if args.detector_profile == "phase3":
            run_rate_generator(
                h4,
                "send_rate_random_microburst.py",
                condition,
                args,
                send_log_dir / "random_microburst_baseline_send_log.csv",
                scenario_dir / "random_microburst_baseline.summary.json",
                src_port=40004,
                duration_sec=args.attack_start_sec,
            )
        else:
            time.sleep(args.attack_start_sec)
        return run_rate_generator(
            h3,
            "send_rate_periodic_ldos.py",
            condition,
            args,
            send_log_dir / "periodic_ldos_attack_send_log.csv",
            scenario_dir / "periodic_ldos_attack.summary.json",
            src_port=40003,
            duration_sec=attack_duration,
        )
    raise ValueError(f"unknown scenario: {scenario}")


def build_windows_for_rate_scenario(
    scenario: str,
    condition: TradeoffCondition,
    args: argparse.Namespace,
    pcap_path: Path,
    throughput: pd.DataFrame,
    scenario_dir: Path,
    experiment_start_wall: float,
) -> pd.DataFrame:
    """Build feature/detector windows for a rate-based scenario."""
    if scenario == "no_attack":
        return build_no_attack_windows(scenario, throughput, args.window_sec, args.step_sec, args.duration_sec, args.attack_start_sec)

    features, packets = build_features_from_pcap(
        pcap_path=pcap_path,
        bucket_ms=args.bucket_ms,
        window_sec=args.window_sec,
        step_sec=args.step_sec,
        duration_sec=args.duration_sec,
        attack_start_sec=args.attack_start_sec if scenario in {"original_like_ldos", "stat_matched_ldos"} else None,
        time_origin_sec=experiment_start_wall if experiment_start_wall > 0 else None,
        dst_port=UDP_PORT,
    )
    if scenario == "random_microburst_only":
        features["label"] = "benign"
    elif args.detector_profile == "phase3":
        features["label"] = np.where(features["window_start_sec"] >= args.attack_start_sec, "attack", "benign")
    else:
        features["label"] = np.where(features["window_end_sec"] > args.attack_start_sec, "attack", "benign")
    features["target"] = (features["label"] == "attack").astype(int)
    features.insert(0, "scenario", scenario)
    features.insert(1, "seed", args.seed)
    features["condition_id"] = condition.condition_id
    features["stream_id"] = f"{condition.condition_id}_{scenario}_seed_{args.seed}"
    features["stream_time_sec"] = features["window_start_sec"]
    features["stream_window_end_sec"] = features["window_end_sec"]
    features.to_csv(scenario_dir / "features.csv", index=False)
    packets.to_csv(scenario_dir / "udp_packets_from_pcap.csv", index=False)

    detector_config = PaperDetectorConfig(
        warmup_windows=args.warmup_windows,
        min_packets_for_detection=args.min_packets_for_detection,
        suspicious_threshold=args.score_threshold,
        use_observed_initial_state=True,
    )
    predictions = run_paper_detector_by_seed(features, detector_config)
    predictions.to_csv(scenario_dir / "predictions.csv", index=False)
    return enrich_window_predictions(scenario, predictions, throughput, args.attack_start_sec)


def run_rate_generator(
    host: Any,
    script_name: str,
    condition: TradeoffCondition,
    args: argparse.Namespace,
    send_log: Path,
    summary_json: Path,
    src_port: int,
    duration_sec: float,
) -> dict[str, Any]:
    """Run a rate-based UDP generator synchronously in a Mininet host."""
    command = [
        py(),
        str(MININET_ROOT / "traffic_generators" / script_name),
        "--dst-ip",
        "10.0.0.2",
        "--dst-port",
        str(UDP_PORT),
        "--src-port",
        str(src_port),
        "--duration-sec",
        str(duration_sec),
        "--attack-rate-mbps",
        str(condition.attack_rate_mbps),
        "--burst-ms",
        str(condition.burst_ms),
        "--period-ms",
        str(condition.period_ms),
        "--payload-size",
        str(condition.payload_size),
        "--seed",
        str(args.seed),
        "--log",
        str(send_log),
        "--summary-json",
        str(summary_json),
    ]
    host.cmd(shell_join(command) + f" > {shlex.quote(str(summary_json.with_suffix('.stdout.log')))} 2>&1")
    return json.loads(summary_json.read_text(encoding="utf-8")) if summary_json.exists() else {}


def run_normal_benign(host: Any, args: argparse.Namespace, send_log: Path, stdout_log: Path, duration_sec: float) -> None:
    """Run existing normal benign generator synchronously."""
    command = [
        py(),
        str(MININET_ROOT / "traffic_generators" / "send_normal_benign.py"),
        "--dst-ip",
        "10.0.0.2",
        "--dst-port",
        str(UDP_PORT),
        "--src-port",
        "40004",
        "--duration-sec",
        str(duration_sec),
        "--bucket-ms",
        str(args.bucket_ms),
        "--payload-size",
        "80",
        "--seed",
        str(args.seed),
        "--log",
        str(send_log),
    ]
    host.cmd(shell_join(command) + f" > {shlex.quote(str(stdout_log))} 2>&1")


def aggregate_udp_metrics(summaries: list[dict[str, Any]]) -> dict[str, float]:
    """Aggregate UDP sender summaries, preferring periodic attack summaries."""
    periodic = [summary for summary in summaries if str(summary.get("mode", "")).startswith("periodic")]
    selected = periodic or summaries
    if not selected:
        return {"actual_burst_rate_mbps": 0.0, "actual_average_rate_mbps": 0.0}
    return {
        "actual_burst_rate_mbps": float(np.mean([float(item.get("actual_burst_rate_mbps", 0.0)) for item in selected])),
        "actual_average_rate_mbps": float(np.mean([float(item.get("actual_average_rate_mbps", 0.0)) for item in selected])),
    }


def run_or_load_condition_synthetic(
    condition: TradeoffCondition,
    args: argparse.Namespace,
    output_dir: Path,
) -> pd.DataFrame | None:
    """Generate deterministic synthetic condition outputs for smoke tests."""
    condition_dir = ensure_dir(output_dir / condition.condition_id)
    row_path = condition_dir / "tradeoff_condition_metrics.csv"
    if args.resume and row_path.exists():
        return pd.read_csv(row_path)
    timeseries_frames: list[pd.DataFrame] = []
    window_frames: list[pd.DataFrame] = []
    for scenario in TRADEOFF_SCENARIOS:
        attack_mbps = synthetic_attack_mbps_for_condition(condition, scenario)
        ts = synthetic_throughput(scenario, args.duration_sec, args.attack_start_sec, attack_mbps)
        win_args = synthetic_args(args, condition)
        windows = synthetic_windows(scenario, win_args, ts)
        windows["condition_id"] = condition.condition_id
        if scenario == "stat_matched_ldos":
            apply_synthetic_feature_gap(windows, condition)
        timeseries_frames.append(ts)
        window_frames.append(windows)
    timeseries = pd.concat(timeseries_frames, ignore_index=True)
    window_log = pd.concat(window_frames, ignore_index=True)
    throughput_metrics = build_throughput_metrics(timeseries, args.attack_start_sec)
    detector_metrics = build_detector_metrics(window_log, args.attack_start_sec)
    confusion_matrices = build_confusion_matrices(detector_metrics)
    missed_harmful = build_missed_harmful_windows(window_log)
    write_throughput_outputs(
        condition_dir,
        timeseries,
        window_log,
        throughput_metrics,
        detector_metrics,
        confusion_matrices,
        missed_harmful,
        attack_start_sec=args.attack_start_sec,
        notes=["synthetic tradeoff smoke test"],
    )
    stat_metrics = compute_stat_match_metrics(
        window_log[window_log["scenario"] == "stat_matched_ldos"],
        None,
        bucket_ms=args.bucket_ms,
        attack_start_sec=args.attack_start_sec,
        duration_sec=args.duration_sec,
        period_ms=condition.period_ms,
    )
    load = condition.attack_rate_mbps * condition.burst_ms / condition.period_ms
    udp_metrics = {"actual_burst_rate_mbps": condition.attack_rate_mbps, "actual_average_rate_mbps": load}
    row = condition_tradeoff_row(condition, throughput_metrics, detector_metrics, stat_metrics, udp_metrics)
    row_frame = pd.DataFrame([row])
    row_frame.to_csv(row_path, index=False)
    return row_frame


def synthetic_attack_mbps_for_condition(condition: TradeoffCondition, scenario: str) -> float:
    """Return synthetic attack-period throughput for a scenario."""
    if scenario == "no_attack":
        return 90.0
    load = condition.attack_rate_mbps * condition.burst_ms / condition.period_ms * (condition.payload_size / 1472.0)
    degradation = min(0.75, 0.02 + load / 180.0)
    if scenario == "random_microburst_only":
        degradation *= 0.35
    elif scenario == "stat_matched_ldos":
        degradation *= 0.9
    return max(1.0, 90.0 * (1.0 - degradation))


def synthetic_args(args: argparse.Namespace, condition: TradeoffCondition) -> argparse.Namespace:
    """Return args object compatible with synthetic_windows."""
    clone = argparse.Namespace(**vars(args))
    clone.burst_pkts_per_bucket = max(1, int(condition.attack_rate_mbps / 10))
    clone.payload_size = condition.payload_size
    return clone


def apply_synthetic_feature_gap(windows: pd.DataFrame, condition: TradeoffCondition) -> None:
    """Inject condition-dependent feature gaps into synthetic stat_matched windows."""
    gap = min(0.8, 0.03 + (condition.attack_rate_mbps / 300.0) + (condition.payload_size / 6000.0))
    attack_mask = windows["true_label"].astype(str).eq("attack")
    for feature in ["iat_variance", "burst_rate", "payload_size_variance", "new_flow_arrival_rate"]:
        windows.loc[attack_mask, feature] = windows.loc[attack_mask, feature].astype(float) * (1.0 + gap)


def shell_join(command: list[str]) -> str:
    """Quote shell command."""
    return " ".join(shlex.quote(str(item)) for item in command)


def py() -> str:
    """Return current Python executable."""
    return sys.executable


if __name__ == "__main__":
    main()
