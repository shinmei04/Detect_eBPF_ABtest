"""Run single-flow, composite LDDoS, and F-LDDoS-style experiments."""

from __future__ import annotations

import argparse
import json
import math
import random
import shlex
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Iterable

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
    parse_iperf_json,
    start_background,
    start_tcpdump,
    stop_background,
    wait_for_process,
)
from src.lddos_composite_analysis import (
    ATTACK_MODES,
    SCENARIOS,
    CompositeCondition,
    build_condition_row,
    build_scenario_throughput_metrics,
    condition_metadata,
    evaluate_packet_views,
    iter_composite_conditions,
    write_composite_outputs,
)
from src.phase_labeling import build_phase_intervals, read_phase_intervals
from src.utils import ensure_dir


SS_COLUMNS = [
    "timestamp_sec",
    "cwnd",
    "rtt_ms",
    "rto_ms",
    "rttvar_ms",
    "delivery_rate",
    "retrans_current",
    "retrans_total",
    "raw_ss",
]

FOCUSED_PRESETS: dict[str, dict[str, Any]] = {
    "clean_top": {
        "attack_mode": [
            "multi_flow_sync_lddos",
            "multi_flow_staggered_lddos",
            "f_lddos",
        ],
        "total_attack_rate_mbps_values": [60.0, 120.0],
        "num_attack_flows_values": [4, 8],
        "burst_ms_values": [100, 150, 250],
        "period_ms_values": [1200, 1500],
        "payload_size_values": [80, 750],
        "phase_spread_ms_values": [0.0, 100.0],
        "jitter_ratio_values": [0.25],
        "payload_mode": ["empirical"],
        "feint_rate_ratio_values": [0.10],
        "feint_randomness": ["poisson"],
        "attack_interval_placement": "end",
    },
    "clean_best": {
        "attack_mode": [
            "multi_flow_staggered_lddos",
            "f_lddos",
        ],
        "total_attack_rate_mbps_values": [60.0],
        "num_attack_flows_values": [4, 8],
        "burst_ms_values": [150, 250],
        "period_ms_values": [1500],
        "payload_size_values": [750],
        "phase_spread_ms_values": [100.0],
        "jitter_ratio_values": [0.25],
        "payload_mode": ["empirical"],
        "feint_rate_ratio_values": [0.10],
        "feint_randomness": ["poisson"],
        "attack_interval_placement": "end",
    },
}
FOCUSED_GRID_FLAGS = {
    "--attack-mode",
    "--total-attack-rate-mbps-values",
    "--num-attack-flows-values",
    "--burst-ms-values",
    "--period-ms-values",
    "--payload-size-values",
    "--phase-spread-ms-values",
    "--jitter-ratio-values",
    "--payload-mode",
    "--feint-rate-ratio-values",
    "--feint-randomness",
    "--attack-interval-placement",
}
RESULT_FILENAMES = {
    "experiment_plan": "実験計画.json",
    "condition_metadata": "条件メタデータ.json",
    "condition_metrics": "条件別集約結果.csv",
    "throughput_metrics": "スループット指標.csv",
    "tcp_throughput_timeseries": "TCPスループット時系列.csv",
    "tcp_stack_config": "TCPスタック設定.csv",
    "tcp_ss_timeseries": "TCP内部状態時系列.csv",
    "tcp_retransmission_metrics": "TCP再送指標.csv",
    "packet_capture": "パケットキャプチャ.pcap",
    "iperf_client_json": "iperfクライアント出力.json",
    "iperf_server_log": "iperfサーバログ.log",
    "udp_sink_csv": "UDP受信ログ.csv",
    "udp_sink_log": "UDP受信プロセスログ.log",
    "packet_capture_log": "パケットキャプチャログ.log",
    "ss_collection_log": "TCP内部状態収集ログ.log",
    "iperf_summary": "iperf3集約結果.json",
    "udp_packets": "pcap抽出UDPパケット.csv",
    "pcap_rate_summary": "pcap観測レート集約.json",
    "aggregate_predictions": "集約評価予測.csv",
    "per_flow_predictions": "フロー別評価予測.csv",
    "per_flow_metrics": "フロー別評価指標.csv",
    "evaluation_metrics": "評価指標.json",
    "sender_phase_flow_log": "送信フェーズ別フローログ.csv",
    "sender_summary": "送信集約結果.json",
    "sender_stdout_log": "送信器標準出力.log",
    "flow_behavior_metrics": "フロー挙動指標.json",
    "synthetic_notice": "合成スモークテスト注意事項.txt",
}
LEGACY_RESULT_FILENAMES = {
    "condition_metrics": "lddos_condition_metrics.csv",
    "tcp_stack_config": "tcp_stack_config.csv",
    "tcp_ss_timeseries": "tcp_ss_timeseries.csv",
    "tcp_retransmission_metrics": "tcp_retransmission_metrics.csv",
}


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Run aggregate/per-flow composite LDDoS and F-LDDoS experiments."
    )
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--attack-start-sec", type=float, default=20.0)
    parser.add_argument("--detector-profile", choices=["phase3", "current"], default="phase3")
    parser.add_argument(
        "--focused-preset",
        choices=sorted(FOCUSED_PRESETS),
        help=(
            "Use a focused clean-tradeoff-derived grid. Cannot be combined with manual attack/grid options."
        ),
    )
    parser.add_argument("--attack-mode", nargs="+", choices=["all", *ATTACK_MODES], default=["all"])
    parser.add_argument("--total-attack-rate-mbps-values", type=float, nargs="+", default=[60, 120, 150])
    parser.add_argument("--num-attack-flows-values", type=int, nargs="+", default=[1, 2, 4, 8, 16])
    parser.add_argument("--burst-ms-values", type=int, nargs="+", default=[100, 200, 300])
    parser.add_argument("--period-ms-values", type=int, nargs="+", default=[800, 1000, 1200])
    parser.add_argument("--payload-size-values", type=int, nargs="+", default=[80, 750, 1000, 1200])
    parser.add_argument("--phase-spread-ms-values", type=float, nargs="+", default=[0, 50, 100, 200])
    parser.add_argument("--jitter-ratio-values", type=float, nargs="+", default=[0.0, 0.25, 0.5, 1.0])
    parser.add_argument(
        "--payload-mode",
        nargs="+",
        choices=["fixed", "empirical", "uniform"],
        default=["fixed", "empirical", "uniform"],
    )
    parser.add_argument("--feint-rate-ratio-values", type=float, nargs="+", default=[0.05, 0.10, 0.20, 0.30])
    parser.add_argument(
        "--feint-randomness",
        nargs="+",
        choices=["uniform", "poisson"],
        default=["uniform", "poisson"],
    )
    parser.add_argument("--attack-interval-placement", choices=["start", "end"], default="end")
    parser.add_argument(
        "--tcp-congestion-control",
        nargs="+",
        choices=["cubic", "reno"],
        default=["cubic"],
        help="Pass both values to run cubic/reno in one resumable grid.",
    )
    parser.add_argument(
        "--tcp-sack",
        nargs="+",
        choices=["on", "off"],
        default=["on"],
        help="Pass both values to run SACK on/off in one resumable grid.",
    )
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--window-sec", type=float, default=0.025)
    parser.add_argument("--step-sec", type=float, default=0.025)
    parser.add_argument("--warmup-windows", type=int, default=20)
    parser.add_argument("--score-threshold", type=int, default=2)
    parser.add_argument("--min-packets-for-detection", type=int, default=10)
    parser.add_argument(
        "--phase-min-overlap-sec",
        type=float,
        help="Minimum attack-burst overlap for target_burst; defaults to bucket_ms / 1000.",
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--collect-ss", action="store_true")
    parser.add_argument("--ss-interval-sec", type=float, default=0.1)
    parser.add_argument(
        "--iperf-json",
        action="store_true",
        help="Retain explicit iperf3 JSON summary files; raw JSON is always used for metrics.",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--max-cases", type=int)
    parser.add_argument("--output-dir", type=Path, default=Path("results_lddos_composite"))
    parser.add_argument(
        "--synthetic-test",
        action="store_true",
        help="Generate deterministic smoke-test artifacts without Mininet.",
    )
    args = parser.parse_args()
    apply_focused_preset(args, sys.argv[1:])
    return args


def apply_focused_preset(args: argparse.Namespace, argv: list[str]) -> None:
    """Apply one focused preset after rejecting ambiguous manual grid options."""
    if not args.focused_preset:
        return
    explicit_grid_flags = sorted(
        flag
        for flag in FOCUSED_GRID_FLAGS
        if any(token == flag or token.startswith(f"{flag}=") for token in argv)
    )
    if explicit_grid_flags:
        joined = ", ".join(explicit_grid_flags)
        raise SystemExit(
            f"--focused-preset cannot be combined with manual grid option(s): {joined}"
        )
    for attribute, value in FOCUSED_PRESETS[args.focused_preset].items():
        setattr(args, attribute, value)


def validate_args(args: argparse.Namespace) -> None:
    """Validate experiment arguments."""
    if args.duration_sec <= 0:
        raise SystemExit("--duration-sec must be positive")
    if not 0 <= args.attack_start_sec < args.duration_sec:
        raise SystemExit("--attack-start-sec must be in [0, duration-sec)")
    if args.bucket_ms <= 0:
        raise SystemExit("--bucket-ms must be positive")
    if args.window_sec <= 0 or args.step_sec <= 0:
        raise SystemExit("--window-sec and --step-sec must be positive")
    if args.max_cases is not None and args.max_cases <= 0:
        raise SystemExit("--max-cases must be positive")
    if args.score_threshold <= 0:
        raise SystemExit("--score-threshold must be positive")
    if args.phase_min_overlap_sec is not None and args.phase_min_overlap_sec <= 0:
        raise SystemExit("--phase-min-overlap-sec must be positive")
    if any(value <= 0 for value in args.total_attack_rate_mbps_values):
        raise SystemExit("all total attack rates must be positive")
    if any(value <= 0 for value in args.num_attack_flows_values):
        raise SystemExit("all flow counts must be positive")
    if any(value <= 0 for value in args.burst_ms_values + args.period_ms_values):
        raise SystemExit("burst/period values must be positive")
    if any(not 80 <= value <= 1472 for value in args.payload_size_values):
        raise SystemExit("payload sizes must be in 80..1472")
    if any(not 0 <= value <= 1 for value in args.jitter_ratio_values):
        raise SystemExit("jitter ratios must be in [0, 1]")


def main() -> None:
    """Run requested conditions and write aggregate outputs."""
    args = parse_args()
    validate_args(args)
    output_dir = ensure_dir(args.output_dir)
    planned_condition_count = sum(1 for _ in build_conditions(args))
    if planned_condition_count <= 0:
        raise SystemExit("No valid conditions were generated.")
    experiment_plan = build_experiment_plan(args, planned_condition_count)
    args.planned_condition_count = planned_condition_count
    args.estimated_minimum_runtime_sec = experiment_plan["estimated_minimum_runtime_sec"]
    print_experiment_plan(experiment_plan)
    result_path(output_dir, "experiment_plan").write_text(
        json.dumps(experiment_plan, indent=2),
        encoding="utf-8",
    )
    conditions = build_conditions(args)
    if not args.synthetic_test:
        assert_mininet_environment()
        if args.collect_ss and shutil.which("ss") is None:
            raise SystemExit("--collect-ss requires the `ss` command.")

    new_cases = 0
    if args.synthetic_test:
        for condition in conditions:
            condition_dir = output_dir / condition.condition_id
            if args.resume and existing_result_path(condition_dir, "condition_metrics").exists():
                continue
            run_condition_synthetic(condition, args, condition_dir)
            new_cases += 1
            if args.max_cases is not None and new_cases >= args.max_cases:
                break
    else:
        run_mininet_conditions(conditions, args, output_dir)

    completed = load_completed_rows(output_dir)
    write_composite_outputs(completed, output_dir, experiment_plan)
    write_tcp_aggregate_outputs(output_dir)


def build_conditions(args: argparse.Namespace) -> Iterable[CompositeCondition]:
    """Yield conditions from CLI values."""
    return iter_composite_conditions(
        attack_modes=args.attack_mode,
        total_rates=args.total_attack_rate_mbps_values,
        num_flows=args.num_attack_flows_values,
        burst_values=args.burst_ms_values,
        period_values=args.period_ms_values,
        payload_sizes=args.payload_size_values,
        phase_spreads=args.phase_spread_ms_values,
        jitter_ratios=args.jitter_ratio_values,
        payload_modes=args.payload_mode,
        feint_ratios=args.feint_rate_ratio_values,
        feint_randomness_values=args.feint_randomness,
        attack_interval_placement=args.attack_interval_placement,
        tcp_congestion_controls=args.tcp_congestion_control,
        tcp_sacks=args.tcp_sack,
        preserve_sync_staggered_shaping=bool(args.focused_preset),
    )


def build_experiment_plan(
    args: argparse.Namespace,
    planned_condition_count: int,
) -> dict[str, Any]:
    """Build condition-count and minimum-runtime metadata."""
    minimum_runtime_sec = planned_condition_count * len(SCENARIOS) * args.duration_sec
    invocation_condition_limit = (
        min(planned_condition_count, args.max_cases)
        if args.max_cases is not None
        else planned_condition_count
    )
    focused_preset = args.focused_preset or ""
    return {
        "focused_preset_used": bool(focused_preset),
        "focused_preset": focused_preset,
        "focused_reason": focused_reason(focused_preset),
        "planned_condition_count": int(planned_condition_count),
        "scenario_count_per_condition": int(len(SCENARIOS)),
        "duration_sec_per_scenario": float(args.duration_sec),
        "estimated_minimum_runtime_sec": float(minimum_runtime_sec),
        "estimated_minimum_runtime_minutes": float(minimum_runtime_sec / 60.0),
        "estimated_minimum_runtime_hours": float(minimum_runtime_sec / 3600.0),
        "max_cases": args.max_cases,
        "invocation_condition_limit": int(invocation_condition_limit),
        "invocation_minimum_runtime_sec": float(
            invocation_condition_limit * len(SCENARIOS) * args.duration_sec
        ),
        "resume": bool(args.resume),
    }


def focused_reason(focused_preset: str) -> str:
    """Return the rationale recorded for focused exploration."""
    if not focused_preset:
        return "No focused preset; the manually selected or standard grid is used."
    if focused_preset == "clean_best":
        return (
            "Small focused exploration around the clean-tradeoff best candidate "
            "r60_l250_t1500_p750."
        )
    return (
        "Focused exploration of the high-success-probability region around "
        "r60_l250_t1500_p750 and other top clean-tradeoff candidates."
    )


def print_experiment_plan(plan: dict[str, Any]) -> None:
    """Print the planned condition count and theoretical minimum runtime."""
    preset = str(plan["focused_preset"]) or "none"
    print(f"Focused preset: {preset}")
    print(f"Total planned conditions: {plan['planned_condition_count']}")
    print(
        "Estimated minimum runtime: "
        f"{plan['estimated_minimum_runtime_minutes']:.1f} minutes "
        f"({plan['estimated_minimum_runtime_hours']:.2f} hours)"
    )
    if plan["max_cases"] is not None:
        invocation_minutes = float(plan["invocation_minimum_runtime_sec"]) / 60.0
        print(f"This invocation condition limit: {plan['invocation_condition_limit']}")
        print(f"This invocation minimum runtime: {invocation_minutes:.1f} minutes")


def load_completed_rows(output_dir: Path) -> pd.DataFrame:
    """Load all completed per-condition rows."""
    rows = []
    condition_dirs = sorted(path for path in output_dir.iterdir() if path.is_dir())
    for condition_dir in condition_dirs:
        path = existing_result_path(condition_dir, "condition_metrics")
        if not path.exists():
            continue
        frame = pd.read_csv(path)
        if not frame.empty:
            rows.append(frame)
    if not rows:
        return pd.DataFrame()
    return pd.concat(rows, ignore_index=True).drop_duplicates(subset=["condition_id"], keep="last")


def run_mininet_conditions(
    conditions: Iterable[CompositeCondition],
    args: argparse.Namespace,
    output_dir: Path,
) -> None:
    """Run resumable conditions in one Mininet network."""
    from mininet.clean import cleanup
    from mininet.link import TCLink
    from mininet.net import Mininet

    from minimal_topo import MinimalABTopo

    cleanup()
    network: Mininet | None = None
    new_cases = 0
    try:
        network = Mininet(topo=MinimalABTopo(), link=TCLink, autoSetMacs=True, autoStaticArp=True)
        network.start()
        for condition in conditions:
            condition_dir = output_dir / condition.condition_id
            if args.resume and existing_result_path(condition_dir, "condition_metrics").exists():
                continue
            run_condition_mininet(network, condition, args, condition_dir)
            new_cases += 1
            if args.max_cases is not None and new_cases >= args.max_cases:
                break
    finally:
        if network is not None:
            network.stop()
        cleanup()


def run_condition_mininet(
    network: Any,
    condition: CompositeCondition,
    args: argparse.Namespace,
    condition_dir: Path,
) -> None:
    """Run all scenarios for one real Mininet condition."""
    ensure_dir(condition_dir)
    result_path(condition_dir, "condition_metadata").write_text(
        json.dumps(experiment_metadata(condition, args, synthetic_test=False), indent=2),
        encoding="utf-8",
    )
    tcp_config = configure_tcp(network, condition)
    timeseries_frames = []
    ss_frames = []
    retransmission_rows = []
    sender_summaries: dict[str, dict[str, Any]] = {}
    evaluation_metrics: dict[str, Any] = {}
    for scenario in SCENARIOS:
        scenario_dir = ensure_dir(condition_dir / scenario)
        result = run_scenario_mininet(network, condition, scenario, args, scenario_dir)
        timeseries_frames.append(result["throughput"])
        if not result["ss"].empty:
            ss_frames.append(result["ss"])
        retransmission_rows.append(result["retransmission"])
        sender_summaries[scenario] = result["sender_summary"]
        if scenario == "stat_matched_composite_lddos":
            evaluation_metrics = result["evaluation_metrics"]

    timeseries = pd.concat(timeseries_frames, ignore_index=True)
    throughput_metrics = build_scenario_throughput_metrics(timeseries, args.attack_start_sec)
    row = build_condition_row(
        condition,
        throughput_metrics,
        evaluation_metrics,
        sender_summaries.get("composite_lddos", {}),
        tcp_config,
    )
    row["synthetic_test"] = False
    add_plan_fields(row, args)
    pd.DataFrame([row]).to_csv(result_path(condition_dir, "condition_metrics"), index=False)
    throughput_metrics.to_csv(result_path(condition_dir, "throughput_metrics"), index=False)
    timeseries.to_csv(result_path(condition_dir, "tcp_throughput_timeseries"), index=False)
    pd.DataFrame([tcp_config]).to_csv(result_path(condition_dir, "tcp_stack_config"), index=False)
    condition_ss = (
        pd.concat(ss_frames, ignore_index=True)
        if ss_frames
        else pd.DataFrame(columns=["scenario", *SS_COLUMNS])
    )
    condition_ss.to_csv(result_path(condition_dir, "tcp_ss_timeseries"), index=False)
    pd.DataFrame(retransmission_rows).to_csv(
        result_path(condition_dir, "tcp_retransmission_metrics"), index=False
    )


def run_scenario_mininet(
    network: Any,
    condition: CompositeCondition,
    scenario: str,
    args: argparse.Namespace,
    scenario_dir: Path,
) -> dict[str, Any]:
    """Run one real Mininet scenario."""
    h1, h2, h3 = [network.get(name) for name in ("h1", "h2", "h3")]
    pcap_path = result_path(scenario_dir, "packet_capture")
    iperf_json_path = result_path(scenario_dir, "iperf_client_json")
    has_udp = scenario != "no_attack"
    pids: dict[str, str] = {}
    experiment_start_wall = 0.0
    sender_summary: dict[str, Any] = {}
    try:
        pids["iperf_server"] = start_background(
            h2,
            ["iperf3", "-s", "-p", str(IPERF_PORT)],
            result_path(scenario_dir, "iperf_server_log"),
        )
        time.sleep(0.4)
        if has_udp:
            pids["sink"] = start_background(
                h2,
                [
                    sys.executable,
                    str(MININET_ROOT / "traffic_generators" / "udp_sink.py"),
                    "--bind-ip",
                    "0.0.0.0",
                    "--port",
                    str(UDP_PORT),
                    "--duration-sec",
                    str(args.duration_sec + 3.0),
                    "--log",
                    str(result_path(scenario_dir, "udp_sink_csv")),
                ],
                result_path(scenario_dir, "udp_sink_log"),
            )
            pids["tcpdump"] = start_tcpdump(
                h2, pcap_path, result_path(scenario_dir, "packet_capture_log")
            )
            time.sleep(0.3)
        pids["iperf_client"] = start_background(
            h1,
            [
                "iperf3",
                "-c",
                "10.0.0.2",
                "-p",
                str(IPERF_PORT),
                "-t",
                str(int(math.ceil(args.duration_sec))),
                "-i",
                "1",
                "-J",
            ],
            iperf_json_path,
        )
        experiment_start_wall = time.time()
        if args.collect_ss:
            pids["ss"] = start_background(
                h1,
                [
                    sys.executable,
                    str(MININET_ROOT / "collect_ss.py"),
                    "--duration-sec",
                    str(args.duration_sec),
                    "--interval-sec",
                    str(args.ss_interval_sec),
                    "--dst-ip",
                    "10.0.0.2",
                    "--dst-port",
                    str(IPERF_PORT),
                    "--output",
                    str(result_path(scenario_dir, "tcp_ss_timeseries")),
                ],
                result_path(scenario_dir, "ss_collection_log"),
            )
        if has_udp:
            sender_summary = run_composite_sender(
                h3,
                condition,
                scenario,
                args,
                scenario_dir,
                experiment_start_wall,
            )
        wait_for_process(h1, pids["iperf_client"])
        if "ss" in pids:
            wait_for_process(h1, pids["ss"])
        time.sleep(0.4)
    finally:
        stop_background(h1, pids.get("ss", ""))
        stop_background(h1, pids.get("iperf_client", ""))
        stop_background(h2, pids.get("tcpdump", ""))
        stop_background(h2, pids.get("sink", ""))
        stop_background(h2, pids.get("iperf_server", ""))

    throughput = parse_iperf_json(iperf_json_path, scenario)
    throughput.to_csv(result_path(scenario_dir, "tcp_throughput_timeseries"), index=False)
    write_iperf_summary(iperf_json_path, result_path(scenario_dir, "iperf_summary"))
    ss_frame = read_optional_csv(result_path(scenario_dir, "tcp_ss_timeseries"))
    if not ss_frame.empty:
        ss_frame.insert(0, "scenario", scenario)
    retransmission = retransmission_summary(scenario, throughput, ss_frame)
    evaluation_metrics: dict[str, Any] = {}
    if has_udp:
        phase_log_path = result_path(scenario_dir, "sender_phase_flow_log")
        _, packets = build_features_from_pcap(
            pcap_path=pcap_path,
            bucket_ms=args.bucket_ms,
            window_sec=args.window_sec,
            step_sec=args.step_sec,
            duration_sec=args.duration_sec,
            attack_start_sec=args.attack_start_sec,
            time_origin_sec=experiment_start_wall,
            dst_port=UDP_PORT,
            phase_intervals=phase_log_path,
            min_overlap_sec=phase_min_overlap_sec(args),
        )
        packets.to_csv(result_path(scenario_dir, "udp_packets"), index=False)
        observed_rates = pcap_rate_summary(packets, condition, scenario, args, sender_summary)
        sender_summary.update(observed_rates)
        result_path(scenario_dir, "pcap_rate_summary").write_text(
            json.dumps(observed_rates, indent=2),
            encoding="utf-8",
        )
        aggregate, per_flow, metrics, per_flow_metrics = evaluate_packet_views(
            packets,
            duration_sec=args.duration_sec,
            attack_start_sec=args.attack_start_sec,
            bucket_ms=args.bucket_ms,
            window_sec=args.window_sec,
            step_sec=args.step_sec,
            scenario=scenario,
            seed=args.seed,
            warmup_windows=args.warmup_windows,
            score_threshold=args.score_threshold,
            min_packets_for_detection=args.min_packets_for_detection,
            detector_profile=args.detector_profile,
            phase_intervals=read_phase_intervals(phase_log_path),
            min_overlap_sec=phase_min_overlap_sec(args),
            stable_flow_mode=bool(sender_summary.get("stable_flow_mode", True)),
            src_port_reuse=bool(sender_summary.get("src_port_reuse", True)),
        )
        aggregate.to_csv(result_path(scenario_dir, "aggregate_predictions"), index=False)
        per_flow.to_csv(result_path(scenario_dir, "per_flow_predictions"), index=False)
        per_flow_metrics.to_csv(result_path(scenario_dir, "per_flow_metrics"), index=False)
        write_evaluation_metrics(metrics, result_path(scenario_dir, "evaluation_metrics"))
        write_flow_behavior_metrics(metrics, result_path(scenario_dir, "flow_behavior_metrics"))
        if scenario == "stat_matched_composite_lddos":
            evaluation_metrics = metrics
    else:
        result_path(scenario_dir, "evaluation_metrics").write_text("{}\n", encoding="utf-8")
        write_flow_behavior_metrics({}, result_path(scenario_dir, "flow_behavior_metrics"))
    return {
        "throughput": throughput,
        "ss": ss_frame,
        "retransmission": retransmission,
        "sender_summary": sender_summary,
        "evaluation_metrics": evaluation_metrics,
    }


def run_composite_sender(
    host: Any,
    condition: CompositeCondition,
    scenario: str,
    args: argparse.Namespace,
    scenario_dir: Path,
    experiment_start_wall: float,
) -> dict[str, Any]:
    """Run the composite sender synchronously inside h3."""
    attack_mode = "single_flow_ldos" if scenario == "single_flow_ldos" else condition.attack_mode
    num_flows = 1 if scenario == "single_flow_ldos" else condition.num_attack_flows
    command = [
        sys.executable,
        str(MININET_ROOT / "traffic_generators" / "send_composite_lddos.py"),
        "--dst-ip",
        "10.0.0.2",
        "--dst-port",
        str(UDP_PORT),
        "--base-src-port",
        "40000",
        "--duration-sec",
        str(args.duration_sec),
        "--attack-start-sec",
        str(args.attack_start_sec),
        "--experiment-start-wall",
        str(experiment_start_wall),
        "--scenario",
        scenario,
        "--attack-mode",
        attack_mode,
        "--total-attack-rate-mbps",
        str(condition.total_attack_rate_mbps),
        "--num-attack-flows",
        str(num_flows),
        "--burst-ms",
        str(condition.burst_ms),
        "--period-ms",
        str(condition.period_ms),
        "--payload-size",
        str(condition.payload_size),
        "--payload-mode",
        condition.payload_mode,
        "--phase-spread-ms",
        str(condition.phase_spread_ms),
        "--jitter-ratio",
        str(condition.jitter_ratio),
        "--feint-rate-ratio",
        str(condition.feint_rate_ratio),
        "--feint-randomness",
        condition.feint_randomness,
        "--attack-interval-placement",
        condition.attack_interval_placement,
        "--seed",
        str(args.seed),
        "--log",
        str(result_path(scenario_dir, "sender_phase_flow_log")),
        "--summary-json",
        str(result_path(scenario_dir, "sender_summary")),
    ]
    stdout_path = result_path(scenario_dir, "sender_stdout_log")
    host.cmd(shell_join(command) + f" > {shlex.quote(str(stdout_path))} 2>&1")
    summary_path = result_path(scenario_dir, "sender_summary")
    if not summary_path.exists():
        raise RuntimeError(f"sender failed; inspect {stdout_path}")
    return json.loads(summary_path.read_text(encoding="utf-8"))


def configure_tcp(network: Any, condition: CompositeCondition) -> dict[str, Any]:
    """Apply and record TCP stack settings in the Mininet TCP endpoints."""
    sack_value = "1" if condition.tcp_sack == "on" else "0"
    for host_name in ("h1", "h2"):
        host = network.get(host_name)
        host.cmd(f"sysctl -w net.ipv4.tcp_congestion_control={shlex.quote(condition.tcp_congestion_control)}")
        host.cmd(f"sysctl -w net.ipv4.tcp_sack={sack_value}")
    h1 = network.get("h1")
    return {
        "tcp_congestion_control": sysctl_value(h1, "net.ipv4.tcp_congestion_control"),
        "tcp_sack": "on" if sysctl_value(h1, "net.ipv4.tcp_sack") == "1" else "off",
        "tcp_timestamps": sysctl_value(h1, "net.ipv4.tcp_timestamps"),
        "tcp_window_scaling": sysctl_value(h1, "net.ipv4.tcp_window_scaling"),
        "tcp_recovery": sysctl_value(h1, "net.ipv4.tcp_recovery"),
    }


def sysctl_value(host: Any, name: str) -> str:
    """Read a sysctl value from one Mininet host."""
    return host.cmd(f"sysctl -n {shlex.quote(name)} 2>/dev/null").strip()


def run_condition_synthetic(
    condition: CompositeCondition,
    args: argparse.Namespace,
    condition_dir: Path,
) -> None:
    """Generate deterministic smoke-test outputs without Mininet."""
    ensure_dir(condition_dir)
    result_path(condition_dir, "condition_metadata").write_text(
        json.dumps(experiment_metadata(condition, args, synthetic_test=True), indent=2),
        encoding="utf-8",
    )
    timeseries_frames = []
    sender_summaries: dict[str, dict[str, Any]] = {}
    evaluation_metrics: dict[str, Any] = {}
    retransmission_rows = []
    for scenario in SCENARIOS:
        scenario_dir = ensure_dir(condition_dir / scenario)
        throughput = synthetic_throughput(condition, scenario, args)
        throughput.to_csv(result_path(scenario_dir, "tcp_throughput_timeseries"), index=False)
        result_path(scenario_dir, "iperf_summary").write_text(
            json.dumps(
                {
                    "synthetic_test": True,
                    "scenario": scenario,
                    "mean_tcp_throughput_mbps": float(throughput["tcp_throughput_mbps"].mean()),
                    "retransmits": int(throughput["tcp_retransmits"].sum()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        timeseries_frames.append(throughput)
        retransmission_rows.append(retransmission_summary(scenario, throughput, pd.DataFrame()))
        if scenario != "no_attack":
            packets = synthetic_packets(condition, scenario, args)
            packets.to_csv(result_path(scenario_dir, "udp_packets"), index=False)
            phase_intervals = phase_intervals_for_condition(condition, scenario, args)
            phase_intervals.to_csv(result_path(scenario_dir, "sender_phase_flow_log"), index=False)
            aggregate, per_flow, metrics, per_flow_metrics = evaluate_packet_views(
                packets,
                duration_sec=args.duration_sec,
                attack_start_sec=args.attack_start_sec,
                bucket_ms=args.bucket_ms,
                window_sec=args.window_sec,
                step_sec=args.step_sec,
                scenario=scenario,
                seed=args.seed,
                warmup_windows=args.warmup_windows,
                score_threshold=args.score_threshold,
                min_packets_for_detection=args.min_packets_for_detection,
                detector_profile=args.detector_profile,
                phase_intervals=phase_intervals,
                min_overlap_sec=phase_min_overlap_sec(args),
                stable_flow_mode=True,
                src_port_reuse=True,
            )
            aggregate.to_csv(result_path(scenario_dir, "aggregate_predictions"), index=False)
            per_flow.to_csv(result_path(scenario_dir, "per_flow_predictions"), index=False)
            per_flow_metrics.to_csv(result_path(scenario_dir, "per_flow_metrics"), index=False)
            write_evaluation_metrics(metrics, result_path(scenario_dir, "evaluation_metrics"))
            write_flow_behavior_metrics(metrics, result_path(scenario_dir, "flow_behavior_metrics"))
            sender_summaries[scenario] = synthetic_sender_summary(condition, scenario)
            result_path(scenario_dir, "sender_summary").write_text(
                json.dumps(sender_summaries[scenario], indent=2),
                encoding="utf-8",
            )
            if scenario == "stat_matched_composite_lddos":
                evaluation_metrics = metrics
        else:
            sender_summaries[scenario] = {}
            result_path(scenario_dir, "evaluation_metrics").write_text("{}\n", encoding="utf-8")
            write_flow_behavior_metrics({}, result_path(scenario_dir, "flow_behavior_metrics"))

    timeseries = pd.concat(timeseries_frames, ignore_index=True)
    throughput_metrics = build_scenario_throughput_metrics(timeseries, args.attack_start_sec)
    tcp_config = {
        "tcp_congestion_control": condition.tcp_congestion_control,
        "tcp_sack": condition.tcp_sack,
        "tcp_timestamps": "1",
        "tcp_window_scaling": "1",
        "tcp_recovery": "1",
    }
    row = build_condition_row(
        condition,
        throughput_metrics,
        evaluation_metrics,
        sender_summaries["composite_lddos"],
        tcp_config,
    )
    row["synthetic_test"] = True
    add_plan_fields(row, args)
    pd.DataFrame([row]).to_csv(result_path(condition_dir, "condition_metrics"), index=False)
    throughput_metrics.to_csv(result_path(condition_dir, "throughput_metrics"), index=False)
    timeseries.to_csv(result_path(condition_dir, "tcp_throughput_timeseries"), index=False)
    pd.DataFrame([tcp_config]).to_csv(result_path(condition_dir, "tcp_stack_config"), index=False)
    pd.DataFrame(columns=["scenario", *SS_COLUMNS]).to_csv(
        result_path(condition_dir, "tcp_ss_timeseries"), index=False
    )
    pd.DataFrame(retransmission_rows).to_csv(
        result_path(condition_dir, "tcp_retransmission_metrics"), index=False
    )
    result_path(condition_dir, "synthetic_notice").write_text(
        "Synthetic smoke-test output. Mininet and XDP/eBPF were not executed.\n",
        encoding="utf-8",
    )


def experiment_metadata(
    condition: CompositeCondition,
    args: argparse.Namespace,
    *,
    synthetic_test: bool,
) -> dict[str, Any]:
    """Return condition plus evaluation settings."""
    return {
        **condition_metadata(condition),
        "synthetic_test": synthetic_test,
        "detector_profile": args.detector_profile,
        "bucket_ms": args.bucket_ms,
        "window_sec": args.window_sec,
        "step_sec": args.step_sec,
        "warmup_windows": args.warmup_windows,
        "score_threshold": args.score_threshold,
        "min_packets_for_detection": args.min_packets_for_detection,
        "phase_min_overlap_sec": phase_min_overlap_sec(args),
        "collect_ss": args.collect_ss,
        "ss_interval_sec": args.ss_interval_sec,
        "focused_preset": args.focused_preset or "",
        "planned_condition_count": args.planned_condition_count,
        "estimated_minimum_runtime_sec": args.estimated_minimum_runtime_sec,
    }


def phase_min_overlap_sec(args: argparse.Namespace) -> float:
    """Return the configured burst-overlap threshold."""
    return (
        float(args.phase_min_overlap_sec)
        if args.phase_min_overlap_sec is not None
        else args.bucket_ms / 1000.0
    )


def phase_intervals_for_condition(
    condition: CompositeCondition,
    scenario: str,
    args: argparse.Namespace,
) -> pd.DataFrame:
    """Build sender-equivalent phase intervals for synthetic smoke tests."""
    mode = "single_flow_ldos" if scenario == "single_flow_ldos" else condition.attack_mode
    num_flows = 1 if scenario == "single_flow_ldos" else condition.num_attack_flows
    return build_phase_intervals(
        duration_sec=args.duration_sec,
        attack_start_sec=args.attack_start_sec,
        scenario=scenario,
        attack_mode=mode,
        num_flows=num_flows,
        period_ms=condition.period_ms,
        burst_ms=condition.burst_ms,
        phase_spread_ms=condition.phase_spread_ms,
        attack_interval_placement=condition.attack_interval_placement,
        seed=args.seed,
        per_flow_rate_mbps=condition.total_attack_rate_mbps / num_flows,
        feint_rate_ratio=condition.feint_rate_ratio,
    )


def write_flow_behavior_metrics(metrics: dict[str, Any], output: Path) -> None:
    """Write stable-flow and new-flow-arrival checks for one scenario."""
    names = [
        "unique_flow_count_total",
        "new_flow_arrival_rate_mean",
        "new_flow_arrival_rate_max",
        "new_flow_arrival_rate_mean_by_phase",
        "new_flow_arrival_rate_max_by_phase",
        "stable_flow_mode",
        "src_port_reuse",
    ]
    defaults = {
        "unique_flow_count_total": 0,
        "new_flow_arrival_rate_mean": 0.0,
        "new_flow_arrival_rate_max": 0.0,
        "new_flow_arrival_rate_mean_by_phase": {},
        "new_flow_arrival_rate_max_by_phase": {},
        "stable_flow_mode": False,
        "src_port_reuse": False,
    }
    payload = {name: metrics.get(name, defaults[name]) for name in names}
    for name in ["new_flow_arrival_rate_mean_by_phase", "new_flow_arrival_rate_max_by_phase"]:
        if isinstance(payload[name], str):
            payload[name] = json.loads(payload[name])
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_evaluation_metrics(metrics: dict[str, Any], output: Path) -> None:
    """Write scenario metrics using JSON null for unavailable phase metrics."""
    payload = {
        key: None if isinstance(value, float) and math.isnan(value) else value
        for key, value in metrics.items()
    }
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def add_plan_fields(row: dict[str, Any], args: argparse.Namespace) -> None:
    """Add focused-grid execution plan fields to one condition row."""
    row.update(
        {
            "focused_preset": args.focused_preset or "",
            "planned_condition_count": args.planned_condition_count,
            "estimated_minimum_runtime_sec": args.estimated_minimum_runtime_sec,
        }
    )


def write_tcp_aggregate_outputs(output_dir: Path) -> None:
    """Aggregate optional per-condition TCP state files at the result root."""
    for key in ["tcp_stack_config", "tcp_ss_timeseries", "tcp_retransmission_metrics"]:
        frames = []
        condition_dirs = sorted(path for path in output_dir.iterdir() if path.is_dir())
        for condition_dir in condition_dirs:
            path = existing_result_path(condition_dir, key)
            if not path.exists():
                continue
            frame = read_optional_csv(path)
            if frame.empty:
                continue
            if "condition_id" not in frame:
                frame.insert(0, "condition_id", path.parent.name)
            frames.append(frame)
        if frames:
            aggregate = pd.concat(frames, ignore_index=True)
        elif key == "tcp_ss_timeseries":
            aggregate = pd.DataFrame(columns=["condition_id", "scenario", *SS_COLUMNS])
        else:
            aggregate = pd.DataFrame()
        aggregate.to_csv(result_path(output_dir, key), index=False)


def result_path(directory: Path, key: str) -> Path:
    """Return the Japanese output path for a result artifact."""
    return directory / RESULT_FILENAMES[key]


def existing_result_path(directory: Path, key: str) -> Path:
    """Return Japanese output path, falling back to a legacy English filename."""
    japanese = result_path(directory, key)
    if japanese.exists():
        return japanese
    legacy_name = LEGACY_RESULT_FILENAMES.get(key)
    legacy = directory / legacy_name if legacy_name else japanese
    return legacy if legacy.exists() else japanese


def synthetic_throughput(
    condition: CompositeCondition,
    scenario: str,
    args: argparse.Namespace,
) -> pd.DataFrame:
    """Build deterministic iperf-like throughput for smoke tests."""
    degradation = synthetic_degradation(condition, scenario)
    rows = []
    for index in range(int(math.ceil(args.duration_sec))):
        before_attack = index + 1 <= args.attack_start_sec
        current_degradation = 0.0 if before_attack else degradation
        mbps = max(0.0, 90.0 * (1.0 - current_degradation) + 1.5 * math.sin(index / 3.0))
        rows.append(
            {
                "scenario": scenario,
                "interval_index": index,
                "start_sec": float(index),
                "end_sec": min(float(index + 1), args.duration_sec),
                "tcp_throughput_bps": mbps * 1_000_000.0,
                "tcp_throughput_mbps": mbps,
                "tcp_retransmits": int(round(20 * current_degradation)),
            }
        )
    return pd.DataFrame(rows)


def synthetic_degradation(condition: CompositeCondition, scenario: str) -> float:
    """Return deterministic scenario degradation."""
    if scenario == "no_attack":
        return 0.0
    duty = condition.burst_ms / condition.period_ms
    average_load = condition.total_attack_rate_mbps * duty
    if scenario == "random_microburst_only":
        return min(0.35, 0.03 + average_load / 160.0)
    if scenario == "single_flow_ldos":
        return min(0.88, 0.20 + average_load / 42.0)
    mode_bonus = {
        "single_flow_ldos": 0.00,
        "multi_flow_sync_lddos": 0.10,
        "multi_flow_staggered_lddos": 0.06,
        "multi_flow_randomized_lddos": 0.03,
        "score_aware_lddos": 0.02,
        "f_lddos": 0.08,
    }[condition.attack_mode]
    degradation = min(0.92, 0.18 + average_load / 38.0 + mode_bonus)
    return degradation * (0.98 if scenario == "stat_matched_composite_lddos" else 1.0)


def synthetic_packets(
    condition: CompositeCondition,
    scenario: str,
    args: argparse.Namespace,
) -> pd.DataFrame:
    """Build manageable pcap-like packets for detector smoke tests."""
    rng = random.Random(args.seed * 1009 + sum(ord(char) for char in scenario))
    num_flows = 1 if scenario == "single_flow_ldos" else condition.num_attack_flows
    bucket_sec = args.bucket_ms / 1000.0
    total_buckets = int(round(args.duration_sec / bucket_sec))
    period_buckets = max(1, int(round(condition.period_ms / args.bucket_ms)))
    burst_buckets = max(1, int(round(condition.burst_ms / args.bucket_ms)))
    attack_start_bucket = int(round(args.attack_start_sec / bucket_sec))
    packets_per_bucket = max(10, min(32, int(round(condition.per_flow_rate_mbps / 2.0)) + 10))
    phase_plan = phase_intervals_for_condition(condition, scenario, args)
    rows = []
    for flow in range(num_flows):
        flow_plan = phase_plan[phase_plan["src_port"].astype(int).eq(40000 + flow)]
        phases: dict[int, int] = {}
        for period_index in range(int(math.ceil(total_buckets / period_buckets)) + 1):
            max_phase = max(0, period_buckets - burst_buckets)
            phases[period_index] = rng.randint(0, max_phase) if max_phase > 0 else 0
        for bucket in range(total_buckets):
            period_index = bucket // period_buckets
            phase = bucket % period_buckets
            if scenario == "random_microburst_only" or bucket < attack_start_bucket:
                active = phases[period_index] <= phase < phases[period_index] + burst_buckets
                count = packets_per_bucket if active else 0
            else:
                bucket_start = bucket * bucket_sec
                bucket_end = bucket_start + bucket_sec
                burst_active = phase_overlaps_bucket(
                    flow_plan, "attack_burst", bucket_start, bucket_end
                )
                feint_active = phase_overlaps_bucket(flow_plan, "feint", bucket_start, bucket_end)
                count = packets_per_bucket if burst_active else 0
                if feint_active:
                    feint_count = int(round(packets_per_bucket * condition.feint_rate_ratio))
                    count += feint_count if rng.random() < 0.35 else 0
            for packet_index in range(count):
                timestamp = (bucket + (packet_index + 0.5) / max(count, 1)) * bucket_sec
                size = synthetic_payload(condition, rng)
                rows.append(
                    {
                        "timestamp": timestamp,
                        "timestamp_sec": timestamp,
                        "src_ip": "10.0.0.3",
                        "dst_ip": "10.0.0.2",
                        "src_port": 40000 + flow,
                        "dst_port": UDP_PORT,
                        "packet_size": size,
                        "flow_id": f"10.0.0.3:{40000 + flow}>10.0.0.2:{UDP_PORT}",
                    }
                )
    return pd.DataFrame(rows).sort_values("timestamp_sec", kind="mergesort").reset_index(drop=True)


def phase_overlaps_bucket(
    phase_plan: pd.DataFrame,
    phase: str,
    bucket_start: float,
    bucket_end: float,
) -> bool:
    """Return whether one planned phase overlaps a synthetic packet bucket."""
    rows = phase_plan[phase_plan["phase"].eq(phase)]
    if rows.empty:
        return False
    return bool(
        (
            (rows["phase_start_sec"].astype(float) < bucket_end)
            & (rows["phase_end_sec"].astype(float) > bucket_start)
        ).any()
    )


def synthetic_payload(condition: CompositeCondition, rng: random.Random) -> int:
    """Sample a synthetic payload."""
    mode = condition.payload_mode
    if condition.attack_mode == "score_aware_lddos" and mode == "fixed":
        mode = "empirical"
    if mode == "fixed":
        return condition.payload_size
    if mode == "uniform":
        return int(max(80, min(1472, round(rng.uniform(condition.payload_size * 0.5, condition.payload_size * 1.5)))))
    return int(rng.choices([80, 750, 1000, 1200, 1472], weights=[0.3, 0.3, 0.2, 0.1, 0.1], k=1)[0])


def synthetic_sender_summary(condition: CompositeCondition, scenario: str) -> dict[str, Any]:
    """Return nominal actual-rate fields for smoke tests."""
    num_flows = 1 if scenario == "single_flow_ldos" else condition.num_attack_flows
    duty = condition.burst_ms / condition.period_ms
    feint_rate = (
        condition.total_attack_rate_mbps * condition.feint_rate_ratio * (1.0 - duty)
        if condition.attack_mode == "f_lddos"
        else 0.0
    )
    return {
        "udp_actual_total_burst_rate_mbps": condition.total_attack_rate_mbps * 0.97,
        "udp_actual_total_average_rate_mbps": condition.total_attack_rate_mbps * duty + feint_rate,
        "udp_actual_per_flow_burst_rate_mbps": condition.total_attack_rate_mbps * 0.97 / num_flows,
        "udp_actual_per_flow_average_rate_mbps": (condition.total_attack_rate_mbps * duty + feint_rate) / num_flows,
        "feint_actual_rate_mbps": feint_rate,
        "attack_actual_rate_mbps": condition.total_attack_rate_mbps * 0.97,
        "unique_flow_count_total": num_flows,
        "stable_flow_mode": True,
        "src_port_reuse": True,
    }


def pcap_rate_summary(
    packets: pd.DataFrame,
    condition: CompositeCondition,
    scenario: str,
    args: argparse.Namespace,
    sender_summary: dict[str, Any],
) -> dict[str, float]:
    """Compute delivered UDP rates from the h2-side pcap."""
    attack_packets = packets[packets["timestamp_sec"] >= args.attack_start_sec].copy()
    attack_duration = max(0.0, args.duration_sec - args.attack_start_sec)
    if attack_packets.empty or attack_duration <= 0:
        return {
            "udp_actual_total_burst_rate_mbps": 0.0,
            "udp_actual_total_average_rate_mbps": 0.0,
            "udp_actual_per_flow_burst_rate_mbps": 0.0,
            "udp_actual_per_flow_average_rate_mbps": 0.0,
            "feint_actual_rate_mbps": 0.0,
            "attack_actual_rate_mbps": 0.0,
        }
    mode = "single_flow_ldos" if scenario == "single_flow_ldos" else condition.attack_mode
    num_flows = 1 if scenario == "single_flow_ldos" else condition.num_attack_flows
    period_sec = condition.period_ms / 1000.0
    burst_sec = condition.burst_ms / 1000.0
    spread_sec = float(sender_summary.get("phase_spread_ms", condition.phase_spread_ms)) / 1000.0
    if mode in {"single_flow_ldos", "multi_flow_sync_lddos"}:
        spread_sec = 0.0
    attack_span = min(period_sec, burst_sec + spread_sec)
    phase = (attack_packets["timestamp_sec"].astype(float) - args.attack_start_sec) % period_sec
    if mode == "f_lddos" and condition.attack_interval_placement == "end":
        interval_start = max(0.0, period_sec - attack_span)
        attack_mask = phase >= interval_start
        attack_active_duration = periodic_interval_duration(
            attack_duration,
            period_sec,
            interval_start,
            period_sec,
        )
    else:
        attack_mask = phase < attack_span
        attack_active_duration = periodic_interval_duration(
            attack_duration,
            period_sec,
            0.0,
            attack_span,
        )
    observed_attack = attack_packets[attack_mask]
    observed_feint = attack_packets[~attack_mask] if mode == "f_lddos" else attack_packets.iloc[0:0]
    total_bits = float(attack_packets["packet_size"].astype(float).sum() * 8.0)
    attack_bits = float(observed_attack["packet_size"].astype(float).sum() * 8.0)
    feint_bits = float(observed_feint["packet_size"].astype(float).sum() * 8.0)
    feint_duration = max(0.0, attack_duration - attack_active_duration)
    return {
        "udp_actual_total_burst_rate_mbps": bits_to_mbps(attack_bits, attack_active_duration),
        "udp_actual_total_average_rate_mbps": bits_to_mbps(total_bits, attack_duration),
        "udp_actual_per_flow_burst_rate_mbps": bits_to_mbps(
            attack_bits, attack_active_duration * max(1, num_flows)
        ),
        "udp_actual_per_flow_average_rate_mbps": bits_to_mbps(
            total_bits, attack_duration * max(1, num_flows)
        ),
        "feint_actual_rate_mbps": bits_to_mbps(feint_bits, feint_duration),
        "attack_actual_rate_mbps": bits_to_mbps(attack_bits, attack_active_duration),
    }


def periodic_interval_duration(
    duration_sec: float,
    period_sec: float,
    interval_start_sec: float,
    interval_end_sec: float,
) -> float:
    """Return total duration covered by a periodic sub-interval."""
    total = 0.0
    period_start = 0.0
    while period_start < duration_sec:
        start = period_start + interval_start_sec
        end = min(period_start + interval_end_sec, duration_sec)
        total += max(0.0, end - start)
        period_start += period_sec
    return total


def bits_to_mbps(bits: float, duration_sec: float) -> float:
    """Return Mbps from bits over duration."""
    return bits / duration_sec / 1_000_000.0 if duration_sec > 0 else 0.0


def write_iperf_summary(source: Path, output: Path) -> None:
    """Write a compact iperf JSON summary."""
    data = json.loads(source.read_text(encoding="utf-8"))
    end = data.get("end", {})
    summary = {
        "sum_sent": end.get("sum_sent", {}),
        "sum_received": end.get("sum_received", {}),
        "cpu_utilization_percent": end.get("cpu_utilization_percent", {}),
    }
    output.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def retransmission_summary(
    scenario: str,
    throughput: pd.DataFrame,
    ss_frame: pd.DataFrame,
) -> dict[str, Any]:
    """Build retransmission and zero-throughput summary."""
    return {
        "scenario": scenario,
        "iperf_retransmits": int(throughput["tcp_retransmits"].sum()) if "tcp_retransmits" in throughput else 0,
        "ss_retrans_total_max": numeric_max(ss_frame, "retrans_total"),
        "zero_throughput_interval_count": int((throughput["tcp_throughput_bps"] <= 0.0).sum()),
        "zero_throughput_interval_ratio": float((throughput["tcp_throughput_bps"] <= 0.0).mean())
        if not throughput.empty
        else 0.0,
    }


def numeric_max(frame: pd.DataFrame, column: str) -> float:
    """Return numeric max for an optional column."""
    if frame.empty or column not in frame:
        return 0.0
    values = pd.to_numeric(frame[column], errors="coerce").dropna()
    return float(values.max()) if not values.empty else 0.0


def read_optional_csv(path: Path) -> pd.DataFrame:
    """Read an optional non-empty CSV."""
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def shell_join(command: list[Any]) -> str:
    """Quote a shell command."""
    return " ".join(shlex.quote(str(item)) for item in command)


if __name__ == "__main__":
    main()
