"""Run TCP throughput-impact experiments for missed stat-matched LDoS traffic."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import shutil
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
from src.paper_reproduction_detector import PaperDetectorConfig, run_paper_detector_by_seed
from src.throughput_impact import (
    PAPER_FEATURES,
    THROUGHPUT_SCENARIOS,
    build_confusion_matrices,
    build_detector_metrics,
    build_missed_harmful_windows,
    build_no_attack_windows,
    build_throughput_metrics,
    enrich_window_predictions,
    parse_iperf_json,
    write_throughput_outputs,
)
from src.utils import ensure_dir


UDP_PORT = 5001
IPERF_PORT = 5201


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Run Mininet TCP throughput-impact LDoS experiment.")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--period-ms", type=int, default=1000)
    parser.add_argument("--burst-ms", type=int, default=200)
    parser.add_argument("--burst-pkts-per-bucket", type=int, default=10)
    parser.add_argument("--payload-size", type=int, default=80)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument(
        "--attack-start-sec",
        type=float,
        default=20.0,
        help="Start TCP at t=0, then start UDP attack/microburst traffic after this many seconds.",
    )
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--warmup-windows", type=int, default=20)
    parser.add_argument("--score-threshold", type=int, default=2)
    parser.add_argument("--min-packets-for-detection", type=int, default=10)
    parser.add_argument(
        "--detector-profile",
        choices=["current", "phase3"],
        default="current",
        help=(
            "current keeps the throughput-impact traffic timing; phase3 adds a UDP benign baseline "
            "before attack and uses Phase3-compatible attack labels."
        ),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("results_throughput"))
    parser.add_argument("--scenarios", nargs="+", choices=THROUGHPUT_SCENARIOS, default=THROUGHPUT_SCENARIOS)
    parser.add_argument(
        "--synthetic-test",
        action="store_true",
        help="Generate deterministic synthetic outputs without running Mininet; for CI/local smoke tests only.",
    )
    return parser.parse_args()


def main() -> None:
    """Run throughput-impact experiment and write output artifacts."""
    args = parse_args()
    validate_args(args)
    output_dir = ensure_dir(args.output_dir)
    if args.synthetic_test:
        run_synthetic_test(args, output_dir)
        return

    assert_mininet_environment()
    from mininet.clean import cleanup
    from mininet.link import TCLink
    from mininet.net import Mininet

    from minimal_topo import MinimalABTopo

    cleanup()
    network: Mininet | None = None
    timeseries_frames: list[pd.DataFrame] = []
    window_frames: list[pd.DataFrame] = []
    notes: list[str] = [f"detector_profile: {args.detector_profile}"]
    try:
        network = Mininet(topo=MinimalABTopo(), link=TCLink, autoSetMacs=True, autoStaticArp=True)
        network.start()
        for scenario in args.scenarios:
            scenario_dir = ensure_dir(output_dir / scenario)
            throughput, windows = run_one_scenario(network, scenario, args, scenario_dir)
            timeseries_frames.append(throughput)
            window_frames.append(windows)
    finally:
        if network is not None:
            network.stop()
        cleanup()

    write_aggregate_outputs(
        output_dir,
        timeseries_frames,
        window_frames,
        notes=notes,
        attack_start_sec=args.attack_start_sec,
    )


def validate_args(args: argparse.Namespace) -> None:
    """Validate throughput experiment arguments."""
    if args.duration_sec <= 0:
        raise SystemExit("--duration-sec must be positive")
    if args.attack_start_sec < 0:
        raise SystemExit("--attack-start-sec must be non-negative")
    if args.attack_start_sec >= args.duration_sec:
        raise SystemExit("--attack-start-sec must be smaller than --duration-sec")


def assert_mininet_environment() -> None:
    """Fail with clear guidance outside WSL2/Ubuntu Mininet environments."""
    if platform.system() != "Linux":
        raise SystemExit("This Mininet experiment is intended for WSL2/Ubuntu Linux, not macOS.")
    if os.geteuid() != 0:
        raise SystemExit("Mininet requires root privileges. Run with sudo.")
    missing = [command for command in ("mn", "tcpdump", "iperf3") if shutil.which(command) is None]
    if missing:
        raise SystemExit(
            "Missing required command(s): "
            + ", ".join(missing)
            + ". Run `bash scripts/setup_wsl_ubuntu_mininet.sh` on WSL2 Ubuntu."
        )
    try:
        __import__("mininet")
    except ImportError as exc:
        raise SystemExit("The Mininet Python package is missing. Install Mininet on WSL2 Ubuntu.") from exc


def run_one_scenario(
    network: Any,
    scenario: str,
    args: argparse.Namespace,
    scenario_dir: Path,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Run one throughput scenario in Mininet."""
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
            [
                "iperf3",
                "-c",
                "10.0.0.2",
                "-p",
                str(IPERF_PORT),
                "-t",
                str(int(args.duration_sec)),
                "-i",
                "1",
                "-J",
            ],
            iperf_json,
        )
        experiment_start_wall = time.time()
        if (
            has_udp
            and args.attack_start_sec > 0
            and (args.detector_profile == "current" or scenario == "random_microburst_only")
        ):
            time.sleep(args.attack_start_sec)
        run_udp_for_scenario(h3, h4, scenario, args, send_log_dir, scenario_dir)
        wait_for_process(h1, iperf_client_pid)
        time.sleep(0.5)
    finally:
        stop_background(h1, iperf_client_pid)
        stop_background(h2, tcpdump_pid)
        stop_background(h2, sink_pid)
        stop_background(h2, iperf_server_pid)

    throughput = parse_iperf_json(iperf_json, scenario)
    throughput.to_csv(scenario_dir / "tcp_throughput_timeseries.csv", index=False)
    windows = build_windows_for_scenario(scenario, args, pcap_path, throughput, scenario_dir, experiment_start_wall)
    windows.to_csv(scenario_dir / "window_detailed_log.csv", index=False)
    return throughput, windows


def run_udp_for_scenario(
    h3: Any,
    h4: Any,
    scenario: str,
    args: argparse.Namespace,
    send_log_dir: Path,
    scenario_dir: Path,
) -> None:
    """Run the UDP generator required by a scenario."""
    if scenario == "no_attack":
        return
    if args.detector_profile == "phase3" and scenario in {"original_like_ldos", "stat_matched_ldos"}:
        run_phase3_baseline_then_attack(h3, h4, scenario, args, send_log_dir, scenario_dir)
        return
    if scenario == "random_microburst_only":
        run_generator(
            h4,
            "send_random_microburst.py",
            args,
            send_log_dir / "random_microburst_send_log.csv",
            scenario_dir / "random_microburst_stdout.log",
            src_port=40004,
            duration_sec=max(0.0, args.duration_sec - args.attack_start_sec),
            extra=["--seed", str(args.seed)],
        )
    elif scenario in {"original_like_ldos", "stat_matched_ldos"}:
        run_generator(
            h3,
            "send_periodic_ldos.py",
            args,
            send_log_dir / f"{scenario}_send_log.csv",
            scenario_dir / f"{scenario}_stdout.log",
            src_port=40003,
            duration_sec=max(0.0, args.duration_sec - args.attack_start_sec),
            extra=[],
        )
    else:
        raise ValueError(f"unknown scenario: {scenario}")


def run_phase3_baseline_then_attack(
    h3: Any,
    h4: Any,
    scenario: str,
    args: argparse.Namespace,
    send_log_dir: Path,
    scenario_dir: Path,
) -> None:
    """Run Phase3-compatible UDP baseline first, then periodic LDoS attack."""
    if scenario == "original_like_ldos":
        run_generator(
            h4,
            "send_normal_benign.py",
            args,
            send_log_dir / "normal_benign_baseline_send_log.csv",
            scenario_dir / "normal_benign_baseline_stdout.log",
            src_port=40004,
            duration_sec=args.attack_start_sec,
            extra=["--seed", str(args.seed)],
        )
    elif scenario == "stat_matched_ldos":
        run_generator(
            h4,
            "send_random_microburst.py",
            args,
            send_log_dir / "random_microburst_baseline_send_log.csv",
            scenario_dir / "random_microburst_baseline_stdout.log",
            src_port=40004,
            duration_sec=args.attack_start_sec,
            extra=["--seed", str(args.seed)],
        )
    else:
        raise ValueError(f"phase3 profile does not support scenario: {scenario}")

    run_generator(
        h3,
        "send_periodic_ldos.py",
        args,
        send_log_dir / f"{scenario}_attack_send_log.csv",
        scenario_dir / f"{scenario}_attack_stdout.log",
        src_port=40003,
        duration_sec=max(0.0, args.duration_sec - args.attack_start_sec),
        extra=[],
    )


def build_windows_for_scenario(
    scenario: str,
    args: argparse.Namespace,
    pcap_path: Path,
    throughput: pd.DataFrame,
    scenario_dir: Path,
    experiment_start_wall: float,
) -> pd.DataFrame:
    """Build enriched detector/throughput windows for one scenario."""
    if scenario == "no_attack":
        return build_no_attack_windows(
            scenario,
            throughput,
            args.window_sec,
            args.step_sec,
            args.duration_sec,
            args.attack_start_sec,
        )

    attack_start_sec = args.attack_start_sec if scenario in {"original_like_ldos", "stat_matched_ldos"} else None
    features, packets = build_features_from_pcap(
        pcap_path=pcap_path,
        bucket_ms=args.bucket_ms,
        window_sec=args.window_sec,
        step_sec=args.step_sec,
        duration_sec=args.duration_sec,
        attack_start_sec=attack_start_sec,
        time_origin_sec=experiment_start_wall if experiment_start_wall > 0 else None,
        dst_port=UDP_PORT,
    )
    if scenario == "random_microburst_only":
        features["label"] = "benign"
        features["target"] = 0
    else:
        features["label"] = np.where(
            attack_label_mask(features, args.attack_start_sec, args.detector_profile),
            "attack",
            "benign",
        )
        features["target"] = (features["label"] == "attack").astype(int)
    features.insert(0, "scenario", scenario)
    features.insert(1, "seed", args.seed)
    features["stream_id"] = f"{scenario}_seed_{args.seed}"
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


def attack_label_mask(features: pd.DataFrame, attack_start_sec: float, detector_profile: str) -> pd.Series:
    """Return attack-label mask for the selected detector evaluation profile."""
    if detector_profile == "phase3":
        return features["window_start_sec"] >= attack_start_sec
    return features["window_end_sec"] > attack_start_sec


def write_aggregate_outputs(
    output_dir: Path,
    timeseries_frames: list[pd.DataFrame],
    window_frames: list[pd.DataFrame],
    notes: list[str] | None = None,
    attack_start_sec: float = 0.0,
) -> None:
    """Write aggregate throughput-impact outputs."""
    timeseries = pd.concat(timeseries_frames, ignore_index=True) if timeseries_frames else pd.DataFrame()
    window_log = pd.concat(window_frames, ignore_index=True) if window_frames else pd.DataFrame()
    throughput_metrics = build_throughput_metrics(timeseries, attack_start_sec)
    detector_metrics = build_detector_metrics(window_log, attack_start_sec)
    confusion_matrices = build_confusion_matrices(detector_metrics)
    missed_harmful = build_missed_harmful_windows(window_log)
    write_throughput_outputs(
        output_dir=output_dir,
        timeseries=timeseries,
        window_log=window_log,
        throughput_metrics=throughput_metrics,
        detector_metrics=detector_metrics,
        confusion_matrices=confusion_matrices,
        missed_harmful=missed_harmful,
        attack_start_sec=attack_start_sec,
        notes=notes or [],
    )


def run_synthetic_test(args: argparse.Namespace, output_dir: Path) -> None:
    """Generate deterministic synthetic data and all output files without Mininet."""
    timeseries_frames: list[pd.DataFrame] = []
    window_frames: list[pd.DataFrame] = []
    synthetic_mbps = {
        "no_attack": 90.0,
        "random_microburst_only": 84.0,
        "original_like_ldos": 50.0,
        "stat_matched_ldos": 56.0,
    }
    for scenario in args.scenarios:
        timeseries = synthetic_throughput(scenario, args.duration_sec, args.attack_start_sec, synthetic_mbps[scenario])
        timeseries_frames.append(timeseries)
        windows = synthetic_windows(scenario, args, timeseries)
        window_frames.append(windows)
    write_aggregate_outputs(
        output_dir,
        timeseries_frames,
        window_frames,
        notes=["synthetic-test mode: Mininet was not executed; outputs are smoke-test artifacts."],
        attack_start_sec=args.attack_start_sec,
    )


def synthetic_throughput(
    scenario: str,
    duration_sec: float,
    attack_start_sec: float,
    attack_mbps: float,
) -> pd.DataFrame:
    """Build deterministic synthetic iperf-like throughput."""
    rows = []
    for index in range(int(duration_sec)):
        wave = 2.0 * np.sin(index / 4.0)
        base_mbps = 90.0 if index < attack_start_sec else attack_mbps
        rows.append(
            {
                "scenario": scenario,
                "interval_index": index,
                "start_sec": float(index),
                "end_sec": float(index + 1),
                "tcp_throughput_bps": (base_mbps + wave) * 1_000_000.0,
                "tcp_throughput_mbps": base_mbps + wave,
            }
        )
    return pd.DataFrame(rows)


def synthetic_windows(scenario: str, args: argparse.Namespace, throughput: pd.DataFrame) -> pd.DataFrame:
    """Build deterministic synthetic window logs matching requested output columns."""
    if scenario == "no_attack":
        return build_no_attack_windows(
            scenario,
            throughput,
            args.window_sec,
            args.step_sec,
            args.duration_sec,
            args.attack_start_sec,
        )
    starts = np.arange(0.0, max(args.duration_sec - args.window_sec + 1e-9, 0.0) + 1e-9, args.step_sec)
    rows = []
    for index, start in enumerate(starts):
        if args.detector_profile == "phase3":
            overlaps_attack = start >= args.attack_start_sec
        else:
            overlaps_attack = start + args.window_sec > args.attack_start_sec
        is_attack = scenario in {"original_like_ldos", "stat_matched_ldos"} and overlaps_attack
        if scenario == "original_like_ldos":
            score = 2 if is_attack and index >= args.warmup_windows else 0
        elif scenario == "stat_matched_ldos":
            score = 2 if is_attack and index in {args.warmup_windows + 5, args.warmup_windows + 12} else 1
            if not is_attack or index < args.warmup_windows:
                score = 0
        else:
            score = 0
        row: dict[str, Any] = {
            "scenario": scenario,
            "attack_start_sec": args.attack_start_sec,
            "window_index": index,
            "window_start_sec": start,
            "window_end_sec": start + args.window_sec,
            "label": "attack" if is_attack else "benign",
            "true_label": "attack" if is_attack else "benign",
            "pred_label": "attack" if score >= args.score_threshold else "benign",
            "pred_attack": score >= args.score_threshold,
            "true_attack": is_attack,
            "suspicious_score": score,
            "total_packets": 320 if scenario != "random_microburst_only" else 320,
            "is_warmup": index < args.warmup_windows,
            "detection_enabled": index >= args.warmup_windows,
            "enough_packets_for_detection": True,
            "tcp_throughput_bps": 0.0,
        }
        row["tcp_throughput_bps"] = float(
            throughput[
                (throughput["start_sec"] < row["window_end_sec"]) & (throughput["end_sec"] > row["window_start_sec"])
            ]["tcp_throughput_bps"].mean()
        )
        row["tcp_throughput_mbps"] = row["tcp_throughput_bps"] / 1_000_000.0
        for feature_idx, feature in enumerate(PAPER_FEATURES):
            value = 0.01 * (feature_idx + 1) + 0.001 * index
            threshold = value - 0.001 if score >= 2 and feature_idx < 2 else value + 0.01
            row[feature] = value
            row[f"{feature}_mu"] = value * 0.9
            row[f"{feature}_ema"] = value * 0.9
            row[f"{feature}_sigma"] = abs(value) * 0.05
            row[f"{feature}_threshold"] = threshold
            row[f"{feature}_margin"] = value - threshold
            row[f"{feature}_abnormal"] = score >= 2 and feature_idx < 2
            row[f"{feature}_ema_updated"] = not row[f"{feature}_abnormal"] or row["is_warmup"]
            row[f"{feature}_ema_skipped"] = row[f"{feature}_abnormal"] and not row["is_warmup"]
        row["ema_updated_any"] = any(row[f"{feature}_ema_updated"] for feature in PAPER_FEATURES)
        row["ema_skipped_any"] = any(row[f"{feature}_ema_skipped"] for feature in PAPER_FEATURES)
        rows.append(row)
    return pd.DataFrame(rows)


def run_generator(
    host: Any,
    script_name: str,
    args: argparse.Namespace,
    send_log: Path,
    stdout_log: Path,
    src_port: int,
    duration_sec: float,
    extra: list[str],
) -> None:
    """Run one UDP traffic generator synchronously inside a Mininet host."""
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
        "--bucket-ms",
        str(args.bucket_ms),
        "--payload-size",
        str(args.payload_size),
    ]
    if script_name != "send_normal_benign.py":
        command.extend(
            [
                "--period-ms",
                str(args.period_ms),
                "--burst-ms",
                str(args.burst_ms),
                "--burst-pkts-per-bucket",
                str(args.burst_pkts_per_bucket),
            ]
        )
    command.extend(["--log", str(send_log), *extra])
    host.cmd(shell_join(command) + f" > {shlex.quote(str(stdout_log))} 2>&1")


def start_tcpdump(host: Any, pcap_path: Path, log_path: Path) -> str:
    """Start tcpdump for UDP experiment traffic."""
    return start_background(
        host,
        ["tcpdump", "-i", "h2-eth0", "-U", "-w", str(pcap_path), f"udp port {UDP_PORT}"],
        log_path,
    )


def start_background(host: Any, command: list[str], log_path: Path) -> str:
    """Start a background process in a Mininet host and return its shell PID."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    shell_command = shell_join(command) + f" > {shlex.quote(str(log_path))} 2>&1 & echo $!"
    output = host.cmd(shell_command).strip()
    if not output:
        raise RuntimeError(f"failed to start command on {host.name}: {command}")
    return output.splitlines()[-1].strip()


def wait_for_process(host: Any, pid: str) -> None:
    """Wait until a background process exits."""
    if pid:
        host.cmd(f"while kill -0 {shlex.quote(str(pid))} >/dev/null 2>&1; do sleep 0.2; done")


def stop_background(host: Any, pid: str) -> None:
    """Terminate a background process if it still exists."""
    if pid:
        host.cmd(f"kill -TERM {shlex.quote(str(pid))} >/dev/null 2>&1 || true")
        time.sleep(0.2)
        host.cmd(f"kill -KILL {shlex.quote(str(pid))} >/dev/null 2>&1 || true")


def shell_join(command: list[str]) -> str:
    """Quote a command list for shell execution inside Mininet hosts."""
    return " ".join(shlex.quote(str(item)) for item in command)


def py() -> str:
    """Return current Python executable."""
    return sys.executable


if __name__ == "__main__":
    main()
