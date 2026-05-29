"""Run Mininet A/B experiments and evaluate the four-feature paper detector."""

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

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MININET_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(MININET_ROOT) not in sys.path:
    sys.path.insert(0, str(MININET_ROOT))

from pcap_to_features import build_features_from_pcap
from plot_mininet_results import create_overview_dashboard
from src.paper_reproduction_detector import (
    PAPER_FEATURES,
    PaperDetectorConfig,
    run_paper_detector_by_seed,
)
from src.utils import ensure_dir, markdown_table


DEFAULT_SCENARIOS = ["original_like", "stat_matched"]
UDP_PORT = 5001
IPERF_PORT = 5201


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Run Mininet A/B LDoS detector experiments.")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--period-ms", type=int, default=1000)
    parser.add_argument("--burst-ms", type=int, default=200)
    parser.add_argument("--burst-pkts-per-bucket", type=int, default=10)
    parser.add_argument("--payload-size", type=int, default=80)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--warmup-windows", type=int, default=20)
    parser.add_argument("--score-threshold", type=int, default=2)
    parser.add_argument("--min-packets-for-detection", type=int, default=10)
    parser.add_argument("--output-dir", type=Path, default=Path("results_mininet_ab"))
    parser.add_argument("--scenarios", nargs="+", choices=DEFAULT_SCENARIOS, default=DEFAULT_SCENARIOS)
    return parser.parse_args()


def main() -> None:
    """Run requested Mininet scenarios and write evaluation artifacts."""
    args = parse_args()
    assert_mininet_environment()
    from mininet.clean import cleanup
    from mininet.link import TCLink
    from mininet.net import Mininet

    from minimal_topo import MinimalABTopo

    output_dir = ensure_dir(args.output_dir)
    cleanup()
    metrics_by_scenario: dict[str, dict[str, Any]] = {}
    features_by_scenario: dict[str, pd.DataFrame] = {}
    predictions_by_scenario: dict[str, pd.DataFrame] = {}
    network: Mininet | None = None

    try:
        network = Mininet(topo=MinimalABTopo(), link=TCLink, autoSetMacs=True, autoStaticArp=True)
        network.start()
        for scenario in args.scenarios:
            scenario_dir = ensure_dir(output_dir / scenario)
            metrics, features, predictions = run_one_scenario(network, scenario, args, scenario_dir)
            metrics_by_scenario[scenario] = metrics
            features_by_scenario[scenario] = features
            predictions_by_scenario[scenario] = predictions
    finally:
        if network is not None:
            network.stop()
        cleanup()

    if metrics_by_scenario:
        comparison = build_metrics_comparison(metrics_by_scenario)
        comparison.to_csv(output_dir / "metrics_comparison.csv", index=False)
        plot_metrics_comparison(comparison, output_dir / "metrics_comparison.png")
        for scenario, features in features_by_scenario.items():
            plot_feature_distribution(features, output_dir / f"feature_distribution_{scenario}.png", scenario)
        if "stat_matched" in predictions_by_scenario:
            plot_suspicious_score_distribution(
                predictions_by_scenario["stat_matched"],
                output_dir / "suspicious_score_distribution_stat_matched.png",
            )
        write_summary(args, metrics_by_scenario, output_dir / "mininet_ab_summary.md")
        create_overview_dashboard(output_dir, output_dir / "mininet_ab_overview.png")


def assert_mininet_environment() -> None:
    """Fail early with clear setup errors for non-Mininet environments."""
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
) -> tuple[dict[str, Any], pd.DataFrame, pd.DataFrame]:
    """Run one A/B scenario, parse pcap, and evaluate detector predictions."""
    h1, h2, h3, h4 = [network.get(name) for name in ("h1", "h2", "h3", "h4")]
    send_log_dir = ensure_dir(scenario_dir / "send_logs")
    pcap_path = scenario_dir / f"{scenario}.pcap"
    sink_log = scenario_dir / "sink_log.csv"
    total_duration = args.duration_sec * 2.0 + 8.0
    attack_start_sec = args.duration_sec

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
            str(total_duration),
            "--log",
            str(sink_log),
        ],
        scenario_dir / "udp_sink.log",
    )
    tcpdump_pid = start_tcpdump(h2, pcap_path, scenario_dir / "tcpdump.log")
    iperf_pids: list[tuple[Any, str]] = []
    try:
        time.sleep(1.0)
        if scenario == "original_like":
            iperf_pids = start_iperf_background(h1, h2, scenario_dir, total_duration)
            run_generator(
                h4,
                "send_normal_benign.py",
                args,
                send_log_dir / "normal_benign_send_log.csv",
                scenario_dir / "normal_benign_stdout.log",
                src_port=40004,
                extra=["--seed", str(args.seed)],
            )
        elif scenario == "stat_matched":
            run_generator(
                h4,
                "send_random_microburst.py",
                args,
                send_log_dir / "random_microburst_send_log.csv",
                scenario_dir / "random_microburst_stdout.log",
                src_port=40004,
                extra=["--seed", str(args.seed)],
            )
        else:
            raise ValueError(f"unknown scenario: {scenario}")

        run_generator(
            h3,
            "send_periodic_ldos.py",
            args,
            send_log_dir / "periodic_ldos_send_log.csv",
            scenario_dir / "periodic_ldos_stdout.log",
            src_port=40003,
            extra=[],
        )
        time.sleep(1.0)
    finally:
        for host, pid in iperf_pids:
            stop_background(host, pid)
        stop_background(h2, tcpdump_pid)
        stop_background(h2, sink_pid)

    features, _packets = build_features_from_pcap(
        pcap_path=pcap_path,
        bucket_ms=args.bucket_ms,
        window_sec=args.window_sec,
        step_sec=args.step_sec,
        duration_sec=args.duration_sec * 2.0,
        attack_start_sec=attack_start_sec,
        dst_port=UDP_PORT,
    )
    features.insert(0, "dataset", scenario)
    features.insert(1, "seed", args.seed)
    features.insert(2, "scenario", scenario)
    features["stream_id"] = f"{scenario}_seed_{args.seed}"
    features["stream_time_sec"] = features["window_start_sec"]
    features["stream_window_end_sec"] = features["window_end_sec"]
    features["attack_start_sec"] = attack_start_sec
    features.to_csv(scenario_dir / "features.csv", index=False)

    detector_config = PaperDetectorConfig(
        warmup_windows=args.warmup_windows,
        min_packets_for_detection=args.min_packets_for_detection,
        suspicious_threshold=args.score_threshold,
        use_observed_initial_state=True,
    )
    predictions = run_paper_detector_by_seed(features, detector_config)
    predictions.to_csv(scenario_dir / "predictions.csv", index=False)
    metrics = evaluate_predictions(predictions, attack_start_sec, args.step_sec)
    write_json(metrics, scenario_dir / "metrics.json")
    plot_confusion_matrix(metrics, scenario, scenario_dir / "confusion_matrix.png")
    return metrics, features, predictions


def run_generator(
    host: Any,
    script_name: str,
    args: argparse.Namespace,
    send_log: Path,
    stdout_log: Path,
    src_port: int,
    extra: list[str],
) -> None:
    """Run one traffic generator synchronously in a Mininet host."""
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
        str(args.duration_sec),
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
    command.extend(
        [
            "--log",
            str(send_log),
            *extra,
        ]
    )
    shell_command = shell_join(command) + f" > {shlex.quote(str(stdout_log))} 2>&1"
    host.cmd(shell_command)


def start_tcpdump(host: Any, pcap_path: Path, log_path: Path) -> str:
    """Start tcpdump on h2's Mininet interface and return its PID."""
    command = [
        "tcpdump",
        "-i",
        "h2-eth0",
        "-U",
        "-w",
        str(pcap_path),
        f"udp port {UDP_PORT}",
    ]
    return start_background(host, command, log_path)


def start_iperf_background(host_client: Any, host_server: Any, output_dir: Path, duration_sec: float) -> list[tuple[Any, str]]:
    """Start iperf3 TCP server/client background traffic for original_like."""
    server_pid = start_background(
        host_server,
        ["iperf3", "-s", "-p", str(IPERF_PORT)],
        output_dir / "iperf_server.log",
    )
    time.sleep(0.5)
    client_pid = start_background(
        host_client,
        ["iperf3", "-c", "10.0.0.2", "-p", str(IPERF_PORT), "-t", str(int(duration_sec))],
        output_dir / "iperf_client.log",
    )
    return [(host_client, client_pid), (host_server, server_pid)]


def start_background(host: Any, command: list[str], log_path: Path) -> str:
    """Start a background process in a Mininet host and return its shell PID."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    shell_command = shell_join(command) + f" > {shlex.quote(str(log_path))} 2>&1 & echo $!"
    output = host.cmd(shell_command).strip()
    if not output:
        raise RuntimeError(f"failed to start command on {host.name}: {command}")
    return output.splitlines()[-1].strip()


def stop_background(host: Any, pid: str) -> None:
    """Terminate a background process if it is still running."""
    if pid:
        host.cmd(f"kill -TERM {shlex.quote(str(pid))} >/dev/null 2>&1 || true")
        time.sleep(0.2)
        host.cmd(f"kill -KILL {shlex.quote(str(pid))} >/dev/null 2>&1 || true")


def evaluate_predictions(predictions: pd.DataFrame, attack_start_sec: float, step_sec: float) -> dict[str, Any]:
    """Compute detector metrics and detection delay."""
    evaluated = predictions[~predictions["is_warmup"].astype(bool)].copy()
    y_true = evaluated["true_attack"].astype(bool)
    y_pred = evaluated["pred_attack"].astype(bool)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[False, True]).ravel()
    first_detection = evaluated[y_true & y_pred].sort_values("window_start_sec").head(1)
    if first_detection.empty:
        detection_delay = None
        detection_window = None
    else:
        first = first_detection.iloc[0]
        detection_delay = max(0.0, float(first["window_end_sec"]) - attack_start_sec)
        detection_window = int((float(first["window_start_sec"]) - attack_start_sec) / step_sec) + 1

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": safe_divide(fp, fp + tn),
        "false_negative_rate": safe_divide(fn, fn + tp),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "detection_delay_sec": detection_delay,
        "detection_window_after_attack": detection_window,
        "periodic_ldos_detection_rate": safe_divide(tp, tp + fn),
        "benign_false_attack_rate": safe_divide(fp, fp + tn),
        "evaluated_windows": int(len(evaluated)),
        "total_windows": int(len(predictions)),
    }


def build_metrics_comparison(metrics_by_scenario: dict[str, dict[str, Any]]) -> pd.DataFrame:
    """Build a metric comparison table."""
    rows = []
    original = metrics_by_scenario.get("original_like", {})
    stat = metrics_by_scenario.get("stat_matched", {})
    for metric in [
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "false_positive_rate",
        "false_negative_rate",
        "detection_delay_sec",
    ]:
        original_value = original.get(metric)
        stat_value = stat.get(metric)
        delta = None if original_value is None or stat_value is None else float(stat_value) - float(original_value)
        rows.append(
            {
                "metric": metric,
                "original_like": original_value,
                "stat_matched": stat_value,
                "stat_minus_original": delta,
            }
        )
    return pd.DataFrame(rows)


def plot_confusion_matrix(metrics: dict[str, Any], title: str, output_path: Path) -> None:
    """Save a confusion matrix plot."""
    cm = metrics["confusion_matrix"]
    matrix = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]], dtype=int)
    fig, axis = plt.subplots(figsize=(4.8, 4.2), constrained_layout=True)
    image = axis.imshow(matrix, cmap="Blues")
    axis.set_xticks([0, 1], ["pred benign", "pred attack"])
    axis.set_yticks([0, 1], ["true benign", "true attack"])
    axis.set_title(f"{title} confusion matrix")
    for row in range(2):
        for column in range(2):
            axis.text(column, row, str(matrix[row, column]), ha="center", va="center")
    fig.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def plot_metrics_comparison(comparison: pd.DataFrame, output_path: Path) -> None:
    """Save F1/FPR/FNR comparison plot."""
    selected = comparison[comparison["metric"].isin(["f1_score", "false_positive_rate", "false_negative_rate"])]
    x = np.arange(len(selected))
    width = 0.36
    fig, axis = plt.subplots(figsize=(8.8, 4.4), constrained_layout=True)
    axis.bar(x - width / 2, selected["original_like"].fillna(0), width, label="original_like")
    axis.bar(x + width / 2, selected["stat_matched"].fillna(0), width, label="stat_matched")
    axis.set_xticks(x)
    axis.set_xticklabels(selected["metric"], rotation=15)
    axis.set_ylim(0.0, 1.05)
    axis.set_title("Mininet A/B detector metrics")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def plot_feature_distribution(features: pd.DataFrame, output_path: Path, title: str) -> None:
    """Save simple label-split feature distributions."""
    fig, axes = plt.subplots(2, 2, figsize=(10, 7), constrained_layout=True)
    for axis, feature in zip(axes.ravel(), PAPER_FEATURES):
        for label, color in [("benign", "#4c78a8"), ("attack", "#f58518")]:
            values = features.loc[features["label"] == label, feature].dropna()
            if not values.empty:
                axis.hist(values, bins=20, alpha=0.65, label=label, color=color)
        axis.set_title(feature)
        axis.grid(axis="y", alpha=0.2)
    axes.ravel()[0].legend()
    fig.suptitle(f"{title} feature distributions")
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def plot_suspicious_score_distribution(predictions: pd.DataFrame, output_path: Path) -> None:
    """Save suspicious score distribution for the stat_matched condition."""
    fig, axis = plt.subplots(figsize=(6.6, 4.2), constrained_layout=True)
    for label, color in [("benign", "#4c78a8"), ("attack", "#f58518")]:
        values = predictions.loc[predictions["label"] == label, "suspicious_score"].dropna()
        if not values.empty:
            axis.hist(values, bins=np.arange(-0.5, 5.5, 1.0), alpha=0.7, label=label, color=color)
    axis.set_xticks([0, 1, 2, 3, 4])
    axis.set_title("stat_matched suspicious score distribution")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def write_summary(args: argparse.Namespace, metrics_by_scenario: dict[str, dict[str, Any]], output_path: Path) -> None:
    """Write a Markdown summary for the completed Mininet experiment."""
    comparison = build_metrics_comparison(metrics_by_scenario)
    rows = [
        [
            row["metric"],
            format_optional(row["original_like"]),
            format_optional(row["stat_matched"]),
            format_optional(row["stat_minus_original"]),
        ]
        for _, row in comparison.iterrows()
    ]
    original = metrics_by_scenario.get("original_like", {})
    stat = metrics_by_scenario.get("stat_matched", {})
    lines = [
        "# Mininet A/B experiment summary",
        "",
        "## Purpose",
        "",
        "This WSL2/Ubuntu Mininet experiment replays the A/B traffic conditions as real UDP packets, extracts the four paper-style statistical features from pcap, and evaluates the Python reproduction of the paper-style EMA + suspicious score detector.",
        "",
        "This is not a full reproduction of the original paper. It does not use eBPF/XDP, Mininet is only used as a packet testbed, and Goertzel/Sliding DFT features are not used.",
        "",
        "## Conditions",
        "",
        f"- duration per benign/attack segment: {args.duration_sec} sec",
        f"- bucket_ms: {args.bucket_ms}",
        f"- period_ms: {args.period_ms}",
        f"- burst_ms: {args.burst_ms}",
        f"- burst_pkts_per_bucket: {args.burst_pkts_per_bucket}",
        f"- payload_size: {args.payload_size}",
        f"- seed: {args.seed}",
        f"- warmup_windows: {args.warmup_windows}",
        f"- suspicious score threshold: {args.score_threshold}",
        "",
        "## Metrics",
        "",
        markdown_table(["metric", "original_like", "stat_matched", "stat_minus_original"], rows),
        "",
        "## Interpretation",
        "",
        interpret_metrics(original, stat),
        "",
        "If performance does not degrade under stat_matched, treat that as evidence that the four-feature detector remained strong in this Mininet packet setting. If F1/recall drops or FNR/FPR rises, the packet experiment reproduced the artificial bucket-level weakness.",
        "",
    ]
    output_path.write_text("\n".join(lines), encoding="utf-8")


def interpret_metrics(original: dict[str, Any], stat: dict[str, Any]) -> str:
    """Return a concise interpretation paragraph."""
    if not original or not stat:
        return "Only one scenario was run, so original_like vs stat_matched degradation cannot be compared."
    f1_drop = stat["f1_score"] - original["f1_score"]
    fpr_increase = stat["false_positive_rate"] - original["false_positive_rate"]
    fnr_increase = stat["false_negative_rate"] - original["false_negative_rate"]
    return (
        f"stat_matched minus original_like: F1={f1_drop:.6g}, "
        f"FPR={fpr_increase:.6g}, FNR={fnr_increase:.6g}. "
        "A negative F1 delta or positive FNR/FPR delta indicates detector degradation under stat-matched traffic."
    )


def write_json(data: dict[str, Any], output_path: Path) -> None:
    """Write JSON with indentation."""
    output_path.write_text(json.dumps(data, indent=2, allow_nan=False), encoding="utf-8")


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide with stable zero handling."""
    return 0.0 if denominator == 0 else float(numerator / denominator)


def format_optional(value: Any) -> str:
    """Format optional metric values for Markdown."""
    if value is None:
        return "None"
    if isinstance(value, float):
        if np.isnan(value):
            return "None"
        return f"{value:.6g}"
    return str(value)


def shell_join(command: list[str]) -> str:
    """Quote a command list for Mininet host shell execution."""
    return " ".join(shlex.quote(str(item)) for item in command)


def py() -> str:
    """Return the current Python executable path."""
    return sys.executable


if __name__ == "__main__":
    main()
