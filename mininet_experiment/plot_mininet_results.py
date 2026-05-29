"""Create an at-a-glance dashboard from Mininet A/B experiment outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


SCENARIOS = ["original_like", "stat_matched"]
PAPER_FEATURES = [
    "iat_variance",
    "burst_rate",
    "payload_size_variance",
    "new_flow_arrival_rate",
]
METRIC_COLUMNS = ["precision", "recall", "f1_score", "false_positive_rate", "false_negative_rate"]


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Plot a one-page Mininet A/B result dashboard.")
    parser.add_argument("--results-dir", type=Path, default=Path("results_mininet_ab"))
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args()


def main() -> None:
    """CLI entry point."""
    args = parse_args()
    output_path = args.output or args.results_dir / "mininet_ab_overview.png"
    create_overview_dashboard(args.results_dir, output_path)
    print(f"Wrote overview dashboard to {output_path.resolve()}")


def create_overview_dashboard(results_dir: Path, output_path: Path | None = None) -> Path:
    """Create a single PNG that summarizes metrics, confusion, delay, and scores."""
    if output_path is None:
        output_path = results_dir / "mininet_ab_overview.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    metrics = load_metrics(results_dir)
    features = load_frames(results_dir, "features.csv")
    predictions = load_frames(results_dir, "predictions.csv")
    if not metrics:
        raise FileNotFoundError(f"no metrics.json files found under {results_dir}")

    fig = plt.figure(figsize=(16, 12), constrained_layout=True)
    grid = fig.add_gridspec(3, 3)
    fig.suptitle("Mininet A/B Detector Overview", fontsize=18, fontweight="bold")

    plot_metric_bars(fig.add_subplot(grid[0, 0]), metrics)
    plot_delta_bars(fig.add_subplot(grid[0, 1]), metrics)
    plot_detection_delay(fig.add_subplot(grid[0, 2]), metrics)
    plot_confusion_matrix(fig.add_subplot(grid[1, 0]), metrics, "original_like")
    plot_confusion_matrix(fig.add_subplot(grid[1, 1]), metrics, "stat_matched")
    plot_feature_mean_heatmap(fig.add_subplot(grid[1, 2]), features)
    plot_suspicious_score_timeline(fig.add_subplot(grid[2, 0:2]), predictions)
    plot_conclusion_box(fig.add_subplot(grid[2, 2]), metrics)

    fig.savefig(output_path, dpi=170)
    plt.close(fig)
    return output_path


def load_metrics(results_dir: Path) -> dict[str, dict[str, Any]]:
    """Load scenario metrics from ``metrics.json`` files."""
    loaded: dict[str, dict[str, Any]] = {}
    for scenario in SCENARIOS:
        path = results_dir / scenario / "metrics.json"
        if path.exists():
            loaded[scenario] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def load_frames(results_dir: Path, filename: str) -> dict[str, pd.DataFrame]:
    """Load per-scenario CSV files if present."""
    frames: dict[str, pd.DataFrame] = {}
    for scenario in SCENARIOS:
        path = results_dir / scenario / filename
        if path.exists():
            frame = pd.read_csv(path)
            if "scenario" not in frame.columns:
                frame["scenario"] = scenario
            frames[scenario] = frame
    return frames


def plot_metric_bars(axis: plt.Axes, metrics: dict[str, dict[str, Any]]) -> None:
    """Plot key classification metrics by scenario."""
    available = [scenario for scenario in SCENARIOS if scenario in metrics]
    x = np.arange(len(METRIC_COLUMNS))
    width = 0.36 if len(available) > 1 else 0.5
    colors = {"original_like": "#4c78a8", "stat_matched": "#f58518"}
    for index, scenario in enumerate(available):
        offset = (index - (len(available) - 1) / 2) * width
        values = [float(metrics[scenario].get(metric, 0.0) or 0.0) for metric in METRIC_COLUMNS]
        axis.bar(x + offset, values, width=width, label=scenario, color=colors.get(scenario))
    axis.set_xticks(x)
    axis.set_xticklabels(["precision", "recall", "F1", "FPR", "FNR"], rotation=20, ha="right")
    axis.set_ylim(0.0, 1.05)
    axis.set_title("Detector Metrics")
    axis.grid(axis="y", alpha=0.25)
    axis.legend(loc="upper right")


def plot_delta_bars(axis: plt.Axes, metrics: dict[str, dict[str, Any]]) -> None:
    """Plot stat_matched minus original_like deltas."""
    if "original_like" not in metrics or "stat_matched" not in metrics:
        axis.text(0.5, 0.5, "Need both scenarios", ha="center", va="center")
        axis.set_axis_off()
        return
    delta_metrics = ["f1_score", "false_positive_rate", "false_negative_rate"]
    labels = ["F1 delta", "FPR delta", "FNR delta"]
    deltas = [
        float(metrics["stat_matched"].get(metric, 0.0) or 0.0)
        - float(metrics["original_like"].get(metric, 0.0) or 0.0)
        for metric in delta_metrics
    ]
    colors = [
        "#e45756" if deltas[0] < 0 else "#54a24b",
        "#e45756" if deltas[1] > 0 else "#54a24b",
        "#e45756" if deltas[2] > 0 else "#54a24b",
    ]
    axis.axhline(0.0, color="black", linewidth=1)
    axis.bar(labels, deltas, color=colors)
    axis.set_title("stat_matched - original_like")
    axis.set_ylim(-1.05, 1.05)
    axis.grid(axis="y", alpha=0.25)
    for index, value in enumerate(deltas):
        axis.text(index, value + (0.04 if value >= 0 else -0.08), f"{value:.3g}", ha="center")


def plot_detection_delay(axis: plt.Axes, metrics: dict[str, dict[str, Any]]) -> None:
    """Plot detection delay in seconds."""
    available = [scenario for scenario in SCENARIOS if scenario in metrics]
    values = []
    labels = []
    missed = []
    for scenario in available:
        delay = metrics[scenario].get("detection_delay_sec")
        values.append(0.0 if delay is None else float(delay))
        labels.append(scenario)
        missed.append(delay is None)
    colors = ["#bab0ac" if is_missed else "#72b7b2" for is_missed in missed]
    axis.bar(labels, values, color=colors)
    axis.set_title("Detection Delay")
    axis.set_ylabel("sec")
    axis.grid(axis="y", alpha=0.25)
    for index, is_missed in enumerate(missed):
        text = "missed" if is_missed else f"{values[index]:.2f}s"
        axis.text(index, values[index] + 0.1, text, ha="center")


def plot_confusion_matrix(axis: plt.Axes, metrics: dict[str, dict[str, Any]], scenario: str) -> None:
    """Plot one scenario confusion matrix."""
    if scenario not in metrics:
        axis.text(0.5, 0.5, f"{scenario}\nmissing", ha="center", va="center")
        axis.set_axis_off()
        return
    cm = metrics[scenario]["confusion_matrix"]
    matrix = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]], dtype=int)
    axis.imshow(matrix, cmap="Blues")
    axis.set_xticks([0, 1], ["pred benign", "pred attack"])
    axis.set_yticks([0, 1], ["true benign", "true attack"])
    axis.set_title(f"{scenario} Confusion")
    for row in range(2):
        for column in range(2):
            axis.text(column, row, str(matrix[row, column]), ha="center", va="center", fontsize=14)


def plot_feature_mean_heatmap(axis: plt.Axes, features: dict[str, pd.DataFrame]) -> None:
    """Plot attack/benign feature mean relative differences for each scenario."""
    rows = []
    labels = []
    for scenario in SCENARIOS:
        frame = features.get(scenario)
        if frame is None or "label" not in frame.columns:
            continue
        labels.append(scenario)
        row = []
        for feature in PAPER_FEATURES:
            attack_mean = float(frame.loc[frame["label"] == "attack", feature].mean())
            benign_mean = float(frame.loc[frame["label"] == "benign", feature].mean())
            denominator = max(abs(attack_mean), 1e-12)
            row.append(abs(benign_mean - attack_mean) / denominator)
        rows.append(row)
    if not rows:
        axis.text(0.5, 0.5, "features.csv missing", ha="center", va="center")
        axis.set_axis_off()
        return
    matrix = np.asarray(rows, dtype=float)
    image = axis.imshow(matrix, cmap="YlOrRd", aspect="auto")
    axis.set_xticks(np.arange(len(PAPER_FEATURES)))
    axis.set_xticklabels(["IAT var", "burst", "payload var", "flow rate"], rotation=25, ha="right")
    axis.set_yticks(np.arange(len(labels)))
    axis.set_yticklabels(labels)
    axis.set_title("Feature Relative Difference")
    for row in range(matrix.shape[0]):
        for column in range(matrix.shape[1]):
            axis.text(column, row, f"{matrix[row, column]:.2g}", ha="center", va="center", fontsize=9)
    plt.colorbar(image, ax=axis, fraction=0.046, pad=0.04)


def plot_suspicious_score_timeline(axis: plt.Axes, predictions: dict[str, pd.DataFrame]) -> None:
    """Plot suspicious score and predictions over time."""
    colors = {"original_like": "#4c78a8", "stat_matched": "#f58518"}
    any_data = False
    for scenario, frame in predictions.items():
        if {"window_start_sec", "suspicious_score"}.issubset(frame.columns):
            any_data = True
            axis.plot(
                frame["window_start_sec"],
                frame["suspicious_score"],
                label=f"{scenario} score",
                color=colors.get(scenario),
                linewidth=1.8,
            )
            detected = frame[frame.get("pred_attack", False).astype(bool)] if "pred_attack" in frame else pd.DataFrame()
            if not detected.empty:
                axis.scatter(
                    detected["window_start_sec"],
                    detected["suspicious_score"],
                    color=colors.get(scenario),
                    s=24,
                    marker="x",
                )
    if not any_data:
        axis.text(0.5, 0.5, "predictions.csv missing", ha="center", va="center")
        axis.set_axis_off()
        return
    axis.axhline(2, color="black", linestyle="--", linewidth=1, label="threshold=2")
    axis.set_title("Suspicious Score Timeline")
    axis.set_xlabel("window_start_sec")
    axis.set_ylabel("score")
    axis.set_ylim(-0.2, 4.2)
    axis.grid(alpha=0.25)
    axis.legend(loc="upper right")


def plot_conclusion_box(axis: plt.Axes, metrics: dict[str, dict[str, Any]]) -> None:
    """Render a compact text conclusion."""
    axis.set_axis_off()
    lines = ["Conclusion"]
    if "original_like" in metrics:
        original = metrics["original_like"]
        lines.extend(
            [
                "",
                "original_like",
                f"F1  : {float(original.get('f1_score', 0.0) or 0.0):.3f}",
                f"FPR : {float(original.get('false_positive_rate', 0.0) or 0.0):.3f}",
                f"FNR : {float(original.get('false_negative_rate', 0.0) or 0.0):.3f}",
            ]
        )
    if "stat_matched" in metrics:
        stat = metrics["stat_matched"]
        lines.extend(
            [
                "",
                "stat_matched",
                f"F1  : {float(stat.get('f1_score', 0.0) or 0.0):.3f}",
                f"FPR : {float(stat.get('false_positive_rate', 0.0) or 0.0):.3f}",
                f"FNR : {float(stat.get('false_negative_rate', 0.0) or 0.0):.3f}",
            ]
        )
    if "original_like" in metrics and "stat_matched" in metrics:
        f1_delta = float(metrics["stat_matched"].get("f1_score", 0.0) or 0.0) - float(
            metrics["original_like"].get("f1_score", 0.0) or 0.0
        )
        fnr_delta = float(metrics["stat_matched"].get("false_negative_rate", 0.0) or 0.0) - float(
            metrics["original_like"].get("false_negative_rate", 0.0) or 0.0
        )
        verdict = "degraded" if f1_delta < 0 or fnr_delta > 0 else "not degraded"
        lines.extend(["", f"Result: {verdict}", f"F1 delta : {f1_delta:.3f}", f"FNR delta: {fnr_delta:.3f}"])
    axis.text(
        0.02,
        0.98,
        "\n".join(lines),
        va="top",
        ha="left",
        fontsize=12,
        family="monospace",
        bbox={"boxstyle": "round,pad=0.5", "facecolor": "#f7f7f7", "edgecolor": "#c9c9c9"},
    )


if __name__ == "__main__":
    main()
