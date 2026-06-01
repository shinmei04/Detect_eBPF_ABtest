"""Throughput-impact analysis for Mininet LDoS scenarios.

The functions in this module aggregate TCP iperf throughput, offline detector
predictions, and per-window feature details. They intentionally do not add
Goertzel, Sliding DFT, or any other frequency feature.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from src.paper_reproduction_detector import PAPER_FEATURES, XDP_FEATURE_CONFIGS
from src.utils import ensure_dir, markdown_table


THROUGHPUT_SCENARIOS = [
    "no_attack",
    "random_microburst_only",
    "original_like_ldos",
    "stat_matched_ldos",
]
FEATURE_CONFIGS = {config.name: config for config in XDP_FEATURE_CONFIGS}


def parse_iperf_json(json_path: Path, scenario: str) -> pd.DataFrame:
    """Parse an iperf3 JSON output file into a throughput time series."""
    if not json_path.exists():
        raise FileNotFoundError(json_path)
    data = json.loads(json_path.read_text(encoding="utf-8"))
    rows = []
    for index, interval in enumerate(data.get("intervals", [])):
        interval_sum = interval.get("sum", {})
        start = float(interval_sum.get("start", index))
        end = float(interval_sum.get("end", index + 1))
        bps = float(interval_sum.get("bits_per_second", 0.0))
        rows.append(
            {
                "scenario": scenario,
                "interval_index": index,
                "start_sec": start,
                "end_sec": end,
                "tcp_throughput_bps": bps,
                "tcp_throughput_mbps": bps / 1_000_000.0,
            }
        )
    return pd.DataFrame(rows)


def enrich_window_predictions(
    scenario: str,
    predictions: pd.DataFrame,
    throughput: pd.DataFrame,
) -> pd.DataFrame:
    """Add throughput, abnormal-direction margins, and EMA update flags."""
    frame = predictions.copy()
    if "scenario" not in frame.columns:
        frame["scenario"] = scenario
    if "window_index" not in frame.columns:
        frame["window_index"] = np.arange(len(frame), dtype=int)
    frame["true_label"] = true_labels(frame)
    if "pred_label" not in frame.columns:
        frame["pred_label"] = np.where(frame.get("pred_attack", False).astype(bool), "attack", "benign")

    for feature in PAPER_FEATURES:
        config = FEATURE_CONFIGS[feature]
        threshold_col = f"{feature}_threshold"
        abnormal_source = f"{feature}_is_suspicious"
        abnormal_col = f"{feature}_abnormal"
        margin_col = f"{feature}_margin"
        if threshold_col not in frame.columns:
            frame[threshold_col] = np.nan
        if abnormal_source in frame.columns:
            frame[abnormal_col] = frame[abnormal_source].astype(bool)
        else:
            if config.is_upper_threshold:
                frame[abnormal_col] = frame[feature] > frame[threshold_col]
            else:
                frame[abnormal_col] = frame[feature] < frame[threshold_col]
        if config.is_upper_threshold:
            frame[margin_col] = frame[feature].astype(float) - frame[threshold_col].astype(float)
        else:
            frame[margin_col] = frame[threshold_col].astype(float) - frame[feature].astype(float)

        if f"{feature}_ema" not in frame.columns and f"{feature}_mu" in frame.columns:
            frame[f"{feature}_ema"] = frame[f"{feature}_mu"]
        enough = frame.get("enough_packets_for_detection", True)
        if not isinstance(enough, pd.Series):
            enough = pd.Series([bool(enough)] * len(frame), index=frame.index)
        if "detection_enabled" in frame.columns:
            detection_enabled = frame["detection_enabled"]
        elif "is_warmup" in frame.columns:
            detection_enabled = ~frame["is_warmup"].astype(bool)
        else:
            detection_enabled = pd.Series([True] * len(frame), index=frame.index)
        if not isinstance(detection_enabled, pd.Series):
            detection_enabled = pd.Series([bool(detection_enabled)] * len(frame), index=frame.index)
        frame[f"{feature}_ema_updated"] = enough.astype(bool) & (
            ~frame[abnormal_col].astype(bool) | ~detection_enabled.astype(bool)
        )
        frame[f"{feature}_ema_skipped"] = enough.astype(bool) & frame[abnormal_col].astype(bool) & detection_enabled.astype(bool)

    update_cols = [f"{feature}_ema_updated" for feature in PAPER_FEATURES]
    skip_cols = [f"{feature}_ema_skipped" for feature in PAPER_FEATURES]
    frame["ema_updated_any"] = frame[update_cols].any(axis=1)
    frame["ema_skipped_any"] = frame[skip_cols].any(axis=1)
    frame["tcp_throughput_bps"] = [
        throughput_for_window(throughput, float(row.window_start_sec), float(row.window_end_sec))
        for row in frame.itertuples(index=False)
    ]
    frame["tcp_throughput_mbps"] = frame["tcp_throughput_bps"] / 1_000_000.0
    return frame


def build_no_attack_windows(
    scenario: str,
    throughput: pd.DataFrame,
    window_sec: float,
    step_sec: float,
    duration_sec: float,
) -> pd.DataFrame:
    """Create benign placeholder windows for TCP-only no-UDP scenarios."""
    starts = np.arange(0.0, max(duration_sec - window_sec + 1e-9, 0.0) + 1e-9, step_sec)
    rows = []
    for index, start in enumerate(starts):
        end = start + window_sec
        row: dict[str, Any] = {
            "scenario": scenario,
            "window_index": index,
            "window_start_sec": start,
            "window_end_sec": end,
            "label": "benign",
            "true_label": "benign",
            "pred_label": "benign",
            "pred_attack": False,
            "true_attack": False,
            "suspicious_score": 0,
            "total_packets": 0,
            "detection_enabled": True,
            "enough_packets_for_detection": False,
            "is_warmup": False,
            "tcp_throughput_bps": throughput_for_window(throughput, start, end),
        }
        row["tcp_throughput_mbps"] = row["tcp_throughput_bps"] / 1_000_000.0
        for feature in PAPER_FEATURES:
            row[feature] = 0.0
            row[f"{feature}_ema"] = np.nan
            row[f"{feature}_mu"] = np.nan
            row[f"{feature}_sigma"] = np.nan
            row[f"{feature}_threshold"] = np.nan
            row[f"{feature}_margin"] = np.nan
            row[f"{feature}_abnormal"] = False
            row[f"{feature}_ema_updated"] = False
            row[f"{feature}_ema_skipped"] = False
        row["ema_updated_any"] = False
        row["ema_skipped_any"] = False
        rows.append(row)
    return pd.DataFrame(rows)


def true_labels(frame: pd.DataFrame) -> pd.Series:
    """Return canonical labels from prediction columns."""
    if "true_label" in frame.columns:
        return frame["true_label"].astype(str)
    if "label" in frame.columns:
        return frame["label"].astype(str)
    if "true_attack" in frame.columns:
        return np.where(frame["true_attack"].astype(bool), "attack", "benign")
    raise ValueError("predictions must contain label, true_label, or true_attack")


def throughput_for_window(throughput: pd.DataFrame, start_sec: float, end_sec: float) -> float:
    """Compute a weighted average TCP throughput over a window."""
    if throughput.empty or end_sec <= start_sec:
        return 0.0
    total_weight = 0.0
    weighted = 0.0
    for row in throughput.itertuples(index=False):
        overlap = max(0.0, min(end_sec, float(row.end_sec)) - max(start_sec, float(row.start_sec)))
        if overlap > 0:
            weighted += overlap * float(row.tcp_throughput_bps)
            total_weight += overlap
    return weighted / total_weight if total_weight > 0 else 0.0


def build_throughput_metrics(timeseries: pd.DataFrame, evaluation_start_sec: float = 0.0) -> pd.DataFrame:
    """Compute throughput metrics normalized to the no_attack baseline."""
    rows = []
    for scenario in THROUGHPUT_SCENARIOS:
        values = timeseries[
            (timeseries["scenario"] == scenario) & (timeseries["end_sec"] > evaluation_start_sec)
        ]["tcp_throughput_bps"]
        rows.append(
            {
                "scenario": scenario,
                "tcp_avg_throughput_bps": float(values.mean()) if len(values) else 0.0,
                "tcp_avg_throughput_mbps": float(values.mean() / 1_000_000.0) if len(values) else 0.0,
                "sample_count": int(len(values)),
            }
        )
    metrics = pd.DataFrame(rows)
    baseline = metrics.loc[metrics["scenario"] == "no_attack", "tcp_avg_throughput_bps"]
    baseline_value = float(baseline.iloc[0]) if not baseline.empty and float(baseline.iloc[0]) > 0 else 0.0
    metrics["normalized_throughput"] = metrics["tcp_avg_throughput_bps"].apply(
        lambda value: safe_divide(float(value), baseline_value)
    )
    metrics["throughput_degradation"] = 1.0 - metrics["normalized_throughput"]
    return metrics


def build_detector_metrics(window_log: pd.DataFrame) -> pd.DataFrame:
    """Compute detector metrics per scenario where labels are available."""
    rows = []
    for scenario in THROUGHPUT_SCENARIOS:
        frame = window_log[window_log["scenario"] == scenario].copy()
        if frame.empty:
            continue
        if "is_warmup" in frame.columns:
            evaluated = frame[~frame["is_warmup"].fillna(False).astype(bool)].copy()
        else:
            evaluated = frame
        y_true = evaluated["true_label"].astype(str).eq("attack")
        y_pred = evaluated["pred_label"].astype(str).eq("attack")
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[False, True]).ravel()
        attack_windows = evaluated[y_true]
        detected_attack_windows = evaluated[y_true & y_pred]
        missed_attack_windows = evaluated[y_true & ~y_pred]
        first = detected_attack_windows.sort_values("window_start_sec").head(1)
        delay = None
        first_window_index = None
        if not first.empty:
            delay = float(first.iloc[0]["window_end_sec"])
            first_window_index = int(first.iloc[0]["window_index"])
        rows.append(
            {
                "scenario": scenario,
                "accuracy": float(accuracy_score(y_true, y_pred)) if len(evaluated) else 0.0,
                "precision": float(precision_score(y_true, y_pred, zero_division=0)) if len(evaluated) else 0.0,
                "recall": float(recall_score(y_true, y_pred, zero_division=0)) if len(evaluated) else 0.0,
                "f1": float(f1_score(y_true, y_pred, zero_division=0)) if len(evaluated) else 0.0,
                "fpr": safe_divide(fp, fp + tn),
                "fnr": safe_divide(fn, fn + tp),
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
                "detection_delay_sec": delay,
                "first_detected_window_index": first_window_index,
                "attack_window_count": int(len(attack_windows)),
                "detected_attack_window_count": int(len(detected_attack_windows)),
                "missed_attack_window_count": int(len(missed_attack_windows)),
                "evaluated_windows": int(len(evaluated)),
            }
        )
    return pd.DataFrame(rows)


def build_confusion_matrices(detector_metrics: pd.DataFrame) -> pd.DataFrame:
    """Return confusion matrix counts in a dedicated CSV-friendly table."""
    columns = ["scenario", "tn", "fp", "fn", "tp"]
    return detector_metrics[columns].copy() if not detector_metrics.empty else pd.DataFrame(columns=columns)


def build_missed_harmful_windows(window_log: pd.DataFrame) -> pd.DataFrame:
    """Summarize evaluated missed attack windows and their TCP throughput."""
    rows = []
    for scenario in ["original_like_ldos", "stat_matched_ldos"]:
        frame = window_log[window_log["scenario"] == scenario]
        if "is_warmup" in frame.columns:
            frame = frame[~frame["is_warmup"].fillna(False).astype(bool)]
        attack = frame[frame["true_label"].astype(str).eq("attack")]
        missed = attack[~attack["pred_label"].astype(str).eq("attack")]
        detected = attack[attack["pred_label"].astype(str).eq("attack")]
        benign = frame[frame["true_label"].astype(str).eq("benign")]
        rows.append(
            {
                "scenario": scenario,
                "attack_window_count": int(len(attack)),
                "missed_attack_window_count": int(len(missed)),
                "missed_attack_rate": safe_divide(len(missed), len(attack)),
                "missed_attack_tcp_avg_mbps": mean_mbps(missed),
                "detected_attack_tcp_avg_mbps": mean_mbps(detected),
                "benign_tcp_avg_mbps": mean_mbps(benign),
            }
        )
    return pd.DataFrame(rows)


def mean_mbps(frame: pd.DataFrame) -> float:
    """Return mean Mbps for a frame, or 0 when empty."""
    return float(frame["tcp_throughput_mbps"].mean()) if len(frame) else 0.0


def write_throughput_outputs(
    output_dir: Path,
    timeseries: pd.DataFrame,
    window_log: pd.DataFrame,
    throughput_metrics: pd.DataFrame,
    detector_metrics: pd.DataFrame,
    confusion_matrices: pd.DataFrame,
    missed_harmful: pd.DataFrame,
    notes: list[str] | None = None,
) -> None:
    """Write all requested CSV, PNG, and Markdown throughput artifacts."""
    ensure_dir(output_dir)
    throughput_metrics.to_csv(output_dir / "throughput_metrics.csv", index=False)
    timeseries.to_csv(output_dir / "tcp_throughput_timeseries.csv", index=False)
    window_log.to_csv(output_dir / "window_detailed_log.csv", index=False)
    detector_metrics.to_csv(output_dir / "detector_metrics.csv", index=False)
    confusion_matrices.to_csv(output_dir / "confusion_matrices.csv", index=False)
    missed_harmful.to_csv(output_dir / "missed_harmful_windows.csv", index=False)

    plot_throughput_comparison(throughput_metrics, output_dir / "throughput_comparison.png")
    plot_normalized_throughput(throughput_metrics, output_dir / "normalized_throughput_comparison.png")
    plot_detector_vs_throughput(throughput_metrics, detector_metrics, output_dir / "detector_vs_throughput_summary.png")
    plot_tcp_timeseries(timeseries, output_dir / "tcp_throughput_timeseries_by_scenario.png")
    plot_degradation(throughput_metrics, output_dir / "throughput_degradation_comparison.png")
    plot_stat_matched_detection_timeline(
        window_log,
        output_dir / "stat_matched_detection_vs_throughput_timeline.png",
    )
    (output_dir / "throughput_summary.md").write_text(
        build_summary(throughput_metrics, detector_metrics, missed_harmful, notes or []),
        encoding="utf-8",
    )


def plot_throughput_comparison(metrics: pd.DataFrame, output_path: Path) -> None:
    """Plot average TCP throughput by scenario."""
    fig, axis = plt.subplots(figsize=(9.5, 5.0), constrained_layout=True)
    axis.bar(metrics["scenario"], metrics["tcp_avg_throughput_mbps"], color=["#4c78a8", "#f58518", "#e45756", "#72b7b2"])
    axis.set_title("TCP Average Throughput by Scenario")
    axis.set_ylabel("TCP throughput (Mbps)")
    axis.tick_params(axis="x", rotation=20)
    axis.grid(axis="y", alpha=0.25)
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_normalized_throughput(metrics: pd.DataFrame, output_path: Path) -> None:
    """Plot normalized throughput relative to no_attack."""
    fig, axis = plt.subplots(figsize=(9.5, 5.0), constrained_layout=True)
    axis.axhline(1.0, color="black", linestyle="--", linewidth=1, label="no_attack baseline")
    axis.bar(metrics["scenario"], metrics["normalized_throughput"], color=["#4c78a8", "#f58518", "#e45756", "#72b7b2"])
    axis.set_title("Normalized TCP Throughput")
    axis.set_ylabel("condition / no_attack")
    axis.set_ylim(0.0, max(1.1, float(metrics["normalized_throughput"].max()) + 0.1))
    axis.tick_params(axis="x", rotation=20)
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_detector_vs_throughput(
    throughput_metrics: pd.DataFrame,
    detector_metrics: pd.DataFrame,
    output_path: Path,
) -> None:
    """Plot throughput degradation and detector FNR together."""
    merged = throughput_metrics.merge(detector_metrics[["scenario", "fnr", "recall", "f1"]], on="scenario", how="left")
    x = np.arange(len(merged))
    width = 0.36
    fig, axis = plt.subplots(figsize=(10, 5), constrained_layout=True)
    axis.bar(x - width / 2, merged["throughput_degradation"], width=width, label="throughput degradation", color="#e45756")
    axis.bar(x + width / 2, merged["fnr"].fillna(0), width=width, label="detector FNR", color="#4c78a8")
    axis.set_xticks(x)
    axis.set_xticklabels(merged["scenario"], rotation=20)
    axis.set_ylim(0.0, 1.05)
    axis.set_title("Detector Miss Rate vs TCP Degradation")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_tcp_timeseries(timeseries: pd.DataFrame, output_path: Path) -> None:
    """Plot TCP throughput time series for all scenarios."""
    fig, axis = plt.subplots(figsize=(11, 5.5), constrained_layout=True)
    for scenario in THROUGHPUT_SCENARIOS:
        frame = timeseries[timeseries["scenario"] == scenario]
        if frame.empty:
            continue
        mid = (frame["start_sec"] + frame["end_sec"]) / 2.0
        axis.plot(mid, frame["tcp_throughput_mbps"], linewidth=1.8, label=scenario)
    axis.axvline(0, color="black", linestyle="--", linewidth=1, label="evaluation start")
    axis.set_title("TCP Throughput Time Series by Scenario")
    axis.set_xlabel("time (sec)")
    axis.set_ylabel("TCP throughput (Mbps)")
    axis.grid(alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_degradation(metrics: pd.DataFrame, output_path: Path) -> None:
    """Plot throughput degradation by scenario."""
    fig, axis = plt.subplots(figsize=(9.5, 5.0), constrained_layout=True)
    axis.bar(metrics["scenario"], metrics["throughput_degradation"], color=["#4c78a8", "#f58518", "#e45756", "#72b7b2"])
    axis.set_title("TCP Throughput Degradation vs no_attack")
    axis.set_ylabel("1 - normalized throughput")
    axis.set_ylim(0.0, max(1.0, float(metrics["throughput_degradation"].max()) + 0.1))
    axis.tick_params(axis="x", rotation=20)
    axis.grid(axis="y", alpha=0.25)
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_stat_matched_detection_timeline(window_log: pd.DataFrame, output_path: Path) -> None:
    """Plot stat_matched TCP throughput and detector predictions on one timeline."""
    frame = window_log[window_log["scenario"] == "stat_matched_ldos"].copy()
    fig, axis = plt.subplots(figsize=(11, 5.5), constrained_layout=True)
    if frame.empty:
        axis.text(0.5, 0.5, "stat_matched_ldos missing", ha="center", va="center")
        axis.set_axis_off()
    else:
        x = (frame["window_start_sec"] + frame["window_end_sec"]) / 2.0
        axis.plot(x, frame["tcp_throughput_mbps"], color="#4c78a8", linewidth=1.8, label="TCP throughput")
        missed = frame[frame["true_label"].astype(str).eq("attack") & ~frame["pred_label"].astype(str).eq("attack")]
        detected = frame[frame["true_label"].astype(str).eq("attack") & frame["pred_label"].astype(str).eq("attack")]
        axis.scatter(
            (missed["window_start_sec"] + missed["window_end_sec"]) / 2.0,
            missed["tcp_throughput_mbps"],
            color="#e45756",
            marker="x",
            s=40,
            label="missed attack window",
        )
        axis.scatter(
            (detected["window_start_sec"] + detected["window_end_sec"]) / 2.0,
            detected["tcp_throughput_mbps"],
            color="#54a24b",
            marker="o",
            s=32,
            label="detected attack window",
        )
        axis.axvline(0, color="black", linestyle="--", linewidth=1, label="attack/evaluation start")
        axis.set_title("stat_matched_ldos: Detection vs TCP Throughput")
        axis.set_xlabel("time (sec)")
        axis.set_ylabel("TCP throughput (Mbps)")
        axis.grid(alpha=0.25)
        axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def build_summary(
    throughput_metrics: pd.DataFrame,
    detector_metrics: pd.DataFrame,
    missed_harmful: pd.DataFrame,
    notes: list[str],
) -> str:
    """Build Markdown summary for throughput-impact results."""
    throughput_rows = [
        [
            row.scenario,
            f"{row.tcp_avg_throughput_mbps:.3f}",
            f"{row.normalized_throughput:.3f}",
            f"{row.throughput_degradation:.3f}",
        ]
        for row in throughput_metrics.itertuples(index=False)
    ]
    detector_rows = []
    for row in detector_metrics.itertuples(index=False):
        detector_rows.append(
            [
                row.scenario,
                f"{row.recall:.3f}",
                f"{row.fnr:.3f}",
                f"{row.f1:.3f}",
                f"{row.fpr:.3f}",
            ]
        )
    stat_metric = metric_row(throughput_metrics, "stat_matched_ldos")
    stat_detector = detector_row(detector_metrics, "stat_matched_ldos")
    random_metric = metric_row(throughput_metrics, "random_microburst_only")
    stat_missed = missed_row(missed_harmful, "stat_matched_ldos")
    if stat_metric is None:
        stat_conclusion = "stat_matched_ldosのthroughput metricがないため、攻撃効果は判断できない。"
    elif stat_detector is not None and stat_detector["fnr"] > 0.5 and stat_metric["throughput_degradation"] > 0.1:
        stat_conclusion = (
            "stat_matched LDoSは検知されにくいだけでなく、TCPスループットを低下させる実害を持つ可能性がある。"
        )
    elif stat_detector is not None and stat_detector["fnr"] > 0.5:
        stat_conclusion = (
            "stat_matched LDoSは見逃されやすいが、現時点ではTCP throughput degradationが小さい。"
            "攻撃効果を維持するstat-matched traffic設計が今後の課題である。"
        )
    else:
        stat_conclusion = "stat_matched LDoSの見逃し傾向は限定的であり、検知器が比較的反応した可能性がある。"

    lines = [
        "# Throughput impact experiment summary",
        "",
        "## 1. 実験目的",
        "",
        "見逃されたstat-matched LDoSが、実際にTCPスループットを低下させる攻撃効果を持つか確認する。",
        "",
        "## 2. 実験条件",
        "",
        "- `no_attack`: h1 -> h2 のTCP通信のみ",
        "- `random_microburst_only`: TCP通信 + h4 -> h2 random microburst",
        "- `original_like_ldos`: TCP通信 + h3 -> h2 periodic LDoS",
        "- `stat_matched_ldos`: TCP通信 + h3 -> h2 stat-matched periodic LDoS",
        "",
        "## 3-5. TCP平均スループット / normalized throughput / degradation",
        "",
        markdown_table(["scenario", "avg TCP Mbps", "normalized throughput", "degradation"], throughput_rows),
        "",
        "## 6. detectorのRecall/FNR/F1",
        "",
        markdown_table(["scenario", "recall", "FNR", "F1", "FPR"], detector_rows),
        "",
        "## 7. stat_matched_ldosが見逃されたか",
        "",
    ]
    if stat_missed is not None:
        lines.extend(
            [
                f"- attack window数: {int(stat_missed['attack_window_count'])}",
                f"- missed attack window数: {int(stat_missed['missed_attack_window_count'])}",
                f"- missed attack rate: {stat_missed['missed_attack_rate']:.3f}",
                f"- missed attack window中のTCP平均: {stat_missed['missed_attack_tcp_avg_mbps']:.3f} Mbps",
                f"- detected attack window中のTCP平均: {stat_missed['detected_attack_tcp_avg_mbps']:.3f} Mbps",
            ]
        )
    else:
        lines.append("stat_matched_ldosのmissed window集計は利用できなかった。")
    lines.extend(
        [
            "",
            "## 8. stat_matched_ldosがTCPスループットを低下させたか",
            "",
            stat_conclusion,
            "",
            "## 9. random_microburst_onlyがTCPに与えた影響",
            "",
        ]
    )
    if random_metric is None:
        lines.append("random_microburst_onlyのthroughput metricがないため判断できない。")
    else:
        lines.append(
            f"random_microburst_onlyのnormalized throughputは {random_metric['normalized_throughput']:.3f}、"
            f"degradationは {random_metric['throughput_degradation']:.3f} だった。"
        )
    lines.extend(
        [
            "",
            "## 10. 現時点の結論",
            "",
            stat_conclusion,
            "",
            "## 11. 注意点",
            "",
            "- XDP/eBPF上での実装評価ではなく、Mininet上のパケット列 + offline Python detectorによる評価である。",
            "- 元論文実装の完全再現ではなく、4特徴量・EMA動的しきい値・suspicious score判定ロジックの再現である。",
            "- 今回はGoertzel、Sliding DFT、周期性特徴量などの改善手法を入れていない。",
        ]
    )
    if notes:
        lines.extend(["", "## 実行メモ", ""])
        lines.extend(f"- {note}" for note in notes)
    return "\n".join(lines) + "\n"


def metric_row(metrics: pd.DataFrame, scenario: str) -> dict[str, Any] | None:
    """Return a throughput metric row as dict."""
    row = metrics[metrics["scenario"] == scenario]
    return row.iloc[0].to_dict() if not row.empty else None


def detector_row(metrics: pd.DataFrame, scenario: str) -> dict[str, Any] | None:
    """Return a detector metric row as dict."""
    row = metrics[metrics["scenario"] == scenario]
    return row.iloc[0].to_dict() if not row.empty else None


def missed_row(metrics: pd.DataFrame, scenario: str) -> dict[str, Any] | None:
    """Return a missed-harmful row as dict."""
    row = metrics[metrics["scenario"] == scenario]
    return row.iloc[0].to_dict() if not row.empty else None


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide with zero handling."""
    return 0.0 if denominator == 0 else float(numerator / denominator)
