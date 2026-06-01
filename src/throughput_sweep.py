"""Parameter sweep helpers for Mininet LDoS throughput impact experiments."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from src.utils import ensure_dir, markdown_table


def scenario_summary_row(
    scenario: str,
    burst_pkts_per_bucket: int,
    payload_size: int,
    throughput_metrics: pd.DataFrame,
    detector_metrics: pd.DataFrame,
    missed_harmful: pd.DataFrame,
    selected_best: bool = False,
) -> dict[str, Any]:
    """Flatten one scenario's throughput and detector metrics into a row."""
    throughput = select_row(throughput_metrics, scenario)
    detector = select_row(detector_metrics, scenario)
    missed = select_row(missed_harmful, scenario)
    row: dict[str, Any] = {
        "scenario": scenario,
        "burst_pkts_per_bucket": int(burst_pkts_per_bucket),
        "payload_size": int(payload_size),
        "selected_best_for_stat_matched": bool(selected_best),
    }
    if throughput:
        row.update(
            {
                "attack_start_sec": throughput.get("attack_start_sec", np.nan),
                "pre_attack_tcp_avg_mbps": throughput.get("pre_attack_tcp_avg_throughput_mbps", np.nan),
                "attack_tcp_avg_mbps": throughput.get("attack_tcp_avg_throughput_mbps", np.nan),
                "baseline_attack_tcp_avg_mbps": throughput.get("baseline_attack_tcp_avg_throughput_mbps", np.nan),
                "normalized_throughput": throughput.get("normalized_throughput", np.nan),
                "throughput_degradation": throughput.get("throughput_degradation", np.nan),
            }
        )
    if detector:
        row.update(
            {
                "accuracy": detector.get("accuracy", np.nan),
                "precision": detector.get("precision", np.nan),
                "recall": detector.get("recall", np.nan),
                "f1": detector.get("f1", np.nan),
                "fpr": detector.get("fpr", np.nan),
                "fnr": detector.get("fnr", np.nan),
                "detection_delay_from_attack_start_sec": detector.get(
                    "detection_delay_from_attack_start_sec",
                    np.nan,
                ),
                "attack_window_count": detector.get("attack_window_count", np.nan),
                "detected_attack_window_count": detector.get("detected_attack_window_count", np.nan),
                "missed_attack_window_count": detector.get("missed_attack_window_count", np.nan),
            }
        )
    if missed:
        row.update(
            {
                "missed_attack_rate": missed.get("missed_attack_rate", np.nan),
                "missed_attack_tcp_avg_mbps": missed.get("missed_attack_tcp_avg_mbps", np.nan),
                "detected_attack_tcp_avg_mbps": missed.get("detected_attack_tcp_avg_mbps", np.nan),
                "benign_tcp_avg_mbps": missed.get("benign_tcp_avg_mbps", np.nan),
            }
        )
    return row


def write_sweep_outputs(summary: pd.DataFrame, output_dir: Path) -> None:
    """Write sweep CSV, heatmap, and Markdown summary."""
    ensure_dir(output_dir)
    summary.to_csv(output_dir / "parameter_sweep_summary.csv", index=False)
    plot_degradation_heatmap(summary, output_dir / "degradation_heatmap.png")
    (output_dir / "parameter_sweep_summary.md").write_text(build_sweep_markdown(summary), encoding="utf-8")


def plot_degradation_heatmap(summary: pd.DataFrame, output_path: Path) -> None:
    """Plot original_like degradation by burst and payload."""
    original = summary[summary["scenario"] == "original_like_ldos"].copy()
    fig, axis = plt.subplots(figsize=(8.5, 5.8), constrained_layout=True)
    if original.empty:
        axis.text(0.5, 0.5, "No original_like_ldos rows", ha="center", va="center")
        axis.set_axis_off()
    else:
        pivot = original.pivot_table(
            index="burst_pkts_per_bucket",
            columns="payload_size",
            values="throughput_degradation",
            aggfunc="mean",
        ).sort_index(ascending=True)
        image = axis.imshow(pivot.to_numpy(dtype=float), aspect="auto", origin="lower", cmap="viridis")
        axis.set_xticks(np.arange(len(pivot.columns)))
        axis.set_xticklabels([str(value) for value in pivot.columns])
        axis.set_yticks(np.arange(len(pivot.index)))
        axis.set_yticklabels([str(value) for value in pivot.index])
        axis.set_xlabel("payload size (bytes)")
        axis.set_ylabel("burst packets per bucket")
        axis.set_title("original_like_ldos TCP Throughput Degradation")
        for row_index, burst in enumerate(pivot.index):
            for col_index, payload in enumerate(pivot.columns):
                value = pivot.loc[burst, payload]
                if pd.notna(value):
                    axis.text(col_index, row_index, f"{value:.2f}", ha="center", va="center", color="white")
        fig.colorbar(image, ax=axis, label="degradation = 1 - normalized throughput")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def build_sweep_markdown(summary: pd.DataFrame) -> str:
    """Build a compact Markdown summary for the parameter sweep."""
    original = summary[summary["scenario"] == "original_like_ldos"].copy()
    stat = summary[summary["scenario"] == "stat_matched_ldos"].copy()
    if original.empty:
        best_text = "original_like_ldosのsweep結果がないため、最大degradation条件は判断できない。"
    else:
        best = original.sort_values("throughput_degradation", ascending=False).iloc[0]
        best_text = (
            f"最大degradation条件は burst_pkts_per_bucket={int(best['burst_pkts_per_bucket'])}, "
            f"payload_size={int(best['payload_size'])}, "
            f"degradation={best['throughput_degradation']:.3f} だった。"
        )
    rows = []
    for frame in [original.head(20), stat]:
        for row in frame.itertuples(index=False):
            rows.append(
                [
                    row.scenario,
                    str(row.burst_pkts_per_bucket),
                    str(row.payload_size),
                    f"{row.attack_tcp_avg_mbps:.3f}",
                    f"{row.normalized_throughput:.3f}",
                    f"{row.throughput_degradation:.3f}",
                    f"{row.fnr:.3f}" if pd.notna(row.fnr) else "nan",
                    f"{row.f1:.3f}" if pd.notna(row.f1) else "nan",
                ]
            )
    lines = [
        "# LDoS parameter sweep summary",
        "",
        "## 目的",
        "",
        "original_like_ldosでTCP throughput degradationが大きくなるburst/payload条件を探索し、"
        "その条件をstat_matched_ldosにも適用してFNRとthroughput degradationを確認する。",
        "",
        "## 注意",
        "",
        "- detectorロジックは変更していない。",
        "- Goertzel、Sliding DFT、周期性特徴量は使っていない。",
        "- Mininet上のパケット列とoffline Python detectorによる追加評価である。",
        "",
        "## 最大degradation条件",
        "",
        best_text,
        "",
        "## 主要結果",
        "",
        markdown_table(
            ["scenario", "burst", "payload", "attack Mbps", "normalized", "degradation", "FNR", "F1"],
            rows,
        ),
    ]
    return "\n".join(lines) + "\n"


def select_row(frame: pd.DataFrame, scenario: str) -> dict[str, Any]:
    """Return the first row for a scenario as a dict, or an empty dict."""
    if frame.empty or "scenario" not in frame.columns:
        return {}
    row = frame[frame["scenario"] == scenario]
    return row.iloc[0].to_dict() if not row.empty else {}
