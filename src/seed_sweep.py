"""Phase 1.5 seed sweep for stat-matched bucket simulations."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .detector_dataset import SimulationConfig, generate_feature_pair
from .evaluate_similarity import build_similarity_table
from .utils import EPSILON, ensure_dir, markdown_table


STAT_SWEEP_FEATURES = [
    "iat_variance",
    "burst_rate",
    "payload_size_variance",
    "new_flow_arrival_rate",
    "mean_packet_rate",
    "max_bucket_count",
    "bucket_count_variance",
    "burst_count",
]


def run_seed_sweep(
    config: SimulationConfig,
    seeds: list[int],
    output_dir: str | Path,
) -> pd.DataFrame:
    """Run the Phase 1.5 seed sweep and write CSV, PNG, and Markdown outputs."""
    if not seeds:
        raise ValueError("seeds must not be empty")

    output_path = ensure_dir(output_dir)
    rows: list[dict[str, float | int]] = []
    for seed in seeds:
        periodic_features, random_features = generate_feature_pair(config, seed)
        similarity = build_similarity_table(periodic_features, random_features)
        row: dict[str, float | int] = {"seed": seed}

        for feature in STAT_SWEEP_FEATURES:
            row[f"{feature}_relative_difference"] = _lookup_similarity(similarity, feature, "relative_difference")

        periodic_1hz = float(periodic_features["normalized_1hz_power"].mean())
        random_1hz = float(random_features["normalized_1hz_power"].mean())
        periodic_rto = float(periodic_features["normalized_rto_band_power"].mean())
        random_rto = float(random_features["normalized_rto_band_power"].mean())

        row["normalized_1hz_power_periodic"] = periodic_1hz
        row["normalized_1hz_power_random"] = random_1hz
        row["normalized_1hz_power_ratio"] = _safe_ratio(periodic_1hz, random_1hz)
        row["normalized_rto_band_power_periodic"] = periodic_rto
        row["normalized_rto_band_power_random"] = random_rto
        row["normalized_rto_band_power_ratio"] = _safe_ratio(periodic_rto, random_rto)
        rows.append(row)

    results = pd.DataFrame(rows)
    results.to_csv(output_path / "seed_sweep_results.csv", index=False)
    _plot_power_comparison(
        results,
        "normalized_1hz_power_periodic",
        "normalized_1hz_power_random",
        "Normalized 1Hz power by seed",
        output_path / "seed_sweep_1hz_power.png",
    )
    _plot_power_comparison(
        results,
        "normalized_rto_band_power_periodic",
        "normalized_rto_band_power_random",
        "Normalized RTO-band power by seed",
        output_path / "seed_sweep_rto_band_power.png",
    )
    _plot_stat_feature_distance(results, output_path / "seed_sweep_stat_feature_distance.png")
    summary = build_seed_sweep_summary(results, seeds)
    (output_path / "seed_sweep_summary.md").write_text(summary, encoding="utf-8")
    return results


def build_seed_sweep_summary(results: pd.DataFrame, seeds: list[int]) -> str:
    """Build a Markdown summary for Phase 1.5."""
    stat_columns = [f"{feature}_relative_difference" for feature in STAT_SWEEP_FEATURES]
    frequency_columns = [
        "normalized_1hz_power_periodic",
        "normalized_1hz_power_random",
        "normalized_1hz_power_ratio",
        "normalized_rto_band_power_periodic",
        "normalized_rto_band_power_random",
        "normalized_rto_band_power_ratio",
    ]
    rows = _summary_stat_rows(results, stat_columns + frequency_columns)

    one_hz_better = int(
        (results["normalized_1hz_power_periodic"] > results["normalized_1hz_power_random"]).sum()
    )
    rto_better = int(
        (results["normalized_rto_band_power_periodic"] > results["normalized_rto_band_power_random"]).sum()
    )
    total = len(results)
    one_hz_ratio_mean = float(results["normalized_1hz_power_ratio"].replace([np.inf, -np.inf], np.nan).mean())
    rto_ratio_mean = float(
        results["normalized_rto_band_power_ratio"].replace([np.inf, -np.inf], np.nan).mean()
    )
    max_iat_gap = float(results["iat_variance_relative_difference"].max())
    max_primary_gap = float(
        results[
            [
                "burst_rate_relative_difference",
                "payload_size_variance_relative_difference",
                "new_flow_arrival_rate_relative_difference",
            ]
        ].to_numpy(dtype=float).max()
    )

    if one_hz_better == total and rto_better == total and max_iat_gap < 0.5:
        phase2_comment = "Phase 2に進む価値がある。複数seedで統計特徴の類似性と周期性特徴の差が同時に確認できている。"
    else:
        phase2_comment = "Phase 2に進む前に、random_microburst生成条件やwindow幅を追加確認する価値がある。"

    lines = [
        "# Phase 1.5 seed sweep summary",
        "",
        "## 実行seed",
        "",
        ", ".join(str(seed) for seed in seeds),
        "",
        "## Feature statistics",
        "",
        markdown_table(["feature", "mean", "std", "min", "max"], rows),
        "",
        "## 周波数特徴の優位性",
        "",
        f"- normalized_1hz_power ratio mean: {one_hz_ratio_mean:.6g}",
        f"- normalized_rto_band_power ratio mean: {rto_ratio_mean:.6g}",
        f"- normalized_1hz_powerでperiodic_ldos > random_microburstだったseed数: {one_hz_better}/{total}",
        f"- normalized_rto_band_powerでperiodic_ldos > random_microburstだったseed数: {rto_better}/{total}",
        "",
        "## 既存4特徴量の安定性",
        "",
        f"- iat_variance relative differenceの最大値: {max_iat_gap:.6g}",
        f"- burst_rate / payload_size_variance / new_flow_arrival_rate relative differenceの最大値: {max_primary_gap:.6g}",
        "- burst_rate、payload_size_variance、new_flow_arrival_rateは、bucket分布、payload、flow modeを合わせているため安定して類似しやすい。",
        "- iat_varianceはburst位置のランダム化で多少変動するが、極端な乖離がないかをseed sweepで確認する。",
        "",
        "## 考察",
        "",
        phase2_comment,
        "",
        "この実験は元論文の完全再現ではなく、元論文型の窓内統計特徴量が類似する限界条件を人工bucket列で作るPhase 1.5検証である。",
        "",
    ]
    return "\n".join(lines)


def _lookup_similarity(similarity: pd.DataFrame, feature: str, column: str) -> float:
    """Return one value from the feature similarity table."""
    rows = similarity[similarity["feature"] == feature]
    if rows.empty:
        raise KeyError(f"feature not found in similarity table: {feature}")
    return float(rows.iloc[0][column])


def _safe_ratio(numerator: float, denominator: float) -> float:
    """Return a ratio while avoiding division by zero."""
    if abs(denominator) < EPSILON:
        return float("nan")
    return numerator / denominator


def _summary_stat_rows(results: pd.DataFrame, columns: list[str]) -> list[list[str]]:
    """Build mean/std/min/max rows for selected result columns."""
    rows: list[list[str]] = []
    for column in columns:
        series = results[column].replace([np.inf, -np.inf], np.nan).dropna()
        if series.empty:
            rows.append([column, "nan", "nan", "nan", "nan"])
            continue
        rows.append(
            [
                column,
                f"{float(series.mean()):.6g}",
                f"{float(series.std(ddof=0)):.6g}",
                f"{float(series.min()):.6g}",
                f"{float(series.max()):.6g}",
            ]
        )
    return rows


def _plot_power_comparison(
    results: pd.DataFrame,
    periodic_column: str,
    random_column: str,
    title: str,
    output_path: str | Path,
) -> None:
    """Save a per-seed grouped bar chart for a frequency feature."""
    x = np.arange(len(results))
    width = 0.38
    fig, axis = plt.subplots(figsize=(11, 4.5), constrained_layout=True)
    axis.bar(x - width / 2, results[periodic_column], width, label="periodic_ldos", color="#1f77b4")
    axis.bar(x + width / 2, results[random_column], width, label="random_microburst", color="#ff7f0e")
    axis.set_xticks(x)
    axis.set_xticklabels(results["seed"].astype(str).tolist())
    axis.set_xlabel("seed")
    axis.set_ylabel("normalized power")
    axis.set_title(title)
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def _plot_stat_feature_distance(results: pd.DataFrame, output_path: str | Path) -> None:
    """Save relative differences for statistical features across seeds."""
    fig, axis = plt.subplots(figsize=(12, 5.5), constrained_layout=True)
    for feature in STAT_SWEEP_FEATURES:
        column = f"{feature}_relative_difference"
        axis.plot(results["seed"], results[column], marker="o", linewidth=1.5, label=feature)
    axis.set_xlabel("seed")
    axis.set_ylabel("relative difference")
    axis.set_title("Stat feature relative differences by seed")
    axis.grid(True, alpha=0.25)
    axis.legend(fontsize=8, ncol=2)
    fig.savefig(output_path, dpi=160)
    plt.close(fig)
