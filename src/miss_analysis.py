"""Miss-analysis utilities for Mininet stat-matched detector results.

This module analyzes why the paper-style four-feature detector misses periodic
LDoS windows under the stat-matched Mininet condition. It does not add
frequency features and it does not change detector behavior.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from src.paper_reproduction_detector import (
    PAPER_FEATURES,
    PaperDetectorConfig,
    run_paper_detector_by_seed,
)
from src.utils import ensure_dir, markdown_table


ANALYSIS_GROUPS = ["benign", "detected_attack", "missed_attack"]
SCORE_THRESHOLD = 2
SUMMARY_FEATURES = [*PAPER_FEATURES, "suspicious_score"]


@dataclass(frozen=True)
class MissAnalysisConfig:
    """Runtime configuration for miss analysis."""

    stat_matched_dir: Path
    original_like_dir: Path | None
    output_dir: Path
    warmup_windows: int = 20
    suspicious_threshold: int = 2
    min_packets_for_detection: int = 10


def run_miss_analysis(config: MissAnalysisConfig) -> dict[str, Path]:
    """Run all miss-analysis steps and write CSV/PNG/Markdown outputs."""
    output_dir = ensure_dir(config.output_dir)
    stat = load_condition(
        config.stat_matched_dir,
        scenario="stat_matched",
        config=config,
        output_dir=output_dir,
    )
    original = None
    if config.original_like_dir is not None and config.original_like_dir.exists():
        original = load_condition(
            config.original_like_dir,
            scenario="original_like",
            config=config,
            output_dir=output_dir,
        )

    paths: dict[str, Path] = {}
    paths["window_group_counts"] = output_dir / "window_group_counts.csv"
    window_group_counts(stat).to_csv(paths["window_group_counts"], index=False)

    paths["score_distribution_csv"] = output_dir / "suspicious_score_distribution_stat_matched.csv"
    score_distribution = suspicious_score_distribution(stat)
    score_distribution.to_csv(paths["score_distribution_csv"], index=False)
    paths["score_distribution_png"] = output_dir / "suspicious_score_distribution_stat_matched.png"
    plot_suspicious_score_distribution(score_distribution, paths["score_distribution_png"])

    paths["abnormal_rate_csv"] = output_dir / "abnormal_feature_rate_stat_matched.csv"
    abnormal_rates = abnormal_feature_rates(stat)
    abnormal_rates.to_csv(paths["abnormal_rate_csv"], index=False)
    paths["abnormal_rate_png"] = output_dir / "abnormal_feature_rate_stat_matched.png"
    plot_abnormal_feature_rates(abnormal_rates, paths["abnormal_rate_png"])

    paths["margin_csv"] = output_dir / "threshold_margin_stat_matched.csv"
    margins = threshold_margin_summary(stat)
    margins.to_csv(paths["margin_csv"], index=False)
    paths["margin_png"] = output_dir / "threshold_margin_stat_matched.png"
    plot_threshold_margins(margins, paths["margin_png"])

    paths["feature_distribution_png"] = output_dir / "feature_distribution_stat_matched_error_analysis.png"
    plot_feature_distribution(stat, paths["feature_distribution_png"])

    if original is not None:
        paths["original_vs_stat_feature_png"] = output_dir / "original_vs_stat_attack_feature_comparison.png"
        plot_original_vs_stat_attack_features(original, stat, paths["original_vs_stat_feature_png"])
        paths["original_vs_stat_score_png"] = output_dir / "original_vs_stat_suspicious_score_comparison.png"
        plot_original_vs_stat_scores(original, stat, paths["original_vs_stat_score_png"])
        paths["original_vs_stat_summary_csv"] = output_dir / "original_vs_stat_attack_feature_summary.csv"
        original_vs_stat_attack_summary(original, stat).to_csv(paths["original_vs_stat_summary_csv"], index=False)

    paths["score_timeline_png"] = output_dir / "stat_matched_score_timeline.png"
    plot_score_timeline(stat, paths["score_timeline_png"])
    paths["margin_timeline_png"] = output_dir / "stat_matched_margin_timeline.png"
    plot_margin_timeline(stat, paths["margin_timeline_png"])
    paths["ema_threshold_timeline_png"] = output_dir / "ema_threshold_timeline_stat_matched.png"
    plot_ema_threshold_timeline(stat, paths["ema_threshold_timeline_png"])

    paths["summary_md"] = output_dir / "miss_analysis_stat_matched.md"
    paths["summary_md"].write_text(
        build_summary(config, stat, original, score_distribution, abnormal_rates, margins),
        encoding="utf-8",
    )
    return paths


def load_condition(
    condition_dir: Path,
    scenario: str,
    config: MissAnalysisConfig,
    output_dir: Path,
) -> pd.DataFrame:
    """Load or reconstruct predictions for one condition."""
    features_path = condition_dir / "features.csv"
    predictions_path = condition_dir / "predictions.csv"
    if not features_path.exists() and not predictions_path.exists():
        raise FileNotFoundError(
            f"missing both features.csv and predictions.csv under {condition_dir}. "
            "Run the Mininet experiment first or provide the correct results directory."
        )

    features = pd.read_csv(features_path) if features_path.exists() else None
    predictions = pd.read_csv(predictions_path) if predictions_path.exists() else None
    if predictions is None or not has_detector_detail_columns(predictions):
        if features is None:
            raise FileNotFoundError(
                f"{predictions_path} lacks detector details and {features_path} is unavailable for reconstruction"
            )
        predictions = reconstruct_predictions(features, scenario, config)

    enriched = normalize_prediction_columns(predictions, scenario)
    enriched_path = output_dir / f"{scenario}_predictions_enriched.csv"
    enriched.to_csv(enriched_path, index=False)
    return enriched


def has_detector_detail_columns(frame: pd.DataFrame) -> bool:
    """Return whether predictions already include thresholds and abnormal flags."""
    required = {"suspicious_score", "pred_label"}
    for feature in PAPER_FEATURES:
        required.add(f"{feature}_threshold")
        required.add(f"{feature}_is_suspicious")
    return required.issubset(frame.columns)


def reconstruct_predictions(features: pd.DataFrame, scenario: str, config: MissAnalysisConfig) -> pd.DataFrame:
    """Re-run the detector to reconstruct threshold and abnormal columns."""
    frame = features.copy()
    if "seed" not in frame.columns:
        frame["seed"] = 1
    if "stream_id" not in frame.columns:
        frame["stream_id"] = f"{scenario}_stream"
    if "stream_time_sec" not in frame.columns:
        frame["stream_time_sec"] = frame["window_start_sec"]
    if "stream_window_end_sec" not in frame.columns:
        frame["stream_window_end_sec"] = frame["window_end_sec"]
    if "scenario" not in frame.columns:
        frame["scenario"] = scenario
    if "label" not in frame.columns:
        if "true_label" in frame.columns:
            frame["label"] = frame["true_label"]
        else:
            raise ValueError(f"{scenario} features.csv must include label or true_label")
    detector_config = PaperDetectorConfig(
        warmup_windows=config.warmup_windows,
        min_packets_for_detection=config.min_packets_for_detection,
        suspicious_threshold=config.suspicious_threshold,
        use_observed_initial_state=True,
    )
    return run_paper_detector_by_seed(frame, detector_config)


def normalize_prediction_columns(predictions: pd.DataFrame, scenario: str) -> pd.DataFrame:
    """Add canonical labels, groups, margins, abnormal flags, and EMA aliases."""
    frame = predictions.copy()
    if "scenario" not in frame.columns:
        frame["scenario"] = scenario
    frame["true_label"] = label_from_columns(frame)
    if "pred_label" not in frame.columns:
        if "pred_attack" in frame.columns:
            frame["pred_label"] = np.where(frame["pred_attack"].astype(bool), "attack", "benign")
        else:
            raise ValueError("predictions must include pred_label or pred_attack")
    frame["pred_attack_bool"] = frame["pred_label"].astype(str).eq("attack")
    frame["true_attack_bool"] = frame["true_label"].astype(str).eq("attack")
    frame["analysis_group"] = np.select(
        [
            frame["true_label"].eq("benign"),
            frame["true_attack_bool"] & frame["pred_attack_bool"],
            frame["true_attack_bool"] & ~frame["pred_attack_bool"],
        ],
        ANALYSIS_GROUPS,
        default="other",
    )

    for feature in PAPER_FEATURES:
        threshold_col = f"{feature}_threshold"
        if threshold_col not in frame.columns:
            raise ValueError(f"predictions is missing {threshold_col}")
        margin_col = f"{feature}_margin"
        frame[margin_col] = frame[feature].astype(float) - frame[threshold_col].astype(float)

        suspicious_col = f"{feature}_is_suspicious"
        abnormal_col = f"{feature}_abnormal"
        if suspicious_col in frame.columns:
            frame[abnormal_col] = frame[suspicious_col].astype(bool)
        elif abnormal_col not in frame.columns:
            frame[abnormal_col] = frame[margin_col] > 0.0

        mu_col = f"{feature}_mu"
        ema_col = f"{feature}_ema"
        if ema_col not in frame.columns and mu_col in frame.columns:
            frame[ema_col] = frame[mu_col]

    return frame


def label_from_columns(frame: pd.DataFrame) -> pd.Series:
    """Return canonical true labels from available prediction columns."""
    if "true_label" in frame.columns:
        return frame["true_label"].astype(str)
    if "label" in frame.columns:
        return frame["label"].astype(str)
    if "true_attack" in frame.columns:
        return np.where(frame["true_attack"].astype(bool), "attack", "benign")
    raise ValueError("predictions must include true_label, label, or true_attack")


def grouped_frames(frame: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Return stat-matched analysis groups as DataFrames."""
    return {group: frame[frame["analysis_group"] == group].copy() for group in ANALYSIS_GROUPS}


def window_group_counts(frame: pd.DataFrame) -> pd.DataFrame:
    """Count benign, detected attack, and missed attack windows."""
    total = max(len(frame[frame["analysis_group"].isin(ANALYSIS_GROUPS)]), 1)
    rows = []
    for group in ANALYSIS_GROUPS:
        count = int((frame["analysis_group"] == group).sum())
        rows.append({"group": group, "count": count, "ratio": count / total})
    return pd.DataFrame(rows)


def suspicious_score_distribution(frame: pd.DataFrame) -> pd.DataFrame:
    """Summarize suspicious score distribution by analysis group."""
    rows = []
    groups = grouped_frames(frame)
    for group, group_frame in groups.items():
        scores = group_frame["suspicious_score"].fillna(0).astype(int)
        row: dict[str, Any] = {"group": group}
        for score in range(5):
            row[f"score_{score}_count"] = int((scores == score).sum())
        row["mean_score"] = float(scores.mean()) if len(scores) else 0.0
        row["median_score"] = float(scores.median()) if len(scores) else 0.0
        row["max_score"] = int(scores.max()) if len(scores) else 0
        reached = int((scores >= SCORE_THRESHOLD).sum())
        not_reached = int((scores < SCORE_THRESHOLD).sum())
        row["threshold_reached_count"] = reached
        row["threshold_not_reached_count"] = not_reached
        row["threshold_not_reached_rate"] = safe_divide(not_reached, reached + not_reached)
        rows.append(row)
    return pd.DataFrame(rows)


def abnormal_feature_rates(frame: pd.DataFrame) -> pd.DataFrame:
    """Compute abnormal flag rates by feature and analysis group."""
    groups = grouped_frames(frame)
    rows = []
    for feature in PAPER_FEATURES:
        row: dict[str, Any] = {"feature": feature}
        for group in ANALYSIS_GROUPS:
            group_frame = groups[group]
            abnormal_col = f"{feature}_abnormal"
            rate = float(group_frame[abnormal_col].astype(bool).mean()) if len(group_frame) else 0.0
            row[f"abnormal_rate_{group}"] = rate
        for group in ANALYSIS_GROUPS:
            row[f"count_{group}"] = int(len(groups[group]))
        rows.append(row)
    return pd.DataFrame(rows)


def threshold_margin_summary(frame: pd.DataFrame) -> pd.DataFrame:
    """Summarize value-threshold margins by group and feature."""
    rows = []
    groups = grouped_frames(frame)
    for group, group_frame in groups.items():
        for feature in PAPER_FEATURES:
            margins = group_frame[f"{feature}_margin"].dropna().astype(float)
            rows.append(
                {
                    "group": group,
                    "feature": feature,
                    "mean_margin": float(margins.mean()) if len(margins) else 0.0,
                    "median_margin": float(margins.median()) if len(margins) else 0.0,
                    "min_margin": float(margins.min()) if len(margins) else 0.0,
                    "max_margin": float(margins.max()) if len(margins) else 0.0,
                    "std_margin": float(margins.std(ddof=0)) if len(margins) else 0.0,
                    "positive_margin_rate": float((margins > 0).mean()) if len(margins) else 0.0,
                    "negative_margin_rate": float((margins < 0).mean()) if len(margins) else 0.0,
                }
            )
    return pd.DataFrame(rows)


def original_vs_stat_attack_summary(original: pd.DataFrame, stat: pd.DataFrame) -> pd.DataFrame:
    """Summarize attack feature distributions across original/stat-matched groups."""
    condition_frames = {
        "original_like_attack": original[original["true_label"] == "attack"],
        "stat_matched_detected_attack": stat[stat["analysis_group"] == "detected_attack"],
        "stat_matched_missed_attack": stat[stat["analysis_group"] == "missed_attack"],
    }
    rows = []
    for condition, frame in condition_frames.items():
        for feature in SUMMARY_FEATURES:
            values = frame[feature].dropna().astype(float)
            rows.append(
                {
                    "condition": condition,
                    "feature": feature,
                    "mean": float(values.mean()) if len(values) else 0.0,
                    "median": float(values.median()) if len(values) else 0.0,
                    "std": float(values.std(ddof=0)) if len(values) else 0.0,
                    "min": float(values.min()) if len(values) else 0.0,
                    "max": float(values.max()) if len(values) else 0.0,
                }
            )
    return pd.DataFrame(rows)


def plot_suspicious_score_distribution(summary: pd.DataFrame, output_path: Path) -> None:
    """Plot suspicious score count distribution by group."""
    x = np.arange(5)
    width = 0.25
    fig, axis = plt.subplots(figsize=(8.8, 4.8), constrained_layout=True)
    for index, group in enumerate(ANALYSIS_GROUPS):
        row = summary[summary["group"] == group]
        if row.empty:
            continue
        counts = [int(row.iloc[0][f"score_{score}_count"]) for score in range(5)]
        axis.bar(x + (index - 1) * width, counts, width=width, label=group)
    axis.axvline(SCORE_THRESHOLD - 0.5, color="black", linestyle="--", linewidth=1, label="threshold=2")
    axis.set_xticks(x)
    axis.set_xlabel("suspicious_score")
    axis.set_ylabel("window count")
    axis.set_title("stat_matched suspicious score distribution")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_abnormal_feature_rates(summary: pd.DataFrame, output_path: Path) -> None:
    """Plot abnormal feature rates by group."""
    x = np.arange(len(PAPER_FEATURES))
    width = 0.25
    fig, axis = plt.subplots(figsize=(10.5, 5.0), constrained_layout=True)
    for index, group in enumerate(ANALYSIS_GROUPS):
        values = [float(summary.loc[summary["feature"] == feature, f"abnormal_rate_{group}"].iloc[0]) for feature in PAPER_FEATURES]
        axis.bar(x + (index - 1) * width, values, width=width, label=group)
    axis.set_xticks(x)
    axis.set_xticklabels(PAPER_FEATURES, rotation=20, ha="right")
    axis.set_ylim(0.0, 1.05)
    axis.set_ylabel("abnormal rate")
    axis.set_title("stat_matched abnormal feature rate")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_threshold_margins(summary: pd.DataFrame, output_path: Path) -> None:
    """Plot mean threshold margins by group and feature."""
    fig, axes = plt.subplots(2, 2, figsize=(12, 7), constrained_layout=True)
    for axis, feature in zip(axes.ravel(), PAPER_FEATURES):
        feature_rows = summary[summary["feature"] == feature]
        values = [
            float(feature_rows.loc[feature_rows["group"] == group, "mean_margin"].iloc[0])
            if not feature_rows.loc[feature_rows["group"] == group].empty
            else 0.0
            for group in ANALYSIS_GROUPS
        ]
        colors = ["#4c78a8", "#54a24b", "#e45756"]
        axis.axhline(0.0, color="black", linewidth=1)
        axis.bar(ANALYSIS_GROUPS, values, color=colors)
        axis.set_title(feature)
        axis.tick_params(axis="x", rotation=20)
        axis.grid(axis="y", alpha=0.25)
    fig.suptitle("threshold margin = value - threshold")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_feature_distribution(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot group-wise boxplots for four features plus suspicious score."""
    fig, axes = plt.subplots(3, 2, figsize=(12, 11), constrained_layout=True)
    for axis, feature in zip(axes.ravel(), SUMMARY_FEATURES):
        values = [
            frame.loc[frame["analysis_group"] == group, feature].dropna().astype(float).to_numpy()
            for group in ANALYSIS_GROUPS
        ]
        axis.boxplot(values, labels=ANALYSIS_GROUPS, showfliers=True)
        axis.set_title(feature)
        axis.tick_params(axis="x", rotation=20)
        axis.grid(axis="y", alpha=0.25)
    if len(SUMMARY_FEATURES) < len(axes.ravel()):
        axes.ravel()[-1].set_axis_off()
    fig.suptitle("stat_matched feature distribution by error group")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_original_vs_stat_attack_features(original: pd.DataFrame, stat: pd.DataFrame, output_path: Path) -> None:
    """Plot attack feature boxplots for original_like and stat-matched groups."""
    condition_frames = attack_condition_frames(original, stat)
    fig, axes = plt.subplots(2, 2, figsize=(12, 8), constrained_layout=True)
    for axis, feature in zip(axes.ravel(), PAPER_FEATURES):
        values = [frame[feature].dropna().astype(float).to_numpy() for frame in condition_frames.values()]
        axis.boxplot(values, labels=list(condition_frames.keys()), showfliers=True)
        axis.set_title(feature)
        axis.tick_params(axis="x", rotation=20)
        axis.grid(axis="y", alpha=0.25)
    fig.suptitle("attack feature comparison: original_like vs stat_matched")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_original_vs_stat_scores(original: pd.DataFrame, stat: pd.DataFrame, output_path: Path) -> None:
    """Plot suspicious score distributions for attack windows across conditions."""
    condition_frames = attack_condition_frames(original, stat)
    fig, axis = plt.subplots(figsize=(8.8, 5.0), constrained_layout=True)
    x = np.arange(5)
    width = 0.24
    for index, (condition, frame) in enumerate(condition_frames.items()):
        scores = frame["suspicious_score"].fillna(0).astype(int)
        counts = [int((scores == score).sum()) for score in range(5)]
        axis.bar(x + (index - 1) * width, counts, width=width, label=condition)
    axis.axvline(SCORE_THRESHOLD - 0.5, color="black", linestyle="--", linewidth=1)
    axis.set_xticks(x)
    axis.set_xlabel("suspicious_score")
    axis.set_ylabel("attack window count")
    axis.set_title("attack suspicious score comparison")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def attack_condition_frames(original: pd.DataFrame, stat: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Return original/stat attack comparison frames."""
    return {
        "original_like_attack": original[original["true_label"] == "attack"].copy(),
        "stat_detected_attack": stat[stat["analysis_group"] == "detected_attack"].copy(),
        "stat_missed_attack": stat[stat["analysis_group"] == "missed_attack"].copy(),
    }


def plot_score_timeline(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot suspicious score over time for stat_matched."""
    fig, axis = plt.subplots(figsize=(11, 4.8), constrained_layout=True)
    x = frame["window_start_sec"]
    axis.plot(x, frame["suspicious_score"], color="#4c78a8", linewidth=1.8, label="suspicious_score")
    detected = frame[frame["analysis_group"] == "detected_attack"]
    missed = frame[frame["analysis_group"] == "missed_attack"]
    axis.scatter(detected["window_start_sec"], detected["suspicious_score"], color="#54a24b", marker="o", label="detected attack")
    axis.scatter(missed["window_start_sec"], missed["suspicious_score"], color="#e45756", marker="x", label="missed attack")
    axis.axhline(SCORE_THRESHOLD, color="black", linestyle="--", linewidth=1, label="threshold=2")
    axis.set_xlabel("window_start_sec")
    axis.set_ylabel("suspicious_score")
    axis.set_ylim(-0.2, 4.2)
    axis.set_title("stat_matched suspicious score timeline")
    axis.grid(alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_margin_timeline(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot threshold margin timelines for all four features."""
    fig, axes = plt.subplots(4, 1, figsize=(12, 10), sharex=True, constrained_layout=True)
    for axis, feature in zip(axes, PAPER_FEATURES):
        axis.plot(frame["window_start_sec"], frame[f"{feature}_margin"], color="#4c78a8", linewidth=1.5)
        axis.axhline(0.0, color="black", linestyle="--", linewidth=1)
        detected = frame[frame["analysis_group"] == "detected_attack"]
        missed = frame[frame["analysis_group"] == "missed_attack"]
        axis.scatter(detected["window_start_sec"], detected[f"{feature}_margin"], color="#54a24b", s=18, label="detected")
        axis.scatter(missed["window_start_sec"], missed[f"{feature}_margin"], color="#e45756", s=18, marker="x", label="missed")
        axis.set_ylabel(feature)
        axis.grid(alpha=0.25)
    axes[0].legend(loc="upper right")
    axes[-1].set_xlabel("window_start_sec")
    fig.suptitle("stat_matched threshold margins: margin = value - threshold")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_ema_threshold_timeline(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot feature value, EMA baseline, and threshold over time."""
    fig, axes = plt.subplots(4, 1, figsize=(12, 11), sharex=True, constrained_layout=True)
    for axis, feature in zip(axes, PAPER_FEATURES):
        axis.plot(frame["window_start_sec"], frame[feature], color="#4c78a8", linewidth=1.4, label="value")
        ema_col = f"{feature}_ema"
        if ema_col in frame.columns:
            axis.plot(frame["window_start_sec"], frame[ema_col], color="#54a24b", linewidth=1.2, label="EMA")
        axis.plot(frame["window_start_sec"], frame[f"{feature}_threshold"], color="#e45756", linewidth=1.2, label="threshold")
        axis.set_ylabel(feature)
        axis.grid(alpha=0.25)
    axes[0].legend(loc="upper right")
    axes[-1].set_xlabel("window_start_sec")
    fig.suptitle("stat_matched EMA baseline and dynamic thresholds")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def build_summary(
    config: MissAnalysisConfig,
    stat: pd.DataFrame,
    original: pd.DataFrame | None,
    score_distribution: pd.DataFrame,
    abnormal_rates: pd.DataFrame,
    margins: pd.DataFrame,
) -> str:
    """Build a Markdown summary from computed analysis outputs."""
    counts = window_group_counts(stat)
    count_lookup = dict(zip(counts["group"], counts["count"]))
    benign_count = int(count_lookup.get("benign", 0))
    detected_count = int(count_lookup.get("detected_attack", 0))
    missed_count = int(count_lookup.get("missed_attack", 0))
    attack_count = detected_count + missed_count
    missed_rate = safe_divide(missed_count, attack_count)

    missed_score = row_for_group(score_distribution, "missed_attack")
    detected_score = row_for_group(score_distribution, "detected_attack")
    missed_not_reached_rate = float(missed_score.get("threshold_not_reached_rate", 0.0))
    weak_features = lowest_abnormal_features(abnormal_rates, "missed_attack")
    negative_margin_rows = most_negative_margins(margins, "missed_attack")
    detected_positive = most_positive_margins(margins, "detected_attack")

    summary_rows = [[row["group"], str(int(row["count"])), f"{float(row['ratio']):.4f}"] for _, row in counts.iterrows()]
    score_rows = [
        [
            str(row["group"]),
            f"{float(row['mean_score']):.3f}",
            f"{float(row['median_score']):.3f}",
            str(int(row["threshold_not_reached_count"])),
            f"{float(row['threshold_not_reached_rate']):.3f}",
        ]
        for _, row in score_distribution.iterrows()
    ]
    abnormal_rows = [
        [
            row["feature"],
            f"{float(row['abnormal_rate_detected_attack']):.3f}",
            f"{float(row['abnormal_rate_missed_attack']):.3f}",
        ]
        for _, row in abnormal_rates.iterrows()
    ]

    lines = [
        "# Miss analysis: stat_matched",
        "",
        "## 1. 目的",
        "",
        "stat_matched条件でFNR=0.825となり、periodic LDoSの大半を見逃した理由を分析する。",
        "",
        "## 2. 入力データ",
        "",
        f"- stat_matched features: `{config.stat_matched_dir / 'features.csv'}`",
        f"- stat_matched predictions: `{config.stat_matched_dir / 'predictions.csv'}`",
        f"- stat_matched metrics: `{config.stat_matched_dir / 'metrics.json'}`",
    ]
    if config.original_like_dir is not None:
        lines.extend(
            [
                f"- original_like features: `{config.original_like_dir / 'features.csv'}`",
                f"- original_like predictions: `{config.original_like_dir / 'predictions.csv'}`",
                f"- original_like metrics: `{config.original_like_dir / 'metrics.json'}`",
            ]
        )
    lines.extend(
        [
            "",
            "## 3. window数の内訳",
            "",
            markdown_table(["group", "count", "ratio"], summary_rows),
            "",
            f"- benign window数: {benign_count}",
            f"- attack window数: {attack_count}",
            f"- detected attack window数: {detected_count}",
            f"- missed attack window数: {missed_count}",
            f"- missed attack rate: {missed_rate:.3f}",
            "",
            "## 4. suspicious_scoreの分析",
            "",
            markdown_table(
                ["group", "mean_score", "median_score", "threshold_not_reached_count", "threshold_not_reached_rate"],
                score_rows,
            ),
            "",
            f"missed_attack windowでは、scoreがthreshold=2に届かなかった割合は {missed_not_reached_rate:.3f} だった。"
            f" detected_attackの平均scoreは {float(detected_score.get('mean_score', 0.0)):.3f}、"
            f"missed_attackの平均scoreは {float(missed_score.get('mean_score', 0.0)):.3f} である。",
            "stat_matchedでFNRが高くなった直接的な理由は、attack windowでsuspicious_scoreが2に届かないwindowが多かったかどうかにある。",
            "",
            "## 5. 各特徴量の異常判定率",
            "",
            markdown_table(["feature", "detected_attack abnormal rate", "missed_attack abnormal rate"], abnormal_rows),
            "",
            "missed_attackでabnormal rateが低かった特徴量: " + ", ".join(weak_features) + "。",
            "",
            "## 6. threshold marginの分析",
            "",
            "marginは `margin = value - threshold` と定義した。正の値は数値として閾値を上回ったことを示し、負の値は閾値を下回ったことを示す。"
            " なお、元論文型detectorではIAT varianceとpayload size varianceは低い方向の異常もあるため、abnormal判定はmarginの符号だけではなくdetectorの方向付き判定に従う。",
            "",
            "missed_attackで平均marginが負に偏っていた特徴量: " + ", ".join(negative_margin_rows) + "。",
            "detected_attackで平均marginが正になりやすかった特徴量: " + ", ".join(detected_positive) + "。",
            "",
            "## 7. original_likeとの比較",
            "",
        ]
    )
    if original is None:
        lines.append("original_like結果が入力されていないため、比較はスキップした。")
    else:
        original_attack = original[original["true_label"] == "attack"]
        stat_missed = stat[stat["analysis_group"] == "missed_attack"]
        lines.extend(
            [
                f"original_likeのattack window数は {len(original_attack)}、stat_matchedのmissed_attack window数は {len(stat_missed)} だった。",
                "original_likeでは通常benign baselineからperiodic LDoSへ移るため、4特徴量のうち複数が異常として立ちやすい。"
                "stat_matchedではrandom microburstがperiodic LDoSと窓内統計特徴量を近づけるため、attack windowでも同じ特徴量が閾値を超えにくくなる。",
            ]
        )
    lines.extend(
        [
            "",
            "## 8. EMA baseline / thresholdの分析",
            "",
            "`ema_threshold_timeline_stat_matched.png` に、各特徴量の値、EMA baseline、dynamic thresholdの時系列を出力した。"
            " 時間とともにEMAやthresholdがattack側の値へ近づく場合、攻撃系列にbaselineが適応し、特徴量が異常として立ちにくくなる可能性がある。",
            "",
            "## 9. 総合考察",
            "",
            "stat_matchedでは、periodic LDoSとrandom microburstの窓内統計特徴量が似ているため、各特徴量が異常として立ちにくかった可能性がある。"
            "その結果、suspicious_scoreが2に届かずattack判定されないwindowが増えた可能性がある。",
            "今回の問題はfalse positiveではなくfalse negativeである。元論文型4特徴量detectorはoriginal_likeでは機能した一方、stat_matchedではperiodic LDoSを見逃した。",
            "この分析は元論文の完全再現ではなく、元論文型detectorに対するMininet A/B追加評価である。eBPF/XDP、Goertzel、Sliding DFTは使っていない。",
            "",
        ]
    )
    return "\n".join(lines)


def row_for_group(frame: pd.DataFrame, group: str) -> dict[str, Any]:
    """Return one summary row as a dict, or an empty fallback."""
    row = frame[frame["group"] == group]
    return row.iloc[0].to_dict() if not row.empty else {}


def lowest_abnormal_features(summary: pd.DataFrame, group: str) -> list[str]:
    """Return features sorted by lowest abnormal rate for one group."""
    column = f"abnormal_rate_{group}"
    sorted_rows = summary.sort_values(column, ascending=True)
    return [f"{row.feature} ({getattr(row, column):.3f})" for row in sorted_rows.itertuples(index=False)]


def most_negative_margins(summary: pd.DataFrame, group: str) -> list[str]:
    """Return features with negative average margin for one group."""
    rows = summary[(summary["group"] == group) & (summary["mean_margin"] < 0)].sort_values("mean_margin")
    if rows.empty:
        return ["none"]
    return [f"{row.feature} ({row.mean_margin:.3g})" for row in rows.itertuples(index=False)]


def most_positive_margins(summary: pd.DataFrame, group: str) -> list[str]:
    """Return features with positive average margin for one group."""
    rows = summary[(summary["group"] == group) & (summary["mean_margin"] > 0)].sort_values("mean_margin", ascending=False)
    if rows.empty:
        return ["none"]
    return [f"{row.feature} ({row.mean_margin:.3g})" for row in rows.itertuples(index=False)]


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide while avoiding zero division."""
    return 0.0 if denominator == 0 else float(numerator / denominator)
