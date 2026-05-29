"""Plotting utilities for phase-1 LDoS stat-matching experiments."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .evaluate_similarity import PRIMARY_STAT_FEATURES


def plot_bucket_timeseries(
    periodic_buckets: list[int],
    microburst_buckets: list[int],
    bucket_ms: int,
    output_path: str | Path,
) -> None:
    """Save a two-panel bucket time-series comparison."""
    time_sec = np.arange(len(periodic_buckets), dtype=float) * bucket_ms / 1000.0
    fig, axes = plt.subplots(2, 1, figsize=(13, 5), sharex=True, constrained_layout=True)

    axes[0].step(time_sec, periodic_buckets, where="post", color="#1f77b4", linewidth=1.1)
    axes[0].set_title("periodic_ldos bucket counts")
    axes[0].set_ylabel("pkts/bucket")

    axes[1].step(time_sec, microburst_buckets, where="post", color="#ff7f0e", linewidth=1.1)
    axes[1].set_title("random_microburst bucket counts")
    axes[1].set_ylabel("pkts/bucket")
    axes[1].set_xlabel("time [sec]")

    for axis in axes:
        axis.grid(True, alpha=0.25)
        axis.set_ylim(bottom=-0.5)

    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def plot_stat_features_comparison(
    periodic_features: pd.DataFrame,
    microburst_features: pd.DataFrame,
    output_path: str | Path,
) -> None:
    """Save a 2x2 bar chart for the four primary statistical features."""
    _plot_feature_panels(
        periodic_features,
        microburst_features,
        PRIMARY_STAT_FEATURES,
        output_path,
        title_prefix="Stat feature",
    )


def plot_frequency_features_comparison(
    periodic_features: pd.DataFrame,
    microburst_features: pd.DataFrame,
    output_path: str | Path,
) -> None:
    """Save bar charts for normalized frequency features."""
    feature_names = ["normalized_1hz_power", "normalized_rto_band_power"]
    _plot_feature_panels(
        periodic_features,
        microburst_features,
        feature_names,
        output_path,
        title_prefix="Frequency feature",
        columns=2,
    )


def plot_feature_distance_summary(
    similarity_table: pd.DataFrame,
    output_path: str | Path,
) -> None:
    """Save a bar chart comparing relative differences across selected features."""
    selected_features = PRIMARY_STAT_FEATURES + ["normalized_1hz_power", "normalized_rto_band_power"]
    selected = similarity_table[similarity_table["feature"].isin(selected_features)].copy()
    selected["feature"] = pd.Categorical(selected["feature"], categories=selected_features, ordered=True)
    selected = selected.sort_values("feature")

    colors = ["#4c78a8" if group == "primary_stat" else "#f58518" for group in selected["group"]]
    fig, axis = plt.subplots(figsize=(11, 4.5), constrained_layout=True)
    axis.bar(selected["feature"].astype(str), selected["relative_difference"], color=colors)
    axis.set_ylabel("relative difference")
    axis.set_title("Relative difference: stat features vs frequency features")
    axis.tick_params(axis="x", rotation=25)
    axis.grid(axis="y", alpha=0.25)
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def _plot_feature_panels(
    periodic_features: pd.DataFrame,
    microburst_features: pd.DataFrame,
    feature_names: list[str],
    output_path: str | Path,
    title_prefix: str,
    columns: int = 2,
) -> None:
    """Render small multiples so tiny and large features remain readable."""
    rows = int(np.ceil(len(feature_names) / columns))
    fig, axes = plt.subplots(rows, columns, figsize=(5.2 * columns, 3.4 * rows), constrained_layout=True)
    axes_array = np.atleast_1d(axes).reshape(-1)

    for axis, feature in zip(axes_array, feature_names):
        values = [periodic_features[feature].mean(), microburst_features[feature].mean()]
        axis.bar(["periodic_ldos", "random_microburst"], values, color=["#1f77b4", "#ff7f0e"])
        axis.set_title(f"{title_prefix}: {feature}")
        axis.grid(axis="y", alpha=0.25)
        axis.tick_params(axis="x", rotation=12)

    for axis in axes_array[len(feature_names) :]:
        axis.axis("off")

    fig.savefig(output_path, dpi=160)
    plt.close(fig)
