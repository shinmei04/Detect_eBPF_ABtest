"""Tradeoff analysis for stat matching, TCP degradation, and detector FNR."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from src.goertzel import goertzel_power
from src.paper_reproduction_detector import PAPER_FEATURES
from src.utils import count_buckets_for_duration, ensure_dir, markdown_table


RTO_PRESETS = {
    "rto_2": {"period_ms": 1000, "burst_ms": 200, "attack_rate_mbps": 120.0, "payload_size": 750},
    "rto_3": {"period_ms": 1200, "burst_ms": 300, "attack_rate_mbps": 140.0, "payload_size": 1000},
    "rto_4": {"period_ms": 1500, "burst_ms": 400, "attack_rate_mbps": 150.0, "payload_size": 1472},
}


@dataclass(frozen=True)
class TradeoffCondition:
    """One R/L/T/payload tradeoff condition."""

    condition_id: str
    attack_rate_mbps: float
    burst_ms: int
    period_ms: int
    payload_size: int
    preset: str = ""


def build_tradeoff_conditions(
    attack_rates: list[float],
    burst_values: list[int],
    period_values: list[int],
    payload_values: list[int],
    include_grid: bool,
    attack_preset: str,
) -> list[TradeoffCondition]:
    """Build deduplicated grid and RTO preset conditions."""
    raw: list[dict[str, Any]] = []
    if include_grid:
        for rate in attack_rates:
            for burst in burst_values:
                for period in period_values:
                    for payload in payload_values:
                        raw.append(
                            {
                                "attack_rate_mbps": float(rate),
                                "burst_ms": int(burst),
                                "period_ms": int(period),
                                "payload_size": int(payload),
                                "preset": "",
                            }
                        )
    if include_grid and attack_preset == "none":
        names = list(RTO_PRESETS)
    elif attack_preset in {"all_rto", "rto_2", "rto_3", "rto_4"}:
        names = list(RTO_PRESETS) if attack_preset == "all_rto" else [attack_preset]
    else:
        names = []
    if names:
        for name in names:
            raw.append({**RTO_PRESETS[name], "preset": name})

    dedup: dict[tuple[float, int, int, int], dict[str, Any]] = {}
    for item in raw:
        key = (
            float(item["attack_rate_mbps"]),
            int(item["burst_ms"]),
            int(item["period_ms"]),
            int(item["payload_size"]),
        )
        if key not in dedup or item.get("preset"):
            dedup[key] = item

    conditions = []
    for item in dedup.values():
        preset = str(item.get("preset", ""))
        condition_id = preset or condition_id_from_values(
            float(item["attack_rate_mbps"]),
            int(item["burst_ms"]),
            int(item["period_ms"]),
            int(item["payload_size"]),
        )
        conditions.append(
            TradeoffCondition(
                condition_id=condition_id,
                attack_rate_mbps=float(item["attack_rate_mbps"]),
                burst_ms=int(item["burst_ms"]),
                period_ms=int(item["period_ms"]),
                payload_size=int(item["payload_size"]),
                preset=preset,
            )
        )
    return sorted(conditions, key=lambda c: (c.preset == "", c.period_ms, c.burst_ms, c.attack_rate_mbps, c.payload_size))


def condition_id_from_values(rate: float, burst_ms: int, period_ms: int, payload_size: int) -> str:
    """Return a filesystem-safe condition id."""
    rate_text = f"{rate:g}".replace(".", "p")
    return f"r{rate_text}_l{burst_ms}_t{period_ms}_p{payload_size}"


def compute_stat_match_metrics(
    stat_window_log: pd.DataFrame,
    stat_packets: pd.DataFrame | None,
    bucket_ms: int,
    attack_start_sec: float,
    duration_sec: float,
    period_ms: int,
    weights: dict[str, float] | None = None,
) -> dict[str, float]:
    """Compare periodic LDoS attack windows with random microburst baseline windows."""
    weights = weights or {feature: 0.25 for feature in PAPER_FEATURES}
    random_windows = stat_window_log[stat_window_log["true_label"].astype(str).eq("benign")]
    periodic_windows = stat_window_log[stat_window_log["true_label"].astype(str).eq("attack")]
    metrics: dict[str, float] = {}
    diffs: list[float] = []
    weighted = 0.0
    for feature in PAPER_FEATURES:
        periodic_mean = float(periodic_windows[feature].mean()) if feature in periodic_windows else 0.0
        random_mean = float(random_windows[feature].mean()) if feature in random_windows else 0.0
        diff = relative_diff(periodic_mean, random_mean)
        metrics[f"{feature}_relative_diff"] = diff
        diffs.append(diff)
        weighted += float(weights.get(feature, 0.25)) * diff
    metrics["mean_feature_relative_diff"] = float(np.mean(diffs)) if diffs else 0.0
    metrics["max_feature_relative_diff"] = float(np.max(diffs)) if diffs else 0.0
    metrics["weighted_feature_relative_diff"] = weighted

    periodic_power, random_power = periodicity_metrics(
        stat_packets,
        bucket_ms=bucket_ms,
        attack_start_sec=attack_start_sec,
        duration_sec=duration_sec,
        period_ms=period_ms,
    )
    metrics.update(
        {
            "normalized_1hz_power_periodic": periodic_power["normalized_1hz_power"],
            "normalized_1hz_power_random": random_power["normalized_1hz_power"],
            "normalized_1hz_power_ratio": safe_divide(
                periodic_power["normalized_1hz_power"],
                random_power["normalized_1hz_power"],
            ),
            "rto_band_power_periodic": periodic_power["rto_band_power"],
            "rto_band_power_random": random_power["rto_band_power"],
            "rto_band_power_ratio": safe_divide(periodic_power["rto_band_power"], random_power["rto_band_power"]),
        }
    )
    return metrics


def periodicity_metrics(
    packets: pd.DataFrame | None,
    bucket_ms: int,
    attack_start_sec: float,
    duration_sec: float,
    period_ms: int,
) -> tuple[dict[str, float], dict[str, float]]:
    """Return periodic and random normalized frequency metrics."""
    empty = {"normalized_1hz_power": 0.0, "rto_band_power": 0.0}
    if packets is None or packets.empty or "timestamp_sec" not in packets.columns:
        return empty, empty
    periodic_packets = packets[packets["timestamp_sec"] >= attack_start_sec].copy()
    random_packets = packets[packets["timestamp_sec"] < attack_start_sec].copy()
    periodic_packets["timestamp_sec"] = periodic_packets["timestamp_sec"] - attack_start_sec
    periodic_duration = max(0.0, duration_sec - attack_start_sec)
    random_duration = attack_start_sec
    periodic_buckets = packets_to_buckets(periodic_packets, periodic_duration, bucket_ms)
    random_buckets = packets_to_buckets(random_packets, random_duration, bucket_ms)
    target_freq_hz = 1000.0 / period_ms
    return frequency_summary(periodic_buckets, bucket_ms, target_freq_hz), frequency_summary(
        random_buckets,
        bucket_ms,
        target_freq_hz,
    )


def packets_to_buckets(packets: pd.DataFrame, duration_sec: float, bucket_ms: int) -> list[int]:
    """Convert packet timestamps to bucket counts."""
    total_buckets = count_buckets_for_duration(max(duration_sec, bucket_ms / 1000.0), bucket_ms)
    buckets = [0] * total_buckets
    if packets.empty:
        return buckets
    bucket_sec = bucket_ms / 1000.0
    bucket_indices = np.floor(packets["timestamp_sec"].to_numpy(dtype=float) / bucket_sec).astype(int)
    for bucket_index, count in pd.Series(bucket_indices).value_counts().items():
        if 0 <= int(bucket_index) < total_buckets:
            buckets[int(bucket_index)] += int(count)
    return buckets


def frequency_summary(buckets: list[int], bucket_ms: int, target_freq_hz: float) -> dict[str, float]:
    """Compute analysis-only Goertzel frequency summary."""
    signal = np.asarray(buckets, dtype=float)
    if signal.size == 0:
        return {"normalized_1hz_power": 0.0, "rto_band_power": 0.0}
    centered = signal - np.mean(signal)
    total_power = float(signal.size * np.sum(centered * centered))
    if total_power <= 0:
        return {"normalized_1hz_power": 0.0, "rto_band_power": 0.0}
    sampling_rate_hz = 1000.0 / bucket_ms
    centered_list = centered.tolist()
    normalized_1hz = goertzel_power(centered_list, sampling_rate_hz, 1.0) / total_power
    band_freqs = sorted({target_freq_hz * factor for factor in (0.8, 0.9, 1.0, 1.1, 1.2)})
    rto_band = sum(goertzel_power(centered_list, sampling_rate_hz, freq) for freq in band_freqs) / total_power
    return {"normalized_1hz_power": float(normalized_1hz), "rto_band_power": float(rto_band)}


def packets_from_csv(path: Path) -> pd.DataFrame | None:
    """Load packet CSV if it exists."""
    return pd.read_csv(path) if path.exists() else None


def condition_tradeoff_row(
    condition: TradeoffCondition,
    throughput_metrics: pd.DataFrame,
    detector_metrics: pd.DataFrame,
    stat_metrics: dict[str, float],
    udp_metrics: dict[str, float],
) -> dict[str, Any]:
    """Build one row for tradeoff_all_conditions.csv."""
    original = select_row(throughput_metrics, "original_like_ldos")
    stat = select_row(throughput_metrics, "stat_matched_ldos")
    random = select_row(throughput_metrics, "random_microburst_only")
    original_detector = select_row(detector_metrics, "original_like_ldos")
    stat_detector = select_row(detector_metrics, "stat_matched_ldos")
    original_fnr = float(original_detector.get("fnr", 0.0))
    stat_fnr = float(stat_detector.get("fnr", 0.0))
    row: dict[str, Any] = {
        "condition_id": condition.condition_id,
        "preset": condition.preset,
        "attack_rate_mbps": condition.attack_rate_mbps,
        "burst_ms": condition.burst_ms,
        "period_ms": condition.period_ms,
        "payload_size": condition.payload_size,
        "actual_burst_rate_mbps": udp_metrics.get("actual_burst_rate_mbps", 0.0),
        "actual_average_rate_mbps": udp_metrics.get("actual_average_rate_mbps", 0.0),
        "original_like_degradation": original.get("throughput_degradation", 0.0),
        "stat_matched_degradation": stat.get("throughput_degradation", 0.0),
        "random_microburst_degradation": random.get("throughput_degradation", 0.0),
        "original_like_FNR": original_fnr,
        "stat_matched_FNR": stat_fnr,
        "FNR_delta": stat_fnr - original_fnr,
    }
    row.update(stat_metrics)
    row["success_level"] = success_level(row)
    return row


def success_level(row: dict[str, Any]) -> str:
    """Classify success level from degradation, feature diff, and FNR thresholds."""
    degradation = float(row.get("stat_matched_degradation", 0.0))
    mean_diff = float(row.get("mean_feature_relative_diff", 1.0))
    max_diff = float(row.get("max_feature_relative_diff", 1.0))
    fnr = float(row.get("stat_matched_FNR", 0.0))
    base = mean_diff <= 0.20 and max_diff <= 0.30 and fnr >= 0.70
    if base and degradation >= 0.50:
        return "strong_success"
    if base and degradation >= 0.30:
        return "moderate_success"
    if base and degradation >= 0.20:
        return "weak_success"
    return "no_success"


def write_tradeoff_outputs(all_conditions: pd.DataFrame, output_dir: Path) -> None:
    """Write aggregate CSVs, figures, and Markdown summaries."""
    ensure_dir(output_dir)
    all_conditions.to_csv(output_dir / "tradeoff_all_conditions.csv", index=False)
    pareto = pareto_front(all_conditions)
    pareto.to_csv(output_dir / "pareto_optimal_conditions.csv", index=False)
    top = top_tradeoff_candidates(all_conditions)
    top.to_csv(output_dir / "top_tradeoff_candidates.csv", index=False)
    plot_all_tradeoff_figures(all_conditions, pareto, top, output_dir)
    (output_dir / "tradeoff_summary.md").write_text(
        build_tradeoff_summary(all_conditions, pareto, top),
        encoding="utf-8",
    )
    (output_dir / "final_claim_evaluation.md").write_text(
        build_final_claim_evaluation(all_conditions, pareto, top),
        encoding="utf-8",
    )


def pareto_front(frame: pd.DataFrame) -> pd.DataFrame:
    """Return Pareto-optimal conditions: low mean diff, high degradation, high FNR."""
    if frame.empty:
        return frame.copy()
    keep = []
    for idx, row in frame.iterrows():
        dominated = False
        for other_idx, other in frame.iterrows():
            if idx == other_idx:
                continue
            no_worse = (
                other["mean_feature_relative_diff"] <= row["mean_feature_relative_diff"]
                and other["stat_matched_degradation"] >= row["stat_matched_degradation"]
                and other["stat_matched_FNR"] >= row["stat_matched_FNR"]
            )
            strictly_better = (
                other["mean_feature_relative_diff"] < row["mean_feature_relative_diff"]
                or other["stat_matched_degradation"] > row["stat_matched_degradation"]
                or other["stat_matched_FNR"] > row["stat_matched_FNR"]
            )
            if no_worse and strictly_better:
                dominated = True
                break
        keep.append(not dominated)
    return frame.loc[keep].sort_values(["mean_feature_relative_diff", "stat_matched_degradation"], ascending=[True, False])


def top_tradeoff_candidates(frame: pd.DataFrame) -> pd.DataFrame:
    """Return top 20 ranked tradeoff candidates."""
    if frame.empty:
        return frame.copy()
    ranked = frame.copy()
    ranked["tradeoff_score"] = (
        1.0 * ranked["stat_matched_degradation"]
        + 0.5 * ranked["stat_matched_FNR"]
        - 1.0 * ranked["mean_feature_relative_diff"]
        - 0.5 * ranked["max_feature_relative_diff"]
        - 0.5 * np.maximum(0.0, ranked["random_microburst_degradation"])
    )
    return ranked.sort_values("tradeoff_score", ascending=False).head(20)


def plot_all_tradeoff_figures(frame: pd.DataFrame, pareto: pd.DataFrame, top: pd.DataFrame, output_dir: Path) -> None:
    """Write all requested PNG figures."""
    plot_similarity_vs_degradation(frame, output_dir / "tradeoff_similarity_vs_degradation.png", x_col="mean_feature_relative_diff", x_threshold=0.20)
    plot_similarity_vs_degradation(frame, output_dir / "tradeoff_maxdiff_vs_degradation.png", x_col="max_feature_relative_diff", x_threshold=0.30)
    plot_3d_or_bubble(frame, output_dir / "tradeoff_3d_similarity_degradation_fnr.png")
    plot_pareto(frame, pareto, output_dir / "pareto_front_similarity_degradation.png")
    plot_fnr_vs_similarity(frame, output_dir / "fnr_vs_feature_similarity.png")
    plot_fnr_vs_degradation(frame, output_dir / "fnr_vs_degradation.png")
    plot_feature_diff_breakdown(top if not top.empty else frame, output_dir / "feature_diff_breakdown_top_candidates.png")
    plot_degradation_heatmaps(frame, output_dir / "degradation_by_r_l_t_payload_heatmap.png")
    plot_success_level(frame, output_dir / "success_level_scatter.png")


def plot_similarity_vs_degradation(frame: pd.DataFrame, output_path: Path, x_col: str, x_threshold: float) -> None:
    """Plot similarity degradation tradeoff scatter."""
    fig, axis = plt.subplots(figsize=(10, 6), constrained_layout=True)
    if frame.empty:
        axis.text(0.5, 0.5, "No tradeoff rows", ha="center", va="center")
        axis.set_axis_off()
    else:
        sizes = 30 + 5 * frame["attack_rate_mbps"].astype(float)
        scatter = axis.scatter(
            frame[x_col],
            frame["stat_matched_degradation"],
            c=frame["stat_matched_FNR"],
            s=sizes,
            cmap="viridis",
            alpha=0.78,
            edgecolors=np.where(frame["success_level"].eq("no_success"), "none", "black"),
            linewidths=np.where(frame["success_level"].eq("no_success"), 0.0, 1.3),
        )
        for _, row in frame[~frame["success_level"].eq("no_success")].iterrows():
            axis.annotate(label_for(row), (row[x_col], row["stat_matched_degradation"]), fontsize=7)
        axis.axvline(x_threshold, color="black", linestyle="--", linewidth=1)
        for y in (0.20, 0.30, 0.50):
            axis.axhline(y, color="gray", linestyle=":", linewidth=1)
        axis.set_xlabel(x_col)
        axis.set_ylabel("stat_matched TCP throughput degradation")
        axis.set_title(f"{x_col} vs stat_matched degradation")
        axis.grid(alpha=0.25)
        fig.colorbar(scatter, ax=axis, label="stat_matched FNR")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_3d_or_bubble(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot 3D scatter with similarity, degradation, and FNR."""
    fig = plt.figure(figsize=(10, 7), constrained_layout=True)
    axis = fig.add_subplot(111, projection="3d")
    if frame.empty:
        axis.text2D(0.5, 0.5, "No tradeoff rows", transform=axis.transAxes, ha="center")
    else:
        sizes = 15 + 4 * frame["actual_average_rate_mbps"].fillna(frame["attack_rate_mbps"]).astype(float)
        scatter = axis.scatter(
            frame["mean_feature_relative_diff"],
            frame["stat_matched_degradation"],
            frame["stat_matched_FNR"],
            s=sizes,
            c=frame["stat_matched_FNR"],
            cmap="viridis",
            alpha=0.75,
        )
        axis.set_xlabel("mean feature relative diff")
        axis.set_ylabel("stat_matched degradation")
        axis.set_zlabel("stat_matched FNR")
        axis.set_title("Similarity / degradation / FNR tradeoff")
        fig.colorbar(scatter, ax=axis, shrink=0.7, label="stat_matched FNR")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_pareto(frame: pd.DataFrame, pareto: pd.DataFrame, output_path: Path) -> None:
    """Plot Pareto frontier."""
    fig, axis = plt.subplots(figsize=(10, 6), constrained_layout=True)
    if frame.empty:
        axis.text(0.5, 0.5, "No tradeoff rows", ha="center", va="center")
        axis.set_axis_off()
    else:
        axis.scatter(frame["mean_feature_relative_diff"], frame["stat_matched_degradation"], alpha=0.35, label="all")
        if not pareto.empty:
            ordered = pareto.sort_values("mean_feature_relative_diff")
            axis.plot(ordered["mean_feature_relative_diff"], ordered["stat_matched_degradation"], color="#e45756", linewidth=2, label="Pareto front")
            axis.scatter(ordered["mean_feature_relative_diff"], ordered["stat_matched_degradation"], color="#e45756")
            for _, row in ordered.iterrows():
                axis.annotate(label_for(row), (row["mean_feature_relative_diff"], row["stat_matched_degradation"]), fontsize=7)
        axis.set_xlabel("mean feature relative diff (lower is better)")
        axis.set_ylabel("stat_matched degradation (higher is better)")
        axis.set_title("Pareto frontier: low feature diff, high degradation")
        axis.grid(alpha=0.25)
        axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_fnr_vs_similarity(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot stat_matched FNR vs feature similarity."""
    fig, axis = plt.subplots(figsize=(9, 5.5), constrained_layout=True)
    if not frame.empty:
        scatter = axis.scatter(
            frame["mean_feature_relative_diff"],
            frame["stat_matched_FNR"],
            c=frame["stat_matched_degradation"],
            cmap="plasma",
            s=70,
            alpha=0.8,
        )
        axis.axvline(0.20, color="black", linestyle="--", linewidth=1)
        axis.set_xlabel("mean feature relative diff")
        axis.set_ylabel("stat_matched FNR")
        axis.set_title("FNR vs feature similarity")
        axis.grid(alpha=0.25)
        fig.colorbar(scatter, ax=axis, label="stat_matched degradation")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_fnr_vs_degradation(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot FNR vs degradation."""
    fig, axis = plt.subplots(figsize=(9, 5.5), constrained_layout=True)
    if not frame.empty:
        scatter = axis.scatter(
            frame["stat_matched_degradation"],
            frame["stat_matched_FNR"],
            c=frame["mean_feature_relative_diff"],
            cmap="viridis_r",
            s=70,
            alpha=0.8,
        )
        axis.set_xlabel("stat_matched degradation")
        axis.set_ylabel("stat_matched FNR")
        axis.set_title("FNR vs TCP degradation")
        axis.grid(alpha=0.25)
        fig.colorbar(scatter, ax=axis, label="mean feature relative diff")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_feature_diff_breakdown(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot stacked feature-diff bars for top candidates."""
    selected = frame.head(10).copy()
    fig, axis = plt.subplots(figsize=(11, 6), constrained_layout=True)
    if selected.empty:
        axis.text(0.5, 0.5, "No candidates", ha="center", va="center")
        axis.set_axis_off()
    else:
        labels = [label_for(row) for _, row in selected.iterrows()]
        bottom = np.zeros(len(selected))
        for feature in PAPER_FEATURES:
            values = selected[f"{feature}_relative_diff"].to_numpy(dtype=float)
            axis.bar(labels, values, bottom=bottom, label=feature)
            bottom += values
        axis.set_ylabel("relative diff")
        axis.set_title("Feature-diff breakdown for top tradeoff candidates")
        axis.tick_params(axis="x", rotation=35)
        axis.grid(axis="y", alpha=0.25)
        axis.legend(fontsize=8)
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_degradation_heatmaps(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot faceted heatmaps by period/burst using rate x payload."""
    if frame.empty:
        fig, axis = plt.subplots(figsize=(8, 5))
        axis.text(0.5, 0.5, "No tradeoff rows", ha="center", va="center")
        axis.set_axis_off()
        fig.savefig(output_path, dpi=170)
        plt.close(fig)
        return
    periods = sorted(frame["period_ms"].unique())
    bursts = sorted(frame["burst_ms"].unique())
    nrows = len(periods)
    ncols = len(bursts)
    fig, axes = plt.subplots(nrows, ncols, figsize=(3.0 * ncols, 2.7 * nrows), squeeze=False, constrained_layout=True)
    vmin = float(frame["stat_matched_degradation"].min())
    vmax = float(frame["stat_matched_degradation"].max())
    image = None
    for row_idx, period in enumerate(periods):
        for col_idx, burst in enumerate(bursts):
            axis = axes[row_idx][col_idx]
            subset = frame[(frame["period_ms"] == period) & (frame["burst_ms"] == burst)]
            if subset.empty:
                axis.set_axis_off()
                continue
            pivot = subset.pivot_table(
                index="attack_rate_mbps",
                columns="payload_size",
                values="stat_matched_degradation",
                aggfunc="mean",
            ).sort_index()
            image = axis.imshow(pivot.to_numpy(dtype=float), aspect="auto", origin="lower", vmin=vmin, vmax=vmax, cmap="magma")
            axis.set_title(f"T={period} L={burst}")
            axis.set_xticks(np.arange(len(pivot.columns)))
            axis.set_xticklabels([str(int(v)) for v in pivot.columns], rotation=45, fontsize=7)
            axis.set_yticks(np.arange(len(pivot.index)))
            axis.set_yticklabels([str(int(v)) for v in pivot.index], fontsize=7)
            if row_idx == nrows - 1:
                axis.set_xlabel("payload")
            if col_idx == 0:
                axis.set_ylabel("R Mbps")
    if image is not None:
        fig.colorbar(image, ax=axes, shrink=0.8, label="stat_matched degradation")
    fig.suptitle("TCP degradation by R/L/T/payload")
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_success_level(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot success levels in similarity/degradation space."""
    fig, axis = plt.subplots(figsize=(10, 6), constrained_layout=True)
    if frame.empty:
        axis.text(0.5, 0.5, "No tradeoff rows", ha="center", va="center")
        axis.set_axis_off()
    else:
        colors = {
            "no_success": "#9aa0a6",
            "weak_success": "#f58518",
            "moderate_success": "#54a24b",
            "strong_success": "#e45756",
        }
        for level, group in frame.groupby("success_level"):
            axis.scatter(
                group["mean_feature_relative_diff"],
                group["stat_matched_degradation"],
                label=level,
                color=colors.get(level, "#4c78a8"),
                s=75,
                alpha=0.82,
            )
        axis.axvline(0.20, color="black", linestyle="--", linewidth=1)
        for y in (0.20, 0.30, 0.50):
            axis.axhline(y, color="gray", linestyle=":", linewidth=1)
        axis.set_xlabel("mean feature relative diff")
        axis.set_ylabel("stat_matched degradation")
        axis.set_title("Success level classification")
        axis.grid(alpha=0.25)
        axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def build_tradeoff_summary(frame: pd.DataFrame, pareto: pd.DataFrame, top: pd.DataFrame) -> str:
    """Build tradeoff_summary.md."""
    total = len(frame)
    degradation_max = row_text(frame.sort_values("stat_matched_degradation", ascending=False).head(1))
    similarity_best = row_text(frame.sort_values("mean_feature_relative_diff", ascending=True).head(1))
    success_counts = frame["success_level"].value_counts().to_dict() if not frame.empty else {}
    random_degradation = float(frame["random_microburst_degradation"].mean()) if not frame.empty else 0.0
    rows = [
        [level, str(int(success_counts.get(level, 0)))]
        for level in ["strong_success", "moderate_success", "weak_success", "no_success"]
    ]
    lines = [
        "# Tradeoff summary",
        "",
        "## Purpose",
        "",
        "This experiment visualizes the tradeoff between stat-matched four-feature similarity and TCP throughput degradation.",
        "",
        "## Axes",
        "",
        "- stat-matchedness: lower feature relative difference is better.",
        "- attack effect: higher TCP throughput degradation is stronger.",
        "- In the main scatter plots, points closer to the upper-left are better.",
        "",
        f"- total conditions: {total}",
        f"- max degradation condition: {degradation_max}",
        f"- best feature similarity condition: {similarity_best}",
        f"- mean random_microburst_only degradation: {random_degradation:.3f}",
        "",
        "## Success counts",
        "",
        markdown_table(["success_level", "count"], rows),
        "",
        "## Pareto optimal conditions",
        "",
        pareto_table(pareto),
        "",
        "## Notes",
        "",
        "- This is Mininet packet traffic plus offline Python detector evaluation, not XDP/eBPF in-kernel evaluation.",
        "- Goertzel/frequency metrics are analysis outputs only and are not fed to the detector.",
        "- The detector remains the four-feature EMA dynamic-threshold suspicious-score logic.",
    ]
    if not any(success_counts.get(level, 0) for level in ["weak_success", "moderate_success", "strong_success"]):
        lines.extend(
            [
                "",
                "## Bottleneck",
                "",
                bottleneck_text(frame),
            ]
        )
    return "\n".join(lines) + "\n"


def build_final_claim_evaluation(frame: pd.DataFrame, pareto: pd.DataFrame, top: pd.DataFrame) -> str:
    """Build final_claim_evaluation.md."""
    success = frame[frame["success_level"].isin(["weak_success", "moderate_success", "strong_success"])] if not frame.empty else frame
    if not success.empty:
        best = success.sort_values(["success_level", "stat_matched_degradation"], ascending=[True, False]).iloc[0]
        verdict = "The claim is supported for at least one configured condition."
        detail = [
            f"- condition: {best['condition_id']}",
            f"- R/L/T/payload: {best['attack_rate_mbps']} Mbps / {best['burst_ms']} ms / {best['period_ms']} ms / {best['payload_size']} bytes",
            f"- stat_matched_degradation: {best['stat_matched_degradation']:.3f}",
            f"- stat_matched_FNR: {best['stat_matched_FNR']:.3f}",
            f"- mean_feature_relative_diff: {best['mean_feature_relative_diff']:.3f}",
            f"- max_feature_relative_diff: {best['max_feature_relative_diff']:.3f}",
            f"- random_microburst_degradation: {best['random_microburst_degradation']:.3f}",
        ]
    elif not top.empty:
        best = top.iloc[0]
        verdict = "The configured success thresholds were not met; the closest condition is reported below."
        detail = [
            f"- closest condition: {best['condition_id']}",
            f"- R/L/T/payload: {best['attack_rate_mbps']} Mbps / {best['burst_ms']} ms / {best['period_ms']} ms / {best['payload_size']} bytes",
            f"- stat_matched_degradation: {best['stat_matched_degradation']:.3f}",
            f"- stat_matched_FNR: {best['stat_matched_FNR']:.3f}",
            f"- mean_feature_relative_diff: {best['mean_feature_relative_diff']:.3f}",
            f"- max_feature_relative_diff: {best['max_feature_relative_diff']:.3f}",
            "- next step: widen R/L/T/payload grid or improve stat-matched random microburst construction.",
        ]
    else:
        verdict = "No completed conditions were available."
        detail = ["- no candidate rows"]
    lines = [
        "# Final claim evaluation",
        "",
        "## Claim",
        "",
        "正常マイクロバーストと窓内統計特徴量が類似するLDoSは、検知を回避しつつTCPスループットを低下させる。",
        "",
        "## Verdict",
        "",
        verdict,
        "",
        "## Candidate",
        "",
        *detail,
        "",
        "## Research caveats",
        "",
        "- XDP/eBPF上では未検証であり、Mininet上のパケット列 + offline Python detector評価である。",
        "- detectorにはGoertzel、Sliding DFT、周期性特徴を入れていない。",
    ]
    return "\n".join(lines) + "\n"


def relative_diff(a: float, b: float) -> float:
    """Compute stable relative difference."""
    denom = max(abs(a), abs(b), 1e-12)
    return float(abs(a - b) / denom)


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide with zero handling."""
    return 0.0 if abs(denominator) < 1e-12 else float(numerator / denominator)


def select_row(frame: pd.DataFrame, scenario: str) -> dict[str, Any]:
    """Return first row for a scenario as dict."""
    if frame.empty or "scenario" not in frame.columns:
        return {}
    row = frame[frame["scenario"] == scenario]
    return row.iloc[0].to_dict() if not row.empty else {}


def label_for(row: pd.Series | dict[str, Any]) -> str:
    """Return compact R/L/T/payload label."""
    return f"R{row['attack_rate_mbps']:g}/L{int(row['burst_ms'])}/T{int(row['period_ms'])}/p{int(row['payload_size'])}"


def row_text(frame: pd.DataFrame) -> str:
    """Return one-row condition text."""
    if frame.empty:
        return "none"
    row = frame.iloc[0]
    return (
        f"{row['condition_id']} ({label_for(row)}), "
        f"degradation={row['stat_matched_degradation']:.3f}, "
        f"mean_diff={row['mean_feature_relative_diff']:.3f}, FNR={row['stat_matched_FNR']:.3f}"
    )


def pareto_table(pareto: pd.DataFrame) -> str:
    """Return Markdown table for Pareto rows."""
    if pareto.empty:
        return "No Pareto rows."
    rows = []
    for _, row in pareto.head(20).iterrows():
        rows.append(
            [
                row["condition_id"],
                label_for(row),
                f"{row['mean_feature_relative_diff']:.3f}",
                f"{row['stat_matched_degradation']:.3f}",
                f"{row['stat_matched_FNR']:.3f}",
                row["success_level"],
            ]
        )
    return markdown_table(["condition", "R/L/T/payload", "mean diff", "degradation", "FNR", "success"], rows)


def bottleneck_text(frame: pd.DataFrame) -> str:
    """Explain likely bottleneck when no success exists."""
    if frame.empty:
        return "No completed conditions."
    close = frame.copy()
    attack_ok = int((close["stat_matched_degradation"] >= 0.20).sum())
    similarity_ok = int(((close["mean_feature_relative_diff"] <= 0.20) & (close["max_feature_relative_diff"] <= 0.30)).sum())
    fnr_ok = int((close["stat_matched_FNR"] >= 0.70).sum())
    return (
        f"Conditions meeting attack-effect threshold: {attack_ok}. "
        f"Conditions meeting similarity thresholds: {similarity_ok}. "
        f"Conditions meeting FNR threshold: {fnr_ok}. "
        "The smallest of these counts indicates the current bottleneck."
    )
