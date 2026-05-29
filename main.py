"""CLI entry point for the phase-1 stat-matched LDoS simulation."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from src.evaluate_similarity import (
    PRIMARY_STAT_FEATURES,
    build_similarity_table,
)
from src.features import compute_window_features
from src.goertzel import compute_frequency_features
from src.packet_model import generate_packets_from_buckets
from src.pattern_generator import (
    generate_periodic_ldos_buckets,
    generate_random_microburst_buckets,
)
from src.plots import (
    plot_bucket_timeseries,
    plot_feature_distance_summary,
    plot_frequency_features_comparison,
    plot_stat_features_comparison,
)
from src.utils import ensure_dir, markdown_table, save_buckets_csv


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate stat-matched periodic LDoS and random microburst bucket series."
    )
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--period-ms", type=int, default=1000)
    parser.add_argument("--burst-ms", type=int, default=200)
    parser.add_argument("--burst-pkts-per-bucket", type=int, default=10)
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    return parser.parse_args()


def main() -> None:
    """Run the full generation, feature extraction, evaluation, and plotting flow."""
    args = parse_args()
    output_dir = ensure_dir(args.output_dir)

    periodic_buckets = generate_periodic_ldos_buckets(
        duration_sec=args.duration_sec,
        bucket_ms=args.bucket_ms,
        period_ms=args.period_ms,
        burst_ms=args.burst_ms,
        burst_pkts_per_bucket=args.burst_pkts_per_bucket,
    )
    microburst_buckets = generate_random_microburst_buckets(
        duration_sec=args.duration_sec,
        bucket_ms=args.bucket_ms,
        period_ms=args.period_ms,
        burst_ms=args.burst_ms,
        burst_pkts_per_bucket=args.burst_pkts_per_bucket,
        seed=args.seed,
    )

    save_buckets_csv(periodic_buckets, args.bucket_ms, output_dir / "periodic_ldos_buckets.csv")
    save_buckets_csv(microburst_buckets, args.bucket_ms, output_dir / "random_microburst_buckets.csv")

    periodic_packets = generate_packets_from_buckets(
        periodic_buckets,
        bucket_ms=args.bucket_ms,
        payload_size_mean=80,
        payload_size_jitter=0,
        flow_mode="same_flow",
        seed=args.seed,
    )
    microburst_packets = generate_packets_from_buckets(
        microburst_buckets,
        bucket_ms=args.bucket_ms,
        payload_size_mean=80,
        payload_size_jitter=0,
        flow_mode="same_flow",
        seed=args.seed,
    )

    periodic_features = _compute_all_features(
        periodic_packets,
        periodic_buckets,
        args.bucket_ms,
        args.window_sec,
        args.step_sec,
        label="attack",
    )
    microburst_features = _compute_all_features(
        microburst_packets,
        microburst_buckets,
        args.bucket_ms,
        args.window_sec,
        args.step_sec,
        label="benign",
    )

    periodic_features.to_csv(output_dir / "features_periodic_ldos.csv", index=False)
    microburst_features.to_csv(output_dir / "features_random_microburst.csv", index=False)

    similarity_table = build_similarity_table(periodic_features, microburst_features)
    similarity_table.to_csv(output_dir / "feature_similarity.csv", index=False)

    plot_bucket_timeseries(
        periodic_buckets,
        microburst_buckets,
        args.bucket_ms,
        output_dir / "bucket_timeseries_example.png",
    )
    plot_stat_features_comparison(
        periodic_features,
        microburst_features,
        output_dir / "stat_features_comparison.png",
    )
    plot_frequency_features_comparison(
        periodic_features,
        microburst_features,
        output_dir / "frequency_features_comparison.png",
    )
    plot_feature_distance_summary(similarity_table, output_dir / "feature_distance_summary.png")

    summary_text = build_summary(
        args,
        periodic_buckets,
        microburst_buckets,
        similarity_table,
    )
    (output_dir / "summary.md").write_text(summary_text, encoding="utf-8")

    print(f"Wrote results to {output_dir.resolve()}")
    print(f"periodic_ldos total packets: {sum(periodic_buckets)}")
    print(f"random_microburst total packets: {sum(microburst_buckets)}")


def _compute_all_features(
    packets: pd.DataFrame,
    buckets: list[int],
    bucket_ms: int,
    window_sec: float,
    step_sec: float,
    label: str,
) -> pd.DataFrame:
    """Compute statistical and frequency features and merge them by window."""
    stat_features = compute_window_features(
        packets=packets,
        buckets=buckets,
        bucket_ms=bucket_ms,
        window_sec=window_sec,
        step_sec=step_sec,
        label=label,
    )
    frequency_features = compute_frequency_features(
        buckets=buckets,
        bucket_ms=bucket_ms,
        window_sec=window_sec,
        step_sec=step_sec,
    )
    return stat_features.merge(
        frequency_features,
        on=["window_index", "window_start_sec", "window_end_sec"],
        how="left",
    )


def build_summary(
    args: argparse.Namespace,
    periodic_buckets: list[int],
    microburst_buckets: list[int],
    similarity_table: pd.DataFrame,
) -> str:
    """Build the Japanese Markdown summary for the generated experiment."""
    stat_rows = _summary_rows(similarity_table, PRIMARY_STAT_FEATURES)
    frequency_rows = _summary_rows(
        similarity_table,
        ["normalized_1hz_power", "normalized_rto_band_power"],
    )

    periodic_total = sum(periodic_buckets)
    microburst_total = sum(microburst_buckets)
    periodic_burst_buckets = sum(1 for value in periodic_buckets if value > 0)
    microburst_burst_buckets = sum(1 for value in microburst_buckets if value > 0)

    normalized_1hz = similarity_table[similarity_table["feature"] == "normalized_1hz_power"].iloc[0]

    lines = [
        "# Phase 1 summary",
        "",
        "## 実験条件",
        "",
        f"- duration: {args.duration_sec} sec",
        f"- bucket width: {args.bucket_ms} ms",
        f"- LDoS period: {args.period_ms} ms",
        f"- burst length: {args.burst_ms} ms",
        f"- burst packets per bucket: {args.burst_pkts_per_bucket}",
        f"- window: {args.window_sec} sec, step: {args.step_sec} sec",
        f"- seed: {args.seed}",
        "",
        "## 生成方法",
        "",
        "- periodic_ldos: 各1秒周期の先頭200msに10 packets/bucketを置き、それ以外を0にした。",
        "- random_microburst: 総パケット数、burst bucket数、最大bucket count、payload分布、flow modeをperiodic_ldosと一致させたまま、burst phaseをseed付きでランダム化した。",
        "- random_microburstでは、同じphaseに周期的にburstが固定されにくい候補を選び、1Hz成分が出にくいbucket列にした。",
        "",
        "## Bucket-level checks",
        "",
        markdown_table(
            ["item", "periodic_ldos", "random_microburst"],
            [
                ["total packets", str(periodic_total), str(microburst_total)],
                ["burst buckets", str(periodic_burst_buckets), str(microburst_burst_buckets)],
                ["max bucket count", str(max(periodic_buckets)), str(max(microburst_buckets))],
            ],
        ),
        "",
        "## 既存4特徴量の類似性",
        "",
        markdown_table(
            ["feature", "periodic mean", "microburst mean", "relative diff"],
            stat_rows,
        ),
        "",
        "## 周波数特徴量の差",
        "",
        markdown_table(
            ["feature", "periodic mean", "microburst mean", "relative diff"],
            frequency_rows,
        ),
        "",
        "## 解釈",
        "",
        f"- normalized_1hz_power meanはperiodic_ldos={normalized_1hz['periodic_ldos_mean']:.6g}, random_microburst={normalized_1hz['random_microburst_mean']:.6g}だった。",
        "- payload size varianceとnew flow arrival rateは、payloadとflow modeを同一にしたため一致しやすい。",
        "- burst_rate、総パケット数、bucket分散はbucket列の二値分布を合わせているため近くなる。",
        "- 一方で、periodic_ldosは1秒周期のcoherentなburst構造を持つため、Goertzel法の1Hz特徴で差が出る。",
        "",
        "## 注意",
        "",
        "これは元論文や実eBPF/XDP detectorの完全再現ではない。Phase 1として、元論文型の軽量な窓内統計特徴量が似る条件を人工bucket列で作り、周期性だけを別特徴として観測できるかを確認する実験である。",
        "",
    ]
    return "\n".join(lines)


def _summary_rows(similarity_table: pd.DataFrame, feature_names: list[str]) -> list[list[str]]:
    """Return formatted rows for summary tables."""
    rows = []
    for feature in feature_names:
        row = similarity_table[similarity_table["feature"] == feature].iloc[0]
        rows.append(
            [
                feature,
                f"{row['periodic_ldos_mean']:.6g}",
                f"{row['random_microburst_mean']:.6g}",
                f"{row['relative_difference']:.6g}",
            ]
        )
    return rows


if __name__ == "__main__":
    main()
