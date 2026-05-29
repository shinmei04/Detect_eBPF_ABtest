"""Run the four-feature paper-reproduction detector experiment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from src.packet_model import generate_packets_from_buckets
from src.paper_reproduction_detector import (
    PAPER_FEATURES,
    PAPER_SOURCE_README,
    PAPER_SOURCE_REPOSITORY,
    PAPER_SOURCE_XDP,
    PaperDetectorConfig,
    compute_paper_window_features,
    run_paper_detector_by_seed,
)
from src.pattern_generator import generate_periodic_ldos_buckets, generate_random_microburst_buckets
from src.utils import count_buckets_for_duration, ensure_dir, markdown_table


DEFAULT_SEEDS = [1, 2, 3, 4, 5, 10, 20, 30, 40, 50]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run paper-style four-feature detector reproduction.")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--period-ms", type=int, default=1000)
    parser.add_argument("--burst-ms", type=int, default=200)
    parser.add_argument("--burst-pkts-per-bucket", type=int, default=10)
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--seeds", type=int, nargs="+", default=DEFAULT_SEEDS)
    parser.add_argument("--warmup-windows", type=int, default=20)
    parser.add_argument("--score-threshold", type=int, default=2)
    parser.add_argument("--min-packets-for-detection", type=int, default=10)
    parser.add_argument("--output-dir", type=Path, default=Path("results_paper_reproduction"))
    return parser.parse_args()


def main() -> None:
    """Run data generation, paper detector prediction, evaluation, and summaries."""
    args = parse_args()
    output_dir = ensure_dir(args.output_dir)
    detector_config = PaperDetectorConfig(
        warmup_windows=args.warmup_windows,
        min_packets_for_detection=args.min_packets_for_detection,
        suspicious_threshold=args.score_threshold,
        use_observed_initial_state=True,
    )

    datasets = {
        "original_like": build_reproduction_dataset(args, "original_like"),
        "stat_matched": build_reproduction_dataset(args, "stat_matched"),
    }

    metrics_by_dataset: dict[str, dict[str, Any]] = {}
    predictions_by_dataset: dict[str, pd.DataFrame] = {}
    for dataset_name, dataset in datasets.items():
        dataset.to_csv(output_dir / f"dataset_{dataset_name}.csv", index=False)
        predictions = run_paper_detector_by_seed(dataset, detector_config)
        predictions_by_dataset[dataset_name] = predictions
        predictions.to_csv(output_dir / f"predictions_{dataset_name}.csv", index=False)
        metrics = evaluate_detector_predictions(predictions, args.duration_sec)
        metrics_by_dataset[dataset_name] = metrics
        write_json(metrics, output_dir / f"metrics_{dataset_name}.json")
        plot_confusion_matrix(metrics, dataset_name, output_dir / f"confusion_matrix_{dataset_name}.png")

    comparison = build_metrics_comparison(metrics_by_dataset)
    comparison.to_csv(output_dir / "metrics_comparison.csv", index=False)
    plot_metrics_comparison(comparison, output_dir / "metrics_comparison.png")
    summary = build_summary(args, metrics_by_dataset, datasets)
    (output_dir / "detector_reproduction_summary.md").write_text(summary, encoding="utf-8")

    print(f"Wrote paper reproduction results to {output_dir.resolve()}")
    for dataset_name, metrics in metrics_by_dataset.items():
        print(
            f"{dataset_name}: F1={metrics['f1_score']:.6g}, "
            f"FPR={metrics['false_positive_rate']:.6g}, FNR={metrics['false_negative_rate']:.6g}"
        )


def build_reproduction_dataset(args: argparse.Namespace, dataset_name: str) -> pd.DataFrame:
    """Build a benign-then-attack stream dataset for one condition."""
    frames: list[pd.DataFrame] = []
    for seed in args.seeds:
        benign_scenario = "benign_regular" if dataset_name == "original_like" else "random_microburst"
        benign = generate_scenario_windows(args, seed, dataset_name, benign_scenario, stream_offset_sec=0.0)
        attack = generate_scenario_windows(
            args,
            seed,
            dataset_name,
            "periodic_ldos",
            stream_offset_sec=args.duration_sec,
        )
        stream_id = f"{dataset_name}_seed_{seed}"
        benign["stream_id"] = stream_id
        attack["stream_id"] = stream_id
        benign["attack_start_sec"] = args.duration_sec
        attack["attack_start_sec"] = args.duration_sec
        frames.extend([benign, attack])
    dataset = pd.concat(frames, ignore_index=True)
    return dataset.sort_values(["dataset", "seed", "stream_id", "stream_time_sec"], kind="mergesort").reset_index(
        drop=True
    )


def generate_scenario_windows(
    args: argparse.Namespace,
    seed: int,
    dataset_name: str,
    scenario: str,
    stream_offset_sec: float,
) -> pd.DataFrame:
    """Generate paper-feature windows for one scenario."""
    label = "attack" if scenario == "periodic_ldos" else "benign"
    if scenario == "periodic_ldos":
        buckets = generate_periodic_ldos_buckets(
            duration_sec=args.duration_sec,
            bucket_ms=args.bucket_ms,
            period_ms=args.period_ms,
            burst_ms=args.burst_ms,
            burst_pkts_per_bucket=args.burst_pkts_per_bucket,
        )
        packets = generate_packets_from_buckets(buckets, args.bucket_ms, payload_size_jitter=0, seed=seed)
    elif scenario == "random_microburst":
        buckets = generate_random_microburst_buckets(
            duration_sec=args.duration_sec,
            bucket_ms=args.bucket_ms,
            period_ms=args.period_ms,
            burst_ms=args.burst_ms,
            burst_pkts_per_bucket=args.burst_pkts_per_bucket,
            seed=seed,
        )
        packets = generate_packets_from_buckets(buckets, args.bucket_ms, payload_size_jitter=0, seed=seed)
    elif scenario == "benign_regular":
        buckets = generate_benign_regular_buckets(args.duration_sec, args.bucket_ms)
        packets = generate_packets_from_buckets(buckets, args.bucket_ms, payload_size_jitter=0, seed=seed)
        packets = assign_regular_benign_payload_pattern(packets)
    else:
        raise ValueError(f"unknown scenario: {scenario}")

    features = compute_paper_window_features(
        packets=packets,
        buckets=buckets,
        bucket_ms=args.bucket_ms,
        window_sec=args.window_sec,
        step_sec=args.step_sec,
        label=label,
    )
    features.insert(0, "dataset", dataset_name)
    features.insert(1, "seed", seed)
    features.insert(2, "scenario", scenario)
    features["stream_time_sec"] = features["window_start_sec"] + stream_offset_sec
    features["stream_window_end_sec"] = features["window_end_sec"] + stream_offset_sec
    features["target"] = (features["label"] == "attack").astype(int)
    return features


def generate_benign_regular_buckets(duration_sec: float, bucket_ms: int) -> list[int]:
    """Generate stable low-rate benign traffic that is not stat-matched to LDoS."""
    total_buckets = count_buckets_for_duration(duration_sec, bucket_ms)
    return [1 if bucket_index % 2 == 0 else 0 for bucket_index in range(total_buckets)]


def assign_regular_benign_payload_pattern(packets: pd.DataFrame) -> pd.DataFrame:
    """Assign a stable alternating payload pattern to ordinary benign traffic."""
    output = packets.copy()
    if output.empty:
        return output
    packet_index = np.arange(len(output))
    output["packet_size"] = np.where(packet_index % 2 == 0, 40, 120)
    return output


def evaluate_detector_predictions(predictions: pd.DataFrame, duration_sec: float) -> dict[str, Any]:
    """Compute classification metrics and detection delay."""
    evaluated = predictions[~predictions["is_warmup"].astype(bool)].copy()
    y_true = evaluated["true_attack"].astype(bool)
    y_pred = evaluated["pred_attack"].astype(bool)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[False, True]).ravel()
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)
    fpr = safe_divide(fp, fp + tn)
    fnr = safe_divide(fn, fn + tp)
    delays = detection_delays(predictions, duration_sec)
    valid_delays = [item["detection_delay_sec"] for item in delays if item["detection_delay_sec"] is not None]

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "false_positive_rate": float(fpr),
        "false_negative_rate": float(fnr),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "evaluated_windows": int(len(evaluated)),
        "total_windows": int(len(predictions)),
        "detection_delays": delays,
        "mean_detection_delay_sec": float(np.mean(valid_delays)) if valid_delays else None,
        "missed_attack_seed_count": int(sum(item["detection_delay_sec"] is None for item in delays)),
    }


def detection_delays(predictions: pd.DataFrame, duration_sec: float) -> list[dict[str, Any]]:
    """Return first detection delay per seed from attack stream start."""
    delays: list[dict[str, Any]] = []
    attack_rows = predictions[predictions["true_attack"].astype(bool) & ~predictions["is_warmup"].astype(bool)]
    for (seed, stream_id), seed_rows in attack_rows.groupby(["seed", "stream_id"], sort=True):
        attack_start_sec = float(seed_rows["attack_start_sec"].iloc[0])
        detected = seed_rows[seed_rows["pred_attack"].astype(bool)]
        if detected.empty:
            delay = None
            first_window_after_attack = None
        else:
            first = detected.iloc[0]
            delay = max(0.0, float(first["stream_window_end_sec"]) - attack_start_sec)
            first_window_after_attack = int(round((float(first["stream_time_sec"]) - attack_start_sec) + 1))
        delays.append(
            {
                "seed": int(seed),
                "stream_id": stream_id,
                "detection_delay_sec": delay,
                "detection_window_after_attack": first_window_after_attack,
                "fallback_duration_sec": float(duration_sec) if delay is None else None,
            }
        )
    return delays


def build_metrics_comparison(metrics_by_dataset: dict[str, dict[str, Any]]) -> pd.DataFrame:
    """Build original-like vs stat-matched comparison rows."""
    rows = []
    metric_names = [
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "false_positive_rate",
        "false_negative_rate",
        "mean_detection_delay_sec",
    ]
    original = metrics_by_dataset["original_like"]
    stat = metrics_by_dataset["stat_matched"]
    for metric in metric_names:
        original_value = original[metric]
        stat_value = stat[metric]
        if original_value is None or stat_value is None:
            delta = None
        else:
            delta = float(stat_value) - float(original_value)
        rows.append(
            {
                "metric": metric,
                "original_like": original_value,
                "stat_matched": stat_value,
                "stat_minus_original": delta,
            }
        )
    return pd.DataFrame(rows)


def plot_confusion_matrix(metrics: dict[str, Any], dataset_name: str, output_path: Path) -> None:
    """Save a confusion matrix PNG."""
    cm = metrics["confusion_matrix"]
    matrix = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]], dtype=int)
    fig, axis = plt.subplots(figsize=(4.8, 4.2), constrained_layout=True)
    image = axis.imshow(matrix, cmap="Blues")
    axis.set_xticks([0, 1], ["pred benign", "pred attack"])
    axis.set_yticks([0, 1], ["true benign", "true attack"])
    axis.set_title(f"{dataset_name} confusion matrix")
    for row in range(2):
        for column in range(2):
            axis.text(column, row, str(matrix[row, column]), ha="center", va="center", color="black")
    fig.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def plot_metrics_comparison(comparison: pd.DataFrame, output_path: Path) -> None:
    """Save metric comparison chart."""
    selected = comparison[comparison["metric"].isin(["f1_score", "false_positive_rate", "false_negative_rate"])]
    x = np.arange(len(selected))
    width = 0.38
    fig, axis = plt.subplots(figsize=(8.8, 4.4), constrained_layout=True)
    axis.bar(x - width / 2, selected["original_like"].fillna(0), width, label="original_like", color="#4c78a8")
    axis.bar(x + width / 2, selected["stat_matched"].fillna(0), width, label="stat_matched", color="#f58518")
    axis.set_xticks(x)
    axis.set_xticklabels(selected["metric"], rotation=15)
    axis.set_ylim(0.0, 1.05)
    axis.set_title("Paper reproduction detector metrics")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def build_summary(
    args: argparse.Namespace,
    metrics_by_dataset: dict[str, dict[str, Any]],
    datasets: dict[str, pd.DataFrame],
) -> str:
    """Build detector_reproduction_summary.md."""
    original = metrics_by_dataset["original_like"]
    stat = metrics_by_dataset["stat_matched"]
    comparison = build_metrics_comparison(metrics_by_dataset)
    feature_rows = feature_similarity_rows(datasets["stat_matched"])
    metric_rows = [
        [
            row["metric"],
            format_optional(row["original_like"]),
            format_optional(row["stat_matched"]),
            format_optional(row["stat_minus_original"]),
        ]
        for _, row in comparison.iterrows()
    ]

    lines = [
        "# Paper reproduction detector summary",
        "",
        "## 実験目的",
        "",
        "元論文GitHubリポジトリのREADMEとxdp_prog.cを参考に、4統計特徴量 + EMA dynamic threshold + suspicious scoreのrule-based detectorをPython上で再現し、original_like条件とstat_matched条件で検知性能を比較した。",
        "",
        "## 参照元",
        "",
        f"- Repository: {PAPER_SOURCE_REPOSITORY}",
        f"- xdp_prog.c: {PAPER_SOURCE_XDP}",
        f"- README: {PAPER_SOURCE_README}",
        "",
        "READMEでは4特徴量、EMAベースの動的閾値、score >= 2でdropする検知ワークフローが説明されている。xdp_prog.cではfeature_config、上下方向付きthreshold、warmup、疑わしい特徴ではEMA更新を止める処理、suspicious_count >= 2でXDP_DROPへ進む処理を確認した。",
        "",
        "## 注意",
        "",
        "これは完全な元論文再現ではない。eBPF/XDP、Mininet、実パケット送信は使わず、人工bucket列から抽出したwindow特徴量に対して検知ロジックだけをPythonで再現した追加評価である。",
        "",
        "## 使用特徴量",
        "",
        "- iat_variance",
        "- burst_rate",
        "- payload_size_variance",
        "- new_flow_arrival_rate",
        "",
        "Goertzel法やSliding DFTなどの周波数特徴は今回使っていない。",
        "",
        "## 実験条件",
        "",
        f"- seeds: {', '.join(str(seed) for seed in args.seeds)}",
        f"- duration per benign/attack segment: {args.duration_sec} sec",
        f"- bucket_ms: {args.bucket_ms}",
        f"- window_sec: {args.window_sec}, step_sec: {args.step_sec}",
        f"- warmup_windows: {args.warmup_windows}",
        f"- suspicious score threshold: {args.score_threshold}",
        "",
        "## Metrics comparison",
        "",
        markdown_table(["metric", "original_like", "stat_matched", "stat_minus_original"], metric_rows),
        "",
        "## Stat-matched feature similarity",
        "",
        markdown_table(["feature", "attack mean", "benign mean", "relative diff"], feature_rows),
        "",
        "## 解釈",
        "",
        interpretation(original, stat),
        "",
        "original_likeで高性能かつstat_matchedで性能低下が出れば、既存4特徴量ベース検知器はstat-matched A/B条件で弱くなる可能性がある。性能差が出ない場合は、この人工条件では既存4特徴量だけでも十分強いという結果として扱う。",
        "",
        "次の段階では、今回使わなかったGoertzel/Sliding DFTなどの周期性特徴を追加し、stat_matched条件でF1、FNR、detection delayが改善するか評価する。",
        "",
    ]
    return "\n".join(lines)


def feature_similarity_rows(dataset: pd.DataFrame) -> list[list[str]]:
    """Summarize attack/benign feature similarity for stat-matched data."""
    rows = []
    for feature in PAPER_FEATURES:
        attack_mean = float(dataset.loc[dataset["label"] == "attack", feature].mean())
        benign_mean = float(dataset.loc[dataset["label"] == "benign", feature].mean())
        rows.append(
            [
                feature,
                f"{attack_mean:.6g}",
                f"{benign_mean:.6g}",
                f"{relative_diff(attack_mean, benign_mean):.6g}",
            ]
        )
    return rows


def interpretation(original: dict[str, Any], stat: dict[str, Any]) -> str:
    """Return a concise Japanese interpretation paragraph."""
    f1_drop = stat["f1_score"] - original["f1_score"]
    fpr_increase = stat["false_positive_rate"] - original["false_positive_rate"]
    fnr_increase = stat["false_negative_rate"] - original["false_negative_rate"]
    if f1_drop < 0 or fpr_increase > 0 or fnr_increase > 0:
        return (
            f"original_likeからstat_matchedに変えると、F1差分={f1_drop:.6g}, "
            f"FPR差分={fpr_increase:.6g}, FNR差分={fnr_increase:.6g} だった。"
            "少なくとも一部指標で性能低下または誤判定増加が確認できる。"
        )
    return (
        f"original_likeからstat_matchedに変えても、F1差分={f1_drop:.6g}, "
        f"FPR差分={fpr_increase:.6g}, FNR差分={fnr_increase:.6g} であり、"
        "今回の条件では既存4特徴量ベースのrule detectorは大きく崩れなかった。"
    )


def write_json(data: dict[str, Any], output_path: Path) -> None:
    """Write JSON with stable NaN handling."""
    output_path.write_text(json.dumps(data, indent=2, allow_nan=False), encoding="utf-8")


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide with zero handling."""
    if denominator == 0:
        return 0.0
    return float(numerator / denominator)


def relative_diff(reference: float, candidate: float) -> float:
    """Compute an absolute relative difference."""
    denominator = max(abs(reference), 1e-12)
    return abs(candidate - reference) / denominator


def format_optional(value: Any) -> str:
    """Format metric values for Markdown."""
    if value is None:
        return "None"
    if isinstance(value, float):
        if np.isnan(value):
            return "None"
        return f"{value:.6g}"
    return str(value)


if __name__ == "__main__":
    main()
