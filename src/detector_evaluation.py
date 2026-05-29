"""Evaluation and plotting helpers for paper-like detector experiments."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .paper_like_detector import BASELINE_FEATURES, FREQUENCY_ENHANCED_FEATURES
from .utils import ensure_dir, markdown_table


def evaluate_predictions(predictions: pd.DataFrame, duration_sec: float) -> dict[str, Any]:
    """Compute binary metrics and per-seed detection delays."""
    required = {"is_evaluated", "true_attack", "pred_attack", "seed", "scenario", "window_start_sec"}
    missing = required.difference(predictions.columns)
    if missing:
        raise ValueError(f"predictions is missing required columns: {sorted(missing)}")

    metric_include = (
        predictions["metric_include"].astype(bool)
        if "metric_include" in predictions.columns
        else pd.Series(True, index=predictions.index)
    )
    evaluated = predictions[predictions["is_evaluated"].astype(bool) & metric_include].copy()
    y_true = evaluated["true_attack"].astype(bool)
    y_pred = evaluated["pred_attack"].astype(bool)

    tp = int((y_true & y_pred).sum())
    tn = int((~y_true & ~y_pred).sum())
    fp = int((~y_true & y_pred).sum())
    fn = int((y_true & ~y_pred).sum())

    accuracy = _safe_divide(tp + tn, tp + tn + fp + fn)
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1_score = _safe_divide(2.0 * precision * recall, precision + recall)
    false_positive_rate = _safe_divide(fp, fp + tn)
    false_negative_rate = _safe_divide(fn, fn + tp)

    delays = _detection_delays(predictions, duration_sec)
    valid_delays = [item["detection_delay_sec"] for item in delays if item["detection_delay_sec"] is not None]
    valid_windows = [
        item["detection_window_after_attack"] for item in delays if item["detection_window_after_attack"] is not None
    ]
    adaptation = _ema_adaptation_summary(predictions)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "evaluated_windows": int(len(evaluated)),
        "total_windows": int(len(predictions)),
        "detection_delays": delays,
        "mean_detection_delay_sec": float(np.mean(valid_delays)) if valid_delays else None,
        "mean_detection_window_after_attack": float(np.mean(valid_windows)) if valid_windows else None,
        "missed_attack_seed_count": int(sum(item["detection_delay_sec"] is None for item in delays)),
        "ema_adaptation": adaptation,
    }


def write_metrics_json(metrics: dict[str, Any], output_path: str | Path) -> None:
    """Write metrics as readable JSON."""
    Path(output_path).write_text(json.dumps(metrics, indent=2, allow_nan=False), encoding="utf-8")


def write_detector_summary(
    output_dir: str | Path,
    seeds: list[int],
    baseline_metrics: dict[str, Any],
    frequency_metrics: dict[str, Any],
    use_warmup: bool,
    warmup_windows: int,
) -> None:
    """Write detector_summary.md."""
    output_path = ensure_dir(output_dir)
    baseline_rows = _metric_rows(baseline_metrics)
    frequency_rows = _metric_rows(frequency_metrics)
    improved = _improvement_sentence(baseline_metrics, frequency_metrics)
    baseline_fpr = baseline_metrics["false_positive_rate"]
    baseline_fnr = baseline_metrics["false_negative_rate"]
    frequency_fpr = frequency_metrics["false_positive_rate"]
    frequency_fnr = frequency_metrics["false_negative_rate"]

    lines = [
        "# Phase 2 detector summary",
        "",
        "## 実験目的",
        "",
        "stat-matchedなperiodic_ldosとrandom_microburstに対して、既存4特徴量のみのpaper-like detectorと、Goertzel周波数特徴を追加したdetectorを比較する。",
        "",
        "## 注意",
        "",
        "このdetectorは元論文の完全再現ではない。既存eBPF/XDP論文の特徴量設計に基づく、4特徴量 + EMA動的閾値 + suspicious scoreの簡易baselineである。",
        "",
        "## 使用特徴量",
        "",
        f"- Baseline: {', '.join(BASELINE_FEATURES)}",
        f"- Frequency-enhanced: {', '.join(FREQUENCY_ENHANCED_FEATURES)}",
        f"- EMA warmup: {'enabled' if use_warmup else 'disabled'}, warmup_windows={warmup_windows}",
        "",
        "## Seed一覧",
        "",
        ", ".join(str(seed) for seed in seeds),
        "",
        "## Baseline結果",
        "",
        markdown_table(["metric", "value"], baseline_rows),
        "",
        "## Frequency-enhanced結果",
        "",
        markdown_table(["metric", "value"], frequency_rows),
        "",
        "## 誤判定と見逃し",
        "",
        f"- Baselineでrandom_microburstをattackと誤判定した割合: {baseline_fpr:.6g}",
        f"- Baselineでperiodic_ldosを見逃した割合: {baseline_fnr:.6g}",
        f"- Frequency-enhancedでrandom_microburstをattackと誤判定した割合: {frequency_fpr:.6g}",
        f"- Frequency-enhancedでperiodic_ldosを見逃した割合: {frequency_fnr:.6g}",
        "",
        "## 改善の有無",
        "",
        improved,
        "",
        "改善しなかった指標がある場合は、EMA閾値がattack系列に適応すること、suspicious_threshold=2では複数特徴が同時に閾値を超える必要があること、同一payload/same_flow条件では4特徴量のうち2つが常に無情報になりやすいことが理由として考えられる。",
        "",
        "## 次にMininetで検証すべきこと",
        "",
        "- このA/B条件を実パケット列として再現したとき、pcapから抽出した4特徴量が人工bucket列と同程度に一致するか。",
        "- 実TCPフロー、RTO、queueing、payload揺らぎ、multi-flow化でfrequency-enhanced detectorのFPR/FNRがどう変化するか。",
        "- eBPF/XDP実装に載せた場合、Goertzel特徴の計算コストが許容できるか。",
        "",
    ]
    (output_path / "detector_summary.md").write_text("\n".join(lines), encoding="utf-8")


def write_multi_mode_detector_summary(
    output_dir: str | Path,
    seeds: list[int],
    mode_results: list[dict[str, Any]],
    use_warmup: bool,
    warmup_windows: int,
    attack_start_sec: float,
    conditional_ema_threshold: int,
) -> None:
    """Write detector_summary.md for all evaluation modes."""
    output_path = ensure_dir(output_dir)
    summary_rows: list[list[str]] = []
    for item in mode_results:
        mode = item["evaluation_mode"]
        detector_name = item["detector_name"]
        metrics = item["metrics"]
        adaptation = metrics["ema_adaptation"]
        summary_rows.append(
            [
                mode,
                detector_name,
                f"{metrics['accuracy']:.6g}",
                f"{metrics['precision']:.6g}",
                f"{metrics['recall']:.6g}",
                f"{metrics['f1_score']:.6g}",
                f"{metrics['false_positive_rate']:.6g}",
                f"{metrics['false_negative_rate']:.6g}",
                _format_optional_float(metrics["mean_detection_delay_sec"]),
                _format_optional_float(metrics["mean_detection_window_after_attack"]),
                _format_optional_float(adaptation["suspicious_score_drop"]),
                _format_optional_float(adaptation["positive_margin_drop"]),
            ]
        )

    lines = [
        "# Phase 2 detector summary",
        "",
        "## 実験目的",
        "",
        "stat-matchedなperiodic_ldosとrandom_microburstに対して、既存4特徴量のみのpaper-like detectorと、Goertzel周波数特徴を追加したdetectorを比較する。今回はwarmup_then_attack、cold_start_attack、conditional_emaの3評価モードを追加検証する。",
        "",
        "## 注意",
        "",
        "これは元論文の完全再現ではない。既存eBPF/XDP論文の特徴量設計に基づく、4特徴量 + EMA動的閾値 + suspicious scoreのpaper-like detectorによる追加検証である。",
        "",
        "Mininet、ns-3、eBPF/XDP、ソケット通信、実パケット送信はまだ使っていない。人工bucket列だけで検証している。",
        "",
        "## 評価モード",
        "",
        f"- warmup_then_attack: 最初の{attack_start_sec:g}秒はbenign random_microburst、以降periodic_ldos。detection delayは攻撃開始時刻から計算する。",
        "- cold_start_attack: 時刻0からperiodic_ldosが存在する攻撃ストリームと、正常random_microburstストリームを別々に評価する。EMAが攻撃に適応するかを見る。",
        "- conditional_ema: warmup_then_attackと同じ時系列で、suspicious_scoreが閾値以上のwindowではEMA baselineを更新しない。",
        "",
        "## 使用特徴量",
        "",
        f"- Baseline: {', '.join(BASELINE_FEATURES)}",
        f"- Frequency-enhanced: {', '.join(FREQUENCY_ENHANCED_FEATURES)}",
        f"- EMA warmup: {'enabled' if use_warmup else 'disabled'}, warmup_windows={warmup_windows}",
        f"- conditional_ema freeze threshold: suspicious_score >= {conditional_ema_threshold}",
        "",
        "## Seed一覧",
        "",
        ", ".join(str(seed) for seed in seeds),
        "",
        "## Metrics summary",
        "",
        markdown_table(
            [
                "mode",
                "detector",
                "accuracy",
                "precision",
                "recall",
                "f1",
                "FPR",
                "FNR",
                "delay_sec",
                "delay_window",
                "score_drop",
                "margin_drop",
            ],
            summary_rows,
        ),
        "",
        "## EMA適応の見方",
        "",
        "`score_drop` は攻撃開始直後の平均suspicious_scoreから終盤の平均suspicious_scoreを引いた値で、正なら攻撃中に異常度が下がった可能性がある。`margin_drop` は閾値超過marginについて同じ比較をした値で、正ならEMAが攻撃側の値に寄って閾値超過が弱くなった可能性がある。",
        "",
        "conditional_emaでこれらのdropが小さくなり、Recall/F1またはFNRが改善するなら、baseline poisoningの抑制に寄与したと解釈できる。改善しない場合は、suspicious_threshold、threshold_beta、window幅、周波数特徴の正規化方法に依存している可能性がある。",
        "",
        "## 次にMininetで検証すべきこと",
        "",
        "- 20秒正常warmup後に実パケットLDoSを開始した場合、pcap抽出特徴でも同じdelay/FNR傾向になるか。",
        "- cold start時にEMAが攻撃へ適応する速度が、実TCPやqueueingを含めても人工bucket列と同じか。",
        "- conditional EMAの更新停止が、実トラフィックの正常な負荷変動でFPRを増やしすぎないか。",
        "- Goertzel特徴をeBPF/XDPに載せる場合の計算コストと状態保持量が許容範囲か。",
        "",
    ]
    (output_path / "detector_summary.md").write_text("\n".join(lines), encoding="utf-8")


def plot_confusion_matrix(
    metrics: dict[str, Any],
    title: str,
    output_path: str | Path,
) -> None:
    """Save a 2x2 confusion matrix PNG."""
    cm = metrics["confusion_matrix"]
    matrix = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]], dtype=int)
    fig, axis = plt.subplots(figsize=(4.8, 4.2), constrained_layout=True)
    image = axis.imshow(matrix, cmap="Blues")
    axis.set_xticks([0, 1], ["pred benign", "pred attack"])
    axis.set_yticks([0, 1], ["true benign", "true attack"])
    axis.set_title(title)
    for row in range(2):
        for col in range(2):
            axis.text(col, row, str(matrix[row, col]), ha="center", va="center", color="black")
    fig.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def plot_suspicious_score_timeseries(
    predictions: pd.DataFrame,
    title: str,
    output_path: str | Path,
) -> None:
    """Save mean suspicious score by scenario and window start."""
    group_column = "traffic_phase" if "traffic_phase" in predictions.columns else "scenario"
    grouped = (
        predictions[predictions["is_evaluated"].astype(bool)]
        .groupby([group_column, "window_start_sec"], as_index=False)["suspicious_score"]
        .mean()
    )
    fig, axis = plt.subplots(figsize=(11, 4.5), constrained_layout=True)
    colors = {
        "periodic_ldos": "#1f77b4",
        "random_microburst": "#ff7f0e",
        "periodic_ldos_attack": "#1f77b4",
        "benign_warmup": "#ff7f0e",
        "transition": "#7f7f7f",
    }
    for scenario, scenario_frame in grouped.groupby(group_column, sort=True):
        axis.plot(
            scenario_frame["window_start_sec"],
            scenario_frame["suspicious_score"],
            marker="o",
            linewidth=1.4,
            label=scenario,
            color=colors.get(scenario),
        )
    axis.set_xlabel("window_start_sec")
    axis.set_ylabel("mean suspicious score")
    axis.set_title(title)
    axis.grid(True, alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def plot_multi_mode_metrics_comparison(metrics_table: pd.DataFrame, output_path: str | Path) -> None:
    """Save F1/FPR/FNR comparison across evaluation modes and detectors."""
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.2), constrained_layout=True)
    metric_names = ["f1_score", "false_positive_rate", "false_negative_rate"]
    titles = ["F1-score", "False Positive Rate", "False Negative Rate"]
    detectors = ["baseline", "frequency"]
    colors = {"baseline": "#4c78a8", "frequency": "#f58518"}

    modes = metrics_table["evaluation_mode"].drop_duplicates().tolist()
    x = np.arange(len(modes))
    width = 0.36
    for axis, metric_name, title in zip(axes, metric_names, titles):
        for offset_index, detector in enumerate(detectors):
            detector_rows = metrics_table[metrics_table["detector_name"] == detector]
            values = [
                float(
                    detector_rows[detector_rows["evaluation_mode"] == mode][metric_name].iloc[0]
                )
                for mode in modes
            ]
            offset = (-0.5 + offset_index) * width
            axis.bar(x + offset, values, width, label=detector, color=colors[detector])
        axis.set_title(title)
        axis.set_xticks(x)
        axis.set_xticklabels(modes, rotation=20)
        axis.set_ylim(0.0, 1.05)
        axis.grid(axis="y", alpha=0.25)
    axes[0].legend()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def plot_metrics_comparison(
    baseline_metrics: dict[str, Any],
    frequency_metrics: dict[str, Any],
    output_path: str | Path,
) -> None:
    """Save a bar chart comparing detector metrics."""
    metric_names = ["accuracy", "precision", "recall", "f1_score", "false_positive_rate", "false_negative_rate"]
    x = np.arange(len(metric_names))
    width = 0.38
    baseline_values = [baseline_metrics[name] for name in metric_names]
    frequency_values = [frequency_metrics[name] for name in metric_names]
    fig, axis = plt.subplots(figsize=(11, 4.8), constrained_layout=True)
    axis.bar(x - width / 2, baseline_values, width, label="baseline", color="#4c78a8")
    axis.bar(x + width / 2, frequency_values, width, label="frequency-enhanced", color="#f58518")
    axis.set_xticks(x)
    axis.set_xticklabels(metric_names, rotation=20)
    axis.set_ylim(0.0, 1.05)
    axis.set_ylabel("score")
    axis.set_title("Detector metrics comparison")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def _detection_delays(predictions: pd.DataFrame, duration_sec: float) -> list[dict[str, Any]]:
    """Return first attack decision time per attack stream."""
    delays: list[dict[str, Any]] = []
    metric_include = (
        predictions["metric_include"].astype(bool)
        if "metric_include" in predictions.columns
        else pd.Series(True, index=predictions.index)
    )
    attack_rows = predictions[
        predictions["true_attack"].astype(bool) & predictions["is_evaluated"].astype(bool) & metric_include
    ]
    group_columns = ["seed", "stream_id"] if "stream_id" in attack_rows.columns else ["seed"]
    for group_key, seed_frame in attack_rows.groupby(group_columns, sort=True):
        seed = group_key[0] if isinstance(group_key, tuple) else group_key
        stream_id = group_key[1] if isinstance(group_key, tuple) else ""
        attack_start_sec = _attack_start_for_group(seed_frame)
        detected = seed_frame[seed_frame["pred_attack"].astype(bool)]
        if detected.empty:
            delay = None
            detection_window = None
        else:
            first_detection = detected.iloc[0]
            detection_time_sec = (
                float(first_detection["detection_time_sec"])
                if "detection_time_sec" in first_detection
                else float(first_detection["window_start_sec"])
            )
            delay = max(0.0, detection_time_sec - attack_start_sec)
            detection_window = (
                int(first_detection["attack_window_index"])
                if "attack_window_index" in first_detection and not pd.isna(first_detection["attack_window_index"])
                else None
            )
        delays.append(
            {
                "seed": int(seed),
                "stream_id": stream_id,
                "detection_delay_sec": delay,
                "detection_window_after_attack": detection_window,
                "attack_start_sec": attack_start_sec,
                "fallback_duration_sec": max(0.0, float(duration_sec) - attack_start_sec) if delay is None else None,
            }
        )
    return delays


def _ema_adaptation_summary(predictions: pd.DataFrame) -> dict[str, Any]:
    """Summarize whether anomaly strength drops during attack windows."""
    metric_include = (
        predictions["metric_include"].astype(bool)
        if "metric_include" in predictions.columns
        else pd.Series(True, index=predictions.index)
    )
    attack_rows = predictions[
        predictions["true_attack"].astype(bool) & predictions["is_evaluated"].astype(bool) & metric_include
    ].copy()
    if attack_rows.empty:
        return {
            "attack_first_suspicious_score_mean": None,
            "attack_late_suspicious_score_mean": None,
            "suspicious_score_drop": None,
            "attack_first_positive_margin_mean": None,
            "attack_late_positive_margin_mean": None,
            "positive_margin_drop": None,
            "ema_attack_update_fraction": None,
            "ema_attack_update_skipped_count": 0,
        }

    first_scores: list[float] = []
    late_scores: list[float] = []
    first_margins: list[float] = []
    late_margins: list[float] = []
    group_columns = ["seed", "stream_id"] if "stream_id" in attack_rows.columns else ["seed"]
    for _, stream_rows in attack_rows.groupby(group_columns, sort=True):
        ordered = stream_rows.sort_values("window_start_sec", kind="mergesort")
        first = ordered.head(5)
        late = ordered.tail(5)
        first_scores.append(float(first["suspicious_score"].mean()))
        late_scores.append(float(late["suspicious_score"].mean()))
        first_margins.append(float(first["mean_positive_threshold_margin"].mean()))
        late_margins.append(float(late["mean_positive_threshold_margin"].mean()))

    first_score_mean = float(np.mean(first_scores))
    late_score_mean = float(np.mean(late_scores))
    first_margin_mean = float(np.mean(first_margins))
    late_margin_mean = float(np.mean(late_margins))
    return {
        "attack_first_suspicious_score_mean": first_score_mean,
        "attack_late_suspicious_score_mean": late_score_mean,
        "suspicious_score_drop": first_score_mean - late_score_mean,
        "attack_first_positive_margin_mean": first_margin_mean,
        "attack_late_positive_margin_mean": late_margin_mean,
        "positive_margin_drop": first_margin_mean - late_margin_mean,
        "ema_attack_update_fraction": float(attack_rows["ema_updated"].astype(bool).mean()),
        "ema_attack_update_skipped_count": int(attack_rows["ema_update_skipped"].astype(bool).sum()),
    }


def _metric_rows(metrics: dict[str, Any]) -> list[list[str]]:
    """Return formatted summary rows for a metrics dictionary."""
    keys = [
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "false_positive_rate",
        "false_negative_rate",
        "evaluated_windows",
        "mean_detection_delay_sec",
        "mean_detection_window_after_attack",
        "missed_attack_seed_count",
    ]
    rows: list[list[str]] = []
    for key in keys:
        value = metrics[key]
        if value is None:
            formatted = "None"
        elif isinstance(value, float):
            formatted = f"{value:.6g}"
        else:
            formatted = str(value)
        rows.append([key, formatted])
    cm = metrics["confusion_matrix"]
    rows.append(["confusion_matrix", f"tn={cm['tn']}, fp={cm['fp']}, fn={cm['fn']}, tp={cm['tp']}"])
    adaptation = metrics.get("ema_adaptation", {})
    rows.append(["suspicious_score_drop", _format_optional_float(adaptation.get("suspicious_score_drop"))])
    rows.append(["positive_margin_drop", _format_optional_float(adaptation.get("positive_margin_drop"))])
    return rows


def _improvement_sentence(
    baseline_metrics: dict[str, Any],
    frequency_metrics: dict[str, Any],
) -> str:
    """Describe whether frequency features improved key metrics."""
    improvements = []
    if frequency_metrics["f1_score"] > baseline_metrics["f1_score"]:
        improvements.append("F1-score")
    if frequency_metrics["false_positive_rate"] < baseline_metrics["false_positive_rate"]:
        improvements.append("FPR")
    if frequency_metrics["false_negative_rate"] < baseline_metrics["false_negative_rate"]:
        improvements.append("FNR")

    if improvements:
        return "周波数特徴の追加により、" + ", ".join(improvements) + " が改善した。"
    return "今回の設定では主要指標の明確な改善は確認できなかった。結果は隠さず記録し、閾値やストリーム順序への依存を次に確認する。"


def _safe_divide(numerator: float, denominator: float) -> float:
    """Return numerator / denominator with zero handling."""
    if denominator == 0:
        return 0.0
    return float(numerator / denominator)


def _attack_start_for_group(frame: pd.DataFrame) -> float:
    """Return the attack start timestamp for one attack stream."""
    if "attack_start_sec" not in frame.columns:
        return 0.0
    series = frame["attack_start_sec"].dropna()
    if series.empty:
        return 0.0
    return float(series.iloc[0])


def _format_optional_float(value: Any) -> str:
    """Format optional floats for Markdown tables."""
    if value is None:
        return "None"
    if isinstance(value, (float, np.floating)):
        if np.isnan(value):
            return "None"
        return f"{float(value):.6g}"
    return str(value)
