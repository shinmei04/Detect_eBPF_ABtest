"""CLI for Phase 2 paper-like detector experiments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from src.detector_dataset import DEFAULT_SEEDS, EVALUATION_MODES, SimulationConfig, build_detector_dataset
from src.detector_evaluation import (
    evaluate_predictions,
    plot_confusion_matrix,
    plot_multi_mode_metrics_comparison,
    plot_suspicious_score_timeseries,
    write_multi_mode_detector_summary,
    write_metrics_json,
)
from src.paper_like_detector import (
    BASELINE_FEATURES,
    FREQUENCY_ENHANCED_FEATURES,
    DetectorConfig,
    run_detector_by_seed,
)
from src.utils import ensure_dir


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run Phase 2 paper-like detector experiment.")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--period-ms", type=int, default=1000)
    parser.add_argument("--burst-ms", type=int, default=200)
    parser.add_argument("--burst-pkts-per-bucket", type=int, default=10)
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--seeds", type=int, nargs="+", default=DEFAULT_SEEDS)
    parser.add_argument("--ema-alpha", type=float, default=0.3)
    parser.add_argument("--threshold-beta", type=float, default=3.0)
    parser.add_argument("--suspicious-threshold", type=int, default=2)
    parser.add_argument("--warmup-windows", type=int, default=3)
    parser.add_argument("--no-warmup", action="store_true")
    parser.add_argument("--attack-start-sec", type=float, default=20.0)
    parser.add_argument("--evaluation-modes", nargs="+", choices=EVALUATION_MODES, default=EVALUATION_MODES)
    parser.add_argument("--conditional-ema-threshold", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, default=Path("results_detector"))
    return parser.parse_args()


def main() -> None:
    """Run dataset generation, detector prediction, metric evaluation, and plotting."""
    args = parse_args()
    output_dir = ensure_dir(args.output_dir)
    config = SimulationConfig(
        duration_sec=args.duration_sec,
        bucket_ms=args.bucket_ms,
        period_ms=args.period_ms,
        burst_ms=args.burst_ms,
        burst_pkts_per_bucket=args.burst_pkts_per_bucket,
        window_sec=args.window_sec,
        step_sec=args.step_sec,
    )
    mode_results = []
    metrics_rows = []
    for evaluation_mode in args.evaluation_modes:
        detector_config = _detector_config_for_mode(args, evaluation_mode)
        dataset = build_detector_dataset(
            config,
            args.seeds,
            evaluation_mode=evaluation_mode,
            attack_start_sec=args.attack_start_sec,
        )
        dataset.to_csv(output_dir / f"{evaluation_mode}_detector_dataset.csv", index=False)

        for detector_name, feature_columns in [
            ("baseline", BASELINE_FEATURES),
            ("frequency", FREQUENCY_ENHANCED_FEATURES),
        ]:
            predictions = run_detector_by_seed(dataset, feature_columns, detector_config)
            predictions.to_csv(output_dir / f"{evaluation_mode}_{detector_name}_predictions.csv", index=False)
            metrics = evaluate_predictions(predictions, args.duration_sec)
            write_metrics_json(metrics, output_dir / f"{evaluation_mode}_metrics_{detector_name}.json")
            plot_confusion_matrix(
                metrics,
                f"{evaluation_mode} {detector_name} confusion matrix",
                output_dir / f"{evaluation_mode}_confusion_matrix_{detector_name}.png",
            )
            plot_suspicious_score_timeseries(
                predictions,
                f"{evaluation_mode} {detector_name} suspicious score",
                output_dir / f"{evaluation_mode}_suspicious_score_timeseries_{detector_name}.png",
            )
            mode_results.append(
                {
                    "evaluation_mode": evaluation_mode,
                    "detector_name": detector_name,
                    "metrics": metrics,
                }
            )
            metrics_rows.append(_flat_metrics_row(evaluation_mode, detector_name, metrics))

    metrics_table = pd.DataFrame(metrics_rows)
    metrics_table.to_csv(output_dir / "detector_mode_metrics.csv", index=False)
    plot_multi_mode_metrics_comparison(metrics_table, output_dir / "metrics_comparison.png")
    write_multi_mode_detector_summary(
        output_dir,
        args.seeds,
        mode_results,
        use_warmup=not args.no_warmup,
        warmup_windows=args.warmup_windows,
        attack_start_sec=args.attack_start_sec,
        conditional_ema_threshold=args.conditional_ema_threshold,
    )

    print(f"Wrote detector results to {output_dir.resolve()}")
    for row in metrics_rows:
        print(
            f"{row['evaluation_mode']} {row['detector_name']}: "
            f"F1={row['f1_score']:.6g}, FPR={row['false_positive_rate']:.6g}, "
            f"FNR={row['false_negative_rate']:.6g}"
        )


def _detector_config_for_mode(args: argparse.Namespace, evaluation_mode: str) -> DetectorConfig:
    """Return detector config for one evaluation mode."""
    conditional = evaluation_mode == "conditional_ema"
    return DetectorConfig(
        ema_alpha=args.ema_alpha,
        threshold_beta=args.threshold_beta,
        suspicious_threshold=args.suspicious_threshold,
        warmup_windows=args.warmup_windows,
        use_warmup=not args.no_warmup,
        freeze_ema_on_suspicious=conditional,
        ema_freeze_threshold=args.conditional_ema_threshold,
    )


def _flat_metrics_row(evaluation_mode: str, detector_name: str, metrics: dict) -> dict:
    """Flatten selected metrics for CSV and plotting."""
    adaptation = metrics["ema_adaptation"]
    return {
        "evaluation_mode": evaluation_mode,
        "detector_name": detector_name,
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1_score": metrics["f1_score"],
        "false_positive_rate": metrics["false_positive_rate"],
        "false_negative_rate": metrics["false_negative_rate"],
        "mean_detection_delay_sec": metrics["mean_detection_delay_sec"],
        "mean_detection_window_after_attack": metrics["mean_detection_window_after_attack"],
        "missed_attack_seed_count": metrics["missed_attack_seed_count"],
        "suspicious_score_drop": adaptation["suspicious_score_drop"],
        "positive_margin_drop": adaptation["positive_margin_drop"],
        "ema_attack_update_fraction": adaptation["ema_attack_update_fraction"],
        "ema_attack_update_skipped_count": adaptation["ema_attack_update_skipped_count"],
    }


if __name__ == "__main__":
    main()
