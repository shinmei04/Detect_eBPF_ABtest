"""Analysis helpers for composite and F-LDDoS Mininet experiments.

The existing four-feature paper detector is used unchanged.  Periodicity is
not used for detector decisions in this module.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from src.paper_reproduction_detector import (
    PAPER_FEATURES,
    PaperDetectorConfig,
    compute_paper_window_features,
    run_paper_detector_by_seed,
)
from src.phase_labeling import add_phase_labels
from src.utils import count_buckets_for_duration, ensure_dir, markdown_table


ATTACK_MODES = [
    "single_flow_ldos",
    "multi_flow_sync_lddos",
    "multi_flow_staggered_lddos",
    "multi_flow_randomized_lddos",
    "score_aware_lddos",
    "f_lddos",
]
COMPARISON_MODES = [
    "multi_flow_sync_lddos",
    "multi_flow_staggered_lddos",
    "multi_flow_randomized_lddos",
    "f_lddos",
]
SCENARIOS = [
    "no_attack",
    "random_microburst_only",
    "single_flow_ldos",
    "composite_lddos",
    "stat_matched_composite_lddos",
]
OUTPUT_FILENAMES = {
    "all_conditions": "01_全条件集約結果.csv",
    "top_candidates": "02_合成攻撃上位候補.csv",
    "aggregate_success": "03_集約評価成功条件.csv",
    "per_flow_success": "04_フロー別ステルス成功条件.csv",
    "composite_success": "05_合成攻撃成功条件.csv",
    "aggregate_per_flow_comparison": "06_集約評価とフロー別評価の比較.csv",
    "f_lddos_comparison": "07_F-LDDoSと通常LDDoSの比較.csv",
    "summary": "08_LDDoS合成実験まとめ.md",
    "claim_evaluation": "09_LDDoS最終主張評価.md",
    "flows_degradation_plot": "10_フロー数と攻撃効果.png",
    "flows_similarity_plot": "11_フロー数とフロー別類似度.png",
    "feature_diff_plot": "12_集約評価とフロー別特徴量差.png",
    "fnr_plot": "13_集約評価とフロー別見逃し率.png",
    "tradeoff_plot": "14_合成攻撃トレードオフ散布図.png",
    "aggregate_attack_plot": "15_集約検知と攻撃効果.png",
    "attack_mode_plot": "16_攻撃モード比較.png",
    "f_lddos_degradation_plot": "17_F-LDDoSと通常LDDoSの攻撃効果比較.png",
    "f_lddos_excess_plot": "18_F-LDDoSと通常LDDoSの追加低下率比較.png",
    "feint_stealth_plot": "19_フェイント率とステルス効果.png",
    "feint_degradation_plot": "20_フェイント率と攻撃効果.png",
    "f_lddos_similarity_plot": "21_F-LDDoSの集約評価とフロー別類似度.png",
    "tcp_sack_plot": "22_TCP_SACK比較.png",
}


@dataclass(frozen=True)
class CompositeCondition:
    """One composite/F-LDDoS parameter condition."""

    condition_id: str
    attack_mode: str
    total_attack_rate_mbps: float
    num_attack_flows: int
    per_flow_rate_mbps: float
    burst_ms: int
    period_ms: int
    payload_size: int
    payload_mode: str
    phase_spread_ms: float
    jitter_ratio: float
    feint_rate_ratio: float
    feint_randomness: str
    attack_interval_placement: str
    tcp_congestion_control: str
    tcp_sack: str


def iter_composite_conditions(
    *,
    attack_modes: list[str],
    total_rates: list[float],
    num_flows: list[int],
    burst_values: list[int],
    period_values: list[int],
    payload_sizes: list[int],
    phase_spreads: list[float],
    jitter_ratios: list[float],
    payload_modes: list[str],
    feint_ratios: list[float],
    feint_randomness_values: list[str],
    attack_interval_placement: str,
    tcp_congestion_controls: list[str],
    tcp_sacks: list[str],
    preserve_sync_staggered_shaping: bool = False,
) -> Iterable[CompositeCondition]:
    """Yield a mode-aware grid without retaining every condition in memory."""
    requested_modes = ATTACK_MODES if "all" in attack_modes else attack_modes
    seen: set[str] = set()
    first_feint = feint_ratios[0]
    first_randomness = feint_randomness_values[0]
    for mode in requested_modes:
        if mode == "single_flow_ldos":
            mode_flows = [1]
            mode_phases = [0.0]
            mode_jitters = [0.0]
            mode_payloads = ["fixed"]
            mode_feints = [first_feint]
            mode_randomness = [first_randomness]
        elif mode == "multi_flow_sync_lddos":
            mode_flows = num_flows
            mode_phases = [0.0]
            mode_jitters = jitter_ratios if preserve_sync_staggered_shaping else [0.0]
            mode_payloads = payload_modes if preserve_sync_staggered_shaping else ["fixed"]
            mode_feints = [first_feint]
            mode_randomness = [first_randomness]
        elif mode == "multi_flow_staggered_lddos":
            mode_flows = num_flows
            mode_phases = phase_spreads
            mode_jitters = jitter_ratios if preserve_sync_staggered_shaping else [0.0]
            mode_payloads = payload_modes if preserve_sync_staggered_shaping else ["fixed"]
            mode_feints = [first_feint]
            mode_randomness = [first_randomness]
        elif mode in {"multi_flow_randomized_lddos", "score_aware_lddos"}:
            mode_flows = num_flows
            mode_phases = phase_spreads
            mode_jitters = jitter_ratios
            mode_payloads = payload_modes
            mode_feints = [first_feint]
            mode_randomness = [first_randomness]
        else:
            mode_flows = num_flows
            mode_phases = phase_spreads
            mode_jitters = jitter_ratios
            mode_payloads = payload_modes
            mode_feints = feint_ratios
            mode_randomness = feint_randomness_values

        for values in itertools.product(
            total_rates,
            mode_flows,
            burst_values,
            period_values,
            payload_sizes,
            mode_phases,
            mode_jitters,
            mode_payloads,
            mode_feints,
            mode_randomness,
            tcp_congestion_controls,
            tcp_sacks,
        ):
            (
                rate,
                flows,
                burst_ms,
                period_ms,
                payload_size,
                phase_spread,
                jitter,
                payload_mode,
                feint_ratio,
                randomness,
                congestion_control,
                sack,
            ) = values
            if burst_ms > period_ms:
                continue
            item = {
                "attack_mode": mode,
                "total_attack_rate_mbps": float(rate),
                "num_attack_flows": int(flows),
                "burst_ms": int(burst_ms),
                "period_ms": int(period_ms),
                "payload_size": int(payload_size),
                "payload_mode": str(payload_mode),
                "phase_spread_ms": float(min(phase_spread, burst_ms)),
                "jitter_ratio": float(jitter),
                "feint_rate_ratio": float(feint_ratio),
                "feint_randomness": str(randomness),
                "attack_interval_placement": attack_interval_placement,
                "tcp_congestion_control": str(congestion_control),
                "tcp_sack": str(sack),
            }
            condition_id = condition_id_for(item)
            if condition_id in seen:
                continue
            seen.add(condition_id)
            yield CompositeCondition(
                condition_id=condition_id,
                per_flow_rate_mbps=item["total_attack_rate_mbps"] / item["num_attack_flows"],
                **item,
            )


def build_composite_conditions(**kwargs: Any) -> list[CompositeCondition]:
    """Materialize conditions for small programmatic uses."""
    return list(iter_composite_conditions(**kwargs))


def condition_id_for(item: dict[str, Any]) -> str:
    """Return a readable, stable condition id."""
    encoded = json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha1(encoded).hexdigest()[:10]
    mode = str(item["attack_mode"]).replace("multi_flow_", "mf_").replace("_lddos", "")
    rate = f"{float(item['total_attack_rate_mbps']):g}".replace(".", "p")
    return (
        f"{mode}-r{rate}-n{int(item['num_attack_flows'])}-"
        f"l{int(item['burst_ms'])}-t{int(item['period_ms'])}-{digest}"
    )


def condition_metadata(condition: CompositeCondition) -> dict[str, Any]:
    """Return JSON-serializable condition metadata."""
    return asdict(condition)


def prepare_packet_frame(packets: pd.DataFrame, duration_sec: float, bucket_ms: int) -> pd.DataFrame:
    """Normalize a pcap-like packet frame for feature extraction."""
    frame = packets.copy()
    required = {"timestamp_sec", "packet_size", "flow_id"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"packets missing columns: {sorted(missing)}")
    frame = frame[(frame["timestamp_sec"] >= 0.0) & (frame["timestamp_sec"] < duration_sec)].copy()
    frame["bucket_index"] = np.floor(frame["timestamp_sec"] / (bucket_ms / 1000.0)).astype(int)
    return frame.sort_values("timestamp_sec", kind="mergesort").reset_index(drop=True)


def features_from_packets(
    packets: pd.DataFrame,
    *,
    duration_sec: float,
    attack_start_sec: float,
    bucket_ms: int,
    window_sec: float,
    step_sec: float,
    scenario: str,
    seed: int,
    stream_id: str,
    detector_profile: str,
    phase_intervals: Path | pd.DataFrame | None = None,
    min_overlap_sec: float | None = None,
    phase_flow_id: str | None = None,
    phase_src_port: int | None = None,
) -> pd.DataFrame:
    """Compute the existing four features from one aggregate or flow packet view."""
    frame = prepare_packet_frame(packets, duration_sec, bucket_ms)
    total_buckets = count_buckets_for_duration(duration_sec, bucket_ms)
    buckets = [0] * total_buckets
    for bucket_index, count in frame["bucket_index"].value_counts().items():
        index = int(bucket_index)
        if 0 <= index < total_buckets:
            buckets[index] = int(count)
    feature_packets = frame[["timestamp_sec", "bucket_index", "packet_size", "flow_id"]]
    features = compute_paper_window_features(
        packets=feature_packets,
        buckets=buckets,
        bucket_ms=bucket_ms,
        window_sec=window_sec,
        step_sec=step_sec,
        label="",
    )
    is_attack_scenario = scenario in {
        "single_flow_ldos",
        "composite_lddos",
        "stat_matched_composite_lddos",
    }
    if detector_profile == "phase3":
        attack_mask = features["window_start_sec"] >= attack_start_sec
    else:
        attack_mask = features["window_end_sec"] > attack_start_sec
    features["label"] = np.where(is_attack_scenario & attack_mask, "attack", "benign")
    features["target"] = features["label"].eq("attack").astype(int)
    features = add_phase_labels(
        features,
        attack_start_sec=attack_start_sec,
        phase_intervals=phase_intervals,
        min_overlap_sec=(
            float(min_overlap_sec) if min_overlap_sec is not None else bucket_ms / 1000.0
        ),
        is_attack_scenario=is_attack_scenario,
        flow_id=phase_flow_id,
        src_port=phase_src_port,
    )
    features.insert(0, "scenario", scenario)
    features.insert(1, "seed", int(seed))
    features["stream_id"] = stream_id
    features["stream_time_sec"] = features["window_start_sec"]
    features["stream_window_end_sec"] = features["window_end_sec"]
    return features


def evaluate_packet_views(
    packets: pd.DataFrame,
    *,
    duration_sec: float,
    attack_start_sec: float,
    bucket_ms: int,
    window_sec: float,
    step_sec: float,
    scenario: str,
    seed: int,
    warmup_windows: int,
    score_threshold: int,
    min_packets_for_detection: int,
    detector_profile: str,
    phase_intervals: Path | pd.DataFrame | None = None,
    min_overlap_sec: float | None = None,
    stable_flow_mode: bool = True,
    src_port_reuse: bool = True,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any], pd.DataFrame]:
    """Run the unchanged detector for aggregate and per-flow packet views."""
    config = PaperDetectorConfig(
        warmup_windows=warmup_windows,
        min_packets_for_detection=min_packets_for_detection,
        suspicious_threshold=score_threshold,
        use_observed_initial_state=True,
    )
    aggregate_features = features_from_packets(
        packets,
        duration_sec=duration_sec,
        attack_start_sec=attack_start_sec,
        bucket_ms=bucket_ms,
        window_sec=window_sec,
        step_sec=step_sec,
        scenario=scenario,
        seed=seed,
        stream_id=f"{scenario}_aggregate_seed_{seed}",
        detector_profile=detector_profile,
        phase_intervals=phase_intervals,
        min_overlap_sec=min_overlap_sec,
    )
    aggregate_predictions = run_paper_detector_by_seed(aggregate_features, config)
    aggregate_predictions["evaluation_view"] = "aggregate"

    per_flow_predictions: list[pd.DataFrame] = []
    per_flow_metrics: list[dict[str, Any]] = []
    for flow_id, flow_packets in packets.groupby("flow_id", sort=True):
        features = features_from_packets(
            flow_packets,
            duration_sec=duration_sec,
            attack_start_sec=attack_start_sec,
            bucket_ms=bucket_ms,
            window_sec=window_sec,
            step_sec=step_sec,
            scenario=scenario,
            seed=seed,
            stream_id=f"{scenario}_{flow_id}_seed_{seed}",
            detector_profile=detector_profile,
            phase_intervals=phase_intervals,
            min_overlap_sec=min_overlap_sec,
            phase_flow_id=str(flow_id),
            phase_src_port=(
                int(flow_packets["src_port"].iloc[0])
                if "src_port" in flow_packets and not flow_packets.empty
                else None
            ),
        )
        predictions = run_paper_detector_by_seed(features, config)
        predictions["evaluation_view"] = "per_flow"
        predictions["flow_id"] = flow_id
        per_flow_predictions.append(predictions)
        per_flow_metrics.append(view_metrics(predictions, prefix="", flow_id=str(flow_id)))

    per_flow_frame = (
        pd.concat(per_flow_predictions, ignore_index=True) if per_flow_predictions else pd.DataFrame()
    )
    per_flow_metric_frame = pd.DataFrame(per_flow_metrics)
    aggregate_metrics = view_metrics(aggregate_predictions, prefix="aggregate_")
    aggregate_metrics.update(summarize_per_flow_metrics(per_flow_metric_frame))
    aggregate_metrics.update(
        flow_behavior_metrics(
            packets,
            aggregate_predictions,
            stable_flow_mode=stable_flow_mode,
            src_port_reuse=src_port_reuse,
        )
    )
    for name in [
        "fnr_period",
        "fnr_burst",
        "recall_burst",
        "fpr_feint",
        "fpr_quiet",
        "fpr_pre_attack",
        "detection_delay_to_first_burst_sec",
        "suspicious_score_mean_by_phase",
        "suspicious_score_max_by_phase",
        "score_lt_2_ratio_burst",
    ]:
        aggregate_metrics[name] = aggregate_metrics.get(f"aggregate_{name}", np.nan)
    return aggregate_predictions, per_flow_frame, aggregate_metrics, per_flow_metric_frame


def view_metrics(frame: pd.DataFrame, prefix: str, flow_id: str | None = None) -> dict[str, Any]:
    """Compute feature similarity, FNR, and score distribution for one view."""
    benign = frame[frame["label"].astype(str).eq("benign")]
    attack = frame[frame["label"].astype(str).eq("attack")]
    evaluated_attack = attack[~attack["is_warmup"].fillna(False).astype(bool)] if "is_warmup" in attack else attack
    diffs = []
    metrics: dict[str, Any] = {}
    if flow_id is not None:
        metrics["flow_id"] = flow_id
    for feature in PAPER_FEATURES:
        diff = relative_diff(float(attack[feature].mean()), float(benign[feature].mean()))
        metrics[f"{prefix}{feature}_relative_diff"] = diff
        diffs.append(diff)
    metrics[f"{prefix}mean_feature_relative_diff"] = float(np.mean(diffs)) if diffs else 0.0
    metrics[f"{prefix}max_feature_relative_diff"] = float(np.max(diffs)) if diffs else 0.0
    if evaluated_attack.empty:
        fnr = 0.0
        score_lt_2 = 0.0
        distribution: dict[str, int] = {}
    else:
        fnr = float((~evaluated_attack["pred_attack"].astype(bool)).mean())
        score_lt_2 = float((evaluated_attack["suspicious_score"].astype(float) < 2.0).mean())
        counts = evaluated_attack["suspicious_score"].astype(int).value_counts().sort_index()
        distribution = {str(int(index)): int(value) for index, value in counts.items()}
    metrics[f"{prefix}FNR"] = fnr
    metrics[f"{prefix}fnr_period"] = fnr
    metrics[f"{prefix}score_lt_2_ratio"] = score_lt_2
    metrics[f"{prefix}suspicious_score_distribution"] = json.dumps(distribution, sort_keys=True)
    metrics[f"{prefix}attack_window_count"] = int(len(evaluated_attack))
    metrics.update(phase_detection_metrics(frame, prefix))
    return metrics


def phase_detection_metrics(frame: pd.DataFrame, prefix: str) -> dict[str, Any]:
    """Compute burst-specific FNR and phase-specific false-positive metrics."""
    evaluated = (
        frame[~frame["is_warmup"].fillna(False).astype(bool)].copy()
        if "is_warmup" in frame
        else frame.copy()
    )

    def target_rows(column: str) -> pd.DataFrame:
        if column not in evaluated:
            return evaluated.iloc[0:0]
        return evaluated[evaluated[column].fillna(0).astype(int).eq(1)]

    def all_target_rows(column: str) -> pd.DataFrame:
        if column not in frame:
            return frame.iloc[0:0]
        return frame[frame[column].fillna(0).astype(int).eq(1)]

    def false_negative_rate(rows: pd.DataFrame) -> float:
        return float((~rows["pred_attack"].astype(bool)).mean()) if not rows.empty else math.nan

    def false_positive_rate(rows: pd.DataFrame) -> float:
        return float(rows["pred_attack"].astype(bool).mean()) if not rows.empty else math.nan

    period = target_rows("target_period")
    burst = target_rows("target_burst")
    fnr_period = false_negative_rate(period)
    fnr_burst = false_negative_rate(burst)
    first_burst_start = (
        float(frame["first_attack_burst_start_sec"].dropna().min())
        if "first_attack_burst_start_sec" in frame
        and not frame["first_attack_burst_start_sec"].dropna().empty
        else math.nan
    )
    detected_after_first_burst = (
        evaluated[
            evaluated["pred_attack"].astype(bool)
            & (evaluated["window_end_sec"].astype(float) >= first_burst_start)
        ]
        if not math.isnan(first_burst_start)
        else evaluated.iloc[0:0]
    )
    detection_delay = (
        float(detected_after_first_burst["window_end_sec"].min()) - first_burst_start
        if not detected_after_first_burst.empty
        else math.nan
    )
    score_means: dict[str, float] = {}
    score_maxes: dict[str, float] = {}
    if "truth_phase" in evaluated and "suspicious_score" in evaluated:
        grouped = evaluated.groupby("truth_phase")["suspicious_score"]
        score_means = {str(key): float(value) for key, value in grouped.mean().items()}
        score_maxes = {str(key): float(value) for key, value in grouped.max().items()}
    return {
        f"{prefix}fnr_period": fnr_period,
        f"{prefix}fnr_burst": fnr_burst,
        f"{prefix}recall_burst": 1.0 - fnr_burst if not math.isnan(fnr_burst) else math.nan,
        f"{prefix}fpr_feint": false_positive_rate(all_target_rows("target_feint")),
        f"{prefix}fpr_quiet": false_positive_rate(all_target_rows("target_quiet")),
        f"{prefix}fpr_pre_attack": false_positive_rate(all_target_rows("target_pre_attack")),
        f"{prefix}detection_delay_to_first_burst_sec": detection_delay,
        f"{prefix}score_lt_2_ratio_burst": (
            float((burst["suspicious_score"].astype(float) < 2.0).mean())
            if not burst.empty
            else math.nan
        ),
        f"{prefix}suspicious_score_mean_by_phase": json.dumps(score_means, sort_keys=True),
        f"{prefix}suspicious_score_max_by_phase": json.dumps(score_maxes, sort_keys=True),
        f"{prefix}burst_window_count": int(len(burst)),
    }


def flow_behavior_metrics(
    packets: pd.DataFrame,
    aggregate_predictions: pd.DataFrame,
    *,
    stable_flow_mode: bool,
    src_port_reuse: bool,
) -> dict[str, Any]:
    """Summarize flow cardinality and new-flow feature behavior by truth phase."""
    phase_means: dict[str, float] = {}
    phase_maxes: dict[str, float] = {}
    if "truth_phase" in aggregate_predictions and "new_flow_arrival_rate" in aggregate_predictions:
        grouped = aggregate_predictions.groupby("truth_phase")["new_flow_arrival_rate"]
        phase_means = {str(key): float(value) for key, value in grouped.mean().items()}
        phase_maxes = {str(key): float(value) for key, value in grouped.max().items()}
    rates = aggregate_predictions.get("new_flow_arrival_rate", pd.Series(dtype=float)).astype(float)
    return {
        "unique_flow_count_total": int(packets["flow_id"].nunique()) if "flow_id" in packets else 0,
        "new_flow_arrival_rate_mean": float(rates.mean()) if not rates.empty else 0.0,
        "new_flow_arrival_rate_max": float(rates.max()) if not rates.empty else 0.0,
        "new_flow_arrival_rate_mean_by_phase": json.dumps(phase_means, sort_keys=True),
        "new_flow_arrival_rate_max_by_phase": json.dumps(phase_maxes, sort_keys=True),
        "stable_flow_mode": bool(stable_flow_mode),
        "src_port_reuse": bool(src_port_reuse),
    }


def summarize_per_flow_metrics(frame: pd.DataFrame) -> dict[str, Any]:
    """Aggregate per-flow metric rows."""
    output: dict[str, Any] = {
        "per_flow_count": int(len(frame)),
        "per_flow_mean_feature_relative_diff_mean": 0.0,
        "per_flow_mean_feature_relative_diff_median": 0.0,
        "per_flow_mean_feature_relative_diff_max": 0.0,
        "per_flow_max_feature_relative_diff_mean": 0.0,
        "per_flow_score_lt_2_ratio_mean": 0.0,
        "per_flow_score_lt_2_ratio_median": 0.0,
        "per_flow_FNR_mean": 0.0,
        "per_flow_FNR_median": 0.0,
        "per_flow_fnr_period_mean": 0.0,
        "per_flow_fnr_burst_mean": math.nan,
        "per_flow_fnr_burst_median": math.nan,
        "per_flow_recall_burst_mean": math.nan,
        "per_flow_fpr_feint_mean": math.nan,
        "per_flow_fpr_quiet_mean": math.nan,
        "per_flow_fpr_pre_attack_mean": math.nan,
        "per_flow_score_lt_2_ratio_burst_mean": math.nan,
    }
    if frame.empty:
        return output
    output.update(
        {
            "per_flow_mean_feature_relative_diff_mean": float(frame["mean_feature_relative_diff"].mean()),
            "per_flow_mean_feature_relative_diff_median": float(frame["mean_feature_relative_diff"].median()),
            "per_flow_mean_feature_relative_diff_max": float(frame["mean_feature_relative_diff"].max()),
            "per_flow_max_feature_relative_diff_mean": float(frame["max_feature_relative_diff"].mean()),
            "per_flow_score_lt_2_ratio_mean": float(frame["score_lt_2_ratio"].mean()),
            "per_flow_score_lt_2_ratio_median": float(frame["score_lt_2_ratio"].median()),
            "per_flow_FNR_mean": float(frame["FNR"].mean()),
            "per_flow_FNR_median": float(frame["FNR"].median()),
            "per_flow_fnr_period_mean": mean_or_nan(frame["fnr_period"]),
            "per_flow_fnr_burst_mean": mean_or_nan(frame["fnr_burst"]),
            "per_flow_fnr_burst_median": median_or_nan(frame["fnr_burst"]),
            "per_flow_recall_burst_mean": mean_or_nan(frame["recall_burst"]),
            "per_flow_fpr_feint_mean": mean_or_nan(frame["fpr_feint"]),
            "per_flow_fpr_quiet_mean": mean_or_nan(frame["fpr_quiet"]),
            "per_flow_fpr_pre_attack_mean": mean_or_nan(frame["fpr_pre_attack"]),
            "per_flow_score_lt_2_ratio_burst_mean": mean_or_nan(frame["score_lt_2_ratio_burst"]),
        }
    )
    return output


def mean_or_nan(values: pd.Series) -> float:
    """Return a numeric mean without warnings for an all-NA series."""
    cleaned = pd.to_numeric(values, errors="coerce").dropna()
    return float(cleaned.mean()) if not cleaned.empty else math.nan


def median_or_nan(values: pd.Series) -> float:
    """Return a numeric median without warnings for an all-NA series."""
    cleaned = pd.to_numeric(values, errors="coerce").dropna()
    return float(cleaned.median()) if not cleaned.empty else math.nan


def build_scenario_throughput_metrics(
    timeseries: pd.DataFrame,
    attack_start_sec: float,
) -> pd.DataFrame:
    """Compute throughput metrics for the five composite experiment scenarios."""
    rows = []
    for scenario in SCENARIOS:
        frame = timeseries[timeseries["scenario"] == scenario].copy()
        attack = frame[frame["end_sec"] > attack_start_sec]
        values = attack["tcp_throughput_bps"].astype(float) if not attack.empty else pd.Series(dtype=float)
        rows.append(
            {
                "scenario": scenario,
                "tcp_avg_throughput_mbps": float(values.mean() / 1_000_000.0) if len(values) else 0.0,
                "minimum_throughput_mbps": float(values.min() / 1_000_000.0) if len(values) else 0.0,
                "p05_throughput_mbps": float(values.quantile(0.05) / 1_000_000.0) if len(values) else 0.0,
                "zero_throughput_window_ratio": float((values <= 0.0).mean()) if len(values) else 0.0,
                "iperf_retransmits": int(attack["tcp_retransmits"].sum())
                if "tcp_retransmits" in attack
                else 0,
            }
        )
    metrics = pd.DataFrame(rows)
    baseline = select_row(metrics, "no_attack").get("tcp_avg_throughput_mbps", 0.0)
    metrics["normalized_throughput"] = metrics["tcp_avg_throughput_mbps"].apply(
        lambda value: safe_divide(float(value), float(baseline))
    )
    metrics["degradation"] = 1.0 - metrics["normalized_throughput"]
    return metrics


def build_condition_row(
    condition: CompositeCondition,
    throughput_metrics: pd.DataFrame,
    evaluation_metrics: dict[str, Any],
    sender_summary: dict[str, Any],
    tcp_config: dict[str, Any],
) -> dict[str, Any]:
    """Build one row for lddos_all_conditions.csv."""
    composite = select_row(throughput_metrics, "composite_lddos")
    stat_matched = select_row(throughput_metrics, "stat_matched_composite_lddos")
    random = select_row(throughput_metrics, "random_microburst_only")
    single = select_row(throughput_metrics, "single_flow_ldos")
    row: dict[str, Any] = {
        **asdict(condition),
        "tcp_timestamps": tcp_config.get("tcp_timestamps", ""),
        "tcp_window_scaling": tcp_config.get("tcp_window_scaling", ""),
        "tcp_recovery": tcp_config.get("tcp_recovery", ""),
        "tcp_avg_throughput_mbps": composite.get("tcp_avg_throughput_mbps", 0.0),
        "normalized_throughput": composite.get("normalized_throughput", 0.0),
        "composite_lddos_degradation": composite.get("degradation", 0.0),
        "stat_matched_composite_lddos_degradation": stat_matched.get("degradation", 0.0),
        "single_flow_ldos_degradation": single.get("degradation", 0.0),
        "random_microburst_degradation": random.get("degradation", 0.0),
        "minimum_throughput_mbps": composite.get("minimum_throughput_mbps", 0.0),
        "p05_throughput_mbps": composite.get("p05_throughput_mbps", 0.0),
        "zero_throughput_window_ratio": composite.get("zero_throughput_window_ratio", 0.0),
        "iperf_retransmits": composite.get("iperf_retransmits", 0),
        "udp_actual_total_burst_rate_mbps": sender_summary.get("udp_actual_total_burst_rate_mbps", 0.0),
        "udp_actual_total_average_rate_mbps": sender_summary.get("udp_actual_total_average_rate_mbps", 0.0),
        "udp_actual_per_flow_burst_rate_mbps": sender_summary.get("udp_actual_per_flow_burst_rate_mbps", 0.0),
        "udp_actual_per_flow_average_rate_mbps": sender_summary.get("udp_actual_per_flow_average_rate_mbps", 0.0),
        "feint_actual_rate_mbps": sender_summary.get("feint_actual_rate_mbps", 0.0),
        "attack_actual_rate_mbps": sender_summary.get("attack_actual_rate_mbps", 0.0),
        **evaluation_metrics,
    }
    row["excess_degradation"] = (
        float(row["composite_lddos_degradation"]) - float(row["random_microburst_degradation"])
    )
    row["aggregate_FNR_primary"] = effective_aggregate_fnr(row)
    row["per_flow_FNR_primary"] = effective_per_flow_fnr(row)
    row["aggregate_clean_success"] = aggregate_clean_success(row)
    row["per_flow_stealth_success"] = per_flow_stealth_success(row)
    row["composite_attack_success"] = composite_attack_success(row)
    row["composite_attack_score"] = composite_attack_score(row)
    return row


def aggregate_clean_success(row: dict[str, Any]) -> bool:
    """Return aggregate success criterion."""
    return bool(
        float(row.get("composite_lddos_degradation", 0.0)) >= 0.50
        and float(row.get("excess_degradation", 0.0)) >= 0.20
        and float(row.get("random_microburst_degradation", 1.0)) <= 0.40
        and float(row.get("aggregate_mean_feature_relative_diff", 1.0)) <= 0.20
        and float(row.get("aggregate_max_feature_relative_diff", 1.0)) <= 0.30
        and effective_aggregate_fnr(row) >= 0.70
    )


def effective_aggregate_fnr(row: dict[str, Any]) -> float:
    """Return burst FNR for F-LDDoS and legacy period FNR otherwise."""
    burst_fnr = row.get("fnr_burst", row.get("aggregate_fnr_burst", math.nan))
    if str(row.get("attack_mode", "")) == "f_lddos" and not pd.isna(burst_fnr):
        return float(burst_fnr)
    return float(row.get("aggregate_FNR", row.get("fnr_period", 0.0)))


def effective_per_flow_fnr(row: dict[str, Any]) -> float:
    """Return per-flow burst FNR for F-LDDoS and legacy period FNR otherwise."""
    burst_fnr = row.get("per_flow_fnr_burst_mean", math.nan)
    if str(row.get("attack_mode", "")) == "f_lddos" and not pd.isna(burst_fnr):
        return float(burst_fnr)
    return float(row.get("per_flow_FNR_mean", 0.0))


def per_flow_stealth_success(row: dict[str, Any]) -> bool:
    """Return per-flow stealth success criterion."""
    return bool(
        float(row.get("composite_lddos_degradation", 0.0)) >= 0.50
        and float(row.get("excess_degradation", 0.0)) >= 0.20
        and float(row.get("random_microburst_degradation", 1.0)) <= 0.40
        and float(row.get("per_flow_mean_feature_relative_diff_mean", 1.0)) <= 0.20
        and float(row.get("per_flow_score_lt_2_ratio_mean", 0.0)) >= 0.70
    )


def composite_attack_success(row: dict[str, Any]) -> bool:
    """Return composite attack success criterion."""
    return bool(
        float(row.get("composite_lddos_degradation", 0.0)) >= 0.50
        and float(row.get("excess_degradation", 0.0)) >= 0.20
        and float(row.get("random_microburst_degradation", 1.0)) <= 0.40
        and float(row.get("per_flow_mean_feature_relative_diff_mean", 1.0)) <= 0.20
    )


def composite_attack_score(row: dict[str, Any]) -> float:
    """Return requested candidate ranking score."""
    return float(
        1.0 * float(row.get("excess_degradation", 0.0))
        + 0.5 * float(row.get("composite_lddos_degradation", 0.0))
        + 0.5 * float(row.get("per_flow_score_lt_2_ratio_mean", 0.0))
        - 1.0 * float(row.get("per_flow_mean_feature_relative_diff_mean", 0.0))
        - 0.5 * float(row.get("aggregate_mean_feature_relative_diff", 0.0))
        - 0.5 * float(row.get("random_microburst_degradation", 0.0))
    )


def aggregate_vs_perflow_rows(frame: pd.DataFrame) -> pd.DataFrame:
    """Describe aggregate/per-flow detector differences."""
    if frame.empty:
        return frame.copy()
    columns = [
        "condition_id",
        "attack_mode",
        "composite_lddos_degradation",
        "aggregate_FNR",
        "per_flow_FNR_mean",
        "fnr_burst",
        "per_flow_fnr_burst_mean",
        "aggregate_mean_feature_relative_diff",
        "per_flow_mean_feature_relative_diff_mean",
        "aggregate_score_lt_2_ratio",
        "per_flow_score_lt_2_ratio_mean",
    ]
    source = frame.copy()
    for column in columns:
        if column not in source:
            source[column] = math.nan
    result = source[columns].copy()
    result["aggregate_FNR_primary"] = result["fnr_burst"].fillna(result["aggregate_FNR"])
    result["per_flow_FNR_primary"] = result["per_flow_fnr_burst_mean"].fillna(
        result["per_flow_FNR_mean"]
    )
    result["aggregate_detected_per_flow_missed"] = (
        (result["aggregate_FNR_primary"] < 0.50) & (result["per_flow_FNR_primary"] >= 0.50)
    )
    result["aggregate_also_missed"] = (
        (result["aggregate_FNR_primary"] >= 0.50) & (result["per_flow_FNR_primary"] >= 0.50)
    )
    result["per_flow_benign_aggregate_abnormal"] = (
        (result["per_flow_mean_feature_relative_diff_mean"] <= 0.20)
        & (result["aggregate_mean_feature_relative_diff"] > 0.20)
    )
    return result


def f_lddos_comparison(frame: pd.DataFrame) -> pd.DataFrame:
    """Compare F-LDDoS and baseline composite modes using mode means."""
    subset = frame[frame["attack_mode"].isin(COMPARISON_MODES)].copy()
    metrics = [
        "composite_lddos_degradation",
        "excess_degradation",
        "aggregate_FNR",
        "per_flow_FNR_mean",
        "fnr_burst",
        "per_flow_fnr_burst_mean",
        "score_lt_2_ratio_burst",
        "per_flow_score_lt_2_ratio_burst_mean",
        "fpr_feint",
        "fpr_quiet",
        "fpr_pre_attack",
        "aggregate_score_lt_2_ratio",
        "per_flow_score_lt_2_ratio_mean",
        "aggregate_mean_feature_relative_diff",
        "per_flow_mean_feature_relative_diff_mean",
    ]
    if subset.empty:
        return pd.DataFrame(columns=["attack_mode", "condition_count", *metrics])
    for metric in metrics:
        if metric not in subset:
            subset[metric] = math.nan
    grouped = subset.groupby("attack_mode", as_index=False)[metrics].mean()
    counts = subset.groupby("attack_mode").size().rename("condition_count").reset_index()
    grouped = grouped.merge(counts, on="attack_mode", how="left")
    sync = grouped[grouped["attack_mode"] == "multi_flow_sync_lddos"]
    if not sync.empty:
        baseline = sync.iloc[0]
        for metric in metrics:
            grouped[f"{metric}_delta_vs_sync"] = grouped[metric] - float(baseline[metric])
    return grouped


def write_composite_outputs(
    frame: pd.DataFrame,
    output_dir: Path,
    experiment_context: dict[str, Any] | None = None,
) -> None:
    """Write requested aggregate CSV, PNG, and Markdown outputs."""
    ensure_dir(output_dir)
    ordered = ensure_primary_fnr_columns(frame)
    ordered = ordered.sort_values("condition_id").reset_index(drop=True) if not ordered.empty else ordered
    ordered.to_csv(output_path(output_dir, "all_conditions"), index=False)
    top = (
        ordered.sort_values("composite_attack_score", ascending=False).head(30)
        if not ordered.empty
        else ordered.copy()
    )
    top.to_csv(output_path(output_dir, "top_candidates"), index=False)
    filter_success(ordered, "aggregate_clean_success").to_csv(
        output_path(output_dir, "aggregate_success"), index=False
    )
    filter_success(ordered, "per_flow_stealth_success").to_csv(
        output_path(output_dir, "per_flow_success"), index=False
    )
    filter_success(ordered, "composite_attack_success").to_csv(
        output_path(output_dir, "composite_success"), index=False
    )
    comparison = aggregate_vs_perflow_rows(ordered)
    comparison.to_csv(output_path(output_dir, "aggregate_per_flow_comparison"), index=False)
    f_comparison = f_lddos_comparison(ordered)
    f_comparison.to_csv(output_path(output_dir, "f_lddos_comparison"), index=False)
    plot_composite_figures(ordered, output_dir)
    output_path(output_dir, "summary").write_text(
        build_composite_summary(
            ordered,
            top,
            comparison,
            f_comparison,
            experiment_context or {},
        ),
        encoding="utf-8",
    )
    output_path(output_dir, "claim_evaluation").write_text(
        build_claim_evaluation(ordered, f_comparison),
        encoding="utf-8",
    )


def ensure_primary_fnr_columns(frame: pd.DataFrame) -> pd.DataFrame:
    """Add phase-aware primary FNR columns while preserving legacy result compatibility."""
    result = frame.copy()
    if result.empty:
        return result
    result["aggregate_FNR_primary"] = result.get("aggregate_FNR", pd.Series(0.0, index=result.index))
    result["per_flow_FNR_primary"] = result.get(
        "per_flow_FNR_mean", pd.Series(0.0, index=result.index)
    )
    result["per_flow_score_lt_2_ratio_primary"] = result.get(
        "per_flow_score_lt_2_ratio_mean", pd.Series(0.0, index=result.index)
    )
    f_mask = result.get("attack_mode", pd.Series("", index=result.index)).astype(str).eq("f_lddos")
    if "fnr_burst" in result:
        available = f_mask & result["fnr_burst"].notna()
        result.loc[available, "aggregate_FNR_primary"] = result.loc[available, "fnr_burst"]
    if "per_flow_fnr_burst_mean" in result:
        available = f_mask & result["per_flow_fnr_burst_mean"].notna()
        result.loc[available, "per_flow_FNR_primary"] = result.loc[
            available, "per_flow_fnr_burst_mean"
        ]
    if "per_flow_score_lt_2_ratio_burst_mean" in result:
        available = f_mask & result["per_flow_score_lt_2_ratio_burst_mean"].notna()
        result.loc[available, "per_flow_score_lt_2_ratio_primary"] = result.loc[
            available, "per_flow_score_lt_2_ratio_burst_mean"
        ]
    return result


def filter_success(frame: pd.DataFrame, column: str) -> pd.DataFrame:
    """Return rows where a success column is true."""
    return frame[frame[column].fillna(False).astype(bool)].copy() if column in frame else frame.iloc[0:0].copy()


def plot_composite_figures(frame: pd.DataFrame, output_dir: Path) -> None:
    """Write the thirteen requested figures."""
    scatter_by_mode(
        frame,
        "num_attack_flows",
        "composite_lddos_degradation",
        output_path(output_dir, "flows_degradation_plot"),
        size_col="total_attack_rate_mbps",
    )
    scatter_by_mode(
        frame,
        "num_attack_flows",
        "per_flow_mean_feature_relative_diff_mean",
        output_path(output_dir, "flows_similarity_plot"),
    )
    numeric_scatter(
        frame,
        "per_flow_mean_feature_relative_diff_mean",
        "aggregate_mean_feature_relative_diff",
        "composite_lddos_degradation",
        output_path(output_dir, "feature_diff_plot"),
        diagonal=True,
    )
    numeric_scatter(
        frame,
        "per_flow_FNR_primary",
        "aggregate_FNR_primary",
        "composite_lddos_degradation",
        output_path(output_dir, "fnr_plot"),
    )
    numeric_scatter(
        frame,
        "per_flow_mean_feature_relative_diff_mean",
        "excess_degradation",
        "aggregate_FNR_primary",
        output_path(output_dir, "tradeoff_plot"),
        size_col="composite_lddos_degradation",
    )
    numeric_scatter(
        frame,
        "aggregate_mean_feature_relative_diff",
        "composite_lddos_degradation",
        "aggregate_FNR_primary",
        output_path(output_dir, "aggregate_attack_plot"),
    )
    plot_attack_mode_comparison(frame, output_path(output_dir, "attack_mode_plot"))
    box_by_mode(
        frame,
        "composite_lddos_degradation",
        output_path(output_dir, "f_lddos_degradation_plot"),
    )
    box_by_mode(frame, "excess_degradation", output_path(output_dir, "f_lddos_excess_plot"))
    f_frame = frame[frame["attack_mode"] == "f_lddos"].copy() if not frame.empty else frame.copy()
    numeric_scatter(
        f_frame,
        "feint_rate_ratio",
        "per_flow_score_lt_2_ratio_mean",
        "composite_lddos_degradation",
        output_path(output_dir, "feint_stealth_plot"),
    )
    numeric_scatter(
        f_frame,
        "feint_rate_ratio",
        "composite_lddos_degradation",
        "aggregate_FNR_primary",
        output_path(output_dir, "feint_degradation_plot"),
    )
    numeric_scatter(
        f_frame,
        "per_flow_mean_feature_relative_diff_mean",
        "aggregate_mean_feature_relative_diff",
        "composite_lddos_degradation",
        output_path(output_dir, "f_lddos_similarity_plot"),
    )
    if not frame.empty and frame["tcp_sack"].nunique() > 1:
        box_by_mode(
            frame,
            "composite_lddos_degradation",
            output_path(output_dir, "tcp_sack_plot"),
            group_col="tcp_sack",
            color_col="tcp_congestion_control",
        )


def scatter_by_mode(
    frame: pd.DataFrame,
    x_col: str,
    y_col: str,
    output_path: Path,
    size_col: str | None = None,
) -> None:
    """Plot one scatter series per attack mode."""
    fig, axis = plt.subplots(figsize=(10, 6), constrained_layout=True)
    if frame.empty:
        empty_axis(axis)
    else:
        for mode, group in frame.groupby("attack_mode"):
            sizes = 55 if size_col is None else 25 + group[size_col].astype(float)
            axis.scatter(group[x_col], group[y_col], s=sizes, alpha=0.65, label=mode)
        axis.set_xlabel(x_col)
        axis.set_ylabel(y_col)
        axis.grid(alpha=0.25)
        axis.legend(fontsize=7)
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def numeric_scatter(
    frame: pd.DataFrame,
    x_col: str,
    y_col: str,
    color_col: str,
    output_path: Path,
    *,
    size_col: str | None = None,
    diagonal: bool = False,
) -> None:
    """Plot a numeric-color scatter."""
    fig, axis = plt.subplots(figsize=(9, 6), constrained_layout=True)
    if frame.empty:
        empty_axis(axis)
    else:
        sizes = 60 if size_col is None else 35 + 180 * frame[size_col].clip(lower=0).astype(float)
        scatter = axis.scatter(
            frame[x_col],
            frame[y_col],
            c=frame[color_col],
            s=sizes,
            cmap="viridis",
            alpha=0.75,
        )
        if diagonal:
            lower = min(float(frame[x_col].min()), float(frame[y_col].min()))
            upper = max(float(frame[x_col].max()), float(frame[y_col].max()))
            axis.plot([lower, upper], [lower, upper], color="black", linestyle="--", linewidth=1)
        axis.set_xlabel(x_col)
        axis.set_ylabel(y_col)
        axis.grid(alpha=0.25)
        fig.colorbar(scatter, ax=axis, label=color_col)
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def plot_attack_mode_comparison(frame: pd.DataFrame, output_path: Path) -> None:
    """Plot requested representative mode means."""
    columns = [
        "composite_lddos_degradation",
        "excess_degradation",
        "aggregate_FNR_primary",
        "per_flow_score_lt_2_ratio_primary",
    ]
    fig, axis = plt.subplots(figsize=(12, 6), constrained_layout=True)
    if frame.empty:
        empty_axis(axis)
    else:
        means = frame.groupby("attack_mode")[columns].mean()
        x = np.arange(len(means))
        width = 0.18
        for index, column in enumerate(columns):
            axis.bar(x + (index - 1.5) * width, means[column], width=width, label=column)
        axis.set_xticks(x)
        axis.set_xticklabels(means.index, rotation=25, ha="right")
        axis.grid(axis="y", alpha=0.25)
        axis.legend(fontsize=8)
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def box_by_mode(
    frame: pd.DataFrame,
    y_col: str,
    output_path: Path,
    *,
    group_col: str = "attack_mode",
    color_col: str | None = None,
) -> None:
    """Plot distributions by mode or TCP setting."""
    fig, axis = plt.subplots(figsize=(10, 6), constrained_layout=True)
    if frame.empty:
        empty_axis(axis)
    elif color_col is None:
        selected = frame[frame[group_col].isin(COMPARISON_MODES)] if group_col == "attack_mode" else frame
        groups = [(str(name), group[y_col].dropna().to_numpy()) for name, group in selected.groupby(group_col)]
        if not groups:
            empty_axis(axis)
        else:
            axis.boxplot([values for _, values in groups], tick_labels=[name for name, _ in groups])
            axis.tick_params(axis="x", rotation=25)
            axis.set_ylabel(y_col)
            axis.grid(axis="y", alpha=0.25)
    else:
        for label, group in frame.groupby(color_col):
            means = group.groupby(group_col)[y_col].mean()
            axis.plot(means.index.astype(str), means.values, marker="o", label=str(label))
        axis.set_ylabel(y_col)
        axis.grid(alpha=0.25)
        axis.legend()
    fig.savefig(output_path, dpi=170)
    plt.close(fig)


def empty_axis(axis: Any) -> None:
    """Render an empty-data message."""
    axis.text(0.5, 0.5, "No completed conditions", ha="center", va="center")
    axis.set_axis_off()


def output_path(output_dir: Path, key: str) -> Path:
    """Return the Japanese output path for an aggregate artifact."""
    return output_dir / OUTPUT_FILENAMES[key]


def build_composite_summary(
    frame: pd.DataFrame,
    top: pd.DataFrame,
    comparison: pd.DataFrame,
    f_comparison: pd.DataFrame,
    experiment_context: dict[str, Any] | None = None,
) -> str:
    """Build lddos_composite_summary.md."""
    experiment_context = experiment_context or {}
    counts = {
        name: int(frame[name].fillna(False).astype(bool).sum()) if name in frame else 0
        for name in ["aggregate_clean_success", "per_flow_stealth_success", "composite_attack_success"]
    }
    best = row_summary(top.head(1))
    flow_effect = correlation_text(frame, "num_attack_flows", "per_flow_mean_feature_relative_diff_mean")
    f_text = f_comparison_text(f_comparison)
    sack_text = tcp_comparison_text(frame)
    lines = [
        "# LDDoS composite / F-LDDoS summary",
        "",
        "## 1. 実験目的",
        "複数の弱いフローを合成したLDDoSとF-LDDoS風攻撃について、TCP低下と検知傾向を評価する。",
        "",
        "## 2. 仮説",
        "per-flowでは正常マイクロバーストに近く、aggregateでは攻撃効果を持つ条件、およびFeinting Intervalによるstealth改善を検証する。",
        "",
        "## 3. 実験条件",
        f"- completed conditions: {len(frame)}",
        f"- attack modes: {', '.join(sorted(frame['attack_mode'].unique())) if not frame.empty else 'none'}",
        f"- synthetic smoke-test rows: {int(frame.get('synthetic_test', pd.Series(dtype=bool)).fillna(False).astype(bool).sum())}",
        *focused_experiment_lines(experiment_context),
        "",
        "## 4. attack modeの説明",
        "- single_flow_ldos: 従来型の単一周期バースト。",
        "- multi_flow_sync_lddos: 弱い複数フローを完全同期。",
        "- multi_flow_staggered_lddos: burst開始をphase spread内で分散。",
        "- multi_flow_randomized_lddos: phase、IAT、payloadをランダム化。",
        "- score_aware_lddos: jitter、payload分布、flow spreadを強めるheuristic。",
        "- f_lddos: Feinting Interval後に複数flowがAttack Intervalへ集中。",
        "",
        "## 5. F-LDDoSの再現方針",
        "periodをFeinting IntervalとAttack Intervalに分け、標準ではAttack Intervalを末尾に置いた。feint packetはuniformまたはPoisson timingで送信した。",
        "",
        "## 6. aggregate評価とper-flow評価の違い",
        f"- aggregate detected / per-flow missed: {int(comparison.get('aggregate_detected_per_flow_missed', pd.Series(dtype=bool)).sum())}",
        f"- aggregate also missed: {int(comparison.get('aggregate_also_missed', pd.Series(dtype=bool)).sum())}",
        f"- per-flow benign-like / aggregate abnormal: {int(comparison.get('per_flow_benign_aggregate_abnormal', pd.Series(dtype=bool)).sum())}",
        "",
        "## 7. TCP攻撃効果の結果",
        metric_range_text(frame, "composite_lddos_degradation"),
        "",
        "## 8. per-flowでは正常風に見えるか",
        metric_range_text(frame, "per_flow_mean_feature_relative_diff_mean"),
        "",
        "## 9. aggregateでは検知されるか",
        metric_range_text(frame, "fnr_burst"),
        "- `fnr_period` はattack_start以降を一括attackとするlegacy評価であり、F-LDDoSの主評価には使わない。",
        "- `fnr_burst` は本命attack burst windowだけに対する見逃し率であり、F-LDDoSの主評価に使う。",
        "- `fpr_feint` はfeint-only windowをattackと誤検知した割合である。",
        "- `fpr_quiet` と `fpr_pre_attack` はquiet-only区間と攻撃開始前区間の誤検知率である。",
        "- `detection_delay_to_first_burst_sec` は最初のburst開始から最初のattack判定window終了までの遅延である。",
        "",
        "## 10. flow数を増やす効果",
        flow_effect,
        "",
        "## 11. phase spread / jitter / payload shapingの効果",
        "各parameterはCSVとscatterで分離して確認できる。score-awareは最低jitterとempirical payload shapingをheuristicとして適用した。",
        "",
        "## 12. F-LDDoSが通常LDDoSより有効か",
        f_text,
        "",
        "## 13. Feinting Intervalがper-flow stealth性を高めたか",
        metric_range_text(
            frame[frame["attack_mode"] == "f_lddos"] if not frame.empty else frame,
            "per_flow_score_lt_2_ratio_burst_mean",
        ),
        "",
        "## 14. SACK ON/OFF、CUBIC/Renoの違い",
        sack_text,
        "",
        "## 15. 成功条件の有無",
        f"- aggregate_clean_success: {counts['aggregate_clean_success']}",
        f"- per_flow_stealth_success: {counts['per_flow_stealth_success']}",
        f"- composite_attack_success: {counts['composite_attack_success']}",
        "",
        "## 16. 最良候補",
        best,
        "",
        "## 17. 注意点",
        "- Mininet上のパケット列 + offline Python detector評価であり、XDP/eBPF上の完全評価ではない。",
        "- `synthetic_test` 行は実験結果ではなく、CLI・集計・描画のsmoke test用である。",
        "- detector本体、EMA、threshold、suspicious scoreロジックは変更していない。",
        "- TCP内部状態ログが不十分な環境では追加確認が必要。",
        "- aggregate型detectorでは合成後のburstが見える可能性がある。",
        "- stable-flow条件ではsource portを固定し、new flow arrival rateを意図的に上げない。flow-table overflow型攻撃とは別条件である。",
        "- sender phase logがない旧結果ではphase-aware targetを0/NAとして扱い、legacy `target_period`だけを維持する。",
        "- 周期性指標をdetector判定には使用していない。",
        "- 実験結果ファイル名は `番号_日本語名.拡張子` で統一する。CSV列名とscenario列の値は分析互換性のため英語のまま維持する。",
        "- scenarioディレクトリ名は `01_攻撃なし` のように番号付き日本語で出力する。",
        "",
        "## 18. 次にやるべきこと",
        "上位候補をUbuntu/WSL Mininetで反復実行し、SACK/CC別の再現性を確認した後、XDP/eBPF上で同一packet列を評価する。",
    ]
    return "\n".join(lines) + "\n"


def focused_experiment_lines(experiment_context: dict[str, Any]) -> list[str]:
    """Return focused-preset plan details for the summary."""
    focused_used = bool(experiment_context.get("focused_preset_used", False))
    preset = str(experiment_context.get("focused_preset", "")) or "none"
    planned_count = int(experiment_context.get("planned_condition_count", 0))
    minimum_minutes = float(experiment_context.get("estimated_minimum_runtime_minutes", 0.0))
    minimum_hours = float(experiment_context.get("estimated_minimum_runtime_hours", 0.0))
    lines = [
        f"- focused_preset used: {'yes' if focused_used else 'no'}",
        f"- focused_preset name: {preset}",
        f"- total planned conditions: {planned_count}",
        f"- estimated minimum runtime: {minimum_minutes:.1f} minutes ({minimum_hours:.2f} hours)",
    ]
    if focused_used:
        lines.extend(
            [
                "- exploration strategy: 全探索ではなく、成功可能性の高い範囲を重点探索した。",
                "- focused rationale: 前回のclean tradeoff評価で有望だった `r60_l250_t1500_p750` 周辺に絞った。",
                f"- preset rationale detail: {experiment_context.get('focused_reason', '')}",
            ]
        )
    return lines


def build_claim_evaluation(frame: pd.DataFrame, f_comparison: pd.DataFrame) -> str:
    """Build lddos_final_claim_evaluation.md."""
    composite_count = int(frame.get("composite_attack_success", pd.Series(dtype=bool)).fillna(False).astype(bool).sum())
    per_flow_count = int(frame.get("per_flow_stealth_success", pd.Series(dtype=bool)).fillna(False).astype(bool).sum())
    aggregate_count = int(frame.get("aggregate_clean_success", pd.Series(dtype=bool)).fillna(False).astype(bool).sum())
    claim1 = "supported" if composite_count > 0 else "not supported"
    claim3 = "supported" if aggregate_count > 0 else ("partially supported" if composite_count > 0 else "not supported")
    claim2 = f_claim_verdict(f_comparison)
    return "\n".join(
        [
            "# LDDoS final claim evaluation",
            "",
            "## 主張1",
            "「複数の弱い攻撃フローを同期・合成したLDDoSは、各フロー単体では正常マイクロバーストに近い特徴量を保ちながら、ボトルネックではTCPスループットを追加で低下させる。」",
            "",
            f"- 判定: **{claim1}**",
            f"- composite_attack_success: {composite_count}",
            "",
            "## 主張2",
            "「F-LDDoS風にFeinting Intervalを入れることで、通常LDDoSよりもper-flow stealth性または検知回避性が向上する。」",
            "",
            f"- 判定: **{claim2}**",
            f"- per_flow_stealth_success: {per_flow_count}",
            f"- comparison: {f_comparison_text(f_comparison)}",
            "",
            "## 主張3",
            "「aggregate評価でも元論文型detectorを回避できる。」",
            "",
            f"- 判定: **{claim3}**",
            f"- aggregate_clean_success: {aggregate_count}",
            "",
            "## 評価上の制約",
            "- Mininet上のパケット列 + offline Python detector評価であり、XDP/eBPF上の完全評価ではない。",
            "- synthetic_test行は主張の実証には使用できず、実Mininet結果で再評価する必要がある。",
        ]
    ) + "\n"


def f_claim_verdict(comparison: pd.DataFrame) -> str:
    """Return claim-2 verdict from mode means."""
    if comparison.empty or "f_lddos" not in set(comparison["attack_mode"]):
        return "not supported"
    f_row = comparison[comparison["attack_mode"] == "f_lddos"].iloc[0]
    baselines = comparison[comparison["attack_mode"] != "f_lddos"]
    if baselines.empty:
        return "not supported"
    stealth_improved = (
        float(f_row["per_flow_score_lt_2_ratio_burst_mean"])
        > float(baselines["per_flow_score_lt_2_ratio_burst_mean"].max())
        or float(f_row["per_flow_fnr_burst_mean"])
        > float(baselines["per_flow_fnr_burst_mean"].max())
    )
    degradation_maintained = float(f_row["composite_lddos_degradation"]) >= 0.9 * float(
        baselines["composite_lddos_degradation"].max()
    )
    if stealth_improved and degradation_maintained:
        return "supported"
    if stealth_improved:
        return "partially supported"
    return "not supported"


def f_comparison_text(comparison: pd.DataFrame) -> str:
    """Return compact F-LDDoS comparison text."""
    if comparison.empty or "f_lddos" not in set(comparison["attack_mode"]):
        return "F-LDDoS comparison rows are unavailable."
    row = comparison[comparison["attack_mode"] == "f_lddos"].iloc[0]
    return (
        f"F-LDDoS mean degradation={row['composite_lddos_degradation']:.3f}, "
        f"per-flow burst score<2 ratio={row['per_flow_score_lt_2_ratio_burst_mean']:.3f}, "
        f"aggregate burst FNR={row['fnr_burst']:.3f}, "
        f"legacy period FNR={row['aggregate_FNR']:.3f}."
    )


def tcp_comparison_text(frame: pd.DataFrame) -> str:
    """Return TCP setting comparison text."""
    if frame.empty or frame["tcp_sack"].nunique() <= 1 and frame["tcp_congestion_control"].nunique() <= 1:
        return "単一TCP設定のみ実行されたため比較できない。"
    means = frame.groupby(["tcp_congestion_control", "tcp_sack"])["composite_lddos_degradation"].mean()
    parts = [f"{cc}+SACK {sack}: {value:.3f}" for (cc, sack), value in means.items()]
    return "; ".join(parts)


def metric_range_text(frame: pd.DataFrame, column: str) -> str:
    """Return a min/mean/max description."""
    if frame.empty or column not in frame:
        return f"{column}: no completed data."
    values = frame[column].astype(float)
    return f"{column}: min={values.min():.3f}, mean={values.mean():.3f}, max={values.max():.3f}."


def correlation_text(frame: pd.DataFrame, x_col: str, y_col: str) -> str:
    """Return a simple correlation description."""
    if frame.empty or frame[x_col].nunique() < 2:
        return "flow数の異なる完了条件が不足している。"
    correlation = float(frame[[x_col, y_col]].corr().iloc[0, 1])
    return f"{x_col} と {y_col} のPearson correlationは {correlation:.3f}。"


def row_summary(frame: pd.DataFrame) -> str:
    """Return a compact best-row summary."""
    if frame.empty:
        return "完了候補なし。"
    row = frame.iloc[0]
    return (
        f"{row['condition_id']}: mode={row['attack_mode']}, "
        f"degradation={row['composite_lddos_degradation']:.3f}, "
        f"excess={row['excess_degradation']:.3f}, "
        f"per-flow diff={row['per_flow_mean_feature_relative_diff_mean']:.3f}, "
        f"aggregate burst FNR={row.get('fnr_burst', math.nan):.3f}, "
        f"legacy period FNR={row['aggregate_FNR']:.3f}."
    )


def relative_diff(a: float, b: float) -> float:
    """Return stable symmetric relative difference."""
    if np.isnan(a) or np.isnan(b):
        return 0.0
    denominator = max(abs(a), abs(b), 1e-12)
    return float(abs(a - b) / denominator)


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide with zero handling."""
    return float(numerator / denominator) if abs(denominator) > 1e-12 else 0.0


def select_row(frame: pd.DataFrame, scenario: str) -> dict[str, Any]:
    """Return one scenario metric row."""
    if frame.empty or "scenario" not in frame:
        return {}
    selected = frame[frame["scenario"] == scenario]
    return selected.iloc[0].to_dict() if not selected.empty else {}
