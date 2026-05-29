"""Dataset generation for seed sweeps and paper-like detector experiments."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from .features import compute_window_features
from .goertzel import compute_frequency_features
from .packet_model import generate_packets_from_buckets
from .pattern_generator import (
    generate_periodic_ldos_buckets,
    generate_random_microburst_buckets,
)
from .utils import count_buckets_for_duration


DEFAULT_SEEDS = [1, 2, 3, 4, 5, 10, 20, 30, 40, 50]
EVALUATION_MODES = ["warmup_then_attack", "cold_start_attack", "conditional_ema"]


@dataclass(frozen=True)
class SimulationConfig:
    """Parameters used to generate bucket series and window features."""

    duration_sec: float = 60.0
    bucket_ms: int = 25
    period_ms: int = 1000
    burst_ms: int = 200
    burst_pkts_per_bucket: int = 10
    window_sec: float = 4.0
    step_sec: float = 1.0


def build_detector_dataset(
    config: SimulationConfig,
    seeds: list[int],
    evaluation_mode: str = "warmup_then_attack",
    attack_start_sec: float = 20.0,
) -> pd.DataFrame:
    """Build one detector dataset for the requested evaluation mode."""
    if not seeds:
        raise ValueError("seeds must not be empty")
    if evaluation_mode not in EVALUATION_MODES:
        raise ValueError(f"unknown evaluation_mode: {evaluation_mode}")

    frames: list[pd.DataFrame] = []
    for seed in seeds:
        if evaluation_mode in {"warmup_then_attack", "conditional_ema"}:
            frames.append(generate_warmup_then_attack_features(config, seed, attack_start_sec, evaluation_mode))
        elif evaluation_mode == "cold_start_attack":
            frames.append(generate_cold_start_stream_features(config, seed, "random_microburst", evaluation_mode))
            frames.append(generate_cold_start_stream_features(config, seed, "periodic_ldos", evaluation_mode))

    dataset = pd.concat(frames, ignore_index=True)
    return dataset.sort_values(["seed", "stream_id", "stream_order", "window_start_sec"], kind="mergesort").reset_index(
        drop=True
    )


def generate_warmup_then_attack_features(
    config: SimulationConfig,
    seed: int,
    attack_start_sec: float,
    evaluation_mode: str = "warmup_then_attack",
) -> pd.DataFrame:
    """Generate one stream with benign warmup followed by periodic LDoS."""
    if attack_start_sec <= 0.0:
        raise ValueError("attack_start_sec must be positive for warmup_then_attack")
    if attack_start_sec >= config.duration_sec:
        raise ValueError("attack_start_sec must be shorter than duration_sec")

    total_buckets = count_buckets_for_duration(config.duration_sec, config.bucket_ms)
    attack_start_bucket = count_buckets_for_duration(attack_start_sec, config.bucket_ms)
    benign_buckets = generate_random_microburst_buckets(
        duration_sec=config.duration_sec,
        bucket_ms=config.bucket_ms,
        period_ms=config.period_ms,
        burst_ms=config.burst_ms,
        burst_pkts_per_bucket=config.burst_pkts_per_bucket,
        seed=seed,
    )
    attack_duration_sec = config.duration_sec - attack_start_sec
    attack_buckets = generate_periodic_ldos_buckets(
        duration_sec=attack_duration_sec,
        bucket_ms=config.bucket_ms,
        period_ms=config.period_ms,
        burst_ms=config.burst_ms,
        burst_pkts_per_bucket=config.burst_pkts_per_bucket,
    )
    buckets = benign_buckets[:attack_start_bucket] + attack_buckets
    if len(buckets) != total_buckets:
        buckets = buckets[:total_buckets]

    features = _features_from_buckets(config, seed, buckets, label="")
    labels: list[str] = []
    traffic_phases: list[str] = []
    metric_include: list[bool] = []
    attack_window_indices: list[float] = []
    attack_window_count = 0
    for _, row in features.iterrows():
        end_sec = float(row["window_end_sec"])
        if end_sec <= attack_start_sec:
            labels.append("benign")
            traffic_phases.append("benign_warmup")
            metric_include.append(True)
            attack_window_indices.append(float("nan"))
        else:
            attack_window_count += 1
            labels.append("attack")
            traffic_phases.append("periodic_ldos_attack")
            metric_include.append(True)
            attack_window_indices.append(attack_window_count)

    return _attach_detector_metadata(
        features,
        seed=seed,
        scenario="warmup_then_attack",
        stream_id=f"{evaluation_mode}_seed_{seed}",
        evaluation_mode=evaluation_mode,
        stream_order=0,
        labels=labels,
        traffic_phases=traffic_phases,
        metric_include=metric_include,
        attack_start_sec=attack_start_sec,
        attack_window_indices=attack_window_indices,
    )


def generate_cold_start_stream_features(
    config: SimulationConfig,
    seed: int,
    scenario: str,
    evaluation_mode: str = "cold_start_attack",
) -> pd.DataFrame:
    """Generate a cold-start benign or attack stream beginning at time 0."""
    features = generate_scenario_features(config, seed, scenario)
    label = "attack" if scenario == "periodic_ldos" else "benign"
    stream_id = f"{evaluation_mode}_{scenario}_seed_{seed}"
    attack_window_indices = [
        index + 1
        if label == "attack"
        else float("nan")
        for index, (_, row) in enumerate(features.iterrows())
    ]
    return _attach_detector_metadata(
        features,
        seed=seed,
        scenario=scenario,
        stream_id=stream_id,
        evaluation_mode=evaluation_mode,
        stream_order=0,
        labels=[label] * len(features),
        traffic_phases=[scenario] * len(features),
        metric_include=[True] * len(features),
        attack_start_sec=0.0 if label == "attack" else float("nan"),
        attack_window_indices=attack_window_indices,
    )


def generate_scenario_features(
    config: SimulationConfig,
    seed: int,
    scenario: str,
) -> pd.DataFrame:
    """Generate merged statistical and frequency features for one scenario."""
    if scenario == "periodic_ldos":
        label = "attack"
        stream_order = 1
        buckets = generate_periodic_ldos_buckets(
            duration_sec=config.duration_sec,
            bucket_ms=config.bucket_ms,
            period_ms=config.period_ms,
            burst_ms=config.burst_ms,
            burst_pkts_per_bucket=config.burst_pkts_per_bucket,
        )
    elif scenario == "random_microburst":
        label = "benign"
        stream_order = 0
        buckets = generate_random_microburst_buckets(
            duration_sec=config.duration_sec,
            bucket_ms=config.bucket_ms,
            period_ms=config.period_ms,
            burst_ms=config.burst_ms,
            burst_pkts_per_bucket=config.burst_pkts_per_bucket,
            seed=seed,
        )
    else:
        raise ValueError(f"unknown scenario: {scenario}")

    features = _features_from_buckets(config, seed, buckets, label=label)
    features.insert(0, "seed", seed)
    features.insert(1, "scenario", scenario)
    features.insert(2, "stream_order", stream_order)
    features["label"] = label
    return features


def generate_feature_pair(
    config: SimulationConfig,
    seed: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return periodic and random feature DataFrames for one seed."""
    periodic = generate_scenario_features(config, seed, "periodic_ldos")
    random_microburst = generate_scenario_features(config, seed, "random_microburst")
    return periodic, random_microburst


def _features_from_buckets(
    config: SimulationConfig,
    seed: int,
    buckets: list[int],
    label: str,
) -> pd.DataFrame:
    """Compute merged statistical and frequency features for an arbitrary bucket stream."""
    packets = generate_packets_from_buckets(
        buckets,
        bucket_ms=config.bucket_ms,
        payload_size_mean=80,
        payload_size_jitter=0,
        flow_mode="same_flow",
        seed=seed,
    )
    stat_features = compute_window_features(
        packets=packets,
        buckets=buckets,
        bucket_ms=config.bucket_ms,
        window_sec=config.window_sec,
        step_sec=config.step_sec,
        label=label,
    )
    frequency_features = compute_frequency_features(
        buckets=buckets,
        bucket_ms=config.bucket_ms,
        window_sec=config.window_sec,
        step_sec=config.step_sec,
    )
    return stat_features.merge(
        frequency_features,
        on=["window_index", "window_start_sec", "window_end_sec"],
        how="left",
    )


def _attach_detector_metadata(
    features: pd.DataFrame,
    seed: int,
    scenario: str,
    stream_id: str,
    evaluation_mode: str,
    stream_order: int,
    labels: list[str],
    traffic_phases: list[str],
    metric_include: list[bool],
    attack_start_sec: float,
    attack_window_indices: list[float],
) -> pd.DataFrame:
    """Attach detector experiment metadata columns to a feature frame."""
    if not (
        len(features)
        == len(labels)
        == len(traffic_phases)
        == len(metric_include)
        == len(attack_window_indices)
    ):
        raise ValueError("metadata lengths must match feature rows")
    output = features.copy()
    for column in ["seed", "scenario", "stream_order"]:
        if column in output.columns:
            output = output.drop(columns=[column])
    output.insert(0, "seed", seed)
    output.insert(1, "scenario", scenario)
    output.insert(2, "stream_id", stream_id)
    output.insert(3, "evaluation_mode", evaluation_mode)
    output.insert(4, "stream_order", stream_order)
    output["label"] = labels
    output["traffic_phase"] = traffic_phases
    output["metric_include"] = metric_include
    output["attack_start_sec"] = attack_start_sec
    output["attack_window_index"] = attack_window_indices
    output["detection_time_sec"] = output["window_end_sec"].astype(float)
    output["relative_attack_time_sec"] = np.where(
        output["label"].eq("attack"),
        output["detection_time_sec"].astype(float) - attack_start_sec,
        np.nan,
    )
    return output
