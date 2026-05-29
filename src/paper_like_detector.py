"""Paper-like EMA threshold detector for bucket-window features.

This is not a reproduction of any specific paper implementation. It is a
small baseline that follows the common structure of lightweight eBPF/XDP LDoS
detectors: a few window statistics, dynamic thresholds, and a suspicious score.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import pandas as pd


BASELINE_FEATURES = [
    "iat_variance",
    "burst_rate",
    "payload_size_variance",
    "new_flow_arrival_rate",
]

FREQUENCY_ENHANCED_FEATURES = BASELINE_FEATURES + [
    "normalized_1hz_power",
    "normalized_rto_band_power",
]


@dataclass(frozen=True)
class DetectorConfig:
    """Configuration for the EMA threshold detector."""

    ema_alpha: float = 0.3
    threshold_beta: float = 3.0
    suspicious_threshold: int = 2
    warmup_windows: int = 3
    use_warmup: bool = True
    freeze_ema_on_suspicious: bool = False
    ema_freeze_threshold: int | None = None


@dataclass
class EmaFeatureState:
    """EMA mean/variance state for one feature."""

    mean: float = 0.0
    variance: float = 0.0
    count: int = 0

    @property
    def initialized(self) -> bool:
        """Return whether at least one value has been observed."""
        return self.count > 0

    @property
    def std(self) -> float:
        """Return the non-negative EMA standard deviation."""
        return math.sqrt(max(self.variance, 0.0))


class PaperLikeDetector:
    """Online EMA threshold detector with a suspicious-score decision rule."""

    def __init__(self, feature_columns: list[str], config: DetectorConfig) -> None:
        """Initialize detector state for the selected feature columns."""
        if not feature_columns:
            raise ValueError("feature_columns must not be empty")
        if not (0.0 < config.ema_alpha <= 1.0):
            raise ValueError("ema_alpha must be in the interval (0, 1]")
        if config.threshold_beta < 0.0:
            raise ValueError("threshold_beta must be non-negative")
        if config.suspicious_threshold <= 0:
            raise ValueError("suspicious_threshold must be positive")
        if config.warmup_windows < 0:
            raise ValueError("warmup_windows must be non-negative")
        if config.ema_freeze_threshold is not None and config.ema_freeze_threshold <= 0:
            raise ValueError("ema_freeze_threshold must be positive when set")

        self.feature_columns = feature_columns
        self.config = config
        self.states = {feature: EmaFeatureState() for feature in feature_columns}
        self.seen_windows = 0

    def predict_stream(self, features: pd.DataFrame) -> pd.DataFrame:
        """Run online prediction for a single ordered feature stream."""
        missing = [feature for feature in self.feature_columns if feature not in features.columns]
        if missing:
            raise ValueError(f"features is missing detector columns: {missing}")

        rows: list[dict[str, object]] = []
        for _, feature_row in features.iterrows():
            rows.append(self._predict_one(feature_row))
        return pd.DataFrame(rows)

    def _predict_one(self, row: pd.Series) -> dict[str, object]:
        """Score one row against the current EMA baseline and then update it."""
        has_baseline = all(state.initialized for state in self.states.values())
        warmup_active = self.config.use_warmup and self.seen_windows < self.config.warmup_windows
        is_evaluated = has_baseline and not warmup_active

        output = row.to_dict()
        suspicious_score = 0
        positive_margins: list[float] = []

        for feature in self.feature_columns:
            state = self.states[feature]
            value = float(row[feature])
            threshold = state.mean + self.config.threshold_beta * state.std if state.initialized else float("nan")
            is_anomaly = bool(is_evaluated and value > threshold)
            if is_anomaly:
                suspicious_score += 1
            margin = value - threshold if state.initialized else float("nan")
            positive_margins.append(max(margin, 0.0) if state.initialized else 0.0)
            output[f"{feature}_ema_mean"] = state.mean if state.initialized else float("nan")
            output[f"{feature}_ema_std"] = state.std if state.initialized else float("nan")
            output[f"{feature}_threshold"] = threshold
            output[f"{feature}_threshold_margin"] = margin
            output[f"{feature}_is_anomaly"] = is_anomaly

        pred_attack = bool(is_evaluated and suspicious_score >= self.config.suspicious_threshold)
        freeze_threshold = self.config.ema_freeze_threshold or self.config.suspicious_threshold
        skip_ema_update = bool(
            self.config.freeze_ema_on_suspicious
            and is_evaluated
            and suspicious_score >= freeze_threshold
        )
        output["suspicious_score"] = suspicious_score if is_evaluated else 0
        output["mean_positive_threshold_margin"] = float(sum(positive_margins) / len(positive_margins))
        output["pred_attack"] = pred_attack
        output["pred_label"] = "attack" if pred_attack else "benign"
        output["true_attack"] = row.get("label") == "attack"
        output["is_evaluated"] = bool(is_evaluated)
        output["is_warmup"] = bool(not is_evaluated)
        output["ema_updated"] = not skip_ema_update
        output["ema_update_skipped"] = skip_ema_update

        if not skip_ema_update:
            for feature in self.feature_columns:
                self._update_state(feature, float(row[feature]))
        self.seen_windows += 1
        return output

    def _update_state(self, feature: str, value: float) -> None:
        """Update EMA mean and variance for one feature."""
        state = self.states[feature]
        if not state.initialized:
            state.mean = value
            state.variance = 0.0
            state.count = 1
            return

        previous_mean = state.mean
        alpha = self.config.ema_alpha
        state.mean = alpha * value + (1.0 - alpha) * state.mean
        state.variance = alpha * ((value - previous_mean) ** 2) + (1.0 - alpha) * state.variance
        state.count += 1


def run_detector_by_seed(
    dataset: pd.DataFrame,
    feature_columns: list[str],
    config: DetectorConfig,
) -> pd.DataFrame:
    """Run a fresh detector for each seed and concatenate predictions."""
    required = {"seed", "stream_order", "window_start_sec", "label", *feature_columns}
    missing = required.difference(dataset.columns)
    if missing:
        raise ValueError(f"dataset is missing required columns: {sorted(missing)}")

    predictions: list[pd.DataFrame] = []
    group_columns = ["seed", "stream_id"] if "stream_id" in dataset.columns else ["seed"]
    for group_key, stream_frame in dataset.groupby(group_columns, sort=True):
        seed = group_key[0] if isinstance(group_key, tuple) else group_key
        ordered = stream_frame.sort_values(["stream_order", "window_start_sec"], kind="mergesort").reset_index(
            drop=True
        )
        detector = PaperLikeDetector(feature_columns, config)
        prediction = detector.predict_stream(ordered)
        prediction.insert(0, "detector_seed", int(seed))
        predictions.append(prediction)

    return pd.concat(predictions, ignore_index=True)
