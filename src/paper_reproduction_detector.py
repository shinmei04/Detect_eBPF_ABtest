"""Python reproduction of the repository's four-feature XDP detector logic.

This module reproduces the rule-based detection flow from the reference
``xdp_prog.c`` at the window-feature level: four statistical features, EMA
state, dynamic thresholds, suspicious score, and a drop/attack decision when
the score reaches two. It does not execute eBPF/XDP and it does not send
packets.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


PAPER_FEATURES = [
    "iat_variance",
    "burst_rate",
    "payload_size_variance",
    "new_flow_arrival_rate",
]

PAPER_SOURCE_REPOSITORY = "https://github.com/mahmoudelzoghbi92/LDoS-Detection-eBPF-XDP"
PAPER_SOURCE_XDP = (
    "https://github.com/mahmoudelzoghbi92/LDoS-Detection-eBPF-XDP/blob/main/xdp_prog.c"
)
PAPER_SOURCE_README = (
    "https://github.com/mahmoudelzoghbi92/LDoS-Detection-eBPF-XDP/blob/main/README.md"
)


@dataclass(frozen=True)
class PaperFeatureConfig:
    """Feature threshold/update configuration mirrored from xdp_prog.c."""

    name: str
    alpha_scaled: int
    initial_mu_scaled: float
    initial_sigma_scaled: float
    beta_scaled: int
    is_upper_threshold: bool
    min_threshold: float

    @property
    def old_weight(self) -> float:
        """Return the xdp_prog.c EMA old-state weight."""
        return self.alpha_scaled / 1_000_000.0

    @property
    def beta(self) -> float:
        """Return the beta multiplier used by xdp_prog.c."""
        return self.beta_scaled / 1000.0


XDP_FEATURE_CONFIGS = [
    PaperFeatureConfig("iat_variance", 300000, 95340.0, 41243.0, 19400, False, 0.0),
    PaperFeatureConfig("burst_rate", 300000, 10605000.0, 2140000.0, 48500, True, 0.0),
    PaperFeatureConfig("payload_size_variance", 850000, 214344000000.0, 43408000000.0, 24250, False, 0.0),
    PaperFeatureConfig("new_flow_arrival_rate", 850000, 1830000.0, 160000.0, 3233, True, 0.0),
]


@dataclass(frozen=True)
class PaperDetectorConfig:
    """Configuration for the Python reproduction detector."""

    warmup_windows: int = 20
    min_packets_for_detection: int = 10
    suspicious_threshold: int = 2
    use_observed_initial_state: bool = True
    sigma_floor: float = 1e-12


@dataclass
class PaperFeatureState:
    """EMA state for one feature."""

    mu: float
    sigma: float
    update_count: int = 0
    initialized: bool = True


class PaperReproductionDetector:
    """Window-level reproduction of the source repository's XDP detector."""

    def __init__(self, config: PaperDetectorConfig | None = None) -> None:
        """Initialize detector with source-derived feature configs."""
        self.config = config or PaperDetectorConfig()
        if self.config.warmup_windows < 0:
            raise ValueError("warmup_windows must be non-negative")
        if self.config.min_packets_for_detection < 0:
            raise ValueError("min_packets_for_detection must be non-negative")
        if self.config.suspicious_threshold <= 0:
            raise ValueError("suspicious_threshold must be positive")

        self.feature_configs = {feature.name: feature for feature in XDP_FEATURE_CONFIGS}
        self.states: dict[str, PaperFeatureState] = {}
        self.total_windows_processed = 0
        self.attack_blocked = False

        if not self.config.use_observed_initial_state:
            self.states = {
                feature.name: PaperFeatureState(feature.initial_mu_scaled, feature.initial_sigma_scaled)
                for feature in XDP_FEATURE_CONFIGS
            }

    def predict_stream(self, features: pd.DataFrame) -> pd.DataFrame:
        """Predict a stream of ordered window features."""
        missing = [feature for feature in PAPER_FEATURES if feature not in features.columns]
        if missing:
            raise ValueError(f"features is missing required paper features: {missing}")
        if "total_packets" not in features.columns:
            raise ValueError("features must include total_packets")

        rows: list[dict[str, object]] = []
        for _, row in features.iterrows():
            rows.append(self._predict_one(row))
        return pd.DataFrame(rows)

    def _predict_one(self, row: pd.Series) -> dict[str, object]:
        """Evaluate one window, update EMA state, and return detector fields."""
        output = row.to_dict()
        enough_packets = int(row["total_packets"]) >= self.config.min_packets_for_detection
        detection_enabled = self.total_windows_processed >= self.config.warmup_windows
        if not self.states:
            self._initialize_from_row(row)

        suspicious_score = 0
        output["detection_enabled"] = bool(detection_enabled)
        output["enough_packets_for_detection"] = bool(enough_packets)

        suspicious_by_feature: dict[str, bool] = {}
        for feature_name in PAPER_FEATURES:
            feature_config = self.feature_configs[feature_name]
            state = self.states[feature_name]
            value = float(row[feature_name])
            threshold = self._threshold(feature_config, state)
            is_suspicious = False
            if enough_packets and detection_enabled:
                if feature_config.is_upper_threshold:
                    is_suspicious = value > threshold
                else:
                    is_suspicious = value < threshold
                if is_suspicious:
                    suspicious_score += 1
            suspicious_by_feature[feature_name] = is_suspicious
            output[f"{feature_name}_mu"] = state.mu
            output[f"{feature_name}_sigma"] = state.sigma
            output[f"{feature_name}_threshold"] = threshold
            output[f"{feature_name}_is_suspicious"] = bool(is_suspicious)

        attack_detected = bool(enough_packets and detection_enabled and suspicious_score >= self.config.suspicious_threshold)
        if attack_detected:
            self.attack_blocked = True

        output["suspicious_score"] = suspicious_score if enough_packets and detection_enabled else 0
        output["attack_detected"] = attack_detected
        output["drop_decision"] = attack_detected
        output["blocked_after_window"] = self.attack_blocked
        output["pred_attack"] = attack_detected
        output["pred_label"] = "attack" if attack_detected else "benign"
        output["true_attack"] = row.get("label") == "attack"
        output["is_warmup"] = not detection_enabled

        if enough_packets:
            for feature_name in PAPER_FEATURES:
                if not suspicious_by_feature[feature_name] or not detection_enabled:
                    self._update_feature(feature_name, float(row[feature_name]))
            self.total_windows_processed += 1

        return output

    def _initialize_from_row(self, row: pd.Series) -> None:
        """Initialize states in the current artificial feature scale."""
        for feature_name in PAPER_FEATURES:
            value = float(row[feature_name])
            sigma = max(abs(value) * 0.05, self.config.sigma_floor)
            self.states[feature_name] = PaperFeatureState(mu=value, sigma=sigma)

    def _threshold(self, feature_config: PaperFeatureConfig, state: PaperFeatureState) -> float:
        """Compute xdp_prog.c-style dynamic threshold."""
        beta_sigma = state.sigma * feature_config.beta
        if feature_config.is_upper_threshold:
            threshold = state.mu + beta_sigma
        else:
            threshold = max(state.mu - beta_sigma, feature_config.min_threshold)
        return threshold

    def _update_feature(self, feature_name: str, value: float) -> None:
        """Update EMA mean and absolute-deviation sigma."""
        feature_config = self.feature_configs[feature_name]
        state = self.states[feature_name]
        old_weight = feature_config.old_weight
        new_weight = 1.0 - old_weight
        state.mu = old_weight * state.mu + new_weight * value
        abs_diff = abs(value - state.mu)
        state.sigma = max(old_weight * state.sigma + new_weight * abs_diff, self.config.sigma_floor)
        state.update_count += 1


def run_paper_detector_by_seed(dataset: pd.DataFrame, config: PaperDetectorConfig | None = None) -> pd.DataFrame:
    """Run a fresh paper reproduction detector for each seed/stream."""
    required = {"seed", "stream_id", "window_start_sec", "label", "total_packets", *PAPER_FEATURES}
    missing = required.difference(dataset.columns)
    if missing:
        raise ValueError(f"dataset is missing required columns: {sorted(missing)}")

    predictions: list[pd.DataFrame] = []
    for (seed, stream_id), stream in dataset.groupby(["seed", "stream_id"], sort=True):
        ordered = stream.sort_values("stream_time_sec", kind="mergesort").reset_index(drop=True)
        detector = PaperReproductionDetector(config)
        prediction = detector.predict_stream(ordered)
        prediction.insert(0, "detector_seed", int(seed))
        prediction.insert(1, "detector_stream_id", stream_id)
        predictions.append(prediction)
    return pd.concat(predictions, ignore_index=True)


def compute_paper_window_features(
    packets: pd.DataFrame,
    buckets: list[int],
    bucket_ms: int,
    window_sec: float,
    step_sec: float,
    label: str,
) -> pd.DataFrame:
    """Compute xdp_prog.c-inspired four statistical window features.

    The feature names match the paper/repository terminology. ``burst_rate`` is
    the packet rate in the window, matching xdp_prog.c's
    ``total_packets / window_duration`` calculation.
    """
    from .utils import iter_window_ranges

    rows: list[dict[str, object]] = []
    for window_index, (start_bucket, end_bucket, start_sec, end_sec) in enumerate(
        iter_window_ranges(len(buckets), bucket_ms, window_sec, step_sec)
    ):
        window_packets = packets[
            (packets["timestamp_sec"] >= start_sec) & (packets["timestamp_sec"] < end_sec)
        ]
        timestamps = window_packets["timestamp_sec"].to_numpy(dtype=float)
        packet_sizes = window_packets["packet_size"].to_numpy(dtype=float)
        total_packets = int(len(window_packets))
        iat_variance = float(np.var(np.diff(timestamps), ddof=0)) if total_packets >= 2 else 0.0
        payload_variance = float(np.var(packet_sizes, ddof=0)) if total_packets > 0 else 0.0
        new_flow_rate = (
            float(window_packets["flow_id"].nunique()) / window_sec if total_packets > 0 else 0.0
        )
        rows.append(
            {
                "window_index": window_index,
                "window_start_sec": start_sec,
                "window_end_sec": end_sec,
                "label": label,
                "iat_variance": iat_variance,
                "burst_rate": total_packets / window_sec,
                "payload_size_variance": payload_variance,
                "new_flow_arrival_rate": new_flow_rate,
                "total_packets": total_packets,
                "max_bucket_count": max(buckets[start_bucket:end_bucket], default=0),
                "bucket_count_variance": float(np.var(buckets[start_bucket:end_bucket], ddof=0)),
            }
        )
    return pd.DataFrame(rows)
