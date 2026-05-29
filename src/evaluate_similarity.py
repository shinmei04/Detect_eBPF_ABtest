"""Similarity evaluation for statistical and frequency features."""

from __future__ import annotations

import math

import numpy as np
import pandas as pd

from .utils import EPSILON, relative_difference


PRIMARY_STAT_FEATURES = [
    "iat_variance",
    "burst_rate",
    "payload_size_variance",
    "new_flow_arrival_rate",
]

DIAGNOSTIC_STAT_FEATURES = [
    "mean_packet_rate",
    "max_bucket_count",
    "bucket_count_variance",
    "burst_count",
    "total_packets",
    "total_bytes",
]

FREQUENCY_FEATURES = [
    "normalized_1hz_power",
    "normalized_rto_band_power",
    "max_rto_band_power",
]


def build_similarity_table(
    periodic_features: pd.DataFrame,
    microburst_features: pd.DataFrame,
) -> pd.DataFrame:
    """Build a row-wise feature comparison table for A/B means."""
    rows: list[dict[str, object]] = []
    groups = [
        ("primary_stat", PRIMARY_STAT_FEATURES),
        ("diagnostic_stat", DIAGNOSTIC_STAT_FEATURES),
        ("frequency", FREQUENCY_FEATURES),
    ]

    for group_name, feature_names in groups:
        available_features = [
            feature
            for feature in feature_names
            if feature in periodic_features.columns and feature in microburst_features.columns
        ]
        if not available_features:
            continue

        cosine = cosine_similarity_of_means(periodic_features, microburst_features, available_features)
        distance = standardized_distance(periodic_features, microburst_features, available_features)

        for feature in available_features:
            periodic_mean = float(periodic_features[feature].mean())
            microburst_mean = float(microburst_features[feature].mean())
            signed_difference = microburst_mean - periodic_mean
            rows.append(
                {
                    "group": group_name,
                    "feature": feature,
                    "periodic_ldos_mean": periodic_mean,
                    "random_microburst_mean": microburst_mean,
                    "signed_difference_b_minus_a": signed_difference,
                    "absolute_difference": abs(signed_difference),
                    "relative_difference": relative_difference(periodic_mean, microburst_mean),
                    "cosine_similarity": cosine,
                    "standardized_distance": distance,
                }
            )

    return pd.DataFrame(rows)


def cosine_similarity_of_means(
    periodic_features: pd.DataFrame,
    microburst_features: pd.DataFrame,
    feature_names: list[str],
) -> float:
    """Return cosine similarity between two mean feature vectors."""
    vector_a = np.asarray([periodic_features[feature].mean() for feature in feature_names], dtype=float)
    vector_b = np.asarray([microburst_features[feature].mean() for feature in feature_names], dtype=float)
    norm_a = float(np.linalg.norm(vector_a))
    norm_b = float(np.linalg.norm(vector_b))
    if norm_a < EPSILON and norm_b < EPSILON:
        return 1.0
    if norm_a < EPSILON or norm_b < EPSILON:
        return 0.0
    return float(np.dot(vector_a, vector_b) / (norm_a * norm_b))


def standardized_distance(
    periodic_features: pd.DataFrame,
    microburst_features: pd.DataFrame,
    feature_names: list[str],
) -> float:
    """Return Euclidean distance after scaling by pooled per-feature variation."""
    components = []
    for feature in feature_names:
        mean_a = float(periodic_features[feature].mean())
        mean_b = float(microburst_features[feature].mean())
        combined = pd.concat([periodic_features[feature], microburst_features[feature]], ignore_index=True)
        scale = float(combined.astype(float).std(ddof=0))
        if scale < EPSILON:
            scale = 1.0
        components.append(((mean_b - mean_a) / scale) ** 2)
    return float(math.sqrt(sum(components)))
