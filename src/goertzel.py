"""Goertzel frequency features for bucket time series."""

from __future__ import annotations

import math

import numpy as np
import pandas as pd

from .utils import iter_window_ranges


TARGET_FREQUENCIES_HZ = (1.0, 0.5, 0.25, 0.8, 0.9, 1.1, 1.2)
RTO_BAND_FREQUENCIES_HZ = (0.8, 0.9, 1.0, 1.1, 1.2)


def goertzel_power(
    signal: list[float],
    sampling_rate_hz: float,
    target_freq_hz: float,
) -> float:
    """Return raw Goertzel power at ``target_freq_hz`` for a real signal."""
    if sampling_rate_hz <= 0:
        raise ValueError("sampling_rate_hz must be positive")
    if target_freq_hz < 0:
        raise ValueError("target_freq_hz must be non-negative")
    if not signal:
        return 0.0

    omega = 2.0 * math.pi * target_freq_hz / sampling_rate_hz
    coefficient = 2.0 * math.cos(omega)
    previous = 0.0
    previous2 = 0.0

    for sample in signal:
        current = float(sample) + coefficient * previous - previous2
        previous2 = previous
        previous = current

    power = previous2 * previous2 + previous * previous - coefficient * previous * previous2
    return float(max(power, 0.0))


def compute_frequency_features(
    buckets: list[int],
    bucket_ms: int,
    window_sec: float = 4.0,
    step_sec: float = 1.0,
) -> pd.DataFrame:
    """Compute Goertzel powers and normalized RTO-band features per window."""
    sampling_rate_hz = 1000.0 / bucket_ms
    rows: list[dict[str, float | int]] = []

    for window_index, (start_bucket, end_bucket, start_sec, end_sec) in enumerate(
        iter_window_ranges(len(buckets), bucket_ms, window_sec, step_sec)
    ):
        signal = np.asarray(buckets[start_bucket:end_bucket], dtype=float)
        centered_signal = signal - np.mean(signal) if signal.size else signal
        total_power = float(signal.size * np.sum(centered_signal * centered_signal))

        powers: dict[float, float] = {}
        centered_list = centered_signal.tolist()
        for frequency_hz in TARGET_FREQUENCIES_HZ:
            powers[frequency_hz] = goertzel_power(centered_list, sampling_rate_hz, frequency_hz)

        rto_band_power = sum(powers[frequency_hz] for frequency_hz in RTO_BAND_FREQUENCIES_HZ)
        max_rto_band_power = max(powers[frequency_hz] for frequency_hz in RTO_BAND_FREQUENCIES_HZ)

        if total_power > 0.0:
            normalized_1hz_power = powers[1.0] / total_power
            normalized_rto_band_power = rto_band_power / total_power
        else:
            normalized_1hz_power = 0.0
            normalized_rto_band_power = 0.0

        rows.append(
            {
                "window_index": window_index,
                "window_start_sec": start_sec,
                "window_end_sec": end_sec,
                "power_1hz": powers[1.0],
                "power_0_5hz": powers[0.5],
                "power_0_25hz": powers[0.25],
                "power_0_8hz": powers[0.8],
                "power_0_9hz": powers[0.9],
                "power_1_1hz": powers[1.1],
                "power_1_2hz": powers[1.2],
                "normalized_1hz_power": normalized_1hz_power,
                "normalized_rto_band_power": normalized_rto_band_power,
                "max_rto_band_power": max_rto_band_power,
                "total_frequency_power": total_power,
            }
        )

    return pd.DataFrame(rows)
