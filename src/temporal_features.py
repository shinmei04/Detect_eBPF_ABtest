"""Causal time-structure descriptors; no descriptor is itself an attack label."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
import numpy as np


@dataclass(frozen=True)
class TemporalConfig:
    window_sec: float = 4.0
    burst_threshold_packets: float = 5.0
    min_intervals: int = 3
    min_period_sec: float = 0.1
    max_period_sec: float = 3.0

    def validate(self, bucket_sec: float) -> None:
        values = [self.window_sec, self.burst_threshold_packets, self.min_period_sec, self.max_period_sec]
        if not all(np.isfinite(values)) or min(values) <= 0:
            raise ValueError("temporal parameters must be finite and positive")
        if self.min_intervals < 2 or int(self.min_intervals) != self.min_intervals:
            raise ValueError("min_intervals must be an integer >= 2")
        if not 2 * bucket_sec <= self.min_period_sec <= self.max_period_sec < self.window_sec:
            raise ValueError("require 2*bucket <= min_period <= max_period < temporal window")


def jain(x: np.ndarray, intervals: np.ndarray, dt: float, cfg: TemporalConfig) -> float | None:
    if len(intervals) < cfg.min_intervals:
        return None
    return float(intervals.sum() ** 2 / (len(intervals) * np.dot(intervals, intervals)))


def cv(x: np.ndarray, intervals: np.ndarray, dt: float, cfg: TemporalConfig) -> float | None:
    if len(intervals) < cfg.min_intervals:
        return None
    return float(intervals.std(ddof=0) / intervals.mean())


def autocorrelation(x: np.ndarray, intervals: np.ndarray, dt: float, cfg: TemporalConfig) -> float | None:
    centered = x - x.mean()
    energy = float(np.dot(centered, centered))
    if energy == 0:
        return None
    lags = range(int(np.ceil(cfg.min_period_sec / dt)), min(len(x) - 1, int(cfg.max_period_sec / dt)) + 1)
    values = [float(np.dot(centered[:-lag], centered[lag:]) / energy) for lag in lags]
    return max(values) if values else None


def spectral_peak(x: np.ndarray, intervals: np.ndarray, dt: float, cfg: TemporalConfig) -> float | None:
    # Rectangular, mean-removed window. Normalize by all non-DC one-sided power.
    power = np.abs(np.fft.rfft(x - x.mean())) ** 2
    power[0] = 0.0
    frequencies = np.fft.rfftfreq(len(x), dt)
    band = (frequencies >= 1 / cfg.max_period_sec) & (frequencies <= 1 / cfg.min_period_sec)
    if power.sum() == 0 or not band.any():
        return None
    return float(power[band].max() / power.sum())


METHODS: dict[str, Callable] = {
    "jain": jain, "cv": cv, "autocorrelation": autocorrelation, "spectral_peak": spectral_peak,
}


def describe_window(counts: np.ndarray, start: int, end: int, dt: float, cfg: TemporalConfig) -> dict:
    """Use only buckets [start,end), plus preceding activity to avoid false starts.

    A burst already active at capture start is left-censored, so bucket zero is
    never treated as an observed rising edge. No future burst end is consulted.
    """
    x = np.asarray(counts[start:end], dtype=float)
    if not len(x) or not np.isfinite(x).all() or (x < 0).any():
        raise ValueError("counts must be nonempty, finite and nonnegative")
    active = x >= cfg.burst_threshold_packets
    previous = np.r_[counts[start - 1] >= cfg.burst_threshold_packets if start else True, active[:-1]]
    starts = np.flatnonzero(active & ~previous)
    intervals = np.diff(starts) * dt
    # Complete bursts only for duration; ongoing/right-censored bursts omitted.
    durations = []
    for onset in starts:
        falling = np.flatnonzero(~active[onset:])
        if len(falling):
            durations.append(float(falling[0] * dt))
    result = {name: function(x, intervals, dt, cfg) for name, function in METHODS.items()}
    result.update(interval_count=len(intervals), burst_start_count=len(starts),
                  duty_cycle=float(active.mean()), peak_packets_per_sec=float(x.max() / dt),
                  mean_packets_per_sec=float(x.mean() / dt),
                  mean_complete_burst_duration_sec=float(np.mean(durations)) if durations else None)
    return result
