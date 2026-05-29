"""Bucket-level traffic pattern generators for phase-1 experiments."""

from __future__ import annotations

import math

import numpy as np

from .utils import count_buckets_for_duration, ms_to_bucket_count


def generate_periodic_ldos_buckets(
    duration_sec: float,
    bucket_ms: int = 25,
    period_ms: int = 1000,
    burst_ms: int = 200,
    burst_pkts_per_bucket: int = 10,
) -> list[int]:
    """Generate a periodic LDoS bucket sequence.

    Buckets inside the burst portion of each period receive
    ``burst_pkts_per_bucket`` packets. All other buckets receive zero packets.
    """
    if burst_pkts_per_bucket < 0:
        raise ValueError("burst_pkts_per_bucket must be non-negative")

    total_buckets = count_buckets_for_duration(duration_sec, bucket_ms)
    period_buckets = ms_to_bucket_count(period_ms, bucket_ms, "period_ms")
    burst_buckets = ms_to_bucket_count(burst_ms, bucket_ms, "burst_ms")
    if burst_buckets > period_buckets:
        raise ValueError("burst_ms must be less than or equal to period_ms")

    buckets: list[int] = []
    for bucket_index in range(total_buckets):
        phase = bucket_index % period_buckets
        count = burst_pkts_per_bucket if phase < burst_buckets else 0
        buckets.append(count)
    return buckets


def generate_random_microburst_buckets(
    duration_sec: float,
    bucket_ms: int = 25,
    period_ms: int = 1000,
    burst_ms: int = 200,
    burst_pkts_per_bucket: int = 10,
    seed: int = 1,
) -> list[int]:
    """Generate a stat-matched, phase-randomized microburst bucket sequence.

    The generated sequence has the same total packet count, burst-bucket count,
    maximum bucket count, and two-level bucket distribution as the periodic
    LDoS sequence. Burst blocks are placed at randomized phases within each
    nominal period, and a seeded candidate search chooses a low-1Hz arrangement.
    """
    if burst_pkts_per_bucket < 0:
        raise ValueError("burst_pkts_per_bucket must be non-negative")

    total_buckets = count_buckets_for_duration(duration_sec, bucket_ms)
    period_buckets = ms_to_bucket_count(period_ms, bucket_ms, "period_ms")
    burst_buckets = ms_to_bucket_count(burst_ms, bucket_ms, "burst_ms")
    if burst_buckets > period_buckets:
        raise ValueError("burst_ms must be less than or equal to period_ms")

    periodic = generate_periodic_ldos_buckets(
        duration_sec=duration_sec,
        bucket_ms=bucket_ms,
        period_ms=period_ms,
        burst_ms=burst_ms,
        burst_pkts_per_bucket=burst_pkts_per_bucket,
    )
    target_burst_bucket_count = sum(1 for value in periodic if value > 0)
    if target_burst_bucket_count == 0:
        return [0] * total_buckets

    rng = np.random.default_rng(seed)
    reference_iat_variance = _average_iat_variance(
        periodic,
        bucket_ms=bucket_ms,
        window_sec=4.0,
        step_sec=1.0,
    )
    best_buckets: list[int] | None = None
    best_score = math.inf

    for _ in range(1024):
        candidate = _phase_jittered_candidate(
            total_buckets=total_buckets,
            period_buckets=period_buckets,
            burst_buckets=burst_buckets,
            burst_pkts_per_bucket=burst_pkts_per_bucket,
            target_burst_bucket_count=target_burst_bucket_count,
            rng=rng,
        )
        periodicity_score = _average_normalized_power(
            candidate,
            bucket_ms=bucket_ms,
            target_freq_hz=1000.0 / period_ms,
            window_sec=4.0,
            step_sec=1.0,
        )
        candidate_iat_variance = _average_iat_variance(
            candidate,
            bucket_ms=bucket_ms,
            window_sec=4.0,
            step_sec=1.0,
        )
        iat_relative_gap = _relative_gap(reference_iat_variance, candidate_iat_variance)
        score = periodicity_score + 0.05 * iat_relative_gap + 4.0 * max(0.0, iat_relative_gap - 0.15)
        if score < best_score:
            best_score = score
            best_buckets = candidate

    if best_buckets is None:
        raise RuntimeError("failed to generate random microburst buckets")

    _assert_stat_match(periodic, best_buckets)
    return best_buckets


def _phase_jittered_candidate(
    total_buckets: int,
    period_buckets: int,
    burst_buckets: int,
    burst_pkts_per_bucket: int,
    target_burst_bucket_count: int,
    rng: np.random.Generator,
) -> list[int]:
    """Create one randomized candidate while preserving exact burst-bucket count."""
    buckets = [0] * total_buckets
    remaining = target_burst_bucket_count
    previous_phase: int | None = None

    for period_start in range(0, total_buckets, period_buckets):
        if remaining <= 0:
            break

        period_end = min(period_start + period_buckets, total_buckets)
        segment_len = period_end - period_start
        block_len = min(burst_buckets, segment_len, remaining)
        if block_len <= 0:
            continue

        max_phase = segment_len - block_len
        if max_phase <= 0:
            phase = 0
        else:
            phase = int(rng.integers(0, max_phase + 1))
            for _ in range(8):
                if previous_phase is None or phase != previous_phase:
                    break
                phase = int(rng.integers(0, max_phase + 1))

        for offset in range(block_len):
            buckets[period_start + phase + offset] = burst_pkts_per_bucket

        previous_phase = phase
        remaining -= block_len

    if remaining > 0:
        zero_indices = [index for index, value in enumerate(buckets) if value == 0]
        chosen = rng.choice(zero_indices, size=remaining, replace=False)
        for index in chosen:
            buckets[int(index)] = burst_pkts_per_bucket

    return buckets


def _average_normalized_power(
    buckets: list[int],
    bucket_ms: int,
    target_freq_hz: float,
    window_sec: float,
    step_sec: float,
) -> float:
    """Estimate average normalized target-frequency power for candidate selection."""
    signal = np.asarray(buckets, dtype=float)
    window_buckets = int(round(window_sec * 1000.0 / bucket_ms))
    step_buckets = int(round(step_sec * 1000.0 / bucket_ms))
    if window_buckets <= 0 or step_buckets <= 0:
        raise ValueError("window_sec and step_sec must produce positive bucket counts")
    if len(signal) < window_buckets:
        return _normalized_power(signal, bucket_ms, target_freq_hz)

    scores = []
    for start in range(0, len(signal) - window_buckets + 1, step_buckets):
        scores.append(_normalized_power(signal[start : start + window_buckets], bucket_ms, target_freq_hz))
    return float(np.mean(scores)) if scores else 0.0


def _normalized_power(signal: np.ndarray, bucket_ms: int, target_freq_hz: float) -> float:
    """Return raw single-frequency DFT power divided by mean-centered total energy."""
    if signal.size == 0:
        return 0.0
    centered = signal - np.mean(signal)
    total_power = float(signal.size * np.sum(centered * centered))
    if total_power <= 0.0:
        return 0.0

    sampling_rate_hz = 1000.0 / bucket_ms
    sample_index = np.arange(signal.size, dtype=float)
    basis = np.exp(-2j * np.pi * target_freq_hz * sample_index / sampling_rate_hz)
    power = float(abs(np.dot(centered, basis)) ** 2)
    return power / total_power


def _average_iat_variance(
    buckets: list[int],
    bucket_ms: int,
    window_sec: float,
    step_sec: float,
) -> float:
    """Compute average packet-level IAT variance directly from bucket counts."""
    timestamps = _packet_timestamps_from_buckets(buckets, bucket_ms)
    if timestamps.size < 2:
        return 0.0

    total_duration_sec = len(buckets) * bucket_ms / 1000.0
    if total_duration_sec < window_sec:
        return float(np.var(np.diff(timestamps), ddof=0))

    starts = np.arange(0.0, total_duration_sec - window_sec + 1e-9, step_sec)
    values = []
    for start_sec in starts:
        end_sec = start_sec + window_sec
        window_timestamps = timestamps[(timestamps >= start_sec) & (timestamps < end_sec)]
        if window_timestamps.size >= 2:
            values.append(float(np.var(np.diff(window_timestamps), ddof=0)))
        else:
            values.append(0.0)
    return float(np.mean(values)) if values else 0.0


def _packet_timestamps_from_buckets(buckets: list[int], bucket_ms: int) -> np.ndarray:
    """Expand buckets to packet timestamps using the packet model's spacing rule."""
    bucket_sec = bucket_ms / 1000.0
    timestamps: list[float] = []
    for bucket_index, packet_count in enumerate(buckets):
        if packet_count <= 0:
            continue
        interval = bucket_sec / packet_count
        bucket_start_sec = bucket_index * bucket_sec
        for packet_offset in range(packet_count):
            timestamps.append(bucket_start_sec + (packet_offset + 0.5) * interval)
    return np.asarray(timestamps, dtype=float)


def _relative_gap(reference: float, candidate: float) -> float:
    """Return a stable relative gap for generator-internal scoring."""
    denominator = abs(reference)
    if denominator <= 1e-12:
        denominator = max(abs(candidate), 1.0)
    return abs(candidate - reference) / denominator


def _assert_stat_match(reference: list[int], candidate: list[int]) -> None:
    """Validate exact bucket-level matches required for phase-1 construction."""
    ref_positive = sum(1 for value in reference if value > 0)
    cand_positive = sum(1 for value in candidate if value > 0)
    if sum(reference) != sum(candidate):
        raise RuntimeError("total packet count mismatch")
    if ref_positive != cand_positive:
        raise RuntimeError("burst bucket count mismatch")
    if max(reference, default=0) != max(candidate, default=0):
        raise RuntimeError("maximum bucket count mismatch")
