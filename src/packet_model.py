"""Pseudo-packet generation from bucket count sequences."""

from __future__ import annotations

import numpy as np
import pandas as pd


def generate_packets_from_buckets(
    buckets: list[int],
    bucket_ms: int,
    payload_size_mean: int = 80,
    payload_size_jitter: int = 0,
    flow_mode: str = "same_flow",
    seed: int = 1,
) -> pd.DataFrame:
    """Expand bucket counts into a deterministic pseudo-packet DataFrame.

    Packets are placed at equal intervals inside each bucket. With
    ``payload_size_jitter=0``, all packets have exactly ``payload_size_mean``
    bytes. ``same_flow`` assigns every packet to one flow and leaves room for
    future flow generation modes.
    """
    if bucket_ms <= 0:
        raise ValueError("bucket_ms must be positive")
    if payload_size_mean <= 0:
        raise ValueError("payload_size_mean must be positive")
    if payload_size_jitter < 0:
        raise ValueError("payload_size_jitter must be non-negative")
    if flow_mode != "same_flow":
        raise NotImplementedError("only flow_mode='same_flow' is implemented in phase 1")

    rng = np.random.default_rng(seed)
    bucket_sec = bucket_ms / 1000.0
    rows: list[dict[str, object]] = []

    for bucket_index, packet_count in enumerate(buckets):
        if packet_count < 0:
            raise ValueError("bucket counts must be non-negative")
        if packet_count == 0:
            continue

        interval = bucket_sec / packet_count
        bucket_start_sec = bucket_index * bucket_sec
        for packet_offset in range(packet_count):
            timestamp_sec = bucket_start_sec + (packet_offset + 0.5) * interval
            packet_size = _sample_packet_size(payload_size_mean, payload_size_jitter, rng)
            rows.append(
                {
                    "timestamp_sec": timestamp_sec,
                    "bucket_index": bucket_index,
                    "packet_size": packet_size,
                    "flow_id": "flow_0",
                }
            )

    frame = pd.DataFrame(rows, columns=["timestamp_sec", "bucket_index", "packet_size", "flow_id"])
    if not frame.empty:
        frame = frame.sort_values(["timestamp_sec", "bucket_index"], kind="mergesort").reset_index(drop=True)
    return frame


def _sample_packet_size(
    payload_size_mean: int,
    payload_size_jitter: int,
    rng: np.random.Generator,
) -> int:
    """Sample an integer packet size with optional bounded uniform jitter."""
    if payload_size_jitter == 0:
        return payload_size_mean

    low = max(1, payload_size_mean - payload_size_jitter)
    high = payload_size_mean + payload_size_jitter
    return int(rng.integers(low, high + 1))
