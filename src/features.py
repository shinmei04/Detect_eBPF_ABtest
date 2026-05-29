"""Window-level statistical feature extraction."""

from __future__ import annotations

import numpy as np
import pandas as pd

from .utils import iter_window_ranges


def compute_window_features(
    packets: pd.DataFrame,
    buckets: list[int],
    bucket_ms: int,
    window_sec: float = 4.0,
    step_sec: float = 1.0,
    label: str = "",
    burst_threshold: int = 5,
) -> pd.DataFrame:
    """Compute eBPF/XDP-style statistical features for sliding windows.

    The four primary features are ``iat_variance``, ``burst_rate``,
    ``payload_size_variance``, and ``new_flow_arrival_rate``. Additional
    diagnostic features are included to verify stat matching.
    """
    if burst_threshold < 0:
        raise ValueError("burst_threshold must be non-negative")

    required_columns = {"timestamp_sec", "packet_size", "flow_id"}
    missing_columns = required_columns.difference(packets.columns)
    if missing_columns:
        raise ValueError(f"packets is missing required columns: {sorted(missing_columns)}")

    if packets.empty:
        first_seen_by_flow = pd.Series(dtype=float)
    else:
        first_seen_by_flow = packets.groupby("flow_id", sort=False)["timestamp_sec"].min()

    rows: list[dict[str, object]] = []
    for window_index, (start_bucket, end_bucket, start_sec, end_sec) in enumerate(
        iter_window_ranges(len(buckets), bucket_ms, window_sec, step_sec)
    ):
        window_packets = packets[
            (packets["timestamp_sec"] >= start_sec) & (packets["timestamp_sec"] < end_sec)
        ].copy()
        bucket_slice = np.asarray(buckets[start_bucket:end_bucket], dtype=float)

        timestamps = window_packets["timestamp_sec"].to_numpy(dtype=float)
        iat_variance = float(np.var(np.diff(timestamps), ddof=0)) if len(timestamps) >= 2 else 0.0
        payload_size_variance = (
            float(np.var(window_packets["packet_size"].to_numpy(dtype=float), ddof=0))
            if len(window_packets) > 0
            else 0.0
        )
        new_flow_count = int(((first_seen_by_flow >= start_sec) & (first_seen_by_flow < end_sec)).sum())

        rows.append(
            {
                "window_index": window_index,
                "window_start_sec": start_sec,
                "window_end_sec": end_sec,
                "label": label,
                "iat_variance": iat_variance,
                "burst_rate": float(np.max(bucket_slice)) if bucket_slice.size else 0.0,
                "payload_size_variance": payload_size_variance,
                "new_flow_arrival_rate": new_flow_count / window_sec,
                "mean_packet_rate": len(window_packets) / window_sec,
                "max_bucket_count": float(np.max(bucket_slice)) if bucket_slice.size else 0.0,
                "bucket_count_variance": float(np.var(bucket_slice, ddof=0)) if bucket_slice.size else 0.0,
                "burst_count": int(np.sum(bucket_slice >= burst_threshold)),
                "total_packets": int(len(window_packets)),
                "total_bytes": int(window_packets["packet_size"].sum()) if len(window_packets) > 0 else 0,
            }
        )

    return pd.DataFrame(rows)
