"""Shared helpers for bucket-based traffic simulations."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd


EPSILON = 1e-12


def ensure_dir(path: str | Path) -> Path:
    """Create a directory if it does not already exist and return it as a Path."""
    output_path = Path(path)
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def count_buckets_for_duration(duration_sec: float, bucket_ms: int) -> int:
    """Return the number of fixed-width buckets in the given duration."""
    if duration_sec <= 0:
        raise ValueError("duration_sec must be positive")
    if bucket_ms <= 0:
        raise ValueError("bucket_ms must be positive")

    bucket_count = int(round(duration_sec * 1000.0 / bucket_ms))
    if bucket_count <= 0:
        raise ValueError("duration_sec and bucket_ms produce zero buckets")
    return bucket_count


def ms_to_bucket_count(value_ms: int, bucket_ms: int, name: str) -> int:
    """Convert a millisecond duration to an integer bucket count."""
    if value_ms <= 0:
        raise ValueError(f"{name} must be positive")
    if bucket_ms <= 0:
        raise ValueError("bucket_ms must be positive")

    bucket_count = int(round(value_ms / bucket_ms))
    if bucket_count <= 0:
        raise ValueError(f"{name} is shorter than one bucket")
    return bucket_count


def iter_window_ranges(
    total_buckets: int,
    bucket_ms: int,
    window_sec: float,
    step_sec: float,
) -> Iterable[tuple[int, int, float, float]]:
    """Yield bucket-index and second ranges for complete sliding windows."""
    if total_buckets <= 0:
        return
    if window_sec <= 0:
        raise ValueError("window_sec must be positive")
    if step_sec <= 0:
        raise ValueError("step_sec must be positive")

    window_buckets = count_buckets_for_duration(window_sec, bucket_ms)
    step_buckets = count_buckets_for_duration(step_sec, bucket_ms)
    if window_buckets > total_buckets:
        return

    bucket_sec = bucket_ms / 1000.0
    for start_bucket in range(0, total_buckets - window_buckets + 1, step_buckets):
        end_bucket = start_bucket + window_buckets
        start_sec = start_bucket * bucket_sec
        end_sec = end_bucket * bucket_sec
        yield start_bucket, end_bucket, start_sec, end_sec


def save_buckets_csv(buckets: list[int], bucket_ms: int, output_path: str | Path) -> None:
    """Save bucket counts with index and timestamp columns."""
    bucket_sec = bucket_ms / 1000.0
    frame = pd.DataFrame(
        {
            "bucket_index": np.arange(len(buckets), dtype=int),
            "time_sec": np.arange(len(buckets), dtype=float) * bucket_sec,
            "packet_count": buckets,
        }
    )
    frame.to_csv(output_path, index=False)


def relative_difference(reference: float, candidate: float) -> float:
    """Return an absolute relative difference with stable zero handling."""
    denominator = abs(reference)
    if denominator < EPSILON:
        denominator = max(abs(candidate), 1.0)
    return abs(candidate - reference) / denominator


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    """Build a small GitHub-flavored Markdown table without extra dependencies."""
    header_line = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join(["---"] * len(headers)) + " |"
    row_lines = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header_line, separator, *row_lines])
