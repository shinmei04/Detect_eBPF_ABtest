"""Shared UDP traffic sender helpers for Mininet experiments."""

from __future__ import annotations

import argparse
import csv
import socket
import time
from pathlib import Path
from typing import Callable, Iterable


PayloadSizer = Callable[[int], int]


def add_sender_arguments(parser: argparse.ArgumentParser) -> None:
    """Add common UDP sender CLI options."""
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--dst-port", type=int, default=5001)
    parser.add_argument("--src-port", type=int, default=40000)
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--payload-size", type=int, default=80)
    parser.add_argument("--flow-id", default="flow_0")
    parser.add_argument("--log", type=Path, required=True)


def validate_common_args(args: argparse.Namespace) -> None:
    """Validate common UDP sender arguments."""
    if args.duration_sec <= 0:
        raise ValueError("duration_sec must be positive")
    if args.bucket_ms <= 0:
        raise ValueError("bucket_ms must be positive")
    if args.payload_size <= 0:
        raise ValueError("payload_size must be positive")
    if not 0 < args.dst_port < 65536:
        raise ValueError("dst_port must be in 1..65535")
    if not 0 < args.src_port < 65536:
        raise ValueError("src_port must be in 1..65535")


def send_bucket_pattern(
    buckets: list[int],
    args: argparse.Namespace,
    mode: str,
    payload_sizer: PayloadSizer | None = None,
) -> None:
    """Send UDP packets according to a bucket-count pattern.

    Packets inside each bucket are spaced evenly, matching the pure-Python
    bucket simulation. A fixed source port keeps the sender in a single UDP
    flow.
    """
    validate_common_args(args)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    payload_sizer = payload_sizer or (lambda _packet_index: int(args.payload_size))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", int(args.src_port)))
    bucket_sec = args.bucket_ms / 1000.0
    start_monotonic = time.monotonic()
    packet_index = 0

    with args.log.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["send_timestamp", "bucket_index", "packet_size", "flow_id", "mode"],
        )
        writer.writeheader()
        for bucket_index, packet_count in enumerate(buckets):
            if packet_count <= 0:
                sleep_until(start_monotonic + (bucket_index + 1) * bucket_sec)
                continue

            interval = bucket_sec / packet_count
            bucket_start = start_monotonic + bucket_index * bucket_sec
            for offset in range(packet_count):
                scheduled = bucket_start + (offset + 0.5) * interval
                sleep_until(scheduled)
                packet_size = int(payload_sizer(packet_index))
                sock.sendto(make_payload(packet_size), (args.dst_ip, int(args.dst_port)))
                writer.writerow(
                    {
                        "send_timestamp": f"{time.time():.9f}",
                        "bucket_index": bucket_index,
                        "packet_size": packet_size,
                        "flow_id": args.flow_id,
                        "mode": mode,
                    }
                )
                packet_index += 1
        handle.flush()
    sock.close()


def sleep_until(target_monotonic: float) -> None:
    """Sleep until the requested monotonic timestamp if it is still in the future."""
    delay = target_monotonic - time.monotonic()
    if delay > 0:
        time.sleep(delay)


def make_payload(size: int) -> bytes:
    """Return a deterministic UDP payload of exactly ``size`` bytes."""
    if size <= 0:
        raise ValueError("payload size must be positive")
    return b"L" * size


def buckets_from_counts(counts: Iterable[int]) -> list[int]:
    """Materialize and validate a bucket-count iterable."""
    buckets = [int(count) for count in counts]
    if any(count < 0 for count in buckets):
        raise ValueError("bucket counts must be non-negative")
    return buckets
