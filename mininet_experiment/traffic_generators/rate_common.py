"""Rate-based UDP burst sender helpers for Mininet experiments."""

from __future__ import annotations

import argparse
import csv
import json
import random
import socket
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BurstPlan:
    """One scheduled UDP burst."""

    burst_index: int
    start_sec: float
    duration_sec: float
    packet_count: int


def add_rate_sender_arguments(parser: argparse.ArgumentParser) -> None:
    """Add common CLI arguments for rate-based UDP senders."""
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--dst-port", type=int, default=5001)
    parser.add_argument("--src-port", type=int, default=40000)
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--attack-rate-mbps", type=float, required=True)
    parser.add_argument("--burst-ms", type=int, required=True)
    parser.add_argument("--period-ms", type=int, required=True)
    parser.add_argument("--payload-size", type=int, required=True)
    parser.add_argument("--flow-id", default="flow_0")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--summary-json", type=Path)


def packet_interval_sec(attack_rate_mbps: float, payload_size: int) -> float:
    """Return target inter-packet interval inside a burst."""
    packet_bits = payload_size * 8.0
    packets_per_second = attack_rate_mbps * 1_000_000.0 / packet_bits
    if packets_per_second <= 0:
        raise ValueError("packets_per_second must be positive")
    return 1.0 / packets_per_second


def validate_rate_args(args: argparse.Namespace) -> None:
    """Validate common rate sender arguments."""
    if args.duration_sec <= 0:
        raise ValueError("duration_sec must be positive")
    if args.attack_rate_mbps <= 0:
        raise ValueError("attack_rate_mbps must be positive")
    if args.burst_ms <= 0:
        raise ValueError("burst_ms must be positive")
    if args.period_ms <= 0:
        raise ValueError("period_ms must be positive")
    if args.payload_size <= 0:
        raise ValueError("payload_size must be positive")
    if args.burst_ms > args.period_ms:
        raise ValueError("burst_ms must be <= period_ms")


def periodic_burst_plan(args: argparse.Namespace) -> list[BurstPlan]:
    """Build periodic LDoS burst plan from R/L/T parameters."""
    validate_rate_args(args)
    burst_sec = args.burst_ms / 1000.0
    period_sec = args.period_ms / 1000.0
    interval_sec = packet_interval_sec(args.attack_rate_mbps, args.payload_size)
    packets_per_burst = max(1, int(burst_sec / interval_sec))
    plan: list[BurstPlan] = []
    burst_index = 0
    start_sec = 0.0
    while start_sec < args.duration_sec:
        duration_sec = min(burst_sec, args.duration_sec - start_sec)
        if duration_sec <= 0:
            break
        packet_count = max(1, int(duration_sec / interval_sec))
        if packet_count > packets_per_burst:
            packet_count = packets_per_burst
        plan.append(BurstPlan(burst_index, start_sec, duration_sec, packet_count))
        burst_index += 1
        start_sec += period_sec
    return plan


def random_microburst_plan(args: argparse.Namespace) -> list[BurstPlan]:
    """Build non-periodic random microbursts with periodic plan's packet count."""
    periodic = periodic_burst_plan(args)
    rng = random.Random(args.seed)
    burst_sec = args.burst_ms / 1000.0
    period_sec = args.period_ms / 1000.0
    starts: list[float] = []
    for burst in periodic:
        segment_start = burst.burst_index * period_sec
        segment_end = min((burst.burst_index + 1) * period_sec, args.duration_sec)
        latest = max(segment_start, segment_end - burst.duration_sec)
        if latest <= segment_start:
            start = segment_start
        else:
            start = rng.uniform(segment_start, latest)
        starts.append(min(start, max(0.0, args.duration_sec - burst.duration_sec)))
    rng.shuffle(starts)
    starts = sorted(starts)
    return [
        BurstPlan(index, starts[index], periodic[index].duration_sec, periodic[index].packet_count)
        for index in range(len(periodic))
    ]


def send_burst_plan(args: argparse.Namespace, plan: list[BurstPlan], mode: str) -> dict[str, float | int | str]:
    """Send UDP packets according to a burst plan and write measured burst logs."""
    validate_rate_args(args)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    summary_json = args.summary_json or args.log.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)

    interval_sec = packet_interval_sec(args.attack_rate_mbps, args.payload_size)
    payload = b"L" * int(args.payload_size)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", int(args.src_port)))
    start_monotonic = time.monotonic()
    experiment_start_wall = time.time()
    burst_rows: list[dict[str, float | int | str]] = []
    total_packets = 0
    first_send_monotonic: float | None = None
    last_send_monotonic: float | None = None

    try:
        for burst in plan:
            burst_start_monotonic = start_monotonic + burst.start_sec
            sleep_until(burst_start_monotonic)
            first_packet_monotonic: float | None = None
            last_packet_monotonic: float | None = None
            sent_in_burst = 0
            for packet_offset in range(burst.packet_count):
                scheduled = burst_start_monotonic + packet_offset * interval_sec
                sleep_until(scheduled)
                sock.sendto(payload, (args.dst_ip, int(args.dst_port)))
                now = time.monotonic()
                if first_packet_monotonic is None:
                    first_packet_monotonic = now
                last_packet_monotonic = now
                if first_send_monotonic is None:
                    first_send_monotonic = now
                last_send_monotonic = now
                sent_in_burst += 1
                total_packets += 1

            measured_burst_duration = (
                max(interval_sec, float(last_packet_monotonic - first_packet_monotonic))
                if first_packet_monotonic is not None and last_packet_monotonic is not None
                else 0.0
            )
            actual_burst_rate_mbps = (
                sent_in_burst * args.payload_size * 8.0 / measured_burst_duration / 1_000_000.0
                if measured_burst_duration > 0
                else 0.0
            )
            burst_rows.append(
                {
                    "mode": mode,
                    "burst_index": burst.burst_index,
                    "timestamp": f"{experiment_start_wall + burst.start_sec:.9f}",
                    "target_attack_rate_mbps": float(args.attack_rate_mbps),
                    "actual_burst_rate_mbps": actual_burst_rate_mbps,
                    "actual_sent_packets": sent_in_burst,
                    "actual_burst_duration": measured_burst_duration,
                    "packet_interval_sec": interval_sec,
                    "payload_size": int(args.payload_size),
                    "flow_id": args.flow_id,
                }
            )
    finally:
        sock.close()

    active_duration = (
        max(interval_sec, float(last_send_monotonic - first_send_monotonic))
        if first_send_monotonic is not None and last_send_monotonic is not None
        else 0.0
    )
    actual_average_rate_mbps = total_packets * args.payload_size * 8.0 / args.duration_sec / 1_000_000.0
    for row in burst_rows:
        row["actual_average_rate_mbps"] = actual_average_rate_mbps

    with args.log.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(burst_rows[0].keys()) if burst_rows else [])
        if burst_rows:
            writer.writeheader()
            writer.writerows(burst_rows)

    summary = {
        "mode": mode,
        "target_attack_rate_mbps": float(args.attack_rate_mbps),
        "actual_burst_rate_mbps": mean([float(row["actual_burst_rate_mbps"]) for row in burst_rows]),
        "actual_average_rate_mbps": actual_average_rate_mbps,
        "actual_sent_packets": int(total_packets),
        "actual_burst_duration": mean([float(row["actual_burst_duration"]) for row in burst_rows]),
        "packet_interval_sec": interval_sec,
        "payload_size": int(args.payload_size),
        "burst_count": int(len(burst_rows)),
        "active_duration_sec": active_duration,
        "duration_sec": float(args.duration_sec),
    }
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def sleep_until(target_monotonic: float) -> None:
    """Sleep until target monotonic time."""
    delay = target_monotonic - time.monotonic()
    if delay > 0:
        time.sleep(delay)


def mean(values: list[float]) -> float:
    """Return a mean with empty-list handling."""
    return float(sum(values) / len(values)) if values else 0.0
